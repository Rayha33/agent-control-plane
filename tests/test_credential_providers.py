from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from agent_control_plane.credential_providers import (
    CredentialDefinition,
    CredentialError,
    CredentialRegistry,
    parse_credential_definitions,
)
from agent_control_plane.runtime_drivers import run_trusted


def credential_store(
    tmp_path: Path, payload: str = "*:*:*:*:first-password\n"
) -> tuple[Path, Path]:
    store = tmp_path / "credential-store"
    store.mkdir(mode=0o700)
    version = store / "version-1"
    version.write_text(payload, encoding="utf-8")
    version.chmod(0o600)
    current = store / "current"
    current.symlink_to(version.name)
    return current, version


def registry_for(tmp_path: Path, current: Path) -> CredentialRegistry:
    definition = CredentialDefinition(
        name="postgres-main",
        provider="versioned_file",
        options={"current": str(current)},
    )
    return CredentialRegistry((definition,), tmp_path / "repo", b"supervisor-key")


def rotate(current: Path, target: Path) -> None:
    replacement = current.with_name("next")
    replacement.symlink_to(target.name)
    os.replace(replacement, current)


def test_versioned_handle_contains_no_plaintext_and_reopens_exact_version(
    tmp_path: Path,
) -> None:
    secret = "first-password-that-must-never-persist"
    current, first = credential_store(tmp_path, f"*:*:*:*:{secret}\n")
    registry = registry_for(tmp_path, current)

    handle = registry.resolve_current("postgres-main")
    encoded = json.dumps(handle.as_internal_dict(), sort_keys=True)
    assert secret not in encoded
    assert handle.version
    assert handle.target_fingerprint

    second = first.with_name("version-2")
    second.write_text("*:*:*:*:second-password\n", encoding="utf-8")
    second.chmod(0o600)
    rotate(current, second)

    with registry.materialize(handle, tmp_path / "runtime") as material:
        assert os.read(material.fd, 1024).decode() == f"*:*:*:*:{secret}\n"
        assert not list((tmp_path / "runtime" / ".credentials").glob("material-*"))


def test_deleted_or_mutated_retained_version_fails_closed(tmp_path: Path) -> None:
    current, first = credential_store(tmp_path)
    registry = registry_for(tmp_path, current)
    handle = registry.resolve_current("postgres-main")

    first.write_text("*:*:*:*:changed-in-place\n", encoding="utf-8")
    first.chmod(0o600)
    with (
        pytest.raises(CredentialError) as changed,
        registry.materialize(handle, tmp_path / "runtime"),
    ):
        pass
    assert changed.value.code in {"credential_version_changed", "credential_source_unsafe"}

    first.unlink()
    with (
        pytest.raises(CredentialError) as missing,
        registry.materialize(handle, tmp_path / "runtime"),
    ):
        pass
    assert missing.value.code == "credential_unavailable"


def test_material_is_descriptor_only_and_redacted_from_driver_evidence(
    tmp_path: Path,
) -> None:
    secret = "descriptor-password-7f95b86d"
    current, _ = credential_store(tmp_path, f"*:*:*:*:{secret}\n")
    registry = registry_for(tmp_path, current)
    handle = registry.resolve_current("postgres-main")

    with registry.materialize(handle, tmp_path / "runtime") as material:
        environment = {"PGPASSFILE": material.path}
        result = run_trusted(
            [
                "/bin/sh",
                "-c",
                'value=$(cat "$PGPASSFILE"); printf "%s" "$value"; printf "%s" "$value" >&2; env',
            ],
            tmp_path / "runtime",
            environment,
            credential=material,
        )
        assert secret not in json.dumps(result, sort_keys=True)
        assert "[REDACTED]" in result["stdout"]
        assert "[REDACTED]" in result["stderr"]
        assert secret not in "\x00".join(result["argv"])
        assert secret not in "\x00".join(environment.values())
        fd = material.fd
    with pytest.raises(OSError):
        os.fstat(fd)


@pytest.mark.parametrize(
    ("encoded_password", "decoded_password"),
    [
        (r"terminal-colon\:", "terminal-colon:"),
        (r"terminal-backslash\\", "terminal-backslash\\"),
        (r"both\:\\", "both:\\"),
        (" leading-and-trailing ", " leading-and-trailing "),
    ],
)
def test_pgpass_escaped_password_is_redacted_in_encoded_and_decoded_forms(
    tmp_path: Path,
    encoded_password: str,
    decoded_password: str,
) -> None:
    current, _ = credential_store(tmp_path, f"*:*:*:*:{encoded_password}\n")
    registry = registry_for(tmp_path, current)
    handle = registry.resolve_current("postgres-main")

    with registry.materialize(handle, tmp_path / "runtime") as material:
        result = run_trusted(
            [
                "/bin/sh",
                "-c",
                (
                    'printf "%s\\n%s" "$ACP_ENCODED" "$ACP_DECODED"; '
                    'printf "%s\\n%s" "$ACP_ENCODED" "$ACP_DECODED" >&2'
                ),
            ],
            tmp_path / "runtime",
            {
                "PGPASSFILE": material.path,
                "ACP_ENCODED": encoded_password,
                "ACP_DECODED": decoded_password,
            },
            credential=material,
        )

    serialized = json.dumps(result, sort_keys=True)
    assert encoded_password not in serialized
    assert decoded_password not in serialized
    assert result["stdout"] == "[REDACTED]\n[REDACTED]"
    assert result["stderr"] == "[REDACTED]\n[REDACTED]"


def test_provider_config_rejects_repo_and_nonabsolute_sources(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(CredentialError) as relative:
        parse_credential_definitions(
            [{"name": "x", "provider": "versioned_file", "current": "current"}],
            repo,
        )
    assert relative.value.code == "invalid_config"

    with pytest.raises(CredentialError) as inside:
        parse_credential_definitions(
            [
                {
                    "name": "x",
                    "provider": "versioned_file",
                    "current": str(repo / "current"),
                }
            ],
            repo,
        )
    assert inside.value.code == "credential_source_unsafe"


def test_provider_requires_atomic_current_symlink_and_private_target(tmp_path: Path) -> None:
    current, version = credential_store(tmp_path)
    registry = registry_for(tmp_path, current)

    current.unlink()
    current.write_text("*:*:*:*:not-versioned\n", encoding="utf-8")
    current.chmod(0o600)
    with pytest.raises(CredentialError) as not_versioned:
        registry.resolve_current("postgres-main")
    assert not_versioned.value.code == "credential_unavailable"

    current.unlink()
    current.symlink_to(version.name)
    version.chmod(0o640)
    with pytest.raises(CredentialError) as permissions:
        registry.resolve_current("postgres-main")
    assert permissions.value.code == "credential_source_unsafe"
