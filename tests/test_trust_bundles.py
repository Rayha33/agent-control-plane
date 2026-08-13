from __future__ import annotations

import os
from pathlib import Path

import pytest

from agent_control_plane import trust_bundles
from agent_control_plane.trust_bundles import (
    TrustBundleError,
    install_bundle,
    load_current_bundle,
    retire_bundle,
    verify_bundle_pin,
)


def executable(source: Path, name: str, body: str) -> Path:
    path = source / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def install(source: Path, root: Path, version: str, files: dict[str, str]) -> dict:
    return install_bundle(
        source,
        root,
        version,
        files,
        owner_uid=os.geteuid(),
        require_privilege=False,
    )


def test_install_is_immutable_owned_and_atomically_rotated(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    executable(source, "critic", "echo first")
    root = tmp_path / "trust"

    first = install(source, root, "1.0.0", {"critic": "critic"})
    executable(source, "critic", "echo second")
    second = install(source, root, "1.1.0", {"critic": "critic"})

    assert first["bundle_id"] != second["bundle_id"]
    assert load_current_bundle(root, owner_uid=os.geteuid())["bundle_id"] == second["bundle_id"]
    assert verify_bundle_pin(first)["ok"] is True
    assert verify_bundle_pin(second)["ok"] is True
    for pin in (first, second):
        bundle = root / "bundles" / pin["bundle_id"]
        assert bundle.stat().st_mode & 0o222 == 0
        assert (bundle / "manifest.json").stat().st_mode & 0o222 == 0
        assert (bundle / "critic").stat().st_mode & 0o022 == 0
        assert (bundle / "critic").stat().st_uid in {0, os.geteuid()}


def test_retirement_never_deletes_a_pinned_bundle(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    executable(source, "driver", "exit 0")
    root = tmp_path / "trust"
    first = install(source, root, "old", {"driver": "driver"})
    executable(source, "driver", "exit 1")
    install(source, root, "new", {"driver": "driver"})

    result = retire_bundle(root, first["bundle_id"], owner_uid=os.geteuid())

    assert result == {"bundle_id": first["bundle_id"], "retired": True, "deleted": False}
    assert (root / "bundles" / first["bundle_id"]).is_dir()
    assert verify_bundle_pin(first)["ok"] is True


def test_source_symlinks_are_rejected_without_following_them(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    outside = executable(tmp_path, "outside", "exit 0")
    (source / "linked").symlink_to(outside)

    with pytest.raises(TrustBundleError) as error:
        install(source, tmp_path / "trust", "v1", {"driver": "linked"})

    assert error.value.code == "untrusted_bundle_source"


def test_open_source_fd_defeats_path_replacement_during_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    original = executable(source, "driver", "echo original")
    replacement = executable(source, "replacement", "echo replacement")
    original_bytes = original.read_bytes()
    real_read = trust_bundles.os.read
    replaced = False

    def racing_read(fd: int, size: int) -> bytes:
        nonlocal replaced
        chunk = real_read(fd, size)
        if chunk and not replaced:
            replaced = True
            replacement.replace(original)
        return chunk

    monkeypatch.setattr(trust_bundles.os, "read", racing_read)
    pin = install(source, tmp_path / "trust", "v1", {"driver": "driver"})

    assert Path(pin["executables"]["driver"]["path"]).read_bytes() == original_bytes
    assert verify_bundle_pin(pin)["ok"] is True


def test_verifier_reports_all_replacement_and_permission_failures(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    executable(source, "driver", "echo safe")
    root = tmp_path / "trust"
    pin = install(source, root, "v1", {"driver": "driver"})
    bundle = root / "bundles" / pin["bundle_id"]
    target = bundle / "driver"
    bundle.chmod(0o755)
    target.unlink()
    target.write_text("replaced", encoding="utf-8")
    target.chmod(0o777)

    health = verify_bundle_pin(pin)

    assert health["ok"] is False
    assert any("group/world-writable" in item for item in health["errors"])
    assert any("inode mismatch" in item for item in health["errors"])
    assert any("digest mismatch" in item for item in health["errors"])
    assert any("size mismatch" in item for item in health["errors"])
