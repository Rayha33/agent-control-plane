from __future__ import annotations

import copy
import errno
import fcntl
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urljoin

import pytest
from jsonschema import Draft4Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT4

import agent_control_plane.supervisor.oci_worker as oci_worker
from agent_control_plane.supervisor.common import SupervisorError
from agent_control_plane.supervisor.oci_worker import (
    build_oci_worker_config,
    build_runc_run_argv,
)
from agent_control_plane.supervisor.sandbox_workspace import Snapshot, copy_snapshot

_OCI_SCHEMA_DIR = Path(__file__).parent / "data" / "oci-runtime-spec-v1.2.1"
_OCI_SCHEMA_FILES = (
    "config-schema.json",
    "config-linux.json",
    "defs.json",
    "defs-linux.json",
)
_OCI_SCHEMA_SHA256 = {
    "config-schema.json": "2fd3af83c22f3d1420d42c139462b7f35012ceea402a9a47f090695a5aea84e2",
    "config-linux.json": "ca172a5dbe1242ddde4316cea5568130c552649569b0cc65860910949d529737",
    "defs.json": "9b2420b3f02970e14533f9506b6590f5b405aad8c45dd8871bd129574ee316bb",
    "defs-linux.json": "bb1c6346f7bd683e38389ea489b730e94ad92c3030113d28499ce76bd6e5e73a",
}


def _pinned_oci_schema_validator() -> Draft4Validator:
    schema_dir = _OCI_SCHEMA_DIR.resolve()
    base_uri = schema_dir.as_uri() + "/"
    documents: dict[str, dict] = {}
    resources = []
    for name in _OCI_SCHEMA_FILES:
        schema_bytes = (schema_dir / name).read_bytes()
        digest = hashlib.sha256(schema_bytes).hexdigest()
        assert digest == _OCI_SCHEMA_SHA256[name], f"pinned OCI schema digest mismatch: {name}"
        document = json.loads(schema_bytes)
        # The upstream platform schemas omit an identifier. Anchor their local
        # references to this vendored directory without changing validation rules.
        document.setdefault("id", urljoin(base_uri, name))
        documents[name] = document
        resources.append(
            (
                urljoin(base_uri, name),
                Resource.from_contents(document, default_specification=DRAFT4),
            )
        )
    registry = Registry().with_resources(resources)
    return Draft4Validator(documents["config-schema.json"], registry=registry)


def oci_fixture(tmp_path: Path) -> tuple[Path, Snapshot]:
    bundle = tmp_path / "attempt" / "bundle"
    rootfs = bundle / "rootfs"
    bundle.mkdir(parents=True, mode=0o700)
    for relative in ("bin", "proc", "workspace", "tmp", "home/agent"):
        (rootfs / relative).mkdir(parents=True, exist_ok=True)
    shell = rootfs / "bin" / "sh"
    shell.write_text("fixture shell\n")
    shell.chmod(0o700)
    executable = rootfs / "usr" / "bin" / "busybox"
    executable.parent.mkdir(parents=True)
    executable.write_text("fixture executable\n")
    executable.chmod(0o700)
    workspace = tmp_path / "attempt" / "workspace"
    workspace.mkdir(mode=0o700)
    snapshot = copy_snapshot(workspace, tmp_path / "attempt" / "validated-workspace")
    return bundle, snapshot


def _pin_test_rootfs(rootfs: Path) -> oci_worker._TrustedRootfs:
    manifest = oci_worker.rootfs_tree_manifest(rootfs)
    return oci_worker._pin_trusted_rootfs(
        rootfs,
        manifest["rootfs_sha256"],
        expected_closure_sha256=manifest["closure_sha256"],
    )


def compile_config(bundle: Path, workspace: Snapshot) -> dict:
    rootfs = bundle / "rootfs"
    rootfs_pin = _pin_test_rootfs(rootfs)
    return build_oci_worker_config(
        bundle,
        workspace,
        ("/usr/bin/busybox", "sh", "-c", "printf ready > /workspace/result.txt"),
        rootfs_pin=rootfs_pin,
        container_id="acp-worker-123",
        memory_bytes=256 * 1024 * 1024,
        pids_limit=32,
        cpu_quota_us=100_000,
    )


def test_rootfs_tree_digest_is_deterministic_and_binds_file_content(tmp_path: Path) -> None:
    bundle, _workspace = oci_fixture(tmp_path)
    rootfs = bundle / "rootfs"

    first = oci_worker.rootfs_tree_sha256(rootfs)
    assert first == oci_worker.rootfs_tree_sha256(rootfs)

    executable = rootfs / "usr" / "bin" / "busybox"
    executable.write_text("changed fixture executable\n", encoding="ascii")
    assert oci_worker.rootfs_tree_sha256(rootfs) != first


def test_rootfs_tree_digest_binds_mode_and_symlink_target(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    first_file = rootfs / "first"
    second_file = rootfs / "second"
    first_file.write_text("one\n", encoding="ascii")
    second_file.write_text("two\n", encoding="ascii")
    link = rootfs / "current"
    link.symlink_to("first")

    original = oci_worker.rootfs_tree_sha256(rootfs)
    first_file.chmod(0o600)
    changed_mode = oci_worker.rootfs_tree_sha256(rootfs)
    assert changed_mode != original

    link.unlink()
    link.symlink_to("second")
    assert oci_worker.rootfs_tree_sha256(rootfs) != changed_mode


def test_rootfs_manifest_lists_paths_metadata_and_hashes_not_file_contents(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    secret_like_content = "private sentinel content that must not appear"
    file_path = rootfs / "bin" / "tool"
    file_path.parent.mkdir()
    file_path.write_text(secret_like_content, encoding="utf-8")
    file_path.chmod(0o755)
    (rootfs / "tool-current").symlink_to("bin/tool")

    manifest = oci_worker.rootfs_tree_manifest(rootfs)
    encoded = json.dumps(manifest, ensure_ascii=True, sort_keys=True)
    entries = {entry["path"]: entry for entry in manifest["entries"]}

    assert manifest["schema"] == "acp-oci-rootfs-closure-v1"
    assert manifest["rootfs_sha256"] == oci_worker.rootfs_tree_sha256(rootfs)
    assert (
        manifest["closure_sha256"]
        == hashlib.sha256(oci_worker._canonical_rootfs_closure(manifest["entries"])).hexdigest()
    )
    assert entries["bin/tool"]["mode"] == 0o755
    assert (
        entries["bin/tool"]["content_sha256"]
        == hashlib.sha256(secret_like_content.encode("utf-8")).hexdigest()
    )
    assert entries["tool-current"]["target"] == "bin/tool"
    assert secret_like_content not in encoded


def test_rootfs_manifest_is_stable_across_entry_creation_order(tmp_path: Path) -> None:
    first = tmp_path / "first-rootfs"
    second = tmp_path / "second-rootfs"
    first.mkdir()
    second.mkdir()
    for name in ("zeta", "alpha"):
        (first / name).write_text(name, encoding="ascii")
    for name in ("alpha", "zeta"):
        (second / name).write_text(name, encoding="ascii")

    assert oci_worker.rootfs_tree_manifest(first) == oci_worker.rootfs_tree_manifest(second)


@pytest.mark.skipif(
    sys.platform != "linux", reason="target Linux filesystems permit arbitrary path bytes"
)
def test_rootfs_manifest_round_trips_non_utf8_path_bytes(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    raw_name = b"tool-\xff"
    (rootfs / os.fsdecode(raw_name)).write_text("fixture", encoding="ascii")

    manifest = oci_worker.rootfs_tree_manifest(rootfs)
    encoded = json.dumps(manifest, ensure_ascii=True)
    decoded = json.loads(encoded)
    entry = next(entry for entry in decoded["entries"] if entry["type"] == "file")

    assert os.fsencode(entry["path"]) == raw_name
    assert decoded["closure_sha256"] == manifest["closure_sha256"]


def test_rootfs_pin_requires_the_reviewed_closure_digest(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "tool").write_text("fixture", encoding="ascii")
    manifest = oci_worker.rootfs_tree_manifest(rootfs)

    with pytest.raises(SupervisorError, match="closure digest does not match") as error:
        oci_worker._pin_trusted_rootfs(
            rootfs,
            manifest["rootfs_sha256"],
            expected_closure_sha256="0" * 64,
        )

    assert error.value.code == "invalid_oci_rootfs"


def test_rootfs_digest_enforces_byte_depth_and_path_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "large").write_bytes(b"12")
    monkeypatch.setattr(oci_worker, "_MAX_ROOTFS_BYTES", 1)
    with pytest.raises(SupervisorError, match="byte limit"):
        oci_worker.rootfs_tree_sha256(rootfs)

    (rootfs / "large").unlink()
    (rootfs / "long").mkdir()
    monkeypatch.setattr(oci_worker, "_MAX_ROOTFS_BYTES", 8 * 1024 * 1024 * 1024)
    monkeypatch.setattr(oci_worker, "_MAX_ROOTFS_PATH_BYTES", 3)
    with pytest.raises(SupervisorError, match="path exceeds its limit"):
        oci_worker.rootfs_tree_sha256(rootfs)

    monkeypatch.setattr(oci_worker, "_MAX_ROOTFS_PATH_BYTES", 4096)
    monkeypatch.setattr(oci_worker, "_MAX_ROOTFS_DEPTH", 0)
    with pytest.raises(SupervisorError, match="nesting exceeds its limit"):
        oci_worker.rootfs_tree_sha256(rootfs)


@pytest.mark.parametrize(
    ("state", "message"),
    (("present", "file capabilities"), ("unknown", "capability state is unknown")),
)
def test_rootfs_file_capability_check_fails_closed(
    monkeypatch: pytest.MonkeyPatch, state: str, message: str
) -> None:
    monkeypatch.setattr(oci_worker.platform, "system", lambda: "Linux")

    def getxattr(_descriptor: int, attribute: str) -> bytes:
        assert attribute == "security.capability"
        if state == "present":
            return b"capability"
        raise OSError(errno.EIO, "capability state unavailable")

    monkeypatch.setattr(oci_worker.os, "getxattr", getxattr, raising=False)

    with pytest.raises(SupervisorError, match=message) as error:
        oci_worker._check_rootfs_file_capability(123)

    assert error.value.code == "invalid_oci_rootfs"


def test_rootfs_entry_limit_aborts_scandir_before_materializing_extra_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    names_read = 0

    class Entry:
        @property
        def name(self) -> str:
            nonlocal names_read
            names_read += 1
            return f"entry-{names_read:06d}"

    class Scandir:
        def __enter__(self) -> Scandir:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def __iter__(self):
            return (Entry() for _ in range(oci_worker._MAX_ROOTFS_ENTRIES + 1))

    monkeypatch.setattr(oci_worker.os, "scandir", lambda _directory: Scandir())

    with pytest.raises(SupervisorError, match="too many entries"):
        oci_worker.rootfs_tree_sha256(rootfs)

    assert names_read == oci_worker._MAX_ROOTFS_ENTRIES


def test_rootfs_mountinfo_rejects_same_device_nested_bind_mount_and_decodes_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rootfs = tmp_path / "root fs"
    nested = rootfs / "usr mount"
    nested.mkdir(parents=True)

    def escape_mountpoint(path: Path) -> bytes:
        return os.fsencode(path).replace(b"\\", b"\\134").replace(b" ", b"\\040")

    root_mount = escape_mountpoint(rootfs)
    nested_mount = escape_mountpoint(nested)
    mountinfo = (
        b"36 25 0:42 / " + root_mount + b" rw - ext4 /dev/loop0 rw\n"
        b"37 36 0:42 /usr " + nested_mount + b" rw - ext4 /dev/loop0 rw\n"
    )
    monkeypatch.setattr(oci_worker.platform, "system", lambda: "Linux")
    monkeypatch.setattr(oci_worker, "_read_linux_mountinfo", lambda: mountinfo)

    with pytest.raises(SupervisorError, match="nested mount") as error:
        oci_worker.rootfs_tree_sha256(rootfs)

    assert error.value.code == "invalid_oci_rootfs"


def test_rootfs_mount_table_change_during_scan_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    root_mount = os.fsencode(rootfs)
    first = b"36 25 0:42 / " + root_mount + b" rw - ext4 /dev/loop0 rw\n"
    second = first.replace(b"36 25", b"37 25", 1)
    snapshots = iter((first, second))
    monkeypatch.setattr(oci_worker.platform, "system", lambda: "Linux")
    monkeypatch.setattr(oci_worker, "_read_linux_mountinfo", lambda: next(snapshots))
    monkeypatch.setattr(oci_worker, "_check_rootfs_posix_acl", lambda _descriptor: None)
    monkeypatch.setattr(oci_worker, "_check_rootfs_file_capability", lambda _descriptor: None)

    with pytest.raises(SupervisorError, match="mount table changed") as error:
        oci_worker.rootfs_tree_sha256(rootfs)

    assert error.value.code == "invalid_oci_rootfs"


def test_rootfs_digest_rejects_directory_default_acl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle, _workspace = oci_fixture(tmp_path)
    rootfs = bundle / "rootfs"
    acl_directory = rootfs / "home"
    acl_inode = acl_directory.stat().st_ino
    monkeypatch.setattr(oci_worker.platform, "system", lambda: "Linux")
    mountinfo = (
        b"36 25 0:42 / "
        + os.fsencode(rootfs).replace(b"\\", b"\\134").replace(b" ", b"\\040")
        + b" rw - ext4 /dev/loop0 rw\n"
    )
    monkeypatch.setattr(oci_worker, "_read_linux_mountinfo", lambda: mountinfo)

    def getxattr(descriptor: int, attribute: str) -> bytes:
        if attribute == "system.posix_acl_default" and os.fstat(descriptor).st_ino == acl_inode:
            return b"acl"
        if attribute == "security.capability":
            raise OSError(errno.ENODATA, "no file capability")
        raise OSError(errno.ENODATA, "no POSIX ACL")

    monkeypatch.setattr(oci_worker.os, "getxattr", getxattr, raising=False)

    with pytest.raises(SupervisorError, match="POSIX ACL") as error:
        oci_worker.rootfs_tree_sha256(rootfs)

    assert error.value.code == "invalid_oci_rootfs"


def test_rootfs_pin_retains_inode_observed_by_tree_scan_when_path_is_swapped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "image.txt").write_text("trusted image\n", encoding="ascii")
    digest = oci_worker.rootfs_tree_sha256(rootfs)
    manifest = oci_worker.rootfs_tree_manifest(rootfs)
    original_measure = oci_worker._measure_rootfs_tree
    scanned_device, scanned_inode = original_measure(rootfs)[1:]
    swapped = False

    def measure_then_swap(path: str | Path, **kwargs: Any) -> tuple[str, int, int]:
        nonlocal swapped
        measurement = original_measure(path, **kwargs)
        if not swapped:
            backup = tmp_path / "rootfs-original"
            os.rename(rootfs, backup)
            shutil.copytree(backup, rootfs)
            swapped = True
        return measurement

    monkeypatch.setattr(oci_worker, "_measure_rootfs_tree", measure_then_swap)
    pin = oci_worker._pin_trusted_rootfs(
        rootfs, digest, expected_closure_sha256=manifest["closure_sha256"]
    )

    assert (pin.device, pin.inode) == (scanned_device, scanned_inode)
    assert pin.inode != rootfs.stat().st_ino
    with pytest.raises(SupervisorError, match="no longer matches its pin"):
        oci_worker._verify_trusted_rootfs(pin)


def test_rootfs_verification_rejects_path_swap_between_resolution_and_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "image.txt").write_text("trusted image\n", encoding="ascii")
    digest = oci_worker.rootfs_tree_sha256(rootfs)
    manifest = oci_worker.rootfs_tree_manifest(rootfs)
    pin = oci_worker._pin_trusted_rootfs(
        rootfs, digest, expected_closure_sha256=manifest["closure_sha256"]
    )
    original_measure = oci_worker._measure_rootfs_tree
    swapped = False

    def swap_then_measure(path: str | Path, **kwargs: Any) -> tuple[str, int, int]:
        nonlocal swapped
        if not swapped:
            backup = tmp_path / "rootfs-original"
            os.rename(rootfs, backup)
            shutil.copytree(backup, rootfs)
            swapped = True
        return original_measure(path, **kwargs)

    monkeypatch.setattr(oci_worker, "_measure_rootfs_tree", swap_then_measure)

    with pytest.raises(SupervisorError, match="no longer matches its pin") as error:
        oci_worker._verify_trusted_rootfs(pin)

    assert error.value.code == "invalid_oci_rootfs"


def test_rootfs_tree_digest_rejects_escaping_symlinks(tmp_path: Path) -> None:
    bundle, _workspace = oci_fixture(tmp_path)
    rootfs = bundle / "rootfs"
    (rootfs / "etc").mkdir()
    (rootfs / "etc" / "escape").symlink_to("../../outside")

    with pytest.raises(SupervisorError, match="escaping symlink") as error:
        oci_worker.rootfs_tree_sha256(rootfs)

    assert error.value.code == "invalid_oci_rootfs"


def test_rootfs_tree_digest_rejects_hardlinks_and_special_files(tmp_path: Path) -> None:
    bundle, _workspace = oci_fixture(tmp_path)
    rootfs = bundle / "rootfs"
    linked = rootfs / "usr" / "bin" / "linked-busybox"
    os.link(rootfs / "usr" / "bin" / "busybox", linked)
    with pytest.raises(SupervisorError, match="hard-linked file"):
        oci_worker.rootfs_tree_sha256(rootfs)

    linked.unlink()
    fifo = rootfs / "usr" / "bin" / "worker-fifo"
    os.mkfifo(fifo)
    with pytest.raises(SupervisorError, match="special file") as error:
        oci_worker.rootfs_tree_sha256(rootfs)

    assert error.value.code == "invalid_oci_rootfs"


def test_rootfs_pin_rejects_digest_mismatch_and_repository_path(tmp_path: Path) -> None:
    bundle, _workspace = oci_fixture(tmp_path)
    rootfs = bundle / "rootfs"
    digest = oci_worker.rootfs_tree_sha256(rootfs)

    with pytest.raises(SupervisorError, match="digest does not match"):
        oci_worker._pin_trusted_rootfs(rootfs, "0" * 64)

    with pytest.raises(SupervisorError, match="outside the repository"):
        oci_worker._pin_trusted_rootfs(rootfs, digest, tmp_path)


def test_rootfs_pin_rejects_a_path_that_contains_the_repository(tmp_path: Path) -> None:
    rootfs = tmp_path / "container-root"
    repository = rootfs / "project"
    repository.mkdir(parents=True)
    (rootfs / "image.txt").write_text("image\n", encoding="ascii")
    digest = oci_worker.rootfs_tree_sha256(rootfs)

    with pytest.raises(SupervisorError, match="disjoint") as error:
        oci_worker._pin_trusted_rootfs(rootfs, digest, repository)

    assert error.value.code == "invalid_oci_rootfs"


def test_rootfs_pin_revalidates_content_before_bundle_compilation(tmp_path: Path) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    rootfs = bundle / "rootfs"
    pin = _pin_test_rootfs(rootfs)
    (rootfs / "usr" / "bin" / "busybox").write_text("substituted\n", encoding="ascii")

    with pytest.raises(SupervisorError, match="no longer matches its pin") as error:
        build_oci_worker_config(
            bundle,
            workspace,
            ("/usr/bin/busybox",),
            rootfs_pin=pin,
            container_id="acp-worker-123",
            memory_bytes=256 * 1024 * 1024,
            pids_limit=32,
            cpu_quota_us=100_000,
        )

    assert error.value.code == "invalid_oci_rootfs"


def test_rootfs_pin_rejects_a_caller_constructed_handle(tmp_path: Path) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    rootfs = bundle / "rootfs"
    pin = _pin_test_rootfs(rootfs)
    forged = oci_worker._TrustedRootfs(pin.path, pin.sha256, pin.device, pin.inode)

    with pytest.raises(SupervisorError, match="trusted supervisor configuration") as error:
        build_oci_worker_config(
            bundle,
            workspace,
            ("/usr/bin/busybox",),
            rootfs_pin=forged,
            container_id="acp-worker-123",
            memory_bytes=256 * 1024 * 1024,
            pids_limit=32,
            cpu_quota_us=100_000,
        )

    assert error.value.code == "invalid_oci_rootfs"


def test_bundle_rootfs_copy_must_match_configured_rootfs_pin(tmp_path: Path) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    source = tmp_path / "trusted-rootfs"
    shutil.copytree(bundle / "rootfs", source)
    pin = _pin_test_rootfs(source)
    (bundle / "rootfs" / "usr" / "bin" / "busybox").write_text(
        "substituted copy\n", encoding="ascii"
    )

    with pytest.raises(
        SupervisorError, match="does not match the configured rootfs and closure pins"
    ) as error:
        build_oci_worker_config(
            bundle,
            workspace,
            ("/usr/bin/busybox",),
            rootfs_pin=pin,
            container_id="acp-worker-123",
            memory_bytes=256 * 1024 * 1024,
            pids_limit=32,
            cpu_quota_us=100_000,
        )

    assert error.value.code == "invalid_oci_rootfs"


def test_bundle_rootfs_copy_accepts_matching_tree_and_closure_pins(tmp_path: Path) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    source = tmp_path / "trusted-rootfs"
    shutil.copytree(bundle / "rootfs", source)
    pin = _pin_test_rootfs(source)

    config = build_oci_worker_config(
        bundle,
        workspace,
        ("/usr/bin/busybox",),
        rootfs_pin=pin,
        container_id="acp-worker-123",
        memory_bytes=256 * 1024 * 1024,
        pids_limit=32,
        cpu_quota_us=100_000,
    )

    assert config["root"] == {"path": "rootfs", "readonly": True}


def pinned_runc(repo_root: Path) -> oci_worker._TrustedRuncExecutable:
    return oci_worker._pin_trusted_runc_executable("/bin/sh", repo_root)


def test_runc_version_probe_requires_the_exact_release_and_uses_a_clean_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pin = pinned_runc(tmp_path)
    calls: list[tuple[list[str], dict]] = []
    monkeypatch.setattr(oci_worker, "_supports_runc_fd_exec", lambda: True)

    def fake_run(argv: list[str], **kwargs) -> tuple[int, str]:
        descriptor = kwargs["exec_fd"]
        os.fstat(descriptor)
        assert argv == [str(pin.path), "--version"]
        calls.append((argv, kwargs))
        return 0, "runc version 1.3.5\nspec: 1.2.1\n"

    monkeypatch.setattr(oci_worker, "_run_bounded_command", fake_run)

    assert oci_worker._probe_trusted_runc_version(pin, "1.3.5") == "1.3.5"
    argv, kwargs = calls[0]
    assert argv[1] == "--version"
    assert len(kwargs["pass_fds"]) == 1
    assert kwargs["exec_fd"] == kwargs["pass_fds"][0]
    assert kwargs["env"] == {
        "LC_ALL": "C",
        "LANG": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    }
    assert kwargs["cwd"] == "/"
    assert kwargs["timeout_seconds"] == 5.0
    assert kwargs["max_output_bytes"] == 8192


@pytest.mark.parametrize(
    ("stdout", "returncode", "expected_version"),
    [
        ("runc version 1.3.5\nspec: 1.2.1", 0, "1.3.4"),
        ("runc version 1.3.5-rc1", 0, "1.3.5"),
        ("not runc", 0, "1.3.5"),
        ("runc version 1.3.5", 1, "1.3.5"),
    ],
)
def test_runc_version_probe_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stdout: str,
    returncode: int,
    expected_version: str,
) -> None:
    pin = pinned_runc(tmp_path)
    monkeypatch.setattr(oci_worker, "_supports_runc_fd_exec", lambda: True)
    monkeypatch.setattr(
        oci_worker,
        "_run_bounded_command",
        lambda argv, **kwargs: (returncode, stdout),
    )

    with pytest.raises(SupervisorError) as error:
        oci_worker._probe_trusted_runc_version(pin, expected_version)

    assert error.value.code == "invalid_oci_runtime_version"


@pytest.mark.skipif(os.name != "posix", reason="OCI runtime probes require POSIX process groups")
def test_bounded_runc_probe_kills_descendants_that_hold_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kill_groups: list[tuple[int, int]] = []
    real_killpg = oci_worker.os.killpg

    def record_killpg(process_group: int, sig: int) -> None:
        kill_groups.append((process_group, sig))
        real_killpg(process_group, sig)

    monkeypatch.setattr(oci_worker.os, "killpg", record_killpg)
    started = time.monotonic()

    with pytest.raises(TimeoutError, match="deadline"):
        oci_worker._run_bounded_command(
            ["/bin/sh", "-c", "sleep 30 & exit 0"],
            cwd="/",
            env={"PATH": "/usr/bin:/bin"},
            timeout_seconds=0.2,
            max_output_bytes=1024,
        )

    assert time.monotonic() - started < 2
    assert len(kill_groups) == 1


@pytest.mark.skipif(os.name != "posix", reason="OCI runtime probes require POSIX file descriptors")
def test_bounded_command_passes_only_requested_fds_through_guardian() -> None:
    trusted_fd = os.open("/bin/sh", os.O_RDONLY)
    unrequested_fd = os.open("/bin/echo", os.O_RDONLY)
    try:
        returncode, stdout = oci_worker._run_bounded_command(
            [
                sys.executable,
                "-I",
                "-S",
                "-c",
                "import os, sys; os.fstat(int(sys.argv[1])); "
                "exec('try:\\n os.fstat(int(sys.argv[2]))\\nexcept OSError:\\n print(\"only-requested-fd\")')",
                str(trusted_fd),
                str(unrequested_fd),
            ],
            cwd="/",
            env={"PATH": "/usr/bin:/bin"},
            timeout_seconds=2,
            max_output_bytes=128,
            pass_fds=(trusted_fd,),
        )
    finally:
        os.close(trusted_fd)
        os.close(unrequested_fd)

    assert returncode == 0
    assert stdout.strip() == "only-requested-fd"


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="fd-based execve is supported by the Linux OCI lane",
)
def test_guardian_execs_held_inode_after_its_path_is_replaced(tmp_path: Path) -> None:
    executable = tmp_path / "probe"
    replacement = tmp_path / "replacement"
    executable.write_text("#!/bin/sh\nprintf original-inode\n", encoding="utf-8")
    replacement.write_text("#!/bin/sh\nprintf replacement-path\n", encoding="utf-8")
    executable.chmod(0o700)
    replacement.chmod(0o700)
    descriptor = os.open(executable, os.O_RDONLY)
    os.replace(replacement, executable)
    try:
        returncode, stdout = oci_worker._run_bounded_command(
            [str(executable)],
            cwd=str(tmp_path),
            env={"PATH": "/usr/bin:/bin"},
            timeout_seconds=2,
            max_output_bytes=128,
            pass_fds=(descriptor,),
            exec_fd=descriptor,
        )
    finally:
        os.close(descriptor)

    assert returncode == 0
    assert stdout == "original-inode"


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="fd-based execve is supported by the Linux OCI lane",
)
def test_guardian_fd_exec_preserves_nonzero_exit_status(tmp_path: Path) -> None:
    executable = tmp_path / "nonzero-probe"
    executable.write_text("#!/bin/sh\nprintf nonzero-status\nexit 23\n", encoding="utf-8")
    executable.chmod(0o700)
    descriptor = os.open(executable, os.O_RDONLY)
    try:
        returncode, stdout = oci_worker._run_bounded_command(
            [str(executable)],
            cwd=str(tmp_path),
            env={"PATH": "/usr/bin:/bin"},
            timeout_seconds=2,
            max_output_bytes=128,
            pass_fds=(descriptor,),
            exec_fd=descriptor,
        )
    finally:
        os.close(descriptor)

    assert returncode == 23
    assert stdout == "nonzero-status"


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="fd-based execve is supported by the Linux OCI lane",
)
def test_guardian_fd_exec_timeout_kills_and_reaps_the_group(tmp_path: Path) -> None:
    executable = tmp_path / "timeout-probe"
    executable.write_text("#!/bin/sh\nsleep 30\n", encoding="utf-8")
    executable.chmod(0o700)
    descriptor = os.open(executable, os.O_RDONLY)
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError, match="deadline"):
            oci_worker._run_bounded_command(
                [str(executable)],
                cwd=str(tmp_path),
                env={"PATH": "/usr/bin:/bin"},
                timeout_seconds=0.2,
                max_output_bytes=128,
                pass_fds=(descriptor,),
                exec_fd=descriptor,
            )
    finally:
        os.close(descriptor)

    assert time.monotonic() - started < 2


@pytest.mark.skipif(
    sys.platform.startswith("linux"), reason="Linux supports descriptor-based OCI probes"
)
def test_runc_version_probe_fails_closed_without_linux_fd_exec(tmp_path: Path) -> None:
    pin = pinned_runc(tmp_path)

    with pytest.raises(SupervisorError, match="require Linux fd-based execve") as error:
        oci_worker._probe_trusted_runc_version(pin, "1.3.5")

    assert error.value.code == "invalid_oci_runtime_version"


def test_open_runc_fd_rejects_inode_replaced_after_initial_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pin = pinned_runc(tmp_path)
    real_open = os.open

    def replaced_open(path, flags, *args, **kwargs):
        if Path(path) == pin.path:
            return real_open("/bin/echo", flags, *args, **kwargs)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(oci_worker, "_verify_trusted_runc_executable", lambda _pin: pin.path)
    monkeypatch.setattr(oci_worker.os, "open", replaced_open)

    with pytest.raises(SupervisorError, match="changed while being pinned") as error:
        oci_worker._open_verified_runc_executable(pin)

    assert error.value.code == "invalid_oci_runtime"


@pytest.mark.skipif(os.name != "posix", reason="OCI runtime probes require POSIX process groups")
def test_bounded_runc_probe_caps_combined_stdout_and_stderr() -> None:
    with pytest.raises(ValueError, match="output limit"):
        oci_worker._run_bounded_command(
            ["/bin/sh", "-c", "exec /usr/bin/yes probe-output"],
            cwd="/",
            env={"PATH": "/usr/bin:/bin"},
            timeout_seconds=2,
            max_output_bytes=128,
        )


@pytest.mark.skipif(os.name != "posix", reason="OCI runtime probes require POSIX process groups")
def test_bounded_command_terminates_child_that_closes_pipes_before_exit() -> None:
    started = time.monotonic()

    with pytest.raises(TimeoutError, match="deadline"):
        oci_worker._run_bounded_command(
            ["/bin/sh", "-c", "exec 1>&- 2>&-; sleep 30"],
            cwd="/",
            env={"PATH": "/usr/bin:/bin"},
            timeout_seconds=0.2,
            max_output_bytes=128,
        )

    assert time.monotonic() - started < 2


@pytest.mark.skipif(os.name != "posix", reason="OCI runtime probes require POSIX process groups")
def test_bounded_runc_probe_invalid_utf8_kills_process_group_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup_calls: list[int] = []
    real_cleanup = oci_worker._kill_process_group

    def record_cleanup(process) -> int:
        cleanup_calls.append(process.pid)
        return real_cleanup(process)

    monkeypatch.setattr(oci_worker, "_kill_process_group", record_cleanup)

    with pytest.raises(UnicodeDecodeError):
        oci_worker._run_bounded_command(
            ["/bin/sh", "-c", "printf '\\377'"],
            cwd="/",
            env={"PATH": "/usr/bin:/bin"},
            timeout_seconds=2,
            max_output_bytes=16,
        )

    assert len(cleanup_calls) == 1


@pytest.mark.skipif(os.name != "posix", reason="OCI runtime probes require POSIX process groups")
def test_bounded_runc_probe_releases_live_guardian_after_command_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kill_groups: list[tuple[int, int]] = []
    real_killpg = oci_worker.os.killpg

    def record_killpg(process_group: int, sig: int) -> None:
        kill_groups.append((process_group, sig))
        real_killpg(process_group, sig)

    monkeypatch.setattr(oci_worker.os, "killpg", record_killpg)

    returncode, stdout = oci_worker._run_bounded_command(
        ["/bin/sh", "-c", "printf 'probe complete'"],
        cwd="/",
        env={"PATH": "/usr/bin:/bin"},
        timeout_seconds=2,
        max_output_bytes=32,
    )

    assert returncode == 0
    assert stdout == "probe complete"
    assert len(kill_groups) == 1


@pytest.mark.skipif(os.name != "posix", reason="OCI runtime probes require POSIX process groups")
def test_bounded_runc_probe_kills_descendants_that_redirect_both_pipes() -> None:
    returncode, stdout = oci_worker._run_bounded_command(
        ["/bin/sh", "-c", 'sleep 30 </dev/null >/dev/null 2>&1 & echo "$!"; exit 0'],
        cwd="/",
        env={"PATH": "/usr/bin:/bin"},
        timeout_seconds=2,
        max_output_bytes=32,
    )
    descendant_pid = int(stdout.strip())

    def descendant_is_running() -> bool:
        status = subprocess.run(
            ["ps", "-o", "stat=", "-p", str(descendant_pid)],
            capture_output=True,
            check=False,
            text=True,
            timeout=1,
        ).stdout.strip()
        return bool(status) and not status.startswith("Z")

    deadline = time.monotonic() + 2
    while descendant_is_running() and time.monotonic() < deadline:
        time.sleep(0.01)

    assert returncode == 0
    assert not descendant_is_running(), f"probe descendant {descendant_pid} is still running"


@pytest.mark.skipif(os.name != "posix", reason="OCI runtime probes require POSIX process groups")
def test_bounded_runc_guardian_watchdog_reaps_when_parent_cleanup_stalls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guardian_waits: list[int] = []

    def defer_parent_cleanup(process) -> int:
        guardian_waits.append(process.pid)
        try:
            return process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            # A failed watchdog must not strand the guardian. The wait timeout
            # proves it is still unreaped, so its process-group ID is reserved.
            try:
                os.killpg(process.pid, oci_worker.signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.kill()
            process.wait(timeout=1)
            raise

    monkeypatch.setattr(oci_worker, "_kill_process_group", defer_parent_cleanup)
    returncode, stdout = oci_worker._run_bounded_command(
        ["/bin/sh", "-c", "printf 'guardian proof'"],
        cwd="/",
        env={"PATH": "/usr/bin:/bin"},
        timeout_seconds=1,
        max_output_bytes=32,
    )

    assert returncode == 0
    assert stdout == "guardian proof"
    assert len(guardian_waits) == 1


@pytest.mark.skipif(os.name != "posix", reason="OCI runtime probes require POSIX process groups")
def test_bounded_runc_probe_selector_failure_precedes_child_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launches: list[bool] = []

    def fail_selector():
        raise OSError("injected selector exhaustion")

    def record_launch(*args, **kwargs):
        launches.append(True)
        raise AssertionError("selector must be created before launching the child")

    monkeypatch.setattr(oci_worker.selectors, "DefaultSelector", fail_selector)
    monkeypatch.setattr(oci_worker.subprocess, "Popen", record_launch)

    with pytest.raises(OSError, match="selector exhaustion"):
        oci_worker._run_bounded_command(
            ["/bin/sh", "-c", "exit 0"],
            cwd="/",
            env={"PATH": "/usr/bin:/bin"},
            timeout_seconds=2,
            max_output_bytes=16,
        )

    assert not launches


@pytest.mark.skipif(os.name != "posix", reason="OCI runtime probes require POSIX process groups")
def test_bounded_runc_probe_post_launch_setup_failure_reaps_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup_calls: list[int] = []
    real_cleanup = oci_worker._kill_process_group

    def record_cleanup(process):
        cleanup_calls.append(process.pid)
        return real_cleanup(process)

    real_set_blocking = oci_worker.os.set_blocking
    set_blocking_calls = 0

    def fail_on_output_set_blocking(descriptor: int, blocking: bool) -> None:
        nonlocal set_blocking_calls
        set_blocking_calls += 1
        if set_blocking_calls == 2:
            raise OSError("injected nonblocking setup failure")
        real_set_blocking(descriptor, blocking)

    monkeypatch.setattr(oci_worker, "_kill_process_group", record_cleanup)
    monkeypatch.setattr(oci_worker.os, "set_blocking", fail_on_output_set_blocking)

    with pytest.raises(OSError, match="nonblocking setup failure"):
        oci_worker._run_bounded_command(
            ["/bin/sh", "-c", "exec sleep 30"],
            cwd="/",
            env={"PATH": "/usr/bin:/bin"},
            timeout_seconds=2,
            max_output_bytes=16,
        )

    assert len(cleanup_calls) == 1


def test_compiled_oci_worker_config_matches_pinned_oci_schema(tmp_path: Path) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    config = compile_config(bundle, workspace)
    validator = _pinned_oci_schema_validator()

    errors = sorted(
        validator.iter_errors(config),
        key=lambda error: (tuple(str(part) for part in error.absolute_path), error.message),
    )
    assert not errors, "\n".join(
        f"/{'/'.join(map(str, error.absolute_path))}: {error.message}" for error in errors
    )

    invalid = copy.deepcopy(config)
    invalid["linux"]["resources"]["memory"]["limit"] = "256 MiB"
    assert list(validator.iter_errors(invalid))


def test_oci_policy_encodes_mutable_snapshot_and_private_ephemeral_mounts(
    tmp_path: Path,
) -> None:
    bundle, workspace = oci_fixture(tmp_path)

    config = compile_config(bundle, workspace)

    assert config["ociVersion"] == "1.2.0"
    assert config["root"] == {"path": "rootfs", "readonly": True}
    assert config["process"]["args"] == [
        "/bin/sh",
        "-c",
        oci_worker._LAUNCH_GATE_SCRIPT,
        "acp-launch-gate",
        "/usr/bin/busybox",
        "sh",
        "-c",
        "printf ready > /workspace/result.txt",
    ]
    assert config["process"]["cwd"] == "/workspace"
    assert config["process"]["noNewPrivileges"] is True
    assert config["process"]["rlimits"] == [
        {"type": "RLIMIT_CORE", "hard": 0, "soft": 0},
        {
            "type": "RLIMIT_FSIZE",
            "hard": 64 * 1024 * 1024,
            "soft": 64 * 1024 * 1024,
        },
    ]
    assert all(not caps for caps in config["process"]["capabilities"].values())
    assert set(config["process"]["env"]) == {
        "ACP_PHASE=worker",
        "ACP_REPO_ROOT=/workspace",
        "ACP_RUNTIME_DIR=/tmp/acp-runtime",
        "ACP_WORKTREE=/workspace",
        "HOME=/home/agent",
        "PATH=/usr/bin:/bin",
        "TMPDIR=/tmp",
    }

    mounts = config["mounts"]
    assert {mount["destination"] for mount in mounts} == {
        "/proc",
        "/workspace",
        "/tmp",
        "/home/agent",
    }
    workspace_mount = next(mount for mount in mounts if mount["destination"] == "/workspace")
    assert workspace_mount["source"] == str(workspace.root.resolve())
    assert "rw" in workspace_mount["options"]
    assert "bind" in workspace_mount["options"]
    assert "rprivate" in workspace_mount["options"]
    assert "rbind" not in workspace_mount["options"]
    assert all(mount["type"] != "bind" or mount["destination"] == "/workspace" for mount in mounts)
    assert not any(
        mount.get("source") in {"/etc", "/usr", "/home", "/tmp", "/run", "/var"} for mount in mounts
    )

    linux = config["linux"]
    assert {namespace["type"] for namespace in linux["namespaces"]} == {
        "user",
        "pid",
        "mount",
        "ipc",
        "uts",
        "cgroup",
        "network",
    }
    assert linux["resources"] == {
        "memory": {"limit": 256 * 1024 * 1024},
        "cpu": {"quota": 100_000, "period": 100_000},
        "pids": {"limit": 32},
        "devices": [{"allow": False, "access": "rwm"}],
    }
    assert linux["cgroupsPath"] == "user.slice:acp:acp-worker-123"
    assert linux["rootfsPropagation"] == "private"
    assert "architectures" not in linux["seccomp"]
    assert linux["uidMappings"][0] == {"containerID": 0, "hostID": os.geteuid(), "size": 1}
    assert linux["gidMappings"][0] == {"containerID": 0, "hostID": os.getegid(), "size": 1}


def test_oci_worker_seccomp_profile_is_native_only_and_denies_high_risk_syscalls() -> None:
    profile = oci_worker._worker_seccomp_profile()

    assert profile["defaultAction"] == "SCMP_ACT_ALLOW"
    # The OCI architectures property adds compat ABIs; leaving it absent keeps
    # the runtime's native-only default and avoids re-adding the native ABI.
    assert "architectures" not in profile
    rules = profile["syscalls"]
    denied = next(
        rule for rule in rules if set(rule["names"]) == set(oci_worker._SECCOMP_DENIED_SYSCALLS)
    )
    assert denied["action"] == "SCMP_ACT_ERRNO"
    assert denied["errnoRet"] == 1
    assert {
        "mount",
        "mount_setattr",
        "move_mount",
        "open_tree",
        "pivot_root",
        "setns",
        "unshare",
        "io_uring_setup",
        "io_uring_enter",
        "io_uring_register",
    } <= set(denied["names"])

    clone3 = next(rule for rule in rules if rule["names"] == ["clone3"])
    assert clone3["action"] == "SCMP_ACT_ERRNO"
    assert clone3["errnoRet"] == 38

    clone_rules = [rule for rule in rules if rule["names"] == ["clone"]]
    assert {rule["args"][0]["value"] for rule in clone_rules} == set(
        oci_worker._CLONE_NEW_NAMESPACE_FLAGS
    )
    assert set(oci_worker._CLONE_NEW_NAMESPACE_FLAGS) == {
        0x00000080,  # CLONE_NEWTIME
        0x00020000,  # CLONE_NEWNS
        0x02000000,  # CLONE_NEWCGROUP
        0x04000000,  # CLONE_NEWUTS
        0x08000000,  # CLONE_NEWIPC
        0x10000000,  # CLONE_NEWUSER
        0x20000000,  # CLONE_NEWPID
        0x40000000,  # CLONE_NEWNET
    }
    assert {(rule["args"][0]["value"], rule["args"][0]["valueTwo"]) for rule in clone_rules} == {
        (flag, flag) for flag in oci_worker._CLONE_NEW_NAMESPACE_FLAGS
    }
    assert all(rule["args"][0]["op"] == "SCMP_CMP_MASKED_EQ" for rule in clone_rules)
    assert all(rule["args"][0]["index"] == 0 for rule in clone_rules)

    sockets = next(rule for rule in rules if set(rule["names"]) == {"socket", "socketpair"})
    assert sockets["action"] == "SCMP_ACT_ERRNO"
    assert sockets["errnoRet"] == 1
    assert sockets["args"] == [{"index": 0, "value": 1, "op": "SCMP_CMP_NE"}]


def test_oci_worker_seccomp_profile_rejects_unsupported_native_architecture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(oci_worker.platform, "machine", lambda: "riscv64")

    with pytest.raises(SupervisorError, match="does not support this target architecture") as error:
        oci_worker._worker_seccomp_profile()

    assert error.value.code == "invalid_oci_worker_policy"


def test_oci_policy_launch_gate_fails_closed_and_closes_fd_before_candidate_exec(
    tmp_path: Path,
) -> None:
    bundle, workspace = oci_fixture(tmp_path)

    config = compile_config(bundle, workspace)
    process_args = config["process"]["args"]

    assert process_args[:4] == [
        "/bin/sh",
        "-c",
        oci_worker._LAUNCH_GATE_SCRIPT,
        "acp-launch-gate",
    ]
    assert process_args[4:] == [
        "/usr/bin/busybox",
        "sh",
        "-c",
        "printf ready > /workspace/result.txt",
    ]
    assert "|| exit 125" in process_args[2]
    assert "exec 3<&-" in process_args[2]


@pytest.mark.skipif(os.name != "posix", reason="launch gate requires POSIX inherited descriptors")
def test_launch_gate_waits_for_pipe_release_then_execs_exact_argv(tmp_path: Path) -> None:
    marker = tmp_path / "candidate-started"
    read_fd, write_fd = os.pipe()
    child_read_fd = fcntl.fcntl(read_fd, fcntl.F_DUPFD, 10)
    os.close(read_fd)
    candidate = [
        "/bin/sh",
        "-c",
        'if ( : <&3 ) 2>/dev/null; then exit 17; fi; printf started > "$1"',
        "marker-writer",
        str(marker),
    ]
    argv = [
        "/bin/sh",
        "-c",
        oci_worker._LAUNCH_GATE_SCRIPT,
        "acp-launch-gate",
        *candidate,
    ]
    pid = os.posix_spawn(
        "/bin/sh",
        argv,
        {"PATH": os.environ.get("PATH", "")},
        file_actions=[
            (os.POSIX_SPAWN_DUP2, child_read_fd, 3),
            (os.POSIX_SPAWN_CLOSE, child_read_fd),
            (os.POSIX_SPAWN_CLOSE, write_fd),
        ],
    )
    os.close(child_read_fd)

    finished_status: int | None = None
    started_before_release = False
    release_failed = False
    try:
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline and not marker.exists():
            finished, status = os.waitpid(pid, os.WNOHANG)
            if finished == pid:
                finished_status = status
                break
            time.sleep(0.005)
        started_before_release = marker.exists()
        if finished_status is None and not started_before_release:
            try:
                release = b"release\n"
                release_failed = os.write(write_fd, release) != len(release)
            except BrokenPipeError:
                # Reap below, then fail: a private gate must still be waiting
                # for this authorized release before candidate execution.
                release_failed = True
    finally:
        try:
            os.close(write_fd)
        finally:
            if finished_status is None:
                _, finished_status = os.waitpid(pid, 0)

    assert not started_before_release
    assert not release_failed
    assert os.WIFEXITED(finished_status)
    assert os.WEXITSTATUS(finished_status) == 0
    assert marker.read_text() == "started"


@pytest.mark.skipif(os.name != "posix", reason="launch gate requires POSIX inherited descriptors")
def test_launch_gate_eof_never_execs_candidate(tmp_path: Path) -> None:
    marker = tmp_path / "candidate-started"
    read_fd, write_fd = os.pipe()
    child_read_fd = fcntl.fcntl(read_fd, fcntl.F_DUPFD, 10)
    os.close(read_fd)
    candidate = [
        "/bin/sh",
        "-c",
        'printf started > "$1"',
        "marker-writer",
        str(marker),
    ]
    argv = [
        "/bin/sh",
        "-c",
        oci_worker._LAUNCH_GATE_SCRIPT,
        "acp-launch-gate",
        *candidate,
    ]
    pid = os.posix_spawn(
        "/bin/sh",
        argv,
        {"PATH": os.environ.get("PATH", "")},
        file_actions=[
            (os.POSIX_SPAWN_DUP2, child_read_fd, 3),
            (os.POSIX_SPAWN_CLOSE, child_read_fd),
            (os.POSIX_SPAWN_CLOSE, write_fd),
        ],
    )
    os.close(child_read_fd)
    os.close(write_fd)
    _, status = os.waitpid(pid, 0)

    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 125
    assert not marker.exists()


def test_oci_policy_requires_trusted_shell_in_pinned_rootfs(tmp_path: Path) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    (bundle / "rootfs" / "bin" / "sh").unlink()

    with pytest.raises(SupervisorError, match="worker executable is absent") as error:
        compile_config(bundle, workspace)

    assert error.value.code == "invalid_oci_executable"


@pytest.mark.parametrize(
    ("file_uid", "file_gid", "mode", "allowed"),
    [
        (1000, 3000, 0o100, True),
        (2000, 1000, 0o010, True),
        (2000, 3000, 0o001, True),
        (2000, 3000, 0o100, False),
        (1000, 3000, 0o001, False),
        (2000, 1000, 0o001, False),
        (2000, 3000, 0o010, False),
    ],
)
def test_mapped_execute_permission_uses_owner_then_group_then_other(
    file_uid: int, file_gid: int, mode: int, allowed: bool
) -> None:
    info = SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=file_uid, st_gid=file_gid)

    assert (
        oci_worker._mapped_mode_allows(
            info,
            uid=1000,
            gid=1000,
            owner_bit=stat.S_IXUSR,
            group_bit=stat.S_IXGRP,
            other_bit=stat.S_IXOTH,
        )
        is allowed
    )


@pytest.mark.parametrize(
    ("command", "code"),
    [
        ((), "invalid_command"),
        (("busybox", "sh"), "invalid_command"),
        (("/usr/bin/../bin/busybox",), "invalid_command"),
        (("//workspace/tool",), "invalid_command"),
        (("/workspace//tool",), "invalid_command"),
        (("/workspace/./tool",), "invalid_command"),
        (("/usr/bin/busybox\x00bad",), "invalid_command"),
    ],
)
def test_oci_policy_rejects_ambiguous_or_host_relative_commands(
    tmp_path: Path, command: tuple[str, ...], code: str
) -> None:
    bundle, workspace = oci_fixture(tmp_path)

    with pytest.raises(SupervisorError) as error:
        build_oci_worker_config(
            bundle,
            workspace,
            command,
            rootfs_pin=_pin_test_rootfs(bundle / "rootfs"),
            container_id="acp-worker-123",
            memory_bytes=256 * 1024 * 1024,
            pids_limit=32,
            cpu_quota_us=100_000,
        )

    assert error.value.code == code


def test_oci_policy_rejects_workspace_with_shared_git_metadata(tmp_path: Path) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    (workspace.root / ".git").write_text("gitdir: /shared/repo/.git/worktrees/attempt\n")

    with pytest.raises(SupervisorError, match="Git metadata") as error:
        compile_config(bundle, workspace)

    assert error.value.code == "invalid_oci_workspace"


def test_oci_policy_requires_snapshot_handle_not_an_arbitrary_private_path(
    tmp_path: Path,
) -> None:
    bundle, workspace = oci_fixture(tmp_path)

    with pytest.raises(SupervisorError, match="host-validated snapshot") as error:
        build_oci_worker_config(
            bundle,
            workspace.root,
            ("/usr/bin/busybox",),
            rootfs_pin=_pin_test_rootfs(bundle / "rootfs"),
            container_id="acp-worker-123",
            memory_bytes=256 * 1024 * 1024,
            pids_limit=32,
            cpu_quota_us=100_000,
        )

    assert error.value.code == "invalid_oci_workspace"


def test_oci_policy_rejects_forged_snapshot_for_an_ordinary_private_source(
    tmp_path: Path,
) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    source = workspace.root.parent / "workspace"
    forged = Snapshot(source, workspace.manifest)
    copied_provenance = replace(workspace, root=source)

    for handle in (forged, copied_provenance):
        with pytest.raises(SupervisorError, match="snapshot handle") as error:
            compile_config(bundle, handle)

        assert error.value.code == "invalid_snapshot"


def test_oci_policy_rejects_forced_snapshot_manifest_substitution(tmp_path: Path) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    (workspace.root / "candidate.py").write_text("changed after capture\n")
    changed_snapshot = copy_snapshot(workspace.root, tmp_path / "changed-workspace")
    object.__setattr__(workspace, "manifest", changed_snapshot.manifest)

    with pytest.raises(SupervisorError, match="manifest") as error:
        compile_config(bundle, workspace)

    assert error.value.code == "invalid_snapshot"


def test_oci_policy_rechecks_snapshot_contents_before_selecting_bind_source(
    tmp_path: Path,
) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    (workspace.root / "candidate.py").write_text("unexpected = True\n")

    with pytest.raises(SupervisorError) as error:
        compile_config(bundle, workspace)

    assert error.value.code == "snapshot_changed"


def test_oci_policy_rejects_mount_destination_symlink_escape(tmp_path: Path) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    rootfs = bundle / "rootfs"
    (rootfs / "home" / "agent").rmdir()
    (rootfs / "home" / "agent").symlink_to(tmp_path, target_is_directory=True)

    with pytest.raises(SupervisorError, match="real directories") as error:
        compile_config(bundle, workspace)

    assert error.value.code == "invalid_oci_rootfs"


def test_oci_policy_rejects_workspace_inside_bundle_or_rootfs(tmp_path: Path) -> None:
    bundle, _workspace = oci_fixture(tmp_path)
    workspace = bundle / "rootfs" / "workspace"
    workspace.rmdir()
    source = tmp_path / "workspace-source"
    source.mkdir(mode=0o700)
    snapshot = copy_snapshot(source, workspace)

    with pytest.raises(SupervisorError, match="disjoint") as error:
        compile_config(bundle, snapshot)

    assert error.value.code == "invalid_oci_workspace"


@pytest.mark.parametrize(
    ("target", "mode", "code"),
    [("bundle", 0o755, "invalid_oci_bundle"), ("workspace", 0o750, "invalid_oci_workspace")],
)
def test_oci_policy_requires_owner_only_bundle_and_workspace(
    tmp_path: Path, target: str, mode: int, code: str
) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    (bundle if target == "bundle" else workspace.root).chmod(mode)

    with pytest.raises(SupervisorError) as error:
        compile_config(bundle, workspace)

    assert error.value.code == code


def test_oci_policy_rejects_group_writable_non_sticky_ancestor(tmp_path: Path) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    bundle.parent.chmod(0o770)

    with pytest.raises(SupervisorError, match="ancestor") as error:
        compile_config(bundle, workspace)

    assert error.value.code == "invalid_oci_bundle"


@pytest.mark.parametrize("executable_state", ["missing", "not_executable", "symlink"])
def test_oci_policy_rejects_untrusted_rootfs_executable(
    tmp_path: Path, executable_state: str
) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    executable = bundle / "rootfs" / "usr" / "bin" / "busybox"
    if executable_state == "missing":
        executable.unlink()
    elif executable_state == "not_executable":
        executable.chmod(0o600)
    else:
        executable.unlink()
        executable.symlink_to("/bin/sh")

    with pytest.raises(SupervisorError) as error:
        compile_config(bundle, workspace)

    assert error.value.code == "invalid_oci_executable"


@pytest.mark.parametrize("destination", ["/proc", "/workspace", "/tmp", "/home/agent"])
def test_oci_policy_rejects_executable_shadowed_by_runtime_mount(
    tmp_path: Path, destination: str
) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    rootfs = bundle / "rootfs"
    executable = rootfs.joinpath(*Path(destination).parts[1:], "tool")
    executable.parent.mkdir(parents=True, exist_ok=True)
    executable.write_text("fixture executable\n")
    executable.chmod(0o700)

    with pytest.raises(SupervisorError, match="shadowed by a runtime mount") as error:
        build_oci_worker_config(
            bundle,
            workspace,
            (destination + "/tool",),
            rootfs_pin=_pin_test_rootfs(rootfs),
            container_id="acp-worker-123",
            memory_bytes=256 * 1024 * 1024,
            pids_limit=32,
            cpu_quota_us=100_000,
        )

    assert error.value.code == "invalid_oci_executable"


def test_oci_policy_rejects_root_directory_as_executable(tmp_path: Path) -> None:
    bundle, workspace = oci_fixture(tmp_path)

    with pytest.raises(SupervisorError) as error:
        build_oci_worker_config(
            bundle,
            workspace,
            ("/",),
            rootfs_pin=_pin_test_rootfs(bundle / "rootfs"),
            container_id="acp-worker-123",
            memory_bytes=256 * 1024 * 1024,
            pids_limit=32,
            cpu_quota_us=100_000,
        )

    assert error.value.code == "invalid_oci_executable"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("memory_bytes", 1),
        ("memory_bytes", 1 << 63),
        ("pids_limit", 0),
        ("pids_limit", 65_537),
        ("cpu_quota_us", 0),
        ("cpu_quota_us", 1 << 63),
        ("cpu_period_us", True),
        ("cpu_period_us", 1 << 64),
        ("tmpfs_bytes", 1 << 63),
        ("host_uid", 0),
        ("host_uid", 1 << 32),
        ("host_gid", 1 << 32),
        ("host_uid", os.geteuid() + 1),
        ("host_gid", os.getegid() + 1),
    ],
)
def test_oci_policy_rejects_unsafe_resource_and_identity_values(
    tmp_path: Path, field: str, value: int
) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    args = {
        "rootfs_pin": _pin_test_rootfs(bundle / "rootfs"),
        "container_id": "acp-worker-123",
        "memory_bytes": 256 * 1024 * 1024,
        "pids_limit": 32,
        "cpu_quota_us": 100_000,
    }
    args[field] = value

    with pytest.raises(SupervisorError) as error:
        build_oci_worker_config(bundle, workspace, ("/usr/bin/busybox",), **args)

    assert error.value.code == "invalid_oci_worker_policy"


def test_oci_policy_rejects_root_caller_before_path_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(oci_worker.os, "geteuid", lambda: 0)

    with pytest.raises(SupervisorError, match="non-root caller") as error:
        build_oci_worker_config(
            tmp_path / "missing-bundle",
            tmp_path / "missing-workspace",
            ("/usr/bin/busybox",),
            rootfs_pin=None,
            container_id="acp-worker-123",
            memory_bytes=256 * 1024 * 1024,
            pids_limit=32,
            cpu_quota_us=100_000,
        )

    assert error.value.code == "invalid_oci_worker_policy"


def test_runc_command_rejects_root_caller_before_path_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(oci_worker.os, "geteuid", lambda: 0)

    with pytest.raises(SupervisorError, match="non-root caller") as error:
        build_runc_run_argv(
            "/missing/runc",
            tmp_path / "missing-state",
            tmp_path / "missing-bundle",
            tmp_path / "missing-workspace",
            tmp_path / "missing-state" / "metadata" / "pid",
            "acp-worker-123",
        )

    assert error.value.code == "invalid_oci_worker_policy"


def test_runc_command_is_attached_and_names_explicit_bundle_state_and_pid_file(
    tmp_path: Path,
) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    state = tmp_path / "attempt" / "runc-state"
    state.mkdir(mode=0o700)
    metadata = state / "metadata"
    metadata.mkdir(mode=0o700)
    pid_file = metadata / "container.pid"

    argv = build_runc_run_argv(
        pinned_runc(tmp_path),
        state,
        bundle,
        workspace.root,
        pid_file,
        "acp-worker-123",
    )

    assert argv == [
        str(Path("/bin/sh").resolve()),
        "--root",
        str(state.resolve()),
        "--systemd-cgroup",
        "run",
        "--bundle",
        str(bundle.resolve()),
        "--pid-file",
        str(pid_file),
        "--preserve-fds",
        "1",
        "--keep",
        "acp-worker-123",
    ]
    assert "--detach" not in argv


def test_runc_command_rejects_existing_pid_file(tmp_path: Path) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    state = tmp_path / "attempt" / "runc-state"
    state.mkdir(mode=0o700)
    metadata = state / "metadata"
    metadata.mkdir(mode=0o700)
    pid_file = metadata / "container.pid"
    pid_file.touch()

    with pytest.raises(SupervisorError) as error:
        build_runc_run_argv(
            pinned_runc(tmp_path), state, bundle, workspace.root, pid_file, "acp-worker-123"
        )

    assert error.value.code == "invalid_oci_pid_file"


def test_runc_pid_file_must_be_outside_candidate_workspace(tmp_path: Path) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    state = tmp_path / "attempt" / "runc-state"
    state.mkdir(mode=0o700)
    pid_file = workspace.root / "container.pid"

    with pytest.raises(SupervisorError) as error:
        build_runc_run_argv(
            pinned_runc(tmp_path), state, bundle, workspace.root, pid_file, "acp-worker-123"
        )

    assert error.value.code == "invalid_oci_pid_file"


def test_runc_pid_parent_must_be_private(tmp_path: Path) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    state = tmp_path / "attempt" / "runc-state"
    state.mkdir(mode=0o700)
    metadata = state / "metadata"
    metadata.mkdir(mode=0o755)

    with pytest.raises(SupervisorError) as error:
        build_runc_run_argv(
            pinned_runc(tmp_path),
            state,
            bundle,
            workspace.root,
            metadata / "container.pid",
            "acp-worker-123",
        )

    assert error.value.code == "invalid_oci_pid_file"


def test_runc_command_rejects_a_raw_path_and_a_forged_pin(tmp_path: Path) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    state = tmp_path / "attempt" / "runc-state"
    state.mkdir(mode=0o700)
    metadata = state / "metadata"
    metadata.mkdir(mode=0o700)
    pid_file = metadata / "container.pid"

    with pytest.raises(SupervisorError, match="trusted supervisor configuration") as raw_error:
        build_runc_run_argv(
            "/bin/sh",
            state,
            bundle,
            workspace.root,
            pid_file,
            "acp-worker-123",  # type: ignore[arg-type]
        )
    assert raw_error.value.code == "invalid_oci_runtime"

    pin = pinned_runc(tmp_path)
    forged = oci_worker._TrustedRuncExecutable(
        pin.path, pin.sha256, pin.device, pin.inode, pin.size
    )
    with pytest.raises(SupervisorError, match="trusted supervisor configuration") as forged_error:
        build_runc_run_argv(forged, state, bundle, workspace.root, pid_file, "acp-worker-123")
    assert forged_error.value.code == "invalid_oci_runtime"


def test_runc_pin_rejects_candidate_owned_executable(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    candidate_tool = tmp_path / "runc"
    candidate_tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    candidate_tool.chmod(0o700)

    with pytest.raises(SupervisorError) as error:
        oci_worker._pin_trusted_runc_executable(candidate_tool, repository)

    assert error.value.code == "untrusted_driver"


@pytest.mark.parametrize("setid_bit", [stat.S_ISUID, stat.S_ISGID])
def test_runc_pin_rejects_setid_mode_bits(monkeypatch: pytest.MonkeyPatch, setid_bit: int) -> None:
    executable = Path("/bin/sh").resolve(strict=True)
    real_fstat = os.fstat

    def setid_fstat(descriptor: int):
        info = real_fstat(descriptor)
        fields = {
            name: getattr(info, name)
            for name in (
                "st_dev",
                "st_ino",
                "st_size",
                "st_uid",
                "st_mode",
                "st_mtime_ns",
                "st_ctime_ns",
            )
        }
        fields["st_mode"] |= setid_bit
        return SimpleNamespace(**fields)

    monkeypatch.setattr(oci_worker.os, "fstat", setid_fstat)

    with pytest.raises(SupervisorError, match="non-set-id") as error:
        oci_worker._trusted_executable_identity(executable)

    assert error.value.code == "invalid_oci_runtime"


@pytest.mark.parametrize("capability_state", ["present", "unknown"])
def test_runc_pin_rejects_linux_file_capabilities_or_unknown_state(
    monkeypatch: pytest.MonkeyPatch, capability_state: str
) -> None:
    executable = Path("/bin/sh").resolve(strict=True)
    monkeypatch.setattr(oci_worker.platform, "system", lambda: "Linux")

    def fake_getxattr(descriptor: int, name: str) -> bytes:
        assert name == "security.capability"
        if capability_state == "present":
            return b"capability-data"
        raise OSError(oci_worker.errno.EOPNOTSUPP, "xattr state unavailable")

    monkeypatch.setattr(oci_worker.os, "getxattr", fake_getxattr, raising=False)

    with pytest.raises(SupervisorError, match="capabilit") as error:
        oci_worker._trusted_executable_identity(executable)

    assert error.value.code == "invalid_oci_runtime"


def test_runc_pin_allows_linux_binary_without_capability_xattr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = Path("/bin/sh").resolve(strict=True)
    monkeypatch.setattr(oci_worker.platform, "system", lambda: "Linux")

    def missing_xattr(descriptor: int, name: str) -> bytes:
        assert name == "security.capability"
        raise OSError(oci_worker.errno.ENODATA, "no such attribute")

    monkeypatch.setattr(oci_worker.os, "getxattr", missing_xattr, raising=False)

    digest, identity = oci_worker._trusted_executable_identity(executable)

    assert len(digest) == 64
    assert identity[1] > 0


@pytest.mark.parametrize("acl_target", ["binary", "parent"])
def test_runc_pin_rejects_effective_user_acl_write_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, acl_target: str
) -> None:
    resolved = Path("/bin/sh").resolve(strict=True)
    acl_writable_path = resolved if acl_target == "binary" else resolved.parent
    original_access = os.access

    def access_with_acl(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int,
        *,
        dir_fd: int | None = None,
        effective_ids: bool = False,
        follow_symlinks: bool = True,
    ) -> bool:
        if effective_ids and mode == os.W_OK and Path(path) == acl_writable_path:
            return True
        return original_access(
            path,
            mode,
            dir_fd=dir_fd,
            effective_ids=effective_ids,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(oci_worker.os, "access", access_with_acl)

    with pytest.raises(SupervisorError, match="writable by the supervisor user") as error:
        oci_worker._pin_trusted_runc_executable("/bin/sh", tmp_path)

    assert error.value.code == "invalid_oci_runtime"


def test_runc_pin_fails_closed_without_effective_id_access_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(oci_worker, "_HAS_EFFECTIVE_ID_ACCESS", False)

    with pytest.raises(
        SupervisorError, match="effective-identity write checks are unavailable"
    ) as error:
        oci_worker._pin_trusted_runc_executable("/bin/sh", tmp_path)

    assert error.value.code == "invalid_oci_runtime"


def test_runc_command_rechecks_effective_user_acl_write_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    state = tmp_path / "attempt" / "runc-state"
    state.mkdir(mode=0o700)
    metadata = state / "metadata"
    metadata.mkdir(mode=0o700)
    pid_file = metadata / "container.pid"
    pin = pinned_runc(tmp_path)
    original_access = os.access

    def access_with_acl(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int,
        *,
        dir_fd: int | None = None,
        effective_ids: bool = False,
        follow_symlinks: bool = True,
    ) -> bool:
        if effective_ids and mode == os.W_OK:
            return True
        return original_access(
            path,
            mode,
            dir_fd=dir_fd,
            effective_ids=effective_ids,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(oci_worker.os, "access", access_with_acl)

    with pytest.raises(SupervisorError, match="writable by the supervisor user") as error:
        build_runc_run_argv(pin, state, bundle, workspace.root, pid_file, "acp-worker-123")

    assert error.value.code == "invalid_oci_runtime"


def test_runc_pin_rejects_modified_seal(tmp_path: Path) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    state = tmp_path / "attempt" / "runc-state"
    state.mkdir(mode=0o700)
    metadata = state / "metadata"
    metadata.mkdir(mode=0o700)
    pid_file = metadata / "container.pid"
    pin = pinned_runc(tmp_path)
    object.__setattr__(pin, "sha256", "0" * 64)

    with pytest.raises(SupervisorError, match="pin was modified") as error:
        build_runc_run_argv(pin, state, bundle, workspace.root, pid_file, "acp-worker-123")

    assert error.value.code == "invalid_oci_runtime"


def test_runc_pin_rejects_simulated_executable_identity_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    state = tmp_path / "attempt" / "runc-state"
    state.mkdir(mode=0o700)
    metadata = state / "metadata"
    metadata.mkdir(mode=0o700)
    pid_file = metadata / "container.pid"
    pin = pinned_runc(tmp_path)

    monkeypatch.setattr(
        oci_worker,
        "_trusted_executable_identity",
        lambda _path: (
            "0" * 64,
            (pin.device, pin.inode, pin.size, 0, 0o755, 1, 1),
        ),
    )

    with pytest.raises(SupervisorError, match="no longer matches its pin") as error:
        build_runc_run_argv(pin, state, bundle, workspace.root, pid_file, "acp-worker-123")

    assert error.value.code == "invalid_oci_runtime"
