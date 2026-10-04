from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import stat
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
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


def compile_config(bundle: Path, workspace: Snapshot) -> dict:
    return build_oci_worker_config(
        bundle,
        workspace,
        ("/usr/bin/busybox", "sh", "-c", "printf ready > /workspace/result.txt"),
        container_id="acp-worker-123",
        memory_bytes=256 * 1024 * 1024,
        pids_limit=32,
        cpu_quota_us=100_000,
    )


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
        "/bin/sh",
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
        build_runc_run_argv("/bin/sh", state, bundle, workspace.root, pid_file, "acp-worker-123")

    assert error.value.code == "invalid_oci_pid_file"


def test_runc_pid_file_must_be_outside_candidate_workspace(tmp_path: Path) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    state = tmp_path / "attempt" / "runc-state"
    state.mkdir(mode=0o700)
    pid_file = workspace.root / "container.pid"

    with pytest.raises(SupervisorError) as error:
        build_runc_run_argv("/bin/sh", state, bundle, workspace.root, pid_file, "acp-worker-123")

    assert error.value.code == "invalid_oci_pid_file"


def test_runc_pid_parent_must_be_private(tmp_path: Path) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    state = tmp_path / "attempt" / "runc-state"
    state.mkdir(mode=0o700)
    metadata = state / "metadata"
    metadata.mkdir(mode=0o755)

    with pytest.raises(SupervisorError) as error:
        build_runc_run_argv(
            "/bin/sh",
            state,
            bundle,
            workspace.root,
            metadata / "container.pid",
            "acp-worker-123",
        )

    assert error.value.code == "invalid_oci_pid_file"
