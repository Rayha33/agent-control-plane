from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

import agent_control_plane.supervisor.oci_worker as oci_worker
from agent_control_plane.supervisor.common import SupervisorError
from agent_control_plane.supervisor.oci_worker import (
    build_oci_worker_config,
    build_runc_run_argv,
)


def oci_fixture(tmp_path: Path) -> tuple[Path, Path]:
    bundle = tmp_path / "attempt" / "bundle"
    rootfs = bundle / "rootfs"
    bundle.mkdir(parents=True, mode=0o700)
    for relative in ("proc", "workspace", "tmp", "home/agent"):
        (rootfs / relative).mkdir(parents=True, exist_ok=True)
    executable = rootfs / "usr" / "bin" / "busybox"
    executable.parent.mkdir(parents=True)
    executable.write_text("fixture executable\n")
    executable.chmod(0o700)
    workspace = tmp_path / "attempt" / "workspace"
    workspace.mkdir(mode=0o700)
    return bundle, workspace


def compile_config(bundle: Path, workspace: Path) -> dict:
    return build_oci_worker_config(
        bundle,
        workspace,
        ("/usr/bin/busybox", "sh", "-c", "printf ready > /workspace/result.txt"),
        container_id="acp-worker-123",
        memory_bytes=256 * 1024 * 1024,
        pids_limit=32,
        cpu_quota_us=100_000,
    )


def test_oci_policy_encodes_mutable_snapshot_and_private_ephemeral_mounts(
    tmp_path: Path,
) -> None:
    bundle, workspace = oci_fixture(tmp_path)

    config = compile_config(bundle, workspace)

    assert config["ociVersion"] == "1.2.0"
    assert config["root"] == {"path": "rootfs", "readonly": True}
    assert config["process"]["args"][0] == "/usr/bin/busybox"
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
    assert workspace_mount["source"] == str(workspace.resolve())
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
    assert "seccomp" not in linux
    assert linux["uidMappings"][0] == {"containerID": 0, "hostID": os.geteuid(), "size": 1}
    assert linux["gidMappings"][0] == {"containerID": 0, "hostID": os.getegid(), "size": 1}


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
    (workspace / ".git").write_text("gitdir: /shared/repo/.git/worktrees/attempt\n")

    with pytest.raises(SupervisorError, match="Git metadata") as error:
        compile_config(bundle, workspace)

    assert error.value.code == "invalid_oci_workspace"


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
    workspace.chmod(0o700)

    with pytest.raises(SupervisorError, match="disjoint") as error:
        compile_config(bundle, workspace)

    assert error.value.code == "invalid_oci_workspace"


@pytest.mark.parametrize(
    ("target", "mode", "code"),
    [("bundle", 0o755, "invalid_oci_bundle"), ("workspace", 0o750, "invalid_oci_workspace")],
)
def test_oci_policy_requires_owner_only_bundle_and_workspace(
    tmp_path: Path, target: str, mode: int, code: str
) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    (bundle if target == "bundle" else workspace).chmod(mode)

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
        workspace,
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
        build_runc_run_argv("/bin/sh", state, bundle, workspace, pid_file, "acp-worker-123")

    assert error.value.code == "invalid_oci_pid_file"


def test_runc_pid_file_must_be_outside_candidate_workspace(tmp_path: Path) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    state = tmp_path / "attempt" / "runc-state"
    state.mkdir(mode=0o700)
    pid_file = workspace / "container.pid"

    with pytest.raises(SupervisorError) as error:
        build_runc_run_argv("/bin/sh", state, bundle, workspace, pid_file, "acp-worker-123")

    assert error.value.code == "invalid_oci_pid_file"


def test_runc_pid_parent_must_be_private(tmp_path: Path) -> None:
    bundle, workspace = oci_fixture(tmp_path)
    state = tmp_path / "attempt" / "runc-state"
    state.mkdir(mode=0o700)
    metadata = state / "metadata"
    metadata.mkdir(mode=0o755)

    with pytest.raises(SupervisorError) as error:
        build_runc_run_argv(
            "/bin/sh", state, bundle, workspace, metadata / "container.pid", "acp-worker-123"
        )

    assert error.value.code == "invalid_oci_pid_file"
