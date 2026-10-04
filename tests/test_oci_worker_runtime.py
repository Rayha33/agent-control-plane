"""Opt-in, no-model integration proof for the current OCI policy compiler.

This deliberately launches a disposable BusyBox fixture with the current OCI
helpers. It is not the registered worker executor: ``run_worker`` still fails
closed when OCI is configured. Run only on a disposable Linux host with rootless
runc and delegated cgroup v2, using an exact runc version as an environment
pin. The default test suite skips the live test.

Cleanup assumes pytest's private temporary parent is not concurrently modified
by another process running as the same host UID; the hostile worker itself has
no mount of the attempt bundle or its parent.
"""

from __future__ import annotations

import fcntl
import json
import os
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path
from shlex import quote as shell_quote
from typing import Any

import pytest

import agent_control_plane.supervisor.oci_worker as oci_worker
from agent_control_plane.supervisor.sandbox_attestation import (
    ProcessSnapshot,
    read_linux_process_snapshot,
    read_private_runc_pid_file,
)
from agent_control_plane.supervisor.sandbox_workspace import copy_snapshot

_LIVE_TEST_ENABLED = os.environ.get("ACP_RUN_OCI_INTEGRATION") == "1"
_LIVE_TEST_REASON = "set ACP_RUN_OCI_INTEGRATION=1 on a disposable supported Linux host"
_CONTAINER_MEMORY_BYTES = 128 * 1024 * 1024
_CONTAINER_PIDS_LIMIT = 16
_CONTAINER_CPU_QUOTA_US = 50_000
_CONTAINER_CPU_PERIOD_US = 100_000
_CONTAINER_FILESIZE_LIMIT_BYTES = 64 * 1024 * 1024
_LIVE_PROCESS_STATES = {b"R", b"S", b"D", b"T", b"t", b"W", b"K", b"P", b"I"}
_ATTEMPT_ROOT_CHILDREN = {
    "bundle",
    "host-fixtures",
    "runc-state",
    "workspace-snapshot",
    "workspace-source",
}

# This small host-side trampoline waits until the test has written the exact
# bundle and PID-specific probe, then execs runc by the held executable FD.
# Descriptor 3 becomes the one launch-gate FD preserved into the OCI process.
_RUNC_FD_LAUNCHER = """
import json, os, resource, sys
start_fd, gate_fd, runc_fd = (int(value) for value in sys.argv[1:4])
payload_bytes = bytearray()
while len(payload_bytes) <= 65536:
    chunk = os.read(start_fd, 65537 - len(payload_bytes))
    if not chunk:
        break
    payload_bytes.extend(chunk)
os.close(start_fd)
if not payload_bytes.endswith(b"\\n") or len(payload_bytes) > 65536:
    os._exit(125)
payload = json.loads(payload_bytes)
# The descriptor is needed only to load the pinned executable.  It must not
# survive exec into runc, and therefore cannot be inherited by the OCI init.
os.set_inheritable(runc_fd, False)
if gate_fd == 3:
    os.set_inheritable(gate_fd, True)
else:
    os.dup2(gate_fd, 3, inheritable=True)
    os.close(gate_fd)
resource.setrlimit(
    resource.RLIMIT_FSIZE,
    (64 * 1024 * 1024, 64 * 1024 * 1024),
)
os.execve(runc_fd, payload["argv"], payload["env"])
"""


def _require_root_owned_file(path: Path, label: str) -> Path:
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o022
        or info.st_mode & (stat.S_ISUID | stat.S_ISGID)
    ):
        pytest.fail(f"{label} must be a root-owned, non-writable, non-set-id regular file")
    return resolved


def _copy_busybox_closure(busybox: Path, rootfs: Path) -> tuple[str, set[str]]:
    """Copy BusyBox plus its dynamic-loader closure, never host directories."""

    busybox = _require_root_owned_file(busybox, "BusyBox")
    ldd = shutil.which("ldd")
    if ldd is None:
        pytest.fail("ldd is required to build the minimal audited BusyBox closure")
    completed = subprocess.run(
        [ldd, str(busybox)],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
        env={"LC_ALL": "C", "LANG": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
    )
    if completed.returncode != 0 or "not found" in completed.stdout:
        pytest.fail("trusted BusyBox dependency closure could not be resolved with ldd")

    applets_result = subprocess.run(
        [str(busybox), "--list"],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
        env={"LC_ALL": "C", "LANG": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
    )
    if applets_result.returncode != 0:
        pytest.fail("BusyBox applet list could not be inspected")
    applets = set(applets_result.stdout.splitlines())
    required_applets = {"cat", "grep", "ln", "nc", "readlink", "sed", "touch", "tr"}
    missing_applets = required_applets - applets
    if missing_applets:
        pytest.fail(f"BusyBox is missing required test applets: {sorted(missing_applets)}")

    dependencies: set[str] = set()
    for line in completed.stdout.splitlines():
        if "=> not found" in line:
            pytest.fail("BusyBox has an unresolved dynamic dependency")
        for token in line.replace("=>", " ").split():
            if token.startswith("/") and Path(token).exists():
                dependencies.add(token)

    binary_destination = rootfs / "bin" / "busybox"
    binary_destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    shutil.copyfile(busybox, binary_destination)
    binary_destination.chmod(stat.S_IMODE(busybox.stat().st_mode) & 0o755)

    for dependency in sorted(dependencies):
        dependency_path = _require_root_owned_file(Path(dependency), "BusyBox dependency")
        destination = rootfs / dependency.lstrip("/")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        shutil.copyfile(dependency_path, destination)
        destination.chmod(stat.S_IMODE(dependency_path.stat().st_mode) & 0o755)

    for applet in sorted(required_applets):
        (rootfs / "bin" / applet).symlink_to("busybox")
    shell_binary = rootfs / "bin" / "sh"
    shutil.copyfile(binary_destination, shell_binary)
    shell_binary.chmod(stat.S_IMODE(binary_destination.stat().st_mode))
    version = subprocess.run(
        [str(busybox), "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
        env={"LC_ALL": "C", "LANG": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
    ).stdout.splitlines()
    if not version or not version[0].startswith("BusyBox "):
        pytest.fail("BusyBox version string was not recognized")
    return version[0], applets


def _start_time(stat_bytes: bytes) -> bytes:
    """Return Linux /proc stat field 22, robust to spaces in comm."""

    close = stat_bytes.rfind(b")")
    if close < 0:
        raise AssertionError("malformed /proc stat observation")
    fields_from_state = stat_bytes[close + 2 :].split()
    if len(fields_from_state) <= 19:
        raise AssertionError("truncated /proc stat observation")
    return fields_from_state[19]


def _snapshot_start_time(snapshot: Any, expected_pid: int, *, require_live: bool) -> bytes:
    """Validate one PID identity across the stat/cgroup/stat observation."""

    observations: list[tuple[int, bytes, bytes]] = []
    for stat_bytes in (snapshot.stat_before, snapshot.stat_after):
        open_paren = stat_bytes.find(b"(")
        close_paren = stat_bytes.rfind(b")")
        if open_paren <= 0 or close_paren <= open_paren:
            raise AssertionError("malformed /proc stat observation")
        try:
            pid = int(stat_bytes[:open_paren].strip())
        except ValueError as error:
            raise AssertionError("malformed PID in /proc stat observation") from error
        state_field = stat_bytes[close_paren + 2 : close_paren + 3]
        start_time = _start_time(stat_bytes)
        if pid != expected_pid:
            raise AssertionError("/proc stat PID changed during the cgroup observation")
        if require_live and state_field not in _LIVE_PROCESS_STATES:
            raise AssertionError("worker init was not live across the cgroup observation")
        observations.append((pid, state_field, start_time))
    if observations[0][2] != observations[1][2]:
        raise AssertionError("worker init PID/start-time changed during the cgroup observation")
    return observations[0][2]


def _snapshot_cgroup_path(snapshot: Any) -> Path:
    """Resolve the cgroup bytes captured between the two PID stat reads."""

    try:
        rows = snapshot.cgroup.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise AssertionError("worker init cgroup observation is not ASCII") from error
    unified = [row.split(":", 2)[2] for row in rows if row.startswith("0::")]
    if len(unified) != 1:
        raise AssertionError("worker init snapshot lacks one unified cgroup-v2 path")
    root = Path("/sys/fs/cgroup").resolve(strict=True)
    cgroup = (root / unified[0].lstrip("/")).resolve(strict=True)
    if cgroup == root or root not in cgroup.parents:
        raise AssertionError("worker init snapshot cgroup escaped the host cgroup-v2 root")
    return cgroup


def _read_process_fd_table(pid: int) -> tuple[tuple[int, str], ...]:
    """Read one process's descriptor targets without running code in it."""

    fd_directory = Path(f"/proc/{pid}/fd")
    descriptors: list[tuple[int, str]] = []
    with os.scandir(fd_directory) as entries:
        for entry in entries:
            try:
                descriptor = int(entry.name)
            except ValueError as error:
                raise AssertionError("process FD table contained a non-numeric entry") from error
            descriptors.append((descriptor, os.readlink(entry.path)))
    return tuple(sorted(descriptors))


def _audit_worker_init_fd_table(
    pid: int,
    *,
    expected_start_time: bytes,
    expected_cgroup_path: Path,
) -> tuple[tuple[int, str], ...]:
    """Bracket two stable host-side FD reads with exact process identity checks."""

    expected_cgroup = expected_cgroup_path.resolve(strict=True)

    def verify_identity() -> None:
        snapshot = read_linux_process_snapshot(pid)
        observed_start = _snapshot_start_time(snapshot, pid, require_live=True)
        if observed_start != expected_start_time:
            raise AssertionError("worker init PID/start-time changed during descriptor audit")
        observed_cgroup = _snapshot_cgroup_path(snapshot).resolve(strict=True)
        if observed_cgroup != expected_cgroup:
            raise AssertionError("worker init cgroup changed during descriptor audit")

    verify_identity()
    first = _read_process_fd_table(pid)
    verify_identity()
    second = _read_process_fd_table(pid)
    verify_identity()
    if first != second:
        raise AssertionError("worker init descriptor table changed during host-side audit")
    unexpected = [
        (descriptor, target) for descriptor, target in first if descriptor not in {0, 1, 2}
    ]
    if unexpected:
        raise AssertionError(f"worker init inherited non-stdio descriptors: {unexpected!r}")
    if {descriptor for descriptor, _target in first} != {0, 1, 2}:
        raise AssertionError("worker init did not have exactly the three standard descriptors")
    socket_stdio = [
        (descriptor, target) for descriptor, target in first if target.startswith("socket:")
    ]
    if socket_stdio:
        raise AssertionError(f"worker init stdio inherited socket descriptors: {socket_stdio!r}")
    return first


def _runc_environment(*, marker: str | None = None) -> dict[str, str]:
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.geteuid()}")
    bus = os.environ.get("DBUS_SESSION_BUS_ADDRESS", f"unix:path={runtime_dir}/bus")
    # Keep only values needed by rootless systemd-cgroup runc. In particular,
    # no provider, model, Codex, SSH-agent, or supervisor credential variables
    # cross into this runtime client or the OCI process.
    env = {
        "HOME": str(Path.home()),
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "XDG_RUNTIME_DIR": runtime_dir,
        "DBUS_SESSION_BUS_ADDRESS": bus,
    }
    if marker is not None:
        env["ACP_TEST_RUNC_MARKER"] = marker
    return env


def _safe_run_pinned_runc(
    pin: Any,
    descriptor: int,
    state_root: Path,
    args: list[str],
    *,
    timeout: float = 8,
) -> tuple[int, str]:
    return oci_worker._run_bounded_command(
        [str(pin.path), "--root", str(state_root), *args],
        cwd="/",
        env=_runc_environment(),
        timeout_seconds=timeout,
        max_output_bytes=64 * 1024,
        pass_fds=(descriptor,),
        exec_fd=descriptor,
    )


def _run_user_systemctl(args: list[str]) -> tuple[int, str]:
    systemctl = shutil.which("systemctl")
    if systemctl is None:
        raise AssertionError("systemctl is required to verify the rootless cgroup scope")
    return oci_worker._run_bounded_command(
        [systemctl, "--user", "--no-pager", *args],
        cwd="/",
        env=_runc_environment(),
        timeout_seconds=8,
        max_output_bytes=64 * 1024,
    )


def _systemd_control_group(unit_name: str) -> Path | None:
    code, output = _run_user_systemctl(["show", "--property=ControlGroup", "--value", unit_name])
    if code != 0:
        return None
    control_group = output.strip()
    if not control_group:
        return None
    if not control_group.startswith("/") or ".." in Path(control_group).parts:
        raise AssertionError("systemd returned an invalid worker cgroup path")
    root = Path("/sys/fs/cgroup").resolve(strict=True)
    cgroup = (root / control_group.lstrip("/")).resolve(strict=False)
    if cgroup == root or root not in cgroup.parents:
        raise AssertionError("systemd worker cgroup path escaped the host cgroup-v2 root")
    return cgroup


def _systemd_scope_is_active(unit_name: str) -> bool:
    code, output = _run_user_systemctl(["show", "--property=ActiveState", "--value", unit_name])
    return code == 0 and output.strip() == "active"


def _assert_worker_scope_absent(container_id: str) -> None:
    code, output = _run_user_systemctl(
        ["list-units", "--all", "--plain", "--no-legend", "--full", "--type=scope"]
    )
    if code != 0:
        raise AssertionError(f"could not verify rootless worker scopes: {output}")
    matches = [line for line in output.splitlines() if container_id in line]
    if matches:
        raise AssertionError(f"worker systemd scope remained after cleanup: {matches!r}")


def _wait_for_worker_scope_absent(container_id: str, timeout: float = 5) -> None:
    deadline = time.monotonic() + timeout
    while True:
        _assert_worker_scope_absent(container_id)
        if time.monotonic() >= deadline:
            return
        time.sleep(0.1)


def _attempt_cleanup(errors: list[str], label: str, action: Any) -> Any | None:
    """Record one teardown failure without skipping the remaining cleanup."""

    try:
        return action()
    except Exception as error:  # cleanup must proceed after any ordinary failure
        errors.append(f"{label}: {type(error).__name__}: {error}")
        return None


def _cleanup_path_exists(errors: list[str], label: str, path: Path) -> bool | None:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        errors.append(f"{label}: {type(error).__name__}: {error}")
        return None
    return True


def _remove_checkout_write_probe(
    directory: Path,
    canary: Path,
    identity: tuple[int, int] | None,
    expected_uid: int,
) -> None:
    """Remove only the unique, private canary reserved by this test."""

    info = directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != expected_uid
        or stat.S_IMODE(info.st_mode) != 0o700
        or (identity is not None and (info.st_dev, info.st_ino) != identity)
    ):
        raise AssertionError("checkout write-probe directory identity changed")
    with os.scandir(directory) as entries:
        children = list(entries)
    if any(Path(entry.path) != canary for entry in children):
        raise AssertionError("checkout write-probe directory contains an unexpected entry")
    canary_info: os.stat_result | None = None
    if children:
        canary_info = canary.lstat()
        if not stat.S_ISREG(canary_info.st_mode) or canary_info.st_uid != expected_uid:
            raise AssertionError("checkout write canary is not a test-owned regular file")
        canary.unlink()
    directory.rmdir()


def _remove_private_attempt_tree(
    directory: Path,
    identity: tuple[int, int],
    expected_uid: int,
) -> None:
    """Remove this exact owned tree relative to a pinned private parent FD."""

    if not shutil.rmtree.avoids_symlink_attacks:
        raise AssertionError("platform lacks fd-safe recursive cleanup")
    parent = directory.parent.resolve(strict=True)
    if parent != directory.parent:
        raise AssertionError("private attempt-tree parent is not canonical")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    parent_fd = os.open(parent, directory_flags)
    try:
        parent_info = os.fstat(parent_fd)
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != expected_uid
            or stat.S_IMODE(parent_info.st_mode) != 0o700
        ):
            raise AssertionError("private attempt-tree parent is not owned and mode 0700")
        named_info = os.stat(directory.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(named_info.st_mode)
            or named_info.st_uid != expected_uid
            or stat.S_IMODE(named_info.st_mode) != 0o700
            or (named_info.st_dev, named_info.st_ino) != identity
        ):
            raise AssertionError("private attempt-tree identity changed")
        attempt_fd = os.open(directory.name, directory_flags, dir_fd=parent_fd)
        try:
            opened_info = os.fstat(attempt_fd)
            if not os.path.samestat(named_info, opened_info):
                raise AssertionError("private attempt tree changed during open")
            with os.scandir(attempt_fd) as entries:
                children = list(entries)
            if any(entry.name not in _ATTEMPT_ROOT_CHILDREN for entry in children):
                raise AssertionError("private attempt tree contains an unexpected entry")
            for entry in children:
                child_info = entry.stat(follow_symlinks=False)
                if (
                    not stat.S_ISDIR(child_info.st_mode)
                    or child_info.st_uid != expected_uid
                    or stat.S_IMODE(child_info.st_mode) != 0o700
                ):
                    raise AssertionError("private attempt-tree child is not an owned directory")
        finally:
            os.close(attempt_fd)

        shutil.rmtree(directory.name, dir_fd=parent_fd)
        try:
            os.stat(directory.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise AssertionError("private attempt tree remained after cleanup")
    finally:
        os.close(parent_fd)


def _cleanup_identity_gaps(
    *,
    launch_submitted: bool,
    init_pid: int | None,
    init_start: bytes | None,
    cgroup_path: Path | None,
    systemd_cgroup_path: Path | None,
) -> tuple[str, ...]:
    """Return every missing identity that prevents positive runtime cleanup proof."""

    if not launch_submitted:
        return ()
    gaps: list[str] = []
    if init_pid is None or init_start is None:
        gaps.append("launch was submitted without an exact init PID/start-time identity")
    if cgroup_path is None:
        gaps.append("launch was submitted without the init cgroup path")
    if systemd_cgroup_path is None:
        gaps.append("launch was submitted without the exact systemd scope cgroup path")
    return tuple(gaps)


def _synthetic_proc_stat(pid: int, state: bytes, start_time: int) -> bytes:
    fields = [state, *([b"0"] * 18), str(start_time).encode("ascii")]
    return str(pid).encode("ascii") + b" (acp test worker) " + b" ".join(fields)


def test_snapshot_start_identity_checks_both_sides_of_cgroup_read() -> None:
    pid = 1234
    snapshot = ProcessSnapshot(
        stat_before=_synthetic_proc_stat(pid, b"S", 9876),
        cgroup=b"0::/user.slice/test.scope\n",
        stat_after=_synthetic_proc_stat(pid, b"R", 9876),
    )

    assert _snapshot_start_time(snapshot, pid, require_live=True) == b"9876"

    recycled = ProcessSnapshot(
        stat_before=snapshot.stat_before,
        cgroup=snapshot.cgroup,
        stat_after=_synthetic_proc_stat(pid, b"R", 9877),
    )
    with pytest.raises(AssertionError, match="start-time changed"):
        _snapshot_start_time(recycled, pid, require_live=True)

    exited = ProcessSnapshot(
        stat_before=_synthetic_proc_stat(pid, b"Z", 9876),
        cgroup=snapshot.cgroup,
        stat_after=_synthetic_proc_stat(pid, b"Z", 9876),
    )
    with pytest.raises(AssertionError, match="was not live"):
        _snapshot_start_time(exited, pid, require_live=True)


def test_worker_init_fd_audit_brackets_stable_non_socket_stdio(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid = 1234
    cgroup = tmp_path / "worker.scope"
    cgroup.mkdir()
    snapshot = ProcessSnapshot(
        stat_before=_synthetic_proc_stat(pid, b"S", 9876),
        cgroup=b"0::/user.slice/test.scope\n",
        stat_after=_synthetic_proc_stat(pid, b"S", 9876),
    )
    monkeypatch.setattr(sys.modules[__name__], "read_linux_process_snapshot", lambda _pid: snapshot)
    monkeypatch.setattr(sys.modules[__name__], "_snapshot_cgroup_path", lambda _snapshot: cgroup)
    monkeypatch.setattr(
        sys.modules[__name__],
        "_read_process_fd_table",
        lambda _pid: ((0, "/dev/null"), (1, "/dev/null"), (2, "/dev/null")),
    )

    assert _audit_worker_init_fd_table(
        pid,
        expected_start_time=b"9876",
        expected_cgroup_path=cgroup,
    ) == ((0, "/dev/null"), (1, "/dev/null"), (2, "/dev/null"))


@pytest.mark.parametrize(
    ("fd_table", "message"),
    [
        (((0, "/dev/null"), (1, "/dev/null"), (2, "/dev/null"), (3, "pipe:[9]")), "non-stdio"),
        (((0, "/dev/null"), (1, "socket:[9]"), (2, "/dev/null")), "socket descriptors"),
    ],
)
def test_worker_init_fd_audit_rejects_extra_or_socket_descriptors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fd_table: tuple[tuple[int, str], ...],
    message: str,
) -> None:
    pid = 1234
    cgroup = tmp_path / "worker.scope"
    cgroup.mkdir()
    snapshot = ProcessSnapshot(
        stat_before=_synthetic_proc_stat(pid, b"S", 9876),
        cgroup=b"0::/user.slice/test.scope\n",
        stat_after=_synthetic_proc_stat(pid, b"S", 9876),
    )
    monkeypatch.setattr(sys.modules[__name__], "read_linux_process_snapshot", lambda _pid: snapshot)
    monkeypatch.setattr(sys.modules[__name__], "_snapshot_cgroup_path", lambda _snapshot: cgroup)
    monkeypatch.setattr(sys.modules[__name__], "_read_process_fd_table", lambda _pid: fd_table)

    with pytest.raises(AssertionError, match=message):
        _audit_worker_init_fd_table(
            pid,
            expected_start_time=b"9876",
            expected_cgroup_path=cgroup,
        )


def test_worker_init_fd_audit_rejects_unstable_descriptor_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid = 1234
    cgroup = tmp_path / "worker.scope"
    cgroup.mkdir()
    snapshot = ProcessSnapshot(
        stat_before=_synthetic_proc_stat(pid, b"S", 9876),
        cgroup=b"0::/user.slice/test.scope\n",
        stat_after=_synthetic_proc_stat(pid, b"S", 9876),
    )
    fd_tables = iter(
        (
            ((0, "/dev/null"), (1, "/dev/null"), (2, "/dev/null")),
            ((0, "/dev/null"), (1, "/dev/null"), (2, "/dev/null"), (3, "pipe:[9]")),
        )
    )
    monkeypatch.setattr(sys.modules[__name__], "read_linux_process_snapshot", lambda _pid: snapshot)
    monkeypatch.setattr(sys.modules[__name__], "_snapshot_cgroup_path", lambda _snapshot: cgroup)
    monkeypatch.setattr(
        sys.modules[__name__], "_read_process_fd_table", lambda _pid: next(fd_tables)
    )

    with pytest.raises(AssertionError, match="changed during host-side audit"):
        _audit_worker_init_fd_table(
            pid,
            expected_start_time=b"9876",
            expected_cgroup_path=cgroup,
        )


def test_cleanup_path_probe_treats_only_not_found_as_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / "missing"
    errors: list[str] = []
    assert _cleanup_path_exists(errors, "inspect missing", missing) is False
    assert errors == []

    present = tmp_path / "present"
    present.write_text("sentinel", encoding="ascii")
    assert _cleanup_path_exists(errors, "inspect present", present) is True

    def denied(_path: Path) -> os.stat_result:
        raise PermissionError("access denied")

    monkeypatch.setattr(Path, "lstat", denied)
    assert _cleanup_path_exists(errors, "inspect denied", present) is None
    assert errors == ["inspect denied: PermissionError: access denied"]


def test_checkout_write_probe_cleanup_removes_only_its_canary(tmp_path: Path) -> None:
    directory = tmp_path / "checkout-write-probe"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    canary = directory / "write-canary"
    canary.write_text("test-owned canary", encoding="ascii")
    info = directory.lstat()

    _remove_checkout_write_probe(directory, canary, (info.st_dev, info.st_ino), os.geteuid())

    assert not directory.exists()


def test_checkout_write_probe_cleanup_preserves_unexpected_entries(tmp_path: Path) -> None:
    directory = tmp_path / "checkout-write-probe"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    canary = directory / "write-canary"
    canary.write_text("test-owned canary", encoding="ascii")
    unexpected = directory / "unexpected"
    unexpected.write_text("preserve", encoding="ascii")
    info = directory.lstat()

    with pytest.raises(AssertionError, match="unexpected entry"):
        _remove_checkout_write_probe(directory, canary, (info.st_dev, info.st_ino), os.geteuid())

    assert canary.read_text(encoding="ascii") == "test-owned canary"
    assert unexpected.read_text(encoding="ascii") == "preserve"


def test_private_attempt_tree_cleanup_removes_owned_tree(tmp_path: Path) -> None:
    directory = tmp_path / "live-oci-attempt"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    (directory / "workspace-source").mkdir(mode=0o700)
    info = directory.lstat()

    _remove_private_attempt_tree(directory, (info.st_dev, info.st_ino), os.geteuid())

    assert not directory.exists()


def test_private_attempt_tree_cleanup_preserves_unexpected_entries(tmp_path: Path) -> None:
    directory = tmp_path / "live-oci-attempt"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    unexpected = directory / "unexpected"
    unexpected.write_text("preserve", encoding="ascii")
    info = directory.lstat()

    with pytest.raises(AssertionError, match="unexpected entry"):
        _remove_private_attempt_tree(directory, (info.st_dev, info.st_ino), os.geteuid())

    assert unexpected.read_text(encoding="ascii") == "preserve"


def test_partial_launch_without_runtime_identity_fails_closed() -> None:
    gaps = _cleanup_identity_gaps(
        launch_submitted=True,
        init_pid=None,
        init_start=None,
        cgroup_path=None,
        systemd_cgroup_path=None,
    )

    assert len(gaps) == 3
    assert "init PID/start-time" in gaps[0]
    assert "init cgroup" in gaps[1]
    assert "systemd scope cgroup" in gaps[2]


def _probe_script(
    *,
    host_paths: dict[str, Path],
    host_tmp_relative: str,
    host_runc_marker: str,
    host_runc_pid: int,
    host_network_ip: str,
    host_network_port: int,
) -> str:
    q = {name: shell_quote(str(path)) for name, path in host_paths.items()}
    host_tmp_rel = shell_quote(host_tmp_relative)
    marker = shell_quote(host_runc_marker)
    host_pid = shell_quote(str(host_runc_pid))
    net_ip = shell_quote(host_network_ip)
    net_port = shell_quote(str(host_network_port))
    return f"""set -eu
# Stop at a second host-controlled file gate. The host performs the FD audit.
/bin/busybox touch /workspace/fd-audit-ready
while [ ! -e /workspace/fd-audit-release ]; do :; done

test -r /workspace/input.txt
test "$(/bin/busybox cat /workspace/input.txt)" = 'snapshot input'
printf 'candidate result\\n' > /workspace/result.txt
printf 'private tmpfs\\n' > /tmp/acp-private-tmp.txt
printf 'private home\\n' > /home/agent/acp-private-home.txt

# Host /etc/os-release is a readable host sentinel; the image /etc is empty.
if /bin/busybox cat /etc/os-release > /workspace/host-etc.txt; then exit 31; fi
if /bin/busybox touch /etc/acp-write-probe; then exit 32; fi

# The checkout, sibling attempt, unrelated project, host home, host config,
# synthetic credential marker, and host temp file must not cross mounts.
if /bin/busybox cat {q["checkout"]} > /workspace/checkout.txt; then exit 33; fi
if /bin/busybox cat {q["sibling"]} > /workspace/sibling.txt; then exit 34; fi
if /bin/busybox cat {q["project"]} > /workspace/project.txt; then exit 35; fi
if test -e {q["checkout_git"]}; then exit 36; fi
if test -r {q["home"]}; then exit 37; fi
if /bin/busybox cat {q["host_config"]} > /workspace/host-config.txt; then exit 38; fi
if /bin/busybox cat {q["credential"]} > /workspace/credential.txt; then exit 39; fi
if /bin/busybox cat {q["host_tmp"]} > /workspace/host-tmp.txt; then exit 40; fi
if /bin/busybox touch {q["host_tmp"]}; then exit 41; fi
test ! -e /tmp/{host_tmp_rel}

# Absolute and parent-relative symlinks must remain inside the container root.
/bin/busybox ln -s {q["host_tmp"]} /workspace/absolute-host-tmp
/bin/busybox ln -s ../../tmp/{host_tmp_rel} /workspace/relative-host-tmp
if /bin/busybox cat /workspace/absolute-host-tmp > /workspace/absolute-link.txt; then exit 42; fi
if /bin/busybox cat /workspace/relative-host-tmp > /workspace/relative-link.txt; then exit 43; fi
if /bin/busybox touch /workspace/absolute-host-tmp; then exit 44; fi
if /bin/busybox touch {q["checkout_write"]}; then exit 45; fi

# The host runc client has a unique environment marker absent from the worker.
# Even if a PID number happens to collide, the namespace must not expose it.
if test -r /proc/{host_pid}/environ; then
  visible=$(/bin/busybox tr '\\000' ' ' < /proc/{host_pid}/environ)
  case "$visible" in *{marker}*) exit 46 ;; esac
fi

# No host network interface/default route, no inherited socket descriptor, and
# no connection to a test-owned listener on the host's selected NIC address.
interfaces=$(/bin/busybox sed -n '3,$s/^[[:space:]]*\\([^:]*\\):.*/\\1/p' /proc/net/dev | /bin/busybox tr -d '[:space:]')
test "$interfaces" = lo
if /bin/busybox grep -q '^00000000' /proc/net/route; then exit 47; fi
if /bin/busybox nc -w 1 {net_ip} {net_port} > /workspace/network-probe.txt 2>&1; then
  exit 49
else
  network_rc=$?
fi

printf 'network_probe_rc=%s\\ninterfaces=%s\\n' "$network_rc" "$interfaces" > /workspace/isolation-result.txt
"""


def _kill_runc_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=2)


@pytest.mark.skipif(not _LIVE_TEST_ENABLED, reason=_LIVE_TEST_REASON)
def test_live_rootless_runc_enforces_minimal_worker_boundary(
    tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    """Run one bounded BusyBox payload behind the exact config's launch gate."""

    if not sys.platform.startswith("linux"):
        pytest.skip("the live OCI proof requires Linux namespaces and procfs")
    if os.geteuid() == 0:
        pytest.fail("the live OCI proof must run as an unprivileged host user")
    if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        pytest.fail("the live OCI proof requires a unified cgroup-v2 host")
    tmp_path = tmp_path.resolve()
    if not tmp_path.is_relative_to(Path("/tmp")):
        pytest.fail("the opt-in test must use a private pytest directory below host /tmp")
    expected_version = os.environ.get("ACP_OCI_TEST_RUNC_VERSION")
    if not expected_version:
        pytest.fail("set ACP_OCI_TEST_RUNC_VERSION to the exact approved runc release")

    repo_root = Path(__file__).resolve().parents[1]
    if not repo_root.is_relative_to(Path("/tmp")):
        pytest.fail("the live proof must run from a disposable repository checkout below /tmp")
    pin = oci_worker._pin_trusted_runc_executable(
        Path(os.environ.get("ACP_OCI_TEST_RUNC", "/usr/bin/runc")), repo_root
    )
    observed_version = oci_worker._probe_trusted_runc_version(pin, expected_version)
    if observed_version != expected_version:
        pytest.fail("runc version probe disagreed with the explicit integration-test pin")

    attempt_root = tmp_path / "live-oci-attempt"
    attempt_cleanup = {
        "created": False,
        "identity": None,
        "launch_submitted": False,
        "runtime_verified": False,
        "preserve": False,
    }

    def finalize_attempt_tree() -> None:
        if not attempt_cleanup["created"] or attempt_cleanup["preserve"]:
            return
        if attempt_cleanup["launch_submitted"] and not attempt_cleanup["runtime_verified"]:
            return
        identity = attempt_cleanup["identity"]
        if identity is None:
            raise AssertionError("private attempt-tree identity was not recorded")
        _remove_private_attempt_tree(attempt_root, identity, os.geteuid())

    request.addfinalizer(finalize_attempt_tree)
    if os.path.lexists(attempt_root):
        pytest.fail("unique private attempt-tree path already exists")
    attempt_root.mkdir(mode=0o700)
    attempt_cleanup["created"] = True
    attempt_root.chmod(0o700)
    attempt_root_info = attempt_root.lstat()
    if (
        not stat.S_ISDIR(attempt_root_info.st_mode)
        or attempt_root_info.st_uid != os.geteuid()
        or stat.S_IMODE(attempt_root_info.st_mode) != 0o700
    ):
        pytest.fail("private attempt root is not test-owned and mode 0700")
    attempt_cleanup["identity"] = (attempt_root_info.st_dev, attempt_root_info.st_ino)
    bundle_root = attempt_root / "bundle"
    bundle_root.mkdir(mode=0o700)
    rootfs = bundle_root / "rootfs"
    rootfs.mkdir(mode=0o755)
    for relative in (
        "bin",
        "dev",
        "etc",
        "home/agent",
        "proc",
        "run",
        "tmp",
        "workspace",
    ):
        (rootfs / relative).mkdir(parents=True, exist_ok=True, mode=0o755)
    (rootfs / "home" / "agent").chmod(0o700)
    busybox_version, applets = _copy_busybox_closure(
        Path(os.environ.get("ACP_OCI_TEST_BUSYBOX", "/usr/bin/busybox")), rootfs
    )

    workspace_source = attempt_root / "workspace-source"
    workspace_source.mkdir(mode=0o700)
    (workspace_source / "input.txt").write_text("snapshot input", encoding="ascii")
    (workspace_source / ".git").write_text(
        "gitdir: /tmp/host-shared-git-metadata", encoding="ascii"
    )
    workspace_snapshot = copy_snapshot(workspace_source, attempt_root / "workspace-snapshot")
    workspace = Path(workspace_snapshot.root)
    if (workspace / ".git").exists():
        pytest.fail("host snapshot copied its top-level Git pointer into the worker workspace")
    container_id = f"acp-live-{uuid.uuid4().hex}"
    checkout_probe_directory = repo_root / f".acp-checkout-write-probe-{uuid.uuid4().hex}"
    checkout_write = checkout_probe_directory / "canary"
    checkout_probe_identity: tuple[int, int] | None = None
    checkout_probe_created = False
    state_root = attempt_root / "runc-state"
    state_root.mkdir(mode=0o700)
    pid_file = state_root / "container.pid"
    rootfs_digest = oci_worker.rootfs_tree_sha256(rootfs)
    rootfs_pin = oci_worker._pin_trusted_rootfs(rootfs, rootfs_digest, repo_root=repo_root)

    fixture_root = attempt_root / "host-fixtures"
    sibling_file = fixture_root / "sibling-attempt" / "private-marker"
    project_file = fixture_root / "unrelated-project" / "private-marker"
    host_config_file = fixture_root / "host-home" / ".codex" / "config-marker.toml"
    credential_file = fixture_root / "host-home" / ".ssh" / "synthetic-key-marker"
    host_tmp_file = fixture_root / "host-tmp-sentinel"
    fixture_root.mkdir(mode=0o700)
    fixture_root.chmod(0o700)
    for directory in (
        fixture_root / "sibling-attempt",
        fixture_root / "unrelated-project",
        fixture_root / "host-home",
        fixture_root / "host-home" / ".codex",
        fixture_root / "host-home" / ".ssh",
    ):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
    for file_path in (sibling_file, project_file, host_config_file, credential_file, host_tmp_file):
        file_path.write_text("test-only sentinel; not a credential", encoding="ascii")
        file_path.chmod(0o600)
        if not os.access(file_path, os.R_OK):
            pytest.fail("host isolation sentinel is not readable before launch")
    if not Path("/etc/os-release").is_file() or not os.access("/etc/os-release", os.R_OK):
        pytest.fail("readable host /etc/os-release sentinel is required")
    checkout_sentinel = repo_root / "pyproject.toml"
    if not checkout_sentinel.is_file() or not os.access(checkout_sentinel, os.R_OK):
        pytest.fail("current source checkout sentinel is not host-readable")
    host_paths = {
        "checkout": checkout_sentinel,
        "checkout_git": repo_root / ".git",
        "checkout_write": checkout_write,
        "sibling": sibling_file,
        "project": project_file,
        "home": Path.home(),
        "host_config": host_config_file,
        "credential": credential_file,
        "host_tmp": host_tmp_file,
    }
    host_tmp_relative = str(host_tmp_file.resolve().relative_to(Path("/tmp")))

    # A UDP connect performs local route selection but sends no packet.
    route_probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        route_probe.connect(("192.0.2.1", 9))
        host_network_ip = route_probe.getsockname()[0]
    except OSError as error:
        pytest.fail(f"could not select a host NIC address for the local deny probe: {error}")
    finally:
        route_probe.close()
    if host_network_ip.startswith("127.") or host_network_ip == "0.0.0.0":
        pytest.fail("route selection did not identify a non-loopback host NIC address")

    listener: socket.socket | None = None
    opened_runc_descriptor: int | None = None
    runc_descriptor: int | None = None
    start_read = start_write = gate_read = gate_write = -1
    process: subprocess.Popen[bytes] | None = None
    launch_submitted = False
    init_pid: int | None = None
    init_start: bytes | None = None
    fd_audit: tuple[tuple[int, str], ...] | None = None
    cgroup_path: Path | None = None
    systemd_cgroup_path: Path | None = None
    systemd_unit = f"acp-{container_id}.scope"
    cleanup_errors: list[str] = []
    controls: dict[str, str] = {}
    config: dict[str, Any] = {}
    try:
        if os.path.lexists(checkout_probe_directory):
            pytest.fail("unique test-owned checkout write-probe path already exists")
        checkout_probe_directory.mkdir(mode=0o700)
        checkout_probe_created = True
        checkout_probe_directory.chmod(0o700)
        checkout_probe_info = checkout_probe_directory.lstat()
        if (
            not stat.S_ISDIR(checkout_probe_info.st_mode)
            or checkout_probe_info.st_uid != os.geteuid()
            or stat.S_IMODE(checkout_probe_info.st_mode) != 0o700
        ):
            pytest.fail("checkout write-probe directory is not test-owned and private")
        checkout_probe_identity = (checkout_probe_info.st_dev, checkout_probe_info.st_ino)

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host_network_ip, 0))
        listener.listen(1)
        listener.setblocking(False)
        host_network_port = listener.getsockname()[1]

        opened_runc_descriptor = oci_worker._open_verified_runc_executable(pin)
        runc_descriptor = fcntl.fcntl(opened_runc_descriptor, fcntl.F_DUPFD_CLOEXEC, 10)
        os.close(opened_runc_descriptor)
        opened_runc_descriptor = None
        start_read, start_write = os.pipe2(os.O_CLOEXEC)
        gate_read, gate_write = os.pipe2(os.O_CLOEXEC)

        # The launcher waits on start_read so the test can write a payload
        # containing its exact host PID before runc loads config.json. Standard
        # streams go only to /dev/null; no host log file is inherited by the worker.
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-S",
                "-c",
                _RUNC_FD_LAUNCHER,
                str(start_read),
                str(gate_read),
                str(runc_descriptor),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            pass_fds=(start_read, gate_read, runc_descriptor),
            start_new_session=True,
            env={
                "HOME": str(Path.home()),
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
            },
        )
        os.close(start_read)
        start_read = -1
        os.close(gate_read)
        gate_read = -1

        host_runc_marker = f"acp-runc-{uuid.uuid4().hex}"
        script = _probe_script(
            host_paths=host_paths,
            host_tmp_relative=host_tmp_relative,
            host_runc_marker=host_runc_marker,
            host_runc_pid=process.pid,
            host_network_ip=host_network_ip,
            host_network_port=host_network_port,
        )
        config = oci_worker.build_oci_worker_config(
            bundle_root,
            workspace_snapshot,
            ("/bin/busybox", "sh", "-c", script),
            rootfs_pin=rootfs_pin,
            container_id=container_id,
            memory_bytes=_CONTAINER_MEMORY_BYTES,
            pids_limit=_CONTAINER_PIDS_LIMIT,
            cpu_quota_us=_CONTAINER_CPU_QUOTA_US,
            cpu_period_us=_CONTAINER_CPU_PERIOD_US,
            tmpfs_bytes=8 * 1024 * 1024,
            home_bytes=2 * 1024 * 1024,
        )
        if config["root"].get("readonly") is not True:
            pytest.fail("OCI rootfs policy is not read-only")
        file_size_limits = [
            limit for limit in config["process"]["rlimits"] if limit.get("type") == "RLIMIT_FSIZE"
        ]
        if file_size_limits != [
            {
                "type": "RLIMIT_FSIZE",
                "hard": _CONTAINER_FILESIZE_LIMIT_BYTES,
                "soft": _CONTAINER_FILESIZE_LIMIT_BYTES,
            }
        ]:
            pytest.fail("trampoline and OCI worker file-size limits must match exactly")
        if {mount["destination"] for mount in config["mounts"]} != {
            "/proc",
            "/workspace",
            "/tmp",
            "/home/agent",
        }:
            pytest.fail("OCI policy contains an unexpected mount destination")
        if any(mount["destination"] in {"/etc", "/usr"} for mount in config["mounts"]):
            pytest.fail("OCI policy mounted broad host configuration or toolchain paths")
        if "ACP_TEST_RUNC_MARKER" in {item.split("=", 1)[0] for item in config["process"]["env"]}:
            pytest.fail("host-only runc marker was placed in the OCI worker environment")
        config_path = bundle_root / "config.json"
        config_path.write_text(json.dumps(config, sort_keys=True), encoding="utf-8")
        config_path.chmod(0o600)

        run_argv = oci_worker.build_runc_run_argv(
            pin,
            state_root,
            bundle_root,
            workspace,
            pid_file,
            container_id,
        )
        payload = (
            json.dumps(
                {"argv": run_argv, "env": _runc_environment(marker=host_runc_marker)},
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        if len(payload) > 4096:
            pytest.fail("bounded runc launcher payload exceeded the pipe atomicity ceiling")
        if process.poll() is not None:
            pytest.fail("pinned runc launcher exited before receiving its exact invocation")
        # From this point onward, a partial pipe write may have submitted a
        # valid launch.  Cleanup must always address this exact unique ID.
        launch_submitted = True
        attempt_cleanup["launch_submitted"] = True
        if os.write(start_write, payload) != len(payload):
            pytest.fail("could not deliver the bounded runc invocation to the launcher")
        os.close(start_write)
        start_write = -1

        deadline = time.monotonic() + 12
        while not pid_file.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        if process.poll() is not None or not pid_file.exists():
            pytest.fail(f"runc did not reach the launch gate (exit={process.poll()})")
        host_env = Path(f"/proc/{process.pid}/environ").read_bytes()
        if host_runc_marker.encode("ascii") not in host_env:
            pytest.fail("pinned runc client did not retain its host-only marker")

        init_pid = int(read_private_runc_pid_file(pid_file, state_root))
        init_snapshot = read_linux_process_snapshot(init_pid)
        init_start = _snapshot_start_time(init_snapshot, init_pid, require_live=True)
        cgroup_path = _snapshot_cgroup_path(init_snapshot)
        systemd_cgroup_path = _systemd_control_group(systemd_unit)
        if not _systemd_scope_is_active(systemd_unit):
            pytest.fail("exact runc systemd scope was not active before gate release")
        if systemd_cgroup_path is None:
            pytest.fail("exact runc systemd scope did not report a live ControlGroup")
        if systemd_cgroup_path.resolve(strict=True) != cgroup_path.resolve(strict=True):
            pytest.fail("systemd scope ControlGroup did not match the worker init cgroup")
        state_code, state_output = _safe_run_pinned_runc(
            pin, runc_descriptor, state_root, ["state", container_id]
        )
        if state_code != 0:
            pytest.fail(f"runc state readback failed before gate release: {state_output}")
        state = json.loads(state_output)
        if (
            state.get("id") != container_id
            or state.get("status") != "running"
            or state.get("pid") != init_pid
            or Path(state.get("bundle", "")).resolve() != bundle_root.resolve()
        ):
            pytest.fail("runc state did not match the exact gated OCI attempt")

        controls = {
            "memory.max": cgroup_path.joinpath("memory.max").read_text().strip(),
            "pids.max": cgroup_path.joinpath("pids.max").read_text().strip(),
            "cpu.max": cgroup_path.joinpath("cpu.max").read_text().strip(),
        }
        if controls["memory.max"] != str(_CONTAINER_MEMORY_BYTES):
            pytest.fail("live cgroup memory.max did not match the OCI policy")
        if controls["pids.max"] != str(_CONTAINER_PIDS_LIMIT):
            pytest.fail("live cgroup pids.max did not match the OCI policy")
        if controls["cpu.max"] != f"{_CONTAINER_CPU_QUOTA_US} {_CONTAINER_CPU_PERIOD_US}":
            pytest.fail("live cgroup cpu.max did not match the OCI policy")

        # The launch gate is the proof boundary: the init and policy readbacks
        # are live, but the first candidate instruction has not written output.
        time.sleep(0.1)
        if process.poll() is not None:
            pytest.fail("runc exited while the candidate was required to remain behind the gate")
        if (workspace / "result.txt").exists() or (workspace / "isolation-result.txt").exists():
            pytest.fail("candidate wrote workspace output before the gate was released")

        os.write(gate_write, b"go\n")
        os.close(gate_write)
        gate_write = -1
        fd_ready = workspace / "fd-audit-ready"
        ready_deadline = time.monotonic() + 5
        while (
            not fd_ready.is_file() and process.poll() is None and time.monotonic() < ready_deadline
        ):
            time.sleep(0.01)
        if process.poll() is not None or not fd_ready.is_file():
            pytest.fail("candidate did not reach the host-side descriptor audit gate")
        if any(
            path.exists()
            for path in (
                workspace / "fd-audit.txt",
                workspace / "result.txt",
                workspace / "isolation-result.txt",
            )
        ):
            pytest.fail("candidate produced result output before host-side descriptor audit")
        fd_audit = _audit_worker_init_fd_table(
            init_pid,
            expected_start_time=init_start,
            expected_cgroup_path=cgroup_path,
        )
        if process.poll() is not None:
            pytest.fail("runc exited while candidate was behind the descriptor audit gate")
        if any(
            path.exists() for path in (workspace / "result.txt", workspace / "isolation-result.txt")
        ):
            pytest.fail(
                "candidate bypassed descriptor gate and produced output before host release"
            )
        release_fd = os.open(
            workspace / "fd-audit-release",
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            if os.write(release_fd, b"go\n") != 3:
                pytest.fail("could not release candidate descriptor-audit gate")
        finally:
            os.close(release_fd)
        try:
            returncode = process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            _kill_runc_group(process)
            pytest.fail("bounded OCI BusyBox fixture exceeded its 15-second deadline")
        if returncode != 0:
            pytest.fail(f"gated OCI fixture failed with exit {returncode}; fd audit={fd_audit!r}")

        result = (workspace / "isolation-result.txt").read_text(encoding="ascii")
        result_fields = dict(line.split("=", 1) for line in result.splitlines())
        assert int(result_fields["network_probe_rc"]) != 0
        assert result_fields["interfaces"] == "lo"
        assert (workspace / "result.txt").read_text(encoding="ascii") == "candidate result\n"
        assert (workspace / "absolute-host-tmp").is_symlink()
        assert (workspace / "relative-host-tmp").is_symlink()
        assert not checkout_write.exists()

        ready, _, _ = select.select([listener], [], [], 0)
        if ready:
            accepted, _address = listener.accept()
            accepted.close()
            pytest.fail("isolated worker reached the test-owned host NIC listener")

        print(
            json.dumps(
                {
                    "proof": "bounded direct runc launch using current ACP OCI config builder",
                    "worker_executor_integrated": False,
                    "kernel": Path("/proc/sys/kernel/osrelease").read_text().strip(),
                    "runc_version": observed_version,
                    "busybox": busybox_version,
                    "required_busybox_applets": sorted(
                        applets & {"cat", "grep", "ln", "nc", "readlink", "sed", "touch", "tr"}
                    ),
                    "rootfs_sha256": rootfs_digest,
                    "mount_destinations": [mount["destination"] for mount in config["mounts"]],
                    "cgroup_controls": controls,
                    "cgroup_path": str(cgroup_path),
                    "init_file_descriptors": [
                        {"fd": descriptor, "target": target}
                        for descriptor, target in (fd_audit or ())
                    ],
                    "systemd_unit": systemd_unit,
                    "isolation_result": result.strip(),
                    "host_paths_denied": [
                        "source checkout",
                        "sibling attempt",
                        "unrelated project",
                        "host home",
                        "synthetic host config and credential sentinels",
                        "host /etc/os-release",
                        "host /tmp sentinel",
                        "absolute and relative symlink targets",
                    ],
                    "checkout_write_probe": "unique test-owned canary; removed during teardown",
                    "network_probe": "host NIC listener was not reached",
                },
                sort_keys=True,
            )
        )
    finally:
        active_error = sys.exception()

        def close_fd(label: str, descriptor: int) -> None:
            if descriptor >= 0:
                _attempt_cleanup(cleanup_errors, label, lambda: os.close(descriptor))

        def process_is_running() -> bool | None:
            if process is None:
                return False
            return _attempt_cleanup(
                cleanup_errors,
                "could not inspect runc client process state",
                lambda: process.poll() is None,
            )

        def capture_process_snapshot(pid: int) -> Any | None:
            try:
                return read_linux_process_snapshot(pid)
            except (FileNotFoundError, ProcessLookupError):
                return None
            except Exception as error:
                if isinstance(error.__cause__, (FileNotFoundError, ProcessLookupError)):
                    return None
                cleanup_errors.append(
                    f"could not inspect exact init process before cleanup: "
                    f"{type(error).__name__}: {error}"
                )
                return None

        # Capture the exact runtime identity before closing the gate or killing
        # the runc client.  Missing evidence is tolerated only when no launch
        # was submitted; the unique-ID delete still runs after partial launch.
        pid_file_present = _cleanup_path_exists(
            cleanup_errors, "could not inspect runc PID file before cleanup", pid_file
        )
        if launch_submitted and pid_file_present is True and init_pid is None:
            captured_pid = _attempt_cleanup(
                cleanup_errors,
                "could not read exact runc PID file before cleanup",
                lambda: int(read_private_runc_pid_file(pid_file, state_root)),
            )
            if captured_pid is not None:
                init_pid = captured_pid
        if launch_submitted and init_pid is None:
            state_result = _attempt_cleanup(
                cleanup_errors,
                "could not inspect exact runc state before cleanup",
                lambda: _safe_run_pinned_runc(
                    pin, runc_descriptor, state_root, ["state", container_id]
                ),
            )
            if state_result is not None and state_result[0] == 0:
                parsed_state = _attempt_cleanup(
                    cleanup_errors,
                    "could not parse exact runc state before cleanup",
                    lambda: json.loads(state_result[1]),
                )
                if isinstance(parsed_state, dict) and parsed_state.get("id") == container_id:
                    candidate_pid = parsed_state.get("pid")
                    if type(candidate_pid) is int and candidate_pid > 0:
                        init_pid = candidate_pid
        if launch_submitted and init_pid is not None:
            snapshot = capture_process_snapshot(init_pid)
            if snapshot is not None and init_start is None:
                init_start = _attempt_cleanup(
                    cleanup_errors,
                    "could not capture exact init start time",
                    lambda: _snapshot_start_time(snapshot, init_pid, require_live=False),
                )
            if cgroup_path is None and snapshot is not None:
                cgroup_path = _attempt_cleanup(
                    cleanup_errors,
                    "could not capture exact init cgroup",
                    lambda: _snapshot_cgroup_path(snapshot),
                )
        if launch_submitted and systemd_cgroup_path is None:
            systemd_cgroup_path = _attempt_cleanup(
                cleanup_errors,
                "could not capture worker systemd cgroup before cleanup",
                lambda: _systemd_control_group(systemd_unit),
            )
        cleanup_errors.extend(
            _cleanup_identity_gaps(
                launch_submitted=launch_submitted,
                init_pid=init_pid,
                init_start=init_start,
                cgroup_path=cgroup_path,
                systemd_cgroup_path=systemd_cgroup_path,
            )
        )

        # Closing the gate writer makes an unapproved launch fail closed.
        # Close every pipe independently so a single EBADF cannot skip teardown.
        close_fd("could not close launch-payload writer", start_write)
        start_write = -1
        close_fd("could not close launch-payload reader", start_read)
        start_read = -1
        close_fd("could not close candidate-gate writer", gate_write)
        gate_write = -1
        close_fd("could not close candidate-gate reader", gate_read)
        gate_read = -1

        if process_is_running() is True:
            _attempt_cleanup(
                cleanup_errors,
                "could not terminate the exact runc process group",
                lambda: _kill_runc_group(process),
            )
            if process_is_running() is True:
                _attempt_cleanup(
                    cleanup_errors,
                    "could not terminate the exact runc client process",
                    lambda: process.kill(),
                )
        if process is not None:
            waited = _attempt_cleanup(
                cleanup_errors,
                "could not reap the exact runc client process",
                lambda: process.wait(timeout=3),
            )
            if waited is None and process_is_running() is True:
                _attempt_cleanup(
                    cleanup_errors,
                    "could not force-reap the exact runc client process",
                    lambda: (process.kill(), process.wait(timeout=3)),
                )

        delete_result: tuple[int, str] | None = None
        if launch_submitted:
            delete_result = _attempt_cleanup(
                cleanup_errors,
                "could not issue exact-ID forced runc deletion",
                lambda: _safe_run_pinned_runc(
                    pin, runc_descriptor, state_root, ["delete", "--force", container_id]
                ),
            )
        pid_file_present = _cleanup_path_exists(
            cleanup_errors, "could not inspect runc PID file after deletion", pid_file
        )
        if pid_file_present is True:
            recorded_pid = _attempt_cleanup(
                cleanup_errors,
                "could not revalidate runc PID file before unlink",
                lambda: int(read_private_runc_pid_file(pid_file, state_root)),
            )
            if recorded_pid is not None and init_pid is not None and recorded_pid != init_pid:
                cleanup_errors.append("runc PID file changed before scoped cleanup")
            elif recorded_pid is not None:
                _attempt_cleanup(
                    cleanup_errors,
                    "could not unlink exact private runc PID file",
                    lambda: pid_file.unlink(),
                )
        pid_file_present = _cleanup_path_exists(
            cleanup_errors, "could not verify runc PID file removal", pid_file
        )
        if pid_file_present is True:
            cleanup_errors.append("runc PID file remained after cleanup")
        state_path = state_root / container_id
        state_path_present = _cleanup_path_exists(
            cleanup_errors, "could not inspect exact runc state after deletion", state_path
        )
        if state_path_present is True:
            cleanup_errors.append("runc state directory remained after cleanup")

        paths_to_verify = {path for path in (cgroup_path, systemd_cgroup_path) if path is not None}
        cgroup_residue = False
        for path in paths_to_verify:
            deadline = time.monotonic() + 5
            path_present = _cleanup_path_exists(
                cleanup_errors, f"could not inspect cgroup path {path}", path
            )
            while path_present is True and time.monotonic() < deadline:
                time.sleep(0.05)
                path_present = _cleanup_path_exists(
                    cleanup_errors, f"could not recheck cgroup path {path}", path
                )
            if path_present is True:
                cleanup_errors.append(f"container cgroup remained after cleanup: {path}")
                cgroup_residue = True
        if launch_submitted:
            scope_verified = (
                _attempt_cleanup(
                    cleanup_errors,
                    "could not verify exact worker systemd scope absence",
                    lambda: (_wait_for_worker_scope_absent(container_id), True)[1],
                )
                is True
            )
        else:
            scope_verified = True

        if init_pid is not None and init_start is not None:

            def exact_init_survives() -> bool:
                current = capture_process_snapshot(init_pid)
                if current is None:
                    return False
                return _snapshot_start_time(current, init_pid, require_live=False) == init_start

            survives = _attempt_cleanup(
                cleanup_errors,
                "could not verify exact init PID/start-time absence",
                exact_init_survives,
            )
            if survives:
                cleanup_errors.append("the exact container init PID/start-time survived cleanup")

        if checkout_probe_created:
            _attempt_cleanup(
                cleanup_errors,
                "could not remove unique test-owned checkout write probe",
                lambda: _remove_checkout_write_probe(
                    checkout_probe_directory,
                    checkout_write,
                    checkout_probe_identity,
                    os.geteuid(),
                ),
            )
            probe_directory_present = _cleanup_path_exists(
                cleanup_errors,
                "could not verify checkout write-probe removal",
                checkout_probe_directory,
            )
            if probe_directory_present is True:
                cleanup_errors.append("unique checkout write-probe directory remained")
        client_still_running = process_is_running()
        if client_still_running is True:
            cleanup_errors.append("runc client process remained after cleanup")

        if (
            delete_result is not None
            and delete_result[0] != 0
            and (
                pid_file_present is not False
                or state_path_present is not False
                or cgroup_residue
                or not scope_verified
                or client_still_running is not False
            )
        ):
            cleanup_errors.append(
                f"exact-ID runc delete returned {delete_result[0]} with runtime residue: "
                f"{delete_result[1]}"
            )

        # A failed teardown retains the private evidence tree for diagnosis.
        if not cleanup_errors:
            attempt_cleanup["runtime_verified"] = True
            _attempt_cleanup(
                cleanup_errors,
                "could not remove private OCI bundle",
                lambda: shutil.rmtree(bundle_root),
            )
            _attempt_cleanup(
                cleanup_errors,
                "could not remove private runc state",
                lambda: shutil.rmtree(state_root),
            )
            bundle_present = _cleanup_path_exists(
                cleanup_errors, "could not verify private bundle removal", bundle_root
            )
            state_root_present = _cleanup_path_exists(
                cleanup_errors, "could not verify private state removal", state_root
            )
            if bundle_present or state_root_present:
                cleanup_errors.append("disposable OCI bundle or state directory remained")

        # Descriptor cleanup is an unconditional outermost stage.
        if listener is not None:
            _attempt_cleanup(cleanup_errors, "could not close host-only listener", listener.close)
        close_fd(
            "could not close pinned runc descriptor",
            runc_descriptor if runc_descriptor is not None else -1,
        )
        close_fd(
            "could not close original pinned runc descriptor",
            opened_runc_descriptor if opened_runc_descriptor is not None else -1,
        )
        if cleanup_errors:
            attempt_cleanup["preserve"] = True
            prior = (
                f"; original failure: {type(active_error).__name__}: {active_error}"
                if active_error
                else ""
            )
            raise AssertionError(
                "live OCI cleanup verification failed: " + "; ".join(cleanup_errors) + prior
            )
