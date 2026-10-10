"""Collect and validate host observations required before opening an OCI worker gate.

The trusted collector obtains bounded runc and systemd observations, then binds
them to the exact state root, PID file, executable pin, process identities, and
resource controls in a typed receipt for the durable journal. The validator
alone does not establish collector provenance, a sandbox, or mount/network
policy.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import threading
import weakref
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .common import SupervisorError, canonical_json
from .oci_worker import _oci_worker_systemd_slice

_MAX_OBSERVATION_BYTES = 64 * 1024
_MAX_PID_FILE_BYTES = 11
_MAX_CGROUP_CONTROL_BYTES = 128
_RUNTIME_COMMAND_TIMEOUT_SECONDS = 3.0
_MAX_PID = (1 << 31) - 1
_INVOCATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_ATTEMPT_SLICE_COMPONENT = re.compile(r"user-acp-[0-9a-f]{64}\.slice\Z")
_UNIT = re.compile(r"[A-Za-z0-9_.:@\\-]+\.(?:service|scope|slice)\Z")
_LINUX_IDENTITY = re.compile(r"linux:([1-9][0-9]*):(0|[1-9][0-9]*)\Z")
_PID_FILE = re.compile(rb"([1-9][0-9]{0,9})\n?\Z")
_LIVE_PROCESS_STATES = frozenset({b"R", b"S", b"D", b"T", b"t", b"W", b"K", b"P", b"I"})
_PROCESS_STATES = _LIVE_PROCESS_STATES | {b"Z", b"X", b"x"}


@dataclass(frozen=True)
class ProcessSnapshot:
    """Two PID-start observations around one cgroup read from the host procfs."""

    stat_before: bytes
    cgroup: bytes
    stat_after: bytes


@dataclass(frozen=True)
class RunningRuntimeAttestation:
    """Normalized evidence accepted by the sandbox execution journal."""

    monitor_placement: str
    container_id: str
    bundle_path: str
    monitor_pid: int
    monitor_identity: str
    runc_client_pid: int
    runc_client_identity: str
    wrapper_unit: str
    wrapper_invocation_id: str
    wrapper_control_group: str
    attempt_slice_unit: str
    attempt_slice_invocation_id: str
    attempt_slice_control_group: str
    scope_unit: str
    scope_invocation_id: str
    cgroup_path: str
    init_pid: int
    init_identity: str
    runc_state_sha256: str
    runc_state_root_path: str | None
    runc_state_root_device: int | None
    runc_state_root_inode: int | None
    runc_pid_file_path: str | None
    runc_executable_sha256: str | None
    memory_max_bytes: int
    cpu_quota: int
    cpu_period: int
    pids_max: int
    evidence_sha256: str

    def audit_payload(self) -> dict[str, Any]:
        """Return the bounded, normalized receipt recorded with the transition."""

        return {
            "monitor_placement": self.monitor_placement,
            "container_id": self.container_id,
            "bundle_path": self.bundle_path,
            "monitor_pid": self.monitor_pid,
            "monitor_identity": self.monitor_identity,
            "runc_client_pid": self.runc_client_pid,
            "runc_client_identity": self.runc_client_identity,
            "wrapper_unit": self.wrapper_unit,
            "wrapper_invocation_id": self.wrapper_invocation_id,
            "wrapper_control_group": self.wrapper_control_group,
            "attempt_slice_unit": self.attempt_slice_unit,
            "attempt_slice_invocation_id": self.attempt_slice_invocation_id,
            "attempt_slice_control_group": self.attempt_slice_control_group,
            "scope_unit": self.scope_unit,
            "scope_invocation_id": self.scope_invocation_id,
            "cgroup_path": self.cgroup_path,
            "init_pid": self.init_pid,
            "init_identity": self.init_identity,
            "runc_state_sha256": self.runc_state_sha256,
            "runc_state_root_path": self.runc_state_root_path,
            "runc_state_root_device": self.runc_state_root_device,
            "runc_state_root_inode": self.runc_state_root_inode,
            "runc_pid_file_path": self.runc_pid_file_path,
            "runc_executable_sha256": self.runc_executable_sha256,
            "memory_max_bytes": self.memory_max_bytes,
            "cpu_quota": self.cpu_quota,
            "cpu_period": self.cpu_period,
            "pids_max": self.pids_max,
            "evidence_sha256": self.evidence_sha256,
        }


_COLLECTED_ATTESTATION_LOCK = threading.Lock()
_COLLECTED_ATTESTATIONS: weakref.WeakValueDictionary[int, RunningRuntimeAttestation] = (
    weakref.WeakValueDictionary()
)


def running_attestation_has_collector_provenance(value: Any) -> bool:
    """Return true only for the exact object issued by the runtime collector.

    This is an accidental-misuse guard, not an authentication boundary against
    arbitrary code execution in the supervisor process.
    """

    if type(value) is not RunningRuntimeAttestation:
        return False
    with _COLLECTED_ATTESTATION_LOCK:
        return _COLLECTED_ATTESTATIONS.get(id(value)) is value


def read_linux_process_snapshot(pid: int) -> ProcessSnapshot:
    """Read a process start identity on both sides of its cgroup observation."""

    pid = _pid(pid, "process PID")
    if not sys.platform.startswith("linux"):
        raise _invalid("Linux procfs observations are unavailable on this platform")
    stat_path = f"/proc/{pid}/stat"
    cgroup_path = f"/proc/{pid}/cgroup"
    before = _read_proc_file(stat_path)
    cgroup = _read_proc_file(cgroup_path)
    after = _read_proc_file(stat_path)
    return ProcessSnapshot(stat_before=before, cgroup=cgroup, stat_after=after)


def read_cgroup_resource_controls(
    cgroup_path: str,
    *,
    cgroup_root: str | Path = "/sys/fs/cgroup",
) -> dict[str, bytes]:
    """Read the exact cgroup-v2 limits through pinned, no-follow directory FDs."""

    if not sys.platform.startswith("linux"):
        raise _invalid("Linux cgroup resource observations are unavailable on this platform")
    group = _cgroup_path(cgroup_path, "resource-control cgroup")
    root = _absolute_path(os.fspath(cgroup_root), "cgroup root")
    if root == "/sys/fs/cgroup":
        _require_cgroup2_mount(root)
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    if any(not getattr(os, flag, 0) for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")):
        raise _invalid("safe cgroup directory open flags are unavailable")

    root_fd = -1
    current_fd = -1
    try:
        root_fd = os.open(root, directory_flags)
        if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
            raise _invalid("cgroup root is not a directory")
        current_fd = root_fd
        for component in PurePosixPath(group).parts[1:]:
            next_fd = os.open(component, directory_flags, dir_fd=current_fd)
            if not stat.S_ISDIR(os.fstat(next_fd).st_mode):
                os.close(next_fd)
                raise _invalid("cgroup path contains a non-directory component")
            if current_fd != root_fd:
                os.close(current_fd)
            current_fd = next_fd

        observations: dict[str, bytes] = {}
        for name in ("memory.max", "cpu.max", "pids.max"):
            descriptor = os.open(name, file_flags, dir_fd=current_fd)
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise _invalid("cgroup resource control is not a regular file")
                data = bytearray()
                while len(data) <= _MAX_CGROUP_CONTROL_BYTES:
                    chunk = os.read(descriptor, _MAX_CGROUP_CONTROL_BYTES + 1 - len(data))
                    if not chunk:
                        break
                    data.extend(chunk)
                raw = bytes(data)
                _control_line(raw, name)
                observations[name] = raw
            finally:
                os.close(descriptor)
        return observations
    except SupervisorError:
        raise
    except OSError as error:
        raise _invalid("cgroup resource controls could not be read safely") from error
    finally:
        if current_fd >= 0 and current_fd != root_fd:
            os.close(current_fd)
        if root_fd >= 0:
            os.close(root_fd)


def _require_cgroup2_mount(root: str) -> None:
    """Fail closed unless mountinfo identifies the fixed root as cgroup v2."""

    raw = _read_proc_file("/proc/self/mountinfo")
    expected = os.fsencode(root)
    matching_filesystems: list[bytes] = []
    for line in raw.splitlines():
        before, separator, after = line.partition(b" - ")
        fields = before.split()
        filesystem = after.split()[:1]
        if not separator or len(fields) < 5 or not filesystem:
            continue
        mountpoint = re.sub(
            rb"\\([0-7]{3})",
            lambda match: bytes((int(match.group(1), 8),)),
            fields[4],
        )
        if mountpoint == expected:
            matching_filesystems.append(filesystem[0])
    if not matching_filesystems or any(value != b"cgroup2" for value in matching_filesystems):
        raise _invalid("fixed cgroup root is not mounted as cgroup v2")


def _control_line(raw: Any, field: str) -> bytes:
    if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_CGROUP_CONTROL_BYTES:
        raise _invalid(f"{field} observation is invalid or exceeds its byte limit")
    line = raw[:-1] if raw.endswith(b"\n") else raw
    if not line or b"\n" in line or b"\r" in line:
        raise _invalid(f"{field} observation is not one canonical line")
    try:
        line.decode("ascii")
    except UnicodeDecodeError as error:
        raise _invalid(f"{field} observation is not ASCII") from error
    return line


def _validate_cgroup_resource_controls(
    observations: Any,
    *,
    expected_memory_max_bytes: int,
    expected_cpu_quota: int,
    expected_cpu_period: int,
    expected_pids_max: int,
) -> dict[str, int]:
    expected = {
        "memory_max_bytes": expected_memory_max_bytes,
        "cpu_quota": expected_cpu_quota,
        "cpu_period": expected_cpu_period,
        "pids_max": expected_pids_max,
    }
    if any(
        type(value) is not int or not 1 <= value <= (1 << 64) - 1 for value in expected.values()
    ):
        raise _invalid("expected cgroup resource limits are invalid")
    if type(observations) is not dict or set(observations) != {
        "memory.max",
        "cpu.max",
        "pids.max",
    }:
        raise _invalid("cgroup resource observations are incomplete")
    expected_lines = {
        "memory.max": str(expected_memory_max_bytes).encode("ascii"),
        "cpu.max": f"{expected_cpu_quota} {expected_cpu_period}".encode("ascii"),
        "pids.max": str(expected_pids_max).encode("ascii"),
    }
    for name, expected_line in expected_lines.items():
        if _control_line(observations[name], name) != expected_line:
            raise _invalid(f"{name} does not match the exact OCI launch limit")
    return expected


def _runtime_source_binding(
    *,
    state_root_path: Any,
    state_root_device: Any,
    state_root_inode: Any,
    pid_file_path: Any,
    executable_sha256: Any,
) -> dict[str, Any]:
    """Validate the exact runc inputs attached to a collector-issued receipt."""

    values = (
        state_root_path,
        state_root_device,
        state_root_inode,
        pid_file_path,
        executable_sha256,
    )
    if all(value is None for value in values):
        return {
            "runc_state_root_path": None,
            "runc_state_root_device": None,
            "runc_state_root_inode": None,
            "runc_pid_file_path": None,
            "runc_executable_sha256": None,
        }
    if any(value is None for value in values):
        raise _invalid("runc source binding is incomplete")
    root_path = _absolute_path(state_root_path, "runc state root")
    pid_path = _absolute_path(pid_file_path, "runc PID file path")
    try:
        pid_relative_path = PurePosixPath(pid_path).relative_to(PurePosixPath(root_path))
    except ValueError as error:
        raise _invalid("runc PID file is outside its recorded state root") from error
    if not pid_relative_path.parts:
        raise _invalid("runc PID file path must not be the recorded state root itself")
    if (
        type(state_root_device) is not int
        or state_root_device < 0
        or type(state_root_inode) is not int
        or state_root_inode <= 0
        or not _is_sha256(executable_sha256)
    ):
        raise _invalid("runc source identity is invalid")
    return {
        "runc_state_root_path": root_path,
        "runc_state_root_device": state_root_device,
        "runc_state_root_inode": state_root_inode,
        "runc_pid_file_path": pid_path,
        "runc_executable_sha256": executable_sha256,
    }


def read_private_runc_pid_file(pid_file_path: str | Path, state_root: str | Path) -> bytes:
    """Read one stable PID file below a private runc state directory.

    The worker path must not treat a path-existence check as a reservation.
    runc writes its PID file via an exclusive temporary sibling and rename, so
    the executor must protect the directory and read the resulting inode with
    no-follow and before/after identity checks.
    """

    if os.geteuid() == 0:
        raise _invalid("runc PID observations require a non-root supervisor")
    raw_path = os.fspath(pid_file_path)
    raw_root = os.fspath(state_root)
    path_text = _absolute_path(raw_path, "runc pid file path")
    root_text = _absolute_path(raw_root, "runc state root")
    path = Path(path_text)
    root = Path(root_text)
    if any(not getattr(os, flag, 0) for flag in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC")):
        raise _invalid("safe runc PID file open flags are unavailable")

    # Reuse the OCI path policy: every ancestor must be non-replaceable by an
    # untrusted host identity, and each directory must be owner-private.
    from .oci_worker import _private_directory

    private_root = _private_directory(
        root, code="sandbox_runtime_attestation_invalid", label="runc state root"
    )
    private_parent = _private_directory(
        path.parent,
        code="sandbox_runtime_attestation_invalid",
        label="runc PID file parent",
    )
    if private_root != root or private_parent != path.parent:
        raise _invalid("runc PID file paths must not contain symlinked ancestors")
    try:
        private_parent.relative_to(private_root)
    except ValueError as error:
        raise _invalid("runc PID file must be inside the private state root") from error

    descriptor: int | None = None
    try:
        before_path = path.lstat()
        if not _valid_private_pid_file(before_path):
            raise _invalid("runc PID file is not a private, single-link regular file")
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not _valid_private_pid_file(opened) or _pid_file_identity(opened) != _pid_file_identity(
            before_path
        ):
            raise _invalid("runc PID file changed while it was opened")
        raw = _read_pid_file_bytes(descriptor)
        after_fd = os.fstat(descriptor)
        after_path = path.lstat()
        identity = _pid_file_identity(opened)
        if identity != _pid_file_identity(after_fd) or identity != _pid_file_identity(after_path):
            raise _invalid("runc PID file changed while it was read")
        _parse_pid_file(raw)
        return raw
    except SupervisorError:
        raise
    except OSError as error:
        raise _invalid("runc PID file could not be read safely") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def collect_running_runtime_attestation(
    *,
    runc_executable_pin: Any,
    state_root: str | Path,
    pid_file_path: str | Path,
    expected_container_id: str,
    expected_bundle_path: str,
    expected_monitor_pid: int,
    expected_monitor_identity: str,
    expected_runc_client_pid: int,
    expected_runc_client_identity: str,
    expected_wrapper_unit: str,
    expected_wrapper_invocation_id: str,
    expected_attempt_slice_unit: str,
    expected_attempt_slice_invocation_id: str,
    expected_scope_unit: str,
    expected_scope_invocation_id: str,
    expected_cgroup_path: str,
    expected_memory_max_bytes: int,
    expected_cpu_quota: int,
    expected_cpu_period: int,
    expected_pids_max: int,
) -> RunningRuntimeAttestation:
    """Collect a complete runtime receipt from the pinned runtime and user manager.

    Only this host-command path issues collector provenance accepted by the
    durable journal. Runtime state and systemd properties are read here using
    bounded commands; callers cannot mint a trusted receipt by supplying output
    bytes that merely parse correctly.
    """

    if not sys.platform.startswith("linux"):
        raise _invalid("trusted OCI runtime observations require Linux")
    from . import oci_worker

    runc_path = oci_worker._verify_trusted_runc_executable(runc_executable_pin)
    runc_executable_sha256 = getattr(runc_executable_pin, "sha256", None)
    if not isinstance(runc_executable_sha256, str) or not _is_sha256(runc_executable_sha256):
        raise _invalid("trusted runc pin has no valid executable digest")
    systemctl_path = _trusted_systemctl_executable()
    environment = _trusted_systemd_command_environment()
    container_id = _text(expected_container_id, "container ID")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", container_id):
        raise _invalid("container ID is invalid")
    state_root_path = _absolute_path(os.fspath(state_root), "runc state root")
    pid_file_path = _absolute_path(os.fspath(pid_file_path), "runc PID file path")
    try:
        pid_file_relative_path = PurePosixPath(pid_file_path).relative_to(
            PurePosixPath(state_root_path)
        )
    except ValueError as error:
        raise _invalid("runc PID file must be inside its state root") from error
    if not pid_file_relative_path.parts:
        raise _invalid("runc PID file path must not be the state root itself")
    expected_bundle_path = _absolute_path(expected_bundle_path, "bundle path")
    expected_cgroup_path = _cgroup_path(expected_cgroup_path, "expected scope cgroup")
    wrapper_unit = _unit(expected_wrapper_unit, ".service", "wrapper unit")
    attempt_slice_unit = _unit(expected_attempt_slice_unit, ".slice", "attempt slice unit")
    scope_unit = _unit(expected_scope_unit, ".scope", "scope unit")
    if len({wrapper_unit, attempt_slice_unit, scope_unit}) != 3:
        raise _invalid("wrapper, attempt slice, and scope units must be distinct")
    if attempt_slice_unit != _oci_worker_systemd_slice(container_id):
        raise _invalid("attempt slice unit does not match the exact container ID")
    _invocation(expected_wrapper_invocation_id, "wrapper invocation ID")
    _invocation(expected_attempt_slice_invocation_id, "attempt slice invocation ID")
    _invocation(expected_scope_invocation_id, "scope invocation ID")
    _identity(
        expected_monitor_identity, _pid(expected_monitor_pid, "monitor PID"), "monitor identity"
    )
    _identity(
        expected_runc_client_identity,
        _pid(expected_runc_client_pid, "runc client PID"),
        "runc client identity",
    )

    private_state_root = oci_worker._private_directory(
        state_root_path,
        code="sandbox_runtime_attestation_invalid",
        label="runc state root",
    )
    if os.fspath(private_state_root) != state_root_path:
        raise _invalid("runc state root path is not canonical")
    try:
        state_root_info_before = private_state_root.lstat()
    except OSError as error:
        raise _invalid("runc state root identity is unavailable") from error
    if stat.S_ISLNK(state_root_info_before.st_mode) or not stat.S_ISDIR(
        state_root_info_before.st_mode
    ):
        raise _invalid("runc state root is not a real directory")

    runc_fd = oci_worker._open_verified_runc_executable(runc_executable_pin)
    try:
        runc_state = _run_trusted_runtime_command(
            [str(runc_path), "--root", state_root_path, "state", container_id],
            environment=environment,
            executable_fd=runc_fd,
        )
    finally:
        os.close(runc_fd)

    properties = {
        unit: _run_trusted_runtime_command(
            [
                str(systemctl_path),
                "--user",
                "show",
                "--no-pager",
                "--property=ActiveState,ControlGroup,Id,InvocationID",
                "--",
                unit,
            ],
            environment=environment,
        )
        for unit in (
            wrapper_unit,
            attempt_slice_unit,
            scope_unit,
        )
    }

    attestation = _collect_running_runtime_attestation_from_observations(
        runc_state=runc_state,
        pid_file_path=pid_file_path,
        state_root=state_root_path,
        wrapper_properties=properties[wrapper_unit],
        attempt_slice_properties=properties[attempt_slice_unit],
        scope_properties=properties[scope_unit],
        expected_container_id=container_id,
        expected_bundle_path=expected_bundle_path,
        expected_monitor_pid=expected_monitor_pid,
        expected_monitor_identity=expected_monitor_identity,
        expected_runc_client_pid=expected_runc_client_pid,
        expected_runc_client_identity=expected_runc_client_identity,
        expected_wrapper_unit=wrapper_unit,
        expected_wrapper_invocation_id=expected_wrapper_invocation_id,
        expected_attempt_slice_unit=attempt_slice_unit,
        expected_attempt_slice_invocation_id=expected_attempt_slice_invocation_id,
        expected_scope_unit=scope_unit,
        expected_scope_invocation_id=expected_scope_invocation_id,
        expected_cgroup_path=expected_cgroup_path,
        expected_memory_max_bytes=expected_memory_max_bytes,
        expected_cpu_quota=expected_cpu_quota,
        expected_cpu_period=expected_cpu_period,
        expected_pids_max=expected_pids_max,
        runc_state_root_path=state_root_path,
        runc_state_root_device=state_root_info_before.st_dev,
        runc_state_root_inode=state_root_info_before.st_ino,
        runc_pid_file_path=pid_file_path,
        runc_executable_sha256=runc_executable_sha256,
    )
    try:
        state_root_info_after = private_state_root.lstat()
    except OSError as error:
        raise _invalid("runc state root changed while observations were collected") from error
    if (
        stat.S_ISLNK(state_root_info_after.st_mode)
        or not stat.S_ISDIR(state_root_info_after.st_mode)
        or (state_root_info_before.st_dev, state_root_info_before.st_ino)
        != (state_root_info_after.st_dev, state_root_info_after.st_ino)
    ):
        raise _invalid("runc state root changed while observations were collected")
    with _COLLECTED_ATTESTATION_LOCK:
        _COLLECTED_ATTESTATIONS[id(attestation)] = attestation
    return attestation


def _collect_running_runtime_attestation_from_observations(
    *,
    runc_state: bytes,
    pid_file_path: str | Path,
    state_root: str | Path,
    wrapper_properties: bytes,
    attempt_slice_properties: bytes,
    scope_properties: bytes,
    expected_container_id: str,
    expected_bundle_path: str,
    expected_monitor_pid: int,
    expected_monitor_identity: str,
    expected_runc_client_pid: int,
    expected_runc_client_identity: str,
    expected_wrapper_unit: str,
    expected_wrapper_invocation_id: str,
    expected_attempt_slice_unit: str,
    expected_attempt_slice_invocation_id: str,
    expected_scope_unit: str,
    expected_scope_invocation_id: str,
    expected_cgroup_path: str,
    expected_memory_max_bytes: int,
    expected_cpu_quota: int,
    expected_cpu_period: int,
    expected_pids_max: int,
    runc_state_root_path: str | None = None,
    runc_state_root_device: int | None = None,
    runc_state_root_inode: int | None = None,
    runc_pid_file_path: str | None = None,
    runc_executable_sha256: str | None = None,
) -> RunningRuntimeAttestation:
    """Normalize supplied command observations without granting provenance."""

    pid_file = read_private_runc_pid_file(pid_file_path, state_root)
    init_pid = _parse_pid_file(pid_file)
    pids = (
        _pid(expected_monitor_pid, "monitor PID"),
        _pid(expected_runc_client_pid, "runc client PID"),
        init_pid,
    )
    if len(set(pids)) != 3:
        raise _invalid("monitor, runc client, and container init PIDs must be distinct")
    process_snapshots = {pid: read_linux_process_snapshot(pid) for pid in pids}
    resource_control_files = read_cgroup_resource_controls(expected_cgroup_path)
    return validate_running_runtime_attestation(
        runc_state=runc_state,
        pid_file=pid_file,
        process_snapshots=process_snapshots,
        wrapper_properties=wrapper_properties,
        attempt_slice_properties=attempt_slice_properties,
        scope_properties=scope_properties,
        expected_container_id=expected_container_id,
        expected_bundle_path=expected_bundle_path,
        expected_monitor_pid=expected_monitor_pid,
        expected_monitor_identity=expected_monitor_identity,
        expected_runc_client_pid=expected_runc_client_pid,
        expected_runc_client_identity=expected_runc_client_identity,
        expected_wrapper_unit=expected_wrapper_unit,
        expected_wrapper_invocation_id=expected_wrapper_invocation_id,
        expected_attempt_slice_unit=expected_attempt_slice_unit,
        expected_attempt_slice_invocation_id=expected_attempt_slice_invocation_id,
        expected_scope_unit=expected_scope_unit,
        expected_scope_invocation_id=expected_scope_invocation_id,
        expected_cgroup_path=expected_cgroup_path,
        resource_control_files=resource_control_files,
        expected_memory_max_bytes=expected_memory_max_bytes,
        expected_cpu_quota=expected_cpu_quota,
        expected_cpu_period=expected_cpu_period,
        expected_pids_max=expected_pids_max,
        runc_state_root_path=runc_state_root_path,
        runc_state_root_device=runc_state_root_device,
        runc_state_root_inode=runc_state_root_inode,
        runc_pid_file_path=runc_pid_file_path,
        runc_executable_sha256=runc_executable_sha256,
    )


def _trusted_systemctl_executable() -> Path:
    """Resolve the host systemctl only from a root-owned, non-replaceable path."""

    if not sys.platform.startswith("linux"):
        raise _invalid("systemd observations are unavailable on this platform")
    from ..runtime_drivers import DriverError, resolve_trusted_executable

    module_root = Path(__file__).resolve().parents[3]
    for candidate in (Path("/usr/bin/systemctl"), Path("/bin/systemctl")):
        try:
            return resolve_trusted_executable(str(candidate), module_root, expected_owners={0})
        except DriverError:
            continue
    raise _invalid("a trusted root-owned systemctl executable is unavailable")


def _trusted_systemd_command_environment() -> dict[str, str]:
    """Build and validate the minimal environment for the current user manager."""

    from . import oci_worker

    environment = oci_worker._runc_client_environment()
    runtime_dir = Path(environment["XDG_RUNTIME_DIR"])
    try:
        runtime_info = runtime_dir.lstat()
        bus_info = (runtime_dir / "bus").lstat()
    except OSError as error:
        raise _invalid("the trusted systemd user-manager socket is unavailable") from error
    if (
        not stat.S_ISDIR(runtime_info.st_mode)
        or stat.S_ISLNK(runtime_info.st_mode)
        or runtime_info.st_uid != os.geteuid()
        or runtime_info.st_mode & 0o077
        or not stat.S_ISSOCK(bus_info.st_mode)
        or bus_info.st_uid != os.geteuid()
    ):
        raise _invalid("the systemd user-manager runtime directory is not private")
    return environment


def _run_trusted_runtime_command(
    argv: list[str], *, environment: dict[str, str], executable_fd: int | None = None
) -> bytes:
    """Run one fixed trusted observation command with a deadline and output cap."""

    from . import oci_worker

    kwargs: dict[str, Any] = {}
    if executable_fd is not None:
        kwargs = {"pass_fds": (executable_fd,), "exec_fd": executable_fd}
    try:
        returncode, stdout = oci_worker._run_bounded_command(
            argv,
            cwd="/",
            env=environment,
            timeout_seconds=_RUNTIME_COMMAND_TIMEOUT_SECONDS,
            max_output_bytes=_MAX_OBSERVATION_BYTES,
            **kwargs,
        )
        encoded = stdout.encode("utf-8")
    except (
        OSError,
        TimeoutError,
        ValueError,
        UnicodeDecodeError,
        subprocess.TimeoutExpired,
    ) as error:
        raise _invalid(
            "a trusted runtime observation command failed or exceeded its limits"
        ) from error
    if returncode != 0:
        raise _invalid("a trusted runtime observation command exited unsuccessfully")
    _bounded(encoded, "trusted runtime observation")
    return encoded


def verify_running_runtime_resource_controls(attestation: RunningRuntimeAttestation) -> None:
    """Re-read fixed-root cgroup-v2 controls immediately before gate authorization."""

    if type(attestation) is not RunningRuntimeAttestation:
        raise _invalid("release-time resource verification requires a typed receipt")
    try:
        current = read_cgroup_resource_controls(attestation.cgroup_path)
        _validate_cgroup_resource_controls(
            current,
            expected_memory_max_bytes=attestation.memory_max_bytes,
            expected_cpu_quota=attestation.cpu_quota,
            expected_cpu_period=attestation.cpu_period,
            expected_pids_max=attestation.pids_max,
        )
    except SupervisorError as error:
        raise SupervisorError(
            "sandbox_runtime_attestation_stale",
            "live cgroup controls no longer match the collected receipt",
        ) from error


def verify_running_runtime_process_membership(attestation: RunningRuntimeAttestation) -> None:
    """Re-read execution PIDs and cgroups before the journal authorizes init release.

    These sequential procfs observations narrow the gap between initial
    collection and gate authorization; they are not an atomic snapshot and do
    not authenticate caller-supplied runc or systemd command output.
    """

    if not running_attestation_is_self_consistent(attestation):
        raise _invalid("release-time process verification requires a self-consistent receipt")
    expected_processes = (
        (attestation.monitor_pid, attestation.monitor_identity, attestation.wrapper_control_group),
        (
            attestation.runc_client_pid,
            attestation.runc_client_identity,
            attestation.wrapper_control_group,
        ),
        (attestation.init_pid, attestation.init_identity, attestation.cgroup_path),
    )
    try:
        for pid, expected_identity, expected_cgroup in expected_processes:
            snapshot = read_linux_process_snapshot(pid)
            if type(snapshot) is not ProcessSnapshot:
                raise _invalid("release-time process observation has an unexpected type")
            before_pid, before_state, before_start = _parse_proc_stat(snapshot.stat_before)
            after_pid, after_state, after_start = _parse_proc_stat(snapshot.stat_after)
            if (
                before_pid != pid
                or after_pid != pid
                or before_start != after_start
                or before_state.encode("ascii") not in _LIVE_PROCESS_STATES
                or after_state.encode("ascii") not in _LIVE_PROCESS_STATES
                or f"linux:{pid}:{before_start}" != expected_identity
            ):
                raise _invalid("live execution process identity changed after collection")
            if _parse_proc_cgroup(snapshot.cgroup) != expected_cgroup:
                raise _invalid("live execution process cgroup membership changed after collection")
    except SupervisorError as error:
        raise SupervisorError(
            "sandbox_runtime_attestation_stale",
            "live process identities or cgroup membership no longer match the collected receipt",
        ) from error


def _valid_private_pid_file(info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
        and not stat.S_IMODE(info.st_mode) & 0o022
        and 0 < info.st_size <= _MAX_PID_FILE_BYTES
    )


def _pid_file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_pid_file_bytes(descriptor: int) -> bytes:
    data = bytearray()
    while len(data) <= _MAX_PID_FILE_BYTES:
        chunk = os.read(descriptor, _MAX_PID_FILE_BYTES + 1 - len(data))
        if not chunk:
            break
        data.extend(chunk)
    if not data or len(data) > _MAX_PID_FILE_BYTES:
        raise _invalid("runc PID file is empty or exceeds its byte limit")
    return bytes(data)


def _read_proc_file(path: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            data = stream.read(_MAX_OBSERVATION_BYTES + 1)
    except OSError as error:
        raise _invalid("a required host process observation could not be read") from error
    if len(data) > _MAX_OBSERVATION_BYTES:
        raise _invalid("a host process observation exceeded its byte limit")
    return data


def validate_running_runtime_attestation(
    *,
    runc_state: bytes,
    pid_file: bytes,
    process_snapshots: dict[int, ProcessSnapshot],
    wrapper_properties: bytes,
    attempt_slice_properties: bytes,
    scope_properties: bytes,
    expected_container_id: str,
    expected_bundle_path: str,
    expected_monitor_pid: int,
    expected_monitor_identity: str,
    expected_runc_client_pid: int,
    expected_runc_client_identity: str,
    expected_wrapper_unit: str,
    expected_wrapper_invocation_id: str,
    expected_attempt_slice_unit: str,
    expected_attempt_slice_invocation_id: str,
    expected_scope_unit: str,
    expected_scope_invocation_id: str,
    expected_cgroup_path: str,
    resource_control_files: dict[str, bytes],
    expected_memory_max_bytes: int,
    expected_cpu_quota: int,
    expected_cpu_period: int,
    expected_pids_max: int,
    runc_state_root_path: str | None = None,
    runc_state_root_device: int | None = None,
    runc_state_root_inode: int | None = None,
    runc_pid_file_path: str | None = None,
    runc_executable_sha256: str | None = None,
) -> RunningRuntimeAttestation:
    """Require one exact running runc/container/systemd/procfs identity tuple.

    `runc state` status is only one observation: the pid file, live process
    start identity, and cgroup membership must agree independently. Process
    snapshots bracket each cgroup read to detect differing PID start identities.
    """

    _bounded(runc_state, "runc state")
    _bounded(pid_file, "runc pid file")
    if not isinstance(process_snapshots, dict):
        raise _invalid("process observations are invalid")

    container_id = _text(expected_container_id, "container ID")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", container_id):
        raise _invalid("container ID is invalid")
    bundle_path = _absolute_path(expected_bundle_path, "bundle path")
    monitor_pid = _pid(expected_monitor_pid, "monitor PID")
    runc_client_pid = _pid(expected_runc_client_pid, "runc client PID")
    expected_init_pid = _pid(_parse_pid_file(pid_file), "container init PID")
    if len({monitor_pid, runc_client_pid, expected_init_pid}) != 3:
        raise _invalid("monitor, runc client, and container init PIDs must be distinct")
    monitor_identity = _identity(expected_monitor_identity, monitor_pid, "monitor identity")
    runc_client_identity = _identity(
        expected_runc_client_identity, runc_client_pid, "runc client identity"
    )
    wrapper_unit = _unit(expected_wrapper_unit, ".service", "wrapper unit")
    attempt_slice_unit = _unit(expected_attempt_slice_unit, ".slice", "attempt slice unit")
    scope_unit = _unit(expected_scope_unit, ".scope", "scope unit")
    wrapper_invocation_id = _invocation(expected_wrapper_invocation_id, "wrapper invocation ID")
    attempt_slice_invocation_id = _invocation(
        expected_attempt_slice_invocation_id, "attempt slice invocation ID"
    )
    scope_invocation_id = _invocation(expected_scope_invocation_id, "scope invocation ID")
    expected_scope = _cgroup_path(expected_cgroup_path, "expected scope cgroup")
    if PurePosixPath(expected_scope).name != scope_unit:
        raise _invalid("expected cgroup does not name the recorded scope")

    state = _parse_runc_state(runc_state)
    if (
        state.get("id") != container_id
        or state.get("status") != "running"
        or type(state.get("pid")) is not int
        or state["pid"] != expected_init_pid
        or state.get("bundle") != bundle_path
    ):
        raise _invalid("runc state does not match the expected running container")

    wrapper = _parse_unit_properties(wrapper_properties)
    attempt_slice = _parse_unit_properties(attempt_slice_properties)
    scope = _parse_unit_properties(scope_properties)
    if (
        wrapper["ActiveState"] != "active"
        or wrapper["Id"] != wrapper_unit
        or wrapper["InvocationID"] != wrapper_invocation_id
        or attempt_slice["ActiveState"] != "active"
        or attempt_slice["Id"] != attempt_slice_unit
        or attempt_slice["InvocationID"] != attempt_slice_invocation_id
        or scope["ActiveState"] != "active"
        or scope["Id"] != scope_unit
        or scope["InvocationID"] != scope_invocation_id
    ):
        raise _invalid("systemd unit state or invocation identity changed")
    wrapper_cgroup = _cgroup_path(wrapper["ControlGroup"], "wrapper cgroup")
    attempt_slice_cgroup = _cgroup_path(attempt_slice["ControlGroup"], "attempt slice cgroup")
    scope_cgroup = _cgroup_path(scope["ControlGroup"], "scope cgroup")
    monitor_cgroup_path = PurePosixPath(wrapper_cgroup)
    attempt_slice_path = PurePosixPath(attempt_slice_cgroup)
    monitor_is_in_worker_slice = monitor_cgroup_path.is_relative_to(attempt_slice_path)
    worker_slice_is_in_monitor = attempt_slice_path.is_relative_to(monitor_cgroup_path)
    monitor_is_in_any_attempt_slice = any(
        _ATTEMPT_SLICE_COMPONENT.fullmatch(part) is not None for part in monitor_cgroup_path.parts
    )
    if monitor_is_in_worker_slice or worker_slice_is_in_monitor or monitor_is_in_any_attempt_slice:
        raise _invalid("trusted monitor and worker attempt slice do not have separate cgroups")
    if (
        wrapper_cgroup == scope_cgroup
        or scope_cgroup != expected_scope
        or attempt_slice_unit != _oci_worker_systemd_slice(container_id)
        or PurePosixPath(attempt_slice_cgroup).name != attempt_slice_unit
        or PurePosixPath(scope_cgroup).parent.as_posix() != attempt_slice_cgroup
    ):
        raise _invalid("scope is not a direct child of the exact attempt slice")

    expected_pids = {monitor_pid, runc_client_pid, expected_init_pid}
    if set(process_snapshots) != expected_pids:
        raise _invalid("process observations do not cover the exact execution PIDs")
    identities: dict[int, str] = {}
    for pid, snapshot in process_snapshots.items():
        if type(snapshot) is not ProcessSnapshot:
            raise _invalid("process observation has an unexpected type")
        before_pid, before_state, before_start = _parse_proc_stat(snapshot.stat_before)
        after_pid, after_state, after_start = _parse_proc_stat(snapshot.stat_after)
        if before_pid != pid or after_pid != pid or before_start != after_start:
            raise _invalid("process identity changed during observation")
        if before_state in {"Z", "X", "x"} or after_state in {"Z", "X", "x"}:
            raise _invalid("a required execution process is no longer live")
        actual_cgroup = _parse_proc_cgroup(snapshot.cgroup)
        expected_process_cgroup = wrapper_cgroup if pid != expected_init_pid else scope_cgroup
        if actual_cgroup != expected_process_cgroup:
            raise _invalid("process is outside its recorded systemd cgroup")
        identities[pid] = f"linux:{pid}:{before_start}"

    if (
        identities[monitor_pid] != monitor_identity
        or identities[runc_client_pid] != runc_client_identity
    ):
        raise _invalid("monitor or runc client process identity changed")

    resource_limits = _validate_cgroup_resource_controls(
        resource_control_files,
        expected_memory_max_bytes=expected_memory_max_bytes,
        expected_cpu_quota=expected_cpu_quota,
        expected_cpu_period=expected_cpu_period,
        expected_pids_max=expected_pids_max,
    )
    source_binding = _runtime_source_binding(
        state_root_path=runc_state_root_path,
        state_root_device=runc_state_root_device,
        state_root_inode=runc_state_root_inode,
        pid_file_path=runc_pid_file_path,
        executable_sha256=runc_executable_sha256,
    )
    normalized = {
        "monitor_placement": "outside_attempt_slice",
        "container_id": container_id,
        "bundle_path": bundle_path,
        "monitor_pid": monitor_pid,
        "monitor_identity": monitor_identity,
        "runc_client_pid": runc_client_pid,
        "runc_client_identity": runc_client_identity,
        "wrapper_unit": wrapper_unit,
        "wrapper_invocation_id": wrapper_invocation_id,
        "wrapper_control_group": wrapper_cgroup,
        "attempt_slice_unit": attempt_slice_unit,
        "attempt_slice_invocation_id": attempt_slice_invocation_id,
        "attempt_slice_control_group": attempt_slice_cgroup,
        "scope_unit": scope_unit,
        "scope_invocation_id": scope_invocation_id,
        "cgroup_path": scope_cgroup,
        "init_pid": expected_init_pid,
        "init_identity": identities[expected_init_pid],
        "runc_state_sha256": hashlib.sha256(runc_state).hexdigest(),
        **source_binding,
        **resource_limits,
    }
    evidence_digest = hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()
    return RunningRuntimeAttestation(**normalized, evidence_sha256=evidence_digest)


def running_attestation_is_self_consistent(value: Any) -> bool:
    """Check receipt shape and its unkeyed digest; this does not establish provenance."""

    if type(value) is not RunningRuntimeAttestation:
        return False
    try:
        payload = value.audit_payload()
        claimed_digest = payload.pop("evidence_sha256")
        if (
            not _is_sha256(claimed_digest)
            or not _is_sha256(value.runc_state_sha256)
            or any(
                type(limit) is not int or not 1 <= limit <= (1 << 64) - 1
                for limit in (
                    value.memory_max_bytes,
                    value.cpu_quota,
                    value.cpu_period,
                    value.pids_max,
                )
            )
            or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", value.container_id)
            or len({value.monitor_pid, value.runc_client_pid, value.init_pid}) != 3
            or value.monitor_placement != "outside_attempt_slice"
            or value.wrapper_control_group == value.cgroup_path
            or value.attempt_slice_unit != _oci_worker_systemd_slice(value.container_id)
            or PurePosixPath(value.cgroup_path).name != value.scope_unit
            or PurePosixPath(value.attempt_slice_control_group).name != value.attempt_slice_unit
            or PurePosixPath(value.wrapper_control_group).is_relative_to(
                PurePosixPath(value.attempt_slice_control_group)
            )
            or PurePosixPath(value.attempt_slice_control_group).is_relative_to(
                PurePosixPath(value.wrapper_control_group)
            )
            or any(
                _ATTEMPT_SLICE_COMPONENT.fullmatch(part) is not None
                for part in PurePosixPath(value.wrapper_control_group).parts
            )
            or PurePosixPath(value.cgroup_path).parent.as_posix()
            != value.attempt_slice_control_group
        ):
            return False
        _runtime_source_binding(
            state_root_path=value.runc_state_root_path,
            state_root_device=value.runc_state_root_device,
            state_root_inode=value.runc_state_root_inode,
            pid_file_path=value.runc_pid_file_path,
            executable_sha256=value.runc_executable_sha256,
        )
        if (
            _pid(value.monitor_pid, "monitor PID") != value.monitor_pid
            or _pid(value.runc_client_pid, "runc client PID") != value.runc_client_pid
            or _pid(value.init_pid, "init PID") != value.init_pid
            or _identity(value.monitor_identity, value.monitor_pid, "monitor identity")
            != value.monitor_identity
            or _identity(value.runc_client_identity, value.runc_client_pid, "runc client identity")
            != value.runc_client_identity
            or _identity(value.init_identity, value.init_pid, "init identity")
            != value.init_identity
            or _absolute_path(value.bundle_path, "bundle path") != value.bundle_path
            or _cgroup_path(value.cgroup_path, "scope cgroup") != value.cgroup_path
            or _cgroup_path(value.wrapper_control_group, "wrapper cgroup")
            != value.wrapper_control_group
            or _cgroup_path(value.attempt_slice_control_group, "attempt slice cgroup")
            != value.attempt_slice_control_group
            or _unit(value.wrapper_unit, ".service", "wrapper unit") != value.wrapper_unit
            or _unit(value.attempt_slice_unit, ".slice", "attempt slice unit")
            != value.attempt_slice_unit
            or _unit(value.scope_unit, ".scope", "scope unit") != value.scope_unit
            or _invocation(value.wrapper_invocation_id, "wrapper invocation ID")
            != value.wrapper_invocation_id
            or _invocation(value.attempt_slice_invocation_id, "attempt slice invocation ID")
            != value.attempt_slice_invocation_id
            or _invocation(value.scope_invocation_id, "scope invocation ID")
            != value.scope_invocation_id
        ):
            return False
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest() == claimed_digest
    except (SupervisorError, TypeError, ValueError):
        return False


def _parse_runc_state(raw: bytes) -> dict[str, Any]:
    try:
        state = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise _invalid("runc state is not valid, unique-key JSON") from error
    if not isinstance(state, dict):
        raise _invalid("runc state is not a JSON object")
    return state


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant: {value}")


def _parse_pid_file(raw: bytes) -> int:
    match = _PID_FILE.fullmatch(raw)
    if match is None:
        raise _invalid("runc pid file is not one canonical decimal PID")
    return _pid(int(match.group(1)), "runc pid file PID")


def _parse_proc_stat(raw: bytes) -> tuple[int, str, str]:
    _bounded(raw, "proc stat")
    opening = raw.find(b" (")
    closing = raw.rfind(b")")
    if opening <= 0 or closing <= opening + 1:
        raise _invalid("proc stat is malformed")
    pid_bytes = raw[:opening]
    if not re.fullmatch(rb"[1-9][0-9]{0,9}", pid_bytes):
        raise _invalid("proc stat PID is malformed")
    fields = raw[closing + 1 :].split()
    if (
        len(fields) <= 19
        or fields[0] not in _PROCESS_STATES
        or not re.fullmatch(rb"[0-9]+", fields[19])
    ):
        raise _invalid("proc stat lacks a valid state or start identity")
    return int(pid_bytes), fields[0].decode("ascii"), fields[19].decode("ascii")


def _parse_proc_cgroup(raw: bytes) -> str:
    _bounded(raw, "proc cgroup")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise _invalid("proc cgroup is not ASCII") from error
    unified: list[str] = []
    for line in lines:
        hierarchy, separator, rest = line.partition(":")
        controllers, separator2, path = rest.partition(":")
        if not separator or not separator2 or not hierarchy.isdecimal():
            raise _invalid("proc cgroup has a malformed hierarchy row")
        if hierarchy == "0" and controllers == "":
            unified.append(path)
    if len(unified) != 1:
        raise _invalid("proc cgroup does not contain exactly one unified hierarchy")
    return _cgroup_path(unified[0], "proc cgroup")


def _parse_unit_properties(raw: bytes) -> dict[str, str]:
    _bounded(raw, "systemd properties")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise _invalid("systemd properties are not ASCII") from error
    properties: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator or not key or value != value.strip() or key in properties:
            raise _invalid("systemd properties are malformed or duplicated")
        properties[key] = value
    if set(properties) != {"ActiveState", "ControlGroup", "Id", "InvocationID"}:
        raise _invalid("systemd properties are incomplete or unexpected")
    return properties


def _identity(value: Any, pid: int, field: str) -> str:
    if not isinstance(value, str):
        raise _invalid(f"{field} is invalid")
    match = _LINUX_IDENTITY.fullmatch(value)
    if match is None or int(match.group(1)) != pid:
        raise _invalid(f"{field} is invalid")
    return value


def _pid(value: Any, field: str) -> int:
    if type(value) is not int or not 0 < value <= _MAX_PID:
        raise _invalid(f"{field} is invalid")
    return value


def _unit(value: Any, suffix: str, field: str) -> str:
    if not isinstance(value, str) or not _UNIT.fullmatch(value) or not value.endswith(suffix):
        raise _invalid(f"{field} is invalid")
    return value


def _invocation(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _INVOCATION_ID.fullmatch(value):
        raise _invalid(f"{field} is invalid")
    return value


def _absolute_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise _invalid(f"{field} is invalid")
    path = PurePosixPath(value)
    if (
        not path.is_absolute()
        or value.startswith("//")
        or path.as_posix() != value
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise _invalid(f"{field} is not canonical")
    return value


def _cgroup_path(value: Any, field: str) -> str:
    path = _absolute_path(value, field)
    if path == "/":
        raise _invalid(f"{field} is not an execution cgroup")
    return path


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise _invalid(f"{field} is invalid")
    return value


def _bounded(value: Any, field: str) -> bytes:
    if not isinstance(value, bytes) or len(value) > _MAX_OBSERVATION_BYTES:
        raise _invalid(f"{field} is invalid or too large")
    return value


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _invalid(message: str) -> SupervisorError:
    return SupervisorError("sandbox_runtime_attestation_invalid", message)
