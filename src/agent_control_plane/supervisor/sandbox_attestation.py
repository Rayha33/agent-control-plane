"""Validate the host observations required before opening an OCI worker gate.

This module does not launch runc or collect its state output. The trusted
executor must obtain these bounded observations from its pinned runtime,
private pid file, /proc, and systemd; this validator binds them to one exact
execution and returns a typed receipt for the durable journal. It is not by
itself a sandbox or a substitute for verifying mount/network policy.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .common import SupervisorError, canonical_json

_MAX_OBSERVATION_BYTES = 64 * 1024
_MAX_PID_FILE_BYTES = 11
_MAX_PID = (1 << 31) - 1
_INVOCATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_UNIT = re.compile(r"[A-Za-z0-9_.:@\\-]+\.(?:service|scope)\Z")
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

    container_id: str
    bundle_path: str
    monitor_pid: int
    monitor_identity: str
    runc_client_pid: int
    runc_client_identity: str
    wrapper_unit: str
    wrapper_invocation_id: str
    wrapper_control_group: str
    scope_unit: str
    scope_invocation_id: str
    cgroup_path: str
    init_pid: int
    init_identity: str
    runc_state_sha256: str
    evidence_sha256: str

    def audit_payload(self) -> dict[str, Any]:
        """Return the bounded, normalized receipt recorded with the transition."""

        return {
            "container_id": self.container_id,
            "bundle_path": self.bundle_path,
            "monitor_pid": self.monitor_pid,
            "monitor_identity": self.monitor_identity,
            "runc_client_pid": self.runc_client_pid,
            "runc_client_identity": self.runc_client_identity,
            "wrapper_unit": self.wrapper_unit,
            "wrapper_invocation_id": self.wrapper_invocation_id,
            "wrapper_control_group": self.wrapper_control_group,
            "scope_unit": self.scope_unit,
            "scope_invocation_id": self.scope_invocation_id,
            "cgroup_path": self.cgroup_path,
            "init_pid": self.init_pid,
            "init_identity": self.init_identity,
            "runc_state_sha256": self.runc_state_sha256,
            "evidence_sha256": self.evidence_sha256,
        }


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
    runc_state: bytes,
    pid_file_path: str | Path,
    state_root: str | Path,
    wrapper_properties: bytes,
    scope_properties: bytes,
    expected_container_id: str,
    expected_bundle_path: str,
    expected_monitor_pid: int,
    expected_monitor_identity: str,
    expected_runc_client_pid: int,
    expected_runc_client_identity: str,
    expected_wrapper_unit: str,
    expected_wrapper_invocation_id: str,
    expected_scope_unit: str,
    expected_scope_invocation_id: str,
    expected_cgroup_path: str,
) -> RunningRuntimeAttestation:
    """Collect PID-file and live procfs evidence, then bind command outputs.

    ``runc_state`` and the systemd property bytes must be bounded outputs from
    the trusted executor's pinned commands. This function opens the PID file
    and reads the three host process snapshots itself; it does not execute
    runc/systemctl or authenticate the caller that supplied their output.
    """

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
    return validate_running_runtime_attestation(
        runc_state=runc_state,
        pid_file=pid_file,
        process_snapshots=process_snapshots,
        wrapper_properties=wrapper_properties,
        scope_properties=scope_properties,
        expected_container_id=expected_container_id,
        expected_bundle_path=expected_bundle_path,
        expected_monitor_pid=expected_monitor_pid,
        expected_monitor_identity=expected_monitor_identity,
        expected_runc_client_pid=expected_runc_client_pid,
        expected_runc_client_identity=expected_runc_client_identity,
        expected_wrapper_unit=expected_wrapper_unit,
        expected_wrapper_invocation_id=expected_wrapper_invocation_id,
        expected_scope_unit=expected_scope_unit,
        expected_scope_invocation_id=expected_scope_invocation_id,
        expected_cgroup_path=expected_cgroup_path,
    )


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
    scope_properties: bytes,
    expected_container_id: str,
    expected_bundle_path: str,
    expected_monitor_pid: int,
    expected_monitor_identity: str,
    expected_runc_client_pid: int,
    expected_runc_client_identity: str,
    expected_wrapper_unit: str,
    expected_wrapper_invocation_id: str,
    expected_scope_unit: str,
    expected_scope_invocation_id: str,
    expected_cgroup_path: str,
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
    scope_unit = _unit(expected_scope_unit, ".scope", "scope unit")
    wrapper_invocation_id = _invocation(expected_wrapper_invocation_id, "wrapper invocation ID")
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
    scope = _parse_unit_properties(scope_properties)
    if (
        wrapper["ActiveState"] != "active"
        or wrapper["Id"] != wrapper_unit
        or wrapper["InvocationID"] != wrapper_invocation_id
        or scope["ActiveState"] != "active"
        or scope["Id"] != scope_unit
        or scope["InvocationID"] != scope_invocation_id
    ):
        raise _invalid("systemd unit state or invocation identity changed")
    wrapper_cgroup = _cgroup_path(wrapper["ControlGroup"], "wrapper cgroup")
    scope_cgroup = _cgroup_path(scope["ControlGroup"], "scope cgroup")
    if wrapper_cgroup == scope_cgroup or scope_cgroup != expected_scope:
        raise _invalid("systemd cgroup paths do not match the expected execution")

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

    normalized = {
        "container_id": container_id,
        "bundle_path": bundle_path,
        "monitor_pid": monitor_pid,
        "monitor_identity": monitor_identity,
        "runc_client_pid": runc_client_pid,
        "runc_client_identity": runc_client_identity,
        "wrapper_unit": wrapper_unit,
        "wrapper_invocation_id": wrapper_invocation_id,
        "wrapper_control_group": wrapper_cgroup,
        "scope_unit": scope_unit,
        "scope_invocation_id": scope_invocation_id,
        "cgroup_path": scope_cgroup,
        "init_pid": expected_init_pid,
        "init_identity": identities[expected_init_pid],
        "runc_state_sha256": hashlib.sha256(runc_state).hexdigest(),
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
            or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", value.container_id)
            or len({value.monitor_pid, value.runc_client_pid, value.init_pid}) != 3
            or value.wrapper_control_group == value.cgroup_path
            or PurePosixPath(value.cgroup_path).name != value.scope_unit
        ):
            return False
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
            or _unit(value.wrapper_unit, ".service", "wrapper unit") != value.wrapper_unit
            or _unit(value.scope_unit, ".scope", "scope unit") != value.scope_unit
            or _invocation(value.wrapper_invocation_id, "wrapper invocation ID")
            != value.wrapper_invocation_id
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
