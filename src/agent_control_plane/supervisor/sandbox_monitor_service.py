"""Production systemd producer for authenticated sandbox-scope monitoring.

This starts a per-execution monitor service outside the worker slice after a
trusted launcher has durably recorded the exact scope identity. It owns status
and cancellation of that one scope and survives supervisor exit. The separate
in-slice launch-driver owns candidate launch, its process-local handle, and
wait/reap/cleanup after the scope is stopped. Neither service enables
``run_worker`` or recovers a missing control key.
"""

from __future__ import annotations

import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from . import sandbox_monitor_lifecycle as lifecycle
from .sandbox_attestation import (
    _run_trusted_runtime_command,
    _trusted_systemctl_executable,
    _trusted_systemd_command_environment,
    verify_linux_process_membership,
)
from .sandbox_monitor_ipc import (
    SANDBOX_MONITOR_OPERATION_TIMEOUT_SECONDS,
    SandboxMonitorControlClient,
    SandboxMonitorControlServer,
    SandboxMonitorIPCError,
    _linux_process_identity,
    _open_private_directory,
)
from .sandbox_monitor_lifecycle import _read_unit_properties
from .sandbox_monitor_receipt import (
    SandboxMonitorReceipt,
    SandboxMonitorReceiptError,
    _reject_duplicate_keys,
    load_or_create_sandbox_monitor_control_key,
    read_sandbox_monitor_control_key,
    read_sandbox_monitor_receipt,
    sandbox_attempt_slice_unit,
    sandbox_container_id,
    sandbox_monitor_service_unit,
    validate_monitor_service_reconciliation,
    write_sandbox_monitor_receipt,
)

_MONITOR_SLICE_UNIT = "user-acp.slice"
_WORKER_SCOPE_PREFIX = "acp-"
_BINDING_NAME = "scope-binding.json"
_BINDING_LIMIT = 4096
_INVOCATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_SCOPE_UNIT = re.compile(r"[A-Za-z0-9_.:@\-]+\.scope\Z")
_PROPERTY_SET = ("Id", "LoadState", "ActiveState", "InvocationID", "ControlGroup", "Slice")
_SCOPE_CANCEL_GRACE_SECONDS = 2.0
_SCOPE_CANCEL_FORCE_WAIT_SECONDS = 5.0
_SCOPE_CANCEL_POLL_SECONDS = 0.05
_MONITOR_PROPERTIES = (
    "Id",
    "LoadState",
    "ActiveState",
    "InvocationID",
    "ControlGroup",
    "Slice",
    "MainPID",
)
_ATTEMPT_SLICE_PROPERTIES = (
    "Id",
    "LoadState",
    "ActiveState",
    "InvocationID",
    "ControlGroup",
    "Slice",
)
_RUNC_CLIENT_SCOPE_PREFIX = "acp-runc-client-"


class SandboxMonitorServiceError(RuntimeError):
    """The production monitor could not start or attest its exact scope."""


@dataclass(frozen=True)
class RuncClientScopeBinding:
    """Exact manager and PID identity for the held pinned-runc client."""

    attempt_id: str
    claim_token: int
    execution_id: str
    pid: int
    pid_identity: str
    scope_unit: str
    scope_invocation_id: str
    scope_control_group: str
    attempt_slice_unit: str
    attempt_slice_invocation_id: str
    attempt_slice_control_group: str


def sandbox_runc_client_scope_unit(attempt_id: str, claim_token: int, execution_id: str) -> str:
    """Return the collision-resistant transient scope name for one execution."""

    container_id = sandbox_container_id(attempt_id, claim_token, execution_id)
    return f"{_RUNC_CLIENT_SCOPE_PREFIX}{container_id.removeprefix('acp-')}.scope"


@dataclass(frozen=True)
class SandboxMonitorScopeBinding:
    """Immutable scope identity captured from the durable launch journal."""

    attempt_id: str
    claim_token: int
    execution_id: str
    scope_unit: str
    scope_invocation_id: str
    scope_control_group: str
    attempt_slice_unit: str
    attempt_slice_control_group: str

    def __post_init__(self) -> None:
        identity = (self.attempt_id, self.claim_token, self.execution_id)
        try:
            container_id = sandbox_container_id(*identity)
        except (TypeError, SandboxMonitorReceiptError) as error:
            raise SandboxMonitorServiceError("monitor execution identity is invalid") from error
        expected_slice = sandbox_attempt_slice_unit(*identity)
        # oci_worker encodes `slice:acp:<container_id>` for runc's systemd
        # cgroup manager, so the resulting scope has both the manager prefix
        # and the already-prefixed container ID.
        expected_scope_unit = f"{_WORKER_SCOPE_PREFIX}{container_id}.scope"
        if not isinstance(self.scope_control_group, str) or not isinstance(
            self.attempt_slice_control_group, str
        ):
            raise SandboxMonitorServiceError("monitor cgroup binding is invalid")
        scope_path = PurePosixPath(self.scope_control_group)
        attempt_path = PurePosixPath(self.attempt_slice_control_group)
        if (
            not isinstance(self.scope_unit, str)
            or _SCOPE_UNIT.fullmatch(self.scope_unit) is None
            or self.scope_unit != expected_scope_unit
            or not isinstance(self.scope_invocation_id, str)
            or _INVOCATION_ID.fullmatch(self.scope_invocation_id) is None
            or self.attempt_slice_unit != expected_slice
            or scope_path.as_posix() != self.scope_control_group
            or attempt_path.as_posix() != self.attempt_slice_control_group
            or not scope_path.is_absolute()
            or not attempt_path.is_absolute()
            or any(
                part in {".", ".."} for path in (scope_path, attempt_path) for part in path.parts
            )
            or scope_path.parent != attempt_path
            or scope_path.name != self.scope_unit
            or attempt_path.name != self.attempt_slice_unit
            or attempt_path.parent.name != _MONITOR_SLICE_UNIT
        ):
            raise SandboxMonitorServiceError("monitor scope binding is incomplete or mismatched")

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "attempt_id": self.attempt_id,
            "claim_token": self.claim_token,
            "execution_id": self.execution_id,
            "scope_unit": self.scope_unit,
            "scope_invocation_id": self.scope_invocation_id,
            "scope_control_group": self.scope_control_group,
            "attempt_slice_unit": self.attempt_slice_unit,
            "attempt_slice_control_group": self.attempt_slice_control_group,
        }

    @classmethod
    def from_dict(cls, value: Any) -> SandboxMonitorScopeBinding:
        expected = {
            "version",
            "attempt_id",
            "claim_token",
            "execution_id",
            "scope_unit",
            "scope_invocation_id",
            "scope_control_group",
            "attempt_slice_unit",
            "attempt_slice_control_group",
        }
        if (
            not isinstance(value, dict)
            or set(value) != expected
            or type(value["version"]) is not int
            or value["version"] != 1
            or type(value["claim_token"]) is not int
            or any(
                not isinstance(value[field], str) for field in expected - {"version", "claim_token"}
            )
        ):
            raise SandboxMonitorServiceError("monitor scope binding has an unsupported shape")
        return cls(**{field: value[field] for field in expected if field != "version"})


def _control_directory(
    state_path: str | Path, expected_identity: tuple[str, int, str]
) -> tuple[Path, Path, Path]:
    state = Path(state_path)
    if (
        not state.is_absolute()
        or state == Path("/")
        or ".." in state.parts
        or str(state) != os.path.normpath(str(state))
    ):
        raise SandboxMonitorServiceError("monitor state path is not canonical and absolute")
    try:
        state_fd = _open_private_directory(state)
    except (OSError, SandboxMonitorIPCError) as error:
        raise SandboxMonitorServiceError("monitor state root is not a private directory") from error
    try:
        try:
            os.mkdir("monitor", 0o700, dir_fd=state_fd)
            os.fsync(state_fd)
        except FileExistsError:
            pass
        control_fd = os.open(
            "monitor",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=state_fd,
        )
        try:
            info = os.fstat(control_fd)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise SandboxMonitorServiceError("monitor control directory is not private")
        finally:
            os.close(control_fd)
    except SandboxMonitorServiceError:
        raise
    except OSError as error:
        raise SandboxMonitorServiceError(
            "monitor control directory could not be opened safely"
        ) from error
    finally:
        os.close(state_fd)
    directory, receipt, socket_path = lifecycle.sandbox_monitor_control_paths(
        state_path=state, expected_identity=expected_identity
    )
    return directory, receipt, socket_path


def _trusted_systemd_run_executable() -> Path:
    """Resolve systemd-run only from a root-owned, non-replaceable path."""

    from ..runtime_drivers import DriverError, resolve_trusted_executable

    module_root = Path(__file__).resolve().parents[3]
    for candidate in (Path("/usr/bin/systemd-run"), Path("/bin/systemd-run")):
        try:
            return resolve_trusted_executable(str(candidate), module_root, expected_owners={0})
        except DriverError:
            continue
    raise SandboxMonitorServiceError("a trusted root-owned systemd-run is unavailable")


def _trusted_busctl_executable() -> Path:
    """Resolve busctl only from a root-owned, non-replaceable system path."""

    from ..runtime_drivers import DriverError, resolve_trusted_executable

    module_root = Path(__file__).resolve().parents[3]
    for candidate in (Path("/usr/bin/busctl"), Path("/bin/busctl")):
        try:
            return resolve_trusted_executable(str(candidate), module_root, expected_owners={0})
        except DriverError:
            continue
    raise SandboxMonitorServiceError("a trusted root-owned busctl is unavailable")


def attach_held_runc_client_to_attempt_scope(
    *,
    expected_identity: tuple[str, int, str],
    pid: int,
    pid_identity: str,
    monitor_control_group: str,
    attempt_slice_invocation_id: str,
    attempt_slice_control_group: str,
    timeout_seconds: float = 10.0,
) -> RuncClientScopeBinding:
    """Experimental systemd primitive: move one held child into a transient scope.

    This must be called while the private launcher is still blocked on its
    exec-ack pipe. After an uncertain D-Bus result, exact readback may adopt
    only this still-held PID in the expected active scope. The caller must not
    retry unit creation or release the execution gate on an unresolved result.

    This primitive is not used by the selected launch-driver architecture.
    Calling it for the production runc client would move that client out of the
    exact launch-driver service cgroup and invalidate the existing attestation
    contract.
    """

    if type(expected_identity) is not tuple or len(expected_identity) != 3:
        raise SandboxMonitorServiceError("runc client execution identity is invalid")
    attempt_id, claim_token, execution_id = expected_identity
    try:
        attempt_slice_unit = sandbox_attempt_slice_unit(*expected_identity)
        scope_unit = sandbox_runc_client_scope_unit(*expected_identity)
    except (TypeError, SandboxMonitorReceiptError) as error:
        raise SandboxMonitorServiceError("runc client execution identity is invalid") from error
    if (
        type(pid) is not int
        or pid <= 0
        or not isinstance(pid_identity, str)
        or re.fullmatch(rf"linux:{pid}:[1-9][0-9]*", pid_identity) is None
        or type(timeout_seconds) not in {int, float}
        or not 0.2 <= timeout_seconds <= 30
        or not isinstance(attempt_slice_invocation_id, str)
        or _INVOCATION_ID.fullmatch(attempt_slice_invocation_id) is None
    ):
        raise SandboxMonitorServiceError("runc client process or attempt slice identity is invalid")

    def canonical_cgroup(value: str, label: str) -> PurePosixPath:
        if (
            not isinstance(value, str)
            or not value.startswith("/")
            or "\x00" in value
            or "\n" in value
            or "\r" in value
        ):
            raise SandboxMonitorServiceError(f"{label} is invalid")
        path = PurePosixPath(value)
        if path.as_posix() != value or any(part in {".", ".."} for part in path.parts):
            raise SandboxMonitorServiceError(f"{label} is not canonical")
        return path

    monitor_path = canonical_cgroup(monitor_control_group, "monitor cgroup")
    attempt_path = canonical_cgroup(attempt_slice_control_group, "attempt slice cgroup")
    if (
        attempt_path.name != attempt_slice_unit
        or attempt_path.parent.name != _MONITOR_SLICE_UNIT
        or monitor_path.is_relative_to(attempt_path)
        or attempt_path.is_relative_to(monitor_path)
    ):
        raise SandboxMonitorServiceError("monitor and attempt slice identities are not disjoint")

    slice_properties = _unit_properties(attempt_slice_unit, _ATTEMPT_SLICE_PROPERTIES)
    if (
        slice_properties.get("Id") != attempt_slice_unit
        or slice_properties.get("LoadState") != "loaded"
        or slice_properties.get("ActiveState") != "active"
        or slice_properties.get("InvocationID") != attempt_slice_invocation_id
        or slice_properties.get("ControlGroup") != attempt_slice_control_group
        or slice_properties.get("Slice") != _MONITOR_SLICE_UNIT
    ):
        raise SandboxMonitorServiceError("attempt slice identity changed before runc attachment")

    verify_linux_process_membership(
        pid,
        expected_cgroup=monitor_control_group,
        expected_identity=pid_identity,
    )
    previous = _unit_properties(scope_unit, _PROPERTY_SET)
    if previous.get("LoadState") != "not-found":
        raise SandboxMonitorServiceError("runc client scope already exists; refusing takeover")

    # This is the systemd Manager.StartTransientUnit signature. `PIDs` is a
    # construction-only scope property; `fail` prevents replacing an existing
    # unit of the same unique name. Do not retry if this call has an uncertain
    # result: readback below can adopt only the exact same still-held PID.
    start_error: Exception | None = None
    try:
        _run_trusted_runtime_command(
            [
                str(_trusted_busctl_executable()),
                "--user",
                "call",
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "StartTransientUnit",
                "ssa(sv)a(sa(sv))",
                scope_unit,
                "fail",
                "2",
                "Slice",
                "s",
                attempt_slice_unit,
                "PIDs",
                "au",
                "1",
                str(pid),
                "0",
            ],
            environment=_trusted_systemd_command_environment(),
        )
    except Exception as error:
        # The manager may have completed StartTransientUnit before the bus
        # client lost its reply. Never issue a second call; proceed only if
        # exact readback proves this same held PID was attached as requested.
        start_error = error

    deadline = time.monotonic() + float(timeout_seconds)
    scope_properties: dict[str, str] = {}
    while time.monotonic() < deadline:
        scope_properties = _unit_properties(scope_unit, _PROPERTY_SET)
        if scope_properties.get("LoadState") == "not-found":
            time.sleep(0.05)
            continue
        if (
            scope_properties.get("Id") != scope_unit
            or scope_properties.get("LoadState") != "loaded"
            or scope_properties.get("InvocationID") == ""
            or scope_properties.get("ControlGroup") == ""
            or scope_properties.get("Slice") != attempt_slice_unit
        ):
            raise SandboxMonitorServiceError("runc client scope readback is incomplete or stale")
        if scope_properties.get("ActiveState") == "active":
            break
        if scope_properties.get("ActiveState") not in {"activating", "reloading"}:
            raise SandboxMonitorServiceError("runc client scope did not become active")
        time.sleep(0.05)
    else:
        raise SandboxMonitorServiceError(
            "runc client scope result is ambiguous; caller must close, reap, and retain the fence"
        ) from start_error

    invocation_id = scope_properties["InvocationID"]
    control_group = scope_properties["ControlGroup"]
    control_path = canonical_cgroup(control_group, "runc client scope cgroup")
    if (
        _INVOCATION_ID.fullmatch(invocation_id) is None
        or control_path.name != scope_unit
        or control_path.parent != attempt_path
    ):
        raise SandboxMonitorServiceError("runc client scope is outside the exact attempt slice")

    current_slice = _unit_properties(attempt_slice_unit, _ATTEMPT_SLICE_PROPERTIES)
    if (
        current_slice.get("Id") != attempt_slice_unit
        or current_slice.get("LoadState") != "loaded"
        or current_slice.get("ActiveState") != "active"
        or current_slice.get("InvocationID") != attempt_slice_invocation_id
        or current_slice.get("ControlGroup") != attempt_slice_control_group
        or current_slice.get("Slice") != _MONITOR_SLICE_UNIT
    ):
        raise SandboxMonitorServiceError("attempt slice identity changed during runc attachment")
    verify_linux_process_membership(
        pid,
        expected_cgroup=control_group,
        expected_identity=pid_identity,
    )
    return RuncClientScopeBinding(
        attempt_id=attempt_id,
        claim_token=claim_token,
        execution_id=execution_id,
        pid=pid,
        pid_identity=pid_identity,
        scope_unit=scope_unit,
        scope_invocation_id=invocation_id,
        scope_control_group=control_group,
        attempt_slice_unit=attempt_slice_unit,
        attempt_slice_invocation_id=attempt_slice_invocation_id,
        attempt_slice_control_group=attempt_slice_control_group,
    )


def _validate_scope_binding(
    *,
    expected_identity: tuple[str, int, str],
    scope_unit: str,
    scope_invocation_id: str,
    scope_control_group: str,
    attempt_slice_control_group: str,
) -> SandboxMonitorScopeBinding:
    return SandboxMonitorScopeBinding(
        attempt_id=expected_identity[0],
        claim_token=expected_identity[1],
        execution_id=expected_identity[2],
        scope_unit=scope_unit,
        scope_invocation_id=scope_invocation_id,
        scope_control_group=scope_control_group,
        attempt_slice_unit=sandbox_attempt_slice_unit(*expected_identity),
        attempt_slice_control_group=attempt_slice_control_group,
    )


def _read_private_json(directory: Path, name: str, *, limit: int) -> Any:
    directory_fd = _open_private_directory(directory)
    try:
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=directory_fd,
            )
        except OSError as error:
            raise SandboxMonitorServiceError(
                "monitor binding could not be opened safely"
            ) from error
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or before.st_size <= 0
                or before.st_size > limit
            ):
                raise SandboxMonitorServiceError("monitor binding metadata is unsafe")
            chunks: list[bytes] = []
            remaining = limit + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            after = os.fstat(descriptor)
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                len(data) != before.st_size
                or len(data) > limit
                or (before.st_dev, before.st_ino, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_mtime_ns)
                or (named.st_dev, named.st_ino) != (after.st_dev, after.st_ino)
            ):
                raise SandboxMonitorServiceError("monitor binding changed while being read")
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_fd)
    try:
        return json.loads(data.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, SandboxMonitorReceiptError) as error:
        raise SandboxMonitorServiceError("monitor binding is not valid ASCII JSON") from error


def _write_private_json(path: Path, value: dict[str, Any], *, limit: int) -> None:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    if not encoded or len(encoded) > limit:
        raise SandboxMonitorServiceError("monitor binding exceeds its size bound")
    directory_fd = _open_private_directory(path.parent)
    descriptor = -1
    try:
        descriptor = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise SandboxMonitorServiceError("monitor binding was created unsafely")
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short monitor binding write")
            view = view[written:]
        os.fsync(descriptor)
        os.fsync(directory_fd)
    except FileExistsError as error:
        raise SandboxMonitorServiceError("monitor binding already exists") from error
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
        try:
            os.unlink(path.name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory_fd)


def _read_scope_binding(
    control_directory: Path, expected_identity: tuple[str, int, str]
) -> SandboxMonitorScopeBinding:
    binding = SandboxMonitorScopeBinding.from_dict(
        _read_private_json(control_directory, _BINDING_NAME, limit=_BINDING_LIMIT)
    )
    if (binding.attempt_id, binding.claim_token, binding.execution_id) != expected_identity:
        raise SandboxMonitorServiceError("monitor binding belongs to another fenced execution")
    return binding


def _unit_properties(unit: str, properties: tuple[str, ...]) -> dict[str, str]:
    return _read_unit_properties(
        _trusted_systemctl_executable(),
        _trusted_systemd_command_environment(),
        unit,
        properties,
    )


def _scope_activation_matches(
    binding: SandboxMonitorScopeBinding, properties: dict[str, str]
) -> bool:
    return (
        properties.get("Id") == binding.scope_unit
        and properties.get("LoadState") == "loaded"
        and properties.get("InvocationID") == binding.scope_invocation_id
        and properties.get("ControlGroup") == binding.scope_control_group
        and properties.get("Slice") == binding.attempt_slice_unit
    )


def _scope_population(control_group: str) -> int | None:
    """Read cgroup-v2 population only beneath the trusted mount root."""

    cgroup = PurePosixPath(control_group)
    if (
        not cgroup.is_absolute()
        or cgroup.as_posix() != control_group
        or any(part in {".", ".."} for part in cgroup.parts)
    ):
        return None
    root = Path("/sys/fs/cgroup")
    try:
        root_real = root.resolve(strict=True)
        path = root.joinpath(*cgroup.parts[1:])
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root_real):
            return None
        fields = (resolved / "cgroup.events").read_text(encoding="ascii").splitlines()
    except FileNotFoundError:
        return 0
    except (OSError, UnicodeDecodeError):
        return None
    values: dict[str, str] = {}
    for field in fields:
        key, separator, value = field.partition(" ")
        if not separator or key in values:
            return None
        values[key] = value
    if values.get("populated") not in {"0", "1"}:
        return None
    return int(values["populated"])


def _scope_status(binding: SandboxMonitorScopeBinding) -> dict[str, Any]:
    identity_payload = {
        "scope_unit": binding.scope_unit,
        "scope_invocation_id": binding.scope_invocation_id,
        "scope_control_group": binding.scope_control_group,
    }
    try:
        properties = _unit_properties(binding.scope_unit, _PROPERTY_SET)
    except (
        SandboxMonitorReceiptError,
        SandboxMonitorServiceError,
        OSError,
        TimeoutError,
        subprocess.TimeoutExpired,
    ):
        return {"phase": "unknown", **identity_payload}
    if properties.get("LoadState") == "not-found":
        absent_unit = (
            properties.get("Id") in {"", binding.scope_unit}
            and properties.get("ActiveState") in {"", "inactive"}
            and not properties.get("InvocationID")
            and not properties.get("ControlGroup")
            and not properties.get("Slice")
        )
        if absent_unit and _scope_population(binding.scope_control_group) == 0:
            return {"phase": "exited", **identity_payload}
        return {"phase": "unknown", **identity_payload}
    if not _scope_activation_matches(binding, properties):
        return {"phase": "unknown", **identity_payload}
    populated = _scope_population(binding.scope_control_group)
    if properties["ActiveState"] == "active" and populated == 1:
        return {"phase": "running", **identity_payload}
    if properties["ActiveState"] == "inactive" and populated == 0:
        return {"phase": "exited", **identity_payload}
    if properties["ActiveState"] == "deactivating" and populated in {0, 1}:
        return {"phase": "stopping", **identity_payload}
    return {"phase": "unknown", **identity_payload}


def _cancel_scope(binding: SandboxMonitorScopeBinding) -> dict[str, Any]:
    initial = _scope_status(binding)
    if initial["phase"] == "exited":
        return initial
    if initial["phase"] not in {"running", "stopping"}:
        raise SandboxMonitorServiceError("monitor refuses to cancel an unverified scope")
    if initial["phase"] == "running":
        _run_trusted_runtime_command(
            [
                str(_trusted_systemctl_executable()),
                "--user",
                "--no-block",
                "stop",
                "--",
                binding.scope_unit,
            ],
            environment=_trusted_systemd_command_environment(),
        )

    def wait_for_exit(timeout_seconds: float) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        while True:
            current = _scope_status(binding)
            if current["phase"] in {"exited", "unknown"}:
                return current
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return current
            time.sleep(min(_SCOPE_CANCEL_POLL_SECONDS, remaining))

    current = wait_for_exit(_SCOPE_CANCEL_GRACE_SECONDS)
    if current["phase"] == "exited":
        return current
    if current["phase"] == "unknown":
        raise SandboxMonitorServiceError("scope identity changed during cancellation")
    if current["phase"] not in {"running", "stopping"}:
        raise SandboxMonitorServiceError("scope cancellation reached an invalid state")

    # systemd's inherited TimeoutStopSec may be 90 seconds, longer than the
    # supervisor's bounded cancellation window. Escalate only after the exact
    # bound scope remains verifiably live/stopping, and never target its parent
    # attempt slice or a PID supplied by the controller.
    _run_trusted_runtime_command(
        [
            str(_trusted_systemctl_executable()),
            "--user",
            "kill",
            "--signal=SIGKILL",
            "--kill-whom=all",
            "--",
            binding.scope_unit,
        ],
        environment=_trusted_systemd_command_environment(),
    )
    current = wait_for_exit(_SCOPE_CANCEL_FORCE_WAIT_SECONDS)
    if current["phase"] not in {"stopping", "exited"}:
        raise SandboxMonitorServiceError("scope did not stop after exact-scope force kill")
    return current


def _write_service_receipt(
    *,
    control_directory: Path,
    binding: SandboxMonitorScopeBinding,
    controller_pid: int,
) -> SandboxMonitorReceipt:
    if type(controller_pid) is not int or controller_pid <= 0 or controller_pid == os.getpid():
        raise SandboxMonitorServiceError("monitor controller PID is invalid")
    unit = sandbox_monitor_service_unit(
        binding.attempt_id, binding.claim_token, binding.execution_id
    )
    service = _unit_properties(unit, _MONITOR_PROPERTIES)
    monitor_slice = _unit_properties(
        _MONITOR_SLICE_UNIT, ("Id", "LoadState", "ActiveState", "ControlGroup")
    )
    attempt_slice = _unit_properties(
        binding.attempt_slice_unit,
        ("Id", "LoadState", "ActiveState", "Slice", "ControlGroup"),
    )
    main_pid = int(service.get("MainPID", "0"))
    main_identity = _linux_process_identity(main_pid) if main_pid > 0 else None
    if (
        service.get("Slice") != _MONITOR_SLICE_UNIT
        or not service.get("InvocationID")
        or main_pid != os.getpid()
        or main_identity is None
        or not _scope_activation_matches(
            binding, _unit_properties(binding.scope_unit, _PROPERTY_SET)
        )
    ):
        raise SandboxMonitorServiceError("monitor service or scope identity is incomplete")
    receipt = SandboxMonitorReceipt(
        version=1,
        controller_pid=controller_pid,
        attempt_id=binding.attempt_id,
        claim_token=binding.claim_token,
        execution_id=binding.execution_id,
        unit=unit,
        invocation_id=service["InvocationID"],
        control_group=service["ControlGroup"],
        main_pid=main_pid,
        main_identity=main_identity,
        monitor_slice_unit=_MONITOR_SLICE_UNIT,
        monitor_slice_control_group=monitor_slice["ControlGroup"],
        attempt_slice_unit=binding.attempt_slice_unit,
        attempt_slice_control_group=attempt_slice["ControlGroup"],
    )
    validate_monitor_service_reconciliation(
        receipt,
        service,
        monitor_slice,
        attempt_slice,
        observed_main_identity=main_identity,
        reconciler_pid=os.getpid(),
    )
    if _scope_status(binding)["phase"] not in {"running", "exited"}:
        raise SandboxMonitorServiceError("monitor scope identity is not reconcilable")
    write_sandbox_monitor_receipt(control_directory / "monitor-receipt.json", receipt)
    return receipt


def _service_main(
    *,
    control_directory: Path,
    expected_identity: tuple[str, int, str],
    controller_pid: int,
) -> None:
    binding = _read_scope_binding(control_directory, expected_identity)
    key = read_sandbox_monitor_control_key(
        control_directory,
        attempt_id=binding.attempt_id,
        claim_token=binding.claim_token,
        execution_id=binding.execution_id,
    )
    server = SandboxMonitorControlServer(
        socket_path=lifecycle.sandbox_monitor_control_paths(
            state_path=control_directory.parent,
            expected_identity=expected_identity,
        )[2],
        request_directory=control_directory,
        key=key,
        expected_identity=expected_identity,
        expected_uid=os.geteuid(),
        status_provider=lambda: _scope_status(binding),
        cancel_action=lambda: _cancel_scope(binding),
    )
    _write_service_receipt(
        control_directory=control_directory,
        binding=binding,
        controller_pid=controller_pid,
    )
    signal.signal(signal.SIGTERM, lambda *_args: server.close())
    try:
        server.serve_forever()
    finally:
        server.close()


def _wait_for_receipt(
    receipt_path: Path, *, expected_identity: tuple[str, int, str], timeout_seconds: float
) -> SandboxMonitorReceipt:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            receipt = read_sandbox_monitor_receipt(receipt_path)
        except (FileNotFoundError, SandboxMonitorReceiptError):
            time.sleep(0.05)
            continue
        if (receipt.attempt_id, receipt.claim_token, receipt.execution_id) != expected_identity:
            raise SandboxMonitorServiceError("monitor receipt belongs to another execution")
        return receipt
    raise SandboxMonitorServiceError("monitor service did not publish its durable receipt")


def start_sandbox_execution_monitor(
    *,
    state_path: str | Path,
    expected_identity: tuple[str, int, str],
    scope_unit: str,
    scope_invocation_id: str,
    scope_control_group: str,
    attempt_slice_control_group: str,
    timeout_seconds: float = 10.0,
) -> SandboxMonitorControlClient:
    """Start or adopt a systemd-owned monitor for one journaled scope.

    Initial creation may create the control key. Every subsequent path is an
    adoption only: it reads the prior receipt and key, never replacing either
    when state is partial, stale, or ambiguous.
    """

    if type(timeout_seconds) not in {int, float} or not 0.2 <= timeout_seconds <= 30:
        raise SandboxMonitorServiceError("monitor startup timeout is invalid")
    try:
        binding = _validate_scope_binding(
            expected_identity=expected_identity,
            scope_unit=scope_unit,
            scope_invocation_id=scope_invocation_id,
            scope_control_group=scope_control_group,
            attempt_slice_control_group=attempt_slice_control_group,
        )
        control_directory, receipt_path, socket_path = _control_directory(
            state_path, expected_identity
        )
    except (SandboxMonitorReceiptError, SandboxMonitorIPCError) as error:
        raise SandboxMonitorServiceError("monitor startup identity or path is invalid") from error

    if _scope_status(binding)["phase"] != "running":
        raise SandboxMonitorServiceError("monitor startup requires the exact live worker scope")
    if os.path.lexists(receipt_path):
        client = lifecycle.reconnect_sandbox_monitor(
            receipt_path=receipt_path,
            control_directory=control_directory,
            socket_path=socket_path,
            expected_identity=expected_identity,
        )
        response = client.status()
        if response.outcome != "ok" or any(
            response.payload.get(key) != value
            for key, value in {
                "scope_unit": binding.scope_unit,
                "scope_invocation_id": binding.scope_invocation_id,
                "scope_control_group": binding.scope_control_group,
            }.items()
        ):
            raise SandboxMonitorServiceError("existing monitor does not attest the exact scope")
        return client

    monitor_unit = sandbox_monitor_service_unit(*expected_identity)
    attempt_slice_unit = binding.attempt_slice_unit
    binding_path = control_directory / _BINDING_NAME
    key_name = f"{sandbox_container_id(*expected_identity)}.control-key"
    key_path = control_directory / key_name
    if (
        os.listdir(control_directory)
        or os.path.lexists(binding_path)
        or os.path.lexists(key_path)
        or os.path.lexists(socket_path)
    ):
        raise SandboxMonitorServiceError(
            "partial monitor state exists; refusing replacement key or unit recovery"
        )

    systemctl = _trusted_systemctl_executable()
    environment = _trusted_systemd_command_environment()
    preexisting = _read_unit_properties(
        systemctl,
        environment,
        monitor_unit,
        ("Id", "LoadState", "ActiveState", "InvocationID", "ControlGroup", "MainPID"),
    )
    if preexisting.get("LoadState") != "not-found":
        raise SandboxMonitorServiceError("monitor systemd unit already exists; refusing takeover")
    _write_private_json(binding_path, binding.as_dict(), limit=_BINDING_LIMIT)
    key = load_or_create_sandbox_monitor_control_key(
        control_directory,
        attempt_id=binding.attempt_id,
        claim_token=binding.claim_token,
        execution_id=binding.execution_id,
    )
    # The key remains only in this caller's memory for the initial authenticated
    # connection. It never enters argv, environment, logs, or the receipt.

    python_executable = Path(sys.executable).resolve(strict=True)
    if not python_executable.is_absolute() or not os.access(python_executable, os.X_OK):
        raise SandboxMonitorServiceError("current Python interpreter is not executable")
    command = [
        str(_trusted_systemd_run_executable()),
        "--user",
        f"--unit={monitor_unit}",
        f"--slice={_MONITOR_SLICE_UNIT}",
        "--property=Type=exec",
        "--property=KillMode=control-group",
        "--property=Restart=no",
    ]
    allowed_environment = _trusted_systemd_command_environment()
    allowed_environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[2])
    for name in (
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "HOME",
        "USER",
        "LOGNAME",
        "PATH",
        "PYTHONPATH",
    ):
        value = allowed_environment.get(name)
        if value and not any(character in value for character in "\x00\r\n"):
            command.append(f"--setenv={name}={value}")
    command.extend(
        [
            str(python_executable),
            "-m",
            "agent_control_plane.supervisor.sandbox_monitor_service",
            "serve",
            "--control-directory",
            str(control_directory),
            "--attempt-id",
            binding.attempt_id,
            "--claim-token",
            str(binding.claim_token),
            "--execution-id",
            binding.execution_id,
            "--controller-pid",
            str(os.getpid()),
        ]
    )
    _run_trusted_runtime_command(command, environment=environment)
    receipt = _wait_for_receipt(
        receipt_path,
        expected_identity=expected_identity,
        timeout_seconds=float(timeout_seconds),
    )
    if receipt.unit != monitor_unit or receipt.attempt_slice_unit != attempt_slice_unit:
        raise SandboxMonitorServiceError("monitor receipt unit identity is inconsistent")
    client = SandboxMonitorControlClient(
        receipt=receipt,
        socket_path=socket_path,
        key=key,
        expected_uid=os.geteuid(),
        timeout_seconds=min(
            30.0,
            max(SANDBOX_MONITOR_OPERATION_TIMEOUT_SECONDS, float(timeout_seconds)),
        ),
    )
    response = client.status()
    if response.outcome != "ok" or response.payload.get("phase") != "running":
        raise SandboxMonitorServiceError("new monitor did not authenticate the running scope")
    return client


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="sandbox-monitor-service")
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve")
    serve.add_argument("--control-directory", required=True, type=Path)
    serve.add_argument("--attempt-id", required=True)
    serve.add_argument("--claim-token", required=True, type=int)
    serve.add_argument("--execution-id", required=True)
    serve.add_argument("--controller-pid", required=True, type=int)
    arguments = parser.parse_args(argv)
    if arguments.command == "serve":
        _service_main(
            control_directory=arguments.control_directory,
            expected_identity=(arguments.attempt_id, arguments.claim_token, arguments.execution_id),
            controller_pid=arguments.controller_pid,
        )
        return 0
    parser.error("unsupported monitor command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
