"""Exact-slice systemd producer and process-local OCI launch driver.

The systemd service owns the pinned-runc handle, init gate, runtime attestation,
wait receipt, and journal transitions. The authenticated recovery monitor is
started by the journal outside the attempt slice. This module is deliberately
not wired into ``WorkersMixin.run_worker``; callers must still meet the
workspace, provider, and result-transfer acceptance gates before enabling OCI.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from ..credential_providers import _anonymous_fd
from ..git_supervisor import GitSupervisor
from . import oci_worker
from .common import SupervisorError, canonical_json
from .sandbox_attestation import (
    _run_trusted_runtime_command,
    _trusted_systemctl_executable,
    _trusted_systemd_command_environment,
    collect_launch_driver_start_redemption,
    collect_running_runtime_attestation,
)
from .sandbox_execution_journal import (
    _sandbox_execution_launch_stop_reason,
    _sandbox_launch_driver_service_unit,
    _sandbox_launch_driver_start_digest,
)
from .sandbox_monitor_receipt import sandbox_attempt_slice_unit, sandbox_monitor_service_unit
from .sandbox_workspace import _restore_snapshot_from_record

_REQUEST_NAME = "launch-driver-request.json"
_REQUEST_LIMIT = 16 * 1024
_REQUEST_SCHEMA = 1
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_MAX_TIMEOUT_SECONDS = 3540
_RUNNER_CREDENTIAL_NAME = "acp-runner"
_RUNNER_CREDENTIAL_LIMIT = 4096


class SandboxLaunchDriverServiceError(RuntimeError):
    """The exact systemd-owned launch-driver could not be safely started."""


@dataclass(frozen=True)
class SandboxLaunchDriverReceipt:
    """The launch-driver activation redeemed by its own service MainPID."""

    attempt_id: str
    claim_token: int
    execution_id: str
    service_unit: str
    invocation_id: str
    driver_pid: int
    driver_identity: str
    control_group: str


def _execution_identity(value: Any) -> tuple[str, int, str]:
    if (
        not isinstance(value, tuple)
        or len(value) != 3
        or not isinstance(value[0], str)
        or _IDENTIFIER.fullmatch(value[0]) is None
        or type(value[1]) is not int
        or value[1] <= 0
        or not isinstance(value[2], str)
        or _IDENTIFIER.fullmatch(value[2]) is None
    ):
        raise SandboxLaunchDriverServiceError("launch-driver execution identity is invalid")
    return value


def _validate_request(
    *,
    expected_identity: tuple[str, int, str],
    command: Any,
    memory_max_bytes: Any,
    cpu_quota: Any,
    cpu_period: Any,
    pids_max: Any,
    timeout_seconds: Any,
) -> dict[str, Any]:
    if (
        not isinstance(command, (list, tuple))
        or not command
        or len(command) > 128
        or any(
            not isinstance(part, str)
            or not part
            or "\x00" in part
            or "\n" in part
            or "\r" in part
            or len(part.encode("utf-8")) > 4096
            for part in command
        )
        or any(
            type(value) is not int or value <= 0
            for value in (memory_max_bytes, cpu_quota, cpu_period, pids_max)
        )
        or type(timeout_seconds) not in {int, float}
        or not 0.2 <= timeout_seconds <= _MAX_TIMEOUT_SECONDS
    ):
        raise SandboxLaunchDriverServiceError("launch-driver request is invalid")
    return {
        "schema": _REQUEST_SCHEMA,
        "attempt_id": expected_identity[0],
        "claim_token": expected_identity[1],
        "execution_id": expected_identity[2],
        "command": list(command),
        "resource_limits": {
            "memory_max_bytes": memory_max_bytes,
            "cpu_quota": cpu_quota,
            "cpu_period": cpu_period,
            "pids_max": pids_max,
        },
        "timeout_seconds": float(timeout_seconds),
    }


def _reject_runner_credential_in_command(request: dict[str, Any], credential: str | None) -> None:
    if (
        isinstance(credential, str)
        and credential
        and any(credential in part for part in request["command"])
    ):
        raise SandboxLaunchDriverServiceError(
            "runner credential must not be included in the worker command"
        )


def _state_request_path(supervisor: GitSupervisor, execution: dict[str, Any]) -> Path:
    state_path = Path(execution["state_path"])
    if not state_path.is_absolute() or state_path.as_posix() != str(state_path):
        raise SandboxLaunchDriverServiceError("launch-driver state path is not canonical")
    try:
        state = state_path.lstat()
    except OSError as error:
        raise SandboxLaunchDriverServiceError("launch-driver state root is unavailable") from error
    if (
        not state_path.is_dir()
        or state_path.is_symlink()
        or state.st_uid != os.geteuid()
        or state.st_mode & 0o077
        or (state.st_dev, state.st_ino)
        != (execution["state_root_dev"], execution["state_root_ino"])
    ):
        raise SandboxLaunchDriverServiceError("launch-driver state root identity is unsafe")
    return state_path / _REQUEST_NAME


def _write_request(path: Path, request: dict[str, Any]) -> str:
    encoded = canonical_json(request).encode("utf-8")
    if len(encoded) > _REQUEST_LIMIT:
        raise SandboxLaunchDriverServiceError("launch-driver request exceeds its size limit")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short launch-driver request write")
            view = view[written:]
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size != len(encoded)
        ):
            raise SandboxLaunchDriverServiceError("launch-driver request file is not private")
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except FileExistsError as error:
        raise SandboxLaunchDriverServiceError(
            "launch-driver request already exists; refusing replacement"
        ) from error
    except OSError as error:
        raise SandboxLaunchDriverServiceError(
            "launch-driver request could not be persisted"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return hashlib.sha256(encoded).hexdigest()


def _read_request(
    path: Path, expected_identity: tuple[str, int, str]
) -> tuple[dict[str, Any], str]:
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size < 2
            or info.st_size > _REQUEST_LIMIT
        ):
            raise SandboxLaunchDriverServiceError("launch-driver request file is unsafe")
        chunks: list[bytes] = []
        remaining = _REQUEST_LIMIT + 1
        while remaining:
            chunk = os.read(descriptor, min(4096, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        encoded = b"".join(chunks)
        request = json.loads(encoded.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise SandboxLaunchDriverServiceError(
            "launch-driver request cannot be read safely"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if not isinstance(request, dict) or canonical_json(request).encode("utf-8") != encoded:
        raise SandboxLaunchDriverServiceError("launch-driver request is not canonical")
    expected_keys = {
        "schema",
        "attempt_id",
        "claim_token",
        "execution_id",
        "command",
        "resource_limits",
        "timeout_seconds",
    }
    if (
        set(request) != expected_keys
        or type(request.get("schema")) is not int
        or request.get("schema") != _REQUEST_SCHEMA
        or type(request.get("claim_token")) is not int
        or (request.get("attempt_id"), request.get("claim_token"), request.get("execution_id"))
        != expected_identity
    ):
        raise SandboxLaunchDriverServiceError("launch-driver request identity is mismatched")
    resources = request.get("resource_limits")
    if not isinstance(resources, dict) or set(resources) != {
        "memory_max_bytes",
        "cpu_quota",
        "cpu_period",
        "pids_max",
    }:
        raise SandboxLaunchDriverServiceError("launch-driver resource policy is malformed")
    validated = _validate_request(
        expected_identity=expected_identity,
        command=request.get("command"),
        memory_max_bytes=resources["memory_max_bytes"],
        cpu_quota=resources["cpu_quota"],
        cpu_period=resources["cpu_period"],
        pids_max=resources["pids_max"],
        timeout_seconds=request.get("timeout_seconds"),
    )
    if validated != request:
        raise SandboxLaunchDriverServiceError("launch-driver request changed during validation")
    return request, hashlib.sha256(encoded).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read_service_runner_credential() -> str | None:
    """Read the optional runner credential only from systemd's private credential dir."""

    directory_value = os.environ.get("CREDENTIALS_DIRECTORY")
    if not directory_value:
        return None
    directory = Path(directory_value)
    if not directory.is_absolute() or directory.as_posix() != directory_value:
        raise SandboxLaunchDriverServiceError("launch-driver credential directory is invalid")
    try:
        directory_info = directory.lstat()
        if (
            not stat.S_ISDIR(directory_info.st_mode)
            or stat.S_ISLNK(directory_info.st_mode)
            or directory_info.st_uid != os.geteuid()
            or directory_info.st_mode & 0o077
        ):
            raise SandboxLaunchDriverServiceError(
                "launch-driver credential directory is not private"
            )
        descriptor = os.open(
            directory / _RUNNER_CREDENTIAL_NAME,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as error:
        raise SandboxLaunchDriverServiceError(
            "launch-driver credential cannot be opened safely"
        ) from error
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o222
            or info.st_size < 1
            or info.st_size > _RUNNER_CREDENTIAL_LIMIT
        ):
            raise SandboxLaunchDriverServiceError("launch-driver credential file is unsafe")
        chunks: list[bytes] = []
        remaining = _RUNNER_CREDENTIAL_LIMIT + 1
        while remaining:
            chunk = os.read(descriptor, min(1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) != info.st_size or len(payload) > _RUNNER_CREDENTIAL_LIMIT:
            raise SandboxLaunchDriverServiceError(
                "launch-driver credential file changed while reading"
            )
        try:
            credential = payload.decode("utf-8")
        except UnicodeError as error:
            raise SandboxLaunchDriverServiceError(
                "launch-driver credential encoding is invalid"
            ) from error
        if not credential or any(character in credential for character in "\x00\r\n"):
            raise SandboxLaunchDriverServiceError("launch-driver credential is malformed")
        return credential
    finally:
        os.close(descriptor)


def _unit_properties(unit: str, properties: tuple[str, ...]) -> dict[str, str]:
    raw = _run_trusted_runtime_command(
        [
            str(_trusted_systemctl_executable()),
            "--user",
            "show",
            "--no-pager",
            f"--property={','.join(properties)}",
            "--",
            unit,
        ],
        environment=_trusted_systemd_command_environment(),
    )
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise SandboxLaunchDriverServiceError("systemd unit properties are not ASCII") from error
    values: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise SandboxLaunchDriverServiceError("systemd unit properties are malformed")
        values[key] = value
    if set(values) != set(properties):
        raise SandboxLaunchDriverServiceError("systemd unit properties are incomplete")
    return values


def _redeemed_start_receipt(execution: dict[str, Any], intent: Any) -> SandboxLaunchDriverReceipt:
    receipt = SandboxLaunchDriverReceipt(
        attempt_id=execution["attempt_id"],
        claim_token=execution["claim_token"],
        execution_id=execution["execution_id"],
        service_unit=execution.get("launch_driver_start_unit", ""),
        invocation_id=execution.get("launch_driver_start_redeemed_invocation_id", ""),
        driver_pid=execution.get("launch_driver_start_redeemed_pid"),
        driver_identity=execution.get("launch_driver_start_redeemed_identity", ""),
        control_group=execution.get("launch_driver_start_redeemed_cgroup_path", ""),
    )
    if (
        (receipt.attempt_id, receipt.claim_token, receipt.execution_id)
        != (intent.attempt_id, intent.claim_token, intent.execution_id)
        or receipt.service_unit != intent.service_unit
        or re.fullmatch(r"[0-9a-f]{32}", receipt.invocation_id) is None
        or type(receipt.driver_pid) is not int
        or receipt.driver_pid <= 0
        or not receipt.driver_identity
        or not receipt.control_group
    ):
        raise SandboxLaunchDriverServiceError(
            "launch-driver redemption is incomplete; execution fence retained"
        )
    return receipt


def _committed_handoff_receipt(
    execution: dict[str, Any] | None, intent: Any
) -> SandboxLaunchDriverReceipt | None:
    """Return a receipt only for the complete durable scope/monitor handoff."""

    if (
        execution is None
        or (
            execution.get("attempt_id"),
            execution.get("claim_token"),
            execution.get("execution_id"),
        )
        != (intent.attempt_id, intent.claim_token, intent.execution_id)
        or execution.get("launch_driver_start_id") != intent.start_id
        or execution.get("launch_driver_start_digest") != intent.start_digest
        or execution.get("launch_driver_start_unit") != intent.service_unit
        or execution.get("phase")
        not in {"launched", "running", "stopping", "exited", "cleanup_reported", "cleanup_verified"}
        or execution.get("launch_plan_binding_version") != 1
    ):
        return None
    identity = (intent.attempt_id, intent.claim_token, intent.execution_id)
    attempt_slice = sandbox_attempt_slice_unit(*identity)
    monitor_unit = sandbox_monitor_service_unit(*identity)
    required = (
        execution.get("launch_submission_id"),
        execution.get("monitor_pid"),
        execution.get("monitor_identity"),
        execution.get("runc_client_pid"),
        execution.get("runc_client_identity"),
        execution.get("wrapper_invocation_id"),
        execution.get("wrapper_cgroup_path"),
        execution.get("scope_unit"),
        execution.get("scope_invocation_id"),
        execution.get("cgroup_path"),
        execution.get("launch_plan_digest"),
    )
    if (
        any(value in (None, "") for value in required)
        or type(execution.get("monitor_pid")) is not int
        or execution["monitor_pid"] <= 0
        or type(execution.get("runc_client_pid")) is not int
        or execution["runc_client_pid"] <= 0
        or execution.get("wrapper_unit") != monitor_unit
        or execution.get("attempt_slice_unit") != attempt_slice
        or not re.fullmatch(r"[0-9a-f]{32}", execution["wrapper_invocation_id"])
        or not _DIGEST.fullmatch(execution["launch_plan_digest"])
    ):
        raise SandboxLaunchDriverServiceError(
            "durable launch-driver handoff is incomplete; execution fence retained"
        )
    return _redeemed_start_receipt(execution, intent)


def _systemd_run_path() -> Path:
    from .sandbox_monitor_service import _trusted_systemd_run_executable

    return _trusted_systemd_run_executable()


def _stop_and_reconcile_exact_start(
    supervisor: GitSupervisor,
    *,
    execution: dict[str, Any],
    intent: Any,
    attempt_slice: str,
    reason: str,
    credential: str | None,
) -> bool:
    """Revoke or adopt the exact handoff, then reconcile only its systemd units.

    A confirmed stop is not a cleanup receipt: the journal remains ambiguous
    and its fences remain held until the independent cleanup verifier exists.
    ``True`` means the durable handoff won the journal gate and the caller must
    not stop the services; ``False`` means revocation won and containment
    completed.
    """

    properties = (
        "ActiveState",
        "ControlGroup",
        "Id",
        "InvocationID",
        "Job",
        "LoadState",
        "MainPID",
        "Slice",
        "SubState",
    )
    systemctl = str(_trusted_systemctl_executable())
    environment = _trusted_systemd_command_environment()
    monitor_unit = sandbox_monitor_service_unit(
        intent.attempt_id, intent.claim_token, intent.execution_id
    )

    def current_execution() -> dict[str, Any]:
        current = supervisor._sandbox_execution_get(intent.attempt_id)
        if (
            current is None
            or (current.get("attempt_id"), current.get("claim_token"), current.get("execution_id"))
            != (intent.attempt_id, intent.claim_token, intent.execution_id)
            or current.get("launch_driver_start_id") != intent.start_id
            or current.get("launch_driver_start_digest") != intent.start_digest
            or current.get("launch_driver_start_unit") != intent.service_unit
        ):
            raise SandboxLaunchDriverServiceError(
                "durable execution changed during exact launch reconciliation; fence retained"
            )
        return current

    def revoke_exact_start() -> None:
        supervisor._sandbox_execution_revoke_launch_driver_start(
            intent.attempt_id,
            intent.claim_token,
            execution_id=intent.execution_id,
            start_id=intent.start_id,
            start_digest=intent.start_digest,
            service_unit=intent.service_unit,
            reason=reason,
            credential=credential,
        )

    def read_unit(unit: str) -> dict[str, str]:
        try:
            unit_properties = properties
            if unit.endswith(".slice"):
                # systemd does not expose MainPID for slice units on supported
                # versions; every other observed property remains mandatory.
                unit_properties = tuple(name for name in properties if name != "MainPID")
            return _unit_properties(unit, unit_properties)
        except (SupervisorError, SandboxLaunchDriverServiceError) as error:
            raise SandboxLaunchDriverServiceError(
                "systemd unit state could not be reconciled; execution fence retained"
            ) from error

    def stop_and_reconcile_unit(unit: str, expected_parent: str) -> None:
        before = read_unit(unit)
        if before["Id"] != unit:
            raise SandboxLaunchDriverServiceError(
                "launch-driver cancellation unit identity is mismatched; execution fence retained"
            )
        if before["LoadState"] == "not-found":
            if (
                before["ActiveState"] != "inactive"
                or before.get("MainPID", "0") != "0"
                or before["ControlGroup"]
                or before["Job"]
                or before["InvocationID"]
            ):
                raise SandboxLaunchDriverServiceError(
                    "unloaded launch-driver unit has live properties; execution fence retained"
                )
            return
        if before["LoadState"] != "loaded" or before["Slice"] != expected_parent:
            raise SandboxLaunchDriverServiceError(
                "launch-driver cancellation unit hierarchy is unknown; execution fence retained"
            )

        invocation_id = before["InvocationID"]
        expected_invocation = (
            execution.get("launch_driver_start_redeemed_invocation_id") or ""
            if unit == intent.service_unit
            else ""
        )
        if expected_invocation and invocation_id != expected_invocation:
            raise SandboxLaunchDriverServiceError(
                "launch-driver invocation changed during cancellation; execution fence retained"
            )
        if invocation_id and re.fullmatch(r"[0-9a-f]{32}", invocation_id) is None:
            raise SandboxLaunchDriverServiceError(
                "launch-driver invocation identity is malformed; execution fence retained"
            )

        control_group = before["ControlGroup"]
        path = PurePosixPath(control_group) if control_group else PurePosixPath(".")
        quiescent = (
            before.get("MainPID", "0") == "0"
            and not control_group
            and not before["Job"]
            and (
                (before["ActiveState"] == "inactive" and before["SubState"] == "dead")
                or (
                    before["ActiveState"] == "failed"
                    and before["SubState"] == "failed"
                    and bool(invocation_id)
                )
            )
        )
        if not quiescent and (
            re.fullmatch(r"[0-9a-f]{32}", invocation_id) is None
            or not path.is_absolute()
            or path.as_posix() != control_group
            or path.name != unit
            or path.parent.name != expected_parent
        ):
            raise SandboxLaunchDriverServiceError(
                "active launch-driver unit identity is incomplete; execution fence retained"
            )

        if not quiescent:
            try:
                _run_trusted_runtime_command(
                    [systemctl, "--user", "stop", "--", unit], environment=environment
                )
            except SupervisorError as error:
                raise SandboxLaunchDriverServiceError(
                    "exact systemd stop failed; execution fence retained"
                ) from error

        after = read_unit(unit)
        if after["Id"] != unit or after["LoadState"] not in {"loaded", "not-found"}:
            raise SandboxLaunchDriverServiceError(
                "exact launch-driver unit state is unknown after stop; execution fence retained"
            )
        if after["LoadState"] == "not-found":
            after_quiescent = (
                after["ActiveState"] == "inactive"
                and after.get("MainPID", "0") == "0"
                and not after["ControlGroup"]
                and not after["Job"]
                and not after["InvocationID"]
            )
        else:
            after_quiescent = (
                after["Slice"] == expected_parent
                and after.get("MainPID", "0") == "0"
                and not after["ControlGroup"]
                and not after["Job"]
                and (
                    (after["ActiveState"] == "inactive" and after["SubState"] == "dead")
                    or (
                        after["ActiveState"] == "failed"
                        and after["SubState"] == "failed"
                        and bool(after["InvocationID"])
                    )
                )
            )
        if not after_quiescent:
            raise SandboxLaunchDriverServiceError(
                "exact launch-driver unit or attempt slice remains active; execution fence retained"
            )
        if (
            invocation_id
            and after["LoadState"] == "loaded"
            and after["InvocationID"] != invocation_id
        ):
            raise SandboxLaunchDriverServiceError(
                "systemd invocation changed during cancellation; execution fence retained"
            )
        if (
            expected_invocation
            and after["LoadState"] == "loaded"
            and after["InvocationID"] != expected_invocation
        ):
            raise SandboxLaunchDriverServiceError(
                "launch-driver invocation changed during cancellation; execution fence retained"
            )

    def stop_and_reconcile_units() -> None:
        # record_launch starts the monitor just before committing its receipt.
        # This deterministic unit is absent before this one-shot producer call,
        # so it can be safely contained even when that receipt did not commit.
        stop_and_reconcile_unit(intent.service_unit, attempt_slice)
        stop_and_reconcile_unit(monitor_unit, "user-acp.slice")
        stop_and_reconcile_unit(attempt_slice, "user-acp.slice")

    before = current_execution()
    if _committed_handoff_receipt(before, intent) is not None:
        return True
    if before["phase"] not in {"reserved", "ambiguous"}:
        raise SandboxLaunchDriverServiceError(
            "launch-driver journal phase cannot be reconciled safely; execution fence retained"
        )

    if before["phase"] == "reserved":
        try:
            revoke_exact_start()
        except BaseException as error:
            current = current_execution()
            if _committed_handoff_receipt(current, intent) is not None:
                return True
            if current["phase"] == "ambiguous":
                pass
            elif current["phase"] != "reserved":
                raise SandboxLaunchDriverServiceError(
                    "launch-driver journal changed to an unsupported phase; execution fence retained"
                ) from error
            elif getattr(error, "code", None) == "sandbox_execution_gate_busy":
                # record_launch holds this same cross-process fence across the
                # monitor's systemd activation and the durable launched commit.
                # Never treat a momentary not-found read as quiescence while
                # that handoff is in flight: wait for the journal gate first.
                # Returning while the row is still reserved would let the
                # fenced driver later commit and release the OCI gate after
                # this producer had reported cancellation, so this loop has no
                # timeout. An operator interruption remains fail-closed: no
                # service stop is issued while ownership is unresolved.
                retry_delay = 0.05
                while True:
                    time.sleep(retry_delay)
                    try:
                        revoke_exact_start()
                        break
                    except BaseException as retry_error:
                        current = current_execution()
                        if _committed_handoff_receipt(current, intent) is not None:
                            return True
                        if current["phase"] == "ambiguous":
                            break
                        if current["phase"] != "reserved":
                            raise SandboxLaunchDriverServiceError(
                                "launch-driver journal changed to an unsupported phase; execution fence retained"
                            ) from retry_error
                        if getattr(retry_error, "code", None) != "sandbox_execution_gate_busy":
                            raise SandboxLaunchDriverServiceError(
                                "launch-driver revocation failed while the handoff remained reserved; services were not stopped and execution fences were retained"
                            ) from retry_error
                        retry_delay = min(retry_delay * 2, 0.5)
            else:
                # A non-busy journal failure is not proof that startup is
                # quiescent. Without a durable revoke, do not race a late
                # monitor activation with unit-name stops.
                raise SandboxLaunchDriverServiceError(
                    "launch-driver revocation failed before handoff; services were not stopped and execution fences were retained"
                ) from error

    current = current_execution()
    if _committed_handoff_receipt(current, intent) is not None:
        return True
    if current["phase"] == "reserved":
        raise SandboxLaunchDriverServiceError(
            "launch-driver handoff remains reserved without a durable revoke; services were not stopped and execution fences were retained"
        )
    if current["phase"] != "ambiguous":
        raise SandboxLaunchDriverServiceError(
            "launch-driver journal phase cannot be reconciled safely; execution fence retained"
        )

    # The journal gate has now serialized ownership: either launched was
    # committed and adopted above, or ambiguous revocation won before any
    # monitor activation. It is safe to reconcile only the tuple-derived units.
    stop_and_reconcile_units()
    return False


def start_sandbox_launch_driver(
    supervisor: GitSupervisor,
    *,
    expected_identity: tuple[str, int, str],
    command: list[str] | tuple[str, ...],
    memory_max_bytes: int,
    cpu_quota: int,
    cpu_period: int,
    pids_max: int,
    timeout_seconds: float = 600.0,
    startup_timeout_seconds: float = 15.0,
    credential: str | None = None,
) -> SandboxLaunchDriverReceipt:
    """Start one exact driver service and wait for durable launch handoff.

    The authenticated request is persisted before the durable one-shot start
    intent. Redemption alone is not a handoff: the in-slice driver can still
    fail before its scope and recovery monitor are durably registered. The
    caller therefore waits until the journal leaves ``reserved``. If the
    redeemed service exits first, this out-of-slice producer stops and
    reconciles the exact service and attempt slice; the execution remains
    fenced because the local launch handle and wait receipt are unavailable.
    An uncertain systemd result is never retried.
    """

    identity = _execution_identity(expected_identity)
    if (
        type(startup_timeout_seconds) not in {int, float}
        or not 0.2 <= startup_timeout_seconds <= 30
    ):
        raise SandboxLaunchDriverServiceError("launch-driver startup timeout is invalid")
    request = _validate_request(
        expected_identity=identity,
        command=command,
        memory_max_bytes=memory_max_bytes,
        cpu_quota=cpu_quota,
        cpu_period=cpu_period,
        pids_max=pids_max,
        timeout_seconds=timeout_seconds,
    )
    _reject_runner_credential_in_command(request, credential)
    execution = supervisor._sandbox_execution_get(identity[0])
    if (
        execution is None
        or (execution["attempt_id"], execution["claim_token"], execution["execution_id"])
        != identity
        or execution["phase"] != "reserved"
        or execution["workspace_binding_version"] != 1
        or execution["private_path_binding_version"] != 1
        or execution["launch_plan_required"] != 1
    ):
        raise SandboxLaunchDriverServiceError(
            "launch-driver requires the exact prepared durable execution"
        )
    unit = _sandbox_launch_driver_service_unit(identity[2])
    attempt_slice = sandbox_attempt_slice_unit(*identity)
    monitor_unit = sandbox_monitor_service_unit(*identity)
    existing = _unit_properties(
        unit,
        ("ActiveState", "ControlGroup", "Id", "InvocationID", "LoadState", "MainPID", "Slice"),
    )
    if (
        existing["LoadState"] != "not-found"
        or existing["ActiveState"] != "inactive"
        or existing["MainPID"] != "0"
        or existing["ControlGroup"]
        or existing["InvocationID"]
    ):
        raise SandboxLaunchDriverServiceError(
            "launch-driver service already exists; refusing takeover"
        )
    monitor_existing = _unit_properties(
        monitor_unit,
        ("ActiveState", "ControlGroup", "Id", "InvocationID", "LoadState", "MainPID", "Slice"),
    )
    if (
        monitor_existing["Id"] != monitor_unit
        or monitor_existing["LoadState"] != "not-found"
        or monitor_existing["ActiveState"] != "inactive"
        or monitor_existing["MainPID"] != "0"
        or monitor_existing["ControlGroup"]
        or monitor_existing["InvocationID"]
    ):
        raise SandboxLaunchDriverServiceError(
            "tuple-derived recovery monitor service already exists; refusing takeover"
        )
    repo = Path(supervisor.root).resolve(strict=True)
    python = Path(sys.executable).resolve(strict=True)
    environment = _trusted_systemd_command_environment()
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[2])
    # Resolve anything that can fail before materializing the anonymous
    # credential FD. In particular, a replaced state root must not strand the
    # runner secret in this long-lived producer process.
    systemd_run = _systemd_run_path()
    request_path = _state_request_path(supervisor, execution)
    credential_fd: int | None = None

    def close_credential_fd() -> None:
        nonlocal credential_fd
        if credential_fd is not None:
            descriptor, credential_fd = credential_fd, None
            os.close(descriptor)

    if credential is not None:
        if (
            not isinstance(credential, str)
            or not credential
            or any(character in credential for character in "\x00\r\n")
            or len(credential.encode("utf-8")) > _RUNNER_CREDENTIAL_LIMIT
        ):
            raise SandboxLaunchDriverServiceError("launch-driver runner credential is invalid")
        runtime_dir = Path(environment["XDG_RUNTIME_DIR"])
        try:
            runtime_info = runtime_dir.lstat()
        except OSError as error:
            raise SandboxLaunchDriverServiceError(
                "launch-driver credential runtime directory is unavailable"
            ) from error
        if (
            not stat.S_ISDIR(runtime_info.st_mode)
            or stat.S_ISLNK(runtime_info.st_mode)
            or runtime_info.st_uid != os.geteuid()
            or runtime_info.st_mode & 0o077
        ):
            raise SandboxLaunchDriverServiceError(
                "launch-driver credential runtime directory is not private"
            )
        try:
            credential_fd = _anonymous_fd(credential.encode("utf-8"), runtime_dir)
        except OSError as error:
            raise SandboxLaunchDriverServiceError(
                "launch-driver credential could not be materialized privately"
            ) from error
    command_line = [
        str(systemd_run),
        "--user",
        f"--unit={unit}",
        f"--slice={attempt_slice}",
        "--property=Type=exec",
        "--property=KillMode=control-group",
        "--property=Restart=no",
        f"--property=RuntimeMaxSec={int(request['timeout_seconds']) + 60}s",
    ]
    for name in (
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "HOME",
        "USER",
        "LOGNAME",
        "PATH",
        "PYTHONPATH",
    ):
        value = environment.get(name)
        if value and not any(character in value for character in "\x00\r\n"):
            command_line.append(f"--setenv={name}={value}")
    if credential_fd is not None:
        command_line.append(
            "--property=LoadCredential="
            f"{_RUNNER_CREDENTIAL_NAME}:/proc/{os.getpid()}/fd/{credential_fd}"
        )
    try:
        request_digest = _write_request(request_path, request)
        try:
            intent = supervisor._sandbox_execution_authorize_launch_driver_start(
                identity[0],
                identity[1],
                launch_request_digest=request_digest,
                credential=credential,
            )
        except BaseException:
            request_path.unlink(missing_ok=True)
            raise

        if intent.service_unit != unit:
            raise SandboxLaunchDriverServiceError(
                "durable launch-driver intent named a different service; fence retained"
            )
        command_line.extend(
            [
                "--working-directory",
                str(repo),
                str(python),
                "-m",
                "agent_control_plane.supervisor.sandbox_launch_driver_service",
                "run",
                "--repo",
                str(repo),
                "--attempt-id",
                identity[0],
                "--claim-token",
                str(identity[1]),
                "--execution-id",
                identity[2],
                "--start-id",
                intent.start_id,
                "--start-digest",
                intent.start_digest,
            ]
        )
        try:
            try:
                _run_trusted_runtime_command(command_line, environment=environment)
            finally:
                # Type=exec makes synchronous systemd-run return only after
                # ExecStart has crossed the exec boundary and LoadCredential
                # has been materialized; keep the raw credential FD alive no
                # longer. --no-block would close it before systemd opens it.
                close_credential_fd()
        except BaseException as activation_error:
            # Even an interruption can arrive after systemd accepted the
            # activation. Reconcile the one-shot intent before returning or
            # propagating it; never replay the command.
            try:
                handoff_won = _stop_and_reconcile_exact_start(
                    supervisor,
                    execution=execution,
                    intent=intent,
                    attempt_slice=attempt_slice,
                    reason="launch-driver systemd activation outcome is uncertain",
                    credential=credential,
                )
            except BaseException as reconcile_error:
                if isinstance(activation_error, (KeyboardInterrupt, SystemExit)):
                    activation_error.add_note(
                        "exact launch reconciliation failed; execution fences were retained"
                    )
                    raise activation_error from reconcile_error
                raise SandboxLaunchDriverServiceError(
                    "launch-driver start outcome is uncertain; exact intent and fences retained"
                ) from reconcile_error
            if handoff_won:
                current = supervisor._sandbox_execution_get(identity[0])
                receipt = _committed_handoff_receipt(current, intent)
                if receipt is None:
                    raise SandboxLaunchDriverServiceError(
                        "durable launch-driver handoff disappeared during activation reconciliation"
                    ) from activation_error
                if isinstance(activation_error, (KeyboardInterrupt, SystemExit)):
                    if current is not None and current["phase"] in {
                        "launched",
                        "running",
                        "stopping",
                    }:
                        try:
                            supervisor._cancel_sandbox_execution_monitor(current)
                        except BaseException as cancel_error:
                            activation_error.add_note(
                                "authenticated monitor cancellation was not confirmed; execution fences remain held"
                            )
                            raise activation_error from cancel_error
                    raise activation_error
                return receipt
            if isinstance(activation_error, SupervisorError):
                raise SandboxLaunchDriverServiceError(
                    "launch-driver start was revoked after an uncertain systemd response; execution remains quarantined"
                ) from activation_error
            raise activation_error
    except BaseException:
        close_credential_fd()
        raise

    polling_reconciliation_attempted = False
    try:
        deadline = time.monotonic() + float(startup_timeout_seconds)
        while time.monotonic() < deadline:
            current = supervisor._sandbox_execution_get(identity[0])
            if (
                current is None
                or current["claim_token"] != identity[1]
                or current["execution_id"] != identity[2]
            ):
                raise SandboxLaunchDriverServiceError(
                    "durable execution changed during launch-driver startup"
                )
            if current.get("launch_driver_start_redeemed_at"):
                receipt = _redeemed_start_receipt(current, intent)
                # record_launch commits the exact worker scope, monitor
                # service receipt, and launch plan together. Only that commit
                # transfers ownership to the out-of-slice monitor. Returning
                # on redemption alone leaves a race where the driver can die
                # with a gated runc child in the attempt slice and no monitor
                # responsible for it.
                if current["phase"] != "reserved":
                    if _committed_handoff_receipt(current, intent) is None:
                        raise SandboxLaunchDriverServiceError(
                            "launch-driver handoff reached an unsupported or incomplete durable phase; execution fence retained"
                        )
                    return receipt

                # Before the journal handoff, this process is the only owner
                # outside the attempt slice. Observe the exact activation so
                # an early service death is contained here rather than left as
                # an orphaned scope. Unknown properties are not guessed; the
                # bounded startup deadline will attempt exact reconciliation.
                try:
                    driver_state = _unit_properties(
                        unit,
                        (
                            "ActiveState",
                            "ControlGroup",
                            "Id",
                            "InvocationID",
                            "LoadState",
                            "MainPID",
                            "Slice",
                        ),
                    )
                except (SupervisorError, SandboxLaunchDriverServiceError):
                    time.sleep(0.05)
                    continue
                if (
                    driver_state["LoadState"] == "loaded"
                    and driver_state["ActiveState"] == "active"
                    and driver_state["Id"] == unit
                    and driver_state["InvocationID"] == receipt.invocation_id
                    and driver_state["MainPID"] == str(receipt.driver_pid)
                    and driver_state["ControlGroup"] == receipt.control_group
                    and driver_state["Slice"] == attempt_slice
                ):
                    time.sleep(0.05)
                    continue
                polling_reconciliation_attempted = True
                try:
                    handoff_won = _stop_and_reconcile_exact_start(
                        supervisor,
                        execution=current,
                        intent=intent,
                        attempt_slice=attempt_slice,
                        reason="launch-driver exited before durable scope registration",
                        credential=credential,
                    )
                except BaseException as reconcile_error:
                    raise SandboxLaunchDriverServiceError(
                        "pre-registration launch failure could not be exactly reconciled; execution fence retained"
                    ) from reconcile_error
                if handoff_won:
                    latest = supervisor._sandbox_execution_get(identity[0])
                    adopted = _committed_handoff_receipt(latest, intent)
                    if adopted is not None:
                        return adopted
                    raise SandboxLaunchDriverServiceError(
                        "launch-driver handoff changed during pre-registration reconciliation; execution fence retained"
                    )
                raise SandboxLaunchDriverServiceError(
                    "launch-driver exited before durable scope registration; exact service and attempt slice are quiescent, execution remains fenced"
                )
            time.sleep(0.05)
        polling_reconciliation_attempted = True
        handoff_won = _stop_and_reconcile_exact_start(
            supervisor,
            execution=execution,
            intent=intent,
            attempt_slice=attempt_slice,
            reason="launch-driver did not durably register its exact scope before startup timeout",
            credential=credential,
        )
        if handoff_won:
            latest = supervisor._sandbox_execution_get(identity[0])
            adopted = _committed_handoff_receipt(latest, intent)
            if adopted is not None:
                return adopted
            raise SandboxLaunchDriverServiceError(
                "launch-driver handoff changed at startup deadline; execution fence retained"
            )
        raise SandboxLaunchDriverServiceError(
            "launch-driver did not durably register its exact scope before timeout; exact units are stopped and execution remains quarantined"
        )
    except BaseException as startup_error:
        if polling_reconciliation_attempted:
            raise
        # The activation may already be accepted while this process is polling.
        # A caller interruption, database failure, or malformed observation in
        # this window must not orphan the driver/monitor pair either.
        polling_reconciliation_attempted = True
        try:
            handoff_won = _stop_and_reconcile_exact_start(
                supervisor,
                execution=execution,
                intent=intent,
                attempt_slice=attempt_slice,
                reason="launch-driver producer exited during startup handoff polling",
                credential=credential,
            )
        except BaseException as reconcile_error:
            startup_error.add_note(
                "exact startup reconciliation failed; execution and resource fences were retained"
            )
            raise startup_error from reconcile_error
        if handoff_won:
            current = supervisor._sandbox_execution_get(identity[0])
            if current is not None and current.get("phase") in {
                "launched",
                "running",
                "stopping",
            }:
                try:
                    supervisor._cancel_sandbox_execution_monitor(current)
                except BaseException as cancel_error:
                    startup_error.add_note(
                        "authenticated monitor cancellation was not confirmed; execution fences remain held"
                    )
                    raise startup_error from cancel_error
        raise
    finally:
        close_credential_fd()


def _run_driver(
    *,
    repo: Path,
    expected_identity: tuple[str, int, str],
    start_id: str,
    start_digest: str,
) -> None:
    if not sys.platform.startswith("linux") or os.geteuid() == 0:
        raise SandboxLaunchDriverServiceError("launch-driver requires an unprivileged Linux user")
    supervisor = GitSupervisor(repo)
    execution = supervisor._sandbox_execution_get(expected_identity[0])
    if (
        execution is None
        or (execution["attempt_id"], execution["claim_token"], execution["execution_id"])
        != expected_identity
        or execution["phase"] != "reserved"
        or execution["launch_driver_start_id"] != start_id
        or execution["launch_driver_start_digest"] != start_digest
    ):
        raise SandboxLaunchDriverServiceError("launch-driver has no matching durable start intent")
    unit = _sandbox_launch_driver_service_unit(execution["execution_id"])
    request_path = _state_request_path(supervisor, execution)
    request, request_digest = _read_request(request_path, expected_identity)
    expected_digest = _sandbox_launch_driver_start_digest(
        execution, unit, launch_request_digest=request_digest
    )
    if expected_digest != start_digest:
        raise SandboxLaunchDriverServiceError(
            "launch-driver request does not match its start intent"
        )
    credential = _read_service_runner_credential()
    _reject_runner_credential_in_command(request, credential)
    redemption = collect_launch_driver_start_redemption(
        expected_identity=expected_identity,
        expected_container_id=execution["container_id"],
        start_id=start_id,
        start_digest=start_digest,
        service_unit=unit,
        attempt_slice_unit=sandbox_attempt_slice_unit(*expected_identity),
    )
    supervisor._sandbox_execution_redeem_launch_driver_start(
        expected_identity[0],
        expected_identity[1],
        redemption=redemption,
        credential=credential,
    )
    # Redemption is write-once. Removing the command request prevents it from
    # being replayed by a later service activation; the durable digest remains.
    request_path.unlink()
    directory_fd = os.open(request_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    _execute_pinned_request(supervisor, expected_identity, request, credential=credential)


def _request_timeout_stop_and_cancel_monitor(
    supervisor: GitSupervisor,
    expected_identity: tuple[str, int, str],
    *,
    credential: str | None,
    monitor_client: Any | None = None,
) -> None:
    """Persist timeout intent before asking the exact monitor to stop the scope.

    The launch-driver created the recovery monitor and retains its authenticated
    startup client on the process-local launch handle. It must use that client;
    reconnect intentionally rejects the original controller process.
    """

    attempt_id, claim_token, execution_id = expected_identity
    try:
        stopping = supervisor._sandbox_execution_request_stop(
            attempt_id,
            claim_token,
            "execution_timeout",
            credential=credential,
        )
    except SupervisorError as error:
        if error.code != "sandbox_execution_transition_conflict":
            raise
        # A user cancellation may have won the stop-intent race. Adopt only
        # that exact durable stopping execution; never replace its reason.
        stopping = supervisor._sandbox_execution_get(attempt_id)
        if (
            stopping is None
            or (
                stopping.get("attempt_id"),
                stopping.get("claim_token"),
                stopping.get("execution_id"),
            )
            != expected_identity
            or stopping.get("phase") != "stopping"
            or not stopping.get("stop_reason")
        ):
            raise
    if (
        stopping.get("attempt_id"),
        stopping.get("claim_token"),
        stopping.get("execution_id"),
    ) != expected_identity:
        raise SupervisorError(
            "sandbox_execution_transition_conflict",
            "timeout stop intent returned a different execution identity; fences remain held",
        )
    supervisor._cancel_sandbox_execution_monitor(stopping, monitor_client=monitor_client)


def _request_driver_failure_stop_and_cancel_monitor(
    supervisor: GitSupervisor,
    expected_identity: tuple[str, int, str],
    *,
    credential: str | None,
    monitor_client: Any | None,
) -> None:
    """Persist failure stop intent before authenticated monitor cancellation."""

    attempt_id, claim_token, execution_id = expected_identity
    try:
        supervisor._sandbox_execution_request_stop(
            attempt_id,
            claim_token,
            "launch_driver_failure",
            credential=credential,
        )
    except SupervisorError as error:
        if error.code != "sandbox_execution_transition_conflict":
            raise
        # A timeout or user cancellation may already own this exact execution.
        # The subsequent read must prove that durable intent before it is adopted.
    stopping = supervisor._sandbox_execution_get(attempt_id)
    with supervisor.connect() as connection:
        launch_stop_reason = (
            _sandbox_execution_launch_stop_reason(connection, stopping)
            if stopping is not None and stopping["phase"] == "launched"
            else None
        )
    durable_reason = (
        (stopping.get("stop_reason") or launch_stop_reason) if stopping is not None else None
    )
    if (
        stopping is None
        or (
            stopping.get("attempt_id"),
            stopping.get("claim_token"),
            stopping.get("execution_id"),
        )
        != expected_identity
        or stopping.get("phase") not in {"launched", "stopping"}
        or not durable_reason
    ):
        raise SupervisorError(
            "sandbox_execution_transition_conflict",
            "launch-driver cancellation lacks an exact durable stop intent; fences remain held",
        )
    supervisor._cancel_sandbox_execution_monitor(stopping, monitor_client=monitor_client)


def _execute_pinned_request(
    supervisor: GitSupervisor,
    expected_identity: tuple[str, int, str],
    request: dict[str, Any],
    *,
    credential: str | None,
) -> None:
    """Keep all launch, attestation, gate, and runc wait capabilities in this process."""

    attempt_id, claim_token, execution_id = expected_identity
    execution = supervisor._sandbox_execution_get(attempt_id)
    if (
        execution is None
        or execution["claim_token"] != claim_token
        or execution["execution_id"] != execution_id
        or execution["phase"] != "reserved"
        or execution["launch_driver_start_redeemed_pid"] != os.getpid()
    ):
        raise SandboxLaunchDriverServiceError("launch-driver redemption is not current")
    rootfs_pin = supervisor.config.oci_rootfs_pin
    runc_pin = supervisor.config.oci_runc_executable
    if rootfs_pin is None or runc_pin is None:
        raise SandboxLaunchDriverServiceError("trusted OCI runtime pins are unavailable")
    supervisor._sandbox_execution_restore_workspace_binding(
        attempt_id, claim_token, credential=credential
    )
    with supervisor.connect() as connection:
        durable = connection.execute(
            "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
        ).fetchone()
    if durable is None:
        raise SandboxLaunchDriverServiceError("durable execution disappeared before launch")
    workspace_snapshot = _restore_snapshot_from_record(
        durable["workspace_root_path"],
        durable["baseline_manifest_json"],
        expected_device=durable["workspace_root_dev"],
        expected_inode=durable["workspace_root_ino"],
        expected_digest=durable["baseline_manifest_digest"],
    )
    bundle_root = Path(durable["bundle_path"])
    state_root = Path(durable["state_path"])
    container_id = durable["container_id"]
    attempt_slice_unit = sandbox_attempt_slice_unit(*expected_identity)
    scope_unit = f"acp-{container_id}.scope"
    pid_file = state_root / "init.pid"
    if pid_file.exists():
        raise SandboxLaunchDriverServiceError("runc init PID file already exists")
    resources = request["resource_limits"]
    config = oci_worker.build_oci_worker_config(
        bundle_root,
        workspace_snapshot,
        request["command"],
        rootfs_pin=rootfs_pin,
        container_id=container_id,
        memory_bytes=resources["memory_max_bytes"],
        cpu_quota_us=resources["cpu_quota"],
        cpu_period_us=resources["cpu_period"],
        pids_limit=resources["pids_max"],
    )
    runtime_binding = oci_worker._apply_pinned_runc_recursive_private_policy(
        config,
        runc_pin,
        expected_version=supervisor.config.oci_runc_version,
    )
    submission: Any | None = None

    def authorize(target: oci_worker._RuncLaunchTarget) -> Any:
        nonlocal submission
        submission = supervisor._sandbox_execution_authorize_launch_submission(
            attempt_id, claim_token, launch_target=target, credential=credential
        )
        return submission

    handle: oci_worker.RuncLaunchHandle | None = None
    try:
        handle = oci_worker.spawn_pinned_runc(
            runtime_binding,
            state_root,
            bundle_root,
            Path(durable["workspace_root_path"]),
            pid_file,
            container_id,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            _authorize_runc_submission=authorize,
        )
        client_pid = oci_worker._runc_launch_pid(handle)
        client_identity = oci_worker._runc_launch_process_identity(handle)
        if submission is None or client_pid is None or client_identity is None:
            raise SandboxLaunchDriverServiceError(
                "pinned runc returned incomplete local provenance"
            )
        deadline = time.monotonic() + 15.0
        process = oci_worker._runc_launch_process_for_testing(handle)
        while not pid_file.exists() and time.monotonic() < deadline:
            if process is None or process.poll() is not None:
                raise SandboxLaunchDriverServiceError("pinned runc exited before init was gated")
            time.sleep(0.05)
        if not pid_file.is_file():
            raise SandboxLaunchDriverServiceError("pinned runc did not create its init PID file")
        slice_properties = _unit_properties(
            attempt_slice_unit, ("ActiveState", "ControlGroup", "Id", "InvocationID")
        )
        scope_properties = _unit_properties(
            scope_unit, ("ActiveState", "ControlGroup", "Id", "InvocationID")
        )
        if (
            slice_properties["ActiveState"] != "active"
            or slice_properties["Id"] != attempt_slice_unit
            or not slice_properties["InvocationID"]
            or not slice_properties["ControlGroup"]
            or scope_properties["ActiveState"] != "active"
            or scope_properties["Id"] != scope_unit
            or not scope_properties["InvocationID"]
            or not scope_properties["ControlGroup"]
            or Path(scope_properties["ControlGroup"]).parent.as_posix()
            != slice_properties["ControlGroup"]
        ):
            raise SandboxLaunchDriverServiceError("worker scope is outside the exact attempt slice")
        supervisor._sandbox_execution_record_launch(
            attempt_id,
            claim_token,
            runc_handle=handle,
            launch_submission=submission,
            attempt_slice_unit=attempt_slice_unit,
            attempt_slice_invocation_id=slice_properties["InvocationID"],
            attempt_slice_cgroup_path=slice_properties["ControlGroup"],
            scope_unit=scope_unit,
            scope_invocation_id=scope_properties["InvocationID"],
            cgroup_path=scope_properties["ControlGroup"],
            credential=credential,
        )
        launched = supervisor._sandbox_execution_get(attempt_id)
        if launched is None or launched["phase"] != "launched":
            raise SandboxLaunchDriverServiceError("launch transition was not durable")
        attestation = collect_running_runtime_attestation(
            runc_executable_pin=runc_pin,
            state_root=state_root,
            pid_file_path=pid_file,
            expected_container_id=container_id,
            expected_bundle_path=str(bundle_root),
            expected_monitor_pid=launched["monitor_pid"],
            expected_monitor_identity=launched["monitor_identity"],
            expected_runc_client_pid=client_pid,
            expected_runc_client_identity=client_identity,
            expected_wrapper_unit=launched["wrapper_unit"],
            expected_wrapper_invocation_id=launched["wrapper_invocation_id"],
            expected_launch_driver_unit=launched["launch_driver_start_unit"],
            expected_attempt_slice_unit=attempt_slice_unit,
            expected_attempt_slice_invocation_id=slice_properties["InvocationID"],
            expected_scope_unit=scope_unit,
            expected_scope_invocation_id=scope_properties["InvocationID"],
            expected_cgroup_path=scope_properties["ControlGroup"],
            expected_memory_max_bytes=resources["memory_max_bytes"],
            expected_cpu_quota=resources["cpu_quota"],
            expected_cpu_period=resources["cpu_period"],
            expected_pids_max=resources["pids_max"],
        )
        running = supervisor._sandbox_execution_record_running(
            attempt_id,
            claim_token,
            attestation=attestation,
            runc_handle=handle,
            credential=credential,
        )
        if running["phase"] != "running":
            raise SandboxLaunchDriverServiceError("running transition was not durable")
        handle.release_gate()
        try:
            wait_receipt = handle.wait(timeout=float(request["timeout_seconds"]))
        except subprocess.TimeoutExpired:
            _request_timeout_stop_and_cancel_monitor(
                supervisor,
                expected_identity,
                credential=credential,
                monitor_client=handle._monitor_client,
            )
            wait_receipt = handle.wait()
        supervisor._sandbox_execution_record_exit(
            attempt_id, claim_token, wait_receipt, credential=credential
        )
        cleanup_action = oci_worker._delete_pinned_runc_container(
            runc_pin,
            expected_version=supervisor.config.oci_runc_version,
            state_root=state_root,
            expected_state_device=durable["state_root_dev"],
            expected_state_inode=durable["state_root_ino"],
            container_id=container_id,
            attempt_id=attempt_id,
            claim_token=claim_token,
            execution_id=execution_id,
        )
        supervisor._sandbox_execution_record_cleanup_report(
            attempt_id,
            claim_token,
            runc_delete_receipt=cleanup_action,
            credential=credential,
        )
    except BaseException:
        if handle is not None:
            try:
                handle.close_gate()
            except BaseException:
                pass
            try:
                current = supervisor._sandbox_execution_get(attempt_id)
                if current is not None and current["phase"] in {"launched", "running", "stopping"}:
                    _request_driver_failure_stop_and_cancel_monitor(
                        supervisor,
                        (attempt_id, claim_token, execution_id),
                        credential=credential,
                        monitor_client=handle._monitor_client,
                    )
                    wait_receipt = handle.wait(timeout=15.0)
                    after_cancel = supervisor._sandbox_execution_get(attempt_id)
                    if after_cancel is not None and after_cancel["phase"] in {
                        "running",
                        "stopping",
                    }:
                        supervisor._sandbox_execution_record_exit(
                            attempt_id, claim_token, wait_receipt, credential=credential
                        )
                    # A launched-only row has no trusted init identity. The
                    # launcher's wait receipt cannot prove container-init
                    # absence, so keep that execution fenced for recovery.
            except BaseException:
                # Keep the durable execution and resource fences when exact
                # monitor cancellation or runc wait evidence is unavailable.
                pass
        raise


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="sandbox-launch-driver-service")
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run")
    run.add_argument("--repo", required=True, type=Path)
    run.add_argument("--attempt-id", required=True)
    run.add_argument("--claim-token", required=True, type=int)
    run.add_argument("--execution-id", required=True)
    run.add_argument("--start-id", required=True)
    run.add_argument("--start-digest", required=True)
    arguments = parser.parse_args(argv)
    if arguments.command != "run":
        parser.error("unsupported launch-driver command")
    repo = arguments.repo.resolve(strict=True)
    if not repo.is_dir() or arguments.repo.as_posix() != str(repo):
        raise SandboxLaunchDriverServiceError("launch-driver repository path is not canonical")
    _run_driver(
        repo=repo,
        expected_identity=(arguments.attempt_id, arguments.claim_token, arguments.execution_id),
        start_id=arguments.start_id,
        start_digest=arguments.start_digest,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
