"""Fail-closed controller recovery for a systemd-owned sandbox monitor.

This module only adopts a monitor that is already running. It never starts a
worker or reconstructs a process-local ``RuncLaunchHandle``. A caller must
first bind the expected execution tuple to its durable ACP journal row, then
use this helper to verify the exact systemd activation and reconnect to its
status/cancel channel.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
from pathlib import Path

from .sandbox_attestation import (
    _run_trusted_runtime_command,
    _trusted_systemctl_executable,
    _trusted_systemd_command_environment,
)
from .sandbox_monitor_ipc import (
    SandboxMonitorControlClient,
    SandboxMonitorIPCError,
    _linux_process_identity,
    _open_private_directory,
)
from .sandbox_monitor_receipt import (
    SandboxMonitorReceipt,
    SandboxMonitorReceiptError,
    read_sandbox_monitor_control_key,
    read_sandbox_monitor_receipt,
    sandbox_container_id,
    validate_monitor_service_reconciliation,
)

_MAX_PROPERTIES_BYTES = 16 * 1024
_PROPERTY_NAME = re.compile(r"[A-Za-z][A-Za-z0-9]*\Z")


def _parse_unit_properties(raw: bytes, expected: frozenset[str]) -> dict[str, str]:
    if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_PROPERTIES_BYTES:
        raise SandboxMonitorReceiptError("systemd monitor properties are empty or oversized")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise SandboxMonitorReceiptError("systemd monitor properties are not ASCII") from error
    properties: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if (
            not separator
            or _PROPERTY_NAME.fullmatch(key) is None
            or value != value.strip()
            or key in properties
        ):
            raise SandboxMonitorReceiptError(
                "systemd monitor properties are malformed or duplicated"
            )
        properties[key] = value
    if set(properties) != expected:
        raise SandboxMonitorReceiptError("systemd monitor properties are incomplete")
    return properties


def _read_unit_properties(
    systemctl: Path,
    environment: dict[str, str],
    unit: str,
    properties: tuple[str, ...],
) -> dict[str, str]:
    if not isinstance(unit, str) or not unit or any(character in unit for character in "\x00\r\n"):
        raise SandboxMonitorReceiptError("systemd unit name is invalid")
    argv = [
        str(systemctl),
        "--user",
        "show",
        "--no-pager",
        f"--property={','.join(properties)}",
        "--",
        unit,
    ]
    try:
        raw = _run_trusted_runtime_command(argv, environment=environment)
    except Exception as error:
        raise SandboxMonitorReceiptError(
            "trusted systemd monitor reconciliation query failed"
        ) from error
    return _parse_unit_properties(raw, frozenset(properties))


def reconcile_sandbox_monitor(
    receipt: SandboxMonitorReceipt,
    *,
    expected_identity: tuple[str, int, str],
) -> None:
    """Prove that the receipt still names this exact live monitor activation.

    Production calls resolve a root-owned systemctl and validate the current
    private user-manager socket before observing unit state.
    """

    if type(receipt) is not SandboxMonitorReceipt:
        raise SandboxMonitorReceiptError("monitor reconciliation requires a typed receipt")
    if (
        not isinstance(expected_identity, tuple)
        or len(expected_identity) != 3
        or type(expected_identity[1]) is not int
    ):
        raise SandboxMonitorReceiptError("expected monitor execution identity is invalid")
    try:
        sandbox_container_id(*expected_identity)
    except (TypeError, SandboxMonitorReceiptError) as error:
        raise SandboxMonitorReceiptError(
            "expected monitor execution identity is invalid"
        ) from error
    if (receipt.attempt_id, receipt.claim_token, receipt.execution_id) != expected_identity:
        raise SandboxMonitorReceiptError("monitor receipt belongs to another fenced execution")
    if not sys.platform.startswith("linux"):
        raise SandboxMonitorReceiptError("systemd monitor recovery requires Linux")

    try:
        resolved_systemctl = _trusted_systemctl_executable()
        resolved_environment = _trusted_systemd_command_environment()
        service = _read_unit_properties(
            resolved_systemctl,
            resolved_environment,
            receipt.unit,
            (
                "Id",
                "LoadState",
                "ActiveState",
                "InvocationID",
                "ControlGroup",
                "Slice",
                "MainPID",
            ),
        )
        monitor_slice = _read_unit_properties(
            resolved_systemctl,
            resolved_environment,
            receipt.monitor_slice_unit,
            ("Id", "LoadState", "ActiveState", "ControlGroup"),
        )
        attempt_slice = _read_unit_properties(
            resolved_systemctl,
            resolved_environment,
            receipt.attempt_slice_unit,
            ("Id", "LoadState", "ActiveState", "Slice", "ControlGroup"),
        )
        observed_identity = _linux_process_identity(receipt.main_pid)
    except SandboxMonitorReceiptError:
        raise
    except Exception as error:
        raise SandboxMonitorReceiptError(
            "systemd monitor identity could not be observed safely"
        ) from error
    validate_monitor_service_reconciliation(
        receipt,
        service,
        monitor_slice,
        attempt_slice,
        observed_main_identity=observed_identity,
        reconciler_pid=os.getpid(),
    )


def sandbox_monitor_control_paths(
    *, state_path: str | Path, expected_identity: tuple[str, int, str]
) -> tuple[Path, Path, Path]:
    """Derive the durable monitor directory and short runtime socket path.

    The execution state path is part of the immutable reservation. Keeping the
    receipt, key, and replay ledger beneath it makes them available after a
    supervisor restart. The Unix socket lives in the already-private systemd
    user runtime directory because state paths can exceed ``sun_path`` limits.
    Both locations are deterministic from the exact fenced execution identity.
    """

    try:
        container_id = sandbox_container_id(*expected_identity)
    except (TypeError, SandboxMonitorReceiptError) as error:
        raise SandboxMonitorReceiptError("monitor execution identity is invalid") from error
    state_root = Path(state_path)
    if (
        not state_root.is_absolute()
        or ".." in state_root.parts
        or str(state_root) != os.path.normpath(str(state_root))
    ):
        raise SandboxMonitorReceiptError("monitor state path is not canonical and absolute")

    environment = _trusted_systemd_command_environment()
    runtime_directory = Path(environment["XDG_RUNTIME_DIR"])
    if (
        not runtime_directory.is_absolute()
        or ".." in runtime_directory.parts
        or str(runtime_directory) != os.path.normpath(str(runtime_directory))
    ):
        raise SandboxMonitorReceiptError("trusted monitor runtime directory is not canonical")
    control_directory = state_root / "monitor"
    receipt_path = control_directory / "monitor-receipt.json"
    socket_path = runtime_directory / f"acpmon-{container_id.removeprefix('acp-')}.sock"
    if len(os.fsencode(socket_path)) >= 108:
        raise SandboxMonitorReceiptError("derived monitor socket path exceeds the Unix limit")
    return control_directory, receipt_path, socket_path


def sandbox_monitor_cancel_request_id(expected_identity: tuple[str, int, str]) -> str:
    """Return one execution-bound cancellation ID reusable after any timeout."""

    try:
        container_id = sandbox_container_id(*expected_identity)
    except (TypeError, SandboxMonitorReceiptError) as error:
        raise SandboxMonitorReceiptError("monitor execution identity is invalid") from error
    return hashlib.sha256(
        b"acp-sandbox-monitor-cancel-v1\0" + container_id.encode("ascii")
    ).hexdigest()[:32]


def reconnect_sandbox_monitor(
    *,
    receipt_path: str | Path,
    control_directory: str | Path,
    socket_path: str | Path,
    expected_identity: tuple[str, int, str],
    timeout_seconds: float = 2.0,
) -> SandboxMonitorControlClient:
    """Adopt an exact live monitor after controller restart.

    The durable identity is checked before any key or socket access. Recovery
    reads an existing execution key; it never creates a replacement. If the
    receipt, systemd activation, process start identity, key, or socket does
    not match, the caller gets an error and must retain the execution fence.
    """

    directory = Path(control_directory)
    receipt_file = Path(receipt_path)
    control_socket = Path(socket_path)
    for path, label in (
        (directory, "monitor control directory"),
        (receipt_file, "monitor receipt path"),
        (control_socket, "monitor socket path"),
    ):
        if not path.is_absolute() or ".." in path.parts or str(path) != os.path.normpath(str(path)):
            raise SandboxMonitorReceiptError(f"{label} is not canonical and absolute")
    if receipt_file.parent != directory:
        raise SandboxMonitorReceiptError("monitor receipt must be in its private control directory")
    socket_parent_fd = -1
    try:
        socket_parent_fd = _open_private_directory(control_socket.parent)
    except SandboxMonitorIPCError as error:
        raise SandboxMonitorReceiptError(
            "monitor socket parent is not a private directory"
        ) from error
    finally:
        if socket_parent_fd >= 0:
            os.close(socket_parent_fd)
    receipt = read_sandbox_monitor_receipt(receipt_file)
    reconcile_sandbox_monitor(receipt, expected_identity=expected_identity)
    try:
        key = read_sandbox_monitor_control_key(
            directory,
            attempt_id=receipt.attempt_id,
            claim_token=receipt.claim_token,
            execution_id=receipt.execution_id,
        )
        return SandboxMonitorControlClient(
            receipt=receipt,
            socket_path=control_socket,
            key=key,
            expected_uid=os.geteuid(),
            timeout_seconds=timeout_seconds,
        )
    except (SandboxMonitorReceiptError, SandboxMonitorIPCError) as error:
        raise SandboxMonitorReceiptError(
            "reconnecting to the exact sandbox monitor failed; execution remains fenced"
        ) from error


__all__ = [
    "reconcile_sandbox_monitor",
    "reconnect_sandbox_monitor",
    "sandbox_monitor_cancel_request_id",
    "sandbox_monitor_control_paths",
]
