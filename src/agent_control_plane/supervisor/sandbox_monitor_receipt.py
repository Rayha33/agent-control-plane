"""Durable identity receipts for per-execution systemd monitor services.

This module records and revalidates the manager-owned service identity only.
It does not transfer a live runc handle, authorize its gate, or prove worker
cleanup; those actions remain owned by the monitor process.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_UNIT = re.compile(r"[A-Za-z0-9_.:@\\-]+\.(?:service|slice)\Z")
_INVOCATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_LINUX_IDENTITY = re.compile(r"linux:([1-9][0-9]*):([1-9][0-9]*)\Z")
_MAX_RECEIPT_BYTES = 8192


class SandboxMonitorReceiptError(ValueError):
    """A persisted monitor identity is malformed, stale, or contradictory."""


def sandbox_container_id(attempt_id: str, claim_token: int, execution_id: str) -> str:
    """Derive the runtime identifier from the complete fenced execution identity."""

    _validate_execution_identity(attempt_id, claim_token, execution_id)
    identity = json.dumps(
        {
            "attempt_id": attempt_id,
            "claim_token": claim_token,
            "execution_id": execution_id,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return f"acp-{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:60]}"


def sandbox_monitor_service_unit(attempt_id: str, claim_token: int, execution_id: str) -> str:
    """Return a collision-resistant service name for one claim/fencing epoch."""

    container_id = sandbox_container_id(attempt_id, claim_token, execution_id)
    return f"acp-monitor-{container_id.removeprefix('acp-')}.service"


def sandbox_attempt_slice_unit(attempt_id: str, claim_token: int, execution_id: str) -> str:
    """Return the unique worker slice paired with a monitor service identity."""

    container_id = sandbox_container_id(attempt_id, claim_token, execution_id)
    digest = hashlib.sha256(container_id.encode("ascii")).hexdigest()
    return f"user-acp-{digest}.slice"


def _validate_component(value: Any, field: str) -> str:
    if not isinstance(value, str) or _COMPONENT.fullmatch(value) is None:
        raise SandboxMonitorReceiptError(f"{field} is not a safe component")
    return value


def _validate_execution_identity(attempt_id: Any, claim_token: Any, execution_id: Any) -> None:
    _validate_component(attempt_id, "attempt_id")
    if type(claim_token) is not int or not 0 < claim_token <= (1 << 63) - 1:
        raise SandboxMonitorReceiptError("claim_token is invalid")
    _validate_component(execution_id, "execution_id")


def _cgroup_path(value: Any, field: str) -> PurePosixPath:
    if not isinstance(value, str) or len(value) > 4096:
        raise SandboxMonitorReceiptError(f"{field} is invalid")
    path = PurePosixPath(value)
    if (
        not path.is_absolute()
        or path.as_posix() != value
        or len(path.parts) < 2
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise SandboxMonitorReceiptError(f"{field} is not a canonical absolute cgroup path")
    return path


@dataclass(frozen=True)
class SandboxMonitorReceipt:
    """Immutable systemd and PID-start identity needed for safe reconnect."""

    controller_pid: int
    attempt_id: str
    claim_token: int
    execution_id: str
    unit: str
    invocation_id: str
    control_group: str
    main_pid: int
    main_identity: str
    monitor_slice_unit: str
    monitor_slice_control_group: str
    attempt_slice_unit: str
    attempt_slice_control_group: str
    version: int = 1

    def __post_init__(self) -> None:
        _validate_execution_identity(self.attempt_id, self.claim_token, self.execution_id)
        if type(self.version) is not int or self.version != 1:
            raise SandboxMonitorReceiptError("monitor receipt has an unsupported version")
        if (
            type(self.controller_pid) is not int
            or self.controller_pid <= 0
            or type(self.main_pid) is not int
            or self.main_pid <= 0
            or self.controller_pid == self.main_pid
        ):
            raise SandboxMonitorReceiptError("monitor receipt contains an invalid process identity")
        expected_unit = sandbox_monitor_service_unit(
            self.attempt_id, self.claim_token, self.execution_id
        )
        if self.unit != expected_unit or _UNIT.fullmatch(self.unit) is None:
            raise SandboxMonitorReceiptError("monitor unit is not bound to the fenced execution")
        if (
            not isinstance(self.invocation_id, str)
            or _INVOCATION_ID.fullmatch(self.invocation_id) is None
        ):
            raise SandboxMonitorReceiptError("monitor invocation ID is invalid")
        identity_match = (
            _LINUX_IDENTITY.fullmatch(self.main_identity)
            if isinstance(self.main_identity, str)
            else None
        )
        if identity_match is None or int(identity_match.group(1)) != self.main_pid:
            raise SandboxMonitorReceiptError("monitor PID start identity is invalid")
        if (
            not isinstance(self.monitor_slice_unit, str)
            or _UNIT.fullmatch(self.monitor_slice_unit) is None
            or not self.monitor_slice_unit.endswith(".slice")
        ):
            raise SandboxMonitorReceiptError("monitor slice unit is invalid")
        expected_attempt_slice = sandbox_attempt_slice_unit(
            self.attempt_id, self.claim_token, self.execution_id
        )
        if self.attempt_slice_unit != expected_attempt_slice:
            raise SandboxMonitorReceiptError("attempt slice is not bound to the fenced execution")
        if (
            not isinstance(self.attempt_slice_unit, str)
            or _UNIT.fullmatch(self.attempt_slice_unit) is None
            or not self.attempt_slice_unit.endswith(".slice")
        ):
            raise SandboxMonitorReceiptError("attempt slice unit is invalid")

        service_cgroup = _cgroup_path(self.control_group, "monitor control group")
        monitor_slice_cgroup = _cgroup_path(
            self.monitor_slice_control_group, "monitor slice control group"
        )
        attempt_slice_cgroup = _cgroup_path(
            self.attempt_slice_control_group, "attempt slice control group"
        )
        if (
            service_cgroup.name != self.unit
            or service_cgroup.parent != monitor_slice_cgroup
            or monitor_slice_cgroup.name != self.monitor_slice_unit
            or attempt_slice_cgroup.name != self.attempt_slice_unit
            or attempt_slice_cgroup.parent != monitor_slice_cgroup
            or service_cgroup.is_relative_to(attempt_slice_cgroup)
            or attempt_slice_cgroup.is_relative_to(service_cgroup)
        ):
            raise SandboxMonitorReceiptError(
                "monitor service and worker slice do not have the recorded sibling placement"
            )

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "controller_pid": self.controller_pid,
            "attempt_id": self.attempt_id,
            "claim_token": self.claim_token,
            "execution_id": self.execution_id,
            "unit": self.unit,
            "invocation_id": self.invocation_id,
            "control_group": self.control_group,
            "main_pid": self.main_pid,
            "main_identity": self.main_identity,
            "monitor_slice_unit": self.monitor_slice_unit,
            "monitor_slice_control_group": self.monitor_slice_control_group,
            "attempt_slice_unit": self.attempt_slice_unit,
            "attempt_slice_control_group": self.attempt_slice_control_group,
        }

    @classmethod
    def from_dict(cls, value: Any) -> SandboxMonitorReceipt:
        expected = {
            "version",
            "controller_pid",
            "attempt_id",
            "claim_token",
            "execution_id",
            "unit",
            "invocation_id",
            "control_group",
            "main_pid",
            "main_identity",
            "monitor_slice_unit",
            "monitor_slice_control_group",
            "attempt_slice_unit",
            "attempt_slice_control_group",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise SandboxMonitorReceiptError("monitor receipt has an unsupported shape")
        if type(value["version"]) is not int:
            raise SandboxMonitorReceiptError("monitor receipt has an unsupported version")
        integer_fields = ("controller_pid", "claim_token", "main_pid")
        string_fields = expected - {"version", *integer_fields}
        if any(type(value[field]) is not int for field in integer_fields) or any(
            not isinstance(value[field], str) for field in string_fields
        ):
            raise SandboxMonitorReceiptError("monitor receipt contains invalid field types")
        return cls(**value)


def validate_monitor_service_reconciliation(
    receipt: SandboxMonitorReceipt,
    service: Mapping[str, str],
    monitor_slice: Mapping[str, str],
    attempt_slice: Mapping[str, str],
    *,
    observed_main_identity: str | None,
    reconciler_pid: int,
) -> None:
    """Reject reconnect unless systemd and live PID identity match the receipt."""

    if type(receipt) is not SandboxMonitorReceipt:
        raise SandboxMonitorReceiptError("reconciliation requires a typed monitor receipt")
    expected_service = {
        "Id": receipt.unit,
        "LoadState": "loaded",
        "ActiveState": "active",
        "InvocationID": receipt.invocation_id,
        "ControlGroup": receipt.control_group,
        "Slice": receipt.monitor_slice_unit,
        "MainPID": str(receipt.main_pid),
    }
    expected_monitor_slice = {
        "Id": receipt.monitor_slice_unit,
        "LoadState": "loaded",
        "ActiveState": "active",
        "ControlGroup": receipt.monitor_slice_control_group,
    }
    expected_attempt_slice = {
        "Id": receipt.attempt_slice_unit,
        "LoadState": "loaded",
        "ActiveState": "active",
        "Slice": receipt.monitor_slice_unit,
        "ControlGroup": receipt.attempt_slice_control_group,
    }
    for observed, expected, label in (
        (service, expected_service, "monitor service"),
        (monitor_slice, expected_monitor_slice, "monitor slice"),
        (attempt_slice, expected_attempt_slice, "attempt slice"),
    ):
        if any(not isinstance(value, str) for value in observed.values()) or any(
            observed.get(key) != value for key, value in expected.items()
        ):
            raise SandboxMonitorReceiptError(f"{label} no longer matches its durable receipt")
    if type(reconciler_pid) is not int or reconciler_pid <= 0:
        raise SandboxMonitorReceiptError("reconciler process identity is invalid")
    if reconciler_pid == receipt.controller_pid:
        raise SandboxMonitorReceiptError(
            "reconciliation unexpectedly ran in the original controller process"
        )
    if observed_main_identity != receipt.main_identity:
        raise SandboxMonitorReceiptError(
            "recorded systemd monitor PID start identity changed or is absent"
        )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SandboxMonitorReceiptError("monitor receipt contains duplicate JSON keys")
        result[key] = value
    return result


def _open_private_parent(path: Path) -> int:
    if (
        not path.is_absolute()
        or _COMPONENT.fullmatch(path.name) is None
        or ".." in path.parent.parts
    ):
        raise SandboxMonitorReceiptError("monitor receipt path is not an absolute safe path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path.parent, flags)
    info = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise SandboxMonitorReceiptError("monitor receipt directory is not private and owned")
    return descriptor


def _recover_orphan_temporary_link(
    directory_fd: int, name: str, target_descriptor: int, target_info: os.stat_result
) -> None:
    """Remove only the exact same-inode temp link left by a writer crash."""

    def sync_if_publisher_finished() -> bool:
        current = os.fstat(target_descriptor)
        if (
            current.st_dev != target_info.st_dev
            or current.st_ino != target_info.st_ino
            or current.st_nlink != 1
        ):
            return False
        os.fsync(directory_fd)
        return True

    expected_name = re.compile(rf"\.{re.escape(name)}\.[0-9a-f]{{32}}\.tmp\Z")
    candidates: list[str] = []
    for entry in os.listdir(directory_fd):
        if expected_name.fullmatch(entry) is None:
            continue
        try:
            entry_info = os.stat(entry, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if (entry_info.st_dev, entry_info.st_ino) == (target_info.st_dev, target_info.st_ino):
            candidates.append(entry)
        elif (
            stat.S_ISREG(entry_info.st_mode)
            and entry_info.st_uid == os.geteuid()
            and stat.S_IMODE(entry_info.st_mode) == 0o600
            and entry_info.st_nlink == 1
        ):
            # A publisher can crash before linking its private temp, or still
            # be preparing an exact replay. It is unrelated to this target;
            # leave it alone and do not let it block recovery of the real link.
            continue
        else:
            raise SandboxMonitorReceiptError(
                "monitor receipt has an unrelated or unsafe temporary entry"
            )
    if not candidates and sync_if_publisher_finished():
        # A live publisher may have removed the temp link after our initial
        # fstat; syncing here completes the same durability boundary.
        return
    if len(candidates) != 1:
        raise SandboxMonitorReceiptError("monitor receipt has ambiguous orphan temporary links")

    temporary_name = candidates[0]
    try:
        descriptor = os.open(
            temporary_name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fd,
        )
    except FileNotFoundError:
        if sync_if_publisher_finished():
            return
        raise SandboxMonitorReceiptError("monitor receipt orphan link disappeared") from None
    try:
        temporary_info = os.fstat(descriptor)
        named_info = os.stat(temporary_name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(temporary_info.st_mode)
            or temporary_info.st_uid != os.geteuid()
            or stat.S_IMODE(temporary_info.st_mode) != 0o600
            or temporary_info.st_nlink != 2
            or (temporary_info.st_dev, temporary_info.st_ino)
            != (target_info.st_dev, target_info.st_ino)
            or (named_info.st_dev, named_info.st_ino)
            != (temporary_info.st_dev, temporary_info.st_ino)
        ):
            raise SandboxMonitorReceiptError("monitor receipt orphan link does not match target")
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            # The original writer can win this race after our metadata check.
            pass
    except FileNotFoundError:
        if sync_if_publisher_finished():
            return
        raise SandboxMonitorReceiptError("monitor receipt orphan link disappeared") from None
    finally:
        os.close(descriptor)

    # This also covers a race where the writer removed the temp link just
    # before our unlink; fsync makes either completed cleanup durable.
    os.fsync(directory_fd)
    recovered_info = os.fstat(target_descriptor)
    if (
        recovered_info.st_dev != target_info.st_dev
        or recovered_info.st_ino != target_info.st_ino
        or recovered_info.st_nlink != 1
    ):
        raise SandboxMonitorReceiptError("monitor receipt orphan link recovery was incomplete")


def _read_receipt_at(directory_fd: int, name: str) -> SandboxMonitorReceipt:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        dir_fd=directory_fd,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink not in {1, 2}
            or before.st_size <= 0
            or before.st_size > _MAX_RECEIPT_BYTES
        ):
            raise SandboxMonitorReceiptError("monitor receipt is not a bounded private file")
        if before.st_nlink == 2:
            _recover_orphan_temporary_link(directory_fd, name, descriptor, before)
            before = os.fstat(descriptor)
        chunks: list[bytes] = []
        remaining = _MAX_RECEIPT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        encoded = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(encoded) != before.st_size
            or len(encoded) > _MAX_RECEIPT_BYTES
            or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        ):
            raise SandboxMonitorReceiptError("monitor receipt changed while being read")
    finally:
        os.close(descriptor)
    try:
        raw = json.loads(encoded.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
        receipt = SandboxMonitorReceipt.from_dict(raw)
        canonical = json.dumps(
            receipt.as_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SandboxMonitorReceiptError("monitor receipt is not canonical JSON") from error
    if encoded != canonical:
        raise SandboxMonitorReceiptError("monitor receipt is not canonical JSON")
    return receipt


def read_sandbox_monitor_receipt(path: str | Path) -> SandboxMonitorReceipt:
    """Read one bounded, private, no-follow receipt from a private directory."""

    target = Path(path)
    directory_fd = _open_private_parent(target)
    try:
        receipt = _read_receipt_at(directory_fd, target.name)
        # Stabilize a valid target left by a writer that died after unlinking
        # its temp name but before syncing the containing directory.
        os.fsync(directory_fd)
        return receipt
    finally:
        os.close(directory_fd)


def write_sandbox_monitor_receipt(path: str | Path, receipt: SandboxMonitorReceipt) -> None:
    """Create an immutable receipt atomically; exact replays are idempotent."""

    if type(receipt) is not SandboxMonitorReceipt:
        raise SandboxMonitorReceiptError("writing requires a typed monitor receipt")
    target = Path(path)
    directory_fd = _open_private_parent(target)
    temporary_name = f".{target.name}.{uuid.uuid4().hex}.tmp"
    descriptor = -1
    try:
        encoded = json.dumps(
            receipt.as_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        if len(encoded) > _MAX_RECEIPT_BYTES:
            raise SandboxMonitorReceiptError("monitor receipt exceeds its size bound")
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while persisting monitor receipt")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(
                temporary_name,
                target.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            # Drop this attempt's distinct, unpublished temp before recovery;
            # otherwise it would make a prior publisher's orphan link appear
            # ambiguous to the reader.
            os.unlink(temporary_name, dir_fd=directory_fd)
            if _read_receipt_at(directory_fd, target.name) == receipt:
                # The earlier writer may have died after publishing the link
                # but before making the directory entry durable.
                os.fsync(directory_fd)
                return
            raise SandboxMonitorReceiptError(
                "a conflicting monitor receipt already exists"
            ) from None
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            # A concurrent recovery reader may already have removed this
            # exact hard link after validating it against the published inode.
            pass
        os.fsync(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.close(directory_fd)
