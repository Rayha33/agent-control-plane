"""Durable, fail-closed identity journal for a future OCI worker executor.

Launch and exit records are bound to the pinned-runc process handle and its
wait receipt. The public OCI-init gate can be released only after the exact
registered handle and the exact object issued by the process-local runtime collector are
durably recorded as running, but this module does not orchestrate a worker
lifecycle or establish a sandbox. A cleanup report is not accepted as cleanup
verification.
The existing reaper and runtime teardown stay fenced until a separate trusted
verifier advances the journal to ``cleanup_verified``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
import time
import uuid
import weakref
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .common import CLEANUP_FENCE_EPOCH, SupervisorError, canonical_json, utc_now
from .oci_worker import (
    RuncLaunchHandle,
    _authorize_runc_launch_gate_release_locked,
    _oci_worker_systemd_slice,
    _private_directory,
    _register_runc_launch_submission_target,
    _revoke_runc_launch_gate_release_locked,
    _runc_cleanup_action_receipt_is_self_consistent,
    _runc_client_wait_receipt_is_self_consistent,
    _runc_execution_gate_fence,
    _runc_launch_gate_lock_for_execution,
    _runc_launch_handle_bind_execution,
    _runc_launch_handle_is_bound_to_execution,
    _runc_launch_handle_is_self_consistent,
    _runc_launch_pid,
    _runc_launch_process_identity,
    _runc_launch_submission_is_bound_to_handle,
    _runc_launch_target,
    _RuncClientWaitReceipt,
    _RuncLaunchTarget,
)
from .sandbox_attestation import (
    LaunchDriverStartRedemption,
    RunningRuntimeAttestation,
    collect_launch_driver_start_redemption,
    launch_driver_start_redemption_has_collector_provenance,
    launch_driver_start_redemption_is_self_consistent,
    running_attestation_has_collector_provenance,
    running_attestation_is_self_consistent,
    verify_linux_process_membership,
    verify_running_runtime_process_membership,
    verify_running_runtime_resource_controls,
    verify_running_runtime_systemd_units,
)
from .sandbox_monitor_receipt import (
    sandbox_monitor_service_unit as _sandbox_monitor_service_unit,
)
from .sandbox_workspace import (
    _MAX_DURABLE_MANIFEST_BYTES,
    _restore_snapshot_from_record,
    _verify_directory_identity,
)
from .sandbox_workspace import Snapshot as _Snapshot
from .sandbox_workspace import _snapshot_origin as _snapshot_origin
from .sandbox_workspace import collect_changes as _collect_changes
from .store import (
    _authorize_sandbox_cleanup_action_write,
    _authorize_sandbox_cleanup_report_write,
    _authorize_sandbox_cleanup_verification_write,
    _authorize_sandbox_exit_receipt_write,
    _authorize_sandbox_launch_driver_redemption_write,
    _authorize_sandbox_launch_driver_start_write,
    _authorize_sandbox_launch_plan_write,
    _authorize_sandbox_launch_submission_write,
    _authorize_sandbox_reservation_write,
    _store_raw_connection_for_running_transition,
)


def _sandbox_running_attestation_expected_for_row(row: Any) -> dict[str, Any]:
    launch_driver_unit = _sandbox_launch_driver_service_unit(row["execution_id"])
    return {
        "monitor_placement": "outside_attempt_slice",
        "container_id": row["container_id"],
        "bundle_path": row["bundle_path"],
        "monitor_pid": row["monitor_pid"],
        "monitor_identity": row["monitor_identity"],
        "runc_client_pid": row["runc_client_pid"],
        "runc_client_identity": row["runc_client_identity"],
        "launch_driver_unit": launch_driver_unit,
        "launch_driver_control_group": (f"{row['attempt_slice_cgroup_path']}/{launch_driver_unit}"),
        "wrapper_unit": row["wrapper_unit"],
        "wrapper_invocation_id": row["wrapper_invocation_id"],
        "wrapper_control_group": row["wrapper_cgroup_path"],
        "attempt_slice_unit": row["attempt_slice_unit"],
        "attempt_slice_invocation_id": row["attempt_slice_invocation_id"],
        "attempt_slice_control_group": row["attempt_slice_cgroup_path"],
        "scope_unit": row["scope_unit"],
        "scope_invocation_id": row["scope_invocation_id"],
        "cgroup_path": row["cgroup_path"],
    }


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_OCI_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SYSTEMD_UNIT = re.compile(r"[A-Za-z0-9_.:@\\-]+\.(?:service|scope|slice)\Z")
_INVOCATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_ATTEMPT_SLICE_COMPONENT = re.compile(r"user-acp-[0-9a-f]{64}\.slice\Z")
_LEGACY_BUNDLE_DIGEST_SEMANTICS = "legacy-caller-asserted-v0"
_BUNDLE_DIGEST_SEMANTICS = "oci-reservation-v1"
_LAUNCH_DRIVER_LEASE_LOSS_REASON = (
    "launch-driver stop intent could not be recorded after attempt lease loss"
)
_PHASES = frozenset(
    {
        "reserved",
        "launched",
        "running",
        "stopping",
        "exited",
        "cleanup_reported",
        "cleanup_verified",
        "ambiguous",
    }
)
_TRANSITION_FIELDS = {
    ("reserved", "launched"): frozenset(
        {
            "monitor_pid",
            "monitor_identity",
            "runc_client_pid",
            "runc_client_identity",
            "wrapper_unit",
            "wrapper_invocation_id",
            "wrapper_cgroup_path",
            "attempt_slice_unit",
            "attempt_slice_invocation_id",
            "attempt_slice_cgroup_path",
            "scope_unit",
            "scope_invocation_id",
            "cgroup_path",
            "launch_plan_binding_version",
            "launch_plan_json",
            "launch_config_digest",
            "launch_argv_digest",
            "launch_plan_digest",
        }
    ),
    ("launched", "running"): frozenset(
        {
            "init_pid",
            "init_identity",
            "launch_driver_pid",
            "launch_driver_identity",
            "launch_driver_unit",
            "launch_driver_invocation_id",
            "launch_driver_cgroup_path",
        }
    ),
    ("running", "stopping"): frozenset({"stop_reason"}),
    ("exited", "cleanup_reported"): frozenset({"cleanup_receipt_json"}),
    ("cleanup_reported", "cleanup_verified"): frozenset({"cleanup_verification_json"}),
}


@dataclass(eq=False, frozen=True, slots=True, weakref_slot=True)
class _SandboxLaunchSubmission:
    """Process-local authority returned only after the durable pre-runc latch."""

    attempt_id: str
    claim_token: int
    execution_id: str
    submission_id: str
    submission_digest: str


@dataclass(eq=False, frozen=True, slots=True, weakref_slot=True)
class _SandboxLaunchDriverStartIntent:
    """Process-local capability for one durable pre-activation driver intent."""

    attempt_id: str
    claim_token: int
    execution_id: str
    start_id: str
    start_digest: str
    service_unit: str


@dataclass(eq=False, frozen=True, slots=True, weakref_slot=True)
class _SandboxCleanupVerificationReceipt:
    """Process-local authority issued only after independent post-stop checks."""

    attempt_id: str
    claim_token: int
    execution_id: str
    cleanup_report_sha256: str
    encoded: str


@dataclass(eq=False, frozen=True, slots=True, weakref_slot=True)
class _SandboxCleanupRecoveryReceipt:
    """Process-local authority for an independently recovered cleanup report."""

    attempt_id: str
    claim_token: int
    execution_id: str
    launch_submission_id: str
    launch_submission_digest: str
    reaper_epoch: int
    encoded: str


_SANDBOX_CLEANUP_VERIFICATION_RECEIPTS: dict[
    int,
    tuple[
        weakref.ReferenceType[_SandboxCleanupVerificationReceipt],
        tuple[str, int, str, str, str],
    ],
] = {}
_SANDBOX_CLEANUP_VERIFICATION_RECEIPTS_LOCK = threading.Lock()
_SANDBOX_CLEANUP_RECOVERY_RECEIPTS: dict[
    int,
    tuple[
        weakref.ReferenceType[_SandboxCleanupRecoveryReceipt],
        tuple[str, int, str, str, str, int, str],
    ],
] = {}
_SANDBOX_CLEANUP_RECOVERY_RECEIPTS_LOCK = threading.Lock()


def _register_sandbox_cleanup_verification_receipt(
    receipt: _SandboxCleanupVerificationReceipt,
) -> None:
    key = id(receipt)
    fields = (
        receipt.attempt_id,
        receipt.claim_token,
        receipt.execution_id,
        receipt.cleanup_report_sha256,
        receipt.encoded,
    )

    def discard(reference: weakref.ReferenceType[_SandboxCleanupVerificationReceipt]) -> None:
        with _SANDBOX_CLEANUP_VERIFICATION_RECEIPTS_LOCK:
            current = _SANDBOX_CLEANUP_VERIFICATION_RECEIPTS.get(key)
            if current is not None and current[0] is reference:
                _SANDBOX_CLEANUP_VERIFICATION_RECEIPTS.pop(key, None)

    reference = weakref.ref(receipt, discard)
    with _SANDBOX_CLEANUP_VERIFICATION_RECEIPTS_LOCK:
        _SANDBOX_CLEANUP_VERIFICATION_RECEIPTS[key] = (reference, fields)


def _sandbox_cleanup_verification_receipt_is_self_consistent(receipt: Any) -> bool:
    if type(receipt) is not _SandboxCleanupVerificationReceipt:
        return False
    with _SANDBOX_CLEANUP_VERIFICATION_RECEIPTS_LOCK:
        registered = _SANDBOX_CLEANUP_VERIFICATION_RECEIPTS.get(id(receipt))
        if registered is None or registered[0]() is not receipt:
            return False
        expected = registered[1]
    return (
        receipt.attempt_id,
        receipt.claim_token,
        receipt.execution_id,
        receipt.cleanup_report_sha256,
        receipt.encoded,
    ) == expected and _DIGEST.fullmatch(receipt.cleanup_report_sha256) is not None


def _register_sandbox_cleanup_recovery_receipt(
    receipt: _SandboxCleanupRecoveryReceipt,
) -> None:
    key = id(receipt)
    fields = (
        receipt.attempt_id,
        receipt.claim_token,
        receipt.execution_id,
        receipt.launch_submission_id,
        receipt.launch_submission_digest,
        receipt.reaper_epoch,
        receipt.encoded,
    )

    def discard(reference: weakref.ReferenceType[_SandboxCleanupRecoveryReceipt]) -> None:
        with _SANDBOX_CLEANUP_RECOVERY_RECEIPTS_LOCK:
            current = _SANDBOX_CLEANUP_RECOVERY_RECEIPTS.get(key)
            if current is not None and current[0] is reference:
                _SANDBOX_CLEANUP_RECOVERY_RECEIPTS.pop(key, None)

    reference = weakref.ref(receipt, discard)
    with _SANDBOX_CLEANUP_RECOVERY_RECEIPTS_LOCK:
        _SANDBOX_CLEANUP_RECOVERY_RECEIPTS[key] = (reference, fields)


def _sandbox_cleanup_recovery_receipt_is_self_consistent(receipt: Any) -> bool:
    if type(receipt) is not _SandboxCleanupRecoveryReceipt:
        return False
    with _SANDBOX_CLEANUP_RECOVERY_RECEIPTS_LOCK:
        registered = _SANDBOX_CLEANUP_RECOVERY_RECEIPTS.get(id(receipt))
        if registered is None or registered[0]() is not receipt:
            return False
        expected = registered[1]
    actual = (
        receipt.attempt_id,
        receipt.claim_token,
        receipt.execution_id,
        receipt.launch_submission_id,
        receipt.launch_submission_digest,
        receipt.reaper_epoch,
        receipt.encoded,
    )
    return (
        actual == expected
        and type(receipt.claim_token) is int
        and receipt.claim_token > 0
        and type(receipt.reaper_epoch) is int
        and receipt.reaper_epoch > 0
        and re.fullmatch(r"[0-9a-f]{32}", receipt.launch_submission_id) is not None
        and _DIGEST.fullmatch(receipt.launch_submission_digest) is not None
        and isinstance(receipt.encoded, str)
        and bool(receipt.encoded)
    )


_SANDBOX_LAUNCH_DRIVER_START_INTENTS: dict[
    int,
    tuple[
        weakref.ReferenceType[_SandboxLaunchDriverStartIntent],
        tuple[str, int, str, str, str, str],
    ],
] = {}
_SANDBOX_LAUNCH_DRIVER_START_INTENTS_LOCK = threading.Lock()


def _register_sandbox_launch_driver_start_intent(
    intent: _SandboxLaunchDriverStartIntent,
) -> None:
    key = id(intent)
    fields = (
        intent.attempt_id,
        intent.claim_token,
        intent.execution_id,
        intent.start_id,
        intent.start_digest,
        intent.service_unit,
    )

    def discard(reference: weakref.ReferenceType[_SandboxLaunchDriverStartIntent]) -> None:
        with _SANDBOX_LAUNCH_DRIVER_START_INTENTS_LOCK:
            current = _SANDBOX_LAUNCH_DRIVER_START_INTENTS.get(key)
            if current is not None and current[0] is reference:
                _SANDBOX_LAUNCH_DRIVER_START_INTENTS.pop(key, None)

    reference = weakref.ref(intent, discard)
    with _SANDBOX_LAUNCH_DRIVER_START_INTENTS_LOCK:
        _SANDBOX_LAUNCH_DRIVER_START_INTENTS[key] = (reference, fields)


def _sandbox_launch_driver_start_intent_is_self_consistent(
    intent: Any,
    *,
    attempt_id: str,
    claim_token: int,
    execution_id: str,
    start_digest: str,
    service_unit: str,
) -> bool:
    if type(intent) is not _SandboxLaunchDriverStartIntent:
        return False
    expected = (
        attempt_id,
        claim_token,
        execution_id,
        intent.start_id,
        start_digest,
        service_unit,
    )
    with _SANDBOX_LAUNCH_DRIVER_START_INTENTS_LOCK:
        registered = _SANDBOX_LAUNCH_DRIVER_START_INTENTS.get(id(intent))
        return registered is not None and registered[0]() is intent and registered[1] == expected


_SANDBOX_LAUNCH_SUBMISSIONS: dict[
    int, tuple[weakref.ReferenceType[_SandboxLaunchSubmission], tuple[str, int, str, str, str]]
] = {}
_SANDBOX_LAUNCH_SUBMISSIONS_LOCK = threading.Lock()


def _register_sandbox_launch_submission(
    submission: _SandboxLaunchSubmission,
) -> None:
    key = id(submission)
    fields = (
        submission.attempt_id,
        submission.claim_token,
        submission.execution_id,
        submission.submission_id,
        submission.submission_digest,
    )

    def discard(reference: weakref.ReferenceType[_SandboxLaunchSubmission]) -> None:
        with _SANDBOX_LAUNCH_SUBMISSIONS_LOCK:
            current = _SANDBOX_LAUNCH_SUBMISSIONS.get(key)
            if current is not None and current[0] is reference:
                _SANDBOX_LAUNCH_SUBMISSIONS.pop(key, None)

    reference = weakref.ref(submission, discard)
    with _SANDBOX_LAUNCH_SUBMISSIONS_LOCK:
        _SANDBOX_LAUNCH_SUBMISSIONS[key] = (reference, fields)


def _sandbox_launch_submission_is_self_consistent(
    submission: Any,
    *,
    attempt_id: str,
    claim_token: int,
    execution_id: str,
    submission_digest: str,
) -> bool:
    if type(submission) is not _SandboxLaunchSubmission:
        return False
    expected = (
        attempt_id,
        claim_token,
        execution_id,
        submission.submission_id,
        submission_digest,
    )
    with _SANDBOX_LAUNCH_SUBMISSIONS_LOCK:
        registered = _SANDBOX_LAUNCH_SUBMISSIONS.get(id(submission))
        return (
            registered is not None and registered[0]() is submission and registered[1] == expected
        )


def _sandbox_launch_submission_digest(row: Any, target: _RuncLaunchTarget) -> str:
    """Bind the one-use launch latch to runc and any exact provider-proxy artifact."""

    if type(target) is not _RuncLaunchTarget or target.launch_mode != "private_bundle":
        raise SupervisorError(
            "sandbox_execution_launch_target_mismatch",
            "launch submission requires the pinned private-bundle runc target",
        )
    expected_paths = (
        (target.bundle_path, row["bundle_path"]),
        (target.bundle_device, row["bundle_root_dev"]),
        (target.bundle_inode, row["bundle_root_ino"]),
        (target.rootfs_path, str(Path(row["bundle_path"]) / "rootfs")),
        (target.rootfs_sha256, row["rootfs_digest"]),
        (target.rootfs_closure_sha256, row["rootfs_closure_digest"]),
        (target.state_path, row["state_path"]),
        (target.state_device, row["state_root_dev"]),
        (target.state_inode, row["state_root_ino"]),
        (target.workspace_path, row["workspace_root_path"]),
        (target.workspace_device, row["workspace_root_dev"]),
        (target.workspace_inode, row["workspace_root_ino"]),
        (target.container_id, row["container_id"]),
        (target.runc_executable_sha256, row["runc_executable_digest"]),
    )
    if (
        any(actual != expected for actual, expected in expected_paths)
        or target.pid_file_path is None
        or Path(target.pid_file_path).parent != Path(row["state_path"])
        or not isinstance(target.config_sha256, str)
        or _DIGEST.fullmatch(target.config_sha256) is None
        or not isinstance(target.argv, tuple)
        or any(not isinstance(value, str) or not value for value in target.argv)
        or any(
            type(value) is not int or value <= 0
            for value in (
                target.memory_limit_bytes,
                target.cpu_quota,
                target.cpu_period,
                target.pids_limit,
            )
        )
    ):
        raise SupervisorError(
            "sandbox_execution_launch_target_mismatch",
            "pre-runc target does not match the exact durable reservation",
        )
    target_fields = {
        name: (list(value) if name == "argv" else value)
        for name, value in ((name, getattr(target, name)) for name in target.__dataclass_fields__)
    }
    provider_proxy_artifact_json = _sandbox_provider_proxy_artifact_json_from_row(row)
    if not _sandbox_provider_proxy_artifact_is_self_consistent(row, provider_proxy_artifact_json):
        raise SupervisorError(
            "sandbox_provider_proxy_artifact_invalid",
            "launch submission requires an exact attempt-bound provider proxy artifact identity",
        )
    material = {
        "version": 1,
        "attempt_id": row["attempt_id"],
        "claim_token": row["claim_token"],
        "execution_id": row["execution_id"],
        "target": target_fields,
        "provider_proxy_artifact_sha256": hashlib.sha256(
            provider_proxy_artifact_json.encode("utf-8")
        ).hexdigest(),
    }
    return hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()


def _sandbox_provider_proxy_artifact_json_from_row(row: Any) -> str:
    try:
        encoded = row["provider_proxy_artifact_json"]
    except (IndexError, KeyError, TypeError):
        encoded = "{}"
    return encoded if isinstance(encoded, str) else ""


def _sandbox_provider_proxy_artifact_json(
    row: Any, observed_identity: dict[str, int] | None
) -> str:
    """Encode the exact attempt-local directory and socket identities before runc."""

    if observed_identity is None:
        return "{}"
    if type(observed_identity) is not dict or set(observed_identity) != {
        "directory_device",
        "directory_inode",
        "socket_device",
        "socket_inode",
    }:
        raise SupervisorError(
            "sandbox_provider_proxy_artifact_invalid", "provider proxy inode identity is incomplete"
        )
    values = tuple(observed_identity.values())
    if any(type(value) is not int or value < 0 for value in values) or any(
        observed_identity[name] == 0 for name in ("directory_inode", "socket_inode")
    ):
        raise SupervisorError(
            "sandbox_provider_proxy_artifact_invalid", "provider proxy inode identity is invalid"
        )
    from . import sandbox_monitor_lifecycle

    identity = (row["attempt_id"], row["claim_token"], row["execution_id"])
    directory, socket_path = sandbox_monitor_lifecycle.sandbox_provider_proxy_control_paths(
        state_path=row["state_path"], expected_identity=identity
    )
    if (
        not directory.is_absolute()
        or str(directory) != os.path.normpath(str(directory))
        or socket_path.parent != directory
        or socket_path.name != "provider.sock"
        or len(os.fsencode(socket_path)) >= 103
    ):
        raise SupervisorError(
            "sandbox_provider_proxy_artifact_invalid", "provider proxy path is noncanonical"
        )
    return canonical_json(
        {
            "version": 1,
            "attempt_id": row["attempt_id"],
            "claim_token": row["claim_token"],
            "execution_id": row["execution_id"],
            "state_root": {
                "path": row["state_path"],
                "device": row["state_root_dev"],
                "inode": row["state_root_ino"],
            },
            "directory": {
                "path": str(directory),
                "device": observed_identity["directory_device"],
                "inode": observed_identity["directory_inode"],
            },
            "socket": {
                "path": str(socket_path),
                "device": observed_identity["socket_device"],
                "inode": observed_identity["socket_inode"],
            },
        }
    )


def _sandbox_provider_proxy_artifact_is_self_consistent(
    row: Any, encoded: str | None = None
) -> bool:
    """Check the durable proxy identity against the exact attempt and state root."""

    encoded = _sandbox_provider_proxy_artifact_json_from_row(row) if encoded is None else encoded
    if encoded == "{}":
        return True
    if (
        not isinstance(encoded, str)
        or not encoded
        or len(encoded.encode("utf-8", errors="ignore")) > 16 * 1024
    ):
        return False
    try:
        candidate = json.loads(encoded)
        if not isinstance(candidate, dict) or set(candidate) != {
            "version",
            "attempt_id",
            "claim_token",
            "execution_id",
            "state_root",
            "directory",
            "socket",
        }:
            return False
        if (
            type(candidate.get("version")) is not int
            or candidate["version"] != 1
            or candidate.get("attempt_id") != row["attempt_id"]
            or type(candidate.get("claim_token")) is not int
            or candidate.get("claim_token") != row["claim_token"]
            or candidate.get("execution_id") != row["execution_id"]
        ):
            return False
        state_root = candidate.get("state_root")
        directory = candidate.get("directory")
        socket_path = candidate.get("socket")
        if (
            not isinstance(state_root, dict)
            or set(state_root) != {"path", "device", "inode"}
            or state_root
            != {
                "path": row["state_path"],
                "device": row["state_root_dev"],
                "inode": row["state_root_ino"],
            }
            or not isinstance(directory, dict)
            or set(directory) != {"path", "device", "inode"}
            or not isinstance(socket_path, dict)
            or set(socket_path) != {"path", "device", "inode"}
        ):
            return False
        identity = {
            "directory_device": directory.get("device"),
            "directory_inode": directory.get("inode"),
            "socket_device": socket_path.get("device"),
            "socket_inode": socket_path.get("inode"),
        }
        if any(type(value) is not int for value in identity.values()):
            return False
        expected = _sandbox_provider_proxy_artifact_json(row, identity)
        return canonical_json(candidate) == encoded == expected
    except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError, SupervisorError):
        return False


def _sandbox_container_id(attempt_id: str, claim_token: int, execution_id: str) -> str:
    """Derive a runtime ID from the full fenced execution identity.

    The digest suffix avoids using a short execution-ID prefix as the only
    discriminator between different attempts in a shared runc state root.
    """

    identity = canonical_json(
        {
            "attempt_id": attempt_id,
            "claim_token": claim_token,
            "execution_id": execution_id,
        }
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return f"acp-{digest[:60]}"


def _sandbox_launch_driver_service_unit(execution_id: str) -> str:
    """Return the only launch-driver unit name authorized for an execution."""

    if not isinstance(execution_id, str) or not _COMPONENT.fullmatch(execution_id):
        raise SupervisorError("sandbox_execution_invalid", "execution ID is invalid")
    return f"acp-launch-driver-{execution_id}.service"


def _sandbox_launch_driver_start_digest(
    row: Any,
    service_unit: str,
    *,
    launch_request_digest: str,
) -> str:
    """Bind a start intent to the exact tuple, service, roots, and launch request."""

    if (
        not isinstance(launch_request_digest, str)
        or _DIGEST.fullmatch(launch_request_digest) is None
    ):
        raise SupervisorError(
            "sandbox_launch_driver_request_invalid", "launch-driver request digest is invalid"
        )

    payload = {
        "attempt_id": row["attempt_id"],
        "claim_token": row["claim_token"],
        "execution_id": row["execution_id"],
        "service_unit": service_unit,
        "launch_request_digest": launch_request_digest,
        "container_id": row["container_id"],
        "bundle_digest": row["bundle_digest"],
        "rootfs_digest": row["rootfs_digest"],
        "rootfs_closure_digest": row["rootfs_closure_digest"],
        "runc_executable_digest": row["runc_executable_digest"],
        "bundle": {
            "path": row["bundle_path"],
            "device": row["bundle_root_dev"],
            "inode": row["bundle_root_ino"],
        },
        "state": {
            "path": row["state_path"],
            "device": row["state_root_dev"],
            "inode": row["state_root_ino"],
        },
        "workspace": {
            "path": row["workspace_root_path"],
            "device": row["workspace_root_dev"],
            "inode": row["workspace_root_ino"],
        },
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _sandbox_execution_launch_stop_reason(
    connection: sqlite3.Connection, row: sqlite3.Row | dict[str, Any]
) -> str | None:
    """Read the immutable pre-init stop intent for this exact execution."""

    event = connection.execute(
        """
        SELECT json_extract(payload_json, '$.stop_reason') AS stop_reason
        FROM events
        WHERE event_type = 'sandbox.execution_stop_requested'
          AND json_extract(payload_json, '$.phase') = 'launched'
          AND json_extract(payload_json, '$.attempt_id') = ?
          AND json_extract(payload_json, '$.claim_token') = ?
          AND json_extract(payload_json, '$.execution_id') = ?
        ORDER BY sequence
        LIMIT 1
        """,
        (row["attempt_id"], row["claim_token"], row["execution_id"]),
    ).fetchone()
    return event["stop_reason"] if event is not None else None


def _sandbox_launch_plan_material(execution: Any, target: Any) -> dict[str, Any]:
    """Canonical, durable projection of a registered runc handle and reservation."""

    argv = list(target.argv)
    argv_digest = hashlib.sha256(canonical_json(argv).encode("utf-8")).hexdigest()
    return {
        "version": 6,
        "reservation": {
            "bundle_digest_semantics": _BUNDLE_DIGEST_SEMANTICS,
            **{
                key: execution[key]
                for key in (
                    "attempt_id",
                    "claim_token",
                    "execution_id",
                    "backend",
                    "container_id",
                    "bundle_digest",
                    "rootfs_digest",
                    "rootfs_closure_digest",
                    "runc_executable_digest",
                    "runtime_version",
                    "oci_version",
                    "bundle_path",
                    "state_path",
                    "workspace_binding_version",
                    "baseline_manifest_digest",
                    "workspace_root_path",
                    "workspace_root_dev",
                    "workspace_root_ino",
                    "private_path_binding_version",
                    "execution_root_dev",
                    "execution_root_ino",
                    "bundle_root_dev",
                    "bundle_root_ino",
                    "state_root_dev",
                    "state_root_ino",
                )
            },
        },
        "launch": {
            "mode": target.launch_mode,
            "runc_executable_path": target.runc_executable_path,
            "runc_executable_sha256": target.runc_executable_sha256,
            "config_sha256": target.config_sha256,
            "argv": argv,
            "argv_sha256": argv_digest,
            "container_id": target.container_id,
            "bundle": {
                "path": target.bundle_path,
                "device": target.bundle_device,
                "inode": target.bundle_inode,
            },
            "rootfs": {
                "path": target.rootfs_path,
                "device": target.rootfs_device,
                "inode": target.rootfs_inode,
                "sha256": target.rootfs_sha256,
                "closure_sha256": target.rootfs_closure_sha256,
                "snapshot": {
                    "device": target.rootfs_snapshot_device,
                    "inode": target.rootfs_snapshot_inode,
                    "sha256": target.rootfs_snapshot_sha256,
                    "closure_sha256": target.rootfs_snapshot_closure_sha256,
                    "entry_count": target.rootfs_snapshot_entry_count,
                    "bytes": target.rootfs_snapshot_bytes,
                },
            },
            "state": {
                "path": target.state_path,
                "device": target.state_device,
                "inode": target.state_inode,
            },
            "workspace": {
                "path": target.workspace_path,
                "device": target.workspace_device,
                "inode": target.workspace_inode,
            },
            "pid_file_path": target.pid_file_path,
            "resource_limits": {
                "memory_max_bytes": target.memory_limit_bytes,
                "cpu_quota": target.cpu_quota,
                "cpu_period": target.cpu_period,
                "pids_max": target.pids_limit,
            },
        },
    }


def _sandbox_reservation_bundle_digest(execution: Any) -> str:
    """Hash host-derived reservation identity, not caller-asserted bundle bytes.

    The launch config does not exist when the reservation is inserted. This
    versioned digest therefore commits only the immutable execution identity and
    configured runtime pins. The exact OCI config and argv are bound separately
    by the later launch-plan receipt; this value is never treated as their hash.
    """

    material = {
        "version": 1,
        "kind": _BUNDLE_DIGEST_SEMANTICS,
        **{
            key: execution[key]
            for key in (
                "attempt_id",
                "claim_token",
                "execution_id",
                "backend",
                "container_id",
                "rootfs_digest",
                "rootfs_closure_digest",
                "runc_executable_digest",
                "runtime_version",
                "oci_version",
                "bundle_path",
                "state_path",
            )
        },
    }
    return hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()


def _sandbox_v5_cgroup_topology_is_self_consistent(row: Any) -> bool:
    """Require the trusted monitor to survive an exact worker-slice stop."""

    try:
        monitor = PurePosixPath(row["wrapper_cgroup_path"])
        attempt_slice = PurePosixPath(row["attempt_slice_cgroup_path"])
        scope = PurePosixPath(row["cgroup_path"])
        paths = (monitor, attempt_slice, scope)
        return (
            all(path.is_absolute() and path.as_posix() == str(path) for path in paths)
            and all(part not in {".", ".."} for path in paths for part in path.parts)
            and monitor.name == row["wrapper_unit"]
            and attempt_slice.name == row["attempt_slice_unit"]
            and scope.name == row["scope_unit"]
            and row["attempt_slice_unit"] == _oci_worker_systemd_slice(row["container_id"])
            and not monitor.is_relative_to(attempt_slice)
            and not attempt_slice.is_relative_to(monitor)
            and not any(_ATTEMPT_SLICE_COMPONENT.fullmatch(part) for part in monitor.parts)
            and scope.parent == attempt_slice
        )
    except (KeyError, TypeError, ValueError, SupervisorError):
        return False


def _sandbox_v6_monitor_identity_is_self_consistent(row: Any) -> bool:
    """Require the service name to be derived from the full execution fence."""

    try:
        return _sandbox_v5_cgroup_topology_is_self_consistent(row) and row[
            "wrapper_unit"
        ] == _sandbox_monitor_service_unit(
            row["attempt_id"], row["claim_token"], row["execution_id"]
        )
    except (KeyError, TypeError, ValueError, SupervisorError):
        return False


def _sandbox_launch_plan_binding_is_self_consistent(row: Any) -> bool:
    """Verify the durable plan digest and every reservation identity it commits."""

    try:
        if (
            row["launch_plan_required"] != 1
            or row["launch_plan_binding_version"] != 1
            or _DIGEST.fullmatch(row["launch_config_digest"] or "") is None
            or _DIGEST.fullmatch(row["launch_argv_digest"] or "") is None
            or _DIGEST.fullmatch(row["launch_plan_digest"] or "") is None
        ):
            return False
        raw_plan = row["launch_plan_json"]
        plan = json.loads(raw_plan)
        if not isinstance(plan, dict) or canonical_json(plan) != raw_plan:
            return False
        if hashlib.sha256(raw_plan.encode("utf-8")).hexdigest() != row["launch_plan_digest"]:
            return False
        plan_version = plan.get("version")
        if type(plan_version) is not int or plan_version not in {1, 2, 3, 4, 5, 6}:
            return False
        reservation = plan.get("reservation")
        expected_reservation = {
            key: row[key]
            for key in (
                "attempt_id",
                "claim_token",
                "execution_id",
                "backend",
                "container_id",
                "bundle_digest",
                "rootfs_digest",
                "rootfs_closure_digest",
                "runc_executable_digest",
                "runtime_version",
                "oci_version",
                "bundle_path",
                "state_path",
                "workspace_binding_version",
                "baseline_manifest_digest",
                "workspace_root_path",
                "workspace_root_dev",
                "workspace_root_ino",
                "private_path_binding_version",
                "execution_root_dev",
                "execution_root_ino",
                "bundle_root_dev",
                "bundle_root_ino",
                "state_root_dev",
                "state_root_ino",
            )
        }
        if plan_version in {2, 3, 4, 5, 6}:
            if row["bundle_digest_semantics"] != _BUNDLE_DIGEST_SEMANTICS:
                return False
            if row["bundle_digest"] != _sandbox_reservation_bundle_digest(row):
                return False
            expected_reservation["bundle_digest_semantics"] = _BUNDLE_DIGEST_SEMANTICS
        elif row["bundle_digest_semantics"] != _LEGACY_BUNDLE_DIGEST_SEMANTICS:
            return False
        launch = plan.get("launch")
        if reservation != expected_reservation or not isinstance(launch, dict):
            return False
        if plan_version < 3:
            return False
        systemd_ownership = launch.get("systemd_ownership")
        expected_systemd_ownership = {
            "wrapper_control_group": row["wrapper_cgroup_path"],
            "attempt_slice_unit": row["attempt_slice_unit"],
            "attempt_slice_invocation_id": row["attempt_slice_invocation_id"],
            "attempt_slice_control_group": row["attempt_slice_cgroup_path"],
        }
        if plan_version >= 5:
            expected_systemd_ownership["monitor_placement"] = "outside_attempt_slice"
        if systemd_ownership != expected_systemd_ownership:
            return False
        if plan_version >= 5 and not _sandbox_v5_cgroup_topology_is_self_consistent(row):
            return False
        if plan_version >= 6 and not _sandbox_v6_monitor_identity_is_self_consistent(row):
            return False
        argv = launch.get("argv")
        bundle = launch.get("bundle")
        rootfs = launch.get("rootfs")
        state = launch.get("state")
        workspace = launch.get("workspace")
        if not all(isinstance(value, dict) for value in (bundle, rootfs, state, workspace)):
            return False
        pid_file_path = launch.get("pid_file_path")
        snapshot = rootfs.get("snapshot")
        if not isinstance(pid_file_path, str) or not isinstance(snapshot, dict):
            return False
        resource_limits = launch.get("resource_limits")
        if plan_version >= 4 and (
            not isinstance(resource_limits, dict)
            or set(resource_limits)
            != {
                "memory_max_bytes",
                "cpu_quota",
                "cpu_period",
                "pids_max",
            }
            or any(type(value) is not int or value <= 0 for value in resource_limits.values())
        ):
            return False
        argv_shape_matches = (
            isinstance(argv, list)
            and len(argv) == 13
            and all(isinstance(value, str) and value for value in argv)
            and argv[0] == launch.get("runc_executable_path")
            and argv[1] == "--root"
            and re.fullmatch(r"/proc/self/fd/[1-9][0-9]*", argv[2]) is not None
            and argv[3:6] == ["--systemd-cgroup", "run", "--bundle"]
            and re.fullmatch(r"/proc/self/fd/[1-9][0-9]*", argv[6]) is not None
            and argv[7] == "--pid-file"
            and argv[8] == f"{argv[2]}/{Path(pid_file_path).name}"
            and argv[9:12] == ["--preserve-fds", "1", "--keep"]
            and argv[12] == row["container_id"]
            and argv[2] != argv[6]
        )
        return (
            launch.get("mode") == "private_bundle"
            and launch.get("runc_executable_sha256") == row["runc_executable_digest"]
            and launch.get("container_id") == row["container_id"]
            and launch.get("config_sha256") == row["launch_config_digest"]
            and launch.get("argv_sha256") == row["launch_argv_digest"]
            and argv_shape_matches
            and hashlib.sha256(canonical_json(argv).encode("utf-8")).hexdigest()
            == row["launch_argv_digest"]
            and bundle
            == {
                "path": row["bundle_path"],
                "device": row["bundle_root_dev"],
                "inode": row["bundle_root_ino"],
            }
            and rootfs.get("path") == str(Path(row["bundle_path"]) / "rootfs")
            and rootfs.get("sha256") == row["rootfs_digest"]
            and rootfs.get("closure_sha256") == row["rootfs_closure_digest"]
            and snapshot.get("sha256") == row["rootfs_digest"]
            and snapshot.get("closure_sha256") == row["rootfs_closure_digest"]
            and state
            == {
                "path": row["state_path"],
                "device": row["state_root_dev"],
                "inode": row["state_root_ino"],
            }
            and workspace
            == {
                "path": row["workspace_root_path"],
                "device": row["workspace_root_dev"],
                "inode": row["workspace_root_ino"],
            }
            and Path(pid_file_path).parent == Path(row["state_path"])
        )
    except (IndexError, KeyError, TypeError, ValueError, UnicodeError):
        return False


_CLEANUP_OBSERVATIONS = {
    "runc_delete_exit_code": None,
    "runc_state_absent": None,
    "bundle_absent": None,
    "state_directory_absent": None,
    "wrapper_unit_absent": None,
    "scope_unit_absent": None,
    "cgroup_absent": None,
    "monitor_identity_absent": None,
    "runc_client_identity_absent": None,
    "container_init_identity_absent": None,
}
_PROCESS_IDENTITY = re.compile(r"linux:([1-9][0-9]{0,9}):([1-9][0-9]*)\Z")
_LEGACY_CLEANUP_OBSERVATIONS = {
    "runc_delete_exit_code": 0,
    "runc_state_absent": True,
    "bundle_absent": True,
    "state_directory_absent": True,
    "wrapper_unit_absent": True,
    "scope_unit_absent": True,
    "cgroup_absent": True,
    "monitor_identity_absent": True,
    "runc_client_identity_absent": True,
    "container_init_identity_absent": True,
}


def _sandbox_cleanup_report_base(row: Any, *, version: int) -> dict[str, Any]:
    return {
        "version": version,
        "verification_status": "unverified",
        "attempt_id": row["attempt_id"],
        "claim_token": row["claim_token"],
        "execution_id": row["execution_id"],
        "container_id": row["container_id"],
        "bundle_digest": row["bundle_digest"],
        "rootfs_digest": row["rootfs_digest"],
        "rootfs_closure_digest": row["rootfs_closure_digest"],
        "runc_executable_digest": row["runc_executable_digest"],
        "runtime_version": row["runtime_version"],
        "oci_version": row["oci_version"],
        "runc_exit_code": row["runc_exit_code"],
        "runc_exit_observed_by": (row["runc_exit_evidence_source"] or row["runc_exit_observed_by"]),
        "processes": {
            "monitor": {"pid": row["monitor_pid"], "identity": row["monitor_identity"]},
            "runc_client": {
                "pid": row["runc_client_pid"],
                "identity": row["runc_client_identity"],
            },
            "container_init": {"pid": row["init_pid"], "identity": row["init_identity"]},
        },
        "systemd": {
            "wrapper_unit": row["wrapper_unit"],
            "wrapper_invocation_id": row["wrapper_invocation_id"],
            "scope_unit": row["scope_unit"],
            "scope_invocation_id": row["scope_invocation_id"],
            "cgroup_path": row["cgroup_path"],
        },
        "paths": {"bundle": row["bundle_path"], "state": row["state_path"]},
        "observations": dict(_CLEANUP_OBSERVATIONS),
    }


def _sandbox_launch_submission_latch_is_self_consistent(row: Any) -> bool:
    return (
        isinstance(row["launch_submission_id"], str)
        and re.fullmatch(r"[0-9a-f]{32}", row["launch_submission_id"]) is not None
        and isinstance(row["launch_submission_digest"], str)
        and _DIGEST.fullmatch(row["launch_submission_digest"]) is not None
        and isinstance(row["launch_submission_at"], str)
        and bool(row["launch_submission_at"])
        and row["launch_plan_required"] == 1
        and _sandbox_launch_plan_binding_is_self_consistent(row)
        and isinstance(row["provider_proxy_artifact_json"], str)
        and _sandbox_provider_proxy_artifact_is_self_consistent(
            row, row["provider_proxy_artifact_json"]
        )
    )


def _sandbox_cleanup_recovery_report_is_self_consistent(row: Any, encoded: Any) -> bool:
    """Validate a restart-safe report before trusting it for final re-verification."""

    try:
        if not isinstance(encoded, str) or not encoded or len(encoded.encode("utf-8")) > 64 * 1024:
            return False
        candidate = json.loads(encoded)
        if canonical_json(candidate) != encoded or not isinstance(candidate, dict):
            return False
        recovery = candidate.get("recovery")
        expected_keys = {
            "version",
            "attempt_id",
            "claim_token",
            "execution_id",
            "launch_submission_id",
            "launch_submission_digest",
            "launch_submission_at",
            "provider_proxy_artifact_sha256",
            "state_root",
            "container_id",
            "runc_delete_action",
            "reaper_epoch",
            "recovered_at",
            "verifier",
            "observations",
        }
        if (
            not isinstance(recovery, dict)
            or set(recovery) != expected_keys
            or type(recovery.get("version")) is not int
            or recovery.get("version") != 1
            or recovery.get("attempt_id") != row["attempt_id"]
            or type(recovery.get("claim_token")) is not int
            or recovery["claim_token"] != row["claim_token"]
            or recovery.get("execution_id") != row["execution_id"]
            or not _sandbox_launch_submission_latch_is_self_consistent(row)
            or recovery.get("launch_submission_id") != row["launch_submission_id"]
            or _DIGEST.fullmatch(row["launch_submission_digest"] or "") is None
            or recovery.get("launch_submission_digest") != row["launch_submission_digest"]
            or not isinstance(row["launch_submission_at"], str)
            or not row["launch_submission_at"]
            or recovery.get("launch_submission_at") != row["launch_submission_at"]
            or not isinstance(row["provider_proxy_artifact_json"], str)
            or not _sandbox_provider_proxy_artifact_is_self_consistent(
                row, row["provider_proxy_artifact_json"]
            )
            or recovery.get("provider_proxy_artifact_sha256")
            != hashlib.sha256(row["provider_proxy_artifact_json"].encode("utf-8")).hexdigest()
            or recovery.get("state_root")
            != {
                "path": row["state_path"],
                "device": row["state_root_dev"],
                "inode": row["state_root_ino"],
            }
            or recovery.get("container_id") != row["container_id"]
            or row["phase"] not in {"exited", "cleanup_reported", "cleanup_verified"}
            or type(row["runc_exit_code"]) is not int
            or row["runc_exit_evidence_source"] != "runc_client_kernel_waitpid"
            or type(recovery.get("reaper_epoch")) is not int
            or recovery["reaper_epoch"] <= 0
            or not isinstance(recovery.get("recovered_at"), str)
            or not recovery["recovered_at"]
        ):
            return False
        verifier = recovery.get("verifier")
        if (
            not isinstance(verifier, dict)
            or set(verifier) != {"pid", "identity"}
            or type(verifier.get("pid")) is not int
            or verifier["pid"] <= 0
            or not isinstance(verifier.get("identity"), str)
        ):
            return False
        process_match = _PROCESS_IDENTITY.fullmatch(verifier["identity"])
        if process_match is None or int(process_match.group(1)) != verifier["pid"]:
            return False
        action = recovery.get("runc_delete_action")
        if action is not None:
            plan = json.loads(row["launch_plan_json"])
            launch = plan.get("launch") if isinstance(plan, dict) else None
            executable_path = (
                launch.get("runc_executable_path") if isinstance(launch, dict) else None
            )
            argv = [
                executable_path,
                "--root",
                row["state_path"],
                "delete",
                "--force",
                row["container_id"],
            ]
            if (
                not isinstance(executable_path, str)
                or not executable_path
                or not isinstance(action, dict)
                or set(action)
                != {
                    "attempt_id",
                    "claim_token",
                    "execution_id",
                    "executable_path",
                    "executable_digest",
                    "runtime_version",
                    "argv",
                    "argv_sha256",
                    "actor_pid",
                    "actor_identity",
                    "returncode",
                    "state_entry_absent",
                }
                or action.get("attempt_id") != row["attempt_id"]
                or type(action.get("claim_token")) is not int
                or action["claim_token"] != row["claim_token"]
                or action.get("execution_id") != row["execution_id"]
                or action.get("executable_path") != executable_path
                or action.get("executable_digest") != row["runc_executable_digest"]
                or action.get("runtime_version") != row["runtime_version"]
                or action.get("argv") != argv
                or action.get("argv_sha256")
                != hashlib.sha256(canonical_json(argv).encode("utf-8")).hexdigest()
                or type(action.get("actor_pid")) is not int
                or action["actor_pid"] != verifier["pid"]
                or action.get("actor_identity") != verifier["identity"]
                or type(action.get("returncode")) is not int
                or action["returncode"] != 0
                or action.get("state_entry_absent") is not True
            ):
                return False
        observations = recovery.get("observations")
        if (
            not isinstance(observations, dict)
            or set(observations) != {"runc_state_entry_absent", "units", "processes", "cgroups"}
            or observations.get("runc_state_entry_absent") is not True
        ):
            return False
        units = observations["units"]
        expected_units = {
            "monitor": (
                row["wrapper_unit"],
                row["wrapper_invocation_id"],
                row["wrapper_cgroup_path"],
                False,
            ),
            "launch_driver": (
                row["launch_driver_unit"],
                row["launch_driver_invocation_id"],
                row["launch_driver_cgroup_path"],
                False,
            ),
            "scope": (row["scope_unit"], row["scope_invocation_id"], row["cgroup_path"], False),
            "attempt_slice": (
                row["attempt_slice_unit"],
                row["attempt_slice_invocation_id"],
                row["attempt_slice_cgroup_path"],
                True,
            ),
        }
        if not isinstance(units, dict) or set(units) != set(expected_units):
            return False
        for name, (unit, invocation, cgroup, active_allowed) in expected_units.items():
            snapshot = units[name]
            if (
                not isinstance(snapshot, dict)
                or set(snapshot)
                != {
                    "id",
                    "load_state",
                    "active_state",
                    "invocation_id",
                    "control_group",
                    "main_pid",
                }
                or snapshot.get("load_state") not in {"loaded", "not-found"}
                or snapshot.get("active_state")
                not in (
                    {"inactive", "not-found", "active"}
                    if active_allowed
                    else {"inactive", "not-found", "failed"}
                )
                or snapshot.get("main_pid") != "0"
                or snapshot.get("id") not in {"", unit}
                or snapshot.get("invocation_id") not in {"", invocation}
                or snapshot.get("control_group") not in {"", cgroup}
                or (
                    snapshot.get("active_state") == "failed"
                    and snapshot.get("invocation_id") != invocation
                )
            ):
                return False
        expected_processes = {
            "monitor_identity_absent": (row["monitor_pid"], row["monitor_identity"]),
            "launch_driver_identity_absent": (
                row["launch_driver_pid"],
                row["launch_driver_identity"],
            ),
            "runc_client_identity_absent": (row["runc_client_pid"], row["runc_client_identity"]),
            "container_init_identity_absent": (row["init_pid"], row["init_identity"]),
        }
        processes = observations["processes"]
        if not isinstance(processes, dict) or set(processes) != set(expected_processes):
            return False
        for name, (pid, identity) in expected_processes.items():
            proof = processes[name]
            if (
                not isinstance(proof, dict)
                or set(proof) != {"pid", "identity", "absent"}
                or type(proof.get("pid")) is not int
                or (proof["pid"], proof.get("identity")) != (pid, identity)
                or proof.get("absent") is not True
            ):
                return False
        expected_cgroups = {
            row["wrapper_cgroup_path"],
            row["launch_driver_cgroup_path"],
            row["cgroup_path"],
            row["attempt_slice_cgroup_path"],
        }
        cgroups = observations["cgroups"]
        if (
            not isinstance(cgroups, dict)
            or set(cgroups) != expected_cgroups
            or any(value is not True for value in cgroups.values())
        ):
            return False
        expected = _sandbox_cleanup_report_base(row, version=4)
        expected["recovery"] = recovery
        return canonical_json(candidate) == canonical_json(expected)
    except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError):
        return False


def _sandbox_cleanup_action_payload_for_row(row: Any, *, executable_path: str) -> dict[str, Any]:
    argv = [
        executable_path,
        "--root",
        row["state_path"],
        "delete",
        "--force",
        row["container_id"],
    ]
    return {
        "version": 1,
        "operation": "runc-delete-force",
        "argv": argv,
        "argv_sha256": hashlib.sha256(canonical_json(argv).encode("utf-8")).hexdigest(),
        "executable_sha256": row["runc_executable_digest"],
        "runtime_version": row["runtime_version"],
        "state_root": {
            "path": row["state_path"],
            "device": row["state_root_dev"],
            "inode": row["state_root_ino"],
        },
        "actor": {
            "pid": row["launch_driver_pid"],
            "identity": row["launch_driver_identity"],
            "unit": row["launch_driver_unit"],
            "invocation_id": row["launch_driver_invocation_id"],
            "control_group": row["launch_driver_cgroup_path"],
        },
        "returncode": 0,
        "waited_by": "pinned_runtime_guardian",
        "state_entry_absent_immediately_after_delete": True,
    }


def _private_directory_identity(path: Path, label: str) -> tuple[int, int]:
    """Capture one private directory inode without accepting a symlink root."""

    try:
        observed = path.lstat()
    except OSError as error:
        raise SupervisorError(
            "sandbox_private_path_invalid", f"{label} is unavailable for identity binding"
        ) from error
    if not stat.S_ISDIR(observed.st_mode):
        raise SupervisorError("sandbox_private_path_invalid", f"{label} must be a real directory")
    _verify_directory_identity(
        path,
        expected_device=observed.st_dev,
        expected_inode=observed.st_ino,
    )
    return observed.st_dev, observed.st_ino


def _require_private_path_absent(path: Path, label: str) -> None:
    """Treat only a positively missing private path as cleanup evidence."""

    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise SupervisorError(
            "sandbox_private_path_invalid", f"{label} absence could not be verified"
        ) from error
    raise SupervisorError(
        "sandbox_private_path_conflict", f"{label} remains after cleanup verification"
    )


def _sandbox_execution_gate_identity(row: Any) -> tuple[str, int, int]:
    """Return the persistent execution-root inode used by every lifecycle fence."""

    bundle_path = row["bundle_path"]
    execution_root = Path(bundle_path).parent if isinstance(bundle_path, str) else None
    device = row["execution_root_dev"]
    inode = row["execution_root_ino"]
    if (
        execution_root is None
        or not execution_root.is_absolute()
        or Path(bundle_path) != execution_root / "bundle"
        or type(device) is not int
        or device < 0
        or type(inode) is not int
        or inode <= 0
    ):
        raise SupervisorError(
            "sandbox_execution_gate_identity_mismatch",
            "durable execution-root identity is missing or noncanonical; lifecycle fence retained",
        )
    return str(execution_root), device, inode


def _sandbox_execution_cleanup_is_verified(connection: Any, attempt_id: str) -> bool:
    """Old/direct attempts have no journal; journaled attempts require verification."""

    row = connection.execute(
        "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
    ).fetchone()
    return row is None or (
        row["phase"] == "cleanup_verified"
        and _sandbox_launch_plan_binding_is_self_consistent(row)
        and _sandbox_cleanup_verification_is_self_consistent(row)
    )


def _sandbox_cleanup_verification_is_self_consistent(row: Any) -> bool:
    """Validate persisted verifier evidence after the issuing process exits."""

    from .sandbox_cleanup_verifier import _sandbox_cleanup_verification_json_is_self_consistent

    return _sandbox_cleanup_verification_json_is_self_consistent(
        row, row["cleanup_verification_json"]
    )


def _require_sandbox_execution_result_eligible(connection: Any, attempt_id: str) -> None:
    """Fence result import/submission until a journaled worker exited cleanly."""

    row = connection.execute(
        "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
    ).fetchone()
    if row is not None and not (
        row["phase"] == "cleanup_verified"
        and row["runc_exit_code"] == 0
        and _sandbox_launch_plan_binding_is_self_consistent(row)
        and _sandbox_cleanup_verification_is_self_consistent(row)
    ):
        raise SupervisorError(
            "sandbox_result_unverified",
            "sandbox result requires successful runc exit and independently verified cleanup",
        )


def _require_direct_worker_result_source(connection: Any, attempt_id: str) -> None:
    """Keep a journaled sandbox out of the direct-worker PID/receipt protocol.

    This remains a separate fence even after cleanup verification exists: a
    sandbox execution is identified by its execution journal, not by aliasing
    its monitor, runc client, or container-init PID into ``attempts.pid``.
    """

    row = connection.execute(
        "SELECT 1 FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
    ).fetchone()
    if row is not None:
        raise SupervisorError(
            "sandbox_result_import_route_required",
            "journaled sandbox results cannot use the direct-worker PID receipt route",
        )


class SandboxExecutionJournalMixin:
    """Private persistence API; no worker-launch or user-facing route is wired yet."""

    @staticmethod
    def _sandbox_text(value: Any, field: str, *, limit: int = 256) -> str:
        if not isinstance(value, str):
            raise SupervisorError("sandbox_execution_invalid", f"{field} must be text")
        normalized = value.strip()
        try:
            encoded = normalized.encode("utf-8")
        except UnicodeEncodeError:
            raise SupervisorError(
                "sandbox_execution_invalid", f"{field} is not valid UTF-8"
            ) from None
        if (
            not normalized
            or len(encoded) > limit
            or any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in normalized)
        ):
            raise SupervisorError("sandbox_execution_invalid", f"{field} is invalid")
        return normalized

    @staticmethod
    def _sandbox_pid(value: Any, field: str) -> int:
        if type(value) is not int or not 1 <= value <= 2**31 - 1:
            raise SupervisorError("sandbox_execution_invalid", f"{field} is not a valid PID")
        return value

    @classmethod
    def _sandbox_process_identity(cls, value: Any, field: str) -> str:
        return cls._sandbox_text(value, field, limit=256)

    @classmethod
    def _sandbox_systemd_unit(cls, value: Any, field: str, suffix: str) -> str:
        value = cls._sandbox_text(value, field, limit=255)
        if _SYSTEMD_UNIT.fullmatch(value) is None or not value.endswith(suffix):
            raise SupervisorError("sandbox_execution_invalid", f"{field} is not a systemd unit")
        return value

    @classmethod
    def _sandbox_invocation_id(cls, value: Any, field: str) -> str:
        value = cls._sandbox_text(value, field, limit=32)
        if _INVOCATION_ID.fullmatch(value) is None:
            raise SupervisorError("sandbox_execution_invalid", f"{field} is invalid")
        return value

    @staticmethod
    def _sandbox_validate_attempt_id(attempt_id: Any) -> str:
        if not isinstance(attempt_id, str) or _COMPONENT.fullmatch(attempt_id) is None:
            raise SupervisorError("sandbox_execution_invalid", "attempt_id is not a safe component")
        return attempt_id

    def _sandbox_execution_reserve(
        self,
        attempt_id: str,
        claim_token: int,
        *,
        rootfs_digest: str,
        rootfs_closure_digest: str,
        runc_executable_digest: str,
        runtime_version: str,
        oci_version: str,
        credential: str | None = None,
    ) -> dict[str, Any]:
        """Reserve one journal row before launch; paths and container ID are host-derived."""

        attempt_id = self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        if not isinstance(rootfs_digest, str) or _DIGEST.fullmatch(rootfs_digest) is None:
            raise SupervisorError("sandbox_execution_invalid", "rootfs digest must be SHA-256")
        if (
            not isinstance(rootfs_closure_digest, str)
            or _DIGEST.fullmatch(rootfs_closure_digest) is None
        ):
            raise SupervisorError(
                "sandbox_execution_invalid", "rootfs closure digest must be SHA-256"
            )
        if (
            not isinstance(runc_executable_digest, str)
            or _DIGEST.fullmatch(runc_executable_digest) is None
        ):
            raise SupervisorError(
                "sandbox_execution_invalid", "trusted runc executable digest must be SHA-256"
            )
        runtime_version = self._sandbox_text(runtime_version, "runtime_version", limit=128)
        oci_version = self._sandbox_text(oci_version, "oci_version", limit=32)
        if _OCI_VERSION.fullmatch(oci_version) is None:
            raise SupervisorError("sandbox_execution_invalid", "OCI version must be numeric semver")

        config = self.config
        rootfs_pin = config.oci_rootfs_pin
        runc_pin = config.oci_runc_executable
        configured_runtime_version = config.oci_runc_version
        if (
            rootfs_pin is None
            or runc_pin is None
            or not isinstance(configured_runtime_version, str)
            or not configured_runtime_version
        ):
            raise SupervisorError(
                "sandbox_execution_pin_unavailable",
                "sandbox reservation requires configured rootfs and runc pins",
            )

        # Hash-shaped caller claims are not evidence. Revalidate the process-local
        # sealed handles, then require every persisted runtime identity to match
        # those exact configured values before the reservation can be journaled.
        from . import oci_worker

        try:
            oci_worker._verify_trusted_rootfs(rootfs_pin)
            oci_worker._verify_trusted_runc_executable(runc_pin)
        except SupervisorError as error:
            raise SupervisorError(
                "sandbox_execution_pin_invalid",
                "configured rootfs or runc pin could not be verified",
            ) from error
        if (
            rootfs_digest != rootfs_pin.sha256
            or rootfs_closure_digest != rootfs_pin.closure_sha256
            or runc_executable_digest != runc_pin.sha256
            or runtime_version != configured_runtime_version
        ):
            raise SupervisorError(
                "sandbox_execution_pin_mismatch",
                "reservation runtime identity does not match configured OCI pins",
            )

        execution_id = str(uuid.uuid4())
        container_id = _sandbox_container_id(attempt_id, claim_token, execution_id)
        execution_root = (
            self.state_dir.resolve() / "sandbox-executions" / f"{attempt_id}-{claim_token}"
        )
        bundle_path = str(execution_root / "bundle")
        state_path = str(execution_root / "state")
        bundle_digest = _sandbox_reservation_bundle_digest(
            {
                "attempt_id": attempt_id,
                "claim_token": claim_token,
                "execution_id": execution_id,
                "backend": "oci-runc",
                "container_id": container_id,
                "rootfs_digest": rootfs_digest,
                "rootfs_closure_digest": rootfs_closure_digest,
                "runc_executable_digest": runc_executable_digest,
                "runtime_version": runtime_version,
                "oci_version": oci_version,
                "bundle_path": bundle_path,
                "state_path": state_path,
            }
        )
        stamp = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            if attempt["status"] != "working":
                raise SupervisorError(
                    "claim_inactive", "sandbox execution requires a fully provisioned attempt"
                )
            self._authenticate_attempt(connection, attempt, credential)
            if attempt["pid"] is not None or attempt["launch_owner_pid"] is not None:
                raise SupervisorError(
                    "worker_already_running",
                    "sandbox execution cannot be reserved beside a registered direct worker",
                )
            try:
                with _authorize_sandbox_reservation_write(
                    connection,
                    attempt_id,
                    claim_token,
                    execution_id,
                    bundle_digest,
                    _BUNDLE_DIGEST_SEMANTICS,
                ):
                    connection.execute(
                        """
                        INSERT INTO sandbox_executions
                          (attempt_id, claim_token, execution_id, backend, container_id,
                           bundle_digest, bundle_digest_semantics, launch_plan_required,
                           rootfs_digest, rootfs_closure_digest, runc_executable_digest,
                           runtime_version, oci_version,
                           bundle_path, state_path, phase, created_at, updated_at)
                        VALUES (?, ?, ?, 'oci-runc', ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?)
                        """,
                        (
                            attempt_id,
                            claim_token,
                            execution_id,
                            container_id,
                            bundle_digest,
                            _BUNDLE_DIGEST_SEMANTICS,
                            rootfs_digest,
                            rootfs_closure_digest,
                            runc_executable_digest,
                            runtime_version,
                            oci_version,
                            bundle_path,
                            state_path,
                            stamp,
                            stamp,
                        ),
                    )
            except sqlite3.IntegrityError as error:
                if "UNIQUE constraint failed" in str(error):
                    raise SupervisorError(
                        "sandbox_execution_exists",
                        "this attempt already has a reserved or historical sandbox execution",
                    ) from None
                raise
            self._event(
                connection,
                "sandbox.execution_reserved",
                attempt["agent_id"],
                {
                    "attempt_id": attempt_id,
                    "claim_token": claim_token,
                    "execution_id": execution_id,
                    "backend": "oci-runc",
                    "container_id": container_id,
                    "bundle_digest": bundle_digest,
                    "bundle_digest_semantics": _BUNDLE_DIGEST_SEMANTICS,
                    "rootfs_digest": rootfs_digest,
                    "rootfs_closure_digest": rootfs_closure_digest,
                    "runc_executable_digest": runc_executable_digest,
                    "runtime_version": runtime_version,
                    "oci_version": oci_version,
                },
            )
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        return self._sandbox_execution_view(row)

    def _sandbox_execution_bind_workspace(
        self,
        attempt_id: str,
        claim_token: int,
        baseline: _Snapshot,
        workspace: _Snapshot,
        *,
        credential: str | None = None,
    ) -> dict[str, Any]:
        """Durably bind the immutable baseline and mutable workspace before launch.

        Both roots must be host-copier-minted, disjoint siblings of the reserved
        execution directory and initially reproduce the same manifest. This
        records their inode identities and the canonical baseline manifest so a
        later process can re-establish the binding without the copier's
        process-local weak-reference registry. It does not launch a worker or
        authorize result import.
        """

        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        if type(baseline) is not _Snapshot or type(workspace) is not _Snapshot:
            raise SupervisorError(
                "sandbox_workspace_invalid", "workspace binding needs host-created snapshots"
            )
        if baseline.manifest != workspace.manifest:
            raise SupervisorError(
                "sandbox_workspace_invalid", "baseline and mutable workspace differ before launch"
            )
        baseline_root, baseline_device, baseline_inode = _snapshot_origin(baseline)
        workspace_root, workspace_device, workspace_inode = _snapshot_origin(workspace)
        if (
            baseline_root == workspace_root
            or baseline_root in workspace_root.parents
            or workspace_root in baseline_root.parents
        ):
            raise SupervisorError(
                "sandbox_workspace_invalid", "baseline and mutable workspace must be disjoint"
            )
        baseline.manifest.validate()

        # Authenticate and pin the expected per-execution paths before walking
        # any caller-supplied snapshot tree. Recheck transactionally below
        # before writing the immutable binding.
        with self.connect() as connection:
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            self._authenticate_attempt(connection, attempt, credential)
            reserved = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        if reserved is None or reserved["claim_token"] != claim_token:
            raise SupervisorError("sandbox_execution_not_found", "execution reservation is missing")
        execution_root = Path(reserved["bundle_path"]).parent
        bundle_root = Path(reserved["bundle_path"])
        state_root = Path(reserved["state_path"])
        if (
            baseline_root != execution_root / "baseline"
            or workspace_root != execution_root / "workspace"
            or bundle_root != execution_root / "bundle"
            or state_root != execution_root / "state"
        ):
            raise SupervisorError(
                "sandbox_workspace_invalid",
                "workspace, bundle, and state roots must be reserved execution children",
            )
        execution_root_identity = _private_directory_identity(execution_root, "execution root")
        bundle_root_identity = _private_directory_identity(bundle_root, "bundle root")
        state_root_identity = _private_directory_identity(state_root, "runc state root")
        _verify_directory_identity(
            baseline_root,
            expected_device=baseline_device,
            expected_inode=baseline_inode,
        )
        _verify_directory_identity(
            workspace_root,
            expected_device=workspace_device,
            expected_inode=workspace_inode,
        )
        manifest_json = canonical_json(baseline.manifest.as_json())
        if len(manifest_json.encode("utf-8")) > _MAX_DURABLE_MANIFEST_BYTES:
            raise SupervisorError(
                "workspace_limit_exceeded", "durable baseline manifest exceeds its storage limit"
            )
        baseline_check = _collect_changes(baseline.manifest, baseline_root, write_set_rules=[])
        workspace_check = _collect_changes(workspace.manifest, workspace_root, write_set_rules=[])
        if (
            baseline_check.changes
            or workspace_check.changes
            or baseline_check.result_digest != baseline.manifest.digest
            or workspace_check.result_digest != baseline.manifest.digest
        ):
            raise SupervisorError(
                "sandbox_workspace_invalid", "workspace changed while its baseline was bound"
            )
        _verify_directory_identity(
            baseline_root,
            expected_device=baseline_device,
            expected_inode=baseline_inode,
        )
        _verify_directory_identity(
            workspace_root,
            expected_device=workspace_device,
            expected_inode=workspace_inode,
        )

        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            if attempt["status"] != "working":
                raise SupervisorError("claim_inactive", "sandbox attempt is no longer working")
            self._authenticate_attempt(connection, attempt, credential)
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if row is None or row["claim_token"] != claim_token:
                raise SupervisorError(
                    "sandbox_execution_not_found", "execution reservation is missing"
                )
            execution_root = Path(row["bundle_path"]).parent
            expected_baseline = execution_root / "baseline"
            expected_workspace = execution_root / "workspace"
            if (
                baseline_root != expected_baseline
                or workspace_root != expected_workspace
                or bundle_root != execution_root / "bundle"
                or state_root != execution_root / "state"
            ):
                raise SupervisorError(
                    "sandbox_workspace_invalid",
                    "workspace, bundle, and state roots must be reserved execution children",
                )
            current_path_identities = (
                _private_directory_identity(execution_root, "execution root"),
                _private_directory_identity(bundle_root, "bundle root"),
                _private_directory_identity(state_root, "runc state root"),
            )
            if current_path_identities != (
                execution_root_identity,
                bundle_root_identity,
                state_root_identity,
            ):
                raise SupervisorError(
                    "sandbox_private_path_conflict",
                    "private execution directories changed while workspace binding was recorded",
                )
            values = (
                str(baseline_root),
                baseline_device,
                baseline_inode,
                str(workspace_root),
                workspace_device,
                workspace_inode,
                manifest_json,
                baseline.manifest.digest,
                1,
                *execution_root_identity,
                *bundle_root_identity,
                *state_root_identity,
            )
            if row["workspace_binding_version"] == 1:
                recorded = (
                    row["baseline_root_path"],
                    row["baseline_root_dev"],
                    row["baseline_root_ino"],
                    row["workspace_root_path"],
                    row["workspace_root_dev"],
                    row["workspace_root_ino"],
                    row["baseline_manifest_json"],
                    row["baseline_manifest_digest"],
                    row["private_path_binding_version"],
                    row["execution_root_dev"],
                    row["execution_root_ino"],
                    row["bundle_root_dev"],
                    row["bundle_root_ino"],
                    row["state_root_dev"],
                    row["state_root_ino"],
                )
                if recorded != values:
                    raise SupervisorError(
                        "sandbox_workspace_conflict", "workspace binding conflicts with its journal"
                    )
                return self._sandbox_execution_view(row)
            if row["phase"] != "reserved":
                raise SupervisorError(
                    "sandbox_execution_transition_invalid",
                    "workspace binding must be recorded before runtime launch",
                )
            changed = connection.execute(
                """
                UPDATE sandbox_executions SET
                  workspace_binding_version = 1,
                  baseline_root_path = ?, baseline_root_dev = ?, baseline_root_ino = ?,
                  workspace_root_path = ?, workspace_root_dev = ?, workspace_root_ino = ?,
                  baseline_manifest_json = ?, baseline_manifest_digest = ?,
                  private_path_binding_version = ?,
                  execution_root_dev = ?, execution_root_ino = ?,
                  bundle_root_dev = ?, bundle_root_ino = ?,
                  state_root_dev = ?, state_root_ino = ?, updated_at = ?
                WHERE attempt_id = ? AND claim_token = ? AND phase = 'reserved'
                  AND workspace_binding_version = 0
                """,
                (*values, utc_now(), attempt_id, claim_token),
            ).rowcount
            if changed != 1:
                raise SupervisorError(
                    "sandbox_workspace_conflict", "workspace binding changed concurrently"
                )
            self._event(
                connection,
                "sandbox.workspace_bound",
                attempt["agent_id"],
                {
                    "attempt_id": attempt_id,
                    "claim_token": claim_token,
                    "execution_id": row["execution_id"],
                    "workspace_binding_version": 1,
                    "baseline_manifest_digest": baseline.manifest.digest,
                    "baseline_root_dev": baseline_device,
                    "baseline_root_ino": baseline_inode,
                    "workspace_root_dev": workspace_device,
                    "workspace_root_ino": workspace_inode,
                    "private_path_binding_version": 1,
                    "execution_root_dev": execution_root_identity[0],
                    "execution_root_ino": execution_root_identity[1],
                    "bundle_root_dev": bundle_root_identity[0],
                    "bundle_root_ino": bundle_root_identity[1],
                    "state_root_dev": state_root_identity[0],
                    "state_root_ino": state_root_identity[1],
                    "entry_count": len(baseline.manifest.entries),
                    "total_bytes": baseline.manifest.total_bytes,
                },
            )
            updated = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        return self._sandbox_execution_view(updated)

    def _sandbox_execution_restore_workspace_binding(
        self,
        attempt_id: str,
        claim_token: int,
        *,
        credential: str | None = None,
    ) -> dict[str, Any]:
        """Restore the baseline and re-check both roots after a supervisor restart."""

        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        with self.connect() as connection:
            connection.execute("BEGIN")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            self._authenticate_attempt(connection, attempt, credential)
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        if row is None or row["claim_token"] != claim_token:
            raise SupervisorError("sandbox_execution_not_found", "execution reservation is missing")
        if row["workspace_binding_version"] != 1 or row["private_path_binding_version"] != 1:
            raise SupervisorError(
                "sandbox_workspace_unbound",
                "execution lacks a complete durable workspace/private-path binding",
            )
        if row["phase"] == "ambiguous":
            raise SupervisorError(
                "sandbox_execution_ambiguous", "ambiguous sandbox cannot restore a result workspace"
            )
        execution_root = Path(row["bundle_path"]).parent
        baseline_path = execution_root / "baseline"
        workspace_path = execution_root / "workspace"
        if (
            Path(row["baseline_root_path"]) != baseline_path
            or Path(row["workspace_root_path"]) != workspace_path
            or Path(row["bundle_path"]) != execution_root / "bundle"
            or Path(row["state_path"]) != execution_root / "state"
        ):
            raise SupervisorError(
                "sandbox_workspace_invalid", "journaled workspace paths do not match execution root"
            )
        execution_root_identity = _private_directory_identity(execution_root, "execution root")
        if execution_root_identity != (row["execution_root_dev"], row["execution_root_ino"]):
            raise SupervisorError(
                "sandbox_private_path_conflict",
                "execution root identity no longer matches the durable journal",
            )
        if row["phase"] == "cleanup_verified":
            if not _sandbox_cleanup_verification_is_self_consistent(row):
                raise SupervisorError(
                    "sandbox_cleanup_verification_invalid",
                    "workspace restore requires an exact independently verified cleanup receipt",
                )
            _require_private_path_absent(Path(row["bundle_path"]), "bundle root")
            _require_private_path_absent(Path(row["state_path"]), "runc state root")
        else:
            bundle_root_identity = _private_directory_identity(
                Path(row["bundle_path"]), "bundle root"
            )
            state_root_identity = _private_directory_identity(
                Path(row["state_path"]), "runc state root"
            )
            if bundle_root_identity != (
                row["bundle_root_dev"],
                row["bundle_root_ino"],
            ) or state_root_identity != (row["state_root_dev"], row["state_root_ino"]):
                raise SupervisorError(
                    "sandbox_private_path_conflict",
                    "private execution directory identity no longer matches the durable journal",
                )
        baseline = _restore_snapshot_from_record(
            baseline_path,
            row["baseline_manifest_json"],
            expected_device=row["baseline_root_dev"],
            expected_inode=row["baseline_root_ino"],
            expected_digest=row["baseline_manifest_digest"],
        )
        current_workspace = _verify_directory_identity(
            workspace_path,
            expected_device=row["workspace_root_dev"],
            expected_inode=row["workspace_root_ino"],
        )
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            self._authenticate_attempt(connection, attempt, credential)
            current = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            binding_columns = (
                "execution_id",
                "claim_token",
                "phase",
                "bundle_path",
                "workspace_binding_version",
                "private_path_binding_version",
                "execution_root_dev",
                "execution_root_ino",
                "bundle_root_dev",
                "bundle_root_ino",
                "state_root_dev",
                "state_root_ino",
                "baseline_root_path",
                "baseline_root_dev",
                "baseline_root_ino",
                "workspace_root_path",
                "workspace_root_dev",
                "workspace_root_ino",
                "baseline_manifest_json",
                "baseline_manifest_digest",
            )
            if current is None or any(current[name] != row[name] for name in binding_columns):
                raise SupervisorError(
                    "sandbox_workspace_conflict", "durable workspace binding changed during restore"
                )
            if current["phase"] == "ambiguous":
                raise SupervisorError(
                    "sandbox_execution_ambiguous",
                    "ambiguous sandbox cannot restore a result workspace",
                )
        return {
            "version": 1,
            "private_path_binding_version": row["private_path_binding_version"],
            "execution_id": row["execution_id"],
            "attempt_id": attempt_id,
            "claim_token": claim_token,
            "baseline": baseline,
            "workspace_root": current_workspace,
            "workspace_device": row["workspace_root_dev"],
            "workspace_inode": row["workspace_root_ino"],
            "execution_root": execution_root,
            "execution_root_device": row["execution_root_dev"],
            "execution_root_inode": row["execution_root_ino"],
            "bundle_root": Path(row["bundle_path"]),
            "bundle_root_device": row["bundle_root_dev"],
            "bundle_root_inode": row["bundle_root_ino"],
            "state_root": Path(row["state_path"]),
            "state_root_device": row["state_root_dev"],
            "state_root_inode": row["state_root_ino"],
        }

    def _sandbox_execution_capture_result_candidate(
        self,
        attempt_id: str,
        claim_token: int,
        credential: str | None = None,
    ) -> dict[str, Any]:
        """Host-scan and write once a non-authorizing result-candidate receipt."""

        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        binding = self._sandbox_execution_restore_workspace_binding(
            attempt_id, claim_token, credential=credential
        )
        baseline_root, baseline_device, baseline_inode = _snapshot_origin(binding["baseline"])
        with self.connect() as connection:
            connection.execute("BEGIN")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            if attempt["status"] != "working":
                raise SupervisorError(
                    "claim_inactive", "sandbox result attempt is no longer working"
                )
            self._authenticate_attempt(connection, attempt, credential)
            execution = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if (
                execution is None
                or execution["execution_id"] != binding["execution_id"]
                or execution["phase"] != "cleanup_verified"
                or not _sandbox_cleanup_verification_is_self_consistent(execution)
                or execution["runc_exit_code"] != 0
                or execution["runc_exit_evidence_source"] != "runc_client_kernel_waitpid"
                or execution["baseline_root_path"] != str(baseline_root)
                or execution["baseline_root_dev"] != baseline_device
                or execution["baseline_root_ino"] != baseline_inode
                or execution["workspace_root_path"] != str(binding["workspace_root"])
                or execution["workspace_root_dev"] != binding["workspace_device"]
                or execution["workspace_root_ino"] != binding["workspace_inode"]
            ):
                raise SupervisorError(
                    "sandbox_result_evidence_unverified",
                    "candidate capture requires the exact cleanup-verified workspace",
                )
            task = self._task_row(connection, attempt["task_id"])
            write_set_rules = self._write_set_rules(task, self._case_sensitive_paths(connection))

        change_set = _collect_changes(
            binding["baseline"].manifest,
            binding["workspace_root"],
            write_set_rules=write_set_rules,
        )
        change_set.validate()
        _verify_directory_identity(
            binding["workspace_root"],
            expected_device=binding["workspace_device"],
            expected_inode=binding["workspace_inode"],
        )
        workspace_path = str(binding["workspace_root"])
        workspace_device = binding["workspace_device"]
        workspace_inode = binding["workspace_inode"]

        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            if attempt["status"] != "working":
                raise SupervisorError(
                    "claim_inactive", "sandbox result attempt is no longer working"
                )
            self._authenticate_attempt(connection, attempt, credential)
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if row is None or row["claim_token"] != claim_token:
                raise SupervisorError(
                    "sandbox_execution_not_found", "execution reservation is missing"
                )
            if (
                row["phase"] != "cleanup_verified"
                or not _sandbox_cleanup_verification_is_self_consistent(row)
                or row["runc_exit_code"] != 0
                or row["runc_exit_evidence_source"] != "runc_client_kernel_waitpid"
                or row["workspace_binding_version"] != 1
                or row["baseline_root_path"] != str(baseline_root)
                or row["baseline_root_dev"] != baseline_device
                or row["baseline_root_ino"] != baseline_inode
                or row["workspace_root_path"] != workspace_path
                or row["workspace_root_dev"] != workspace_device
                or row["workspace_root_ino"] != workspace_inode
                or row["baseline_manifest_digest"] != change_set.baseline_digest
            ):
                raise SupervisorError(
                    "sandbox_result_evidence_unverified",
                    "candidate result is not bound to the cleanup-verified execution workspace",
                )
            task = self._task_row(connection, attempt["task_id"])
            current_write_set_rules = self._write_set_rules(
                task, self._case_sensitive_paths(connection)
            )
            if current_write_set_rules != write_set_rules:
                raise SupervisorError(
                    "sandbox_result_evidence_conflict",
                    "task write set changed while the candidate was captured",
                )

            cleanup_json = row["cleanup_receipt_json"]
            if not self._sandbox_cleanup_receipt_is_exact_for_result(row, cleanup_json):
                raise SupervisorError(
                    "sandbox_result_evidence_unverified",
                    "cleanup report is not the exact unverified journal receipt",
                )
            import_digest = hashlib.sha256(
                canonical_json(
                    {
                        "baseline_digest": change_set.baseline_digest,
                        "result_digest": change_set.result_digest,
                        "change_digest": change_set.digest,
                    }
                ).encode("utf-8")
            ).hexdigest()
            candidate = {
                "version": 1,
                "authorization": "none",
                "attempt_id": attempt_id,
                "claim_token": claim_token,
                "execution_id": row["execution_id"],
                "workspace_binding": {
                    "version": row["workspace_binding_version"],
                    "baseline": {
                        "path": row["baseline_root_path"],
                        "device": row["baseline_root_dev"],
                        "inode": row["baseline_root_ino"],
                        "manifest_digest": row["baseline_manifest_digest"],
                    },
                    "workspace": {
                        "path": row["workspace_root_path"],
                        "device": row["workspace_root_dev"],
                        "inode": row["workspace_root_ino"],
                    },
                },
                "result": {
                    "baseline_digest": change_set.baseline_digest,
                    "tree_digest": change_set.result_digest,
                    "change_digest": change_set.digest,
                    "import_digest": import_digest,
                },
                "exit": {
                    "code": row["runc_exit_code"],
                    "observed_by": row["runc_exit_evidence_source"],
                    "runc_client_pid": row["runc_client_pid"],
                    "runc_client_identity": row["runc_client_identity"],
                },
                "cleanup": {
                    "status": "unverified",
                    "report_digest": hashlib.sha256(cleanup_json.encode("utf-8")).hexdigest(),
                },
            }
            encoded = canonical_json(candidate)
            digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            if row["result_candidate_version"] == 1:
                if (
                    row["result_candidate_json"] != encoded
                    or row["result_candidate_digest"] != digest
                ):
                    raise SupervisorError(
                        "sandbox_result_evidence_conflict",
                        "captured candidate differs from the immutable journal receipt",
                    )
                return {
                    "candidate": candidate,
                    "candidate_digest": digest,
                    "baseline": binding["baseline"],
                    "change_set": change_set,
                }
            if row["result_candidate_version"] != 0:
                raise SupervisorError(
                    "sandbox_result_evidence_invalid", "candidate receipt version is unsupported"
                )
            changed = connection.execute(
                """
                UPDATE sandbox_executions
                SET result_candidate_version = 1, result_candidate_json = ?,
                    result_candidate_digest = ?, updated_at = ?
                WHERE attempt_id = ? AND claim_token = ?
                  AND phase = 'cleanup_verified'
                  AND result_candidate_version = 0
                """,
                (encoded, digest, utc_now(), attempt_id, claim_token),
            ).rowcount
            if changed != 1:
                raise SupervisorError(
                    "sandbox_result_evidence_conflict", "candidate receipt changed concurrently"
                )
            self._event(
                connection,
                "sandbox.result_candidate_captured",
                "supervisor",
                {
                    "attempt_id": attempt_id,
                    "claim_token": claim_token,
                    "execution_id": row["execution_id"],
                    "candidate_digest": digest,
                    "import_digest": import_digest,
                    "authorization": "none",
                    "cleanup_status": "unverified",
                },
            )
        return {
            "candidate": candidate,
            "candidate_digest": digest,
            "baseline": binding["baseline"],
            "change_set": change_set,
        }

    def _sandbox_execution_result_import_source(
        self,
        connection: Any,
        attempt_id: str,
        claim_token: int,
    ) -> dict[str, str]:
        """Return journal identities usable only after trusted cleanup verification."""

        row = connection.execute(
            "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
        ).fetchone()
        if row is None or row["claim_token"] != claim_token:
            raise SupervisorError(
                "sandbox_execution_not_found", "matching sandbox execution is missing"
            )
        _require_sandbox_execution_result_eligible(connection, attempt_id)
        direct_import = connection.execute(
            "SELECT id FROM result_imports WHERE attempt_id = ? "
            "AND source_kind = 'direct_worker' LIMIT 1",
            (attempt_id,),
        ).fetchone()
        if direct_import is not None:
            raise SupervisorError(
                "sandbox_result_source_mismatch",
                "attempt already has a direct-worker result import",
            )
        cleanup_json = row["cleanup_receipt_json"]
        if not self._sandbox_cleanup_receipt_is_exact_for_result(row, cleanup_json):
            raise SupervisorError(
                "sandbox_cleanup_report_invalid",
                "verified execution does not retain its exact journaled cleanup report",
            )
        return {
            "execution_id": row["execution_id"],
            "cleanup_receipt_digest": hashlib.sha256(cleanup_json.encode("utf-8")).hexdigest(),
        }

    def _sandbox_execution_require_result_candidate_matches(
        self,
        connection: Any,
        attempt_id: str,
        *,
        baseline_digest: str,
        import_digest: str,
        change_digest: str,
    ) -> None:
        """Match a sandbox import to its immutable, still non-authorizing capture."""

        row = connection.execute(
            "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
        ).fetchone()
        if row is None:
            return
        if (
            row["phase"] != "cleanup_verified"
            or type(row["runc_exit_code"]) is not int
            or row["runc_exit_code"] != 0
            or row["runc_exit_evidence_source"] != "runc_client_kernel_waitpid"
            or not _sandbox_cleanup_verification_is_self_consistent(row)
        ):
            raise SupervisorError(
                "sandbox_result_evidence_unverified",
                "sandbox import candidate requires a successful exit and exact cleanup proof",
            )
        if row["result_candidate_version"] != 1 or not row["result_candidate_json"]:
            raise SupervisorError(
                "sandbox_result_evidence_missing", "sandbox import has no captured result candidate"
            )
        encoded = row["result_candidate_json"]
        if not isinstance(encoded, str):
            raise SupervisorError(
                "sandbox_result_evidence_invalid", "sandbox result candidate is not bounded text"
            )
        try:
            encoded_bytes = encoded.encode("utf-8")
        except UnicodeEncodeError:
            raise SupervisorError(
                "sandbox_result_evidence_invalid", "sandbox result candidate is not valid UTF-8"
            ) from None
        if len(encoded_bytes) > 65536:
            raise SupervisorError(
                "sandbox_result_evidence_invalid", "sandbox result candidate is not bounded text"
            )
        try:
            candidate = json.loads(encoded)
        except (TypeError, ValueError):
            candidate = None
        digest = hashlib.sha256(encoded_bytes).hexdigest()
        if (
            not isinstance(candidate, dict)
            or set(candidate)
            != {
                "version",
                "authorization",
                "attempt_id",
                "claim_token",
                "execution_id",
                "workspace_binding",
                "result",
                "exit",
                "cleanup",
            }
            or canonical_json(candidate) != encoded
            or row["result_candidate_digest"] != digest
        ):
            raise SupervisorError(
                "sandbox_result_evidence_invalid", "sandbox result candidate digest is invalid"
            )
        result = candidate.get("result")
        tree_digest = result.get("tree_digest") if isinstance(result, dict) else ""
        if not all(
            isinstance(value, str) and _DIGEST.fullmatch(value) is not None
            for value in (baseline_digest, import_digest, change_digest, tree_digest)
        ):
            raise SupervisorError(
                "sandbox_result_evidence_invalid", "sandbox result candidate digest is invalid"
            )
        expected_import_digest = hashlib.sha256(
            canonical_json(
                {
                    "baseline_digest": baseline_digest,
                    "result_digest": tree_digest,
                    "change_digest": change_digest,
                }
            ).encode("utf-8")
        ).hexdigest()
        expected_binding = {
            "version": row["workspace_binding_version"],
            "baseline": {
                "path": row["baseline_root_path"],
                "device": row["baseline_root_dev"],
                "inode": row["baseline_root_ino"],
                "manifest_digest": row["baseline_manifest_digest"],
            },
            "workspace": {
                "path": row["workspace_root_path"],
                "device": row["workspace_root_dev"],
                "inode": row["workspace_root_ino"],
            },
        }
        expected_exit = {
            "code": row["runc_exit_code"],
            "observed_by": row["runc_exit_evidence_source"],
            "runc_client_pid": row["runc_client_pid"],
            "runc_client_identity": row["runc_client_identity"],
        }
        expected_cleanup = {
            "status": "unverified",
            "report_digest": hashlib.sha256(
                row["cleanup_receipt_json"].encode("utf-8")
            ).hexdigest(),
        }
        if (
            candidate.get("version") != 1
            or type(candidate.get("version")) is not int
            or candidate.get("authorization") != "none"
            or candidate.get("attempt_id") != attempt_id
            or type(candidate.get("claim_token")) is not int
            or candidate.get("claim_token") != row["claim_token"]
            or candidate.get("execution_id") != row["execution_id"]
            or candidate.get("workspace_binding") != expected_binding
            or candidate.get("exit") != expected_exit
            or candidate.get("cleanup") != expected_cleanup
            or baseline_digest != row["baseline_manifest_digest"]
            or not isinstance(result, dict)
            or set(result) != {"baseline_digest", "tree_digest", "change_digest", "import_digest"}
            or result.get("baseline_digest") != row["baseline_manifest_digest"]
            or result.get("change_digest") != change_digest
            or result.get("import_digest") != import_digest
            or expected_import_digest != import_digest
        ):
            raise SupervisorError(
                "sandbox_result_evidence_mismatch",
                "sandbox import does not match its captured execution candidate",
            )

    def _sandbox_execution_transition(
        self,
        attempt_id: str,
        claim_token: int,
        *,
        expected_phase: str,
        next_phase: str,
        updates: dict[str, Any],
        event_type: str,
        event_payload: dict[str, Any],
        credential: str | None = None,
        _connection: sqlite3.Connection | None = None,
        running_attestation: RunningRuntimeAttestation | None = None,
        _cleanup_action_receipt: Any | None = None,
        _cleanup_verification_receipt: Any | None = None,
        _cleanup_recovery_receipt: Any | None = None,
        _reaper_epoch: int | None = None,
        _allow_quarantined_failure_cleanup: bool = False,
    ) -> dict[str, Any]:
        allowed_fields = _TRANSITION_FIELDS.get((expected_phase, next_phase))
        if (
            allowed_fields is None
            or not isinstance(updates, dict)
            or set(updates) != allowed_fields
        ):
            raise SupervisorError(
                "sandbox_execution_transition_invalid",
                f"transition {expected_phase} -> {next_phase} is not available in this journal slice",
            )
        if _cleanup_action_receipt is not None and (
            (expected_phase, next_phase) != ("exited", "cleanup_reported")
            or set(updates) != {"cleanup_receipt_json"}
            or _cleanup_recovery_receipt is not None
        ):
            raise SupervisorError(
                "sandbox_cleanup_action_invalid",
                "pinned-runc cleanup action can authorize only its exact report transition",
            )
        if _cleanup_recovery_receipt is not None and (
            (expected_phase, next_phase) != ("exited", "cleanup_reported")
            or set(updates) != {"cleanup_receipt_json"}
            or not _sandbox_cleanup_recovery_receipt_is_self_consistent(_cleanup_recovery_receipt)
            or updates["cleanup_receipt_json"] != _cleanup_recovery_receipt.encoded
        ):
            raise SupervisorError(
                "sandbox_cleanup_recovery_required",
                "only the registered recovery verifier can authorize a recovered report",
            )
        if _reaper_epoch is not None and (
            type(_reaper_epoch) is not int
            or _reaper_epoch <= 0
            or (expected_phase, next_phase) != ("exited", "cleanup_reported")
            or (_cleanup_action_receipt is None and _cleanup_recovery_receipt is None)
        ):
            raise SupervisorError(
                "sandbox_cleanup_recovery_required",
                "reaper recovery requires an exact cleanup receipt and expiry epoch",
            )
        if _allow_quarantined_failure_cleanup and (
            (expected_phase, next_phase) != ("exited", "cleanup_reported")
            or _cleanup_action_receipt is None
            or set(updates) != {"cleanup_receipt_json"}
        ):
            raise SupervisorError(
                "sandbox_cleanup_action_invalid",
                "quarantined cleanup requires an exact pinned-runc action receipt",
            )
        if _cleanup_verification_receipt is not None and (
            (expected_phase, next_phase) != ("cleanup_reported", "cleanup_verified")
            or set(updates) != {"cleanup_verification_json"}
            or not _sandbox_cleanup_verification_receipt_is_self_consistent(
                _cleanup_verification_receipt
            )
            or updates["cleanup_verification_json"] != _cleanup_verification_receipt.encoded
        ):
            raise SupervisorError(
                "sandbox_cleanup_verification_required",
                "only the registered independent verifier can finalize cleanup",
            )
        if (expected_phase, next_phase) == (
            "launched",
            "running",
        ) or running_attestation is not None:
            raise SupervisorError(
                "sandbox_runtime_attestation_invalid",
                "running transitions are available only through the fully validated runtime path",
            )
        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        connection_context = self.connect() if _connection is None else nullcontext(_connection)
        with connection_context as connection:
            if _connection is None:
                connection.execute("BEGIN IMMEDIATE")
            if _cleanup_verification_receipt is not None:
                attempt = connection.execute(
                    "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
                ).fetchone()
                if attempt is None or attempt["claim_token"] != claim_token:
                    raise SupervisorError(
                        "stale_fencing_token", "cleanup verifier claim token is stale"
                    )
            elif _reaper_epoch is not None:
                attempt = connection.execute(
                    "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
                ).fetchone()
                if attempt is None or attempt["claim_token"] != claim_token:
                    raise SupervisorError(
                        "stale_fencing_token", "reaper cleanup claim token is stale"
                    )
                expired_attempt = (
                    attempt["status"] in {"provisioning", "working"}
                    and attempt["lease_expires_at"] <= _reaper_epoch
                )
                if attempt["status"] == "terminating":
                    task = connection.execute(
                        "SELECT current_attempt_id, status, cleanup_target_status "
                        "FROM tasks WHERE id = ?",
                        (attempt["task_id"],),
                    ).fetchone()
                    expired_attempt = (
                        attempt["termination_target_status"] == "quarantined"
                        and task is not None
                        and task["current_attempt_id"] == attempt_id
                        and task["status"] == "cleanup_pending"
                        and task["cleanup_target_status"] == "blocked"
                    )
                if not expired_attempt:
                    raise SupervisorError(
                        "sandbox_cleanup_recovery_not_due",
                        "reaper cleanup is not bound to an expired or quarantined attempt",
                    )
            elif _allow_quarantined_failure_cleanup:
                attempt = connection.execute(
                    "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
                ).fetchone()
                if (
                    attempt is None
                    or attempt["claim_token"] != claim_token
                    or attempt["status"] != "terminating"
                    or attempt["termination_target_status"] != "quarantined"
                ):
                    raise SupervisorError(
                        "sandbox_execution_transition_conflict",
                        "quarantined cleanup action has no exact terminating attempt",
                    )
                self._authenticate_attempt(connection, attempt, credential)
            else:
                attempt = self._active_attempt(
                    connection, attempt_id, claim_token, int(time.time())
                )
                if attempt["status"] != "working":
                    raise SupervisorError("claim_inactive", "sandbox attempt is no longer working")
                self._authenticate_attempt(connection, attempt, credential)
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if not row:
                raise SupervisorError("sandbox_execution_not_found", "execution was not reserved")
            if row["claim_token"] != claim_token:
                raise SupervisorError("stale_fencing_token", "sandbox claim token is stale")
            if row["phase"] != expected_phase:
                raise SupervisorError(
                    "sandbox_execution_transition_invalid",
                    f"expected phase {expected_phase}, found {row['phase']}; fence retained",
                )
            if _allow_quarantined_failure_cleanup:
                task = connection.execute(
                    "SELECT current_attempt_id, status, cleanup_target_status "
                    "FROM tasks WHERE id = ?",
                    (attempt["task_id"],),
                ).fetchone()
                if (
                    row["failure_reason"] != _LAUNCH_DRIVER_LEASE_LOSS_REASON
                    or task is None
                    or task["current_attempt_id"] != attempt_id
                    or task["status"] != "cleanup_pending"
                    or task["cleanup_target_status"] != "blocked"
                ):
                    raise SupervisorError(
                        "sandbox_execution_transition_conflict",
                        "quarantined cleanup action is not bound to the exact lease-loss cleanup",
                    )
            if _reaper_epoch is not None:
                if (
                    row["phase"] != "exited"
                    or row["runc_exit_evidence_source"] != "runc_client_kernel_waitpid"
                    or not _sandbox_launch_submission_latch_is_self_consistent(row)
                    or (
                        _cleanup_recovery_receipt is not None
                        and (
                            _cleanup_recovery_receipt.attempt_id != attempt_id
                            or _cleanup_recovery_receipt.claim_token != claim_token
                            or _cleanup_recovery_receipt.execution_id != row["execution_id"]
                            or _cleanup_recovery_receipt.launch_submission_id
                            != row["launch_submission_id"]
                            or _cleanup_recovery_receipt.launch_submission_digest
                            != row["launch_submission_digest"]
                            or _cleanup_recovery_receipt.reaper_epoch != _reaper_epoch
                            or not _sandbox_cleanup_recovery_report_is_self_consistent(
                                row, _cleanup_recovery_receipt.encoded
                            )
                        )
                    )
                ):
                    raise SupervisorError(
                        "sandbox_cleanup_recovery_identity_mismatch",
                        "reaper cleanup receipt does not bind to the exact exited submission",
                    )
            if _cleanup_verification_receipt is not None:
                from .sandbox_cleanup_verifier import (
                    _sandbox_cleanup_verification_json_is_self_consistent,
                )

                candidate = dict(row)
                candidate.update(updates)
                candidate["phase"] = next_phase
                if not _sandbox_cleanup_verification_json_is_self_consistent(
                    candidate, updates["cleanup_verification_json"]
                ):
                    raise SupervisorError(
                        "sandbox_cleanup_verification_required",
                        "verifier receipt does not bind to the exact durable cleanup report",
                    )
            if expected_phase == "reserved" and next_phase == "launched":
                if row["launch_plan_required"] != 1:
                    raise SupervisorError(
                        "sandbox_execution_launch_plan_required",
                        "legacy reservation has no trusted launch-plan requirement",
                    )
                if row["workspace_binding_version"] != 1:
                    raise SupervisorError(
                        "sandbox_workspace_unbound",
                        "sandbox launch requires a durable baseline/workspace binding",
                    )
                if row["private_path_binding_version"] != 1:
                    raise SupervisorError(
                        "sandbox_private_path_unbound",
                        "sandbox launch requires exact private bundle/state directory identities",
                    )
                execution_root = Path(row["bundle_path"]).parent
                expected_paths = (
                    (execution_root, row["execution_root_dev"], row["execution_root_ino"]),
                    (Path(row["bundle_path"]), row["bundle_root_dev"], row["bundle_root_ino"]),
                    (Path(row["state_path"]), row["state_root_dev"], row["state_root_ino"]),
                )
                if (
                    Path(row["bundle_path"]) != execution_root / "bundle"
                    or Path(row["state_path"]) != execution_root / "state"
                    or any(device is None or inode is None for _, device, inode in expected_paths)
                ):
                    raise SupervisorError(
                        "sandbox_private_path_unbound",
                        "journaled private execution paths are incomplete or noncanonical",
                    )
                for path, device, inode in expected_paths:
                    _verify_directory_identity(path, expected_device=device, expected_inode=inode)
                candidate = dict(row)
                candidate.update(updates)
                if not _sandbox_launch_plan_binding_is_self_consistent(candidate):
                    raise SupervisorError(
                        "sandbox_execution_launch_plan_invalid",
                        "launch transition lacks a self-consistent durable launch-plan binding",
                    )
                if any(
                    _DIGEST.fullmatch(row[name] or "") is None
                    for name in ("rootfs_closure_digest", "runc_executable_digest")
                ):
                    raise SupervisorError(
                        "sandbox_execution_content_pins_required",
                        "sandbox launch requires pinned rootfs closure and runc executable digests",
                    )
                if (
                    not row["launch_submission_id"]
                    or not row["launch_submission_digest"]
                    or not row["launch_submission_at"]
                ):
                    raise SupervisorError(
                        "sandbox_execution_launch_submission_required",
                        "launch transition requires the durable pre-runc submission latch",
                    )
            fields = ", ".join(f"{name} = ?" for name in updates)
            statement = (
                f"UPDATE sandbox_executions SET {fields}, phase = ?, updated_at = ? "
                "WHERE attempt_id = ? AND claim_token = ? AND phase = ?"
            )
            parameters = (
                *updates.values(),
                next_phase,
                utc_now(),
                attempt_id,
                claim_token,
                expected_phase,
            )
            if event_type == "sandbox.execution_cleanup_verified":
                with _authorize_sandbox_cleanup_verification_write(
                    connection,
                    _cleanup_verification_receipt,
                    updates["cleanup_verification_json"],
                ):
                    changed = connection.execute(statement, parameters).rowcount
            elif event_type == "sandbox.execution_cleanup_reported":
                with _authorize_sandbox_cleanup_report_write(
                    connection,
                    attempt_id,
                    claim_token,
                    row["execution_id"],
                    updates["cleanup_receipt_json"],
                ):
                    if _cleanup_action_receipt is not None:
                        with _authorize_sandbox_cleanup_action_write(
                            connection,
                            _cleanup_action_receipt,
                            updates["cleanup_receipt_json"],
                        ):
                            changed = connection.execute(statement, parameters).rowcount
                    else:
                        changed = connection.execute(statement, parameters).rowcount
            elif _cleanup_action_receipt is not None:
                with _authorize_sandbox_cleanup_action_write(
                    connection,
                    _cleanup_action_receipt,
                    updates["cleanup_receipt_json"],
                ):
                    changed = connection.execute(statement, parameters).rowcount
            else:
                changed = connection.execute(statement, parameters).rowcount
            if changed != 1:
                raise SupervisorError(
                    "sandbox_execution_transition_conflict",
                    "execution journal changed concurrently; attempt fence retained",
                )
            self._event(
                connection,
                event_type,
                attempt["agent_id"],
                {
                    "attempt_id": attempt_id,
                    "claim_token": claim_token,
                    "execution_id": row["execution_id"],
                    "phase": next_phase,
                    **event_payload,
                },
            )
            updated = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        return self._sandbox_execution_view(updated)

    def _sandbox_execution_authorize_launch_driver_start(
        self,
        attempt_id: str,
        claim_token: int,
        *,
        launch_request_digest: str,
        credential: str | None = None,
    ) -> _SandboxLaunchDriverStartIntent:
        """Commit the sole driver-service start intent before systemd activation.

        A repeated call is not a retry: the first caller may have crossed the
        systemd boundary before losing its response. Until an exact adoption
        path exists, that outcome must remain fenced rather than creating a
        second driver activation.
        """

        attempt_id = self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            if attempt["status"] != "working":
                raise SupervisorError("claim_inactive", "sandbox attempt is no longer working")
            self._authenticate_attempt(connection, attempt, credential)
            if attempt["pid"] is not None or attempt["launch_owner_pid"] is not None:
                raise SupervisorError(
                    "worker_already_running",
                    "launch-driver start cannot be authorized beside a direct worker",
                )
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if row is None:
                raise SupervisorError("sandbox_execution_not_found", "execution was not reserved")
            if row["claim_token"] != claim_token:
                raise SupervisorError("stale_fencing_token", "sandbox claim token is stale")
            if row["phase"] != "reserved":
                raise SupervisorError(
                    "sandbox_execution_transition_invalid",
                    f"expected phase reserved, found {row['phase']}; fence retained",
                )
            if any(
                row[name]
                for name in (
                    "launch_driver_start_id",
                    "launch_driver_start_digest",
                    "launch_driver_start_at",
                    "launch_driver_start_unit",
                )
            ):
                raise SupervisorError(
                    "sandbox_launch_driver_start_ambiguous",
                    "this execution already consumed its only launch-driver start intent; reconcile the exact unit or retain its fence",
                )
            if (
                row["launch_plan_required"] != 1
                or row["workspace_binding_version"] != 1
                or row["private_path_binding_version"] != 1
            ):
                raise SupervisorError(
                    "sandbox_launch_driver_start_unprepared",
                    "launch-driver start requires pinned runtime, workspace, and private path bindings",
                )
            if row["launch_submission_id"] or row["launch_submission_at"]:
                raise SupervisorError(
                    "sandbox_execution_launch_submission_exists",
                    "runc launch submission already exists before launch-driver activation",
                )

            service_unit = _sandbox_launch_driver_service_unit(row["execution_id"])
            start_id = uuid.uuid4().hex
            start_digest = _sandbox_launch_driver_start_digest(
                row, service_unit, launch_request_digest=launch_request_digest
            )
            intent = _SandboxLaunchDriverStartIntent(
                attempt_id=attempt_id,
                claim_token=claim_token,
                execution_id=row["execution_id"],
                start_id=start_id,
                start_digest=start_digest,
                service_unit=service_unit,
            )
            _register_sandbox_launch_driver_start_intent(intent)
            stamp = utc_now()
            try:
                with _authorize_sandbox_launch_driver_start_write(
                    connection,
                    attempt_id,
                    claim_token,
                    row["execution_id"],
                    start_id,
                    start_digest,
                    service_unit,
                ):
                    changed = connection.execute(
                        "UPDATE sandbox_executions SET launch_driver_start_id = ?, "
                        "launch_driver_start_digest = ?, launch_driver_start_at = ?, "
                        "launch_driver_start_unit = ?, updated_at = ? "
                        "WHERE attempt_id = ? AND claim_token = ? AND phase = 'reserved' "
                        "AND launch_driver_start_id = '' AND launch_driver_start_digest = '' "
                        "AND launch_driver_start_at = '' AND launch_driver_start_unit = ''",
                        (
                            start_id,
                            start_digest,
                            stamp,
                            service_unit,
                            stamp,
                            attempt_id,
                            claim_token,
                        ),
                    ).rowcount
                if changed != 1:
                    raise SupervisorError(
                        "sandbox_execution_transition_conflict",
                        "launch-driver start intent changed concurrently; attempt fence retained",
                    )
                self._event(
                    connection,
                    "sandbox.execution_launch_driver_start_authorized",
                    attempt["agent_id"],
                    {
                        "attempt_id": attempt_id,
                        "claim_token": claim_token,
                        "execution_id": row["execution_id"],
                        "start_id": start_id,
                        "start_digest": start_digest,
                        "service_unit": service_unit,
                        "launch_request_digest": launch_request_digest,
                        "boundary": "before_systemd_activation",
                    },
                )
            except BaseException:
                with _SANDBOX_LAUNCH_DRIVER_START_INTENTS_LOCK:
                    registered = _SANDBOX_LAUNCH_DRIVER_START_INTENTS.get(id(intent))
                    if registered is not None and registered[0]() is intent:
                        _SANDBOX_LAUNCH_DRIVER_START_INTENTS.pop(id(intent), None)
                raise
        return intent

    def _sandbox_execution_redeem_launch_driver_start(
        self,
        attempt_id: str,
        claim_token: int,
        *,
        redemption: LaunchDriverStartRedemption,
        credential: str | None = None,
    ) -> dict[str, Any]:
        """Bind the sole start intent to the current exact systemd service activation."""

        attempt_id = self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        if (
            not launch_driver_start_redemption_has_collector_provenance(redemption)
            or not launch_driver_start_redemption_is_self_consistent(redemption)
            or redemption.driver_pid != os.getpid()
            or (redemption.attempt_id, redemption.claim_token) != (attempt_id, claim_token)
        ):
            raise SupervisorError(
                "sandbox_launch_driver_redemption_required",
                "redemption must come from the current exact service process",
            )
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            if attempt["status"] != "working":
                raise SupervisorError("claim_inactive", "sandbox attempt is no longer working")
            self._authenticate_attempt(connection, attempt, credential)
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if row is None:
                raise SupervisorError("sandbox_execution_not_found", "execution was not reserved")
            if row["claim_token"] != claim_token:
                raise SupervisorError("stale_fencing_token", "sandbox claim token is stale")
            if row["phase"] != "reserved":
                raise SupervisorError(
                    "sandbox_execution_transition_invalid",
                    f"expected phase reserved, found {row['phase']}; fence retained",
                )
            if (
                not row["launch_driver_start_id"]
                or not row["launch_driver_start_digest"]
                or row["launch_driver_start_unit"]
                != _sandbox_launch_driver_service_unit(row["execution_id"])
            ):
                raise SupervisorError(
                    "sandbox_launch_driver_start_intent_required",
                    "redemption requires the exact durable pre-activation intent",
                )
            if (
                redemption.execution_id != row["execution_id"]
                or redemption.start_id != row["launch_driver_start_id"]
                or redemption.start_digest != row["launch_driver_start_digest"]
                or redemption.service_unit != row["launch_driver_start_unit"]
                or redemption.attempt_slice_unit != _oci_worker_systemd_slice(row["container_id"])
            ):
                raise SupervisorError(
                    "sandbox_launch_driver_redemption_mismatch",
                    "activation does not match the durable intent and attempt slice",
                )
            redeemed_fields = (
                "launch_driver_start_redeemed_at",
                "launch_driver_start_redeemed_invocation_id",
                "launch_driver_start_redeemed_identity",
                "launch_driver_start_redeemed_cgroup_path",
                "launch_driver_start_redeemed_slice_unit",
                "launch_driver_start_redeemed_slice_invocation_id",
                "launch_driver_start_redeemed_slice_cgroup_path",
            )
            if (
                any(row[name] for name in redeemed_fields)
                or row["launch_driver_start_redeemed_pid"] is not None
            ):
                raise SupervisorError(
                    "sandbox_launch_driver_redemption_ambiguous",
                    "the sole start intent was already redeemed; fence retained",
                )

            stamp = utc_now()
            with _authorize_sandbox_launch_driver_redemption_write(connection, redemption, stamp):
                changed = connection.execute(
                    "UPDATE sandbox_executions SET launch_driver_start_redeemed_at = ?, "
                    "launch_driver_start_redeemed_invocation_id = ?, "
                    "launch_driver_start_redeemed_pid = ?, "
                    "launch_driver_start_redeemed_identity = ?, "
                    "launch_driver_start_redeemed_cgroup_path = ?, "
                    "launch_driver_start_redeemed_slice_unit = ?, "
                    "launch_driver_start_redeemed_slice_invocation_id = ?, "
                    "launch_driver_start_redeemed_slice_cgroup_path = ?, updated_at = ? "
                    "WHERE attempt_id = ? AND claim_token = ? AND phase = 'reserved' "
                    "AND launch_driver_start_redeemed_at = '' "
                    "AND launch_driver_start_redeemed_pid IS NULL",
                    (
                        stamp,
                        redemption.service_invocation_id,
                        redemption.driver_pid,
                        redemption.driver_identity,
                        redemption.driver_control_group,
                        redemption.attempt_slice_unit,
                        redemption.attempt_slice_invocation_id,
                        redemption.attempt_slice_control_group,
                        stamp,
                        attempt_id,
                        claim_token,
                    ),
                ).rowcount
            if changed != 1:
                raise SupervisorError(
                    "sandbox_execution_transition_conflict",
                    "redemption changed concurrently; attempt fence retained",
                )
            self._event(
                connection,
                "sandbox.execution_launch_driver_start_redeemed",
                attempt["agent_id"],
                {
                    "attempt_id": attempt_id,
                    "claim_token": claim_token,
                    "execution_id": row["execution_id"],
                    "start_id": row["launch_driver_start_id"],
                    "start_digest": row["launch_driver_start_digest"],
                    "service_unit": redemption.service_unit,
                    "service_invocation_id": redemption.service_invocation_id,
                    "driver_pid": redemption.driver_pid,
                    "driver_identity": redemption.driver_identity,
                    "driver_control_group": redemption.driver_control_group,
                    "attempt_slice_unit": redemption.attempt_slice_unit,
                    "attempt_slice_invocation_id": redemption.attempt_slice_invocation_id,
                    "attempt_slice_control_group": redemption.attempt_slice_control_group,
                    "evidence_sha256": redemption.evidence_sha256,
                    "boundary": "current_service_before_runc_submission",
                },
            )
            updated = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        return self._sandbox_execution_view(updated)

    def _sandbox_execution_authorize_launch_submission(
        self,
        attempt_id: str,
        claim_token: int,
        *,
        launch_target: _RuncLaunchTarget,
        provider_proxy_artifact: dict[str, int] | None = None,
        credential: str | None = None,
    ) -> _SandboxLaunchSubmission:
        """Durably consume the one launch opportunity immediately before runc exec.

        The caller invokes this from the launcher's pre-submission callback. The
        commit intentionally precedes the byte that releases the private launcher
        into ``execve``. If the monitor dies after the commit, the attempt stays
        fenced and cannot be submitted a second time until an exact reconciler can
        prove what happened.
        """

        attempt_id = self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            if attempt["status"] != "working":
                raise SupervisorError("claim_inactive", "sandbox attempt is no longer working")
            self._authenticate_attempt(connection, attempt, credential)
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if not row:
                raise SupervisorError("sandbox_execution_not_found", "execution was not reserved")
            if row["claim_token"] != claim_token:
                raise SupervisorError("stale_fencing_token", "sandbox claim token is stale")
            if row["phase"] != "reserved":
                raise SupervisorError(
                    "sandbox_execution_transition_invalid",
                    f"expected phase reserved, found {row['phase']}; fence retained",
                )
            if row["launch_submission_id"] or row["launch_submission_at"]:
                raise SupervisorError(
                    "sandbox_execution_launch_submission_exists",
                    "this fenced execution already consumed its only runc submission opportunity",
                )
            if row["provider_proxy_artifact_json"] != "{}":
                raise SupervisorError(
                    "sandbox_execution_launch_submission_exists",
                    "provider proxy identity was already bound to this execution",
                )
            if row["launch_plan_required"] != 1:
                raise SupervisorError(
                    "sandbox_execution_launch_plan_required",
                    "launch submission requires the fully pinned workspace and runtime reservation",
                )
            if row["workspace_binding_version"] != 1:
                raise SupervisorError(
                    "sandbox_workspace_unbound",
                    "launch submission requires a durable baseline/workspace binding",
                )
            if row["private_path_binding_version"] != 1:
                raise SupervisorError(
                    "sandbox_private_path_unbound",
                    "launch submission requires exact private bundle/state directory identities",
                )
            if (
                not row["launch_driver_start_id"]
                or not row["launch_driver_start_digest"]
                or row["launch_driver_start_unit"]
                != _sandbox_launch_driver_service_unit(row["execution_id"])
                or not row["launch_driver_start_redeemed_at"]
                or row["launch_driver_start_redeemed_pid"] is None
                or not row["launch_driver_start_redeemed_invocation_id"]
                or not row["launch_driver_start_redeemed_identity"]
                or not row["launch_driver_start_redeemed_cgroup_path"]
                or row["launch_driver_start_redeemed_slice_unit"]
                != _oci_worker_systemd_slice(row["container_id"])
                or not row["launch_driver_start_redeemed_slice_invocation_id"]
                or not row["launch_driver_start_redeemed_slice_cgroup_path"]
                or row["launch_driver_start_redeemed_cgroup_path"]
                != row["launch_driver_start_redeemed_slice_cgroup_path"]
                + "/"
                + row["launch_driver_start_unit"]
            ):
                raise SupervisorError(
                    "sandbox_launch_driver_redemption_required",
                    "runc submission requires one exact redeemed service activation",
                )
            if row["launch_driver_start_redeemed_pid"] != os.getpid():
                raise SupervisorError(
                    "sandbox_launch_driver_redemption_required",
                    "runc submission must be authorized by the exact redeemed service MainPID",
                )
            try:
                live_redemption = collect_launch_driver_start_redemption(
                    expected_identity=(attempt_id, claim_token, row["execution_id"]),
                    expected_container_id=row["container_id"],
                    start_id=row["launch_driver_start_id"],
                    start_digest=row["launch_driver_start_digest"],
                    service_unit=row["launch_driver_start_unit"],
                    attempt_slice_unit=row["launch_driver_start_redeemed_slice_unit"],
                )
            except SupervisorError as error:
                raise SupervisorError(
                    "sandbox_launch_driver_redemption_stale",
                    "live service or attempt-slice activation is no longer active and exact",
                ) from error
            durable_redemption_fields = (
                row["launch_driver_start_unit"],
                row["launch_driver_start_id"],
                row["launch_driver_start_digest"],
                row["launch_driver_start_redeemed_invocation_id"],
                row["launch_driver_start_redeemed_pid"],
                row["launch_driver_start_redeemed_identity"],
                row["launch_driver_start_redeemed_cgroup_path"],
                row["launch_driver_start_redeemed_slice_unit"],
                row["launch_driver_start_redeemed_slice_invocation_id"],
                row["launch_driver_start_redeemed_slice_cgroup_path"],
            )
            live_redemption_fields = (
                live_redemption.service_unit,
                live_redemption.start_id,
                live_redemption.start_digest,
                live_redemption.service_invocation_id,
                live_redemption.driver_pid,
                live_redemption.driver_identity,
                live_redemption.driver_control_group,
                live_redemption.attempt_slice_unit,
                live_redemption.attempt_slice_invocation_id,
                live_redemption.attempt_slice_control_group,
            )
            if (
                not launch_driver_start_redemption_has_collector_provenance(live_redemption)
                or not launch_driver_start_redemption_is_self_consistent(live_redemption)
                or (live_redemption.attempt_id, live_redemption.claim_token)
                != (attempt_id, claim_token)
                or live_redemption.execution_id != row["execution_id"]
                or live_redemption_fields != durable_redemption_fields
            ):
                raise SupervisorError(
                    "sandbox_launch_driver_redemption_stale",
                    "live service or attempt-slice activation changed after redemption",
                )
            try:
                verify_linux_process_membership(
                    live_redemption.driver_pid,
                    expected_cgroup=live_redemption.driver_control_group,
                    expected_identity=live_redemption.driver_identity,
                )
            except SupervisorError as error:
                raise SupervisorError(
                    "sandbox_launch_driver_redemption_stale",
                    "redeemed MainPID identity or cgroup changed before runc submission",
                ) from error
            if any(
                _DIGEST.fullmatch(row[name] or "") is None
                for name in ("rootfs_closure_digest", "runc_executable_digest")
            ):
                raise SupervisorError(
                    "sandbox_execution_content_pins_required",
                    "launch submission requires pinned rootfs closure and runc executable digests",
                )
            provider_proxy_artifact_json = _sandbox_provider_proxy_artifact_json(
                row, provider_proxy_artifact
            )
            submission_row = dict(row)
            submission_row["provider_proxy_artifact_json"] = provider_proxy_artifact_json
            submission_digest = _sandbox_launch_submission_digest(submission_row, launch_target)
            submission_id = uuid.uuid4().hex
            submission = _SandboxLaunchSubmission(
                attempt_id=attempt_id,
                claim_token=claim_token,
                execution_id=row["execution_id"],
                submission_id=submission_id,
                submission_digest=submission_digest,
            )
            _register_sandbox_launch_submission(submission)
            try:
                with _authorize_sandbox_launch_submission_write(
                    connection,
                    attempt_id,
                    claim_token,
                    row["execution_id"],
                    submission_id,
                    submission_digest,
                ):
                    changed = connection.execute(
                        "UPDATE sandbox_executions SET provider_proxy_artifact_json = ?, "
                        "launch_submission_id = ?, launch_submission_digest = ?, "
                        "launch_submission_at = ?, updated_at = ? "
                        "WHERE attempt_id = ? AND claim_token = ? AND phase = 'reserved' "
                        "AND launch_submission_id = '' AND launch_submission_digest = '' "
                        "AND launch_submission_at = '' AND provider_proxy_artifact_json = '{}'",
                        (
                            provider_proxy_artifact_json,
                            submission_id,
                            submission_digest,
                            utc_now(),
                            utc_now(),
                            attempt_id,
                            claim_token,
                        ),
                    ).rowcount
                if changed != 1:
                    raise SupervisorError(
                        "sandbox_execution_transition_conflict",
                        "launch submission latch changed concurrently; attempt fence retained",
                    )
                self._event(
                    connection,
                    "sandbox.execution_launch_submission_authorized",
                    attempt["agent_id"],
                    {
                        "attempt_id": attempt_id,
                        "claim_token": claim_token,
                        "execution_id": row["execution_id"],
                        "submission_id": submission_id,
                        "submission_digest": submission_digest,
                        "provider_proxy_artifact_sha256": hashlib.sha256(
                            provider_proxy_artifact_json.encode("utf-8")
                        ).hexdigest(),
                        "boundary": "before_private_runc_exec_ack",
                    },
                )
            except BaseException:
                with _SANDBOX_LAUNCH_SUBMISSIONS_LOCK:
                    registered = _SANDBOX_LAUNCH_SUBMISSIONS.get(id(submission))
                    if registered is not None and registered[0]() is submission:
                        _SANDBOX_LAUNCH_SUBMISSIONS.pop(id(submission), None)
                raise
        _register_runc_launch_submission_target(submission, launch_target)
        return submission

    def _sandbox_execution_record_launch(
        self,
        attempt_id: str,
        claim_token: int,
        *,
        runc_handle: RuncLaunchHandle,
        launch_submission: _SandboxLaunchSubmission,
        attempt_slice_unit: str,
        attempt_slice_invocation_id: str,
        attempt_slice_cgroup_path: str,
        scope_unit: str,
        scope_invocation_id: str,
        cgroup_path: str,
        credential: str | None = None,
    ) -> dict[str, Any]:
        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        launch_target = _runc_launch_target(runc_handle)
        if not _runc_launch_handle_is_self_consistent(runc_handle) or launch_target is None:
            raise SupervisorError(
                "sandbox_execution_launch_handle_required",
                "sandbox launch requires registered provenance from a pinned-runc launcher",
            )
        if launch_target.launch_mode != "private_bundle":
            raise SupervisorError(
                "sandbox_execution_launch_target_mismatch",
                "diagnostic runc launches cannot be recorded as supervised attempts",
            )
        runc_client_pid = self._sandbox_pid(_runc_launch_pid(runc_handle), "runc_client_pid")
        runc_client_identity = self._sandbox_process_identity(
            _runc_launch_process_identity(runc_handle), "runc_client_identity"
        )
        attempt_slice_unit = self._sandbox_systemd_unit(
            attempt_slice_unit, "attempt_slice_unit", ".slice"
        )
        attempt_slice_invocation_id = self._sandbox_invocation_id(
            attempt_slice_invocation_id, "attempt_slice_invocation_id"
        )
        scope_unit = self._sandbox_systemd_unit(scope_unit, "scope_unit", ".scope")
        scope_invocation_id = self._sandbox_invocation_id(
            scope_invocation_id, "scope_invocation_id"
        )
        attempt_slice_cgroup_path = self._sandbox_text(
            attempt_slice_cgroup_path, "attempt_slice_cgroup_path", limit=4096
        )
        cgroup_path = self._sandbox_text(cgroup_path, "cgroup_path", limit=4096)
        attempt_slice_cgroup = PurePosixPath(attempt_slice_cgroup_path)
        cgroup = PurePosixPath(cgroup_path)
        cgroup_paths = (attempt_slice_cgroup, cgroup)
        if (
            any(not path.is_absolute() or path.as_posix() != str(path) for path in cgroup_paths)
            or any(part in {".", ".."} for path in cgroup_paths for part in path.parts)
            or attempt_slice_cgroup.name != attempt_slice_unit
            or cgroup.parent != attempt_slice_cgroup
            or cgroup.name != scope_unit
        ):
            raise SupervisorError(
                "sandbox_execution_invalid",
                "trusted monitor must be outside the worker slice and scope inside it",
            )
        if attempt_slice_unit != _oci_worker_systemd_slice(launch_target.container_id):
            raise SupervisorError(
                "sandbox_execution_launch_target_mismatch",
                "attempt slice does not match the pinned runc container identity",
            )
        with self.connect() as connection:
            durable_execution = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
        if not durable_execution:
            raise SupervisorError("sandbox_execution_not_found", "execution reservation is missing")
        if durable_execution["claim_token"] != claim_token:
            raise SupervisorError("stale_fencing_token", "claim token is stale")
        if durable_execution["launch_plan_required"] != 1:
            raise SupervisorError(
                "sandbox_execution_launch_plan_required",
                "legacy reservation has no trusted launch-plan requirement",
            )
        if durable_execution["workspace_binding_version"] != 1:
            raise SupervisorError(
                "sandbox_workspace_unbound",
                "sandbox launch requires a durable baseline/workspace binding",
            )
        if durable_execution["private_path_binding_version"] != 1:
            raise SupervisorError(
                "sandbox_private_path_unbound",
                "sandbox launch requires exact private bundle/state directory identities",
            )
        if durable_execution["phase"] != "reserved":
            raise SupervisorError(
                "sandbox_execution_transition_invalid",
                f"expected phase reserved, found {durable_execution['phase']}; fence retained",
            )
        if (
            not durable_execution["launch_driver_start_redeemed_at"]
            or durable_execution["launch_driver_start_redeemed_pid"] is None
            or not durable_execution["launch_driver_start_redeemed_invocation_id"]
            or not durable_execution["launch_driver_start_redeemed_identity"]
            or not durable_execution["launch_driver_start_redeemed_cgroup_path"]
            or attempt_slice_unit != durable_execution["launch_driver_start_redeemed_slice_unit"]
            or attempt_slice_invocation_id
            != durable_execution["launch_driver_start_redeemed_slice_invocation_id"]
            or attempt_slice_cgroup_path
            != durable_execution["launch_driver_start_redeemed_slice_cgroup_path"]
            or durable_execution["launch_driver_start_redeemed_cgroup_path"]
            != attempt_slice_cgroup_path + "/" + durable_execution["launch_driver_start_unit"]
        ):
            raise SupervisorError(
                "sandbox_launch_driver_redemption_mismatch",
                "attempt slice differs from the redeemed launch-driver placement",
            )
        submission_digest = _sandbox_launch_submission_digest(durable_execution, launch_target)
        if (
            durable_execution["launch_submission_id"]
            != getattr(launch_submission, "submission_id", None)
            or durable_execution["launch_submission_digest"] != submission_digest
            or not durable_execution["launch_submission_at"]
            or not _sandbox_launch_submission_is_self_consistent(
                launch_submission,
                attempt_id=attempt_id,
                claim_token=claim_token,
                execution_id=durable_execution["execution_id"],
                submission_digest=submission_digest,
            )
            or not _runc_launch_submission_is_bound_to_handle(runc_handle, launch_submission)
        ):
            raise SupervisorError(
                "sandbox_execution_launch_submission_required",
                "launch recording requires the exact process-local pre-runc submission capability",
            )
        if durable_execution["bundle_digest_semantics"] == _LEGACY_BUNDLE_DIGEST_SEMANTICS:
            raise SupervisorError(
                "sandbox_execution_legacy_bundle_digest",
                "legacy caller-asserted reservation digest is not eligible for a new launch",
            )
        if durable_execution["bundle_digest_semantics"] != _BUNDLE_DIGEST_SEMANTICS:
            raise SupervisorError(
                "sandbox_execution_bundle_digest_semantics_invalid",
                "reservation digest semantics are not recognized",
            )
        if durable_execution["bundle_digest"] != _sandbox_reservation_bundle_digest(
            durable_execution
        ):
            raise SupervisorError(
                "sandbox_execution_bundle_digest_mismatch",
                "reservation bundle digest does not match its host-derived identity and pins",
            )
        target_paths_match = (
            launch_target.bundle_path == durable_execution["bundle_path"]
            and launch_target.bundle_device == durable_execution["bundle_root_dev"]
            and launch_target.bundle_inode == durable_execution["bundle_root_ino"]
            and launch_target.rootfs_path == str(Path(durable_execution["bundle_path"]) / "rootfs")
            and launch_target.rootfs_sha256 == durable_execution["rootfs_digest"]
            and launch_target.rootfs_closure_sha256 == durable_execution["rootfs_closure_digest"]
            and launch_target.state_path == durable_execution["state_path"]
            and launch_target.state_device == durable_execution["state_root_dev"]
            and launch_target.state_inode == durable_execution["state_root_ino"]
            and launch_target.workspace_path == durable_execution["workspace_root_path"]
            and launch_target.workspace_device == durable_execution["workspace_root_dev"]
            and launch_target.workspace_inode == durable_execution["workspace_root_ino"]
            and launch_target.container_id == durable_execution["container_id"]
            and launch_target.runc_executable_sha256 == durable_execution["runc_executable_digest"]
        )
        if (
            not target_paths_match
            or launch_target.pid_file_path is None
            or Path(launch_target.pid_file_path).parent != Path(durable_execution["state_path"])
            or launch_target.config_sha256 is None
            or _DIGEST.fullmatch(launch_target.config_sha256) is None
            or any(
                type(value) is not int or value <= 0
                for value in (
                    launch_target.memory_limit_bytes,
                    launch_target.cpu_quota,
                    launch_target.cpu_period,
                    launch_target.pids_limit,
                )
            )
            or type(launch_target.rootfs_device) is not int
            or type(launch_target.rootfs_inode) is not int
            or type(launch_target.rootfs_snapshot_device) is not int
            or type(launch_target.rootfs_snapshot_inode) is not int
            or launch_target.rootfs_snapshot_sha256 != launch_target.rootfs_sha256
            or launch_target.rootfs_snapshot_closure_sha256 != launch_target.rootfs_closure_sha256
            or launch_target.rootfs_snapshot_entry_count != launch_target.rootfs_entry_count
            or launch_target.rootfs_snapshot_bytes != launch_target.rootfs_bytes
            or (launch_target.rootfs_snapshot_device, launch_target.rootfs_snapshot_inode)
            == (launch_target.rootfs_device, launch_target.rootfs_inode)
        ):
            raise SupervisorError(
                "sandbox_execution_launch_target_mismatch",
                "pinned-runc launch target does not match the exact durable reservation",
            )
        launch_config_digest = launch_target.config_sha256
        launch_argv_digest = hashlib.sha256(
            canonical_json(list(launch_target.argv)).encode("utf-8")
        ).hexdigest()
        _runc_launch_handle_bind_execution(
            runc_handle,
            attempt_id,
            claim_token,
            durable_execution["execution_id"],
            execution_gate_identity=_sandbox_execution_gate_identity(durable_execution),
            gate_release_guard=lambda: self._sandbox_execution_gate_release_is_allowed(
                attempt_id,
                claim_token,
                durable_execution["execution_id"],
                execution_root_path=_sandbox_execution_gate_identity(durable_execution)[0],
                execution_root_device=durable_execution["execution_root_dev"],
                execution_root_inode=durable_execution["execution_root_ino"],
            ),
        )
        from .sandbox_monitor_ipc import SandboxMonitorControlClient
        from .sandbox_monitor_receipt import SandboxMonitorReceipt
        from .sandbox_monitor_service import start_sandbox_execution_monitor

        expected_identity = (attempt_id, claim_token, durable_execution["execution_id"])
        execution_gate_identity = _sandbox_execution_gate_identity(durable_execution)
        with (
            _runc_launch_gate_lock_for_execution(*expected_identity) as locked_handle,
            _runc_execution_gate_fence(*execution_gate_identity),
        ):
            if locked_handle is not runc_handle:
                raise SupervisorError(
                    "sandbox_execution_launch_handle_required",
                    "monitor startup requires the exact locked launch handle",
                )
            with self.connect() as connection:
                locked_execution = connection.execute(
                    "SELECT * FROM sandbox_executions WHERE attempt_id = ?",
                    (attempt_id,),
                ).fetchone()
            if (
                locked_execution is None
                or locked_execution["claim_token"] != claim_token
                or locked_execution["execution_id"] != durable_execution["execution_id"]
                or locked_execution["phase"] != "reserved"
                or locked_execution["launch_submission_id"]
                != durable_execution["launch_submission_id"]
                or locked_execution["launch_submission_digest"] != submission_digest
                or locked_execution["bundle_digest"] != durable_execution["bundle_digest"]
            ):
                raise SupervisorError(
                    "sandbox_execution_transition_invalid",
                    "reserved execution changed before trusted monitor startup; fence retained",
                )
            try:
                monitor_client = start_sandbox_execution_monitor(
                    state_path=locked_execution["state_path"],
                    expected_identity=expected_identity,
                    scope_unit=scope_unit,
                    scope_invocation_id=scope_invocation_id,
                    scope_control_group=cgroup_path,
                    attempt_slice_control_group=attempt_slice_cgroup_path,
                )
                receipt = monitor_client._receipt
                status = monitor_client.status()
            except Exception as error:
                raise SupervisorError(
                    "sandbox_execution_monitor_unavailable",
                    "trusted monitor start or reconnect failed; launch gate remains closed and execution fences are retained",
                ) from error
            if type(receipt) is not SandboxMonitorReceipt:
                raise SupervisorError(
                    "sandbox_execution_monitor_identity_mismatch",
                    "monitor startup returned no typed durable service receipt",
                )
            monitor_identity = self._sandbox_process_identity(
                receipt.main_identity, "monitor_identity"
            )
            monitor_pid = self._sandbox_pid(receipt.main_pid, "monitor_pid")
            wrapper_unit = self._sandbox_systemd_unit(receipt.unit, "wrapper_unit", ".service")
            wrapper_invocation_id = self._sandbox_invocation_id(
                receipt.invocation_id, "wrapper_invocation_id"
            )
            wrapper_cgroup_path = self._sandbox_text(
                receipt.control_group, "wrapper_cgroup_path", limit=4096
            )
            wrapper_cgroup = PurePosixPath(wrapper_cgroup_path)
            if (
                (receipt.attempt_id, receipt.claim_token, receipt.execution_id) != expected_identity
                or wrapper_unit != _sandbox_monitor_service_unit(*expected_identity)
                or wrapper_unit == scope_unit
                or wrapper_cgroup.name != wrapper_unit
                or wrapper_cgroup.parent != PurePosixPath(receipt.monitor_slice_control_group)
                or wrapper_cgroup == attempt_slice_cgroup
                or wrapper_cgroup.is_relative_to(attempt_slice_cgroup)
                or attempt_slice_cgroup.is_relative_to(wrapper_cgroup)
                or any(_ATTEMPT_SLICE_COMPONENT.fullmatch(part) for part in wrapper_cgroup.parts)
                or receipt.attempt_slice_unit != attempt_slice_unit
                or receipt.attempt_slice_control_group != attempt_slice_cgroup_path
                or monitor_pid == runc_client_pid
                or status.outcome != "ok"
                or not isinstance(status.payload, dict)
                or status.payload.get("phase") != "running"
                or status.payload.get("scope_unit") != scope_unit
                or status.payload.get("scope_invocation_id") != scope_invocation_id
                or status.payload.get("scope_control_group") != cgroup_path
            ):
                raise SupervisorError(
                    "sandbox_execution_monitor_identity_mismatch",
                    "authenticated monitor does not attest the exact fenced worker scope",
                )

            launch_plan = _sandbox_launch_plan_material(durable_execution, launch_target)
            launch_plan["launch"]["systemd_ownership"] = {
                "wrapper_control_group": wrapper_cgroup_path,
                "monitor_placement": "outside_attempt_slice",
                "attempt_slice_unit": attempt_slice_unit,
                "attempt_slice_invocation_id": attempt_slice_invocation_id,
                "attempt_slice_control_group": attempt_slice_cgroup_path,
            }
            launch_plan_json = canonical_json(launch_plan)
            launch_plan_digest = hashlib.sha256(launch_plan_json.encode("utf-8")).hexdigest()
            updates = {
                "monitor_pid": monitor_pid,
                "monitor_identity": monitor_identity,
                "runc_client_pid": runc_client_pid,
                "runc_client_identity": runc_client_identity,
                "wrapper_unit": wrapper_unit,
                "wrapper_invocation_id": wrapper_invocation_id,
                "wrapper_cgroup_path": wrapper_cgroup_path,
                "attempt_slice_unit": attempt_slice_unit,
                "attempt_slice_invocation_id": attempt_slice_invocation_id,
                "attempt_slice_cgroup_path": attempt_slice_cgroup_path,
                "scope_unit": scope_unit,
                "scope_invocation_id": scope_invocation_id,
                "cgroup_path": cgroup_path,
                "launch_plan_binding_version": 1,
                "launch_plan_json": launch_plan_json,
                "launch_config_digest": launch_config_digest,
                "launch_argv_digest": launch_argv_digest,
                "launch_plan_digest": launch_plan_digest,
            }
            with self.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                with _authorize_sandbox_launch_plan_write(
                    connection,
                    runc_handle,
                    attempt_id,
                    claim_token,
                    durable_execution["execution_id"],
                    launch_plan_json,
                    launch_plan_digest,
                ):
                    updated = self._sandbox_execution_transition(
                        attempt_id,
                        claim_token,
                        expected_phase="reserved",
                        next_phase="launched",
                        updates=updates,
                        event_type="sandbox.execution_launched",
                        event_payload={
                            **updates,
                            "launch_plan": launch_plan,
                            "launch_target": {
                                "mode": launch_target.launch_mode,
                                "runc_executable_path": launch_target.runc_executable_path,
                                "runc_executable_sha256": launch_target.runc_executable_sha256,
                                "config_sha256": launch_target.config_sha256,
                                "config_sha256_semantics": "sha256-exact-config-json-bytes",
                                "argv_sha256": launch_argv_digest,
                                "container_id": launch_target.container_id,
                                "bundle": {
                                    "path": launch_target.bundle_path,
                                    "device": launch_target.bundle_device,
                                    "inode": launch_target.bundle_inode,
                                },
                                "rootfs": {
                                    "path": launch_target.rootfs_path,
                                    "device": launch_target.rootfs_device,
                                    "inode": launch_target.rootfs_inode,
                                    "sha256": launch_target.rootfs_sha256,
                                    "closure_sha256": launch_target.rootfs_closure_sha256,
                                    "snapshot": {
                                        "device": launch_target.rootfs_snapshot_device,
                                        "inode": launch_target.rootfs_snapshot_inode,
                                        "sha256": launch_target.rootfs_snapshot_sha256,
                                        "closure_sha256": launch_target.rootfs_snapshot_closure_sha256,
                                        "entry_count": launch_target.rootfs_snapshot_entry_count,
                                        "bytes": launch_target.rootfs_snapshot_bytes,
                                    },
                                },
                                "state": {
                                    "path": launch_target.state_path,
                                    "device": launch_target.state_device,
                                    "inode": launch_target.state_inode,
                                },
                                "workspace": {
                                    "path": launch_target.workspace_path,
                                    "device": launch_target.workspace_device,
                                    "inode": launch_target.workspace_inode,
                                },
                                "pid_file_path": launch_target.pid_file_path,
                            },
                        },
                        credential=credential,
                        _connection=connection,
                    )
            if (
                type(monitor_client) is SandboxMonitorControlClient
                and monitor_client._receipt is receipt
                and (receipt.attempt_id, receipt.claim_token, receipt.execution_id)
                == expected_identity
                and receipt.controller_pid == os.getpid()
            ):
                # The recovery path intentionally rejects the process that
                # originally created the monitor. Retain only this exact
                # authenticated startup client on the exact launch handle so
                # its owner can cancel without weakening recovery checks.
                locked_handle._monitor_client = monitor_client
            return updated

    def _sandbox_execution_gate_release_is_allowed(
        self,
        attempt_id: str,
        claim_token: int,
        execution_id: str,
        *,
        execution_root_path: str,
        execution_root_device: int,
        execution_root_inode: int,
    ) -> bool:
        """Recheck the durable execution while holding its cross-process gate fence."""

        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            attempt = connection.execute(
                "SELECT status, claim_token FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
            if (
                row is None
                or attempt is None
                or row["claim_token"] != claim_token
                or row["execution_id"] != execution_id
                or _sandbox_execution_gate_identity(row)
                != (execution_root_path, execution_root_device, execution_root_inode)
                or row["phase"] != "running"
                or row["stop_reason"]
                or attempt["claim_token"] != claim_token
                or attempt["status"] != "working"
                or _sandbox_execution_launch_stop_reason(connection, row)
            ):
                return False
        return True

    def _sandbox_execution_record_running(
        self,
        attempt_id: str,
        claim_token: int,
        *,
        attestation: RunningRuntimeAttestation,
        runc_handle: RuncLaunchHandle | None = None,
        credential: str | None = None,
    ) -> dict[str, Any]:
        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            launch_stop_reason = (
                _sandbox_execution_launch_stop_reason(connection, row) if row else None
            )
        if not row or row["claim_token"] != claim_token:
            raise SupervisorError("sandbox_execution_not_found", "execution reservation is missing")
        if row["phase"] != "launched":
            raise SupervisorError(
                "sandbox_execution_transition_invalid",
                f"cannot record running from phase {row['phase']}; fence retained",
            )
        if row["stop_reason"] or launch_stop_reason:
            raise SupervisorError(
                "sandbox_execution_transition_invalid",
                "running transition is fenced by a durable stop request",
            )
        if not _sandbox_launch_plan_binding_is_self_consistent(row):
            raise SupervisorError(
                "sandbox_execution_launch_plan_required",
                "running transition requires a durable trusted launch-plan binding",
            )
        launch_plan = json.loads(row["launch_plan_json"])
        if launch_plan.get("version") not in {5, 6}:
            raise SupervisorError(
                "sandbox_execution_launch_plan_required",
                "running transition requires a supported plan with a separate trusted monitor cgroup",
            )
        if not running_attestation_is_self_consistent(
            attestation
        ) or not running_attestation_has_collector_provenance(attestation):
            raise SupervisorError(
                "sandbox_runtime_attestation_invalid",
                "running transition requires the exact self-consistent collector-issued receipt",
            )
        if attestation.launch_driver_pid != os.getpid():
            raise SupervisorError(
                "sandbox_runtime_attestation_stale",
                "running transition must be recorded by the exact launch-driver service MainPID",
            )
        expected_resource_limits = launch_plan["launch"]["resource_limits"]
        attested_resource_limits = {
            "memory_max_bytes": attestation.memory_max_bytes,
            "cpu_quota": attestation.cpu_quota,
            "cpu_period": attestation.cpu_period,
            "pids_max": attestation.pids_max,
        }
        if attested_resource_limits != expected_resource_limits:
            raise SupervisorError(
                "sandbox_runtime_attestation_stale",
                "cgroup resource readback does not match the durable OCI launch policy",
            )
        expected = _sandbox_running_attestation_expected_for_row(row)
        if any(getattr(attestation, key) != value for key, value in expected.items()):
            raise SupervisorError(
                "sandbox_runtime_attestation_stale",
                "runtime evidence does not match the durable launch identities",
            )
        redeemed_driver_identity = {
            "launch_driver_pid": row["launch_driver_start_redeemed_pid"],
            "launch_driver_identity": row["launch_driver_start_redeemed_identity"],
            "launch_driver_unit": row["launch_driver_start_unit"],
            "launch_driver_invocation_id": row["launch_driver_start_redeemed_invocation_id"],
            "launch_driver_control_group": row["launch_driver_start_redeemed_cgroup_path"],
            "attempt_slice_unit": row["launch_driver_start_redeemed_slice_unit"],
            "attempt_slice_invocation_id": row["launch_driver_start_redeemed_slice_invocation_id"],
            "attempt_slice_control_group": row["launch_driver_start_redeemed_slice_cgroup_path"],
        }
        if not row["launch_driver_start_redeemed_at"] or any(
            getattr(attestation, key) != value for key, value in redeemed_driver_identity.items()
        ):
            raise SupervisorError(
                "sandbox_runtime_attestation_stale",
                "running evidence does not match the once-redeemed launch-driver activation",
            )
        init_pid = self._sandbox_pid(attestation.init_pid, "init_pid")
        init_identity = self._sandbox_process_identity(attestation.init_identity, "init_identity")
        if init_pid in {
            row["monitor_pid"],
            row["runc_client_pid"],
            attestation.launch_driver_pid,
        }:
            raise SupervisorError(
                "sandbox_execution_invalid", "container init must have a distinct host PID"
            )
        if not _runc_launch_handle_is_bound_to_execution(
            runc_handle, attempt_id, claim_token, row["execution_id"]
        ):
            raise SupervisorError(
                "sandbox_execution_launch_handle_required",
                "running transition requires the exact registered launch handle",
            )
        with (
            _runc_launch_gate_lock_for_execution(
                attempt_id, claim_token, row["execution_id"]
            ) as locked_handle,
            _runc_execution_gate_fence(*_sandbox_execution_gate_identity(row)),
        ):
            if locked_handle is not runc_handle:
                raise SupervisorError(
                    "sandbox_execution_launch_handle_required",
                    "running transition requires the exact locked launch handle",
                )
            with self.connect() as connection:
                locked_row = connection.execute(
                    "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
                ).fetchone()
                locked_launch_stop_reason = (
                    _sandbox_execution_launch_stop_reason(connection, locked_row)
                    if locked_row
                    else None
                )
            if (
                locked_row is None
                or locked_row["claim_token"] != claim_token
                or locked_row["execution_id"] != row["execution_id"]
                or locked_row["state_path"] != row["state_path"]
                or locked_row["state_root_dev"] != row["state_root_dev"]
                or locked_row["state_root_ino"] != row["state_root_ino"]
                or locked_row["phase"] != "launched"
                or locked_row["stop_reason"]
                or locked_launch_stop_reason
                or not _sandbox_launch_plan_binding_is_self_consistent(locked_row)
            ):
                raise SupervisorError(
                    "sandbox_runtime_attestation_stale",
                    "durable launch plan changed before the running transition",
                )
            locked_plan = json.loads(locked_row["launch_plan_json"])
            locked_launch = locked_plan["launch"]
            locked_state = locked_launch["state"]
            expected_source_binding = {
                "runc_state_root_path": locked_state["path"],
                "runc_state_root_device": locked_state["device"],
                "runc_state_root_inode": locked_state["inode"],
                "runc_pid_file_path": locked_launch["pid_file_path"],
                "runc_executable_sha256": locked_launch["runc_executable_sha256"],
            }
            if any(
                getattr(attestation, key) != value for key, value in expected_source_binding.items()
            ):
                raise SupervisorError(
                    "sandbox_runtime_attestation_stale",
                    "runc observations do not match the exact durable state root and executable",
                )
            try:
                live_state_root = _private_directory(
                    expected_source_binding["runc_state_root_path"],
                    code="sandbox_runtime_attestation_stale",
                    label="runc state root",
                )
                live_state_info = live_state_root.lstat()
            except (OSError, SupervisorError) as error:
                raise SupervisorError(
                    "sandbox_runtime_attestation_stale",
                    "durable runc state root is no longer available",
                ) from error
            if (
                str(live_state_root) != expected_source_binding["runc_state_root_path"]
                or stat.S_ISLNK(live_state_info.st_mode)
                or not stat.S_ISDIR(live_state_info.st_mode)
                or (live_state_info.st_dev, live_state_info.st_ino)
                != (
                    expected_source_binding["runc_state_root_device"],
                    expected_source_binding["runc_state_root_inode"],
                )
            ):
                raise SupervisorError(
                    "sandbox_runtime_attestation_stale",
                    "durable runc state root identity changed before gate release",
                )
            locked_expected = _sandbox_running_attestation_expected_for_row(locked_row)
            if any(getattr(attestation, key) != value for key, value in locked_expected.items()):
                raise SupervisorError(
                    "sandbox_runtime_attestation_stale",
                    "runtime evidence no longer matches the exact locked launch identities",
                )
            locked_resource_limits = locked_launch["resource_limits"]
            if any(
                getattr(attestation, key) != value for key, value in locked_resource_limits.items()
            ):
                raise SupervisorError(
                    "sandbox_runtime_attestation_stale",
                    "cgroup limits no longer match the exact locked launch policy",
                )
            # Revalidate exact live process membership and cgroup limits under
            # the release lock before the durable transition and one-shot permit.
            verify_running_runtime_resource_controls(attestation)
            verify_running_runtime_process_membership(attestation)
            verify_running_runtime_systemd_units(attestation)
            with self.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                active_attempt = self._active_attempt(
                    connection, attempt_id, claim_token, int(time.time())
                )
                if active_attempt["status"] != "working":
                    raise SupervisorError("claim_inactive", "sandbox attempt is no longer working")
                self._authenticate_attempt(connection, active_attempt, credential)
                current_row = connection.execute(
                    "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
                ).fetchone()
                current_stop_reason = (
                    _sandbox_execution_launch_stop_reason(connection, current_row)
                    if current_row
                    else None
                )
                if current_row is None:
                    raise SupervisorError(
                        "sandbox_execution_not_found", "execution was not reserved"
                    )
                if current_row["claim_token"] != claim_token:
                    raise SupervisorError("stale_fencing_token", "sandbox claim token is stale")
                if current_row["phase"] != "launched":
                    raise SupervisorError(
                        "sandbox_execution_transition_invalid",
                        f"cannot record running from phase {current_row['phase']}; fence retained",
                    )
                if (
                    current_row["stop_reason"]
                    or current_stop_reason
                    or current_row["execution_id"] != locked_row["execution_id"]
                    or current_row["launch_plan_digest"] != locked_row["launch_plan_digest"]
                    or current_row["launch_plan_json"] != locked_row["launch_plan_json"]
                    or not _sandbox_launch_plan_binding_is_self_consistent(current_row)
                    or any(
                        getattr(attestation, key) != value
                        for key, value in _sandbox_running_attestation_expected_for_row(
                            current_row
                        ).items()
                    )
                    or not current_row["launch_driver_start_redeemed_at"]
                    or any(
                        getattr(attestation, key) != value
                        for key, value in {
                            "launch_driver_pid": current_row["launch_driver_start_redeemed_pid"],
                            "launch_driver_identity": current_row[
                                "launch_driver_start_redeemed_identity"
                            ],
                            "launch_driver_unit": current_row["launch_driver_start_unit"],
                            "launch_driver_invocation_id": current_row[
                                "launch_driver_start_redeemed_invocation_id"
                            ],
                            "launch_driver_control_group": current_row[
                                "launch_driver_start_redeemed_cgroup_path"
                            ],
                            "attempt_slice_unit": current_row[
                                "launch_driver_start_redeemed_slice_unit"
                            ],
                            "attempt_slice_invocation_id": current_row[
                                "launch_driver_start_redeemed_slice_invocation_id"
                            ],
                            "attempt_slice_control_group": current_row[
                                "launch_driver_start_redeemed_slice_cgroup_path"
                            ],
                        }.items()
                    )
                ):
                    raise SupervisorError(
                        "sandbox_runtime_attestation_stale",
                        "durable launch identities changed before the running transition",
                    )
                running_updates = {
                    "init_pid": init_pid,
                    "init_identity": init_identity,
                    "launch_driver_pid": attestation.launch_driver_pid,
                    "launch_driver_identity": attestation.launch_driver_identity,
                    "launch_driver_unit": attestation.launch_driver_unit,
                    "launch_driver_invocation_id": attestation.launch_driver_invocation_id,
                    "launch_driver_cgroup_path": attestation.launch_driver_control_group,
                }
                assignments = ", ".join(f"{name} = ?" for name in running_updates)
                expected_authorization = (
                    attempt_id,
                    claim_token,
                    current_row["execution_id"],
                    attestation.launch_driver_pid,
                    attestation.launch_driver_identity,
                    attestation.launch_driver_unit,
                    attestation.launch_driver_invocation_id,
                    attestation.launch_driver_control_group,
                )

                def authorize_running_attestation(*fields: Any) -> int:
                    return int(fields == expected_authorization)

                # The public store facade deliberately withholds SQLite callback
                # registration. Install this exact-row grant on its private backing
                # connection only after every launch and attestation check above.
                raw_connection = _store_raw_connection_for_running_transition(connection)
                sqlite3.Connection.create_function(
                    raw_connection,
                    "acp_sandbox_running_attestation_authorized",
                    8,
                    authorize_running_attestation,
                )
                changed = connection.execute(
                    f"UPDATE sandbox_executions SET {assignments}, phase = 'running', "
                    "updated_at = ? WHERE attempt_id = ? AND claim_token = ? "
                    "AND execution_id = ? AND phase = 'launched'",
                    (
                        *running_updates.values(),
                        utc_now(),
                        attempt_id,
                        claim_token,
                        current_row["execution_id"],
                    ),
                ).rowcount
                if changed != 1:
                    raise SupervisorError(
                        "sandbox_execution_transition_conflict",
                        "execution journal changed concurrently; attempt fence retained",
                    )
                self._event(
                    connection,
                    "sandbox.execution_running",
                    active_attempt["agent_id"],
                    {
                        "attempt_id": attempt_id,
                        "claim_token": claim_token,
                        "execution_id": current_row["execution_id"],
                        "phase": "running",
                        "attestation": attestation.audit_payload(),
                    },
                )
                updated = connection.execute(
                    "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
                ).fetchone()
            _authorize_runc_launch_gate_release_locked(
                locked_handle, attempt_id, claim_token, row["execution_id"]
            )
            return self._sandbox_execution_view(updated)

    def _sandbox_execution_request_stop(
        self,
        attempt_id: str,
        claim_token: int,
        reason: str,
        *,
        credential: str | None = None,
    ) -> dict[str, Any]:
        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        reason = self._sandbox_text(reason, "stop_reason", limit=512)
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        if not row or row["claim_token"] != claim_token:
            raise SupervisorError("sandbox_execution_not_found", "execution reservation is missing")
        execution_id = row["execution_id"]
        state_identity = (row["state_path"], row["state_root_dev"], row["state_root_ino"])
        with (
            _runc_launch_gate_lock_for_execution(
                attempt_id, claim_token, execution_id
            ) as locked_handle,
            _runc_execution_gate_fence(*_sandbox_execution_gate_identity(row)),
        ):
            # Re-read after acquiring the release lock: this closes both the
            # launched->stopping and running->stopping races against gate open.
            with self.connect() as connection:
                row = connection.execute(
                    "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
                ).fetchone()
            if not row or row["claim_token"] != claim_token:
                raise SupervisorError(
                    "sandbox_execution_not_found", "execution reservation is missing"
                )
            if row["execution_id"] != execution_id:
                raise SupervisorError(
                    "sandbox_execution_transition_conflict",
                    "durable execution identity changed while requesting stop",
                )
            if (row["state_path"], row["state_root_dev"], row["state_root_ino"]) != state_identity:
                raise SupervisorError(
                    "sandbox_execution_gate_identity_mismatch",
                    "durable state-root identity changed while requesting stop; fence retained",
                )
            if row["phase"] == "stopping":
                # An existing stop intent is idempotent only while this exact
                # attempt still owns a live lease. In particular, do not let a
                # launch driver adopt a stale `stopping` row after expiry: the
                # caller must route that lease loss through quarantine.
                with self.connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    attempt = self._active_attempt(
                        connection, attempt_id, claim_token, int(time.time())
                    )
                    self._authenticate_attempt(connection, attempt, credential)
                    durable_row = connection.execute(
                        "SELECT * FROM sandbox_executions WHERE attempt_id = ?",
                        (attempt_id,),
                    ).fetchone()
                    if (
                        durable_row is None
                        or durable_row["claim_token"] != claim_token
                        or durable_row["execution_id"] != execution_id
                        or durable_row["phase"] != "stopping"
                    ):
                        raise SupervisorError(
                            "sandbox_execution_transition_conflict",
                            "execution changed before adopting its stop intent",
                        )
                    row = durable_row
                if row["stop_reason"] != reason:
                    raise SupervisorError(
                        "sandbox_execution_transition_conflict",
                        "a different stop reason is already durable; fence retained",
                    )
                updated = self._sandbox_execution_view(row)
            elif row["phase"] == "launched":
                if row["stop_reason"] and row["stop_reason"] != reason:
                    raise SupervisorError(
                        "sandbox_execution_transition_conflict",
                        "a different stop reason is already durable; fence retained",
                    )
                # A pre-running launch has no init PID, so it cannot enter the
                # `stopping` phase (whose schema requires that identity). Persist
                # intent as an append-only, hash-chained event; record_running
                # checks it under the same gate lock before it can authorize GO.
                with self.connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    attempt = self._active_attempt(
                        connection, attempt_id, claim_token, int(time.time())
                    )
                    if attempt["status"] != "working":
                        raise SupervisorError(
                            "claim_inactive", "sandbox attempt is no longer working"
                        )
                    self._authenticate_attempt(connection, attempt, credential)
                    durable_row = connection.execute(
                        "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
                    ).fetchone()
                    if (
                        durable_row is None
                        or durable_row["claim_token"] != claim_token
                        or durable_row["execution_id"] != execution_id
                        or durable_row["phase"] != "launched"
                    ):
                        raise SupervisorError(
                            "sandbox_execution_transition_conflict",
                            "execution changed before recording pre-running stop intent",
                        )
                    existing_intent = _sandbox_execution_launch_stop_reason(connection, durable_row)
                    if existing_intent and existing_intent != reason:
                        raise SupervisorError(
                            "sandbox_execution_transition_conflict",
                            "a different stop reason is already durable; fence retained",
                        )
                    if existing_intent is None:
                        self._event(
                            connection,
                            "sandbox.execution_stop_requested",
                            attempt["agent_id"],
                            {
                                "attempt_id": attempt_id,
                                "claim_token": claim_token,
                                "execution_id": execution_id,
                                "phase": "launched",
                                "stop_reason": reason,
                                "stop_pending": True,
                            },
                        )
                    updated = self._sandbox_execution_view(durable_row)
                    updated["stop_reason"] = reason
                    updated["stop_requested"] = True
            else:
                if row["phase"] != "running":
                    raise SupervisorError(
                        "sandbox_execution_transition_invalid",
                        f"cannot request stop from phase {row['phase']}; fence retained",
                    )
                updated = self._sandbox_execution_transition(
                    attempt_id,
                    claim_token,
                    expected_phase=row["phase"],
                    next_phase="stopping",
                    updates={"stop_reason": reason},
                    event_type="sandbox.execution_stop_requested",
                    event_payload={"stop_reason": reason},
                    credential=credential,
                )
            if locked_handle is not None:
                _revoke_runc_launch_gate_release_locked(
                    locked_handle, attempt_id, claim_token, execution_id
                )
            return updated

    def _sandbox_execution_record_exit(
        self,
        attempt_id: str,
        claim_token: int,
        wait_receipt: _RuncClientWaitReceipt,
        *,
        credential: str | None = None,
        _allow_quarantined_failure: bool = False,
    ) -> dict[str, Any]:
        if not _runc_client_wait_receipt_is_self_consistent(wait_receipt):
            raise SupervisorError(
                "sandbox_execution_wait_receipt_required",
                "runc exit recording requires a sealed receipt issued by the pinned-runc wait handle",
            )
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        if (
            row is None
            or row["claim_token"] != claim_token
            or row["execution_id"] != wait_receipt.execution_id
        ):
            raise SupervisorError(
                "sandbox_execution_wait_receipt_stale",
                "runc wait receipt has no matching durable execution identity",
            )
        state_identity = (row["state_path"], row["state_root_dev"], row["state_root_ino"])
        with (
            _runc_launch_gate_lock_for_execution(
                attempt_id, claim_token, wait_receipt.execution_id
            ) as locked_handle,
            _runc_execution_gate_fence(*_sandbox_execution_gate_identity(row)),
        ):
            with self.connect() as connection:
                locked_row = connection.execute(
                    "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
                ).fetchone()
            if (
                locked_row is None
                or locked_row["claim_token"] != claim_token
                or locked_row["execution_id"] != wait_receipt.execution_id
                or (
                    locked_row["state_path"],
                    locked_row["state_root_dev"],
                    locked_row["state_root_ino"],
                )
                != state_identity
            ):
                raise SupervisorError(
                    "sandbox_execution_gate_identity_mismatch",
                    "execution changed before its exit receipt was committed; fence retained",
                )
            updated = self._sandbox_execution_record_exit_under_gate_lock(
                attempt_id,
                claim_token,
                wait_receipt,
                credential=credential,
                _allow_quarantined_failure=_allow_quarantined_failure,
            )
            if locked_handle is not None:
                _revoke_runc_launch_gate_release_locked(
                    locked_handle,
                    attempt_id,
                    claim_token,
                    wait_receipt.execution_id,
                )
                # The monitor key is process-local and no longer needed after
                # the exact runc child has a durable kernel-wait receipt.
                locked_handle._monitor_client = None
            return updated

    def _sandbox_execution_record_exit_under_gate_lock(
        self,
        attempt_id: str,
        claim_token: int,
        wait_receipt: _RuncClientWaitReceipt,
        *,
        credential: str | None = None,
        _allow_quarantined_failure: bool = False,
    ) -> dict[str, Any]:
        """Persist exit evidence while its release gate cannot be opened."""

        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        if not _runc_client_wait_receipt_is_self_consistent(wait_receipt):
            raise SupervisorError(
                "sandbox_execution_wait_receipt_required",
                "runc exit recording requires a sealed receipt issued by the pinned-runc wait handle",
            )
        exit_code = wait_receipt.returncode
        if type(exit_code) is not int or not -255 <= exit_code <= 255:
            raise SupervisorError("sandbox_execution_invalid", "runc exit code is invalid")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if not row:
                raise SupervisorError(
                    "sandbox_execution_not_found", "execution reservation is missing"
                )
            if row["claim_token"] != claim_token:
                raise SupervisorError("stale_fencing_token", "sandbox claim token is stale")
            if row["phase"] in {"launched", "running", "stopping", "ambiguous"} and not (
                _sandbox_launch_plan_binding_is_self_consistent(row)
            ):
                raise SupervisorError(
                    "sandbox_execution_launch_plan_required",
                    "exit transition requires a durable trusted launch-plan binding",
                )
            if (
                wait_receipt.pid != row["runc_client_pid"]
                or wait_receipt.process_identity != row["runc_client_identity"]
                or wait_receipt.attempt_id != row["attempt_id"]
                or wait_receipt.claim_token != row["claim_token"]
                or wait_receipt.execution_id != row["execution_id"]
            ):
                raise SupervisorError(
                    "sandbox_execution_wait_receipt_stale",
                    "runc wait receipt does not match the durable launch process identity",
                )
            if row["phase"] in {"exited", "cleanup_reported", "cleanup_verified"}:
                if row["runc_exit_code"] == exit_code:
                    if row["runc_exit_evidence_source"] == "runc_client_kernel_waitpid":
                        return self._sandbox_execution_view(row)
                    raise SupervisorError(
                        "sandbox_execution_evidence_unverified",
                        "legacy exit row has no durable kernel-wait evidence",
                    )
                raise SupervisorError(
                    "sandbox_execution_transition_conflict", "conflicting runc exit receipt"
                )
            if row["phase"] not in {"launched", "running", "stopping"} and not (
                _allow_quarantined_failure
                and row["phase"] == "ambiguous"
                and row["failure_reason"] == _LAUNCH_DRIVER_LEASE_LOSS_REASON
            ):
                raise SupervisorError(
                    "sandbox_execution_transition_invalid",
                    f"cannot record exit from phase {row['phase']}; fence retained",
                )
            if _allow_quarantined_failure:
                attempt = connection.execute(
                    "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
                ).fetchone()
                task = (
                    connection.execute(
                        "SELECT current_attempt_id, status, cleanup_target_status "
                        "FROM tasks WHERE id = ?",
                        (attempt["task_id"],),
                    ).fetchone()
                    if attempt is not None
                    else None
                )
                if (
                    attempt is None
                    or attempt["claim_token"] != claim_token
                    or attempt["status"] != "terminating"
                    or attempt["termination_target_status"] != "quarantined"
                    or row["phase"] != "ambiguous"
                    or row["failure_reason"] != _LAUNCH_DRIVER_LEASE_LOSS_REASON
                    or task is None
                    or task["current_attempt_id"] != attempt_id
                    or task["status"] != "cleanup_pending"
                    or task["cleanup_target_status"] != "blocked"
                ):
                    raise SupervisorError(
                        "sandbox_execution_transition_conflict",
                        "quarantined exit receipt is not authorized for this exact lease-loss execution",
                    )
            else:
                attempt = self._active_attempt(
                    connection, attempt_id, claim_token, int(time.time())
                )
                if attempt["status"] != "working":
                    raise SupervisorError("claim_inactive", "sandbox attempt is no longer working")
            self._authenticate_attempt(connection, attempt, credential)
            with _authorize_sandbox_exit_receipt_write(connection, wait_receipt):
                changed = connection.execute(
                    "UPDATE sandbox_executions SET runc_exit_code = ?, "
                    "runc_exit_observed_by = 'runc_client_popen_wait', "
                    "runc_exit_evidence_source = 'runc_client_kernel_waitpid', "
                    "phase = 'exited', updated_at = ? "
                    "WHERE attempt_id = ? AND claim_token = ? AND phase = ?",
                    (exit_code, utc_now(), attempt_id, claim_token, row["phase"]),
                ).rowcount
            if changed != 1:
                raise SupervisorError(
                    "sandbox_execution_transition_conflict",
                    "execution journal changed concurrently; fence retained",
                )
            self._event(
                connection,
                "sandbox.execution_exited",
                attempt["agent_id"],
                {
                    "attempt_id": attempt_id,
                    "claim_token": claim_token,
                    "execution_id": row["execution_id"],
                    "phase": "exited",
                    "runc_exit_code": exit_code,
                    "observed_by": "runc_client_kernel_waitpid",
                    "recovered_after_lease_loss": _allow_quarantined_failure,
                },
            )
            updated = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        return self._sandbox_execution_view(updated)

    def _sandbox_execution_record_cleanup_report(
        self,
        attempt_id: str,
        claim_token: int,
        receipt: dict[str, Any] | None = None,
        *,
        runc_delete_receipt: Any | None = None,
        recovery_receipt: Any | None = None,
        credential: str | None = None,
        _allow_quarantined_failure: bool = False,
        _reaper_epoch: int | None = None,
    ) -> dict[str, Any]:
        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        if not row or row["claim_token"] != claim_token:
            raise SupervisorError("sandbox_execution_not_found", "execution reservation is missing")
        if runc_delete_receipt is not None and recovery_receipt is not None:
            raise SupervisorError(
                "sandbox_cleanup_report_invalid",
                "cleanup report cannot mix driver and recovery receipts",
            )
        action_payload = None
        if runc_delete_receipt is not None:
            action_payload = self._sandbox_cleanup_action_payload(row, runc_delete_receipt)
        if recovery_receipt is not None:
            if (
                not _sandbox_cleanup_recovery_receipt_is_self_consistent(recovery_receipt)
                or recovery_receipt.attempt_id != attempt_id
                or recovery_receipt.claim_token != claim_token
                or recovery_receipt.execution_id != row["execution_id"]
                or recovery_receipt.launch_submission_id != row["launch_submission_id"]
                or recovery_receipt.launch_submission_digest != row["launch_submission_digest"]
                or recovery_receipt.reaper_epoch != _reaper_epoch
                or not self._sandbox_cleanup_recovery_receipt_is_self_consistent(
                    row, recovery_receipt.encoded
                )
            ):
                raise SupervisorError(
                    "sandbox_cleanup_recovery_required",
                    "recovery report requires the registered exact restart-verifier receipt",
                )
            expected = json.loads(recovery_receipt.encoded)
            expected_encoded = recovery_receipt.encoded
        else:
            expected = self._sandbox_cleanup_receipt(row, action_payload=action_payload)
            expected_encoded = canonical_json(expected)
        if receipt is None and runc_delete_receipt is not None:
            receipt = expected
        if receipt is None and recovery_receipt is not None:
            receipt = expected
        if not isinstance(receipt, dict):
            raise SupervisorError(
                "sandbox_cleanup_report_invalid",
                "cleanup report is incomplete or is not bound to the recorded identities",
            )
        encoded = canonical_json(receipt)
        if len(encoded.encode("utf-8")) > 64 * 1024:
            raise SupervisorError("sandbox_cleanup_report_invalid", "cleanup report is too large")
        if row["phase"] == "cleanup_reported":
            persisted = row["cleanup_receipt_json"]
            legacy_v2_encoded = canonical_json(self._sandbox_cleanup_receipt_v2_legacy(row))
            legacy_encoded = canonical_json(self._sandbox_cleanup_receipt_v1(row))
            if encoded == persisted and (
                persisted in {expected_encoded, legacy_v2_encoded, legacy_encoded}
                or self._sandbox_cleanup_receipt_v3_is_self_consistent(row, persisted)
                or self._sandbox_cleanup_recovery_receipt_is_self_consistent(row, persisted)
            ):
                return self._sandbox_execution_view(row)
            if encoded != expected_encoded:
                raise SupervisorError(
                    "sandbox_cleanup_report_invalid",
                    "cleanup report is incomplete or is not bound to the recorded identities",
                )
            raise SupervisorError(
                "sandbox_execution_transition_conflict",
                "cleanup receipt is already recorded and cannot be replaced",
            )
        if encoded != expected_encoded:
            raise SupervisorError(
                "sandbox_cleanup_report_invalid",
                "cleanup report is incomplete or is not bound to the recorded identities",
            )
        return self._sandbox_execution_transition(
            attempt_id,
            claim_token,
            expected_phase="exited",
            next_phase="cleanup_reported",
            updates={"cleanup_receipt_json": encoded},
            event_type="sandbox.execution_cleanup_reported",
            event_payload={
                "receipt_sha256": hashlib.sha256(encoded.encode()).hexdigest(),
                "cleanup_action_sha256": (
                    action_payload["argv_sha256"] if action_payload is not None else ""
                ),
            },
            credential=credential,
            _cleanup_action_receipt=runc_delete_receipt,
            _cleanup_recovery_receipt=recovery_receipt,
            _reaper_epoch=_reaper_epoch,
            _allow_quarantined_failure_cleanup=_allow_quarantined_failure,
        )

    def _sandbox_execution_verify_cleanup(
        self,
        attempt_id: str,
        claim_token: int,
        *,
        credential: str | None = None,
    ) -> dict[str, Any]:
        """Independently observe post-stop cleanup before enabling result consumers."""

        from .sandbox_cleanup_verifier import verify_sandbox_execution_cleanup

        return verify_sandbox_execution_cleanup(
            self, attempt_id, claim_token, credential=credential
        )

    def _sandbox_execution_recover_cleanup(
        self,
        attempt_id: str,
        claim_token: int,
        *,
        reaper_epoch: int,
    ) -> dict[str, Any]:
        """Recover an exited execution only through the independent Linux verifier."""

        from .sandbox_cleanup_verifier import recover_sandbox_execution_cleanup

        return recover_sandbox_execution_cleanup(
            self, attempt_id, claim_token, reaper_epoch=reaper_epoch
        )

    def _sandbox_cleanup_action_payload(self, row: Any, receipt: Any) -> dict[str, Any]:
        if not _runc_cleanup_action_receipt_is_self_consistent(receipt):
            raise SupervisorError(
                "sandbox_cleanup_action_required",
                "cleanup report requires the registered exact pinned-runc delete receipt",
            )
        pin = self.config.oci_runc_executable
        if pin is None or pin.sha256 != row["runc_executable_digest"]:
            raise SupervisorError(
                "sandbox_cleanup_action_invalid", "configured pinned-runc identity changed"
            )
        expected = _sandbox_cleanup_action_payload_for_row(row, executable_path=str(pin.path))
        actual = {
            "attempt_id": receipt.attempt_id,
            "claim_token": receipt.claim_token,
            "execution_id": receipt.execution_id,
            "container_id": receipt.container_id,
            "state_root": receipt.state_root,
            "state_root_device": receipt.state_root_device,
            "state_root_inode": receipt.state_root_inode,
            "executable_path": receipt.executable_path,
            "executable_digest": receipt.executable_digest,
            "runtime_version": receipt.runtime_version,
            "argv": list(receipt.argv),
            "argv_digest": receipt.argv_digest,
            "actor_pid": receipt.actor_pid,
            "actor_identity": receipt.actor_identity,
            "returncode": receipt.returncode,
            "state_entry_absent": receipt.state_entry_absent,
        }
        expected_receipt = {
            "attempt_id": row["attempt_id"],
            "claim_token": row["claim_token"],
            "execution_id": row["execution_id"],
            "container_id": row["container_id"],
            "state_root": row["state_path"],
            "state_root_device": row["state_root_dev"],
            "state_root_inode": row["state_root_ino"],
            "executable_path": str(pin.path),
            "executable_digest": row["runc_executable_digest"],
            "runtime_version": row["runtime_version"],
            "argv": expected["argv"],
            "argv_digest": expected["argv_sha256"],
            "actor_pid": row["launch_driver_pid"],
            "actor_identity": row["launch_driver_identity"],
            "returncode": 0,
            "state_entry_absent": True,
        }
        if actual != expected_receipt:
            raise SupervisorError(
                "sandbox_cleanup_action_mismatch",
                "pinned-runc delete receipt does not match the exact durable execution",
            )
        return expected

    def _sandbox_cleanup_receipt_v3_is_self_consistent(self, row: Any, encoded: str) -> bool:
        pin = self.config.oci_runc_executable
        if pin is None or pin.sha256 != row["runc_executable_digest"]:
            return False
        try:
            candidate = json.loads(encoded)
            if canonical_json(candidate) != encoded:
                return False
            expected = self._sandbox_cleanup_receipt(row)
            expected["version"] = 3
            expected["action"] = _sandbox_cleanup_action_payload_for_row(
                row, executable_path=str(pin.path)
            )
            # Python considers numerically equal JSON values interchangeable
            # (for example 3.0 == 3). Compare canonical encodings so receipt
            # provenance also enforces exact JSON number types at every depth.
            return canonical_json(candidate) == canonical_json(expected)
        except (TypeError, ValueError, KeyError, json.JSONDecodeError):
            return False

    def _sandbox_cleanup_receipt_is_exact_for_result(self, row: Any, encoded: str) -> bool:
        """Accept only a byte-exact legacy, action, or recovered cleanup report."""

        return (
            encoded
            in {
                canonical_json(self._sandbox_cleanup_receipt(row)),
                canonical_json(self._sandbox_cleanup_receipt_v2_legacy(row)),
                canonical_json(self._sandbox_cleanup_receipt_v1(row)),
            }
            or self._sandbox_cleanup_receipt_v3_is_self_consistent(row, encoded)
            or self._sandbox_cleanup_recovery_receipt_is_self_consistent(row, encoded)
        )

    def _sandbox_cleanup_recovery_receipt_is_self_consistent(self, row: Any, encoded: str) -> bool:
        pin = self.config.oci_runc_executable
        return (
            pin is not None
            and pin.sha256 == row["runc_executable_digest"]
            and _sandbox_cleanup_recovery_report_is_self_consistent(row, encoded)
        )

    def _sandbox_cleanup_receipt(
        self,
        row: Any,
        *,
        action_payload: dict[str, Any] | None = None,
        recovery_payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if action_payload is not None and recovery_payload is not None:
            raise SupervisorError(
                "sandbox_cleanup_report_invalid",
                "cleanup report cannot claim both driver and recovery action evidence",
            )
        version = 4 if recovery_payload is not None else (3 if action_payload is not None else 2)
        receipt = _sandbox_cleanup_report_base(row, version=version)
        if action_payload is not None:
            receipt["action"] = action_payload
        if recovery_payload is not None:
            receipt["recovery"] = recovery_payload
        return receipt

    def _sandbox_cleanup_receipt_v1(self, row: Any) -> dict[str, Any]:
        """Reconstruct the historical receipt solely for immutable replay checks."""

        receipt = self._sandbox_cleanup_receipt_v2_legacy(row)
        receipt["version"] = 1
        receipt.pop("verification_status")
        receipt["observations"] = dict(_LEGACY_CLEANUP_OBSERVATIONS)
        return receipt

    def _sandbox_cleanup_receipt_v2_legacy(self, row: Any) -> dict[str, Any]:
        """Reconstruct a schema-16 v2 receipt for exact post-migration replay."""

        receipt = self._sandbox_cleanup_receipt(row)
        receipt.pop("rootfs_closure_digest")
        receipt.pop("runc_executable_digest")
        return receipt

    def _sandbox_execution_mark_ambiguous(
        self,
        attempt_id: str,
        claim_token: int,
        reason: str,
    ) -> dict[str, Any]:
        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        reason = self._sandbox_text(reason, "ambiguity_reason", limit=512)
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        if not row or row["claim_token"] != claim_token:
            return self._sandbox_execution_mark_ambiguous_under_gate_lock(
                attempt_id, claim_token, reason
            )
        execution_id = row["execution_id"]
        state_identity = (row["state_path"], row["state_root_dev"], row["state_root_ino"])
        with (
            _runc_launch_gate_lock_for_execution(
                attempt_id, claim_token, execution_id
            ) as locked_handle,
            _runc_execution_gate_fence(*_sandbox_execution_gate_identity(row)),
        ):
            with self.connect() as connection:
                locked_row = connection.execute(
                    "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
                ).fetchone()
            if (
                locked_row is None
                or locked_row["claim_token"] != claim_token
                or locked_row["execution_id"] != execution_id
                or (
                    locked_row["state_path"],
                    locked_row["state_root_dev"],
                    locked_row["state_root_ino"],
                )
                != state_identity
            ):
                raise SupervisorError(
                    "sandbox_execution_gate_identity_mismatch",
                    "execution changed before ambiguity was committed; fence retained",
                )
            updated = self._sandbox_execution_mark_ambiguous_under_gate_lock(
                attempt_id, claim_token, reason
            )
            if locked_handle is not None:
                _revoke_runc_launch_gate_release_locked(
                    locked_handle, attempt_id, claim_token, execution_id
                )
            return updated

    def _sandbox_execution_quarantine_lease_loss(
        self,
        attempt_id: str,
        claim_token: int,
        execution_id: str,
        *,
        credential: str | None = None,
    ) -> dict[str, Any]:
        """Quarantine one exact execution under its release lock after lease loss.

        The accepted phase set is checked by the journal transaction, not by a
        phase snapshot taken before the lock. That lets a concurrent
        ``launched -> running`` publication win cleanly without skipping the
        fail-closed quarantine/cancellation path.
        """

        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        execution_id = self._sandbox_text(execution_id, "execution_id")
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        if row is None or row["claim_token"] != claim_token or row["execution_id"] != execution_id:
            raise SupervisorError(
                "sandbox_execution_gate_identity_mismatch",
                "lease-loss quarantine does not identify the exact execution; fence retained",
            )
        allowed_phases = frozenset({"launched", "running", "stopping", "ambiguous"})
        state_identity = (row["state_path"], row["state_root_dev"], row["state_root_ino"])
        with (
            _runc_launch_gate_lock_for_execution(
                attempt_id, claim_token, execution_id
            ) as locked_handle,
            _runc_execution_gate_fence(*_sandbox_execution_gate_identity(row)),
        ):
            with self.connect() as connection:
                locked_row = connection.execute(
                    "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
                ).fetchone()
            if (
                locked_row is None
                or locked_row["claim_token"] != claim_token
                or locked_row["execution_id"] != execution_id
                or (
                    locked_row["state_path"],
                    locked_row["state_root_dev"],
                    locked_row["state_root_ino"],
                )
                != state_identity
            ):
                raise SupervisorError(
                    "sandbox_execution_gate_identity_mismatch",
                    "execution changed before lease-loss quarantine; fence retained",
                )
            if locked_row["phase"] not in allowed_phases:
                raise SupervisorError(
                    "sandbox_execution_transition_conflict",
                    "lease-loss quarantine found no exact active execution to stop",
                )
            updated = self._sandbox_execution_mark_ambiguous_under_gate_lock(
                attempt_id,
                claim_token,
                _LAUNCH_DRIVER_LEASE_LOSS_REASON,
                credential=credential,
                expected_phases=allowed_phases,
                require_lease_loss=True,
            )
            if locked_handle is not None:
                _revoke_runc_launch_gate_release_locked(
                    locked_handle, attempt_id, claim_token, execution_id
                )
            return updated

    def _sandbox_execution_revoke_launch_driver_start(
        self,
        attempt_id: str,
        claim_token: int,
        *,
        execution_id: str,
        start_id: str,
        start_digest: str,
        service_unit: str,
        reason: str,
        credential: str | None = None,
    ) -> dict[str, Any]:
        """Atomically revoke one exact launch-driver activation and quarantine it.

        Redemption and runc submission both require the durable ``reserved``
        phase. The transaction below serializes against both operations; after
        it commits neither operation can authorize a later gate release. The
        service controller must still reconcile this exact unit, and ambiguity
        deliberately retains every attempt and runtime fence.
        """

        attempt_id = self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        execution_id = self._sandbox_text(execution_id, "execution_id")
        start_id = self._sandbox_text(start_id, "launch_driver_start_id", limit=32)
        start_digest = self._sandbox_text(start_digest, "launch_driver_start_digest", limit=64)
        service_unit = self._sandbox_systemd_unit(
            service_unit, "launch_driver_start_unit", ".service"
        )
        reason = self._sandbox_text(reason, "ambiguity_reason", limit=512)
        if (
            re.fullmatch(r"[0-9a-f]{32}", start_id) is None
            or re.fullmatch(r"[0-9a-f]{64}", start_digest) is None
            or service_unit != _sandbox_launch_driver_service_unit(execution_id)
        ):
            raise SupervisorError(
                "sandbox_launch_driver_start_mismatch",
                "revocation does not identify one exact durable start intent",
            )
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        if row is None or row["claim_token"] != claim_token or row["execution_id"] != execution_id:
            raise SupervisorError(
                "sandbox_launch_driver_start_mismatch",
                "revocation execution identity is stale",
            )
        with (
            _runc_launch_gate_lock_for_execution(
                attempt_id, claim_token, execution_id
            ) as locked_handle,
            _runc_execution_gate_fence(*_sandbox_execution_gate_identity(row)),
        ):
            updated = self._sandbox_execution_mark_ambiguous_under_gate_lock(
                attempt_id,
                claim_token,
                reason,
                credential=credential,
                expected_phase="reserved",
                expected_launch_driver_start=(start_id, start_digest, service_unit),
            )
            if locked_handle is not None:
                _revoke_runc_launch_gate_release_locked(
                    locked_handle, attempt_id, claim_token, execution_id
                )
            return updated

    def _sandbox_execution_mark_ambiguous_under_gate_lock(
        self,
        attempt_id: str,
        claim_token: int,
        reason: str,
        *,
        credential: str | None = None,
        expected_phase: str | None = None,
        expected_phases: frozenset[str] | None = None,
        expected_launch_driver_start: tuple[str, str, str] | None = None,
        require_lease_loss: bool = False,
    ) -> dict[str, Any]:
        """Quarantine an unresolved execution and extend all attempt resource fences."""

        reason = self._sandbox_text(reason, "ambiguity_reason", limit=512)
        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        if (
            expected_phase is not None
            and expected_phases is not None
            or expected_phases is not None
            and (
                type(expected_phases) is not frozenset
                or not expected_phases
                or not expected_phases <= _PHASES
                or "cleanup_verified" in expected_phases
            )
        ):
            raise SupervisorError(
                "sandbox_execution_transition_invalid",
                "ambiguity phase guard is malformed",
            )
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if not attempt or not row:
                raise SupervisorError(
                    "sandbox_execution_not_found", "execution reservation is missing"
                )
            if attempt["claim_token"] != claim_token or row["claim_token"] != claim_token:
                raise SupervisorError("stale_fencing_token", "sandbox claim token is stale")
            if credential is not None:
                self._authenticate_attempt(connection, attempt, credential)
            if require_lease_loss:
                now = int(time.time())
                task = connection.execute(
                    "SELECT current_attempt_id, status, cleanup_target_status "
                    "FROM tasks WHERE id = ?",
                    (attempt["task_id"],),
                ).fetchone()
                working_lease_expired = (
                    attempt["status"] == "working"
                    and attempt["lease_expires_at"] <= now
                    and task is not None
                    and task["current_attempt_id"] == attempt_id
                    and task["status"] == "working"
                )
                reaper_quarantined_expired_attempt = (
                    attempt["status"] == "terminating"
                    and attempt["termination_target_status"] == "quarantined"
                    and attempt["lease_expires_at"] <= now
                    and task is not None
                    and task["current_attempt_id"] == attempt_id
                    and task["status"] == "cleanup_pending"
                    and task["cleanup_target_status"] == "blocked"
                )
                if not (working_lease_expired or reaper_quarantined_expired_attempt):
                    raise SupervisorError(
                        "sandbox_execution_lease_loss_unconfirmed",
                        "lease-loss quarantine requires the exact expired attempt and task",
                    )
            if expected_phase is not None and row["phase"] not in {
                expected_phase,
                "ambiguous",
            }:
                raise SupervisorError(
                    "sandbox_execution_transition_conflict",
                    f"expected phase {expected_phase} or ambiguous, found {row['phase']}; fence retained",
                )
            if expected_phases is not None and row["phase"] not in (
                expected_phases | {"ambiguous"}
            ):
                raise SupervisorError(
                    "sandbox_execution_transition_conflict",
                    f"expected one of {sorted(expected_phases)}, found {row['phase']}; fence retained",
                )
            if expected_launch_driver_start is not None:
                start_id, start_digest, service_unit = expected_launch_driver_start
                if (
                    row["launch_driver_start_id"] != start_id
                    or row["launch_driver_start_digest"] != start_digest
                    or row["launch_driver_start_unit"] != service_unit
                    or service_unit != _sandbox_launch_driver_service_unit(row["execution_id"])
                ):
                    raise SupervisorError(
                        "sandbox_launch_driver_start_mismatch",
                        "revocation does not match the durable one-shot start intent",
                    )
            task = connection.execute(
                "SELECT current_attempt_id FROM tasks WHERE id = ?", (attempt["task_id"],)
            ).fetchone()
            if not task or task["current_attempt_id"] != attempt_id:
                raise SupervisorError("stale_fencing_token", "attempt no longer owns its task")
            if row["phase"] == "cleanup_verified":
                raise SupervisorError(
                    "sandbox_execution_terminal", "verified execution cannot be re-quarantined"
                )
            if row["phase"] != "ambiguous":
                connection.execute(
                    "UPDATE sandbox_executions SET phase = 'ambiguous', failure_reason = ?, "
                    "updated_at = ? WHERE attempt_id = ? AND claim_token = ?",
                    (reason, utc_now(), attempt_id, claim_token),
                )
            stamp = utc_now()
            connection.execute(
                "UPDATE attempts SET status = 'terminating', "
                "termination_target_status = 'quarantined', updated_at = ? WHERE id = ?",
                (stamp, attempt_id),
            )
            connection.execute(
                "UPDATE tasks SET status = 'cleanup_pending', cleanup_target_status = 'blocked', "
                "cleanup_error = ?, updated_at = ? WHERE id = ? AND current_attempt_id = ?",
                (
                    "sandbox execution cleanup is ambiguous; attempt and resources remain fenced",
                    stamp,
                    attempt["task_id"],
                    attempt_id,
                ),
            )
            connection.execute(
                "UPDATE resource_leases SET lease_expires_at = ?, updated_at = ? "
                "WHERE attempt_id = ?",
                (CLEANUP_FENCE_EPOCH, stamp, attempt_id),
            )
            connection.execute(
                "UPDATE runtime_allocations SET lease_expires_at = ?, updated_at = ? "
                "WHERE attempt_id = ?",
                (CLEANUP_FENCE_EPOCH, stamp, attempt_id),
            )
            self._event(
                connection,
                "sandbox.execution_ambiguous",
                "supervisor",
                {
                    "attempt_id": attempt_id,
                    "claim_token": claim_token,
                    "execution_id": row["execution_id"],
                    "reason": reason,
                },
            )
            updated = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        return self._sandbox_execution_view(updated)

    def _sandbox_execution_get(self, attempt_id: str) -> dict[str, Any] | None:
        self._sandbox_validate_attempt_id(attempt_id)
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        return self._sandbox_execution_view(row) if row else None

    @staticmethod
    def _sandbox_execution_view(row: Any) -> dict[str, Any]:
        value = dict(row)
        if value.get("runc_exit_evidence_source"):
            # Keep the historical API field useful while the database column is
            # retained only to satisfy the immutable pre-v20 SQLite CHECK.
            value["runc_exit_observed_by"] = value["runc_exit_evidence_source"]
        raw = value.pop("cleanup_receipt_json", "{}")
        try:
            value["cleanup_receipt"] = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            value["cleanup_receipt"] = {"state": "unavailable"}
        raw_verification = value.get("cleanup_verification_json", "{}")
        try:
            value["cleanup_verification"] = json.loads(raw_verification)
        except (TypeError, ValueError, json.JSONDecodeError):
            value["cleanup_verification"] = {"state": "unavailable"}
        raw_provider_proxy = value.get("provider_proxy_artifact_json", "{}")
        try:
            value["provider_proxy_artifact"] = json.loads(raw_provider_proxy)
        except (TypeError, ValueError, json.JSONDecodeError):
            value["provider_proxy_artifact"] = {"state": "unavailable"}
        raw_candidate = value.pop("result_candidate_json", "")
        try:
            value["result_candidate"] = json.loads(raw_candidate) if raw_candidate else None
        except (TypeError, ValueError, json.JSONDecodeError):
            value["result_candidate"] = {"state": "unavailable"}
        raw_launch_plan = value.get("launch_plan_json", "")
        try:
            value["launch_plan"] = json.loads(raw_launch_plan) if raw_launch_plan else None
        except (TypeError, ValueError, json.JSONDecodeError):
            value["launch_plan"] = {"state": "unavailable"}
        return value

    @staticmethod
    def _sandbox_claim_token(value: Any) -> int:
        if type(value) is not int or value <= 0:
            raise SupervisorError("stale_fencing_token", "claim token must be positive")
        return value
