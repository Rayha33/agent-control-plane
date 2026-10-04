"""Durable, fail-closed identity journal for a future OCI worker executor.

This module records lifecycle claims; it does not launch runc, attest kernel
state, or establish a sandbox. In particular, a cleanup report is not accepted
as cleanup verification. The existing reaper and runtime teardown stay fenced
until a separate trusted verifier advances the journal to ``cleanup_verified``.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
import uuid
from pathlib import PurePosixPath
from typing import Any

from .common import CLEANUP_FENCE_EPOCH, SupervisorError, canonical_json, utc_now

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_OCI_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SYSTEMD_UNIT = re.compile(r"[A-Za-z0-9_.:@\\-]+\.(?:service|scope)\Z")
_INVOCATION_ID = re.compile(r"[0-9a-f]{32}\Z")
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
            "scope_unit",
            "scope_invocation_id",
            "cgroup_path",
        }
    ),
    ("launched", "running"): frozenset({"init_pid", "init_identity"}),
    ("launched", "stopping"): frozenset({"stop_reason"}),
    ("running", "stopping"): frozenset({"stop_reason"}),
    ("launched", "exited"): frozenset({"runc_exit_code", "runc_exit_observed_by"}),
    ("running", "exited"): frozenset({"runc_exit_code", "runc_exit_observed_by"}),
    ("stopping", "exited"): frozenset({"runc_exit_code", "runc_exit_observed_by"}),
    ("exited", "cleanup_reported"): frozenset({"cleanup_receipt_json"}),
}
_CLEANUP_OBSERVATIONS = {
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


def _sandbox_execution_cleanup_is_verified(connection: Any, attempt_id: str) -> bool:
    """Old/direct attempts have no journal; journaled attempts require verification."""

    row = connection.execute(
        "SELECT phase FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
    ).fetchone()
    return row is None or row["phase"] == "cleanup_verified"


def _require_sandbox_execution_result_eligible(connection: Any, attempt_id: str) -> None:
    """Fence result import/submission until a journaled worker exited cleanly."""

    row = connection.execute(
        "SELECT phase, runc_exit_code FROM sandbox_executions WHERE attempt_id = ?",
        (attempt_id,),
    ).fetchone()
    if row is not None and not (row["phase"] == "cleanup_verified" and row["runc_exit_code"] == 0):
        raise SupervisorError(
            "sandbox_result_unverified",
            "sandbox result requires successful runc exit and independently verified cleanup",
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
        bundle_digest: str,
        *,
        rootfs_digest: str,
        runtime_version: str,
        oci_version: str,
        credential: str | None = None,
    ) -> dict[str, Any]:
        """Reserve one journal row before launch; paths and container ID are host-derived."""

        attempt_id = self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        if not isinstance(bundle_digest, str) or _DIGEST.fullmatch(bundle_digest) is None:
            raise SupervisorError("sandbox_execution_invalid", "bundle digest must be SHA-256")
        if not isinstance(rootfs_digest, str) or _DIGEST.fullmatch(rootfs_digest) is None:
            raise SupervisorError("sandbox_execution_invalid", "rootfs digest must be SHA-256")
        runtime_version = self._sandbox_text(runtime_version, "runtime_version", limit=128)
        oci_version = self._sandbox_text(oci_version, "oci_version", limit=32)
        if _OCI_VERSION.fullmatch(oci_version) is None:
            raise SupervisorError("sandbox_execution_invalid", "OCI version must be numeric semver")
        execution_id = str(uuid.uuid4())
        container_id = f"acp-{attempt_id[:24]}-{claim_token}-{execution_id[:8]}"
        execution_root = (
            self.state_dir.resolve() / "sandbox-executions" / f"{attempt_id}-{claim_token}"
        )
        bundle_path = str(execution_root / "bundle")
        state_path = str(execution_root / "state")
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
                connection.execute(
                    """
                    INSERT INTO sandbox_executions
                      (attempt_id, claim_token, execution_id, backend, container_id,
                       bundle_digest, rootfs_digest, runtime_version, oci_version,
                       bundle_path, state_path, phase, created_at, updated_at)
                    VALUES (?, ?, ?, 'oci-runc', ?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?)
                    """,
                    (
                        attempt_id,
                        claim_token,
                        execution_id,
                        container_id,
                        bundle_digest,
                        rootfs_digest,
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
                    "rootfs_digest": rootfs_digest,
                    "runtime_version": runtime_version,
                    "oci_version": oci_version,
                },
            )
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        return self._sandbox_execution_view(row)

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
        self._sandbox_validate_attempt_id(attempt_id)
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
            if row["phase"] != expected_phase:
                raise SupervisorError(
                    "sandbox_execution_transition_invalid",
                    f"expected phase {expected_phase}, found {row['phase']}; fence retained",
                )
            fields = ", ".join(f"{name} = ?" for name in updates)
            changed = connection.execute(
                f"UPDATE sandbox_executions SET {fields}, phase = ?, updated_at = ? "
                "WHERE attempt_id = ? AND claim_token = ? AND phase = ?",
                (
                    *updates.values(),
                    next_phase,
                    utc_now(),
                    attempt_id,
                    claim_token,
                    expected_phase,
                ),
            ).rowcount
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

    def _sandbox_execution_record_launch(
        self,
        attempt_id: str,
        claim_token: int,
        *,
        monitor_pid: int,
        monitor_identity: str,
        runc_client_pid: int,
        runc_client_identity: str,
        wrapper_unit: str,
        wrapper_invocation_id: str,
        scope_unit: str,
        scope_invocation_id: str,
        cgroup_path: str,
        credential: str | None = None,
    ) -> dict[str, Any]:
        monitor_pid = self._sandbox_pid(monitor_pid, "monitor_pid")
        runc_client_pid = self._sandbox_pid(runc_client_pid, "runc_client_pid")
        monitor_identity = self._sandbox_process_identity(monitor_identity, "monitor_identity")
        runc_client_identity = self._sandbox_process_identity(
            runc_client_identity, "runc_client_identity"
        )
        wrapper_unit = self._sandbox_systemd_unit(wrapper_unit, "wrapper_unit", ".service")
        wrapper_invocation_id = self._sandbox_invocation_id(
            wrapper_invocation_id, "wrapper_invocation_id"
        )
        scope_unit = self._sandbox_systemd_unit(scope_unit, "scope_unit", ".scope")
        scope_invocation_id = self._sandbox_invocation_id(
            scope_invocation_id, "scope_invocation_id"
        )
        if monitor_pid == runc_client_pid or wrapper_unit == scope_unit:
            raise SupervisorError(
                "sandbox_execution_invalid", "monitor, runc client, and scope identities conflict"
            )
        cgroup_path = self._sandbox_text(cgroup_path, "cgroup_path", limit=4096)
        cgroup = PurePosixPath(cgroup_path)
        if (
            not cgroup.is_absolute()
            or cgroup.as_posix() != cgroup_path
            or any(part in {".", ".."} for part in cgroup.parts)
            or cgroup.name != scope_unit
        ):
            raise SupervisorError(
                "sandbox_execution_invalid", "cgroup path must name the exact recorded scope"
            )
        updates = {
            "monitor_pid": monitor_pid,
            "monitor_identity": monitor_identity,
            "runc_client_pid": runc_client_pid,
            "runc_client_identity": runc_client_identity,
            "wrapper_unit": wrapper_unit,
            "wrapper_invocation_id": wrapper_invocation_id,
            "scope_unit": scope_unit,
            "scope_invocation_id": scope_invocation_id,
            "cgroup_path": cgroup_path,
        }
        return self._sandbox_execution_transition(
            attempt_id,
            claim_token,
            expected_phase="reserved",
            next_phase="launched",
            updates=updates,
            event_type="sandbox.execution_launched",
            event_payload={key: value for key, value in updates.items()},
            credential=credential,
        )

    def _sandbox_execution_record_running(
        self,
        attempt_id: str,
        claim_token: int,
        *,
        init_pid: int,
        init_identity: str,
        credential: str | None = None,
    ) -> dict[str, Any]:
        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        init_pid = self._sandbox_pid(init_pid, "init_pid")
        init_identity = self._sandbox_process_identity(init_identity, "init_identity")
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        if not row or row["claim_token"] != claim_token:
            raise SupervisorError("sandbox_execution_not_found", "execution reservation is missing")
        if init_pid in {row["monitor_pid"], row["runc_client_pid"]}:
            raise SupervisorError(
                "sandbox_execution_invalid", "container init must have a distinct host PID"
            )
        return self._sandbox_execution_transition(
            attempt_id,
            claim_token,
            expected_phase="launched",
            next_phase="running",
            updates={"init_pid": init_pid, "init_identity": init_identity},
            event_type="sandbox.execution_running",
            event_payload={"init_pid": init_pid, "init_identity": init_identity},
            credential=credential,
        )

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
        if row and row["claim_token"] == claim_token and row["phase"] == "stopping":
            if row["stop_reason"] == reason:
                return self._sandbox_execution_view(row)
            raise SupervisorError(
                "sandbox_execution_transition_conflict",
                "a different stop reason is already durable; fence retained",
            )
        if not row or row["phase"] not in {"launched", "running"}:
            phase = row["phase"] if row else "missing"
            raise SupervisorError(
                "sandbox_execution_transition_invalid",
                f"cannot request stop from phase {phase}; fence retained",
            )
        return self._sandbox_execution_transition(
            attempt_id,
            claim_token,
            expected_phase=row["phase"],
            next_phase="stopping",
            updates={"stop_reason": reason},
            event_type="sandbox.execution_stop_requested",
            event_payload={"stop_reason": reason},
            credential=credential,
        )

    def _sandbox_execution_record_exit(
        self,
        attempt_id: str,
        claim_token: int,
        exit_code: int,
        *,
        credential: str | None = None,
    ) -> dict[str, Any]:
        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        if type(exit_code) is not int or not -255 <= exit_code <= 255:
            raise SupervisorError("sandbox_execution_invalid", "runc exit code is invalid")
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        if (
            row
            and row["claim_token"] == claim_token
            and row["phase"]
            in {
                "exited",
                "cleanup_reported",
                "cleanup_verified",
            }
        ):
            if row["runc_exit_code"] == exit_code:
                return self._sandbox_execution_view(row)
            raise SupervisorError(
                "sandbox_execution_transition_conflict", "conflicting runc exit receipt"
            )
        if not row or row["phase"] not in {"launched", "running", "stopping"}:
            phase = row["phase"] if row else "missing"
            raise SupervisorError(
                "sandbox_execution_transition_invalid",
                f"cannot record exit from phase {phase}; fence retained",
            )
        return self._sandbox_execution_transition(
            attempt_id,
            claim_token,
            expected_phase=row["phase"],
            next_phase="exited",
            updates={
                "runc_exit_code": exit_code,
                "runc_exit_observed_by": "runc_client_popen_wait",
            },
            event_type="sandbox.execution_exited",
            event_payload={
                "runc_exit_code": exit_code,
                "observed_by": "runc_client_popen_wait",
            },
            credential=credential,
        )

    def _sandbox_execution_record_cleanup_report(
        self,
        attempt_id: str,
        claim_token: int,
        receipt: dict[str, Any],
        *,
        credential: str | None = None,
    ) -> dict[str, Any]:
        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        if not row or row["claim_token"] != claim_token:
            raise SupervisorError("sandbox_execution_not_found", "execution reservation is missing")
        expected = self._sandbox_cleanup_receipt(row)
        if not isinstance(receipt, dict) or canonical_json(receipt) != canonical_json(expected):
            raise SupervisorError(
                "sandbox_cleanup_report_invalid",
                "cleanup report is incomplete or is not bound to the recorded identities",
            )
        encoded = canonical_json(receipt)
        if len(encoded.encode("utf-8")) > 64 * 1024:
            raise SupervisorError("sandbox_cleanup_report_invalid", "cleanup report is too large")
        if row["phase"] == "cleanup_reported" and row["cleanup_receipt_json"] == encoded:
            return self._sandbox_execution_view(row)
        return self._sandbox_execution_transition(
            attempt_id,
            claim_token,
            expected_phase="exited",
            next_phase="cleanup_reported",
            updates={"cleanup_receipt_json": encoded},
            event_type="sandbox.execution_cleanup_reported",
            event_payload={"receipt_sha256": hashlib.sha256(encoded.encode()).hexdigest()},
            credential=credential,
        )

    def _sandbox_cleanup_receipt(self, row: Any) -> dict[str, Any]:
        return {
            "version": 1,
            "attempt_id": row["attempt_id"],
            "claim_token": row["claim_token"],
            "execution_id": row["execution_id"],
            "container_id": row["container_id"],
            "bundle_digest": row["bundle_digest"],
            "rootfs_digest": row["rootfs_digest"],
            "runtime_version": row["runtime_version"],
            "oci_version": row["oci_version"],
            "runc_exit_code": row["runc_exit_code"],
            "runc_exit_observed_by": row["runc_exit_observed_by"],
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

    def _sandbox_execution_mark_ambiguous(
        self,
        attempt_id: str,
        claim_token: int,
        reason: str,
    ) -> dict[str, Any]:
        """Quarantine an unresolved execution and extend all attempt resource fences."""

        reason = self._sandbox_text(reason, "ambiguity_reason", limit=512)
        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
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
        raw = value.pop("cleanup_receipt_json", "{}")
        try:
            value["cleanup_receipt"] = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            value["cleanup_receipt"] = {"state": "unavailable"}
        return value

    @staticmethod
    def _sandbox_claim_token(value: Any) -> int:
        if type(value) is not int or value <= 0:
            raise SupervisorError("stale_fencing_token", "claim token must be positive")
        return value
