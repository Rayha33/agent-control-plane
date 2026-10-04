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
from pathlib import Path, PurePosixPath
from typing import Any

from .common import CLEANUP_FENCE_EPOCH, SupervisorError, canonical_json, utc_now
from .sandbox_attestation import (
    RunningRuntimeAttestation,
    running_attestation_is_self_consistent,
)
from .sandbox_workspace import (
    _MAX_DURABLE_MANIFEST_BYTES,
    _restore_snapshot_from_record,
    _verify_directory_identity,
)
from .sandbox_workspace import Snapshot as _Snapshot
from .sandbox_workspace import _snapshot_origin as _snapshot_origin
from .sandbox_workspace import collect_changes as _collect_changes

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
        if (
            baseline_root != execution_root / "baseline"
            or workspace_root != execution_root / "workspace"
        ):
            raise SupervisorError(
                "sandbox_workspace_invalid",
                "workspace roots must be the reserved execution directory's exact children",
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
            if baseline_root != expected_baseline or workspace_root != expected_workspace:
                raise SupervisorError(
                    "sandbox_workspace_invalid",
                    "workspace roots must be the reserved execution directory's exact children",
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
                  baseline_manifest_json = ?, baseline_manifest_digest = ?, updated_at = ?
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
        if row["workspace_binding_version"] != 1:
            raise SupervisorError(
                "sandbox_workspace_unbound", "execution has no durable workspace binding"
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
        ):
            raise SupervisorError(
                "sandbox_workspace_invalid", "journaled workspace paths do not match execution root"
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
                "bundle_path",
                "workspace_binding_version",
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
            "execution_id": row["execution_id"],
            "attempt_id": attempt_id,
            "claim_token": claim_token,
            "baseline": baseline,
            "workspace_root": current_workspace,
            "workspace_device": row["workspace_root_dev"],
            "workspace_inode": row["workspace_root_ino"],
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
                or execution["phase"] != "cleanup_reported"
                or execution["runc_exit_code"] != 0
                or execution["runc_exit_observed_by"] != "runc_client_popen_wait"
                or execution["baseline_root_path"] != str(baseline_root)
                or execution["baseline_root_dev"] != baseline_device
                or execution["baseline_root_ino"] != baseline_inode
                or execution["workspace_root_path"] != str(binding["workspace_root"])
                or execution["workspace_root_dev"] != binding["workspace_device"]
                or execution["workspace_root_ino"] != binding["workspace_inode"]
            ):
                raise SupervisorError(
                    "sandbox_result_evidence_unverified",
                    "candidate capture requires the exact exited, cleanup-reported workspace",
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
                row["phase"] != "cleanup_reported"
                or row["runc_exit_code"] != 0
                or row["runc_exit_observed_by"] != "runc_client_popen_wait"
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
                    "candidate result is not bound to the exited execution workspace",
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
            if cleanup_json not in {
                canonical_json(self._sandbox_cleanup_receipt(row)),
                canonical_json(self._sandbox_cleanup_receipt_v1(row)),
            }:
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
                    "observed_by": row["runc_exit_observed_by"],
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
                WHERE attempt_id = ? AND claim_token = ? AND phase = 'cleanup_reported'
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
        return {"candidate": candidate, "candidate_digest": digest, "change_set": change_set}

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
            "observed_by": row["runc_exit_observed_by"],
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
            if expected_phase == "reserved" and next_phase == "launched":
                if row["workspace_binding_version"] != 1:
                    raise SupervisorError(
                        "sandbox_workspace_unbound",
                        "sandbox launch requires a durable baseline/workspace binding",
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
        attestation: RunningRuntimeAttestation,
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
        if row["phase"] != "launched":
            raise SupervisorError(
                "sandbox_execution_transition_invalid",
                f"cannot record running from phase {row['phase']}; fence retained",
            )
        if not running_attestation_is_self_consistent(attestation):
            raise SupervisorError(
                "sandbox_runtime_attestation_invalid",
                "running transition requires a self-consistent typed receipt",
            )
        expected = {
            "container_id": row["container_id"],
            "bundle_path": row["bundle_path"],
            "monitor_pid": row["monitor_pid"],
            "monitor_identity": row["monitor_identity"],
            "runc_client_pid": row["runc_client_pid"],
            "runc_client_identity": row["runc_client_identity"],
            "wrapper_unit": row["wrapper_unit"],
            "wrapper_invocation_id": row["wrapper_invocation_id"],
            "scope_unit": row["scope_unit"],
            "scope_invocation_id": row["scope_invocation_id"],
            "cgroup_path": row["cgroup_path"],
        }
        if any(getattr(attestation, key) != value for key, value in expected.items()):
            raise SupervisorError(
                "sandbox_runtime_attestation_stale",
                "runtime evidence does not match the durable launch identities",
            )
        init_pid = self._sandbox_pid(attestation.init_pid, "init_pid")
        init_identity = self._sandbox_process_identity(attestation.init_identity, "init_identity")
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
            event_payload={"attestation": attestation.audit_payload()},
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
        if not isinstance(receipt, dict):
            raise SupervisorError(
                "sandbox_cleanup_report_invalid",
                "cleanup report is incomplete or is not bound to the recorded identities",
            )
        encoded = canonical_json(receipt)
        if len(encoded.encode("utf-8")) > 64 * 1024:
            raise SupervisorError("sandbox_cleanup_report_invalid", "cleanup report is too large")
        expected = self._sandbox_cleanup_receipt(row)
        expected_encoded = canonical_json(expected)
        if row["phase"] == "cleanup_reported":
            persisted = row["cleanup_receipt_json"]
            legacy_encoded = canonical_json(self._sandbox_cleanup_receipt_v1(row))
            if encoded == persisted and persisted in {expected_encoded, legacy_encoded}:
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
            event_payload={"receipt_sha256": hashlib.sha256(encoded.encode()).hexdigest()},
            credential=credential,
        )

    def _sandbox_cleanup_receipt(self, row: Any) -> dict[str, Any]:
        return {
            "version": 2,
            "verification_status": "unverified",
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

    def _sandbox_cleanup_receipt_v1(self, row: Any) -> dict[str, Any]:
        """Reconstruct the historical receipt solely for immutable replay checks."""

        receipt = self._sandbox_cleanup_receipt(row)
        receipt["version"] = 1
        receipt.pop("verification_status")
        receipt["observations"] = dict(_LEGACY_CLEANUP_OBSERVATIONS)
        return receipt

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
        raw_candidate = value.pop("result_candidate_json", "")
        try:
            value["result_candidate"] = json.loads(raw_candidate) if raw_candidate else None
        except (TypeError, ValueError, json.JSONDecodeError):
            value["result_candidate"] = {"state": "unavailable"}
        return value

    @staticmethod
    def _sandbox_claim_token(value: Any) -> int:
        if type(value) is not int or value <= 0:
            raise SupervisorError("stale_fencing_token", "claim token must be positive")
        return value
