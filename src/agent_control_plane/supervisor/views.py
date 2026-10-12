"""Row lookups and the JSON views the CLI, status and MCP surfaces print.

Moved verbatim out of `git_supervisor` (board #1630). `GitSupervisor` inherits this mixin, so
every call site, CLI path and `GitSupervisor.<name>` lookup resolves exactly as before.
"""

from __future__ import annotations

import json
import re
import shutil
import sqlite3
import time
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from ..scheduling import Scheduler, declared_read_resources
from ..status import DEFAULT_LEASE_RISK_SECONDS, StatusView
from .common import DEFAULT_GC_RETENTION_SECONDS, SupervisorError, canonical_json, sha256


class ViewsMixin:
    """Row lookups and read-only JSON views of tasks, attempts, runtimes, submissions and QC runs."""

    @staticmethod
    def _completion_receipt_view(row: Any) -> dict[str, Any]:
        raw = row["result_manifest_json"] or ""
        if not raw:
            return {"state": "not_provided"}
        if not isinstance(raw, str):
            return {"state": "unavailable"}
        try:
            if len(raw.encode("utf-8")) > 64 * 1024:
                return {"state": "unavailable"}
            receipt = json.loads(raw)
        except (TypeError, UnicodeEncodeError, ValueError, RecursionError):
            return {"state": "unavailable"}
        if not isinstance(receipt, dict) or set(receipt) != {
            "version",
            "summary",
            "manifest_path",
            "manifest_blob_oid",
            "artifacts",
        }:
            return {"state": "unavailable"}
        try:
            summary_size = len(receipt["summary"].encode("utf-8"))
        except (AttributeError, UnicodeEncodeError):
            return {"state": "unavailable"}
        if (
            type(receipt["version"]) is not int
            or receipt["version"] != 1
            or not isinstance(receipt["summary"], str)
            or not receipt["summary"].strip()
            or summary_size > 4 * 1024
            or any(
                ord(character) < 32 and character not in "\n\t" or 127 <= ord(character) <= 159
                for character in receipt["summary"]
            )
        ):
            return {"state": "unavailable"}

        def valid_path(value: Any) -> bool:
            if not isinstance(value, str) or not value or "\\" in value:
                return False
            try:
                encoded = value.encode("utf-8")
            except UnicodeEncodeError:
                return False
            path = PurePosixPath(value)
            return (
                len(encoded) <= 1024
                and not path.is_absolute()
                and path.as_posix() == value
                and all(part not in {"", ".", ".."} for part in value.split("/"))
                and not any(
                    ord(character) < 32 or 127 <= ord(character) <= 159 for character in value
                )
            )

        oid_pattern = r"[0-9a-f]{40}|[0-9a-f]{64}"
        manifest_path = receipt["manifest_path"]
        manifest_oid = receipt["manifest_blob_oid"]
        artifacts = receipt["artifacts"]
        if (
            not valid_path(manifest_path)
            or not isinstance(manifest_oid, str)
            or re.fullmatch(oid_pattern, manifest_oid) is None
            or not isinstance(artifacts, list)
            or not artifacts
            or len(artifacts) > 16
        ):
            return {"state": "unavailable"}
        seen: set[str] = set()
        total_size = 0
        for artifact in artifacts:
            if not isinstance(artifact, dict) or set(artifact) != {
                "path",
                "blob_oid",
                "size_bytes",
            }:
                return {"state": "unavailable"}
            path = artifact["path"]
            blob_oid = artifact["blob_oid"]
            size = artifact["size_bytes"]
            if (
                not valid_path(path)
                or path == manifest_path
                or path in seen
                or not isinstance(blob_oid, str)
                or re.fullmatch(oid_pattern, blob_oid) is None
                or type(size) is not int
                or size < 0
                or size > 64 * 1024 * 1024
            ):
                return {"state": "unavailable"}
            seen.add(path)
            total_size += size
            if total_size > 256 * 1024 * 1024:
                return {"state": "unavailable"}
        return {"state": "provided", **receipt}

    def _task_view(self, connection: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        attempt = connection.execute(
            """
            SELECT * FROM attempts WHERE task_id = ?
            ORDER BY number DESC LIMIT 1
            """,
            (row["id"],),
        ).fetchone()
        submission = connection.execute(
            """
            SELECT * FROM submissions WHERE task_id = ?
            ORDER BY created_at DESC LIMIT 1
            """,
            (row["id"],),
        ).fetchone()
        return {
            "id": row["id"],
            "title": row["title"],
            "description": row["description"],
            "acceptance": json.loads(row["acceptance_json"]),
            # `resources` is the folded lease key and stays that, because callers key
            # overlap and lease identity off it. `declared_resources` is the same set as
            # the operator typed it, so `acp show`, `queue` and `status` stop printing a
            # path that does not exist in a case-sensitive checkout.
            "resources": json.loads(row["resources_json"]),
            "declared_resources": self._declared_resources(row),
            "read_resources": json.loads(row["read_resources_json"] or "[]"),
            "declared_read_resources": declared_read_resources(row),
            "dependencies": json.loads(row["dependencies_json"]),
            "produces": json.loads(row["produces_json"]),
            "consumes": json.loads(row["consumes_json"]),
            "base_branch": row["base_branch"],
            "base_sha": row["base_sha"],
            "priority": row["priority"],
            "status": row["status"],
            "cleanup_target_status": row["cleanup_target_status"],
            "cleanup_error": row["cleanup_error"],
            "current_attempt_id": row["current_attempt_id"],
            "latest_attempt": self._attempt_view(connection, attempt) if attempt else None,
            "latest_submission": self._submission_view(connection, submission)
            if submission
            else None,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _attempt_view(self, connection: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        leases = connection.execute(
            """
            SELECT resource, fencing_token, lease_expires_at
            FROM resource_leases WHERE attempt_id = ? ORDER BY resource
            """,
            (row["id"],),
        ).fetchall()
        runtime = connection.execute(
            "SELECT * FROM runtime_environments WHERE attempt_id = ?", (row["id"],)
        ).fetchone()
        trust_pin = json.loads(row["trust_bundle_json"] or "{}")
        return {
            "id": row["id"],
            "task_id": row["task_id"],
            "number": row["number"],
            "agent_id": row["agent_id"],
            "branch": row["branch"],
            "worktree": row["worktree"],
            "worktree_root": row["worktree_root"]
            or str((self.state_dir / "worktrees").resolve(strict=False)),
            "claim_token": row["claim_token"],
            "start_sha": row["start_sha"],
            "latest_sha": row["latest_sha"],
            "checkpoint": json.loads(row["checkpoint_json"]),
            "heartbeat_at": row["heartbeat_at"],
            "checkpoint_at": row["checkpoint_at"],
            "pid": row["pid"],
            "pid_identity": row["pid_identity"],
            "termination_target_status": row["termination_target_status"],
            "termination_proof": row["termination_proof"],
            "launch_owner_pid": row["launch_owner_pid"],
            "launch_owner_identity": row["launch_owner_identity"],
            "log_path": row["log_path"],
            "status": row["status"],
            "lease_expires_at": row["lease_expires_at"],
            "resource_leases": [dict(lease) for lease in leases],
            "runtime": self._runtime_view(connection, runtime) if runtime else None,
            "trust_bundle": (
                {
                    "bundle_id": trust_pin.get("bundle_id"),
                    "manifest_sha256": trust_pin.get("manifest_sha256"),
                }
                if trust_pin
                else None
            ),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _runtime_view(connection: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        allocations = connection.execute(
            "SELECT pool_name, value, lease_expires_at FROM runtime_allocations "
            "WHERE attempt_id = ? ORDER BY pool_name",
            (row["attempt_id"],),
        ).fetchall()
        return {
            "attempt_id": row["attempt_id"],
            "state": row["state"],
            "recovery_action": row["recovery_action"],
            "environment": json.loads(row["env_json"]),
            "allocations": [dict(allocation) for allocation in allocations],
            "setup_results": json.loads(row["setup_results_json"]),
            "teardown_results": json.loads(row["teardown_results_json"]),
            "log_path": row["log_path"],
            "updated_at": row["updated_at"],
        }

    def _submission_view(self, connection: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        qc = connection.execute(
            """
            SELECT * FROM qc_runs WHERE submission_id = ?
            ORDER BY finished_at DESC LIMIT 1
            """,
            (row["id"],),
        ).fetchone()
        return {
            "id": row["id"],
            "task_id": row["task_id"],
            "attempt_id": row["attempt_id"],
            "worker_agent_id": row["worker_agent_id"],
            "commit_sha": row["commit_sha"],
            "tree_sha": row["tree_sha"],
            "object_contract": row["object_contract"],
            "patch_sha256": row["patch_sha256"],
            "changed_paths": json.loads(row["changed_paths_json"]),
            "resource_tokens": json.loads(row["resource_tokens_json"]),
            "status": row["status"],
            "qc_resume_status": row["qc_resume_status"],
            "completion_receipt": self._completion_receipt_view(row),
            "latest_qc": self._qc_view(qc) if qc else None,
            "created_at": row["created_at"],
        }

    @staticmethod
    def _qc_view(row: sqlite3.Row) -> dict[str, Any]:
        trust_pin = json.loads(row["trust_bundle_json"] or "{}")
        return {
            "id": row["id"],
            "submission_id": row["submission_id"],
            "reviewer_id": row["reviewer_id"],
            "commit_sha": row["commit_sha"],
            "verdict": row["verdict"],
            "findings": json.loads(row["findings_json"]),
            "command_results": json.loads(row["results_json"]),
            "acceptance_coverage": json.loads(row["acceptance_coverage_json"] or "[]"),
            "acceptance_coverage_contract_version": int(
                row["acceptance_coverage_contract_version"] or 0
            ),
            "review_packet_sha256": row["packet_sha256"],
            "reviewer_provenance": json.loads(row["reviewer_provenance_json"] or "{}"),
            "reviewer_signature": row["reviewer_signature"],
            "bundle_sha256": row["bundle_sha256"],
            "policy_fingerprint": row["policy_fingerprint"],
            "trust_bundle": (
                {
                    "bundle_id": trust_pin.get("bundle_id"),
                    "manifest_sha256": trust_pin.get("manifest_sha256"),
                }
                if trust_pin
                else None
            ),
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
        }

    @staticmethod
    def _task_row(connection: sqlite3.Connection, task_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not row:
            raise SupervisorError("task_not_found", f"task {task_id} not found")
        return row

    @staticmethod
    def _submission_row(connection: sqlite3.Connection, submission_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM submissions WHERE id = ?", (submission_id,)
        ).fetchone()
        if not row:
            raise SupervisorError("submission_not_found", f"submission {submission_id} not found")
        return row

    def task(self, task_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            return self._task_view(connection, self._task_row(connection, task_id))

    def list_tasks(self) -> list[dict[str, Any]]:
        self.reap_expired()
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM tasks ORDER BY priority DESC, created_at"
            ).fetchall()
            return [self._task_view(connection, row) for row in rows]

    def plan_claim(self, task_id: str) -> dict[str, Any]:
        """Dry-run a claim. Read-only: it never reaps, claims, or provisions."""
        preview = Scheduler(self).plan_claim(task_id)
        preview["intent_coordination"] = self.intent_snapshot()
        return preview

    def ready_queue(self) -> dict[str, Any]:
        """Deterministic launch plan for every claimable task. Read-only."""
        queue = Scheduler(self).ready_queue()
        queue["intent_coordination"] = self.intent_snapshot()
        return queue

    def merge_plan(self) -> dict[str, Any]:
        """Integration ordering preview for approved submissions. Read-only."""
        self._assert_no_git_grafts()
        return Scheduler(self).merge_plan()

    @staticmethod
    def _bounded_comparison_json(raw: Any, maximum_bytes: int) -> tuple[str, Any]:
        if not isinstance(raw, str):
            return "unavailable", None
        try:
            if len(raw.encode("utf-8")) > maximum_bytes:
                return "unavailable", None
            return "available", json.loads(raw)
        except (UnicodeEncodeError, ValueError, RecursionError):
            return "unavailable", None

    @staticmethod
    def _comparison_text(value: Any, maximum: int = 512) -> str | None:
        if not isinstance(value, str):
            return None
        normalized = "".join(
            character
            for character in value
            if ord(character) >= 32 and not 127 <= ord(character) <= 159
        )
        return normalized[:maximum]

    @staticmethod
    def _valid_comparison_submission_id(value: Any) -> bool:
        if not isinstance(value, str) or not value or not value.isprintable():
            return False
        try:
            return len(value.encode("utf-8")) <= 128
        except UnicodeEncodeError:
            return False

    def _comparison_qc_view(
        self,
        connection: sqlite3.Connection,
        submission: sqlite3.Row,
        task_acceptance: Any,
    ) -> dict[str, Any]:
        # Keep the private comparison module's pinned public surface unchanged.
        from .acceptance import (
            ACCEPTANCE_COVERAGE_CONTRACT_VERSION,
            acceptance_criteria,
            validate_acceptance_coverage,
        )

        row = connection.execute(
            """
            SELECT id, submission_id, reviewer_id, commit_sha, verdict,
                   substr(findings_json, 1, 32769) AS findings_json,
                   substr(results_json, 1, 65537) AS results_json,
                   packet_sha256,
                   substr(reviewer_provenance_json, 1, 16385) AS reviewer_provenance_json,
                   reviewer_signature, bundle_sha256, policy_fingerprint,
                   substr(acceptance_coverage_json, 1, 32769) AS acceptance_coverage_json,
                   acceptance_coverage_contract_version, started_at, finished_at
            FROM qc_runs WHERE submission_id = ?
            ORDER BY finished_at DESC, id DESC LIMIT 1
            """,
            (submission["id"],),
        ).fetchone()
        if row is None:
            return {"state": "missing"}

        findings_state, findings_value = self._bounded_comparison_json(
            row["findings_json"], 32 * 1024
        )
        findings: list[dict[str, Any]] = []
        findings_count: int | None = None
        findings_truncated = False
        if findings_state == "available" and isinstance(findings_value, list):
            findings_count = len(findings_value)
            findings_truncated = findings_count > 8
            required_finding_fields = {
                "severity",
                "requirement",
                "finding",
                "evidence",
                "required_fix",
            }
            finding_severities = {"critical", "high", "medium", "low", "info"}
            for item in findings_value[:8]:
                if (
                    not isinstance(item, dict)
                    or not required_finding_fields.issubset(item)
                    or not isinstance(item.get("severity"), str)
                    or item["severity"] not in finding_severities
                    or any(not isinstance(item.get(key), str) for key in required_finding_fields)
                ):
                    findings_state = "unavailable"
                    continue
                finding: dict[str, Any] = {}
                for key in (
                    "severity",
                    "requirement",
                    "finding",
                    "evidence",
                    "required_fix",
                    "path",
                ):
                    value = self._comparison_text(item.get(key))
                    if value is not None:
                        finding[key] = value
                line = item.get("line")
                if type(line) is int and line >= 0:
                    finding["line"] = line
                findings.append(finding)
        else:
            findings_state = "unavailable"

        results_state, results_value = self._bounded_comparison_json(row["results_json"], 64 * 1024)
        command_results: list[dict[str, Any]] = []
        result_count: int | None = None
        results_truncated = False
        if results_state == "available" and isinstance(results_value, list):
            result_count = len(results_value)
            results_truncated = result_count > 16
            for item in results_value[:16]:
                has_evidence_identity = isinstance(item, dict) and (
                    "evidence_id" in item or "evidence_sha256" in item
                )
                evidence_record_valid = (
                    isinstance(item.get("evidence_id"), str)
                    and bool(item["evidence_id"])
                    and isinstance(item.get("evidence_sha256"), str)
                    and re.fullmatch(r"[0-9a-f]{64}", item["evidence_sha256"]) is not None
                    if isinstance(item, dict)
                    else False
                )
                command_record_valid = (
                    isinstance(item.get("command"), str)
                    and bool(item["command"])
                    and isinstance(item.get("argv"), list)
                    and all(isinstance(value, str) for value in item["argv"])
                    and type(item.get("duration_ms")) is int
                    and item["duration_ms"] >= 0
                    and type(item.get("timed_out")) is bool
                    and type(item.get("output_limited")) is bool
                    if isinstance(item, dict)
                    else False
                )
                if (
                    not isinstance(item, dict)
                    or type(item.get("exit_code")) is not int
                    or not (
                        evidence_record_valid if has_evidence_identity else command_record_valid
                    )
                ):
                    results_state = "unavailable"
                    continue
                result: dict[str, Any] = {}
                for key in (
                    "evidence_id",
                    "evidence_sha256",
                    "command_set_sha256",
                    "kind",
                    "phase",
                    "status",
                ):
                    value = self._comparison_text(item.get(key), 160)
                    if value is not None:
                        result[key] = value
                for key in ("exit_code", "command_count"):
                    value = item.get(key)
                    if type(value) is int:
                        result[key] = value
                duration = item.get("duration_seconds")
                if type(duration) in {int, float}:
                    result["duration_seconds"] = duration
                command_results.append(result)
        else:
            results_state = "unavailable"

        coverage_state, coverage_value = self._bounded_comparison_json(
            row["acceptance_coverage_json"], 32 * 1024
        )
        acceptance_coverage: list[dict[str, Any]] = []
        coverage_count: int | None = None
        coverage_truncated = False
        if coverage_state == "available" and isinstance(coverage_value, list):
            coverage_count = len(coverage_value)
            coverage_truncated = coverage_count > 16
            coverage_statuses = {"pass", "revise", "unknown", "human_required"}
            for item in coverage_value[:16]:
                evidence_refs = item.get("evidence_refs") if isinstance(item, dict) else None
                if (
                    not isinstance(item, dict)
                    or not isinstance(item.get("criterion_id"), str)
                    or not item["criterion_id"]
                    or not isinstance(item.get("status"), str)
                    or item["status"] not in coverage_statuses
                    or not isinstance(item.get("rationale"), str)
                    or not item["rationale"].strip()
                    or not isinstance(evidence_refs, list)
                    or not evidence_refs
                    or len(evidence_refs) > 20
                    or any(not isinstance(value, str) or not value for value in evidence_refs)
                    or len(set(evidence_refs)) != len(evidence_refs)
                ):
                    coverage_state = "unavailable"
                    continue
                if len(evidence_refs) > 16:
                    coverage_truncated = True
                entry: dict[str, Any] = {}
                # Free-form acceptance text belongs to the task brief, not this view.
                coverage_status = self._comparison_text(item.get("status"), 80)
                if coverage_status is not None:
                    entry["status"] = coverage_status
                criterion_id = self._comparison_text(item.get("criterion_id"), 160)
                if criterion_id is not None:
                    entry["criterion_id"] = criterion_id
                entry["evidence_refs"] = [value[:160] for value in evidence_refs[:16]]
                entry["evidence_refs_truncated"] = len(evidence_refs) > 16
                acceptance_coverage.append(entry)
        else:
            coverage_state = "unavailable"

        provenance_state, provenance = self._bounded_comparison_json(
            row["reviewer_provenance_json"], 16 * 1024
        )
        provenance_fingerprint = (
            sha256(canonical_json(provenance).encode("utf-8"))
            if provenance_state == "available" and isinstance(provenance, dict)
            else None
        )
        reviewer_identity = (
            self._comparison_text(provenance.get("identity"), 160)
            if isinstance(provenance, dict)
            else None
        )
        reviewer_provider = (
            self._comparison_text(provenance.get("provider"), 160)
            if isinstance(provenance, dict)
            else None
        )
        reviewer_model = (
            self._comparison_text(provenance.get("model"), 160)
            if isinstance(provenance, dict)
            else None
        )

        bundle_record_valid = False
        bundle_core_binding_matches = False
        coverage_bundle_binding_matches = False
        findings_integrity_state = "unavailable"
        results_integrity_state = "unavailable"
        bundle: dict[str, Any] = {}
        try:
            stored_bundle = self.assurance.read_bundle(row["id"], max_bytes=1024 * 1024)
            bundle = stored_bundle["bundle"]
            bundle_record_valid = (
                stored_bundle["signature_valid"] is True
                and sha256(canonical_json(bundle).encode("utf-8")) == row["bundle_sha256"]
                and bundle.get("signature") == row["reviewer_signature"]
            )
            bundle_core_binding_matches = (
                bundle_record_valid
                and bundle.get("qc_id") == row["id"]
                and bundle.get("submission_id") == submission["id"]
                and bundle.get("commit_sha") == row["commit_sha"]
                and bundle.get("tree_sha") == submission["tree_sha"]
                and bundle.get("patch_sha256") == submission["patch_sha256"]
                and bundle.get("packet_sha256") == row["packet_sha256"]
                and bundle.get("verdict") == row["verdict"]
                and bundle.get("policy_fingerprint") == row["policy_fingerprint"]
                and isinstance(provenance, dict)
                and bundle.get("reviewer") == provenance
                and provenance.get("identity") == row["reviewer_id"]
            )
            if (
                bundle_core_binding_matches
                and findings_state == "available"
                and not findings_truncated
                and bundle.get("findings_sha256")
                == sha256(canonical_json(findings_value).encode("utf-8"))
            ):
                findings_integrity_state = "verified"
            else:
                findings_state = "unavailable"
                findings = []
            if (
                bundle_core_binding_matches
                and results_state == "available"
                and not results_truncated
                and bundle.get("results_sha256")
                == sha256(canonical_json(results_value).encode("utf-8"))
            ):
                results_integrity_state = "verified"
            else:
                results_state = "unavailable"
                command_results = []
            coverage_bundle_binding_matches = (
                bundle_core_binding_matches
                and bundle.get("acceptance_coverage") == coverage_value
                and type(bundle.get("acceptance_coverage_contract_version")) is int
                and bundle.get("acceptance_coverage_contract_version")
                == row["acceptance_coverage_contract_version"]
            )
        except (
            AttributeError,
            KeyError,
            OSError,
            RecursionError,
            TypeError,
            UnicodeError,
            ValueError,
            SupervisorError,
        ):
            findings_state = "unavailable"
            findings = []
            results_state = "unavailable"
            command_results = []

        coverage_integrity_state = "unavailable"
        if coverage_state == "available" and not coverage_truncated:
            try:
                expected = acceptance_criteria(task_acceptance)
                bundled_coverage = bundle.get("acceptance_coverage")
                raw_coverage = (
                    [
                        {
                            key: item[key]
                            for key in ("criterion_id", "status", "rationale", "evidence_refs")
                        }
                        for item in bundled_coverage
                        if isinstance(item, dict)
                        and set(item)
                        == {
                            "criterion_id",
                            "criterion",
                            "status",
                            "rationale",
                            "evidence_refs",
                        }
                    ]
                    if isinstance(bundled_coverage, list)
                    else None
                )
                validated_coverage = validate_acceptance_coverage(
                    raw_coverage,
                    expected,
                    bundle.get("acceptance_evidence_catalog"),
                    run_id=row["id"],
                    commit_sha=row["commit_sha"],
                )
                if coverage_bundle_binding_matches and validated_coverage == bundled_coverage:
                    coverage_integrity_state = "verified"
                else:
                    coverage_state = "unavailable"
                    acceptance_coverage = []
            except (
                AttributeError,
                KeyError,
                OSError,
                RecursionError,
                TypeError,
                UnicodeError,
                ValueError,
                SupervisorError,
            ):
                coverage_state = "unavailable"
                acceptance_coverage = []
        bundle_integrity_state = (
            "verified"
            if bundle_core_binding_matches
            and findings_integrity_state == "verified"
            and results_integrity_state == "verified"
            and coverage_bundle_binding_matches
            else "unavailable"
        )
        exact_binding = (
            row["submission_id"] == submission["id"]
            and row["commit_sha"] == submission["commit_sha"]
        )
        current_policy_fingerprint = self.assurance_policy.fingerprint
        ratified_policy_fingerprint = self.assurance.ratified_fingerprint(connection)
        recorded_policy_fingerprint = row["policy_fingerprint"]
        policy_state = (
            "unknown"
            if not isinstance(recorded_policy_fingerprint, str) or not recorded_policy_fingerprint
            else "stale"
            if recorded_policy_fingerprint != current_policy_fingerprint
            else "current_unratified"
            if ratified_policy_fingerprint != current_policy_fingerprint
            else "current_and_ratified"
        )
        evidence_hashes_valid = all(
            isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None
            for value in (row["packet_sha256"], row["bundle_sha256"])
        )
        coverage_contract_version = row["acceptance_coverage_contract_version"]
        coverage_contract_state = (
            "unknown"
            if type(coverage_contract_version) is not int
            else "current"
            if coverage_contract_version == ACCEPTANCE_COVERAGE_CONTRACT_VERSION
            else "not_current"
        )
        evidence_complete = (
            evidence_hashes_valid
            and bool(row["reviewer_signature"])
            and provenance_fingerprint is not None
            and findings_state == "available"
            and findings_integrity_state == "verified"
            and not findings_truncated
            and results_state == "available"
            and results_integrity_state == "verified"
            and not results_truncated
            and coverage_state == "available"
            and not coverage_truncated
            and coverage_integrity_state == "verified"
            and bundle_integrity_state == "verified"
            and coverage_contract_state == "current"
        )
        handoff_eligibility = (
            "candidate_mismatch"
            if not exact_binding
            else "stale_policy"
            if policy_state == "stale"
            else "policy_unratified"
            if policy_state == "current_unratified"
            else "policy_unknown"
            if policy_state == "unknown"
            else "coverage_contract_not_current"
            if coverage_contract_state == "not_current"
            else "coverage_contract_unknown"
            if coverage_contract_state == "unknown"
            else "incomplete_evidence"
            if not evidence_complete
            else "eligible"
        )
        return {
            "state": "available",
            "record_state": "recorded_only_not_revalidated",
            "qc_run_id": row["id"],
            "submission_id": row["submission_id"],
            "commit_sha": row["commit_sha"],
            "candidate_binding": "exact" if exact_binding else "mismatch",
            "recorded_verdict": row["verdict"],
            "reviewer_id": row["reviewer_id"],
            "reviewer_identity": reviewer_identity,
            "reviewer_provider": reviewer_provider,
            "reviewer_model": reviewer_model,
            "reviewer_provenance_sha256": provenance_fingerprint,
            "reviewer_provenance_state": provenance_state,
            "reviewer_signature_present": bool(row["reviewer_signature"]),
            "policy_fingerprint": recorded_policy_fingerprint,
            "policy_state": policy_state,
            "bundle_integrity_state": bundle_integrity_state,
            "coverage_contract_state": coverage_contract_state,
            "evidence_complete": evidence_complete,
            "handoff_eligibility": handoff_eligibility,
            "review_packet_sha256": row["packet_sha256"],
            "bundle_sha256": row["bundle_sha256"],
            "command_results": {
                "state": results_state,
                "integrity_state": results_integrity_state,
                "count": result_count,
                "truncated": results_truncated,
                "items": command_results,
            },
            "findings": {
                "state": findings_state,
                "integrity_state": findings_integrity_state,
                "count": findings_count,
                "truncated": findings_truncated,
                "items": findings,
            },
            "acceptance_coverage": {
                "state": coverage_state,
                "contract_version": row["acceptance_coverage_contract_version"],
                "count": coverage_count,
                "truncated": coverage_truncated,
                "integrity_state": coverage_integrity_state,
                "items": acceptance_coverage,
            },
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
        }

    def compare_submissions(self, submission_ids: Sequence[str]) -> dict[str, Any]:
        """Compare 2-8 submissions for one task without ranking or mutating them."""
        if (
            isinstance(submission_ids, (str, bytes))
            or not isinstance(submission_ids, Sequence)
            or not 2 <= len(submission_ids) <= 8
            or any(not self._valid_comparison_submission_id(value) for value in submission_ids)
            or len(set(submission_ids)) != len(submission_ids)
        ):
            raise SupervisorError(
                "invalid_submission_ids", "pass 2 to 8 unique submission IDs (maximum 128 bytes)"
            )

        diff_deadline = time.monotonic() + 5.0

        def diff_summary(start_sha: Any, commit_sha: Any) -> dict[str, Any]:
            if any(
                not isinstance(value, str)
                or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value) is None
                for value in (start_sha, commit_sha)
            ):
                return {"state": "unavailable", "basis": "attempt_start_to_commit"}
            remaining = diff_deadline - time.monotonic()
            if remaining <= 0:
                return {"state": "unavailable", "basis": "attempt_start_to_commit"}
            try:
                raw = self._git_readonly_bytes(
                    "diff",
                    "--shortstat",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--no-renames",
                    start_sha,
                    commit_sha,
                    "--",
                    timeout=min(2.0, remaining),
                    no_lazy_fetch=True,
                )
            except SupervisorError:
                return {"state": "unavailable", "basis": "attempt_start_to_commit"}
            summary = raw.decode("ascii", errors="replace").strip()
            if not summary:
                return {
                    "state": "available",
                    "basis": "attempt_start_to_commit",
                    "files_changed": 0,
                    "insertions": 0,
                    "deletions": 0,
                }
            match = re.fullmatch(
                r"(\d+) files? changed"
                r"(?:, (\d+) insertions?\(\+\))?"
                r"(?:, (\d+) deletions?\(-\))?",
                summary,
            )
            if match is None:
                return {"state": "unavailable", "basis": "attempt_start_to_commit"}
            return {
                "state": "available",
                "basis": "attempt_start_to_commit",
                "files_changed": int(match.group(1)),
                "insertions": int(match.group(2)) if match.group(2) is not None else None,
                "deletions": int(match.group(3)) if match.group(3) is not None else None,
            }

        with self.connect() as connection:
            connection.execute("BEGIN")
            submissions: list[sqlite3.Row] = []
            for submission_id in submission_ids:
                row = connection.execute(
                    """
                    SELECT id, task_id, attempt_id, worker_agent_id, commit_sha, tree_sha,
                           object_contract, patch_sha256,
                           substr(changed_paths_json, 1, 65537) AS changed_paths_json,
                           status, substr(result_manifest_json, 1, 65537) AS result_manifest_json,
                           created_at
                    FROM submissions WHERE id = ?
                    """,
                    (submission_id,),
                ).fetchone()
                if row is None:
                    raise SupervisorError(
                        "submission_not_found", f"submission {submission_id} not found"
                    )
                submissions.append(row)

            task_id = submissions[0]["task_id"]
            if any(row["task_id"] != task_id for row in submissions[1:]):
                raise SupervisorError(
                    "submission_task_mismatch", "all compared submissions must belong to one task"
                )
            task = connection.execute(
                """
                SELECT id, substr(title, 1, 1025) AS title, base_branch, base_sha,
                       substr(description, 1, 65537) AS description,
                       substr(acceptance_json, 1, 65537) AS acceptance_json
                FROM tasks WHERE id = ?
                """,
                (task_id,),
            ).fetchone()
            if task is None:
                raise SupervisorError("task_not_found", f"task {task_id} not found")

            raw_title = task["title"]
            title = self._comparison_text(raw_title, 1024)
            description = task["description"]
            brief_state, acceptance = self._bounded_comparison_json(
                task["acceptance_json"], 64 * 1024
            )
            if (
                brief_state == "available"
                and isinstance(raw_title, str)
                and len(raw_title) <= 1024
                and isinstance(description, str)
                and len(description.encode("utf-8")) <= 64 * 1024
            ):
                brief_fingerprint = sha256(
                    canonical_json(
                        {
                            "title": raw_title,
                            "description": description,
                            "acceptance": acceptance,
                        }
                    ).encode("utf-8")
                )
            else:
                brief_state = "unavailable"
                brief_fingerprint = None

            candidates: list[dict[str, Any]] = []
            for submission in submissions:
                attempt = connection.execute(
                    """
                    SELECT id, task_id, number, agent_id, branch, start_sha, status
                    FROM attempts WHERE id = ? AND task_id = ?
                    """,
                    (submission["attempt_id"], task_id),
                ).fetchone()
                attempt_state = "available" if attempt is not None else "unavailable"
                attempt_start_sha = attempt["start_sha"] if attempt is not None else None
                paths_state, paths = self._bounded_comparison_json(
                    submission["changed_paths_json"], 64 * 1024
                )
                if paths_state == "available" and isinstance(paths, list):
                    paths_truncated = len(paths) > 100
                    normalized_paths = [
                        value[:1024] for value in paths[:100] if isinstance(value, str)
                    ]
                    if len(normalized_paths) != min(len(paths), 100):
                        paths_state = "unavailable"
                        normalized_paths = []
                else:
                    paths_state = "unavailable"
                    paths_truncated = False
                    normalized_paths = []

                candidate = {
                    "submission_id": submission["id"],
                    "attempt_id": submission["attempt_id"],
                    "worker_agent_id": submission["worker_agent_id"],
                    "attempt": (
                        {
                            "state": attempt_state,
                            "number": attempt["number"],
                            "agent_id": attempt["agent_id"],
                            "branch": attempt["branch"],
                            "start_sha": attempt_start_sha,
                            "status": attempt["status"],
                        }
                        if attempt is not None
                        else {"state": "unavailable"}
                    ),
                    "base_relation": {
                        "attempt_start_sha": attempt_start_sha,
                        "task_base_sha_at_comparison": task["base_sha"],
                        "state": (
                            "same_as_current_task_base"
                            if attempt_start_sha == task["base_sha"]
                            else "different_from_current_task_base"
                            if attempt_start_sha is not None
                            else "unavailable"
                        ),
                    },
                    "commit_sha": submission["commit_sha"],
                    "tree_sha": submission["tree_sha"],
                    "object_contract": submission["object_contract"],
                    "patch_sha256": submission["patch_sha256"],
                    "changed_paths": {
                        "state": paths_state,
                        "truncated": paths_truncated,
                        "items": normalized_paths,
                    },
                    "diff_summary": diff_summary(attempt_start_sha, submission["commit_sha"]),
                    "status": submission["status"],
                    "completion_receipt": self._completion_receipt_view(submission),
                    "latest_qc": self._comparison_qc_view(connection, submission, acceptance),
                    "created_at": submission["created_at"],
                }
                qc = candidate["latest_qc"]
                candidate["review_handoff"] = {
                    "state": "prepared_not_dispatched",
                    "task_id": task_id,
                    "task_brief_sha256": brief_fingerprint,
                    "task_brief_binding_state": "current_only_not_pinned_at_attempt_start",
                    "candidate_submission_id": submission["id"],
                    "candidate_commit_sha": submission["commit_sha"],
                    "candidate_tree_sha": submission["tree_sha"],
                    "candidate_patch_sha256": submission["patch_sha256"],
                    "attempt_id": submission["attempt_id"],
                    "writer_agent_id": submission["worker_agent_id"],
                    "feedback_route": {
                        "agent_id": submission["worker_agent_id"],
                        "mode": "manual_operator_routing",
                    },
                    "qc_evidence_state": qc.get("handoff_eligibility", "qc_missing"),
                    "qc_run_id": (
                        qc.get("qc_run_id") if qc.get("handoff_eligibility") == "eligible" else None
                    ),
                    "review_packet_sha256": (
                        qc.get("review_packet_sha256")
                        if qc.get("handoff_eligibility") == "eligible"
                        else None
                    ),
                    "policy_fingerprint": (
                        qc.get("policy_fingerprint")
                        if qc.get("handoff_eligibility") == "eligible"
                        else None
                    ),
                    "critic_write_authority": False,
                    "automatic_selection_or_dispatch": False,
                }
                candidates.append(candidate)

            return {
                "schema": "acp-submission-comparison-v1",
                "task_id": task_id,
                "task_title": title,
                "task_base": {"branch": task["base_branch"], "sha": task["base_sha"]},
                "task_brief": {
                    "state": "current_only_not_pinned_at_attempt_start",
                    "fingerprint_state": brief_state,
                    "sha256": brief_fingerprint,
                },
                "candidate_count": len(candidates),
                "order": "caller_supplied_no_ranking",
                "read_only": True,
                "candidates": candidates,
            }

    def status(
        self,
        limit: int | None = None,
        lease_risk_seconds: int = DEFAULT_LEASE_RISK_SECONDS,
        checkpoint_stale_seconds: int | None = None,
    ) -> dict[str, Any]:
        """Operator snapshot: attention queue, phases, runtimes, blockers. Read-only."""
        snapshot = StatusView(self).snapshot(limit, lease_risk_seconds, checkpoint_stale_seconds)
        inventory = snapshot["git_worktrees"]
        registered_worktrees = (
            {entry["path"]: entry["branch"] for entry in inventory["entries"]}
            if inventory["status"] == "available"
            else {}
        )
        with self.connect() as connection:
            reclaimable, retained = self._gc_survey(
                connection,
                time.time(),
                DEFAULT_GC_RETENTION_SECONDS,
                registered_worktrees=registered_worktrees,
            )
        try:
            filesystem_usage = shutil.disk_usage(self.state_dir)
        except OSError:
            filesystem = {
                "path": str(self.state_dir),
                "status": "unavailable",
                "total_bytes": None,
                "free_bytes": None,
            }
        else:
            filesystem = {
                "path": str(self.state_dir),
                "status": "available",
                "total_bytes": filesystem_usage.total,
                "free_bytes": filesystem_usage.free,
            }
        snapshot["disk"] = {
            "state_bytes": self._directory_bytes(self.state_dir),
            "reclaimable_worktrees": len(reclaimable),
            "reclaimable_bytes": sum(entry["bytes"] for entry in reclaimable),
            "admission_min_free_bytes": self.config.min_free_bytes,
            "filesystem": filesystem,
        }
        default_worktree_root = (self.state_dir / "worktrees").resolve(strict=False)
        configured_worktree_root = self._attempt_worktree_root.resolve(strict=False)
        bytes_by_root: dict[str, int] = {}
        for entry in (*reclaimable, *retained):
            if "bytes" in entry:
                root = str(Path(entry["worktree_root"]).resolve(strict=False))
                bytes_by_root[root] = bytes_by_root.get(root, 0) + entry["bytes"]
        bytes_by_root.setdefault(str(configured_worktree_root), 0)

        managed_roots = []
        for root, worktree_bytes in sorted(bytes_by_root.items()):
            if root == str(default_worktree_root):
                root_filesystem = filesystem
            else:
                try:
                    usage = shutil.disk_usage(root)
                except OSError:
                    root_filesystem = {
                        "path": root,
                        "status": "unavailable",
                        "total_bytes": None,
                        "free_bytes": None,
                    }
                else:
                    root_filesystem = {
                        "path": root,
                        "status": "available",
                        "total_bytes": usage.total,
                        "free_bytes": usage.free,
                    }
            managed_roots.append(
                {"root": root, "registered_bytes": worktree_bytes, "filesystem": root_filesystem}
            )
        snapshot["disk"]["attempt_worktrees"] = {
            "configured_root": str(configured_worktree_root),
            "managed_roots": managed_roots,
        }
        snapshot["intent_coordination"] = self.intent_snapshot()
        return snapshot

    @staticmethod
    def render_status(snapshot: dict[str, Any]) -> str:
        """Human-readable rendering of a `status()` snapshot; JSON stays canonical."""
        return StatusView.render(snapshot)
