"""Row lookups and the JSON views the CLI, status and MCP surfaces print.

Moved verbatim out of `git_supervisor` (board #1630). `GitSupervisor` inherits this mixin, so
every call site, CLI path and `GitSupervisor.<name>` lookup resolves exactly as before.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from .common import SupervisorError


class ViewsMixin:
    """Row lookups and read-only JSON views of tasks, attempts, runtimes, submissions and QC runs."""

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
            "claim_token": row["claim_token"],
            "start_sha": row["start_sha"],
            "latest_sha": row["latest_sha"],
            "checkpoint": json.loads(row["checkpoint_json"]),
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
