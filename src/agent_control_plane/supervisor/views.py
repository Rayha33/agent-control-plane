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
from pathlib import Path, PurePosixPath
from typing import Any

from ..scheduling import Scheduler, declared_read_resources
from ..status import DEFAULT_LEASE_RISK_SECONDS, StatusView
from .common import DEFAULT_GC_RETENTION_SECONDS, SupervisorError


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
