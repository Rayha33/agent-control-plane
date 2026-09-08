"""Read-only operator status view.

One screen that answers: who owns what, what needs a human, and which resources
are blocked. An operator running several agents should not have to visit N
terminal tabs to discover which session is stuck.

This module is strictly observational. It deliberately does NOT call
`reap_expired()` — the ordinary read paths (`list_tasks`, `claim`) do reap, so a
status view that reaped would silently change the state an operator is trying to
read, and orphan an attempt merely because someone looked at the dashboard.
Expired-but-unreaped attempts are reported as `awaiting_reap` instead.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from collections.abc import Callable
from datetime import datetime
from typing import TYPE_CHECKING, Any

from .scheduling import Scheduler

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .git_supervisor import GitSupervisor

# Lower rank wins the operator's attention.
CATEGORY_RANKS: dict[str, int] = {
    "human_required": 0,
    "cleanup_failed": 1,
    "lease_risk": 2,
    "review": 3,
    "active": 4,
}

HUMAN_REQUIRED_STATUSES = frozenset({"blocked", "conflicted", "changes_requested"})
REVIEW_STATUSES = frozenset({"submitted", "qc_review", "approved"})
ACTIVE_STATUSES = frozenset({"provisioning", "working", "terminating", "cleanup_pending"})
LIVE_ATTEMPT_STATUSES = frozenset({"provisioning", "working", "terminating"})
CLEANUP_STATUSES = frozenset({"terminating", "cleanup_pending"})
DEFAULT_LEASE_RISK_SECONDS = 30


def _age_seconds(stamp: str | None, now: float) -> int | None:
    if not stamp:
        return None
    try:
        moment = datetime.fromisoformat(stamp)
    except ValueError:
        return None
    return max(0, int(now - moment.timestamp()))


def _process_liveness(
    pid: int | None,
    expected_identity: str,
    identity_reader: Callable[[int], str | None],
) -> str:
    """Return alive, dead, or unproven for the exact registered process."""

    if not pid or pid <= 0:
        return "dead"
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return "dead"
    except PermissionError:
        pass
    except OSError:
        return "unproven"
    if not expected_identity:
        return "unproven"
    try:
        current_identity = identity_reader(pid)
    except (OSError, RuntimeError, ValueError):
        return "unproven"
    if current_identity is None:
        return "unproven"
    return "alive" if current_identity == expected_identity else "dead"


class StatusView:
    def __init__(self, supervisor: GitSupervisor):
        self.supervisor = supervisor

    def snapshot(
        self,
        limit: int | None = None,
        lease_risk_seconds: int = DEFAULT_LEASE_RISK_SECONDS,
    ) -> dict[str, Any]:
        now = time.time()
        epoch = int(now)
        scheduler = Scheduler(self.supervisor)
        with self.supervisor.connect() as connection:
            tasks = scheduler._task_records(connection)
            holders = scheduler._active_leases(connection, epoch)
            attempts = self._latest_attempts(connection)
            submissions = self._latest_submissions(connection)
            runtimes = self._runtimes(connection)
            allocations = self._allocations(connection)
            quarantines = self._quarantines(connection, now)
            held_resources = self._held_resources(holders)

        # One admission pass, shared with `acp queue`: readiness here means
        # "launchable now, alongside everything above it", not "launchable alone".
        plan = scheduler.plan_pass(tasks, holders)
        previews = {entry["task_id"]: entry for entry in [*plan["ready"], *plan["blocked"]]}
        entries: list[dict[str, Any]] = []
        for task in tasks:
            attempt = attempts.get(task["id"])
            runtime = runtimes.get(attempt["id"]) if attempt else None
            entries.append(
                self._task_entry(
                    task=task,
                    attempt=attempt,
                    runtime=runtime,
                    quarantine=quarantines.get(attempt["id"]) if attempt else None,
                    allocations=allocations.get(attempt["id"], []) if attempt else [],
                    submission=submissions.get(task["id"]),
                    preview=previews.get(task["id"]),
                    now=now,
                    lease_risk_seconds=lease_risk_seconds,
                    held_resources=held_resources.get(task["id"], []),
                )
            )

        attention = sorted(
            (self._attention_item(entry) for entry in entries if entry["category"]),
            key=lambda item: (item["rank"], -item["priority"], item["task_id"]),
        )
        cleanup_failures = [
            {
                "attempt_id": entry["attempt_id"],
                "task_id": entry["task_id"],
                "state": entry["runtime"]["state"],
                "owner": entry["agent_id"],
                "severity": (entry["runtime"].get("quarantine") or {}).get("severity"),
                "age_seconds": (entry["runtime"].get("quarantine") or {}).get("age_seconds"),
                "quarantined_resources": (entry["runtime"].get("quarantine") or {}).get("count", 0),
            }
            for entry in entries
            if entry["runtime"] and entry["runtime"]["state"] == "teardown_failed"
        ]
        cleanup_failures.extend(
            {
                "attempt_id": entry["attempt_id"],
                "task_id": entry["task_id"],
                "state": entry["status"],
                "owner": entry["agent_id"],
                "severity": "critical",
                "age_seconds": entry["heartbeat_age_seconds"],
                "quarantined_resources": len(entry["held_resources"]),
            }
            for entry in entries
            if entry["status"] in CLEANUP_STATUSES
            and not (entry["runtime"] and entry["runtime"]["state"] == "teardown_failed")
        )
        counts = {
            "tasks": len(entries),
            "ready": sum(1 for entry in entries if entry["ready"] is True),
            "blocked": sum(1 for entry in entries if entry["ready"] is False),
            "active": sum(1 for entry in entries if entry["status"] in ACTIVE_STATUSES),
            "attention": len(attention),
            "cleanup_failures": len(cleanup_failures),
        }
        shown = entries if limit is None else entries[:limit]
        return {
            "generated_at": epoch,
            "repo": str(self.supervisor.root),
            "counts": counts,
            "attention": attention if limit is None else attention[:limit],
            "tasks": shown,
            "cleanup_failures": cleanup_failures,
            "truncated": len(shown) < len(entries),
        }

    # ----------------------------------------------------------------- loading

    @staticmethod
    def _latest_attempts(connection: sqlite3.Connection) -> dict[str, dict[str, Any]]:
        rows = connection.execute(
            """
            SELECT attempt.* FROM attempts AS attempt
            JOIN (
              SELECT task_id, MAX(number) AS number FROM attempts GROUP BY task_id
            ) AS latest
              ON latest.task_id = attempt.task_id AND latest.number = attempt.number
            """
        ).fetchall()
        return {row["task_id"]: dict(row) for row in rows}

    @staticmethod
    def _latest_submissions(connection: sqlite3.Connection) -> dict[str, dict[str, Any]]:
        rows = connection.execute(
            """
            SELECT submission.*, qc.verdict AS qc_verdict, qc.finished_at AS qc_finished_at
            FROM submissions AS submission
            LEFT JOIN qc_runs AS qc ON qc.id = (
              SELECT id FROM qc_runs WHERE submission_id = submission.id
              ORDER BY finished_at DESC LIMIT 1
            )
            ORDER BY submission.created_at
            """
        ).fetchall()
        return {row["task_id"]: dict(row) for row in rows}

    @staticmethod
    def _runtimes(connection: sqlite3.Connection) -> dict[str, dict[str, Any]]:
        rows = connection.execute("SELECT * FROM runtime_environments").fetchall()
        return {row["attempt_id"]: dict(row) for row in rows}

    @staticmethod
    def _quarantines(connection: sqlite3.Connection, now: float) -> dict[str, dict[str, Any]]:
        """Per-attempt quarantine summary for the operator view (#740).

        `cleanup_failed` already outranks review here, but it said only that a
        teardown had failed — not how long ago, nor whether anything might still
        be RUNNING. Those are the two facts that decide whether this is tonight's
        problem or next week's, so they belong on the one screen an operator
        actually reads.

        Severity is computed locally rather than imported: git_supervisor imports
        this module, so a reverse import would cycle.
        """

        rows = connection.execute(
            "SELECT attempt_id, driver, evidence_json, updated_at "
            "FROM runtime_driver_resources WHERE state = 'quarantined' ORDER BY driver"
        ).fetchall()
        summary: dict[str, dict[str, Any]] = {}
        for row in rows:
            try:
                evidence = json.loads(row["evidence_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                evidence = {}
            present = bool(evidence.get("present")) if isinstance(evidence, dict) else False
            proof = evidence.get("proof") if isinstance(evidence, dict) else None
            cleanup_unproven = isinstance(proof, dict) and not proof.get("cleanup_proved")
            item = summary.setdefault(
                row["attempt_id"],
                {"count": 0, "drivers": [], "age_seconds": None, "severity": "high"},
            )
            item["count"] += 1
            item["drivers"].append(row["driver"])
            age = _age_seconds(row["updated_at"], now)
            if age is not None and (item["age_seconds"] is None or age > item["age_seconds"]):
                item["age_seconds"] = age
            if present or cleanup_unproven:
                # Something may still be alive: that outranks a merely unproven row.
                item["severity"] = "critical"
        return summary

    @staticmethod
    def _allocations(connection: sqlite3.Connection) -> dict[str, list[dict[str, Any]]]:
        rows = connection.execute(
            "SELECT attempt_id, pool_name, value FROM runtime_allocations ORDER BY pool_name"
        ).fetchall()
        grouped: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            grouped.setdefault(row["attempt_id"], []).append(
                {"pool_name": row["pool_name"], "value": row["value"]}
            )
        return grouped

    @staticmethod
    def _held_resources(holders: list[dict[str, Any]]) -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = {}
        for holder in holders:
            task_id = holder.get("task_id")
            if task_id:
                grouped.setdefault(task_id, []).append(holder["resource"])
        return grouped

    # ------------------------------------------------------------------ shaping

    def _task_entry(
        self,
        task: dict[str, Any],
        attempt: dict[str, Any] | None,
        runtime: dict[str, Any] | None,
        quarantine: dict[str, Any] | None,
        allocations: list[dict[str, Any]],
        submission: dict[str, Any] | None,
        preview: dict[str, Any] | None,
        now: float,
        lease_risk_seconds: int,
        held_resources: list[str],
    ) -> dict[str, Any]:
        live = bool(attempt and attempt["status"] in LIVE_ATTEMPT_STATUSES)
        remaining = int(attempt["lease_expires_at"] - now) if live else None
        entry: dict[str, Any] = {
            "task_id": task["id"],
            "title": task["title"],
            "priority": task["priority"],
            "status": task["status"],
            "phase": attempt["status"] if live else task["status"],
            "attempt_id": attempt["id"] if attempt else None,
            "agent_id": attempt["agent_id"] if attempt else None,
            "branch": attempt["branch"] if attempt else None,
            "worktree": attempt["worktree"] if attempt else None,
            "checkpoint": json.loads(attempt["checkpoint_json"]) if attempt else {},
            "heartbeat_age_seconds": _age_seconds(attempt["updated_at"], now) if attempt else None,
            "lease_seconds_remaining": remaining,
            "lease_expired": bool(live and remaining is not None and remaining <= 0),
            "awaiting_reap": bool(
                task["status"] in CLEANUP_STATUSES
                or (live and remaining is not None and remaining <= 0)
            ),
            # #1764: claimed_paths is the folded LEASE KEY and stays folded — overlap and
            # lease identity are keyed off it. declared_claimed_paths is the same set as the
            # operator typed it, so `acp status` stops naming files that do not exist on a
            # case-sensitive checkout.
            "claimed_paths": task["resources"],
            "declared_claimed_paths": task.get("declared_resources", task["resources"]),
            "held_resources": held_resources,
            "cleanup_target_status": task.get("cleanup_target_status", ""),
            "cleanup_error": task.get("cleanup_error", ""),
            "produces": task["produces"],
            "consumes": task["consumes"],
            "runtime": {
                "state": runtime["state"],
                "recovery_action": runtime["recovery_action"],
                "allocations": allocations,
                "log_path": runtime["log_path"],
                "quarantine": quarantine,
            }
            if runtime
            else None,
            "worker": self._worker(attempt) if attempt else None,
            "qc": {
                "submission_id": submission["id"],
                "status": submission["status"],
                "verdict": submission["qc_verdict"],
                "finished_at": submission["qc_finished_at"],
            }
            if submission
            else None,
            "ready": preview["ready"] if preview else None,
            "blockers": preview["blockers"] if preview else [],
        }
        entry["category"], entry["reason"] = self._categorize(entry, lease_risk_seconds)
        return entry

    def _worker(self, attempt: dict[str, Any]) -> dict[str, Any]:
        liveness = _process_liveness(
            attempt["pid"],
            attempt.get("pid_identity", ""),
            self.supervisor._process_identity,
        )
        return {
            "status": attempt["status"],
            "pid": attempt["pid"],
            "pid_identity": attempt.get("pid_identity", ""),
            "liveness": liveness,
            "alive": True if liveness == "alive" else False if liveness == "dead" else None,
            "log_path": attempt["log_path"],
        }

    @staticmethod
    def _categorize(entry: dict[str, Any], lease_risk_seconds: int) -> tuple[str | None, str]:
        if entry["status"] in CLEANUP_STATUSES:
            worker = entry["worker"] or {}
            held = entry["held_resources"]
            details = [f"{len(held)} collision fence(s) held"]
            if worker.get("pid"):
                liveness = worker.get("liveness", "unproven")
                liveness_label = {
                    "alive": "alive",
                    "dead": "not alive",
                    "unproven": "liveness unproven",
                }.get(liveness, "liveness unproven")
                details.append(
                    f"worker pid {worker['pid']} {liveness_label}"
                    + (
                        f" identity {worker.get('pid_identity')}"
                        if worker.get("pid_identity")
                        else ""
                    )
                )
            if entry["cleanup_error"]:
                details.append(f"last error: {entry['cleanup_error']}")
            return "cleanup_failed", "; ".join(details)
        if entry["status"] in HUMAN_REQUIRED_STATUSES:
            verdict = (entry["qc"] or {}).get("verdict")
            return "human_required", f"task is {entry['status']}" + (
                f" after a {verdict} verdict" if verdict else ""
            )
        if entry["runtime"] and entry["runtime"]["state"] == "teardown_failed":
            quarantine = entry["runtime"].get("quarantine")
            if quarantine:
                age = quarantine["age_seconds"]
                owner = entry["agent_id"] or "an unknown agent"
                return "cleanup_failed", (
                    f"{quarantine['severity']}: {quarantine['count']} resource(s) quarantined"
                    + (f" for {age}s" if age is not None else "")
                    + f", owned by {owner}"
                    f" — acp runtime-quarantine explain {entry['attempt_id']}"
                )
            recovery_action = entry["runtime"].get("recovery_action")
            if recovery_action:
                return "cleanup_failed", (
                    f"interrupted {recovery_action} recovery; resume with "
                    f"acp runtime-quarantine recover {entry['attempt_id']} "
                    f"--action {recovery_action}"
                )
            return "cleanup_failed", "runtime teardown failed; resources stay quarantined"
        remaining = entry["lease_seconds_remaining"]
        if remaining is not None and remaining <= lease_risk_seconds:
            if remaining <= 0:
                return "lease_risk", "lease expired; the next claim or reap will orphan it"
            return "lease_risk", f"lease expires in {remaining}s"
        if entry["status"] in REVIEW_STATUSES:
            return "review", f"awaiting review action ({entry['status']})"
        if entry["status"] in ACTIVE_STATUSES:
            return "active", f"{entry['agent_id'] or 'an agent'} is working"
        return None, ""

    @staticmethod
    def _attention_item(entry: dict[str, Any]) -> dict[str, Any]:
        return {
            "rank": CATEGORY_RANKS[entry["category"]],
            "category": entry["category"],
            "reason": entry["reason"],
            "task_id": entry["task_id"],
            "title": entry["title"],
            "priority": entry["priority"],
            "agent_id": entry["agent_id"],
            "attempt_id": entry["attempt_id"],
        }

    # ---------------------------------------------------------------- rendering

    @staticmethod
    def render(snapshot: dict[str, Any]) -> str:
        counts = snapshot["counts"]
        lines = [
            f"ACP {snapshot['repo']}",
            (
                f"tasks {counts['tasks']}  active {counts['active']}  "
                f"ready {counts['ready']}  blocked {counts['blocked']}  "
                f"attention {counts['attention']}  cleanup-failed {counts['cleanup_failures']}"
            ),
            "",
            "ATTENTION",
        ]
        if snapshot["attention"]:
            for item in snapshot["attention"][:10]:
                agent = item["agent_id"] or "-"
                lines.append(
                    f"  {item['category']:<15} {item['title'][:32]:<32} {agent:<16} "
                    f"{item['reason']}"
                )
        else:
            lines.append("  nothing waiting on you")
        lines += ["", "TASKS"]
        for entry in snapshot["tasks"][:15]:
            heartbeat = entry["heartbeat_age_seconds"]
            beat = f"{heartbeat}s ago" if heartbeat is not None else "-"
            lines.append(
                f"  {entry['phase']:<16} {entry['title'][:32]:<32} "
                f"{entry['agent_id'] or '-':<16} hb {beat:<10} "
                f"{','.join(entry['claimed_paths'])[:40]}"
            )
        if snapshot["truncated"]:
            lines.append(f"  ... {counts['tasks'] - len(snapshot['tasks'])} more")
        return "\n".join(lines)
