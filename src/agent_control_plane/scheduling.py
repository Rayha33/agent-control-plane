"""Dependency-aware overlap preview and merge scheduling.

Every entry point here is a *preview*. Nothing in this module claims a resource,
creates a worktree, reaps an expired lease, or writes a row: an operator must be
able to ask "what would happen" without changing what will happen. The read-only
property is asserted by tests rather than assumed.

Two scopes overlap `exact`ly when their normalized forms are identical, and
`potential`ly when they are different strings that can still match one path
(`src/**` against `src/module.py`). Both block a claim; the distinction tells an
operator whether the task list needs re-partitioning or merely re-ordering.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import time
import unicodedata
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .git_supervisor import GitSupervisor

CLAIMABLE_STATUSES = frozenset({"open", "orphaned", "changes_requested"})


def normalize_artifact(raw: str) -> str:
    """Artifacts are logical names, not paths; they are matched case-insensitively."""
    from .git_supervisor import SupervisorError

    value = unicodedata.normalize("NFC", raw.strip()).casefold()
    if not value:
        raise SupervisorError("invalid_artifact", "artifact name cannot be empty")
    if any(character.isspace() for character in value):
        raise SupervisorError(
            "invalid_artifact", f"artifact name cannot contain whitespace: {raw!r}"
        )
    return value


class Scheduler:
    """Read-only planning views over supervisor state."""

    def __init__(self, supervisor: GitSupervisor):
        self.supervisor = supervisor

    # ---------------------------------------------------------------- loading

    @staticmethod
    def _task_records(connection: sqlite3.Connection) -> list[dict[str, Any]]:
        rows = connection.execute(
            "SELECT * FROM tasks ORDER BY priority DESC, created_at, id"
        ).fetchall()
        records = []
        for row in rows:
            record = dict(row)
            record["resources"] = json.loads(row["resources_json"])
            record["dependencies"] = json.loads(row["dependencies_json"])
            record["produces"] = json.loads(row["produces_json"])
            record["consumes"] = json.loads(row["consumes_json"])
            records.append(record)
        return records

    @staticmethod
    def _active_leases(connection: sqlite3.Connection, now: int) -> list[dict[str, Any]]:
        """Leases that still exclude a claim. Expired rows are ignored, never reaped."""
        rows = connection.execute(
            """
            SELECT lease.resource, lease.task_id, lease.attempt_id, lease.lease_expires_at,
                   task.title AS task_title, attempt.agent_id AS agent_id
            FROM resource_leases AS lease
            LEFT JOIN tasks AS task ON task.id = lease.task_id
            LEFT JOIN attempts AS attempt ON attempt.id = lease.attempt_id
            WHERE lease.task_id IS NOT NULL AND lease.lease_expires_at > ?
            ORDER BY lease.resource
            """,
            (now,),
        ).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------ dependencies

    def _producers(self, tasks: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        index: dict[str, list[dict[str, Any]]] = {}
        for task in tasks:
            for artifact in task["produces"]:
                index.setdefault(artifact, []).append(task)
        return index

    def _dependency_edges(self, tasks: list[dict[str, Any]]) -> dict[str, list[str]]:
        """Explicit task dependencies plus derived producer/consumer artifact edges."""
        by_id = {task["id"]: task for task in tasks}
        producers = self._producers(tasks)
        edges: dict[str, list[str]] = {}
        for task in tasks:
            targets: list[str] = []
            for dependency in task["dependencies"]:
                if dependency in by_id and dependency not in targets:
                    targets.append(dependency)
            for artifact in task["consumes"]:
                for producer in producers.get(artifact, []):
                    if producer["id"] != task["id"] and producer["id"] not in targets:
                        targets.append(producer["id"])
            edges[task["id"]] = targets
        return edges

    @staticmethod
    def _find_cycle(edges: dict[str, list[str]], start: str) -> list[str] | None:
        """Return a concrete cycle containing `start`, or None. Depth-bounded by node count."""
        stack = [(start, [start])]
        seen: set[tuple[str, ...]] = set()
        while stack:
            node, path = stack.pop()
            for target in edges.get(node, []):
                if target == start:
                    return [*path, start]
                if target in path:
                    continue
                key = (*path, target)
                if key in seen:
                    continue
                seen.add(key)
                stack.append((target, [*path, target]))
        return None

    def _dependency_blockers(
        self,
        task: dict[str, Any],
        by_id: dict[str, dict[str, Any]],
        producers: dict[str, list[dict[str, Any]]],
        edges: dict[str, list[str]],
    ) -> list[dict[str, Any]]:
        blockers: list[dict[str, Any]] = []
        for dependency in task["dependencies"]:
            row = by_id.get(dependency)
            if row is None:
                blockers.append(
                    {
                        "kind": "dependency_missing",
                        "task_id": dependency,
                        "detail": "declared dependency no longer exists",
                    }
                )
            elif row["status"] != "done":
                blockers.append(
                    {
                        "kind": "dependency_incomplete",
                        "task_id": row["id"],
                        "title": row["title"],
                        "status": row["status"],
                    }
                )
        for artifact in sorted(set(task["consumes"])):
            for producer in producers.get(artifact, []):
                if producer["id"] == task["id"] or producer["status"] == "done":
                    continue
                blockers.append(
                    {
                        "kind": "artifact_dependency_incomplete",
                        "artifact": artifact,
                        "task_id": producer["id"],
                        "title": producer["title"],
                        "status": producer["status"],
                    }
                )
        cycle = self._find_cycle(edges, task["id"])
        if cycle:
            blockers.append(
                {
                    "kind": "dependency_cycle",
                    "cycle": cycle,
                    "detail": "artifact or declared dependencies form a cycle",
                }
            )
        return blockers

    # ---------------------------------------------------------------- overlaps

    def _conflict_blockers(
        self,
        resources: list[str],
        holders: list[dict[str, Any]],
        task_id: str,
    ) -> list[dict[str, Any]]:
        overlap_of = self.supervisor.resources_overlap
        blockers: list[dict[str, Any]] = []
        for resource in resources:
            for holder in holders:
                if holder["task_id"] == task_id:
                    continue
                if not overlap_of(resource, holder["resource"]):
                    continue
                blockers.append(
                    {
                        "kind": "resource_conflict",
                        "overlap": "exact" if resource == holder["resource"] else "potential",
                        "resource": resource,
                        "conflicting_resource": holder["resource"],
                        "owner_kind": holder.get("owner_kind", "lease"),
                        "owner_task_id": holder["task_id"],
                        "owner_task_title": holder.get("task_title"),
                        "owner_attempt_id": holder.get("attempt_id"),
                        "owner_agent_id": holder.get("agent_id"),
                        "lease_expires_at": holder.get("lease_expires_at"),
                    }
                )
        return blockers

    # ------------------------------------------------------------------ views

    def plan_claim(self, task_id: str) -> dict[str, Any]:
        """Dry-run a claim: what would block it, and who owns the conflicting scope."""
        now = int(time.time())
        with self.supervisor.connect() as connection:
            self.supervisor._task_row(connection, task_id)
            tasks = self._task_records(connection)
            holders = self._active_leases(connection, now)
        return self._preview(task_id, tasks, holders)

    def _preview(
        self,
        task_id: str,
        tasks: list[dict[str, Any]],
        holders: list[dict[str, Any]],
    ) -> dict[str, Any]:
        by_id = {task["id"]: task for task in tasks}
        task = by_id[task_id]
        blockers: list[dict[str, Any]] = []
        if task["status"] not in CLAIMABLE_STATUSES:
            blockers.append({"kind": "task_unavailable", "status": task["status"]})
        blockers.extend(
            self._dependency_blockers(
                task, by_id, self._producers(tasks), self._dependency_edges(tasks)
            )
        )
        blockers.extend(self._conflict_blockers(task["resources"], holders, task_id))
        return {
            "task_id": task["id"],
            "title": task["title"],
            "status": task["status"],
            "priority": task["priority"],
            "resources": task["resources"],
            "produces": task["produces"],
            "consumes": task["consumes"],
            "ready": not blockers,
            "blockers": blockers,
        }

    def ready_queue(self) -> dict[str, Any]:
        """Ordered launch plan.

        Admitting a task reserves its scopes for the rest of the pass, so the
        `ready` list is a set of tasks that can run *at the same time* rather
        than a list of tasks that could each run alone.
        """
        now = int(time.time())
        with self.supervisor.connect() as connection:
            tasks = self._task_records(connection)
            holders = self._active_leases(connection, now)
        plan = self.plan_pass(tasks, holders)
        return {"generated_at": now, **plan}

    def plan_pass(
        self, tasks: list[dict[str, Any]], holders: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """One sequential admission pass. Shared with the status view so that
        `acp queue` and `acp status` can never disagree about what is launchable."""
        reserved = list(holders)
        ready: list[dict[str, Any]] = []
        blocked: list[dict[str, Any]] = []
        active: list[dict[str, Any]] = []
        for task in tasks:
            if task["status"] not in CLAIMABLE_STATUSES:
                active.append(
                    {"task_id": task["id"], "title": task["title"], "status": task["status"]}
                )
                continue
            preview = self._preview(task["id"], tasks, reserved)
            if preview["ready"]:
                preview["position"] = len(ready) + 1
                ready.append(preview)
                for resource in task["resources"]:
                    reserved.append(
                        {
                            "resource": resource,
                            "task_id": task["id"],
                            "task_title": task["title"],
                            "attempt_id": None,
                            "agent_id": None,
                            "lease_expires_at": None,
                            "owner_kind": "queued",
                        }
                    )
            else:
                blocked.append(preview)
        return {"ready": ready, "blocked": blocked, "active": active}

    # ------------------------------------------------------------- merge plan

    def merge_plan(self) -> dict[str, Any]:
        """Order approved submissions for integration and flag ones the base invalidated."""
        excluded: list[dict[str, Any]] = []
        with self.supervisor.connect() as connection:
            tasks = self._task_records(connection)
            candidates = []
            for task in tasks:
                if task["status"] != "approved":
                    continue
                submission = connection.execute(
                    """
                    SELECT * FROM submissions
                    WHERE task_id = ? AND status = 'approved'
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    (task["id"],),
                ).fetchone()
                if not submission:
                    continue
                assurance = self.supervisor._submission_assurance(connection, submission)
                if not assurance["ready"]:
                    excluded.append(
                        {
                            "task_id": task["id"],
                            "submission_id": submission["id"],
                            "blocker": assurance["blocker"],
                            "reason": assurance["reason"],
                            "policy_fingerprint": assurance["policy_fingerprint"],
                            "ratified_fingerprint": assurance["ratified_fingerprint"],
                        }
                    )
                    continue
                candidates.append((task, dict(submission)))

        ordered = self._merge_order(candidates)
        entries: list[dict[str, Any]] = []
        merged_paths: list[tuple[str, set[str]]] = []
        for position, (task, submission) in enumerate(ordered, start=1):
            changed = set(json.loads(submission["changed_paths_json"]))
            conflicts_with = []
            conflict_paths: set[str] = set()
            for earlier_id, earlier_paths in merged_paths:
                shared = changed & earlier_paths
                if shared:
                    conflicts_with.append(earlier_id)
                    conflict_paths |= shared
            entries.append(
                {
                    "position": position,
                    "task_id": task["id"],
                    "title": task["title"],
                    "priority": task["priority"],
                    "submission_id": submission["id"],
                    "commit_sha": submission["commit_sha"],
                    "changed_paths": sorted(changed),
                    "conflicts_with": conflicts_with,
                    "predicted_conflict_paths": sorted(conflict_paths),
                    "blocked_by": self._blocking_dependencies(task, ordered),
                    **self._base_state(task, submission),
                }
            )
            merged_paths.append((task["id"], changed))
        return {"order": entries, "count": len(entries), "excluded": excluded}

    def _merge_order(
        self, candidates: list[tuple[dict[str, Any], dict[str, Any]]]
    ) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        """Topological by dependency, then priority DESC, created_at, id. Cycles degrade
        to plain ordering rather than looping forever."""
        tasks = [task for task, _ in candidates]
        edges = self._dependency_edges(tasks)
        present = {task["id"] for task in tasks}
        pending = {
            task["id"]: [target for target in edges[task["id"]] if target in present]
            for task in tasks
        }
        remaining = sorted(
            candidates,
            key=lambda item: (-item[0]["priority"], item[0]["created_at"], item[0]["id"]),
        )
        ordered: list[tuple[dict[str, Any], dict[str, Any]]] = []
        emitted: set[str] = set()
        while remaining:
            index = next(
                (
                    position
                    for position, (task, _) in enumerate(remaining)
                    if all(target in emitted for target in pending[task["id"]])
                ),
                0,
            )
            task, submission = remaining.pop(index)
            emitted.add(task["id"])
            ordered.append((task, submission))
        return ordered

    def _blocking_dependencies(
        self,
        task: dict[str, Any],
        ordered: list[tuple[dict[str, Any], dict[str, Any]]],
    ) -> list[str]:
        present = {item[0]["id"] for item in ordered}
        edges = self._dependency_edges([item[0] for item in ordered])
        return [target for target in edges.get(task["id"], []) if target in present]

    def _base_state(self, task: dict[str, Any], submission: dict[str, Any]) -> dict[str, Any]:
        """Has the base branch moved under this submission since it was approved?"""
        git_text = self.supervisor._git_text
        current_base = git_text("rev-parse", task["base_branch"], check=False)
        commit = submission["commit_sha"]
        upstream = 0
        if current_base:
            counted = git_text("rev-list", "--count", f"{commit}..{current_base}", check=False)
            upstream = int(counted) if counted.isdigit() else 0
        return {
            "base_branch": task["base_branch"],
            "base_sha": task["base_sha"],
            "current_base_sha": current_base or None,
            "base_moved": bool(current_base) and current_base != task["base_sha"],
            "upstream_commits": upstream,
            "stale": upstream > 0,
            "base_conflicts": self._base_conflicts(current_base, commit) if upstream else [],
        }

    def _base_conflicts(self, base: str, commit: str) -> list[str] | None:
        """Paths git predicts will conflict merging `commit` into the current base.

        Uses `git merge-tree --write-tree`, which computes the merge in memory and
        writes only unreferenced objects; it never touches a worktree, index, or
        ref. Returns None when the installed Git is too old to support it.
        """
        result = subprocess.run(
            [
                "git",
                "-C",
                str(self.supervisor.root),
                "merge-tree",
                "--write-tree",
                "--name-only",
                base,
                commit,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return []
        if result.returncode != 1:
            return None
        sections = result.stdout.split("\n\n")
        if len(sections) < 2:
            return []
        return sorted(line for line in sections[0].splitlines()[1:] if line)
