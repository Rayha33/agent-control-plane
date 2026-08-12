from __future__ import annotations

import json
import sqlite3
import time
import uuid
from typing import Any

from .coordination_schemas import (
    HeartbeatRequest,
    QCReviewCreate,
    SubmissionCreate,
    TaskCreate,
)
from .database import Database, canonical_json, utc_now
from .policy import scope_allows
from .service import ControlPlaneError, ControlPlaneService

QC_RESERVATION_SECONDS = 3600


class CoordinationService:
    def __init__(self, database: Database, control_plane: ControlPlaneService):
        self.database = database
        self.control_plane = control_plane

    def create_task(self, request: TaskCreate) -> dict[str, Any]:
        task_id = str(uuid.uuid4())
        created_at = utc_now()
        with self.database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for dependency_id in request.dependencies:
                dependency = connection.execute(
                    "SELECT id FROM tasks WHERE id = ?", (dependency_id,)
                ).fetchone()
                if not dependency:
                    raise ControlPlaneError(
                        404,
                        "dependency_not_found",
                        f"dependency task {dependency_id} does not exist",
                    )
            connection.execute(
                """
                INSERT INTO tasks
                    (id, title, description, acceptance_criteria_json,
                     resources_json, priority, status, owner_agent_id,
                     claim_expires_at, claim_fencing_token, version,
                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 'open', NULL, NULL, 0, 1, ?, ?)
                """,
                (
                    task_id,
                    request.title,
                    request.description,
                    canonical_json(request.acceptance_criteria),
                    canonical_json(request.resources),
                    request.priority,
                    created_at,
                    created_at,
                ),
            )
            for dependency_id in request.dependencies:
                connection.execute(
                    """
                    INSERT INTO task_dependencies (task_id, depends_on_task_id)
                    VALUES (?, ?)
                    """,
                    (task_id, dependency_id),
                )

        self.database.append_audit(
            "task.created",
            "admin",
            {
                "dependencies": request.dependencies,
                "priority": request.priority,
                "resources": request.resources,
                "task_id": task_id,
                "title": request.title,
            },
        )
        return self.task(task_id)

    def task(self, task_id: str) -> dict[str, Any]:
        row = self.database.one("SELECT * FROM tasks WHERE id = ?", (task_id,))
        if not row:
            raise ControlPlaneError(404, "task_not_found", "task not found")
        return self._task_view(row)

    def list_tasks(self, status: str | None = None) -> list[dict[str, Any]]:
        if status:
            rows = self.database.all(
                """
                SELECT * FROM tasks WHERE status = ?
                ORDER BY priority DESC, created_at ASC
                """,
                (status,),
            )
        else:
            rows = self.database.all("SELECT * FROM tasks ORDER BY priority DESC, created_at ASC")
        return [self._task_view(row) for row in rows]

    def claim_task(self, task_id: str, token: str, ttl_seconds: int) -> dict[str, Any]:
        claims, _mandate, agent = self._agent_for_action(
            token, "coordination.claim", f"task:{task_id}", {"worker"}
        )
        now = int(time.time())
        expires_at = now + ttl_seconds
        lease_views: list[dict[str, Any]] = []

        with self.database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            task = self._task_row(connection, task_id)
            if task["status"] not in {"open", "orphaned", "changes_requested"}:
                raise ControlPlaneError(
                    409,
                    "task_unavailable",
                    f"task cannot be claimed while status is {task['status']}",
                )
            incomplete = connection.execute(
                """
                SELECT dependency.id, dependency.status
                FROM task_dependencies AS edge
                JOIN tasks AS dependency ON dependency.id = edge.depends_on_task_id
                WHERE edge.task_id = ? AND dependency.status <> 'done'
                LIMIT 1
                """,
                (task_id,),
            ).fetchone()
            if incomplete:
                raise ControlPlaneError(
                    409,
                    "dependency_incomplete",
                    f"dependency {incomplete['id']} is {incomplete['status']}",
                )

            resources = json.loads(task["resources_json"])
            for resource in resources:
                lease = connection.execute(
                    "SELECT * FROM resource_leases WHERE resource = ?", (resource,)
                ).fetchone()
                if lease and lease["task_id"] and lease["expires_at"] > now:
                    raise ControlPlaneError(
                        409,
                        "resource_busy",
                        f"resource {resource} is leased by another active task",
                    )

            claim_fencing_token = task["claim_fencing_token"] + 1
            updated_at = utc_now()
            connection.execute(
                """
                UPDATE tasks
                SET status = 'claimed', owner_agent_id = ?, claim_expires_at = ?,
                    claim_fencing_token = ?, version = version + 1, updated_at = ?
                WHERE id = ?
                """,
                (
                    agent["id"],
                    expires_at,
                    claim_fencing_token,
                    updated_at,
                    task_id,
                ),
            )
            for resource in resources:
                prior = connection.execute(
                    "SELECT fencing_token FROM resource_leases WHERE resource = ?",
                    (resource,),
                ).fetchone()
                resource_token = (prior["fencing_token"] if prior else 0) + 1
                connection.execute(
                    """
                    INSERT INTO resource_leases
                        (resource, task_id, holder_agent_id, fencing_token,
                         expires_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(resource) DO UPDATE SET
                        task_id = excluded.task_id,
                        holder_agent_id = excluded.holder_agent_id,
                        fencing_token = excluded.fencing_token,
                        expires_at = excluded.expires_at,
                        updated_at = excluded.updated_at
                    """,
                    (
                        resource,
                        task_id,
                        agent["id"],
                        resource_token,
                        expires_at,
                        updated_at,
                    ),
                )
                lease_views.append(
                    {
                        "resource": resource,
                        "task_id": task_id,
                        "holder_agent_id": agent["id"],
                        "fencing_token": resource_token,
                        "expires_at": expires_at,
                    }
                )
            connection.execute(
                """
                INSERT INTO agent_heartbeats
                    (agent_id, task_id, claim_fencing_token, checkpoint_json,
                     expires_at, updated_at)
                VALUES (?, ?, ?, '{}', ?, ?)
                ON CONFLICT(agent_id, task_id) DO UPDATE SET
                    claim_fencing_token = excluded.claim_fencing_token,
                    checkpoint_json = excluded.checkpoint_json,
                    expires_at = excluded.expires_at,
                    updated_at = excluded.updated_at
                """,
                (
                    agent["id"],
                    task_id,
                    claim_fencing_token,
                    expires_at,
                    updated_at,
                ),
            )

        self.database.append_audit(
            "task.claimed",
            claims["actor"],
            {
                "agent_id": agent["id"],
                "claim_fencing_token": claim_fencing_token,
                "expires_at": expires_at,
                "resource_fencing_tokens": {
                    lease["resource"]: lease["fencing_token"] for lease in lease_views
                },
                "task_id": task_id,
            },
        )
        return {"task": self.task(task_id), "resource_leases": lease_views}

    def heartbeat(self, task_id: str, token: str, request: HeartbeatRequest) -> dict[str, Any]:
        claims, _mandate, agent = self._agent_for_action(
            token, "coordination.heartbeat", f"task:{task_id}", {"worker"}
        )
        now = int(time.time())
        expires_at = now + request.ttl_seconds
        updated_at = utc_now()
        with self.database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            task = self._task_row(connection, task_id)
            self._assert_active_claim(
                connection,
                task,
                agent["id"],
                request.claim_fencing_token,
                request.resource_fencing_tokens,
                now,
            )
            connection.execute(
                """
                UPDATE tasks
                SET status = 'working', claim_expires_at = ?, updated_at = ?
                WHERE id = ? AND claim_fencing_token = ?
                """,
                (expires_at, updated_at, task_id, request.claim_fencing_token),
            )
            for resource, fencing_token in request.resource_fencing_tokens.items():
                changed = connection.execute(
                    """
                    UPDATE resource_leases
                    SET expires_at = ?, updated_at = ?
                    WHERE resource = ? AND task_id = ? AND holder_agent_id = ?
                      AND fencing_token = ?
                    """,
                    (
                        expires_at,
                        updated_at,
                        resource,
                        task_id,
                        agent["id"],
                        fencing_token,
                    ),
                ).rowcount
                if changed != 1:
                    raise ControlPlaneError(
                        409, "stale_fencing_token", f"stale lease for {resource}"
                    )
            connection.execute(
                """
                INSERT INTO agent_heartbeats
                    (agent_id, task_id, claim_fencing_token, checkpoint_json,
                     expires_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id, task_id) DO UPDATE SET
                    claim_fencing_token = excluded.claim_fencing_token,
                    checkpoint_json = excluded.checkpoint_json,
                    expires_at = excluded.expires_at,
                    updated_at = excluded.updated_at
                """,
                (
                    agent["id"],
                    task_id,
                    request.claim_fencing_token,
                    canonical_json(request.checkpoint),
                    expires_at,
                    updated_at,
                ),
            )

        self.database.append_audit(
            "task.heartbeat",
            claims["actor"],
            {
                "agent_id": agent["id"],
                "checkpoint_keys": sorted(request.checkpoint),
                "expires_at": expires_at,
                "task_id": task_id,
            },
        )
        return {
            "task_id": task_id,
            "agent_id": agent["id"],
            "claim_fencing_token": request.claim_fencing_token,
            "expires_at": expires_at,
            "checkpoint": request.checkpoint,
        }

    def submit(self, task_id: str, token: str, request: SubmissionCreate) -> dict[str, Any]:
        claims, _mandate, agent = self._agent_for_action(
            token, "coordination.submit", f"task:{task_id}", {"worker"}
        )
        now = int(time.time())
        submission_id = str(uuid.uuid4())
        created_at = utc_now()
        qc_reservation_expires_at = now + QC_RESERVATION_SECONDS
        with self.database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            task = self._task_row(connection, task_id)
            self._assert_active_claim(
                connection,
                task,
                agent["id"],
                request.claim_fencing_token,
                request.resource_fencing_tokens,
                now,
            )
            if task["version"] != request.task_version:
                raise ControlPlaneError(
                    409,
                    "stale_task_version",
                    f"expected task version {task['version']}",
                )
            connection.execute(
                """
                INSERT INTO submissions
                    (id, task_id, worker_agent_id, task_version,
                     claim_fencing_token, resource_fencing_tokens_json,
                     base_revision, artifact_uri,
                     artifact_hash, summary, evidence_json, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_qc', ?)
                """,
                (
                    submission_id,
                    task_id,
                    agent["id"],
                    request.task_version,
                    request.claim_fencing_token,
                    canonical_json(request.resource_fencing_tokens),
                    request.base_revision,
                    request.artifact_uri,
                    request.artifact_hash.lower(),
                    request.summary,
                    canonical_json(request.evidence),
                    created_at,
                ),
            )
            connection.execute(
                """
                UPDATE tasks
                SET status = 'qc_review', claim_expires_at = NULL,
                    version = version + 1, updated_at = ?
                WHERE id = ?
                """,
                (created_at, task_id),
            )
            for resource, fencing_token in request.resource_fencing_tokens.items():
                connection.execute(
                    """
                    UPDATE resource_leases
                    SET holder_agent_id = NULL, expires_at = ?, updated_at = ?
                    WHERE resource = ? AND task_id = ? AND holder_agent_id = ?
                      AND fencing_token = ?
                    """,
                    (
                        qc_reservation_expires_at,
                        created_at,
                        resource,
                        task_id,
                        agent["id"],
                        fencing_token,
                    ),
                )
            connection.execute(
                "DELETE FROM agent_heartbeats WHERE agent_id = ? AND task_id = ?",
                (agent["id"], task_id),
            )

        self.database.append_audit(
            "submission.created",
            claims["actor"],
            {
                "artifact_hash": request.artifact_hash.lower(),
                "base_revision": request.base_revision,
                "submission_id": submission_id,
                "task_id": task_id,
                "worker_agent_id": agent["id"],
            },
        )
        return self.submission(submission_id)

    def review(self, submission_id: str, token: str, request: QCReviewCreate) -> dict[str, Any]:
        submission = self._submission_row(submission_id)
        task_id = submission["task_id"]
        claims, _mandate, agent = self._agent_for_action(
            token, "coordination.review", f"task:{task_id}", {"qc"}
        )
        if agent["id"] == submission["worker_agent_id"]:
            raise ControlPlaneError(
                403,
                "self_review_forbidden",
                "workers cannot review their own submission",
            )

        review_id = str(uuid.uuid4())
        created_at = utc_now()
        submission_status, task_status = {
            "pass": ("approved", "approved"),
            "revise": ("changes_requested", "changes_requested"),
            "block": ("blocked", "blocked"),
            "human_required": ("human_required", "blocked"),
        }[request.verdict]
        findings = [finding.model_dump() for finding in request.findings]

        with self.database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current_submission = connection.execute(
                "SELECT * FROM submissions WHERE id = ?", (submission_id,)
            ).fetchone()
            task = self._task_row(connection, task_id)
            latest = connection.execute(
                """
                SELECT id FROM submissions
                WHERE task_id = ? ORDER BY created_at DESC, id DESC LIMIT 1
                """,
                (task_id,),
            ).fetchone()
            if (
                not current_submission
                or current_submission["status"] != "pending_qc"
                or task["status"] != "qc_review"
                or not latest
                or latest["id"] != submission_id
            ):
                raise ControlPlaneError(
                    409,
                    "submission_not_reviewable",
                    "submission is stale or has already been reviewed",
                )
            connection.execute(
                """
                INSERT INTO reviews
                    (id, submission_id, qc_agent_id, verdict, summary,
                     findings_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    review_id,
                    submission_id,
                    agent["id"],
                    request.verdict,
                    request.summary,
                    canonical_json(findings),
                    created_at,
                ),
            )
            connection.execute(
                "UPDATE submissions SET status = ? WHERE id = ?",
                (submission_status, submission_id),
            )
            connection.execute(
                """
                UPDATE tasks
                SET status = ?, owner_agent_id = NULL, claim_expires_at = NULL,
                    version = version + 1, updated_at = ?
                WHERE id = ?
                """,
                (task_status, created_at, task_id),
            )
            if request.verdict == "pass":
                resources = json.loads(task["resources_json"])
                for resource in resources:
                    reservation = connection.execute(
                        "SELECT * FROM resource_leases WHERE resource = ?",
                        (resource,),
                    ).fetchone()
                    if (
                        not reservation
                        or reservation["task_id"] != task_id
                        or reservation["expires_at"] <= int(time.time())
                    ):
                        raise ControlPlaneError(
                            409,
                            "qc_reservation_lost",
                            f"resource reservation expired for {resource}",
                        )
                connection.execute(
                    """
                    UPDATE resource_leases
                    SET expires_at = ?, updated_at = ?
                    WHERE task_id = ?
                    """,
                    (int(time.time()) + QC_RESERVATION_SECONDS, created_at, task_id),
                )
            else:
                connection.execute(
                    """
                    UPDATE resource_leases
                    SET task_id = NULL, holder_agent_id = NULL,
                        expires_at = 0, updated_at = ?
                    WHERE task_id = ?
                    """,
                    (created_at, task_id),
                )

        self.database.append_audit(
            "review.completed",
            claims["actor"],
            {
                "finding_count": len(findings),
                "qc_agent_id": agent["id"],
                "review_id": review_id,
                "submission_id": submission_id,
                "task_id": task_id,
                "verdict": request.verdict,
            },
        )
        return self.review_view(review_id)

    def complete_task(self, task_id: str, reason: str) -> dict[str, Any]:
        completed_at = utc_now()
        with self.database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            task = self._task_row(connection, task_id)
            if task["status"] != "approved":
                raise ControlPlaneError(
                    409,
                    "qc_gate_not_passed",
                    "task cannot complete without an approved QC review",
                )
            latest = connection.execute(
                """
                SELECT submission.id, submission.status, review.verdict,
                       submission.resource_fencing_tokens_json
                FROM submissions AS submission
                LEFT JOIN reviews AS review ON review.submission_id = submission.id
                WHERE submission.task_id = ?
                ORDER BY submission.created_at DESC, review.created_at DESC
                LIMIT 1
                """,
                (task_id,),
            ).fetchone()
            if not latest or latest["status"] != "approved" or latest["verdict"] != "pass":
                raise ControlPlaneError(
                    409,
                    "qc_evidence_missing",
                    "latest submission lacks a passing independent review",
                )
            expected_tokens = json.loads(latest["resource_fencing_tokens_json"])
            reservations = connection.execute(
                "SELECT * FROM resource_leases WHERE task_id = ?",
                (task_id,),
            ).fetchall()
            actual_tokens = {
                reservation["resource"]: reservation["fencing_token"]
                for reservation in reservations
                if reservation["expires_at"] > int(time.time())
            }
            if actual_tokens != expected_tokens:
                raise ControlPlaneError(
                    409,
                    "reservation_lost",
                    "approved work cannot complete after its fenced reservation expires",
                )
            connection.execute(
                """
                UPDATE tasks
                SET status = 'done', version = version + 1, updated_at = ?
                WHERE id = ?
                """,
                (completed_at, task_id),
            )
            connection.execute(
                """
                UPDATE resource_leases
                SET task_id = NULL, holder_agent_id = NULL,
                    expires_at = 0, updated_at = ?
                WHERE task_id = ?
                """,
                (completed_at, task_id),
            )

        self.database.append_audit(
            "task.completed",
            "admin",
            {"reason": reason, "task_id": task_id},
        )
        return self.task(task_id)

    def reap_expired(self) -> dict[str, Any]:
        now = int(time.time())
        updated_at = utc_now()
        orphaned: list[str] = []
        conflicted: list[str] = []
        released = 0
        with self.database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """
                SELECT id FROM tasks
                WHERE status IN ('claimed', 'working')
                  AND claim_expires_at IS NOT NULL
                  AND claim_expires_at <= ?
                """,
                (now,),
            ).fetchall()
            orphaned = [row["id"] for row in rows]
            for task_id in orphaned:
                connection.execute(
                    """
                    UPDATE tasks
                    SET status = 'orphaned', owner_agent_id = NULL,
                        claim_expires_at = NULL, version = version + 1,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (updated_at, task_id),
                )
                released += connection.execute(
                    """
                    UPDATE resource_leases
                    SET task_id = NULL, holder_agent_id = NULL,
                        expires_at = 0, updated_at = ?
                    WHERE task_id = ?
                    """,
                    (updated_at, task_id),
                ).rowcount
                connection.execute("DELETE FROM agent_heartbeats WHERE task_id = ?", (task_id,))

            rows = connection.execute(
                """
                SELECT DISTINCT task.id
                FROM tasks AS task
                JOIN resource_leases AS lease ON lease.task_id = task.id
                WHERE task.status IN ('qc_review', 'approved')
                  AND lease.expires_at <= ?
                """,
                (now,),
            ).fetchall()
            conflicted = [row["id"] for row in rows]
            for task_id in conflicted:
                connection.execute(
                    """
                    UPDATE tasks
                    SET status = 'conflicted', version = version + 1,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (updated_at, task_id),
                )

            released += connection.execute(
                """
                UPDATE resource_leases
                SET task_id = NULL, holder_agent_id = NULL,
                    expires_at = 0, updated_at = ?
                WHERE task_id IS NOT NULL AND expires_at <= ?
                """,
                (updated_at, now),
            ).rowcount

        if orphaned or conflicted or released:
            self.database.append_audit(
                "coordination.reaped",
                "admin",
                {
                    "conflicted_task_ids": conflicted,
                    "orphaned_task_ids": orphaned,
                    "released_resources": released,
                },
            )
        return {
            "conflicted_task_ids": conflicted,
            "orphaned_task_ids": orphaned,
            "released_resources": released,
        }

    def submission(self, submission_id: str) -> dict[str, Any]:
        return self._submission_view(self._submission_row(submission_id))

    def review_view(self, review_id: str) -> dict[str, Any]:
        row = self.database.one("SELECT * FROM reviews WHERE id = ?", (review_id,))
        if not row:
            raise ControlPlaneError(404, "review_not_found", "review not found")
        return self._review_view(row)

    def _agent_for_action(
        self,
        token: str,
        action: str,
        resource: str,
        allowed_roles: set[str],
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        claims, mandate, agent = self.control_plane.authenticated_agent(token)
        if agent["role"] not in allowed_roles:
            raise ControlPlaneError(
                403,
                "role_forbidden",
                f"agent role {agent['role']} cannot perform {action}",
            )
        if not scope_allows(claims["scopes"], action, resource):
            raise ControlPlaneError(
                403,
                "coordination_scope_denied",
                f"mandate does not allow {action} on {resource}",
            )
        return claims, mandate, agent

    @staticmethod
    def _task_row(connection: sqlite3.Connection, task_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not row:
            raise ControlPlaneError(404, "task_not_found", "task not found")
        return row

    def _submission_row(self, submission_id: str) -> sqlite3.Row:
        row = self.database.one("SELECT * FROM submissions WHERE id = ?", (submission_id,))
        if not row:
            raise ControlPlaneError(404, "submission_not_found", "submission not found")
        return row

    def _assert_active_claim(
        self,
        connection: sqlite3.Connection,
        task: sqlite3.Row,
        agent_id: str,
        claim_fencing_token: int,
        resource_fencing_tokens: dict[str, int],
        now: int,
    ) -> None:
        if task["status"] not in {"claimed", "working"}:
            raise ControlPlaneError(409, "claim_inactive", "task claim is not active")
        if (
            task["owner_agent_id"] != agent_id
            or task["claim_fencing_token"] != claim_fencing_token
            or not task["claim_expires_at"]
            or task["claim_expires_at"] <= now
        ):
            raise ControlPlaneError(
                409, "stale_claim_fencing_token", "task claim is stale or expired"
            )
        resources = set(json.loads(task["resources_json"]))
        if set(resource_fencing_tokens) != resources:
            raise ControlPlaneError(
                409,
                "incomplete_resource_fencing_tokens",
                "submission must carry every leased resource token",
            )
        for resource, fencing_token in resource_fencing_tokens.items():
            lease = connection.execute(
                "SELECT * FROM resource_leases WHERE resource = ?", (resource,)
            ).fetchone()
            if (
                not lease
                or lease["task_id"] != task["id"]
                or lease["holder_agent_id"] != agent_id
                or lease["fencing_token"] != fencing_token
                or lease["expires_at"] <= now
            ):
                raise ControlPlaneError(409, "stale_fencing_token", f"stale lease for {resource}")

    def _task_view(self, row: sqlite3.Row) -> dict[str, Any]:
        dependencies = self.database.all(
            """
            SELECT depends_on_task_id FROM task_dependencies
            WHERE task_id = ? ORDER BY depends_on_task_id
            """,
            (row["id"],),
        )
        latest_submission = self.database.one(
            """
            SELECT * FROM submissions
            WHERE task_id = ? ORDER BY created_at DESC, id DESC LIMIT 1
            """,
            (row["id"],),
        )
        latest_review = self.database.one(
            """
            SELECT review.* FROM reviews AS review
            JOIN submissions AS submission ON submission.id = review.submission_id
            WHERE submission.task_id = ?
            ORDER BY review.created_at DESC, review.id DESC LIMIT 1
            """,
            (row["id"],),
        )
        return {
            "id": row["id"],
            "title": row["title"],
            "description": row["description"],
            "acceptance_criteria": json.loads(row["acceptance_criteria_json"]),
            "resources": json.loads(row["resources_json"]),
            "dependencies": [dependency["depends_on_task_id"] for dependency in dependencies],
            "priority": row["priority"],
            "status": row["status"],
            "owner_agent_id": row["owner_agent_id"],
            "claim_expires_at": row["claim_expires_at"],
            "claim_fencing_token": row["claim_fencing_token"],
            "version": row["version"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "latest_submission": (
                self._submission_view(latest_submission) if latest_submission else None
            ),
            "latest_review": self._review_view(latest_review) if latest_review else None,
        }

    @staticmethod
    def _submission_view(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "task_id": row["task_id"],
            "worker_agent_id": row["worker_agent_id"],
            "task_version": row["task_version"],
            "claim_fencing_token": row["claim_fencing_token"],
            "resource_fencing_tokens": json.loads(row["resource_fencing_tokens_json"]),
            "base_revision": row["base_revision"],
            "artifact_uri": row["artifact_uri"],
            "artifact_hash": row["artifact_hash"],
            "summary": row["summary"],
            "evidence": json.loads(row["evidence_json"]),
            "status": row["status"],
            "created_at": row["created_at"],
        }

    @staticmethod
    def _review_view(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "submission_id": row["submission_id"],
            "qc_agent_id": row["qc_agent_id"],
            "verdict": row["verdict"],
            "summary": row["summary"],
            "findings": json.loads(row["findings_json"]),
            "created_at": row["created_at"],
        }
