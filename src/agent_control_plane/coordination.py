from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from .coordination_schemas import (
    BudgetInterruptionReportCreate,
    BudgetInterruptionReportView,
    ClaimBudgetView,
    DispatchAttemptBudgetView,
    DispatchAttemptReceiptCreate,
    DispatchAttemptReceiptView,
    DispatchAttemptReservationCreate,
    HeartbeatRequest,
    OutstandingDispatchBudgetView,
    ProviderUsageEvidence,
    ProviderUsageReport,
    QCReviewCreate,
    ReportedProviderUsageView,
    SubmissionCreate,
    TaskCreate,
)
from .database import Database, canonical_json, utc_now
from .policy import scope_allows
from .scheduling import declared_resources
from .service import ControlPlaneError, ControlPlaneService

QC_RESERVATION_SECONDS = 3600
_PROVIDER_USAGE_SUMMARY_MAX_RESERVATIONS = 1000


class CoordinationService:
    def __init__(self, database: Database, control_plane: ControlPlaneService):
        self.database = database
        self.control_plane = control_plane

    def create_task(self, request: TaskCreate) -> dict[str, Any]:
        if request.provider_cost_limit_usd_micros is not None:
            raise ControlPlaneError(
                422,
                "budget_capability_unsupported",
                "provider cost hard limit requested but unsupported: no authenticated provider "
                "meter or request gate is configured",
            )
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
            if request.parent_task_id is not None:
                parent = connection.execute(
                    "SELECT * FROM tasks WHERE id = ?", (request.parent_task_id,)
                ).fetchone()
                if not parent:
                    raise ControlPlaneError(
                        404,
                        "parent_task_not_found",
                        f"parent task {request.parent_task_id} does not exist",
                    )
                self._task_ancestor_chain(connection, parent)
            connection.execute(
                """
                INSERT INTO tasks
                    (id, title, description, acceptance_criteria_json,
                     resources_json, priority, status, owner_agent_id,
                     claim_expires_at, claim_fencing_token, parent_task_id,
                     max_claims, max_descendant_claims, max_dispatch_attempts,
                     max_descendant_dispatch_attempts, max_unreceipted_dispatch_attempts,
                     max_descendant_unreceipted_dispatch_attempts, version,
                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 'open', NULL, NULL, 0, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    task_id,
                    request.title,
                    request.description,
                    canonical_json(request.acceptance_criteria),
                    canonical_json(request.resources),
                    request.priority,
                    request.parent_task_id,
                    request.max_claims,
                    request.max_descendant_claims,
                    request.max_dispatch_attempts,
                    request.max_descendant_dispatch_attempts,
                    request.max_unreceipted_dispatch_attempts,
                    request.max_descendant_unreceipted_dispatch_attempts,
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
                    "max_claims": request.max_claims,
                    "max_descendant_claims": request.max_descendant_claims,
                    "max_dispatch_attempts": request.max_dispatch_attempts,
                    "max_descendant_dispatch_attempts": request.max_descendant_dispatch_attempts,
                    "max_unreceipted_dispatch_attempts": (
                        request.max_unreceipted_dispatch_attempts
                    ),
                    "max_descendant_unreceipted_dispatch_attempts": (
                        request.max_descendant_unreceipted_dispatch_attempts
                    ),
                    "parent_task_id": request.parent_task_id,
                    "priority": request.priority,
                    "resources": request.resources,
                    "task_id": task_id,
                    "title": request.title,
                },
                connection=connection,
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
        return [
            self._task_view(row, include_reported_usage=False, include_interruption_report=False)
            for row in rows
        ]

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
            ancestors = self._task_ancestor_chain(connection, task)
            claims_used = self._claim_count(task["claim_fencing_token"])
            local_limit = self._claim_limit(task["max_claims"], "max_claims")
            if local_limit is not None and claims_used >= local_limit:
                raise ControlPlaneError(
                    409,
                    "task_claim_budget_exhausted",
                    f"task {task_id} has used {claims_used} of {local_limit} successful claims",
                )
            for ancestor in ancestors:
                descendant_limit = self._claim_limit(
                    ancestor["max_descendant_claims"],
                    "max_descendant_claims",
                    allow_zero=True,
                )
                if descendant_limit is None:
                    continue
                descendant_claims = self._descendant_claim_count(connection, ancestor["id"])
                if descendant_claims is None:
                    raise ControlPlaneError(
                        409,
                        "task_lineage_invalid",
                        f"task lineage below ancestor {ancestor['id']} is invalid",
                    )
                if descendant_claims >= descendant_limit:
                    raise ControlPlaneError(
                        409,
                        "descendant_claim_budget_exhausted",
                        f"descendants of task {ancestor['id']} have used "
                        f"{descendant_claims} of {descendant_limit} successful claims",
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
            try:
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
            except sqlite3.IntegrityError as error:
                self._raise_claim_guard_error(error)
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
                connection=connection,
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
                connection=connection,
            )
        return {
            "task_id": task_id,
            "agent_id": agent["id"],
            "claim_fencing_token": request.claim_fencing_token,
            "expires_at": expires_at,
            "checkpoint": request.checkpoint,
        }

    def reserve_dispatch_attempt(
        self, task_id: str, token: str, request: DispatchAttemptReservationCreate
    ) -> dict[str, Any]:
        """Reserve one cooperative outbound-dispatch slot before a client call."""
        claims, _mandate, agent = self._agent_for_action(
            token, "coordination.dispatch", f"task:{task_id}", {"worker"}
        )
        reservation_id = str(uuid.uuid4())
        resource_fencing_tokens_json = json.dumps(
            request.resource_fencing_tokens, sort_keys=True, separators=(",", ":")
        )
        with self.database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            now = int(time.time())
            created_at = utc_now()
            task = self._task_row(connection, task_id)
            self._assert_active_claim(
                connection,
                task,
                agent["id"],
                request.claim_fencing_token,
                request.resource_fencing_tokens,
                now,
            )
            interrupted = connection.execute(
                """SELECT 1 WHERE EXISTS (
                       SELECT 1 FROM budget_unresolved_interruption_reports
                       WHERE task_id = ?
                   ) OR EXISTS (
                       SELECT 1 FROM budget_interruption_reports
                       WHERE task_id = ? AND agent_id = ? AND claim_fencing_token = ?
                   )""",
                (task_id, task_id, agent["id"], request.claim_fencing_token),
            ).fetchone()
            if interrupted is not None:
                raise ControlPlaneError(
                    409,
                    "claim_interrupted",
                    "this claim generation reported an interruption and cannot reserve more "
                    "dispatches or submit; resume only under a newly fenced claim",
                )
            existing = connection.execute(
                "SELECT * FROM dispatch_attempt_reservations "
                "WHERE task_id = ? AND idempotency_key = ?",
                (task_id, request.idempotency_key),
            ).fetchone()
            if existing:
                if (
                    existing["agent_id"] != agent["id"]
                    or existing["claim_fencing_token"] != request.claim_fencing_token
                    or existing["resource_fencing_tokens_json"] != resource_fencing_tokens_json
                ):
                    raise ControlPlaneError(
                        409,
                        "dispatch_idempotency_conflict",
                        "idempotency key belongs to a different claim generation",
                    )
                return {
                    "reservation": self._dispatch_attempt_view(connection, existing),
                    "created": False,
                }

            ancestors = self._task_ancestor_chain(connection, task)
            task_limit = self._dispatch_limit(
                task["max_dispatch_attempts"], "max_dispatch_attempts"
            )
            task_used = self._dispatch_attempt_count(connection, task_id)
            if task_limit is not None and task_used >= task_limit:
                raise ControlPlaneError(
                    409,
                    "task_dispatch_budget_exhausted",
                    "task has exhausted its cooperative dispatch-attempt limit",
                )
            for ancestor in ancestors:
                ancestor_limit = self._dispatch_limit(
                    ancestor["max_descendant_dispatch_attempts"],
                    "max_descendant_dispatch_attempts",
                )
                descendant_outstanding_limit = self._dispatch_limit(
                    ancestor["max_descendant_unreceipted_dispatch_attempts"],
                    "max_descendant_unreceipted_dispatch_attempts",
                )
                descendant_counts = self._descendant_dispatch_attempt_counts(
                    connection, ancestor["id"]
                )
                if descendant_counts is None:
                    raise ControlPlaneError(
                        409,
                        "descendant_dispatch_budget_invalid",
                        "descendant task lineage is invalid",
                    )
                descendant_used, descendant_outstanding = descendant_counts
                if ancestor_limit is not None and descendant_used >= ancestor_limit:
                    raise ControlPlaneError(
                        409,
                        "descendant_dispatch_budget_exhausted",
                        "an ancestor task has exhausted its descendant dispatch-attempt limit",
                    )
                if (
                    descendant_outstanding_limit is not None
                    and descendant_outstanding >= descendant_outstanding_limit
                ):
                    raise ControlPlaneError(
                        409,
                        "descendant_dispatch_outstanding_budget_exhausted",
                        "an ancestor task has exhausted its outstanding descendant "
                        "dispatch-reservation limit",
                    )

            task_outstanding_limit = self._dispatch_limit(
                task["max_unreceipted_dispatch_attempts"],
                "max_unreceipted_dispatch_attempts",
            )
            task_outstanding = self._dispatch_attempt_outstanding_count(connection, task_id)
            if task_outstanding_limit is not None and task_outstanding >= task_outstanding_limit:
                raise ControlPlaneError(
                    409,
                    "task_dispatch_outstanding_budget_exhausted",
                    "task has exhausted its outstanding dispatch-reservation limit",
                )

            # Recheck time-based task/resource leases immediately before the
            # irreversible reservation insert; BEGIN IMMEDIATE prevents their
            # fencing rows from changing while this transaction is held.
            self._assert_active_claim(
                connection,
                task,
                agent["id"],
                request.claim_fencing_token,
                request.resource_fencing_tokens,
                int(time.time()),
            )
            try:
                connection.execute(
                    """
                    INSERT INTO dispatch_attempt_reservations
                        (id, task_id, agent_id, claim_fencing_token,
                         resource_fencing_tokens_json, idempotency_key, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        reservation_id,
                        task_id,
                        agent["id"],
                        request.claim_fencing_token,
                        resource_fencing_tokens_json,
                        request.idempotency_key,
                        created_at,
                    ),
                )
            except sqlite3.IntegrityError as error:
                self._raise_dispatch_guard_error(error)
            self.database.append_audit(
                "dispatch_attempt.reserved",
                claims["actor"],
                {
                    "agent_id": agent["id"],
                    "claim_fencing_token": request.claim_fencing_token,
                    "dispatch_attempt_id": reservation_id,
                    "resource_fencing_tokens": request.resource_fencing_tokens,
                    "task_id": task_id,
                },
                connection=connection,
            )
            reservation = connection.execute(
                "SELECT * FROM dispatch_attempt_reservations WHERE id = ?",
                (reservation_id,),
            ).fetchone()
            assert reservation is not None
            return {
                "reservation": self._dispatch_attempt_view(connection, reservation),
                "created": True,
            }

    def record_dispatch_attempt_receipt(
        self,
        task_id: str,
        dispatch_attempt_id: str,
        token: str,
        request: DispatchAttemptReceiptCreate,
    ) -> dict[str, Any]:
        """Persist an immutable, explicitly client-reported response observation."""
        claims, _mandate, agent = self._agent_for_action(
            token, "coordination.dispatch_receipt", f"task:{task_id}", {"worker"}
        )
        received_at = utc_now()
        provider_usage_json = (
            canonical_json(request.provider_usage_report.model_dump())
            if request.provider_usage_report is not None
            else "{}"
        )
        with self.database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            reservation = connection.execute(
                "SELECT * FROM dispatch_attempt_reservations WHERE id = ? AND task_id = ?",
                (dispatch_attempt_id, task_id),
            ).fetchone()
            if not reservation:
                raise ControlPlaneError(
                    404, "dispatch_attempt_not_found", "dispatch attempt reservation not found"
                )
            if (
                reservation["agent_id"] != agent["id"]
                or reservation["claim_fencing_token"] != request.claim_fencing_token
            ):
                raise ControlPlaneError(
                    409,
                    "dispatch_attempt_fence_mismatch",
                    "receipt does not match the reservation's worker and claim fence",
                )
            existing = connection.execute(
                "SELECT * FROM dispatch_attempt_receipts WHERE dispatch_attempt_id = ?",
                (dispatch_attempt_id,),
            ).fetchone()
            if existing:
                if (
                    existing["http_status_code"] != request.http_status_code
                    or existing["retry_after_seconds"] != request.retry_after_seconds
                    or (existing["provider_usage_json"] or "{}") != provider_usage_json
                ):
                    raise ControlPlaneError(
                        409,
                        "dispatch_attempt_receipt_conflict",
                        "dispatch attempt already has a different immutable receipt",
                    )
                return {"receipt": self._dispatch_attempt_receipt_view(existing), "created": False}

            connection.execute(
                """
                INSERT INTO dispatch_attempt_receipts
                    (dispatch_attempt_id, source, http_status_code,
                     retry_after_seconds, received_at, provider_usage_json)
                VALUES (?, 'client_reported', ?, ?, ?, ?)
                """,
                (
                    dispatch_attempt_id,
                    request.http_status_code,
                    request.retry_after_seconds,
                    received_at,
                    provider_usage_json,
                ),
            )
            self.database.append_audit(
                "dispatch_attempt.receipt_reported",
                claims["actor"],
                {
                    "dispatch_attempt_id": dispatch_attempt_id,
                    "http_status_code": request.http_status_code,
                    "retry_after_seconds": request.retry_after_seconds,
                    "source": "client_reported",
                    "task_id": task_id,
                    "provider_usage_status": (
                        request.provider_usage_report.status
                        if request.provider_usage_report is not None
                        else "unsupported"
                    ),
                },
                connection=connection,
            )
            receipt = connection.execute(
                "SELECT * FROM dispatch_attempt_receipts WHERE dispatch_attempt_id = ?",
                (dispatch_attempt_id,),
            ).fetchone()
            assert receipt is not None
            return {"receipt": self._dispatch_attempt_receipt_view(receipt), "created": True}

    def record_budget_interruption_report(
        self,
        task_id: str,
        token: str,
        request: BudgetInterruptionReportCreate,
    ) -> dict[str, Any]:
        """Persist a fenced, bounded checkpoint without changing task lifecycle state."""
        claims, _mandate, agent = self._agent_for_action(
            token, "coordination.interruption_report", f"task:{task_id}", {"worker"}
        )
        report_id = str(uuid.uuid4())
        received_at = utc_now()
        checkpoint_json = canonical_json(request.checkpoint)
        checkpoint_sha256 = hashlib.sha256(checkpoint_json.encode("utf-8")).hexdigest()
        resource_tokens_json = canonical_json(request.resource_fencing_tokens)
        dispatch_ids_json = canonical_json(request.dispatch_attempt_ids)
        with self.database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            values = {
                "agent_id": agent["id"],
                "claim_fencing_token": request.claim_fencing_token,
                "resource_fencing_tokens_json": resource_tokens_json,
                "reason": request.reason,
                "summary": request.summary,
                "checkpoint_json": checkpoint_json,
                "checkpoint_sha256": checkpoint_sha256,
                "dispatch_attempt_ids_json": dispatch_ids_json,
            }
            existing = connection.execute(
                """SELECT * FROM budget_interruption_reports
                   WHERE task_id = ? AND claim_fencing_token = ?""",
                (task_id, request.claim_fencing_token),
            ).fetchone()
            if existing is not None:
                if any(existing[key] != value for key, value in values.items()):
                    raise ControlPlaneError(
                        409,
                        "interruption_report_conflict",
                        "this claim already has a different immutable interruption report",
                    )
                return {
                    "report": self._budget_interruption_report_view(connection, existing),
                    "created": False,
                }

            task = self._task_row(connection, task_id)
            self._assert_active_claim(
                connection,
                task,
                agent["id"],
                request.claim_fencing_token,
                request.resource_fencing_tokens,
                int(time.time()),
            )
            for dispatch_attempt_id in request.dispatch_attempt_ids:
                receipt = connection.execute(
                    """
                    SELECT reservation.id, reservation.resource_fencing_tokens_json
                    FROM dispatch_attempt_reservations AS reservation
                    JOIN dispatch_attempt_receipts AS receipt
                      ON receipt.dispatch_attempt_id = reservation.id
                    WHERE reservation.id = ? AND reservation.task_id = ?
                      AND reservation.agent_id = ?
                      AND reservation.claim_fencing_token = ?
                    """,
                    (
                        dispatch_attempt_id,
                        task_id,
                        agent["id"],
                        request.claim_fencing_token,
                    ),
                ).fetchone()
                if receipt is None or not self._resource_fencing_tokens_match(
                    receipt["resource_fencing_tokens_json"],
                    request.resource_fencing_tokens,
                ):
                    raise ControlPlaneError(
                        422,
                        "interruption_dispatch_receipt_invalid",
                        "every linked dispatch attempt must have a client-reported receipt "
                        "from this task claim and resource fence",
                    )

            # The first check fences linked receipts. Recheck the wall-clock expiry
            # immediately before persistence so a claim expiring during validation
            # cannot create a fresh interruption report.
            self._assert_active_claim(
                connection,
                task,
                agent["id"],
                request.claim_fencing_token,
                request.resource_fencing_tokens,
                int(time.time()),
            )
            connection.execute(
                """
                INSERT INTO budget_interruption_reports
                  (id, task_id, agent_id, claim_fencing_token,
                   resource_fencing_tokens_json, status, source, reason, summary,
                   checkpoint_json, checkpoint_sha256, dispatch_attempt_ids_json, received_at)
                VALUES (?, ?, ?, ?, ?, 'partial', 'client_reported', ?, ?, ?, ?, ?, ?)
                """,
                (
                    report_id,
                    task_id,
                    agent["id"],
                    request.claim_fencing_token,
                    resource_tokens_json,
                    request.reason,
                    request.summary,
                    checkpoint_json,
                    checkpoint_sha256,
                    dispatch_ids_json,
                    received_at,
                ),
            )
            self.database.append_audit(
                "task.interruption_reported",
                claims["actor"],
                {
                    "checkpoint_sha256": checkpoint_sha256,
                    "claim_fencing_token": request.claim_fencing_token,
                    "dispatch_attempt_ids": request.dispatch_attempt_ids,
                    "reason": request.reason,
                    "report_id": report_id,
                    "source": "client_reported",
                    "status": "partial",
                    "task_id": task_id,
                },
                connection=connection,
            )
            report = connection.execute(
                "SELECT * FROM budget_interruption_reports WHERE id = ?", (report_id,)
            ).fetchone()
            assert report is not None
            return {
                "report": self._budget_interruption_report_view(connection, report),
                "created": True,
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
            interrupted = connection.execute(
                """SELECT 1 WHERE EXISTS (
                       SELECT 1 FROM budget_unresolved_interruption_reports
                       WHERE task_id = ?
                   ) OR EXISTS (
                       SELECT 1 FROM budget_interruption_reports
                       WHERE task_id = ? AND agent_id = ? AND claim_fencing_token = ?
                   )""",
                (task_id, task_id, agent["id"], request.claim_fencing_token),
            ).fetchone()
            if interrupted is not None:
                raise ControlPlaneError(
                    409,
                    "claim_interrupted",
                    "this claim generation reported an interruption and cannot reserve more "
                    "dispatches or submit; resume only under a newly fenced claim",
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
            self._clear_heartbeats(connection, task_id)

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
                connection=connection,
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
            self._clear_heartbeats(connection, task_id)
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
                connection=connection,
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
            self._clear_heartbeats(connection, task_id)

            self.database.append_audit(
                "task.completed",
                "admin",
                {"reason": reason, "task_id": task_id},
                connection=connection,
            )
        return self.task(task_id)

    def reopen_task(self, task_id: str, reason: str) -> dict[str, Any]:
        """Return a task the service parked to the pool after operator action.

        ``conflicted`` (the reaper found its post-submission reservation expired)
        and ``blocked`` (QC blocked it or asked for a human) are the two states
        nothing else leaves. Reopening is explicit and audited: the task goes
        back to ``open`` with a new version, any remaining reservation is
        released, and the next claim mints fresh fencing tokens.
        """
        reopened_at = utc_now()
        with self.database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            task = self._task_row(connection, task_id)
            previous_status = task["status"]
            if previous_status not in {"conflicted", "blocked"}:
                raise ControlPlaneError(
                    409,
                    "task_not_reopenable",
                    f"task cannot be reopened while status is {previous_status}",
                )
            self.database.append_audit(
                "task.reopened",
                "admin",
                {
                    "previous_status": previous_status,
                    "reason": reason,
                    "task_id": task_id,
                },
                connection=connection,
            )
            connection.execute(
                """
                UPDATE tasks
                SET status = 'open', owner_agent_id = NULL, claim_expires_at = NULL,
                    version = version + 1, updated_at = ?
                WHERE id = ?
                """,
                (reopened_at, task_id),
            )
            connection.execute(
                """
                UPDATE resource_leases
                SET task_id = NULL, holder_agent_id = NULL,
                    expires_at = 0, updated_at = ?
                WHERE task_id = ?
                """,
                (reopened_at, task_id),
            )
            self._clear_heartbeats(connection, task_id)
        return self.task(task_id)

    def reap_expired(self) -> dict[str, Any]:
        now = int(time.time())
        updated_at = utc_now()
        orphaned: list[str] = []
        blocked_interruption_task_ids: list[str] = []
        conflicted: list[str] = []
        released = 0
        with self.database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """
                SELECT task.id,
                       EXISTS (
                           SELECT 1 FROM budget_unresolved_interruption_reports AS report
                           WHERE report.task_id = task.id
                       ) AS interruption_reported
                FROM tasks AS task
                WHERE task.status IN ('claimed', 'working')
                  AND task.claim_expires_at IS NOT NULL
                  AND task.claim_expires_at <= ?
                """,
                (now,),
            ).fetchall()
            orphaned = [row["id"] for row in rows if not row["interruption_reported"]]
            blocked_interruption_task_ids = [
                row["id"] for row in rows if row["interruption_reported"]
            ]
            for row in rows:
                task_id = row["id"]
                expired_status = "blocked" if row["interruption_reported"] else "orphaned"
                connection.execute(
                    """
                    UPDATE tasks
                    SET status = ?, owner_agent_id = NULL,
                        claim_expires_at = NULL, version = version + 1,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (expired_status, updated_at, task_id),
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
                self._clear_heartbeats(connection, task_id)

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

            if orphaned or blocked_interruption_task_ids or conflicted or released:
                self.database.append_audit(
                    "coordination.reaped",
                    "admin",
                    {
                        "blocked_interruption_task_ids": blocked_interruption_task_ids,
                        "conflicted_task_ids": conflicted,
                        "orphaned_task_ids": orphaned,
                        "released_resources": released,
                    },
                    connection=connection,
                )
        return {
            "blocked_interruption_task_ids": blocked_interruption_task_ids,
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
    def _clear_heartbeats(connection: sqlite3.Connection, task_id: str) -> None:
        """Drop a task's heartbeat rows whenever its claim ends, whatever ended it."""
        connection.execute("DELETE FROM agent_heartbeats WHERE task_id = ?", (task_id,))

    @staticmethod
    def _task_row(connection: sqlite3.Connection, task_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not row:
            raise ControlPlaneError(404, "task_not_found", "task not found")
        return row

    @staticmethod
    def _claim_count(value: Any) -> int:
        if type(value) is not int or value < 0:
            raise ControlPlaneError(
                409,
                "task_claim_budget_invalid",
                "stored successful-claim count is not a non-negative integer",
            )
        return value

    @staticmethod
    def _claim_limit(value: Any, field: str, *, allow_zero: bool = False) -> int | None:
        if value is None:
            return None
        minimum = 0 if allow_zero else 1
        if type(value) is not int or value < minimum:
            raise ControlPlaneError(
                409,
                "task_claim_budget_invalid",
                f"stored {field} is not a valid non-negative claim limit",
            )
        return value

    @staticmethod
    def _dispatch_limit(value: Any, field: str) -> int | None:
        if value is None:
            return None
        if type(value) is not int or value < 0:
            raise ControlPlaneError(
                409,
                "dispatch_budget_invalid",
                f"stored {field} is not a valid non-negative dispatch-attempt limit",
            )
        return value

    @staticmethod
    def _dispatch_attempt_count(connection: sqlite3.Connection, task_id: str) -> int:
        row = connection.execute(
            "SELECT COUNT(*) AS count FROM dispatch_attempt_reservations WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        return int(row["count"])

    @staticmethod
    def _dispatch_attempt_outstanding_count(connection: sqlite3.Connection, task_id: str) -> int:
        row = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM dispatch_attempt_reservations AS reservation
            LEFT JOIN dispatch_attempt_receipts AS receipt
              ON receipt.dispatch_attempt_id = reservation.id
            WHERE reservation.task_id = ? AND receipt.dispatch_attempt_id IS NULL
            """,
            (task_id,),
        ).fetchone()
        return int(row["count"])

    @staticmethod
    def _descendant_dispatch_attempt_counts(
        connection: sqlite3.Connection, ancestor_id: str
    ) -> tuple[int, int] | None:
        rows = connection.execute(
            """
            WITH RECURSIVE descendants(id, path, cycle) AS (
                SELECT id, ? || id || '|', id = ?
                FROM tasks WHERE parent_task_id = ?
                UNION ALL
                SELECT child.id, descendants.path || child.id || '|',
                       instr(descendants.path, '|' || child.id || '|') > 0
                FROM tasks AS child
                JOIN descendants ON child.parent_task_id = descendants.id
                WHERE descendants.cycle = 0
            )
            SELECT descendants.id, descendants.cycle,
                   COUNT(reservation.id) AS reservations,
                   COUNT(CASE WHEN receipt.dispatch_attempt_id IS NULL
                              THEN reservation.id END) AS outstanding
            FROM descendants
            LEFT JOIN dispatch_attempt_reservations AS reservation
              ON reservation.task_id = descendants.id
            LEFT JOIN dispatch_attempt_receipts AS receipt
              ON receipt.dispatch_attempt_id = reservation.id
            GROUP BY descendants.id, descendants.cycle
            """,
            (f"|{ancestor_id}|", ancestor_id, ancestor_id),
        ).fetchall()
        if any(row["cycle"] for row in rows):
            return None
        return (
            sum(int(row["reservations"]) for row in rows),
            sum(int(row["outstanding"]) for row in rows),
        )

    @staticmethod
    def _raise_dispatch_guard_error(error: sqlite3.IntegrityError) -> None:
        message = str(error)
        errors = {
            "task_dispatch_budget_exhausted": (
                "task_dispatch_budget_exhausted",
                "task has exhausted its cooperative dispatch-attempt limit",
            ),
            "descendant_dispatch_budget_exhausted": (
                "descendant_dispatch_budget_exhausted",
                "an ancestor task has exhausted its descendant dispatch-attempt limit",
            ),
            "task_dispatch_budget_invalid": (
                "task_dispatch_budget_invalid",
                "stored task dispatch-attempt budget is invalid",
            ),
            "descendant_dispatch_budget_invalid": (
                "descendant_dispatch_budget_invalid",
                "stored descendant dispatch-attempt budget is invalid",
            ),
            "task_dispatch_outstanding_budget_exhausted": (
                "task_dispatch_outstanding_budget_exhausted",
                "task has exhausted its outstanding dispatch-reservation limit",
            ),
            "descendant_dispatch_outstanding_budget_exhausted": (
                "descendant_dispatch_outstanding_budget_exhausted",
                "an ancestor task has exhausted its outstanding descendant "
                "dispatch-reservation limit",
            ),
            "task_dispatch_outstanding_budget_invalid": (
                "task_dispatch_outstanding_budget_invalid",
                "stored task outstanding dispatch-reservation budget is invalid",
            ),
            "descendant_dispatch_outstanding_budget_invalid": (
                "descendant_dispatch_outstanding_budget_invalid",
                "stored descendant outstanding dispatch-reservation budget is invalid",
            ),
            "dispatch_claim_fence_invalid": (
                "stale_claim_fencing_token",
                "dispatch attempt reservation has a stale or inactive task claim",
            ),
            "dispatch_resource_fence_invalid": (
                "stale_fencing_token",
                "dispatch attempt reservation has a stale or incomplete resource fence",
            ),
            "task_lineage_invalid": (
                "task_lineage_invalid",
                "task parent lineage is invalid",
            ),
        }
        for marker, (code, detail) in errors.items():
            if marker in message:
                raise ControlPlaneError(409, code, detail) from error
        raise error

    @classmethod
    def _task_ancestor_chain(
        cls, connection: sqlite3.Connection, task: sqlite3.Row
    ) -> list[sqlite3.Row]:
        """Return nearest-first parents; malformed, missing, or cyclic links fail closed."""
        ancestors: list[sqlite3.Row] = []
        visited = {task["id"]}
        parent_id = task["parent_task_id"]
        while parent_id is not None:
            if (
                not isinstance(parent_id, str)
                or not parent_id.strip()
                or parent_id != parent_id.strip()
                or parent_id in visited
            ):
                raise ControlPlaneError(
                    409, "task_lineage_invalid", "task parent lineage is invalid"
                )
            parent = connection.execute("SELECT * FROM tasks WHERE id = ?", (parent_id,)).fetchone()
            if not parent:
                raise ControlPlaneError(
                    409, "task_lineage_invalid", "task parent lineage is invalid"
                )
            cls._claim_count(parent["claim_fencing_token"])
            cls._claim_limit(
                parent["max_descendant_claims"], "max_descendant_claims", allow_zero=True
            )
            cls._dispatch_limit(
                parent["max_descendant_dispatch_attempts"],
                "max_descendant_dispatch_attempts",
            )
            cls._dispatch_limit(
                parent["max_descendant_unreceipted_dispatch_attempts"],
                "max_descendant_unreceipted_dispatch_attempts",
            )
            visited.add(parent_id)
            ancestors.append(parent)
            parent_id = parent["parent_task_id"]
        return ancestors

    @classmethod
    def _descendant_claim_count(
        cls, connection: sqlite3.Connection, ancestor_id: str
    ) -> int | None:
        """Count claim generations below one task; return None for corrupt descendants."""
        rows = connection.execute(
            """
            WITH RECURSIVE descendants(id, claim_fencing_token, path, cycle) AS (
                SELECT id, claim_fencing_token, ? || id || '|', id = ?
                FROM tasks WHERE parent_task_id = ?
                UNION ALL
                SELECT child.id, child.claim_fencing_token,
                       descendants.path || child.id || '|',
                       instr(descendants.path, '|' || child.id || '|') > 0
                FROM tasks AS child
                JOIN descendants ON child.parent_task_id = descendants.id
                WHERE descendants.cycle = 0
            )
            SELECT id, claim_fencing_token, cycle FROM descendants
            """,
            (f"|{ancestor_id}|", ancestor_id, ancestor_id),
        ).fetchall()
        consumed = 0
        for row in rows:
            if row["cycle"]:
                return None
            try:
                consumed += cls._claim_count(row["claim_fencing_token"])
            except ControlPlaneError:
                return None
        return consumed

    @staticmethod
    def _raise_claim_guard_error(error: sqlite3.IntegrityError) -> None:
        message = str(error)
        errors = {
            "task_interruption_requires_reopen": (
                "task_interruption_requires_reopen",
                "interrupted task requires an audited operator reopen before it can resume",
            ),
            "task_claim_budget_exhausted": (
                "task_claim_budget_exhausted",
                "task has exhausted its successful-claim limit",
            ),
            "descendant_claim_budget_exhausted": (
                "descendant_claim_budget_exhausted",
                "an ancestor task has exhausted its descendant successful-claim limit",
            ),
            "task_lineage_invalid": (
                "task_lineage_invalid",
                "task parent lineage is invalid",
            ),
            "task_claim_budget_invalid": (
                "task_claim_budget_invalid",
                "stored task claim budget is invalid",
            ),
            "descendant_claim_budget_invalid": (
                "descendant_claim_budget_invalid",
                "stored descendant claim budget is invalid",
            ),
            "task_claim_fencing_invalid": (
                "task_claim_fencing_invalid",
                "stored claim fencing generation is invalid",
            ),
        }
        for marker, (code, detail) in errors.items():
            if marker in message:
                raise ControlPlaneError(409, code, detail) from error
        raise error

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

    def _task_view(
        self,
        row: sqlite3.Row,
        *,
        include_reported_usage: bool = True,
        include_interruption_report: bool = True,
    ) -> dict[str, Any]:
        with self.database.connect() as connection:
            connection.execute("BEGIN")
            row = self._task_row(connection, row["id"])
            dependencies = connection.execute(
                """
                SELECT depends_on_task_id FROM task_dependencies
                WHERE task_id = ? ORDER BY depends_on_task_id
                """,
                (row["id"],),
            ).fetchall()
            latest_submission = connection.execute(
                """
                SELECT * FROM submissions
                WHERE task_id = ? ORDER BY created_at DESC, id DESC LIMIT 1
                """,
                (row["id"],),
            ).fetchone()
            latest_review = connection.execute(
                """
                SELECT review.* FROM reviews AS review
                JOIN submissions AS submission ON submission.id = review.submission_id
                WHERE submission.task_id = ?
                ORDER BY review.created_at DESC, review.id DESC LIMIT 1
                """,
                (row["id"],),
            ).fetchone()
            latest_interruption = (
                connection.execute(
                    """SELECT * FROM budget_interruption_reports
                       WHERE task_id = ? ORDER BY received_at DESC, id DESC LIMIT 1""",
                    (row["id"],),
                ).fetchone()
                if include_interruption_report
                else None
            )
            try:
                self._task_ancestor_chain(connection, row)
                ancestor_lineage_integrity = "valid"
            except ControlPlaneError:
                ancestor_lineage_integrity = "invalid"
            descendant_claims = self._descendant_claim_count(connection, row["id"])
            descendant_dispatch_counts = self._descendant_dispatch_attempt_counts(
                connection, row["id"]
            )
            descendant_dispatches = (
                descendant_dispatch_counts[0] if descendant_dispatch_counts is not None else None
            )
            dispatches_used = self._dispatch_attempt_count(connection, row["id"])
            dispatches_outstanding = self._dispatch_attempt_outstanding_count(connection, row["id"])
            descendant_dispatches_outstanding = (
                descendant_dispatch_counts[1] if descendant_dispatch_counts is not None else None
            )
            try:
                claims_used: int | None = self._claim_count(row["claim_fencing_token"])
            except ControlPlaneError:
                claims_used = None
            max_claims_valid = row["max_claims"] is None or (
                type(row["max_claims"]) is int and row["max_claims"] > 0
            )
            max_claims = row["max_claims"] if max_claims_valid else None
            max_descendant_claims_valid = row["max_descendant_claims"] is None or (
                type(row["max_descendant_claims"]) is int and row["max_descendant_claims"] >= 0
            )
            max_descendant_claims = (
                row["max_descendant_claims"] if max_descendant_claims_valid else None
            )
            max_dispatch_attempts_valid = row["max_dispatch_attempts"] is None or (
                type(row["max_dispatch_attempts"]) is int and row["max_dispatch_attempts"] >= 0
            )
            max_dispatch_attempts = (
                row["max_dispatch_attempts"] if max_dispatch_attempts_valid else None
            )
            max_descendant_dispatch_attempts_valid = row[
                "max_descendant_dispatch_attempts"
            ] is None or (
                type(row["max_descendant_dispatch_attempts"]) is int
                and row["max_descendant_dispatch_attempts"] >= 0
            )
            max_descendant_dispatch_attempts = (
                row["max_descendant_dispatch_attempts"]
                if max_descendant_dispatch_attempts_valid
                else None
            )
            max_unreceipted_dispatch_attempts_valid = row[
                "max_unreceipted_dispatch_attempts"
            ] is None or (
                type(row["max_unreceipted_dispatch_attempts"]) is int
                and row["max_unreceipted_dispatch_attempts"] >= 0
            )
            max_unreceipted_dispatch_attempts = (
                row["max_unreceipted_dispatch_attempts"]
                if max_unreceipted_dispatch_attempts_valid
                else None
            )
            max_descendant_unreceipted_dispatch_attempts_valid = row[
                "max_descendant_unreceipted_dispatch_attempts"
            ] is None or (
                type(row["max_descendant_unreceipted_dispatch_attempts"]) is int
                and row["max_descendant_unreceipted_dispatch_attempts"] >= 0
            )
            max_descendant_unreceipted_dispatch_attempts = (
                row["max_descendant_unreceipted_dispatch_attempts"]
                if max_descendant_unreceipted_dispatch_attempts_valid
                else None
            )
            observed_at = utc_now()
            task_reported_usage = (
                self._reported_provider_usage_view(connection, row["id"], "task", dispatches_used)
                if include_reported_usage
                else None
            )
            descendant_reported_usage = (
                self._reported_provider_usage_view(
                    connection,
                    row["id"],
                    "descendant_tree",
                    descendant_dispatches,
                )
                if include_reported_usage
                else None
            )
            return {
                "id": row["id"],
                "title": row["title"],
                "description": row["description"],
                "acceptance_criteria": json.loads(row["acceptance_criteria_json"]),
                "resources": json.loads(row["resources_json"]),
                # #1764: folded above is the lease key; declared is the operator's capitalisation.
                "declared_resources": declared_resources(row),
                "dependencies": [dependency["depends_on_task_id"] for dependency in dependencies],
                "priority": row["priority"],
                "status": row["status"],
                "owner_agent_id": row["owner_agent_id"],
                "claim_expires_at": row["claim_expires_at"],
                "claim_fencing_token": row["claim_fencing_token"],
                "parent_task_id": (
                    row["parent_task_id"] if isinstance(row["parent_task_id"], str) else None
                ),
                "ancestor_lineage_integrity": ancestor_lineage_integrity,
                "max_claims": max_claims,
                "max_descendant_claims": max_descendant_claims,
                "claim_budget": self._claim_budget_view(
                    "task", max_claims, claims_used, observed_at, invalid=not max_claims_valid
                ),
                "max_dispatch_attempts": max_dispatch_attempts,
                "max_descendant_dispatch_attempts": max_descendant_dispatch_attempts,
                "max_unreceipted_dispatch_attempts": max_unreceipted_dispatch_attempts,
                "max_descendant_unreceipted_dispatch_attempts": (
                    max_descendant_unreceipted_dispatch_attempts
                ),
                "dispatch_attempt_budget": self._dispatch_attempt_budget_view(
                    "task",
                    max_dispatch_attempts,
                    dispatches_used,
                    observed_at,
                    reported_provider_usage=task_reported_usage,
                    invalid=not max_dispatch_attempts_valid,
                ),
                "descendant_dispatch_attempt_budget": self._dispatch_attempt_budget_view(
                    "descendant_tree",
                    max_descendant_dispatch_attempts,
                    descendant_dispatches,
                    observed_at,
                    reported_provider_usage=descendant_reported_usage,
                    invalid=not max_descendant_dispatch_attempts_valid,
                ),
                "outstanding_dispatch_budget": self._outstanding_dispatch_budget_view(
                    "task",
                    max_unreceipted_dispatch_attempts,
                    dispatches_outstanding,
                    dispatches_used - dispatches_outstanding,
                    observed_at,
                    invalid=not max_unreceipted_dispatch_attempts_valid,
                ),
                "descendant_outstanding_dispatch_budget": self._outstanding_dispatch_budget_view(
                    "descendant_tree",
                    max_descendant_unreceipted_dispatch_attempts,
                    descendant_dispatches_outstanding,
                    (
                        descendant_dispatches - descendant_dispatches_outstanding
                        if descendant_dispatches is not None
                        and descendant_dispatches_outstanding is not None
                        else None
                    ),
                    observed_at,
                    invalid=(
                        not max_descendant_unreceipted_dispatch_attempts_valid
                        or descendant_dispatches is None
                        or descendant_dispatches_outstanding is None
                    ),
                ),
                "descendant_claim_budget": self._claim_budget_view(
                    "descendant_tree",
                    max_descendant_claims,
                    descendant_claims,
                    observed_at,
                    invalid=not max_descendant_claims_valid,
                ),
                "version": row["version"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "latest_submission": (
                    self._submission_view(latest_submission) if latest_submission else None
                ),
                "latest_review": self._review_view(latest_review) if latest_review else None,
                "latest_interruption_report": (
                    self._budget_interruption_report_view(connection, latest_interruption)
                    if latest_interruption
                    else None
                ),
            }

    @staticmethod
    def _budget_interruption_report_view(
        connection: sqlite3.Connection, row: sqlite3.Row
    ) -> dict[str, Any]:
        checkpoint_raw = row["checkpoint_json"]
        try:
            checkpoint = json.loads(checkpoint_raw) if isinstance(checkpoint_raw, str) else None
            if not isinstance(checkpoint, dict):
                checkpoint = {}
                checkpoint_integrity = "invalid"
            else:
                checkpoint_integrity = "valid"
        except (TypeError, ValueError):
            checkpoint = {}
            checkpoint_integrity = "invalid"
        expected_digest = (
            hashlib.sha256(checkpoint_raw.encode("utf-8")).hexdigest()
            if isinstance(checkpoint_raw, str)
            else None
        )
        if expected_digest is None or expected_digest != row["checkpoint_sha256"]:
            checkpoint = {}
            checkpoint_integrity = "invalid"
        try:
            resource_fencing_tokens = json.loads(row["resource_fencing_tokens_json"])
            if not isinstance(resource_fencing_tokens, dict) or any(
                not isinstance(key, str) or type(value) is not int or value < 1
                for key, value in resource_fencing_tokens.items()
            ):
                resource_fencing_tokens = {}
                resource_fencing_tokens_integrity = "invalid"
            else:
                resource_fencing_tokens_integrity = "valid"
        except (TypeError, ValueError):
            resource_fencing_tokens = {}
            resource_fencing_tokens_integrity = "invalid"
        try:
            dispatch_attempt_ids = json.loads(row["dispatch_attempt_ids_json"])
            if not isinstance(dispatch_attempt_ids, list) or any(
                not isinstance(item, str) for item in dispatch_attempt_ids
            ):
                dispatch_attempt_ids = []
                dispatch_attempts_integrity = "invalid"
            else:
                dispatch_attempts_integrity = "valid"
        except (TypeError, ValueError):
            dispatch_attempt_ids = []
            dispatch_attempts_integrity = "invalid"
        dispatch_attempts = []
        for dispatch_attempt_id in dispatch_attempt_ids:
            reservation = connection.execute(
                """SELECT * FROM dispatch_attempt_reservations
                   WHERE id = ? AND task_id = ?""",
                (dispatch_attempt_id, row["task_id"]),
            ).fetchone()
            if reservation is None:
                dispatch_attempts_integrity = "invalid"
                continue
            attempt_view = CoordinationService._dispatch_attempt_view(connection, reservation)
            if (
                reservation["agent_id"] != row["agent_id"]
                or reservation["claim_fencing_token"] != row["claim_fencing_token"]
                or not CoordinationService._resource_fencing_tokens_match(
                    reservation["resource_fencing_tokens_json"], resource_fencing_tokens
                )
                or attempt_view["status"] != "reported"
            ):
                dispatch_attempts_integrity = "invalid"
            dispatch_attempts.append(attempt_view)
        return BudgetInterruptionReportView(
            id=row["id"],
            task_id=row["task_id"],
            agent_id=row["agent_id"],
            claim_fencing_token=row["claim_fencing_token"],
            resource_fencing_tokens=resource_fencing_tokens,
            interruption_status="interrupted",
            status=row["status"],
            source=row["source"],
            reason=row["reason"],
            summary=row["summary"],
            checkpoint=checkpoint,
            checkpoint_sha256=row["checkpoint_sha256"],
            checkpoint_integrity=checkpoint_integrity,
            resource_fencing_tokens_integrity=resource_fencing_tokens_integrity,
            dispatch_attempt_ids=dispatch_attempt_ids,
            dispatch_attempts=dispatch_attempts,
            dispatch_attempts_integrity=dispatch_attempts_integrity,
            received_at=row["received_at"],
            promotable=False,
        ).model_dump()

    @staticmethod
    def _resource_fencing_tokens_match(stored_json: str, expected: dict[str, int]) -> bool:
        try:
            stored = json.loads(stored_json)
        except (TypeError, ValueError):
            return False
        return (
            isinstance(stored, dict)
            and all(
                isinstance(resource, str) and type(token) is int and token >= 1
                for resource, token in stored.items()
            )
            and stored == expected
        )

    @staticmethod
    def _claim_budget_view(
        scope: str,
        limit: int | None,
        consumed: int | None,
        observed_at: str,
        *,
        invalid: bool = False,
    ) -> dict[str, Any]:
        if invalid or consumed is None or (limit is not None and type(limit) is not int):
            status = "invalid"
            safe_limit = None if type(limit) is not int else limit
            safe_consumed = None
            remaining = None
        elif limit is None:
            status = "unlimited"
            safe_limit = None
            safe_consumed = consumed
            remaining = None
        else:
            safe_limit = limit
            safe_consumed = consumed
            remaining = max(0, limit - consumed)
            status = "exhausted" if remaining == 0 else "available"
        return ClaimBudgetView(
            scope=scope,
            unit="successful_claim_reservations",
            limit=safe_limit,
            consumed=safe_consumed,
            remaining=remaining,
            status=status,
            source="tasks.claim_fencing_token",
            enforcement="BEGIN IMMEDIATE task claim and SQLite trigger",
            observed_at=observed_at,
        ).model_dump()

    @staticmethod
    def _reported_provider_usage_view(
        connection: sqlite3.Connection,
        task_id: str,
        scope: str,
        reservation_count: int | None,
    ) -> dict[str, Any]:
        if reservation_count is None:
            return ReportedProviderUsageView(
                scope=scope,
                status="invalid",
                source="client_reported",
                capture_scope="ACP dispatch receipts only",
                unit="tokens",
                reservation_count=None,
                sampled_reservation_count=None,
                reported_response_count=None,
                missing_report_count=None,
                invalid_report_count=None,
                receipt_without_report_count=None,
                reservation_without_receipt_count=None,
                latest_receipt_received_at_in_sample=None,
                truncated=False,
                sample_limit=_PROVIDER_USAGE_SUMMARY_MAX_RESERVATIONS,
                freshness="unknown",
                enforcement="report_only",
                reasons=["descendant_lineage_invalid"],
                groups=[],
            ).model_dump()

        if scope == "task":
            rows = connection.execute(
                """
                SELECT receipt.provider_usage_json, receipt.received_at
                FROM dispatch_attempt_reservations AS reservation
                LEFT JOIN dispatch_attempt_receipts AS receipt
                  ON receipt.dispatch_attempt_id = reservation.id
                WHERE reservation.task_id = ?
                ORDER BY reservation.created_at DESC, reservation.id DESC
                LIMIT ?
                """,
                (task_id, _PROVIDER_USAGE_SUMMARY_MAX_RESERVATIONS),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                WITH RECURSIVE descendants(id) AS (
                    SELECT id FROM tasks WHERE parent_task_id = ?
                    UNION
                    SELECT child.id FROM tasks AS child
                    JOIN descendants ON child.parent_task_id = descendants.id
                )
                SELECT receipt.provider_usage_json, receipt.received_at
                FROM descendants
                JOIN dispatch_attempt_reservations AS reservation
                  ON reservation.task_id = descendants.id
                LEFT JOIN dispatch_attempt_receipts AS receipt
                  ON receipt.dispatch_attempt_id = reservation.id
                ORDER BY reservation.created_at DESC, reservation.id DESC
                LIMIT ?
                """,
                (task_id, _PROVIDER_USAGE_SUMMARY_MAX_RESERVATIONS),
            ).fetchall()

        reported_response_count = 0
        missing_report_count = 0
        invalid_report_count = 0
        receipt_without_report_count = 0
        reservation_without_receipt_count = 0
        latest_receipt_received_at = max(
            (row["received_at"] for row in rows if row["received_at"] is not None),
            default=None,
        )
        groups: dict[tuple[str, str, str], dict[str, Any]] = {}
        invalid_stored_report = False

        for row in rows:
            stored_report = row["provider_usage_json"]
            if stored_report is None:
                reservation_without_receipt_count += 1
                continue
            try:
                report_payload = json.loads(stored_report or "{}")
                if report_payload == {}:
                    receipt_without_report_count += 1
                    continue
                report = ProviderUsageReport.model_validate(report_payload)
                client_observed_at = datetime.fromisoformat(
                    report.observed_at.replace("Z", "+00:00")
                ).astimezone(UTC)
            except (OverflowError, TypeError, ValueError):
                invalid_report_count += 1
                invalid_stored_report = True
                continue

            if report.status == "missing":
                missing_report_count += 1
                continue
            if report.status == "invalid":
                invalid_report_count += 1
                continue

            assert report.model is not None
            reported_response_count += 1
            key = (report.provider, report.adapter, report.model)
            group = groups.setdefault(
                key,
                {
                    "response_count": 0,
                    "measurements": {},
                    "measurement_response_counts": {},
                    "_latest_client_observed_at": None,
                },
            )
            group["response_count"] += 1
            if (
                group["_latest_client_observed_at"] is None
                or client_observed_at > group["_latest_client_observed_at"]
            ):
                group["_latest_client_observed_at"] = client_observed_at
            for name, value in report.measurements.items():
                group["measurements"][name] = group["measurements"].get(name, 0) + value
                group["measurement_response_counts"][name] = (
                    group["measurement_response_counts"].get(name, 0) + 1
                )

        truncated = reservation_count > len(rows)
        reasons: list[str] = []
        if invalid_stored_report:
            reasons.append("stored_usage_report_invalid")
        if truncated:
            reasons.append("summary_truncated")
        has_gaps = any(
            (
                missing_report_count,
                invalid_report_count,
                receipt_without_report_count,
                reservation_without_receipt_count,
                int(truncated),
            )
        )
        if reservation_count == 0:
            status = "none"
        elif has_gaps:
            status = "partial"
        elif reported_response_count:
            status = "observed"
        else:
            status = "partial"

        group_views = []
        for provider, adapter, model in sorted(groups):
            group = groups[(provider, adapter, model)]
            latest_client_observed_at = group["_latest_client_observed_at"]
            assert isinstance(latest_client_observed_at, datetime)
            group_views.append(
                {
                    "provider": provider,
                    "adapter": adapter,
                    "model": model,
                    "response_count": group["response_count"],
                    "latest_client_observed_at": latest_client_observed_at.isoformat().replace(
                        "+00:00", "Z"
                    ),
                    "measurements": group["measurements"],
                    "measurement_response_counts": group["measurement_response_counts"],
                }
            )
        return ReportedProviderUsageView(
            scope=scope,
            status=status,
            source="client_reported",
            capture_scope="ACP dispatch receipts only",
            unit="tokens",
            reservation_count=reservation_count,
            sampled_reservation_count=len(rows),
            reported_response_count=reported_response_count,
            missing_report_count=missing_report_count,
            invalid_report_count=invalid_report_count,
            receipt_without_report_count=receipt_without_report_count,
            reservation_without_receipt_count=reservation_without_receipt_count,
            latest_receipt_received_at_in_sample=latest_receipt_received_at,
            truncated=truncated,
            sample_limit=_PROVIDER_USAGE_SUMMARY_MAX_RESERVATIONS,
            freshness="unknown",
            enforcement="report_only",
            reasons=reasons,
            groups=group_views,
        ).model_dump()

    @staticmethod
    def _dispatch_attempt_budget_view(
        scope: str,
        limit: int | None,
        consumed: int | None,
        observed_at: str,
        *,
        reported_provider_usage: dict[str, Any] | None,
        invalid: bool = False,
    ) -> dict[str, Any]:
        if (
            invalid
            or consumed is None
            or (limit is not None and (type(limit) is not int or limit < 0))
        ):
            status = "invalid"
            safe_limit = None
            safe_consumed = None
            remaining = None
        elif limit is None:
            status = "unlimited"
            safe_limit = None
            safe_consumed = consumed
            remaining = None
        else:
            safe_limit = limit
            safe_consumed = consumed
            remaining = max(0, limit - consumed)
            status = "exhausted" if remaining == 0 else "available"
        return DispatchAttemptBudgetView(
            scope=scope,
            unit="dispatch_attempt_reservations",
            limit=safe_limit,
            consumed=safe_consumed,
            remaining=remaining,
            reserved=0,
            released=0,
            status=status,
            source="dispatch_attempt_reservations",
            enforcement="BEGIN IMMEDIATE reservation and SQLite trigger",
            observed_at=observed_at,
            provider_usage=ProviderUsageEvidence(
                status="unsupported",
                unit=None,
                source=None,
                scope="provider calls and provider-internal fan-out",
                observed_at=None,
                freshness="unknown",
                enforcement_point=None,
                reason=(
                    "no authenticated provider meter or request gate are wired to this supervisor"
                ),
            ),
            reported_provider_usage=reported_provider_usage,
        ).model_dump()

    @staticmethod
    def _outstanding_dispatch_budget_view(
        scope: str,
        limit: int | None,
        reserved: int | None,
        released: int | None,
        observed_at: str,
        *,
        invalid: bool = False,
    ) -> dict[str, Any]:
        if (
            invalid
            or reserved is None
            or released is None
            or (limit is not None and (type(limit) is not int or limit < 0))
        ):
            status = "invalid"
            safe_limit = None if type(limit) is not int or limit < 0 else limit
            safe_reserved = None
            safe_released = None
            remaining = None
            freshness = "unknown"
        elif limit is None:
            status = "unlimited"
            safe_limit = None
            safe_reserved = reserved
            safe_released = released
            remaining = None
            freshness = "current_snapshot"
        else:
            safe_limit = limit
            safe_reserved = reserved
            safe_released = released
            remaining = max(0, limit - reserved)
            status = "exhausted" if remaining == 0 else "available"
            freshness = "current_snapshot"
        return OutstandingDispatchBudgetView(
            scope=scope,
            unit="unreceipted_dispatch_attempt_reservations",
            limit=safe_limit,
            reserved=safe_reserved,
            released=safe_released,
            remaining=remaining,
            status=status,
            source="dispatch_attempt_reservations_and_receipts",
            enforcement="BEGIN IMMEDIATE reservation and SQLite trigger",
            observed_at=observed_at,
            freshness=freshness,
            provider_usage=ProviderUsageEvidence(
                status="unsupported",
                unit=None,
                source=None,
                scope="provider calls and provider-internal fan-out",
                observed_at=None,
                freshness="unknown",
                enforcement_point=None,
                reason=(
                    "no authenticated provider meter or request gate are wired to this supervisor"
                ),
            ),
        ).model_dump()

    @staticmethod
    def _dispatch_attempt_receipt_view(row: sqlite3.Row) -> dict[str, Any]:
        raw_provider_usage_report = json.loads(row["provider_usage_json"] or "{}")
        return DispatchAttemptReceiptView(
            dispatch_attempt_id=row["dispatch_attempt_id"],
            source=row["source"],
            http_status_code=row["http_status_code"],
            retry_after_seconds=row["retry_after_seconds"],
            received_at=row["received_at"],
            provider_usage=ProviderUsageEvidence(
                status="unsupported",
                unit=None,
                source=None,
                scope="provider calls and provider-internal fan-out",
                observed_at=None,
                freshness="unknown",
                enforcement_point=None,
                reason=(
                    "no authenticated provider meter or request gate are wired to this supervisor"
                ),
            ),
            provider_usage_report=(
                ProviderUsageReport.model_validate(raw_provider_usage_report)
                if raw_provider_usage_report
                else None
            ),
        ).model_dump()

    @classmethod
    def _dispatch_attempt_view(
        cls, connection: sqlite3.Connection, row: sqlite3.Row
    ) -> dict[str, Any]:
        receipt = connection.execute(
            "SELECT * FROM dispatch_attempt_receipts WHERE dispatch_attempt_id = ?",
            (row["id"],),
        ).fetchone()
        return {
            "id": row["id"],
            "task_id": row["task_id"],
            "agent_id": row["agent_id"],
            "claim_fencing_token": row["claim_fencing_token"],
            "resource_fencing_tokens": json.loads(row["resource_fencing_tokens_json"]),
            "idempotency_key": row["idempotency_key"],
            "status": "reported" if receipt else "reserved",
            "created_at": row["created_at"],
            "receipt": cls._dispatch_attempt_receipt_view(receipt) if receipt else None,
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
