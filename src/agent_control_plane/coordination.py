from __future__ import annotations

import base64
import binascii
import hashlib
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
    WorkspaceFileWriteRequest,
)
from .database import Database, canonical_json, utc_now
from .policy import scope_allows
from .service import ControlPlaneError, ControlPlaneService
from .workspace_files import (
    MAX_WORKSPACE_FILE_BYTES,
    WorkspaceFileError,
    WorkspaceFileStore,
    canonical_relative_path,
)

QC_RESERVATION_SECONDS = 3600
WORKSPACE_FILE_RESOURCE_PREFIX = "workspace-file:"


class CoordinationService:
    def __init__(
        self,
        database: Database,
        control_plane: ControlPlaneService,
        workspace_root: str | None = None,
    ):
        self.database = database
        self.control_plane = control_plane
        self.workspace_files = (
            WorkspaceFileStore(workspace_root) if workspace_root else None
        )

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
            rows = self.database.all(
                "SELECT * FROM tasks ORDER BY priority DESC, created_at ASC"
            )
        return [self._task_view(row) for row in rows]

    def _workspace_file_alias_key(self, resource: str) -> str | None:
        if not resource.startswith(WORKSPACE_FILE_RESOURCE_PREFIX):
            return None
        if not self.workspace_files:
            raise ControlPlaneError(
                503,
                "workspace_root_unconfigured",
                "workspace-file resources require ACP_WORKSPACE_ROOT",
            )
        relative_path = resource[len(WORKSPACE_FILE_RESOURCE_PREFIX) :]
        try:
            return self.workspace_files.lease_alias_key(relative_path)
        except WorkspaceFileError as error:
            raise ControlPlaneError(
                error.status_code, error.code, error.message
            ) from error

    def _assert_no_workspace_file_alias_conflicts(
        self,
        connection: sqlite3.Connection,
        resources: list[str],
        task_id: str,
        now: int,
    ) -> None:
        requested_aliases: dict[str, str] = {}
        for resource in resources:
            alias_key = self._workspace_file_alias_key(resource)
            if alias_key is None:
                continue
            prior_resource = requested_aliases.get(alias_key)
            if prior_resource is not None and prior_resource != resource:
                raise ControlPlaneError(
                    409,
                    "resource_alias_conflict",
                    f"task declares workspace resources {prior_resource} and {resource} for the same filesystem path",
                )
            requested_aliases[alias_key] = resource

        if not requested_aliases:
            return

        requested_resources = set(resources)
        active_leases = connection.execute(
            """
            SELECT resource, task_id FROM resource_leases
            WHERE task_id IS NOT NULL AND expires_at > ?
              AND substr(resource, 1, 15) = 'workspace-file:'
            """,
            (now,),
        ).fetchall()
        for lease in active_leases:
            if lease["task_id"] == task_id and lease["resource"] in requested_resources:
                continue
            alias_key = self._workspace_file_alias_key(lease["resource"])
            if alias_key in requested_aliases:
                requested_resource = requested_aliases[alias_key]
                raise ControlPlaneError(
                    409,
                    "resource_busy",
                    f"resource {requested_resource} aliases active leased workspace file {lease['resource']}",
                )

    def write_workspace_file(
        self, task_id: str, token: str, request: WorkspaceFileWriteRequest
    ) -> dict[str, Any]:
        claims, _mandate, agent = self._agent_for_action(
            token, "coordination.write_file", f"task:{task_id}", {"worker"}
        )
        if not self.workspace_files:
            raise ControlPlaneError(
                503,
                "workspace_root_unconfigured",
                "set ACP_WORKSPACE_ROOT before using workspace file writes",
            )
        try:
            relative_path = canonical_relative_path(request.path)
        except WorkspaceFileError as error:
            raise ControlPlaneError(
                error.status_code, error.code, error.message
            ) from error

        try:
            content = base64.b64decode(request.content_base64, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ControlPlaneError(
                422, "invalid_file_content", "content_base64 must be valid base64"
            ) from error
        if len(content) > MAX_WORKSPACE_FILE_BYTES:
            raise ControlPlaneError(
                413, "workspace_file_too_large", "workspace writes are limited to 1 MiB"
            )

        operation_id = str(request.operation_id)
        expected_sha256 = (
            request.expected_sha256.lower() if request.expected_sha256 else None
        )
        new_sha256 = hashlib.sha256(content).hexdigest()
        lease_resource = f"workspace-file:{relative_path}"
        conflict_message: str | None = None
        receipt: dict[str, Any] | None = None
        should_write = False

        try:
            with self.database.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                task = self._task_row(connection, task_id)
                prior = connection.execute(
                    "SELECT * FROM workspace_file_writes WHERE operation_id = ?",
                    (operation_id,),
                ).fetchone()

                if prior:
                    if prior["task_id"] != task_id or prior["agent_id"] != agent["id"]:
                        raise ControlPlaneError(
                            404,
                            "file_write_not_found",
                            "workspace file write not found",
                        )
                    if (
                        prior["relative_path"] != relative_path
                        or prior["expected_sha256"] != expected_sha256
                        or prior["new_sha256"] != new_sha256
                        or prior["content_bytes"] != len(content)
                    ):
                        raise ControlPlaneError(
                            409,
                            "idempotency_key_conflict",
                            "operation_id was already used for different file content",
                        )
                    if prior["status"] == "committed":
                        return self._workspace_file_write_view(prior)
                    if prior["status"] == "conflict":
                        conflict_message = "workspace file write previously conflicted; use a new operation_id"
                    else:
                        observed_sha256, _mode = self.workspace_files.current(
                            relative_path
                        )
                        if observed_sha256 == new_sha256:
                            self.workspace_files.sync_directory(relative_path)
                            updated_at = utc_now()
                            connection.execute(
                                """UPDATE workspace_file_writes
                                   SET status = 'committed', updated_at = ?
                                   WHERE operation_id = ?""",
                                (updated_at, operation_id),
                            )
                            self.database.append_audit_in_transaction(
                                connection,
                                "workspace_file_write.recovered",
                                claims["actor"],
                                self._workspace_file_audit_payload(
                                    prior, observed_sha256
                                ),
                            )
                            receipt = self._workspace_file_write_view(
                                connection.execute(
                                    "SELECT * FROM workspace_file_writes WHERE operation_id = ?",
                                    (operation_id,),
                                ).fetchone()
                            )
                        elif observed_sha256 != expected_sha256:
                            updated_at = utc_now()
                            connection.execute(
                                """UPDATE workspace_file_writes
                                   SET status = 'conflict', observed_sha256 = ?, updated_at = ?
                                   WHERE operation_id = ?""",
                                (observed_sha256, updated_at, operation_id),
                            )
                            self.database.append_audit_in_transaction(
                                connection,
                                "workspace_file_write.conflicted",
                                claims["actor"],
                                self._workspace_file_audit_payload(
                                    prior, observed_sha256
                                ),
                            )
                            conflict_message = self._stale_file_message(observed_sha256)
                        else:
                            self._assert_active_claim(
                                connection,
                                task,
                                agent["id"],
                                request.claim_fencing_token,
                                request.resource_fencing_tokens,
                                int(time.time()),
                            )
                            self._assert_workspace_file_resource(task, lease_resource)
                            should_write = True
                else:
                    self._assert_active_claim(
                        connection,
                        task,
                        agent["id"],
                        request.claim_fencing_token,
                        request.resource_fencing_tokens,
                        int(time.time()),
                    )
                    self._assert_workspace_file_resource(task, lease_resource)
                    observed_sha256, _mode = self.workspace_files.current(relative_path)
                    created_at = utc_now()
                    status = (
                        "prepared" if observed_sha256 == expected_sha256 else "conflict"
                    )
                    connection.execute(
                        """INSERT INTO workspace_file_writes
                           (operation_id, task_id, agent_id, relative_path,
                            expected_sha256, observed_sha256, new_sha256,
                            content_bytes, status, created_at, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            operation_id,
                            task_id,
                            agent["id"],
                            relative_path,
                            expected_sha256,
                            observed_sha256,
                            new_sha256,
                            len(content),
                            status,
                            created_at,
                            created_at,
                        ),
                    )
                    prior = connection.execute(
                        "SELECT * FROM workspace_file_writes WHERE operation_id = ?",
                        (operation_id,),
                    ).fetchone()
                    if status == "prepared":
                        self.database.append_audit_in_transaction(
                            connection,
                            "workspace_file_write.prepared",
                            claims["actor"],
                            self._workspace_file_audit_payload(prior, observed_sha256),
                        )
                        should_write = True
                    else:
                        self.database.append_audit_in_transaction(
                            connection,
                            "workspace_file_write.conflicted",
                            claims["actor"],
                            self._workspace_file_audit_payload(prior, observed_sha256),
                        )
                        conflict_message = self._stale_file_message(observed_sha256)
        except WorkspaceFileError as error:
            raise ControlPlaneError(
                error.status_code, error.code, error.message
            ) from error

        if receipt:
            return receipt
        if conflict_message:
            raise ControlPlaneError(409, "stale_file_version", conflict_message)
        if not should_write:
            raise ControlPlaneError(
                500,
                "file_write_state_invalid",
                "workspace file write did not reach a safe state",
            )

        conflict_message = None
        try:
            with self.database.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                prior = connection.execute(
                    "SELECT * FROM workspace_file_writes WHERE operation_id = ?",
                    (operation_id,),
                ).fetchone()
                if (
                    not prior
                    or prior["task_id"] != task_id
                    or prior["agent_id"] != agent["id"]
                ):
                    raise ControlPlaneError(
                        404, "file_write_not_found", "workspace file write not found"
                    )
                if prior["status"] == "committed":
                    return self._workspace_file_write_view(prior)
                if prior["status"] == "conflict":
                    raise ControlPlaneError(
                        409,
                        "stale_file_version",
                        "workspace file write previously conflicted; use a new operation_id",
                    )

                task = self._task_row(connection, task_id)
                observed_sha256, _mode = self.workspace_files.current(relative_path)
                if observed_sha256 == new_sha256:
                    self.workspace_files.sync_directory(relative_path)
                    updated_at = utc_now()
                    connection.execute(
                        """UPDATE workspace_file_writes
                           SET status = 'committed', updated_at = ?
                           WHERE operation_id = ?""",
                        (updated_at, operation_id),
                    )
                    self.database.append_audit_in_transaction(
                        connection,
                        "workspace_file_write.recovered",
                        claims["actor"],
                        self._workspace_file_audit_payload(prior, observed_sha256),
                    )
                elif observed_sha256 != expected_sha256:
                    updated_at = utc_now()
                    connection.execute(
                        """UPDATE workspace_file_writes
                           SET status = 'conflict', observed_sha256 = ?, updated_at = ?
                           WHERE operation_id = ?""",
                        (observed_sha256, updated_at, operation_id),
                    )
                    self.database.append_audit_in_transaction(
                        connection,
                        "workspace_file_write.conflicted",
                        claims["actor"],
                        self._workspace_file_audit_payload(prior, observed_sha256),
                    )
                    conflict_message = self._stale_file_message(observed_sha256)
                else:
                    self._assert_active_claim(
                        connection,
                        task,
                        agent["id"],
                        request.claim_fencing_token,
                        request.resource_fencing_tokens,
                        int(time.time()),
                    )
                    self._assert_workspace_file_resource(task, lease_resource)
                    try:
                        self.workspace_files.atomic_replace(
                            relative_path,
                            operation_id,
                            expected_sha256,
                            content,
                            new_sha256,
                        )
                    except WorkspaceFileError as error:
                        if error.code != "stale_file_version":
                            raise
                        observed_sha256, _mode = self.workspace_files.current(
                            relative_path
                        )
                        updated_at = utc_now()
                        connection.execute(
                            """UPDATE workspace_file_writes
                               SET status = 'conflict', observed_sha256 = ?, updated_at = ?
                               WHERE operation_id = ?""",
                            (observed_sha256, updated_at, operation_id),
                        )
                        self.database.append_audit_in_transaction(
                            connection,
                            "workspace_file_write.conflicted",
                            claims["actor"],
                            self._workspace_file_audit_payload(prior, observed_sha256),
                        )
                        conflict_message = self._stale_file_message(observed_sha256)
                    else:
                        updated_at = utc_now()
                        connection.execute(
                            """UPDATE workspace_file_writes
                               SET status = 'committed', updated_at = ?
                               WHERE operation_id = ?""",
                            (updated_at, operation_id),
                        )
                        self.database.append_audit_in_transaction(
                            connection,
                            "workspace_file_write.committed",
                            claims["actor"],
                            self._workspace_file_audit_payload(prior, observed_sha256),
                        )
                if not conflict_message:
                    receipt = self._workspace_file_write_view(
                        connection.execute(
                            "SELECT * FROM workspace_file_writes WHERE operation_id = ?",
                            (operation_id,),
                        ).fetchone()
                    )
        except WorkspaceFileError as error:
            raise ControlPlaneError(
                error.status_code, error.code, error.message
            ) from error

        if conflict_message:
            raise ControlPlaneError(409, "stale_file_version", conflict_message)
        if receipt:
            return receipt
        raise ControlPlaneError(
            500,
            "file_write_state_invalid",
            "workspace file write did not reach a safe state",
        )

    def workspace_file_write(
        self, task_id: str, operation_id: str, token: str
    ) -> dict[str, Any]:
        _claims, _mandate, agent = self._agent_for_action(
            token, "coordination.write_file", f"task:{task_id}", {"worker"}
        )
        row = self.database.one(
            "SELECT * FROM workspace_file_writes WHERE operation_id = ? AND task_id = ?",
            (operation_id, task_id),
        )
        if not row or row["agent_id"] != agent["id"]:
            raise ControlPlaneError(
                404, "file_write_not_found", "workspace file write not found"
            )
        return self._workspace_file_write_view(row)

    @staticmethod
    def _assert_workspace_file_resource(task: sqlite3.Row, lease_resource: str) -> None:
        if lease_resource not in json.loads(task["resources_json"]):
            raise ControlPlaneError(
                409,
                "file_resource_not_leased",
                f"task must declare the exact resource {lease_resource}",
            )

    @staticmethod
    def _stale_file_message(observed_sha256: str | None) -> str:
        return "workspace file version changed; current sha256 is " + (
            observed_sha256 or "missing"
        )

    @staticmethod
    def _workspace_file_write_view(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "operation_id": row["operation_id"],
            "task_id": row["task_id"],
            "agent_id": row["agent_id"],
            "path": row["relative_path"],
            "expected_sha256": row["expected_sha256"],
            "observed_sha256": row["observed_sha256"],
            "new_sha256": row["new_sha256"],
            "content_bytes": row["content_bytes"],
            "status": row["status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _workspace_file_audit_payload(
        row: sqlite3.Row, observed_sha256: str | None
    ) -> dict[str, Any]:
        return {
            "agent_id": row["agent_id"],
            "expected_sha256": row["expected_sha256"],
            "new_sha256": row["new_sha256"],
            "observed_sha256": observed_sha256,
            "operation_id": row["operation_id"],
            "path": row["relative_path"],
            "task_id": row["task_id"],
        }

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
            self._assert_no_workspace_file_alias_conflicts(
                connection, resources, task_id, now
            )
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

    def heartbeat(
        self, task_id: str, token: str, request: HeartbeatRequest
    ) -> dict[str, Any]:
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

    def submit(
        self, task_id: str, token: str, request: SubmissionCreate
    ) -> dict[str, Any]:
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
                     claim_fencing_token, base_revision, artifact_uri,
                     artifact_hash, summary, evidence_json, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_qc', ?)
                """,
                (
                    submission_id,
                    task_id,
                    agent["id"],
                    request.task_version,
                    request.claim_fencing_token,
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
        )
        return self.submission(submission_id)

    def review(
        self, submission_id: str, token: str, request: QCReviewCreate
    ) -> dict[str, Any]:
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
                SELECT submission.id, submission.status, review.verdict
                FROM submissions AS submission
                LEFT JOIN reviews AS review ON review.submission_id = submission.id
                WHERE submission.task_id = ?
                ORDER BY submission.created_at DESC, review.created_at DESC
                LIMIT 1
                """,
                (task_id,),
            ).fetchone()
            if (
                not latest
                or latest["status"] != "approved"
                or latest["verdict"] != "pass"
            ):
                raise ControlPlaneError(
                    409,
                    "qc_evidence_missing",
                    "latest submission lacks a passing independent review",
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

        self.database.append_audit(
            "task.reopened",
            "admin",
            {
                "previous_status": previous_status,
                "reason": reason,
                "task_id": task_id,
            },
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
    def _clear_heartbeats(connection: sqlite3.Connection, task_id: str) -> None:
        """Drop a task's heartbeat rows whenever its claim ends, whatever ended it."""
        connection.execute("DELETE FROM agent_heartbeats WHERE task_id = ?", (task_id,))

    @staticmethod
    def _task_row(connection: sqlite3.Connection, task_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM tasks WHERE id = ?", (task_id,)
        ).fetchone()
        if not row:
            raise ControlPlaneError(404, "task_not_found", "task not found")
        return row

    def _submission_row(self, submission_id: str) -> sqlite3.Row:
        row = self.database.one(
            "SELECT * FROM submissions WHERE id = ?", (submission_id,)
        )
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
        resource_list = json.loads(task["resources_json"])
        resources = set(resource_list)
        if set(resource_fencing_tokens) != resources:
            raise ControlPlaneError(
                409,
                "incomplete_resource_fencing_tokens",
                "submission must carry every leased resource token",
            )
        self._assert_no_workspace_file_alias_conflicts(
            connection, resource_list, task["id"], now
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
                raise ControlPlaneError(
                    409, "stale_fencing_token", f"stale lease for {resource}"
                )

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
            "dependencies": [
                dependency["depends_on_task_id"] for dependency in dependencies
            ],
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
            "latest_review": self._review_view(latest_review)
            if latest_review
            else None,
        }

    @staticmethod
    def _submission_view(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "task_id": row["task_id"],
            "worker_agent_id": row["worker_agent_id"],
            "task_version": row["task_version"],
            "claim_fencing_token": row["claim_fencing_token"],
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
