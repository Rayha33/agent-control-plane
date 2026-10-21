from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .schema_version import (
    META_TABLE,
    Migration,
    apply_migration_ledger,
    assert_schema_not_newer,
    stamp_schema_version,
    stored_schema_version,
)

GENESIS_HASH = "0" * 64


SERVICE_SCHEMA_VERSION = 12
"""Schema this binary understands for the FastAPI service database.

Independent of the supervisor's SCHEMA_VERSION on purpose: these are two files with
two lifecycles — the service database is created by `create_app`, the control database
by `acp init` — and coupling their numbers would force a version bump on one whenever
the other changed.
"""

_SERVICE_DB_BUSY_TIMEOUT_MS = 10_000
_SERVICE_DB_WAL_RETRY_SECONDS = 10.0


def _enable_service_wal_mode(connection: sqlite3.Connection) -> None:
    """Set WAL mode despite concurrent initializers racing the first migration."""

    deadline = time.monotonic() + _SERVICE_DB_WAL_RETRY_SECONDS
    backoff = 0.005
    # PRAGMA journal_mode can fail immediately while another initializer is
    # changing the journal mode or holding the schema-migration write lock. Use
    # one bounded retry loop here, then restore the normal write busy timeout.
    connection.execute("PRAGMA busy_timeout = 0")
    try:
        while True:
            try:
                current_mode = connection.execute("PRAGMA journal_mode").fetchone()
                if current_mode and str(current_mode[0]).casefold() == "wal":
                    return
                selected_mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
                if not selected_mode or str(selected_mode[0]).casefold() != "wal":
                    raise sqlite3.OperationalError(
                        "service database did not accept WAL journal mode"
                    )
                return
            except sqlite3.OperationalError as error:
                code = getattr(error, "sqlite_errorcode", None)
                sqlite_contention = isinstance(code, int) and (code & 0xFF) in {
                    sqlite3.SQLITE_BUSY,
                    sqlite3.SQLITE_LOCKED,
                }
                message = str(error).casefold()
                if not sqlite_contention and "locked" not in message and "busy" not in message:
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise
                time.sleep(min(backoff, remaining))
                backoff = min(backoff * 2, 0.1)
    finally:
        connection.execute(f"PRAGMA busy_timeout = {_SERVICE_DB_BUSY_TIMEOUT_MS}")


def _add_mandate_descendant_cap(connection: sqlite3.Connection) -> None:
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(mandates)")}
    if "max_descendant_mandates" not in columns:
        connection.execute("ALTER TABLE mandates ADD COLUMN max_descendant_mandates INTEGER")


def _install_mandate_fanout_guard(connection: sqlite3.Connection) -> None:
    """Enforce issued-mandate caps below old service workers too.

    A worker that was already running when the service database was migrated has
    already passed its startup schema-version check. Its old INSERT statement does
    not know about the cap, so the persistent database trigger is the compatibility
    boundary during a rolling upgrade.
    """
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS mandate_fanout_guard
        BEFORE INSERT ON mandates
        WHEN NEW.parent_mandate_id IS NOT NULL
        BEGIN
            SELECT CASE WHEN EXISTS (
                WITH RECURSIVE
                ancestors(id, parent_id, cap) AS (
                    SELECT id, parent_mandate_id, max_descendant_mandates
                    FROM mandates
                    WHERE id = NEW.parent_mandate_id
                    UNION
                    SELECT parent.id, parent.parent_mandate_id,
                           parent.max_descendant_mandates
                    FROM mandates AS parent
                    JOIN ancestors AS child ON parent.id = child.parent_id
                ),
                descendants(ancestor_id, descendant_id) AS (
                    SELECT ancestor.id, child.id
                    FROM ancestors AS ancestor
                    JOIN mandates AS child ON child.parent_mandate_id = ancestor.id
                    WHERE ancestor.cap IS NOT NULL
                    UNION
                    SELECT descendants.ancestor_id, child.id
                    FROM descendants
                    JOIN mandates AS child
                      ON child.parent_mandate_id = descendants.descendant_id
                )
                SELECT 1
                FROM ancestors AS ancestor
                WHERE ancestor.cap IS NOT NULL
                  AND (
                      SELECT COUNT(*)
                      FROM descendants
                      WHERE descendants.ancestor_id = ancestor.id
                  ) >= ancestor.cap
            ) THEN RAISE(ABORT, 'mandate_fanout_exhausted') END;
        END;
        """
    )


def _install_schema_version_monotonicity_guard(connection: sqlite3.Connection) -> None:
    """Keep a stale initializer from making a migrated DB look older again.

    An older process can have read its startup version before this migration takes
    the writer lock. Its legacy ``INSERT OR REPLACE`` stamp must not overwrite the
    newer version after that process resumes.
    """
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS service_schema_version_no_downgrade
        BEFORE INSERT ON meta
        WHEN NEW.key = 'schema_version'
          AND EXISTS (
              SELECT 1 FROM meta
              WHERE key = NEW.key
                AND CAST(value AS INTEGER) > CAST(NEW.value AS INTEGER)
          )
        BEGIN
            SELECT RAISE(ABORT, 'service_schema_version_downgrade');
        END;
        """
    )


def _install_service_upgrade_guards(connection: sqlite3.Connection) -> None:
    _install_mandate_fanout_guard(connection)
    _install_schema_version_monotonicity_guard(connection)


def _install_task_claim_budget_guards(connection: sqlite3.Connection) -> None:
    """Keep successful-claim caps effective across already-running service writers."""
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS task_claim_budget_insert_guard
        BEFORE INSERT ON tasks
        BEGIN
            SELECT CASE WHEN EXISTS (SELECT 1 FROM tasks WHERE id = NEW.id)
              THEN RAISE(ABORT, 'task_claim_budget_config_immutable') END;
            SELECT CASE WHEN typeof(NEW.claim_fencing_token) <> 'integer'
              OR NEW.claim_fencing_token <> 0
              THEN RAISE(ABORT, 'task_claim_fencing_invalid') END;
            SELECT CASE WHEN NEW.parent_task_id IS NOT NULL
              AND (typeof(NEW.parent_task_id) <> 'text'
                OR length(trim(NEW.parent_task_id)) = 0
                OR NOT EXISTS (SELECT 1 FROM tasks WHERE id = NEW.parent_task_id))
              THEN RAISE(ABORT, 'task_lineage_invalid') END;
            SELECT CASE WHEN NEW.parent_task_id IS NOT NULL AND EXISTS (
                WITH RECURSIVE ancestors(id, parent_task_id, path, cycle) AS (
                    SELECT id, parent_task_id, '|' || id || '|', 0
                    FROM tasks WHERE id = NEW.parent_task_id
                    UNION ALL
                    SELECT parent.id, parent.parent_task_id,
                           ancestors.path || parent.id || '|',
                           instr(ancestors.path, '|' || parent.id || '|') > 0
                    FROM tasks AS parent
                    JOIN ancestors ON parent.id = ancestors.parent_task_id
                    WHERE ancestors.cycle = 0
                )
                SELECT 1 FROM ancestors
                WHERE cycle = 1 OR (parent_task_id IS NOT NULL AND (
                    typeof(parent_task_id) <> 'text'
                    OR length(trim(parent_task_id)) = 0
                    OR NOT EXISTS (SELECT 1 FROM tasks WHERE id = ancestors.parent_task_id)
                ))
            ) THEN RAISE(ABORT, 'task_lineage_invalid') END;
        END;
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS task_claim_budget_config_immutable
        BEFORE UPDATE OF parent_task_id, max_claims, max_descendant_claims ON tasks
        WHEN NEW.parent_task_id IS NOT OLD.parent_task_id
          OR NEW.max_claims IS NOT OLD.max_claims
          OR NEW.max_descendant_claims IS NOT OLD.max_descendant_claims
        BEGIN
            SELECT RAISE(ABORT, 'task_claim_budget_config_immutable');
        END;
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS task_claim_budget_guard
        BEFORE UPDATE OF claim_fencing_token ON tasks
        WHEN NEW.claim_fencing_token IS NOT OLD.claim_fencing_token
        BEGIN
            SELECT CASE WHEN typeof(OLD.claim_fencing_token) <> 'integer'
              OR OLD.claim_fencing_token < 0
              OR typeof(NEW.claim_fencing_token) <> 'integer'
              OR NEW.claim_fencing_token <> OLD.claim_fencing_token + 1
              THEN RAISE(ABORT, 'task_claim_fencing_invalid') END;
            SELECT CASE WHEN OLD.max_claims IS NOT NULL
              AND (typeof(OLD.max_claims) <> 'integer' OR OLD.max_claims <= 0)
              THEN RAISE(ABORT, 'task_claim_budget_invalid') END;
            SELECT CASE WHEN OLD.max_claims IS NOT NULL
              AND OLD.claim_fencing_token >= OLD.max_claims
              THEN RAISE(ABORT, 'task_claim_budget_exhausted') END;
            SELECT CASE WHEN OLD.parent_task_id IS NOT NULL
              AND (typeof(OLD.parent_task_id) <> 'text'
                OR length(trim(OLD.parent_task_id)) = 0
                OR NOT EXISTS (SELECT 1 FROM tasks WHERE id = OLD.parent_task_id))
              THEN RAISE(ABORT, 'task_lineage_invalid') END;
            SELECT CASE WHEN OLD.parent_task_id IS NOT NULL AND EXISTS (
                WITH RECURSIVE ancestors(id, parent_task_id, path, cycle) AS (
                    SELECT id, parent_task_id, '|' || id || '|', 0
                    FROM tasks WHERE id = OLD.parent_task_id
                    UNION ALL
                    SELECT parent.id, parent.parent_task_id,
                           ancestors.path || parent.id || '|',
                           instr(ancestors.path, '|' || parent.id || '|') > 0
                    FROM tasks AS parent
                    JOIN ancestors ON parent.id = ancestors.parent_task_id
                    WHERE ancestors.cycle = 0
                )
                SELECT 1 FROM ancestors
                WHERE cycle = 1 OR (parent_task_id IS NOT NULL AND (
                    typeof(parent_task_id) <> 'text'
                    OR length(trim(parent_task_id)) = 0
                    OR NOT EXISTS (SELECT 1 FROM tasks WHERE id = ancestors.parent_task_id)
                ))
            ) THEN RAISE(ABORT, 'task_lineage_invalid') END;
            SELECT CASE WHEN OLD.parent_task_id IS NOT NULL AND EXISTS (
                WITH RECURSIVE ancestors(id, parent_task_id, cap) AS (
                    SELECT id, parent_task_id, max_descendant_claims
                    FROM tasks WHERE id = OLD.parent_task_id
                    UNION
                    SELECT parent.id, parent.parent_task_id,
                           parent.max_descendant_claims
                    FROM tasks AS parent
                    JOIN ancestors AS child ON parent.id = child.parent_task_id
                )
                SELECT 1 FROM ancestors
                WHERE cap IS NOT NULL AND (typeof(cap) <> 'integer' OR cap < 0)
            ) THEN RAISE(ABORT, 'descendant_claim_budget_invalid') END;
            SELECT CASE WHEN OLD.parent_task_id IS NOT NULL AND EXISTS (
                WITH RECURSIVE ancestors(id, parent_task_id) AS (
                    SELECT id, parent_task_id FROM tasks WHERE id = OLD.parent_task_id
                    UNION
                    SELECT parent.id, parent.parent_task_id
                    FROM tasks AS parent
                    JOIN ancestors AS child ON parent.id = child.parent_task_id
                ), descendants(ancestor_id, descendant_id, path, cycle) AS (
                    SELECT ancestor.id, child.id,
                           '|' || ancestor.id || '|' || child.id || '|',
                           child.id = ancestor.id
                    FROM ancestors AS ancestor
                    JOIN tasks AS child ON child.parent_task_id = ancestor.id
                    UNION ALL
                    SELECT descendants.ancestor_id, child.id,
                           descendants.path || child.id || '|',
                           instr(descendants.path, '|' || child.id || '|') > 0
                    FROM descendants
                    JOIN tasks AS child ON child.parent_task_id = descendants.descendant_id
                    WHERE descendants.cycle = 0
                )
                SELECT 1 FROM descendants WHERE cycle = 1
            ) THEN RAISE(ABORT, 'task_lineage_invalid') END;
            SELECT CASE WHEN OLD.parent_task_id IS NOT NULL AND EXISTS (
                WITH RECURSIVE ancestors(id, parent_task_id, cap) AS (
                    SELECT id, parent_task_id, max_descendant_claims
                    FROM tasks WHERE id = OLD.parent_task_id
                    UNION
                    SELECT parent.id, parent.parent_task_id,
                           parent.max_descendant_claims
                    FROM tasks AS parent
                    JOIN ancestors AS child ON parent.id = child.parent_task_id
                ), descendants(ancestor_id, descendant_id) AS (
                    SELECT ancestor.id, child.id
                    FROM ancestors AS ancestor
                    JOIN tasks AS child ON child.parent_task_id = ancestor.id
                    UNION
                    SELECT descendants.ancestor_id, child.id
                    FROM descendants
                    JOIN tasks AS child ON child.parent_task_id = descendants.descendant_id
                )
                SELECT 1
                FROM ancestors AS ancestor
                JOIN descendants ON descendants.ancestor_id = ancestor.id
                JOIN tasks AS descendant ON descendant.id = descendants.descendant_id
                WHERE ancestor.cap IS NOT NULL
                  AND (typeof(descendant.claim_fencing_token) <> 'integer'
                    OR descendant.claim_fencing_token < 0)
            ) THEN RAISE(ABORT, 'descendant_claim_budget_invalid') END;
            SELECT CASE WHEN OLD.parent_task_id IS NOT NULL AND EXISTS (
                WITH RECURSIVE ancestors(id, parent_task_id, cap) AS (
                    SELECT id, parent_task_id, max_descendant_claims
                    FROM tasks WHERE id = OLD.parent_task_id
                    UNION
                    SELECT parent.id, parent.parent_task_id,
                           parent.max_descendant_claims
                    FROM tasks AS parent
                    JOIN ancestors AS child ON parent.id = child.parent_task_id
                ), descendants(ancestor_id, descendant_id) AS (
                    SELECT ancestor.id, child.id
                    FROM ancestors AS ancestor
                    JOIN tasks AS child ON child.parent_task_id = ancestor.id
                    UNION
                    SELECT descendants.ancestor_id, child.id
                    FROM descendants
                    JOIN tasks AS child ON child.parent_task_id = descendants.descendant_id
                ), usage(ancestor_id, claims) AS (
                    SELECT descendants.ancestor_id, SUM(task.claim_fencing_token)
                    FROM descendants
                    JOIN tasks AS task ON task.id = descendants.descendant_id
                    GROUP BY descendants.ancestor_id
                )
                SELECT 1 FROM ancestors AS ancestor
                LEFT JOIN usage ON usage.ancestor_id = ancestor.id
                WHERE ancestor.cap IS NOT NULL
                  AND COALESCE(usage.claims, 0) >= ancestor.cap
            ) THEN RAISE(ABORT, 'descendant_claim_budget_exhausted') END;
        END;
        """
    )


def _add_task_claim_budgets(connection: sqlite3.Connection) -> None:
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(tasks)")}
    if "parent_task_id" not in columns:
        connection.execute(
            "ALTER TABLE tasks ADD COLUMN parent_task_id TEXT REFERENCES tasks(id) CHECK ("
            "parent_task_id IS NULL OR "
            "(typeof(parent_task_id) = 'text' AND length(trim(parent_task_id)) > 0))"
        )
    if "max_claims" not in columns:
        connection.execute(
            "ALTER TABLE tasks ADD COLUMN max_claims INTEGER CHECK ("
            "max_claims IS NULL OR (typeof(max_claims) = 'integer' AND max_claims > 0))"
        )
    if "max_descendant_claims" not in columns:
        connection.execute(
            "ALTER TABLE tasks ADD COLUMN max_descendant_claims INTEGER CHECK ("
            "max_descendant_claims IS NULL OR "
            "(typeof(max_descendant_claims) = 'integer' AND max_descendant_claims >= 0))"
        )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_tasks_parent_task ON tasks(parent_task_id)")
    _install_task_claim_budget_guards(connection)


def _add_dispatch_attempt_budgets(connection: sqlite3.Connection) -> None:
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(tasks)")}
    if "max_dispatch_attempts" not in columns:
        connection.execute(
            "ALTER TABLE tasks ADD COLUMN max_dispatch_attempts INTEGER CHECK ("
            "max_dispatch_attempts IS NULL OR "
            "(typeof(max_dispatch_attempts) = 'integer' AND max_dispatch_attempts >= 0))"
        )
    if "max_descendant_dispatch_attempts" not in columns:
        connection.execute(
            "ALTER TABLE tasks ADD COLUMN max_descendant_dispatch_attempts INTEGER CHECK ("
            "max_descendant_dispatch_attempts IS NULL OR "
            "(typeof(max_descendant_dispatch_attempts) = 'integer' "
            "AND max_descendant_dispatch_attempts >= 0))"
        )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS dispatch_attempt_reservations ("
        "id TEXT PRIMARY KEY, "
        "task_id TEXT NOT NULL REFERENCES tasks(id), "
        "agent_id TEXT NOT NULL REFERENCES agents(id), "
        "claim_fencing_token INTEGER NOT NULL CHECK "
        "(typeof(claim_fencing_token) = 'integer' AND claim_fencing_token > 0), "
        "resource_fencing_tokens_json TEXT NOT NULL DEFAULT '{}', "
        "idempotency_key TEXT NOT NULL CHECK "
        "(typeof(idempotency_key) = 'text' AND length(idempotency_key) BETWEEN 1 AND 200), "
        "created_at TEXT NOT NULL, UNIQUE(task_id, idempotency_key))"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_dispatch_attempt_reservations_task "
        "ON dispatch_attempt_reservations(task_id, created_at, id)"
    )
    reservation_columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(dispatch_attempt_reservations)")
    }
    if "resource_fencing_tokens_json" not in reservation_columns:
        connection.execute(
            "ALTER TABLE dispatch_attempt_reservations "
            "ADD COLUMN resource_fencing_tokens_json TEXT NOT NULL DEFAULT '{}'"
        )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS dispatch_attempt_receipts ("
        "dispatch_attempt_id TEXT PRIMARY KEY "
        "REFERENCES dispatch_attempt_reservations(id), "
        "source TEXT NOT NULL CHECK(source = 'client_reported'), "
        "http_status_code INTEGER NOT NULL CHECK "
        "(typeof(http_status_code) = 'integer' AND http_status_code BETWEEN 100 AND 599), "
        "retry_after_seconds INTEGER CHECK "
        "(retry_after_seconds IS NULL OR "
        "(typeof(retry_after_seconds) = 'integer' AND retry_after_seconds BETWEEN 0 AND 86400)), "
        "received_at TEXT NOT NULL)"
    )
    connection.execute(
        "CREATE TRIGGER IF NOT EXISTS task_dispatch_budget_config_immutable "
        "BEFORE UPDATE OF max_dispatch_attempts, max_descendant_dispatch_attempts ON tasks "
        "WHEN NEW.max_dispatch_attempts IS NOT OLD.max_dispatch_attempts "
        "OR NEW.max_descendant_dispatch_attempts IS NOT OLD.max_descendant_dispatch_attempts "
        "BEGIN SELECT RAISE(ABORT, 'task_dispatch_budget_config_immutable'); END"
    )
    connection.execute(
        "CREATE TRIGGER IF NOT EXISTS task_dispatch_budget_insert_guard "
        "BEFORE INSERT ON tasks BEGIN "
        "SELECT CASE WHEN NEW.max_dispatch_attempts IS NOT NULL AND "
        "(typeof(NEW.max_dispatch_attempts) <> 'integer' OR NEW.max_dispatch_attempts < 0) "
        "THEN RAISE(ABORT, 'task_dispatch_budget_invalid') END; "
        "SELECT CASE WHEN NEW.max_descendant_dispatch_attempts IS NOT NULL AND "
        "(typeof(NEW.max_descendant_dispatch_attempts) <> 'integer' "
        "OR NEW.max_descendant_dispatch_attempts < 0) "
        "THEN RAISE(ABORT, 'descendant_dispatch_budget_invalid') END; END"
    )
    connection.execute(
        "CREATE TRIGGER IF NOT EXISTS dispatch_attempt_insert_guard "
        "BEFORE INSERT ON dispatch_attempt_reservations BEGIN "
        "SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM tasks AS task "
        "WHERE task.id = NEW.task_id AND task.owner_agent_id = NEW.agent_id "
        "AND task.claim_fencing_token = NEW.claim_fencing_token "
        "AND task.status IN ('claimed', 'working') AND task.claim_expires_at > "
        "CAST(strftime('%s', 'now') AS INTEGER)) "
        "THEN RAISE(ABORT, 'dispatch_claim_fence_invalid') END; "
        "SELECT CASE WHEN json_valid(NEW.resource_fencing_tokens_json) <> 1 "
        "THEN RAISE(ABORT, 'dispatch_resource_fence_invalid') END; "
        "SELECT CASE WHEN json_type(NEW.resource_fencing_tokens_json) <> 'object' "
        "THEN RAISE(ABORT, 'dispatch_resource_fence_invalid') END; "
        "SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM tasks AS task "
        "WHERE task.id = NEW.task_id AND "
        "(SELECT COUNT(*) FROM json_each(NEW.resource_fencing_tokens_json)) "
        "= json_array_length(task.resources_json) AND NOT EXISTS ("
        "SELECT 1 FROM json_each(NEW.resource_fencing_tokens_json) AS fence "
        "LEFT JOIN resource_leases AS lease ON lease.resource = fence.key "
        "WHERE fence.type <> 'integer' OR fence.value < 1 OR lease.resource IS NULL "
        "OR lease.task_id IS NOT NEW.task_id "
        "OR lease.holder_agent_id IS NOT NEW.agent_id "
        "OR lease.fencing_token <> fence.value OR lease.expires_at <= "
        "CAST(strftime('%s', 'now') AS INTEGER) OR NOT EXISTS ("
        "SELECT 1 FROM json_each(task.resources_json) AS declared "
        "WHERE declared.value = fence.key)) AND NOT EXISTS ("
        "SELECT 1 FROM json_each(task.resources_json) AS declared "
        "WHERE NOT EXISTS (SELECT 1 FROM json_each(NEW.resource_fencing_tokens_json) "
        "AS fence WHERE fence.key = declared.value))) "
        "THEN RAISE(ABORT, 'dispatch_resource_fence_invalid') END; "
        "SELECT CASE WHEN EXISTS (SELECT 1 FROM tasks AS task WHERE task.id = NEW.task_id "
        "AND task.max_dispatch_attempts IS NOT NULL "
        "AND (typeof(task.max_dispatch_attempts) <> 'integer' "
        "OR task.max_dispatch_attempts < 0)) "
        "THEN RAISE(ABORT, 'task_dispatch_budget_invalid') END; "
        "SELECT CASE WHEN EXISTS (SELECT 1 FROM tasks AS task WHERE task.id = NEW.task_id "
        "AND task.max_dispatch_attempts IS NOT NULL AND "
        "(SELECT COUNT(*) FROM dispatch_attempt_reservations WHERE task_id = NEW.task_id) "
        ">= task.max_dispatch_attempts) "
        "THEN RAISE(ABORT, 'task_dispatch_budget_exhausted') END; "
        "SELECT CASE WHEN EXISTS (SELECT 1 FROM tasks AS child WHERE child.id = NEW.task_id "
        "AND child.parent_task_id IS NOT NULL AND NOT EXISTS "
        "(SELECT 1 FROM tasks AS parent WHERE parent.id = child.parent_task_id)) "
        "THEN RAISE(ABORT, 'task_lineage_invalid') END; "
        "SELECT CASE WHEN EXISTS (WITH RECURSIVE ancestors(id, parent_task_id, "
        "max_descendant_dispatch_attempts, path, cycle) AS ("
        "SELECT parent.id, parent.parent_task_id, parent.max_descendant_dispatch_attempts, "
        "'|' || parent.id || '|', 0 "
        "FROM tasks AS child JOIN tasks AS parent ON parent.id = child.parent_task_id "
        "WHERE child.id = NEW.task_id UNION ALL "
        "SELECT parent.id, parent.parent_task_id, parent.max_descendant_dispatch_attempts, "
        "ancestors.path || parent.id || '|', "
        "instr(ancestors.path, '|' || parent.id || '|') > 0 "
        "FROM tasks AS parent JOIN ancestors ON parent.id = ancestors.parent_task_id "
        "WHERE ancestors.cycle = 0) SELECT 1 FROM ancestors WHERE cycle = 1 "
        "OR (parent_task_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM tasks AS parent "
        "WHERE parent.id = ancestors.parent_task_id))) "
        "THEN RAISE(ABORT, 'task_lineage_invalid') END; "
        "SELECT CASE WHEN EXISTS (WITH RECURSIVE ancestors(id, parent_task_id, "
        "max_descendant_dispatch_attempts, path, cycle) AS ("
        "SELECT parent.id, parent.parent_task_id, parent.max_descendant_dispatch_attempts, "
        "'|' || parent.id || '|', 0 "
        "FROM tasks AS child JOIN tasks AS parent ON parent.id = child.parent_task_id "
        "WHERE child.id = NEW.task_id UNION ALL "
        "SELECT parent.id, parent.parent_task_id, parent.max_descendant_dispatch_attempts, "
        "ancestors.path || parent.id || '|', "
        "instr(ancestors.path, '|' || parent.id || '|') > 0 "
        "FROM tasks AS parent JOIN ancestors ON parent.id = ancestors.parent_task_id "
        "WHERE ancestors.cycle = 0), descendants(ancestor_id, id, path, cycle) AS ("
        "SELECT ancestor.id, child.id, '|' || ancestor.id || '|' || child.id || '|', "
        "child.id = ancestor.id FROM ancestors AS ancestor JOIN tasks AS child "
        "ON child.parent_task_id = ancestor.id UNION ALL "
        "SELECT descendants.ancestor_id, child.id, descendants.path || child.id || '|', "
        "instr(descendants.path, '|' || child.id || '|') > 0 FROM tasks AS child "
        "JOIN descendants ON child.parent_task_id = descendants.id WHERE descendants.cycle = 0), "
        "usage(ancestor_id, reservations) AS (SELECT ancestor.id, COUNT(reservation.id) "
        "FROM ancestors AS ancestor LEFT JOIN descendants "
        "ON descendants.ancestor_id = ancestor.id LEFT JOIN dispatch_attempt_reservations AS reservation "
        "ON reservation.task_id = descendants.id GROUP BY ancestor.id) "
        "SELECT 1 FROM ancestors AS ancestor LEFT JOIN usage "
        "ON usage.ancestor_id = ancestor.id WHERE ancestor.max_descendant_dispatch_attempts "
        "IS NOT NULL AND (typeof(ancestor.max_descendant_dispatch_attempts) <> 'integer' "
        "OR ancestor.max_descendant_dispatch_attempts < 0)) "
        "THEN RAISE(ABORT, 'descendant_dispatch_budget_invalid') END; "
        "SELECT CASE WHEN EXISTS (WITH RECURSIVE ancestors(id, parent_task_id, "
        "max_descendant_dispatch_attempts, path, cycle) AS ("
        "SELECT parent.id, parent.parent_task_id, parent.max_descendant_dispatch_attempts, "
        "'|' || parent.id || '|', 0 "
        "FROM tasks AS child JOIN tasks AS parent ON parent.id = child.parent_task_id "
        "WHERE child.id = NEW.task_id UNION ALL "
        "SELECT parent.id, parent.parent_task_id, parent.max_descendant_dispatch_attempts, "
        "ancestors.path || parent.id || '|', "
        "instr(ancestors.path, '|' || parent.id || '|') > 0 "
        "FROM tasks AS parent JOIN ancestors ON parent.id = ancestors.parent_task_id "
        "WHERE ancestors.cycle = 0), descendants(ancestor_id, id, path, cycle) AS ("
        "SELECT ancestor.id, child.id, '|' || ancestor.id || '|' || child.id || '|', "
        "child.id = ancestor.id FROM ancestors AS ancestor JOIN tasks AS child "
        "ON child.parent_task_id = ancestor.id UNION ALL "
        "SELECT descendants.ancestor_id, child.id, descendants.path || child.id || '|', "
        "instr(descendants.path, '|' || child.id || '|') > 0 FROM tasks AS child "
        "JOIN descendants ON child.parent_task_id = descendants.id WHERE descendants.cycle = 0), "
        "usage(ancestor_id, reservations) AS (SELECT ancestor.id, COUNT(reservation.id) "
        "FROM ancestors AS ancestor LEFT JOIN descendants "
        "ON descendants.ancestor_id = ancestor.id LEFT JOIN dispatch_attempt_reservations AS reservation "
        "ON reservation.task_id = descendants.id GROUP BY ancestor.id) "
        "SELECT 1 FROM ancestors AS ancestor LEFT JOIN usage "
        "ON usage.ancestor_id = ancestor.id WHERE ancestor.max_descendant_dispatch_attempts "
        "IS NOT NULL AND COALESCE(usage.reservations, 0) >= "
        "ancestor.max_descendant_dispatch_attempts) "
        "THEN RAISE(ABORT, 'descendant_dispatch_budget_exhausted') END; END"
    )
    connection.execute(
        "CREATE TRIGGER IF NOT EXISTS dispatch_attempt_reservation_immutable "
        "BEFORE UPDATE ON dispatch_attempt_reservations "
        "BEGIN SELECT RAISE(ABORT, 'dispatch_attempt_reservation_immutable'); END"
    )
    connection.execute(
        "CREATE TRIGGER IF NOT EXISTS dispatch_attempt_reservation_no_delete "
        "BEFORE DELETE ON dispatch_attempt_reservations "
        "BEGIN SELECT RAISE(ABORT, 'dispatch_attempt_reservation_immutable'); END"
    )
    connection.execute(
        "CREATE TRIGGER IF NOT EXISTS dispatch_attempt_receipt_immutable "
        "BEFORE UPDATE ON dispatch_attempt_receipts "
        "BEGIN SELECT RAISE(ABORT, 'dispatch_attempt_receipt_immutable'); END"
    )
    connection.execute(
        "CREATE TRIGGER IF NOT EXISTS dispatch_attempt_receipt_no_delete "
        "BEFORE DELETE ON dispatch_attempt_receipts "
        "BEGIN SELECT RAISE(ABORT, 'dispatch_attempt_receipt_immutable'); END"
    )


def _add_dispatch_attempt_provider_usage(connection: sqlite3.Connection) -> None:
    columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(dispatch_attempt_receipts)")
    }
    if "provider_usage_json" not in columns:
        connection.execute(
            "ALTER TABLE dispatch_attempt_receipts ADD COLUMN provider_usage_json TEXT "
            "NOT NULL DEFAULT '{}' CHECK(json_valid(provider_usage_json) = 1 AND "
            "json_type(provider_usage_json) = 'object')"
        )


def _add_outstanding_dispatch_budgets(connection: sqlite3.Connection) -> None:
    """Persist and enforce task-tree caps on reservations without response receipts."""
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(tasks)")}
    if "max_unreceipted_dispatch_attempts" not in columns:
        connection.execute(
            "ALTER TABLE tasks ADD COLUMN max_unreceipted_dispatch_attempts INTEGER CHECK ("
            "max_unreceipted_dispatch_attempts IS NULL OR "
            "(typeof(max_unreceipted_dispatch_attempts) = 'integer' "
            "AND max_unreceipted_dispatch_attempts >= 0))"
        )
    if "max_descendant_unreceipted_dispatch_attempts" not in columns:
        connection.execute(
            "ALTER TABLE tasks ADD COLUMN max_descendant_unreceipted_dispatch_attempts "
            "INTEGER CHECK (max_descendant_unreceipted_dispatch_attempts IS NULL OR "
            "(typeof(max_descendant_unreceipted_dispatch_attempts) = 'integer' "
            "AND max_descendant_unreceipted_dispatch_attempts >= 0))"
        )
    connection.execute(
        "CREATE TRIGGER IF NOT EXISTS task_dispatch_outstanding_config_immutable "
        "BEFORE UPDATE OF max_unreceipted_dispatch_attempts, "
        "max_descendant_unreceipted_dispatch_attempts ON tasks "
        "WHEN NEW.max_unreceipted_dispatch_attempts IS NOT OLD.max_unreceipted_dispatch_attempts "
        "OR NEW.max_descendant_unreceipted_dispatch_attempts "
        "IS NOT OLD.max_descendant_unreceipted_dispatch_attempts "
        "BEGIN SELECT RAISE(ABORT, 'task_dispatch_outstanding_config_immutable'); END"
    )
    connection.execute(
        "CREATE TRIGGER IF NOT EXISTS task_dispatch_outstanding_insert_guard "
        "BEFORE INSERT ON tasks BEGIN "
        "SELECT CASE WHEN NEW.max_unreceipted_dispatch_attempts IS NOT NULL AND "
        "(typeof(NEW.max_unreceipted_dispatch_attempts) <> 'integer' "
        "OR NEW.max_unreceipted_dispatch_attempts < 0) "
        "THEN RAISE(ABORT, 'task_dispatch_outstanding_budget_invalid') END; "
        "SELECT CASE WHEN NEW.max_descendant_unreceipted_dispatch_attempts IS NOT NULL AND "
        "(typeof(NEW.max_descendant_unreceipted_dispatch_attempts) <> 'integer' "
        "OR NEW.max_descendant_unreceipted_dispatch_attempts < 0) "
        "THEN RAISE(ABORT, 'descendant_dispatch_outstanding_budget_invalid') END; END"
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS dispatch_attempt_outstanding_budget_guard
        BEFORE INSERT ON dispatch_attempt_reservations
        BEGIN
            SELECT CASE WHEN EXISTS (
                SELECT 1 FROM tasks AS task
                WHERE task.id = NEW.task_id
                  AND task.max_unreceipted_dispatch_attempts IS NOT NULL
                  AND (typeof(task.max_unreceipted_dispatch_attempts) <> 'integer'
                       OR task.max_unreceipted_dispatch_attempts < 0)
            ) THEN RAISE(ABORT, 'task_dispatch_outstanding_budget_invalid') END;
            SELECT CASE WHEN EXISTS (
                SELECT 1 FROM tasks AS task
                WHERE task.id = NEW.task_id
                  AND task.max_unreceipted_dispatch_attempts IS NOT NULL
                  AND (
                      SELECT COUNT(*)
                      FROM dispatch_attempt_reservations AS reservation
                      LEFT JOIN dispatch_attempt_receipts AS receipt
                        ON receipt.dispatch_attempt_id = reservation.id
                      WHERE reservation.task_id = task.id
                        AND receipt.dispatch_attempt_id IS NULL
                  ) >= task.max_unreceipted_dispatch_attempts
            ) THEN RAISE(ABORT, 'task_dispatch_outstanding_budget_exhausted') END;
            SELECT CASE WHEN EXISTS (
                WITH RECURSIVE
                ancestors(id, parent_task_id, cap, path, cycle) AS (
                    SELECT parent.id, parent.parent_task_id,
                           parent.max_descendant_unreceipted_dispatch_attempts,
                           '|' || parent.id || '|', 0
                    FROM tasks AS child
                    JOIN tasks AS parent ON parent.id = child.parent_task_id
                    WHERE child.id = NEW.task_id
                    UNION ALL
                    SELECT parent.id, parent.parent_task_id,
                           parent.max_descendant_unreceipted_dispatch_attempts,
                           ancestors.path || parent.id || '|',
                           instr(ancestors.path, '|' || parent.id || '|') > 0
                    FROM tasks AS parent
                    JOIN ancestors ON parent.id = ancestors.parent_task_id
                    WHERE ancestors.cycle = 0
                ),
                descendants(ancestor_id, id, path, cycle) AS (
                    SELECT ancestor.id, child.id,
                           '|' || ancestor.id || '|' || child.id || '|',
                           child.id = ancestor.id
                    FROM ancestors AS ancestor
                    JOIN tasks AS child ON child.parent_task_id = ancestor.id
                    UNION ALL
                    SELECT descendants.ancestor_id, child.id,
                           descendants.path || child.id || '|',
                           instr(descendants.path, '|' || child.id || '|') > 0
                    FROM tasks AS child
                    JOIN descendants ON child.parent_task_id = descendants.id
                    WHERE descendants.cycle = 0
                ),
                usage(ancestor_id, outstanding) AS (
                    SELECT ancestor.id,
                           COUNT(CASE WHEN receipt.dispatch_attempt_id IS NULL
                                      THEN reservation.id END)
                    FROM ancestors AS ancestor
                    LEFT JOIN descendants
                      ON descendants.ancestor_id = ancestor.id
                    LEFT JOIN dispatch_attempt_reservations AS reservation
                      ON reservation.task_id = descendants.id
                    LEFT JOIN dispatch_attempt_receipts AS receipt
                      ON receipt.dispatch_attempt_id = reservation.id
                    GROUP BY ancestor.id
                )
                SELECT 1 FROM ancestors AS ancestor
                LEFT JOIN usage ON usage.ancestor_id = ancestor.id
                WHERE ancestor.cap IS NOT NULL
                  AND (typeof(ancestor.cap) <> 'integer' OR ancestor.cap < 0)
            ) THEN RAISE(ABORT, 'descendant_dispatch_outstanding_budget_invalid') END;
            SELECT CASE WHEN EXISTS (
                WITH RECURSIVE
                ancestors(id, parent_task_id, cap, path, cycle) AS (
                    SELECT parent.id, parent.parent_task_id,
                           parent.max_descendant_unreceipted_dispatch_attempts,
                           '|' || parent.id || '|', 0
                    FROM tasks AS child
                    JOIN tasks AS parent ON parent.id = child.parent_task_id
                    WHERE child.id = NEW.task_id
                    UNION ALL
                    SELECT parent.id, parent.parent_task_id,
                           parent.max_descendant_unreceipted_dispatch_attempts,
                           ancestors.path || parent.id || '|',
                           instr(ancestors.path, '|' || parent.id || '|') > 0
                    FROM tasks AS parent
                    JOIN ancestors ON parent.id = ancestors.parent_task_id
                    WHERE ancestors.cycle = 0
                ),
                descendants(ancestor_id, id, path, cycle) AS (
                    SELECT ancestor.id, child.id,
                           '|' || ancestor.id || '|' || child.id || '|',
                           child.id = ancestor.id
                    FROM ancestors AS ancestor
                    JOIN tasks AS child ON child.parent_task_id = ancestor.id
                    UNION ALL
                    SELECT descendants.ancestor_id, child.id,
                           descendants.path || child.id || '|',
                           instr(descendants.path, '|' || child.id || '|') > 0
                    FROM tasks AS child
                    JOIN descendants ON child.parent_task_id = descendants.id
                    WHERE descendants.cycle = 0
                ),
                usage(ancestor_id, outstanding) AS (
                    SELECT ancestor.id,
                           COUNT(CASE WHEN receipt.dispatch_attempt_id IS NULL
                                      THEN reservation.id END)
                    FROM ancestors AS ancestor
                    LEFT JOIN descendants
                      ON descendants.ancestor_id = ancestor.id
                    LEFT JOIN dispatch_attempt_reservations AS reservation
                      ON reservation.task_id = descendants.id
                    LEFT JOIN dispatch_attempt_receipts AS receipt
                      ON receipt.dispatch_attempt_id = reservation.id
                    GROUP BY ancestor.id
                )
                SELECT 1 FROM ancestors AS ancestor
                LEFT JOIN usage ON usage.ancestor_id = ancestor.id
                WHERE ancestor.cap IS NOT NULL
                  AND COALESCE(usage.outstanding, 0) >= ancestor.cap
            ) THEN RAISE(ABORT, 'descendant_dispatch_outstanding_budget_exhausted') END;
        END;
        """
    )


def _add_budget_interruption_reports(connection: sqlite3.Connection) -> None:
    """Persist bounded, non-promotable client checkpoints for interrupted work."""

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS budget_interruption_reports (
          id TEXT PRIMARY KEY,
          task_id TEXT NOT NULL REFERENCES tasks(id),
          agent_id TEXT NOT NULL REFERENCES agents(id),
          claim_fencing_token INTEGER NOT NULL CHECK
            (typeof(claim_fencing_token) = 'integer' AND claim_fencing_token > 0),
          resource_fencing_tokens_json TEXT NOT NULL CHECK
            (json_valid(resource_fencing_tokens_json) = 1
              AND json_type(resource_fencing_tokens_json) = 'object'),
          status TEXT NOT NULL CHECK(status = 'partial'),
          source TEXT NOT NULL CHECK(source = 'client_reported'),
          reason TEXT NOT NULL CHECK(reason IN (
            'provider_quota_exhausted', 'local_budget_exhausted',
            'retry_exhausted', 'operator_interrupted', 'unknown'
          )),
          summary TEXT NOT NULL CHECK
            (typeof(summary) = 'text' AND length(summary) BETWEEN 1 AND 2000),
          checkpoint_json TEXT NOT NULL CHECK
            (typeof(checkpoint_json) = 'text'
              AND json_valid(checkpoint_json) = 1
              AND json_type(checkpoint_json) = 'object'
              AND length(CAST(checkpoint_json AS BLOB)) <= 8192),
          checkpoint_sha256 TEXT NOT NULL CHECK
            (typeof(checkpoint_sha256) = 'text'
              AND length(checkpoint_sha256) = 64
              AND checkpoint_sha256 NOT GLOB '*[^0-9a-f]*'),
          dispatch_attempt_ids_json TEXT NOT NULL CHECK
            (typeof(dispatch_attempt_ids_json) = 'text'
              AND json_valid(dispatch_attempt_ids_json) = 1
              AND json_type(dispatch_attempt_ids_json) = 'array'
              AND length(CAST(dispatch_attempt_ids_json AS BLOB)) <= 12000),
          received_at TEXT NOT NULL,
          UNIQUE(task_id, claim_fencing_token)
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_budget_interruption_reports_task "
        "ON budget_interruption_reports(task_id, received_at DESC, id)"
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS budget_interruption_report_immutable_update
        BEFORE UPDATE ON budget_interruption_reports
        BEGIN SELECT RAISE(ABORT, 'budget_interruption_report_immutable'); END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS budget_interruption_report_immutable_delete
        BEFORE DELETE ON budget_interruption_reports
        BEGIN SELECT RAISE(ABORT, 'budget_interruption_report_immutable'); END
        """
    )


def _guard_interrupted_claim_writes(connection: sqlite3.Connection) -> None:
    """Enforce interruption fences in SQLite, including for older service workers."""

    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS budget_interruption_dispatch_insert_guard
        BEFORE INSERT ON dispatch_attempt_reservations
        WHEN EXISTS (
            SELECT 1 FROM budget_interruption_reports
            WHERE task_id = NEW.task_id
              AND agent_id = NEW.agent_id
              AND claim_fencing_token = NEW.claim_fencing_token
        )
        BEGIN SELECT RAISE(ABORT, 'claim_interrupted'); END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS budget_interruption_submission_insert_guard
        BEFORE INSERT ON submissions
        WHEN EXISTS (
            SELECT 1 FROM budget_interruption_reports
            WHERE task_id = NEW.task_id
              AND agent_id = NEW.worker_agent_id
              AND claim_fencing_token = NEW.claim_fencing_token
        )
        BEGIN SELECT RAISE(ABORT, 'claim_interrupted'); END
        """
    )


def _guard_interrupted_task_resume(connection: sqlite3.Connection) -> None:
    """Require explicit operator reopen across mixed-version task lifecycles.

    A pre-migration service process can keep writing the migrated database without
    seeing this binary's Python reaper/claim checks. The persistent trigger prevents
    its legacy `orphaned` transition or automatic orphaned-task claim from resuming
    the same interrupted claim generation.
    """
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS budget_interruption_task_resume_guard
        BEFORE UPDATE OF status ON tasks
        WHEN (
            (OLD.status IN ('claimed', 'working') AND NEW.status = 'orphaned')
            OR (OLD.status = 'orphaned' AND NEW.status IN ('claimed', 'working'))
        )
        AND EXISTS (
            SELECT 1 FROM budget_interruption_reports
            WHERE task_id = OLD.id
              AND claim_fencing_token = OLD.claim_fencing_token
        )
        BEGIN
            SELECT RAISE(ABORT, 'task_interruption_requires_reopen');
        END
        """
    )


def _park_previously_orphaned_interrupted_tasks(connection: sqlite3.Connection) -> None:
    """Make pre-migration interrupted orphan rows explicitly recoverable.

    Migration 10 prevents an orphaned interrupted claim from being automatically
    claimed, while the audited operator reopen path intentionally accepts only
    ``blocked`` or ``conflicted`` tasks. Older databases may already contain an
    ``orphaned`` row with a matching client interruption report, so park exactly
    those rows as blocked before normal service resumes.
    """
    rows = connection.execute(
        """
        SELECT tasks.id, tasks.claim_fencing_token, tasks.version,
               report.id AS interruption_report_id
        FROM tasks
        JOIN budget_interruption_reports AS report
          ON report.task_id = tasks.id
         AND report.claim_fencing_token = tasks.claim_fencing_token
        WHERE tasks.status = 'orphaned'
        ORDER BY tasks.id
        """
    ).fetchall()
    for row in rows:
        changed_at = utc_now()
        cursor = connection.execute(
            """
            UPDATE tasks
            SET status = 'blocked', owner_agent_id = NULL, claim_expires_at = NULL,
                version = version + 1, updated_at = ?
            WHERE id = ? AND status = 'orphaned' AND claim_fencing_token = ?
            """,
            (changed_at, row["id"], row["claim_fencing_token"]),
        )
        if cursor.rowcount != 1:
            raise sqlite3.IntegrityError("interrupted orphan changed during schema migration")
        _append_audit_event(
            connection,
            "task.interruption_migration_parked",
            "system",
            {
                "claim_fencing_token": row["claim_fencing_token"],
                "from_status": "orphaned",
                "interruption_report_id": row["interruption_report_id"],
                "previous_version": row["version"],
                "schema_version": 11,
                "task_id": row["id"],
                "to_status": "blocked",
            },
        )


def _guard_unresolved_interruption_resumes(connection: sqlite3.Connection) -> None:
    """Quarantine legacy reclaims unless an operator audited a later reopen.

    Before migration 10, a service process could reap a reported claim to
    ``orphaned`` and then claim it again under a higher fence. Exact-fence
    checks no longer recognize that older report. A report is resolved only by
    a later hash-chained ``task.reopened`` event for the same task; missing
    report provenance fails closed.
    """
    connection.execute("DROP TRIGGER IF EXISTS budget_interruption_task_resume_guard")
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_interruption_report_id
        ON audit_events(json_extract(payload_json, '$.report_id'))
        WHERE event_type = 'task.interruption_reported'
        """
    )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_task_reopened_id
        ON audit_events(json_extract(payload_json, '$.task_id'))
        WHERE event_type = 'task.reopened'
        """
    )
    connection.execute("DROP VIEW IF EXISTS budget_unresolved_interruption_reports")
    connection.execute(
        """
        CREATE VIEW budget_unresolved_interruption_reports AS
        SELECT report.id AS report_id,
               report.task_id,
               report.agent_id,
               report.claim_fencing_token,
               report.received_at
        FROM budget_interruption_reports AS report
        LEFT JOIN audit_events AS interruption_event
          ON interruption_event.event_type = 'task.interruption_reported'
         AND json_extract(interruption_event.payload_json, '$.report_id') = report.id
         AND json_extract(interruption_event.payload_json, '$.task_id') = report.task_id
         AND json_extract(
                 interruption_event.payload_json, '$.claim_fencing_token'
             ) = report.claim_fencing_token
        WHERE interruption_event.sequence IS NULL
           OR interruption_event.sequence > COALESCE(
               (
                   SELECT MAX(reopened_event.sequence)
                   FROM audit_events AS reopened_event
                   WHERE reopened_event.event_type = 'task.reopened'
                     AND reopened_event.actor = 'admin'
                     AND json_extract(reopened_event.payload_json, '$.task_id') = report.task_id
               ),
               0
           )
        """
    )
    rows = connection.execute(
        """
        SELECT task.id, task.status, task.owner_agent_id, task.claim_expires_at,
               task.claim_fencing_token, task.version,
               (
                   SELECT report.report_id
                   FROM budget_unresolved_interruption_reports AS report
                   WHERE report.task_id = task.id
                   ORDER BY report.claim_fencing_token DESC, report.received_at DESC,
                            report.report_id DESC
                   LIMIT 1
               ) AS interruption_report_id,
               (
                   SELECT report.claim_fencing_token
                   FROM budget_unresolved_interruption_reports AS report
                   WHERE report.task_id = task.id
                   ORDER BY report.claim_fencing_token DESC, report.received_at DESC,
                            report.report_id DESC
                   LIMIT 1
               ) AS interruption_report_fencing_token,
               (
                   SELECT COUNT(*)
                   FROM budget_unresolved_interruption_reports AS report
                   WHERE report.task_id = task.id
               ) AS unresolved_interruption_report_count
        FROM tasks AS task
        WHERE EXISTS (
              SELECT 1 FROM budget_unresolved_interruption_reports AS report
              WHERE report.task_id = task.id
          )
        ORDER BY task.id
        """
    ).fetchall()
    for row in rows:
        changed_at = utc_now()
        task_changed = (
            row["status"] != "blocked"
            or row["owner_agent_id"] is not None
            or row["claim_expires_at"] is not None
        )
        if task_changed:
            cursor = connection.execute(
                """
                UPDATE tasks
                SET status = 'blocked', owner_agent_id = NULL, claim_expires_at = NULL,
                    version = version + 1, updated_at = ?
                WHERE id = ? AND status = ? AND claim_fencing_token = ?
                """,
                (changed_at, row["id"], row["status"], row["claim_fencing_token"]),
            )
            if cursor.rowcount != 1:
                raise sqlite3.IntegrityError("interrupted task changed during schema migration")
        released_leases = connection.execute(
            """
            UPDATE resource_leases
            SET task_id = NULL, holder_agent_id = NULL, expires_at = 0, updated_at = ?
            WHERE task_id = ?
            """,
            (changed_at, row["id"]),
        ).rowcount
        removed_heartbeats = connection.execute(
            "DELETE FROM agent_heartbeats WHERE task_id = ?", (row["id"],)
        ).rowcount
        if not task_changed and not released_leases and not removed_heartbeats:
            # Migration 11 already parked and audited this exact-fence orphan.
            # Do not increment its version or emit a duplicate park event.
            continue
        _append_audit_event(
            connection,
            "task.interruption_migration_parked",
            "system",
            {
                "claim_fencing_token": row["claim_fencing_token"],
                "from_status": row["status"],
                "interruption_report_fencing_token": row["interruption_report_fencing_token"],
                "interruption_report_id": row["interruption_report_id"],
                "previous_version": row["version"],
                "schema_version": 12,
                "task_id": row["id"],
                "to_status": "blocked",
                "unresolved_interruption_report_count": row["unresolved_interruption_report_count"],
            },
        )

    # A stale worker may have submitted or passed QC under a higher fence before
    # this migration acquired SQLite's write lock. Quarantine every lifecycle
    # state, including qc_review/approved/merging/done, before installing guards.
    # The report remains unresolved until a later audited task.reopened event.
    for trigger_name in (
        "budget_interruption_dispatch_insert_guard",
        "budget_interruption_submission_insert_guard",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger_name}")
    connection.execute(
        """
        CREATE TRIGGER budget_interruption_dispatch_insert_guard
        BEFORE INSERT ON dispatch_attempt_reservations
        WHEN EXISTS (
                 SELECT 1 FROM budget_unresolved_interruption_reports AS report
                 WHERE report.task_id = NEW.task_id
             )
          OR EXISTS (
                 SELECT 1 FROM budget_interruption_reports AS report
                 WHERE report.task_id = NEW.task_id
                   AND report.agent_id = NEW.agent_id
                   AND report.claim_fencing_token = NEW.claim_fencing_token
             )
        BEGIN SELECT RAISE(ABORT, 'claim_interrupted'); END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER budget_interruption_submission_insert_guard
        BEFORE INSERT ON submissions
        WHEN EXISTS (
                 SELECT 1 FROM budget_unresolved_interruption_reports AS report
                 WHERE report.task_id = NEW.task_id
             )
          OR EXISTS (
                 SELECT 1 FROM budget_interruption_reports AS report
                 WHERE report.task_id = NEW.task_id
                   AND report.agent_id = NEW.worker_agent_id
                   AND report.claim_fencing_token = NEW.claim_fencing_token
             )
        BEGIN SELECT RAISE(ABORT, 'claim_interrupted'); END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER budget_interruption_task_resume_guard
        BEFORE UPDATE OF status ON tasks
        WHEN NEW.status <> OLD.status AND NEW.status <> 'blocked'
         AND NOT (OLD.status = 'blocked' AND NEW.status = 'open')
         AND EXISTS (
             SELECT 1 FROM budget_unresolved_interruption_reports AS report
             WHERE report.task_id = OLD.id
         )
        BEGIN
            SELECT RAISE(ABORT, 'task_interruption_requires_reopen');
        END
        """
    )


def _execute_script_in_transaction(connection: sqlite3.Connection, script: str) -> None:
    """Execute a static SQL script without sqlite3.executescript's implicit COMMIT."""
    statement = ""
    for line in script.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            if statement.strip():
                connection.execute(statement)
            statement = ""
    if statement.strip():
        raise ValueError("incomplete SQL statement in service schema")


# Version 1 is the baseline CREATE TABLE script plus pre-stamp column additions.
# Numbered upgrades from 2 onward are applied transactionally by the schema ledger.
MIGRATIONS: tuple[Migration, ...] = (
    (2, _add_mandate_descendant_cap),
    (3, _install_service_upgrade_guards),
    (4, _add_task_claim_budgets),
    (5, _add_dispatch_attempt_budgets),
    (6, _add_dispatch_attempt_provider_usage),
    (7, _add_outstanding_dispatch_budgets),
    (8, _add_budget_interruption_reports),
    (9, _guard_interrupted_claim_writes),
    (10, _guard_interrupted_task_resume),
    (11, _park_previously_orphaned_interrupted_tasks),
    (12, _guard_unresolved_interruption_resumes),
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner TEXT NOT NULL,
    parent_agent_id TEXT REFERENCES agents(id),
    role TEXT NOT NULL DEFAULT 'worker'
        CHECK(role IN ('worker', 'qc', 'planner', 'integration')),
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mandates (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id),
    subject TEXT NOT NULL,
    parent_mandate_id TEXT REFERENCES mandates(id),
    scopes_json TEXT NOT NULL,
    max_amount_cents INTEGER,
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    agent_id TEXT REFERENCES agents(id),
    action_pattern TEXT NOT NULL,
    resource_pattern TEXT NOT NULL,
    effect TEXT NOT NULL CHECK(effect IN ('allow', 'deny')),
    requires_approval INTEGER NOT NULL DEFAULT 0,
    max_amount_cents INTEGER,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS action_requests (
    id TEXT PRIMARY KEY,
    mandate_id TEXT NOT NULL REFERENCES mandates(id),
    agent_id TEXT NOT NULL REFERENCES agents(id),
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    context_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'denied', 'consumed')),
    resolution_reason TEXT,
    created_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    acceptance_criteria_json TEXT NOT NULL,
    resources_json TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 50,
    status TEXT NOT NULL CHECK(status IN (
        'open', 'claimed', 'working', 'qc_review', 'changes_requested',
        'approved', 'merging', 'done', 'blocked', 'orphaned', 'conflicted'
    )),
    owner_agent_id TEXT REFERENCES agents(id),
    claim_expires_at INTEGER,
    claim_fencing_token INTEGER NOT NULL DEFAULT 0,
    parent_task_id TEXT REFERENCES tasks(id) CHECK (
        parent_task_id IS NULL OR
        (typeof(parent_task_id) = 'text' AND length(trim(parent_task_id)) > 0)
    ),
    max_claims INTEGER CHECK (
        max_claims IS NULL OR (typeof(max_claims) = 'integer' AND max_claims > 0)
    ),
    max_descendant_claims INTEGER CHECK (
        max_descendant_claims IS NULL OR
        (typeof(max_descendant_claims) = 'integer' AND max_descendant_claims >= 0)
    ),
    max_dispatch_attempts INTEGER CHECK (
        max_dispatch_attempts IS NULL OR
        (typeof(max_dispatch_attempts) = 'integer' AND max_dispatch_attempts >= 0)
    ),
    max_descendant_dispatch_attempts INTEGER CHECK (
        max_descendant_dispatch_attempts IS NULL OR
        (typeof(max_descendant_dispatch_attempts) = 'integer' AND max_descendant_dispatch_attempts >= 0)
    ),
    version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS task_dependencies (
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    depends_on_task_id TEXT NOT NULL REFERENCES tasks(id),
    PRIMARY KEY (task_id, depends_on_task_id),
    CHECK(task_id <> depends_on_task_id)
);

CREATE TABLE IF NOT EXISTS resource_leases (
    resource TEXT PRIMARY KEY,
    task_id TEXT REFERENCES tasks(id),
    holder_agent_id TEXT REFERENCES agents(id),
    fencing_token INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_heartbeats (
    agent_id TEXT NOT NULL REFERENCES agents(id),
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    claim_fencing_token INTEGER NOT NULL,
    checkpoint_json TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (agent_id, task_id)
);

CREATE TABLE IF NOT EXISTS submissions (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id),
    worker_agent_id TEXT NOT NULL REFERENCES agents(id),
    task_version INTEGER NOT NULL,
    claim_fencing_token INTEGER NOT NULL,
    resource_fencing_tokens_json TEXT NOT NULL DEFAULT '{}',
    base_revision TEXT NOT NULL,
    artifact_uri TEXT NOT NULL,
    artifact_hash TEXT NOT NULL,
    summary TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN (
        'pending_qc', 'approved', 'changes_requested', 'blocked', 'human_required'
    )),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reviews (
    id TEXT PRIMARY KEY,
    submission_id TEXT NOT NULL REFERENCES submissions(id),
    qc_agent_id TEXT NOT NULL REFERENCES agents(id),
    verdict TEXT NOT NULL CHECK(verdict IN ('pass', 'revise', 'block', 'human_required')),
    summary TEXT NOT NULL,
    findings_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_mandates_agent ON mandates(agent_id);
CREATE INDEX IF NOT EXISTS idx_mandates_parent ON mandates(parent_mandate_id);
CREATE INDEX IF NOT EXISTS idx_policies_agent ON policies(agent_id);
CREATE INDEX IF NOT EXISTS idx_actions_status ON action_requests(status);
CREATE INDEX IF NOT EXISTS idx_tasks_status_priority ON tasks(status, priority DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_owner ON tasks(owner_agent_id);
CREATE INDEX IF NOT EXISTS idx_submissions_task ON submissions(task_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reviews_submission ON reviews(submission_id, created_at DESC);
"""


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def event_digest(
    previous_hash: str,
    event_id: str,
    event_type: str,
    actor: str,
    payload_json: str,
    created_at: str,
) -> str:
    material = canonical_json(
        {
            "actor": actor,
            "created_at": created_at,
            "event_id": event_id,
            "event_type": event_type,
            "payload": json.loads(payload_json),
            "previous_hash": previous_hash,
        }
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _append_audit_event(
    connection: sqlite3.Connection,
    event_type: str,
    actor: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Append one event to the hash chain inside the caller's transaction."""
    if not connection.in_transaction:
        raise ValueError("audit connection must already hold a transaction")
    event_id = str(uuid.uuid4())
    created_at = utc_now()
    payload_json = canonical_json(payload)
    previous = connection.execute(
        "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    previous_hash = previous["event_hash"] if previous else GENESIS_HASH
    digest = event_digest(previous_hash, event_id, event_type, actor, payload_json, created_at)
    cursor = connection.execute(
        """
        INSERT INTO audit_events
            (event_id, event_type, actor, payload_json, previous_hash, event_hash, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (event_id, event_type, actor, payload_json, previous_hash, digest, created_at),
    )
    return {
        "sequence": cursor.lastrowid,
        "event_id": event_id,
        "event_type": event_type,
        "actor": actor,
        "payload": payload,
        "previous_hash": previous_hash,
        "event_hash": digest,
        "created_at": created_at,
    }


class Database:
    def __init__(self, path: str):
        self.path = path

    def initialize(self) -> None:
        if self.path != ":memory:":
            Path(self.path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            # Read the stamp before the first CREATE or ALTER. Checking afterwards
            # would be checking a database this binary had already written to.
            stored = stored_schema_version(connection)
            assert_schema_not_newer(
                stored,
                binary_version=SERVICE_SCHEMA_VERSION,
                component="service database",
                package_version=__version__,
            )
            if self.path != ":memory:":
                # Validate the schema before changing the file's journal mode.
                # WAL lets readers continue while another connection holds a claim.
                _enable_service_wal_mode(connection)
            # Serialize all schema work. Re-read only after obtaining the write lock:
            # another process may have completed this migration after our first read.
            # This explicit transaction also makes the ledger stamp atomic with its
            # ALTER/trigger statements; executescript() would implicitly COMMIT it.
            connection.execute("BEGIN IMMEDIATE")
            stored = stored_schema_version(connection)
            assert_schema_not_newer(
                stored,
                binary_version=SERVICE_SCHEMA_VERSION,
                component="service database",
                package_version=__version__,
            )
            connection.execute(META_TABLE)
            _execute_script_in_transaction(connection, SCHEMA)
            columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(agents)").fetchall()
            }
            if "role" not in columns:
                connection.execute(
                    "ALTER TABLE agents ADD COLUMN role TEXT NOT NULL DEFAULT 'worker'"
                )
            submission_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(submissions)").fetchall()
            }
            if "resource_fencing_tokens_json" not in submission_columns:
                connection.execute(
                    """
                    ALTER TABLE submissions
                    ADD COLUMN resource_fencing_tokens_json TEXT NOT NULL DEFAULT '{}'
                    """
                )
            apply_migration_ledger(connection, stored, MIGRATIONS)
            stamp_schema_version(
                connection,
                version=SERVICE_SCHEMA_VERSION,
                package_version=__version__,
            )

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=_SERVICE_DB_BUSY_TIMEOUT_MS / 1000)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def one(self, query: str, parameters: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute(query, parameters).fetchone()

    def all(self, query: str, parameters: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return list(connection.execute(query, parameters).fetchall())

    def execute(self, query: str, parameters: tuple[Any, ...] = ()) -> None:
        with self.connect() as connection:
            connection.execute(query, parameters)

    def execute_count(self, query: str, parameters: tuple[Any, ...] = ()) -> int:
        with self.connect() as connection:
            cursor = connection.execute(query, parameters)
            return cursor.rowcount

    def append_audit(
        self,
        event_type: str,
        actor: str,
        payload: dict[str, Any],
        *,
        connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        """Append to the audit chain, optionally inside the caller's transaction.

        A supplied connection must already hold a transaction. Its caller owns
        commit and rollback, so domain state and its audit event cannot separate.
        Existing callers still get the original self-contained transaction.
        """
        if connection is not None and not connection.in_transaction:
            raise ValueError("audit connection must already hold a transaction")
        context = self.connect() if connection is None else nullcontext(connection)
        with context as audit_connection:
            if connection is None:
                audit_connection.execute("BEGIN IMMEDIATE")
            return _append_audit_event(audit_connection, event_type, actor, payload)

    def audit_events(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.all("SELECT * FROM audit_events ORDER BY sequence DESC LIMIT ?", (limit,))
        return [
            {
                "sequence": row["sequence"],
                "event_id": row["event_id"],
                "event_type": row["event_type"],
                "actor": row["actor"],
                "payload": json.loads(row["payload_json"]),
                "previous_hash": row["previous_hash"],
                "event_hash": row["event_hash"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def verify_audit_chain(self) -> tuple[bool, int, int | None]:
        rows = self.all("SELECT * FROM audit_events ORDER BY sequence ASC")
        expected_previous = GENESIS_HASH
        for row in rows:
            expected_hash = event_digest(
                expected_previous,
                row["event_id"],
                row["event_type"],
                row["actor"],
                row["payload_json"],
                row["created_at"],
            )
            if row["previous_hash"] != expected_previous or row["event_hash"] != expected_hash:
                return False, len(rows), row["sequence"]
            expected_previous = row["event_hash"]
        return True, len(rows), None
