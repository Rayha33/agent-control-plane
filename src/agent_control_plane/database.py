from __future__ import annotations

import hashlib
import json
import sqlite3
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

POSTGRES_URL_PREFIXES = ("postgresql://", "postgres://")


def is_postgres_url(value: str) -> bool:
    """A ``postgresql://`` URL selects the multi-host backend; anything else is a SQLite path."""

    return value.startswith(POSTGRES_URL_PREFIXES)


class StorageBusyError(RuntimeError):
    """The backend could not serialise this request, so nothing was applied; retry it whole.

    Raised by the PostgreSQL backend for serialization failures, deadlocks, lock timeouts and
    lost sessions. The transaction rolled back, and every mutation re-validates its fencing
    tokens when retried, so a retry cannot apply a stale request.
    """

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


SERVICE_SCHEMA_VERSION = 1
"""Schema this binary understands for the FastAPI service database.

Independent of the supervisor's SCHEMA_VERSION on purpose: these are two files with
two lifecycles — the service database is created by `create_app`, the control database
by `acp init` — and coupling their numbers would force a version bump on one whenever
the other changed.
"""

# Numbered upgrades from SERVICE_SCHEMA_VERSION - 1 to SERVICE_SCHEMA_VERSION. Version 1
# is the baseline: the CREATE TABLE IF NOT EXISTS script plus the column adds that
# predate stamping. Anything after 1 goes here, including changes ALTER TABLE ADD COLUMN
# cannot express.
MIGRATIONS: tuple[Migration, ...] = ()

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


class Database:
    def __init__(self, path: str):
        self.path = path
        self._backend: Any = None
        if is_postgres_url(path):
            from .postgres_backend import PostgresBackend

            self._backend = PostgresBackend(path)

    @property
    def dialect(self) -> str:
        return "sqlite" if self._backend is None else self._backend.dialect

    def describe(self) -> str:
        """Where the state lives, with any password removed."""

        return self.path if self._backend is None else self._backend.describe()

    def initialize(self) -> None:
        if self._backend is not None:
            self._initialize_postgres()
            return
        if self.path != ":memory:":
            Path(self.path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            # Read the stamp before the first CREATE or ALTER. Checking afterwards
            # would be checking a database this binary had already written to.
            connection.executescript(META_TABLE)
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
                connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(SCHEMA)
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

    def _initialize_postgres(self) -> None:
        # Replicas that start together must not interleave CREATE TABLE IF NOT EXISTS, so
        # initialisation runs under the same write lock that serialises claims.
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.executescript(META_TABLE)
            stored = stored_schema_version(connection)
            assert_schema_not_newer(
                stored,
                binary_version=SERVICE_SCHEMA_VERSION,
                component="service database",
                package_version=__version__,
            )
            # A PostgreSQL database is always created from the current SCHEMA, so the
            # pre-stamping ALTER TABLE upgrades in initialize() are SQLite history it never had.
            connection.executescript(SCHEMA)
            apply_migration_ledger(connection, stored, MIGRATIONS)
            stamp_schema_version(
                connection,
                version=SERVICE_SCHEMA_VERSION,
                package_version=__version__,
            )

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        if self._backend is not None:
            # Same contract as below: commit on success, roll back on any exception.
            with self._backend.connect() as backend_connection:
                yield backend_connection
            return
        connection = sqlite3.connect(self.path, timeout=10)
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
        event_id = str(uuid.uuid4())
        created_at = utc_now()
        payload_json = canonical_json(payload)

        context = self.connect() if connection is None else nullcontext(connection)
        with context as audit_connection:
            if connection is None:
                audit_connection.execute("BEGIN IMMEDIATE")
            previous = audit_connection.execute(
                "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_hash = previous["event_hash"] if previous else GENESIS_HASH
            digest = event_digest(
                previous_hash,
                event_id,
                event_type,
                actor,
                payload_json,
                created_at,
            )
            insert = """
                INSERT INTO audit_events
                    (event_id, event_type, actor, payload_json, previous_hash, event_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """
            values = (
                event_id,
                event_type,
                actor,
                payload_json,
                previous_hash,
                digest,
                created_at,
            )
            if getattr(audit_connection, "dialect", "sqlite") == "sqlite":
                sequence = audit_connection.execute(insert, values).lastrowid
            else:
                # PostgreSQL has no lastrowid; the identity column hands the value back.
                sequence = audit_connection.execute(
                    insert + " RETURNING sequence", values
                ).fetchone()[0]

        return {
            "sequence": sequence,
            "event_id": event_id,
            "event_type": event_type,
            "actor": actor,
            "payload": payload,
            "previous_hash": previous_hash,
            "event_hash": digest,
            "created_at": created_at,
        }

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
