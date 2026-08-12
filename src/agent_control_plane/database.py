from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


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

    def initialize(self) -> None:
        if self.path != ":memory:":
            Path(self.path).expanduser().resolve().parent.mkdir(
                parents=True, exist_ok=True
            )
        with self.connect() as connection:
            connection.executescript(SCHEMA)
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(agents)").fetchall()
            }
            if "role" not in columns:
                connection.execute(
                    "ALTER TABLE agents ADD COLUMN role TEXT NOT NULL DEFAULT 'worker'"
                )

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
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
        self, event_type: str, actor: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        event_id = str(uuid.uuid4())
        created_at = utc_now()
        payload_json = canonical_json(payload)

        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
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
            cursor = connection.execute(
                """
                INSERT INTO audit_events
                    (event_id, event_type, actor, payload_json, previous_hash, event_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    event_type,
                    actor,
                    payload_json,
                    previous_hash,
                    digest,
                    created_at,
                ),
            )
            sequence = cursor.lastrowid

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
        rows = self.all(
            "SELECT * FROM audit_events ORDER BY sequence DESC LIMIT ?", (limit,)
        )
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
            if (
                row["previous_hash"] != expected_previous
                or row["event_hash"] != expected_hash
            ):
                return False, len(rows), row["sequence"]
            expected_previous = row["event_hash"]
        return True, len(rows), None
