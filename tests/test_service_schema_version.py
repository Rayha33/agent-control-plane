"""The FastAPI service database records its version and refuses a newer one.

#1629 gave the supervisor's `.acp/control.db` a version stamp and a forward refusal.
`database.py` had its own separate `PRAGMA table_info` + `ALTER TABLE` pass against a
different file and none of that protection, so an older service binary still opened a
newer service database without noticing — `CREATE TABLE IF NOT EXISTS` leaves newer
tables alone and each column check finds its column already there, so the open succeeds
and the newer columns are simply invisible.

The two databases version INDEPENDENTLY. They share the mechanism, not the number.
"""

from __future__ import annotations

import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from agent_control_plane import __version__
from agent_control_plane.database import (
    SERVICE_SCHEMA_VERSION,
    Database,
    _enable_service_wal_mode,
)
from agent_control_plane.git_supervisor import SCHEMA_VERSION as CONTROL_SCHEMA_VERSION
from agent_control_plane.schema_version import (
    SCHEMA_VERSION_KEY,
    SCHEMA_WRITTEN_BY_KEY,
    SchemaVersionError,
)


@pytest.fixture
def database_path(tmp_path: Path) -> Path:
    path = tmp_path / "service.db"
    Database(str(path)).initialize()
    return path


def meta(path: Path) -> dict[str, str]:
    connection = sqlite3.connect(path)
    try:
        return dict(connection.execute("SELECT key, value FROM meta").fetchall())
    finally:
        connection.close()


def write_meta(path: Path, key: str, value: str) -> None:
    connection = sqlite3.connect(path)
    connection.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (key, value))
    connection.commit()
    connection.close()


def create_v1_service_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO meta(key, value) VALUES ('schema_version', '1');
        CREATE TABLE agents (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            owner TEXT NOT NULL,
            parent_agent_id TEXT,
            role TEXT NOT NULL DEFAULT 'worker',
            disabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE mandates (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            subject TEXT NOT NULL,
            parent_mandate_id TEXT,
            scopes_json TEXT NOT NULL,
            max_amount_cents INTEGER,
            expires_at INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        INSERT INTO agents(id, name, owner, created_at)
        VALUES ('legacy-agent', 'legacy', 'owner', '2026-01-01T00:00:00+00:00');
        INSERT INTO mandates(
            id, agent_id, subject, scopes_json, max_amount_cents, expires_at, created_at
        ) VALUES (
            'legacy-mandate', 'legacy-agent', 'owner', '[]', 2500, 4102444800,
            '2026-01-01T00:00:00+00:00'
        );
        """
    )
    connection.commit()
    connection.close()


def create_v3_service_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO meta(key, value) VALUES ('schema_version', '3');
        CREATE TABLE tasks (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            acceptance_criteria_json TEXT NOT NULL,
            resources_json TEXT NOT NULL,
            priority INTEGER NOT NULL DEFAULT 50,
            status TEXT NOT NULL DEFAULT 'open',
            owner_agent_id TEXT,
            claim_expires_at INTEGER,
            claim_fencing_token INTEGER NOT NULL DEFAULT 0,
            version INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        INSERT INTO tasks(
            id, title, description, acceptance_criteria_json, resources_json,
            created_at, updated_at
        ) VALUES (
            'legacy-task', 'Legacy task', 'Existing v3 work', '[]', '[]', 'now', 'now'
        );
        """
    )
    connection.commit()
    connection.close()


def test_initialize_stamps_the_version_and_the_writer(database_path: Path) -> None:
    recorded = meta(database_path)
    assert recorded[SCHEMA_VERSION_KEY] == str(SERVICE_SCHEMA_VERSION)
    assert recorded[SCHEMA_WRITTEN_BY_KEY] == __version__


def test_v5_service_database_adds_the_report_only_usage_receipt_column(
    database_path: Path,
) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.execute("DROP TRIGGER service_schema_version_no_downgrade")
        connection.execute("ALTER TABLE dispatch_attempt_receipts DROP COLUMN provider_usage_json")
        connection.execute("UPDATE meta SET value = '5' WHERE key = ?", (SCHEMA_VERSION_KEY,))
        connection.execute(
            """
            CREATE TRIGGER service_schema_version_no_downgrade
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

    Database(str(database_path)).initialize()

    with sqlite3.connect(database_path) as connection:
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(dispatch_attempt_receipts)")
        }
        version = connection.execute(
            "SELECT value FROM meta WHERE key = ?", (SCHEMA_VERSION_KEY,)
        ).fetchone()[0]
        usage_default = next(
            row[4]
            for row in connection.execute("PRAGMA table_info(dispatch_attempt_receipts)")
            if row[1] == "provider_usage_json"
        )

    assert "provider_usage_json" in columns
    assert usage_default == "'{}'"
    assert version == str(SERVICE_SCHEMA_VERSION)


def test_a_database_from_the_future_is_refused(database_path: Path) -> None:
    write_meta(database_path, SCHEMA_VERSION_KEY, str(SERVICE_SCHEMA_VERSION + 1))

    with pytest.raises(SchemaVersionError) as error:
        Database(str(database_path)).initialize()

    assert error.value.code == "schema_newer_than_binary"
    assert "service database" in str(error.value)


def test_the_refusal_names_the_service_database_not_the_control_one(
    database_path: Path,
) -> None:
    """Two databases, two messages. An operator has to know which file to look at."""

    write_meta(database_path, SCHEMA_VERSION_KEY, "99")
    with pytest.raises(SchemaVersionError) as error:
        Database(str(database_path)).initialize()
    assert "control database" not in str(error.value)


def test_an_unstamped_database_is_upgraded_and_stamped(database_path: Path) -> None:
    connection = sqlite3.connect(database_path)
    connection.execute("DELETE FROM meta WHERE key = ?", (SCHEMA_VERSION_KEY,))
    connection.commit()
    connection.close()

    Database(str(database_path)).initialize()

    assert meta(database_path)[SCHEMA_VERSION_KEY] == str(SERVICE_SCHEMA_VERSION)


def test_v1_service_database_gets_the_nullable_mandate_descendant_cap(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "service-v1.db"
    create_v1_service_database(database_path)

    Database(str(database_path)).initialize()

    connection = sqlite3.connect(database_path)
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(mandates)")}
        mandate = connection.execute(
            "SELECT max_amount_cents, max_descendant_mandates "
            "FROM mandates WHERE id = 'legacy-mandate'"
        ).fetchone()
        recorded_version = connection.execute(
            "SELECT value FROM meta WHERE key = ?", (SCHEMA_VERSION_KEY,)
        ).fetchone()[0]
    finally:
        connection.close()

    assert "max_descendant_mandates" in columns
    assert mandate == (2500, None)
    assert recorded_version == str(SERVICE_SCHEMA_VERSION)


def test_v2_service_database_installs_the_rolling_upgrade_guard(
    database_path: Path,
) -> None:
    connection = sqlite3.connect(database_path)
    connection.execute("DROP TRIGGER mandate_fanout_guard")
    connection.execute("DROP TRIGGER service_schema_version_no_downgrade")
    connection.execute("UPDATE meta SET value = '2' WHERE key = ?", (SCHEMA_VERSION_KEY,))
    connection.commit()
    connection.close()

    Database(str(database_path)).initialize()

    assert meta(database_path)[SCHEMA_VERSION_KEY] == str(SERVICE_SCHEMA_VERSION)
    with sqlite3.connect(database_path) as connection:
        trigger_count = connection.execute(
            "SELECT COUNT(*) FROM sqlite_master "
            "WHERE type = 'trigger' AND name IN "
            "('mandate_fanout_guard', 'service_schema_version_no_downgrade')"
        ).fetchone()[0]
    assert trigger_count == 2


def test_v3_service_database_adds_nullable_task_claim_budgets_and_legacy_guard(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "service-v3.db"
    create_v3_service_database(database_path)

    Database(str(database_path)).initialize()

    with sqlite3.connect(database_path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(tasks)")}
        legacy = connection.execute(
            "SELECT parent_task_id, max_claims, max_descendant_claims "
            "FROM tasks WHERE id = 'legacy-task'"
        ).fetchone()
        triggers = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")
        }
        indexes = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
        }

    assert {
        "parent_task_id",
        "max_claims",
        "max_descendant_claims",
        "max_dispatch_attempts",
        "max_descendant_dispatch_attempts",
        "max_unreceipted_dispatch_attempts",
        "max_descendant_unreceipted_dispatch_attempts",
    } <= columns
    reservation_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(dispatch_attempt_reservations)")
    }
    assert "resource_fencing_tokens_json" in reservation_columns
    assert legacy == (None, None, None)
    assert {
        "task_claim_budget_guard",
        "task_claim_budget_config_immutable",
        "task_claim_budget_insert_guard",
        "task_dispatch_budget_config_immutable",
        "task_dispatch_budget_insert_guard",
        "task_dispatch_outstanding_config_immutable",
        "task_dispatch_outstanding_insert_guard",
        "dispatch_attempt_insert_guard",
        "dispatch_attempt_outstanding_budget_guard",
        "dispatch_attempt_reservation_immutable",
        "dispatch_attempt_receipt_immutable",
    } <= triggers
    assert "idx_tasks_parent_task" in indexes
    assert "idx_dispatch_attempt_reservations_task" in indexes
    assert meta(database_path)[SCHEMA_VERSION_KEY] == str(SERVICE_SCHEMA_VERSION)


def test_v6_service_database_migrates_to_outstanding_dispatch_reservations(
    database_path: Path,
) -> None:
    with sqlite3.connect(database_path) as connection:
        for trigger in (
            "task_dispatch_outstanding_config_immutable",
            "task_dispatch_outstanding_insert_guard",
            "dispatch_attempt_outstanding_budget_guard",
        ):
            connection.execute(f"DROP TRIGGER {trigger}")
        connection.execute("ALTER TABLE tasks DROP COLUMN max_unreceipted_dispatch_attempts")
        connection.execute(
            "ALTER TABLE tasks DROP COLUMN max_descendant_unreceipted_dispatch_attempts"
        )
        connection.execute("UPDATE meta SET value = '6' WHERE key = ?", (SCHEMA_VERSION_KEY,))

    Database(str(database_path)).initialize()

    with sqlite3.connect(database_path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(tasks)")}
        triggers = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")
        }
        version = connection.execute(
            "SELECT value FROM meta WHERE key = ?", (SCHEMA_VERSION_KEY,)
        ).fetchone()[0]
    assert "max_unreceipted_dispatch_attempts" in columns
    assert "max_descendant_unreceipted_dispatch_attempts" in columns
    assert "dispatch_attempt_outstanding_budget_guard" in triggers
    assert version == str(SERVICE_SCHEMA_VERSION)


def test_v7_service_database_migrates_append_only_interruption_reports(
    database_path: Path,
) -> None:
    with sqlite3.connect(database_path) as connection:
        for trigger in (
            "budget_interruption_report_immutable_update",
            "budget_interruption_report_immutable_delete",
        ):
            connection.execute(f"DROP TRIGGER {trigger}")
        connection.execute("DROP TABLE budget_interruption_reports")
        connection.execute("UPDATE meta SET value = '7' WHERE key = ?", (SCHEMA_VERSION_KEY,))

    Database(str(database_path)).initialize()

    with sqlite3.connect(database_path) as connection:
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(budget_interruption_reports)")
        }
        triggers = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")
        }
        version = connection.execute(
            "SELECT value FROM meta WHERE key = ?", (SCHEMA_VERSION_KEY,)
        ).fetchone()[0]
    assert {
        "task_id",
        "agent_id",
        "claim_fencing_token",
        "status",
        "source",
        "checkpoint_json",
        "checkpoint_sha256",
        "dispatch_attempt_ids_json",
        "received_at",
    } <= columns
    assert {
        "budget_interruption_report_immutable_update",
        "budget_interruption_report_immutable_delete",
    } <= triggers
    assert version == str(SERVICE_SCHEMA_VERSION)


def test_v9_service_database_quarantines_legacy_reclaims_but_keeps_audited_reopen(
    database_path: Path,
) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.execute("DROP TRIGGER IF EXISTS budget_interruption_task_resume_guard")
        connection.execute("UPDATE meta SET value = '9' WHERE key = ?", (SCHEMA_VERSION_KEY,))

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "INSERT INTO agents(id, name, owner, role, created_at) "
            "VALUES ('legacy-worker', 'legacy worker', 'owner', 'worker', 'now')"
        )

        def add_interrupted_task(task_id: str, *, status: str, owner: str | None) -> None:
            connection.execute(
                """
                INSERT INTO tasks(
                    id, title, description, acceptance_criteria_json, resources_json,
                    status, owner_agent_id, claim_expires_at, claim_fencing_token,
                    created_at, updated_at
                ) VALUES (?, 'task', 'description', '[]', '[]', 'open', NULL, NULL, 0,
                          'now', 'now')
                """,
                (task_id,),
            )
            connection.execute(
                """
                UPDATE tasks
                SET status = ?, owner_agent_id = ?, claim_expires_at = 0,
                    claim_fencing_token = 1
                WHERE id = ?
                """,
                (status, owner, task_id),
            )
            connection.execute(
                """
                INSERT INTO budget_interruption_reports(
                    id, task_id, agent_id, claim_fencing_token,
                    resource_fencing_tokens_json, status, source, reason, summary,
                    checkpoint_json, checkpoint_sha256, dispatch_attempt_ids_json,
                    received_at
                ) VALUES (?, ?, 'legacy-worker', 1, '{}', 'partial', 'client_reported',
                          'provider_quota_exhausted', 'interrupted', '{}', ?, '[]', 'now')
                """,
                (f"report-{task_id}", task_id, "0" * 64),
            )

        add_interrupted_task("resumed-claimed", status="claimed", owner="legacy-worker")
        add_interrupted_task("resumed-orphaned", status="claimed", owner="legacy-worker")
        add_interrupted_task("audited-reopen", status="claimed", owner="legacy-worker")

        for task_id in ("resumed-claimed", "resumed-orphaned", "audited-reopen"):
            connection.execute(
                "INSERT INTO resource_leases(resource, task_id, holder_agent_id, fencing_token, "
                "expires_at, updated_at) VALUES (?, ?, 'legacy-worker', 3, 4102444800, 'now')",
                (f"resource-{task_id}", task_id),
            )
            connection.execute(
                "INSERT INTO agent_heartbeats(agent_id, task_id, claim_fencing_token, "
                "checkpoint_json, expires_at, updated_at) VALUES "
                "('legacy-worker', ?, 1, '{}', 4102444800, 'now')",
                (task_id,),
            )

    database = Database(str(database_path))
    for task_id in ("resumed-claimed", "resumed-orphaned", "audited-reopen"):
        database.append_audit(
            "task.interruption_reported",
            "legacy-worker",
            {
                "claim_fencing_token": 1,
                "report_id": f"report-{task_id}",
                "task_id": task_id,
            },
        )
    database.append_audit(
        "task.reopened",
        "admin",
        {"previous_status": "blocked", "reason": "audited recovery", "task_id": "audited-reopen"},
    )

    with sqlite3.connect(database_path) as connection:
        # Reproduce v9's reaper -> orphaned -> automatic claim path. The old
        # implementation had no status guard, so the old worker advances to fence 2.
        for task_id in ("resumed-claimed", "resumed-orphaned"):
            connection.execute(
                "UPDATE tasks SET status = 'orphaned', owner_agent_id = NULL, "
                "claim_expires_at = NULL WHERE id = ?",
                (task_id,),
            )
            connection.execute(
                "UPDATE tasks SET status = 'claimed', owner_agent_id = 'legacy-worker', "
                "claim_expires_at = 4102444800, claim_fencing_token = 2 WHERE id = ?",
                (task_id,),
            )
        connection.execute(
            "UPDATE tasks SET status = 'orphaned', owner_agent_id = NULL, "
            "claim_expires_at = NULL WHERE id = 'resumed-orphaned'"
        )
        # The required operator action is audited before the fresh claim.
        connection.execute("UPDATE tasks SET status = 'open' WHERE id = 'audited-reopen'")
        connection.execute(
            "UPDATE tasks SET status = 'claimed', owner_agent_id = 'legacy-worker', "
            "claim_expires_at = 4102444800, claim_fencing_token = 2 "
            "WHERE id = 'audited-reopen'"
        )

    Database(str(database_path)).initialize()

    with sqlite3.connect(database_path) as connection:
        rows = {
            row[0]: row[1:]
            for row in connection.execute(
                "SELECT id, status, owner_agent_id, claim_expires_at, claim_fencing_token "
                "FROM tasks WHERE id IN ('resumed-claimed', 'resumed-orphaned', 'audited-reopen')"
            )
        }
        interrupted_leases = connection.execute(
            "SELECT COUNT(*) FROM resource_leases WHERE task_id IN "
            "('resumed-claimed', 'resumed-orphaned') AND expires_at > 0"
        ).fetchone()[0]
        interrupted_heartbeats = connection.execute(
            "SELECT COUNT(*) FROM agent_heartbeats WHERE task_id IN "
            "('resumed-claimed', 'resumed-orphaned')"
        ).fetchone()[0]
        audited_reopen_lease_count = connection.execute(
            "SELECT COUNT(*) FROM resource_leases WHERE task_id = 'audited-reopen' "
            "AND holder_agent_id = 'legacy-worker' AND expires_at = 4102444800"
        ).fetchone()[0]
        audited_reopen_heartbeat_count = connection.execute(
            "SELECT COUNT(*) FROM agent_heartbeats WHERE task_id = 'audited-reopen'"
        ).fetchone()[0]
        triggers = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")
        }
        version = connection.execute(
            "SELECT value FROM meta WHERE key = ?", (SCHEMA_VERSION_KEY,)
        ).fetchone()[0]

    assert "budget_interruption_task_resume_guard" in triggers
    assert rows["resumed-claimed"] == ("blocked", None, None, 2)
    assert rows["resumed-orphaned"] == ("blocked", None, None, 2)
    assert rows["audited-reopen"] == ("claimed", "legacy-worker", 4102444800, 2)
    assert interrupted_leases == 0
    assert interrupted_heartbeats == 0
    assert audited_reopen_lease_count == 1
    assert audited_reopen_heartbeat_count == 1
    assert version == str(SERVICE_SCHEMA_VERSION)
    assert Database(str(database_path)).verify_audit_chain() == (True, 6, None)

    with sqlite3.connect(database_path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="task_interruption_requires_reopen"):
            connection.execute("UPDATE tasks SET status = 'claimed' WHERE id = 'resumed-claimed'")


def test_v11_migration_quarantines_interrupted_work_past_submit_and_qc(
    database_path: Path,
) -> None:
    task_states = {
        "stale-claimed": "claimed",
        "stale-working": "working",
        "stale-qc-review": "qc_review",
        "stale-approved": "approved",
        "stale-merging": "merging",
        "stale-done": "done",
        "missing-report-event": "working",
        "mismatched-report-event": "working",
        "reopened-without-report-event": "open",
        "legacy-reopen-compat": "blocked",
    }
    with sqlite3.connect(database_path) as connection:
        connection.execute("UPDATE meta SET value = '11' WHERE key = ?", (SCHEMA_VERSION_KEY,))
        connection.execute(
            "INSERT INTO agents(id, name, owner, role, created_at) "
            "VALUES ('legacy-worker', 'legacy worker', 'owner', 'worker', 'now')"
        )
        for task_id, status in task_states.items():
            connection.execute(
                """
                INSERT INTO tasks(
                    id, title, description, acceptance_criteria_json, resources_json,
                    status, owner_agent_id, claim_expires_at, claim_fencing_token,
                    version, created_at, updated_at
                ) VALUES (?, 'task', 'legacy lifecycle state', '[]', '[]',
                          'open', NULL, NULL, 0, 1, 'now', 'before')
                """,
                (task_id,),
            )
            connection.execute(
                "UPDATE tasks SET status = 'claimed', owner_agent_id = 'legacy-worker', "
                "claim_expires_at = 4102444800, claim_fencing_token = 1 WHERE id = ?",
                (task_id,),
            )
            connection.execute(
                "UPDATE tasks SET claim_fencing_token = 2, version = 7 WHERE id = ?",
                (task_id,),
            )
            if status != "claimed":
                connection.execute(
                    "UPDATE tasks SET status = ?, owner_agent_id = NULL, "
                    "claim_expires_at = NULL WHERE id = ?",
                    (status, task_id),
                )
            connection.execute(
                """
                INSERT INTO resource_leases(
                    resource, task_id, holder_agent_id, fencing_token, expires_at, updated_at
                ) VALUES (?, ?, 'legacy-worker', 4, 4102444800, 'before')
                """,
                (f"resource-{task_id}", task_id),
            )
            connection.execute(
                """
                INSERT INTO agent_heartbeats(
                    agent_id, task_id, claim_fencing_token, checkpoint_json, expires_at, updated_at
                ) VALUES ('legacy-worker', ?, 2, '{}', 4102444800, 'before')
                """,
                (task_id,),
            )

        # This is a higher-fence submission committed by the old writer before
        # the migration obtains SQLite's write lock. The stale report arrives
        # afterward, leaving the row in qc_review on a v11 database.
        connection.execute(
            """
            INSERT INTO submissions(
                id, task_id, worker_agent_id, task_version, claim_fencing_token,
                resource_fencing_tokens_json, base_revision, artifact_uri,
                artifact_hash, summary, evidence_json, status, created_at
            ) VALUES ('old-submit', 'stale-qc-review', 'legacy-worker', 7, 2, '{}',
                      'main@old', 'patch://old', ?, 'committed before upgrade', '[]',
                      'pending_qc', 'before')
            """,
            ("a" * 64,),
        )
        for task_id in task_states:
            connection.execute(
                """
                INSERT INTO budget_interruption_reports(
                    id, task_id, agent_id, claim_fencing_token,
                    resource_fencing_tokens_json, status, source, reason, summary,
                    checkpoint_json, checkpoint_sha256, dispatch_attempt_ids_json, received_at
                ) VALUES (?, ?, 'legacy-worker', 1, '{}', 'partial', 'client_reported',
                          'provider_quota_exhausted', 'interrupted', '{}', ?, '[]', 'now')
                """,
                (f"report-{task_id}", task_id, "0" * 64),
            )

    database = Database(str(database_path))
    for task_id in task_states:
        if task_id in {"missing-report-event", "reopened-without-report-event"}:
            continue
        report_id = (
            f"wrong-report-{task_id}"
            if task_id == "mismatched-report-event"
            else f"report-{task_id}"
        )
        database.append_audit(
            "task.interruption_reported",
            "legacy-worker",
            {
                "claim_fencing_token": 1,
                "report_id": report_id,
                "task_id": task_id,
            },
        )
    database.append_audit(
        "task.reopened",
        "admin",
        {
            "previous_status": "blocked",
            "reason": "legacy reopen without report provenance",
            "task_id": "reopened-without-report-event",
        },
    )

    database.initialize()

    with sqlite3.connect(database_path) as connection:
        rows = {
            row[0]: row[1:]
            for row in connection.execute(
                "SELECT id, status, owner_agent_id, claim_expires_at, "
                "claim_fencing_token, version, updated_at FROM tasks"
            )
            if row[0] in task_states
        }
        active_leases = connection.execute(
            "SELECT COUNT(*) FROM resource_leases WHERE task_id IS NOT NULL"
        ).fetchone()[0]
        heartbeats = connection.execute(
            "SELECT COUNT(*) FROM agent_heartbeats WHERE task_id IN "
            "('stale-claimed', 'stale-working', 'stale-qc-review', 'stale-approved', "
            "'stale-merging', 'stale-done', 'missing-report-event', "
            "'mismatched-report-event', 'reopened-without-report-event', "
            "'legacy-reopen-compat')"
        ).fetchone()[0]
        schema_version = connection.execute(
            "SELECT value FROM meta WHERE key = ?", (SCHEMA_VERSION_KEY,)
        ).fetchone()[0]

        assert set(rows) == set(task_states)
        for task_id, row in rows.items():
            expected_version = 7 if task_id == "legacy-reopen-compat" else 8
            assert row[:5] == ("blocked", None, None, 2, expected_version), task_id
            if task_id != "legacy-reopen-compat":
                assert row[5] != "before", task_id
        assert active_leases == 0
        assert heartbeats == 0
        assert schema_version == str(SERVICE_SCHEMA_VERSION)

        with pytest.raises(sqlite3.IntegrityError, match="task_interruption_requires_reopen"):
            connection.execute("UPDATE tasks SET status = 'approved' WHERE id = 'stale-qc-review'")
        with pytest.raises(sqlite3.IntegrityError, match="task_interruption_requires_reopen"):
            connection.execute(
                "UPDATE tasks SET status = 'done' WHERE id = 'reopened-without-report-event'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="claim_interrupted"):
            connection.execute(
                """
                INSERT INTO submissions(
                    id, task_id, worker_agent_id, task_version, claim_fencing_token,
                    resource_fencing_tokens_json, base_revision, artifact_uri,
                    artifact_hash, summary, evidence_json, status, created_at
                ) VALUES ('new-submit', 'stale-qc-review', 'legacy-worker', 8, 2, '{}',
                          'main@new', 'patch://new', ?, 'must stay parked', '[]',
                          'pending_qc', 'after')
                """,
                ("b" * 64,),
            )

    database = Database(str(database_path))
    migration_events = [
        event
        for event in database.audit_events()
        if event["event_type"] == "task.interruption_migration_parked"
    ]
    assert len(migration_events) == len(task_states)

    # An older service writes task.reopened after its blocked->open update. The
    # intermediate open row remains unresolved and cannot advance before the
    # admin event is appended in the same transaction.
    with database.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("UPDATE tasks SET status = 'open' WHERE id = 'legacy-reopen-compat'")
        unresolved_count = connection.execute(
            "SELECT COUNT(*) FROM budget_unresolved_interruption_reports "
            "WHERE task_id = 'legacy-reopen-compat'"
        ).fetchone()[0]
        assert unresolved_count == 1
        with pytest.raises(sqlite3.IntegrityError, match="task_interruption_requires_reopen"):
            connection.execute(
                "UPDATE tasks SET status = 'claimed' WHERE id = 'legacy-reopen-compat'"
            )
        database.append_audit(
            "task.reopened",
            "admin",
            {
                "previous_status": "blocked",
                "reason": "legacy service transaction ordering",
                "task_id": "legacy-reopen-compat",
            },
            connection=connection,
        )
        connection.execute("SAVEPOINT fresh_claim_probe")
        connection.execute(
            "UPDATE tasks SET status = 'claimed', owner_agent_id = 'legacy-worker', "
            "claim_expires_at = 4102444800, claim_fencing_token = 3 "
            "WHERE id = 'legacy-reopen-compat'"
        )
        connection.execute("ROLLBACK TO fresh_claim_probe")
        connection.execute("RELEASE fresh_claim_probe")
        resolved_count = connection.execute(
            "SELECT COUNT(*) FROM budget_unresolved_interruption_reports "
            "WHERE task_id = 'legacy-reopen-compat'"
        ).fetchone()[0]
        assert resolved_count == 0
    assert database.verify_audit_chain() == (True, 20, None)


def test_v11_migration_12_park_and_cleanup_roll_back_on_audit_failure(
    database_path: Path,
) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.execute("UPDATE meta SET value = '11' WHERE key = ?", (SCHEMA_VERSION_KEY,))
        connection.execute(
            "INSERT INTO agents(id, name, owner, role, created_at) "
            "VALUES ('legacy-worker', 'legacy worker', 'owner', 'worker', 'now')"
        )
        connection.execute(
            """
            INSERT INTO tasks(
                id, title, description, acceptance_criteria_json, resources_json,
                status, owner_agent_id, claim_expires_at, claim_fencing_token,
                version, created_at, updated_at
            ) VALUES ('migration12-rollback', 'task', 'stale fence', '[]', '[]',
                      'open', NULL, NULL, 0, 1, 'now', 'before')
            """
        )
        connection.execute(
            "UPDATE tasks SET status = 'claimed', owner_agent_id = 'legacy-worker', "
            "claim_expires_at = 4102444800, claim_fencing_token = 1 "
            "WHERE id = 'migration12-rollback'"
        )
        connection.execute(
            "UPDATE tasks SET claim_fencing_token = 2, version = 7, status = 'qc_review', "
            "owner_agent_id = NULL, claim_expires_at = NULL "
            "WHERE id = 'migration12-rollback'"
        )
        connection.execute(
            """
            INSERT INTO resource_leases(
                resource, task_id, holder_agent_id, fencing_token, expires_at, updated_at
            ) VALUES ('resource-rollback', 'migration12-rollback', 'legacy-worker',
                      4, 4102444800, 'before')
            """
        )
        connection.execute(
            """
            INSERT INTO agent_heartbeats(
                agent_id, task_id, claim_fencing_token, checkpoint_json, expires_at, updated_at
            ) VALUES ('legacy-worker', 'migration12-rollback', 2, '{}', 4102444800, 'before')
            """
        )
        connection.execute(
            """
            INSERT INTO budget_interruption_reports(
                id, task_id, agent_id, claim_fencing_token,
                resource_fencing_tokens_json, status, source, reason, summary,
                checkpoint_json, checkpoint_sha256, dispatch_attempt_ids_json, received_at
            ) VALUES ('report-rollback', 'migration12-rollback', 'legacy-worker', 1,
                      '{}', 'partial', 'client_reported', 'provider_quota_exhausted',
                      'interrupted', '{}', ?, '[]', 'now')
            """,
            ("0" * 64,),
        )
        connection.execute(
            """
            CREATE TRIGGER reject_migration12_park BEFORE INSERT ON audit_events
            WHEN NEW.event_type = 'task.interruption_migration_parked'
             AND json_extract(NEW.payload_json, '$.schema_version') = 12
            BEGIN SELECT RAISE(ABORT, 'induced migration 12 audit failure'); END
            """
        )

    database = Database(str(database_path))
    database.append_audit(
        "task.interruption_reported",
        "legacy-worker",
        {
            "claim_fencing_token": 1,
            "report_id": "report-rollback",
            "task_id": "migration12-rollback",
        },
    )

    with pytest.raises(sqlite3.IntegrityError, match="induced migration 12 audit failure"):
        database.initialize()

    with sqlite3.connect(database_path) as connection:
        task = connection.execute(
            "SELECT status, owner_agent_id, claim_expires_at, claim_fencing_token, version, "
            "updated_at FROM tasks WHERE id = 'migration12-rollback'"
        ).fetchone()
        lease = connection.execute(
            "SELECT task_id, holder_agent_id, expires_at, updated_at "
            "FROM resource_leases WHERE resource = 'resource-rollback'"
        ).fetchone()
        heartbeat_count = connection.execute(
            "SELECT COUNT(*) FROM agent_heartbeats WHERE task_id = 'migration12-rollback'"
        ).fetchone()[0]
        schema_version = connection.execute(
            "SELECT value FROM meta WHERE key = ?", (SCHEMA_VERSION_KEY,)
        ).fetchone()[0]
        migration12_events = connection.execute(
            "SELECT COUNT(*) FROM audit_events WHERE event_type = 'task.interruption_migration_parked'"
        ).fetchone()[0]

    assert task == ("qc_review", None, None, 2, 7, "before")
    assert lease == ("migration12-rollback", "legacy-worker", 4102444800, "before")
    assert heartbeat_count == 1
    assert schema_version == "11"
    assert migration12_events == 0
    assert Database(str(database_path)).verify_audit_chain() == (True, 1, None)


def test_v10_migration_parks_preexisting_interrupted_orphans(database_path: Path) -> None:
    with sqlite3.connect(database_path) as connection:
        # This fixture represents a v10 database, before the schema-12 view and
        # lifecycle trigger existed.
        connection.execute("DROP TRIGGER IF EXISTS budget_interruption_task_resume_guard")
        connection.execute("DROP VIEW IF EXISTS budget_unresolved_interruption_reports")
        connection.execute(
            "INSERT INTO agents(id, name, owner, role, created_at) "
            "VALUES ('legacy-worker', 'legacy worker', 'owner', 'worker', 'now')"
        )

        report_specs: list[tuple[str, int]] = []

        def add_orphan(task_id: str, *, report_token: int | None, task_token: int = 1) -> None:
            connection.execute(
                """
                INSERT INTO tasks(
                    id, title, description, acceptance_criteria_json, resources_json,
                    status, claim_fencing_token, version, created_at, updated_at
                ) VALUES (?, 'task', 'legacy orphan', '[]', '[]', 'open', 0, 7, 'now', 'before')
                """,
                (task_id,),
            )
            connection.execute(
                """
                UPDATE tasks
                SET status = 'claimed', claim_fencing_token = 1,
                    owner_agent_id = 'legacy-worker', claim_expires_at = 0
                WHERE id = ?
                """,
                (task_id,),
            )
            connection.execute(
                "UPDATE tasks SET status = 'orphaned', owner_agent_id = NULL, "
                "claim_expires_at = NULL WHERE id = ?",
                (task_id,),
            )
            if task_token == 2:
                connection.execute(
                    "UPDATE tasks SET status = 'claimed', claim_fencing_token = 2, "
                    "owner_agent_id = 'legacy-worker', claim_expires_at = 0 WHERE id = ?",
                    (task_id,),
                )
                connection.execute(
                    "UPDATE tasks SET status = 'orphaned', owner_agent_id = NULL, "
                    "claim_expires_at = NULL WHERE id = ?",
                    (task_id,),
                )
            if report_token is not None:
                connection.execute(
                    """
                    INSERT INTO budget_interruption_reports(
                        id, task_id, agent_id, claim_fencing_token,
                        resource_fencing_tokens_json, status, source, reason, summary,
                        checkpoint_json, checkpoint_sha256, dispatch_attempt_ids_json,
                        received_at
                    ) VALUES (?, ?, 'legacy-worker', ?, '{}', 'partial', 'client_reported',
                              'provider_quota_exhausted', 'interrupted', '{}', ?, '[]', 'now')
                    """,
                    (f"report-{task_id}", task_id, report_token, "0" * 64),
                )
                report_specs.append((task_id, report_token))

        add_orphan("interrupted-orphan", report_token=1)
        add_orphan("stale-report-orphan", report_token=1, task_token=2)
        add_orphan("unreported-orphan", report_token=None)
        connection.execute("UPDATE meta SET value = '10' WHERE key = ?", (SCHEMA_VERSION_KEY,))

    database = Database(str(database_path))
    for task_id, report_token in report_specs:
        database.append_audit(
            "task.interruption_reported",
            "legacy-worker",
            {
                "claim_fencing_token": report_token,
                "report_id": f"report-{task_id}",
                "task_id": task_id,
            },
        )

    Database(str(database_path)).initialize()

    with sqlite3.connect(database_path) as connection:
        rows = {
            row[0]: row[1:]
            for row in connection.execute(
                """
                SELECT id, status, owner_agent_id, claim_expires_at,
                       claim_fencing_token, version, updated_at
                FROM tasks
                WHERE id IN ('interrupted-orphan', 'stale-report-orphan', 'unreported-orphan')
                """
            )
        }
        version = connection.execute(
            "SELECT value FROM meta WHERE key = ?", (SCHEMA_VERSION_KEY,)
        ).fetchone()[0]

    interrupted = rows["interrupted-orphan"]
    assert interrupted[:5] == ("blocked", None, None, 1, 8)
    assert interrupted[5] != "before"
    stale = rows["stale-report-orphan"]
    assert stale[:5] == ("blocked", None, None, 2, 8)
    assert stale[5] != "before"
    assert rows["unreported-orphan"] == ("orphaned", None, None, 1, 7, "before")
    assert version == str(SERVICE_SCHEMA_VERSION)

    database = Database(str(database_path))
    events = database.audit_events()
    migration_events = [
        event for event in events if event["event_type"] == "task.interruption_migration_parked"
    ]
    migration_events.sort(key=lambda event: event["sequence"])
    assert len(migration_events) == 2
    assert migration_events[0]["actor"] == "system"
    assert migration_events[0]["payload"] == {
        "claim_fencing_token": 1,
        "from_status": "orphaned",
        "interruption_report_id": "report-interrupted-orphan",
        "previous_version": 7,
        "schema_version": 11,
        "task_id": "interrupted-orphan",
        "to_status": "blocked",
    }
    assert migration_events[1]["actor"] == "system"
    assert migration_events[1]["payload"] == {
        "claim_fencing_token": 2,
        "from_status": "orphaned",
        "interruption_report_fencing_token": 1,
        "interruption_report_id": "report-stale-report-orphan",
        "previous_version": 7,
        "schema_version": 12,
        "task_id": "stale-report-orphan",
        "to_status": "blocked",
        "unresolved_interruption_report_count": 1,
    }
    assert database.verify_audit_chain() == (True, 4, None)


def test_v10_migration_rolls_back_when_interrupted_orphan_audit_fails(
    database_path: Path,
) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.execute("DROP TRIGGER IF EXISTS budget_interruption_task_resume_guard")
        connection.execute("DROP VIEW IF EXISTS budget_unresolved_interruption_reports")
        connection.execute(
            "INSERT INTO agents(id, name, owner, role, created_at) "
            "VALUES ('legacy-worker', 'legacy worker', 'owner', 'worker', 'now')"
        )
        connection.execute(
            """
            INSERT INTO tasks(
                id, title, description, acceptance_criteria_json, resources_json,
                status, claim_fencing_token, version, created_at, updated_at
            ) VALUES ('interrupted-orphan', 'task', 'legacy orphan', '[]', '[]',
                      'open', 0, 7, 'now', 'before')
            """
        )
        connection.execute(
            "UPDATE tasks SET status = 'orphaned', claim_fencing_token = 1 "
            "WHERE id = 'interrupted-orphan'"
        )
        connection.execute(
            """
            INSERT INTO budget_interruption_reports(
                id, task_id, agent_id, claim_fencing_token,
                resource_fencing_tokens_json, status, source, reason, summary,
                checkpoint_json, checkpoint_sha256, dispatch_attempt_ids_json,
                received_at
            ) VALUES ('report-interrupted-orphan', 'interrupted-orphan', 'legacy-worker', 1,
                      '{}', 'partial', 'client_reported', 'provider_quota_exhausted',
                      'interrupted', '{}', ?, '[]', 'now')
            """,
            ("0" * 64,),
        )
        connection.execute("UPDATE meta SET value = '10' WHERE key = ?", (SCHEMA_VERSION_KEY,))
        connection.execute(
            """
            CREATE TRIGGER reject_migration_audit BEFORE INSERT ON audit_events
            WHEN NEW.event_type = 'task.interruption_migration_parked'
            BEGIN SELECT RAISE(ABORT, 'induced migration audit failure'); END
            """
        )

    with pytest.raises(sqlite3.IntegrityError, match="induced migration audit failure"):
        Database(str(database_path)).initialize()

    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            "SELECT status, version, updated_at FROM tasks WHERE id = 'interrupted-orphan'"
        ).fetchone()
        version = connection.execute(
            "SELECT value FROM meta WHERE key = ?", (SCHEMA_VERSION_KEY,)
        ).fetchone()[0]
        audit_count = connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]

    assert row == ("orphaned", 7, "before")
    assert version == "10"
    assert audit_count == 0


def test_dispatch_outstanding_budget_sql_guard_cannot_be_bypassed(database_path: Path) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            "INSERT INTO agents(id, name, owner, created_at) "
            "VALUES ('outstanding-worker', 'worker', 'owner', 'now')"
        )
        connection.execute(
            """
            INSERT INTO tasks(
                id, title, description, acceptance_criteria_json, resources_json,
                status,
                max_unreceipted_dispatch_attempts, created_at, updated_at
            ) VALUES ('outstanding-task', 'task', 'budget', '[]', '[]', 'open',
                      0, 'now', 'now')
            """
        )
        connection.execute(
            "UPDATE tasks SET status = 'working', owner_agent_id = ?, claim_expires_at = ?, "
            "claim_fencing_token = 1 WHERE id = 'outstanding-task'",
            ("outstanding-worker", int(time.time()) + 300),
        )
        with pytest.raises(
            sqlite3.IntegrityError,
            match="task_dispatch_outstanding_budget_exhausted",
        ):
            connection.execute(
                """
                INSERT INTO dispatch_attempt_reservations(
                    id, task_id, agent_id, claim_fencing_token,
                    resource_fencing_tokens_json, idempotency_key, created_at
                ) VALUES ('outstanding-reservation', 'outstanding-task',
                          'outstanding-worker', 1, '{}', 'direct-insert', 'now')
                """
            )


def test_descendant_dispatch_outstanding_sql_guard_cannot_be_bypassed(
    database_path: Path,
) -> None:
    now = int(time.time())
    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            "INSERT INTO agents(id, name, owner, created_at) "
            "VALUES ('outstanding-worker', 'worker', 'owner', 'now')"
        )
        connection.execute(
            """
            INSERT INTO tasks(
                id, title, description, acceptance_criteria_json, resources_json,
                status, max_descendant_unreceipted_dispatch_attempts,
                created_at, updated_at
            ) VALUES ('outstanding-root', 'root', 'budget', '[]', '[]', 'open', 1, 'now', 'now')
            """
        )
        connection.execute(
            """
            INSERT INTO tasks(
                id, title, description, acceptance_criteria_json, resources_json,
                status, parent_task_id, created_at, updated_at
            ) VALUES ('outstanding-middle', 'middle', 'nested', '[]', '[]', 'open',
                      'outstanding-root', 'now', 'now')
            """
        )
        for task_id in ("outstanding-child-a", "outstanding-child-b"):
            connection.execute(
                """
                INSERT INTO tasks(
                    id, title, description, acceptance_criteria_json, resources_json,
                    status, parent_task_id, created_at, updated_at
                ) VALUES (?, 'child', 'budget', '[]', '[]', 'open',
                          'outstanding-middle', 'now', 'now')
                """,
                (task_id,),
            )
            connection.execute(
                "UPDATE tasks SET status = 'working', owner_agent_id = ?, claim_expires_at = ?, "
                "claim_fencing_token = 1 WHERE id = ?",
                ("outstanding-worker", now + 300, task_id),
            )

        connection.execute(
            """
            INSERT INTO dispatch_attempt_reservations(
                id, task_id, agent_id, claim_fencing_token,
                resource_fencing_tokens_json, idempotency_key, created_at
            ) VALUES ('outstanding-reservation-a', 'outstanding-child-a',
                      'outstanding-worker', 1, '{}', 'direct-insert-a', 'now')
            """
        )
        with pytest.raises(
            sqlite3.IntegrityError,
            match="descendant_dispatch_outstanding_budget_exhausted",
        ):
            connection.execute(
                """
                INSERT INTO dispatch_attempt_reservations(
                    id, task_id, agent_id, claim_fencing_token,
                    resource_fencing_tokens_json, idempotency_key, created_at
                ) VALUES ('outstanding-reservation-b', 'outstanding-child-b',
                          'outstanding-worker', 1, '{}', 'direct-insert-b', 'now')
                """
            )


def test_dispatch_reservation_sql_guard_enforces_caps_and_immutable_receipts(
    database_path: Path,
) -> None:
    now = int(time.time())
    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            "INSERT INTO agents(id, name, owner, created_at) VALUES "
            "('dispatch-worker', 'worker', 'owner', 'now')"
        )
        connection.execute(
            """
            INSERT INTO tasks(
                id, title, description, acceptance_criteria_json, resources_json,
                status, max_descendant_dispatch_attempts, created_at, updated_at
            ) VALUES ('dispatch-root', 'root', 'budget', '[]', '[]', 'open', 1, 'now', 'now')
            """
        )
        connection.execute(
            """
            INSERT INTO tasks(
                id, title, description, acceptance_criteria_json, resources_json,
                status, parent_task_id, created_at, updated_at
            ) VALUES ('dispatch-middle', 'middle', 'nested', '[]', '[]', 'open',
                      'dispatch-root', 'now', 'now')
            """
        )
        for task_id in ("dispatch-a", "dispatch-b"):
            resource = f"repo:file:{task_id}.py"
            connection.execute(
                """
                INSERT INTO tasks(
                    id, title, description, acceptance_criteria_json, resources_json,
                    status, owner_agent_id, claim_expires_at, claim_fencing_token,
                    parent_task_id, max_dispatch_attempts, created_at, updated_at
                ) VALUES (?, 'child', 'budget', '[]', ?, 'open', NULL, NULL,
                          0, 'dispatch-middle', 1, 'now', 'now')
                """,
                (task_id, f'["{resource}"]'),
            )
            connection.execute(
                "UPDATE tasks SET status = 'working', owner_agent_id = 'dispatch-worker', "
                "claim_expires_at = ?, claim_fencing_token = 1 WHERE id = ?",
                (now + 3600, task_id),
            )
            connection.execute(
                "INSERT INTO resource_leases("
                "resource, task_id, holder_agent_id, fencing_token, expires_at, updated_at) "
                "VALUES (?, ?, 'dispatch-worker', 1, ?, 'now')",
                (resource, task_id, now + 3600),
            )
        with pytest.raises(sqlite3.IntegrityError, match="dispatch_resource_fence_invalid"):
            connection.execute(
                """
                INSERT INTO dispatch_attempt_reservations(
                    id, task_id, agent_id, claim_fencing_token,
                    resource_fencing_tokens_json, idempotency_key, created_at
                ) VALUES ('bad-resource-fence', 'dispatch-a', 'dispatch-worker', 1,
                          '{"repo:file:dispatch-a.py":2}', 'bad-call', 'now')
                """
            )
        connection.execute(
            "UPDATE resource_leases SET task_id = NULL, holder_agent_id = NULL "
            "WHERE resource = 'repo:file:dispatch-a.py'"
        )
        with pytest.raises(sqlite3.IntegrityError, match="dispatch_resource_fence_invalid"):
            connection.execute(
                """
                INSERT INTO dispatch_attempt_reservations(
                    id, task_id, agent_id, claim_fencing_token, resource_fencing_tokens_json,
                    idempotency_key, created_at
                ) VALUES ('ownerless-resource-fence', 'dispatch-a', 'dispatch-worker', 1,
                          '{"repo:file:dispatch-a.py":1}', 'ownerless-call', 'now')
                """
            )
        connection.execute(
            "UPDATE resource_leases SET task_id = 'dispatch-a', holder_agent_id = 'dispatch-worker' "
            "WHERE resource = 'repo:file:dispatch-a.py'"
        )
        connection.execute(
            """
            INSERT INTO dispatch_attempt_reservations(
                id, task_id, agent_id, claim_fencing_token, resource_fencing_tokens_json,
                idempotency_key, created_at
            ) VALUES ('dispatch-reservation-a', 'dispatch-a', 'dispatch-worker', 1,
                      '{"repo:file:dispatch-a.py":1}', 'call-a', 'now')
            """
        )
        with pytest.raises(sqlite3.IntegrityError, match="descendant_dispatch_budget_exhausted"):
            connection.execute(
                """
                INSERT INTO dispatch_attempt_reservations(
                    id, task_id, agent_id, claim_fencing_token, resource_fencing_tokens_json,
                    idempotency_key, created_at
                ) VALUES ('dispatch-reservation-b', 'dispatch-b', 'dispatch-worker', 1,
                          '{"repo:file:dispatch-b.py":1}', 'call-b', 'now')
                """
            )
        connection.execute(
            """
            INSERT INTO dispatch_attempt_receipts(
                dispatch_attempt_id, source, http_status_code, retry_after_seconds, received_at
            ) VALUES ('dispatch-reservation-a', 'client_reported', 429, 30, 'now')
            """
        )
        with pytest.raises(sqlite3.IntegrityError, match="dispatch_attempt_receipt_immutable"):
            connection.execute(
                "UPDATE dispatch_attempt_receipts SET http_status_code = 200 "
                "WHERE dispatch_attempt_id = 'dispatch-reservation-a'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="dispatch_attempt_receipt_immutable"):
            connection.execute(
                "UPDATE dispatch_attempt_receipts SET provider_usage_json = '{}' "
                "WHERE dispatch_attempt_id = 'dispatch-reservation-a'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="task_dispatch_budget_config_immutable"):
            connection.execute("UPDATE tasks SET max_dispatch_attempts = 2 WHERE id = 'dispatch-a'")


def test_stale_service_sql_writer_cannot_bypass_task_claim_cap(
    database_path: Path,
) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        for task_id, parent_id, descendant_cap in (
            ("root", None, 1),
            ("child-a", "root", None),
            ("child-b", "root", None),
        ):
            connection.execute(
                """
                INSERT INTO tasks(
                    id, title, description, acceptance_criteria_json, resources_json,
                    priority, status, claim_fencing_token, parent_task_id,
                    max_descendant_claims, created_at, updated_at
                ) VALUES (?, 'task', 'legacy writer test', '[]', '[]', 50, 'open',
                          0, ?, ?, 'now', 'now')
                """,
                (task_id, parent_id, descendant_cap),
            )
        connection.execute(
            """
            INSERT INTO tasks(
                id, title, description, acceptance_criteria_json, resources_json,
                status, max_claims, created_at, updated_at
            ) VALUES ('local', 'task', 'local cap', '[]', '[]', 'open', 1, 'now', 'now')
            """
        )

        # This is the old service's claim update: it knows only the fencing token.
        connection.execute(
            "UPDATE tasks SET claim_fencing_token = claim_fencing_token + 1 WHERE id = 'child-a'"
        )
        with pytest.raises(sqlite3.IntegrityError, match="descendant_claim_budget_exhausted"):
            connection.execute(
                "UPDATE tasks SET claim_fencing_token = claim_fencing_token + 1 "
                "WHERE id = 'child-b'"
            )
        connection.execute(
            "UPDATE tasks SET claim_fencing_token = claim_fencing_token + 1 WHERE id = 'local'"
        )
        with pytest.raises(sqlite3.IntegrityError, match="task_claim_budget_exhausted"):
            connection.execute(
                "UPDATE tasks SET claim_fencing_token = claim_fencing_token + 1 WHERE id = 'local'"
            )
        stored = connection.execute(
            "SELECT id, claim_fencing_token FROM tasks "
            "WHERE id IN ('child-a', 'child-b', 'local') ORDER BY id"
        ).fetchall()

    assert stored == [("child-a", 1), ("child-b", 0), ("local", 1)]


def test_task_claim_budget_insert_guard_rejects_preconsumed_and_replaced_tasks(
    database_path: Path,
) -> None:
    with sqlite3.connect(database_path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="task_claim_fencing_invalid"):
            connection.execute(
                """
                INSERT INTO tasks(
                    id, title, description, acceptance_criteria_json, resources_json,
                    claim_fencing_token, created_at, updated_at
                ) VALUES ('preclaimed', 'task', 'invalid insert', '[]', '[]', 1, 'now', 'now')
                """
            )

        connection.execute(
            """
                INSERT INTO tasks(
                    id, title, description, acceptance_criteria_json, resources_json,
                    status, max_claims, created_at, updated_at
                ) VALUES (
                    'immutable', 'task', 'immutable config', '[]', '[]', 'open', 1, 'now', 'now'
                )
            """
        )
        with pytest.raises(sqlite3.IntegrityError, match="task_claim_budget_config_immutable"):
            connection.execute(
                """
                INSERT OR REPLACE INTO tasks(
                    id, title, description, acceptance_criteria_json, resources_json,
                    status, max_claims, created_at, updated_at
                ) VALUES (
                    'immutable', 'task', 'replace attempt', '[]', '[]', 'open', 10, 'now', 'now'
                )
                """
            )
        stored = connection.execute(
            "SELECT max_claims FROM tasks WHERE id = 'immutable'"
        ).fetchone()[0]

    assert stored == 1


def test_stale_service_sql_writer_fails_closed_on_corrupt_task_lineage(
    database_path: Path,
) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO tasks(
                id, title, description, acceptance_criteria_json, resources_json,
                status, max_descendant_claims, created_at, updated_at
            ) VALUES ('root', 'task', 'cycle test', '[]', '[]', 'open', 2, 'now', 'now')
            """
        )
        connection.execute(
            """
            INSERT INTO tasks(
                id, title, description, acceptance_criteria_json, resources_json,
                status, parent_task_id, created_at, updated_at
            ) VALUES ('child', 'task', 'cycle test', '[]', '[]', 'open', 'root', 'now', 'now')
            """
        )
        connection.execute("DROP TRIGGER task_claim_budget_config_immutable")
        connection.execute("UPDATE tasks SET parent_task_id = 'child' WHERE id = 'root'")
        with pytest.raises(sqlite3.IntegrityError, match="task_lineage_invalid"):
            connection.execute(
                "UPDATE tasks SET claim_fencing_token = claim_fencing_token + 1 WHERE id = 'child'"
            )
        token = connection.execute(
            "SELECT claim_fencing_token FROM tasks WHERE id = 'child'"
        ).fetchone()[0]

    assert token == 0


def test_a_stale_initializer_cannot_downgrade_the_service_schema_stamp(
    database_path: Path,
) -> None:
    """Old stamp_schema_version used INSERT OR REPLACE after preflight."""
    connection = sqlite3.connect(database_path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="service_schema_version_downgrade"):
            connection.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                (SCHEMA_VERSION_KEY, "2"),
            )
        recorded_version = connection.execute(
            "SELECT value FROM meta WHERE key = ?", (SCHEMA_VERSION_KEY,)
        ).fetchone()[0]
    finally:
        connection.close()

    assert recorded_version == str(SERVICE_SCHEMA_VERSION)


def test_an_already_running_v1_writer_cannot_bypass_the_fanout_cap(
    database_path: Path,
) -> None:
    """Model the old INSERT column list, which has no field for the new cap."""
    connection = sqlite3.connect(database_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executemany(
            "INSERT INTO agents(id, name, owner, created_at) VALUES (?, ?, ?, ?)",
            [
                ("root-agent", "root", "owner", "2026-01-01T00:00:00+00:00"),
                ("child-agent", "child", "owner", "2026-01-01T00:00:00+00:00"),
                ("grandchild-agent", "grandchild", "owner", "2026-01-01T00:00:00+00:00"),
            ],
        )
        connection.execute(
            """
            INSERT INTO mandates(
                id, agent_id, subject, scopes_json, max_descendant_mandates,
                expires_at, created_at
            ) VALUES ('root', 'root-agent', 'owner', '[]', 1, 4102444800, 'now')
            """
        )

        def old_writer_insert(mandate_id: str, agent_id: str, parent_id: str) -> None:
            connection.execute(
                """
                INSERT INTO mandates(
                    id, agent_id, subject, parent_mandate_id, scopes_json,
                    max_amount_cents, expires_at, revoked, created_at
                ) VALUES (?, ?, 'owner', ?, '[]', NULL, 4102444800, 0, 'now')
                """,
                (mandate_id, agent_id, parent_id),
            )

        old_writer_insert("child", "child-agent", "root")
        with pytest.raises(sqlite3.IntegrityError, match="mandate_fanout_exhausted"):
            old_writer_insert("grandchild", "grandchild-agent", "child")

        count = connection.execute(
            """
            WITH RECURSIVE descendants(id) AS (
                SELECT id FROM mandates WHERE parent_mandate_id = 'root'
                UNION
                SELECT child.id FROM mandates AS child
                JOIN descendants ON child.parent_mandate_id = descendants.id
            ) SELECT COUNT(*) FROM descendants
            """
        ).fetchone()[0]
        assert count == 1
    finally:
        connection.close()


def test_wal_setup_retries_contention_and_restores_the_write_timeout() -> None:
    class Cursor:
        def __init__(self, value: str):
            self.value = value

        def fetchone(self) -> tuple[str]:
            return (self.value,)

    class ContendedConnection:
        def __init__(self) -> None:
            self.busy_timeouts: list[int] = []
            self.mode_reads = 0
            self.wal_changes = 0

        def execute(self, sql: str) -> Cursor:
            if sql.startswith("PRAGMA busy_timeout = "):
                self.busy_timeouts.append(int(sql.rsplit(" ", maxsplit=1)[1]))
                return Cursor("0")
            if sql == "PRAGMA journal_mode":
                self.mode_reads += 1
                return Cursor("delete" if self.mode_reads == 1 else "wal")
            if sql == "PRAGMA journal_mode = WAL":
                self.wal_changes += 1
                raise sqlite3.OperationalError("database is locked")
            raise AssertionError(f"unexpected SQL: {sql}")

    connection = ContendedConnection()

    _enable_service_wal_mode(connection)  # type: ignore[arg-type]

    assert connection.busy_timeouts == [0, 10_000]
    assert connection.mode_reads == 2
    assert connection.wal_changes == 1


def test_concurrent_v1_initializers_serialize_the_schema_migration(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "concurrent-v1.db"
    create_v1_service_database(database_path)
    barrier = Barrier(6)

    def initialize_together(_: int) -> None:
        barrier.wait(timeout=5)
        Database(str(database_path)).initialize()

    with ThreadPoolExecutor(max_workers=6) as executor:
        list(executor.map(initialize_together, range(6)))

    connection = sqlite3.connect(database_path)
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(mandates)")}
        recorded_version = connection.execute(
            "SELECT value FROM meta WHERE key = ?", (SCHEMA_VERSION_KEY,)
        ).fetchone()[0]
        trigger_count = connection.execute(
            "SELECT COUNT(*) FROM sqlite_master "
            "WHERE type = 'trigger' AND name = 'mandate_fanout_guard'"
        ).fetchone()[0]
    finally:
        connection.close()

    assert "max_descendant_mandates" in columns
    assert recorded_version == str(SERVICE_SCHEMA_VERSION)
    assert trigger_count == 1


def test_a_corrupt_stamp_is_not_guessed(database_path: Path) -> None:
    connection = sqlite3.connect(database_path)
    connection.execute("DROP TRIGGER service_schema_version_no_downgrade")
    connection.commit()
    connection.close()
    write_meta(database_path, SCHEMA_VERSION_KEY, "one")

    with pytest.raises(SchemaVersionError) as error:
        Database(str(database_path)).initialize()

    assert error.value.code == "schema_version_unreadable"


def test_initialize_is_idempotent(database_path: Path) -> None:
    Database(str(database_path)).initialize()
    Database(str(database_path)).initialize()
    assert meta(database_path)[SCHEMA_VERSION_KEY] == str(SERVICE_SCHEMA_VERSION)


def test_the_two_databases_version_independently(database_path: Path) -> None:
    """The gate. These are separate files with separate lifecycles.

    Stamping the service database at the control database's version — or vice versa —
    must not be what makes either one open or refuse. Today both constants happen to be
    1; if a future change bumps one, this test is what stops the other being dragged
    along or spuriously refused.
    """

    write_meta(database_path, SCHEMA_VERSION_KEY, str(SERVICE_SCHEMA_VERSION))
    Database(str(database_path)).initialize()  # opens fine at its OWN version

    # The service database is judged against SERVICE_SCHEMA_VERSION alone, so a stamp
    # one above it is refused whatever the control database's number happens to be.
    write_meta(database_path, SCHEMA_VERSION_KEY, str(SERVICE_SCHEMA_VERSION + 1))
    with pytest.raises(SchemaVersionError):
        Database(str(database_path)).initialize()

    assert isinstance(CONTROL_SCHEMA_VERSION, int)
    assert isinstance(SERVICE_SCHEMA_VERSION, int)


def test_an_in_memory_database_still_stamps() -> None:
    """`:memory:` skips the mkdir branch; it must not skip the versioning."""

    database = Database(":memory:")
    database.initialize()  # must not raise
