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
        "dispatch_attempt_insert_guard",
        "dispatch_attempt_reservation_immutable",
        "dispatch_attempt_receipt_immutable",
    } <= triggers
    assert "idx_tasks_parent_task" in indexes
    assert "idx_dispatch_attempt_reservations_task" in indexes
    assert meta(database_path)[SCHEMA_VERSION_KEY] == str(SERVICE_SCHEMA_VERSION)


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
