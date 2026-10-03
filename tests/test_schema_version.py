"""The control database says which schema it is at, and the binary refuses what it cannot read.

Two failures motivate these tests. A binary older than the database used to open it
happily — CREATE TABLE IF NOT EXISTS leaves newer tables alone and every PRAGMA check
finds its column already there — so the newer columns were simply invisible, and an old
critic could approve what a new contract rejects. And commands documented as read-only
mutated the schema on the way to their first SELECT.
"""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest
from support import commit_change, init_repo, make_task

from agent_control_plane import __version__, git_supervisor
from agent_control_plane.cli import READ_ONLY_ACTIONS, main
from agent_control_plane.git_supervisor import (
    MIGRATIONS,
    SCHEMA_VERSION,
    GitSupervisor,
    SupervisorError,
)
from agent_control_plane.schema_version import SCHEMA_VERSION_KEY, SCHEMA_WRITTEN_BY_KEY


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return init_repo(tmp_path)


def db_path(repo: Path) -> Path:
    return repo / ".acp" / "control.db"


def fingerprint(repo: Path) -> str:
    """Hash the database with the write-ahead log folded back in first.

    Hashing control.db on its own would call a write still parked in control.db-wal
    "identical", which is the one thing these tests must not do.
    """

    connection = sqlite3.connect(db_path(repo))
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    connection.close()
    return hashlib.sha256(db_path(repo).read_bytes()).hexdigest()


def meta(repo: Path) -> dict[str, str]:
    connection = sqlite3.connect(db_path(repo))
    try:
        return dict(connection.execute("SELECT key, value FROM meta").fetchall())
    finally:
        connection.close()


def write_meta(repo: Path, key: str, value: str) -> None:
    connection = sqlite3.connect(db_path(repo))
    connection.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (key, value))
    connection.commit()
    connection.close()


def drop_meta(repo: Path, key: str) -> None:
    connection = sqlite3.connect(db_path(repo))
    connection.execute("DELETE FROM meta WHERE key = ?", (key,))
    connection.commit()
    connection.close()


def test_initialize_stamps_the_version_and_the_writer(repo: Path) -> None:
    recorded = meta(repo)
    assert recorded[SCHEMA_VERSION_KEY] == str(SCHEMA_VERSION)
    assert recorded[SCHEMA_WRITTEN_BY_KEY] == __version__


def test_attempt_progress_migration_keeps_legacy_ages_unknown() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        CREATE TABLE tasks (id TEXT PRIMARY KEY);
        CREATE TABLE attempts (
          id TEXT PRIMARY KEY,
          checkpoint_json TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE submissions (id TEXT PRIMARY KEY);
        CREATE TABLE qc_runs (id TEXT PRIMARY KEY);
        INSERT INTO attempts VALUES(
          'attempt-1', '{"phase":"tests"}',
          '2025-01-01T00:00:00Z', '2025-01-02T00:00:00Z'
        );
        """
    )

    migration = dict(MIGRATIONS)[3]
    migration(connection)
    row = connection.execute(
        "SELECT heartbeat_at, checkpoint_at, checkpoint_json FROM attempts WHERE id = 'attempt-1'"
    ).fetchone()
    assert row["heartbeat_at"] == ""
    assert row["checkpoint_at"] == ""
    assert row["checkpoint_json"] == '{"phase":"tests"}'

    migration(connection)
    repeated = connection.execute(
        "SELECT heartbeat_at, checkpoint_at, checkpoint_json FROM attempts WHERE id = 'attempt-1'"
    ).fetchone()
    assert dict(repeated) == dict(row)
    connection.close()


def test_base_checkout_snapshot_migration_leaves_legacy_baseline_unknown() -> None:
    connection = sqlite3.connect(":memory:")
    connection.executescript(
        """
        CREATE TABLE attempts (id TEXT PRIMARY KEY);
        INSERT INTO attempts VALUES ('legacy-active-attempt');
        """
    )

    migration = dict(MIGRATIONS)[4]
    migration(connection)
    assert (
        connection.execute(
            "SELECT base_checkout_snapshot_json FROM attempts WHERE id = 'legacy-active-attempt'"
        ).fetchone()[0]
        == ""
    )
    migration(connection)
    assert (
        connection.execute(
            "SELECT base_checkout_snapshot_json FROM attempts WHERE id = 'legacy-active-attempt'"
        ).fetchone()[0]
        == ""
    )
    connection.close()


def test_base_checkout_snapshot_requirement_migration_preserves_legacy_marker() -> None:
    connection = sqlite3.connect(":memory:")
    connection.executescript(
        """
        CREATE TABLE attempts (id TEXT PRIMARY KEY);
        INSERT INTO attempts VALUES ('legacy-active-attempt');
        """
    )

    migration = dict(MIGRATIONS)[5]
    migration(connection)
    assert (
        connection.execute(
            "SELECT base_checkout_snapshot_required FROM attempts "
            "WHERE id = 'legacy-active-attempt'"
        ).fetchone()[0]
        == 0
    )
    migration(connection)
    assert (
        connection.execute(
            "SELECT base_checkout_snapshot_required FROM attempts "
            "WHERE id = 'legacy-active-attempt'"
        ).fetchone()[0]
        == 0
    )
    connection.close()


def test_attempt_worktree_root_migration_leaves_legacy_attempts_on_default_root() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        CREATE TABLE attempts (id TEXT PRIMARY KEY, worktree TEXT NOT NULL);
        INSERT INTO attempts VALUES ('legacy-attempt', '/repo/.acp/worktrees/legacy-attempt');
        """
    )

    migration = dict(MIGRATIONS)[7]
    migration(connection)
    row = connection.execute(
        "SELECT worktree, worktree_root FROM attempts WHERE id = 'legacy-attempt'"
    ).fetchone()
    assert row["worktree"] == "/repo/.acp/worktrees/legacy-attempt"
    assert row["worktree_root"] == ""

    migration(connection)
    repeated = connection.execute(
        "SELECT worktree_root FROM attempts WHERE id = 'legacy-attempt'"
    ).fetchone()
    assert repeated["worktree_root"] == ""
    connection.close()


def test_qc_latest_lookup_index_migration_is_idempotent() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        CREATE TABLE qc_runs (
          id TEXT PRIMARY KEY,
          submission_id TEXT NOT NULL,
          finished_at TEXT NOT NULL
        );
        """
    )

    migration = dict(MIGRATIONS)[8]
    migration(connection)
    columns = connection.execute("PRAGMA index_info('idx_qc_runs_submission_latest')").fetchall()
    migration(connection)
    repeated = connection.execute("PRAGMA index_info('idx_qc_runs_submission_latest')").fetchall()

    assert [row["name"] for row in columns] == ["submission_id", "finished_at", "id"]
    assert [dict(row) for row in repeated] == [dict(row) for row in columns]
    connection.close()


def test_v7_read_only_open_requires_qc_latest_index_migration(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    with supervisor.connect() as connection:
        connection.execute("DROP INDEX idx_qc_runs_submission_latest")
        connection.execute("UPDATE meta SET value = '7' WHERE key = ?", (SCHEMA_VERSION_KEY,))

    before = fingerprint(repo)
    with pytest.raises(SupervisorError) as error:
        GitSupervisor(repo, read_only=True)
    assert error.value.code == "schema_upgrade_required"
    assert "version 7" in str(error.value)
    assert fingerprint(repo) == before

    migrated = GitSupervisor(repo)
    assert migrated.schema_version_on_open == 7
    assert meta(repo)[SCHEMA_VERSION_KEY] == str(SCHEMA_VERSION)
    with migrated.connect() as connection:
        columns = connection.execute(
            "PRAGMA index_info('idx_qc_runs_submission_latest')"
        ).fetchall()
    assert [row["name"] for row in columns] == ["submission_id", "finished_at", "id"]


def test_v8_read_only_open_requires_read_dependency_migration(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    with supervisor.connect() as connection:
        connection.execute("ALTER TABLE tasks DROP COLUMN declared_read_resources_json")
        connection.execute("ALTER TABLE tasks DROP COLUMN read_resources_json")
        connection.execute("ALTER TABLE attempts DROP COLUMN read_resources_snapshot_json")
        connection.execute("UPDATE meta SET value = '8' WHERE key = ?", (SCHEMA_VERSION_KEY,))

    before = fingerprint(repo)
    with pytest.raises(SupervisorError) as error:
        GitSupervisor(repo, read_only=True)
    assert error.value.code == "schema_upgrade_required"
    assert "version 8" in str(error.value)
    assert fingerprint(repo) == before

    migrated = GitSupervisor(repo)
    assert migrated.schema_version_on_open == 8
    assert meta(repo)[SCHEMA_VERSION_KEY] == str(SCHEMA_VERSION)
    with migrated.connect() as connection:
        task_columns = {row["name"] for row in connection.execute("PRAGMA table_info(tasks)")}
        attempt_columns = {row["name"] for row in connection.execute("PRAGMA table_info(attempts)")}
    assert {"read_resources_json", "declared_read_resources_json"} <= task_columns
    assert "read_resources_snapshot_json" in attempt_columns
    with migrated.connect() as connection:
        migration = dict(MIGRATIONS)[9]
        migration(connection)
        migration(connection)


def test_v9_read_only_open_requires_criterion_coverage_migration(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    with supervisor.connect() as connection:
        connection.execute("ALTER TABLE qc_runs DROP COLUMN acceptance_coverage_contract_version")
        connection.execute("ALTER TABLE qc_runs DROP COLUMN acceptance_coverage_json")
        connection.execute("UPDATE meta SET value = '9' WHERE key = ?", (SCHEMA_VERSION_KEY,))

    before = fingerprint(repo)
    with pytest.raises(SupervisorError) as error:
        GitSupervisor(repo, read_only=True)
    assert error.value.code == "schema_upgrade_required"
    assert "version 9" in str(error.value)
    assert fingerprint(repo) == before

    migrated = GitSupervisor(repo)
    assert migrated.schema_version_on_open == 9
    assert meta(repo)[SCHEMA_VERSION_KEY] == str(SCHEMA_VERSION)
    with migrated.connect() as connection:
        columns = {row["name"]: row for row in connection.execute("PRAGMA table_info(qc_runs)")}
    assert columns["acceptance_coverage_json"]["type"] == "TEXT"
    assert columns["acceptance_coverage_json"]["dflt_value"] == "'[]'"
    assert columns["acceptance_coverage_contract_version"]["type"] == "INTEGER"
    assert columns["acceptance_coverage_contract_version"]["dflt_value"] == "0"
    with migrated.connect() as connection:
        migration = dict(MIGRATIONS)[10]
        migration(connection)
        migration(connection)


def test_v10_read_only_open_requires_completion_receipt_migration(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt", title="legacy submission")
    attempt = supervisor.claim(created["id"], "legacy-worker")
    commit_change(attempt, "alpha.txt", "legacy candidate\n")
    legacy_submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    with supervisor.connect() as connection:
        connection.execute("ALTER TABLE submissions DROP COLUMN result_manifest_json")
        connection.execute("UPDATE meta SET value = '10' WHERE key = ?", (SCHEMA_VERSION_KEY,))

    before = fingerprint(repo)
    with pytest.raises(SupervisorError) as error:
        GitSupervisor(repo, read_only=True)
    assert error.value.code == "schema_upgrade_required"
    assert "version 10" in str(error.value)
    assert fingerprint(repo) == before

    migrated = GitSupervisor(repo)
    assert migrated.schema_version_on_open == 10
    assert meta(repo)[SCHEMA_VERSION_KEY] == str(SCHEMA_VERSION)
    with migrated.connect() as connection:
        column = next(
            row
            for row in connection.execute("PRAGMA table_info(submissions)")
            if row["name"] == "result_manifest_json"
        )
        migration = dict(MIGRATIONS)[11]
        migration(connection)
        migration(connection)
    assert column["type"] == "TEXT"
    assert column["dflt_value"] == "''"
    assert migrated.submission(legacy_submission["id"])["completion_receipt"] == {
        "state": "not_provided"
    }


def test_v11_read_only_open_requires_result_import_journal_migration(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    with supervisor.connect() as connection:
        connection.execute("DROP TABLE result_imports")
        connection.execute("UPDATE meta SET value = '11' WHERE key = ?", (SCHEMA_VERSION_KEY,))

    before = fingerprint(repo)
    with pytest.raises(SupervisorError) as error:
        GitSupervisor(repo, read_only=True)
    assert error.value.code == "schema_upgrade_required"
    assert "version 11" in str(error.value)
    assert fingerprint(repo) == before

    migrated = GitSupervisor(repo)
    assert migrated.schema_version_on_open == 11
    assert meta(repo)[SCHEMA_VERSION_KEY] == str(SCHEMA_VERSION)
    with migrated.connect() as connection:
        migration = dict(MIGRATIONS)[12]
        migration(connection)
        migration(connection)
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(result_imports)")}
    assert {
        "attempt_id",
        "claim_token",
        "worker_pid",
        "worker_identity",
        "worker_exit_receipt_json",
        "result_digest",
        "tree_sha",
        "commit_sha",
        "result_ref",
        "phase",
        "submission_id",
    } <= columns


def test_v12_read_only_open_requires_result_object_staging_migration(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    with supervisor.connect() as connection:
        for column in (
            "staging_path",
            "object_ids_json",
            "promote_object_ids_json",
        ):
            connection.execute(f"ALTER TABLE result_imports DROP COLUMN {column}")
        connection.execute("UPDATE meta SET value = '12' WHERE key = ?", (SCHEMA_VERSION_KEY,))

    before = fingerprint(repo)
    with pytest.raises(SupervisorError) as error:
        GitSupervisor(repo, read_only=True)
    assert error.value.code == "schema_upgrade_required"
    assert "version 12" in str(error.value)
    assert fingerprint(repo) == before

    migrated = GitSupervisor(repo)
    assert migrated.schema_version_on_open == 12
    assert meta(repo)[SCHEMA_VERSION_KEY] == str(SCHEMA_VERSION)
    with migrated.connect() as connection:
        columns = {
            row["name"]: row for row in connection.execute("PRAGMA table_info(result_imports)")
        }
        migration = dict(MIGRATIONS)[13]
        migration(connection)
        migration(connection)
    assert columns["staging_path"]["type"] == "TEXT"
    assert columns["staging_path"]["notnull"] == 1
    assert columns["staging_path"]["dflt_value"] == "''"
    assert columns["object_ids_json"]["dflt_value"] == "'[]'"
    assert columns["promote_object_ids_json"]["dflt_value"] == "'[]'"


def test_snapshot_migration_fences_inserts_from_pre_migration_supervisors(repo: Path) -> None:
    """A live old process cannot create a new marker-less attempt after upgrade."""

    supervisor = GitSupervisor(repo)
    task = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(task["id"], "agent-a")

    # Recreate the v4 database shape: snapshot JSON exists, but the old process
    # predates the required marker and has already passed its startup check.
    with supervisor.connect() as connection:
        connection.execute("DROP TRIGGER attempts_require_base_checkout_snapshot")
        connection.execute("ALTER TABLE attempts DROP COLUMN base_checkout_snapshot_required")
        connection.execute("UPDATE meta SET value = '4' WHERE key = ?", (SCHEMA_VERSION_KEY,))

    migrated = GitSupervisor(repo)
    assert migrated.schema_version_on_open == 4
    assert meta(repo)[SCHEMA_VERSION_KEY] == str(SCHEMA_VERSION)

    with migrated.connect() as connection:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="attempt_base_checkout_snapshot_required",
        ):
            # This uses the v4 column list: it can store the claim-time JSON but
            # cannot set the v5 required marker. The trigger must fail closed.
            connection.execute(
                """
                INSERT INTO attempts
                  (id, task_id, number, agent_id, branch, worktree, claim_token,
                   start_sha, checkpoint_json, status, lease_expires_at, created_at,
                   updated_at, base_checkout_snapshot_json)
                SELECT 'stale-writer-attempt', task_id, number + 1, agent_id,
                       'acp/stale-writer', worktree, claim_token + 1, start_sha,
                       checkpoint_json, 'provisioning', lease_expires_at, created_at,
                       updated_at, base_checkout_snapshot_json
                FROM attempts WHERE id = ?
                """,
                (attempt["id"],),
            )

        marker, snapshot = connection.execute(
            "SELECT base_checkout_snapshot_required, base_checkout_snapshot_json "
            "FROM attempts WHERE id = ?",
            (attempt["id"],),
        ).fetchone()
        assert marker == 0
        assert snapshot


def test_read_only_open_refuses_version_two_before_touching_database(repo: Path) -> None:
    """v2 databases lack independent heartbeat/checkpoint timestamps."""

    connection = sqlite3.connect(db_path(repo))
    connection.execute("DROP TRIGGER attempts_require_base_checkout_snapshot")
    connection.execute("ALTER TABLE attempts DROP COLUMN base_checkout_snapshot_required")
    connection.execute("ALTER TABLE attempts DROP COLUMN checkpoint_at")
    connection.execute("ALTER TABLE attempts DROP COLUMN heartbeat_at")
    connection.execute("ALTER TABLE attempts DROP COLUMN base_checkout_snapshot_json")
    connection.execute("UPDATE meta SET value = '2' WHERE key = ?", (SCHEMA_VERSION_KEY,))
    connection.commit()
    connection.close()

    before = fingerprint(repo)
    with pytest.raises(SupervisorError) as error:
        GitSupervisor(repo, read_only=True)
    assert error.value.code == "schema_upgrade_required"
    assert "version 2" in str(error.value)
    assert fingerprint(repo) == before


def test_read_write_open_applies_all_migrations_from_version_two(repo: Path) -> None:
    original = GitSupervisor(repo)
    created = make_task(original, "alpha.txt")
    attempt = original.claim(created["id"], "agent-a")
    with original.connect() as connection:
        connection.execute(
            "UPDATE attempts SET checkpoint_json = ? WHERE id = ?",
            ('{"phase":"tests"}', attempt["id"]),
        )

    connection = sqlite3.connect(db_path(repo))
    connection.execute("DROP TRIGGER attempts_require_base_checkout_snapshot")
    connection.execute("ALTER TABLE attempts DROP COLUMN base_checkout_snapshot_required")
    connection.execute("ALTER TABLE attempts DROP COLUMN checkpoint_at")
    connection.execute("ALTER TABLE attempts DROP COLUMN heartbeat_at")
    connection.execute("ALTER TABLE attempts DROP COLUMN base_checkout_snapshot_json")
    connection.execute("UPDATE meta SET value = '2' WHERE key = ?", (SCHEMA_VERSION_KEY,))
    connection.commit()
    connection.close()

    supervisor = GitSupervisor(repo)
    assert supervisor.schema_version_on_open == 2
    assert meta(repo)[SCHEMA_VERSION_KEY] == str(SCHEMA_VERSION)
    with supervisor.connect() as migrated:
        columns = {row["name"] for row in migrated.execute("PRAGMA table_info(attempts)")}
        snapshot = migrated.execute(
            "SELECT base_checkout_snapshot_json FROM attempts WHERE id = ?", (attempt["id"],)
        ).fetchone()[0]
    assert {
        "heartbeat_at",
        "checkpoint_at",
        "base_checkout_snapshot_json",
        "base_checkout_snapshot_required",
    } <= columns
    assert snapshot == ""
    restored = supervisor.attempt(attempt["id"])
    assert restored["checkpoint"] == {"phase": "tests"}
    assert restored["heartbeat_at"] == ""
    assert restored["checkpoint_at"] == ""
    status = supervisor.status(checkpoint_stale_seconds=1)
    entry = next(item for item in status["tasks"] if item["task_id"] == created["id"])
    assert entry["heartbeat_age_seconds"] is None
    assert entry["checkpoint_age_seconds"] is None
    assert entry["checkpoint_stale_advisory"] is False


def test_read_write_open_refuses_a_database_from_the_future(repo: Path) -> None:
    write_meta(repo, SCHEMA_VERSION_KEY, str(SCHEMA_VERSION + 1))
    before = fingerprint(repo)
    with pytest.raises(SupervisorError) as error:
        GitSupervisor(repo)
    assert error.value.code == "schema_newer_than_binary"
    assert str(SCHEMA_VERSION + 1) in str(error.value)
    # The refusal has to come before the first CREATE or ALTER, or it is a check on a
    # database this binary already wrote to.
    assert fingerprint(repo) == before


def test_read_only_open_refuses_a_database_from_the_future(repo: Path) -> None:
    write_meta(repo, SCHEMA_VERSION_KEY, str(SCHEMA_VERSION + 1))
    with pytest.raises(SupervisorError) as error:
        GitSupervisor(repo, read_only=True)
    assert error.value.code == "schema_newer_than_binary"


def test_read_only_open_refuses_a_database_behind_the_binary(repo: Path) -> None:
    drop_meta(repo, SCHEMA_VERSION_KEY)
    with pytest.raises(SupervisorError) as error:
        GitSupervisor(repo, read_only=True)
    assert error.value.code == "schema_upgrade_required"
    assert "acp migrate" in str(error.value)


def test_read_only_status_leaves_a_stale_database_byte_identical(repo: Path) -> None:
    """The gate: a read-only command reports the upgrade instead of performing it."""

    drop_meta(repo, SCHEMA_VERSION_KEY)
    before = fingerprint(repo)
    assert main(["--repo", str(repo), "status"]) == 1
    assert fingerprint(repo) == before
    assert SCHEMA_VERSION_KEY not in meta(repo)


def test_read_write_open_upgrades_an_unstamped_database(repo: Path) -> None:
    drop_meta(repo, SCHEMA_VERSION_KEY)
    supervisor = GitSupervisor(repo)
    assert supervisor.schema_version_on_open is None
    assert meta(repo)[SCHEMA_VERSION_KEY] == str(SCHEMA_VERSION)
    assert supervisor.migrate() == {
        "ok": True,
        "previous": None,
        "current": SCHEMA_VERSION,
        "version_changed": True,
    }


def test_a_stamp_that_is_not_a_version_is_never_guessed(repo: Path) -> None:
    write_meta(repo, SCHEMA_VERSION_KEY, "v2-ish")
    with pytest.raises(SupervisorError) as error:
        GitSupervisor(repo)
    assert error.value.code == "schema_version_unreadable"


def test_a_read_only_connection_cannot_write(repo: Path) -> None:
    supervisor = GitSupervisor(repo, read_only=True)
    with (
        supervisor.connect() as connection,
        pytest.raises(sqlite3.OperationalError, match="readonly"),
    ):
        connection.execute("INSERT INTO meta(key, value) VALUES('probe', '1')")


def test_read_only_commands_leave_the_database_byte_identical(repo: Path) -> None:
    supervisor = GitSupervisor(repo, read_only=True)
    before = fingerprint(repo)
    supervisor.ready_queue()
    supervisor.merge_plan()
    supervisor.reviewers()
    supervisor.verify_event_chain()
    assert fingerprint(repo) == before


def test_list_is_excluded_because_it_reaps(repo: Path) -> None:
    """`list` prints a listing but mutates, so it must not be routed read-only.

    An empty repository hides this: `reap_expired()` with nothing to reap writes
    nothing, so `list` under mode=ro looks read-only right up until an attempt
    actually expires. This test supplies the expired attempt.
    """

    assert "list" not in READ_ONLY_ACTIONS

    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "agent-a")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET lease_expires_at = 0 WHERE id = ?", (attempt["id"],)
        )
        connection.execute(
            "UPDATE resource_leases SET lease_expires_at = 0 WHERE attempt_id = ?",
            (attempt["id"],),
        )

    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        GitSupervisor(repo, read_only=True).list_tasks()


def test_the_fingerprint_notices_a_write(repo: Path) -> None:
    """Positive control for the test above.

    Without it, "identical" would also be what a broken fingerprint returns.
    """

    before = fingerprint(repo)
    GitSupervisor(repo).reap_expired()
    assert fingerprint(repo) != before


def test_mutating_actions_are_not_routed_read_only() -> None:
    assert READ_ONLY_ACTIONS.isdisjoint(
        {"init", "migrate", "reap", "list", "claim", "submit", "qc", "integrate", "terminate"}
    )
    # doctor stays read-write on purpose: it is what an operator runs when the database
    # needs upgrading, so refusing to open one would hide the answer they came for.
    assert "doctor" not in READ_ONLY_ACTIONS


def test_doctor_reports_the_schema_version(repo: Path) -> None:
    report = GitSupervisor(repo, diagnostic=True).doctor()
    schema = next(check for check in report["checks"] if check["name"] == "schema")
    assert schema["ok"] is True
    assert f"version {SCHEMA_VERSION}" in schema["detail"]
    assert __version__ in schema["detail"]


def test_the_migration_ledger_applies_in_order_and_stamps(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Version 1 needs no ledger entry, so prove the mechanism with injected upgrades.

    An empty MIGRATIONS tuple would otherwise let a ledger that never runs look correct.
    """

    applied: list[int] = []

    def add_index(connection: sqlite3.Connection) -> None:
        applied.append(2)
        connection.execute("CREATE INDEX IF NOT EXISTS ix_probe ON tasks(status)")

    def backfill(connection: sqlite3.Connection) -> None:
        applied.append(3)
        connection.execute("UPDATE meta SET value = value WHERE key = ?", (SCHEMA_VERSION_KEY,))

    first, second = SCHEMA_VERSION + 1, SCHEMA_VERSION + 2
    monkeypatch.setattr(git_supervisor, "SCHEMA_VERSION", second)
    monkeypatch.setattr(git_supervisor, "MIGRATIONS", ((first, add_index), (second, backfill)))

    supervisor = GitSupervisor(repo)

    assert applied == [2, 3]
    assert meta(repo)[SCHEMA_VERSION_KEY] == str(second)
    assert supervisor.schema_version_on_open == SCHEMA_VERSION
    # An index is the case the ADD COLUMN pattern could not express at all.
    with supervisor.connect() as connection:
        names = {row["name"] for row in connection.execute("PRAGMA index_list(tasks)")}
    assert "ix_probe" in names

    # Re-opening must not replay an upgrade the database has already recorded.
    applied.clear()
    GitSupervisor(repo)
    assert applied == []


def test_a_failed_upgrade_leaves_the_version_where_it_started(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A half-applied ledger must not be stamped as if it finished."""

    def add_index(connection: sqlite3.Connection) -> None:
        connection.execute("CREATE INDEX IF NOT EXISTS ix_probe ON tasks(status)")

    def explodes(connection: sqlite3.Connection) -> None:
        raise sqlite3.OperationalError("upgrade 3 failed halfway")

    first, second = SCHEMA_VERSION + 1, SCHEMA_VERSION + 2
    monkeypatch.setattr(git_supervisor, "SCHEMA_VERSION", second)
    monkeypatch.setattr(git_supervisor, "MIGRATIONS", ((first, add_index), (second, explodes)))

    with pytest.raises(sqlite3.OperationalError):
        GitSupervisor(repo)

    # Not `first`: the entry that succeeded rolls back with the one that did not.
    assert meta(repo)[SCHEMA_VERSION_KEY] == str(SCHEMA_VERSION)
    connection = sqlite3.connect(db_path(repo))
    try:
        names = {row[1] for row in connection.execute("PRAGMA index_list(tasks)")}
    finally:
        connection.close()
    assert "ix_probe" not in names


def test_the_declared_write_set_is_shown_as_the_operator_typed_it(repo: Path) -> None:
    """`normalize_resource` casefolds, and the folded string is the lease PRIMARY KEY.

    So the stored form cannot carry the operator's capitalisation without rewriting
    lease identity. A separate column does, and only the display reads it — every
    operator surface used to print `changelog.md` at someone who wrote `CHANGELOG.md`,
    a path that does not exist on a case-sensitive checkout.
    """

    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "CHANGELOG.md", "Docs/READMEs.md")
    attempt = supervisor.claim(created["id"], "worker")

    assert created["resources"] == ["changelog.md", "docs/readmes.md"]  # lease keys, unchanged
    assert supervisor.guard_context(attempt["id"])["declared"] == [
        "CHANGELOG.md",
        "Docs/READMEs.md",
    ]


@pytest.mark.parametrize("recorded_case, allow_lower", [("0", True), ("1", False)])
def test_declared_display_preserves_filesystem_matching_policy(
    repo: Path, recorded_case: str, allow_lower: bool
) -> None:
    """Drive both recorded policies; test_resource_case verifies the real volume probe.

    Display preservation must not override the filesystem-aware matching added in
    #1708. The old unconditional case-insensitive expectation allowed an undeclared
    write on a case-sensitive volume and consequently failed Linux CI.
    """

    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "CHANGELOG.md")
    attempt = supervisor.claim(created["id"], "worker")
    with supervisor.connect() as connection:
        updated = connection.execute(
            "UPDATE meta SET value = ? WHERE key = ?",
            (recorded_case, git_supervisor.META_CASE_SENSITIVE),
        )
        assert updated.rowcount == 1
    assert created["resources"] == ["changelog.md"]  # folded lease identity stays unchanged
    assert supervisor.guard_context(attempt["id"])["declared"] == ["CHANGELOG.md"]
    assert supervisor.guard(attempt["id"], "CHANGELOG.md")["allow"] is True
    lower = supervisor.guard(attempt["id"], "changelog.md")
    assert lower["allow"] is allow_lower
    if not allow_lower:
        assert lower["reason"] == "undeclared_write"


def test_a_task_created_before_the_column_still_displays(repo: Path) -> None:
    """Legacy rows have no map, and the raw form is not recoverable from anywhere.

    The fallback is the folded string rather than a guess at its capitalisation.
    """

    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "CHANGELOG.md")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE tasks SET declared_resources_json = '{}' WHERE id = ?", (created["id"],)
        )
    attempt = supervisor.claim(created["id"], "worker")
    assert supervisor.guard_context(attempt["id"])["declared"] == ["changelog.md"]


def test_the_ledger_upgrades_a_version_one_database(repo: Path) -> None:
    """Entry 2 is the ledger's first real use; this drives it on a v1-shaped database."""

    with GitSupervisor(repo).connect() as connection:
        connection.execute("UPDATE meta SET value = '1' WHERE key = ?", (SCHEMA_VERSION_KEY,))
        connection.execute("ALTER TABLE tasks DROP COLUMN declared_resources_json")

    supervisor = GitSupervisor(repo)

    assert supervisor.schema_version_on_open == 1
    assert meta(repo)[SCHEMA_VERSION_KEY] == str(SCHEMA_VERSION)
    connection = sqlite3.connect(db_path(repo))
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(tasks)")}
    finally:
        connection.close()
    assert "declared_resources_json" in columns
