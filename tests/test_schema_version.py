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
from support import init_repo, make_task

from agent_control_plane import __version__, git_supervisor
from agent_control_plane.cli import READ_ONLY_ACTIONS, main
from agent_control_plane.git_supervisor import (
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


def test_matching_is_still_case_insensitive(repo: Path) -> None:
    """The control: preserving the display must not tighten what the guard accepts."""

    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "CHANGELOG.md")
    attempt = supervisor.claim(created["id"], "worker")
    assert supervisor.guard(attempt["id"], "CHANGELOG.md")["allow"] is True
    assert supervisor.guard(attempt["id"], "changelog.md")["allow"] is True


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
