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
from pathlib import Path

import pytest

from agent_control_plane import __version__
from agent_control_plane.database import SERVICE_SCHEMA_VERSION, Database
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


def test_a_corrupt_stamp_is_not_guessed(database_path: Path) -> None:
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
