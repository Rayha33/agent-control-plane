"""Schema version stamping shared by the two SQLite databases in this package.

The supervisor's `.acp/control.db` and the FastAPI service database are separate files
with separate lifecycles, and they version INDEPENDENTLY — each keeps its own
SCHEMA_VERSION constant and its own ledger. What they share is the mechanism: record
the version, refuse a database written by a newer binary, and apply numbered upgrades.

Sharing the mechanism rather than copying it matters for the refusal in particular.
An older binary opening a newer database does not fail on its own — `CREATE TABLE IF
NOT EXISTS` leaves the newer tables alone and every `PRAGMA table_info` check finds
its column already present — so the open succeeds and the newer columns are simply
invisible. Two copies of that check would eventually stop agreeing about it.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable

SCHEMA_VERSION_KEY = "schema_version"
SCHEMA_WRITTEN_BY_KEY = "written_by"

Migration = tuple[int, Callable[[sqlite3.Connection], None]]

META_TABLE = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
"""


class SchemaVersionError(RuntimeError):
    """Carries a `code` so callers can translate it into their own error type."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def stored_schema_version(connection: sqlite3.Connection) -> int | None:
    """Version recorded in this database, or None when it predates stamping.

    None means "older than 1", not "unknown": a database written before versioning has
    no meta row, and one written before `meta` existed has no table. A stamp that is
    present but not an integer is a different thing entirely — that is corruption, and
    guessing a version for it would migrate a database we cannot identify.
    """

    try:
        row = connection.execute(
            "SELECT value FROM meta WHERE key = ?", (SCHEMA_VERSION_KEY,)
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    if row is None:
        return None
    value = row["value"] if isinstance(row, sqlite3.Row) else row[0]
    try:
        return int(value)
    except (TypeError, ValueError):
        raise SchemaVersionError(
            "schema_version_unreadable",
            f"meta.{SCHEMA_VERSION_KEY} is {value!r}, which is not a version number; "
            "the database is corrupt or was not written by acp",
        ) from None


def assert_schema_not_newer(
    stored: int | None, *, binary_version: int, component: str, package_version: str
) -> None:
    """Refuse a database written by a newer binary than this one.

    Call this BEFORE the first CREATE or ALTER, or it is a check on a database this
    binary has already written to.
    """

    if stored is not None and stored > binary_version:
        raise SchemaVersionError(
            "schema_newer_than_binary",
            f"{component} is at schema version {stored}; this acp ({package_version}) "
            f"understands version {binary_version}. Upgrade acp — an older binary "
            "cannot see the newer columns and would operate on a partial view of the "
            "state.",
        )


def stamp_schema_version(
    connection: sqlite3.Connection, *, version: int, package_version: str
) -> None:
    for key, value in (
        (SCHEMA_VERSION_KEY, str(version)),
        (SCHEMA_WRITTEN_BY_KEY, package_version),
    ):
        connection.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (key, value))


def apply_migration_ledger(
    connection: sqlite3.Connection, stored: int | None, migrations: tuple[Migration, ...]
) -> None:
    """Apply every numbered upgrade this database has not seen, in order.

    `stored` is None for a database that predates stamping; the baseline schema has
    just brought it to version 1, so it starts here from 1 like any other.

    The caller's transaction is the boundary, and it is deliberately ONE transaction
    for the whole ledger rather than one per entry: an upgrade that fails halfway
    should leave the database at the version it arrived at, not at whichever entry
    happened to be the last to succeed. Each stamp is written next to the change it
    describes, so both roll back together.
    """

    current = 1 if stored is None else stored
    for version, upgrade in migrations:
        if version <= current:
            continue
        upgrade(connection)
        connection.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)",
            (SCHEMA_VERSION_KEY, str(version)),
        )
        current = version
