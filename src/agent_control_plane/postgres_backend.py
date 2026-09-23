"""PostgreSQL storage for the HTTP coordination service, so more than one host can share it.

Board #568. SQLite gives the service exactly one property the invariants lean on: every write
transaction runs alone. `BEGIN IMMEDIATE` takes the file's single write lock before the first
read of the transaction, so a claim that reads "no live lease on this resource" and then writes
its own lease cannot interleave with another claim doing the same thing, and two audit events
can never be built on the same predecessor hash. That lock is a property of one file on one
host. This module reproduces it for PostgreSQL, where the writers are separate processes on
separate machines.

How a write transaction is serialised
-------------------------------------
1. ``pg_advisory_lock(key)`` — a SESSION-level advisory lock, taken while the connection is
   still in autocommit and therefore BEFORE any transaction snapshot exists.
2. ``SERIALIZABLE`` transaction, then the caller's reads and writes.
3. commit (or rollback), then ``pg_advisory_unlock(key)``.

The order of 1 and 2 is load-bearing, and it is the easy thing to get wrong. Taking
``pg_advisory_xact_lock`` as the first statement INSIDE a serializable transaction looks
equivalent, but PostgreSQL fixes a serializable transaction's snapshot at the start of its first
statement — which is the lock call itself, before it waits. A writer that queued behind another
would then read the world as it was before that writer committed, and every such contention
would surface as ``40001 could not serialize access``. Taking the lock first means the snapshot
is taken after the previous writer has committed, so contention costs waiting, not aborts.
``tests/test_multihost_races.py`` measures both orders.

SERIALIZABLE is kept anyway, as the net under the lock rather than the mechanism: a future
write path that forgets the lock gets a serialization failure, which fails closed, instead of
silently granting two leases. The same suite shows that too.

A write the caller did not announce with ``BEGIN IMMEDIATE`` (a bare UPDATE) escalates to the
same locked transaction automatically, which is what SQLite does when a DML statement takes its
RESERVED lock. Reads outside a write transaction run in autocommit.

What it does not do
-------------------
- It does not retry. A serialization failure, lock timeout or lost connection is reported as
  :class:`~agent_control_plane.database.StorageBusyError` and the caller retries the whole
  request. Retrying inside would mean re-running a caller's Python between statements, which
  this layer cannot see.
- It is not a general SQLite emulator. It translates exactly the dialect the service uses
  (``?`` placeholders, ``BEGIN IMMEDIATE``, the ``meta`` upsert, the schema's column types) and
  raises :class:`UnsupportedSqlError` for SQLite-only statements such as ``PRAGMA``, so a code
  path that depends on SQLite fails loudly here instead of doing something nearby.
- It does not make lease EXPIRY safe across hosts with skewed clocks. Expiry decides liveness;
  the fencing tokens decide safety. A replica whose clock runs fast can orphan a live claim
  early, and the replaced runner is then fenced out — it cannot corrupt state, but it can lose
  work. Keep replica clocks disciplined.

Requires the optional ``postgres`` extra (``psycopg``).
"""

from __future__ import annotations

import hashlib
import re
import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from typing import Any

from .database import StorageBusyError

try:  # pragma: no cover - exercised only where the optional extra is installed
    import psycopg
    from psycopg import errors as pg_errors
    from psycopg.conninfo import conninfo_to_dict
    from psycopg.pq import TransactionStatus
except ImportError:  # pragma: no cover
    psycopg = None  # type: ignore[assignment]

DIALECT = "postgresql"

# Keepalive defaults so a peer that vanished mid-transaction is noticed in seconds rather than
# after the kernel's two-hour default. Values in the URL win.
_KEEPALIVE_DEFAULTS = {
    "keepalives": "1",
    "keepalives_idle": "10",
    "keepalives_interval": "5",
    "keepalives_count": "3",
    "connect_timeout": "10",
}

_BEGIN_IMMEDIATE = re.compile(r"^\s*BEGIN\s+IMMEDIATE\s*;?\s*$", re.IGNORECASE)
_META_UPSERT = re.compile(
    r"^\s*INSERT\s+OR\s+REPLACE\s+INTO\s+meta\s*\(\s*key\s*,\s*value\s*\)\s*"
    r"VALUES\s*\(\s*(?P<values>[^)]*)\)\s*;?\s*$",
    re.IGNORECASE,
)
_SQLITE_ONLY = re.compile(
    r"\bPRAGMA\b|\bsqlite_master\b|\bINSERT\s+OR\s+(REPLACE|IGNORE)\b|\bAUTOINCREMENT\b",
    re.IGNORECASE,
)
_MUTATING = re.compile(r"^\s*(INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE)\b", re.IGNORECASE)


class UnsupportedSqlError(RuntimeError):
    """A SQLite-only statement reached the PostgreSQL backend."""


def require_psycopg() -> None:
    if psycopg is None:
        raise RuntimeError(
            "a postgresql:// database needs the optional dependency: "
            "pip install 'agent-control-plane[postgres]'"
        )


# ------------------------------------------------------------------------ translation ----


def _segments(sql: str) -> Iterator[tuple[bool, str]]:
    """Split SQL into (is_code, text) runs; quoted strings, identifiers and comments are not code."""

    index = 0
    start = 0
    length = len(sql)
    while index < length:
        char = sql[index]
        if char in ("'", '"'):
            if start < index:
                yield True, sql[start:index]
            end = index + 1
            while end < length:
                if sql[end] == char:
                    if end + 1 < length and sql[end + 1] == char:
                        end += 2
                        continue
                    break
                end += 1
            yield False, sql[index : end + 1]
            index = start = end + 1
            continue
        if sql.startswith("--", index):
            if start < index:
                yield True, sql[start:index]
            end = sql.find("\n", index)
            end = length if end == -1 else end
            yield False, sql[index:end]
            index = start = end
            continue
        index += 1
    if start < length:
        yield True, sql[start:]


def translate_query(sql: str) -> str:
    """``?`` placeholders become ``%s``; a literal ``%`` is escaped for psycopg's parser."""

    parts: list[str] = []
    for is_code, text in _segments(sql):
        text = text.replace("%", "%%")
        parts.append(text.replace("?", "%s") if is_code else text)
    return "".join(parts)


def translate_ddl(script: str) -> str:
    """Map the SQLite schema's column types onto PostgreSQL, without touching literals.

    - ``INTEGER PRIMARY KEY AUTOINCREMENT`` becomes an identity column.
    - ``INTEGER`` becomes ``BIGINT``: the schema stores epoch seconds, which outgrow a 32-bit
      column in 2038, and SQLite's INTEGER was always 64-bit.
    - ``TEXT`` gets ``COLLATE "C"``: SQLite compares TEXT bytewise (BINARY), and the service
      orders by ISO-8601 text timestamps. A locale collation that ignores punctuation would
      reorder ``…:00+00:00`` against ``…:00.000001+00:00``.
    """

    parts: list[str] = []
    for is_code, text in _segments(script):
        if is_code:
            text = re.sub(
                r"\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b",
                "BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY",
                text,
                flags=re.IGNORECASE,
            )
            text = re.sub(r"\bINTEGER\b", "BIGINT", text, flags=re.IGNORECASE)
            text = re.sub(r"\bTEXT\b", 'TEXT COLLATE "C"', text, flags=re.IGNORECASE)
        parts.append(text)
    return "".join(parts)


def split_script(script: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    for is_code, text in _segments(script):
        if not is_code:
            if not text.startswith("--"):
                current.append(text)
            continue
        pieces = text.split(";")
        for position, piece in enumerate(pieces):
            current.append(piece)
            if position < len(pieces) - 1:
                statement = "".join(current).strip()
                if statement:
                    statements.append(statement)
                current = []
    tail = "".join(current).strip()
    if tail:
        statements.append(tail)
    return statements


def advisory_lock_key(namespace: str) -> int:
    """A signed 64-bit key for ``pg_advisory_lock``, scoped to one database + schema."""

    digest = hashlib.sha256(f"agent-control-plane:write:{namespace}".encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


# ------------------------------------------------------------------------------ rows -----


class PostgresRow(Sequence):
    """Behaves like ``sqlite3.Row``: index by position or column name, ``dict(row)`` works."""

    __slots__ = ("_index", "_values")

    def __init__(self, index: Mapping[str, int], values: Sequence[Any]):
        self._index = index
        self._values = tuple(values)

    def __getitem__(self, key: Any) -> Any:  # type: ignore[override]
        if isinstance(key, str):
            try:
                return self._values[self._index[key]]
            except KeyError:
                raise IndexError(f"no such column: {key}") from None
        return self._values[key]

    def __len__(self) -> int:
        return len(self._values)

    def __iter__(self) -> Iterator[Any]:
        return iter(self._values)

    def keys(self) -> list[str]:
        return list(self._index)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, PostgresRow):
            return self._values == other._values and self.keys() == other.keys()
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._values)

    def __repr__(self) -> str:
        return f"PostgresRow({dict(zip(self._index, self._values, strict=False))!r})"


def _row_factory(cursor: Any) -> Any:
    description = cursor.description
    if description is None:
        return lambda values: values
    index: dict[str, int] = {}
    for position, column in enumerate(description):
        # sqlite3.Row answers a duplicated column name with its FIRST occurrence.
        index.setdefault(column.name, position)
    return lambda values: PostgresRow(index, values)


class _Result:
    """The subset of the DB-API cursor the service reads: fetchone, fetchall, rowcount."""

    def __init__(self, cursor: Any | None):
        self._cursor = cursor

    @property
    def rowcount(self) -> int:
        return -1 if self._cursor is None else self._cursor.rowcount

    def fetchone(self) -> Any:
        if self._cursor is None or self._cursor.description is None:
            return None
        return self._cursor.fetchone()

    def fetchall(self) -> list[Any]:
        if self._cursor is None or self._cursor.description is None:
            return []
        return self._cursor.fetchall()


# ------------------------------------------------------------------------ connection -----


def _busy(error: Exception) -> StorageBusyError:
    sqlstate = getattr(error, "sqlstate", None) or ""
    if sqlstate == "40001":
        code = "storage_serialization_conflict"
    elif sqlstate == "40P01":
        code = "storage_deadlock"
    elif sqlstate in {"55P03", "57014"}:
        code = "storage_lock_timeout"
    else:
        code = "storage_unavailable"
    return StorageBusyError(code, f"{code}: {type(error).__name__}: {error}".strip())


def _retryable(error: Exception, raw: Any = None) -> bool:
    """True when the request did not apply (or may not have) and can be retried whole."""

    if psycopg is None:  # pragma: no cover
        return False
    if raw is not None and (raw.closed or raw.broken):
        # However psycopg classifies the error, a dead session means storage is unavailable.
        # IdleInTransactionSessionTimeout, for one, is class 25 and not an OperationalError.
        return True
    return isinstance(
        error,
        (
            pg_errors.SerializationFailure,
            pg_errors.DeadlockDetected,
            pg_errors.LockNotAvailable,
            pg_errors.QueryCanceled,
            pg_errors.IdleInTransactionSessionTimeout,
            psycopg.OperationalError,
        ),
    )


class PostgresConnection:
    """One service transaction on one PostgreSQL session. See the module docstring."""

    dialect = DIALECT

    def __init__(
        self,
        raw: Any,
        lock_key: int,
        backend: PostgresBackend | None = None,
        applied: tuple[int, int] | None = None,
    ):
        self._raw = raw
        self._lock_key = lock_key
        self._backend = backend
        self._applied = applied
        self._write = False
        self._lock_held = False
        self._used = False

    # The service asserts this before appending an audit event into the caller's transaction.
    @property
    def in_transaction(self) -> bool:
        return self._write or self._raw.info.transaction_status != TransactionStatus.IDLE

    @property
    def raw(self) -> Any:
        """The psycopg connection, for tests that need to inject faults."""

        return self._raw

    def begin_write(self) -> None:
        if self._write:
            return
        self._run(self._open_write_transaction)
        self._write = True

    def _open_write_transaction(self) -> None:
        self._acquire_lock()
        self._raw.autocommit = False
        self._raw.isolation_level = psycopg.IsolationLevel.SERIALIZABLE
        # Open the transaction NOW, straight after the lock. Its snapshot is therefore taken
        # after the previous writer committed, and a client that partitions from here on is
        # "idle in transaction", which the server evicts after idle_timeout_seconds.
        self._raw.execute("SELECT 1")

    def _acquire_lock(self) -> None:
        """Take the write lock before the transaction exists. Overridden only by tests."""

        self._raw.execute("SELECT pg_advisory_lock(%s)", (self._lock_key,))
        self._lock_held = True

    def _run(self, action: Any) -> Any:
        """Run one statement, mapping storage failures onto StorageBusyError.

        A pooled session can die while idle (server restart, failover, an operator ending it).
        When that surfaces on the FIRST statement of a request, nothing has applied — the first
        statement is always a read or the write lock — so the session is replaced and the
        statement re-run once. Any later failure is reported, never retried here.
        """

        first = not self._used
        self._used = True
        try:
            return action()
        except Exception as error:
            dead = self._raw.closed or self._raw.broken
            if not (first and dead and self._backend is not None):
                if _retryable(error, self._raw):
                    raise _busy(error) from error
                raise
        self._lock_held = False
        self._backend._discard(self._raw)
        self._raw, self._applied = self._backend._fresh()
        try:
            return action()
        except Exception as error:
            if _retryable(error, self._raw):
                raise _busy(error) from error
            raise

    def execute(self, sql: str, parameters: Sequence[Any] = ()) -> _Result:
        if _BEGIN_IMMEDIATE.match(sql):
            self.begin_write()
            return _Result(None)
        match = _META_UPSERT.match(sql)
        if match:
            sql = (
                f"INSERT INTO meta(key, value) VALUES ({match.group('values')}) "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
            )
        elif _SQLITE_ONLY.search("".join(text for code, text in _segments(sql) if code)):
            raise UnsupportedSqlError(f"SQLite-only SQL reached PostgreSQL: {sql.strip()[:120]}")
        if _MUTATING.match(sql):
            self.begin_write()
        translated = translate_query(sql)
        values = tuple(parameters)

        def run() -> Any:
            cursor = self._raw.cursor()
            cursor.execute(translated, values)
            return cursor

        return _Result(self._run(run))

    def executescript(self, script: str) -> None:
        self.begin_write()
        for statement in split_script(translate_ddl(script)):
            if _SQLITE_ONLY.search(statement):
                raise UnsupportedSqlError(
                    f"SQLite-only SQL reached PostgreSQL: {statement.strip()[:120]}"
                )
            self._run(lambda statement=statement: self._raw.execute(statement))

    def commit(self) -> None:
        try:
            if self._write:
                self._raw.commit()
        except Exception as error:
            if _retryable(error, self._raw):
                raise _busy(error) from error
            raise
        finally:
            self._end_write()

    def rollback(self) -> None:
        try:
            if not self._raw.closed and self._raw.info.transaction_status != TransactionStatus.IDLE:
                self._raw.rollback()
        except Exception:  # noqa: BLE001 - a dead session has nothing left to roll back
            pass
        finally:
            self._end_write()

    def _end_write(self) -> None:
        self._write = False
        if self._raw.closed:
            self._lock_held = False
            return
        try:
            if self._raw.info.transaction_status != TransactionStatus.IDLE:
                self._raw.rollback()
            self._raw.autocommit = True
            if self._lock_held:
                self._raw.execute("SELECT pg_advisory_unlock(%s)", (self._lock_key,))
        except Exception:  # noqa: BLE001 - closing the session releases the lock regardless
            try:
                self._raw.close()
            except Exception:  # noqa: BLE001
                pass
        finally:
            self._lock_held = False

    def close(self) -> None:
        if self._backend is not None:
            self._backend._release(self._raw, self._applied)
            return
        try:
            self._raw.close()
        except Exception:  # noqa: BLE001
            pass


class PostgresBackend:
    """Pooled PostgreSQL sessions for :class:`~agent_control_plane.database.Database`.

    Sessions are reused. Opening one per statement, the SQLite habit, costs a TCP (and TLS)
    handshake per query and, measured on this suite's multi-process race run, exhausted the
    client's ephemeral ports within seconds. A session returns to the pool only when it is
    healthy, idle, in autocommit and holding no lock; anything else is closed.
    """

    dialect = DIALECT
    connection_class: type[PostgresConnection] = PostgresConnection

    def __init__(
        self,
        url: str,
        *,
        lock_timeout_seconds: float = 30.0,
        idle_timeout_seconds: float = 60.0,
        max_idle_connections: int = 8,
    ):
        require_psycopg()
        self.url = url
        self.lock_timeout_seconds = lock_timeout_seconds
        self.idle_timeout_seconds = idle_timeout_seconds
        self.max_idle_connections = max_idle_connections
        self._lock_key: int | None = None
        self._idle: list[tuple[Any, tuple[int, int]]] = []
        self._pool_lock = threading.Lock()

    def _wanted(self) -> tuple[int, int]:
        return int(self.lock_timeout_seconds * 1000), int(self.idle_timeout_seconds * 1000)

    def _open(self) -> Any:
        settings = conninfo_to_dict(self.url)
        extra = {key: value for key, value in _KEEPALIVE_DEFAULTS.items() if key not in settings}
        try:
            raw = psycopg.connect(self.url, autocommit=True, row_factory=_row_factory, **extra)
            if self._lock_key is None:
                namespace = raw.execute("SELECT current_database() || '.' || current_schema()")
                self._lock_key = advisory_lock_key(namespace.fetchone()[0])
        except psycopg.OperationalError as error:
            raise _busy(error) from error
        return raw

    def _configure(self, raw: Any, applied: tuple[int, int] | None) -> tuple[int, int]:
        wanted = self._wanted()
        if applied != wanted:
            # lock_timeout bounds a wait for the write lock. idle_in_transaction_session_timeout
            # bounds how long a client that partitioned away WHILE HOLDING it can stall every
            # other host: the server ends that session, rolling back and releasing the lock.
            raw.execute(f"SET lock_timeout = {wanted[0]}")
            raw.execute(f"SET idle_in_transaction_session_timeout = {wanted[1]}")
        return wanted

    def _fresh(self) -> tuple[Any, tuple[int, int]]:
        raw = self._open()
        try:
            return raw, self._configure(raw, None)
        except psycopg.Error as error:
            self._discard(raw)
            raise _busy(error) from error

    def _checkout(self) -> tuple[Any, tuple[int, int]]:
        while True:
            with self._pool_lock:
                entry = self._idle.pop() if self._idle else None
            if entry is None:
                return self._fresh()
            raw, applied = entry
            if raw.closed or raw.broken:
                self._discard(raw)
                continue
            try:
                return raw, self._configure(raw, applied)
            except psycopg.Error:
                # It died while pooled, before anything was sent on this request's behalf.
                self._discard(raw)

    def _release(self, raw: Any, applied: tuple[int, int] | None) -> None:
        healthy = (
            applied is not None
            and not raw.closed
            and not raw.broken
            and raw.autocommit
            and raw.info.transaction_status == TransactionStatus.IDLE
        )
        if healthy:
            with self._pool_lock:
                if len(self._idle) < self.max_idle_connections:
                    self._idle.append((raw, applied))
                    return
        self._discard(raw)

    @staticmethod
    def _discard(raw: Any) -> None:
        try:
            raw.close()
        except Exception:  # noqa: BLE001
            pass

    def close(self) -> None:
        """Close every pooled session."""

        with self._pool_lock:
            idle, self._idle = self._idle, []
        for raw, _applied in idle:
            self._discard(raw)

    @contextmanager
    def connect(self) -> Iterator[PostgresConnection]:
        raw, applied = self._checkout()
        connection = self.connection_class(raw, self._lock_key or 0, self, applied)
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def describe(self) -> str:
        """The URL with any password removed — safe for logs and /health."""

        return redact_url(self.url)


def redact_url(url: str) -> str:
    return re.sub(r"(://[^:/@]+:)[^@]*@", r"\1***@", url)


__all__ = [
    "DIALECT",
    "PostgresBackend",
    "PostgresConnection",
    "PostgresRow",
    "UnsupportedSqlError",
    "advisory_lock_key",
    "redact_url",
    "require_psycopg",
    "split_script",
    "translate_ddl",
    "translate_query",
]
