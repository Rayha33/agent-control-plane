"""The control database connection and the hash-chained audit event log.

Every phase opens the database through `connect` and records what it did through `_event`,
so these two are the persistence primitives the other mixins share; `verify_event_chain`
is the read side of the same chain.

Moved verbatim out of `git_supervisor` (board #1630). `GitSupervisor` inherits this mixin, so
every call site, CLI path and `GitSupervisor.<name>` lookup resolves exactly as before.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any
from weakref import WeakKeyDictionary

from .common import GENESIS_HASH, SupervisorError, canonical_json, sha256, utc_now

_RUNNING_ATTESTATION_SQL_FUNCTION = "acp_sandbox_running_attestation_authorized"
_RAW_STORE_CONNECTIONS: WeakKeyDictionary[Any, sqlite3.Connection] = WeakKeyDictionary()
_RAW_STORE_CURSORS: WeakKeyDictionary[Any, sqlite3.Cursor] = WeakKeyDictionary()


class _StoreCursor:
    """Cursor facade that does not leak its mutable raw connection."""

    __slots__ = ("__weakref__",)

    def __init__(self, raw: sqlite3.Cursor) -> None:
        _RAW_STORE_CURSORS[self] = raw

    def __getattr__(self, name: str):
        if name == "connection":
            raise AttributeError("raw store connections are private")
        raw = _RAW_STORE_CURSORS[self]
        return getattr(raw, name)

    def __iter__(self):
        return self

    def __next__(self):
        return next(_RAW_STORE_CURSORS[self])

    def execute(self, *args, **kwargs):
        _RAW_STORE_CURSORS[self].execute(*args, **kwargs)
        return self

    def executemany(self, *args, **kwargs):
        _RAW_STORE_CURSORS[self].executemany(*args, **kwargs)
        return self


class _StoreConnection:
    """SQL facade that withholds callback-registration access to the raw connection."""

    __slots__ = ("__weakref__",)
    _BLOCKED = frozenset(
        {
            "create_aggregate",
            "create_collation",
            "create_function",
            "create_window_function",
            "deserialize",
            "enable_load_extension",
            "load_extension",
            "set_authorizer",
            "set_progress_handler",
            "set_trace_callback",
        }
    )

    def __init__(self, raw: sqlite3.Connection) -> None:
        _RAW_STORE_CONNECTIONS[self] = raw

    def __getattr__(self, name: str):
        if name in self._BLOCKED:
            raise AttributeError(f"{name} is reserved by the store connection")
        raw = _RAW_STORE_CONNECTIONS[self]
        return getattr(raw, name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "row_factory":
            raise AttributeError("row_factory is reserved by the store connection")
        raw = _RAW_STORE_CONNECTIONS[self]
        setattr(raw, name, value)

    def execute(self, *args, **kwargs) -> _StoreCursor:
        raw = _RAW_STORE_CONNECTIONS[self]
        return _StoreCursor(raw.execute(*args, **kwargs))

    def executemany(self, *args, **kwargs) -> _StoreCursor:
        raw = _RAW_STORE_CONNECTIONS[self]
        return _StoreCursor(raw.executemany(*args, **kwargs))

    def executescript(self, *args, **kwargs) -> _StoreCursor:
        raw = _RAW_STORE_CONNECTIONS[self]
        return _StoreCursor(raw.executescript(*args, **kwargs))

    def cursor(self, *args, **kwargs) -> _StoreCursor:
        raw = _RAW_STORE_CONNECTIONS[self]
        factory = kwargs.get("factory")
        if (
            args
            or set(kwargs) - {"factory"}
            or (factory is not None and factory is not sqlite3.Cursor)
        ):
            raise TypeError("custom cursor factories are not exposed by the store connection")
        return _StoreCursor(raw.cursor())

    def __enter__(self) -> _StoreConnection:
        raw = _RAW_STORE_CONNECTIONS[self]
        raw.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        raw = _RAW_STORE_CONNECTIONS[self]
        return raw.__exit__(exc_type, exc_value, traceback)


def _store_connection_identity(connection: Any) -> int:
    try:
        raw = _RAW_STORE_CONNECTIONS[connection]
    except (KeyError, TypeError):
        raw = connection
    return id(raw)


def _store_raw_connection_for_running_transition(connection: Any) -> sqlite3.Connection:
    """Return the backing connection for the journal's validated transition only."""

    if type(connection) is not _StoreConnection:
        raise TypeError("running authorization requires a store-owned connection")
    return _RAW_STORE_CONNECTIONS[connection]


_SANDBOX_EXIT_RECEIPT_AUTHORIZATION: ContextVar[
    tuple[int, tuple[str, int, str, int, str, int]] | None
] = ContextVar("acp_sandbox_exit_receipt_authorization", default=None)
_SANDBOX_LAUNCH_PLAN_AUTHORIZATION: ContextVar[
    tuple[int, tuple[str, int, str, str, str, str, str]] | None
] = ContextVar("acp_sandbox_launch_plan_authorization", default=None)
_SANDBOX_LAUNCH_SUBMISSION_AUTHORIZATION: ContextVar[
    tuple[int, tuple[str, int, str, str, str]] | None
] = ContextVar("acp_sandbox_launch_submission_authorization", default=None)
_SANDBOX_LAUNCH_DRIVER_START_AUTHORIZATION: ContextVar[
    tuple[int, tuple[str, int, str, str, str, str]] | None
] = ContextVar("acp_sandbox_launch_driver_start_authorization", default=None)
_SANDBOX_LAUNCH_DRIVER_REDEMPTION_AUTHORIZATION: ContextVar[tuple[int, tuple[Any, ...]] | None] = (
    ContextVar("acp_sandbox_launch_driver_redemption_authorization", default=None)
)
_SANDBOX_CLEANUP_ACTION_AUTHORIZATION: ContextVar[tuple[int, tuple[str, int, str, str]] | None] = (
    ContextVar("acp_sandbox_cleanup_action_authorization", default=None)
)
_SANDBOX_CLEANUP_REPORT_AUTHORIZATION: ContextVar[tuple[int, tuple[str, int, str, str]] | None] = (
    ContextVar("acp_sandbox_cleanup_report_authorization", default=None)
)
_SANDBOX_CLEANUP_VERIFICATION_AUTHORIZATION: ContextVar[
    tuple[int, tuple[str, int, str, str]] | None
] = ContextVar("acp_sandbox_cleanup_verification_authorization", default=None)
_SANDBOX_RESERVATION_AUTHORIZATION: ContextVar[
    tuple[int, tuple[str, int, str, str, str]] | None
] = ContextVar("acp_sandbox_reservation_authorization", default=None)


@contextmanager
def _authorize_sandbox_exit_receipt_write(
    connection: sqlite3.Connection, receipt: Any
) -> Iterator[None]:
    """Scope the SQLite exit-write capability to one validated wait receipt."""

    from .oci_worker import _runc_client_wait_receipt_is_self_consistent

    if not _runc_client_wait_receipt_is_self_consistent(receipt):
        raise SupervisorError(
            "sandbox_execution_wait_receipt_required",
            "runc exit persistence requires a registered pinned-runc wait receipt",
        )
    fields = (
        receipt.attempt_id,
        receipt.claim_token,
        receipt.execution_id,
        receipt.pid,
        receipt.process_identity,
        receipt.returncode,
    )
    token = _SANDBOX_EXIT_RECEIPT_AUTHORIZATION.set(
        (_store_connection_identity(connection), fields)
    )
    try:
        yield
    finally:
        _SANDBOX_EXIT_RECEIPT_AUTHORIZATION.reset(token)


def _sandbox_exit_receipt_authorized_for(connection: sqlite3.Connection):
    connection_id = id(connection)

    def authorized(
        attempt_id: str,
        claim_token: int,
        execution_id: str,
        runc_client_pid: int,
        runc_client_identity: str,
        exit_code: int,
    ) -> int:
        authorization = _SANDBOX_EXIT_RECEIPT_AUTHORIZATION.get()
        expected = (
            attempt_id,
            claim_token,
            execution_id,
            runc_client_pid,
            runc_client_identity,
            exit_code,
        )
        return int(
            authorization is not None
            and authorization[0] == connection_id
            and authorization[1] == expected
        )

    return authorized


@contextmanager
def _authorize_sandbox_launch_plan_write(
    connection: sqlite3.Connection,
    handle: Any,
    attempt_id: str,
    claim_token: int,
    execution_id: str,
    plan_json: str,
    plan_digest: str,
) -> Iterator[None]:
    """Scope one launch-plan update to the exact registered, bound runc handle."""

    import hashlib

    from .oci_worker import (
        RuncLaunchHandle,
        _runc_launch_handle_is_bound_to_execution,
        _runc_launch_handle_is_self_consistent,
        _runc_launch_target,
    )

    target = _runc_launch_target(handle)
    if (
        type(handle) is not RuncLaunchHandle
        or not _runc_launch_handle_is_self_consistent(handle)
        or target is None
        or not _runc_launch_handle_is_bound_to_execution(
            handle, attempt_id, claim_token, execution_id
        )
        or not isinstance(target.config_sha256, str)
        or len(target.config_sha256) != 64
        or not isinstance(target.argv, tuple)
        or any(not isinstance(value, str) for value in target.argv)
    ):
        raise SupervisorError(
            "sandbox_execution_launch_handle_required",
            "launch-plan persistence requires the exact registered runc handle",
        )
    config_digest = target.config_sha256
    argv_digest = hashlib.sha256(canonical_json(list(target.argv)).encode("utf-8")).hexdigest()
    if (
        not isinstance(plan_json, str)
        or not plan_json
        or hashlib.sha256(plan_json.encode("utf-8")).hexdigest() != plan_digest
    ):
        raise SupervisorError(
            "sandbox_execution_launch_plan_invalid",
            "launch-plan digest does not match its canonical journal payload",
        )
    fields = (
        attempt_id,
        claim_token,
        execution_id,
        config_digest,
        argv_digest,
        plan_digest,
        plan_json,
    )
    token = _SANDBOX_LAUNCH_PLAN_AUTHORIZATION.set((_store_connection_identity(connection), fields))
    try:
        yield
    finally:
        _SANDBOX_LAUNCH_PLAN_AUTHORIZATION.reset(token)


def _sandbox_launch_plan_authorized_for(connection: sqlite3.Connection):
    connection_id = id(connection)

    def authorized(
        attempt_id: str,
        claim_token: int,
        execution_id: str,
        config_digest: str,
        argv_digest: str,
        plan_digest: str,
        plan_json: str,
    ) -> int:
        authorization = _SANDBOX_LAUNCH_PLAN_AUTHORIZATION.get()
        expected = (
            attempt_id,
            claim_token,
            execution_id,
            config_digest,
            argv_digest,
            plan_digest,
            plan_json,
        )
        return int(
            authorization is not None
            and authorization[0] == connection_id
            and authorization[1] == expected
        )

    return authorized


@contextmanager
def _authorize_sandbox_launch_submission_write(
    connection: sqlite3.Connection,
    attempt_id: str,
    claim_token: int,
    execution_id: str,
    submission_id: str,
    submission_digest: str,
) -> Iterator[None]:
    """Scope the irreversible launch marker to one validated runc target."""

    fields = (attempt_id, claim_token, execution_id, submission_id, submission_digest)
    token = _SANDBOX_LAUNCH_SUBMISSION_AUTHORIZATION.set(
        (_store_connection_identity(connection), fields)
    )
    try:
        yield
    finally:
        _SANDBOX_LAUNCH_SUBMISSION_AUTHORIZATION.reset(token)


def _sandbox_launch_submission_authorized_for(connection: sqlite3.Connection):
    connection_id = id(connection)

    def authorized(
        attempt_id: str,
        claim_token: int,
        execution_id: str,
        submission_id: str,
        submission_digest: str,
    ) -> int:
        authorization = _SANDBOX_LAUNCH_SUBMISSION_AUTHORIZATION.get()
        expected = (attempt_id, claim_token, execution_id, submission_id, submission_digest)
        return int(
            authorization is not None
            and authorization[0] == connection_id
            and authorization[1] == expected
        )

    return authorized


@contextmanager
def _authorize_sandbox_launch_driver_start_write(
    connection: sqlite3.Connection,
    attempt_id: str,
    claim_token: int,
    execution_id: str,
    start_id: str,
    start_digest: str,
    service_unit: str,
) -> Iterator[None]:
    """Scope the one-shot systemd launch-driver intent to one execution tuple."""

    fields = (attempt_id, claim_token, execution_id, start_id, start_digest, service_unit)
    token = _SANDBOX_LAUNCH_DRIVER_START_AUTHORIZATION.set(
        (_store_connection_identity(connection), fields)
    )
    try:
        yield
    finally:
        _SANDBOX_LAUNCH_DRIVER_START_AUTHORIZATION.reset(token)


def _sandbox_launch_driver_start_authorized_for(connection: sqlite3.Connection):
    connection_id = id(connection)

    def authorized(
        attempt_id: str,
        claim_token: int,
        execution_id: str,
        start_id: str,
        start_digest: str,
        service_unit: str,
    ) -> int:
        authorization = _SANDBOX_LAUNCH_DRIVER_START_AUTHORIZATION.get()
        expected = (
            attempt_id,
            claim_token,
            execution_id,
            start_id,
            start_digest,
            service_unit,
        )
        return int(
            authorization is not None
            and authorization[0] == connection_id
            and authorization[1] == expected
        )

    return authorized


@contextmanager
def _authorize_sandbox_launch_driver_redemption_write(
    connection: sqlite3.Connection, redemption: Any, redeemed_at: str
) -> Iterator[None]:
    """Scope one redemption write to the exact collector-issued service identity."""

    from .sandbox_attestation import launch_driver_start_redemption_is_self_consistent

    if not launch_driver_start_redemption_is_self_consistent(redemption):
        raise SupervisorError(
            "sandbox_launch_driver_redemption_required",
            "launch-driver redemption requires a registered service-identity receipt",
        )
    fields = (
        redemption.attempt_id,
        redemption.claim_token,
        redemption.execution_id,
        redemption.start_id,
        redemption.start_digest,
        redemption.service_unit,
        redeemed_at,
        redemption.service_invocation_id,
        redemption.driver_pid,
        redemption.driver_identity,
        redemption.driver_control_group,
        redemption.attempt_slice_unit,
        redemption.attempt_slice_invocation_id,
        redemption.attempt_slice_control_group,
    )
    token = _SANDBOX_LAUNCH_DRIVER_REDEMPTION_AUTHORIZATION.set(
        (_store_connection_identity(connection), fields)
    )
    try:
        yield
    finally:
        _SANDBOX_LAUNCH_DRIVER_REDEMPTION_AUTHORIZATION.reset(token)


def _sandbox_launch_driver_redemption_authorized_for(connection: sqlite3.Connection):
    connection_id = id(connection)

    def authorized(*fields: Any) -> int:
        authorization = _SANDBOX_LAUNCH_DRIVER_REDEMPTION_AUTHORIZATION.get()
        return int(
            authorization is not None
            and authorization[0] == connection_id
            and authorization[1] == fields
        )

    return authorized


@contextmanager
def _authorize_sandbox_cleanup_action_write(
    connection: sqlite3.Connection, receipt: Any, cleanup_receipt_json: str
) -> Iterator[None]:
    """Scope one cleanup-report write to a registered exact pinned-runc delete."""

    from .oci_worker import _runc_cleanup_action_receipt_is_self_consistent

    if (
        not _runc_cleanup_action_receipt_is_self_consistent(receipt)
        or not isinstance(cleanup_receipt_json, str)
        or not cleanup_receipt_json
        or len(cleanup_receipt_json.encode("utf-8")) > 64 * 1024
    ):
        raise SupervisorError(
            "sandbox_cleanup_action_required",
            "cleanup report requires the exact registered pinned-runc delete receipt",
        )
    fields = (
        receipt.attempt_id,
        receipt.claim_token,
        receipt.execution_id,
        cleanup_receipt_json,
    )
    token = _SANDBOX_CLEANUP_ACTION_AUTHORIZATION.set(
        (_store_connection_identity(connection), fields)
    )
    try:
        yield
    finally:
        _SANDBOX_CLEANUP_ACTION_AUTHORIZATION.reset(token)


def _sandbox_cleanup_action_authorized_for(connection: sqlite3.Connection):
    connection_id = id(connection)

    def authorized(
        attempt_id: str,
        claim_token: int,
        execution_id: str,
        cleanup_receipt_json: str,
    ) -> int:
        authorization = _SANDBOX_CLEANUP_ACTION_AUTHORIZATION.get()
        expected = (attempt_id, claim_token, execution_id, cleanup_receipt_json)
        return int(
            authorization is not None
            and authorization[0] == connection_id
            and authorization[1] == expected
        )

    return authorized


@contextmanager
def _authorize_sandbox_cleanup_report_write(
    connection: sqlite3.Connection,
    attempt_id: str,
    claim_token: int,
    execution_id: str,
    cleanup_receipt_json: str,
) -> Iterator[None]:
    """Scope one validated unverified cleanup report to its exact journal row."""

    if (
        not isinstance(cleanup_receipt_json, str)
        or not cleanup_receipt_json
        or len(cleanup_receipt_json.encode("utf-8")) > 64 * 1024
    ):
        raise SupervisorError(
            "sandbox_cleanup_report_invalid", "cleanup report is not bounded text"
        )
    fields = (attempt_id, claim_token, execution_id, cleanup_receipt_json)
    token = _SANDBOX_CLEANUP_REPORT_AUTHORIZATION.set(
        (_store_connection_identity(connection), fields)
    )
    try:
        yield
    finally:
        _SANDBOX_CLEANUP_REPORT_AUTHORIZATION.reset(token)


def _sandbox_cleanup_report_authorized_for(connection: sqlite3.Connection):
    connection_id = id(connection)

    def authorized(
        attempt_id: str,
        claim_token: int,
        execution_id: str,
        cleanup_receipt_json: str,
    ) -> int:
        authorization = _SANDBOX_CLEANUP_REPORT_AUTHORIZATION.get()
        expected = (attempt_id, claim_token, execution_id, cleanup_receipt_json)
        return int(
            authorization is not None
            and authorization[0] == connection_id
            and authorization[1] == expected
        )

    return authorized


@contextmanager
def _authorize_sandbox_cleanup_verification_write(
    connection: sqlite3.Connection, receipt: Any, cleanup_verification_json: str
) -> Iterator[None]:
    """Scope the final phase write to a registered independent-verifier receipt."""

    from .sandbox_execution_journal import (
        _sandbox_cleanup_verification_receipt_is_self_consistent,
    )

    if (
        not _sandbox_cleanup_verification_receipt_is_self_consistent(receipt)
        or not isinstance(cleanup_verification_json, str)
        or not cleanup_verification_json
        or len(cleanup_verification_json.encode("utf-8")) > 64 * 1024
        or cleanup_verification_json != receipt.encoded
    ):
        raise SupervisorError(
            "sandbox_cleanup_verification_required",
            "cleanup verification requires the exact registered post-stop receipt",
        )
    fields = (
        receipt.attempt_id,
        receipt.claim_token,
        receipt.execution_id,
        cleanup_verification_json,
    )
    token = _SANDBOX_CLEANUP_VERIFICATION_AUTHORIZATION.set(
        (_store_connection_identity(connection), fields)
    )
    try:
        yield
    finally:
        _SANDBOX_CLEANUP_VERIFICATION_AUTHORIZATION.reset(token)


def _sandbox_cleanup_verification_authorized_for(connection: sqlite3.Connection):
    connection_id = id(connection)

    def authorized(
        attempt_id: str,
        claim_token: int,
        execution_id: str,
        cleanup_verification_json: str,
    ) -> int:
        authorization = _SANDBOX_CLEANUP_VERIFICATION_AUTHORIZATION.get()
        expected = (
            attempt_id,
            claim_token,
            execution_id,
            cleanup_verification_json,
        )
        return int(
            authorization is not None
            and authorization[0] == connection_id
            and authorization[1] == expected
        )

    return authorized


@contextmanager
def _authorize_sandbox_reservation_write(
    connection: sqlite3.Connection,
    attempt_id: str,
    claim_token: int,
    execution_id: str,
    bundle_digest: str,
    bundle_digest_semantics: str,
) -> Iterator[None]:
    """Scope one new reservation insert to the validated host-derived tuple."""

    fields = (
        attempt_id,
        claim_token,
        execution_id,
        bundle_digest,
        bundle_digest_semantics,
    )
    token = _SANDBOX_RESERVATION_AUTHORIZATION.set((_store_connection_identity(connection), fields))
    try:
        yield
    finally:
        _SANDBOX_RESERVATION_AUTHORIZATION.reset(token)


def _sandbox_reservation_authorized_for(connection: sqlite3.Connection):
    connection_id = id(connection)

    def authorized(
        attempt_id: str,
        claim_token: int,
        execution_id: str,
        bundle_digest: str,
        bundle_digest_semantics: str,
    ) -> int:
        authorization = _SANDBOX_RESERVATION_AUTHORIZATION.get()
        expected = (
            attempt_id,
            claim_token,
            execution_id,
            bundle_digest,
            bundle_digest_semantics,
        )
        return int(
            authorization is not None
            and authorization[0] == connection_id
            and authorization[1] == expected
        )

    return authorized


def _sandbox_running_attestation_denied(*_fields: Any) -> int:
    """Fail closed unless the fully validated journal path installs a local grant."""

    return 0


class StoreMixin:
    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        if self.read_only:
            # mode=ro makes the refusal structural rather than a matter of discipline:
            # a stray INSERT raises instead of landing. journal_mode and secure_delete
            # are omitted because setting them writes the database header — which is
            # exactly how a "read-only" command used to leave fingerprints.
            raw_connection = sqlite3.connect(
                f"{self.db_path.as_uri()}?mode=ro",
                uri=True,
                timeout=30,
            )
            raw_connection.row_factory = sqlite3.Row
            raw_connection.execute("PRAGMA foreign_keys = ON")
            raw_connection.execute("PRAGMA busy_timeout = 30000")
            raw_connection.create_function(
                "acp_sandbox_exit_receipt_authorized",
                6,
                _sandbox_exit_receipt_authorized_for(raw_connection),
            )
            raw_connection.create_function(
                "acp_sandbox_launch_plan_authorized",
                7,
                _sandbox_launch_plan_authorized_for(raw_connection),
            )
            raw_connection.create_function(
                "acp_sandbox_launch_submission_authorized",
                5,
                _sandbox_launch_submission_authorized_for(raw_connection),
            )
            raw_connection.create_function(
                "acp_sandbox_launch_driver_start_authorized",
                6,
                _sandbox_launch_driver_start_authorized_for(raw_connection),
            )
            raw_connection.create_function(
                "acp_sandbox_launch_driver_redemption_authorized",
                14,
                _sandbox_launch_driver_redemption_authorized_for(raw_connection),
            )
            raw_connection.create_function(
                "acp_sandbox_cleanup_action_authorized",
                4,
                _sandbox_cleanup_action_authorized_for(raw_connection),
            )
            raw_connection.create_function(
                "acp_sandbox_cleanup_report_authorized",
                4,
                _sandbox_cleanup_report_authorized_for(raw_connection),
            )
            raw_connection.create_function(
                "acp_sandbox_cleanup_verification_authorized",
                4,
                _sandbox_cleanup_verification_authorized_for(raw_connection),
            )
            raw_connection.create_function(
                "acp_sandbox_reservation_authorized",
                5,
                _sandbox_reservation_authorized_for(raw_connection),
            )
            sqlite3.Connection.create_function(
                raw_connection,
                _RUNNING_ATTESTATION_SQL_FUNCTION,
                8,
                _sandbox_running_attestation_denied,
            )
            connection = _StoreConnection(raw_connection)
            try:
                yield connection
            finally:
                raw_connection.close()
            return
        raw_connection = sqlite3.connect(self.db_path, timeout=30)
        raw_connection.row_factory = sqlite3.Row
        raw_connection.create_function(
            "acp_sandbox_exit_receipt_authorized",
            6,
            _sandbox_exit_receipt_authorized_for(raw_connection),
        )
        raw_connection.create_function(
            "acp_sandbox_launch_plan_authorized",
            7,
            _sandbox_launch_plan_authorized_for(raw_connection),
        )
        raw_connection.create_function(
            "acp_sandbox_launch_submission_authorized",
            5,
            _sandbox_launch_submission_authorized_for(raw_connection),
        )
        raw_connection.create_function(
            "acp_sandbox_launch_driver_start_authorized",
            6,
            _sandbox_launch_driver_start_authorized_for(raw_connection),
        )
        raw_connection.create_function(
            "acp_sandbox_launch_driver_redemption_authorized",
            14,
            _sandbox_launch_driver_redemption_authorized_for(raw_connection),
        )
        raw_connection.create_function(
            "acp_sandbox_cleanup_action_authorized",
            4,
            _sandbox_cleanup_action_authorized_for(raw_connection),
        )
        raw_connection.create_function(
            "acp_sandbox_cleanup_report_authorized",
            4,
            _sandbox_cleanup_report_authorized_for(raw_connection),
        )
        raw_connection.create_function(
            "acp_sandbox_cleanup_verification_authorized",
            4,
            _sandbox_cleanup_verification_authorized_for(raw_connection),
        )
        raw_connection.create_function(
            "acp_sandbox_reservation_authorized",
            5,
            _sandbox_reservation_authorized_for(raw_connection),
        )
        sqlite3.Connection.create_function(
            raw_connection,
            _RUNNING_ATTESTATION_SQL_FUNCTION,
            8,
            _sandbox_running_attestation_denied,
        )
        raw_connection.execute("PRAGMA foreign_keys = ON")
        raw_connection.execute("PRAGMA journal_mode = WAL")
        raw_connection.execute("PRAGMA busy_timeout = 30000")
        raw_connection.execute("PRAGMA secure_delete = ON")
        connection = _StoreConnection(raw_connection)
        try:
            yield connection
            raw_connection.commit()
        except Exception:
            raw_connection.rollback()
            raise
        finally:
            raw_connection.close()

    def _event(
        self,
        connection: sqlite3.Connection,
        event_type: str,
        actor: str,
        payload: dict[str, Any],
    ) -> None:
        event_id = str(uuid.uuid4())
        created = utc_now()
        prior = connection.execute(
            "SELECT event_hash FROM events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = prior["event_hash"] if prior else GENESIS_HASH
        material = canonical_json(
            {
                "actor": actor,
                "created_at": created,
                "event_id": event_id,
                "event_type": event_type,
                "payload": payload,
                "previous_hash": previous_hash,
            }
        )
        connection.execute(
            """
            INSERT INTO events
              (id, event_type, actor, payload_json, previous_hash, event_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                event_type,
                actor,
                canonical_json(payload),
                previous_hash,
                sha256(material.encode()),
                created,
            ),
        )

    def _verify_event_chain(self, connection: sqlite3.Connection) -> dict[str, Any]:
        previous = GENESIS_HASH
        rows = connection.execute("SELECT * FROM events ORDER BY sequence").fetchall()
        for row in rows:
            try:
                payload = json.loads(row["payload_json"])
            except (json.JSONDecodeError, TypeError, UnicodeError):
                return {
                    "ok": False,
                    "detail": f"event payload is invalid at sequence {row['sequence']}",
                }
            material = canonical_json(
                {
                    "actor": row["actor"],
                    "created_at": row["created_at"],
                    "event_id": row["id"],
                    "event_type": row["event_type"],
                    "payload": payload,
                    "previous_hash": previous,
                }
            )
            expected = sha256(material.encode())
            if row["previous_hash"] != previous or row["event_hash"] != expected:
                return {
                    "ok": False,
                    "detail": f"event chain breaks at sequence {row['sequence']}",
                }
            previous = row["event_hash"]
        return {"ok": True, "detail": f"{len(rows)} events verified"}

    def verify_event_chain(self) -> dict[str, Any]:
        with self.connect() as connection:
            return self._verify_event_chain(connection)
