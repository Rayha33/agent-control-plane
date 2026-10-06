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

from .common import GENESIS_HASH, SupervisorError, canonical_json, sha256, utc_now

_SANDBOX_EXIT_RECEIPT_AUTHORIZATION: ContextVar[
    tuple[int, tuple[str, int, str, int, str, int]] | None
] = ContextVar("acp_sandbox_exit_receipt_authorization", default=None)


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
    token = _SANDBOX_EXIT_RECEIPT_AUTHORIZATION.set((id(connection), fields))
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


class StoreMixin:
    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        if self.read_only:
            # mode=ro makes the refusal structural rather than a matter of discipline:
            # a stray INSERT raises instead of landing. journal_mode and secure_delete
            # are omitted because setting them writes the database header — which is
            # exactly how a "read-only" command used to leave fingerprints.
            connection = sqlite3.connect(f"{self.db_path.as_uri()}?mode=ro", uri=True, timeout=30)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 30000")
            connection.create_function(
                "acp_sandbox_exit_receipt_authorized",
                6,
                _sandbox_exit_receipt_authorized_for(connection),
            )
            try:
                yield connection
            finally:
                connection.close()
            return
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.create_function(
            "acp_sandbox_exit_receipt_authorized",
            6,
            _sandbox_exit_receipt_authorized_for(connection),
        )
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA secure_delete = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

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
