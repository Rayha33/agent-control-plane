"""Runner enrollment and the credential checks that bind a caller to an attempt.

Moved verbatim out of `git_supervisor` (board #1630). `GitSupervisor` inherits this mixin, so
every call site, CLI path and `GitSupervisor.<name>` lookup resolves exactly as before.
"""

from __future__ import annotations

import hmac
import sqlite3
from typing import Any

from ..runner_identity import (
    IdentityError,
    credential_digest,
    issue_credential,
    validate_role,
    verify_credential,
)
from .common import SupervisorError, utc_now


class IdentityMixin:
    """Runner enrollment, revocation and authentication."""

    def enroll_runner(self, agent_id: str, role: str) -> dict[str, Any]:
        """Register a runner and return its credential exactly once.

        Only the digest is stored, so the state file never holds a usable
        credential — losing the returned value means re-enrolling, not reading
        it back out of the database.
        """

        if not agent_id.strip():
            raise SupervisorError("invalid_agent", "agent_id is required")
        try:
            validate_role(role)
        except IdentityError as error:
            raise SupervisorError(error.code, error.message) from error
        credential = issue_credential()
        stamp = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM runner_identities WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            if existing and existing["revoked_at"] is None:
                raise SupervisorError(
                    "runner_already_enrolled",
                    f"{agent_id} is already enrolled; revoke it before re-enrolling",
                )
            digest = credential_digest(credential)
            if existing:
                connection.execute(
                    """
                    UPDATE runner_identities
                    SET role = ?, credential_digest = ?, created_at = ?, revoked_at = NULL
                    WHERE agent_id = ?
                    """,
                    (role, digest, stamp, agent_id),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO runner_identities
                      (agent_id, role, credential_digest, created_at, revoked_at)
                    VALUES (?, ?, ?, ?, NULL)
                    """,
                    (agent_id, role, digest, stamp),
                )
            connection.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('runner_auth_enabled', '1')"
            )
            self._event(
                connection,
                "runner.enrolled",
                "supervisor",
                {"agent_id": agent_id, "role": role, "rotated": bool(existing)},
            )
        return {"agent_id": agent_id, "role": role, "credential": credential}

    def revoke_runner(self, agent_id: str) -> dict[str, Any]:
        stamp = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM runner_identities WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            if not row:
                raise SupervisorError("runner_not_found", f"{agent_id} is not enrolled")
            connection.execute(
                "UPDATE runner_identities SET revoked_at = ? WHERE agent_id = ?",
                (stamp, agent_id),
            )
            self._event(connection, "runner.revoked", "supervisor", {"agent_id": agent_id})
        return {"agent_id": agent_id, "revoked_at": stamp}

    def runners(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT agent_id, role, created_at, revoked_at FROM runner_identities "
                "ORDER BY agent_id"
            ).fetchall()
        # credential_digest is deliberately not returned.
        return [dict(row) for row in rows]

    def _identity_enforced(self, connection: sqlite3.Connection | None = None) -> bool:
        """Authentication activates permanently after the first enrollment.

        An empty registry keeps the single-host default behaviour, so enabling
        this is a deliberate act rather than a breaking upgrade. Revocation
        cannot turn authentication back off.
        """
        if connection is not None:
            row = connection.execute(
                "SELECT value FROM meta WHERE key = 'runner_auth_enabled'"
            ).fetchone()
            return bool(row and row["value"] == "1")
        with self.connect() as owned_connection:
            row = owned_connection.execute(
                "SELECT value FROM meta WHERE key = 'runner_auth_enabled'"
            ).fetchone()
        return bool(row)

    def _authenticate(
        self,
        agent_id: str,
        role: str,
        credential: str | None,
        connection: sqlite3.Connection | None = None,
    ) -> sqlite3.Row | None:
        if not self._identity_enforced(connection):
            return None
        if connection is None:
            with self.connect() as owned_connection:
                row = owned_connection.execute(
                    "SELECT * FROM runner_identities WHERE agent_id = ?", (agent_id,)
                ).fetchone()
        else:
            row = connection.execute(
                "SELECT * FROM runner_identities WHERE agent_id = ?", (agent_id,)
            ).fetchone()
        if not row:
            raise SupervisorError(
                "runner_not_enrolled",
                f"{agent_id} is not an enrolled runner; enroll it or revoke the registry",
            )
        if row["revoked_at"] is not None:
            raise SupervisorError("runner_revoked", f"{agent_id} credential is revoked")
        if row["role"] != role:
            raise SupervisorError(
                "runner_role_mismatch",
                f"{agent_id} is enrolled as {row['role']}, not {role}",
            )
        if not credential or not verify_credential(credential, row["credential_digest"]):
            raise SupervisorError(
                "runner_authentication_failed",
                f"{agent_id} did not present a valid {role} credential",
            )
        return row

    def _authenticate_attempt(
        self,
        connection: sqlite3.Connection,
        attempt: sqlite3.Row,
        credential: str | None,
    ) -> None:
        identity = self._authenticate(attempt["agent_id"], "worker", credential, connection)
        if identity is None:
            return
        bound_digest = attempt["runner_credential_digest"]
        if not bound_digest:
            raise SupervisorError(
                "attempt_identity_unbound",
                "attempt predates runner authentication and cannot cross the trust boundary",
            )
        if not hmac.compare_digest(bound_digest, identity["credential_digest"]):
            raise SupervisorError(
                "attempt_identity_stale",
                "attempt is bound to an older runner credential",
            )

    def _reauthenticate_bound(
        self,
        connection: sqlite3.Connection,
        agent_id: str,
        role: str,
        credential: str | None,
        expected_digest: str | None,
    ) -> None:
        identity = self._authenticate(agent_id, role, credential, connection)
        if identity is None:
            return
        if not expected_digest or not hmac.compare_digest(
            expected_digest, identity["credential_digest"]
        ):
            raise SupervisorError(
                "runner_identity_stale",
                f"{role} credential changed while the operation was running",
            )
