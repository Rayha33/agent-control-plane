"""Credentialed, append-only messages shared across attempt worktrees.

Messages live in the base checkout's control database event chain. They are a
coordination aid, not control-plane instructions or an authorization mechanism.
"""

from __future__ import annotations

import json
import time
import unicodedata
import uuid
from typing import Any

from .common import SupervisorError

MESSAGE_KINDS = frozenset({"finding", "blocker", "handoff", "question", "checkpoint"})
MESSAGE_MAX_BYTES = 4096
MESSAGE_PROJECT_MAX = 10_000
MESSAGE_PAGE_MAX = 100
MESSAGE_SCAN_BATCH = 128


class MessagingMixin:
    def post_message(
        self,
        attempt_id: str,
        claim_token: int,
        body: str,
        *,
        kind: str = "checkpoint",
        recipient_attempt_id: str | None = None,
        credential: str | None = None,
    ) -> dict[str, Any]:
        """Append one bounded message from an authenticated live worker attempt."""

        if self.read_only:
            raise SupervisorError(
                "read_only", "cannot post a message through a read-only supervisor"
            )
        if not isinstance(kind, str) or kind not in MESSAGE_KINDS:
            raise SupervisorError("invalid_message_kind", "unsupported message kind")
        if not isinstance(body, str) or not body.strip():
            raise SupervisorError("invalid_message", "message body must be non-empty text")
        try:
            encoded = body.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise SupervisorError("invalid_message", "message must be valid UTF-8 text") from error
        if len(encoded) > MESSAGE_MAX_BYTES:
            raise SupervisorError(
                "message_too_large", f"message exceeds {MESSAGE_MAX_BYTES} UTF-8 bytes"
            )
        if any(
            unicodedata.category(character) == "Cc" and character not in "\n\t"
            for character in body
        ):
            raise SupervisorError(
                "invalid_message", "message contains unsupported control characters"
            )
        if not credential:
            raise SupervisorError(
                "credential_required", "posting a message requires a runner credential"
            )
        if recipient_attempt_id is not None:
            try:
                recipient_attempt_id = str(uuid.UUID(recipient_attempt_id))
            except (TypeError, ValueError, AttributeError) as error:
                raise SupervisorError(
                    "invalid_recipient", "recipient must be an attempt UUID"
                ) from error

        now = int(time.time())
        with self.connect() as connection:
            if not self._identity_enforced(connection):
                raise SupervisorError(
                    "runner_auth_disabled",
                    "posting messages requires runner authentication; enroll the worker "
                    "and start a new attempt",
                )
            attempt = self._active_attempt(connection, attempt_id, claim_token, now)
            self._authenticate_attempt(connection, attempt, credential)

        # As with heartbeat/submit, an active worker must still satisfy the trust
        # pin before a side effect is allowed. Recheck liveness and identity in the
        # write transaction after trust verification.
        self._verify_attempt_trust(attempt_id)
        commit_sha = self._git_text("-C", attempt["worktree"], "rev-parse", "HEAD")
        message_id = str(uuid.uuid4())
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            if not self._identity_enforced(connection):
                raise SupervisorError(
                    "runner_auth_disabled",
                    "posting messages requires runner authentication; enroll the worker "
                    "and start a new attempt",
                )
            self._authenticate_attempt(connection, attempt, credential)
            message_count = connection.execute(
                "SELECT COUNT(*) AS count FROM events WHERE event_type = 'agent.message'"
            ).fetchone()["count"]
            if message_count >= MESSAGE_PROJECT_MAX:
                raise SupervisorError(
                    "message_quota_exhausted",
                    f"project message limit ({MESSAGE_PROJECT_MAX}) has been reached",
                )
            if recipient_attempt_id is not None:
                recipient = connection.execute(
                    "SELECT id FROM attempts WHERE id = ?", (recipient_attempt_id,)
                ).fetchone()
                if recipient is None:
                    raise SupervisorError(
                        "invalid_recipient", "recipient attempt is not in this ACP project"
                    )

            payload = {
                "attempt_id": attempt["id"],
                "body": body,
                "commit_sha": commit_sha,
                "kind": kind,
                "message_id": message_id,
                "recipient_attempt_id": recipient_attempt_id,
                "task_id": attempt["task_id"],
            }
            self._event(connection, "agent.message", attempt["agent_id"], payload)
            row = connection.execute(
                "SELECT sequence, created_at FROM events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if row is None:
                raise SupervisorError("message_write_failed", "message event was not recorded")
            result = {
                "sequence": row["sequence"],
                "message_id": message_id,
                "task_id": attempt["task_id"],
                "attempt_id": attempt["id"],
                "sender": attempt["agent_id"],
                "recipient_attempt_id": recipient_attempt_id,
                "kind": kind,
                "body": body,
                "commit_sha": commit_sha,
                "created_at": row["created_at"],
                "content_trust": "untrusted_agent_content",
            }
            return result

    def list_messages(
        self,
        attempt_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Read project broadcasts and messages addressed to an existing attempt."""

        if not isinstance(attempt_id, str) or not attempt_id:
            raise SupervisorError("invalid_attempt", "attempt_id is required")
        try:
            attempt_id = str(uuid.UUID(attempt_id))
        except (TypeError, ValueError, AttributeError) as error:
            raise SupervisorError("invalid_attempt", "attempt_id must be a UUID") from error
        if type(after_sequence) is not int or after_sequence < 0:
            raise SupervisorError("invalid_cursor", "after_sequence must be a non-negative integer")
        if type(limit) is not int or not 1 <= limit <= MESSAGE_PAGE_MAX:
            raise SupervisorError(
                "invalid_limit", f"limit must be between 1 and {MESSAGE_PAGE_MAX}"
            )

        items: list[dict[str, Any]] = []
        cursor = after_sequence
        has_more = False
        with self.connect() as connection:
            # Keep verification and reads on one stable snapshot: otherwise a
            # concurrently appended event could appear after the chain was checked.
            connection.execute("BEGIN")
            known = connection.execute(
                "SELECT 1 FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
            if known is None:
                raise SupervisorError("attempt_not_found", "attempt is not in this ACP project")
            verification = self._verify_event_chain_in(connection)
            if not verification.get("ok"):
                raise SupervisorError(
                    "event_chain_invalid",
                    "messages are withheld because the event chain is invalid",
                )

            while True:
                rows = connection.execute(
                    "SELECT sequence, actor, payload_json, created_at FROM events "
                    "WHERE event_type = 'agent.message' AND sequence > ? "
                    "ORDER BY sequence ASC LIMIT ?",
                    (cursor, MESSAGE_SCAN_BATCH),
                ).fetchall()
                if not rows:
                    break
                for row in rows:
                    cursor = row["sequence"]
                    try:
                        payload = json.loads(row["payload_json"])
                    except (json.JSONDecodeError, TypeError, UnicodeError) as error:
                        raise SupervisorError(
                            "message_log_invalid", "message event payload is invalid"
                        ) from error
                    if not isinstance(payload, dict) or payload.get("recipient_attempt_id") not in (
                        None,
                        attempt_id,
                    ):
                        continue
                    required = ("message_id", "task_id", "attempt_id", "kind", "body", "commit_sha")
                    if any(key not in payload for key in required) or not isinstance(
                        payload["body"], str
                    ):
                        raise SupervisorError(
                            "message_log_invalid", "message event is missing required fields"
                        )
                    items.append(
                        {
                            "sequence": row["sequence"],
                            "message_id": payload["message_id"],
                            "task_id": payload["task_id"],
                            "attempt_id": payload["attempt_id"],
                            "sender": row["actor"],
                            "recipient_attempt_id": payload.get("recipient_attempt_id"),
                            "kind": payload["kind"],
                            "body": payload["body"],
                            "commit_sha": payload["commit_sha"],
                            "created_at": row["created_at"],
                            "content_trust": "untrusted_agent_content",
                        }
                    )
                    if len(items) > limit:
                        has_more = True
                        break
                if has_more or len(rows) < MESSAGE_SCAN_BATCH:
                    break

        if has_more:
            items = items[:limit]
            next_after_sequence = items[-1]["sequence"]
        else:
            next_after_sequence = cursor
        return {
            "messages": items,
            "after_sequence": after_sequence,
            "next_after_sequence": next_after_sequence,
            "has_more": has_more,
            "content_trust": "untrusted_agent_content",
        }
