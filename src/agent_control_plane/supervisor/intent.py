"""Append-only agent intent and read-only coordination views.

Intent is a caller-authored, advisory map of likely work. It is deliberately separate
from task leases, resource reservations, and observed Git changes: it can warn about
overlap, but never grants write authority or proves semantic compatibility.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import time
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any

from .common import SupervisorError, canonical_json, utc_now

INTENT_VERSION = 1
INTENT_MAX_BYTES = 64 * 1024
INTENT_MAX_SCOPES = 128
INTENT_MAX_DEPENDENCIES = 128
INTENT_HISTORY_DEFAULT_LIMIT = 25
INTENT_HISTORY_MAX_LIMIT = 50
INTENT_PHASES = frozenset({"exploring", "planned", "implementing", "verifying", "blocked"})
INTENT_CHANGES = frozenset({"read", "additive", "write", "destructive"})
INTENT_SURFACE_KINDS = frozenset({"symbol", "interface", "schema", "api", "resource"})
_OBSERVED_PATHS_MAX_BYTES = 2 * 1024 * 1024
_OBSERVED_PATHS_MAX_COUNT = 4096


def _text(value: Any, field: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str):
        raise SupervisorError("invalid_intent", f"{field} must be a string")
    value = unicodedata.normalize("NFC", value.strip())
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise SupervisorError("invalid_intent", f"{field} must be valid UTF-8") from error
    if (
        not value
        or size > maximum
        or any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value)
    ):
        raise SupervisorError("invalid_intent", f"{field} is empty, too long, or contains controls")
    return value


def _path_pattern(value: Any) -> str:
    pattern = _text(value, "path pattern", maximum=1024)
    path = PurePosixPath(pattern)
    if (
        "\\" in pattern
        or path.is_absolute()
        or path.as_posix() != pattern
        or any(part in {"", ".", ".."} for part in pattern.split("/"))
        or pattern.startswith("~")
    ):
        raise SupervisorError(
            "invalid_intent", "path patterns must be safe repository-relative paths"
        )
    return pattern


def validate_intent(value: Any) -> dict[str, Any]:
    """Validate and normalize the versioned, untrusted intent document."""

    if not isinstance(value, dict):
        raise SupervisorError("invalid_intent", "intent must be a JSON object")
    allowed = {
        "version",
        "responsibility",
        "paths",
        "surfaces",
        "depends_on",
        "phase",
        "confidence",
    }
    if set(value) != allowed:
        raise SupervisorError(
            "invalid_intent",
            f"intent fields must be exactly {', '.join(sorted(allowed))}",
        )
    if type(value["version"]) is not int or value["version"] != INTENT_VERSION:
        raise SupervisorError(
            "unsupported_intent_version", f"intent version must be {INTENT_VERSION}"
        )
    responsibility = _text(value["responsibility"], "responsibility", maximum=2048)
    if not isinstance(value["paths"], list) or len(value["paths"]) > INTENT_MAX_SCOPES:
        raise SupervisorError("invalid_intent", "paths must be an array with at most 128 entries")
    if not isinstance(value["surfaces"], list) or len(value["surfaces"]) > INTENT_MAX_SCOPES:
        raise SupervisorError(
            "invalid_intent", "surfaces must be an array with at most 128 entries"
        )
    if (
        not isinstance(value["depends_on"], list)
        or len(value["depends_on"]) > INTENT_MAX_DEPENDENCIES
    ):
        raise SupervisorError(
            "invalid_intent", "depends_on must be an array with at most 128 entries"
        )
    if not isinstance(value["phase"], str) or value["phase"] not in INTENT_PHASES:
        raise SupervisorError("invalid_intent", "phase is not a supported intent phase")
    confidence = value["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise SupervisorError("invalid_intent", "confidence must be a finite number from 0 to 1")
    confidence = float(confidence)
    if not math.isfinite(confidence) or not 0 <= confidence <= 1:
        raise SupervisorError("invalid_intent", "confidence must be a finite number from 0 to 1")

    paths: list[dict[str, Any]] = []
    for entry in value["paths"]:
        if not isinstance(entry, dict) or set(entry) - {"pattern", "change", "shared"}:
            raise SupervisorError(
                "invalid_intent", "each path needs pattern/change and optional shared"
            )
        if not {"pattern", "change"} <= set(entry):
            raise SupervisorError("invalid_intent", "each path needs pattern and change")
        pattern = _path_pattern(entry["pattern"])
        change = entry["change"]
        shared = entry.get("shared", False)
        if not isinstance(change, str) or change not in INTENT_CHANGES or type(shared) is not bool:
            raise SupervisorError("invalid_intent", "path change/shared value is invalid")
        paths.append({"pattern": pattern, "change": change, "shared": shared})

    surfaces: list[dict[str, Any]] = []
    for entry in value["surfaces"]:
        if not isinstance(entry, dict) or set(entry) - {"kind", "name", "change", "shared"}:
            raise SupervisorError(
                "invalid_intent", "each surface needs kind/name/change and optional shared"
            )
        if not {"kind", "name", "change"} <= set(entry):
            raise SupervisorError("invalid_intent", "each surface needs kind, name, and change")
        kind = entry["kind"]
        name = _text(entry["name"], "surface name")
        change = entry["change"]
        shared = entry.get("shared", False)
        if (
            not isinstance(kind, str)
            or kind not in INTENT_SURFACE_KINDS
            or not isinstance(change, str)
            or change not in INTENT_CHANGES
            or type(shared) is not bool
        ):
            raise SupervisorError("invalid_intent", "surface kind/change/shared value is invalid")
        surfaces.append({"kind": kind, "name": name, "change": change, "shared": shared})

    dependencies = [_text(item, "dependency") for item in value["depends_on"]]
    return {
        "version": INTENT_VERSION,
        "responsibility": responsibility,
        "paths": paths,
        "surfaces": surfaces,
        "depends_on": dependencies,
        "phase": value["phase"],
        "confidence": confidence,
    }


def _decode_intent(raw: str) -> tuple[dict[str, Any] | None, str]:
    if not isinstance(raw, str):
        return None, "unparseable"
    try:
        if len(raw.encode("utf-8")) > INTENT_MAX_BYTES:
            return None, "unparseable"
        value = json.loads(raw)
        return validate_intent(value), "valid"
    except (TypeError, UnicodeEncodeError, ValueError, RecursionError, SupervisorError):
        return None, "unparseable"


def _scope_interaction(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    changes = {left["change"], right["change"]}
    deliberate_shared = left.get("shared") is True and right.get("shared") is True
    left_writes = left["change"] != "read"
    right_writes = right["change"] != "read"
    if changes == {"read"}:
        kind = "read_read"
        conflict = False
    elif deliberate_shared:
        kind = "deliberate_shared"
        conflict = False
    elif "destructive" in changes or (left_writes and right_writes):
        kind = "conflicting_write_intent"
        conflict = True
    else:
        kind = "read_write_advisory"
        conflict = False
    return {
        "classification": kind,
        "conflict": conflict,
        "underlying_write_conflict": "destructive" in changes or (left_writes and right_writes),
        "change_interaction": sorted(changes),
        "both_declare_shared_ownership": deliberate_shared,
    }


def _name_key(value: str) -> str:
    return unicodedata.normalize("NFC", value.strip()).casefold()


def _path_key(value: str, *, case_sensitive: bool) -> str:
    normalized = unicodedata.normalize("NFC", value)
    if not case_sensitive or normalized.casefold().startswith("logical:"):
        return normalized.casefold()
    return normalized


class AgentIntentMixin:
    """Claim-fenced intent writes and read-only active/history views."""

    def publish_intent(
        self,
        attempt_id: str,
        claim_token: int,
        intent: dict[str, Any],
        credential: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(attempt_id, str) or not attempt_id.strip():
            raise SupervisorError("invalid_attempt", "attempt_id is required")
        if type(claim_token) is not int or claim_token <= 0:
            raise SupervisorError("invalid_claim_token", "claim token must be a positive integer")
        normalized = validate_intent(intent)
        serialized = canonical_json(normalized)
        if len(serialized.encode("utf-8")) > INTENT_MAX_BYTES:
            raise SupervisorError("invalid_intent", "intent exceeds 64 KiB")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            self._authenticate_attempt(connection, attempt, credential)
            revision = connection.execute(
                "SELECT COALESCE(MAX(revision), 0) + 1 AS value "
                "FROM agent_intent_revisions WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()["value"]
            created_at = utc_now()
            connection.execute(
                """
                INSERT INTO agent_intent_revisions
                  (attempt_id, claim_token, revision, intent_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (attempt_id, claim_token, revision, serialized, created_at),
            )
            self._event(
                connection,
                "attempt.intent_revised",
                attempt["agent_id"],
                {
                    "attempt_id": attempt_id,
                    "claim_token": claim_token,
                    "revision": revision,
                    "intent_sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
                    "phase": normalized["phase"],
                },
            )
        return {
            "attempt_id": attempt_id,
            "claim_token": claim_token,
            "revision": revision,
            "created_at": created_at,
            "intent": normalized,
        }

    def intent_history(
        self,
        attempt_id: str,
        limit: int = INTENT_HISTORY_DEFAULT_LIMIT,
        after_revision: int = 0,
    ) -> dict[str, Any]:
        """Retain and report revisions for active and terminal attempts alike."""
        if type(limit) is not int or not 1 <= limit <= INTENT_HISTORY_MAX_LIMIT:
            raise SupervisorError(
                "invalid_intent_history_limit",
                f"history limit must be from 1 to {INTENT_HISTORY_MAX_LIMIT}",
            )
        if type(after_revision) is not int or after_revision < 0:
            raise SupervisorError(
                "invalid_intent_history_cursor", "after_revision must be non-negative"
            )
        with self.connect() as connection:
            attempt = connection.execute(
                "SELECT attempt.id, attempt.task_id, attempt.number, attempt.agent_id, "
                "attempt.claim_token, attempt.status, attempt.lease_expires_at, "
                "task.status AS task_status, task.current_attempt_id "
                "FROM attempts AS attempt JOIN tasks AS task ON task.id = attempt.task_id "
                "WHERE attempt.id = ?",
                (attempt_id,),
            ).fetchone()
            if not attempt:
                raise SupervisorError("attempt_not_found", f"attempt {attempt_id} not found")
            rows = connection.execute(
                "SELECT claim_token, revision, intent_json, created_at "
                "FROM agent_intent_revisions WHERE attempt_id = ? AND revision > ? "
                "ORDER BY revision LIMIT ?",
                (attempt_id, after_revision, limit + 1),
            ).fetchall()
            total_revisions = connection.execute(
                "SELECT COUNT(*) AS value FROM agent_intent_revisions WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()["value"]
            latest_row = connection.execute(
                "SELECT claim_token, revision, intent_json, created_at "
                "FROM agent_intent_revisions WHERE attempt_id = ? "
                "ORDER BY revision DESC LIMIT 1",
                (attempt_id,),
            ).fetchone()
        has_more = len(rows) > limit
        rows = rows[:limit]
        revisions = []
        for row in rows:
            intent, parse_status = _decode_intent(row["intent_json"])
            revisions.append(
                {
                    "claim_token": row["claim_token"],
                    "revision": row["revision"],
                    "state": (
                        "stale" if row["claim_token"] != attempt["claim_token"] else parse_status
                    ),
                    "intent": intent,
                    "created_at": row["created_at"],
                }
            )
        latest_revision = None
        if latest_row is not None:
            latest_intent, latest_status = _decode_intent(latest_row["intent_json"])
            latest_revision = {
                "claim_token": latest_row["claim_token"],
                "revision": latest_row["revision"],
                "state": (
                    "stale"
                    if latest_row["claim_token"] != attempt["claim_token"]
                    else latest_status
                ),
                "intent": latest_intent,
                "created_at": latest_row["created_at"],
            }
        return {
            "attempt": dict(attempt),
            "active": (
                attempt["status"] == "working"
                and attempt["task_status"] == "working"
                and attempt["current_attempt_id"] == attempt_id
                and attempt["lease_expires_at"] > int(time.time())
            ),
            "revisions": revisions,
            "revision_count": total_revisions,
            "has_more": has_more,
            "next_after_revision": revisions[-1]["revision"] if has_more and revisions else None,
            "latest_revision": latest_revision,
        }

    def _observed_changed_paths(self, attempt: sqlite3.Row) -> dict[str, Any]:
        worktree = Path(attempt["worktree"])
        root_value = attempt["worktree_root"] or str(self.state_dir / "worktrees")
        root = Path(root_value)
        expected = root / attempt["id"]
        if (
            not worktree.is_absolute()
            or not root.is_absolute()
            or worktree.is_symlink()
            or worktree.resolve(strict=False) != expected.resolve(strict=False)
            or not worktree.is_dir()
        ):
            return {"status": "unavailable", "reason": "attempt_worktree_unavailable", "paths": []}
        if (
            not isinstance(attempt["start_sha"], str)
            or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", attempt["start_sha"]) is None
        ):
            return {"status": "unavailable", "reason": "invalid_start_revision", "paths": []}
        try:
            tracked = self._git_readonly_bytes_bounded(
                "-C",
                str(worktree),
                "diff",
                "--no-ext-diff",
                "--no-renames",
                "--name-only",
                "-z",
                attempt["start_sha"],
                "--",
                max_bytes=_OBSERVED_PATHS_MAX_BYTES,
            )
            untracked = self._git_readonly_bytes_bounded(
                "-C",
                str(worktree),
                "ls-files",
                "--others",
                "--exclude-standard",
                "-z",
                max_bytes=_OBSERVED_PATHS_MAX_BYTES,
            )
            raw_paths = sorted(set(tracked.split(b"\0") + untracked.split(b"\0")) - {b""})
            if len(raw_paths) > _OBSERVED_PATHS_MAX_COUNT:
                return {"status": "unavailable", "reason": "too_many_changed_paths", "paths": []}
            paths = [path.decode("utf-8") for path in raw_paths]
        except (OSError, UnicodeDecodeError, SupervisorError):
            return {"status": "unavailable", "reason": "git_observation_failed", "paths": []}
        return {"status": "available", "source": "supervisor_git_observation", "paths": paths}

    def intent_snapshot(self) -> dict[str, Any]:
        """Compare active, caller-declared scopes without making scheduling decisions."""
        now = int(time.time())
        with self.connect() as connection:
            attempts = connection.execute(
                """
                SELECT attempt.*, task.title AS task_title
                FROM attempts AS attempt
                JOIN tasks AS task ON task.id = attempt.task_id
                WHERE attempt.status = 'working' AND task.status = 'working'
                  AND task.current_attempt_id = attempt.id AND attempt.lease_expires_at > ?
                ORDER BY attempt.task_id, attempt.number
                """,
                (now,),
            ).fetchall()
            case_row = connection.execute(
                "SELECT value FROM meta WHERE key = 'path_case_sensitive'"
            ).fetchone()
            path_case_sensitive = bool(case_row and case_row["value"] == "1")
            latest_rows = {
                row["attempt_id"]: row
                for row in connection.execute(
                    """
                    SELECT intent.* FROM agent_intent_revisions AS intent
                    JOIN (
                      SELECT attempt_id, MAX(revision) AS revision
                      FROM agent_intent_revisions GROUP BY attempt_id
                    ) AS latest
                      ON latest.attempt_id = intent.attempt_id
                     AND latest.revision = intent.revision
                    """
                ).fetchall()
            }

        entries: list[dict[str, Any]] = []
        unknown_attempts: list[dict[str, str]] = []
        for attempt in attempts:
            revision = latest_rows.get(attempt["id"])
            if revision is None:
                state, intent = "missing", None
            elif revision["claim_token"] != attempt["claim_token"]:
                state, intent = "stale", None
            else:
                intent, parse_status = _decode_intent(revision["intent_json"])
                state = parse_status
                if intent is not None:
                    state = "declared" if intent["paths"] or intent["surfaces"] else "incomplete"
            if state in {"missing", "stale", "unparseable", "incomplete"}:
                unknown_attempts.append({"attempt_id": attempt["id"], "state": state})
            entry = {
                "task_id": attempt["task_id"],
                "task_title": attempt["task_title"],
                "attempt_id": attempt["id"],
                "attempt_number": attempt["number"],
                "agent_id": attempt["agent_id"],
                "attempt_phase": attempt["status"],
                "lease_expires_at": attempt["lease_expires_at"],
                "intent_state": state,
                "revision": revision["revision"] if revision else None,
                "intent": intent,
                "observed": self._observed_changed_paths(attempt),
            }
            entries.append(entry)

        overlaps: list[dict[str, Any]] = []
        dependency_matches: list[dict[str, Any]] = []
        providers: dict[str, list[dict[str, Any]]] = {}
        for entry in entries:
            intent = entry["intent"]
            if not intent:
                continue
            for surface in intent["surfaces"]:
                providers.setdefault(f"{surface['kind']}:{_name_key(surface['name'])}", []).append(
                    {"entry": entry, "surface": surface}
                )
                providers.setdefault(_name_key(surface["name"]), []).append(
                    {"entry": entry, "surface": surface}
                )
        for entry in entries:
            intent = entry["intent"]
            if not intent:
                continue
            for dependency in intent["depends_on"]:
                matches = providers.get(_name_key(dependency), [])
                unique = {
                    (
                        match["entry"]["attempt_id"],
                        match["surface"]["kind"],
                        match["surface"]["name"],
                    ): match
                    for match in matches
                    if match["entry"]["attempt_id"] != entry["attempt_id"]
                }
                for match in unique.values():
                    dependency_matches.append(
                        {
                            "dependent_attempt_id": entry["attempt_id"],
                            "dependent_task_id": entry["task_id"],
                            "dependency": dependency,
                            "provider_attempt_id": match["entry"]["attempt_id"],
                            "provider_task_id": match["entry"]["task_id"],
                            "provider_surface": {
                                "kind": match["surface"]["kind"],
                                "name": match["surface"]["name"],
                            },
                            "compatibility": "not_assessed",
                        }
                    )

        for index, left_entry in enumerate(entries):
            left_intent = left_entry["intent"]
            if not left_intent:
                continue
            for right_entry in entries[index + 1 :]:
                right_intent = right_entry["intent"]
                if not right_intent:
                    continue
                for left in left_intent["paths"]:
                    for right in right_intent["paths"]:
                        left_key = _path_key(left["pattern"], case_sensitive=path_case_sensitive)
                        right_key = _path_key(right["pattern"], case_sensitive=path_case_sensitive)
                        if not self.resources_overlap(left_key, right_key):
                            continue
                        interaction = _scope_interaction(left, right)
                        overlaps.append(
                            {
                                "kind": "path",
                                "overlap": "exact" if left_key == right_key else "potential",
                                "left": {
                                    "task_id": left_entry["task_id"],
                                    "attempt_id": left_entry["attempt_id"],
                                    **left,
                                },
                                "right": {
                                    "task_id": right_entry["task_id"],
                                    "attempt_id": right_entry["attempt_id"],
                                    **right,
                                },
                                **interaction,
                            }
                        )
                for left in left_intent["surfaces"]:
                    for right in right_intent["surfaces"]:
                        if left["kind"] != right["kind"] or _name_key(left["name"]) != _name_key(
                            right["name"]
                        ):
                            continue
                        interaction = _scope_interaction(left, right)
                        overlaps.append(
                            {
                                "kind": left["kind"],
                                "overlap": "exact",
                                "left": {
                                    "task_id": left_entry["task_id"],
                                    "attempt_id": left_entry["attempt_id"],
                                    **left,
                                },
                                "right": {
                                    "task_id": right_entry["task_id"],
                                    "attempt_id": right_entry["attempt_id"],
                                    **right,
                                },
                                **interaction,
                            }
                        )

        return {
            "version": INTENT_VERSION,
            "advisory_only": True,
            "active_attempts": entries,
            "overlaps": overlaps,
            "dependency_matches": dependency_matches,
            "unknown_attempts": unknown_attempts,
        }
