"""Claim, heartbeat, the write guard, and submit: everything an attempt does while it holds
its leases and fencing tokens.

Moved verbatim out of `git_supervisor` (board #1630). `GitSupervisor` inherits this mixin, so
every call site, CLI path and `GitSupervisor.<name>` lookup resolves exactly as before.
"""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import json
import os
import queue
import re
import shutil
import sqlite3
import stat
import subprocess
import threading
import time
import unicodedata
import uuid
from collections.abc import Sequence
from functools import cache
from pathlib import Path, PurePosixPath
from typing import Any

from ..scheduling import declared_read_resources, declared_resources, normalize_artifact
from .common import SUBMISSION_OBJECT_CONTRACT, SupervisorError, canonical_json, sha256, utc_now
from .result_import import (
    CandidateTree,
    build_candidate_tree,
    candidate_commit_object,
    candidate_commit_payload,
    candidate_ref_target,
    candidate_tree_object_ids,
    cleanup_candidate_object_temps,
    missing_candidate_objects,
    promote_candidate_objects,
    publish_candidate_ref,
    remove_unreachable_candidate_objects,
    result_ref_name,
    verify_candidate_objects,
)
from .sandbox_execution_journal import _require_sandbox_execution_result_eligible
from .sandbox_workspace import ChangeSet, Snapshot
from .schema import META_CASE_SENSITIVE

_READ_RESOURCE_MAX_PATHS = 10_000
_READ_RESOURCE_MAX_CACHED_SCOPES = 16
_READ_RESOURCE_MAX_LISTING_BYTES = 16 * 1024 * 1024
_RESULT_MANIFEST_MAX_BYTES = 64 * 1024
_RESULT_SUMMARY_MAX_BYTES = 4 * 1024
_RESULT_ARTIFACT_MAX_COUNT = 16
_RESULT_ARTIFACT_MAX_PATH_BYTES = 1024
_RESULT_ARTIFACT_MAX_BYTES = 64 * 1024 * 1024
_RESULT_ARTIFACT_TOTAL_MAX_BYTES = 256 * 1024 * 1024
_RESULT_IMPORT_STAGE_MAX_BYTES = 512 * 1024 * 1024
_RESULT_IMPORT_STAGING_TOTAL_MAX_BYTES = 2 * 1024 * 1024 * 1024


class ClaimsMixin:
    """Claiming a task, heartbeats, the write-set guard and submission."""

    def _git_readonly_bytes_bounded(self, *arguments: str, max_bytes: int) -> bytes:
        """Read a sanitized Git query without buffering an unbounded tree listing."""
        git = str(self._system_git_executable(self.root))
        argv = [
            *self._supervisor_git_prefix(git, Path(os.devnull)),
            "-C",
            str(self.root),
            *arguments,
        ]
        try:
            process = subprocess.Popen(
                argv,
                env=self._supervisor_git_env(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except OSError as error:
            raise SupervisorError("git_error", "could not start read-only Git query") from error

        chunks: queue.Queue[bytes] = queue.Queue(maxsize=2)
        reader_done = threading.Event()
        stop_reader = threading.Event()

        def drain_stdout() -> None:
            try:
                assert process.stdout is not None
                while not stop_reader.is_set():
                    chunk = process.stdout.read1(64 * 1024)
                    if not chunk:
                        break
                    while not stop_reader.is_set():
                        try:
                            chunks.put(chunk, timeout=0.05)
                            break
                        except queue.Full:
                            continue
            except (OSError, ValueError):
                # The parent closes the pipe after a timeout or size-limit refusal.
                pass
            finally:
                reader_done.set()

        reader = threading.Thread(target=drain_stdout, daemon=True)
        reader.start()
        output = bytearray()
        deadline = time.monotonic() + 10
        try:
            while not reader_done.is_set() or not chunks.empty():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SupervisorError("git_timeout", "read-only Git query timed out")
                try:
                    chunk = chunks.get(timeout=min(0.05, remaining))
                except queue.Empty:
                    continue
                if len(output) + len(chunk) > max_bytes:
                    raise SupervisorError(
                        "read_resource_scope_too_large",
                        f"read-resource Git listing exceeded {max_bytes} bytes",
                    )
                output.extend(chunk)
            try:
                return_code = process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as error:
                raise SupervisorError("git_timeout", "read-only Git query timed out") from error
            if return_code:
                raise SupervisorError("git_error", "read-only Git query failed")
            return bytes(output)
        finally:
            stop_reader.set()
            if process.poll() is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                if process.poll() is None:
                    try:
                        process.wait(timeout=0.5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
            if process.stdout is not None:
                process.stdout.close()
            reader.join(timeout=1)

    @staticmethod
    def _result_manifest_path(value: Any) -> str:
        """Return one portable repository-relative UTF-8 path or reject it."""
        if not isinstance(value, str) or not value or "\\" in value:
            raise SupervisorError(
                "invalid_result_manifest", "completion result manifest contains an invalid path"
            )
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise SupervisorError(
                "invalid_result_manifest", "completion result manifest contains an invalid path"
            ) from error
        parts = value.split("/")
        path = PurePosixPath(value)
        if (
            len(encoded) > _RESULT_ARTIFACT_MAX_PATH_BYTES
            or path.is_absolute()
            or path.as_posix() != value
            or any(part in {"", ".", ".."} for part in parts)
            or any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value)
        ):
            raise SupervisorError(
                "invalid_result_manifest", "completion result manifest contains an invalid path"
            )
        return value

    def _result_manifest_tree_entry(self, commit: str, path: str) -> tuple[str, str, str]:
        """Resolve one literal path from an immutable commit without reading file bodies."""
        try:
            listing = self._git_readonly_bytes_bounded(
                "--literal-pathspecs",
                "ls-tree",
                "-rz",
                "--full-tree",
                commit,
                "--",
                path,
                max_bytes=128 * 1024,
            )
        except SupervisorError as error:
            raise SupervisorError(
                "invalid_result_manifest",
                "completion result manifest references an unreadable path",
            ) from error
        wanted = path.encode("utf-8")
        matches: list[tuple[str, str, str]] = []
        for record in listing.split(b"\0"):
            if not record:
                continue
            metadata, separator, raw_path = record.partition(b"\t")
            if not separator or raw_path != wanted:
                continue
            try:
                mode, object_type, object_id = metadata.decode("ascii").split(" ")
            except (UnicodeDecodeError, ValueError) as error:
                raise SupervisorError(
                    "invalid_result_manifest",
                    "completion result manifest references an invalid Git entry",
                ) from error
            matches.append((mode, object_type, object_id))
        if len(matches) != 1:
            raise SupervisorError(
                "invalid_result_manifest", "completion result manifest path is absent or ambiguous"
            )
        mode, object_type, object_id = matches[0]
        if (
            mode not in {"100644", "100755"}
            or object_type != "blob"
            or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", object_id) is None
        ):
            raise SupervisorError(
                "invalid_result_manifest",
                "completion result manifest only supports regular Git files",
            )
        return mode, object_type, object_id

    def _completion_receipt_json(
        self,
        commit: str,
        changed_paths: list[str],
        manifest_path: str | None,
        credential: str | None,
    ) -> str:
        """Validate an optional manifest against the submitted commit and store only refs."""
        if manifest_path is None:
            return ""

        manifest_path = self._result_manifest_path(manifest_path)
        if manifest_path not in changed_paths:
            raise SupervisorError(
                "invalid_result_manifest", "completion manifest must be changed in the submission"
            )
        _, _, manifest_blob = self._result_manifest_tree_entry(commit, manifest_path)
        try:
            manifest_size = int(self._git_text("cat-file", "-s", manifest_blob))
            if manifest_size < 1 or manifest_size > _RESULT_MANIFEST_MAX_BYTES:
                raise ValueError("manifest size outside configured limit")
            raw_manifest = self._git_readonly_bytes_bounded(
                "cat-file", "blob", manifest_blob, max_bytes=_RESULT_MANIFEST_MAX_BYTES
            )
            text_manifest = raw_manifest.decode("utf-8")

            def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
                result: dict[str, Any] = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("duplicate JSON key")
                    result[key] = value
                return result

            payload = json.loads(text_manifest, object_pairs_hook=unique_object)
        except (
            SupervisorError,
            UnicodeDecodeError,
            ValueError,
            json.JSONDecodeError,
            RecursionError,
        ) as error:
            raise SupervisorError(
                "invalid_result_manifest", "completion result manifest is unreadable or over limit"
            ) from error
        if (
            not isinstance(payload, dict)
            or set(payload) != {"version", "summary", "artifacts"}
            or type(payload.get("version")) is not int
            or payload["version"] != 1
        ):
            raise SupervisorError(
                "invalid_result_manifest", "completion result manifest has an unsupported shape"
            )

        summary = payload.get("summary")
        artifacts = payload.get("artifacts")
        if not isinstance(summary, str) or not summary.strip() or not isinstance(artifacts, list):
            raise SupervisorError(
                "invalid_result_manifest",
                "completion result manifest requires a summary and artifacts",
            )
        try:
            summary_bytes = summary.encode("utf-8")
        except UnicodeEncodeError as error:
            raise SupervisorError(
                "invalid_result_manifest", "completion summary is not valid UTF-8"
            ) from error
        if (
            len(summary_bytes) > _RESULT_SUMMARY_MAX_BYTES
            or any(
                ord(character) < 32 and character not in "\n\t" or 127 <= ord(character) <= 159
                for character in summary
            )
            or (credential and credential in summary)
            or (credential and credential in manifest_path)
        ):
            raise SupervisorError(
                "invalid_result_manifest", "completion summary is unsafe or over its size limit"
            )
        if not artifacts or len(artifacts) > _RESULT_ARTIFACT_MAX_COUNT:
            raise SupervisorError(
                "invalid_result_manifest", "completion artifact count is outside configured limits"
            )

        resolved: list[dict[str, Any]] = []
        seen: set[str] = set()
        total_bytes = 0
        for artifact in artifacts:
            if not isinstance(artifact, dict) or set(artifact) != {"path", "blob_oid"}:
                raise SupervisorError(
                    "invalid_result_manifest",
                    "completion artifacts require exactly a path and Git blob id",
                )
            path = self._result_manifest_path(artifact["path"])
            if path == manifest_path or path in seen or (credential and credential in path):
                raise SupervisorError(
                    "invalid_result_manifest",
                    "completion result manifest contains a duplicate or unsafe path",
                )
            expected_blob_id = artifact["blob_oid"]
            if (
                not isinstance(expected_blob_id, str)
                or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", expected_blob_id) is None
            ):
                raise SupervisorError(
                    "invalid_result_manifest", "completion artifact Git blob id is invalid"
                )
            seen.add(path)
            _, _, blob_id = self._result_manifest_tree_entry(commit, path)
            if blob_id != expected_blob_id:
                raise SupervisorError(
                    "invalid_result_manifest",
                    "completion artifact Git blob id does not match the submitted commit",
                )
            try:
                size = int(self._git_text("cat-file", "-s", blob_id))
            except (SupervisorError, ValueError) as error:
                raise SupervisorError(
                    "invalid_result_manifest", "completion artifact size could not be verified"
                ) from error
            if size < 0 or size > _RESULT_ARTIFACT_MAX_BYTES:
                raise SupervisorError(
                    "invalid_result_manifest", "completion artifact exceeds its size limit"
                )
            total_bytes += size
            if total_bytes > _RESULT_ARTIFACT_TOTAL_MAX_BYTES:
                raise SupervisorError(
                    "invalid_result_manifest", "completion artifacts exceed aggregate size limit"
                )
            resolved.append({"path": path, "blob_oid": blob_id, "size_bytes": size})

        return canonical_json(
            {
                "version": 1,
                "summary": summary,
                "manifest_path": manifest_path,
                "manifest_blob_oid": manifest_blob,
                "artifacts": resolved,
            }
        )

    def _prepare_attempt_worktree(self, attempt_id: str) -> tuple[Path, Path]:
        """Create/validate the managed root and reserve an unused attempt path.

        Only the root is created here. The attempt directory itself is left to Git,
        and a pre-existing path or Git registration is rejected before any attempt
        row is inserted or worker can be launched.
        """

        root = self._attempt_worktree_root
        try:
            root.mkdir(parents=True, exist_ok=True)
            canonical_root = root.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise SupervisorError(
                "worktree_root_unavailable",
                f"attempt worktree root cannot be safely created: {root}",
            ) from error
        if canonical_root != root or not canonical_root.is_dir() or canonical_root.is_symlink():
            raise SupervisorError(
                "unsafe_worktree_root",
                f"attempt worktree root changed during creation: {root}",
            )
        worktree = canonical_root / attempt_id
        if os.path.lexists(worktree) or str(worktree) in self._registered_worktrees():
            raise SupervisorError(
                "worktree_collision",
                f"attempt worktree path is already present or registered: {worktree}",
            )
        return canonical_root, worktree

    def claim(
        self,
        task_id: str,
        agent_id: str,
        lease_seconds: int | None = None,
        credential: str | None = None,
    ) -> dict[str, Any]:
        if not agent_id.strip():
            raise SupervisorError("invalid_agent", "agent_id is required")
        self._authenticate(agent_id, "worker", credential)
        self._assert_safe_git_execution_config()
        self.reap_expired()
        ttl = lease_seconds or self.config.lease_seconds
        if ttl < 10:
            raise SupervisorError("invalid_lease", "lease must be at least 10 seconds")
        # Pin the shared checkout before this claim provisions anything. ACP does
        # not require it to be clean; it records the exact pre-existing source state.
        base_checkout_snapshot = self._capture_base_checkout_snapshot()
        expires = int(time.time()) + ttl
        attempt_id = str(uuid.uuid4())
        worktree_root, worktree = self._prepare_attempt_worktree(attempt_id)
        now = utc_now()
        # Resolve ``current`` once, before the attempt exists. Every later phase
        # reads this stored pin, so a rotation affects only subsequent claims.
        trust_pin = self._current_trust_pin()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            identity = self._authenticate(agent_id, "worker", credential, connection)
            task = self._task_row(connection, task_id)
            if task["status"] not in {"open", "orphaned", "changes_requested"}:
                raise SupervisorError("task_unavailable", f"task status is {task['status']}")
            for dependency in json.loads(task["dependencies_json"]):
                row = connection.execute(
                    "SELECT status FROM tasks WHERE id = ?", (dependency,)
                ).fetchone()
                if not row or row["status"] != "done":
                    raise SupervisorError(
                        "dependency_incomplete", f"dependency {dependency} is not done"
                    )
            for artifact in json.loads(task["consumes_json"]):
                producer = connection.execute(
                    """
                    SELECT id, status FROM tasks
                    WHERE id != ? AND status != 'done'
                      AND EXISTS (
                        SELECT 1 FROM json_each(tasks.produces_json) WHERE value = ?
                      )
                    ORDER BY id LIMIT 1
                    """,
                    (task_id, artifact),
                ).fetchone()
                if producer:
                    raise SupervisorError(
                        "dependency_incomplete",
                        f"artifact {artifact} is produced by task {producer['id']} "
                        f"which is {producer['status']}",
                    )
            requested = json.loads(task["resources_json"])
            requested_declared = dict(zip(requested, self._declared_resources(task), strict=False))
            leases = connection.execute(
                """
                SELECT lease.resource, lease.task_id, lease.attempt_id,
                       attempt.agent_id AS agent_id,
                       owner.resources_json AS resources_json,
                       owner.declared_resources_json AS declared_resources_json
                FROM resource_leases AS lease
                LEFT JOIN attempts AS attempt ON attempt.id = lease.attempt_id
                LEFT JOIN tasks AS owner ON owner.id = lease.task_id
                WHERE lease.task_id IS NOT NULL AND lease.lease_expires_at > ?
                """,
                (int(time.time()),),
            ).fetchall()
            for resource in requested:
                for lease in leases:
                    holder_declared = (
                        dict(
                            zip(
                                json.loads(lease["resources_json"]),
                                declared_resources(lease),
                                strict=False,
                            )
                        ).get(lease["resource"])
                        if lease["resources_json"]
                        else None
                    )
                    if lease["task_id"] != task_id and self.resources_overlap(
                        resource,
                        lease["resource"],
                        left_declared=requested_declared.get(resource),
                        right_declared=holder_declared,
                    ):
                        overlap = "exact" if resource == lease["resource"] else "potential"
                        # Name BOTH sides as their tasks declared them (#1764, board #1630):
                        # on a case-sensitive checkout the folded spelling names a file that
                        # does not exist. Display only, and only on this refusal path — the
                        # collision itself was decided above on the folded lease keys.
                        # strict=False: declared_resources maps over the folded list, so the
                        # lengths match by construction, and a refusal must never turn into a
                        # ValueError the CLI does not catch.
                        mine = dict(zip(requested, self._declared_resources(task), strict=False))
                        holder = connection.execute(
                            "SELECT resources_json, declared_resources_json FROM tasks "
                            "WHERE id = ?",
                            (lease["task_id"],),
                        ).fetchone()
                        theirs = (
                            dict(
                                zip(
                                    json.loads(holder["resources_json"]),
                                    declared_resources(holder),
                                    strict=False,
                                )
                            )
                            if holder
                            else {}
                        )
                        raise SupervisorError(
                            "resource_busy",
                            f"{mine.get(resource, resource)} has an {overlap} overlap with "
                            f"active lease {theirs.get(lease['resource'], lease['resource'])} "
                            f"held by task {lease['task_id']} "
                            f"(agent {lease['agent_id'] or 'unknown'}, "
                            f"attempt {lease['attempt_id'] or 'unknown'})",
                        )
            counter_row = connection.execute(
                "SELECT value FROM meta WHERE key = 'claim_counter'"
            ).fetchone()
            counter = int(counter_row["value"]) + 1
            connection.execute(
                "UPDATE meta SET value = ? WHERE key = 'claim_counter'", (str(counter),)
            )
            number = connection.execute(
                """
                SELECT COALESCE(MAX(number), 0) + 1 AS value
                FROM attempts WHERE task_id = ?
                """,
                (task_id,),
            ).fetchone()["value"]
            resume = connection.execute(
                """
                SELECT latest_sha, read_resources_snapshot_json FROM attempts
                WHERE task_id = ? AND latest_sha IS NOT NULL
                ORDER BY number DESC LIMIT 1
                """,
                (task_id,),
            ).fetchone()
            start_sha = resume["latest_sha"] if resume else task["base_sha"]
            read_resources = declared_read_resources(task)
            read_snapshot_json = (
                resume["read_resources_snapshot_json"]
                if resume and resume["read_resources_snapshot_json"]
                else self._capture_read_resource_snapshot(
                    start_sha,
                    read_resources,
                )
            )
            branch = f"acp/task-{task_id[:8]}-a{number}"
            connection.execute(
                """
                INSERT INTO attempts
                  (id, task_id, number, agent_id, runner_credential_digest,
                   branch, worktree, worktree_root, claim_token,
                   start_sha, latest_sha, checkpoint_json, heartbeat_at, checkpoint_at,
                   read_resources_snapshot_json, trust_bundle_json,
                   pid, log_path, status,
                   lease_expires_at, created_at, updated_at, base_checkout_snapshot_json,
                   base_checkout_snapshot_required)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', ?, ?, ?, ?, NULL, NULL,
                        'provisioning', ?, ?, ?, ?, 1)
                """,
                (
                    attempt_id,
                    task_id,
                    number,
                    agent_id,
                    identity["credential_digest"] if identity else None,
                    branch,
                    str(worktree),
                    str(worktree_root),
                    counter,
                    start_sha,
                    start_sha,
                    now,
                    "",
                    read_snapshot_json,
                    canonical_json(trust_pin),
                    expires,
                    now,
                    now,
                    canonical_json(base_checkout_snapshot),
                ),
            )
            self._allocate_runtime(
                connection,
                attempt_id,
                task_id,
                worktree,
                expires,
                now,
            )
            for resource in requested:
                prior = connection.execute(
                    "SELECT fencing_token FROM resource_leases WHERE resource = ?",
                    (resource,),
                ).fetchone()
                token = (prior["fencing_token"] if prior else 0) + 1
                connection.execute(
                    """
                    INSERT INTO resource_leases
                      (resource, task_id, attempt_id, fencing_token,
                       lease_expires_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(resource) DO UPDATE SET
                      task_id = excluded.task_id,
                      attempt_id = excluded.attempt_id,
                      fencing_token = excluded.fencing_token,
                      lease_expires_at = excluded.lease_expires_at,
                      updated_at = excluded.updated_at
                    """,
                    (resource, task_id, attempt_id, token, expires, now),
                )
            connection.execute(
                """
                UPDATE tasks SET status = 'provisioning',
                  current_attempt_id = ?, updated_at = ? WHERE id = ?
                """,
                (attempt_id, now, task_id),
            )
            self._event(
                connection,
                "attempt.claimed",
                agent_id,
                {
                    "task_id": task_id,
                    "attempt_id": attempt_id,
                    "claim_token": counter,
                    "start_sha": start_sha,
                },
            )
        worktree_created = False
        try:
            self._assert_safe_git_execution_config()
            self._git(
                "worktree",
                "add",
                "-b",
                branch,
                str(worktree),
                start_sha,
                _before=lambda: self._assert_attempt_worktree_headroom(worktree_root),
            )
            worktree_created = True
            self._runtime_up(attempt_id)
        except (OSError, subprocess.SubprocessError, SupervisorError):
            if worktree_created:
                try:
                    self.runtime_down(attempt_id, force=True, _allow_active=True)
                except (OSError, subprocess.SubprocessError, SupervisorError):
                    pass
                try:
                    self._remove_worktree(worktree, delete_branch=True, expected_branch=branch)
                except (OSError, subprocess.SubprocessError, SupervisorError):
                    pass
            else:
                self._abandon_runtime(attempt_id)
                # A command wrapper or interruption can report failure after Git
                # registered the exact path. Clean up only when the unique attempt
                # path is registered on this attempt's branch; never infer ownership
                # from a directory merely existing at the target path.
                try:
                    registered_branch = self._registered_worktrees().get(
                        str(worktree.resolve(strict=False))
                    )
                except (OSError, subprocess.SubprocessError, SupervisorError):
                    registered_branch = None
                if registered_branch == branch:
                    try:
                        self._remove_worktree(worktree, delete_branch=True, expected_branch=branch)
                    except (OSError, subprocess.SubprocessError, SupervisorError):
                        pass
            self._rollback_provision(task_id, attempt_id)
            raise
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE attempts SET status = 'working', updated_at = ? WHERE id = ?",
                (utc_now(), attempt_id),
            )
            connection.execute(
                "UPDATE tasks SET status = 'working', updated_at = ? WHERE id = ?",
                (utc_now(), task_id),
            )
            self._event(
                connection,
                "attempt.ready",
                "supervisor",
                {
                    "attempt_id": attempt_id,
                    "worktree": str(worktree),
                    "base_checkout_snapshot_sha256": sha256(
                        canonical_json(base_checkout_snapshot).encode()
                    ),
                    "base_checkout_path_count": len(base_checkout_snapshot["entries"]),
                },
            )
        return self.attempt(attempt_id)

    def _rollback_provision(self, task_id: str, attempt_id: str) -> None:
        now = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE attempts SET status = 'failed', updated_at = ? WHERE id = ?",
                (now, attempt_id),
            )
            connection.execute(
                """
                UPDATE tasks SET status = 'open', current_attempt_id = NULL,
                  updated_at = ? WHERE id = ? AND current_attempt_id = ?
                """,
                (now, task_id, attempt_id),
            )
            connection.execute(
                """
                UPDATE resource_leases SET task_id = NULL, attempt_id = NULL,
                  lease_expires_at = 0, updated_at = ? WHERE attempt_id = ?
                """,
                (now, attempt_id),
            )
            self._event(
                connection,
                "attempt.provision_failed",
                "supervisor",
                {"attempt_id": attempt_id},
            )

    def heartbeat(
        self,
        attempt_id: str,
        claim_token: int,
        checkpoint: dict[str, Any] | None = None,
        lease_seconds: int | None = None,
        credential: str | None = None,
    ) -> dict[str, Any]:
        if checkpoint is not None and not isinstance(checkpoint, dict):
            raise SupervisorError("invalid_checkpoint", "checkpoint must be a JSON object")
        # Authenticate before a verification failure is allowed to change state.
        with self.connect() as connection:
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            self._authenticate_attempt(connection, attempt, credential)
        # A long-running worker must not retain authority after its immutable
        # trust bundle disappears. Quarantine commits in its own transaction so
        # the following claim-inactive error cannot roll the fence back.
        self._verify_attempt_trust(attempt_id)
        ttl = lease_seconds or self.config.lease_seconds
        expires = int(time.time()) + ttl
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            self._authenticate_attempt(connection, attempt, credential)
            task = self._task_row(connection, attempt["task_id"])
            runtime = connection.execute(
                "SELECT state FROM runtime_environments WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if not runtime or runtime["state"] != "ready":
                raise SupervisorError(
                    "runtime_not_ready",
                    f"attempt runtime state is {runtime['state'] if runtime else 'missing'}",
                )
            expected = set(json.loads(task["resources_json"]))
            rows = connection.execute(
                "SELECT * FROM resource_leases WHERE attempt_id = ?", (attempt_id,)
            ).fetchall()
            active = {
                row["resource"]
                for row in rows
                if row["task_id"] == task["id"] and row["lease_expires_at"] > int(time.time())
            }
            if active != expected:
                raise SupervisorError("stale_fencing_token", "resource lease set changed")
            head = self._git_text("-C", attempt["worktree"], "rev-parse", "HEAD")
            now = utc_now()
            assignments = [
                "latest_sha = ?",
                "heartbeat_at = ?",
                "lease_expires_at = ?",
                "updated_at = ?",
            ]
            values: list[Any] = [head, now, expires, now]
            checkpoint_json = canonical_json(checkpoint) if checkpoint is not None else None
            if checkpoint_json is not None and (
                checkpoint_json != attempt["checkpoint_json"] or not attempt["checkpoint_at"]
            ):
                assignments.extend(["checkpoint_json = ?", "checkpoint_at = ?"])
                values.extend([checkpoint_json, now])
            values.append(attempt_id)
            connection.execute(f"UPDATE attempts SET {', '.join(assignments)} WHERE id = ?", values)
            count = connection.execute(
                """
                UPDATE resource_leases SET lease_expires_at = ?, updated_at = ?
                WHERE attempt_id = ? AND task_id = ?
                """,
                (expires, now, attempt_id, task["id"]),
            ).rowcount
            if count != len(expected):
                raise SupervisorError("stale_fencing_token", "resource lease set changed")
            connection.execute(
                """
                UPDATE runtime_allocations SET lease_expires_at = ?, updated_at = ?
                WHERE attempt_id = ?
                """,
                (expires, now, attempt_id),
            )
            self._event(
                connection,
                "attempt.heartbeat",
                attempt["agent_id"],
                {"attempt_id": attempt_id, "latest_sha": head},
            )
        return self.attempt(attempt_id)

    def attempt(self, attempt_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
            if not row:
                raise SupervisorError("attempt_not_found", f"attempt {attempt_id} not found")
            return self._attempt_view(connection, row)

    def guard(
        self,
        attempt_id: str,
        path: str,
        *,
        cwd: str | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Decide whether an agent holding `attempt_id` may write `path`.

        This is the check an editor's pre-write hook asks before letting a tool call
        through, and it is deliberately the SAME check `submit` applies to the diff:
        both run `_path_matches` over `_write_set_rules`, so the case sensitivity of the
        filesystem is decided in one place for both. An adapter that reimplemented the
        matching would be a second enforcement implementation that could disagree with
        the one that matters, which is worse than none.

        `cwd` binds an editor hook's relative target to the directory the host says the
        tool is running in. If supplied, it must resolve to the attempt worktree or one
        of its subdirectories. Omit it for the CLI/MCP contract, where relative paths
        are rooted at the attempt worktree.

        Read-only, so it runs on a read-only supervisor and cannot itself become a
        reason the state changed.
        """

        epoch = int(time.time()) if now is None else now
        with self.connect() as connection:
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
            if attempt is None:
                return self._guard_denial(
                    attempt_id, path, "attempt_not_found", f"no attempt {attempt_id}"
                )
            task = connection.execute(
                "SELECT * FROM tasks WHERE id = ?", (attempt["task_id"],)
            ).fetchone()
            # Shown to the agent as the operator typed it: on a case-sensitive volume a
            # denial that answered `makefile` would point at the path just refused.
            declared = self._declared_resources(task) if task else []
            rules = (
                self._write_set_rules(task, self._case_sensitive_paths(connection)) if task else []
            )

        if attempt["status"] not in {"provisioning", "working"}:
            return self._guard_denial(
                attempt_id,
                path,
                "attempt_not_live",
                f"attempt is {attempt['status']}; only a live attempt may write",
                declared=declared,
            )
        if attempt["lease_expires_at"] <= epoch:
            return self._guard_denial(
                attempt_id,
                path,
                "lease_expired",
                "the claim lease has expired; heartbeat or re-claim before writing",
                declared=declared,
            )

        worktree = Path(attempt["worktree"]).resolve()
        working_directory = worktree
        if cwd is not None:
            supplied_cwd = Path(cwd)
            if not supplied_cwd.is_absolute():
                return self._guard_denial(
                    attempt_id,
                    path,
                    "invalid_working_directory",
                    "the hook working directory must be an absolute existing directory",
                    declared=declared,
                )
            try:
                working_directory = supplied_cwd.resolve(strict=True)
            except (OSError, RuntimeError, ValueError):
                return self._guard_denial(
                    attempt_id,
                    path,
                    "invalid_working_directory",
                    "the hook working directory could not be resolved",
                    declared=declared,
                )
            if not working_directory.is_dir():
                return self._guard_denial(
                    attempt_id,
                    path,
                    "invalid_working_directory",
                    "the hook working directory is not an existing directory",
                    declared=declared,
                )
            if working_directory != worktree and worktree not in working_directory.parents:
                return self._guard_denial(
                    attempt_id,
                    path,
                    "cwd_outside_worktree",
                    f"hook working directory {working_directory} is outside the attempt worktree {worktree}",
                    declared=declared,
                )

        # resolve() follows symlinks, so a link planted inside the worktree that points
        # outside it resolves outside and is refused here rather than at submit time.
        try:
            target = Path(path)
            if not target.is_absolute():
                target = working_directory / target
            target = target.resolve()
        except (OSError, RuntimeError, ValueError):
            return self._guard_denial(
                attempt_id,
                path,
                "invalid_path",
                "the target path could not be resolved",
                declared=declared,
            )
        if target != worktree and worktree not in target.parents:
            return self._guard_denial(
                attempt_id,
                path,
                "outside_worktree",
                f"{target} is outside the attempt worktree {worktree}",
                declared=declared,
            )

        relative = target.relative_to(worktree).as_posix()
        if not any(
            self._path_matches(relative, resource, fold=fold, is_logical=is_logical)
            for resource, fold, is_logical in rules
        ):
            return self._guard_denial(
                attempt_id,
                path,
                "undeclared_write",
                f"{relative} is not in the task's declared write set",
                declared=declared,
                relative_path=relative,
            )
        return {
            "ok": True,
            "allow": True,
            "attempt_id": attempt_id,
            "path": str(target),
            "relative_path": relative,
            "worktree": str(worktree),
            "declared": declared,
        }

    @staticmethod
    def _declared_resources(task: sqlite3.Row) -> list[str]:
        """The write set as the operator wrote it, falling back to the folded form.

        Rows created before the column existed have an empty map, and a raw form is not
        recoverable from anywhere in the database — so the fallback is the folded string
        rather than a guess at its capitalisation.
        """

        return declared_resources(task)

    @staticmethod
    def _case_sensitive_paths(connection: sqlite3.Connection) -> bool:
        """The recorded answer, or the pre-existing behaviour when nothing was recorded."""

        row = connection.execute(
            "SELECT value FROM meta WHERE key = ?", (META_CASE_SENSITIVE,)
        ).fetchone()
        return bool(row) and row["value"] == "1"

    def _capture_read_resource_snapshot(
        self,
        base_sha: str,
        resources: Sequence[str],
        *,
        tree_cache: dict[tuple[str, tuple[str, ...]], dict[str, str]] | None = None,
    ) -> str:
        """Capture matching tracked Git object ids without executing candidate code."""
        if not resources:
            return ""
        files: dict[str, str] = {}
        matched = {resource: False for resource in resources}
        try:
            normalized_resources = {
                resource: self.normalize_resource(resource, self.root, fold=False)
                for resource in resources
            }
            prefixes: set[str] = set()
            for resource in normalized_resources.values():
                has_glob = any(character in resource for character in "*?[")
                prefix = (
                    self._literal_prefix(resource) if has_glob else resource.removesuffix("/**")
                )
                if has_glob and not prefix:
                    return canonical_json(
                        {
                            "state": "unknown",
                            "base_sha": base_sha,
                            "files": {},
                            "unmatched_resources": [
                                item
                                for item, normalized in normalized_resources.items()
                                if any(character in normalized for character in "*?[")
                                and not self._literal_prefix(normalized)
                            ],
                            "reason": (
                                "root-wide glob has no literal directory prefix; narrow the "
                                "read resource to avoid scanning the full repository"
                            ),
                        }
                    )
                if prefix:
                    prefixes.add(prefix)

            # A parent prefix already covers every descendant; removing descendants keeps
            # Git's literal pathspec query and the per-render cache bounded and predictable.
            pathspecs: list[str] = []
            for prefix in sorted(prefixes, key=lambda item: (item.count("/"), item)):
                if not any(
                    prefix == parent or prefix.startswith(parent + "/") for parent in pathspecs
                ):
                    pathspecs.append(prefix)
            cache_key = (base_sha, tuple(pathspecs))
            tracked = tree_cache.get(cache_key) if tree_cache is not None else None
            if tracked is None:
                listing = self._git_readonly_bytes_bounded(
                    "--literal-pathspecs",
                    "ls-tree",
                    "-r",
                    "-z",
                    base_sha,
                    "--",
                    *pathspecs,
                    max_bytes=_READ_RESOURCE_MAX_LISTING_BYTES,
                )
                tracked = {}
                offset = 0
                entry_count = 0
                while offset < len(listing):
                    end = listing.find(b"\0", offset)
                    if end < 0:
                        end = len(listing)
                    entry = listing[offset:end]
                    offset = end + 1
                    if not entry:
                        continue
                    entry_count += 1
                    if entry_count > _READ_RESOURCE_MAX_PATHS:
                        return canonical_json(
                            {
                                "state": "unknown",
                                "base_sha": base_sha,
                                "files": {},
                                "unmatched_resources": list(resources),
                                "reason": (
                                    "read-resource prefix scan exceeded "
                                    f"{_READ_RESOURCE_MAX_PATHS} tracked paths"
                                ),
                            }
                        )
                    metadata, separator, path_bytes = entry.partition(b"\t")
                    if not separator:
                        continue
                    fields = metadata.decode("ascii", errors="replace").split()
                    if len(fields) != 3 or fields[1] not in {"blob", "commit"}:
                        continue
                    path = path_bytes.decode("utf-8", errors="surrogateescape")
                    tracked[path] = fields[2]
                if tree_cache is not None and len(tree_cache) < _READ_RESOURCE_MAX_CACHED_SCOPES:
                    tree_cache[cache_key] = tracked
            for path, object_id in tracked.items():
                for resource, normalized in normalized_resources.items():
                    if not self._path_matches(
                        path,
                        normalized,
                        fold=False,
                        is_logical=False,
                    ):
                        continue
                    files[path] = object_id
                    matched[resource] = True
        except (OSError, SupervisorError, subprocess.SubprocessError, ValueError) as error:
            return canonical_json(
                {
                    "state": "unknown",
                    "base_sha": base_sha,
                    "files": {},
                    "unmatched_resources": list(resources),
                    "reason": f"read-resource snapshot failed: {error}",
                }
            )
        return canonical_json(
            {
                "state": "known",
                "base_sha": base_sha,
                "files": files,
                "unmatched_resources": [
                    resource for resource, found in matched.items() if not found
                ],
            }
        )

    def _read_resource_advisory(
        self,
        resources: Sequence[str],
        snapshot_json: str | None,
        base_branch: str,
        *,
        tree_cache: dict[tuple[str, tuple[str, ...]], dict[str, str]] | None = None,
    ) -> dict[str, Any] | None:
        """Compare declared input identities with the current integration base."""
        if not resources:
            return None
        try:
            baseline = json.loads(snapshot_json or "")
        except (TypeError, ValueError, json.JSONDecodeError):
            baseline = None
        try:
            current_base = (
                self._git_readonly_bytes("rev-parse", base_branch, check=False)
                .decode("ascii", errors="ignore")
                .strip()
            )
        except (OSError, SupervisorError, subprocess.SubprocessError):
            current_base = ""
        if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", current_base):
            return {
                "advisory": True,
                "state": "unknown",
                "base_branch": base_branch,
                "captured_base_sha": baseline.get("base_sha")
                if isinstance(baseline, dict)
                else None,
                "current_base_sha": None,
                "changed_path_count": 0,
                "changed_paths": [],
                "changed_paths_truncated": False,
                "unmatched_resources": list(resources),
                "reason": "configured integration base is unavailable",
            }
        if (
            not isinstance(baseline, dict)
            or baseline.get("state") != "known"
            or not isinstance(baseline.get("base_sha"), str)
            or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", baseline["base_sha"])
        ):
            return {
                "advisory": True,
                "state": "unknown",
                "base_branch": base_branch,
                "captured_base_sha": baseline.get("base_sha")
                if isinstance(baseline, dict)
                else None,
                "current_base_sha": current_base,
                "changed_path_count": 0,
                "changed_paths": [],
                "changed_paths_truncated": False,
                "unmatched_resources": list(resources),
                "reason": (
                    baseline.get("reason", "claim-time read-resource snapshot is unavailable")
                    if isinstance(baseline, dict)
                    else "claim-time read-resource snapshot is unavailable"
                ),
            }
        current_snapshot = json.loads(
            self._capture_read_resource_snapshot(current_base, resources, tree_cache=tree_cache)
        )
        if current_snapshot.get("state") != "known":
            return {
                "advisory": True,
                "state": "unknown",
                "base_branch": base_branch,
                "captured_base_sha": baseline.get("base_sha"),
                "current_base_sha": current_base,
                "changed_path_count": 0,
                "changed_paths": [],
                "changed_paths_truncated": False,
                "unmatched_resources": list(resources),
                "reason": current_snapshot.get(
                    "reason", "current read-resource snapshot is unavailable"
                ),
            }
        before = baseline.get("files")
        after = current_snapshot.get("files")
        if not isinstance(before, dict) or not isinstance(after, dict):
            changed: list[dict[str, Any]] = []
            reason = "read-resource snapshot has an invalid file map"
            state = "unknown"
        elif len(before) > _READ_RESOURCE_MAX_PATHS or len(after) > _READ_RESOURCE_MAX_PATHS:
            changed = []
            reason = "read-resource snapshot exceeds the tracked-path limit"
            state = "unknown"
        else:
            if any(
                not isinstance(path, str)
                or not isinstance(object_id, str)
                or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", object_id)
                for file_map in (before, after)
                for path, object_id in file_map.items()
            ):
                changed = []
                reason = "read-resource snapshot has an invalid file identity"
                state = "unknown"
            else:
                changed = [
                    {
                        "path": path,
                        "before_object_oid": before.get(path),
                        "after_object_oid": after.get(path),
                    }
                    for path in sorted(before.keys() | after.keys())
                    if before.get(path) != after.get(path)
                ]
                baseline_unmatched = baseline.get("unmatched_resources", [])
                current_unmatched = current_snapshot.get("unmatched_resources", [])
                if (
                    not isinstance(baseline_unmatched, list)
                    or not all(isinstance(item, str) for item in baseline_unmatched)
                    or not isinstance(current_unmatched, list)
                    or not all(isinstance(item, str) for item in current_unmatched)
                ):
                    baseline_unmatched = list(resources)
                    current_unmatched = []
                    reason = "read-resource snapshot has invalid unmatched-scope metadata"
                    state = "unknown"
                else:
                    unmatched = set(baseline_unmatched) | set(current_unmatched)
                    state = "unknown" if unmatched else "changed" if changed else "unchanged"
                    reason = (
                        "declared read resource did not match a tracked file" if unmatched else ""
                    )
        baseline_unmatched = baseline.get("unmatched_resources", [])
        current_unmatched = current_snapshot.get("unmatched_resources", [])
        if not isinstance(baseline_unmatched, list) or not all(
            isinstance(item, str) for item in baseline_unmatched
        ):
            baseline_unmatched = list(resources)
        if not isinstance(current_unmatched, list) or not all(
            isinstance(item, str) for item in current_unmatched
        ):
            current_unmatched = []
        unmatched_resources = sorted(set(baseline_unmatched) | set(current_unmatched))
        sample_limit = 20
        return {
            "advisory": True,
            "state": state,
            "base_branch": base_branch,
            "captured_base_sha": baseline.get("base_sha"),
            "current_base_sha": current_base,
            "changed_path_count": len(changed),
            "changed_paths": changed[:sample_limit],
            "changed_paths_truncated": len(changed) > sample_limit,
            "unmatched_resources": unmatched_resources,
            "reason": reason,
        }

    @classmethod
    def _write_set_rules(
        cls, task: sqlite3.Row, case_sensitive: bool
    ) -> list[tuple[str, bool, bool]]:
        """The write set as `(resource, fold, is_logical)` rules for `_path_matches`.

        The stored resource is folded, and folded is what the lease is keyed on, so this
        does not change what a task owns. It changes what counts as being INSIDE what the
        task owns: on a case-sensitive volume `Makefile` and `makefile` are two files, and
        a task that declared one must not be waved through to write the other.

        The decision is per resource, not per repository, because the raw form is the
        only thing that makes case-sensitive matching possible and it is not always
        there. `declared_resources_json` arrived with schema 2; for a row written before
        it, the operator's capitalisation is not recoverable from anywhere in the
        database, and matching its folded string case-sensitively would deny the task its
        own declared write. Such a row keeps folded matching — the behaviour it was
        created under. Same fallback when the stored raw form does not fold back to its
        own key, which means it is not the unfolded form of this resource and must not be
        matched against as if it were.
        """

        folded = json.loads(task["resources_json"])
        try:
            declared = json.loads(task["declared_resources_json"] or "{}")
        except (KeyError, IndexError, TypeError, ValueError):
            declared = {}
        rules: list[tuple[str, bool, bool]] = []
        for item in folded:
            raw = declared.get(item)
            if not isinstance(raw, str):
                rules.append((item, True, item.startswith("logical:")))
                continue
            # Before `logical:` was reserved, a case-variant prefix could name an
            # ordinary POSIX path and fold to the same stored key as a logical lock.
            # Keep those old rows path-typed using their raw declaration. New rows
            # cannot create this ambiguity (see normalize_resource).
            if cls._is_legacy_logical_path(raw):
                value = unicodedata.normalize("NFC", raw.strip().replace("\\", "/"))
                cased = PurePosixPath(value).as_posix()
                if item.endswith("/**") and not cased.endswith("/**"):
                    cased = cased.rstrip("/") + "/**"
                rules.append((cased, not case_sensitive, False))
                continue
            raw_value = unicodedata.normalize("NFC", raw.strip().replace("\\", "/"))
            is_logical = raw_value.startswith("logical:")
            if not case_sensitive:
                rules.append((item, True, is_logical))
                continue
            try:
                cased = cls.normalize_resource(raw, fold=False)
            except SupervisorError:
                rules.append((item, True, item.startswith("logical:")))
                continue
            # The directory suffix came from a probe of the repository at task creation,
            # which cannot be re-run reliably later; take it from the folded form, which
            # recorded the answer.
            if item.endswith("/**") and not cased.endswith("/**"):
                cased = cased.rstrip("/") + "/**"
            if cased.casefold() != item:
                rules.append((item, True, item.startswith("logical:")))
            else:
                rules.append((cased, False, is_logical))
        return rules

    @staticmethod
    def _is_legacy_logical_path(raw: str) -> bool:
        """Whether a pre-reservation declaration was a path alias of `logical:`."""

        value = unicodedata.normalize("NFC", raw.strip().replace("\\", "/"))
        canonical = PurePosixPath(value).as_posix()
        return canonical.casefold().startswith("logical:") and not value.startswith("logical:")

    def guard_context(self, attempt_id: str) -> dict[str, Any]:
        """What an agent needs to stay inside its claim: worktree and write set.

        A SessionStart hook prints this into the model's context. An agent told which
        paths it may write can plan inside them; one that finds out per-denial spends
        turns discovering the boundary by hitting it.
        """

        with self.connect() as connection:
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
            if attempt is None:
                raise SupervisorError("attempt_not_found", f"no attempt {attempt_id}")
            task = connection.execute(
                "SELECT * FROM tasks WHERE id = ?", (attempt["task_id"],)
            ).fetchone()
        return {
            "ok": True,
            "attempt_id": attempt_id,
            "task_id": attempt["task_id"],
            "status": attempt["status"],
            "worktree": attempt["worktree"],
            "branch": attempt["branch"],
            "lease_expires_at": attempt["lease_expires_at"],
            "declared": self._declared_resources(task) if task else [],
            "acceptance": json.loads(task["acceptance_json"]) if task else [],
        }

    @staticmethod
    def _guard_denial(
        attempt_id: str,
        path: str,
        reason: str,
        detail: str,
        *,
        declared: list[str] | None = None,
        relative_path: str | None = None,
    ) -> dict[str, Any]:
        return {
            "ok": True,
            "allow": False,
            "reason": reason,
            "detail": detail,
            "attempt_id": attempt_id,
            "path": path,
            "relative_path": relative_path,
            "declared": declared or [],
        }

    @staticmethod
    def _snapshot_metadata_path(path: bytes) -> bool:
        """Exclude ACP runtime state and Git administration from source evidence."""

        return any(path == name or path.startswith(name + b"/") for name in (b".acp", b".git"))

    @staticmethod
    def _snapshot_path_key(path: bytes) -> str:
        return base64.b64encode(path).decode("ascii")

    @staticmethod
    def _snapshot_path_error(path: bytes) -> SupervisorError:
        display = json.dumps(os.fsdecode(path), ensure_ascii=True)
        return SupervisorError(
            "base_checkout_uninspectable",
            f"cannot safely fingerprint base checkout path {display}",
        )

    def _open_snapshot_directory(
        self,
        parent_fd: int,
        name: str,
        display: bytes,
        *,
        within_snapshot_root: bool = True,
    ) -> int:
        descriptor = -1
        try:
            before_path = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISDIR(before_path.st_mode):
                raise self._snapshot_path_error(display)
            flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            descriptor = os.open(name, flags, dir_fd=parent_fd)
            opened = os.fstat(descriptor)
            after_path = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except SupervisorError:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        except (OSError, RuntimeError, TypeError, ValueError):
            if descriptor >= 0:
                os.close(descriptor)
            raise self._snapshot_path_error(display) from None
        identity = (
            self._stat_identity if within_snapshot_root else self._snapshot_directory_identity
        )
        if identity(before_path) != identity(opened) or identity(opened) != identity(after_path):
            os.close(descriptor)
            raise self._snapshot_path_error(display)
        return descriptor

    def _open_snapshot_root(
        self,
        root_real: Path,
        display: bytes,
        *,
        expected_root_identity: tuple[int, int, int, int, int] | None = None,
    ) -> tuple[int, list[int], list[tuple[int, str, int, bool]]]:
        if not root_real.is_absolute():
            raise self._snapshot_path_error(display)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            descriptor = os.open(root_real.anchor, flags)
        except (OSError, RuntimeError, TypeError, ValueError):
            raise self._snapshot_path_error(display) from None
        descriptors = [descriptor]
        directories: list[tuple[int, str, int, bool]] = []
        try:
            components = root_real.parts[1:]
            for index, component in enumerate(components):
                within_snapshot_root = index == len(components) - 1
                parent_fd = descriptors[-1]
                child_fd = self._open_snapshot_directory(
                    parent_fd,
                    component,
                    display,
                    within_snapshot_root=within_snapshot_root,
                )
                descriptors.append(child_fd)
                directories.append((parent_fd, component, child_fd, within_snapshot_root))
            if (
                expected_root_identity is not None
                and self._snapshot_directory_identity(os.fstat(descriptors[-1]))
                != expected_root_identity
            ):
                raise self._snapshot_path_error(display)
        except Exception:
            for opened_fd in reversed(descriptors):
                os.close(opened_fd)
            raise
        return descriptors[-1], descriptors, directories

    def _verify_snapshot_directories(
        self, directories: list[tuple[int, str, int, bool]], display: bytes
    ) -> None:
        try:
            for parent_fd, name, child_fd, within_snapshot_root in directories:
                current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                opened = os.fstat(child_fd)
                identity = (
                    self._stat_identity
                    if within_snapshot_root
                    else self._snapshot_directory_identity
                )
                if identity(current) != identity(opened):
                    raise self._snapshot_path_error(display)
        except SupervisorError:
            raise
        except (OSError, RuntimeError, TypeError, ValueError):
            raise self._snapshot_path_error(display) from None

    def _fingerprint_base_path(
        self,
        root_real: Path,
        relative: bytes,
        display: bytes,
        *,
        expected_root_identity: tuple[int, int, int, int, int] | None = None,
    ) -> dict[str, Any]:
        components = relative.split(b"/")
        if not components or any(part in {b"", b".", b".."} for part in components):
            raise self._snapshot_path_error(display)
        decoded = [os.fsdecode(part) for part in components]
        if any(
            separator and separator in part for part in decoded for separator in (os.sep, os.altsep)
        ):
            raise self._snapshot_path_error(display)
        if os.path.isabs(decoded[0]) or os.path.splitdrive(decoded[0])[0]:
            raise self._snapshot_path_error(display)
        if expected_root_identity is None:
            expected_root_identity = self._snapshot_root_identity(root_real, display)
        _root_fd, descriptors, directories = self._open_snapshot_root(
            root_real, display, expected_root_identity=expected_root_identity
        )
        try:
            for component in decoded[:-1]:
                parent_fd = descriptors[-1]
                child_fd = self._open_snapshot_directory(parent_fd, component, display)
                descriptors.append(child_fd)
                directories.append((parent_fd, component, child_fd, True))
            parent_fd = descriptors[-1]
            leaf = decoded[-1]
            before_path = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
            return {"kind": "missing"}
        except SupervisorError:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
            raise
        except (OSError, RuntimeError, TypeError, ValueError):
            for descriptor in reversed(descriptors):
                os.close(descriptor)
            raise self._snapshot_path_error(display) from None
        try:
            self._verify_snapshot_directories(directories, display)
            if stat.S_ISLNK(before_path.st_mode):
                try:
                    target_value = os.readlink(leaf, dir_fd=parent_fd)
                    after_path = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                except (OSError, RuntimeError, TypeError, ValueError):
                    raise self._snapshot_path_error(display) from None
                self._verify_snapshot_directories(directories, display)
                if self._stat_identity(before_path) != self._stat_identity(after_path):
                    raise self._snapshot_path_error(display)
                return {
                    "kind": "symlink",
                    "mode": stat.S_IMODE(before_path.st_mode),
                    "target_sha256": sha256(os.fsencode(target_value)),
                }
            if stat.S_ISREG(before_path.st_mode):
                file_fd = -1
                try:
                    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
                    file_fd = os.open(leaf, flags, dir_fd=parent_fd)
                    before_fd = os.fstat(file_fd)
                    if not stat.S_ISREG(before_fd.st_mode):
                        raise self._snapshot_path_error(display)
                    digest = hashlib.sha256()
                    while chunk := os.read(file_fd, 1024 * 1024):
                        digest.update(chunk)
                    after_fd = os.fstat(file_fd)
                    after_path = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                    self._verify_snapshot_directories(directories, display)
                except SupervisorError:
                    raise
                except (OSError, RuntimeError, TypeError, ValueError):
                    raise self._snapshot_path_error(display) from None
                finally:
                    if file_fd >= 0:
                        os.close(file_fd)
                if (
                    self._stat_identity(before_path) != self._stat_identity(before_fd)
                    or self._stat_identity(before_fd) != self._stat_identity(after_fd)
                    or self._stat_identity(after_fd) != self._stat_identity(after_path)
                ):
                    raise self._snapshot_path_error(display)
                return {
                    "kind": "file",
                    "mode": stat.S_IMODE(after_fd.st_mode),
                    "size": after_fd.st_size,
                    "sha256": digest.hexdigest(),
                }
            if stat.S_ISDIR(before_path.st_mode):
                child_fd = self._open_snapshot_directory(parent_fd, leaf, display)
                descriptors.append(child_fd)
                directories.append((parent_fd, leaf, child_fd, True))
                self._verify_snapshot_directories(directories, display)
                metadata = os.fstat(child_fd)
                return {"kind": "directory", "mode": stat.S_IMODE(metadata.st_mode)}
            raise self._snapshot_path_error(display)
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    @staticmethod
    def _stat_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    @staticmethod
    def _snapshot_directory_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
        """Identity of a path-prefix directory outside the checkout snapshot.

        Sibling worktrees and concurrent tests routinely create entries beneath
        shared temporary-directory ancestors. That changes directory size and
        timestamps without replacing the path component. Compare stable object
        and access-control identity there; retain full metadata checks from the
        checkout root downward, where entry changes can race the snapshot.
        """

        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
        )

    def _snapshot_root_identity(
        self, root_real: Path, display: bytes
    ) -> tuple[int, int, int, int, int]:
        try:
            metadata = os.stat(root_real, follow_symlinks=False)
        except (OSError, RuntimeError, TypeError, ValueError):
            raise self._snapshot_path_error(display) from None
        if not stat.S_ISDIR(metadata.st_mode):
            raise self._snapshot_path_error(display)
        return self._snapshot_directory_identity(metadata)

    def _verify_snapshot_root_identity(
        self,
        root_real: Path,
        expected: tuple[int, int, int, int, int],
        display: bytes,
    ) -> None:
        if self._snapshot_root_identity(root_real, display) != expected:
            raise self._snapshot_path_error(display)

    def _snapshot_checkout_repository(
        self,
        root: Path,
        prefix: bytes = b"",
        ancestors: frozenset[Path] = frozenset(),
    ) -> dict[str, Any]:
        try:
            real_root = root.resolve(strict=True)
            if real_root in ancestors:
                raise SupervisorError(
                    "base_checkout_uninspectable", "nested Git checkout loop in base checkout"
                )
            if len(ancestors) >= 64:
                raise SupervisorError(
                    "base_checkout_uninspectable", "nested Git checkout depth exceeds the limit"
                )
            ancestors = ancestors | {real_root}
            root_identity = self._snapshot_root_identity(real_root, os.fsencode(real_root))
            self._assert_safe_git_execution_config(real_root, snapshot_only=True)
            reported_root = self._git_bytes(
                "-C",
                str(root),
                "rev-parse",
                "--path-format=absolute",
                "--show-toplevel",
            )
            if (
                not reported_root.endswith(b"\n")
                or Path(os.fsdecode(reported_root[:-1])).resolve(strict=True) != real_root
            ):
                raise SupervisorError(
                    "base_checkout_uninspectable",
                    "nested Git checkout root does not match its source path",
                )
            self._verify_snapshot_root_identity(real_root, root_identity, os.fsencode(real_root))
            status_raw = self._git_bytes(
                "-C",
                str(root),
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=none",
            )
            self._verify_snapshot_root_identity(real_root, root_identity, os.fsencode(real_root))
            index_raw = self._git_bytes("-C", str(root), "ls-files", "--stage", "-z")
            self._verify_snapshot_root_identity(real_root, root_identity, os.fsencode(real_root))
        except SupervisorError as error:
            if error.code in {
                "base_checkout_uninspectable",
                "git_config_unreadable",
                "unsafe_git_execution_config",
            }:
                raise
            raise SupervisorError(
                "base_checkout_uninspectable", "cannot inspect base checkout Git state"
            ) from None
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            raise SupervisorError(
                "base_checkout_uninspectable", "cannot inspect base checkout Git state"
            ) from None

        index: dict[bytes, list[str]] = {}
        for record in index_raw.split(b"\0"):
            if not record:
                continue
            separator = record.find(b"\t")
            if separator < 0:
                raise SupervisorError(
                    "base_checkout_uninspectable", "base checkout index is unreadable"
                )
            header, path = record[:separator], record[separator + 1 :]
            fields = header.split(b" ")
            if len(fields) != 3 or self._snapshot_metadata_path(path):
                if len(fields) != 3:
                    raise SupervisorError(
                        "base_checkout_uninspectable", "base checkout index is unreadable"
                    )
                continue
            try:
                index.setdefault(path, []).append(header.decode("ascii"))
            except UnicodeDecodeError:
                raise SupervisorError(
                    "base_checkout_uninspectable", "base checkout index is unreadable"
                ) from None

        status: dict[bytes, str] = {}
        records = status_raw.split(b"\0")
        position = 0
        while position < len(records):
            record = records[position]
            position += 1
            if not record:
                continue
            if len(record) < 4 or record[2:3] != b" ":
                raise SupervisorError(
                    "base_checkout_uninspectable", "base checkout status is unreadable"
                )
            code = record[:2]
            try:
                code_text = code.decode("ascii")
            except UnicodeDecodeError:
                raise SupervisorError(
                    "base_checkout_uninspectable", "base checkout status is unreadable"
                ) from None
            path = record[3:]
            if path.endswith(b"/"):
                path = path.rstrip(b"/")
            changed_paths = [path]
            if b"R" in code or b"C" in code:
                if position >= len(records) or not records[position]:
                    raise SupervisorError(
                        "base_checkout_uninspectable", "base checkout rename state is unreadable"
                    )
                changed_paths.append(records[position])
                position += 1
            for changed_path in changed_paths:
                if changed_path.endswith(b"/"):
                    changed_path = changed_path.rstrip(b"/")
                if not self._snapshot_metadata_path(changed_path):
                    status[changed_path] = code_text

        entries: dict[str, str] = {}
        for path in sorted(set(index) | set(status)):
            display = prefix + path
            fingerprint = self._fingerprint_base_path(
                real_root,
                path,
                display,
                expected_root_identity=root_identity,
            )
            index_entries = sorted(index.get(path, []))
            modes = {entry.split(" ", 1)[0] for entry in index_entries}
            target = root.joinpath(*(os.fsdecode(part) for part in path.split(b"/")))
            is_gitlink = "160000" in modes
            is_nested_repository = fingerprint["kind"] == "directory" and (
                is_gitlink or os.path.lexists(target / ".git")
            )
            if is_nested_repository:
                nested = self._snapshot_checkout_repository(
                    target,
                    display + b"/",
                    ancestors,
                )
                fingerprint = {
                    "kind": "gitlink" if is_gitlink else "nested-repository",
                    "snapshot_sha256": sha256(canonical_json(nested).encode()),
                }
                entries.update(nested["entries"])
            entry = {
                "status": status.get(path, "  "),
                "index": index_entries,
                "worktree": fingerprint,
            }
            entries[self._snapshot_path_key(display)] = sha256(canonical_json(entry).encode())

        self._verify_snapshot_root_identity(real_root, root_identity, os.fsencode(real_root))
        return {"format": 2, "root_identity": list(root_identity), "entries": entries}

    def _capture_base_checkout_snapshot(self) -> dict[str, Any]:
        return self._snapshot_checkout_repository(self.root)

    def _assert_base_checkout_unchanged(
        self,
        connection: sqlite3.Connection,
        attempt_id: str,
        snapshot_json: str,
        snapshot_required: bool,
    ) -> None:
        # New attempts require the snapshot even if local audit data is damaged or
        # the claim event is missing. Legacy attempts retain their explicit default
        # marker because their true claim-time baseline cannot be reconstructed.
        if snapshot_required:
            chain = self._verify_event_chain(connection)
            if not chain["ok"]:
                raise SupervisorError(
                    "base_checkout_snapshot_invalid",
                    "attempt audit event chain failed integrity verification",
                )
        try:
            anchor = connection.execute(
                "SELECT payload_json FROM events "
                "WHERE event_type = 'attempt.ready' "
                "AND json_extract(payload_json, '$.attempt_id') = ? "
                "ORDER BY sequence DESC LIMIT 1",
                (attempt_id,),
            ).fetchone()
        except sqlite3.DatabaseError:
            raise SupervisorError(
                "base_checkout_snapshot_invalid", "attempt audit record is unreadable"
            ) from None
        try:
            anchor_payload = json.loads(anchor["payload_json"]) if anchor else {}
        except (TypeError, json.JSONDecodeError):
            anchor_payload = {}
        anchor_digest = anchor_payload.get("base_checkout_snapshot_sha256")
        if not snapshot_required and anchor_digest is None and not snapshot_json:
            # A pre-migration attempt has no truthful claim-time baseline.
            return
        if (
            not snapshot_required
            or not snapshot_json
            or anchor_digest != sha256(snapshot_json.encode())
        ):
            raise SupervisorError(
                "base_checkout_snapshot_invalid",
                "claim-time base checkout snapshot failed its audit integrity check",
            )
        try:
            baseline = json.loads(snapshot_json)
        except (TypeError, json.JSONDecodeError):
            raise SupervisorError(
                "base_checkout_snapshot_invalid", "claim-time base checkout snapshot is unreadable"
            ) from None
        snapshot_format = baseline.get("format") if isinstance(baseline, dict) else None
        if not isinstance(baseline, dict) or snapshot_format not in {1, 2}:
            raise SupervisorError(
                "base_checkout_snapshot_invalid", "claim-time base checkout snapshot is unsupported"
            )
        current = self._capture_base_checkout_snapshot()
        if snapshot_format == 2:
            root_identity = baseline.get("root_identity")
            if (
                not isinstance(root_identity, list)
                or len(root_identity) != 5
                or any(type(value) is not int for value in root_identity)
            ):
                raise SupervisorError(
                    "base_checkout_snapshot_invalid",
                    "claim-time base checkout root identity is unreadable",
                )
            if root_identity != current.get("root_identity"):
                raise SupervisorError(
                    "base_checkout_mutated",
                    "base checkout root identity changed since attempt claim",
                )
        old_entries = baseline.get("entries")
        new_entries = current["entries"]
        if not isinstance(old_entries, dict):
            raise SupervisorError(
                "base_checkout_snapshot_invalid", "claim-time base checkout snapshot is unreadable"
            )
        changed_keys = {
            key
            for key in set(old_entries) | set(new_entries)
            if old_entries.get(key) != new_entries.get(key)
        }
        try:
            changed_paths = {
                os.fsdecode(base64.b64decode(key.encode("ascii"), validate=True))
                for key in changed_keys
            }
        except (UnicodeEncodeError, ValueError):
            raise SupervisorError(
                "base_checkout_snapshot_invalid", "claim-time base checkout paths are unreadable"
            ) from None
        if not changed_paths:
            return
        quoted_paths = ", ".join(
            json.dumps(path, ensure_ascii=True) for path in sorted(changed_paths)
        )
        raise SupervisorError(
            "base_checkout_mutated",
            f"base checkout changed since attempt claim; paths: {quoted_paths}",
        )

    def submit(
        self,
        attempt_id: str,
        claim_token: int,
        credential: str | None = None,
        result_manifest_path: str | None = None,
    ) -> dict[str, Any]:
        return self._submit(
            attempt_id,
            claim_token,
            expected_worker_pid=None,
            credential=credential,
            result_manifest_path=result_manifest_path,
        )

    @staticmethod
    def _worker_exit_receipt_in(
        connection: sqlite3.Connection,
        attempt: sqlite3.Row,
        expected_pid: int,
    ) -> str:
        """Return the hash-chained supervisor wait receipt for this exact worker."""

        identity = attempt["pid_identity"]
        if (
            attempt["pid"] != expected_pid
            or expected_pid < 1
            or re.fullmatch(rf"linux:{expected_pid}:[0-9]+", identity or "") is None
        ):
            raise SupervisorError(
                "worker_registration_lost",
                "result import has no exact registered worker process identity",
            )
        try:
            row = connection.execute(
                """
                SELECT id, event_hash, created_at, payload_json, sequence FROM events
                WHERE event_type = 'worker.exited'
                  AND json_extract(payload_json, '$.attempt_id') = ?
                  AND json_extract(payload_json, '$.claim_token') = ?
                  AND json_extract(payload_json, '$.pid') = ?
                  AND json_extract(payload_json, '$.pid_identity') = ?
                  AND json_extract(payload_json, '$.observed_by') = 'supervisor_popen_wait'
                ORDER BY sequence DESC LIMIT 1
                """,
                (attempt["id"], attempt["claim_token"], expected_pid, identity),
            ).fetchone()
        except sqlite3.DatabaseError:
            raise SupervisorError(
                "worker_exit_receipt_invalid", "worker exit audit record is unreadable"
            ) from None
        if row is None:
            raise SupervisorError(
                "worker_not_exited", "supervisor has no wait receipt for this worker identity"
            )
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError):
            raise SupervisorError(
                "worker_exit_receipt_invalid", "worker exit audit record is malformed"
            ) from None
        command_pid = payload.get("command_pid")
        command_identity = payload.get("command_identity")
        command_digest = payload.get("command_digest")
        if (
            type(command_pid) is not int
            or command_pid < 1
            or command_pid == expected_pid
            or type(command_identity) is not str
            or type(command_digest) is not str
            or re.fullmatch(rf"linux:{command_pid}:[0-9]+", command_identity) is None
            or re.fullmatch(r"[0-9a-f]{64}", command_digest) is None
        ):
            raise SupervisorError(
                "worker_exit_receipt_invalid",
                "worker exit audit record lacks a valid pre-exec command identity",
            )
        try:
            ready = connection.execute(
                """
                SELECT 1 FROM events
                WHERE event_type = 'worker.command_ready'
                  AND json_extract(payload_json, '$.attempt_id') = ?
                  AND json_extract(payload_json, '$.claim_token') = ?
                  AND json_extract(payload_json, '$.monitor_pid') = ?
                  AND json_extract(payload_json, '$.monitor_identity') = ?
                  AND json_extract(payload_json, '$.command_pid') = ?
                  AND json_extract(payload_json, '$.command_identity') = ?
                  AND json_extract(payload_json, '$.command_digest') = ?
                  AND sequence < ?
                ORDER BY sequence DESC LIMIT 1
                """,
                (
                    attempt["id"],
                    attempt["claim_token"],
                    expected_pid,
                    identity,
                    command_pid,
                    command_identity,
                    command_digest,
                    row["sequence"],
                ),
            ).fetchone()
        except sqlite3.DatabaseError:
            raise SupervisorError(
                "worker_exit_receipt_invalid", "worker command identity record is unreadable"
            ) from None
        if ready is None:
            raise SupervisorError(
                "worker_exit_receipt_invalid",
                "worker exit has no matching durable pre-exec command identity record",
            )
        if type(payload.get("exit_code")) is not int or payload["exit_code"] != 0:
            raise SupervisorError("worker_failed", "worker did not exit successfully")
        return canonical_json(
            {
                "event_id": row["id"],
                "event_hash": row["event_hash"],
                "created_at": row["created_at"],
                "payload": payload,
            }
        )

    def _assert_result_import_worktree_base_locked(
        self, attempt: sqlite3.Row, base_sha: str
    ) -> None:
        """Prove the exact registered attempt worktree is still clean at its base."""

        worktree = Path(attempt["worktree"])
        root = (
            Path(attempt["worktree_root"])
            if attempt["worktree_root"]
            else (self.state_dir / "worktrees").resolve(strict=False)
        )
        if (
            not self._attempt_worktree_is_managed(attempt["id"], worktree, root)
            or worktree.is_symlink()
        ):
            raise SupervisorError(
                "result_import_worktree_invalid", "registered attempt worktree identity is invalid"
            )
        try:
            canonical = str(worktree.resolve(strict=True))
        except (OSError, RuntimeError, ValueError):
            raise SupervisorError(
                "result_import_worktree_invalid", "registered attempt worktree is unavailable"
            ) from None

        def git(*arguments: str) -> str:
            result = self._run_git_while_locked(*arguments)
            if result.returncode:
                raise SupervisorError(
                    "result_import_worktree_invalid", "registered attempt Git state is unreadable"
                )
            return result.stdout.decode("utf-8", errors="strict").rstrip("\r\n")

        registered = self._parse_registered_worktrees(git("worktree", "list", "--porcelain", "-z"))
        if registered.get(canonical) != attempt["branch"]:
            raise SupervisorError(
                "result_import_worktree_invalid", "attempt path is not registered to its branch"
            )
        top = Path(git("-C", canonical, "rev-parse", "--show-toplevel")).resolve(strict=True)
        common = Path(
            git("-C", canonical, "rev-parse", "--path-format=absolute", "--git-common-dir")
        ).resolve(strict=True)
        expected_common = Path(self._git_common_dir).resolve(strict=True)
        branch = git("-C", canonical, "branch", "--show-current")
        head = git("-C", canonical, "rev-parse", "--verify", "HEAD")
        status = self._run_git_while_locked("-C", canonical, "status", "--porcelain=v1", "-z")
        if (
            top != Path(canonical)
            or common != expected_common
            or branch != attempt["branch"]
            or head != base_sha
            or status.returncode != 0
            or status.stdout
        ):
            raise SupervisorError(
                "stale_worker_result",
                "registered attempt worktree is not clean at the recorded base",
            )

    def _result_import_staging_root(self, *, create: bool = False) -> Path:
        state_root = self.state_dir.resolve(strict=True)
        root = state_root / "result-import-staging"
        if root.is_symlink():
            raise SupervisorError(
                "result_import_staging_unavailable", "result staging root must not be a symlink"
            )
        try:
            if create:
                root.mkdir(mode=0o700, exist_ok=True)
                if os.name != "nt":
                    self._fsync_result_import_directory(state_root)
            resolved = root.resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as error:
            raise SupervisorError(
                "result_import_staging_unavailable", "result staging root is unavailable"
            ) from error
        if resolved != root or not resolved.is_dir():
            raise SupervisorError(
                "result_import_staging_unavailable", "result staging root identity is invalid"
            )
        return resolved

    def _result_import_stage_path(self, import_id: str, *, create: bool = False) -> Path:
        try:
            if str(uuid.UUID(import_id)) != import_id:
                raise ValueError
        except (AttributeError, TypeError, ValueError):
            raise SupervisorError(
                "invalid_worker_result", "result stage identity is invalid"
            ) from None
        root = self._result_import_staging_root(create=create)
        stage = root / import_id
        if stage.is_symlink():
            raise SupervisorError(
                "result_import_staging_unavailable", "result import stage must not be a symlink"
            )
        if create:
            try:
                stage.mkdir(mode=0o700)
                (stage / "objects").mkdir(mode=0o700)
            except FileExistsError:
                raise SupervisorError(
                    "result_import_staging_unavailable",
                    "result import stage already exists without a matching journal",
                ) from None
            except OSError as error:
                raise SupervisorError(
                    "result_import_staging_unavailable", "result import stage could not be created"
                ) from error
        return stage

    @staticmethod
    def _parse_result_import_object_ids(raw: str, object_id_length: int) -> tuple[str, ...] | None:
        try:
            values = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            return None
        if not isinstance(values, list) or any(
            not isinstance(value, str)
            or re.fullmatch(rf"[0-9a-f]{{{object_id_length}}}", value) is None
            for value in values
        ):
            return None
        if values != sorted(set(values)):
            return None
        return tuple(values)

    def _result_import_stage_size(self, root: Path) -> int:
        total = 0

        def fail_walk(error: OSError) -> None:
            raise error

        try:
            for current, directories, files in os.walk(root, followlinks=False, onerror=fail_walk):
                current_path = Path(current)
                for name in directories:
                    path = current_path / name
                    if path.is_symlink():
                        raise SupervisorError(
                            "result_import_staging_unavailable", "staging tree contains a symlink"
                        )
                for name in files:
                    path = current_path / name
                    if path.is_symlink():
                        raise SupervisorError(
                            "result_import_staging_unavailable", "staging tree contains a symlink"
                        )
                    total += path.stat(follow_symlinks=False).st_size
        except OSError as error:
            raise SupervisorError(
                "result_import_staging_unavailable", "staging size could not be measured"
            ) from error
        return total

    def _fsync_result_import_stage(self, root: Path) -> None:
        """Flush the exact staged object files before the SQLite journal can name them."""

        directories: list[Path] = []

        def fail_walk(error: OSError) -> None:
            raise error

        try:
            for current, child_directories, files in os.walk(
                root, followlinks=False, onerror=fail_walk
            ):
                current_path = Path(current)
                directories.append(current_path)
                for name in (*child_directories, *files):
                    if (current_path / name).is_symlink():
                        raise OSError("staging tree contains a symlink")
                for name in files:
                    descriptor = os.open(current_path / name, os.O_RDONLY)
                    try:
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
            if os.name != "nt":
                for directory in reversed(directories):
                    descriptor = os.open(directory, os.O_RDONLY)
                    try:
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                self._fsync_result_import_directory(root.parent)
        except OSError as error:
            raise SupervisorError(
                "result_import_staging_unavailable", "staged Git objects could not be flushed"
            ) from error

    @staticmethod
    def _fsync_result_import_directory(directory: Path) -> None:
        if os.name == "nt":
            return
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(directory, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _cleanup_result_import_staging_locked(self) -> None:
        """Remove only unjournaled/terminal private stages and proven unreachable owned blobs."""

        root = self._result_import_staging_root(create=True)
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM result_imports").fetchall()
        by_id = {row["id"]: row for row in rows}

        try:
            entries = tuple(os.scandir(root))
        except OSError as error:
            raise SupervisorError(
                "result_import_staging_unavailable", "result staging directory could not be listed"
            ) from error
        for entry in entries:
            if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                continue
            try:
                if str(uuid.UUID(entry.name)) != entry.name:
                    continue
            except (TypeError, ValueError):
                continue
            row = by_id.get(entry.name)
            if row is not None and row["phase"] == "prepared":
                recorded_path = row["staging_path"]
                if recorded_path and Path(recorded_path) == root / entry.name:
                    continue
            if row is not None and row["phase"] not in {"ref_published", "submitted", "ambiguous"}:
                continue
            target = root / entry.name
            if target.is_symlink() or target.parent != root:
                continue
            try:
                shutil.rmtree(target)
            except OSError as error:
                raise SupervisorError(
                    "result_import_staging_unavailable",
                    "terminal private result stage could not be removed",
                ) from error

        cleanup_rows = [
            row
            for row in rows
            if row["phase"] == "ambiguous"
            and row["staging_path"]
            and Path(row["staging_path"]) == root / row["id"]
        ]
        if not cleanup_rows:
            completed_rows = self._cleanup_completed_result_stages_locked(rows, root)
            self._clear_result_import_staging_paths(completed_rows)
            return

        prepared_events = self._result_import_prepared_events_locked(cleanup_rows)
        if prepared_events is None:
            completed_rows = self._cleanup_completed_result_stages_locked(rows, root)
            self._clear_result_import_staging_paths(completed_rows)
            return

        object_format_result = self._run_git_while_locked("rev-parse", "--show-object-format")
        if object_format_result.returncode:
            return
        object_format = object_format_result.stdout.decode("ascii", errors="strict").strip()
        if object_format not in {"sha1", "sha256"}:
            return
        object_id_length = 64 if object_format == "sha256" else 40

        protected: set[str] = set()
        terminal_rows: list[sqlite3.Row] = []
        inventory_valid = True
        git_executable = self._system_git_executable(self.root)
        cleanup_import_ids = {row["id"] for row in cleanup_rows}
        promote_inventory_by_import: dict[str, tuple[str, ...]] = {}
        for row in cleanup_rows:
            object_ids = self._parse_result_import_object_ids(
                row["object_ids_json"] or "[]", object_id_length
            )
            promote_ids = self._parse_result_import_object_ids(
                row["promote_object_ids_json"] or "[]", object_id_length
            )
            if (
                object_ids is None
                or promote_ids is None
                or not set(promote_ids).issubset(object_ids)
                or row["tree_sha"] not in object_ids
                or row["commit_sha"] not in object_ids
                or not self._prepared_result_import_event_matches(
                    row, object_ids, promote_ids, prepared_events.get(row["id"])
                )
            ):
                completed_rows = self._cleanup_completed_result_stages_locked(rows, root)
                self._clear_result_import_staging_paths(completed_rows)
                return
            promote_inventory_by_import[row["id"]] = promote_ids

        for row in rows:
            object_ids = self._parse_result_import_object_ids(
                row["object_ids_json"] or "[]", object_id_length
            )
            promote_ids = self._parse_result_import_object_ids(
                row["promote_object_ids_json"] or "[]", object_id_length
            )
            if object_ids is None or promote_ids is None:
                if row["phase"] != "ambiguous":
                    inventory_valid = False
                continue
            if row["phase"] == "ambiguous":
                if row["id"] in cleanup_import_ids:
                    cleanup_candidate_object_temps(
                        self.root,
                        row["id"],
                        promote_inventory_by_import[row["id"]],
                        git_executable=git_executable,
                    )
                    if not (root / row["id"]).exists() and not (root / row["id"]).is_symlink():
                        terminal_rows.append(row)
            else:
                protected.update(object_ids)
                if not object_ids:
                    try:
                        protected.update(
                            candidate_tree_object_ids(
                                self.root,
                                row["tree_sha"],
                                git_executable=git_executable,
                            )
                        )
                    except SupervisorError:
                        inventory_valid = False
                if re.fullmatch(rf"[0-9a-f]{{{object_id_length}}}", row["commit_sha"]):
                    protected.add(row["commit_sha"])
        if not inventory_valid:
            completed_rows = self._cleanup_completed_result_stages_locked(rows, root)
            self._clear_result_import_staging_paths(completed_rows)
            return
        reachable = self._result_import_reachable_objects_locked(object_id_length)
        if reachable is None:
            completed_rows = self._cleanup_completed_result_stages_locked(rows, root)
            self._clear_result_import_staging_paths(completed_rows)
            return
        for row in cleanup_rows:
            remove_unreachable_candidate_objects(
                self.root,
                promote_inventory_by_import[row["id"]],
                protected_object_ids=protected,
                reachable_object_ids=reachable,
                git_executable=git_executable,
            )
        completed_rows = self._cleanup_completed_result_stages_locked(rows, root)
        self._clear_result_import_staging_paths([*completed_rows, *terminal_rows])

    def _result_import_prepared_events_locked(
        self, rows: Sequence[sqlite3.Row]
    ) -> dict[str, dict[str, Any]] | None:
        """Load prepared event provenance only from an intact audit chain."""

        payloads: dict[str, dict[str, Any]] = {}
        with self.connect() as connection:
            if not self._verify_event_chain(connection)["ok"]:
                return None
            for row in rows:
                events = connection.execute(
                    "SELECT payload_json FROM events WHERE event_type = ? "
                    "AND json_extract(payload_json, '$.import_id') = ?",
                    ("worker.result_import_prepared", row["id"]),
                ).fetchall()
                if len(events) != 1:
                    return None
                try:
                    payload = json.loads(events[0]["payload_json"])
                except (TypeError, json.JSONDecodeError):
                    return None
                if not isinstance(payload, dict):
                    return None
                payloads[row["id"]] = payload
        return payloads

    @staticmethod
    def _prepared_result_import_event_matches(
        row: sqlite3.Row,
        object_ids: Sequence[str],
        promote_ids: Sequence[str],
        payload: dict[str, Any] | None,
    ) -> bool:
        if payload is None:
            return False
        expected = {
            "import_id": row["id"],
            "attempt_id": row["attempt_id"],
            "claim_token": row["claim_token"],
            "worker_pid": row["worker_pid"],
            "worker_identity": row["worker_identity"],
            "worker_exit_receipt_digest": sha256(row["worker_exit_receipt_json"].encode("utf-8")),
            "result_digest": row["result_digest"],
            "tree_sha": row["tree_sha"],
            "commit_sha": row["commit_sha"],
            "result_ref": row["result_ref"],
            "staging_path": row["staging_path"],
            "object_inventory_digest": sha256(canonical_json(list(object_ids)).encode("utf-8")),
            "promotion_inventory_digest": sha256(canonical_json(list(promote_ids)).encode("utf-8")),
            "promotion_object_count": len(promote_ids),
        }
        return all(payload.get(key) == value for key, value in expected.items())

    @staticmethod
    def _cleanup_completed_result_stages_locked(
        rows: Sequence[sqlite3.Row], root: Path
    ) -> list[sqlite3.Row]:
        """Return completed imports whose canonical private stage is already absent."""

        completed: list[sqlite3.Row] = []
        for row in rows:
            if row["phase"] not in {"ref_published", "submitted"}:
                continue
            if not row["staging_path"] or Path(row["staging_path"]) != root / row["id"]:
                continue
            stage = root / row["id"]
            if stage.exists() or stage.is_symlink():
                continue
            completed.append(row)
        return completed

    def _clear_result_import_staging_paths(self, rows: Sequence[sqlite3.Row]) -> None:
        if not rows:
            return
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for import_id in sorted({row["id"] for row in rows}):
                current = connection.execute(
                    "SELECT attempt_id, claim_token, result_digest, phase, staging_path "
                    "FROM result_imports WHERE id = ?",
                    (import_id,),
                ).fetchone()
                if (
                    current is None
                    or not current["staging_path"]
                    or current["phase"] not in {"ref_published", "submitted", "ambiguous"}
                ):
                    continue
                connection.execute(
                    "UPDATE result_imports SET staging_path = '' WHERE id = ?",
                    (import_id,),
                )
                self._event(
                    connection,
                    "worker.result_import_stage_cleaned",
                    "recovery",
                    {
                        "import_id": import_id,
                        "attempt_id": current["attempt_id"],
                        "claim_token": current["claim_token"],
                        "result_digest": current["result_digest"],
                        "phase": current["phase"],
                    },
                )

    def _result_import_reachable_objects_locked(self, object_id_length: int) -> set[str] | None:
        """Read refs, reflogs, every registered worktree HEAD, and every worktree index."""

        listed = self._run_git_while_locked("worktree", "list", "--porcelain", "-z")
        if listed.returncode:
            return None
        try:
            worktrees = self._parse_registered_worktrees(
                listed.stdout.decode("utf-8", errors="surrogateescape")
            )
        except (UnicodeError, ValueError):
            return None
        if not worktrees:
            return None
        heads: set[str] = set()
        indexed: set[str] = set()
        for worktree_text in worktrees:
            worktree = Path(worktree_text)
            if worktree.is_symlink() or not worktree.is_dir():
                return None
            head = self._run_git_while_locked(
                "-C", str(worktree), "rev-parse", "--verify", "HEAD^{commit}"
            )
            if head.returncode:
                return None
            head_id = head.stdout.decode("ascii", errors="strict").strip()
            if re.fullmatch(rf"[0-9a-f]{{{object_id_length}}}", head_id) is None:
                return None
            heads.add(head_id)
            index = self._run_git_while_locked("-C", str(worktree), "ls-files", "--stage", "-z")
            if index.returncode:
                return None
            for record in index.stdout.split(b"\0"):
                if not record:
                    continue
                metadata, separator, _path = record.partition(b"\t")
                fields = metadata.split(b" ")
                if not separator or len(fields) != 3:
                    return None
                try:
                    object_id = fields[1].decode("ascii", errors="strict")
                except UnicodeDecodeError:
                    return None
                if re.fullmatch(rf"[0-9a-f]{{{object_id_length}}}", object_id) is None:
                    return None
                indexed.add(object_id)

        arguments = (
            "rev-list",
            "--objects",
            "--all",
            "--reflog",
            "--no-object-names",
            *sorted(heads),
        )
        reachable_result = self._run_git_while_locked(*arguments)
        if reachable_result.returncode:
            return None
        reachable = set(indexed)
        for line in reachable_result.stdout.splitlines():
            if not line:
                continue
            try:
                object_id = line.split(maxsplit=1)[0].decode("ascii", errors="strict")
            except UnicodeDecodeError:
                return None
            if re.fullmatch(rf"[0-9a-f]{{{object_id_length}}}", object_id) is None:
                return None
            reachable.add(object_id)
        return reachable

    def import_worker_result(
        self,
        attempt_id: str,
        claim_token: int,
        baseline: Snapshot,
        change_set: ChangeSet,
        credential: str | None = None,
    ) -> dict[str, Any]:
        """Journal and submit a host-validated result without mutating the checkout.

        Worker identity is the supervisor-registered PID plus its kernel start
        identity and successful ``Popen.wait`` event. Runtime-driver unit IDs are
        intentionally not used as worker identity.
        """

        if type(baseline) is not Snapshot or type(change_set) is not ChangeSet:
            raise SupervisorError("invalid_worker_result", "snapshot or change set is invalid")
        baseline.manifest.validate()
        change_set.validate()
        if change_set.baseline_digest != baseline.manifest.digest:
            raise SupervisorError(
                "invalid_worker_result", "change set is not bound to the supplied baseline"
            )
        result_digest = sha256(
            canonical_json(
                {
                    "baseline_digest": baseline.manifest.digest,
                    "result_digest": change_set.result_digest,
                    "change_digest": change_set.digest,
                }
            ).encode("utf-8")
        )
        reference = result_ref_name(attempt_id, claim_token, result_digest)
        import_id = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"acp-worker-result:{attempt_id}:{claim_token}:{result_digest}",
            )
        )
        with self.connect() as connection:
            existing = connection.execute(
                "SELECT id FROM result_imports WHERE attempt_id = ? "
                "AND claim_token = ? AND result_digest = ?",
                (attempt_id, claim_token, result_digest),
            ).fetchone()
        if existing is not None:
            if existing["id"] != import_id:
                self._mark_result_import_ambiguous(
                    existing["id"], "result journal ID is not its deterministic identity"
                )
                raise SupervisorError(
                    "result_import_ambiguous", "result journal identity is inconsistent"
                )
            return self.recover_worker_result_import(import_id, credential=credential)

        self._assert_safe_git_execution_config()
        self._assert_no_git_grafts()

        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            self._authenticate_attempt(connection, attempt, credential)
            _require_sandbox_execution_result_eligible(connection, attempt_id)
            if not attempt["base_checkout_snapshot_required"]:
                raise SupervisorError(
                    "base_checkout_snapshot_invalid",
                    "result import requires a claim-time checkout snapshot",
                )
            task = self._task_row(connection, attempt["task_id"])
            worker_pid = attempt["pid"]
            if worker_pid is None or worker_pid < 1:
                raise SupervisorError(
                    "worker_registration_lost", "result import has no registered worker PID"
                )
            exit_receipt = self._worker_exit_receipt_in(connection, attempt, worker_pid)
            self._assert_base_checkout_unchanged(
                connection,
                attempt_id,
                attempt["base_checkout_snapshot_json"],
                bool(attempt["base_checkout_snapshot_required"]),
            )
            rules = self._write_set_rules(task, self._case_sensitive_paths(connection))
            attempt_snapshot = dict(attempt)
            base_sha = task["base_sha"]

        git_executable = self._system_git_executable(self.root)
        with self._git_operation_guard():
            self._cleanup_result_import_staging_locked()
            journal_id = import_id
            with self.connect() as connection:
                existing = connection.execute(
                    "SELECT id FROM result_imports WHERE attempt_id = ? "
                    "AND claim_token = ? AND result_digest = ?",
                    (attempt_id, claim_token, result_digest),
                ).fetchone()
            if existing:
                if existing["id"] != import_id:
                    self._mark_result_import_ambiguous(
                        existing["id"], "result journal ID is not its deterministic identity"
                    )
                    raise SupervisorError(
                        "result_import_ambiguous", "result journal identity is inconsistent"
                    )
                journal_id = existing["id"]
            else:
                self._assert_result_import_worktree_base_locked(attempt_snapshot, base_sha)
                staging_root = self._result_import_staging_root()
                existing_stage_bytes = self._result_import_stage_size(staging_root)
                if (
                    existing_stage_bytes
                    > _RESULT_IMPORT_STAGING_TOTAL_MAX_BYTES - _RESULT_IMPORT_STAGE_MAX_BYTES
                ):
                    raise SupervisorError(
                        "result_import_storage_limit",
                        "bounded result-import staging capacity is exhausted",
                    )
                stage_path = self._result_import_stage_path(import_id, create=True)
                stage_objects = stage_path / "objects"
                common_objects = Path(self._git_common_dir).resolve(strict=True) / "objects"
                candidate = build_candidate_tree(
                    attempt_snapshot["worktree"],
                    baseline,
                    change_set,
                    base_sha=base_sha,
                    write_set_rules=rules,
                    object_directory=stage_objects,
                    alternate_object_directory=common_objects,
                    git_executable=git_executable,
                )
                self._assert_result_import_worktree_base_locked(attempt_snapshot, base_sha)
                committed_at = int(time.time())
                payload = candidate_commit_payload(
                    candidate,
                    attempt_id=attempt_id,
                    claim_token=claim_token,
                    result_digest=result_digest,
                    committed_at=committed_at,
                )
                commit_sha = candidate_commit_object(
                    attempt_snapshot["worktree"],
                    payload,
                    write=False,
                    object_directory=stage_objects,
                    git_executable=git_executable,
                )
                written_commit = candidate_commit_object(
                    attempt_snapshot["worktree"],
                    payload,
                    write=True,
                    object_directory=stage_objects,
                    git_executable=git_executable,
                )
                if written_commit != commit_sha:
                    raise SupervisorError(
                        "candidate_tree_failed", "staged result commit hash changed while writing"
                    )
                self._fsync_result_import_stage(stage_path)
                object_ids = tuple(sorted({*candidate.object_ids, commit_sha}))
                promote_ids = missing_candidate_objects(
                    attempt_snapshot["worktree"],
                    object_ids,
                    git_executable=git_executable,
                )
                stage_bytes = self._result_import_stage_size(stage_path)
                total_stage_bytes = self._result_import_stage_size(
                    self._result_import_staging_root()
                )
                if (
                    stage_bytes > _RESULT_IMPORT_STAGE_MAX_BYTES
                    or total_stage_bytes > _RESULT_IMPORT_STAGING_TOTAL_MAX_BYTES
                ):
                    shutil.rmtree(stage_path)
                    raise SupervisorError(
                        "result_import_storage_limit",
                        "bounded result-import staging capacity is exhausted",
                    )
                stamp = utc_now()
                with self.connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    current = self._active_attempt(
                        connection, attempt_id, claim_token, int(time.time())
                    )
                    self._authenticate_attempt(connection, current, credential)
                    _require_sandbox_execution_result_eligible(connection, attempt_id)
                    current_receipt = self._worker_exit_receipt_in(connection, current, worker_pid)
                    if (
                        current["pid_identity"] != attempt_snapshot["pid_identity"]
                        or current_receipt != exit_receipt
                        or self._task_row(connection, current["task_id"])["base_sha"] != base_sha
                    ):
                        raise SupervisorError(
                            "stale_worker_result",
                            "worker or task fence changed during result import",
                        )
                    connection.execute(
                        """
                        INSERT INTO result_imports
                          (id, attempt_id, claim_token, worker_pid, worker_identity,
                           worker_exit_receipt_json, base_sha, tree_sha, baseline_digest,
                           result_digest, change_digest, result_ref, commit_timestamp,
                           commit_sha, phase, staging_path, object_ids_json,
                           promote_object_ids_json, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', ?, ?, ?, ?, ?)
                        """,
                        (
                            import_id,
                            attempt_id,
                            claim_token,
                            worker_pid,
                            current["pid_identity"],
                            exit_receipt,
                            base_sha,
                            candidate.tree_sha,
                            candidate.baseline_digest,
                            result_digest,
                            candidate.change_digest,
                            reference,
                            committed_at,
                            commit_sha,
                            str(stage_path),
                            canonical_json(list(object_ids)),
                            canonical_json(list(promote_ids)),
                            stamp,
                            stamp,
                        ),
                    )
                    self._event(
                        connection,
                        "worker.result_import_prepared",
                        current["agent_id"],
                        {
                            "import_id": import_id,
                            "attempt_id": attempt_id,
                            "claim_token": claim_token,
                            "worker_pid": worker_pid,
                            "worker_identity": current["pid_identity"],
                            "worker_exit_receipt_digest": sha256(exit_receipt.encode("utf-8")),
                            "result_digest": result_digest,
                            "tree_sha": candidate.tree_sha,
                            "commit_sha": commit_sha,
                            "result_ref": reference,
                            "staging_path": str(stage_path),
                            "object_inventory_digest": sha256(
                                canonical_json(list(object_ids)).encode("utf-8")
                            ),
                            "promotion_inventory_digest": sha256(
                                canonical_json(list(promote_ids)).encode("utf-8")
                            ),
                            "promotion_object_count": len(promote_ids),
                        },
                    )

        return self.recover_worker_result_import(journal_id, credential=credential)

    @staticmethod
    def _mark_result_import_ambiguous_in(
        connection: sqlite3.Connection, import_id: str, error: str
    ) -> None:
        connection.execute(
            "UPDATE result_imports SET phase = 'ambiguous', error = ?, updated_at = ? "
            "WHERE id = ? AND phase != 'submitted'",
            (error[:1000], utc_now(), import_id),
        )

    def _mark_result_import_ambiguous(self, import_id: str, error: str) -> None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT attempt_id, claim_token, result_digest, phase FROM result_imports "
                "WHERE id = ?",
                (import_id,),
            ).fetchone()
            if not row or row["phase"] == "submitted":
                return
            self._mark_result_import_ambiguous_in(connection, import_id, error)
            self._event(
                connection,
                "worker.result_import_ambiguous",
                "recovery",
                {
                    "import_id": import_id,
                    "attempt_id": row["attempt_id"],
                    "claim_token": row["claim_token"],
                    "result_digest": row["result_digest"],
                    "error": error[:1000],
                },
            )

    def recover_worker_result_import(
        self,
        import_id: str,
        credential: str | None = None,
    ) -> dict[str, Any]:
        """Reconcile only the exact journaled commit/ref; stale claims stay fenced."""

        self._assert_safe_git_execution_config()
        self._assert_no_git_grafts()
        with self.connect() as connection:
            preflight_row = connection.execute(
                "SELECT attempt_id FROM result_imports WHERE id = ?", (import_id,)
            ).fetchone()
            if preflight_row is None:
                raise SupervisorError("result_import_not_found", "result import journal is missing")
            preflight_attempt = connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (preflight_row["attempt_id"],)
            ).fetchone()
            if preflight_attempt is None:
                self._mark_result_import_ambiguous(import_id, "journal attempt is missing")
                raise SupervisorError(
                    "result_import_ambiguous", "journal attempt is missing; result remains fenced"
                )
            self._authenticate_attempt(connection, preflight_attempt, credential)
            _require_sandbox_execution_result_eligible(connection, preflight_row["attempt_id"])
        with self._git_operation_guard():
            self._cleanup_result_import_staging_locked()
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM result_imports WHERE id = ?", (import_id,)
            ).fetchone()
            if row is None:
                raise SupervisorError("result_import_not_found", "result import journal is missing")
            attempt_row = connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (row["attempt_id"],)
            ).fetchone()
            if attempt_row is None:
                self._mark_result_import_ambiguous(import_id, "journal attempt is missing")
                raise SupervisorError(
                    "result_import_ambiguous", "journal attempt is missing; result remains fenced"
                )
            self._authenticate_attempt(connection, attempt_row, credential)
            _require_sandbox_execution_result_eligible(connection, row["attempt_id"])
            try:
                expected_id = str(
                    uuid.uuid5(
                        uuid.NAMESPACE_URL,
                        "acp-worker-result:"
                        f"{row['attempt_id']}:{row['claim_token']}:{row['result_digest']}",
                    )
                )
                expected_ref = result_ref_name(
                    row["attempt_id"], row["claim_token"], row["result_digest"]
                )
            except (SupervisorError, TypeError, ValueError) as error:
                self._mark_result_import_ambiguous(import_id, "journal identity fields are invalid")
                raise SupervisorError(
                    "result_import_ambiguous", "result journal identity is invalid"
                ) from error
            if row["id"] != expected_id or row["result_ref"] != expected_ref:
                self._mark_result_import_ambiguous(
                    import_id, "journal identity or result ref is not canonical"
                )
                raise SupervisorError(
                    "result_import_ambiguous", "result journal identity or ref is inconsistent"
                )
            if row["phase"] == "submitted":
                if not row["submission_id"]:
                    self._mark_result_import_ambiguous(
                        import_id, "submitted journal lacks submission ID"
                    )
                    raise SupervisorError(
                        "result_import_ambiguous", "submitted journal has no linked submission"
                    )
                submission_row = connection.execute(
                    "SELECT attempt_id, commit_sha FROM submissions WHERE id = ?",
                    (row["submission_id"],),
                ).fetchone()
                if (
                    submission_row is None
                    or submission_row["attempt_id"] != row["attempt_id"]
                    or submission_row["commit_sha"] != row["commit_sha"]
                    or attempt_row["status"] != "submitted"
                    or attempt_row["latest_sha"] != row["commit_sha"]
                ):
                    raise SupervisorError(
                        "result_import_ambiguous",
                        "submitted result journal does not match its submission",
                    )
                candidate = CandidateTree(
                    tree_sha=row["tree_sha"],
                    base_sha=row["base_sha"],
                    baseline_digest=row["baseline_digest"],
                    result_digest=row["result_digest"],
                    change_digest=row["change_digest"],
                )
                payload = candidate_commit_payload(
                    candidate,
                    attempt_id=row["attempt_id"],
                    claim_token=row["claim_token"],
                    result_digest=row["result_digest"],
                    committed_at=row["commit_timestamp"],
                )
                git_executable = self._system_git_executable(self.root)
                try:
                    expected_commit = candidate_commit_object(
                        self.root,
                        payload,
                        write=False,
                        git_executable=git_executable,
                    )
                    target = candidate_ref_target(
                        self.root,
                        expected_ref,
                        git_executable=git_executable,
                    )
                    verify_candidate_objects(
                        self.root,
                        candidate,
                        commit_sha=target,
                        git_executable=git_executable,
                    )
                except SupervisorError as error:
                    raise SupervisorError(
                        "result_import_ambiguous",
                        "submitted result commit or ref cannot be verified",
                    ) from error
                if target != row["commit_sha"] or expected_commit != row["commit_sha"]:
                    raise SupervisorError(
                        "result_import_ambiguous",
                        "submitted result ref does not match its journaled commit",
                    )
                return self.submission(row["submission_id"])
            if row["phase"] == "ambiguous":
                raise SupervisorError(
                    "result_import_ambiguous", "result import is fenced as ambiguous"
                )

            try:
                attempt = self._active_attempt(
                    connection, row["attempt_id"], row["claim_token"], int(time.time())
                )
                receipt = self._worker_exit_receipt_in(connection, attempt, row["worker_pid"])
                if (
                    attempt["pid_identity"] != row["worker_identity"]
                    or receipt != row["worker_exit_receipt_json"]
                ):
                    raise SupervisorError(
                        "worker_registration_lost", "journal no longer matches its worker identity"
                    )
                task = self._task_row(connection, attempt["task_id"])
                if task["base_sha"] != row["base_sha"]:
                    raise SupervisorError(
                        "stale_worker_result", "task base changed since result was journaled"
                    )
                self._assert_base_checkout_unchanged(
                    connection,
                    row["attempt_id"],
                    attempt["base_checkout_snapshot_json"],
                    bool(attempt["base_checkout_snapshot_required"]),
                )
            except SupervisorError as error:
                if error.code not in {"invalid_runner_credential", "runner_auth_required"}:
                    self._mark_result_import_ambiguous(import_id, str(error))
                    raise SupervisorError(
                        "result_import_ambiguous",
                        "worker or claim fence changed; result remains retained and unsubmitted",
                    ) from error
                raise
            journal = dict(row)
            attempt_snapshot = dict(attempt)

        candidate = CandidateTree(
            tree_sha=journal["tree_sha"],
            base_sha=journal["base_sha"],
            baseline_digest=journal["baseline_digest"],
            result_digest=journal["result_digest"],
            change_digest=journal["change_digest"],
        )
        payload = candidate_commit_payload(
            candidate,
            attempt_id=journal["attempt_id"],
            claim_token=journal["claim_token"],
            result_digest=journal["result_digest"],
            committed_at=journal["commit_timestamp"],
        )
        git_executable = self._system_git_executable(self.root)
        try:
            with self._git_operation_guard():
                self._assert_result_import_worktree_base_locked(
                    attempt_snapshot, journal["base_sha"]
                )
                expected_commit = candidate_commit_object(
                    attempt_snapshot["worktree"],
                    payload,
                    write=False,
                    git_executable=git_executable,
                )
                if expected_commit != journal["commit_sha"]:
                    raise SupervisorError(
                        "result_import_ambiguous", "deterministic result commit hash changed"
                    )
                with self.connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    current = connection.execute(
                        "SELECT * FROM result_imports WHERE id = ?", (import_id,)
                    ).fetchone()
                    if current is None or current["phase"] not in {"prepared", "ref_published"}:
                        raise SupervisorError(
                            "result_import_ambiguous", "result journal changed during recovery"
                        )
                    active = self._active_attempt(
                        connection,
                        current["attempt_id"],
                        current["claim_token"],
                        int(time.time()),
                    )
                    self._authenticate_attempt(connection, active, credential)
                    _require_sandbox_execution_result_eligible(connection, current["attempt_id"])
                    current_receipt = self._worker_exit_receipt_in(
                        connection, active, current["worker_pid"]
                    )
                    if (
                        active["pid_identity"] != current["worker_identity"]
                        or current_receipt != current["worker_exit_receipt_json"]
                    ):
                        raise SupervisorError(
                            "result_import_ambiguous", "worker fence changed during recovery"
                        )
                    target = candidate_ref_target(
                        attempt_snapshot["worktree"],
                        current["result_ref"],
                        git_executable=git_executable,
                    )
                    if target is None:
                        if current["phase"] != "prepared":
                            raise SupervisorError(
                                "result_import_ambiguous",
                                "published result ref disappeared; automatic replay refused",
                            )
                        if current["staging_path"]:
                            expected_stage = self._result_import_stage_path(import_id)
                            if current["staging_path"] != str(expected_stage):
                                raise SupervisorError(
                                    "result_import_ambiguous",
                                    "journaled result stage path is not canonical",
                                )
                            stage_objects = expected_stage / "objects"
                            if (
                                expected_stage.is_symlink()
                                or not expected_stage.is_dir()
                                or stage_objects.is_symlink()
                                or not stage_objects.is_dir()
                            ):
                                raise SupervisorError(
                                    "result_import_ambiguous",
                                    "journaled result object stage is unavailable",
                                )
                            object_id_length = len(current["base_sha"])
                            object_ids = self._parse_result_import_object_ids(
                                current["object_ids_json"], object_id_length
                            )
                            promote_ids = self._parse_result_import_object_ids(
                                current["promote_object_ids_json"], object_id_length
                            )
                            if (
                                object_ids is None
                                or promote_ids is None
                                or current["tree_sha"] not in object_ids
                                or current["commit_sha"] not in object_ids
                                or not set(promote_ids).issubset(object_ids)
                            ):
                                raise SupervisorError(
                                    "result_import_ambiguous",
                                    "journaled result object provenance is invalid",
                                )
                            tree_object_ids = candidate_tree_object_ids(
                                attempt_snapshot["worktree"],
                                current["tree_sha"],
                                object_directory=stage_objects,
                                git_executable=git_executable,
                            )
                            if set(tree_object_ids) | {current["commit_sha"]} != set(object_ids):
                                raise SupervisorError(
                                    "result_import_ambiguous",
                                    "journaled result object inventory does not match its tree",
                                )
                            verify_candidate_objects(
                                attempt_snapshot["worktree"],
                                candidate,
                                commit_sha=expected_commit,
                                object_directory=stage_objects,
                                git_executable=git_executable,
                            )
                            promote_candidate_objects(
                                attempt_snapshot["worktree"],
                                stage_objects,
                                promote_ids,
                                import_id=import_id,
                                git_executable=git_executable,
                            )
                            verify_candidate_objects(
                                attempt_snapshot["worktree"],
                                candidate,
                                commit_sha=expected_commit,
                                git_executable=git_executable,
                            )
                        else:
                            # Pre-v13 journals already wrote trees to the shared ODB.
                            verify_candidate_objects(
                                attempt_snapshot["worktree"],
                                candidate,
                                git_executable=git_executable,
                            )
                            written = candidate_commit_object(
                                attempt_snapshot["worktree"],
                                payload,
                                write=True,
                                git_executable=git_executable,
                            )
                            if written != expected_commit:
                                raise SupervisorError(
                                    "result_import_ambiguous",
                                    "written result commit differs from journal",
                                )
                        publish_candidate_ref(
                            attempt_snapshot["worktree"],
                            current["result_ref"],
                            expected_commit,
                            git_executable=git_executable,
                        )
                    elif target != expected_commit:
                        raise SupervisorError(
                            "result_import_ambiguous", "result ref names an unjournaled commit"
                        )
                    verify_candidate_objects(
                        attempt_snapshot["worktree"],
                        candidate,
                        commit_sha=expected_commit,
                        git_executable=git_executable,
                    )
                    if current["phase"] == "prepared":
                        connection.execute(
                            "UPDATE result_imports SET phase = 'ref_published', updated_at = ? "
                            "WHERE id = ? AND phase = 'prepared'",
                            (utc_now(), import_id),
                        )
                        self._event(
                            connection,
                            "worker.result_import_ref_published",
                            "recovery",
                            {
                                "import_id": import_id,
                                "attempt_id": current["attempt_id"],
                                "claim_token": current["claim_token"],
                                "result_digest": current["result_digest"],
                                "commit_sha": expected_commit,
                                "result_ref": current["result_ref"],
                            },
                        )
        except SupervisorError as error:
            if error.code in {
                "result_import_ambiguous",
                "worker_registration_lost",
                "claim_inactive",
                "stale_fencing_token",
                "lease_expired",
                "stale_worker_result",
                "result_import_worktree_invalid",
                "worker_not_exited",
            }:
                self._mark_result_import_ambiguous(import_id, str(error))
                raise SupervisorError(
                    "result_import_ambiguous", "recovery could not prove the exact result fence"
                ) from error
            raise

        try:
            submission = self._submit(
                journal["attempt_id"],
                journal["claim_token"],
                expected_worker_pid=journal["worker_pid"],
                credential=credential,
                imported_result_id=import_id,
            )
        except SupervisorError as error:
            if error.code in {
                "claim_inactive",
                "stale_fencing_token",
                "lease_expired",
                "worker_registration_lost",
                "stale_worker_result",
                "base_checkout_mutated",
                "dirty_worktree",
                "reservation_lost",
                "stale_reservation",
            }:
                with self.connect() as connection:
                    completed = connection.execute(
                        "SELECT phase, submission_id FROM result_imports WHERE id = ?",
                        (import_id,),
                    ).fetchone()
                if completed and completed["phase"] == "submitted" and completed["submission_id"]:
                    return self.recover_worker_result_import(import_id, credential=credential)
                self._mark_result_import_ambiguous(import_id, str(error))
                with self._git_operation_guard():
                    self._cleanup_result_import_staging_locked()
                raise SupervisorError(
                    "result_import_ambiguous", "submission lost its claim fence; result is retained"
                ) from error
            raise
        try:
            with self._git_operation_guard():
                self._cleanup_result_import_staging_locked()
        except SupervisorError:
            # Submission is already durable. Staging remains bounded and will be
            # retried by the next import/recovery call if cleanup was unavailable.
            pass
        return submission

    def _submit(
        self,
        attempt_id: str,
        claim_token: int,
        expected_worker_pid: int | None,
        credential: str | None,
        result_manifest_path: str | None = None,
        imported_result_id: str | None = None,
    ) -> dict[str, Any]:
        self._assert_safe_git_execution_config()
        self._assert_no_git_grafts()
        epoch = int(time.time())
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, epoch)
            self._authenticate_attempt(connection, attempt, credential)
            _require_sandbox_execution_result_eligible(connection, attempt_id)
            if expected_worker_pid is None and attempt["pid"] is not None:
                raise SupervisorError(
                    "worker_still_running",
                    "manual submit is forbidden while a supervised worker is registered",
                )
            if expected_worker_pid is not None and attempt["pid"] != expected_worker_pid:
                raise SupervisorError(
                    "worker_registration_lost",
                    "supervised submit does not own the registered worker PID",
                )
            task = self._task_row(connection, attempt["task_id"])
            self._assert_base_checkout_unchanged(
                connection,
                attempt_id,
                attempt["base_checkout_snapshot_json"],
                bool(attempt["base_checkout_snapshot_required"]),
            )
            worktree = Path(attempt["worktree"])
            import_row = None
            if imported_result_id is not None:
                if expected_worker_pid is None:
                    raise SupervisorError(
                        "worker_registration_lost",
                        "imported submission requires a worker PID fence",
                    )
                import_row = connection.execute(
                    "SELECT * FROM result_imports WHERE id = ?", (imported_result_id,)
                ).fetchone()
                if (
                    import_row is None
                    or import_row["phase"] != "ref_published"
                    or import_row["attempt_id"] != attempt_id
                    or import_row["claim_token"] != claim_token
                    or import_row["worker_pid"] != expected_worker_pid
                    or attempt["pid"] != import_row["worker_pid"]
                    or attempt["pid_identity"] != import_row["worker_identity"]
                    or task["base_sha"] != import_row["base_sha"]
                ):
                    raise SupervisorError(
                        "result_import_ambiguous",
                        "result journal does not match this exact attempt",
                    )
                receipt = self._worker_exit_receipt_in(connection, attempt, expected_worker_pid)
                if receipt != import_row["worker_exit_receipt_json"]:
                    raise SupervisorError(
                        "result_import_ambiguous", "result journal worker exit receipt changed"
                    )
                candidate = CandidateTree(
                    tree_sha=import_row["tree_sha"],
                    base_sha=import_row["base_sha"],
                    baseline_digest=import_row["baseline_digest"],
                    result_digest=import_row["result_digest"],
                    change_digest=import_row["change_digest"],
                )
                payload = candidate_commit_payload(
                    candidate,
                    attempt_id=attempt_id,
                    claim_token=claim_token,
                    result_digest=import_row["result_digest"],
                    committed_at=import_row["commit_timestamp"],
                )
                with self._git_operation_guard():
                    self._assert_result_import_worktree_base_locked(attempt, task["base_sha"])
                    expected_ref = result_ref_name(
                        attempt_id, claim_token, import_row["result_digest"]
                    )
                    target = candidate_ref_target(
                        worktree,
                        expected_ref,
                        git_executable=self._system_git_executable(self.root),
                    )
                    expected_commit = candidate_commit_object(
                        worktree,
                        payload,
                        write=False,
                        git_executable=self._system_git_executable(self.root),
                    )
                    verify_candidate_objects(
                        worktree,
                        candidate,
                        commit_sha=target,
                        git_executable=self._system_git_executable(self.root),
                    )
                if (
                    import_row["result_ref"] != expected_ref
                    or target != import_row["commit_sha"]
                    or expected_commit != import_row["commit_sha"]
                ):
                    raise SupervisorError(
                        "result_import_ambiguous", "published ref differs from durable journal"
                    )
                commit = import_row["commit_sha"]
            else:
                if self._git_bytes("-C", str(worktree), "status", "--porcelain=v1", "-z"):
                    raise SupervisorError("dirty_worktree", "submission requires committed work")
                commit = self._git_text("-C", str(worktree), "rev-parse", "HEAD")
            if self._git_text("cat-file", "-t", commit) != "commit":
                raise SupervisorError(
                    "invalid_submission_object", "submission HEAD is not a commit object"
                )
            if commit == task["base_sha"]:
                raise SupervisorError("empty_submission", "submission has no commits")
            self._git(
                "-C",
                str(worktree),
                "merge-base",
                "--is-ancestor",
                task["base_sha"],
                commit,
            )
            raw = self._git_bytes(
                "-C",
                str(worktree),
                "diff",
                "--name-only",
                "-z",
                task["base_sha"],
                commit,
            )
            changed = sorted(value.decode("utf-8") for value in raw.split(b"\0") if value)
            if not changed:
                raise SupervisorError("empty_submission", "no changed paths")
            result_manifest_json = self._completion_receipt_json(
                commit, changed, result_manifest_path, credential
            )
            declared = json.loads(task["resources_json"])
            rules = self._write_set_rules(task, self._case_sensitive_paths(connection))
            undeclared = [
                path
                for path in changed
                if not any(
                    self._path_matches(path, resource, fold=fold, is_logical=is_logical)
                    for resource, fold, is_logical in rules
                )
            ]
            if undeclared:
                raise SupervisorError(
                    "undeclared_write",
                    "changed paths are not leased: " + ", ".join(undeclared),
                )
            for path in changed:
                self._assert_safe_symlink(worktree, commit, path)
            rows = connection.execute(
                "SELECT * FROM resource_leases WHERE attempt_id = ?", (attempt_id,)
            ).fetchall()
            tokens = {
                row["resource"]: row["fencing_token"]
                for row in rows
                if row["task_id"] == task["id"] and row["lease_expires_at"] > epoch
            }
            if set(tokens) != set(declared):
                raise SupervisorError("stale_fencing_token", "resource lease set is stale")
            tree = self._git_text("-C", str(worktree), "rev-parse", f"{commit}^{{tree}}")
            if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", tree):
                raise SupervisorError(
                    "invalid_submission_object", "submission tree object id is invalid"
                )
            patch = self._git_bytes(
                "-C",
                str(worktree),
                "diff",
                "--binary",
                task["base_sha"],
                commit,
            )
            try:
                # This is the worker-completion authority boundary. Verify in
                # the same write transaction immediately before creating the
                # submission. On failure the quarantine mutations must survive
                # the rejected submit, so commit them before propagating the
                # error; nothing in this transaction has written before here.
                self._verify_attempt_trust_in(connection, attempt_id)
            except SupervisorError:
                connection.commit()
                raise
            submission_id = str(uuid.uuid4())
            stamp = utc_now()
            connection.execute(
                """
                INSERT INTO submissions
                  (id, task_id, attempt_id, worker_agent_id, commit_sha, tree_sha,
                   object_contract, result_manifest_json, patch_sha256, changed_paths_json,
                   resource_tokens_json, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_qc', ?)
                """,
                (
                    submission_id,
                    task["id"],
                    attempt_id,
                    attempt["agent_id"],
                    commit,
                    tree,
                    SUBMISSION_OBJECT_CONTRACT,
                    result_manifest_json,
                    sha256(patch),
                    canonical_json(changed),
                    canonical_json(tokens),
                    stamp,
                ),
            )
            if import_row is not None:
                changed_import = connection.execute(
                    "UPDATE result_imports SET phase = 'submitted', submission_id = ?, "
                    "updated_at = ? WHERE id = ? AND phase = 'ref_published' "
                    "AND attempt_id = ? AND claim_token = ? AND commit_sha = ?",
                    (
                        submission_id,
                        stamp,
                        imported_result_id,
                        attempt_id,
                        claim_token,
                        commit,
                    ),
                ).rowcount
                if changed_import != 1:
                    raise SupervisorError(
                        "result_import_ambiguous", "result journal changed before submission commit"
                    )
            connection.execute(
                """
                UPDATE attempts SET status = 'submitted', latest_sha = ?,
                  pid = NULL, pid_identity = '', termination_target_status = '',
                  termination_proof = '', launch_owner_pid = NULL,
                  launch_owner_identity = '',
                  updated_at = ? WHERE id = ?
                """,
                (commit, stamp, attempt_id),
            )
            connection.execute(
                "UPDATE tasks SET status = 'qc_review', updated_at = ? WHERE id = ?",
                (stamp, task["id"]),
            )
            reserve_until = epoch + max(3600, self.config.timeout_seconds * 3)
            connection.execute(
                """
                UPDATE resource_leases SET attempt_id = NULL,
                  lease_expires_at = ?, updated_at = ?
                WHERE task_id = ? AND attempt_id = ?
                """,
                (reserve_until, stamp, task["id"], attempt_id),
            )
            connection.execute(
                """
                UPDATE runtime_allocations SET lease_expires_at = ?, updated_at = ?
                WHERE attempt_id = ?
                """,
                (reserve_until, stamp, attempt_id),
            )
            self._event(
                connection,
                "submission.created",
                attempt["agent_id"],
                {
                    "submission_id": submission_id,
                    "commit_sha": commit,
                    "patch_sha256": sha256(patch),
                    "resource_tokens": tokens,
                    "result_import_id": imported_result_id,
                    "result_digest": import_row["result_digest"]
                    if import_row is not None
                    else None,
                },
            )
        return self.submission(submission_id)

    def submission(self, submission_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            row = self._submission_row(connection, submission_id)
            return self._submission_view(connection, row)

    @staticmethod
    def _active_attempt(
        connection: sqlite3.Connection,
        attempt_id: str,
        claim_token: int,
        epoch: int,
    ) -> sqlite3.Row:
        attempt = connection.execute(
            "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
        ).fetchone()
        if not attempt:
            raise SupervisorError("attempt_not_found", f"attempt {attempt_id} not found")
        if attempt["status"] != "working":
            raise SupervisorError("claim_inactive", f"attempt status is {attempt['status']}")
        if attempt["claim_token"] != claim_token:
            raise SupervisorError("stale_fencing_token", "claim token is stale")
        if attempt["lease_expires_at"] <= epoch:
            raise SupervisorError("lease_expired", "claim lease expired")
        task = connection.execute(
            "SELECT * FROM tasks WHERE id = ?", (attempt["task_id"],)
        ).fetchone()
        if not task or task["current_attempt_id"] != attempt_id or task["status"] != "working":
            raise SupervisorError("claim_inactive", "task no longer owns this attempt")
        return attempt

    def _assert_reservations(
        self,
        connection: sqlite3.Connection,
        task: sqlite3.Row,
        submission: sqlite3.Row,
    ) -> None:
        expected = json.loads(submission["resource_tokens_json"])
        rows = connection.execute(
            "SELECT * FROM resource_leases WHERE task_id = ?", (task["id"],)
        ).fetchall()
        actual = {
            row["resource"]: row["fencing_token"]
            for row in rows
            if row["lease_expires_at"] > int(time.time())
        }
        if actual != expected:
            raise SupervisorError(
                "reservation_lost",
                "resource reservation or fencing token changed",
            )

    @staticmethod
    def _path_matches(
        path: str, resource: str, *, fold: bool = True, is_logical: bool | None = None
    ) -> bool:
        """Is `path` inside `resource`?

        `fold=False` compares capitalisation too, and the caller must then pass the
        case-preserving form of the resource — `_write_set_rules` is what pairs the two,
        so no call site has to remember the correspondence itself.
        """

        candidate = unicodedata.normalize("NFC", PurePosixPath(path).as_posix())
        if fold:
            candidate = candidate.casefold()
        logical_resource = resource.startswith("logical:") if is_logical is None else is_logical
        if fold:
            resource = resource.casefold()
        if logical_resource:
            return False
        if resource.endswith("/**") and not any(character in resource[:-3] for character in "*?["):
            prefix = resource[:-3].rstrip("/")
            return candidate == prefix or candidate.startswith(prefix + "/")
        if any(character in resource for character in "*?["):
            path_parts = tuple(candidate.split("/"))
            pattern_parts = tuple(resource.split("/"))

            @cache
            def match_parts(path_index: int, pattern_index: int) -> bool:
                if pattern_index == len(pattern_parts):
                    return path_index == len(path_parts)
                pattern_part = pattern_parts[pattern_index]
                if pattern_part == "**":
                    return match_parts(path_index, pattern_index + 1) or (
                        path_index < len(path_parts) and match_parts(path_index + 1, pattern_index)
                    )
                return (
                    path_index < len(path_parts)
                    and fnmatch.fnmatchcase(path_parts[path_index], pattern_part)
                    and match_parts(path_index + 1, pattern_index + 1)
                )

            return match_parts(0, 0)
        return candidate == resource

    def _restore_candidate(self, worktree: Path, commit_sha: str) -> None:
        self._git("-C", str(worktree), "reset", "--hard", commit_sha)
        self._git("-C", str(worktree), "clean", "-fdx")

    def _worktree_matches(self, worktree: Path, commit_sha: str) -> bool:
        self._assert_no_git_grafts()
        head = self._git_text("-C", str(worktree), "rev-parse", "HEAD", check=False)
        unstaged = self._git(
            "-C",
            str(worktree),
            "diff",
            "--quiet",
            commit_sha,
            "--",
            check=False,
        )
        staged = self._git(
            "-C",
            str(worktree),
            "diff",
            "--cached",
            "--quiet",
            commit_sha,
            "--",
            check=False,
        )
        return head == commit_sha and unstaged.returncode == 0 and staged.returncode == 0

    def _assert_safe_symlink(self, worktree: Path, commit_sha: str, path: str) -> None:
        listing = self._git_text(
            "-C", str(worktree), "ls-tree", commit_sha, "--", path, check=False
        )
        if not listing.startswith("120000 "):
            return
        target = self._git_text("-C", str(worktree), "show", f"{commit_sha}:{path}")
        resolved = (worktree / path).parent.joinpath(target).resolve()
        try:
            resolved.relative_to(worktree.resolve())
        except ValueError as error:
            raise SupervisorError(
                "symlink_escape", f"symlink {path} points outside its worktree"
            ) from error

    @staticmethod
    def normalize_resource(raw: str, repo: Path | None = None, *, fold: bool = True) -> str:
        """Canonical form of a declared resource.

        `fold=True` is the storage form and the lease PRIMARY KEY, and it stays folded.
        `fold=False` is the same canonicalisation — NFC, `\\` to `/`, the `/**` suffix on
        a directory, the same refusals — with the operator's capitalisation intact, for
        matching on a filesystem that distinguishes it. A `logical:` resource is an
        identity rather than a path and stays folded either way, because folding is what
        makes `logical:Deploy` and `logical:deploy` one lock.
        """

        value = unicodedata.normalize("NFC", raw.strip().replace("\\", "/"))
        if not value:
            raise SupervisorError("invalid_resource", "resource cannot be empty")
        if value.startswith("logical:"):
            suffix = value.removeprefix("logical:").strip().casefold()
            if not suffix or any(part in {"", ".", ".."} for part in suffix.split("/")):
                raise SupervisorError("invalid_resource", f"invalid logical resource: {raw}")
            return f"logical:{suffix}"
        directory = value.endswith("/")
        path = PurePosixPath(value)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise SupervisorError("invalid_resource", f"resource must be repo-relative: {raw}")
        value = path.as_posix()
        lowered = value.casefold()
        if lowered.startswith("logical:"):
            raise SupervisorError(
                "invalid_resource",
                "path uses the reserved logical: prefix (case-insensitive)",
            )
        if lowered in {".git", ".acp"} or lowered.startswith((".git/", ".acp/")):
            raise SupervisorError("invalid_resource", f"internal resource forbidden: {raw}")
        directory = directory or bool(repo and (repo / value).is_dir())
        canonical = value.rstrip("/") + "/**" if directory else value
        return canonical.casefold() if fold else canonical

    @staticmethod
    def _literal_prefix(resource: str) -> str:
        wildcard = min(
            (resource.find(character) for character in "*?[" if character in resource),
            default=len(resource),
        )
        prefix = resource[:wildcard]
        if wildcard < len(resource) and "/" in prefix:
            prefix = prefix.rsplit("/", 1)[0]
        elif wildcard < len(resource):
            prefix = ""
        return prefix.rstrip("/")

    def create_task(
        self,
        title: str,
        description: str,
        acceptance: Sequence[str],
        resources: Sequence[str],
        dependencies: Sequence[str] = (),
        priority: int = 50,
        base_branch: str = "HEAD",
        produces: Sequence[str] = (),
        consumes: Sequence[str] = (),
        read_resources: Sequence[str] = (),
    ) -> dict[str, Any]:
        if not title.strip() or not acceptance:
            raise SupervisorError("invalid_task", "title and acceptance criteria are required")
        declared: dict[str, str] = {}
        for item in resources:
            folded = self.normalize_resource(item, self.root)
            declared.setdefault(folded, item.strip())
        normalized = sorted(declared)
        if not normalized:
            raise SupervisorError("invalid_task", "at least one write resource is required")
        declared_reads: dict[str, str] = {}
        for item in read_resources:
            canonical = self.normalize_resource(item, self.root, fold=False)
            if canonical.startswith("logical:"):
                raise SupervisorError(
                    "invalid_resource", "read resources must be tracked repository paths"
                )
            declared_reads.setdefault(canonical, canonical)
        normalized_reads = sorted(declared_reads)
        produced = sorted({normalize_artifact(item) for item in produces})
        consumed = sorted({normalize_artifact(item) for item in consumes})
        base_sha = self._git_text("rev-parse", base_branch)
        resolved_branch = base_branch
        if base_branch == "HEAD":
            symbolic = self._git_text("symbolic-ref", "--quiet", "--short", "HEAD", check=False)
            resolved_branch = symbolic or base_sha
        task_id = str(uuid.uuid4())
        now = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for dependency in dependencies:
                if not connection.execute(
                    "SELECT 1 FROM tasks WHERE id = ?", (dependency,)
                ).fetchone():
                    raise SupervisorError(
                        "dependency_not_found", f"task {dependency} does not exist"
                    )
            connection.execute(
                """
                INSERT INTO tasks
                  (id, title, description, acceptance_json, resources_json,
                   declared_resources_json,
                   read_resources_json, declared_read_resources_json,
                   dependencies_json, produces_json, consumes_json, base_branch,
                   base_sha, priority, status, current_attempt_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', NULL, ?, ?)
                """,
                (
                    task_id,
                    title.strip(),
                    description.strip(),
                    canonical_json(list(acceptance)),
                    canonical_json(normalized),
                    canonical_json(declared),
                    canonical_json(normalized_reads),
                    canonical_json(declared_reads),
                    canonical_json(list(dependencies)),
                    canonical_json(produced),
                    canonical_json(consumed),
                    resolved_branch,
                    base_sha,
                    priority,
                    now,
                    now,
                ),
            )
            self._event(
                connection,
                "task.created",
                "operator",
                {
                    "task_id": task_id,
                    "resources": normalized,
                    "read_resources": normalized_reads,
                    "produces": produced,
                    "consumes": consumed,
                    "base_sha": base_sha,
                },
            )
        return self.task(task_id)
