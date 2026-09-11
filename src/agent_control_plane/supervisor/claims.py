"""Claim, heartbeat, the write guard, and submit: everything an attempt does while it holds
its leases and fencing tokens.

Moved verbatim out of `git_supervisor` (board #1630). `GitSupervisor` inherits this mixin, so
every call site, CLI path and `GitSupervisor.<name>` lookup resolves exactly as before.
"""

from __future__ import annotations

import json
import re
import shutil
import sqlite3
import subprocess
import time
import unicodedata
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

from ..scheduling import declared_resources
from .common import SUBMISSION_OBJECT_CONTRACT, SupervisorError, canonical_json, sha256, utc_now
from .schema import META_CASE_SENSITIVE


class ClaimsMixin:
    """Claiming a task, heartbeats, the write-set guard and submission."""

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
        self.reap_expired()
        ttl = lease_seconds or self.config.lease_seconds
        if ttl < 10:
            raise SupervisorError("invalid_lease", "lease must be at least 10 seconds")
        expires = int(time.time()) + ttl
        attempt_id = str(uuid.uuid4())
        worktree = self.state_dir / "worktrees" / attempt_id
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
            leases = connection.execute(
                """
                SELECT lease.resource, lease.task_id, lease.attempt_id,
                       attempt.agent_id AS agent_id
                FROM resource_leases AS lease
                LEFT JOIN attempts AS attempt ON attempt.id = lease.attempt_id
                WHERE lease.task_id IS NOT NULL AND lease.lease_expires_at > ?
                """,
                (int(time.time()),),
            ).fetchall()
            for resource in requested:
                for lease in leases:
                    if lease["task_id"] != task_id and self.resources_overlap(
                        resource, lease["resource"]
                    ):
                        overlap = "exact" if resource == lease["resource"] else "potential"
                        raise SupervisorError(
                            "resource_busy",
                            f"{resource} has an {overlap} overlap with active lease "
                            f"{lease['resource']} held by task {lease['task_id']} "
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
                SELECT latest_sha FROM attempts
                WHERE task_id = ? AND latest_sha IS NOT NULL
                ORDER BY number DESC LIMIT 1
                """,
                (task_id,),
            ).fetchone()
            start_sha = resume["latest_sha"] if resume else task["base_sha"]
            branch = f"acp/task-{task_id[:8]}-a{number}"
            connection.execute(
                """
                INSERT INTO attempts
                  (id, task_id, number, agent_id, runner_credential_digest,
                   branch, worktree, claim_token,
                   start_sha, latest_sha, checkpoint_json, trust_bundle_json,
                   pid, log_path, status,
                   lease_expires_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', ?, NULL, NULL,
                        'provisioning', ?, ?, ?)
                """,
                (
                    attempt_id,
                    task_id,
                    number,
                    agent_id,
                    identity["credential_digest"] if identity else None,
                    branch,
                    str(worktree),
                    counter,
                    start_sha,
                    start_sha,
                    canonical_json(trust_pin),
                    expires,
                    now,
                    now,
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
            self._git("worktree", "add", "-b", branch, str(worktree), start_sha)
            worktree_created = True
            self._runtime_up(attempt_id)
        except (OSError, subprocess.SubprocessError, SupervisorError):
            if worktree_created:
                try:
                    self.runtime_down(attempt_id, force=True, _allow_active=True)
                except (OSError, subprocess.SubprocessError, SupervisorError):
                    pass
            else:
                self._abandon_runtime(attempt_id)
            self._git("worktree", "remove", "--force", str(worktree), check=False)
            if worktree.exists():
                shutil.rmtree(worktree)
            self._git("worktree", "prune", check=False)
            self._git("branch", "-D", branch, check=False)
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
                {"attempt_id": attempt_id, "worktree": str(worktree)},
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
            connection.execute(
                """
                UPDATE attempts SET latest_sha = ?, checkpoint_json = ?,
                  lease_expires_at = ?, updated_at = ? WHERE id = ?
                """,
                (head, canonical_json(checkpoint or {}), expires, now, attempt_id),
            )
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

    def guard(self, attempt_id: str, path: str, *, now: int | None = None) -> dict[str, Any]:
        """Decide whether an agent holding `attempt_id` may write `path`.

        This is the check an editor's pre-write hook asks before letting a tool call
        through, and it is deliberately the SAME check `submit` applies to the diff:
        both run `_path_matches` over `_write_set_rules`, so the case sensitivity of the
        filesystem is decided in one place for both. An adapter that reimplemented the
        matching would be a second enforcement implementation that could disagree with
        the one that matters, which is worse than none.

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
        # resolve() follows symlinks, so a link planted inside the worktree that points
        # outside it resolves outside and is refused here rather than at submit time.
        target = Path(path)
        if not target.is_absolute():
            target = worktree / target
        target = target.resolve()
        if target != worktree and worktree not in target.parents:
            return self._guard_denial(
                attempt_id,
                path,
                "outside_worktree",
                f"{target} is outside the attempt worktree {worktree}",
                declared=declared,
            )

        relative = target.relative_to(worktree).as_posix()
        if not any(self._path_matches(relative, resource, fold=fold) for resource, fold in rules):
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

    @classmethod
    def _write_set_rules(cls, task: sqlite3.Row, case_sensitive: bool) -> list[tuple[str, bool]]:
        """The write set as `(resource, fold)` pairs for `_path_matches`.

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
        if not case_sensitive:
            return [(item, True) for item in folded]
        try:
            declared = json.loads(task["declared_resources_json"] or "{}")
        except (KeyError, IndexError, TypeError, ValueError):
            declared = {}
        rules: list[tuple[str, bool]] = []
        for item in folded:
            raw = declared.get(item)
            if not isinstance(raw, str):
                rules.append((item, True))
                continue
            try:
                cased = cls.normalize_resource(raw, fold=False)
            except SupervisorError:
                rules.append((item, True))
                continue
            # The directory suffix came from a probe of the repository at task creation,
            # which cannot be re-run reliably later; take it from the folded form, which
            # recorded the answer.
            if item.endswith("/**") and not cased.endswith("/**"):
                cased = cased.rstrip("/") + "/**"
            rules.append((item, True) if cased.casefold() != item else (cased, False))
        return rules

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

    def submit(
        self,
        attempt_id: str,
        claim_token: int,
        credential: str | None = None,
    ) -> dict[str, Any]:
        return self._submit(
            attempt_id,
            claim_token,
            expected_worker_pid=None,
            credential=credential,
        )

    def _submit(
        self,
        attempt_id: str,
        claim_token: int,
        expected_worker_pid: int | None,
        credential: str | None,
    ) -> dict[str, Any]:
        self._assert_no_git_grafts()
        epoch = int(time.time())
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, epoch)
            self._authenticate_attempt(connection, attempt, credential)
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
            worktree = Path(attempt["worktree"])
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
            declared = json.loads(task["resources_json"])
            rules = self._write_set_rules(task, self._case_sensitive_paths(connection))
            undeclared = [
                path
                for path in changed
                if not any(
                    self._path_matches(path, resource, fold=fold) for resource, fold in rules
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
                   object_contract, patch_sha256, changed_paths_json, resource_tokens_json,
                   status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_qc', ?)
                """,
                (
                    submission_id,
                    task["id"],
                    attempt_id,
                    attempt["agent_id"],
                    commit,
                    tree,
                    SUBMISSION_OBJECT_CONTRACT,
                    sha256(patch),
                    canonical_json(changed),
                    canonical_json(tokens),
                    stamp,
                ),
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
    def _path_matches(path: str, resource: str, *, fold: bool = True) -> bool:
        """Is `path` inside `resource`?

        `fold=False` compares capitalisation too, and the caller must then pass the
        case-preserving form of the resource — `_write_set_rules` is what pairs the two,
        so no call site has to remember the correspondence itself.
        """

        candidate = unicodedata.normalize("NFC", PurePosixPath(path).as_posix())
        if fold:
            candidate = candidate.casefold()
        if resource.startswith("logical:"):
            return False
        if resource.endswith("/**"):
            prefix = resource[:-3].rstrip("/")
            return candidate == prefix or candidate.startswith(prefix + "/")
        if any(character in resource for character in "*?["):
            return PurePosixPath(candidate).match(resource)
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
