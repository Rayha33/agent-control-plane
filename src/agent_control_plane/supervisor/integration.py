"""Integration: the merge, the isolated integration Git boundary, attribute snapshots,
ref publication and deletion, and reconciliation after a crash.

What stayed in git_supervisor, on purpose: `_read_integration_info_attributes` names
`GitSupervisor._attribute_snapshot` explicitly.

Moved verbatim out of `git_supervisor` (board #1630). `GitSupervisor` inherits this mixin, so
every call site, CLI path and `GitSupervisor.<name>` lookup resolves exactly as before.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any

from .common import (
    MAX_ATTRIBUTE_BYTES,
    MERGE_SEMANTIC_CONFIG,
    AttributeSnapshot,
    IntegrationGitBoundary,
    SupervisorError,
    canonical_json,
    sha256,
    utc_now,
)


class IntegrationMixin:
    """Integration merge, the isolated Git boundary, ref publication and crash reconciliation."""

    def integrate(
        self,
        task_id: str,
        integrator_id: str = "integration",
        credential: str | None = None,
    ) -> dict[str, Any]:
        self._authenticate(integrator_id, "integrator", credential)
        self._assert_no_git_grafts()
        with self._task_operation_guard(task_id) as operation_guard_fd:
            return self._integrate_locked(
                task_id,
                integrator_id,
                credential,
                operation_guard_fd,
            )

    def _integrate_locked(
        self,
        task_id: str,
        integrator_id: str,
        credential: str | None,
        operation_guard_fd: int,
    ) -> dict[str, Any]:
        integrator_identity = self._authenticate(integrator_id, "integrator", credential)
        integrator_digest = (
            integrator_identity["credential_digest"] if integrator_identity else None
        )
        integration_id = str(uuid.uuid4())
        branch = f"acp/integrate-{task_id[:8]}-{integration_id[:8]}"
        worktree = self.state_dir / "worktrees" / f"integrate-{integration_id}"
        created = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._authenticate(integrator_id, "integrator", credential, connection)
            task = self._task_row(connection, task_id)
            if task["status"] != "approved":
                raise SupervisorError("qc_gate_not_passed", "task is not approved")
            submission = connection.execute(
                """
                SELECT * FROM submissions
                WHERE task_id = ? AND status = 'approved'
                ORDER BY created_at DESC LIMIT 1
                """,
                (task_id,),
            ).fetchone()
            if not submission:
                raise SupervisorError("qc_evidence_missing", "approved submission is missing")
            try:
                self._assert_submission_object_contract(submission)
            except SupervisorError:
                self._invalidate_legacy_submission_in(connection, submission, integrator_id)
                connection.commit()
                raise
            try:
                self._verify_attempt_trust_in(connection, submission["attempt_id"])
            except SupervisorError:
                # Persist quarantine while rejecting integration before it can
                # create a branch or invoke an external gate.
                connection.commit()
                raise
            self._assert_submission_assurance(connection, submission)
            self._assert_reservations(connection, task, submission)
            runtime = connection.execute(
                "SELECT * FROM runtime_environments WHERE attempt_id = ?",
                (submission["attempt_id"],),
            ).fetchone()
            if not runtime or runtime["state"] != "ready":
                raise SupervisorError(
                    "runtime_not_ready",
                    f"submission runtime state is {runtime['state'] if runtime else 'missing'}",
                )
            runtime_env = json.loads(runtime["env_json"])
            connection.execute(
                "UPDATE tasks SET status = 'integrating', updated_at = ? WHERE id = ?",
                (utc_now(), task_id),
            )
            operation_until = int(time.time()) + max(
                3600,
                self.config.timeout_seconds * (len(self.config.integration_commands) + 2) * 2,
            )
            connection.execute(
                "UPDATE resource_leases SET lease_expires_at = ?, updated_at = ? WHERE task_id = ?",
                (operation_until, utc_now(), task_id),
            )
            connection.execute(
                "UPDATE runtime_allocations SET lease_expires_at = ?, updated_at = ? "
                "WHERE attempt_id = ?",
                (operation_until, utc_now(), submission["attempt_id"]),
            )
            connection.execute(
                """
                INSERT INTO integrations
                  (id, task_id, submission_id, branch, commit_sha, verdict,
                   results_json, error, created_at)
                VALUES (?, ?, ?, NULL, NULL, 'running', '[]', '', ?)
                """,
                (integration_id, task_id, submission["id"], created),
            )
            self._event(
                connection,
                "integration.started",
                integrator_id,
                {
                    "integration_id": integration_id,
                    "task_id": task_id,
                    "submission_id": submission["id"],
                },
            )

        results: list[dict[str, Any]] = []
        verdict = "failed"
        commit: str | None = None
        error_message = ""
        try:
            if (
                self._git_text("cat-file", "-t", submission["commit_sha"]) != "commit"
                or self._git_text("rev-parse", f"{submission['commit_sha']}^{{tree}}")
                != submission["tree_sha"]
            ):
                raise SupervisorError(
                    "submission_evidence_mismatch",
                    "replacement-free submission object no longer matches reviewed evidence",
                )
            current_base = self._git_text("rev-parse", task["base_branch"])
            with self._isolated_integration_git(worktree, current_base) as git_boundary:
                merge_results, integration_commit = self._run_integration_merge(
                    current_base,
                    submission["commit_sha"],
                    operation_guard_fd,
                    git_boundary,
                )
                results.extend(merge_results)
                results.append(
                    self._integration_merge_input_result(
                        current_base,
                        submission["commit_sha"],
                        git_boundary,
                    )
                )
                if integration_commit is None:
                    merge = merge_results[-1]
                    code = (
                        "merge_conflict"
                        if merge.get("phase") == "merge-tree" and merge["exit_code"] == 1
                        else "integration_merge_failed"
                    )
                    raise SupervisorError(
                        code,
                        merge["stderr"].strip()
                        or merge["stdout"].strip()
                        or "isolated merge failed",
                    )
                for command in self.config.integration_commands:
                    self._restore_integration_workspace(
                        worktree,
                        integration_commit,
                        operation_guard_fd,
                        git_boundary,
                    )
                    result = self._run_command(
                        command,
                        worktree,
                        self._phase_runtime_env(runtime_env, "integration", worktree),
                        pass_fds=(operation_guard_fd,),
                    )
                    results.append(result)
                    if result["exit_code"]:
                        raise SupervisorError(
                            "integration_gate_failed",
                            f"integration command failed: {command}",
                        )
                    if not self._integration_workspace_matches(
                        worktree,
                        integration_commit,
                        operation_guard_fd,
                        git_boundary,
                    ):
                        raise SupervisorError(
                            "integration_gate_mutated_source",
                            f"integration command mutated tracked source or Git controls: {command}",
                        )
                self._assert_integration_git_boundary(
                    worktree,
                    integration_commit,
                    git_boundary,
                )
            commit = integration_commit
            verdict = "ready_to_publish"
        except (OSError, subprocess.SubprocessError, SupervisorError) as error:
            error_message = str(error)
            verdict = (
                "conflict"
                if isinstance(error, SupervisorError) and error.code == "merge_conflict"
                else "failed"
            )
        recorded = True
        publication_pending = False
        try:
            with self.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    self._reauthenticate_bound(
                        connection,
                        integrator_id,
                        "integrator",
                        credential,
                        integrator_digest,
                    )
                except SupervisorError as auth_error:
                    verdict = "stale"
                    error_message = f"{auth_error.code}: {auth_error}"
                trust_valid = True
                try:
                    self._verify_attempt_trust_in(connection, submission["attempt_id"])
                except SupervisorError as trust_error:
                    trust_valid = False
                    error_message = f"{trust_error.code}: {trust_error}"
                current_task = self._task_row(connection, task_id)
                reservation_valid = trust_valid and current_task["status"] == "integrating"
                if reservation_valid:
                    try:
                        self._assert_submission_assurance(connection, submission)
                    except SupervisorError as error:
                        reservation_valid = False
                        error_message = f"{error.code}: {error}"
                if reservation_valid:
                    try:
                        self._assert_reservations(connection, current_task, submission)
                    except SupervisorError as error:
                        reservation_valid = False
                        error_message = str(error)
                elif not error_message:
                    error_message = "task or reservation changed while integration was running"
                if not reservation_valid:
                    verdict = "stale"
                publication_pending = verdict == "ready_to_publish"
                stored_verdict = "publish_pending" if publication_pending else verdict
                updated = connection.execute(
                    """
                    UPDATE integrations
                    SET branch = ?, commit_sha = ?, verdict = ?, results_json = ?, error = ?
                    WHERE id = ? AND verdict = 'running'
                    """,
                    (
                        branch if publication_pending else None,
                        commit,
                        stored_verdict,
                        canonical_json(results),
                        error_message,
                        integration_id,
                    ),
                ).rowcount
                if updated != 1:
                    raise SupervisorError(
                        "integration_record_state_changed",
                        "durable integration execution record changed before completion",
                    )
                if not publication_pending and current_task["status"] == "integrating":
                    self._fence_task_cleanup(
                        connection,
                        task_id,
                        submission["attempt_id"],
                        "conflicted",
                        integrator_id,
                        "integration_completed",
                    )
                self._event(
                    connection,
                    (
                        "integration.publish_pending"
                        if publication_pending
                        else "integration.completed"
                    ),
                    integrator_id,
                    {
                        "integration_id": integration_id,
                        "task_id": task_id,
                        "verdict": stored_verdict,
                        "commit_sha": commit,
                        "error": error_message,
                    },
                )
            if publication_pending:
                try:
                    assert commit is not None
                    self._publish_integration_ref(branch, commit, operation_guard_fd)
                except (OSError, subprocess.SubprocessError, SupervisorError) as publish_error:
                    verdict = "failed"
                    error_message = f"integration publication failed: {publish_error}"
                    with self.connect() as connection:
                        connection.execute("BEGIN IMMEDIATE")
                        pending = connection.execute(
                            "SELECT verdict FROM integrations WHERE id = ?", (integration_id,)
                        ).fetchone()
                        if pending and pending["verdict"] == "publish_pending":
                            connection.execute(
                                "UPDATE integrations SET verdict = 'delete_pending', "
                                "error = ? WHERE id = ? AND verdict = 'publish_pending'",
                                (error_message, integration_id),
                            )
                            current_task = self._task_row(connection, task_id)
                            if current_task["status"] == "integrating":
                                self._fence_task_cleanup(
                                    connection,
                                    task_id,
                                    submission["attempt_id"],
                                    "conflicted",
                                    integrator_id,
                                    "integration_publication_failed",
                                )
                            self._event(
                                connection,
                                "integration.completed",
                                integrator_id,
                                {
                                    "integration_id": integration_id,
                                    "task_id": task_id,
                                    "verdict": verdict,
                                    "commit_sha": commit,
                                    "error": error_message,
                                },
                            )
                    try:
                        self._finalize_integration_ref_deletion(
                            integration_id,
                            branch,
                            commit,
                            operation_guard_fd,
                        )
                    except (OSError, subprocess.SubprocessError, SupervisorError) as delete_error:
                        publication_pending = True
                        error_message = f"{error_message}; ref cleanup pending: {delete_error}"
                        with self.connect() as connection:
                            connection.execute(
                                "UPDATE integrations SET error = ? "
                                "WHERE id = ? AND verdict = 'delete_pending'",
                                (error_message, integration_id),
                            )
                    else:
                        publication_pending = False
                else:
                    with self.connect() as connection:
                        connection.execute("BEGIN IMMEDIATE")
                        pending = connection.execute(
                            "SELECT verdict FROM integrations WHERE id = ?", (integration_id,)
                        ).fetchone()
                        if not pending or pending["verdict"] != "publish_pending":
                            raise SupervisorError(
                                "integration_publication_state_changed",
                                "durable integration publication intent changed",
                            )
                        current_task = self._task_row(connection, task_id)
                        if current_task["status"] != "integrating":
                            raise SupervisorError(
                                "integration_publication_state_changed",
                                "task changed after integration publication intent",
                            )
                        connection.execute(
                            "UPDATE integrations SET verdict = 'pass', error = '' "
                            "WHERE id = ? AND verdict = 'publish_pending'",
                            (integration_id,),
                        )
                        self._fence_task_cleanup(
                            connection,
                            task_id,
                            submission["attempt_id"],
                            "done",
                            integrator_id,
                            "integration_published",
                        )
                        self._event(
                            connection,
                            "integration.completed",
                            integrator_id,
                            {
                                "integration_id": integration_id,
                                "task_id": task_id,
                                "verdict": "pass",
                                "commit_sha": commit,
                                "error": "",
                            },
                        )
                    verdict = "pass"
                    publication_pending = False
        finally:
            if worktree.is_symlink():
                worktree.unlink()
            elif worktree.exists():
                shutil.rmtree(worktree)
            if (not recorded or verdict != "pass") and not publication_pending:
                self._delete_integration_ref(branch, commit, operation_guard_fd)
        try:
            runtime_cleanup: dict[str, Any] = self.runtime_down(submission["attempt_id"])
        except (OSError, subprocess.SubprocessError, SupervisorError) as cleanup_error:
            runtime_cleanup = {
                "attempt_id": submission["attempt_id"],
                "state": "cleanup_error",
                "error": str(cleanup_error),
            }
            with self.connect() as connection:
                connection.execute(
                    "UPDATE tasks SET cleanup_error = ?, updated_at = ? "
                    "WHERE id = ? AND status = 'cleanup_pending'",
                    (str(cleanup_error), utc_now(), task_id),
                )
        if runtime_cleanup["state"] == "released":
            with self.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._complete_task_cleanup(
                    connection,
                    task_id,
                    submission["attempt_id"],
                    integrator_id,
                )
        return {
            "id": integration_id,
            "task_id": task_id,
            "submission_id": submission["id"],
            "branch": branch if verdict == "pass" else None,
            "commit_sha": commit,
            "verdict": verdict,
            "error": error_message,
            "command_results": results,
            "runtime_cleanup": runtime_cleanup,
        }

    @staticmethod
    def _integration_merge_input_result(
        base_sha: str,
        candidate_sha: str,
        boundary: IntegrationGitBoundary,
    ) -> dict[str, Any]:
        evidence = json.loads(canonical_json(boundary.merge_input_evidence))
        evidence.update({"base_sha": base_sha, "candidate_sha": candidate_sha})
        return {
            "command": "isolated merge input snapshot",
            "phase": "merge-input-evidence",
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "timed_out": False,
            "security_boundary": "synthetic-config+empty-exec-path+contained",
            "evidence": evidence,
        }

    def _publish_integration_ref(
        self, branch: str, commit_sha: str, operation_guard_fd: int
    ) -> None:
        """Create the public ref after its durable publication intent exists."""

        reference = f"refs/heads/{branch}"
        result = self._run_ref_git_contained(
            ["update-ref", reference, commit_sha, "0" * len(commit_sha)],
            f"git update-ref {reference}",
            operation_guard_fd,
        )
        if result["exit_code"] == 0:
            return
        verify = self._run_ref_git_contained(
            ["rev-parse", "--verify", reference],
            f"git rev-parse --verify {reference}",
            operation_guard_fd,
        )
        if verify["exit_code"] == 0 and verify["stdout"].strip() == commit_sha:
            return
        raise SupervisorError(
            "integration_publication_failed",
            result["stderr"].strip() or "integration ref could not be created",
        )

    def _delete_integration_ref(
        self, branch: str, commit_sha: str | None, operation_guard_fd: int
    ) -> None:
        reference = f"refs/heads/{branch}"
        arguments = ["update-ref", "-d", reference]
        if commit_sha:
            arguments.append(commit_sha)
        self._run_ref_git_contained(
            arguments,
            f"git update-ref -d {reference}",
            operation_guard_fd,
        )
        verify = self._run_ref_git_contained(
            ["show-ref", "--verify", "--quiet", reference],
            f"git show-ref --verify --quiet {reference}",
            operation_guard_fd,
        )
        if verify["exit_code"] == 0:
            raise SupervisorError(
                "integration_ref_deletion_failed",
                f"integration ref still exists after deletion: {reference}",
            )
        if verify["exit_code"] != 1:
            raise SupervisorError(
                "integration_ref_deletion_unverified",
                verify["stderr"].strip()
                or f"integration ref absence could not be verified: {reference}",
            )

    def _finalize_integration_ref_deletion(
        self,
        integration_id: str,
        branch: str,
        commit_sha: str,
        operation_guard_fd: int,
    ) -> None:
        self._delete_integration_ref(branch, commit_sha, operation_guard_fd)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE integrations SET branch = NULL, verdict = 'failed' "
                "WHERE id = ? AND verdict = 'delete_pending'",
                (integration_id,),
            )

    def _run_ref_git_contained(
        self, arguments: Sequence[str], label: str, operation_guard_fd: int
    ) -> dict[str, Any]:
        git = str(self._system_git_executable(self.root))
        argv = [
            *self._supervisor_git_prefix(git, self._disabled_git_hooks_dir()),
            "-C",
            str(self.root),
            *arguments,
        ]
        with self._git_operation_guard() as git_guard_fd:
            return self._run_process(
                argv,
                label,
                self.root,
                self._supervisor_git_env(),
                lifecycle_fds=(operation_guard_fd, git_guard_fd),
            )

    def _reconcile_pending_integrations(self) -> None:
        """Finish durable publications and remove residue for every recorded integration."""

        with self.connect() as connection:
            pending_rows = connection.execute(
                """
                SELECT integration.id, integration.task_id, integration.branch,
                  integration.commit_sha, integration.verdict, submission.attempt_id
                FROM integrations AS integration
                JOIN submissions AS submission ON submission.id = integration.submission_id
                ORDER BY integration.created_at, integration.id
                """
            ).fetchall()
        for pending in pending_rows:
            try:
                with self._task_operation_guard(
                    pending["task_id"], recover=True
                ) as operation_guard_fd:
                    self._reconcile_pending_integration_locked(pending, operation_guard_fd)
            except SupervisorError as error:
                if error.code != "task_operation_executor_alive":
                    raise

    def _reconcile_pending_integration_locked(
        self, pending: sqlite3.Row, operation_guard_fd: int
    ) -> None:
        try:
            if pending["verdict"] == "publish_pending":
                self._reconcile_pending_integration_state(pending, operation_guard_fd)
            elif pending["verdict"] == "running":
                self._reconcile_interrupted_integration_state(pending)
            elif pending["verdict"] == "delete_pending":
                self._reconcile_pending_ref_deletion(pending, operation_guard_fd)
        finally:
            self._remove_integration_residue(pending["id"])

    def _reconcile_interrupted_integration_state(self, pending: sqlite3.Row) -> None:
        error_message = "integration process stopped before recording a terminal result"
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT verdict FROM integrations WHERE id = ?", (pending["id"],)
            ).fetchone()
            if not row or row["verdict"] != "running":
                return
            task = self._task_row(connection, pending["task_id"])
            recovered_verdict = "failed" if task["status"] == "integrating" else "stale"
            connection.execute(
                "UPDATE integrations SET verdict = ?, error = ? "
                "WHERE id = ? AND verdict = 'running'",
                (recovered_verdict, error_message, pending["id"]),
            )
            if task["status"] == "integrating":
                self._fence_task_cleanup(
                    connection,
                    pending["task_id"],
                    pending["attempt_id"],
                    "conflicted",
                    "recovery",
                    "integration_execution_interrupted",
                )
            self._event(
                connection,
                "integration.execution_recovered",
                "recovery",
                {
                    "integration_id": pending["id"],
                    "task_id": pending["task_id"],
                    "verdict": recovered_verdict,
                    "error": error_message,
                },
            )

    def _reconcile_pending_ref_deletion(
        self, pending: sqlite3.Row, operation_guard_fd: int
    ) -> None:
        branch = pending["branch"]
        commit_sha = pending["commit_sha"]
        if not branch or not commit_sha:
            raise SupervisorError(
                "integration_ref_cleanup_invalid",
                "durable integration ref cleanup intent is incomplete",
            )
        self._finalize_integration_ref_deletion(
            pending["id"], branch, commit_sha, operation_guard_fd
        )

    def _reconcile_pending_integration_state(
        self, pending: sqlite3.Row, operation_guard_fd: int
    ) -> None:
        branch = pending["branch"]
        commit_sha = pending["commit_sha"]
        if not branch or not commit_sha:
            raise SupervisorError(
                "integration_publication_invalid",
                "durable integration publication intent is incomplete",
            )
        try:
            self._publish_integration_ref(branch, commit_sha, operation_guard_fd)
        except (OSError, subprocess.SubprocessError, SupervisorError) as error:
            error_message = f"restart publication failed: {error}"
            with self.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT verdict FROM integrations WHERE id = ?", (pending["id"],)
                ).fetchone()
                if not row or row["verdict"] != "publish_pending":
                    return
                connection.execute(
                    "UPDATE integrations SET verdict = 'delete_pending', error = ? "
                    "WHERE id = ? AND verdict = 'publish_pending'",
                    (error_message, pending["id"]),
                )
                task = self._task_row(connection, pending["task_id"])
                if task["status"] == "integrating":
                    self._fence_task_cleanup(
                        connection,
                        pending["task_id"],
                        pending["attempt_id"],
                        "conflicted",
                        "recovery",
                        "integration_publication_failed",
                    )
                self._event(
                    connection,
                    "integration.publication_recovered",
                    "recovery",
                    {
                        "integration_id": pending["id"],
                        "task_id": pending["task_id"],
                        "verdict": "failed",
                        "error": error_message,
                    },
                )
            self._finalize_integration_ref_deletion(
                pending["id"], branch, commit_sha, operation_guard_fd
            )
            return
        delete_ref = False
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT verdict FROM integrations WHERE id = ?", (pending["id"],)
            ).fetchone()
            if not row or row["verdict"] != "publish_pending":
                return
            task = self._task_row(connection, pending["task_id"])
            if task["status"] == "integrating":
                connection.execute(
                    "UPDATE integrations SET verdict = 'pass', error = '' "
                    "WHERE id = ? AND verdict = 'publish_pending'",
                    (pending["id"],),
                )
                self._fence_task_cleanup(
                    connection,
                    pending["task_id"],
                    pending["attempt_id"],
                    "done",
                    "recovery",
                    "integration_publication_recovered",
                )
                recovered_verdict = "pass"
            elif task["status"] == "cleanup_pending" and task["cleanup_target_status"] == "done":
                connection.execute(
                    "UPDATE integrations SET verdict = 'pass', error = '' "
                    "WHERE id = ? AND verdict = 'publish_pending'",
                    (pending["id"],),
                )
                recovered_verdict = "pass"
            else:
                error_message = "task changed before publication recovery"
                connection.execute(
                    "UPDATE integrations SET verdict = 'delete_pending', error = ? "
                    "WHERE id = ? AND verdict = 'publish_pending'",
                    (error_message, pending["id"]),
                )
                recovered_verdict = "failed"
                delete_ref = True
            self._event(
                connection,
                "integration.publication_recovered",
                "recovery",
                {
                    "integration_id": pending["id"],
                    "task_id": pending["task_id"],
                    "verdict": recovered_verdict,
                },
            )
        if delete_ref:
            self._finalize_integration_ref_deletion(
                pending["id"], branch, commit_sha, operation_guard_fd
            )

    def _remove_integration_residue(self, integration_id: str) -> None:
        for path in (
            self.state_dir / "worktrees" / f"integrate-{integration_id}",
            self.state_dir / "integration-git" / f"integrate-{integration_id}",
        ):
            if path.is_symlink():
                path.unlink()
            elif path.exists():
                shutil.rmtree(path)

    def _run_integration_merge(
        self,
        base_sha: str,
        commit_sha: str,
        operation_guard_fd: int,
        boundary: IntegrationGitBoundary,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Create one real merge commit through candidate-inert Git plumbing.

        The synthetic GIT_DIR has no repository/user/system configuration, no
        hooks and an empty Git exec path. `merge-tree` and `commit-tree` are
        built-ins, so Darwin can enforce the same no-fork kernel policy used by
        every other bounded command instead of exempting porcelain `git merge`.
        """

        self._assert_integration_git_boundary(None, None, boundary)
        ancestry = self._run_isolated_git(
            boundary,
            ["merge-base", "--is-ancestor", commit_sha, base_sha],
            f"git merge-base --is-ancestor {commit_sha} {base_sha}",
            operation_guard_fd,
        )
        ancestry["phase"] = "ancestry-check"
        results = [ancestry]
        if ancestry["exit_code"] == 0:
            head = boundary.git_dir / "HEAD"
            head.write_text(base_sha + "\n", encoding="ascii")
            head.chmod(0o600)
            self._assert_integration_git_boundary(None, base_sha, boundary)
            return results, base_sha
        if ancestry["exit_code"] != 1:
            return results, None
        merge = self._run_isolated_git(
            boundary,
            ["merge-tree", "--write-tree", "--no-messages", base_sha, commit_sha],
            f"git merge-tree {base_sha} {commit_sha}",
            operation_guard_fd,
        )
        merge["phase"] = "merge-tree"
        results.append(merge)
        if merge["exit_code"]:
            return results, None
        tree_sha = merge["stdout"].strip()
        if not re.fullmatch(rf"[0-9a-f]{{{boundary.oid_length}}}", tree_sha):
            raise SupervisorError(
                "integration_merge_invalid_output",
                "isolated merge-tree did not return exactly one tree object id",
            )
        commit = self._run_isolated_git(
            boundary,
            [
                "-c",
                "user.name=Agent Control Plane",
                "-c",
                "user.email=acp@localhost.invalid",
                "commit-tree",
                tree_sha,
                "-p",
                base_sha,
                "-p",
                commit_sha,
                "-m",
                f"ACP integration merge of {commit_sha[:12]}",
                "--no-gpg-sign",
            ],
            f"git commit-tree {tree_sha}",
            operation_guard_fd,
        )
        commit["phase"] = "commit-tree"
        results.append(commit)
        if commit["exit_code"]:
            return results, None
        integration_commit = commit["stdout"].strip()
        if not re.fullmatch(rf"[0-9a-f]{{{boundary.oid_length}}}", integration_commit):
            raise SupervisorError(
                "integration_commit_invalid_output",
                "isolated commit-tree did not return exactly one commit object id",
            )
        verify = self._run_isolated_git(
            boundary,
            ["cat-file", "-p", integration_commit],
            f"git cat-file -p {integration_commit}",
            operation_guard_fd,
        )
        verify["phase"] = "verify-commit"
        results.append(verify)
        if verify["exit_code"]:
            return results, None
        headers = verify["stdout"].split("\n\n", 1)[0].splitlines()
        tree_headers = [line.removeprefix("tree ") for line in headers if line.startswith("tree ")]
        parents = [line.removeprefix("parent ") for line in headers if line.startswith("parent ")]
        if tree_headers != [tree_sha] or parents != [base_sha, commit_sha]:
            raise SupervisorError(
                "integration_commit_invalid",
                "isolated merge commit tree or parents do not match the requested merge",
            )
        head = boundary.git_dir / "HEAD"
        head.write_text(integration_commit + "\n", encoding="ascii")
        head.chmod(0o600)
        self._assert_integration_git_boundary(None, integration_commit, boundary)
        return results, integration_commit

    @contextmanager
    def _isolated_integration_git(
        self, worktree: Path, base_sha: str
    ) -> Iterator[IntegrationGitBoundary]:
        """Build a minimal Git control directory that cannot load repo config."""

        git_source = self._system_git_executable(self.root)
        common_value = self._git_text("rev-parse", "--path-format=absolute", "--git-common-dir")
        common_dir = Path(common_value)
        if not common_dir.is_absolute():
            common_dir = (self.root / common_dir).resolve()
        try:
            object_dir = (common_dir / "objects").resolve(strict=True)
        except FileNotFoundError as error:
            raise SupervisorError(
                "git_object_store_missing", "repository object store is missing"
            ) from error
        object_format = self._git_text("rev-parse", "--show-object-format")
        if object_format not in {"sha1", "sha256"}:
            raise SupervisorError(
                "git_object_format_unsupported",
                f"unsupported Git object format: {object_format}",
            )
        merge_config = self._integration_merge_config()
        git_version = self._git_text("--version")
        global_snapshot = self._read_core_attributes_file(base_sha)
        info_snapshot = self._read_integration_info_attributes(common_dir)
        global_attributes = global_snapshot.content
        info_attributes = info_snapshot.content
        for path in (object_dir, worktree):
            if "\n" in str(path) or "\r" in str(path):
                raise SupervisorError(
                    "unsafe_git_path", "integration Git paths cannot contain newlines"
                )
        boundary_root = self.state_dir / "integration-git"
        boundary_root.mkdir(mode=0o700, exist_ok=True)
        boundary_root.chmod(0o700)
        git_dir = boundary_root / worktree.name
        try:
            git_dir.mkdir(mode=0o700)
        except FileExistsError as error:
            raise SupervisorError(
                "integration_git_boundary_exists",
                "stale integration Git boundary must be reconciled before reuse",
            ) from error
        try:
            git_dir.chmod(0o700)
            source_digest = sha256(git_source.read_bytes())
            git = git_dir / "supervisor-git"
            shutil.copyfile(git_source, git)
            git.chmod(0o500)
            if (
                sha256(git.read_bytes()) != source_digest
                or sha256(git_source.read_bytes()) != source_digest
            ):
                raise SupervisorError(
                    "git_executable_changed",
                    "the system Git executable changed while its private snapshot was created",
                )
            for directory in (
                git_dir / "objects" / "info",
                git_dir / "objects" / "pack",
                git_dir / "info",
                git_dir / "refs" / "heads",
                git_dir / "hooks",
                git_dir / "empty-exec",
            ):
                directory.mkdir(parents=True, exist_ok=True)
                directory.chmod(0o700)
            repository_version = 1 if object_format == "sha256" else 0
            extensions = (
                f"[extensions]\n\tobjectFormat = {object_format}\n"
                if object_format != "sha1"
                else ""
            )
            config_text = (
                "[core]\n"
                f"\trepositoryFormatVersion = {repository_version}\n"
                "\tbare = false\n"
                f"\tworktree = {json.dumps(str(worktree))}\n"
                f"\thooksPath = {json.dumps(str(git_dir / 'hooks'))}\n"
                "\tfsmonitor = false\n"
                f"\tattributesFile = {json.dumps(str(git_dir / 'info' / 'global-attributes') if global_attributes is not None else os.devnull)}\n"
                "[commit]\n"
                "\tgpgSign = false\n"
                "[merge]\n"
                "\tverifySignatures = false\n"
                "[maintenance]\n"
                "\tauto = false\n"
                "[gc]\n"
                "\tauto = 0\n"
                f"{extensions}"
                f"{merge_config}"
            )
            config = git_dir / "config"
            config.write_text(config_text, encoding="utf-8")
            config.chmod(0o600)
            head = git_dir / "HEAD"
            head.write_text("ref: refs/heads/acp-isolated\n", encoding="ascii")
            head.chmod(0o600)
            alternates_text = str(object_dir) + "\n"
            alternates = git_dir / "objects" / "info" / "alternates"
            alternates.write_text(alternates_text, encoding="utf-8")
            alternates.chmod(0o600)
            if info_attributes is not None:
                attributes = git_dir / "info" / "attributes"
                attributes.write_bytes(info_attributes)
                attributes.chmod(0o600)
            if global_attributes is not None:
                attributes = git_dir / "info" / "global-attributes"
                attributes.write_bytes(global_attributes)
                attributes.chmod(0o600)
            env = self._supervisor_git_env()
            env.update(
                {
                    "HOME": str(git_dir),
                    "GIT_ATTR_NOSYSTEM": "1",
                    "GIT_CONFIG_COUNT": "0",
                    "GIT_DIR": str(git_dir),
                    "GIT_EXEC_PATH": str(git_dir / "empty-exec"),
                    "GIT_INDEX_FILE": str(git_dir / "index"),
                    "GIT_OBJECT_DIRECTORY": str(object_dir),
                    "GIT_PAGER": "",
                    "GIT_WORK_TREE": str(worktree),
                    "PAGER": "",
                }
            )
            boundary = IntegrationGitBoundary(
                git=str(git),
                git_dir=git_dir,
                object_dir=object_dir,
                env=env,
                git_digest=source_digest,
                git_size=git.stat().st_size,
                config_digest=sha256(config_text.encode()),
                alternates_text=alternates_text,
                global_attributes=global_attributes,
                info_attributes=info_attributes,
                merge_input_evidence={
                    "contract": "isolated-merge-input-v1",
                    "git": {
                        "sha256": source_digest,
                        "size": git.stat().st_size,
                        "version": git_version,
                    },
                    "object_format": object_format,
                    "semantic_config": merge_config,
                    "core_attributes": dict(global_snapshot.evidence),
                    "info_attributes": dict(info_snapshot.evidence),
                    "system_attributes": "disabled",
                },
                oid_length=64 if object_format == "sha256" else 40,
            )
            self._assert_integration_git_boundary(None, None, boundary)
            yield boundary
        finally:
            if git_dir.is_symlink():
                git_dir.unlink()
            elif git_dir.exists():
                shutil.rmtree(git_dir)

    def _integration_merge_config(self) -> str:
        """Copy only data-only settings that affect ort's merge result."""

        copied: list[str] = []
        for key in MERGE_SEMANTIC_CONFIG:
            result = self._git(
                "config",
                "--local",
                "--null",
                "--get-all",
                key,
                check=False,
            )
            if result.returncode == 1:
                continue
            if result.returncode:
                raise SupervisorError(
                    "git_config_unreadable",
                    result.stderr.decode(errors="replace").strip()
                    or f"local Git setting {key} could not be read",
                )
            raw_values = result.stdout.split(b"\0")
            if raw_values and raw_values[-1] == b"":
                raw_values.pop()
            if not raw_values:
                continue
            try:
                value = raw_values[-1].decode("utf-8")
            except UnicodeDecodeError as error:
                raise SupervisorError(
                    "unsafe_git_merge_config", f"local Git setting {key} is not UTF-8"
                ) from error
            if len(value.encode()) > 1024 or any(character in value for character in "\0\r\n"):
                raise SupervisorError(
                    "unsafe_git_merge_config", f"local Git setting {key} is not bounded"
                )
            if value == "":
                value = "true"
            section, name = key.split(".", 1)
            copied.append(f"[{section}]\n\t{name} = {json.dumps(value)}\n")
        return "".join(copied)

    def _read_core_attributes_file(self, base_sha: str) -> AttributeSnapshot:
        result = self._git(
            "config",
            "--local",
            "--path",
            "--get",
            "core.attributesFile",
            check=False,
        )
        if result.returncode == 1:
            return self._attribute_snapshot("core_attributes", "unset", None)
        if result.returncode:
            raise SupervisorError(
                "git_config_unreadable",
                result.stderr.decode(errors="replace").strip()
                or "core.attributesFile could not be read",
            )
        try:
            value = result.stdout.decode("utf-8").rstrip("\n")
        except UnicodeDecodeError as error:
            raise SupervisorError(
                "unsafe_git_attributes", "core.attributesFile is not UTF-8"
            ) from error
        if not value or any(character in value for character in "\0\r\n"):
            raise SupervisorError("unsafe_git_attributes", "core.attributesFile path is invalid")
        source = Path(value).expanduser()
        if not source.is_absolute():
            relative = PurePosixPath(value)
            if relative.is_absolute() or ".." in relative.parts:
                raise SupervisorError(
                    "unsafe_git_attributes",
                    "relative core.attributesFile must stay within the integration tree",
                )
            tree_path = relative.as_posix()
            entry = self._git(
                "ls-tree",
                "--full-tree",
                "-z",
                base_sha,
                "--",
                f":(literal){tree_path}",
                check=False,
            )
            if entry.returncode:
                raise SupervisorError(
                    "unsafe_git_attributes",
                    entry.stderr.decode(errors="replace").strip()
                    or "relative core.attributesFile could not be read from the base tree",
                )
            if not entry.stdout:
                return self._attribute_snapshot("core_attributes", f"base-tree:{tree_path}", None)
            metadata, separator, returned_path = entry.stdout.partition(b"\t")
            fields = metadata.split()
            try:
                decoded_path = returned_path.removesuffix(b"\0").decode("utf-8")
            except UnicodeDecodeError as error:
                raise SupervisorError(
                    "unsafe_git_attributes", "relative core.attributesFile is not UTF-8"
                ) from error
            if (
                separator != b"\t"
                or not returned_path.endswith(b"\0")
                or len(fields) != 3
                or fields[0] not in {b"100644", b"100755"}
                or fields[1] != b"blob"
                or decoded_path != tree_path
            ):
                raise SupervisorError(
                    "unsafe_git_attributes",
                    "relative core.attributesFile must identify one regular file in the base tree",
                )
            object_id = fields[2].decode("ascii")
            size_text = self._git_text("cat-file", "-s", object_id)
            if not size_text.isascii() or not size_text.isdecimal():
                raise SupervisorError(
                    "unsafe_git_attributes",
                    "relative core.attributesFile size is invalid",
                )
            if int(size_text) > MAX_ATTRIBUTE_BYTES:
                raise SupervisorError(
                    "unsafe_git_attributes",
                    "core.attributesFile must be no larger than 1 MiB",
                )
            content = self._git_bytes("cat-file", "blob", object_id)
            return self._attribute_snapshot(
                "core_attributes",
                f"base-tree:{tree_path}",
                content,
                {"blob_oid": object_id, "base_sha": base_sha},
            )
        if source == Path(os.devnull):
            return self._attribute_snapshot("core_attributes", "disabled", None)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(source, flags)
        except FileNotFoundError:
            return self._attribute_snapshot("core_attributes", f"absolute:{source}", None)
        except OSError as error:
            raise SupervisorError(
                "unsafe_git_attributes", "core.attributesFile could not be opened"
            ) from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_ATTRIBUTE_BYTES:
                raise SupervisorError(
                    "unsafe_git_attributes",
                    "core.attributesFile must be a regular file no larger than 1 MiB",
                )
            with os.fdopen(descriptor, "rb", closefd=False) as opened:
                content = opened.read(MAX_ATTRIBUTE_BYTES + 1)
            if len(content) > MAX_ATTRIBUTE_BYTES:
                raise SupervisorError(
                    "unsafe_git_attributes",
                    "core.attributesFile must be no larger than 1 MiB",
                )
            return self._attribute_snapshot("core_attributes", f"absolute:{source}", content)
        finally:
            os.close(descriptor)

    @staticmethod
    def _attribute_snapshot(
        kind: str,
        source: str,
        content: bytes | None,
        extra: Mapping[str, Any] | None = None,
    ) -> AttributeSnapshot:
        evidence: dict[str, Any] = {
            "kind": kind,
            "source": source,
            "present": content is not None,
            "size": len(content) if content is not None else 0,
            "sha256": sha256(content) if content is not None else None,
            "content_b64": (
                base64.b64encode(content).decode("ascii") if content is not None else None
            ),
        }
        if extra:
            evidence.update(extra)
        return AttributeSnapshot(content=content, evidence=evidence)

    @staticmethod
    def _system_git_executable(repo_root: Path | None = None) -> Path:
        """Resolve Git without ever executing a PATH-selected candidate wrapper."""

        raw = shutil.which("git")
        candidates: list[Path] = []
        if sys.platform == "darwin":
            # /usr/bin/git is an xcrun launcher and needs a child process. Use
            # the actual Apple Git binary so the no-fork sandbox can stay on.
            candidates.extend(
                [
                    Path("/Library/Developer/CommandLineTools/usr/bin/git"),
                    Path("/Applications/Xcode.app/Contents/Developer/usr/bin/git"),
                ]
            )
            if raw and Path(raw) != Path("/usr/bin/git"):
                candidates.append(Path(raw))
        else:
            candidates.extend([Path("/usr/bin/git"), Path("/usr/local/bin/git")])
            if raw:
                candidates.append(Path(raw))
        seen: set[Path] = set()
        for path in candidates:
            try:
                resolved = path.resolve(strict=True)
                metadata = resolved.stat()
            except OSError:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            if repo_root is not None:
                try:
                    resolved.relative_to(repo_root.resolve())
                except ValueError:
                    pass
                else:
                    continue
            if (
                stat.S_ISREG(metadata.st_mode)
                and metadata.st_uid == 0
                and not metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                and os.access(resolved, os.X_OK)
            ):
                return resolved
        raise SupervisorError(
            "untrusted_git_executable",
            "a root-owned, non-writable system Git executable is required",
        )

    def _run_isolated_git(
        self,
        boundary: IntegrationGitBoundary,
        arguments: Sequence[str],
        label: str,
        operation_guard_fd: int,
    ) -> dict[str, Any]:
        with self._git_operation_guard() as git_guard_fd:
            result = self._run_process(
                [
                    *self._supervisor_git_prefix(boundary.git, boundary.git_dir / "hooks"),
                    "-c",
                    "submodule.recurse=false",
                    *arguments,
                ],
                label,
                self.root,
                dict(boundary.env),
                lifecycle_fds=(operation_guard_fd, git_guard_fd),
            )
        result["security_boundary"] = "synthetic-config+empty-exec-path+contained"
        return result

    def _restore_integration_workspace(
        self,
        worktree: Path,
        commit_sha: str,
        operation_guard_fd: int,
        boundary: IntegrationGitBoundary,
    ) -> None:
        if worktree.exists():
            if (worktree / ".git").exists():
                self._assert_integration_git_boundary(worktree, commit_sha, boundary)
            for entry in worktree.iterdir():
                if entry.is_symlink() or not entry.is_dir():
                    entry.unlink()
                else:
                    shutil.rmtree(entry)
        else:
            worktree.mkdir(mode=0o700, parents=True)
        (boundary.git_dir / "HEAD").write_text(commit_sha + "\n", encoding="ascii")
        (boundary.git_dir / "HEAD").chmod(0o600)
        read_tree = self._run_isolated_git(
            boundary,
            ["read-tree", "--reset", commit_sha],
            f"git read-tree {commit_sha}",
            operation_guard_fd,
        )
        if read_tree["exit_code"]:
            raise SupervisorError(
                "integration_materialization_failed",
                read_tree["stderr"].strip() or "isolated read-tree failed",
            )
        checkout = self._run_isolated_git(
            boundary,
            ["checkout-index", "--all", "--force", f"--prefix={worktree}{os.sep}"],
            f"git checkout-index {commit_sha}",
            operation_guard_fd,
        )
        if checkout["exit_code"]:
            raise SupervisorError(
                "integration_materialization_failed",
                checkout["stderr"].strip() or "isolated checkout-index failed",
            )
        git_file = worktree / ".git"
        git_file.write_text(f"gitdir: {boundary.git_dir}\n", encoding="utf-8")
        git_file.chmod(0o600)
        self._assert_integration_git_boundary(worktree, commit_sha, boundary)

    def _integration_workspace_matches(
        self,
        worktree: Path,
        commit_sha: str,
        operation_guard_fd: int,
        boundary: IntegrationGitBoundary,
    ) -> bool:
        self._assert_no_git_grafts()
        try:
            self._assert_integration_git_boundary(worktree, commit_sha, boundary)
        except SupervisorError:
            return False
        for arguments, label in (
            (["diff", "--no-ext-diff", "--quiet", commit_sha, "--"], "git diff --quiet"),
            (
                ["diff", "--cached", "--no-ext-diff", "--quiet", commit_sha, "--"],
                "git diff --cached --quiet",
            ),
        ):
            if self._run_isolated_git(
                boundary,
                arguments,
                label,
                operation_guard_fd,
            )["exit_code"]:
                return False
        return True

    def _assert_integration_git_boundary(
        self,
        worktree: Path | None,
        commit_sha: str | None,
        boundary: IntegrationGitBoundary,
    ) -> None:
        def require_file(path: Path, expected: bytes) -> None:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(path, flags)
            except OSError as error:
                raise SupervisorError(
                    "integration_git_boundary_changed",
                    f"isolated Git control file is unavailable: {path.name}",
                ) from error
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_size != len(expected)
                ):
                    raise SupervisorError(
                        "integration_git_boundary_changed",
                        f"isolated Git control file changed: {path.name}",
                    )
                with os.fdopen(descriptor, "rb", closefd=False) as opened:
                    actual = opened.read(len(expected) + 1)
            finally:
                os.close(descriptor)
            if actual != expected:
                raise SupervisorError(
                    "integration_git_boundary_changed",
                    f"isolated Git control file changed: {path.name}",
                )

        metadata = boundary.git_dir.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise SupervisorError(
                "integration_git_boundary_changed", "isolated Git directory changed"
            )
        try:
            git_metadata = Path(boundary.git).lstat()
        except OSError as error:
            raise SupervisorError(
                "integration_git_boundary_changed", "private Git executable is unavailable"
            ) from error
        if (
            not stat.S_ISREG(git_metadata.st_mode)
            or git_metadata.st_uid != os.getuid()
            or stat.S_IMODE(git_metadata.st_mode) != 0o500
            or git_metadata.st_size != boundary.git_size
        ):
            raise SupervisorError(
                "integration_git_boundary_changed", "private Git executable changed"
            )
        try:
            git_bytes = Path(boundary.git).read_bytes()
        except OSError as error:
            raise SupervisorError(
                "integration_git_boundary_changed", "private Git executable is unavailable"
            ) from error
        if sha256(git_bytes) != boundary.git_digest:
            raise SupervisorError(
                "integration_git_boundary_changed", "private Git executable changed"
            )
        config = boundary.git_dir / "config"
        try:
            config_bytes = config.read_bytes()
        except OSError as error:
            raise SupervisorError(
                "integration_git_boundary_changed", "isolated Git config is unavailable"
            ) from error
        require_file(config, config_bytes)
        if sha256(config_bytes) != boundary.config_digest:
            raise SupervisorError("integration_git_boundary_changed", "isolated Git config changed")
        expected_head = (
            (commit_sha + "\n").encode() if commit_sha else b"ref: refs/heads/acp-isolated\n"
        )
        require_file(boundary.git_dir / "HEAD", expected_head)
        require_file(
            boundary.git_dir / "objects" / "info" / "alternates",
            boundary.alternates_text.encode(),
        )
        info_dir = boundary.git_dir / "info"
        info_metadata = info_dir.lstat()
        expected_info_names: set[str] = set()
        if boundary.info_attributes is not None:
            expected_info_names.add("attributes")
        if boundary.global_attributes is not None:
            expected_info_names.add("global-attributes")
        if (
            not stat.S_ISDIR(info_metadata.st_mode)
            or info_metadata.st_uid != os.getuid()
            or stat.S_IMODE(info_metadata.st_mode) != 0o700
            or {entry.name for entry in info_dir.iterdir()} != expected_info_names
        ):
            raise SupervisorError(
                "integration_git_boundary_changed", "isolated Git info directory changed"
            )
        if boundary.info_attributes is not None:
            require_file(info_dir / "attributes", boundary.info_attributes)
        if boundary.global_attributes is not None:
            require_file(info_dir / "global-attributes", boundary.global_attributes)
        for directory in (boundary.git_dir / "hooks", boundary.git_dir / "empty-exec"):
            opened = directory.lstat()
            if (
                not stat.S_ISDIR(opened.st_mode)
                or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o700
                or any(directory.iterdir())
            ):
                raise SupervisorError(
                    "integration_git_boundary_changed",
                    f"isolated Git {directory.name} directory changed",
                )
        if any(
            entry.is_file() or entry.is_symlink()
            for entry in (boundary.git_dir / "refs").rglob("*")
        ):
            raise SupervisorError("integration_git_boundary_changed", "isolated Git refs changed")
        allowed = {
            "HEAD",
            "config",
            "empty-exec",
            "hooks",
            "index",
            "info",
            "objects",
            "refs",
            "supervisor-git",
        }
        if any(entry.name not in allowed for entry in boundary.git_dir.iterdir()):
            raise SupervisorError(
                "integration_git_boundary_changed", "isolated Git control files changed"
            )
        if worktree is not None:
            require_file(
                worktree / ".git",
                f"gitdir: {boundary.git_dir}\n".encode(),
            )

    def _assert_safe_git_execution_config(self) -> None:
        executable_config = self._git(
            "config",
            "--local",
            "--name-only",
            "--get-regexp",
            (
                r"^(filter\..*\.(clean|smudge|process|required)|merge\..*\.driver|"
                r"core\.(fsmonitor|sshcommand)|diff\.external|difftool\..*\.cmd|"
                r"mergetool\..*\.cmd|gpg(\..*)?\.program|credential(\..*)?\.helper|"
                r"include\.path|includeif\..*\.path)$"
            ),
            check=False,
        )
        if executable_config.returncode not in {0, 1}:
            raise SupervisorError(
                "git_config_unreadable",
                executable_config.stderr.decode(errors="replace").strip()
                or "local Git execution config could not be inspected",
            )
        configured = executable_config.stdout.decode(errors="replace").splitlines()
        if configured:
            raise SupervisorError(
                "unsafe_git_execution_config",
                "integration refuses executable Git config: " + ", ".join(configured),
            )

    def _assert_no_git_grafts(self) -> None:
        """Grafts cannot participate in ACP's replacement-free object contract."""

        grafts = self._git_common_dir / "info" / "grafts"
        try:
            grafts.lstat()
        except FileNotFoundError:
            return
        except OSError as error:
            raise SupervisorError(
                "git_grafts_unreadable", "repository graft metadata could not be inspected"
            ) from error
        raise SupervisorError(
            "git_grafts_unsupported",
            "repository .git/info/grafts must be removed; ACP disables replacement objects",
        )

    def _disabled_git_hooks_dir(self) -> Path:
        hooks_dir = self.state_dir / "disabled-hooks"
        hooks_dir.mkdir(mode=0o700, exist_ok=True)
        opened = hooks_dir.stat()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
            or any(hooks_dir.iterdir())
        ):
            raise SupervisorError(
                "unsafe_git_hooks_directory",
                "the supervisor's disabled-hooks directory must be empty, current-user-owned 0700",
            )
        return hooks_dir

    @staticmethod
    def _supervisor_git_prefix(git: str, hooks_dir: Path) -> list[str]:
        return [
            git,
            "-c",
            f"core.hooksPath={hooks_dir}",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "commit.gpgSign=false",
            "-c",
            "merge.verifySignatures=false",
            "-c",
            "maintenance.auto=false",
            "-c",
            "gc.auto=0",
        ]

    def _supervisor_git_env(self) -> dict[str, str]:
        env = self._child_env()
        env.update(
            {
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_ATTR_NOSYSTEM": "1",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_TERMINAL_PROMPT": "0",
            }
        )
        return env
