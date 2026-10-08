"""Independent QC: reviewer policy and assurance, calibration, the QC run itself, and
the critic's evidence.

What stayed in git_supervisor, on purpose: `_run_critic` calls `run_trusted` (monkeypatched
on git_supervisor by tests), and `_command_finding` names `GitSupervisor.` explicitly.

Moved verbatim out of `git_supervisor` (board #1630). `GitSupervisor` inherits this mixin, so
every call site, CLI path and `GitSupervisor.<name>` lookup resolves exactly as before.
"""

from __future__ import annotations

import json
import os
import selectors
import sqlite3
import subprocess
import tempfile
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ..assurance import REJECT_VERDICTS, Assurance, Reviewer
from ..runner_identity import IdentityError, assert_distinct
from ..scheduling import declared_resources
from .acceptance import (
    ACCEPTANCE_COVERAGE_CONTRACT_VERSION,
    acceptance_criteria,
    validate_acceptance_coverage,
)
from .common import (
    EVIDENCE_STREAM_BUDGET,
    FORK_DENIED_EXIT_CODE,
    FORK_DENIED_SIGNATURE,
    SUBMISSION_OBJECT_CONTRACT,
    SupervisorError,
    canonical_json,
    sha256,
    utc_now,
)
from .runtime_targets import runtime_target_phase


class QcMixin:
    """Reviewer policy, submission assurance, calibration and QC runs."""

    @property
    def assurance(self) -> Assurance:
        return Assurance(self)

    def reviewers(self) -> dict[str, Any]:
        """Declared reviewers, the policy fingerprint, and whether it is ratified."""
        ratified = self.assurance.ratified_fingerprint()
        described = self.assurance_policy.describe()
        return {
            **described,
            "ratified_fingerprint": ratified,
            "ratified": ratified == described["fingerprint"],
        }

    def ratify_reviewers(
        self,
        integrator_id: str = "integration",
        credential: str | None = None,
    ) -> dict[str, Any]:
        """Accept the current evaluation policy under integrator authority.

        Ratification changes which reviewer evidence can release code, so it is
        a privileged transition rather than a read-only operator convenience.
        """
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._authenticate(integrator_id, "integrator", credential, connection)
            return self.assurance.ratify(integrator_id, connection)

    def _policy_reviewer(self, reviewer_id: str) -> Reviewer | None:
        reviewer = self.assurance_policy.reviewer(reviewer_id)
        if reviewer is not None:
            return reviewer
        if reviewer_id == self.config.critic_identity:
            return Reviewer(
                identity=reviewer_id,
                provider="unknown",
                model="unknown",
                prompt_policy="unset",
                command=self.config.critic_selector,
            )
        return None

    def _current_policy_passes(
        self,
        connection: sqlite3.Connection,
        submission: sqlite3.Row | dict[str, Any],
    ) -> list[dict[str, str]]:
        """Return unique passes made by the current declared reviewer versions."""
        attempt = connection.execute(
            "SELECT trust_bundle_json FROM attempts WHERE id = ?",
            (submission["attempt_id"],),
        ).fetchone()
        if not attempt:
            return []
        try:
            expected_trust_pin = json.loads(attempt["trust_bundle_json"] or "{}")
        except (json.JSONDecodeError, TypeError):
            return []
        rows = connection.execute(
            """
            SELECT reviewer_id, reviewer_provenance_json, trust_bundle_json FROM qc_runs
            WHERE submission_id = ? AND commit_sha = ? AND verdict = 'pass'
              AND policy_fingerprint = ?
            ORDER BY finished_at
            """,
            (
                submission["id"],
                submission["commit_sha"],
                self.assurance_policy.fingerprint,
            ),
        ).fetchall()
        passes: list[dict[str, str]] = []
        seen: set[str] = set()
        for row in rows:
            reviewer_id = row["reviewer_id"]
            reviewer = self._policy_reviewer(reviewer_id)
            if reviewer is None or reviewer_id in seen:
                continue
            try:
                provenance = json.loads(row["reviewer_provenance_json"] or "{}")
                review_trust_pin = json.loads(row["trust_bundle_json"] or "{}")
            except (json.JSONDecodeError, TypeError):
                continue
            if provenance != reviewer.provenance() or review_trust_pin != expected_trust_pin:
                continue
            passes.append({"reviewer_id": reviewer_id, "provider": reviewer.provider})
            seen.add(reviewer_id)
        return passes

    def _submission_assurance(
        self,
        connection: sqlite3.Connection,
        submission: sqlite3.Row | dict[str, Any],
    ) -> dict[str, Any]:
        current = self.assurance_policy.fingerprint
        ratified = self.assurance.ratified_fingerprint(connection)
        if ratified != current:
            return {
                "ready": False,
                "policy_fingerprint": current,
                "ratified_fingerprint": ratified,
                "passes": [],
                "blocker": "reviewer_policy_changed",
                "reason": "the current reviewer policy has not been ratified",
            }
        passes = self._current_policy_passes(connection, submission)
        if not passes:
            return {
                "ready": False,
                "policy_fingerprint": current,
                "ratified_fingerprint": ratified,
                "passes": [],
                "blocker": "qc_policy_stale",
                "reason": "no passing review matches this commit and current reviewer policy",
            }
        requirement = self.assurance.review_requirement(
            json.loads(submission["changed_paths_json"]), passes
        )
        if requirement["high_risk"] and not requirement["satisfied"]:
            return {
                "ready": False,
                "policy_fingerprint": current,
                "ratified_fingerprint": ratified,
                "passes": passes,
                "blocker": "qc_assurance_incomplete",
                "reason": requirement["reason"],
            }
        return {
            "ready": True,
            "policy_fingerprint": current,
            "ratified_fingerprint": ratified,
            "passes": passes,
            "blocker": None,
            "reason": "",
        }

    def _assert_submission_assurance(
        self,
        connection: sqlite3.Connection,
        submission: sqlite3.Row | dict[str, Any],
    ) -> dict[str, Any]:
        assurance = self._submission_assurance(connection, submission)
        if not assurance["ready"]:
            raise SupervisorError(assurance["blocker"], assurance["reason"])
        return assurance

    @staticmethod
    def _assert_submission_object_contract(
        submission: sqlite3.Row | dict[str, Any],
    ) -> None:
        if submission["object_contract"] != SUBMISSION_OBJECT_CONTRACT:
            raise SupervisorError(
                "submission_evidence_contract_stale",
                "submission predates the replacement-free object contract; resubmit and rerun QC",
            )

    def _invalidate_legacy_submissions(self) -> None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """
                SELECT submission.* FROM submissions AS submission
                JOIN tasks AS task ON task.id = submission.task_id
                WHERE submission.object_contract != ?
                  AND submission.status IN
                    ('pending_qc', 'qc_running', 'pending_second_review', 'approved',
                     'human_required')
                  AND task.status IN ('qc_review', 'approved', 'integrating')
                ORDER BY submission.created_at, submission.id
                """,
                (SUBMISSION_OBJECT_CONTRACT,),
            ).fetchall()
            for submission in rows:
                self._invalidate_legacy_submission_in(connection, submission, "migration")

    def _invalidate_legacy_submission_in(
        self,
        connection: sqlite3.Connection,
        submission: sqlite3.Row,
        actor: str,
    ) -> None:
        connection.execute(
            "UPDATE submissions SET status = 'changes_requested', qc_resume_status = '' "
            "WHERE id = ?",
            (submission["id"],),
        )
        task = self._task_row(connection, submission["task_id"])
        if task["status"] != "cleanup_pending":
            self._fence_task_cleanup(
                connection,
                submission["task_id"],
                submission["attempt_id"],
                "changes_requested",
                actor,
                "submission_object_contract_changed",
            )
        self._event(
            connection,
            "submission.object_contract_invalidated",
            actor,
            {
                "submission_id": submission["id"],
                "task_id": submission["task_id"],
                "old_contract": submission["object_contract"],
                "required_contract": SUBMISSION_OBJECT_CONTRACT,
            },
        )

    def calibrate(self, reviewer_id: str | None = None) -> dict[str, Any]:
        """Measure the reviewer against repository-specific golden cases.

        Each case is materialised in a detached worktree at HEAD, mutated to
        seed a known defect (or left clean), and handed to the *real* configured
        critic through the same entry point QC uses. Anything else would measure
        a simulation of the reviewer rather than the reviewer.
        """
        reviewer = self._calibration_reviewer(reviewer_id)
        self.assurance.assert_policy_ratified()
        cases = self.assurance.golden_cases()
        if not cases:
            raise SupervisorError(
                "no_golden_cases",
                f"no golden cases in {self.assurance_policy.golden_dir}/; "
                "add *.toml cases with an expected verdict",
            )
        head = self._git_text("rev-parse", "HEAD")
        results: list[dict[str, Any]] = []
        for case in cases:
            run_id = f"calibration-{uuid.uuid4()}"
            worktree = self.state_dir / "worktrees" / f"golden-{uuid.uuid4().hex}"
            packet_path = self.state_dir / "logs" / f"golden-{uuid.uuid4().hex}.json"
            result_path = self.state_dir / "logs" / f"golden-result-{uuid.uuid4().hex}.json"
            verdict = "block"
            error = ""
            touched: list[str] = []
            try:
                self._assert_safe_git_execution_config()
                self._git("worktree", "add", "--detach", str(worktree), head)
                touched = self.assurance.apply_mutations(worktree, case.mutations)
                packet = self._golden_packet(case, head, touched, worktree, run_id)
                packet_bytes = json.dumps(packet, indent=2).encode("utf-8")
                packet_hash = sha256(packet_bytes)
                packet_path.write_bytes(packet_bytes)
                with self._read_only_review_packet_fd(packet_bytes) as packet_fd:
                    critic = self._run_critic(
                        reviewer.command or "builtin",
                        worktree,
                        {
                            "ACP_PHASE": "calibration",
                            "ACP_WORKTREE": str(worktree),
                            "ACP_REPO_ROOT": str(self.root),
                            "ACP_REVIEW_PACKET_FD": str(packet_fd),
                            "ACP_REVIEW_PACKET_ARCHIVE": str(packet_path),
                            "ACP_REVIEW_RESULT": str(result_path),
                        },
                        review_packet_fd=packet_fd,
                    )
                if critic["exit_code"]:
                    error = f"critic exited {critic['exit_code']}"
                else:
                    packet_unchanged = (
                        not packet_path.is_symlink()
                        and packet_path.is_file()
                        and sha256(packet_path.read_bytes()) == packet_hash
                    )
                    if not packet_unchanged:
                        raise SupervisorError(
                            "critic_packet_tampered",
                            "critic changed the archived calibration packet",
                        )
                    verdict = self._critic_payload(result_path, packet)["verdict"]
            except (OSError, subprocess.SubprocessError, SupervisorError, ValueError) as failure:
                error = str(failure)
            finally:
                cleanup_errors: list[str] = []
                for artifact_path in (result_path, packet_path):
                    try:
                        self._cleanup_calibration_artifact(artifact_path)
                    except OSError as cleanup_failure:
                        cleanup_errors.append(
                            f"could not clean {artifact_path.name}: {cleanup_failure}"
                        )
                try:
                    if worktree.exists() or worktree.is_symlink():
                        if not self._remove_worktree(
                            worktree, delete_branch=False, expected_branch=None
                        ):
                            cleanup_errors.append("golden worktree cleanup could not be verified")
                except Exception as cleanup_failure:
                    cleanup_errors.append(f"golden worktree cleanup failed: {cleanup_failure}")
                if cleanup_errors:
                    error = "; ".join(filter(None, (error, *cleanup_errors)))
            results.append(
                {
                    "name": case.name,
                    "description": case.description,
                    "expected": case.expect,
                    "verdict": verdict,
                    "rejected": verdict in REJECT_VERDICTS,
                    "correct": not error and (verdict in REJECT_VERDICTS) == case.expects_rejection,
                    "mutated_paths": touched,
                    "error": error,
                }
            )
        summary = self.assurance.summarize(results)
        calibration_id = str(uuid.uuid4())
        created = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO calibration_runs
                  (id, policy_fingerprint, reviewer_id, results_json, summary_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    calibration_id,
                    self.assurance_policy.fingerprint,
                    reviewer.identity,
                    canonical_json(results),
                    canonical_json(summary),
                    created,
                ),
            )
            self._event(
                connection,
                "calibration.completed",
                reviewer.identity,
                {
                    "calibration_id": calibration_id,
                    "fingerprint": self.assurance_policy.fingerprint,
                    "summary": summary,
                },
            )
        return {
            "id": calibration_id,
            "reviewer": reviewer.provenance(),
            "policy_fingerprint": self.assurance_policy.fingerprint,
            "created_at": created,
            "results": results,
            "summary": summary,
        }

    def _calibration_reviewer(self, reviewer_id: str | None) -> Reviewer:
        if reviewer_id:
            reviewer = self.assurance_policy.reviewer(reviewer_id)
            if reviewer is None:
                raise SupervisorError(
                    "reviewer_identity_mismatch", f"{reviewer_id} is not a declared reviewer"
                )
            return reviewer
        if self.assurance_policy.reviewers:
            return self.assurance_policy.reviewers[0]
        return Reviewer(
            identity=self.config.critic_identity or "independent-qc",
            provider="unknown",
            model="unknown",
            prompt_policy="unset",
            command=self.config.critic_selector or "builtin",
        )

    def _golden_packet(
        self,
        case: Any,
        head: str,
        touched: list[str],
        worktree: Path,
        run_id: str,
    ) -> dict[str, Any]:
        """A review packet shaped exactly like a real one, for a synthetic candidate."""
        acceptance = ["the seeded repository state is judged correctly"]
        synthetic_diff = self._git_text("-C", str(worktree), "diff", "--binary", head).encode(
            "utf-8"
        )
        return {
            "run_id": run_id,
            "acceptance_coverage_contract_version": ACCEPTANCE_COVERAGE_CONTRACT_VERSION,
            "task": {
                "id": f"golden:{case.name}",
                "title": f"calibration case {case.name}",
                "description": case.description,
                "acceptance": acceptance,
                "acceptance_criteria": acceptance_criteria(acceptance),
                "declared_resources": sorted(touched),
                "base_sha": head,
            },
            "submission": {
                "id": f"golden:{case.name}",
                "commit_sha": head,
                "tree_sha": head,
                "patch_sha256": "",
                "changed_paths": sorted(touched),
                "commits": [],
                "diff_stat": "",
            },
            "deterministic_results": [],
            "evidence_catalog": [
                {
                    "id": f"{run_id}:synthetic-state",
                    "kind": "synthetic_calibration_state",
                    "run_id": run_id,
                    "commit_sha": head,
                    "sha256": sha256(synthetic_diff),
                }
            ],
            "policy": {
                "inspect_repository": True,
                "reproduce_acceptance": True,
                "worker_conclusions_excluded": True,
                "calibration": True,
            },
        }

    def reproduction_bundle(self, qc_id: str) -> dict[str, Any]:
        """The signed, deterministic bundle for one QC verdict."""
        return self.assurance.read_bundle(qc_id)

    def run_qc(
        self,
        submission_id: str,
        reviewer_id: str,
        credential: str | None = None,
    ) -> dict[str, Any]:
        # Authenticate before looking up the task whose operation lock must be
        # taken; this keeps submission identifiers from becoming an oracle.
        self._authenticate(reviewer_id, "critic", credential)
        self._assert_no_git_grafts()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            pending_submission = self._submission_row(connection, submission_id)
            try:
                self._assert_submission_object_contract(pending_submission)
            except SupervisorError:
                self._invalidate_legacy_submission_in(connection, pending_submission, reviewer_id)
                connection.commit()
                raise
        with self._task_operation_guard(pending_submission["task_id"]) as operation_guard_fd:
            try:
                return self._run_qc_locked(
                    submission_id,
                    reviewer_id,
                    credential,
                    operation_guard_fd,
                )
            except Exception:
                # A normal exception unwinds only after every contained child
                # has ended, so the same process can safely restore the exact
                # sequential-review state it claimed. Process death cannot run
                # this block; the durable qc_running state then goes through
                # the reaper's fenced crash-recovery path.
                with self.connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    current = self._submission_row(connection, submission_id)
                    current_task = self._task_row(connection, current["task_id"])
                    if (
                        current["status"] == "qc_running"
                        and current["qc_resume_status"] in {"pending_qc", "pending_second_review"}
                        and current_task["status"] == "qc_review"
                    ):
                        connection.execute(
                            "UPDATE submissions SET status = qc_resume_status, "
                            "qc_resume_status = '' WHERE id = ?",
                            (submission_id,),
                        )
                raise

    def _run_qc_locked(
        self,
        submission_id: str,
        reviewer_id: str,
        credential: str | None,
        operation_guard_fd: int,
    ) -> dict[str, Any]:
        # Prove the reviewer holds the critic credential before anything else.
        # Until this existed, "independent QC" was a string a worker could type.
        reviewer_identity = self._authenticate(reviewer_id, "critic", credential)
        reviewer_digest = reviewer_identity["credential_digest"] if reviewer_identity else None
        with self.connect() as connection:
            pending_submission = self._submission_row(connection, submission_id)
        trust_pin = self._verify_attempt_trust(pending_submission["attempt_id"])
        reviewer = self.assurance_policy.reviewer(reviewer_id)
        if reviewer is None:
            if reviewer_id != self.config.critic_identity:
                raise SupervisorError(
                    "reviewer_identity_mismatch",
                    f"reviewer must be a declared reviewer or {self.config.critic_identity}",
                )
            reviewer = Reviewer(
                identity=reviewer_id,
                provider="unknown",
                model="unknown",
                prompt_policy="unset",
                command=self.config.critic_selector,
            )
        # A reviewer upgrade must be ratified before it can judge anything.
        self.assurance.assert_policy_ratified()
        started = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._authenticate(reviewer_id, "critic", credential, connection)
            submission = self._submission_row(connection, submission_id)
            self._assert_submission_object_contract(submission)
            task = self._task_row(connection, submission["task_id"])
            if (
                submission["status"] not in {"pending_qc", "pending_second_review"}
                or task["status"] != "qc_review"
            ):
                raise SupervisorError("submission_not_reviewable", "submission is not pending QC")
            try:
                assert_distinct(submission["worker_agent_id"], reviewer_id)
            except IdentityError as error:
                raise SupervisorError(error.code, error.message) from error
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
            operation_until = int(time.time()) + max(
                3600,
                self.config.timeout_seconds * (len(self.config.qc_commands) + 2) * 2,
            )
            connection.execute(
                "UPDATE submissions SET status = 'qc_running', qc_resume_status = ? WHERE id = ?",
                (submission["status"], submission_id),
            )
            connection.execute(
                "UPDATE resource_leases SET lease_expires_at = ?, updated_at = ? WHERE task_id = ?",
                (operation_until, utc_now(), task["id"]),
            )
            connection.execute(
                "UPDATE runtime_allocations SET lease_expires_at = ?, updated_at = ? "
                "WHERE attempt_id = ?",
                (operation_until, utc_now(), submission["attempt_id"]),
            )

        qc_id = str(uuid.uuid4())
        qc_dir = self.state_dir / "worktrees" / f"qc-{uuid.uuid4().hex}"
        packet_path = self.state_dir / "logs" / f"review-{submission_id}-{qc_id}.json"
        results: list[dict[str, Any]] = []
        findings: list[dict[str, str]] = []
        acceptance_coverage: list[dict[str, Any]] = []
        critic_verdict = "pass"
        packet: dict[str, Any] | None = None
        packet_hash = sha256(b"")
        try:
            self._assert_safe_git_execution_config()
            self._git("worktree", "add", "--detach", str(qc_dir), submission["commit_sha"])
            packet = self._review_packet(task, submission, qc_dir, qc_id)
            packet_path.write_text(json.dumps(packet, indent=2), encoding="utf-8")
            packet_hash = sha256(packet_path.read_bytes())
            # Fresh services before review. Otherwise QC can pass against an app
            # server the worker left running, which proves the worker's old code
            # works, not the code being reviewed.
            if self.config.runtime_drivers:
                try:
                    phase_targets = tuple(
                        target for target in self.config.runtime_targets if "qc" in target.phases
                    )
                    phase_context = None
                    if phase_targets:
                        if not self._worktree_matches(qc_dir, submission["commit_sha"]):
                            raise SupervisorError(
                                "runtime_target_source_mismatch",
                                "QC target checkout is not the submitted source revision",
                            )
                        with self.connect() as connection:
                            attempt = connection.execute(
                                "SELECT task_id, claim_token FROM attempts WHERE id = ?",
                                (submission["attempt_id"],),
                            ).fetchone()
                        if not attempt or str(attempt["task_id"]) != str(submission["task_id"]):
                            raise SupervisorError(
                                "runtime_target_claim_stale", "QC target claim is no longer current"
                            )
                        phase_context = {
                            "ACP_PHASE": "qc",
                            "ACP_WORKTREE": str(qc_dir),
                            "ACP_SOURCE_REVISION": str(submission["commit_sha"]),
                            "ACP_CLAIM_TOKEN": str(attempt["claim_token"]),
                            "ACP_TASK_ID": str(submission["task_id"]),
                        }
                    self._runtime_restart_in_operation(
                        submission["attempt_id"],
                        operation_guard_fd,
                        phase_context=phase_context,
                    )
                except SupervisorError as error:
                    findings.append(
                        {
                            "severity": "high",
                            "requirement": "review runs against freshly started services",
                            "finding": f"runtime restart before QC failed: {error.code}",
                            "evidence": error.message,
                            "required_fix": (
                                "resolve the runtime cleanup/startup failure; a review against a "
                                "stale or unproven runtime is not evidence"
                            ),
                        }
                    )
                    raise
                else:
                    runtime_env = self._runtime_env(submission["attempt_id"], require_ready=False)
                    if phase_targets:
                        fence_sha = sha256(str(submission["resource_tokens_json"]).encode("utf-8"))
                        receipt, target_env, blocked = runtime_target_phase(
                            definitions=phase_targets,
                            runtime_environment=runtime_env,
                            driver_resources=self.driver_resources(submission["attempt_id"]),
                            attempt_id=str(submission["attempt_id"]),
                            task_id=str(submission["task_id"]),
                            claim_token=int(attempt["claim_token"]),
                            reservation_fence_sha256=fence_sha,
                            phase="qc",
                            source_revision=str(submission["commit_sha"]),
                            runtime_dir=Path(runtime_env["ACP_RUNTIME_DIR"]),
                            receipt_id=qc_id,
                        )
                        results.append(receipt)
                        packet["runtime_target_preflight"] = receipt
                        packet["evidence_catalog"].append(
                            {
                                "id": receipt["evidence_id"],
                                "kind": "runtime_target_preflight",
                                "run_id": qc_id,
                                "commit_sha": submission["commit_sha"],
                                "sha256": receipt["evidence_sha256"],
                                "exit_code": receipt["exit_code"],
                            }
                        )
                        packet_path.write_text(json.dumps(packet, indent=2), encoding="utf-8")
                        packet_hash = sha256(packet_path.read_bytes())
                        if blocked:
                            raise SupervisorError(
                                "runtime_target_identity_mismatch",
                                "required QC runtime target identity is missing or mismatched",
                            )
                        runtime_env.update(phase_context or {})
                        runtime_env.update(target_env)
            for index, command in enumerate(self.config.qc_commands, start=1):
                self._restore_candidate(qc_dir, submission["commit_sha"])
                result = self._run_command(
                    command,
                    qc_dir,
                    self._phase_runtime_env(runtime_env, "qc", qc_dir),
                    pass_fds=(operation_guard_fd,),
                )
                evidence_id = f"{qc_id}:command:{index:03d}"
                result["evidence_id"] = evidence_id
                result["evidence_sha256"] = sha256(
                    canonical_json(
                        {key: value for key, value in result.items() if key != "evidence_sha256"}
                    ).encode("utf-8")
                )
                results.append(result)
                packet["evidence_catalog"].append(
                    {
                        "id": evidence_id,
                        "kind": "deterministic_command_result",
                        "run_id": qc_id,
                        "commit_sha": submission["commit_sha"],
                        "sha256": result["evidence_sha256"],
                        "command": command,
                        "exit_code": result["exit_code"],
                    }
                )
                if result["exit_code"]:
                    findings.append(self._command_finding(command, result))
                elif not self._worktree_matches(qc_dir, submission["commit_sha"]):
                    findings.append(
                        {
                            "severity": "high",
                            "requirement": "QC observes the submitted commit",
                            "finding": f"command mutated the candidate: {command}",
                            "evidence": "HEAD, index, or tracked files changed during QC",
                            "required_fix": "make the command read-only for tracked source",
                        }
                    )
            packet["deterministic_results"] = results
            packet_path.write_text(json.dumps(packet, indent=2), encoding="utf-8")
            packet_bytes = packet_path.read_bytes()
            packet_hash = sha256(packet_bytes)
            if reviewer.command:
                self._restore_candidate(qc_dir, submission["commit_sha"])
                if reviewer.command.startswith("trusted:"):
                    trust_pin = self._verify_attempt_trust(submission["attempt_id"])
                result_path = self.state_dir / "logs" / f"critic-{submission_id}-{qc_id}.json"
                with self._read_only_review_packet_fd(packet_bytes) as packet_fd:
                    critic = self._run_critic(
                        reviewer.command,
                        qc_dir,
                        self._phase_runtime_env(runtime_env, "critic", qc_dir)
                        | {
                            "ACP_REVIEW_PACKET_FD": str(packet_fd),
                            "ACP_REVIEW_PACKET_ARCHIVE": str(packet_path),
                            "ACP_REVIEW_RESULT": str(result_path),
                        },
                        trust_pin,
                        pass_fds=(operation_guard_fd,),
                        review_packet_fd=packet_fd,
                    )
                results.append(critic)
                try:
                    packet_is_unchanged = (
                        not packet_path.is_symlink()
                        and packet_path.is_file()
                        and sha256(packet_path.read_bytes()) == packet_hash
                    )
                except OSError:
                    packet_is_unchanged = False
                if not packet_is_unchanged:
                    self._restore_review_packet(packet_path, packet_bytes)
                    acceptance_coverage = self._unassessed_coverage(
                        packet, "The critic changed the server-generated review packet."
                    )
                    findings.append(
                        {
                            "severity": "high",
                            "requirement": "the signed review packet matches the packet evaluated by QC",
                            "finding": "independent critic modified or removed its review packet",
                            "evidence": f"expected packet sha256 {packet_hash}",
                            "required_fix": "use a reviewer that reads but does not modify the review packet",
                        }
                    )
                    critic_verdict = "block"
                elif critic["exit_code"] or not self._worktree_matches(
                    qc_dir, submission["commit_sha"]
                ):
                    findings.append(self._command_finding("independent critic", critic))
                    critic_verdict = "block"
                else:
                    try:
                        payload = self._critic_payload(result_path, packet)
                    finally:
                        result_path.unlink(missing_ok=True)
                    critic_verdict = payload["verdict"]
                    acceptance_coverage = payload["acceptance_coverage"]
                    findings.extend(payload["findings"])
            elif self.config.require_critic:
                acceptance_coverage = self._unassessed_coverage(
                    packet, "No independent critic is configured for this QC run."
                )
                findings.append(
                    {
                        "severity": "high",
                        "requirement": "independent critic is mandatory",
                        "finding": "require_critic is true but critic_command is empty",
                        "evidence": "acp.toml policy evaluation",
                        "required_fix": "configure a structured critic command",
                    }
                )
                critic_verdict = "block"
            else:
                acceptance_coverage = self._unassessed_coverage(
                    packet, "No independent critic is configured for this QC run."
                )
                findings.append(
                    {
                        "severity": "low",
                        "requirement": "every acceptance criterion receives independent QC",
                        "finding": "acceptance criteria were not assessed by an independent critic",
                        "evidence": "; ".join(item["criterion_id"] for item in acceptance_coverage),
                        "required_fix": "configure an independent reviewer or obtain explicit human review",
                    }
                )
                critic_verdict = "human_required"
        except (OSError, subprocess.SubprocessError, SupervisorError, ValueError) as error:
            critic_verdict = "block"
            if packet is not None and not acceptance_coverage:
                acceptance_coverage = self._unassessed_coverage(
                    packet, "QC did not produce a valid per-criterion reviewer result."
                )
            findings.append(
                {
                    "severity": "high",
                    "requirement": "QC execution is trustworthy",
                    "finding": "QC execution failed",
                    "evidence": str(error),
                    "required_fix": "repair QC and rerun it on the immutable commit",
                }
            )
        finally:
            if qc_dir.exists():
                self._remove_worktree(qc_dir, delete_branch=False, expected_branch=None)

        serious = {"critical", "high", "medium"}
        if any(result["exit_code"] for result in results):
            verdict = "block"
        elif critic_verdict == "block":
            verdict = "block"
        elif any(item.get("severity") in serious for item in findings):
            verdict = "revise"
        else:
            verdict = critic_verdict
        if verdict not in {"pass", "revise", "block", "human_required"}:
            verdict = "block"
            findings.append(
                {
                    "severity": "high",
                    "requirement": "critic output follows the contract",
                    "finding": "critic returned an unsupported verdict",
                    "evidence": str(critic_verdict),
                    "required_fix": "emit pass, revise, block, or human_required",
                }
            )
        finished = utc_now()
        bundle = self.assurance.bundle(
            qc_id,
            dict(submission),
            task["base_sha"],
            [*self.config.qc_commands, *([reviewer.command] if reviewer.command else [])],
            reviewer,
            verdict,
            packet_hash,
            acceptance_coverage,
            ACCEPTANCE_COVERAGE_CONTRACT_VERSION,
        )
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._reauthenticate_bound(
                connection,
                reviewer_id,
                "critic",
                credential,
                reviewer_digest,
            )
            try:
                trust_pin = self._verify_attempt_trust_in(connection, submission["attempt_id"])
            except SupervisorError:
                # Preserve the quarantine even though this verdict must not be
                # recorded. The context manager's later rollback is then a no-op.
                connection.commit()
                raise
            if self.assurance.ratified_fingerprint(connection) != self.assurance_policy.fingerprint:
                raise SupervisorError(
                    "reviewer_policy_changed",
                    "reviewer policy changed while QC was running; discard this verdict and rerun",
                )
            current = self._submission_row(connection, submission_id)
            current_task = self._task_row(connection, current["task_id"])
            if (
                current["status"] != "qc_running"
                or current["qc_resume_status"] not in {"pending_qc", "pending_second_review"}
                or current_task["status"] != "qc_review"
            ):
                raise SupervisorError("submission_not_reviewable", "submission changed during QC")
            self._assert_reservations(connection, current_task, current)
            connection.execute(
                """
                INSERT INTO qc_runs
                  (id, submission_id, reviewer_id, commit_sha, verdict,
                   findings_json, results_json, packet_sha256,
                   reviewer_provenance_json, reviewer_signature, bundle_sha256,
                   policy_fingerprint, trust_bundle_json, acceptance_coverage_json,
                   acceptance_coverage_contract_version, started_at, finished_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    qc_id,
                    submission_id,
                    reviewer_id,
                    current["commit_sha"],
                    verdict,
                    canonical_json(findings),
                    canonical_json(results),
                    packet_hash,
                    canonical_json(reviewer.provenance()),
                    bundle["record"]["signature"],
                    bundle["sha256"],
                    self.assurance_policy.fingerprint,
                    canonical_json(trust_pin),
                    canonical_json(acceptance_coverage),
                    ACCEPTANCE_COVERAGE_CONTRACT_VERSION,
                    started,
                    finished,
                ),
            )
            passing = self._current_policy_passes(connection, current)
            requirement = self.assurance.review_requirement(
                json.loads(current["changed_paths_json"]), passing
            )
            submission_status = {
                "pass": "approved",
                "revise": "changes_requested",
                "block": "blocked",
                "human_required": "human_required",
            }[verdict]
            task_status = (
                "approved"
                if verdict == "pass"
                else "changes_requested"
                if verdict == "revise"
                else "blocked"
            )
            if verdict == "pass" and requirement["high_risk"] and not requirement["satisfied"]:
                # A passing verdict is not an approval while policy still owes a
                # second reviewer, a second provider, or a human.
                findings = [
                    *findings,
                    {
                        "severity": "low",
                        "requirement": "high-risk paths satisfy the reviewer policy",
                        "finding": requirement["reason"],
                        "evidence": ", ".join(requirement["paths"][:20]),
                        "required_fix": "obtain the additional review the policy requires",
                    },
                ]
                if self.assurance_policy.high_risk_mode == "human":
                    submission_status, task_status = "human_required", "blocked"
                else:
                    submission_status, task_status = "pending_second_review", "qc_review"
                connection.execute(
                    "UPDATE qc_runs SET findings_json = ? WHERE id = ?",
                    (canonical_json(findings), qc_id),
                )
            connection.execute(
                "UPDATE submissions SET status = ?, qc_resume_status = '' WHERE id = ?",
                (submission_status, submission_id),
            )
            cleanup_required = not (verdict == "pass" and submission_status != "human_required")
            if not cleanup_required:
                connection.execute(
                    "UPDATE tasks SET status = ?, cleanup_target_status = '', "
                    "cleanup_error = '', updated_at = ? WHERE id = ?",
                    (task_status, finished, current_task["id"]),
                )
                reserve_until = int(time.time()) + max(3600, self.config.timeout_seconds * 3)
                connection.execute(
                    """
                    UPDATE resource_leases SET lease_expires_at = ?, updated_at = ?
                    WHERE task_id = ?
                    """,
                    (
                        reserve_until,
                        finished,
                        current_task["id"],
                    ),
                )
                connection.execute(
                    """
                    UPDATE runtime_allocations SET lease_expires_at = ?, updated_at = ?
                    WHERE attempt_id = ?
                    """,
                    (reserve_until, finished, current["attempt_id"]),
                )
            else:
                self._fence_task_cleanup(
                    connection,
                    current_task["id"],
                    current["attempt_id"],
                    task_status,
                    reviewer_id,
                    "qc_completed_without_approval",
                )
            self._event(
                connection,
                "qc.completed",
                reviewer_id,
                {
                    "qc_id": qc_id,
                    "submission_id": submission_id,
                    "verdict": verdict,
                    "finding_count": len(findings),
                },
            )
        result = self.qc_run(qc_id)
        if cleanup_required:
            try:
                result["runtime_cleanup"] = self.runtime_down(submission["attempt_id"])
            except (OSError, subprocess.SubprocessError, SupervisorError) as cleanup_error:
                result["runtime_cleanup"] = {
                    "attempt_id": submission["attempt_id"],
                    "state": "cleanup_error",
                    "error": str(cleanup_error),
                }
                with self.connect() as connection:
                    connection.execute(
                        "UPDATE tasks SET cleanup_error = ?, updated_at = ? "
                        "WHERE id = ? AND status = 'cleanup_pending'",
                        (str(cleanup_error), utc_now(), task["id"]),
                    )
            if result["runtime_cleanup"]["state"] == "released":
                with self.connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    self._complete_task_cleanup(
                        connection,
                        task["id"],
                        submission["attempt_id"],
                        reviewer_id,
                    )
        return result

    def qc_run(self, qc_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM qc_runs WHERE id = ?", (qc_id,)).fetchone()
            if not row:
                raise SupervisorError("qc_not_found", f"QC run {qc_id} not found")
            return self._qc_view(row)

    def _review_packet(
        self,
        task: sqlite3.Row,
        submission: sqlite3.Row,
        worktree: Path,
        qc_id: str,
    ) -> dict[str, Any]:
        diff_stat = self._git_text(
            "-C",
            str(worktree),
            "diff",
            "--stat",
            task["base_sha"],
            submission["commit_sha"],
        )
        commits = self._git_text(
            "-C",
            str(worktree),
            "log",
            "--format=%H %s",
            f"{task['base_sha']}..{submission['commit_sha']}",
        )
        changed_paths = json.loads(submission["changed_paths_json"])
        catalog: list[dict[str, Any]] = [
            {
                "id": f"{qc_id}:diff",
                "kind": "candidate_diff",
                "run_id": qc_id,
                "commit_sha": submission["commit_sha"],
                "sha256": submission["patch_sha256"],
            }
        ]

        def tree_entry(revision: str, path: str) -> tuple[str, str, str] | None:
            raw = self._git_bytes(
                "-C",
                str(worktree),
                "ls-tree",
                "-r",
                "-z",
                "--full-tree",
                revision,
                "--",
                f":(literal){path}",
            )
            target = path.encode("utf-8")
            for entry in raw.split(b"\0"):
                if not entry:
                    continue
                metadata, separator, entry_path = entry.partition(b"\t")
                if not separator or entry_path != target:
                    continue
                fields = metadata.decode("ascii").split(" ", 2)
                if len(fields) != 3:
                    raise SupervisorError(
                        "invalid_git_tree_entry", "Git returned a malformed tree entry"
                    )
                return fields[0], fields[1], fields[2]
            return None

        for index, path in enumerate(changed_paths, start=1):
            submitted_entry = tree_entry(submission["commit_sha"], path)
            if submitted_entry is not None:
                mode, object_type, object_id = submitted_entry
                catalog.append(
                    {
                        "id": f"{qc_id}:file:{index:03d}",
                        "kind": "submitted_file",
                        "run_id": qc_id,
                        "commit_sha": submission["commit_sha"],
                        "path": path,
                        "git_object_mode": mode,
                        "git_object_type": object_type,
                        "git_object_oid": object_id,
                    }
                )
                continue

            base_entry = tree_entry(task["base_sha"], path)
            if base_entry is None:
                raise SupervisorError(
                    "invalid_submission_path",
                    f"changed path has no exact entry in either commit: {path}",
                )
            mode, object_type, object_id = base_entry
            deletion = {
                "commit_sha": submission["commit_sha"],
                "path": path,
                "previous_mode": mode,
                "previous_object_type": object_type,
                "previous_object_oid": object_id,
                "state": "absent_from_submitted_commit",
            }
            catalog.append(
                {
                    "id": f"{qc_id}:deletion:{index:03d}",
                    "kind": "deleted_path",
                    "run_id": qc_id,
                    "commit_sha": submission["commit_sha"],
                    "path": path,
                    "previous_git_object_mode": mode,
                    "previous_git_object_type": object_type,
                    "previous_git_object_oid": object_id,
                    "sha256": sha256(canonical_json(deletion).encode("utf-8")),
                }
            )
        acceptance = json.loads(task["acceptance_json"])
        return {
            "run_id": qc_id,
            "acceptance_coverage_contract_version": ACCEPTANCE_COVERAGE_CONTRACT_VERSION,
            "task": {
                "id": task["id"],
                "title": task["title"],
                "description": task["description"],
                "acceptance": acceptance,
                "acceptance_criteria": acceptance_criteria(acceptance),
                # 🔴 #1764: this field is NAMED declared_resources and held the FOLDED set
                # (pre-existing, blame 8139c743). After #1708 the same name in _task_view
                # carries the true declared case, so a reviewer reading a QC packet saw
                # `declared_resources: ["makefile"]` for a task that declared `Makefile` —
                # two fields, one name, opposite meanings. A wrong field NAME is worse than
                # a missing one, so this now holds what it says it holds.
                "declared_resources": declared_resources(task),
                "resources": json.loads(task["resources_json"]),
                "base_sha": task["base_sha"],
            },
            "submission": {
                "id": submission["id"],
                "commit_sha": submission["commit_sha"],
                "tree_sha": submission["tree_sha"],
                "patch_sha256": submission["patch_sha256"],
                "changed_paths": changed_paths,
                "commits": commits.splitlines(),
                "diff_stat": diff_stat,
            },
            "policy": {
                "inspect_repository": True,
                "reproduce_acceptance": True,
                "worker_conclusions_excluded": True,
            },
            "evidence_catalog": catalog,
        }

    @staticmethod
    def _unassessed_coverage(packet: dict[str, Any], reason: str) -> list[dict[str, Any]]:
        """Represent a missing/failed independent review explicitly, never as pass."""
        criteria = packet.get("task", {}).get("acceptance_criteria", [])
        catalog = packet.get("evidence_catalog", [])
        references = [catalog[0]["id"]] if catalog else []
        return [
            {
                "criterion_id": item["id"],
                "criterion": item["text"],
                "status": "unknown",
                "rationale": reason,
                "evidence_refs": references,
            }
            for item in criteria
        ]

    @staticmethod
    def _restore_review_packet(path: Path, packet_bytes: bytes) -> None:
        """Replace reviewer-modified packet bytes without following a planted symlink."""
        temporary_path: Path | None = None
        try:
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
            )
            temporary_path = Path(temporary)
            with os.fdopen(descriptor, "wb") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(packet_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            if path.is_dir() and not path.is_symlink():
                substituted_directory = path.with_name(f"{path.name}.tampered-{uuid.uuid4().hex}")
                os.replace(path, substituted_directory)
            os.replace(temporary_path, path)
            temporary_path = None
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    @staticmethod
    @contextmanager
    def _read_only_review_packet_fd(packet_bytes: bytes) -> Iterator[int]:
        """Stream immutable packet bytes to the reviewer through a read-only pipe FD."""
        packet_fd, writer_fd = os.pipe()
        cancelled = threading.Event()
        written = 0
        write_error: OSError | None = None

        def feed_packet() -> None:
            nonlocal write_error, written
            remaining = memoryview(packet_bytes)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(writer_fd, selectors.EVENT_WRITE)
                    while remaining and not cancelled.is_set():
                        try:
                            count = os.write(writer_fd, remaining)
                        except BlockingIOError:
                            selector.select(timeout=0.1)
                            continue
                        except InterruptedError:
                            continue
                        if count <= 0:
                            raise OSError("review packet pipe accepted no bytes")
                        remaining = remaining[count:]
                        written += count
                    if remaining and not cancelled.is_set():
                        raise OSError("review packet pipe closed before delivery completed")
            except (OSError, ValueError) as error:
                write_error = (
                    error
                    if isinstance(error, OSError)
                    else OSError("review packet selector failed")
                )
            finally:
                os.close(writer_fd)

        feeder = threading.Thread(target=feed_packet, name="acp-review-packet", daemon=True)
        try:
            os.set_blocking(writer_fd, False)
            feeder.start()
        except BaseException:
            os.close(packet_fd)
            os.close(writer_fd)
            raise
        body_failed = False
        try:
            yield packet_fd
        except BaseException:
            body_failed = True
            raise
        finally:
            os.close(packet_fd)
            cancelled.set()
            feeder.join(timeout=2)
            if feeder.is_alive():
                raise SupervisorError(
                    "review_packet_stream_stalled",
                    "review packet feeder did not stop after the critic exited",
                )
            if not body_failed and (written != len(packet_bytes) or write_error is not None):
                raise SupervisorError(
                    "review_packet_delivery_failed",
                    "critic did not receive the complete frozen review packet",
                ) from write_error

    @staticmethod
    def _cleanup_calibration_artifact(path: Path) -> None:
        """Remove reviewer files, but quarantine substituted directories intact."""
        if path.is_dir() and not path.is_symlink():
            quarantine = path.with_name(f"{path.name}.tampered-{uuid.uuid4().hex}")
            os.replace(path, quarantine)
        elif path.is_symlink():
            path.unlink()
        else:
            path.unlink(missing_ok=True)

    @staticmethod
    def _evidence_window(text: str, budget: int = EVIDENCE_STREAM_BUDGET) -> str:
        """Keep both ends of a long output and say what was dropped.

        A plain tail loses the first failure's traceback; a plain head loses the summary
        a test runner prints last. A reviewer reads both, so neither end is the one to
        throw away, and the gap is marked rather than left as a silent cut that reads
        like the output simply ended there.
        """

        stripped = text.strip()
        if len(stripped) <= budget:
            return stripped
        head = budget // 3
        tail = budget - head
        omitted = len(stripped) - head - tail
        return f"{stripped[:head]}\n… {omitted} characters omitted …\n{stripped[-tail:]}"

    @staticmethod
    def _is_fork_denial(result: dict[str, Any]) -> bool:
        """Did the containment refuse this command a subprocess, rather than the command failing?

        Both halves are required. Measured on Darwin under this repository's own
        profile: a denied fork exits 128 with `fork: Operation not permitted`, while a
        missing binary exits 127 with `No such file or directory` and fork fully
        available — so the exit code alone would call an ordinary broken command a
        platform problem, which is the same misattribution in the other direction.
        """

        return result.get("exit_code") == FORK_DENIED_EXIT_CODE and FORK_DENIED_SIGNATURE in (
            result.get("stderr") or ""
        )

    @staticmethod
    def _critic_payload(path: Path, packet: dict[str, Any]) -> dict[str, Any]:
        if not path.is_file():
            raise SupervisorError(
                "invalid_critic_output",
                "critic did not create its unique result file",
            )
        raw = path.read_text(encoding="utf-8")
        payload = json.loads(raw)
        verdicts = {"pass", "revise", "block", "human_required"}
        if not isinstance(payload, dict) or payload.get("verdict") not in verdicts:
            raise SupervisorError("invalid_critic_output", "critic verdict is invalid")
        if payload.get("contract_version") != ACCEPTANCE_COVERAGE_CONTRACT_VERSION:
            raise SupervisorError(
                "invalid_critic_output",
                "critic must use acceptance-coverage contract version 2",
            )
        findings = payload.get("findings", [])
        required = {
            "severity",
            "requirement",
            "finding",
            "evidence",
            "required_fix",
        }
        severities = {"critical", "high", "medium", "low", "info"}
        if not isinstance(findings, list):
            raise SupervisorError("invalid_critic_output", "critic findings must be a list")
        for finding in findings:
            if (
                not isinstance(finding, dict)
                or not required.issubset(finding)
                or finding.get("severity") not in severities
            ):
                raise SupervisorError("invalid_critic_output", "critic finding is invalid")
        try:
            coverage = validate_acceptance_coverage(
                payload.get("acceptance_coverage"),
                packet["task"]["acceptance_criteria"],
                packet["evidence_catalog"],
                run_id=packet["run_id"],
                commit_sha=packet["submission"]["commit_sha"],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise SupervisorError("invalid_critic_output", str(error)) from error

        coverage_findings: list[dict[str, str]] = []
        for item in coverage:
            if item["status"] == "pass":
                continue
            revise = item["status"] == "revise"
            coverage_findings.append(
                {
                    "severity": "high" if revise else "low",
                    "requirement": f"acceptance criterion {item['criterion_id']} is independently assessed",
                    "finding": f"criterion disposition is {item['status']}: {item['criterion']}",
                    "evidence": (f"refs={', '.join(item['evidence_refs'])}; {item['rationale']}"),
                    "required_fix": (
                        "address the criterion and rerun QC"
                        if revise
                        else "obtain the independent or human evidence needed to resolve this criterion"
                    ),
                }
            )
        findings = [*findings, *coverage_findings]
        verdict = payload["verdict"]
        if verdict == "pass":
            if any(item["status"] == "revise" for item in coverage):
                verdict = "revise"
            elif any(item["status"] != "pass" for item in coverage):
                verdict = "human_required"
        if verdict in {"revise", "block"} and not findings:
            raise SupervisorError("invalid_critic_output", "negative verdict requires findings")
        return {
            "verdict": verdict,
            "findings": findings,
            "acceptance_coverage": coverage,
        }
