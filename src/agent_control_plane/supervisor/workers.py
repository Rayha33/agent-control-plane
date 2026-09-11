"""Launching, registering and terminating long-running worker processes.

What stayed in git_supervisor, on purpose: `_terminate_registered_group` and
`_open_registered_pidfd` call through `GitSupervisor.` by name, and tests monkeypatch
`_open_registered_pidfd` and `_process_identity` on the GitSupervisor class.

Moved verbatim out of `git_supervisor` (board #1630). `GitSupervisor` inherits this mixin, so
every call site, CLI path and `GitSupervisor.<name>` lookup resolves exactly as before.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ..worker_trampoline import LIFECYCLE_FDS_PREFIX, MONITOR_MODE
from .common import SupervisorError, utc_now


class WorkersMixin:
    """Worker launch reservation, registration, exit recording and termination."""

    def run_worker(
        self,
        attempt_id: str,
        claim_token: int,
        command: Sequence[str],
        credential: str | None = None,
    ) -> dict[str, Any]:
        if not command:
            raise SupervisorError("invalid_command", "worker command is required")
        attempt = self.heartbeat(
            attempt_id,
            claim_token,
            {"phase": "launching", "command": list(command)},
            credential=credential,
        )
        if not sys.platform.startswith("linux"):
            raise SupervisorError(
                "process_containment_unavailable",
                "long-running workers require Linux child-subreaper containment",
            )
        worker_env = self._child_env(
            self._phase_runtime_env(
                self._runtime_env(attempt_id), "worker", Path(attempt["worktree"])
            )
        )
        log_path = self.state_dir / "logs" / f"worker-{attempt_id}.log"
        with log_path.open("ab") as log:
            process: subprocess.Popen[bytes] | None = None
            handshake_read = -1
            handshake_write = -1
            launch_reserved = False
            try:
                handshake_read, handshake_write = os.pipe()
                self._reserve_worker_launch(attempt_id, claim_token, str(log_path), credential)
                launch_reserved = True
                trampoline = Path(__file__).parent.with_name("worker_trampoline.py").resolve()
                process = subprocess.Popen(
                    [
                        sys.executable,
                        "-I",
                        str(trampoline),
                        str(handshake_read),
                        "-1",
                        "-1",
                        MONITOR_MODE,
                        LIFECYCLE_FDS_PREFIX,
                        *command,
                    ],
                    cwd=attempt["worktree"],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                    pass_fds=(handshake_read,),
                    env=worker_env,
                )
                process_identity = self._process_identity(process.pid)
                if process_identity is None:
                    raise SupervisorError(
                        "worker_identity_unavailable",
                        "worker kernel identity could not be recorded",
                    )
                os.close(handshake_read)
                handshake_read = -1
                launch_fenced = False
                with self.connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    registered = connection.execute(
                        "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
                    ).fetchone()
                    if not registered:
                        raise SupervisorError(
                            "attempt_not_found", f"attempt {attempt_id} not found"
                        )
                    self._authenticate_attempt(connection, registered, credential)
                    if registered["claim_token"] != claim_token:
                        raise SupervisorError("stale_fencing_token", "claim token is stale")
                    if registered["status"] != "working" and registered["pid"] == -1:
                        target_status = (
                            registered["termination_target_status"] or registered["status"]
                        )
                        changed = connection.execute(
                            "UPDATE attempts SET status = 'terminating', "
                            "termination_target_status = ?, pid = ?, pid_identity = ?, "
                            "launch_owner_pid = NULL, launch_owner_identity = '', "
                            "log_path = ?, updated_at = ? WHERE id = ? AND status = ? AND pid = -1",
                            (
                                target_status,
                                process.pid,
                                process_identity,
                                str(log_path),
                                utc_now(),
                                attempt_id,
                                registered["status"],
                            ),
                        ).rowcount
                        if changed != 1:
                            raise SupervisorError(
                                "worker_registration_lost",
                                "terminated worker launch reservation changed",
                            )
                        launch_fenced = True
                        self._event(
                            connection,
                            "worker.launch_fenced",
                            registered["agent_id"],
                            {"attempt_id": attempt_id, "pid": process.pid},
                        )
                    else:
                        active = self._active_attempt(
                            connection, attempt_id, claim_token, int(time.time())
                        )
                        changed = connection.execute(
                            """
                            UPDATE attempts SET pid = ?, pid_identity = ?, log_path = ?,
                              launch_owner_pid = NULL, launch_owner_identity = '', updated_at = ?
                            WHERE id = ? AND status = 'working' AND pid = -1
                            """,
                            (
                                process.pid,
                                process_identity,
                                str(log_path),
                                utc_now(),
                                attempt_id,
                            ),
                        ).rowcount
                        if changed != 1:
                            raise SupervisorError(
                                "worker_registration_lost",
                                "worker launch reservation was lost",
                            )
                        self._event(
                            connection,
                            "worker.started",
                            active["agent_id"],
                            {
                                "attempt_id": attempt_id,
                                "pid": process.pid,
                                "command": list(command),
                            },
                        )
                if launch_fenced:
                    raise SupervisorError(
                        "worker_launch_fenced",
                        "trust quarantine fenced the worker before launch authorization",
                    )
                # Revalidate after the kernel identity is durable but before the
                # handshake authorizes candidate code. If the pin disappeared,
                # quarantine retains this PID until the monitor is reaped.
                self._verify_attempt_trust(attempt_id)
                os.write(handshake_write, b"G")
                os.close(handshake_write)
                handshake_write = -1
                interval = max(2, min(10, self.config.lease_seconds // 3))
                while True:
                    try:
                        process.wait(timeout=interval)
                        break
                    except subprocess.TimeoutExpired:
                        self.heartbeat(
                            attempt_id,
                            claim_token,
                            {"pid": process.pid, "command": list(command)},
                            credential=credential,
                        )
            except BaseException:
                for descriptor in (handshake_read, handshake_write):
                    if descriptor >= 0:
                        os.close(descriptor)
                if process is not None:
                    self._stop_kernel_monitor(process)
                if launch_reserved:
                    self._clear_worker_registration(
                        attempt_id,
                        {-1, process.pid if process is not None else -1},
                        "worker.launch_aborted",
                        process.returncode if process is not None else None,
                    )
                raise
        if process is None:
            raise SupervisorError("worker_launch_failed", "worker was not started")
        if process.returncode:
            self._clear_worker_registration(
                attempt_id,
                {process.pid},
                "worker.exited",
                process.returncode,
            )
            raise SupervisorError(
                "worker_failed",
                f"worker exited {process.returncode}; log: {log_path}",
            )
        self._record_worker_exit(attempt_id, process.pid, process.returncode)
        try:
            return self._submit(
                attempt_id,
                claim_token,
                expected_worker_pid=process.pid,
                credential=credential,
            )
        except BaseException:
            self._clear_worker_registration(
                attempt_id,
                {process.pid},
                "worker.submission_failed",
                process.returncode,
            )
            raise

    def _reserve_worker_launch(
        self,
        attempt_id: str,
        claim_token: int,
        log_path: str,
        credential: str | None,
    ) -> None:
        launch_owner_pid = os.getpid()
        launch_owner_identity = self._process_identity(launch_owner_pid)
        if not launch_owner_identity:
            raise SupervisorError(
                "worker_identity_unavailable",
                "worker launcher kernel identity could not be recorded",
            )
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            self._authenticate_attempt(connection, attempt, credential)
            if attempt["pid"] is not None:
                raise SupervisorError(
                    "worker_already_running",
                    "this attempt already has a launching or running worker",
                )
            changed = connection.execute(
                """
                UPDATE attempts SET pid = -1, pid_identity = '', termination_proof = '',
                  launch_owner_pid = ?, launch_owner_identity = ?, log_path = ?, updated_at = ?
                WHERE id = ? AND pid IS NULL
                """,
                (
                    launch_owner_pid,
                    launch_owner_identity,
                    log_path,
                    utc_now(),
                    attempt_id,
                ),
            ).rowcount
            if changed != 1:
                raise SupervisorError(
                    "worker_already_running",
                    "this attempt already has a launching or running worker",
                )
            self._event(
                connection,
                "worker.launch_reserved",
                attempt["agent_id"],
                {"attempt_id": attempt_id, "command_log": log_path},
            )

    def _clear_worker_registration(
        self,
        attempt_id: str,
        expected_pids: set[int],
        event_type: str,
        exit_code: int | None,
    ) -> None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
            if not attempt or attempt["pid"] not in expected_pids:
                return
            terminating = attempt["status"] == "terminating"
            if terminating:
                # The monitor is gone, but the runtime is not yet proven down.
                # Retain the exact registration until that second proof is
                # durable, so a failed cleanup remains safely retryable.
                connection.execute(
                    "UPDATE attempts SET termination_proof = ?, "
                    "launch_owner_pid = NULL, launch_owner_identity = '', "
                    "updated_at = ? WHERE id = ?",
                    (event_type, utc_now(), attempt_id),
                )
            else:
                connection.execute(
                    "UPDATE attempts SET pid = NULL, pid_identity = '', "
                    "termination_target_status = '', termination_proof = '', "
                    "launch_owner_pid = NULL, launch_owner_identity = '', "
                    "updated_at = ? WHERE id = ?",
                    (utc_now(), attempt_id),
                )
            self._event(
                connection,
                event_type,
                attempt["agent_id"],
                {
                    "attempt_id": attempt_id,
                    "exit_code": exit_code,
                    "termination_target_status": attempt["termination_target_status"],
                    "termination_proved": terminating,
                },
            )

    def _record_registered_worker_termination(
        self,
        attempt_id: str,
        expected_pid: int,
        expected_identity: str,
        proof: str,
    ) -> bool:
        """Durably record process death without releasing its cleanup identity."""

        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
            if (
                not attempt
                or attempt["status"] != "terminating"
                or attempt["pid"] != expected_pid
                or attempt["pid_identity"] != expected_identity
            ):
                return False
            stamp = utc_now()
            connection.execute(
                "UPDATE attempts SET termination_proof = ?, launch_owner_pid = NULL, "
                "launch_owner_identity = '', updated_at = ? WHERE id = ? "
                "AND status = 'terminating' AND pid = ? AND pid_identity = ?",
                (proof, stamp, attempt_id, expected_pid, expected_identity),
            )
            self._event(
                connection,
                "worker.termination_proved",
                "reaper",
                {
                    "attempt_id": attempt_id,
                    "pid": expected_pid,
                    "proof": proof,
                    "target_status": attempt["termination_target_status"],
                },
            )
            return True

    def _prepare_terminated_attempt_cleanup(self, attempt_id: str) -> None:
        """Require process-death proof before runtime teardown may start."""

        with self.connect() as connection:
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
        if not attempt or attempt["status"] != "terminating" or attempt["pid"] is None:
            return
        if attempt["termination_proof"]:
            return
        if attempt["pid"] == -1:
            owner_pid = attempt["launch_owner_pid"]
            owner_identity = attempt["launch_owner_identity"]
            if not owner_pid or not owner_identity:
                raise SupervisorError(
                    "worker_launch_identity_unavailable",
                    "launch reservation has no verifiable owner; cleanup fence remains held",
                )
            if self._process_identity(owner_pid) == owner_identity:
                raise SupervisorError(
                    "worker_launch_unresolved",
                    "launch owner is still active; cleanup fence remains held",
                )
            if not self._record_registered_worker_termination(
                attempt_id,
                -1,
                "",
                "launch-owner-gone",
            ):
                raise SupervisorError(
                    "worker_registration_lost",
                    "launch reservation changed before owner-death proof was recorded",
                )
            return
        if attempt["pid"] > 0:
            raise SupervisorError(
                "worker_termination_unproven",
                "registered worker death is unproven; cleanup fence remains held",
            )
        raise SupervisorError(
            "worker_registration_invalid",
            "worker registration is invalid; cleanup fence remains held",
        )

    def _finalize_registered_worker_cleanup(self, attempt_id: str) -> str | None:
        """Clear worker identity only after runtime release is also durable."""

        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
            if (
                not attempt
                or attempt["status"] != "terminating"
                or not attempt["termination_target_status"]
            ):
                return None
            runtime = connection.execute(
                "SELECT state FROM runtime_environments WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if not attempt["termination_proof"] or not runtime or runtime["state"] != "released":
                raise SupervisorError(
                    "worker_cleanup_unproven",
                    "worker identity and runtime cleanup are not both proven",
                )
            target = attempt["termination_target_status"]
            stamp = utc_now()
            changed = connection.execute(
                "UPDATE attempts SET status = ?, pid = NULL, pid_identity = '', "
                "termination_target_status = '', termination_proof = '', "
                "launch_owner_pid = NULL, launch_owner_identity = '', updated_at = ? "
                "WHERE id = ? AND status = 'terminating' AND pid IS ? "
                "AND pid_identity = ? AND termination_proof = ?",
                (
                    target,
                    stamp,
                    attempt_id,
                    attempt["pid"],
                    attempt["pid_identity"],
                    attempt["termination_proof"],
                ),
            ).rowcount
            if changed != 1:
                raise SupervisorError(
                    "worker_registration_lost",
                    "worker cleanup identity changed before finalization",
                )
            self._event(
                connection,
                "worker.cleanup_proved",
                "reaper",
                {
                    "attempt_id": attempt_id,
                    "pid": attempt["pid"],
                    "termination_proof": attempt["termination_proof"],
                    "target_status": target,
                },
            )
            return target

    def _record_worker_exit(self, attempt_id: str, pid: int, exit_code: int) -> None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
            if not attempt or attempt["pid"] != pid:
                raise SupervisorError(
                    "worker_registration_lost",
                    "worker PID ownership changed before submission",
                )
            self._event(
                connection,
                "worker.exited",
                attempt["agent_id"],
                {
                    "attempt_id": attempt_id,
                    "pid": pid,
                    "exit_code": exit_code,
                },
            )

    def terminate_worker(self, attempt_id: str, credential: str | None = None) -> dict[str, Any]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
            if not row:
                raise SupervisorError("attempt_not_found", f"attempt {attempt_id} not found")
            self._authenticate_attempt(connection, row, credential)
            attempt = self._attempt_view(connection, row)
        if not attempt["pid"]:
            raise SupervisorError("worker_not_running", "attempt has no running worker")
        if attempt["pid"] < 0:
            raise SupervisorError(
                "worker_launching", "worker launch is reserved but has no PID yet"
            )
        pidfd = self._open_registered_pidfd(attempt["pid"], attempt["pid_identity"])
        if pidfd is None:
            raise SupervisorError(
                "worker_identity_mismatch",
                "registered worker PID was reused; refusing to signal it",
            )
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        except ProcessLookupError as error:
            raise SupervisorError(
                "worker_not_running", "worker process no longer exists"
            ) from error
        finally:
            os.close(pidfd)
        return {"attempt_id": attempt_id, "pid": attempt["pid"], "signal": "SIGTERM"}
