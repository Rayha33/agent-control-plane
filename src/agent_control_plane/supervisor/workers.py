"""Launching, registering and terminating long-running worker processes.

What stayed in git_supervisor, on purpose: `_terminate_registered_group` and
`_open_registered_pidfd` call through `GitSupervisor.` by name, and tests monkeypatch
`_open_registered_pidfd` and `_process_identity` on the GitSupervisor class.

Moved verbatim out of `git_supervisor` (board #1630). `GitSupervisor` inherits this mixin, so
every call site, CLI path and `GitSupervisor.<name>` lookup resolves exactly as before.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import select
import signal
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ..worker_trampoline import LIFECYCLE_FDS_PREFIX as LIFECYCLE_FDS_PREFIX
from ..worker_trampoline import MONITOR_MODE as MONITOR_MODE
from .common import SupervisorError, utc_now
from .sandbox_execution_journal import (
    _runc_launch_gate_lock_for_execution,
    _sandbox_execution_cleanup_is_verified,
    _sandbox_execution_launch_stop_reason,
)

_MAX_WORKER_LOG_BYTES = 8 * 1024 * 1024
_WORKER_LOG_TRUNCATION_MARKER = b"\n[ACP worker output truncated at 8 MiB]\n"
_WORKER_OUTPUT_CHUNK_BYTES = 64 * 1024


def _read_worker_output_chunk(
    output_fd: int, log: Any, remaining_bytes: int
) -> tuple[int, bool, bool]:
    """Drain one pipe chunk, retaining only the bounded prefix in the host log."""

    chunk = os.read(output_fd, _WORKER_OUTPUT_CHUNK_BYTES)
    if not chunk:
        return 0, False, True
    retained = chunk[:remaining_bytes]
    written = log.write(retained) if retained else 0
    written = written or 0
    return written, written < len(chunk), False


def _worker_command_digest(command: Sequence[str]) -> str:
    """Fingerprint argv for receipts; the digest is correlation, not confidentiality."""

    return hashlib.sha256(
        json.dumps(list(command), ensure_ascii=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


class WorkersMixin:
    """Worker launch reservation, registration, exit recording and termination."""

    def _cancel_sandbox_execution_monitor(
        self,
        execution: dict[str, Any],
        *,
        monitor_client: Any | None = None,
        _allow_ambiguous_failure: bool = False,
    ) -> dict[str, Any]:
        """Cancel a journaled execution only through its authenticated monitor."""

        from .sandbox_monitor_ipc import (
            SANDBOX_MONITOR_OPERATION_TIMEOUT_SECONDS,
            SandboxMonitorControlClient,
            SandboxMonitorIPCError,
        )
        from .sandbox_monitor_lifecycle import (
            reconnect_sandbox_monitor,
            sandbox_monitor_cancel_request_id,
            sandbox_monitor_control_paths,
        )
        from .sandbox_monitor_receipt import SandboxMonitorReceipt, SandboxMonitorReceiptError

        identity = (
            execution["attempt_id"],
            execution["claim_token"],
            execution["execution_id"],
        )

        def durable_stop_result(monitor_phase: str) -> dict[str, Any]:
            durable = self._sandbox_execution_get(execution["attempt_id"])
            with self.connect() as connection:
                launch_stop_reason = (
                    _sandbox_execution_launch_stop_reason(connection, durable)
                    if durable is not None
                    else None
                )
                cleanup_verified = (
                    _sandbox_execution_cleanup_is_verified(connection, execution["attempt_id"])
                    if durable is not None
                    else False
                )
            durable_stop_reason = (
                (durable["stop_reason"] or launch_stop_reason) if durable is not None else None
            )
            ambiguous_failure = (
                _allow_ambiguous_failure
                and durable is not None
                and durable.get("phase") == "ambiguous"
                and bool(durable.get("failure_reason"))
            )
            if (
                durable is None
                or durable["claim_token"] != identity[1]
                or durable["execution_id"] != identity[2]
                or (not durable_stop_reason and not ambiguous_failure)
            ):
                raise SupervisorError(
                    "sandbox_execution_transition_conflict",
                    "monitor stop acknowledgement has no matching durable stop intent",
                )
            return {
                "attempt_id": execution["attempt_id"],
                "execution_id": execution["execution_id"],
                "outcome": "stop_pending"
                if durable["phase"] in {"launched", "ambiguous"}
                else "ok",
                "phase": durable["phase"],
                "stop_requested": True,
                "monitor_phase": monitor_phase,
                "cleanup_verified": cleanup_verified,
            }

        expected_scope = {
            "scope_unit": execution.get("scope_unit"),
            "scope_invocation_id": execution.get("scope_invocation_id"),
            "scope_control_group": execution.get("cgroup_path"),
        }
        if any(not isinstance(value, str) or not value for value in expected_scope.values()):
            raise SupervisorError(
                "sandbox_execution_monitor_unavailable",
                "durable scope identity is unavailable; execution and resource fences remain held",
            )
        try:
            if monitor_client is None:
                control_directory, receipt_path, socket_path = sandbox_monitor_control_paths(
                    state_path=execution["state_path"], expected_identity=identity
                )
                client = reconnect_sandbox_monitor(
                    receipt_path=receipt_path,
                    control_directory=control_directory,
                    socket_path=socket_path,
                    expected_identity=identity,
                    timeout_seconds=SANDBOX_MONITOR_OPERATION_TIMEOUT_SECONDS,
                )
            else:
                receipt = getattr(monitor_client, "_receipt", None)
                if (
                    type(monitor_client) is not SandboxMonitorControlClient
                    or type(receipt) is not SandboxMonitorReceipt
                    or (
                        receipt.attempt_id,
                        receipt.claim_token,
                        receipt.execution_id,
                    )
                    != identity
                    or receipt.controller_pid != os.getpid()
                ):
                    raise SupervisorError(
                        "sandbox_execution_monitor_identity_mismatch",
                        "cached monitor client is not bound to this process and execution",
                    )
                client = monitor_client
            status = client.status()
            if status.outcome != "ok":
                raise SupervisorError(
                    "sandbox_execution_monitor_ambiguous",
                    "monitor status is ambiguous; execution and resource fences remain held",
                )
            if any(status.payload.get(key) != value for key, value in expected_scope.items()):
                raise SupervisorError(
                    "sandbox_execution_monitor_identity_mismatch",
                    "monitor status does not match the journaled scope; execution and resource fences remain held",
                )
            phase = status.payload.get("phase")
            if phase not in {
                "reserved",
                "launched",
                "running",
                "stopping",
                "exited",
                "cleanup_verified",
            }:
                raise SupervisorError(
                    "sandbox_execution_monitor_ambiguous",
                    "monitor returned an unknown phase; execution and resource fences remain held",
                )
            if phase in {"exited", "cleanup_verified"}:
                # An exit report does not satisfy the journal's independent
                # cleanup verifier. Do not alter the durable execution phase.
                monitor_phase = phase
            else:
                cancelled = client.cancel(sandbox_monitor_cancel_request_id(identity))
                if cancelled.outcome != "ok" or cancelled.payload.get("phase") not in {
                    "stopping",
                    "exited",
                }:
                    raise SupervisorError(
                        "sandbox_execution_monitor_ambiguous",
                        "monitor cancellation is ambiguous; execution and resource fences remain held",
                    )
                monitor_phase = cancelled.payload["phase"]
        except SupervisorError as error:
            if error.code in {
                "sandbox_execution_monitor_ambiguous",
                "sandbox_execution_monitor_identity_mismatch",
            }:
                raise
            raise SupervisorError(
                "sandbox_execution_monitor_unavailable",
                "authenticated monitor control is unavailable; refusing host-PID signaling and retaining execution fences",
            ) from error
        except (SandboxMonitorIPCError, SandboxMonitorReceiptError, OSError, TimeoutError) as error:
            raise SupervisorError(
                "sandbox_execution_monitor_unavailable",
                "authenticated monitor control is unavailable; refusing host-PID signaling and retaining execution fences",
            ) from error
        except Exception as error:
            # The monitor is an authorization boundary. Unexpected failure is
            # not permission to fall back to a PID, process group, or systemctl
            # action in the supervisor.
            raise SupervisorError(
                "sandbox_execution_monitor_unavailable",
                "authenticated monitor control failed; refusing host-PID signaling and retaining execution fences",
            ) from error

        return durable_stop_result(monitor_phase)

    def run_worker(
        self,
        attempt_id: str,
        claim_token: int,
        command: Sequence[str],
        credential: str | None = None,
        result_manifest_path: str | None = None,
        *,
        sandbox_experimental_opt_in: bool = False,
        sandbox_memory_max_bytes: int | None = None,
        sandbox_cpu_quota: int | None = None,
        sandbox_cpu_period: int | None = None,
        sandbox_pids_max: int | None = None,
        sandbox_timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        from ..worker_trampoline import _monitor_argv_prefix

        if type(sandbox_experimental_opt_in) is not bool:
            raise SupervisorError(
                "invalid_sandbox_opt_in",
                "experimental sandbox opt-in must be a boolean",
            )

        if isinstance(command, (str, bytes)) or not isinstance(command, Sequence):
            raise SupervisorError(
                "invalid_command",
                "worker command must be a non-empty argument sequence of strings without NUL bytes",
            )
        # Freeze caller-owned mutable argv before it is logged, expanded into
        # Popen, or hashed for the pre-exec receipt.
        command = tuple(command)
        if (
            not command
            or any(type(argument) is not str or "\x00" in argument for argument in command)
            or not command[0]
        ):
            raise SupervisorError(
                "invalid_command",
                "worker command must be a non-empty argument sequence of strings without NUL bytes",
            )
        command_digest = _worker_command_digest(command)
        sandbox_options = (
            sandbox_memory_max_bytes,
            sandbox_cpu_quota,
            sandbox_cpu_period,
            sandbox_pids_max,
            sandbox_timeout_seconds,
        )
        if sandbox_experimental_opt_in is True:
            from . import oci_worker
            from .sandbox_launch_driver_service import _MAX_TIMEOUT_SECONDS

            if result_manifest_path is not None:
                raise SupervisorError(
                    "sandbox_result_manifest_unsupported",
                    "sandboxed workers use the host-validated workspace import; --result-manifest is not supported",
                )
            if any(value is None for value in sandbox_options):
                raise SupervisorError(
                    "sandbox_resource_limits_required",
                    "experimental sandbox execution requires explicit memory, CPU quota, CPU period, PID, and timeout limits",
                )
            if (
                any(type(value) is not int or value <= 0 for value in sandbox_options[:4])
                or (
                    type(sandbox_timeout_seconds) not in {int, float}
                    or not 0.2 <= sandbox_timeout_seconds <= _MAX_TIMEOUT_SECONDS
                )
                or (
                    not oci_worker._MIN_MEMORY_BYTES
                    <= sandbox_memory_max_bytes
                    <= oci_worker._MAX_INT64
                    or sandbox_cpu_quota > oci_worker._MAX_INT64
                    or sandbox_cpu_period > oci_worker._MAX_UINT64
                    or sandbox_pids_max > oci_worker._MAX_PIDS
                )
            ):
                raise SupervisorError(
                    "invalid_sandbox_resource_limits",
                    "sandbox resource limits must satisfy the OCI compiler bounds and timeout must be between 0.2 and 3540 seconds",
                )
            return self._run_experimental_sandbox_worker(
                attempt_id,
                claim_token,
                command,
                credential=credential,
                memory_max_bytes=sandbox_memory_max_bytes,
                cpu_quota=sandbox_cpu_quota,
                cpu_period=sandbox_cpu_period,
                pids_max=sandbox_pids_max,
                timeout_seconds=sandbox_timeout_seconds,
            )
        if any(value is not None for value in sandbox_options):
            raise SupervisorError(
                "sandbox_opt_in_required",
                "sandbox resource limits require the explicit experimental opt-in",
            )
        if self.config.oci_runc_executable is not None:
            raise SupervisorError(
                "sandbox_executor_unavailable",
                "sandbox.oci is configured but supervised OCI worker execution is unavailable; refusing host fallback",
            )
        # A journaled OCI reservation can survive a supervisor restart or a
        # configuration change. Reject it before heartbeat/log setup so an
        # unavailable executor cannot mutate that attempt while refusing it.
        # This is only a side-effect-free preflight: _reserve_worker_launch
        # retains the transactional check that arbitrates concurrent claims.
        self._preflight_direct_worker_launch(attempt_id, claim_token, credential)
        if not sys.platform.startswith("linux"):
            raise SupervisorError(
                "process_containment_unavailable",
                "long-running workers require Linux child-subreaper containment",
            )
        attempt = self.heartbeat(
            attempt_id,
            claim_token,
            {
                "phase": "launching",
                "command_digest": command_digest,
                "command_argument_count": len(command),
            },
            credential=credential,
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
            target_read = -1
            target_write = -1
            start_read = -1
            start_write = -1
            output_fd: int | None = None
            output_open = False
            output_bytes_written = 0
            output_truncated = False
            log_bytes_existing = os.fstat(log.fileno()).st_size
            log_bytes_available = _MAX_WORKER_LOG_BYTES - log_bytes_existing
            if log_bytes_available < len(_WORKER_LOG_TRUNCATION_MARKER):
                raise SupervisorError(
                    "worker_log_budget_exhausted",
                    "existing worker log leaves no room for the bounded output notice",
                )
            output_bytes_budget = log_bytes_available - len(_WORKER_LOG_TRUNCATION_MARKER)
            launch_reserved = False
            try:
                handshake_read, handshake_write = os.pipe()
                target_read, target_write = os.pipe()
                start_read, start_write = os.pipe()
                self._reserve_worker_launch(attempt_id, claim_token, str(log_path), credential)
                launch_reserved = True
                trampoline = Path(__file__).parent.with_name("worker_trampoline.py").resolve()
                process = subprocess.Popen(
                    [
                        sys.executable,
                        "-I",
                        str(trampoline),
                        *_monitor_argv_prefix(handshake_read, target_write, start_read, (), None),
                        *command,
                    ],
                    cwd=attempt["worktree"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                    pass_fds=(handshake_read, target_write, start_read),
                    env=worker_env,
                )
                if process.stdout is None:
                    raise SupervisorError(
                        "worker_output_unavailable", "worker output pipe was not created"
                    )
                output_fd = process.stdout.fileno()
                output_open = True
                process_identity = self._process_identity(process.pid)
                if process_identity is None:
                    raise SupervisorError(
                        "worker_identity_unavailable",
                        "worker kernel identity could not be recorded",
                    )
                for descriptor in (handshake_read, target_write, start_read):
                    os.close(descriptor)
                handshake_read = target_write = start_read = -1
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
                                "command_digest": command_digest,
                                "command_argument_count": len(command),
                            },
                        )
                if launch_fenced:
                    raise SupervisorError(
                        "worker_launch_fenced",
                        "trust quarantine fenced the worker before launch authorization",
                    )
                # The first gate releases only the trusted monitor. Its child
                # blocks before exec while ACP records the exact command PID and
                # start identity; candidate code remains unable to run.
                self._verify_attempt_trust(attempt_id)
                os.write(handshake_write, b"G")
                os.close(handshake_write)
                handshake_write = -1
                ready, _, _ = select.select([target_read], [], [], 3)
                raw_target = os.read(target_read, 32) if ready else b""
                if not re.fullmatch(rb"[1-9][0-9]*\n", raw_target):
                    raise SupervisorError(
                        "worker_identity_unavailable",
                        "worker monitor did not report its blocked command identity",
                    )
                command_pid = int(raw_target)
                command_identity = self._process_identity(command_pid)
                if command_identity is None:
                    raise SupervisorError(
                        "worker_identity_unavailable",
                        "worker command kernel identity could not be recorded before exec",
                    )
                os.close(target_read)
                target_read = -1
                command_digest = self._record_worker_command_ready(
                    attempt_id,
                    claim_token,
                    process.pid,
                    process_identity,
                    command_pid,
                    command_identity,
                    command,
                    credential,
                )
                # Revalidate after both monitor and command identities are
                # durable, but before the second gate authorizes candidate code.
                self._verify_attempt_trust(attempt_id)
                os.write(start_write, b"G")
                os.close(start_write)
                start_write = -1
                interval = max(2, min(10, self.config.lease_seconds // 3))
                heartbeat_at = time.monotonic() + interval
                while process.poll() is None:
                    timeout = max(0.0, min(0.1, heartbeat_at - time.monotonic()))
                    readable, _, _ = select.select(
                        [output_fd] if output_open and output_fd is not None else [],
                        [],
                        [],
                        timeout,
                    )
                    if readable and output_fd is not None:
                        written, truncated, eof = _read_worker_output_chunk(
                            output_fd,
                            log,
                            output_bytes_budget - output_bytes_written,
                        )
                        output_bytes_written += written
                        output_truncated = output_truncated or truncated
                        output_open = output_open and not eof
                    if time.monotonic() >= heartbeat_at:
                        self.heartbeat(
                            attempt_id,
                            claim_token,
                            None,
                            credential=credential,
                        )
                        heartbeat_at = time.monotonic() + interval
                process.wait()
                # Collect any bytes already buffered when the monitor exited,
                # but do not wait for an escaped writer to close the pipe.
                drain_until = time.monotonic() + 0.25
                while output_open and output_fd is not None and time.monotonic() < drain_until:
                    readable, _, _ = select.select([output_fd], [], [], 0)
                    if not readable:
                        break
                    written, truncated, eof = _read_worker_output_chunk(
                        output_fd,
                        log,
                        output_bytes_budget - output_bytes_written,
                    )
                    output_bytes_written += written
                    output_truncated = output_truncated or truncated
                    output_open = output_open and not eof
                if output_truncated and log_bytes_available >= len(_WORKER_LOG_TRUNCATION_MARKER):
                    log.write(_WORKER_LOG_TRUNCATION_MARKER)
                log.flush()
                if process.stdout is not None:
                    process.stdout.close()
            except BaseException:
                for descriptor in (
                    handshake_read,
                    handshake_write,
                    target_read,
                    target_write,
                    start_read,
                    start_write,
                ):
                    if descriptor >= 0:
                        os.close(descriptor)
                if process is not None:
                    self._stop_kernel_monitor(process)
                    if process.stdout is not None:
                        process.stdout.close()
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
        try:
            self._record_worker_exit(
                attempt_id,
                process.pid,
                process.returncode,
                command_pid,
                command_identity,
                command_digest,
            )
        except BaseException:
            self._clear_worker_registration(
                attempt_id,
                {process.pid},
                "worker.exit_receipt_failed",
                process.returncode,
            )
            raise
        try:
            submit_options = {
                "expected_worker_pid": process.pid,
                "credential": credential,
            }
            if result_manifest_path is not None:
                submit_options["result_manifest_path"] = result_manifest_path
            return self._submit(attempt_id, claim_token, **submit_options)
        except BaseException:
            self._clear_worker_registration(
                attempt_id,
                {process.pid},
                "worker.submission_failed",
                process.returncode,
            )
            raise

    def _run_experimental_sandbox_worker(
        self,
        attempt_id: str,
        claim_token: int,
        command: Sequence[str],
        *,
        credential: str | None,
        memory_max_bytes: int,
        cpu_quota: int,
        cpu_period: int,
        pids_max: int,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        """Run a no-provider worker through the explicit OCI lifecycle experiment.

        Provider authentication and egress are intentionally not configured by
        this path. Result transfer is allowed only after the exact execution
        exits successfully, its independent cleanup verifier passes, and the
        existing host-side importer validates the private workspace diff.
        """

        from .sandbox_launch_driver_service import (
            SandboxLaunchDriverServiceError,
            start_registered_no_model_sandbox_worker,
        )

        if self.config.oci_runc_executable is None or self.config.oci_rootfs_pin is None:
            raise SupervisorError(
                "sandbox_executor_unavailable",
                "experimental sandbox execution requires configured pinned runc and rootfs; refusing host fallback",
            )
        try:
            execution, launch_receipt = start_registered_no_model_sandbox_worker(
                self,
                attempt_id=attempt_id,
                claim_token=claim_token,
                command=tuple(command),
                memory_max_bytes=memory_max_bytes,
                cpu_quota=cpu_quota,
                cpu_period=cpu_period,
                pids_max=pids_max,
                timeout_seconds=float(timeout_seconds),
                credential=credential,
                experimental_opt_in=True,
            )
        except SandboxLaunchDriverServiceError as error:
            raise SupervisorError("sandbox_execution_start_failed", str(error)) from error

        identity = (
            attempt_id,
            claim_token,
            execution.get("execution_id") if isinstance(execution, dict) else None,
        )
        if not isinstance(identity[2], str) or not identity[2]:
            raise SupervisorError(
                "sandbox_execution_identity_invalid",
                "sandbox launch returned no durable execution identity; execution remains fenced",
            )

        deadline = time.monotonic() + float(timeout_seconds) + 90
        cancellation_deadline: float | None = None
        try:
            while True:
                current = self._sandbox_execution_get(attempt_id)
                if (
                    current is None
                    or (
                        current.get("attempt_id"),
                        current.get("claim_token"),
                        current.get("execution_id"),
                    )
                    != identity
                ):
                    raise SupervisorError(
                        "sandbox_execution_transition_conflict",
                        "sandbox worker execution identity changed while waiting; execution remains fenced",
                    )
                phase = current.get("phase")
                if phase == "cleanup_verified":
                    verified = current
                    break
                if phase == "cleanup_reported":
                    verified = self._sandbox_execution_verify_cleanup(
                        attempt_id,
                        claim_token,
                        credential=credential,
                    )
                    break
                if phase == "ambiguous":
                    raise SupervisorError(
                        "sandbox_execution_ambiguous",
                        "sandbox worker cleanup is ambiguous; execution and resource fences remain held",
                    )
                if phase not in {"reserved", "launched", "running", "stopping", "exited"}:
                    raise SupervisorError(
                        "sandbox_execution_transition_invalid",
                        "sandbox worker reached an unknown phase; execution and resource fences remain held",
                    )

                now = time.monotonic()
                if now >= deadline and cancellation_deadline is None:
                    # The launch driver has its own exact systemd deadline. If
                    # its durable cleanup handoff is late, request cancellation
                    # only through the authenticated monitor and keep polling.
                    if phase in {"launched", "running", "stopping"}:
                        self.terminate_worker(attempt_id, credential=credential)
                    cancellation_deadline = now + 30
                elif cancellation_deadline is not None and now >= cancellation_deadline:
                    raise SupervisorError(
                        "sandbox_execution_cleanup_unverified",
                        "sandbox worker did not produce a cleanup report after exact cancellation; execution and resource fences remain held",
                    )
                time.sleep(0.05)
        except KeyboardInterrupt as error:
            try:
                current = self._sandbox_execution_get(attempt_id)
                if (
                    current is not None
                    and (
                        current.get("attempt_id"),
                        current.get("claim_token"),
                        current.get("execution_id"),
                    )
                    == identity
                    and current.get("phase") in {"launched", "running", "stopping"}
                ):
                    self.terminate_worker(attempt_id, credential=credential)
                cleanup_deadline = time.monotonic() + 30
                while time.monotonic() < cleanup_deadline:
                    current = self._sandbox_execution_get(attempt_id)
                    if (
                        current is None
                        or (
                            current.get("attempt_id"),
                            current.get("claim_token"),
                            current.get("execution_id"),
                        )
                        != identity
                    ):
                        raise SupervisorError(
                            "sandbox_execution_transition_conflict",
                            "sandbox worker identity changed during cancellation; execution remains fenced",
                        )
                    if current.get("phase") == "cleanup_reported":
                        verified = self._sandbox_execution_verify_cleanup(
                            attempt_id,
                            claim_token,
                            credential=credential,
                        )
                        if (
                            verified.get("attempt_id"),
                            verified.get("claim_token"),
                            verified.get("execution_id"),
                            verified.get("phase"),
                        ) != (*identity, "cleanup_verified"):
                            raise SupervisorError(
                                "sandbox_execution_transition_conflict",
                                "cleanup verifier returned a different execution identity; execution remains fenced",
                            )
                        break
                    if current.get("phase") == "cleanup_verified":
                        break
                    if current.get("phase") == "ambiguous":
                        raise SupervisorError(
                            "sandbox_execution_ambiguous",
                            "sandbox cancellation is ambiguous; execution and resource fences remain held",
                        )
                    time.sleep(0.05)
                else:
                    raise SupervisorError(
                        "sandbox_execution_cleanup_unverified",
                        "sandbox cancellation did not produce a cleanup report; execution and resource fences remain held",
                    )
            except BaseException as cleanup_error:
                error.add_note(
                    f"sandbox cancellation/cleanup verification also failed: {type(cleanup_error).__name__}: {cleanup_error}"
                )
            raise

        if (
            verified.get("attempt_id"),
            verified.get("claim_token"),
            verified.get("execution_id"),
        ) != identity or verified.get("phase") != "cleanup_verified":
            raise SupervisorError(
                "sandbox_execution_cleanup_unverified",
                "sandbox worker result cannot be imported without exact-identity independent cleanup verification",
            )
        exit_code = verified.get("runc_exit_code")
        if type(exit_code) is not int or exit_code != 0:
            raise SupervisorError(
                "worker_failed",
                f"sandbox worker exited {exit_code!r}; cleanup was independently verified and no result was imported",
            )
        imported = self.import_sandbox_execution_result(
            attempt_id,
            claim_token,
            credential=credential,
        )
        return {
            **imported,
            "sandbox_execution_id": identity[2],
            "sandbox_cleanup_verified": True,
            "sandbox_launch_receipt": {
                "attempt_id": launch_receipt.attempt_id,
                "claim_token": launch_receipt.claim_token,
                "execution_id": launch_receipt.execution_id,
                "service_unit": launch_receipt.service_unit,
                "invocation_id": launch_receipt.invocation_id,
                "driver_pid": launch_receipt.driver_pid,
                "driver_identity": launch_receipt.driver_identity,
                "control_group": launch_receipt.control_group,
            },
        }

    def _preflight_direct_worker_launch(
        self,
        attempt_id: str,
        claim_token: int,
        credential: str | None,
    ) -> None:
        """Reject an existing sandbox reservation before direct-launch side effects.

        This does not reserve the attempt slot: a concurrent sandbox reservation
        may still win after this read. `_reserve_worker_launch` remains the
        authoritative atomic check immediately before host process creation.
        """

        with self.connect() as connection:
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            self._authenticate_attempt(connection, attempt, credential)
            if connection.execute(
                "SELECT 1 FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone():
                raise SupervisorError(
                    "sandbox_execution_reserved",
                    "a journaled sandbox execution owns this attempt slot",
                )

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
            if connection.execute(
                "SELECT 1 FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone():
                raise SupervisorError(
                    "sandbox_execution_reserved",
                    "a journaled sandbox execution owns this attempt slot",
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
            if not _sandbox_execution_cleanup_is_verified(connection, attempt_id):
                raise SupervisorError(
                    "sandbox_cleanup_unverified",
                    "OCI execution cleanup is not independently verified; worker identity remains fenced",
                )
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
            # Sandbox-only attempts have no separate registered worker PID to
            # prove dead; a registered PID still requires explicit proof.
            worker_identity_unproven = (
                (attempt["pid"] is not None and not attempt["termination_proof"])
                or (
                    attempt["pid"] is None
                    and (attempt["pid_identity"] or attempt["termination_proof"])
                )
                or attempt["launch_owner_pid"] is not None
                or bool(attempt["launch_owner_identity"])
            )
            if worker_identity_unproven or not runtime or runtime["state"] != "released":
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

    def _record_worker_command_ready(
        self,
        attempt_id: str,
        claim_token: int,
        monitor_pid: int,
        monitor_identity: str,
        command_pid: int,
        command_identity: str,
        command: Sequence[str],
        credential: str | None,
    ) -> str:
        """Persist the blocked command identity before releasing its exec gate."""

        command_digest = _worker_command_digest(command)
        if (
            command_pid < 1
            or command_pid == monitor_pid
            or type(command_identity) is not str
            or re.fullmatch(rf"linux:{command_pid}:[0-9]+", command_identity) is None
            or self._process_identity(command_pid) != command_identity
        ):
            raise SupervisorError(
                "worker_identity_unavailable",
                "blocked worker command identity is missing or changed before exec",
            )
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            self._authenticate_attempt(connection, attempt, credential)
            if (
                attempt["pid"] != monitor_pid
                or attempt["pid_identity"] != monitor_identity
                or self._process_identity(monitor_pid) != monitor_identity
            ):
                raise SupervisorError(
                    "worker_registration_lost",
                    "worker monitor identity changed before command authorization",
                )
            self._event(
                connection,
                "worker.command_ready",
                attempt["agent_id"],
                {
                    "attempt_id": attempt_id,
                    "claim_token": claim_token,
                    "monitor_pid": monitor_pid,
                    "monitor_identity": monitor_identity,
                    "command_pid": command_pid,
                    "command_identity": command_identity,
                    "command_digest": command_digest,
                },
            )
        return command_digest

    def _record_worker_exit(
        self,
        attempt_id: str,
        pid: int,
        exit_code: int,
        command_pid: int,
        command_identity: str,
        command_digest: str,
    ) -> None:
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
            if not attempt["pid_identity"]:
                raise SupervisorError(
                    "worker_identity_unavailable",
                    "worker exit cannot be tied to a recorded kernel identity",
                )
            if (
                command_pid < 1
                or command_pid == pid
                or type(command_identity) is not str
                or type(command_digest) is not str
                or re.fullmatch(rf"linux:{command_pid}:[0-9]+", command_identity) is None
                or re.fullmatch(r"[0-9a-f]{64}", command_digest) is None
            ):
                raise SupervisorError(
                    "worker_identity_unavailable",
                    "worker command identity or digest is malformed",
                )
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
                ORDER BY sequence DESC LIMIT 1
                """,
                (
                    attempt_id,
                    attempt["claim_token"],
                    pid,
                    attempt["pid_identity"],
                    command_pid,
                    command_identity,
                    command_digest,
                ),
            ).fetchone()
            if ready is None:
                raise SupervisorError(
                    "worker_identity_unavailable",
                    "worker exit has no durable pre-exec command identity record",
                )
            self._event(
                connection,
                "worker.exited",
                attempt["agent_id"],
                {
                    "attempt_id": attempt_id,
                    "claim_token": attempt["claim_token"],
                    "pid": pid,
                    "pid_identity": attempt["pid_identity"],
                    "command_pid": command_pid,
                    "command_identity": command_identity,
                    "command_digest": command_digest,
                    "exit_code": exit_code,
                    "observed_by": "supervisor_popen_wait",
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
        # A sandbox execution is stopped only by its exact authenticated
        # systemd-owned monitor. Reconnection checks the fenced identity before
        # reading the existing key or contacting the socket; any failure keeps
        # the execution fenced and never reaches the legacy PID path.
        execution = self._sandbox_execution_get(attempt_id)
        if execution is not None:
            if execution["phase"] in {"exited", "cleanup_reported", "cleanup_verified"}:
                with self.connect() as connection:
                    cleanup_verified = _sandbox_execution_cleanup_is_verified(
                        connection, attempt_id
                    )
                    launch_stop_reason = _sandbox_execution_launch_stop_reason(
                        connection, execution
                    )
                return {
                    "attempt_id": attempt_id,
                    "execution_id": execution["execution_id"],
                    "outcome": "ok",
                    "phase": execution["phase"],
                    "stop_requested": bool(execution.get("stop_reason") or launch_stop_reason),
                    "monitor_phase": None,
                    "cleanup_verified": cleanup_verified,
                }
            if execution["phase"] not in {"launched", "running", "stopping"}:
                raise SupervisorError(
                    "sandbox_execution_monitor_unavailable",
                    "journaled execution has no stoppable monitor-owned scope; execution and resource fences remain held",
                )
            with self.connect() as connection:
                launch_stop_reason = (
                    _sandbox_execution_launch_stop_reason(connection, execution)
                    if execution["phase"] == "launched"
                    else None
                )
            stop_reason = execution.get("stop_reason") or launch_stop_reason or "terminate_worker"
            try:
                self._sandbox_execution_request_stop(
                    attempt_id,
                    execution["claim_token"],
                    stop_reason,
                    credential=credential,
                )
            except SupervisorError as error:
                if error.code != "sandbox_execution_transition_conflict":
                    raise
                # A timeout may have durably stopped this exact execution
                # after our snapshot. Adopt only that fenced stopping row;
                # never replace the first stop reason or soften other errors.
                stopped_execution = self._sandbox_execution_get(attempt_id)
                if (
                    stopped_execution is None
                    or (
                        stopped_execution.get("attempt_id"),
                        stopped_execution.get("claim_token"),
                        stopped_execution.get("execution_id"),
                    )
                    != (
                        attempt_id,
                        execution["claim_token"],
                        execution["execution_id"],
                    )
                    or stopped_execution.get("phase") != "stopping"
                    or not stopped_execution.get("stop_reason")
                ):
                    raise
            else:
                stopped_execution = self._sandbox_execution_get(attempt_id)
            if (
                stopped_execution is None
                or stopped_execution["claim_token"] != execution["claim_token"]
                or stopped_execution["execution_id"] != execution["execution_id"]
            ):
                raise SupervisorError(
                    "sandbox_execution_transition_conflict",
                    "durable execution identity changed after recording stop intent",
                )
            with _runc_launch_gate_lock_for_execution(
                attempt_id,
                stopped_execution["claim_token"],
                stopped_execution["execution_id"],
            ) as locked_handle:
                if locked_handle is not None:
                    # Closing an unreleased init gate makes its fixed trampoline
                    # exit on EOF; the monitor still handles exact-scope stop.
                    locked_handle._close_gate_locked()
                monitor_client = (
                    locked_handle._monitor_client if locked_handle is not None else None
                )
            return self._cancel_sandbox_execution_monitor(
                stopped_execution, monitor_client=monitor_client
            )
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
