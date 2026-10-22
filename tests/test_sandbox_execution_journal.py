from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import select
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import weakref
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from support import init_repo, make_task

from agent_control_plane.git_supervisor import (
    CLEANUP_FENCE_EPOCH,
    MIGRATIONS,
    SCHEMA_VERSION,
    GitSupervisor,
    SupervisorError,
)
from agent_control_plane.supervisor import claims as claims_module
from agent_control_plane.supervisor import oci_worker
from agent_control_plane.supervisor import sandbox_attestation as sandbox_attestation_module
from agent_control_plane.supervisor import sandbox_cleanup_verifier as verifier_module
from agent_control_plane.supervisor import sandbox_execution_journal as journal_module
from agent_control_plane.supervisor import sandbox_launch_driver_service as launch_driver_service
from agent_control_plane.supervisor import sandbox_monitor_ipc as monitor_ipc_module
from agent_control_plane.supervisor import sandbox_monitor_lifecycle as monitor_lifecycle_module
from agent_control_plane.supervisor import workers as workers_module
from agent_control_plane.supervisor.common import RuntimePortPool, canonical_json
from agent_control_plane.supervisor.sandbox_attestation import (
    ProcessSnapshot,
    collect_running_runtime_attestation,
    running_attestation_has_collector_provenance,
    running_attestation_is_self_consistent,
    validate_running_runtime_attestation,
)
from agent_control_plane.supervisor.sandbox_monitor_receipt import (
    SandboxMonitorReceipt,
    sandbox_attempt_slice_unit,
    sandbox_container_id,
    sandbox_monitor_service_unit,
)
from agent_control_plane.supervisor.sandbox_workspace import (
    ManifestEntry,
    _make_manifest,
    _tree_manifest_from_json,
    collect_changes,
    copy_snapshot,
    read_snapshot_files,
)
from agent_control_plane.supervisor.store import (
    _authorize_sandbox_launch_driver_redemption_write,
    _authorize_sandbox_reservation_write,
)

_RUNTIME_TMP_DIR = Path("/private/tmp")
if not _RUNTIME_TMP_DIR.is_dir() or _RUNTIME_TMP_DIR.is_symlink():
    _RUNTIME_TMP_DIR = Path("/tmp")

_RECORD_LAUNCH_MONITOR = threading.local()


def _record_launch_monitor_for_thread(**kwargs: Any) -> Any:
    """Route one shared mock to the caller thread's exact launch fixture."""

    starter = getattr(_RECORD_LAUNCH_MONITOR, "starter", None)
    if starter is None:
        raise AssertionError("record_launch test monitor callback is not configured")
    return starter(**kwargs)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return init_repo(tmp_path)


def _execution_gate_identity(row: Any) -> tuple[str, int, int]:
    return (
        str(Path(row["bundle_path"]).parent),
        row["execution_root_dev"],
        row["execution_root_ino"],
    )


@pytest.fixture(autouse=True)
def no_host_systemd_for_journal_unit_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep synthetic journal tests independent of the host's systemd manager."""

    monkeypatch.setattr(
        journal_module, "verify_running_runtime_systemd_units", lambda _receipt: None
    )


def claimed(supervisor: GitSupervisor, path: str = "alpha.txt") -> dict:
    task = make_task(supervisor, path, title="sandbox journal test")
    return supervisor.claim(task["id"], "sandbox-worker")


def _request_stop_from_fresh_process(
    repo: Path,
    attempt_id: str,
    claim_token: int,
    reason: str,
    result_sender,
) -> None:
    supervisor = GitSupervisor(repo)
    try:
        updated = supervisor._sandbox_execution_request_stop(attempt_id, claim_token, reason)
    except SupervisorError as error:
        row = supervisor._sandbox_execution_get(attempt_id)
        result_sender.send((error.code, row["phase"] if row else None))
    else:
        result_sender.send(("ok", updated["phase"]))
    finally:
        result_sender.close()


def _hold_execution_gate_fence(
    execution_root_path: str,
    execution_root_device: int,
    execution_root_inode: int,
    release_receiver,
    result_sender,
) -> None:
    """Hold the real process-shared execution fence for cancellation-race tests."""

    try:
        with oci_worker._runc_execution_gate_fence(
            execution_root_path, execution_root_device, execution_root_inode
        ):
            result_sender.send("held")
            release_receiver.recv()
        result_sender.send("released")
    except BaseException as error:
        result_sender.send(("error", type(error).__name__, str(error)))
    finally:
        release_receiver.close()
        result_sender.close()


def _revoke_launch_start_after_gate_acquire(
    repo: Path,
    execution: dict[str, Any],
    attempt_slice: str,
    intent_values: dict[str, Any],
    release_gate: Any,
    gate_sender,
    result_sender,
) -> None:
    """Pause the real producer after it owns the gate, before revoke commit."""

    from agent_control_plane.supervisor import sandbox_launch_driver_service as service

    supervisor = GitSupervisor(repo)
    intent = SimpleNamespace(**intent_values)
    original_mark_ambiguous = supervisor._sandbox_execution_mark_ambiguous_under_gate_lock
    unit_reads: list[str] = []
    stops: list[list[str]] = []

    def missing_unit(unit: str, properties: tuple[str, ...]) -> dict[str, str]:
        unit_reads.append(unit)
        values = {
            "ActiveState": "inactive",
            "ControlGroup": "",
            "Id": unit,
            "InvocationID": "",
            "Job": "",
            "LoadState": "not-found",
            "MainPID": "0",
            "Slice": "",
            "SubState": "dead",
        }
        return {name: values[name] for name in properties}

    def unexpected_stop(command: list[str], *, environment: dict[str, str]) -> bytes:
        del environment
        stops.append(command)
        raise AssertionError("quiescent exact units must not be stopped")

    def pause_before_commit(*args: Any, **kwargs: Any) -> dict[str, Any]:
        gate_sender.send("revocation owns process-shared gate")
        if not release_gate.wait(10):
            raise AssertionError("test barrier did not release exact revocation")
        return original_mark_ambiguous(*args, **kwargs)

    supervisor._sandbox_execution_mark_ambiguous_under_gate_lock = pause_before_commit
    service._unit_properties = missing_unit
    service._trusted_systemctl_executable = lambda: Path("/usr/bin/systemctl")
    service._trusted_systemd_command_environment = lambda: {"PATH": "/usr/bin"}
    service._run_trusted_runtime_command = unexpected_stop
    try:
        adopted = service._stop_and_reconcile_exact_start(
            supervisor,
            execution=execution,
            intent=intent,
            attempt_slice=attempt_slice,
            reason="cross-process revoke won launch handoff barrier",
            credential=None,
        )
        result_sender.send(("ok", adopted, unit_reads, stops))
    except BaseException as error:
        result_sender.send(("error", type(error).__name__, getattr(error, "code", None)))
    finally:
        gate_sender.close()
        result_sender.close()


def _reconcile_timeout_from_fresh_process(
    repo: Path,
    execution: dict[str, Any],
    intent_values: dict[str, Any],
    attempt_slice: str,
    event_sender,
    result_sender,
) -> None:
    """Race a fresh producer against a process that owns the handoff fence."""

    from agent_control_plane.supervisor import sandbox_launch_driver_service as service

    supervisor = GitSupervisor(repo)
    intent = SimpleNamespace(**intent_values)
    unit_reads: list[str] = []
    stops: list[list[str]] = []
    original_revoke = supervisor._sandbox_execution_revoke_launch_driver_start
    busy_reported = False

    def trace_revoke(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal busy_reported
        try:
            return original_revoke(*args, **kwargs)
        except SupervisorError as error:
            if error.code == "sandbox_execution_gate_busy" and not busy_reported:
                busy_reported = True
                event_sender.send("busy")
            raise

    def unit_properties(unit: str, properties: tuple[str, ...]) -> dict[str, str]:
        unit_reads.append(unit)
        event_sender.send(f"read:{unit}")
        monitor = sandbox_monitor_service_unit(
            intent.attempt_id, intent.claim_token, intent.execution_id
        )
        if unit == intent.service_unit:
            values = {
                "ActiveState": "active",
                "ControlGroup": f"/user.slice/user-acp.slice/{attempt_slice}/{unit}",
                "Id": unit,
                "InvocationID": "2" * 32,
                "Job": "",
                "LoadState": "loaded",
                "MainPID": "1234",
                "Slice": attempt_slice,
                "SubState": "running",
            }
        elif unit == monitor:
            values = {
                "ActiveState": "inactive",
                "ControlGroup": "",
                "Id": unit,
                "InvocationID": "",
                "Job": "",
                "LoadState": "not-found",
                "MainPID": "0",
                "Slice": "",
                "SubState": "dead",
            }
        else:
            assert unit == attempt_slice
            values = {
                "ActiveState": "active",
                "ControlGroup": f"/user.slice/user-acp.slice/{unit}",
                "Id": unit,
                "InvocationID": "3" * 32,
                "Job": "",
                "LoadState": "loaded",
                "MainPID": "0",
                "Slice": "user-acp.slice",
                "SubState": "active",
            }
        assert set(properties).issubset(values)
        return {name: values[name] for name in properties}

    def systemd_command(command: list[str], *, environment: dict[str, str]) -> bytes:
        del environment
        stops.append(command)
        event_sender.send(f"stop:{command[-1]}")
        return b""

    supervisor._sandbox_execution_revoke_launch_driver_start = trace_revoke
    service._unit_properties = unit_properties
    service._trusted_systemctl_executable = lambda: Path("/usr/bin/systemctl")
    service._trusted_systemd_command_environment = lambda: {"PATH": "/usr/bin"}
    service._run_trusted_runtime_command = systemd_command
    try:
        adopted = service._stop_and_reconcile_exact_start(
            supervisor,
            execution=execution,
            intent=intent,
            attempt_slice=attempt_slice,
            reason="startup timeout raced with monitor handoff",
            credential=None,
        )
        result_sender.send(("ok", adopted, unit_reads, stops))
    except BaseException as error:
        result_sender.send(("error", type(error).__name__, str(error), unit_reads, stops))
    finally:
        event_sender.close()
        result_sender.close()


def _crash_record_launch_after_monitor_acceptance(
    repo: Path,
    attempt: dict[str, Any],
    intent_values: dict[str, Any],
    accepted_sender,
) -> None:
    """Lose the launch-driver process after manager acceptance, before receipt return."""

    supervisor = GitSupervisor(repo)
    redeem_test_launch_driver_start(supervisor, attempt, intent=SimpleNamespace(**intent_values))

    def manager_accepted(_kwargs: dict[str, Any]) -> None:
        accepted_sender.send(("accepted", os.getpid()))
        accepted_sender.close()
        os._exit(74)

    record_launch(supervisor, attempt, monitor_start_hook=manager_accepted)
    os._exit(75)  # The accepted hook must terminate before record_launch can commit.


def _reconcile_monitor_accepted_driver_crash(
    repo: Path,
    execution: dict[str, Any],
    intent_values: dict[str, Any],
    attempt_slice: str,
    uncertain_after_stop_unit: str | None,
    result_sender,
) -> None:
    """Recover a stranded handoff from a fresh supervisor process."""

    from agent_control_plane.supervisor import sandbox_launch_driver_service as service

    supervisor = GitSupervisor(repo)
    intent = SimpleNamespace(**intent_values)
    monitor_unit = sandbox_monitor_service_unit(
        intent.attempt_id, intent.claim_token, intent.execution_id
    )
    common_cgroup = "/user.slice/user-1000.slice/user@1000.service/user-acp.slice"
    unit_reads: list[str] = []
    stopped: set[str] = set()
    stop_commands: list[list[str]] = []

    def unit_properties(unit: str, properties: tuple[str, ...]) -> dict[str, str]:
        unit_reads.append(unit)
        active = unit not in stopped or unit == uncertain_after_stop_unit
        if unit == intent.service_unit:
            values = {
                "ActiveState": "active" if active else "inactive",
                "ControlGroup": (
                    f"{common_cgroup}/{attempt_slice}/{intent.service_unit}" if active else ""
                ),
                "Id": unit,
                "InvocationID": execution["launch_driver_start_redeemed_invocation_id"],
                "Job": "",
                "LoadState": "loaded",
                "MainPID": "2345" if active else "0",
                "Slice": attempt_slice,
                "SubState": "running" if active else "dead",
            }
        elif unit == monitor_unit:
            values = {
                "ActiveState": "active" if active else "inactive",
                "ControlGroup": f"{common_cgroup}/{monitor_unit}" if active else "",
                "Id": unit,
                "InvocationID": "5" * 32,
                "Job": "",
                "LoadState": "loaded",
                "MainPID": "3456" if active else "0",
                "Slice": "user-acp.slice",
                "SubState": "running" if active else "dead",
            }
        else:
            assert unit == attempt_slice
            values = {
                "ActiveState": "active" if active else "inactive",
                "ControlGroup": f"{common_cgroup}/{unit}" if active else "",
                "Id": unit,
                "InvocationID": "3" * 32,
                "Job": "",
                "LoadState": "loaded",
                "MainPID": "0",
                "Slice": "user-acp.slice",
                "SubState": "active" if active else "dead",
            }
        assert set(properties).issubset(values)
        return {name: values[name] for name in properties}

    def stop_unit(command: list[str], *, environment: dict[str, str]) -> bytes:
        del environment
        unit = command[4]
        assert command == ["/usr/bin/systemctl", "--user", "stop", "--", unit]
        assert unit in {intent.service_unit, monitor_unit, attempt_slice}
        stop_commands.append(command)
        stopped.add(unit)
        return b""

    service._unit_properties = unit_properties
    service._trusted_systemctl_executable = lambda: Path("/usr/bin/systemctl")
    service._trusted_systemd_command_environment = lambda: {"PATH": "/usr/bin"}
    service._run_trusted_runtime_command = stop_unit
    try:
        adopted = service._stop_and_reconcile_exact_start(
            supervisor,
            execution=execution,
            intent=intent,
            attempt_slice=attempt_slice,
            reason="launch-driver died after monitor manager acceptance",
            credential=None,
        )
        result_sender.send(("ok", adopted, unit_reads, stop_commands))
    except BaseException as error:
        result_sender.send(("error", type(error).__name__, str(error), unit_reads, stop_commands))
    finally:
        result_sender.close()


def _terminate_worker_from_fresh_supervisor(
    repo: Path,
    attempt_id: str,
    expected_identity: tuple[str, int, str],
    state_path: str,
    scope: dict[str, str],
    result_sender,
) -> None:
    """Exercise the public recovery path without a process-local launch handle."""

    calls: list[tuple[str, tuple[str, int, str], str]] = []

    def control_paths(**kwargs: object) -> tuple[Path, Path, Path]:
        if (
            kwargs.get("expected_identity") != expected_identity
            or kwargs.get("state_path") != state_path
        ):
            raise AssertionError("fresh supervisor derived control paths from the wrong identity")
        return (
            Path("/private/control"),
            Path("/private/control/receipt"),
            Path("/private/runtime/socket"),
        )

    monitor_lifecycle_module.sandbox_monitor_control_paths = control_paths
    monitor_lifecycle_module.reconnect_sandbox_monitor = lambda **kwargs: _FreshMonitorStub(
        expected_identity, scope, calls, kwargs
    )
    supervisor = GitSupervisor(repo)
    try:
        result = supervisor.terminate_worker(attempt_id)
    except SupervisorError as error:
        result_sender.send(
            (
                "error",
                error.code,
                repr(error.__cause__),
                supervisor._sandbox_execution_get(attempt_id)["phase"],
                calls,
            )
        )
    else:
        result_sender.send(("ok", result, calls))
    finally:
        result_sender.close()


class _FreshMonitorStub:
    """Small monitor double used only by the spawned restart regression."""

    def __init__(
        self,
        expected_identity: tuple[str, int, str],
        scope: dict[str, str],
        calls: list[tuple[str, tuple[str, int, str], str]],
        reconnect_kwargs: dict[str, object],
    ) -> None:
        if reconnect_kwargs.get("expected_identity") != expected_identity:
            raise AssertionError("fresh supervisor reconnected with the wrong execution identity")
        self.expected_identity = expected_identity
        self.scope = scope
        self.calls = calls

    def status(self):
        self.calls.append(("status", self.expected_identity, ""))
        return SimpleNamespace(outcome="ok", payload={"phase": "running", **self.scope})

    def cancel(self, request_id: str):
        self.calls.append(("cancel", self.expected_identity, request_id))
        return SimpleNamespace(outcome="ok", payload={"phase": "stopping"})


def _acquire_gate_fence_after_parent_release(
    execution_root_path: str,
    execution_root_device: int,
    execution_root_inode: int,
    inherited_lock_fd: int,
    release_receiver,
    result_sender,
) -> None:
    try:
        os.fstat(inherited_lock_fd)
    except OSError:
        result_sender.send("inherited-closed")
    else:
        result_sender.send("inherited-open")
    release_receiver.recv()
    try:
        with oci_worker._runc_execution_gate_fence(
            execution_root_path, execution_root_device, execution_root_inode
        ):
            result_sender.send("acquired")
    except SupervisorError as error:
        result_sender.send(error.code)
    finally:
        release_receiver.close()
        result_sender.close()


def _terminate_worker_from_forked_process(
    repo: Path,
    attempt_id: str,
    inherited_handle: oci_worker.RuncLaunchHandle,
    inherited_record: oci_worker._RuncLaunchRecord,
    result_sender,
) -> None:
    supervisor = GitSupervisor(repo)
    try:
        supervisor.terminate_worker(attempt_id)
    except SupervisorError as error:
        global_locks = (
            oci_worker._RUNC_LAUNCH_SUBMISSION_TARGETS_LOCK,
            oci_worker._RUNC_LAUNCH_RECORDS_LOCK,
            oci_worker._RUNC_WAIT_RECEIPTS_LOCK,
        )
        acquired_locks = []
        for lock in global_locks:
            if not lock.acquire(timeout=1):
                break
            acquired_locks.append(lock)
        locks_available = len(acquired_locks) == len(global_locks)
        for lock in reversed(acquired_locks):
            lock.release()
        gate_lock_available = inherited_handle._gate_lock.acquire(timeout=1)
        if gate_lock_available:
            inherited_handle._gate_lock.release()
        wait_lock_available = inherited_record.wait_lock.acquire(timeout=1)
        if wait_lock_available:
            inherited_record.wait_lock.release()
        result_sender.send(
            (
                error.code,
                inherited_handle._monitor_client is None,
                locks_available,
                gate_lock_available,
                wait_lock_available,
                inherited_handle._gate_writer is None,
            )
        )
    else:
        result_sender.send(("unexpected_success", inherited_handle._monitor_client is None))
    finally:
        result_sender.close()


def _forked_child_wait_for_release(ready_sender, release_receiver) -> None:
    ready_sender.send(True)
    release_receiver.recv()
    ready_sender.close()
    release_receiver.close()


def _retry_launch_submission_from_fresh_process(
    repo: Path,
    attempt_id: str,
    claim_token: int,
    target: oci_worker._RuncLaunchTarget,
    result_sender,
) -> None:
    supervisor = GitSupervisor(repo)
    try:
        supervisor._sandbox_execution_authorize_launch_submission(
            attempt_id,
            claim_token,
            launch_target=target,
        )
    except SupervisorError as error:
        result_sender.send(error.code)
    else:
        result_sender.send("unexpected_second_submission_authorized")
    finally:
        result_sender.close()


def _race_launch_submission_from_fresh_process(
    repo: Path,
    attempt_id: str,
    claim_token: int,
    target: oci_worker._RuncLaunchTarget,
    start_event,
    result_sender,
) -> None:
    supervisor = GitSupervisor(repo)
    start_event.wait(timeout=10)
    try:
        submission = supervisor._sandbox_execution_authorize_launch_submission(
            attempt_id,
            claim_token,
            launch_target=target,
        )
    except SupervisorError as error:
        result_sender.send(("error", error.code))
    else:
        result_sender.send(("ok", submission.submission_id))
    finally:
        result_sender.close()


def configure_test_sandbox_pins(supervisor: GitSupervisor) -> None:
    if (
        supervisor.config.oci_rootfs_pin is not None
        and supervisor.config.oci_runc_executable is not None
        and supervisor.config.oci_runc_version is not None
    ):
        return
    rootfs = supervisor.root.parent / f"{supervisor.root.name}-test-rootfs"
    (rootfs / "bin").mkdir(parents=True, mode=0o700, exist_ok=True)
    fixture_executable = rootfs / "bin" / "sh"
    if not fixture_executable.exists():
        fixture_executable.write_text("sandbox journal test rootfs\n", encoding="ascii")
        fixture_executable.chmod(0o700)
    manifest = oci_worker.rootfs_tree_manifest(rootfs)
    rootfs_pin = oci_worker._pin_trusted_rootfs(
        rootfs,
        manifest["rootfs_sha256"],
        supervisor.root,
        expected_closure_sha256=manifest["closure_sha256"],
    )
    runc_pin = oci_worker._pin_trusted_runc_executable("/bin/sh", supervisor.root)
    supervisor.config = replace(
        supervisor.config,
        oci_rootfs_pin=rootfs_pin,
        oci_runc_executable=runc_pin,
        oci_runc_version="1.3.5",
    )


def configured_sandbox_claims(supervisor: GitSupervisor) -> dict[str, str]:
    configure_test_sandbox_pins(supervisor)
    return {
        "rootfs_digest": supervisor.config.oci_rootfs_pin.sha256,
        "rootfs_closure_digest": supervisor.config.oci_rootfs_pin.closure_sha256,
        "runc_executable_digest": supervisor.config.oci_runc_executable.sha256,
        "runtime_version": supervisor.config.oci_runc_version,
        "oci_version": "1.2.1",
    }


class _TestRuncProcess:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.returncode: int | None = None


_TEST_RUNC_LAUNCH_SPECS: dict[int, tuple[weakref.ReferenceType, dict[str, object]]] = {}


def _test_runc_launch_spec(handle: oci_worker.RuncLaunchHandle) -> dict[str, object] | None:
    registered = _TEST_RUNC_LAUNCH_SPECS.get(id(handle))
    if registered is None or registered[0]() is not handle:
        return None
    return registered[1]


def _register_test_runc_launch(
    handle: oci_worker.RuncLaunchHandle,
    *,
    launch_submission: object | None,
) -> None:
    spec = _test_runc_launch_spec(handle)
    assert spec is not None

    oci_worker._register_runc_launch_handle(
        handle,
        process=spec["process"],
        process_identity=spec["identity"],
        target=spec["target"],
        launch_submission=launch_submission,
        _test_waitpid=spec["test_waitpid"],
        _test_identity_reader=spec["identity_reader"],
    )
    _TEST_RUNC_LAUNCH_SPECS.pop(id(handle), None)


def _test_runc_handle(
    *,
    target: oci_worker._RuncLaunchTarget | None = None,
    start_ticks: int = 1202,
    exit_code: int = 0,
    sealed: bool = True,
    gate_writer: int | None = None,
) -> oci_worker.RuncLaunchHandle:
    process = _TestRuncProcess(202)
    identity = f"linux:{process.pid}:{start_ticks}"
    if gate_writer is None:
        gate_read, gate_writer = os.pipe()
        os.close(gate_read)
    handle = oci_worker.RuncLaunchHandle(_gate_writer=gate_writer)
    if sealed:
        assert target is not None

        def test_waitpid(pid: int, _options: int) -> tuple[int, int]:
            return pid, exit_code << 8

        handle_id = id(handle)

        def discard(reference: weakref.ReferenceType) -> None:
            current = _TEST_RUNC_LAUNCH_SPECS.get(handle_id)
            if current is not None and current[0] is reference:
                _TEST_RUNC_LAUNCH_SPECS.pop(handle_id, None)

        reference = weakref.ref(handle, discard)
        _TEST_RUNC_LAUNCH_SPECS[id(handle)] = (
            reference,
            {
                "process": process,
                "identity": identity,
                "target": target,
                "test_waitpid": test_waitpid,
                "identity_reader": lambda pid: identity if pid == process.pid else None,
            },
        )
    return handle


def _test_runc_target(
    execution: dict, *, launch_mode: str = "private_bundle", container_id: str | None = None
) -> oci_worker._RuncLaunchTarget:
    state_path = execution["state_path"]
    return oci_worker._RuncLaunchTarget(
        launch_mode=launch_mode,
        argv=(
            "/usr/bin/runc",
            "--root",
            "/proc/self/fd/66",
            "--systemd-cgroup",
            "run",
            "--bundle",
            "/proc/self/fd/64",
            "--pid-file",
            "/proc/self/fd/66/init.pid",
            "--preserve-fds",
            "1",
            "--keep",
            container_id or execution["container_id"],
        ),
        runc_executable_path="/usr/bin/runc",
        runc_executable_sha256=execution["runc_executable_digest"],
        config_sha256="b" * 64,
        bundle_path=execution["bundle_path"],
        bundle_device=execution["bundle_root_dev"],
        bundle_inode=execution["bundle_root_ino"],
        rootfs_path=str(Path(execution["bundle_path"]) / "rootfs"),
        rootfs_device=1,
        rootfs_inode=1202,
        rootfs_sha256=execution["rootfs_digest"],
        rootfs_closure_sha256=execution["rootfs_closure_digest"],
        rootfs_entry_count=3,
        rootfs_bytes=25,
        rootfs_snapshot_limit_bytes=4 * 1024 * 1024,
        rootfs_snapshot_device=2,
        rootfs_snapshot_inode=1203,
        rootfs_snapshot_sha256=execution["rootfs_digest"],
        rootfs_snapshot_closure_sha256=execution["rootfs_closure_digest"],
        rootfs_snapshot_entry_count=3,
        rootfs_snapshot_bytes=25,
        state_path=state_path,
        state_device=execution["state_root_dev"],
        state_inode=execution["state_root_ino"],
        workspace_path=execution["workspace_root_path"],
        workspace_device=execution["workspace_root_dev"],
        workspace_inode=execution["workspace_root_ino"],
        pid_file_path=str(Path(state_path) / "init.pid"),
        container_id=container_id or execution["container_id"],
        memory_limit_bytes=1_073_741_824,
        cpu_quota=100_000,
        cpu_period=100_000,
        pids_limit=256,
    )


def reserve(
    supervisor: GitSupervisor,
    attempt: dict,
    *,
    runtime_claims: dict[str, str] | None = None,
) -> dict:
    if runtime_claims is None:
        runtime_claims = configured_sandbox_claims(supervisor)
    row = supervisor._sandbox_execution_reserve(
        attempt["id"],
        attempt["claim_token"],
        **runtime_claims,
    )
    execution_root = Path(row["bundle_path"]).parent
    execution_root.mkdir(mode=0o700, parents=True)
    Path(row["bundle_path"]).mkdir(mode=0o700)
    Path(row["state_path"]).mkdir(mode=0o700)
    baseline = copy_snapshot(attempt["worktree"], execution_root / "baseline")
    workspace = copy_snapshot(baseline.root, execution_root / "workspace")
    return supervisor._sandbox_execution_bind_workspace(
        attempt["id"], attempt["claim_token"], baseline, workspace
    )


def redeem_test_launch_driver_start(
    supervisor: GitSupervisor, attempt: dict, *, intent: Any | None = None
) -> tuple[Any, dict[str, Any]]:
    """Issue synthetic collector evidence for one journal-only redemption test."""

    if intent is None:
        existing = supervisor._sandbox_execution_get(attempt["id"])
        assert existing is not None
        if existing["launch_driver_start_id"]:
            intent = SimpleNamespace(
                attempt_id=attempt["id"],
                claim_token=attempt["claim_token"],
                execution_id=existing["execution_id"],
                start_id=existing["launch_driver_start_id"],
                start_digest=existing["launch_driver_start_digest"],
                service_unit=existing["launch_driver_start_unit"],
            )
        else:
            intent = supervisor._sandbox_execution_authorize_launch_driver_start(
                attempt["id"], attempt["claim_token"], launch_request_digest="e" * 64
            )
    redemption = collect_test_launch_driver_redemption(supervisor, attempt)
    updated = supervisor._sandbox_execution_redeem_launch_driver_start(
        attempt["id"], attempt["claim_token"], redemption=redemption
    )
    return redemption, updated


def collect_test_launch_driver_redemption(
    supervisor: GitSupervisor,
    attempt: dict,
    *,
    service_active_state: str = "active",
    service_invocation_id: str = "4" * 32,
    slice_active_state: str = "active",
    slice_invocation_id: str = "3" * 32,
) -> Any:
    """Issue synthetic collector evidence for one journal-only observation."""

    row = supervisor._sandbox_execution_get(attempt["id"])
    assert row is not None
    attempt_slice_unit = oci_worker._oci_worker_systemd_slice(row["container_id"])
    parent_cgroup = "/user.slice/user-1000.slice/user@1000.service/user-acp.slice"
    attempt_slice_cgroup = f"{parent_cgroup}/{attempt_slice_unit}"
    driver_cgroup = f"{attempt_slice_cgroup}/{row['launch_driver_start_unit']}"
    pid = os.getpid()
    service_properties = (
        f"ActiveState={service_active_state}\n"
        f"ControlGroup={driver_cgroup}\n"
        f"Id={row['launch_driver_start_unit']}\n"
        f"InvocationID={service_invocation_id}\n"
        "LoadState=loaded\n"
        f"MainPID={pid}\n"
        f"Slice={attempt_slice_unit}\n"
    ).encode("ascii")
    slice_properties = (
        f"ActiveState={slice_active_state}\n"
        f"ControlGroup={attempt_slice_cgroup}\n"
        f"Id={attempt_slice_unit}\n"
        f"InvocationID={slice_invocation_id}\n"
        "LoadState=loaded\n"
        "Slice=user-acp.slice\n"
    ).encode("ascii")
    with patch.object(
        sandbox_attestation_module,
        "verify_linux_process_membership",
        return_value=f"linux:{pid}:1404",
    ):
        redemption = (
            sandbox_attestation_module._collect_launch_driver_start_redemption_from_observations(
                expected_identity=(attempt["id"], attempt["claim_token"], row["execution_id"]),
                expected_container_id=row["container_id"],
                start_id=row["launch_driver_start_id"],
                start_digest=row["launch_driver_start_digest"],
                service_unit=row["launch_driver_start_unit"],
                attempt_slice_unit=attempt_slice_unit,
                service_properties=service_properties,
                attempt_slice_properties=slice_properties,
                expected_current_pid=pid,
            )
        )
    return redemption


def authorize_test_launch_submission(
    supervisor: GitSupervisor,
    attempt: dict,
    launch_target: oci_worker._RuncLaunchTarget,
) -> Any:
    """Give legacy journal tests an explicit synthetic service-receipt setup."""

    execution = supervisor._sandbox_execution_get(attempt["id"])
    assert execution is not None
    ready = (
        execution["launch_plan_required"] == 1
        and execution["workspace_binding_version"] == 1
        and execution["private_path_binding_version"] == 1
    )
    if ready and not execution["launch_driver_start_redeemed_at"]:
        redeem_test_launch_driver_start(supervisor, attempt)
    execution = supervisor._sandbox_execution_get(attempt["id"])
    assert execution is not None
    redemption = collect_test_launch_driver_redemption(supervisor, attempt) if ready else None
    with (
        patch.object(
            journal_module,
            "collect_launch_driver_start_redemption",
            return_value=redemption,
        ),
        patch.object(
            journal_module,
            "verify_linux_process_membership",
            return_value=execution["launch_driver_start_redeemed_identity"],
        ),
    ):
        return supervisor._sandbox_execution_authorize_launch_submission(
            attempt["id"], attempt["claim_token"], launch_target=launch_target
        )


def test_sandbox_container_id_binds_full_execution_identity() -> None:
    first_execution = "12345678-0000-4000-8000-000000000001"
    second_execution = "12345678-0000-4000-8000-000000000002"

    assert first_execution[:8] == second_execution[:8]
    first = journal_module._sandbox_container_id("a" * 64, 7, first_execution)
    retry = journal_module._sandbox_container_id("a" * 64, 7, first_execution)
    different_execution = journal_module._sandbox_container_id("a" * 64, 7, second_execution)
    different_claim = journal_module._sandbox_container_id("a" * 64, 8, first_execution)
    different_attempt = journal_module._sandbox_container_id("b" * 64, 7, first_execution)

    assert first == retry
    assert first != different_execution
    assert first != different_claim
    assert first != different_attempt
    assert len(first) == 64
    assert first.startswith("acp-")
    assert all(character in "0123456789abcdef" for character in first[4:])


def test_existing_legacy_container_id_is_not_recomputed_on_read(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    legacy_container_id = (
        f"acp-{execution['attempt_id'][:24]}-{execution['claim_token']}-"
        f"{execution['execution_id'][:8]}"
    )
    assert legacy_container_id != execution["container_id"]

    # Model the pre-full-identity identifier in the current schema. The
    # production identity trigger correctly forbids changing this field.
    with supervisor.connect() as connection:
        connection.execute("DROP TRIGGER sandbox_execution_identity_immutable")
        connection.execute(
            "UPDATE sandbox_executions SET container_id = ? WHERE attempt_id = ?",
            (legacy_container_id, attempt["id"]),
        )

    reopened = GitSupervisor(repo)
    stored = reopened._sandbox_execution_get(attempt["id"])
    assert stored is not None
    assert stored["container_id"] == legacy_container_id


def test_launch_record_requires_pinned_runc_handle(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)

    with pytest.raises(SupervisorError) as unsealed:
        record_launch(
            supervisor,
            attempt,
            runc_handle=_test_runc_handle(target=_test_runc_target(execution), sealed=False),
        )

    assert unsealed.value.code == "sandbox_execution_launch_handle_required"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "reserved"


def test_pinned_runc_handle_cannot_be_rebound_to_another_attempt(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    first_attempt = claimed(supervisor)
    first_execution = reserve(supervisor, first_attempt)
    handle = _test_runc_handle(target=_test_runc_target(first_execution))
    record_launch(supervisor, first_attempt, runc_handle=handle)

    second_attempt = claimed(supervisor, "beta.txt")
    reserve(supervisor, second_attempt)
    with pytest.raises(SupervisorError) as rebound:
        record_launch(supervisor, second_attempt, runc_handle=handle)

    assert rebound.value.code == "sandbox_execution_launch_target_mismatch"
    assert supervisor._sandbox_execution_get(second_attempt["id"])["phase"] == "reserved"


def test_wrong_first_attempt_cannot_claim_runc_handle_provenance(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    first_attempt = claimed(supervisor)
    first_execution = reserve(supervisor, first_attempt)
    second_attempt = claimed(supervisor, "beta.txt")
    reserve(supervisor, second_attempt)
    handle = _test_runc_handle(target=_test_runc_target(first_execution))
    assert record_launch(supervisor, first_attempt, runc_handle=handle)["phase"] == "launched"

    with pytest.raises(SupervisorError) as wrong_first_binding:
        record_launch(supervisor, second_attempt, runc_handle=handle)

    assert wrong_first_binding.value.code == "sandbox_execution_launch_target_mismatch"
    assert supervisor._sandbox_execution_get(second_attempt["id"])["phase"] == "reserved"


def test_launch_submission_commit_precedes_fake_runc_exec_marker(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    target = _test_runc_target(execution)

    # This models the launcher's callback boundary: the durable transaction
    # commits before the fake runc marker and its exact handle are registered.
    def authorize_before_exec(launch_target):
        submission = authorize_test_launch_submission(supervisor, attempt, launch_target)
        durable = supervisor._sandbox_execution_get(attempt["id"])
        assert durable is not None
        assert durable["phase"] == "reserved"
        assert durable["launch_submission_id"] == submission.submission_id
        return submission

    submission = oci_worker._authorize_runc_submission_before_exec(authorize_before_exec, target)
    durable = supervisor._sandbox_execution_get(attempt["id"])
    assert durable is not None

    fake_runc_exec_marker = f"exec-ack:{submission.submission_id}"
    handle = _test_runc_handle(target=target)
    _register_test_runc_launch(handle, launch_submission=submission)
    attempt["_test_launch_submission"] = submission
    assert fake_runc_exec_marker == f"exec-ack:{durable['launch_submission_id']}"
    assert oci_worker._runc_launch_submission_is_bound_to_handle(handle, submission)

    assert record_launch(supervisor, attempt, runc_handle=handle)["phase"] == "launched"


@pytest.mark.parametrize("callback_result", ["none", "unrelated", "other_target"])
def test_private_launcher_rejects_missing_or_mismatched_capability_before_exec_ack(
    repo: Path,
    callback_result: str,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    target = _test_runc_target(execution)
    fake_exec_ack: list[str] = []

    def authorize(launch_target):
        if callback_result == "none":
            return None
        if callback_result == "unrelated":
            return object()
        wrong_target = replace(launch_target, config_sha256="c" * 64)
        return authorize_test_launch_submission(supervisor, attempt, wrong_target)

    with pytest.raises(SupervisorError) as rejected:
        submission = oci_worker._authorize_runc_submission_before_exec(authorize, target)
        fake_exec_ack.append(f"exec-ack:{submission.submission_id}")

    assert rejected.value.code == "sandbox_execution_launch_submission_required"
    assert fake_exec_ack == []
    durable = supervisor._sandbox_execution_get(attempt["id"])
    assert durable is not None
    assert durable["phase"] == "reserved"
    if callback_result == "other_target":
        assert durable["launch_submission_id"]
    else:
        assert durable["launch_submission_id"] == ""


def test_post_launch_authorization_cannot_be_paired_with_existing_handle(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    target = _test_runc_target(execution)
    handle = _test_runc_handle(target=target)

    # Model an unjournaled submission first, then an attacker attempting to
    # authorize the same target after the handle already exists.
    _register_test_runc_launch(handle, launch_submission=None)
    submission = authorize_test_launch_submission(supervisor, attempt, target)
    attempt["_test_launch_submission"] = submission

    assert not oci_worker._runc_launch_submission_is_bound_to_handle(handle, submission)
    with pytest.raises(SupervisorError) as rejected:
        record_launch(supervisor, attempt, runc_handle=handle)

    assert rejected.value.code == "sandbox_execution_launch_submission_required"
    durable = supervisor._sandbox_execution_get(attempt["id"])
    assert durable is not None
    assert durable["phase"] == "reserved"
    assert durable["launch_submission_id"] == submission.submission_id


def test_diagnostic_runc_handle_cannot_be_recorded_as_supervised(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    handle = _test_runc_handle(
        target=_test_runc_target(execution, launch_mode="unisolated_diagnostic")
    )

    with pytest.raises(SupervisorError) as diagnostic:
        record_launch(supervisor, attempt, runc_handle=handle)

    assert diagnostic.value.code == "sandbox_execution_launch_target_mismatch"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "reserved"


def test_launch_binds_rootfs_pins_and_persists_exact_config_digest(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    target = _test_runc_target(execution)
    handle = _test_runc_handle(target=target)

    assert record_launch(supervisor, attempt, runc_handle=handle)["phase"] == "launched"
    with supervisor.connect() as connection:
        event = connection.execute(
            "SELECT payload_json FROM events WHERE event_type = 'sandbox.execution_launched'"
        ).fetchone()
    assert event is not None
    launch = json.loads(event["payload_json"])["launch_target"]
    assert launch["config_sha256"] == target.config_sha256
    assert launch["config_sha256_semantics"] == "sha256-exact-config-json-bytes"
    assert launch["rootfs"]["sha256"] == execution["rootfs_digest"]
    assert launch["rootfs"]["closure_sha256"] == execution["rootfs_closure_digest"]
    assert launch["rootfs"]["device"] == target.rootfs_device
    assert launch["rootfs"]["inode"] == target.rootfs_inode
    assert launch["rootfs"]["snapshot"]["device"] == target.rootfs_snapshot_device
    assert launch["rootfs"]["snapshot"]["inode"] == target.rootfs_snapshot_inode
    assert launch["rootfs"]["snapshot"]["sha256"] == execution["rootfs_digest"]
    durable = supervisor._sandbox_execution_get(attempt["id"])
    assert durable["launch_plan_required"] == 1
    assert durable["launch_plan_binding_version"] == 1
    assert durable["bundle_digest"] == journal_module._sandbox_reservation_bundle_digest(durable)
    assert durable["bundle_digest_semantics"] == "oci-reservation-v1"
    assert durable["launch_config_digest"] == target.config_sha256
    assert (
        durable["launch_argv_digest"]
        == hashlib.sha256(canonical_json(list(target.argv)).encode("utf-8")).hexdigest()
    )
    assert (
        durable["launch_plan_digest"]
        == hashlib.sha256(canonical_json(durable["launch_plan"]).encode("utf-8")).hexdigest()
    )
    assert durable["launch_plan"]["reservation"]["bundle_digest"] == execution["bundle_digest"]
    assert durable["launch_plan"]["version"] == 6
    assert durable["launch_plan"]["reservation"]["bundle_digest_semantics"] == "oci-reservation-v1"
    assert durable["launch_plan"]["launch"]["argv"] == list(target.argv)
    assert durable["launch_plan"]["launch"]["resource_limits"] == {
        "memory_max_bytes": target.memory_limit_bytes,
        "cpu_quota": target.cpu_quota,
        "cpu_period": target.cpu_period,
        "pids_max": target.pids_limit,
    }
    assert journal_module._sandbox_launch_plan_binding_is_self_consistent(durable)
    event_plan = json.loads(event["payload_json"])["launch_plan"]
    assert event_plan == durable["launch_plan"]
    assert supervisor.verify_event_chain()["ok"] is True

    # Version 5 keeps its previous monitor-unit semantics so already-recorded
    # plans remain readable after the version 6 identity strengthening.
    legacy_v5_plan = json.loads(canonical_json(durable["launch_plan"]))
    legacy_v5_plan["version"] = 5
    legacy_v5_row = dict(durable)
    legacy_v5_row["wrapper_unit"] = "acp-worker.service"
    legacy_v5_row["wrapper_cgroup_path"] = (
        "/user.slice/user-1000.slice/user@1000.service/app.slice/acp-worker.service"
    )
    legacy_v5_plan["launch"]["systemd_ownership"]["wrapper_control_group"] = legacy_v5_row[
        "wrapper_cgroup_path"
    ]
    legacy_v5_row["launch_plan_json"] = canonical_json(legacy_v5_plan)
    legacy_v5_row["launch_plan_digest"] = hashlib.sha256(
        legacy_v5_row["launch_plan_json"].encode("utf-8")
    ).hexdigest()
    assert journal_module._sandbox_launch_plan_binding_is_self_consistent(legacy_v5_row)

    # Version 4 remains auditable under its original ownership evidence, but
    # does not carry the split-monitor placement contract required for running.
    legacy_v4_plan = json.loads(canonical_json(durable["launch_plan"]))
    legacy_v4_plan["version"] = 4
    legacy_v4_plan["launch"]["systemd_ownership"].pop("monitor_placement")
    old_wrapper_cgroup = f"{durable['attempt_slice_cgroup_path']}/{durable['wrapper_unit']}"
    legacy_v4_plan["launch"]["systemd_ownership"]["wrapper_control_group"] = old_wrapper_cgroup
    legacy_v4_row = dict(durable)
    legacy_v4_row["wrapper_cgroup_path"] = old_wrapper_cgroup
    legacy_v4_row["launch_plan_json"] = canonical_json(legacy_v4_plan)
    legacy_v4_row["launch_plan_digest"] = hashlib.sha256(
        legacy_v4_row["launch_plan_json"].encode("utf-8")
    ).hexdigest()
    assert journal_module._sandbox_launch_plan_binding_is_self_consistent(legacy_v4_row)

    sibling_monitor_cgroup = (
        "/user.slice/user-1000.slice/user@1000.service/app.slice/"
        f"{oci_worker._oci_worker_systemd_slice('sibling-attempt')}/{durable['wrapper_unit']}"
    )
    sibling_plan = json.loads(canonical_json(durable["launch_plan"]))
    sibling_plan["launch"]["systemd_ownership"]["wrapper_control_group"] = sibling_monitor_cgroup
    sibling_row = dict(durable)
    sibling_row["wrapper_cgroup_path"] = sibling_monitor_cgroup
    sibling_row["launch_plan_json"] = canonical_json(sibling_plan)
    sibling_row["launch_plan_digest"] = hashlib.sha256(
        sibling_row["launch_plan_json"].encode("utf-8")
    ).hexdigest()
    assert not journal_module._sandbox_launch_plan_binding_is_self_consistent(sibling_row)

    # Earlier plan versions did not bind an attempt-slice identity and cannot
    # authorize the stronger current launch/running evidence.
    legacy_plan = json.loads(canonical_json(durable["launch_plan"]))
    legacy_plan["version"] = 1
    legacy_plan["reservation"].pop("bundle_digest_semantics")
    legacy_row = dict(durable)
    legacy_row["bundle_digest_semantics"] = "legacy-caller-asserted-v0"
    legacy_row["launch_plan_json"] = canonical_json(legacy_plan)
    legacy_row["launch_plan_digest"] = hashlib.sha256(
        legacy_row["launch_plan_json"].encode("utf-8")
    ).hexdigest()
    assert not journal_module._sandbox_launch_plan_binding_is_self_consistent(legacy_row)
    legacy_plan["version"] = True
    legacy_row["launch_plan_json"] = canonical_json(legacy_plan)
    legacy_row["launch_plan_digest"] = hashlib.sha256(
        legacy_row["launch_plan_json"].encode("utf-8")
    ).hexdigest()
    assert not journal_module._sandbox_launch_plan_binding_is_self_consistent(legacy_row)


def test_launch_rejects_forged_reservation_bundle_digest(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    handle = _test_runc_handle(target=_test_runc_target(execution))

    # Simulate a tampered/legacy reservation row; the immutable trigger is
    # tested separately, while this proves launch independently re-derives it.
    with supervisor.connect() as connection:
        connection.execute("DROP TRIGGER sandbox_execution_identity_immutable")
        connection.execute(
            "UPDATE sandbox_executions SET bundle_digest = ? WHERE attempt_id = ?",
            ("a" * 64, attempt["id"]),
        )

    with pytest.raises(SupervisorError) as mismatch:
        record_launch(supervisor, attempt, runc_handle=handle)

    assert mismatch.value.code == "sandbox_execution_bundle_digest_mismatch"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "reserved"


def test_launch_rejects_legacy_caller_asserted_reservation_digest(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    handle = _test_runc_handle(target=_test_runc_target(execution))

    # Model a schema-24 reserved row migrated with the legacy default marker.
    with supervisor.connect() as connection:
        connection.execute("DROP TRIGGER sandbox_execution_identity_immutable")
        connection.execute(
            "UPDATE sandbox_executions SET bundle_digest = ?, bundle_digest_semantics = ? "
            "WHERE attempt_id = ?",
            ("a" * 64, "legacy-caller-asserted-v0", attempt["id"]),
        )

    with pytest.raises(SupervisorError) as legacy:
        record_launch(supervisor, attempt, runc_handle=handle)

    assert legacy.value.code == "sandbox_execution_legacy_bundle_digest"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "reserved"


def test_direct_sql_cannot_claim_host_derived_reservation_provenance(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = {
        "attempt_id": attempt["id"],
        "claim_token": attempt["claim_token"],
        "execution_id": "forged-execution",
        "backend": "oci-runc",
        "container_id": "forged-container",
        "rootfs_digest": "a" * 64,
        "rootfs_closure_digest": "b" * 64,
        "runc_executable_digest": "c" * 64,
        "runtime_version": "1.3.5",
        "oci_version": "1.2.1",
        "bundle_path": f"{repo}/.acp/sandbox-executions/forged/bundle",
        "state_path": f"{repo}/.acp/sandbox-executions/forged/state",
    }
    bundle_digest = journal_module._sandbox_reservation_bundle_digest(execution)

    with supervisor.connect() as connection:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="sandbox_execution_reservation_authorization_required",
        ):
            connection.execute(
                """
                INSERT INTO sandbox_executions
                  (attempt_id, claim_token, execution_id, backend, container_id,
                   bundle_digest, bundle_digest_semantics, launch_plan_required,
                   rootfs_digest, rootfs_closure_digest, runc_executable_digest,
                   runtime_version, oci_version, bundle_path, state_path, phase,
                   created_at, updated_at)
                VALUES (?, ?, ?, 'oci-runc', ?, ?, 'oci-reservation-v1', 1,
                        ?, ?, ?, ?, ?, ?, ?, 'reserved', 'now', 'now')
                """,
                (
                    execution["attempt_id"],
                    execution["claim_token"],
                    execution["execution_id"],
                    execution["container_id"],
                    bundle_digest,
                    execution["rootfs_digest"],
                    execution["rootfs_closure_digest"],
                    execution["runc_executable_digest"],
                    execution["runtime_version"],
                    execution["oci_version"],
                    execution["bundle_path"],
                    execution["state_path"],
                ),
            )

    assert supervisor._sandbox_execution_get(attempt["id"]) is None


def test_v25_bundle_digest_semantics_migration_preserves_and_freezes_legacy_rows() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.execute(
            """
            CREATE TABLE sandbox_executions (
              attempt_id TEXT PRIMARY KEY,
              claim_token INTEGER NOT NULL,
              execution_id TEXT NOT NULL,
              backend TEXT NOT NULL,
              container_id TEXT NOT NULL,
              bundle_digest TEXT NOT NULL,
              rootfs_digest TEXT NOT NULL,
              rootfs_closure_digest TEXT NOT NULL,
              runc_executable_digest TEXT NOT NULL,
              runtime_version TEXT NOT NULL,
              oci_version TEXT NOT NULL,
              bundle_path TEXT NOT NULL,
              state_path TEXT NOT NULL,
              phase TEXT NOT NULL DEFAULT 'reserved',
              created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO sandbox_executions VALUES
              ('attempt-old', 7, 'execution-old', 'oci-runc', 'container-old', ?, ?, ?, ?,
               '1.3.5', '1.2.1', '/bundle-old', '/state-old', 'reserved', 'now')
            """,
            ("f" * 64, "a" * 64, "b" * 64, "c" * 64),
        )

        migrations = dict(MIGRATIONS)
        migrations[25](connection)
        migrations[25](connection)
        migrations[26](connection)
        migrations[26](connection)

        row = connection.execute(
            "SELECT bundle_digest, bundle_digest_semantics, phase, wrapper_cgroup_path, "
            "attempt_slice_unit, attempt_slice_invocation_id, attempt_slice_cgroup_path "
            "FROM sandbox_executions "
            "WHERE attempt_id = 'attempt-old'"
        ).fetchone()
        assert row["bundle_digest"] == "f" * 64
        assert row["bundle_digest_semantics"] == "legacy-caller-asserted-v0"
        assert row["phase"] == "reserved"
        assert row["wrapper_cgroup_path"] == ""
        assert row["attempt_slice_unit"] == ""
        assert row["attempt_slice_invocation_id"] == ""
        assert row["attempt_slice_cgroup_path"] == ""
        with pytest.raises(sqlite3.IntegrityError, match="identity_immutable"):
            connection.execute(
                "UPDATE sandbox_executions SET bundle_digest_semantics = 'oci-reservation-v1' "
                "WHERE attempt_id = 'attempt-old'"
            )
        with pytest.raises(
            sqlite3.IntegrityError, match="sandbox_execution_attempt_slice_identity_required"
        ):
            connection.execute(
                "UPDATE sandbox_executions SET phase = 'launched' WHERE attempt_id = 'attempt-old'"
            )
        assert (
            connection.execute(
                "SELECT phase FROM sandbox_executions WHERE attempt_id = 'attempt-old'"
            ).fetchone()["phase"]
            == "reserved"
        )
    finally:
        connection.close()


def test_generic_transition_cannot_forge_launch_plan_binding(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    target = _test_runc_target(execution)
    updates = launch_transition_updates(execution, target)
    authorize_test_launch_submission(supervisor, attempt, target)

    with pytest.raises(sqlite3.IntegrityError, match="sandbox_launch_plan_binding_required"):
        supervisor._sandbox_execution_transition(
            attempt["id"],
            attempt["claim_token"],
            expected_phase="reserved",
            next_phase="launched",
            updates=updates,
            event_type="sandbox.execution_launched",
            event_payload=updates,
        )

    columns = ", ".join(f"{name} = ?" for name in updates)
    with (
        supervisor.connect() as connection,
        pytest.raises(sqlite3.IntegrityError, match="sandbox_launch_plan_binding_required"),
    ):
        connection.execute(
            f"UPDATE sandbox_executions SET {columns}, phase = 'launched' "
            "WHERE attempt_id = ? AND claim_token = ? AND phase = 'reserved'",
            (*updates.values(), attempt["id"], attempt["claim_token"]),
        )

    row = supervisor._sandbox_execution_get(attempt["id"])
    assert row["phase"] == "reserved"
    assert row["launch_plan_binding_version"] == 0
    assert row["launch_plan_json"] == ""
    assert row["wrapper_cgroup_path"] == ""
    assert row["attempt_slice_unit"] == ""
    assert row["attempt_slice_invocation_id"] == ""
    assert row["attempt_slice_cgroup_path"] == ""


@pytest.mark.parametrize("mismatch", ["config", "argv"])
def test_launch_transition_rejects_mismatched_config_or_argv(repo: Path, mismatch: str) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    target = _test_runc_target(execution)
    updates = launch_transition_updates(execution, target)
    authorize_test_launch_submission(supervisor, attempt, target)
    plan = json.loads(updates["launch_plan_json"])
    if mismatch == "config":
        plan["launch"]["config_sha256"] = "f" * 64
    else:
        plan["launch"]["argv"].append("--unexpected")
        plan["launch"]["argv_sha256"] = hashlib.sha256(
            canonical_json(plan["launch"]["argv"]).encode("utf-8")
        ).hexdigest()
    updates["launch_plan_json"] = canonical_json(plan)
    updates["launch_plan_digest"] = hashlib.sha256(
        updates["launch_plan_json"].encode("utf-8")
    ).hexdigest()

    with pytest.raises(SupervisorError) as error:
        supervisor._sandbox_execution_transition(
            attempt["id"],
            attempt["claim_token"],
            expected_phase="reserved",
            next_phase="launched",
            updates=updates,
            event_type="sandbox.execution_launched",
            event_payload=updates,
        )

    assert error.value.code == "sandbox_execution_launch_plan_invalid"
    row = supervisor._sandbox_execution_get(attempt["id"])
    assert row["phase"] == "reserved"
    assert row["launch_plan_binding_version"] == 0


def test_launch_plan_binding_is_write_once(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    record_launch(supervisor, attempt)
    original = supervisor._sandbox_execution_get(attempt["id"])["launch_plan_digest"]
    changed = ("1" if original[0] == "0" else "0") * 64

    with (
        supervisor.connect() as connection,
        pytest.raises(sqlite3.IntegrityError, match="sandbox_launch_plan_binding_required"),
    ):
        connection.execute(
            "UPDATE sandbox_executions SET launch_plan_digest = ? WHERE attempt_id = ?",
            (changed, attempt["id"]),
        )

    row = supervisor._sandbox_execution_get(attempt["id"])
    assert row["phase"] == "launched"
    assert row["launch_plan_digest"] == original
    assert row["launch_plan_digest"] != changed
    assert journal_module._sandbox_launch_plan_binding_is_self_consistent(row)


def test_launch_plan_transition_rolls_back_and_replays_after_event_failure(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    handle = _test_runc_handle(target=_test_runc_target(execution))
    original_event = supervisor._event

    def fail_launch_event(connection, event_type: str, actor: str, payload: dict) -> None:
        if event_type == "sandbox.execution_launched":
            raise RuntimeError("injected crash before launch transaction commit")
        original_event(connection, event_type, actor, payload)

    monkeypatch.setattr(supervisor, "_event", fail_launch_event)
    with pytest.raises(RuntimeError, match="injected crash"):
        record_launch(supervisor, attempt, runc_handle=handle)
    after_failure = supervisor._sandbox_execution_get(attempt["id"])
    assert after_failure["phase"] == "reserved"
    assert after_failure["launch_plan_binding_version"] == 0
    assert after_failure["launch_plan_json"] == ""
    with supervisor.connect() as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM events WHERE event_type = 'sandbox.execution_launched'"
            ).fetchone()[0]
            == 0
        )

    monkeypatch.setattr(supervisor, "_event", original_event)
    replayed = record_launch(supervisor, attempt, runc_handle=handle)
    assert replayed["phase"] == "launched"
    assert journal_module._sandbox_launch_plan_binding_is_self_consistent(replayed)
    assert supervisor.verify_event_chain()["ok"] is True


def test_launch_plan_survives_reopen_but_does_not_recover_dead_handle(
    repo: Path,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    handle = _test_runc_handle(target=_test_runc_target(execution))
    record_launch(supervisor, attempt, runc_handle=handle)
    registry_entry = oci_worker._RUNC_LAUNCH_RECORDS.pop(id(handle))
    try:
        reopened = GitSupervisor(repo)
        durable = reopened._sandbox_execution_get(attempt["id"])
        assert durable["phase"] == "launched"
        assert journal_module._sandbox_launch_plan_binding_is_self_consistent(durable)
        with pytest.raises(SupervisorError) as missing_handle:
            reopened._sandbox_execution_record_running(
                attempt["id"],
                attempt["claim_token"],
                attestation=running_attestation(reopened, attempt),
                runc_handle=handle,
            )
        assert missing_handle.value.code == "sandbox_execution_launch_handle_required"
        assert reopened._sandbox_execution_get(attempt["id"])["phase"] == "launched"
    finally:
        oci_worker._RUNC_LAUNCH_RECORDS[id(handle)] = registry_entry


def test_concurrent_launch_plan_binding_has_one_durable_winner(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    handle = _test_runc_handle(target=_test_runc_target(execution))
    barrier = threading.Barrier(2)

    def race_launch() -> tuple[str, object]:
        barrier.wait(timeout=3)
        try:
            return "ok", record_launch(
                supervisor,
                attempt,
                runc_handle=handle,
                patch_monitor_starter=False,
            )
        except SupervisorError as error:
            return "error", error

    with patch(
        "agent_control_plane.supervisor.sandbox_monitor_service.start_sandbox_execution_monitor",
        side_effect=_record_launch_monitor_for_thread,
    ):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = [
                future.result(timeout=5)
                for future in (pool.submit(race_launch), pool.submit(race_launch))
            ]

    assert [kind for kind, _ in results].count("ok") == 1
    errors = [value for kind, value in results if kind == "error"]
    assert len(errors) == 1
    assert isinstance(errors[0], SupervisorError)
    assert errors[0].code in {
        "sandbox_execution_transition_invalid",
        "sandbox_execution_launch_submission_exists",
        "sandbox_launch_driver_start_ambiguous",
        "sandbox_launch_driver_redemption_ambiguous",
    }
    durable = supervisor._sandbox_execution_get(attempt["id"])
    assert durable["phase"] == "launched"
    assert durable["launch_plan_binding_version"] == 1
    assert journal_module._sandbox_launch_plan_binding_is_self_consistent(durable)
    with supervisor.connect() as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM events WHERE event_type = 'sandbox.execution_launched'"
            ).fetchone()[0]
            == 1
        )


def test_public_gate_release_requires_exact_durable_running_transition(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    try:
        record_launch(supervisor, attempt, runc_handle=handle)

        with pytest.raises(SupervisorError) as premature:
            handle.release_gate()
        assert premature.value.code == "sandbox_launch_gate_not_authorized"
        assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"

        unrelated = _test_runc_handle(target=_test_runc_target(execution))
        with pytest.raises(SupervisorError) as wrong_handle:
            supervisor._sandbox_execution_record_running(
                attempt["id"],
                attempt["claim_token"],
                attestation=running_attestation(supervisor, attempt),
                runc_handle=unrelated,
            )
        assert wrong_handle.value.code == "sandbox_execution_launch_handle_required"
        assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"

        running = record_running(supervisor, attempt)
        assert running["phase"] == "running"
        assert running["launch_driver_pid"] == os.getpid()
        assert running["launch_driver_identity"].startswith(f"linux:{os.getpid()}:")
        assert running["launch_driver_unit"] == journal_module._sandbox_launch_driver_service_unit(
            running["execution_id"]
        )
        assert running["launch_driver_invocation_id"] == "4" * 32
        assert running["launch_driver_cgroup_path"] == (
            f"{running['attempt_slice_cgroup_path']}/{running['launch_driver_unit']}"
        )
        with supervisor.connect() as connection:
            with pytest.raises(
                sqlite3.IntegrityError,
                match="sandbox_execution_driver_identity_requires_collector_receipt",
            ):
                connection.execute(
                    "UPDATE sandbox_executions SET launch_driver_pid = launch_driver_pid "
                    "WHERE attempt_id = ?",
                    (attempt["id"],),
                )
        handle.release_gate()
        assert os.read(gate_read, 3) == b"go\n"
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_running_transition_rejects_caller_constructed_receipt_before_gate_release(
    repo: Path,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        caller_constructed = running_attestation(supervisor, attempt, register_collected=False)

        assert running_attestation_is_self_consistent(caller_constructed)
        assert not running_attestation_has_collector_provenance(caller_constructed)
        with pytest.raises(SupervisorError) as rejected:
            supervisor._sandbox_execution_record_running(
                attempt["id"],
                attempt["claim_token"],
                attestation=caller_constructed,
                runc_handle=handle,
            )

        assert rejected.value.code == "sandbox_runtime_attestation_invalid"
        assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"
        with pytest.raises(SupervisorError) as gate_rejected:
            handle.release_gate()
        assert gate_rejected.value.code == "sandbox_launch_gate_not_authorized"
        os.set_blocking(gate_read, False)
        with pytest.raises(BlockingIOError):
            os.read(gate_read, 3)
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_direct_sql_cannot_use_collector_receipt_without_validated_running_path(
    repo: Path,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        attestation = running_attestation(supervisor, attempt)
        assert running_attestation_has_collector_provenance(attestation)
        with supervisor.connect() as connection:
            cursor = connection.execute("SELECT 1")
            with pytest.raises(AttributeError):
                object.__getattribute__(connection, "_StoreConnection__raw")
            with pytest.raises(AttributeError):
                object.__getattribute__(cursor, "_StoreCursor__raw")
            with connection as nested_connection:
                assert nested_connection is connection
            with pytest.raises(AttributeError, match="row_factory is reserved"):
                connection.row_factory = lambda cursor, row: cursor.connection
            with pytest.raises(TypeError, match="custom cursor factories"):
                connection.cursor(factory=lambda raw: raw)
            with pytest.raises(AttributeError, match="raw store connections are private"):
                assert connection.execute("SELECT 1").connection is not None
            with pytest.raises(AttributeError, match="raw store connections are private"):
                assert connection.cursor().connection is not None
            with pytest.raises(TypeError):
                sqlite3.Connection.create_function(
                    connection,
                    "acp_sandbox_running_attestation_authorized",
                    8,
                    lambda *_: 1,
                )
            with pytest.raises(AttributeError, match="reserved by the store"):
                connection.create_function(
                    "acp_sandbox_running_attestation_authorized", 8, lambda *_: 1
                )
            with pytest.raises(AttributeError, match="reserved by the store"):
                connection.create_aggregate("acp_sandbox_running_attestation_authorized", 8, object)
            with pytest.raises(AttributeError, match="reserved by the store"):
                connection.create_window_function(
                    "acp_sandbox_running_attestation_authorized", 8, object
                )
            with pytest.raises(
                sqlite3.IntegrityError,
                match="sandbox_execution_driver_identity_requires_collector_receipt",
            ):
                connection.execute(
                    "UPDATE sandbox_executions SET phase = 'running', init_pid = ?, "
                    "init_identity = ?, launch_driver_pid = ?, launch_driver_identity = ?, "
                    "launch_driver_unit = ?, launch_driver_invocation_id = ?, "
                    "launch_driver_cgroup_path = ? WHERE attempt_id = ?",
                    (
                        attestation.init_pid,
                        attestation.init_identity,
                        attestation.launch_driver_pid,
                        attestation.launch_driver_identity,
                        attestation.launch_driver_unit,
                        attestation.launch_driver_invocation_id,
                        attestation.launch_driver_control_group,
                        attempt["id"],
                    ),
                )

        assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"
        with pytest.raises(SupervisorError) as gate_rejected:
            handle.release_gate()
        assert gate_rejected.value.code == "sandbox_launch_gate_not_authorized"
        os.set_blocking(gate_read, False)
        with pytest.raises(BlockingIOError):
            os.read(gate_read, 3)
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_transition_helper_cannot_authorize_caller_constructed_driver_identity(
    repo: Path,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    handle = _test_runc_handle(target=_test_runc_target(execution))
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        attestation = running_attestation(supervisor, attempt, register_collected=False)
        updates = {
            "init_pid": attestation.init_pid,
            "init_identity": attestation.init_identity,
            "launch_driver_pid": attestation.launch_driver_pid,
            "launch_driver_identity": attestation.launch_driver_identity,
            "launch_driver_unit": attestation.launch_driver_unit,
            "launch_driver_invocation_id": attestation.launch_driver_invocation_id,
            "launch_driver_cgroup_path": attestation.launch_driver_control_group,
        }
        with pytest.raises(SupervisorError) as rejected:
            supervisor._sandbox_execution_transition(
                attempt["id"],
                attempt["claim_token"],
                expected_phase="launched",
                next_phase="running",
                updates=updates,
                event_type="sandbox.execution_running",
                event_payload={"attestation": attestation.audit_payload()},
                running_attestation=attestation,
            )

        assert rejected.value.code == "sandbox_runtime_attestation_invalid"
        assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"
        with pytest.raises(SupervisorError) as gate_rejected:
            handle.release_gate()
        assert gate_rejected.value.code == "sandbox_launch_gate_not_authorized"
    finally:
        handle.close_gate()


def test_transition_helper_rejects_collector_receipt_from_another_execution(
    repo: Path,
) -> None:
    supervisor = GitSupervisor(repo)
    source = claimed(supervisor, "receipt-source.txt")
    source_execution = reserve(supervisor, source)
    source_handle = _test_runc_handle(target=_test_runc_target(source_execution))
    record_launch(supervisor, source, runc_handle=source_handle)

    target = claimed(supervisor, "receipt-target.txt")
    target_execution = reserve(supervisor, target)
    target_handle = _test_runc_handle(target=_test_runc_target(target_execution))
    record_launch(supervisor, target, runc_handle=target_handle)
    try:
        attestation = running_attestation(supervisor, source)
        assert running_attestation_has_collector_provenance(attestation)
        updates = {
            "init_pid": attestation.init_pid,
            "init_identity": attestation.init_identity,
            "launch_driver_pid": attestation.launch_driver_pid,
            "launch_driver_identity": attestation.launch_driver_identity,
            "launch_driver_unit": attestation.launch_driver_unit,
            "launch_driver_invocation_id": attestation.launch_driver_invocation_id,
            "launch_driver_cgroup_path": attestation.launch_driver_control_group,
        }

        with pytest.raises(SupervisorError) as rejected:
            supervisor._sandbox_execution_transition(
                target["id"],
                target["claim_token"],
                expected_phase="launched",
                next_phase="running",
                updates=updates,
                event_type="sandbox.execution_running",
                event_payload={"attestation": attestation.audit_payload()},
                running_attestation=attestation,
            )

        assert rejected.value.code == "sandbox_runtime_attestation_invalid"
        target_row = supervisor._sandbox_execution_get(target["id"])
        assert target_row["phase"] == "launched"
        assert target_row["launch_driver_pid"] is None

        target_attestation = running_attestation(supervisor, target)
        assert running_attestation_has_collector_provenance(target_attestation)
        with pytest.raises(SupervisorError) as direct_rejected:
            supervisor._sandbox_execution_transition(
                target["id"],
                target["claim_token"],
                expected_phase="launched",
                next_phase="running",
                updates={
                    "init_pid": target_attestation.init_pid,
                    "init_identity": target_attestation.init_identity,
                    "launch_driver_pid": target_attestation.launch_driver_pid,
                    "launch_driver_identity": target_attestation.launch_driver_identity,
                    "launch_driver_unit": target_attestation.launch_driver_unit,
                    "launch_driver_invocation_id": (target_attestation.launch_driver_invocation_id),
                    "launch_driver_cgroup_path": (target_attestation.launch_driver_control_group),
                },
                event_type="sandbox.execution_running",
                event_payload={"attestation": target_attestation.audit_payload()},
                running_attestation=target_attestation,
            )
        assert direct_rejected.value.code == "sandbox_runtime_attestation_invalid"
        assert supervisor._sandbox_execution_get(target["id"])["phase"] == "launched"
        with pytest.raises(SupervisorError) as gate_rejected:
            target_handle.release_gate()
        assert gate_rejected.value.code == "sandbox_launch_gate_not_authorized"
    finally:
        source_handle.close_gate()
        target_handle.close_gate()


@pytest.mark.parametrize("mismatch", ["state_root", "pid_file", "runc_executable"])
def test_running_transition_rejects_collected_runtime_source_mismatch(
    repo: Path,
    mismatch: str,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        source_override: dict[str, object] = {}
        if mismatch == "state_root":
            source_override["state_root_override"] = Path(execution["bundle_path"]).parent
        elif mismatch == "pid_file":
            source_override["pid_file_name_override"] = "other.pid"
        else:
            source_override["runc_executable_sha256"] = "f" * 64
        attestation = running_attestation(supervisor, attempt, **source_override)

        assert running_attestation_is_self_consistent(attestation)
        assert running_attestation_has_collector_provenance(attestation)
        with pytest.raises(SupervisorError) as rejected:
            supervisor._sandbox_execution_record_running(
                attempt["id"],
                attempt["claim_token"],
                attestation=attestation,
                runc_handle=handle,
            )

        assert rejected.value.code == "sandbox_runtime_attestation_stale"
        assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"
        with pytest.raises(SupervisorError) as gate_rejected:
            handle.release_gate()
        assert gate_rejected.value.code == "sandbox_launch_gate_not_authorized"
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_running_transition_rejects_forged_cgroup_limit_before_gate_release(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        attestation = running_attestation(supervisor, attempt)
        forged = replace(attestation, memory_max_bytes=attestation.memory_max_bytes + 1)
        payload = forged.audit_payload()
        payload.pop("evidence_sha256")
        forged = replace(
            forged,
            evidence_sha256=hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest(),
        )
        # Isolate the durable-limit comparison after the provenance guard; replacing
        # a collector receipt ordinarily discards its process-local provenance.
        monkeypatch.setattr(
            journal_module,
            "running_attestation_has_collector_provenance",
            lambda candidate: candidate is forged,
        )

        with pytest.raises(SupervisorError) as mismatch:
            supervisor._sandbox_execution_record_running(
                attempt["id"],
                attempt["claim_token"],
                attestation=forged,
                runc_handle=handle,
            )

        assert mismatch.value.code == "sandbox_runtime_attestation_stale"
        assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"
        with pytest.raises(SupervisorError) as rejected:
            handle.release_gate()
        assert rejected.value.code == "sandbox_launch_gate_not_authorized"
        os.set_blocking(gate_read, False)
        with pytest.raises(BlockingIOError):
            os.read(gate_read, 3)
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_running_transition_rechecks_live_limits_under_gate_lock(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        attestation = running_attestation(supervisor, attempt)
        monkeypatch.setattr(
            sandbox_attestation_module,
            "read_cgroup_resource_controls",
            lambda _path: {
                "memory.max": b"1073741825\n",
                "cpu.max": b"100000 100000\n",
                "pids.max": b"256\n",
            },
        )
        verify_resources = journal_module.verify_running_runtime_resource_controls

        def verify_resources_under_gate_lock(receipt) -> None:
            assert handle._gate_lock.locked()
            verify_resources(receipt)

        monkeypatch.setattr(
            journal_module,
            "verify_running_runtime_resource_controls",
            verify_resources_under_gate_lock,
        )

        with pytest.raises(SupervisorError) as changed:
            supervisor._sandbox_execution_record_running(
                attempt["id"],
                attempt["claim_token"],
                attestation=attestation,
                runc_handle=handle,
            )

        assert changed.value.code == "sandbox_runtime_attestation_stale"
        assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"
        with pytest.raises(SupervisorError) as rejected:
            handle.release_gate()
        assert rejected.value.code == "sandbox_launch_gate_not_authorized"
        os.set_blocking(gate_read, False)
        with pytest.raises(BlockingIOError):
            os.read(gate_read, 3)
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_running_transition_rechecks_process_membership_under_gate_lock(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        attestation = running_attestation(supervisor, attempt)
        monkeypatch.setattr(
            sandbox_attestation_module,
            "read_cgroup_resource_controls",
            lambda _path: {
                "memory.max": f"{attestation.memory_max_bytes}\n".encode("ascii"),
                "cpu.max": f"{attestation.cpu_quota} {attestation.cpu_period}\n".encode("ascii"),
                "pids.max": f"{attestation.pids_max}\n".encode("ascii"),
            },
        )

        def read_moved_process(pid: int) -> ProcessSnapshot:
            snapshot = _live_process_snapshot(attestation, pid)
            if pid == attestation.init_pid:
                return replace(snapshot, cgroup=b"0::/user.slice/foreign.scope\n")
            return snapshot

        monkeypatch.setattr(
            sandbox_attestation_module,
            "read_linux_process_snapshot",
            read_moved_process,
        )
        verify_membership = journal_module.verify_running_runtime_process_membership

        def verify_membership_under_gate_lock(receipt) -> None:
            assert handle._gate_lock.locked()
            verify_membership(receipt)

        monkeypatch.setattr(
            journal_module,
            "verify_running_runtime_process_membership",
            verify_membership_under_gate_lock,
        )
        verify_private_directory = journal_module._private_directory

        def verify_state_root_under_gate_lock(path, **kwargs):
            assert handle._gate_lock.locked()
            return verify_private_directory(path, **kwargs)

        monkeypatch.setattr(
            journal_module,
            "_private_directory",
            verify_state_root_under_gate_lock,
        )

        with pytest.raises(SupervisorError) as moved:
            supervisor._sandbox_execution_record_running(
                attempt["id"],
                attempt["claim_token"],
                attestation=attestation,
                runc_handle=handle,
            )

        assert moved.value.code == "sandbox_runtime_attestation_stale"
        assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"
        with pytest.raises(SupervisorError) as rejected:
            handle.release_gate()
        assert rejected.value.code == "sandbox_launch_gate_not_authorized"
        os.set_blocking(gate_read, False)
        with pytest.raises(BlockingIOError):
            os.read(gate_read, 3)
    finally:
        handle.close_gate()
        os.close(gate_read)


@pytest.mark.parametrize(
    ("changed_unit", "changed_property"),
    [
        (None, None),
        ("wrapper", "MainPID"),
        ("wrapper", "InvocationID"),
        ("wrapper", "ControlGroup"),
        ("launch_driver", "MainPID"),
        ("launch_driver", "InvocationID"),
        ("launch_driver", "ControlGroup"),
        ("slice", "InvocationID"),
        ("scope", "InvocationID"),
    ],
)
def test_running_transition_rechecks_systemd_identity_under_gate_lock(
    repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    changed_unit: str | None,
    changed_property: str | None,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        attestation = running_attestation(supervisor, attempt)
        controls = {
            "memory.max": f"{attestation.memory_max_bytes}\n".encode("ascii"),
            "cpu.max": f"{attestation.cpu_quota} {attestation.cpu_period}\n".encode("ascii"),
            "pids.max": f"{attestation.pids_max}\n".encode("ascii"),
        }
        monkeypatch.setattr(
            sandbox_attestation_module,
            "read_cgroup_resource_controls",
            lambda _path: controls,
        )
        monkeypatch.setattr(
            sandbox_attestation_module,
            "read_linux_process_snapshot",
            lambda pid: _live_process_snapshot(attestation, pid),
        )
        monkeypatch.setattr(
            sandbox_attestation_module,
            "_trusted_systemctl_executable",
            lambda: Path("/usr/bin/systemctl"),
        )
        monkeypatch.setattr(
            sandbox_attestation_module,
            "_trusted_systemd_command_environment",
            lambda: {"LANG": "C", "LC_ALL": "C"},
        )

        def run_systemctl(argv, **_kwargs) -> bytes:
            unit = argv[-1]
            if unit == attestation.wrapper_unit:
                values = {
                    "ActiveState": "active",
                    "ControlGroup": attestation.wrapper_control_group,
                    "Id": attestation.wrapper_unit,
                    "InvocationID": attestation.wrapper_invocation_id,
                    "MainPID": str(attestation.monitor_pid),
                }
            elif unit == attestation.launch_driver_unit:
                values = {
                    "ActiveState": "active",
                    "ControlGroup": attestation.launch_driver_control_group,
                    "Id": attestation.launch_driver_unit,
                    "InvocationID": attestation.launch_driver_invocation_id,
                    "MainPID": str(attestation.launch_driver_pid),
                }
            elif unit == attestation.attempt_slice_unit:
                values = {
                    "ActiveState": "active",
                    "ControlGroup": attestation.attempt_slice_control_group,
                    "Id": attestation.attempt_slice_unit,
                    "InvocationID": attestation.attempt_slice_invocation_id,
                }
            else:
                assert unit == attestation.scope_unit
                values = {
                    "ActiveState": "active",
                    "ControlGroup": attestation.cgroup_path,
                    "Id": attestation.scope_unit,
                    "InvocationID": attestation.scope_invocation_id,
                }
            unit_names = {
                "wrapper": attestation.wrapper_unit,
                "launch_driver": attestation.launch_driver_unit,
                "slice": attestation.attempt_slice_unit,
                "scope": attestation.scope_unit,
            }
            if (
                changed_unit is not None
                and changed_property is not None
                and unit == unit_names[changed_unit]
            ):
                if changed_property == "MainPID":
                    pid = (
                        attestation.launch_driver_pid
                        if changed_unit == "launch_driver"
                        else attestation.monitor_pid
                    )
                    values[changed_property] = str(pid + 1)
                elif changed_property == "InvocationID":
                    values[changed_property] = "f" * 32
                elif changed_property == "ControlGroup":
                    values[changed_property] += "/replaced"
                else:
                    raise AssertionError(f"unexpected systemd property: {changed_property}")
            return "".join(f"{key}={value}\n" for key, value in values.items()).encode("ascii")

        monkeypatch.setattr(
            sandbox_attestation_module, "_run_trusted_runtime_command", run_systemctl
        )
        verify_systemd = sandbox_attestation_module.verify_running_runtime_systemd_units

        def verify_under_gate_lock(receipt) -> None:
            assert handle._gate_lock.locked()
            verify_systemd(receipt)

        monkeypatch.setattr(
            journal_module, "verify_running_runtime_systemd_units", verify_under_gate_lock
        )

        if changed_property is None:
            running = supervisor._sandbox_execution_record_running(
                attempt["id"],
                attempt["claim_token"],
                attestation=attestation,
                runc_handle=handle,
            )
            assert running["phase"] == "running"
            handle.release_gate()
            assert os.read(gate_read, 3) == b"go\n"
            return

        with pytest.raises(SupervisorError) as stale:
            supervisor._sandbox_execution_record_running(
                attempt["id"],
                attempt["claim_token"],
                attestation=attestation,
                runc_handle=handle,
            )

        assert stale.value.code == "sandbox_runtime_attestation_stale"
        assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"
        with pytest.raises(SupervisorError) as rejected:
            handle.release_gate()
        assert rejected.value.code == "sandbox_launch_gate_not_authorized"
        os.set_blocking(gate_read, False)
        with pytest.raises(BlockingIOError):
            os.read(gate_read, 3)
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_stop_before_running_transition_is_recorded_without_gate_release(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        stopped = supervisor._sandbox_execution_request_stop(
            attempt["id"], attempt["claim_token"], "cancel before init"
        )
        assert stopped["phase"] == "launched"
        assert stopped["stop_reason"] == "cancel before init"
        durable = supervisor._sandbox_execution_get(attempt["id"])
        assert durable["phase"] == "launched"
        with supervisor.connect() as connection:
            assert (
                journal_module._sandbox_execution_launch_stop_reason(connection, durable)
                == "cancel before init"
            )
        with pytest.raises(SupervisorError) as rejected:
            handle.release_gate()
        assert rejected.value.code == "sandbox_launch_gate_not_authorized"
        os.set_blocking(gate_read, False)
        with pytest.raises(BlockingIOError):
            os.read(gate_read, 3)
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_stop_after_running_transition_revokes_unconsumed_gate_permit(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        assert record_running(supervisor, attempt)["phase"] == "running"
        assert (
            supervisor._sandbox_execution_request_stop(
                attempt["id"], attempt["claim_token"], "cancel before release"
            )["phase"]
            == "stopping"
        )

        with pytest.raises(SupervisorError) as rejected:
            handle.release_gate()
        assert rejected.value.code == "sandbox_launch_gate_not_authorized"
        os.set_blocking(gate_read, False)
        with pytest.raises(BlockingIOError):
            os.read(gate_read, 3)
    finally:
        handle.close_gate()
        os.close(gate_read)


@pytest.mark.parametrize("phase_before_reconnect", ["launched", "running", "stopping"])
def test_reconnected_supervisor_records_stop_intent_and_keeps_gate_closed(
    repo: Path, phase_before_reconnect: str
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    reason = "cancel after supervisor reconnect"
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        if phase_before_reconnect != "launched":
            assert record_running(supervisor, attempt)["phase"] == "running"
        if phase_before_reconnect == "stopping":
            assert (
                supervisor._sandbox_execution_request_stop(
                    attempt["id"], attempt["claim_token"], reason
                )["phase"]
                == "stopping"
            )

        # A spawned interpreter shares the durable state-root fence and SQLite
        # journal, but has no access to the monitor's process-local handle.
        context = multiprocessing.get_context("spawn")
        result_receiver, result_sender = context.Pipe(duplex=False)
        process = context.Process(
            target=_request_stop_from_fresh_process,
            args=(repo, attempt["id"], attempt["claim_token"], reason, result_sender),
        )
        process.start()
        result_sender.close()
        try:
            assert result_receiver.poll(10), (
                "fresh supervisor process did not return its stop result"
            )
            result = result_receiver.recv()
            process.join(timeout=10)
            assert not process.is_alive(), "fresh supervisor process did not exit"
            assert process.exitcode == 0
            expected_phase = "launched" if phase_before_reconnect == "launched" else "stopping"
            assert result == ("ok", expected_phase)
        finally:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
            result_receiver.close()

        durable = supervisor._sandbox_execution_get(attempt["id"])
        assert durable is not None and durable["phase"] == expected_phase
        if expected_phase == "launched":
            with supervisor.connect() as connection:
                assert (
                    journal_module._sandbox_execution_launch_stop_reason(connection, durable)
                    == reason
                )
        else:
            assert durable["stop_reason"] == reason
        with pytest.raises(SupervisorError) as revoked:
            handle.release_gate()
        assert revoked.value.code == "sandbox_launch_gate_not_authorized"
        os.set_blocking(gate_read, False)
        with pytest.raises(BlockingIOError):
            os.read(gate_read, 3)
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_public_terminate_worker_reconnects_after_supervisor_restart(
    repo: Path,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        assert record_running(supervisor, attempt)["phase"] == "running"
        durable = supervisor._sandbox_execution_get(attempt["id"])
        assert durable is not None
        identity = (attempt["id"], attempt["claim_token"], execution["execution_id"])
        scope = {
            "scope_unit": durable["scope_unit"],
            "scope_invocation_id": durable["scope_invocation_id"],
            "scope_control_group": durable["cgroup_path"],
        }
        with pytest.raises(SupervisorError) as wrong_root:
            with oci_worker._runc_execution_gate_fence(
                _execution_gate_identity(durable)[0],
                durable["execution_root_dev"] + 1,
                durable["execution_root_ino"],
            ):
                pytest.fail("mismatched execution-root identity acquired a lifecycle fence")
        assert wrong_root.value.code == "sandbox_execution_gate_identity_mismatch"

        import fcntl

        execution_root = Path(durable["bundle_path"]).parent
        displaced_root = execution_root.with_name(f"{execution_root.name}.displaced-for-test")
        original_root_identity = os.stat(execution_root)
        original_flock = fcntl.flock

        def replace_state_root_after_lock(descriptor: int, operation: int) -> None:
            original_flock(descriptor, operation)
            if operation & fcntl.LOCK_EX:
                execution_root.rename(displaced_root)
                execution_root.mkdir(mode=0o700)

        with patch("fcntl.flock", side_effect=replace_state_root_after_lock):
            with pytest.raises(SupervisorError) as replaced_root:
                with oci_worker._runc_execution_gate_fence(
                    *_execution_gate_identity(durable),
                ):
                    pytest.fail("replaced execution-root path acquired a lifecycle fence")
        assert replaced_root.value.code == "sandbox_execution_gate_identity_mismatch"
        execution_root.rmdir()
        displaced_root.rename(execution_root)
        restored_root_identity = os.stat(execution_root)
        assert (restored_root_identity.st_dev, restored_root_identity.st_ino) == (
            original_root_identity.st_dev,
            original_root_identity.st_ino,
        )

        with oci_worker._runc_execution_gate_fence(*_execution_gate_identity(durable)):
            context = multiprocessing.get_context("spawn")
            receiver, sender = context.Pipe(duplex=False)
            process = context.Process(
                target=_request_stop_from_fresh_process,
                args=(repo, attempt["id"], attempt["claim_token"], "concurrent-stop", sender),
            )
            process.start()
            sender.close()
            try:
                assert receiver.poll(10), "contending supervisor did not return"
                assert receiver.recv() == ("sandbox_execution_gate_busy", "running")
                process.join(timeout=10)
                assert not process.is_alive()
                assert process.exitcode == 0
            finally:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
                receiver.close()
        assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "running"

        if "fork" in multiprocessing.get_all_start_methods():
            context = multiprocessing.get_context("fork")
            release_receiver, release_sender = context.Pipe(duplex=False)
            acquired_receiver, acquired_sender = context.Pipe(duplex=False)
            process = None
            try:
                with oci_worker._runc_execution_gate_fence(
                    *_execution_gate_identity(durable),
                ):
                    process = context.Process(
                        target=_acquire_gate_fence_after_parent_release,
                        args=(
                            *_execution_gate_identity(durable),
                            next(iter(oci_worker._RUNC_EXECUTION_GATE_LOCK_FDS)),
                            release_receiver,
                            acquired_sender,
                        ),
                    )
                    process.start()
                    release_receiver.close()
                    acquired_sender.close()
                    assert acquired_receiver.poll(5), (
                        "forked child did not report inherited fd state"
                    )
                    assert acquired_receiver.recv() == "inherited-closed"
                release_sender.send(True)
                assert acquired_receiver.poll(5), "forked child retained the inherited flock fd"
                assert acquired_receiver.recv() == "acquired"
                process.join(timeout=5)
                assert process.exitcode == 0
            finally:
                release_sender.close()
                acquired_receiver.close()
                if process is not None and process.is_alive():
                    process.terminate()
                    process.join(timeout=5)

        def invoke_fresh_supervisor() -> tuple:
            context = multiprocessing.get_context("spawn")
            receiver, sender = context.Pipe(duplex=False)
            process = context.Process(
                target=_terminate_worker_from_fresh_supervisor,
                args=(repo, attempt["id"], identity, durable["state_path"], scope, sender),
            )
            process.start()
            sender.close()
            try:
                assert receiver.poll(10), "fresh supervisor did not return terminate_worker result"
                result = receiver.recv()
                process.join(timeout=10)
                assert not process.is_alive(), "fresh supervisor did not exit"
                assert process.exitcode == 0
                return result
            finally:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
                receiver.close()

        first = invoke_fresh_supervisor()
        second = invoke_fresh_supervisor()
        assert first[0] == second[0] == "ok", (first, second)
        assert first[1] == second[1]
        result = first[1]
        assert result["outcome"] == "ok"
        assert result["phase"] == "stopping"
        assert result["monitor_phase"] == "stopping"
        assert result["stop_requested"] is True
        assert result["cleanup_verified"] is False
        assert first[2] == second[2]
        expected_cancel_id = monitor_lifecycle_module.sandbox_monitor_cancel_request_id(identity)
        assert first[2] == [
            ("status", identity, ""),
            ("cancel", identity, expected_cancel_id),
        ]
        assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "stopping"
        with pytest.raises(SupervisorError) as fenced:
            handle.release_gate()
        assert fenced.value.code == "sandbox_launch_gate_not_authorized"
        os.set_blocking(gate_read, False)
        with pytest.raises(BlockingIOError):
            os.read(gate_read, 3)
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_stop_from_launched_revokes_gate_before_running_transition(
    repo: Path,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        receipt = running_attestation(supervisor, attempt)

        stopped = supervisor._sandbox_execution_request_stop(
            attempt["id"], attempt["claim_token"], "terminate_worker"
        )
        assert stopped["phase"] == "launched"
        assert stopped["stop_reason"] == "terminate_worker"
        with pytest.raises(SupervisorError) as rejected:
            handle.release_gate()
        assert rejected.value.code == "sandbox_launch_gate_not_authorized"
        repeated = supervisor._sandbox_execution_request_stop(
            attempt["id"], attempt["claim_token"], "terminate_worker"
        )
        assert repeated["phase"] == "launched"
        assert repeated["stop_reason"] == "terminate_worker"
        with pytest.raises(SupervisorError) as running_rejected:
            supervisor._sandbox_execution_record_running(
                attempt["id"],
                attempt["claim_token"],
                attestation=receipt,
                runc_handle=handle,
            )
        assert running_rejected.value.code == "sandbox_execution_transition_invalid"
        durable = supervisor._sandbox_execution_get(attempt["id"])
        assert durable["phase"] == "launched"
        with supervisor.connect() as connection:
            assert (
                journal_module._sandbox_execution_launch_stop_reason(connection, durable)
                == "terminate_worker"
            )
            stop_intents = connection.execute(
                """
                SELECT COUNT(*)
                FROM events
                WHERE event_type = 'sandbox.execution_stop_requested'
                  AND json_extract(payload_json, '$.phase') = 'launched'
                  AND json_extract(payload_json, '$.attempt_id') = ?
                  AND json_extract(payload_json, '$.claim_token') = ?
                  AND json_extract(payload_json, '$.execution_id') = ?
                """,
                (attempt["id"], attempt["claim_token"], execution["execution_id"]),
            ).fetchone()[0]
            assert stop_intents == 1
        os.set_blocking(gate_read, False)
        with pytest.raises(BlockingIOError):
            os.read(gate_read, 3)
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_stop_cannot_commit_between_running_and_gate_authorization(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    original_gate_authorization = journal_module._authorize_runc_launch_gate_release_locked
    running_commit_finished = threading.Event()
    allow_running_transition_to_return = threading.Event()
    stop_started = threading.Event()
    stop_finished = threading.Event()
    results: dict[str, object] = {}

    def pause_before_gate_authorization(*args, **kwargs):
        running_commit_finished.set()
        assert allow_running_transition_to_return.wait(timeout=3)
        return original_gate_authorization(*args, **kwargs)

    def run_running_transition() -> None:
        try:
            results["running"] = record_running(supervisor, attempt)
        except BaseException as error:
            results["running_error"] = error

    def request_stop() -> None:
        stop_started.set()
        try:
            results["stopped"] = supervisor._sandbox_execution_request_stop(
                attempt["id"], attempt["claim_token"], "concurrent cancel"
            )
        except BaseException as error:
            results["stop_error"] = error
        finally:
            stop_finished.set()

    monkeypatch.setattr(
        journal_module,
        "_authorize_runc_launch_gate_release_locked",
        pause_before_gate_authorization,
    )
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        with ThreadPoolExecutor(max_workers=2) as pool:
            running_future = pool.submit(run_running_transition)
            assert running_commit_finished.wait(timeout=3)
            stop_future = pool.submit(request_stop)
            assert stop_started.wait(timeout=3)
            assert not stop_finished.wait(timeout=0.05)
            allow_running_transition_to_return.set()
            running_future.result(timeout=3)
            stop_future.result(timeout=3)

        assert "running_error" not in results
        assert results["running"]["phase"] == "running"
        assert results["stopped"]["phase"] == "stopping"
        with pytest.raises(SupervisorError) as rejected:
            handle.release_gate()
        assert rejected.value.code == "sandbox_launch_gate_not_authorized"
        os.set_blocking(gate_read, False)
        with pytest.raises(BlockingIOError):
            os.read(gate_read, 3)
    finally:
        allow_running_transition_to_return.set()
        handle.close_gate()
        os.close(gate_read)


@pytest.mark.parametrize("terminal_transition", ["exit", "ambiguous"])
def test_terminal_journal_transition_revokes_unconsumed_gate_permit(
    repo: Path, terminal_transition: str
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        record_running(supervisor, attempt)
        if terminal_transition == "exit":
            assert record_exit(supervisor, attempt)["phase"] == "exited"
        else:
            assert (
                supervisor._sandbox_execution_mark_ambiguous(
                    attempt["id"], attempt["claim_token"], "ambiguous test quarantine"
                )["phase"]
                == "ambiguous"
            )

        with pytest.raises(SupervisorError) as rejected:
            handle.release_gate()
        assert rejected.value.code == "sandbox_launch_gate_not_authorized"
        os.set_blocking(gate_read, False)
        with pytest.raises(BlockingIOError):
            os.read(gate_read, 3)
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_launch_rejects_rootfs_content_that_differs_from_reservation(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    target = replace(_test_runc_target(execution), rootfs_sha256="c" * 64)
    handle = _test_runc_handle(target=target)

    with pytest.raises(SupervisorError) as rootfs_mismatch:
        record_launch(supervisor, attempt, runc_handle=handle)

    assert rootfs_mismatch.value.code == "sandbox_execution_launch_target_mismatch"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "reserved"


def record_launch(
    supervisor: GitSupervisor,
    attempt: dict,
    *,
    runc_handle: oci_worker.RuncLaunchHandle | None = None,
    wrapper_unit: str | None = None,
    wrapper_cgroup_path: str | None = None,
    monitor_start_calls: list[dict[str, Any]] | None = None,
    monitor_start_error: Exception | None = None,
    monitor_start_hook: Callable[[dict[str, Any]], None] | None = None,
    patch_monitor_starter: bool = True,
) -> dict:
    if runc_handle is None:
        execution = supervisor._sandbox_execution_get(attempt["id"])
        assert execution is not None
        runc_handle = _test_runc_handle(target=_test_runc_target(execution))
    attempt["_test_runc_handle"] = runc_handle
    execution = supervisor._sandbox_execution_get(attempt["id"])
    assert execution is not None
    launch_record = oci_worker._runc_launch_record(runc_handle)
    launch_target = (
        launch_record.target
        if launch_record is not None
        else (_test_runc_launch_spec(runc_handle) or {}).get("target")
    )
    launch_submission = attempt.get("_test_launch_submission")
    if launch_record is None and launch_target is not None:
        if launch_target.launch_mode == "private_bundle" and launch_submission is None:
            # The synthetic launcher calls the durable callback first, then
            # captures its returned capability in the exact registered handle.
            launch_submission = authorize_test_launch_submission(supervisor, attempt, launch_target)
            attempt["_test_launch_submission"] = launch_submission
        _register_test_runc_launch(
            runc_handle,
            launch_submission=launch_submission,
        )
        launch_record = oci_worker._runc_launch_record(runc_handle)
    if launch_record is not None and launch_submission is None:
        launch_submission = launch_record.launch_submission
    if launch_target is None and launch_record is not None:
        launch_target = launch_record.target
    if launch_target is not None and launch_submission is None:
        launch_submission = attempt.get("_test_launch_submission")
    if launch_submission is not None:
        attempt["_test_launch_submission"] = launch_submission
    slice_unit = oci_worker._oci_worker_systemd_slice(execution["container_id"])
    common_cgroup = "/user.slice/user-1000.slice/user@1000.service/user-acp.slice"
    wrapper_unit = wrapper_unit or journal_module._sandbox_monitor_service_unit(
        attempt["id"], attempt["claim_token"], execution["execution_id"]
    )
    slice_cgroup = common_cgroup + "/" + slice_unit
    receipt_fields = {
        "controller_pid": 202,
        "attempt_id": attempt["id"],
        "claim_token": attempt["claim_token"],
        "execution_id": execution["execution_id"],
        "unit": wrapper_unit,
        "invocation_id": "1" * 32,
        "control_group": wrapper_cgroup_path or f"{common_cgroup}/{wrapper_unit}",
        "main_pid": 101,
        "main_identity": "linux:101:1101",
        "monitor_slice_unit": "user-acp.slice",
        "monitor_slice_control_group": common_cgroup,
        "attempt_slice_unit": slice_unit,
        "attempt_slice_control_group": slice_cgroup,
    }
    try:
        receipt = SandboxMonitorReceipt(**receipt_fields)
    except ValueError:
        # Malformed systemd receipt fixtures model a compromised producer; the
        # launch recorder must reject them before writing the durable phase.
        receipt = SimpleNamespace(**receipt_fields)
    client = SimpleNamespace(
        _receipt=receipt,
        status=lambda: SimpleNamespace(
            outcome="ok",
            payload={
                "phase": "running",
                "scope_unit": "acp-container.scope",
                "scope_invocation_id": "2" * 32,
                "scope_control_group": f"{slice_cgroup}/acp-container.scope",
            },
        ),
    )

    def start_monitor(**kwargs: Any) -> Any:
        if monitor_start_calls is not None:
            monitor_start_calls.append(kwargs)
        if monitor_start_hook is not None:
            monitor_start_hook(kwargs)
        if monitor_start_error is not None:
            raise monitor_start_error
        return client

    def record() -> dict:
        return supervisor._sandbox_execution_record_launch(
            attempt["id"],
            attempt["claim_token"],
            runc_handle=runc_handle,
            launch_submission=launch_submission,
            attempt_slice_unit=slice_unit,
            attempt_slice_invocation_id="3" * 32,
            attempt_slice_cgroup_path=slice_cgroup,
            scope_unit="acp-container.scope",
            scope_invocation_id="2" * 32,
            cgroup_path=f"{slice_cgroup}/acp-container.scope",
        )

    if patch_monitor_starter:
        with patch(
            "agent_control_plane.supervisor.sandbox_monitor_service.start_sandbox_execution_monitor",
            side_effect=start_monitor,
        ):
            return record()

    previous_starter = getattr(_RECORD_LAUNCH_MONITOR, "starter", None)
    _RECORD_LAUNCH_MONITOR.starter = start_monitor
    try:
        return record()
    finally:
        if previous_starter is None:
            del _RECORD_LAUNCH_MONITOR.starter
        else:
            _RECORD_LAUNCH_MONITOR.starter = previous_starter


def test_launch_starts_monitor_for_exact_fenced_scope_and_uses_service_receipt(
    repo: Path,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    calls: list[dict[str, Any]] = []

    launched = record_launch(supervisor, attempt, monitor_start_calls=calls)

    assert len(calls) == 1
    assert calls[0] == {
        "state_path": execution["state_path"],
        "expected_identity": (attempt["id"], attempt["claim_token"], execution["execution_id"]),
        "scope_unit": "acp-container.scope",
        "scope_invocation_id": "2" * 32,
        "scope_control_group": launched["cgroup_path"],
        "attempt_slice_control_group": launched["attempt_slice_cgroup_path"],
    }
    assert launched["monitor_pid"] == 101
    assert launched["monitor_identity"] == "linux:101:1101"
    assert launched["wrapper_unit"] == journal_module._sandbox_monitor_service_unit(
        attempt["id"], attempt["claim_token"], execution["execution_id"]
    )
    assert launched["wrapper_cgroup_path"].endswith("/" + launched["wrapper_unit"])


@pytest.mark.parametrize(
    "failure_point",
    ["timeout", "post-launch-exception", "lease-expired", "lease-expired-after-stop"],
)
def test_registered_launch_driver_fake_worker_opens_gate_only_after_running_and_keeps_fence(
    monkeypatch: pytest.MonkeyPatch, repo: Path, failure_point: str
) -> None:
    """Exercise admitted registered orchestration without systemd, runc, or model calls."""

    if os.geteuid() == 0:
        pytest.skip("the real launch-driver entrypoint refuses a root caller")
    supervisor = GitSupervisor(repo)
    supervisor.config = replace(
        supervisor.config,
        runtime_port_pools=(RuntimePortPool("ACP_TEST_PORT", 24002, 24002),),
    )
    supervisor._port_available = lambda _port: True
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    identity = (attempt["id"], attempt["claim_token"], execution["execution_id"])
    request = launch_driver_service._validate_request(
        expected_identity=identity,
        command=("fake-worker", "--no-model"),
        memory_max_bytes=1_073_741_824,
        cpu_quota=100_000,
        cpu_period=100_000,
        pids_max=256,
        timeout_seconds=2,
    )
    request_path = launch_driver_service._state_request_path(supervisor, execution)
    request_digest = launch_driver_service._write_request(request_path, request)
    intent = supervisor._sandbox_execution_authorize_launch_driver_start(
        attempt["id"], attempt["claim_token"], launch_request_digest=request_digest
    )
    redemption = collect_test_launch_driver_redemption(supervisor, attempt)
    target = _test_runc_target(execution)
    spawn_calls: list[oci_worker._RuncLaunchTarget] = []
    wait_calls: list[float | None] = []
    original_wait = oci_worker.RuncLaunchHandle.wait

    def timeout_once(
        exact_handle: oci_worker.RuncLaunchHandle, timeout: float | None = None
    ) -> Any:
        wait_calls.append(timeout)
        if timeout is not None and len(wait_calls) == 1:
            time.sleep(timeout)
            raise subprocess.TimeoutExpired("pinned-runc", timeout)
        return original_wait(exact_handle, timeout)

    monkeypatch.setattr(oci_worker.RuncLaunchHandle, "wait", timeout_once)
    fake_config = object()
    fake_runtime_binding = object()
    monkeypatch.setattr(
        oci_worker, "build_oci_worker_config", lambda *_args, **_kwargs: fake_config
    )
    monkeypatch.setattr(
        oci_worker,
        "_apply_pinned_runc_recursive_private_policy",
        lambda _config, _pin, *, expected_version: fake_runtime_binding,
    )
    monkeypatch.setattr(
        journal_module,
        "collect_launch_driver_start_redemption",
        lambda **_kwargs: redemption,
    )
    monkeypatch.setattr(
        launch_driver_service,
        "collect_launch_driver_start_redemption",
        lambda **_kwargs: redemption,
    )
    monkeypatch.setattr(
        journal_module,
        "verify_linux_process_membership",
        lambda _pid, *, expected_cgroup, expected_identity: expected_identity,
    )

    attempt_slice = sandbox_attempt_slice_unit(*identity)
    scope_unit = f"acp-{execution['container_id']}.scope"
    common_cgroup = "/user.slice/user-1000.slice/user@1000.service/user-acp.slice"
    slice_cgroup = f"{common_cgroup}/{attempt_slice}"
    scope_cgroup = f"{slice_cgroup}/{scope_unit}"

    def unit_properties(unit: str, properties: tuple[str, ...]) -> dict[str, str]:
        values = {
            "ActiveState": "active",
            "ControlGroup": slice_cgroup if unit == attempt_slice else scope_cgroup,
            "Id": unit,
            "InvocationID": "3" * 32 if unit == attempt_slice else "2" * 32,
        }
        assert unit in {attempt_slice, scope_unit}
        return {name: values[name] for name in properties}

    monkeypatch.setattr(launch_driver_service, "_unit_properties", unit_properties)

    if failure_point in {"lease-expired", "lease-expired-after-stop"}:
        original_heartbeat = supervisor.heartbeat
        request_stop_before_driver = supervisor._sandbox_execution_request_stop
        heartbeat_calls = 0

        def expire_lease_after_running(*args: Any, **kwargs: Any) -> Any:
            nonlocal heartbeat_calls
            result = original_heartbeat(*args, **kwargs)
            heartbeat_calls += 1
            if heartbeat_calls == 2:
                if failure_point == "lease-expired-after-stop":
                    stopping = request_stop_before_driver(
                        attempt["id"], attempt["claim_token"], "attempt cancellation"
                    )
                    assert stopping["phase"] == "stopping"
                with supervisor.connect() as connection:
                    connection.execute(
                        "UPDATE attempts SET lease_expires_at = 0 WHERE id = ?",
                        (attempt["id"],),
                    )
                if failure_point == "lease-expired-after-stop":
                    supervisor.reap_expired()
            return result

        monkeypatch.setattr(supervisor, "heartbeat", expire_lease_after_running)

    monitor_clients: list[monitor_ipc_module.SandboxMonitorControlClient] = []

    def fake_start_monitor(**_kwargs: Any) -> Any:
        wrapper_unit = journal_module._sandbox_monitor_service_unit(*identity)
        receipt = SandboxMonitorReceipt(
            controller_pid=os.getpid(),
            attempt_id=attempt["id"],
            claim_token=attempt["claim_token"],
            execution_id=execution["execution_id"],
            unit=wrapper_unit,
            invocation_id="1" * 32,
            control_group=f"{common_cgroup}/{wrapper_unit}",
            main_pid=101,
            main_identity="linux:101:1101",
            monitor_slice_unit="user-acp.slice",
            monitor_slice_control_group=common_cgroup,
            attempt_slice_unit=attempt_slice,
            attempt_slice_control_group=slice_cgroup,
        )
        client = object.__new__(monitor_ipc_module.SandboxMonitorControlClient)
        client._receipt = receipt
        client.status = lambda: SimpleNamespace(
            outcome="ok",
            payload={
                "phase": "running",
                "scope_unit": scope_unit,
                "scope_invocation_id": "2" * 32,
                "scope_control_group": scope_cgroup,
            },
        )
        monitor_clients.append(client)
        return client

    monkeypatch.setattr(
        "agent_control_plane.supervisor.sandbox_monitor_service.start_sandbox_execution_monitor",
        fake_start_monitor,
    )

    handle: oci_worker.RuncLaunchHandle | None = None

    def fake_spawn(
        _runtime_binding: Any,
        _state_root: Path,
        _bundle_root: Path,
        _workspace_root: Path,
        pid_file: Path,
        _container_id: str,
        *,
        stdout: int,
        stderr: int,
        _authorize_runc_submission: Callable[[oci_worker._RuncLaunchTarget], Any],
    ) -> oci_worker.RuncLaunchHandle:
        assert stdout == subprocess.DEVNULL and stderr == subprocess.DEVNULL
        assert handle is not None
        spawn_calls.append(target)
        submission = _authorize_runc_submission(target)
        _register_test_runc_launch(handle, launch_submission=submission)
        pid_file.write_text("303\n", encoding="ascii")
        pid_file.chmod(0o600)
        return handle

    monkeypatch.setattr(oci_worker, "spawn_pinned_runc", fake_spawn)

    class InjectedDriverFailure(RuntimeError):
        pass

    def fake_attestation(**_kwargs: Any) -> Any:
        if failure_point == "post-launch-exception":
            raise InjectedDriverFailure("injected post-launch attestation failure")
        attestation = running_attestation(supervisor, attempt)
        monkeypatch.setattr(
            journal_module, "verify_running_runtime_resource_controls", lambda _a: None
        )
        monkeypatch.setattr(
            journal_module, "verify_running_runtime_process_membership", lambda _a: None
        )
        monkeypatch.setattr(journal_module, "verify_running_runtime_systemd_units", lambda _a: None)
        return attestation

    monkeypatch.setattr(
        launch_driver_service, "collect_running_runtime_attestation", fake_attestation
    )

    class CleanupBoundaryReached(RuntimeError):
        pass

    cleanup_calls: list[tuple[Any, ...]] = []
    cancellation_calls: list[tuple[str, int, str, str, str | None]] = []
    cancelled_clients: list[Any] = []
    request_stop = supervisor._sandbox_execution_request_stop

    def user_cancel_wins(
        attempt_id: str, claim_token: int, reason: str, *, credential: str | None
    ) -> dict[str, Any]:
        assert reason == "execution_timeout"
        # Deterministically commit the competing cancellation first; the timeout
        # path then sees the same transition conflict as a real concurrent winner.
        stopping = request_stop(
            attempt_id, claim_token, "attempt cancellation", credential=credential
        )
        assert stopping["phase"] == "stopping"
        raise SupervisorError(
            "sandbox_execution_transition_conflict", "user cancellation won the stop race"
        )

    def request_stop_with_timeout_race(
        attempt_id: str, claim_token: int, reason: str, *, credential: str | None
    ) -> dict[str, Any]:
        if reason == "execution_timeout" and failure_point == "timeout":
            return user_cancel_wins(attempt_id, claim_token, reason, credential=credential)
        return request_stop(attempt_id, claim_token, reason, credential=credential)

    def cancel_exact_monitor(
        stopping: dict[str, Any],
        *,
        monitor_client: Any | None = None,
        _allow_ambiguous_failure: bool = False,
    ) -> None:
        durable_stop_reason = stopping.get("stop_reason")
        if stopping["phase"] == "launched":
            with supervisor.connect() as connection:
                durable_stop_reason = journal_module._sandbox_execution_launch_stop_reason(
                    connection, stopping
                )
        elif stopping["phase"] == "ambiguous":
            durable_stop_reason = stopping.get("failure_reason")
        cancellation_calls.append(
            (
                stopping["attempt_id"],
                stopping["claim_token"],
                stopping["execution_id"],
                stopping["phase"],
                durable_stop_reason,
            )
        )
        cancelled_clients.append(monitor_client)
        expected_cancel_phase = {
            "timeout": "stopping",
            "post-launch-exception": "launched",
            "lease-expired": "ambiguous",
            "lease-expired-after-stop": "ambiguous",
        }[failure_point]
        assert stopping["phase"] == expected_cancel_phase
        assert _allow_ambiguous_failure is (
            failure_point in {"lease-expired", "lease-expired-after-stop"}
        )

    monkeypatch.setattr(
        supervisor, "_sandbox_execution_request_stop", request_stop_with_timeout_race
    )
    monkeypatch.setattr(supervisor, "_cancel_sandbox_execution_monitor", cancel_exact_monitor)
    record_exit_errors: list[BaseException] = []
    record_exit = supervisor._sandbox_execution_record_exit

    def trace_record_exit(*args: Any, **kwargs: Any) -> Any:
        try:
            return record_exit(*args, **kwargs)
        except BaseException as error:
            record_exit_errors.append(error)
            raise

    monkeypatch.setattr(supervisor, "_sandbox_execution_record_exit", trace_record_exit)

    def stop_before_cleanup(*args: Any, **kwargs: Any) -> Any:
        cleanup_calls.append((*args, kwargs))
        current = supervisor._sandbox_execution_get(attempt["id"])
        assert current is not None and current["phase"] == "exited"
        if failure_point == "lease-expired-after-stop":
            pin = supervisor.config.oci_runc_executable
            assert pin is not None
            action_payload = journal_module._sandbox_cleanup_action_payload_for_row(
                current, executable_path=str(pin.path)
            )
            receipt = oci_worker._RuncCleanupActionReceipt(
                attempt_id=current["attempt_id"],
                claim_token=current["claim_token"],
                execution_id=current["execution_id"],
                container_id=current["container_id"],
                state_root=current["state_path"],
                state_root_device=current["state_root_dev"],
                state_root_inode=current["state_root_ino"],
                executable_path=str(pin.path),
                executable_digest=pin.sha256,
                runtime_version=current["runtime_version"],
                argv=tuple(action_payload["argv"]),
                argv_digest=action_payload["argv_sha256"],
                actor_pid=current["launch_driver_pid"],
                actor_identity=current["launch_driver_identity"],
                returncode=0,
                state_entry_absent=True,
            )
            oci_worker._register_runc_cleanup_action_receipt(receipt)
            return receipt
        if failure_point != "lease-expired":
            supervisor._sandbox_execution_mark_ambiguous(
                attempt["id"], attempt["claim_token"], "cleanup evidence unavailable"
            )
        raise CleanupBoundaryReached

    monkeypatch.setattr(oci_worker, "_delete_pinned_runc_container", stop_before_cleanup)

    monkeypatch.setattr(launch_driver_service, "sys", SimpleNamespace(platform="linux"))
    # The service process normally reloads operator pins from the same config;
    # preserve this fixture's synthetic pins across its constructor boundary.
    monkeypatch.setattr(launch_driver_service, "GitSupervisor", lambda _repo: supervisor)
    tampered_request = launch_driver_service._validate_request(
        expected_identity=identity,
        command=("fake-worker", "--tampered"),
        memory_max_bytes=1_073_741_824,
        cpu_quota=100_000,
        cpu_period=100_000,
        pids_max=256,
        timeout_seconds=2,
    )
    request_path.write_bytes(canonical_json(tampered_request).encode("utf-8"))
    request_path.chmod(0o600)
    with pytest.raises(launch_driver_service.SandboxLaunchDriverServiceError, match="start intent"):
        launch_driver_service._run_driver(
            repo=repo,
            expected_identity=identity,
            start_id=intent.start_id,
            start_digest=intent.start_digest,
        )
    still_reserved = supervisor._sandbox_execution_get(attempt["id"])
    assert still_reserved is not None and still_reserved["phase"] == "reserved"
    assert not still_reserved["launch_driver_start_redeemed_at"]
    request_path.write_bytes(canonical_json(request).encode("utf-8"))
    request_path.chmod(0o600)

    gate_read, gate_write = os.pipe()
    gate_observations: list[tuple[bytes, str | None]] = []
    gate_observed = threading.Event()

    def fake_payload() -> None:
        try:
            permit = os.read(gate_read, 3)
            current = supervisor._sandbox_execution_get(attempt["id"])
            gate_observations.append((permit, current["phase"] if current else None))
        finally:
            os.close(gate_read)
            gate_observed.set()

    payload_thread = threading.Thread(target=fake_payload, name="fake-gated-payload", daemon=True)
    handle = _test_runc_handle(target=target, gate_writer=gate_write)
    launch_spec = _test_runc_launch_spec(handle)
    assert launch_spec is not None

    def wait_for_fake_payload(pid: int, _options: int) -> tuple[int, int]:
        assert gate_observed.wait(timeout=2), "fake payload did not receive the gate permit"
        return pid, 0

    launch_spec["test_waitpid"] = wait_for_fake_payload

    try:
        payload_thread.start()
        expected_error = (
            InjectedDriverFailure
            if failure_point == "post-launch-exception"
            else (None if failure_point == "lease-expired-after-stop" else CleanupBoundaryReached)
        )
        if expected_error is None:
            launch_driver_service._run_driver(
                repo=repo,
                expected_identity=identity,
                start_id=intent.start_id,
                start_digest=intent.start_digest,
            )
        else:
            with pytest.raises(expected_error):
                launch_driver_service._run_driver(
                    repo=repo,
                    expected_identity=identity,
                    start_id=intent.start_id,
                    start_digest=intent.start_digest,
                )
    finally:
        payload_thread.join(timeout=2)
        if payload_thread.is_alive():
            try:
                os.close(gate_write)
            except OSError:
                pass
            payload_thread.join(timeout=2)

    assert not payload_thread.is_alive()
    assert record_exit_errors == [], [repr(error) for error in record_exit_errors]
    if failure_point == "timeout":
        assert gate_observations == [(b"go\n", "running")]
        assert len(wait_calls) == 2
        assert wait_calls[0] == pytest.approx(2.0, abs=0.05)
        assert wait_calls[1] is None
        assert cancellation_calls == [
            (
                attempt["id"],
                attempt["claim_token"],
                execution["execution_id"],
                "stopping",
                "attempt cancellation",
            )
        ]
    elif failure_point in {"lease-expired", "lease-expired-after-stop"}:
        assert gate_observations == [(b"go\n", "running")]
        assert len(wait_calls) == 2
        assert wait_calls[0] == pytest.approx(2.0, abs=0.05)
        assert wait_calls[1] is None
        assert cancellation_calls == [
            (
                attempt["id"],
                attempt["claim_token"],
                execution["execution_id"],
                "ambiguous",
                "launch-driver stop intent could not be recorded after attempt lease loss",
            )
        ]
    else:
        assert gate_observations == [(b"", "launched")]
        assert wait_calls == [15.0]
        assert cancellation_calls == [
            (
                attempt["id"],
                attempt["claim_token"],
                execution["execution_id"],
                "launched",
                "launch_driver_failure",
            )
        ]
    assert len(monitor_clients) == 1 and cancelled_clients == monitor_clients
    assert len(cleanup_calls) == (0 if failure_point == "post-launch-exception" else 1)
    assert spawn_calls == [target]
    assert not request_path.exists(), "redeemed request must be consumed before execution"
    durable = supervisor._sandbox_execution_get(attempt["id"])
    expected_phase = {
        "timeout": "ambiguous",
        "post-launch-exception": "launched",
        "lease-expired": "exited",
        "lease-expired-after-stop": "cleanup_reported",
    }[failure_point]
    assert durable is not None and durable["phase"] == expected_phase
    assert durable["cleanup_verification_json"] == "{}"
    if failure_point == "timeout":
        assert durable["failure_reason"] == "cleanup evidence unavailable"
    elif failure_point in {"lease-expired", "lease-expired-after-stop"}:
        assert durable["failure_reason"] == journal_module._LAUNCH_DRIVER_LEASE_LOSS_REASON
    if failure_point == "lease-expired-after-stop":
        assert durable["cleanup_receipt"]["version"] == 3
        assert durable["cleanup_receipt"]["verification_status"] == "unverified"
        assert durable["cleanup_verification_json"] == "{}"
    with pytest.raises(launch_driver_service.SandboxLaunchDriverServiceError):
        launch_driver_service._run_driver(
            repo=repo,
            expected_identity=identity,
            start_id=intent.start_id,
            start_digest=intent.start_digest,
        )
    assert spawn_calls == [target], "ambiguous execution must not replay a second worker launch"
    with supervisor.connect() as connection:
        runtime = connection.execute(
            "SELECT state FROM runtime_environments WHERE attempt_id = ?", (attempt["id"],)
        ).fetchone()
        leases = connection.execute(
            "SELECT lease_expires_at FROM resource_leases WHERE attempt_id = ?", (attempt["id"],)
        ).fetchall()
        runtime_allocation = connection.execute(
            "SELECT lease_expires_at FROM runtime_allocations WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()
        attempt_state = connection.execute(
            "SELECT status, termination_target_status FROM attempts WHERE id = ?",
            (attempt["id"],),
        ).fetchone()
        task_state = connection.execute(
            "SELECT status, cleanup_target_status FROM tasks WHERE id = ?",
            (attempt["task_id"],),
        ).fetchone()
    assert runtime is not None and runtime["state"] != "released"
    if failure_point in {
        "timeout",
        "lease-expired",
        "lease-expired-after-stop",
    }:
        assert leases and all(
            lease["lease_expires_at"] == CLEANUP_FENCE_EPOCH for lease in leases
        ), "ambiguous cleanup evidence must leave resource fences quarantined"
        assert runtime_allocation is not None
        assert runtime_allocation["lease_expires_at"] == CLEANUP_FENCE_EPOCH
    else:
        assert leases and all(lease["lease_expires_at"] > int(time.time()) for lease in leases), (
            "unattested launch must retain active resource leases"
        )
    if failure_point == "lease-expired-after-stop":
        assert attempt_state is not None
        assert attempt_state["status"] == "terminating"
        assert attempt_state["termination_target_status"] == "quarantined"
        assert task_state is not None
        assert task_state["status"] == "cleanup_pending"
        assert task_state["cleanup_target_status"] == "blocked"


def test_lease_loss_quarantine_rechecks_phase_after_release_lock_race(
    monkeypatch: pytest.MonkeyPatch, repo: Path
) -> None:
    """An observed launched phase must not skip quarantine if running wins before lock."""

    if os.geteuid() == 0:
        pytest.skip("launch journal fixture requires an unprivileged caller")
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    record_launch(supervisor, attempt)
    original_gate_lock = journal_module._runc_launch_gate_lock_for_execution
    raced = False

    @contextmanager
    def publish_running_before_lock(*args: Any, **kwargs: Any):
        nonlocal raced
        if not raced:
            raced = True
            # The lease-loss caller already read `launched`. Model the driver
            # committing `running` immediately before it acquires the same
            # release lock; the journal must recheck and accept the new active
            # phase instead of dropping exact monitor cancellation.
            monkeypatch.setattr(
                journal_module,
                "_runc_launch_gate_lock_for_execution",
                original_gate_lock,
            )
            record_running(supervisor, attempt)
            with supervisor.connect() as connection:
                connection.execute(
                    "UPDATE attempts SET lease_expires_at = 0 WHERE id = ?",
                    (attempt["id"],),
                )
        with original_gate_lock(*args, **kwargs) as handle:
            yield handle

    monkeypatch.setattr(
        journal_module, "_runc_launch_gate_lock_for_execution", publish_running_before_lock
    )
    quarantined = supervisor._sandbox_execution_quarantine_lease_loss(
        attempt["id"], attempt["claim_token"], execution["execution_id"]
    )

    assert raced
    assert quarantined["phase"] == "ambiguous"
    assert quarantined["failure_reason"] == journal_module._LAUNCH_DRIVER_LEASE_LOSS_REASON
    with supervisor.connect() as connection:
        task = connection.execute(
            "SELECT status, cleanup_target_status FROM tasks WHERE id = ?",
            (attempt["task_id"],),
        ).fetchone()
        leases = connection.execute(
            "SELECT lease_expires_at FROM resource_leases WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchall()
    assert task["status"] == "cleanup_pending"
    assert task["cleanup_target_status"] == "blocked"
    assert leases and all(lease["lease_expires_at"] == CLEANUP_FENCE_EPOCH for lease in leases)


def test_launch_monitor_start_holds_process_shared_lifecycle_fence(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    observed_busy: list[str] = []

    def inspect_fence(_kwargs: dict[str, Any]) -> None:
        with pytest.raises(SupervisorError) as busy:
            with oci_worker._runc_execution_gate_fence(
                *_execution_gate_identity(execution),
            ):
                pass
        observed_busy.append(busy.value.code)

    launched = record_launch(supervisor, attempt, monitor_start_hook=inspect_fence)

    assert observed_busy == ["sandbox_execution_gate_busy"]
    assert launched["phase"] == "launched"
    durable = supervisor._sandbox_execution_get(attempt["id"])
    assert durable is not None and durable["phase"] == "launched"


def test_timeout_waits_for_cross_process_monitor_handoff_then_adopts(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor, "launch-driver-monitor-handoff-race.txt")
    execution = reserve(supervisor, attempt)
    intent = supervisor._sandbox_execution_authorize_launch_driver_start(
        attempt["id"], attempt["claim_token"], launch_request_digest="e" * 64
    )
    redeem_test_launch_driver_start(supervisor, attempt, intent=intent)
    execution = supervisor._sandbox_execution_get(attempt["id"])
    assert execution is not None and execution["phase"] == "reserved"
    attempt_slice = sandbox_attempt_slice_unit(
        attempt["id"], attempt["claim_token"], execution["execution_id"]
    )
    intent_values = {
        "attempt_id": intent.attempt_id,
        "claim_token": intent.claim_token,
        "execution_id": intent.execution_id,
        "start_id": intent.start_id,
        "start_digest": intent.start_digest,
        "service_unit": intent.service_unit,
    }
    monitor_entered = threading.Event()
    release_monitor = threading.Event()

    def pause_monitor_start(_kwargs: dict[str, Any]) -> None:
        monitor_entered.set()
        if not release_monitor.wait(10):
            raise AssertionError("test barrier did not release monitor startup")

    context = multiprocessing.get_context("spawn")
    event_receiver, event_sender = context.Pipe(duplex=False)
    result_receiver, result_sender = context.Pipe(duplex=False)
    producer = context.Process(
        target=_reconcile_timeout_from_fresh_process,
        args=(repo, execution, intent_values, attempt_slice, event_sender, result_sender),
    )

    with ThreadPoolExecutor(max_workers=1) as pool:
        launch = pool.submit(
            record_launch,
            supervisor,
            attempt,
            monitor_start_hook=pause_monitor_start,
        )
        producer_started = False
        try:
            assert monitor_entered.wait(5), "record_launch did not reach the held monitor start"
            producer.start()
            producer_started = True
            event_sender.close()
            result_sender.close()
            assert event_receiver.poll(5), "fresh producer did not encounter the held process fence"
            assert event_receiver.recv() == "busy"
            assert not event_receiver.poll(0.2), (
                "fresh producer inspected or stopped units while monitor handoff owned the fence"
            )

            release_monitor.set()
            launched = launch.result(timeout=5)
            assert launched["phase"] == "launched"
            assert result_receiver.poll(10), "fresh producer did not finish handoff reconciliation"
            result = result_receiver.recv()
            producer.join(timeout=5)
            assert not producer.is_alive()
            assert producer.exitcode == 0
            assert result == ("ok", True, [], [])
            if event_receiver.poll(0.1):
                with pytest.raises(EOFError):
                    event_receiver.recv()
            durable = supervisor._sandbox_execution_get(attempt["id"])
            assert durable is not None and durable["phase"] == "launched"
        finally:
            release_monitor.set()
            if producer_started and producer.is_alive():
                producer.join(timeout=5)
                if producer.is_alive():
                    producer.terminate()
                    producer.join(timeout=5)
            event_receiver.close()
            result_receiver.close()
            if not event_sender.closed:
                event_sender.close()
            if not result_sender.closed:
                result_sender.close()


@pytest.mark.parametrize("recovery_mode", ["quiescent", "uncertain_driver"])
def test_fresh_supervisor_contains_driver_crash_after_monitor_acceptance(
    repo: Path, recovery_mode: str
) -> None:
    supervisor = GitSupervisor(repo)
    task = make_task(
        supervisor,
        f"monitor-accepted-driver-crash-{recovery_mode}.txt",
        title="sandbox journal test",
    )
    supervisor.config = replace(
        supervisor.config,
        runtime_port_pools=(RuntimePortPool("ACP_TEST_PORT", 24001, 24001),),
    )
    supervisor._port_available = lambda _port: True
    attempt = supervisor.claim(task["id"], "sandbox-worker")
    execution = reserve(supervisor, attempt)
    intent = supervisor._sandbox_execution_authorize_launch_driver_start(
        attempt["id"], attempt["claim_token"], launch_request_digest="e" * 64
    )
    execution = supervisor._sandbox_execution_get(attempt["id"])
    assert execution is not None and execution["phase"] == "reserved"
    attempt_slice = sandbox_attempt_slice_unit(
        attempt["id"], attempt["claim_token"], execution["execution_id"]
    )
    intent_values = {
        "attempt_id": intent.attempt_id,
        "claim_token": intent.claim_token,
        "execution_id": intent.execution_id,
        "start_id": intent.start_id,
        "start_digest": intent.start_digest,
        "service_unit": intent.service_unit,
    }

    context = multiprocessing.get_context("spawn")
    accepted_receiver, accepted_sender = context.Pipe(duplex=False)
    producer = context.Process(
        target=_crash_record_launch_after_monitor_acceptance,
        args=(repo, attempt, intent_values, accepted_sender),
    )
    producer_started = False
    try:
        producer.start()
        producer_started = True
        accepted_sender.close()
        assert accepted_receiver.poll(10), "producer did not reach monitor manager acceptance"
        accepted = accepted_receiver.recv()
        assert accepted[0] == "accepted" and accepted[1] > 0
        producer.join(timeout=10)
        assert not producer.is_alive(), "producer did not crash at the handoff boundary"
        assert producer.exitcode == 74
    finally:
        if producer_started and producer.is_alive():
            producer.terminate()
            producer.join(timeout=5)
        accepted_receiver.close()
        if not accepted_sender.closed:
            accepted_sender.close()

    stranded = supervisor._sandbox_execution_get(attempt["id"])
    assert stranded is not None and stranded["phase"] == "reserved"
    assert stranded["launch_driver_start_id"] == intent.start_id
    assert stranded["launch_driver_start_digest"] == intent.start_digest
    assert stranded["launch_driver_start_unit"] == intent.service_unit
    assert stranded["launch_submission_id"]
    assert stranded["launch_submission_digest"]
    assert stranded["launch_plan_binding_version"] == 0
    assert stranded["wrapper_unit"] == ""
    with supervisor.connect() as connection:
        allocation_before = connection.execute(
            "SELECT pool_name, value, lease_expires_at FROM runtime_allocations "
            "WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()
        runtime_before = connection.execute(
            "SELECT state FROM runtime_environments WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()
    assert allocation_before is not None
    assert allocation_before["pool_name"] == "ACP_TEST_PORT"
    assert allocation_before["value"] == 24001
    assert allocation_before["lease_expires_at"] == attempt["lease_expires_at"]
    assert runtime_before is not None and runtime_before["state"] != "released"

    monitor_unit = sandbox_monitor_service_unit(
        attempt["id"], attempt["claim_token"], execution["execution_id"]
    )
    uncertain_unit = intent.service_unit if recovery_mode == "uncertain_driver" else None
    result_receiver, result_sender = context.Pipe(duplex=False)
    recovery = context.Process(
        target=_reconcile_monitor_accepted_driver_crash,
        args=(repo, stranded, intent_values, attempt_slice, uncertain_unit, result_sender),
    )
    recovery_started = False
    try:
        recovery.start()
        recovery_started = True
        result_sender.close()
        assert result_receiver.poll(10), "fresh supervisor did not return crash reconciliation"
        result = result_receiver.recv()
        recovery.join(timeout=10)
        assert not recovery.is_alive(), "fresh supervisor did not exit after reconciliation"
        assert recovery.exitcode == 0
    finally:
        if recovery_started and recovery.is_alive():
            recovery.terminate()
            recovery.join(timeout=5)
        result_receiver.close()
        if not result_sender.closed:
            result_sender.close()

    if recovery_mode == "quiescent":
        assert result[0] == "ok" and result[1] is False
        assert result[2] == [
            intent.service_unit,
            intent.service_unit,
            monitor_unit,
            monitor_unit,
            attempt_slice,
            attempt_slice,
        ]
        assert result[-1] == [
            ["/usr/bin/systemctl", "--user", "stop", "--", unit]
            for unit in (intent.service_unit, monitor_unit, attempt_slice)
        ]
    else:
        assert result[0:2] == ("error", "SandboxLaunchDriverServiceError")
        assert "remains active" in result[2]
        assert result[3] == [intent.service_unit, intent.service_unit]
        assert result[-1] == [["/usr/bin/systemctl", "--user", "stop", "--", intent.service_unit]]

    durable = supervisor._sandbox_execution_get(attempt["id"])
    assert durable is not None and durable["phase"] == "ambiguous"
    assert durable["launch_driver_start_id"] == intent.start_id
    assert durable["launch_driver_start_digest"] == intent.start_digest
    assert durable["launch_driver_start_unit"] == intent.service_unit
    assert durable["launch_submission_id"] == stranded["launch_submission_id"]
    assert durable["launch_submission_digest"] == stranded["launch_submission_digest"]
    assert durable["launch_plan_binding_version"] == 0
    assert durable["cleanup_verification_json"] == "{}"
    assert supervisor.attempt(attempt["id"])["termination_target_status"] == "quarantined"
    assert supervisor.task(attempt["task_id"])["cleanup_target_status"] == "blocked"
    with supervisor.connect() as connection:
        resource_leases = connection.execute(
            "SELECT lease_expires_at FROM resource_leases WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchall()
        allocation_after = connection.execute(
            "SELECT pool_name, value, lease_expires_at FROM runtime_allocations "
            "WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()
        runtime_after = connection.execute(
            "SELECT state FROM runtime_environments WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()
    assert resource_leases and all(
        lease["lease_expires_at"] == CLEANUP_FENCE_EPOCH for lease in resource_leases
    )
    assert allocation_after is not None
    assert (allocation_after["pool_name"], allocation_after["value"]) == (
        allocation_before["pool_name"],
        allocation_before["value"],
    )
    assert allocation_after["lease_expires_at"] == CLEANUP_FENCE_EPOCH
    assert runtime_after is not None and runtime_after["state"] == runtime_before["state"]

    monitor_start_calls: list[dict[str, Any]] = []
    with pytest.raises(SupervisorError):
        record_launch(supervisor, attempt, monitor_start_calls=monitor_start_calls)
    assert monitor_start_calls == []
    assert (
        supervisor._sandbox_execution_get(attempt["id"])["launch_submission_id"]
        == (stranded["launch_submission_id"])
    )
    assert supervisor.verify_event_chain()["ok"] is True


def test_cross_process_revoke_wins_launch_barrier_and_prevents_monitor_start(
    repo: Path,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor, "launch-driver-revoke-wins-race.txt")
    execution = reserve(supervisor, attempt)
    intent = supervisor._sandbox_execution_authorize_launch_driver_start(
        attempt["id"], attempt["claim_token"], launch_request_digest="e" * 64
    )
    redeem_test_launch_driver_start(supervisor, attempt, intent=intent)
    execution = supervisor._sandbox_execution_get(attempt["id"])
    assert execution is not None and execution["phase"] == "reserved"
    attempt_slice = sandbox_attempt_slice_unit(
        attempt["id"], attempt["claim_token"], execution["execution_id"]
    )
    monitor_unit = sandbox_monitor_service_unit(
        attempt["id"], attempt["claim_token"], execution["execution_id"]
    )
    intent_values = {
        "attempt_id": intent.attempt_id,
        "claim_token": intent.claim_token,
        "execution_id": intent.execution_id,
        "start_id": intent.start_id,
        "start_digest": intent.start_digest,
        "service_unit": intent.service_unit,
    }

    context = multiprocessing.get_context("spawn")
    release_gate = context.Event()
    gate_receiver, gate_sender = context.Pipe(duplex=False)
    result_receiver, result_sender = context.Pipe(duplex=False)
    revoker = context.Process(
        target=_revoke_launch_start_after_gate_acquire,
        args=(
            repo,
            execution,
            attempt_slice,
            intent_values,
            release_gate,
            gate_sender,
            result_sender,
        ),
    )
    revoker_started = False
    try:
        revoker.start()
        revoker_started = True
        gate_sender.close()
        result_sender.close()
        assert gate_receiver.poll(10), "fresh revoker did not acquire the lifecycle gate"
        assert gate_receiver.recv() == "revocation owns process-shared gate"

        monitor_start_calls: list[dict[str, Any]] = []
        with pytest.raises(SupervisorError) as busy:
            record_launch(supervisor, attempt, monitor_start_calls=monitor_start_calls)
        assert busy.value.code == "sandbox_execution_gate_busy"
        assert monitor_start_calls == []

        release_gate.set()
        assert result_receiver.poll(10), "fresh revoker did not durably commit revocation"
        assert result_receiver.recv() == (
            "ok",
            False,
            [intent.service_unit, monitor_unit, attempt_slice],
            [],
        )
        revoker.join(timeout=5)
        assert not revoker.is_alive()
        assert revoker.exitcode == 0
    finally:
        release_gate.set()
        if revoker_started and revoker.is_alive():
            revoker.join(timeout=5)
            if revoker.is_alive():
                revoker.terminate()
                revoker.join(timeout=5)
        gate_receiver.close()
        result_receiver.close()
        if not gate_sender.closed:
            gate_sender.close()
        if not result_sender.closed:
            result_sender.close()

    durable = supervisor._sandbox_execution_get(attempt["id"])
    assert durable is not None and durable["phase"] == "ambiguous"

    with pytest.raises(SupervisorError) as refused:
        record_launch(supervisor, attempt, monitor_start_calls=monitor_start_calls)
    assert refused.value.code == "sandbox_execution_transition_invalid"
    assert monitor_start_calls == []
    durable = supervisor._sandbox_execution_get(attempt["id"])
    assert durable is not None and durable["phase"] == "ambiguous"


def test_monitor_start_failure_keeps_launch_gate_closed_and_fences_reserved(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    handle = _test_runc_handle(target=_test_runc_target(execution))

    with pytest.raises(SupervisorError) as unavailable:
        record_launch(
            supervisor,
            attempt,
            runc_handle=handle,
            monitor_start_error=RuntimeError("ambiguous service startup"),
        )

    assert unavailable.value.code == "sandbox_execution_monitor_unavailable"
    durable = supervisor._sandbox_execution_get(attempt["id"])
    assert durable is not None and durable["phase"] == "reserved"
    assert durable["launch_plan_binding_version"] == 0


def test_launch_submission_is_not_retried_after_monitor_restart(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    target = _test_runc_target(execution)

    # Model the monitor's durable callback immediately before runc submission,
    # then lose its process-local capability before record_launch can commit.
    submission = authorize_test_launch_submission(supervisor, attempt, target)
    stranded = supervisor._sandbox_execution_get(attempt["id"])
    assert stranded is not None
    assert stranded["phase"] == "reserved"
    assert stranded["launch_submission_id"] == submission.submission_id
    assert stranded["launch_submission_digest"] == submission.submission_digest
    assert stranded["launch_submission_at"]

    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(
        target=_retry_launch_submission_from_fresh_process,
        args=(repo, attempt["id"], attempt["claim_token"], target, child),
    )
    process.start()
    child.close()
    try:
        assert parent.poll(10)
        retry_result = parent.recv()
    finally:
        parent.close()
        process.join(timeout=10)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
    assert process.exitcode == 0
    assert retry_result == "sandbox_execution_launch_submission_exists"
    after_restart = supervisor._sandbox_execution_get(attempt["id"])
    assert after_restart is not None
    assert after_restart["phase"] == "reserved"
    assert after_restart["launch_submission_id"] == submission.submission_id


def test_fresh_processes_cannot_submit_with_parent_driver_redemption(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    target = _test_runc_target(execution)
    redeem_test_launch_driver_start(supervisor, attempt)
    context = multiprocessing.get_context("spawn")
    start_event = context.Event()
    workers = []
    receivers = []

    for _ in range(2):
        parent, child = context.Pipe(duplex=False)
        process = context.Process(
            target=_race_launch_submission_from_fresh_process,
            args=(repo, attempt["id"], attempt["claim_token"], target, start_event, child),
        )
        process.start()
        child.close()
        workers.append(process)
        receivers.append(parent)

    start_event.set()
    try:
        results = []
        for receiver in receivers:
            assert receiver.poll(15)
            results.append(receiver.recv())
    finally:
        for receiver in receivers:
            receiver.close()
        for process in workers:
            process.join(timeout=10)
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)

    assert [process.exitcode for process in workers] == [0, 0]
    assert [kind for kind, _value in results].count("ok") == 0
    assert results.count(("error", "sandbox_launch_driver_redemption_required")) == 2
    durable = supervisor._sandbox_execution_get(attempt["id"])
    assert durable is not None
    assert durable["phase"] == "reserved"
    assert durable["launch_submission_id"] == ""
    assert supervisor.verify_event_chain()["ok"] is True


def test_sql_cannot_forge_launch_submission(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)

    with supervisor.connect() as connection:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="sandbox_execution_driver_redemption_required|"
            "sandbox_launch_submission_must_be_authorized_once",
        ):
            connection.execute(
                "UPDATE sandbox_executions SET launch_submission_id = ?, "
                "launch_submission_digest = ?, launch_submission_at = ? WHERE attempt_id = ?",
                ("a" * 32, "b" * 64, "2026-10-11T00:00:00+00:00", attempt["id"]),
            )

    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "reserved"


def test_launch_rejects_monitor_in_sibling_attempt_slice(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    handle = _test_runc_handle(target=_test_runc_target(execution))
    sibling_monitor_path = (
        "/user.slice/user-1000.slice/user@1000.service/app.slice/"
        f"user-acp-{'f' * 64}.slice/acp-worker.service"
    )

    with pytest.raises(SupervisorError) as invalid:
        record_launch(
            supervisor,
            attempt,
            runc_handle=handle,
            wrapper_cgroup_path=sibling_monitor_path,
        )

    assert invalid.value.code == "sandbox_execution_monitor_identity_mismatch"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "reserved"


def test_monitor_service_unit_is_bound_to_full_fenced_execution_identity() -> None:
    identity = ("attempt-1", 7, "execution-1")
    expected = journal_module._sandbox_monitor_service_unit(*identity)

    assert expected.startswith("acp-monitor-")
    assert expected.endswith(".service")
    assert journal_module._sandbox_monitor_service_unit("attempt-2", 7, "execution-1") != expected
    assert journal_module._sandbox_monitor_service_unit("attempt-1", 8, "execution-1") != expected
    assert journal_module._sandbox_monitor_service_unit("attempt-1", 7, "execution-2") != expected


def test_launch_rejects_monitor_service_reused_for_another_execution(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    handle = _test_runc_handle(target=_test_runc_target(execution))

    with pytest.raises(SupervisorError) as rejected:
        record_launch(
            supervisor,
            attempt,
            runc_handle=handle,
            wrapper_unit="acp-monitor-reused.service",
        )

    assert rejected.value.code == "sandbox_execution_monitor_identity_mismatch"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "reserved"


def test_adoption_rejects_a_self_consistent_plan_with_reused_monitor_unit(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    record_launch(supervisor, attempt)
    durable = supervisor._sandbox_execution_get(attempt["id"])
    assert durable is not None

    forged = dict(durable)
    forged["wrapper_unit"] = "acp-monitor-reused.service"
    forged["wrapper_cgroup_path"] = (
        str(Path(durable["wrapper_cgroup_path"]).parent) + "/" + forged["wrapper_unit"]
    )
    plan = json.loads(durable["launch_plan_json"])
    plan["launch"]["systemd_ownership"]["wrapper_control_group"] = forged["wrapper_cgroup_path"]
    forged["launch_plan_json"] = canonical_json(plan)
    forged["launch_plan_digest"] = hashlib.sha256(
        forged["launch_plan_json"].encode("utf-8")
    ).hexdigest()

    assert not journal_module._sandbox_launch_plan_binding_is_self_consistent(forged)


def launch_transition_updates(execution: dict, target: oci_worker._RuncLaunchTarget) -> dict:
    plan = journal_module._sandbox_launch_plan_material(execution, target)
    slice_unit = oci_worker._oci_worker_systemd_slice(target.container_id)
    common_cgroup = "/user.slice/user-1000.slice/user@1000.service/user-acp.slice"
    slice_cgroup = common_cgroup + "/" + slice_unit
    wrapper_unit = journal_module._sandbox_monitor_service_unit(
        execution["attempt_id"], execution["claim_token"], execution["execution_id"]
    )
    plan["launch"]["systemd_ownership"] = {
        "wrapper_control_group": f"{common_cgroup}/{wrapper_unit}",
        "monitor_placement": "outside_attempt_slice",
        "attempt_slice_unit": slice_unit,
        "attempt_slice_invocation_id": "3" * 32,
        "attempt_slice_control_group": slice_cgroup,
    }
    plan_json = canonical_json(plan)
    argv_digest = hashlib.sha256(canonical_json(list(target.argv)).encode("utf-8")).hexdigest()
    return {
        "monitor_pid": 101,
        "monitor_identity": "linux:101:1101",
        "runc_client_pid": 202,
        "runc_client_identity": "linux:202:1202",
        "wrapper_unit": wrapper_unit,
        "wrapper_invocation_id": "1" * 32,
        "wrapper_cgroup_path": f"{common_cgroup}/{wrapper_unit}",
        "attempt_slice_unit": slice_unit,
        "attempt_slice_invocation_id": "3" * 32,
        "attempt_slice_cgroup_path": slice_cgroup,
        "scope_unit": "acp-container.scope",
        "scope_invocation_id": "2" * 32,
        "cgroup_path": f"{slice_cgroup}/acp-container.scope",
        "launch_plan_binding_version": 1,
        "launch_plan_json": plan_json,
        "launch_config_digest": target.config_sha256,
        "launch_argv_digest": argv_digest,
        "launch_plan_digest": hashlib.sha256(plan_json.encode("utf-8")).hexdigest(),
    }


def record_exit(supervisor: GitSupervisor, attempt: dict, exit_code: int = 0) -> dict:
    handle = attempt.get("_test_runc_handle")
    assert isinstance(handle, oci_worker.RuncLaunchHandle)
    receipt = handle.wait()
    assert receipt.returncode == exit_code
    return supervisor._sandbox_execution_record_exit(attempt["id"], attempt["claim_token"], receipt)


def running_attestation(
    supervisor: GitSupervisor,
    attempt: dict,
    init_pid: int = 303,
    *,
    register_collected: bool = True,
    state_root_override: Path | None = None,
    pid_file_name_override: str | None = None,
    runc_executable_sha256: str | None = None,
    launch_driver_unit_override: str | None = None,
):
    row = supervisor._sandbox_execution_get(attempt["id"])
    assert row is not None and row["phase"] == "launched"
    init_start = 1303
    launch_driver_pid = os.getpid()
    wrapper_cgroup = row["wrapper_cgroup_path"]
    slice_cgroup = row["attempt_slice_cgroup_path"]
    launch_driver_unit = launch_driver_unit_override or (
        journal_module._sandbox_launch_driver_service_unit(row["execution_id"])
    )
    launch_driver_cgroup = f"{slice_cgroup}/{launch_driver_unit}"
    scope_cgroup = row["cgroup_path"]
    resource_limits = (
        json.loads(row["launch_plan_json"])["launch"]["resource_limits"]
        if row["launch_plan_json"]
        else {
            "memory_max_bytes": 1_073_741_824,
            "cpu_quota": 100_000,
            "cpu_period": 100_000,
            "pids_max": 256,
        }
    )

    def stat(pid: int, start: int) -> bytes:
        fields = [b"S", *([b"0"] * 18), str(start).encode("ascii")]
        return f"{pid} (worker (gate)) ".encode("ascii") + b" ".join(fields) + b"\n"

    snapshots = {
        row["monitor_pid"]: ProcessSnapshot(
            stat(row["monitor_pid"], 1101),
            f"0::{wrapper_cgroup}\n".encode("ascii"),
            stat(row["monitor_pid"], 1101),
        ),
        row["runc_client_pid"]: ProcessSnapshot(
            stat(
                row["runc_client_pid"],
                int(row["runc_client_identity"].rsplit(":", 1)[1]),
            ),
            f"0::{launch_driver_cgroup}\n".encode("ascii"),
            stat(
                row["runc_client_pid"],
                int(row["runc_client_identity"].rsplit(":", 1)[1]),
            ),
        ),
        launch_driver_pid: ProcessSnapshot(
            stat(launch_driver_pid, 1404),
            f"0::{launch_driver_cgroup}\n".encode("ascii"),
            stat(launch_driver_pid, 1404),
        ),
        init_pid: ProcessSnapshot(
            stat(init_pid, init_start),
            f"0::{scope_cgroup}\n".encode("ascii"),
            stat(init_pid, init_start),
        ),
    }
    resource_control_files = {
        "memory.max": f"{resource_limits['memory_max_bytes']}\n".encode("ascii"),
        "cpu.max": (f"{resource_limits['cpu_quota']} {resource_limits['cpu_period']}\n").encode(
            "ascii"
        ),
        "pids.max": f"{resource_limits['pids_max']}\n".encode("ascii"),
    }
    expected = {
        "expected_container_id": row["container_id"],
        "expected_bundle_path": row["bundle_path"],
        "expected_monitor_pid": row["monitor_pid"],
        "expected_monitor_identity": row["monitor_identity"],
        "expected_runc_client_pid": row["runc_client_pid"],
        "expected_runc_client_identity": row["runc_client_identity"],
        "expected_wrapper_unit": row["wrapper_unit"],
        "expected_wrapper_invocation_id": row["wrapper_invocation_id"],
        "expected_launch_driver_unit": launch_driver_unit,
        "expected_attempt_slice_unit": row["attempt_slice_unit"],
        "expected_attempt_slice_invocation_id": row["attempt_slice_invocation_id"],
        "expected_scope_unit": row["scope_unit"],
        "expected_scope_invocation_id": row["scope_invocation_id"],
        "expected_cgroup_path": scope_cgroup,
        "expected_memory_max_bytes": resource_limits["memory_max_bytes"],
        "expected_cpu_quota": resource_limits["cpu_quota"],
        "expected_cpu_period": resource_limits["cpu_period"],
        "expected_pids_max": resource_limits["pids_max"],
    }
    runc_state = json.dumps(
        {
            "id": row["container_id"],
            "status": "running",
            "pid": init_pid,
            "bundle": row["bundle_path"],
        }
    ).encode("utf-8")
    wrapper_properties = (
        "ActiveState=active\n"
        f"ControlGroup={wrapper_cgroup}\n"
        f"Id={row['wrapper_unit']}\n"
        f"InvocationID={row['wrapper_invocation_id']}\n"
        f"MainPID={row['monitor_pid']}\n"
    ).encode("ascii")
    launch_driver_properties = (
        "ActiveState=active\n"
        f"ControlGroup={launch_driver_cgroup}\n"
        f"Id={launch_driver_unit}\n"
        f"InvocationID={'4' * 32}\n"
        f"MainPID={launch_driver_pid}\n"
    ).encode("ascii")
    attempt_slice_properties = (
        "ActiveState=active\n"
        f"ControlGroup={slice_cgroup}\n"
        f"Id={row['attempt_slice_unit']}\n"
        f"InvocationID={row['attempt_slice_invocation_id']}\n"
    ).encode("ascii")
    scope_properties = (
        "ActiveState=active\n"
        f"ControlGroup={scope_cgroup}\n"
        f"Id={row['scope_unit']}\n"
        f"InvocationID={row['scope_invocation_id']}\n"
    ).encode("ascii")
    validation_args = {
        **expected,
        "runc_state": runc_state,
        "pid_file": f"{init_pid}\n".encode("ascii"),
        "process_snapshots": snapshots,
        "wrapper_properties": wrapper_properties,
        "launch_driver_properties": launch_driver_properties,
        "attempt_slice_properties": attempt_slice_properties,
        "scope_properties": scope_properties,
        "resource_control_files": resource_control_files,
    }
    if not register_collected:
        return validate_running_runtime_attestation(**validation_args)

    state_root = state_root_override or Path(row["state_path"])
    pid_file_path = state_root / (pid_file_name_override or "init.pid")
    pid_file_path.write_bytes(validation_args["pid_file"])
    pid_file_path.chmod(0o600)

    def read_proc_file(path: str) -> bytes:
        snapshot = snapshots[int(path.split("/")[2])]
        return snapshot.cgroup if path.endswith("/cgroup") else snapshot.stat_before

    collector_args = expected
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(sandbox_attestation_module.sys, "platform", "linux")
        patch.setattr(sandbox_attestation_module, "_read_proc_file", read_proc_file)
        patch.setattr(
            sandbox_attestation_module,
            "read_cgroup_resource_controls",
            lambda _path: resource_control_files,
        )
        patch.setattr(
            sandbox_attestation_module,
            "_trusted_systemctl_executable",
            lambda: Path("/usr/bin/systemctl"),
        )
        patch.setattr(
            sandbox_attestation_module,
            "_trusted_systemd_command_environment",
            lambda: {"LANG": "C", "LC_ALL": "C"},
        )
        patch.setattr(
            oci_worker,
            "_verify_trusted_runc_executable",
            lambda _pin: Path("/usr/bin/runc"),
        )
        executable_fd = os.open(os.devnull, os.O_RDONLY)
        patch.setattr(
            oci_worker,
            "_open_verified_runc_executable",
            lambda _pin: executable_fd,
        )

        def run_bounded(argv, **_kwargs):
            command = list(argv)
            if command[0] == "/usr/bin/runc":
                return 0, runc_state.decode("utf-8")
            return 0, {
                row["wrapper_unit"]: wrapper_properties,
                launch_driver_unit: launch_driver_properties,
                row["attempt_slice_unit"]: attempt_slice_properties,
                row["scope_unit"]: scope_properties,
            }[command[-1]].decode("ascii")

        patch.setattr(oci_worker, "_run_bounded_command", run_bounded)
        attestation = collect_running_runtime_attestation(
            pid_file_path=pid_file_path,
            state_root=state_root,
            runc_executable_pin=SimpleNamespace(
                sha256=runc_executable_sha256 or row["runc_executable_digest"]
            ),
            **collector_args,
        )
    pid_file_path.unlink()
    return attestation


def record_running(supervisor: GitSupervisor, attempt: dict) -> dict:
    handle = attempt.get("_test_runc_handle")
    assert isinstance(handle, oci_worker.RuncLaunchHandle)
    attestation = running_attestation(supervisor, attempt)
    controls = {
        "memory.max": f"{attestation.memory_max_bytes}\n".encode("ascii"),
        "cpu.max": f"{attestation.cpu_quota} {attestation.cpu_period}\n".encode("ascii"),
        "pids.max": f"{attestation.pids_max}\n".encode("ascii"),
    }
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            sandbox_attestation_module,
            "read_cgroup_resource_controls",
            lambda _path: controls,
        )
        patch.setattr(
            sandbox_attestation_module,
            "read_linux_process_snapshot",
            lambda pid: _live_process_snapshot(attestation, pid),
        )
        return supervisor._sandbox_execution_record_running(
            attempt["id"],
            attempt["claim_token"],
            attestation=attestation,
            runc_handle=handle,
        )


def _live_process_snapshot(attestation, pid: int) -> ProcessSnapshot:
    expected = {
        attestation.monitor_pid: (
            attestation.monitor_identity,
            attestation.wrapper_control_group,
        ),
        attestation.launch_driver_pid: (
            attestation.launch_driver_identity,
            attestation.launch_driver_control_group,
        ),
        attestation.runc_client_pid: (
            attestation.runc_client_identity,
            attestation.launch_driver_control_group,
        ),
        attestation.init_pid: (attestation.init_identity, attestation.cgroup_path),
    }
    identity, cgroup = expected[pid]
    start_time = identity.rsplit(":", 1)[1]
    fields = [b"S", *([b"0"] * 18), start_time.encode("ascii")]
    raw_stat = f"{pid} (worker (gate)) ".encode("ascii") + b" ".join(fields) + b"\n"
    return ProcessSnapshot(
        stat_before=raw_stat,
        cgroup=f"0::{cgroup}\n".encode("ascii"),
        stat_after=raw_stat,
    )


def cleanup_receipt(supervisor: GitSupervisor, attempt_id: str) -> dict:
    with supervisor.connect() as connection:
        row = connection.execute(
            "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
        ).fetchone()
    assert row is not None
    return supervisor._sandbox_cleanup_receipt(row)


def configure_cleanup_verifier_os_observations(
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
    execution: dict,
    attempt: dict,
    row: dict,
) -> Path:
    """Provide deterministic Linux/systemd observations to the real verifier."""

    monkeypatch.setattr(verifier_module.sys, "platform", "linux")
    monkeypatch.setattr(
        verifier_module, "_trusted_systemctl_executable", lambda: Path("/usr/bin/systemctl")
    )
    runtime_context = tempfile.TemporaryDirectory(prefix="a-", dir=str(_RUNTIME_TMP_DIR))
    request.addfinalizer(runtime_context.cleanup)
    runtime_environment = {"XDG_RUNTIME_DIR": runtime_context.name}
    monkeypatch.setattr(
        verifier_module,
        "_trusted_systemd_command_environment",
        lambda: runtime_environment,
    )
    monkeypatch.setattr(
        verifier_module.sandbox_monitor_lifecycle,
        "_trusted_systemd_command_environment",
        lambda: runtime_environment,
    )
    monkeypatch.setattr(verifier_module, "_process_identity_is_absent", lambda *_args: True)
    monkeypatch.setattr(verifier_module, "_cgroup_tree_is_unpopulated", lambda _path: True)
    monkeypatch.setattr(verifier_module, "_assert_no_mounts_below", lambda _paths: None)
    monkeypatch.setattr(
        verifier_module,
        "_verifier_process_identity",
        lambda: f"linux:{os.getpid()}:1",
    )

    def unit_properties(_systemctl, _environment, unit, _properties):
        expected = {
            row["wrapper_unit"]: (row["wrapper_invocation_id"], row["wrapper_cgroup_path"]),
            row["launch_driver_unit"]: (
                row["launch_driver_invocation_id"],
                row["launch_driver_cgroup_path"],
            ),
            row["scope_unit"]: (row["scope_invocation_id"], row["cgroup_path"]),
            row["attempt_slice_unit"]: (
                row["attempt_slice_invocation_id"],
                row["attempt_slice_cgroup_path"],
            ),
        }
        invocation_id, control_group = expected[unit]
        return {
            "Id": unit,
            "LoadState": "loaded",
            "ActiveState": "active" if unit == row["attempt_slice_unit"] else "inactive",
            "InvocationID": invocation_id,
            "ControlGroup": control_group,
            "MainPID": "0",
        }

    monkeypatch.setattr(
        verifier_module.sandbox_monitor_lifecycle,
        "_read_unit_properties",
        unit_properties,
    )
    _, _, monitor_socket = verifier_module.sandbox_monitor_lifecycle.sandbox_monitor_control_paths(
        state_path=execution["state_path"],
        expected_identity=(attempt["id"], attempt["claim_token"], execution["execution_id"]),
    )
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(monitor_socket))
    listener.close()
    return monitor_socket


def test_independent_cleanup_verifier_commits_separate_receipt_and_removes_bound_trees(
    repo: Path, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor, "independent-cleanup-verifier.txt")
    execution = reserve(supervisor, attempt)
    record_launch(supervisor, attempt)
    record_running(supervisor, attempt)
    record_exit(supervisor, attempt)
    row = supervisor._sandbox_execution_get(attempt["id"])
    pin = supervisor.config.oci_runc_executable
    assert row is not None and pin is not None and row["phase"] == "exited"
    action_payload = journal_module._sandbox_cleanup_action_payload_for_row(
        row, executable_path=str(pin.path)
    )
    action = oci_worker._RuncCleanupActionReceipt(
        attempt_id=row["attempt_id"],
        claim_token=row["claim_token"],
        execution_id=row["execution_id"],
        container_id=row["container_id"],
        state_root=row["state_path"],
        state_root_device=row["state_root_dev"],
        state_root_inode=row["state_root_ino"],
        executable_path=str(pin.path),
        executable_digest=pin.sha256,
        runtime_version=row["runtime_version"],
        argv=tuple(action_payload["argv"]),
        argv_digest=action_payload["argv_sha256"],
        actor_pid=row["launch_driver_pid"],
        actor_identity=row["launch_driver_identity"],
        returncode=0,
        state_entry_absent=True,
    )
    oci_worker._register_runc_cleanup_action_receipt(action)
    supervisor._sandbox_execution_record_cleanup_report(
        attempt["id"], attempt["claim_token"], runc_delete_receipt=action
    )

    monitor_socket = configure_cleanup_verifier_os_observations(
        monkeypatch, request, execution, attempt, row
    )

    remove_exact_tree = verifier_module._remove_exact_tree_at
    failed_state_removal = False

    def fail_state_removal_once(parent_fd, name, **kwargs):
        nonlocal failed_state_removal
        if name == "state" and not failed_state_removal:
            failed_state_removal = True
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "synthetic partial cleanup failure"
            )
        return remove_exact_tree(parent_fd, name, **kwargs)

    monkeypatch.setattr(verifier_module, "_remove_exact_tree_at", fail_state_removal_once)
    with pytest.raises(SupervisorError, match="synthetic partial cleanup failure"):
        supervisor._sandbox_execution_verify_cleanup(attempt["id"], attempt["claim_token"])
    pending = supervisor._sandbox_execution_get(attempt["id"])
    assert pending is not None and pending["phase"] == "cleanup_reported"
    assert not Path(execution["bundle_path"]).exists()
    assert Path(execution["state_path"]).is_dir()
    assert monitor_socket.exists()

    monkeypatch.setattr(verifier_module, "_remove_exact_tree_at", remove_exact_tree)
    verified = supervisor._sandbox_execution_verify_cleanup(attempt["id"], attempt["claim_token"])

    assert verified["phase"] == "cleanup_verified"
    assert verified["cleanup_verification"]["version"] == 1
    assert verified["cleanup_verification"]["observations"]["paths"]["monitor_socket"]["absent"]
    assert Path(execution["bundle_path"]).exists() is False
    assert Path(execution["state_path"]).exists() is False
    assert Path(execution["baseline_root_path"]).is_dir()
    assert Path(execution["workspace_root_path"]).is_dir()
    with supervisor.connect() as connection:
        persisted = connection.execute(
            "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt["id"],)
        ).fetchone()
    assert (
        persisted is not None
        and journal_module._sandbox_cleanup_verification_is_self_consistent(persisted)
    )


def test_reaper_retries_cleanup_verification_before_releasing_attempt_fence(
    repo: Path, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor, "reaper-cleanup-verifier.txt")
    execution = reserve(supervisor, attempt)
    record_launch(supervisor, attempt)
    record_running(supervisor, attempt)
    record_exit(supervisor, attempt)
    row = supervisor._sandbox_execution_get(attempt["id"])
    pin = supervisor.config.oci_runc_executable
    assert row is not None and pin is not None and row["phase"] == "exited"
    action_payload = journal_module._sandbox_cleanup_action_payload_for_row(
        row, executable_path=str(pin.path)
    )
    action = oci_worker._RuncCleanupActionReceipt(
        attempt_id=row["attempt_id"],
        claim_token=row["claim_token"],
        execution_id=row["execution_id"],
        container_id=row["container_id"],
        state_root=row["state_path"],
        state_root_device=row["state_root_dev"],
        state_root_inode=row["state_root_ino"],
        executable_path=str(pin.path),
        executable_digest=pin.sha256,
        runtime_version=row["runtime_version"],
        argv=tuple(action_payload["argv"]),
        argv_digest=action_payload["argv_sha256"],
        actor_pid=row["launch_driver_pid"],
        actor_identity=row["launch_driver_identity"],
        returncode=0,
        state_entry_absent=True,
    )
    oci_worker._register_runc_cleanup_action_receipt(action)
    supervisor._sandbox_execution_record_cleanup_report(
        attempt["id"], attempt["claim_token"], runc_delete_receipt=action
    )
    pending = supervisor._sandbox_execution_get(attempt["id"])
    assert pending is not None and pending["phase"] == "cleanup_reported"
    configure_cleanup_verifier_os_observations(monkeypatch, request, execution, attempt, pending)
    with supervisor.connect() as connection:
        lease_before = connection.execute(
            "SELECT resource FROM resource_leases WHERE task_id = ? AND attempt_id = ?",
            (attempt["task_id"], attempt["id"]),
        ).fetchone()
    assert lease_before is not None

    verify_calls: list[tuple[str, int]] = []
    verify_cleanup = supervisor._sandbox_execution_verify_cleanup

    def record_verification(attempt_id: str, claim_token: int) -> dict:
        verify_calls.append((attempt_id, claim_token))
        return verify_cleanup(attempt_id, claim_token)

    monkeypatch.setattr(supervisor, "_sandbox_execution_verify_cleanup", record_verification)

    def release_runtime(attempt_id: str, force: bool, _allow_active: bool, guard_fd: int) -> dict:
        assert force is True and guard_fd >= 0
        with supervisor.connect() as connection:
            assert journal_module._sandbox_execution_cleanup_is_verified(connection, attempt_id)
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM runtime_allocations WHERE attempt_id = ?", (attempt_id,)
            )
            connection.execute(
                "UPDATE runtime_environments SET state = 'released', updated_at = ? "
                "WHERE attempt_id = ?",
                (journal_module.utc_now(), attempt_id),
            )
        return {"attempt_id": attempt_id, "state": "released"}

    monkeypatch.setattr(supervisor, "_runtime_down_locked", release_runtime)

    result = supervisor.reap_expired(now=attempt["lease_expires_at"] + 1)

    assert verify_calls == [(attempt["id"], attempt["claim_token"])]
    assert result["runtime_cleanup"] == [{"attempt_id": attempt["id"], "state": "released"}]
    assert result["orphaned"] == [attempt["task_id"]]
    verified = supervisor._sandbox_execution_get(attempt["id"])
    assert verified is not None and verified["phase"] == "cleanup_verified"
    assert supervisor.attempt(attempt["id"])["status"] == "orphaned"
    assert supervisor.task(attempt["task_id"])["status"] == "orphaned"
    with supervisor.connect() as connection:
        lease = connection.execute(
            "SELECT task_id, attempt_id, lease_expires_at FROM resource_leases WHERE resource = ?",
            (lease_before["resource"],),
        ).fetchone()
        runtime = connection.execute(
            "SELECT state FROM runtime_environments WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()
        allocation = connection.execute(
            "SELECT 1 FROM runtime_allocations WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()
    assert lease is not None and lease["task_id"] is None and lease["attempt_id"] is None
    assert lease["lease_expires_at"] == 0
    assert runtime is not None and runtime["state"] == "released"
    assert allocation is None


@pytest.mark.parametrize("mutation", ["top_level_version", "action_version"])
def test_cleanup_action_receipt_rejects_integer_float_equivalence(
    repo: Path, mutation: str
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    row = supervisor._sandbox_execution_get(attempt["id"])
    pin = supervisor.config.oci_runc_executable
    assert row is not None and pin is not None

    valid = supervisor._sandbox_cleanup_receipt(row)
    valid["version"] = 3
    valid["action"] = journal_module._sandbox_cleanup_action_payload_for_row(
        row, executable_path=str(pin.path)
    )
    assert supervisor._sandbox_cleanup_receipt_v3_is_self_consistent(row, canonical_json(valid))

    forged = json.loads(canonical_json(valid))
    if mutation == "top_level_version":
        forged["version"] = 3.0
    else:
        forged["action"]["version"] = 1.0
    encoded = canonical_json(forged)
    assert canonical_json(json.loads(encoded)) == encoded
    assert not supervisor._sandbox_cleanup_receipt_v3_is_self_consistent(row, encoded)


def synthesize_cleanup_verified_for_downstream_test(
    supervisor: GitSupervisor, attempt_id: str
) -> None:
    """Forge test-only structure to exercise downstream consumers, never verifier evidence."""

    row = supervisor._sandbox_execution_get(attempt_id)
    assert row is not None and row["phase"] == "cleanup_reported"
    container_id = sandbox_container_id(row["attempt_id"], row["claim_token"], row["execution_id"])
    Path(row["bundle_path"]).rmdir()
    Path(row["state_path"]).rmdir()
    pin = supervisor.config.oci_runc_executable
    assert pin is not None
    synthetic_report = supervisor._sandbox_cleanup_receipt(row)
    synthetic_report["version"] = 3
    synthetic_report["action"] = journal_module._sandbox_cleanup_action_payload_for_row(
        row, executable_path=str(pin.path)
    )
    cleanup_receipt_json = canonical_json(synthetic_report)
    report_digest = hashlib.sha256(cleanup_receipt_json.encode("utf-8")).hexdigest()

    def unit_snapshot(unit: str, invocation_id: str, control_group: str) -> dict[str, str]:
        return {
            "id": unit,
            "load_state": "loaded",
            "active_state": "inactive",
            "invocation_id": invocation_id,
            "control_group": control_group,
            "main_pid": "0",
        }

    verification_json = canonical_json(
        {
            "version": 1,
            "attempt_id": row["attempt_id"],
            "claim_token": row["claim_token"],
            "execution_id": row["execution_id"],
            "cleanup_report_sha256": report_digest,
            "verified_at": "synthetic-test-only",
            "verifier": {"pid": 1, "identity": "linux:1:1"},
            "observations": {
                "units": {
                    "monitor": unit_snapshot(
                        row["wrapper_unit"],
                        row["wrapper_invocation_id"],
                        row["wrapper_cgroup_path"],
                    ),
                    "launch_driver": unit_snapshot(
                        row["launch_driver_unit"],
                        row["launch_driver_invocation_id"],
                        row["launch_driver_cgroup_path"],
                    ),
                    "scope": unit_snapshot(
                        row["scope_unit"], row["scope_invocation_id"], row["cgroup_path"]
                    ),
                    "attempt_slice": unit_snapshot(
                        row["attempt_slice_unit"],
                        row["attempt_slice_invocation_id"],
                        row["attempt_slice_cgroup_path"],
                    ),
                },
                "processes": {
                    "monitor_identity_absent": {
                        "pid": row["monitor_pid"],
                        "identity": row["monitor_identity"],
                        "absent": True,
                    },
                    "launch_driver_identity_absent": {
                        "pid": row["launch_driver_pid"],
                        "identity": row["launch_driver_identity"],
                        "absent": True,
                    },
                    "runc_client_identity_absent": {
                        "pid": row["runc_client_pid"],
                        "identity": row["runc_client_identity"],
                        "absent": True,
                    },
                    "container_init_identity_absent": {
                        "pid": row["init_pid"],
                        "identity": row["init_identity"],
                        "absent": True,
                    },
                },
                "cgroups": {
                    path: True
                    for path in {
                        row["wrapper_cgroup_path"],
                        row["launch_driver_cgroup_path"],
                        row["cgroup_path"],
                        row["attempt_slice_cgroup_path"],
                    }
                },
                "paths": {
                    "runc_state_entry_absent": True,
                    "bundle_absent": True,
                    "state_root_absent": True,
                    "execution_root": {
                        "path": str(Path(row["bundle_path"]).parent),
                        "device": row["execution_root_dev"],
                        "inode": row["execution_root_ino"],
                    },
                    "monitor_socket": {
                        "path": f"/run/user/1000/acpmon-{container_id.removeprefix('acp-')}.sock",
                        "parent_device": 1,
                        "parent_inode": 2,
                        "socket_device": None,
                        "socket_inode": None,
                        "removed": False,
                        "absent": True,
                    },
                },
            },
        }
    )
    with supervisor.connect() as connection:
        # Drop the production-only writer guards; this fabricated JSON is
        # intentionally not issued by the supervisor verifier capability.
        connection.execute("DROP TRIGGER sandbox_execution_phase_transition")
        connection.execute("DROP TRIGGER sandbox_cleanup_verification_write_once")
        connection.execute("DROP TRIGGER sandbox_execution_cleanup_action_receipt_guard")
        connection.execute("DROP TRIGGER sandbox_execution_evidence_immutable")
        connection.execute("DROP TRIGGER sandbox_execution_evidence_phase_guard")
        connection.execute(
            "UPDATE sandbox_executions SET phase = 'cleanup_verified', "
            "cleanup_receipt_json = ?, cleanup_verification_json = ? WHERE attempt_id = ?",
            (cleanup_receipt_json, verification_json, attempt_id),
        )
        connection.commit()


def result_fixture(attempt: dict, tmp_path: Path):
    baseline = copy_snapshot(attempt["worktree"], tmp_path / "baseline")
    output = copy_snapshot(attempt["worktree"], tmp_path / "worker-output").root
    (output / "alpha.txt").write_text("sandbox result\n", encoding="utf-8")
    change_set = collect_changes(
        baseline.manifest,
        output,
        write_set_rules=[("alpha.txt", True, False)],
    )
    return baseline, change_set


def test_current_schema_requires_durable_workspace_and_private_path_binding_before_launch(
    repo: Path,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)

    assert SCHEMA_VERSION == 34
    assert row["phase"] == "reserved"
    assert row["workspace_binding_version"] == 1
    assert row["private_path_binding_version"] == 1
    assert row["execution_root_ino"] == Path(row["bundle_path"]).parent.stat().st_ino
    assert row["bundle_root_ino"] == Path(row["bundle_path"]).stat().st_ino
    assert row["state_root_ino"] == Path(row["state_path"]).stat().st_ino
    assert row["baseline_manifest_digest"]
    assert row["baseline_root_path"].endswith("/baseline")
    assert row["workspace_root_path"].endswith("/workspace")
    assert row["claim_token"] == attempt["claim_token"]
    assert row["backend"] == "oci-runc"
    assert row["container_id"] == journal_module._sandbox_container_id(
        row["attempt_id"], row["claim_token"], row["execution_id"]
    )

    assert row["runtime_version"] == "1.3.5"
    assert row["oci_version"] == "1.2.1"
    assert row["rootfs_digest"] == supervisor.config.oci_rootfs_pin.sha256
    assert row["rootfs_closure_digest"] == supervisor.config.oci_rootfs_pin.closure_sha256
    assert row["runc_executable_digest"] == supervisor.config.oci_runc_executable.sha256
    assert row["result_candidate_version"] == 0
    assert row["launch_plan_required"] == 1
    assert row["launch_plan_binding_version"] == 0
    assert row["bundle_path"].startswith(str((repo / ".acp" / "sandbox-executions").resolve()))
    assert row["state_path"].endswith("/state")

    with supervisor.connect() as connection:
        migration = dict(MIGRATIONS)[15]
        migration(connection)
        migration(connection)
        result_migration = dict(MIGRATIONS)[16]
        result_migration(connection)
        result_migration(connection)
        runtime_pin_migration = dict(MIGRATIONS)[17]
        runtime_pin_migration(connection)
        runtime_pin_migration(connection)
        private_path_migration = dict(MIGRATIONS)[18]
        private_path_migration(connection)
        private_path_migration(connection)
        kernel_wait_migration = dict(MIGRATIONS)[20]
        kernel_wait_migration(connection)
        kernel_wait_migration(connection)
        with pytest.raises(sqlite3.IntegrityError, match="result_candidate_immutable"):
            connection.execute(
                "UPDATE sandbox_executions SET result_candidate_version = 1, "
                "result_candidate_json = '{}', result_candidate_digest = ? WHERE attempt_id = ?",
                ("c" * 64, attempt["id"]),
            )
        with pytest.raises(sqlite3.IntegrityError, match="phase_transition_invalid"):
            connection.execute(
                "UPDATE sandbox_executions SET phase = 'cleanup_verified' WHERE attempt_id = ?",
                (attempt["id"],),
            )
        with _authorize_sandbox_reservation_write(
            connection,
            attempt["id"],
            attempt["claim_token"],
            "direct-insert",
            row["bundle_digest"],
            row["bundle_digest_semantics"],
        ):
            with pytest.raises(sqlite3.IntegrityError, match="must_start_reserved"):
                connection.execute(
                    """
                    INSERT INTO sandbox_executions
                      (attempt_id, claim_token, execution_id, backend, container_id,
                       bundle_digest, bundle_digest_semantics, rootfs_digest,
                       runtime_version, oci_version, bundle_path, state_path, phase,
                       created_at, updated_at)
                    SELECT attempt_id, claim_token, 'direct-insert', backend, 'direct-container',
                           bundle_digest, bundle_digest_semantics, rootfs_digest,
                           runtime_version, oci_version, bundle_path, state_path,
                           'cleanup_verified', created_at, updated_at
                    FROM sandbox_executions WHERE attempt_id = ?
                    """,
                    (attempt["id"],),
                )
    with supervisor.connect() as connection:
        with pytest.raises(sqlite3.IntegrityError, match="identity_immutable"):
            connection.execute(
                "UPDATE sandbox_executions SET claim_token = claim_token + 1 WHERE attempt_id = ?",
                (attempt["id"],),
            )
    with supervisor.connect() as connection:
        with pytest.raises(sqlite3.IntegrityError, match="journal_retained"):
            connection.execute(
                "DELETE FROM sandbox_executions WHERE attempt_id = ?", (attempt["id"],)
            )
    assert supervisor.verify_event_chain()["ok"] is True


def test_launch_driver_start_intent_is_exact_and_one_shot(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)

    intent = supervisor._sandbox_execution_authorize_launch_driver_start(
        attempt["id"], attempt["claim_token"], launch_request_digest="e" * 64
    )
    durable = supervisor._sandbox_execution_get(attempt["id"])
    assert durable is not None
    assert durable["phase"] == "reserved"
    assert intent.attempt_id == attempt["id"]
    assert intent.claim_token == attempt["claim_token"]
    assert intent.execution_id == execution["execution_id"]
    assert intent.service_unit == f"acp-launch-driver-{execution['execution_id']}.service"
    assert intent.start_id == durable["launch_driver_start_id"]
    assert intent.start_digest == durable["launch_driver_start_digest"]
    assert durable["launch_driver_start_at"]
    assert durable["launch_driver_start_unit"] == intent.service_unit
    assert durable["launch_submission_id"] == ""
    expected = {
        "attempt_id": attempt["id"],
        "claim_token": attempt["claim_token"],
        "execution_id": execution["execution_id"],
        "start_digest": durable["launch_driver_start_digest"],
        "service_unit": intent.service_unit,
    }
    assert journal_module._sandbox_launch_driver_start_intent_is_self_consistent(intent, **expected)
    for mismatch in (
        {"attempt_id": "other-attempt"},
        {"claim_token": attempt["claim_token"] + 1},
        {"execution_id": "other-execution"},
        {"start_digest": "f" * 64},
        {"service_unit": "acp-launch-driver-other.service"},
    ):
        assert not journal_module._sandbox_launch_driver_start_intent_is_self_consistent(
            intent, **(expected | mismatch)
        )
    assert not journal_module._sandbox_launch_driver_start_intent_is_self_consistent(
        object(),
        **expected,
    )

    # A fresh controller cannot turn an uncertain systemd response into a new
    # activation attempt. Until exact unit adoption is implemented, it fails
    # closed and leaves the original durable start marker intact.
    restarted = GitSupervisor(repo)
    with pytest.raises(SupervisorError) as duplicate:
        restarted._sandbox_execution_authorize_launch_driver_start(
            attempt["id"], attempt["claim_token"], launch_request_digest="e" * 64
        )
    assert duplicate.value.code == "sandbox_launch_driver_start_ambiguous"
    after_restart = restarted._sandbox_execution_get(attempt["id"])
    assert after_restart is not None
    assert after_restart["launch_driver_start_id"] == intent.start_id
    assert after_restart["launch_driver_start_digest"] == intent.start_digest

    # SQL callers cannot replace or clear the one-shot marker outside the
    # journal's connection-scoped authorization context.
    with pytest.raises(
        sqlite3.IntegrityError, match="sandbox_launch_driver_start_must_be_authorized_once"
    ):
        with restarted.connect() as connection:
            connection.execute(
                "UPDATE sandbox_executions SET launch_driver_start_id = ? WHERE attempt_id = ?",
                ("f" * 32, attempt["id"]),
            )


def test_launch_driver_timeout_revokes_exact_start_and_quarantines(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor, "launch-driver-revocation.txt")
    execution = reserve(supervisor, attempt)
    intent = supervisor._sandbox_execution_authorize_launch_driver_start(
        attempt["id"], attempt["claim_token"], launch_request_digest="e" * 64
    )

    with pytest.raises(SupervisorError) as mismatch:
        supervisor._sandbox_execution_revoke_launch_driver_start(
            attempt["id"],
            attempt["claim_token"],
            execution_id=execution["execution_id"],
            start_id=intent.start_id,
            start_digest="f" * 64,
            service_unit=intent.service_unit,
            reason="startup timeout",
        )
    assert mismatch.value.code == "sandbox_launch_driver_start_mismatch"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "reserved"

    revoked = supervisor._sandbox_execution_revoke_launch_driver_start(
        attempt["id"],
        attempt["claim_token"],
        execution_id=execution["execution_id"],
        start_id=intent.start_id,
        start_digest=intent.start_digest,
        service_unit=intent.service_unit,
        reason="launch-driver did not redeem before timeout",
    )

    assert revoked["phase"] == "ambiguous"
    assert revoked["failure_reason"] == "launch-driver did not redeem before timeout"
    assert supervisor.attempt(attempt["id"])["status"] == "terminating"
    assert supervisor.attempt(attempt["id"])["termination_target_status"] == "quarantined"
    assert supervisor.task(attempt["task_id"])["status"] == "cleanup_pending"
    with pytest.raises(SupervisorError) as late_redemption:
        redeem_test_launch_driver_start(supervisor, attempt)
    assert late_redemption.value.code == "claim_inactive"
    durable = supervisor._sandbox_execution_get(attempt["id"])
    assert durable is not None
    assert durable["phase"] == "ambiguous"
    assert durable["launch_driver_start_redeemed_at"] == ""
    assert supervisor.verify_event_chain()["ok"] is True


def test_launch_driver_timeout_retries_real_fence_before_stopping_exact_units(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor, "launch-driver-fence-race.txt")
    execution = reserve(supervisor, attempt)
    intent = supervisor._sandbox_execution_authorize_launch_driver_start(
        attempt["id"], attempt["claim_token"], launch_request_digest="e" * 64
    )
    attempt_slice = sandbox_attempt_slice_unit(
        attempt["id"], attempt["claim_token"], execution["execution_id"]
    )
    monitor_unit = sandbox_monitor_service_unit(
        attempt["id"], attempt["claim_token"], execution["execution_id"]
    )

    context = multiprocessing.get_context("spawn")
    held_receiver, held_sender = context.Pipe(duplex=False)
    release_receiver, release_sender = context.Pipe(duplex=False)
    fence_holder = context.Process(
        target=_hold_execution_gate_fence,
        args=(
            *_execution_gate_identity(execution),
            release_receiver,
            held_sender,
        ),
    )
    fence_holder.start()
    held_sender.close()
    release_receiver.close()
    events: list[str] = []
    stopped: set[str] = set()
    fence_release_requested = False
    release_ack_received = False
    service_cgroup = f"/user.slice/user-acp.slice/{attempt_slice}/{intent.service_unit}"
    slice_cgroup = f"/user.slice/user-acp.slice/{attempt_slice}"

    def unit_properties(unit: str, properties: tuple[str, ...]) -> dict[str, str]:
        assert fence_release_requested, (
            "unit state was inspected before the lifecycle fence cleared"
        )
        active = unit not in stopped
        if unit == intent.service_unit:
            values = {
                "ActiveState": "active" if active else "inactive",
                "ControlGroup": service_cgroup if active else "",
                "Id": intent.service_unit,
                "InvocationID": "2" * 32,
                "Job": "",
                "LoadState": "loaded",
                "MainPID": "1234" if active else "0",
                "Slice": attempt_slice,
                "SubState": "running" if active else "dead",
            }
        elif unit == monitor_unit:
            values = {
                "ActiveState": "inactive",
                "ControlGroup": "",
                "Id": monitor_unit,
                "InvocationID": "",
                "Job": "",
                "LoadState": "not-found",
                "MainPID": "0",
                "Slice": "",
                "SubState": "dead",
            }
        else:
            assert unit == attempt_slice
            values = {
                "ActiveState": "active" if active else "inactive",
                "ControlGroup": slice_cgroup if active else "",
                "Id": attempt_slice,
                "InvocationID": "3" * 32,
                "Job": "",
                "LoadState": "loaded",
                "MainPID": "0",
                "Slice": "user-acp.slice",
                "SubState": "active" if active else "dead",
            }
        assert set(properties).issubset(values)
        return {key: values[key] for key in properties}

    original_revoke = supervisor._sandbox_execution_revoke_launch_driver_start

    def trace_revoke(*args: Any, **kwargs: Any) -> dict[str, Any]:
        try:
            result = original_revoke(*args, **kwargs)
        except SupervisorError as error:
            events.append(f"revoke:{error.code}")
            raise
        events.append("revoke:committed")
        return result

    def systemd_command(command: list[str], *, environment: dict[str, str]) -> bytes:
        del environment
        assert command == ["/usr/bin/systemctl", "--user", "stop", "--", command[-1]]
        unit = command[-1]
        assert unit in {intent.service_unit, attempt_slice}
        stopped.add(unit)
        events.append(f"stop:{unit}")
        return b""

    original_sleep = time.sleep

    def release_fence_during_retry(seconds: float) -> None:
        nonlocal fence_release_requested, release_ack_received
        if not fence_release_requested:
            fence_release_requested = True
            release_sender.send(True)
            assert held_receiver.poll(5), "lifecycle fence holder did not release after the barrier"
            assert held_receiver.recv() == "released"
            release_ack_received = True
            return
        original_sleep(seconds)

    monkeypatch.setattr(supervisor, "_sandbox_execution_revoke_launch_driver_start", trace_revoke)
    monkeypatch.setattr(launch_driver_service, "_unit_properties", unit_properties)
    monkeypatch.setattr(
        launch_driver_service,
        "_trusted_systemctl_executable",
        lambda: Path("/usr/bin/systemctl"),
    )
    monkeypatch.setattr(
        launch_driver_service,
        "_trusted_systemd_command_environment",
        lambda: {"PATH": "/usr/bin"},
    )
    monkeypatch.setattr(launch_driver_service, "_run_trusted_runtime_command", systemd_command)
    monkeypatch.setattr(launch_driver_service.time, "sleep", release_fence_during_retry)
    try:
        assert held_receiver.poll(5), "competing lifecycle process did not acquire the real fence"
        assert held_receiver.recv() == "held"
        launch_driver_service._stop_and_reconcile_exact_start(
            supervisor,
            execution=execution,
            intent=intent,
            attempt_slice=attempt_slice,
            reason="startup timeout raced with gate release",
            credential=None,
        )
        assert events == [
            "revoke:sandbox_execution_gate_busy",
            "revoke:committed",
            f"stop:{intent.service_unit}",
            f"stop:{attempt_slice}",
        ]
        durable = supervisor._sandbox_execution_get(attempt["id"])
        assert durable is not None
        assert durable["phase"] == "ambiguous"
        assert supervisor.attempt(attempt["id"])["termination_target_status"] == "quarantined"
        assert supervisor.verify_event_chain()["ok"] is True
    finally:
        if fence_holder.is_alive() and not fence_release_requested:
            release_sender.send(True)
        fence_holder.join(timeout=5)
        assert not fence_holder.is_alive(), "competing lifecycle process did not release its fence"
        assert fence_holder.exitcode == 0
        if not release_ack_received:
            assert held_receiver.poll(0.1)
            assert held_receiver.recv() == "released"
        release_sender.close()
        held_receiver.close()


def test_launch_driver_redemption_is_exact_and_one_shot(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    first_attempt = claimed(supervisor, "redemption-first.txt")
    reserve(supervisor, first_attempt)
    second_attempt = claimed(supervisor, "redemption-second.txt")
    reserve(supervisor, second_attempt)

    first_intent = supervisor._sandbox_execution_authorize_launch_driver_start(
        first_attempt["id"],
        first_attempt["claim_token"],
        launch_request_digest="e" * 64,
    )
    first_row = supervisor._sandbox_execution_get(first_attempt["id"])
    assert first_row is not None
    attempt_slice_unit = oci_worker._oci_worker_systemd_slice(first_row["container_id"])
    parent_cgroup = "/user.slice/user-1000.slice/user@1000.service/user-acp.slice"
    attempt_slice_cgroup = f"{parent_cgroup}/{attempt_slice_unit}"
    driver_cgroup = f"{attempt_slice_cgroup}/{first_intent.service_unit}"
    pid = os.getpid()
    service_properties = (
        "ActiveState=active\n"
        f"ControlGroup={driver_cgroup}\n"
        f"Id={first_intent.service_unit}\n"
        f"InvocationID={'c' * 32}\n"
        "LoadState=loaded\n"
        f"MainPID={pid}\n"
        f"Slice={attempt_slice_unit}\n"
    ).encode("ascii")
    slice_properties = (
        "ActiveState=active\n"
        f"ControlGroup={attempt_slice_cgroup}\n"
        f"Id={attempt_slice_unit}\n"
        f"InvocationID={'d' * 32}\n"
        "LoadState=loaded\n"
        "Slice=user-acp.slice\n"
    ).encode("ascii")
    with patch.object(
        sandbox_attestation_module,
        "verify_linux_process_membership",
        return_value=f"linux:{pid}:123456",
    ):
        redemption = (
            sandbox_attestation_module._collect_launch_driver_start_redemption_from_observations(
                expected_identity=(
                    first_attempt["id"],
                    first_attempt["claim_token"],
                    first_row["execution_id"],
                ),
                expected_container_id=first_row["container_id"],
                start_id=first_intent.start_id,
                start_digest=first_intent.start_digest,
                service_unit=first_intent.service_unit,
                attempt_slice_unit=attempt_slice_unit,
                service_properties=service_properties,
                attempt_slice_properties=slice_properties,
                expected_current_pid=pid,
            )
        )

    with pytest.raises(SupervisorError) as cross_tuple:
        supervisor._sandbox_execution_redeem_launch_driver_start(
            second_attempt["id"], second_attempt["claim_token"], redemption=redemption
        )
    assert cross_tuple.value.code == "sandbox_launch_driver_redemption_required"
    first = supervisor._sandbox_execution_redeem_launch_driver_start(
        first_attempt["id"], first_attempt["claim_token"], redemption=redemption
    )
    assert first["launch_driver_start_redeemed_invocation_id"] == "c" * 32
    assert first["launch_driver_start_redeemed_pid"] == pid
    assert first["launch_driver_start_redeemed_slice_invocation_id"] == "d" * 32
    with pytest.raises(SupervisorError) as duplicate:
        supervisor._sandbox_execution_redeem_launch_driver_start(
            first_attempt["id"], first_attempt["claim_token"], redemption=redemption
        )
    assert duplicate.value.code == "sandbox_launch_driver_redemption_ambiguous"


def test_launch_submission_requires_redeemed_driver_activation(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor, "redemption-required.txt")
    execution = reserve(supervisor, attempt)
    intent = supervisor._sandbox_execution_authorize_launch_driver_start(
        attempt["id"], attempt["claim_token"], launch_request_digest="e" * 64
    )

    with pytest.raises(SupervisorError) as missing:
        supervisor._sandbox_execution_authorize_launch_submission(
            attempt["id"],
            attempt["claim_token"],
            launch_target=_test_runc_target(execution),
        )
    assert missing.value.code == "sandbox_launch_driver_redemption_required"

    _receipt, redeemed = redeem_test_launch_driver_start(supervisor, attempt, intent=intent)
    assert redeemed["launch_driver_start_redeemed_at"]
    submission = authorize_test_launch_submission(supervisor, attempt, _test_runc_target(execution))
    assert submission.execution_id == execution["execution_id"]


@pytest.mark.parametrize("activation_change", ["deactivating", "restarted"])
def test_launch_submission_rechecks_live_driver_activation(
    repo: Path, activation_change: str
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor, f"redemption-{activation_change}.txt")
    execution = reserve(supervisor, attempt)
    redeem_test_launch_driver_start(supervisor, attempt)
    target = _test_runc_target(execution)

    if activation_change == "deactivating":

        def collect_deactivating_activation(**_kwargs: Any) -> Any:
            return collect_test_launch_driver_redemption(
                supervisor, attempt, service_active_state="deactivating"
            )

        collector = collect_deactivating_activation
    else:

        def collect_restarted_activation(**_kwargs: Any) -> Any:
            return collect_test_launch_driver_redemption(
                supervisor, attempt, service_invocation_id="5" * 32
            )

        collector = collect_restarted_activation

    with (
        patch.object(
            journal_module,
            "collect_launch_driver_start_redemption",
            side_effect=collector,
        ),
        patch.object(journal_module, "verify_linux_process_membership", return_value="unused"),
        pytest.raises(SupervisorError) as stale,
    ):
        supervisor._sandbox_execution_authorize_launch_submission(
            attempt["id"], attempt["claim_token"], launch_target=target
        )

    assert stale.value.code == "sandbox_launch_driver_redemption_stale"
    durable = supervisor._sandbox_execution_get(attempt["id"])
    assert durable is not None
    assert durable["launch_submission_id"] == ""
    assert durable["launch_submission_at"] == ""


def test_redemption_sql_authorization_binds_exact_timestamp(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor, "redemption-timestamp.txt")
    reserve(supervisor, attempt)
    redeem_test_launch_driver_start(supervisor, attempt)
    row = supervisor._sandbox_execution_get(attempt["id"])
    assert row is not None
    redemption = collect_test_launch_driver_redemption(supervisor, attempt)
    redeemed_at = "2026-10-16T03:00:00Z"
    fields = (
        attempt["id"],
        attempt["claim_token"],
        row["execution_id"],
        row["launch_driver_start_id"],
        row["launch_driver_start_digest"],
        row["launch_driver_start_unit"],
        redeemed_at,
        redemption.service_invocation_id,
        redemption.driver_pid,
        redemption.driver_identity,
        redemption.driver_control_group,
        redemption.attempt_slice_unit,
        redemption.attempt_slice_invocation_id,
        redemption.attempt_slice_control_group,
    )
    with supervisor.connect() as connection:
        with _authorize_sandbox_launch_driver_redemption_write(connection, redemption, redeemed_at):
            exact = connection.execute(
                "SELECT acp_sandbox_launch_driver_redemption_authorized("
                + ",".join("?" for _ in fields)
                + ")",
                fields,
            ).fetchone()[0]
            changed_timestamp = connection.execute(
                "SELECT acp_sandbox_launch_driver_redemption_authorized("
                + ",".join("?" for _ in fields)
                + ")",
                (*fields[:6], "2026-10-16T03:00:01Z", *fields[7:]),
            ).fetchone()[0]
    assert exact == 1
    assert changed_timestamp == 0


def test_v15_to_v16_migration_adds_non_authorizing_candidate_fields() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("CREATE TABLE attempts (id TEXT PRIMARY KEY, pid INTEGER)")
        connection.execute("INSERT INTO attempts (id, pid) VALUES ('attempt-1', NULL)")
        migrations = dict(MIGRATIONS)
        migrations[14](connection)
        migrations[15](connection)

        v15_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(sandbox_executions)")
        }
        candidate_columns = {
            "result_candidate_version",
            "result_candidate_json",
            "result_candidate_digest",
        }
        assert candidate_columns.isdisjoint(v15_columns)
        connection.execute(
            """
            INSERT INTO sandbox_executions
              (attempt_id, claim_token, execution_id, backend, container_id,
               bundle_digest, rootfs_digest, runtime_version, oci_version,
               bundle_path, state_path, phase, created_at, updated_at)
            VALUES (?, 1, 'execution-1', 'oci-runc', 'container-1', ?, ?,
                    '1.3.5', '1.2.1', '/bundle', '/state', 'reserved', 'now', 'now')
            """,
            ("attempt-1", "a" * 64, "b" * 64),
        )

        migrations[16](connection)
        migrations[16](connection)
        v16_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(sandbox_executions)")
        }
        assert candidate_columns.issubset(v16_columns)
        migrated = connection.execute(
            "SELECT result_candidate_version, result_candidate_json, result_candidate_digest "
            "FROM sandbox_executions WHERE attempt_id = 'attempt-1'"
        ).fetchone()
        assert migrated["result_candidate_version"] == 0
        assert migrated["result_candidate_json"] == ""
        assert migrated["result_candidate_digest"] == ""
    finally:
        connection.close()


def test_v19_to_v20_migration_preserves_legacy_check_and_does_not_backfill_evidence() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("CREATE TABLE attempts (id TEXT PRIMARY KEY, pid INTEGER)")
        connection.execute("INSERT INTO attempts (id, pid) VALUES ('attempt-1', NULL)")
        connection.execute("CREATE TABLE submissions (id TEXT PRIMARY KEY)")
        migrations = dict(MIGRATIONS)
        for version in (14, 15, 16, 17, 18):
            migrations[version](connection)
        connection.execute(
            """
            CREATE TABLE result_imports (
              id TEXT PRIMARY KEY,
              attempt_id TEXT NOT NULL REFERENCES attempts(id),
              claim_token INTEGER NOT NULL,
              worker_pid INTEGER,
              worker_identity TEXT NOT NULL DEFAULT '',
              worker_exit_receipt_json TEXT NOT NULL DEFAULT '',
              base_sha TEXT NOT NULL,
              tree_sha TEXT NOT NULL,
              baseline_digest TEXT NOT NULL,
              result_digest TEXT NOT NULL,
              change_digest TEXT NOT NULL,
              result_ref TEXT NOT NULL UNIQUE,
              commit_timestamp INTEGER NOT NULL,
              commit_sha TEXT NOT NULL,
              phase TEXT NOT NULL,
              submission_id TEXT REFERENCES submissions(id),
              error TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              staging_path TEXT NOT NULL DEFAULT '',
              object_ids_json TEXT NOT NULL DEFAULT '[]',
              promote_object_ids_json TEXT NOT NULL DEFAULT '[]'
            )
            """
        )
        migrations[19](connection)
        connection.execute(
            """
            INSERT INTO sandbox_executions
              (attempt_id, claim_token, execution_id, backend, container_id,
               bundle_digest, rootfs_digest, rootfs_closure_digest,
               runc_executable_digest, runtime_version, oci_version,
               bundle_path, state_path, phase, created_at, updated_at)
            VALUES (?, 1, 'execution-1', 'oci-runc', 'container-1', ?, ?, ?, ?,
                    '1.3.5', '1.2.1', '/bundle', '/state', 'reserved', 'now', 'now')
            """,
            ("attempt-1", "a" * 64, "b" * 64, "c" * 64, "d" * 64),
        )
        before_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'sandbox_executions'"
        ).fetchone()["sql"]
        assert "runc_exit_observed_by = 'runc_client_popen_wait'" in before_sql

        migrations[20](connection)
        migrations[20](connection)
        migrations[21](connection)
        migrations[21](connection)

        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(sandbox_executions)")
        }
        assert "runc_exit_evidence_source" in columns
        migrated = connection.execute(
            "SELECT runc_exit_observed_by, runc_exit_evidence_source "
            "FROM sandbox_executions WHERE attempt_id = 'attempt-1'"
        ).fetchone()
        assert migrated["runc_exit_observed_by"] == ""
        assert migrated["runc_exit_evidence_source"] == ""
        after_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'sandbox_executions'"
        ).fetchone()["sql"]
        assert "runc_exit_observed_by = 'runc_client_popen_wait'" in after_sql
        candidate_trigger = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' "
            "AND name = 'sandbox_result_candidate_write_once'"
        ).fetchone()["sql"]
        assert "NEW.runc_exit_evidence_source = 'runc_client_kernel_waitpid'" in candidate_trigger
        assert "NEW.runc_exit_observed_by = 'runc_client_kernel_waitpid'" not in candidate_trigger
        receipt_guard = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' "
            "AND name = 'sandbox_execution_exit_receipt_guard'"
        ).fetchone()["sql"]
        assert "acp_sandbox_exit_receipt_authorized" in receipt_guard

        with pytest.raises(sqlite3.IntegrityError, match="evidence"):
            connection.execute(
                "UPDATE sandbox_executions SET runc_exit_evidence_source = "
                "'runc_client_kernel_waitpid' WHERE attempt_id = 'attempt-1'"
            )
    finally:
        connection.close()


def test_v16_to_v18_migrations_keep_unknown_content_and_path_pins_non_authorizing() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("CREATE TABLE attempts (id TEXT PRIMARY KEY, pid INTEGER)")
        connection.execute("INSERT INTO attempts (id, pid) VALUES ('attempt-1', NULL)")
        migrations = dict(MIGRATIONS)
        for version in (14, 15, 16):
            migrations[version](connection)
        connection.execute(
            """
            INSERT INTO sandbox_executions
              (attempt_id, claim_token, execution_id, backend, container_id,
               bundle_digest, rootfs_digest, runtime_version, oci_version,
               bundle_path, state_path, phase, created_at, updated_at)
            VALUES (?, 1, 'execution-1', 'oci-runc', 'container-1', ?, ?,
                    '1.3.5', '1.2.1', '/bundle', '/state', 'reserved', 'now', 'now')
            """,
            ("attempt-1", "a" * 64, "b" * 64),
        )

        migrations[17](connection)
        migrations[17](connection)
        migrated = connection.execute(
            "SELECT rootfs_closure_digest, runc_executable_digest "
            "FROM sandbox_executions WHERE attempt_id = 'attempt-1'"
        ).fetchone()
        assert migrated["rootfs_closure_digest"] == ""
        assert migrated["runc_executable_digest"] == ""

        connection.execute(
            """
            UPDATE sandbox_executions
            SET workspace_binding_version = 1,
                baseline_root_path = '/baseline', baseline_root_dev = 1,
                baseline_root_ino = 2, workspace_root_path = '/workspace',
                workspace_root_dev = 1, workspace_root_ino = 3,
                baseline_manifest_json = '{}', baseline_manifest_digest = ?
            WHERE attempt_id = 'attempt-1'
            """,
            ("c" * 64,),
        )
        migrations[18](connection)
        migrations[18](connection)
        legacy_path_binding = connection.execute(
            "SELECT private_path_binding_version, execution_root_ino, bundle_root_ino, "
            "state_root_ino FROM sandbox_executions WHERE attempt_id = 'attempt-1'"
        ).fetchone()
        assert legacy_path_binding["private_path_binding_version"] == 0
        assert legacy_path_binding["execution_root_ino"] is None
        with pytest.raises(sqlite3.IntegrityError, match="sandbox_private_path_binding_immutable"):
            connection.execute(
                "UPDATE sandbox_executions SET private_path_binding_version = 1, "
                "execution_root_dev = 1, execution_root_ino = 2, bundle_root_dev = 1, "
                "bundle_root_ino = 3, state_root_dev = 1, state_root_ino = 4 "
                "WHERE attempt_id = 'attempt-1'"
            )
        with pytest.raises(
            sqlite3.IntegrityError,
            match="sandbox_execution_(content_pins|private_paths)_required",
        ):
            connection.execute(
                """
                UPDATE sandbox_executions
                SET phase = 'launched', monitor_pid = 101,
                    monitor_identity = 'linux:101:1101', runc_client_pid = 202,
                    runc_client_identity = 'linux:202:1202', wrapper_unit = 'acp-worker.service',
                    wrapper_invocation_id = '11111111111111111111111111111111',
                    scope_unit = 'acp-container.scope',
                    scope_invocation_id = '22222222222222222222222222222222',
                    cgroup_path = '/user.slice/acp-container.scope'
                WHERE attempt_id = 'attempt-1'
                """
            )
    finally:
        connection.close()


def test_sandbox_launch_cannot_bypass_workspace_binding(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    runtime_claims = configured_sandbox_claims(supervisor)
    row = supervisor._sandbox_execution_reserve(
        attempt["id"],
        attempt["claim_token"],
        **runtime_claims,
    )
    assert row["workspace_binding_version"] == 0

    with pytest.raises(SupervisorError) as error:
        record_launch(supervisor, attempt)
    assert error.value.code == "sandbox_workspace_unbound"

    with (
        supervisor.connect() as connection,
        pytest.raises(
            sqlite3.IntegrityError,
            match=(
                "workspace_binding_required|private_paths_required|"
                "sandbox_execution_launch_plan_required|attempt_slice_identity_required|"
                "sandbox_execution_launch_submission_required|phase_transition_invalid|"
                "sandbox_execution_driver_redemption_mismatch"
            ),
        ),
    ):
        connection.execute(
            "UPDATE sandbox_executions SET phase = 'launched' WHERE attempt_id = ?",
            (attempt["id"],),
        )


def test_workspace_binding_restores_after_process_local_snapshot_registry_is_lost(
    repo: Path,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)
    assert row["workspace_binding_version"] == 1

    with (
        supervisor.connect() as connection,
        pytest.raises(sqlite3.IntegrityError, match="workspace_binding_immutable"),
    ):
        replacement = "0" * 64
        if replacement == row["baseline_manifest_digest"]:
            replacement = "1" * 64
        connection.execute(
            "UPDATE sandbox_executions SET baseline_manifest_digest = ? WHERE attempt_id = ?",
            (replacement, attempt["id"]),
        )

    from agent_control_plane.supervisor import sandbox_workspace

    # Simulate a fresh process: durable journal values, not the in-memory weak
    # reference registry, must re-establish the baseline handle.
    sandbox_workspace._SNAPSHOT_ORIGINS.clear()
    restored = supervisor._sandbox_execution_restore_workspace_binding(
        attempt["id"], attempt["claim_token"]
    )
    assert restored["version"] == 1
    assert restored["execution_id"] == row["execution_id"]
    assert restored["baseline"].manifest.digest == row["baseline_manifest_digest"]
    assert read_snapshot_files(restored["baseline"])["alpha.txt"] == b"base\n"
    assert restored["workspace_root"] == Path(row["workspace_root_path"])

    (restored["workspace_root"] / "alpha.txt").write_text("sandbox result\n", encoding="utf-8")
    changes = collect_changes(
        restored["baseline"].manifest,
        restored["workspace_root"],
        write_set_rules=[("alpha.txt", True, False)],
    )
    assert changes.baseline_digest == restored["baseline"].manifest.digest
    assert [change.path for change in changes.changes] == ["alpha.txt"]


def test_workspace_binding_restore_rejects_replaced_output_root(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)
    workspace_root = Path(row["workspace_root_path"])
    saved_root = workspace_root.with_name("workspace-saved")
    workspace_root.rename(saved_root)
    workspace_root.mkdir(mode=0o700)

    with pytest.raises(SupervisorError) as error:
        supervisor._sandbox_execution_restore_workspace_binding(
            attempt["id"], attempt["claim_token"]
        )
    assert error.value.code == "invalid_snapshot"


def test_workspace_binding_restore_rejects_changed_baseline_content(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)
    (Path(row["baseline_root_path"]) / "alpha.txt").write_text("forged\n", encoding="utf-8")

    with pytest.raises(SupervisorError) as error:
        supervisor._sandbox_execution_restore_workspace_binding(
            attempt["id"], attempt["claim_token"]
        )
    assert error.value.code == "snapshot_changed"


def test_workspace_binding_restore_rechecks_claim_fence_after_baseline_scan(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    restore = journal_module._restore_snapshot_from_record

    def expire_claim_during_restore(*args, **kwargs):
        snapshot = restore(*args, **kwargs)
        with supervisor.connect() as connection:
            connection.execute(
                "UPDATE attempts SET lease_expires_at = 0 WHERE id = ?", (attempt["id"],)
            )
        return snapshot

    monkeypatch.setattr(
        journal_module, "_restore_snapshot_from_record", expire_claim_during_restore
    )

    with pytest.raises(SupervisorError) as error:
        supervisor._sandbox_execution_restore_workspace_binding(
            attempt["id"], attempt["claim_token"]
        )
    assert error.value.code == "lease_expired"


def test_durable_manifest_parser_accepts_valid_manifest_above_old_32_mib_cap() -> None:
    target = "a" * 4_096
    count = 8_500
    entries = tuple(
        ManifestEntry(f"link-{index:05d}", "symlink", 0o777, len(target), symlink_target=target)
        for index in range(count)
    )
    manifest = _make_manifest(entries, count * len(target))
    encoded = canonical_json(manifest.as_json())
    assert len(encoded.encode("utf-8")) > 32 * 1024 * 1024

    assert _tree_manifest_from_json(encoded) == manifest


def test_schema_13_read_only_open_refuses_until_journal_migration(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    with supervisor.connect() as connection:
        connection.execute("DROP TABLE sandbox_executions")
        connection.execute("UPDATE meta SET value = '13' WHERE key = 'schema_version'")

    with pytest.raises(SupervisorError) as error:
        GitSupervisor(repo, read_only=True)
    assert error.value.code == "schema_upgrade_required"

    migrated = GitSupervisor(repo)
    assert migrated.schema_version_on_open == 13
    with migrated.connect() as connection:
        tables = {
            row["name"]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    assert "sandbox_executions" in tables


@pytest.mark.parametrize("phase", ["reserved", "launched"])
def test_v21_rows_migrate_unattested_and_remain_fail_closed(repo: Path, phase: str) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    handle = _test_runc_handle(target=_test_runc_target(execution))
    if phase == "launched":
        record_launch(supervisor, attempt, runc_handle=handle)

    # Recreate the pre-v22 table: the migration must not infer that a historical
    # caller-supplied digest was a trusted config/argv binding.
    with supervisor.connect() as connection:
        for trigger in (
            "sandbox_launch_driver_start_insert_guard",
            "sandbox_launch_driver_start_write_once",
            "sandbox_launch_plan_insert_guard",
            "sandbox_launch_plan_required_immutable",
            "sandbox_launch_plan_write_once",
            "sandbox_execution_launch_requires_plan",
            "sandbox_execution_running_requires_plan",
            "sandbox_execution_exit_requires_plan",
        ):
            connection.execute(f"DROP TRIGGER {trigger}")
        for column in (
            "launch_plan_digest",
            "launch_argv_digest",
            "launch_config_digest",
            "launch_plan_json",
            "launch_plan_binding_version",
            "launch_plan_required",
        ):
            connection.execute(f"ALTER TABLE sandbox_executions DROP COLUMN {column}")
        connection.execute("UPDATE meta SET value = '21' WHERE key = 'schema_version'")

    migrated = GitSupervisor(repo)
    assert migrated.schema_version_on_open == 21
    legacy = migrated._sandbox_execution_get(attempt["id"])
    assert legacy["phase"] == phase
    assert legacy["launch_plan_required"] == 0
    assert legacy["launch_plan_binding_version"] == 0
    assert legacy["launch_plan_json"] == ""
    assert legacy["launch_plan_digest"] == ""

    if phase == "reserved":
        with pytest.raises(SupervisorError) as error:
            record_launch(migrated, attempt, runc_handle=handle)
    else:
        with pytest.raises(SupervisorError) as error:
            migrated._sandbox_execution_record_running(
                attempt["id"],
                attempt["claim_token"],
                attestation=running_attestation(migrated, attempt),
                runc_handle=handle,
            )
    assert error.value.code == "sandbox_execution_launch_plan_required"
    assert migrated._sandbox_execution_get(attempt["id"])["phase"] == phase


def test_reservation_requires_exact_live_fence_and_no_registered_direct_worker(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    runtime_claims = configured_sandbox_claims(supervisor)

    with pytest.raises(SupervisorError) as stale:
        supervisor._sandbox_execution_reserve(
            attempt["id"],
            attempt["claim_token"] + 1,
            **runtime_claims,
        )
    assert stale.value.code == "stale_fencing_token"

    for field in ("rootfs_closure_digest", "runc_executable_digest"):
        options = dict(runtime_claims)
        options[field] = "not-a-digest"
        with pytest.raises(SupervisorError) as malformed:
            supervisor._sandbox_execution_reserve(attempt["id"], attempt["claim_token"], **options)
        assert malformed.value.code == "sandbox_execution_invalid"
    assert supervisor._sandbox_execution_get(attempt["id"]) is None

    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET pid = 12345, pid_identity = 'direct-worker' WHERE id = ?",
            (attempt["id"],),
        )
    with pytest.raises(SupervisorError) as registered:
        reserve(supervisor, attempt)
    assert registered.value.code == "worker_already_running"
    assert supervisor._sandbox_execution_get(attempt["id"]) is None


def test_sandbox_reservation_requires_configured_sealed_runtime_pins(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    with pytest.raises(SupervisorError) as missing:
        supervisor._sandbox_execution_reserve(
            attempt["id"],
            attempt["claim_token"],
            rootfs_digest="b" * 64,
            rootfs_closure_digest="c" * 64,
            runc_executable_digest="d" * 64,
            runtime_version="1.3.5",
            oci_version="1.2.1",
        )
    assert missing.value.code == "sandbox_execution_pin_unavailable"
    assert supervisor._sandbox_execution_get(attempt["id"]) is None


@pytest.mark.parametrize(
    "field",
    (
        "rootfs_digest",
        "rootfs_closure_digest",
        "runc_executable_digest",
        "runtime_version",
    ),
)
def test_sandbox_reservation_binds_claims_to_configured_runtime_pins(
    repo: Path, field: str
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    runtime_claims = configured_sandbox_claims(supervisor)
    mismatched_claims = dict(runtime_claims)
    original = mismatched_claims[field]
    mismatched_claims[field] = (
        "1.3.4"
        if field == "runtime_version"
        else ("0" if original[0] != "0" else "1") + original[1:]
    )

    with pytest.raises(SupervisorError) as mismatch:
        supervisor._sandbox_execution_reserve(
            attempt["id"],
            attempt["claim_token"],
            **mismatched_claims,
        )
    assert mismatch.value.code == "sandbox_execution_pin_mismatch"
    assert supervisor._sandbox_execution_get(attempt["id"]) is None


def test_journal_reservation_prevents_later_direct_worker_launch(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)

    with pytest.raises(SupervisorError) as launch:
        supervisor._reserve_worker_launch(
            attempt["id"], attempt["claim_token"], ".acp/logs/direct.log", None
        )
    assert launch.value.code == "sandbox_execution_reserved"
    assert supervisor.attempt(attempt["id"])["pid"] is None

    before = supervisor.attempt(attempt["id"])
    # Exercise a later configuration downgrade/restart: the journal survives,
    # but the current process no longer has an OCI pin and must not touch the
    # attempt through the direct-worker path.
    supervisor.config = replace(
        supervisor.config,
        oci_rootfs_pin=None,
        oci_runc_executable=None,
        oci_runc_version=None,
    )

    def direct_launch_must_not_start(*_args, **_kwargs):
        pytest.fail("a journaled sandbox reservation must stop direct worker setup")

    monkeypatch.setattr(supervisor, "heartbeat", direct_launch_must_not_start)
    monkeypatch.setattr(supervisor, "_reserve_worker_launch", direct_launch_must_not_start)
    with pytest.raises(SupervisorError) as worker:
        supervisor.run_worker(attempt["id"], attempt["claim_token"], ["/bin/true"])

    assert worker.value.code == "sandbox_execution_reserved"
    after = supervisor.attempt(attempt["id"])
    assert after["pid"] is None
    assert after["updated_at"] == before["updated_at"]


def test_journaled_sandbox_termination_never_opens_registered_host_pid(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    attempt_view = supervisor._attempt_view

    def registered_pid_view(connection, row):
        view = attempt_view(connection, row)
        view["pid"] = 4242
        view["pid_identity"] = "linux:4242:99"
        return view

    # Journal ownership triggers correctly prevent direct PID registration;
    # emulate a legacy/recovered view to prove the termination boundary still
    # refuses the host-PID route if such a value is present.
    monkeypatch.setattr(supervisor, "_attempt_view", registered_pid_view)

    def host_pid_operation_must_not_run(*_args: object, **_kwargs: object) -> None:
        pytest.fail("journaled sandbox termination must not access or signal a host PID")

    monkeypatch.setattr(
        workers_module.os, "pidfd_open", host_pid_operation_must_not_run, raising=False
    )
    monkeypatch.setattr(
        workers_module.signal,
        "pidfd_send_signal",
        host_pid_operation_must_not_run,
        raising=False,
    )
    monkeypatch.setattr(workers_module.os, "kill", host_pid_operation_must_not_run)
    monkeypatch.setattr(workers_module.os, "killpg", host_pid_operation_must_not_run, raising=False)
    with pytest.raises(SupervisorError) as termination:
        supervisor.terminate_worker(attempt["id"])

    assert termination.value.code == "sandbox_execution_monitor_unavailable"
    monkeypatch.setattr(supervisor, "_attempt_view", attempt_view)
    assert supervisor.attempt(attempt["id"])["pid"] is None
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "reserved"


def test_journaled_termination_reuses_exact_startup_monitor_client(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    launched = record_launch(supervisor, attempt, runc_handle=handle)
    identity = (attempt["id"], attempt["claim_token"], execution["execution_id"])
    monitor_slice_control_group = "/user.slice/user-1000.slice/user@1000.service/user-acp.slice"
    attempt_slice_unit = sandbox_attempt_slice_unit(*identity)
    attempt_slice_control_group = f"{monitor_slice_control_group}/{attempt_slice_unit}"
    receipt = SandboxMonitorReceipt(
        controller_pid=os.getpid(),
        attempt_id=identity[0],
        claim_token=identity[1],
        execution_id=identity[2],
        unit=launched["wrapper_unit"],
        invocation_id=launched["wrapper_invocation_id"],
        control_group=launched["wrapper_cgroup_path"],
        main_pid=101,
        main_identity="linux:101:1101",
        monitor_slice_unit="user-acp.slice",
        monitor_slice_control_group=monitor_slice_control_group,
        attempt_slice_unit=attempt_slice_unit,
        attempt_slice_control_group=attempt_slice_control_group,
    )
    client = object.__new__(monitor_ipc_module.SandboxMonitorControlClient)
    client._receipt = receipt
    client.status = lambda: SimpleNamespace(
        outcome="ok",
        payload={
            "phase": "running",
            "scope_unit": launched["scope_unit"],
            "scope_invocation_id": launched["scope_invocation_id"],
            "scope_control_group": launched["cgroup_path"],
        },
    )
    cancel_ids: list[str] = []
    client.cancel = lambda request_id: (
        cancel_ids.append(request_id)
        or SimpleNamespace(outcome="ok", payload={"phase": "stopping"})
    )
    with handle._gate_lock:
        handle._monitor_client = client

    def reconnect_must_not_run(**_kwargs: object) -> None:
        pytest.fail("original controller must reuse its exact startup client, not recover")

    monkeypatch.setattr(
        monitor_lifecycle_module, "reconnect_sandbox_monitor", reconnect_must_not_run
    )
    monkeypatch.setattr(
        monitor_lifecycle_module,
        "sandbox_monitor_control_paths",
        lambda **_kwargs: pytest.fail("cached monitor client must not reread recovery files"),
    )
    try:
        first = supervisor.terminate_worker(attempt["id"])
        second = supervisor.terminate_worker(attempt["id"])

        assert first == second
        assert first["outcome"] == "stop_pending"
        assert first["phase"] == "launched"
        assert first["monitor_phase"] == "stopping"
        assert first["stop_requested"] is True
        assert first["cleanup_verified"] is False
        assert len(cancel_ids) == 2 and cancel_ids[0] == cancel_ids[1]
        assert "_monitor_client" not in repr(handle)
        assert handle._monitor_client is client
        assert handle._gate_writer is None
        assert os.read(gate_read, 1) == b""
        with pytest.raises(SupervisorError) as gate_rejected:
            handle.release_gate()
        assert gate_rejected.value.code == "sandbox_launch_gate_closed"
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_journaled_termination_rejects_cached_monitor_client_for_other_execution(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    launched = record_launch(supervisor, attempt, runc_handle=handle)
    identity = (attempt["id"], attempt["claim_token"], execution["execution_id"])
    monitor_slice_control_group = "/user.slice/user-1000.slice/user@1000.service/user-acp.slice"
    other_identity = (identity[0], identity[1], "00000000-0000-4000-8000-000000000001")
    other_unit = journal_module._sandbox_monitor_service_unit(*other_identity)
    other_slice = sandbox_attempt_slice_unit(*other_identity)
    wrong_receipt = SandboxMonitorReceipt(
        controller_pid=os.getpid(),
        attempt_id=other_identity[0],
        claim_token=other_identity[1],
        execution_id=other_identity[2],
        unit=other_unit,
        invocation_id="4" * 32,
        control_group=f"{monitor_slice_control_group}/{other_unit}",
        main_pid=101,
        main_identity="linux:101:1101",
        monitor_slice_unit="user-acp.slice",
        monitor_slice_control_group=monitor_slice_control_group,
        attempt_slice_unit=other_slice,
        attempt_slice_control_group=f"{monitor_slice_control_group}/{other_slice}",
    )
    wrong_client = object.__new__(monitor_ipc_module.SandboxMonitorControlClient)
    wrong_client._receipt = wrong_receipt
    with handle._gate_lock:
        handle._monitor_client = wrong_client

    monkeypatch.setattr(
        monitor_lifecycle_module,
        "reconnect_sandbox_monitor",
        lambda **_kwargs: pytest.fail("a mismatched cached client must not fall back to recovery"),
    )
    try:
        with pytest.raises(SupervisorError) as termination:
            supervisor.terminate_worker(attempt["id"])

        assert termination.value.code == "sandbox_execution_monitor_identity_mismatch"
        durable = supervisor._sandbox_execution_get(attempt["id"])
        assert durable is not None and durable["phase"] == "launched"
        assert handle._monitor_client is wrong_client
        assert handle._gate_writer is None
        with pytest.raises(SupervisorError) as gate_rejected:
            handle.release_gate()
        assert gate_rejected.value.code == "sandbox_launch_gate_closed"
        assert launched["phase"] == "launched"
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_forked_process_cannot_reuse_parent_launch_handle(
    repo: Path,
) -> None:
    if "fork" not in multiprocessing.get_all_start_methods():
        pytest.skip("fork is unavailable on this platform")
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    record_launch(supervisor, attempt, runc_handle=handle)
    inherited_record = oci_worker._runc_launch_record(handle)
    assert inherited_record is not None
    inherited_client_marker = object()
    with handle._gate_lock:
        handle._monitor_client = inherited_client_marker

    context = multiprocessing.get_context("fork")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_terminate_worker_from_forked_process,
        args=(repo, attempt["id"], handle, inherited_record, sender),
    )
    try:
        held_locks = (
            oci_worker._RUNC_LAUNCH_SUBMISSION_TARGETS_LOCK,
            oci_worker._RUNC_LAUNCH_RECORDS_LOCK,
            oci_worker._RUNC_WAIT_RECEIPTS_LOCK,
            handle._gate_lock,
            inherited_record.wait_lock,
        )
        for lock in held_locks:
            lock.acquire()
        try:
            process.start()
        finally:
            for lock in reversed(held_locks):
                lock.release()
        sender.close()
        assert receiver.poll(10), "forked stop attempt did not return"
        (
            error_code,
            inherited_client_cleared,
            inherited_global_locks_available,
            inherited_gate_lock_available,
            inherited_wait_lock_available,
            inherited_gate_closed,
        ) = receiver.recv()
        process.join(10)
        assert process.exitcode == 0
        assert error_code == "sandbox_execution_monitor_unavailable"
        assert inherited_client_cleared is True
        assert inherited_global_locks_available is True
        assert inherited_gate_lock_available is True
        assert inherited_wait_lock_available is True
        assert inherited_gate_closed is True
        assert handle._monitor_client is inherited_client_marker
        assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"
        with supervisor.connect() as connection:
            assert (
                journal_module._sandbox_execution_launch_stop_reason(
                    connection, supervisor._sandbox_execution_get(attempt["id"])
                )
                == "terminate_worker"
            )
    finally:
        if process.is_alive():
            process.terminate()
            process.join(5)
        receiver.close()
        handle.close_gate()
        os.close(gate_read)


def test_fork_closes_gate_writer_created_before_handle_registration() -> None:
    if "fork" not in multiprocessing.get_all_start_methods():
        pytest.skip("fork is unavailable on this platform")
    gate_read, gate_write = oci_worker._create_runc_launch_gate_pipe()
    context = multiprocessing.get_context("fork")
    ready_receiver, ready_sender = context.Pipe(duplex=False)
    release_receiver, release_sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_forked_child_wait_for_release,
        args=(ready_sender, release_receiver),
    )
    try:
        process.start()
        ready_sender.close()
        release_receiver.close()
        assert ready_receiver.poll(5), "forked child did not reach its hold point"
        assert ready_receiver.recv() is True

        oci_worker._close_runc_launch_gate_writer(gate_write)
        gate_write = -1
        readable, _, _ = select.select([gate_read], [], [], 2)
        assert readable, "forked child retained the pre-registration gate writer"
        assert os.read(gate_read, 1) == b""

        release_sender.send(True)
        process.join(5)
        assert process.exitcode == 0
    finally:
        if gate_write >= 0:
            oci_worker._close_runc_launch_gate_writer(gate_write)
        os.close(gate_read)
        release_sender.close()
        ready_receiver.close()
        if process.is_alive():
            process.terminate()
            process.join(5)


def test_journaled_sandbox_termination_reuses_identity_bound_monitor_cancel_id(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    record_launch(supervisor, attempt, runc_handle=handle)
    execution_with_scope = supervisor._sandbox_execution_get(attempt["id"])
    assert execution_with_scope is not None
    cancel_ids: list[str] = []
    reconnect_calls: list[dict[str, object]] = []

    def status():
        # There is no init PID yet, so the journal truthfully remains launched;
        # the durable pre-init stop intent is carried by its hash-chained event.
        assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"
        with supervisor.connect() as connection:
            assert (
                journal_module._sandbox_execution_launch_stop_reason(
                    connection, supervisor._sandbox_execution_get(attempt["id"])
                )
                == "terminate_worker"
            )
        with pytest.raises(SupervisorError) as gate_rejected:
            handle.release_gate()
        assert gate_rejected.value.code == "sandbox_launch_gate_closed"
        return SimpleNamespace(
            outcome="ok",
            payload={
                "phase": "running",
                "scope_unit": execution_with_scope["scope_unit"],
                "scope_invocation_id": execution_with_scope["scope_invocation_id"],
                "scope_control_group": execution_with_scope["cgroup_path"],
            },
        )

    client = SimpleNamespace(
        status=status,
        cancel=lambda request_id: (
            cancel_ids.append(request_id)
            or SimpleNamespace(outcome="ok", payload={"phase": "stopping"})
        ),
    )

    def paths(*, state_path: str, expected_identity: tuple[str, int, str]):
        assert state_path == execution["state_path"]
        assert expected_identity == (
            attempt["id"],
            attempt["claim_token"],
            execution["execution_id"],
        )
        return (
            Path("/private/control"),
            Path("/private/control/receipt"),
            Path("/private/runtime/socket"),
        )

    def reconnect(**kwargs: object):
        reconnect_calls.append(kwargs)
        return client

    monkeypatch.setattr(monitor_lifecycle_module, "sandbox_monitor_control_paths", paths)
    monkeypatch.setattr(monitor_lifecycle_module, "reconnect_sandbox_monitor", reconnect)
    monkeypatch.setattr(
        supervisor,
        "_open_registered_pidfd",
        lambda *_args: pytest.fail("monitor cancellation must not open a host PID"),
    )

    try:
        first = supervisor.terminate_worker(attempt["id"])
        second = supervisor.terminate_worker(attempt["id"])

        assert first == second
        assert first["phase"] == "launched"
        assert first["monitor_phase"] == "stopping"
        assert first["cleanup_verified"] is False
        assert first["outcome"] == "stop_pending"
        assert first["stop_requested"] is True
        assert len(reconnect_calls) == 2
        assert cancel_ids[0] == cancel_ids[1]
        assert len(cancel_ids[0]) == 32
        durable = supervisor._sandbox_execution_get(attempt["id"])
        assert durable["phase"] == "launched"
        with supervisor.connect() as connection:
            assert (
                journal_module._sandbox_execution_launch_stop_reason(connection, durable)
                == "terminate_worker"
            )
        assert os.read(gate_read, 3) == b""
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_journaled_termination_adopts_timeout_stop_that_wins_race(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    handle = _test_runc_handle(target=_test_runc_target(execution))
    record_launch(supervisor, attempt, runc_handle=handle)
    assert record_running(supervisor, attempt)["phase"] == "running"

    request_stop = supervisor._sandbox_execution_request_stop
    timeout_won: list[bool] = []

    def timeout_wins_then_stale_termination(
        attempt_id: str,
        claim_token: int,
        reason: str,
        *,
        credential: str | None = None,
    ) -> dict[str, Any]:
        if reason == "terminate_worker":
            timeout_won.append(True)
            request_stop(
                attempt_id,
                claim_token,
                "execution_timeout",
                credential=credential,
            )
        return request_stop(attempt_id, claim_token, reason, credential=credential)

    monkeypatch.setattr(
        supervisor,
        "_sandbox_execution_request_stop",
        timeout_wins_then_stale_termination,
    )
    cancelled: list[dict[str, Any]] = []

    def cancel_exact(execution: dict[str, Any], *, monitor_client: Any | None = None):
        cancelled.append(execution)
        return {
            "attempt_id": execution["attempt_id"],
            "execution_id": execution["execution_id"],
            "outcome": "ok",
            "phase": execution["phase"],
            "stop_requested": True,
            "monitor_phase": "stopping",
            "cleanup_verified": False,
        }

    monkeypatch.setattr(supervisor, "_cancel_sandbox_execution_monitor", cancel_exact)
    try:
        result = supervisor.terminate_worker(attempt["id"])

        durable = supervisor._sandbox_execution_get(attempt["id"])
        assert timeout_won == [True]
        assert durable is not None and durable["phase"] == "stopping"
        assert durable["stop_reason"] == "execution_timeout"
        assert len(cancelled) == 1
        assert (
            cancelled[0]["attempt_id"],
            cancelled[0]["claim_token"],
            cancelled[0]["execution_id"],
        ) == (attempt["id"], attempt["claim_token"], execution["execution_id"])
        assert result["execution_id"] == execution["execution_id"]
        assert result["phase"] == "stopping"
    finally:
        handle.close_gate()


@pytest.mark.parametrize(
    "reread_overrides",
    [
        pytest.param(
            {"execution_id": "00000000-0000-4000-8000-000000000001"},
            id="different-execution",
        ),
        pytest.param({"phase": "running"}, id="same-execution-not-stopping"),
        pytest.param({"stop_reason": None}, id="same-execution-no-durable-reason"),
    ],
)
def test_journaled_termination_does_not_adopt_unqualified_execution_after_stop_conflict(
    repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    reread_overrides: dict[str, Any],
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    handle = _test_runc_handle(target=_test_runc_target(execution))
    record_launch(supervisor, attempt, runc_handle=handle)
    assert record_running(supervisor, attempt)["phase"] == "running"

    request_stop = supervisor._sandbox_execution_request_stop

    def timeout_wins_then_stale_termination(
        attempt_id: str,
        claim_token: int,
        reason: str,
        *,
        credential: str | None = None,
    ) -> dict[str, Any]:
        if reason == "terminate_worker":
            request_stop(
                attempt_id,
                claim_token,
                "execution_timeout",
                credential=credential,
            )
        return request_stop(attempt_id, claim_token, reason, credential=credential)

    monkeypatch.setattr(
        supervisor,
        "_sandbox_execution_request_stop",
        timeout_wins_then_stale_termination,
    )
    get_execution = supervisor._sandbox_execution_get
    reads = 0

    def mismatched_reread(attempt_id: str) -> dict[str, Any] | None:
        nonlocal reads
        reads += 1
        current = get_execution(attempt_id)
        if reads == 2 and current is not None:
            current = {**current, **reread_overrides}
        return current

    monkeypatch.setattr(supervisor, "_sandbox_execution_get", mismatched_reread)
    monkeypatch.setattr(
        supervisor,
        "_cancel_sandbox_execution_monitor",
        lambda *_args, **_kwargs: pytest.fail("a different execution must not be cancelled"),
    )
    try:
        with pytest.raises(SupervisorError) as termination:
            supervisor.terminate_worker(attempt["id"])

        assert termination.value.code == "sandbox_execution_transition_conflict"
        assert reads >= 2
        durable = get_execution(attempt["id"])
        assert durable is not None and durable["phase"] == "stopping"
        assert durable["stop_reason"] == "execution_timeout"
    finally:
        handle.close_gate()


def test_terminal_termination_reports_durable_stop_without_fake_monitor_phase(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    handle = _test_runc_handle(target=_test_runc_target(execution))
    record_launch(supervisor, attempt, runc_handle=handle)
    try:
        assert record_running(supervisor, attempt)["phase"] == "running"
        assert (
            supervisor._sandbox_execution_request_stop(
                attempt["id"], attempt["claim_token"], "terminate_worker"
            )["phase"]
            == "stopping"
        )
        with handle._gate_lock:
            handle._monitor_client = object()
        assert record_exit(supervisor, attempt)["phase"] == "exited"
        assert handle._monitor_client is None
        monkeypatch.setattr(
            supervisor,
            "_cancel_sandbox_execution_monitor",
            lambda _execution: pytest.fail("terminal execution must not claim a monitor query"),
        )

        result = supervisor.terminate_worker(attempt["id"])

        assert result["phase"] == "exited"
        assert result["stop_requested"] is True
        assert result["monitor_phase"] is None
        assert result["cleanup_verified"] is False
    finally:
        handle.close_gate()


def test_ambiguous_monitor_cancel_keeps_sandbox_execution_fenced(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    record_launch(supervisor, attempt, runc_handle=handle)
    execution_with_scope = supervisor._sandbox_execution_get(attempt["id"])
    assert execution_with_scope is not None
    client = SimpleNamespace(
        status=lambda: SimpleNamespace(
            outcome="ok",
            payload={
                "phase": "running",
                "scope_unit": execution_with_scope["scope_unit"],
                "scope_invocation_id": execution_with_scope["scope_invocation_id"],
                "scope_control_group": execution_with_scope["cgroup_path"],
            },
        ),
        cancel=lambda _request_id: SimpleNamespace(outcome="unknown", payload={"phase": "unknown"}),
    )
    monkeypatch.setattr(
        monitor_lifecycle_module,
        "sandbox_monitor_control_paths",
        lambda **_kwargs: (
            Path("/private/control"),
            Path("/private/control/receipt"),
            Path("/private/runtime/socket"),
        ),
    )
    monkeypatch.setattr(
        monitor_lifecycle_module, "reconnect_sandbox_monitor", lambda **_kwargs: client
    )
    monkeypatch.setattr(
        supervisor,
        "_open_registered_pidfd",
        lambda *_args: pytest.fail("ambiguous monitor result must not fall back to a host PID"),
    )

    try:
        with pytest.raises(SupervisorError) as termination:
            supervisor.terminate_worker(attempt["id"])

        assert termination.value.code == "sandbox_execution_monitor_ambiguous"
        durable = supervisor._sandbox_execution_get(attempt["id"])
        assert durable["phase"] == "launched"
        with supervisor.connect() as connection:
            assert (
                journal_module._sandbox_execution_launch_stop_reason(connection, durable)
                == "terminate_worker"
            )
        with pytest.raises(SupervisorError) as gate_rejected:
            handle.release_gate()
        assert gate_rejected.value.code == "sandbox_launch_gate_closed"
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_monitor_for_another_scope_cannot_cancel_this_execution(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    record_launch(supervisor, attempt, runc_handle=handle)
    execution_with_scope = supervisor._sandbox_execution_get(attempt["id"])
    assert execution_with_scope is not None
    cancel_calls: list[str] = []
    client = SimpleNamespace(
        status=lambda: SimpleNamespace(
            outcome="ok",
            payload={
                "phase": "running",
                "scope_unit": "acp-scope-other.scope",
                "scope_invocation_id": "c" * 32,
                "scope_control_group": "/user.slice/user-1000.slice/acp-scope-other.scope",
            },
        ),
        cancel=lambda request_id: cancel_calls.append(request_id),
    )
    monkeypatch.setattr(
        monitor_lifecycle_module,
        "sandbox_monitor_control_paths",
        lambda **_kwargs: (
            Path("/private/control"),
            Path("/private/control/receipt"),
            Path("/private/runtime/socket"),
        ),
    )
    monkeypatch.setattr(
        monitor_lifecycle_module, "reconnect_sandbox_monitor", lambda **_kwargs: client
    )

    try:
        with pytest.raises(SupervisorError) as termination:
            supervisor.terminate_worker(attempt["id"])

        assert termination.value.code == "sandbox_execution_monitor_identity_mismatch"
        assert cancel_calls == []
        durable = supervisor._sandbox_execution_get(attempt["id"])
        assert durable["phase"] == "launched"
        with supervisor.connect() as connection:
            assert (
                journal_module._sandbox_execution_launch_stop_reason(connection, durable)
                == "terminate_worker"
            )
        with pytest.raises(SupervisorError) as gate_rejected:
            handle.release_gate()
        assert gate_rejected.value.code == "sandbox_launch_gate_closed"
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_journaled_result_import_and_manual_submission_fail_closed(
    repo: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    result_root = tmp_path_factory.mktemp("worker-result")
    baseline, change_set = result_fixture(attempt, result_root)

    with pytest.raises(SupervisorError) as imported:
        supervisor.import_worker_result(attempt["id"], attempt["claim_token"], baseline, change_set)
    assert imported.value.code == "sandbox_result_unverified"

    with pytest.raises(SupervisorError) as submitted:
        supervisor._submit(
            attempt["id"],
            attempt["claim_token"],
            expected_worker_pid=None,
            credential=None,
        )
    assert submitted.value.code == "sandbox_result_unverified"
    with supervisor.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM result_imports").fetchone()[0] == 0
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "reserved"


def test_cleanup_verified_nonzero_exit_is_not_result_eligible() -> None:
    row = {"phase": "cleanup_verified", "runc_exit_code": 137}
    connection = SimpleNamespace(execute=lambda *_args: SimpleNamespace(fetchone=lambda: row))

    with pytest.raises(SupervisorError) as rejected:
        journal_module._require_sandbox_execution_result_eligible(connection, "cancelled-attempt")

    assert rejected.value.code == "sandbox_result_unverified"


def test_nonzero_cleanup_verified_execution_cannot_match_import_candidate() -> None:
    row = {"phase": "cleanup_verified", "runc_exit_code": 137}
    connection = SimpleNamespace(execute=lambda *_args: SimpleNamespace(fetchone=lambda: row))

    with pytest.raises(SupervisorError) as rejected:
        GitSupervisor._sandbox_execution_require_result_candidate_matches(
            SimpleNamespace(),
            connection,
            "cancelled-attempt",
            baseline_digest="a" * 64,
            import_digest="b" * 64,
            change_digest="c" * 64,
        )

    assert rejected.value.code == "sandbox_result_evidence_unverified"


def test_journaled_sandbox_never_aliases_into_direct_worker_result_receipts(
    repo: Path,
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    result_root = tmp_path_factory.mktemp("worker-result")
    baseline, change_set = result_fixture(attempt, result_root)

    # Simulate an open eligibility gate to isolate the independent identity
    # source check. It must reject the direct-worker route before PID or
    # worker.exit receipts can be consulted, even after a future verifier exists.
    monkeypatch.setattr(
        claims_module,
        "_require_sandbox_execution_result_eligible",
        lambda _connection, _attempt_id: None,
    )
    with pytest.raises(SupervisorError) as imported:
        supervisor.import_worker_result(attempt["id"], attempt["claim_token"], baseline, change_set)

    assert imported.value.code == "sandbox_result_import_route_required"
    with supervisor.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM result_imports").fetchone()[0] == 0

        # Deliberately bypass the new database guard so the application-level
        # recovery/submit fence also gets exercised against a corrupt legacy row.
        connection.execute("DROP TRIGGER result_import_direct_source_insert_guard")
        connection.execute(
            """
            INSERT INTO result_imports
              (id, attempt_id, claim_token, worker_pid, worker_identity,
               worker_exit_receipt_json, base_sha, tree_sha, baseline_digest,
               result_digest, change_digest, result_ref, commit_timestamp,
               commit_sha, phase, created_at, updated_at)
            VALUES ('untrusted-direct-import', ?, ?, 202, 'synthetic-pid-identity', '{}',
                    'base', 'tree', 'baseline', 'result', 'change', 'refs/acp/untrusted',
                    0, 'commit', 'prepared', 'now', 'now')
            """,
            (attempt["id"], attempt["claim_token"]),
        )

    staging_cleanup_called = False

    def record_staging_cleanup() -> None:
        nonlocal staging_cleanup_called
        staging_cleanup_called = True

    monkeypatch.setattr(supervisor, "_cleanup_result_import_staging_locked", record_staging_cleanup)
    with pytest.raises(SupervisorError) as recovered:
        supervisor.recover_worker_result_import("untrusted-direct-import")
    assert recovered.value.code == "sandbox_result_import_route_required"
    assert staging_cleanup_called is False

    with pytest.raises(SupervisorError) as submitted:
        supervisor._submit(
            attempt["id"],
            attempt["claim_token"],
            expected_worker_pid=202,
            credential=None,
            imported_result_id="untrusted-direct-import",
        )
    assert submitted.value.code == "sandbox_result_import_route_required"


def test_result_import_rechecks_journal_at_result_write_boundary(
    repo: Path, tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    worker_pid = 9876
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET pid = ?, pid_identity = ? WHERE id = ?",
            (worker_pid, "synthetic-worker-identity", attempt["id"]),
        )
    monkeypatch.setattr(
        supervisor,
        "_worker_exit_receipt_in",
        lambda connection, current, expected_pid: "synthetic-exit-receipt",
    )
    result_root = tmp_path_factory.mktemp("worker-result")
    baseline, change_set = result_fixture(attempt, result_root)
    original_guard = claims_module._require_sandbox_execution_result_eligible
    guard_calls = 0

    def add_journal_before_second_check(connection, attempt_id: str) -> None:
        nonlocal guard_calls
        guard_calls += 1
        if guard_calls == 2:
            stamp = "2026-10-04T00:00:00Z"
            execution = {
                "attempt_id": attempt_id,
                "claim_token": attempt["claim_token"],
                "execution_id": "race-execution",
                "backend": "oci-runc",
                "container_id": "race-container",
                "rootfs_digest": "a" * 64,
                "rootfs_closure_digest": "b" * 64,
                "runc_executable_digest": "c" * 64,
                "runtime_version": "test-runc",
                "oci_version": "1.2.1",
                "bundle_path": "/bundle",
                "state_path": "/state",
            }
            bundle_digest = journal_module._sandbox_reservation_bundle_digest(execution)
            with _authorize_sandbox_reservation_write(
                connection,
                attempt_id,
                attempt["claim_token"],
                execution["execution_id"],
                bundle_digest,
                "oci-reservation-v1",
            ):
                connection.execute(
                    """
                    INSERT INTO sandbox_executions
                      (attempt_id, claim_token, execution_id, backend, container_id,
                       bundle_digest, bundle_digest_semantics, rootfs_digest,
                       rootfs_closure_digest, runc_executable_digest, runtime_version,
                       oci_version, bundle_path, state_path, phase, created_at, updated_at)
                    VALUES (?, ?, ?, 'oci-runc', ?, ?, 'oci-reservation-v1', ?, ?, ?, ?,
                            ?, ?, ?, 'reserved', ?, ?)
                    """,
                    (
                        execution["attempt_id"],
                        execution["claim_token"],
                        execution["execution_id"],
                        execution["container_id"],
                        bundle_digest,
                        execution["rootfs_digest"],
                        execution["rootfs_closure_digest"],
                        execution["runc_executable_digest"],
                        execution["runtime_version"],
                        execution["oci_version"],
                        execution["bundle_path"],
                        execution["state_path"],
                        stamp,
                        stamp,
                    ),
                )
        original_guard(connection, attempt_id)

    monkeypatch.setattr(
        claims_module,
        "_require_sandbox_execution_result_eligible",
        add_journal_before_second_check,
    )
    with pytest.raises(SupervisorError) as imported:
        supervisor.import_worker_result(attempt["id"], attempt["claim_token"], baseline, change_set)

    assert imported.value.code == "sandbox_result_unverified"
    assert guard_calls == 2
    with supervisor.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM result_imports").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM sandbox_executions").fetchone()[0] == 0


def test_journaled_result_recovery_is_fenced_before_staging_cleanup(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    import_id = "untrusted-result-import"
    stamp = "2026-10-04T00:00:00Z"
    with supervisor.connect() as connection:
        # Simulate a corrupt pre-v19 database row; current schema writes reject it.
        connection.execute("DROP TRIGGER result_import_direct_source_insert_guard")
        connection.execute(
            """
            INSERT INTO result_imports
              (id, attempt_id, claim_token, worker_pid, worker_identity,
               worker_exit_receipt_json, base_sha, tree_sha, baseline_digest,
               result_digest, change_digest, result_ref, commit_timestamp,
               commit_sha, phase, created_at, updated_at)
            VALUES (?, ?, ?, 41, 'worker-identity', '{}', 'base', 'tree', 'baseline',
                    'result', 'changes', 'refs/acp/result', 0, 'commit',
                    'prepared', ?, ?)
            """,
            (
                import_id,
                attempt["id"],
                attempt["claim_token"],
                stamp,
                stamp,
            ),
        )
    cleanup_called = False

    def record_cleanup() -> None:
        nonlocal cleanup_called
        cleanup_called = True

    monkeypatch.setattr(supervisor, "_cleanup_result_import_staging_locked", record_cleanup)
    with pytest.raises(SupervisorError) as recovered:
        supervisor.recover_worker_result_import(import_id)

    assert recovered.value.code == "sandbox_result_unverified"
    assert cleanup_called is False
    with supervisor.connect() as connection:
        row = connection.execute(
            "SELECT phase FROM result_imports WHERE id = ?", (import_id,)
        ).fetchone()
    assert row["phase"] == "prepared"


def test_missing_result_journal_still_cleans_unowned_staging(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    import_id = "00000000-0000-4000-8000-000000000001"
    stage = supervisor._result_import_stage_path(import_id, create=True)
    (stage / "objects" / "orphan-marker").write_text("orphan", encoding="utf-8")

    with pytest.raises(SupervisorError) as recovered:
        supervisor.recover_worker_result_import(import_id)

    assert recovered.value.code == "result_import_not_found"
    assert not stage.exists()


def test_concurrent_reservations_have_one_winner(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    # Provision the shared config once; the race under test is journal
    # reservation, not concurrent issuance of process-local OCI pin handles.
    configured_sandbox_claims(supervisor)
    barrier = threading.Barrier(2)

    def try_reserve() -> dict | str:
        barrier.wait(timeout=5)
        try:
            return reserve(supervisor, attempt)
        except SupervisorError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: try_reserve(), range(2)))

    assert sum(isinstance(result, dict) for result in results) == 1
    assert sum(result == "sandbox_execution_exists" for result in results) == 1
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "reserved"


def test_concurrent_direct_and_sandbox_reservations_serialize(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    barrier = threading.Barrier(2)

    def reserve_sandbox() -> str:
        barrier.wait(timeout=5)
        try:
            reserve(supervisor, attempt)
        except SupervisorError as error:
            return error.code
        return "sandbox"

    def reserve_direct() -> str:
        barrier.wait(timeout=5)
        try:
            supervisor._reserve_worker_launch(
                attempt["id"], attempt["claim_token"], ".acp/logs/direct.log", None
            )
        except SupervisorError as error:
            return error.code
        return "direct"

    with ThreadPoolExecutor(max_workers=2) as pool:
        sandbox_result, direct_result = list(
            pool.map(lambda function: function(), (reserve_sandbox, reserve_direct))
        )

    assert (sandbox_result, direct_result) in {
        ("sandbox", "sandbox_execution_reserved"),
        ("worker_already_running", "direct"),
    }
    journal = supervisor._sandbox_execution_get(attempt["id"])
    direct_pid = supervisor.attempt(attempt["id"])["pid"]
    if sandbox_result == "sandbox":
        assert journal is not None
        assert direct_pid is None
    else:
        assert journal is None
        assert direct_pid == -1


def test_concurrent_sandbox_attempts_bind_disjoint_private_workspaces(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    first = claimed(supervisor, "alpha.txt")
    second = claimed(supervisor, "beta.txt")
    runtime_claims = configured_sandbox_claims(supervisor)
    barrier = threading.Barrier(2)

    def reserve_attempt(attempt: dict) -> dict:
        barrier.wait(timeout=5)
        return reserve(supervisor, attempt, runtime_claims=runtime_claims)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first_execution, second_execution = list(pool.map(reserve_attempt, (first, second)))

    assert first_execution["attempt_id"] == first["id"]
    assert second_execution["attempt_id"] == second["id"]
    assert first_execution["execution_id"] != second_execution["execution_id"]
    assert first_execution["container_id"] != second_execution["container_id"]

    first_root = Path(first_execution["bundle_path"]).parent
    second_root = Path(second_execution["bundle_path"]).parent
    assert first_root != second_root
    assert first_root.parent == second_root.parent == supervisor.state_dir / "sandbox-executions"
    assert first_root.name == f"{first['id']}-{first['claim_token']}"
    assert second_root.name == f"{second['id']}-{second['claim_token']}"

    first_workspace = Path(first_execution["workspace_root_path"])
    second_workspace = Path(second_execution["workspace_root_path"])
    first_baseline = Path(first_execution["baseline_root_path"])
    second_baseline = Path(second_execution["baseline_root_path"])
    assert first_workspace == first_root / "workspace"
    assert second_workspace == second_root / "workspace"
    assert first_baseline == first_root / "baseline"
    assert second_baseline == second_root / "baseline"
    assert not (first_workspace / ".git").exists()
    assert not (second_workspace / ".git").exists()
    assert not os.path.samefile(first_workspace, second_workspace)
    assert not os.path.samefile(first_baseline, second_baseline)

    write_barrier = threading.Barrier(2)

    def write_sentinel(workspace: Path, owner: str) -> str:
        write_barrier.wait(timeout=5)
        marker = workspace / "parallel-owner.marker"
        marker.write_text(owner, encoding="ascii")
        return marker.read_text(encoding="ascii")

    with ThreadPoolExecutor(max_workers=2) as pool:
        first_marker, second_marker = list(
            pool.map(
                write_sentinel,
                (first_workspace, second_workspace),
                ("first", "second"),
            )
        )
    assert first_marker == "first"
    assert second_marker == "second"
    assert not (first_baseline / "parallel-owner.marker").exists()
    assert not (second_baseline / "parallel-owner.marker").exists()
    assert not (Path(first["worktree"]) / "parallel-owner.marker").exists()
    assert not (Path(second["worktree"]) / "parallel-owner.marker").exists()


def test_sql_phase_checks_reject_nullable_process_identities(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    launch_fields = (
        "monitor_identity = 'linux:101:1101', runc_client_pid = 202, "
        "runc_client_identity = 'linux:202:1202', wrapper_unit = 'acp-worker.service', "
        "wrapper_invocation_id = '11111111111111111111111111111111', "
        "scope_unit = 'acp-container.scope', "
        "scope_invocation_id = '22222222222222222222222222222222', "
        "cgroup_path = '/user.slice/user-1000.slice/user@1000.service/app.slice/acp-container.scope'"
    )
    with supervisor.connect() as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                f"UPDATE sandbox_executions SET phase = 'launched', monitor_pid = NULL, "
                f"{launch_fields} WHERE attempt_id = ?",
                (attempt["id"],),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                f"UPDATE sandbox_executions SET phase = 'launched', monitor_pid = 101, "
                f"{launch_fields.replace('runc_client_pid = 202', 'runc_client_pid = NULL')} "
                "WHERE attempt_id = ?",
                (attempt["id"],),
            )

    record_launch(supervisor, attempt)
    with supervisor.connect() as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE sandbox_executions SET phase = 'running', init_pid = NULL, "
                "init_identity = 'linux:303:1303' WHERE attempt_id = ?",
                (attempt["id"],),
            )
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"


def test_recorded_execution_evidence_is_immutable(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    record_launch(supervisor, attempt)
    record_running(supervisor, attempt)

    mutations = (
        ("rootfs_closure_digest = 'e' || substr(rootfs_closure_digest, 2)", "identity"),
        ("runc_executable_digest = 'e' || substr(runc_executable_digest, 2)", "identity"),
        ("monitor_pid = 404", "evidence"),
        ("monitor_identity = 'replacement-monitor'", "evidence"),
        ("scope_invocation_id = '33333333333333333333333333333333'", "evidence"),
        ("cgroup_path = '/different/scope'", "evidence"),
        ("init_pid = 505", "evidence"),
    )
    for mutation, identity_or_evidence in mutations:
        expected_error = (
            "sandbox_execution_identity_immutable"
            if identity_or_evidence == "identity"
            else "sandbox_execution_evidence"
        )
        with supervisor.connect() as connection:
            with pytest.raises(
                sqlite3.IntegrityError,
                match=expected_error,
            ):
                connection.execute(
                    f"UPDATE sandbox_executions SET {mutation} WHERE attempt_id = ?",
                    (attempt["id"],),
                )

    record_exit(supervisor, attempt)
    with supervisor.connect() as connection:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="sandbox_execution_exit_evidence_write_requires_exit",
        ):
            connection.execute(
                "UPDATE sandbox_executions SET runc_exit_code = 1 WHERE attempt_id = ?",
                (attempt["id"],),
            )

    receipt = cleanup_receipt(supervisor, attempt["id"])
    supervisor._sandbox_execution_record_cleanup_report(
        attempt["id"], attempt["claim_token"], receipt
    )
    with supervisor.connect() as connection:
        with pytest.raises(sqlite3.IntegrityError, match="sandbox_execution_evidence"):
            connection.execute(
                "UPDATE sandbox_executions SET cleanup_receipt_json = '{}' WHERE attempt_id = ?",
                (attempt["id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="sandbox_private_path_binding_immutable"):
            connection.execute(
                "UPDATE sandbox_executions SET bundle_root_ino = bundle_root_ino + 1 "
                "WHERE attempt_id = ?",
                (attempt["id"],),
            )


def test_transition_order_keeps_monitor_runc_and_init_identities_distinct(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)

    with pytest.raises(SupervisorError) as out_of_order:
        supervisor._sandbox_execution_record_running(
            attempt["id"], attempt["claim_token"], attestation=None
        )
    assert out_of_order.value.code == "sandbox_execution_transition_invalid"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "reserved"

    row = record_launch(supervisor, attempt)
    assert row["phase"] == "launched"
    with pytest.raises(SupervisorError) as pid_alias:
        supervisor._sandbox_execution_record_running(
            attempt["id"],
            attempt["claim_token"],
            attestation=replace(running_attestation(supervisor, attempt), init_pid=202),
        )
    assert pid_alias.value.code == "sandbox_runtime_attestation_invalid"

    row = record_running(supervisor, attempt)
    assert row["phase"] == "running"
    row = supervisor._sandbox_execution_request_stop(
        attempt["id"], attempt["claim_token"], "attempt cancellation"
    )
    assert row["phase"] == "stopping"
    assert (
        supervisor._sandbox_execution_request_stop(
            attempt["id"], attempt["claim_token"], "attempt cancellation"
        )["phase"]
        == "stopping"
    )

    with pytest.raises(SupervisorError) as caller_supplied:
        supervisor._sandbox_execution_record_exit(attempt["id"], attempt["claim_token"], 0)
    assert caller_supplied.value.code == "sandbox_execution_wait_receipt_required"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "stopping"

    row = record_exit(supervisor, attempt)
    assert row["phase"] == "exited"
    assert row["runc_exit_code"] == 0
    assert row["runc_exit_observed_by"] == "runc_client_kernel_waitpid"
    assert row["runc_exit_evidence_source"] == "runc_client_kernel_waitpid"
    with supervisor.connect() as connection:
        stored = connection.execute(
            "SELECT runc_exit_observed_by, runc_exit_evidence_source "
            "FROM sandbox_executions WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()
    assert stored["runc_exit_observed_by"] == "runc_client_popen_wait"
    assert stored["runc_exit_evidence_source"] == "runc_client_kernel_waitpid"
    assert supervisor.verify_event_chain()["ok"] is True


def test_exit_evidence_cannot_be_stamped_before_kernel_wait(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    record_launch(supervisor, attempt)

    with supervisor.connect() as connection:
        row = connection.execute(
            "SELECT execution_id, attempt_slice_cgroup_path, "
            "launch_driver_start_redeemed_pid, launch_driver_start_redeemed_identity, "
            "launch_driver_start_redeemed_invocation_id, "
            "launch_driver_start_redeemed_cgroup_path, "
            "launch_driver_start_redeemed_slice_unit, "
            "launch_driver_start_redeemed_slice_invocation_id, "
            "launch_driver_start_redeemed_slice_cgroup_path "
            "FROM sandbox_executions "
            "WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()
        driver_unit = journal_module._sandbox_launch_driver_service_unit(row["execution_id"])
    # Use a separate, deliberately unprotected test connection to isolate this
    # trigger from the public store facade's callback-registration boundary.
    with sqlite3.connect(supervisor.db_path) as raw_connection:
        for function_name, argument_count in (
            ("acp_sandbox_exit_receipt_authorized", 6),
            ("acp_sandbox_launch_plan_authorized", 7),
            ("acp_sandbox_launch_submission_authorized", 5),
            ("acp_sandbox_reservation_authorized", 5),
            ("acp_sandbox_cleanup_action_authorized", 4),
            ("acp_sandbox_cleanup_report_authorized", 4),
            ("acp_sandbox_cleanup_verification_authorized", 4),
        ):
            raw_connection.create_function(function_name, argument_count, lambda *_: 0)
        raw_connection.create_function(
            "acp_sandbox_running_attestation_authorized",
            8,
            lambda *_: 1,
        )
        with pytest.raises(
            sqlite3.IntegrityError,
            match="sandbox_execution_exit_evidence_write_requires_exit",
        ):
            raw_connection.execute(
                """
                UPDATE sandbox_executions
                SET phase = 'running', init_pid = 4242, init_identity = 'synthetic-start',
                    runc_exit_evidence_source = 'runc_client_kernel_waitpid',
                    launch_driver_pid = ?, launch_driver_identity = ?,
                    launch_driver_unit = ?, launch_driver_invocation_id = ?,
                    launch_driver_cgroup_path = ?
                WHERE attempt_id = ?
                """,
                (
                    row["launch_driver_start_redeemed_pid"],
                    row["launch_driver_start_redeemed_identity"],
                    driver_unit,
                    row["launch_driver_start_redeemed_invocation_id"],
                    row["launch_driver_start_redeemed_cgroup_path"],
                    attempt["id"],
                ),
            )

    still_launched = supervisor._sandbox_execution_get(attempt["id"])
    assert still_launched is not None
    assert still_launched["phase"] == "launched"
    assert still_launched["runc_exit_evidence_source"] == ""

    record_running(supervisor, attempt)
    exited = record_exit(supervisor, attempt)
    assert exited["runc_exit_evidence_source"] == "runc_client_kernel_waitpid"


def test_generic_transition_cannot_forge_exit_without_registered_wait_receipt() -> None:
    # Exit persistence is not part of the generic transition surface. Keep this
    # regression independent of a Git checkout so it runs on the NAS Linux lane.
    supervisor = GitSupervisor.__new__(GitSupervisor)
    attempt_id = "sandbox-attempt-receipt-gate"
    claim_token = 7
    with pytest.raises(SupervisorError) as rejected:
        supervisor._sandbox_execution_transition(
            attempt_id,
            claim_token,
            expected_phase="launched",
            next_phase="exited",
            updates={
                "runc_exit_code": 0,
                "runc_exit_observed_by": "runc_client_popen_wait",
                "runc_exit_evidence_source": "runc_client_kernel_waitpid",
            },
            event_type="sandbox.execution_exited",
            event_payload={
                "runc_exit_code": 0,
                "observed_by": "runc_client_kernel_waitpid",
            },
        )
    assert rejected.value.code == "sandbox_execution_transition_invalid"


def test_sql_exit_transition_cannot_forge_kernel_wait_receipt(tmp_path: Path) -> None:
    database_path = tmp_path / "receipt-guard.db"
    raw_connection = sqlite3.connect(database_path)
    try:
        raw_connection.execute(
            """
            CREATE TABLE sandbox_executions (
              attempt_id TEXT PRIMARY KEY,
              claim_token INTEGER NOT NULL,
              execution_id TEXT NOT NULL,
              phase TEXT NOT NULL,
              runc_client_pid INTEGER,
              runc_client_identity TEXT NOT NULL,
              runc_exit_code INTEGER,
              runc_exit_observed_by TEXT NOT NULL DEFAULT '',
              runc_exit_evidence_source TEXT NOT NULL DEFAULT ''
            )
            """
        )
        raw_connection.commit()
    finally:
        raw_connection.close()

    supervisor = GitSupervisor.__new__(GitSupervisor)
    supervisor.read_only = False
    supervisor.db_path = database_path
    with supervisor.connect() as connection:
        dict(MIGRATIONS)[21](connection)
        connection.execute(
            "INSERT INTO sandbox_executions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "sandbox-attempt-sql-guard",
                11,
                "sandbox-execution-sql-guard",
                "launched",
                202,
                "linux:202:1202",
                None,
                "",
                "",
            ),
        )

    with supervisor.connect() as connection:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="sandbox_execution_wait_receipt_required",
        ):
            connection.execute(
                "UPDATE sandbox_executions SET runc_exit_code = 0, "
                "runc_exit_observed_by = 'runc_client_popen_wait', "
                "runc_exit_evidence_source = 'runc_client_kernel_waitpid', "
                "phase = 'exited' WHERE attempt_id = ?",
                ("sandbox-attempt-sql-guard",),
            )

    with supervisor.connect() as connection:
        row = connection.execute(
            "SELECT phase, runc_exit_evidence_source FROM sandbox_executions WHERE attempt_id = ?",
            ("sandbox-attempt-sql-guard",),
        ).fetchone()
    assert row["phase"] == "launched"
    assert row["runc_exit_evidence_source"] == ""


def test_runc_wait_receipt_must_match_durable_pid_start_identity(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    record_launch(supervisor, attempt)
    record_running(supervisor, attempt)

    execution = supervisor._sandbox_execution_get(attempt["id"])
    assert execution is not None
    wrong_handle = _test_runc_handle(target=_test_runc_target(execution), start_ticks=9999)
    _register_test_runc_launch(wrong_handle, launch_submission=None)
    oci_worker._runc_launch_handle_bind_execution(
        wrong_handle,
        attempt["id"],
        attempt["claim_token"],
        execution["execution_id"] + "-different",
    )
    reused_pid = wrong_handle.wait()
    with pytest.raises(SupervisorError) as mismatched:
        supervisor._sandbox_execution_record_exit(attempt["id"], attempt["claim_token"], reused_pid)

    assert mismatched.value.code == "sandbox_execution_wait_receipt_stale"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "running"
    assert record_exit(supervisor, attempt)["phase"] == "exited"


@pytest.mark.parametrize("path_field", ["execution_root", "bundle_path", "state_path"])
@pytest.mark.parametrize("replacement_kind", ["symlink", "directory"])
def test_workspace_restore_and_launch_reject_replaced_private_runtime_paths(
    repo: Path,
    tmp_path: Path,
    path_field: str,
    replacement_kind: str,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)
    runtime_path = (
        Path(row["bundle_path"]).parent if path_field == "execution_root" else Path(row[path_field])
    )
    moved_path = runtime_path.with_name(f"{runtime_path.name}-original")
    runtime_path.rename(moved_path)
    if replacement_kind == "symlink":
        runtime_path.symlink_to(tmp_path, target_is_directory=True)
    else:
        runtime_path.mkdir(mode=0o700)
        if path_field == "execution_root":
            (runtime_path / "bundle").mkdir(mode=0o700)
            (runtime_path / "state").mkdir(mode=0o700)

    with pytest.raises(SupervisorError) as restore:
        supervisor._sandbox_execution_restore_workspace_binding(
            attempt["id"], attempt["claim_token"]
        )
    assert restore.value.code in {
        "sandbox_private_path_invalid",
        "sandbox_private_path_conflict",
        "invalid_snapshot",
    }

    with pytest.raises(SupervisorError) as launch:
        record_launch(supervisor, attempt)
    assert launch.value.code in {
        "sandbox_private_path_invalid",
        "sandbox_execution_gate_unavailable",
        "sandbox_execution_gate_identity_mismatch",
        "invalid_snapshot",
        "unsafe_workspace_root",
    }


def test_private_runtime_path_binding_is_required_and_write_once(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)

    with supervisor.connect() as connection:
        with pytest.raises(sqlite3.IntegrityError, match="sandbox_private_path_binding_immutable"):
            connection.execute(
                "UPDATE sandbox_executions SET state_root_ino = state_root_ino + 1 "
                "WHERE attempt_id = ?",
                (attempt["id"],),
            )

    restored = supervisor._sandbox_execution_restore_workspace_binding(
        attempt["id"], attempt["claim_token"]
    )
    assert restored["private_path_binding_version"] == 1
    assert restored["bundle_root_inode"] == row["bundle_root_ino"]
    assert restored["state_root_inode"] == row["state_root_ino"]
    assert supervisor.verify_event_chain()["ok"] is True


def test_running_transition_requires_intact_attestation_bound_to_launch(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    record_launch(supervisor, attempt)

    with pytest.raises(SupervisorError) as untyped:
        supervisor._sandbox_execution_record_running(
            attempt["id"], attempt["claim_token"], attestation={"init_pid": 303}
        )
    assert untyped.value.code == "sandbox_runtime_attestation_invalid"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"

    receipt = running_attestation(supervisor, attempt)
    tampered = replace(receipt, init_identity="linux:303:9999")
    with pytest.raises(SupervisorError) as invalid:
        supervisor._sandbox_execution_record_running(
            attempt["id"], attempt["claim_token"], attestation=tampered
        )
    assert invalid.value.code == "sandbox_runtime_attestation_invalid"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"

    stale = replace(receipt, container_id="different-container")
    stale_payload = stale.audit_payload()
    stale_payload.pop("evidence_sha256")
    stale = replace(
        stale,
        evidence_sha256=hashlib.sha256(canonical_json(stale_payload).encode("utf-8")).hexdigest(),
    )
    assert not running_attestation_is_self_consistent(stale)
    with pytest.raises(SupervisorError) as mismatched_launch:
        supervisor._sandbox_execution_record_running(
            attempt["id"], attempt["claim_token"], attestation=stale
        )
    assert mismatched_launch.value.code == "sandbox_runtime_attestation_invalid"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"

    monkeypatch.setattr(
        sandbox_attestation_module,
        "read_cgroup_resource_controls",
        lambda _path: {
            "memory.max": f"{receipt.memory_max_bytes}\n".encode("ascii"),
            "cpu.max": f"{receipt.cpu_quota} {receipt.cpu_period}\n".encode("ascii"),
            "pids.max": f"{receipt.pids_max}\n".encode("ascii"),
        },
    )
    monkeypatch.setattr(
        sandbox_attestation_module,
        "read_linux_process_snapshot",
        lambda pid: _live_process_snapshot(receipt, pid),
    )
    running = supervisor._sandbox_execution_record_running(
        attempt["id"],
        attempt["claim_token"],
        attestation=receipt,
        runc_handle=attempt["_test_runc_handle"],
    )
    assert running["phase"] == "running"
    assert running["init_pid"] == 303
    assert running["init_identity"] == "linux:303:1303"


def test_running_transition_rejects_collected_receipt_for_other_launch_driver(
    repo: Path,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        receipt = running_attestation(
            supervisor,
            attempt,
            launch_driver_unit_override="acp-launch-driver-other-execution.service",
        )

        assert running_attestation_is_self_consistent(receipt)
        assert running_attestation_has_collector_provenance(receipt)
        with pytest.raises(SupervisorError) as rejected:
            supervisor._sandbox_execution_record_running(
                attempt["id"],
                attempt["claim_token"],
                attestation=receipt,
                runc_handle=handle,
            )

        assert rejected.value.code == "sandbox_runtime_attestation_stale"
        assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"
        with pytest.raises(SupervisorError) as gate_rejected:
            handle.release_gate()
        assert gate_rejected.value.code == "sandbox_launch_gate_not_authorized"
        os.set_blocking(gate_read, False)
        with pytest.raises(BlockingIOError):
            os.read(gate_read, 3)
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_reaper_retries_cleanup_verification_but_legacy_receipt_stays_fenced(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    record_launch(supervisor, attempt)
    record_running(supervisor, attempt)
    record_exit(supervisor, attempt)

    receipt = cleanup_receipt(supervisor, attempt["id"])
    assert receipt["version"] == 2
    assert receipt["verification_status"] == "unverified"
    assert all(observation is None for observation in receipt["observations"].values())
    counterfeit = json.loads(json.dumps(receipt))
    counterfeit["observations"]["runc_delete_exit_code"] = 0
    with pytest.raises(SupervisorError) as invalid:
        supervisor._sandbox_execution_record_cleanup_report(
            attempt["id"], attempt["claim_token"], counterfeit
        )
    assert invalid.value.code == "sandbox_cleanup_report_invalid"
    forged_status = json.loads(json.dumps(receipt))
    forged_status["verification_status"] = "verified"
    with pytest.raises(SupervisorError) as invalid_status:
        supervisor._sandbox_execution_record_cleanup_report(
            attempt["id"], attempt["claim_token"], forged_status
        )
    assert invalid_status.value.code == "sandbox_cleanup_report_invalid"

    row = supervisor._sandbox_execution_record_cleanup_report(
        attempt["id"], attempt["claim_token"], receipt
    )
    assert row["phase"] == "cleanup_reported"

    retry_calls: list[tuple[str, int]] = []

    def reject_legacy_report(attempt_id: str, claim_token: int) -> None:
        retry_calls.append((attempt_id, claim_token))
        raise SupervisorError(
            "sandbox_cleanup_verification_unavailable",
            "legacy cleanup receipt cannot satisfy the independent verifier",
        )

    monkeypatch.setattr(supervisor, "_sandbox_execution_verify_cleanup", reject_legacy_report)

    with supervisor.connect() as connection:
        with pytest.raises(sqlite3.IntegrityError, match="phase_transition_invalid"):
            connection.execute(
                "UPDATE sandbox_executions SET phase = 'cleanup_verified' WHERE attempt_id = ?",
                (attempt["id"],),
            )
    with pytest.raises(SupervisorError) as unavailable:
        supervisor._sandbox_execution_transition(
            attempt["id"],
            attempt["claim_token"],
            expected_phase="cleanup_reported",
            next_phase="cleanup_verified",
            updates={},
            event_type="sandbox.execution_cleanup_verified",
            event_payload={},
        )
    assert unavailable.value.code == "sandbox_execution_transition_invalid"

    with pytest.raises(SupervisorError) as teardown:
        supervisor.runtime_down(attempt["id"], force=True)
    assert teardown.value.code == "sandbox_cleanup_unverified"

    result = supervisor.reap_expired(now=attempt["lease_expires_at"] + 1)
    assert retry_calls == [(attempt["id"], attempt["claim_token"])]
    assert result["terminated_workers"] == []
    assert result["runtime_cleanup"] == []
    assert supervisor.attempt(attempt["id"])["termination_target_status"] == "quarantined"
    assert supervisor.task(attempt["task_id"])["status"] == "cleanup_pending"
    with supervisor.connect() as connection:
        with pytest.raises(SupervisorError) as task_cleanup:
            supervisor._complete_task_cleanup(connection, attempt["task_id"], attempt["id"], "test")
    assert task_cleanup.value.code == "sandbox_cleanup_unverified"
    with supervisor.connect() as connection:
        lease = connection.execute(
            "SELECT lease_expires_at FROM resource_leases WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()
    assert lease["lease_expires_at"] == CLEANUP_FENCE_EPOCH
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "cleanup_reported"


@pytest.mark.parametrize(
    ("phase", "submission_state"),
    [
        ("reserved", "absent"),
        ("running", "recorded"),
        ("exited", "recorded"),
        ("cleanup_reported", "recorded"),
    ],
)
def test_reaper_quarantine_diagnoses_proxy_artifact_hold(
    repo: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    submission_state: str,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    if phase != "reserved":
        record_launch(supervisor, attempt)
    if phase in {"running", "exited", "cleanup_reported"}:
        record_running(supervisor, attempt)
    if phase in {"exited", "cleanup_reported"}:
        record_exit(supervisor, attempt)
    if phase == "cleanup_reported":
        supervisor._sandbox_execution_record_cleanup_report(
            attempt["id"], attempt["claim_token"], cleanup_receipt(supervisor, attempt["id"])
        )

        def reject_cleanup_verification(*_args: Any, **_kwargs: Any) -> None:
            raise SupervisorError("sandbox_cleanup_verification_unavailable", "injected hold")

        monkeypatch.setattr(
            supervisor, "_sandbox_execution_verify_cleanup", reject_cleanup_verification
        )

    proxy_directory = tmp_path / "attempt-provider-proxy"
    proxy_directory.mkdir(mode=0o700)
    proxy_socket = proxy_directory / "provider.sock"
    proxy_socket.write_text("must remain quarantined\n", encoding="utf-8")
    monkeypatch.setattr(
        monitor_lifecycle_module,
        "sandbox_provider_proxy_control_paths",
        lambda **_kwargs: (proxy_directory, proxy_socket),
    )

    result = supervisor.reap_expired(now=attempt["lease_expires_at"] + 1)

    assert result["runtime_cleanup"] == []
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == phase
    task = supervisor.task(attempt["task_id"])
    assert task["status"] == "cleanup_pending"
    assert task["cleanup_target_status"] == "blocked"
    assert f"phase={phase}" in task["cleanup_error"]
    assert f"launch_submission={submission_state}" in task["cleanup_error"]
    assert "provider proxy artifact, if present, is retained" in task["cleanup_error"]
    assert proxy_socket.read_text(encoding="utf-8") == "must remain quarantined\n"
    assert supervisor.attempt(attempt["id"])["termination_target_status"] == "quarantined"
    with supervisor.connect() as connection:
        leases = connection.execute(
            "SELECT lease_expires_at FROM resource_leases WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchall()
    assert leases and all(item["lease_expires_at"] == CLEANUP_FENCE_EPOCH for item in leases)


def test_result_candidate_is_versioned_bound_and_never_authorizes_import(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)
    workspace = Path(row["workspace_root_path"])
    record_launch(supervisor, attempt)
    record_running(supervisor, attempt)
    (workspace / "alpha.txt").write_text("candidate result\n", encoding="utf-8")
    record_exit(supervisor, attempt)
    supervisor._sandbox_execution_record_cleanup_report(
        attempt["id"], attempt["claim_token"], cleanup_receipt(supervisor, attempt["id"])
    )

    with pytest.raises(SupervisorError) as unverified:
        supervisor._sandbox_execution_capture_result_candidate(
            attempt["id"], attempt["claim_token"]
        )
    assert unverified.value.code == "sandbox_result_evidence_unverified"
    assert supervisor._sandbox_execution_get(attempt["id"])["result_candidate_version"] == 0

    synthesize_cleanup_verified_for_downstream_test(supervisor, attempt["id"])

    captured = supervisor._sandbox_execution_capture_result_candidate(
        attempt["id"], attempt["claim_token"]
    )
    candidate = captured["candidate"]
    change_set = captured["change_set"]
    assert candidate["version"] == 1
    assert candidate["authorization"] == "none"
    assert candidate["attempt_id"] == attempt["id"]
    assert candidate["claim_token"] == attempt["claim_token"]
    assert candidate["execution_id"] == row["execution_id"]
    assert candidate["workspace_binding"]["baseline"]["manifest_digest"] == (
        change_set.baseline_digest
    )
    assert candidate["workspace_binding"]["workspace"]["path"] == str(workspace)
    assert candidate["workspace_binding"]["workspace"]["device"] == row["workspace_root_dev"]
    assert candidate["workspace_binding"]["workspace"]["inode"] == row["workspace_root_ino"]
    assert candidate["result"]["tree_digest"] == change_set.result_digest
    assert candidate["result"]["change_digest"] == change_set.digest
    assert candidate["result"]["import_digest"]
    recorded = supervisor._sandbox_execution_get(attempt["id"])
    assert candidate["exit"] == {
        "code": 0,
        "observed_by": "runc_client_kernel_waitpid",
        "runc_client_pid": recorded["runc_client_pid"],
        "runc_client_identity": recorded["runc_client_identity"],
    }
    assert candidate["cleanup"]["status"] == "unverified"
    assert (
        captured["candidate_digest"]
        == hashlib.sha256(canonical_json(candidate).encode("utf-8")).hexdigest()
    )

    binding = supervisor._sandbox_execution_restore_workspace_binding(
        attempt["id"], attempt["claim_token"]
    )
    with supervisor.connect() as connection:
        supervisor._sandbox_execution_require_result_candidate_matches(
            connection,
            attempt["id"],
            baseline_digest=change_set.baseline_digest,
            import_digest=candidate["result"]["import_digest"],
            change_digest=change_set.digest,
        )
        with pytest.raises(SupervisorError) as mismatch:
            supervisor._sandbox_execution_require_result_candidate_matches(
                connection,
                attempt["id"],
                baseline_digest=change_set.baseline_digest,
                import_digest="0" * 64,
                change_digest=change_set.digest,
            )
    assert mismatch.value.code == "sandbox_result_evidence_mismatch"

    with pytest.raises(SupervisorError) as imported:
        supervisor.import_worker_result(
            attempt["id"], attempt["claim_token"], binding["baseline"], change_set
        )
    assert imported.value.code == "sandbox_result_import_route_required"
    with supervisor.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM result_imports").fetchone()[0] == 0
    reopened = GitSupervisor(repo)
    persisted = reopened._sandbox_execution_get(attempt["id"])
    assert persisted["result_candidate"] == candidate
    assert persisted["result_candidate_digest"] == captured["candidate_digest"]


def test_schema27_migration_moves_candidate_write_guard_to_verified_cleanup(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    record_launch(supervisor, attempt)
    record_running(supervisor, attempt)
    record_exit(supervisor, attempt)
    supervisor._sandbox_execution_record_cleanup_report(
        attempt["id"], attempt["claim_token"], cleanup_receipt(supervisor, attempt["id"])
    )

    with supervisor.connect() as connection:
        connection.execute("DROP TRIGGER sandbox_result_candidate_write_once")
        # Recreate the schema-26 predicate and version marker to exercise the
        # forward migration on a database containing an unverified row.
        connection.execute(
            """
            CREATE TRIGGER sandbox_result_candidate_write_once
            BEFORE UPDATE OF result_candidate_version, result_candidate_json,
              result_candidate_digest ON sandbox_executions
            WHEN OLD.result_candidate_version = 0
              AND NEW.result_candidate_version = 1
              AND OLD.phase = 'cleanup_reported'
            BEGIN
              SELECT RAISE(ABORT, 'sandbox_result_candidate_immutable');
            END
            """
        )
        connection.execute("UPDATE meta SET value = '26' WHERE key = 'schema_version'")
        connection.commit()

    upgraded = GitSupervisor(repo)
    assert upgraded.schema_version_on_open == 26
    with upgraded.connect() as connection:
        trigger = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' "
            "AND name = 'sandbox_result_candidate_write_once'"
        ).fetchone()
        assert trigger is not None
        assert "cleanup_verified" in trigger["sql"]
        assert "cleanup_reported" not in trigger["sql"]
        with pytest.raises(sqlite3.IntegrityError, match="sandbox_result_candidate_immutable"):
            connection.execute(
                "UPDATE sandbox_executions SET result_candidate_version = 1, "
                "result_candidate_json = ?, result_candidate_digest = ? WHERE attempt_id = ?",
                (
                    '{"authorization":"none","status":"unverified"}',
                    "0" * 64,
                    attempt["id"],
                ),
            )


def test_sandbox_import_route_fails_closed_before_cleanup_verification(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)
    record_launch(supervisor, attempt)
    record_running(supervisor, attempt)
    (Path(row["workspace_root_path"]) / "alpha.txt").write_text(
        "sandbox result\n", encoding="utf-8"
    )
    record_exit(supervisor, attempt)
    supervisor._sandbox_execution_record_cleanup_report(
        attempt["id"], attempt["claim_token"], cleanup_receipt(supervisor, attempt["id"])
    )

    with pytest.raises(SupervisorError) as rejected:
        supervisor.import_sandbox_execution_result(attempt["id"], attempt["claim_token"])

    assert rejected.value.code == "sandbox_result_unverified"
    assert supervisor._sandbox_execution_get(attempt["id"])["result_candidate_version"] == 0
    with supervisor.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM result_imports").fetchone()[0] == 0


def test_sandbox_import_rejects_stale_claim_before_candidate_capture(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET claim_token = claim_token + 1 WHERE id = ?",
            (attempt["id"],),
        )
        connection.commit()

    with pytest.raises(SupervisorError) as stale:
        supervisor.import_sandbox_execution_result(attempt["id"], attempt["claim_token"])

    assert stale.value.code == "stale_fencing_token"
    assert supervisor._sandbox_execution_get(attempt["id"])["result_candidate_version"] == 0
    with supervisor.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM result_imports").fetchone()[0] == 0


def test_sandbox_import_uses_distinct_source_and_recovers_published_ref(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)
    record_launch(supervisor, attempt)
    record_running(supervisor, attempt)
    (Path(row["workspace_root_path"]) / "alpha.txt").write_text(
        "sandbox result\n", encoding="utf-8"
    )
    record_exit(supervisor, attempt)
    supervisor._sandbox_execution_record_cleanup_report(
        attempt["id"], attempt["claim_token"], cleanup_receipt(supervisor, attempt["id"])
    )

    # Exercise downstream import only with a synthetic already-verified
    # journal state. The separate live launch-driver test exercises the
    # production cleanup verifier; this test is not live result-import evidence.
    synthesize_cleanup_verified_for_downstream_test(supervisor, attempt["id"])
    supervisor._sandbox_execution_capture_result_candidate(attempt["id"], attempt["claim_token"])
    with supervisor.connect() as connection:
        # Model a corrupt/legacy mixed-source journal with a different claim
        # token and result digest; healthy-schema guards normally prevent it.
        connection.execute("DROP TRIGGER result_import_direct_source_insert_guard")
        connection.execute(
            """
            INSERT INTO result_imports
              (id, attempt_id, claim_token, source_kind, worker_pid, worker_identity,
               worker_exit_receipt_json, base_sha, tree_sha, baseline_digest,
               result_digest, change_digest, result_ref, commit_timestamp,
               commit_sha, phase, created_at, updated_at)
            VALUES ('corrupt-direct-import', ?, ?, 'direct_worker', 202,
                    'synthetic-pid-identity', '{}', 'base', 'tree', 'baseline',
                    ?, 'changes', 'refs/acp/corrupt-direct', 0, 'commit',
                    'prepared', 'now', 'now')
            """,
            (attempt["id"], attempt["claim_token"] + 1, "f" * 64),
        )
        connection.commit()

    with pytest.raises(SupervisorError) as mixed_source:
        supervisor.import_sandbox_execution_result(attempt["id"], attempt["claim_token"])
    assert mixed_source.value.code == "sandbox_result_source_mismatch"
    with supervisor.connect() as connection:
        connection.execute("DELETE FROM result_imports WHERE id = 'corrupt-direct-import'")

    def interrupt_before_submit(*args, **kwargs):
        raise RuntimeError("simulated crash after result ref publication")

    monkeypatch.setattr(supervisor, "_submit", interrupt_before_submit)
    with pytest.raises(RuntimeError, match="simulated crash"):
        supervisor.import_sandbox_execution_result(attempt["id"], attempt["claim_token"])

    with supervisor.connect() as connection:
        imported = connection.execute(
            "SELECT * FROM result_imports WHERE attempt_id = ?", (attempt["id"],)
        ).fetchone()
        assert imported["phase"] == "ref_published"
        assert imported["source_kind"] == "sandbox_execution"
        assert imported["worker_pid"] is None
        assert imported["worker_identity"] == ""
        assert imported["worker_exit_receipt_json"] == ""
        assert imported["sandbox_execution_id"] == row["execution_id"]
        assert len(imported["sandbox_cleanup_receipt_digest"]) == 64

    reopened = GitSupervisor(repo)
    configure_test_sandbox_pins(reopened)
    expected_cleanup_digest = imported["sandbox_cleanup_receipt_digest"]
    with reopened.connect() as connection:
        connection.execute("DROP TRIGGER result_import_source_identity_immutable")
        connection.execute(
            "UPDATE result_imports SET sandbox_cleanup_receipt_digest = ? WHERE id = ?",
            ("a" * 64, imported["id"]),
        )
        connection.commit()
    with pytest.raises(SupervisorError) as digest_conflict:
        reopened.recover_worker_result_import(imported["id"])
    assert digest_conflict.value.code == "sandbox_result_source_mismatch"
    with reopened.connect() as connection:
        persisted = connection.execute(
            "SELECT phase FROM result_imports WHERE id = ?", (imported["id"],)
        ).fetchone()
        assert persisted["phase"] == "ref_published"
        connection.execute(
            "UPDATE result_imports SET sandbox_cleanup_receipt_digest = ? WHERE id = ?",
            (expected_cleanup_digest, imported["id"]),
        )
        connection.commit()

    with reopened.connect() as connection:
        connection.execute(
            """
            INSERT INTO result_imports
              (id, attempt_id, claim_token, source_kind, worker_pid, worker_identity,
               worker_exit_receipt_json, base_sha, tree_sha, baseline_digest,
               result_digest, change_digest, result_ref, commit_timestamp,
               commit_sha, phase, created_at, updated_at)
            VALUES ('corrupt-direct-recovery', ?, ?, 'direct_worker', 203,
                    'other-pid-identity', '{}', 'base', 'tree', 'baseline',
                    ?, 'changes', 'refs/acp/corrupt-recovery', 0, 'commit',
                    'prepared', 'now', 'now')
            """,
            (attempt["id"], attempt["claim_token"] + 1, "e" * 64),
        )
        connection.commit()
    with pytest.raises(SupervisorError) as recovery_conflict:
        reopened.recover_worker_result_import(imported["id"])
    assert recovery_conflict.value.code == "sandbox_result_source_mismatch"
    with pytest.raises(SupervisorError) as submit_conflict:
        reopened._submit(
            attempt["id"],
            attempt["claim_token"],
            expected_worker_pid=None,
            credential=None,
            imported_result_id=imported["id"],
        )
    assert submit_conflict.value.code == "sandbox_result_source_mismatch"
    with reopened.connect() as connection:
        connection.execute("DELETE FROM result_imports WHERE id = 'corrupt-direct-recovery'")

    submission = reopened.recover_worker_result_import(imported["id"])
    repeated = reopened.import_sandbox_execution_result(attempt["id"], attempt["claim_token"])
    assert repeated["id"] == submission["id"]
    with reopened.connect() as connection:
        persisted = connection.execute(
            "SELECT phase, submission_id, source_kind FROM result_imports WHERE id = ?",
            (imported["id"],),
        ).fetchone()
        assert persisted["phase"] == "submitted"
        assert persisted["submission_id"] == submission["id"]
        assert persisted["source_kind"] == "sandbox_execution"
    assert reopened.verify_event_chain()["ok"] is True


def test_result_candidate_is_idempotent_but_cannot_be_replaced(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)
    workspace = Path(row["workspace_root_path"])
    record_launch(supervisor, attempt)
    record_running(supervisor, attempt)
    (workspace / "alpha.txt").write_text("candidate v1\n", encoding="utf-8")
    record_exit(supervisor, attempt)
    supervisor._sandbox_execution_record_cleanup_report(
        attempt["id"], attempt["claim_token"], cleanup_receipt(supervisor, attempt["id"])
    )

    synthesize_cleanup_verified_for_downstream_test(supervisor, attempt["id"])

    first = supervisor._sandbox_execution_capture_result_candidate(
        attempt["id"], attempt["claim_token"]
    )
    replay = supervisor._sandbox_execution_capture_result_candidate(
        attempt["id"], attempt["claim_token"]
    )
    assert replay["candidate"] == first["candidate"]
    assert replay["candidate_digest"] == first["candidate_digest"]

    (workspace / "alpha.txt").write_text("candidate v2\n", encoding="utf-8")
    with pytest.raises(SupervisorError) as conflict:
        supervisor._sandbox_execution_capture_result_candidate(
            attempt["id"], attempt["claim_token"]
        )
    assert conflict.value.code == "sandbox_result_evidence_conflict"
    persisted = supervisor._sandbox_execution_get(attempt["id"])
    assert persisted["result_candidate"] == first["candidate"]
    assert persisted["result_candidate_digest"] == first["candidate_digest"]


@pytest.mark.parametrize("legacy_version", [1, 2])
def test_persisted_pre_schema17_cleanup_receipt_replays_but_never_proves_cleanup(
    repo: Path, tmp_path: Path, legacy_version: int
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    record_launch(supervisor, attempt)
    record_running(supervisor, attempt)
    record_exit(supervisor, attempt)

    legacy_receipt = cleanup_receipt(supervisor, attempt["id"])
    legacy_receipt.pop("rootfs_closure_digest")
    legacy_receipt.pop("runc_executable_digest")
    if legacy_version == 1:
        legacy_receipt["version"] = 1
        legacy_receipt.pop("verification_status")
        legacy_receipt["observations"] = {
            "runc_delete_exit_code": 0,
            "runc_state_absent": True,
            "bundle_absent": True,
            "state_directory_absent": True,
            "wrapper_unit_absent": True,
            "scope_unit_absent": True,
            "cgroup_absent": True,
            "monitor_identity_absent": True,
            "runc_client_identity_absent": True,
            "container_init_identity_absent": True,
        }
    encoded = canonical_json(legacy_receipt)
    supervisor._sandbox_execution_transition(
        attempt["id"],
        attempt["claim_token"],
        expected_phase="exited",
        next_phase="cleanup_reported",
        updates={"cleanup_receipt_json": encoded},
        event_type="sandbox.execution_cleanup_reported",
        event_payload={"receipt_sha256": hashlib.sha256(encoded.encode()).hexdigest()},
    )

    # Recreate the pre-17 table shape, then exercise the real version-16 upgrade
    # with a cleanup_reported row already carrying its historical receipt.
    with supervisor.connect() as connection:
        for trigger in (
            "sandbox_execution_insert_reserved",
            "sandbox_execution_identity_immutable",
            "sandbox_execution_launch_requires_content_pins",
        ):
            connection.execute(f"DROP TRIGGER {trigger}")
        connection.execute("ALTER TABLE sandbox_executions DROP COLUMN runc_executable_digest")
        connection.execute("ALTER TABLE sandbox_executions DROP COLUMN rootfs_closure_digest")
        connection.execute("UPDATE meta SET value = '16' WHERE key = 'schema_version'")
    supervisor = GitSupervisor(repo)
    assert supervisor.schema_version_on_open == 16
    migrated = supervisor._sandbox_execution_get(attempt["id"])
    assert migrated["rootfs_closure_digest"] == ""
    assert migrated["runc_executable_digest"] == ""

    replayed = supervisor._sandbox_execution_record_cleanup_report(
        attempt["id"], attempt["claim_token"], legacy_receipt
    )
    assert replayed["phase"] == "cleanup_reported"
    assert replayed["cleanup_receipt"]["version"] == legacy_version

    workspace = Path(supervisor._sandbox_execution_get(attempt["id"])["workspace_root_path"])
    (workspace / "alpha.txt").write_text("legacy cleanup receipt candidate\n", encoding="utf-8")
    with pytest.raises(SupervisorError) as unverified_candidate:
        supervisor._sandbox_execution_capture_result_candidate(
            attempt["id"], attempt["claim_token"]
        )
    assert unverified_candidate.value.code == "sandbox_result_evidence_unverified"
    assert supervisor._sandbox_execution_get(attempt["id"])["result_candidate_version"] == 0

    current_receipt = cleanup_receipt(supervisor, attempt["id"])
    with pytest.raises(SupervisorError) as replace_legacy:
        supervisor._sandbox_execution_record_cleanup_report(
            attempt["id"], attempt["claim_token"], current_receipt
        )
    assert replace_legacy.value.code == "sandbox_execution_transition_conflict"

    baseline, change_set = result_fixture(attempt, tmp_path)
    with pytest.raises(SupervisorError) as import_unverified:
        supervisor.import_worker_result(attempt["id"], attempt["claim_token"], baseline, change_set)
    assert import_unverified.value.code == "sandbox_result_unverified"


def test_ambiguous_execution_is_durably_quarantined(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)

    row = supervisor._sandbox_execution_mark_ambiguous(
        attempt["id"], attempt["claim_token"], "runc state readback disagreed"
    )
    assert row["phase"] == "ambiguous"
    assert supervisor.attempt(attempt["id"])["termination_target_status"] == "quarantined"
    assert supervisor.task(attempt["task_id"])["status"] == "cleanup_pending"
    result = supervisor.reap_expired(now=attempt["lease_expires_at"] + 1)
    assert result["terminated_workers"] == []
    assert result["runtime_cleanup"] == []
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "ambiguous"
