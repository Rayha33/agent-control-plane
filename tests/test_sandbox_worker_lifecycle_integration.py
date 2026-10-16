"""Opt-in Linux/systemd proofs for OCI launch-driver and monitor components.

The process-local runc handle must remain in the exact systemd launch-driver
process; a separate systemd-owned service controls the exact worker scope. The
default branch proves launch-to-``running``, natural completion, and
reaper-driven cleanup verification/runtime release. Opt-in branches also cover
fresh-supervisor cancellation and launch-driver timeout. The production
producer runs in a short-lived process that exits abruptly after durable
handoff; fresh supervisor processes cancel (when requested) and reap the exact
execution. An additional opt-in natural-completion branch asks the independent
cleanup verifier to prove teardown, then imports the host-captured workspace
result into the normal pending-QC submission path. None of these branches
wires ``run_worker`` or starts a provider/model worker.

The legacy direct-monitor lifecycle fixture is intentionally skipped: it starts
runc from a monitor-owned service and cannot satisfy the current launch-driver
redemption contract. The production launch-driver test remains opt-in. Its
default branch verifies natural completion; setting
`ACP_LIVE_CANCEL_AFTER_START=1` runs the same fixture with a long payload and
verifies cancellation from a fresh supervisor. Setting
`ACP_LIVE_TIMEOUT_AFTER_START=1` uses a one-second driver timeout with a long
payload and verifies automatic stop-intent recording, monitor cancellation,
and cleanup verification. Setting
`ACP_LIVE_CRASH_AFTER_MANAGER_ACCEPTANCE=1` exits the producer after successful
`systemd-run` return but before receipt propagation, then verifies a fresh
producer cannot replay the launch. Crash modes are mutually exclusive with
cancellation, timeout, and one another. Run on a disposable supported Linux host
with rootless runc 1.5.2,
delegated cgroup v2, and an active private systemd user manager:

    ACP_RUN_SANDBOX_WORKER_LIFECYCLE=1 \
    ACP_OCI_TEST_RUNC=/usr/bin/runc \
    ACP_OCI_TEST_RUNC_VERSION=1.5.2 \
    uv run --extra dev pytest -q tests/test_sandbox_worker_lifecycle_integration.py

For the fresh-supervisor cancellation branch, add:

    ACP_LIVE_CANCEL_AFTER_START=1

For the launch-driver timeout branch, add:

    ACP_LIVE_TIMEOUT_AFTER_START=1

For the manager-accepted/pre-receipt crash branch, add:

    ACP_LIVE_CRASH_AFTER_MANAGER_ACCEPTANCE=1

For the live crash after the recovery monitor is accepted but before the
launch-driver records that receipt, add:

    ACP_LIVE_CRASH_AFTER_MONITOR_ACCEPTANCE=1

For a driver crash after the gated runc scope exists but before monitor
activation is requested, add:

    ACP_LIVE_CRASH_BEFORE_MONITOR_START=1

For natural completion followed by production cleanup verification and
host-side sandbox-result import (mutually exclusive with cancellation, timeout,
and crash modes), add:

    ACP_LIVE_IMPORT_RESULT_AFTER_CLEANUP=1
"""

from __future__ import annotations

import json
import multiprocessing
import os
import posixpath
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path, PurePosixPath
from typing import Any
from unittest.mock import patch

import pytest
from support import init_repo, make_task
from test_oci_worker_runtime import (
    _CONTAINER_CPU_PERIOD_US,
    _CONTAINER_CPU_QUOTA_US,
    _CONTAINER_MEMORY_BYTES,
    _CONTAINER_PIDS_LIMIT,
    _copy_busybox_closure,
)

import agent_control_plane.supervisor.oci_worker as oci_worker
from agent_control_plane.git_supervisor import GitSupervisor
from agent_control_plane.supervisor import (
    sandbox_attestation,
    sandbox_launch_driver_service,
    sandbox_monitor_ipc,
    sandbox_monitor_lifecycle,
    sandbox_monitor_service,
)
from agent_control_plane.supervisor import (
    sandbox_execution_journal as journal_module,
)
from agent_control_plane.supervisor.common import SupervisorError
from agent_control_plane.supervisor.sandbox_attestation import collect_running_runtime_attestation
from agent_control_plane.supervisor.sandbox_monitor_ipc import _linux_process_identity
from agent_control_plane.supervisor.sandbox_monitor_receipt import (
    sandbox_attempt_slice_unit,
    sandbox_monitor_service_unit,
)
from agent_control_plane.supervisor.sandbox_workspace import collect_changes, copy_snapshot

_LIVE_ENABLED = os.environ.get("ACP_RUN_SANDBOX_WORKER_LIFECYCLE") == "1"
_SUPPORTED_RUNC_VERSION = "1.5.2"
_MONITOR_SLICE_UNIT = "user-acp.slice"
_PAYLOAD_MARKER = "lifecycle-gate-marker"
_GIT_METADATA_MARKER = "git-metadata-absent-marker"


def _terminate_worker_from_fresh_process(
    repo: Path, attempt_id: str, credential: str, result_sender
) -> None:
    """Cancel through a genuinely fresh supervisor with no launch-handle registry."""

    from agent_control_plane.supervisor import sandbox_monitor_lifecycle

    supervisor = GitSupervisor(repo)
    reconnect_calls = 0
    legacy_pid_calls = 0
    original_reconnect = sandbox_monitor_lifecycle.reconnect_sandbox_monitor

    def record_reconnect(**kwargs: Any):
        nonlocal reconnect_calls
        reconnect_calls += 1
        return original_reconnect(**kwargs)

    def reject_legacy_pid(*_args: Any, **_kwargs: Any):
        nonlocal legacy_pid_calls
        legacy_pid_calls += 1
        raise AssertionError("fresh sandbox cancellation used the legacy PID path")

    sandbox_monitor_lifecycle.reconnect_sandbox_monitor = record_reconnect
    supervisor._open_registered_pidfd = reject_legacy_pid
    try:
        termination = supervisor.terminate_worker(attempt_id, credential=credential)
        result_sender.send(("ok", os.getpid(), termination, reconnect_calls, legacy_pid_calls))
    except SupervisorError as error:
        result_sender.send(("supervisor-error", error.code, reconnect_calls, legacy_pid_calls))
    except BaseException as error:
        result_sender.send(("error", type(error).__name__, reconnect_calls, legacy_pid_calls))
    finally:
        sandbox_monitor_lifecycle.reconnect_sandbox_monitor = original_reconnect
        result_sender.close()


def _start_launch_driver_then_crash_controller(
    repo: Path,
    expected_identity: tuple[str, int, str],
    command: tuple[str, ...],
    memory_max_bytes: int,
    cpu_quota: int,
    cpu_period: int,
    pids_max: int,
    timeout_seconds: int,
    credential: str,
    service_log_path: Path,
    result_sender,
    crash_after_manager_acceptance: bool = False,
    monitor_acceptance_crash_marker: Path | None = None,
    crash_before_monitor_start: bool = False,
) -> None:
    """Exit the launch-driver service at the selected monitor-handoff crash point."""

    original_runner = sandbox_launch_driver_service._run_trusted_runtime_command

    def capture_driver_service_output(argv: list[str], *, environment: dict[str, str]) -> bytes:
        if Path(argv[0]).name == "systemd-run":
            argv = list(argv)
            insertion = argv.index("--working-directory")
            argv[insertion:insertion] = [
                f"--property=StandardOutput=append:{service_log_path}",
                f"--property=StandardError=append:{service_log_path}",
            ]
            if monitor_acceptance_crash_marker is not None:
                module_flag = argv.index("-m")
                python = argv[module_flag - 1]
                module_name = argv[module_flag + 1]
                if module_name != "agent_control_plane.supervisor.sandbox_launch_driver_service":
                    raise AssertionError("production launch-driver command changed unexpectedly")
                driver_args = argv[module_flag + 2 :]
                wrapper = """
import json
import os
import sys
from pathlib import Path

from agent_control_plane.git_supervisor import GitSupervisor
from agent_control_plane.supervisor import oci_worker, sandbox_launch_driver_service
from agent_control_plane.supervisor import sandbox_monitor_ipc, sandbox_monitor_service

marker = Path(sys.argv[1])
crash_phase = sys.argv[2]
driver_args = sys.argv[3:]
captured = {}
original_record_launch = GitSupervisor._sandbox_execution_record_launch

def capture_launch_handle(self, *args, **kwargs):
    handle = kwargs["runc_handle"]
    captured["runc_client_pid"] = oci_worker._runc_launch_pid(handle)
    captured["runc_client_identity"] = oci_worker._runc_launch_process_identity(handle)
    return original_record_launch(self, *args, **kwargs)

GitSupervisor._sandbox_execution_record_launch = capture_launch_handle
original_monitor_start = sandbox_monitor_service.start_sandbox_execution_monitor

def write_crash_marker(kwargs, receipt):
    identity = kwargs["expected_identity"]
    attempt_slice = sandbox_launch_driver_service.sandbox_attempt_slice_unit(*identity)
    driver_unit = f"acp-launch-driver-{identity[2]}.service"
    monitor_unit = sandbox_launch_driver_service.sandbox_monitor_service_unit(*identity)
    properties = sandbox_launch_driver_service._unit_properties(
        driver_unit,
        ("ActiveState", "ControlGroup", "Id", "InvocationID", "MainPID", "Slice"),
    )
    monitor_value = None
    if receipt is not None:
        monitor_value = {
            "unit": receipt.unit,
            "invocation_id": receipt.invocation_id,
            "pid": receipt.main_pid,
            "identity": receipt.main_identity,
            "control_group": receipt.control_group,
            "attempt_id": receipt.attempt_id,
            "claim_token": receipt.claim_token,
            "execution_id": receipt.execution_id,
        }
    value = {
        "crash_phase": crash_phase,
        "identity": list(identity),
        "driver": {
            "unit": driver_unit,
            "pid": os.getpid(),
            "identity": sandbox_monitor_ipc._linux_process_identity(os.getpid()),
            "active_state": properties["ActiveState"],
            "invocation_id": properties["InvocationID"],
            "control_group": properties["ControlGroup"],
            "slice": properties["Slice"],
            "main_pid": int(properties["MainPID"]),
        },
        "monitor_unit": monitor_unit,
        "monitor": monitor_value,
        "attempt_slice": attempt_slice,
        "attempt_slice_control_group": kwargs["attempt_slice_control_group"],
        "scope": {
            "unit": kwargs["scope_unit"],
            "invocation_id": kwargs["scope_invocation_id"],
            "control_group": kwargs["scope_control_group"],
        },
        "runc_client_pid": captured["runc_client_pid"],
        "runc_client_identity": captured["runc_client_identity"],
    }
    marker.write_text(json.dumps(value, sort_keys=True), encoding="ascii")
    os._exit(74)

def crash_at_monitor_start(*args, **kwargs):
    if crash_phase == "before_monitor_start":
        write_crash_marker(kwargs, None)
    client = original_monitor_start(*args, **kwargs)
    if crash_phase != "after_monitor_acceptance":
        raise AssertionError("unknown live monitor crash phase")
    write_crash_marker(kwargs, client._receipt)

sandbox_monitor_service.start_sandbox_execution_monitor = crash_at_monitor_start
raise SystemExit(sandbox_launch_driver_service.main(driver_args))
"""
                argv[module_flag - 1 :] = [
                    python,
                    "-c",
                    wrapper,
                    str(monitor_acceptance_crash_marker),
                    "before_monitor_start"
                    if crash_before_monitor_start
                    else "after_monitor_acceptance",
                    *driver_args,
                ]
        result = original_runner(argv, environment=environment)
        if crash_after_manager_acceptance and Path(argv[0]).name == "systemd-run":
            # Type=exec returns only after systemd accepts the unit and crosses
            # ExecStart. Lose the producer before it can observe or persist the
            # service receipt; the durable intent must prevent a duplicate start.
            result_sender.send(("manager_accepted", os.getpid()))
            result_sender.close()
            os._exit(74)
        return result

    exit_code = 73
    try:
        with patch.object(
            sandbox_launch_driver_service,
            "_run_trusted_runtime_command",
            capture_driver_service_output,
        ):
            receipt = sandbox_launch_driver_service.start_sandbox_launch_driver(
                GitSupervisor(repo),
                expected_identity=expected_identity,
                command=command,
                memory_max_bytes=memory_max_bytes,
                cpu_quota=cpu_quota,
                cpu_period=cpu_period,
                pids_max=pids_max,
                timeout_seconds=timeout_seconds,
                credential=credential,
            )
        result_sender.send(
            (
                "ok",
                os.getpid(),
                {
                    "attempt_id": receipt.attempt_id,
                    "claim_token": receipt.claim_token,
                    "execution_id": receipt.execution_id,
                    "service_unit": receipt.service_unit,
                    "invocation_id": receipt.invocation_id,
                    "driver_pid": receipt.driver_pid,
                    "driver_identity": receipt.driver_identity,
                    "control_group": receipt.control_group,
                },
            )
        )
    except BaseException as error:
        exit_code = 1
        result_sender.send(("error", type(error).__name__))
    finally:
        result_sender.close()
    # Abruptly lose the producer after the one-shot handoff. The independent
    # user manager retains the launch-driver service and its process-local handle.
    os._exit(exit_code)


def _retry_launch_driver_without_replay_from_fresh_process(
    repo: Path,
    expected_identity: tuple[str, int, str],
    command: tuple[str, ...],
    memory_max_bytes: int,
    cpu_quota: int,
    cpu_period: int,
    pids_max: int,
    timeout_seconds: int,
    credential: str,
    result_sender,
) -> None:
    """Prove a fresh producer cannot submit a second systemd start."""

    original_runner = sandbox_launch_driver_service._run_trusted_runtime_command
    start_submissions: list[tuple[str, ...]] = []

    def refuse_second_start(argv: list[str], *, environment: dict[str, str]) -> bytes:
        if Path(argv[0]).name == "systemd-run":
            start_submissions.append(tuple(argv))
            raise RuntimeError("duplicate launch-driver activation blocked by test")
        return original_runner(argv, environment=environment)

    try:
        with patch.object(
            sandbox_launch_driver_service,
            "_run_trusted_runtime_command",
            refuse_second_start,
        ):
            sandbox_launch_driver_service.start_sandbox_launch_driver(
                GitSupervisor(repo),
                expected_identity=expected_identity,
                command=command,
                memory_max_bytes=memory_max_bytes,
                cpu_quota=cpu_quota,
                cpu_period=cpu_period,
                pids_max=pids_max,
                timeout_seconds=timeout_seconds,
                credential=credential,
            )
        result_sender.send(("accepted", os.getpid(), len(start_submissions)))
    except sandbox_launch_driver_service.SandboxLaunchDriverServiceError as error:
        result_sender.send(("rejected", os.getpid(), type(error).__name__, len(start_submissions)))
    except BaseException as error:
        result_sender.send(("error", os.getpid(), type(error).__name__, len(start_submissions)))
    finally:
        result_sender.close()


def _reap_expired_from_fresh_process(
    repo: Path,
    now: int,
    result_sender,
    import_probe: tuple[str, str, str] | None = None,
) -> None:
    """Run the real reaper in a new supervisor process after producer loss."""

    try:
        supervisor = GitSupervisor(repo)

        def imported_state_snapshot() -> dict[str, Any]:
            if import_probe is None:
                return {}
            task_id, attempt_id, submission_id = import_probe
            task = supervisor.task(task_id)
            attempt = supervisor.attempt(attempt_id)
            submission = supervisor.submission(submission_id)
            execution = supervisor._sandbox_execution_get(attempt_id)
            if execution is None:
                raise AssertionError("fresh supervisor could not recover the imported execution")
            return {
                "task_status": task["status"],
                "attempt_status": attempt["status"],
                "submission_id": submission["id"],
                "submission_status": submission["status"],
                "submission_commit_sha": submission["commit_sha"],
                "task_latest_submission_id": task["latest_submission"]["id"],
                "execution_id": execution["execution_id"],
                "execution_phase": execution["phase"],
            }

        before = imported_state_snapshot()
        reaped = supervisor.reap_expired(now=now)
        after = imported_state_snapshot()
        result_sender.send(("ok", os.getpid(), reaped, before, after))
    except BaseException as error:
        result_sender.send(("error", type(error).__name__))
    finally:
        result_sender.close()


def _reconcile_monitor_accepted_driver_crash_from_fresh_process(
    repo: Path,
    attempt_id: str,
    claim_token: int,
    execution_id: str,
    credential: str,
    result_sender,
) -> None:
    """Contain the exact interrupted handoff using a fresh supervisor process."""

    try:
        supervisor = GitSupervisor(repo)
        execution = supervisor._sandbox_execution_get(attempt_id)
        if execution is None:
            raise RuntimeError("execution disappeared before fresh-process reconciliation")
        intent = journal_module._SandboxLaunchDriverStartIntent(
            attempt_id=attempt_id,
            claim_token=claim_token,
            execution_id=execution_id,
            start_id=execution["launch_driver_start_id"],
            start_digest=execution["launch_driver_start_digest"],
            service_unit=execution["launch_driver_start_unit"],
        )
        result = sandbox_launch_driver_service._stop_and_reconcile_exact_start(
            supervisor,
            execution=execution,
            intent=intent,
            attempt_slice=sandbox_attempt_slice_unit(attempt_id, claim_token, execution_id),
            reason="live test: launch driver crashed after recovery-monitor acceptance",
            credential=credential,
        )
        result_sender.send(("ok", os.getpid(), result))
    except BaseException as error:
        result_sender.send(("error", os.getpid(), type(error).__name__, str(error)))
    finally:
        result_sender.close()


def _write_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _entry_is_present(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _persisted_write_set_rules(
    supervisor: GitSupervisor, attempt_id: str
) -> list[tuple[str, bool, bool]]:
    with supervisor.connect() as connection:
        attempt = connection.execute(
            "SELECT task_id FROM attempts WHERE id = ?", (attempt_id,)
        ).fetchone()
        if attempt is None:
            raise RuntimeError("test attempt disappeared before output collection")
        task = supervisor._task_row(connection, attempt["task_id"])
        return supervisor._write_set_rules(task, supervisor._case_sensitive_paths(connection))


def _unit_properties(unit: str, properties: tuple[str, ...]) -> dict[str, str]:
    raw = sandbox_attestation._run_trusted_runtime_command(
        [
            str(sandbox_attestation._trusted_systemctl_executable()),
            "--user",
            "show",
            "--no-pager",
            f"--property={','.join(properties)}",
            "--",
            unit,
        ],
        environment=sandbox_attestation._trusted_systemd_command_environment(),
    )
    values: dict[str, str] = {}
    for line in raw.decode("ascii").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise RuntimeError(f"malformed systemd properties for {unit}")
        values[key] = value
    if set(values) != set(properties):
        raise RuntimeError(f"incomplete systemd properties for {unit}: {values!r}")
    return values


def _assert_units_available_for_test(*units: str) -> None:
    for unit in units:
        props = _unit_properties(unit, ("ActiveState", "ControlGroup", "FragmentPath", "LoadState"))
        if props["LoadState"] == "not-found":
            continue
        # systemd keeps implicit, inactive slices loaded after they are stopped.
        # Reusing one is safe only while it has no backing unit file or cgroup.
        if (
            unit.endswith(".slice")
            and props["LoadState"] == "loaded"
            and props["ActiveState"] == "inactive"
            and not props["ControlGroup"]
            and not props["FragmentPath"]
        ):
            continue
        pytest.fail(f"refusing to use pre-existing systemd unit {unit}")


def _wait_for_path(path: Path, error_path: Path, timeout: float = 45.0) -> Path:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            return path
        if error_path.is_file():
            error = json.loads(error_path.read_text(encoding="utf-8"))
            raise AssertionError(
                f"monitor child failed:\n{error.get('traceback', 'unknown error')}"
            )
        time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for monitor receipt {path.name}")


def _wait_for_receipt(control: Path, name: str, timeout: float = 45.0) -> Path:
    return _wait_for_path(control / name, control / "error.json", timeout)


def _apparmor_identity() -> str | None:
    try:
        return Path("/proc/self/attr/current").read_text(encoding="ascii").strip()
    except OSError:
        return None


def _cgroup_is_empty(control_group: str) -> bool:
    if (
        not isinstance(control_group, str)
        or not control_group.startswith("/")
        or posixpath.normpath(control_group) != control_group
        or any(part in {".", ".."} for part in PurePosixPath(control_group).parts)
    ):
        return False
    root = Path("/sys/fs/cgroup").resolve()
    path = root.joinpath(*PurePosixPath(control_group).parts[1:])
    if not path.exists():
        return True
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root):
            return False
        events = (resolved / "cgroup.events").read_text(encoding="ascii").splitlines()
    except OSError:
        return False
    return "populated 0" in events


def _monitor_child(
    repo: Path,
    rootfs_source: Path,
    source_worktree: Path,
    attempt_id: str,
    claim_token: int,
    execution_id: str,
    control: Path,
    terminate_before_gate: bool,
) -> None:
    """Perform process-local launch work in the driver and verify its monitor service."""

    handle: oci_worker.RuncLaunchHandle | None = None
    try:
        supervisor = GitSupervisor(repo)
        execution = supervisor._sandbox_execution_get(attempt_id)
        if (
            execution is None
            or execution["claim_token"] != claim_token
            or execution["execution_id"] != execution_id
            or execution["phase"] != "reserved"
        ):
            raise RuntimeError("child did not reopen the exact reserved execution")
        rootfs_pin = supervisor.config.oci_rootfs_pin
        runc_pin = supervisor.config.oci_runc_executable
        if rootfs_pin is None or runc_pin is None:
            raise RuntimeError("child configuration did not recreate trusted OCI pins")

        execution_root = Path(execution["bundle_path"]).parent
        bundle_root = Path(execution["bundle_path"])
        state_root = Path(execution["state_path"])
        baseline_root = execution_root / "baseline"
        workspace_root = execution_root / "workspace"
        for path in (execution_root, bundle_root, state_root):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            info = path.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise RuntimeError(f"reserved execution directory is not private: {path.name}")
        rootfs = bundle_root / "rootfs"
        if rootfs.exists():
            raise RuntimeError("reserved bundle rootfs already exists")
        shutil.copytree(rootfs_source, rootfs, symlinks=True)
        source_git_pointer = source_worktree / ".git"
        try:
            source_git_pointer_mode = source_git_pointer.lstat().st_mode
        except FileNotFoundError:
            raise RuntimeError(
                "attempt worktree is missing its expected .git pointer fixture"
            ) from None
        if not stat.S_ISREG(source_git_pointer_mode):
            raise RuntimeError("attempt worktree .git pointer fixture is not a regular file")
        git_pointer_text = source_git_pointer.read_text(encoding="utf-8").strip()
        pointer_key, separator, git_directory_value = git_pointer_text.partition(": ")
        if pointer_key != "gitdir" or not separator or not git_directory_value:
            raise RuntimeError("attempt worktree .git pointer is malformed")
        git_directory = Path(git_directory_value)
        if not git_directory.is_absolute():
            git_directory = source_worktree / git_directory
        git_directory = git_directory.resolve(strict=True)
        trusted_git_root = (repo / ".git").resolve(strict=True)
        if not git_directory.is_relative_to(trusted_git_root) or not git_directory.is_dir():
            raise RuntimeError("attempt worktree .git pointer escaped the private test repository")
        baseline = copy_snapshot(source_worktree, baseline_root)
        workspace = copy_snapshot(baseline.root, workspace_root)
        if _entry_is_present(baseline.root / ".git") or _entry_is_present(workspace.root / ".git"):
            raise RuntimeError("host Git pointer metadata entered a private worker snapshot")
        execution = supervisor._sandbox_execution_bind_workspace(
            attempt_id, claim_token, baseline, workspace
        )
        container_id = execution["container_id"]
        launch_driver_unit = f"acp-launch-driver-{execution_id}.service"
        launch_driver = _unit_properties(
            launch_driver_unit,
            ("ActiveState", "ControlGroup", "Id", "InvocationID", "MainPID", "Slice"),
        )
        if (
            launch_driver["Id"] != launch_driver_unit
            or launch_driver["ActiveState"] != "active"
            or int(launch_driver["MainPID"]) != os.getpid()
            or not launch_driver["InvocationID"]
            or not launch_driver["ControlGroup"]
        ):
            raise RuntimeError("child is not the exact live systemd launch-driver MainPID")

        attempt_slice_unit = oci_worker._oci_worker_systemd_slice(container_id)
        scope_unit = f"acp-{container_id}.scope"
        pid_file = state_root / "init.pid"
        marker = workspace_root / _PAYLOAD_MARKER
        git_marker = workspace_root / _GIT_METADATA_MARKER
        config = oci_worker.build_oci_worker_config(
            bundle_root,
            workspace,
            (
                "/bin/sh",
                "-c",
                "set -eu; "
                "test ! -e /workspace/.git; "
                "test ! -L /workspace/.git; "
                "test ! -e /workspace/.git/HEAD; "
                f"printf 'host-git-metadata-not-visible\\n' > /workspace/{_GIT_METADATA_MARKER}; "
                f"printf 'candidate-payload-ran\\n' > /workspace/{_PAYLOAD_MARKER}; "
                "/bin/busybox sleep 3",
            ),
            rootfs_pin=rootfs_pin,
            container_id=container_id,
            memory_bytes=_CONTAINER_MEMORY_BYTES,
            pids_limit=_CONTAINER_PIDS_LIMIT,
            cpu_quota_us=_CONTAINER_CPU_QUOTA_US,
            cpu_period_us=_CONTAINER_CPU_PERIOD_US,
        )
        binding = oci_worker._apply_pinned_runc_recursive_private_policy(
            config, runc_pin, expected_version=_SUPPORTED_RUNC_VERSION
        )
        submission: Any | None = None

        def authorize(target: oci_worker._RuncLaunchTarget) -> Any:
            nonlocal submission
            submission = supervisor._sandbox_execution_authorize_launch_submission(
                attempt_id, claim_token, launch_target=target
            )
            return submission

        handle = oci_worker.spawn_pinned_runc(
            binding,
            state_root,
            bundle_root,
            workspace_root,
            pid_file,
            container_id,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            _authorize_runc_submission=authorize,
        )
        client_pid = oci_worker._runc_launch_pid(handle)
        client_identity = oci_worker._runc_launch_process_identity(handle)
        process = oci_worker._runc_launch_process_for_testing(handle)
        if submission is None or client_pid is None or client_identity is None or process is None:
            raise RuntimeError("pinned runc did not retain the exact launch capability")
        deadline = time.monotonic() + 15.0
        while not pid_file.exists() and time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("pinned runc exited before reaching the held init gate")
            time.sleep(0.05)
        if not pid_file.is_file():
            raise TimeoutError("pinned runc did not create its private init PID file")

        attempt_slice = _unit_properties(
            attempt_slice_unit, ("ActiveState", "ControlGroup", "Id", "InvocationID")
        )
        scope = _unit_properties(scope_unit, ("ActiveState", "ControlGroup", "Id", "InvocationID"))
        for unit, props in ((attempt_slice_unit, attempt_slice), (scope_unit, scope)):
            if (
                props["ActiveState"] != "active"
                or props["Id"] != unit
                or not props["InvocationID"]
                or not props["ControlGroup"]
            ):
                raise RuntimeError(f"exact worker systemd identity is incomplete: {unit}")
        if Path(scope["ControlGroup"]).parent.as_posix() != attempt_slice["ControlGroup"]:
            raise RuntimeError("worker scope is not inside its exact attempt slice")

        try:
            sandbox_monitor_service._validate_scope_binding(
                expected_identity=(attempt_id, claim_token, execution_id),
                scope_unit=scope_unit,
                scope_invocation_id=scope["InvocationID"],
                scope_control_group=scope["ControlGroup"],
                attempt_slice_control_group=attempt_slice["ControlGroup"],
            )
        except sandbox_monitor_service.SandboxMonitorServiceError as error:
            raise RuntimeError(
                "live monitor scope binding rejected: "
                f"identity={(attempt_id, claim_token, execution_id)!r}; "
                f"scope_unit={scope_unit!r}; "
                f"scope_invocation_id={scope['InvocationID']!r}; "
                f"scope_control_group={scope['ControlGroup']!r}; "
                f"attempt_slice_unit={attempt_slice_unit!r}; "
                f"attempt_slice_control_group={attempt_slice['ControlGroup']!r}"
            ) from error

        supervisor._sandbox_execution_record_launch(
            attempt_id,
            claim_token,
            runc_handle=handle,
            launch_submission=submission,
            attempt_slice_unit=attempt_slice_unit,
            attempt_slice_invocation_id=attempt_slice["InvocationID"],
            attempt_slice_cgroup_path=attempt_slice["ControlGroup"],
            scope_unit=scope_unit,
            scope_invocation_id=scope["InvocationID"],
            cgroup_path=scope["ControlGroup"],
        )
        durable = supervisor._sandbox_execution_get(attempt_id)
        if durable is None or durable["phase"] != "launched":
            raise RuntimeError("trusted monitor did not durably record the launched execution")
        wrapper_unit = durable["wrapper_unit"]
        wrapper = _unit_properties(
            wrapper_unit,
            ("ActiveState", "ControlGroup", "Id", "InvocationID", "MainPID", "Slice"),
        )
        monitor_pid = durable["monitor_pid"]
        monitor_identity = durable["monitor_identity"]
        if (
            wrapper["Id"] != wrapper_unit
            or wrapper["ActiveState"] != "active"
            or wrapper["Slice"] != _MONITOR_SLICE_UNIT
            or int(wrapper["MainPID"]) != monitor_pid
            or wrapper["InvocationID"] != durable["wrapper_invocation_id"]
            or wrapper["ControlGroup"] != durable["wrapper_cgroup_path"]
            or _linux_process_identity(monitor_pid) != monitor_identity
            or _linux_process_identity(client_pid) != client_identity
            or Path(wrapper["ControlGroup"]).is_relative_to(Path(attempt_slice["ControlGroup"]))
        ):
            raise RuntimeError("service-owned monitor identity changed before running attestation")
        try:
            attestation = collect_running_runtime_attestation(
                runc_executable_pin=runc_pin,
                state_root=state_root,
                pid_file_path=pid_file,
                expected_container_id=container_id,
                expected_bundle_path=str(bundle_root),
                expected_monitor_pid=monitor_pid,
                expected_monitor_identity=monitor_identity,
                expected_runc_client_pid=client_pid,
                expected_runc_client_identity=client_identity,
                expected_wrapper_unit=wrapper_unit,
                expected_wrapper_invocation_id=wrapper["InvocationID"],
                expected_launch_driver_unit=launch_driver_unit,
                expected_attempt_slice_unit=attempt_slice_unit,
                expected_attempt_slice_invocation_id=attempt_slice["InvocationID"],
                expected_scope_unit=scope_unit,
                expected_scope_invocation_id=scope["InvocationID"],
                expected_cgroup_path=scope["ControlGroup"],
                expected_memory_max_bytes=_CONTAINER_MEMORY_BYTES,
                expected_cpu_quota=_CONTAINER_CPU_QUOTA_US,
                expected_cpu_period=_CONTAINER_CPU_PERIOD_US,
                expected_pids_max=_CONTAINER_PIDS_LIMIT,
            )
        except SupervisorError as error:
            try:
                init_pid = int(pid_file.read_text(encoding="ascii").strip())
                process_cgroups = {
                    pid: sandbox_attestation.read_linux_process_snapshot(pid).cgroup.decode(
                        "ascii", errors="replace"
                    )
                    for pid in (monitor_pid, client_pid, init_pid)
                }
            except BaseException as diagnostic_error:
                process_cgroups = {"diagnostic_error": repr(diagnostic_error)}
            raise RuntimeError(
                "live runtime attestation rejected process cgroup membership: "
                f"expected_scope={scope['ControlGroup']!r}; "
                f"observed_process_cgroups={process_cgroups!r}"
            ) from error
        durable = supervisor._sandbox_execution_get(attempt_id)
        if (
            durable is None
            or durable["phase"] != "launched"
            or marker.exists()
            or git_marker.exists()
        ):
            raise RuntimeError("payload ran before the durable running transition")
        _write_json(
            control / "pre-running.json",
            {
                "phase": durable["phase"],
                "monitor_pid": monitor_pid,
                "wrapper_main_pid": int(wrapper["MainPID"]),
                "runc_client_pid": client_pid,
                "launch_driver_apparmor_identity": _apparmor_identity(),
                "attestation_digest": attestation.evidence_sha256,
                "payload_marker_present": marker.exists(),
                "git_metadata_marker_present": git_marker.exists(),
                "source_git_pointer_regular_file": stat.S_ISREG(source_git_pointer.lstat().st_mode),
                "baseline_git_metadata_absent": not _entry_is_present(baseline.root / ".git"),
                "workspace_git_metadata_absent": not _entry_is_present(workspace.root / ".git"),
            },
        )
        _wait_for_receipt(control, "continue-running.json")
        durable = supervisor._sandbox_execution_get(attempt_id)
        if (
            durable is None
            or durable["phase"] != "launched"
            or marker.exists()
            or git_marker.exists()
        ):
            raise RuntimeError("journal or launch gate changed before test release")
        running = supervisor._sandbox_execution_record_running(
            attempt_id, claim_token, attestation=attestation, runc_handle=handle
        )
        if running["phase"] != "running" or marker.exists() or git_marker.exists():
            raise RuntimeError("payload escaped before the durable running transition")
        _write_json(
            control / "post-running.json",
            {
                "phase": running["phase"],
                "payload_marker_present_before_gate": marker.exists(),
                "git_metadata_marker_present_before_gate": git_marker.exists(),
            },
        )
        _wait_for_receipt(control, "running-observed.json")
        durable = supervisor._sandbox_execution_get(attempt_id)
        if (
            durable is None
            or durable["phase"] != "running"
            or marker.exists()
            or git_marker.exists()
        ):
            raise RuntimeError("worker gate changed before parent observed durable running state")
        if terminate_before_gate:
            termination = supervisor.terminate_worker(attempt_id)
            if (
                termination.get("outcome") != "ok"
                or termination.get("phase") != "stopping"
                or termination.get("monitor_phase") not in {"stopping", "exited"}
                or termination.get("stop_requested") is not True
                or termination.get("cleanup_verified") is not False
            ):
                raise RuntimeError(f"live monitor termination was not truthful: {termination!r}")
            if marker.exists() or git_marker.exists():
                raise RuntimeError("worker payload ran despite cancellation before gate release")
            wait_receipt = handle.wait(timeout=15.0)
            exited = supervisor._sandbox_execution_record_exit(
                attempt_id, claim_token, wait_receipt
            )
            if exited["phase"] != "exited":
                raise RuntimeError("cancelled runc client did not record its exact exit receipt")
            delete = subprocess.run(
                [str(runc_pin.path), "--root", str(state_root), "delete", "--force", container_id],
                check=False,
                capture_output=True,
                text=True,
                timeout=8.0,
                env=oci_worker._runc_client_environment(),
            )
            if delete.returncode != 0:
                raise RuntimeError("exact pinned runc state deletion failed after cancellation")
            _write_json(
                control / "result.json",
                {
                    "phase": exited["phase"],
                    "stop_outcome": termination["outcome"],
                    "stop_journal_phase": termination["phase"],
                    "stop_monitor_phase": termination["monitor_phase"],
                    "stop_requested": termination["stop_requested"],
                    "stop_cleanup_verified": termination["cleanup_verified"],
                    "runc_client_returncode": wait_receipt.returncode,
                    "runc_state_deleted": not (state_root / container_id).exists(),
                    "payload_marker_absent": not marker.exists(),
                    "git_marker_absent": not git_marker.exists(),
                    "cleanup_verified_written": False,
                },
            )
            return
        handle.release_gate()
        _wait_for_path(marker, control / "error.json", timeout=10.0)
        if marker.read_text(encoding="ascii") != "candidate-payload-ran\n":
            raise RuntimeError("payload wrote unexpected content into the private workspace")
        if git_marker.read_text(encoding="ascii") != "host-git-metadata-not-visible\n":
            raise RuntimeError("worker did not confirm the host .git pointer was absent")
        wait_receipt = handle.wait(timeout=15.0)
        exited = supervisor._sandbox_execution_record_exit(attempt_id, claim_token, wait_receipt)
        if exited["phase"] != "exited" or wait_receipt.returncode != 0:
            raise RuntimeError("test payload did not exit cleanly")
        write_set_rules = _persisted_write_set_rules(supervisor, attempt_id)
        change_set = collect_changes(
            baseline.manifest, workspace.root, write_set_rules=write_set_rules
        )
        if {
            change.path: change.content for change in change_set.changes if change.kind == "file"
        } != {
            _PAYLOAD_MARKER: b"candidate-payload-ran\n",
            _GIT_METADATA_MARKER: b"host-git-metadata-not-visible\n",
        }:
            raise RuntimeError("host change collection did not capture the exact declared output")
        undeclared_probe = workspace.root / "undeclared-output-probe"
        if _entry_is_present(undeclared_probe):
            raise RuntimeError("undeclared-write probe path already exists")
        try:
            undeclared_probe.write_bytes(b"must-not-be-authorized\n")
            try:
                collect_changes(baseline.manifest, workspace.root, write_set_rules=write_set_rules)
            except SupervisorError as error:
                if error.code != "undeclared_write":
                    raise
            else:
                raise RuntimeError("host change collector accepted an undeclared output")
        finally:
            undeclared_probe.unlink(missing_ok=True)
        if _entry_is_present(undeclared_probe):
            raise RuntimeError("undeclared-write probe remained in the private workspace")
        delete = subprocess.run(
            [str(runc_pin.path), "--root", str(state_root), "delete", "--force", container_id],
            check=False,
            capture_output=True,
            text=True,
            timeout=8.0,
            env=oci_worker._runc_client_environment(),
        )
        if delete.returncode != 0:
            raise RuntimeError("exact pinned runc state deletion failed after payload exit")
        _write_json(
            control / "result.json",
            {
                "phase": exited["phase"],
                "payload_marker": marker.read_text(encoding="ascii"),
                "git_metadata_absent_inside_worker": (
                    git_marker.read_text(encoding="ascii") == "host-git-metadata-not-visible\n"
                ),
                "runc_client_returncode": wait_receipt.returncode,
                "runc_state_deleted": not (state_root / container_id).exists(),
                "change_set_paths": [change.path for change in change_set.changes],
                "change_set_actions": [change.action for change in change_set.changes],
                "change_set_digest": change_set.digest,
                "undeclared_write_rejected": True,
                "cleanup_verified_written": False,
            },
        )
    except BaseException:
        _write_json(
            control / "error.json",
            {
                "traceback": traceback.format_exc(),
                "launch_driver_apparmor_identity": _apparmor_identity(),
            },
        )
        if handle is not None:
            handle.close_gate()
            process = oci_worker._runc_launch_process_for_testing(handle)
            if process is not None and process.poll() is None:
                try:
                    oci_worker._kill_process_group(process)
                except BaseException:
                    pass
        raise


def _monitor_child_entry(argv: list[str]) -> None:
    if len(argv) != 8 or argv[7] not in {"0", "1"}:
        raise SystemExit("monitor child requires seven arguments and a 0/1 terminate mode")
    repo, rootfs, worktree, attempt_id, claim_token, execution_id, control, terminate_mode = argv
    _monitor_child(
        Path(repo),
        Path(rootfs),
        Path(worktree),
        attempt_id,
        int(claim_token),
        execution_id,
        Path(control),
        terminate_mode == "1",
    )


def _systemd_command(argv: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=sandbox_attestation._trusted_systemd_command_environment(),
    )


def _wait_for_quiescence(service_unit: str | None, slice_unit: str | None) -> bool:
    safe = True
    for unit in (service_unit, slice_unit):
        if unit is None:
            continue
        try:
            properties = ("ActiveState", "ControlGroup", "Id", "LoadState")
            if unit.endswith(".service"):
                properties += ("MainPID",)
            props = _unit_properties(unit, properties)
        except Exception:
            return False
        not_running = props["LoadState"] == "not-found" or props["ActiveState"] == "inactive"
        if props["ActiveState"] == "failed":
            not_running = not unit.endswith(".service") or props["MainPID"] == "0"
        empty = (
            props["LoadState"] == "not-found"
            or (not props["ControlGroup"] and not_running)
            or _cgroup_is_empty(props["ControlGroup"])
        )
        inactive = not_running
        safe = safe and inactive and empty
    return safe


def _best_effort_stop_unit(systemctl: str, unit: str) -> None:
    """Request stop even when a start client timed out after systemd accepted it."""

    try:
        _systemd_command([systemctl, "--user", "stop", unit], timeout=12.0)
    except (OSError, subprocess.TimeoutExpired):
        # The caller still requires an independent exact-unit quiescence proof.
        pass


def _reset_transient_service_after_quiescence(systemctl: str, service_unit: str) -> bool:
    """Unload only the exact test-owned transient service after proving it is inert."""

    try:
        properties = _unit_properties(
            service_unit, ("ActiveState", "ControlGroup", "LoadState", "MainPID")
        )
        if properties["LoadState"] == "not-found":
            return (
                properties["ActiveState"] == "inactive"
                and not properties["ControlGroup"]
                and properties["MainPID"] == "0"
            )
        if (
            properties["LoadState"] != "loaded"
            or properties["ActiveState"] not in {"inactive", "failed"}
            or properties["ControlGroup"]
            or properties["MainPID"] != "0"
        ):
            return False
        reset = _systemd_command([systemctl, "--user", "reset-failed", service_unit], timeout=12.0)
        if reset.returncode != 0:
            return False
        properties = _unit_properties(
            service_unit, ("ActiveState", "ControlGroup", "LoadState", "MainPID")
        )
    except Exception:
        return False
    return (
        properties["LoadState"] == "not-found"
        and properties["ActiveState"] == "inactive"
        and not properties["ControlGroup"]
        and properties["MainPID"] == "0"
    )


def _stop_attempted_units_and_check_quiescence(
    systemctl: str,
    service_unit: str | None,
    service_start_attempted: bool,
    slice_unit: str | None,
    slice_start_attempted: bool,
) -> bool:
    """Stop and verify each unit whose start request might have reached systemd."""

    if service_start_attempted and service_unit is not None:
        _best_effort_stop_unit(systemctl, service_unit)
    if slice_start_attempted and slice_unit is not None:
        _best_effort_stop_unit(systemctl, slice_unit)
    quiescent = _wait_for_quiescence(
        service_unit if service_start_attempted else None,
        slice_unit if slice_start_attempted else None,
    )
    if not quiescent:
        return False
    if service_start_attempted and service_unit is not None:
        return _reset_transient_service_after_quiescence(systemctl, service_unit)
    return True


def test_attempted_systemd_starts_are_stopped_and_checked_after_client_timeouts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stop_requests: list[str] = []
    checked_units: list[tuple[str | None, str | None]] = []
    reset_units: list[str] = []

    def timed_out_stop(argv: list[str], timeout: float = 10.0) -> None:
        stop_requests.append(argv[-1])
        raise subprocess.TimeoutExpired(argv, timeout)

    def quiescent(service: str | None, slice_: str | None) -> bool:
        checked_units.append((service, slice_))
        return True

    def reset_after_quiescence(systemctl: str, service: str) -> bool:
        reset_units.append(service)
        return True

    monkeypatch.setattr(sys.modules[__name__], "_systemd_command", timed_out_stop)
    monkeypatch.setattr(sys.modules[__name__], "_wait_for_quiescence", quiescent)
    monkeypatch.setattr(
        sys.modules[__name__],
        "_reset_transient_service_after_quiescence",
        reset_after_quiescence,
    )
    assert _stop_attempted_units_and_check_quiescence(
        "/usr/bin/systemctl",
        "acp-test.service",
        True,
        "acp-test.slice",
        True,
    )
    assert stop_requests == ["acp-test.service", "acp-test.slice"]
    assert checked_units == [("acp-test.service", "acp-test.slice")]
    assert reset_units == ["acp-test.service"]


def test_reset_transient_service_requires_exact_unit_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []

    def command(argv: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
        commands.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    properties = {
        "ActiveState": "inactive",
        "ControlGroup": "",
        "LoadState": "not-found",
        "MainPID": "0",
    }
    monkeypatch.setattr(sys.modules[__name__], "_systemd_command", command)
    monkeypatch.setattr(
        sys.modules[__name__],
        "_unit_properties",
        lambda unit, requested: {name: properties[name] for name in requested},
    )

    assert _reset_transient_service_after_quiescence("/usr/bin/systemctl", "acp-test.service")
    assert commands == []

    properties["LoadState"] = "loaded"
    properties["ActiveState"] = "failed"
    properties["MainPID"] = "0"
    queue = [
        dict(properties),
        {
            "ActiveState": "inactive",
            "ControlGroup": "",
            "LoadState": "not-found",
            "MainPID": "0",
        },
    ]

    def queued_properties(unit: str, requested: tuple[str, ...]) -> dict[str, str]:
        current = queue.pop(0)
        return {name: current[name] for name in requested}

    monkeypatch.setattr(
        sys.modules[__name__],
        "_unit_properties",
        queued_properties,
    )
    assert _reset_transient_service_after_quiescence("/usr/bin/systemctl", "acp-test.service")
    assert commands == [["/usr/bin/systemctl", "--user", "reset-failed", "acp-test.service"]]


def test_unit_preflight_allows_only_inactive_empty_implicit_slices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unit_properties = {
        "ActiveState": "inactive",
        "ControlGroup": "",
        "FragmentPath": "",
        "LoadState": "loaded",
    }
    monkeypatch.setattr(
        sys.modules[__name__],
        "_unit_properties",
        lambda unit, properties: {name: unit_properties[name] for name in properties},
    )
    _assert_units_available_for_test("user-acp-test.slice")
    with pytest.raises(pytest.fail.Exception, match="pre-existing systemd unit"):
        _assert_units_available_for_test("acp-test.service")


def _remove_private_test_tree(root: Path) -> None:
    """Remove only this private fixture after making its read-only files deletable."""

    root_info = root.lstat()
    if (
        root.parent != Path("/tmp")
        or not root.name.startswith(("acp-live-sandbox-lifecycle-", "acp-live-launch-driver-"))
        or not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != os.geteuid()
    ):
        raise RuntimeError("refusing to remove an unexpected live-test artifact root")

    def fail_walk(error: OSError) -> None:
        raise error

    for directory, subdirectories, filenames in os.walk(
        root, topdown=False, followlinks=False, onerror=fail_walk
    ):
        current = Path(directory)
        for name in (*subdirectories, *filenames):
            child = current / name
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode):
                continue
            if info.st_uid != os.geteuid():
                raise RuntimeError(
                    f"refusing to change permissions on non-owned fixture data: {child}"
                )
            if stat.S_ISDIR(info.st_mode):
                child.chmod(0o700)
            elif stat.S_ISREG(info.st_mode):
                child.chmod(0o600)
        current.chmod(0o700)
    shutil.rmtree(root)


def _ensure_private_fixture_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise RuntimeError(f"fixture state path is not a real directory: {path.name}")
    if info.st_uid != os.geteuid():
        raise RuntimeError(f"fixture state directory has an unexpected owner: {path.name}")
    path.chmod(0o700)


@pytest.mark.skip(
    reason=(
        "superseded: direct monitor-owned launch violates exact launch-driver redemption; "
        "rebuild this harness on start_sandbox_launch_driver before re-enabling"
    )
)
@pytest.mark.parametrize("terminate_before_gate", [False, True], ids=["release", "terminate"])
def test_live_monitor_journal_holds_payload_until_durable_running_transition(
    terminate_before_gate: bool,
) -> None:
    """Deprecated harness; see the explicit skip reason and current producer proof."""

    source_root = Path(__file__).resolve().parents[1]
    if not sys.platform.startswith("linux") or os.geteuid() == 0:
        pytest.fail("live monitor/journal composition requires an unprivileged Linux user")
    if not source_root.is_relative_to(Path("/tmp")):
        pytest.fail("run this opt-in proof from a disposable checkout beneath /tmp")
    if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        pytest.fail("live monitor/journal composition requires unified cgroup v2")
    controllers = set(Path("/sys/fs/cgroup/cgroup.controllers").read_text().split())
    if not {"cpu", "memory", "pids"}.issubset(controllers):
        pytest.fail("cpu, memory, and pids cgroup v2 controllers are required")
    if os.environ.get("ACP_OCI_TEST_RUNC_VERSION") != _SUPPORTED_RUNC_VERSION:
        pytest.fail("set ACP_OCI_TEST_RUNC_VERSION=1.5.2 for this exact live proof")
    environment = sandbox_attestation._trusted_systemd_command_environment()
    if not (Path(environment["XDG_RUNTIME_DIR"]) / "bus").is_socket():
        pytest.fail("private systemd user-manager socket is unavailable")
    systemctl = str(sandbox_attestation._trusted_systemctl_executable())
    if _systemd_command([systemctl, "--user", "show-environment"]).returncode != 0:
        pytest.fail("active systemd user manager is required")
    if " - cgroup2 " not in Path("/proc/self/mountinfo").read_text(encoding="ascii"):
        pytest.fail("current host does not expose unified cgroup v2")

    runc_path = Path(os.environ.get("ACP_OCI_TEST_RUNC", "/usr/bin/runc"))
    busybox_path = Path(os.environ.get("ACP_OCI_TEST_BUSYBOX", "/usr/bin/busybox"))
    apparmor_profile = os.environ.get("ACP_OCI_TEST_APPARMOR_PROFILE", "").strip()
    apparmor_prefix: list[str] = []
    if apparmor_profile:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", apparmor_profile):
            pytest.fail("ACP_OCI_TEST_APPARMOR_PROFILE must be a simple profile name")
        aa_exec = shutil.which("aa-exec", path=environment["PATH"])
        if aa_exec is None:
            pytest.fail("aa-exec is required when an AppArmor profile is requested")
        profile_probe = _systemd_command([aa_exec, "-p", apparmor_profile, "--", "true"])
        if profile_probe.returncode != 0:
            pytest.fail(f"requested AppArmor profile is unavailable: {apparmor_profile}")
        apparmor_prefix = [aa_exec, "-p", apparmor_profile, "--"]
    systemd_run = shutil.which("systemd-run", path=environment["PATH"])
    if systemd_run is None:
        pytest.fail("systemd-run is required for the exact launch-driver service")
    run_root = Path(tempfile.mkdtemp(prefix="acp-live-sandbox-lifecycle-", dir="/tmp"))
    rootfs_source = run_root / "rootfs-source"
    service_unit: str | None = None
    monitor_unit: str | None = None
    slice_unit: str | None = None
    service_start_attempted = False
    monitor_start_attempted = False
    slice_start_attempted = False
    safe_to_remove = False
    try:
        run_root.chmod(0o700)
        rootfs_source.mkdir(mode=0o755)
        for directory in ("bin", "dev", "etc", "home/agent", "proc", "run", "tmp", "workspace"):
            (rootfs_source / directory).mkdir(parents=True, exist_ok=True, mode=0o755)
        _copy_busybox_closure(busybox_path, rootfs_source)
        repo_root = run_root / "repo"
        repo_root.mkdir(mode=0o700)
        repo = init_repo(repo_root)
        _ensure_private_fixture_directory(repo / ".acp")
        _ensure_private_fixture_directory(repo / ".acp" / "sandbox-executions")
        rootfs_manifest = oci_worker.rootfs_tree_manifest(rootfs_source)
        with (repo / "acp.toml").open("a", encoding="utf-8") as stream:
            stream.write(
                "\n[sandbox.oci]\n"
                f"runc_executable = {json.dumps(str(runc_path.resolve(strict=True)))}\n"
                f"runc_version = {json.dumps(_SUPPORTED_RUNC_VERSION)}\n"
                f"rootfs_path = {json.dumps(str(rootfs_source.resolve(strict=True)))}\n"
                f"rootfs_sha256 = {json.dumps(rootfs_manifest['rootfs_sha256'])}\n"
                f"rootfs_closure_sha256 = {json.dumps(rootfs_manifest['closure_sha256'])}\n"
            )
        supervisor = GitSupervisor(repo)
        task = make_task(
            supervisor,
            _PAYLOAD_MARKER,
            _GIT_METADATA_MARKER,
            title="sandbox lifecycle integration",
        )
        attempt = supervisor.claim(task["id"], "sandbox-lifecycle-test")
        pin = supervisor.config.oci_rootfs_pin
        runc_pin = supervisor.config.oci_runc_executable
        if (
            pin is None
            or runc_pin is None
            or supervisor.config.oci_runc_version != _SUPPORTED_RUNC_VERSION
        ):
            pytest.fail("test config did not pin the exact rootfs and runc identities")
        execution = supervisor._sandbox_execution_reserve(
            attempt["id"],
            attempt["claim_token"],
            rootfs_digest=pin.sha256,
            rootfs_closure_digest=pin.closure_sha256,
            runc_executable_digest=runc_pin.sha256,
            runtime_version=supervisor.config.oci_runc_version,
            oci_version="1.2.1",
        )
        execution_root = Path(execution["bundle_path"]).parent
        execution_root.mkdir(mode=0o700, parents=True)
        Path(execution["bundle_path"]).mkdir(mode=0o700)
        Path(execution["state_path"]).mkdir(mode=0o700)
        control = run_root / "control"
        control.mkdir(mode=0o700)
        monitor_unit = sandbox_monitor_service_unit(
            attempt["id"], attempt["claim_token"], execution["execution_id"]
        )
        service_unit = f"acp-launch-driver-{execution['execution_id']}.service"
        slice_unit = sandbox_attempt_slice_unit(
            attempt["id"], attempt["claim_token"], execution["execution_id"]
        )
        _assert_units_available_for_test(service_unit, monitor_unit, slice_unit)
        # Mark before IPC: a timeout/error can happen after systemd accepted the
        # request, so teardown must inspect and stop this exact unit regardless.
        slice_start_attempted = True
        started = _systemd_command([systemctl, "--user", "start", slice_unit])
        if started.returncode != 0:
            pytest.fail("systemd could not start the exact execution attempt slice")
        pythonpath = os.pathsep.join((str(source_root / "src"), str(source_root / "tests")))
        service_command = [
            systemd_run,
            "--user",
            f"--unit={service_unit}",
            f"--slice={slice_unit}",
            "--property=Type=exec",
            "--property=KillMode=control-group",
            "--property=RuntimeMaxSec=120s",
            f"--working-directory={source_root}",
            f"--setenv=PYTHONPATH={pythonpath}",
            "--no-block",
            *apparmor_prefix,
            sys.executable,
            str(Path(__file__).resolve()),
            "--monitor-child",
            str(repo),
            str(rootfs_source),
            str(attempt["worktree"]),
            attempt["id"],
            str(attempt["claim_token"]),
            execution["execution_id"],
            str(control),
            "1" if terminate_before_gate else "0",
        ]
        # The exact driver service is a child of the attempt slice and is
        # stopped and checked independently even if systemd-run times out.
        service_start_attempted = True
        # The launch driver creates this exact per-execution monitor unit after
        # the worker scope exists. Treat a driver timeout as an ambiguous start
        # of both units and inspect both during isolated test teardown.
        monitor_start_attempted = True
        launched = _systemd_command(service_command, timeout=12.0)
        if launched.returncode != 0:
            pytest.fail(f"could not start exact monitor service: {launched.stderr[-1200:]}")

        pre_path = _wait_for_receipt(control, "pre-running.json")
        pre = json.loads(pre_path.read_text(encoding="utf-8"))
        durable = supervisor._sandbox_execution_get(attempt["id"])
        marker = Path(durable["workspace_root_path"]) / _PAYLOAD_MARKER if durable else None
        git_marker = (
            Path(durable["workspace_root_path"]) / _GIT_METADATA_MARKER if durable else None
        )
        assert durable is not None and durable["phase"] == "launched"
        assert pre["phase"] == "launched"
        assert pre["monitor_pid"] == pre["wrapper_main_pid"]
        assert pre["payload_marker_present"] is False
        assert pre["git_metadata_marker_present"] is False
        assert pre["source_git_pointer_regular_file"] is True
        assert pre["baseline_git_metadata_absent"] is True
        assert pre["workspace_git_metadata_absent"] is True
        if apparmor_profile:
            profile_stack = (
                str(pre["launch_driver_apparmor_identity"]).partition(" (")[0].split("//&")
            )
            assert apparmor_profile in profile_stack
        assert marker is not None and not marker.exists()
        assert git_marker is not None and not git_marker.exists()

        (control / "continue-running.json").write_text("release-transition\n", encoding="ascii")
        post_path = _wait_for_receipt(control, "post-running.json")
        post = json.loads(post_path.read_text(encoding="utf-8"))
        durable = supervisor._sandbox_execution_get(attempt["id"])
        assert post["phase"] == "running"
        assert post["payload_marker_present_before_gate"] is False
        assert post["git_metadata_marker_present_before_gate"] is False
        assert durable is not None and durable["phase"] == "running"
        assert marker is not None
        assert not marker.exists()
        assert git_marker is not None and not git_marker.exists()
        (control / "running-observed.json").write_text("running-state-verified\n", encoding="ascii")
        result_path = _wait_for_receipt(control, "result.json", timeout=20.0)
        result = json.loads(result_path.read_text(encoding="utf-8"))
        durable = supervisor._sandbox_execution_get(attempt["id"])
        if terminate_before_gate:
            assert set(result) == {
                "phase",
                "stop_outcome",
                "stop_journal_phase",
                "stop_monitor_phase",
                "stop_requested",
                "stop_cleanup_verified",
                "runc_client_returncode",
                "runc_state_deleted",
                "payload_marker_absent",
                "git_marker_absent",
                "cleanup_verified_written",
            }
            assert result["stop_outcome"] == "ok"
            assert result["stop_journal_phase"] == "stopping"
            assert result["stop_monitor_phase"] in {"stopping", "exited"}
            assert result["stop_requested"] is True
            assert result["stop_cleanup_verified"] is False
            assert result["runc_state_deleted"] is True
            assert result["payload_marker_absent"] is True
            assert result["git_marker_absent"] is True
            assert result["cleanup_verified_written"] is False
            assert marker is not None and not marker.exists()
            assert git_marker is not None and not git_marker.exists()
        else:
            _wait_for_path(marker, control / "error.json", timeout=10.0)
            assert (
                marker is not None
                and marker.read_text(encoding="ascii") == "candidate-payload-ran\n"
            )
            assert (
                git_marker is not None
                and git_marker.read_text(encoding="ascii") == "host-git-metadata-not-visible\n"
            )
            assert set(result) == {
                "phase",
                "payload_marker",
                "git_metadata_absent_inside_worker",
                "runc_client_returncode",
                "runc_state_deleted",
                "change_set_paths",
                "change_set_actions",
                "change_set_digest",
                "undeclared_write_rejected",
                "cleanup_verified_written",
            }
            assert result["payload_marker"] == "candidate-payload-ran\n"
            assert result["git_metadata_absent_inside_worker"] is True
            assert result["runc_client_returncode"] == 0
            assert result["runc_state_deleted"] is True
            assert result["change_set_paths"] == sorted([_PAYLOAD_MARKER, _GIT_METADATA_MARKER])
            assert result["change_set_actions"] == ["create", "create"]
            assert re.fullmatch(r"[0-9a-f]{64}", result["change_set_digest"])
            assert result["undeclared_write_rejected"] is True
            assert result["cleanup_verified_written"] is False
        assert result["phase"] == "exited"
        assert durable is not None and durable["phase"] == "exited"
        worktree = Path(attempt["worktree"])
        binding = supervisor._sandbox_execution_restore_workspace_binding(
            attempt["id"], attempt["claim_token"]
        )
        source_after = copy_snapshot(worktree, control / "registered-source-after")
        assert source_after.manifest == binding["baseline"].manifest
        assert not _entry_is_present(worktree / _PAYLOAD_MARKER)
        assert not _entry_is_present(worktree / _GIT_METADATA_MARKER)
        with pytest.raises(SupervisorError) as unverified_result:
            supervisor._sandbox_execution_capture_result_candidate(
                attempt["id"], attempt["claim_token"]
            )
        assert unverified_result.value.code == "sandbox_result_evidence_unverified"
        durable_after_rejection = supervisor._sandbox_execution_get(attempt["id"])
        assert durable_after_rejection is not None
        assert durable_after_rejection["phase"] == "exited"
        assert durable_after_rejection["result_candidate"] is None
    finally:
        driver_and_slice_safe = _stop_attempted_units_and_check_quiescence(
            systemctl,
            service_unit,
            service_start_attempted,
            slice_unit,
            slice_start_attempted,
        )
        monitor_safe = False
        if driver_and_slice_safe:
            monitor_safe = _stop_attempted_units_and_check_quiescence(
                systemctl,
                monitor_unit,
                monitor_start_attempted,
                None,
                False,
            )
        safe_to_remove = driver_and_slice_safe and monitor_safe
        if safe_to_remove:
            _remove_private_test_tree(run_root)
        else:
            pytest.fail(f"exact test units are not quiescent; preserving artifacts at {run_root}")


@pytest.mark.skipif(
    not _LIVE_ENABLED,
    reason="set ACP_RUN_SANDBOX_WORKER_LIFECYCLE=1 on a disposable supported Linux host",
)
def test_live_production_launch_driver_runs_exact_pinned_runc_request() -> None:
    """Use the production launcher and reaper for completion, cancel, or timeout."""

    source_root = Path(__file__).resolve().parents[1]
    if not sys.platform.startswith("linux") or os.geteuid() == 0:
        pytest.fail("live launch-driver proof requires an unprivileged Linux user")
    if not source_root.is_relative_to(Path("/tmp")):
        pytest.fail("run this opt-in proof from a disposable checkout beneath /tmp")
    if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        pytest.fail("live launch-driver proof requires unified cgroup v2")
    controllers = set(Path("/sys/fs/cgroup/cgroup.controllers").read_text().split())
    if not {"cpu", "memory", "pids"}.issubset(controllers):
        pytest.fail("cpu, memory, and pids cgroup v2 controllers are required")
    if os.environ.get("ACP_OCI_TEST_RUNC_VERSION") != _SUPPORTED_RUNC_VERSION:
        pytest.fail("set ACP_OCI_TEST_RUNC_VERSION=1.5.2 for this exact live proof")
    environment = sandbox_attestation._trusted_systemd_command_environment()
    if not (Path(environment["XDG_RUNTIME_DIR"]) / "bus").is_socket():
        pytest.fail("private systemd user-manager socket is unavailable")
    systemctl = str(sandbox_attestation._trusted_systemctl_executable())
    if _systemd_command([systemctl, "--user", "show-environment"]).returncode != 0:
        pytest.fail("active systemd user manager is required")
    if " - cgroup2 " not in Path("/proc/self/mountinfo").read_text(encoding="ascii"):
        pytest.fail("current host does not expose unified cgroup v2")

    runc_path = Path(os.environ.get("ACP_OCI_TEST_RUNC", "/usr/bin/runc"))
    busybox_path = Path(os.environ.get("ACP_OCI_TEST_BUSYBOX", "/usr/bin/busybox"))
    run_root = Path(tempfile.mkdtemp(prefix="acp-live-launch-driver-", dir="/tmp"))
    rootfs_source = run_root / "rootfs-source"
    service_log_path = run_root / "launch-driver-service.log"
    service_unit: str | None = None
    monitor_unit: str | None = None
    slice_unit: str | None = None
    service_start_attempted = False
    monitor_start_attempted = False
    slice_start_attempted = False
    safe_to_remove = False
    child_processes: list[multiprocessing.Process] = []
    try:
        run_root.chmod(0o700)
        rootfs_source.mkdir(mode=0o755)
        for directory in (
            "bin",
            "dev",
            "etc",
            "home/agent",
            "proc",
            "run",
            "tmp",
            "workspace",
        ):
            (rootfs_source / directory).mkdir(parents=True, exist_ok=True, mode=0o755)
        _copy_busybox_closure(busybox_path, rootfs_source)
        repo_root = run_root / "repo"
        repo_root.mkdir(mode=0o700)
        repo = init_repo(repo_root)
        _ensure_private_fixture_directory(repo / ".acp")
        _ensure_private_fixture_directory(repo / ".acp" / "sandbox-executions")
        rootfs_manifest = oci_worker.rootfs_tree_manifest(rootfs_source)
        runtime_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            runtime_probe.bind(("127.0.0.1", 0))
            runtime_test_port = runtime_probe.getsockname()[1]
        finally:
            runtime_probe.close()
        with (repo / "acp.toml").open("a", encoding="utf-8") as stream:
            stream.write(
                "\n[sandbox.oci]\n"
                f"runc_executable = {json.dumps(str(runc_path.resolve(strict=True)))}\n"
                f"runc_version = {json.dumps(_SUPPORTED_RUNC_VERSION)}\n"
                f"rootfs_path = {json.dumps(str(rootfs_source.resolve(strict=True)))}\n"
                f"rootfs_sha256 = {json.dumps(rootfs_manifest['rootfs_sha256'])}\n"
                f"rootfs_closure_sha256 = {json.dumps(rootfs_manifest['closure_sha256'])}\n"
                "\n[runtime.ports]\n"
                f"LAUNCH_DRIVER_TEST_PORT = [{runtime_test_port}, {runtime_test_port}]\n"
            )
        supervisor = GitSupervisor(repo)
        runner = supervisor.enroll_runner("sandbox-launch-driver-test", "worker")
        task = make_task(
            supervisor,
            "launch-driver-marker",
            "launch-driver-started",
            title="launch-driver producer test",
        )
        attempt = supervisor.claim(
            task["id"],
            "sandbox-launch-driver-test",
            credential=runner["credential"],
        )
        rootfs_pin = supervisor.config.oci_rootfs_pin
        runc_pin = supervisor.config.oci_runc_executable
        if (
            rootfs_pin is None
            or runc_pin is None
            or supervisor.config.oci_runc_version != _SUPPORTED_RUNC_VERSION
        ):
            pytest.fail("test config did not pin the exact rootfs and runc identities")
        execution = supervisor._sandbox_execution_reserve(
            attempt["id"],
            attempt["claim_token"],
            rootfs_digest=rootfs_pin.sha256,
            rootfs_closure_digest=rootfs_pin.closure_sha256,
            runc_executable_digest=runc_pin.sha256,
            runtime_version=supervisor.config.oci_runc_version,
            oci_version="1.2.1",
            credential=runner["credential"],
        )
        execution_root = Path(execution["bundle_path"]).parent
        execution_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        bundle_root = Path(execution["bundle_path"])
        state_root = Path(execution["state_path"])
        bundle_root.mkdir(mode=0o700)
        state_root.mkdir(mode=0o700)
        shutil.copytree(rootfs_source, bundle_root / "rootfs", symlinks=True)
        source_worktree = Path(attempt["worktree"])
        baseline = copy_snapshot(source_worktree, execution_root / "baseline")
        workspace = copy_snapshot(baseline.root, execution_root / "workspace")
        assert not _entry_is_present(workspace.root / ".git")
        supervisor._sandbox_execution_bind_workspace(
            attempt["id"],
            attempt["claim_token"],
            baseline,
            workspace,
            credential=runner["credential"],
        )

        identity = (attempt["id"], attempt["claim_token"], execution["execution_id"])
        service_unit = f"acp-launch-driver-{execution['execution_id']}.service"
        monitor_unit = sandbox_monitor_service_unit(*identity)
        slice_unit = sandbox_attempt_slice_unit(*identity)
        _assert_units_available_for_test(service_unit, monitor_unit, slice_unit)
        service_start_attempted = True
        slice_start_attempted = True
        monitor_start_attempted = True

        cancel_after_start = os.environ.get("ACP_LIVE_CANCEL_AFTER_START") == "1"
        timeout_after_start = os.environ.get("ACP_LIVE_TIMEOUT_AFTER_START") == "1"
        crash_after_manager_acceptance = (
            os.environ.get("ACP_LIVE_CRASH_AFTER_MANAGER_ACCEPTANCE") == "1"
        )
        crash_after_monitor_acceptance = (
            os.environ.get("ACP_LIVE_CRASH_AFTER_MONITOR_ACCEPTANCE") == "1"
        )
        crash_before_monitor_start = os.environ.get("ACP_LIVE_CRASH_BEFORE_MONITOR_START") == "1"
        import_result_after_cleanup = os.environ.get("ACP_LIVE_IMPORT_RESULT_AFTER_CLEANUP") == "1"
        if (
            sum(
                (
                    cancel_after_start,
                    timeout_after_start,
                    crash_after_manager_acceptance,
                    crash_after_monitor_acceptance,
                    crash_before_monitor_start,
                )
            )
            > 1
        ):
            pytest.fail("live cancel, timeout, and crash-injection modes are mutually exclusive")
        if import_result_after_cleanup and any(
            (
                cancel_after_start,
                timeout_after_start,
                crash_after_manager_acceptance,
                crash_after_monitor_acceptance,
                crash_before_monitor_start,
            )
        ):
            pytest.fail("live result import requires the natural-completion mode")
        crash_driver_service_before_receipt = (
            crash_after_manager_acceptance
            or crash_after_monitor_acceptance
            or crash_before_monitor_start
        )
        monitor_acceptance_marker = run_root / "monitor-handoff-crash.json"
        payload_sleep_seconds = 30 if cancel_after_start or timeout_after_start else 1
        sandbox_timeout_seconds = 1 if timeout_after_start else 30
        payload_command = (
            "/bin/busybox",
            "sh",
            "-c",
            "printf 'production-driver-started\\n' > /workspace/launch-driver-started; "
            f"/bin/busybox sleep {payload_sleep_seconds} && "
            "printf 'production-driver-ran\\n' > /workspace/launch-driver-marker",
        )
        context = multiprocessing.get_context("spawn")
        producer_result_receiver, producer_result_sender = context.Pipe(duplex=False)
        producer_controller = context.Process(
            target=_start_launch_driver_then_crash_controller,
            args=(
                repo,
                identity,
                payload_command,
                _CONTAINER_MEMORY_BYTES,
                _CONTAINER_CPU_QUOTA_US,
                _CONTAINER_CPU_PERIOD_US,
                _CONTAINER_PIDS_LIMIT,
                sandbox_timeout_seconds,
                runner["credential"],
                service_log_path,
                producer_result_sender,
                crash_driver_service_before_receipt,
                monitor_acceptance_marker
                if crash_after_monitor_acceptance or crash_before_monitor_start
                else None,
                crash_before_monitor_start,
            ),
        )
        producer_controller.start()
        child_processes.append(producer_controller)
        producer_result_sender.close()
        assert producer_result_receiver.poll(35), "launch producer did not report its handoff"
        producer_result = producer_result_receiver.recv()
        producer_controller.join(timeout=5)
        assert not producer_controller.is_alive(), (
            "launch producer survived simulated controller loss"
        )
        if producer_result[0] not in {"ok", "manager_accepted"}:
            service_log = service_log_path.read_text(encoding="utf-8", errors="replace")
            assert runner["credential"] not in service_log
            service_detail = service_log[-12_000:] or "<launch-driver service log is empty>"
            raise AssertionError(
                f"production launch-driver startup failed: {producer_result}; "
                f"service log tail:\n{service_detail}"
            )
        if crash_driver_service_before_receipt:
            assert producer_result[0] == "manager_accepted", producer_result
            producer_exit = 74
        else:
            assert producer_result[0] == "ok", producer_result
            producer_exit = 73
        assert producer_controller.exitcode == producer_exit
        producer_result_receiver.close()
        if producer_result[0] == "manager_accepted":
            controller_pid = producer_result[1]
            producer_receipt = None
        else:
            controller_pid, producer_receipt = producer_result[1:]
            assert producer_receipt["attempt_id"] == identity[0]
            assert producer_receipt["claim_token"] == identity[1]
            assert producer_receipt["execution_id"] == identity[2]
        if crash_after_monitor_acceptance or crash_before_monitor_start:
            _wait_for_receipt(run_root, "monitor-handoff-crash.json", timeout=40.0)
            accepted = json.loads(monitor_acceptance_marker.read_text(encoding="ascii"))
            expected_crash_phase = (
                "before_monitor_start" if crash_before_monitor_start else "after_monitor_acceptance"
            )
            assert accepted["crash_phase"] == expected_crash_phase
            assert accepted["identity"] == list(identity)
            driver = accepted["driver"]
            monitor = accepted["monitor"]
            scope = accepted["scope"]
            assert driver["unit"] == service_unit
            assert driver["pid"] == driver["main_pid"] > 0
            assert driver["identity"].startswith(f"linux:{driver['pid']}:")
            assert driver["active_state"] == "active"
            assert re.fullmatch(r"[0-9a-f]{32}", driver["invocation_id"])
            assert driver["slice"] == slice_unit
            assert PurePosixPath(driver["control_group"]).name == service_unit
            assert (
                PurePosixPath(driver["control_group"]).parent.as_posix()
                == accepted["attempt_slice_control_group"]
            )
            assert accepted["attempt_slice"] == slice_unit
            assert accepted["monitor_unit"] == monitor_unit
            if crash_before_monitor_start:
                assert monitor is None
            else:
                assert monitor is not None
                assert monitor["unit"] == monitor_unit
                assert (
                    monitor["attempt_id"],
                    monitor["claim_token"],
                    monitor["execution_id"],
                ) == identity
                assert monitor["pid"] > 0
                assert monitor["identity"].startswith(f"linux:{monitor['pid']}:")
                assert re.fullmatch(r"[0-9a-f]{32}", monitor["invocation_id"])
                assert monitor["control_group"]
                assert not PurePosixPath(monitor["control_group"]).is_relative_to(
                    PurePosixPath(accepted["attempt_slice_control_group"])
                )
            assert scope["unit"] == f"acp-{execution['container_id']}.scope"
            assert re.fullmatch(r"[0-9a-f]{32}", scope["invocation_id"])
            assert (
                PurePosixPath(scope["control_group"]).parent.as_posix()
                == (accepted["attempt_slice_control_group"])
            )
            assert accepted["runc_client_pid"] > 0
            assert accepted["runc_client_identity"].startswith(
                f"linux:{accepted['runc_client_pid']}:"
            )
            service_log = service_log_path.read_text(encoding="utf-8", errors="replace")
            assert runner["credential"] not in service_log

            deadline = time.monotonic() + 10
            driver_after_crash = _unit_properties(
                service_unit,
                (
                    "ActiveState",
                    "ControlGroup",
                    "Id",
                    "InvocationID",
                    "LoadState",
                    "MainPID",
                    "Slice",
                ),
            )
            while time.monotonic() < deadline and (
                driver_after_crash["MainPID"] != "0"
                or driver_after_crash["ActiveState"] not in {"failed", "inactive"}
            ):
                time.sleep(0.05)
                driver_after_crash = _unit_properties(
                    service_unit,
                    (
                        "ActiveState",
                        "ControlGroup",
                        "Id",
                        "InvocationID",
                        "LoadState",
                        "MainPID",
                        "Slice",
                    ),
                )
            assert driver_after_crash["Id"] == service_unit
            assert driver_after_crash["LoadState"] == "loaded"
            assert driver_after_crash["ActiveState"] in {"failed", "inactive"}
            assert driver_after_crash["MainPID"] == "0"
            assert driver_after_crash["InvocationID"] == driver["invocation_id"]
            assert driver_after_crash["Slice"] == slice_unit
            monitor_before_recovery = _unit_properties(
                monitor_unit,
                (
                    "ActiveState",
                    "ControlGroup",
                    "Id",
                    "InvocationID",
                    "LoadState",
                    "MainPID",
                    "Slice",
                ),
            )
            assert monitor_before_recovery["Id"] == monitor_unit
            if crash_before_monitor_start:
                assert monitor_before_recovery["ActiveState"] == "inactive"
                assert monitor_before_recovery["LoadState"] == "not-found"
                assert monitor_before_recovery["MainPID"] == "0"
                assert not monitor_before_recovery["InvocationID"]
                assert not monitor_before_recovery["ControlGroup"]
            else:
                assert monitor_before_recovery["ActiveState"] == "active"
                assert monitor_before_recovery["LoadState"] == "loaded"
                assert monitor_before_recovery["MainPID"] == str(monitor["pid"])
                assert monitor_before_recovery["InvocationID"] == monitor["invocation_id"]
                assert monitor_before_recovery["ControlGroup"] == monitor["control_group"]
            attempt_slice_before_recovery = _unit_properties(
                slice_unit, ("ActiveState", "ControlGroup", "Id", "LoadState")
            )
            assert attempt_slice_before_recovery["ActiveState"] == "active"
            assert attempt_slice_before_recovery["Id"] == slice_unit
            assert (
                attempt_slice_before_recovery["ControlGroup"]
                == accepted["attempt_slice_control_group"]
            )
            scope_before_recovery = _unit_properties(
                scope["unit"],
                ("ActiveState", "ControlGroup", "Id", "InvocationID", "LoadState", "Slice"),
            )
            assert scope_before_recovery["Id"] == scope["unit"]
            assert scope_before_recovery["ActiveState"] in {"active", "inactive"}
            if scope_before_recovery["ActiveState"] == "active":
                assert scope_before_recovery["InvocationID"] == scope["invocation_id"]
                assert scope_before_recovery["ControlGroup"] == scope["control_group"]
                assert scope_before_recovery["Slice"] == slice_unit
            else:
                # With the gate still closed, EOF at driver death may reap the
                # blocked runc process before fresh-supervisor reconciliation.
                assert not scope_before_recovery["ControlGroup"]
                assert scope_before_recovery["LoadState"] in {"loaded", "not-found"}
                assert scope_before_recovery["Slice"] in {"", slice_unit}

            durable_before_recovery = supervisor._sandbox_execution_get(attempt["id"])
            assert durable_before_recovery is not None
            assert durable_before_recovery["phase"] == "reserved"
            assert durable_before_recovery["launch_driver_start_id"]
            assert durable_before_recovery["launch_driver_start_digest"]
            assert durable_before_recovery["launch_submission_id"]
            assert durable_before_recovery["launch_submission_digest"]
            assert durable_before_recovery["launch_plan_binding_version"] == 0
            assert durable_before_recovery["launch_driver_start_redeemed_pid"] == driver["pid"]
            assert (
                durable_before_recovery["launch_driver_start_redeemed_invocation_id"]
                == driver["invocation_id"]
            )
            assert (
                durable_before_recovery["launch_driver_start_redeemed_identity"]
                == driver["identity"]
            )
            assert (
                durable_before_recovery["launch_driver_start_redeemed_cgroup_path"]
                == driver["control_group"]
            )
            assert durable_before_recovery["wrapper_unit"] == ""
            assert durable_before_recovery["monitor_pid"] is None
            payload_marker = Path(durable_before_recovery["workspace_root_path"])
            assert not (payload_marker / "launch-driver-started").exists()
            assert not (payload_marker / "launch-driver-marker").exists()
            assert Path(durable_before_recovery["state_path"]).is_dir()
            with supervisor.connect() as connection:
                resource_leases_before = connection.execute(
                    "SELECT resource, lease_expires_at FROM resource_leases WHERE attempt_id = ?",
                    (attempt["id"],),
                ).fetchall()
                allocation_before = connection.execute(
                    "SELECT pool_name, value, lease_expires_at FROM runtime_allocations "
                    "WHERE attempt_id = ?",
                    (attempt["id"],),
                ).fetchone()
                runtime_before = connection.execute(
                    "SELECT state FROM runtime_environments WHERE attempt_id = ?",
                    (attempt["id"],),
                ).fetchone()
            assert resource_leases_before
            assert allocation_before is not None
            assert runtime_before is not None and runtime_before["state"] != "released"

            context = multiprocessing.get_context("spawn")
            recovery_receiver, recovery_sender = context.Pipe(duplex=False)
            recovery = context.Process(
                target=_reconcile_monitor_accepted_driver_crash_from_fresh_process,
                args=(
                    repo,
                    attempt["id"],
                    attempt["claim_token"],
                    execution["execution_id"],
                    runner["credential"],
                    recovery_sender,
                ),
            )
            recovery.start()
            child_processes.append(recovery)
            recovery_sender.close()
            assert recovery_receiver.poll(30), (
                "fresh supervisor did not reconcile the exact handoff"
            )
            recovery_result = recovery_receiver.recv()
            recovery.join(timeout=10)
            assert not recovery.is_alive()
            assert recovery.exitcode == 0
            recovery_receiver.close()
            assert recovery_result[0] == "ok", recovery_result
            recovery_excluded_pids = {
                controller_pid,
                driver["pid"],
                accepted["runc_client_pid"],
            }
            if monitor is not None:
                recovery_excluded_pids.add(monitor["pid"])
            assert recovery_result[1] not in recovery_excluded_pids
            assert recovery_result[2] is False

            for unit in (service_unit, monitor_unit):
                props = _unit_properties(
                    unit, ("ActiveState", "ControlGroup", "Id", "LoadState", "MainPID")
                )
                assert props["Id"] == unit
                assert props["LoadState"] in {"loaded", "not-found"}
                assert props["ActiveState"] in {"inactive", "failed"}
                assert props["MainPID"] == "0"
                assert not props["ControlGroup"]
                if crash_before_monitor_start and unit == monitor_unit:
                    assert props["LoadState"] == "not-found"
                    assert props["ActiveState"] == "inactive"
            scope_after_recovery = _unit_properties(
                scope["unit"], ("ActiveState", "ControlGroup", "Id", "LoadState")
            )
            assert scope_after_recovery["Id"] == scope["unit"]
            assert scope_after_recovery["LoadState"] in {"loaded", "not-found"}
            assert scope_after_recovery["ActiveState"] in {"inactive", "failed"}
            assert not scope_after_recovery["ControlGroup"]
            slice_props = _unit_properties(
                slice_unit, ("ActiveState", "ControlGroup", "Id", "LoadState")
            )
            assert slice_props["Id"] == slice_unit
            assert slice_props["ActiveState"] in {"inactive", "failed"}
            assert slice_props["LoadState"] in {"loaded", "not-found"}
            assert not slice_props["ControlGroup"]
            observed_processes = [
                (driver["pid"], driver["identity"]),
                (accepted["runc_client_pid"], accepted["runc_client_identity"]),
            ]
            if monitor is not None:
                observed_processes.append((monitor["pid"], monitor["identity"]))
            for observed_pid, observed_identity in observed_processes:
                try:
                    current_identity = _linux_process_identity(observed_pid)
                except sandbox_monitor_ipc.SandboxMonitorIPCError:
                    current_identity = ""
                assert current_identity != observed_identity

            durable_after_recovery = supervisor._sandbox_execution_get(attempt["id"])
            assert durable_after_recovery is not None
            assert durable_after_recovery["phase"] == "ambiguous"
            assert (
                durable_after_recovery["launch_driver_start_id"]
                == durable_before_recovery["launch_driver_start_id"]
            )
            assert (
                durable_after_recovery["launch_driver_start_digest"]
                == (durable_before_recovery["launch_driver_start_digest"])
            )
            assert (
                durable_after_recovery["launch_submission_id"]
                == durable_before_recovery["launch_submission_id"]
            )
            assert (
                durable_after_recovery["launch_submission_digest"]
                == (durable_before_recovery["launch_submission_digest"])
            )
            assert durable_after_recovery["launch_plan_binding_version"] == 0
            assert durable_after_recovery["cleanup_verification_json"] == "{}"
            assert not (payload_marker / "launch-driver-started").exists()
            assert not (payload_marker / "launch-driver-marker").exists()
            assert Path(durable_after_recovery["state_path"]).is_dir()
            assert supervisor.attempt(attempt["id"])["termination_target_status"] == "quarantined"
            assert supervisor.task(task["id"])["cleanup_target_status"] == "blocked"
            with pytest.raises(SupervisorError) as result_rejected:
                supervisor._sandbox_execution_capture_result_candidate(
                    attempt["id"], attempt["claim_token"], credential=runner["credential"]
                )
            assert result_rejected.value.code == "claim_inactive"
            assert supervisor._sandbox_execution_get(attempt["id"])["result_candidate"] is None

            with supervisor.connect() as connection:
                leases = connection.execute(
                    "SELECT resource, lease_expires_at FROM resource_leases WHERE attempt_id = ?",
                    (attempt["id"],),
                ).fetchall()
                allocation = connection.execute(
                    "SELECT pool_name, value, lease_expires_at FROM runtime_allocations "
                    "WHERE attempt_id = ?",
                    (attempt["id"],),
                ).fetchone()
                runtime = connection.execute(
                    "SELECT state FROM runtime_environments WHERE attempt_id = ?",
                    (attempt["id"],),
                ).fetchone()
            assert leases and [row["resource"] for row in leases] == [
                row["resource"] for row in resource_leases_before
            ]
            assert all(
                row["lease_expires_at"] == journal_module.CLEANUP_FENCE_EPOCH for row in leases
            )
            assert allocation is not None and allocation_before is not None
            assert (allocation["pool_name"], allocation["value"]) == (
                allocation_before["pool_name"],
                allocation_before["value"],
            )
            assert allocation["pool_name"] == "LAUNCH_DRIVER_TEST_PORT"
            assert allocation["value"] == runtime_test_port
            assert allocation["lease_expires_at"] == journal_module.CLEANUP_FENCE_EPOCH
            assert runtime is not None and runtime["state"] == runtime_before["state"]

            start_identity_before_retry = tuple(
                durable_after_recovery[field]
                for field in (
                    "launch_driver_start_id",
                    "launch_driver_start_digest",
                    "launch_driver_start_unit",
                    "launch_driver_start_redeemed_invocation_id",
                    "launch_driver_start_redeemed_pid",
                    "launch_driver_start_redeemed_identity",
                    "launch_driver_start_redeemed_cgroup_path",
                )
            )
            retry_receiver, retry_sender = context.Pipe(duplex=False)
            retry_controller = context.Process(
                target=_retry_launch_driver_without_replay_from_fresh_process,
                args=(
                    repo,
                    identity,
                    payload_command,
                    _CONTAINER_MEMORY_BYTES,
                    _CONTAINER_CPU_QUOTA_US,
                    _CONTAINER_CPU_PERIOD_US,
                    _CONTAINER_PIDS_LIMIT,
                    sandbox_timeout_seconds,
                    runner["credential"],
                    retry_sender,
                ),
            )
            retry_controller.start()
            child_processes.append(retry_controller)
            retry_sender.close()
            assert retry_receiver.poll(20), "fresh retry did not reject the one-shot launch"
            retry_result = retry_receiver.recv()
            retry_controller.join(timeout=5)
            assert not retry_controller.is_alive()
            assert retry_controller.exitcode == 0
            retry_receiver.close()
            assert retry_result[0] == "rejected", retry_result
            assert retry_result[1] not in {
                controller_pid,
                driver["pid"],
                recovery_result[1],
            }
            assert retry_result[2] == "SandboxLaunchDriverServiceError"
            assert retry_result[3] == 0, "fresh retry reached systemd-run and could replay the unit"
            final_row = supervisor._sandbox_execution_get(attempt["id"])
            assert final_row is not None
            assert (
                tuple(
                    final_row[field]
                    for field in (
                        "launch_driver_start_id",
                        "launch_driver_start_digest",
                        "launch_driver_start_unit",
                        "launch_driver_start_redeemed_invocation_id",
                        "launch_driver_start_redeemed_pid",
                        "launch_driver_start_redeemed_identity",
                        "launch_driver_start_redeemed_cgroup_path",
                    )
                )
                == start_identity_before_retry
            )
            assert (
                final_row["launch_submission_id"] == durable_after_recovery["launch_submission_id"]
            )
            assert (
                final_row["launch_submission_digest"]
                == durable_after_recovery["launch_submission_digest"]
            )
            assert monitor_acceptance_marker.is_file()
            return
        launch_receipt_deadline = time.monotonic() + 30
        durable_before_retry = supervisor._sandbox_execution_get(attempt["id"])
        while time.monotonic() < launch_receipt_deadline and (
            durable_before_retry is None
            or durable_before_retry["phase"] == "reserved"
            or not durable_before_retry["launch_driver_invocation_id"]
            or not durable_before_retry["launch_driver_pid"]
            or (
                producer_receipt is not None
                and (
                    durable_before_retry["launch_driver_invocation_id"]
                    != producer_receipt["invocation_id"]
                    or durable_before_retry["launch_driver_pid"] != producer_receipt["driver_pid"]
                )
            )
        ):
            time.sleep(0.05)
            durable_before_retry = supervisor._sandbox_execution_get(attempt["id"])
        assert durable_before_retry is not None
        assert durable_before_retry["phase"] != "reserved"
        assert durable_before_retry["launch_driver_start_id"]
        assert durable_before_retry["launch_driver_start_digest"]
        assert durable_before_retry["launch_driver_invocation_id"]
        assert durable_before_retry["launch_driver_pid"]
        if producer_receipt is not None:
            assert (
                durable_before_retry["launch_driver_invocation_id"]
                == producer_receipt["invocation_id"]
            )
            assert durable_before_retry["launch_driver_pid"] == producer_receipt["driver_pid"]
        driver_pid = durable_before_retry["launch_driver_pid"]
        start_identity_before_retry = tuple(
            durable_before_retry[field]
            for field in (
                "launch_driver_start_id",
                "launch_driver_start_digest",
                "launch_driver_invocation_id",
                "launch_driver_pid",
                "launch_driver_identity",
                "launch_driver_cgroup_path",
            )
        )
        retry_receiver, retry_sender = context.Pipe(duplex=False)
        retry_controller = context.Process(
            target=_retry_launch_driver_without_replay_from_fresh_process,
            args=(
                repo,
                identity,
                payload_command,
                _CONTAINER_MEMORY_BYTES,
                _CONTAINER_CPU_QUOTA_US,
                _CONTAINER_CPU_PERIOD_US,
                _CONTAINER_PIDS_LIMIT,
                sandbox_timeout_seconds,
                runner["credential"],
                retry_sender,
            ),
        )
        retry_controller.start()
        child_processes.append(retry_controller)
        retry_sender.close()
        assert retry_receiver.poll(20), "fresh retry controller did not reject the duplicate start"
        retry_result = retry_receiver.recv()
        retry_controller.join(timeout=5)
        assert not retry_controller.is_alive()
        assert retry_controller.exitcode == 0
        retry_receiver.close()
        assert retry_result[0] == "rejected", retry_result
        assert retry_result[1] not in {os.getpid(), controller_pid, driver_pid}
        assert retry_result[2] == "SandboxLaunchDriverServiceError"
        assert retry_result[3] == 0, "fresh retry reached systemd-run and risked replay"
        durable_after_retry = supervisor._sandbox_execution_get(attempt["id"])
        assert durable_after_retry is not None
        assert (
            tuple(
                durable_after_retry[field]
                for field in (
                    "launch_driver_start_id",
                    "launch_driver_start_digest",
                    "launch_driver_invocation_id",
                    "launch_driver_pid",
                    "launch_driver_identity",
                    "launch_driver_cgroup_path",
                )
            )
            == start_identity_before_retry
        )
        if cancel_after_start:
            running_deadline = time.monotonic() + 30
            durable = supervisor._sandbox_execution_get(attempt["id"])
            while (
                durable is not None
                and durable["phase"] != "running"
                and time.monotonic() < running_deadline
            ):
                time.sleep(0.05)
                durable = supervisor._sandbox_execution_get(attempt["id"])
            assert durable is not None and durable["phase"] == "running"
            started_marker = Path(durable["workspace_root_path"]) / "launch-driver-started"
            started_deadline = time.monotonic() + 5
            while not _entry_is_present(started_marker) and time.monotonic() < started_deadline:
                time.sleep(0.05)
            assert _entry_is_present(started_marker), "bounded payload never entered its command"

            wrong_credential_supervisor = GitSupervisor(repo)
            with patch.object(
                sandbox_monitor_lifecycle,
                "reconnect_sandbox_monitor",
                side_effect=AssertionError("invalid runner credential reached the monitor"),
            ) as reconnect:
                with pytest.raises(SupervisorError) as rejected:
                    wrong_credential_supervisor.terminate_worker(
                        attempt["id"], credential="not-the-enrolled-runner-credential"
                    )
                assert rejected.value.code == "runner_authentication_failed"
                reconnect.assert_not_called()

            result_receiver, result_sender = context.Pipe(duplex=False)
            fresh_controller = context.Process(
                target=_terminate_worker_from_fresh_process,
                args=(repo, attempt["id"], runner["credential"], result_sender),
            )
            fresh_controller.start()
            child_processes.append(fresh_controller)
            result_sender.close()
            assert result_receiver.poll(20), "fresh controller did not receive a monitor response"
            termination_result = result_receiver.recv()
            fresh_controller.join(timeout=5)
            assert not fresh_controller.is_alive()
            assert fresh_controller.exitcode == 0
            result_receiver.close()
            assert termination_result[0] == "ok", termination_result
            assert termination_result[1] not in {driver_pid, controller_pid}
            termination = termination_result[2]
            assert termination_result[3:] == (1, 0)
            assert termination["attempt_id"] == attempt["id"]
            assert termination["execution_id"] == execution["execution_id"]
            assert termination["stop_requested"] is True
            assert termination["cleanup_verified"] is False
            assert termination["monitor_phase"] in {"stopping", "exited"}

        deadline = time.monotonic() + 30
        durable = supervisor._sandbox_execution_get(attempt["id"])
        while (
            durable is not None
            and durable["phase"] != "cleanup_reported"
            and time.monotonic() < deadline
        ):
            time.sleep(0.05)
            durable = supervisor._sandbox_execution_get(attempt["id"])
        service_log = service_log_path.read_text(encoding="utf-8", errors="replace")
        assert runner["credential"] not in service_log
        assert durable is not None and durable["phase"] == "cleanup_reported", service_log
        if not cancel_after_start and not timeout_after_start:
            assert durable["runc_exit_code"] == 0
        else:
            assert type(durable["runc_exit_code"]) is int
            assert durable["runc_exit_code"] != 0
        assert durable["launch_driver_pid"] == driver_pid
        assert (
            durable["launch_driver_invocation_id"]
            == durable_before_retry["launch_driver_invocation_id"]
        )
        assert durable["launch_driver_identity"] == durable_before_retry["launch_driver_identity"]
        assert (
            durable["launch_driver_cgroup_path"]
            == durable_before_retry["launch_driver_cgroup_path"]
        )
        assert durable["launch_driver_cgroup_path"] == (
            f"{durable['attempt_slice_cgroup_path']}/{service_unit}"
        )
        if producer_receipt is not None:
            assert producer_receipt["service_unit"] == service_unit
            assert producer_receipt["driver_pid"] == durable["launch_driver_pid"]
            assert producer_receipt["driver_identity"] == durable["launch_driver_identity"]
            assert producer_receipt["invocation_id"] == durable["launch_driver_invocation_id"]
            assert producer_receipt["control_group"] == durable["launch_driver_cgroup_path"]
        assert durable["wrapper_cgroup_path"] != durable["attempt_slice_cgroup_path"]
        assert not Path(durable["wrapper_cgroup_path"]).is_relative_to(
            Path(durable["attempt_slice_cgroup_path"])
        )
        assert (
            Path(durable["cgroup_path"]).parent.as_posix() == durable["attempt_slice_cgroup_path"]
        )
        marker = Path(durable["workspace_root_path"]) / "launch-driver-marker"
        if cancel_after_start or timeout_after_start:
            assert _entry_is_present(Path(durable["workspace_root_path"]) / "launch-driver-started")
            assert not _entry_is_present(marker)
        else:
            assert marker.read_text(encoding="ascii") == "production-driver-ran\n"
        assert not _entry_is_present(source_worktree / "launch-driver-marker")
        with supervisor.connect() as connection:
            events = connection.execute(
                "SELECT sequence, event_type FROM events "
                "WHERE json_extract(payload_json, '$.execution_id') = ? "
                "AND event_type IN (?, ?, ?, ?, ?, ?) ORDER BY sequence",
                (
                    execution["execution_id"],
                    "sandbox.execution_launch_submission_authorized",
                    "sandbox.execution_launched",
                    "sandbox.execution_running",
                    "sandbox.execution_stop_requested",
                    "sandbox.execution_exited",
                    "sandbox.execution_cleanup_reported",
                ),
            ).fetchall()
        expected_events = [
            "sandbox.execution_launch_submission_authorized",
            "sandbox.execution_launched",
            "sandbox.execution_running",
        ]
        if cancel_after_start or timeout_after_start:
            expected_events.append("sandbox.execution_stop_requested")
        expected_events.extend(["sandbox.execution_exited", "sandbox.execution_cleanup_reported"])
        assert [row["event_type"] for row in events] == expected_events
        assert len({row["sequence"] for row in events}) == len(expected_events)
        with supervisor.connect() as connection:
            event_bodies = "\n".join(
                row[0]
                for row in connection.execute(
                    "SELECT payload_json FROM events "
                    "WHERE json_extract(payload_json, '$.attempt_id') = ?",
                    (attempt["id"],),
                )
            )
        assert runner["credential"] not in event_bodies
        assert runner["credential"].encode("utf-8") not in Path(supervisor.db_path).read_bytes()
        assert not (Path(execution["state_path"]) / "launch-driver-request.json").exists()
        assert durable["phase"] == "cleanup_reported"
        assert durable["cleanup_receipt"]["version"] == 3
        assert durable["cleanup_receipt"]["verification_status"] == "unverified"
        action = durable["cleanup_receipt"]["action"]
        assert action["operation"] == "runc-delete-force"
        assert action["argv"] == [
            str(runc_pin.path),
            "--root",
            str(state_root),
            "delete",
            "--force",
            execution["container_id"],
        ]
        assert action["actor"]["pid"] == durable["launch_driver_pid"]
        assert action["actor"]["identity"] == durable["launch_driver_identity"]
        assert action["returncode"] == 0
        assert action["state_entry_absent_immediately_after_delete"] is True
        assert not (state_root / execution["container_id"]).exists()

        imported_submission = None
        if import_result_after_cleanup:
            verified_before_import = supervisor._sandbox_execution_verify_cleanup(
                attempt["id"],
                attempt["claim_token"],
                credential=runner["credential"],
            )
            assert verified_before_import["phase"] == "cleanup_verified"
            assert verified_before_import["runc_exit_code"] == 0
            assert verified_before_import["cleanup_verification"]["observations"]
            assert not _entry_is_present(
                Path(verified_before_import["workspace_root_path"]) / ".git"
            )

            imported_submission = supervisor.import_sandbox_execution_result(
                attempt["id"], attempt["claim_token"], credential=runner["credential"]
            )
            assert imported_submission["status"] == "pending_qc"
            assert imported_submission["commit_sha"]
            assert supervisor.attempt(attempt["id"])["status"] == "submitted"
            assert supervisor.task(task["id"])["status"] == "qc_review"

            def git_text(*arguments: str) -> str:
                completed = subprocess.run(
                    ["git", "-C", str(repo), *arguments],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                return completed.stdout.strip()

            assert git_text("rev-parse", "HEAD") == task["base_sha"]
            assert (
                git_text("rev-parse", f"{imported_submission['commit_sha']}^") == task["base_sha"]
            )
            assert (
                git_text("show", f"{imported_submission['commit_sha']}:launch-driver-started")
                == "production-driver-started"
            )
            assert (
                git_text("show", f"{imported_submission['commit_sha']}:launch-driver-marker")
                == "production-driver-ran"
            )
            assert (
                subprocess.run(
                    ["git", "-C", str(source_worktree), "status", "--porcelain=v1"],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                ).stdout
                == ""
            )

            with supervisor.connect() as connection:
                imported_row = connection.execute(
                    "SELECT * FROM result_imports WHERE attempt_id = ?",
                    (attempt["id"],),
                ).fetchone()
                import_source = supervisor._sandbox_execution_result_import_source(
                    connection, attempt["id"], attempt["claim_token"]
                )
            assert imported_row is not None
            assert imported_row["phase"] == "submitted"
            assert imported_row["source_kind"] == "sandbox_execution"
            assert imported_row["sandbox_execution_id"] == execution["execution_id"]
            assert (
                imported_row["sandbox_cleanup_receipt_digest"]
                == import_source["cleanup_receipt_digest"]
            )
            assert imported_row["worker_pid"] is None
            assert imported_row["worker_identity"] == ""
            assert imported_row["worker_exit_receipt_json"] == ""

        with supervisor.connect() as connection:
            lease_before_rows = connection.execute(
                "SELECT resource, task_id, attempt_id, lease_expires_at "
                "FROM resource_leases WHERE task_id = ? ORDER BY resource",
                (task["id"],),
            ).fetchall()
            runtime_before = connection.execute(
                "SELECT state FROM runtime_environments WHERE attempt_id = ?",
                (attempt["id"],),
            ).fetchone()
            allocations_before = connection.execute(
                "SELECT pool_name, value, lease_expires_at FROM runtime_allocations "
                "WHERE attempt_id = ?",
                (attempt["id"],),
            ).fetchall()
        lease_before = {row["resource"]: row for row in lease_before_rows}
        assert set(lease_before) == set(task["resources"])
        assert len(lease_before) == 2
        assert len({row["lease_expires_at"] for row in lease_before.values()}) == 1
        expected_lease_expiry = next(iter(lease_before.values()))["lease_expires_at"]
        if imported_submission is None:
            for lease in lease_before.values():
                assert lease["task_id"] == task["id"]
                assert lease["attempt_id"] == attempt["id"]
                assert lease["lease_expires_at"] == attempt["lease_expires_at"]
        else:
            for lease in lease_before.values():
                assert lease["task_id"] == task["id"]
                assert lease["attempt_id"] is None
                assert lease["lease_expires_at"] > attempt["lease_expires_at"]
        assert len(allocations_before) == 1
        assert runtime_before is not None and runtime_before["state"] != "released"
        assert [
            (row["pool_name"], row["value"], row["lease_expires_at"]) for row in allocations_before
        ] == [("LAUNCH_DRIVER_TEST_PORT", runtime_test_port, expected_lease_expiry)]

        reap_receiver, reap_sender = context.Pipe(duplex=False)
        import_probe = (
            (task["id"], attempt["id"], imported_submission["id"])
            if imported_submission is not None
            else None
        )
        fresh_reaper = context.Process(
            target=_reap_expired_from_fresh_process,
            args=(repo, attempt["lease_expires_at"] + 1, reap_sender, import_probe),
        )
        fresh_reaper.start()
        child_processes.append(fresh_reaper)
        reap_sender.close()
        assert reap_receiver.poll(30), "fresh supervisor did not finish the real reaper"
        reap_result = reap_receiver.recv()
        fresh_reaper.join(timeout=5)
        assert not fresh_reaper.is_alive()
        assert fresh_reaper.exitcode == 0
        reap_receiver.close()
        assert reap_result[0] == "ok", reap_result
        assert reap_result[1] not in {controller_pid, driver_pid}
        reaped = reap_result[2]
        if imported_submission is None:
            assert reaped["orphaned"] == [task["id"]]
            assert reaped["runtime_cleanup"] == [{"attempt_id": attempt["id"], "state": "released"}]
            assert supervisor.attempt(attempt["id"])["status"] == "orphaned"
            assert supervisor.task(task["id"])["status"] == "orphaned"
        else:
            assert reaped["orphaned"] == []
            assert reaped["runtime_cleanup"] == []
            assert supervisor.attempt(attempt["id"])["status"] == "submitted"
            assert supervisor.task(task["id"])["status"] == "qc_review"
            recovered_before, recovered_after = reap_result[3:5]
            assert recovered_before == recovered_after
            assert recovered_before == {
                "task_status": "qc_review",
                "attempt_status": "submitted",
                "submission_id": imported_submission["id"],
                "submission_status": "pending_qc",
                "submission_commit_sha": imported_submission["commit_sha"],
                "task_latest_submission_id": imported_submission["id"],
                "execution_id": execution["execution_id"],
                "execution_phase": "cleanup_verified",
            }
        with supervisor.connect() as connection:
            lease_resources = sorted(lease_before)
            placeholders = ", ".join("?" for _ in lease_resources)
            lease_after_rows = connection.execute(
                "SELECT resource, task_id, attempt_id, lease_expires_at FROM resource_leases "
                f"WHERE resource IN ({placeholders}) ORDER BY resource",
                lease_resources,
            ).fetchall()
            runtime_after = connection.execute(
                "SELECT state FROM runtime_environments WHERE attempt_id = ?",
                (attempt["id"],),
            ).fetchone()
            allocations_after = connection.execute(
                "SELECT pool_name, value FROM runtime_allocations WHERE attempt_id = ?",
                (attempt["id"],),
            ).fetchall()
        lease_after = {row["resource"]: row for row in lease_after_rows}
        assert set(lease_after) == set(lease_before)
        assert runtime_after is not None
        if imported_submission is None:
            for resource, lease in lease_after.items():
                assert lease["task_id"] is None
                assert lease["attempt_id"] is None
                assert lease["lease_expires_at"] == 0
                assert lease_before[resource]["task_id"] == task["id"]
            assert runtime_after["state"] == "released"
            assert allocations_after == []
        else:
            for resource, lease in lease_after.items():
                assert lease["task_id"] == task["id"]
                assert lease["attempt_id"] is None
                assert lease["lease_expires_at"] == lease_before[resource]["lease_expires_at"]
            assert runtime_after["state"] == runtime_before["state"]
            assert [(row["pool_name"], row["value"]) for row in allocations_after] == [
                ("LAUNCH_DRIVER_TEST_PORT", runtime_test_port)
            ]
            qc_reap_receiver, qc_reap_sender = context.Pipe(duplex=False)
            fresh_qc_reaper = context.Process(
                target=_reap_expired_from_fresh_process,
                args=(repo, expected_lease_expiry + 1, qc_reap_sender, import_probe),
            )
            fresh_qc_reaper.start()
            child_processes.append(fresh_qc_reaper)
            qc_reap_sender.close()
            assert qc_reap_receiver.poll(30), "fresh supervisor did not expire the QC reservation"
            qc_reap_result = qc_reap_receiver.recv()
            fresh_qc_reaper.join(timeout=5)
            assert not fresh_qc_reaper.is_alive()
            assert fresh_qc_reaper.exitcode == 0
            qc_reap_receiver.close()
            assert qc_reap_result[0] == "ok", qc_reap_result
            assert qc_reap_result[1] not in {controller_pid, driver_pid}
            qc_reaped = qc_reap_result[2]
            assert qc_reaped["conflicted"] == [task["id"]]
            assert qc_reaped["orphaned"] == []
            assert {
                tuple(sorted(item.items()))
                for item in qc_reaped["runtime_cleanup"]
                if item.get("task_id") == task["id"]
            } == {
                tuple(
                    sorted(
                        {
                            "task_id": task["id"],
                            "attempt_id": attempt["id"],
                            "state": "released",
                        }.items()
                    )
                )
            }
            recovered_before_expiry, recovered_after_expiry = qc_reap_result[3:5]
            assert recovered_before_expiry == recovered_after
            assert recovered_after_expiry == {
                "task_status": "conflicted",
                "attempt_status": "submitted",
                "submission_id": imported_submission["id"],
                "submission_status": "pending_qc",
                "submission_commit_sha": imported_submission["commit_sha"],
                "task_latest_submission_id": imported_submission["id"],
                "execution_id": execution["execution_id"],
                "execution_phase": "cleanup_verified",
            }
            assert supervisor.task(task["id"])["status"] == "conflicted"
            assert supervisor.attempt(attempt["id"])["status"] == "submitted"
            assert supervisor.submission(imported_submission["id"])["status"] == "pending_qc"
            with supervisor.connect() as connection:
                final_lease_rows = connection.execute(
                    "SELECT resource, task_id, attempt_id, lease_expires_at FROM resource_leases "
                    f"WHERE resource IN ({placeholders}) ORDER BY resource",
                    lease_resources,
                ).fetchall()
                final_runtime = connection.execute(
                    "SELECT state FROM runtime_environments WHERE attempt_id = ?",
                    (attempt["id"],),
                ).fetchone()
                final_allocations = connection.execute(
                    "SELECT pool_name, value FROM runtime_allocations WHERE attempt_id = ?",
                    (attempt["id"],),
                ).fetchall()
            assert {row["resource"] for row in final_lease_rows} == set(lease_before)
            assert all(
                row["task_id"] is None
                and row["attempt_id"] is None
                and row["lease_expires_at"] == 0
                for row in final_lease_rows
            )
            assert final_runtime is not None and final_runtime["state"] == "released"
            assert final_allocations == []
        verified = supervisor._sandbox_execution_get(attempt["id"])
        assert verified is not None
        assert verified["phase"] == "cleanup_verified"
        if cancel_after_start or timeout_after_start:
            assert verified["runc_exit_code"] != 0
            if timeout_after_start:
                assert verified["stop_reason"] == "execution_timeout"
            with supervisor.connect() as connection:
                with pytest.raises(SupervisorError) as result_rejected:
                    journal_module._require_sandbox_execution_result_eligible(
                        connection, attempt["id"]
                    )
            assert result_rejected.value.code == "sandbox_result_unverified"
        observations = verified["cleanup_verification"]["observations"]
        assert all(item["absent"] for item in observations["processes"].values())
        assert all(observations["cgroups"].values())
        assert observations["paths"]["runc_state_entry_absent"] is True
        assert observations["paths"]["monitor_socket"]["absent"] is True
        assert not Path(durable["bundle_path"]).exists()
        assert not state_root.exists()
    finally:
        for child in child_processes:
            child.join(timeout=30)
        live_children = [child.pid for child in child_processes if child.is_alive()]
        if live_children:
            pytest.fail(
                "controller child processes are not quiescent; preserving the exact "
                f"fixture and service state at {run_root}; pids={live_children}"
            )
        driver_safe = _stop_attempted_units_and_check_quiescence(
            systemctl, service_unit, service_start_attempted, slice_unit, slice_start_attempted
        )
        monitor_safe = False
        if driver_safe:
            monitor_safe = _stop_attempted_units_and_check_quiescence(
                systemctl, monitor_unit, monitor_start_attempted, None, False
            )
        safe_to_remove = driver_safe and monitor_safe
        if safe_to_remove:
            _remove_private_test_tree(run_root)
        else:
            pytest.fail(
                "exact production-driver test units are not quiescent; preserving "
                f"artifacts at {run_root}"
            )


if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "--monitor-child":
    _monitor_child_entry(sys.argv[2:])
