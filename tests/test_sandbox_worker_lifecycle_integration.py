"""Opt-in live proof joining the OCI launch gate, monitor, and journal.

The process-local runc handle must remain in the exact systemd launch-driver
process; a separate systemd-owned service controls the exact worker scope. The
release case proves the launch-to-``running`` gate, while the terminate case
requests cancellation through ``WorkersMixin.terminate_worker()`` before gate
release and checks the real monitor response. Neither case wires
``run_worker``, proves crash recovery or cleanup, authorizes result import, or
writes a ``cleanup_verified`` receipt.

Run on a disposable supported Linux host with rootless runc 1.5.2, delegated
cgroup v2, and an active private systemd user manager:

    ACP_RUN_SANDBOX_WORKER_LIFECYCLE=1 \
    ACP_OCI_TEST_RUNC=/usr/bin/runc \
    ACP_OCI_TEST_RUNC_VERSION=1.5.2 \
    uv run --extra dev pytest -q tests/test_sandbox_worker_lifecycle_integration.py
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path, PurePosixPath
from typing import Any

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
from agent_control_plane.supervisor import sandbox_attestation, sandbox_monitor_service
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
    return _wait_for_quiescence(
        service_unit if service_start_attempted else None,
        slice_unit if slice_start_attempted else None,
    )


def test_attempted_systemd_starts_are_stopped_and_checked_after_client_timeouts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stop_requests: list[str] = []
    checked_units: list[tuple[str | None, str | None]] = []

    def timed_out_stop(argv: list[str], timeout: float = 10.0) -> None:
        stop_requests.append(argv[-1])
        raise subprocess.TimeoutExpired(argv, timeout)

    def quiescent(service: str | None, slice_: str | None) -> bool:
        checked_units.append((service, slice_))
        return True

    monkeypatch.setattr(sys.modules[__name__], "_systemd_command", timed_out_stop)
    monkeypatch.setattr(sys.modules[__name__], "_wait_for_quiescence", quiescent)
    assert _stop_attempted_units_and_check_quiescence(
        "/usr/bin/systemctl",
        "acp-test.service",
        True,
        "acp-test.slice",
        True,
    )
    assert stop_requests == ["acp-test.service", "acp-test.slice"]
    assert checked_units == [("acp-test.service", "acp-test.slice")]


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
        or not root.name.startswith("acp-live-sandbox-lifecycle-")
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


@pytest.mark.skipif(
    not _LIVE_ENABLED,
    reason="set ACP_RUN_SANDBOX_WORKER_LIFECYCLE=1 on a disposable supported Linux host",
)
@pytest.mark.parametrize("terminate_before_gate", [False, True], ids=["release", "terminate"])
def test_live_monitor_journal_holds_payload_until_durable_running_transition(
    terminate_before_gate: bool,
) -> None:
    """Exercise actual runc, systemd identities, journal transitions, and fd-3 gate/cancel."""

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


if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "--monitor-child":
    _monitor_child_entry(sys.argv[2:])
