"""Opt-in proof for systemd-owned service receipt recovery and attempt-slice teardown.

Run with ``ACP_RUN_SYSTEMD_SLICE_INTEGRATION=1`` on a disposable Linux host
with an active user systemd manager and cgroup v2. It verifies receipt-based
service identity reconciliation after controller-process exit and unit/cgroup
teardown only; it does not integrate or attest the supervised OCI worker
lifecycle.
"""

from __future__ import annotations

import json
import os
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

from agent_control_plane.supervisor.common import SupervisorError
from agent_control_plane.supervisor.oci_worker import _oci_worker_systemd_slice
from agent_control_plane.supervisor.process import ProcessMixin
from agent_control_plane.supervisor.sandbox_attestation import (
    _parse_proc_stat,
    read_linux_process_snapshot,
    validate_running_runtime_attestation,
    verify_running_runtime_systemd_units,
)
from agent_control_plane.supervisor.sandbox_monitor_receipt import (
    SandboxMonitorReceipt,
    read_sandbox_monitor_receipt,
    sandbox_attempt_slice_unit,
    sandbox_container_id,
    sandbox_monitor_service_unit,
    validate_monitor_service_reconciliation,
    write_sandbox_monitor_receipt,
)

_ENABLED = os.environ.get("ACP_RUN_SYSTEMD_SLICE_INTEGRATION") == "1"
_WAIT_SECONDS = 8.0


def _environment() -> dict[str, str]:
    environment = {
        "LC_ALL": "C",
        "LANG": "C",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
    }
    for name in ("HOME", "USER", "LOGNAME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _run(
    argv: list[str], *, timeout: float = 8.0, accepted_returncodes: tuple[int, ...] = (0,)
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=_environment(),
    )
    if result.returncode not in accepted_returncodes:
        raise RuntimeError(f"{argv[0]} failed with {result.returncode}: {result.stderr.strip()}")
    return result


def _unit_properties(systemctl: str, unit: str) -> dict[str, str]:
    result = _run(
        [
            systemctl,
            "--user",
            "show",
            unit,
            "--no-pager",
            "--property=Id",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=InvocationID",
            "--property=ControlGroup",
            "--property=Slice",
            "--property=MainPID",
        ]
    )
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def _write_monitor_receipt(path: Path, receipt: dict[str, Any]) -> None:
    """Use the production codec for the test controller's durable receipt."""

    write_sandbox_monitor_receipt(path, SandboxMonitorReceipt.from_dict(receipt))


def _read_monitor_receipt(path: Path) -> dict[str, Any]:
    return read_sandbox_monitor_receipt(path).as_dict()


def _start_monitor_controller(
    systemd_run: str,
    systemctl: str,
    service_unit: str,
    monitor_slice_unit: str,
    slice_unit: str,
    receipt_path: Path,
    attempt_id: str,
    claim_token: int,
    execution_id: str,
) -> None:
    """Start the trusted monitor outside the worker slice and fsync its receipt."""

    _run(
        [
            systemd_run,
            "--user",
            f"--unit={service_unit}",
            f"--slice={monitor_slice_unit}",
            "--property=Type=exec",
            "--property=KillMode=control-group",
            "--property=RuntimeMaxSec=45s",
            "/usr/bin/sleep",
            "45",
        ]
    )
    service = _wait_active(systemctl, service_unit)
    monitor_slice = _wait_active(systemctl, monitor_slice_unit)
    _run([systemctl, "--user", "start", slice_unit])
    attempt_slice = _wait_active(systemctl, slice_unit)
    if (
        service.get("Id") != service_unit
        or service.get("Slice") != monitor_slice_unit
        or service.get("LoadState") != "loaded"
        or not service.get("InvocationID")
        or not service.get("ControlGroup")
        or not monitor_slice.get("ControlGroup")
        or not attempt_slice.get("ControlGroup")
        or PurePosixPath(service["ControlGroup"]).parent.as_posix() != monitor_slice["ControlGroup"]
        or PurePosixPath(service["ControlGroup"]).is_relative_to(
            PurePosixPath(attempt_slice["ControlGroup"])
        )
    ):
        raise RuntimeError(f"systemd monitor identity is incomplete: {service}")
    main_pid = int(service.get("MainPID", "0"))
    main_identity = ProcessMixin._process_identity(main_pid)
    receipt = {
        "version": 1,
        "controller_pid": os.getpid(),
        "attempt_id": attempt_id,
        "claim_token": claim_token,
        "execution_id": execution_id,
        "unit": service_unit,
        "invocation_id": service["InvocationID"],
        "control_group": service["ControlGroup"],
        "main_pid": main_pid,
        "main_identity": main_identity,
        "monitor_slice_unit": monitor_slice_unit,
        "monitor_slice_control_group": monitor_slice["ControlGroup"],
        "attempt_slice_unit": slice_unit,
        "attempt_slice_control_group": attempt_slice["ControlGroup"],
    }
    if main_pid <= 0 or main_pid == os.getpid() or main_identity is None:
        raise RuntimeError(
            "systemd monitor MainPID lacks a distinct, readable process start identity"
        )
    _write_monitor_receipt(receipt_path, receipt)
    # The parent kills this controller after the durable receipt is visible.
    # The transient service must remain owned by systemd, not this process.
    print("receipt-durable", flush=True)
    time.sleep(60)


def _reconcile_monitor_after_restart(systemctl: str, receipt_path: Path) -> dict[str, Any]:
    """Fresh-controller subprocess: adopt only the exact recorded unit activation."""

    receipt = read_sandbox_monitor_receipt(receipt_path)
    service = _unit_properties(systemctl, receipt.unit)
    monitor_slice = _unit_properties(systemctl, receipt.monitor_slice_unit)
    attempt_slice = _unit_properties(systemctl, receipt.attempt_slice_unit)
    validate_monitor_service_reconciliation(
        receipt,
        service,
        monitor_slice,
        attempt_slice,
        observed_main_identity=ProcessMixin._process_identity(receipt.main_pid),
        reconciler_pid=os.getpid(),
    )
    return {
        "receipt": receipt.as_dict(),
        "service": service,
        "monitor_slice": monitor_slice,
        "slice": attempt_slice,
    }


def _crash_controller_and_reconcile(
    systemd_run: str,
    systemctl: str,
    service_unit: str,
    monitor_slice_unit: str,
    slice_unit: str,
    receipt_path: Path,
    attempt_id: str,
    claim_token: int,
    execution_id: str,
) -> dict[str, Any]:
    controller = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--monitor-controller",
            systemd_run,
            systemctl,
            service_unit,
            monitor_slice_unit,
            slice_unit,
            str(receipt_path),
            attempt_id,
            str(claim_token),
            execution_id,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
        env=_environment(),
    )
    deadline = time.monotonic() + _WAIT_SECONDS * 2
    try:
        while not receipt_path.exists():
            if controller.poll() is not None:
                _, stderr = controller.communicate()
                raise RuntimeError(
                    f"old monitor controller exited {controller.returncode} before receipt: "
                    f"{stderr.strip()}"
                )
            if time.monotonic() >= deadline:
                raise RuntimeError("old monitor controller did not persist its receipt in time")
            time.sleep(0.05)
        receipt = _read_monitor_receipt(receipt_path)
        if receipt["controller_pid"] != controller.pid:
            raise RuntimeError(
                "durable receipt controller PID does not identify the process being killed"
            )
        if controller.stdout is None:
            raise RuntimeError("old controller has no receipt-durability acknowledgment pipe")
        with selectors.DefaultSelector() as selector:
            selector.register(controller.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=_WAIT_SECONDS):
                raise RuntimeError("old controller did not acknowledge receipt directory fsync")
            if controller.stdout.readline().strip() != "receipt-durable":
                raise RuntimeError("old controller exited before acknowledging receipt durability")
        controller.send_signal(signal.SIGKILL)
        stdout, stderr = controller.communicate(timeout=_WAIT_SECONDS)
        if controller.returncode != -signal.SIGKILL:
            raise RuntimeError(
                f"old controller did not die abruptly: rc={controller.returncode}; "
                f"stdout={stdout.strip()}; stderr={stderr.strip()}"
            )
    finally:
        if controller.poll() is None:
            controller.kill()
            controller.communicate(timeout=_WAIT_SECONDS)

    reconciler = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--reconcile-monitor",
            systemctl,
            str(receipt_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=_WAIT_SECONDS,
        env=_environment(),
    )
    if reconciler.returncode != 0:
        raise RuntimeError(f"fresh monitor reconciler failed: {reconciler.stderr.strip()}")
    evidence = json.loads(reconciler.stdout)
    if evidence.get("receipt") != receipt:
        raise RuntimeError("fresh reconciler did not consume the exact durable receipt")
    return evidence


def _wait_active(systemctl: str, unit: str, client: subprocess.Popen[str] | None = None):
    deadline = time.monotonic() + _WAIT_SECONDS
    last: dict[str, str] = {}
    while time.monotonic() < deadline:
        last = _unit_properties(systemctl, unit)
        if last.get("ActiveState") == "active" and last.get("ControlGroup"):
            return last
        if client is not None and client.poll() is not None:
            detail = client.stderr.read() if client.stderr is not None else ""
            raise RuntimeError(
                f"systemd-run scope client exited {client.returncode}: {detail.strip()}"
            )
        time.sleep(0.05)
    raise RuntimeError(f"unit did not become active: {unit}: {last}")


def _wait_inactive(systemctl: str, unit: str) -> dict[str, str]:
    deadline = time.monotonic() + _WAIT_SECONDS
    last: dict[str, str] = {}
    while time.monotonic() < deadline:
        last = _unit_properties(systemctl, unit)
        if last.get("ActiveState") not in {"active", "activating", "deactivating"}:
            return last
        time.sleep(0.05)
    raise RuntimeError(f"unit remained active after its slice was stopped: {unit}: {last}")


def _wait_cgroup_pids(control_group: str, *, count: int) -> set[int]:
    path = Path("/sys/fs/cgroup") / control_group.lstrip("/") / "cgroup.procs"
    deadline = time.monotonic() + _WAIT_SECONDS
    while time.monotonic() < deadline:
        try:
            pids = {int(value) for value in path.read_text(encoding="ascii").split()}
        except (OSError, ValueError):
            pids = set()
        if len(pids) >= count:
            return pids
        time.sleep(0.05)
    raise RuntimeError(f"cgroup did not contain {count} process(es): {control_group}")


def _attestation_unit_bytes(properties: dict[str, str], *, include_main_pid: bool) -> bytes:
    names = ("ActiveState", "ControlGroup", "Id", "InvocationID")
    if include_main_pid:
        names += ("MainPID",)
    try:
        return "".join(f"{name}={properties[name]}\n" for name in names).encode("ascii")
    except (KeyError, UnicodeEncodeError) as error:
        raise RuntimeError("live systemd unit properties are incomplete or non-ASCII") from error


def _attestation_for_live_units(
    *,
    container_id: str,
    wrapper_unit: str,
    wrapper: dict[str, str],
    attempt_slice_unit: str,
    attempt_slice: dict[str, str],
    scope_unit: str,
    scope: dict[str, str],
    bundle_path: str,
):
    """Build a self-consistent test receipt from live unit/process identities.

    Resource-control bytes and runc state below are fixture values: this probe
    tests the systemctl identity recheck, not a real runc launch or cgroup limit.
    """

    monitor_pid = int(wrapper["MainPID"])
    wrapper_cgroup = wrapper["ControlGroup"]
    worker_pids = _wait_cgroup_pids(wrapper_cgroup, count=2)
    runc_client_pid = next(pid for pid in worker_pids if pid != monitor_pid)
    init_pids = _wait_cgroup_pids(scope["ControlGroup"], count=1)
    init_pid = next(iter(init_pids))
    pids = (monitor_pid, runc_client_pid, init_pid)
    snapshots = {pid: read_linux_process_snapshot(pid) for pid in pids}
    identities = {
        pid: f"linux:{pid}:{_parse_proc_stat(snapshot.stat_before)[2]}"
        for pid, snapshot in snapshots.items()
    }
    memory_max_bytes = 1_073_741_824
    cpu_quota = 100_000
    cpu_period = 100_000
    pids_max = 256
    return validate_running_runtime_attestation(
        runc_state=json.dumps(
            {"id": container_id, "status": "running", "pid": init_pid, "bundle": bundle_path},
            separators=(",", ":"),
        ).encode("ascii"),
        pid_file=f"{init_pid}\n".encode("ascii"),
        process_snapshots=snapshots,
        wrapper_properties=_attestation_unit_bytes(wrapper, include_main_pid=True),
        attempt_slice_properties=_attestation_unit_bytes(attempt_slice, include_main_pid=False),
        scope_properties=_attestation_unit_bytes(scope, include_main_pid=False),
        expected_container_id=container_id,
        expected_bundle_path=bundle_path,
        expected_monitor_pid=monitor_pid,
        expected_monitor_identity=identities[monitor_pid],
        expected_runc_client_pid=runc_client_pid,
        expected_runc_client_identity=identities[runc_client_pid],
        expected_wrapper_unit=wrapper_unit,
        expected_wrapper_invocation_id=wrapper["InvocationID"],
        expected_attempt_slice_unit=attempt_slice_unit,
        expected_attempt_slice_invocation_id=attempt_slice["InvocationID"],
        expected_scope_unit=scope_unit,
        expected_scope_invocation_id=scope["InvocationID"],
        expected_cgroup_path=scope["ControlGroup"],
        resource_control_files={
            "memory.max": f"{memory_max_bytes}\n".encode("ascii"),
            "cpu.max": f"{cpu_quota} {cpu_period}\n".encode("ascii"),
            "pids.max": f"{pids_max}\n".encode("ascii"),
        },
        expected_memory_max_bytes=memory_max_bytes,
        expected_cpu_quota=cpu_quota,
        expected_cpu_period=cpu_period,
        expected_pids_max=pids_max,
    )


def _cgroup_is_empty(control_group: str) -> bool:
    if not control_group:
        return True
    if not control_group.startswith("/") or ".." in Path(control_group).parts:
        raise AssertionError(f"systemd returned a non-canonical ControlGroup: {control_group!r}")
    path = Path("/sys/fs/cgroup") / control_group.lstrip("/")
    if not path.exists():
        return True
    events = path.joinpath("cgroup.events")
    processes = path.joinpath("cgroup.procs")
    if not events.is_file() or not processes.is_file():
        return False
    return (
        "populated 0" in events.read_text(encoding="ascii")
        and not processes.read_text(encoding="ascii").strip()
    )


def _probe(receipt_directory: Path) -> dict[str, Any]:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("the opt-in systemd slice test requires Linux")
    if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        raise RuntimeError("the opt-in systemd slice test requires cgroup v2")
    systemd_run = shutil.which("systemd-run", path=_environment()["PATH"])
    systemctl = shutil.which("systemctl", path=_environment()["PATH"])
    if systemd_run is None or systemctl is None:
        raise RuntimeError("systemd-run and systemctl are required")

    manager_state = _run(
        [systemctl, "--user", "is-system-running"], accepted_returncodes=(0, 1)
    ).stdout.strip()
    if manager_state not in {"running", "degraded"}:
        raise RuntimeError(f"user systemd manager is not available: {manager_state!r}")

    token = uuid.uuid4().hex
    attempt_id = f"probe-{token[:16]}"
    claim_token = 1
    execution_id = token
    container_id = sandbox_container_id(attempt_id, claim_token, execution_id)
    slice_unit = sandbox_attempt_slice_unit(attempt_id, claim_token, execution_id)
    if slice_unit != _oci_worker_systemd_slice(container_id):
        raise AssertionError("monitor receipt and runc derive different attempt slices")
    # Per-attempt slice names are `user-acp-<digest>.slice`, which systemd
    # nests beneath this shared parent. Keep the durable monitor service in
    # that same parent but outside the attempt slice so worker-slice teardown
    # cannot stop its owner.
    monitor_slice_unit = "user-acp.slice"
    service_unit = sandbox_monitor_service_unit(attempt_id, claim_token, execution_id)
    scope_unit = f"acp-scope-probe-{token}.scope"
    scope_client: subprocess.Popen[str] | None = None
    pre_stop: dict[str, dict[str, str]] = {}
    post_stop: dict[str, dict[str, str]] = {}
    receipt_path = receipt_directory / "monitor-receipt.json"
    try:
        monitor_reconciliation = _crash_controller_and_reconcile(
            systemd_run,
            systemctl,
            service_unit,
            monitor_slice_unit,
            slice_unit,
            receipt_path,
            attempt_id,
            claim_token,
            execution_id,
        )
        monitor_receipt = monitor_reconciliation["receipt"]
        pre_stop[slice_unit] = _wait_active(systemctl, slice_unit)
        pre_stop[monitor_slice_unit] = _unit_properties(systemctl, monitor_slice_unit)
        pre_stop[service_unit] = _wait_active(systemctl, service_unit)
        if (
            pre_stop[monitor_slice_unit].get("ControlGroup")
            != monitor_receipt["monitor_slice_control_group"]
        ):
            raise AssertionError("monitor service parent slice differs from its receipt")
        expected_service_identity = {
            "Id": monitor_receipt["unit"],
            "InvocationID": monitor_receipt["invocation_id"],
            "ControlGroup": monitor_receipt["control_group"],
            "MainPID": str(monitor_receipt["main_pid"]),
            "Slice": monitor_receipt["monitor_slice_unit"],
        }
        if any(
            pre_stop[service_unit].get(key) != expected
            for key, expected in expected_service_identity.items()
        ):
            raise AssertionError("post-restart service identity differs from its receipt")

        scope_client = subprocess.Popen(
            [
                systemd_run,
                "--user",
                "--scope",
                f"--unit={scope_unit}",
                f"--slice={slice_unit}",
                "/usr/bin/sleep",
                "45",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
            env=_environment(),
        )

        pre_stop[scope_unit] = _wait_active(systemctl, scope_unit, scope_client)
        attempt_slice_cgroup = pre_stop[slice_unit]["ControlGroup"]
        monitor_slice_cgroup = pre_stop[monitor_slice_unit]["ControlGroup"]
        if pre_stop[service_unit].get("Slice") != monitor_slice_unit:
            raise AssertionError(f"monitor is not assigned to {monitor_slice_unit}")
        if PurePosixPath(pre_stop[service_unit]["ControlGroup"]).parent.as_posix() != (
            monitor_slice_cgroup
        ):
            raise AssertionError("monitor service is not a direct child of its trusted slice")
        if pre_stop[scope_unit].get("Slice") != slice_unit:
            raise AssertionError(f"worker scope is not assigned to {slice_unit}")
        if PurePosixPath(pre_stop[scope_unit]["ControlGroup"]).parent.as_posix() != (
            attempt_slice_cgroup
        ):
            raise AssertionError("worker scope is not a direct child of its attempt slice")
        if PurePosixPath(pre_stop[service_unit]["ControlGroup"]).is_relative_to(
            PurePosixPath(attempt_slice_cgroup)
        ):
            raise AssertionError("trusted monitor is inside the cancellable worker slice")
        for unit in (service_unit, scope_unit):
            properties = pre_stop[unit]
            if not properties.get("InvocationID"):
                raise AssertionError(f"{unit} has no systemd InvocationID")
            if _cgroup_is_empty(properties["ControlGroup"]):
                raise AssertionError(f"{unit} has no process in its active cgroup")

        _run([systemctl, "--user", "stop", slice_unit])
        for unit in (slice_unit, scope_unit):
            post_stop[unit] = _wait_inactive(systemctl, unit)
            if not _cgroup_is_empty(pre_stop[unit]["ControlGroup"]):
                raise AssertionError(
                    f"cgroup still contains processes after stopping {slice_unit}: {unit}"
                )
        surviving_monitor = _unit_properties(systemctl, service_unit)
        if any(
            surviving_monitor.get(key) != expected
            for key, expected in expected_service_identity.items()
        ) or _cgroup_is_empty(pre_stop[service_unit]["ControlGroup"]):
            raise AssertionError(
                "trusted monitor did not survive worker-slice cancellation with exact identity"
            )
        if scope_client is None or scope_client.wait(timeout=_WAIT_SECONDS) is None:
            raise AssertionError(
                "the systemd-run scope client did not exit after stopping its slice"
            )
        _run([systemctl, "--user", "stop", service_unit])
        post_stop[service_unit] = _wait_inactive(systemctl, service_unit)
        if not _cgroup_is_empty(pre_stop[service_unit]["ControlGroup"]):
            raise AssertionError("monitor service cgroup remained populated after its own stop")

        return {
            "systemd_user_manager": manager_state,
            "slice": slice_unit,
            "invocation_ids": {
                unit: properties.get("InvocationID", "") for unit, properties in pre_stop.items()
            },
            "control_groups": {
                unit: properties["ControlGroup"] for unit, properties in pre_stop.items()
            },
            "post_stop_states": {
                unit: properties.get("ActiveState", "") for unit, properties in post_stop.items()
            },
            "monitor_reconciled_after_controller_sigkill": True,
            "monitor_invocation_id": monitor_receipt["invocation_id"],
            "monitor_main_pid": monitor_receipt["main_pid"],
            "monitor_survived_worker_slice_stop": True,
            "cgroups_empty": True,
            "scope_client_exit_code": scope_client.returncode,
        }
    finally:
        cleanup_errors: list[str] = []
        for unit in (slice_unit, scope_unit, service_unit):
            try:
                subprocess.run(
                    [systemctl, "--user", "stop", unit],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=_WAIT_SECONDS,
                    env=_environment(),
                )
                properties = _wait_inactive(systemctl, unit)
                if properties.get("ActiveState") in {"active", "activating", "deactivating"}:
                    cleanup_errors.append(f"{unit} remained active: {properties}")
                control_groups = {
                    properties.get("ControlGroup", ""),
                    pre_stop.get(unit, {}).get("ControlGroup", ""),
                }
                for control_group in control_groups - {""}:
                    if not _cgroup_is_empty(control_group):
                        cleanup_errors.append(f"{unit} retained populated cgroup {control_group}")
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                cleanup_errors.append(f"could not verify {unit} cleanup: {exc}")
        if scope_client is not None and scope_client.poll() is None:
            scope_client.terminate()
            try:
                scope_client.wait(timeout=2)
            except subprocess.TimeoutExpired:
                scope_client.kill()
                scope_client.wait(timeout=2)
        if cleanup_errors:
            active_error = sys.exc_info()[1]
            message = "systemd probe cleanup was not verified: " + "; ".join(cleanup_errors)
            if active_error is not None:
                raise RuntimeError(message) from active_error
            raise RuntimeError(message)


def test_systemd_monitor_reconciles_after_controller_crash_and_slice_stops_units(
    tmp_path: Path,
) -> None:
    import pytest

    if not _ENABLED:
        pytest.skip("set ACP_RUN_SYSTEMD_SLICE_INTEGRATION=1 on a disposable Linux host")
    evidence = _probe(tmp_path)
    assert evidence["monitor_reconciled_after_controller_sigkill"] is True
    assert evidence["monitor_survived_worker_slice_stop"] is True
    assert evidence["cgroups_empty"] is True
    assert set(evidence["post_stop_states"].values()) <= {"inactive", "failed", "not-found"}


def test_live_systemd_attestation_verifier_rejects_restarted_wrapper() -> None:
    import pytest

    if not _ENABLED:
        pytest.skip("set ACP_RUN_SYSTEMD_SLICE_INTEGRATION=1 on a disposable Linux host")
    if not sys.platform.startswith("linux"):
        raise RuntimeError("the opt-in systemd attestation test requires Linux")
    if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        raise RuntimeError("the opt-in systemd attestation test requires cgroup v2")

    systemd_run = shutil.which("systemd-run", path=_environment()["PATH"])
    systemctl = shutil.which("systemctl", path=_environment()["PATH"])
    if systemd_run is None or systemctl is None:
        raise RuntimeError("systemd-run and systemctl are required")
    manager_state = _run(
        [systemctl, "--user", "is-system-running"], accepted_returncodes=(0, 1)
    ).stdout.strip()
    if manager_state not in {"running", "degraded"}:
        raise RuntimeError(f"user systemd manager is not available: {manager_state!r}")

    token = uuid.uuid4().hex
    container_id = f"acp-live-systemd-{token}"
    attempt_slice_unit = _oci_worker_systemd_slice(container_id)
    wrapper_unit = f"acp-live-wrapper-{token}.service"
    scope_unit = f"acp-live-scope-{token}.scope"
    bundle_path = f"/tmp/{container_id}/bundle"
    active: dict[str, dict[str, str]] = {}
    scope_client: subprocess.Popen[str] | None = None
    try:
        _run([systemctl, "--user", "start", attempt_slice_unit])
        _run(
            [
                systemd_run,
                "--user",
                f"--unit={wrapper_unit}",
                "--slice=app.slice",
                "--property=Type=exec",
                "--property=KillMode=control-group",
                "--property=RuntimeMaxSec=90s",
                "/usr/bin/python3",
                "-c",
                "import subprocess; p = subprocess.Popen(['/usr/bin/sleep', '90']); p.wait()",
            ]
        )
        active[wrapper_unit] = _wait_active(systemctl, wrapper_unit)
        active[attempt_slice_unit] = _wait_active(systemctl, attempt_slice_unit)
        scope_client = subprocess.Popen(
            [
                systemd_run,
                "--user",
                "--scope",
                f"--unit={scope_unit}",
                f"--slice={attempt_slice_unit}",
                "/usr/bin/sleep",
                "90",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
            env=_environment(),
        )
        active[scope_unit] = _wait_active(systemctl, scope_unit, scope_client)
        receipt = _attestation_for_live_units(
            container_id=container_id,
            wrapper_unit=wrapper_unit,
            wrapper=active[wrapper_unit],
            attempt_slice_unit=attempt_slice_unit,
            attempt_slice=active[attempt_slice_unit],
            scope_unit=scope_unit,
            scope=active[scope_unit],
            bundle_path=bundle_path,
        )
        verify_running_runtime_systemd_units(receipt)

        original_invocation = active[wrapper_unit]["InvocationID"]
        _run([systemctl, "--user", "restart", wrapper_unit])
        restarted = _wait_active(systemctl, wrapper_unit)
        active[wrapper_unit] = restarted
        if restarted.get("InvocationID") == original_invocation:
            raise AssertionError("systemd restart reused the wrapper InvocationID")
        with pytest.raises(SupervisorError) as stale:
            verify_running_runtime_systemd_units(receipt)
        assert stale.value.code == "sandbox_runtime_attestation_stale"
    finally:
        cleanup_errors: list[str] = []
        for unit in (scope_unit, attempt_slice_unit, wrapper_unit):
            try:
                subprocess.run(
                    [systemctl, "--user", "stop", unit],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=_WAIT_SECONDS,
                    env=_environment(),
                )
                inactive = _wait_inactive(systemctl, unit)
                if inactive.get("ActiveState") in {"active", "activating", "deactivating"}:
                    cleanup_errors.append(f"{unit} remained active: {inactive}")
                control_groups = {
                    inactive.get("ControlGroup", ""),
                    active.get(unit, {}).get("ControlGroup", ""),
                }
                for control_group in control_groups - {""}:
                    if not _cgroup_is_empty(control_group):
                        cleanup_errors.append(f"{unit} retained populated cgroup {control_group}")
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                cleanup_errors.append(f"could not verify {unit} cleanup: {error}")
        if scope_client is not None and scope_client.poll() is None:
            scope_client.terminate()
            try:
                scope_client.wait(timeout=2)
            except subprocess.TimeoutExpired:
                scope_client.kill()
                scope_client.wait(timeout=2)
        if cleanup_errors:
            active_error = sys.exc_info()[1]
            message = "systemd attestation probe cleanup was not verified: " + "; ".join(
                cleanup_errors
            )
            if active_error is not None:
                raise RuntimeError(message) from active_error
            raise RuntimeError(message)


if __name__ == "__main__":
    arguments = sys.argv[1:]
    if arguments and arguments[0] == "--monitor-controller":
        if len(arguments) != 10:
            raise SystemExit("monitor-controller mode requires nine arguments")
        _start_monitor_controller(
            *arguments[1:6],
            Path(arguments[6]),
            arguments[7],
            int(arguments[8]),
            arguments[9],
        )
    elif arguments and arguments[0] == "--reconcile-monitor":
        if len(arguments) != 3:
            raise SystemExit("reconcile-monitor mode requires two arguments")
        print(json.dumps(_reconcile_monitor_after_restart(arguments[1], Path(arguments[2]))))
    else:
        if not _ENABLED:
            raise SystemExit("set ACP_RUN_SYSTEMD_SLICE_INTEGRATION=1 to run this probe")
        with tempfile.TemporaryDirectory(prefix="acp-systemd-monitor-recovery-") as directory:
            print(json.dumps(_probe(Path(directory)), sort_keys=True))
