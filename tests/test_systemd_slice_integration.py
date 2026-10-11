"""Opt-in proofs for systemd-owned monitor identity, IPC, and slice teardown.

Run with ``ACP_RUN_SYSTEMD_SLICE_INTEGRATION=1`` on a disposable Linux host
with an active user systemd manager and cgroup v2. The control-channel case
uses a test-only monitor service and ``/usr/bin/sleep`` scope to exercise the
production receipt and authenticated IPC code after controller-process exit.
It does not launch or attest the supervised OCI worker or its runc handle.
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
import traceback
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
from agent_control_plane.supervisor.sandbox_monitor_ipc import (
    SandboxMonitorControlClient,
    SandboxMonitorControlServer,
)
from agent_control_plane.supervisor.sandbox_monitor_receipt import (
    SandboxMonitorReceipt,
    load_or_create_sandbox_monitor_control_key,
    read_sandbox_monitor_receipt,
    sandbox_attempt_slice_unit,
    sandbox_container_id,
    sandbox_monitor_service_unit,
    validate_monitor_service_reconciliation,
    write_sandbox_monitor_receipt,
)

_ENABLED = os.environ.get("ACP_RUN_SYSTEMD_SLICE_INTEGRATION") == "1"
_WAIT_SECONDS = 8.0
_SYSTEMD_ACTIVATION_PROPERTIES = ("Id", "InvocationID", "ControlGroup", "Slice")


def _same_systemd_activation(expected: dict[str, str], observed: dict[str, str]) -> bool:
    return all(
        bool(expected.get(name)) and observed.get(name) == expected[name]
        for name in _SYSTEMD_ACTIVATION_PROPERTIES
    )


def _monitor_scope_phase(
    expected: dict[str, str],
    observed: dict[str, str],
    *,
    worker_identity_matches: bool,
    worker_process_absent: bool,
    worker_in_scope: bool,
) -> str:
    if (
        _same_systemd_activation(expected, observed)
        and observed.get("ActiveState") == "active"
        and worker_identity_matches
        and worker_in_scope
    ):
        return "running"
    if (
        _same_systemd_activation(expected, observed)
        and observed.get("ActiveState") == "inactive"
        and worker_process_absent
    ):
        return "exited"
    return "unknown"


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


def _serve_control_monitor(
    systemctl: str,
    scope_unit: str,
    control_directory: Path,
    attempt_id: str,
    claim_token: int,
    execution_id: str,
) -> None:
    """Test-only monitor: own a systemd scope and expose the production IPC."""

    (control_directory / "scope-launching").touch(mode=0o600)
    scope_client = subprocess.Popen(
        [
            shutil.which("systemd-run", path=_environment()["PATH"]) or "systemd-run",
            "--user",
            "--scope",
            f"--unit={scope_unit}",
            f"--slice={sandbox_attempt_slice_unit(attempt_id, claim_token, execution_id)}",
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
    scope = _wait_active(systemctl, scope_unit, scope_client)
    # systemd scopes do not promise a MainPID property. The retained
    # systemd-run client PID is the command PID for this exact scope.
    worker_pid = scope_client.pid
    worker_identity = ProcessMixin._process_identity(worker_pid)

    def worker_in_exact_scope() -> bool:
        try:
            worker_cgroup = Path(f"/proc/{worker_pid}/cgroup").read_text(encoding="ascii")
        except OSError:
            return False
        return any(
            line.endswith(f":{scope['ControlGroup']}") for line in worker_cgroup.splitlines()
        )

    scope_identity = {name: scope.get(name, "") for name in _SYSTEMD_ACTIVATION_PROPERTIES}
    if (
        worker_pid <= 0
        or worker_identity is None
        or not all(scope_identity.values())
        or not worker_in_exact_scope()
    ):
        scope_client.terminate()
        scope_client.wait(timeout=_WAIT_SECONDS)
        raise RuntimeError("monitor-owned scope lacks its exact live command identity")
    (control_directory / "scope-ready").touch(mode=0o600)

    def status() -> dict[str, Any]:
        current = _unit_properties(systemctl, scope_unit)
        current_worker_identity = ProcessMixin._process_identity(worker_pid)
        phase = _monitor_scope_phase(
            scope_identity,
            current,
            worker_identity_matches=current_worker_identity == worker_identity,
            worker_process_absent=current_worker_identity is None,
            worker_in_scope=worker_in_exact_scope(),
        )
        if phase == "running":
            return {"phase": "running", "worker_pid": worker_pid}
        if phase == "exited":
            return {"phase": "exited", "worker_pid": worker_pid, "worker_exit_code": 0}
        return {"phase": "unknown"}

    def cancel() -> dict[str, Any]:
        current = _unit_properties(systemctl, scope_unit)
        if (
            not _same_systemd_activation(scope_identity, current)
            or current.get("ActiveState") != "active"
            or ProcessMixin._process_identity(worker_pid) != worker_identity
            or not worker_in_exact_scope()
        ):
            raise RuntimeError("monitor refuses to cancel a changed worker-scope identity")
        _run([systemctl, "--user", "stop", scope_unit])
        scope_client.wait(timeout=_WAIT_SECONDS)
        current = _wait_inactive(systemctl, scope_unit)
        if current.get("ActiveState") in {"active", "activating", "deactivating"}:
            raise RuntimeError("monitor did not stop its exact worker scope")
        if not _cgroup_is_empty(scope_identity["ControlGroup"]):
            raise RuntimeError("monitor worker scope cgroup remained populated")
        if ProcessMixin._process_identity(worker_pid) is not None:
            raise RuntimeError("monitor worker PID survived its exact scope stop")
        return {
            "phase": "exited",
            "worker_pid": worker_pid,
            "worker_exit_code": scope_client.returncode,
        }

    identity = (attempt_id, claim_token, execution_id)
    key = load_or_create_sandbox_monitor_control_key(
        control_directory,
        attempt_id=attempt_id,
        claim_token=claim_token,
        execution_id=execution_id,
    )
    server = SandboxMonitorControlServer(
        socket_path=control_directory / "monitor.sock",
        request_directory=control_directory,
        key=key,
        expected_identity=identity,
        expected_uid=os.geteuid(),
        status_provider=status,
        cancel_action=cancel,
    )
    (control_directory / "server-bound").touch(mode=0o600)
    signal.signal(signal.SIGTERM, lambda *_args: server.close())
    server.serve_forever()
    if scope_client.poll() is None:
        scope_client.terminate()
        try:
            scope_client.wait(timeout=_WAIT_SECONDS)
        except subprocess.TimeoutExpired:
            scope_client.kill()
            scope_client.wait(timeout=_WAIT_SECONDS)


def _start_control_monitor_controller(
    systemd_run: str,
    systemctl: str,
    service_unit: str,
    monitor_slice_unit: str,
    attempt_slice_unit: str,
    scope_unit: str,
    control_directory: Path,
    receipt_path: Path,
    attempt_id: str,
    claim_token: int,
    execution_id: str,
) -> None:
    """Launch the test monitor service, attest it, and acknowledge durable receipt."""

    (control_directory / "attempt-slice-launching").touch(mode=0o600)
    _run([systemctl, "--user", "start", attempt_slice_unit])
    environment = _environment()
    command = [
        systemd_run,
        "--user",
        f"--unit={service_unit}",
        f"--slice={monitor_slice_unit}",
        "--property=Type=exec",
        "--property=KillMode=control-group",
        "--property=RuntimeMaxSec=90s",
    ]
    for name in ("PYTHONPATH", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
        value = environment.get(name)
        if value:
            command.append(f"--setenv={name}={value}")
    command.extend(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--control-monitor-service",
            systemctl,
            scope_unit,
            str(control_directory),
            attempt_id,
            str(claim_token),
            execution_id,
        ]
    )
    (control_directory / "monitor-service-launching").touch(mode=0o600)
    _run(command)
    service = _wait_active(systemctl, service_unit)
    monitor_slice = _wait_active(systemctl, monitor_slice_unit)
    attempt_slice = _wait_active(systemctl, attempt_slice_unit)
    if (
        service.get("Id") != service_unit
        or service.get("Slice") != monitor_slice_unit
        or not service.get("InvocationID")
        or not service.get("ControlGroup")
        or PurePosixPath(service["ControlGroup"]).parent.as_posix() != monitor_slice["ControlGroup"]
        or PurePosixPath(service["ControlGroup"]).is_relative_to(
            PurePosixPath(attempt_slice["ControlGroup"])
        )
    ):
        raise RuntimeError(f"monitor service identity or placement is incomplete: {service}")
    main_pid = int(service.get("MainPID", "0"))
    main_identity = ProcessMixin._process_identity(main_pid)
    if main_pid <= 0 or main_pid == os.getpid() or main_identity is None:
        raise RuntimeError("monitor service lacks a distinct live PID-start identity")

    socket_path = control_directory / "monitor.sock"
    deadline = time.monotonic() + _WAIT_SECONDS
    while not socket_path.is_socket():
        if time.monotonic() >= deadline:
            properties = _unit_properties(systemctl, service_unit)
            progress = sorted(path.name for path in control_directory.iterdir())
            diagnostic_path = control_directory / "monitor-error.txt"
            diagnostic = (
                diagnostic_path.read_text(encoding="utf-8") if diagnostic_path.is_file() else ""
            )
            raise RuntimeError(
                "monitor service did not bind its control socket: "
                f"properties={properties}; progress={progress}; diagnostic={diagnostic}"
            )
        time.sleep(0.02)
    receipt = SandboxMonitorReceipt(
        version=1,
        controller_pid=os.getpid(),
        attempt_id=attempt_id,
        claim_token=claim_token,
        execution_id=execution_id,
        unit=service_unit,
        invocation_id=service["InvocationID"],
        control_group=service["ControlGroup"],
        main_pid=main_pid,
        main_identity=main_identity,
        monitor_slice_unit=monitor_slice_unit,
        monitor_slice_control_group=monitor_slice["ControlGroup"],
        attempt_slice_unit=attempt_slice_unit,
        attempt_slice_control_group=attempt_slice["ControlGroup"],
    )
    _write_monitor_receipt(receipt_path, receipt.as_dict())
    key = load_or_create_sandbox_monitor_control_key(
        control_directory,
        attempt_id=attempt_id,
        claim_token=claim_token,
        execution_id=execution_id,
    )
    client = SandboxMonitorControlClient(
        receipt=receipt,
        socket_path=socket_path,
        key=key,
        expected_uid=os.geteuid(),
    )
    response = client.status()
    if response.outcome != "ok" or response.payload.get("phase") != "running":
        raise RuntimeError("monitor did not return authenticated running status")
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


def test_monitor_scope_phase_requires_exact_activation_even_after_exit() -> None:
    expected = {
        "Id": "acp-worker.scope",
        "InvocationID": "original-invocation",
        "ControlGroup": "/user.slice/user-acp.slice/acp-worker.scope",
        "Slice": "user-acp.slice",
    }
    exited = {**expected, "ActiveState": "inactive"}
    assert (
        _monitor_scope_phase(
            expected,
            exited,
            worker_identity_matches=False,
            worker_process_absent=True,
            worker_in_scope=False,
        )
        == "exited"
    )
    for name in _SYSTEMD_ACTIVATION_PROPERTIES:
        replacement = {**exited, name: f"replacement-{name}"}
        assert (
            _monitor_scope_phase(
                expected,
                replacement,
                worker_identity_matches=False,
                worker_process_absent=True,
                worker_in_scope=False,
            )
            == "unknown"
        )
    assert (
        _monitor_scope_phase(
            expected,
            exited,
            worker_identity_matches=False,
            worker_process_absent=False,
            worker_in_scope=False,
        )
        == "unknown"
    )


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


def test_exec_stop_post_is_not_final_unit_absence_evidence() -> None:
    """A post-stop hook can persist action evidence, but cannot certify its own absence."""

    import pytest

    if not _ENABLED:
        pytest.skip("set ACP_RUN_SYSTEMD_SLICE_INTEGRATION=1 on a disposable Linux host")
    if not sys.platform.startswith("linux"):
        raise RuntimeError("the opt-in systemd teardown test requires Linux")

    systemd_run = shutil.which("systemd-run", path=_environment()["PATH"])
    systemctl = shutil.which("systemctl", path=_environment()["PATH"])
    if systemd_run is None or systemctl is None:
        raise RuntimeError("systemd-run and systemctl are required")

    token = uuid.uuid4().hex
    unit = f"acp-stop-post-{token}.service"
    hook_cgroup = ""
    service_cgroup = ""
    output_lines: list[str] = []
    try:
        completed = _run(
            [
                systemd_run,
                "--user",
                "--wait",
                "--pipe",
                f"--unit={unit}",
                "--property=Type=exec",
                "--property=Delegate=yes",
                '--property=ExecStopPost=/bin/sh -c "cat /proc/self/cgroup"',
                "/usr/bin/true",
            ]
        )
        output_lines = (completed.stdout + "\n" + completed.stderr).splitlines()
        invocation_line = next(
            (line for line in output_lines if line.startswith("Running as unit: ")), ""
        )
        expected_prefix = f"Running as unit: {unit}; invocation ID: "
        if not invocation_line.startswith(expected_prefix):
            raise RuntimeError("systemd-run did not return the exact transient unit invocation")
        invocation_id = invocation_line.removeprefix(expected_prefix)
        if len(invocation_id) != 32 or any(
            character not in "0123456789abcdef" for character in invocation_id
        ):
            raise RuntimeError("systemd-run returned a malformed invocation ID")

        cgroup_line = next((line for line in output_lines if line.startswith("0::/")), "")
        if not cgroup_line:
            raise RuntimeError("ExecStopPost did not report its live cgroup")
        hook_cgroup = cgroup_line.removeprefix("0::")
        hook_path = PurePosixPath(hook_cgroup)
        if unit in hook_path.parts:
            unit_index = hook_path.parts.index(unit)
            service_cgroup = PurePosixPath(*hook_path.parts[: unit_index + 1]).as_posix()
        if hook_path.name != ".control" or hook_path.parent.name != unit:
            raise RuntimeError(
                f"ExecStopPost did not run in the expected service control subgroup: {hook_cgroup}"
            )

        after_stop = _unit_properties(systemctl, unit)
        if (
            after_stop.get("LoadState") != "not-found"
            or after_stop.get("ActiveState") != "inactive"
            or after_stop.get("MainPID") != "0"
            or after_stop.get("ControlGroup") != ""
            or after_stop.get("InvocationID") != ""
        ):
            raise RuntimeError(
                f"post-stop unit properties were inconsistent for {unit}: {after_stop}"
            )
        if not _cgroup_is_empty(hook_path.parent.as_posix()):
            raise RuntimeError(f"the service cgroup remained populated after stop: {hook_cgroup}")
        assert invocation_id != after_stop.get("InvocationID")
    finally:
        if not service_cgroup:
            cgroup_line = next((line for line in output_lines if line.startswith("0::/")), "")
            if cgroup_line:
                hook_path = PurePosixPath(cgroup_line.removeprefix("0::"))
                if unit in hook_path.parts:
                    unit_index = hook_path.parts.index(unit)
                    service_cgroup = PurePosixPath(*hook_path.parts[: unit_index + 1]).as_posix()
            if not service_cgroup:
                service_cgroup = _unit_properties(systemctl, unit).get("ControlGroup", "")
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
            raise RuntimeError(f"transient post-stop probe remained active: {inactive}")
        if service_cgroup and not _cgroup_is_empty(service_cgroup):
            raise RuntimeError(
                f"transient post-stop probe cgroup was not cleaned: {service_cgroup}"
            )


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


def test_live_systemd_monitor_ipc_survives_controller_crash_and_cancels_exact_scope() -> None:
    import pytest

    if not _ENABLED:
        pytest.skip("set ACP_RUN_SYSTEMD_SLICE_INTEGRATION=1 on a disposable Linux host")
    if (
        not sys.platform.startswith("linux")
        or not Path("/sys/fs/cgroup/cgroup.controllers").is_file()
    ):
        raise RuntimeError("the opt-in systemd monitor IPC test requires Linux cgroup v2")
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
    attempt_id = f"ipc-{token[:16]}"
    claim_token = 1
    execution_id = token
    service_unit = sandbox_monitor_service_unit(attempt_id, claim_token, execution_id)
    attempt_slice_unit = sandbox_attempt_slice_unit(attempt_id, claim_token, execution_id)
    monitor_slice_unit = "user-acp.slice"
    scope_unit = f"acp-ipc-scope-{token}.scope"
    runtime_directory_value = os.environ.get("XDG_RUNTIME_DIR")
    if not runtime_directory_value:
        raise RuntimeError("XDG_RUNTIME_DIR is required for the user-systemd probe")
    runtime_directory = Path(runtime_directory_value)
    control_directory = Path(tempfile.mkdtemp(prefix="acp-mipc-", dir=runtime_directory))
    os.chmod(control_directory, 0o700)
    directory_identity = control_directory.stat()
    receipt_path = control_directory / "monitor-receipt.json"
    socket_path = control_directory / "monitor.sock"
    controller: subprocess.Popen[str] | None = None
    cleanup_errors: list[str] = []
    active: dict[str, dict[str, str]] = {}
    try:
        controller = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--start-control-monitor",
                systemd_run,
                systemctl,
                service_unit,
                monitor_slice_unit,
                attempt_slice_unit,
                scope_unit,
                str(control_directory),
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
        while not receipt_path.exists():
            if controller.poll() is not None:
                _, stderr = controller.communicate()
                raise RuntimeError(
                    f"monitor controller exited {controller.returncode} before receipt: "
                    f"{stderr.strip()}"
                )
            if time.monotonic() >= deadline:
                raise RuntimeError("monitor controller did not persist its receipt in time")
            time.sleep(0.05)
        if controller.stdout is None:
            raise RuntimeError("monitor controller has no durability acknowledgment pipe")
        with selectors.DefaultSelector() as selector:
            selector.register(controller.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=_WAIT_SECONDS):
                raise RuntimeError("monitor controller did not acknowledge authenticated status")
            if controller.stdout.readline().strip() != "receipt-durable":
                raise RuntimeError("monitor controller exited before its durability acknowledgment")
        controller.send_signal(signal.SIGKILL)
        stdout, stderr = controller.communicate(timeout=_WAIT_SECONDS)
        if controller.returncode != -signal.SIGKILL:
            raise RuntimeError(
                f"monitor controller did not die abruptly: rc={controller.returncode}; "
                f"stdout={stdout.strip()}; stderr={stderr.strip()}"
            )
        controller = None

        reconciliation = _reconcile_monitor_after_restart(systemctl, receipt_path)
        receipt = SandboxMonitorReceipt.from_dict(reconciliation["receipt"])
        service = _wait_active(systemctl, service_unit)
        active[service_unit] = service
        attempt_slice = _wait_active(systemctl, attempt_slice_unit)
        active[attempt_slice_unit] = attempt_slice
        scope = _wait_active(systemctl, scope_unit)
        active[scope_unit] = scope
        if (
            service.get("Slice") != monitor_slice_unit
            or PurePosixPath(service["ControlGroup"]).parent.as_posix()
            != reconciliation["monitor_slice"]["ControlGroup"]
            or scope.get("Slice") != attempt_slice_unit
            or PurePosixPath(scope["ControlGroup"]).parent.as_posix()
            != attempt_slice["ControlGroup"]
            or PurePosixPath(service["ControlGroup"]).is_relative_to(
                PurePosixPath(attempt_slice["ControlGroup"])
            )
        ):
            raise AssertionError("monitor service and worker scope are not isolated siblings")
        key = load_or_create_sandbox_monitor_control_key(
            control_directory,
            attempt_id=attempt_id,
            claim_token=claim_token,
            execution_id=execution_id,
        )
        client = SandboxMonitorControlClient(
            receipt=receipt,
            socket_path=socket_path,
            key=key,
            expected_uid=os.geteuid(),
        )
        status = client.status()
        if status.outcome != "ok" or status.payload.get("phase") != "running":
            raise AssertionError(f"reconnected monitor status was not authenticated: {status}")
        worker_pid = status.payload.get("worker_pid")
        if type(worker_pid) is not int or ProcessMixin._process_identity(worker_pid) is None:
            raise AssertionError("monitor status did not identify a live worker process")
        worker_cgroup = Path(f"/proc/{worker_pid}/cgroup").read_text(encoding="ascii")
        if not any(
            line.endswith(f":{scope['ControlGroup']}") for line in worker_cgroup.splitlines()
        ):
            raise AssertionError("monitor-reported worker PID is outside the exact scope cgroup")

        request_id = uuid.uuid4().hex
        cancelled = client.cancel(request_id)
        replayed = client.cancel(request_id)
        if (
            cancelled.outcome != "ok"
            or cancelled.payload.get("phase") != "exited"
            or cancelled.payload.get("worker_pid") != worker_pid
            or replayed != cancelled
        ):
            raise AssertionError(
                "monitor cancellation was not exact, durable, and idempotent: "
                f"cancelled={cancelled!r}; replayed={replayed!r}"
            )
        scope = _wait_inactive(systemctl, scope_unit)
        if scope.get("ActiveState") in {"active", "activating", "deactivating"}:
            raise AssertionError("monitor cancellation left the exact worker scope active")
        if not _cgroup_is_empty(scope.get("ControlGroup", "")):
            raise AssertionError("monitor cancellation left the worker scope cgroup populated")
        if ProcessMixin._process_identity(worker_pid) is not None:
            raise AssertionError("monitor cancellation left its worker process alive")
        service = _wait_active(systemctl, service_unit)
        if service.get("InvocationID") != receipt.invocation_id:
            raise AssertionError("monitor service changed while its worker scope was stopped")
        if ProcessMixin._process_identity(receipt.main_pid) != receipt.main_identity:
            raise AssertionError("monitor process identity changed during cancellation")
    finally:
        if controller is not None and controller.poll() is None:
            controller.kill()
            controller.communicate(timeout=_WAIT_SECONDS)
        launch_markers = {
            scope_unit: "scope-launching",
            service_unit: "monitor-service-launching",
            attempt_slice_unit: "attempt-slice-launching",
        }
        for unit in (scope_unit, service_unit, attempt_slice_unit):
            try:
                original = active.get(unit)
                before_stop = _unit_properties(systemctl, unit)
                if original is None and before_stop.get("ControlGroup"):
                    original = before_stop
                    active[unit] = before_stop
                if (control_directory / launch_markers[unit]).exists() and not (
                    original and original.get("ControlGroup")
                ):
                    cleanup_errors.append(
                        f"{unit} was launched but its original cgroup was not captured"
                    )
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
                for control_group in {
                    inactive.get("ControlGroup", ""),
                    active.get(unit, {}).get("ControlGroup", ""),
                } - {""}:
                    if not _cgroup_is_empty(control_group):
                        cleanup_errors.append(f"{unit} retained populated cgroup {control_group}")
                if inactive.get("ActiveState") == "failed":
                    _run([systemctl, "--user", "reset-failed", unit])
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                cleanup_errors.append(f"could not verify {unit} cleanup: {error}")
        try:
            after = control_directory.lstat()
            if (
                (after.st_dev, after.st_ino)
                != (directory_identity.st_dev, directory_identity.st_ino)
                or after.st_uid != os.geteuid()
                or control_directory.is_symlink()
                or (after.st_mode & 0o777) != 0o700
            ):
                cleanup_errors.append("monitor IPC fixture directory identity changed")
        except OSError as error:
            cleanup_errors.append(f"monitor IPC fixture directory could not be verified: {error}")
        if cleanup_errors:
            raise RuntimeError(
                "monitor IPC integration cleanup was not verified; fixture retained: "
                + "; ".join(cleanup_errors)
            )
        shutil.rmtree(control_directory)


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
    elif arguments and arguments[0] == "--start-control-monitor":
        if len(arguments) != 12:
            raise SystemExit("start-control-monitor mode requires eleven arguments")
        _start_control_monitor_controller(
            arguments[1],
            arguments[2],
            arguments[3],
            arguments[4],
            arguments[5],
            arguments[6],
            Path(arguments[7]),
            Path(arguments[8]),
            arguments[9],
            int(arguments[10]),
            arguments[11],
        )
    elif arguments and arguments[0] == "--control-monitor-service":
        if len(arguments) != 7:
            raise SystemExit("control-monitor-service mode requires six arguments")
        try:
            _serve_control_monitor(
                arguments[1],
                arguments[2],
                Path(arguments[3]),
                arguments[4],
                int(arguments[5]),
                arguments[6],
            )
        except BaseException:
            diagnostic_path = Path(arguments[3]) / "monitor-error.txt"
            try:
                with diagnostic_path.open("x", encoding="utf-8") as stream:
                    stream.write(traceback.format_exc())
            except OSError:
                pass
            raise
    elif arguments and arguments[0] == "--reconcile-monitor":
        if len(arguments) != 3:
            raise SystemExit("reconcile-monitor mode requires two arguments")
        print(json.dumps(_reconcile_monitor_after_restart(arguments[1], Path(arguments[2]))))
    else:
        if not _ENABLED:
            raise SystemExit("set ACP_RUN_SYSTEMD_SLICE_INTEGRATION=1 to run this probe")
        with tempfile.TemporaryDirectory(prefix="acp-systemd-monitor-recovery-") as directory:
            print(json.dumps(_probe(Path(directory)), sort_keys=True))
