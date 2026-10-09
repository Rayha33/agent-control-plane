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
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from agent_control_plane.supervisor.oci_worker import _oci_worker_systemd_slice

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
    """Persist the test controller's exact systemd identity before it is killed."""

    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(encoded) > 4096:
        raise RuntimeError("monitor receipt exceeded its bounded size")
    temporary = path.with_name(f".{path.name}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while persisting monitor receipt")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _read_monitor_receipt(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_size <= 0
            or info.st_size > 4096
        ):
            raise RuntimeError("monitor receipt is not a bounded private regular file")
        chunks: list[bytes] = []
        remaining = 4097
        while remaining:
            chunk = os.read(descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        encoded = b"".join(chunks)
        if len(encoded) != info.st_size or len(encoded) > 4096:
            raise RuntimeError("monitor receipt changed or exceeded its bound while reading")
    finally:
        os.close(descriptor)
    receipt = json.loads(encoded.decode("ascii"))
    expected = {
        "version",
        "controller_pid",
        "unit",
        "invocation_id",
        "control_group",
        "main_pid",
        "slice_unit",
        "slice_control_group",
    }
    if (
        not isinstance(receipt, dict)
        or set(receipt) != expected
        or type(receipt["version"]) is not int
        or receipt["version"] != 1
    ):
        raise RuntimeError("monitor receipt has an unsupported shape")
    if (
        type(receipt["controller_pid"]) is not int
        or receipt["controller_pid"] <= 0
        or type(receipt["main_pid"]) is not int
        or receipt["main_pid"] <= 0
        or not isinstance(receipt["invocation_id"], str)
        or len(receipt["invocation_id"]) != 32
        or any(char not in "0123456789abcdef" for char in receipt["invocation_id"])
        or not all(
            isinstance(receipt[name], str) and receipt[name]
            for name in ("unit", "control_group", "slice_unit", "slice_control_group")
        )
    ):
        raise RuntimeError("monitor receipt contains an invalid identity")
    return receipt


def _start_monitor_controller(
    systemd_run: str,
    systemctl: str,
    service_unit: str,
    slice_unit: str,
    receipt_path: Path,
) -> None:
    """Old-controller subprocess: start a systemd-owned sleep service and fsync its receipt."""

    _run(
        [
            systemd_run,
            "--user",
            f"--unit={service_unit}",
            f"--slice={slice_unit}",
            "--property=Type=exec",
            "--property=KillMode=control-group",
            "--property=RuntimeMaxSec=45s",
            "/usr/bin/sleep",
            "45",
        ]
    )
    service = _wait_active(systemctl, service_unit)
    attempt_slice = _wait_active(systemctl, slice_unit)
    if (
        service.get("Id") != service_unit
        or service.get("Slice") != slice_unit
        or service.get("LoadState") != "loaded"
        or not service.get("InvocationID")
        or not service.get("ControlGroup")
        or not attempt_slice.get("ControlGroup")
    ):
        raise RuntimeError(f"systemd monitor identity is incomplete: {service}")
    main_pid = int(service.get("MainPID", "0"))
    receipt = {
        "version": 1,
        "controller_pid": os.getpid(),
        "unit": service_unit,
        "invocation_id": service["InvocationID"],
        "control_group": service["ControlGroup"],
        "main_pid": main_pid,
        "slice_unit": slice_unit,
        "slice_control_group": attempt_slice["ControlGroup"],
    }
    if main_pid <= 0 or main_pid == os.getpid():
        raise RuntimeError("systemd monitor MainPID is not owned by a distinct service process")
    _write_monitor_receipt(receipt_path, receipt)
    # The parent kills this controller after the durable receipt is visible.
    # The transient service must remain owned by systemd, not this process.
    print("receipt-durable", flush=True)
    time.sleep(60)


def _reconcile_monitor_after_restart(systemctl: str, receipt_path: Path) -> dict[str, Any]:
    """Fresh-controller subprocess: adopt only the exact recorded unit activation."""

    receipt = _read_monitor_receipt(receipt_path)
    service = _unit_properties(systemctl, receipt["unit"])
    attempt_slice = _unit_properties(systemctl, receipt["slice_unit"])
    expected_service = {
        "Id": receipt["unit"],
        "LoadState": "loaded",
        "ActiveState": "active",
        "InvocationID": receipt["invocation_id"],
        "ControlGroup": receipt["control_group"],
        "Slice": receipt["slice_unit"],
        "MainPID": str(receipt["main_pid"]),
    }
    expected_slice = {
        "Id": receipt["slice_unit"],
        "LoadState": "loaded",
        "ActiveState": "active",
        "ControlGroup": receipt["slice_control_group"],
    }
    if any(service.get(key) != value for key, value in expected_service.items()):
        raise RuntimeError(f"monitor service no longer matches its durable receipt: {service}")
    if any(attempt_slice.get(key) != value for key, value in expected_slice.items()):
        raise RuntimeError(f"attempt slice no longer matches its durable receipt: {attempt_slice}")
    if Path(service["ControlGroup"]).parent.as_posix() != attempt_slice["ControlGroup"]:
        raise RuntimeError("monitor service cgroup is not a direct child of the recorded slice")
    if not Path(f"/proc/{receipt['main_pid']}").is_dir():
        raise RuntimeError("recorded systemd monitor MainPID is no longer present")
    if os.getpid() == receipt["controller_pid"]:
        raise RuntimeError("reconciliation unexpectedly ran in the original controller process")
    return {"receipt": receipt, "service": service, "slice": attempt_slice}


def _crash_controller_and_reconcile(
    systemd_run: str,
    systemctl: str,
    service_unit: str,
    slice_unit: str,
    receipt_path: Path,
) -> dict[str, Any]:
    controller = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--monitor-controller",
            systemd_run,
            systemctl,
            service_unit,
            slice_unit,
            str(receipt_path),
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


def test_monitor_receipt_round_trips_as_private_durable_identity(tmp_path: Path) -> None:
    receipt = {
        "version": 1,
        "controller_pid": 101,
        "unit": "acp-monitor-test.service",
        "invocation_id": "a" * 32,
        "control_group": "/user.slice/user-1000.slice/acp-monitor-test.service",
        "main_pid": 102,
        "slice_unit": "user-acp-test.slice",
        "slice_control_group": "/user.slice/user-1000.slice/user-acp-test.slice",
    }
    path = tmp_path / "monitor-receipt.json"

    _write_monitor_receipt(path, receipt)

    assert path.stat().st_mode & 0o777 == 0o600
    assert _read_monitor_receipt(path) == receipt


def test_monitor_receipt_rejects_symlinks_and_boolean_versions(tmp_path: Path) -> None:
    import pytest

    receipt = {
        "version": 1,
        "controller_pid": 101,
        "unit": "acp-monitor-test.service",
        "invocation_id": "a" * 32,
        "control_group": "/user.slice/user-1000.slice/acp-monitor-test.service",
        "main_pid": 102,
        "slice_unit": "user-acp-test.slice",
        "slice_control_group": "/user.slice/user-1000.slice/user-acp-test.slice",
    }
    target = tmp_path / "receipt-target.json"
    link = tmp_path / "receipt-link.json"
    _write_monitor_receipt(target, receipt)
    link.symlink_to(target)
    with pytest.raises(OSError):
        _read_monitor_receipt(link)

    invalid = dict(receipt, version=True)
    invalid_path = tmp_path / "boolean-version.json"
    invalid_path.write_text(json.dumps(invalid), encoding="ascii")
    invalid_path.chmod(0o600)
    with pytest.raises(RuntimeError, match="unsupported shape"):
        _read_monitor_receipt(invalid_path)


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
    container_id = f"acp-slice-probe-{token}"
    slice_unit = _oci_worker_systemd_slice(container_id)
    service_unit = f"acp-monitor-probe-{token}.service"
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
            slice_unit,
            receipt_path,
        )
        monitor_receipt = monitor_reconciliation["receipt"]
        pre_stop[slice_unit] = _wait_active(systemctl, slice_unit)
        pre_stop[service_unit] = _wait_active(systemctl, service_unit)
        expected_service_identity = {
            "Id": monitor_receipt["unit"],
            "InvocationID": monitor_receipt["invocation_id"],
            "ControlGroup": monitor_receipt["control_group"],
            "MainPID": str(monitor_receipt["main_pid"]),
            "Slice": monitor_receipt["slice_unit"],
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
        slice_cgroup = pre_stop[slice_unit]["ControlGroup"]
        for unit in (service_unit, scope_unit):
            properties = pre_stop[unit]
            if properties.get("Slice") != slice_unit:
                raise AssertionError(f"{unit} is not assigned to {slice_unit}: {properties}")
            if Path(properties["ControlGroup"]).parent.as_posix() != slice_cgroup:
                raise AssertionError(f"{unit} is not a direct cgroup child of {slice_unit}")
            if not properties.get("InvocationID"):
                raise AssertionError(f"{unit} has no systemd InvocationID")
            if _cgroup_is_empty(properties["ControlGroup"]):
                raise AssertionError(f"{unit} has no process in its active cgroup")

        _run([systemctl, "--user", "stop", slice_unit])
        for unit in (slice_unit, service_unit, scope_unit):
            post_stop[unit] = _wait_inactive(systemctl, unit)
            if not _cgroup_is_empty(pre_stop[unit]["ControlGroup"]):
                raise AssertionError(
                    f"cgroup still contains processes after stopping {slice_unit}: {unit}"
                )
        if scope_client is None or scope_client.wait(timeout=_WAIT_SECONDS) is None:
            raise AssertionError(
                "the systemd-run scope client did not exit after stopping its slice"
            )

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
            "cgroups_empty": True,
            "scope_client_exit_code": scope_client.returncode,
        }
    finally:
        cleanup_errors: list[str] = []
        for unit in (slice_unit, service_unit, scope_unit):
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
    assert evidence["cgroups_empty"] is True
    assert set(evidence["post_stop_states"].values()) <= {"inactive", "failed", "not-found"}


if __name__ == "__main__":
    arguments = sys.argv[1:]
    if arguments and arguments[0] == "--monitor-controller":
        if len(arguments) != 6:
            raise SystemExit("monitor-controller mode requires five arguments")
        _start_monitor_controller(*arguments[1:5], Path(arguments[5]))
    elif arguments and arguments[0] == "--reconcile-monitor":
        if len(arguments) != 3:
            raise SystemExit("reconcile-monitor mode requires two arguments")
        print(json.dumps(_reconcile_monitor_after_restart(arguments[1], Path(arguments[2]))))
    else:
        if not _ENABLED:
            raise SystemExit("set ACP_RUN_SYSTEMD_SLICE_INTEGRATION=1 to run this probe")
        with tempfile.TemporaryDirectory(prefix="acp-systemd-monitor-recovery-") as directory:
            print(json.dumps(_probe(Path(directory)), sort_keys=True))
