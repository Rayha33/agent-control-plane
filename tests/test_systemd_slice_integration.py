"""Opt-in proofs for systemd-owned monitor identity, IPC, and slice teardown.

Run with ``ACP_RUN_SYSTEMD_SLICE_INTEGRATION=1`` on a disposable Linux host
with an active user systemd manager and cgroup v2. The production monitor case
starts the in-repo service against a no-model ``/usr/bin/sleep`` scope, kills the
starting controller, then reconnects and cancels through the durable receipt.
It does not launch or attest the supervised OCI worker or its runc handle.
"""

from __future__ import annotations

import hashlib
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

import pytest

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
    SandboxMonitorIPCError,
    _linux_process_identity,
)
from agent_control_plane.supervisor.sandbox_monitor_lifecycle import (
    reconnect_sandbox_monitor,
    sandbox_monitor_cancel_request_id,
    sandbox_monitor_control_paths,
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
from agent_control_plane.supervisor.sandbox_monitor_service import (
    RuncClientScopeBinding,
    attach_held_runc_client_to_attempt_scope,
    sandbox_runc_client_scope_unit,
    start_sandbox_execution_monitor,
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
            "--property=FragmentPath",
        ]
    )
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def _scope_binding_is_active(binding: RuncClientScopeBinding, observed: dict[str, str]) -> bool:
    """Require the same loaded activation before a test cleanup stop."""

    return (
        observed.get("Id") == binding.scope_unit
        and observed.get("LoadState") == "loaded"
        and observed.get("ActiveState") == "active"
        and observed.get("InvocationID") == binding.scope_invocation_id
        and observed.get("ControlGroup") == binding.scope_control_group
        and observed.get("Slice") == binding.attempt_slice_unit
    )


def _stop_exact_runc_client_scope(systemctl: str, binding: RuncClientScopeBinding) -> bool:
    """Stop only the exact active scope activation previously returned by the helper."""

    observed = _unit_properties(systemctl, binding.scope_unit)
    if not _scope_binding_is_active(binding, observed):
        return False
    _run([systemctl, "--user", "stop", "--", binding.scope_unit])
    return True


def _linux_process_identity_if_present(pid: int) -> str | None:
    """Treat only a vanished /proc entry as absence; preserve other probe failures."""

    try:
        return _linux_process_identity(pid)
    except SandboxMonitorIPCError as error:
        if isinstance(error.__cause__, FileNotFoundError):
            return None
        raise


def _stop_exact_attempt_slice(systemctl: str, binding: dict[str, str]) -> bool:
    """Stop only the loaded active attempt-slice activation captured by this test."""

    unit = binding.get("Id", "")
    if not unit:
        return False
    observed = _unit_properties(systemctl, unit)
    if observed.get("LoadState") == "not-found":
        return True
    if (
        any(
            observed.get(name) != binding.get(name)
            for name in ("Id", "InvocationID", "ControlGroup", "Slice")
        )
        or observed.get("LoadState") != "loaded"
        or observed.get("ActiveState") != "active"
    ):
        return False
    _run([systemctl, "--user", "stop", "--", unit])
    return True


def _cleanup_step(errors: list[str], label: str, action) -> None:
    try:
        action()
    except Exception as error:
        errors.append(f"{label}: {error}")


def _cleanup_held_scope_probe(
    *,
    systemctl: str,
    attempt_slice_started: bool,
    attempt_slice_binding: dict[str, str] | None,
    attachment_attempted: bool,
    scope_binding: RuncClientScopeBinding | None,
    child: subprocess.Popen[bytes] | None,
) -> None:
    """Attempt every owned cleanup independently and preserve uncertain units."""

    errors: list[str] = []
    if scope_binding is not None:
        _cleanup_step(
            errors,
            "could not stop the exact runc client scope",
            lambda: _stop_exact_runc_client_scope(systemctl, scope_binding),
        )

    if child is not None:
        try:
            child_running = child.poll() is None
        except Exception as error:
            errors.append(f"could not inspect held child before cleanup: {error}")
            child_running = True
        if child_running:
            _cleanup_step(errors, "could not kill exact held child", child.kill)
        wait_failed = False
        try:
            child.wait(timeout=_WAIT_SECONDS)
        except Exception as error:
            errors.append(f"could not wait/reap exact held child: {error}")
            wait_failed = True
        if child.stdin is not None and not child.stdin.closed:
            _cleanup_step(errors, "could not close held child gate", child.stdin.close)
        if wait_failed:
            _cleanup_step(
                errors,
                "could not reap exact held child after closing abort gate",
                lambda: child.wait(timeout=_WAIT_SECONDS),
            )

    if scope_binding is not None:
        _cleanup_step(
            errors,
            "could not verify runc client scope inactivity",
            lambda: _wait_inactive(systemctl, scope_binding.scope_unit),
        )

    if attempt_slice_started:
        if attempt_slice_binding is None:
            errors.append("attempt slice identity was not verified; left it untouched")
        elif attachment_attempted and scope_binding is None:
            errors.append("scope binding was not verified; left attempt slice untouched")
        else:
            stopped = False
            try:
                stopped = _stop_exact_attempt_slice(systemctl, attempt_slice_binding)
                if not stopped:
                    errors.append("attempt slice activation changed; refused cleanup stop")
            except Exception as error:
                errors.append(f"could not stop exact attempt slice: {error}")
            _cleanup_step(
                errors,
                "could not verify attempt slice inactivity",
                lambda: _wait_inactive(systemctl, attempt_slice_binding["Id"]),
            )

    if errors:
        raise RuntimeError("held runc-client scope probe cleanup failed: " + "; ".join(errors))


def _held_child_argv() -> list[str]:
    """The child may exec only on an explicit byte; EOF is an abort signal."""

    code = (
        "import os; os.read(0, 1) == b'x' and "
        "os.execv('/usr/bin/sleep', ['sleep', '60']); os._exit(126)"
    )
    return [sys.executable, "-c", code]


def _test_runc_client_scope_binding() -> RuncClientScopeBinding:
    identity = ("attempt-cleanup", 1, "12345678-0000-4000-8000-000000000001")
    slice_unit = sandbox_attempt_slice_unit(*identity)
    scope_unit = sandbox_runc_client_scope_unit(*identity)
    slice_cgroup = f"/user.slice/user-1000.slice/user@1000.service/user-acp.slice/{slice_unit}"
    return RuncClientScopeBinding(
        attempt_id=identity[0],
        claim_token=identity[1],
        execution_id=identity[2],
        pid=4321,
        pid_identity="linux:4321:7654321",
        scope_unit=scope_unit,
        scope_invocation_id="a" * 32,
        scope_control_group=f"{slice_cgroup}/{scope_unit}",
        attempt_slice_unit=slice_unit,
        attempt_slice_invocation_id="b" * 32,
        attempt_slice_control_group=slice_cgroup,
    )


def test_scope_cleanup_requires_the_exact_returned_active_binding(monkeypatch) -> None:
    binding = _test_runc_client_scope_binding()
    observed = {
        "Id": binding.scope_unit,
        "LoadState": "loaded",
        "ActiveState": "active",
        "InvocationID": binding.scope_invocation_id,
        "ControlGroup": binding.scope_control_group,
        "Slice": binding.attempt_slice_unit,
    }
    commands: list[list[str]] = []
    monkeypatch.setattr(sys.modules[__name__], "_unit_properties", lambda *_args: observed.copy())
    monkeypatch.setattr(
        sys.modules[__name__],
        "_run",
        lambda argv, **_kwargs: commands.append(argv),
    )

    for property_name, wrong_value in (
        ("Id", "other.scope"),
        ("LoadState", "not-found"),
        ("ActiveState", "inactive"),
        ("InvocationID", "c" * 32),
        ("ControlGroup", "/different/cgroup"),
        ("Slice", "other.slice"),
    ):
        original_value = observed[property_name]
        observed[property_name] = wrong_value
        assert not _stop_exact_runc_client_scope("systemctl", binding)
        assert commands == []
        observed[property_name] = original_value

    assert _stop_exact_runc_client_scope("systemctl", binding)
    assert commands == [["systemctl", "--user", "stop", "--", binding.scope_unit]]


def test_scope_probe_cleanup_continues_after_scope_stop_failure(monkeypatch) -> None:
    events: list[str] = []

    class FakeStdin:
        closed = False

        def close(self) -> None:
            events.append("gate-close")
            self.closed = True

    class FakeChild:
        stdin = FakeStdin()
        running = True

        def poll(self) -> int | None:
            return None if self.running else 0

        def kill(self) -> None:
            events.append("child-kill")
            self.running = False

        def wait(self, *, timeout: float) -> int:
            assert timeout == _WAIT_SECONDS
            events.append("child-wait")
            return 0

    def fail_scope_stop(_systemctl: str, _binding: RuncClientScopeBinding) -> bool:
        events.append("scope-stop")
        raise RuntimeError("injected scope-stop failure")

    monkeypatch.setattr(sys.modules[__name__], "_stop_exact_runc_client_scope", fail_scope_stop)
    monkeypatch.setattr(
        sys.modules[__name__],
        "_stop_exact_attempt_slice",
        lambda *_args: events.append("slice-stop") or True,
    )
    monkeypatch.setattr(
        sys.modules[__name__],
        "_wait_inactive",
        lambda _systemctl, unit: events.append(f"wait:{unit}"),
    )

    binding = _test_runc_client_scope_binding()
    attempt_slice = {
        "Id": binding.attempt_slice_unit,
        "InvocationID": binding.attempt_slice_invocation_id,
        "ControlGroup": binding.attempt_slice_control_group,
        "Slice": "user-acp.slice",
    }
    with pytest.raises(RuntimeError, match="injected scope-stop failure"):
        _cleanup_held_scope_probe(
            systemctl="systemctl",
            attempt_slice_started=True,
            attempt_slice_binding=attempt_slice,
            attachment_attempted=True,
            scope_binding=binding,
            child=FakeChild(),
        )

    assert "child-kill" in events
    assert "child-wait" in events
    assert "gate-close" in events
    assert "slice-stop" in events
    assert f"wait:{binding.scope_unit}" in events
    assert f"wait:{binding.attempt_slice_unit}" in events


def test_scope_probe_cleanup_preserves_slice_without_verified_scope_binding(monkeypatch) -> None:
    events: list[str] = []
    monkeypatch.setattr(
        sys.modules[__name__],
        "_stop_exact_attempt_slice",
        lambda *_args: events.append("slice-stop") or True,
    )
    with pytest.raises(RuntimeError, match="scope binding was not verified"):
        _cleanup_held_scope_probe(
            systemctl="systemctl",
            attempt_slice_started=True,
            attempt_slice_binding={"Id": "attempt.slice"},
            attachment_attempted=True,
            scope_binding=None,
            child=None,
        )
    assert events == []


def test_scope_probe_cleanup_gate_eof_aborts_after_kill_and_wait_failures(monkeypatch) -> None:
    events: list[str] = []

    child = subprocess.Popen(
        _held_child_argv(),
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=_environment(),
    )
    if child.stdin is None:
        child.kill()
        child.wait(timeout=_WAIT_SECONDS)
        raise AssertionError("held child stdin gate is unavailable")

    class FaultInjectedStdin:
        @property
        def closed(self) -> bool:
            return child.stdin is None or child.stdin.closed

        def close(self) -> None:
            events.append("gate-close")
            if child.stdin is not None:
                child.stdin.close()

    class FaultInjectedChild:
        stdin = FaultInjectedStdin()

        def poll(self) -> int | None:
            return child.poll()

        def kill(self) -> None:
            events.append("child-kill")
            raise OSError("injected kill failure")

        def wait(self, *, timeout: float) -> int:
            assert timeout == _WAIT_SECONDS
            events.append("child-wait")
            if not self.stdin.closed:
                raise subprocess.TimeoutExpired("held-child", timeout)
            return child.wait(timeout=timeout)

    monkeypatch.setattr(
        sys.modules[__name__],
        "_stop_exact_attempt_slice",
        lambda *_args: events.append("slice-stop") or True,
    )
    try:
        with pytest.raises(RuntimeError) as error:
            _cleanup_held_scope_probe(
                systemctl="systemctl",
                attempt_slice_started=True,
                attempt_slice_binding={"Id": "attempt.slice"},
                attachment_attempted=True,
                scope_binding=None,
                child=FaultInjectedChild(),
            )

        assert "injected kill failure" in str(error.value)
        assert "could not wait/reap exact held child" in str(error.value)
        assert "scope binding was not verified; left attempt slice untouched" in str(error.value)
        assert events == ["child-kill", "child-wait", "gate-close", "child-wait"]
        assert child.wait(timeout=_WAIT_SECONDS) == 126
    finally:
        if child.poll() is None:
            if child.stdin is not None and not child.stdin.closed:
                child.stdin.close()
            try:
                child.wait(timeout=_WAIT_SECONDS)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=_WAIT_SECONDS)


def test_held_child_gate_eof_aborts_without_executing_payload() -> None:
    child = subprocess.Popen(
        _held_child_argv(),
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=_environment(),
    )
    try:
        if child.stdin is None:
            raise AssertionError("held child stdin gate is unavailable")
        child.stdin.close()
        assert child.wait(timeout=_WAIT_SECONDS) == 126
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=_WAIT_SECONDS)


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
    launch_driver_unit: str,
    launch_driver: dict[str, str],
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
    worker_pids = _wait_cgroup_pids(launch_driver["ControlGroup"], count=2)
    runc_client_pid = next(pid for pid in worker_pids if pid != int(launch_driver["MainPID"]))
    init_pids = _wait_cgroup_pids(scope["ControlGroup"], count=1)
    init_pid = next(iter(init_pids))
    launch_driver_pid = int(launch_driver["MainPID"])
    pids = (monitor_pid, launch_driver_pid, runc_client_pid, init_pid)
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
        launch_driver_properties=_attestation_unit_bytes(launch_driver, include_main_pid=True),
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
        expected_launch_driver_unit=launch_driver_unit,
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
    launch_driver_unit = f"acp-launch-driver-live-{token}.service"
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
        _run(
            [
                systemd_run,
                "--user",
                f"--unit={launch_driver_unit}",
                f"--slice={attempt_slice_unit}",
                "--property=Type=exec",
                "--property=KillMode=control-group",
                "--property=RuntimeMaxSec=90s",
                "/usr/bin/python3",
                "-c",
                "import subprocess; p = subprocess.Popen(['/usr/bin/sleep', '90']); p.wait()",
            ]
        )
        active[launch_driver_unit] = _wait_active(systemctl, launch_driver_unit)
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
            launch_driver_unit=launch_driver_unit,
            launch_driver=active[launch_driver_unit],
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
        for unit in (scope_unit, launch_driver_unit, attempt_slice_unit, wrapper_unit):
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
        client = reconnect_sandbox_monitor(
            receipt_path=receipt_path,
            control_directory=control_directory,
            socket_path=socket_path,
            expected_identity=(attempt_id, claim_token, execution_id),
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


def _start_production_monitor_controller(
    *,
    state_path: Path,
    attempt_id: str,
    claim_token: int,
    execution_id: str,
    scope_unit: str,
    scope_invocation_id: str,
    scope_control_group: str,
    attempt_slice_control_group: str,
) -> None:
    client = start_sandbox_execution_monitor(
        state_path=state_path,
        expected_identity=(attempt_id, claim_token, execution_id),
        scope_unit=scope_unit,
        scope_invocation_id=scope_invocation_id,
        scope_control_group=scope_control_group,
        attempt_slice_control_group=attempt_slice_control_group,
    )
    response = client.status()
    if (
        response.outcome != "ok"
        or response.payload.get("phase") != "running"
        or response.payload.get("scope_unit") != scope_unit
        or response.payload.get("scope_invocation_id") != scope_invocation_id
        or response.payload.get("scope_control_group") != scope_control_group
    ):
        raise RuntimeError("production monitor did not authenticate the exact running scope")
    print("monitor-ready", flush=True)
    time.sleep(60)


def test_live_production_monitor_service_survives_controller_crash_and_cancels_exact_scope() -> (
    None
):
    """Exercise the in-repo producer and control service against a harmless scope."""

    import stat

    import pytest

    if not _ENABLED:
        pytest.skip("set ACP_RUN_SYSTEMD_SLICE_INTEGRATION=1 on a disposable Linux host")
    if (
        not sys.platform.startswith("linux")
        or not Path("/sys/fs/cgroup/cgroup.controllers").is_file()
    ):
        raise RuntimeError("the production monitor test requires Linux cgroup v2")
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
    attempt_id = f"production-{token[:16]}"
    claim_token = 1
    execution_id = token
    identity = (attempt_id, claim_token, execution_id)
    container_id = sandbox_container_id(*identity)
    attempt_slice_unit = sandbox_attempt_slice_unit(*identity)
    monitor_unit = sandbox_monitor_service_unit(*identity)
    scope_unit = f"acp-{container_id}.scope"
    for unit in (scope_unit, monitor_unit, attempt_slice_unit):
        props = _unit_properties(systemctl, unit)
        if props.get("LoadState") == "not-found":
            continue
        implicit_inactive_slice = (
            unit.endswith(".slice")
            and props.get("LoadState") == "loaded"
            and props.get("ActiveState") == "inactive"
            and not props.get("ControlGroup")
            and not props.get("FragmentPath")
        )
        if not implicit_inactive_slice:
            raise RuntimeError(f"refusing to reuse a pre-existing systemd unit: {unit}")

    runtime_value = os.environ.get("XDG_RUNTIME_DIR")
    if not runtime_value:
        raise RuntimeError("XDG_RUNTIME_DIR is required for the production monitor test")
    fixture_root = Path(tempfile.mkdtemp(prefix="acp-production-monitor-", dir="/tmp"))
    os.chmod(fixture_root, 0o700)
    root_identity = fixture_root.lstat()
    state_path = fixture_root / "state"
    state_path.mkdir(mode=0o700)
    control_directory, receipt_path, socket_path = sandbox_monitor_control_paths(
        state_path=state_path,
        expected_identity=identity,
    )
    scope_client: subprocess.Popen[str] | None = None
    controller: subprocess.Popen[str] | None = None
    active: dict[str, dict[str, str]] = {}
    cleanup_errors: list[str] = []
    try:
        scope_client = subprocess.Popen(
            [
                systemd_run,
                "--user",
                "--scope",
                f"--unit={scope_unit}",
                f"--slice={attempt_slice_unit}",
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
        scope = _wait_active(systemctl, scope_unit, scope_client)
        active[scope_unit] = scope
        attempt_slice = _wait_active(systemctl, attempt_slice_unit)
        active[attempt_slice_unit] = attempt_slice
        scope_invocation_id = scope.get("InvocationID", "")
        scope_control_group = scope.get("ControlGroup", "")
        attempt_slice_control_group = attempt_slice.get("ControlGroup", "")
        if (
            not scope_invocation_id
            or not scope_control_group
            or not attempt_slice_control_group
            or scope.get("Slice") != attempt_slice_unit
            or PurePosixPath(scope_control_group).parent.as_posix() != attempt_slice_control_group
        ):
            raise AssertionError("test worker scope lacks exact attempt-slice identity")

        controller = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--start-production-monitor",
                str(state_path),
                attempt_id,
                str(claim_token),
                execution_id,
                scope_unit,
                scope_invocation_id,
                scope_control_group,
                attempt_slice_control_group,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
            env=_environment(),
        )
        deadline = time.monotonic() + _WAIT_SECONDS * 2
        while not receipt_path.is_file():
            if controller.poll() is not None:
                _, stderr = controller.communicate()
                raise RuntimeError(
                    f"production monitor controller exited {controller.returncode}: {stderr.strip()}"
                )
            if time.monotonic() >= deadline:
                raise RuntimeError("production monitor did not publish its durable receipt")
            time.sleep(0.05)
        if controller.stdout is None:
            raise RuntimeError("production controller has no readiness pipe")
        with selectors.DefaultSelector() as selector:
            selector.register(controller.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=_WAIT_SECONDS):
                raise RuntimeError("production monitor controller did not finish authentication")
            readiness = controller.stdout.readline().strip()
            if readiness != "monitor-ready":
                stdout, stderr = controller.communicate(timeout=_WAIT_SECONDS)
                raise RuntimeError(
                    "production monitor controller failed its status check: "
                    f"line={readiness!r}; stdout={stdout.strip()}; stderr={stderr.strip()}"
                )
        receipt = read_sandbox_monitor_receipt(receipt_path)
        if (
            receipt.unit != monitor_unit
            or receipt.attempt_slice_unit != attempt_slice_unit
            or receipt.attempt_slice_control_group != attempt_slice_control_group
        ):
            raise AssertionError("production receipt differs from the exact launch scope")
        key_path = control_directory / f"{container_id}.control-key"
        key = key_path.read_bytes()
        if (
            key_path.stat().st_mode & 0o777 != 0o600
            or control_directory.stat().st_mode & 0o777 != 0o700
            or key in receipt_path.read_bytes()
        ):
            raise AssertionError("production monitor key or private state boundary is unsafe")
        monitor_cmdline = Path(f"/proc/{receipt.main_pid}/cmdline").read_bytes()
        monitor_environment = Path(f"/proc/{receipt.main_pid}/environ").read_bytes()
        if (
            key in monitor_cmdline
            or key in monitor_environment
            or b"control-key" in monitor_cmdline
        ):
            raise AssertionError("monitor key or key filename was exposed through process metadata")

        controller.send_signal(signal.SIGKILL)
        stdout, stderr = controller.communicate(timeout=_WAIT_SECONDS)
        if controller.returncode != -signal.SIGKILL:
            raise RuntimeError(
                f"controller did not die abruptly: rc={controller.returncode}; "
                f"stdout={stdout.strip()}; stderr={stderr.strip()}"
            )
        controller = None

        client = reconnect_sandbox_monitor(
            receipt_path=receipt_path,
            control_directory=control_directory,
            socket_path=socket_path,
            expected_identity=identity,
        )
        status = client.status()
        expected_scope = {
            "scope_unit": scope_unit,
            "scope_invocation_id": scope_invocation_id,
            "scope_control_group": scope_control_group,
        }
        if (
            status.outcome != "ok"
            or status.payload.get("phase") != "running"
            or any(status.payload.get(key) != value for key, value in expected_scope.items())
        ):
            raise AssertionError(f"restarted controller did not observe exact scope: {status!r}")
        cancel_id = sandbox_monitor_cancel_request_id(identity)
        cancelled = client.cancel(cancel_id)
        retried = client.cancel(cancel_id)
        if (
            cancelled.outcome != "ok"
            or cancelled.payload.get("phase") != "exited"
            or any(cancelled.payload.get(key) != value for key, value in expected_scope.items())
            or retried != cancelled
        ):
            raise AssertionError(
                f"production monitor cancellation did not replay exactly: {cancelled!r}, {retried!r}"
            )
        scope_after = _wait_inactive(systemctl, scope_unit)
        if scope_after.get("ActiveState") in {"active", "activating", "deactivating"}:
            raise AssertionError("production monitor left its exact worker scope active")
        if not _cgroup_is_empty(scope_control_group):
            raise AssertionError("production monitor left the exact worker cgroup populated")
        active[monitor_unit] = _wait_active(systemctl, monitor_unit)
        if active[monitor_unit].get("InvocationID") != receipt.invocation_id:
            raise AssertionError("production monitor service changed after controller crash")
        if _linux_process_identity(receipt.main_pid) != receipt.main_identity:
            raise AssertionError("production monitor process identity changed unexpectedly")
    finally:
        if controller is not None and controller.poll() is None:
            controller.kill()
            controller.communicate(timeout=_WAIT_SECONDS)
        for unit in (scope_unit, monitor_unit, attempt_slice_unit):
            try:
                original = active.get(unit)
                before_stop = _unit_properties(systemctl, unit)
                if original is None and before_stop.get("ControlGroup"):
                    original = before_stop
                    active[unit] = before_stop
                if original and before_stop.get("InvocationID") not in {
                    original.get("InvocationID"),
                    "",
                }:
                    cleanup_errors.append(f"refusing to stop changed unit activation: {unit}")
                    continue
                subprocess.run(
                    [systemctl, "--user", "stop", "--", unit],
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
                    original.get("ControlGroup", "") if original else "",
                } - {""}:
                    if not _cgroup_is_empty(control_group):
                        cleanup_errors.append(f"{unit} retained populated cgroup {control_group}")
                if inactive.get("ActiveState") == "failed":
                    _run([systemctl, "--user", "reset-failed", "--", unit])
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                cleanup_errors.append(f"could not verify {unit} cleanup: {error}")
        if scope_client is not None and scope_client.poll() is None:
            scope_client.terminate()
            try:
                scope_client.wait(timeout=2)
            except subprocess.TimeoutExpired:
                scope_client.kill()
                scope_client.wait(timeout=2)
        try:
            after = fixture_root.lstat()
            if (
                (after.st_dev, after.st_ino) != (root_identity.st_dev, root_identity.st_ino)
                or after.st_uid != os.geteuid()
                or not stat.S_ISDIR(after.st_mode)
                or stat.S_IMODE(after.st_mode) != 0o700
            ):
                cleanup_errors.append("production monitor fixture directory identity changed")
        except OSError as error:
            cleanup_errors.append(f"production monitor fixture could not be verified: {error}")
        if cleanup_errors:
            raise RuntimeError(
                "production monitor integration cleanup was not verified; fixture retained at "
                f"{fixture_root}: " + "; ".join(cleanup_errors)
            )
        shutil.rmtree(fixture_root)


def test_live_systemd_loadcredential_is_read_only_and_not_environment() -> None:
    """Prove the systemd credential handoff primitive with a fake secret only."""

    import stat

    import pytest

    if not _ENABLED:
        pytest.skip("set ACP_RUN_SYSTEMD_SLICE_INTEGRATION=1 on a disposable Linux host")
    if (
        not sys.platform.startswith("linux")
        or not Path("/sys/fs/cgroup/cgroup.controllers").is_file()
    ):
        raise RuntimeError("the opt-in systemd credential test requires Linux cgroup v2")
    systemd_run = shutil.which("systemd-run", path=_environment()["PATH"])
    systemctl = shutil.which("systemctl", path=_environment()["PATH"])
    if systemd_run is None or systemctl is None:
        raise RuntimeError("systemd-run and systemctl are required")
    version_line = _run([systemctl, "--version"]).stdout.splitlines()[0]
    try:
        systemd_version = int(version_line.split()[1].split(".", 1)[0])
    except (IndexError, ValueError) as error:
        raise RuntimeError("systemd version could not be read") from error
    if systemd_version < 252:
        raise RuntimeError("the supported systemd credential probe requires version 252 or newer")
    manager_state = _run(
        [systemctl, "--user", "is-system-running"], accepted_returncodes=(0, 1)
    ).stdout.strip()
    if manager_state not in {"running", "degraded"}:
        raise RuntimeError(f"user systemd manager is not available: {manager_state!r}")
    runtime_directory_value = os.environ.get("XDG_RUNTIME_DIR")
    if not runtime_directory_value:
        raise RuntimeError("XDG_RUNTIME_DIR is required for the user-systemd credential probe")

    token = uuid.uuid4().hex
    unit = f"acp-credential-probe-{token}.service"
    runtime_directory = Path(runtime_directory_value)
    existing = _unit_properties(systemctl, unit)
    if existing.get("LoadState") != "not-found":
        raise RuntimeError(f"random credential probe unit already exists: {existing!r}")

    private_directory = Path(tempfile.mkdtemp(prefix="acp-credential-", dir=runtime_directory))
    directory_identity = private_directory.lstat()
    credential_source = private_directory / "credential-source"
    result_path = private_directory / "probe-result.json"
    secret = (uuid.uuid4().hex + uuid.uuid4().hex).encode("ascii")
    launch_attempted = False
    observed_unit: dict[str, str] = {}
    captured_main_pid = 0
    captured_main_identity: str | None = None
    cleanup_errors: list[str] = []
    try:
        if (
            directory_identity.st_uid != os.geteuid()
            or stat.S_IMODE(directory_identity.st_mode) != 0o700
            or not stat.S_ISDIR(directory_identity.st_mode)
        ):
            raise AssertionError("credential fixture directory is not private to the current user")
        descriptor = os.open(
            credential_source,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            if os.write(descriptor, secret) != len(secret):
                raise RuntimeError("fake credential source write was incomplete")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        source_info = credential_source.lstat()
        if (
            not stat.S_ISREG(source_info.st_mode)
            or source_info.st_uid != os.geteuid()
            or stat.S_IMODE(source_info.st_mode) != 0o600
        ):
            raise AssertionError("fake credential source is not private to the current user")
        expected_digest = hashlib.sha256(secret).hexdigest()
        probe = (
            "import hashlib,json,os,stat,sys; from pathlib import Path; "
            "credential_path=Path(os.environ['CREDENTIALS_DIRECTORY'])/'launch'; "
            "credential=credential_path.read_bytes(); "
            "report={'sha256':hashlib.sha256(credential).hexdigest(), "
            "'secret_in_environment':any(credential.decode('ascii') in value "
            "for value in os.environ.values()), "
            "'credential_read_only':(stat.S_IMODE(credential_path.stat().st_mode)&0o222)==0, "
            "'credential_owner_uid':credential_path.stat().st_uid}; "
            "Path(sys.argv[1]).write_text(json.dumps(report),encoding='ascii'); "
            "import time; time.sleep(60)"
        )
        launch_attempted = True
        launch_result = _run(
            [
                systemd_run,
                "--user",
                f"--unit={unit}",
                "--property=Type=exec",
                "--property=RuntimeMaxSec=90s",
                f"--property=LoadCredential=launch:{credential_source}",
                "--no-block",
                sys.executable,
                "-c",
                probe,
                str(result_path),
            ],
            timeout=10.0,
        )
        if secret.decode("ascii") in launch_result.stdout + launch_result.stderr:
            raise AssertionError("systemd-run output exposed the fake credential")
        observed_unit = _wait_active(systemctl, unit)
        if (
            observed_unit.get("LoadState") != "loaded"
            or observed_unit.get("Id") != unit
            or not observed_unit.get("InvocationID")
            or not observed_unit.get("ControlGroup")
            or observed_unit.get("ActiveState") != "active"
        ):
            raise AssertionError(
                "systemd did not expose the exact active credential-probe identity"
            )
        main_pid = int(observed_unit.get("MainPID", "0"))
        main_identity = ProcessMixin._process_identity(main_pid) if main_pid > 0 else None
        if main_identity is None:
            raise AssertionError("credential-probe service process identity was not observable")
        captured_main_pid = main_pid
        captured_main_identity = main_identity
        result_deadline = time.monotonic() + _WAIT_SECONDS
        while not result_path.is_file() and time.monotonic() < result_deadline:
            time.sleep(0.05)
        if not result_path.is_file():
            raise AssertionError("monitor service did not read the supplied fake credential")
        observed = json.loads(result_path.read_text(encoding="ascii"))
        expected = {
            "sha256": expected_digest,
            "secret_in_environment": False,
            "credential_read_only": True,
            "credential_owner_uid": os.geteuid(),
        }
        if observed != expected:
            raise AssertionError(f"systemd credential handoff differed: {observed!r}")
    finally:
        # Preserve the private fixture unless the exact transient unit is terminal,
        # its captured cgroups are empty, and its main process is gone.
        deadline = time.monotonic() + _WAIT_SECONDS
        control_groups: set[str] = set()
        process_identities: set[tuple[int, str]] = set()
        invocation_id = observed_unit.get("InvocationID", "")
        if launch_attempted and (
            observed_unit.get("Id") != unit
            or not invocation_id
            or not observed_unit.get("ControlGroup")
        ):
            cleanup_errors.append("the exact launched service identity was not captured")
        if observed_unit.get("ControlGroup"):
            control_groups.add(observed_unit["ControlGroup"])
        if captured_main_pid > 0 and captured_main_identity is not None:
            process_identities.add((captured_main_pid, captured_main_identity))
        elif launch_attempted:
            cleanup_errors.append("the pre-stop credential-probe process identity was not captured")
        try:
            observed_pid = int(observed_unit.get("MainPID", "0"))
            observed_identity = (
                ProcessMixin._process_identity(observed_pid) if observed_pid > 0 else None
            )
            if observed_identity is not None:
                process_identities.add((observed_pid, observed_identity))
        except (OSError, ValueError):
            cleanup_errors.append("the captured credential-probe MainPID could not be verified")
        if launch_attempted:
            try:
                subprocess.run(
                    [systemctl, "--user", "stop", unit],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=min(2.0, _WAIT_SECONDS),
                    env=_environment(),
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                cleanup_errors.append(f"could not stop exact credential-probe unit: {error}")
        terminal = False
        last: dict[str, str] = {}
        while time.monotonic() < deadline:
            try:
                last = _unit_properties(systemctl, unit)
                load_state = last.get("LoadState")
                if load_state == "loaded":
                    if last.get("Id") != unit:
                        cleanup_errors.append("systemd credential probe unit ID changed")
                        break
                    current_invocation = last.get("InvocationID", "")
                    if invocation_id and current_invocation and current_invocation != invocation_id:
                        cleanup_errors.append("systemd credential probe invocation changed")
                        break
                    invocation_id = invocation_id or current_invocation
                    if last.get("ControlGroup"):
                        control_groups.add(last["ControlGroup"])
                    try:
                        main_pid = int(last.get("MainPID", "0"))
                    except ValueError:
                        cleanup_errors.append("systemd credential probe MainPID was invalid")
                        break
                    if main_pid > 0:
                        identity = ProcessMixin._process_identity(main_pid)
                        if identity is not None:
                            process_identities.add((main_pid, identity))
                    active_state = last.get("ActiveState")
                    if active_state == "failed":
                        subprocess.run(
                            [systemctl, "--user", "reset-failed", unit],
                            check=False,
                            capture_output=True,
                            text=True,
                            timeout=min(2.0, _WAIT_SECONDS),
                            env=_environment(),
                        )
                    elif active_state in {"active", "activating", "deactivating"}:
                        subprocess.run(
                            [systemctl, "--user", "stop", unit],
                            check=False,
                            capture_output=True,
                            text=True,
                            timeout=min(2.0, _WAIT_SECONDS),
                            env=_environment(),
                        )
                    elif active_state != "inactive" or main_pid != 0:
                        cleanup_errors.append(
                            f"systemd credential probe has unknown active state: {last!r}"
                        )
                        break
                    terminal = False
                elif load_state == "not-found":
                    terminal = True
                else:
                    cleanup_errors.append(
                        f"systemd credential probe has unknown load state: {last!r}"
                    )
                    break
                cgroups_empty = all(_cgroup_is_empty(group) for group in control_groups)
                processes_gone = all(
                    ProcessMixin._process_identity(pid) != identity
                    for pid, identity in process_identities
                )
                if terminal and cgroups_empty and processes_gone:
                    break
                terminal = False
            except (OSError, RuntimeError, AssertionError, subprocess.TimeoutExpired) as error:
                cleanup_errors.append(f"could not verify systemd credential probe cleanup: {error}")
                break
            time.sleep(0.05)
        else:
            cleanup_errors.append(
                f"systemd credential probe did not reach a verified terminal state: {last!r}"
            )
        if not terminal:
            if not cleanup_errors:
                cleanup_errors.append(f"systemd credential probe remained non-terminal: {last!r}")
        for control_group in control_groups:
            try:
                if not _cgroup_is_empty(control_group):
                    cleanup_errors.append(
                        f"systemd credential probe retained populated cgroup {control_group}"
                    )
            except (OSError, RuntimeError, AssertionError) as error:
                cleanup_errors.append(f"could not verify credential-probe cgroup: {error}")
        if any(
            ProcessMixin._process_identity(pid) == identity for pid, identity in process_identities
        ):
            cleanup_errors.append("systemd credential probe process identity remained alive")
        try:
            after = private_directory.lstat()
            if (
                (after.st_dev, after.st_ino)
                != (directory_identity.st_dev, directory_identity.st_ino)
                or after.st_uid != os.geteuid()
                or not stat.S_ISDIR(after.st_mode)
                or stat.S_IMODE(after.st_mode) != 0o700
                or private_directory.is_symlink()
            ):
                cleanup_errors.append("credential fixture directory identity changed")
            else:
                for entry in private_directory.iterdir():
                    info = entry.lstat()
                    if (
                        entry.name not in {"credential-source", "probe-result.json"}
                        or not stat.S_ISREG(info.st_mode)
                        or info.st_uid != os.geteuid()
                        or entry.is_symlink()
                    ):
                        cleanup_errors.append(
                            f"credential fixture entry was not expected: {entry.name}"
                        )
        except OSError as error:
            cleanup_errors.append(f"credential fixture directory could not be verified: {error}")
        if cleanup_errors:
            raise RuntimeError(
                "systemd credential probe cleanup was not verified; "
                f"private fixture retained at {private_directory}: " + "; ".join(cleanup_errors)
            ) from sys.exc_info()[1]
        shutil.rmtree(private_directory)


def test_live_systemd_loadcredential_restart_requires_source_again() -> None:
    """Prove a restart re-resolves LoadCredential sources using only a fake value."""

    import stat

    import pytest

    if not _ENABLED:
        pytest.skip("set ACP_RUN_SYSTEMD_SLICE_INTEGRATION=1 on a disposable Linux host")
    if (
        not sys.platform.startswith("linux")
        or not Path("/sys/fs/cgroup/cgroup.controllers").is_file()
    ):
        raise RuntimeError("the opt-in credential restart test requires Linux cgroup v2")
    systemd_run = shutil.which("systemd-run", path=_environment()["PATH"])
    systemctl = shutil.which("systemctl", path=_environment()["PATH"])
    if systemd_run is None or systemctl is None:
        raise RuntimeError("systemd-run and systemctl are required")
    version_line = _run([systemctl, "--version"]).stdout.splitlines()[0]
    try:
        systemd_version = int(version_line.split()[1].split(".", 1)[0])
    except (IndexError, ValueError) as error:
        raise RuntimeError("systemd version could not be read") from error
    if systemd_version < 252:
        raise RuntimeError("the supported credential restart probe requires systemd 252 or newer")
    manager_state = _run(
        [systemctl, "--user", "is-system-running"], accepted_returncodes=(0, 1)
    ).stdout.strip()
    if manager_state not in {"running", "degraded"}:
        raise RuntimeError(f"user systemd manager is not available: {manager_state!r}")
    runtime_directory_value = os.environ.get("XDG_RUNTIME_DIR")
    if not runtime_directory_value:
        raise RuntimeError("XDG_RUNTIME_DIR is required for the credential restart probe")

    token = uuid.uuid4().hex
    unit = f"acp-credential-restart-{token}.service"
    runtime_directory = Path(runtime_directory_value)
    if _unit_properties(systemctl, unit).get("LoadState") != "not-found":
        raise RuntimeError(f"random credential restart unit already exists: {unit}")
    private_directory = Path(
        tempfile.mkdtemp(prefix="acp-credential-restart-", dir=runtime_directory)
    )
    directory_identity = private_directory.lstat()
    source_path = private_directory / "credential-source"
    starts_path = private_directory / "starts"
    report_path = private_directory / "credential-report.json"
    release_path = private_directory / "release"
    fake_secret = (uuid.uuid4().hex + uuid.uuid4().hex).encode("ascii")
    fake_digest = hashlib.sha256(fake_secret).hexdigest()
    launch_attempted = False
    first_unit: dict[str, str] = {}
    control_groups: set[str] = set()
    process_identities: set[tuple[int, str]] = set()
    cleanup_errors: list[str] = []
    try:
        if (
            directory_identity.st_uid != os.geteuid()
            or stat.S_IMODE(directory_identity.st_mode) != 0o700
            or not stat.S_ISDIR(directory_identity.st_mode)
        ):
            raise AssertionError("credential restart fixture directory is not private")
        descriptor = os.open(
            source_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            if os.write(descriptor, fake_secret) != len(fake_secret):
                raise RuntimeError("fake credential source write was incomplete")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        source_info = source_path.lstat()
        if (
            not stat.S_ISREG(source_info.st_mode)
            or source_info.st_uid != os.geteuid()
            or stat.S_IMODE(source_info.st_mode) != 0o600
        ):
            raise AssertionError("fake credential source is not private")

        # The first activation proves its copied credential survives source
        # removal. It then exits unsuccessfully so systemd must perform a real
        # automatic restart; a second process marker would mean the restart
        # improperly reused the old credential copy.
        worker = (
            "import hashlib,json,os,sys,time; from pathlib import Path; "
            "root=Path(sys.argv[1]); starts=root/'starts'; "
            "fd=os.open(starts,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600); "
            "os.write(fd,b'worker-started\\n'); os.close(fd); "
            "credential=Path(os.environ['CREDENTIALS_DIRECTORY'])/'launch'; "
            "before=credential.read_bytes(); "
            "deadline=time.monotonic()+10; "
            "exec(\"while not (root/'release').exists() and time.monotonic()<deadline: time.sleep(0.01)\"); "
            "after=credential.read_bytes(); "
            "report={'before_sha256':hashlib.sha256(before).hexdigest(), "
            "'after_sha256':hashlib.sha256(after).hexdigest(), "
            "'secret_in_environment':any(before.decode('ascii') in value for value in os.environ.values()), "
            "'credential_read_only':(credential.stat().st_mode&0o222)==0}; "
            "(root/'credential-report.json').write_text(json.dumps(report),encoding='ascii'); "
            "sys.exit(75)"
        )
        launch_attempted = True
        launch_output = _run(
            [
                systemd_run,
                "--user",
                f"--unit={unit}",
                "--property=Type=exec",
                "--property=RuntimeMaxSec=30s",
                "--property=Restart=on-failure",
                "--property=RestartSec=500ms",
                "--property=StartLimitIntervalSec=15s",
                "--property=StartLimitBurst=2",
                f"--property=LoadCredential=launch:{source_path}",
                "--no-block",
                sys.executable,
                "-c",
                worker,
                str(private_directory),
            ],
            timeout=10.0,
        )
        if fake_secret.decode("ascii") in launch_output.stdout + launch_output.stderr:
            raise AssertionError("systemd-run output exposed the fake credential")
        first_unit = _wait_active(systemctl, unit)
        if (
            first_unit.get("Id") != unit
            or first_unit.get("LoadState") != "loaded"
            or not first_unit.get("InvocationID")
            or not first_unit.get("ControlGroup")
        ):
            raise AssertionError("credential restart probe lacks an exact active unit identity")
        control_groups.add(first_unit["ControlGroup"])
        first_pid = int(first_unit.get("MainPID", "0"))
        first_identity = ProcessMixin._process_identity(first_pid) if first_pid > 0 else None
        if first_identity is None:
            raise AssertionError("first credential activation process identity was not observable")
        process_identities.add((first_pid, first_identity))

        deadline = time.monotonic() + _WAIT_SECONDS
        while not starts_path.is_file() and time.monotonic() < deadline:
            time.sleep(0.05)
        if not starts_path.is_file() or starts_path.read_bytes() != b"worker-started\n":
            raise AssertionError("first fake worker activation did not reach its read gate")

        # Unlink only the private, identity-checked source entry. systemd's
        # already-created credential copy must remain readable by this first
        # activation, while a later activation must resolve the now-missing
        # source anew.
        current_source = source_path.lstat()
        if (
            not stat.S_ISREG(current_source.st_mode)
            or (current_source.st_dev, current_source.st_ino)
            != (source_info.st_dev, source_info.st_ino)
            or current_source.st_uid != os.geteuid()
            or stat.S_IMODE(current_source.st_mode) != 0o600
        ):
            raise AssertionError("credential source identity changed before unlink")
        source_path.unlink()
        descriptor = os.open(
            release_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            if os.write(descriptor, b"release\n") != 8:
                raise RuntimeError("credential restart release marker write was incomplete")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

        deadline = time.monotonic() + _WAIT_SECONDS
        terminal: dict[str, str] = {}
        unit_status = ""
        restart_count = 0
        while time.monotonic() < deadline:
            observed = _run(
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
                    "--property=MainPID",
                    "--property=NRestarts",
                    "--property=Result",
                ]
            )
            terminal = dict(
                line.split("=", 1) for line in observed.stdout.splitlines() if "=" in line
            )
            if terminal.get("LoadState") == "not-found":
                status = _run(
                    [systemctl, "--user", "status", unit, "--no-pager", "--full"],
                    accepted_returncodes=(0, 3),
                )
                unit_status = status.stdout + status.stderr
                break
            if terminal.get("Id") != unit:
                raise AssertionError("credential restart unit identity changed")
            if terminal.get("ControlGroup"):
                control_groups.add(terminal["ControlGroup"])
            try:
                restart_count = int(terminal.get("NRestarts", "0"))
                main_pid = int(terminal.get("MainPID", "0"))
            except ValueError as error:
                raise AssertionError(
                    "systemd credential restart properties were invalid"
                ) from error
            if main_pid > 0:
                identity = ProcessMixin._process_identity(main_pid)
                if identity is not None:
                    process_identities.add((main_pid, identity))
            if terminal.get("ActiveState") == "failed" and restart_count >= 1:
                status = _run(
                    [systemctl, "--user", "status", unit, "--no-pager", "--full"],
                    accepted_returncodes=(0, 3),
                )
                unit_status = status.stdout + status.stderr
                break
            time.sleep(0.05)
        if restart_count < 1:
            raise AssertionError(
                f"systemd did not record the expected automatic restart: {terminal!r}"
            )
        if terminal.get("LoadState") != "loaded" or terminal.get("ActiveState") != "failed":
            raise AssertionError(
                f"restart did not fail closed on the missing credential: {terminal!r}"
            )
        if int(terminal.get("MainPID", "-1")) != 0:
            raise AssertionError("failed credential restart left a live main process")
        if not report_path.is_file():
            raise AssertionError("first activation did not re-read its copied credential")
        report = json.loads(report_path.read_text(encoding="ascii"))
        expected_report = {
            "before_sha256": fake_digest,
            "after_sha256": fake_digest,
            "secret_in_environment": False,
            "credential_read_only": True,
        }
        if report != expected_report:
            raise AssertionError(
                f"systemd credential copy changed after source removal: {report!r}"
            )
        if starts_path.read_bytes() != b"worker-started\n":
            raise AssertionError("restart executed a second worker without the removed source")
        if "243/CREDENTIALS" not in unit_status:
            raise AssertionError(
                "systemd did not report the credential-load failure for the restart; "
                f"unit={terminal!r}; status={unit_status!r}"
            )
        if fake_secret.decode("ascii") in unit_status:
            raise AssertionError("systemd status exposed the fake credential")
    finally:
        deadline = time.monotonic() + _WAIT_SECONDS
        terminal_unit = False
        last: dict[str, str] = {}
        if launch_attempted:
            try:
                subprocess.run(
                    [systemctl, "--user", "stop", unit],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=min(2.0, _WAIT_SECONDS),
                    env=_environment(),
                )
                subprocess.run(
                    [systemctl, "--user", "reset-failed", unit],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=min(2.0, _WAIT_SECONDS),
                    env=_environment(),
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                cleanup_errors.append(f"could not stop exact credential restart unit: {error}")
        while time.monotonic() < deadline:
            try:
                last = _unit_properties(systemctl, unit)
                if last.get("LoadState") == "not-found":
                    terminal_unit = True
                elif last.get("LoadState") == "loaded" and last.get("Id") == unit:
                    if last.get("ControlGroup"):
                        control_groups.add(last["ControlGroup"])
                    try:
                        main_pid = int(last.get("MainPID", "0"))
                    except ValueError:
                        cleanup_errors.append("credential restart MainPID was invalid")
                        break
                    if main_pid > 0:
                        identity = ProcessMixin._process_identity(main_pid)
                        if identity is not None:
                            process_identities.add((main_pid, identity))
                    if last.get("ActiveState") not in {"inactive", "failed"} or main_pid != 0:
                        subprocess.run(
                            [systemctl, "--user", "stop", unit],
                            check=False,
                            capture_output=True,
                            text=True,
                            timeout=min(2.0, _WAIT_SECONDS),
                            env=_environment(),
                        )
                    else:
                        subprocess.run(
                            [systemctl, "--user", "reset-failed", unit],
                            check=False,
                            capture_output=True,
                            text=True,
                            timeout=min(2.0, _WAIT_SECONDS),
                            env=_environment(),
                        )
                else:
                    cleanup_errors.append(f"credential restart unit identity is unknown: {last!r}")
                    break
                if (
                    terminal_unit
                    and all(_cgroup_is_empty(group) for group in control_groups)
                    and all(
                        ProcessMixin._process_identity(pid) != identity
                        for pid, identity in process_identities
                    )
                ):
                    break
            except (OSError, RuntimeError, AssertionError, subprocess.TimeoutExpired) as error:
                cleanup_errors.append(f"could not verify credential restart cleanup: {error}")
                break
            time.sleep(0.05)
        else:
            cleanup_errors.append(f"credential restart unit did not unload: {last!r}")
        if not terminal_unit:
            if not cleanup_errors:
                cleanup_errors.append(f"credential restart unit remained loaded: {last!r}")
        for control_group in control_groups:
            try:
                if not _cgroup_is_empty(control_group):
                    cleanup_errors.append(
                        f"credential restart cgroup remained populated: {control_group}"
                    )
            except (OSError, RuntimeError, AssertionError) as error:
                cleanup_errors.append(f"could not verify credential restart cgroup: {error}")
        if any(
            ProcessMixin._process_identity(pid) == identity for pid, identity in process_identities
        ):
            cleanup_errors.append("credential restart process identity remained alive")
        try:
            after = private_directory.lstat()
            if (
                (after.st_dev, after.st_ino)
                != (directory_identity.st_dev, directory_identity.st_ino)
                or after.st_uid != os.geteuid()
                or not stat.S_ISDIR(after.st_mode)
                or stat.S_IMODE(after.st_mode) != 0o700
                or private_directory.is_symlink()
            ):
                cleanup_errors.append("credential restart fixture directory identity changed")
            else:
                expected_entries = {"starts", "credential-report.json", "release"}
                if source_path.exists():
                    expected_entries.add(source_path.name)
                for entry in private_directory.iterdir():
                    info = entry.lstat()
                    if (
                        entry.name not in expected_entries
                        or not stat.S_ISREG(info.st_mode)
                        or info.st_uid != os.geteuid()
                        or entry.is_symlink()
                    ):
                        cleanup_errors.append(
                            f"unexpected credential restart fixture entry: {entry.name}"
                        )
        except OSError as error:
            cleanup_errors.append(
                f"credential restart fixture directory could not be verified: {error}"
            )
        if cleanup_errors:
            raise RuntimeError(
                "credential restart cleanup was not verified; private fixture retained at "
                f"{private_directory}: " + "; ".join(cleanup_errors)
            ) from sys.exc_info()[1]
        shutil.rmtree(private_directory)


def test_live_systemd_attaches_blocked_child_to_execution_scope_before_exec() -> None:
    """Prove StartTransientUnit(PIDs=...) moves the exact held child once."""

    import pytest

    if not _ENABLED:
        pytest.skip("set ACP_RUN_SYSTEMD_SLICE_INTEGRATION=1 on a disposable Linux host")
    if (
        not sys.platform.startswith("linux")
        or not Path("/sys/fs/cgroup/cgroup.controllers").is_file()
    ):
        raise RuntimeError("the runc-client scope probe requires Linux cgroup v2")
    systemctl = shutil.which("systemctl", path=_environment()["PATH"])
    if systemctl is None:
        raise RuntimeError("systemctl is required")
    manager_state = _run(
        [systemctl, "--user", "is-system-running"], accepted_returncodes=(0, 1)
    ).stdout.strip()
    if manager_state not in {"running", "degraded"}:
        raise RuntimeError(f"user systemd manager is not available: {manager_state!r}")

    token = uuid.uuid4().hex
    identity = (
        f"attempt-{token}",
        7,
        f"{token[:8]}-0000-4000-8000-{token[8:20]}",
    )
    attempt_slice_unit = sandbox_attempt_slice_unit(*identity)
    scope_unit = sandbox_runc_client_scope_unit(*identity)
    attempt_slice_started = False
    attempt_slice_binding: dict[str, str] | None = None
    attachment_attempted = False
    scope_binding: RuncClientScopeBinding | None = None
    child: subprocess.Popen[bytes] | None = None
    try:
        _run([systemctl, "--user", "start", attempt_slice_unit])
        attempt_slice_started = True
        attempt_slice_binding = _wait_active(systemctl, attempt_slice_unit)
        attempt_slice = attempt_slice_binding
        parent_snapshot = read_linux_process_snapshot(os.getpid())
        unified = [
            line.split(b":", 2)[2].decode("ascii")
            for line in parent_snapshot.cgroup.splitlines()
            if line.startswith(b"0::")
        ]
        if len(unified) != 1:
            raise RuntimeError("test controller has no unique cgroup-v2 membership")
        monitor_cgroup = unified[0]

        child = subprocess.Popen(
            _held_child_argv(),
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=_environment(),
        )
        pid_identity = _linux_process_identity(child.pid)
        if pid_identity is None:
            raise RuntimeError("held test child PID/start identity is unavailable")
        attachment_attempted = True
        scope = attach_held_runc_client_to_attempt_scope(
            expected_identity=identity,
            pid=child.pid,
            pid_identity=pid_identity,
            monitor_control_group=monitor_cgroup,
            attempt_slice_invocation_id=attempt_slice["InvocationID"],
            attempt_slice_control_group=attempt_slice["ControlGroup"],
        )
        scope_binding = scope
        if scope.scope_unit != scope_unit or _linux_process_identity(child.pid) != pid_identity:
            raise RuntimeError("runc client PID or deterministic unit identity changed at attach")

        if child.stdin is None:
            raise RuntimeError("held test child stdin gate is unavailable")
        child.stdin.write(b"x")
        child.stdin.close()
        if child.poll() is not None:
            detail = child.stderr.read().decode("utf-8", errors="replace") if child.stderr else ""
            raise RuntimeError(f"held child exited before scope cancellation: {detail}")

        if not _stop_exact_runc_client_scope(systemctl, scope_binding):
            raise RuntimeError("runc client scope activation changed before cancellation")
        child.wait(timeout=_WAIT_SECONDS)
        _wait_inactive(systemctl, scope_unit)
        if _linux_process_identity_if_present(child.pid) is not None:
            raise RuntimeError("systemd scope stop left the held child alive")
    finally:
        _cleanup_held_scope_probe(
            systemctl=systemctl,
            attempt_slice_started=attempt_slice_started,
            attempt_slice_binding=attempt_slice_binding,
            attachment_attempted=attachment_attempted,
            scope_binding=scope_binding,
            child=child,
        )


if __name__ == "__main__":
    arguments = sys.argv[1:]
    if arguments and arguments[0] == "--start-production-monitor":
        if len(arguments) != 9:
            raise SystemExit("start-production-monitor mode requires eight arguments")
        _start_production_monitor_controller(
            state_path=Path(arguments[1]),
            attempt_id=arguments[2],
            claim_token=int(arguments[3]),
            execution_id=arguments[4],
            scope_unit=arguments[5],
            scope_invocation_id=arguments[6],
            scope_control_group=arguments[7],
            attempt_slice_control_group=arguments[8],
        )
    elif arguments and arguments[0] == "--monitor-controller":
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
