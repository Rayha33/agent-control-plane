from __future__ import annotations

import os
import socket
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest

import agent_control_plane.supervisor.sandbox_monitor_lifecycle as lifecycle
from agent_control_plane.supervisor.sandbox_monitor_ipc import (
    SandboxMonitorControlClient,
    SandboxMonitorControlServer,
    _linux_process_identity,
)
from agent_control_plane.supervisor.sandbox_monitor_receipt import (
    SandboxMonitorReceipt,
    SandboxMonitorReceiptError,
    load_or_create_sandbox_monitor_control_key,
    sandbox_attempt_slice_unit,
    sandbox_container_id,
    sandbox_monitor_service_unit,
    write_sandbox_monitor_receipt,
)


def _receipt() -> SandboxMonitorReceipt:
    attempt_id = "attempt-live"
    claim_token = 17
    execution_id = "a" * 32
    main_pid = os.getpid() + 1000
    monitor_slice_unit = "user-acp.slice"
    monitor_slice_cgroup = "/user.slice/user-1000.slice/user@1000.service/user-acp.slice"
    unit = sandbox_monitor_service_unit(attempt_id, claim_token, execution_id)
    attempt_slice_unit = sandbox_attempt_slice_unit(attempt_id, claim_token, execution_id)
    return SandboxMonitorReceipt(
        version=1,
        controller_pid=os.getpid() + 1,
        attempt_id=attempt_id,
        claim_token=claim_token,
        execution_id=execution_id,
        unit=unit,
        invocation_id="b" * 32,
        control_group=f"{monitor_slice_cgroup}/{unit}",
        main_pid=main_pid,
        main_identity=f"linux:{main_pid}:123456",
        monitor_slice_unit=monitor_slice_unit,
        monitor_slice_control_group=monitor_slice_cgroup,
        attempt_slice_unit=attempt_slice_unit,
        attempt_slice_control_group=f"{monitor_slice_cgroup}/{attempt_slice_unit}",
    )


def _properties(receipt: SandboxMonitorReceipt) -> dict[str, dict[str, str]]:
    return {
        receipt.unit: {
            "Id": receipt.unit,
            "LoadState": "loaded",
            "ActiveState": "active",
            "InvocationID": receipt.invocation_id,
            "ControlGroup": receipt.control_group,
            "Slice": receipt.monitor_slice_unit,
            "MainPID": str(receipt.main_pid),
        },
        receipt.monitor_slice_unit: {
            "Id": receipt.monitor_slice_unit,
            "LoadState": "loaded",
            "ActiveState": "active",
            "ControlGroup": receipt.monitor_slice_control_group,
        },
        receipt.attempt_slice_unit: {
            "Id": receipt.attempt_slice_unit,
            "LoadState": "loaded",
            "ActiveState": "active",
            "Slice": receipt.monitor_slice_unit,
            "ControlGroup": receipt.attempt_slice_control_group,
        },
    }


def _install_systemd_observers(
    monkeypatch: pytest.MonkeyPatch,
    receipt: SandboxMonitorReceipt,
    observed: dict[str, dict[str, str]],
) -> list[list[str]]:
    calls: list[list[str]] = []

    def run(argv: list[str], *, environment: dict[str, str]) -> bytes:
        assert environment == {"PATH": "/usr/bin:/bin"}
        assert argv[1:4] == ["--user", "show", "--no-pager"]
        assert argv[-2] == "--"
        unit = argv[-1]
        fields = argv[-3].removeprefix("--property=").split(",")
        assert set(fields) == set(observed[unit])
        calls.append(argv)
        return "\n".join(f"{field}={observed[unit][field]}" for field in fields).encode("ascii")

    monkeypatch.setattr(lifecycle, "_run_trusted_runtime_command", run)
    monkeypatch.setattr(
        lifecycle, "_trusted_systemctl_executable", lambda: Path("/usr/bin/systemctl")
    )
    monkeypatch.setattr(
        lifecycle, "_trusted_systemd_command_environment", lambda: {"PATH": "/usr/bin:/bin"}
    )
    monkeypatch.setattr(lifecycle.sys, "platform", "linux")
    monkeypatch.setattr(
        lifecycle,
        "_linux_process_identity",
        lambda pid: receipt.main_identity if pid == receipt.main_pid else None,
    )
    return calls


@contextmanager
def _private_control_dir() -> Iterator[Path]:
    temporary_root = Path("/private/tmp")
    if not temporary_root.is_dir():
        temporary_root = Path(tempfile.gettempdir())
    with tempfile.TemporaryDirectory(prefix="acpmon-", dir=temporary_root) as raw:
        path = Path(raw)
        path.chmod(0o700)
        yield path


def _bound_socket(path: Path) -> socket.socket:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    os.chmod(path, 0o600)
    listener.listen(1)
    return listener


def test_reconcile_requires_exact_fence_and_all_systemd_activation_identities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _receipt()
    observed = _properties(receipt)
    calls = _install_systemd_observers(monkeypatch, receipt, observed)

    lifecycle.reconcile_sandbox_monitor(
        receipt,
        expected_identity=(receipt.attempt_id, receipt.claim_token, receipt.execution_id),
    )
    assert len(calls) == 3
    assert all(call[-2] == "--" for call in calls)

    observed[receipt.unit]["InvocationID"] = "c" * 32
    with pytest.raises(SandboxMonitorReceiptError, match="no longer matches"):
        lifecycle.reconcile_sandbox_monitor(
            receipt,
            expected_identity=(receipt.attempt_id, receipt.claim_token, receipt.execution_id),
        )

    before = len(calls)
    with pytest.raises(SandboxMonitorReceiptError, match="another fenced execution"):
        lifecycle.reconcile_sandbox_monitor(
            receipt,
            expected_identity=(receipt.attempt_id, receipt.claim_token + 1, receipt.execution_id),
        )
    assert len(calls) == before


def test_reconnect_adopts_only_existing_key_after_systemd_reconciliation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _receipt()
    with _private_control_dir() as directory:
        receipt_path = directory / "monitor-receipt.json"
        socket_path = directory / "monitor.sock"
        write_sandbox_monitor_receipt(receipt_path, receipt)
        key = load_or_create_sandbox_monitor_control_key(
            directory,
            attempt_id=receipt.attempt_id,
            claim_token=receipt.claim_token,
            execution_id=receipt.execution_id,
        )
        listener = _bound_socket(socket_path)
        calls = _install_systemd_observers(monkeypatch, receipt, _properties(receipt))
        try:
            client = lifecycle.reconnect_sandbox_monitor(
                receipt_path=receipt_path,
                control_directory=directory,
                socket_path=socket_path,
                expected_identity=(receipt.attempt_id, receipt.claim_token, receipt.execution_id),
            )
            assert isinstance(client, SandboxMonitorControlClient)
            assert client._receipt == receipt
            assert client._key == key
            assert len(calls) == 3
        finally:
            listener.close()


@pytest.mark.skipif(not hasattr(socket, "SO_PEERCRED"), reason="monitor IPC requires Linux")
def test_reconnected_client_authenticates_monitor_and_reads_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _receipt()
    receipt = replace(
        receipt,
        main_pid=os.getpid(),
        main_identity=_linux_process_identity(os.getpid()),
    )
    with _private_control_dir() as directory:
        receipt_path = directory / "monitor-receipt.json"
        socket_path = directory / "monitor.sock"
        write_sandbox_monitor_receipt(receipt_path, receipt)
        key = load_or_create_sandbox_monitor_control_key(
            directory,
            attempt_id=receipt.attempt_id,
            claim_token=receipt.claim_token,
            execution_id=receipt.execution_id,
        )
        calls = _install_systemd_observers(monkeypatch, receipt, _properties(receipt))
        server = SandboxMonitorControlServer(
            socket_path=socket_path,
            request_directory=directory,
            key=key,
            expected_identity=(receipt.attempt_id, receipt.claim_token, receipt.execution_id),
            expected_uid=os.geteuid(),
            status_provider=lambda: {"phase": "running", "worker_pid": 1234},
            cancel_action=lambda: {"phase": "stopping", "worker_pid": 1234},
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        deadline = time.monotonic() + 2
        try:
            while time.monotonic() < deadline:
                with server._lifecycle_lock:
                    if server._serving:
                        break
                time.sleep(0.001)
            else:
                pytest.fail("monitor control server did not enter its serving loop")

            client = lifecycle.reconnect_sandbox_monitor(
                receipt_path=receipt_path,
                control_directory=directory,
                socket_path=socket_path,
                expected_identity=(receipt.attempt_id, receipt.claim_token, receipt.execution_id),
            )
            response = client.status()
            assert response.outcome == "ok"
            assert response.payload == {"phase": "running", "worker_pid": 1234}
            assert len(calls) == 3
        finally:
            server.close()
            thread.join(timeout=2)
            assert not thread.is_alive()


def test_reconnect_with_missing_key_fails_closed_without_minting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _receipt()
    with _private_control_dir() as directory:
        receipt_path = directory / "monitor-receipt.json"
        socket_path = directory / "monitor.sock"
        write_sandbox_monitor_receipt(receipt_path, receipt)
        listener = _bound_socket(socket_path)
        _install_systemd_observers(monkeypatch, receipt, _properties(receipt))
        try:
            with pytest.raises(
                SandboxMonitorReceiptError, match="execution remains fenced"
            ) as error:
                lifecycle.reconnect_sandbox_monitor(
                    receipt_path=receipt_path,
                    control_directory=directory,
                    socket_path=socket_path,
                    expected_identity=(
                        receipt.attempt_id,
                        receipt.claim_token,
                        receipt.execution_id,
                    ),
                )
            assert "refusing to mint a replacement" in str(error.value.__cause__)
            key_name = f"{sandbox_container_id(receipt.attempt_id, receipt.claim_token, receipt.execution_id)}.control-key"
            assert not (directory / key_name).exists()
            assert not list(directory.glob(".*.control-key.lock"))
        finally:
            listener.close()
