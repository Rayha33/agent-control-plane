from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

import agent_control_plane.supervisor.sandbox_monitor_ipc as ipc_module
from agent_control_plane.supervisor.sandbox_monitor_ipc import (
    SandboxMonitorControlClient,
    SandboxMonitorControlServer,
    SandboxMonitorIPCError,
)
from agent_control_plane.supervisor.sandbox_monitor_receipt import (
    SandboxMonitorReceipt,
    encode_sandbox_monitor_control_request,
    sandbox_attempt_slice_unit,
    sandbox_monitor_service_unit,
)

pytestmark = pytest.mark.skipif(
    not hasattr(socket, "SO_PEERCRED"), reason="monitor control IPC requires Linux SO_PEERCRED"
)

_KEY = b"x" * 32


def _process_identity(pid: int) -> str:
    record = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    closing = record.rfind(")")
    start_time = int(record[closing + 2 :].split()[19])
    return f"linux:{pid}:{start_time}"


def _receipt(main_pid: int | None = None) -> SandboxMonitorReceipt:
    pid = os.getpid() if main_pid is None else main_pid
    attempt_id = "attempt-1"
    claim_token = 7
    execution_id = "execution-1"
    monitor_slice_unit = "app.slice"
    monitor_slice_cgroup = "/user.slice/user-1000.slice/user@1000.service/app.slice"
    unit = sandbox_monitor_service_unit(attempt_id, claim_token, execution_id)
    attempt_slice_unit = sandbox_attempt_slice_unit(attempt_id, claim_token, execution_id)
    return SandboxMonitorReceipt(
        version=1,
        controller_pid=pid + 1,
        attempt_id=attempt_id,
        claim_token=claim_token,
        execution_id=execution_id,
        unit=unit,
        invocation_id="a" * 32,
        control_group=f"{monitor_slice_cgroup}/{unit}",
        main_pid=pid,
        main_identity=_process_identity(pid),
        monitor_slice_unit=monitor_slice_unit,
        monitor_slice_control_group=monitor_slice_cgroup,
        attempt_slice_unit=attempt_slice_unit,
        attempt_slice_control_group=f"{monitor_slice_cgroup}/{attempt_slice_unit}",
    )


def _request(receipt: SandboxMonitorReceipt, operation: str, request_id: str) -> bytes:
    return encode_sandbox_monitor_control_request(
        attempt_id=receipt.attempt_id,
        claim_token=receipt.claim_token,
        execution_id=receipt.execution_id,
        request_id=request_id,
        operation=operation,
        key=_KEY,
    )


def _scope_identity() -> dict[str, str]:
    return {
        "scope_unit": "acp-test.scope",
        "scope_invocation_id": "b" * 32,
        "scope_control_group": "/user.slice/acp-test.scope",
    }


def _server(
    tmp_path: Path,
    *,
    status_provider=None,
    cancel_action=None,
    request_limit: int = 256,
) -> tuple[SandboxMonitorControlServer, SandboxMonitorReceipt, Path, Path]:
    os.chmod(tmp_path, 0o700)
    private = tmp_path / "execution"
    private.mkdir(mode=0o700)
    os.chmod(private, 0o700)
    receipt = _receipt()
    server = SandboxMonitorControlServer(
        socket_path=private / "monitor.sock",
        request_directory=private,
        key=_KEY,
        expected_identity=(receipt.attempt_id, receipt.claim_token, receipt.execution_id),
        expected_uid=os.geteuid(),
        status_provider=status_provider or (lambda: {"phase": "running", "worker_pid": 500}),
        cancel_action=cancel_action
        or (lambda: {"phase": "exited", "worker_pid": 500, "cancel_method": "graceful"}),
        request_limit=request_limit,
    )
    return server, receipt, private / "monitor.sock", private


def _serve(server: SandboxMonitorControlServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def _stop(server: SandboxMonitorControlServer, thread: threading.Thread) -> None:
    server.close()
    thread.join(timeout=2)
    assert not thread.is_alive()


def _wait_until_serving(server: SandboxMonitorControlServer) -> None:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        with server._lifecycle_lock:
            if server._serving:
                return
        time.sleep(0.001)
    pytest.fail("monitor control server did not enter its serving loop")


def test_monitor_client_authenticates_systemd_owned_server_and_round_trips_status_cancel(
    tmp_path: Path,
) -> None:
    calls = {"status": 0, "cancel": 0}

    def status() -> dict[str, object]:
        calls["status"] += 1
        return {"phase": "running", "worker_pid": 500}

    def cancel() -> dict[str, object]:
        calls["cancel"] += 1
        return {
            "phase": "exited",
            "worker_pid": 500,
            "cancel_method": "graceful",
            **_scope_identity(),
        }

    server, receipt, socket_path, private = _server(
        tmp_path, status_provider=status, cancel_action=cancel
    )
    thread = _serve(server)
    try:
        client = SandboxMonitorControlClient(
            receipt=receipt,
            socket_path=socket_path,
            key=_KEY,
            expected_uid=os.geteuid(),
            control_directory=private,
        )
        status_response = client.status()
        with pytest.raises(SandboxMonitorIPCError, match="caller-held"):
            client.cancel(None)  # type: ignore[arg-type]
        cancel_response = client.cancel(request_id="a" * 32)
        retried_cancel_response = client.cancel(request_id="a" * 32)
        assert status_response.operation == "status"
        assert status_response.outcome == "ok"
        assert status_response.payload == {"phase": "running", "worker_pid": 500}
        assert cancel_response.operation == "cancel"
        assert cancel_response.outcome == "ok"
        assert cancel_response.payload == {
            "phase": "exited",
            "worker_pid": 500,
            **_scope_identity(),
        }
        assert cancel_response.cancel_attestation is not None
        assert cancel_response.cancel_attestation.request_id == "a" * 32
        assert (
            cancel_response.cancel_attestation.request_sha256
            == hashlib.sha256(_request(receipt, "cancel", "a" * 32)).hexdigest()
        )
        assert cancel_response.cancel_attestation.method == "graceful"
        assert cancel_response.cancel_attestation.phase == "exited"
        assert cancel_response.cancel_attestation.scope_identity == _scope_identity()
        attestation_path = private / f"r-{'a' * 32}.cancel-attestation"
        attestation_record = json.loads(attestation_path.read_text(encoding="ascii"))
        assert set(attestation_record) == {
            "format",
            "request_id",
            "request_sha256",
            "identity",
            "outcome",
            "phase",
            "method",
            "scope_identity",
            "mac",
        }
        assert attestation_record["identity"] == {
            "attempt_id": receipt.attempt_id,
            "claim_token": receipt.claim_token,
            "execution_id": receipt.execution_id,
        }
        assert attestation_path.stat().st_mode & 0o777 == 0o600
        assert retried_cancel_response == cancel_response
        assert calls == {"status": 1, "cancel": 1}
    finally:
        _stop(server, thread)
    assert not socket_path.exists()


def test_monitor_control_client_cannot_be_reused_from_a_forked_process(
    tmp_path: Path,
) -> None:
    if not hasattr(os, "fork"):
        pytest.skip("fork is unavailable on this platform")
    calls = {"status": 0, "cancel": 0}

    def status() -> dict[str, object]:
        calls["status"] += 1
        return {"phase": "running", "worker_pid": 500}

    def cancel() -> dict[str, object]:
        calls["cancel"] += 1
        return {"phase": "exited", "worker_pid": 500, "cancel_method": "graceful"}

    server, receipt, socket_path, _private = _server(
        tmp_path, status_provider=status, cancel_action=cancel
    )
    thread = _serve(server)
    client = SandboxMonitorControlClient(
        receipt=receipt,
        socket_path=socket_path,
        key=_KEY,
        expected_uid=os.geteuid(),
    )
    receiver, sender = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:
        os.close(receiver)
        outcomes: dict[str, str] = {}
        for operation in ("status", "cancel"):
            try:
                if operation == "status":
                    client.status()
                else:
                    client.cancel("f" * 32)
            except SandboxMonitorIPCError as error:
                outcomes[operation] = str(error)
            else:
                outcomes[operation] = "accepted"
        os.write(sender, json.dumps(outcomes, sort_keys=True).encode("ascii"))
        os.close(sender)
        os._exit(0)
    os.close(sender)
    try:
        child_outcomes = json.loads(os.read(receiver, 4096).decode("ascii"))
        _waited_pid, status_code = os.waitpid(child_pid, 0)
        assert os.WIFEXITED(status_code) and os.WEXITSTATUS(status_code) == 0
        assert child_outcomes == {
            "status": "monitor control client cannot be reused after fork",
            "cancel": "monitor control client cannot be reused after fork",
        }
        assert client.status().outcome == "ok"
        assert client.cancel("e" * 32).outcome == "ok"
        assert calls == {"status": 1, "cancel": 1}
    finally:
        os.close(receiver)
        _stop(server, thread)

    assert not socket_path.exists()


def test_server_rejects_a_second_concurrent_serving_loop(tmp_path: Path) -> None:
    server, _receipt_value, _socket_path, _private = _server(tmp_path)
    thread = _serve(server)
    try:
        _wait_until_serving(server)
        with pytest.raises(SandboxMonitorIPCError, match="already serving"):
            server.serve_forever()
    finally:
        _stop(server, thread)


def test_server_rejects_restart_after_unexpected_loop_exit(tmp_path: Path) -> None:
    server, _receipt_value, _socket_path, _private = _server(tmp_path)
    cleanup_started = threading.Event()
    finish_cleanup = threading.Event()
    original_cleanup = server._cleanup

    def hold_cleanup() -> None:
        cleanup_started.set()
        assert finish_cleanup.wait(timeout=2)
        original_cleanup()

    server._cleanup = hold_cleanup  # type: ignore[method-assign]
    failures: list[OSError] = []

    def serve() -> None:
        try:
            server.serve_forever()
        except OSError as error:
            failures.append(error)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    _wait_until_serving(server)
    listener = server._listener
    assert listener is not None
    listener.close()
    try:
        assert cleanup_started.wait(timeout=2)
        with pytest.raises(SandboxMonitorIPCError, match="closed"):
            server.serve_forever()
    finally:
        finish_cleanup.set()
        server.close()
        thread.join(timeout=2)
        assert not thread.is_alive()
    assert failures


def test_cancel_request_id_replay_returns_durable_response_without_repeating_action(
    tmp_path: Path,
) -> None:
    calls = 0

    def cancel() -> dict[str, str]:
        nonlocal calls
        calls += 1
        return {"phase": "exited", "cancel_method": "sigkill"}

    server, receipt, _socket_path, private = _server(tmp_path, cancel_action=cancel)
    try:
        encoded = _request(receipt, "cancel", "c" * 32)
        first = server._dispatch(os.geteuid(), encoded)
        second = server._dispatch(os.geteuid(), encoded)
        assert first == second
        assert calls == 1
        accepted = private / f"r-{'c' * 32}.accepted"
        response = private / f"r-{'c' * 32}.response"
        assert accepted.stat().st_mode & 0o777 == 0o600
        assert response.stat().st_mode & 0o777 == 0o600
        assert accepted.stat().st_nlink == response.stat().st_nlink == 1
    finally:
        server.close()


def test_read_only_request_does_not_change_a_cancel_replay_record(tmp_path: Path) -> None:
    calls = 0

    def cancel() -> dict[str, str]:
        nonlocal calls
        calls += 1
        return {"phase": "exited", "cancel_method": "graceful"}

    server, receipt, _socket_path, _private = _server(tmp_path, cancel_action=cancel)
    try:
        cancel_request = _request(receipt, "cancel", "d" * 32)
        first = server._dispatch(os.geteuid(), cancel_request)
        status = server._dispatch(os.geteuid(), _request(receipt, "status", "d" * 32))
        replay = server._dispatch(os.geteuid(), cancel_request)
        assert first == replay
        assert json.loads(status)["operation"] == "status"
        assert calls == 1
    finally:
        server.close()


def test_accepted_without_response_is_reported_unknown_without_reapplying(tmp_path: Path) -> None:
    calls = 0

    def cancel() -> dict[str, str]:
        nonlocal calls
        calls += 1
        return {"phase": "exited", "cancel_method": "graceful"}

    server, receipt, _socket_path, _private = _server(tmp_path, cancel_action=cancel)
    try:
        request_id = "e" * 32
        encoded = _request(receipt, "cancel", request_id)
        accepted = {
            "version": 1,
            "request_sha256": hashlib.sha256(encoded).hexdigest(),
            "operation": "cancel",
        }
        ipc_module._create_private_record(
            server._ledger_fd,
            f"r-{request_id}.accepted",
            ipc_module._canonical_json(accepted),
        )
        first = server._dispatch(os.geteuid(), encoded)
        second = server._dispatch(os.geteuid(), encoded)
        assert first == second
        assert json.loads(first)["outcome"] == "unknown"
        assert calls == 0
    finally:
        server.close()


def test_peer_uid_and_fencing_identity_are_checked_before_side_effects(tmp_path: Path) -> None:
    calls = 0

    def cancel() -> dict[str, str]:
        nonlocal calls
        calls += 1
        return {"phase": "exited", "cancel_method": "graceful"}

    server, receipt, _socket_path, _private = _server(tmp_path, cancel_action=cancel)
    try:
        with pytest.raises(SandboxMonitorIPCError, match="peer UID"):
            server._dispatch(os.geteuid() + 1, _request(receipt, "cancel", "f" * 32))
        stale = encode_sandbox_monitor_control_request(
            attempt_id=receipt.attempt_id,
            claim_token=receipt.claim_token + 1,
            execution_id=receipt.execution_id,
            request_id="f" * 32,
            operation="cancel",
            key=_KEY,
        )
        with pytest.raises(SandboxMonitorIPCError, match="authentication failed"):
            server._dispatch(os.geteuid(), stale)
        assert calls == 0
    finally:
        server.close()


def test_client_rejects_connected_process_with_wrong_pid_start_identity(tmp_path: Path) -> None:
    server, receipt, socket_path, _private = _server(tmp_path)
    thread = _serve(server)
    try:
        incorrect_receipt = replace(receipt, main_identity=f"linux:{receipt.main_pid}:1")
        client = SandboxMonitorControlClient(
            receipt=incorrect_receipt,
            socket_path=socket_path,
            key=_KEY,
            expected_uid=os.geteuid(),
        )
        with pytest.raises(SandboxMonitorIPCError, match="start identity changed"):
            client.status()
    finally:
        _stop(server, thread)


def test_monitor_refuses_existing_socket_path_instead_of_unlinking_it(tmp_path: Path) -> None:
    os.chmod(tmp_path, 0o700)
    private = tmp_path / "execution"
    private.mkdir(mode=0o700)
    os.chmod(private, 0o700)
    socket_path = private / "monitor.sock"
    socket_path.write_text("do not remove", encoding="ascii")
    receipt = _receipt()
    with pytest.raises(SandboxMonitorIPCError, match="already exists"):
        SandboxMonitorControlServer(
            socket_path=socket_path,
            request_directory=private,
            key=_KEY,
            expected_identity=(receipt.attempt_id, receipt.claim_token, receipt.execution_id),
            expected_uid=os.geteuid(),
            status_provider=lambda: {"phase": "running"},
            cancel_action=lambda: {"phase": "exited", "cancel_method": "graceful"},
        )
    assert socket_path.read_text(encoding="ascii") == "do not remove"


def test_monitor_status_payload_rejects_secret_or_arbitrary_fields(tmp_path: Path) -> None:
    server, receipt, _socket_path, _private = _server(
        tmp_path,
        status_provider=lambda: {"phase": "running", "cancel_method": "sigkill"},
    )
    try:
        response = server._dispatch(os.geteuid(), _request(receipt, "status", "1" * 32))
        assert json.loads(response)["outcome"] == "unknown"
        assert json.loads(response)["payload"] == {"phase": "unknown"}
    finally:
        server.close()


def test_cancel_response_is_unknown_unless_monitor_reports_stopping_or_exited(
    tmp_path: Path,
) -> None:
    server, receipt, _socket_path, _private = _server(
        tmp_path, cancel_action=lambda: {"phase": "running", "cancel_method": "graceful"}
    )
    try:
        response = server._dispatch(os.geteuid(), _request(receipt, "cancel", "2" * 32))
        decoded = json.loads(response)
        assert decoded["outcome"] == "unknown"
        assert decoded["payload"] == {"phase": "unknown"}
    finally:
        server.close()


def test_cancel_response_is_unknown_for_an_unrecognized_local_method(tmp_path: Path) -> None:
    server, receipt, _socket_path, _private = _server(
        tmp_path,
        cancel_action=lambda: {"phase": "exited", "cancel_method": "not-a-monitor-method"},
    )
    try:
        response = server._dispatch(os.geteuid(), _request(receipt, "cancel", "4" * 32))
        decoded = json.loads(response)
        assert decoded["outcome"] == "unknown"
        assert decoded["payload"] == {"phase": "unknown"}
    finally:
        server.close()


def test_successful_cancel_response_requires_a_recognized_method(tmp_path: Path) -> None:
    server, receipt, _socket_path, _private = _server(
        tmp_path, cancel_action=lambda: {"phase": "exited"}
    )
    try:
        response = server._dispatch(os.geteuid(), _request(receipt, "cancel", "3" * 32))
        decoded = json.loads(response)
        assert decoded["outcome"] == "unknown"
        assert decoded["payload"] == {"phase": "unknown"}
    finally:
        server.close()


def test_cancel_v1_response_stays_compatible_when_attestation_is_unavailable(
    tmp_path: Path,
) -> None:
    server, receipt, socket_path, private = _server(
        tmp_path,
        cancel_action=lambda: {"phase": "exited", "cancel_method": "graceful"},
    )
    thread = _serve(server)
    try:
        client = SandboxMonitorControlClient(
            receipt=receipt,
            socket_path=socket_path,
            key=_KEY,
            expected_uid=os.geteuid(),
            control_directory=private,
        )
        response = client.cancel("5" * 32)
        assert response.outcome == "ok"
        assert response.payload == {"phase": "exited"}
        assert response.cancel_attestation is None
        stored, _decoded = server._load_response("5" * 32, "cancel") or (b"", None)
        wire = json.loads(stored)
        assert wire["version"] == 1
        assert set(wire) == {"version", "request_id", "operation", "outcome", "payload", "mac"}
        assert wire["payload"] == {"phase": "exited"}
        assert "cancel_method" not in wire["payload"]
    finally:
        _stop(server, thread)


def test_cancel_attestation_write_failure_does_not_fail_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_create = ipc_module._create_private_record

    def fail_attestation_write(directory_fd: int, name: str, data: bytes) -> None:
        if name.endswith(".cancel-attestation"):
            raise OSError("synthetic sidecar write failure")
        original_create(directory_fd, name, data)

    monkeypatch.setattr(ipc_module, "_create_private_record", fail_attestation_write)
    server, receipt, socket_path, private = _server(
        tmp_path,
        cancel_action=lambda: {
            "phase": "exited",
            "cancel_method": "sigkill",
            **_scope_identity(),
        },
    )
    thread = _serve(server)
    try:
        client = SandboxMonitorControlClient(
            receipt=receipt,
            socket_path=socket_path,
            key=_KEY,
            expected_uid=os.geteuid(),
            control_directory=private,
        )

        response = client.cancel("7" * 32)

        assert response.outcome == "ok"
        assert response.payload["phase"] == "exited"
        assert response.cancel_attestation is None
        assert server._load_response("7" * 32, "cancel") is not None
    finally:
        _stop(server, thread)


def test_corrupt_cancel_attestation_only_removes_method_evidence(tmp_path: Path) -> None:
    calls = 0

    def cancel() -> dict[str, str]:
        nonlocal calls
        calls += 1
        return {"phase": "exited", "cancel_method": "sigkill", **_scope_identity()}

    server, receipt, socket_path, private = _server(tmp_path, cancel_action=cancel)
    thread = _serve(server)
    request_id = "6" * 32
    try:
        client = SandboxMonitorControlClient(
            receipt=receipt,
            socket_path=socket_path,
            key=_KEY,
            expected_uid=os.geteuid(),
            control_directory=private,
        )
        first = client.cancel(request_id)
        assert first.outcome == "ok"
        assert first.cancel_attestation is not None
        attestation_path = private / ipc_module._cancel_attestation_record_name(request_id)
        attestation = json.loads(attestation_path.read_text(encoding="ascii"))
        attestation["method"] = "graceful"
        attestation_path.write_bytes(ipc_module._canonical_json(attestation))

        replay = client.cancel(request_id)

        assert replay.outcome == "ok"
        assert replay.payload["phase"] == "exited"
        assert replay.cancel_attestation is None
        assert calls == 1
    finally:
        _stop(server, thread)


def test_read_only_status_polling_does_not_consume_cancel_replay_limit(tmp_path: Path) -> None:
    calls = 0

    def status() -> dict[str, str]:
        nonlocal calls
        calls += 1
        return {"phase": "running"}

    server, receipt, _socket_path, private = _server(
        tmp_path, status_provider=status, request_limit=1
    )
    try:
        for request_number in range(20):
            server._dispatch(os.geteuid(), _request(receipt, "status", f"{request_number:032x}"))
        assert calls == 20
        assert not list(private.glob("*.accepted"))
        server._dispatch(os.geteuid(), _request(receipt, "cancel", "9" * 32))
        assert len(list(private.glob("*.accepted"))) == 1
    finally:
        server.close()
