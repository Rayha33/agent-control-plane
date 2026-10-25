from __future__ import annotations

import fcntl
import hashlib
import json
import os
import socket
import sqlite3
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from support import init_repo, make_task

from agent_control_plane.supervisor import sandbox_execution_journal as journal
from agent_control_plane.supervisor.common import RuntimePortPool, SupervisorError, canonical_json
from agent_control_plane.supervisor.sandbox_launch_driver_service import (
    SandboxLaunchDriverServiceError,
    _provider_credential_pipe,
    _read_provider_credential_fd,
    _read_request,
    _read_service_provider_credential,
    _read_service_runner_credential,
    _read_service_test_worker_canary,
    _request_driver_failure_stop_and_cancel_monitor,
    _request_timeout_stop_and_cancel_monitor,
    _test_worker_canary_pipe,
    _validate_request,
    _wait_for_driver_running_handoff,
    _wait_for_runc_with_attempt_heartbeat,
    _write_request,
    start_registered_no_model_sandbox_worker,
    start_sandbox_launch_driver,
)
from agent_control_plane.supervisor.sandbox_monitor_receipt import (
    sandbox_attempt_slice_unit,
    sandbox_monitor_service_unit,
)

_IDENTITY = ("attempt-1", 7, "execution-1")
_RUNTIME_TMP_DIR = Path("/private/tmp")
if not _RUNTIME_TMP_DIR.is_dir() or _RUNTIME_TMP_DIR.is_symlink():
    _RUNTIME_TMP_DIR = Path("/tmp")
_RESOURCES = {
    "memory_max_bytes": 64 * 1024 * 1024,
    "cpu_quota": 100_000,
    "cpu_period": 100_000,
    "pids_max": 32,
}
_PROVIDER_CREDENTIAL_POLICY = "read-only-fd4-v1"


def _sealed_memfd(payload: bytes, *, seals: int | None = None) -> int:
    if not hasattr(os, "memfd_create") or not hasattr(os, "MFD_ALLOW_SEALING"):
        pytest.skip("sealed memfd is only available on supported Linux hosts")
    flags = os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
    descriptor = os.memfd_create("acp-test-provider", flags)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        if seals is None:
            seals = (
                getattr(fcntl, "F_SEAL_WRITE", 0x0008)
                | getattr(fcntl, "F_SEAL_GROW", 0x0004)
                | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
                | getattr(fcntl, "F_SEAL_SEAL", 0x0001)
            )
        fcntl.fcntl(descriptor, getattr(fcntl, "F_ADD_SEALS", 1033), seals)
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _request(command: list[str] | tuple[str, ...] = ("/bin/busybox", "true")) -> dict:
    return _validate_request(
        expected_identity=_IDENTITY,
        command=command,
        memory_max_bytes=_RESOURCES["memory_max_bytes"],
        cpu_quota=_RESOURCES["cpu_quota"],
        cpu_period=_RESOURCES["cpu_period"],
        pids_max=_RESOURCES["pids_max"],
        timeout_seconds=30,
    )


def test_request_freezes_mutable_command_before_validation() -> None:
    command = ["/bin/busybox", "true"]

    request = _request(command)
    command[1] = "sh"

    assert request["command"] == ["/bin/busybox", "true"]


def test_request_rejects_tuple_subclasses_with_unstable_iteration() -> None:
    class UnstableTuple(tuple):
        def __iter__(self):
            return iter(("/bin/busybox", "mutated"))

    with pytest.raises(SandboxLaunchDriverServiceError, match="request is invalid"):
        _request(UnstableTuple(("/bin/busybox", "true")))


def _committed_execution(intent: SimpleNamespace, state_path: Path) -> dict[str, object]:
    attempt_slice = sandbox_attempt_slice_unit(*_IDENTITY)
    monitor_unit = sandbox_monitor_service_unit(*_IDENTITY)
    state = state_path.lstat()
    return {
        "attempt_id": intent.attempt_id,
        "claim_token": intent.claim_token,
        "execution_id": intent.execution_id,
        "state_path": str(state_path),
        "state_root_dev": state.st_dev,
        "state_root_ino": state.st_ino,
        "phase": "launched",
        "launch_driver_start_id": intent.start_id,
        "launch_driver_start_digest": intent.start_digest,
        "launch_driver_start_unit": intent.service_unit,
        "launch_driver_start_redeemed_at": 1,
        "launch_driver_start_redeemed_invocation_id": "1" * 32,
        "launch_driver_start_redeemed_pid": 1234,
        "launch_driver_start_redeemed_identity": "linux:1234:9876",
        "launch_driver_start_redeemed_cgroup_path": (
            f"/user.slice/user-acp.slice/{attempt_slice}/{intent.service_unit}"
        ),
        "launch_plan_binding_version": 1,
        "launch_plan_digest": "6" * 64,
        "launch_submission_id": "submission-1",
        "monitor_pid": 4321,
        "monitor_identity": "linux:4321:12345",
        "runc_client_pid": 4322,
        "runc_client_identity": "linux:4322:12346",
        "wrapper_unit": monitor_unit,
        "wrapper_invocation_id": "4" * 32,
        "wrapper_cgroup_path": f"/user.slice/user-acp.slice/{monitor_unit}",
        "attempt_slice_unit": attempt_slice,
        "scope_unit": "acp-scope-test.scope",
        "scope_invocation_id": "5" * 32,
        "cgroup_path": f"/user.slice/user-acp.slice/{attempt_slice}/acp-scope-test.scope",
    }


def test_registered_no_model_worker_requires_explicit_opt_in() -> None:
    with pytest.raises(SandboxLaunchDriverServiceError, match="explicit experimental opt-in"):
        start_registered_no_model_sandbox_worker(
            object(),
            attempt_id="attempt-1",
            claim_token=7,
            command=("/bin/true",),
            **_RESOURCES,
        )


def test_registered_no_model_worker_rejects_unsupported_platform_before_supervisor_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_control_plane.supervisor import sandbox_launch_driver_service as service

    monkeypatch.setattr(service.sys, "platform", "darwin")
    with pytest.raises(SandboxLaunchDriverServiceError, match="unprivileged supported Linux"):
        start_registered_no_model_sandbox_worker(
            object(),
            attempt_id="attempt-1",
            claim_token=7,
            command=("/bin/true",),
            experimental_opt_in=True,
            **_RESOURCES,
        )


def test_registered_no_model_worker_rejects_missing_pins_before_reservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_control_plane.supervisor import sandbox_launch_driver_service as service

    monkeypatch.setattr(service.sys, "platform", "linux")
    monkeypatch.setattr(service.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        service.provider_proxy,
        "require_peer_pidfd_support",
        lambda: pytest.fail("no-provider worker must not require SO_PEERPIDFD"),
    )
    supervisor = SimpleNamespace(
        config=SimpleNamespace(
            oci_rootfs_pin=None,
            oci_runc_executable=None,
            oci_runc_version=None,
        ),
        _sandbox_validate_attempt_id=lambda value: value,
        _sandbox_claim_token=lambda value: value,
    )
    with pytest.raises(SandboxLaunchDriverServiceError, match="pinned rootfs and runc 1.5.2"):
        start_registered_no_model_sandbox_worker(
            supervisor,
            attempt_id="attempt-1",
            claim_token=7,
            command=("/bin/true",),
            experimental_opt_in=True,
            **_RESOURCES,
        )


def test_registered_provider_worker_rejects_unsupported_peer_pidfd_before_reservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_control_plane.supervisor import sandbox_launch_driver_service as service

    monkeypatch.setattr(service.sys, "platform", "linux")
    monkeypatch.setattr(service.os, "geteuid", lambda: 1000)

    def unsupported() -> None:
        raise SupervisorError(
            "provider_proxy_peer_pidfd_unsupported",
            "provider proxy requires kernel SO_PEERPIDFD support",
        )

    monkeypatch.setattr(
        service.provider_proxy,
        "require_peer_pidfd_support",
        unsupported,
    )
    reservations: list[tuple[object, ...]] = []
    supervisor = SimpleNamespace(
        _sandbox_validate_attempt_id=lambda value: value,
        _sandbox_claim_token=lambda value: value,
        _sandbox_execution_reserve=lambda *args, **kwargs: reservations.append(args),
    )

    with pytest.raises(SandboxLaunchDriverServiceError, match="kernel SO_PEERPIDFD"):
        start_registered_no_model_sandbox_worker(
            supervisor,
            attempt_id="attempt-1",
            claim_token=7,
            command=("/bin/true",),
            experimental_opt_in=True,
            provider_egress_policy_name="local-mock",
            provider_egress_destinations={"mock.example": [443]},
            **_RESOURCES,
        )

    assert reservations == []


def test_launch_driver_rejects_unsupported_peer_pidfd_before_service_activation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_control_plane.supervisor import sandbox_launch_driver_service as service

    def unsupported() -> None:
        raise SupervisorError(
            "provider_proxy_peer_pidfd_unsupported",
            "provider proxy requires kernel SO_PEERPIDFD support",
        )

    monkeypatch.setattr(
        service.provider_proxy,
        "require_peer_pidfd_support",
        unsupported,
    )
    supervisor = SimpleNamespace(
        _sandbox_execution_get=lambda _attempt_id: pytest.fail(
            "unsupported provider mode must fail before activation lookup"
        )
    )

    with pytest.raises(SandboxLaunchDriverServiceError, match="kernel SO_PEERPIDFD"):
        start_sandbox_launch_driver(
            supervisor,
            expected_identity=_IDENTITY,
            command=("/bin/true",),
            provider_egress_policy_name="local-mock",
            provider_egress_destinations={"mock.example": [443]},
            timeout_seconds=30,
            **_RESOURCES,
        )


def test_redeemed_provider_request_rechecks_peer_pidfd_before_execution_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_control_plane.supervisor import sandbox_launch_driver_service as service

    def unsupported() -> None:
        raise SupervisorError(
            "provider_proxy_peer_pidfd_unsupported",
            "provider proxy requires kernel SO_PEERPIDFD support",
        )

    monkeypatch.setattr(
        service.provider_proxy,
        "require_peer_pidfd_support",
        unsupported,
    )
    supervisor = SimpleNamespace(
        _sandbox_execution_get=lambda _attempt_id: pytest.fail(
            "persisted provider request must fail before execution/worker lookup"
        )
    )
    request = _validate_request(
        expected_identity=_IDENTITY,
        command=("/bin/true",),
        timeout_seconds=30,
        provider_egress_policy_name="local-mock",
        provider_egress_destinations={"mock.example": [443]},
        **_RESOURCES,
    )

    with pytest.raises(SandboxLaunchDriverServiceError, match="kernel SO_PEERPIDFD"):
        service._execute_pinned_request(
            supervisor,
            _IDENTITY,
            request,
            credential=None,
        )


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="requires a Linux kernel probe")
def test_registered_provider_worker_applies_actual_kernel_gate_before_reservation() -> None:
    from agent_control_plane.supervisor import sandbox_launch_driver_service as service

    if os.geteuid() == 0:
        pytest.skip("registered no-model composition refuses a root caller")
    try:
        service.provider_proxy.require_peer_pidfd_support()
    except SupervisorError as error:
        assert error.code == "provider_proxy_peer_pidfd_unsupported"
        expected_error = "SO_PEERPIDFD"
    else:
        expected_error = "pinned rootfs and runc 1.5.2"

    reservations: list[tuple[object, ...]] = []
    supervisor = SimpleNamespace(
        config=SimpleNamespace(
            oci_rootfs_pin=None,
            oci_runc_executable=None,
            oci_runc_version=None,
        ),
        _sandbox_validate_attempt_id=lambda value: value,
        _sandbox_claim_token=lambda value: value,
        _sandbox_execution_reserve=lambda *args, **kwargs: reservations.append(args),
    )
    try:
        start_registered_no_model_sandbox_worker(
            supervisor,
            attempt_id="attempt-1",
            claim_token=7,
            command=("/bin/true",),
            experimental_opt_in=True,
            provider_egress_policy_name="local-mock",
            provider_egress_destinations={"mock.example": [443]},
            **_RESOURCES,
        )
    except SandboxLaunchDriverServiceError as error:
        assert expected_error in str(error)
    else:
        pytest.fail("registered no-model composition unexpectedly reached worker launch")
    assert reservations == []


def test_post_reservation_preparation_failure_retains_partial_private_tree(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from agent_control_plane.supervisor import sandbox_launch_driver_service as service

    if os.geteuid() == 0:
        pytest.skip("registered no-model composition refuses a root caller")
    monkeypatch.setattr(service.sys, "platform", "linux")
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    trusted_rootfs = tmp_path / "trusted-rootfs"
    trusted_rootfs.mkdir(mode=0o700)
    rootfs_pin = SimpleNamespace(sha256="a" * 64, closure_sha256="b" * 64)
    runc_pin = SimpleNamespace(sha256="c" * 64)
    version = service.oci_worker._RUNC_RECURSIVE_PRIVATE_VERSION
    reserved: list[dict[str, object]] = []
    heartbeat_calls: list[tuple[object, ...]] = []
    execution_root = state_dir / "sandbox-executions" / "attempt-1-7"
    execution = {
        "attempt_id": "attempt-1",
        "claim_token": 7,
        "execution_id": "execution-1",
        "bundle_path": str(execution_root / "bundle"),
        "state_path": str(execution_root / "state"),
    }

    def reserve(*_args: object, **_kwargs: object) -> dict[str, object]:
        reserved.append(execution)
        return execution

    supervisor = SimpleNamespace(
        config=SimpleNamespace(
            oci_rootfs_pin=rootfs_pin,
            oci_runc_executable=runc_pin,
            oci_runc_version=version,
            lease_seconds=30,
        ),
        state_dir=state_dir,
        _sandbox_validate_attempt_id=lambda value: value,
        _sandbox_claim_token=lambda _value: None,
        _sandbox_execution_reserve=reserve,
        heartbeat=lambda *args, **kwargs: heartbeat_calls.append(args),
    )
    monkeypatch.setattr(service.oci_worker, "_verify_trusted_rootfs", lambda _pin: trusted_rootfs)
    monkeypatch.setattr(service.oci_worker, "_verify_trusted_runc_executable", lambda _pin: None)
    monkeypatch.setattr(
        service.oci_worker, "_probe_trusted_runc_version", lambda _pin, _version: version
    )
    monkeypatch.setattr(
        service.oci_worker,
        "rootfs_tree_manifest",
        lambda _path: {
            "rootfs_sha256": rootfs_pin.sha256,
            "closure_sha256": rootfs_pin.closure_sha256,
        },
    )

    def fail_during_copy(_source: Path, destination: Path, *, symlinks: bool) -> None:
        assert symlinks is True
        destination.mkdir(mode=0o700)
        (destination / "partial-entry").write_text("incomplete", encoding="utf-8")
        raise OSError("injected partial rootfs copy failure")

    monkeypatch.setattr(service.shutil, "copytree", fail_during_copy)
    with pytest.raises(
        SandboxLaunchDriverServiceError, match="could not be copied and re-verified"
    ):
        start_registered_no_model_sandbox_worker(
            supervisor,
            attempt_id="attempt-1",
            claim_token=7,
            command=("fake-worker", "--no-model"),
            experimental_opt_in=True,
            **_RESOURCES,
        )

    assert reserved == [execution]
    assert heartbeat_calls
    assert (execution_root / "bundle" / "rootfs" / "partial-entry").is_file()
    assert (execution_root / "state").is_dir()


def test_real_journal_quarantines_fences_after_partial_preparation_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from agent_control_plane.git_supervisor import CLEANUP_FENCE_EPOCH, GitSupervisor
    from agent_control_plane.supervisor import sandbox_launch_driver_service as service

    if os.geteuid() == 0:
        pytest.skip("registered no-model composition refuses a root caller")
    monkeypatch.setattr(service.sys, "platform", "linux")
    repo = tmp_path / "repo"
    repo.mkdir()
    init_repo(repo)
    supervisor = GitSupervisor(repo)
    supervisor.config = replace(
        supervisor.config,
        runtime_port_pools=(RuntimePortPool("ACP_TEST_PORT", 24003, 24003),),
    )
    supervisor._port_available = lambda _port: True
    task = make_task(supervisor, "partial-preparation", title="partial preparation failure")
    attempt = supervisor.claim(task["id"], "sandbox-worker")
    state_dir = Path(supervisor.state_dir)
    state_dir.chmod(0o700)
    trusted_rootfs = tmp_path / "trusted-rootfs"
    trusted_rootfs.mkdir(mode=0o700)
    rootfs_pin = SimpleNamespace(sha256="a" * 64, closure_sha256="b" * 64)
    runc_pin = SimpleNamespace(sha256="c" * 64)
    version = service.oci_worker._RUNC_RECURSIVE_PRIVATE_VERSION
    supervisor.config = replace(
        supervisor.config,
        oci_rootfs_pin=rootfs_pin,
        oci_runc_executable=runc_pin,
        oci_runc_version=version,
        lease_seconds=3,
    )
    monkeypatch.setattr(service.oci_worker, "_verify_trusted_rootfs", lambda _pin: trusted_rootfs)
    monkeypatch.setattr(service.oci_worker, "_verify_trusted_runc_executable", lambda _pin: None)
    monkeypatch.setattr(
        service.oci_worker, "_probe_trusted_runc_version", lambda _pin, _version: version
    )
    monkeypatch.setattr(
        service.oci_worker,
        "rootfs_tree_manifest",
        lambda _path: {
            "rootfs_sha256": rootfs_pin.sha256,
            "closure_sha256": rootfs_pin.closure_sha256,
        },
    )

    def fail_during_copy(_source: Path, destination: Path, *, symlinks: bool) -> None:
        assert symlinks is True
        destination.mkdir(mode=0o700)
        (destination / "partial-entry").write_text("incomplete", encoding="utf-8")
        raise OSError("injected partial rootfs copy failure")

    monkeypatch.setattr(service.shutil, "copytree", fail_during_copy)
    with pytest.raises(
        SandboxLaunchDriverServiceError, match="could not be copied and re-verified"
    ):
        start_registered_no_model_sandbox_worker(
            supervisor,
            attempt_id=attempt["id"],
            claim_token=attempt["claim_token"],
            command=("fake-worker", "--no-model"),
            experimental_opt_in=True,
            **_RESOURCES,
        )

    execution = supervisor._sandbox_execution_get(attempt["id"])
    assert execution is not None and execution["phase"] == "reserved"
    assert (Path(execution["bundle_path"]) / "rootfs" / "partial-entry").is_file()
    assert Path(execution["state_path"]).is_dir()
    with supervisor.connect() as connection:
        lease_count = connection.execute(
            "SELECT COUNT(*) AS n FROM resource_leases WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()["n"]
        runtime = connection.execute(
            "SELECT state FROM runtime_environments WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()
        allocation_before = connection.execute(
            "SELECT pool_name, value, lease_expires_at FROM runtime_allocations "
            "WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()
    assert lease_count > 0
    assert runtime is not None and runtime["state"] != "released"
    assert allocation_before is not None
    assert (allocation_before["pool_name"], allocation_before["value"]) == (
        "ACP_TEST_PORT",
        24003,
    )
    assert allocation_before["lease_expires_at"] != CLEANUP_FENCE_EPOCH

    supervisor.reap_expired(now=int(time.time()) + 4)

    with supervisor.connect() as connection:
        quarantined_attempt = connection.execute(
            "SELECT status, termination_target_status FROM attempts WHERE id = ?",
            (attempt["id"],),
        ).fetchone()
        quarantined_task = connection.execute(
            "SELECT status, cleanup_target_status FROM tasks WHERE id = ?",
            (task["id"],),
        ).fetchone()
        leases = connection.execute(
            "SELECT lease_expires_at FROM resource_leases WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchall()
        runtime_after = connection.execute(
            "SELECT state FROM runtime_environments WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()
        allocation_after = connection.execute(
            "SELECT pool_name, value, lease_expires_at FROM runtime_allocations "
            "WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()
    assert quarantined_attempt["status"] == "terminating"
    assert quarantined_attempt["termination_target_status"] == "quarantined"
    assert quarantined_task["status"] == "cleanup_pending"
    assert quarantined_task["cleanup_target_status"] == "blocked"
    assert leases and all(lease["lease_expires_at"] == CLEANUP_FENCE_EPOCH for lease in leases)
    assert runtime_after is not None and runtime_after["state"] != "released"
    assert allocation_after is not None
    assert (allocation_after["pool_name"], allocation_after["value"]) == (
        "ACP_TEST_PORT",
        24003,
    )
    assert allocation_after["lease_expires_at"] == CLEANUP_FENCE_EPOCH


def test_launch_driver_wait_renews_attempt_lease_between_bounded_waits() -> None:
    from subprocess import TimeoutExpired

    calls: list[object] = []

    class Handle:
        def wait(self, *, timeout: float):
            calls.append(timeout)
            if len(calls) == 1:
                raise TimeoutExpired("pinned-runc", timeout)
            return "wait-receipt"

    supervisor = SimpleNamespace(
        config=SimpleNamespace(lease_seconds=30),
        heartbeat=lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    result = _wait_for_runc_with_attempt_heartbeat(
        supervisor,
        Handle(),
        attempt_id="attempt-1",
        claim_token=7,
        credential="runner-secret",
        timeout_seconds=5,
    )

    assert result == "wait-receipt"
    assert len(calls) == 3
    heartbeat_call = calls[1]
    assert heartbeat_call == (
        ("attempt-1", 7, None),
        {"credential": "runner-secret"},
    )


def test_producer_keeps_lease_until_driver_publishes_running_handoff() -> None:
    class LeaseHeartbeat:
        checks = 0

        def check(self) -> None:
            self.checks += 1

    phases = iter(("launched", "running"))
    identity = _IDENTITY
    supervisor = SimpleNamespace(
        _sandbox_execution_get=lambda _attempt_id: {
            "attempt_id": identity[0],
            "claim_token": identity[1],
            "execution_id": identity[2],
            "phase": next(phases),
        }
    )
    lease_heartbeat = LeaseHeartbeat()

    execution = _wait_for_driver_running_handoff(
        supervisor,
        identity,
        lease_heartbeat,
        timeout_seconds=1,
    )

    assert execution["phase"] == "running"
    assert lease_heartbeat.checks == 2


def test_expired_attempt_quarantines_then_cancels_exact_monitor_scope() -> None:
    identity = _IDENTITY
    current = {
        "attempt_id": identity[0],
        "claim_token": identity[1],
        "execution_id": identity[2],
        "phase": "running",
    }
    transitions: list[tuple[str, Any]] = []

    def request_stop(*_args: Any, **_kwargs: Any) -> None:
        raise SupervisorError("claim_inactive", "attempt lease expired")

    def quarantine_lease_loss(
        attempt_id: str,
        claim_token: int,
        execution_id: str,
        *,
        credential: str | None,
    ) -> dict[str, Any]:
        assert (attempt_id, claim_token) == identity[:2]
        assert execution_id == identity[2]
        assert credential == "runner-secret"
        transitions.append(("quarantine", execution_id))
        current["phase"] = "ambiguous"
        current["failure_reason"] = (
            "launch-driver stop intent could not be recorded after attempt lease loss"
        )
        return dict(current)

    def cancel_monitor(
        execution: dict[str, Any], *, monitor_client: Any, _allow_ambiguous_failure: bool
    ) -> dict[str, Any]:
        assert execution["phase"] == "ambiguous"
        assert execution["execution_id"] == identity[2]
        assert monitor_client == "exact-monitor-client"
        assert _allow_ambiguous_failure is True
        transitions.append(("cancel", execution["execution_id"]))
        return {"outcome": "stop_pending"}

    supervisor = SimpleNamespace(
        _sandbox_execution_request_stop=request_stop,
        _sandbox_execution_get=lambda _attempt_id: dict(current),
        _sandbox_execution_quarantine_lease_loss=quarantine_lease_loss,
        _cancel_sandbox_execution_monitor=cancel_monitor,
    )
    _request_driver_failure_stop_and_cancel_monitor(
        supervisor,
        identity,
        credential="runner-secret",
        monitor_client="exact-monitor-client",
    )

    assert [kind for kind, _ in transitions] == ["quarantine", "cancel"]


def test_request_is_canonical_private_and_bound_to_the_execution(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    path = tmp_path / "launch-driver-request.json"
    request = _request()

    digest = _write_request(path, request)
    restored, observed_digest = _read_request(path, _IDENTITY)

    assert restored == request
    assert observed_digest == digest
    assert digest == hashlib.sha256(canonical_json(request).encode()).hexdigest()
    with pytest.raises(SandboxLaunchDriverServiceError, match="already exists"):
        _write_request(path, request)
    with pytest.raises(SandboxLaunchDriverServiceError, match="mismatched"):
        _read_request(path, ("attempt-1", 8, "execution-1"))


def test_named_provider_policy_is_canonical_and_bound_to_the_launch_request(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    request = _validate_request(
        expected_identity=_IDENTITY,
        command=("/bin/busybox", "true"),
        timeout_seconds=30,
        provider_egress_policy_name="openai-api",
        provider_egress_destinations={
            "API.Example.com.": [443],
            "static.example.com": [8443, 443],
        },
        **_RESOURCES,
    )

    assert request["provider_egress_policy"] == {
        "name": "openai-api",
        "destinations": {
            "api.example.com": [443],
            "static.example.com": [443, 8443],
        },
    }
    path = tmp_path / "provider-launch-request.json"
    digest = _write_request(path, request)
    restored, restored_digest = _read_request(path, _IDENTITY)
    assert restored == request
    assert restored_digest == digest


def test_named_provider_credential_policy_is_bound_to_named_egress_and_contains_no_bytes(
    tmp_path: Path,
) -> None:
    payload = b"synthetic-provider-token"
    request = _validate_request(
        expected_identity=_IDENTITY,
        command=("/bin/busybox", "true"),
        timeout_seconds=30,
        provider_egress_policy_name="local-mock",
        provider_egress_destinations={"api.example.com": [443]},
        provider_credential_policy_name=_PROVIDER_CREDENTIAL_POLICY,
        **_RESOURCES,
    )

    assert request["provider_credential_policy"] == {"name": _PROVIDER_CREDENTIAL_POLICY}
    assert payload.decode() not in canonical_json(request)
    path = tmp_path / "provider-credential-launch-request.json"
    digest = _write_request(path, request)
    restored, restored_digest = _read_request(path, _IDENTITY)
    assert restored == request
    assert restored_digest == digest

    with pytest.raises(SandboxLaunchDriverServiceError, match="supported named policy"):
        _validate_request(
            expected_identity=_IDENTITY,
            command=("/bin/busybox", "true"),
            timeout_seconds=30,
            provider_credential_policy_name=_PROVIDER_CREDENTIAL_POLICY,
            **_RESOURCES,
        )
    with pytest.raises(SandboxLaunchDriverServiceError, match="supported named policy"):
        _validate_request(
            expected_identity=_IDENTITY,
            command=("/bin/busybox", "true"),
            timeout_seconds=30,
            provider_egress_policy_name="local-mock",
            provider_egress_destinations={"api.example.com": [443]},
            provider_credential_policy_name="unrecognized",
            **_RESOURCES,
        )


def test_provider_credential_fd_requires_a_bounded_fully_sealed_memfd(
    tmp_path: Path,
) -> None:
    payload = b"synthetic-provider-token"
    descriptor = _sealed_memfd(payload)
    try:
        os.lseek(descriptor, 3, os.SEEK_SET)
        assert _read_provider_credential_fd(descriptor) == payload
        assert os.lseek(descriptor, 0, os.SEEK_CUR) == 3
    finally:
        os.close(descriptor)

    for invalid in (b"", b"x" * 7, b"x" * 4097):
        descriptor = _sealed_memfd(invalid)
        try:
            with pytest.raises(SandboxLaunchDriverServiceError, match="bounded and fully sealed"):
                _read_provider_credential_fd(descriptor)
        finally:
            os.close(descriptor)

    descriptor = _sealed_memfd(
        payload,
        seals=getattr(fcntl, "F_SEAL_WRITE", 0x0008) | getattr(fcntl, "F_SEAL_GROW", 0x0004),
    )
    try:
        with pytest.raises(SandboxLaunchDriverServiceError, match="bounded and fully sealed"):
            _read_provider_credential_fd(descriptor)
    finally:
        os.close(descriptor)

    ordinary_file = tmp_path / "unsealed-provider-credential"
    ordinary_file.write_bytes(payload)
    with ordinary_file.open("rb") as stream:
        with pytest.raises(SandboxLaunchDriverServiceError, match="sealed anonymous descriptor"):
            _read_provider_credential_fd(stream.fileno())

    with pytest.raises(SandboxLaunchDriverServiceError, match="descriptor is invalid"):
        _read_provider_credential_fd(-1)
    with pytest.raises(SandboxLaunchDriverServiceError, match="descriptor is invalid"):
        _read_provider_credential_fd(True)
    with pytest.raises(SandboxLaunchDriverServiceError, match="sealed anonymous descriptor"):
        _read_provider_credential_fd(999_999)


def test_provider_credential_pipe_is_bounded_read_only_and_eof_terminated() -> None:
    payload = b"synthetic-provider-token"
    read_fd = _provider_credential_pipe(payload)
    try:
        assert fcntl.fcntl(read_fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
        assert os.read(read_fd, 4096) == payload
        assert os.read(read_fd, 1) == b""
    finally:
        os.close(read_fd)

    with pytest.raises(SandboxLaunchDriverServiceError, match="payload is invalid"):
        _provider_credential_pipe(b"")


@pytest.mark.parametrize(
    ("name", "destinations"),
    [
        (None, {"api.example.com": [443]}),
        ("openai-api", None),
        ("OpenAI API", {"api.example.com": [443]}),
        ("openai-api", {}),
        ("openai-api", {"127.0.0.1": [443]}),
        ("openai-api", {"api.example.com": [True]}),
    ],
)
def test_invalid_named_provider_policy_fails_before_request_creation(
    name: Any, destinations: Any
) -> None:
    with pytest.raises(SandboxLaunchDriverServiceError, match="provider egress policy"):
        _validate_request(
            expected_identity=_IDENTITY,
            command=("/bin/busybox", "true"),
            timeout_seconds=30,
            provider_egress_policy_name=name,
            provider_egress_destinations=destinations,
            **_RESOURCES,
        )


@pytest.mark.parametrize(
    "scenario",
    [
        "complete",
        "cancel",
        "proxy_close_unverified",
        "proxy_close_drains_after_worker_stop",
        "authorization_rejected",
        "authorization_commit_uncertain",
    ],
)
def test_pinned_request_leaves_provider_directory_for_independent_cleanup(
    tmp_path: Path,
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
) -> None:
    from agent_control_plane.supervisor import sandbox_launch_driver_service as service

    # This parametrized test exercises provider-proxy lifecycle behavior with
    # local listener fixtures, not the host kernel's SO_PEERPIDFD capability.
    monkeypatch.setattr(service.provider_proxy, "require_peer_pidfd_support", lambda: None)

    events: list[str] = []
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    bundle_root = tmp_path / "bundle"
    workspace_root = tmp_path / "workspace"
    rootfs_pin = SimpleNamespace(sha256="a" * 64)
    runc_pin = SimpleNamespace(sha256="b" * 64)
    resources = {
        "memory_max_bytes": _RESOURCES["memory_max_bytes"],
        "cpu_quota": _RESOURCES["cpu_quota"],
        "cpu_period": _RESOURCES["cpu_period"],
        "pids_max": _RESOURCES["pids_max"],
    }
    attempt_slice = sandbox_attempt_slice_unit(*_IDENTITY)
    container_id = "test-container"
    scope_unit = f"acp-{container_id}.scope"
    slice_cgroup = f"/user.slice/user-acp.slice/{attempt_slice}"
    scope_cgroup = f"{slice_cgroup}/{scope_unit}"
    execution: dict[str, Any] = {
        "attempt_id": _IDENTITY[0],
        "claim_token": _IDENTITY[1],
        "execution_id": _IDENTITY[2],
        "phase": "reserved",
        "launch_driver_start_redeemed_pid": os.getpid(),
        "launch_driver_start_unit": "acp-launch-driver.service",
        "monitor_pid": 4321,
        "monitor_identity": "linux:4321:12345",
        "wrapper_unit": "acp-monitor.service",
        "wrapper_invocation_id": "1" * 32,
    }
    state_info = state_root.lstat()
    durable = {
        "workspace_root_path": str(workspace_root),
        "baseline_manifest_json": "{}",
        "workspace_root_dev": 1,
        "workspace_root_ino": 2,
        "baseline_manifest_digest": "c" * 64,
        "bundle_path": str(bundle_root),
        "state_path": str(state_root),
        "state_root_dev": state_info.st_dev,
        "state_root_ino": state_info.st_ino,
        "container_id": container_id,
    }

    class Connection:
        def __enter__(self) -> Connection:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        @staticmethod
        def execute(*_args: object) -> Connection:
            return Connection()

        @staticmethod
        def fetchone() -> dict[str, Any]:
            return durable

    supervisor = SimpleNamespace(
        config=SimpleNamespace(
            oci_rootfs_pin=rootfs_pin,
            oci_runc_executable=runc_pin,
            oci_runc_version="1.5.2",
        ),
        connect=lambda: Connection(),
        _sandbox_execution_get=lambda _attempt_id: execution,
        _sandbox_execution_restore_workspace_binding=lambda *_args, **_kwargs: None,
        _sandbox_execution_authorize_launch_submission=lambda *_args, **_kwargs: object(),
        _sandbox_execution_record_launch=lambda *_args, **_kwargs: (
            events.append("record_launched") or execution.update(phase="launched")
        ),
        _sandbox_execution_record_running=lambda *_args, **_kwargs: (
            events.append("record_running") or {"phase": "running"}
        ),
        _sandbox_execution_record_cleanup_report=lambda *_args, **_kwargs: events.append(
            "record_cleanup"
        ),
        heartbeat=lambda *_args, **_kwargs: None,
    )

    class Listener:
        def __init__(self, directory: Path) -> None:
            self.path = directory / "provider.sock"
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.socket.bind(str(self.path))
            self.path.chmod(0o600)
            info = self.path.lstat()
            self.identity = (info.st_dev, info.st_ino)

        def close(self) -> None:
            events.append("listener_close")
            self.socket.close()
            self.path.unlink(missing_ok=True)

    class ProxyService:
        def __init__(self, listener: Listener, _policy: object, *, authorize_peer: object) -> None:
            self.listener = listener
            assert authorize_peer is peer_authorizer

        def start(self) -> None:
            events.append("proxy_start")

        def close(self, *, timeout: float) -> None:
            assert timeout == 10.0
            events.append("proxy_close")
            self.listener.close()
            close_attempt = events.count("proxy_close")
            if scenario == "proxy_close_unverified" or (
                scenario == "proxy_close_drains_after_worker_stop" and close_attempt < 3
            ):
                raise RuntimeError("provider proxy handler drain unverified")

    peer_authorizer = object()
    runtime_context = tempfile.TemporaryDirectory(prefix="acppx-", dir=str(_RUNTIME_TMP_DIR))
    request.addfinalizer(runtime_context.cleanup)
    proxy_directory = Path(runtime_context.name) / "provider-proxy"
    proxy_socket = proxy_directory / "provider.sock"
    config_listener: list[object] = []

    def authorize_submission(*_args: object, **_kwargs: object) -> object:
        if scenario == "authorization_rejected":
            raise RuntimeError("authorization rejected before commit")
        if scenario == "authorization_commit_uncertain":
            execution.update(
                launch_submission_id="d" * 32,
                launch_submission_digest="e" * 64,
                launch_submission_at="2026-10-22T00:00:00Z",
            )
            raise RuntimeError("authorization response failed after commit")
        return object()

    supervisor._sandbox_execution_authorize_launch_submission = authorize_submission

    monkeypatch.setattr(
        service.sandbox_monitor_lifecycle,
        "sandbox_provider_proxy_control_paths",
        lambda **_kwargs: (proxy_directory, proxy_socket),
    )
    monkeypatch.setattr(service.provider_proxy, "AttemptProviderProxyListener", Listener)
    monkeypatch.setattr(service.provider_proxy, "AttemptProviderProxyService", ProxyService)
    monkeypatch.setattr(
        service.provider_proxy,
        "attempt_scoped_peer_authorizer",
        lambda attestation: (
            (events.append("authorize_attested_peer") or peer_authorizer)
            if attestation is attestation_token
            else pytest.fail("peer authorizer did not receive the collector attestation")
        ),
    )
    monkeypatch.setattr(
        service, "_restore_snapshot_from_record", lambda *_args, **_kwargs: object()
    )

    def build_config(*_args: object, **kwargs: object) -> object:
        config_listener.append(kwargs["provider_proxy_listener"])
        return object()

    monkeypatch.setattr(service.oci_worker, "build_oci_worker_config", build_config)
    monkeypatch.setattr(
        service.oci_worker,
        "_apply_pinned_runc_recursive_private_policy",
        lambda *_args, **_kwargs: object(),
    )

    class Process:
        @staticmethod
        def poll() -> None:
            return None

    class Handle:
        _monitor_client = object()

        @staticmethod
        def release_gate() -> None:
            events.append("release_gate")

        @staticmethod
        def close_gate() -> None:
            events.append("close_gate")

        @staticmethod
        def wait(*, timeout: float | None = None) -> object:
            if timeout is not None:
                assert timeout == 15.0
                events.append("cancel_wait")
            return object()

    handle = Handle()

    def spawn(
        _binding: object, _state: Path, _bundle: Path, *args: object, **kwargs: object
    ) -> Handle:
        Path(args[1]).write_text("4322\n", encoding="ascii")
        kwargs["_authorize_runc_submission"](object())
        events.append("spawn_runc")
        return handle

    monkeypatch.setattr(service.oci_worker, "spawn_pinned_runc", spawn)
    monkeypatch.setattr(service.oci_worker, "_runc_launch_pid", lambda _handle: 4322)
    monkeypatch.setattr(
        service.oci_worker, "_runc_launch_process_identity", lambda _handle: "linux:4322:12346"
    )
    monkeypatch.setattr(
        service.oci_worker, "_runc_launch_process_for_testing", lambda _handle: Process()
    )
    monkeypatch.setattr(
        service,
        "_unit_properties",
        lambda name, _properties: {
            "ActiveState": "active",
            "ControlGroup": slice_cgroup if name == attempt_slice else scope_cgroup,
            "Id": name,
            "InvocationID": "2" * 32,
        },
    )
    attestation_token = object()
    monkeypatch.setattr(
        service,
        "collect_running_runtime_attestation",
        lambda **_kwargs: events.append("collect_attestation") or attestation_token,
    )

    def record_running(*_args: object, **_kwargs: object) -> dict[str, str]:
        events.append("record_running")
        execution["phase"] = "running"
        return {"phase": "running"}

    supervisor._sandbox_execution_record_running = record_running

    def wait_for_runc(*_args: object, **_kwargs: object) -> object:
        events.append("wait")
        if scenario == "cancel":
            raise KeyboardInterrupt
        return object()

    monkeypatch.setattr(service, "_wait_for_runc_with_attempt_heartbeat", wait_for_runc)

    def record_exit(*_args: object, **_kwargs: object) -> None:
        events.append("record_exit")
        execution["phase"] = "exited"

    monkeypatch.setattr(service, "_record_driver_exit_with_lease_recovery", record_exit)
    if scenario in {
        "cancel",
        "proxy_close_unverified",
        "proxy_close_drains_after_worker_stop",
    }:

        def cancel_exact_attempt(*_args: object, **_kwargs: object) -> None:
            events.append("cancel_exact_attempt")
            execution["phase"] = "stopping"

        monkeypatch.setattr(
            service, "_request_driver_failure_stop_and_cancel_monitor", cancel_exact_attempt
        )
    monkeypatch.setattr(
        service.oci_worker,
        "_delete_pinned_runc_container",
        lambda *_args, **_kwargs: events.append("delete_runc") or object(),
    )

    def execute_request() -> None:
        service._execute_pinned_request(
            supervisor,  # type: ignore[arg-type]
            _IDENTITY,
            {
                "command": ["fake-worker", "--no-model"],
                "resource_limits": resources,
                "timeout_seconds": 30,
                "provider_egress_policy": {
                    "name": "openai-api",
                    "destinations": {"api.example.com": [443]},
                },
            },
            credential=None,
        )

    if scenario == "cancel":
        with pytest.raises(KeyboardInterrupt):
            execute_request()
    elif scenario == "proxy_close_unverified":
        with pytest.raises(RuntimeError, match="handler drain unverified"):
            execute_request()
        assert execution["phase"] == "exited"
        assert events.count("proxy_close") == 3
        assert "delete_runc" not in events
        assert "record_cleanup" not in events
        assert proxy_directory.is_dir()
        return
    elif scenario == "proxy_close_drains_after_worker_stop":
        with pytest.raises(RuntimeError, match="handler drain unverified"):
            execute_request()
        assert events.count("proxy_close") == 3
        assert events.index("cancel_wait") < max(
            index for index, event in enumerate(events) if event == "proxy_close"
        )
        assert execution["phase"] == "exited"
        assert events.index("delete_runc") < events.index("record_cleanup")
        assert proxy_directory.is_dir()
        assert list(proxy_directory.iterdir()) == []
        return
    elif scenario in {"authorization_rejected", "authorization_commit_uncertain"}:
        with pytest.raises(RuntimeError, match="authorization"):
            execute_request()
        assert events == ["listener_close"]
        if scenario == "authorization_rejected":
            assert not proxy_directory.exists()
        else:
            assert proxy_directory.is_dir()
            assert list(proxy_directory.iterdir()) == []
        return
    else:
        execute_request()

    assert len(config_listener) == 1 and isinstance(config_listener[0], Listener)
    assert events.index("record_running") < events.index("proxy_start")
    assert events.index("authorize_attested_peer") < events.index("proxy_start")
    assert events.index("proxy_start") < events.index("release_gate")
    assert events.index("release_gate") < events.index("wait")
    assert events.index("wait") < events.index("proxy_close")
    assert events.index("proxy_close") < events.index("record_exit")
    assert events.index("listener_close") < events.index("record_exit")
    if scenario in {"cancel", "proxy_close_drains_after_worker_stop"}:
        assert events.index("proxy_close") < events.index("close_gate")
        assert events.index("close_gate") < events.index("cancel_exact_attempt")
        assert events.index("cancel_exact_attempt") < events.index("cancel_wait")
        assert events.index("cancel_wait") < events.index("record_exit")
    assert proxy_directory.is_dir()
    assert list(proxy_directory.iterdir()) == []
    # Directory deletion belongs to the independent postflight verifier, not
    # this launch-driver process. Cleanup-verifier tests cover exact removal.


def test_timeout_records_exact_stop_intent_before_monitor_cancel() -> None:
    events: list[tuple[object, ...]] = []
    credential = "runner-secret"
    monitor_client = object()
    stopping = {
        "attempt_id": _IDENTITY[0],
        "claim_token": _IDENTITY[1],
        "execution_id": _IDENTITY[2],
        "phase": "stopping",
        "stop_reason": "execution_timeout",
    }

    class SupervisorStub:
        def _sandbox_execution_request_stop(
            self, attempt_id: str, claim_token: int, reason: str, *, credential: str | None
        ) -> dict[str, object]:
            events.append(("request_stop", attempt_id, claim_token, reason, credential))
            return stopping

        def _cancel_sandbox_execution_monitor(
            self, execution: dict[str, object], *, monitor_client: object | None = None
        ) -> None:
            events.append(("cancel_monitor", execution, monitor_client))

    _request_timeout_stop_and_cancel_monitor(
        SupervisorStub(),
        _IDENTITY,
        credential=credential,  # type: ignore[arg-type]
        monitor_client=monitor_client,
    )

    assert events == [
        ("request_stop", *_IDENTITY[:2], "execution_timeout", credential),
        ("cancel_monitor", stopping, monitor_client),
    ]


def test_timeout_adopts_existing_exact_stop_reason_after_cancel_race() -> None:
    events: list[tuple[object, ...]] = []
    monitor_client = object()
    stopping = {
        "attempt_id": _IDENTITY[0],
        "claim_token": _IDENTITY[1],
        "execution_id": _IDENTITY[2],
        "phase": "stopping",
        "stop_reason": "terminate_worker",
    }

    class SupervisorStub:
        def _sandbox_execution_request_stop(
            self, _attempt_id: str, _claim_token: int, _reason: str, *, credential: str | None
        ) -> dict[str, object]:
            raise SupervisorError(
                "sandbox_execution_transition_conflict", "another stop reason already won"
            )

        def _sandbox_execution_get(self, attempt_id: str) -> dict[str, object] | None:
            assert attempt_id == _IDENTITY[0]
            return stopping

        def _cancel_sandbox_execution_monitor(
            self, execution: dict[str, object], *, monitor_client: object | None = None
        ) -> None:
            events.append(("cancel_monitor", execution, monitor_client))

    _request_timeout_stop_and_cancel_monitor(
        SupervisorStub(),
        _IDENTITY,
        credential="runner-secret",  # type: ignore[arg-type]
        monitor_client=monitor_client,
    )

    assert events == [("cancel_monitor", stopping, monitor_client)]


def test_timeout_conflict_cannot_cancel_a_different_execution() -> None:
    events: list[dict[str, object]] = []
    unrelated = {
        "attempt_id": _IDENTITY[0],
        "claim_token": _IDENTITY[1],
        "execution_id": "another-execution",
        "phase": "stopping",
        "stop_reason": "terminate_worker",
    }

    class SupervisorStub:
        def _sandbox_execution_request_stop(
            self, _attempt_id: str, _claim_token: int, _reason: str, *, credential: str | None
        ) -> dict[str, object]:
            raise SupervisorError(
                "sandbox_execution_transition_conflict", "another stop reason already won"
            )

        def _sandbox_execution_get(self, attempt_id: str) -> dict[str, object] | None:
            assert attempt_id == _IDENTITY[0]
            return unrelated

        def _cancel_sandbox_execution_monitor(
            self, execution: dict[str, object], *, monitor_client: object | None = None
        ) -> None:
            events.append(execution)

    with pytest.raises(SupervisorError, match="another stop reason already won"):
        _request_timeout_stop_and_cancel_monitor(
            SupervisorStub(),
            _IDENTITY,
            credential="runner-secret",  # type: ignore[arg-type]
        )

    assert events == []


def test_start_intent_digest_binds_exact_request_content() -> None:
    request_a = _request(("/bin/busybox", "true"))
    request_b = _request(("/bin/busybox", "false"))
    digest_a = hashlib.sha256(canonical_json(request_a).encode()).hexdigest()
    digest_b = hashlib.sha256(canonical_json(request_b).encode()).hexdigest()
    row = {
        "attempt_id": _IDENTITY[0],
        "claim_token": _IDENTITY[1],
        "execution_id": _IDENTITY[2],
        "container_id": "acp-test-container",
        "bundle_digest": "a" * 64,
        "rootfs_digest": "b" * 64,
        "rootfs_closure_digest": "c" * 64,
        "runc_executable_digest": "d" * 64,
        "bundle_path": "/private/bundle",
        "bundle_root_dev": 1,
        "bundle_root_ino": 2,
        "state_path": "/private/state",
        "state_root_dev": 1,
        "state_root_ino": 3,
        "workspace_root_path": "/private/workspace",
        "workspace_root_dev": 1,
        "workspace_root_ino": 4,
    }
    unit = journal._sandbox_launch_driver_service_unit(_IDENTITY[2])

    assert digest_a != digest_b
    assert journal._sandbox_launch_driver_start_digest(
        row, unit, launch_request_digest=digest_a
    ) != journal._sandbox_launch_driver_start_digest(row, unit, launch_request_digest=digest_b)


@pytest.mark.parametrize(
    "overrides",
    [
        {"command": ["/bin/sh", "-c", "true\nfalse"]},
        {"memory_max_bytes": True},
        {"timeout_seconds": 0},
        {"pids_max": 0},
    ],
)
def test_invalid_launch_requests_fail_before_any_service_start(overrides: dict) -> None:
    values = {
        "expected_identity": _IDENTITY,
        "command": ["/bin/busybox", "true"],
        **_RESOURCES,
        "timeout_seconds": 30,
    }
    values.update(overrides)

    with pytest.raises(SandboxLaunchDriverServiceError, match="request is invalid"):
        _validate_request(**values)


def test_producer_rejects_unprepared_execution_before_systemd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SupervisorStub:
        @staticmethod
        def _sandbox_execution_get(_attempt_id: str) -> None:
            return None

    def unexpected_systemd(*_args: object, **_kwargs: object) -> dict[str, str]:
        pytest.fail("systemd must not be queried before a prepared execution is verified")

    monkeypatch.setattr(
        "agent_control_plane.supervisor.sandbox_launch_driver_service._unit_properties",
        unexpected_systemd,
    )
    with pytest.raises(SandboxLaunchDriverServiceError, match="prepared durable execution"):
        start_sandbox_launch_driver(
            SupervisorStub(),  # type: ignore[arg-type]
            expected_identity=_IDENTITY,
            command=["/bin/busybox", "true"],
            **_RESOURCES,
        )


def test_duplicate_json_keys_fail_closed(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    request = _request()
    encoded = canonical_json(request).replace('"schema":1', '"schema":1,"schema":1')
    path = tmp_path / "launch-driver-request.json"
    path.write_text(encoded, encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(SandboxLaunchDriverServiceError, match="cannot be read safely"):
        _read_request(path, _IDENTITY)


def test_runner_credential_is_read_only_from_private_systemd_credential_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    credential_dir = tmp_path / "credentials"
    credential_dir.mkdir(mode=0o700)
    credential = "opaque-runner-test-credential"
    credential_path = credential_dir / "acp-runner"
    credential_path.write_text(credential, encoding="utf-8")
    credential_path.chmod(0o400)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credential_dir))

    assert _read_service_runner_credential() == credential

    credential_path.chmod(0o600)
    with pytest.raises(SandboxLaunchDriverServiceError, match="file is unsafe"):
        _read_service_runner_credential()


def test_test_worker_canary_is_read_only_bounded_and_explicitly_opted_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    credential_dir = tmp_path / "credentials"
    credential_dir.mkdir(mode=0o700)
    canary = b"fake-only-worker-canary"
    credential_path = credential_dir / "acp-test-worker-canary"
    credential_path.write_bytes(canary)
    credential_path.chmod(0o400)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credential_dir))

    assert _read_service_test_worker_canary() is None
    monkeypatch.setenv("ACP_TEST_ALLOW_WORKER_CANARY", "1")
    assert _read_service_test_worker_canary() == canary
    read_fd = _test_worker_canary_pipe(canary)
    try:
        assert os.read(read_fd, 4096) == canary
        assert os.read(read_fd, 1) == b""
    finally:
        os.close(read_fd)

    credential_path.chmod(0o600)
    with pytest.raises(SandboxLaunchDriverServiceError, match="file is unsafe"):
        _read_service_test_worker_canary()


def test_provider_credential_is_read_only_and_requires_the_named_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential_dir = tmp_path / "provider-credentials"
    credential_dir.mkdir(mode=0o700)
    payload = b"synthetic-provider-token"
    credential_path = credential_dir / "acp-provider-credential"
    credential_path.write_bytes(payload)
    credential_path.chmod(0o400)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credential_dir))

    assert _read_service_provider_credential(_PROVIDER_CREDENTIAL_POLICY) == payload
    with pytest.raises(SandboxLaunchDriverServiceError, match="without an explicit named policy"):
        _read_service_provider_credential(None)
    with pytest.raises(SandboxLaunchDriverServiceError, match="unsupported"):
        _read_service_provider_credential("unrecognized")

    credential_path.chmod(0o600)
    with pytest.raises(SandboxLaunchDriverServiceError, match="file is unsafe"):
        _read_service_provider_credential(_PROVIDER_CREDENTIAL_POLICY)
    credential_path.unlink()
    assert _read_service_provider_credential(None) is None
    with pytest.raises(SandboxLaunchDriverServiceError, match="cannot be opened safely"):
        _read_service_provider_credential(_PROVIDER_CREDENTIAL_POLICY)


def test_authenticated_producer_uses_systemd_credential_descriptor_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    state_path = tmp_path / "state"
    state_path.mkdir(mode=0o700)
    state = state_path.lstat()
    credential = "opaque-runner-test-credential"
    unit = journal._sandbox_launch_driver_service_unit(_IDENTITY[2])
    monitor_unit = sandbox_monitor_service_unit(*_IDENTITY)
    attempt_slice = sandbox_attempt_slice_unit(*_IDENTITY)
    initial_execution = {
        "attempt_id": _IDENTITY[0],
        "claim_token": _IDENTITY[1],
        "execution_id": _IDENTITY[2],
        "state_path": str(state_path),
        "state_root_dev": state.st_dev,
        "state_root_ino": state.st_ino,
        "phase": "reserved",
        "workspace_binding_version": 1,
        "private_path_binding_version": 1,
        "launch_plan_required": 1,
    }
    redeemed_execution = {
        **initial_execution,
        "launch_driver_start_redeemed_at": 1,
        "launch_driver_start_id": "start-1",
        "launch_driver_start_digest": "a" * 64,
        "launch_driver_start_unit": unit,
        "launch_driver_start_redeemed_invocation_id": "1" * 32,
        "launch_driver_start_redeemed_pid": 1234,
        "launch_driver_start_redeemed_identity": "linux:1234:9876",
        "launch_driver_start_redeemed_cgroup_path": (
            f"/user.slice/user-acp.slice/{sandbox_attempt_slice_unit(*_IDENTITY)}/{unit}"
        ),
    }
    launched_execution = {
        **redeemed_execution,
        "phase": "launched",
        "launch_plan_binding_version": 1,
        "launch_submission_id": "submission-1",
        "monitor_pid": 4321,
        "monitor_identity": "linux:4321:12345",
        "runc_client_pid": 4322,
        "runc_client_identity": "linux:4322:12346",
        "wrapper_unit": monitor_unit,
        "wrapper_invocation_id": "4" * 32,
        "wrapper_cgroup_path": f"/user.slice/user-acp.slice/{monitor_unit}",
        "attempt_slice_unit": attempt_slice,
        "scope_unit": "acp-scope-test.scope",
        "scope_invocation_id": "5" * 32,
        "cgroup_path": f"/user.slice/user-acp.slice/{attempt_slice}/acp-scope-test.scope",
        "launch_plan_digest": "6" * 64,
    }

    class SupervisorStub:
        root = repo

        def __init__(self) -> None:
            self.read_count = 0
            self.authorized_credential: str | None = None

        def _sandbox_execution_get(self, _attempt_id: str) -> dict:
            self.read_count += 1
            if self.read_count == 1:
                return initial_execution
            if self.read_count == 2:
                return redeemed_execution
            return launched_execution

        def _sandbox_execution_authorize_launch_driver_start(
            self, _attempt_id: str, _claim_token: int, **kwargs: object
        ) -> SimpleNamespace:
            self.authorized_credential = kwargs.get("credential")  # type: ignore[assignment]
            return SimpleNamespace(
                attempt_id=_IDENTITY[0],
                claim_token=_IDENTITY[1],
                execution_id=_IDENTITY[2],
                service_unit=unit,
                start_id="start-1",
                start_digest="a" * 64,
            )

    supervisor = SupervisorStub()
    observed_command: list[str] = []
    observed_environment: dict[str, str] = {}
    unit_property_reads: dict[str, int] = {}

    def unit_properties(name: str, properties: tuple[str, ...]) -> dict[str, str]:
        unit_property_reads[name] = unit_property_reads.get(name, 0) + 1
        if name == monitor_unit or unit_property_reads[name] == 1:
            values = {
                "LoadState": "not-found",
                "ActiveState": "inactive",
                "ControlGroup": "",
                "Id": name,
                "InvocationID": "",
                "MainPID": "0",
                "Slice": "",
            }
        else:
            values = {
                "LoadState": "loaded",
                "ActiveState": "active",
                "ControlGroup": f"/user.slice/user-acp.slice/{sandbox_attempt_slice_unit(*_IDENTITY)}/{unit}",
                "Id": name,
                "InvocationID": "1" * 32,
                "MainPID": "1234",
                "Slice": sandbox_attempt_slice_unit(*_IDENTITY),
            }
        assert set(properties).issubset(values)
        return {key: values[key] for key in properties}

    monkeypatch.setattr(
        "agent_control_plane.supervisor.sandbox_launch_driver_service._unit_properties",
        unit_properties,
    )
    monkeypatch.setattr(
        "agent_control_plane.supervisor.sandbox_launch_driver_service._trusted_systemd_command_environment",
        lambda: {
            "XDG_RUNTIME_DIR": str(runtime_dir),
            "HOME": str(tmp_path),
            "USER": "test",
            "LOGNAME": "test",
            "PATH": "/usr/bin:/bin",
        },
    )
    monkeypatch.setattr(
        "agent_control_plane.supervisor.sandbox_launch_driver_service._systemd_run_path",
        lambda: Path("/usr/bin/systemd-run"),
    )

    def capture_command(command: list[str], *, environment: dict[str, str]) -> bytes:
        observed_command.extend(command)
        observed_environment.update(environment)
        return b""

    monkeypatch.setattr(
        "agent_control_plane.supervisor.sandbox_launch_driver_service._run_trusted_runtime_command",
        capture_command,
    )

    with pytest.raises(SandboxLaunchDriverServiceError, match="must not be included"):
        start_sandbox_launch_driver(
            supervisor,  # type: ignore[arg-type]
            expected_identity=_IDENTITY,
            command=["/bin/busybox", credential],
            credential=credential,
            **_RESOURCES,
        )

    test_worker_canary = b"fake-only-test-worker-canary"
    with pytest.raises(SandboxLaunchDriverServiceError, match="test-only opt-in"):
        start_sandbox_launch_driver(
            supervisor,  # type: ignore[arg-type]
            expected_identity=_IDENTITY,
            command=["/bin/busybox", "true"],
            _test_worker_canary=test_worker_canary,
            **_RESOURCES,
        )
    monkeypatch.setenv("ACP_TEST_ALLOW_WORKER_CANARY", "1")
    with pytest.raises(SandboxLaunchDriverServiceError, match="worker command"):
        start_sandbox_launch_driver(
            supervisor,  # type: ignore[arg-type]
            expected_identity=_IDENTITY,
            command=["/bin/busybox", test_worker_canary.decode("ascii")],
            _test_worker_canary=test_worker_canary,
            **_RESOURCES,
        )
    monkeypatch.delenv("ACP_TEST_ALLOW_WORKER_CANARY")

    provider_payload = b"synthetic-provider-token"
    provider_fd = _sealed_memfd(provider_payload)
    try:
        receipt = start_sandbox_launch_driver(
            supervisor,  # type: ignore[arg-type]
            expected_identity=_IDENTITY,
            command=["/bin/busybox", "true"],
            credential=credential,
            provider_credential_policy_name=_PROVIDER_CREDENTIAL_POLICY,
            provider_credential_fd=provider_fd,
            provider_egress_policy_name="live-uds-only",
            provider_egress_destinations={"api.example.com": [443]},
            **_RESOURCES,
        )

        assert receipt.service_unit == unit
        assert os.fstat(provider_fd).st_size == len(provider_payload)
    finally:
        os.close(provider_fd)
    assert supervisor.read_count == 3
    assert unit_property_reads[unit] == 2
    assert unit_property_reads[monitor_unit] == 1
    assert "--no-block" not in observed_command
    assert supervisor.authorized_credential == credential
    command_text = "\n".join(observed_command)
    assert credential not in command_text
    assert test_worker_canary.decode("ascii") not in command_text
    assert provider_payload.decode("ascii") not in command_text
    assert credential not in observed_environment.values()
    assert test_worker_canary.decode("ascii") not in "\n".join(observed_environment.values())
    assert provider_payload.decode("ascii") not in "\n".join(observed_environment.values())
    assert any(
        part.startswith("--property=LoadCredential=acp-runner:/proc/") for part in observed_command
    )
    assert any(
        part.startswith("--property=LoadCredential=acp-provider-credential:/proc/")
        for part in observed_command
    )
    assert "--setenv=ACP_TEST_ALLOW_WORKER_CANARY=1" not in observed_command
    credential_fds = [
        int(part.rsplit("/", maxsplit=1)[1])
        for part in observed_command
        if part.startswith("--property=LoadCredential=")
    ]
    assert len(credential_fds) == 2
    for descriptor in credential_fds:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    request_path = state_path / "launch-driver-request.json"
    request = json.loads(request_path.read_text(encoding="utf-8"))
    assert credential not in request_path.read_text(encoding="utf-8")
    assert test_worker_canary.decode("ascii") not in request_path.read_text(encoding="utf-8")
    assert provider_payload.decode("ascii") not in request_path.read_text(encoding="utf-8")
    assert set(request) == {
        "schema",
        "attempt_id",
        "claim_token",
        "execution_id",
        "command",
        "resource_limits",
        "timeout_seconds",
        "provider_egress_policy",
        "provider_credential_policy",
    }
    assert request["provider_credential_policy"] == {"name": _PROVIDER_CREDENTIAL_POLICY}
    assert request["provider_egress_policy"] == {
        "name": "live-uds-only",
        "destinations": {"api.example.com": [443]},
    }

    from agent_control_plane.supervisor import sandbox_launch_driver_service as service

    allocated_fds: list[int] = []
    original_anonymous_fd = service._anonymous_fd

    def capture_anonymous_fd(*args: object, **kwargs: object) -> int:
        descriptor = original_anonymous_fd(*args, **kwargs)  # type: ignore[arg-type]
        allocated_fds.append(descriptor)
        return descriptor

    monkeypatch.setattr(service, "_anonymous_fd", capture_anonymous_fd)

    def fail_state_request_path(*_args: object, **_kwargs: object) -> Path:
        raise SandboxLaunchDriverServiceError("injected unsafe state path")

    monkeypatch.setattr(service, "_state_request_path", fail_state_request_path)
    supervisor.read_count = 0
    unit_property_reads.clear()
    with pytest.raises(SandboxLaunchDriverServiceError, match="unsafe state path"):
        start_sandbox_launch_driver(
            supervisor,  # type: ignore[arg-type]
            expected_identity=_IDENTITY,
            command=["/bin/busybox", "true"],
            credential=credential,
            **_RESOURCES,
        )
    assert allocated_fds == []


def test_activation_interruption_adopts_then_cancels_only_through_monitor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agent_control_plane.supervisor import sandbox_launch_driver_service as service

    repo = tmp_path / "repo"
    repo.mkdir()
    state_path = tmp_path / "state"
    state_path.mkdir(mode=0o700)
    unit = journal._sandbox_launch_driver_service_unit(_IDENTITY[2])
    monitor_unit = sandbox_monitor_service_unit(*_IDENTITY)
    intent = SimpleNamespace(
        attempt_id=_IDENTITY[0],
        claim_token=_IDENTITY[1],
        execution_id=_IDENTITY[2],
        start_id="2" * 32,
        start_digest="a" * 64,
        service_unit=unit,
    )
    prepared = {
        "attempt_id": _IDENTITY[0],
        "claim_token": _IDENTITY[1],
        "execution_id": _IDENTITY[2],
        "state_path": str(state_path),
        "state_root_dev": state_path.lstat().st_dev,
        "state_root_ino": state_path.lstat().st_ino,
        "phase": "reserved",
        "workspace_binding_version": 1,
        "private_path_binding_version": 1,
        "launch_plan_required": 1,
    }
    launched = _committed_execution(intent, state_path)
    assert service._committed_handoff_receipt(launched, intent) is not None

    class SupervisorStub:
        root = repo

        def __init__(self) -> None:
            self.current = prepared
            self.cancelled: list[dict[str, object]] = []

        def _sandbox_execution_get(self, _attempt_id: str) -> dict[str, object]:
            return self.current

        def _sandbox_execution_authorize_launch_driver_start(
            self, _attempt_id: str, _claim_token: int, **_kwargs: object
        ) -> SimpleNamespace:
            return intent

        def _cancel_sandbox_execution_monitor(self, execution: dict[str, object]) -> dict[str, str]:
            self.cancelled.append(execution)
            return {"phase": "stopping"}

    supervisor = SupervisorStub()
    unit_reads: dict[str, int] = {}
    systemd_calls: list[list[str]] = []
    reconciliation_outcomes: list[bool] = []
    reconciliation_errors: list[str] = []
    original_reconcile = service._stop_and_reconcile_exact_start

    def trace_reconcile(*args: object, **kwargs: object) -> bool:
        try:
            outcome = original_reconcile(*args, **kwargs)  # type: ignore[arg-type]
        except BaseException as error:
            reconciliation_errors.append(repr(error))
            raise
        reconciliation_outcomes.append(outcome)
        return outcome

    def unit_properties(name: str, properties: tuple[str, ...]) -> dict[str, str]:
        unit_reads[name] = unit_reads.get(name, 0) + 1
        assert name in {unit, monitor_unit}
        values = {
            "ActiveState": "inactive",
            "ControlGroup": "",
            "Id": name,
            "InvocationID": "",
            "LoadState": "not-found",
            "MainPID": "0",
            "Slice": "",
        }
        return {key: values[key] for key in properties}

    def command(argv: list[str], *, environment: dict[str, str]) -> bytes:
        del environment
        systemd_calls.append(argv)
        assert argv[0].endswith("systemd-run")
        supervisor.current = launched
        raise KeyboardInterrupt

    monkeypatch.setattr(service, "_unit_properties", unit_properties)
    monkeypatch.setattr(service, "_systemd_run_path", lambda: Path("/usr/bin/systemd-run"))
    monkeypatch.setattr(
        service, "_trusted_systemctl_executable", lambda: Path("/usr/bin/systemctl")
    )
    monkeypatch.setattr(
        service, "_trusted_systemd_command_environment", lambda: {"PATH": "/usr/bin"}
    )
    monkeypatch.setattr(service, "_run_trusted_runtime_command", command)
    monkeypatch.setattr(service, "_stop_and_reconcile_exact_start", trace_reconcile)

    with pytest.raises(KeyboardInterrupt):
        start_sandbox_launch_driver(
            supervisor,  # type: ignore[arg-type]
            expected_identity=_IDENTITY,
            command=["/bin/busybox", "true"],
            **_RESOURCES,
        )

    assert len(systemd_calls) == 1
    assert reconciliation_errors == []
    assert reconciliation_outcomes == [True]
    assert supervisor.cancelled == [launched]
    assert unit_reads[unit] == 1
    assert unit_reads[monitor_unit] == 1


@pytest.mark.parametrize("interrupt_during", ["deadline", "sleep"])
def test_polling_interruption_revokes_and_stops_exact_driver_monitor_and_slice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, interrupt_during: str
) -> None:
    from agent_control_plane.supervisor import sandbox_launch_driver_service as service

    repo = tmp_path / "repo"
    repo.mkdir()
    state_path = tmp_path / "state"
    state_path.mkdir(mode=0o700)
    state_info = state_path.lstat()
    unit = journal._sandbox_launch_driver_service_unit(_IDENTITY[2])
    attempt_slice = sandbox_attempt_slice_unit(*_IDENTITY)
    monitor_unit = sandbox_monitor_service_unit(*_IDENTITY)
    invocation_id = "a" * 32
    current: dict[str, object] = {
        "attempt_id": _IDENTITY[0],
        "claim_token": _IDENTITY[1],
        "execution_id": _IDENTITY[2],
        "state_path": str(state_path),
        "state_root_dev": state_info.st_dev,
        "state_root_ino": state_info.st_ino,
        "phase": "reserved",
        "workspace_binding_version": 1,
        "private_path_binding_version": 1,
        "launch_plan_required": 1,
    }
    intent = SimpleNamespace(
        attempt_id=_IDENTITY[0],
        claim_token=_IDENTITY[1],
        execution_id=_IDENTITY[2],
        start_id="7" * 32,
        start_digest="8" * 64,
        service_unit=unit,
    )

    class SupervisorStub:
        root = repo

        def _sandbox_execution_get(self, _attempt_id: str) -> dict[str, object]:
            return current

        def _sandbox_execution_authorize_launch_driver_start(
            self, _attempt_id: str, _claim_token: int, **_kwargs: object
        ) -> SimpleNamespace:
            current.update(
                {
                    "launch_driver_start_id": intent.start_id,
                    "launch_driver_start_digest": intent.start_digest,
                    "launch_driver_start_unit": unit,
                    "launch_driver_start_redeemed_at": 1,
                    "launch_driver_start_redeemed_invocation_id": invocation_id,
                    "launch_driver_start_redeemed_pid": 1234,
                    "launch_driver_start_redeemed_identity": "linux:1234:9876",
                    "launch_driver_start_redeemed_cgroup_path": (
                        f"/user.slice/user-acp.slice/{attempt_slice}/{unit}"
                    ),
                }
            )
            return intent

        def _sandbox_execution_revoke_launch_driver_start(
            self, _attempt_id: str, _claim_token: int, **kwargs: object
        ) -> dict[str, str]:
            assert kwargs["execution_id"] == _IDENTITY[2]
            assert kwargs["start_id"] == intent.start_id
            assert kwargs["start_digest"] == intent.start_digest
            assert kwargs["service_unit"] == unit
            current["phase"] = "ambiguous"
            return {"phase": "ambiguous"}

    supervisor = SupervisorStub()
    clock_interrupted = False

    def properties_for(name: str, properties: tuple[str, ...], call: int) -> dict[str, str]:
        if name == unit and call == 1:
            values = {
                "ActiveState": "inactive",
                "ControlGroup": "",
                "Id": unit,
                "InvocationID": "",
                "LoadState": "not-found",
                "MainPID": "0",
                "Slice": "",
                "Job": "",
                "SubState": "dead",
            }
        elif name == monitor_unit and call == 1:
            values = {
                "ActiveState": "inactive",
                "ControlGroup": "",
                "Id": monitor_unit,
                "InvocationID": "",
                "LoadState": "not-found",
                "MainPID": "0",
                "Slice": "",
                "Job": "",
                "SubState": "dead",
            }
        elif name == unit:
            active = call in ({2} if clock_interrupted else {2, 3})
            values = {
                "ActiveState": "active" if active else "inactive",
                "ControlGroup": (
                    f"/user.slice/user-acp.slice/{attempt_slice}/{unit}" if active else ""
                ),
                "Id": unit,
                "InvocationID": invocation_id,
                "LoadState": "loaded",
                "MainPID": "1234" if active else "0",
                "Slice": attempt_slice,
                "Job": "",
                "SubState": "running" if active else "dead",
            }
        elif name == monitor_unit:
            active = call == 2
            values = {
                "ActiveState": "active" if active else "inactive",
                "ControlGroup": (f"/user.slice/user-acp.slice/{monitor_unit}" if active else ""),
                "Id": monitor_unit,
                "InvocationID": "b" * 32 if call > 1 else "",
                "LoadState": "loaded" if call > 1 else "not-found",
                "MainPID": "2222" if active else "0",
                "Slice": "user-acp.slice" if call > 1 else "",
                "Job": "",
                "SubState": "running" if active else "dead",
            }
        else:
            active = call == 1
            values = {
                "ActiveState": "active" if active else "inactive",
                "ControlGroup": (f"/user.slice/user-acp.slice/{attempt_slice}" if active else ""),
                "Id": attempt_slice,
                "InvocationID": "c" * 32,
                "LoadState": "loaded",
                "Slice": "user-acp.slice",
                "Job": "",
                "SubState": "active" if active else "dead",
            }
        return {key: values[key] for key in properties}

    unit_reads: dict[str, int] = {}

    def read_properties(name: str, properties: tuple[str, ...]) -> dict[str, str]:
        call = unit_reads.get(name, 0) + 1
        unit_reads[name] = call
        return properties_for(name, properties, call)

    commands: list[list[str]] = []

    def run_command(command: list[str], *, environment: dict[str, str]) -> bytes:
        del environment
        commands.append(command)
        return b""

    def monotonic() -> float:
        nonlocal clock_interrupted
        if interrupt_during == "deadline" and not clock_interrupted:
            clock_interrupted = True
            raise KeyboardInterrupt
        return 0.0

    def sleep(_seconds: float) -> None:
        if interrupt_during == "sleep":
            raise KeyboardInterrupt

    monkeypatch.setattr(service, "_unit_properties", read_properties)
    monkeypatch.setattr(service, "_systemd_run_path", lambda: Path("/usr/bin/systemd-run"))
    monkeypatch.setattr(
        service, "_trusted_systemctl_executable", lambda: Path("/usr/bin/systemctl")
    )
    monkeypatch.setattr(
        service, "_trusted_systemd_command_environment", lambda: {"PATH": "/usr/bin"}
    )
    monkeypatch.setattr(service, "_run_trusted_runtime_command", run_command)
    monkeypatch.setattr(service.time, "monotonic", monotonic)
    monkeypatch.setattr(service.time, "sleep", sleep)

    with pytest.raises(KeyboardInterrupt):
        start_sandbox_launch_driver(
            supervisor,  # type: ignore[arg-type]
            expected_identity=_IDENTITY,
            command=["/bin/busybox", "true"],
            **_RESOURCES,
        )

    stopped_units = [command[-1] for command in commands if command[0].endswith("systemctl")]
    assert stopped_units == [unit, monitor_unit, attempt_slice]
    assert current["phase"] == "ambiguous"
    assert unit_reads[unit] >= 2
    assert unit_reads[monitor_unit] >= 1
    assert unit_reads[attempt_slice] >= 2


def test_timeout_reconciliation_adopts_handoff_that_wins_revocation_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agent_control_plane.supervisor import sandbox_launch_driver_service as service

    state_path = tmp_path / "state"
    state_path.mkdir(mode=0o700)
    unit = journal._sandbox_launch_driver_service_unit(_IDENTITY[2])
    intent = SimpleNamespace(
        attempt_id=_IDENTITY[0],
        claim_token=_IDENTITY[1],
        execution_id=_IDENTITY[2],
        start_id="3" * 32,
        start_digest="b" * 64,
        service_unit=unit,
    )
    reserved = {
        "attempt_id": _IDENTITY[0],
        "claim_token": _IDENTITY[1],
        "execution_id": _IDENTITY[2],
        "phase": "reserved",
        "launch_driver_start_id": intent.start_id,
        "launch_driver_start_digest": intent.start_digest,
        "launch_driver_start_unit": unit,
    }
    launched = _committed_execution(intent, state_path)

    class SupervisorStub:
        current: dict[str, object] = reserved

        @staticmethod
        def _sandbox_execution_get(_attempt_id: str) -> dict[str, object]:
            return SupervisorStub.current

        @staticmethod
        def _sandbox_execution_revoke_launch_driver_start(
            *_args: object, **_kwargs: object
        ) -> None:
            SupervisorStub.current = launched
            raise SupervisorError(
                "sandbox_execution_transition_conflict", "launch registration won the gate"
            )

    def unexpected_unit_read(*_args: object, **_kwargs: object) -> dict[str, str]:
        pytest.fail("handoff adoption must not stop or probe the newly-owned services")

    monkeypatch.setattr(service, "_unit_properties", unexpected_unit_read)
    monkeypatch.setattr(
        service, "_trusted_systemctl_executable", lambda: Path("/usr/bin/systemctl")
    )
    monkeypatch.setattr(
        service, "_trusted_systemd_command_environment", lambda: {"PATH": "/usr/bin"}
    )

    assert (
        service._stop_and_reconcile_exact_start(
            SupervisorStub(),  # type: ignore[arg-type]
            execution=reserved,
            intent=intent,
            attempt_slice=sandbox_attempt_slice_unit(*_IDENTITY),
            reason="startup timeout",
            credential=None,
        )
        is True
    )


def test_unit_property_parser_turns_non_ascii_systemd_output_into_typed_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_control_plane.supervisor import sandbox_launch_driver_service as service

    monkeypatch.setattr(
        service, "_trusted_systemctl_executable", lambda: Path("/usr/bin/systemctl")
    )
    monkeypatch.setattr(
        service, "_trusted_systemd_command_environment", lambda: {"PATH": "/usr/bin"}
    )
    monkeypatch.setattr(
        service, "_run_trusted_runtime_command", lambda *_args, **_kwargs: b"Id=\xff\n"
    )

    with pytest.raises(SandboxLaunchDriverServiceError, match="not ASCII"):
        service._unit_properties("acp-test.service", ("Id",))


def test_redeemed_driver_exit_before_scope_handoff_stops_exact_attempt_slice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agent_control_plane.supervisor import sandbox_launch_driver_service as service

    repo = tmp_path / "repo"
    repo.mkdir()
    state_path = tmp_path / "state"
    state_path.mkdir(mode=0o700)
    state = state_path.lstat()
    unit = journal._sandbox_launch_driver_service_unit(_IDENTITY[2])
    attempt_slice = sandbox_attempt_slice_unit(*_IDENTITY)
    monitor_unit = sandbox_monitor_service_unit(*_IDENTITY)
    initial_execution = {
        "attempt_id": _IDENTITY[0],
        "claim_token": _IDENTITY[1],
        "execution_id": _IDENTITY[2],
        "state_path": str(state_path),
        "state_root_dev": state.st_dev,
        "state_root_ino": state.st_ino,
        "phase": "reserved",
        "workspace_binding_version": 1,
        "private_path_binding_version": 1,
        "launch_plan_required": 1,
    }
    redeemed_execution = {
        **initial_execution,
        "launch_driver_start_redeemed_at": 1,
        "launch_driver_start_id": "2" * 32,
        "launch_driver_start_digest": "a" * 64,
        "launch_driver_start_unit": unit,
        "launch_driver_start_redeemed_invocation_id": "1" * 32,
        "launch_driver_start_redeemed_pid": 1234,
        "launch_driver_start_redeemed_identity": "linux:1234:9876",
        "launch_driver_start_redeemed_cgroup_path": f"/user.slice/user-acp.slice/{attempt_slice}/{unit}",
    }
    start = SimpleNamespace(
        attempt_id=_IDENTITY[0],
        claim_token=_IDENTITY[1],
        execution_id=_IDENTITY[2],
        start_id="2" * 32,
        start_digest="a" * 64,
        service_unit=unit,
    )

    class SupervisorStub:
        root = repo

        def __init__(self) -> None:
            self.read_count = 0
            self.revocations: list[dict[str, object]] = []

        def _sandbox_execution_get(self, _attempt_id: str) -> dict:
            self.read_count += 1
            return initial_execution if self.read_count == 1 else redeemed_execution

        def _sandbox_execution_authorize_launch_driver_start(
            self, _attempt_id: str, _claim_token: int, **_kwargs: object
        ) -> SimpleNamespace:
            return start

        def _sandbox_execution_revoke_launch_driver_start(
            self, _attempt_id: str, _claim_token: int, **kwargs: object
        ) -> dict[str, str]:
            self.revocations.append(kwargs)
            redeemed_execution["phase"] = "ambiguous"
            return {"phase": "ambiguous"}

    supervisor = SupervisorStub()
    unit_calls: dict[str, int] = {}
    stopped: list[list[str]] = []
    slice_cgroup = f"/user.slice/user-acp.slice/{attempt_slice}"

    def unit_properties(name: str, properties: tuple[str, ...]) -> dict[str, str]:
        unit_calls[name] = unit_calls.get(name, 0) + 1
        if name == unit:
            if unit_calls[name] == 1:
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
                values = {
                    "ActiveState": "failed",
                    "ControlGroup": "",
                    "Id": unit,
                    "InvocationID": "1" * 32,
                    "Job": "",
                    "LoadState": "loaded",
                    "MainPID": "0",
                    "Slice": attempt_slice,
                    "SubState": "failed",
                }
        elif name == monitor_unit:
            if unit_calls[name] == 1:
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
            elif unit_calls[name] == 2:
                values = {
                    "ActiveState": "active",
                    "ControlGroup": f"/user.slice/user-acp.slice/{monitor_unit}",
                    "Id": monitor_unit,
                    "InvocationID": "4" * 32,
                    "Job": "",
                    "LoadState": "loaded",
                    "MainPID": "2345",
                    "Slice": "user-acp.slice",
                    "SubState": "running",
                }
            else:
                values = {
                    "ActiveState": "inactive",
                    "ControlGroup": "",
                    "Id": monitor_unit,
                    "InvocationID": "4" * 32,
                    "Job": "",
                    "LoadState": "loaded",
                    "MainPID": "0",
                    "Slice": "user-acp.slice",
                    "SubState": "dead",
                }
        elif unit_calls[name] == 1:
            values = {
                "ActiveState": "active",
                "ControlGroup": slice_cgroup,
                "Id": attempt_slice,
                "InvocationID": "3" * 32,
                "Job": "",
                "LoadState": "loaded",
                "MainPID": "0",
                "Slice": "user-acp.slice",
                "SubState": "active",
            }
        else:
            values = {
                "ActiveState": "inactive",
                "ControlGroup": "",
                "Id": attempt_slice,
                "InvocationID": "3" * 32,
                "Job": "",
                "LoadState": "loaded",
                "MainPID": "0",
                "Slice": "user-acp.slice",
                "SubState": "dead",
            }
        assert set(properties).issubset(values)
        return {key: values[key] for key in properties}

    def run_command(command: list[str], *, environment: dict[str, str]) -> bytes:
        del environment
        if command[0].endswith("systemctl"):
            stopped.append(command)
        return b""

    monkeypatch.setattr(service, "_unit_properties", unit_properties)
    monkeypatch.setattr(service, "_systemd_run_path", lambda: Path("/usr/bin/systemd-run"))
    monkeypatch.setattr(
        service, "_trusted_systemctl_executable", lambda: Path("/usr/bin/systemctl")
    )
    monkeypatch.setattr(
        service, "_trusted_systemd_command_environment", lambda: {"PATH": "/usr/bin"}
    )
    monkeypatch.setattr(service, "_run_trusted_runtime_command", run_command)

    with pytest.raises(
        SandboxLaunchDriverServiceError, match="exited before durable scope registration"
    ):
        start_sandbox_launch_driver(
            supervisor,  # type: ignore[arg-type]
            expected_identity=_IDENTITY,
            command=["/bin/busybox", "true"],
            startup_timeout_seconds=0.2,
            **_RESOURCES,
        )

    assert len(supervisor.revocations) == 1
    assert supervisor.revocations[0]["execution_id"] == _IDENTITY[2]
    assert (
        supervisor.revocations[0]["reason"]
        == "launch-driver exited before durable scope registration"
    )
    assert [command[-1] for command in stopped] == [monitor_unit, attempt_slice]
    assert all(command[-2] == "--" for command in stopped)


@pytest.mark.parametrize("fail_stop", [False, True])
@pytest.mark.parametrize("busy_once", [False, True])
@pytest.mark.parametrize("revocation_failure", ["none", "supervisor", "sqlite"])
def test_startup_timeout_revokes_and_stops_only_the_exact_units(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fail_stop: bool,
    busy_once: bool,
    revocation_failure: str,
) -> None:
    from agent_control_plane.supervisor import sandbox_launch_driver_service as service

    repo = tmp_path / "repo"
    repo.mkdir()
    state_path = tmp_path / "state"
    state_path.mkdir(mode=0o700)
    state = state_path.lstat()
    unit = journal._sandbox_launch_driver_service_unit(_IDENTITY[2])
    attempt_slice = sandbox_attempt_slice_unit(*_IDENTITY)
    monitor_unit = sandbox_monitor_service_unit(*_IDENTITY)
    start = SimpleNamespace(
        attempt_id=_IDENTITY[0],
        claim_token=_IDENTITY[1],
        execution_id=_IDENTITY[2],
        start_id="1" * 32,
        start_digest="a" * 64,
        service_unit=unit,
    )
    execution = {
        "attempt_id": _IDENTITY[0],
        "claim_token": _IDENTITY[1],
        "execution_id": _IDENTITY[2],
        "state_path": str(state_path),
        "state_root_dev": state.st_dev,
        "state_root_ino": state.st_ino,
        "phase": "reserved",
        "launch_driver_start_id": "1" * 32,
        "launch_driver_start_digest": "a" * 64,
        "launch_driver_start_unit": unit,
        "workspace_binding_version": 1,
        "private_path_binding_version": 1,
        "launch_plan_required": 1,
    }

    events: list[str] = []

    class SupervisorStub:
        root = repo

        def __init__(self) -> None:
            self.revocations: list[dict[str, object]] = []

        def _sandbox_execution_get(self, _attempt_id: str) -> dict:
            return execution

        def _sandbox_execution_authorize_launch_driver_start(
            self, _attempt_id: str, _claim_token: int, **_kwargs: object
        ) -> SimpleNamespace:
            return start

        def _sandbox_execution_revoke_launch_driver_start(
            self, _attempt_id: str, _claim_token: int, **kwargs: object
        ) -> dict[str, str]:
            self.revocations.append(kwargs)
            events.append(f"revoke-{len(self.revocations)}")
            if busy_once and len(self.revocations) == 1:
                raise SupervisorError("sandbox_execution_gate_busy", "test lifecycle fence is busy")
            if revocation_failure == "supervisor":
                raise SupervisorError("test_store_failure", "injected durable revoke failure")
            if revocation_failure == "sqlite":
                raise sqlite3.OperationalError("injected database connection failure")
            execution["phase"] = "ambiguous"
            return {"phase": "ambiguous"}

    supervisor = SupervisorStub()
    unit_calls: dict[str, int] = {}
    service_cgroup = f"/user.slice/user-acp.slice/{attempt_slice}/{unit}"
    slice_cgroup = f"/user.slice/user-acp.slice/{attempt_slice}"

    def unit_properties(name: str, properties: tuple[str, ...]) -> dict[str, str]:
        call = unit_calls.get(name, 0) + 1
        unit_calls[name] = call
        if name == unit and call == 1:
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
        elif name == unit and call == 2:
            values = {
                "ActiveState": "active",
                "ControlGroup": service_cgroup,
                "Id": unit,
                "InvocationID": "2" * 32,
                "Job": "",
                "LoadState": "loaded",
                "MainPID": "1234",
                "Slice": attempt_slice,
                "SubState": "running",
            }
        elif name == unit:
            values = {
                "ActiveState": "inactive",
                "ControlGroup": "",
                "Id": unit,
                "InvocationID": "2" * 32,
                "Job": "",
                "LoadState": "loaded",
                "MainPID": "0",
                "Slice": attempt_slice,
                "SubState": "dead",
            }
        elif name == monitor_unit:
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
        elif call == 1:
            values = {
                "ActiveState": "active",
                "ControlGroup": slice_cgroup,
                "Id": attempt_slice,
                "InvocationID": "3" * 32,
                "Job": "",
                "LoadState": "loaded",
                "MainPID": "0",
                "Slice": "user-acp.slice",
                "SubState": "active",
            }
        else:
            values = {
                "ActiveState": "inactive",
                "ControlGroup": "",
                "Id": attempt_slice,
                "InvocationID": "3" * 32,
                "Job": "",
                "LoadState": "loaded",
                "MainPID": "0",
                "Slice": "user-acp.slice",
                "SubState": "dead",
            }
        assert set(properties).issubset(values)
        return {key: values[key] for key in properties}

    stopped: list[list[str]] = []

    def capture_command(command: list[str], *, environment: dict[str, str]) -> bytes:
        del environment
        if command[0].endswith("systemctl"):
            stopped.append(command)
            events.append(f"stop-{command[-1]}")
            if fail_stop:
                raise SupervisorError("test_systemd_stop_failed", "test stop failure")
        return b""

    monkeypatch.setattr(service, "_unit_properties", unit_properties)
    monkeypatch.setattr(
        service, "_trusted_systemctl_executable", lambda: Path("/usr/bin/systemctl")
    )
    monkeypatch.setattr(
        service, "_trusted_systemd_command_environment", lambda: {"PATH": "/usr/bin"}
    )
    monkeypatch.setattr(service, "_systemd_run_path", lambda: Path("/usr/bin/systemd-run"))
    monkeypatch.setattr(service, "_run_trusted_runtime_command", capture_command)
    ticks = iter((0.0, 0.1, 0.2))
    monkeypatch.setattr(service.time, "monotonic", lambda: next(ticks, 0.2))
    monkeypatch.setattr(service.time, "sleep", lambda _seconds: None)

    if revocation_failure != "none":
        error_match = "revocation failed"
    elif fail_stop:
        error_match = "stop failed"
    else:
        error_match = "remains quarantined"
    with pytest.raises(SandboxLaunchDriverServiceError, match=error_match):
        start_sandbox_launch_driver(
            supervisor,  # type: ignore[arg-type]
            expected_identity=_IDENTITY,
            command=["/bin/busybox", "true"],
            startup_timeout_seconds=0.2,
            **_RESOURCES,
        )

    assert len(supervisor.revocations) == (2 if busy_once else 1)
    assert supervisor.revocations[0]["execution_id"] == _IDENTITY[2]
    assert supervisor.revocations[0]["start_id"] == start.start_id
    assert supervisor.revocations[0]["start_digest"] == start.start_digest
    assert supervisor.revocations[0]["service_unit"] == unit
    if revocation_failure != "none":
        expected_stops = []
    else:
        expected_stops = [unit] if fail_stop else [unit, attempt_slice]
    assert [command[-1] for command in stopped] == expected_stops
    assert all(command[-2] == "--" for command in stopped)
    if busy_once and expected_stops:
        first_stop = next(index for index, event in enumerate(events) if event.startswith("stop-"))
        assert events.index("revoke-2") < first_stop
    if revocation_failure != "none":
        assert not any(event.startswith("stop-") for event in events)
