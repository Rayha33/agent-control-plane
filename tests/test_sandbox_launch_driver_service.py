from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_control_plane.supervisor import sandbox_execution_journal as journal
from agent_control_plane.supervisor.common import SupervisorError, canonical_json
from agent_control_plane.supervisor.sandbox_launch_driver_service import (
    SandboxLaunchDriverServiceError,
    _read_request,
    _read_service_runner_credential,
    _request_timeout_stop_and_cancel_monitor,
    _validate_request,
    _write_request,
    start_sandbox_launch_driver,
)
from agent_control_plane.supervisor.sandbox_monitor_receipt import (
    sandbox_attempt_slice_unit,
    sandbox_monitor_service_unit,
)

_IDENTITY = ("attempt-1", 7, "execution-1")
_RESOURCES = {
    "memory_max_bytes": 64 * 1024 * 1024,
    "cpu_quota": 100_000,
    "cpu_period": 100_000,
    "pids_max": 32,
}


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

    receipt = start_sandbox_launch_driver(
        supervisor,  # type: ignore[arg-type]
        expected_identity=_IDENTITY,
        command=["/bin/busybox", "true"],
        credential=credential,
        **_RESOURCES,
    )

    assert receipt.service_unit == unit
    assert supervisor.read_count == 3
    assert unit_property_reads[unit] == 2
    assert unit_property_reads[monitor_unit] == 1
    assert "--no-block" not in observed_command
    assert supervisor.authorized_credential == credential
    command_text = "\n".join(observed_command)
    assert credential not in command_text
    assert credential not in observed_environment.values()
    assert any(
        part.startswith("--property=LoadCredential=acp-runner:/proc/") for part in observed_command
    )
    credential_fd_arg = next(
        part for part in observed_command if part.startswith("--property=LoadCredential=")
    )
    credential_fd = int(credential_fd_arg.rsplit("/", maxsplit=1)[1])
    with pytest.raises(OSError):
        os.fstat(credential_fd)
    request_path = state_path / "launch-driver-request.json"
    request = json.loads(request_path.read_text(encoding="utf-8"))
    assert credential not in request_path.read_text(encoding="utf-8")
    assert set(request) == {
        "schema",
        "attempt_id",
        "claim_token",
        "execution_id",
        "command",
        "resource_limits",
        "timeout_seconds",
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
