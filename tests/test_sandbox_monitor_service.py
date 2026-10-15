from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_control_plane.supervisor import sandbox_monitor_service as monitor_service
from agent_control_plane.supervisor.sandbox_monitor_receipt import (
    sandbox_attempt_slice_unit,
    sandbox_container_id,
)


def _binding() -> monitor_service.SandboxMonitorScopeBinding:
    identity = ("attempt-0001", 7, "12345678-0000-4000-8000-000000000001")
    container_id = sandbox_container_id(*identity)
    attempt_slice = sandbox_attempt_slice_unit(*identity)
    attempt_cgroup = f"/user.slice/user-1000.slice/user@1000.service/user-acp.slice/{attempt_slice}"
    scope_unit = f"acp-{container_id}.scope"
    return monitor_service.SandboxMonitorScopeBinding(
        attempt_id=identity[0],
        claim_token=identity[1],
        execution_id=identity[2],
        scope_unit=scope_unit,
        scope_invocation_id="a" * 32,
        scope_control_group=f"{attempt_cgroup}/{scope_unit}",
        attempt_slice_unit=attempt_slice,
        attempt_slice_control_group=attempt_cgroup,
    )


def test_scope_binding_is_fenced_to_exact_attempt_slice_and_scope() -> None:
    binding = _binding()
    assert monitor_service.SandboxMonitorScopeBinding.from_dict(binding.as_dict()) == binding
    container_id = sandbox_container_id(
        binding.attempt_id, binding.claim_token, binding.execution_id
    )
    assert binding.scope_unit == f"acp-{container_id}.scope"

    with pytest.raises(monitor_service.SandboxMonitorServiceError):
        monitor_service.SandboxMonitorScopeBinding(
            **{
                **binding.__dict__,
                "scope_unit": "other-execution.scope",
            }
        )

    with pytest.raises(monitor_service.SandboxMonitorServiceError):
        monitor_service.SandboxMonitorScopeBinding(
            **{
                **binding.__dict__,
                "scope_unit": f"{container_id}.scope",
                "scope_control_group": f"{binding.attempt_slice_control_group}/{container_id}.scope",
            }
        )


def test_status_reports_only_the_bound_scope_activation(monkeypatch: pytest.MonkeyPatch) -> None:
    binding = _binding()
    properties = {
        "Id": binding.scope_unit,
        "LoadState": "loaded",
        "ActiveState": "active",
        "InvocationID": binding.scope_invocation_id,
        "ControlGroup": binding.scope_control_group,
        "Slice": binding.attempt_slice_unit,
    }
    monkeypatch.setattr(monitor_service, "_unit_properties", lambda *_args: properties)
    monkeypatch.setattr(monitor_service, "_scope_population", lambda _path: 1)

    status = monitor_service._scope_status(binding)
    assert status == {
        "phase": "running",
        "scope_unit": binding.scope_unit,
        "scope_invocation_id": binding.scope_invocation_id,
        "scope_control_group": binding.scope_control_group,
    }

    properties["InvocationID"] = "b" * 32
    assert monitor_service._scope_status(binding)["phase"] == "unknown"


def test_status_accepts_unloaded_scope_only_when_its_recorded_cgroup_is_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
    properties = {
        "Id": binding.scope_unit,
        "LoadState": "not-found",
        "ActiveState": "inactive",
        "InvocationID": "",
        "ControlGroup": "",
        "Slice": "",
    }
    monkeypatch.setattr(monitor_service, "_unit_properties", lambda *_args: properties)
    monkeypatch.setattr(monitor_service, "_scope_population", lambda _path: 0)

    assert monitor_service._scope_status(binding)["phase"] == "exited"

    monkeypatch.setattr(monitor_service, "_scope_population", lambda _path: 1)
    assert monitor_service._scope_status(binding)["phase"] == "unknown"


def test_cancel_stops_only_the_bound_scope_and_verifies_inactive_empty_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
    phases = iter(("running", "exited"))
    calls: list[list[str]] = []
    monkeypatch.setattr(
        monitor_service,
        "_scope_status",
        lambda current: {
            "phase": next(phases),
            "scope_unit": current.scope_unit,
            "scope_invocation_id": current.scope_invocation_id,
            "scope_control_group": current.scope_control_group,
        },
    )
    monkeypatch.setattr(
        monitor_service,
        "_run_trusted_runtime_command",
        lambda argv, **_kwargs: calls.append(argv) or b"",
    )
    monkeypatch.setattr(
        monitor_service, "_trusted_systemctl_executable", lambda: Path("/usr/bin/systemctl")
    )
    monkeypatch.setattr(
        monitor_service,
        "_trusted_systemd_command_environment",
        lambda: {"XDG_RUNTIME_DIR": "/run/user/1000"},
    )

    response = monitor_service._cancel_scope(binding)

    assert response["phase"] == "exited"
    assert len(calls) == 1
    assert calls[0][-3:] == ["stop", "--", binding.scope_unit]
    assert "--no-block" in calls[0]
    assert binding.attempt_slice_unit not in calls[0]


def test_cancel_accepts_an_already_stopping_exact_scope_without_another_stop_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
    calls: list[list[str]] = []
    monkeypatch.setattr(
        monitor_service,
        "_scope_status",
        lambda current: {
            "phase": "stopping",
            "scope_unit": current.scope_unit,
            "scope_invocation_id": current.scope_invocation_id,
            "scope_control_group": current.scope_control_group,
        },
    )
    monkeypatch.setattr(
        monitor_service,
        "_run_trusted_runtime_command",
        lambda argv, **_kwargs: calls.append(argv) or b"",
    )

    response = monitor_service._cancel_scope(binding)

    assert response["phase"] == "stopping"
    assert calls == []


def test_cancel_refuses_activating_scope_without_acknowledging_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
    properties = {
        "Id": binding.scope_unit,
        "LoadState": "loaded",
        "ActiveState": "activating",
        "InvocationID": binding.scope_invocation_id,
        "ControlGroup": binding.scope_control_group,
        "Slice": binding.attempt_slice_unit,
    }
    monkeypatch.setattr(monitor_service, "_unit_properties", lambda *_args: properties)
    monkeypatch.setattr(monitor_service, "_scope_population", lambda _path: 1)
    monkeypatch.setattr(
        monitor_service,
        "_run_trusted_runtime_command",
        lambda *_args, **_kwargs: pytest.fail("unverified activation must not be acknowledged"),
    )

    assert monitor_service._scope_status(binding)["phase"] == "unknown"
    with pytest.raises(monitor_service.SandboxMonitorServiceError):
        monitor_service._cancel_scope(binding)


def test_monitor_start_creates_initial_key_but_never_places_it_in_service_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding = _binding()
    identity = (binding.attempt_id, binding.claim_token, binding.execution_id)
    state_path = tmp_path / "state"
    state_path.mkdir(mode=0o700)
    control_directory = state_path / "monitor"
    receipt_path = control_directory / "monitor-receipt.json"
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    socket_path = runtime / "acpmon-test.sock"
    monkeypatch.setattr(
        monitor_service.lifecycle,
        "sandbox_monitor_control_paths",
        lambda **_kwargs: (control_directory, receipt_path, socket_path),
    )
    monkeypatch.setattr(
        monitor_service.lifecycle,
        "_trusted_systemd_command_environment",
        lambda: {"XDG_RUNTIME_DIR": str(runtime)},
    )
    monkeypatch.setattr(
        monitor_service,
        "_scope_status",
        lambda _binding: {"phase": "running"},
    )
    monkeypatch.setattr(
        monitor_service, "_trusted_systemctl_executable", lambda: Path("/usr/bin/systemctl")
    )
    monkeypatch.setattr(
        monitor_service,
        "_trusted_systemd_command_environment",
        lambda: {"XDG_RUNTIME_DIR": str(runtime)},
    )
    monkeypatch.setattr(
        monitor_service, "_trusted_systemd_run_executable", lambda: Path("/usr/bin/systemd-run")
    )
    monkeypatch.setattr(
        monitor_service,
        "_read_unit_properties",
        lambda *_args: {"LoadState": "not-found"},
    )
    commands: list[list[str]] = []
    client_options: dict[str, object] = {}
    monkeypatch.setattr(
        monitor_service,
        "_run_trusted_runtime_command",
        lambda argv, **_kwargs: commands.append(argv) or b"",
    )
    monkeypatch.setattr(
        monitor_service,
        "_wait_for_receipt",
        lambda *_args, **_kwargs: SimpleNamespace(
            unit=monitor_service.sandbox_monitor_service_unit(*identity),
            attempt_slice_unit=binding.attempt_slice_unit,
        ),
    )

    class Client:
        def status(self):
            return SimpleNamespace(outcome="ok", payload={"phase": "running"})

    def make_client(**kwargs):
        client_options.update(kwargs)
        return Client()

    monkeypatch.setattr(monitor_service, "SandboxMonitorControlClient", make_client)
    client = monitor_service.start_sandbox_execution_monitor(
        state_path=state_path,
        expected_identity=identity,
        scope_unit=binding.scope_unit,
        scope_invocation_id=binding.scope_invocation_id,
        scope_control_group=binding.scope_control_group,
        attempt_slice_control_group=binding.attempt_slice_control_group,
    )

    assert isinstance(client, Client)
    assert client_options["timeout_seconds"] == 15.0
    assert (control_directory / "scope-binding.json").is_file()
    key_path = control_directory / f"{sandbox_container_id(*identity)}.control-key"
    assert key_path.stat().st_mode & 0o777 == 0o600
    command_text = "\0".join(commands[0])
    assert key_path.read_bytes().decode("latin1") not in command_text
    assert "--unit=" + monitor_service.sandbox_monitor_service_unit(*identity) in command_text
    assert "--execution-id\0" + binding.execution_id in command_text
    assert "control-key" not in command_text


def test_partial_monitor_state_fails_closed_without_replacing_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding = _binding()
    identity = (binding.attempt_id, binding.claim_token, binding.execution_id)
    state_path = tmp_path / "state"
    state_path.mkdir(mode=0o700)
    control_directory = state_path / "monitor"
    control_directory.mkdir(mode=0o700)
    key_path = control_directory / f"{sandbox_container_id(*identity)}.control-key"
    key_path.write_bytes(b"preserve-existing-key")
    key_path.chmod(0o600)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    monkeypatch.setattr(
        monitor_service.lifecycle,
        "sandbox_monitor_control_paths",
        lambda **_kwargs: (
            control_directory,
            control_directory / "monitor-receipt.json",
            runtime / "monitor.sock",
        ),
    )
    monkeypatch.setattr(
        monitor_service.lifecycle,
        "_trusted_systemd_command_environment",
        lambda: {"XDG_RUNTIME_DIR": str(runtime)},
    )
    monkeypatch.setattr(
        monitor_service,
        "_scope_status",
        lambda _binding: {"phase": "running"},
    )

    with pytest.raises(monitor_service.SandboxMonitorServiceError, match="partial monitor state"):
        monitor_service.start_sandbox_execution_monitor(
            state_path=state_path,
            expected_identity=identity,
            scope_unit=binding.scope_unit,
            scope_invocation_id=binding.scope_invocation_id,
            scope_control_group=binding.scope_control_group,
            attempt_slice_control_group=binding.attempt_slice_control_group,
        )
    assert key_path.read_bytes() == b"preserve-existing-key"
