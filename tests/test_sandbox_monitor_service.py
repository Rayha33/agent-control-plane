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


def _configure_held_runc_client_scope(
    monkeypatch: pytest.MonkeyPatch,
    *,
    scope_created: bool = True,
    scope_overrides: dict[str, str] | None = None,
    slice_overrides: dict[str, str] | None = None,
) -> SimpleNamespace:
    binding = _binding()
    identity = (binding.attempt_id, binding.claim_token, binding.execution_id)
    scope_unit = monitor_service.sandbox_runc_client_scope_unit(*identity)
    scope_cgroup = f"{binding.attempt_slice_control_group}/{scope_unit}"
    monitor_cgroup = (
        f"/user.slice/user-1000.slice/user@1000.service/user-acp.slice/"
        f"{monitor_service.sandbox_monitor_service_unit(*identity)}"
    )
    slice_properties = {
        "Id": binding.attempt_slice_unit,
        "LoadState": "loaded",
        "ActiveState": "active",
        "InvocationID": "b" * 32,
        "ControlGroup": binding.attempt_slice_control_group,
        "Slice": "user-acp.slice",
        **(slice_overrides or {}),
    }
    scope_properties = {
        "Id": scope_unit,
        "LoadState": "loaded",
        "ActiveState": "active",
        "InvocationID": "c" * 32,
        "ControlGroup": scope_cgroup,
        "Slice": binding.attempt_slice_unit,
        **(scope_overrides or {}),
    }
    scope_reads = 0

    def read_unit(unit: str, _properties: tuple[str, ...]) -> dict[str, str]:
        nonlocal scope_reads
        if unit == binding.attempt_slice_unit:
            return slice_properties
        assert unit == scope_unit
        scope_reads += 1
        if scope_reads == 1 or not scope_created:
            return {"LoadState": "not-found"}
        return scope_properties

    monkeypatch.setattr(monitor_service, "_unit_properties", read_unit)
    monkeypatch.setattr(
        monitor_service, "_trusted_busctl_executable", lambda: Path("/usr/bin/busctl")
    )
    monkeypatch.setattr(
        monitor_service,
        "_trusted_systemd_command_environment",
        lambda: {"DBUS_SESSION_BUS_ADDRESS": "test"},
    )
    membership_checks: list[tuple[int, str, str]] = []

    def verify_membership(pid: int, *, expected_cgroup: str, expected_identity: str) -> str:
        membership_checks.append((pid, expected_cgroup, expected_identity))
        return expected_identity

    monkeypatch.setattr(monitor_service, "verify_linux_process_membership", verify_membership)
    commands: list[list[str]] = []
    monkeypatch.setattr(
        monitor_service,
        "_run_trusted_runtime_command",
        lambda argv, **_kwargs: commands.append(argv) or b'"/org/freedesktop/systemd1/job/17"',
    )
    return SimpleNamespace(
        binding=binding,
        identity=identity,
        scope_unit=scope_unit,
        scope_cgroup=scope_cgroup,
        monitor_cgroup=monitor_cgroup,
        slice_properties=slice_properties,
        membership_checks=membership_checks,
        commands=commands,
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


def test_held_runc_client_scope_uses_exact_pid_and_slice_before_exec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
    identity = (binding.attempt_id, binding.claim_token, binding.execution_id)
    client_scope_unit = monitor_service.sandbox_runc_client_scope_unit(*identity)
    client_scope_cgroup = f"{binding.attempt_slice_control_group}/{client_scope_unit}"
    monitor_cgroup = (
        f"/user.slice/user-1000.slice/user@1000.service/user-acp.slice/"
        f"{monitor_service.sandbox_monitor_service_unit(*identity)}"
    )
    slice_properties = {
        "Id": binding.attempt_slice_unit,
        "LoadState": "loaded",
        "ActiveState": "active",
        "InvocationID": "b" * 32,
        "ControlGroup": binding.attempt_slice_control_group,
        "Slice": "user-acp.slice",
    }
    scope_properties = {
        "Id": client_scope_unit,
        "LoadState": "loaded",
        "ActiveState": "active",
        "InvocationID": "c" * 32,
        "ControlGroup": client_scope_cgroup,
        "Slice": binding.attempt_slice_unit,
    }
    scope_reads = 0

    def read_unit(unit: str, _properties: tuple[str, ...]) -> dict[str, str]:
        nonlocal scope_reads
        if unit == binding.attempt_slice_unit:
            return slice_properties
        assert unit == client_scope_unit
        scope_reads += 1
        return {"LoadState": "not-found"} if scope_reads == 1 else scope_properties

    monkeypatch.setattr(monitor_service, "_unit_properties", read_unit)
    monkeypatch.setattr(
        monitor_service, "_trusted_busctl_executable", lambda: Path("/usr/bin/busctl")
    )
    monkeypatch.setattr(
        monitor_service,
        "_trusted_systemd_command_environment",
        lambda: {"DBUS_SESSION_BUS_ADDRESS": "test"},
    )
    membership_checks: list[tuple[int, str, str]] = []

    def verify_membership(pid: int, *, expected_cgroup: str, expected_identity: str) -> str:
        membership_checks.append((pid, expected_cgroup, expected_identity))
        return expected_identity

    monkeypatch.setattr(monitor_service, "verify_linux_process_membership", verify_membership)
    commands: list[list[str]] = []
    monkeypatch.setattr(
        monitor_service,
        "_run_trusted_runtime_command",
        lambda argv, **_kwargs: commands.append(argv) or b'"/org/freedesktop/systemd1/job/17"',
    )

    result = monitor_service.attach_held_runc_client_to_attempt_scope(
        expected_identity=identity,
        pid=4321,
        pid_identity="linux:4321:7654321",
        monitor_control_group=monitor_cgroup,
        attempt_slice_invocation_id=slice_properties["InvocationID"],
        attempt_slice_control_group=binding.attempt_slice_control_group,
    )

    assert result.scope_unit == client_scope_unit
    assert result.scope_invocation_id == "c" * 32
    assert result.scope_control_group == client_scope_cgroup
    assert result.attempt_slice_unit == binding.attempt_slice_unit
    assert membership_checks == [
        (4321, monitor_cgroup, "linux:4321:7654321"),
        (4321, client_scope_cgroup, "linux:4321:7654321"),
    ]
    assert commands == [
        [
            "/usr/bin/busctl",
            "--user",
            "call",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "StartTransientUnit",
            "ssa(sv)a(sa(sv))",
            client_scope_unit,
            "fail",
            "2",
            "Slice",
            "s",
            binding.attempt_slice_unit,
            "PIDs",
            "au",
            "1",
            "4321",
            "0",
        ]
    ]


def test_held_runc_client_scope_refuses_existing_unit_without_starting_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
    identity = (binding.attempt_id, binding.claim_token, binding.execution_id)
    scope_unit = monitor_service.sandbox_runc_client_scope_unit(*identity)
    monitor_cgroup = (
        f"/user.slice/user-1000.slice/user@1000.service/user-acp.slice/"
        f"{monitor_service.sandbox_monitor_service_unit(*identity)}"
    )
    properties = {
        "Id": binding.attempt_slice_unit,
        "LoadState": "loaded",
        "ActiveState": "active",
        "InvocationID": "b" * 32,
        "ControlGroup": binding.attempt_slice_control_group,
        "Slice": "user-acp.slice",
    }

    def read_unit(unit: str, _props: tuple[str, ...]) -> dict[str, str]:
        if unit == binding.attempt_slice_unit:
            return properties
        assert unit == scope_unit
        return {"LoadState": "loaded"}

    monkeypatch.setattr(monitor_service, "_unit_properties", read_unit)
    monkeypatch.setattr(
        monitor_service, "verify_linux_process_membership", lambda *_args, **_kwargs: None
    )
    commands: list[list[str]] = []
    monkeypatch.setattr(
        monitor_service,
        "_run_trusted_runtime_command",
        lambda argv, **_kwargs: commands.append(argv) or b"",
    )

    with pytest.raises(monitor_service.SandboxMonitorServiceError, match="already exists"):
        monitor_service.attach_held_runc_client_to_attempt_scope(
            expected_identity=identity,
            pid=4321,
            pid_identity="linux:4321:7654321",
            monitor_control_group=monitor_cgroup,
            attempt_slice_invocation_id="b" * 32,
            attempt_slice_control_group=binding.attempt_slice_control_group,
        )

    assert commands == []


def test_held_runc_client_scope_reconciles_lost_bus_reply_without_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured = _configure_held_runc_client_scope(monkeypatch)

    def start_then_lose_reply(argv: list[str], **_kwargs: object) -> bytes:
        configured.commands.append(argv)
        raise TimeoutError("the manager reply was lost after scope creation")

    monkeypatch.setattr(monitor_service, "_run_trusted_runtime_command", start_then_lose_reply)

    result = monitor_service.attach_held_runc_client_to_attempt_scope(
        expected_identity=configured.identity,
        pid=4321,
        pid_identity="linux:4321:7654321",
        monitor_control_group=configured.monitor_cgroup,
        attempt_slice_invocation_id=configured.slice_properties["InvocationID"],
        attempt_slice_control_group=configured.binding.attempt_slice_control_group,
    )

    assert result.scope_unit == configured.scope_unit
    assert result.scope_control_group == configured.scope_cgroup
    assert len(configured.commands) == 1
    assert configured.membership_checks == [
        (4321, configured.monitor_cgroup, "linux:4321:7654321"),
        (4321, configured.scope_cgroup, "linux:4321:7654321"),
    ]


def test_held_runc_client_scope_does_not_retry_ambiguous_start_without_exact_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured = _configure_held_runc_client_scope(monkeypatch, scope_created=False)

    def start_without_observable_scope(argv: list[str], **_kwargs: object) -> bytes:
        configured.commands.append(argv)
        raise TimeoutError("the manager reply was lost and no exact scope is visible")

    monkeypatch.setattr(
        monitor_service, "_run_trusted_runtime_command", start_without_observable_scope
    )

    with pytest.raises(
        monitor_service.SandboxMonitorServiceError,
        match="ambiguous; caller must close, reap, and retain the fence",
    ):
        monitor_service.attach_held_runc_client_to_attempt_scope(
            expected_identity=configured.identity,
            pid=4321,
            pid_identity="linux:4321:7654321",
            monitor_control_group=configured.monitor_cgroup,
            attempt_slice_invocation_id=configured.slice_properties["InvocationID"],
            attempt_slice_control_group=configured.binding.attempt_slice_control_group,
            timeout_seconds=0.2,
        )

    assert len(configured.commands) == 1
    assert configured.membership_checks == [(4321, configured.monitor_cgroup, "linux:4321:7654321")]


def test_held_runc_client_scope_rejects_mismatched_slice_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured = _configure_held_runc_client_scope(
        monkeypatch, scope_overrides={"Slice": "user.slice"}
    )

    with pytest.raises(
        monitor_service.SandboxMonitorServiceError,
        match="readback is incomplete or stale",
    ):
        monitor_service.attach_held_runc_client_to_attempt_scope(
            expected_identity=configured.identity,
            pid=4321,
            pid_identity="linux:4321:7654321",
            monitor_control_group=configured.monitor_cgroup,
            attempt_slice_invocation_id=configured.slice_properties["InvocationID"],
            attempt_slice_control_group=configured.binding.attempt_slice_control_group,
        )

    assert len(configured.commands) == 1
    assert configured.membership_checks == [(4321, configured.monitor_cgroup, "linux:4321:7654321")]


def test_held_runc_client_scope_refuses_attempt_slice_with_wrong_parent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured = _configure_held_runc_client_scope(
        monkeypatch, slice_overrides={"Slice": "user.slice"}
    )

    with pytest.raises(
        monitor_service.SandboxMonitorServiceError,
        match="attempt slice identity changed before runc attachment",
    ):
        monitor_service.attach_held_runc_client_to_attempt_scope(
            expected_identity=configured.identity,
            pid=4321,
            pid_identity="linux:4321:7654321",
            monitor_control_group=configured.monitor_cgroup,
            attempt_slice_invocation_id=configured.slice_properties["InvocationID"],
            attempt_slice_control_group=configured.binding.attempt_slice_control_group,
        )

    assert configured.commands == []
    assert configured.membership_checks == []


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
    monkeypatch.setattr(monitor_service, "_SCOPE_CANCEL_GRACE_SECONDS", 0.0)

    response = monitor_service._cancel_scope(binding)

    assert response["phase"] == "exited"
    assert len(calls) == 1
    assert calls[0][-3:] == ["stop", "--", binding.scope_unit]
    assert "--no-block" in calls[0]
    assert binding.attempt_slice_unit not in calls[0]


def test_cancel_escalates_an_already_stopping_exact_scope_only_after_grace(
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
    monkeypatch.setattr(
        monitor_service, "_trusted_systemctl_executable", lambda: Path("/usr/bin/systemctl")
    )
    monkeypatch.setattr(
        monitor_service,
        "_trusted_systemd_command_environment",
        lambda: {"XDG_RUNTIME_DIR": "/run/user/1000"},
    )
    monkeypatch.setattr(monitor_service, "_SCOPE_CANCEL_GRACE_SECONDS", 0.0)
    monkeypatch.setattr(monitor_service, "_SCOPE_CANCEL_FORCE_WAIT_SECONDS", 0.0)

    response = monitor_service._cancel_scope(binding)

    assert response["phase"] == "stopping"
    assert len(calls) == 1
    assert calls[0] == [
        "/usr/bin/systemctl",
        "--user",
        "kill",
        "--signal=SIGKILL",
        "--kill-whom=all",
        "--",
        binding.scope_unit,
    ]


def test_cancel_force_kills_only_the_exact_scope_after_graceful_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
    phases = iter(("running", "stopping", "exited"))
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
    monkeypatch.setattr(monitor_service, "_SCOPE_CANCEL_GRACE_SECONDS", 0.0)
    monkeypatch.setattr(monitor_service, "_SCOPE_CANCEL_FORCE_WAIT_SECONDS", 0.0)

    response = monitor_service._cancel_scope(binding)

    assert response["phase"] == "exited"
    assert calls == [
        [
            "/usr/bin/systemctl",
            "--user",
            "--no-block",
            "stop",
            "--",
            binding.scope_unit,
        ],
        [
            "/usr/bin/systemctl",
            "--user",
            "kill",
            "--signal=SIGKILL",
            "--kill-whom=all",
            "--",
            binding.scope_unit,
        ],
    ]


def test_cancel_does_not_escalate_after_scope_identity_becomes_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
    phases = iter(("running", "unknown"))
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
    monkeypatch.setattr(monitor_service, "_SCOPE_CANCEL_GRACE_SECONDS", 0.0)

    with pytest.raises(monitor_service.SandboxMonitorServiceError):
        monitor_service._cancel_scope(binding)

    assert len(calls) == 1
    assert calls[0][-3:] == ["stop", "--", binding.scope_unit]


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
