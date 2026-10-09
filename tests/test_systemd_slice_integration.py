"""Opt-in proof that stopping an attempt slice stops its service and scope units.

Run with ``ACP_RUN_SYSTEMD_SLICE_INTEGRATION=1`` on a disposable Linux host
with an active user systemd manager and cgroup v2. This verifies systemd unit
dependency and cgroup teardown behavior only; it does not integrate or attest
the supervised OCI worker lifecycle.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
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
            "--property=LoadState",
            "--property=ActiveState",
            "--property=InvocationID",
            "--property=ControlGroup",
            "--property=Slice",
        ]
    )
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


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


def _probe() -> dict[str, Any]:
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
    try:
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

        pre_stop[slice_unit] = _wait_active(systemctl, slice_unit)
        pre_stop[service_unit] = _wait_active(systemctl, service_unit)
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
            "cgroups_empty": True,
            "scope_client_exit_code": scope_client.returncode,
        }
    finally:
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
            except (OSError, subprocess.TimeoutExpired):
                pass
        if scope_client is not None and scope_client.poll() is None:
            scope_client.terminate()
            try:
                scope_client.wait(timeout=2)
            except subprocess.TimeoutExpired:
                scope_client.kill()
                scope_client.wait(timeout=2)


def test_stopping_attempt_slice_stops_service_and_sibling_scope() -> None:
    import pytest

    if not _ENABLED:
        pytest.skip("set ACP_RUN_SYSTEMD_SLICE_INTEGRATION=1 on a disposable Linux host")
    evidence = _probe()
    assert evidence["cgroups_empty"] is True
    assert set(evidence["post_stop_states"].values()) <= {"inactive", "failed", "not-found"}


if __name__ == "__main__":
    if not _ENABLED:
        raise SystemExit("set ACP_RUN_SYSTEMD_SLICE_INTEGRATION=1 to run this probe")
    import json

    print(json.dumps(_probe(), sort_keys=True))
