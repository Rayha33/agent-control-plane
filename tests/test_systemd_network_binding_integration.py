"""Opt-in proof of systemd attempt-to-command network namespace binding.

Run only on a disposable Linux host with systemd 247+, an active system manager,
and cgroup v2 as root. Before opt-in, create the root-owned marker (the test
refuses to run without it):
``ACP_RUN_SYSTEMD_NETWORK_BINDING_INTEGRATION=1 pytest -q tests/test_systemd_network_binding_integration.py``
``printf 'acp-systemd-network-binding-v1\\n' | sudo tee /run/acp-disposable-systemd-test >/dev/null && sudo chmod 600 /run/acp-disposable-systemd-test``

This exercises a systemd primitive with local fake app, DB/schema, and queue
services. It proves that commands join one exact attempt namespace, sibling
ports are unreachable, and a healthy wrong-attempt response fails before the
fake DB or queue is mutated. It is not the ACP broker or production worker
path; it does not prove broker authorization, restart recovery, disk limits,
or cleanup from every crash boundary.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import stat
import subprocess
import time
import uuid
from pathlib import Path

import pytest

_ENABLED = os.environ.get("ACP_RUN_SYSTEMD_NETWORK_BINDING_INTEGRATION") == "1"
_MIN_SYSTEMD_VERSION = 247
_WAIT_SECONDS = 12.0
_PROBE_SECONDS = 0.75
_ROLES = ("app", "database", "queue")
_PROTECTED_RUNTIME_PATHS = "/run/systemd/private /run/dbus/system_bus_socket"
_DISPOSABLE_HOST_MARKER = Path("/run/acp-disposable-systemd-test")
_DISPOSABLE_HOST_MARKER_CONTENT = "acp-systemd-network-binding-v1\n"


def _environment() -> dict[str, str]:
    return {
        "LC_ALL": "C",
        "LANG": "C",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    }


def _run(
    argv: list[str],
    *,
    timeout: float = _WAIT_SECONDS,
    accepted_returncodes: tuple[int, ...] = (0,),
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


def _properties(systemctl: str, unit: str) -> dict[str, str]:
    result = _run(
        [
            systemctl,
            "--system",
            "show",
            unit,
            "--no-pager",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=InvocationID",
            "--property=ControlGroup",
            "--property=MainPID",
            "--property=Result",
            "--property=ExecMainStatus",
        ]
    )
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def _wait_active(systemctl: str, unit: str) -> dict[str, str]:
    deadline = time.monotonic() + _WAIT_SECONDS
    while time.monotonic() < deadline:
        state = _properties(systemctl, unit)
        if state.get("ActiveState") == "active" and state.get("MainPID", "0") != "0":
            return state
        if state.get("ActiveState") == "failed":
            raise RuntimeError(f"transient unit {unit} failed to start: {state}")
        time.sleep(0.05)
    raise RuntimeError(f"transient unit {unit} did not become active")


def _wait_inactive(systemctl: str, unit: str) -> dict[str, str]:
    deadline = time.monotonic() + _WAIT_SECONDS
    while time.monotonic() < deadline:
        state = _properties(systemctl, unit)
        if state.get("ActiveState") in {"inactive", "failed"}:
            return state
        time.sleep(0.05)
    raise RuntimeError(f"transient unit {unit} did not finish")


def _namespace_identity(pid: int) -> tuple[int, int]:
    info = os.stat(f"/proc/{pid}/ns/net")
    return info.st_dev, info.st_ino


def _assert_disposable_host_marker() -> None:
    """Require an explicit root-created marker before changing systemd state."""

    try:
        info = _DISPOSABLE_HOST_MARKER.lstat()
        marker = _DISPOSABLE_HOST_MARKER.read_text(encoding="ascii")
    except FileNotFoundError:
        pytest.skip("requires root-created /run/acp-disposable-systemd-test on a disposable host")
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
        or marker != _DISPOSABLE_HOST_MARKER_CONTENT
    ):
        pytest.fail("disposable-host marker is not a root-owned, protected exact marker file")


def _systemd_version(systemctl: str) -> int:
    version = _run([systemctl, "--version"]).stdout.splitlines()[0].split()
    if len(version) < 2 or not version[1].isdigit():
        pytest.skip("could not determine the installed systemd version")
    return int(version[1])


def _cgroup_events(cgroup: Path) -> dict[str, str] | None:
    try:
        content = (cgroup / "cgroup.events").read_text()
    except FileNotFoundError:
        return None if not cgroup.exists() else {}
    return dict(line.split(" ", 1) for line in content.splitlines() if " " in line)


def _resource_identity(attempt: str, role: str) -> dict[str, str]:
    identity = {"attempt_id": attempt, "resource": role}
    if role == "app":
        identity["service_id"] = f"{attempt}-app"
    elif role == "database":
        identity["schema"] = f"schema-{attempt}"
    else:
        identity["queue"] = f"queue-{attempt}"
    return identity


def _resource_server_script(port: int, attempt: str, role: str) -> str:
    identity = json.dumps(_resource_identity(attempt, role), sort_keys=True)
    return f"""\
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

identity = json.loads({identity!r})
state = {{"writes": 0}}

class Handler(BaseHTTPRequestHandler):
    def reply(self, value):
        body = json.dumps(value, sort_keys=True).encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/identity":
            self.reply(identity)
        elif self.path == "/state":
            self.reply(
                {{
                    "attempt_id": identity["attempt_id"],
                    "resource": identity["resource"],
                    "writes": state["writes"],
                }}
            )
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path != "/mutate" or identity["resource"] == "app":
            self.send_error(404)
            return
        state["writes"] += 1
        self.reply({{"writes": state["writes"]}})

    def log_message(self, *_args):
        pass

HTTPServer(("127.0.0.1", {port}), Handler).serve_forever()
"""


def _command_script(
    *,
    mode: str,
    expected_attempt: str,
    ports: dict[str, int],
    systemd_run: str,
    forbidden_unit: str,
    holder_pid: int,
) -> str:
    expected = {role: _resource_identity(expected_attempt, role) for role in _ROLES}
    return f"""\
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

opener = urllib.request.build_opener(urllib.request.ProxyHandler({{}}))
ports = {ports!r}
expected = {expected!r}
mode = {mode!r}

def finish(code):
    time.sleep({_PROBE_SECONDS})
    sys.exit(code)

manager = subprocess.run(
    [{systemd_run!r}, "--system", "--quiet", "--wait",
     {f"--unit={forbidden_unit}"!r}, "/usr/bin/true"],
    check=False,
    capture_output=True,
    text=True,
    timeout=3,
)
print("acp_system_manager_rc=" + str(manager.returncode), flush=True)
if "permission denied" not in manager.stderr.lower():
    print("acp_system_manager_denial=unexpected", flush=True)
    finish(20)
print("acp_system_manager_denial=permission-denied", flush=True)
if manager.returncode == 0:
    finish(19)

try:
    os.stat("/proc/{holder_pid}")
    holder_visible = True
except FileNotFoundError:
    holder_visible = False
try:
    os.kill({holder_pid}, 0)
    holder_signal_denied = False
except PermissionError:
    holder_signal_denied = True
print("acp_holder_proc_visible=" + str(int(holder_visible)), flush=True)
print("acp_holder_signal_denied=" + str(int(holder_signal_denied)), flush=True)
if holder_visible or not holder_signal_denied:
    finish(18)

def request(role, path, data=None, timeout=1.5):
    url = "http://127.0.0.1:" + str(ports[role]) + path
    request = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    with opener.open(request, timeout=timeout) as response:
        return json.loads(response.read().decode("ascii"))

if mode == "reachability":
    reachable = []
    for role in ("app", "database", "queue"):
        try:
            request(role, "/identity", timeout=0.5)
        except (urllib.error.URLError, OSError, TimeoutError):
            continue
        reachable.append(role)
    print("acp_sibling_endpoints_reachable=" + ",".join(reachable), flush=True)
    finish(18 if not reachable else 19)

if mode == "state":
    state = {{role: request(role, "/state") for role in ("database", "queue")}}
    print("acp_resource_state=" + json.dumps(state, sort_keys=True), flush=True)
    finish(0)

observed = {{}}
for role in ("app", "database", "queue"):
    try:
        observed[role] = request(role, "/identity")
    except (urllib.error.URLError, OSError, TimeoutError):
        print("acp_identity_match=unreachable", flush=True)
        finish(18)

if observed != expected:
    print("acp_identity_match=0", flush=True)
    print("acp_observed=" + json.dumps(observed, sort_keys=True), flush=True)
    finish(17)

print("acp_identity_match=1", flush=True)
if mode == "validate":
    finish(0)
database_write = request("database", "/mutate", data=b"write")
queue_write = request("queue", "/mutate", data=b"write")
print("acp_database_writes=" + str(database_write["writes"]), flush=True)
print("acp_queue_writes=" + str(queue_write["writes"]), flush=True)
finish(0)
"""


def _start_unit(
    systemd_run: str,
    systemctl: str,
    unit: str,
    command: list[str],
    properties: list[str],
    created_units: list[str],
) -> None:
    if _properties(systemctl, f"{unit}.service").get("LoadState") != "not-found":
        raise RuntimeError(f"refusing to start pre-existing transient unit {unit}.service")
    _run(
        [
            systemd_run,
            "--system",
            "--quiet",
            "--no-block",
            f"--unit={unit}",
            *[f"--property={value}" for value in properties],
            *command,
        ]
    )
    created_units.append(unit)


def _unit_properties(*, joins_namespace_of: str | None = None) -> list[str]:
    properties = [
        "Type=exec",
        "DynamicUser=yes",
        "KillMode=control-group",
        "Delegate=no",
        "NoNewPrivileges=yes",
        "ProtectControlGroups=yes",
        "ProtectProc=invisible",
        f"InaccessiblePaths={_PROTECTED_RUNTIME_PATHS}",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "RuntimeMaxSec=30s",
        "StandardOutput=journal",
        "StandardError=journal",
    ]
    properties.append("PrivateNetwork=yes")
    if joins_namespace_of is not None:
        properties.append(f"JoinsNamespaceOf={joins_namespace_of}")
    return properties


def _run_command_unit(
    *,
    systemd_run: str,
    systemctl: str,
    journalctl: str,
    created_units: list[str],
    unit: str,
    holder_unit: str,
    holder_pid: int,
    holder_namespace: tuple[int, int],
    mode: str,
    expected_attempt: str,
    ports: dict[str, int],
    forbidden_unit: str,
) -> tuple[dict[str, str], str]:
    script = _command_script(
        mode=mode,
        expected_attempt=expected_attempt,
        ports=ports,
        systemd_run=systemd_run,
        forbidden_unit=forbidden_unit,
        holder_pid=holder_pid,
    )
    _start_unit(
        systemd_run,
        systemctl,
        unit,
        ["/usr/bin/python3", "-I", "-c", script],
        _unit_properties(joins_namespace_of=f"{holder_unit}.service"),
        created_units,
    )
    systemd_unit = f"{unit}.service"
    state = _wait_active(systemctl, systemd_unit)
    main_pid = int(state["MainPID"])
    if _namespace_identity(main_pid) != holder_namespace:
        raise RuntimeError(f"phase unit {unit} did not join its exact holder namespace")
    if not state.get("InvocationID"):
        raise RuntimeError(f"phase unit {unit} has no systemd InvocationID")

    finished = _wait_inactive(systemctl, systemd_unit)
    output = _run(
        [journalctl, "--system", "--unit", systemd_unit, "--output=cat", "--no-pager"]
    ).stdout
    return finished, output


@pytest.mark.skipif(
    not _ENABLED,
    reason="requires an explicit opt-in on a disposable systemd test host",
)
def test_systemd_phase_commands_are_bound_to_one_attempt_and_fail_closed_on_crosswire() -> None:
    if not os.name == "posix" or not Path("/run/systemd/system").is_dir():
        pytest.skip("requires a running Linux systemd manager")
    if os.geteuid() != 0:
        pytest.skip("system-manager transient units require root authorization")
    if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        pytest.skip("requires cgroup v2")
    _assert_disposable_host_marker()

    systemd_run = shutil.which("systemd-run", path=_environment()["PATH"])
    systemctl = shutil.which("systemctl", path=_environment()["PATH"])
    journalctl = shutil.which("journalctl", path=_environment()["PATH"])
    if not systemd_run or not systemctl or not journalctl:
        pytest.skip("systemd-run, systemctl, and journalctl are required")
    if _systemd_version(systemctl) < _MIN_SYSTEMD_VERSION:
        pytest.skip(f"requires systemd {_MIN_SYSTEMD_VERSION} or newer")

    suffix = uuid.uuid4().hex[:16]
    attempt_a = f"attempt-a-{suffix}"
    attempt_b = f"attempt-b-{suffix}"
    holder_a = f"acp-netbind-holder-a-{suffix}"
    holder_b = f"acp-netbind-holder-b-{suffix}"
    phase_specs = (
        ("write-a", "write", attempt_a, attempt_a, attempt_a),
        ("write-b", "write", attempt_b, attempt_b, attempt_b),
        ("wrong-identity", "write", attempt_b, attempt_a, attempt_a),
        ("sibling-ports", "reachability", attempt_b, attempt_a, attempt_b),
        ("state-a", "state", attempt_a, attempt_a, attempt_a),
        ("state-b", "state", attempt_b, attempt_b, attempt_b),
    )
    phase_units = {name: f"acp-netbind-{name}-{suffix}" for name, *_ in phase_specs}
    restart_phase_name = "holder-restarted"
    phase_units[restart_phase_name] = f"acp-netbind-{restart_phase_name}-{suffix}"
    forbidden_units = {name: f"acp-netbind-forbidden-{name}-{suffix}" for name in (*phase_units,)}
    ports_a_base = secrets.randbelow(10000) + 30000
    ports_b_base = ports_a_base + 15000
    ports_by_attempt = {
        attempt_a: {role: ports_a_base + index for index, role in enumerate(_ROLES)},
        attempt_b: {role: ports_b_base + index for index, role in enumerate(_ROLES)},
    }
    if set(ports_by_attempt[attempt_a].values()) & set(ports_by_attempt[attempt_b].values()):
        raise RuntimeError("attempt resource ports unexpectedly overlap")

    resource_units = [f"{holder}-{role}" for holder in (holder_a, holder_b) for role in _ROLES]
    reserved_units = [
        holder_a,
        holder_b,
        *resource_units,
        *phase_units.values(),
        *forbidden_units.values(),
    ]
    created_units: list[str] = []
    try:
        for unit in reserved_units:
            if _properties(systemctl, f"{unit}.service").get("LoadState") != "not-found":
                raise RuntimeError(f"generated systemd unit name is already in use: {unit}.service")
        sleep = shutil.which("sleep", path=_environment()["PATH"]) or "/usr/bin/sleep"
        python = shutil.which("python3", path=_environment()["PATH"]) or "/usr/bin/python3"
        if not Path(sleep).is_file() or not os.access(sleep, os.X_OK):
            raise RuntimeError("verified sleep executable is unavailable")
        if not Path("/usr/bin/true").is_file() or not os.access("/usr/bin/true", os.X_OK):
            raise RuntimeError("verified /usr/bin/true executable is unavailable")
        for holder in (holder_a, holder_b):
            _start_unit(
                systemd_run,
                systemctl,
                holder,
                [sleep, "infinity"],
                _unit_properties(),
                created_units,
            )
        state_a = _wait_active(systemctl, f"{holder_a}.service")
        state_b = _wait_active(systemctl, f"{holder_b}.service")
        pid_by_attempt = {
            attempt_a: int(state_a["MainPID"]),
            attempt_b: int(state_b["MainPID"]),
        }
        namespace_by_attempt = {
            attempt_a: _namespace_identity(pid_by_attempt[attempt_a]),
            attempt_b: _namespace_identity(pid_by_attempt[attempt_b]),
        }
        if namespace_by_attempt[attempt_a] == namespace_by_attempt[attempt_b]:
            raise RuntimeError("attempt holders unexpectedly share a network namespace")

        invocation_ids = {state_a.get("InvocationID", ""), state_b.get("InvocationID", "")}
        if "" in invocation_ids or len(invocation_ids) != 2:
            raise RuntimeError("attempt holders lack distinct systemd InvocationIDs")

        resource_states: dict[str, dict[str, dict[str, str]]] = {attempt_a: {}, attempt_b: {}}
        for attempt, holder in ((attempt_a, holder_a), (attempt_b, holder_b)):
            namespace = namespace_by_attempt[attempt]
            for role in _ROLES:
                unit = f"{holder}-{role}"
                _start_unit(
                    systemd_run,
                    systemctl,
                    unit,
                    [
                        python,
                        "-I",
                        "-c",
                        _resource_server_script(ports_by_attempt[attempt][role], attempt, role),
                    ],
                    _unit_properties(joins_namespace_of=f"{holder}.service"),
                    created_units,
                )
                state = _wait_active(systemctl, f"{unit}.service")
                resource_states[attempt][role] = state
                if _namespace_identity(int(state["MainPID"])) != namespace:
                    raise RuntimeError(f"resource unit {unit} joined the wrong attempt namespace")
                invocation = state.get("InvocationID", "")
                if not invocation or invocation in invocation_ids:
                    raise RuntimeError(f"resource unit {unit} has a missing or reused InvocationID")
                invocation_ids.add(invocation)

        outputs: dict[str, str] = {}
        finished_states: dict[str, dict[str, str]] = {}
        for name, mode, expected, endpoint_attempt, command_attempt in phase_specs:
            finished, output = _run_command_unit(
                systemd_run=systemd_run,
                systemctl=systemctl,
                journalctl=journalctl,
                created_units=created_units,
                unit=phase_units[name],
                holder_unit=holder_a if endpoint_attempt == attempt_a else holder_b,
                holder_pid=pid_by_attempt[endpoint_attempt],
                holder_namespace=namespace_by_attempt[endpoint_attempt],
                mode=mode,
                expected_attempt=expected,
                ports=ports_by_attempt[command_attempt],
                forbidden_unit=forbidden_units[name],
            )
            outputs[name] = output
            finished_states[name] = finished

        for name in outputs:
            output = outputs[name]
            if "acp_system_manager_denial=permission-denied" not in output:
                raise RuntimeError(f"untrusted phase {name} did not prove socket denial")
            if "acp_system_manager_rc=0" in output:
                raise RuntimeError(f"untrusted phase {name} reached the system manager")
            if "acp_holder_proc_visible=0" not in output:
                raise RuntimeError(f"untrusted phase {name} inspected its holder")
            if "acp_holder_signal_denied=1" not in output:
                raise RuntimeError(f"untrusted phase {name} could signal its holder")

        for name in ("write-a", "write-b", "state-a", "state-b"):
            if finished_states[name].get("Result") != "success":
                raise RuntimeError(f"valid command {name} failed: {finished_states[name]}")
        for name in ("wrong-identity", "sibling-ports"):
            if finished_states[name].get("Result") != "exit-code":
                raise RuntimeError(f"negative command {name} did not fail: {finished_states[name]}")

        for name in phase_units:
            forbidden_state = _properties(systemctl, f"{forbidden_units[name]}.service")
            if (
                forbidden_state.get("LoadState") != "not-found"
                or forbidden_state.get("MainPID", "0") != "0"
            ):
                raise RuntimeError(
                    f"worker manager request created its forbidden unit: {forbidden_state}"
                )
            if name in finished_states and finished_states[name].get("ExecMainStatus") == "20":
                raise RuntimeError(f"phase {name} manager denial reason was not Permission denied")

        original_holder_invocation = state_a["InvocationID"]
        original_holder_namespace = namespace_by_attempt[attempt_a]
        original_service_invocations = {
            role: resource_states[attempt_a][role]["InvocationID"] for role in _ROLES
        }
        _run([systemctl, "--system", "restart", f"{holder_a}.service"])
        restarted_holder = _wait_active(systemctl, f"{holder_a}.service")
        restarted_namespace = _namespace_identity(int(restarted_holder["MainPID"]))
        if restarted_holder.get("InvocationID") in {"", original_holder_invocation}:
            raise RuntimeError("holder restart did not produce a new systemd InvocationID")
        print(
            "acp_holder_namespace_reused_after_restart="
            + str(int(restarted_namespace == original_holder_namespace)),
            flush=True,
        )
        for role in _ROLES:
            resource_unit = f"{holder_a}-{role}.service"
            current_resource = _properties(systemctl, resource_unit)
            if current_resource.get("InvocationID") != original_service_invocations[role]:
                raise RuntimeError(f"resource unit {resource_unit} unexpectedly restarted")
            if current_resource.get("MainPID", "0") == "0":
                raise RuntimeError(f"resource unit {resource_unit} unexpectedly stopped")
            if (
                _namespace_identity(int(current_resource["MainPID"]))
                != namespace_by_attempt[attempt_a]
            ):
                raise RuntimeError(f"resource unit {resource_unit} escaped its original namespace")

        # A changed InvocationID invalidates the old binding even on systemd
        # versions that keep the same network namespace inode for this unit.
        if restarted_holder["InvocationID"] == original_holder_invocation:
            raise RuntimeError("a pre-restart target receipt would remain current")

        restarted_finished, restarted_output = _run_command_unit(
            systemd_run=systemd_run,
            systemctl=systemctl,
            journalctl=journalctl,
            created_units=created_units,
            unit=phase_units[restart_phase_name],
            holder_unit=holder_a,
            holder_pid=int(restarted_holder["MainPID"]),
            holder_namespace=restarted_namespace,
            mode="validate",
            expected_attempt=attempt_a,
            ports=ports_by_attempt[attempt_a],
            forbidden_unit=forbidden_units[restart_phase_name],
        )
        if "acp_system_manager_denial=permission-denied" not in restarted_output:
            raise RuntimeError("restarted phase did not prove system-manager socket denial")
        if "acp_holder_proc_visible=0" not in restarted_output or (
            "acp_holder_signal_denied=1" not in restarted_output
        ):
            raise RuntimeError("restarted phase could inspect or signal its namespace holder")
        if restarted_namespace == original_holder_namespace:
            if "acp_identity_match=1" not in restarted_output:
                raise RuntimeError(
                    "fresh post-restart validation rejected its live attempt services"
                )
            if restarted_finished.get("Result") != "success":
                raise RuntimeError("fresh post-restart target validation failed")
        elif (
            "acp_identity_match=unreachable" not in restarted_output
            or restarted_finished.get("ExecMainStatus") != "18"
        ):
            raise RuntimeError("post-restart phase did not fail closed on unavailable services")
        restarted_forbidden = _properties(
            systemctl, f"{forbidden_units[restart_phase_name]}.service"
        )
        if restarted_forbidden.get("LoadState") != "not-found":
            raise RuntimeError("restarted phase reached the system manager")

        if "acp_identity_match=1" not in outputs["write-a"]:
            raise RuntimeError("attempt A did not validate its app/DB/schema/queue identities")
        if "acp_identity_match=1" not in outputs["write-b"]:
            raise RuntimeError("attempt B did not validate its app/DB/schema/queue identities")
        if "acp_identity_match=0" not in outputs["wrong-identity"]:
            raise RuntimeError("healthy wrong-attempt responses were not rejected")
        if finished_states["wrong-identity"].get("ExecMainStatus") != "17":
            raise RuntimeError("wrong-identity command did not fail before its writes")
        if "acp_sibling_endpoints_reachable=\n" not in outputs["sibling-ports"]:
            raise RuntimeError("sibling app/database/queue ports were reachable")
        if finished_states["sibling-ports"].get("ExecMainStatus") != "18":
            raise RuntimeError("sibling-port command did not fail closed")

        state_a_line = next(
            line
            for line in outputs["state-a"].splitlines()
            if line.startswith("acp_resource_state=")
        )
        state_b_line = next(
            line
            for line in outputs["state-b"].splitlines()
            if line.startswith("acp_resource_state=")
        )
        expected_state_a = {
            "database": {"attempt_id": attempt_a, "resource": "database", "writes": 1},
            "queue": {"attempt_id": attempt_a, "resource": "queue", "writes": 1},
        }
        expected_state_b = {
            "database": {"attempt_id": attempt_b, "resource": "database", "writes": 1},
            "queue": {"attempt_id": attempt_b, "resource": "queue", "writes": 1},
        }
        if json.loads(state_a_line.split("=", 1)[1]) != expected_state_a:
            raise RuntimeError(
                "attempt A writable state changed outside its own successful command"
            )
        if json.loads(state_b_line.split("=", 1)[1]) != expected_state_b:
            raise RuntimeError(
                "attempt B writable state changed outside its own successful command"
            )
    finally:
        cleanup_errors: list[str] = []
        control_groups: dict[str, str] = {}
        for unit in created_units:
            try:
                control_group = _properties(systemctl, f"{unit}.service").get("ControlGroup", "")
                if control_group:
                    expected_group = f"/system.slice/{unit}.service"
                    if control_group != expected_group:
                        cleanup_errors.append(f"{unit}: unexpected ControlGroup={control_group}")
                    else:
                        control_groups[unit] = control_group
            except Exception as error:
                cleanup_errors.append(f"{unit}: could not capture ControlGroup: {error}")
        for unit in reversed(created_units):
            try:
                if _properties(systemctl, f"{unit}.service").get("LoadState") != "loaded":
                    continue
                _run(
                    [systemctl, "--system", "stop", f"{unit}.service"],
                    accepted_returncodes=(0, 1, 5),
                )
                if _properties(systemctl, f"{unit}.service").get("LoadState") == "loaded":
                    _run(
                        [systemctl, "--system", "reset-failed", f"{unit}.service"],
                        accepted_returncodes=(0, 1),
                    )
            except Exception as error:
                cleanup_errors.append(f"{unit}: {error}")
        for unit in created_units:
            try:
                state = _properties(systemctl, f"{unit}.service")
                if state.get("ActiveState") == "active" or state.get("MainPID", "0") != "0":
                    cleanup_errors.append(
                        f"{unit}: still active with MainPID={state.get('MainPID')}"
                    )
            except Exception as error:
                cleanup_errors.append(f"{unit}: post-cleanup check failed: {error}")
        for unit, control_group in control_groups.items():
            cgroup = Path("/sys/fs/cgroup") / control_group.lstrip("/")
            deadline = time.monotonic() + _WAIT_SECONDS
            values = _cgroup_events(cgroup)
            while values is not None and values.get("populated") != "0":
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.05)
                values = _cgroup_events(cgroup)
            if values is not None and values.get("populated") != "0":
                cleanup_errors.append(f"{unit}: cgroup did not become empty: {values}")
        if cleanup_errors:
            raise RuntimeError("transient unit cleanup failed: " + "; ".join(cleanup_errors))
