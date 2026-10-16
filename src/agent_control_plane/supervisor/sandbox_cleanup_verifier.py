"""Independent, supervisor-owned verification and final removal of OCI attempts.

The launch driver records only the pinned-runc delete action. This verifier runs
after that service has stopped, takes the persistent execution-root fence,
reconciles exact systemd/process/cgroup identities, then removes only the bound
``bundle`` and ``state`` children. Unknown observations leave the attempt fenced.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import time
from pathlib import Path, PurePosixPath
from typing import Any

from . import sandbox_attestation, sandbox_monitor_lifecycle, sandbox_monitor_receipt
from . import sandbox_execution_journal as journal
from .common import SupervisorError, canonical_json, utc_now
from .oci_worker import _runc_execution_gate_fence
from .sandbox_attestation import (
    _run_trusted_runtime_command,
    _trusted_systemctl_executable,
    _trusted_systemd_command_environment,
)

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_PROCESS_IDENTITY = re.compile(r"linux:([1-9][0-9]{0,9}):([1-9][0-9]*)\Z")
_SYSTEMD_PROPERTIES = (
    "Id",
    "LoadState",
    "ActiveState",
    "InvocationID",
    "ControlGroup",
    "MainPID",
)
_SYSTEMD_SLICE_PROPERTIES = (
    "Id",
    "LoadState",
    "ActiveState",
    "InvocationID",
    "ControlGroup",
)
_MAX_CGROUPS = 8192
_MAX_CGROUP_DEPTH = 128
_MAX_MOUNTINFO_BYTES = 8 * 1024 * 1024
_VERIFY_TIMEOUT_SECONDS = 10.0


def _read_cleanup_unit_properties(
    systemctl: Path,
    environment: dict[str, str],
    unit: str,
    properties: tuple[str, ...],
) -> dict[str, str]:
    """Accept systemd's sparse property response only for a confirmed absent unit."""

    try:
        return sandbox_monitor_lifecycle._read_unit_properties(
            systemctl, environment, unit, properties
        )
    except Exception as original_error:
        try:
            state = sandbox_monitor_lifecycle._read_unit_properties(
                systemctl, environment, unit, ("LoadState",)
            )
        except Exception as fallback_error:
            raise original_error from fallback_error
        if state.get("LoadState") != "not-found":
            raise original_error from None
        # systemd 252 omits properties such as MainPID for unloaded transient
        # units. A separate exact LoadState query confirms not-found; process
        # identities and cgroup emptiness are independently checked as well.
        return {
            "Id": unit,
            "LoadState": "not-found",
            "ActiveState": "inactive",
            "InvocationID": "",
            "ControlGroup": "",
            "MainPID": "0",
        }


def _sandbox_cleanup_verification_json_is_self_consistent(row: Any, encoded: Any) -> bool:
    """Validate the durable binding needed by consumers after verifier exit."""

    if (
        not isinstance(encoded, str)
        or not encoded
        or len(encoded.encode("utf-8", errors="ignore")) > 64 * 1024
        or row["phase"] != "cleanup_verified"
        or type(row["runc_exit_code"]) is not int
        or row["runc_exit_evidence_source"] != "runc_client_kernel_waitpid"
        or not isinstance(row["cleanup_receipt_json"], str)
    ):
        return False
    try:
        candidate = json.loads(encoded)
        cleanup = json.loads(row["cleanup_receipt_json"])
        if canonical_json(candidate) != encoded:
            return False
        report_digest = hashlib.sha256(row["cleanup_receipt_json"].encode("utf-8")).hexdigest()
        if (
            not isinstance(cleanup, dict)
            or cleanup.get("version") != 3
            or type(cleanup.get("version")) is not int
            or cleanup.get("verification_status") != "unverified"
            or cleanup.get("attempt_id") != row["attempt_id"]
            or type(cleanup.get("claim_token")) is not int
            or cleanup.get("claim_token") != row["claim_token"]
            or cleanup.get("execution_id") != row["execution_id"]
            or type(cleanup.get("runc_exit_code")) is not int
            or cleanup["runc_exit_code"] != row["runc_exit_code"]
            or not isinstance(cleanup.get("action"), dict)
            or type(cleanup["action"].get("returncode")) is not int
            or cleanup["action"].get("returncode") != 0
            or cleanup["action"].get("state_entry_absent_immediately_after_delete") is not True
        ):
            return False
        expected_keys = {
            "version",
            "attempt_id",
            "claim_token",
            "execution_id",
            "cleanup_report_sha256",
            "verified_at",
            "verifier",
            "observations",
        }
        if (
            not isinstance(candidate, dict)
            or set(candidate) != expected_keys
            or candidate.get("version") != 1
            or type(candidate.get("version")) is not int
            or candidate.get("attempt_id") != row["attempt_id"]
            or type(candidate.get("claim_token")) is not int
            or candidate.get("claim_token") != row["claim_token"]
            or candidate.get("execution_id") != row["execution_id"]
            or candidate.get("cleanup_report_sha256") != report_digest
            or not isinstance(candidate.get("verified_at"), str)
            or not candidate["verified_at"]
        ):
            return False
        verifier = candidate.get("verifier")
        observations = candidate.get("observations")
        if (
            not isinstance(verifier, dict)
            or set(verifier) != {"pid", "identity"}
            or type(verifier.get("pid")) is not int
            or verifier["pid"] <= 0
            or not isinstance(verifier.get("identity"), str)
        ):
            return False
        match = _PROCESS_IDENTITY.fullmatch(verifier["identity"])
        if match is None or int(match.group(1)) != verifier["pid"]:
            return False
        if not isinstance(observations, dict) or set(observations) != {
            "units",
            "processes",
            "cgroups",
            "paths",
        }:
            return False
        units = observations["units"]
        processes = observations["processes"]
        cgroups = observations["cgroups"]
        paths = observations["paths"]
        expected_container_id = sandbox_monitor_receipt.sandbox_container_id(
            row["attempt_id"], row["claim_token"], row["execution_id"]
        )
        expected_monitor_socket_name = f"acpmon-{expected_container_id.removeprefix('acp-')}.sock"
        expected_cgroups = {
            row["wrapper_cgroup_path"],
            row["launch_driver_cgroup_path"],
            row["cgroup_path"],
            row["attempt_slice_cgroup_path"],
        }
        if (
            not isinstance(units, dict)
            or set(units) != {"monitor", "launch_driver", "scope", "attempt_slice"}
            or not isinstance(processes, dict)
            or set(processes)
            != {
                "monitor_identity_absent",
                "launch_driver_identity_absent",
                "runc_client_identity_absent",
                "container_init_identity_absent",
            }
            or not isinstance(cgroups, dict)
            or set(cgroups) != expected_cgroups
            or any(not isinstance(path, str) or not path.startswith("/") for path in cgroups)
            or any(value is not True for value in cgroups.values())
            or not isinstance(paths, dict)
            or set(paths)
            != {
                "runc_state_entry_absent",
                "bundle_absent",
                "state_root_absent",
                "execution_root",
                "monitor_socket",
            }
            or any(
                paths.get(name) is not True
                for name in ("runc_state_entry_absent", "bundle_absent", "state_root_absent")
            )
            or not isinstance(paths.get("execution_root"), dict)
            or type(paths["execution_root"].get("device")) is not int
            or type(paths["execution_root"].get("inode")) is not int
            or paths.get("execution_root")
            != {
                "path": str(Path(row["bundle_path"]).parent),
                "device": row["execution_root_dev"],
                "inode": row["execution_root_ino"],
            }
        ):
            return False
        monitor_socket = paths["monitor_socket"]
        if (
            not isinstance(monitor_socket, dict)
            or set(monitor_socket)
            != {
                "path",
                "parent_device",
                "parent_inode",
                "socket_device",
                "socket_inode",
                "removed",
                "absent",
            }
            or not isinstance(monitor_socket.get("path"), str)
            or type(monitor_socket.get("parent_device")) is not int
            or monitor_socket["parent_device"] < 0
            or type(monitor_socket.get("parent_inode")) is not int
            or monitor_socket["parent_inode"] <= 0
            or type(monitor_socket.get("removed")) is not bool
            or monitor_socket.get("absent") is not True
        ):
            return False
        monitor_socket_path = Path(monitor_socket["path"])
        if (
            not monitor_socket_path.is_absolute()
            or str(monitor_socket_path) != os.path.normpath(str(monitor_socket_path))
            or monitor_socket_path.parent == Path("/")
            or monitor_socket_path.name != expected_monitor_socket_name
            or len(os.fsencode(monitor_socket_path)) >= 108
        ):
            return False
        socket_device = monitor_socket["socket_device"]
        socket_inode = monitor_socket["socket_inode"]
        if (socket_device is None) != (socket_inode is None):
            return False
        if socket_device is not None and (
            type(socket_device) is not int
            or socket_device < 0
            or type(socket_inode) is not int
            or socket_inode <= 0
        ):
            return False
        expected_units = {
            "monitor": (
                row["wrapper_unit"],
                row["wrapper_invocation_id"],
                row["wrapper_cgroup_path"],
            ),
            "launch_driver": (
                row["launch_driver_unit"],
                row["launch_driver_invocation_id"],
                row["launch_driver_cgroup_path"],
            ),
            "scope": (row["scope_unit"], row["scope_invocation_id"], row["cgroup_path"]),
            "attempt_slice": (
                row["attempt_slice_unit"],
                row["attempt_slice_invocation_id"],
                row["attempt_slice_cgroup_path"],
            ),
        }
        for name, snapshot in units.items():
            expected_id, expected_invocation, expected_cgroup = expected_units[name]
            if (
                not isinstance(snapshot, dict)
                or set(snapshot)
                != {
                    "id",
                    "load_state",
                    "active_state",
                    "invocation_id",
                    "control_group",
                    "main_pid",
                }
                or snapshot.get("active_state")
                not in (
                    {"inactive", "not-found", "active"}
                    if name == "attempt_slice"
                    else {"inactive", "not-found", "failed"}
                )
                or snapshot.get("load_state") not in {"loaded", "not-found"}
                or snapshot.get("main_pid") != "0"
                or snapshot.get("id") not in {"", expected_id}
                or snapshot.get("invocation_id") not in {"", expected_invocation}
                or snapshot.get("control_group") not in {"", expected_cgroup}
            ):
                return False
        expected_processes = {
            "monitor_identity_absent": (row["monitor_pid"], row["monitor_identity"]),
            "launch_driver_identity_absent": (
                row["launch_driver_pid"],
                row["launch_driver_identity"],
            ),
            "runc_client_identity_absent": (
                row["runc_client_pid"],
                row["runc_client_identity"],
            ),
            "container_init_identity_absent": (row["init_pid"], row["init_identity"]),
        }
        for name, expected in expected_processes.items():
            proof = processes[name]
            if (
                not isinstance(proof, dict)
                or set(proof) != {"pid", "identity", "absent"}
                or type(proof.get("pid")) is not int
                or not isinstance(proof.get("identity"), str)
                or (proof.get("pid"), proof.get("identity")) != expected
                or proof.get("absent") is not True
            ):
                return False
        return True
    except (TypeError, ValueError, KeyError, UnicodeError, json.JSONDecodeError):
        return False


def _linux_process_identity(pid: int) -> str | None:
    """Read one PID start tick; only a missing proc entry is positive absence."""

    try:
        raw = Path(f"/proc/{pid}/stat").read_bytes()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "process identity could not be read safely"
        ) from error
    closing = raw.rfind(b")")
    opening = raw.find(b" (")
    if opening <= 0 or closing <= opening + 1:
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "process stat record is malformed"
        )
    try:
        observed_pid = int(raw[:opening])
        fields = raw[closing + 1 :].split()
        start_ticks = int(fields[19])
    except (ValueError, IndexError) as error:
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "process stat identity is malformed"
        ) from error
    if observed_pid != pid or start_ticks <= 0:
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "process stat identity changed ambiguously"
        )
    return f"linux:{pid}:{start_ticks}"


def _process_identity_is_absent(pid: Any, identity: Any) -> bool:
    if type(pid) is not int or pid <= 0 or not isinstance(identity, str):
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "durable process identity is incomplete"
        )
    match = _PROCESS_IDENTITY.fullmatch(identity)
    if match is None or int(match.group(1)) != pid:
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "durable process identity is malformed"
        )
    return _linux_process_identity(pid) != identity


def _unit_snapshot(
    unit: str,
    *,
    invocation_id: str,
    control_group: str,
    main_pid: int | None,
    stop_if_active: bool,
    systemctl: Path,
    environment: dict[str, str],
) -> dict[str, str]:
    """Stop only the recorded activation, then require its process to be absent."""

    def read() -> dict[str, str]:
        try:
            return _read_cleanup_unit_properties(systemctl, environment, unit, _SYSTEMD_PROPERTIES)
        except Exception as error:
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "systemd unit identity is unavailable"
            ) from error

    def exact_identity(properties: dict[str, str]) -> bool:
        if properties.get("LoadState") == "not-found":
            return False
        return (
            properties.get("Id") == unit
            and properties.get("InvocationID") == invocation_id
            and properties.get("ControlGroup") == control_group
        )

    properties = read()
    if properties.get("LoadState") == "not-found":
        if (
            properties.get("Id", "") not in {"", unit}
            or any(properties.get(name, "") for name in ("InvocationID", "ControlGroup"))
            or properties.get("MainPID", "0") not in {"", "0"}
        ):
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "not-found unit retained live identity data"
            )
        return _normalized_unit_snapshot(properties, unit)

    if not exact_identity(properties):
        # A stopped service may lose its ControlGroup while systemd retains its
        # failed InvocationID. Accept that only for this exact failed activation;
        # a different activation or residual MainPID is never treated as absent.
        state = properties.get("ActiveState")
        stopped_identity_matches = state == "inactive" or (
            state == "failed" and properties.get("InvocationID") == invocation_id
        )
        if (
            properties.get("Id") != unit
            or properties.get("InvocationID") not in {"", invocation_id}
            or properties.get("ControlGroup") not in {"", control_group}
            or properties.get("MainPID") != "0"
            or not stopped_identity_matches
        ):
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "systemd unit changed identity"
            )
        return _normalized_unit_snapshot(properties, unit)

    if main_pid is not None and properties.get("MainPID") != str(main_pid):
        if (
            properties.get("ActiveState") not in {"inactive", "failed"}
            or properties.get("MainPID") != "0"
        ):
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown",
                "systemd MainPID differs from recorded process",
            )

    if properties.get("ActiveState") in {"inactive", "failed"}:
        if properties.get("MainPID") != "0":
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "inactive unit retains a main process"
            )
        return _normalized_unit_snapshot(properties, unit)
    if not stop_if_active:
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "recorded systemd unit remains active"
        )

    try:
        _run_trusted_runtime_command(
            [str(systemctl), "--user", "--no-block", "stop", "--", unit],
            environment=environment,
        )
    except Exception as error:
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "exact systemd unit could not be stopped"
        ) from error
    deadline = time.monotonic() + _VERIFY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        properties = read()
        if properties.get("LoadState") == "not-found":
            if properties.get("MainPID", "0") not in {"", "0"}:
                raise SupervisorError(
                    "sandbox_cleanup_verification_unknown", "stopped unit retained a main process"
                )
            return _normalized_unit_snapshot(properties, unit)
        if not exact_identity(properties):
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "systemd unit was replaced during stop"
            )
        if (
            properties.get("ActiveState") in {"inactive", "failed"}
            and properties.get("MainPID") == "0"
        ):
            return _normalized_unit_snapshot(properties, unit)
        if main_pid is not None and properties.get("MainPID") != str(main_pid):
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "systemd MainPID changed during stop"
            )
        time.sleep(0.05)
    raise SupervisorError(
        "sandbox_cleanup_verification_unknown", "exact systemd unit did not stop before deadline"
    )


def _normalized_unit_snapshot(
    properties: dict[str, str], unit: str, *, allow_active: bool = False
) -> dict[str, str]:
    load_state = properties.get("LoadState", "")
    active_state = properties.get("ActiveState", "")
    main_pid = properties.get("MainPID", "0") or "0"
    if load_state == "not-found":
        active_state = "not-found"
        main_pid = "0"
    allowed_states = (
        {"inactive", "not-found", "active"}
        if allow_active
        else {
            "inactive",
            "not-found",
            "failed",
        }
    )
    if active_state not in allowed_states or main_pid != "0":
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "systemd unit is not positively inactive"
        )
    return {
        "id": properties.get("Id", unit),
        "load_state": load_state,
        "active_state": active_state,
        "invocation_id": properties.get("InvocationID", ""),
        "control_group": properties.get("ControlGroup", ""),
        "main_pid": main_pid,
    }


def _cgroup_tree_is_unpopulated(
    control_group: str, *, cgroup_root: Path = Path("/sys/fs/cgroup")
) -> bool:
    """Require every node in the exact cgroup-v2 subtree to report empty."""

    cgroup = PurePosixPath(control_group)
    if (
        not cgroup.is_absolute()
        or cgroup.as_posix() != control_group
        or len(cgroup.parts) < 2
        or any(part in {".", ".."} for part in cgroup.parts)
    ):
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "cgroup path is not canonical"
        )
    if not cgroup_root.is_absolute() or str(cgroup_root) != os.path.normpath(str(cgroup_root)):
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "cgroup root is not canonical"
        )
    try:
        sandbox_attestation._require_cgroup2_mount(str(cgroup_root))
    except Exception as error:
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown",
            "cgroup-v2 mount root could not be verified",
        ) from error
    current = cgroup_root.joinpath(*cgroup.parts[1:])
    try:
        info = current.lstat()
    except FileNotFoundError:
        return True
    except OSError as error:
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "cgroup path could not be inspected"
        ) from error
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "cgroup path is not a real directory"
        )
    visited = 0

    def inspect(path: Path, depth: int) -> None:
        nonlocal visited
        visited += 1
        if visited > _MAX_CGROUPS or depth > _MAX_CGROUP_DEPTH:
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "cgroup subtree exceeds safe bounds"
            )
        try:
            event_lines = (path / "cgroup.events").read_text(encoding="ascii").splitlines()
            process_lines = (path / "cgroup.procs").read_text(encoding="ascii").splitlines()
        except (OSError, UnicodeError) as error:
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "cgroup population could not be read"
            ) from error
        events: dict[str, str] = {}
        for line in event_lines:
            key, separator, value = line.partition(" ")
            if not separator or key in events:
                raise SupervisorError(
                    "sandbox_cleanup_verification_unknown", "cgroup.events is malformed"
                )
            events[key] = value
        if events.get("populated") != "0" or process_lines:
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "cgroup still contains processes"
            )
        try:
            with os.scandir(path) as iterator:
                children = [entry.name for entry in iterator if entry.is_dir(follow_symlinks=False)]
        except OSError as error:
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "cgroup subtree could not be enumerated"
            ) from error
        for name in children:
            child = path / name
            try:
                child_info = child.lstat()
            except OSError as error:
                raise SupervisorError(
                    "sandbox_cleanup_verification_unknown", "cgroup child changed during inspection"
                ) from error
            if stat.S_ISLNK(child_info.st_mode) or not stat.S_ISDIR(child_info.st_mode):
                raise SupervisorError(
                    "sandbox_cleanup_verification_unknown", "cgroup child identity is unsafe"
                )
            inspect(child, depth + 1)

    inspect(current, 0)
    return True


def _assert_no_mounts_below(paths: tuple[Path, ...]) -> None:
    try:
        raw = Path("/proc/self/mountinfo").read_bytes()
    except OSError as error:
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "mount table could not be read safely"
        ) from error
    if len(raw) > _MAX_MOUNTINFO_BYTES:
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "mount table exceeds its safe bound"
        )
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError as error:
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "mount table is not ASCII"
        ) from error
    for line in lines:
        fields = line.split()
        if len(fields) < 6:
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "mount table record is malformed"
            )
        mount = re.sub(
            r"\\([0-7]{3})",
            lambda match: chr(int(match.group(1), 8)),
            fields[4],
        )
        mount_path = Path(mount)
        for target in paths:
            if mount_path == target or mount_path.is_relative_to(target):
                raise SupervisorError(
                    "sandbox_cleanup_verification_unknown", "private cleanup tree contains a mount"
                )


def _remove_exact_tree_at(
    parent_fd: int,
    name: str,
    *,
    expected_device: int,
    expected_inode: int,
) -> bool:
    """Remove one exact private tree without following symlinks or mount points."""

    try:
        entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError as error:
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "private cleanup path could not be inspected"
        ) from error
    if (
        not stat.S_ISDIR(entry.st_mode)
        or stat.S_ISLNK(entry.st_mode)
        or (entry.st_dev, entry.st_ino) != (expected_device, expected_inode)
        or entry.st_dev != os.fstat(parent_fd).st_dev
    ):
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "private cleanup tree identity changed"
        )
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        child_fd = os.open(name, flags, dir_fd=parent_fd)
    except OSError as error:
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown",
            "private cleanup tree could not be opened safely",
        ) from error
    try:
        opened = os.fstat(child_fd)
        if (opened.st_dev, opened.st_ino) != (expected_device, expected_inode):
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "private cleanup tree was replaced"
            )
        with os.scandir(child_fd) as iterator:
            names = [entry.name for entry in iterator]
        for child_name in names:
            try:
                info = os.stat(child_name, dir_fd=child_fd, follow_symlinks=False)
            except OSError as error:
                raise SupervisorError(
                    "sandbox_cleanup_verification_unknown", "private cleanup entry changed"
                ) from error
            if info.st_dev != expected_device:
                raise SupervisorError(
                    "sandbox_cleanup_verification_unknown", "private cleanup entry crosses a device"
                )
            if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                _remove_exact_tree_at(
                    child_fd,
                    child_name,
                    expected_device=info.st_dev,
                    expected_inode=info.st_ino,
                )
            else:
                try:
                    os.unlink(child_name, dir_fd=child_fd)
                except OSError as error:
                    raise SupervisorError(
                        "sandbox_cleanup_verification_unknown",
                        "private cleanup entry could not be unlinked",
                    ) from error
        os.fsync(child_fd)
    finally:
        os.close(child_fd)
    try:
        os.rmdir(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except OSError as error:
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "private cleanup tree could not be removed"
        ) from error
    return True


def _remove_bound_private_paths(row: Any) -> dict[str, bool]:
    execution_root = Path(row["bundle_path"]).parent
    if (
        Path(row["bundle_path"]) != execution_root / "bundle"
        or Path(row["state_path"]) != execution_root / "state"
    ):
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "private cleanup paths are noncanonical"
        )
    try:
        root_info = execution_root.lstat()
    except OSError as error:
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "execution root is unavailable"
        ) from error
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or stat.S_ISLNK(root_info.st_mode)
        or (root_info.st_dev, root_info.st_ino)
        != (row["execution_root_dev"], row["execution_root_ino"])
        or root_info.st_uid != os.geteuid()
        or stat.S_IMODE(root_info.st_mode) != 0o700
    ):
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "execution root identity is unsafe"
        )
    bundle_path = Path(row["bundle_path"])
    state_path = Path(row["state_path"])
    _assert_no_mounts_below((bundle_path, state_path))
    descriptor = os.open(
        execution_root,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        opened_root = os.fstat(descriptor)
        if (opened_root.st_dev, opened_root.st_ino) != (
            row["execution_root_dev"],
            row["execution_root_ino"],
        ):
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "execution root changed before removal"
            )
        for name, device_key, inode_key in (
            ("bundle", "bundle_root_dev", "bundle_root_ino"),
            ("state", "state_root_dev", "state_root_ino"),
        ):
            if row[device_key] is None or row[inode_key] is None:
                raise SupervisorError(
                    "sandbox_cleanup_verification_unknown",
                    "private cleanup inode binding is absent",
                )
            _remove_exact_tree_at(
                descriptor,
                name,
                expected_device=row[device_key],
                expected_inode=row[inode_key],
            )
        for name in ("bundle", "state"):
            try:
                os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError as error:
                raise SupervisorError(
                    "sandbox_cleanup_verification_unknown", "private path absence is unknown"
                ) from error
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "private path remains after removal"
            )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {"bundle_absent": True, "state_root_absent": True}


def _remove_monitor_socket(row: Any) -> dict[str, Any]:
    """Remove only the stopped execution's exact socket in the private runtime dir."""

    expected_identity = (row["attempt_id"], row["claim_token"], row["execution_id"])
    try:
        _, _, socket_path = sandbox_monitor_lifecycle.sandbox_monitor_control_paths(
            state_path=row["state_path"], expected_identity=expected_identity
        )
        expected_container_id = sandbox_monitor_receipt.sandbox_container_id(*expected_identity)
    except Exception as error:
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "monitor socket path could not be derived"
        ) from error
    expected_name = f"acpmon-{expected_container_id.removeprefix('acp-')}.sock"
    parent = socket_path.parent
    if (
        not socket_path.is_absolute()
        or str(socket_path) != os.path.normpath(str(socket_path))
        or socket_path.name != expected_name
        or len(os.fsencode(socket_path)) >= 108
        or parent == Path("/")
    ):
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "monitor socket path is noncanonical"
        )
    try:
        if parent.resolve(strict=True) != parent:
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "monitor runtime directory is aliased"
            )
        parent_info = parent.lstat()
    except OSError as error:
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "monitor runtime directory is unavailable"
        ) from error
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or stat.S_ISLNK(parent_info.st_mode)
        or parent_info.st_uid != os.geteuid()
        or stat.S_IMODE(parent_info.st_mode) != 0o700
    ):
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "monitor runtime directory is not private"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        parent_fd = os.open(parent, flags)
    except OSError as error:
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "monitor runtime directory changed"
        ) from error
    try:
        opened_parent = os.fstat(parent_fd)
        if (
            (opened_parent.st_dev, opened_parent.st_ino) != (parent_info.st_dev, parent_info.st_ino)
            or not stat.S_ISDIR(opened_parent.st_mode)
            or opened_parent.st_uid != os.geteuid()
            or stat.S_IMODE(opened_parent.st_mode) != 0o700
        ):
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "monitor runtime directory identity changed"
            )
        try:
            socket_info = os.stat(socket_path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            socket_info = None
        except OSError as error:
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "monitor socket identity is unavailable"
            ) from error
        removed = False
        if socket_info is not None:
            if (
                not stat.S_ISSOCK(socket_info.st_mode)
                or socket_info.st_uid != os.geteuid()
                or socket_info.st_dev != opened_parent.st_dev
            ):
                raise SupervisorError(
                    "sandbox_cleanup_verification_unknown", "monitor socket identity is unsafe"
                )
            try:
                current_socket = os.stat(socket_path.name, dir_fd=parent_fd, follow_symlinks=False)
            except OSError as error:
                raise SupervisorError(
                    "sandbox_cleanup_verification_unknown", "monitor socket changed before removal"
                ) from error
            if (
                (current_socket.st_dev, current_socket.st_ino)
                != (socket_info.st_dev, socket_info.st_ino)
                or not stat.S_ISSOCK(current_socket.st_mode)
                or current_socket.st_uid != os.geteuid()
            ):
                raise SupervisorError(
                    "sandbox_cleanup_verification_unknown", "monitor socket identity changed"
                )
            try:
                os.unlink(socket_path.name, dir_fd=parent_fd)
                removed = True
                os.fsync(parent_fd)
            except OSError as error:
                raise SupervisorError(
                    "sandbox_cleanup_verification_unknown", "monitor socket could not be removed"
                ) from error
        try:
            os.stat(socket_path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as error:
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "monitor socket absence is unknown"
            ) from error
        else:
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "monitor socket remains after removal"
            )
        try:
            parent_after = parent.lstat()
        except OSError as error:
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "monitor runtime directory disappeared"
            ) from error
        if (
            (parent_after.st_dev, parent_after.st_ino)
            != (opened_parent.st_dev, opened_parent.st_ino)
            or not stat.S_ISDIR(parent_after.st_mode)
            or stat.S_ISLNK(parent_after.st_mode)
            or parent_after.st_uid != os.geteuid()
            or stat.S_IMODE(parent_after.st_mode) != 0o700
        ):
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "monitor runtime directory changed"
            )
    finally:
        os.close(parent_fd)
    return {
        "path": str(socket_path),
        "parent_device": parent_info.st_dev,
        "parent_inode": parent_info.st_ino,
        "socket_device": socket_info.st_dev if socket_info is not None else None,
        "socket_inode": socket_info.st_ino if socket_info is not None else None,
        "removed": removed,
        "absent": True,
    }


def _row_cgroup_paths(row: Any) -> dict[str, str]:
    paths = {
        "monitor": row["wrapper_cgroup_path"],
        "launch_driver": row["launch_driver_cgroup_path"],
        "scope": row["cgroup_path"],
        "attempt_slice": row["attempt_slice_cgroup_path"],
    }
    if any(not isinstance(path, str) or not path for path in paths.values()):
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "durable cgroup paths are incomplete"
        )
    parsed = {name: PurePosixPath(path) for name, path in paths.items()}
    if (
        any(
            not path.is_absolute() or path.as_posix() != paths[name]
            for name, path in parsed.items()
        )
        or any(part in {".", ".."} for path in parsed.values() for part in path.parts)
        or parsed["scope"].parent != parsed["attempt_slice"]
        or parsed["launch_driver"].parent != parsed["attempt_slice"]
        or parsed["monitor"] == parsed["attempt_slice"]
        or parsed["attempt_slice"].name != row["attempt_slice_unit"]
        or parsed["scope"].name != row["scope_unit"]
        or parsed["launch_driver"].name != row["launch_driver_unit"]
        or parsed["monitor"].name != row["wrapper_unit"]
    ):
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "durable cgroup paths are inconsistent"
        )
    return paths


def _verify_and_stop_units(row: Any) -> dict[str, dict[str, str]]:
    if not sys.platform.startswith("linux"):
        raise SupervisorError(
            "sandbox_cleanup_verification_unavailable",
            "cleanup verification requires Linux/systemd",
        )
    systemctl = _trusted_systemctl_executable()
    environment = _trusted_systemd_command_environment()
    expected = (
        (
            "monitor",
            row["wrapper_unit"],
            row["wrapper_invocation_id"],
            row["wrapper_cgroup_path"],
            row["monitor_pid"],
        ),
        (
            "launch_driver",
            row["launch_driver_unit"],
            row["launch_driver_invocation_id"],
            row["launch_driver_cgroup_path"],
            row["launch_driver_pid"],
        ),
        (
            "scope",
            row["scope_unit"],
            row["scope_invocation_id"],
            row["cgroup_path"],
            None,
        ),
    )
    result = {
        name: _unit_snapshot(
            unit,
            invocation_id=invocation,
            control_group=control_group,
            main_pid=pid,
            stop_if_active=True,
            systemctl=systemctl,
            environment=environment,
        )
        for name, unit, invocation, control_group, pid in expected
    }
    slice_props = _read_cleanup_unit_properties(
        systemctl,
        environment,
        row["attempt_slice_unit"],
        _SYSTEMD_SLICE_PROPERTIES,
    )
    if slice_props.get("LoadState") == "not-found":
        if slice_props.get("MainPID", "0") not in {"", "0"}:
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "attempt slice retained a MainPID"
            )
        result["attempt_slice"] = _normalized_unit_snapshot(slice_props, row["attempt_slice_unit"])
    elif (
        slice_props.get("Id") != row["attempt_slice_unit"]
        or slice_props.get("ControlGroup") != row["attempt_slice_cgroup_path"]
        or slice_props.get("MainPID", "0") != "0"
        or slice_props.get("ActiveState") not in {"active", "inactive"}
    ):
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "attempt slice identity is inconsistent"
        )
    else:
        result["attempt_slice"] = _normalized_unit_snapshot(
            slice_props, row["attempt_slice_unit"], allow_active=True
        )
    return result


def _observe_processes(row: Any) -> dict[str, dict[str, Any]]:
    identities = {
        "monitor_identity_absent": (row["monitor_pid"], row["monitor_identity"]),
        "launch_driver_identity_absent": (row["launch_driver_pid"], row["launch_driver_identity"]),
        "runc_client_identity_absent": (row["runc_client_pid"], row["runc_client_identity"]),
        "container_init_identity_absent": (row["init_pid"], row["init_identity"]),
    }
    result: dict[str, dict[str, Any]] = {}
    for name, (pid, identity) in identities.items():
        if not _process_identity_is_absent(pid, identity):
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", f"{name} is still present"
            )
        result[name] = {"pid": pid, "identity": identity, "absent": True}
    return result


def _state_entry_is_absent(row: Any) -> bool:
    state_path = Path(row["state_path"])
    try:
        info = state_path.lstat()
    except FileNotFoundError:
        return True
    except OSError as error:
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "runc state-root status is unknown"
        ) from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or (info.st_dev, info.st_ino) != (row["state_root_dev"], row["state_root_ino"])
    ):
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "runc state-root inode changed"
        )
    entry = state_path / row["container_id"]
    try:
        entry.lstat()
    except FileNotFoundError:
        return True
    except OSError as error:
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "runc state-entry absence is unknown"
        ) from error
    raise SupervisorError(
        "sandbox_cleanup_verification_unknown", "runc state entry remains after delete"
    )


def _verifier_process_identity() -> str:
    from .oci_worker import _runc_client_process_identity

    identity = _runc_client_process_identity(os.getpid())
    if not identity:
        raise SupervisorError(
            "sandbox_cleanup_verification_unknown", "verifier process identity is unavailable"
        )
    return identity


def verify_sandbox_execution_cleanup(
    supervisor: Any,
    attempt_id: str,
    claim_token: int,
    *,
    credential: str | None = None,
) -> dict[str, Any]:
    """Finalize one exact cleanup_reported execution after independent checks."""

    attempt_id = supervisor._sandbox_validate_attempt_id(attempt_id)
    supervisor._sandbox_claim_token(claim_token)
    with supervisor.connect() as connection:
        row = connection.execute(
            "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
        ).fetchone()
    if row is None or row["claim_token"] != claim_token:
        raise SupervisorError("sandbox_execution_not_found", "cleanup execution is missing")
    if row["phase"] == "cleanup_verified":
        if journal._sandbox_cleanup_verification_is_self_consistent(row):
            return supervisor._sandbox_execution_view(row)
        raise SupervisorError(
            "sandbox_cleanup_verification_invalid", "stored verification receipt is inconsistent"
        )
    if row["phase"] != "cleanup_reported":
        raise SupervisorError(
            "sandbox_cleanup_verification_unavailable",
            "only a cleanup_reported execution can be independently verified",
        )
    if (
        type(row["runc_exit_code"]) is not int
        or row["runc_exit_evidence_source"] != "runc_client_kernel_waitpid"
        or not supervisor._sandbox_cleanup_receipt_v3_is_self_consistent(
            row, row["cleanup_receipt_json"]
        )
    ):
        raise SupervisorError(
            "sandbox_cleanup_verification_unavailable",
            "independent cleanup verification requires an observed kernel wait and exact runc v3 action receipt",
        )
    if not sys.platform.startswith("linux"):
        raise SupervisorError(
            "sandbox_cleanup_verification_unavailable", "cleanup verification requires Linux"
        )

    root_identity = journal._sandbox_execution_gate_identity(row)
    with _runc_execution_gate_fence(*root_identity):
        with supervisor.connect() as connection:
            locked_row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        if (
            locked_row is None
            or locked_row["claim_token"] != claim_token
            or locked_row["execution_id"] != row["execution_id"]
            or journal._sandbox_execution_gate_identity(locked_row) != root_identity
        ):
            raise SupervisorError(
                "sandbox_execution_gate_identity_mismatch", "execution changed under cleanup fence"
            )
        row = locked_row
        if row["phase"] == "cleanup_verified":
            if journal._sandbox_cleanup_verification_is_self_consistent(row):
                return supervisor._sandbox_execution_view(row)
            raise SupervisorError(
                "sandbox_cleanup_verification_invalid",
                "stored verification receipt is inconsistent",
            )
        if row[
            "phase"
        ] != "cleanup_reported" or not supervisor._sandbox_cleanup_receipt_v3_is_self_consistent(
            row, row["cleanup_receipt_json"]
        ):
            raise SupervisorError(
                "sandbox_cleanup_verification_unavailable", "cleanup report changed under fence"
            )
        cgroup_paths = _row_cgroup_paths(row)
        units = _verify_and_stop_units(row)
        processes = _observe_processes(row)
        if not _state_entry_is_absent(row):
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "runc state entry remains"
            )
        cgroups: dict[str, bool] = {}
        for control_group in dict.fromkeys(cgroup_paths.values()):
            cgroups[control_group] = _cgroup_tree_is_unpopulated(control_group)
        paths = _remove_bound_private_paths(row)
        paths["runc_state_entry_absent"] = True
        paths["execution_root"] = {
            "path": root_identity[0],
            "device": root_identity[1],
            "inode": root_identity[2],
        }
        if not _observe_processes(row) == processes:
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown", "a recorded process identity reappeared"
            )
        for control_group in cgroups:
            if not _cgroup_tree_is_unpopulated(control_group):
                raise SupervisorError(
                    "sandbox_cleanup_verification_unknown", "a cgroup became populated again"
                )
        # Re-read the exact recorded systemd activations after deleting the
        # private trees.  A unit restarted while the paths were being removed
        # gets a new InvocationID and fails closed; a unit unloaded by systemd
        # is recorded as not-found.  Do this immediately before committing the
        # receipt so cleanup cannot rely only on the pre-deletion snapshot.
        units = _verify_and_stop_units(row)
        # Retire the deterministic monitor socket only after all other cleanup
        # and final systemd checks, minimizing the interval in which a stale
        # socket could be recreated before the receipt is committed.
        paths["monitor_socket"] = _remove_monitor_socket(row)

        cleanup_digest = hashlib.sha256(row["cleanup_receipt_json"].encode("utf-8")).hexdigest()
        verifier_identity = _verifier_process_identity()
        encoded = canonical_json(
            {
                "version": 1,
                "attempt_id": attempt_id,
                "claim_token": claim_token,
                "execution_id": row["execution_id"],
                "cleanup_report_sha256": cleanup_digest,
                "verified_at": utc_now(),
                "verifier": {"pid": os.getpid(), "identity": verifier_identity},
                "observations": {
                    "units": units,
                    "processes": processes,
                    "cgroups": cgroups,
                    "paths": paths,
                },
            }
        )
        if len(encoded.encode("utf-8")) > 64 * 1024:
            raise SupervisorError(
                "sandbox_cleanup_verification_unknown",
                "verification receipt exceeds its durable bound",
            )
        receipt = journal._SandboxCleanupVerificationReceipt(
            attempt_id=attempt_id,
            claim_token=claim_token,
            execution_id=row["execution_id"],
            cleanup_report_sha256=cleanup_digest,
            encoded=encoded,
        )
        journal._register_sandbox_cleanup_verification_receipt(receipt)
        return supervisor._sandbox_execution_transition(
            attempt_id,
            claim_token,
            expected_phase="cleanup_reported",
            next_phase="cleanup_verified",
            updates={"cleanup_verification_json": encoded},
            event_type="sandbox.execution_cleanup_verified",
            event_payload={"verification_sha256": hashlib.sha256(encoded.encode()).hexdigest()},
            credential=credential,
            _cleanup_verification_receipt=receipt,
        )
