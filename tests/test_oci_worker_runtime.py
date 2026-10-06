"""Opt-in, no-model integration proof for the current OCI policy compiler.

This deliberately launches a disposable BusyBox fixture with the current OCI
helpers. It is not the registered worker executor: ``run_worker`` still fails
closed when OCI is configured. Run only on a disposable Linux host with rootless
runc and delegated cgroup v2, using an exact runc version as an environment
pin. The default test suite skips the live test.

Cleanup assumes pytest's private temporary parent is not concurrently modified
by another process running as the same host UID; the hostile worker itself has
no mount of the attempt bundle or its parent.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from shlex import quote as shell_quote
from typing import Any

import pytest

import agent_control_plane.supervisor.oci_worker as oci_worker
from agent_control_plane.supervisor.sandbox_attestation import (
    ProcessSnapshot,
    read_linux_process_snapshot,
    read_private_runc_pid_file,
)
from agent_control_plane.supervisor.sandbox_workspace import copy_snapshot

_LIVE_TEST_ENABLED = os.environ.get("ACP_RUN_OCI_INTEGRATION") == "1"
_LIVE_TEST_REASON = "set ACP_RUN_OCI_INTEGRATION=1 on a disposable supported Linux host"
_CONTAINER_MEMORY_BYTES = 128 * 1024 * 1024
_CONTAINER_PIDS_LIMIT = 16
_CONTAINER_CPU_QUOTA_US = 50_000
_CONTAINER_CPU_PERIOD_US = 100_000
_CONTAINER_FILESIZE_LIMIT_BYTES = 64 * 1024 * 1024
_LIVE_PROCESS_STATES = {b"R", b"S", b"D", b"T", b"t", b"W", b"K", b"P", b"I"}
_ATTEMPT_ROOT_CHILDREN = {
    "bundle",
    "host-fixtures",
    "runc-state",
    "runc-state-pinned",
    "workspace-snapshot",
    "workspace-pinned",
    "workspace-source",
}


def _release_unjournaled_gate_for_test(handle: oci_worker.RuncLaunchHandle) -> None:
    """Bypass the journal only for the opt-in runtime policy test."""

    assert oci_worker._runc_launch_handle_is_self_consistent(handle)
    with handle._gate_lock:
        descriptor = handle._gate_writer
        assert descriptor is not None
        handle._gate_writer = None
        try:
            assert os.write(descriptor, b"go\n") == 3
        finally:
            os.close(descriptor)


def _require_root_owned_file(path: Path, label: str) -> Path:
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o022
        or info.st_mode & (stat.S_ISUID | stat.S_ISGID)
    ):
        pytest.fail(f"{label} must be a root-owned, non-writable, non-set-id regular file")
    return resolved


def _copy_busybox_closure(busybox: Path, rootfs: Path) -> tuple[str, set[str]]:
    """Copy BusyBox plus its dynamic-loader closure, never host directories."""

    busybox = _require_root_owned_file(busybox, "BusyBox")
    ldd = shutil.which("ldd")
    if ldd is None:
        pytest.fail("ldd is required to build the minimal audited BusyBox closure")
    completed = subprocess.run(
        [ldd, str(busybox)],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
        env={"LC_ALL": "C", "LANG": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
    )
    if completed.returncode != 0 or "not found" in completed.stdout:
        pytest.fail("trusted BusyBox dependency closure could not be resolved with ldd")

    applets_result = subprocess.run(
        [str(busybox), "--list"],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
        env={"LC_ALL": "C", "LANG": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
    )
    if applets_result.returncode != 0:
        pytest.fail("BusyBox applet list could not be inspected")
    applets = set(applets_result.stdout.splitlines())
    required_applets = {"cat", "grep", "ln", "nc", "readlink", "sed", "touch", "tr"}
    missing_applets = required_applets - applets
    if missing_applets:
        pytest.fail(f"BusyBox is missing required test applets: {sorted(missing_applets)}")

    dependencies: set[str] = set()
    for line in completed.stdout.splitlines():
        if "=> not found" in line:
            pytest.fail("BusyBox has an unresolved dynamic dependency")
        for token in line.replace("=>", " ").split():
            if token.startswith("/") and Path(token).exists():
                dependencies.add(token)

    binary_destination = rootfs / "bin" / "busybox"
    binary_destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    shutil.copyfile(busybox, binary_destination)
    binary_destination.chmod(stat.S_IMODE(busybox.stat().st_mode) & 0o755)

    for dependency in sorted(dependencies):
        dependency_path = _require_root_owned_file(Path(dependency), "BusyBox dependency")
        destination = rootfs / dependency.lstrip("/")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        shutil.copyfile(dependency_path, destination)
        destination.chmod(stat.S_IMODE(dependency_path.stat().st_mode) & 0o755)

    for applet in sorted(required_applets):
        (rootfs / "bin" / applet).symlink_to("busybox")
    shell_binary = rootfs / "bin" / "sh"
    shutil.copyfile(binary_destination, shell_binary)
    shell_binary.chmod(stat.S_IMODE(binary_destination.stat().st_mode))
    version = subprocess.run(
        [str(busybox), "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
        env={"LC_ALL": "C", "LANG": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
    ).stdout.splitlines()
    if not version or not version[0].startswith("BusyBox "):
        pytest.fail("BusyBox version string was not recognized")
    return version[0], applets


def _start_time(stat_bytes: bytes) -> bytes:
    """Return Linux /proc stat field 22, robust to spaces in comm."""

    close = stat_bytes.rfind(b")")
    if close < 0:
        raise AssertionError("malformed /proc stat observation")
    fields_from_state = stat_bytes[close + 2 :].split()
    if len(fields_from_state) <= 19:
        raise AssertionError("truncated /proc stat observation")
    return fields_from_state[19]


def _snapshot_start_time(snapshot: Any, expected_pid: int, *, require_live: bool) -> bytes:
    """Validate one PID identity across the stat/cgroup/stat observation."""

    observations: list[tuple[int, bytes, bytes]] = []
    for stat_bytes in (snapshot.stat_before, snapshot.stat_after):
        open_paren = stat_bytes.find(b"(")
        close_paren = stat_bytes.rfind(b")")
        if open_paren <= 0 or close_paren <= open_paren:
            raise AssertionError("malformed /proc stat observation")
        try:
            pid = int(stat_bytes[:open_paren].strip())
        except ValueError as error:
            raise AssertionError("malformed PID in /proc stat observation") from error
        state_field = stat_bytes[close_paren + 2 : close_paren + 3]
        start_time = _start_time(stat_bytes)
        if pid != expected_pid:
            raise AssertionError("/proc stat PID changed during the cgroup observation")
        if require_live and state_field not in _LIVE_PROCESS_STATES:
            raise AssertionError("worker init was not live across the cgroup observation")
        observations.append((pid, state_field, start_time))
    if observations[0][2] != observations[1][2]:
        raise AssertionError("worker init PID/start-time changed during the cgroup observation")
    return observations[0][2]


def _snapshot_tty_number(snapshot: Any, expected_pid: int) -> int:
    """Return one stable Linux proc-stat tty_nr value for the exact PID."""

    observations: list[tuple[int, int]] = []
    for stat_bytes in (snapshot.stat_before, snapshot.stat_after):
        open_paren = stat_bytes.find(b"(")
        close_paren = stat_bytes.rfind(b")")
        if open_paren <= 0 or close_paren <= open_paren:
            raise AssertionError("malformed /proc stat observation")
        try:
            pid = int(stat_bytes[:open_paren].strip())
            fields_from_state = stat_bytes[close_paren + 2 :].split()
            if len(fields_from_state) <= 4:
                raise ValueError("missing tty_nr")
            tty_number = int(fields_from_state[4])
        except ValueError as error:
            raise AssertionError("malformed PID or tty_nr in /proc stat observation") from error
        if pid != expected_pid:
            raise AssertionError("/proc stat PID changed during the tty observation")
        observations.append((pid, tty_number))
    if observations[0] != observations[1]:
        raise AssertionError("worker init controlling-terminal identity changed during audit")
    return observations[0][1]


def _snapshot_cgroup_path(snapshot: Any) -> Path:
    """Resolve the cgroup bytes captured between the two PID stat reads."""

    try:
        rows = snapshot.cgroup.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise AssertionError("worker init cgroup observation is not ASCII") from error
    unified = [row.split(":", 2)[2] for row in rows if row.startswith("0::")]
    if len(unified) != 1:
        raise AssertionError("worker init snapshot lacks one unified cgroup-v2 path")
    root = Path("/sys/fs/cgroup").resolve(strict=True)
    cgroup = (root / unified[0].lstrip("/")).resolve(strict=True)
    if cgroup == root or root not in cgroup.parents:
        raise AssertionError("worker init snapshot cgroup escaped the host cgroup-v2 root")
    return cgroup


def _read_process_fd_table(pid: int) -> tuple[tuple[int, str], ...]:
    """Read one process's descriptor targets without running code in it."""

    fd_directory = Path(f"/proc/{pid}/fd")
    descriptors: list[tuple[int, str]] = []
    with os.scandir(fd_directory) as entries:
        for entry in entries:
            try:
                descriptor = int(entry.name)
            except ValueError as error:
                raise AssertionError("process FD table contained a non-numeric entry") from error
            descriptors.append((descriptor, os.readlink(entry.path)))
    return tuple(sorted(descriptors))


def _audit_worker_init_fd_table(
    pid: int,
    *,
    expected_start_time: bytes,
    expected_cgroup_path: Path,
) -> tuple[tuple[int, str], ...]:
    """Bracket two stable host-side FD reads with exact process identity checks."""

    expected_cgroup = expected_cgroup_path.resolve(strict=True)

    def verify_identity() -> None:
        snapshot = read_linux_process_snapshot(pid)
        observed_start = _snapshot_start_time(snapshot, pid, require_live=True)
        if observed_start != expected_start_time:
            raise AssertionError("worker init PID/start-time changed during descriptor audit")
        observed_cgroup = _snapshot_cgroup_path(snapshot).resolve(strict=True)
        if observed_cgroup != expected_cgroup:
            raise AssertionError("worker init cgroup changed during descriptor audit")

    verify_identity()
    first = _read_process_fd_table(pid)
    verify_identity()
    second = _read_process_fd_table(pid)
    verify_identity()
    if first != second:
        raise AssertionError("worker init descriptor table changed during host-side audit")
    unexpected = [
        (descriptor, target) for descriptor, target in first if descriptor not in {0, 1, 2}
    ]
    if unexpected:
        raise AssertionError(f"worker init inherited non-stdio descriptors: {unexpected!r}")
    if {descriptor for descriptor, _target in first} != {0, 1, 2}:
        raise AssertionError("worker init did not have exactly the three standard descriptors")
    socket_stdio = [
        (descriptor, target) for descriptor, target in first if target.startswith("socket:")
    ]
    if socket_stdio:
        raise AssertionError(f"worker init stdio inherited socket descriptors: {socket_stdio!r}")
    return first


_WORKER_CAPABILITY_FIELDS = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
_WORKER_SECURITY_STATUS_FIELDS = (*_WORKER_CAPABILITY_FIELDS, "NoNewPrivs")
_MAX_WORKER_STATUS_BYTES = 1024 * 1024
_MAX_WORKER_MOUNTINFO_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class _WorkerMountInfo:
    device_id: tuple[int, int]
    root: str
    filesystem: str
    source: str
    mount_options: frozenset[str]
    optional_fields: tuple[str, ...]
    super_options: frozenset[str]


def _tmpfs_size_bytes(super_options: frozenset[str]) -> int | None:
    """Return the one effective tmpfs size option, including kernel unit suffixes."""

    values = [option.partition("=")[2] for option in super_options if option.startswith("size=")]
    if len(values) != 1:
        return None
    raw_value = values[0]
    digits = raw_value
    while digits and digits[-1].isalpha():
        digits = digits[:-1]
    suffix = raw_value[len(digits) :].lower()
    if not digits or not digits.isascii() or not digits.isdigit() or len(suffix) > 1:
        return None
    multiplier = {
        "": 1,
        "k": 1024,
        "m": 1024**2,
        "g": 1024**3,
        "t": 1024**4,
        "p": 1024**5,
        "e": 1024**6,
    }.get(suffix)
    if multiplier is None:
        return None
    return int(digits) * multiplier


def _tmpfs_inode_limit(super_options: frozenset[str]) -> int | None:
    """Return the one effective tmpfs inode limit when it is canonical decimal."""

    values = [
        option.partition("=")[2] for option in super_options if option.startswith("nr_inodes=")
    ]
    if len(values) != 1:
        return None
    raw_value = values[0]
    if not raw_value.isascii() or not raw_value.isdigit():
        return None
    return int(raw_value)


def _parse_worker_security_status(raw: bytes) -> dict[str, int | bool]:
    """Parse effective Linux capability and no_new_privs fields strictly."""

    if len(raw) > _MAX_WORKER_STATUS_BYTES or not raw.endswith(b"\n"):
        raise AssertionError("worker status is malformed or exceeds its read limit")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise AssertionError("worker status is not ASCII") from error
    fields: dict[str, str] = {}
    for line in lines:
        name, separator, value = line.partition(":")
        if not separator:
            raise AssertionError("worker status contains a malformed line")
        if name in _WORKER_SECURITY_STATUS_FIELDS:
            if name in fields:
                raise AssertionError(f"worker status contains duplicate {name}")
            fields[name] = value.strip()
    missing = set(_WORKER_SECURITY_STATUS_FIELDS) - fields.keys()
    if missing:
        raise AssertionError(f"worker status omits security fields: {sorted(missing)}")
    parsed: dict[str, int | bool] = {}
    for name in _WORKER_CAPABILITY_FIELDS:
        value = fields[name]
        if not value or any(character not in "0123456789abcdefABCDEF" for character in value):
            raise AssertionError(f"worker status has an invalid {name} value")
        parsed[name] = int(value, 16)
    if fields["NoNewPrivs"] not in {"0", "1"}:
        raise AssertionError("worker status has an invalid NoNewPrivs value")
    parsed["NoNewPrivs"] = fields["NoNewPrivs"] == "1"
    if any(parsed[name] != 0 for name in _WORKER_CAPABILITY_FIELDS):
        raise AssertionError("worker init has non-empty effective or bounding capabilities")
    if parsed["NoNewPrivs"] is not True:
        raise AssertionError("worker init does not have NoNewPrivs enabled")
    return parsed


def _parse_worker_pid_namespace_status(raw: bytes, *, label: str) -> tuple[int, tuple[int, ...]]:
    """Parse Pid/NSpid from one bounded proc status record without ambiguity."""

    if len(raw) > _MAX_WORKER_STATUS_BYTES or not raw.endswith(b"\n"):
        raise AssertionError(f"{label} is malformed or exceeds its read limit")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise AssertionError(f"{label} is not ASCII") from error
    fields: dict[str, str] = {}
    for line in lines:
        name, separator, value = line.partition(":")
        if not separator:
            raise AssertionError(f"{label} contains a malformed line")
        if name in {"Pid", "NSpid"}:
            if name in fields:
                raise AssertionError(f"{label} contains duplicate {name}")
            fields[name] = value.strip()
    if set(fields) != {"Pid", "NSpid"}:
        raise AssertionError(f"{label} omits Pid or NSpid")
    pid_value = fields["Pid"]
    namespace_values = fields["NSpid"].split()
    values = [pid_value, *namespace_values]
    if any(not value.isascii() or not value.isdigit() or int(value) < 1 for value in values):
        raise AssertionError(f"{label} has an invalid Pid or NSpid")
    pid = int(pid_value)
    nspid = tuple(int(value) for value in namespace_values)
    if not nspid or nspid[0] != pid:
        raise AssertionError(f"{label} Pid does not match its procfs-relative NSpid")
    return pid, nspid


def _parse_worker_mountinfo(raw: bytes) -> dict[str, _WorkerMountInfo]:
    """Parse complete mountinfo records from target procfs with strict framing."""

    if len(raw) > _MAX_WORKER_MOUNTINFO_BYTES or not raw.endswith(b"\n"):
        raise AssertionError("worker mountinfo is malformed or exceeds its read limit")
    result: dict[str, _WorkerMountInfo] = {}

    def decode_canonical_absolute_path(raw_path: bytes, label: str) -> str:
        try:
            path = os.fsdecode(oci_worker._decode_mountinfo_path(raw_path))
        except oci_worker.SupervisorError as error:
            raise AssertionError(f"worker mountinfo has an invalid {label} path") from error
        if (
            not path.startswith("/")
            or path.startswith("//")
            or ".." in Path(path).parts
            or os.path.normpath(path) != path
        ):
            raise AssertionError(f"worker mountinfo has a non-canonical {label} path")
        return path

    def parse_options(raw_options: bytes, label: str) -> frozenset[str]:
        raw_values = raw_options.split(b",")
        if not raw_options or any(not value for value in raw_values):
            raise AssertionError(f"worker mountinfo has empty {label}")
        try:
            values = tuple(value.decode("ascii") for value in raw_values)
        except UnicodeDecodeError as error:
            raise AssertionError(f"worker mountinfo has non-ASCII {label}") from error
        if len(values) != len(set(values)):
            raise AssertionError(f"worker mountinfo has duplicate {label}")
        return frozenset(values)

    for line in raw.splitlines():
        before_separator, separator, after_separator = line.partition(b" - ")
        before = before_separator.split()
        after = after_separator.split()
        if not separator or len(before) < 6 or len(after) != 3:
            raise AssertionError("worker mountinfo contains a malformed entry")
        if not before[0].isdigit() or not before[1].isdigit():
            raise AssertionError("worker mountinfo contains an invalid mount identity")
        major, device_separator, minor = before[2].partition(b":")
        if not device_separator or not major.isdigit() or not minor.isdigit():
            raise AssertionError("worker mountinfo contains an invalid device identity")
        device_id = (int(major), int(minor))
        try:
            root = decode_canonical_absolute_path(before[3], "root")
            mountpoint = decode_canonical_absolute_path(before[4], "mountpoint")
            filesystem = after[0].decode("ascii")
            source = os.fsdecode(oci_worker._decode_mountinfo_path(after[1]))
            optional_fields = tuple(field.decode("ascii") for field in before[6:])
            options = parse_options(before[5], "mount options")
            super_options = parse_options(after[2], "super options")
        except (UnicodeDecodeError, oci_worker.SupervisorError) as error:
            raise AssertionError("worker mountinfo contains invalid path or option data") from error
        if not filesystem or not source or any(not field for field in optional_fields):
            raise AssertionError("worker mountinfo contains an empty filesystem or source field")
        normalized = os.path.normpath(mountpoint)
        if normalized != mountpoint or normalized in result:
            raise AssertionError(
                "worker mountinfo contains a non-canonical or duplicate mountpoint"
            )
        result[normalized] = _WorkerMountInfo(
            device_id=device_id,
            root=root,
            filesystem=filesystem,
            source=source,
            mount_options=options,
            optional_fields=optional_fields,
            super_options=super_options,
        )
    if not result:
        raise AssertionError("worker mountinfo contains no mounts")
    return result


def _validate_worker_mount_policy(
    mounts: dict[str, _WorkerMountInfo],
    *,
    expected_runc_version: str | None = None,
) -> list[dict[str, Any]]:
    expected_mounts = {
        "/": (None, "ro"),
        "/proc": ("proc", "ro"),
        "/dev": ("tmpfs", "rw"),
        "/workspace": (None, "rw"),
        "/tmp": ("tmpfs", "rw"),
        "/home/agent": ("tmpfs", "rw"),
    }
    expected_runc_135_mounts = {
        "/dev/full": ("/full", "devtmpfs", "udev", {"rw", "nosuid", "relatime"}),
        "/dev/null": ("/null", "devtmpfs", "udev", {"rw", "nosuid", "relatime"}),
        "/dev/random": ("/random", "devtmpfs", "udev", {"rw", "nosuid", "relatime"}),
        "/dev/tty": ("/tty", "devtmpfs", "udev", {"rw", "nosuid", "relatime"}),
        "/dev/urandom": ("/urandom", "devtmpfs", "udev", {"rw", "nosuid", "relatime"}),
        "/dev/zero": ("/zero", "devtmpfs", "udev", {"rw", "nosuid", "relatime"}),
        "/proc/kcore": ("/null", "devtmpfs", "udev", {"rw", "nosuid", "relatime"}),
        "/proc/keys": ("/null", "devtmpfs", "udev", {"rw", "nosuid", "relatime"}),
        "/proc/sys": ("/sys", "proc", "proc", {"ro", "nodev", "noexec", "nosuid", "relatime"}),
        "/proc/sysrq-trigger": (
            "/sysrq-trigger",
            "proc",
            "proc",
            {"ro", "nodev", "noexec", "nosuid", "relatime"},
        ),
    }
    actual_mountpoints = set(mounts)
    base_mountpoints = set(expected_mounts)
    extra_mountpoints = actual_mountpoints - base_mountpoints
    if extra_mountpoints and expected_runc_version != "1.3.5":
        unexpected_mountpoints = sorted(extra_mountpoints)
    else:
        unexpected_mountpoints = sorted(extra_mountpoints - expected_runc_135_mounts.keys())
    if unexpected_mountpoints:
        unexpected = {
            target: {
                "device_id": mounts[target].device_id,
                "root": mounts[target].root,
                "filesystem": mounts[target].filesystem,
                "source": mounts[target].source,
                "mount_options": sorted(mounts[target].mount_options),
                "optional_fields": list(mounts[target].optional_fields),
                "super_options": sorted(mounts[target].super_options),
            }
            for target in unexpected_mountpoints
        }
        raise AssertionError(f"worker mountinfo contains unexpected mountpoints: {unexpected}")
    if expected_runc_version == "1.3.5":
        propagating_mounts = {
            target: list(mount.optional_fields)
            for target, mount in mounts.items()
            if mount.optional_fields
        }
        if propagating_mounts:
            raise AssertionError(
                f"worker runc 1.3.5 mounts retain propagation fields: {propagating_mounts}"
            )
        missing_defaults = sorted(set(expected_runc_135_mounts) - extra_mountpoints)
        if missing_defaults:
            raise AssertionError(
                f"runc 1.3.5 mountinfo omits exact default mounts: {missing_defaults}"
            )
        device_mount_ids: set[tuple[int, int]] = set()
        for target, (root, filesystem, source, options) in expected_runc_135_mounts.items():
            observed = mounts[target]
            if (observed.root, observed.filesystem, observed.source) != (
                root,
                filesystem,
                source,
            ):
                raise AssertionError(
                    f"worker default mount {target} has unexpected root/filesystem/source: "
                    f"{observed.root!r}/{observed.filesystem!r}/{observed.source!r}"
                )
            if observed.mount_options != frozenset(options):
                raise AssertionError(
                    f"worker default mount {target} has unexpected mount options "
                    f"{sorted(observed.mount_options)}"
                )
            if observed.optional_fields:
                raise AssertionError(
                    f"worker default mount {target} has propagation fields "
                    f"{list(observed.optional_fields)}"
                )
            if filesystem == "devtmpfs":
                if "rw" not in observed.super_options or "ro" in observed.super_options:
                    raise AssertionError(
                        f"worker device mount {target} has unexpected super options "
                        f"{sorted(observed.super_options)}"
                    )
                device_mount_ids.add(observed.device_id)
            elif observed.super_options != frozenset({"ro"}):
                raise AssertionError(
                    f"worker proc mask {target} is not read-only at the superblock: "
                    f"{sorted(observed.super_options)}"
                )
        if len(device_mount_ids) != 1:
            raise AssertionError(
                f"worker runc device mounts do not share one devtmpfs identity: "
                f"{sorted(device_mount_ids)}"
            )
        proc_mount = mounts["/proc"]
        if any(
            mounts[target].device_id != proc_mount.device_id
            for target in ("/proc/sys", "/proc/sysrq-trigger")
        ):
            raise AssertionError(
                "worker read-only proc masks do not share the /proc device identity"
            )
    elif extra_mountpoints:
        raise AssertionError(
            "worker runtime version is required to inspect default mount identities"
        )
    observed_mounts: list[dict[str, Any]] = []
    for target, (expected_filesystem, access) in expected_mounts.items():
        observed = mounts.get(target)
        if observed is None:
            raise AssertionError(f"worker mountinfo omits configured mount {target}")
        filesystem = observed.filesystem
        options = observed.mount_options
        if expected_filesystem is not None and filesystem != expected_filesystem:
            raise AssertionError(f"worker mount {target} has unexpected filesystem {filesystem!r}")
        if access not in options or ({"ro", "rw"} - {access}) & options:
            raise AssertionError(
                f"worker mount {target} has unexpected access options {sorted(options)}"
            )
        if target == "/dev":
            if not {"nosuid", "noexec"}.issubset(options) or "nodev" in options:
                raise AssertionError(
                    "worker /dev tmpfs must be non-executable and permit its device binds"
                )
            observed_size = _tmpfs_size_bytes(observed.super_options)
            if observed_size != oci_worker._DEFAULT_DEV_TMPFS_BYTES:
                raise AssertionError(
                    "worker /dev tmpfs does not retain its exact byte limit: "
                    f"expected={oci_worker._DEFAULT_DEV_TMPFS_BYTES}, observed={observed_size!r}, "
                    f"observed_super_options={sorted(observed.super_options)!r}"
                )
            observed_inodes = _tmpfs_inode_limit(observed.super_options)
            if observed_inodes != oci_worker._DEFAULT_DEV_TMPFS_INODES:
                raise AssertionError(
                    "worker /dev tmpfs does not retain its exact inode limit: "
                    f"expected={oci_worker._DEFAULT_DEV_TMPFS_INODES}, "
                    f"observed={observed_inodes!r}, "
                    f"observed_super_options={sorted(observed.super_options)!r}"
                )
        elif target != "/" and not {"nosuid", "nodev"}.issubset(options):
            raise AssertionError(f"worker mount {target} is missing nosuid/nodev protection")
        if target == "/proc" and (observed.root != "/" or observed.source != "proc"):
            raise AssertionError("worker /proc mount is not a fresh procfs rooted at /")
        observed_mounts.append(
            {
                "target": target,
                "device_id": list(observed.device_id),
                "filesystem": filesystem,
                "source": observed.source,
                "root": observed.root,
                "options": sorted(options),
                "optional_fields": list(observed.optional_fields),
                "super_options": sorted(observed.super_options),
            }
        )
    if expected_runc_version == "1.3.5":
        for target in expected_runc_135_mounts:
            observed = mounts[target]
            observed_mounts.append(
                {
                    "target": target,
                    "device_id": list(observed.device_id),
                    "filesystem": observed.filesystem,
                    "source": observed.source,
                    "root": observed.root,
                    "options": sorted(observed.mount_options),
                    "optional_fields": list(observed.optional_fields),
                    "super_options": sorted(observed.super_options),
                }
            )
    return observed_mounts


_WORKER_RUNC_135_DEVICE_NODES = {
    "/dev/full": ("/dev/full", (1, 7)),
    "/dev/null": ("/dev/null", (1, 3)),
    "/dev/random": ("/dev/random", (1, 8)),
    "/dev/tty": ("/dev/tty", (5, 0)),
    "/dev/urandom": ("/dev/urandom", (1, 9)),
    "/dev/zero": ("/dev/zero", (1, 5)),
    "/proc/kcore": ("/dev/null", (1, 3)),
    "/proc/keys": ("/dev/null", (1, 3)),
}


def _worker_char_device_identity(
    info: os.stat_result,
    *,
    expected_device_number: tuple[int, int],
    label: str,
) -> tuple[int, int, int, int, int, int]:
    if not stat.S_ISCHR(info.st_mode):
        raise AssertionError(f"worker device path {label} is not a character device")
    device_number = (os.major(info.st_rdev), os.minor(info.st_rdev))
    if device_number != expected_device_number:
        raise AssertionError(
            f"worker device path {label} has device number {device_number}, "
            f"expected {expected_device_number}"
        )
    # Device-node group ownership is host-policy-dependent (for example,
    # /dev/tty is commonly root:tty). Require a root owner and expected access
    # mode; the host/guest identity comparison below binds the exact GID.
    if stat.S_IMODE(info.st_mode) != 0o666 or info.st_uid != 0:
        raise AssertionError(
            f"worker device path {label} has unexpected owner/mode "
            f"{info.st_uid}:{info.st_gid} {stat.S_IMODE(info.st_mode):04o}"
        )
    return (info.st_dev, info.st_ino, info.st_rdev, info.st_mode, info.st_uid, info.st_gid)


def _audit_worker_init_device_mount_identities(
    pid: int,
    mounts: dict[str, _WorkerMountInfo],
    *,
    stat_path: Callable[..., os.stat_result] | None = None,
) -> dict[str, dict[str, Any]]:
    """Prove default device binds retain the exact approved host character nodes."""

    if stat_path is None:
        stat_path = os.stat
    observed: dict[str, dict[str, Any]] = {}
    process_root = Path(f"/proc/{pid}/root")
    for target, (host_path, expected_device_number) in _WORKER_RUNC_135_DEVICE_NODES.items():
        try:
            host_info = stat_path(Path(host_path), follow_symlinks=False)
            guest_info = stat_path(process_root / target.lstrip("/"), follow_symlinks=False)
        except OSError as error:
            raise AssertionError(
                f"could not stat exact worker device identity for {target}"
            ) from error
        host_identity = _worker_char_device_identity(
            host_info,
            expected_device_number=expected_device_number,
            label=host_path,
        )
        guest_identity = _worker_char_device_identity(
            guest_info,
            expected_device_number=expected_device_number,
            label=f"/proc/{pid}/root{target}",
        )
        expected_mount_id = (os.major(host_info.st_dev), os.minor(host_info.st_dev))
        if expected_mount_id != mounts[target].device_id:
            raise AssertionError(
                f"worker device mount {target} filesystem identity "
                f"{mounts[target].device_id} does not match its host node {expected_mount_id}"
            )
        if host_identity != guest_identity:
            raise AssertionError(
                f"worker device mount {target} does not preserve exact host inode/owner/mode identity"
            )
        observed[target] = {
            "host_path": host_path,
            "device_number": list(expected_device_number),
            "st_dev": host_info.st_dev,
            "st_ino": host_info.st_ino,
            "st_mode": stat.S_IMODE(host_info.st_mode),
            "st_uid": host_info.st_uid,
            "st_gid": host_info.st_gid,
        }
    return observed


def _audit_worker_init_pid_namespace(
    pid: int,
    process_root: Path,
    host_status: bytes,
    *,
    read_bounded: Callable[[Path, int, str], bytes],
    stat_path: Callable[..., os.stat_result] | None = None,
) -> dict[str, Any]:
    """Prove the mounted /proc is bound to the exact worker-init PID namespace."""

    if stat_path is None:
        stat_path = os.stat
    host_pid, host_nspid = _parse_worker_pid_namespace_status(
        host_status,
        label="host worker-init status",
    )
    if host_pid != pid or len(host_nspid) < 2 or host_nspid[-1] != 1:
        raise AssertionError(
            "host worker-init status does not place the exact PID at PID 1 of a child namespace"
        )

    guest_proc_one = process_root / "root" / "proc" / "1"
    guest_status = _parse_worker_pid_namespace_status(
        read_bounded(
            guest_proc_one / "status",
            _MAX_WORKER_STATUS_BYTES,
            "worker /proc/1 status",
        ),
        label="worker /proc/1 status",
    )
    if guest_status != (1, (1,)):
        raise AssertionError(
            "worker /proc/1 has an unexpected procfs-relative PID view: "
            f"observed={guest_status!r}, expected={(1, (1,))!r}"
        )

    host_pid_namespace = stat_path(Path(f"/proc/{pid}/ns/pid"), follow_symlinks=True)
    proc_one_pid_namespace = stat_path(
        guest_proc_one / "ns" / "pid",
        follow_symlinks=True,
    )
    host_identity = (host_pid_namespace.st_dev, host_pid_namespace.st_ino)
    proc_identity = (proc_one_pid_namespace.st_dev, proc_one_pid_namespace.st_ino)
    if proc_identity != host_identity:
        raise AssertionError(
            "worker /proc/1 PID namespace identity differs from the exact host init: "
            f"observed={proc_identity!r}, expected={host_identity!r}"
        )
    return {
        "host_pid": host_pid,
        "host_nspid": list(host_nspid),
        "proc_one_nspid": list(guest_status[1]),
        "pid_namespace_device": host_pid_namespace.st_dev,
        "pid_namespace_inode": host_pid_namespace.st_ino,
    }


def _audit_worker_init_runtime_policy(
    pid: int,
    *,
    expected_start_time: bytes,
    expected_cgroup_path: Path,
    expected_runc_version: str,
) -> dict[str, Any]:
    """Read effective privilege and mount policy from the host before gate release."""

    expected_cgroup = expected_cgroup_path.resolve(strict=True)

    def verify_identity() -> None:
        snapshot = read_linux_process_snapshot(pid)
        if _snapshot_start_time(snapshot, pid, require_live=True) != expected_start_time:
            raise AssertionError("worker init PID/start-time changed during runtime policy audit")
        if _snapshot_cgroup_path(snapshot).resolve(strict=True) != expected_cgroup:
            raise AssertionError("worker init cgroup changed during runtime policy audit")
        if expected_runc_version == "1.3.5" and _snapshot_tty_number(snapshot, pid) != 0:
            raise AssertionError("worker init has a controlling terminal while /dev/tty is mounted")

    def read_bounded(path: Path, limit: int, label: str) -> bytes:
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise AssertionError(f"worker {label} exceeds its read limit")
        return raw

    process_root = Path(f"/proc/{pid}")
    verify_identity()
    raw_status = read_bounded(process_root / "status", _MAX_WORKER_STATUS_BYTES, "status")
    status = _parse_worker_security_status(raw_status)
    pid_namespace = _audit_worker_init_pid_namespace(
        pid,
        process_root,
        raw_status,
        read_bounded=read_bounded,
    )
    mounts = _parse_worker_mountinfo(
        read_bounded(process_root / "mountinfo", _MAX_WORKER_MOUNTINFO_BYTES, "mountinfo")
    )
    observed_mounts = _validate_worker_mount_policy(
        mounts,
        expected_runc_version=expected_runc_version,
    )
    device_identities = (
        _audit_worker_init_device_mount_identities(pid, mounts)
        if expected_runc_version == "1.3.5"
        else {}
    )
    verify_identity()
    return {
        "status": status,
        "pid_namespace": pid_namespace,
        "mounts": observed_mounts,
        "device_identities": device_identities,
        "mountpoints": sorted(mounts),
    }


def _runc_environment() -> dict[str, str]:
    return oci_worker._runc_client_environment()


def _safe_run_pinned_runc(
    pin: Any,
    descriptor: int,
    state_root: Path,
    args: list[str],
    *,
    timeout: float = 8,
) -> tuple[int, str]:
    return oci_worker._run_bounded_command(
        [str(pin.path), "--root", str(state_root), *args],
        cwd="/",
        env=_runc_environment(),
        timeout_seconds=timeout,
        max_output_bytes=64 * 1024,
        pass_fds=(descriptor,),
        exec_fd=descriptor,
    )


def _run_user_systemctl(args: list[str]) -> tuple[int, str]:
    systemctl = shutil.which("systemctl")
    if systemctl is None:
        raise AssertionError("systemctl is required to verify the rootless cgroup scope")
    return oci_worker._run_bounded_command(
        [systemctl, "--user", "--no-pager", *args],
        cwd="/",
        env=_runc_environment(),
        timeout_seconds=8,
        max_output_bytes=64 * 1024,
    )


def _systemd_control_group(unit_name: str) -> Path | None:
    code, output = _run_user_systemctl(["show", "--property=ControlGroup", "--value", unit_name])
    if code != 0:
        return None
    control_group = output.strip()
    if not control_group:
        return None
    if not control_group.startswith("/") or ".." in Path(control_group).parts:
        raise AssertionError("systemd returned an invalid worker cgroup path")
    root = Path("/sys/fs/cgroup").resolve(strict=True)
    cgroup = (root / control_group.lstrip("/")).resolve(strict=False)
    if cgroup == root or root not in cgroup.parents:
        raise AssertionError("systemd worker cgroup path escaped the host cgroup-v2 root")
    return cgroup


def _systemd_scope_is_active(unit_name: str) -> bool:
    code, output = _run_user_systemctl(["show", "--property=ActiveState", "--value", unit_name])
    return code == 0 and output.strip() == "active"


def _assert_worker_scope_absent(container_id: str) -> None:
    code, output = _run_user_systemctl(
        ["list-units", "--all", "--plain", "--no-legend", "--full", "--type=scope"]
    )
    if code != 0:
        raise AssertionError(f"could not verify rootless worker scopes: {output}")
    matches = [line for line in output.splitlines() if container_id in line]
    if matches:
        raise AssertionError(f"worker systemd scope remained after cleanup: {matches!r}")


def _wait_for_worker_scope_absent(container_id: str, timeout: float = 5) -> None:
    deadline = time.monotonic() + timeout
    while True:
        _assert_worker_scope_absent(container_id)
        if time.monotonic() >= deadline:
            return
        time.sleep(0.1)


def _attempt_cleanup(errors: list[str], label: str, action: Any) -> Any | None:
    """Record one teardown failure without skipping the remaining cleanup."""

    try:
        return action()
    except Exception as error:  # cleanup must proceed after any ordinary failure
        errors.append(f"{label}: {type(error).__name__}: {error}")
        return None


def _run_cleanup_action_if_client_state_known(client_state_known: bool, action: Any) -> Any | None:
    """Do not mutate runtime artifacts while a submitted client's state is unknown."""

    if not client_state_known:
        return None
    return action()


def _check_runc_client_after_submission(attempt_cleanup: dict[str, Any], process: Any) -> bool:
    """Record a returned launch handle before its first fallible process poll."""

    attempt_cleanup["launch_submitted"] = True
    return process.poll() is None


def _attempt_tree_removal_allowed(
    attempt_cleanup: dict[str, Any], *, client_state_known: bool
) -> bool:
    """Retain attempt evidence until every submitted runtime is verified gone."""

    return bool(
        attempt_cleanup["created"]
        and not attempt_cleanup["preserve"]
        and client_state_known
        and (not attempt_cleanup["launch_submitted"] or attempt_cleanup["runtime_verified"])
    )


def _cleanup_path_exists(errors: list[str], label: str, path: Path) -> bool | None:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        errors.append(f"{label}: {type(error).__name__}: {error}")
        return None
    return True


def _remove_checkout_write_probe(
    directory: Path,
    canary: Path,
    identity: tuple[int, int] | None,
    expected_uid: int,
) -> None:
    """Remove only the unique, private canary reserved by this test."""

    info = directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != expected_uid
        or stat.S_IMODE(info.st_mode) != 0o700
        or (identity is not None and (info.st_dev, info.st_ino) != identity)
    ):
        raise AssertionError("checkout write-probe directory identity changed")
    with os.scandir(directory) as entries:
        children = list(entries)
    if any(Path(entry.path) != canary for entry in children):
        raise AssertionError("checkout write-probe directory contains an unexpected entry")
    canary_info: os.stat_result | None = None
    if children:
        canary_info = canary.lstat()
        if not stat.S_ISREG(canary_info.st_mode) or canary_info.st_uid != expected_uid:
            raise AssertionError("checkout write canary is not a test-owned regular file")
        canary.unlink()
    directory.rmdir()


def _remove_private_attempt_tree(
    directory: Path,
    identity: tuple[int, int],
    expected_uid: int,
) -> None:
    """Remove this exact owned tree relative to a pinned private parent FD."""

    if not shutil.rmtree.avoids_symlink_attacks:
        raise AssertionError("platform lacks fd-safe recursive cleanup")
    parent = directory.parent.resolve(strict=True)
    if parent != directory.parent:
        raise AssertionError("private attempt-tree parent is not canonical")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    parent_fd = os.open(parent, directory_flags)
    try:
        parent_info = os.fstat(parent_fd)
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != expected_uid
            or stat.S_IMODE(parent_info.st_mode) != 0o700
        ):
            raise AssertionError("private attempt-tree parent is not owned and mode 0700")
        named_info = os.stat(directory.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(named_info.st_mode)
            or named_info.st_uid != expected_uid
            or stat.S_IMODE(named_info.st_mode) != 0o700
            or (named_info.st_dev, named_info.st_ino) != identity
        ):
            raise AssertionError("private attempt-tree identity changed")
        attempt_fd = os.open(directory.name, directory_flags, dir_fd=parent_fd)
        try:
            opened_info = os.fstat(attempt_fd)
            if not os.path.samestat(named_info, opened_info):
                raise AssertionError("private attempt tree changed during open")
            with os.scandir(attempt_fd) as entries:
                children = list(entries)
            if any(entry.name not in _ATTEMPT_ROOT_CHILDREN for entry in children):
                raise AssertionError("private attempt tree contains an unexpected entry")
            for entry in children:
                child_info = entry.stat(follow_symlinks=False)
                if (
                    not stat.S_ISDIR(child_info.st_mode)
                    or child_info.st_uid != expected_uid
                    or stat.S_IMODE(child_info.st_mode) != 0o700
                ):
                    raise AssertionError("private attempt-tree child is not an owned directory")
        finally:
            os.close(attempt_fd)

        shutil.rmtree(directory.name, dir_fd=parent_fd)
        try:
            os.stat(directory.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise AssertionError("private attempt tree remained after cleanup")
    finally:
        os.close(parent_fd)


def _cleanup_identity_gaps(
    *,
    launch_submitted: bool,
    init_pid: int | None,
    init_start: bytes | None,
    cgroup_path: Path | None,
    systemd_cgroup_path: Path | None,
) -> tuple[str, ...]:
    """Return every missing identity that prevents positive runtime cleanup proof."""

    if not launch_submitted:
        return ()
    gaps: list[str] = []
    if init_pid is None or init_start is None:
        gaps.append("launch was submitted without an exact init PID/start-time identity")
    if cgroup_path is None:
        gaps.append("launch was submitted without the init cgroup path")
    if systemd_cgroup_path is None:
        gaps.append("launch was submitted without the exact systemd scope cgroup path")
    return tuple(gaps)


def _runc_client_is_running(
    process: subprocess.Popen[bytes] | None,
    *,
    launch_client_reaped: bool | None,
) -> bool | None:
    """Keep absent handles unknown unless the launcher positively reaped its child."""

    if process is None:
        return False if launch_client_reaped is True else None
    return process.poll() is None


def _launch_client_state_known(
    *,
    launch_submitted: bool,
    client_running_after_cleanup: bool | None,
    launch_client_reaped: bool | None,
) -> bool:
    """Return whether cleanup may mutate runtime state after launch submission."""

    return (
        not launch_submitted
        or launch_client_reaped is True
        or client_running_after_cleanup is False
    )


def _synthetic_proc_stat(
    pid: int,
    state: bytes,
    start_time: int,
    *,
    tty_number: int = 0,
) -> bytes:
    fields = [
        state,
        b"0",
        b"0",
        b"0",
        str(tty_number).encode("ascii"),
        *([b"0"] * 14),
        str(start_time).encode("ascii"),
    ]
    return str(pid).encode("ascii") + b" (acp test worker) " + b" ".join(fields)


def test_snapshot_start_identity_checks_both_sides_of_cgroup_read() -> None:
    pid = 1234
    snapshot = ProcessSnapshot(
        stat_before=_synthetic_proc_stat(pid, b"S", 9876),
        cgroup=b"0::/user.slice/test.scope\n",
        stat_after=_synthetic_proc_stat(pid, b"R", 9876),
    )

    assert _snapshot_start_time(snapshot, pid, require_live=True) == b"9876"
    assert _snapshot_tty_number(snapshot, pid) == 0

    recycled = ProcessSnapshot(
        stat_before=snapshot.stat_before,
        cgroup=snapshot.cgroup,
        stat_after=_synthetic_proc_stat(pid, b"R", 9877),
    )
    with pytest.raises(AssertionError, match="start-time changed"):
        _snapshot_start_time(recycled, pid, require_live=True)

    tty_attached = ProcessSnapshot(
        stat_before=_synthetic_proc_stat(pid, b"S", 9876),
        cgroup=snapshot.cgroup,
        stat_after=_synthetic_proc_stat(pid, b"R", 9876, tty_number=123),
    )
    with pytest.raises(AssertionError, match="controlling-terminal identity changed"):
        _snapshot_tty_number(tty_attached, pid)

    exited = ProcessSnapshot(
        stat_before=_synthetic_proc_stat(pid, b"Z", 9876),
        cgroup=snapshot.cgroup,
        stat_after=_synthetic_proc_stat(pid, b"Z", 9876),
    )
    with pytest.raises(AssertionError, match="was not live"):
        _snapshot_start_time(exited, pid, require_live=True)


def test_worker_security_status_requires_empty_capabilities_and_no_new_privs() -> None:
    status = b"""Name:\tsh
CapInh:\t0000000000000000
CapPrm:\t0000000000000000
CapEff:\t0000000000000000
CapBnd:\t0000000000000000
CapAmb:\t0000000000000000
NoNewPrivs:\t1
"""
    observed = _parse_worker_security_status(status)
    assert observed == {
        "CapInh": 0,
        "CapPrm": 0,
        "CapEff": 0,
        "CapBnd": 0,
        "CapAmb": 0,
        "NoNewPrivs": True,
    }

    with pytest.raises(AssertionError, match="non-empty"):
        _parse_worker_security_status(status.replace(b"CapEff:\t0000000000000000", b"CapEff:\t1"))
    with pytest.raises(AssertionError, match="NoNewPrivs"):
        _parse_worker_security_status(status.replace(b"NoNewPrivs:\t1", b"NoNewPrivs:\t0"))
    with pytest.raises(AssertionError, match="duplicate CapEff"):
        _parse_worker_security_status(status + b"CapEff:\t0000000000000000\n")


def test_worker_mountinfo_parser_decodes_mountpoint_and_rejects_duplicates() -> None:
    raw = (
        b"1 0 0:1 / / ro,nosuid,nodev - rootfs rootfs ro\n"
        b"2 1 0:2 / /workspace rw,nosuid,nodev - ext4 /dev/attempt rw\n"
        b"3 1 0:3 / /home/agent\\040private rw,nosuid,nodev - tmpfs tmpfs rw,size=1024\n"
        b"4 1 0:4 /root\\040dir /mnt/agent\\040files rw,nosuid,nodev shared:4 - "
        b"ext4 /dev/worker\\040volume rw,relatime\n"
    )
    observed = _parse_worker_mountinfo(raw)
    assert observed["/"].device_id == (0, 1)
    assert observed["/"].filesystem == "rootfs"
    assert observed["/"].mount_options == frozenset({"ro", "nosuid", "nodev"})
    assert observed["/workspace"].filesystem == "ext4"
    assert observed["/workspace"].source == "/dev/attempt"
    assert observed["/home/agent private"].filesystem == "tmpfs"
    assert observed["/home/agent private"].super_options == frozenset({"rw", "size=1024"})
    assert observed["/mnt/agent files"].root == "/root dir"
    assert observed["/mnt/agent files"].source == "/dev/worker volume"
    assert observed["/mnt/agent files"].optional_fields == ("shared:4",)
    with pytest.raises(AssertionError, match="duplicate"):
        _parse_worker_mountinfo(raw + raw.splitlines()[1] + b"\n")
    with pytest.raises(AssertionError, match="malformed"):
        _parse_worker_mountinfo(b"not mountinfo\n")
    with pytest.raises(AssertionError, match="malformed"):
        _parse_worker_mountinfo(
            raw.replace(b" - rootfs rootfs ro\n", b" - rootfs rootfs ro extra\n", 1)
        )
    with pytest.raises(AssertionError, match="device identity"):
        _parse_worker_mountinfo(raw.replace(b"0:1", b"not-a-device", 1))
    with pytest.raises(AssertionError, match="non-canonical root"):
        _parse_worker_mountinfo(raw.replace(b"0:1 / / ", b"0:1 /../outside / ", 1))
    with pytest.raises(AssertionError, match="non-canonical root"):
        _parse_worker_mountinfo(raw.replace(b"0:1 / / ", b"0:1 // / ", 1))
    with pytest.raises(AssertionError, match="non-canonical mountpoint"):
        _parse_worker_mountinfo(raw.replace(b"0:1 / / ", b"0:1 / // ", 1))
    with pytest.raises(AssertionError, match="duplicate mount options"):
        _parse_worker_mountinfo(raw.replace(b"ro,nosuid,nodev", b"ro,ro,nosuid,nodev", 1))


def test_worker_mount_policy_requires_isolated_expected_mounts() -> None:
    def mount(
        filesystem: str,
        options: set[str],
        *,
        root: str = "/",
        source: str | None = None,
        device_id: tuple[int, int] = (0, 1),
        super_options: set[str] | None = None,
        optional_fields: tuple[str, ...] = (),
    ) -> _WorkerMountInfo:
        return _WorkerMountInfo(
            device_id=device_id,
            root=root,
            filesystem=filesystem,
            source=filesystem if source is None else source,
            mount_options=frozenset(options),
            optional_fields=optional_fields,
            super_options=frozenset(options if super_options is None else super_options),
        )

    mounts = {
        "/": mount("rootfs", {"ro"}),
        "/proc": mount("proc", {"ro", "nosuid", "nodev", "noexec"}),
        "/dev": mount(
            "tmpfs",
            {"rw", "nosuid", "noexec"},
            source="tmpfs",
            super_options={"rw", "size=1024k", "nr_inodes=64"},
        ),
        "/workspace": mount("ext4", {"rw", "nosuid", "nodev"}),
        "/tmp": mount("tmpfs", {"rw", "nosuid", "nodev"}),
        "/home/agent": mount("tmpfs", {"rw", "nosuid", "nodev"}),
    }
    observed = _validate_worker_mount_policy(mounts)
    assert {mount["target"] for mount in observed} == set(mounts)

    with pytest.raises(AssertionError, match="exact byte limit"):
        _validate_worker_mount_policy(
            {
                **mounts,
                "/dev": mount(
                    "tmpfs",
                    {"rw", "nosuid", "noexec"},
                    source="tmpfs",
                    super_options={"rw", "size=1023k"},
                ),
            }
        )

    with pytest.raises(AssertionError, match="exact inode limit"):
        _validate_worker_mount_policy(
            {
                **mounts,
                "/dev": mount(
                    "tmpfs",
                    {"rw", "nosuid", "noexec"},
                    source="tmpfs",
                    super_options={"rw", "size=1024k", "nr_inodes=65"},
                ),
            }
        )

    with pytest.raises(AssertionError, match="unexpected access"):
        _validate_worker_mount_policy({**mounts, "/": mount("rootfs", {"rw"})})
    with pytest.raises(AssertionError, match="omits configured mount /home/agent"):
        _validate_worker_mount_policy(
            {key: value for key, value in mounts.items() if key != "/home/agent"}
        )
    with pytest.raises(AssertionError, match="unexpected mountpoints"):
        _validate_worker_mount_policy({**mounts, "/etc/credentials": mount("bind", {"ro"})})
    with pytest.raises(AssertionError, match="unexpected mountpoints"):
        _validate_worker_mount_policy({**mounts, "/var/agent-data": mount("tmpfs", {"rw"})})

    runc_135_mounts = dict(mounts)
    dev_id = (0, 55)
    proc_id = (0, 56)
    for target, root in (
        ("/dev/full", "/full"),
        ("/dev/null", "/null"),
        ("/dev/random", "/random"),
        ("/dev/tty", "/tty"),
        ("/dev/urandom", "/urandom"),
        ("/dev/zero", "/zero"),
        ("/proc/kcore", "/null"),
        ("/proc/keys", "/null"),
    ):
        runc_135_mounts[target] = mount(
            "devtmpfs",
            {"rw", "nosuid", "relatime"},
            root=root,
            source="udev",
            device_id=dev_id,
            super_options={"rw", "size=1024"},
        )
    for target, root in (
        ("/proc/sys", "/sys"),
        ("/proc/sysrq-trigger", "/sysrq-trigger"),
    ):
        runc_135_mounts[target] = mount(
            "proc",
            {"ro", "nodev", "noexec", "nosuid", "relatime"},
            root=root,
            source="proc",
            device_id=proc_id,
            super_options={"ro"},
        )
    runc_135_mounts["/proc"] = mount(
        "proc",
        {"ro", "nosuid", "nodev", "noexec"},
        device_id=proc_id,
    )
    accepted_defaults = _validate_worker_mount_policy(
        runc_135_mounts,
        expected_runc_version="1.3.5",
    )
    assert {mount["target"] for mount in accepted_defaults} == set(runc_135_mounts)
    with pytest.raises(AssertionError, match="unexpected mountpoints"):
        _validate_worker_mount_policy(runc_135_mounts)
    with pytest.raises(AssertionError, match="unexpected mountpoints"):
        _validate_worker_mount_policy(runc_135_mounts, expected_runc_version="1.4.0")
    with pytest.raises(AssertionError, match="root/filesystem/source"):
        _validate_worker_mount_policy(
            {
                **runc_135_mounts,
                "/dev/null": mount(
                    "devtmpfs",
                    {"rw"},
                    root="/zero",
                    source="udev",
                    device_id=dev_id,
                    super_options={"rw"},
                ),
            },
            expected_runc_version="1.3.5",
        )
    with pytest.raises(AssertionError, match="propagation fields"):
        _validate_worker_mount_policy(
            {
                **runc_135_mounts,
                "/dev/null": mount(
                    "devtmpfs",
                    {"rw", "nosuid", "relatime"},
                    root="/null",
                    source="udev",
                    device_id=dev_id,
                    super_options={"rw"},
                    optional_fields=("master:10",),
                ),
            },
            expected_runc_version="1.3.5",
        )
    with pytest.raises(AssertionError, match="fresh procfs rooted at /"):
        _validate_worker_mount_policy(
            {
                **mounts,
                "/proc": mount("proc", {"ro", "nosuid", "nodev", "noexec"}, root="/host"),
            }
        )


@pytest.mark.parametrize(
    ("option", "expected_bytes"),
    [
        ("size=1048576", 1048576),
        ("size=1024k", 1048576),
        ("size=1m", 1048576),
        ("size=1K", 1024),
        ("size=2g", 2 * 1024**3),
    ],
)
def test_tmpfs_size_parser_converts_kernel_unit_suffixes(option: str, expected_bytes: int) -> None:
    assert _tmpfs_size_bytes(frozenset({"rw", option})) == expected_bytes


@pytest.mark.parametrize(
    "options",
    [
        frozenset({"rw"}),
        frozenset({"rw", "size=1m", "size=1024k"}),
        frozenset({"rw", "size=1MB"}),
        frozenset({"rw", "size=-1"}),
    ],
)
def test_tmpfs_size_parser_rejects_missing_ambiguous_or_malformed_limits(
    options: frozenset[str],
) -> None:
    assert _tmpfs_size_bytes(options) is None


@pytest.mark.parametrize("raw_value", ["0", "64", "999"])
def test_tmpfs_inode_parser_accepts_one_decimal_limit(raw_value: str) -> None:
    assert _tmpfs_inode_limit(frozenset({"rw", f"nr_inodes={raw_value}"})) == int(raw_value)


@pytest.mark.parametrize(
    "options",
    [
        frozenset({"rw"}),
        frozenset({"rw", "nr_inodes=64", "nr_inodes=65"}),
        frozenset({"rw", "nr_inodes=64k"}),
        frozenset({"rw", "nr_inodes=-1"}),
    ],
)
def test_tmpfs_inode_parser_rejects_missing_ambiguous_or_malformed_limits(
    options: frozenset[str],
) -> None:
    assert _tmpfs_inode_limit(options) is None


def test_worker_default_device_mounts_require_exact_host_inode_identity() -> None:
    from types import SimpleNamespace

    pid = 1234
    devtmpfs_id = os.makedev(0, 57)
    stats: dict[Path, Any] = {}
    mounts: dict[str, _WorkerMountInfo] = {}
    host_stats: dict[str, Any] = {}
    for index, (target, (host_path, device_number)) in enumerate(
        _WORKER_RUNC_135_DEVICE_NODES.items(), start=1
    ):
        host_stat = host_stats.get(host_path)
        if host_stat is None:
            host_stat = SimpleNamespace(
                st_mode=stat.S_IFCHR | 0o666,
                st_rdev=os.makedev(*device_number),
                st_dev=devtmpfs_id,
                st_ino=100 + index,
                st_uid=0,
                st_gid=5 if host_path == "/dev/tty" else 0,
            )
            host_stats[host_path] = host_stat
            stats[Path(host_path)] = host_stat
        guest_path = Path(f"/proc/{pid}/root") / target.lstrip("/")
        stats[guest_path] = host_stat
        mounts[target] = _WorkerMountInfo(
            device_id=(0, 57),
            root="/null" if target.startswith("/proc/") else target.removeprefix("/dev"),
            filesystem="devtmpfs",
            source="udev",
            mount_options=frozenset({"rw", "nosuid", "relatime"}),
            optional_fields=(),
            super_options=frozenset({"rw"}),
        )

    def stat_path(path: Path, *, follow_symlinks: bool) -> os.stat_result:
        assert follow_symlinks is False
        return stats[path]

    observed = _audit_worker_init_device_mount_identities(pid, mounts, stat_path=stat_path)
    assert set(observed) == set(_WORKER_RUNC_135_DEVICE_NODES)

    null_guest = Path(f"/proc/{pid}/root/dev/null")
    stats[null_guest] = SimpleNamespace(
        **{
            **vars(stats[null_guest]),
            "st_ino": stats[null_guest].st_ino + 1,
        }
    )
    with pytest.raises(AssertionError, match="exact host inode/owner/mode identity"):
        _audit_worker_init_device_mount_identities(pid, mounts, stat_path=stat_path)

    stats[null_guest] = host_stats["/dev/null"]
    tty_guest = Path(f"/proc/{pid}/root/dev/tty")
    stats[tty_guest] = SimpleNamespace(
        **{
            **vars(stats[tty_guest]),
            "st_gid": stats[tty_guest].st_gid + 1,
        }
    )
    with pytest.raises(AssertionError, match="exact host inode/owner/mode identity"):
        _audit_worker_init_device_mount_identities(pid, mounts, stat_path=stat_path)

    stats[tty_guest] = host_stats["/dev/tty"]
    null_mount = mounts["/dev/null"]
    mounts["/dev/null"] = _WorkerMountInfo(
        device_id=(0, 58),
        root=null_mount.root,
        filesystem=null_mount.filesystem,
        source=null_mount.source,
        mount_options=null_mount.mount_options,
        optional_fields=null_mount.optional_fields,
        super_options=null_mount.super_options,
    )
    with pytest.raises(AssertionError, match="filesystem identity"):
        _audit_worker_init_device_mount_identities(pid, mounts, stat_path=stat_path)


def test_worker_char_device_identity_rejects_unapproved_node_metadata() -> None:
    from types import SimpleNamespace

    tty = SimpleNamespace(
        st_mode=stat.S_IFCHR | 0o666,
        st_rdev=os.makedev(5, 0),
        st_dev=os.makedev(0, 57),
        st_ino=12,
        st_uid=0,
        st_gid=5,
    )
    assert _worker_char_device_identity(
        tty,
        expected_device_number=(5, 0),
        label="/dev/tty",
    ) == (tty.st_dev, tty.st_ino, tty.st_rdev, tty.st_mode, 0, 5)

    with pytest.raises(AssertionError, match="not a character device"):
        _worker_char_device_identity(
            SimpleNamespace(**{**vars(tty), "st_mode": stat.S_IFREG | 0o666}),
            expected_device_number=(5, 0),
            label="/dev/tty",
        )
    with pytest.raises(AssertionError, match="device number"):
        _worker_char_device_identity(
            SimpleNamespace(**{**vars(tty), "st_rdev": os.makedev(5, 1)}),
            expected_device_number=(5, 0),
            label="/dev/tty",
        )
    with pytest.raises(AssertionError, match="owner/mode"):
        _worker_char_device_identity(
            SimpleNamespace(**{**vars(tty), "st_uid": 1000}),
            expected_device_number=(5, 0),
            label="/dev/tty",
        )
    with pytest.raises(AssertionError, match="owner/mode"):
        _worker_char_device_identity(
            SimpleNamespace(**{**vars(tty), "st_mode": stat.S_IFCHR | 0o640}),
            expected_device_number=(5, 0),
            label="/dev/tty",
        )


def test_worker_proc_mount_must_match_exact_init_pid_namespace() -> None:
    from types import SimpleNamespace

    pid = 1234
    process_root = Path(f"/proc/{pid}")
    host_status = b"Name:\tacp-worker\nPid:\t1234\nNSpid:\t1234 1\n"
    guest_status = b"Name:\tacp-worker\nPid:\t1\nNSpid:\t1\n"
    guest_proc_one = process_root / "root" / "proc" / "1"
    namespace_path = Path(f"/proc/{pid}/ns/pid")
    guest_namespace_path = guest_proc_one / "ns" / "pid"
    namespace_stat = SimpleNamespace(st_dev=9, st_ino=77)
    namespace_stats = {
        namespace_path: namespace_stat,
        guest_namespace_path: namespace_stat,
    }

    def read_bounded(path: Path, limit: int, _label: str) -> bytes:
        assert limit == _MAX_WORKER_STATUS_BYTES
        assert path == guest_proc_one / "status"
        return guest_status

    def stat_path(path: Path, *, follow_symlinks: bool) -> os.stat_result:
        assert follow_symlinks is True
        return namespace_stats[path]

    observed = _audit_worker_init_pid_namespace(
        pid,
        process_root,
        host_status,
        read_bounded=read_bounded,
        stat_path=stat_path,
    )
    assert observed["host_pid"] == pid
    assert observed["host_nspid"] == [pid, 1]
    assert observed["proc_one_nspid"] == [1]

    host_proc_status = b"Name:\tinit\nPid:\t1\nNSpid:\t1\n"
    namespace_stats[guest_namespace_path] = SimpleNamespace(st_dev=9, st_ino=78)
    with pytest.raises(AssertionError, match="PID namespace identity differs"):
        _audit_worker_init_pid_namespace(
            pid,
            process_root,
            host_status,
            read_bounded=lambda _path, _limit, _label: host_proc_status,
            stat_path=stat_path,
        )

    nested_proc_status = b"Name:\tworker-child\nPid:\t2\nNSpid:\t2\n"
    with pytest.raises(AssertionError, match="unexpected procfs-relative PID view"):
        _audit_worker_init_pid_namespace(
            pid,
            process_root,
            host_status,
            read_bounded=lambda _path, _limit, _label: nested_proc_status,
            stat_path=stat_path,
        )


def test_worker_init_fd_audit_brackets_stable_non_socket_stdio(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid = 1234
    cgroup = tmp_path / "worker.scope"
    cgroup.mkdir()
    snapshot = ProcessSnapshot(
        stat_before=_synthetic_proc_stat(pid, b"S", 9876),
        cgroup=b"0::/user.slice/test.scope\n",
        stat_after=_synthetic_proc_stat(pid, b"S", 9876),
    )
    monkeypatch.setattr(sys.modules[__name__], "read_linux_process_snapshot", lambda _pid: snapshot)
    monkeypatch.setattr(sys.modules[__name__], "_snapshot_cgroup_path", lambda _snapshot: cgroup)
    monkeypatch.setattr(
        sys.modules[__name__],
        "_read_process_fd_table",
        lambda _pid: ((0, "/dev/null"), (1, "/dev/null"), (2, "/dev/null")),
    )

    assert _audit_worker_init_fd_table(
        pid,
        expected_start_time=b"9876",
        expected_cgroup_path=cgroup,
    ) == ((0, "/dev/null"), (1, "/dev/null"), (2, "/dev/null"))


@pytest.mark.parametrize(
    ("fd_table", "message"),
    [
        (((0, "/dev/null"), (1, "/dev/null"), (2, "/dev/null"), (3, "pipe:[9]")), "non-stdio"),
        (((0, "/dev/null"), (1, "socket:[9]"), (2, "/dev/null")), "socket descriptors"),
    ],
)
def test_worker_init_fd_audit_rejects_extra_or_socket_descriptors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fd_table: tuple[tuple[int, str], ...],
    message: str,
) -> None:
    pid = 1234
    cgroup = tmp_path / "worker.scope"
    cgroup.mkdir()
    snapshot = ProcessSnapshot(
        stat_before=_synthetic_proc_stat(pid, b"S", 9876),
        cgroup=b"0::/user.slice/test.scope\n",
        stat_after=_synthetic_proc_stat(pid, b"S", 9876),
    )
    monkeypatch.setattr(sys.modules[__name__], "read_linux_process_snapshot", lambda _pid: snapshot)
    monkeypatch.setattr(sys.modules[__name__], "_snapshot_cgroup_path", lambda _snapshot: cgroup)
    monkeypatch.setattr(sys.modules[__name__], "_read_process_fd_table", lambda _pid: fd_table)

    with pytest.raises(AssertionError, match=message):
        _audit_worker_init_fd_table(
            pid,
            expected_start_time=b"9876",
            expected_cgroup_path=cgroup,
        )


def test_worker_init_fd_audit_rejects_unstable_descriptor_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid = 1234
    cgroup = tmp_path / "worker.scope"
    cgroup.mkdir()
    snapshot = ProcessSnapshot(
        stat_before=_synthetic_proc_stat(pid, b"S", 9876),
        cgroup=b"0::/user.slice/test.scope\n",
        stat_after=_synthetic_proc_stat(pid, b"S", 9876),
    )
    fd_tables = iter(
        (
            ((0, "/dev/null"), (1, "/dev/null"), (2, "/dev/null")),
            ((0, "/dev/null"), (1, "/dev/null"), (2, "/dev/null"), (3, "pipe:[9]")),
        )
    )
    monkeypatch.setattr(sys.modules[__name__], "read_linux_process_snapshot", lambda _pid: snapshot)
    monkeypatch.setattr(sys.modules[__name__], "_snapshot_cgroup_path", lambda _snapshot: cgroup)
    monkeypatch.setattr(
        sys.modules[__name__], "_read_process_fd_table", lambda _pid: next(fd_tables)
    )

    with pytest.raises(AssertionError, match="changed during host-side audit"):
        _audit_worker_init_fd_table(
            pid,
            expected_start_time=b"9876",
            expected_cgroup_path=cgroup,
        )


def test_cleanup_path_probe_treats_only_not_found_as_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / "missing"
    errors: list[str] = []
    assert _cleanup_path_exists(errors, "inspect missing", missing) is False
    assert errors == []

    present = tmp_path / "present"
    present.write_text("sentinel", encoding="ascii")
    assert _cleanup_path_exists(errors, "inspect present", present) is True

    def denied(_path: Path) -> os.stat_result:
        raise PermissionError("access denied")

    monkeypatch.setattr(Path, "lstat", denied)
    assert _cleanup_path_exists(errors, "inspect denied", present) is None
    assert errors == ["inspect denied: PermissionError: access denied"]


def test_checkout_write_probe_cleanup_removes_only_its_canary(tmp_path: Path) -> None:
    directory = tmp_path / "checkout-write-probe"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    canary = directory / "write-canary"
    canary.write_text("test-owned canary", encoding="ascii")
    info = directory.lstat()

    _remove_checkout_write_probe(directory, canary, (info.st_dev, info.st_ino), os.geteuid())

    assert not directory.exists()


def test_checkout_write_probe_cleanup_preserves_unexpected_entries(tmp_path: Path) -> None:
    directory = tmp_path / "checkout-write-probe"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    canary = directory / "write-canary"
    canary.write_text("test-owned canary", encoding="ascii")
    unexpected = directory / "unexpected"
    unexpected.write_text("preserve", encoding="ascii")
    info = directory.lstat()

    with pytest.raises(AssertionError, match="unexpected entry"):
        _remove_checkout_write_probe(directory, canary, (info.st_dev, info.st_ino), os.geteuid())

    assert canary.read_text(encoding="ascii") == "test-owned canary"
    assert unexpected.read_text(encoding="ascii") == "preserve"


def test_private_attempt_tree_cleanup_removes_owned_tree(tmp_path: Path) -> None:
    directory = tmp_path / "live-oci-attempt"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    (directory / "workspace-source").mkdir(mode=0o700)
    info = directory.lstat()

    _remove_private_attempt_tree(directory, (info.st_dev, info.st_ino), os.geteuid())

    assert not directory.exists()


def test_private_attempt_tree_cleanup_preserves_unexpected_entries(tmp_path: Path) -> None:
    directory = tmp_path / "live-oci-attempt"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    unexpected = directory / "unexpected"
    unexpected.write_text("preserve", encoding="ascii")
    info = directory.lstat()

    with pytest.raises(AssertionError, match="unexpected entry"):
        _remove_private_attempt_tree(directory, (info.st_dev, info.st_ino), os.geteuid())

    assert unexpected.read_text(encoding="ascii") == "preserve"


def test_partial_launch_without_runtime_identity_fails_closed() -> None:
    gaps = _cleanup_identity_gaps(
        launch_submitted=True,
        init_pid=None,
        init_start=None,
        cgroup_path=None,
        systemd_cgroup_path=None,
    )

    assert len(gaps) == 3
    assert "init PID/start-time" in gaps[0]
    assert "init cgroup" in gaps[1]
    assert "systemd scope cgroup" in gaps[2]


def test_missing_launcher_handle_is_unknown_unless_reap_receipt_is_positive() -> None:
    assert _runc_client_is_running(None, launch_client_reaped=None) is None
    assert _runc_client_is_running(None, launch_client_reaped=False) is None
    assert _runc_client_is_running(None, launch_client_reaped=True) is False

    class RunningProcess:
        def poll(self) -> None:
            return None

    class ExitedProcess:
        def poll(self) -> int:
            return 0

    assert _runc_client_is_running(RunningProcess(), launch_client_reaped=None) is True
    assert _runc_client_is_running(ExitedProcess(), launch_client_reaped=None) is False


@pytest.mark.parametrize(
    ("client_running_after_cleanup", "launch_client_reaped"),
    [(None, None), (True, None), (None, False)],
)
def test_unresolved_submitted_client_suppresses_destructive_cleanup_actions(
    client_running_after_cleanup: bool | None,
    launch_client_reaped: bool | None,
) -> None:
    client_state_known = _launch_client_state_known(
        launch_submitted=True,
        client_running_after_cleanup=client_running_after_cleanup,
        launch_client_reaped=launch_client_reaped,
    )
    assert not client_state_known

    attempted: list[str] = []
    for action_name in (
        "exact-ID runc delete",
        "PID file unlink",
        "checkout probe removal",
        "bundle restore",
        "attempt-tree removal",
    ):
        result = _run_cleanup_action_if_client_state_known(
            client_state_known,
            lambda name=action_name: attempted.append(name),
        )
        assert result is None

    assert attempted == []


def test_submitted_client_cleanup_requires_positive_exit_or_reap_receipt() -> None:
    assert not _launch_client_state_known(
        launch_submitted=True,
        client_running_after_cleanup=None,
        launch_client_reaped=None,
    )
    assert not _launch_client_state_known(
        launch_submitted=True,
        client_running_after_cleanup=True,
        launch_client_reaped=None,
    )
    assert _launch_client_state_known(
        launch_submitted=True,
        client_running_after_cleanup=False,
        launch_client_reaped=None,
    )
    assert _launch_client_state_known(
        launch_submitted=True,
        client_running_after_cleanup=None,
        launch_client_reaped=True,
    )


def test_present_but_uninspectable_client_does_not_authorize_cleanup() -> None:
    class UninspectableProcess:
        def poll(self) -> None:
            raise OSError("wait status unavailable")

    errors: list[str] = []
    running = _attempt_cleanup(
        errors,
        "could not inspect runc client after reap attempt",
        lambda: _runc_client_is_running(
            UninspectableProcess(),
            launch_client_reaped=None,  # type: ignore[arg-type]
        ),
    )
    assert running is None
    assert errors == [
        "could not inspect runc client after reap attempt: OSError: wait status unavailable"
    ]

    client_state_known = _launch_client_state_known(
        launch_submitted=True,
        client_running_after_cleanup=running,
        launch_client_reaped=None,
    )
    assert not client_state_known

    attempted: list[str] = []
    result = _run_cleanup_action_if_client_state_known(
        client_state_known, lambda: attempted.append("exact-ID runc delete")
    )
    assert result is None
    assert attempted == []


@pytest.mark.parametrize("poll_raises", [False, True])
def test_launch_submission_is_recorded_before_initial_client_poll(poll_raises: bool) -> None:
    attempt_cleanup = {
        "created": True,
        "launch_submitted": False,
        "preserve": False,
        "runtime_verified": False,
    }

    class ImmediateClient:
        def poll(self) -> int:
            assert attempt_cleanup["launch_submitted"]
            if poll_raises:
                raise OSError("initial poll failed")
            return 1

    if poll_raises:
        with pytest.raises(OSError, match="initial poll failed"):
            _check_runc_client_after_submission(attempt_cleanup, ImmediateClient())
    else:
        assert not _check_runc_client_after_submission(attempt_cleanup, ImmediateClient())
    assert attempt_cleanup["launch_submitted"]
    assert not _attempt_tree_removal_allowed(attempt_cleanup, client_state_known=True)


def _probe_script(
    *,
    host_paths: dict[str, Path],
    host_tmp_relative: str,
    host_network_ip: str,
    host_network_port: int,
) -> str:
    q = {name: shell_quote(str(path)) for name, path in host_paths.items()}
    host_tmp_rel = shell_quote(host_tmp_relative)
    net_ip = shell_quote(host_network_ip)
    net_port = shell_quote(str(host_network_port))
    return f"""set -eu
# Stop at a second host-controlled file gate. The host performs the FD audit.
/bin/busybox touch /workspace/fd-audit-ready
while [ ! -e /workspace/fd-audit-release ]; do :; done

test -r /workspace/input.txt
test "$(/bin/busybox cat /workspace/input.txt)" = 'snapshot input'
printf 'candidate result\\n' > /workspace/result.txt
printf 'private tmpfs\\n' > /tmp/acp-private-tmp.txt
printf 'private home\\n' > /home/agent/acp-private-home.txt

# Host /etc/os-release is a readable host sentinel; the image /etc is empty.
if /bin/busybox cat /etc/os-release > /workspace/host-etc.txt; then exit 31; fi
if /bin/busybox touch /etc/acp-write-probe; then exit 32; fi

# The checkout, sibling attempt, unrelated project, host home, host config,
# synthetic credential marker, and host temp file must not cross mounts.
if /bin/busybox cat {q["checkout"]} > /workspace/checkout.txt; then exit 33; fi
if /bin/busybox cat {q["sibling"]} > /workspace/sibling.txt; then exit 34; fi
if /bin/busybox cat {q["project"]} > /workspace/project.txt; then exit 35; fi
if test -e {q["checkout_git"]}; then exit 36; fi
if test -r {q["home"]}; then exit 37; fi
if /bin/busybox cat {q["host_config"]} > /workspace/host-config.txt; then exit 38; fi
if /bin/busybox cat {q["credential"]} > /workspace/credential.txt; then exit 39; fi
if /bin/busybox cat {q["host_tmp"]} > /workspace/host-tmp.txt; then exit 40; fi
if /bin/busybox touch {q["host_tmp"]}; then exit 41; fi
test ! -e /tmp/{host_tmp_rel}

# Absolute and parent-relative symlinks must remain inside the container root.
/bin/busybox ln -s {q["host_tmp"]} /workspace/absolute-host-tmp
/bin/busybox ln -s ../../tmp/{host_tmp_rel} /workspace/relative-host-tmp
if /bin/busybox cat /workspace/absolute-host-tmp > /workspace/absolute-link.txt; then exit 42; fi
if /bin/busybox cat /workspace/relative-host-tmp > /workspace/relative-link.txt; then exit 43; fi
if /bin/busybox touch /workspace/absolute-host-tmp; then exit 44; fi
if /bin/busybox touch {q["checkout_write"]}; then exit 45; fi

# No host network interface/default route, no inherited socket descriptor, and
# no connection to a test-owned listener on the host's selected NIC address.
interfaces=$(/bin/busybox sed -n '3,$s/^[[:space:]]*\\([^:]*\\):.*/\\1/p' /proc/net/dev | /bin/busybox tr -d '[:space:]')
test "$interfaces" = lo
if /bin/busybox grep -q '^00000000' /proc/net/route; then exit 47; fi
if /bin/busybox nc -w 1 {net_ip} {net_port} > /workspace/network-probe.txt 2>&1; then
  exit 49
else
  network_rc=$?
fi

printf 'network_probe_rc=%s\\ninterfaces=%s\\n' "$network_rc" "$interfaces" > /workspace/isolation-result.txt
"""


def _kill_runc_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=2)


@pytest.mark.skipif(not _LIVE_TEST_ENABLED, reason=_LIVE_TEST_REASON)
def test_live_rootless_runc_enforces_minimal_worker_boundary(
    tmp_path: Path, request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Attack the private bundle handoff, then run a bounded gated BusyBox payload."""

    if not sys.platform.startswith("linux"):
        pytest.skip("the live OCI proof requires Linux namespaces and procfs")
    if os.geteuid() == 0:
        pytest.fail("the live OCI proof must run as an unprivileged host user")
    if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        pytest.fail("the live OCI proof requires a unified cgroup-v2 host")
    tmp_path = tmp_path.resolve()
    if not tmp_path.is_relative_to(Path("/tmp")):
        pytest.fail("the opt-in test must use a private pytest directory below host /tmp")
    expected_version = os.environ.get("ACP_OCI_TEST_RUNC_VERSION")
    if not expected_version:
        pytest.fail("set ACP_OCI_TEST_RUNC_VERSION to the exact approved runc release")

    repo_root = Path(__file__).resolve().parents[1]
    if not repo_root.is_relative_to(Path("/tmp")):
        pytest.fail("the live proof must run from a disposable repository checkout below /tmp")
    pin = oci_worker._pin_trusted_runc_executable(
        Path(os.environ.get("ACP_OCI_TEST_RUNC", "/usr/bin/runc")), repo_root
    )
    observed_version = oci_worker._probe_trusted_runc_version(pin, expected_version)
    if observed_version != expected_version:
        pytest.fail("runc version probe disagreed with the explicit integration-test pin")

    attempt_root = tmp_path / "live-oci-attempt"
    renamed_bundle_root = attempt_root / "bundle-host-renamed"
    original_bundle_identity: tuple[int, int] | None = None
    recreated_bundle_identity: tuple[int, int] | None = None
    attacker_config = (
        b'{"ociVersion":"1.2.0","root":{"path":"rootfs","readonly":false},'
        b'"linux":{"rootfsPropagation":"shared"}}\n'
    )
    bundle_attack_evidence: dict[str, Any] = {}
    attempt_cleanup = {
        "created": False,
        "identity": None,
        "launch_submitted": False,
        "runtime_verified": False,
        "preserve": False,
    }
    cleanup_client_state_known = True

    def finalize_attempt_tree() -> None:
        if not _attempt_tree_removal_allowed(
            attempt_cleanup, client_state_known=cleanup_client_state_known
        ):
            return
        identity = attempt_cleanup["identity"]
        if identity is None:
            raise AssertionError("private attempt-tree identity was not recorded")
        _run_cleanup_action_if_client_state_known(
            cleanup_client_state_known,
            lambda: _remove_private_attempt_tree(attempt_root, identity, os.geteuid()),
        )

    request.addfinalizer(finalize_attempt_tree)
    if os.path.lexists(attempt_root):
        pytest.fail("unique private attempt-tree path already exists")
    attempt_root.mkdir(mode=0o700)
    attempt_cleanup["created"] = True
    attempt_root.chmod(0o700)
    attempt_root_info = attempt_root.lstat()
    if (
        not stat.S_ISDIR(attempt_root_info.st_mode)
        or attempt_root_info.st_uid != os.geteuid()
        or stat.S_IMODE(attempt_root_info.st_mode) != 0o700
    ):
        pytest.fail("private attempt root is not test-owned and mode 0700")
    attempt_cleanup["identity"] = (attempt_root_info.st_dev, attempt_root_info.st_ino)
    bundle_root = attempt_root / "bundle"
    bundle_root.mkdir(mode=0o700)
    bundle_info = bundle_root.lstat()
    original_bundle_identity = (bundle_info.st_dev, bundle_info.st_ino)
    rootfs = bundle_root / "rootfs"
    rootfs.mkdir(mode=0o755)
    for relative in (
        "bin",
        "dev",
        "etc",
        "home/agent",
        "proc",
        "run",
        "tmp",
        "workspace",
    ):
        (rootfs / relative).mkdir(parents=True, exist_ok=True, mode=0o755)
    (rootfs / "home" / "agent").chmod(0o700)
    busybox_version, applets = _copy_busybox_closure(
        Path(os.environ.get("ACP_OCI_TEST_BUSYBOX", "/usr/bin/busybox")), rootfs
    )

    workspace_source = attempt_root / "workspace-source"
    workspace_source.mkdir(mode=0o700)
    (workspace_source / "input.txt").write_text("snapshot input", encoding="ascii")
    (workspace_source / ".git").write_text(
        "gitdir: /tmp/host-shared-git-metadata", encoding="ascii"
    )
    workspace_snapshot = copy_snapshot(workspace_source, attempt_root / "workspace-snapshot")
    workspace = Path(workspace_snapshot.root)
    if (workspace / ".git").exists():
        pytest.fail("host snapshot copied its top-level Git pointer into the worker workspace")
    container_id = f"acp-live-{uuid.uuid4().hex}"
    host_workspace_anchor = Path("/dev/shm") / f"acp-{container_id}-workspace"
    host_workspace_anchor_marker = host_workspace_anchor / "host-only-marker"
    host_workspace_anchor_identity: tuple[int, int] | None = None
    checkout_probe_directory = repo_root / f".acp-checkout-write-probe-{uuid.uuid4().hex}"
    checkout_write = checkout_probe_directory / "canary"
    checkout_probe_identity: tuple[int, int] | None = None
    checkout_probe_created = False
    state_root = attempt_root / "runc-state"
    state_root.mkdir(mode=0o700)
    pid_file = state_root / "container.pid"
    original_state_root = state_root
    renamed_state_root = attempt_root / "runc-state-pinned"
    original_workspace = workspace
    renamed_workspace = attempt_root / "workspace-pinned"
    recreated_state_identity: tuple[int, int] | None = None
    recreated_workspace_identity: tuple[int, int] | None = None
    rootfs_manifest = oci_worker.rootfs_tree_manifest(rootfs)
    rootfs_digest = rootfs_manifest["rootfs_sha256"]
    rootfs_pin = oci_worker._pin_trusted_rootfs(
        rootfs,
        rootfs_digest,
        repo_root=repo_root,
        expected_closure_sha256=rootfs_manifest["closure_sha256"],
    )

    fixture_root = attempt_root / "host-fixtures"
    sibling_file = fixture_root / "sibling-attempt" / "private-marker"
    project_file = fixture_root / "unrelated-project" / "private-marker"
    host_config_file = fixture_root / "host-home" / ".codex" / "config-marker.toml"
    credential_file = fixture_root / "host-home" / ".ssh" / "synthetic-key-marker"
    host_tmp_file = fixture_root / "host-tmp-sentinel"
    fixture_root.mkdir(mode=0o700)
    fixture_root.chmod(0o700)
    for directory in (
        fixture_root / "sibling-attempt",
        fixture_root / "unrelated-project",
        fixture_root / "host-home",
        fixture_root / "host-home" / ".codex",
        fixture_root / "host-home" / ".ssh",
    ):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
    for file_path in (sibling_file, project_file, host_config_file, credential_file, host_tmp_file):
        file_path.write_text("test-only sentinel; not a credential", encoding="ascii")
        file_path.chmod(0o600)
        if not os.access(file_path, os.R_OK):
            pytest.fail("host isolation sentinel is not readable before launch")
    if not Path("/etc/os-release").is_file() or not os.access("/etc/os-release", os.R_OK):
        pytest.fail("readable host /etc/os-release sentinel is required")
    checkout_sentinel = repo_root / "pyproject.toml"
    if not checkout_sentinel.is_file() or not os.access(checkout_sentinel, os.R_OK):
        pytest.fail("current source checkout sentinel is not host-readable")
    host_paths = {
        "checkout": checkout_sentinel,
        "checkout_git": repo_root / ".git",
        "checkout_write": checkout_write,
        "sibling": sibling_file,
        "project": project_file,
        "home": Path.home(),
        "host_config": host_config_file,
        "credential": credential_file,
        "host_tmp": host_tmp_file,
    }
    host_tmp_relative = str(host_tmp_file.resolve().relative_to(Path("/tmp")))

    # A UDP connect performs local route selection but sends no packet.
    route_probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        route_probe.connect(("192.0.2.1", 9))
        host_network_ip = route_probe.getsockname()[0]
    except OSError as error:
        pytest.fail(f"could not select a host NIC address for the local deny probe: {error}")
    finally:
        route_probe.close()
    if host_network_ip.startswith("127.") or host_network_ip == "0.0.0.0":
        pytest.fail("route selection did not identify a non-loopback host NIC address")

    listener: socket.socket | None = None
    opened_runc_descriptor: int | None = None
    runc_descriptor: int | None = None
    run_handle: oci_worker.RuncLaunchHandle | None = None
    process: subprocess.Popen[bytes] | None = None
    launch_submitted = False
    launch_client_pid: int | None = None
    launch_client_reaped: bool | None = None
    init_pid: int | None = None
    init_start: bytes | None = None
    fd_audit: tuple[tuple[int, str], ...] | None = None
    cgroup_path: Path | None = None
    systemd_cgroup_path: Path | None = None
    systemd_unit = f"acp-{container_id}.scope"
    cleanup_errors: list[str] = []
    controls: dict[str, str] = {}
    runtime_policy: dict[str, Any] | None = None
    config: dict[str, Any] = {}
    runtime_path_attack_evidence: dict[str, Any] = {}
    workspace_lookup_probe: dict[str, Any] = {}
    try:
        if not Path("/dev/shm").is_dir():
            pytest.fail("live workspace-anchor proof requires host /dev/shm")
        if os.path.lexists(host_workspace_anchor):
            pytest.fail("unique host workspace-anchor collision path already exists")
        host_workspace_anchor.mkdir(mode=0o700)
        host_workspace_anchor_marker.write_text("host-only replacement marker", encoding="ascii")
        host_workspace_anchor_identity = (
            host_workspace_anchor.stat().st_dev,
            host_workspace_anchor.stat().st_ino,
        )
        if os.path.lexists(checkout_probe_directory):
            pytest.fail("unique test-owned checkout write-probe path already exists")
        checkout_probe_directory.mkdir(mode=0o700)
        checkout_probe_created = True
        checkout_probe_directory.chmod(0o700)
        checkout_probe_info = checkout_probe_directory.lstat()
        if (
            not stat.S_ISDIR(checkout_probe_info.st_mode)
            or checkout_probe_info.st_uid != os.geteuid()
            or stat.S_IMODE(checkout_probe_info.st_mode) != 0o700
        ):
            pytest.fail("checkout write-probe directory is not test-owned and private")
        checkout_probe_identity = (checkout_probe_info.st_dev, checkout_probe_info.st_ino)

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host_network_ip, 0))
        listener.listen(1)
        listener.setblocking(False)
        host_network_port = listener.getsockname()[1]

        opened_runc_descriptor = oci_worker._open_verified_runc_executable(pin)
        runc_descriptor = fcntl.fcntl(opened_runc_descriptor, fcntl.F_DUPFD_CLOEXEC, 10)
        os.close(opened_runc_descriptor)
        opened_runc_descriptor = None
        script = _probe_script(
            host_paths=host_paths,
            host_tmp_relative=host_tmp_relative,
            host_network_ip=host_network_ip,
            host_network_port=host_network_port,
        )
        config = oci_worker.build_oci_worker_config(
            bundle_root,
            workspace_snapshot,
            ("/bin/busybox", "sh", "-c", script),
            rootfs_pin=rootfs_pin,
            container_id=container_id,
            memory_bytes=_CONTAINER_MEMORY_BYTES,
            pids_limit=_CONTAINER_PIDS_LIMIT,
            cpu_quota_us=_CONTAINER_CPU_QUOTA_US,
            cpu_period_us=_CONTAINER_CPU_PERIOD_US,
            tmpfs_bytes=8 * 1024 * 1024,
            home_bytes=2 * 1024 * 1024,
        )
        worker_config = oci_worker._apply_pinned_runc_recursive_private_policy(
            config, pin, expected_version=observed_version
        )
        config = json.loads(worker_config.config_json)
        rootfs_propagation = config["linux"]["rootfsPropagation"]
        if config["root"].get("readonly") is not True:
            pytest.fail("OCI rootfs policy is not read-only")
        file_size_limits = [
            limit for limit in config["process"]["rlimits"] if limit.get("type") == "RLIMIT_FSIZE"
        ]
        if file_size_limits != [
            {
                "type": "RLIMIT_FSIZE",
                "hard": _CONTAINER_FILESIZE_LIMIT_BYTES,
                "soft": _CONTAINER_FILESIZE_LIMIT_BYTES,
            }
        ]:
            pytest.fail("trampoline and OCI worker file-size limits must match exactly")
        if {mount["destination"] for mount in config["mounts"]} != {
            "/proc",
            "/dev",
            "/workspace",
            "/tmp",
            "/home/agent",
        }:
            pytest.fail("OCI policy contains an unexpected mount destination")
        if any(mount["destination"] in {"/etc", "/usr"} for mount in config["mounts"]):
            pytest.fail("OCI policy mounted broad host configuration or toolchain paths")
        sensitive_worker_environment = {
            "OPENAI_API_KEY",
            "CODEX_HOME",
            "ACP_RUNNER_CREDENTIAL",
            "ANTHROPIC_API_KEY",
            "GEMINI_API_KEY",
            "SSH_AUTH_SOCK",
        }
        if sensitive_worker_environment & {
            item.split("=", 1)[0] for item in config["process"]["env"]
        }:
            pytest.fail("host credential or agent environment reached the OCI worker")

        def attack_bundle_before_runc(
            helper_pid: int, private_bundle: Path, bundle_fd: int
        ) -> None:
            nonlocal recreated_bundle_identity, recreated_state_identity
            nonlocal recreated_workspace_identity, state_root, workspace, pid_file
            proc_root_config = (
                Path(f"/proc/{helper_pid}/root")
                / private_bundle.relative_to(Path("/"))
                / "config.json"
            )
            try:
                descriptor = os.open(proc_root_config, os.O_WRONLY)
            except OSError as error:
                if error.errno not in {errno.EROFS, errno.EACCES, errno.EPERM}:
                    raise AssertionError("same-UID proc-root writer was not denied") from error
                bundle_attack_evidence["proc_root_write"] = errno.errorcode[error.errno]
            else:
                os.close(descriptor)
                raise AssertionError("same-UID writer opened the private config for writing")

            config_fd = os.open(
                "config.json", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0), dir_fd=bundle_fd
            )
            with os.fdopen(config_fd, "rb") as config_stream:
                private_config = config_stream.read()
            private_config_obj = json.loads(private_config)
            workspace_mount = next(
                mount
                for mount in private_config_obj["mounts"]
                if mount.get("destination") == "/workspace"
            )
            workspace_fd_source = workspace_mount.get("source")
            expected_workspace_source = f"/dev/shm/acp-{container_id}-workspace"
            if workspace_fd_source != expected_workspace_source:
                raise AssertionError("private config workspace source was not namespace-anchored")
            expected_private_config = json.loads(worker_config.config_json)
            expected_workspace_mount = next(
                mount
                for mount in expected_private_config["mounts"]
                if mount.get("destination") == "/workspace"
            )
            expected_workspace_mount["source"] = workspace_fd_source
            expected_private_config_bytes = oci_worker._canonical_oci_worker_config(
                expected_private_config
            )
            if private_config != expected_private_config_bytes:
                raise AssertionError(
                    "fd-anchored config changed beyond its pinned workspace source"
                )
            bundle_attack_evidence["private_config_digest"] = hashlib.sha256(
                private_config
            ).hexdigest()
            runtime_path_attack_evidence["workspace_fd_source"] = workspace_fd_source
            if host_workspace_anchor_marker.read_text(encoding="ascii") != (
                "host-only replacement marker"
            ):
                raise AssertionError("host /dev/shm collision marker changed before runc exec")
            runtime_path_attack_evidence["host_workspace_anchor_collision"] = True

            snapshot_busybox_fd = os.open(
                "rootfs/bin/busybox",
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
                dir_fd=bundle_fd,
            )
            with os.fdopen(snapshot_busybox_fd, "rb") as snapshot_stream:
                snapshot_busybox = snapshot_stream.read()
            snapshot_busybox_sha256 = hashlib.sha256(snapshot_busybox).hexdigest()
            source_busybox = private_bundle / "rootfs" / "bin" / "busybox"
            original_source_busybox_sha256 = hashlib.sha256(source_busybox.read_bytes()).hexdigest()
            expected_busybox_sha256 = next(
                entry["content_sha256"]
                for entry in rootfs_manifest["entries"]
                if entry["path"] == "bin/busybox"
            )
            if snapshot_busybox_sha256 != expected_busybox_sha256:
                raise AssertionError(
                    "private rootfs snapshot differs from the reserved BusyBox bytes"
                )
            source_busybox.write_bytes(b"mutated after private snapshot verification\n")
            bundle_attack_evidence["rootfs_source_mutated"] = True
            bundle_attack_evidence["snapshot_busybox_sha256"] = snapshot_busybox_sha256
            bundle_attack_evidence["reserved_busybox_sha256"] = expected_busybox_sha256
            bundle_attack_evidence["source_busybox_before_sha256"] = original_source_busybox_sha256
            bundle_attack_evidence["source_busybox_after_sha256"] = hashlib.sha256(
                source_busybox.read_bytes()
            ).hexdigest()

            replacement = private_bundle / "host-replacement.json"
            replacement.write_bytes(attacker_config)
            os.replace(replacement, private_bundle / "config.json")
            os.rename(private_bundle, renamed_bundle_root)
            private_bundle.mkdir(mode=0o700)
            recreated_info = private_bundle.lstat()
            recreated_bundle_identity = (recreated_info.st_dev, recreated_info.st_ino)
            (private_bundle / "config.json").write_bytes(attacker_config)
            bundle_attack_evidence["host_config_replaced"] = True
            bundle_attack_evidence["host_bundle_renamed_and_recreated"] = True

            if renamed_state_root.exists() or renamed_workspace.exists():
                raise AssertionError("runtime-path replacement targets already exist")
            os.rename(original_state_root, renamed_state_root)
            original_state_root.mkdir(mode=0o700)
            state_marker = original_state_root / "replacement-marker"
            state_marker.write_text("attacker-controlled state path", encoding="ascii")
            state_replacement = original_state_root.lstat()
            recreated_state_identity = (state_replacement.st_dev, state_replacement.st_ino)
            os.rename(original_workspace, renamed_workspace)
            original_workspace.mkdir(mode=0o700)
            workspace_marker = original_workspace / "replacement-marker"
            workspace_marker.write_text("attacker-controlled workspace path", encoding="ascii")
            workspace_replacement = original_workspace.lstat()
            recreated_workspace_identity = (
                workspace_replacement.st_dev,
                workspace_replacement.st_ino,
            )
            state_root = renamed_state_root
            workspace = renamed_workspace
            pid_file = state_root / "container.pid"
            runtime_path_attack_evidence["state_path_replaced_after_fd_capture"] = True
            runtime_path_attack_evidence["workspace_path_replaced_after_fd_capture"] = True
            runtime_path_attack_evidence["replacement_state_inode"] = recreated_state_identity[1]
            runtime_path_attack_evidence["replacement_workspace_inode"] = (
                recreated_workspace_identity[1]
            )

            setns_script = (
                "import ctypes, os, sys\n"
                "try:\n"
                "    fd=os.open(f'/proc/{sys.argv[1]}/ns/mnt', os.O_RDONLY)\n"
                "except OSError as e:\n"
                "    print(e.errno)\n"
                "else: libc=ctypes.CDLL(None, use_errno=True); "
                "rc=libc.setns(fd, 0x00020000); "
                "print(0 if rc == 0 else ctypes.get_errno())"
            )
            setns = subprocess.run(
                [sys.executable, "-I", "-S", "-c", setns_script, str(helper_pid)],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            )
            if setns.returncode != 0 or setns.stdout.strip() not in {
                str(errno.EPERM),
                str(errno.EACCES),
            }:
                raise AssertionError(
                    f"same-UID setns did not fail with EPERM: {setns.returncode}/{setns.stdout!r}"
                )
            bundle_attack_evidence["setns"] = errno.errorcode[int(setns.stdout.strip())]
            config_fd = os.open(
                "config.json", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0), dir_fd=bundle_fd
            )
            with os.fdopen(config_fd, "rb") as config_stream:
                private_config_after_attack = config_stream.read()
            if private_config_after_attack != private_config:
                raise AssertionError("host bundle replacement changed the fd-anchored config")

        private_bundle_launcher = oci_worker._spawn_pinned_runc_with_private_bundle
        private_bundle_launch_count = 0

        def replace_workspace_before_mount_lookup(
            helper_pid: int,
            selected_workspace: Path,
            pinned_workspace_device: int,
            pinned_workspace_inode: int,
        ) -> None:
            if selected_workspace != original_workspace:
                raise AssertionError("workspace lookup probe received an unexpected path")
            original_info = original_workspace.lstat()
            original_identity = (original_info.st_dev, original_info.st_ino)
            if (
                not stat.S_ISDIR(original_info.st_mode)
                or original_identity != (pinned_workspace_device, pinned_workspace_inode)
                or os.path.lexists(renamed_workspace)
            ):
                raise AssertionError("workspace lookup probe did not start from the pinned inode")
            workspace_lookup_probe["helper_pid"] = helper_pid
            workspace_lookup_probe["original_identity"] = original_identity
            os.rename(original_workspace, renamed_workspace)
            original_workspace.mkdir(mode=0o700)
            marker = original_workspace / "replacement-marker"
            marker.write_text("replacement before open_tree", encoding="ascii")
            replacement_info = original_workspace.lstat()
            workspace_lookup_probe["replacement_identity"] = (
                replacement_info.st_dev,
                replacement_info.st_ino,
            )
            runtime_path_attack_evidence["workspace_path_replaced_before_open_tree"] = True

        def fail_if_workspace_replacement_reaches_exec(
            _helper_pid: int, _bundle: Path, _private_bundle_fd: int
        ) -> None:
            workspace_lookup_probe["exec_hook_reached"] = True
            raise AssertionError("workspace replacement was not rejected before runc exec")

        def inject_same_uid_attack(
            executable: Any,
            argv: Any,
            selected_bundle: Path,
            config_json: bytes,
            **kwargs: Any,
        ) -> Any:
            nonlocal private_bundle_launch_count
            private_bundle_launch_count += 1
            if private_bundle_launch_count == 1:
                return private_bundle_launcher(
                    executable,
                    argv,
                    selected_bundle,
                    config_json,
                    _before_workspace_open=replace_workspace_before_mount_lookup,
                    _before_runc_exec=fail_if_workspace_replacement_reaches_exec,
                    **kwargs,
                )
            return private_bundle_launcher(
                executable,
                argv,
                selected_bundle,
                config_json,
                _before_runc_exec=attack_bundle_before_runc,
                **kwargs,
            )

        monkeypatch.setattr(
            oci_worker, "_spawn_pinned_runc_with_private_bundle", inject_same_uid_attack
        )
        try:
            oci_worker.spawn_pinned_runc(
                worker_config,
                state_root,
                bundle_root,
                workspace,
                pid_file,
                container_id,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except oci_worker.SupervisorError as error:
            workspace_lookup_probe["launch_error"] = str(error)
            if error.code != "sandbox_bundle_setup_failed":
                raise AssertionError(
                    "workspace lookup replacement did not fail before runc submission"
                ) from error
        else:
            raise AssertionError("workspace lookup replacement unexpectedly launched runc")
        if workspace_lookup_probe.get("exec_hook_reached"):
            raise AssertionError("workspace pathname replacement reached the runc exec hook")
        if not runtime_path_attack_evidence.get("workspace_path_replaced_before_open_tree"):
            raise AssertionError(
                "workspace lookup replacement hook did not run: "
                f"{workspace_lookup_probe.get('launch_error', 'launch returned without error')}"
            )
        try:
            os.waitpid(workspace_lookup_probe["helper_pid"], os.WNOHANG)
        except ChildProcessError:
            workspace_lookup_probe["helper_reaped"] = True
        else:
            raise AssertionError("workspace lookup helper was not reaped after fail-closed setup")
        replacement_info = original_workspace.lstat()
        replacement_identity = workspace_lookup_probe.get("replacement_identity")
        replacement_marker = original_workspace / "replacement-marker"
        if (
            not stat.S_ISDIR(replacement_info.st_mode)
            or (replacement_info.st_dev, replacement_info.st_ino) != replacement_identity
            or replacement_info.st_uid != os.geteuid()
            or stat.S_IMODE(replacement_info.st_mode) != 0o700
            or [entry.name for entry in original_workspace.iterdir()] != ["replacement-marker"]
            or not stat.S_ISREG(replacement_marker.lstat().st_mode)
            or replacement_marker.read_text(encoding="ascii") != "replacement before open_tree"
        ):
            raise AssertionError("workspace lookup replacement identity changed before restore")
        replacement_marker.unlink()
        original_workspace.rmdir()
        renamed_info = renamed_workspace.lstat()
        if not stat.S_ISDIR(renamed_info.st_mode) or (
            renamed_info.st_dev,
            renamed_info.st_ino,
        ) != workspace_lookup_probe.get("original_identity"):
            raise AssertionError("pinned workspace inode changed during lookup race probe")
        os.rename(renamed_workspace, original_workspace)
        runtime_path_attack_evidence["workspace_path_replacement_failed_closed"] = True
        try:
            run_handle = oci_worker.spawn_pinned_runc(
                worker_config,
                state_root,
                bundle_root,
                workspace,
                pid_file,
                container_id,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except oci_worker.SupervisorError as error:
            if error.code == "sandbox_launch_submission_unverified":
                launch_submitted = True
                attempt_cleanup["launch_submitted"] = True
                launch_client_pid = getattr(error, "client_pid", None)
                launch_client_reaped = getattr(error, "client_reaped", None)
                if launch_client_reaped is not True:
                    attempt_cleanup["preserve"] = True
            raise
        process = oci_worker._runc_launch_process_for_testing(run_handle)
        assert process is not None
        launch_submitted = True
        if not _check_runc_client_after_submission(attempt_cleanup, process):
            pytest.fail("pinned runc launcher exited before reaching its fd-3 gate")

        deadline = time.monotonic() + 12
        while not pid_file.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        if process.poll() is not None or not pid_file.exists():
            runc_stderr = (
                process.stderr.read().decode("utf-8", errors="replace")
                if process.stderr is not None and process.poll() is not None
                else ""
            )
            pytest.fail(
                f"runc did not reach the launch gate (exit={process.poll()}, "
                f"stderr={runc_stderr[-2048:]!r})"
            )

        init_pid = int(read_private_runc_pid_file(pid_file, state_root))
        init_snapshot = read_linux_process_snapshot(init_pid)
        init_start = _snapshot_start_time(init_snapshot, init_pid, require_live=True)
        cgroup_path = _snapshot_cgroup_path(init_snapshot)
        systemd_cgroup_path = _systemd_control_group(systemd_unit)
        if not _systemd_scope_is_active(systemd_unit):
            pytest.fail("exact runc systemd scope was not active before gate release")
        if systemd_cgroup_path is None:
            pytest.fail("exact runc systemd scope did not report a live ControlGroup")
        if systemd_cgroup_path.resolve(strict=True) != cgroup_path.resolve(strict=True):
            pytest.fail("systemd scope ControlGroup did not match the worker init cgroup")
        state_code, state_output = _safe_run_pinned_runc(
            pin, runc_descriptor, state_root, ["state", container_id]
        )
        if state_code != 0:
            pytest.fail(f"runc state readback failed before gate release: {state_output}")
        state = json.loads(state_output)
        expected_bundle_path = str(renamed_bundle_root.resolve())
        if (
            state.get("id") != container_id
            or state.get("status") != "running"
            or state.get("pid") != init_pid
            or state.get("bundle") != expected_bundle_path
        ):
            observed_state = tuple(state.get(key) for key in ("id", "status", "pid", "bundle"))
            expected_state = (container_id, "running", init_pid, expected_bundle_path)
            pytest.fail(
                "runc state did not match the exact gated OCI attempt: "
                f"observed={observed_state!r}, expected={expected_state!r}"
            )
        state_bundle_info = Path(state["bundle"]).stat()
        if (
            original_bundle_identity is None
            or (state_bundle_info.st_dev, state_bundle_info.st_ino) != original_bundle_identity
            or Path(state["bundle"]).resolve() == bundle_root.resolve()
        ):
            pytest.fail("runc state bundle path did not resolve to the renamed pinned directory")

        controls = {
            "memory.max": cgroup_path.joinpath("memory.max").read_text().strip(),
            "pids.max": cgroup_path.joinpath("pids.max").read_text().strip(),
            "cpu.max": cgroup_path.joinpath("cpu.max").read_text().strip(),
        }
        if controls["memory.max"] != str(_CONTAINER_MEMORY_BYTES):
            pytest.fail("live cgroup memory.max did not match the OCI policy")
        if controls["pids.max"] != str(_CONTAINER_PIDS_LIMIT):
            pytest.fail("live cgroup pids.max did not match the OCI policy")
        if controls["cpu.max"] != f"{_CONTAINER_CPU_QUOTA_US} {_CONTAINER_CPU_PERIOD_US}":
            pytest.fail("live cgroup cpu.max did not match the OCI policy")

        # Read kernel-applied privilege and mount state through the host's
        # procfs while the trusted fd3 launcher still blocks candidate code.
        try:
            runtime_policy = _audit_worker_init_runtime_policy(
                init_pid,
                expected_start_time=init_start,
                expected_cgroup_path=cgroup_path,
                expected_runc_version=observed_version,
            )
        except AssertionError as error:
            raise AssertionError(
                f"runc rootfsPropagation={rootfs_propagation!r} failed before fd3 gate release: "
                f"{error}"
            ) from error

        # The launch gate is the proof boundary: the init and policy readbacks
        # are live, but the first candidate instruction has not written output.
        time.sleep(0.1)
        if process.poll() is not None:
            pytest.fail("runc exited while the candidate was required to remain behind the gate")
        if (workspace / "result.txt").exists() or (workspace / "isolation-result.txt").exists():
            pytest.fail("candidate wrote workspace output before the gate was released")

        if run_handle is None:
            pytest.fail("pinned runc launch handle was not retained")
        _release_unjournaled_gate_for_test(run_handle)
        fd_ready = workspace / "fd-audit-ready"
        ready_deadline = time.monotonic() + 5
        while (
            not fd_ready.is_file() and process.poll() is None and time.monotonic() < ready_deadline
        ):
            time.sleep(0.01)
        if process.poll() is not None or not fd_ready.is_file():
            pytest.fail("candidate did not reach the host-side descriptor audit gate")
        if any(
            path.exists()
            for path in (
                workspace / "fd-audit.txt",
                workspace / "result.txt",
                workspace / "isolation-result.txt",
            )
        ):
            pytest.fail("candidate produced result output before host-side descriptor audit")
        fd_audit = _audit_worker_init_fd_table(
            init_pid,
            expected_start_time=init_start,
            expected_cgroup_path=cgroup_path,
        )
        if process.poll() is not None:
            pytest.fail("runc exited while candidate was behind the descriptor audit gate")
        if any(
            path.exists() for path in (workspace / "result.txt", workspace / "isolation-result.txt")
        ):
            pytest.fail(
                "candidate bypassed descriptor gate and produced output before host release"
            )
        release_fd = os.open(
            workspace / "fd-audit-release",
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            if os.write(release_fd, b"go\n") != 3:
                pytest.fail("could not release candidate descriptor-audit gate")
        finally:
            os.close(release_fd)
        try:
            returncode = process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            _kill_runc_group(process)
            pytest.fail("bounded OCI BusyBox fixture exceeded its 15-second deadline")
        if returncode != 0:
            pytest.fail(f"gated OCI fixture failed with exit {returncode}; fd audit={fd_audit!r}")

        result = (workspace / "isolation-result.txt").read_text(encoding="ascii")
        result_fields = dict(line.split("=", 1) for line in result.splitlines())
        assert int(result_fields["network_probe_rc"]) != 0
        assert result_fields["interfaces"] == "lo"
        assert (workspace / "result.txt").read_text(encoding="ascii") == "candidate result\n"
        assert (workspace / "absolute-host-tmp").is_symlink()
        assert (workspace / "relative-host-tmp").is_symlink()
        assert not checkout_write.exists()
        assert bundle_attack_evidence["rootfs_source_mutated"] is True
        assert (
            bundle_attack_evidence["snapshot_busybox_sha256"]
            == bundle_attack_evidence["reserved_busybox_sha256"]
            == bundle_attack_evidence["source_busybox_before_sha256"]
        )
        assert (
            bundle_attack_evidence["source_busybox_after_sha256"]
            != bundle_attack_evidence["snapshot_busybox_sha256"]
        )
        assert runtime_path_attack_evidence["state_path_replaced_after_fd_capture"] is True
        assert runtime_path_attack_evidence["workspace_path_replaced_after_fd_capture"] is True
        assert (state_root / container_id).is_dir()
        assert pid_file.is_file()
        assert sorted(path.name for path in original_state_root.iterdir()) == ["replacement-marker"]
        assert (original_state_root / "replacement-marker").read_text(encoding="ascii") == (
            "attacker-controlled state path"
        )
        assert sorted(path.name for path in original_workspace.iterdir()) == ["replacement-marker"]
        assert (original_workspace / "replacement-marker").read_text(encoding="ascii") == (
            "attacker-controlled workspace path"
        )
        assert host_workspace_anchor_marker.read_text(encoding="ascii") == (
            "host-only replacement marker"
        )

        ready, _, _ = select.select([listener], [], [], 0)
        if ready:
            accepted, _address = listener.accept()
            accepted.close()
            pytest.fail("isolated worker reached the test-owned host NIC listener")

        print(
            json.dumps(
                {
                    "proof": "bounded public spawn_pinned_runc launch using compiler-bound OCI config",
                    "worker_executor_integrated": False,
                    "same_uid_bundle_attack": bundle_attack_evidence,
                    "same_uid_runtime_path_attack": runtime_path_attack_evidence,
                    "kernel": Path("/proc/sys/kernel/osrelease").read_text().strip(),
                    "runc_version": observed_version,
                    "rootfs_propagation": rootfs_propagation,
                    "busybox": busybox_version,
                    "required_busybox_applets": sorted(
                        applets & {"cat", "grep", "ln", "nc", "readlink", "sed", "touch", "tr"}
                    ),
                    "rootfs_sha256": rootfs_digest,
                    "rootfs_closure_sha256": rootfs_manifest["closure_sha256"],
                    "rootfs_manifest_entries": len(rootfs_manifest["entries"]),
                    "mount_destinations": [mount["destination"] for mount in config["mounts"]],
                    "effective_runtime_policy": runtime_policy,
                    "cgroup_controls": controls,
                    "cgroup_path": str(cgroup_path),
                    "init_file_descriptors": [
                        {"fd": descriptor, "target": target}
                        for descriptor, target in (fd_audit or ())
                    ],
                    "systemd_unit": systemd_unit,
                    "isolation_result": result.strip(),
                    "host_paths_denied": [
                        "source checkout",
                        "sibling attempt",
                        "unrelated project",
                        "host home",
                        "synthetic host config and credential sentinels",
                        "host /etc/os-release",
                        "host /tmp sentinel",
                        "absolute and relative symlink targets",
                    ],
                    "checkout_write_probe": "unique test-owned canary; removed during teardown",
                    "network_probe": "host NIC listener was not reached",
                },
                sort_keys=True,
            )
        )
    finally:
        active_error = sys.exception()
        launch_submitted = bool(attempt_cleanup["launch_submitted"])

        def close_fd(label: str, descriptor: int) -> None:
            if descriptor >= 0:
                _attempt_cleanup(cleanup_errors, label, lambda: os.close(descriptor))

        def process_is_running() -> bool | None:
            return _attempt_cleanup(
                cleanup_errors,
                "could not inspect runc client process state",
                lambda: _runc_client_is_running(
                    process,
                    launch_client_reaped=launch_client_reaped,
                ),
            )

        def capture_process_snapshot(pid: int) -> Any | None:
            try:
                return read_linux_process_snapshot(pid)
            except (FileNotFoundError, ProcessLookupError):
                return None
            except Exception as error:
                if isinstance(error.__cause__, (FileNotFoundError, ProcessLookupError)):
                    return None
                cleanup_errors.append(
                    f"could not inspect exact init process before cleanup: "
                    f"{type(error).__name__}: {error}"
                )
                return None

        # Capture the exact runtime identity before closing the gate or killing
        # the runc client. Missing evidence is tolerated only when no launch was
        # submitted; destructive cleanup also requires a known client state.
        pid_file_present = _cleanup_path_exists(
            cleanup_errors, "could not inspect runc PID file before cleanup", pid_file
        )
        if launch_submitted and pid_file_present is True and init_pid is None:
            captured_pid = _attempt_cleanup(
                cleanup_errors,
                "could not read exact runc PID file before cleanup",
                lambda: int(read_private_runc_pid_file(pid_file, state_root)),
            )
            if captured_pid is not None:
                init_pid = captured_pid
        if launch_submitted and init_pid is None:
            state_result = _attempt_cleanup(
                cleanup_errors,
                "could not inspect exact runc state before cleanup",
                lambda: _safe_run_pinned_runc(
                    pin, runc_descriptor, state_root, ["state", container_id]
                ),
            )
            if state_result is not None and state_result[0] == 0:
                parsed_state = _attempt_cleanup(
                    cleanup_errors,
                    "could not parse exact runc state before cleanup",
                    lambda: json.loads(state_result[1]),
                )
                if isinstance(parsed_state, dict) and parsed_state.get("id") == container_id:
                    candidate_pid = parsed_state.get("pid")
                    if type(candidate_pid) is int and candidate_pid > 0:
                        init_pid = candidate_pid
        if launch_submitted and init_pid is not None:
            snapshot = capture_process_snapshot(init_pid)
            if snapshot is not None and init_start is None:
                init_start = _attempt_cleanup(
                    cleanup_errors,
                    "could not capture exact init start time",
                    lambda: _snapshot_start_time(snapshot, init_pid, require_live=False),
                )
            if cgroup_path is None and snapshot is not None:
                cgroup_path = _attempt_cleanup(
                    cleanup_errors,
                    "could not capture exact init cgroup",
                    lambda: _snapshot_cgroup_path(snapshot),
                )
        if launch_submitted and systemd_cgroup_path is None:
            systemd_cgroup_path = _attempt_cleanup(
                cleanup_errors,
                "could not capture worker systemd cgroup before cleanup",
                lambda: _systemd_control_group(systemd_unit),
            )
        cleanup_errors.extend(
            _cleanup_identity_gaps(
                launch_submitted=launch_submitted,
                init_pid=init_pid,
                init_start=init_start,
                cgroup_path=cgroup_path,
                systemd_cgroup_path=systemd_cgroup_path,
            )
        )

        # Closing the gate writer makes an unapproved launch fail closed before
        # the runtime process group is terminated and exact-ID cleanup runs.
        if run_handle is not None:
            _attempt_cleanup(
                cleanup_errors,
                "could not close candidate-exec gate",
                run_handle.close_gate,
            )

        if process_is_running() is True:
            _attempt_cleanup(
                cleanup_errors,
                "could not terminate the exact runc process group",
                lambda: _kill_runc_group(process),
            )
            if process_is_running() is True:
                _attempt_cleanup(
                    cleanup_errors,
                    "could not terminate the exact runc client process",
                    lambda: process.kill(),
                )
        if process is not None:
            waited = _attempt_cleanup(
                cleanup_errors,
                "could not reap the exact runc client process",
                lambda: process.wait(timeout=3),
            )
            if waited is None and process_is_running() is True:
                _attempt_cleanup(
                    cleanup_errors,
                    "could not force-reap the exact runc client process",
                    lambda: (process.kill(), process.wait(timeout=3)),
                )
            if process.stderr is not None:
                _attempt_cleanup(
                    cleanup_errors,
                    "could not close runc stderr capture",
                    process.stderr.close,
                )

        client_running_after_cleanup = process_is_running()
        if process is not None:
            launch_client_reaped = client_running_after_cleanup is False
        cleanup_client_state_known = _launch_client_state_known(
            launch_submitted=launch_submitted,
            client_running_after_cleanup=client_running_after_cleanup,
            launch_client_reaped=launch_client_reaped,
        )
        client_state_unverified = launch_submitted and not cleanup_client_state_known
        if client_state_unverified:
            attempt_cleanup["preserve"] = True
            cleanup_errors.append(
                "ambiguous launch client status after termination/reap; preserving "
                f"bundle/state evidence (pid={launch_client_pid!r}, "
                f"running={client_running_after_cleanup!r}, reaped={launch_client_reaped!r})"
            )

        delete_result: tuple[int, str] | None = None
        if launch_submitted:
            delete_result = _run_cleanup_action_if_client_state_known(
                cleanup_client_state_known,
                lambda: _attempt_cleanup(
                    cleanup_errors,
                    "could not issue exact-ID forced runc deletion",
                    lambda: _safe_run_pinned_runc(
                        pin, runc_descriptor, state_root, ["delete", "--force", container_id]
                    ),
                ),
            )
        pid_file_present = _cleanup_path_exists(
            cleanup_errors, "could not inspect runc PID file after deletion", pid_file
        )
        if pid_file_present is True:
            recorded_pid = _run_cleanup_action_if_client_state_known(
                cleanup_client_state_known,
                lambda: _attempt_cleanup(
                    cleanup_errors,
                    "could not revalidate runc PID file before unlink",
                    lambda: int(read_private_runc_pid_file(pid_file, state_root)),
                ),
            )
            if recorded_pid is not None and init_pid is not None and recorded_pid != init_pid:
                cleanup_errors.append("runc PID file changed before scoped cleanup")
            elif recorded_pid is not None:
                _run_cleanup_action_if_client_state_known(
                    cleanup_client_state_known,
                    lambda: _attempt_cleanup(
                        cleanup_errors,
                        "could not unlink exact private runc PID file",
                        lambda: pid_file.unlink(),
                    ),
                )
        pid_file_present = _cleanup_path_exists(
            cleanup_errors, "could not verify runc PID file removal", pid_file
        )
        if pid_file_present is True:
            cleanup_errors.append("runc PID file remained after cleanup")
        state_path = state_root / container_id
        state_path_present = _cleanup_path_exists(
            cleanup_errors, "could not inspect exact runc state after deletion", state_path
        )
        if state_path_present is True:
            cleanup_errors.append("runc state directory remained after cleanup")

        paths_to_verify = {path for path in (cgroup_path, systemd_cgroup_path) if path is not None}
        cgroup_residue = False
        for path in paths_to_verify:
            deadline = time.monotonic() + 5
            path_present = _cleanup_path_exists(
                cleanup_errors, f"could not inspect cgroup path {path}", path
            )
            while path_present is True and time.monotonic() < deadline:
                time.sleep(0.05)
                path_present = _cleanup_path_exists(
                    cleanup_errors, f"could not recheck cgroup path {path}", path
                )
            if path_present is True:
                cleanup_errors.append(f"container cgroup remained after cleanup: {path}")
                cgroup_residue = True
        if launch_submitted:
            scope_verified = (
                _attempt_cleanup(
                    cleanup_errors,
                    "could not verify exact worker systemd scope absence",
                    lambda: (_wait_for_worker_scope_absent(container_id), True)[1],
                )
                is True
            )
        else:
            scope_verified = True

        if init_pid is not None and init_start is not None:

            def exact_init_survives() -> bool:
                current = capture_process_snapshot(init_pid)
                if current is None:
                    return False
                return _snapshot_start_time(current, init_pid, require_live=False) == init_start

            survives = _attempt_cleanup(
                cleanup_errors,
                "could not verify exact init PID/start-time absence",
                exact_init_survives,
            )
            if survives:
                cleanup_errors.append("the exact container init PID/start-time survived cleanup")

        if checkout_probe_created:
            _run_cleanup_action_if_client_state_known(
                cleanup_client_state_known,
                lambda: _attempt_cleanup(
                    cleanup_errors,
                    "could not remove unique test-owned checkout write probe",
                    lambda: _remove_checkout_write_probe(
                        checkout_probe_directory,
                        checkout_write,
                        checkout_probe_identity,
                        os.geteuid(),
                    ),
                ),
            )
            probe_directory_present = _cleanup_path_exists(
                cleanup_errors,
                "could not verify checkout write-probe removal",
                checkout_probe_directory,
            )
            if probe_directory_present is True:
                cleanup_errors.append("unique checkout write-probe directory remained")
        client_still_running = process_is_running()
        if client_still_running is True:
            cleanup_errors.append("runc client process remained after cleanup")

        def remove_exact_host_workspace_anchor() -> None:
            if host_workspace_anchor_identity is None:
                return
            info = host_workspace_anchor.lstat()
            entries = list(host_workspace_anchor.iterdir())
            if (
                not stat.S_ISDIR(info.st_mode)
                or (info.st_dev, info.st_ino) != host_workspace_anchor_identity
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700
                or [entry.name for entry in entries] != ["host-only-marker"]
                or not stat.S_ISREG(host_workspace_anchor_marker.lstat().st_mode)
                or host_workspace_anchor_marker.read_text(encoding="ascii")
                != "host-only replacement marker"
            ):
                raise AssertionError("host workspace-anchor collision probe changed")
            host_workspace_anchor_marker.unlink()
            host_workspace_anchor.rmdir()

        _run_cleanup_action_if_client_state_known(
            cleanup_client_state_known,
            lambda: _attempt_cleanup(
                cleanup_errors,
                "could not remove exact host workspace-anchor collision probe",
                remove_exact_host_workspace_anchor,
            ),
        )
        if (
            host_workspace_anchor_identity is not None
            and cleanup_client_state_known
            and _cleanup_path_exists(
                cleanup_errors,
                "could not verify host workspace-anchor collision probe removal",
                host_workspace_anchor,
            )
            is True
        ):
            cleanup_errors.append("host workspace-anchor collision probe remained")

        if (
            delete_result is not None
            and delete_result[0] != 0
            and (
                pid_file_present is not False
                or state_path_present is not False
                or cgroup_residue
                or not scope_verified
                or client_still_running is not False
            )
        ):
            cleanup_errors.append(
                f"exact-ID runc delete returned {delete_result[0]} with runtime residue: "
                f"{delete_result[1]}"
            )

        if os.path.lexists(renamed_bundle_root):

            def restore_attacked_bundle() -> None:
                if original_bundle_identity is None:
                    raise AssertionError("original bundle identity was not captured")
                renamed_info = renamed_bundle_root.lstat()
                if (renamed_info.st_dev, renamed_info.st_ino) != original_bundle_identity:
                    raise AssertionError("renamed bundle identity changed during the attack test")
                if os.path.lexists(bundle_root):
                    if recreated_bundle_identity is None:
                        raise AssertionError("recreated bundle identity was not captured")
                    recreated_info = bundle_root.lstat()
                    if (
                        not stat.S_ISDIR(recreated_info.st_mode)
                        or (recreated_info.st_dev, recreated_info.st_ino)
                        != recreated_bundle_identity
                        or recreated_info.st_uid != os.geteuid()
                        or stat.S_IMODE(recreated_info.st_mode) != 0o700
                    ):
                        raise AssertionError("attacker replacement directory identity changed")
                    entries = list(bundle_root.iterdir())
                    config_path = bundle_root / "config.json"
                    if (
                        [entry.name for entry in entries] != ["config.json"]
                        or not stat.S_ISREG(config_path.lstat().st_mode)
                        or config_path.read_bytes() != attacker_config
                    ):
                        raise AssertionError("attacker replacement directory contents changed")
                    config_path.unlink()
                    bundle_root.rmdir()
                os.rename(renamed_bundle_root, bundle_root)

            _run_cleanup_action_if_client_state_known(
                cleanup_client_state_known,
                lambda: _attempt_cleanup(
                    cleanup_errors,
                    "could not restore exact test-owned bundle path after the attack replay",
                    restore_attacked_bundle,
                ),
            )

        # A failed teardown retains the private evidence tree for diagnosis.
        if not cleanup_errors:

            def remove_exact_runtime_path_replacement(
                path: Path, identity: tuple[int, int] | None, expected_contents: str
            ) -> None:
                if identity is None:
                    raise AssertionError("runtime-path replacement identity was not captured")
                info = path.lstat()
                entries = list(path.iterdir())
                marker = path / "replacement-marker"
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or (info.st_dev, info.st_ino) != identity
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o700
                    or [entry.name for entry in entries] != ["replacement-marker"]
                    or not stat.S_ISREG(marker.lstat().st_mode)
                    or marker.read_text(encoding="ascii") != expected_contents
                ):
                    raise AssertionError("runtime-path replacement changed after the attack proof")
                marker.unlink()
                path.rmdir()

            _attempt_cleanup(
                cleanup_errors,
                "could not remove the exact state-path replacement probe",
                lambda: remove_exact_runtime_path_replacement(
                    original_state_root,
                    recreated_state_identity,
                    "attacker-controlled state path",
                ),
            )
            _attempt_cleanup(
                cleanup_errors,
                "could not remove the exact workspace-path replacement probe",
                lambda: remove_exact_runtime_path_replacement(
                    original_workspace,
                    recreated_workspace_identity,
                    "attacker-controlled workspace path",
                ),
            )
            attempt_cleanup["runtime_verified"] = True
            _attempt_cleanup(
                cleanup_errors,
                "could not remove private OCI bundle",
                lambda: shutil.rmtree(bundle_root),
            )
            _attempt_cleanup(
                cleanup_errors,
                "could not remove private runc state",
                lambda: shutil.rmtree(state_root),
            )
            bundle_present = _cleanup_path_exists(
                cleanup_errors, "could not verify private bundle removal", bundle_root
            )
            state_root_present = _cleanup_path_exists(
                cleanup_errors, "could not verify private state removal", state_root
            )
            if bundle_present or state_root_present:
                cleanup_errors.append("disposable OCI bundle or state directory remained")

        # Descriptor cleanup is an unconditional outermost stage.
        if listener is not None:
            _attempt_cleanup(cleanup_errors, "could not close host-only listener", listener.close)
        close_fd(
            "could not close pinned runc descriptor",
            runc_descriptor if runc_descriptor is not None else -1,
        )
        close_fd(
            "could not close original pinned runc descriptor",
            opened_runc_descriptor if opened_runc_descriptor is not None else -1,
        )
        if cleanup_errors:
            attempt_cleanup["preserve"] = True
            prior = (
                f"; original failure: {type(active_error).__name__}: {active_error}"
                if active_error
                else ""
            )
            raise AssertionError(
                "live OCI cleanup verification failed: " + "; ".join(cleanup_errors) + prior
            )
