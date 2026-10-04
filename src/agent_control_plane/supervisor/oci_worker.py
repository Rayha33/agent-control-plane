"""Compile an OCI policy request for a future supervised worker executor.

This module deliberately does not launch a worker or claim that ACP currently
enforces this policy. It produces the narrow OCI config and attached ``runc``
argv that an integrated executor can consume after it has provisioned and
verified a private rootfs, snapshot workspace, durable lifecycle journal, and
cleanup/recovery path. This compiler does not prove that runc applies the
requested policy. The request is offline-only: it passes no caller environment
or credentials and creates an unconfigured network namespace. It encodes finite
memory, CPU, process-count, and tmpfs limits, but no aggregate quota for the
host-backed workspace. The device-cgroup deny entry is a requested rule, not
device isolation evidence: OCI runtimes provide default device nodes and may
apply additional device rules, while rootless cgroup setup may be unavailable.
The generated ``linux.seccomp`` profile is a denylist defense-in-depth layer,
not a complete syscall allowlist or a substitute for the namespace/mount
boundary. Runtime application and behavioral denial still require exact-host
verification before worker launch is enabled.
Path checks are not atomic and do not protect against an untrusted process with
the same host UID; the integrating executor must provision beneath trusted
ancestors, control same-UID writers, and reserve launch metadata safely.
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import stat
import weakref
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .common import SupervisorError
from .sandbox_workspace import Snapshot, read_snapshot_files

_CONTAINER_ID = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}\Z")
_MIN_MEMORY_BYTES = 16 * 1024 * 1024
_MAX_PIDS = 65_536
_MAX_UINT32 = (1 << 32) - 1
_MAX_UINT64 = (1 << 64) - 1
_MAX_INT64 = (1 << 63) - 1
_DEFAULT_TMPFS_BYTES = 64 * 1024 * 1024
_DEFAULT_HOME_BYTES = 16 * 1024 * 1024
_MOUNT_DESTINATIONS = ("/proc", "/workspace", "/tmp", "/home/agent")
_LAUNCH_GATE_SCRIPT = 'IFS= read -r _ <&3 || exit 125; exec 3<&-; exec "$@"'
_SUPPORTED_SECCOMP_MACHINES = frozenset({"x86_64", "amd64", "aarch64", "arm64"})
_HAS_EFFECTIVE_ID_ACCESS = os.access in os.supports_effective_ids
_TRUSTED_RUNC_PINS: dict[
    int,
    tuple[
        weakref.ReferenceType[Any],
        tuple[Path, Path, str, int, int, int, int, int, int, int],
    ],
] = {}
_SECCOMP_DENIED_SYSCALLS = (
    "add_key",
    "bpf",
    "chroot",
    "delete_module",
    "finit_module",
    "fsconfig",
    "fsmount",
    "fsopen",
    "init_module",
    "io_uring_enter",
    "io_uring_register",
    "io_uring_setup",
    "keyctl",
    "kexec_file_load",
    "kexec_load",
    "mount",
    "mount_setattr",
    "move_mount",
    "name_to_handle_at",
    "open_by_handle_at",
    "open_tree",
    "perf_event_open",
    "pidfd_getfd",
    "pivot_root",
    "process_vm_readv",
    "process_vm_writev",
    "ptrace",
    "reboot",
    "request_key",
    "setns",
    "swapon",
    "swapoff",
    "umount2",
    "unshare",
    "userfaultfd",
)
_CLONE_NEW_NAMESPACE_FLAGS = (
    0x00020000,  # CLONE_NEWNS
    0x00000080,  # CLONE_NEWTIME
    0x02000000,  # CLONE_NEWCGROUP
    0x04000000,  # CLONE_NEWUTS
    0x08000000,  # CLONE_NEWIPC
    0x10000000,  # CLONE_NEWUSER
    0x20000000,  # CLONE_NEWPID
    0x40000000,  # CLONE_NEWNET
)


def _worker_seccomp_profile() -> dict[str, Any]:
    machine = platform.machine().casefold()
    if machine not in _SUPPORTED_SECCOMP_MACHINES:
        raise SupervisorError(
            "invalid_oci_worker_policy",
            "OCI worker seccomp profile does not support this target architecture",
        )
    denied = {
        "names": list(_SECCOMP_DENIED_SYSCALLS),
        "action": "SCMP_ACT_ERRNO",
        "errnoRet": 1,
    }
    # classic seccomp cannot dereference clone3's flags pointer. ENOSYS is the
    # compatibility signal for libc to use clone, whose namespace bits are
    # filtered below while ordinary thread/fork bits remain available.
    clone3 = {"names": ["clone3"], "action": "SCMP_ACT_ERRNO", "errnoRet": 38}
    clone_namespace_rules = [
        {
            "names": ["clone"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
            "args": [
                {
                    "index": 0,
                    "value": flag,
                    "valueTwo": flag,
                    "op": "SCMP_CMP_MASKED_EQ",
                }
            ],
        }
        for flag in _CLONE_NEW_NAMESPACE_FLAGS
    ]
    non_unix_sockets = {
        "names": ["socket", "socketpair"],
        "action": "SCMP_ACT_ERRNO",
        "errnoRet": 1,
        "args": [{"index": 0, "value": 1, "op": "SCMP_CMP_NE"}],
    }
    return {
        "defaultAction": "SCMP_ACT_ALLOW",
        # OCI runtimes permit only the native ABI by default. `architectures`
        # adds ABIs, so repeating the native ABI can make runc reject the
        # filter as a duplicate. Compat ABIs are intentionally not enabled.
        "syscalls": [denied, clone3, *clone_namespace_rules, non_unix_sockets],
    }


def _plain_directory(path: str | Path, *, code: str, label: str) -> Path:
    candidate = Path(path).expanduser()
    try:
        info = candidate.lstat()
        canonical = candidate.resolve(strict=True)
        resolved_info = canonical.lstat()
    except (OSError, RuntimeError, ValueError) as error:
        raise SupervisorError(code, f"{label} is unavailable") from error
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or (info.st_dev, info.st_ino) != (resolved_info.st_dev, resolved_info.st_ino)
    ):
        raise SupervisorError(code, f"{label} must be a real directory, not a symlink")
    return canonical


def _private_directory(path: str | Path, *, code: str, label: str) -> Path:
    canonical = _plain_directory(path, code=code, label=label)
    effective_uid = os.geteuid()
    for ancestor in (canonical, *canonical.parents):
        try:
            info = ancestor.stat()
        except OSError as error:
            raise SupervisorError(code, f"{label} has an unavailable ancestor") from error
        mode = stat.S_IMODE(info.st_mode)
        sticky = bool(info.st_mode & stat.S_ISVTX)
        owner_is_trusted = info.st_uid in {0, effective_uid}
        other_writable = bool(mode & 0o022)
        if (not owner_is_trusted and mode & 0o200) or (other_writable and not sticky):
            raise SupervisorError(
                code,
                f"{label} has an ancestor that an untrusted host identity can replace",
            )

    info = canonical.stat()
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid != os.geteuid() or mode & 0o077 or mode & 0o700 != 0o700:
        raise SupervisorError(
            code,
            f"{label} must be owned by the current user and accessible only to that user",
        )
    return canonical


def _positive_int(value: Any, *, name: str, maximum: int | None = None) -> int:
    if type(value) is not int or value < 1 or (maximum is not None and value > maximum):
        raise SupervisorError("invalid_oci_worker_policy", f"{name} is outside its allowed range")
    return value


def _nonnegative_int(value: Any, *, name: str, maximum: int | None = None) -> int:
    if type(value) is not int or value < 0 or (maximum is not None and value > maximum):
        raise SupervisorError("invalid_oci_worker_policy", f"{name} is outside its allowed range")
    return value


def _validate_command(command: Sequence[str]) -> list[str]:
    if isinstance(command, (str, bytes)) or not isinstance(command, Sequence) or not command:
        raise SupervisorError("invalid_command", "OCI worker command must be a non-empty argv")
    args: list[str] = []
    for argument in command:
        if not isinstance(argument, str) or "\x00" in argument:
            raise SupervisorError("invalid_command", "OCI worker argv contains an invalid value")
        args.append(argument)
    executable = Path(args[0])
    if (
        not executable.is_absolute()
        or args[0].startswith("//")
        or executable.as_posix() != args[0]
        or ".." in executable.parts
    ):
        raise SupervisorError(
            "invalid_command",
            "OCI worker executable must use a canonical absolute path inside the pinned rootfs",
        )
    return args


def _validate_rootfs_executable(rootfs: Path, executable: str) -> None:
    executable_path = Path(executable)
    if any(
        mount == executable_path or mount in executable_path.parents
        for mount in map(Path, _MOUNT_DESTINATIONS)
    ):
        raise SupervisorError(
            "invalid_oci_executable",
            "worker executable must not be shadowed by a runtime mount",
        )
    candidate = rootfs
    components = executable_path.parts[1:]
    if not components:
        raise SupervisorError(
            "invalid_oci_executable", "worker executable must be a file inside the pinned rootfs"
        )
    effective_uid = os.geteuid()
    effective_gid = os.getegid()
    try:
        rootfs_info = rootfs.lstat()
    except OSError as error:
        raise SupervisorError("invalid_oci_rootfs", "OCI bundle rootfs is unavailable") from error
    if not _mapped_mode_allows(
        rootfs_info,
        uid=effective_uid,
        gid=effective_gid,
        owner_bit=stat.S_IXUSR,
        group_bit=stat.S_IXGRP,
        other_bit=stat.S_IXOTH,
    ):
        raise SupervisorError("invalid_oci_executable", "worker cannot traverse the pinned rootfs")
    for index, component in enumerate(components):
        candidate = candidate / component
        try:
            info = candidate.lstat()
        except OSError as error:
            raise SupervisorError(
                "invalid_oci_executable", "worker executable is absent from the pinned rootfs"
            ) from error
        final = index == len(components) - 1
        if stat.S_ISLNK(info.st_mode):
            raise SupervisorError(
                "invalid_oci_executable", "worker executable path must not traverse symlinks"
            )
        if final:
            if not stat.S_ISREG(info.st_mode) or not _mapped_mode_allows(
                info,
                uid=effective_uid,
                gid=effective_gid,
                owner_bit=stat.S_IXUSR,
                group_bit=stat.S_IXGRP,
                other_bit=stat.S_IXOTH,
            ):
                raise SupervisorError(
                    "invalid_oci_executable",
                    "worker executable must be executable by the mapped identity in the pinned rootfs",
                )
        else:
            if not stat.S_ISDIR(info.st_mode):
                raise SupervisorError(
                    "invalid_oci_executable", "worker executable path has a non-directory parent"
                )
            if not _mapped_mode_allows(
                info,
                uid=effective_uid,
                gid=effective_gid,
                owner_bit=stat.S_IXUSR,
                group_bit=stat.S_IXGRP,
                other_bit=stat.S_IXOTH,
            ):
                raise SupervisorError(
                    "invalid_oci_executable",
                    "worker cannot traverse a parent directory in the pinned rootfs",
                )


def _mapped_mode_allows(
    info: os.stat_result,
    *,
    uid: int,
    gid: int,
    owner_bit: int,
    group_bit: int,
    other_bit: int,
) -> bool:
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid == uid:
        return bool(mode & owner_bit)
    if info.st_gid == gid:
        return bool(mode & group_bit)
    return bool(mode & other_bit)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class _TrustedRuncExecutable:
    """Process-local provenance handle for one trusted, root-owned runc binary.

    A path string is not an executable trust pin: it can be replaced between
    configuration validation and invocation. The origin registry below binds
    this exact object to a canonical path, inode, size and content digest. A
    hand-constructed or copied handle is not accepted.
    """

    path: Path
    sha256: str
    device: int
    inode: int
    size: int


def _trusted_executable_identity(
    path: Path,
) -> tuple[str, tuple[int, int, int, int, int, int, int]]:
    """Hash one root-owned executable through a no-follow descriptor."""

    if not _HAS_EFFECTIVE_ID_ACCESS:
        raise SupervisorError(
            "invalid_oci_runtime",
            "effective-identity write checks are unavailable for the runc path",
        )
    for candidate in (path, *path.parents):
        try:
            writable = os.access(candidate, os.W_OK, effective_ids=True)
        except (OSError, NotImplementedError, TypeError) as error:
            raise SupervisorError(
                "invalid_oci_runtime",
                "effective-identity write check failed for the runc path",
            ) from error
        if writable:
            raise SupervisorError(
                "invalid_oci_runtime",
                "runc executable or parent path is writable by the supervisor user",
            )

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SupervisorError(
            "invalid_oci_runtime", "runc executable cannot be opened safely"
        ) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not before.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        ):
            raise SupervisorError(
                "invalid_oci_runtime",
                "runc executable must be a root-owned, non-group/world-writable regular file",
            )
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise SupervisorError(
            "invalid_oci_runtime", "runc executable changed while being pinned"
        ) from error
    finally:
        os.close(descriptor)

    def identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
        return (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_uid,
            stat.S_IMODE(info.st_mode),
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    if identity(before) != identity(after) or identity(after) != identity(current):
        raise SupervisorError("invalid_oci_runtime", "runc executable changed while being pinned")
    return digest.hexdigest(), identity(after)


def _pin_trusted_runc_executable(
    executable: str | Path, repo_root: str | Path
) -> _TrustedRuncExecutable:
    """Create a sealed handle for a root-owned executable.

    The resolved executable and every parent must be root-owned and not
    replaceable by group/other users. Candidate-controlled executables are
    rejected even when they happen to be executable and outside the attempt
    workspace. This helper is not currently wired into supervisor configuration
    or a worker launch path. It does not verify a desired runc version; a future
    executor must compare the pinned binary's version with operator
    configuration before launch.
    """

    if os.geteuid() == 0:
        raise SupervisorError(
            "invalid_oci_worker_policy", "OCI worker runtime must be invoked by a non-root caller"
        )
    try:
        root = Path(repo_root).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise SupervisorError(
            "invalid_oci_runtime", "supervisor repository is unavailable"
        ) from error
    try:
        from ..runtime_drivers import DriverError, resolve_trusted_executable

        resolved = resolve_trusted_executable(str(executable), root, expected_owners={0})
    except DriverError as error:
        raise SupervisorError(error.code, error.message) from error
    digest, identity = _trusted_executable_identity(resolved)
    pin = _TrustedRuncExecutable(
        path=resolved,
        sha256=digest,
        device=identity[0],
        inode=identity[1],
        size=identity[2],
    )
    key = id(pin)

    def discard(reference: weakref.ReferenceType[Any]) -> None:
        current = _TRUSTED_RUNC_PINS.get(key)
        if current is not None and current[0] is reference:
            _TRUSTED_RUNC_PINS.pop(key, None)

    reference = weakref.ref(pin, discard)
    _TRUSTED_RUNC_PINS[key] = (reference, (root, resolved, digest, *identity))
    return pin


def _verify_trusted_runc_executable(pin: _TrustedRuncExecutable) -> Path:
    """Revalidate a sealed pin before constructing the runtime command."""

    sealed = _TRUSTED_RUNC_PINS.get(id(pin)) if type(pin) is _TrustedRuncExecutable else None
    if sealed is None or sealed[0]() is not pin:
        raise SupervisorError(
            "invalid_oci_runtime", "runc executable must come from trusted supervisor configuration"
        )
    root, expected_path, expected_digest, *expected_identity = sealed[1]
    if (
        pin.path != expected_path
        or pin.sha256 != expected_digest
        or (pin.device, pin.inode, pin.size)
        != (expected_identity[0], expected_identity[1], expected_identity[2])
    ):
        raise SupervisorError("invalid_oci_runtime", "runc executable pin was modified")
    try:
        from ..runtime_drivers import DriverError, resolve_trusted_executable

        current_path = resolve_trusted_executable(str(expected_path), root, expected_owners={0})
    except DriverError as error:
        raise SupervisorError(error.code, error.message) from error
    current_digest, current_identity = _trusted_executable_identity(current_path)
    if (
        current_path != expected_path
        or current_digest != expected_digest
        or current_identity != tuple(expected_identity)
    ):
        raise SupervisorError("invalid_oci_runtime", "runc executable no longer matches its pin")
    return current_path


def build_oci_worker_config(
    bundle_root: str | Path,
    workspace_snapshot: Snapshot,
    command: Sequence[str],
    *,
    container_id: str,
    memory_bytes: int,
    pids_limit: int,
    cpu_quota_us: int,
    cpu_period_us: int = 100_000,
    tmpfs_bytes: int = _DEFAULT_TMPFS_BYTES,
    home_bytes: int = _DEFAULT_HOME_BYTES,
    host_uid: int | None = None,
    host_gid: int | None = None,
) -> dict[str, Any]:
    """Build an OCI 1.2 config with one mutable workspace and no host secrets.

    ``bundle_root/rootfs`` must already be a trusted, audited rootfs produced
    outside candidate control. ``workspace_snapshot`` must be a separate
    host-created snapshot with no Git metadata. Its complete tree is reopened
    and checked against the captured manifest immediately before the bind source
    is selected. The configured init blocks on inherited descriptor 3 before
    execing candidate code. The runc caller must map the trusted pipe read end
    to fd 3, pass exactly that descriptor with ``--preserve-fds 1``, and release
    its paired writer only after durable journal and runtime identity checks.
    This compiler does not release the gate or prove that the runtime applies
    the requested policy.
    """

    if os.geteuid() == 0:
        raise SupervisorError(
            "invalid_oci_worker_policy", "OCI worker config must be built by a non-root caller"
        )
    if type(workspace_snapshot) is not Snapshot:
        raise SupervisorError(
            "invalid_oci_workspace",
            "OCI worker workspace must be a host-validated snapshot",
        )
    bundle = _private_directory(bundle_root, code="invalid_oci_bundle", label="OCI bundle root")
    rootfs = bundle / "rootfs"
    try:
        rootfs_info = rootfs.lstat()
    except OSError as error:
        raise SupervisorError("invalid_oci_rootfs", "OCI bundle rootfs is unavailable") from error
    if stat.S_ISLNK(rootfs_info.st_mode) or not stat.S_ISDIR(rootfs_info.st_mode):
        raise SupervisorError("invalid_oci_rootfs", "OCI bundle rootfs must be a real directory")
    workspace = _private_directory(
        workspace_snapshot.root,
        code="invalid_oci_workspace",
        label="OCI worker workspace",
    )
    if bundle == workspace or bundle in workspace.parents or workspace in bundle.parents:
        raise SupervisorError(
            "invalid_oci_workspace", "OCI bundle and worker workspace must be disjoint"
        )
    if os.path.lexists(workspace / ".git"):
        raise SupervisorError(
            "invalid_oci_workspace", "OCI worker workspace must not expose Git metadata"
        )
    # The mount source must still be the exact host-captured baseline. Merely
    # checking that the directory is private does not establish that it is the
    # intended attempt snapshot or that it was not changed after capture.
    read_snapshot_files(workspace_snapshot)
    if not isinstance(container_id, str) or not _CONTAINER_ID.fullmatch(container_id):
        raise SupervisorError("invalid_oci_worker_policy", "OCI container ID is invalid")
    args = _validate_command(command)
    _validate_rootfs_executable(rootfs, args[0])
    _validate_rootfs_executable(rootfs, "/bin/sh")
    memory = _positive_int(memory_bytes, name="memory_bytes", maximum=_MAX_INT64)
    if memory < _MIN_MEMORY_BYTES:
        raise SupervisorError(
            "invalid_oci_worker_policy", "memory_bytes is below the 16 MiB minimum"
        )
    pids = _positive_int(pids_limit, name="pids_limit", maximum=_MAX_PIDS)
    quota = _positive_int(cpu_quota_us, name="cpu_quota_us", maximum=_MAX_INT64)
    period = _positive_int(cpu_period_us, name="cpu_period_us", maximum=_MAX_UINT64)
    tmpfs = _positive_int(tmpfs_bytes, name="tmpfs_bytes", maximum=_MAX_INT64)
    home = _positive_int(home_bytes, name="home_bytes", maximum=_MAX_INT64)
    uid = _nonnegative_int(
        os.geteuid() if host_uid is None else host_uid,
        name="host_uid",
        maximum=_MAX_UINT32,
    )
    gid = _nonnegative_int(
        os.getegid() if host_gid is None else host_gid,
        name="host_gid",
        maximum=_MAX_UINT32,
    )
    if uid == 0 or gid == 0 or uid != os.geteuid() or gid != os.getegid():
        raise SupervisorError(
            "invalid_oci_worker_policy",
            "OCI worker mappings must match the non-root caller's effective identity",
        )

    for destination in _MOUNT_DESTINATIONS:
        target = rootfs
        for component in Path(destination).parts[1:]:
            target = target / component
            try:
                target_info = target.lstat()
            except OSError as error:
                raise SupervisorError(
                    "invalid_oci_rootfs",
                    f"OCI rootfs mount target {destination} is unavailable",
                ) from error
            if stat.S_ISLNK(target_info.st_mode) or not stat.S_ISDIR(target_info.st_mode):
                raise SupervisorError(
                    "invalid_oci_rootfs",
                    f"OCI rootfs mount target {destination} and its parents must be real directories",
                )

    env = [
        "ACP_PHASE=worker",
        "ACP_REPO_ROOT=/workspace",
        "ACP_RUNTIME_DIR=/tmp/acp-runtime",
        "ACP_WORKTREE=/workspace",
        "HOME=/home/agent",
        "PATH=/usr/bin:/bin",
        "TMPDIR=/tmp",
    ]
    namespace_types = ("user", "pid", "mount", "ipc", "uts", "cgroup", "network")
    return {
        "ociVersion": "1.2.0",
        "hostname": "acp-worker",
        "root": {"path": "rootfs", "readonly": True},
        "process": {
            "terminal": False,
            "user": {"uid": 0, "gid": 0, "additionalGids": []},
            "args": [
                "/bin/sh",
                "-c",
                _LAUNCH_GATE_SCRIPT,
                "acp-launch-gate",
                *args,
            ],
            "env": env,
            "cwd": "/workspace",
            "noNewPrivileges": True,
            "rlimits": [
                {"type": "RLIMIT_CORE", "hard": 0, "soft": 0},
                {"type": "RLIMIT_FSIZE", "hard": 64 * 1024 * 1024, "soft": 64 * 1024 * 1024},
            ],
            "capabilities": {
                "bounding": [],
                "effective": [],
                "inheritable": [],
                "permitted": [],
                "ambient": [],
            },
        },
        "mounts": [
            {
                "destination": "/proc",
                "type": "proc",
                "source": "proc",
                "options": ["nosuid", "nodev", "noexec", "ro"],
            },
            {
                "destination": "/workspace",
                "type": "bind",
                "source": str(workspace),
                "options": ["bind", "rprivate", "rw", "nosuid", "nodev"],
            },
            {
                "destination": "/tmp",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "nodev", "mode=1777", f"size={tmpfs}"],
            },
            {
                "destination": "/home/agent",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "nodev", "mode=0700", f"size={home}"],
            },
        ],
        "linux": {
            "uidMappings": [{"containerID": 0, "hostID": uid, "size": 1}],
            "gidMappings": [{"containerID": 0, "hostID": gid, "size": 1}],
            "namespaces": [{"type": namespace} for namespace in namespace_types],
            "resources": {
                "memory": {"limit": memory},
                "cpu": {"quota": quota, "period": period},
                "pids": {"limit": pids},
                "devices": [{"allow": False, "access": "rwm"}],
            },
            "seccomp": _worker_seccomp_profile(),
            "cgroupsPath": f"user.slice:acp:{container_id}",
            "rootfsPropagation": "private",
            "maskedPaths": [
                "/proc/kcore",
                "/proc/keys",
                "/proc/latency_stats",
                "/proc/timer_stats",
                "/proc/sched_debug",
            ],
            "readonlyPaths": ["/proc/sys", "/proc/sysrq-trigger"],
        },
    }


def build_runc_run_argv(
    executable: _TrustedRuncExecutable,
    state_root: str | Path,
    bundle_root: str | Path,
    workspace_root: str | Path,
    pid_file: str | Path,
    container_id: str,
) -> list[str]:
    """Return an attached runc command with explicit state root and bundle.

    The OCI init requires one inherited launch-gate descriptor at fd 3. The
    caller must map the read end to fd 3, sanitize runc activation environment,
    pass exactly that one descriptor to ``subprocess.Popen``, and keep its
    paired writer private until it has durably authorized launch.
    ``executable`` must be a process-local pin minted by
    ``_pin_trusted_runc_executable``. Its root-owned file identity and SHA-256
    are rechecked here; a caller-supplied path or forged pin is refused. No
    supervisor config currently creates or passes this handle, and this helper
    does not verify the desired runc version or prove that runc applies policy.
    ``--keep`` preserves runc state/cgroup for an eventual supervised cleanup;
    the caller must not release its attempt fence until it separately proves
    that the init process, cgroup, and runc state are gone. The PID-path check
    is not an atomic reservation; only the exclusive, trusted executor may
    launch against this path.
    """

    if os.geteuid() == 0:
        raise SupervisorError(
            "invalid_oci_worker_policy", "OCI worker runtime must be invoked by a non-root caller"
        )
    binary = _verify_trusted_runc_executable(executable)
    state = _private_directory(state_root, code="invalid_oci_state", label="runc state root")
    bundle = _private_directory(bundle_root, code="invalid_oci_bundle", label="OCI bundle root")
    workspace = _private_directory(
        workspace_root, code="invalid_oci_workspace", label="OCI worker workspace"
    )
    private_roots = (state, bundle, workspace)
    for index, root in enumerate(private_roots):
        if any(
            root == other or root in other.parents or other in root.parents
            for other in private_roots[index + 1 :]
        ):
            raise SupervisorError(
                "invalid_oci_runtime_paths",
                "runc state, bundle, and workspace paths must be disjoint",
            )
    if not isinstance(container_id, str) or not _CONTAINER_ID.fullmatch(container_id):
        raise SupervisorError("invalid_oci_worker_policy", "OCI container ID is invalid")
    pid_path = Path(pid_file).expanduser()
    if not pid_path.is_absolute():
        raise SupervisorError("invalid_oci_pid_file", "runc PID file must be absolute")
    pid_parent = _private_directory(
        pid_path.parent, code="invalid_oci_pid_file", label="runc PID file parent"
    )
    try:
        pid_parent.relative_to(state)
    except ValueError as error:
        raise SupervisorError(
            "invalid_oci_pid_file", "runc PID file must be inside the private state root"
        ) from error
    pid_path = pid_parent / pid_path.name
    if os.path.lexists(pid_path):
        raise SupervisorError("invalid_oci_pid_file", "runc PID file must not already exist")
    return [
        str(binary),
        "--root",
        str(state),
        "--systemd-cgroup",
        "run",
        "--bundle",
        str(bundle),
        "--pid-file",
        str(pid_path),
        "--preserve-fds",
        "1",
        "--keep",
        container_id,
    ]
