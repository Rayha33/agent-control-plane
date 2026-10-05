"""Compile and launch an OCI policy request for a supervised worker executor.

This module compiles the narrow OCI config and attached ``runc`` argv, and
provides a held-executable-FD launcher that maps one private gate descriptor to
fd 3. The launcher is not wired into ``run_worker``: it does not reserve the
supervisor lifecycle journal, attest the live runtime, verify cleanup, recover
after crashes, or authorize result import. It therefore does not establish
that ACP currently enforces this policy. The request is offline-only: it passes
no caller environment or credentials into the OCI process and creates an
unconfigured network namespace. It encodes finite memory, CPU, process-count,
and tmpfs limits, but no aggregate quota for the host-backed workspace. The
device-cgroup deny entry is a requested rule, not device isolation evidence:
OCI runtimes provide default device nodes and may apply additional device rules,
while rootless cgroup setup may be unavailable. The generated
``linux.seccomp`` profile is a denylist defense-in-depth layer, not a complete
syscall allowlist or a substitute for the namespace/mount boundary. Runtime
application and behavioral denial still require exact-host verification before
worker launch is enabled.
Path checks are not atomic and do not protect against a concurrent writer with
access to the rootfs path (including a same-UID writer); the integrating
executor must provision beneath trusted ancestors, control writers, and
reserve launch metadata safely.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import platform
import re
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
import weakref
from collections.abc import Sequence
from dataclasses import dataclass, field
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
_MAX_ROOTFS_ENTRIES = 200_000
_MAX_ROOTFS_BYTES = 8 * 1024 * 1024 * 1024
_MAX_ROOTFS_PATH_BYTES = 4096
_MAX_ROOTFS_DEPTH = 256
_ROOTFS_CLOSURE_SCHEMA = "acp-oci-rootfs-closure-v1"
_MAX_MOUNTINFO_BYTES = 16 * 1024 * 1024
_DEFAULT_TMPFS_BYTES = 64 * 1024 * 1024
_DEFAULT_HOME_BYTES = 16 * 1024 * 1024
_MAX_RUNC_LAUNCH_PAYLOAD_BYTES = 64 * 1024
_MOUNT_DESTINATIONS = ("/proc", "/workspace", "/tmp", "/home/agent")
_LAUNCH_GATE_SCRIPT = 'IFS= read -r _ <&3 || exit 125; exec 3<&-; exec "$@"'
_RUNC_FD_LAUNCHER = r"""
import json
import os
import resource
import sys

start_fd, gate_fd, runc_fd = (int(value) for value in sys.argv[1:4])
payload_bytes = bytearray()
while len(payload_bytes) <= 65536:
    chunk = os.read(start_fd, 65537 - len(payload_bytes))
    if not chunk:
        break
    payload_bytes.extend(chunk)
os.close(start_fd)
if not payload_bytes.endswith(b"\n") or len(payload_bytes) > 65536:
    os._exit(125)
payload = json.loads(payload_bytes)
if (
    not isinstance(payload, dict)
    or set(payload) != {"argv", "env"}
    or not isinstance(payload["argv"], list)
    or not isinstance(payload["env"], dict)
):
    os._exit(125)
# runc is loaded from this exact descriptor, but its executable handle is not
# passed into runc or the OCI init. Keep it above fd 3 so the gate remap cannot
# accidentally clobber it.
os.set_inheritable(runc_fd, False)
if gate_fd == 3:
    os.set_inheritable(gate_fd, True)
else:
    os.dup2(gate_fd, 3, inheritable=True)
    os.close(gate_fd)
resource.setrlimit(
    resource.RLIMIT_FSIZE,
    (67108864, 67108864),
)
os.execve(runc_fd, payload["argv"], payload["env"])
"""
_LAUNCH_GATE_PRIVATE_GIT_SCRIPT = """\
IFS= read -r _ <&3 || exit 125
exec 3<&-
umask 077 || exit 125
unset GIT_TEMPLATE_DIR GIT_DIR GIT_COMMON_DIR GIT_WORK_TREE \\
  GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_INDEX_FILE \\
  GIT_NAMESPACE GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS GIT_REPLACE_REF_BASE \\
  GIT_SHALLOW_FILE GIT_GRAFT_FILE GIT_ATTR_SOURCE || exit 125
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_ATTR_NOSYSTEM=1
export GIT_TERMINAL_PROMPT=0
export GIT_CEILING_DIRECTORIES=/workspace
test ! -e .git && test ! -L .git || exit 125
_acp_git_template=/tmp/acp-git-template-$$
@ACP_MKDIR@ "$_acp_git_template" || exit 125
@ACP_GIT@ init --quiet --template="$_acp_git_template" . || exit 125
@ACP_RMDIR@ "$_acp_git_template" || exit 125
test ! -e .git/objects/info/alternates && \\
  test ! -L .git/objects/info/alternates || exit 125
test ! -e .git/objects/info/http-alternates && \\
  test ! -L .git/objects/info/http-alternates || exit 125
test ! -e .git/commondir && test ! -L .git/commondir || exit 125
test ! -e .git/info/grafts && test ! -L .git/info/grafts || exit 125
test ! -e .git/shallow && test ! -L .git/shallow || exit 125
@ACP_GIT@ symbolic-ref HEAD refs/heads/acp-worker || exit 125
@ACP_GIT@ config --local core.hooksPath /dev/null || exit 125
@ACP_GIT@ config --local core.fsmonitor false || exit 125
@ACP_GIT@ config --local core.excludesFile /dev/null || exit 125
@ACP_GIT@ add --all --force -- . || exit 125
@ACP_GIT@ -c 'user.name=ACP Worker' -c user.email=acp-worker@localhost \\
  -c commit.gpgsign=false commit --quiet --allow-empty --no-verify \\
  -m 'ACP isolated input snapshot' || exit 125
test -z "$(@ACP_GIT@ remote)" || exit 125
test "$(@ACP_GIT@ for-each-ref --format='%(refname)')" = refs/heads/acp-worker || exit 125
test "$(@ACP_GIT@ rev-list --all --count)" = 1 || exit 125
exec "$@"
"""


def _render_private_git_launch_script(*, git_path: str, mkdir_path: str, rmdir_path: str) -> str:
    script = _LAUNCH_GATE_PRIVATE_GIT_SCRIPT
    for token, path in (
        ("@ACP_GIT@", git_path),
        ("@ACP_MKDIR@", mkdir_path),
        ("@ACP_RMDIR@", rmdir_path),
    ):
        script = script.replace(token, path)
    if "@ACP_" in script:
        raise ValueError("private Git launch script has an unresolved executable")
    return script


_BOUNDED_COMMAND_GUARDIAN = """\
import os
import signal
import subprocess
import sys

def _expire_group(_signum=None, _frame=None):
    try:
        os.killpg(0, signal.SIGKILL)
    finally:
        os._exit(125)

try:
    timeout_seconds = float(sys.argv[1])
    status_fd = int(sys.argv[2])
    inherited_count = int(sys.argv[3])
    raw_exec_fd = sys.argv[4]
    exec_fd = int(raw_exec_fd) if raw_exec_fd else None
    inherited_fds = tuple(int(value) for value in sys.argv[5:5 + inherited_count])
    command_argv = sys.argv[5 + inherited_count:]
    if (
        inherited_count < 0
        or len(inherited_fds) != inherited_count
        or not command_argv
        or (exec_fd is not None and exec_fd not in inherited_fds)
    ):
        raise ValueError("invalid bounded command arguments")
    signal.signal(signal.SIGALRM, _expire_group)
    signal.alarm(max(1, int(timeout_seconds) + 2))
    if exec_fd is None:
        try:
            command = subprocess.Popen(
                command_argv,
                stdin=subprocess.DEVNULL,
                close_fds=True,
                pass_fds=inherited_fds,
            )
        except OSError:
            command_status = 125
        else:
            command_status = command.wait()
    else:
        child_pid = os.fork()
        if child_pid == 0:
            try:
                os.close(status_fd)
                for descriptor in inherited_fds:
                    if descriptor != exec_fd:
                        os.close(descriptor)
                os.set_inheritable(exec_fd, True)
                os.execve(exec_fd, command_argv, os.environ)
            except BaseException:
                os._exit(125)
        while True:
            try:
                _, child_status = os.waitpid(child_pid, 0)
                break
            except InterruptedError:
                continue
        command_status = os.waitstatus_to_exitcode(child_status)
    status_bytes = str(command_status).encode("ascii")
    offset = 0
    while offset < len(status_bytes):
        offset += os.write(status_fd, status_bytes[offset:])
    os.close(status_fd)
    os.close(1)
    os.close(2)
    while True:
        signal.pause()
except BaseException:
    _expire_group()
"""
_RUNC_RELEASE_VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_RUNC_VERSION_LINE = re.compile(r"runc version ([^\s]+)\Z")
_RUNC_VERSION_PROBE_TIMEOUT_SECONDS = 5.0
_RUNC_VERSION_PROBE_MAX_OUTPUT_BYTES = 8192
_SUPPORTED_SECCOMP_MACHINES = frozenset({"x86_64", "amd64", "aarch64", "arm64"})
_HAS_EFFECTIVE_ID_ACCESS = os.access in os.supports_effective_ids
_TRUSTED_RUNC_PINS: dict[
    int,
    tuple[
        weakref.ReferenceType[Any],
        tuple[Path, Path, str, int, int, int, int, int, int, int],
    ],
] = {}
_TRUSTED_ROOTFS_PINS: dict[
    int,
    tuple[
        weakref.ReferenceType[Any],
        tuple[Path, str, str, int, int],
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


@dataclass(frozen=True, slots=True, weakref_slot=True)
class _TrustedRootfs:
    """Process-local pin for an operator-digested OCI rootfs and closure."""

    path: Path
    sha256: str
    device: int
    inode: int
    closure_sha256: str | None = None


def _rootfs_stat_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _rootfs_link_stays_inside(relative_path: bytes, target: bytes) -> bool:
    """Check lexical symlink resolution stays below the container root."""

    if not target:
        return False
    parts = [] if target.startswith(b"/") else relative_path.split(b"/")[:-1]
    for component in target.split(b"/"):
        if component in {b"", b"."}:
            continue
        if component == b"..":
            if not parts:
                return False
            parts.pop()
        else:
            parts.append(component)
    return True


def _read_linux_mountinfo() -> bytes:
    """Read a bounded snapshot of the current Linux mount namespace."""

    try:
        with open("/proc/self/mountinfo", "rb") as mountinfo:
            content = mountinfo.read(_MAX_MOUNTINFO_BYTES + 1)
    except OSError as error:
        raise SupervisorError(
            "invalid_oci_rootfs", "Linux mount table cannot be read safely"
        ) from error
    if len(content) > _MAX_MOUNTINFO_BYTES or not content.endswith(b"\n"):
        raise SupervisorError(
            "invalid_oci_rootfs", "Linux mount table is invalid or exceeds its limit"
        )
    return content


def _decode_mountinfo_path(field: bytes) -> bytes:
    """Decode the four octal escapes used for path fields in mountinfo."""

    escapes = {b"040": b" ", b"011": b"\t", b"012": b"\n", b"134": b"\\"}
    decoded = bytearray()
    index = 0
    while index < len(field):
        if field[index] != ord("\\"):
            decoded.append(field[index])
            index += 1
            continue
        replacement = escapes.get(field[index + 1 : index + 4])
        if replacement is None:
            raise SupervisorError(
                "invalid_oci_rootfs", "Linux mount table contains an invalid path escape"
            )
        decoded.extend(replacement)
        index += 4
    if b"\0" in decoded:
        raise SupervisorError("invalid_oci_rootfs", "Linux mount table contains an invalid path")
    return bytes(decoded)


def _reject_nested_linux_mounts(root: Path, mountinfo: bytes) -> None:
    """Reject any mountpoint strictly below root, including same-device binds."""

    root = Path(os.path.normpath(os.fspath(root)))
    if not mountinfo or not mountinfo.endswith(b"\n"):
        raise SupervisorError("invalid_oci_rootfs", "Linux mount table is invalid")
    for line in mountinfo.splitlines():
        before_separator, separator, after_separator = line.partition(b" - ")
        fields = before_separator.split()
        if (
            not separator
            or len(fields) < 6
            or len(after_separator.split()) < 3
            or not fields[0].isdigit()
            or not fields[1].isdigit()
            or re.fullmatch(rb"[0-9]+:[0-9]+", fields[2]) is None
        ):
            raise SupervisorError(
                "invalid_oci_rootfs", "Linux mount table contains a malformed entry"
            )
        mountpoint_bytes = _decode_mountinfo_path(fields[4])
        try:
            mountpoint_text = os.fsdecode(mountpoint_bytes)
            if not os.path.isabs(mountpoint_text) or ".." in Path(mountpoint_text).parts:
                raise ValueError("non-canonical mountpoint")
            mountpoint = Path(os.path.normpath(mountpoint_text))
        except (TypeError, ValueError) as error:
            raise SupervisorError(
                "invalid_oci_rootfs", "Linux mount table contains an invalid mountpoint"
            ) from error
        if mountpoint != root and root in mountpoint.parents:
            raise SupervisorError("invalid_oci_rootfs", "OCI rootfs contains a nested mount")


def _check_rootfs_posix_acl(descriptor: int) -> None:
    """Reject POSIX ACLs so the digest's mode bits cannot hide access grants."""

    if platform.system() != "Linux":
        return
    getxattr = getattr(os, "getxattr", None)
    if getxattr is None:
        raise SupervisorError("invalid_oci_rootfs", "Linux rootfs ACL checks are unavailable")
    missing = {errno.ENODATA, getattr(errno, "ENOATTR", errno.ENODATA)}
    unsupported = {errno.ENOTSUP, getattr(errno, "EOPNOTSUPP", errno.ENOTSUP)}
    for attribute in ("system.posix_acl_access", "system.posix_acl_default"):
        try:
            getxattr(descriptor, attribute)
        except OSError as error:
            if error.errno in missing or error.errno in unsupported:
                continue
            raise SupervisorError(
                "invalid_oci_rootfs", "Linux rootfs ACL state is unknown"
            ) from error
        raise SupervisorError("invalid_oci_rootfs", "OCI rootfs contains a POSIX ACL")


def _check_rootfs_file_capability(descriptor: int) -> None:
    if platform.system() != "Linux":
        return
    getxattr = getattr(os, "getxattr", None)
    if getxattr is None:
        raise SupervisorError(
            "invalid_oci_rootfs", "Linux rootfs file-capability checks are unavailable"
        )
    try:
        getxattr(descriptor, "security.capability")
    except OSError as error:
        unsupported = {
            errno.ENODATA,
            getattr(errno, "ENOATTR", errno.ENODATA),
            errno.ENOTSUP,
            getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
        }
        if error.errno not in unsupported:
            raise SupervisorError(
                "invalid_oci_rootfs", "rootfs file-capability state is unknown"
            ) from error
    else:
        raise SupervisorError(
            "invalid_oci_rootfs", "OCI worker rootfs must not contain file capabilities"
        )


def _measure_rootfs_tree(
    path: str | Path,
    *,
    _manifest_entries: list[dict[str, Any]] | None = None,
) -> tuple[str, int, int]:
    """Return a canonical tree digest and the inode opened for that scan.

    The digest binds relative names, entry types, permission/ownership metadata,
    regular-file contents, and symlink targets. Devices, sockets, FIFOs,
    cross-device or nested mounts, hard-linked files, Linux POSIX ACLs,
    escaping symlinks, set-id entries, Linux file capabilities, and trees above fixed
    limits fail closed. This is an integrity measurement, not evidence that an
    image was audited.
    """

    root = _plain_directory(path, code="invalid_oci_rootfs", label="OCI rootfs")
    is_linux = platform.system() == "Linux"
    mountinfo_before = _read_linux_mountinfo() if is_linux else None
    if mountinfo_before is not None:
        _reject_nested_linux_mounts(root, mountinfo_before)
    root_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    try:
        root_fd = os.open(root, root_flags | nofollow | cloexec)
    except OSError as error:
        raise SupervisorError("invalid_oci_rootfs", "OCI rootfs cannot be opened safely") from error

    digest = hashlib.sha256(b"ACP-OCI-ROOTFS-TREE-V1\0")
    entries_seen = 0
    entries_pending = 0
    bytes_seen = 0

    def record(
        relative_path: bytes,
        kind: str,
        info: os.stat_result,
        payload: str,
        *,
        symlink_target: bytes | None = None,
    ) -> None:
        fields = [
            relative_path.hex(),
            kind,
            stat.S_IMODE(info.st_mode),
            info.st_uid,
            info.st_gid,
            info.st_size if kind in {"file", "symlink"} else 0,
            payload,
        ]
        encoded = json.dumps(fields, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        if _manifest_entries is not None:
            entry: dict[str, Any] = {
                "path": os.fsdecode(relative_path),
                "type": kind,
                "mode": stat.S_IMODE(info.st_mode),
                "uid": info.st_uid,
                "gid": info.st_gid,
                "size": info.st_size if kind in {"file", "symlink"} else 0,
            }
            if kind == "file":
                entry["content_sha256"] = payload
            elif kind == "symlink":
                if symlink_target is None:
                    raise SupervisorError(
                        "invalid_oci_rootfs", "OCI rootfs symlink target was not recorded"
                    )
                entry["target"] = os.fsdecode(symlink_target)
                entry["target_sha256"] = payload
            _manifest_entries.append(entry)

    def visit(directory: Path, directory_fd: int, prefix: bytes, depth: int) -> None:
        nonlocal entries_seen, entries_pending, bytes_seen
        if depth > _MAX_ROOTFS_DEPTH:
            raise SupervisorError("invalid_oci_rootfs", "OCI rootfs nesting exceeds its limit")
        before_directory = os.fstat(directory_fd)
        try:
            with os.scandir(directory_fd) as iterator:
                names = []
                for entry in iterator:
                    if entries_seen + entries_pending >= _MAX_ROOTFS_ENTRIES:
                        raise SupervisorError(
                            "invalid_oci_rootfs", "OCI rootfs contains too many entries"
                        )
                    names.append(entry.name)
                    entries_pending += 1
                names.sort(key=os.fsencode)
        except OSError as error:
            raise SupervisorError(
                "invalid_oci_rootfs", "OCI rootfs directory is unreadable"
            ) from error
        for name in names:
            entries_pending -= 1
            entries_seen += 1
            name_bytes = os.fsencode(name)
            relative_path = name_bytes if not prefix else prefix + b"/" + name_bytes
            if len(relative_path) > _MAX_ROOTFS_PATH_BYTES:
                raise SupervisorError("invalid_oci_rootfs", "OCI rootfs path exceeds its limit")
            child = directory / name
            try:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as error:
                raise SupervisorError(
                    "invalid_oci_rootfs", "OCI rootfs changed while being read"
                ) from error
            if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                raise SupervisorError("invalid_oci_rootfs", "OCI rootfs contains a set-id entry")
            if info.st_dev != before_directory.st_dev:
                raise SupervisorError(
                    "invalid_oci_rootfs", "OCI rootfs crosses a filesystem boundary"
                )
            if stat.S_ISDIR(info.st_mode):
                if not is_linux and os.path.ismount(child):
                    raise SupervisorError(
                        "invalid_oci_rootfs", "OCI rootfs contains a nested mount"
                    )
                try:
                    child_fd = os.open(name, root_flags | nofollow | cloexec, dir_fd=directory_fd)
                except OSError as error:
                    raise SupervisorError(
                        "invalid_oci_rootfs", "OCI rootfs directory changed while being read"
                    ) from error
                try:
                    opened = os.fstat(child_fd)
                    if _rootfs_stat_identity(info) != _rootfs_stat_identity(opened):
                        raise SupervisorError(
                            "invalid_oci_rootfs", "OCI rootfs changed while being read"
                        )
                    _check_rootfs_posix_acl(child_fd)
                    record(relative_path, "directory", info, "")
                    visit(child, child_fd, relative_path, depth + 1)
                    if _rootfs_stat_identity(opened) != _rootfs_stat_identity(os.fstat(child_fd)):
                        raise SupervisorError(
                            "invalid_oci_rootfs", "OCI rootfs changed while being read"
                        )
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise SupervisorError(
                        "invalid_oci_rootfs", "OCI rootfs contains a hard-linked file"
                    )
                bytes_seen += info.st_size
                if bytes_seen > _MAX_ROOTFS_BYTES:
                    raise SupervisorError("invalid_oci_rootfs", "OCI rootfs exceeds its byte limit")
                try:
                    file_fd = os.open(name, os.O_RDONLY | nofollow | cloexec, dir_fd=directory_fd)
                except OSError as error:
                    raise SupervisorError(
                        "invalid_oci_rootfs", "OCI rootfs file changed while being read"
                    ) from error
                try:
                    opened = os.fstat(file_fd)
                    if _rootfs_stat_identity(info) != _rootfs_stat_identity(opened):
                        raise SupervisorError(
                            "invalid_oci_rootfs", "OCI rootfs changed while being read"
                        )
                    _check_rootfs_posix_acl(file_fd)
                    _check_rootfs_file_capability(file_fd)
                    file_digest = hashlib.sha256()
                    size = 0
                    while True:
                        chunk = os.read(file_fd, 1024 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        file_digest.update(chunk)
                    after = os.fstat(file_fd)
                    if size != info.st_size or _rootfs_stat_identity(
                        opened
                    ) != _rootfs_stat_identity(after):
                        raise SupervisorError(
                            "invalid_oci_rootfs", "OCI rootfs changed while being read"
                        )
                    record(relative_path, "file", info, file_digest.hexdigest())
                finally:
                    os.close(file_fd)
            elif stat.S_ISLNK(info.st_mode):
                try:
                    target = os.fsencode(os.readlink(name, dir_fd=directory_fd))
                    after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError as error:
                    raise SupervisorError(
                        "invalid_oci_rootfs", "OCI rootfs symlink changed while being read"
                    ) from error
                if _rootfs_stat_identity(info) != _rootfs_stat_identity(after):
                    raise SupervisorError(
                        "invalid_oci_rootfs", "OCI rootfs changed while being read"
                    )
                if not _rootfs_link_stays_inside(relative_path, target):
                    raise SupervisorError(
                        "invalid_oci_rootfs", "OCI rootfs contains an escaping symlink"
                    )
                bytes_seen += len(target)
                if bytes_seen > _MAX_ROOTFS_BYTES:
                    raise SupervisorError("invalid_oci_rootfs", "OCI rootfs exceeds its byte limit")
                record(
                    relative_path,
                    "symlink",
                    info,
                    hashlib.sha256(target).hexdigest(),
                    symlink_target=target,
                )
            else:
                raise SupervisorError("invalid_oci_rootfs", "OCI rootfs contains a special file")
        if _rootfs_stat_identity(before_directory) != _rootfs_stat_identity(os.fstat(directory_fd)):
            raise SupervisorError("invalid_oci_rootfs", "OCI rootfs changed while being read")

    try:
        opened_root = os.fstat(root_fd)
        if opened_root.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise SupervisorError("invalid_oci_rootfs", "OCI rootfs contains a set-id root")
        _check_rootfs_posix_acl(root_fd)
        record(b"", "directory", opened_root, "")
        visit(root, root_fd, b"", 0)
        current_root = os.stat(root, follow_symlinks=False)
        if _rootfs_stat_identity(opened_root) != _rootfs_stat_identity(current_root):
            raise SupervisorError("invalid_oci_rootfs", "OCI rootfs changed while being read")
        if mountinfo_before is not None and _read_linux_mountinfo() != mountinfo_before:
            raise SupervisorError(
                "invalid_oci_rootfs", "Linux mount table changed while rootfs was read"
            )
    except SupervisorError:
        raise
    except (OSError, TypeError, NotImplementedError) as error:
        raise SupervisorError(
            "invalid_oci_rootfs", "OCI rootfs cannot be verified safely"
        ) from error
    finally:
        os.close(root_fd)
    if _manifest_entries is not None:
        _manifest_entries.sort(key=lambda entry: os.fsencode(entry["path"]))
    return digest.hexdigest(), opened_root.st_dev, opened_root.st_ino


def rootfs_tree_sha256(path: str | Path) -> str:
    """Return a canonical rootfs digest without following links.

    Linux POSIX ACLs and nested Linux mounts are rejected. Other extended
    attributes and non-Linux ACL mechanisms are not included in this digest;
    Linux file capabilities are separately rejected.
    """

    return _measure_rootfs_tree(path)[0]


def _canonical_rootfs_closure(entries: list[dict[str, Any]]) -> bytes:
    return json.dumps(
        {"schema": _ROOTFS_CLOSURE_SCHEMA, "entries": entries},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def rootfs_tree_manifest(path: str | Path) -> dict[str, Any]:
    """Inventory every filesystem entry without exposing regular-file bytes.

    Paths and metadata are listed, while regular-file contents are represented
    only by SHA-256. ``closure_sha256`` binds the schema and complete ordered
    filesystem inventory; it is not runtime dependency resolution or an
    attestation of provenance, audit quality, or absence of secrets.
    """

    entries: list[dict[str, Any]] = []
    tree_sha256, _device, _inode = _measure_rootfs_tree(path, _manifest_entries=entries)
    closure_sha256 = hashlib.sha256(_canonical_rootfs_closure(entries)).hexdigest()
    return {
        "schema": _ROOTFS_CLOSURE_SCHEMA,
        "rootfs_sha256": tree_sha256,
        "closure_sha256": closure_sha256,
        "entries": entries,
    }


def _is_rootfs_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _pin_trusted_rootfs(
    path: str | Path,
    expected_sha256: str,
    repo_root: str | Path | None = None,
    *,
    expected_closure_sha256: str | None = None,
) -> _TrustedRootfs:
    """Pin an operator-selected rootfs by path, inode, tree, and closure digests."""

    if os.geteuid() == 0:
        raise SupervisorError(
            "invalid_oci_rootfs", "OCI worker rootfs must be configured by a non-root caller"
        )
    if not _is_rootfs_sha256(expected_sha256):
        raise SupervisorError("invalid_oci_rootfs", "configured OCI rootfs digest is invalid")
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        raise SupervisorError("invalid_oci_rootfs", "configured OCI rootfs path must be absolute")
    root = _plain_directory(candidate, code="invalid_oci_rootfs", label="configured OCI rootfs")
    if root == Path(root.anchor):
        raise SupervisorError(
            "invalid_oci_rootfs", "filesystem root cannot be used as the OCI rootfs"
        )
    repository = None
    if repo_root is not None:
        try:
            repository = Path(repo_root).resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise SupervisorError(
                "invalid_oci_rootfs", "supervisor repository is unavailable"
            ) from error
        if root == repository or root in repository.parents or repository in root.parents:
            raise SupervisorError(
                "invalid_oci_rootfs",
                "configured OCI rootfs must be outside the repository and disjoint from it",
            )
    try:
        manifest_entries: list[dict[str, Any]] = []
        observed, device, inode = _measure_rootfs_tree(root, _manifest_entries=manifest_entries)
    except OSError as error:
        raise SupervisorError(
            "invalid_oci_rootfs", "configured OCI rootfs cannot be verified"
        ) from error
    if observed != expected_sha256:
        raise SupervisorError("invalid_oci_rootfs", "configured OCI rootfs digest does not match")
    if not _is_rootfs_sha256(expected_closure_sha256):
        raise SupervisorError(
            "invalid_oci_rootfs", "configured OCI rootfs closure digest is required and invalid"
        )
    observed_closure_sha256 = hashlib.sha256(
        _canonical_rootfs_closure(manifest_entries)
    ).hexdigest()
    if observed_closure_sha256 != expected_closure_sha256:
        raise SupervisorError(
            "invalid_oci_rootfs", "configured OCI rootfs closure digest does not match"
        )
    pin = _TrustedRootfs(root, observed, device, inode, observed_closure_sha256)
    key = id(pin)

    def discard(reference: weakref.ReferenceType[Any]) -> None:
        current = _TRUSTED_ROOTFS_PINS.get(key)
        if current is not None and current[0] is reference:
            _TRUSTED_ROOTFS_PINS.pop(key, None)

    reference = weakref.ref(pin, discard)
    _TRUSTED_ROOTFS_PINS[key] = (
        reference,
        (root, observed, observed_closure_sha256, device, inode),
    )
    return pin


def _verify_trusted_rootfs(pin: _TrustedRootfs) -> Path:
    sealed = _TRUSTED_ROOTFS_PINS.get(id(pin)) if type(pin) is _TrustedRootfs else None
    if sealed is None or sealed[0]() is not pin:
        raise SupervisorError(
            "invalid_oci_rootfs", "OCI rootfs must come from trusted supervisor configuration"
        )
    expected_path, expected_digest, expected_closure, expected_device, expected_inode = sealed[1]
    if (
        pin.path != expected_path
        or pin.sha256 != expected_digest
        or pin.closure_sha256 != expected_closure
        or (pin.device, pin.inode) != (expected_device, expected_inode)
    ):
        raise SupervisorError("invalid_oci_rootfs", "OCI rootfs pin was modified")
    current = _plain_directory(
        expected_path, code="invalid_oci_rootfs", label="configured OCI rootfs"
    )
    try:
        manifest_entries: list[dict[str, Any]] = []
        observed, device, inode = _measure_rootfs_tree(current, _manifest_entries=manifest_entries)
    except OSError as error:
        raise SupervisorError(
            "invalid_oci_rootfs", "configured OCI rootfs cannot be verified"
        ) from error
    observed_closure = hashlib.sha256(_canonical_rootfs_closure(manifest_entries)).hexdigest()
    if (
        current != expected_path
        or device != expected_device
        or inode != expected_inode
        or observed != expected_digest
        or observed_closure != expected_closure
    ):
        raise SupervisorError(
            "invalid_oci_rootfs", "configured OCI rootfs no longer matches its pin"
        )
    return current


def _trusted_executable_identity(
    path: Path,
    *,
    descriptor: int | None = None,
) -> tuple[str, tuple[int, int, int, int, int, int, int]]:
    """Hash one root-owned, non-set-id executable through a no-follow descriptor.

    A supplied descriptor remains open for its caller. This lets an executor
    carry the exact validated inode into a child instead of reopening a checked
    path after validation.
    """

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

    owns_descriptor = descriptor is None
    if descriptor is None:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise SupervisorError(
                "invalid_oci_runtime", "runc executable cannot be opened safely"
            ) from error
    assert descriptor is not None
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
            or not before.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        ):
            raise SupervisorError(
                "invalid_oci_runtime",
                "runc executable must be root-owned, non-set-id, and non-group/world-writable",
            )
        if platform.system() == "Linux":
            getxattr = getattr(os, "getxattr", None)
            if getxattr is None:
                raise SupervisorError(
                    "invalid_oci_runtime", "Linux runc file-capability checks are unavailable"
                )
            try:
                getxattr(descriptor, "security.capability")
            except OSError as error:
                if error.errno not in {
                    errno.ENODATA,
                    getattr(errno, "ENOATTR", errno.ENODATA),
                }:
                    raise SupervisorError(
                        "invalid_oci_runtime", "Linux runc file-capability state is unknown"
                    ) from error
            else:
                raise SupervisorError(
                    "invalid_oci_runtime", "runc executable must not carry Linux file capabilities"
                )
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError as error:
        raise SupervisorError(
            "invalid_oci_runtime", "runc executable changed while being pinned"
        ) from error
    finally:
        if owns_descriptor:
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
    """Create a sealed handle for a root-owned, non-privilege-bearing executable.

    The resolved executable and every parent must be root-owned and not
    replaceable by group/other users; set-id bits and Linux file capabilities
    are rejected. Candidate-controlled executables are rejected even when they
    happen to be executable and outside the attempt workspace. The process-local
    pin is used by optional supervisor configuration, but no worker launch path
    consumes it.
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


def _open_verified_runc_executable(pin: _TrustedRuncExecutable) -> int:
    """Open the exact trusted runc inode and leave its verified FD held."""

    binary = _verify_trusted_runc_executable(pin)
    sealed = _TRUSTED_RUNC_PINS.get(id(pin)) if type(pin) is _TrustedRuncExecutable else None
    if sealed is None or sealed[0]() is not pin:
        raise SupervisorError(
            "invalid_oci_runtime", "runc executable must come from trusted supervisor configuration"
        )
    _root, expected_path, expected_digest, *expected_identity = sealed[1]
    if binary != expected_path:
        raise SupervisorError(
            "invalid_oci_runtime", "runc executable path no longer matches its pin"
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(binary, flags)
    except OSError as error:
        raise SupervisorError(
            "invalid_oci_runtime", "runc executable cannot be opened safely"
        ) from error
    try:
        digest, identity = _trusted_executable_identity(binary, descriptor=descriptor)
        if digest != expected_digest or identity != tuple(expected_identity):
            raise SupervisorError(
                "invalid_oci_runtime", "opened runc executable no longer matches its pin"
            )
        return descriptor
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _supports_runc_fd_exec() -> bool:
    """Whether this host exposes Linux execve-by-descriptor semantics."""

    return sys.platform.startswith("linux") and os.execve in os.supports_fd


def _probe_trusted_runc_version(pin: _TrustedRuncExecutable, expected_version: str) -> str:
    """Run the pinned runc version probe and require the configured release.

    This is a supervisor configuration check, not launch authorization. The
    later executor must still revalidate the pin at launch and execute the held
    file descriptor rather than trusting a path checked earlier.
    """

    if not _is_runc_release_version(expected_version):
        raise SupervisorError(
            "invalid_oci_runtime_version", "expected runc version must be an exact release version"
        )
    if not _supports_runc_fd_exec():
        raise SupervisorError(
            "invalid_oci_runtime_version",
            "held-descriptor runc probes require Linux fd-based execve support",
        )
    descriptor = _open_verified_runc_executable(pin)
    try:
        returncode, stdout = _run_bounded_command(
            [str(pin.path), "--version"],
            cwd="/",
            env={"LC_ALL": "C", "LANG": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            timeout_seconds=_RUNC_VERSION_PROBE_TIMEOUT_SECONDS,
            max_output_bytes=_RUNC_VERSION_PROBE_MAX_OUTPUT_BYTES,
            pass_fds=(descriptor,),
            exec_fd=descriptor,
        )
    except (
        OSError,
        TimeoutError,
        ValueError,
        UnicodeDecodeError,
        subprocess.TimeoutExpired,
    ) as error:
        raise SupervisorError(
            "invalid_oci_runtime_version", "trusted runc --version probe failed"
        ) from error
    finally:
        os.close(descriptor)
    if returncode != 0:
        raise SupervisorError(
            "invalid_oci_runtime_version", "trusted runc --version exited unsuccessfully"
        )
    lines = stdout.splitlines()
    match = _RUNC_VERSION_LINE.fullmatch(lines[0].strip() if lines else "")
    if match is None:
        raise SupervisorError(
            "invalid_oci_runtime_version", "trusted runc returned an unrecognized version"
        )
    observed_version = match.group(1)
    if (
        not _RUNC_RELEASE_VERSION.fullmatch(observed_version)
        or observed_version != expected_version
    ):
        raise SupervisorError(
            "invalid_oci_runtime_version", "trusted runc version does not match configuration"
        )
    return observed_version


def _kill_process_group(process: subprocess.Popen[bytes]) -> int:
    """Kill the private group and reap its direct child within a bounded wait."""

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as error:
        raise OSError("could not terminate the bounded command process group") from error
    try:
        return process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            return process.wait(timeout=1)
        except subprocess.TimeoutExpired as error:
            raise TimeoutError("bounded command child could not be reaped") from error


def _run_bounded_command(
    argv: Sequence[str],
    *,
    cwd: str,
    env: dict[str, str],
    timeout_seconds: float,
    max_output_bytes: int,
    pass_fds: Sequence[int] = (),
    exec_fd: int | None = None,
) -> tuple[int, str]:
    """Capture a small command result with a hard deadline and output ceiling.

    Both pipes are drained concurrently. The process starts a fresh session so
    timeout/output overflow can kill its process group, including descendants
    that inherit either pipe and would otherwise prevent EOF after the parent
    exits.
    """

    if os.name != "posix":
        raise OSError("bounded OCI runtime probes require POSIX process groups")
    if not argv:
        raise ValueError("bounded command requires a nonempty argument vector")
    inherited_fds = tuple(pass_fds)
    if any(type(descriptor) is not int or descriptor < 3 for descriptor in inherited_fds) or len(
        set(inherited_fds)
    ) != len(inherited_fds):
        raise ValueError(
            "bounded command file descriptors must be unique open descriptors above stdio"
        )
    for descriptor in inherited_fds:
        os.fstat(descriptor)
    if exec_fd is not None and (
        type(exec_fd) is not int or exec_fd not in inherited_fds or not _supports_runc_fd_exec()
    ):
        raise ValueError("bounded command exec_fd must be an inherited Linux executable descriptor")
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    status_reader: int | None = None
    status_writer: int | None = None
    cleanup_started = False
    try:
        # Allocate probe state before launching the child. Any setup that must
        # happen after Popen stays under this same cleanup-protected try block.
        selector = selectors.DefaultSelector()
        stdout = bytearray()
        stderr = bytearray()
        status = bytearray()
        status_reader, status_writer = os.pipe()
        os.set_blocking(status_reader, False)
        selector.register(status_reader, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout_seconds
        if not sys.executable:
            raise OSError("bounded command guardian requires the current Python executable")
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-S",
                "-c",
                _BOUNDED_COMMAND_GUARDIAN,
                str(timeout_seconds),
                str(status_writer),
                str(len(inherited_fds)),
                "" if exec_fd is None else str(exec_fd),
                *(str(descriptor) for descriptor in inherited_fds),
                *argv,
            ],
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=(status_writer, *inherited_fds),
            start_new_session=True,
        )
        parent_status_writer = status_writer
        status_writer = None
        os.close(parent_status_writer)
        if process.stdout is None or process.stderr is None:
            raise OSError("bounded command pipes were not created")
        streams = {process.stdout: stdout, process.stderr: stderr}
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("bounded command exceeded its deadline")
            for key, _ in selector.select(remaining):
                try:
                    chunk = os.read(key.fd, 4096)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.fileobj == status_reader:
                    if len(status) + len(chunk) > 16:
                        raise ValueError("bounded command guardian returned oversized status")
                    status.extend(chunk)
                    continue
                captured = streams[key.fileobj]
                if len(stdout) + len(stderr) + len(chunk) > max_output_bytes:
                    raise ValueError("bounded command exceeded its output limit")
                captured.extend(chunk)
        if deadline - time.monotonic() <= 0:
            raise TimeoutError("bounded command exceeded its deadline")
        # The guardian stays alive after the command exits, keeping its process
        # group ID reserved while the result and all output pipes drain. Killing
        # the group now also removes descendants that closed or redirected both
        # output streams before their parent exited.
        decoded_stdout = stdout.decode("utf-8")
        if not status:
            raise OSError("bounded command guardian omitted its exit status")
        try:
            returncode = int(status.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as error:
            raise OSError("bounded command guardian returned an invalid exit status") from error
        cleanup_started = True
        _kill_process_group(process)
        return returncode, decoded_stdout
    except BaseException:
        if process is not None and not cleanup_started:
            cleanup_started = True
            _kill_process_group(process)
        raise
    finally:
        if selector is not None:
            selector.close()
        if process is not None:
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        if status_reader is not None:
            os.close(status_reader)
        if status_writer is not None:
            os.close(status_writer)


def _is_runc_release_version(value: Any) -> bool:
    """Whether a configured version is canonical stable major.minor.patch."""

    return isinstance(value, str) and _RUNC_RELEASE_VERSION.fullmatch(value) is not None


def build_oci_worker_config(
    bundle_root: str | Path,
    workspace_snapshot: Snapshot,
    command: Sequence[str],
    *,
    rootfs_pin: _TrustedRootfs,
    container_id: str,
    memory_bytes: int,
    pids_limit: int,
    cpu_quota_us: int,
    cpu_period_us: int = 100_000,
    tmpfs_bytes: int = _DEFAULT_TMPFS_BYTES,
    home_bytes: int = _DEFAULT_HOME_BYTES,
    private_git: bool = False,
    host_uid: int | None = None,
    host_gid: int | None = None,
) -> dict[str, Any]:
    """Build an OCI 1.2 config with one mutable workspace and no host secrets.

    rootfs_pin must come from strict supervisor configuration and bind an
    operator-selected rootfs tree digest and closure digest. The bundle's
    rootfs must either be that exact pinned directory or have the same tree and
    closure digests. These digests prove integrity against the operator's pins,
    not that the image has been audited.
    workspace_snapshot must be a separate
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
    trusted_rootfs = _verify_trusted_rootfs(rootfs_pin)
    rootfs = bundle / "rootfs"
    try:
        rootfs_info = rootfs.lstat()
    except OSError as error:
        raise SupervisorError("invalid_oci_rootfs", "OCI bundle rootfs is unavailable") from error
    if stat.S_ISLNK(rootfs_info.st_mode) or not stat.S_ISDIR(rootfs_info.st_mode):
        raise SupervisorError("invalid_oci_rootfs", "OCI bundle rootfs must be a real directory")
    if rootfs.resolve(strict=True) != trusted_rootfs or (
        rootfs_info.st_dev,
        rootfs_info.st_ino,
    ) != (rootfs_pin.device, rootfs_pin.inode):
        bundle_manifest = rootfs_tree_manifest(rootfs)
        if (
            bundle_manifest["rootfs_sha256"] != rootfs_pin.sha256
            or bundle_manifest["closure_sha256"] != rootfs_pin.closure_sha256
        ):
            raise SupervisorError(
                "invalid_oci_rootfs",
                "OCI bundle rootfs does not match the configured rootfs and closure pins",
            )
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
    if type(private_git) is not bool:
        raise SupervisorError("invalid_oci_worker_policy", "private_git must be a boolean")
    private_git_paths: dict[str, str] = {}
    if not isinstance(container_id, str) or not _CONTAINER_ID.fullmatch(container_id):
        raise SupervisorError("invalid_oci_worker_policy", "OCI container ID is invalid")
    args = _validate_command(command)
    _validate_rootfs_executable(rootfs, args[0])
    _validate_rootfs_executable(rootfs, "/bin/sh")
    if private_git:
        for executable, label, candidates in (
            ("git", "Git", ("/usr/bin/git", "/bin/git")),
            ("mkdir", "mkdir", ("/usr/bin/mkdir", "/bin/mkdir")),
            ("rmdir", "rmdir", ("/usr/bin/rmdir", "/bin/rmdir")),
        ):
            selected_path = None
            for candidate in candidates:
                try:
                    _validate_rootfs_executable(rootfs, candidate)
                except SupervisorError:
                    continue
                selected_path = candidate
                break
            if selected_path is None:
                raise SupervisorError(
                    "invalid_oci_executable",
                    f"private Git mode requires an executable {label} in the pinned rootfs",
                )
            private_git_paths[executable] = selected_path
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
    if private_git:
        env.extend(
            (
                "GIT_CONFIG_NOSYSTEM=1",
                "GIT_CONFIG_GLOBAL=/dev/null",
                "GIT_ATTR_NOSYSTEM=1",
                "GIT_TERMINAL_PROMPT=0",
                "GIT_CEILING_DIRECTORIES=/workspace",
            )
        )
    namespace_types = ("user", "pid", "mount", "ipc", "uts", "cgroup", "network")
    launch_gate_script = _LAUNCH_GATE_SCRIPT
    if private_git:
        launch_gate_script = _render_private_git_launch_script(
            git_path=private_git_paths["git"],
            mkdir_path=private_git_paths["mkdir"],
            rmdir_path=private_git_paths["rmdir"],
        )
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
                launch_gate_script,
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
    caller must use :func:`spawn_pinned_runc` to map the read end to fd 3,
    sanitize runc's activation environment, and keep its paired writer private
    until it has durably authorized launch.
    ``executable`` must be a process-local pin minted by
    ``_pin_trusted_runc_executable``. Its root-owned file identity and SHA-256
    are rechecked here; a caller-supplied path or forged pin is refused. This
    helper does not verify the desired runc version or prove that runc applies
    policy.
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


@dataclass
class RuncLaunchHandle:
    """One held runc client process and its private OCI-init release gate.

    ``process.pid`` remains the runc client PID after the launcher execs the
    pinned binary. The handle intentionally has no automatic-release behavior:
    the caller must persist and attest launch state before calling
    :meth:`release_gate`. The lock linearizes release against cancellation:
    whichever operation acquires it first determines whether the gate is
    released or closed. Closing an unreleased gate denies candidate exec.
    """

    process: subprocess.Popen[bytes]
    _gate_writer: int | None
    _gate_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def release_gate(self) -> None:
        """Authorize the already-attested OCI init to execute its command once."""

        with self._gate_lock:
            descriptor = self._gate_writer
            if descriptor is None:
                raise SupervisorError(
                    "sandbox_launch_gate_closed", "OCI init launch gate is already closed"
                )
            self._gate_writer = None
            try:
                if os.write(descriptor, b"go\n") != 3:
                    raise OSError("short write to the OCI init launch gate")
            except OSError as error:
                raise SupervisorError(
                    "sandbox_launch_gate_failed",
                    "OCI init launch gate could not be released",
                ) from error
            finally:
                os.close(descriptor)

    def close_gate(self) -> None:
        """Close an unreleased gate so the OCI init's fixed trampoline exits."""

        with self._gate_lock:
            descriptor = self._gate_writer
            self._gate_writer = None
            if descriptor is not None:
                os.close(descriptor)

    def __del__(self) -> None:
        try:
            self.close_gate()
        except OSError:
            pass


def _runc_client_environment() -> dict[str, str]:
    """Build the small host-side environment needed by rootless systemd runc."""

    runtime_dir = f"/run/user/{os.geteuid()}"
    return {
        "HOME": str(Path.home()),
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "XDG_RUNTIME_DIR": runtime_dir,
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime_dir}/bus",
    }


def _reap_failed_runc_launch(process: subprocess.Popen[bytes]) -> None:
    """Bound launch-failure cleanup and report when the client cannot be reaped."""

    try:
        _kill_process_group(process)
        return
    except BaseException:
        if process.poll() is not None:
            return
    try:
        process.kill()
    except OSError:
        # The process may have exited between poll() and kill(). A bounded
        # wait below distinguishes that race from an unreaped live child.
        pass
    try:
        process.wait(timeout=1)
    except BaseException as error:
        raise SupervisorError(
            "sandbox_launch_cleanup_unverified",
            f"runc launcher pid {process.pid} could not be reaped after launch failure",
        ) from error


def spawn_pinned_runc(
    executable: _TrustedRuncExecutable,
    argv: Sequence[str],
    *,
    stdout: Any = subprocess.DEVNULL,
    stderr: Any = subprocess.DEVNULL,
) -> RuncLaunchHandle:
    """Start pinned runc by held FD with exactly one inherited fd-3 launch gate.

    The rootless supervisor opens and revalidates the configured runc inode,
    then a tiny isolated Python launcher uses ``execve(fd, ...)`` so a later
    pathname replacement cannot substitute another runtime. Only the three
    protocol FDs are inherited by that launcher; the runc executable FD is
    close-on-exec, and fd 3 is the sole descriptor intentionally preserved by
    the OCI runtime. Stdin is closed and runc receives a fixed environment with
    no provider, Codex, SSH-agent, or ACP runner credentials.

    This starts the runtime client but does not reserve an attempt, verify its
    version, attest the resulting namespaces/cgroups, or authorize release of
    the returned gate. The caller must keep the attempt fenced until separate
    runtime and cleanup evidence is durably verified. If payload delivery begins
    but this function cannot return the handle, it raises
    ``sandbox_launch_submission_unverified``; the caller must retain attempt
    ownership and reconcile the exact runtime state before releasing its fence.
    """

    if os.geteuid() == 0:
        raise SupervisorError(
            "invalid_oci_worker_policy", "OCI worker runtime must be invoked by a non-root caller"
        )
    if not _supports_runc_fd_exec() or not hasattr(os, "pipe2"):
        raise SupervisorError(
            "invalid_oci_runtime",
            "pinned runc launch requires Linux fd-based exec and close-on-exec pipes",
        )
    binary = _verify_trusted_runc_executable(executable)
    if isinstance(argv, (str, bytes)):
        raise SupervisorError("invalid_oci_command", "runc command must be an argument sequence")
    try:
        command = tuple(argv)
    except TypeError as error:
        raise SupervisorError(
            "invalid_oci_command", "runc command must be an argument sequence"
        ) from error
    if (
        not command
        or command[0] != str(binary)
        or any(not isinstance(value, str) or not value or "\x00" in value for value in command)
    ):
        raise SupervisorError(
            "invalid_oci_command", "runc argv must begin with the exact pinned executable path"
        )
    if sum(len(os.fsencode(value)) + 1 for value in command) > _MAX_RUNC_LAUNCH_PAYLOAD_BYTES:
        raise SupervisorError("invalid_oci_command", "runc argument payload exceeds its byte limit")

    runtime_environment = _runc_client_environment()
    payload = (
        json.dumps(
            {"argv": command, "env": runtime_environment},
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        + b"\n"
    )
    if len(payload) > _MAX_RUNC_LAUNCH_PAYLOAD_BYTES:
        raise SupervisorError("invalid_oci_command", "runc launch payload exceeds its byte limit")

    import fcntl

    opened_descriptor = _open_verified_runc_executable(executable)
    runc_descriptor = -1
    start_read = start_write = gate_read = gate_write = -1
    process: subprocess.Popen[bytes] | None = None
    launch_payload_may_have_been_delivered = False
    try:
        runc_descriptor = fcntl.fcntl(opened_descriptor, fcntl.F_DUPFD_CLOEXEC, 10)
        descriptor_to_close = opened_descriptor
        opened_descriptor = -1
        os.close(descriptor_to_close)
        start_read, start_write = os.pipe2(os.O_CLOEXEC)
        gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
        launcher_environment = {
            "HOME": runtime_environment["HOME"],
            "PATH": runtime_environment["PATH"],
            "LANG": "C",
            "LC_ALL": "C",
        }
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-S",
                "-c",
                _RUNC_FD_LAUNCHER,
                str(start_read),
                str(gate_read),
                str(runc_descriptor),
            ],
            cwd="/",
            env=launcher_environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            close_fds=True,
            pass_fds=(start_read, gate_read, runc_descriptor),
            start_new_session=True,
        )
        descriptor_to_close = start_read
        start_read = -1
        os.close(descriptor_to_close)
        descriptor_to_close = gate_read
        gate_read = -1
        os.close(descriptor_to_close)
        descriptor_to_close = runc_descriptor
        runc_descriptor = -1
        os.close(descriptor_to_close)

        remaining = memoryview(payload)
        while remaining:
            # Treat any attempted write conservatively: interruption after a
            # successful write but before updating local state must not hide a
            # possible runtime submission from the caller.
            launch_payload_may_have_been_delivered = True
            written = os.write(start_write, remaining)
            if written <= 0:
                raise OSError("could not write the bounded runc launch payload")
            remaining = remaining[written:]
        descriptor_to_close = start_write
        start_write = -1
        os.close(descriptor_to_close)
        handle = RuncLaunchHandle(process=process, _gate_writer=gate_write)
        gate_write = -1
        return handle
    except BaseException as launch_error:
        cleanup_error: BaseException | None = None
        if gate_write >= 0:
            descriptor_to_close = gate_write
            gate_write = -1
            try:
                os.close(descriptor_to_close)
            except BaseException as error:
                cleanup_error = error
        if process is not None:
            try:
                _reap_failed_runc_launch(process)
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
        if launch_payload_may_have_been_delivered:
            cleanup_status = (
                "runc client cleanup is also unverified"
                if cleanup_error is not None
                else "runc client was reaped"
            )
            submission_error = SupervisorError(
                "sandbox_launch_submission_unverified",
                "runc launch payload may have been submitted; "
                f"client_pid={process.pid if process is not None else 'unknown'}; "
                f"{cleanup_status}; owning attempt must stay fenced until the "
                "exact runtime state is independently reconciled",
            )
            raise submission_error from (cleanup_error or launch_error)
        if cleanup_error is not None:
            raise cleanup_error from launch_error
        raise
    finally:
        descriptors_to_close = (
            opened_descriptor,
            runc_descriptor,
            start_read,
            start_write,
            gate_read,
        )
        opened_descriptor = runc_descriptor = start_read = start_write = gate_read = -1
        for descriptor in descriptors_to_close:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
