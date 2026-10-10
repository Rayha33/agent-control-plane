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
worker launch is enabled. The public low-level runc API places the sealed config
and a verified copy of the rootfs in private, read-only tmpfs mounts addressed
through an inherited bundle FD. The rootfs copy is bounded and rejects
unsupported ownership or extended attributes. State and workspace directory
objects are pinned through inherited descriptors to prevent launch-time path
replacement, but remain host-backed and are not an outer worker isolation
boundary. The helper binds the workspace descriptor into a private tmpfs anchor
inside its mount namespace so runc's container-init child does not depend on
inheriting the supervisor's FD. Lifecycle journal ownership, cleanup, and result
import remain subject to separate gates.
"""

from __future__ import annotations

import array
import errno
import hashlib
import json
import os
import platform
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import weakref
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
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
_MAX_ROOTFS_SNAPSHOT_BYTES = 256 * 1024 * 1024
_ROOTFS_SNAPSHOT_OVERHEAD_BYTES = 4 * 1024 * 1024


def _oci_worker_systemd_slice(container_id: str) -> str:
    """Return the deterministic, per-container user slice for a rootless runc scope."""

    if not isinstance(container_id, str) or _CONTAINER_ID.fullmatch(container_id) is None:
        raise SupervisorError("invalid_oci_worker_policy", "OCI container ID is invalid")
    digest = hashlib.sha256(container_id.encode("ascii")).hexdigest()
    return f"user-acp-{digest}.slice"


def _oci_worker_cgroups_path(container_id: str) -> str:
    """Bind a runc scope to a unique parent slice, never the shared user.slice."""

    return f"{_oci_worker_systemd_slice(container_id)}:acp:{container_id}"


_MAX_ROOTFS_PATH_BYTES = 4096
_MAX_ROOTFS_DEPTH = 256
_ROOTFS_CLOSURE_SCHEMA = "acp-oci-rootfs-closure-v1"
_ST_RDONLY = 1
_MAX_MOUNTINFO_BYTES = 16 * 1024 * 1024
_DEFAULT_TMPFS_BYTES = 64 * 1024 * 1024
_DEFAULT_HOME_BYTES = 16 * 1024 * 1024
_DEFAULT_DEV_TMPFS_BYTES = 1 * 1024 * 1024
_DEFAULT_DEV_TMPFS_INODES = 64
_MAX_RUNC_LAUNCH_PAYLOAD_BYTES = 64 * 1024
_RUNC_NAMESPACE_SETUP_TIMEOUT_SECONDS = 5.0
_MOUNT_DESTINATIONS = ("/proc", "/dev", "/workspace", "/tmp", "/home/agent")
_RUNC_RECURSIVE_PRIVATE_VERSION = "1.3.5"
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
_RUNC_PRIVATE_BUNDLE_LAUNCHER = r"""
import array
import ctypes
import errno
import json
import os
import resource
import socket
import stat
import sys

start_fd, status_fd, map_ack_fd, exec_ack_fd, gate_fd, runc_fd, bundle_fd, rootfs_fd, snapshot_socket_fd = (
    int(value) for value in sys.argv[1:10]
)
CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000
MS_PRIVATE = 0x00040000
MS_REC = 0x00004000
ST_RDONLY = 1
AT_EMPTY_PATH = 0x1000
AT_FDCWD = -100
OPEN_TREE_CLONE = 0x00000001
OPEN_TREE_CLOEXEC = 0x00080000
FSOPEN_CLOEXEC = 0x00000001
FSCONFIG_SET_STRING = 1
FSCONFIG_CMD_CREATE = 6
FSMOUNT_CLOEXEC = 0x00000001
MOVE_MOUNT_F_EMPTY_PATH = 0x00000004
MOVE_MOUNT_T_EMPTY_PATH = 0x00000040
MOUNT_ATTR_RDONLY = 0x00000001
MOUNT_ATTR_NOSUID = 0x00000002
MOUNT_ATTR_NODEV = 0x00000004
MOUNT_ATTR_NOEXEC = 0x00000008
os.set_inheritable(status_fd, False)
os.umask(0o077)
phase = b"0"

class _MountAttr(ctypes.Structure):
    _fields_ = [
        ("attr_set", ctypes.c_uint64),
        ("attr_clr", ctypes.c_uint64),
        ("propagation", ctypes.c_uint64),
        ("userns_fd", ctypes.c_uint64),
    ]

def _message(value):
    try:
        os.write(status_fd, value)
    except BaseException:
        pass

def _fail(error_number=0, detail=b""):
    try:
        encoded_errno = max(0, min(int(error_number), 255))
    except BaseException:
        encoded_errno = 255
    if isinstance(detail, str):
        detail = detail.encode("utf-8", errors="replace")
    _message(b"F" + phase + bytes((encoded_errno,)) + detail[:128])
    os._exit(125)

def _read_exact(descriptor, expected):
    result = bytearray()
    while len(result) < len(expected):
        part = os.read(descriptor, len(expected) - len(result))
        if not part:
            return False
        result.extend(part)
    return bytes(result) == expected

def _unshare(flags):
    libc = ctypes.CDLL(None, use_errno=True)
    unshare = libc.unshare
    unshare.argtypes = [ctypes.c_int]
    unshare.restype = ctypes.c_int
    if unshare(flags) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))

def _set_nondumpable():
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    if prctl(4, 0, 0, 0, 0) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), "PR_SET_DUMPABLE")

def _make_mounts_private():
    libc = ctypes.CDLL(None, use_errno=True)
    mount = libc.mount
    mount.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_ulong,
        ctypes.c_char_p,
    ]
    mount.restype = ctypes.c_int
    ctypes.set_errno(0)
    if mount(None, b"/", None, MS_REC | MS_PRIVATE, None) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), "make mount namespace private")

def _mount_api():
    libc = ctypes.CDLL(None, use_errno=True)
    fsopen = libc.fsopen
    fsopen.argtypes = [ctypes.c_char_p, ctypes.c_uint]
    fsopen.restype = ctypes.c_int
    fsconfig = libc.fsconfig
    fsconfig.argtypes = [
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_int,
    ]
    fsconfig.restype = ctypes.c_int
    fsmount = libc.fsmount
    fsmount.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint]
    fsmount.restype = ctypes.c_int
    move_mount = libc.move_mount
    move_mount.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    move_mount.restype = ctypes.c_int
    open_tree = libc.open_tree
    open_tree.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    open_tree.restype = ctypes.c_int
    mount_setattr = libc.mount_setattr
    mount_setattr.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
        ctypes.POINTER(_MountAttr),
        ctypes.c_size_t,
    ]
    mount_setattr.restype = ctypes.c_int
    return fsopen, fsconfig, fsmount, move_mount, open_tree, mount_setattr

def _check_mount_call(result, label):
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), label)

def _check_mount_fd(descriptor, label):
    if descriptor < 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), label)
    return descriptor

def _set_mount_attributes(mount_setattr, descriptor, attributes):
    mount_attr = _MountAttr(attributes, 0, 0, 0)
    _check_mount_call(
        mount_setattr(
            descriptor,
            b"",
            AT_EMPTY_PATH,
            ctypes.byref(mount_attr),
            ctypes.sizeof(mount_attr),
        ),
        "mount_setattr",
    )

def _source_identity(info):
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

def _check_source_entry(info, source_device, *, regular=False):
    if (
        info.st_dev != source_device
        or info.st_uid != payload["uid"]
        or info.st_gid != payload["gid"]
        or info.st_mode & (stat.S_ISUID | stat.S_ISGID)
        or (regular and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1))
    ):
        raise OSError("rootfs snapshot source has unsupported type, owner, or metadata")

def _check_no_xattrs(descriptor):
    try:
        if os.listxattr(descriptor):
            raise OSError("rootfs snapshot does not copy extended attributes")
    except (AttributeError, OSError) as error:
        raise OSError("rootfs extended attributes cannot be verified") from error

def _link_stays_inside(relative_path, target):
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

def _copy_rootfs_tree(source_root_fd, destination_root_fd, source_device):
    counts = {"entries": 1, "bytes": 0}
    root_info = os.fstat(source_root_fd)
    _check_source_entry(root_info, source_device)
    _check_no_xattrs(source_root_fd)

    def copy_directory(source_fd, destination_fd, prefix, depth):
        if depth > 256:
            raise OSError("rootfs snapshot exceeds its depth limit")
        before = os.fstat(source_fd)
        with os.scandir(source_fd) as iterator:
            names = sorted((entry.name for entry in iterator), key=os.fsencode)
        for name in names:
            counts["entries"] += 1
            if counts["entries"] > payload["rootfs_entry_count"]:
                raise OSError("rootfs changed beyond its reserved entry count")
            name_bytes = os.fsencode(name)
            relative_path = name_bytes if not prefix else prefix + b"/" + name_bytes
            if len(relative_path) > 4096:
                raise OSError("rootfs snapshot path exceeds its limit")
            info = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
            _check_source_entry(info, source_device)
            if stat.S_ISDIR(info.st_mode):
                os.mkdir(name, 0o700, dir_fd=destination_fd)
                source_child = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=source_fd,
                )
                destination_child = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=destination_fd,
                )
                try:
                    opened = os.fstat(source_child)
                    if _source_identity(info) != _source_identity(opened):
                        raise OSError("rootfs directory changed during snapshot")
                    _check_no_xattrs(source_child)
                    copy_directory(source_child, destination_child, relative_path, depth + 1)
                    if _source_identity(opened) != _source_identity(os.fstat(source_child)):
                        raise OSError("rootfs directory changed during snapshot")
                    os.fchmod(destination_child, stat.S_IMODE(info.st_mode))
                finally:
                    os.close(source_child)
                    os.close(destination_child)
            elif stat.S_ISREG(info.st_mode):
                _check_source_entry(info, source_device, regular=True)
                counts["bytes"] += info.st_size
                if counts["bytes"] > payload["rootfs_bytes"]:
                    raise OSError("rootfs changed beyond its reserved byte count")
                source_file = os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                    dir_fd=source_fd,
                )
                destination_file = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=destination_fd,
                )
                try:
                    opened = os.fstat(source_file)
                    if _source_identity(info) != _source_identity(opened):
                        raise OSError("rootfs file changed during snapshot")
                    _check_no_xattrs(source_file)
                    size = 0
                    while True:
                        block = os.read(source_file, 1024 * 1024)
                        if not block:
                            break
                        size += len(block)
                        offset = 0
                        while offset < len(block):
                            offset += os.write(destination_file, block[offset:])
                    if size != info.st_size or _source_identity(opened) != _source_identity(
                        os.fstat(source_file)
                    ):
                        raise OSError("rootfs file changed during snapshot")
                    os.fchmod(destination_file, stat.S_IMODE(info.st_mode))
                    os.fsync(destination_file)
                finally:
                    os.close(source_file)
                    os.close(destination_file)
            elif stat.S_ISLNK(info.st_mode):
                link_path = f"/proc/self/fd/{source_fd}/{name}"
                if os.listxattr(link_path, follow_symlinks=False):
                    raise OSError("rootfs symlink has unsupported extended attributes")
                target = os.fsencode(os.readlink(name, dir_fd=source_fd))
                after = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
                if (
                    _source_identity(info) != _source_identity(after)
                    or not _link_stays_inside(relative_path, target)
                ):
                    raise OSError("rootfs symlink changed or escapes during snapshot")
                counts["bytes"] += len(target)
                if counts["bytes"] > payload["rootfs_bytes"]:
                    raise OSError("rootfs changed beyond its reserved byte count")
                os.symlink(os.fsdecode(target), name, dir_fd=destination_fd)
            else:
                raise OSError("rootfs snapshot encountered a special file")
        if _source_identity(before) != _source_identity(os.fstat(source_fd)):
            raise OSError("rootfs directory changed during snapshot")

    copy_directory(source_root_fd, destination_root_fd, b"", 0)
    if (
        counts["entries"] != payload["rootfs_entry_count"]
        or counts["bytes"] != payload["rootfs_bytes"]
    ):
        raise OSError("rootfs changed while its private snapshot was created")
    os.fchmod(destination_root_fd, stat.S_IMODE(root_info.st_mode))

try:
    phase = b"1"
    payload_bytes = bytearray()
    while len(payload_bytes) <= 65536:
        chunk = os.read(start_fd, 65537 - len(payload_bytes))
        if not chunk:
            break
        payload_bytes.extend(chunk)
    os.close(start_fd)
    if not payload_bytes.endswith(b"\n") or len(payload_bytes) > 65536:
        _fail()
    payload = json.loads(payload_bytes)
    if (
        not isinstance(payload, dict)
        or set(payload)
        != {
            "argv",
            "env",
            "config",
            "bundle",
            "bundle_fd_path",
            "bundle_device",
            "bundle_inode",
            "rootfs_device",
            "rootfs_inode",
            "state_fd",
            "state_device",
            "state_inode",
            "workspace_fd",
            "workspace_device",
            "workspace_inode",
            "workspace_path",
            "workspace_source",
            "rootfs_entry_count",
            "rootfs_bytes",
            "rootfs_snapshot_limit_bytes",
            "uid",
            "gid",
        }
        or not isinstance(payload["argv"], list)
        or not isinstance(payload["env"], dict)
        or not isinstance(payload["config"], str)
        or not isinstance(payload["bundle"], str)
        or not isinstance(payload["bundle_fd_path"], str)
        or type(payload["bundle_device"]) is not int
        or type(payload["bundle_inode"]) is not int
        or type(payload["rootfs_device"]) is not int
        or type(payload["rootfs_inode"]) is not int
        or type(payload["state_fd"]) is not int
        or type(payload["state_device"]) is not int
        or type(payload["state_inode"]) is not int
        or type(payload["workspace_fd"]) is not int
        or type(payload["workspace_device"]) is not int
        or type(payload["workspace_inode"]) is not int
        or not isinstance(payload["workspace_path"], str)
        or not payload["workspace_path"].startswith("/")
        or "\x00" in payload["workspace_path"]
        or not isinstance(payload["workspace_source"], str)
        or payload["state_fd"] in {bundle_fd, rootfs_fd, payload["workspace_fd"]}
        or payload["workspace_fd"] in {bundle_fd, rootfs_fd}
        or payload["bundle_fd_path"] != f"/proc/self/fd/{bundle_fd}"
        or type(payload["rootfs_entry_count"]) is not int
        or payload["rootfs_entry_count"] < 1
        or payload["rootfs_entry_count"] > 200001
        or type(payload["rootfs_bytes"]) is not int
        or payload["rootfs_bytes"] < 0
        or type(payload["rootfs_snapshot_limit_bytes"]) is not int
        or payload["rootfs_snapshot_limit_bytes"] < payload["rootfs_bytes"]
        or payload["rootfs_snapshot_limit_bytes"] > 268435456
        or type(payload["uid"]) is not int
        or type(payload["gid"]) is not int
    ):
        _fail()
    command = payload["argv"]
    if (
        any(not isinstance(value, str) or not value or "\x00" in value for value in command)
        or sum(len(os.fsencode(value)) + 1 for value in command) > 65536
        or len(command) != 13
        or command[1] != "--root"
        or command[3:5] != ["--systemd-cgroup", "run"]
        or command[5] != "--bundle"
        or command[7] != "--pid-file"
        or command[9:11] != ["--preserve-fds", "1"]
        or command[11] != "--keep"
    ):
        _fail()
    container_id = command[12]
    if (
        not container_id
        or len(container_id) > 64
        or container_id[0] not in "abcdefghijklmnopqrstuvwxyz0123456789"
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_.-" for character in container_id)
        or payload["workspace_source"] != f"/dev/shm/acp-{container_id}-workspace"
    ):
        _fail()

    # Map the caller's own host identity 1:1 in a new user namespace. This
    # gives only this helper a private mount namespace; it does not map host
    # root or change the OCI policy's existing caller-identity mapping.
    phase = b"2"
    _unshare(CLONE_NEWUSER)
    _message(b"U")
    if not _read_exact(map_ack_fd, b"M"):
        _fail()
    phase = b"3"
    with open("/proc/self/uid_map", "rb") as stream:
        uid_map = stream.read().split()
    with open("/proc/self/gid_map", "rb") as stream:
        gid_map = stream.read().split()
    if uid_map != [str(payload["uid"]).encode(), str(payload["uid"]).encode(), b"1"]:
        _fail()
    if gid_map != [str(payload["gid"]).encode(), str(payload["gid"]).encode(), b"1"]:
        _fail()
    if os.getuid() != payload["uid"] or os.getgid() != payload["gid"]:
        _fail()
    _set_nondumpable()

    for descriptor, device, inode in (
        (payload["state_fd"], payload["state_device"], payload["state_inode"]),
        (payload["workspace_fd"], payload["workspace_device"], payload["workspace_inode"]),
    ):
        descriptor_info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(descriptor_info.st_mode)
            or (descriptor_info.st_dev, descriptor_info.st_ino) != (device, inode)
        ):
            _fail()

    phase = b"4"
    _unshare(CLONE_NEWNS)
    phase = b"5"
    _make_mounts_private()
    phase = b"6"
    try:
        fsopen, fsconfig, fsmount, move_mount, open_tree, mount_setattr = _mount_api()
    except AttributeError as error:
        raise OSError(errno.ENOSYS, "descriptor-based mount API is unavailable") from error

    # Give runc's container-init child a stable workspace source path without
    # relying on that child inheriting the supervisor's descriptor. The private
    # tmpfs covers root-owned /dev/shm only in this mount namespace; a same-UID
    # host process cannot replace its anchor through the host's /dev/shm.
    workspace_anchor_mount_target_fd = os.open(
        "/dev/shm",
        getattr(os, "O_PATH", os.O_RDONLY)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    workspace_anchor_mount_before = os.fstat(workspace_anchor_mount_target_fd)
    if not stat.S_ISDIR(workspace_anchor_mount_before.st_mode):
        _fail()
    workspace_anchor_filesystem_fd = _check_mount_fd(
        fsopen(b"tmpfs", FSOPEN_CLOEXEC), "fsopen(workspace anchor tmpfs)"
    )
    _check_mount_call(
        fsconfig(
            workspace_anchor_filesystem_fd,
            FSCONFIG_SET_STRING,
            b"size",
            b"1m",
            0,
        ),
        "workspace anchor tmpfs size",
    )
    _check_mount_call(
        fsconfig(
            workspace_anchor_filesystem_fd,
            FSCONFIG_SET_STRING,
            b"nr_inodes",
            b"4",
            0,
        ),
        "workspace anchor tmpfs inode limit",
    )
    _check_mount_call(
        fsconfig(
            workspace_anchor_filesystem_fd,
            FSCONFIG_SET_STRING,
            b"mode",
            b"0700",
            0,
        ),
        "workspace anchor tmpfs mode",
    )
    _check_mount_call(
        fsconfig(workspace_anchor_filesystem_fd, FSCONFIG_CMD_CREATE, None, None, 0),
        "workspace anchor tmpfs create",
    )
    workspace_anchor_mount_fd = _check_mount_fd(
        fsmount(
            workspace_anchor_filesystem_fd,
            FSMOUNT_CLOEXEC,
            MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC,
        ),
        "fsmount(workspace anchor tmpfs)",
    )
    os.close(workspace_anchor_filesystem_fd)
    _check_mount_call(
        move_mount(
            workspace_anchor_mount_fd,
            b"",
            workspace_anchor_mount_target_fd,
            b"",
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        ),
        "attach private workspace anchor tmpfs",
    )
    os.close(workspace_anchor_mount_fd)
    os.close(workspace_anchor_mount_target_fd)
    private_shm_fd = os.open(
        "/dev/shm",
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    private_shm_info = os.fstat(private_shm_fd)
    if (
        not stat.S_ISDIR(private_shm_info.st_mode)
        or private_shm_info.st_uid != payload["uid"]
        or stat.S_IMODE(private_shm_info.st_mode) != 0o700
        or (private_shm_info.st_dev, private_shm_info.st_ino)
        == (workspace_anchor_mount_before.st_dev, workspace_anchor_mount_before.st_ino)
    ):
        _fail()
    workspace_anchor_name = payload["workspace_source"].rsplit("/", 1)[-1]
    os.mkdir(workspace_anchor_name, 0o700, dir_fd=private_shm_fd)
    workspace_anchor_fd = os.open(
        workspace_anchor_name,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=private_shm_fd,
    )
    os.close(private_shm_fd)
    # Let the parent run a deterministic same-UID path-replacement probe at
    # the last point before open_tree resolves the host pathname. Production
    # callers only acknowledge this bounded setup stage without a callback.
    _message(b"W")
    if not _read_exact(map_ack_fd, b"A"):
        _fail()
    os.close(map_ack_fd)
    # mount(2) cannot attach a bind mount by an inherited /proc/self/fd path:
    # that magic-link source is rejected with EINVAL on supported Linux hosts.
    # open_tree must therefore resolve the captured pathname in this private
    # namespace. Its detached mount pins the selected object; comparing that
    # mount root to the inherited descriptor closes the pathname race before
    # it can be attached anywhere.
    workspace_mount_fd = _check_mount_fd(
        open_tree(
            AT_FDCWD,
            payload["workspace_path"].encode("utf-8"),
            OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC,
        ),
        "open pinned workspace mount tree",
    )
    workspace_mount_info = os.fstat(workspace_mount_fd)
    if (
        not stat.S_ISDIR(workspace_mount_info.st_mode)
        or (workspace_mount_info.st_dev, workspace_mount_info.st_ino)
        != (payload["workspace_device"], payload["workspace_inode"])
    ):
        _fail()
    _set_mount_attributes(mount_setattr, workspace_mount_fd, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV)
    _check_mount_call(
        move_mount(
            workspace_mount_fd,
            b"",
            workspace_anchor_fd,
            b"",
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        ),
        "attach pinned workspace mount tree to private anchor",
    )
    os.close(workspace_mount_fd)
    os.close(workspace_anchor_fd)
    private_shm_fd = os.open(
        "/dev/shm",
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    workspace_anchor_fd = os.open(
        workspace_anchor_name,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=private_shm_fd,
    )
    os.close(private_shm_fd)
    workspace_anchor_info = os.fstat(workspace_anchor_fd)
    if (
        not stat.S_ISDIR(workspace_anchor_info.st_mode)
        or (workspace_anchor_info.st_dev, workspace_anchor_info.st_ino)
        != (payload["workspace_device"], payload["workspace_inode"])
        or os.fstatvfs(workspace_anchor_fd).f_flag & ST_RDONLY
    ):
        _fail()
    _set_mount_attributes(mount_setattr, workspace_anchor_fd, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV)
    os.close(workspace_anchor_fd)

    # Reopen bundle and rootfs after unshare: inherited descriptors refer to
    # parent-namespace mount objects and are not targets in this namespace.
    bundle_target_fd = os.open(
        payload["bundle"],
        getattr(os, "O_PATH", os.O_RDONLY)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    bundle_target_info = os.fstat(bundle_target_fd)
    if (
        not stat.S_ISDIR(bundle_target_info.st_mode)
        or (bundle_target_info.st_dev, bundle_target_info.st_ino)
        != (payload["bundle_device"], payload["bundle_inode"])
        or bundle_target_info.st_uid != payload["uid"]
        or stat.S_IMODE(bundle_target_info.st_mode) & 0o077
        or stat.S_IMODE(bundle_target_info.st_mode) & 0o700 != 0o700
    ):
        _fail()
    rootfs_source_fd = os.open(
        "rootfs",
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=bundle_target_fd,
    )
    rootfs_source_open_info = os.fstat(rootfs_source_fd)
    if (
        not stat.S_ISDIR(rootfs_source_open_info.st_mode)
        or (rootfs_source_open_info.st_dev, rootfs_source_open_info.st_ino)
        != (payload["rootfs_device"], payload["rootfs_inode"])
    ):
        _fail()
    os.close(rootfs_fd)
    rootfs_fd = rootfs_source_fd
    filesystem_fd = _check_mount_fd(fsopen(b"tmpfs", FSOPEN_CLOEXEC), "fsopen(tmpfs)")
    _check_mount_call(
        fsconfig(filesystem_fd, FSCONFIG_SET_STRING, b"size", b"1m", 0),
        "tmpfs size",
    )
    _check_mount_call(
        fsconfig(filesystem_fd, FSCONFIG_SET_STRING, b"mode", b"0700", 0),
        "tmpfs mode",
    )
    _check_mount_call(
        fsconfig(filesystem_fd, FSCONFIG_CMD_CREATE, None, None, 0),
        "tmpfs create",
    )
    bundle_mount_fd = _check_mount_fd(
        fsmount(
            filesystem_fd,
            FSMOUNT_CLOEXEC,
            MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC,
        ),
        "fsmount(tmpfs)",
    )
    os.close(filesystem_fd)

    # Attach the detached tmpfs to the already-open bundle directory itself.
    # Empty-path move_mount keeps both sides descriptor-anchored and avoids the
    # EINVAL/race-prone /proc/self/fd mount target used by mount(2).
    phase = b"7"
    _check_mount_call(
        move_mount(
            bundle_mount_fd,
            b"",
            bundle_target_fd,
            b"",
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        ),
        "attach private bundle tmpfs",
    )
    os.dup2(bundle_mount_fd, bundle_fd, inheritable=False)
    if bundle_target_fd != bundle_fd:
        os.close(bundle_target_fd)
    if bundle_mount_fd != bundle_fd:
        os.close(bundle_mount_fd)
    bundle_mount_fd = bundle_fd

    phase = b"8"
    rootfs_source_info = os.fstat(rootfs_fd)
    rootfs_filesystem_fd = _check_mount_fd(fsopen(b"tmpfs", FSOPEN_CLOEXEC), "fsopen(rootfs tmpfs)")
    _check_mount_call(
        fsconfig(
            rootfs_filesystem_fd,
            FSCONFIG_SET_STRING,
            b"size",
            str(payload["rootfs_snapshot_limit_bytes"]).encode("ascii"),
            0,
        ),
        "rootfs tmpfs size",
    )
    _check_mount_call(
        fsconfig(
            rootfs_filesystem_fd,
            FSCONFIG_SET_STRING,
            b"nr_inodes",
            str(payload["rootfs_entry_count"]).encode("ascii"),
            0,
        ),
        "rootfs tmpfs inode limit",
    )
    _check_mount_call(
        fsconfig(rootfs_filesystem_fd, FSCONFIG_SET_STRING, b"mode", b"0700", 0),
        "rootfs tmpfs mode",
    )
    _check_mount_call(
        fsconfig(rootfs_filesystem_fd, FSCONFIG_CMD_CREATE, None, None, 0),
        "rootfs tmpfs create",
    )
    rootfs_mount_fd = _check_mount_fd(
        fsmount(
            rootfs_filesystem_fd,
            FSMOUNT_CLOEXEC,
            MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
        ),
        "fsmount(rootfs tmpfs)",
    )
    os.close(rootfs_filesystem_fd)
    os.mkdir("rootfs", 0o700, dir_fd=bundle_fd)
    rootfs_target_fd = os.open(
        "rootfs",
        getattr(os, "O_PATH", os.O_RDONLY)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=bundle_fd,
    )
    _check_mount_call(
        move_mount(
            rootfs_mount_fd,
            b"",
            rootfs_target_fd,
            b"",
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        ),
        "attach private rootfs tmpfs",
    )
    os.close(rootfs_target_fd)
    rootfs_snapshot_fd = os.open(
        "rootfs",
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=bundle_fd,
    )
    _copy_rootfs_tree(rootfs_fd, rootfs_snapshot_fd, rootfs_source_info.st_dev)
    os.close(rootfs_fd)
    _set_mount_attributes(
        mount_setattr,
        rootfs_mount_fd,
        MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
    )
    if not os.fstatvfs(rootfs_snapshot_fd).f_flag & ST_RDONLY:
        _fail()
    os.close(rootfs_mount_fd)

    config_bytes = payload["config"].encode("ascii")
    if not config_bytes or len(config_bytes) > 65536:
        _fail()
    config = json.loads(config_bytes)
    workspace_mounts = [
        mount
        for mount in config.get("mounts", [])
        if isinstance(mount, dict) and mount.get("destination") == "/workspace"
    ]
    if (
        len(workspace_mounts) != 1
        or workspace_mounts[0].get("type") != "bind"
        or workspace_mounts[0].get("source") != payload["workspace_source"]
    ):
        _fail()
    config_fd = os.open(
        "config.json",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
        dir_fd=bundle_fd,
    )
    try:
        offset = 0
        while offset < len(config_bytes):
            offset += os.write(config_fd, config_bytes[offset:])
        os.fsync(config_fd)
    finally:
        os.close(config_fd)
    phase = b"9"
    _set_mount_attributes(
        mount_setattr,
        bundle_mount_fd,
        MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC,
    )
    if not os.fstatvfs(bundle_mount_fd).f_flag & ST_RDONLY:
        _fail()
    config_read_fd = os.open(
        "config.json",
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
        dir_fd=bundle_fd,
    )
    try:
        with os.fdopen(config_read_fd, "rb") as stream:
            observed_config = stream.read(65537)
    finally:
        config_read_fd = -1
    if observed_config != config_bytes:
        _fail()
    phase = b"A"
    bundle_args = [index for index, value in enumerate(command) if value == "--bundle"]
    if (
        len(command) != 13
        or command[1] != "--root"
        or command[3:5] != ["--systemd-cgroup", "run"]
        or command[5] != "--bundle"
        or command[7] != "--pid-file"
        or command[9:11] != ["--preserve-fds", "1"]
        or command[11] != "--keep"
        or len(bundle_args) != 1
        or bundle_args[0] + 1 >= len(command)
        or command[bundle_args[0] + 1] != payload["bundle_fd_path"]
        or command[2] != f"/proc/self/fd/{payload['state_fd']}"
    ):
        _fail()
    pid_file_parent, pid_file_name = os.path.split(command[8])
    if (
        pid_file_parent != f"/proc/self/fd/{payload['state_fd']}"
        or pid_file_name in {"", ".", ".."}
        or "/" in pid_file_name
    ):
        _fail()
    os.set_inheritable(payload["state_fd"], True)
    os.set_inheritable(bundle_fd, True)
    os.close(payload["workspace_fd"])
    phase = b"B"
    bundle_snapshot_fd = os.open(
        ".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=bundle_fd
    )
    transfer_socket = socket.socket(fileno=snapshot_socket_fd)
    descriptors = array.array("i", [rootfs_snapshot_fd, bundle_snapshot_fd])
    if transfer_socket.sendmsg(
        [b"S"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors.tobytes())]
    ) != 1:
        _fail()
    transfer_socket.close()
    os.close(rootfs_snapshot_fd)
    os.close(bundle_snapshot_fd)
    _message(b"R")
    if not _read_exact(exec_ack_fd, b"X"):
        _fail()
    os.close(exec_ack_fd)

    phase = b"C"
    if gate_fd == 3:
        os.set_inheritable(gate_fd, True)
    else:
        os.dup2(gate_fd, 3, inheritable=True)
        os.close(gate_fd)
    os.set_inheritable(runc_fd, False)
    resource.setrlimit(resource.RLIMIT_FSIZE, (67108864, 67108864))
    os.execve(runc_fd, command, payload["env"])
except BaseException as error:
    error_detail = f"{type(error).__name__}: {error}"
    _fail(getattr(error, "errno", 0) or 0, error_detail)
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
_PINNED_RUNC_WORKER_CONFIGS: dict[
    int,
    tuple[
        weakref.ReferenceType[Any],
        tuple[_TrustedRuncExecutable, str, bytes, str, str, str],
    ],
] = {}
_COMPILER_ISSUED_OCI_WORKER_CONFIGS: dict[
    int,
    tuple[weakref.ReferenceType[Any], bytes, str, str, str],
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


@dataclass(frozen=True, slots=True, weakref_slot=True, eq=False)
class _PinnedRuncWorkerConfig:
    """Immutable worker config bound to sealed runtime and rootfs pins."""

    executable: _TrustedRuncExecutable
    version: str
    config_json: bytes = field(repr=False)
    sha256: str
    rootfs_sha256: str
    rootfs_closure_sha256: str


class _CompilerIssuedOciWorkerConfig(dict[str, Any]):
    """Dict-compatible OCI config whose compiler provenance is process-local."""


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
    path: str | Path | None,
    *,
    _manifest_entries: list[dict[str, Any]] | None = None,
    _root_fd: int | None = None,
) -> tuple[str, int, int]:
    """Return a canonical tree digest and the inode opened for that scan.

    The digest binds relative names, entry types, permission/ownership metadata,
    regular-file contents, and symlink targets. Devices, sockets, FIFOs,
    cross-device or nested mounts, hard-linked files, Linux POSIX ACLs,
    escaping symlinks, set-id entries, Linux file capabilities, and trees above fixed
    limits fail closed. This is an integrity measurement, not evidence that an
    image was audited.
    """

    if _root_fd is None:
        root = _plain_directory(path, code="invalid_oci_rootfs", label="OCI rootfs")
    else:
        if path is not None:
            raise SupervisorError("invalid_oci_rootfs", "rootfs descriptor and path are exclusive")
        root = Path(".")
    is_linux = platform.system() == "Linux"
    mountinfo_before = _read_linux_mountinfo() if is_linux and _root_fd is None else None
    if mountinfo_before is not None:
        _reject_nested_linux_mounts(root, mountinfo_before)
    root_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    try:
        if _root_fd is None:
            root_fd = os.open(root, root_flags | nofollow | cloexec)
        else:
            descriptor_info = os.fstat(_root_fd)
            if not stat.S_ISDIR(descriptor_info.st_mode):
                raise OSError("rootfs descriptor is not a directory")
            root_fd = os.open(".", root_flags | nofollow | cloexec, dir_fd=_root_fd)
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
                if not is_linux and _root_fd is None and os.path.ismount(child):
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
        current_root = (
            os.stat(root, follow_symlinks=False) if _root_fd is None else os.fstat(root_fd)
        )
        if _rootfs_stat_identity(opened_root) != _rootfs_stat_identity(current_root):
            raise SupervisorError("invalid_oci_rootfs", "OCI rootfs changed while being read")
        if mountinfo_before is not None:
            # Global mount namespaces may legitimately change outside this tree while
            # it is measured. Revalidate the only relevant invariant: no nested
            # mount is present beneath this root at either boundary.
            _reject_nested_linux_mounts(root, _read_linux_mountinfo())
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


def rootfs_tree_manifest_fd(root_fd: int) -> dict[str, Any]:
    """Measure a rootfs through an already-open directory descriptor."""

    entries: list[dict[str, Any]] = []
    tree_sha256, _device, _inode = _measure_rootfs_tree(
        None, _manifest_entries=entries, _root_fd=root_fd
    )
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


def _canonical_oci_worker_config(config: dict[str, Any]) -> bytes:
    try:
        return (
            json.dumps(
                config,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise SupervisorError(
            "invalid_oci_worker_policy", "OCI worker config is not canonical JSON"
        ) from error


def _issue_compiler_oci_worker_config(
    config: dict[str, Any], *, rootfs_sha256: str, rootfs_closure_sha256: str
) -> _CompilerIssuedOciWorkerConfig:
    if not _is_rootfs_sha256(rootfs_sha256) or not _is_rootfs_sha256(rootfs_closure_sha256):
        raise SupervisorError(
            "invalid_oci_rootfs", "compiler-issued worker config requires exact rootfs pins"
        )
    issued = _CompilerIssuedOciWorkerConfig(config)
    config_json = _canonical_oci_worker_config(issued)
    digest = hashlib.sha256(config_json).hexdigest()
    key = id(issued)

    def discard(reference: weakref.ReferenceType[Any]) -> None:
        current = _COMPILER_ISSUED_OCI_WORKER_CONFIGS.get(key)
        if current is not None and current[0] is reference:
            _COMPILER_ISSUED_OCI_WORKER_CONFIGS.pop(key, None)

    reference = weakref.ref(issued, discard)
    _COMPILER_ISSUED_OCI_WORKER_CONFIGS[key] = (
        reference,
        config_json,
        digest,
        rootfs_sha256,
        rootfs_closure_sha256,
    )
    return issued


def _compiler_issued_oci_worker_config(
    config: dict[str, Any],
) -> tuple[dict[str, Any], str, str]:
    """Return the exact config and rootfs pins sealed by the compiler."""

    sealed = (
        _COMPILER_ISSUED_OCI_WORKER_CONFIGS.get(id(config))
        if type(config) is _CompilerIssuedOciWorkerConfig
        else None
    )
    if sealed is None or sealed[0]() is not config:
        raise SupervisorError(
            "invalid_oci_worker_policy",
            "runc compatibility adapter requires an exact compiler-issued OCI config",
        )
    config_json, digest, rootfs_sha256, rootfs_closure_sha256 = sealed[1:]
    if (
        _canonical_oci_worker_config(config) != config_json
        or hashlib.sha256(config_json).hexdigest() != digest
    ):
        raise SupervisorError(
            "invalid_oci_worker_policy", "compiler-issued OCI config was mutated after build"
        )
    try:
        decoded = json.loads(config_json)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise SupervisorError(
            "invalid_oci_worker_policy", "sealed compiler OCI config cannot be decoded"
        ) from error
    _validate_complete_oci_worker_policy(decoded)
    return decoded, rootfs_sha256, rootfs_closure_sha256


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
    return _issue_compiler_oci_worker_config(
        {
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
                    "destination": "/dev",
                    "type": "tmpfs",
                    "source": "tmpfs",
                    "options": [
                        "nosuid",
                        "noexec",
                        "mode=0755",
                        f"size={_DEFAULT_DEV_TMPFS_BYTES}",
                        f"nr_inodes={_DEFAULT_DEV_TMPFS_INODES}",
                    ],
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
                "cgroupsPath": _oci_worker_cgroups_path(container_id),
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
        },
        rootfs_sha256=rootfs_pin.sha256,
        rootfs_closure_sha256=rootfs_pin.closure_sha256 or "",
    )


def _validate_complete_oci_worker_policy(config: dict[str, Any]) -> None:
    """Reject any compiler document outside ACP's supported, bounded OCI subset."""

    def reject() -> None:
        raise SupervisorError(
            "invalid_oci_worker_policy",
            "compiler-issued OCI config does not satisfy the complete worker policy",
        )

    def exact(actual: Any, expected: Any) -> bool:
        """Compare JSON values without Python's bool/int equality aliasing."""
        if type(actual) is not type(expected):
            return False
        if type(expected) is dict:
            return actual.keys() == expected.keys() and all(
                exact(actual[key], expected[key]) for key in expected
            )
        if type(expected) is list:
            return len(actual) == len(expected) and all(
                exact(left, right) for left, right in zip(actual, expected, strict=True)
            )
        return actual == expected

    if type(config) is not dict or set(config) != {
        "ociVersion",
        "hostname",
        "root",
        "process",
        "mounts",
        "linux",
    }:
        reject()
    if config.get("ociVersion") != "1.2.0" or config.get("hostname") != "acp-worker":
        reject()

    root = config.get("root")
    if not exact(root, {"path": "rootfs", "readonly": True}):
        reject()

    process = config.get("process")
    if type(process) is not dict or set(process) != {
        "terminal",
        "user",
        "args",
        "env",
        "cwd",
        "noNewPrivileges",
        "rlimits",
        "capabilities",
    }:
        reject()
    if (
        process.get("terminal") is not False
        or process.get("cwd") != "/workspace"
        or process.get("noNewPrivileges") is not True
        or not exact(process.get("user"), {"uid": 0, "gid": 0, "additionalGids": []})
        or not exact(
            process.get("rlimits"),
            [
                {"type": "RLIMIT_CORE", "hard": 0, "soft": 0},
                {
                    "type": "RLIMIT_FSIZE",
                    "hard": 64 * 1024 * 1024,
                    "soft": 64 * 1024 * 1024,
                },
            ],
        )
        or not exact(
            process.get("capabilities"),
            {
                "bounding": [],
                "effective": [],
                "inheritable": [],
                "permitted": [],
                "ambient": [],
            },
        )
    ):
        reject()

    args = process.get("args")
    if (
        type(args) is not list
        or len(args) < 5
        or args[:2] != ["/bin/sh", "-c"]
        or args[3] != "acp-launch-gate"
        or not all(isinstance(value, str) and value and "\x00" not in value for value in args)
    ):
        reject()
    private_git_scripts = {
        _render_private_git_launch_script(git_path=git, mkdir_path=mkdir, rmdir_path=rmdir)
        for git in ("/usr/bin/git", "/bin/git")
        for mkdir in ("/usr/bin/mkdir", "/bin/mkdir")
        for rmdir in ("/usr/bin/rmdir", "/bin/rmdir")
    }
    if args[2] not in ({_LAUNCH_GATE_SCRIPT} | private_git_scripts):
        reject()
    try:
        _validate_command(args[4:])
    except SupervisorError:
        reject()

    base_environment = {
        "ACP_PHASE": "worker",
        "ACP_REPO_ROOT": "/workspace",
        "ACP_RUNTIME_DIR": "/tmp/acp-runtime",
        "ACP_WORKTREE": "/workspace",
        "HOME": "/home/agent",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": "/tmp",
    }
    git_environment = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CEILING_DIRECTORIES": "/workspace",
    }
    env = process.get("env")
    if type(env) is not list or not all(isinstance(item, str) for item in env):
        reject()
    environment: dict[str, str] = {}
    for entry in env:
        name, separator, value = entry.partition("=")
        if not separator or not name or name in environment:
            reject()
        environment[name] = value
    if environment not in (base_environment, base_environment | git_environment):
        reject()

    mounts = config.get("mounts")
    if type(mounts) is not list or len(mounts) != 5:
        reject()
    if not exact(
        mounts[0],
        {
            "destination": "/proc",
            "type": "proc",
            "source": "proc",
            "options": ["nosuid", "nodev", "noexec", "ro"],
        },
    ):
        reject()
    if not exact(
        mounts[1],
        {
            "destination": "/dev",
            "type": "tmpfs",
            "source": "tmpfs",
            "options": [
                "nosuid",
                "noexec",
                "mode=0755",
                f"size={_DEFAULT_DEV_TMPFS_BYTES}",
                f"nr_inodes={_DEFAULT_DEV_TMPFS_INODES}",
            ],
        },
    ):
        reject()
    workspace_mount = mounts[2]
    if (
        type(workspace_mount) is not dict
        or set(workspace_mount) != {"destination", "type", "source", "options"}
        or workspace_mount.get("destination") != "/workspace"
        or workspace_mount.get("type") != "bind"
        or not isinstance(workspace_mount.get("source"), str)
        or not Path(workspace_mount["source"]).is_absolute()
        or not exact(workspace_mount.get("options"), ["bind", "rprivate", "rw", "nosuid", "nodev"])
    ):
        reject()
    for mount, destination, mode in (
        (mounts[3], "/tmp", "mode=1777"),
        (mounts[4], "/home/agent", "mode=0700"),
    ):
        if (
            type(mount) is not dict
            or set(mount) != {"destination", "type", "source", "options"}
            or mount.get("destination") != destination
            or mount.get("type") != "tmpfs"
            or mount.get("source") != "tmpfs"
        ):
            reject()
        options = mount.get("options")
        size_match = (
            re.fullmatch(r"size=([1-9][0-9]*)", options[3])
            if type(options) is list and len(options) == 4 and isinstance(options[3], str)
            else None
        )
        if (
            type(options) is not list
            or len(options) != 4
            or not exact(options[:3], ["nosuid", "nodev", mode])
            or size_match is None
        ):
            reject()
        size_text = size_match.group(1)
        max_size_text = str(_MAX_INT64)
        if len(size_text) > len(max_size_text) or (
            len(size_text) == len(max_size_text) and size_text > max_size_text
        ):
            reject()

    linux = config.get("linux")
    if type(linux) is not dict or set(linux) != {
        "uidMappings",
        "gidMappings",
        "namespaces",
        "resources",
        "seccomp",
        "cgroupsPath",
        "rootfsPropagation",
        "maskedPaths",
        "readonlyPaths",
    }:
        reject()
    if (
        not exact(
            linux.get("uidMappings"),
            [{"containerID": 0, "hostID": os.geteuid(), "size": 1}],
        )
        or not exact(
            linux.get("gidMappings"),
            [{"containerID": 0, "hostID": os.getegid(), "size": 1}],
        )
        or not exact(
            linux.get("namespaces"),
            [
                {"type": name}
                for name in ("user", "pid", "mount", "ipc", "uts", "cgroup", "network")
            ],
        )
        or linux.get("rootfsPropagation") != "private"
        or not exact(
            linux.get("maskedPaths"),
            [
                "/proc/kcore",
                "/proc/keys",
                "/proc/latency_stats",
                "/proc/timer_stats",
                "/proc/sched_debug",
            ],
        )
        or not exact(linux.get("readonlyPaths"), ["/proc/sys", "/proc/sysrq-trigger"])
        or not exact(linux.get("seccomp"), _worker_seccomp_profile())
    ):
        reject()
    resources = linux.get("resources")
    if type(resources) is not dict or set(resources) != {"memory", "cpu", "pids", "devices"}:
        reject()
    memory = resources.get("memory")
    cpu = resources.get("cpu")
    pids = resources.get("pids")
    if (
        type(memory) is not dict
        or set(memory) != {"limit"}
        or type(memory.get("limit")) is not int
        or not _MIN_MEMORY_BYTES <= memory["limit"] <= _MAX_INT64
        or type(cpu) is not dict
        or set(cpu) != {"quota", "period"}
        or type(cpu.get("quota")) is not int
        or not 1 <= cpu["quota"] <= _MAX_INT64
        or type(cpu.get("period")) is not int
        or not 1 <= cpu["period"] <= _MAX_UINT64
        or type(pids) is not dict
        or set(pids) != {"limit"}
        or type(pids.get("limit")) is not int
        or not 1 <= pids["limit"] <= _MAX_PIDS
        or not exact(resources.get("devices"), [{"allow": False, "access": "rwm"}])
    ):
        reject()
    cgroups_path = linux.get("cgroupsPath")
    parts = cgroups_path.split(":") if isinstance(cgroups_path, str) else ()
    if (
        len(parts) != 3
        or parts[1] != "acp"
        or _CONTAINER_ID.fullmatch(parts[2]) is None
        or parts[0] != _oci_worker_systemd_slice(parts[2])
    ):
        reject()


def _apply_pinned_runc_recursive_private_policy(
    config: dict[str, Any],
    executable: _TrustedRuncExecutable,
    *,
    expected_version: str,
) -> _PinnedRuncWorkerConfig:
    """Apply the narrowly pinned runc extension needed for recursive isolation.

    The portable OCI compiler emits the standard rootfsPropagation value
    "private". On the supported runc release, that leaves propagation state on
    nested runtime mounts. Runc 1.3.5 accepts the implementation-specific
    spelling "rprivate" and maps it to MS_PRIVATE|MS_REC. Keep that extension
    out of the generic compiler and refuse it for every other pinned release.
    """

    if expected_version != _RUNC_RECURSIVE_PRIVATE_VERSION:
        raise SupervisorError(
            "invalid_oci_runtime_version",
            "recursive rootfs propagation currently requires pinned runc 1.3.5",
        )
    compiled_config, rootfs_sha256, rootfs_closure_sha256 = _compiler_issued_oci_worker_config(
        config
    )
    observed_version = _probe_trusted_runc_version(executable, expected_version)
    if observed_version != _RUNC_RECURSIVE_PRIVATE_VERSION:
        raise SupervisorError(
            "invalid_oci_runtime_version",
            "recursive rootfs propagation requires the exact pinned runc release",
        )
    adapted = compiled_config
    adapted["linux"]["rootfsPropagation"] = "rprivate"
    config_json = _canonical_oci_worker_config(adapted)
    digest = hashlib.sha256(config_json).hexdigest()
    binding = _PinnedRuncWorkerConfig(
        executable=executable,
        version=observed_version,
        config_json=config_json,
        sha256=digest,
        rootfs_sha256=rootfs_sha256,
        rootfs_closure_sha256=rootfs_closure_sha256,
    )
    key = id(binding)

    def discard(reference: weakref.ReferenceType[Any]) -> None:
        current = _PINNED_RUNC_WORKER_CONFIGS.get(key)
        if current is not None and current[0] is reference:
            _PINNED_RUNC_WORKER_CONFIGS.pop(key, None)

    reference = weakref.ref(binding, discard)
    _PINNED_RUNC_WORKER_CONFIGS[key] = (
        reference,
        (
            executable,
            observed_version,
            config_json,
            digest,
            rootfs_sha256,
            rootfs_closure_sha256,
        ),
    )
    return binding


def _verify_pinned_runc_worker_config(
    binding: _PinnedRuncWorkerConfig,
    executable: _TrustedRuncExecutable,
) -> None:
    """Verify the sealed config still names the exact pinned runtime object."""

    sealed = (
        _PINNED_RUNC_WORKER_CONFIGS.get(id(binding))
        if type(binding) is _PinnedRuncWorkerConfig
        else None
    )
    if sealed is None or sealed[0]() is not binding:
        raise SupervisorError(
            "invalid_oci_worker_policy", "runc worker config must come from the pinned adapter"
        )
    pinned, version, config_json, digest, rootfs_sha256, rootfs_closure_sha256 = sealed[1]
    if (
        binding.executable is not executable
        or pinned is not executable
        or binding.version != version
        or binding.config_json != config_json
        or binding.sha256 != digest
        or hashlib.sha256(binding.config_json).hexdigest() != digest
        or binding.rootfs_sha256 != rootfs_sha256
        or binding.rootfs_closure_sha256 != rootfs_closure_sha256
        or not _is_rootfs_sha256(rootfs_sha256)
        or not _is_rootfs_sha256(rootfs_closure_sha256)
    ):
        raise SupervisorError(
            "invalid_oci_worker_policy",
            "runc worker config is not bound to this exact executable and policy",
        )
    if version != _RUNC_RECURSIVE_PRIVATE_VERSION:
        raise SupervisorError(
            "invalid_oci_runtime_version", "runc worker config requires pinned runc 1.3.5"
        )
    _verify_trusted_runc_executable(executable)
    observed_version = _probe_trusted_runc_version(executable, version)
    if observed_version != version:
        raise SupervisorError(
            "invalid_oci_runtime_version", "runc worker config runtime version changed"
        )


def _write_pinned_runc_worker_config(
    binding: _PinnedRuncWorkerConfig,
    executable: _TrustedRuncExecutable,
    bundle_root: str | Path,
) -> Path:
    """Create config.json from the sealed bytes in a private OCI bundle."""

    _verify_pinned_runc_worker_config(binding, executable)
    bundle = _private_directory(bundle_root, code="invalid_oci_bundle", label="OCI bundle root")
    config_path = bundle / "config.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(config_path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(binding.config_json)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise SupervisorError(
            "invalid_oci_bundle", "could not create the bound runc worker config"
        ) from error
    return config_path


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
    public :func:`spawn_pinned_runc` replaces the host bundle path with an
    inherited descriptor path inside a private mount namespace before runc is
    executed. The diagnostic helper intentionally retains its host-path mode.
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


@dataclass(eq=False, slots=True, weakref_slot=True)
class RuncLaunchHandle:
    """One registered runc client and its private OCI-init release gate.

    The child process is deliberately kept out of this public handle and in the
    launcher's private registry. The public :meth:`release_gate` is enabled only
    after the durable journal records this exact execution as running. The lock
    linearizes release against cancellation:
    whichever operation acquires it first determines whether the gate is
    released or closed. Closing an unreleased gate denies candidate exec.
    """

    _gate_writer: int | None
    _bundle_path: str | None = None
    _gate_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def bundle_path(self) -> str | None:
        """The exact bundle path handed to this runc process, when descriptor-backed."""

        return self._bundle_path

    def release_gate(self) -> None:
        """Release the init gate after this launch's durable running transition."""

        with self._gate_lock:
            descriptor = self._gate_writer
            if descriptor is None:
                raise SupervisorError(
                    "sandbox_launch_gate_closed", "OCI init launch gate is already closed"
                )
            _consume_runc_launch_gate_authorization(self)
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

    def wait(self, timeout: float | None = None) -> _RuncClientWaitReceipt:
        """Reap this pinned-runc child and return its bound kernel wait receipt."""

        launch = _runc_launch_record(self)
        if launch is None:
            raise SupervisorError(
                "sandbox_runc_wait_unverified",
                "runc wait requires the handle returned by the pinned launcher",
            )
        binding = launch.execution_binding
        if binding is None:
            raise SupervisorError(
                "sandbox_runc_wait_unbound",
                "runc wait evidence must be bound to a durable attempt before it is recorded",
            )
        wait_lock = launch.wait_lock
        if not wait_lock.acquire(timeout=max(0.0, timeout) if timeout is not None else -1):
            raise subprocess.TimeoutExpired("pinned-runc", timeout)
        try:
            launch = _runc_launch_record(self)
            if launch is None or launch.execution_binding != binding:
                raise SupervisorError(
                    "sandbox_runc_wait_unverified",
                    "pinned runc launch provenance changed while waiting",
                )
            returncode = launch.wait_returncode
            if returncode is None:
                returncode = _wait_and_reap_registered_runc(launch, timeout)
                _record_runc_kernel_wait_status(self, launch, returncode)
        finally:
            wait_lock.release()
        current = _runc_launch_record(self)
        if current is None or current.execution_binding != binding:
            raise SupervisorError(
                "sandbox_runc_wait_unverified",
                "pinned runc launch provenance changed while waiting",
            )
        receipt = _RuncClientWaitReceipt(
            pid=launch.pid,
            process_identity=launch.process_identity,
            returncode=returncode,
            attempt_id=binding[0],
            claim_token=binding[1],
            execution_id=binding[2],
        )
        _register_runc_client_wait_receipt(receipt)
        return receipt

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


@dataclass(frozen=True)
class _RuncLaunchTarget:
    """Immutable launch inputs captured by the selected pinned-runc launcher."""

    launch_mode: str
    argv: tuple[str, ...]
    runc_executable_path: str
    runc_executable_sha256: str
    # SHA-256 over the exact config.json bytes embedded in the launcher payload.
    config_sha256: str | None = None
    bundle_path: str | None = None
    bundle_device: int | None = None
    bundle_inode: int | None = None
    rootfs_path: str | None = None
    rootfs_device: int | None = None
    rootfs_inode: int | None = None
    rootfs_sha256: str | None = None
    rootfs_closure_sha256: str | None = None
    rootfs_entry_count: int | None = None
    rootfs_bytes: int | None = None
    rootfs_snapshot_limit_bytes: int | None = None
    rootfs_snapshot_device: int | None = None
    rootfs_snapshot_inode: int | None = None
    rootfs_snapshot_sha256: str | None = None
    rootfs_snapshot_closure_sha256: str | None = None
    rootfs_snapshot_entry_count: int | None = None
    rootfs_snapshot_bytes: int | None = None
    state_path: str | None = None
    state_device: int | None = None
    state_inode: int | None = None
    workspace_path: str | None = None
    workspace_device: int | None = None
    workspace_inode: int | None = None
    pid_file_path: str | None = None
    container_id: str | None = None
    memory_limit_bytes: int | None = None
    cpu_quota: int | None = None
    cpu_period: int | None = None
    pids_limit: int | None = None


@dataclass(frozen=True)
class _RuncLaunchRecord:
    """Private immutable provenance retained independently of mutable handles."""

    process: Any
    pid: int
    process_identity: str
    target: _RuncLaunchTarget
    execution_binding: tuple[str, int, str] | None = None
    gate_release_authorized: bool = False
    wait_lock: threading.Lock = field(default_factory=threading.Lock, compare=False, repr=False)
    wait_returncode: int | None = None
    _test_waitpid: Callable[[int, int], tuple[int, int]] | None = field(
        default=None, compare=False, repr=False
    )
    _test_identity_reader: Callable[[int], str | None] | None = field(
        default=None, compare=False, repr=False
    )


@dataclass(frozen=True)
class _RuncClientWaitReceipt:
    """Process wait evidence issued only by a registered pinned-runc handle."""

    pid: int
    process_identity: str
    returncode: int
    attempt_id: str
    claim_token: int
    execution_id: str


_RUNC_LAUNCH_RECORDS: dict[
    int, tuple[weakref.ReferenceType[RuncLaunchHandle], _RuncLaunchRecord]
] = {}
_RUNC_LAUNCH_RECORDS_LOCK = threading.RLock()
_RUNC_WAIT_RECEIPTS: dict[
    int, tuple[weakref.ReferenceType[Any], tuple[int, str, int, str, int, str]]
] = {}
_RUNC_WAIT_RECEIPTS_LOCK = threading.Lock()


@contextmanager
def _runc_launch_gate_lock_for_execution(
    attempt_id: str, claim_token: int, execution_id: str
) -> Iterator[RuncLaunchHandle | None]:
    """Serialize a journal lifecycle mutation with release of its exact gate.

    The registry lock is released before waiting for the handle lock, matching
    ``release_gate``'s handle-then-registry order and avoiding lock inversion.
    A missing handle is safe: without a live registered handle no caller can
    release that execution's gate.
    """

    binding = (attempt_id, claim_token, execution_id)
    with _RUNC_LAUNCH_RECORDS_LOCK:
        candidates = []
        for key, (reference, record) in tuple(_RUNC_LAUNCH_RECORDS.items()):
            handle = reference()
            if handle is None:
                _RUNC_LAUNCH_RECORDS.pop(key, None)
            elif record.execution_binding == binding:
                candidates.append(handle)
    if len(candidates) > 1:
        raise SupervisorError(
            "sandbox_execution_launch_handle_conflict",
            "more than one pinned-runc handle is bound to this durable execution",
        )
    if not candidates:
        yield None
        return

    handle = candidates[0]
    with handle._gate_lock:
        with _RUNC_LAUNCH_RECORDS_LOCK:
            registered = _RUNC_LAUNCH_RECORDS.get(id(handle))
            if (
                registered is None
                or registered[0]() is not handle
                or registered[1].execution_binding != binding
            ):
                locked_handle = None
            else:
                locked_handle = handle
        yield locked_handle


def _register_runc_launch_handle(
    handle: RuncLaunchHandle,
    *,
    process: Any,
    process_identity: str,
    target: _RuncLaunchTarget,
    _test_waitpid: Callable[[int, int], tuple[int, int]] | None = None,
    _test_identity_reader: Callable[[int], str | None] | None = None,
) -> None:
    """Keep launcher provenance in a private weak registry, not mutable fields."""

    if type(handle) is not RuncLaunchHandle or type(target) is not _RuncLaunchTarget:
        raise SupervisorError("sandbox_runc_handle_invalid", "pinned runc handle is invalid")
    pid = getattr(process, "pid", None)
    if (
        type(pid) is not int
        or pid <= 0
        or not isinstance(process_identity, str)
        or not process_identity.startswith(f"linux:{pid}:")
        or not process_identity.rsplit(":", 1)[-1].isdecimal()
    ):
        raise SupervisorError(
            "sandbox_runc_identity_unavailable", "pinned runc process identity is invalid"
        )
    key = id(handle)

    def discard(reference: weakref.ReferenceType[RuncLaunchHandle]) -> None:
        with _RUNC_LAUNCH_RECORDS_LOCK:
            current = _RUNC_LAUNCH_RECORDS.get(key)
            if current is not None and current[0] is reference:
                _RUNC_LAUNCH_RECORDS.pop(key, None)

    reference = weakref.ref(handle, discard)
    record = _RuncLaunchRecord(
        process=process,
        pid=pid,
        process_identity=process_identity,
        target=target,
        _test_waitpid=_test_waitpid,
        _test_identity_reader=_test_identity_reader,
    )
    with _RUNC_LAUNCH_RECORDS_LOCK:
        _RUNC_LAUNCH_RECORDS[key] = (reference, record)


def _runc_launch_record(handle: Any) -> _RuncLaunchRecord | None:
    if type(handle) is not RuncLaunchHandle:
        return None
    with _RUNC_LAUNCH_RECORDS_LOCK:
        registered = _RUNC_LAUNCH_RECORDS.get(id(handle))
        if registered is None or registered[0]() is not handle:
            return None
        record = registered[1]
    if getattr(record.process, "pid", None) != record.pid or not record.process_identity.startswith(
        f"linux:{record.pid}:"
    ):
        return None
    return record


def _runc_launch_pid(handle: Any) -> int | None:
    """Return the registered PID without exposing its mutable Popen object."""

    record = _runc_launch_record(handle)
    return record.pid if record is not None else None


def _runc_launch_process_for_testing(handle: Any) -> Any | None:
    """Private subprocess access for launcher integration tests only."""

    record = _runc_launch_record(handle)
    return record.process if record is not None else None


def _wait_and_reap_registered_runc(launch: _RuncLaunchRecord, timeout: float | None) -> int:
    """Wait for and reap the exact registered PID using kernel wait status.

    ``Popen.returncode`` is only a mutable Python cache and is never treated as
    evidence. A successful ``waitpid`` is required before a receipt can exist.
    """

    deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
    while True:
        identity_reader = launch._test_identity_reader or _runc_client_process_identity
        if identity_reader(launch.pid) != launch.process_identity:
            raise SupervisorError(
                "sandbox_runc_wait_unverified",
                "registered runc PID identity changed before kernel reaping",
            )
        try:
            waitpid = launch._test_waitpid or os.waitpid
            waited_pid, wait_status = waitpid(launch.pid, os.WNOHANG)
        except InterruptedError:
            continue
        except (ChildProcessError, OSError) as error:
            raise SupervisorError(
                "sandbox_runc_wait_unverified",
                "registered runc child could not be reaped by its supervisor",
            ) from error
        if waited_pid == launch.pid:
            returncode = os.waitstatus_to_exitcode(wait_status)
            # Keep Popen's convenience API internally consistent, but only
            # after the kernel has supplied and reaped the actual status.
            launch.process.returncode = returncode
            return returncode
        if waited_pid != 0:
            raise SupervisorError(
                "sandbox_runc_wait_unverified", "kernel returned an unexpected child PID"
            )
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired("pinned-runc", timeout)
            time.sleep(min(0.01, remaining))
        else:
            time.sleep(0.01)


def _record_runc_kernel_wait_status(
    handle: RuncLaunchHandle, launch: _RuncLaunchRecord, returncode: int
) -> None:
    with _RUNC_LAUNCH_RECORDS_LOCK:
        registered = _RUNC_LAUNCH_RECORDS.get(id(handle))
        if registered is None or registered[0]() is not handle:
            raise SupervisorError(
                "sandbox_runc_wait_unverified", "registered runc handle disappeared after wait"
            )
        current = registered[1]
        if (
            current.pid != launch.pid
            or current.process_identity != launch.process_identity
            or current.execution_binding != launch.execution_binding
            or current.process is not launch.process
        ):
            raise SupervisorError(
                "sandbox_runc_wait_unverified", "registered runc provenance changed after wait"
            )
        updated = _RuncLaunchRecord(
            process=current.process,
            pid=current.pid,
            process_identity=current.process_identity,
            target=current.target,
            execution_binding=current.execution_binding,
            gate_release_authorized=current.gate_release_authorized,
            wait_lock=current.wait_lock,
            wait_returncode=returncode,
            _test_waitpid=current._test_waitpid,
            _test_identity_reader=current._test_identity_reader,
        )
        _RUNC_LAUNCH_RECORDS[id(handle)] = (registered[0], updated)


def _runc_launch_target(handle: Any) -> _RuncLaunchTarget | None:
    record = _runc_launch_record(handle)
    return record.target if record is not None else None


def _runc_launch_process_identity(handle: Any) -> str | None:
    record = _runc_launch_record(handle)
    return record.process_identity if record is not None else None


def _runc_launch_handle_is_self_consistent(handle: Any) -> bool:
    """Recognize only a live handle present in the private launch registry."""

    return _runc_launch_record(handle) is not None


def _runc_launch_handle_is_bound_to_execution(
    handle: Any, attempt_id: str, claim_token: int, execution_id: str
) -> bool:
    """Check that a registered launch handle has the exact durable binding."""

    record = _runc_launch_record(handle)
    return record is not None and record.execution_binding == (
        attempt_id,
        claim_token,
        execution_id,
    )


def _authorize_runc_launch_gate_release(
    handle: RuncLaunchHandle, attempt_id: str, claim_token: int, execution_id: str
) -> None:
    """Issue one in-process gate permit after the journal commits ``running``."""

    if type(handle) is not RuncLaunchHandle:
        raise SupervisorError(
            "sandbox_execution_launch_handle_required",
            "OCI gate authorization requires the registered pinned-runc handle",
        )
    with handle._gate_lock:
        _authorize_runc_launch_gate_release_locked(handle, attempt_id, claim_token, execution_id)


def _authorize_runc_launch_gate_release_locked(
    handle: RuncLaunchHandle, attempt_id: str, claim_token: int, execution_id: str
) -> None:
    """Issue the permit while the caller holds the handle's gate lock."""

    if type(handle) is not RuncLaunchHandle:
        raise SupervisorError(
            "sandbox_execution_launch_handle_required",
            "OCI gate authorization requires the registered pinned-runc handle",
        )
    binding = (attempt_id, claim_token, execution_id)
    if handle._gate_writer is None:
        raise SupervisorError(
            "sandbox_launch_gate_closed", "OCI init launch gate is already closed"
        )
    with _RUNC_LAUNCH_RECORDS_LOCK:
        registered = _RUNC_LAUNCH_RECORDS.get(id(handle))
        if registered is None or registered[0]() is not handle:
            raise SupervisorError(
                "sandbox_execution_launch_handle_required",
                "OCI gate authorization requires registered launcher provenance",
            )
        record = registered[1]
        if record.execution_binding != binding:
            raise SupervisorError(
                "sandbox_execution_launch_handle_conflict",
                "OCI gate authorization does not match the durable execution binding",
            )
        if record.gate_release_authorized:
            raise SupervisorError(
                "sandbox_launch_gate_authorization_conflict",
                "OCI gate already has an unconsumed running authorization",
            )
        updated = _RuncLaunchRecord(
            process=record.process,
            pid=record.pid,
            process_identity=record.process_identity,
            target=record.target,
            execution_binding=record.execution_binding,
            gate_release_authorized=True,
            wait_lock=record.wait_lock,
            wait_returncode=record.wait_returncode,
            _test_waitpid=record._test_waitpid,
            _test_identity_reader=record._test_identity_reader,
        )
        _RUNC_LAUNCH_RECORDS[id(handle)] = (registered[0], updated)


def _revoke_runc_launch_gate_release_locked(
    handle: RuncLaunchHandle, attempt_id: str, claim_token: int, execution_id: str
) -> None:
    """Revoke an unconsumed gate permit while the caller holds the gate lock."""

    if type(handle) is not RuncLaunchHandle:
        return
    binding = (attempt_id, claim_token, execution_id)
    with _RUNC_LAUNCH_RECORDS_LOCK:
        registered = _RUNC_LAUNCH_RECORDS.get(id(handle))
        if (
            registered is None
            or registered[0]() is not handle
            or registered[1].execution_binding != binding
            or not registered[1].gate_release_authorized
        ):
            return
        record = registered[1]
        updated = _RuncLaunchRecord(
            process=record.process,
            pid=record.pid,
            process_identity=record.process_identity,
            target=record.target,
            execution_binding=record.execution_binding,
            gate_release_authorized=False,
            wait_lock=record.wait_lock,
            wait_returncode=record.wait_returncode,
            _test_waitpid=record._test_waitpid,
            _test_identity_reader=record._test_identity_reader,
        )
        _RUNC_LAUNCH_RECORDS[id(handle)] = (registered[0], updated)


def _consume_runc_launch_gate_authorization(handle: RuncLaunchHandle) -> None:
    """Consume the one-shot permit; only the journal issues it in production."""

    with _RUNC_LAUNCH_RECORDS_LOCK:
        registered = _RUNC_LAUNCH_RECORDS.get(id(handle))
        if (
            registered is None
            or registered[0]() is not handle
            or not registered[1].gate_release_authorized
            or registered[1].execution_binding is None
        ):
            raise SupervisorError(
                "sandbox_launch_gate_not_authorized",
                "OCI init gate release requires a durable running transition for this launch",
            )
        record = registered[1]
        updated = _RuncLaunchRecord(
            process=record.process,
            pid=record.pid,
            process_identity=record.process_identity,
            target=record.target,
            execution_binding=record.execution_binding,
            gate_release_authorized=False,
            wait_lock=record.wait_lock,
            wait_returncode=record.wait_returncode,
            _test_waitpid=record._test_waitpid,
            _test_identity_reader=record._test_identity_reader,
        )
        _RUNC_LAUNCH_RECORDS[id(handle)] = (registered[0], updated)


def _runc_launch_handle_bind_execution(
    handle: RuncLaunchHandle, attempt_id: str, claim_token: int, execution_id: str
) -> None:
    """Bind a prevalidated launch target once to its exact durable execution."""

    binding = (attempt_id, claim_token, execution_id)
    with _RUNC_LAUNCH_RECORDS_LOCK:
        registered = _RUNC_LAUNCH_RECORDS.get(id(handle))
        if registered is None or registered[0]() is not handle:
            raise SupervisorError(
                "sandbox_execution_launch_handle_required",
                "attempt binding requires launcher-captured pinned-runc provenance",
            )
        record = registered[1]
        if record.target.launch_mode != "private_bundle":
            raise SupervisorError(
                "sandbox_execution_launch_target_mismatch",
                "diagnostic runc launches cannot be bound to supervised attempts",
            )
        if record.execution_binding not in {None, binding}:
            raise SupervisorError(
                "sandbox_execution_launch_handle_conflict",
                "pinned-runc handle is already bound to another durable execution",
            )
        if record.execution_binding is None and any(
            other_id != id(handle)
            and reference() is not None
            and other_record.execution_binding == binding
            for other_id, (reference, other_record) in _RUNC_LAUNCH_RECORDS.items()
        ):
            raise SupervisorError(
                "sandbox_execution_launch_handle_conflict",
                "durable execution is already bound to another pinned-runc handle",
            )
        updated = _RuncLaunchRecord(
            process=record.process,
            pid=record.pid,
            process_identity=record.process_identity,
            target=record.target,
            execution_binding=binding,
            gate_release_authorized=record.gate_release_authorized,
            wait_lock=record.wait_lock,
            wait_returncode=record.wait_returncode,
            _test_waitpid=record._test_waitpid,
            _test_identity_reader=record._test_identity_reader,
        )
        _RUNC_LAUNCH_RECORDS[id(handle)] = (registered[0], updated)


def _register_runc_client_wait_receipt(receipt: _RuncClientWaitReceipt) -> None:
    key = id(receipt)
    contents = (
        receipt.pid,
        receipt.process_identity,
        receipt.returncode,
        receipt.attempt_id,
        receipt.claim_token,
        receipt.execution_id,
    )

    def discard(reference: weakref.ReferenceType[Any]) -> None:
        with _RUNC_WAIT_RECEIPTS_LOCK:
            current = _RUNC_WAIT_RECEIPTS.get(key)
            if current is not None and current[0] is reference:
                _RUNC_WAIT_RECEIPTS.pop(key, None)

    reference = weakref.ref(receipt, discard)
    with _RUNC_WAIT_RECEIPTS_LOCK:
        _RUNC_WAIT_RECEIPTS[key] = (reference, contents)


def _runc_client_process_identity(pid: int) -> str | None:
    """Capture a PID-reuse-resistant identity while the launched process exists."""

    if type(pid) is not int or pid <= 0 or not sys.platform.startswith("linux"):
        return None
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        fields = raw.rsplit(")", 1)[1].split()
        start_ticks = fields[19]
    except (FileNotFoundError, IndexError, OSError, ValueError):
        return None
    if not start_ticks.isdecimal():
        return None
    return f"linux:{pid}:{start_ticks}"


def _runc_client_wait_receipt_is_self_consistent(receipt: Any) -> bool:
    """Accept only an unmodified receipt returned by a registered handle."""

    if type(receipt) is not _RuncClientWaitReceipt:
        return False
    with _RUNC_WAIT_RECEIPTS_LOCK:
        registered = _RUNC_WAIT_RECEIPTS.get(id(receipt))
        if registered is None or registered[0]() is not receipt:
            return False
        expected = registered[1]
    actual = (
        receipt.pid,
        receipt.process_identity,
        receipt.returncode,
        receipt.attempt_id,
        receipt.claim_token,
        receipt.execution_id,
    )
    return (
        actual == expected
        and type(receipt.pid) is int
        and receipt.pid > 0
        and receipt.process_identity.startswith(f"linux:{receipt.pid}:")
        and receipt.process_identity.rsplit(":", 1)[-1].isdecimal()
        and type(receipt.returncode) is int
        and -255 <= receipt.returncode <= 255
        and isinstance(receipt.attempt_id, str)
        and bool(receipt.attempt_id)
        and type(receipt.claim_token) is int
        and receipt.claim_token > 0
        and isinstance(receipt.execution_id, str)
        and bool(receipt.execution_id)
    )


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


class _RuncLaunchSubmissionUnverified(SupervisorError):
    """A launch may have crossed the runtime boundary without returning a handle."""

    def __init__(
        self,
        message: str,
        *,
        client_pid: int | None,
        client_reaped: bool,
    ) -> None:
        super().__init__("sandbox_launch_submission_unverified", message)
        self.client_pid = client_pid
        self.client_reaped = client_reaped


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


def _spawn_pinned_runc(
    executable: _TrustedRuncExecutable,
    argv: Sequence[str],
    *,
    stdout: Any = subprocess.DEVNULL,
    stderr: Any = subprocess.DEVNULL,
) -> RuncLaunchHandle:
    """Unisolated held-FD primitive used only by the diagnostic helper.

    Start pinned runc with exactly one inherited fd-3 launch gate. The public
    API uses :func:`_spawn_pinned_runc_with_private_bundle` instead; this
    helper intentionally retains host-path bundle semantics for historical
    no-model diagnostics and must not be used for worker execution.

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
    process_identity: str | None = None
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
        process_identity = _runc_client_process_identity(process.pid)
        if process_identity is None:
            raise SupervisorError(
                "sandbox_runc_identity_unavailable",
                "pinned-runc client process identity could not be recorded before submission",
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
        launch_target = _RuncLaunchTarget(
            launch_mode="unisolated_diagnostic",
            argv=command,
            runc_executable_path=str(binary),
            runc_executable_sha256=executable.sha256,
        )
        handle = RuncLaunchHandle(
            _gate_writer=gate_write,
        )
        _register_runc_launch_handle(
            handle, process=process, process_identity=process_identity, target=launch_target
        )
        gate_write = -1
        return handle
    except BaseException as launch_error:
        cleanup_error: BaseException | None = None
        client_reap_error: BaseException | None = None
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
                client_reap_error = error
                if cleanup_error is None:
                    cleanup_error = error
        if launch_payload_may_have_been_delivered:
            cleanup_status = (
                "runc client cleanup is also unverified"
                if client_reap_error is not None or process is None
                else "runc client was reaped"
            )
            submission_error = _RuncLaunchSubmissionUnverified(
                "runc launch payload may have been submitted; "
                f"client_pid={process.pid if process is not None else 'unknown'}; "
                f"{cleanup_status}; owning attempt must stay fenced until the "
                "exact runtime state is independently reconciled",
                client_pid=process.pid if process is not None else None,
                client_reaped=process is not None and client_reap_error is None,
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


def _read_private_launcher_message(
    descriptor: int,
    process: subprocess.Popen[bytes],
    *,
    expected: bytes | None,
    timeout_seconds: float = _RUNC_NAMESPACE_SETUP_TIMEOUT_SECONDS,
) -> bytes:
    """Read one bounded namespace-launcher status byte or exec-close receipt."""

    deadline = time.monotonic() + timeout_seconds
    with selectors.DefaultSelector() as selector:
        selector.register(descriptor, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise TimeoutError("private OCI bundle launcher did not complete its handshake")
            message = os.read(descriptor, 1)
            if expected is None:
                if not message:
                    return b""
                if message == b"F":
                    details = os.read(descriptor, 2)
                    phase = details[:1].decode("ascii", errors="replace")
                    error_number = details[1] if len(details) > 1 else "unknown"
                    detail = os.read(descriptor, 128).decode("utf-8", errors="replace")
                    raise OSError(
                        "private OCI bundle launcher failed before runc exec "
                        f"(phase {phase}, errno {error_number})"
                        f"{': ' + detail if detail else ''}"
                    )
                raise OSError("private OCI bundle launcher returned an invalid exec receipt")
            if message != expected:
                if message == b"F":
                    details = os.read(descriptor, 2)
                    phase = details[:1].decode("ascii", errors="replace")
                    error_number = details[1] if len(details) > 1 else "unknown"
                    detail = os.read(descriptor, 128).decode("utf-8", errors="replace")
                    raise OSError(
                        "private OCI bundle launcher rejected namespace setup "
                        f"(phase {phase}, errno {error_number})"
                        f"{': ' + detail if detail else ''}"
                    )
                raise OSError("private OCI bundle launcher exited before its handshake")
            return message


def _write_child_user_namespace_maps(pid: int, uid: int, gid: int) -> None:
    """Install the minimum caller-to-self maps for a helper's user namespace."""

    if uid == 0 or gid == 0:
        raise SupervisorError(
            "invalid_oci_worker_policy", "OCI worker runtime must use a non-root caller identity"
        )

    def write_proc_file(name: str, value: bytes) -> None:
        descriptor = os.open(
            f"/proc/{pid}/{name}",
            os.O_WRONLY | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            remaining = memoryview(value)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError(f"could not write /proc/{pid}/{name}")
                remaining = remaining[written:]
        finally:
            os.close(descriptor)

    write_proc_file("setgroups", b"deny\n")
    write_proc_file("uid_map", f"{uid} {uid} 1\n".encode("ascii"))
    write_proc_file("gid_map", f"{gid} {gid} 1\n".encode("ascii"))
    for name, identity in (("uid_map", uid), ("gid_map", gid)):
        observed = Path(f"/proc/{pid}/{name}").read_text(encoding="ascii").split()
        if observed != [str(identity), str(identity), "1"]:
            raise OSError(f"/proc/{pid}/{name} did not retain the exact one-ID mapping")


def _open_private_bundle_fds(bundle_root: str | Path) -> tuple[Path, int, int]:
    """Open stable directory descriptors for the exact bundle and its rootfs."""

    bundle = _private_directory(bundle_root, code="invalid_oci_bundle", label="OCI bundle root")
    flags = (
        getattr(os, "O_PATH", os.O_RDONLY)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    bundle_fd = rootfs_fd = -1
    try:
        bundle_fd = os.open(bundle, flags)
        bundle_info = os.fstat(bundle_fd)
        bundle_path_info = os.stat(bundle, follow_symlinks=False)
        if (
            not stat.S_ISDIR(bundle_info.st_mode)
            or (bundle_info.st_dev, bundle_info.st_ino)
            != (bundle_path_info.st_dev, bundle_path_info.st_ino)
            or bundle_info.st_uid != os.geteuid()
            or stat.S_IMODE(bundle_info.st_mode) & 0o077
            or stat.S_IMODE(bundle_info.st_mode) & 0o700 != 0o700
        ):
            raise SupervisorError(
                "invalid_oci_bundle", "OCI bundle changed while its directory was opened"
            )
        rootfs_fd = os.open("rootfs", flags, dir_fd=bundle_fd)
        rootfs_info = os.fstat(rootfs_fd)
        rootfs_path_info = os.stat("rootfs", dir_fd=bundle_fd, follow_symlinks=False)
        if not stat.S_ISDIR(rootfs_info.st_mode) or (rootfs_info.st_dev, rootfs_info.st_ino) != (
            rootfs_path_info.st_dev,
            rootfs_path_info.st_ino,
        ):
            raise SupervisorError("invalid_oci_rootfs", "OCI bundle rootfs changed during open")
        return bundle, bundle_fd, rootfs_fd
    except BaseException:
        for descriptor in (bundle_fd, rootfs_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        raise


def _open_pinned_runtime_directory(path: str | Path, *, device: int, inode: int, label: str) -> int:
    """Open a pinned state/workspace directory without following its path later."""

    flags = (
        getattr(os, "O_PATH", os.O_RDONLY)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        observed = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (device, inode)
            or (observed.st_dev, observed.st_ino) != (device, inode)
        ):
            raise OSError(f"{label} path no longer matches its captured identity")
    except OSError as error:
        if "descriptor" in locals():
            os.close(descriptor)
        raise SupervisorError(
            "invalid_oci_runtime_paths", f"pinned runc {label} changed before fd binding"
        ) from error
    return descriptor


def _private_bundle_runc_launch_target(
    executable: _TrustedRuncExecutable,
    command: tuple[str, ...],
    bundle: Path,
    bundle_info: os.stat_result,
    rootfs_info: os.stat_result,
    rootfs_fd: int,
    config_json: bytes,
    expected_rootfs_sha256: str,
    expected_rootfs_closure_sha256: str,
) -> _RuncLaunchTarget:
    """Capture the exact command, config, and path identities launched by runc."""

    if (
        len(command) != 13
        or command[1] != "--root"
        or command[3:5] != ("--systemd-cgroup", "run")
        or command[5] != "--bundle"
        or command[7] != "--pid-file"
        or command[9:11] != ("--preserve-fds", "1")
        or command[11] != "--keep"
        or command[0] != str(executable.path)
        or command[6] != str(bundle)
    ):
        raise SupervisorError(
            "invalid_oci_command", "private-bundle launch command is not the exact supported form"
        )
    state_path = Path(command[2])
    pid_file_path = Path(command[8])
    container_id = command[12]
    if (
        not state_path.is_absolute()
        or not pid_file_path.is_absolute()
        or not _CONTAINER_ID.fullmatch(container_id)
    ):
        raise SupervisorError(
            "invalid_oci_command", "private-bundle launch target contains invalid paths or ID"
        )
    try:
        config = json.loads(config_json)
        mounts = config["mounts"]
        resources = config["linux"]["resources"]
        memory_limit_bytes = resources["memory"]["limit"]
        cpu_quota = resources["cpu"]["quota"]
        cpu_period = resources["cpu"]["period"]
        pids_limit = resources["pids"]["limit"]
        workspace_mounts = [
            mount
            for mount in mounts
            if isinstance(mount, dict) and mount.get("destination") == "/workspace"
        ]
        workspace_path = workspace_mounts[0]["source"]
        cgroups_path = config["linux"]["cgroupsPath"]
        if (
            len(workspace_mounts) != 1
            or workspace_mounts[0].get("type") != "bind"
            or not isinstance(workspace_path, str)
            or not Path(workspace_path).is_absolute()
            or cgroups_path != _oci_worker_cgroups_path(container_id)
            or any(
                type(value) is not int or value <= 0
                for value in (memory_limit_bytes, cpu_quota, cpu_period, pids_limit)
            )
        ):
            raise ValueError("OCI config does not bind one exact workspace and container ID")
    except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise SupervisorError(
            "invalid_oci_worker_policy",
            "private-bundle launch config lacks an exact workspace/container binding",
        ) from error

    directory_identities: list[tuple[int, int]] = []
    for path, label in ((state_path, "state root"), (Path(workspace_path), "workspace")):
        try:
            info = os.stat(path, follow_symlinks=False)
        except OSError as error:
            raise SupervisorError(
                "invalid_oci_runtime_paths", f"pinned runc {label} is unavailable"
            ) from error
        if not stat.S_ISDIR(info.st_mode):
            raise SupervisorError(
                "invalid_oci_runtime_paths", f"pinned runc {label} is not a real directory"
            )
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise SupervisorError(
                "invalid_oci_runtime_paths", f"pinned runc {label} is not owner-private"
            )
        directory_identities.append((info.st_dev, info.st_ino))
    (state_device, state_inode), (workspace_device, workspace_inode) = directory_identities
    if (state_device, state_inode) == (workspace_device, workspace_inode):
        raise SupervisorError(
            "invalid_oci_runtime_paths",
            "runc state root and workspace must be distinct directories",
        )
    rootfs_path = bundle / "rootfs"
    expected_rootfs_identity = (rootfs_info.st_dev, rootfs_info.st_ino)
    try:
        opened_rootfs = os.fstat(rootfs_fd)
        path_rootfs = os.stat(rootfs_path, follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened_rootfs.st_mode)
            or (opened_rootfs.st_dev, opened_rootfs.st_ino) != expected_rootfs_identity
            or (path_rootfs.st_dev, path_rootfs.st_ino) != expected_rootfs_identity
        ):
            raise OSError("opened rootfs no longer matches the captured bundle identity")
        # Bind the opened bundle rootfs to the operator-pinned content. This
        # catches replacement or mutation after config compilation and before
        # the private launcher submits runc.
        rootfs_manifest = rootfs_tree_manifest(rootfs_path)
        if (
            rootfs_manifest["rootfs_sha256"] != expected_rootfs_sha256
            or rootfs_manifest["closure_sha256"] != expected_rootfs_closure_sha256
        ):
            raise SupervisorError(
                "invalid_oci_rootfs",
                "OCI bundle rootfs no longer matches the compiler-sealed operator pins",
            )
        rootfs_bytes = sum(entry["size"] for entry in rootfs_manifest["entries"])
        rootfs_entry_count = len(rootfs_manifest["entries"])
        rootfs_snapshot_data_bytes = sum(
            ((entry["size"] + 4095) // 4096) * 4096
            for entry in rootfs_manifest["entries"]
            if entry["type"] in {"file", "symlink"}
        )
        rootfs_snapshot_limit_bytes = max(
            _ROOTFS_SNAPSHOT_OVERHEAD_BYTES,
            rootfs_snapshot_data_bytes + _ROOTFS_SNAPSHOT_OVERHEAD_BYTES,
        )
        if rootfs_snapshot_limit_bytes > _MAX_ROOTFS_SNAPSHOT_BYTES:
            raise SupervisorError(
                "invalid_oci_rootfs",
                "OCI rootfs exceeds the bounded private snapshot capacity",
            )
        opened_rootfs_after = os.fstat(rootfs_fd)
        path_rootfs_after = os.stat(rootfs_path, follow_symlinks=False)
        if (opened_rootfs_after.st_dev, opened_rootfs_after.st_ino) != expected_rootfs_identity or (
            path_rootfs_after.st_dev,
            path_rootfs_after.st_ino,
        ) != expected_rootfs_identity:
            raise OSError("rootfs changed identity while its content was verified")
    except SupervisorError:
        raise
    except OSError as error:
        raise SupervisorError(
            "invalid_oci_rootfs", "opened runc rootfs could not be verified against its path"
        ) from error
    return _RuncLaunchTarget(
        launch_mode="private_bundle",
        argv=command,
        runc_executable_path=str(executable.path),
        runc_executable_sha256=executable.sha256,
        config_sha256=hashlib.sha256(config_json).hexdigest(),
        bundle_path=str(bundle),
        bundle_device=bundle_info.st_dev,
        bundle_inode=bundle_info.st_ino,
        rootfs_path=str(rootfs_path),
        rootfs_device=rootfs_info.st_dev,
        rootfs_inode=rootfs_info.st_ino,
        rootfs_sha256=rootfs_manifest["rootfs_sha256"],
        rootfs_closure_sha256=rootfs_manifest["closure_sha256"],
        rootfs_entry_count=rootfs_entry_count,
        rootfs_bytes=rootfs_bytes,
        rootfs_snapshot_limit_bytes=rootfs_snapshot_limit_bytes,
        state_path=str(state_path),
        state_device=state_device,
        state_inode=state_inode,
        workspace_path=workspace_path,
        workspace_device=workspace_device,
        workspace_inode=workspace_inode,
        pid_file_path=str(pid_file_path),
        container_id=container_id,
        memory_limit_bytes=memory_limit_bytes,
        cpu_quota=cpu_quota,
        cpu_period=cpu_period,
        pids_limit=pids_limit,
    )


def _bind_private_runc_launch_fds(
    target: _RuncLaunchTarget,
    config_json: bytes,
    *,
    bundle_fd_path: str,
    state_fd: int,
    workspace_fd: int,
) -> tuple[_RuncLaunchTarget, bytes]:
    """Rewrite runc inputs to resolve state, bundle, and workspace by FD."""

    command = target.argv
    if (
        not isinstance(bundle_fd_path, str)
        or re.fullmatch(r"/proc/self/fd/(?:0|[1-9][0-9]{0,8})", bundle_fd_path) is None
    ):
        raise SupervisorError(
            "invalid_oci_runtime_paths", "private runc bundle path is not descriptor-addressed"
        )
    bundle_fd_number = int(bundle_fd_path.rsplit("/", 1)[-1])
    if (
        target.launch_mode != "private_bundle"
        or len(command) != 13
        or command[1] != "--root"
        or command[3:5] != ("--systemd-cgroup", "run")
        or command[5] != "--bundle"
        or command[7] != "--pid-file"
        or command[9:11] != ("--preserve-fds", "1")
        or command[11] != "--keep"
        or target.state_path is None
        or target.workspace_path is None
        or target.pid_file_path is None
        or target.container_id is None
        or command[2] != target.state_path
        or command[8] != target.pid_file_path
        or command[6] != target.bundle_path
        or command[12] != target.container_id
        or type(state_fd) is not int
        or type(workspace_fd) is not int
        or state_fd < 3
        or workspace_fd < 3
        or state_fd in {workspace_fd, bundle_fd_number}
        or workspace_fd == bundle_fd_number
    ):
        raise SupervisorError(
            "invalid_oci_runtime_paths", "private runc inputs cannot be bound to pinned FDs"
        )

    state_fd_path = f"/proc/self/fd/{state_fd}"
    workspace_source_path = f"/dev/shm/acp-{target.container_id}-workspace"
    pid_file = Path(target.pid_file_path)
    if (
        pid_file.parent != Path(target.state_path)
        or pid_file.name in {"", ".", ".."}
        or "/" in pid_file.name
    ):
        raise SupervisorError(
            "invalid_oci_runtime_paths", "runc PID file must be a direct child of its state root"
        )

    try:
        config = json.loads(config_json)
        mounts = config["mounts"]
        workspace_mounts = [
            mount
            for mount in mounts
            if isinstance(mount, dict) and mount.get("destination") == "/workspace"
        ]
        if (
            len(workspace_mounts) != 1
            or workspace_mounts[0].get("type") != "bind"
            or workspace_mounts[0].get("source") != target.workspace_path
        ):
            raise ValueError("OCI workspace mount no longer matches its captured path")
        workspace_mounts[0]["source"] = workspace_source_path
        effective_config = _canonical_oci_worker_config(config)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, SupervisorError) as error:
        raise SupervisorError(
            "invalid_oci_worker_policy", "private runc config cannot be rebound to workspace FD"
        ) from error

    effective_command = list(command)
    effective_command[2] = state_fd_path
    effective_command[6] = bundle_fd_path
    effective_command[8] = f"{state_fd_path}/{pid_file.name}"
    bound_target = replace(
        target,
        argv=tuple(effective_command),
        config_sha256=hashlib.sha256(effective_config).hexdigest(),
    )
    return bound_target, effective_config


def _spawn_pinned_runc_with_private_bundle(
    executable: _TrustedRuncExecutable,
    argv: Sequence[str],
    bundle_root: str | Path,
    config_json: bytes,
    *,
    rootfs_sha256: str,
    rootfs_closure_sha256: str,
    stdout: Any = subprocess.DEVNULL,
    stderr: Any = subprocess.DEVNULL,
    _before_workspace_open: Callable[[int, Path, int, int], None] | None = None,
    _before_runc_exec: Callable[[int, Path, int], None] | None = None,
) -> RuncLaunchHandle:
    """Exec pinned runc only after sealing its bundle in a private mount namespace.

    A mapped user namespace grants the helper mount authority over a private
    mount namespace without mapping host root. It creates a bounded detached
    tmpfs for the bundle and another for a content copy of the rootfs, verifies
    the copy through a returned directory FD, then marks both mounts read-only.
    The compiler policy supplies a bounded /dev tmpfs so runc can prepare its
    device nodes without making the rootfs writable. The helper is made
    non-dumpable before creating the snapshot, blocking same-UID procfs access.
    Runc consumes the bundle through its inherited mount FD, never through the
    mutable host pathname. The optional pre-exec callback is
    private test instrumentation; the supported public API never supplies it.
    """

    if os.geteuid() == 0:
        raise SupervisorError(
            "invalid_oci_worker_policy", "OCI worker runtime must be invoked by a non-root caller"
        )
    if not _supports_runc_fd_exec() or not hasattr(os, "pipe2"):
        raise SupervisorError(
            "invalid_oci_runtime",
            "private runc bundle launch requires Linux fd-based exec and close-on-exec pipes",
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
        or sum(len(os.fsencode(value)) + 1 for value in command) > _MAX_RUNC_LAUNCH_PAYLOAD_BYTES
    ):
        raise SupervisorError("invalid_oci_command", "runc argv is invalid or exceeds its limit")
    bundle_args = [index for index, value in enumerate(command) if value == "--bundle"]
    if len(bundle_args) != 1 or bundle_args[0] + 1 >= len(command):
        raise SupervisorError("invalid_oci_command", "runc argv must contain one bundle path")

    bundle, initial_bundle_fd, initial_rootfs_fd = _open_private_bundle_fds(bundle_root)
    initial_bundle_info = os.fstat(initial_bundle_fd)
    initial_rootfs_info = os.fstat(initial_rootfs_fd)
    import fcntl

    runtime_environment = _runc_client_environment()
    try:
        config_text = config_json.decode("ascii")
    except UnicodeDecodeError as error:
        os.close(initial_bundle_fd)
        os.close(initial_rootfs_fd)
        raise SupervisorError(
            "invalid_oci_worker_policy", "sealed OCI config is not ASCII"
        ) from error
    try:
        opened_descriptor = _open_verified_runc_executable(executable)
    except BaseException:
        os.close(initial_bundle_fd)
        os.close(initial_rootfs_fd)
        raise
    runc_fd = bundle_fd = rootfs_fd = -1
    state_path_fd = workspace_path_fd = state_fd = workspace_fd = -1
    start_read = start_write = status_read = status_write = -1
    map_ack_read = map_ack_write = exec_ack_read = exec_ack_write = -1
    gate_read = gate_write = -1
    snapshot_socket_parent: socket.socket | None = None
    snapshot_socket_child: socket.socket | None = None
    snapshot_rootfs_fd = private_bundle_fd = -1
    process: subprocess.Popen[bytes] | None = None
    process_identity: str | None = None
    launch_payload_may_have_been_delivered = False
    try:
        runc_fd = fcntl.fcntl(opened_descriptor, fcntl.F_DUPFD_CLOEXEC, 10)
        descriptor = opened_descriptor
        opened_descriptor = -1
        os.close(descriptor)
        bundle_fd = fcntl.fcntl(initial_bundle_fd, fcntl.F_DUPFD_CLOEXEC, 64)
        descriptor = initial_bundle_fd
        initial_bundle_fd = -1
        os.close(descriptor)
        rootfs_fd = fcntl.fcntl(initial_rootfs_fd, fcntl.F_DUPFD_CLOEXEC, 65)
        descriptor = initial_rootfs_fd
        initial_rootfs_fd = -1
        os.close(descriptor)
        bundle_fd_path = f"/proc/self/fd/{bundle_fd}"
        if command[bundle_args[0] + 1] != str(bundle):
            raise SupervisorError(
                "invalid_oci_bundle", "runc bundle argv does not match its pinned directory"
            )
        launch_target = _private_bundle_runc_launch_target(
            executable,
            command,
            bundle,
            initial_bundle_info,
            initial_rootfs_info,
            rootfs_fd,
            config_json,
            rootfs_sha256,
            rootfs_closure_sha256,
        )
        if (
            launch_target.state_device is None
            or launch_target.state_inode is None
            or launch_target.workspace_device is None
            or launch_target.workspace_inode is None
            or launch_target.workspace_path is None
        ):
            raise SupervisorError(
                "invalid_oci_runtime_paths", "state/workspace identities were not captured"
            )
        state_path_fd = _open_pinned_runtime_directory(
            launch_target.state_path,
            device=launch_target.state_device,
            inode=launch_target.state_inode,
            label="state root",
        )
        workspace_path_fd = _open_pinned_runtime_directory(
            launch_target.workspace_path,
            device=launch_target.workspace_device,
            inode=launch_target.workspace_inode,
            label="workspace",
        )
        state_fd = fcntl.fcntl(state_path_fd, fcntl.F_DUPFD_CLOEXEC, 66)
        workspace_fd = fcntl.fcntl(workspace_path_fd, fcntl.F_DUPFD_CLOEXEC, 67)
        os.close(state_path_fd)
        state_path_fd = -1
        os.close(workspace_path_fd)
        workspace_path_fd = -1
        launch_target, config_json = _bind_private_runc_launch_fds(
            launch_target,
            config_json,
            bundle_fd_path=bundle_fd_path,
            state_fd=state_fd,
            workspace_fd=workspace_fd,
        )
        config_text = config_json.decode("ascii")
        if any(
            type(value) is not int
            for value in (
                launch_target.rootfs_entry_count,
                launch_target.rootfs_bytes,
                launch_target.rootfs_snapshot_limit_bytes,
            )
        ):
            raise SupervisorError("invalid_oci_rootfs", "rootfs snapshot bounds were not captured")

        payload = (
            json.dumps(
                {
                    "argv": launch_target.argv,
                    "env": runtime_environment,
                    "config": config_text,
                    "bundle": command[bundle_args[0] + 1],
                    "bundle_fd_path": bundle_fd_path,
                    "bundle_device": initial_bundle_info.st_dev,
                    "bundle_inode": initial_bundle_info.st_ino,
                    "rootfs_device": initial_rootfs_info.st_dev,
                    "rootfs_inode": initial_rootfs_info.st_ino,
                    "state_fd": state_fd,
                    "state_device": launch_target.state_device,
                    "state_inode": launch_target.state_inode,
                    "workspace_fd": workspace_fd,
                    "workspace_device": launch_target.workspace_device,
                    "workspace_inode": launch_target.workspace_inode,
                    "workspace_path": launch_target.workspace_path,
                    "workspace_source": (f"/dev/shm/acp-{launch_target.container_id}-workspace"),
                    "rootfs_entry_count": launch_target.rootfs_entry_count,
                    "rootfs_bytes": launch_target.rootfs_bytes,
                    "rootfs_snapshot_limit_bytes": launch_target.rootfs_snapshot_limit_bytes,
                    "uid": os.geteuid(),
                    "gid": os.getegid(),
                },
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
            + b"\n"
        )
        if len(payload) > _MAX_RUNC_LAUNCH_PAYLOAD_BYTES:
            raise SupervisorError(
                "invalid_oci_command", "private runc payload exceeds its byte limit"
            )

        start_read, start_write = os.pipe2(os.O_CLOEXEC)
        status_read, status_write = os.pipe2(os.O_CLOEXEC)
        map_ack_read, map_ack_write = os.pipe2(os.O_CLOEXEC)
        exec_ack_read, exec_ack_write = os.pipe2(os.O_CLOEXEC)
        gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
        snapshot_socket_parent, snapshot_socket_child = socket.socketpair(
            socket.AF_UNIX,
            socket.SOCK_SEQPACKET | getattr(socket, "SOCK_CLOEXEC", 0),
        )
        snapshot_socket_parent.settimeout(_RUNC_NAMESPACE_SETUP_TIMEOUT_SECONDS)
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
                _RUNC_PRIVATE_BUNDLE_LAUNCHER,
                str(start_read),
                str(status_write),
                str(map_ack_read),
                str(exec_ack_read),
                str(gate_read),
                str(runc_fd),
                str(bundle_fd),
                str(rootfs_fd),
                str(snapshot_socket_child.fileno()),
            ],
            cwd="/",
            env=launcher_environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            close_fds=True,
            pass_fds=(
                start_read,
                status_write,
                map_ack_read,
                exec_ack_read,
                gate_read,
                runc_fd,
                bundle_fd,
                rootfs_fd,
                state_fd,
                workspace_fd,
                snapshot_socket_child.fileno(),
            ),
            start_new_session=True,
        )
        snapshot_socket_child.close()
        snapshot_socket_child = None
        os.close(state_fd)
        state_fd = -1
        os.close(workspace_fd)
        workspace_fd = -1
        process_identity = _runc_client_process_identity(process.pid)
        if process_identity is None:
            raise SupervisorError(
                "sandbox_runc_identity_unavailable",
                "pinned-runc client process identity could not be recorded before namespace setup",
            )
        descriptor = start_read
        start_read = -1
        os.close(descriptor)
        descriptor = status_write
        status_write = -1
        os.close(descriptor)
        descriptor = map_ack_read
        map_ack_read = -1
        os.close(descriptor)
        descriptor = exec_ack_read
        exec_ack_read = -1
        os.close(descriptor)
        descriptor = gate_read
        gate_read = -1
        os.close(descriptor)
        descriptor = runc_fd
        runc_fd = -1
        os.close(descriptor)
        descriptor = bundle_fd
        bundle_fd = -1
        os.close(descriptor)
        descriptor = rootfs_fd
        rootfs_fd = -1
        os.close(descriptor)

        remaining = memoryview(payload)
        while remaining:
            written = os.write(start_write, remaining)
            if written <= 0:
                raise OSError("could not write the bounded private runc payload")
            remaining = remaining[written:]
        descriptor = start_write
        start_write = -1
        os.close(descriptor)

        _read_private_launcher_message(status_read, process, expected=b"U")
        _write_child_user_namespace_maps(process.pid, os.geteuid(), os.getegid())
        if os.write(map_ack_write, b"M") != 1:
            raise OSError("could not acknowledge user-namespace maps")
        _read_private_launcher_message(status_read, process, expected=b"W")
        if _before_workspace_open is not None:
            if launch_target.workspace_path is None:
                raise SupervisorError(
                    "invalid_oci_runtime_paths", "workspace path was not captured"
                )
            _before_workspace_open(
                process.pid,
                Path(launch_target.workspace_path),
                launch_target.workspace_device,
                launch_target.workspace_inode,
            )
        if os.write(map_ack_write, b"A") != 1:
            raise OSError("could not acknowledge workspace mount lookup")
        descriptor = map_ack_write
        map_ack_write = -1
        os.close(descriptor)
        _read_private_launcher_message(status_read, process, expected=b"R")
        if snapshot_socket_parent is None:
            raise OSError("private rootfs snapshot channel is unavailable")
        try:
            packet, ancillary, message_flags, _address = snapshot_socket_parent.recvmsg(
                1, socket.CMSG_SPACE(2 * array.array("i").itemsize)
            )
        except OSError as error:
            raise SupervisorError(
                "invalid_oci_rootfs", "private rootfs snapshot descriptor was not received"
            ) from error
        received_descriptors: list[int] = []
        unexpected_control = False
        for level, message_type, data in ancillary:
            if level == socket.SOL_SOCKET and message_type == socket.SCM_RIGHTS:
                values = array.array("i")
                values.frombytes(data[: len(data) - (len(data) % values.itemsize)])
                received_descriptors.extend(values.tolist())
            else:
                unexpected_control = True
        if message_flags & socket.MSG_CTRUNC or unexpected_control:
            for received in received_descriptors:
                os.close(received)
            reason = (
                "rootfs snapshot descriptor packet was truncated"
                if message_flags & socket.MSG_CTRUNC
                else "unexpected rootfs snapshot control data"
            )
            raise SupervisorError("invalid_oci_rootfs", reason)
        if packet != b"S" or len(received_descriptors) != 2:
            for received in received_descriptors:
                os.close(received)
            raise SupervisorError("invalid_oci_rootfs", "rootfs snapshot descriptors are invalid")
        snapshot_rootfs_fd, private_bundle_fd = received_descriptors
        snapshot_socket_parent.close()
        snapshot_socket_parent = None
        snapshot_info = os.fstat(snapshot_rootfs_fd)
        private_bundle_info = os.fstat(private_bundle_fd)
        if (
            not stat.S_ISDIR(snapshot_info.st_mode)
            or os.fstatvfs(snapshot_rootfs_fd).f_flag & _ST_RDONLY == 0
            or (snapshot_info.st_dev, snapshot_info.st_ino)
            == (launch_target.rootfs_device, launch_target.rootfs_inode)
            or not stat.S_ISDIR(private_bundle_info.st_mode)
            or os.fstatvfs(private_bundle_fd).f_flag & _ST_RDONLY == 0
            or (private_bundle_info.st_dev, private_bundle_info.st_ino)
            == (launch_target.bundle_device, launch_target.bundle_inode)
        ):
            raise SupervisorError(
                "invalid_oci_rootfs",
                "private rootfs or bundle snapshot is not a distinct read-only mount",
            )
        snapshot_manifest = rootfs_tree_manifest_fd(snapshot_rootfs_fd)
        snapshot_bytes = sum(entry["size"] for entry in snapshot_manifest["entries"])
        if (
            snapshot_manifest["rootfs_sha256"] != launch_target.rootfs_sha256
            or snapshot_manifest["closure_sha256"] != launch_target.rootfs_closure_sha256
            or len(snapshot_manifest["entries"]) != launch_target.rootfs_entry_count
            or snapshot_bytes != launch_target.rootfs_bytes
        ):
            raise SupervisorError(
                "invalid_oci_rootfs",
                "private rootfs snapshot does not match the pre-launch reserved content",
            )
        launch_target = replace(
            launch_target,
            rootfs_snapshot_device=snapshot_info.st_dev,
            rootfs_snapshot_inode=snapshot_info.st_ino,
            rootfs_snapshot_sha256=snapshot_manifest["rootfs_sha256"],
            rootfs_snapshot_closure_sha256=snapshot_manifest["closure_sha256"],
            rootfs_snapshot_entry_count=len(snapshot_manifest["entries"]),
            rootfs_snapshot_bytes=snapshot_bytes,
        )
        if _before_runc_exec is not None:
            _before_runc_exec(process.pid, bundle, private_bundle_fd)
        # This byte is the runc-submission boundary: after it is attempted the
        # caller must reconcile exact runtime state if no handle is returned.
        launch_payload_may_have_been_delivered = True
        if os.write(exec_ack_write, b"X") != 1:
            raise OSError("could not authorize pinned runc exec")
        descriptor = exec_ack_write
        exec_ack_write = -1
        os.close(descriptor)
        _read_private_launcher_message(status_read, process, expected=None)
        descriptor = status_read
        status_read = -1
        os.close(descriptor)
        handle = RuncLaunchHandle(
            _gate_writer=gate_write,
            _bundle_path=bundle_fd_path,
        )
        _register_runc_launch_handle(
            handle, process=process, process_identity=process_identity, target=launch_target
        )
        gate_write = -1
        return handle
    except BaseException as launch_error:
        cleanup_error: BaseException | None = None
        client_reap_error: BaseException | None = None
        if gate_write >= 0:
            descriptor = gate_write
            gate_write = -1
            try:
                os.close(descriptor)
            except BaseException as error:
                cleanup_error = error
        if process is not None:
            try:
                _reap_failed_runc_launch(process)
            except BaseException as error:
                client_reap_error = error
                if cleanup_error is None:
                    cleanup_error = error
        if launch_payload_may_have_been_delivered:
            cleanup_status = (
                "runc client cleanup is also unverified"
                if client_reap_error is not None or process is None
                else "runc client was reaped"
            )
            raise _RuncLaunchSubmissionUnverified(
                "private runc exec may have been submitted; "
                f"client_pid={process.pid if process is not None else 'unknown'}; "
                f"{cleanup_status}; exact runtime state must be reconciled",
                client_pid=process.pid if process is not None else None,
                client_reaped=process is not None and client_reap_error is None,
            ) from (cleanup_error or launch_error)
        if cleanup_error is not None:
            raise cleanup_error from launch_error
        if isinstance(launch_error, SupervisorError):
            raise
        raise SupervisorError(
            "sandbox_bundle_setup_failed",
            f"private OCI namespace or bundle setup failed before runc exec: {launch_error}",
        ) from launch_error
    finally:
        descriptors_to_close = (
            opened_descriptor,
            initial_bundle_fd,
            initial_rootfs_fd,
            runc_fd,
            bundle_fd,
            rootfs_fd,
            state_path_fd,
            workspace_path_fd,
            state_fd,
            workspace_fd,
            start_read,
            start_write,
            status_read,
            status_write,
            map_ack_read,
            map_ack_write,
            exec_ack_read,
            exec_ack_write,
            gate_read,
        )
        opened_descriptor = initial_bundle_fd = initial_rootfs_fd = -1
        runc_fd = bundle_fd = rootfs_fd = -1
        state_path_fd = workspace_path_fd = state_fd = workspace_fd = -1
        start_read = start_write = status_read = status_write = -1
        map_ack_read = map_ack_write = exec_ack_read = exec_ack_write = -1
        gate_read = -1
        for descriptor in descriptors_to_close:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        for descriptor in (snapshot_rootfs_fd, private_bundle_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        for channel in (snapshot_socket_parent, snapshot_socket_child):
            if channel is not None:
                channel.close()


def spawn_pinned_runc(
    binding: _PinnedRuncWorkerConfig,
    state_root: str | Path,
    bundle_root: str | Path,
    workspace_root: str | Path,
    pid_file: str | Path,
    container_id: str,
    *,
    stdout: Any = subprocess.DEVNULL,
    stderr: Any = subprocess.DEVNULL,
) -> RuncLaunchHandle:
    """Launch sealed runc policy from a private, descriptor-anchored bundle.

    Callers cannot provide a second executable: the policy binding supplies the
    exact sealed pin. The launcher creates config.json only inside a detached
    private tmpfs attached to the already-open bundle directory using
    descriptor-based ``move_mount`` in a mapped user and mount namespace. It
    copies the pinned rootfs into a bounded private tmpfs and verifies the exact
    copied tree before runc exec as a separate read-only mount.
    Runc receives the tmpfs mount through an inherited FD, so same-UID host-path
    replacement cannot redirect the config handoff.
    This low-level API still does not reserve a supervisor attempt, attest
    runtime state, supervise cancellation/recovery, prove cleanup, or authorize
    result import; ``run_worker`` remains fail-closed for configured OCI.
    """

    if type(binding) is not _PinnedRuncWorkerConfig:
        raise SupervisorError(
            "invalid_oci_worker_policy", "worker launch requires a pinned runc config binding"
        )
    executable = binding.executable
    _verify_pinned_runc_worker_config(binding, executable)
    run_argv = build_runc_run_argv(
        executable,
        state_root,
        bundle_root,
        workspace_root,
        pid_file,
        container_id,
    )
    return _spawn_pinned_runc_with_private_bundle(
        executable,
        run_argv,
        bundle_root,
        binding.config_json,
        rootfs_sha256=binding.rootfs_sha256,
        rootfs_closure_sha256=binding.rootfs_closure_sha256,
        stdout=stdout,
        stderr=stderr,
    )


def _spawn_pinned_runc_for_unisolated_diagnostic(
    binding: _PinnedRuncWorkerConfig,
    state_root: str | Path,
    bundle_root: str | Path,
    workspace_root: str | Path,
    pid_file: str | Path,
    container_id: str,
    *,
    stdout: Any = subprocess.DEVNULL,
    stderr: Any = subprocess.DEVNULL,
) -> RuncLaunchHandle:
    """Diagnostic-only launch; never use this for supervised worker execution.

    It is retained for exact-host, no-model runc policy tests. The config is
    written in the caller's mount namespace, so same-UID bundle replacement
    remains possible until the outer ownership boundary is implemented.
    """

    if type(binding) is not _PinnedRuncWorkerConfig:
        raise SupervisorError(
            "invalid_oci_worker_policy", "worker launch requires a pinned runc config binding"
        )
    executable = binding.executable
    _verify_pinned_runc_worker_config(binding, executable)
    run_argv = build_runc_run_argv(
        executable,
        state_root,
        bundle_root,
        workspace_root,
        pid_file,
        container_id,
    )
    _write_pinned_runc_worker_config(binding, executable, bundle_root)
    return _spawn_pinned_runc(executable, run_argv, stdout=stdout, stderr=stderr)
