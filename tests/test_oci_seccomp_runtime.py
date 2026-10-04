from __future__ import annotations

import json
import platform
import subprocess
import sys
from pathlib import Path

import pytest

import agent_control_plane.supervisor.oci_worker as oci_worker
from agent_control_plane.supervisor.sandbox_workspace import copy_snapshot

_SYSCALL_PROBES = {
    "add_key": (0, 0, 0, 0, 0),
    "bpf": (0, 0, 0),
    "chroot": (0,),
    "delete_module": (0, 0),
    "finit_module": (-1, 0, 0),
    "fsconfig": (-1, 0, 0, 0, 0),
    "fsmount": (-1, 0, 0),
    "fsopen": (0, 0),
    "init_module": (0, 0, 0),
    "io_uring_enter": (-1, 0, 0, 0, 0, 0),
    "io_uring_register": (-1, 0, 0, 0),
    "io_uring_setup": (0, 0),
    "keyctl": (0, 0, 0, 0, 0),
    "kexec_file_load": (-1, -1, 0, 0, 0),
    "kexec_load": (0, 0, 0, 0),
    "mount": (0, 0, 0, 0, 0),
    "mount_setattr": (-1, 0, 0, 0, 0),
    "move_mount": (-1, 0, -1, 0, 0),
    "name_to_handle_at": (-100, 0, 0, 0, 0),
    "open_by_handle_at": (-1, 0, 0),
    "open_tree": (-1, 0, 0),
    "perf_event_open": (0, 0, -1, -1, 0),
    "pidfd_getfd": (-1, 0, 0),
    "pivot_root": (0, 0),
    "process_vm_readv": (-1, 0, 0, 0, 0, 0),
    "process_vm_writev": (-1, 0, 0, 0, 0, 0),
    "ptrace": (2, -1, 0, 0),
    "reboot": (0, 0, 0, 0),
    "request_key": (0, 0, 0, 0),
    "setns": (-1, 0),
    "swapon": (0, 0),
    "swapoff": (0,),
    "umount2": (0, 0),
    "unshare": (0,),
    # Invalid bits make the unfiltered operation fail without creating a
    # namespace or child. The generated masked rules must still match.
    "clone": (),
    "clone3": (0, 0),
    "socket": (2, 1, 0),
    "socketpair": (2, 1, 0, 0),
    # Invalid flags avoid allocating a descriptor if the rule is absent.
    "userfaultfd": (-1,),
}


_SECCOMP_PROBE = r"""
import ctypes
import ctypes.util
import json
import os
import socket
import sys
import threading

request = json.loads(sys.argv[1])
profile = request["profile"]
probe_args = request["probes"]
clone_flags = request["clone_flags"]
mode = request["mode"]
library_path = ctypes.util.find_library("seccomp")
if library_path is None:
    raise RuntimeError("libseccomp is required for the Linux runtime profile test")
seccomp = ctypes.CDLL(library_path, use_errno=True)
libc = ctypes.CDLL(None, use_errno=True)

class ArgCompare(ctypes.Structure):
    _fields_ = [
        ("arg", ctypes.c_uint),
        ("op", ctypes.c_int),
        ("datum_a", ctypes.c_uint64),
        ("datum_b", ctypes.c_uint64),
    ]

seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
seccomp.seccomp_init.restype = ctypes.c_void_p
seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
seccomp.seccomp_load.restype = ctypes.c_int
seccomp.seccomp_release.argtypes = [ctypes.c_void_p]
seccomp.seccomp_rule_add_array.argtypes = [
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.c_int,
    ctypes.c_uint,
    ctypes.POINTER(ArgCompare),
]
seccomp.seccomp_rule_add_array.restype = ctypes.c_int
seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
seccomp.seccomp_syscall_resolve_name.restype = ctypes.c_int
libc.prctl.restype = ctypes.c_int
libc.syscall.restype = ctypes.c_long
libc.socket.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
libc.socket.restype = ctypes.c_int
libc.socketpair.argtypes = [
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_int),
]
libc.socketpair.restype = ctypes.c_int

allow = 0x7FFF0000
errno_action = 0x00050000
comparisons = {"SCMP_CMP_NE": 1, "SCMP_CMP_MASKED_EQ": 7}
def resolve(name):
    number = seccomp.seccomp_syscall_resolve_name(name.encode("ascii"))
    if number < 0:
        raise RuntimeError(f"libseccomp cannot resolve configured syscall {name!r}")
    return number

resolved = {}
for rule in profile["syscalls"]:
    for name in rule["names"]:
        resolved[name] = resolve(name)

if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
    raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
ctx = seccomp.seccomp_init(allow)
if not ctx:
    raise RuntimeError("seccomp_init failed")
try:
    for rule in profile["syscalls"]:
        action = errno_action | (
            13 if mode == "marker" else int(rule["errnoRet"])
        )
        args = rule.get("args", [])
        comparisons_for_rule = (ArgCompare * len(args))(
            *(
                ArgCompare(
                    int(arg["index"]),
                    comparisons[arg["op"]],
                    int(arg["value"]),
                    int(arg.get("valueTwo", 0)),
                )
                for arg in args
            )
        )
        for name in rule["names"]:
            result = seccomp.seccomp_rule_add_array(
                ctx,
                action,
                resolved[name],
                len(args),
                comparisons_for_rule if args else None,
            )
            if result < 0:
                raise RuntimeError(f"seccomp_rule_add_array({name}) failed: {result}")
    result = seccomp.seccomp_load(ctx)
    if result < 0:
        raise RuntimeError(f"seccomp_load failed: {result}")
finally:
    seccomp.seccomp_release(ctx)

def check_syscall(name, args, expected_errno):
    ctypes.set_errno(0)
    syscall_args = [ctypes.c_long(value) for value in args]
    syscall_args.extend(ctypes.c_long(0) for _ in range(6 - len(syscall_args)))
    result = libc.syscall(
        ctypes.c_long(resolve(name)), *syscall_args
    )
    actual_errno = ctypes.get_errno()
    if result != -1 or actual_errno != expected_errno:
        raise AssertionError(
            f"{name}: expected errno {expected_errno}, got result={result}, errno={actual_errno}"
        )

status = open("/proc/self/status", encoding="ascii").read()
seccomp_mode = next(
    int(line.split()[1]) for line in status.splitlines() if line.startswith("Seccomp:")
)
if seccomp_mode != 2:
    raise AssertionError(f"expected Seccomp: 2, got {seccomp_mode}")

if mode == "marker":
    marker_errno = 13  # EACCES distinguishes a matched filter from kernel EPERM.
    for name, args in probe_args.items():
        if name == "clone":
            continue
        check_syscall(name, args, marker_errno)
    invalid_high_bit = 1 << 63
    for flag in clone_flags:
        flags = flag | invalid_high_bit
        signed_flags = ctypes.c_long(flags).value
        check_syscall("clone", (signed_flags, 0, 0, 0, 0), marker_errno)

    descriptor = libc.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    if descriptor < 0:
        raise OSError(ctypes.get_errno(), "AF_UNIX socket should be allowed")
    os.close(descriptor)
    pair = (ctypes.c_int * 2)()
    if libc.socketpair(
        socket.AF_UNIX,
        socket.SOCK_STREAM,
        0,
        ctypes.cast(pair, ctypes.POINTER(ctypes.c_int)),
    ) != 0:
        raise OSError(ctypes.get_errno(), "AF_UNIX socketpair should be allowed")
    os.close(pair[0])
    os.close(pair[1])

    child = os.fork()
    if child == 0:
        os._exit(0)
    _, wait_status = os.waitpid(child, 0)
    if wait_status != 0:
        raise AssertionError(f"ordinary fork exited with wait status {wait_status}")
    completed = []
    worker = threading.Thread(target=lambda: completed.append(True))
    worker.start()
    worker.join(timeout=5)
    if worker.is_alive() or completed != [True]:
        raise AssertionError("ordinary thread creation failed")
    checked = len(probe_args) + len(clone_flags)
else:
    check_syscall("clone3", probe_args["clone3"], 38)  # ENOSYS for libc fallback.
    checked = 1

print(json.dumps({"seccomp": seccomp_mode, "checked": checked, "mode": mode}))
"""


def _compiled_seccomp_profile(tmp_path: Path) -> dict:
    bundle = tmp_path / "bundle"
    rootfs = bundle / "rootfs"
    bundle.mkdir(mode=0o700)
    for relative in ("bin", "usr/bin", "proc", "workspace", "tmp", "home/agent"):
        (rootfs / relative).mkdir(parents=True, mode=0o700)
    for relative in ("bin/sh", "usr/bin/busybox"):
        executable = rootfs / relative
        executable.write_text("fixture only; not executed\n", encoding="ascii")
        executable.chmod(0o700)

    source = tmp_path / "source-worktree"
    source.mkdir(mode=0o700)
    (source / "README.md").write_text("profile compiler fixture\n", encoding="ascii")
    snapshot_parent = tmp_path / "attempt"
    snapshot_parent.mkdir(mode=0o700)
    snapshot = copy_snapshot(source, snapshot_parent / "workspace")
    config = oci_worker.build_oci_worker_config(
        bundle,
        snapshot,
        ("/usr/bin/busybox", "true"),
        container_id="acp-seccomp-runtime-test",
        memory_bytes=64 * 1024 * 1024,
        pids_limit=8,
        cpu_quota_us=50_000,
    )
    return config["linux"]["seccomp"]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux seccomp runtime only")
def test_generated_oci_seccomp_profile_resolves_and_enforces_rules(tmp_path: Path) -> None:
    machine = platform.machine().casefold()
    if machine not in oci_worker._SUPPORTED_SECCOMP_MACHINES:
        pytest.skip(f"OCI seccomp profile does not target {machine}")

    profile = _compiled_seccomp_profile(tmp_path)
    names = {name for rule in profile["syscalls"] for name in rule["names"]}
    assert set(_SYSCALL_PROBES) == names
    clone_flags = sorted(oci_worker._CLONE_NEW_NAMESPACE_FLAGS)
    request = {
        "profile": profile,
        "probes": {name: list(args) for name, args in _SYSCALL_PROBES.items()},
        "clone_flags": clone_flags,
    }

    for mode in ("marker", "production"):
        result = subprocess.run(
            [sys.executable, "-c", _SECCOMP_PROBE, json.dumps({**request, "mode": mode})],
            capture_output=True,
            check=False,
            text=True,
            timeout=20,
            env={},
        )
        assert result.returncode == 0, (
            f"libseccomp profile probe failed in {mode} mode\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
        receipt = json.loads(result.stdout)
        assert receipt["seccomp"] == 2
        assert receipt["checked"] == (
            1 if mode == "production" else len(_SYSCALL_PROBES) + len(clone_flags)
        )
