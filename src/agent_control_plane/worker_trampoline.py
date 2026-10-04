from __future__ import annotations

import ctypes
import os
import signal
import sys
import time
from collections.abc import Sequence

MONITOR_MODE = "__ACP_MONITOR_PROCESS_TREE_V2__"
LIFECYCLE_FDS_PREFIX = "__ACP_LIFECYCLE_FDS_V1__="
_FD3_SOURCE_PREFIX = "__ACP_FD3_SOURCE_V1__="


def _monitor_argv_prefix(
    handshake_fd: int,
    target_fd: int,
    start_fd: int,
    lifecycle_fds: Sequence[int],
    fd3_source: int | None,
) -> list[str]:
    """Build the versioned monitor header shared by both supervisor launch paths."""

    lifecycle_argument = LIFECYCLE_FDS_PREFIX + ",".join(
        str(descriptor) for descriptor in sorted(set(lifecycle_fds))
    )
    fd3_source_argument = _FD3_SOURCE_PREFIX + ("" if fd3_source is None else str(fd3_source))
    return [
        str(handshake_fd),
        str(target_fd),
        str(start_fd),
        MONITOR_MODE,
        lifecycle_argument,
        fd3_source_argument,
    ]


def _close_lifecycle_fds(lifecycle_fds: tuple[int, ...]) -> None:
    for descriptor in lifecycle_fds:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _report_target(target_fd: int, child: int) -> None:
    if target_fd < 0:
        return
    try:
        os.write(target_fd, f"{child}\n".encode("ascii"))
    finally:
        os.close(target_fd)


def _await_target_release(start_fd: int) -> bool:
    if start_fd < 0:
        return True
    try:
        return os.read(start_fd, 1) == b"G"
    finally:
        os.close(start_fd)


def _map_fd3_source(fd3_source: int | None) -> None:
    if fd3_source is None:
        return
    if fd3_source == 3:
        os.set_inheritable(3, True)
        return
    os.dup2(fd3_source, 3, inheritable=True)
    os.close(fd3_source)


def _linux_children() -> list[int] | None:
    try:
        with open(
            f"/proc/{os.getpid()}/task/{os.getpid()}/children", encoding="ascii"
        ) as children_file:
            raw = children_file.read()
    except OSError:
        return None
    return [int(value) for value in raw.split() if value.isdigit()]


def _reap_adopted() -> None:
    while True:
        try:
            waited, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if waited == 0:
            return


def _kill_adopted_processes() -> None:
    """Kill every orphan adopted by this Linux subreaper, or stay alive.

    A bounded retry would eventually orphan an uninterruptible descendant to
    PID 1. Remaining alive is the fail-closed state: the monitor and any
    inherited lifecycle lock continue to fence recovery until the kernel has
    actually reaped the complete tree.
    """

    own_group = os.getpgrp()
    while True:
        children = _linux_children()
        if children is None:
            # An unreadable procfs snapshot is not proof that every adopted
            # descendant exited. Retain lifecycle locks and try again.
            time.sleep(0.01)
            continue
        if not children:
            return
        for pid in children:
            try:
                group = os.getpgid(pid)
                if group != own_group:
                    os.killpg(group, signal.SIGKILL)
                else:
                    os.kill(pid, signal.SIGKILL)
            except (PermissionError, ProcessLookupError):
                pass
        _reap_adopted()
        time.sleep(0.01)


def _monitor_linux(
    command: list[str],
    lifecycle_fds: tuple[int, ...],
    fd3_source: int | None,
    target_fd: int,
    start_fd: int,
) -> int:
    # PR_SET_CHILD_SUBREAPER makes double-fork/setsid daemons reparent here,
    # not to PID 1. The monitor does not return the command's exit status until
    # every adopted process has been killed and reaped.
    pr_set_child_subreaper = 36
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(pr_set_child_subreaper, 1, 0, 0, 0) != 0:
        return 125
    terminate_requested = False

    def request_termination(_signum: int, _frame: object) -> None:
        nonlocal terminate_requested
        terminate_requested = True

    signal.signal(signal.SIGTERM, request_termination)
    signal.signal(signal.SIGINT, request_termination)
    monitor_pid = os.getpid()
    child = os.fork()
    if child == 0:
        if target_fd >= 0:
            os.close(target_fd)
        _close_lifecycle_fds(lifecycle_fds)
        if not _await_target_release(start_fd):
            os._exit(125)
        try:
            _map_fd3_source(fd3_source)
        except OSError:
            os._exit(125)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        # If a same-UID command kills its direct monitor, the kernel must kill
        # that command rather than letting it outlive the process-tree fence.
        pr_set_pdeathsig = 1
        if libc.prctl(pr_set_pdeathsig, signal.SIGKILL, 0, 0, 0) != 0:
            os._exit(125)
        if os.getppid() != monitor_pid:
            os._exit(125)
        try:
            os.execvp(command[0], command)
        except OSError:
            os._exit(126)
    if fd3_source is not None:
        _close_lifecycle_fds((fd3_source,))
    if start_fd >= 0:
        os.close(start_fd)
    _report_target(target_fd, child)
    status: int | None = None
    while True:
        if terminate_requested:
            break
        try:
            waited, candidate = os.waitpid(child, os.WNOHANG)
        except InterruptedError:
            continue
        if waited == child:
            status = candidate
            break
        time.sleep(0.002)
    _kill_adopted_processes()
    if terminate_requested:
        return 124
    if status is None:
        return 125
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 125


def _monitor_single_process(
    command: list[str],
    lifecycle_fds: tuple[int, ...],
    fd3_source: int | None,
    target_fd: int,
    start_fd: int,
) -> int:
    """Retain lifecycle FDs while a no-fork Darwin sandbox runs one PID."""

    terminate_requested = False

    def request_termination(_signum: int, _frame: object) -> None:
        nonlocal terminate_requested
        terminate_requested = True

    signal.signal(signal.SIGTERM, request_termination)
    signal.signal(signal.SIGINT, request_termination)
    child = os.fork()
    if child == 0:
        if target_fd >= 0:
            os.close(target_fd)
        _close_lifecycle_fds(lifecycle_fds)
        if not _await_target_release(start_fd):
            os._exit(125)
        try:
            _map_fd3_source(fd3_source)
        except OSError:
            os._exit(125)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        try:
            os.execvp(command[0], command)
        except OSError:
            os._exit(126)
    if fd3_source is not None:
        _close_lifecycle_fds((fd3_source,))
    if start_fd >= 0:
        os.close(start_fd)
    _report_target(target_fd, child)
    status: int | None = None
    while True:
        if terminate_requested:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            waited, candidate = os.waitpid(child, os.WNOHANG)
        except InterruptedError:
            continue
        if waited == child:
            status = candidate
            break
        time.sleep(0.002)
    if terminate_requested:
        return 124
    if status is not None and os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if status is not None and os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 125


def main() -> int:
    if len(sys.argv) < 5:
        return 125
    handshake_fd = int(sys.argv[1])
    target_fd = int(sys.argv[2])
    start_fd = int(sys.argv[3])
    monitor = sys.argv[4] == MONITOR_MODE
    lifecycle_fds: tuple[int, ...] = ()
    fd3_source: int | None = None
    if monitor:
        if (
            len(sys.argv) < 7
            or not sys.argv[5].startswith(LIFECYCLE_FDS_PREFIX)
            or not sys.argv[6].startswith(_FD3_SOURCE_PREFIX)
        ):
            return 125
        raw_lifecycle_fds = sys.argv[5].removeprefix(LIFECYCLE_FDS_PREFIX)
        try:
            lifecycle_fds = tuple(int(value) for value in raw_lifecycle_fds.split(",") if value)
        except ValueError:
            return 125
        raw_fd3_source = sys.argv[6].removeprefix(_FD3_SOURCE_PREFIX)
        if raw_fd3_source:
            if not raw_fd3_source.isdecimal():
                return 125
            fd3_source = int(raw_fd3_source)
            if (
                fd3_source < 3
                or fd3_source in lifecycle_fds
                or fd3_source in {handshake_fd, target_fd, start_fd}
            ):
                return 125
        command = sys.argv[7:]
    else:
        command = sys.argv[5:]
    if not command:
        return 125
    try:
        permission = os.read(handshake_fd, 1)
    finally:
        os.close(handshake_fd)
    if permission != b"G":
        return 125
    if monitor and sys.platform.startswith("linux"):
        return _monitor_linux(command, lifecycle_fds, fd3_source, target_fd, start_fd)
    if monitor and sys.platform == "darwin":
        return _monitor_single_process(command, lifecycle_fds, fd3_source, target_fd, start_fd)
    if monitor:
        return 125
    try:
        os.execvp(command[0], command)
    except OSError:
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
