from __future__ import annotations

import ctypes
import os
import signal
import sys
import time

MONITOR_MODE = "__ACP_MONITOR_PROCESS_TREE_V1__"


def _linux_children() -> list[int]:
    try:
        with open(
            f"/proc/{os.getpid()}/task/{os.getpid()}/children", encoding="ascii"
        ) as children_file:
            raw = children_file.read()
    except OSError:
        return []
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


def _monitor_linux(command: list[str]) -> int:
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
    child = os.fork()
    if child == 0:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        try:
            os.execvp(command[0], command)
        except OSError:
            os._exit(126)
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


def _monitor_single_process(command: list[str]) -> int:
    """Retain lifecycle FDs while a no-fork Darwin sandbox runs one PID."""

    terminate_requested = False

    def request_termination(_signum: int, _frame: object) -> None:
        nonlocal terminate_requested
        terminate_requested = True

    signal.signal(signal.SIGTERM, request_termination)
    signal.signal(signal.SIGINT, request_termination)
    child = os.fork()
    if child == 0:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        try:
            os.execvp(command[0], command)
        except OSError:
            os._exit(126)
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
    if len(sys.argv) < 3:
        return 125
    handshake_fd = int(sys.argv[1])
    monitor = sys.argv[2] == MONITOR_MODE
    command = sys.argv[3:] if monitor else sys.argv[2:]
    if not command:
        return 125
    try:
        permission = os.read(handshake_fd, 1)
    finally:
        os.close(handshake_fd)
    if permission != b"G":
        return 125
    if monitor and sys.platform.startswith("linux"):
        return _monitor_linux(command)
    if monitor and sys.platform == "darwin":
        return _monitor_single_process(command)
    if monitor:
        return 125
    try:
        os.execvp(command[0], command)
    except OSError:
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
