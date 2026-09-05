"""A zombie is dead, and the containment check has to know that.

`_terminate_unexpected_monitor_target` SIGKILLs the exact command PID and then refuses
to return until the kill is proven. It proved it by watching the PID's start-time
identity change — but a zombie keeps both its /proc entry and its start time until its
parent reaps it, so a process that had already exited read as still running and a
successful containment kill was reported as
"command survived unexpected kernel monitor termination".

Measured under ACP's own QC (#1707): state `Z` before the SIGKILL and still `Z` after
the three-second wait. The process died; nothing in that nested arrangement reaped it.
"""

from __future__ import annotations

import subprocess
import sys
import time

import pytest

from agent_control_plane.git_supervisor import GitSupervisor


def wait_for_zombie(pid: int, timeout: float = 10.0) -> str | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = GitSupervisor._process_state(pid)
        if state == "Z":
            return state
        time.sleep(0.01)
    return GitSupervisor._process_state(pid)


@pytest.fixture
def zombie():
    """A child that has exited and deliberately has not been reaped."""

    child = subprocess.Popen([sys.executable, "-c", "pass"])
    try:
        assert wait_for_zombie(child.pid) == "Z", "could not produce a zombie to test with"
        yield child
    finally:
        child.wait()


def test_a_zombie_reports_state_z(zombie) -> None:
    assert GitSupervisor._process_state(zombie.pid) == "Z"


def test_a_zombie_still_answers_the_identity_check(zombie) -> None:
    """The reason the bug existed: identity alone cannot see the difference."""

    assert GitSupervisor._process_identity(zombie.pid) is not None


def test_a_zombie_counts_as_exited(zombie) -> None:
    """The fix. Red before it: identity matched, so the process looked alive."""

    identity = GitSupervisor._process_identity(zombie.pid)
    assert identity is not None
    assert GitSupervisor._process_has_exited(zombie.pid, identity) is True


def test_a_live_process_does_not_count_as_exited() -> None:
    """The control. Without it, `return True` would pass every test above."""

    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        identity = GitSupervisor._process_identity(child.pid)
        assert identity is not None
        assert GitSupervisor._process_state(child.pid) != "Z"
        assert GitSupervisor._process_has_exited(child.pid, identity) is False
    finally:
        child.kill()
        child.wait()


def test_a_reaped_process_counts_as_exited() -> None:
    """A PID that is gone entirely, which is the case that always worked."""

    child = subprocess.Popen([sys.executable, "-c", "pass"])
    identity = GitSupervisor._process_identity(child.pid)
    child.wait()
    assert identity is not None
    assert GitSupervisor._process_has_exited(child.pid, identity) is True


def test_a_different_process_at_the_same_pid_counts_as_exited(zombie) -> None:
    """PID reuse must still read as exited — that is what the identity is for."""

    assert GitSupervisor._process_has_exited(zombie.pid, "linux:0:not-this-process") is True
