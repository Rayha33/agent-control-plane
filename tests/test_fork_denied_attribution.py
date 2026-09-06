"""A gate that could not run must not blame the worker for it.

Measured on macOS before this existed: a QC command that forks is denied by the Darwin
containment profile, and ACP recorded

    verdict        block
    finding        command failed: /usr/bin/true && /usr/bin/true
    required_fix   fix the failure and submit a new committed attempt
    qc_runs        1 row, submission blocked, task blocked
    bundle         signed

The candidate was fine; the host denies fork. That is a false attribution made durable
and signed, told to a worker who cannot act on it — the failure class this project
exists to prevent, pointed at its own users.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from support import init_repo, make_task, write_config

from agent_control_plane.git_supervisor import (
    FORK_DENIED_EXIT_CODE,
    FORK_DENIED_SIGNATURE,
    GitSupervisor,
)

FORKING_COMMAND = "/usr/bin/true && /usr/bin/true"

requires_fork_denial = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="only the Darwin containment profile denies a contained command its fork",
)


def result(exit_code: int, stderr: str = "", stdout: str = "") -> dict:
    return {"exit_code": exit_code, "stderr": stderr, "stdout": stdout}


def test_a_denied_fork_is_recognised() -> None:
    assert GitSupervisor._is_fork_denial(
        result(FORK_DENIED_EXIT_CODE, f"/bin/sh: {FORK_DENIED_SIGNATURE}")
    )


def test_an_ordinary_failure_is_not_mistaken_for_a_denied_fork() -> None:
    """The control. Exit code alone would misattribute in the other direction.

    Measured with fork fully available: a missing binary exits 127. Treating any
    non-zero exit as a platform problem would excuse real broken commands.
    """

    assert not GitSupervisor._is_fork_denial(
        result(127, "/bin/sh: /usr/bin/nosuchthing: No such file or directory")
    )
    assert not GitSupervisor._is_fork_denial(result(1, "AssertionError"))
    # Both halves are required, so neither on its own is enough.
    assert not GitSupervisor._is_fork_denial(result(FORK_DENIED_EXIT_CODE, "killed by a signal"))
    assert not GitSupervisor._is_fork_denial(result(1, f"/bin/sh: {FORK_DENIED_SIGNATURE}"))


def test_the_finding_for_a_denied_fork_does_not_blame_the_worker() -> None:
    finding = GitSupervisor._command_finding(
        "uv run pytest", result(FORK_DENIED_EXIT_CODE, f"/bin/sh: {FORK_DENIED_SIGNATURE}")
    )
    assert "could not run on this host" in finding["finding"]
    assert "not a defect in the submitted work" in finding["required_fix"]
    # The sentence that made the old record false.
    assert "submit a new committed attempt" not in finding["required_fix"]
    assert finding["requirement"] == "the host can run the configured gate"


def test_the_finding_for_a_real_failure_still_blames_the_work() -> None:
    """The other control: the fix must not excuse commands that genuinely failed."""

    finding = GitSupervisor._command_finding("pytest", result(1, "1 failed", "FAILED test_x"))
    assert finding["finding"].startswith("command failed:")
    assert finding["required_fix"] == "fix the failure and submit a new committed attempt"
    assert finding["requirement"] == "deterministic QC command passes"


@requires_fork_denial
def test_a_fork_denied_qc_run_records_the_host_not_the_candidate(tmp_path: Path) -> None:
    """End to end, against the real containment, on the platform that denies fork."""

    repo = init_repo(tmp_path)
    write_config(repo, qc_commands=[FORKING_COMMAND])
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    worktree = Path(attempt["worktree"])
    (worktree / "alpha.txt").write_text("candidate\n", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(worktree), "commit", "-am", "change"], check=True, capture_output=True
    )
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])

    verdict = supervisor.run_qc(submission["id"], "independent-qc")

    command_findings = [
        finding
        for finding in verdict["findings"]
        if finding["requirement"] == "the host can run the configured gate"
    ]
    assert command_findings, verdict["findings"]
    assert all(
        "submit a new committed attempt" not in finding["required_fix"]
        for finding in verdict["findings"]
    )


@requires_fork_denial
def test_the_fork_canary_measures_the_platform(tmp_path: Path) -> None:
    """Not a tautology: it must follow `_run_process`, not `sys.platform`.

    A canary implemented as `return sys.platform != "darwin"` would satisfy a bare
    platform assertion, so this drives the real containment and then feeds it a
    fabricated fork-allowed result to prove the answer tracks the measurement.
    """

    supervisor = GitSupervisor(init_repo(tmp_path))
    assert supervisor._containment_permits_fork() is False

    supervisor._fork_support = None
    supervisor._run_process = lambda *a, **k: (  # type: ignore[method-assign]
        result(7) if "control" in a[1] else result(0)  # a[1] is the label, a[0] the argv
    )
    assert supervisor._containment_permits_fork() is True
