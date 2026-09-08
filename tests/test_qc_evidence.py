"""A blocked QC verdict must say what failed.

Measured during the #1626 dogfood: a real `acp qc` run whose pytest command failed
produced a finding whose entire evidence was `exit=1; Using CPython 3.12.14 …
Creating virtual environment at: .venv / Installed 35 packages in 18ms`. The whole
pytest failure summary — which test, which assertion — was in the command's stdout and
never reached the finding, because evidence was `stderr or stdout` and the runner had
written something to stderr.

Every mainstream test runner reports failures on stdout, so this was the normal case,
not an edge one. README and ARCHITECTURE sell the verdict as replayable evidence; a
finding that says "command failed" and shows the venv being created is not evidence.
"""

from __future__ import annotations

import shlex
import sys
from pathlib import Path

import pytest
from support import init_repo, make_task, write_config

from agent_control_plane.git_supervisor import GitSupervisor

STDOUT_MARKER = "FAILED tests/test_thing.py::test_the_important_one"
STDERR_MARKER = "warning: something on the error stream"


def noisy_failing_command() -> str:
    """A command that writes to BOTH streams and fails, like a real test runner."""

    source = (
        "import sys; "
        f"print({STDOUT_MARKER!r}); "
        f"print({STDERR_MARKER!r}, file=sys.stderr); "
        "sys.exit(1)"
    )
    return f"{shlex.quote(sys.executable)} -c {shlex.quote(source)}"


@pytest.fixture
def blocked_verdict(tmp_path: Path):
    repo = init_repo(tmp_path)
    write_config(repo, qc_commands=[noisy_failing_command()])
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    worktree = Path(attempt["worktree"])
    (worktree / "alpha.txt").write_text("candidate\n", encoding="utf-8")
    import subprocess

    subprocess.run(
        ["git", "-C", str(worktree), "commit", "-am", "change"],
        check=True,
        capture_output=True,
    )
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    return supervisor.run_qc(submission["id"], "independent-qc")


def command_evidence(verdict) -> str:
    findings = [
        finding
        for finding in verdict["findings"]
        if finding["requirement"] == "deterministic QC command passes"
    ]
    assert findings, "a failing QC command must produce a finding"
    return findings[0]["evidence"]


def test_evidence_names_the_failure_from_stdout(blocked_verdict) -> None:
    """The gate. Red against `stderr or stdout`, which discards stdout entirely."""

    assert blocked_verdict["verdict"] == "block"
    assert STDOUT_MARKER in command_evidence(blocked_verdict)


def test_evidence_keeps_stderr_too(blocked_verdict) -> None:
    """Fixing the stdout gap must not create the mirror-image one.

    On macOS a sandbox denial ("Operation not permitted") arrives on stderr, and that
    is the whole diagnosis in that case.
    """

    assert STDERR_MARKER in command_evidence(blocked_verdict)


def test_evidence_labels_which_stream_is_which(blocked_verdict) -> None:
    evidence = command_evidence(blocked_verdict)
    assert "stdout" in evidence
    assert "stderr" in evidence
    # stdout first: it is where the failure summary lives, and evidence is truncated.
    assert evidence.index("stdout") < evidence.index("stderr")


def test_a_long_output_keeps_both_ends() -> None:
    """A plain tail loses the first traceback; a plain head loses the summary.

    Both are what a reviewer reads, so the window keeps each end and says how much it
    dropped rather than silently cutting.
    """

    window = GitSupervisor._evidence_window
    text = "FIRST-FAILURE\n" + ("x" * 20000) + "\nLAST-SUMMARY"

    kept = window(text)

    assert "FIRST-FAILURE" in kept
    assert "LAST-SUMMARY" in kept
    assert "omitted" in kept
    assert len(kept) < len(text)


def test_a_short_output_is_not_mangled() -> None:
    assert GitSupervisor._evidence_window("  brief and complete  ") == "brief and complete"


def test_evidence_still_reports_the_exit_code(blocked_verdict) -> None:
    assert "exit=1" in command_evidence(blocked_verdict)
