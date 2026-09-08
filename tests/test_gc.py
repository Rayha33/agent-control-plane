"""`acp gc` reclaims what nothing is using, and nothing else.

Measured before this existed: one claim -> submit -> qc -> integrate cycle left the
attempt worktree on disk, still registered with `git worktree list`, with its task
branch alive — per task, forever, with no subcommand to reclaim any of it.

Every refusal below is asserted against a real non-dry-run sweep with the retention
window set to zero, not against the report alone. A gc that prints "retained" and
deletes anyway would pass the weaker check.
"""

from __future__ import annotations

import sqlite3
import subprocess
from pathlib import Path

import pytest
from support import git, init_repo, make_task

from agent_control_plane.cli import parse_duration
from agent_control_plane.git_supervisor import (
    CLEANUP_FENCE_EPOCH,
    GitSupervisor,
    SupervisorError,
)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return init_repo(tmp_path)


def commit_change(attempt: dict, name: str, content: str) -> None:
    worktree = Path(attempt["worktree"])
    (worktree / name).write_text(content, encoding="utf-8")
    subprocess.run(["git", "-C", str(worktree), "add", name], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(worktree), "commit", "-m", "change"], check=True, capture_output=True
    )


def finish_a_task(supervisor: GitSupervisor) -> dict:
    """Drive one task all the way to `done` and return its attempt."""

    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "isolated\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"
    assert supervisor.integrate(attempt["task_id"])["verdict"] == "pass"
    assert supervisor.task(created["id"])["status"] == "done"
    return attempt


def reasons(report: dict) -> dict[str, str]:
    return {entry["attempt_id"]: entry["reason"] for entry in report["retained"]}


def test_gc_reclaims_a_finished_task_worktree_and_branch(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = finish_a_task(supervisor)
    worktree = Path(attempt["worktree"])
    assert worktree.exists()
    assert attempt["branch"] in git(repo, "branch", "--list", "--format=%(refname:short)")

    report = supervisor.gc(older_than_seconds=0)

    assert report["removed"] == [attempt["id"]]
    assert not worktree.exists()
    assert attempt["branch"] not in git(repo, "branch", "--list", "--format=%(refname:short)")
    # The registration has to go too, or `git worktree list` keeps naming a dead path.
    assert str(worktree) not in git(repo, "worktree", "list")


def test_gc_refuses_a_live_attempt(repo: Path) -> None:
    """The gate: point a real sweep at a claimed, unfinished attempt."""

    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    worktree = Path(attempt["worktree"])

    report = supervisor.gc(older_than_seconds=0)

    assert report["removed"] == []
    assert reasons(report)[attempt["id"]] == "task_active"
    assert worktree.exists()
    assert (worktree / "alpha.txt").exists()


def test_gc_honours_the_retention_window(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = finish_a_task(supervisor)

    report = supervisor.gc()  # default retention is a week; this finished seconds ago

    assert report["removed"] == []
    assert reasons(report)[attempt["id"]] == "within_retention"
    assert Path(attempt["worktree"]).exists()


def test_dry_run_reports_without_removing(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = finish_a_task(supervisor)

    report = supervisor.gc(dry_run=True, older_than_seconds=0)

    assert report["dry_run"] is True
    assert report["removed"] == []
    assert [entry["attempt_id"] for entry in report["reclaimable"]] == [attempt["id"]]
    assert report["bytes"] > 0
    assert Path(attempt["worktree"]).exists()


def test_gc_refuses_a_fenced_attempt(repo: Path) -> None:
    """A cleanup fence is a lease expiring in the far future, and must survive gc."""

    supervisor = GitSupervisor(repo)
    attempt = finish_a_task(supervisor)
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE resource_leases SET attempt_id = ?, lease_expires_at = ? "
            "WHERE resource = 'alpha.txt'",
            (attempt["id"], CLEANUP_FENCE_EPOCH),
        )

    report = supervisor.gc(older_than_seconds=0)

    assert report["removed"] == []
    assert reasons(report)[attempt["id"]] == "resource_lease_held"
    assert Path(attempt["worktree"]).exists()


def test_gc_refuses_when_cleanup_is_unproven(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = finish_a_task(supervisor)
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE tasks SET cleanup_error = ? WHERE id = ?",
            ("teardown probe never observed the resource absent", attempt["task_id"]),
        )

    report = supervisor.gc(older_than_seconds=0)

    assert report["removed"] == []
    assert reasons(report)[attempt["id"]] == "cleanup_unproven"
    assert Path(attempt["worktree"]).exists()


def test_gc_never_deletes_an_integration_branch(repo: Path) -> None:
    """Those commits are the published evidence for an approved task."""

    supervisor = GitSupervisor(repo)
    finish_a_task(supervisor)
    report = supervisor.gc(older_than_seconds=0)

    published = [entry["branch"] for entry in report["integration_branches"]]
    assert published
    surviving = git(repo, "branch", "--list", "--format=%(refname:short)")
    for branch in published:
        assert branch in surviving


def test_gc_is_idempotent_and_keeps_the_event_chain_valid(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = finish_a_task(supervisor)

    first = supervisor.gc(older_than_seconds=0)
    second = supervisor.gc(older_than_seconds=0)

    assert first["removed"] == [attempt["id"]]
    assert second["removed"] == []
    assert reasons(second)[attempt["id"]] == "worktree_already_gone"
    # gc appends a hash-chained event; a broken link would make the whole log unverifiable.
    assert supervisor.verify_event_chain()["ok"] is True
    with supervisor.connect() as connection:
        recorded = connection.execute(
            "SELECT payload_json FROM events WHERE event_type = 'worktree.reclaimed'"
        ).fetchall()
    assert len(recorded) == 1


def test_status_reports_reclaimable_disk(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    finish_a_task(supervisor)

    disk = supervisor.status()["disk"]

    assert disk["state_bytes"] > 0
    # Default retention has not elapsed, so nothing is reclaimable yet.
    assert disk["reclaimable_worktrees"] == 0


def test_parse_duration_requires_a_unit() -> None:
    assert parse_duration("30s") == 30
    assert parse_duration("15m") == 900
    assert parse_duration("12h") == 43200
    assert parse_duration("7d") == 604800
    # A bare number is the dangerous case: `--older-than 7` meaning seconds when the
    # operator meant days would reclaim a week of worktrees immediately.
    for bad in ("7", "", "d", "-1d", "7w", "seven days"):
        with pytest.raises(SupervisorError) as error:
            parse_duration(bad)
        assert error.value.code == "invalid_duration"


def test_a_read_only_supervisor_can_survey_but_not_gc(repo: Path) -> None:
    """`acp status` computes the disk figures on a mode=ro connection (#1629)."""

    supervisor = GitSupervisor(repo)
    finish_a_task(supervisor)

    viewer = GitSupervisor(repo, read_only=True)
    assert viewer.status()["disk"]["state_bytes"] > 0
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        viewer.gc(older_than_seconds=0)
