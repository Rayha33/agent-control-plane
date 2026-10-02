"""`acp gc` reclaims what nothing is using, and nothing else.

Measured before this existed: one claim -> submit -> qc -> integrate cycle left the
attempt worktree on disk, still registered with `git worktree list`, with its task
branch alive — per task, forever, with no subcommand to reclaim any of it.

Every refusal below is asserted against a real non-dry-run sweep with the retention
window set to zero, not against the report alone. A gc that prints "retained" and
deletes anyway would pass the weaker check.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
from pathlib import Path
from types import SimpleNamespace

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


def configure_attempt_worktree_root(repo: Path, root: Path) -> None:
    with (repo / "acp.toml").open("a", encoding="utf-8") as handle:
        handle.write(f"\n[worktrees]\nattempts_root = {json.dumps(str(root))}\n")


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


def test_external_worktree_root_stays_pinned_across_config_change_and_gc(repo: Path) -> None:
    original_root = repo.parent / f"{repo.name}-external-worktrees"
    replacement_root = repo.parent / f"{repo.name}-replacement-worktrees"
    configure_attempt_worktree_root(repo, original_root)
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt", title="external worker")
    attempt = supervisor.claim(created["id"], "worker")
    worktree = Path(attempt["worktree"])

    assert worktree.parent == original_root.resolve()
    assert attempt["worktree_root"] == str(original_root.resolve())
    storage = supervisor.status()["disk"]["attempt_worktrees"]
    assert storage["configured_root"] == str(original_root.resolve())
    assert storage["managed_roots"][0]["root"] == str(original_root.resolve())
    assert storage["managed_roots"][0]["registered_bytes"] > 0
    assert storage["managed_roots"][0]["filesystem"]["path"] == str(original_root.resolve())
    assert f"attempt worktrees at {original_root.resolve()}" in supervisor.render_status(
        supervisor.status()
    )

    config_path = repo / "acp.toml"
    config = config_path.read_text(encoding="utf-8")
    (repo / "acp.toml").write_text(
        config.replace(str(original_root), str(replacement_root)), encoding="utf-8"
    )
    reopened = GitSupervisor(repo)
    assert reopened.attempt(attempt["id"])["worktree"] == str(worktree)
    assert reopened.attempt(attempt["id"])["worktree_root"] == str(original_root.resolve())
    # The independent base-checkout snapshot correctly rejects a source-config edit
    # during an active attempt. Restore the original file while retaining the reopened
    # supervisor's changed in-memory setting to isolate path pinning from that guard.
    config_path.write_text(config, encoding="utf-8")
    commit_change(attempt, "alpha.txt", "external change\n")
    submission = reopened.submit(attempt["id"], attempt["claim_token"])
    assert reopened.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"
    assert reopened.integrate(created["id"])["verdict"] == "pass"

    report = reopened.gc(older_than_seconds=0)

    assert report["removed"] == [attempt["id"]]
    assert not worktree.exists()


def test_gc_rechecks_the_expected_branch_after_survey(repo: Path, monkeypatch) -> None:
    supervisor = GitSupervisor(repo)
    attempt = finish_a_task(supervisor)
    worktree = Path(attempt["worktree"])
    unexpected_branch = "acp-unexpected-gc-branch"
    original_remove = supervisor._remove_worktree

    def switch_branch_then_remove(path, delete_branch, expected_branch):
        git(path, "switch", "-c", unexpected_branch)
        return original_remove(path, delete_branch, expected_branch)

    monkeypatch.setattr(supervisor, "_remove_worktree", switch_branch_then_remove)

    report = supervisor.gc(older_than_seconds=0)

    assert report["removed"] == []
    assert reasons(report)[attempt["id"]] == "worktree_removal_unproven"
    assert report["bytes"] == 0
    assert report["reclaimable_bytes"] > 0
    assert worktree.exists()
    assert git(worktree, "branch", "--show-current") == unexpected_branch
    surviving = git(repo, "branch", "--list", "--format=%(refname:short)")
    assert attempt["branch"] in surviving
    assert unexpected_branch in surviving


def test_gc_never_removes_an_unregistered_directory_at_attempt_path(repo: Path) -> None:
    external_root = repo.parent / f"{repo.name}-external-worktrees"
    configure_attempt_worktree_root(repo, external_root)
    supervisor = GitSupervisor(repo)
    attempt = finish_a_task(supervisor)
    worktree = Path(attempt["worktree"])

    git(repo, "worktree", "remove", "--force", str(worktree))
    worktree.mkdir()
    sentinel = worktree / "unrelated.txt"
    sentinel.write_text("keep", encoding="utf-8")

    report = supervisor.gc(older_than_seconds=0)

    assert report["removed"] == []
    assert reasons(report)[attempt["id"]] == "worktree_unregistered"
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_gc_never_removes_an_unrelated_sibling_outside_the_attempt_id(repo: Path) -> None:
    external_root = repo.parent / f"{repo.name}-external-worktrees"
    configure_attempt_worktree_root(repo, external_root)
    supervisor = GitSupervisor(repo)
    attempt = finish_a_task(supervisor)
    unrelated = external_root / "unrelated-checkout"
    unrelated.mkdir()
    sentinel = unrelated / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET worktree = ? WHERE id = ?", (str(unrelated), attempt["id"])
        )

    report = supervisor.gc(older_than_seconds=0)

    assert report["removed"] == []
    assert reasons(report)[attempt["id"]] == "worktree_path_unmanaged"
    assert sentinel.read_text(encoding="utf-8") == "keep"


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
    assert report["bytes"] == 0
    assert report["reclaimable_bytes"] > 0
    assert Path(attempt["worktree"]).exists()


def test_expired_recovery_keeps_last_sha_when_worktree_path_becomes_symlink(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt", title="recovery path identity")
    attempt = supervisor.claim(created["id"], "worker")
    worktree = Path(attempt["worktree"])
    original_path = worktree.with_name(f"{worktree.name}-original")
    latest_before = attempt["latest_sha"]
    commit_change(attempt, "alpha.txt", "unheartbeat-ed commit\n")
    worktree_head = git(worktree, "rev-parse", "HEAD")
    assert worktree_head != latest_before

    foreign = tmp_path / "foreign-repository"
    foreign.mkdir()
    git(foreign, "init", "-b", "main")
    git(foreign, "config", "user.name", "ACP Test")
    git(foreign, "config", "user.email", "acp@example.test")
    (foreign / "foreign.txt").write_text("unrelated\n", encoding="utf-8")
    git(foreign, "add", "foreign.txt")
    git(foreign, "commit", "-m", "unrelated")
    foreign_head = git(foreign, "rev-parse", "HEAD")
    assert foreign_head != latest_before

    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET pid = ?, pid_identity = ? WHERE id = ?",
            (4242, "linux:4242:1", attempt["id"]),
        )

    def replace_worktree_after_worker_termination(_pid: int, _identity: str) -> str:
        worktree.rename(original_path)
        worktree.symlink_to(foreign, target_is_directory=True)
        return "already_gone"

    monkeypatch.setattr(
        supervisor, "_terminate_registered_group", replace_worktree_after_worker_termination
    )
    try:
        supervisor.reap_expired(now=attempt["lease_expires_at"] + 1)
        with supervisor.connect() as connection:
            latest_after = connection.execute(
                "SELECT latest_sha FROM attempts WHERE id = ?", (attempt["id"],)
            ).fetchone()["latest_sha"]
        assert latest_after == latest_before
        assert worktree.is_symlink()
    finally:
        worktree.unlink(missing_ok=True)
        original_path.rename(worktree)


def test_expired_recovery_captures_head_from_registered_attempt_worktree(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt", title="recovery commit identity")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "committed before crash\n")
    recovered_head = git(Path(attempt["worktree"]), "rev-parse", "HEAD")

    supervisor.reap_expired(now=attempt["lease_expires_at"] + 1)

    with supervisor.connect() as connection:
        latest_sha = connection.execute(
            "SELECT latest_sha FROM attempts WHERE id = ?", (attempt["id"],)
        ).fetchone()["latest_sha"]
    assert latest_sha == recovered_head


def test_expired_recovery_does_not_read_head_while_launch_owner_is_live(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt", title="launch owner recovery fence")
    attempt = supervisor.claim(created["id"], "worker")
    latest_before = attempt["latest_sha"]
    commit_change(attempt, "alpha.txt", "launcher may still be active\n")
    assert git(Path(attempt["worktree"]), "rev-parse", "HEAD") != latest_before
    owner_identity = supervisor._process_identity(os.getpid())
    assert owner_identity
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET pid = -1, launch_owner_pid = ?, "
            "launch_owner_identity = ? WHERE id = ?",
            (os.getpid(), owner_identity, attempt["id"]),
        )

    report = supervisor.reap_expired(now=attempt["lease_expires_at"] + 1)

    with supervisor.connect() as connection:
        latest_after = connection.execute(
            "SELECT latest_sha FROM attempts WHERE id = ?", (attempt["id"],)
        ).fetchone()["latest_sha"]
    assert latest_after == latest_before
    assert report["runtime_cleanup"][0]["state"] == "cleanup_error"
    assert "launch owner is still active" in report["runtime_cleanup"][0]["error"]


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


def test_status_reports_filesystem_capacity_separately_from_acp_usage(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    observed_paths: list[Path] = []

    def disk_usage(path: Path) -> SimpleNamespace:
        observed_paths.append(path)
        return SimpleNamespace(total=1000, used=700, free=300)

    monkeypatch.setattr("agent_control_plane.supervisor.views.shutil.disk_usage", disk_usage)

    disk = supervisor.status()["disk"]

    assert observed_paths == [supervisor.state_dir]
    assert disk["state_bytes"] > 0
    assert disk["filesystem"] == {
        "path": str(supervisor.state_dir),
        "status": "available",
        "total_bytes": 1000,
        "free_bytes": 300,
    }


def test_status_keeps_working_when_filesystem_capacity_is_unavailable(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)

    def fail_disk_usage(_path: Path) -> SimpleNamespace:
        raise OSError("probe failed")

    monkeypatch.setattr("agent_control_plane.supervisor.views.shutil.disk_usage", fail_disk_usage)

    snapshot = supervisor.status()
    filesystem = snapshot["disk"]["filesystem"]

    assert filesystem == {
        "path": str(supervisor.state_dir),
        "status": "unavailable",
        "total_bytes": None,
        "free_bytes": None,
    }
    assert "filesystem capacity unavailable" in supervisor.render_status(snapshot)


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
    disk = viewer.status()["disk"]
    assert disk["state_bytes"] > 0
    assert disk["filesystem"]["status"] == "available"
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        viewer.gc(older_than_seconds=0)
