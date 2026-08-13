from __future__ import annotations

import json
import socket
import time
from pathlib import Path

import pytest
from support import approve, commit_change, init_repo, make_task, state_fingerprint, write_config

from agent_control_plane.git_supervisor import GitSupervisor


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return init_repo(tmp_path)


def entry_for(snapshot: dict, task_id: str) -> dict:
    return next(item for item in snapshot["tasks"] if item["task_id"] == task_id)


def test_status_reports_phase_paths_and_runtime_for_a_working_attempt(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt", title="live work")
    attempt = supervisor.claim(created["id"], "agent-a")

    entry = entry_for(supervisor.status(), created["id"])

    assert entry["phase"] == "working"
    assert entry["agent_id"] == "agent-a"
    assert entry["attempt_id"] == attempt["id"]
    assert entry["claimed_paths"] == ["alpha.txt"]
    assert entry["runtime"]["state"] == "ready"
    assert entry["heartbeat_age_seconds"] >= 0
    assert entry["worker"]["status"] == "working"


def test_status_never_mutates_even_with_an_expired_attempt(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "agent-a")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET lease_expires_at = 1 WHERE id = ?", (attempt["id"],)
        )
    before = state_fingerprint(supervisor)

    snapshot = supervisor.status()

    assert state_fingerprint(supervisor) == before
    entry = entry_for(snapshot, created["id"])
    assert entry["lease_expired"] is True
    assert entry["awaiting_reap"] is True
    assert entry["phase"] == "working"


def test_heartbeat_age_shrinks_after_a_heartbeat(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "agent-a")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET updated_at = '2020-01-01T00:00:00Z' WHERE id = ?",
            (attempt["id"],),
        )
    stale = entry_for(supervisor.status(), created["id"])["heartbeat_age_seconds"]
    assert stale > 100000

    supervisor.heartbeat(attempt["id"], attempt["claim_token"], {"phase": "tests"})

    entry = entry_for(supervisor.status(), created["id"])
    assert entry["heartbeat_age_seconds"] < 60
    assert entry["checkpoint"] == {"phase": "tests"}


def test_attention_queue_ranks_human_required_above_active_work(repo: Path) -> None:
    write_config(repo, qc_commands=["python -c 'raise SystemExit(1)'"])
    supervisor = GitSupervisor(repo)
    failing = make_task(supervisor, "alpha.txt", title="needs a human")
    busy = make_task(supervisor, "beta.txt", title="ordinary work")
    attempt = supervisor.claim(failing["id"], "agent-a")
    commit_change(attempt, "alpha.txt", "change\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    supervisor.run_qc(submission["id"], "independent-qc")
    supervisor.claim(busy["id"], "agent-b")

    attention = supervisor.status()["attention"]

    assert attention[0]["task_id"] == failing["id"]
    assert attention[0]["category"] == "human_required"
    assert attention[0]["rank"] < attention[-1]["rank"]
    assert attention[-1]["task_id"] == busy["id"]
    assert attention[-1]["category"] == "active"
    assert attention[0]["reason"]


def test_failed_cleanup_outranks_review_and_is_listed(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt", title="leaky runtime")
    attempt = supervisor.claim(created["id"], "agent-a")
    reviewing = make_task(supervisor, "beta.txt", title="waiting on review")
    approve(supervisor, reviewing["id"], "beta.txt", "reviewed\n")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE runtime_environments SET state = 'teardown_failed' WHERE attempt_id = ?",
            (attempt["id"],),
        )

    snapshot = supervisor.status()

    categories = [item["category"] for item in snapshot["attention"]]
    assert categories.index("cleanup_failed") < categories.index("review")
    assert snapshot["cleanup_failures"] == [
        {"attempt_id": attempt["id"], "task_id": created["id"], "state": "teardown_failed"}
    ]


def test_lease_risk_is_reported_before_expiry(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "agent-a")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET lease_expires_at = ? WHERE id = ?",
            (int(time.time()) + 5, attempt["id"]),
        )

    snapshot = supervisor.status(lease_risk_seconds=30)

    item = next(entry for entry in snapshot["attention"] if entry["task_id"] == created["id"])
    assert item["category"] == "lease_risk"
    assert entry_for(snapshot, created["id"])["lease_seconds_remaining"] <= 5


def test_status_reports_runtime_allocations_and_blockers(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    holder = make_task(supervisor, "alpha.txt", title="holder")
    waiting = make_task(supervisor, "alpha.txt", title="waiting")
    supervisor.claim(holder["id"], "agent-a")

    snapshot = supervisor.status()

    blocked = entry_for(snapshot, waiting["id"])
    assert blocked["ready"] is False
    conflict = next(item for item in blocked["blockers"] if item["kind"] == "resource_conflict")
    assert conflict["owner_task_id"] == holder["id"]
    assert snapshot["counts"]["blocked"] == 1
    assert snapshot["counts"]["active"] == 1


def test_status_is_bounded_and_machine_readable(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    for index in range(6):
        make_task(supervisor, f"file-{index}.txt", title=f"task {index}", priority=index)

    snapshot = supervisor.status(limit=3)

    assert len(snapshot["tasks"]) == 3
    assert snapshot["truncated"] is True
    assert snapshot["counts"]["tasks"] == 6
    assert json.loads(json.dumps(snapshot, sort_keys=True))["truncated"] is True
    assert [item["title"] for item in snapshot["tasks"]] == ["task 5", "task 4", "task 3"]


def test_status_survives_a_dead_worker_pid(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "agent-a")
    with supervisor.connect() as connection:
        connection.execute("UPDATE attempts SET pid = 999999 WHERE id = ?", (attempt["id"],))

    entry = entry_for(supervisor.status(), created["id"])

    assert entry["worker"]["pid"] == 999999
    assert entry["worker"]["alive"] is False


def test_render_text_is_a_single_screen_summary(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt", title="live work")
    supervisor.claim(created["id"], "agent-a")

    text = supervisor.render_status(supervisor.status())

    assert "live work" in text
    assert "ATTENTION" in text
    assert "agent-a" in text
    assert len(text.splitlines()) < 40


def test_status_reports_ports_held_by_an_attempt(repo: Path) -> None:
    port = _free_port()
    (repo / "acp.toml").write_text(
        (repo / "acp.toml").read_text(encoding="utf-8")
        + f"\n[runtime.ports]\nAPP_PORT = [{port}, {port}]\n",
        encoding="utf-8",
    )
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    supervisor.claim(created["id"], "agent-a")

    entry = entry_for(supervisor.status(), created["id"])

    assert entry["runtime"]["allocations"] == [{"pool_name": "APP_PORT", "value": port}]


def _free_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])
    finally:
        probe.close()


def test_status_and_queue_agree_about_what_is_launchable(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    make_task(supervisor, "src/**", title="wide", priority=90)
    make_task(supervisor, "src/module.py", title="narrow", priority=80)
    make_task(supervisor, "beta.txt", title="separate", priority=70)

    snapshot = supervisor.status()
    queue = supervisor.ready_queue()

    assert snapshot["counts"]["ready"] == len(queue["ready"]) == 2
    assert snapshot["counts"]["blocked"] == len(queue["blocked"]) == 1
    assert {entry["task_id"] for entry in snapshot["tasks"] if entry["ready"] is True} == {
        entry["task_id"] for entry in queue["ready"]
    }
