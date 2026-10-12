from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
from support import init_repo

from agent_control_plane.git_supervisor import GitSupervisor, SupervisorError


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return init_repo(tmp_path)


def _task(supervisor: GitSupervisor, max_attempts: int | None) -> dict:
    return supervisor.create_task(
        "Bounded implementation",
        "Implement and verify one isolated change.",
        ["Tests pass"],
        ["alpha.txt"],
        max_attempts=max_attempts,
    )


def _make_retryable(supervisor: GitSupervisor, task_id: str) -> None:
    with supervisor.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "UPDATE tasks SET status = 'orphaned', current_attempt_id = NULL WHERE id = ?",
            (task_id,),
        )


def test_exhausted_cap_refuses_before_creating_attempt_and_is_audited(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    task = _task(supervisor, 1)
    first = supervisor.claim(task["id"], "worker-one")
    _make_retryable(supervisor, task["id"])
    before = supervisor.task(task["id"])

    with pytest.raises(SupervisorError) as error:
        supervisor.claim(task["id"], "worker-two")

    assert error.value.code == "attempt_budget_exhausted"
    after = supervisor.task(task["id"])
    assert after["current_attempt_id"] is None
    assert after["status"] == before["status"] == "orphaned"
    assert after["attempts_used"] == 1
    assert after["attempts_remaining"] == 0
    assert after["latest_attempt"]["id"] == first["id"]
    assert after["attempt_budget_exhausted_at"]
    with supervisor.connect() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM attempts WHERE task_id = ?", (task["id"],)
            ).fetchone()[0]
            == 1
        )
        event = connection.execute(
            """
            SELECT payload_json FROM events
            WHERE event_type = 'task.attempt_budget_exhausted'
            ORDER BY sequence DESC LIMIT 1
            """
        ).fetchone()
    assert '"attempts_used":1' in event["payload_json"]
    assert '"max_attempts":1' in event["payload_json"]
    with pytest.raises(SupervisorError) as repeated_error:
        supervisor.claim(task["id"], "worker-three")
    assert repeated_error.value.code == "attempt_budget_exhausted"
    with supervisor.connect() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE event_type = 'task.attempt_budget_exhausted'"
            ).fetchone()[0]
            == 1
        )
    assert supervisor.verify_event_chain()["ok"] is True
    preview = supervisor.plan_claim(task["id"])
    assert any(item["kind"] == "attempt_budget_exhausted" for item in preview["blockers"])
    blocked = supervisor.ready_queue()["blocked"]
    assert len(blocked) == 1
    assert blocked[0]["task_id"] == task["id"]
    assert blocked[0]["max_attempts"] == 1
    assert blocked[0]["attempts_used"] == 1
    assert blocked[0]["attempts_remaining"] == 0
    assert any(item["kind"] == "attempt_budget_exhausted" for item in blocked[0]["blockers"])


def test_failed_provisioning_consumes_the_attempt_cap(repo: Path, monkeypatch) -> None:
    supervisor = GitSupervisor(repo)
    task = _task(supervisor, 1)

    def fail_runtime_setup(_attempt_id: str) -> None:
        raise SupervisorError("test_runtime_setup", "injected setup failure")

    monkeypatch.setattr(supervisor, "_runtime_up", fail_runtime_setup)
    with pytest.raises(SupervisorError, match="injected setup failure"):
        supervisor.claim(task["id"], "worker-one")

    view = supervisor.task(task["id"])
    assert view["status"] == "open"
    assert view["attempts_used"] == 1
    assert view["attempts_remaining"] == 0
    assert view["latest_attempt"]["status"] == "failed"
    with pytest.raises(SupervisorError) as error:
        supervisor.claim(task["id"], "worker-two")
    assert error.value.code == "attempt_budget_exhausted"


def test_concurrent_claims_cannot_oversubscribe_last_attempt(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    task = _task(supervisor, 2)
    supervisor.claim(task["id"], "worker-initial")
    _make_retryable(supervisor, task["id"])
    start = Barrier(2)

    def claim() -> dict | str:
        start.wait()
        try:
            return supervisor.claim(task["id"], "concurrent-worker")
        except SupervisorError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _: claim(), range(2)))

    winners = [item for item in outcomes if isinstance(item, dict)]
    losers = [item for item in outcomes if isinstance(item, str)]
    assert len(winners) == 1
    assert len(losers) == 1
    assert losers[0] in {"attempt_budget_exhausted", "task_unavailable"}
    view = supervisor.task(task["id"])
    assert view["attempts_used"] == 2
    assert view["attempts_remaining"] == 0


@pytest.mark.parametrize("invalid", [0, -1, True, 1.5, "2", 2**63])
def test_invalid_attempt_caps_are_rejected(repo: Path, invalid: object) -> None:
    supervisor = GitSupervisor(repo)
    with pytest.raises(SupervisorError) as error:
        supervisor.create_task(
            "Invalid budget",
            "This must fail closed.",
            ["Tests pass"],
            ["alpha.txt"],
            max_attempts=invalid,  # type: ignore[arg-type]
        )
    assert error.value.code == "invalid_task"


def test_legacy_unlimited_task_behavior_is_preserved(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    task = _task(supervisor, None)

    attempt = supervisor.claim(task["id"], "unlimited-worker")

    view = supervisor.task(task["id"])
    assert attempt["task_id"] == task["id"]
    assert view["max_attempts"] is None
    assert view["attempts_used"] == 1
    assert view["attempts_remaining"] is None


def test_plan_and_queue_report_under_cap_usage(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    task = _task(supervisor, 3)

    plan = supervisor.plan_claim(task["id"])
    queued = supervisor.ready_queue()["ready"][0]
    for row in (plan, queued):
        assert row["max_attempts"] == 3
        assert row["attempts_used"] == 0
        assert row["attempts_remaining"] == 3

    supervisor.claim(task["id"], "worker-one")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE tasks SET status = 'orphaned', current_attempt_id = NULL WHERE id = ?",
            (task["id"],),
        )

    plan = supervisor.plan_claim(task["id"])
    queued = supervisor.ready_queue()["ready"][0]
    for row in (plan, queued):
        assert row["max_attempts"] == 3
        assert row["attempts_used"] == 1
        assert row["attempts_remaining"] == 2


def test_active_queue_rows_report_attempt_budget_usage(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    task = _task(supervisor, 2)
    supervisor.claim(task["id"], "worker-one")

    active = supervisor.ready_queue()["active"]
    assert len(active) == 1
    assert active[0]["max_attempts"] == 2
    assert active[0]["attempts_used"] == 1
    assert active[0]["attempts_remaining"] == 1
