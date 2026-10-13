from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
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
    assert after["attempt_budget"]["status"] == "exhausted"
    assert after["attempt_budget"]["consumed"] == 1
    assert after["attempt_budget"]["configured_limit"] == 1
    assert after["attempt_budget"]["provider_usage"]["status"] == "unsupported"
    assert after["latest_attempt"]["attempt_budget"]["consumed"] == 1
    assert after["latest_attempt"]["attempt_budget"]["freshness"] == "historical"
    assert (
        after["latest_attempt"]["attempt_budget"]["observed_at"]
        == after["latest_attempt"]["created_at"]
    )
    assert datetime.fromisoformat(after["attempt_budget"]["observed_at"])
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


def test_attempt_cap_usage_survives_supervisor_restart(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    task = _task(supervisor, 1)
    first = supervisor.claim(task["id"], "worker-one")
    _make_retryable(supervisor, task["id"])

    restarted = GitSupervisor(repo)
    recovered = restarted.task(task["id"])
    assert recovered["attempts_used"] == 1
    assert recovered["attempts_remaining"] == 0

    with pytest.raises(SupervisorError) as error:
        restarted.claim(task["id"], "worker-after-restart")

    assert error.value.code == "attempt_budget_exhausted"
    assert restarted.task(task["id"])["latest_attempt"]["id"] == first["id"]


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


def _child_task(
    supervisor: GitSupervisor,
    parent_task_id: str,
    title: str,
    resource: str,
    *,
    max_descendant_attempts: int | None = None,
    max_attempts: int | None = None,
) -> dict:
    return supervisor.create_task(
        title,
        "A child task in the explicit task tree.",
        ["Tests pass"],
        [resource],
        max_attempts=max_attempts,
        parent_task_id=parent_task_id,
        max_descendant_attempts=max_descendant_attempts,
    )


def test_descendant_attempt_budget_counts_nested_attempts_but_not_parent_attempts(
    repo: Path,
) -> None:
    supervisor = GitSupervisor(repo)
    root = supervisor.create_task(
        "Root budget",
        "A cap applies to all descendant task attempts.",
        ["Attempts are bounded"],
        ["root.txt"],
        max_descendant_attempts=2,
    )
    child = _child_task(supervisor, root["id"], "Child", "child.txt")
    leaf = _child_task(supervisor, child["id"], "Nested leaf", "leaf.txt")
    sibling = _child_task(supervisor, root["id"], "Sibling", "sibling.txt")

    supervisor.claim(root["id"], "root-worker")
    supervisor.claim(leaf["id"], "leaf-worker")
    supervisor.claim(sibling["id"], "sibling-worker")
    root_view = supervisor.task(root["id"])

    assert root_view["attempts_used"] == 1
    assert root_view["descendant_attempts_used"] == 2
    assert root_view["descendant_attempts_remaining"] == 0
    assert root_view["descendant_attempt_budget"]["scope"] == {
        "kind": "task_descendants",
        "id": root["id"],
    }
    assert root_view["descendant_attempt_budget"]["dimension"] == (
        "descendant_task_attempt_launches"
    )
    assert root_view["descendant_attempt_budget"]["status"] == "exhausted"
    assert root_view["descendant_attempt_budget"]["consumed"] == 2
    assert root_view["descendant_attempt_budget"]["reserved"] == 0
    assert root_view["descendant_attempt_budget"]["released"] == 0
    assert root_view["descendant_attempt_budget"]["provider_usage"]["status"] == "unsupported"

    blocked = _child_task(supervisor, root["id"], "Over-cap sibling", "blocked.txt")
    with pytest.raises(SupervisorError) as error:
        supervisor.claim(blocked["id"], "blocked-worker")
    assert error.value.code == "descendant_attempt_budget_exhausted"
    assert "2/2" in str(error.value)
    assert supervisor.task(blocked["id"])["attempts_used"] == 0
    assert supervisor.task(root["id"])["descendant_attempt_budget_exhausted_at"]
    preview = supervisor.plan_claim(blocked["id"])
    assert any(
        item["kind"] == "descendant_attempt_budget_exhausted"
        and item["ancestor_task_id"] == root["id"]
        for item in preview["blockers"]
    )

    with supervisor.connect() as connection:
        events = connection.execute(
            "SELECT COUNT(*) FROM events "
            "WHERE event_type = 'task.descendant_attempt_budget_exhausted'"
        ).fetchone()[0]
    assert events == 1
    with pytest.raises(SupervisorError):
        supervisor.claim(blocked["id"], "repeat-worker")
    with supervisor.connect() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM events "
                "WHERE event_type = 'task.descendant_attempt_budget_exhausted'"
            ).fetchone()[0]
            == 1
        )
    assert supervisor.verify_event_chain()["ok"] is True


def test_zero_descendant_cap_allows_parent_but_denies_first_child_attempt(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    parent = supervisor.create_task(
        "Closed fan-out",
        "Zero means no descendant attempt slots.",
        ["Parent attempt remains independent"],
        ["parent.txt"],
        max_descendant_attempts=0,
    )
    child = _child_task(supervisor, parent["id"], "Child", "child.txt")

    parent_attempt = supervisor.claim(parent["id"], "parent-worker")
    assert parent_attempt["task_id"] == parent["id"]
    with pytest.raises(SupervisorError) as error:
        supervisor.claim(child["id"], "child-worker")

    assert error.value.code == "descendant_attempt_budget_exhausted"
    parent_view = supervisor.task(parent["id"])
    assert parent_view["attempts_used"] == 1
    assert parent_view["descendant_attempts_used"] == 0
    assert parent_view["descendant_attempt_budget"]["configured_limit"] == 0
    assert parent_view["descendant_attempt_budget"]["status"] == "exhausted"
    assert parent_view["descendant_attempt_budget"]["remaining"] == 0


def test_nested_ancestor_cap_is_enforced_and_survives_restart(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    root = supervisor.create_task(
        "Root", "Root allowance", ["Bounded"], ["root.txt"], max_descendant_attempts=5
    )
    child = _child_task(
        supervisor, root["id"], "Capped child", "child.txt", max_descendant_attempts=1
    )
    leaf = _child_task(supervisor, child["id"], "Leaf", "leaf.txt")
    leaf_retry = _child_task(supervisor, child["id"], "Leaf retry", "retry.txt")

    supervisor.claim(leaf["id"], "leaf-worker")
    restarted = GitSupervisor(repo)
    assert restarted.task(child["id"])["descendant_attempts_used"] == 1
    with pytest.raises(SupervisorError) as error:
        restarted.claim(leaf_retry["id"], "retry-worker")
    assert error.value.code == "descendant_attempt_budget_exhausted"
    assert child["id"] in str(error.value)
    assert restarted.task(leaf_retry["id"])["attempts_used"] == 0


def test_queue_reserves_descendant_slots_only_in_its_advisory_plan(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    parent = supervisor.create_task(
        "Parent",
        "One planned descendant slot",
        ["Bounded"],
        ["parent.txt"],
        max_descendant_attempts=1,
    )
    children = [
        _child_task(supervisor, parent["id"], "First", "first.txt"),
        _child_task(supervisor, parent["id"], "Second", "second.txt"),
    ]

    queue = supervisor.ready_queue()
    ready_children = {row["task_id"] for row in queue["ready"]} & {task["id"] for task in children}
    blocked_children = [
        row for row in queue["blocked"] if row["task_id"] in {task["id"] for task in children}
    ]

    assert len(ready_children) == 1
    assert len(blocked_children) == 1
    blocker = next(
        item
        for item in blocked_children[0]["blockers"]
        if item["kind"] == "descendant_attempt_budget_exhausted"
    )
    assert blocker["ancestor_task_id"] == parent["id"]
    assert blocker["descendant_attempts_used"] == 0
    assert blocker["planned_descendant_claims"] == 1
    assert blocked_children[0]["descendant_attempt_budget"]["consumed"] == 0
    assert blocked_children[0]["descendant_attempt_budget"]["status"] == "unconfigured"
    assert supervisor.task(parent["id"])["descendant_attempts_used"] == 0


def test_concurrent_sibling_attempts_cannot_oversubscribe_ancestor_cap(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    parent = supervisor.create_task(
        "Parent", "One descendant slot", ["Bounded"], ["parent.txt"], max_descendant_attempts=1
    )
    children = [
        _child_task(supervisor, parent["id"], "First", "first.txt"),
        _child_task(supervisor, parent["id"], "Second", "second.txt"),
    ]
    start = Barrier(2)

    def claim(task: dict) -> dict | str:
        start.wait()
        try:
            return supervisor.claim(task["id"], "concurrent-child")
        except SupervisorError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(claim, children))

    assert sum(isinstance(outcome, dict) for outcome in outcomes) == 1
    assert sum(outcome == "descendant_attempt_budget_exhausted" for outcome in outcomes) == 1
    assert supervisor.task(parent["id"])["descendant_attempts_used"] == 1
    assert sum(supervisor.task(child["id"])["attempts_used"] for child in children) == 1


def test_failed_child_provisioning_still_consumes_ancestor_allowance(
    repo: Path, monkeypatch
) -> None:
    supervisor = GitSupervisor(repo)
    parent = supervisor.create_task(
        "Parent", "One descendant slot", ["Bounded"], ["parent.txt"], max_descendant_attempts=1
    )
    child = _child_task(supervisor, parent["id"], "Child", "child.txt")
    sibling = _child_task(supervisor, parent["id"], "Sibling", "sibling.txt")

    def fail_runtime_setup(_attempt_id: str) -> None:
        raise SupervisorError("test_runtime_setup", "injected setup failure")

    monkeypatch.setattr(supervisor, "_runtime_up", fail_runtime_setup)
    with pytest.raises(SupervisorError, match="injected setup failure"):
        supervisor.claim(child["id"], "worker-one")
    assert supervisor.task(parent["id"])["descendant_attempts_used"] == 1
    with pytest.raises(SupervisorError) as error:
        supervisor.claim(sibling["id"], "worker-two")
    assert error.value.code == "descendant_attempt_budget_exhausted"
    assert supervisor.task(child["id"])["latest_attempt"]["status"] == "failed"


@pytest.mark.parametrize("invalid", [-1, True, 1.5, "2", 2**63])
def test_invalid_descendant_attempt_caps_are_rejected(repo: Path, invalid: object) -> None:
    supervisor = GitSupervisor(repo)
    with pytest.raises(SupervisorError) as error:
        supervisor.create_task(
            "Invalid descendant budget",
            "This must fail closed.",
            ["Tests pass"],
            ["alpha.txt"],
            max_descendant_attempts=invalid,  # type: ignore[arg-type]
        )
    assert error.value.code == "invalid_task"


def test_parent_task_must_exist(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    with pytest.raises(SupervisorError) as error:
        supervisor.create_task(
            "Orphan child",
            "A task cannot refer to a missing hierarchy parent.",
            ["No task is created"],
            ["alpha.txt"],
            parent_task_id="missing-parent",
        )
    assert error.value.code == "parent_task_not_found"


@pytest.mark.parametrize("invalid_parent_id", ["", " "])
def test_blank_corrupt_parent_link_blocks_plan_and_claim(
    repo: Path, invalid_parent_id: str
) -> None:
    supervisor = GitSupervisor(repo)
    parent = supervisor.create_task(
        "Parent",
        "The child link is corrupted after a valid task is created.",
        ["Admission fails closed"],
        ["parent.txt"],
        max_descendant_attempts=2,
    )
    child = _child_task(supervisor, parent["id"], "Child", "child.txt")
    with sqlite3.connect(supervisor.db_path) as connection:
        connection.execute(
            "UPDATE tasks SET id = ? WHERE id = ?", (invalid_parent_id, parent["id"])
        )
        connection.execute(
            "UPDATE tasks SET parent_task_id = ? WHERE id = ?",
            (invalid_parent_id, child["id"]),
        )

    preview = supervisor.plan_claim(child["id"])
    assert preview["ready"] is False
    assert any(item["kind"] == "task_hierarchy_invalid" for item in preview["blockers"])
    with pytest.raises(SupervisorError) as error:
        supervisor.claim(child["id"], "child-worker")
    assert error.value.code == "task_hierarchy_invalid"
    assert supervisor.task(child["id"])["attempts_used"] == 0


def test_invalid_ancestry_precedes_local_attempt_exhaustion_marker(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    parent = supervisor.create_task(
        "Parent",
        "A malformed cycle must be detected before recording a local retry-cap refusal.",
        ["Hierarchy validation runs first"],
        ["parent.txt"],
    )
    child = _child_task(supervisor, parent["id"], "One-attempt child", "child.txt", max_attempts=1)
    supervisor.claim(child["id"], "first-worker")
    _make_retryable(supervisor, child["id"])
    with sqlite3.connect(supervisor.db_path) as connection:
        connection.execute(
            "UPDATE tasks SET parent_task_id = ? WHERE id = ?",
            (child["id"], parent["id"]),
        )

    with pytest.raises(SupervisorError) as error:
        supervisor.claim(child["id"], "second-worker")

    assert error.value.code == "task_hierarchy_invalid"
    view = supervisor.task(child["id"])
    assert view["attempts_used"] == 1
    assert not view["attempt_budget_exhausted_at"]


def test_local_attempt_cap_precedes_ancestor_cap_after_valid_lineage(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    parent = supervisor.create_task(
        "One-descendant budget",
        "A valid hierarchy retains local-cap refusal precedence.",
        ["The local refusal is audited first"],
        ["parent.txt"],
        max_descendant_attempts=1,
    )
    child = _child_task(supervisor, parent["id"], "One-attempt child", "child.txt", max_attempts=1)
    supervisor.claim(child["id"], "first-worker")
    _make_retryable(supervisor, child["id"])

    with pytest.raises(SupervisorError) as error:
        supervisor.claim(child["id"], "second-worker")

    assert error.value.code == "attempt_budget_exhausted"
    assert supervisor.task(child["id"])["attempt_budget_exhausted_at"]
    assert not supervisor.task(parent["id"])["descendant_attempt_budget_exhausted_at"]


def test_cyclic_parent_link_blocks_before_budget_arithmetic(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    parent = supervisor.create_task(
        "Zero-descendant budget",
        "Invalid ancestry takes precedence over any cap arithmetic or exhaustion marker.",
        ["The hierarchy error is reported"],
        ["parent.txt"],
        max_descendant_attempts=0,
    )
    child = _child_task(supervisor, parent["id"], "Child", "child.txt")
    with sqlite3.connect(supervisor.db_path) as connection:
        connection.execute(
            "UPDATE tasks SET parent_task_id = ? WHERE id = ?",
            (child["id"], parent["id"]),
        )

    preview = supervisor.plan_claim(child["id"])
    assert preview["ready"] is False
    assert any(item["kind"] == "task_hierarchy_invalid" for item in preview["blockers"])
    assert not any(
        item["kind"] == "descendant_attempt_budget_exhausted" for item in preview["blockers"]
    )
    with pytest.raises(SupervisorError) as error:
        supervisor.claim(child["id"], "child-worker")
    assert error.value.code == "task_hierarchy_invalid"
    assert supervisor.task(child["id"])["attempts_used"] == 0
    assert not supervisor.task(parent["id"])["descendant_attempt_budget_exhausted_at"]


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


def test_unsupported_provider_cost_limit_is_refused_before_task_persistence(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    with supervisor.connect() as connection:
        before = connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]

    with pytest.raises(SupervisorError) as error:
        supervisor.create_task(
            "Provider-budgeted task",
            "This request must not start without a provider meter and request gate.",
            ["No provider request occurs"],
            ["alpha.txt"],
            provider_cost_limit_usd_micros=5_000_000,
        )

    assert error.value.code == "budget_capability_unsupported"
    assert "authenticated provider meter" in str(error.value)
    assert "request gate" in str(error.value)
    with supervisor.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == before


def test_legacy_unlimited_task_behavior_is_preserved(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    task = _task(supervisor, None)

    attempt = supervisor.claim(task["id"], "unlimited-worker")

    view = supervisor.task(task["id"])
    assert attempt["task_id"] == task["id"]
    assert view["max_attempts"] is None
    assert view["attempts_used"] == 1
    assert view["attempts_remaining"] is None
    assert view["attempt_budget"]["status"] == "unconfigured"
    assert view["attempt_budget"]["provider_usage"]["status"] == "unsupported"
    assert view["latest_attempt"]["attempt_budget"]["status"] == "unconfigured"
    assert view["descendant_attempt_budget"]["status"] == "unconfigured"


def test_plan_and_queue_report_under_cap_usage(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    task = _task(supervisor, 3)

    plan = supervisor.plan_claim(task["id"])
    queued = supervisor.ready_queue()["ready"][0]
    for row in (plan, queued):
        assert row["max_attempts"] == 3
        assert row["attempts_used"] == 0
        assert row["attempts_remaining"] == 3
        evidence = row["attempt_budget"]
        assert evidence["status"] == "enforced"
        assert evidence["dimension"] == "task_attempt_launches"
        assert evidence["unit"] == "attempts"
        assert evidence["scope"] == {"kind": "task", "id": task["id"]}
        assert evidence["configured_limit"] == 3
        assert evidence["consumed"] == 0
        assert evidence["reserved"] == 0
        assert evidence["released"] == 0
        assert evidence["source"] == "ACP supervisor attempts table"
        assert evidence["freshness"] == "current"
        assert evidence["observed_at"] is None
        assert evidence["observation_time_ref"] == "generated_at"
        assert evidence["provider_usage"]["status"] == "unsupported"
        assert evidence["provider_usage"]["freshness"] == "unknown"

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
        assert row["attempt_budget"]["consumed"] == 1
        assert row["attempt_budget"]["remaining"] == 2


def test_active_queue_rows_report_attempt_budget_usage(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    task = _task(supervisor, 2)
    supervisor.claim(task["id"], "worker-one")

    active = supervisor.ready_queue()["active"]
    assert len(active) == 1
    assert active[0]["max_attempts"] == 2
    assert active[0]["attempts_used"] == 1
    assert active[0]["attempts_remaining"] == 1
    assert active[0]["attempt_budget"]["consumed"] == 1
    assert active[0]["attempt_budget"]["observation_time_ref"] == "generated_at"
