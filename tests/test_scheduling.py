from __future__ import annotations

import json
from pathlib import Path

import pytest
from support import approve, commit_change, git, init_repo, make_task, state_fingerprint

from agent_control_plane.git_supervisor import GitSupervisor, SupervisorError


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return init_repo(tmp_path)


def blockers_of(preview: dict, kind: str) -> list[dict]:
    return [item for item in preview["blockers"] if item["kind"] == kind]


def test_plan_reports_ready_task_without_mutating_state(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    before = state_fingerprint(supervisor)

    preview = supervisor.plan_claim(created["id"])

    assert preview["ready"] is True
    assert preview["blockers"] == []
    assert preview["resources"] == ["alpha.txt"]
    assert state_fingerprint(supervisor) == before


def test_plan_names_the_owner_of_an_exact_overlap(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    holder = make_task(supervisor, "alpha.txt", title="holder")
    waiting = make_task(supervisor, "alpha.txt", title="waiting")
    attempt = supervisor.claim(holder["id"], "agent-holder")

    preview = supervisor.plan_claim(waiting["id"])

    assert preview["ready"] is False
    conflict = blockers_of(preview, "resource_conflict")[0]
    assert conflict["overlap"] == "exact"
    assert conflict["resource"] == "alpha.txt"
    assert conflict["conflicting_resource"] == "alpha.txt"
    assert conflict["owner_task_id"] == holder["id"]
    assert conflict["owner_task_title"] == "holder"
    assert conflict["owner_attempt_id"] == attempt["id"]
    assert conflict["owner_agent_id"] == "agent-holder"


def test_plan_classifies_directory_scope_as_potential_overlap(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    holder = make_task(supervisor, "src/**", title="holder")
    waiting = make_task(supervisor, "src/module.py", title="waiting")
    supervisor.claim(holder["id"], "agent-holder")

    conflict = blockers_of(supervisor.plan_claim(waiting["id"]), "resource_conflict")[0]

    assert conflict["overlap"] == "potential"
    assert conflict["resource"] == "src/module.py"
    assert conflict["conflicting_resource"] == "src/**"


def test_plan_ignores_an_expired_lease_without_reaping_it(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    holder = make_task(supervisor, "alpha.txt", title="holder")
    waiting = make_task(supervisor, "alpha.txt", title="waiting")
    attempt = supervisor.claim(holder["id"], "agent-holder")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE resource_leases SET lease_expires_at = 1 WHERE attempt_id = ?",
            (attempt["id"],),
        )
        connection.execute(
            "UPDATE attempts SET lease_expires_at = 1 WHERE id = ?", (attempt["id"],)
        )
    before = state_fingerprint(supervisor)

    preview = supervisor.plan_claim(waiting["id"])

    assert blockers_of(preview, "resource_conflict") == []
    assert state_fingerprint(supervisor) == before


def test_plan_and_claim_agree_that_a_dependency_must_be_done(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    upstream = make_task(supervisor, "alpha.txt", title="upstream")
    downstream = make_task(
        supervisor, "beta.txt", title="downstream", dependencies=[upstream["id"]]
    )

    preview = supervisor.plan_claim(downstream["id"])

    blocker = blockers_of(preview, "dependency_incomplete")[0]
    assert blocker["task_id"] == upstream["id"]
    assert blocker["title"] == "upstream"
    assert blocker["status"] == "open"
    assert preview["ready"] is False
    with pytest.raises(SupervisorError) as refused:
        supervisor.claim(downstream["id"], "agent-downstream")
    assert refused.value.code == "dependency_incomplete"


def test_artifact_consumer_waits_for_its_producer(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    producer = make_task(supervisor, "alpha.txt", title="producer", produces=["openapi-schema"])
    consumer = make_task(supervisor, "beta.txt", title="consumer", consumes=["openapi-schema"])

    preview = supervisor.plan_claim(consumer["id"])

    blocker = blockers_of(preview, "artifact_dependency_incomplete")[0]
    assert blocker["artifact"] == "openapi-schema"
    assert blocker["task_id"] == producer["id"]
    assert blocker["status"] == "open"
    with pytest.raises(SupervisorError) as refused:
        supervisor.claim(consumer["id"], "agent-consumer")
    assert refused.value.code == "dependency_incomplete"


def test_consumer_without_a_producer_is_not_blocked(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    consumer = make_task(supervisor, "beta.txt", title="consumer", consumes=["external-feed"])

    preview = supervisor.plan_claim(consumer["id"])

    assert preview["ready"] is True
    assert preview["blockers"] == []


def test_ready_queue_reserves_scopes_so_the_plan_is_launchable(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    first = make_task(supervisor, "src/**", title="first", priority=90)
    second = make_task(supervisor, "src/module.py", title="second", priority=80)
    third = make_task(supervisor, "beta.txt", title="third", priority=70)

    queue = supervisor.ready_queue()

    assert [entry["task_id"] for entry in queue["ready"]] == [first["id"], third["id"]]
    assert [entry["position"] for entry in queue["ready"]] == [1, 2]
    blocked = queue["blocked"][0]
    assert blocked["task_id"] == second["id"]
    conflict = next(item for item in blocked["blockers"] if item["kind"] == "resource_conflict")
    assert conflict["owner_kind"] == "queued"
    assert conflict["owner_task_id"] == first["id"]
    assert conflict["overlap"] == "potential"


def test_ready_queue_is_deterministic_and_read_only(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    make_task(supervisor, "alpha.txt", title="a", priority=50)
    make_task(supervisor, "beta.txt", title="b", priority=50)
    make_task(supervisor, "gamma.txt", title="c", priority=99)
    before = state_fingerprint(supervisor)

    first = json.dumps(supervisor.ready_queue(), sort_keys=True)
    second = json.dumps(supervisor.ready_queue(), sort_keys=True)

    assert first == second
    assert state_fingerprint(supervisor) == before
    assert [entry["title"] for entry in json.loads(first)["ready"]] == ["c", "a", "b"]


def test_dependency_cycle_is_reported_not_hung(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    left = make_task(supervisor, "alpha.txt", title="left", produces=["x"], consumes=["y"])
    right = make_task(supervisor, "beta.txt", title="right", produces=["y"], consumes=["x"])

    queue = supervisor.ready_queue()

    blocked = {entry["task_id"]: entry for entry in queue["blocked"]}
    assert left["id"] in blocked and right["id"] in blocked
    cycle = [item for item in blocked[left["id"]]["blockers"] if item["kind"] == "dependency_cycle"]
    assert cycle and left["id"] in cycle[0]["cycle"]
    assert queue["ready"] == []


def test_merge_plan_orders_overlapping_submissions_and_predicts_conflict(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    first = make_task(supervisor, "alpha.txt", title="first", priority=90)
    second = make_task(supervisor, "alpha.txt", title="second", priority=80)
    approve(supervisor, first["id"], "alpha.txt", "first change\n")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE resource_leases SET task_id = NULL, attempt_id = NULL, lease_expires_at = 0 "
            "WHERE task_id = ?",
            (first["id"],),
        )
    approve(supervisor, second["id"], "alpha.txt", "second change\n")

    plan = supervisor.merge_plan()

    assert [entry["task_id"] for entry in plan["order"]] == [first["id"], second["id"]]
    assert plan["order"][0]["position"] == 1
    assert plan["order"][0]["conflicts_with"] == []
    later = plan["order"][1]
    assert later["conflicts_with"] == [first["id"]]
    assert later["predicted_conflict_paths"] == ["alpha.txt"]


def test_merge_plan_invalidates_a_submission_when_upstream_lands(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt", title="only")
    approve(supervisor, created["id"], "alpha.txt", "worker change\n")
    fresh = supervisor.merge_plan()["order"][0]
    assert fresh["base_moved"] is False
    assert fresh["stale"] is False

    (repo / "gamma.txt").write_text("upstream\n", encoding="utf-8")
    git(repo, "add", "gamma.txt")
    git(repo, "commit", "-m", "upstream work")

    entry = supervisor.merge_plan()["order"][0]

    assert entry["base_moved"] is True
    assert entry["stale"] is True
    assert entry["current_base_sha"] == git(repo, "rev-parse", "main")
    assert entry["upstream_commits"] == 1


def test_merge_plan_is_read_only(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt", title="only")
    approve(supervisor, created["id"], "alpha.txt", "worker change\n")
    before = state_fingerprint(supervisor)

    supervisor.merge_plan()

    assert state_fingerprint(supervisor) == before


def test_merge_plan_respects_declared_dependency_order(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    upstream = make_task(supervisor, "alpha.txt", title="upstream", priority=10)
    downstream = make_task(supervisor, "beta.txt", title="downstream", priority=99)
    approve(supervisor, upstream["id"], "alpha.txt", "upstream change\n")
    approve(supervisor, downstream["id"], "beta.txt", "downstream change\n")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE tasks SET dependencies_json = ? WHERE id = ?",
            (json.dumps([upstream["id"]]), downstream["id"]),
        )

    plan = supervisor.merge_plan()

    assert [entry["task_id"] for entry in plan["order"]] == [upstream["id"], downstream["id"]]
    assert plan["order"][1]["blocked_by"] == [upstream["id"]]


def test_claim_error_identifies_the_conflicting_owner(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    holder = make_task(supervisor, "alpha.txt", title="holder")
    waiting = make_task(supervisor, "alpha.txt", title="waiting")
    supervisor.claim(holder["id"], "agent-holder")

    with pytest.raises(SupervisorError) as busy:
        supervisor.claim(waiting["id"], "agent-waiting")

    assert busy.value.code == "resource_busy"
    assert "agent-holder" in str(busy.value)
    assert holder["id"] in str(busy.value)


def test_artifact_names_are_normalized_and_validated(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt", produces=["  OpenAPI-Schema  "])

    assert created["produces"] == ["openapi-schema"]
    with pytest.raises(SupervisorError) as invalid:
        make_task(supervisor, "beta.txt", produces=["   "])
    assert invalid.value.code == "invalid_artifact"


def test_worktree_changes_do_not_leak_into_the_preview(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    holder = make_task(supervisor, "alpha.txt", title="holder")
    attempt = supervisor.claim(holder["id"], "agent-holder")
    commit_change(attempt, "alpha.txt", "in progress\n")
    waiting = make_task(supervisor, "beta.txt", title="waiting")

    preview = supervisor.plan_claim(waiting["id"])

    assert preview["ready"] is True


def test_existing_database_is_migrated_to_carry_artifacts(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    legacy = make_task(supervisor, "alpha.txt", title="created before artifacts existed")
    with supervisor.connect() as connection:
        connection.execute("ALTER TABLE tasks DROP COLUMN produces_json")
        connection.execute("ALTER TABLE tasks DROP COLUMN consumes_json")

    reopened = GitSupervisor(repo)

    assert reopened.task(legacy["id"])["produces"] == []
    fresh = make_task(reopened, "beta.txt", title="after", produces=["schema"])
    assert fresh["produces"] == ["schema"]
    assert reopened.ready_queue()["ready"][0]["task_id"] in {legacy["id"], fresh["id"]}
