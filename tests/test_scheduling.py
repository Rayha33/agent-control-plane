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


def test_declared_read_inputs_do_not_reserve_peer_write_resources(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    consumer = supervisor.create_task(
        "Update API client",
        "Read the API declaration while changing the client.",
        ["client checks pass"],
        ["beta.txt"],
        read_resources=["alpha.txt"],
    )
    api_writer = make_task(supervisor, "alpha.txt", title="change API declaration")

    queue = supervisor.ready_queue()

    assert {consumer["id"], api_writer["id"]} <= {entry["task_id"] for entry in queue["ready"]}
    supervisor.claim(consumer["id"], "consumer-worker")
    supervisor.claim(api_writer["id"], "api-worker")


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


def test_plan_classifies_parent_child_logical_scope_as_potential_overlap(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    holder = make_task(supervisor, "logical:auth", title="auth subsystem")
    waiting = make_task(supervisor, "logical:auth/session-migration", title="session migration")
    supervisor.claim(holder["id"], "agent-holder")

    conflict = blockers_of(supervisor.plan_claim(waiting["id"]), "resource_conflict")[0]

    assert conflict["overlap"] == "potential"
    assert conflict["resource"] == "logical:auth/session-migration"
    assert conflict["conflicting_resource"] == "logical:auth"


@pytest.mark.parametrize(
    "legacy_declared_path", ["Logical:auth", "./Logical:auth", "./logical:auth"]
)
def test_plan_keeps_legacy_case_variant_prefix_path_separate_from_logical_scope(
    repo: Path, legacy_declared_path: str
) -> None:
    supervisor = GitSupervisor(repo)
    legacy_path = make_task(supervisor, "logical:auth", title="legacy path alias")
    logical_child = make_task(supervisor, "logical:auth/session", title="logical child")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE tasks SET declared_resources_json = ? WHERE id = ?",
            (json.dumps({"logical:auth": legacy_declared_path}), legacy_path["id"]),
        )
    supervisor.claim(legacy_path["id"], "agent-path")

    preview = supervisor.plan_claim(logical_child["id"])

    assert preview["ready"] is True
    assert blockers_of(preview, "resource_conflict") == []


def test_plan_and_queue_serialize_identical_legacy_path_and_logical_keys(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    legacy_path = make_task(supervisor, "logical:auth", title="legacy path", priority=90)
    logical_scope = make_task(supervisor, "logical:auth", title="logical namespace", priority=80)
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE tasks SET declared_resources_json = ? WHERE id = ?",
            (json.dumps({"logical:auth": "Logical:auth"}), legacy_path["id"]),
        )

    queue = supervisor.ready_queue()
    supervisor.claim(legacy_path["id"], "agent-path")
    preview = supervisor.plan_claim(logical_scope["id"])

    assert preview["ready"] is False
    conflict = blockers_of(preview, "resource_conflict")[0]
    assert conflict["overlap"] == "exact"
    assert conflict["owner_task_id"] == legacy_path["id"]
    assert [entry["task_id"] for entry in queue["ready"]] == [legacy_path["id"]]
    queued_conflict = blockers_of(queue["blocked"][0], "resource_conflict")[0]
    assert queued_conflict["overlap"] == "exact"


def test_plan_keeps_sibling_logical_scopes_parallel(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    holder = make_task(supervisor, "logical:auth/session", title="session flow")
    waiting = make_task(supervisor, "logical:auth/tokens", title="token format")
    supervisor.claim(holder["id"], "agent-holder")

    preview = supervisor.plan_claim(waiting["id"])

    assert preview["ready"] is True
    assert blockers_of(preview, "resource_conflict") == []


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


def test_ready_queue_reserves_parent_logical_scope_but_admits_sibling(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    parent = make_task(supervisor, "logical:auth", title="auth", priority=90)
    child = make_task(supervisor, "logical:auth/sessions", title="sessions", priority=80)
    sibling = make_task(supervisor, "logical:billing", title="billing", priority=70)

    queue = supervisor.ready_queue()

    assert [entry["task_id"] for entry in queue["ready"]] == [parent["id"], sibling["id"]]
    blocked = queue["blocked"][0]
    assert blocked["task_id"] == child["id"]
    conflict = next(item for item in blocked["blockers"] if item["kind"] == "resource_conflict")
    assert conflict["overlap"] == "potential"
    assert conflict["owner_kind"] == "queued"
    assert conflict["owner_task_id"] == parent["id"]


def test_ready_queue_keeps_legacy_path_alias_separate_from_logical_child(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    legacy_path = make_task(supervisor, "logical:auth", title="legacy path", priority=90)
    logical_child = make_task(supervisor, "logical:auth/sessions", title="sessions", priority=80)
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE tasks SET declared_resources_json = ? WHERE id = ?",
            (json.dumps({"logical:auth": "./logical:auth"}), legacy_path["id"]),
        )

    queue = supervisor.ready_queue()

    assert [entry["task_id"] for entry in queue["ready"]] == [
        legacy_path["id"],
        logical_child["id"],
    ]
    assert queue["blocked"] == []


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


def test_merge_plan_reports_stale_read_input_without_mutating_state(repo: Path) -> None:
    git(repo, "branch", "integration", "HEAD")
    supervisor = GitSupervisor(repo)
    task = supervisor.create_task(
        "Update API consumer",
        "Use the tracked API input.",
        ["consumer checks pass"],
        ["beta.txt"],
        base_branch="integration",
        read_resources=["alpha.txt"],
    )
    attempt = supervisor.claim(task["id"], "worker-a")
    commit_change(attempt, "beta.txt", "consumer update\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    qc = supervisor.run_qc(submission["id"], "independent-qc")
    assert qc["verdict"] == "pass"

    changed_base = commit_change(attempt, "alpha.txt", "API input v2\n")
    git(repo, "update-ref", "refs/heads/integration", changed_base)
    before_view = state_fingerprint(supervisor)

    entry = supervisor.merge_plan()["order"][0]

    advisory = entry["read_dependency_advisory"]
    assert advisory["state"] == "changed"
    assert advisory["changed_paths"] == [
        {
            "path": "alpha.txt",
            "before_object_oid": git(repo, "rev-parse", f"{task['base_sha']}:alpha.txt"),
            "after_object_oid": git(repo, "rev-parse", "integration:alpha.txt"),
        }
    ]
    assert state_fingerprint(supervisor) == before_view


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
