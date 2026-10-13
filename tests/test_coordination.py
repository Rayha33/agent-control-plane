from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from agent_control_plane.service import ControlPlaneError


def create_agent(client, admin_headers, name, role):
    response = client.post(
        "/v1/agents",
        headers=admin_headers,
        json={
            "name": name,
            "owner": "operations@example.com",
            "role": role,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def issue_coordination_mandate(client, admin_headers, agent_id):
    response = client.post(
        "/v1/mandates",
        headers=admin_headers,
        json={
            "agent_id": agent_id,
            "subject": f"agent:{agent_id}",
            "scopes": [{"action": "coordination.*", "resource": "task:*"}],
            "ttl_seconds": 3600,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["token"]


def create_task(client, admin_headers, resources=None, dependencies=None, title="Task", **extra):
    response = client.post(
        "/v1/tasks",
        headers=admin_headers,
        json={
            "title": title,
            "description": "Implement and verify a bounded product increment.",
            "acceptance_criteria": ["Tests pass", "QC evidence is reproducible"],
            "resources": resources or [],
            "dependencies": dependencies or [],
            "priority": 80,
            **extra,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_public_task_api_refuses_unsupported_provider_limit_before_persistence(
    client, app, admin_headers
):
    before_tasks = app.state.database.one("SELECT COUNT(*) AS count FROM tasks")["count"]
    before_audit = app.state.database.one("SELECT COUNT(*) AS count FROM audit_events")["count"]

    response = client.post(
        "/v1/tasks",
        headers=admin_headers,
        json={
            "title": "Provider-limited task",
            "description": "Do not create work without the requested hard limit.",
            "acceptance_criteria": ["No provider request starts"],
            "resources": ["repo:file:budgeted.py"],
            "provider_cost_limit_usd_micros": 2_500_000,
        },
    )

    assert response.status_code == 422
    assert response.json() == {
        "error": "budget_capability_unsupported",
        "message": (
            "provider cost hard limit requested but unsupported: no authenticated provider "
            "meter or request gate is configured"
        ),
    }
    assert app.state.database.one("SELECT COUNT(*) AS count FROM tasks")["count"] == before_tasks
    assert (
        app.state.database.one("SELECT COUNT(*) AS count FROM audit_events")["count"]
        == before_audit
    )


@pytest.mark.parametrize("invalid_limit", [0, -1, 2**63, True, "2500000", 1.5])
def test_public_task_api_rejects_invalid_provider_limit_values(
    client, app, admin_headers, invalid_limit
):
    before_tasks = app.state.database.one("SELECT COUNT(*) AS count FROM tasks")["count"]

    response = client.post(
        "/v1/tasks",
        headers=admin_headers,
        json={
            "title": "Invalid provider limit",
            "description": "Invalid limit types and bounds fail validation.",
            "acceptance_criteria": ["No task is created"],
            "resources": ["repo:file:invalid-budget.py"],
            "provider_cost_limit_usd_micros": invalid_limit,
        },
    )

    assert response.status_code == 422
    assert app.state.database.one("SELECT COUNT(*) AS count FROM tasks")["count"] == before_tasks


@pytest.mark.parametrize("unsupported_field", ["max_attempts", "max_descendant_attempts"])
def test_public_task_api_rejects_unimplemented_attempt_caps_before_persistence(
    client, app, admin_headers, unsupported_field
):
    before_tasks = app.state.database.one("SELECT COUNT(*) AS count FROM tasks")["count"]
    before_audit = app.state.database.one("SELECT COUNT(*) AS count FROM audit_events")["count"]

    response = client.post(
        "/v1/tasks",
        headers=admin_headers,
        json={
            "title": "Unsupported attempt budget",
            "description": "This request cannot silently lose its hard limit.",
            "acceptance_criteria": ["No task is created"],
            "resources": ["repo:file:unsupported-budget.py"],
            unsupported_field: 1,
        },
    )

    assert response.status_code == 422
    assert unsupported_field in response.text
    assert app.state.database.one("SELECT COUNT(*) AS count FROM tasks")["count"] == before_tasks
    assert (
        app.state.database.one("SELECT COUNT(*) AS count FROM audit_events")["count"]
        == before_audit
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_claims", 0),
        ("max_claims", -1),
        ("max_claims", True),
        ("max_claims", "2"),
        ("max_descendant_claims", -1),
        ("max_descendant_claims", True),
        ("max_descendant_claims", "2"),
        ("parent_task_id", "   "),
    ],
)
def test_public_task_api_rejects_invalid_claim_budget_fields_before_persistence(
    client, app, admin_headers, field, value
):
    before_tasks = app.state.database.one("SELECT COUNT(*) AS count FROM tasks")["count"]
    before_audit = app.state.database.one("SELECT COUNT(*) AS count FROM audit_events")["count"]
    response = client.post(
        "/v1/tasks",
        headers=admin_headers,
        json={
            "title": "Invalid claim budget",
            "description": "Invalid claim caps cannot create a partial task.",
            "acceptance_criteria": ["No task is created"],
            field: value,
        },
    )
    assert response.status_code == 422
    assert app.state.database.one("SELECT COUNT(*) AS count FROM tasks")["count"] == before_tasks
    assert (
        app.state.database.one("SELECT COUNT(*) AS count FROM audit_events")["count"]
        == before_audit
    )


def test_public_task_api_rejects_unknown_parent_before_persistence(client, app, admin_headers):
    before_tasks = app.state.database.one("SELECT COUNT(*) AS count FROM tasks")["count"]
    before_audit = app.state.database.one("SELECT COUNT(*) AS count FROM audit_events")["count"]
    response = client.post(
        "/v1/tasks",
        headers=admin_headers,
        json={
            "title": "Missing parent",
            "description": "A hierarchical claim cap requires a real parent task.",
            "acceptance_criteria": ["No task is created"],
            "parent_task_id": "missing-parent",
        },
    )
    assert response.status_code == 404
    assert response.json()["error"] == "parent_task_not_found"
    assert app.state.database.one("SELECT COUNT(*) AS count FROM tasks")["count"] == before_tasks
    assert (
        app.state.database.one("SELECT COUNT(*) AS count FROM audit_events")["count"]
        == before_audit
    )


def claim_task(client, task_id, token):
    return client.post(
        f"/v1/tasks/{task_id}/claim",
        headers={"Authorization": f"Bearer {token}"},
        json={"ttl_seconds": 300},
    )


def resource_tokens(claim):
    return {lease["resource"]: lease["fencing_token"] for lease in claim["resource_leases"]}


def submit_task(client, task_id, token, claim, artifact_hash="a" * 64):
    return client.post(
        f"/v1/tasks/{task_id}/submissions",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "task_version": claim["task"]["version"],
            "claim_fencing_token": claim["task"]["claim_fencing_token"],
            "resource_fencing_tokens": resource_tokens(claim),
            "base_revision": "main@abc123",
            "artifact_uri": f"patch://{task_id}",
            "artifact_hash": artifact_hash,
            "summary": "Implemented the acceptance criteria and added tests.",
            "evidence": ["pytest: passed", "ruff: passed"],
        },
    )


def test_simultaneous_claims_have_exactly_one_winner(client, app, admin_headers):
    worker_a = create_agent(client, admin_headers, "parallel-worker-a", "worker")
    worker_b = create_agent(client, admin_headers, "parallel-worker-b", "worker")
    tokens = [
        issue_coordination_mandate(client, admin_headers, worker_a["id"]),
        issue_coordination_mandate(client, admin_headers, worker_b["id"]),
    ]
    task = create_task(client, admin_headers, resources=["repo:file:shared.py"])
    start = Barrier(2)

    def compete(token):
        start.wait()
        try:
            claim = app.state.coordination.claim_task(task["id"], token, 300)
            return "won", claim["task"]["owner_agent_id"]
        except ControlPlaneError as error:
            return "lost", error.status_code, error.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(compete, tokens))

    winners = [outcome for outcome in outcomes if outcome[0] == "won"]
    losers = [outcome for outcome in outcomes if outcome[0] == "lost"]
    assert len(winners) == 1
    assert losers == [("lost", 409, "task_unavailable")]


def test_sibling_claims_share_atomic_descendant_budget(client, app, admin_headers):
    worker_a = create_agent(client, admin_headers, "budget-worker-a", "worker")
    worker_b = create_agent(client, admin_headers, "budget-worker-b", "worker")
    tokens = [
        issue_coordination_mandate(client, admin_headers, worker_a["id"]),
        issue_coordination_mandate(client, admin_headers, worker_b["id"]),
    ]
    parent = create_task(
        client,
        admin_headers,
        title="Parent with one descendant claim",
        max_descendant_claims=1,
    )
    children = [
        create_task(
            client,
            admin_headers,
            title=f"Budget child {index}",
            parent_task_id=parent["id"],
            resources=[f"repo:file:budget-child-{index}.py"],
        )
        for index in range(2)
    ]
    claimed_events_before = app.state.database.one(
        "SELECT COUNT(*) AS count FROM audit_events WHERE event_type = 'task.claimed'"
    )["count"]
    start = Barrier(2)

    def compete(args):
        task_id, token = args
        start.wait(timeout=5)
        try:
            return "won", app.state.coordination.claim_task(task_id, token, 300)
        except ControlPlaneError as error:
            return "lost", error.status_code, error.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(
            executor.map(
                compete,
                zip([child["id"] for child in children], tokens, strict=True),
            )
        )

    winners = [outcome for outcome in outcomes if outcome[0] == "won"]
    losers = [outcome for outcome in outcomes if outcome[0] == "lost"]
    assert len(winners) == 1
    assert losers == [("lost", 409, "descendant_claim_budget_exhausted")]
    child_rows = app.state.database.all(
        "SELECT id, claim_fencing_token FROM tasks WHERE parent_task_id = ?",
        (parent["id"],),
    )
    assert sum(row["claim_fencing_token"] for row in child_rows) == 1
    assert (
        app.state.database.one(
            "SELECT claim_fencing_token FROM tasks WHERE id = ?", (parent["id"],)
        )["claim_fencing_token"]
        == 0
    )
    assert (
        app.state.database.one(
            "SELECT COUNT(*) AS count FROM audit_events WHERE event_type = 'task.claimed'"
        )["count"]
        == claimed_events_before + 1
    )
    assert (
        app.state.database.one(
            "SELECT COUNT(*) AS count FROM resource_leases WHERE task_id IN (?, ?)",
            tuple(child["id"] for child in children),
        )["count"]
        == 1
    )
    winner = winners[0][1]
    assert winner["task"]["descendant_claim_budget"]["consumed"] == 0
    assert winner["task"]["ancestor_lineage_integrity"] == "valid"
    parent_after_claim = client.get(f"/v1/tasks/{parent['id']}", headers=admin_headers).json()
    assert parent_after_claim["descendant_claim_budget"]["consumed"] == 1
    assert parent_after_claim["descendant_claim_budget"]["remaining"] == 0
    assert parent_after_claim["ancestor_lineage_integrity"] == "valid"


def test_zero_descendant_cap_allows_parent_claim_but_denies_child(client, admin_headers):
    parent_worker = create_agent(client, admin_headers, "zero-cap-parent-worker", "worker")
    child_worker = create_agent(client, admin_headers, "zero-cap-child-worker", "worker")
    parent_token = issue_coordination_mandate(client, admin_headers, parent_worker["id"])
    child_token = issue_coordination_mandate(client, admin_headers, child_worker["id"])
    parent = create_task(
        client,
        admin_headers,
        title="No descendants permitted",
        max_descendant_claims=0,
    )
    child = create_task(
        client,
        admin_headers,
        title="First denied descendant",
        parent_task_id=parent["id"],
    )

    parent_claim = claim_task(client, parent["id"], parent_token)
    assert parent_claim.status_code == 200, parent_claim.text
    assert parent_claim.json()["task"]["descendant_claim_budget"]["status"] == "exhausted"

    child_claim = claim_task(client, child["id"], child_token)
    assert child_claim.status_code == 409
    assert child_claim.json()["error"] == "descendant_claim_budget_exhausted"
    child_view = client.get(f"/v1/tasks/{child['id']}", headers=admin_headers).json()
    assert child_view["ancestor_lineage_integrity"] == "valid"


@pytest.mark.parametrize(
    ("root_cap", "intermediate_cap", "blocking_ancestor"),
    [(2, 1, "intermediate"), (1, 2, "root")],
)
def test_nested_descendant_cap_is_enforced_at_every_ancestor(
    client, admin_headers, root_cap, intermediate_cap, blocking_ancestor
):
    worker_a = create_agent(client, admin_headers, "nested-cap-worker-a", "worker")
    worker_b = create_agent(client, admin_headers, "nested-cap-worker-b", "worker")
    token_a = issue_coordination_mandate(client, admin_headers, worker_a["id"])
    token_b = issue_coordination_mandate(client, admin_headers, worker_b["id"])
    root = create_task(
        client,
        admin_headers,
        title="Outer budget",
        max_descendant_claims=root_cap,
    )
    intermediate = create_task(
        client,
        admin_headers,
        title="Nested budget",
        parent_task_id=root["id"],
        max_descendant_claims=intermediate_cap,
    )
    grandchildren = [
        create_task(
            client,
            admin_headers,
            title=f"Nested child {index}",
            parent_task_id=intermediate["id"],
            resources=[f"repo:file:nested-budget-{index}.py"],
        )
        for index in range(2)
    ]

    first = claim_task(client, grandchildren[0]["id"], token_a)
    assert first.status_code == 200, first.text
    second = claim_task(client, grandchildren[1]["id"], token_b)
    assert second.status_code == 409
    assert second.json()["error"] == "descendant_claim_budget_exhausted"
    limiting_id = intermediate["id"] if blocking_ancestor == "intermediate" else root["id"]
    assert limiting_id in second.json()["message"]
    assert (
        client.get(f"/v1/tasks/{intermediate['id']}", headers=admin_headers).json()[
            "descendant_claim_budget"
        ]["consumed"]
        == 1
    )
    assert (
        client.get(f"/v1/tasks/{root['id']}", headers=admin_headers).json()[
            "descendant_claim_budget"
        ]["consumed"]
        == 1
    )


def test_task_view_marks_corrupt_ancestor_lineage_invalid(client, app, admin_headers):
    parent = create_task(client, admin_headers, title="Corruption fixture parent")
    child = create_task(
        client,
        admin_headers,
        title="Corruption fixture child",
        parent_task_id=parent["id"],
    )
    with sqlite3.connect(app.state.database.path) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("DROP TRIGGER task_claim_budget_config_immutable")
        connection.execute(
            "UPDATE tasks SET parent_task_id = 'missing-parent' WHERE id = ?",
            (child["id"],),
        )

    response = client.get(f"/v1/tasks/{child['id']}", headers=admin_headers)
    assert response.status_code == 200, response.text
    assert response.json()["ancestor_lineage_integrity"] == "invalid"


def test_expired_claim_still_consumes_task_claim_budget(client, app, admin_headers):
    worker = create_agent(client, admin_headers, "budget-expired-worker", "worker")
    token = issue_coordination_mandate(client, admin_headers, worker["id"])
    task = create_task(
        client,
        admin_headers,
        title="One claim survives expiry",
        max_claims=1,
    )
    first = claim_task(client, task["id"], token)
    assert first.status_code == 200, first.text
    first_task_view = first.json()["task"]
    claim_budget = first_task_view["claim_budget"]
    assert {key: claim_budget[key] for key in claim_budget if key != "observed_at"} == {
        "scope": "task",
        "unit": "successful_claim_reservations",
        "limit": 1,
        "consumed": 1,
        "remaining": 0,
        "status": "exhausted",
        "source": "tasks.claim_fencing_token",
        "enforcement": "BEGIN IMMEDIATE task claim and SQLite trigger",
    }
    assert claim_budget["observed_at"]

    with app.state.database.connect() as connection:
        connection.execute(
            """
            UPDATE tasks SET status = 'open', owner_agent_id = NULL, claim_expires_at = 1
            WHERE id = ?
            """,
            (task["id"],),
        )

    claimed_events_before = app.state.database.one(
        "SELECT COUNT(*) AS count FROM audit_events WHERE event_type = 'task.claimed'"
    )["count"]
    second = claim_task(client, task["id"], token)

    assert second.status_code == 409
    assert second.json()["error"] == "task_claim_budget_exhausted"
    stored = app.state.database.one(
        "SELECT claim_fencing_token FROM tasks WHERE id = ?", (task["id"],)
    )
    assert stored["claim_fencing_token"] == 1
    assert (
        app.state.database.one(
            "SELECT COUNT(*) AS count FROM audit_events WHERE event_type = 'task.claimed'"
        )["count"]
        == claimed_events_before
    )


def test_atomic_claim_resource_reservation_independent_qc_and_release_gate(client, admin_headers):
    worker_a = create_agent(client, admin_headers, "worker-a", "worker")
    worker_b = create_agent(client, admin_headers, "worker-b", "worker")
    qc_agent = create_agent(client, admin_headers, "critical-qc", "qc")
    worker_a_token = issue_coordination_mandate(client, admin_headers, worker_a["id"])
    worker_b_token = issue_coordination_mandate(client, admin_headers, worker_b["id"])
    qc_token = issue_coordination_mandate(client, admin_headers, qc_agent["id"])

    task = create_task(
        client,
        admin_headers,
        resources=["src/policy.py", "database:policies"],
        title="Policy engine",
    )
    colliding_task = create_task(
        client,
        admin_headers,
        resources=["src/policy.py"],
        title="Conflicting policy edit",
    )

    claimed_response = claim_task(client, task["id"], worker_a_token)
    assert claimed_response.status_code == 200, claimed_response.text
    claim = claimed_response.json()

    duplicate = claim_task(client, task["id"], worker_b_token)
    assert duplicate.status_code == 409
    assert duplicate.json()["error"] == "task_unavailable"

    resource_collision = claim_task(client, colliding_task["id"], worker_b_token)
    assert resource_collision.status_code == 409
    assert resource_collision.json()["error"] == "resource_busy"

    heartbeat = client.post(
        f"/v1/tasks/{task['id']}/heartbeat",
        headers={"Authorization": f"Bearer {worker_a_token}"},
        json={
            "claim_fencing_token": claim["task"]["claim_fencing_token"],
            "resource_fencing_tokens": resource_tokens(claim),
            "ttl_seconds": 300,
            "checkpoint": {"step": "tests", "files_changed": ["src/policy.py"]},
        },
    )
    assert heartbeat.status_code == 200, heartbeat.text

    submission_response = submit_task(client, task["id"], worker_a_token, claim)
    assert submission_response.status_code == 201, submission_response.text
    submission = submission_response.json()

    still_reserved = claim_task(client, colliding_task["id"], worker_b_token)
    assert still_reserved.status_code == 409
    assert still_reserved.json()["error"] == "resource_busy"

    worker_review = client.post(
        f"/v1/submissions/{submission['id']}/reviews",
        headers={"Authorization": f"Bearer {worker_a_token}"},
        json={"verdict": "pass", "summary": "Self-approved", "findings": []},
    )
    assert worker_review.status_code == 403
    assert worker_review.json()["error"] == "role_forbidden"

    premature_complete = client.post(
        f"/v1/tasks/{task['id']}/complete",
        headers=admin_headers,
        json={"reason": "Attempt before QC"},
    )
    assert premature_complete.status_code == 409
    assert premature_complete.json()["error"] == "qc_gate_not_passed"

    review = client.post(
        f"/v1/submissions/{submission['id']}/reviews",
        headers={"Authorization": f"Bearer {qc_token}"},
        json={
            "verdict": "pass",
            "summary": "All requirements reproduced independently.",
            "findings": [],
        },
    )
    assert review.status_code == 201, review.text
    assert review.json()["qc_agent_id"] == qc_agent["id"]

    reserved_until_integration = claim_task(client, colliding_task["id"], worker_b_token)
    assert reserved_until_integration.status_code == 409

    completed = client.post(
        f"/v1/tasks/{task['id']}/complete",
        headers=admin_headers,
        json={"reason": "Independent QC passed"},
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "done"

    collision_released = claim_task(client, colliding_task["id"], worker_b_token)
    assert collision_released.status_code == 200, collision_released.text


def test_qc_revision_requeues_work_with_new_fencing_tokens(client, admin_headers):
    worker_a = create_agent(client, admin_headers, "first-worker", "worker")
    worker_b = create_agent(client, admin_headers, "repair-worker", "worker")
    qc_agent = create_agent(client, admin_headers, "adversarial-qc", "qc")
    worker_a_token = issue_coordination_mandate(client, admin_headers, worker_a["id"])
    worker_b_token = issue_coordination_mandate(client, admin_headers, worker_b["id"])
    qc_token = issue_coordination_mandate(client, admin_headers, qc_agent["id"])
    task = create_task(client, admin_headers, resources=["src/service.py"])

    first_claim = claim_task(client, task["id"], worker_a_token).json()
    first_submission = submit_task(client, task["id"], worker_a_token, first_claim).json()
    review = client.post(
        f"/v1/submissions/{first_submission['id']}/reviews",
        headers={"Authorization": f"Bearer {qc_token}"},
        json={
            "verdict": "revise",
            "summary": "A stale parent mandate remains usable.",
            "findings": [
                {
                    "severity": "critical",
                    "requirement": "Revocation cascades through delegation chains",
                    "finding": "The child remains authorized after parent revocation.",
                    "evidence": "Reproduced with parent revoke followed by child authorize.",
                    "required_fix": "Validate every ancestor mandate on each action.",
                }
            ],
        },
    )
    assert review.status_code == 201, review.text
    assert review.json()["verdict"] == "revise"

    task_after_review = client.get(f"/v1/tasks/{task['id']}", headers=admin_headers).json()
    assert task_after_review["status"] == "changes_requested"
    assert task_after_review["latest_review"]["findings"][0]["severity"] == "critical"

    second_claim_response = claim_task(client, task["id"], worker_b_token)
    assert second_claim_response.status_code == 200, second_claim_response.text
    second_claim = second_claim_response.json()
    assert second_claim["task"]["claim_fencing_token"] > first_claim["task"]["claim_fencing_token"]
    assert (
        resource_tokens(second_claim)["src/service.py"]
        > resource_tokens(first_claim)["src/service.py"]
    )

    zombie_heartbeat = client.post(
        f"/v1/tasks/{task['id']}/heartbeat",
        headers={"Authorization": f"Bearer {worker_a_token}"},
        json={
            "claim_fencing_token": first_claim["task"]["claim_fencing_token"],
            "resource_fencing_tokens": resource_tokens(first_claim),
            "checkpoint": {"step": "late write"},
        },
    )
    assert zombie_heartbeat.status_code == 409

    repaired = submit_task(client, task["id"], worker_b_token, second_claim, artifact_hash="b" * 64)
    assert repaired.status_code == 201, repaired.text
    passed = client.post(
        f"/v1/submissions/{repaired.json()['id']}/reviews",
        headers={"Authorization": f"Bearer {qc_token}"},
        json={
            "verdict": "pass",
            "summary": "The revocation regression test now passes.",
            "findings": [],
        },
    )
    assert passed.status_code == 201, passed.text


def test_expired_claim_is_reaped_and_zombie_writer_is_rejected(client, app, admin_headers):
    worker_a = create_agent(client, admin_headers, "crashed-worker", "worker")
    worker_b = create_agent(client, admin_headers, "replacement-worker", "worker")
    token_a = issue_coordination_mandate(client, admin_headers, worker_a["id"])
    token_b = issue_coordination_mandate(client, admin_headers, worker_b["id"])
    task = create_task(client, admin_headers, resources=["deploy:staging"])
    first_claim = claim_task(client, task["id"], token_a).json()

    with app.state.database.connect() as connection:
        connection.execute("UPDATE tasks SET claim_expires_at = 0 WHERE id = ?", (task["id"],))
        connection.execute(
            "UPDATE resource_leases SET expires_at = 0 WHERE task_id = ?",
            (task["id"],),
        )

    reaped = client.post("/v1/coordination/reap", headers=admin_headers)
    assert reaped.status_code == 200
    assert task["id"] in reaped.json()["orphaned_task_ids"]

    replacement = claim_task(client, task["id"], token_b)
    assert replacement.status_code == 200, replacement.text
    replacement_claim = replacement.json()
    assert (
        replacement_claim["task"]["claim_fencing_token"]
        > first_claim["task"]["claim_fencing_token"]
    )
    zombie_submission = submit_task(client, task["id"], token_a, first_claim)
    assert zombie_submission.status_code == 409
    assert zombie_submission.json()["error"] == "stale_claim_fencing_token"


def test_expired_approved_reservation_cannot_complete(client, app, admin_headers):
    worker = create_agent(client, admin_headers, "reservation-worker", "worker")
    reviewer = create_agent(client, admin_headers, "reservation-qc", "qc")
    worker_token = issue_coordination_mandate(client, admin_headers, worker["id"])
    reviewer_token = issue_coordination_mandate(client, admin_headers, reviewer["id"])
    task_spec = create_task(client, admin_headers, resources=["src/reserved.py"])
    claim = claim_task(client, task_spec["id"], worker_token).json()
    submission = submit_task(client, task_spec["id"], worker_token, claim).json()
    review = client.post(
        f"/v1/submissions/{submission['id']}/reviews",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={
            "verdict": "pass",
            "summary": "Evidence reproduced before the reservation expired.",
            "findings": [],
        },
    )
    assert review.status_code == 201, review.text
    with app.state.database.connect() as connection:
        connection.execute(
            "UPDATE resource_leases SET expires_at = 0 WHERE task_id = ?",
            (task_spec["id"],),
        )
    completed = client.post(
        f"/v1/tasks/{task_spec['id']}/complete",
        headers=admin_headers,
        json={"reason": "must not bypass a lost reservation"},
    )
    assert completed.status_code == 409
    assert completed.json()["error"] == "reservation_lost"


def test_dependency_must_be_done_before_claim(client, app, admin_headers):
    worker = create_agent(client, admin_headers, "dependency-worker", "worker")
    token = issue_coordination_mandate(client, admin_headers, worker["id"])
    prerequisite = create_task(client, admin_headers, title="Prerequisite")
    dependent = create_task(
        client,
        admin_headers,
        dependencies=[prerequisite["id"]],
        title="Dependent",
    )

    blocked = claim_task(client, dependent["id"], token)
    assert blocked.status_code == 409
    assert blocked.json()["error"] == "dependency_incomplete"

    with app.state.database.connect() as connection:
        connection.execute("UPDATE tasks SET status = 'done' WHERE id = ?", (prerequisite["id"],))
    allowed = claim_task(client, dependent["id"], token)
    assert allowed.status_code == 200, allowed.text


def heartbeat_rows(app, task_id):
    with app.state.database.connect() as connection:
        return connection.execute(
            "SELECT COUNT(*) FROM agent_heartbeats WHERE task_id = ?", (task_id,)
        ).fetchone()[0]


def test_conflicted_task_is_reopened_by_an_operator_and_reclaimed(client, app, admin_headers):
    worker = create_agent(client, admin_headers, "conflict-worker", "worker")
    token = issue_coordination_mandate(client, admin_headers, worker["id"])
    task = create_task(client, admin_headers, resources=["deploy:reopen-target"])
    claim = claim_task(client, task["id"], token).json()
    submitted = submit_task(client, task["id"], token, claim)
    assert submitted.status_code == 201, submitted.text

    with app.state.database.connect() as connection:
        connection.execute(
            "UPDATE resource_leases SET expires_at = 0 WHERE task_id = ?",
            (task["id"],),
        )
    reaped = client.post("/v1/coordination/reap", headers=admin_headers).json()
    assert task["id"] in reaped["conflicted_task_ids"]

    stuck = claim_task(client, task["id"], token)
    assert stuck.status_code == 409
    assert stuck.json()["error"] == "task_unavailable"

    reopened = client.post(
        f"/v1/tasks/{task['id']}/reopen",
        headers=admin_headers,
        json={"reason": "Reservation lapsed during review; operator confirmed a redo"},
    )
    assert reopened.status_code == 200, reopened.text
    assert reopened.json()["status"] == "open"
    assert reopened.json()["owner_agent_id"] is None
    assert reopened.json()["version"] > claim["task"]["version"]
    assert heartbeat_rows(app, task["id"]) == 0

    reclaimed = claim_task(client, task["id"], token)
    assert reclaimed.status_code == 200, reclaimed.text
    assert reclaimed.json()["task"]["claim_fencing_token"] > claim["task"]["claim_fencing_token"]
    assert (
        resource_tokens(reclaimed.json())["deploy:reopen-target"]
        > resource_tokens(claim)["deploy:reopen-target"]
    )

    verification = client.get("/v1/audit/verify", headers=admin_headers).json()
    assert verification["valid"] is True
    events = client.get("/v1/audit", headers=admin_headers).json()
    reopen_events = [e for e in events if e["event_type"] == "task.reopened"]
    assert reopen_events[0]["payload"]["previous_status"] == "conflicted"


def test_blocked_task_is_reopened_after_human_action(client, app, admin_headers):
    worker = create_agent(client, admin_headers, "blocked-worker", "worker")
    qc_agent = create_agent(client, admin_headers, "blocking-qc", "qc")
    worker_token = issue_coordination_mandate(client, admin_headers, worker["id"])
    qc_token = issue_coordination_mandate(client, admin_headers, qc_agent["id"])
    task = create_task(client, admin_headers, resources=["src/blocked.py"])
    claim = claim_task(client, task["id"], worker_token).json()
    submission = submit_task(client, task["id"], worker_token, claim).json()

    blocked = client.post(
        f"/v1/submissions/{submission['id']}/reviews",
        headers={"Authorization": f"Bearer {qc_token}"},
        json={
            "verdict": "block",
            "summary": "The change needs a policy decision before it can proceed.",
            "findings": [
                {
                    "severity": "high",
                    "requirement": "Deployment targets are declared before execution",
                    "finding": "The artifact touches an undeclared production target.",
                    "evidence": "Diff writes deployment:production:api.",
                    "required_fix": "Declare the target or split the change.",
                }
            ],
        },
    )
    assert blocked.status_code == 201, blocked.text
    assert (
        client.get(f"/v1/tasks/{task['id']}", headers=admin_headers).json()["status"] == "blocked"
    )
    assert heartbeat_rows(app, task["id"]) == 0

    reopened = client.post(
        f"/v1/tasks/{task['id']}/reopen",
        headers=admin_headers,
        json={"reason": "Policy decision recorded; work may resume"},
    )
    assert reopened.status_code == 200, reopened.text
    assert reopened.json()["status"] == "open"
    assert reopened.json()["latest_review"]["verdict"] == "block"

    reclaimed = claim_task(client, task["id"], worker_token)
    assert reclaimed.status_code == 200, reclaimed.text


def test_reopen_is_refused_outside_conflicted_and_blocked(client, admin_headers):
    task = create_task(client, admin_headers, title="Still open")
    refused = client.post(
        f"/v1/tasks/{task['id']}/reopen",
        headers=admin_headers,
        json={"reason": "Nothing to reopen"},
    )
    assert refused.status_code == 409
    assert refused.json()["error"] == "task_not_reopenable"


def test_heartbeat_rows_end_with_the_claim(client, app, admin_headers):
    worker = create_agent(client, admin_headers, "heartbeat-worker", "worker")
    qc_agent = create_agent(client, admin_headers, "heartbeat-qc", "qc")
    worker_token = issue_coordination_mandate(client, admin_headers, worker["id"])
    qc_token = issue_coordination_mandate(client, admin_headers, qc_agent["id"])
    task = create_task(client, admin_headers, resources=["src/heartbeat.py"])
    claim = claim_task(client, task["id"], worker_token).json()
    assert heartbeat_rows(app, task["id"]) == 1

    beat = client.post(
        f"/v1/tasks/{task['id']}/heartbeat",
        headers={"Authorization": f"Bearer {worker_token}"},
        json={
            "claim_fencing_token": claim["task"]["claim_fencing_token"],
            "resource_fencing_tokens": resource_tokens(claim),
            "checkpoint": {"step": "tests"},
        },
    )
    assert beat.status_code == 200, beat.text
    assert heartbeat_rows(app, task["id"]) == 1

    submission = submit_task(client, task["id"], worker_token, claim).json()
    assert heartbeat_rows(app, task["id"]) == 0

    passed = client.post(
        f"/v1/submissions/{submission['id']}/reviews",
        headers={"Authorization": f"Bearer {qc_token}"},
        json={"verdict": "pass", "summary": "Reproduced.", "findings": []},
    )
    assert passed.status_code == 201, passed.text
    completed = client.post(
        f"/v1/tasks/{task['id']}/complete",
        headers=admin_headers,
        json={"reason": "QC passed"},
    )
    assert completed.status_code == 200, completed.text
    assert heartbeat_rows(app, task["id"]) == 0
