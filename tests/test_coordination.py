from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from agent_control_plane.database import Database
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


def create_task(client, admin_headers, resources=None, dependencies=None, title="Task"):
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
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def claim_task(client, task_id, token):
    return client.post(
        f"/v1/tasks/{task_id}/claim",
        headers={"Authorization": f"Bearer {token}"},
        json={"ttl_seconds": 300},
    )


def resource_tokens(claim):
    return {
        lease["resource"]: lease["fencing_token"] for lease in claim["resource_leases"]
    }


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


def test_atomic_claim_resource_reservation_independent_qc_and_release_gate(
    client, admin_headers
):
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

    reserved_until_integration = claim_task(
        client, colliding_task["id"], worker_b_token
    )
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
    first_submission = submit_task(
        client, task["id"], worker_a_token, first_claim
    ).json()
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

    task_after_review = client.get(
        f"/v1/tasks/{task['id']}", headers=admin_headers
    ).json()
    assert task_after_review["status"] == "changes_requested"
    assert task_after_review["latest_review"]["findings"][0]["severity"] == "critical"

    second_claim_response = claim_task(client, task["id"], worker_b_token)
    assert second_claim_response.status_code == 200, second_claim_response.text
    second_claim = second_claim_response.json()
    assert (
        second_claim["task"]["claim_fencing_token"]
        > first_claim["task"]["claim_fencing_token"]
    )
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

    repaired = submit_task(
        client, task["id"], worker_b_token, second_claim, artifact_hash="b" * 64
    )
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


def test_expired_claim_is_reaped_and_zombie_writer_is_rejected(
    client, app, admin_headers
):
    worker_a = create_agent(client, admin_headers, "crashed-worker", "worker")
    worker_b = create_agent(client, admin_headers, "replacement-worker", "worker")
    token_a = issue_coordination_mandate(client, admin_headers, worker_a["id"])
    token_b = issue_coordination_mandate(client, admin_headers, worker_b["id"])
    task = create_task(client, admin_headers, resources=["deploy:staging"])
    first_claim = claim_task(client, task["id"], token_a).json()

    with app.state.database.connect() as connection:
        connection.execute(
            "UPDATE tasks SET claim_expires_at = 0 WHERE id = ?", (task["id"],)
        )
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
        connection.execute(
            "UPDATE tasks SET status = 'done' WHERE id = ?", (prerequisite["id"],)
        )
    allowed = claim_task(client, dependent["id"], token)
    assert allowed.status_code == 200, allowed.text


def heartbeat_rows(app, task_id):
    with app.state.database.connect() as connection:
        return connection.execute(
            "SELECT COUNT(*) FROM agent_heartbeats WHERE task_id = ?", (task_id,)
        ).fetchone()[0]


def test_conflicted_task_is_reopened_by_an_operator_and_reclaimed(
    client, app, admin_headers
):
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
    assert (
        reclaimed.json()["task"]["claim_fencing_token"]
        > claim["task"]["claim_fencing_token"]
    )
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
        client.get(f"/v1/tasks/{task['id']}", headers=admin_headers).json()["status"]
        == "blocked"
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


def test_audit_failure_rolls_back_the_state_change(
    client, app, admin_headers, monkeypatch
):
    worker = create_agent(client, admin_headers, "atomic-worker", "worker")
    token = issue_coordination_mandate(client, admin_headers, worker["id"])
    task = create_task(client, admin_headers, resources=["repo:atomic"])
    database = app.state.database
    events_before = len(database.audit_events(limit=1000))

    def failing_insert(*_args, **_kwargs):
        raise RuntimeError("audit write failed")

    monkeypatch.setattr(Database, "_insert_audit", staticmethod(failing_insert))
    with pytest.raises(RuntimeError, match="audit write failed"):
        claim_task(client, task["id"], token)
    with pytest.raises(RuntimeError, match="audit write failed"):
        create_task(client, admin_headers, title="Never created")
    monkeypatch.undo()

    # Neither the claim nor the second task survived without its audit event.
    assert (
        client.get(f"/v1/tasks/{task['id']}", headers=admin_headers).json()["status"]
        == "open"
    )
    with database.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1
        lease = connection.execute(
            "SELECT task_id FROM resource_leases WHERE resource = 'repo:atomic'"
        ).fetchone()
    assert lease is None
    assert len(database.audit_events(limit=1000)) == events_before
    assert claim_task(client, task["id"], token).status_code == 200


def test_author_cannot_review_own_submission_even_after_becoming_qc(
    client, app, admin_headers
):
    # No endpoint changes a role, so the role split normally stops self-review
    # first. This pins the second line of defence for an agent whose role is
    # changed underneath it (or a future dual-role agent).
    worker = create_agent(client, admin_headers, "role-changing-worker", "worker")
    token = issue_coordination_mandate(client, admin_headers, worker["id"])
    task = create_task(client, admin_headers, resources=["repo:self-review"])
    claim = claim_task(client, task["id"], token).json()
    submission = submit_task(client, task["id"], token, claim)
    assert submission.status_code == 201, submission.text

    with app.state.database.connect() as connection:
        connection.execute(
            "UPDATE agents SET role = 'qc' WHERE id = ?", (worker["id"],)
        )

    review = client.post(
        f"/v1/submissions/{submission.json()['id']}/reviews",
        headers={"Authorization": f"Bearer {token}"},
        json={"verdict": "pass", "summary": "Self-approved", "findings": []},
    )
    assert review.status_code == 403
    assert review.json()["error"] == "self_review_forbidden"
    status = client.get(f"/v1/tasks/{task['id']}", headers=admin_headers)
    assert status.json()["status"] == "qc_review"
