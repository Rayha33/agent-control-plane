from __future__ import annotations

import json
import sqlite3

import pytest

from agent_control_plane.coordination_schemas import (
    HeartbeatRequest,
    QCReviewCreate,
    SubmissionCreate,
    TaskCreate,
)
from agent_control_plane.schemas import (
    AgentCreate,
    ApprovalResolve,
    AuthorizationRequest,
    MandateCreate,
    PolicyCreate,
    Scope,
)

# Every write that records an audit event, driven once with the audit append
# failing. A row that outlives its failed event is a state change the hash chain
# never recorded. The append fails two ways: append_audit raising before it
# touches SQLite, and a trigger making SQLite refuse the INSERT inside whatever
# transaction is open, so moving the call without sharing the transaction fails.

COORDINATION = [{"action": "coordination.*", "resource": "task:*"}]
PAYMENTS = [{"action": "payments.*", "resource": "*"}]


def create_agent(client, admin_headers, name, role="worker"):
    response = client.post(
        "/v1/agents",
        headers=admin_headers,
        json={"name": name, "owner": "operations@example.com", "role": role},
    )
    assert response.status_code == 201, response.text
    return response.json()


def issue_mandate(client, admin_headers, agent_id, scopes=None):
    response = client.post(
        "/v1/mandates",
        headers=admin_headers,
        json={
            "agent_id": agent_id,
            "subject": f"agent:{agent_id}",
            "scopes": scopes or COORDINATION,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def create_task(client, admin_headers, resource):
    response = client.post(
        "/v1/tasks",
        headers=admin_headers,
        json={
            "title": f"Change {resource}",
            "description": "A bounded change driven through the real API.",
            "acceptance_criteria": ["State and audit commit together"],
            "resources": [resource],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def claimed_task(client, app, admin_headers, label):
    worker = create_agent(client, admin_headers, f"{label}-worker")
    token = issue_mandate(client, admin_headers, worker["id"])["token"]
    task = create_task(client, admin_headers, f"src/{label}.py")
    claim = app.state.coordination.claim_task(task["id"], token, 300)
    return token, task, claim


def resource_tokens(claim):
    return {
        lease["resource"]: lease["fencing_token"] for lease in claim["resource_leases"]
    }


def submission_for(claim):
    return SubmissionCreate(
        task_version=claim["task"]["version"],
        claim_fencing_token=claim["task"]["claim_fencing_token"],
        resource_fencing_tokens=resource_tokens(claim),
        base_revision="main@abc123",
        artifact_uri="patch://atomic-audit",
        artifact_hash="a" * 64,
        summary="Implemented the acceptance criteria.",
    )


def submitted_task(client, app, admin_headers, label):
    token, task, claim = claimed_task(client, app, admin_headers, label)
    submission = app.state.coordination.submit(task["id"], token, submission_for(claim))
    reviewer = create_agent(client, admin_headers, f"{label}-qc", "qc")
    qc_token = issue_mandate(client, admin_headers, reviewer["id"])["token"]
    return task, submission, qc_token


def pending_approval(client, app, admin_headers):
    """A payments mandate, an approval-gated policy and one pending request."""
    agent = create_agent(client, admin_headers, "payer")
    token = issue_mandate(client, admin_headers, agent["id"], PAYMENTS)["token"]
    app.state.service.create_policy(
        PolicyCreate(
            action_pattern="payments.*", resource_pattern="*", requires_approval=True
        )
    )
    request = AuthorizationRequest(
        action="payments.charge", resource="invoice:1", context={"amount_cents": 100}
    )
    decision = app.state.service.authorize(token, request)
    assert decision["decision"] == "approval_required", decision
    return token, request, decision["action_request_id"]


SCENARIOS = {}


def scenario(name, event_type):
    """Register a builder: it sets up state and returns the write under test."""

    def register(build):
        SCENARIOS[name] = (event_type, build)
        return build

    return register


@scenario("create_task", "task.created")
def _create_task(client, app, admin_headers):
    request = TaskCreate(
        title="Atomic", description="A bounded change.", acceptance_criteria=["Done"]
    )
    return lambda: app.state.coordination.create_task(request)


@scenario("claim", "task.claimed")
def _claim(client, app, admin_headers):
    worker = create_agent(client, admin_headers, "claim-worker")
    token = issue_mandate(client, admin_headers, worker["id"])["token"]
    task = create_task(client, admin_headers, "src/claim.py")
    return lambda: app.state.coordination.claim_task(task["id"], token, 300)


@scenario("heartbeat", "task.heartbeat")
def _heartbeat(client, app, admin_headers):
    token, task, claim = claimed_task(client, app, admin_headers, "heartbeat")
    request = HeartbeatRequest(
        claim_fencing_token=claim["task"]["claim_fencing_token"],
        resource_fencing_tokens=resource_tokens(claim),
        checkpoint={"step": "tests"},
    )
    return lambda: app.state.coordination.heartbeat(task["id"], token, request)


@scenario("submit", "submission.created")
def _submit(client, app, admin_headers):
    token, task, claim = claimed_task(client, app, admin_headers, "submit")
    request = submission_for(claim)
    return lambda: app.state.coordination.submit(task["id"], token, request)


@scenario("review", "review.completed")
def _review(client, app, admin_headers):
    _task, submission, qc_token = submitted_task(client, app, admin_headers, "review")
    request = QCReviewCreate(verdict="pass", summary="Reproduced the evidence.")
    return lambda: app.state.coordination.review(submission["id"], qc_token, request)


@scenario("complete", "task.completed")
def _complete(client, app, admin_headers):
    task, submission, qc_token = submitted_task(client, app, admin_headers, "complete")
    app.state.coordination.review(
        submission["id"],
        qc_token,
        QCReviewCreate(verdict="pass", summary="Reproduced the evidence."),
    )
    return lambda: app.state.coordination.complete_task(task["id"], "QC passed")


@scenario("reopen", "task.reopened")
def _reopen(client, app, admin_headers):
    task, submission, qc_token = submitted_task(client, app, admin_headers, "reopen")
    app.state.coordination.review(
        submission["id"],
        qc_token,
        QCReviewCreate(verdict="human_required", summary="Needs a human decision."),
    )
    return lambda: app.state.coordination.reopen_task(task["id"], "Decision made")


@scenario("reap", "coordination.reaped")
def _reap(client, app, admin_headers):
    _token, task, _claim = claimed_task(client, app, admin_headers, "reap")
    with app.state.database.connect() as connection:
        connection.execute(
            "UPDATE tasks SET claim_expires_at = 1 WHERE id = ?", (task["id"],)
        )
    return app.state.coordination.reap_expired


@scenario("create_agent", "agent.created")
def _create_agent(client, app, admin_headers):
    request = AgentCreate(name="atomic-agent", owner="operations@example.com")
    return lambda: app.state.service.create_agent(request)


@scenario("create_policy", "policy.created")
def _create_policy(client, app, admin_headers):
    request = PolicyCreate(action_pattern="payments.*", resource_pattern="*")
    return lambda: app.state.service.create_policy(request)


@scenario("issue_mandate", "mandate.issued")
def _issue_mandate(client, app, admin_headers):
    agent = create_agent(client, admin_headers, "mandate-agent")
    request = MandateCreate(
        agent_id=agent["id"],
        subject="operator",
        scopes=[Scope(action="payments.charge", resource="*")],
    )
    return lambda: app.state.service.issue_mandate(request)


@scenario("approval_required", "authorization.decided")
def _approval_required(client, app, admin_headers):
    token, request, _action_id = pending_approval(client, app, admin_headers)
    second = request.model_copy(update={"resource": "invoice:2"})
    return lambda: app.state.service.authorize(token, second)


@scenario("resolve_approval", "approval.approved")
def _resolve_approval(client, app, admin_headers):
    _token, _request, action_id = pending_approval(client, app, admin_headers)
    resolution = ApprovalResolve(approved=True, reason="Expected charge")
    return lambda: app.state.service.resolve_approval(action_id, resolution)


@scenario("consume_approval", "authorization.decided")
def _consume_approval(client, app, admin_headers):
    token, request, action_id = pending_approval(client, app, admin_headers)
    app.state.service.resolve_approval(
        action_id, ApprovalResolve(approved=True, reason="Expected charge")
    )
    consuming = request.model_copy(update={"approval_id": action_id})
    return lambda: app.state.service.authorize(token, consuming)


@scenario("set_agent_disabled", "agent.disabled")
def _set_agent_disabled(client, app, admin_headers):
    agent = create_agent(client, admin_headers, "kill-switch-agent")
    return lambda: app.state.service.set_agent_state(
        agent["id"], disabled=True, reason="Emergency stop"
    )


@scenario("revoke_mandate", "mandate.revoked")
def _revoke_mandate(client, app, admin_headers):
    agent = create_agent(client, admin_headers, "revoked-agent")
    mandate = issue_mandate(client, admin_headers, agent["id"])
    return lambda: app.state.service.revoke_mandate(mandate["id"], "Rotated")


def fail_in_python(*_args, **_kwargs):
    raise OSError("induced audit failure")


def fail_in_sqlite(database):
    with database.connect() as connection:
        connection.execute(
            "CREATE TRIGGER refuse_audit BEFORE INSERT ON audit_events "
            "BEGIN SELECT RAISE(ABORT, 'induced audit failure'); END"
        )


def snapshot(database):
    """Every row of every table, sqlite_sequence included, comparable by value."""
    with database.connect() as connection:
        tables = [
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            )
        ]
        return {
            table: sorted(
                json.dumps(dict(row), sort_keys=True)
                for row in connection.execute(f"SELECT * FROM {table}")
            )
            for table in tables
        }


@pytest.mark.parametrize("failure", ["python", "sqlite"])
@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_a_write_never_outlives_its_failed_audit_event(
    client, app, admin_headers, monkeypatch, name, failure
):
    _event_type, build = SCENARIOS[name]
    write = build(client, app, admin_headers)
    database = app.state.database
    if failure == "python":
        monkeypatch.setattr(database, "append_audit", fail_in_python)
        expected = OSError
    else:
        fail_in_sqlite(database)
        expected = sqlite3.IntegrityError
    before = snapshot(database)

    with pytest.raises(expected, match="induced audit failure"):
        write()

    assert snapshot(database) == before, f"{name} committed without its audit event"
    assert database.verify_audit_chain()["valid"] is True


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_each_write_appends_exactly_its_audit_event(client, app, admin_headers, name):
    # The control for the test above: a scenario that never reached its audit
    # call would leave the snapshot unchanged for the wrong reason.
    event_type, build = SCENARIOS[name]
    write = build(client, app, admin_headers)
    database = app.state.database
    before = len(database.audit_events(limit=10_000))

    write()

    events = database.audit_events(limit=10_000)
    assert [event["event_type"] for event in events[: len(events) - before]] == [
        event_type
    ]
    assert database.verify_audit_chain()["valid"] is True


def test_a_caller_connection_must_already_hold_a_transaction(app):
    # Outside a transaction the chain head is read without the write lock, so two
    # such callers could both chain from it and fork the chain.
    database = app.state.database
    with database.connect() as connection:
        with pytest.raises(ValueError, match="transaction"):
            database.append_audit("test.event", "tester", {}, connection=connection)
    assert database.audit_events() == []
