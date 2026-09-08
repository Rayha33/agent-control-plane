"""Board #1832: a mutation and its audit event commit together, or neither commits.

Independent QC on #1831 found ``task.reopened`` writing its state change in one
transaction and its audit event in another. This suite is the general control. Every
mutating entry point is driven for real, the audit append is then made to fail, and
the whole database is compared against the snapshot taken immediately before the call.
A row that survives its failed audit event is a state change with no entry in the
tamper-evident chain, which is exactly what the chain exists to make impossible.

Two failure modes, because they fail in different places:

``method``
    ``Database.append_audit`` raises before it touches SQLite -- the injected fault the
    row describes, and the one that catches a mutation whose transaction has already
    closed by the time the audit is attempted.
``insert``
    a ``BEFORE INSERT`` trigger on ``audit_events`` aborts the real INSERT. Nothing is
    mocked: SQLite itself refuses the write from inside whatever transaction happens to
    be open, so a fix that merely moved the *call* without sharing the *transaction*
    still fails here.

``coordination.reopen_task`` is carried as the control that #1831 already fixed: it is
green in both modes before and after this change. ``test_scenario_reaches_its_audit_event``
is the other control -- a scenario whose setup silently stopped reaching the audit call
would make the rollback assertion pass for the wrong reason, so each scenario must also
be shown to append exactly one event of its type on the success path.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from typing import Any

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
from agent_control_plane.service import ControlPlaneError
from agent_control_plane.side_effects import (
    CoordinationClaimVerifier,
    FencedGateway,
    SideEffectRequest,
    postgres_schema_adapter,
)

DB_RESOURCE = "db:orders/public"


# --------------------------------------------------------------------------- helpers -------


def _agent(client, admin_headers, name, role="worker"):
    response = client.post(
        "/v1/agents",
        headers=admin_headers,
        json={"name": name, "owner": "operations@example.com", "role": role},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _mandate(client, admin_headers, agent_id, scopes=None):
    response = client.post(
        "/v1/mandates",
        headers=admin_headers,
        json={
            "agent_id": agent_id,
            "subject": f"agent:{agent_id}",
            "scopes": scopes or [{"action": "coordination.*", "resource": "task:*"}],
            "ttl_seconds": 3600,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _task(client, admin_headers, resources, title="Atomic audit target"):
    response = client.post(
        "/v1/tasks",
        headers=admin_headers,
        json={
            "title": title,
            "description": "Bounded change driven through the real coordination API.",
            "acceptance_criteria": ["State and audit commit together"],
            "resources": resources,
            "dependencies": [],
            "priority": 50,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _resource_tokens(claimed):
    return {lease["resource"]: lease["fencing_token"] for lease in claimed["resource_leases"]}


def _approval_setup(client, app, admin_headers, resource="invoice:1"):
    """A mandate, an approval-gated policy and one pending action request."""

    agent = _agent(client, admin_headers, f"approval-agent-{resource}", "worker")
    token = _mandate(
        client,
        admin_headers,
        agent["id"],
        scopes=[{"action": "payments.*", "resource": "*"}],
    )["token"]
    created = client.post(
        "/v1/policies",
        headers=admin_headers,
        json={
            "action_pattern": "payments.*",
            "resource_pattern": "*",
            "effect": "allow",
            "requires_approval": True,
        },
    )
    assert created.status_code == 201, created.text
    request = AuthorizationRequest(
        action="payments.charge", resource=resource, context={"amount_cents": 100}
    )
    decision = app.state.service.authorize(token, request)
    assert decision["decision"] == "approval_required", decision
    return token, request, decision["action_request_id"]


def _snapshot(database) -> dict[str, list[str]]:
    """Every row of every user table, in a form that compares by value."""

    with database.connect() as connection:
        tables = [
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        ]
        return {
            table: sorted(
                json.dumps(dict(row), sort_keys=True, default=str)
                for row in connection.execute(f"SELECT * FROM {table}").fetchall()
            )
            for table in tables
        }


def _explode_on_audit(*_args: Any, **_kwargs: Any):
    raise OSError("induced audit write failure")


def _reject_audit_inserts(database, event_type: str) -> None:
    """Make SQLite itself refuse the audit INSERT, from inside the open transaction.

    A trigger body is stored SQL, so the event type cannot be bound as a parameter; the
    values interpolated here are the module's own constants, never test input.
    """

    with database.connect() as connection:
        connection.execute(
            "CREATE TRIGGER reject_audit_event BEFORE INSERT ON audit_events "
            f"WHEN NEW.event_type = '{event_type}' "
            "BEGIN SELECT RAISE(ABORT, 'induced audit insert failure'); END"
        )


# ------------------------------------------------------------------------- scenarios -------

Scenario = Callable[[Any, Any, dict[str, str]], Callable[[], Any]]
SCENARIOS: dict[str, tuple[str, Scenario]] = {}


def scenario(name: str, event_type: str):
    def register(builder: Scenario) -> Scenario:
        SCENARIOS[name] = (event_type, builder)
        return builder

    return register


def _claimed_worker(client, app, admin_headers, label, resources):
    worker = _agent(client, admin_headers, f"{label}-worker", "worker")
    token = _mandate(client, admin_headers, worker["id"])["token"]
    task = _task(client, admin_headers, resources, title=f"{label} target")
    claimed = app.state.coordination.claim_task(task["id"], token, 300)
    return worker, token, task, claimed


def _submission_request(claimed):
    return SubmissionCreate(
        task_version=claimed["task"]["version"],
        claim_fencing_token=claimed["task"]["claim_fencing_token"],
        resource_fencing_tokens=_resource_tokens(claimed),
        base_revision="main@abc123",
        artifact_uri="patch://atomic-audit",
        artifact_hash="a" * 64,
        summary="Implemented the acceptance criteria and added tests.",
        evidence=["pytest: passed"],
    )


@scenario("coordination.create_task", "task.created")
def _create_task(client, app, admin_headers):
    request = TaskCreate(
        title="atomic",
        description="Bounded change.",
        acceptance_criteria=["State and audit commit together"],
        resources=["src/atomic.py"],
    )
    return lambda: app.state.coordination.create_task(request)


@scenario("coordination.claim_task", "task.claimed")
def _claim_task(client, app, admin_headers):
    worker = _agent(client, admin_headers, "claim-worker", "worker")
    token = _mandate(client, admin_headers, worker["id"])["token"]
    task = _task(client, admin_headers, ["src/claim.py"])
    return lambda: app.state.coordination.claim_task(task["id"], token, 300)


@scenario("coordination.heartbeat", "task.heartbeat")
def _heartbeat(client, app, admin_headers):
    _worker, token, task, claimed = _claimed_worker(
        client, app, admin_headers, "heartbeat", ["src/heartbeat.py"]
    )
    request = HeartbeatRequest(
        claim_fencing_token=claimed["task"]["claim_fencing_token"],
        resource_fencing_tokens=_resource_tokens(claimed),
        ttl_seconds=300,
        checkpoint={"step": "midway"},
    )
    return lambda: app.state.coordination.heartbeat(task["id"], token, request)


@scenario("coordination.submit", "submission.created")
def _submit(client, app, admin_headers):
    _worker, token, task, claimed = _claimed_worker(
        client, app, admin_headers, "submit", ["src/submit.py"]
    )
    request = _submission_request(claimed)
    return lambda: app.state.coordination.submit(task["id"], token, request)


@scenario("coordination.review", "review.completed")
def _review(client, app, admin_headers):
    _worker, token, task, claimed = _claimed_worker(
        client, app, admin_headers, "review", ["src/review.py"]
    )
    submission = app.state.coordination.submit(task["id"], token, _submission_request(claimed))
    reviewer = _agent(client, admin_headers, "review-qc", "qc")
    qc_token = _mandate(client, admin_headers, reviewer["id"])["token"]
    request = QCReviewCreate(verdict="pass", summary="Reproduced the evidence; approved.")
    return lambda: app.state.coordination.review(submission["id"], qc_token, request)


@scenario("coordination.complete_task", "task.completed")
def _complete_task(client, app, admin_headers):
    _worker, token, task, claimed = _claimed_worker(
        client, app, admin_headers, "complete", ["src/complete.py"]
    )
    submission = app.state.coordination.submit(task["id"], token, _submission_request(claimed))
    reviewer = _agent(client, admin_headers, "complete-qc", "qc")
    qc_token = _mandate(client, admin_headers, reviewer["id"])["token"]
    app.state.coordination.review(
        submission["id"],
        qc_token,
        QCReviewCreate(verdict="pass", summary="Reproduced the evidence; approved."),
    )
    return lambda: app.state.coordination.complete_task(task["id"], "merged to main")


@scenario("coordination.reopen_task", "task.reopened")
def _reopen_task(client, app, admin_headers):
    """Control: #1831 already made this one atomic."""

    _worker, _token, task, _claimed = _claimed_worker(
        client, app, admin_headers, "reopen", ["src/reopen.py"]
    )
    with app.state.database.connect() as connection:
        connection.execute("UPDATE tasks SET status = 'blocked' WHERE id = ?", (task["id"],))
    return lambda: app.state.coordination.reopen_task(task["id"], "operator-approved redo")


@scenario("coordination.reap_expired", "coordination.reaped")
def _reap_expired(client, app, admin_headers):
    _worker, _token, task, _claimed = _claimed_worker(
        client, app, admin_headers, "reap", ["src/reap.py"]
    )
    with app.state.database.connect() as connection:
        connection.execute("UPDATE tasks SET claim_expires_at = 1 WHERE id = ?", (task["id"],))
    return lambda: app.state.coordination.reap_expired()


@scenario("service.create_agent", "agent.created")
def _create_agent(client, app, admin_headers):
    request = AgentCreate(name="atomic-agent", owner="operations@example.com")
    return lambda: app.state.service.create_agent(request)


@scenario("service.create_policy", "policy.created")
def _create_policy(client, app, admin_headers):
    request = PolicyCreate(action_pattern="payments.*", resource_pattern="*", effect="allow")
    return lambda: app.state.service.create_policy(request)


@scenario("service.issue_mandate", "mandate.issued")
def _issue_mandate(client, app, admin_headers):
    agent = _agent(client, admin_headers, "mandate-agent", "worker")
    request = MandateCreate(
        agent_id=agent["id"],
        subject="atomic",
        scopes=[Scope(action="payments.charge", resource="*")],
        ttl_seconds=3600,
    )
    return lambda: app.state.service.issue_mandate(request)


@scenario("service.set_agent_state", "agent.disabled")
def _set_agent_state(client, app, admin_headers):
    agent = _agent(client, admin_headers, "kill-switch-agent", "worker")
    return lambda: app.state.service.set_agent_state(
        agent["id"], disabled=True, reason="operator kill switch"
    )


@scenario("service.revoke_mandate", "mandate.revoked")
def _revoke_mandate(client, app, admin_headers):
    agent = _agent(client, admin_headers, "revoke-agent", "worker")
    issued = _mandate(client, admin_headers, agent["id"])
    return lambda: app.state.service.revoke_mandate(issued["id"], "credential rotation")


@scenario("service.resolve_approval", "approval.approved")
def _resolve_approval(client, app, admin_headers):
    _token, _request, action_id = _approval_setup(client, app, admin_headers)
    return lambda: app.state.service.resolve_approval(
        action_id, ApprovalResolve(approved=True, reason="operator approved")
    )


@scenario("service.authorize_creates_action_request", "authorization.decided")
def _authorize_creates_action_request(client, app, admin_headers):
    token, _request, _action_id = _approval_setup(client, app, admin_headers, resource="invoice:1")
    second = AuthorizationRequest(
        action="payments.charge", resource="invoice:2", context={"amount_cents": 100}
    )
    return lambda: app.state.service.authorize(token, second)


@scenario("service.authorize_consumes_approval", "authorization.decided")
def _authorize_consumes_approval(client, app, admin_headers):
    token, request, action_id = _approval_setup(client, app, admin_headers)
    app.state.service.resolve_approval(
        action_id, ApprovalResolve(approved=True, reason="operator approved")
    )
    consuming = AuthorizationRequest(
        action=request.action,
        resource=request.resource,
        context=request.context,
        approval_id=action_id,
    )
    return lambda: app.state.service.authorize(token, consuming)


@scenario("side_effects.execute", "side_effect.applied")
def _side_effect(client, app, admin_headers):
    worker = _agent(client, admin_headers, "side-effect-worker", "worker")
    token = _mandate(
        client,
        admin_headers,
        worker["id"],
        scopes=[
            {"action": "coordination.*", "resource": "task:*"},
            {"action": "side_effect.*", "resource": "*"},
        ],
    )["token"]
    task = _task(client, admin_headers, [DB_RESOURCE], title="side effect target")
    claimed = app.state.coordination.claim_task(task["id"], token, 300)
    gateway = FencedGateway(
        database=app.state.database,
        verifier=CoordinationClaimVerifier(app.state.coordination),
        adapters={"db.migrate": postgres_schema_adapter(lambda _call: {"migrated": True})},
    )
    request = SideEffectRequest(
        task_id=task["id"],
        agent_id=worker["id"],
        role="worker",
        claim_fencing_token=claimed["task"]["claim_fencing_token"],
        resource_fencing_tokens=_resource_tokens(claimed),
        target_resource=DB_RESOURCE,
        operation="db.migrate",
        idempotency_key="idem-atomic-audit",
        payload={"database": "orders", "schema": "public", "statement": "ALTER TABLE ..."},
    )
    return lambda: gateway.execute(request)


# ----------------------------------------------------------------------------- tests -------


@pytest.mark.parametrize("failure", ["method", "insert"])
@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_mutation_never_outlives_its_audit_event(
    client, app, admin_headers, monkeypatch, name, failure
):
    event_type, build = SCENARIOS[name]
    operation = build(client, app, admin_headers)
    database = app.state.database

    if failure == "method":
        monkeypatch.setattr(database, "append_audit", _explode_on_audit)
        expected: type[Exception] = OSError
    else:
        _reject_audit_inserts(database, event_type)
        expected = sqlite3.IntegrityError

    before = _snapshot(database)
    with pytest.raises(expected, match="induced audit"):
        operation()
    assert _snapshot(database) == before, f"{name} committed state without its audit event"


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_scenario_reaches_its_audit_event(client, app, admin_headers, name):
    """Without this, a scenario that never reached the audit call would look atomic."""

    event_type, build = SCENARIOS[name]
    operation = build(client, app, admin_headers)
    database = app.state.database

    before = len(database.audit_events(10_000))
    operation()
    events = database.audit_events(10_000)

    assert len(events) == before + 1, f"{name} appended {len(events) - before} audit events"
    assert events[0]["event_type"] == event_type
    assert database.verify_audit_chain() == (True, len(events), None)


def test_concurrent_claims_keep_one_winner_and_one_valid_chain(client, app, admin_headers):
    """The audit INSERT now runs inside the claim's BEGIN IMMEDIATE, so it holds the write
    lock for longer. If that had weakened serialisation the symptom would be two winners on
    one task, or a hash chain forked by two events built on the same predecessor -- so this
    asserts against both directly rather than against "the claim returned 200".
    """

    task = _task(client, admin_headers, ["src/contended.py"], title="contended")
    workers = [
        _agent(client, admin_headers, f"race-worker-{index}", "worker") for index in range(6)
    ]
    tokens = [_mandate(client, admin_headers, worker["id"])["token"] for worker in workers]
    barrier = Barrier(len(tokens))

    def attempt(token):
        barrier.wait(timeout=30)
        try:
            app.state.coordination.claim_task(task["id"], token, 300)
        except ControlPlaneError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=len(tokens)) as pool:
        outcomes = list(pool.map(attempt, tokens))

    assert outcomes.count(True) == 1, f"{outcomes.count(True)} winners claimed one task"
    events = app.state.database.audit_events(10_000)
    claimed = [event for event in events if event["event_type"] == "task.claimed"]
    assert len(claimed) == 1, "a losing claim still wrote an audit event"
    assert app.state.database.verify_audit_chain() == (True, len(events), None)
