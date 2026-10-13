from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from threading import Barrier

import pytest
from fastapi.testclient import TestClient

from agent_control_plane import coordination as coordination_module
from agent_control_plane.app import create_app
from agent_control_plane.coordination_schemas import (
    DispatchAttemptReceiptCreate,
    DispatchAttemptReservationCreate,
    ProviderUsageReport,
)
from agent_control_plane.database import Database
from agent_control_plane.provider_usage import parse_openai_responses_usage
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


def _unsupported_provider_usage():
    return {
        "status": "unsupported",
        "unit": None,
        "source": None,
        "scope": "provider calls and provider-internal fan-out",
        "observed_at": None,
        "freshness": "unknown",
        "enforcement_point": None,
        "reason": "no authenticated provider meter or request gate are wired to this supervisor",
    }


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
        ("max_unreceipted_dispatch_attempts", -1),
        ("max_unreceipted_dispatch_attempts", True),
        ("max_unreceipted_dispatch_attempts", "2"),
        ("max_descendant_unreceipted_dispatch_attempts", -1),
        ("max_descendant_unreceipted_dispatch_attempts", True),
        ("max_descendant_unreceipted_dispatch_attempts", "2"),
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


def reserve_dispatch_attempt(client, task_id, token, claim, idempotency_key):
    return client.post(
        f"/v1/tasks/{task_id}/dispatch-attempts",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "claim_fencing_token": claim["task"]["claim_fencing_token"],
            "resource_fencing_tokens": resource_tokens(claim),
            "idempotency_key": idempotency_key,
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


def test_dispatch_attempt_reservations_are_idempotent_bounded_and_receipts_are_untrusted(
    client, app, admin_headers
):
    worker = create_agent(client, admin_headers, "dispatch-budget-worker", "worker")
    token = issue_coordination_mandate(client, admin_headers, worker["id"])
    task = create_task(
        client,
        admin_headers,
        title="Two cooperative dispatch slots",
        resources=["repo:file:dispatch-budget.py"],
        max_dispatch_attempts=2,
    )
    claim = claim_task(client, task["id"], token).json()

    malformed_fence = client.post(
        f"/v1/tasks/{task['id']}/dispatch-attempts",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "claim_fencing_token": claim["task"]["claim_fencing_token"],
            "resource_fencing_tokens": {resource: True for resource in resource_tokens(claim)},
            "idempotency_key": "boolean-is-not-a-fence",
        },
    )
    assert malformed_fence.status_code == 422

    first = reserve_dispatch_attempt(client, task["id"], token, claim, "call-1")
    assert first.status_code == 201, first.text
    assert first.json()["created"] is True
    reservation = first.json()["reservation"]
    assert reservation["status"] == "reserved"
    assert reservation["claim_fencing_token"] == claim["task"]["claim_fencing_token"]
    assert reservation["resource_fencing_tokens"] == resource_tokens(claim)

    replay = reserve_dispatch_attempt(client, task["id"], token, claim, "call-1")
    assert replay.status_code == 201, replay.text
    assert replay.json()["created"] is False
    assert replay.json()["reservation"]["id"] == reservation["id"]
    assert (
        client.get(f"/v1/tasks/{task['id']}", headers=admin_headers).json()[
            "dispatch_attempt_budget"
        ]["consumed"]
        == 1
    )

    receipt_url = f"/v1/tasks/{task['id']}/dispatch-attempts/{reservation['id']}/receipt"
    receipt_body = {
        "claim_fencing_token": claim["task"]["claim_fencing_token"],
        "http_status_code": 429,
        "retry_after_seconds": 30,
    }
    receipt = client.post(
        receipt_url,
        headers={"Authorization": f"Bearer {token}"},
        json=receipt_body,
    )
    assert receipt.status_code == 200, receipt.text
    assert receipt.json()["created"] is True
    assert receipt.json()["receipt"]["source"] == "client_reported"
    assert receipt.json()["receipt"]["http_status_code"] == 429
    assert receipt.json()["receipt"]["retry_after_seconds"] == 30
    expected_provider_usage = _unsupported_provider_usage()
    assert receipt.json()["receipt"]["provider_usage"] == expected_provider_usage
    receipt_replay = client.post(
        receipt_url,
        headers={"Authorization": f"Bearer {token}"},
        json=receipt_body,
    )
    assert receipt_replay.status_code == 200, receipt_replay.text
    assert receipt_replay.json()["created"] is False
    assert receipt_replay.json()["receipt"]["provider_usage"] == expected_provider_usage
    conflicting_receipt = client.post(
        receipt_url,
        headers={"Authorization": f"Bearer {token}"},
        json={**receipt_body, "http_status_code": 503},
    )
    assert conflicting_receipt.status_code == 409
    assert conflicting_receipt.json()["error"] == "dispatch_attempt_receipt_conflict"

    second = reserve_dispatch_attempt(client, task["id"], token, claim, "call-2")
    assert second.status_code == 201, second.text
    exhausted = reserve_dispatch_attempt(client, task["id"], token, claim, "call-3")
    assert exhausted.status_code == 409
    assert exhausted.json()["error"] == "task_dispatch_budget_exhausted"
    task_view = client.get(f"/v1/tasks/{task['id']}", headers=admin_headers).json()
    assert task_view["dispatch_attempt_budget"]["consumed"] == 2
    assert task_view["dispatch_attempt_budget"]["remaining"] == 0
    assert task_view["dispatch_attempt_budget"]["reserved"] == 0
    assert task_view["dispatch_attempt_budget"]["released"] == 0
    assert task_view["dispatch_attempt_budget"]["provider_usage"] == expected_provider_usage
    assert (
        task_view["descendant_dispatch_attempt_budget"]["provider_usage"] == expected_provider_usage
    )
    assert (
        app.state.database.one(
            "SELECT COUNT(*) AS count FROM audit_events "
            "WHERE event_type = 'dispatch_attempt.receipt_reported'"
        )["count"]
        == 1
    )


def test_interruption_report_is_bounded_fenced_append_only_and_survives_restart(
    client, app, admin_headers
):
    worker = create_agent(client, admin_headers, "interruption-report-worker", "worker")
    token = issue_coordination_mandate(client, admin_headers, worker["id"])
    task = create_task(
        client,
        admin_headers,
        title="Preserve interrupted partial work",
        resources=["repo:file:café.py"],
    )
    claim = claim_task(client, task["id"], token).json()
    reservation = reserve_dispatch_attempt(client, task["id"], token, claim, "interrupted-call")
    assert reservation.status_code == 201, reservation.text
    dispatch_id = reservation.json()["reservation"]["id"]
    request = {
        "claim_fencing_token": claim["task"]["claim_fencing_token"],
        "resource_fencing_tokens": resource_tokens(claim),
        "reason": "provider_quota_exhausted",
        "summary": "Stopped before submission; the latest safe checkpoint is recorded below.",
        "checkpoint": {
            "phase": "tests",
            "last_safe_revision": "a" * 40,
            "debug_note": "retry_count=3",
        },
        "dispatch_attempt_ids": [dispatch_id],
    }
    endpoint = f"/v1/tasks/{task['id']}/interruption-reports"
    headers = {"Authorization": f"Bearer {token}"}

    secret_shaped_payloads = [
        {"checkpoint": {"phase": "tests", "provider_api_key": "placeholder-value"}},
        {"checkpoint": {"apiKey": "placeholder-value"}},
        {"checkpoint": {"APIKey": "placeholder-value"}},
        {"checkpoint": {"accessToken": "placeholder-value"}},
        {"checkpoint": {"clientSecret": "placeholder-value"}},
        {"checkpoint": {"secretKey": "placeholder-value"}},
        {"checkpoint": {"awsSecretAccessKey": "placeholder-value"}},
        {"checkpoint": {"authToken": "placeholder-value"}},
        {"checkpoint": {"bearerToken": "placeholder-value"}},
        {"checkpoint": {"sessionToken": "placeholder-value"}},
        {"checkpoint": {"idToken": "placeholder-value"}},
        {"checkpoint": {"apiToken": "placeholder-value"}},
        {"checkpoint": {"githubToken": "opaque-value"}},
        {"checkpoint": {"token": "opaque-value"}},
        {"checkpoint": {"awsAccessKeyId": "opaque-value"}},
        {"checkpoint": {"clientKey": "opaque-value"}},
        {"checkpoint": {"consumerKey": "opaque-value"}},
        {"checkpoint": {"consumerSecret": "opaque-value"}},
        {"checkpoint": {"apiSecret": "opaque-value"}},
        {"checkpoint": {"databasePassword": "opaque-value"}},
        {"checkpoint": {"dbPassword": "opaque-value"}},
        {"checkpoint": {"sessionCookie": "opaque-value"}},
        {"checkpoint": {"serviceCredential": "opaque-value"}},
        {"checkpoint": {"accountKey": "opaque-value"}},
        {"checkpoint": {"storageKey": "opaque-value"}},
        {"checkpoint": {"subscriptionKey": "opaque-value"}},
        {"checkpoint": {"masterKey": "opaque-value"}},
        {
            "checkpoint": {
                "connectionString": "DefaultEndpointsProtocol=https;AccountName=sample;"
                "AccountKey=opaque-connection-key-value"
            }
        },
        {
            "checkpoint": {
                "serviceConfig": "Endpoint=https://example.invalid;"
                "SubscriptionKey=opaque-subscription-key;MasterKey=opaque-master-key"
            }
        },
        {
            "checkpoint": {
                "connectionString": "Endpoint=sb://example.invalid/;"
                "SharedAccessSignature=opaque-shared-access-signature"
            }
        },
        {
            "checkpoint": {
                "query": "https://example.invalid/resource?sv=1&sig=opaque-signature-value"
            }
        },
        {"checkpoint": {"environment": "AWS_SECRET_ACCESS_KEY=opaque-aws-secret-access-key"}},
        {"checkpoint": {"tokenResponse": "refresh_token=opaque-refresh-token-value"}},
        {"checkpoint": {"environment": "AWS_SESSION_TOKEN=opaque-aws-session-token"}},
        {"checkpoint": {"environment": "session_token=opaque-session-token-value"}},
        {"checkpoint": {"environment": "API_TOKEN=opaque-api-token-value"}},
        {"checkpoint": {"environment": "GITHUB_TOKEN=opaque-github-token-value"}},
        {"summary": "Provider rejected Authorization: Bearer " + "x" * 32},
        {"checkpoint": {"details": ["sk-proj-" + "x" * 24]}},
        {"checkpoint": {"details": ["password=" + "x" * 20]}},
    ]
    secret_sentinel = "SENTINEL_SECRET_SHOULD_NOT_ECHO_92f84e16"
    secret_shaped_payloads.append({"checkpoint": {"clientSecret": secret_sentinel}})
    for sensitive_fields in secret_shaped_payloads:
        rejected = client.post(
            endpoint,
            headers=headers,
            json={**request, **sensitive_fields, "dispatch_attempt_ids": []},
        )
        assert rejected.status_code == 422, rejected.text
        assert secret_sentinel not in rejected.text

    deeply_nested_checkpoint = {"leaf": "safe"}
    for _ in range(40):
        deeply_nested_checkpoint = {"nested": deeply_nested_checkpoint}
    deeply_nested = client.post(
        endpoint,
        headers=headers,
        json={**request, "checkpoint": deeply_nested_checkpoint},
    )
    assert deeply_nested.status_code == 422, deeply_nested.text
    assert (
        app.state.database.one(
            "SELECT COUNT(*) AS count FROM budget_interruption_reports WHERE task_id = ?",
            (task["id"],),
        )["count"]
        == 0
    )

    too_large = client.post(
        endpoint,
        headers=headers,
        json={**request, "checkpoint": {"payload": "x" * 9000}},
    )
    assert too_large.status_code == 422
    unreceipted = client.post(endpoint, headers=headers, json=request)
    assert unreceipted.status_code == 422
    assert unreceipted.json()["error"] == "interruption_dispatch_receipt_invalid"

    receipt_response = client.post(
        f"/v1/tasks/{task['id']}/dispatch-attempts/{dispatch_id}/receipt",
        headers=headers,
        json={
            "claim_fencing_token": claim["task"]["claim_fencing_token"],
            "http_status_code": 429,
            "retry_after_seconds": 300,
        },
    )
    assert receipt_response.status_code == 200, receipt_response.text
    usage_reservation = reserve_dispatch_attempt(
        client, task["id"], token, claim, "interrupted-usage-call"
    )
    assert usage_reservation.status_code == 201, usage_reservation.text
    usage_dispatch_id = usage_reservation.json()["reservation"]["id"]
    usage_report = ProviderUsageReport(
        status="reported",
        provider="openai",
        adapter="responses",
        source="client_reported",
        scope="single_response",
        unit="tokens",
        observed_at="2026-10-13T13:00:00Z",
        response_id="resp_interruption",
        model="gpt-test",
        response_created_at=1791896400,
        measurements={"input_tokens": 4, "output_tokens": 3, "total_tokens": 7},
        freshness="unknown",
        enforcement="report_only",
        reason=None,
    )
    usage_receipt_response = client.post(
        f"/v1/tasks/{task['id']}/dispatch-attempts/{usage_dispatch_id}/receipt",
        headers=headers,
        json={
            "claim_fencing_token": claim["task"]["claim_fencing_token"],
            "http_status_code": 200,
            "provider_usage_report": usage_report.model_dump(),
        },
    )
    assert usage_receipt_response.status_code == 200, usage_receipt_response.text
    request["dispatch_attempt_ids"].append(usage_dispatch_id)

    stale_fence = client.post(
        endpoint,
        headers=headers,
        json={**request, "claim_fencing_token": claim["task"]["claim_fencing_token"] + 1},
    )
    assert stale_fence.status_code == 409
    assert stale_fence.json()["error"] == "stale_claim_fencing_token"

    report_response = client.post(endpoint, headers=headers, json=request)
    assert report_response.status_code == 201, report_response.text
    result = report_response.json()
    report = result["report"]
    assert result["created"] is True
    assert report["interruption_status"] == "interrupted"
    assert report["status"] == "partial"
    assert report["source"] == "client_reported"
    assert report["promotable"] is False
    assert report["checkpoint_integrity"] == "valid"
    assert report["checkpoint"] == request["checkpoint"]
    assert report["resource_fencing_tokens_integrity"] == "valid"
    assert report["resource_fencing_tokens"] == resource_tokens(claim)
    assert report["dispatch_attempt_ids"] == [dispatch_id, usage_dispatch_id]
    assert report["dispatch_attempts_integrity"] == "valid"
    assert (
        report["dispatch_attempts"][0]["claim_fencing_token"]
        == claim["task"]["claim_fencing_token"]
    )
    assert report["dispatch_attempts"][0]["receipt"]["source"] == "client_reported"
    assert report["dispatch_attempts"][0]["receipt"]["http_status_code"] == 429
    assert report["dispatch_attempts"][0]["receipt"]["provider_usage"]["status"] == "unsupported"
    assert (
        report["dispatch_attempts"][1]["receipt"]["provider_usage_report"]["measurements"][
            "total_tokens"
        ]
        == 7
    )
    assert report["received_at"]

    replay = client.post(endpoint, headers=headers, json=request)
    assert replay.status_code == 201, replay.text
    assert replay.json()["created"] is False
    assert replay.json()["report"]["id"] == report["id"]
    conflict = client.post(
        endpoint,
        headers=headers,
        json={**request, "summary": "A conflicting second immutable report."},
    )
    assert conflict.status_code == 409
    assert conflict.json()["error"] == "interruption_report_conflict"
    with app.state.database.connect() as connection:
        connection.execute("UPDATE tasks SET claim_expires_at = 0 WHERE id = ?", (task["id"],))
    expired_replay = client.post(endpoint, headers=headers, json=request)
    assert expired_replay.status_code == 201, expired_replay.text
    assert expired_replay.json()["created"] is False

    task_view = client.get(f"/v1/tasks/{task['id']}", headers=admin_headers).json()
    assert task_view["status"] == claim["task"]["status"]
    assert task_view["latest_submission"] is None
    assert task_view["latest_interruption_report"]["id"] == report["id"]
    assert task_view["latest_interruption_report"]["promotable"] is False
    cannot_complete = client.post(
        f"/v1/tasks/{task['id']}/complete",
        headers=admin_headers,
        json={"reason": "A partial interruption report is not completed work."},
    )
    assert cannot_complete.status_code == 409
    assert cannot_complete.json()["error"] == "qc_gate_not_passed"

    Database(app.state.database.path).initialize()
    after_restart = client.get(f"/v1/tasks/{task['id']}", headers=admin_headers).json()
    assert after_restart["latest_interruption_report"] == task_view["latest_interruption_report"]
    with pytest.raises(sqlite3.IntegrityError, match="budget_interruption_report_immutable"):
        with app.state.database.connect() as connection:
            connection.execute(
                "UPDATE budget_interruption_reports SET summary = 'changed' WHERE id = ?",
                (report["id"],),
            )
    with pytest.raises(sqlite3.IntegrityError, match="budget_interruption_report_immutable"):
        with app.state.database.connect() as connection:
            connection.execute(
                "DELETE FROM budget_interruption_reports WHERE id = ?", (report["id"],)
            )


def test_non_interruption_validation_errors_keep_default_input_details(client, admin_headers):
    response = client.post("/v1/tasks", headers=admin_headers, json={"title": 123})

    assert response.status_code == 422
    assert any("input" in detail for detail in response.json()["detail"])


def test_interruption_report_rechecks_claim_expiry_before_insert(
    client, app, admin_headers, monkeypatch
):
    worker = create_agent(client, admin_headers, "interruption-expiry-worker", "worker")
    token = issue_coordination_mandate(client, admin_headers, worker["id"])
    task = create_task(
        client,
        admin_headers,
        title="Reject a checkpoint after claim expiry",
        resources=["repo:file:expiring-claim.py"],
    )
    claim = claim_task(client, task["id"], token).json()
    reservation = reserve_dispatch_attempt(
        client, task["id"], token, claim, "claim-expiry-checkpoint"
    )
    assert reservation.status_code == 201, reservation.text
    dispatch_attempt_id = reservation.json()["reservation"]["id"]
    receipt = client.post(
        f"/v1/tasks/{task['id']}/dispatch-attempts/{dispatch_attempt_id}/receipt",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "claim_fencing_token": claim["task"]["claim_fencing_token"],
            "http_status_code": 429,
            "retry_after_seconds": 30,
        },
    )
    assert receipt.status_code == 200, receipt.text
    request = {
        "claim_fencing_token": claim["task"]["claim_fencing_token"],
        "resource_fencing_tokens": resource_tokens(claim),
        "reason": "provider_quota_exhausted",
        "summary": "The claim expires during report validation.",
        "checkpoint": {"phase": "tests"},
        "dispatch_attempt_ids": [dispatch_attempt_id],
    }
    service = app.state.coordination
    original_assert_active_claim = service._assert_active_claim
    calls = 0

    def expire_on_final_check(connection, task_row, agent_id, fence, resource_fences, now):
        nonlocal calls
        calls += 1
        if calls == 2:
            now = task_row["claim_expires_at"]
        return original_assert_active_claim(
            connection, task_row, agent_id, fence, resource_fences, now
        )

    monkeypatch.setattr(service, "_assert_active_claim", expire_on_final_check)
    response = client.post(
        f"/v1/tasks/{task['id']}/interruption-reports",
        headers={"Authorization": f"Bearer {token}"},
        json=request,
    )

    assert calls == 2
    assert response.status_code == 409
    assert response.json()["error"] == "stale_claim_fencing_token"
    assert (
        app.state.database.one(
            "SELECT COUNT(*) AS count FROM budget_interruption_reports WHERE task_id = ?",
            (task["id"],),
        )["count"]
        == 0
    )


def test_interruption_report_rejects_duplicate_dispatch_receipt_ids():
    from agent_control_plane.coordination_schemas import BudgetInterruptionReportCreate

    with pytest.raises(ValueError, match="must be unique"):
        BudgetInterruptionReportCreate.model_validate(
            {
                "claim_fencing_token": 1,
                "resource_fencing_tokens": {},
                "reason": "retry_exhausted",
                "summary": "Retry budget was exhausted.",
                "checkpoint": {},
                "dispatch_attempt_ids": ["receipt-1", "receipt-1"],
            }
        )


def test_legacy_task_has_no_interruption_report(client, admin_headers):
    task = create_task(client, admin_headers, title="Legacy task without interruption")
    task_view = client.get(f"/v1/tasks/{task['id']}", headers=admin_headers).json()
    assert task_view["latest_interruption_report"] is None


def test_provider_usage_report_rejects_timestamp_that_cannot_normalize_to_utc():
    with pytest.raises(ValueError, match="normalize to UTC"):
        ProviderUsageReport.model_validate(
            {
                "status": "reported",
                "provider": "openai",
                "adapter": "responses",
                "source": "client_reported",
                "scope": "single_response",
                "unit": "tokens",
                "observed_at": "0001-01-01T00:00:00+14:00",
                "response_id": "resp_overflow",
                "model": "gpt-test",
                "response_created_at": 0,
                "measurements": {
                    "input_tokens": 1,
                    "output_tokens": 1,
                    "total_tokens": 2,
                },
                "freshness": "unknown",
                "enforcement": "report_only",
                "reason": None,
            }
        )


def test_task_usage_summary_is_report_only_and_exposes_descendant_gaps(
    client, app, admin_headers, monkeypatch
):
    worker = create_agent(client, admin_headers, "usage-summary-worker", "worker")
    token = issue_coordination_mandate(client, admin_headers, worker["id"])
    root = create_task(client, admin_headers, title="Usage summary root")
    child = create_task(
        client,
        admin_headers,
        title="Usage summary child",
        parent_task_id=root["id"],
    )
    root_claim = claim_task(client, root["id"], token).json()
    child_claim = claim_task(client, child["id"], token).json()

    def reserve_and_receipt(task, claim, key, *, report_marker="omit"):
        reservation_response = reserve_dispatch_attempt(client, task["id"], token, claim, key)
        assert reservation_response.status_code == 201, reservation_response.text
        attempt_id = reservation_response.json()["reservation"]["id"]
        payload = {
            "claim_fencing_token": claim["task"]["claim_fencing_token"],
            "http_status_code": 200,
            "retry_after_seconds": None,
        }
        if report_marker != "omit":
            payload["provider_usage_report"] = report_marker
        response = client.post(
            f"/v1/tasks/{task['id']}/dispatch-attempts/{attempt_id}/receipt",
            headers={"Authorization": f"Bearer {token}"},
            json=payload,
        )
        assert response.status_code == 200, response.text
        return response.json()["receipt"]

    root_report = parse_openai_responses_usage(
        {
            "object": "response",
            "id": "resp_root_usage",
            "model": "gpt-root",
            "status": "completed",
            "usage": {"input_tokens": 4, "output_tokens": 1, "total_tokens": 5},
        },
        observed_at=datetime.fromisoformat("2026-10-13T10:00:00+02:00"),
    ).as_dict()
    child_report = parse_openai_responses_usage(
        {
            "object": "response",
            "id": "resp_child_usage",
            "model": "gpt-child",
            "status": "completed",
            "usage": {"input_tokens": 7, "output_tokens": 3, "total_tokens": 10},
        }
    ).as_dict()
    child_other_model_report = parse_openai_responses_usage(
        {
            "object": "response",
            "id": "resp_child_other_model",
            "model": "gpt-child-alt",
            "status": "completed",
            "usage": {"input_tokens": 2, "output_tokens": 1, "total_tokens": 3},
        }
    ).as_dict()
    root_second_report = parse_openai_responses_usage(
        {
            "object": "response",
            "id": "resp_root_usage_2",
            "model": "gpt-root",
            "status": "completed",
            "usage": {"input_tokens": 10, "output_tokens": 2, "total_tokens": 12},
        },
        observed_at=datetime.fromisoformat("2026-10-13T07:30:00+00:00"),
    ).as_dict()
    missing_report = parse_openai_responses_usage({"error": {"type": "rate_limit_error"}}).as_dict()
    invalid_report = parse_openai_responses_usage(
        {
            "object": "response",
            "id": "resp_invalid_child",
            "model": "gpt-child",
            "status": "completed",
            "usage": {"input_tokens": True, "output_tokens": 3, "total_tokens": 10},
        }
    ).as_dict()

    reserve_and_receipt(root, root_claim, "usage-root", report_marker=root_report)
    reserve_and_receipt(root, root_claim, "usage-root-2", report_marker=root_second_report)
    child_report_receipt = reserve_and_receipt(
        child, child_claim, "usage-child-reported", report_marker=child_report
    )
    child_other_model_receipt = reserve_and_receipt(
        child, child_claim, "usage-child-other-model", report_marker=child_other_model_report
    )
    reserve_and_receipt(child, child_claim, "usage-child-missing", report_marker=missing_report)
    reserve_and_receipt(child, child_claim, "usage-child-invalid", report_marker=invalid_report)
    reserve_and_receipt(child, child_claim, "usage-child-no-report")
    unreceipted = reserve_dispatch_attempt(
        client, child["id"], token, child_claim, "usage-child-unreceipted"
    )
    assert unreceipted.status_code == 201, unreceipted.text

    child_view = client.get(f"/v1/tasks/{child['id']}", headers=admin_headers).json()
    child_usage = child_view["dispatch_attempt_budget"]["reported_provider_usage"]
    assert child_usage["scope"] == "task"
    assert child_usage["status"] == "partial"
    assert child_usage["source"] == "client_reported"
    assert child_usage["capture_scope"] == "ACP dispatch receipts only"
    assert child_usage["unit"] == "tokens"
    assert child_usage["freshness"] == "unknown"
    assert child_usage["enforcement"] == "report_only"
    assert child_usage["reservation_count"] == 6
    assert child_usage["sampled_reservation_count"] == 6
    assert child_usage["reported_response_count"] == 2
    assert child_usage["missing_report_count"] == 1
    assert child_usage["invalid_report_count"] == 1
    assert child_usage["receipt_without_report_count"] == 1
    assert child_usage["reservation_without_receipt_count"] == 1
    assert child_usage["latest_receipt_received_at_in_sample"] is not None
    assert child_usage["groups"] == [
        {
            "provider": "openai",
            "adapter": "responses",
            "model": "gpt-child",
            "response_count": 1,
            "latest_client_observed_at": child_report["observed_at"],
            "measurements": {
                "input_tokens": 7,
                "output_tokens": 3,
                "total_tokens": 10,
            },
            "measurement_response_counts": {
                "input_tokens": 1,
                "output_tokens": 1,
                "total_tokens": 1,
            },
        },
        {
            "provider": "openai",
            "adapter": "responses",
            "model": "gpt-child-alt",
            "response_count": 1,
            "latest_client_observed_at": child_other_model_report["observed_at"],
            "measurements": {
                "input_tokens": 2,
                "output_tokens": 1,
                "total_tokens": 3,
            },
            "measurement_response_counts": {
                "input_tokens": 1,
                "output_tokens": 1,
                "total_tokens": 1,
            },
        },
    ]
    assert child_view["dispatch_attempt_budget"]["provider_usage"] == _unsupported_provider_usage()
    assert child_view["dispatch_attempt_budget"]["reported_provider_usage"]["status"] != "observed"
    assert (
        child_view["descendant_dispatch_attempt_budget"]["reported_provider_usage"]["status"]
        == "none"
    )

    root_view = client.get(f"/v1/tasks/{root['id']}", headers=admin_headers).json()
    root_task_usage = root_view["dispatch_attempt_budget"]["reported_provider_usage"]
    root_descendant_usage = root_view["descendant_dispatch_attempt_budget"][
        "reported_provider_usage"
    ]
    assert root_task_usage["status"] == "observed"
    assert root_task_usage["groups"][0]["model"] == "gpt-root"
    assert root_task_usage["groups"][0]["response_count"] == 2
    assert root_task_usage["groups"][0]["latest_client_observed_at"] == ("2026-10-13T08:00:00Z")
    assert root_task_usage["groups"][0]["measurements"] == {
        "input_tokens": 14,
        "output_tokens": 3,
        "total_tokens": 17,
    }
    assert root_task_usage["groups"][0]["measurement_response_counts"] == {
        "input_tokens": 2,
        "output_tokens": 2,
        "total_tokens": 2,
    }
    assert root_descendant_usage["status"] == "partial"
    assert root_descendant_usage["reported_response_count"] == 2
    assert root_descendant_usage["invalid_report_count"] == 1
    assert [group["model"] for group in root_descendant_usage["groups"]] == [
        "gpt-child",
        "gpt-child-alt",
    ]

    listed = client.get("/v1/tasks", headers=admin_headers)
    assert listed.status_code == 200, listed.text
    listed_by_id = {task["id"]: task for task in listed.json()}
    assert listed_by_id[root["id"]]["dispatch_attempt_budget"]["reported_provider_usage"] is None
    assert (
        listed_by_id[root["id"]]["descendant_dispatch_attempt_budget"]["reported_provider_usage"]
        is None
    )
    assert listed_by_id[child["id"]]["dispatch_attempt_budget"]["reported_provider_usage"] is None

    monkeypatch.setattr(coordination_module, "_PROVIDER_USAGE_SUMMARY_MAX_RESERVATIONS", 2)
    truncated = client.get(f"/v1/tasks/{child['id']}", headers=admin_headers).json()
    truncated_usage = truncated["dispatch_attempt_budget"]["reported_provider_usage"]
    assert truncated_usage["reservation_count"] == 6
    assert truncated_usage["sampled_reservation_count"] == 2
    assert truncated_usage["truncated"] is True
    assert truncated_usage["status"] == "partial"
    assert "summary_truncated" in truncated_usage["reasons"]

    monkeypatch.setattr(coordination_module, "_PROVIDER_USAGE_SUMMARY_MAX_RESERVATIONS", 1000)
    with sqlite3.connect(app.state.database.path) as connection:
        connection.execute("DROP TRIGGER dispatch_attempt_receipt_immutable")
        connection.execute(
            "UPDATE dispatch_attempt_receipts SET provider_usage_json = ? "
            "WHERE dispatch_attempt_id = ?",
            (
                '{"unexpected":"secret-shaped test value"}',
                child_report_receipt["dispatch_attempt_id"],
            ),
        )
        overflow_report = {
            **child_other_model_report,
            "observed_at": "0001-01-01T00:00:00+14:00",
        }
        connection.execute(
            "UPDATE dispatch_attempt_receipts SET provider_usage_json = ? "
            "WHERE dispatch_attempt_id = ?",
            (
                json.dumps(overflow_report),
                child_other_model_receipt["dispatch_attempt_id"],
            ),
        )
    malformed_stored = client.get(f"/v1/tasks/{child['id']}", headers=admin_headers).json()
    malformed_usage = malformed_stored["dispatch_attempt_budget"]["reported_provider_usage"]
    assert malformed_usage["status"] == "partial"
    assert malformed_usage["invalid_report_count"] == 3
    assert "stored_usage_report_invalid" in malformed_usage["reasons"]
    assert "secret-shaped" not in str(malformed_usage)
    assert malformed_usage["groups"] == []


def test_dispatch_attempt_usage_and_receipt_survive_service_database_restart(
    client, app, admin_headers
):
    worker = create_agent(client, admin_headers, "restart-dispatch-worker", "worker")
    token = issue_coordination_mandate(client, admin_headers, worker["id"])
    task = create_task(
        client,
        admin_headers,
        title="Dispatch budget restored after restart",
        resources=["repo:file:dispatch-restart.py"],
        max_dispatch_attempts=2,
    )
    claim = claim_task(client, task["id"], token).json()

    first = reserve_dispatch_attempt(client, task["id"], token, claim, "restart-call-1")
    assert first.status_code == 201, first.text
    assert first.json()["created"] is True
    reservation_id = first.json()["reservation"]["id"]

    receipt_url = f"/v1/tasks/{task['id']}/dispatch-attempts/{reservation_id}/receipt"
    provider_usage_report = parse_openai_responses_usage(
        {
            "object": "response",
            "id": "resp_restart_1",
            "model": "gpt-5.6",
            "status": "completed",
            "created_at": 1_791_000_000,
            "usage": {"input_tokens": 20, "output_tokens": 5, "total_tokens": 25},
        },
        observed_at=datetime.fromisoformat("2026-10-13T07:00:00+00:00"),
    ).as_dict()
    receipt = client.post(
        receipt_url,
        headers={"Authorization": f"Bearer {token}"},
        json={
            "claim_fencing_token": claim["task"]["claim_fencing_token"],
            "http_status_code": 200,
            "retry_after_seconds": None,
            "provider_usage_report": provider_usage_report,
        },
    )
    assert receipt.status_code == 200, receipt.text
    assert receipt.json()["receipt"]["source"] == "client_reported"
    assert receipt.json()["receipt"]["provider_usage_report"] == provider_usage_report
    receipt_replay = client.post(
        receipt_url,
        headers={"Authorization": f"Bearer {token}"},
        json={
            "claim_fencing_token": claim["task"]["claim_fencing_token"],
            "http_status_code": 200,
            "retry_after_seconds": None,
            "provider_usage_report": provider_usage_report,
        },
    )
    assert receipt_replay.status_code == 200, receipt_replay.text
    assert receipt_replay.json()["created"] is False
    assert receipt_replay.json()["receipt"]["provider_usage_report"] == provider_usage_report
    conflicting_usage = {**provider_usage_report, "response_id": "resp_different_1"}
    usage_conflict = client.post(
        receipt_url,
        headers={"Authorization": f"Bearer {token}"},
        json={
            "claim_fencing_token": claim["task"]["claim_fencing_token"],
            "http_status_code": 200,
            "retry_after_seconds": None,
            "provider_usage_report": conflicting_usage,
        },
    )
    assert usage_conflict.status_code == 409
    assert usage_conflict.json()["error"] == "dispatch_attempt_receipt_conflict"

    restarted_app = create_app(app.state.settings)
    with TestClient(restarted_app) as restarted_client:
        restored = restarted_client.get(f"/v1/tasks/{task['id']}", headers=admin_headers)
        assert restored.status_code == 200, restored.text
        assert restored.json()["dispatch_attempt_budget"]["consumed"] == 1
        assert restored.json()["dispatch_attempt_budget"]["remaining"] == 1
        restored_usage = restored.json()["dispatch_attempt_budget"]["reported_provider_usage"]
        assert restored_usage["status"] == "observed"
        assert restored_usage["reported_response_count"] == 1
        assert restored_usage["groups"][0]["measurements"]["total_tokens"] == 25
        assert (
            restored_usage["groups"][0]["latest_client_observed_at"]
            == (provider_usage_report["observed_at"])
        )

        replay = reserve_dispatch_attempt(
            restarted_client, task["id"], token, claim, "restart-call-1"
        )
        assert replay.status_code == 201, replay.text
        assert replay.json()["created"] is False
        restored_reservation = replay.json()["reservation"]
        assert restored_reservation["id"] == reservation_id
        assert restored_reservation["status"] == "reported"
        assert restored_reservation["receipt"]["http_status_code"] == 200
        assert restored_reservation["receipt"]["retry_after_seconds"] is None
        assert restored_reservation["receipt"]["provider_usage"] == _unsupported_provider_usage()
        assert restored_reservation["receipt"]["provider_usage_report"] == provider_usage_report

        second = reserve_dispatch_attempt(
            restarted_client, task["id"], token, claim, "restart-call-2"
        )
        assert second.status_code == 201, second.text
        exhausted = reserve_dispatch_attempt(
            restarted_client, task["id"], token, claim, "restart-call-3"
        )
        assert exhausted.status_code == 409
        assert exhausted.json()["error"] == "task_dispatch_budget_exhausted"

        final_view = restarted_client.get(f"/v1/tasks/{task['id']}", headers=admin_headers)
        assert final_view.status_code == 200, final_view.text
        final_usage = final_view.json()["dispatch_attempt_budget"]["reported_provider_usage"]
        assert final_usage["status"] == "partial"
        assert final_usage["reported_response_count"] == 1
        assert final_usage["reservation_without_receipt_count"] == 1
        assert final_usage["groups"][0]["measurements"]["total_tokens"] == 25
        assert final_view.json()["dispatch_attempt_budget"]["consumed"] == 2
        assert final_view.json()["dispatch_attempt_budget"]["remaining"] == 0


def test_zero_dispatch_budget_and_expired_claim_fail_closed(client, app, admin_headers):
    worker = create_agent(client, admin_headers, "dispatch-zero-worker", "worker")
    token = issue_coordination_mandate(client, admin_headers, worker["id"])
    zero_task = create_task(
        client,
        admin_headers,
        title="No cooperative dispatch slots",
        resources=["repo:file:dispatch-zero.py"],
        max_dispatch_attempts=0,
    )
    zero_claim = claim_task(client, zero_task["id"], token).json()
    denied = reserve_dispatch_attempt(client, zero_task["id"], token, zero_claim, "never-send")
    assert denied.status_code == 409
    assert denied.json()["error"] == "task_dispatch_budget_exhausted"
    assert (
        app.state.database.one(
            "SELECT COUNT(*) AS count FROM dispatch_attempt_reservations WHERE task_id = ?",
            (zero_task["id"],),
        )["count"]
        == 0
    )

    task = create_task(
        client,
        admin_headers,
        title="Expired claim cannot reserve",
        resources=["repo:file:dispatch-expired.py"],
        max_dispatch_attempts=1,
    )
    claim = claim_task(client, task["id"], token).json()
    app.state.database.execute("UPDATE tasks SET claim_expires_at = 1 WHERE id = ?", (task["id"],))
    stale = reserve_dispatch_attempt(client, task["id"], token, claim, "expired-call")
    assert stale.status_code == 409
    assert stale.json()["error"] == "stale_claim_fencing_token"
    assert (
        app.state.database.one(
            "SELECT COUNT(*) AS count FROM dispatch_attempt_reservations WHERE task_id = ?",
            (task["id"],),
        )["count"]
        == 0
    )


def test_sibling_dispatch_attempts_share_atomic_ancestor_budget(client, app, admin_headers):
    workers = [
        create_agent(client, admin_headers, f"dispatch-race-worker-{i}", "worker") for i in range(2)
    ]
    tokens = [issue_coordination_mandate(client, admin_headers, worker["id"]) for worker in workers]
    parent = create_task(
        client,
        admin_headers,
        title="One descendant dispatch slot",
        max_descendant_dispatch_attempts=1,
    )
    children = [
        create_task(
            client,
            admin_headers,
            title=f"Dispatch child {i}",
            parent_task_id=parent["id"],
            resources=[f"repo:file:dispatch-child-{i}.py"],
        )
        for i in range(2)
    ]
    claims = [
        claim_task(client, child["id"], token).json()
        for child, token in zip(children, tokens, strict=True)
    ]
    start = Barrier(2)

    def reserve(args):
        task_id, token, claim, key = args
        start.wait(timeout=5)
        try:
            return "created", app.state.coordination.reserve_dispatch_attempt(
                task_id,
                token,
                DispatchAttemptReservationCreate(
                    claim_fencing_token=claim["task"]["claim_fencing_token"],
                    resource_fencing_tokens=resource_tokens(claim),
                    idempotency_key=key,
                ),
            )
        except ControlPlaneError as error:
            return "rejected", getattr(error, "code", type(error).__name__)

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(
            executor.map(
                reserve,
                zip(
                    [child["id"] for child in children],
                    tokens,
                    claims,
                    ["race-a", "race-b"],
                    strict=True,
                ),
            )
        )

    assert sum(outcome[0] == "created" for outcome in outcomes) == 1
    assert (
        sum(outcome == ("rejected", "descendant_dispatch_budget_exhausted") for outcome in outcomes)
        == 1
    )
    parent_view = client.get(f"/v1/tasks/{parent['id']}", headers=admin_headers).json()
    assert parent_view["descendant_dispatch_attempt_budget"]["consumed"] == 1
    assert parent_view["descendant_dispatch_attempt_budget"]["remaining"] == 0


def test_outstanding_dispatch_reservation_cap_survives_restart_and_receipt_releases_slot(
    client, app, admin_headers
):
    worker = create_agent(client, admin_headers, "outstanding-dispatch-worker", "worker")
    token = issue_coordination_mandate(client, admin_headers, worker["id"])
    task = create_task(
        client,
        admin_headers,
        title="One outstanding dispatch slot",
        resources=["repo:file:outstanding-dispatch.py"],
        max_dispatch_attempts=3,
        max_unreceipted_dispatch_attempts=1,
    )
    claim = claim_task(client, task["id"], token).json()
    first = reserve_dispatch_attempt(client, task["id"], token, claim, "held-call")
    assert first.status_code == 201, first.text
    first_id = first.json()["reservation"]["id"]

    Database(app.state.database.path).initialize()
    denied = reserve_dispatch_attempt(client, task["id"], token, claim, "second-call")
    assert denied.status_code == 409
    assert denied.json()["error"] == "task_dispatch_outstanding_budget_exhausted"

    before_receipt = client.get(f"/v1/tasks/{task['id']}", headers=admin_headers).json()
    assert before_receipt["outstanding_dispatch_budget"]["reserved"] == 1
    assert before_receipt["outstanding_dispatch_budget"]["released"] == 0
    assert before_receipt["outstanding_dispatch_budget"]["remaining"] == 0
    assert before_receipt["outstanding_dispatch_budget"]["freshness"] == "current_snapshot"
    assert before_receipt["outstanding_dispatch_budget"]["provider_usage"]["status"] == (
        "unsupported"
    )

    receipt = app.state.coordination.record_dispatch_attempt_receipt(
        task["id"],
        first_id,
        token,
        DispatchAttemptReceiptCreate(
            claim_fencing_token=claim["task"]["claim_fencing_token"],
            http_status_code=429,
            retry_after_seconds=60,
        ),
    )
    assert receipt["created"] is True
    after_receipt = client.get(f"/v1/tasks/{task['id']}", headers=admin_headers).json()
    assert after_receipt["outstanding_dispatch_budget"]["reserved"] == 0
    assert after_receipt["outstanding_dispatch_budget"]["released"] == 1
    assert after_receipt["outstanding_dispatch_budget"]["remaining"] == 1
    assert after_receipt["outstanding_dispatch_budget"]["status"] == "available"

    second = reserve_dispatch_attempt(client, task["id"], token, claim, "second-call")
    assert second.status_code == 201, second.text


def test_sibling_dispatch_fanout_shares_atomic_unreceipted_reservation_cap(
    client, app, admin_headers
):
    workers = [
        create_agent(client, admin_headers, f"outstanding-race-worker-{i}", "worker")
        for i in range(2)
    ]
    tokens = [issue_coordination_mandate(client, admin_headers, worker["id"]) for worker in workers]
    parent = create_task(
        client,
        admin_headers,
        title="One outstanding reservation across descendants",
        max_descendant_unreceipted_dispatch_attempts=1,
    )
    children = [
        create_task(
            client,
            admin_headers,
            title=f"Outstanding dispatch child {i}",
            parent_task_id=parent["id"],
            resources=[f"repo:file:outstanding-child-{i}.py"],
        )
        for i in range(2)
    ]
    claims = [
        claim_task(client, child["id"], token).json()
        for child, token in zip(children, tokens, strict=True)
    ]
    start = Barrier(2)

    def reserve(args):
        child_id, token, claim, key = args
        start.wait(timeout=5)
        try:
            result = app.state.coordination.reserve_dispatch_attempt(
                child_id,
                token,
                DispatchAttemptReservationCreate(
                    claim_fencing_token=claim["task"]["claim_fencing_token"],
                    resource_fencing_tokens=resource_tokens(claim),
                    idempotency_key=key,
                ),
            )
            return "created", child_id, token, claim, result["reservation"]["id"]
        except ControlPlaneError as error:
            return "rejected", getattr(error, "code", type(error).__name__)

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(
            executor.map(
                reserve,
                zip(
                    [child["id"] for child in children],
                    tokens,
                    claims,
                    ["fanout-a", "fanout-b"],
                    strict=True,
                ),
            )
        )

    winners = [outcome for outcome in outcomes if outcome[0] == "created"]
    assert len(winners) == 1
    assert outcomes.count(("rejected", "descendant_dispatch_outstanding_budget_exhausted")) == 1
    parent_view = client.get(f"/v1/tasks/{parent['id']}", headers=admin_headers).json()
    assert parent_view["descendant_outstanding_dispatch_budget"]["reserved"] == 1
    assert parent_view["descendant_outstanding_dispatch_budget"]["released"] == 0
    assert parent_view["descendant_outstanding_dispatch_budget"]["remaining"] == 0

    _, child_id, token, claim, reservation_id = winners[0]
    app.state.coordination.record_dispatch_attempt_receipt(
        child_id,
        reservation_id,
        token,
        DispatchAttemptReceiptCreate(
            claim_fencing_token=claim["task"]["claim_fencing_token"],
            http_status_code=200,
        ),
    )
    released_view = client.get(f"/v1/tasks/{parent['id']}", headers=admin_headers).json()
    assert released_view["descendant_outstanding_dispatch_budget"]["reserved"] == 0
    assert released_view["descendant_outstanding_dispatch_budget"]["released"] == 1


def test_concurrent_dispatch_idempotency_returns_only_one_new_slot(client, app, admin_headers):
    worker = create_agent(client, admin_headers, "dispatch-idempotency-worker", "worker")
    token = issue_coordination_mandate(client, admin_headers, worker["id"])
    task = create_task(
        client,
        admin_headers,
        title="Concurrent idempotent reservation",
        resources=["repo:file:dispatch-idempotency.py"],
        max_dispatch_attempts=1,
    )
    claim = claim_task(client, task["id"], token).json()
    request = DispatchAttemptReservationCreate(
        claim_fencing_token=claim["task"]["claim_fencing_token"],
        resource_fencing_tokens=resource_tokens(claim),
        idempotency_key="same-logical-call",
    )
    start = Barrier(2)

    def reserve(_index):
        start.wait(timeout=5)
        return app.state.coordination.reserve_dispatch_attempt(task["id"], token, request)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(reserve, range(2)))

    assert sorted(result["created"] for result in results) == [False, True]
    assert results[0]["reservation"]["id"] == results[1]["reservation"]["id"]
    assert (
        app.state.database.one(
            "SELECT COUNT(*) AS count FROM dispatch_attempt_reservations WHERE task_id = ?",
            (task["id"],),
        )["count"]
        == 1
    )


@pytest.mark.parametrize(
    ("root_cap", "middle_cap", "blocking_ancestor"),
    [(2, 1, "middle"), (1, 2, "root")],
)
def test_deep_ancestor_dispatch_budget_covers_grandchildren(
    client, admin_headers, root_cap, middle_cap, blocking_ancestor
):
    workers = [
        create_agent(client, admin_headers, f"deep-dispatch-worker-{i}", "worker") for i in range(2)
    ]
    tokens = [issue_coordination_mandate(client, admin_headers, worker["id"]) for worker in workers]
    root = create_task(
        client,
        admin_headers,
        title="One slot for all descendants",
        max_descendant_dispatch_attempts=root_cap,
    )
    middle = create_task(
        client,
        admin_headers,
        title="Intermediate task",
        parent_task_id=root["id"],
        max_descendant_dispatch_attempts=middle_cap,
    )
    leaves = [
        create_task(
            client,
            admin_headers,
            title=f"Grandchild {i}",
            parent_task_id=middle["id"],
            resources=[f"repo:file:deep-dispatch-{i}.py"],
        )
        for i in range(2)
    ]
    claims = [
        claim_task(client, leaf["id"], token).json()
        for leaf, token in zip(leaves, tokens, strict=True)
    ]

    first = reserve_dispatch_attempt(client, leaves[0]["id"], tokens[0], claims[0], "deep-a")
    second = reserve_dispatch_attempt(client, leaves[1]["id"], tokens[1], claims[1], "deep-b")
    assert first.status_code == 201, first.text
    assert second.status_code == 409
    assert second.json()["error"] == "descendant_dispatch_budget_exhausted"
    root_view = client.get(f"/v1/tasks/{root['id']}", headers=admin_headers).json()
    middle_view = client.get(f"/v1/tasks/{middle['id']}", headers=admin_headers).json()
    assert root_view["descendant_dispatch_attempt_budget"]["consumed"] == 1
    assert middle_view["descendant_dispatch_attempt_budget"]["consumed"] == 1
    assert root_view["descendant_dispatch_attempt_budget"]["status"] == (
        "exhausted" if blocking_ancestor == "root" else "available"
    )
    assert middle_view["descendant_dispatch_attempt_budget"]["status"] == (
        "exhausted" if blocking_ancestor == "middle" else "available"
    )


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


def test_claim_budget_usage_survives_service_database_restart(client, app, admin_headers):
    worker_a = create_agent(client, admin_headers, "restart-budget-worker-a", "worker")
    worker_b = create_agent(client, admin_headers, "restart-budget-worker-b", "worker")
    token_a = issue_coordination_mandate(client, admin_headers, worker_a["id"])
    token_b = issue_coordination_mandate(client, admin_headers, worker_b["id"])
    parent = create_task(
        client,
        admin_headers,
        title="Restart-persistent descendant budget",
        max_descendant_claims=1,
    )
    child_a = create_task(
        client,
        admin_headers,
        title="Claimed before restart",
        parent_task_id=parent["id"],
        max_claims=1,
    )
    child_b = create_task(
        client,
        admin_headers,
        title="Claimed after restart",
        parent_task_id=parent["id"],
    )

    first = claim_task(client, child_a["id"], token_a)
    assert first.status_code == 200, first.text

    restarted_app = create_app(app.state.settings)
    with TestClient(restarted_app) as restarted_client:
        restored_child = restarted_client.get(f"/v1/tasks/{child_a['id']}", headers=admin_headers)
        assert restored_child.status_code == 200, restored_child.text
        assert restored_child.json()["claim_budget"]["consumed"] == 1
        assert restored_child.json()["claim_budget"]["status"] == "exhausted"

        second = claim_task(restarted_client, child_b["id"], token_b)
        assert second.status_code == 409
        assert second.json()["error"] == "descendant_claim_budget_exhausted"


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
