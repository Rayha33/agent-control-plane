from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from agent_control_plane.schemas import MandateCreate
from agent_control_plane.service import ControlPlaneError


def create_agent(client, admin_headers, name, parent_agent_id=None):
    response = client.post(
        "/v1/agents",
        headers=admin_headers,
        json={
            "name": name,
            "owner": "operations@example.com",
            "parent_agent_id": parent_agent_id,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def issue_root_mandate(client, admin_headers, agent_id, max_descendant_mandates=None):
    body = {
        "agent_id": agent_id,
        "subject": "raymond",
        "scopes": [{"action": "payments.*", "resource": "merchant:*"}],
        "ttl_seconds": 3600,
        "max_amount_cents": 10_000,
    }
    if max_descendant_mandates is not None:
        body["max_descendant_mandates"] = max_descendant_mandates
    response = client.post(
        "/v1/mandates",
        headers=admin_headers,
        json=body,
    )
    assert response.status_code == 201, response.text
    return response.json()


def issue_child_mandate(client, parent_mandate, child_agent_id, max_descendant_mandates=None):
    body = {
        "agent_id": child_agent_id,
        "subject": "parent-agent",
        "parent_mandate_id": parent_mandate["id"],
        "scopes": [{"action": "payments.charge", "resource": "merchant:acme"}],
        "ttl_seconds": 1800,
        "max_amount_cents": 5_000,
    }
    if max_descendant_mandates is not None:
        body["max_descendant_mandates"] = max_descendant_mandates
    return client.post(
        "/v1/mandates",
        headers={"Authorization": f"Bearer {parent_mandate['token']}"},
        json=body,
    )


def test_mandate_descendant_cap_counts_nested_issuance_and_stops_at_boundary(
    client, app, admin_headers
):
    root_agent = create_agent(client, admin_headers, "root-budget")
    child_agent = create_agent(client, admin_headers, "child-budget", root_agent["id"])
    grandchild_agent = create_agent(client, admin_headers, "grandchild-budget", child_agent["id"])
    other_grandchild_agent = create_agent(
        client, admin_headers, "other-grandchild-budget", child_agent["id"]
    )
    sibling_agent = create_agent(client, admin_headers, "sibling-budget", root_agent["id"])
    other_sibling_agent = create_agent(
        client, admin_headers, "other-sibling-budget", root_agent["id"]
    )
    root_mandate = issue_root_mandate(
        client, admin_headers, root_agent["id"], max_descendant_mandates=3
    )
    assert root_mandate["max_descendant_mandates"] == 3

    child_response = issue_child_mandate(
        client, root_mandate, child_agent["id"], max_descendant_mandates=1
    )
    assert child_response.status_code == 201, child_response.text
    child_mandate = child_response.json()
    assert child_mandate["max_descendant_mandates"] == 1

    grandchild_response = issue_child_mandate(client, child_mandate, grandchild_agent["id"])
    assert grandchild_response.status_code == 201, grandchild_response.text

    local_cap_denial = issue_child_mandate(client, child_mandate, other_grandchild_agent["id"])
    assert local_cap_denial.status_code == 403
    assert local_cap_denial.json()["error"] == "mandate_fanout_exhausted"

    sibling_response = issue_child_mandate(client, root_mandate, sibling_agent["id"])
    assert sibling_response.status_code == 201, sibling_response.text
    denied = issue_child_mandate(client, root_mandate, other_sibling_agent["id"])
    assert denied.status_code == 403
    assert denied.json()["error"] == "mandate_fanout_exhausted"
    with app.state.database.connect() as connection:
        count = connection.execute(
            """
            WITH RECURSIVE descendants(id) AS (
                SELECT id FROM mandates WHERE parent_mandate_id = ?
                UNION
                SELECT mandate.id
                FROM mandates AS mandate
                JOIN descendants ON mandate.parent_mandate_id = descendants.id
            )
            SELECT COUNT(*) FROM descendants
            """,
            (root_mandate["id"],),
        ).fetchone()[0]
    assert count == 3


def test_unset_mandate_descendant_cap_preserves_unlimited_issuance(client, admin_headers):
    root_agent = create_agent(client, admin_headers, "unlimited-budget-root")
    children = [
        create_agent(client, admin_headers, f"unlimited-budget-child-{n}", root_agent["id"])
        for n in range(2)
    ]
    root_mandate = issue_root_mandate(client, admin_headers, root_agent["id"])
    assert root_mandate["max_descendant_mandates"] is None

    issued = [issue_child_mandate(client, root_mandate, child["id"]) for child in children]
    assert [response.status_code for response in issued] == [201, 201]


def test_zero_mandate_descendant_cap_denies_and_audits_without_token_or_row(
    client, app, admin_headers
):
    root_agent = create_agent(client, admin_headers, "zero-budget-root")
    child_agent = create_agent(client, admin_headers, "zero-budget-child", root_agent["id"])
    root_mandate = issue_root_mandate(
        client, admin_headers, root_agent["id"], max_descendant_mandates=0
    )

    denied = issue_child_mandate(client, root_mandate, child_agent["id"])
    assert denied.status_code == 403
    assert denied.json() == {
        "error": "mandate_fanout_exhausted",
        "message": "an ancestor mandate has exhausted its descendant issuance allowance",
    }
    with app.state.database.connect() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM mandates WHERE parent_mandate_id = ?",
                (root_mandate["id"],),
            ).fetchone()[0]
            == 0
        )
        event = connection.execute(
            "SELECT payload_json FROM audit_events WHERE event_type = 'mandate.fanout_denied'"
        ).fetchone()
    assert event is not None
    payload = json.loads(event["payload_json"])
    assert payload["ancestor_mandate_id"] == root_mandate["id"]
    assert payload["issued_descendant_mandates"] == 0
    assert payload["max_descendant_mandates"] == 0
    assert "token" not in payload
    assert root_mandate["token"] not in event["payload_json"]


@pytest.mark.parametrize("state", ["expired", "revoked"])
def test_expired_or_revoked_descendant_still_consumes_lifetime_cap(
    client, app, admin_headers, state
):
    root_agent = create_agent(client, admin_headers, f"{state}-root")
    child_agent = create_agent(client, admin_headers, f"{state}-child", root_agent["id"])
    root_mandate = issue_root_mandate(
        client, admin_headers, root_agent["id"], max_descendant_mandates=1
    )
    first = issue_child_mandate(client, root_mandate, child_agent["id"])
    assert first.status_code == 201, first.text
    first_mandate = first.json()

    if state == "expired":
        with app.state.database.connect() as connection:
            connection.execute(
                "UPDATE mandates SET expires_at = 1 WHERE id = ?",
                (first_mandate["id"],),
            )
    else:
        response = client.post(
            f"/v1/mandates/{first_mandate['id']}/revoke",
            headers=admin_headers,
            json={"reason": "Test lifetime budget accounting"},
        )
        assert response.status_code == 204

    denied = issue_child_mandate(client, root_mandate, child_agent["id"])
    assert denied.status_code == 403
    assert denied.json()["error"] == "mandate_fanout_exhausted"


def test_concurrent_sibling_mandate_issuance_cannot_overspend_ancestor_cap(
    client, app, admin_headers
):
    root_agent = create_agent(client, admin_headers, "concurrent-budget-root")
    child_agents = [
        create_agent(client, admin_headers, f"concurrent-child-{n}", root_agent["id"])
        for n in range(2)
    ]
    root_mandate = issue_root_mandate(
        client, admin_headers, root_agent["id"], max_descendant_mandates=1
    )

    def issue(agent_id):
        request = MandateCreate(
            agent_id=agent_id,
            subject="parallel-child",
            scopes=[{"action": "payments.charge", "resource": "merchant:acme"}],
            ttl_seconds=1800,
            max_amount_cents=5_000,
            parent_mandate_id=root_mandate["id"],
        )
        try:
            return app.state.service.issue_mandate(request, root_mandate["token"])
        except ControlPlaneError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(issue, [agent["id"] for agent in child_agents]))

    assert sum(isinstance(outcome, dict) for outcome in outcomes) == 1
    assert outcomes.count("mandate_fanout_exhausted") == 1
    with app.state.database.connect() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM mandates WHERE parent_mandate_id = ?",
                (root_mandate["id"],),
            ).fetchone()[0]
            == 1
        )


def test_delegation_approval_kill_switch_and_audit(client, app, admin_headers):
    parent = create_agent(client, admin_headers, "buyer")
    child = create_agent(client, admin_headers, "checkout-worker", parent["id"])
    parent_mandate = issue_root_mandate(client, admin_headers, parent["id"])
    assert parent_mandate["max_descendant_mandates"] is None

    delegated = client.post(
        "/v1/mandates",
        headers={"Authorization": f"Bearer {parent_mandate['token']}"},
        json={
            "agent_id": child["id"],
            "subject": "buyer-agent",
            "parent_mandate_id": parent_mandate["id"],
            "scopes": [{"action": "payments.charge", "resource": "merchant:acme"}],
            "ttl_seconds": 1800,
            "max_amount_cents": 5_000,
        },
    )
    assert delegated.status_code == 201, delegated.text
    child_mandate = delegated.json()
    auth_headers = {"Authorization": f"Bearer {child_mandate['token']}"}

    policy = client.post(
        "/v1/policies",
        headers=admin_headers,
        json={
            "agent_id": child["id"],
            "action_pattern": "payments.charge",
            "resource_pattern": "merchant:*",
            "effect": "allow",
            "requires_approval": True,
            "max_amount_cents": 5_000,
        },
    )
    assert policy.status_code == 201, policy.text

    action = {
        "action": "payments.charge",
        "resource": "merchant:acme",
        "context": {"amount_cents": 2_500, "order_id": "order-123"},
    }
    decision = client.post("/v1/authorize", headers=auth_headers, json=action)
    assert decision.status_code == 200, decision.text
    assert decision.json()["decision"] == "approval_required"
    approval_id = decision.json()["action_request_id"]

    approval = client.post(
        f"/v1/approvals/{approval_id}",
        headers=admin_headers,
        json={"approved": True, "reason": "Known merchant and expected amount"},
    )
    assert approval.status_code == 200
    assert approval.json()["status"] == "approved"

    execution = client.post(
        "/v1/authorize",
        headers=auth_headers,
        json=action | {"approval_id": approval_id},
    )
    assert execution.status_code == 200
    assert execution.json()["decision"] == "allowed"

    replay = client.post(
        "/v1/authorize",
        headers=auth_headers,
        json=action | {"approval_id": approval_id},
    )
    assert replay.status_code == 200
    assert replay.json()["decision"] == "denied"
    assert "consumed" in replay.json()["reason"]

    over_limit = client.post(
        "/v1/authorize",
        headers=auth_headers,
        json=action | {"context": {"amount_cents": 5_001}},
    )
    assert over_limit.json()["decision"] == "denied"

    disabled = client.post(
        f"/v1/agents/{child['id']}/state",
        headers=admin_headers,
        json={"disabled": True, "reason": "Emergency stop"},
    )
    assert disabled.status_code == 200
    assert disabled.json()["disabled"] is True

    after_kill = client.post("/v1/authorize", headers=auth_headers, json=action)
    assert after_kill.json()["decision"] == "denied"
    assert after_kill.json()["reason"] == "agent lineage is disabled"

    verification = client.get("/v1/audit/verify", headers=admin_headers)
    assert verification.status_code == 200
    assert verification.json()["valid"] is True
    assert verification.json()["events_checked"] >= 10

    with app.state.database.connect() as connection:
        connection.execute(
            "UPDATE audit_events SET payload_json = ? WHERE sequence = 1",
            ('{"tampered":true}',),
        )
    tampered = client.get("/v1/audit/verify", headers=admin_headers)
    assert tampered.json()["valid"] is False
    assert tampered.json()["broken_at_sequence"] == 1


def test_child_mandate_cannot_escalate_authority(client, admin_headers):
    parent = create_agent(client, admin_headers, "parent")
    child = create_agent(client, admin_headers, "child", parent["id"])
    parent_mandate = issue_root_mandate(client, admin_headers, parent["id"])

    response = client.post(
        "/v1/mandates",
        headers={"Authorization": f"Bearer {parent_mandate['token']}"},
        json={
            "agent_id": child["id"],
            "subject": "parent-agent",
            "parent_mandate_id": parent_mandate["id"],
            "scopes": [{"action": "*", "resource": "*"}],
            "ttl_seconds": 1800,
            "max_amount_cents": 10_000,
        },
    )
    assert response.status_code == 403
    assert response.json()["error"] == "scope_escalation"


def test_deny_policy_overrides_mandate_scope(client, admin_headers):
    agent = create_agent(client, admin_headers, "restricted-buyer")
    mandate = issue_root_mandate(client, admin_headers, agent["id"])
    client.post(
        "/v1/policies",
        headers=admin_headers,
        json={
            "agent_id": agent["id"],
            "action_pattern": "payments.*",
            "resource_pattern": "merchant:blocked",
            "effect": "deny",
        },
    )

    response = client.post(
        "/v1/authorize",
        headers={"Authorization": f"Bearer {mandate['token']}"},
        json={
            "action": "payments.charge",
            "resource": "merchant:blocked",
            "context": {"amount_cents": 100},
        },
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "denied"
    assert response.json()["reason"] == "denied by policy"


def test_revoke_mandate_invalidates_token(client, admin_headers):
    agent = create_agent(client, admin_headers, "revocable")
    mandate = issue_root_mandate(client, admin_headers, agent["id"])

    revoked = client.post(
        f"/v1/mandates/{mandate['id']}/revoke",
        headers=admin_headers,
        json={"reason": "Task completed"},
    )
    assert revoked.status_code == 204

    response = client.post(
        "/v1/authorize",
        headers={"Authorization": f"Bearer {mandate['token']}"},
        json={
            "action": "payments.charge",
            "resource": "merchant:acme",
            "context": {"amount_cents": 100},
        },
    )
    assert response.status_code == 401
    assert response.json()["error"] == "mandate_revoked"


def test_parent_revocation_and_kill_switch_invalidate_child(client, admin_headers):
    parent = create_agent(client, admin_headers, "parent-controller")
    child = create_agent(client, admin_headers, "child-worker", parent["id"])
    parent_mandate = issue_root_mandate(client, admin_headers, parent["id"])
    delegated = client.post(
        "/v1/mandates",
        headers={"Authorization": f"Bearer {parent_mandate['token']}"},
        json={
            "agent_id": child["id"],
            "subject": "parent-controller",
            "parent_mandate_id": parent_mandate["id"],
            "scopes": [{"action": "payments.charge", "resource": "merchant:acme"}],
            "ttl_seconds": 1800,
            "max_amount_cents": 1_000,
        },
    ).json()
    child_headers = {"Authorization": f"Bearer {delegated['token']}"}
    action = {
        "action": "payments.charge",
        "resource": "merchant:acme",
        "context": {"amount_cents": 100},
    }

    parent_disabled = client.post(
        f"/v1/agents/{parent['id']}/state",
        headers=admin_headers,
        json={"disabled": True, "reason": "Stop the full delegation tree"},
    )
    assert parent_disabled.status_code == 200
    denied = client.post("/v1/authorize", headers=child_headers, json=action)
    assert denied.json()["decision"] == "denied"
    assert denied.json()["reason"] == "agent lineage is disabled"

    client.post(
        f"/v1/agents/{parent['id']}/state",
        headers=admin_headers,
        json={"disabled": False, "reason": "Resume after review"},
    )
    allowed = client.post("/v1/authorize", headers=child_headers, json=action)
    assert allowed.json()["decision"] == "allowed"

    client.post(
        f"/v1/mandates/{parent_mandate['id']}/revoke",
        headers=admin_headers,
        json={"reason": "Root authority removed"},
    )
    invalidated = client.post("/v1/authorize", headers=child_headers, json=action)
    assert invalidated.status_code == 401
    assert invalidated.json()["error"] == "ancestor_mandate_inactive"


def test_disabled_parent_cannot_delegate_a_child_mandate(client, admin_headers):
    parent = create_agent(client, admin_headers, "paused-parent")
    child = create_agent(client, admin_headers, "paused-child", parent["id"])
    parent_mandate = issue_root_mandate(client, admin_headers, parent["id"])

    stopped = client.post(
        f"/v1/agents/{parent['id']}/state",
        headers=admin_headers,
        json={"disabled": True, "reason": "Kill switch"},
    )
    assert stopped.status_code == 200

    delegated = client.post(
        "/v1/mandates",
        headers={"Authorization": f"Bearer {parent_mandate['token']}"},
        json={
            "agent_id": child["id"],
            "subject": "paused-parent",
            "parent_mandate_id": parent_mandate["id"],
            "scopes": [{"action": "payments.charge", "resource": "merchant:acme"}],
            "ttl_seconds": 1800,
            "max_amount_cents": 1_000,
        },
    )
    assert delegated.status_code == 401
    assert delegated.json()["error"] == "agent_lineage_disabled"
