from __future__ import annotations


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


def issue_root_mandate(client, admin_headers, agent_id):
    response = client.post(
        "/v1/mandates",
        headers=admin_headers,
        json={
            "agent_id": agent_id,
            "subject": "raymond",
            "scopes": [{"action": "payments.*", "resource": "merchant:*"}],
            "ttl_seconds": 3600,
            "max_amount_cents": 10_000,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_delegation_approval_kill_switch_and_audit(client, app, admin_headers):
    parent = create_agent(client, admin_headers, "buyer")
    child = create_agent(client, admin_headers, "checkout-worker", parent["id"])
    parent_mandate = issue_root_mandate(client, admin_headers, parent["id"])

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
