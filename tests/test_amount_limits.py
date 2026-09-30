from __future__ import annotations

import sqlite3

from agent_control_plane.database import SCHEMA, Database


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


def issue_mandate(client, headers, agent_id, **fields):
    response = client.post(
        "/v1/mandates",
        headers=headers,
        json={
            "agent_id": agent_id,
            "subject": "operator",
            "scopes": [{"action": "*", "resource": "*"}],
            "ttl_seconds": 1800,
        }
        | fields,
    )
    return response


def authorize(client, token, action, context=None):
    response = client.post(
        "/v1/authorize",
        headers={"Authorization": f"Bearer {token}"},
        json={"action": action, "resource": "repo:app", "context": context or {}},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_a_capped_mandate_requires_an_amount_by_default(client, admin_headers):
    agent = create_agent(client, admin_headers, "capped")
    issued = issue_mandate(
        client, admin_headers, agent["id"], max_amount_cents=1_000
    ).json()
    assert issued["requires_amount"] is True

    decision = authorize(client, issued["token"], "repo.write")
    assert decision["decision"] == "denied"
    assert decision["reason"] == "amount is required by the mandate limit"
    assert authorize(
        client, issued["token"], "payments.charge", {"amount_cents": 1_001}
    )["reason"] == ("amount exceeds mandate limit")
    assert (
        authorize(client, issued["token"], "payments.charge", {"amount_cents": 999})[
            "decision"
        ]
        == "allowed"
    )


def test_a_mandate_can_waive_the_amount_for_actions_that_carry_none(
    client, admin_headers
):
    agent = create_agent(client, admin_headers, "waived")
    issued = issue_mandate(
        client,
        admin_headers,
        agent["id"],
        max_amount_cents=1_000,
        requires_amount=False,
    ).json()
    assert issued["requires_amount"] is False
    token = issued["token"]

    assert authorize(client, token, "repo.write")["decision"] == "allowed"
    # The cap still binds every amount that is declared.
    over = authorize(client, token, "payments.charge", {"amount_cents": 1_001})
    assert over["decision"] == "denied"
    assert over["reason"] == "amount exceeds mandate limit"
    assert (
        authorize(client, token, "payments.charge", {"amount_cents": 1_000})["decision"]
        == "allowed"
    )


def test_a_policy_limit_still_requires_an_amount_under_a_waived_mandate(
    client, admin_headers
):
    agent = create_agent(client, admin_headers, "policy-capped")
    token = issue_mandate(
        client,
        admin_headers,
        agent["id"],
        max_amount_cents=1_000,
        requires_amount=False,
    ).json()["token"]
    policy = client.post(
        "/v1/policies",
        headers=admin_headers,
        json={
            "agent_id": agent["id"],
            "action_pattern": "payments.*",
            "resource_pattern": "*",
            "max_amount_cents": 500,
        },
    )
    assert policy.status_code == 201, policy.text

    missing = authorize(client, token, "payments.charge")
    assert missing["decision"] == "denied"
    assert missing["reason"] == "amount is required by a policy limit"
    over = authorize(client, token, "payments.charge", {"amount_cents": 501})
    assert over["reason"] == "amount exceeds policy limit"
    assert authorize(client, token, "repo.write")["decision"] == "allowed"


def test_a_child_cannot_waive_an_amount_its_parent_requires(client, admin_headers):
    parent = create_agent(client, admin_headers, "requiring-parent")
    child = create_agent(client, admin_headers, "waiving-child", parent["id"])
    parent_mandate = issue_mandate(
        client, admin_headers, parent["id"], max_amount_cents=1_000
    ).json()
    delegated = issue_mandate(
        client,
        {"Authorization": f"Bearer {parent_mandate['token']}"},
        child["id"],
        parent_mandate_id=parent_mandate["id"],
        max_amount_cents=500,
        requires_amount=False,
        ttl_seconds=600,  # well inside the parent's, so only the amount rule can refuse
    )
    assert delegated.status_code == 403, delegated.text
    assert delegated.json()["error"] == "amount_escalation"


def test_a_child_of_a_waived_parent_may_waive_or_require(client, admin_headers):
    parent = create_agent(client, admin_headers, "waived-parent")
    child = create_agent(client, admin_headers, "either-child", parent["id"])
    parent_mandate = issue_mandate(
        client,
        admin_headers,
        parent["id"],
        max_amount_cents=1_000,
        requires_amount=False,
    ).json()
    parent_headers = {"Authorization": f"Bearer {parent_mandate['token']}"}
    for requires_amount in (False, True):
        delegated = issue_mandate(
            client,
            parent_headers,
            child["id"],
            parent_mandate_id=parent_mandate["id"],
            max_amount_cents=500,
            requires_amount=requires_amount,
            ttl_seconds=600,
        )
        assert delegated.status_code == 201, delegated.text
        assert delegated.json()["requires_amount"] is requires_amount


def test_existing_mandates_keep_requiring_an_amount_after_upgrade(tmp_path):
    path = str(tmp_path / "old.db")
    old_schema = SCHEMA.replace("    requires_amount INTEGER NOT NULL DEFAULT 1,\n", "")
    assert old_schema != SCHEMA
    with sqlite3.connect(path) as connection:
        connection.executescript(old_schema)
        connection.execute(
            "INSERT INTO agents (id, name, owner, created_at) VALUES ('a', 'n', 'o', 't')"
        )
        connection.execute(
            """
            INSERT INTO mandates
                (id, agent_id, subject, scopes_json, max_amount_cents,
                 expires_at, created_at)
            VALUES ('m', 'a', 's', '[]', 100, 0, 't')
            """
        )

    Database(path).initialize()
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT requires_amount FROM mandates WHERE id = 'm'"
        ).fetchone() == (1,)
