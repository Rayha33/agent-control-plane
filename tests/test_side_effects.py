"""Tests for the #741 fenced side-effect gateway.

Every rejection test uses ``exploding_driver``: an adapter that raises if it is ever reached. That
is the point of the whole module -- a gate that refuses *after* the mutation has already happened
is a log, not a gate -- so "was rejected" is not enough evidence on its own. The assertion that
matters is that the external system was never touched.

Claims and leases here are real: tasks are created and claimed over the HTTP API, so the fencing
tokens under test are the ones the control plane actually mints, not fixtures shaped to pass.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from agent_control_plane.service import ControlPlaneError
from agent_control_plane.side_effects import (
    CoordinationClaimVerifier,
    FencedGateway,
    ProviderCall,
    SideEffectRequest,
    artifact_publication_adapter,
    deploy_namespace_adapter,
    mcp_resource_identity,
    postgres_schema_adapter,
)

DB_RESOURCE = "db:orders/public"
DEPLOY_RESOURCE = "deploy:preview/pr-42"
ARTIFACT_RESOURCE = "artifact:acme%2Fapi/v1.2.3"


# --------------------------------------------------------------------------- helpers -------


def create_agent(client, admin_headers, name, role):
    response = client.post(
        "/v1/agents",
        headers=admin_headers,
        json={"name": name, "owner": "operations@example.com", "role": role},
    )
    assert response.status_code == 201, response.text
    return response.json()


def issue_mandate(client, admin_headers, agent_id, *, allow_side_effects=False):
    scopes = [{"action": "coordination.*", "resource": "task:*"}]
    if allow_side_effects:
        scopes.append({"action": "side_effect.*", "resource": "*"})
    response = client.post(
        "/v1/mandates",
        headers=admin_headers,
        json={
            "agent_id": agent_id,
            "subject": f"agent:{agent_id}",
            "scopes": scopes,
            "ttl_seconds": 3600,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["token"]


def create_task(client, admin_headers, resources, title="Fenced work"):
    response = client.post(
        "/v1/tasks",
        headers=admin_headers,
        json={
            "title": title,
            "description": "Mutate an external system behind the fencing gate.",
            "acceptance_criteria": ["Gate admits only the current owner"],
            "resources": resources,
            "dependencies": [],
            "priority": 50,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def claim(client, task_id, token, ttl=300):
    response = client.post(
        f"/v1/tasks/{task_id}/claim",
        headers={"Authorization": f"Bearer {token}"},
        json={"ttl_seconds": ttl},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "claim_token": body["task"]["claim_fencing_token"],
        "resource_tokens": {
            lease["resource"]: lease["fencing_token"] for lease in body["resource_leases"]
        },
    }


class RecordingDriver:
    def __init__(self, result=None):
        self.calls: list[ProviderCall] = []
        self.result = result or {"ok": True}

    def __call__(self, call):
        self.calls.append(call)
        return self.result


def exploding_driver(call):  # pragma: no cover - reaching this IS the failure
    raise AssertionError(f"the external system was mutated despite a rejected request: {call!r}")


def build_gateway(app, drivers=None):
    drivers = drivers or {}
    return FencedGateway(
        database=app.state.database,
        verifier=CoordinationClaimVerifier(app.state.coordination),
        adapters={
            "db.migrate": postgres_schema_adapter(drivers.get("db", exploding_driver)),
            "deploy.publish": deploy_namespace_adapter(drivers.get("deploy", exploding_driver)),
            "artifact.publish": artifact_publication_adapter(
                drivers.get("artifact", exploding_driver)
            ),
        },
    )


def db_request(agent_id, task_id, claimed, key="idem-1", **overrides):
    base = {
        "task_id": task_id,
        "agent_id": agent_id,
        "role": "worker",
        "claim_fencing_token": claimed["claim_token"],
        "resource_fencing_tokens": claimed["resource_tokens"],
        "target_resource": DB_RESOURCE,
        "operation": "db.migrate",
        "idempotency_key": key,
        "payload": {"database": "orders", "schema": "public", "statement": "ALTER TABLE ..."},
    }
    base.update(overrides)
    return SideEffectRequest(**base)


@pytest.fixture
def worker(client, admin_headers):
    agent = create_agent(client, admin_headers, "worker-a", "worker")
    return {"agent": agent, "token": issue_mandate(client, admin_headers, agent["id"])}


# ------------------------------------------------------------------------ happy path -------


def test_admitted_request_applies_the_side_effect_and_returns_a_receipt(
    client, app, admin_headers, worker
):
    task = create_task(client, admin_headers, [DB_RESOURCE])
    claimed = claim(client, task["id"], worker["token"])
    driver = RecordingDriver({"migrated": True})
    gateway = build_gateway(app, {"db": driver})

    receipt = gateway.execute(db_request(worker["agent"]["id"], task["id"], claimed))

    assert len(driver.calls) == 1
    assert receipt.status == "applied"
    assert receipt.target_resource == DB_RESOURCE
    assert receipt.actor_agent_id == worker["agent"]["id"]
    assert receipt.replayed is False
    assert receipt.resource_fencing_token == claimed["resource_tokens"][DB_RESOURCE]
    assert gateway.receipts(task["id"])[0]["id"] == receipt.id
    provider_call = driver.calls[0]
    assert provider_call.idempotency_key == "idem-1"
    assert provider_call.resource_fencing_token == claimed["resource_tokens"][DB_RESOURCE]
    assert provider_call.request_digest == receipt.request_digest


def test_all_three_adapters_derive_their_contended_identity_from_the_payload(
    client, app, admin_headers, worker
):
    resources = [DB_RESOURCE, DEPLOY_RESOURCE, ARTIFACT_RESOURCE]
    task = create_task(client, admin_headers, resources)
    claimed = claim(client, task["id"], worker["token"])
    drivers = {"db": RecordingDriver(), "deploy": RecordingDriver(), "artifact": RecordingDriver()}
    gateway = build_gateway(app, drivers)
    agent_id = worker["agent"]["id"]

    gateway.execute(db_request(agent_id, task["id"], claimed, key="k-db"))
    gateway.execute(
        db_request(
            agent_id,
            task["id"],
            claimed,
            key="k-deploy",
            operation="deploy.publish",
            target_resource=DEPLOY_RESOURCE,
            payload={"environment": "preview", "namespace": "pr-42"},
        )
    )
    gateway.execute(
        db_request(
            agent_id,
            task["id"],
            claimed,
            key="k-art",
            operation="artifact.publish",
            target_resource=ARTIFACT_RESOURCE,
            payload={"repository": "acme/api", "tag": "v1.2.3", "digest": "sha256:abc"},
        )
    )

    assert [len(d.calls) for d in drivers.values()] == [1, 1, 1]


# -------------------------------------------------------------------------- refusals -------


def test_a_reviewer_cannot_drive_side_effects(client, app, admin_headers, worker):
    task = create_task(client, admin_headers, [DB_RESOURCE])
    claimed = claim(client, task["id"], worker["token"])
    gateway = build_gateway(app)  # every driver explodes

    with pytest.raises(ControlPlaneError) as error:
        gateway.execute(db_request(worker["agent"]["id"], task["id"], claimed, role="reviewer"))
    assert error.value.code == "role_forbidden"


def test_request_cannot_spoof_an_authoritative_worker_role(client, app, admin_headers, worker):
    task = create_task(client, admin_headers, [DB_RESOURCE])
    claimed = claim(client, task["id"], worker["token"])
    app.state.database.execute(
        "UPDATE agents SET role = 'qc' WHERE id = ?", (worker["agent"]["id"],)
    )
    gateway = build_gateway(app)

    with pytest.raises(ControlPlaneError) as error:
        gateway.execute(
            db_request(
                worker["agent"]["id"],
                task["id"],
                claimed,
                role="worker",
            )
        )

    assert error.value.code == "role_mismatch"


def test_a_resource_the_task_never_leased_is_refused(client, app, admin_headers, worker):
    task = create_task(client, admin_headers, [DB_RESOURCE])
    claimed = claim(client, task["id"], worker["token"])
    gateway = build_gateway(app)

    # A payload naming a schema this task holds no lease for.
    with pytest.raises(ControlPlaneError) as error:
        gateway.execute(
            db_request(
                worker["agent"]["id"],
                task["id"],
                claimed,
                target_resource="db:billing/public",
                payload={"database": "billing", "schema": "public", "statement": "DROP ..."},
            )
        )
    assert error.value.code == "undeclared_resource"


def test_a_payload_that_targets_something_other_than_the_declared_resource_is_refused(
    client, app, admin_headers, worker
):
    """Declaring a resource you hold and then acting on another is the obvious bypass."""
    task = create_task(client, admin_headers, [DB_RESOURCE])
    claimed = claim(client, task["id"], worker["token"])
    gateway = build_gateway(app)

    with pytest.raises(ControlPlaneError) as error:
        gateway.execute(
            db_request(
                worker["agent"]["id"],
                task["id"],
                claimed,
                payload={"database": "orders", "schema": "secret", "statement": "..."},
            )
        )
    assert error.value.code == "resource_mismatch"


def test_an_expired_claim_cannot_mutate(client, app, admin_headers, worker):
    task = create_task(client, admin_headers, [DB_RESOURCE])
    claimed = claim(client, task["id"], worker["token"])
    gateway = build_gateway(app)

    # Expire the claim the way wall-clock time would.
    app.state.database.execute("UPDATE tasks SET claim_expires_at = 1 WHERE id = ?", (task["id"],))
    app.state.database.execute(
        "UPDATE resource_leases SET expires_at = 1 WHERE task_id = ?", (task["id"],)
    )

    with pytest.raises(ControlPlaneError) as error:
        gateway.execute(db_request(worker["agent"]["id"], task["id"], claimed))
    assert error.value.code == "stale_claim_fencing_token"


def test_a_superseded_resource_token_cannot_mutate(client, app, admin_headers, worker):
    task = create_task(client, admin_headers, [DB_RESOURCE])
    claimed = claim(client, task["id"], worker["token"])
    gateway = build_gateway(app)

    app.state.database.execute(
        "UPDATE resource_leases SET fencing_token = fencing_token + 1 WHERE task_id = ?",
        (task["id"],),
    )

    with pytest.raises(ControlPlaneError) as error:
        gateway.execute(db_request(worker["agent"]["id"], task["id"], claimed))
    assert error.value.code == "stale_fencing_token"


def test_a_lease_held_under_a_different_task_cannot_be_used(client, app, admin_headers, worker):
    """Holding two tasks must not let either one's lease authorise the other's mutation.

    🔴 The obvious version of this test does NOT work, and the reason is worth writing down:
    fencing tokens are PER-TASK counters, so two freshly claimed tasks both carry
    ``claim_fencing_token == 1``. Presenting "the other task's token" is therefore not an attack --
    the number is only ever compared against the task named in the request, which this agent
    legitimately owns, so it is admitted and SHOULD be. A token value is not a capability on its
    own; the binding lives in the (task, resource, holder) tuple that `_assert_active_claim`
    checks, never in the integer. The first draft of this test asserted the wrong thing and the
    exploding driver is what exposed it.

    The real cross-task move is to reach for a resource leased under the OTHER task while acting
    in this one, which is what is exercised here.
    """
    task = create_task(client, admin_headers, [DB_RESOURCE])
    other = create_task(client, admin_headers, ["db:other/public"], title="Other work")
    claimed = claim(client, task["id"], worker["token"])
    other_claimed = claim(client, other["id"], worker["token"])
    gateway = build_gateway(app)

    merged = dict(claimed["resource_tokens"])
    merged.update(other_claimed["resource_tokens"])

    with pytest.raises(ControlPlaneError) as error:
        gateway.execute(
            db_request(
                worker["agent"]["id"],
                task["id"],
                {"claim_token": claimed["claim_token"], "resource_tokens": merged},
                target_resource="db:other/public",
                payload={"database": "other", "schema": "public", "statement": "DROP ..."},
            )
        )
    # The token set no longer matches this task's declared resources, so admission fails before
    # the adapter -- the same predicate that guards submissions.
    assert error.value.code == "incomplete_resource_fencing_tokens"


# ------------------------------------------------------------- the zombie, and ordering ----


def test_a_delayed_zombie_cannot_mutate_after_a_newer_owner_is_admitted(client, app, admin_headers):
    """The failure this whole module exists to prevent.

    Agent A claims and begins a long migration. Its claim lapses; agent B is admitted and gets a
    HIGHER fencing token. A's call finally lands. It must be refused even though A once held a
    perfectly valid claim, and B's newer claim must still work.
    """
    a = create_agent(client, admin_headers, "zombie", "worker")
    b = create_agent(client, admin_headers, "successor", "worker")
    a_token = issue_mandate(client, admin_headers, a["id"])
    b_token = issue_mandate(client, admin_headers, b["id"])

    task = create_task(client, admin_headers, [DB_RESOURCE])
    a_claim = claim(client, task["id"], a_token)

    # A stalls; its claim lapses and the reaper orphans the task so B can take over.
    # 🔴 Driven through the REAL reaper, not by hand-setting status: expiring the timestamps alone
    # leaves the task 'claimed' and unclaimable, so a test that patched the status directly would
    # be exercising a state the control plane never actually produces.
    app.state.database.execute("UPDATE tasks SET claim_expires_at = 1 WHERE id = ?", (task["id"],))
    app.state.database.execute(
        "UPDATE resource_leases SET expires_at = 1 WHERE task_id = ?", (task["id"],)
    )
    reaped = app.state.coordination.reap_expired()
    assert task["id"] in reaped["orphaned_task_ids"], reaped
    b_claim = claim(client, task["id"], b_token)

    assert b_claim["claim_token"] > a_claim["claim_token"], "a new claim must supersede"
    assert b_claim["resource_tokens"][DB_RESOURCE] > a_claim["resource_tokens"][DB_RESOURCE], (
        "the resource lease must also advance"
    )

    gateway = build_gateway(app)  # explodes if A is ever admitted
    with pytest.raises(ControlPlaneError) as error:
        gateway.execute(db_request(a["id"], task["id"], a_claim, key="zombie-write"))
    assert error.value.code == "stale_claim_fencing_token"

    # And the rightful owner is still able to work -- a gate that also blocks B would be useless.
    driver = RecordingDriver()
    live = build_gateway(app, {"db": driver})
    receipt = live.execute(db_request(b["id"], task["id"], b_claim, key="successor-write"))
    assert receipt.status == "applied"
    assert len(driver.calls) == 1


# ----------------------------------------------------------------------- idempotency -------


def test_a_retried_request_executes_once_and_replays_the_receipt(
    client, app, admin_headers, worker
):
    task = create_task(client, admin_headers, [DB_RESOURCE])
    claimed = claim(client, task["id"], worker["token"])
    driver = RecordingDriver()
    gateway = build_gateway(app, {"db": driver})
    request = db_request(worker["agent"]["id"], task["id"], claimed, key="retry-me")

    first = gateway.execute(request)
    second = gateway.execute(request)

    assert len(driver.calls) == 1, "a retry must not mutate the external system twice"
    assert second.id == first.id
    assert second.replayed is True
    assert first.replayed is False


def test_concurrent_retries_are_serialized_by_the_durable_idempotency_row(
    client, app, admin_headers, worker
):
    task = create_task(client, admin_headers, [DB_RESOURCE])
    claimed = claim(client, task["id"], worker["token"])
    driver = RecordingDriver()
    gateway = build_gateway(app, {"db": driver})
    request = db_request(worker["agent"]["id"], task["id"], claimed, key="concurrent")

    with ThreadPoolExecutor(max_workers=2) as pool:
        receipts = list(pool.map(lambda _index: gateway.execute(request), range(2)))

    assert len(driver.calls) == 1
    assert receipts[0].id == receipts[1].id
    assert sorted(receipt.replayed for receipt in receipts) == [False, True]


def test_reusing_an_idempotency_key_for_a_different_request_is_refused(
    client, app, admin_headers, worker
):
    """Silently replaying the old receipt would report success for work never done."""
    task = create_task(client, admin_headers, [DB_RESOURCE])
    claimed = claim(client, task["id"], worker["token"])
    gateway = build_gateway(app, {"db": RecordingDriver()})
    agent_id = worker["agent"]["id"]

    gateway.execute(db_request(agent_id, task["id"], claimed, key="shared"))
    with pytest.raises(ControlPlaneError) as error:
        gateway.execute(
            db_request(
                agent_id,
                task["id"],
                claimed,
                key="shared",
                payload={"database": "orders", "schema": "public", "statement": "DIFFERENT"},
            )
        )
    assert error.value.code == "idempotency_key_reused"


def test_an_idempotency_replay_still_happens_when_the_claim_has_since_expired(
    client, app, admin_headers, worker
):
    """A retry of work already done must not be punished for a lapsed claim -- the effect already
    exists, and refusing would push callers into re-issuing it under a fresh key."""
    task = create_task(client, admin_headers, [DB_RESOURCE])
    claimed = claim(client, task["id"], worker["token"])
    gateway = build_gateway(app, {"db": RecordingDriver()})
    request = db_request(worker["agent"]["id"], task["id"], claimed, key="settled")
    gateway.execute(request)

    app.state.database.execute("UPDATE tasks SET claim_expires_at = 1 WHERE id = ?", (task["id"],))
    replayed = gateway.execute(request)
    assert replayed.replayed is True


# --------------------------------------------------------------------------- receipts ------


def test_receipts_bind_actor_target_and_result_without_leaking_credentials(
    client, app, admin_headers, worker
):
    task = create_task(client, admin_headers, [DB_RESOURCE])
    claimed = claim(client, task["id"], worker["token"])
    gateway = build_gateway(app, {"db": RecordingDriver({"rows": 3})})

    secret = "postgres://admin:hunter2@db.internal:5432/orders"
    receipt = gateway.execute(
        db_request(
            worker["agent"]["id"],
            task["id"],
            claimed,
            payload={
                "database": "orders",
                "schema": "public",
                "statement": "ALTER TABLE orders ADD COLUMN x int",
                "dsn": secret,
            },
        )
    )

    blob = repr(receipt.to_dict())
    assert "hunter2" not in blob and secret not in blob
    assert "ALTER TABLE" not in blob, "the payload itself must not be echoed into the receipt"
    # It still binds the four things an auditor needs.
    assert receipt.actor_agent_id == worker["agent"]["id"]
    assert receipt.target_resource == DB_RESOURCE
    assert len(receipt.request_digest) == 64 and len(receipt.result_digest) == 64

    stored = repr(app.state.database.all("SELECT * FROM side_effect_receipts", ()))
    assert "hunter2" not in stored


def test_the_audit_chain_records_the_side_effect_and_stays_verifiable(
    client, app, admin_headers, worker
):
    task = create_task(client, admin_headers, [DB_RESOURCE])
    claimed = claim(client, task["id"], worker["token"])
    gateway = build_gateway(app, {"db": RecordingDriver()})
    gateway.execute(db_request(worker["agent"]["id"], task["id"], claimed))

    events = [event["event_type"] for event in app.state.database.audit_events(limit=50)]
    assert "side_effect.applied" in events
    valid, _checked, broken_at = app.state.database.verify_audit_chain()
    assert valid and broken_at is None


# ------------------------------------------------------------------------- MCP / A2A -------


def test_mcp_identity_maps_onto_the_same_resource_namespace(client, app):
    assert mcp_resource_identity("deploy", "task-1", "preview/pr-42") == "deploy:preview/pr-42"
    with pytest.raises(ControlPlaneError) as missing:
        mcp_resource_identity("deploy", "task-1", "")
    assert missing.value.code == "invalid_mcp_identity"
    with pytest.raises(ControlPlaneError) as unknown:
        mcp_resource_identity("email", "task-1", "someone@example.com")
    assert unknown.value.code == "unknown_resource_kind"


def test_authenticated_http_gateway_derives_actor_and_exposes_safe_receipts(
    client, app, admin_headers
):
    agent = create_agent(client, admin_headers, "http-worker", "worker")
    token = issue_mandate(client, admin_headers, agent["id"], allow_side_effects=True)
    task = create_task(client, admin_headers, [DB_RESOURCE])
    claimed = claim(client, task["id"], token)
    driver = RecordingDriver({"migration": "applied"})
    app.state.side_effect_gateway.adapters["db.migrate"] = postgres_schema_adapter(driver)
    body = {
        "task_id": task["id"],
        "claim_fencing_token": claimed["claim_token"],
        "resource_fencing_tokens": claimed["resource_tokens"],
        "target_resource": DB_RESOURCE,
        "idempotency_key": "http-migration-1",
        "payload": {"database": "orders", "schema": "public", "migration": "20260813"},
    }

    response = client.post(
        "/v1/side-effects/db.migrate",
        headers={"Authorization": f"Bearer {token}"},
        json=body,
    )

    assert response.status_code == 201, response.text
    receipt = response.json()
    assert receipt["actor_agent_id"] == agent["id"]
    assert receipt["target_resource"] == DB_RESOURCE
    assert driver.calls[0].idempotency_key == "http-migration-1"
    observed = client.get(f"/v1/tasks/{task['id']}/side-effect-receipts", headers=admin_headers)
    assert observed.status_code == 200
    assert observed.json() == [receipt]


def test_http_gateway_rejects_scope_denial_and_actor_spoofing_before_provider(
    client, app, admin_headers, worker
):
    task = create_task(client, admin_headers, [DB_RESOURCE])
    claimed = claim(client, task["id"], worker["token"])
    app.state.side_effect_gateway.adapters["db.migrate"] = postgres_schema_adapter(exploding_driver)
    body = {
        "task_id": task["id"],
        "claim_fencing_token": claimed["claim_token"],
        "resource_fencing_tokens": claimed["resource_tokens"],
        "target_resource": DB_RESOURCE,
        "idempotency_key": "must-not-run",
        "payload": {"database": "orders", "schema": "public"},
    }

    denied = client.post(
        "/v1/side-effects/db.migrate",
        headers={"Authorization": f"Bearer {worker['token']}"},
        json=body,
    )
    assert denied.status_code == 403
    assert denied.json()["error"] == "side_effect_scope_denied"

    spoofed = client.post(
        "/v1/side-effects/db.migrate",
        headers={"Authorization": f"Bearer {worker['token']}"},
        json=body | {"agent_id": worker["agent"]["id"], "role": "worker"},
    )
    assert spoofed.status_code == 422


def test_a2a_transport_maps_durable_identity_into_the_same_fenced_adapter(
    client, app, admin_headers
):
    agent = create_agent(client, admin_headers, "a2a-worker", "worker")
    token = issue_mandate(client, admin_headers, agent["id"], allow_side_effects=True)
    task = create_task(client, admin_headers, [DEPLOY_RESOURCE])
    claimed = claim(client, task["id"], token)
    driver = RecordingDriver({"preview": "ready"})
    app.state.side_effect_gateway.adapters["deploy.publish"] = deploy_namespace_adapter(driver)

    response = client.post(
        "/v1/a2a/side-effects/deploy.publish",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "task_id": task["id"],
            "artifact_id": "preview/pr-42",
            "kind": "deploy",
            "claim_fencing_token": claimed["claim_token"],
            "resource_fencing_tokens": claimed["resource_tokens"],
            "idempotency_key": "a2a-preview-1",
            "payload": {"environment": "preview", "namespace": "pr-42"},
        },
    )

    assert response.status_code == 201, response.text
    assert response.json()["target_resource"] == DEPLOY_RESOURCE
    assert driver.calls[0].target_resource == DEPLOY_RESOURCE


def test_an_unknown_operation_is_refused_before_anything_else(client, app, admin_headers, worker):
    task = create_task(client, admin_headers, [DB_RESOURCE])
    claimed = claim(client, task["id"], worker["token"])
    gateway = build_gateway(app)
    with pytest.raises(ControlPlaneError) as error:
        gateway.execute(db_request(worker["agent"]["id"], task["id"], claimed, operation="dns.set"))
    assert error.value.code == "unknown_side_effect"
