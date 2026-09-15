"""Board #568 acceptance: a partitioned or delayed runner cannot act after it is replaced.

Three places could let a replaced runner through, and each is tested separately:

- the AUTHORITY (heartbeat, submit): the live claim predicate plus, now, the signed attempt
  token that binds a request to the generation it was issued for;
- a GATE on another host that cannot query the authority: :class:`FencingGate` remembers the
  newest generation per resource and refuses anything older, whatever the old token says;
- the RUNNER itself: :class:`LeaseKeeper` stops the runner's own work when the authority
  refuses it, and stops it BEFORE the authority could hand the work to anyone else when it
  cannot reach the authority at all.

Everything here that touches storage runs on SQLite and, with ACP_TEST_POSTGRES_URL, on
PostgreSQL. Acceptance 1 (one winner) is ``test_multihost_races``; acceptance 3 (reviewer
identity is cryptographically distinct) is ``test_runner_identity`` from 912409e.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import jwt
import pytest
from fastapi.testclient import TestClient
from test_coordination import (
    claim_task,
    create_agent,
    create_task,
    issue_coordination_mandate,
    resource_tokens,
    submit_task,
)

from agent_control_plane.app import create_app
from agent_control_plane.attempt_tokens import (
    AttemptTokenError,
    AttemptTokenSigner,
    derive_attempt_key,
)
from agent_control_plane.config import Settings
from agent_control_plane.database import Database
from agent_control_plane.fencing import (
    DatabaseHighWaterStore,
    FencingError,
    FencingGate,
    MemoryHighWaterStore,
)
from agent_control_plane.runner_protocol import (
    TERMINATE_CODES,
    LeaseKeeper,
    LeaseLost,
    LeaseRevoked,
    Renewal,
    http_renewer,
)
from agent_control_plane.security import TokenError, decode_token

pytestmark = pytest.mark.storage_portable

SIGNING_KEY = "test-signing-key-with-enough-entropy"
ISSUER = "test-control-plane"


def signer() -> AttemptTokenSigner:
    return AttemptTokenSigner.from_signing_key(SIGNING_KEY, ISSUER)


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def heartbeat(client, task_id, token, claim, attempt_token=None, ttl=300):
    body = {
        "claim_fencing_token": claim["task"]["claim_fencing_token"],
        "resource_fencing_tokens": resource_tokens(claim),
        "ttl_seconds": ttl,
        "checkpoint": {"step": "working"},
    }
    if attempt_token is not None:
        body["attempt_token"] = attempt_token
    return client.post(f"/v1/tasks/{task_id}/heartbeat", headers=bearer(token), json=body)


def force_lease_expiry(app, task_id: str) -> None:
    with app.state.database.connect() as connection:
        connection.execute("UPDATE tasks SET claim_expires_at = 0 WHERE id = ?", (task_id,))
        connection.execute(
            "UPDATE resource_leases SET expires_at = 0 WHERE task_id = ?", (task_id,)
        )


# --------------------------------------------------------------------- attempt tokens -----


def test_claim_issues_an_attempt_token_bound_to_the_committed_generation(client, admin_headers):
    worker = create_agent(client, admin_headers, "token-worker", "worker")
    mandate = issue_coordination_mandate(client, admin_headers, worker["id"])
    task = create_task(client, admin_headers, resources=["src/a.py", "deploy:staging"])
    claim = claim_task(client, task["id"], mandate).json()

    claims = signer().verify(claim["attempt_token"])
    assert claims.task_id == task["id"]
    assert claims.agent_id == worker["id"]
    assert claims.claim_fencing_token == claim["task"]["claim_fencing_token"]
    assert claims.resource_fencing_tokens == resource_tokens(claim)
    assert claims.expires_at == claim["task"]["claim_expires_at"]

    # A gateway provisioned with only the DERIVED key verifies it...
    gateway_view = AttemptTokenSigner.from_attempt_key(derive_attempt_key(SIGNING_KEY), ISSUER)
    assert gateway_view.verify(claim["attempt_token"]).holder == claims.holder
    # ...and the two token kinds never stand in for each other.
    with pytest.raises(TokenError):
        decode_token(token=claim["attempt_token"], signing_key=SIGNING_KEY, issuer=ISSUER)
    with pytest.raises(AttemptTokenError) as not_attempt:
        signer().verify(mandate)
    assert not_attempt.value.code == "attempt_token_invalid"
    as_bearer = heartbeat(client, task["id"], claim["attempt_token"], claim)
    assert as_bearer.status_code == 401, as_bearer.text


def test_tampered_and_transplanted_attempt_tokens_are_refused(client, admin_headers):
    worker_a = create_agent(client, admin_headers, "token-a", "worker")
    worker_b = create_agent(client, admin_headers, "token-b", "worker")
    mandate_a = issue_coordination_mandate(client, admin_headers, worker_a["id"])
    mandate_b = issue_coordination_mandate(client, admin_headers, worker_b["id"])
    task_a = create_task(client, admin_headers, resources=["src/one.py"], title="A")
    task_b = create_task(client, admin_headers, resources=["src/two.py"], title="B")
    claim_a = claim_task(client, task_a["id"], mandate_a).json()
    claim_b = claim_task(client, task_b["id"], mandate_b).json()

    transplanted = heartbeat(client, task_a["id"], mandate_a, claim_a, claim_b["attempt_token"])
    assert transplanted.status_code == 409
    assert transplanted.json()["error"] == "attempt_token_mismatch"

    payload = jwt.decode(claim_a["attempt_token"], options={"verify_signature": False})
    payload["cft"] += 1
    forged = jwt.encode(payload, "x" * 32, algorithm="HS256", headers={"typ": "acp-attempt+jwt"})
    refused = heartbeat(client, task_a["id"], mandate_a, claim_a, forged)
    assert refused.status_code == 401
    assert refused.json()["error"] == "attempt_token_invalid"

    renewed = heartbeat(client, task_a["id"], mandate_a, claim_a, claim_a["attempt_token"])
    assert renewed.status_code == 200, renewed.text
    body = renewed.json()
    assert body["directive"] == "continue"
    assert body["renew_after_seconds"] == 100
    assert signer().verify(body["attempt_token"]).expires_at == body["expires_at"]


def test_required_attempt_tokens_refuse_bare_heartbeats_and_submissions(
    tmp_path, storage_backend, request, admin_headers
):
    database_path = str(tmp_path / "strict.db")
    if storage_backend == "postgresql":
        database_path = request.getfixturevalue("postgres_url")
    strict = create_app(
        Settings(
            database_path=database_path,
            admin_key="test-admin",
            signing_key=SIGNING_KEY,
            issuer=ISSUER,
            require_attempt_tokens=True,
        )
    )
    with TestClient(strict) as client:
        worker = create_agent(client, admin_headers, "strict-worker", "worker")
        mandate = issue_coordination_mandate(client, admin_headers, worker["id"])
        task = create_task(client, admin_headers, resources=["src/strict.py"])
        claim = claim_task(client, task["id"], mandate).json()

        bare = heartbeat(client, task["id"], mandate, claim)
        assert bare.status_code == 401
        assert bare.json()["error"] == "attempt_token_required"
        assert submit_task(client, task["id"], mandate, claim).status_code == 401

        beat = heartbeat(client, task["id"], mandate, claim, claim["attempt_token"])
        assert beat.status_code == 200, beat.text
        submission = client.post(
            f"/v1/tasks/{task['id']}/submissions",
            headers=bearer(mandate),
            json={
                "task_version": claim["task"]["version"],
                "claim_fencing_token": claim["task"]["claim_fencing_token"],
                "resource_fencing_tokens": resource_tokens(claim),
                "base_revision": "main@abc123",
                "artifact_uri": "patch://strict",
                "artifact_hash": "c" * 64,
                "summary": "Carries the attempt token the strict authority requires.",
                "attempt_token": beat.json()["attempt_token"],
            },
        )
        assert submission.status_code == 201, submission.text


# ------------------------------------------------------------ the acceptance scenario -----


class FakeClock:
    def __init__(self, now: float = 0.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


def test_delayed_runner_is_fenced_at_authority_gate_and_itself_after_replacement(
    client, app, admin_headers, tmp_path
):
    runner_a = create_agent(client, admin_headers, "partitioned-runner", "worker")
    runner_b = create_agent(client, admin_headers, "replacement-runner", "worker")
    mandate_a = issue_coordination_mandate(client, admin_headers, runner_a["id"])
    mandate_b = issue_coordination_mandate(client, admin_headers, runner_b["id"])
    task = create_task(client, admin_headers, resources=["deploy:staging", "src/app.py"])

    claim_a = claim_task(client, task["id"], mandate_a).json()
    # The gate runs on another host with its own store and only the derived key. Its clock is
    # deliberately the authority's issue time, so runner A's token never looks expired to it:
    # what must stop A there is the newer generation, not the clock.
    gate = FencingGate(
        AttemptTokenSigner.from_attempt_key(derive_attempt_key(SIGNING_KEY), ISSUER),
        DatabaseHighWaterStore(Database(str(tmp_path / "gate.db"))),
        clock=lambda: claim_a["task"]["claim_expires_at"] - 300,
    )
    assert gate.admit(claim_a["attempt_token"], "deploy:staging").generation == 1

    # A partitions: no heartbeats. Its lease runs out and the reaper orphans the task.
    clock = FakeClock(0.0)
    terminated: list[str] = []
    keeper_a = LeaseKeeper(
        http_renewer(
            client.post,
            task_id=task["id"],
            bearer_token=mandate_a,
            claim_fencing_token=claim_a["task"]["claim_fencing_token"],
            resource_fencing_tokens=resource_tokens(claim_a),
            ttl_seconds=300,
            attempt_token_ref=lambda: keeper_a.attempt_token,
        ),
        ttl_seconds=300,
        granted_at=0.0,
        attempt_token=claim_a["attempt_token"],
        clock=clock,
        on_terminate=terminated.append,
    )
    force_lease_expiry(app, task["id"])
    reaped = client.post("/v1/coordination/reap", headers=admin_headers).json()
    assert task["id"] in reaped["orphaned_task_ids"]

    claim_b = claim_task(client, task["id"], mandate_b).json()
    assert claim_b["task"]["claim_fencing_token"] > claim_a["task"]["claim_fencing_token"]
    assert gate.admit(claim_b["attempt_token"], "deploy:staging").generation == 2

    # A wakes up. The authority refuses every write it can see...
    late_beat = heartbeat(client, task["id"], mandate_a, claim_a, claim_a["attempt_token"])
    assert late_beat.status_code == 409
    assert late_beat.json()["error"] in TERMINATE_CODES
    late_submit = submit_task(client, task["id"], mandate_a, claim_a)
    assert late_submit.status_code == 409
    assert late_submit.json()["error"] == "stale_claim_fencing_token"

    # ...the remote gate refuses it although its token has not expired by the gate's clock...
    with pytest.raises(FencingError) as stale:
        gate.admit(claim_a["attempt_token"], "deploy:staging")
    assert stale.value.code == "stale_fencing_token"

    # ...and A's own keeper, on its next renewal, is told the claim is gone and stops A.
    clock.now = 101.0
    assert keeper_a.tick().startswith("replaced")
    assert terminated == ["replaced"]
    with pytest.raises(LeaseLost):
        keeper_a.assert_may_act()

    # The replacement is unaffected.
    assert (
        heartbeat(client, task["id"], mandate_b, claim_b, claim_b["attempt_token"]).status_code
        == 200
    )


def test_revoked_claim_keeps_its_resources_reserved_until_the_last_token_expires(
    client, app, admin_headers
):
    runner_a = create_agent(client, admin_headers, "revoked-runner", "worker")
    runner_b = create_agent(client, admin_headers, "waiting-runner", "worker")
    mandate_a = issue_coordination_mandate(client, admin_headers, runner_a["id"])
    mandate_b = issue_coordination_mandate(client, admin_headers, runner_b["id"])
    revoked_task = create_task(client, admin_headers, resources=["src/shared.py"], title="revoked")
    other_task = create_task(client, admin_headers, resources=["src/shared.py"], title="other")
    claim_a = claim_task(client, revoked_task["id"], mandate_a).json()

    revoked = client.post(
        f"/v1/tasks/{revoked_task['id']}/revoke-claim",
        headers=admin_headers,
        json={"reason": "operator terminated a runaway runner"},
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["task"]["status"] == "orphaned"
    assert revoked.json()["revoked_agent_id"] == runner_a["id"]
    assert revoked.json()["resources_reserved_until"] == claim_a["task"]["claim_expires_at"]

    refused = heartbeat(client, revoked_task["id"], mandate_a, claim_a, claim_a["attempt_token"])
    assert refused.status_code == 409 and refused.json()["error"] == "claim_inactive"

    # A's token is still unexpired, so no second generation may exist anywhere yet.
    assert claim_task(client, other_task["id"], mandate_b).json()["error"] == "resource_busy"
    assert claim_task(client, revoked_task["id"], mandate_b).json()["error"] == "resource_busy"

    with app.state.database.connect() as connection:  # A's last token has now expired
        connection.execute(
            "UPDATE resource_leases SET expires_at = 0 WHERE task_id = ?", (revoked_task["id"],)
        )
    replacement = claim_task(client, other_task["id"], mandate_b)
    assert replacement.status_code == 200, replacement.text
    assert (
        resource_tokens(replacement.json())["src/shared.py"]
        > resource_tokens(claim_a)["src/shared.py"]
    )

    again = client.post(
        f"/v1/tasks/{revoked_task['id']}/revoke-claim",
        headers=admin_headers,
        json={"reason": "nothing left to revoke"},
    )
    assert again.status_code == 409 and again.json()["error"] == "claim_not_revocable"
    events = client.get("/v1/audit", headers=admin_headers).json()
    assert [e for e in events if e["event_type"] == "task.claim_revoked"]
    assert client.get("/v1/audit/verify", headers=admin_headers).json()["valid"] is True


# ------------------------------------------------------------------------------ gates -----


def _token(task="t", agent="a", cft=1, generation=5, expires_at=1_000):
    return signer().issue(
        task_id=task,
        agent_id=agent,
        claim_fencing_token=cft,
        resource_fencing_tokens={"deploy:x": generation},
        expires_at=expires_at,
        now=0,
    )


def test_gate_admits_only_the_newest_generation_and_only_its_owner():
    gate = FencingGate(signer(), MemoryHighWaterStore(), clock=lambda: 10)
    assert gate.admit(_token(), "deploy:x").generation == 5
    assert gate.admit(_token(), "deploy:x").generation == 5  # the same attempt, again

    with pytest.raises(FencingError) as confused:
        gate.admit(_token(agent="b"), "deploy:x")
    assert confused.value.code == "fencing_generation_conflict"
    with pytest.raises(FencingError) as undeclared:
        gate.admit(_token(), "deploy:other")
    assert undeclared.value.code == "resource_not_leased"

    assert gate.admit(_token(cft=2, generation=6), "deploy:x").generation == 6
    with pytest.raises(FencingError) as stale:
        gate.admit(_token(), "deploy:x")
    assert stale.value.code == "stale_fencing_token"


def test_gate_expiry_is_judged_by_its_own_clock_and_leeway():
    expired_gate = FencingGate(signer(), MemoryHighWaterStore(), clock=lambda: 1_001)
    with pytest.raises(FencingError) as expired:
        expired_gate.admit(_token(), "deploy:x")
    assert expired.value.code == "attempt_token_expired"
    tolerant = FencingGate(signer(), MemoryHighWaterStore(), clock=lambda: 1_001, leeway_seconds=5)
    assert tolerant.admit(_token(), "deploy:x").generation == 5


def test_gate_replicas_sharing_a_store_admit_one_holder_per_generation(app):
    """Eight gate replicas, one generation, eight different holders: exactly one may win."""

    path = app.state.database.path
    DatabaseHighWaterStore(Database(path))
    replicas = [
        FencingGate(signer(), DatabaseHighWaterStore(Database(path)), clock=lambda: 10)
        for _ in range(8)
    ]
    start = threading.Barrier(len(replicas))

    def contend(index: int) -> str:
        start.wait(timeout=30)
        try:
            replicas[index].admit(_token(agent=f"holder-{index}"), "deploy:x")
        except FencingError as error:
            return error.code
        return "admitted"

    with ThreadPoolExecutor(max_workers=len(replicas)) as pool:
        outcomes = list(pool.map(contend, range(len(replicas))))
    assert outcomes.count("admitted") == 1, outcomes
    assert outcomes.count("fencing_generation_conflict") == len(replicas) - 1, outcomes

    newest = max(range(6, 14))
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(
            pool.map(
                lambda generation: _try(replicas[generation % 8], generation),
                reversed(range(6, 14)),
            )
        )
    with pytest.raises(FencingError):
        replicas[0].admit(_token(agent="late", cft=3, generation=newest - 1), "deploy:x")
    assert (
        replicas[1].admit(_token(agent="holder-13", generation=newest), "deploy:x").generation
        == newest
    )


def _try(gate: FencingGate, generation: int) -> None:
    try:
        gate.admit(_token(agent=f"holder-{generation}", generation=generation), "deploy:x")
    except FencingError:
        pass


# ------------------------------------------------------------------------ lease keeper -----


def test_partitioned_runner_stops_before_the_authority_could_replace_it():
    clock = FakeClock(0.0)
    stopped: list[tuple[str, float]] = []

    def unreachable() -> Renewal:
        clock.now += 0.2  # every attempt costs time, and never gets an answer
        raise ConnectionError("partitioned")

    keeper = LeaseKeeper(
        unreachable,
        ttl_seconds=30,
        granted_at=0.0,
        safety_margin_seconds=3,
        clock=clock,
        on_terminate=lambda reason: stopped.append((reason, clock.now)),
    )
    while keeper.terminated_reason is None and clock.now < 60:
        keeper.tick()
        clock.now += 0.25
    reason, at = stopped[0]
    authority_expiry = 0.0 + 30  # the claim was processed no earlier than it was sent
    assert reason == "lease_unconfirmed"
    assert at < authority_expiry, (
        f"runner still acting at {at}, authority expiry {authority_expiry}"
    )
    assert keeper.transport_failures > 0
    with pytest.raises(LeaseLost):
        keeper.assert_may_act()


def test_a_slow_renewal_counts_from_when_it_was_sent_not_when_it_returned():
    clock = FakeClock(0.0)
    round_trip = 20.0

    def slow() -> Renewal:
        clock.now += round_trip
        return Renewal(ttl_seconds=30, attempt_token="renewed")

    keeper = LeaseKeeper(slow, ttl_seconds=30, granted_at=0.0, safety_margin_seconds=3, clock=clock)
    clock.now = 10.0
    assert keeper.tick() == "renewed"
    sent, received = 10.0, 10.0 + round_trip
    earliest_authority_expiry = sent + 30
    assert keeper.deadline == earliest_authority_expiry - 3
    assert received + 30 > earliest_authority_expiry, "counting from the reply would overrun"
    assert keeper.attempt_token == "renewed"


def test_a_fencing_refusal_terminates_at_once_and_nothing_revives_it():
    clock = FakeClock(0.0)
    calls: list[int] = []
    stopped: list[str] = []

    def refused() -> Renewal:
        calls.append(1)
        raise LeaseRevoked("stale_claim_fencing_token")

    keeper = LeaseKeeper(
        refused, ttl_seconds=30, granted_at=0.0, clock=clock, on_terminate=stopped.append
    )
    clock.now = 10.0
    assert keeper.tick() == "replaced:stale_claim_fencing_token"
    clock.now = 11.0
    assert keeper.tick() == "replaced"
    assert calls == [1] and stopped == ["replaced"]
    with pytest.raises(LeaseLost):
        keeper.assert_may_act()
