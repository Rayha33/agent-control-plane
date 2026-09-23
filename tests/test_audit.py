from __future__ import annotations

import pytest

from agent_control_plane import database as database_module


def append_events(database, count):
    for n in range(count):
        database.append_audit("test.event", "tester", {"n": n})


def tamper(database, sequence):
    with database.connect() as connection:
        connection.execute(
            "UPDATE audit_events SET payload_json = ? WHERE sequence = ?",
            ('{"tampered":true}', sequence),
        )


def test_verification_streams_the_chain_in_bounded_batches(app, monkeypatch):
    database = app.state.database
    append_events(database, 10)
    monkeypatch.setattr(database_module, "AUDIT_VERIFY_BATCH", 3)

    def whole_table(*_args, **_kwargs):
        raise AssertionError("verification must not load the whole audit table")

    monkeypatch.setattr(database, "all", whole_table)

    result = database.verify_audit_chain()
    assert result["valid"] is True
    assert result["events_checked"] == 10
    assert result["broken_at_sequence"] is None
    assert result["last_sequence"] == 10

    tamper(database, 8)
    broken = database.verify_audit_chain()
    assert broken["valid"] is False
    assert broken["broken_at_sequence"] == 8
    # Unchanged semantics: a broken chain still reports every row it holds.
    assert broken["events_checked"] == 10
    assert broken["last_sequence"] is None
    assert broken["last_event_hash"] is None


def test_verification_resumes_from_a_caller_held_anchor(client, app, admin_headers):
    database = app.state.database
    append_events(database, 4)
    full = client.get("/v1/audit/verify", headers=admin_headers).json()
    assert full["valid"] is True
    anchor = {
        "after_sequence": full["last_sequence"],
        "anchor_hash": full["last_event_hash"],
    }

    append_events(database, 3)
    resumed = client.get("/v1/audit/verify", headers=admin_headers, params=anchor)
    assert resumed.status_code == 200, resumed.text
    assert resumed.json()["valid"] is True
    assert resumed.json()["events_checked"] == 3
    assert resumed.json()["last_sequence"] == anchor["after_sequence"] + 3

    nothing_new = client.get(
        "/v1/audit/verify",
        headers=admin_headers,
        params={
            "after_sequence": resumed.json()["last_sequence"],
            "anchor_hash": resumed.json()["last_event_hash"],
        },
    ).json()
    assert nothing_new["valid"] is True
    assert nothing_new["events_checked"] == 0
    assert nothing_new["last_event_hash"] == resumed.json()["last_event_hash"]

    wrong_anchor = client.get(
        "/v1/audit/verify",
        headers=admin_headers,
        params=anchor | {"anchor_hash": "f" * 64},
    ).json()
    assert wrong_anchor["valid"] is False
    assert wrong_anchor["broken_at_sequence"] == anchor["after_sequence"]

    tamper(database, anchor["after_sequence"] + 2)
    tampered = client.get("/v1/audit/verify", headers=admin_headers, params=anchor)
    assert tampered.json()["valid"] is False
    assert tampered.json()["broken_at_sequence"] == anchor["after_sequence"] + 2


@pytest.mark.parametrize(
    "params",
    [
        {"after_sequence": 3},
        {"anchor_hash": "a" * 64},
    ],
)
def test_an_anchor_needs_both_halves(client, admin_headers, params):
    response = client.get("/v1/audit/verify", headers=admin_headers, params=params)
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_anchor"


def test_anchor_hash_must_be_a_sha256_hex_digest(client, admin_headers):
    response = client.get(
        "/v1/audit/verify",
        headers=admin_headers,
        params={"after_sequence": 1, "anchor_hash": "not-a-hash"},
    )
    assert response.status_code == 422
