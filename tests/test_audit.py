from __future__ import annotations

from contextlib import contextmanager

import pytest

from agent_control_plane import database as database_module


def append_events(database, count):
    for n in range(count):
        database.append_audit("test.event", "tester", {"n": n})


def tamper(database, sequence, column="payload_json", value='{"tampered":true}'):
    with database.connect() as connection:
        connection.execute(
            f"UPDATE audit_events SET {column} = ? WHERE sequence = ?",
            (value, sequence),
        )


class StreamingOnlyCursor:
    """A cursor that refuses whole-result reads and records each batch it serves."""

    def __init__(self, cursor, batches):
        self._cursor = cursor
        self._batches = batches

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchmany(self, size=None):
        size = self._cursor.arraysize if size is None else size
        rows = self._cursor.fetchmany(size)
        self._batches.append((size, len(rows)))
        return rows

    def fetchall(self):
        raise AssertionError("verification must not load the whole audit table")

    def __iter__(self):
        raise AssertionError("verification must read the audit table in batches")


class StreamingOnlyConnection:
    def __init__(self, connection, batches):
        self._connection = connection
        self._batches = batches

    def execute(self, *args):
        return StreamingOnlyCursor(self._connection.execute(*args), self._batches)

    def __getattr__(self, name):
        return getattr(self._connection, name)


def test_verification_streams_the_chain_in_bounded_batches(app, monkeypatch):
    database = app.state.database
    append_events(database, 10)
    monkeypatch.setattr(database_module, "AUDIT_VERIFY_BATCH", 3)
    # Every read goes through cursors that only hand out bounded batches, so
    # fetchall(), list(cursor) or an oversized fetchmany() fails here.
    batches = []
    real_connect = database.connect

    @contextmanager
    def streaming_only_connect():
        with real_connect() as connection:
            yield StreamingOnlyConnection(connection, batches)

    monkeypatch.setattr(database, "connect", streaming_only_connect)

    result = database.verify_audit_chain()
    assert result["valid"] is True
    assert result["events_checked"] == 10
    assert result["broken_at_sequence"] is None
    assert result["last_sequence"] == 10
    assert all(size <= 3 for size, _rows in batches)
    assert sum(rows for _size, rows in batches) == 10

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
    ("column", "value"),
    [
        # The fields the hash covers change and the stored event_hash does not.
        ("payload_json", '{"tampered":true}'),
        # The stored event_hash changes and the fields it covers do not.
        ("event_hash", "0" * 64),
    ],
)
def test_an_anchored_verification_re_hashes_the_anchor_row(app, column, value):
    # Comparing only the anchor row's stored event_hash let an edit to its payload
    # pass, since that column was left alone. Re-hashing alone would miss the
    # reverse, so both the stored and the recomputed hash must match the anchor.
    database = app.state.database
    append_events(database, 4)
    full = database.verify_audit_chain()
    append_events(database, 2)

    tamper(database, full["last_sequence"], column, value)
    resumed = database.verify_audit_chain(
        after_sequence=full["last_sequence"], anchor_hash=full["last_event_hash"]
    )
    assert resumed["valid"] is False
    assert resumed["broken_at_sequence"] == full["last_sequence"]
    assert resumed["last_event_hash"] is None


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


def test_after_sequence_must_fit_a_sqlite_integer(client, admin_headers):
    # One past SQLite's INTEGER range used to reach the query and raise
    # OverflowError, a 500.
    anchor = {"anchor_hash": "a" * 64}
    too_big = client.get(
        "/v1/audit/verify",
        headers=admin_headers,
        params=anchor | {"after_sequence": 2**63},
    )
    assert too_big.status_code == 422
    largest = client.get(
        "/v1/audit/verify",
        headers=admin_headers,
        params=anchor | {"after_sequence": 2**63 - 1},
    )
    assert largest.status_code == 200, largest.text
    assert largest.json()["valid"] is False


def test_anchor_hash_must_be_a_sha256_hex_digest(client, admin_headers):
    response = client.get(
        "/v1/audit/verify",
        headers=admin_headers,
        params={"after_sequence": 1, "anchor_hash": "not-a-hash"},
    )
    assert response.status_code == 422
