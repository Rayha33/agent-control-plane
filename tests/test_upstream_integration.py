"""Independent acceptance checks for integrating upstream PR2 into ACP v0.2."""

from __future__ import annotations

import hashlib
import sqlite3

import pytest
from fastapi.testclient import TestClient

from agent_control_plane.app import create_app
from agent_control_plane.config import Settings
from agent_control_plane.database import SERVICE_SCHEMA_VERSION, Database
from agent_control_plane.schema_version import SCHEMA_VERSION_KEY, SchemaVersionError


@pytest.fixture
def app(tmp_path):
    return create_app(
        Settings(database_path=str(tmp_path / "qc.db"), admin_key="qc-admin", signing_key="s" * 32)
    )


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


ADMIN = {"X-Control-Plane-Key": "qc-admin"}


def agent(client, name, parent=None):
    result = client.post(
        "/v1/agents",
        headers=ADMIN,
        json={"name": name, "owner": "qc@example.invalid", "parent_agent_id": parent},
    )
    assert result.status_code == 201, result.text
    return result.json()["id"]


def mandate(client, agent_id, parent=None):
    headers = ADMIN if parent is None else {"Authorization": f"Bearer {parent['token']}"}
    result = client.post(
        "/v1/mandates",
        headers=headers,
        json={
            "agent_id": agent_id,
            "subject": "independent-qc",
            "scopes": [{"action": "coordination.*", "resource": "task:*"}],
            "ttl_seconds": 3600 if parent is None else 300,
            "parent_mandate_id": None if parent is None else parent["id"],
        },
    )
    assert result.status_code == 201, result.text
    return result.json()


def task(client):
    result = client.post(
        "/v1/tasks",
        headers=ADMIN,
        json={
            "title": "QC reopen target",
            "description": "Independent adversarial acceptance",
            "acceptance_criteria": ["Authorization preserved"],
            "resources": ["src/qc.py"],
        },
    )
    assert result.status_code == 201, result.text
    return result.json()["id"]


@pytest.mark.parametrize("credential", ["missing", "wrong", "worker"])
def test_reopen_requires_admin_not_worker_mandate(client, app, credential):
    task_id = task(client)
    with app.state.database.connect() as connection:
        connection.execute("UPDATE tasks SET status = 'blocked' WHERE id = ?", (task_id,))
    headers = {}
    if credential == "wrong":
        headers = {"X-Control-Plane-Key": "wrong"}
    elif credential == "worker":
        token = mandate(client, agent(client, "worker"))["token"]
        headers = {"Authorization": f"Bearer {token}"}
    result = client.post(
        f"/v1/tasks/{task_id}/reopen", headers=headers, json={"reason": "Try unauthorized reopen"}
    )
    assert result.status_code == 401, result.status_code
    assert result.json()["error"] == "invalid_admin_key"
    assert app.state.coordination.task(task_id)["status"] == "blocked"


@pytest.mark.parametrize(
    "status",
    [
        "open",
        "claimed",
        "working",
        "qc_review",
        "approved",
        "merging",
        "done",
        "changes_requested",
        "orphaned",
    ],
)
def test_reopen_cannot_override_other_states(client, app, status):
    task_id = task(client)
    with app.state.database.connect() as connection:
        connection.execute("UPDATE tasks SET status = ? WHERE id = ?", (status, task_id))
    result = client.post(
        f"/v1/tasks/{task_id}/reopen", headers=ADMIN, json={"reason": "Try wrong state"}
    )
    assert result.status_code == 409, result.text
    assert result.json()["error"] == "task_not_reopenable"
    assert app.state.coordination.task(task_id)["status"] == status


def test_disabled_ancestor_cannot_mint_from_active_child(client, app):
    root = agent(client, "root")
    parent = agent(client, "parent", root)
    child = agent(client, "child", parent)
    parent_mandate = mandate(client, parent, mandate(client, root))
    disabled = client.post(
        f"/v1/agents/{root}/state",
        headers=ADMIN,
        json={"disabled": True, "reason": "Stop ancestor"},
    )
    assert disabled.status_code == 200, disabled.text
    before = app.state.database.one("SELECT COUNT(*) AS count FROM mandates")["count"]
    result = client.post(
        "/v1/mandates",
        headers={"Authorization": f"Bearer {parent_mandate['token']}"},
        json={
            "agent_id": child,
            "subject": "latent-mandate-attempt",
            "parent_mandate_id": parent_mandate["id"],
            "scopes": [{"action": "coordination.claim", "resource": "task:*"}],
            "ttl_seconds": 60,
        },
    )
    assert result.status_code == 401, result.status_code
    assert result.json()["error"] == "agent_lineage_disabled"
    assert app.state.database.one("SELECT COUNT(*) AS count FROM mandates")["count"] == before


@pytest.mark.parametrize("stamp", [str(SERVICE_SCHEMA_VERSION + 1), "unreadable"])
def test_refused_schema_does_not_switch_journal_or_change_bytes(tmp_path, stamp):
    path = tmp_path / "future.db"
    database = Database(str(path))
    database.initialize()
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("UPDATE meta SET value = ? WHERE key = ?", (stamp, SCHEMA_VERSION_KEY))
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(SchemaVersionError):
        database.initialize()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"


@pytest.mark.parametrize("failure", ["method", "insert"])
def test_reopen_audit_failure_rolls_back_transition(client, app, monkeypatch, failure):
    task_id = task(client)
    token = mandate(client, agent(client, "rollback-worker"))["token"]
    claimed = client.post(
        f"/v1/tasks/{task_id}/claim",
        headers={"Authorization": f"Bearer {token}"},
        json={"ttl_seconds": 300},
    )
    assert claimed.status_code == 200, claimed.status_code
    with app.state.database.connect() as connection:
        connection.execute("UPDATE tasks SET status = 'blocked' WHERE id = ?", (task_id,))

    def snapshot():
        with app.state.database.connect() as connection:
            return {
                table: [dict(row) for row in connection.execute(f"SELECT * FROM {table}")]
                for table in ("tasks", "resource_leases", "agent_heartbeats", "audit_events")
            }

    original = snapshot()
    assert original["agent_heartbeats"]
    assert original["resource_leases"]

    def failed_audit(*args, **kwargs):
        raise OSError("induced audit write failure")

    if failure == "method":
        monkeypatch.setattr(app.state.database, "append_audit", failed_audit)
        error_type = OSError
    else:
        with app.state.database.connect() as connection:
            connection.execute("""
                CREATE TRIGGER reject_reopen_audit BEFORE INSERT ON audit_events
                WHEN NEW.event_type = 'task.reopened'
                BEGIN SELECT RAISE(ABORT, 'induced audit insert failure'); END
            """)
        error_type = sqlite3.IntegrityError
    with pytest.raises(error_type, match="induced audit"):
        app.state.coordination.reopen_task(task_id, "Operator-approved redo")
    assert snapshot() == original, "reopen committed changes without its audit event"


def test_transactional_audit_does_not_commit_for_its_caller(app):
    database = app.state.database
    with database.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        database.append_audit("test.pending", "qc", {"pending": True}, connection=connection)
        assert connection.in_transaction
        assert database.audit_events() == [], "audit committed the caller's transaction"
        connection.rollback()
    assert database.audit_events() == []


def test_transactional_audit_rejects_an_idle_connection(app):
    database = app.state.database
    with database.connect() as connection:
        with pytest.raises(ValueError, match="already hold a transaction"):
            database.append_audit("test.idle", "qc", {}, connection=connection)
    assert database.audit_events() == []


def test_transactional_and_original_audit_calls_share_one_valid_chain(app):
    database = app.state.database
    first = database.append_audit("test.original", "qc", {})
    with database.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        second = database.append_audit("test.txn1", "qc", {}, connection=connection)
        third = database.append_audit("test.txn2", "qc", {}, connection=connection)
    assert second["previous_hash"] == first["event_hash"]
    assert third["previous_hash"] == second["event_hash"]
    assert database.verify_audit_chain() == (True, 3, None)
