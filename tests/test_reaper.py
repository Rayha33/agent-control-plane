from __future__ import annotations

import logging
import time

import pytest
from fastapi.testclient import TestClient

from agent_control_plane.app import create_app
from agent_control_plane.config import Settings

ADMIN = {"X-Control-Plane-Key": "test-admin"}


def settings(tmp_path, **fields):
    return Settings(
        database_path=str(tmp_path / "reaper.db"),
        admin_key="test-admin",
        signing_key="test-signing-key-with-enough-entropy",
        **fields,
    )


def expired_claim(client, app):
    agent = client.post(
        "/v1/agents",
        headers=ADMIN,
        json={"name": "crashes", "owner": "ops@example.com", "role": "worker"},
    ).json()
    token = client.post(
        "/v1/mandates",
        headers=ADMIN,
        json={
            "agent_id": agent["id"],
            "subject": "ops",
            "scopes": [{"action": "coordination.*", "resource": "task:*"}],
        },
    ).json()["token"]
    task = client.post(
        "/v1/tasks",
        headers=ADMIN,
        json={
            "title": "Work",
            "description": "Work that a crashed worker abandons.",
            "acceptance_criteria": ["done"],
            "resources": ["src/reaped.py"],
        },
    ).json()
    claimed = client.post(
        f"/v1/tasks/{task['id']}/claim",
        headers={"Authorization": f"Bearer {token}"},
        json={"ttl_seconds": 30},
    )
    assert claimed.status_code == 200, claimed.text
    with app.state.database.connect() as connection:
        connection.execute(
            "UPDATE tasks SET claim_expires_at = 0 WHERE id = ?", (task["id"],)
        )
        connection.execute(
            "UPDATE resource_leases SET expires_at = 0 WHERE task_id = ?",
            (task["id"],),
        )
    return task["id"]


def status_after(client, task_id, want, seconds=5.0):
    deadline = time.monotonic() + seconds
    while True:
        status = client.get(f"/v1/tasks/{task_id}", headers=ADMIN).json()["status"]
        if status == want or time.monotonic() > deadline:
            return status
        time.sleep(0.02)


def test_scheduled_reaper_orphans_an_expired_claim(tmp_path):
    app = create_app(settings(tmp_path, reap_interval_seconds=0.05))
    with TestClient(app) as client:
        task_id = expired_claim(client, app)
        assert status_after(client, task_id, "orphaned") == "orphaned"


def test_reaper_is_off_by_default(tmp_path):
    app = create_app(settings(tmp_path))
    assert app.state.settings.reap_interval_seconds == 0
    with TestClient(app) as client:
        task_id = expired_claim(client, app)
        assert status_after(client, task_id, "orphaned", seconds=0.3) == "claimed"


def test_a_failed_reap_is_logged_and_the_loop_keeps_running(tmp_path, caplog):
    app = create_app(settings(tmp_path, reap_interval_seconds=0.05))
    real_reap = app.state.coordination.reap_expired
    calls = []

    def flaky_reap():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("database is locked")
        return real_reap()

    app.state.coordination.reap_expired = flaky_reap
    with caplog.at_level(logging.ERROR, logger="agent_control_plane.app"):
        with TestClient(app) as client:
            task_id = expired_claim(client, app)
            assert status_after(client, task_id, "orphaned") == "orphaned"
    assert "scheduled reap failed" in caplog.text


@pytest.mark.parametrize(
    ("raw", "expected"), [("", 0.0), ("0", 0.0), ("30", 30.0), ("2.5", 2.5)]
)
def test_reap_interval_is_read_from_the_environment(
    monkeypatch, tmp_path, raw, expected
):
    monkeypatch.setenv("ACP_ADMIN_KEY", "a-real-admin-key")
    monkeypatch.setenv("ACP_SIGNING_KEY", "a-real-signing-key-with-enough-entropy")
    monkeypatch.setenv("ACP_DATABASE_PATH", str(tmp_path / "env.db"))
    monkeypatch.setenv("ACP_REAP_INTERVAL_SECONDS", raw)
    assert Settings.from_env().reap_interval_seconds == expected


@pytest.mark.parametrize("raw", ["-1", "soon", "nan", "inf"])
def test_a_bad_reap_interval_is_refused(monkeypatch, tmp_path, raw):
    monkeypatch.setenv("ACP_ADMIN_KEY", "a-real-admin-key")
    monkeypatch.setenv("ACP_SIGNING_KEY", "a-real-signing-key-with-enough-entropy")
    monkeypatch.setenv("ACP_DATABASE_PATH", str(tmp_path / "env.db"))
    monkeypatch.setenv("ACP_REAP_INTERVAL_SECONDS", raw)
    with pytest.raises(ValueError, match="ACP_REAP_INTERVAL_SECONDS"):
        Settings.from_env()
