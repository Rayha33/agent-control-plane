from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from agent_control_plane import __version__
from agent_control_plane.app import create_app
from agent_control_plane.config import (
    DEV_ADMIN_KEY,
    DEV_SIGNING_KEY,
    InsecureDefaultsError,
    Settings,
)


def test_health_reports_the_package_version(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__}


def test_openapi_version_matches_the_package(client):
    assert client.get("/openapi.json").json()["info"]["version"] == __version__


def test_from_env_reports_which_development_defaults_are_active(monkeypatch, tmp_path):
    monkeypatch.delenv("ACP_ADMIN_KEY", raising=False)
    monkeypatch.delenv("ACP_SIGNING_KEY", raising=False)
    monkeypatch.setenv("ACP_DEV_MODE", "1")
    monkeypatch.setenv("ACP_DATABASE_PATH", str(tmp_path / "env.db"))
    assert Settings.from_env().insecure_defaults == [
        "ACP_ADMIN_KEY",
        "ACP_SIGNING_KEY",
    ]
    monkeypatch.setenv("ACP_ADMIN_KEY", "a-real-admin-key")
    assert Settings.from_env().insecure_defaults == ["ACP_SIGNING_KEY"]


def test_from_env_refuses_development_defaults_unless_dev_mode(monkeypatch, tmp_path):
    monkeypatch.delenv("ACP_ADMIN_KEY", raising=False)
    monkeypatch.delenv("ACP_SIGNING_KEY", raising=False)
    monkeypatch.delenv("ACP_DEV_MODE", raising=False)
    monkeypatch.setenv("ACP_DATABASE_PATH", str(tmp_path / "env.db"))
    with pytest.raises(InsecureDefaultsError) as refused:
        Settings.from_env()
    assert refused.value.variables == ["ACP_ADMIN_KEY", "ACP_SIGNING_KEY"]
    assert "ACP_DEV_MODE=1" in str(refused.value)

    # One real value is not enough: the published signing key still forges mandates.
    monkeypatch.setenv("ACP_ADMIN_KEY", "a-real-admin-key")
    with pytest.raises(InsecureDefaultsError) as refused:
        Settings.from_env()
    assert refused.value.variables == ["ACP_SIGNING_KEY"]

    monkeypatch.setenv("ACP_SIGNING_KEY", "a-real-signing-key-with-enough-entropy")
    assert Settings.from_env().insecure_defaults == []


def test_development_defaults_are_logged_at_startup(tmp_path, caplog):
    settings = Settings(
        database_path=str(tmp_path / "dev.db"),
        admin_key=DEV_ADMIN_KEY,
        signing_key=DEV_SIGNING_KEY,
    )
    with caplog.at_level(logging.WARNING, logger="agent_control_plane.app"):
        create_app(settings)
    assert "ACP_ADMIN_KEY" in caplog.text
    assert "ACP_SIGNING_KEY" in caplog.text


def test_explicit_credentials_are_not_flagged(app, caplog):
    assert app.state.settings.insecure_defaults == []
    assert "development defaults" not in caplog.text


def test_file_backed_database_runs_in_wal_mode(app):
    with app.state.database.connect() as connection:
        mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode == "wal"


def test_non_ascii_admin_key_is_a_clean_401_not_a_500(client):
    # secrets.compare_digest rejects str operands with non-ASCII characters; an
    # accented header value used to escape as a TypeError and a 500 stack trace.
    # Sent as UTF-8 bytes, which is what a real client puts on the wire.
    response = client.post(
        "/v1/agents",
        headers={"X-Control-Plane-Key": "cl\u00e9-secr\u00e8te".encode()},
        json={"name": "x", "owner": "ops@example.com", "role": "worker"},
    )
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_admin_key"


def test_non_ascii_configured_admin_key_still_authenticates(tmp_path):
    settings = Settings(
        database_path=str(tmp_path / "accent.db"),
        admin_key="cl\u00e9-secr\u00e8te",
        signing_key="test-signing-key-with-enough-entropy",
    )
    with TestClient(create_app(settings)) as accented_client:
        response = accented_client.post(
            "/v1/agents",
            headers={"X-Control-Plane-Key": "cl\u00e9-secr\u00e8te".encode()},
            json={"name": "x", "owner": "ops@example.com", "role": "worker"},
        )
    assert response.status_code == 201, response.text
