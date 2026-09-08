from __future__ import annotations

import logging

from agent_control_plane import __version__
from agent_control_plane.app import create_app
from agent_control_plane.config import DEV_ADMIN_KEY, DEV_SIGNING_KEY, Settings


def test_health_reports_the_package_version(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__}


def test_openapi_version_matches_the_package(client):
    assert client.get("/openapi.json").json()["info"]["version"] == __version__


def test_from_env_reports_which_development_defaults_are_active(monkeypatch, tmp_path):
    monkeypatch.delenv("ACP_ADMIN_KEY", raising=False)
    monkeypatch.delenv("ACP_SIGNING_KEY", raising=False)
    monkeypatch.setenv("ACP_DATABASE_PATH", str(tmp_path / "env.db"))
    assert Settings.from_env().insecure_defaults == [
        "ACP_ADMIN_KEY",
        "ACP_SIGNING_KEY",
    ]
    monkeypatch.setenv("ACP_ADMIN_KEY", "a-real-admin-key")
    assert Settings.from_env().insecure_defaults == ["ACP_SIGNING_KEY"]


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
