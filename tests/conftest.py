from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agent_control_plane.app import create_app
from agent_control_plane.config import Settings


@pytest.fixture
def app(tmp_path):
    settings = Settings(
        database_path=str(tmp_path / "test.db"),
        admin_key="test-admin",
        signing_key="test-signing-key-with-enough-entropy",
        issuer="test-control-plane",
    )
    return create_app(settings)


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def admin_headers():
    return {"X-Control-Plane-Key": "test-admin"}
