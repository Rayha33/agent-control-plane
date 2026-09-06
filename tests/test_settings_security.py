from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agent_control_plane.app import create_app
from agent_control_plane.config import (
    DEV_ADMIN_KEY,
    DEV_SIGNING_KEY,
    MINIMUM_SIGNING_KEY_BYTES,
    InsecureSettingsError,
    Settings,
)

# Board #1624. Settings.from_env used to DEFAULT admin_key to "dev-admin-key" and
# signing_key to "dev-signing-key-change-before-production" — both published in a public
# repository. create_app() calls from_env() whenever it is given no settings, so
# `uvicorn agent_control_plane.app:create_app --factory` with nothing exported started a
# server whose admin key was a string in the README: full access to /v1/agents,
# /v1/policies, /v1/audit, /v1/tasks, reap and approvals, plus the ability to mint valid
# HS256 mandates. The README told the operator to export both keys; nothing enforced it.
#
# These tests fail against that behaviour: with a clean environment the old code returned
# Settings happily, so every "refuses" case below would not raise.

ACP_ENV = (
    "ACP_ADMIN_KEY",
    "ACP_SIGNING_KEY",
    "ACP_INSECURE_DEV",
    "ACP_DATABASE_PATH",
    "ACP_ISSUER",
)


@pytest.fixture
def clean_env(monkeypatch):
    for name in ACP_ENV:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_an_unconfigured_environment_is_refused_rather_than_defaulted(clean_env):
    with pytest.raises(InsecureSettingsError) as raised:
        Settings.from_env()
    message = str(raised.value)
    # Both problems reported at once — an operator should not fix one, re-run, and
    # discover the second.
    assert "ACP_ADMIN_KEY is not set" in message
    assert "ACP_SIGNING_KEY is not set" in message
    # The message must be actionable, not just a refusal.
    assert "ACP_INSECURE_DEV" in message


def test_the_published_development_keys_are_refused_by_name(clean_env):
    clean_env.setenv("ACP_ADMIN_KEY", DEV_ADMIN_KEY)
    clean_env.setenv("ACP_SIGNING_KEY", DEV_SIGNING_KEY)
    with pytest.raises(InsecureSettingsError) as raised:
        Settings.from_env()
    # Count the PROBLEM BULLETS, not the whole message: the actionable hint at the end
    # also contains the phrase, so a naive count over the message reads 3 and would make
    # this assertion look wrong when the behaviour is right.
    bullets = [line for line in str(raised.value).splitlines() if line.startswith("  - ")]
    assert len(bullets) == 2, bullets
    assert all("published development key" in line for line in bullets), bullets


def test_a_signing_key_shorter_than_the_digest_it_protects_is_refused(clean_env):
    clean_env.setenv("ACP_ADMIN_KEY", "a-real-admin-key")
    clean_env.setenv("ACP_SIGNING_KEY", "x" * (MINIMUM_SIGNING_KEY_BYTES - 1))
    with pytest.raises(InsecureSettingsError) as raised:
        Settings.from_env()
    assert f"shorter than {MINIMUM_SIGNING_KEY_BYTES} bytes" in str(raised.value)


def test_the_length_floor_counts_bytes_not_characters(clean_env):
    # 31 multi-byte characters are well over the floor in bytes; 31 ASCII ones are not.
    # Counting characters would accept a key the floor is meant to reject.
    clean_env.setenv("ACP_ADMIN_KEY", "a-real-admin-key")
    clean_env.setenv("ACP_SIGNING_KEY", "é" * (MINIMUM_SIGNING_KEY_BYTES - 1))
    Settings.from_env()  # 62 bytes — accepted


def test_real_secrets_are_accepted_and_marked_enforced(clean_env):
    clean_env.setenv("ACP_ADMIN_KEY", "a-real-admin-key")
    clean_env.setenv("ACP_SIGNING_KEY", "s" * MINIMUM_SIGNING_KEY_BYTES)
    settings = Settings.from_env()
    assert settings.insecure_dev is False


def test_the_dev_override_is_explicit_and_visible_on_health(clean_env, tmp_path):
    clean_env.setenv("ACP_INSECURE_DEV", "1")
    clean_env.setenv("ACP_DATABASE_PATH", str(tmp_path / "insecure.db"))
    settings = Settings.from_env()
    assert settings.admin_key == DEV_ADMIN_KEY
    assert settings.signing_key == DEV_SIGNING_KEY
    assert settings.insecure_dev is True

    with TestClient(create_app(settings)) as client:
        body = client.get("/health").json()
    # The whole point of the override: it starts, but it cannot look secure.
    assert body["auth"] == "insecure-dev"
    assert body["status"] == "ok"


def test_a_secured_server_says_so_on_health(clean_env, tmp_path):
    settings = Settings(
        database_path=str(tmp_path / "secure.db"),
        admin_key="a-real-admin-key",
        signing_key="s" * MINIMUM_SIGNING_KEY_BYTES,
        issuer="test-control-plane",
    )
    with TestClient(create_app(settings)) as client:
        body = client.get("/health").json()
    assert body["auth"] == "enforced"


def test_only_the_exact_opt_in_value_enables_the_override(clean_env):
    # "true", "yes" and "0" must NOT open the door — a near-miss in a deployment script
    # should fail closed, not almost-fail-closed.
    for value in ("0", "true", "yes", "TRUE", ""):
        clean_env.setenv("ACP_INSECURE_DEV", value)
        with pytest.raises(InsecureSettingsError):
            Settings.from_env()
