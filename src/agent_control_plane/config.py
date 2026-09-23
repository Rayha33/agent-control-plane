from __future__ import annotations

import os
from dataclasses import dataclass

# Built-in development credentials. They are deliberately obvious, and create_app
# logs a warning whenever either one is still in use.
DEV_ADMIN_KEY = "dev-admin-key"
DEV_SIGNING_KEY = "dev-signing-key-change-before-production"

# HS256 wants at least as many key bytes as the digest (RFC 7518 section 3.2).
MIN_KEY_BYTES = {"ACP_SIGNING_KEY": 32, "ACP_ADMIN_KEY": 16}


def dev_mode_enabled() -> bool:
    return os.getenv("ACP_DEV_MODE", "").strip().lower() in {"1", "true", "yes"}


class InsecureDefaultsError(RuntimeError):
    """Raised by Settings.from_env when development credentials would go live."""

    def __init__(self, variables: list[str]):
        self.variables = list(variables)
        super().__init__(
            "refusing to start with built-in development credentials for "
            + ", ".join(self.variables)
            + "; set them to real values, or set ACP_DEV_MODE=1 for local development"
        )


class WeakKeyError(RuntimeError):
    """Raised by Settings.from_env when a configured key is too short to be safe."""

    def __init__(self, variables: list[str]):
        self.variables = list(variables)
        super().__init__(
            "refusing to start with keys shorter than the minimum: "
            + ", ".join(
                f"{name} needs {MIN_KEY_BYTES[name]} bytes" for name in variables
            )
            + "; set longer values, or set ACP_DEV_MODE=1 for local development"
        )


@dataclass(frozen=True)
class Settings:
    database_path: str
    admin_key: str
    signing_key: str
    issuer: str = "agent-control-plane"

    @classmethod
    def from_env(cls) -> Settings:
        """Build settings from ACP_* variables.

        The built-in development credentials are published in this repository, so a
        deployment that forgets ACP_SIGNING_KEY would let anyone forge a mandate for
        any agent with any scopes. They are therefore refused unless ACP_DEV_MODE=1
        says the operator wants them; a log line at startup is not a safeguard.
        """
        settings = cls(
            database_path=os.getenv("ACP_DATABASE_PATH", "agent_control_plane.db"),
            admin_key=os.getenv("ACP_ADMIN_KEY", DEV_ADMIN_KEY),
            signing_key=os.getenv("ACP_SIGNING_KEY", DEV_SIGNING_KEY),
            issuer=os.getenv("ACP_ISSUER", "agent-control-plane"),
        )
        if not dev_mode_enabled():
            if settings.insecure_defaults:
                raise InsecureDefaultsError(settings.insecure_defaults)
            if settings.short_keys:
                raise WeakKeyError(settings.short_keys)
        return settings

    @property
    def insecure_defaults(self) -> list[str]:
        """Environment variables still carrying their built-in development value."""
        active = []
        if self.admin_key == DEV_ADMIN_KEY:
            active.append("ACP_ADMIN_KEY")
        if self.signing_key == DEV_SIGNING_KEY:
            active.append("ACP_SIGNING_KEY")
        return active

    @property
    def short_keys(self) -> list[str]:
        """Environment variables whose key is below its minimum length in bytes."""
        values = {"ACP_SIGNING_KEY": self.signing_key, "ACP_ADMIN_KEY": self.admin_key}
        return [
            name
            for name, value in values.items()
            if len(value.encode("utf-8")) < MIN_KEY_BYTES[name]
        ]
