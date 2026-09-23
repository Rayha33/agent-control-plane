from __future__ import annotations

import os
from dataclasses import dataclass

# Built-in development credentials. They are deliberately obvious and are only
# accepted when ACP_DEV_MODE=1; create_app refuses to start with them otherwise.
DEV_ADMIN_KEY = "dev-admin-key"
DEV_SIGNING_KEY = "dev-signing-key-change-before-production"

# HS256 wants at least as many key bytes as the digest (RFC 7518 §3.2).
MIN_SIGNING_KEY_BYTES = 32
MIN_ADMIN_KEY_BYTES = 16


class ConfigurationError(RuntimeError):
    """Settings that are unsafe to serve with."""


@dataclass(frozen=True)
class Settings:
    database_path: str
    admin_key: str
    signing_key: str
    issuer: str = "agent-control-plane"
    dev_mode: bool = False

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            database_path=os.getenv("ACP_DATABASE_PATH", "agent_control_plane.db"),
            admin_key=os.getenv("ACP_ADMIN_KEY", DEV_ADMIN_KEY),
            signing_key=os.getenv("ACP_SIGNING_KEY", DEV_SIGNING_KEY),
            issuer=os.getenv("ACP_ISSUER", "agent-control-plane"),
            dev_mode=os.getenv("ACP_DEV_MODE", "") == "1",
        )

    @property
    def insecure_defaults(self) -> list[str]:
        """Environment variables still carrying their built-in development value."""
        active = []
        if self.admin_key == DEV_ADMIN_KEY:
            active.append("ACP_ADMIN_KEY")
        if self.signing_key == DEV_SIGNING_KEY:
            active.append("ACP_SIGNING_KEY")
        return active

    def validate(self) -> None:
        """Refuse credentials that would let anyone forge mandates or admin calls.

        Development mode skips the checks so a local run needs no configuration.
        """
        if self.dev_mode:
            return
        if self.insecure_defaults:
            raise ConfigurationError(
                f"{', '.join(self.insecure_defaults)} still carry the published "
                "development value; set real keys or ACP_DEV_MODE=1 for local use"
            )
        if len(self.signing_key.encode("utf-8")) < MIN_SIGNING_KEY_BYTES:
            raise ConfigurationError(
                f"ACP_SIGNING_KEY must be at least {MIN_SIGNING_KEY_BYTES} bytes"
            )
        if len(self.admin_key.encode("utf-8")) < MIN_ADMIN_KEY_BYTES:
            raise ConfigurationError(
                f"ACP_ADMIN_KEY must be at least {MIN_ADMIN_KEY_BYTES} bytes"
            )
