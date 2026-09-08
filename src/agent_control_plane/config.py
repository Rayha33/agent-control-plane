from __future__ import annotations

import os
from dataclasses import dataclass

# Built-in development credentials. They are deliberately obvious, and create_app
# logs a warning whenever either one is still in use.
DEV_ADMIN_KEY = "dev-admin-key"
DEV_SIGNING_KEY = "dev-signing-key-change-before-production"


@dataclass(frozen=True)
class Settings:
    database_path: str
    admin_key: str
    signing_key: str
    issuer: str = "agent-control-plane"

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            database_path=os.getenv("ACP_DATABASE_PATH", "agent_control_plane.db"),
            admin_key=os.getenv("ACP_ADMIN_KEY", DEV_ADMIN_KEY),
            signing_key=os.getenv("ACP_SIGNING_KEY", DEV_SIGNING_KEY),
            issuer=os.getenv("ACP_ISSUER", "agent-control-plane"),
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
