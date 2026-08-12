from __future__ import annotations

import os
from dataclasses import dataclass


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
            admin_key=os.getenv("ACP_ADMIN_KEY", "dev-admin-key"),
            signing_key=os.getenv("ACP_SIGNING_KEY", "dev-signing-key-change-before-production"),
            issuer=os.getenv("ACP_ISSUER", "agent-control-plane"),
        )
