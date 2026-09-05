from __future__ import annotations

import os
from dataclasses import dataclass

# The values that used to be the DEFAULTS. They are published in a public repository, so
# anyone who can read GitHub holds them. They are named here so the checks below can
# recognise them and refuse, rather than silently accepting a key that is not a secret.
DEV_ADMIN_KEY = "dev-admin-key"
DEV_SIGNING_KEY = "dev-signing-key-change-before-production"

# HS256 mandates are only as strong as the key behind them. 32 bytes matches the hash
# output size; anything shorter adds no security over a shorter digest.
MINIMUM_SIGNING_KEY_BYTES = 32

INSECURE_DEV_ENV = "ACP_INSECURE_DEV"


class InsecureSettingsError(RuntimeError):
    """The control plane would have started with credentials that are not secret.

    Raised by :meth:`Settings.from_env` instead of falling back to a published default.
    This exists because the previous behaviour failed OPEN on the most common mistake:
    `uvicorn agent_control_plane.app:create_app --factory` with no environment exported
    started a server whose admin key was a string in the public README, granting
    /v1/agents, /v1/policies, /v1/audit, /v1/tasks, reap and approvals to anyone who had
    read the repository — and letting them mint valid HS256 mandates.

    In a system whose whole claim is that it fails closed, the reference HTTP layer must
    not be the part that fails open.
    """


@dataclass(frozen=True)
class Settings:
    database_path: str
    admin_key: str
    signing_key: str
    issuer: str = "agent-control-plane"
    # True only when the operator explicitly asked for the published dev credentials.
    # Surfaced on /health so a server running this way cannot look like a secure one.
    insecure_dev: bool = False

    @classmethod
    def from_env(cls) -> Settings:
        """Build settings from the environment, refusing insecure credentials.

        Set ACP_INSECURE_DEV=1 to opt into the published development keys for local
        work. That is deliberately an explicit action with a visible marker rather than
        a default, so "I forgot to export the keys" and "I meant to run insecurely"
        cannot look identical from the outside.
        """
        insecure_dev = os.getenv(INSECURE_DEV_ENV, "") == "1"
        admin_key = os.getenv("ACP_ADMIN_KEY", "")
        signing_key = os.getenv("ACP_SIGNING_KEY", "")

        if insecure_dev:
            admin_key = admin_key or DEV_ADMIN_KEY
            signing_key = signing_key or DEV_SIGNING_KEY
        else:
            problems = _credential_problems(admin_key, signing_key)
            if problems:
                raise InsecureSettingsError(
                    "refusing to start the agent control plane with insecure credentials:\n"
                    + "\n".join(f"  - {problem}" for problem in problems)
                    + "\n\nExport real secrets, for example:\n"
                    '  export ACP_ADMIN_KEY="$(openssl rand -hex 32)"\n'
                    '  export ACP_SIGNING_KEY="$(openssl rand -hex 32)"\n'
                    f"or set {INSECURE_DEV_ENV}=1 to accept the published development keys."
                )

        return cls(
            database_path=os.getenv("ACP_DATABASE_PATH", "agent_control_plane.db"),
            admin_key=admin_key,
            signing_key=signing_key,
            issuer=os.getenv("ACP_ISSUER", "agent-control-plane"),
            insecure_dev=insecure_dev,
        )


def _credential_problems(admin_key: str, signing_key: str) -> list[str]:
    """Every reason these credentials are unfit, so the operator sees them all at once."""
    problems: list[str] = []

    if not admin_key:
        problems.append("ACP_ADMIN_KEY is not set")
    elif admin_key == DEV_ADMIN_KEY:
        problems.append("ACP_ADMIN_KEY is the published development key, which is not a secret")

    if not signing_key:
        problems.append("ACP_SIGNING_KEY is not set")
    elif signing_key == DEV_SIGNING_KEY:
        problems.append("ACP_SIGNING_KEY is the published development key, which is not a secret")
    elif len(signing_key.encode("utf-8")) < MINIMUM_SIGNING_KEY_BYTES:
        problems.append(
            f"ACP_SIGNING_KEY is shorter than {MINIMUM_SIGNING_KEY_BYTES} bytes, "
            "which is weaker than the HS256 digest it protects"
        )

    return problems
