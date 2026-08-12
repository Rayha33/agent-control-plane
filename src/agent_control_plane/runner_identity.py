"""Authenticated runner identities.

Before this module, ``agent_id`` and ``reviewer_id`` were self-asserted
strings. ``run_qc`` decided whether a reviewer was independent by comparing
``reviewer_id`` to a value from ``acp.toml`` and to the submission's
``worker_agent_id`` — so anything able to call the supervisor could review its
own work simply by passing the critic's name. The no-self-approval invariant
rested on a string literal.

A runner now proves possession of a high-entropy credential that only its
holder has. Distinctness becomes a property of key material rather than of a
name: a worker cannot review its own submission because it cannot produce the
critic's secret, whatever identity string it supplies.

Storage follows password practice — the database keeps only a SHA-256 digest,
so the supervisor's state file never contains a usable credential. Comparison
is constant-time.

Deliberate limitation, stated rather than papered over: this is a bearer
credential, so it authenticates the holder to a *local* supervisor but is
replayable by anything that observes it in transit. Remote runners over an
untrusted network need asymmetric identities (Ed25519 assertions over a nonce),
which requires the ``cryptography`` dependency this project does not currently
take. The registry below is deliberately shaped so that swapping the verifier
is a local change: roles, revocation, and the call sites do not move.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

ROLES: tuple[str, ...] = ("worker", "critic", "integrator")

# 32 bytes of urandom, hex-encoded.
CREDENTIAL_BYTES = 32


class IdentityError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class RunnerIdentity:
    agent_id: str
    role: str
    credential_digest: str
    created_at: str
    revoked_at: str | None

    @property
    def revoked(self) -> bool:
        return self.revoked_at is not None


def issue_credential() -> str:
    """Generate a credential. Returned once; only its digest is persisted."""
    return secrets.token_hex(CREDENTIAL_BYTES)


def credential_digest(credential: str) -> str:
    return hashlib.sha256(credential.encode("utf-8")).hexdigest()


def verify_credential(credential: str, digest: str) -> bool:
    """Constant-time check so a wrong credential leaks no timing signal."""
    return hmac.compare_digest(credential_digest(credential), digest)


def validate_role(role: str) -> str:
    if role not in ROLES:
        raise IdentityError(
            "invalid_role", f"unknown runner role {role!r}; expected one of {', '.join(ROLES)}"
        )
    return role


def assert_distinct(worker_agent_id: str, reviewer_agent_id: str) -> None:
    """Reject self-review at the identity layer.

    Kept separate from credential verification so the two failures are
    distinguishable: 'you are not who you say' and 'you may not review your own
    work' are different findings.
    """

    if worker_agent_id == reviewer_agent_id:
        raise IdentityError(
            "self_review_forbidden", "worker cannot review its own submission"
        )
