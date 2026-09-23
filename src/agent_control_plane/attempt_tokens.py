"""Signed attempt tokens: a claim's generation, checkable on a host with no database access.

Board #568. Inside the authority, fencing is a database comparison: a submission's claim token
and resource tokens must equal the live rows. A resource on ANOTHER host (a deploy API, an
artifact registry, a schema migrator) cannot run that query. It needs something it can check
on its own: which task, which runner, which generation of each resource, and until when. An
attempt token is exactly that, minted by the authority when a claim or heartbeat commits.

Properties that matter
----------------------
- **Bound.** Task, agent, claim generation, every resource generation and lease expiry are
  signed together. A token cannot be moved to another task, another runner or another
  generation, and ``exp`` is the lease expiry the authority committed, so a stalled runner's
  token dies with its lease.
- **Domain-separated.** Tokens are HS256 JWTs signed with a key DERIVED from the deployment
  signing key (HMAC-SHA256 over a fixed context string), never the key itself. Mandates are
  signed with the raw key, so a mandate can never verify as an attempt token or the reverse;
  on top of that, attempt tokens carry an audience that mandate verification rejects. A
  gateway is provisioned with the derived key only, which cannot mint mandates.
- **Clock-explicit.** Expiry is checked against an injected clock with an explicit leeway, so
  a gateway's tolerance for skew is a visible setting rather than library behaviour.

Stated limitation: the derived key is symmetric, so anything that can verify a token can also
mint one. That is sufficient against delayed, partitioned and confused runners, which is this
row's threat. It is not sufficient against a compromised gateway; that needs asymmetric
workload identity (Ed25519), which requires the ``cryptography`` dependency this project has
deliberately not taken on. The verifier is the only thing that would change.
"""

from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import jwt

ATTEMPT_TOKEN_AUDIENCE = "acp:attempt"
ATTEMPT_TOKEN_TYPE = "acp-attempt+jwt"
_KEY_CONTEXT = b"agent-control-plane attempt token v1"
_REQUIRED_CLAIMS = ["iss", "aud", "sub", "tid", "cft", "rft", "iat", "exp", "jti"]


class AttemptTokenError(ValueError):
    """``code`` is one of attempt_token_invalid, attempt_token_expired."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class AttemptClaims:
    task_id: str
    agent_id: str
    claim_fencing_token: int
    resource_fencing_tokens: dict[str, int]
    issued_at: int
    expires_at: int
    token_id: str

    @property
    def holder(self) -> str:
        """One string naming this exact attempt: a gate compares it on an equal generation."""

        return f"{self.task_id}/{self.agent_id}/{self.claim_fencing_token}"


def derive_attempt_key(signing_key: str | bytes) -> bytes:
    raw = signing_key.encode("utf-8") if isinstance(signing_key, str) else signing_key
    return hmac.new(raw, _KEY_CONTEXT, hashlib.sha256).digest()


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


class AttemptTokenSigner:
    """Issues and verifies attempt tokens.

    Construct with the deployment signing key on the authority. A gateway that only verifies
    should use :meth:`from_attempt_key` with the derived key, so it never holds the key that
    mints mandates. ``previous_keys`` lets tokens minted before a key rotation verify until
    they expire; new tokens are always signed with the current key.
    """

    def __init__(
        self,
        attempt_key: bytes,
        issuer: str,
        *,
        previous_keys: Sequence[bytes] = (),
    ):
        if len(attempt_key) < 32:
            raise ValueError("attempt token key must be at least 32 bytes")
        self._key = attempt_key
        self._verify_keys = [attempt_key, *previous_keys]
        self.issuer = issuer

    @classmethod
    def from_signing_key(
        cls, signing_key: str, issuer: str, *, previous_signing_keys: Sequence[str] = ()
    ) -> AttemptTokenSigner:
        return cls(
            derive_attempt_key(signing_key),
            issuer,
            previous_keys=[derive_attempt_key(key) for key in previous_signing_keys],
        )

    @classmethod
    def from_attempt_key(cls, attempt_key: bytes, issuer: str) -> AttemptTokenSigner:
        return cls(attempt_key, issuer)

    def issue(
        self,
        *,
        task_id: str,
        agent_id: str,
        claim_fencing_token: int,
        resource_fencing_tokens: Mapping[str, int],
        expires_at: int,
        now: int | None = None,
    ) -> str:
        payload = {
            "iss": self.issuer,
            "aud": ATTEMPT_TOKEN_AUDIENCE,
            "sub": agent_id,
            "tid": task_id,
            "cft": int(claim_fencing_token),
            "rft": {str(key): int(value) for key, value in resource_fencing_tokens.items()},
            "iat": int(time.time()) if now is None else int(now),
            "exp": int(expires_at),
            "jti": str(uuid.uuid4()),
        }
        return jwt.encode(
            payload, self._key, algorithm="HS256", headers={"typ": ATTEMPT_TOKEN_TYPE}
        )

    def verify(
        self,
        token: str,
        *,
        now: float | None = None,
        leeway_seconds: float = 0.0,
    ) -> AttemptClaims:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as error:
            raise AttemptTokenError(
                "attempt_token_invalid", "attempt token is malformed"
            ) from error
        if header.get("typ") != ATTEMPT_TOKEN_TYPE or header.get("alg") != "HS256":
            raise AttemptTokenError("attempt_token_invalid", "token is not an attempt token")

        payload: dict[str, Any] | None = None
        for key in self._verify_keys:
            try:
                payload = jwt.decode(
                    token,
                    key,
                    algorithms=["HS256"],
                    audience=ATTEMPT_TOKEN_AUDIENCE,
                    issuer=self.issuer,
                    # Expiry is checked below against the caller's clock, not the library's.
                    options={"require": _REQUIRED_CLAIMS, "verify_exp": False, "verify_iat": False},
                )
                break
            except jwt.InvalidSignatureError:
                continue
            except jwt.PyJWTError as error:
                raise AttemptTokenError(
                    "attempt_token_invalid", f"attempt token rejected: {type(error).__name__}"
                ) from error
        if payload is None:
            raise AttemptTokenError("attempt_token_invalid", "attempt token signature is invalid")

        resources = payload["rft"]
        if (
            not isinstance(payload["tid"], str)
            or not isinstance(payload["sub"], str)
            or not _is_int(payload["cft"])
            or payload["cft"] < 1
            or not _is_int(payload["exp"])
            or not isinstance(resources, dict)
            or not all(isinstance(k, str) and _is_int(v) for k, v in resources.items())
        ):
            raise AttemptTokenError("attempt_token_invalid", "attempt token claims are malformed")

        current = time.time() if now is None else now
        if payload["exp"] <= current - leeway_seconds:
            raise AttemptTokenError(
                "attempt_token_expired", "the lease this attempt token vouched for has ended"
            )
        return AttemptClaims(
            task_id=payload["tid"],
            agent_id=payload["sub"],
            claim_fencing_token=payload["cft"],
            resource_fencing_tokens=dict(resources),
            issued_at=payload["iat"],
            expires_at=payload["exp"],
            token_id=payload["jti"],
        )


__all__ = [
    "ATTEMPT_TOKEN_AUDIENCE",
    "ATTEMPT_TOKEN_TYPE",
    "AttemptClaims",
    "AttemptTokenError",
    "AttemptTokenSigner",
    "derive_attempt_key",
]
