from __future__ import annotations

import time
import uuid
from typing import Any

import jwt


class TokenError(ValueError):
    pass


def issue_token(
    *,
    signing_key: str,
    issuer: str,
    agent_id: str,
    mandate_id: str,
    subject: str,
    scopes: list[dict[str, str]],
    expires_at: int,
) -> str:
    now = int(time.time())
    payload = {
        "iss": issuer,
        "sub": agent_id,
        "actor": subject,
        "mid": mandate_id,
        "scopes": scopes,
        "iat": now,
        "exp": expires_at,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, signing_key, algorithm="HS256")


def decode_token(*, token: str, signing_key: str, issuer: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=["HS256"],
            issuer=issuer,
            options={"require": ["exp", "iat", "iss", "sub", "mid", "scopes"]},
        )
    except jwt.PyJWTError as exc:
        raise TokenError("invalid or expired mandate token") from exc
    if not isinstance(payload.get("scopes"), list):
        raise TokenError("mandate token has invalid scopes")
    return payload
