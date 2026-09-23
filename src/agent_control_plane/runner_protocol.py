"""The runner's half of the heartbeat/termination protocol (board #568).

The authority fences a replaced runner out of every write it can see. What it cannot do is
stop the runner's own process, which may still be editing files, holding a port or talking to
a system the authority does not front. The runner has to stop itself, and it has to decide to
do so using only what it can observe locally, because the case that matters is the one where
it cannot reach the authority at all.

The rule :class:`LeaseKeeper` enforces
-------------------------------------
A runner may act only while it can show, BY ITS OWN MONOTONIC CLOCK, that its lease has not
ended. The lease is counted from when the renewing request was SENT, not when its reply
arrived: the authority granted ``ttl`` from the moment it processed the request, which is no
earlier than the send, so ``sent + ttl`` can never be later than the authority's own expiry.
Counting from the reply would let a slow round trip stretch the runner's belief past the
authority's, which is precisely the window in which a replacement is admitted. A safety margin
absorbs clock-rate differences between the two hosts.

Protocol
--------
- claim: the authority returns a lease (``ttl``) and an attempt token.
- heartbeat every ``ttl / 3``: success renews the lease from its send time and may return a
  fresh attempt token ("continue"). A fencing refusal — ``claim_inactive``,
  ``stale_claim_fencing_token``, ``stale_fencing_token``, ``attempt_token_expired`` — means the
  claim is gone (revoked, reaped or replaced): terminate NOW, reason ``replaced``.
- a transport failure is not a verdict: keep retrying, but terminate at the local deadline,
  reason ``lease_unconfirmed``. That happens before the authority can hand the work to anyone
  else, so the old runner has stopped before the new one starts.
- before every side effect the runner calls :meth:`LeaseKeeper.assert_may_act`, which also
  enforces the deadline, so a runner whose heartbeat thread was starved still cannot act late.

Termination is a callback (``on_terminate``) — killing a process group, cancelling a task —
because what "stop" means belongs to the runner.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

TERMINATE_CODES = frozenset(
    {
        "claim_inactive",
        "stale_claim_fencing_token",
        "stale_fencing_token",
        "incomplete_resource_fencing_tokens",
        "attempt_token_expired",
        "attempt_token_mismatch",
    }
)


class LeaseRevoked(Exception):
    """Raised by a renew callable when the authority refused the heartbeat on fencing grounds."""

    def __init__(self, code: str, message: str = ""):
        super().__init__(message or code)
        self.code = code


class LeaseLost(RuntimeError):
    def __init__(self, reason: str):
        super().__init__(f"lease lost: {reason}")
        self.reason = reason


@dataclass(frozen=True)
class Renewal:
    ttl_seconds: float
    attempt_token: str | None = None


def default_safety_margin(ttl_seconds: float) -> float:
    """10% of the lease, at least one second: covers a 10% clock-rate difference."""

    return max(1.0, ttl_seconds * 0.1)


class LeaseKeeper:
    def __init__(
        self,
        renew: Callable[[], Renewal],
        *,
        ttl_seconds: float,
        granted_at: float,
        attempt_token: str | None = None,
        safety_margin_seconds: float | None = None,
        clock: Callable[[], float] = time.monotonic,
        on_terminate: Callable[[str], None] | None = None,
        retry_seconds: float = 0.5,
    ):
        """``granted_at`` is ``clock()`` read just BEFORE the claim request was sent."""

        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._renew = renew
        self._clock = clock
        self._on_terminate = on_terminate
        self._retry_seconds = retry_seconds
        self._margin = (
            default_safety_margin(ttl_seconds)
            if safety_margin_seconds is None
            else safety_margin_seconds
        )
        if self._margin >= ttl_seconds:
            raise ValueError("the safety margin must be shorter than the lease")
        self._lock = threading.RLock()
        self._confirmed_at = granted_at
        self._ttl = ttl_seconds
        self._next_renewal = granted_at + ttl_seconds / 3
        self._attempt_token = attempt_token
        self.terminated_reason: str | None = None
        self.renewals = 0
        self.transport_failures = 0

    @property
    def deadline(self) -> float:
        with self._lock:
            return self._confirmed_at + self._ttl - self._margin

    @property
    def attempt_token(self) -> str | None:
        return self._attempt_token

    def terminate(self, reason: str) -> None:
        with self._lock:
            if self.terminated_reason is not None:
                return
            self.terminated_reason = reason
        if self._on_terminate is not None:
            self._on_terminate(reason)

    def assert_may_act(self) -> str | None:
        """Call before every side effect. Returns the current attempt token."""

        with self._lock:
            if self.terminated_reason is None and self._clock() >= self.deadline:
                pass_deadline = True
            else:
                pass_deadline = False
        if pass_deadline:
            self.terminate("lease_unconfirmed")
        if self.terminated_reason is not None:
            raise LeaseLost(self.terminated_reason)
        return self._attempt_token

    def tick(self) -> str:
        """Advance the protocol once. Returns running, renewed, retrying or the termination reason."""

        if self.terminated_reason is not None:
            return self.terminated_reason
        now = self._clock()
        if now >= self.deadline:
            self.terminate("lease_unconfirmed")
            return "lease_unconfirmed"
        if now < self._next_renewal:
            return "running"
        sent = self._clock()
        try:
            renewal = self._renew()
        except LeaseRevoked as refusal:
            self.terminate("replaced")
            return f"replaced:{refusal.code}"
        except Exception:  # noqa: BLE001 - any transport failure is "no answer", not "no lease"
            self.transport_failures += 1
            self._next_renewal = self._clock() + self._retry_seconds
            if self._clock() >= self.deadline:
                self.terminate("lease_unconfirmed")
                return "lease_unconfirmed"
            return "retrying"
        with self._lock:
            if self.terminated_reason is not None:
                # A reply that lands after the keeper gave up does not resurrect the runner.
                return self.terminated_reason
            self._confirmed_at = sent
            self._ttl = renewal.ttl_seconds
            self._next_renewal = sent + renewal.ttl_seconds / 3
            if renewal.attempt_token:
                self._attempt_token = renewal.attempt_token
            self.renewals += 1
        return "renewed"

    def run(self, stop: threading.Event, poll_seconds: float = 0.1) -> str:
        """Blocking loop for a heartbeat thread."""

        while not stop.is_set():
            outcome = self.tick()
            if self.terminated_reason is not None:
                return outcome
            stop.wait(poll_seconds)
        return "stopped"


def http_renewer(
    post: Callable[..., object],
    *,
    task_id: str,
    bearer_token: str,
    claim_fencing_token: int,
    resource_fencing_tokens: dict[str, int],
    ttl_seconds: int,
    attempt_token_ref: Callable[[], str | None] | None = None,
) -> Callable[[], Renewal]:
    """A renew callable over the reference HTTP API (``post`` is e.g. ``httpx.Client.post``)."""

    def renew() -> Renewal:
        body: dict[str, object] = {
            "claim_fencing_token": claim_fencing_token,
            "resource_fencing_tokens": resource_fencing_tokens,
            "ttl_seconds": ttl_seconds,
        }
        token = attempt_token_ref() if attempt_token_ref else None
        if token:
            body["attempt_token"] = token
        response = post(
            f"/v1/tasks/{task_id}/heartbeat",
            headers={"Authorization": f"Bearer {bearer_token}"},
            json=body,
        )
        status = response.status_code  # type: ignore[attr-defined]
        if status == 200:
            payload = response.json()  # type: ignore[attr-defined]
            return Renewal(ttl_seconds=ttl_seconds, attempt_token=payload.get("attempt_token"))
        code = ""
        try:
            code = response.json().get("error", "")  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            pass
        if code in TERMINATE_CODES:
            raise LeaseRevoked(code)
        raise ConnectionError(f"heartbeat returned {status} {code}".strip())

    return renew


__all__ = [
    "TERMINATE_CODES",
    "LeaseKeeper",
    "LeaseLost",
    "LeaseRevoked",
    "Renewal",
    "default_safety_margin",
    "http_renewer",
]
