"""Monotonic resource fencing on a host that cannot see the authority's database.

Board #568. :mod:`agent_control_plane.side_effects` fences mutations INSIDE the authority by
re-running the live claim predicate in the same transaction. A resource owned by another
system cannot do that, and a lease alone does not protect it: a runner that stalled (a GC
pause, a partition, a suspended laptop) wakes up still believing it holds the lease and
writes. The classic fix is a fencing token the resource itself compares — it remembers the
highest generation it has accepted for each resource and refuses anything older.

:class:`FencingGate` is that comparison, driven by a signed attempt token:

1. verify the token (signature, audience, issuer, expiry against this gate's clock);
2. the resource must be one the attempt leased; its generation comes from the token, never
   from the caller;
3. atomically: a NEWER generation raises the high-water mark and is admitted; the SAME
   generation is admitted only for the same attempt; anything else is refused.

What fences a delayed runner, and when
--------------------------------------
- After the replacement's first write through this gate: always. The high-water mark has
  moved past the old generation, whatever the clocks say.
- Before it: the old token's ``exp`` (the lease expiry the authority committed) does. The
  authority only lets a replacement claim a resource once that lease has expired or been
  released, and a revoked claim keeps its resources reserved until its last token expires,
  so by the time a replacement exists the old token is already expired — PROVIDED the gate's
  clock is within ``leeway_seconds`` of the authority's. A gate with a badly skewed clock can
  admit one stale write in that window. That is the irreducible cost of fencing without a
  round trip, and why ``leeway_seconds`` is explicit.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from .attempt_tokens import AttemptClaims, AttemptTokenError, AttemptTokenSigner
from .database import Database, utc_now


class FencingError(PermissionError):
    """``code``: resource_not_leased, stale_fencing_token, fencing_generation_conflict,
    or an :class:`AttemptTokenError` code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Advance:
    admitted: bool
    high_water: int
    holder: str


class HighWaterStore(Protocol):
    def advance(self, resource: str, generation: int, holder: str) -> Advance: ...


def _decide(current: tuple[int, str] | None, generation: int, holder: str) -> Advance:
    if current is None or generation > current[0]:
        return Advance(True, generation, holder)
    if generation == current[0] and holder == current[1]:
        return Advance(True, generation, holder)
    return Advance(False, current[0], current[1])


class MemoryHighWaterStore:
    """For a single gate process. Lost on restart, which re-opens the pre-first-write window."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._marks: dict[str, tuple[int, str]] = {}

    def advance(self, resource: str, generation: int, holder: str) -> Advance:
        with self._lock:
            decision = _decide(self._marks.get(resource), generation, holder)
            if decision.admitted:
                self._marks[resource] = (decision.high_water, decision.holder)
            return decision


HIGH_WATER_SCHEMA = """
CREATE TABLE IF NOT EXISTS fencing_high_water (
    resource TEXT PRIMARY KEY,
    generation INTEGER NOT NULL,
    holder TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


class DatabaseHighWaterStore:
    """Durable, and shared by every replica of a gate that points at the same database.

    Works on SQLite and PostgreSQL. The read and the write share one write transaction, so
    two replicas admitting different generations at once cannot both win.
    """

    def __init__(self, database: Database):
        self.database = database
        with database.connect() as connection:
            connection.executescript(HIGH_WATER_SCHEMA)

    def advance(self, resource: str, generation: int, holder: str) -> Advance:
        with self.database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT generation, holder FROM fencing_high_water WHERE resource = ?",
                (resource,),
            ).fetchone()
            decision = _decide(None if row is None else (row[0], row[1]), generation, holder)
            if decision.admitted and (row is None or generation != row[0]):
                connection.execute(
                    """
                    INSERT INTO fencing_high_water (resource, generation, holder, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT (resource) DO UPDATE SET
                        generation = excluded.generation,
                        holder = excluded.holder,
                        updated_at = excluded.updated_at
                    """,
                    (resource, generation, holder, utc_now()),
                )
            return decision


@dataclass(frozen=True)
class Admission:
    resource: str
    generation: int
    claims: AttemptClaims


class FencingGate:
    def __init__(
        self,
        verifier: AttemptTokenSigner,
        store: HighWaterStore,
        *,
        clock: Callable[[], float] = time.time,
        leeway_seconds: float = 0.0,
    ):
        self.verifier = verifier
        self.store = store
        self.clock = clock
        self.leeway_seconds = leeway_seconds

    def admit(self, attempt_token: str, resource: str) -> Admission:
        try:
            claims = self.verifier.verify(
                attempt_token, now=self.clock(), leeway_seconds=self.leeway_seconds
            )
        except AttemptTokenError as error:
            raise FencingError(error.code, error.message) from error
        if resource not in claims.resource_fencing_tokens:
            raise FencingError(
                "resource_not_leased", f"attempt {claims.holder} did not lease {resource}"
            )
        generation = claims.resource_fencing_tokens[resource]
        decision = self.store.advance(resource, generation, claims.holder)
        if not decision.admitted:
            if generation == decision.high_water:
                raise FencingError(
                    "fencing_generation_conflict",
                    f"generation {generation} of {resource} belongs to {decision.holder}",
                )
            raise FencingError(
                "stale_fencing_token",
                f"generation {generation} of {resource} is older than {decision.high_water}",
            )
        return Admission(resource, generation, claims)


__all__ = [
    "HIGH_WATER_SCHEMA",
    "Admission",
    "Advance",
    "DatabaseHighWaterStore",
    "FencingError",
    "FencingGate",
    "HighWaterStore",
    "MemoryHighWaterStore",
]
