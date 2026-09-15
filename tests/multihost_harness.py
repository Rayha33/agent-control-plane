"""Multi-process race harness for board #568.

Each spawned process builds its own ``Database`` and ``CoordinationService`` against one
PostgreSQL server and shares nothing else with the others: no memory, no connection, no
Python lock. That is what a second API replica on another host looks like to the storage
layer, which is the layer whose serialisation is under test.

Kept out of the test module so ``multiprocessing``'s spawn start method can import the entry
points in a child without importing pytest's test collection.
"""

from __future__ import annotations

import json
import random
import re
import time
from collections import Counter
from collections.abc import Iterable
from typing import Any

from agent_control_plane.config import Settings
from agent_control_plane.coordination import CoordinationService
from agent_control_plane.coordination_schemas import HeartbeatRequest, SubmissionCreate
from agent_control_plane.database import Database, StorageBusyError
from agent_control_plane.postgres_backend import PostgresConnection
from agent_control_plane.service import ControlPlaneError, ControlPlaneService

SIGNING_KEY = "test-signing-key-with-enough-entropy"
ISSUER = "test-control-plane"
LEASE_TTL = 2

_MUTATING = re.compile(r"^\s*(INSERT|UPDATE|DELETE)\b", re.IGNORECASE)


def settings(url: str) -> Settings:
    return Settings(
        database_path=url, admin_key="test-admin", signing_key=SIGNING_KEY, issuer=ISSUER
    )


class SlowWriteConnection(PostgresConnection):
    """Sleeps before a transaction's first write, after its reads.

    Widens the read-then-write window so a missing serialisation shows up every time rather
    than occasionally. Used by the correct backend too, so the GREEN and RED runs differ only
    in the lock and isolation level.
    """

    write_delay_seconds = 0.05

    def execute(self, sql: str, parameters: Any = ()) -> Any:
        if _MUTATING.match(sql) and not getattr(self, "_delayed", False):
            self._delayed = True
            time.sleep(self.write_delay_seconds)
        return super().execute(sql, parameters)


class SlowWriteWithoutLock(SlowWriteConnection):
    """Known-broken: no advisory lock, READ COMMITTED. The control the race checks must catch."""

    def begin_write(self) -> None:
        if self._write:
            return
        import psycopg

        self._raw.autocommit = False
        self._raw.isolation_level = psycopg.IsolationLevel.READ_COMMITTED
        self._write = True


def open_host(
    url: str, connection_class: type[PostgresConnection] | None = None
) -> CoordinationService:
    database = Database(url)
    if connection_class is not None:
        database._backend.connection_class = connection_class
    return CoordinationService(database, ControlPlaneService(database, settings(url)))


def with_application_name(url: str, name: str) -> str:
    return f"{url}{'&' if '?' in url else '?'}application_name={name}"


# ------------------------------------------------------------------------------ bursts ----


def burst_worker(url, broken, token, commands, results, barrier) -> None:
    connection_class = SlowWriteWithoutLock if broken else SlowWriteConnection
    coordination = open_host(url, connection_class)
    while True:
        command = commands.get()
        if command is None:
            return
        round_id, task_id = command
        barrier.wait(timeout=120)
        try:
            claim = coordination.claim_task(task_id, token, 300)
        except ControlPlaneError as error:
            results.put((round_id, task_id, "lost", error.code, None))
        except StorageBusyError as error:
            results.put((round_id, task_id, "busy", error.code, None))
        except Exception as error:  # noqa: BLE001 - reported to the parent, which fails the test
            results.put((round_id, task_id, "error", repr(error), None))
        else:
            tokens = {
                lease["resource"]: lease["fencing_token"] for lease in claim["resource_leases"]
            }
            results.put((round_id, task_id, "won", claim["task"]["claim_fencing_token"], tokens))


# ------------------------------------------------------------------------------- chaos ----


def _record(out, **op: Any) -> None:
    out.write(json.dumps(op, sort_keys=True) + "\n")
    out.flush()


def _busy_outcome(error: StorageBusyError) -> str:
    # A lost session can die after COMMIT reached the server, so its outcome is unknown
    # ("info", in Jepsen's terms). A serialization failure or lock timeout never committed.
    return "info" if error.code == "storage_unavailable" else "fail"


def chaos_worker(url, token, agent_id, task_ids, deadline, seed, out_path) -> None:
    rng = random.Random(seed)
    coordination = open_host(with_application_name(url, "acp-race-worker"))
    with open(out_path, "w", encoding="utf-8") as out:
        while time.time() < deadline:
            task_id = rng.choice(task_ids)
            started = time.time()
            try:
                claim = coordination.claim_task(task_id, token, LEASE_TTL)
            except ControlPlaneError as error:
                _record(
                    out,
                    kind="claim",
                    outcome="fail",
                    code=error.code,
                    task_id=task_id,
                    agent_id=agent_id,
                    started=started,
                    finished=time.time(),
                )
                # Back off. A hot retry loop spends the run losing races (measured: 50,639
                # refusals against 19 claims) and starves the successes the checker reads.
                time.sleep(rng.uniform(0.02, 0.08))
                continue
            except StorageBusyError as error:
                _record(
                    out,
                    kind="claim",
                    outcome=_busy_outcome(error),
                    code=error.code,
                    task_id=task_id,
                    agent_id=agent_id,
                    started=started,
                    finished=time.time(),
                )
                continue
            claim_token = claim["task"]["claim_fencing_token"]
            version = claim["task"]["version"]
            tokens = {
                lease["resource"]: lease["fencing_token"] for lease in claim["resource_leases"]
            }
            expires_at = max(
                (lease["expires_at"] for lease in claim["resource_leases"]),
                default=claim["task"]["claim_expires_at"],
            )
            expires_at = claim["task"]["claim_expires_at"] or expires_at
            _record(
                out,
                kind="claim",
                outcome="ok",
                task_id=task_id,
                agent_id=agent_id,
                claim_token=claim_token,
                resources=tokens,
                expires_at=expires_at,
                started=started,
                finished=time.time(),
            )

            for beat in range(rng.randint(0, 3)):
                time.sleep(rng.uniform(0.2, 1.4))
                started = time.time()
                request = HeartbeatRequest.model_construct(
                    claim_fencing_token=claim_token,
                    resource_fencing_tokens=tokens,
                    ttl_seconds=LEASE_TTL,
                    checkpoint={"beat": beat},
                )
                try:
                    renewed = coordination.heartbeat(task_id, token, request)
                except ControlPlaneError as error:
                    _record(
                        out,
                        kind="heartbeat",
                        outcome="fail",
                        code=error.code,
                        task_id=task_id,
                        agent_id=agent_id,
                        started=started,
                        finished=time.time(),
                    )
                    break
                except StorageBusyError as error:
                    _record(
                        out,
                        kind="heartbeat",
                        outcome=_busy_outcome(error),
                        code=error.code,
                        task_id=task_id,
                        agent_id=agent_id,
                        started=started,
                        finished=time.time(),
                    )
                    break
                expires_at = renewed["expires_at"]
                _record(
                    out,
                    kind="heartbeat",
                    outcome="ok",
                    task_id=task_id,
                    agent_id=agent_id,
                    expires_at=expires_at,
                    started=started,
                    finished=time.time(),
                )

            if rng.random() < 0.4:
                # A delayed runner: stall until its lease is certainly over, then try to submit
                # the work it still believes it owns.
                while time.time() <= expires_at + 0.25:
                    time.sleep(0.05)
                started = time.time()
                request = SubmissionCreate.model_construct(
                    task_version=version,
                    claim_fencing_token=claim_token,
                    resource_fencing_tokens=tokens,
                    base_revision="main@late",
                    artifact_uri=f"patch://{task_id}/late",
                    artifact_hash="a" * 64,
                    summary="submitted after the lease ended",
                    evidence=[],
                )
                try:
                    coordination.submit(task_id, token, request)
                except ControlPlaneError as error:
                    outcome, code = "fail", error.code
                except StorageBusyError as error:
                    outcome, code = _busy_outcome(error), error.code
                else:
                    outcome, code = "ok", None
                _record(
                    out,
                    kind="submit",
                    outcome=outcome,
                    code=code,
                    task_id=task_id,
                    agent_id=agent_id,
                    claim_token=claim_token,
                    started=started,
                    finished=time.time(),
                )


def nemesis(admin_url, url, deadline, seed, out_path) -> None:
    """Terminates live worker sessions (a connection partition) and reaps expired claims."""

    import psycopg

    rng = random.Random(seed)
    reaper = open_host(with_application_name(url, "acp-race-reaper"))
    with (
        psycopg.connect(admin_url, autocommit=True) as admin,
        open(out_path, "w", encoding="utf-8") as out,
    ):
        while time.time() < deadline:
            time.sleep(rng.uniform(0.1, 0.4))
            pids = [
                row[0]
                for row in admin.execute(
                    "SELECT pid FROM pg_stat_activity "
                    "WHERE application_name = 'acp-race-worker' AND state <> 'idle'"
                ).fetchall()
            ]
            if pids:
                hit = admin.execute(
                    "SELECT pg_terminate_backend(%s)", (rng.choice(pids),)
                ).fetchone()[0]
                _record(out, kind="kill", hit=bool(hit), at=time.time())
            try:
                report = reaper.reap_expired()
            except StorageBusyError as error:
                _record(out, kind="reap", outcome="info", code=error.code, at=time.time())
            else:
                _record(
                    out,
                    kind="reap",
                    outcome="ok",
                    orphaned=report["orphaned_task_ids"],
                    at=time.time(),
                )


def read_ops(paths: Iterable[str]) -> list[dict[str, Any]]:
    ops: list[dict[str, Any]] = []
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            ops.extend(json.loads(line) for line in handle if line.strip())
    return ops


# ----------------------------------------------------------------------------- checker ----


def check_history(
    events: list[dict[str, Any]],
    ops: list[dict[str, Any]],
    *,
    lease_ttl: int = LEASE_TTL,
) -> tuple[list[str], dict[str, int]]:
    """Replay the committed audit chain and compare it with what clients observed.

    ``events`` must be in chain (commit) order. Returns (violations, stats). The rules are
    exact for the chaos workload: every claim uses ``lease_ttl``, nothing is reviewed, and
    every submission is attempted only after its lease has ended.
    """

    violations: list[str] = []
    stats = {"claims": 0, "heartbeats": 0, "orphaned": 0, "reclaimed_after_orphan": 0}
    active: dict[str, dict[str, Any]] = {}  # task -> {agent, token, expires, resources}
    holders: dict[str, dict[str, Any]] = {}  # resource -> {task, expires}
    last_task_token: dict[str, int] = {}
    last_resource_token: dict[str, int] = {}
    orphaned_once: set[str] = set()

    for event in events:
        kind, payload, sequence = event["event_type"], event["payload"], event["sequence"]
        if kind == "task.claimed":
            stats["claims"] += 1
            task, agent = payload["task_id"], payload["agent_id"]
            token, expires = payload["claim_fencing_token"], payload["expires_at"]
            now = expires - lease_ttl
            if task in active:
                violations.append(f"#{sequence}: task {task} claimed while already claimed")
            if token <= last_task_token.get(task, 0):
                violations.append(f"#{sequence}: claim token for {task} did not increase")
            last_task_token[task] = token
            if task in orphaned_once:
                stats["reclaimed_after_orphan"] += 1
            for resource, resource_token in payload["resource_fencing_tokens"].items():
                if resource_token <= last_resource_token.get(resource, 0):
                    violations.append(f"#{sequence}: fencing token for {resource} did not increase")
                last_resource_token[resource] = resource_token
                holder = holders.get(resource)
                if holder and holder["task"] != task and holder["expires"] > now:
                    violations.append(
                        f"#{sequence}: {task} leased {resource} while {holder['task']} held it "
                        f"until {holder['expires']} (claim time {now})"
                    )
                holders[resource] = {"task": task, "expires": expires}
            active[task] = {
                "agent": agent,
                "token": token,
                "expires": expires,
                "resources": set(payload["resource_fencing_tokens"]),
            }
        elif kind == "task.heartbeat":
            stats["heartbeats"] += 1
            task, agent, expires = payload["task_id"], payload["agent_id"], payload["expires_at"]
            current = active.get(task)
            if current is None or current["agent"] != agent:
                violations.append(
                    f"#{sequence}: heartbeat on {task} by a runner that does not hold it"
                )
                continue
            if current["expires"] <= expires - lease_ttl:
                violations.append(f"#{sequence}: heartbeat revived an expired claim on {task}")
            current["expires"] = expires
            for resource in current["resources"]:
                holders[resource] = {"task": task, "expires": expires}
        elif kind == "coordination.reaped":
            for task in payload["orphaned_task_ids"]:
                stats["orphaned"] += 1
                current = active.pop(task, None)
                if current is None:
                    violations.append(f"#{sequence}: reaper orphaned {task}, which was not claimed")
                    continue
                orphaned_once.add(task)
                for resource in current["resources"]:
                    if holders.get(resource, {}).get("task") == task:
                        holders.pop(resource)
        elif kind == "submission.created":
            violations.append(
                f"#{sequence}: {payload['worker_agent_id']} submitted {payload['task_id']} "
                "after its lease had ended"
            )

    # Counters, not sets: two heartbeats by one runner inside the same second carry the same
    # expires_at, and collapsing them would report more acknowledged writes than committed.
    claim_events = Counter(
        (e["payload"]["task_id"], e["payload"]["agent_id"], e["payload"]["claim_fencing_token"])
        for e in events
        if e["event_type"] == "task.claimed"
    )
    heartbeat_events = Counter(
        (e["payload"]["task_id"], e["payload"]["agent_id"], e["payload"]["expires_at"])
        for e in events
        if e["event_type"] == "task.heartbeat"
    )
    committed = {"claim": sum(claim_events.values()), "heartbeat": sum(heartbeat_events.values())}
    by_kind: dict[tuple[str, str], int] = {}
    matched = {"claim": 0, "heartbeat": 0}
    for op in ops:
        key = (op["kind"], op.get("outcome", ""))
        by_kind[key] = by_kind.get(key, 0) + 1
        if op["kind"] == "claim" and op["outcome"] == "ok":
            event = (op["task_id"], op["agent_id"], op["claim_token"])
            if claim_events[event] > 0:
                # Consume it: a second acknowledged write needs a SECOND committed event.
                claim_events[event] -= 1
                matched["claim"] += 1
            else:
                violations.append(f"client saw a claim of {op['task_id']} that never committed")
        if op["kind"] == "heartbeat" and op["outcome"] == "ok":
            event = (op["task_id"], op["agent_id"], op["expires_at"])
            if heartbeat_events[event] > 0:
                heartbeat_events[event] -= 1
                matched["heartbeat"] += 1
            else:
                violations.append(f"client saw a heartbeat on {op['task_id']} that never committed")
        if op["kind"] == "submit" and op["outcome"] == "ok":
            violations.append(f"a delayed runner's submit of {op['task_id']} was accepted")

    for kind in ("claim", "heartbeat"):
        # A write that committed without the client being told must be covered by an
        # indeterminate op: those are the requests whose session died around the commit.
        unacknowledged = committed[kind] - matched[kind]
        if unacknowledged > by_kind.get((kind, "info"), 0):
            violations.append(
                f"{kind}: {committed[kind]} committed, {matched[kind]} acknowledged, "
                f"{by_kind.get((kind, 'info'), 0)} indeterminate"
            )

    for (kind, outcome), count in by_kind.items():
        stats[f"{kind}_{outcome}" if outcome else kind] = count
    return violations, stats
