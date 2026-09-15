"""Board #568 acceptance: Jepsen-style races across processes that share only PostgreSQL.

Spawned processes stand in for hosts (see ``multihost_harness``). Two experiments:

1. **Bursts.** Six processes release together on a barrier and claim tasks whose write sets
   overlap along a chain (a+b, b+c, c+d, d, a), two of them contending for the same task.
   Every round must have exactly one winner per task and pairwise-disjoint winning write
   sets. The same experiment against a backend with the lock and SERIALIZABLE removed must
   FAIL, which is what makes the green run evidence.

2. **Chaos history.** Processes claim, heartbeat and stall for random intervals while a
   nemesis terminates their live database sessions mid-request and reaps expired claims.
   Some runners stall past their lease and then submit. Afterwards the committed audit
   chain is replayed and compared with every client-observed outcome: no task held twice,
   no overlapping live lease, strictly increasing fencing tokens, no acknowledged write
   missing from the chain, no committed write beyond the indeterminate ones, and no
   submission from a delayed runner. A second test feeds the checker corrupted histories so
   its silence on the real one means something.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import shutil
import time
from itertools import combinations
from pathlib import Path

import multihost_harness as harness
import pytest

from agent_control_plane.app import create_app
from agent_control_plane.coordination_schemas import TaskCreate
from agent_control_plane.schemas import AgentCreate, MandateCreate, Scope

pytestmark = pytest.mark.postgres_backend

EVIDENCE_ENV = "ACP_RACE_EVIDENCE_DIR"
CHAIN = [("a", "b"), ("b", "c"), ("c", "d"), ("d",), ("a",)]
ASSIGNMENT = [0, 0, 1, 2, 3, 4]  # process -> task index; processes 0 and 1 contend for one task


def _workers(app, count: int) -> list[tuple[str, str]]:
    service = app.state.service
    tokens = []
    for index in range(count):
        agent = service.create_agent(
            AgentCreate(name=f"host-{index}", owner="race@example.com", role="worker")
        )
        mandate = service.issue_mandate(
            MandateCreate(
                agent_id=agent["id"],
                subject=f"agent:{agent['id']}",
                scopes=[Scope(action="coordination.*", resource="task:*")],
                ttl_seconds=3600,
            )
        )
        tokens.append((agent["id"], mandate["token"]))
    return tokens


def _task(app, resources: list[str], title: str) -> str:
    created = app.state.coordination.create_task(
        TaskCreate(
            title=title,
            description="Race target.",
            acceptance_criteria=["exactly one owner"],
            resources=resources,
        )
    )
    return created["id"]


def _events(app) -> list[dict]:
    return list(reversed(app.state.database.audit_events(1_000_000)))


def _save_evidence(name: str, payload: dict) -> None:
    target = os.getenv(EVIDENCE_ENV)
    if target:
        Path(target).mkdir(parents=True, exist_ok=True)
        Path(target, name).write_text(json.dumps(payload, indent=2, sort_keys=True, default=str))


def _run_bursts(url: str, *, broken: bool, rounds: int) -> dict:
    app = create_app(harness.settings(url))
    workers = _workers(app, len(ASSIGNMENT))
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(len(ASSIGNMENT))
    results = context.Queue()
    commands = [context.Queue() for _ in ASSIGNMENT]
    processes = [
        context.Process(
            target=harness.burst_worker,
            args=(url, broken, token, commands[index], results, barrier),
            daemon=True,
        )
        for index, (_agent, token) in enumerate(workers)
    ]
    for process in processes:
        process.start()

    violations: list[str] = []
    outcomes: list[tuple] = []
    try:
        for round_id in range(rounds):
            tasks = []
            for index, names in enumerate(CHAIN):
                resources = [f"src/round-{round_id}/{name}.py" for name in names]
                tasks.append((_task(app, resources, f"r{round_id}-t{index}"), set(resources)))
            for process_index, queue in enumerate(commands):
                queue.put((round_id, tasks[ASSIGNMENT[process_index]][0]))
            round_outcomes = [results.get(timeout=180) for _ in ASSIGNMENT]
            outcomes.extend(round_outcomes)
            errors = [outcome for outcome in round_outcomes if outcome[2] == "error"]
            violations.extend(f"round {round_id}: worker raised {error[3]}" for error in errors)

            winners = [outcome for outcome in round_outcomes if outcome[2] == "won"]
            if not winners:
                violations.append(f"round {round_id}: no claim won (the race proved nothing)")
            won_tasks = [outcome[1] for outcome in winners]
            for task_id in set(won_tasks):
                if won_tasks.count(task_id) > 1:
                    violations.append(
                        f"round {round_id}: task {task_id} had {won_tasks.count(task_id)} winners"
                    )
            resources_by_task = dict(tasks)
            for left, right in combinations(winners, 2):
                if left[1] != right[1]:
                    shared = resources_by_task[left[1]] & resources_by_task[right[1]]
                    if shared:
                        violations.append(
                            f"round {round_id}: overlapping winners share {sorted(shared)}"
                        )
    finally:
        for queue in commands:
            queue.put(None)
        for process in processes:
            process.join(timeout=30)
            if process.is_alive():
                process.terminate()

    events = _events(app)
    chain_ok, checked, broken_at = app.state.database.verify_audit_chain()
    if not chain_ok:
        violations.append(f"audit chain forked or broke at sequence {broken_at} of {checked}")
    committed_claims = sum(1 for event in events if event["event_type"] == "task.claimed")
    acknowledged = sum(1 for outcome in outcomes if outcome[2] == "won")
    if committed_claims != acknowledged:
        violations.append(f"{committed_claims} claims committed but {acknowledged} acknowledged")
    return {
        "violations": violations,
        "rounds": rounds,
        "won": acknowledged,
        "lost": sum(1 for outcome in outcomes if outcome[2] == "lost"),
        "busy": sum(1 for outcome in outcomes if outcome[2] == "busy"),
        "lost_codes": sorted({outcome[3] for outcome in outcomes if outcome[2] == "lost"}),
    }


def test_overlapping_claims_across_processes_have_exactly_one_winner(postgres_url):
    report = _run_bursts(postgres_url, broken=False, rounds=12)
    _save_evidence("burst_green.json", report)
    assert report["violations"] == []
    assert report["busy"] == 0, "the write lock should make contention wait, never abort"
    assert report["won"] >= 12 * 2, report  # a+b or b+c... at least two disjoint winners per round
    assert {"task_unavailable", "resource_busy"} <= set(report["lost_codes"]), report


def test_control_the_same_bursts_without_the_lock_produce_double_winners(postgres_url):
    report = _run_bursts(postgres_url, broken=True, rounds=4)
    _save_evidence("burst_red_control.json", report)
    assert report["violations"], (
        "the burst check cannot see a missing lock, so its green run is not evidence"
    )


def test_chaos_history_keeps_every_lease_fenced(postgres_url, tmp_path):
    app = create_app(harness.settings(postgres_url))
    workers = _workers(app, 6)
    resources = [f"src/chaos/{name}.py" for name in "abcde"]
    shapes = [(0, 1), (1, 2), (2, 3), (3, 4), (4, 0), (0,), (2,), (1, 3), (0, 2, 4), (3,)]
    task_ids = [
        _task(app, [resources[i] for i in shape], f"chaos-{index}")
        for index, shape in enumerate(shapes)
    ]

    context = multiprocessing.get_context("spawn")
    deadline = time.time() + 5 + 14  # spawn start-up, then 14 seconds of traffic
    paths = [str(tmp_path / f"worker-{index}.jsonl") for index in range(len(workers))]
    processes = [
        context.Process(
            target=harness.chaos_worker,
            args=(postgres_url, token, agent_id, task_ids, deadline, 1000 + index, paths[index]),
            daemon=True,
        )
        for index, (agent_id, token) in enumerate(workers)
    ]
    nemesis_path = str(tmp_path / "nemesis.jsonl")
    base_url = os.environ["ACP_TEST_POSTGRES_URL"]
    processes.append(
        context.Process(
            target=harness.nemesis,
            args=(base_url, postgres_url, deadline, 7, nemesis_path),
            daemon=True,
        )
    )
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=120)
        assert process.exitcode == 0, f"{process.name} exited {process.exitcode}"

    # One final reap so claims left running at the deadline do not look like violations.
    time.sleep(harness.LEASE_TTL + 1)
    app.state.coordination.reap_expired()

    events = _events(app)
    ops = harness.read_ops(paths)
    nemesis_ops = harness.read_ops([nemesis_path])
    violations, stats = harness.check_history(events, ops)
    chain_ok, checked, broken_at = app.state.database.verify_audit_chain()
    stats["kills_hit"] = sum(1 for op in nemesis_ops if op["kind"] == "kill" and op["hit"])
    stats["events"] = checked
    replaced_zombies = sum(
        1
        for zombie in ops
        if zombie["kind"] == "submit"
        and any(
            other["kind"] == "claim"
            and other["outcome"] == "ok"
            and other["task_id"] == zombie["task_id"]
            and other["claim_token"] > zombie["claim_token"]
            and other["finished"] < zombie["started"]
            for other in ops
        )
    )
    stats["delayed_submits_after_replacement"] = replaced_zombies
    for path in [*paths, nemesis_path]:
        target = os.getenv(EVIDENCE_ENV)
        if target:
            Path(target).mkdir(parents=True, exist_ok=True)
            shutil.copy(path, Path(target, f"chaos_{Path(path).name}"))
    _save_evidence(
        "chaos_report.json", {"violations": violations, "stats": stats, "chain_ok": chain_ok}
    )

    assert chain_ok, f"audit chain broke at {broken_at}"
    assert violations == [], violations[:20]
    # Non-vacuity: the run must actually have exercised what it claims to prove. Thresholds are
    # what this workload reliably produces, measured, not what would be nice to see.
    assert stats["claim_ok"] >= 10, stats
    assert stats.get("claim_fail", 0) >= 10, stats
    assert stats["heartbeat_ok"] >= 5, stats
    assert stats["orphaned"] >= 3, stats
    # Replacements really happened: an orphaned task was claimed again by someone else.
    assert stats["reclaimed_after_orphan"] >= 3, stats
    assert stats["kills_hit"] >= 3, stats
    # Every delayed submission was refused. The checker also fails on any submission.created
    # event, so "none were accepted" is asserted from the committed chain as well as here.
    assert stats.get("submit_fail", 0) >= 3, stats
    assert stats.get("submit_ok", 0) == 0, stats


def _claim_event(sequence, task, agent, token, expires, resources):
    return {
        "sequence": sequence,
        "event_type": "task.claimed",
        "payload": {
            "task_id": task,
            "agent_id": agent,
            "claim_fencing_token": token,
            "expires_at": expires,
            "resource_fencing_tokens": resources,
        },
    }


def test_checker_flags_each_kind_of_corrupted_history():
    """RED control for check_history: every rule must be able to fire."""

    ttl = 2
    clean = [
        _claim_event(1, "t1", "a1", 1, 102, {"r": 1}),
        {
            "sequence": 2,
            "event_type": "task.heartbeat",
            "payload": {"task_id": "t1", "agent_id": "a1", "expires_at": 103},
        },
        {
            "sequence": 3,
            "event_type": "coordination.reaped",
            "payload": {"orphaned_task_ids": ["t1"]},
        },
        _claim_event(4, "t1", "a2", 2, 110, {"r": 2}),
    ]
    ok_ops = [
        {"kind": "claim", "outcome": "ok", "task_id": "t1", "agent_id": "a1", "claim_token": 1},
        {
            "kind": "heartbeat",
            "outcome": "ok",
            "task_id": "t1",
            "agent_id": "a1",
            "expires_at": 103,
        },
        {"kind": "claim", "outcome": "ok", "task_id": "t1", "agent_id": "a2", "claim_token": 2},
    ]
    violations, stats = harness.check_history(clean, ok_ops, lease_ttl=ttl)
    assert violations == [] and stats["reclaimed_after_orphan"] == 1

    corruptions = {
        "double claim": clean[:2] + [_claim_event(3, "t1", "a2", 2, 104, {"r": 2})],
        "overlapping lease": [
            _claim_event(1, "t1", "a1", 1, 102, {"r": 1}),
            _claim_event(2, "t2", "a2", 1, 103, {"r": 2}),
        ],
        "token did not increase": clean[:3] + [_claim_event(4, "t1", "a2", 1, 110, {"r": 1})],
        "heartbeat by non-holder": [
            clean[0],
            {
                "sequence": 2,
                "event_type": "task.heartbeat",
                "payload": {"task_id": "t1", "agent_id": "zz", "expires_at": 103},
            },
        ],
        "revived expired claim": [
            clean[0],
            {
                "sequence": 2,
                "event_type": "task.heartbeat",
                "payload": {"task_id": "t1", "agent_id": "a1", "expires_at": 105},
            },
        ],
        "late submission": clean
        + [
            {
                "sequence": 5,
                "event_type": "submission.created",
                "payload": {"task_id": "t1", "worker_agent_id": "a1"},
            }
        ],
    }
    for name, history in corruptions.items():
        found, _stats = harness.check_history(history, [], lease_ttl=ttl)
        assert found, f"checker missed: {name}"

    phantom = ok_ops + [
        {"kind": "claim", "outcome": "ok", "task_id": "t9", "agent_id": "a9", "claim_token": 7}
    ]
    assert harness.check_history(clean, phantom, lease_ttl=ttl)[0], (
        "checker missed a phantom success"
    )
    unacknowledged = ok_ops[:2]
    assert harness.check_history(clean, unacknowledged, lease_ttl=ttl)[0], (
        "checker missed a committed claim the client was told had failed"
    )
    accepted_zombie = ok_ops + [{"kind": "submit", "outcome": "ok", "task_id": "t1"}]
    assert harness.check_history(clean, accepted_zombie, lease_ttl=ttl)[0], (
        "checker missed an accepted late submit"
    )
