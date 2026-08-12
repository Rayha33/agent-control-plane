from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Sequence
from typing import Any

from .git_supervisor import GitSupervisor, SupervisorError
from .status import DEFAULT_LEASE_RISK_SECONDS


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="acp",
        description="Concurrency control and independent QC for AI coding agents.",
    )
    root.add_argument("--repo", default=".", help="path inside the Git repository")
    commands = root.add_subparsers(dest="action", required=True)
    commands.add_parser("init", help="initialize config and local state")
    commands.add_parser("doctor", help="check repository and state integrity")
    commands.add_parser("list", help="list tasks")
    commands.add_parser("reap", help="orphan expired attempts without deleting work")
    commands.add_parser("verify-events", help="verify the hash-chained event log")

    add = commands.add_parser("task-add", help="create a resource-scoped task")
    add.add_argument("--title", required=True)
    add.add_argument("--description", default="")
    add.add_argument("--accept", action="append", required=True, dest="acceptance")
    add.add_argument("--resource", action="append", required=True, dest="resources")
    add.add_argument("--depends-on", action="append", default=[], dest="dependencies")
    add.add_argument(
        "--produces",
        action="append",
        default=[],
        dest="produces",
        help="logical artifact this task publishes for other tasks",
    )
    add.add_argument(
        "--consumes",
        action="append",
        default=[],
        dest="consumes",
        help="logical artifact this task requires; its producers must finish first",
    )
    add.add_argument("--priority", type=int, default=50)
    add.add_argument("--base", default="HEAD", dest="base_branch")

    show = commands.add_parser("show", help="show a task")
    show.add_argument("task_id")
    plan = commands.add_parser("plan", help="dry-run a claim and report what would block it")
    plan.add_argument("task_id")
    commands.add_parser("queue", help="ordered ready queue with overlap and dependency blockers")
    commands.add_parser("merge-plan", help="integration ordering preview for approved work")
    commands.add_parser("reviewers", help="declared reviewers and the evaluation policy state")
    commands.add_parser(
        "ratify-reviewers", help="accept a changed reviewer policy so QC may run again"
    )
    calibrate = commands.add_parser(
        "calibrate", help="score a reviewer against repository golden cases"
    )
    calibrate.add_argument("--reviewer", dest="reviewer_id")
    bundle = commands.add_parser("bundle", help="show the reproduction bundle for a QC verdict")
    bundle.add_argument("qc_id")
    status = commands.add_parser("status", help="read-only operator view of every agent")
    status.add_argument("--limit", type=int, help="show at most this many tasks")
    status.add_argument("--format", choices=("json", "text"), default="json", dest="output_format")
    status.add_argument(
        "--lease-risk-seconds",
        type=int,
        default=DEFAULT_LEASE_RISK_SECONDS,
        help="flag an attempt whose lease expires within this many seconds",
    )
    status.add_argument("--watch", action="store_true", help="refresh until interrupted")
    status.add_argument("--interval", type=float, default=2.0, help="seconds between refreshes")
    status.add_argument(
        "--iterations",
        type=int,
        default=0,
        help="stop after this many refreshes (0 means run until interrupted)",
    )
    claim = commands.add_parser("claim", help="claim resources and create a worktree")
    claim.add_argument("task_id")
    claim.add_argument("--agent", required=True, dest="agent_id")
    claim.add_argument("--lease-seconds", type=int)
    heartbeat = commands.add_parser("heartbeat", help="renew a fenced attempt")
    heartbeat.add_argument("attempt_id")
    heartbeat.add_argument("--token", type=int, required=True, dest="claim_token")
    heartbeat.add_argument("--checkpoint", default="{}")
    heartbeat.add_argument("--lease-seconds", type=int)
    submit = commands.add_parser("submit", help="submit committed Git evidence")
    submit.add_argument("attempt_id")
    submit.add_argument("--token", type=int, required=True, dest="claim_token")
    qc = commands.add_parser("qc", help="run QC in a fresh detached worktree")
    qc.add_argument("submission_id")
    qc.add_argument("--reviewer", help="must match critic_identity in acp.toml")
    integrate = commands.add_parser("integrate", help="create a gated integration branch")
    integrate.add_argument("task_id")
    run = commands.add_parser("run", help="run an agent command in its worktree")
    run.add_argument("attempt_id")
    run.add_argument("--token", type=int, required=True, dest="claim_token")
    run.add_argument("command", nargs=argparse.REMAINDER)
    terminate = commands.add_parser("terminate", help="stop a supervised worker")
    terminate.add_argument("attempt_id")
    environment = commands.add_parser(
        "environment", help="show the isolated runtime assigned to an attempt"
    )
    environment.add_argument("attempt_id")
    runtime_down = commands.add_parser(
        "runtime-down", help="retry teardown and release an attempt runtime"
    )
    runtime_down.add_argument("attempt_id")
    runtime_down.add_argument(
        "--force",
        action="store_true",
        help="recover a teardown left in-progress by a crashed supervisor",
    )
    return root


def emit(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def watch_status(supervisor: GitSupervisor, args: Any) -> int:
    """Render the read-only status view once, or repeatedly under --watch.

    JSON stays canonical; --format text is a convenience rendering of the same
    snapshot. Ctrl-C ends a watch cleanly instead of raising.
    """
    iteration = 0
    try:
        while True:
            snapshot = supervisor.status(args.limit, args.lease_risk_seconds)
            if args.output_format == "text":
                print(supervisor.render_status(snapshot), flush=True)
            else:
                emit(snapshot)
            iteration += 1
            if not args.watch or (args.iterations and iteration >= args.iterations):
                return 0
            time.sleep(max(0.1, args.interval))
    except KeyboardInterrupt:
        return 0


def main(argv: Sequence[str] | None = None) -> int:
    root = parser()
    args = root.parse_args(argv)
    try:
        if args.action == "init":
            supervisor = GitSupervisor.initialize(args.repo)
            emit(
                {
                    "ok": True,
                    "repo": str(supervisor.root),
                    "config": str(supervisor.config_path),
                    "state": str(supervisor.state_dir),
                }
            )
            return 0
        supervisor = GitSupervisor(args.repo)
        if args.action == "doctor":
            result = supervisor.doctor()
        elif args.action == "list":
            result = supervisor.list_tasks()
        elif args.action == "reap":
            result = supervisor.reap_expired()
        elif args.action == "verify-events":
            result = supervisor.verify_event_chain()
        elif args.action == "task-add":
            result = supervisor.create_task(
                args.title,
                args.description,
                args.acceptance,
                args.resources,
                args.dependencies,
                args.priority,
                args.base_branch,
                args.produces,
                args.consumes,
            )
        elif args.action == "show":
            result = supervisor.task(args.task_id)
        elif args.action == "plan":
            result = supervisor.plan_claim(args.task_id)
        elif args.action == "queue":
            result = supervisor.ready_queue()
        elif args.action == "merge-plan":
            result = supervisor.merge_plan()
        elif args.action == "reviewers":
            result = supervisor.reviewers()
        elif args.action == "ratify-reviewers":
            result = supervisor.ratify_reviewers()
        elif args.action == "calibrate":
            result = supervisor.calibrate(args.reviewer_id)
        elif args.action == "bundle":
            result = supervisor.reproduction_bundle(args.qc_id)
        elif args.action == "status":
            return watch_status(supervisor, args)
        elif args.action == "claim":
            result = supervisor.claim(args.task_id, args.agent_id, args.lease_seconds)
        elif args.action == "heartbeat":
            try:
                checkpoint = json.loads(args.checkpoint)
            except json.JSONDecodeError as error:
                raise SupervisorError(
                    "invalid_checkpoint", "checkpoint must be a JSON object"
                ) from error
            if not isinstance(checkpoint, dict):
                raise SupervisorError("invalid_checkpoint", "checkpoint must be a JSON object")
            result = supervisor.heartbeat(
                args.attempt_id,
                args.claim_token,
                checkpoint,
                args.lease_seconds,
            )
        elif args.action == "submit":
            result = supervisor.submit(args.attempt_id, args.claim_token)
        elif args.action == "qc":
            reviewer = args.reviewer or supervisor.config.critic_identity
            result = supervisor.run_qc(args.submission_id, reviewer)
        elif args.action == "integrate":
            result = supervisor.integrate(args.task_id)
        elif args.action == "run":
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            result = supervisor.run_worker(args.attempt_id, args.claim_token, command)
        elif args.action == "terminate":
            result = supervisor.terminate_worker(args.attempt_id)
        elif args.action == "environment":
            result = supervisor.runtime_environment(args.attempt_id)
        elif args.action == "runtime-down":
            result = supervisor.runtime_down(args.attempt_id, args.force)
        else:
            root.error(f"unknown action {args.action}")
            return 2
        emit(result)
        if args.action in {"doctor", "verify-events"} and not result["ok"]:
            return 1
        return 0
    except SupervisorError as error:
        print(
            json.dumps({"ok": False, "error": error.code, "message": str(error)}),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
