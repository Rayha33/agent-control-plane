from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import Any

from .git_supervisor import GitSupervisor, SupervisorError


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
    add.add_argument("--priority", type=int, default=50)
    add.add_argument("--base", default="HEAD", dest="base_branch")

    show = commands.add_parser("show", help="show a task")
    show.add_argument("task_id")
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
    enroll = commands.add_parser(
        "runner-enroll",
        help="register a runner identity and print its credential once",
    )
    enroll.add_argument("agent_id")
    enroll.add_argument("--role", required=True, choices=["worker", "critic", "integrator"])
    revoke = commands.add_parser("runner-revoke", help="revoke a runner credential")
    revoke.add_argument("agent_id")
    commands.add_parser("runner-list", help="list enrolled runner identities")

    driver_resources = commands.add_parser(
        "runtime-resources",
        help="show driver-managed resources and their cleanup proofs for an attempt",
    )
    driver_resources.add_argument("attempt_id")
    commands.add_parser(
        "runtime-quarantine",
        help="list allocations whose cleanup could not be proven",
    )
    runtime_restart = commands.add_parser(
        "runtime-restart",
        help="tear down and re-create driver resources so review gets fresh services",
    )
    runtime_restart.add_argument("attempt_id")
    runtime_down.add_argument("attempt_id")
    runtime_down.add_argument(
        "--force",
        action="store_true",
        help="recover a teardown left in-progress by a crashed supervisor",
    )
    return root


def emit(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


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
            )
        elif args.action == "show":
            result = supervisor.task(args.task_id)
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
        elif args.action == "runner-enroll":
            result = supervisor.enroll_runner(args.agent_id, args.role)
        elif args.action == "runner-revoke":
            result = supervisor.revoke_runner(args.agent_id)
        elif args.action == "runner-list":
            result = supervisor.runners()
        elif args.action == "runtime-resources":
            result = supervisor.driver_resources(args.attempt_id)
        elif args.action == "runtime-quarantine":
            result = supervisor.quarantined_resources()
        elif args.action == "runtime-restart":
            result = supervisor.runtime_restart(args.attempt_id)
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
