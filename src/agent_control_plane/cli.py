from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import time
from collections.abc import Sequence
from typing import Any

from .git_supervisor import GitSupervisor, SupervisorError
from .status import DEFAULT_LEASE_RISK_SECONDS


def add_credential_source(command: argparse.ArgumentParser) -> None:
    source = command.add_mutually_exclusive_group()
    source.add_argument(
        "--credential-file",
        help="read the runner credential from a private (0600) file",
    )
    source.add_argument(
        "--credential-fd",
        type=int,
        help="read the runner credential from an already-open file descriptor",
    )


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
    ratify = commands.add_parser(
        "ratify-reviewers", help="accept a changed reviewer policy so QC may run again"
    )
    ratify.add_argument("--integrator", default="integration")
    add_credential_source(ratify)
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
    add_credential_source(claim)
    heartbeat = commands.add_parser("heartbeat", help="renew a fenced attempt")
    heartbeat.add_argument("attempt_id")
    heartbeat.add_argument("--token", type=int, required=True, dest="claim_token")
    heartbeat.add_argument("--checkpoint", default="{}")
    heartbeat.add_argument("--lease-seconds", type=int)
    add_credential_source(heartbeat)
    submit = commands.add_parser("submit", help="submit committed Git evidence")
    submit.add_argument("attempt_id")
    submit.add_argument("--token", type=int, required=True, dest="claim_token")
    add_credential_source(submit)
    qc = commands.add_parser("qc", help="run QC in a fresh detached worktree")
    qc.add_argument("submission_id")
    qc.add_argument("--reviewer", help="must match critic_identity in acp.toml")
    add_credential_source(qc)
    integrate = commands.add_parser("integrate", help="create a gated integration branch")
    integrate.add_argument("task_id")
    integrate.add_argument("--integrator", default="integration")
    add_credential_source(integrate)
    run = commands.add_parser("run", help="run an agent command in its worktree")
    run.add_argument("attempt_id")
    run.add_argument("--token", type=int, required=True, dest="claim_token")
    add_credential_source(run)
    run.add_argument("command", nargs=argparse.REMAINDER)
    terminate = commands.add_parser("terminate", help="stop a supervised worker")
    terminate.add_argument("attempt_id")
    add_credential_source(terminate)
    environment = commands.add_parser(
        "environment", help="show the isolated runtime assigned to an attempt"
    )
    environment.add_argument("attempt_id")
    runtime_down = commands.add_parser(
        "runtime-down", help="retry teardown and release an attempt runtime"
    )
    enroll = commands.add_parser(
        "runner-enroll",
        help="register a runner identity and write its credential to a private sink",
    )
    enroll.add_argument("agent_id")
    enroll.add_argument("--role", required=True, choices=["worker", "critic", "integrator"])
    output = enroll.add_mutually_exclusive_group(required=True)
    output.add_argument(
        "--credential-output-file",
        help="create this private file (must not already exist) for the credential",
    )
    output.add_argument(
        "--credential-output-fd",
        type=int,
        help="write the credential to an already-open file descriptor",
    )
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


def _read_credential(args: argparse.Namespace) -> str | None:
    credential_file = getattr(args, "credential_file", None)
    credential_fd = getattr(args, "credential_fd", None)
    if credential_file:
        path = os.path.abspath(os.path.expanduser(credential_file))
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as error:
            raise SupervisorError(
                "credential_source_unavailable", "credential file is unavailable"
            ) from error
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode) or details.st_mode & 0o077:
                raise SupervisorError(
                    "insecure_credential_file",
                    "credential file must be a regular file with no group/other permissions",
                )
            value = os.read(descriptor, 4097).decode("utf-8")
        except (OSError, UnicodeError) as error:
            raise SupervisorError(
                "credential_source_unavailable", "credential file could not be read"
            ) from error
        finally:
            os.close(descriptor)
    elif credential_fd is not None:
        if credential_fd < 0:
            raise SupervisorError("invalid_credential_fd", "credential fd must be non-negative")
        try:
            value = os.read(credential_fd, 4097).decode("utf-8")
        except (OSError, UnicodeError) as error:
            raise SupervisorError(
                "credential_source_unavailable", "credential fd could not be read"
            ) from error
    else:
        value = os.environ.get("ACP_RUNNER_CREDENTIAL", "")
    value = value.strip()
    if len(value) > 4096:
        raise SupervisorError("invalid_credential", "runner credential is too long")
    return value or None


def _deliver_enrollment_credential(
    enrolled: dict[str, Any], descriptor: int, sink: str
) -> dict[str, Any]:
    secret = enrolled.pop("credential")
    payload = (secret + "\n").encode()
    written = 0
    while written < len(payload):
        written += os.write(descriptor, payload[written:])
    enrolled["credential_sink"] = sink
    return enrolled


def _prepare_enrollment_sink(
    args: argparse.Namespace,
) -> tuple[int, str, str | None]:
    output_file = getattr(args, "credential_output_file", None)
    output_fd = getattr(args, "credential_output_fd", None)
    if output_file:
        path = os.path.abspath(os.path.expanduser(output_file))
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as error:
            raise SupervisorError(
                "credential_sink_unavailable",
                "credential output file must be a new writable private file",
            ) from error
        return descriptor, path, path
    if output_fd is not None:
        if output_fd <= 2:
            raise SupervisorError(
                "invalid_credential_fd",
                "credential output fd must be 3 or greater, never stdout/stderr",
            )
        try:
            descriptor = os.dup(output_fd)
        except OSError as error:
            raise SupervisorError(
                "credential_sink_unavailable", "credential output fd is not open"
            ) from error
        return descriptor, f"fd:{output_fd}", None
    # argparse makes this unreachable; keep the API fail-closed.
    raise SupervisorError("credential_sink_required", "secure credential sink is required")


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
            result = supervisor.ratify_reviewers(args.integrator, _read_credential(args))
        elif args.action == "calibrate":
            result = supervisor.calibrate(args.reviewer_id)
        elif args.action == "bundle":
            result = supervisor.reproduction_bundle(args.qc_id)
        elif args.action == "status":
            return watch_status(supervisor, args)
        elif args.action == "claim":
            result = supervisor.claim(
                args.task_id,
                args.agent_id,
                args.lease_seconds,
                _read_credential(args),
            )
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
                _read_credential(args),
            )
        elif args.action == "submit":
            result = supervisor.submit(args.attempt_id, args.claim_token, _read_credential(args))
        elif args.action == "qc":
            reviewer = args.reviewer or supervisor.config.critic_identity
            result = supervisor.run_qc(args.submission_id, reviewer, _read_credential(args))
        elif args.action == "integrate":
            result = supervisor.integrate(args.task_id, args.integrator, _read_credential(args))
        elif args.action == "run":
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            result = supervisor.run_worker(
                args.attempt_id, args.claim_token, command, _read_credential(args)
            )
        elif args.action == "terminate":
            result = supervisor.terminate_worker(args.attempt_id, _read_credential(args))
        elif args.action == "environment":
            result = supervisor.runtime_environment(args.attempt_id)
        elif args.action == "runner-enroll":
            descriptor, sink, created_path = _prepare_enrollment_sink(args)
            enrolled = False
            delivered = False
            try:
                result = supervisor.enroll_runner(args.agent_id, args.role)
                enrolled = True
                result = _deliver_enrollment_credential(result, descriptor, sink)
                delivered = True
            except OSError as error:
                if enrolled:
                    supervisor.revoke_runner(args.agent_id)
                raise SupervisorError(
                    "credential_delivery_failed",
                    "credential sink failed; the new identity was revoked",
                ) from error
            finally:
                os.close(descriptor)
                if created_path and not delivered:
                    try:
                        os.unlink(created_path)
                    except FileNotFoundError:
                        pass
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
