"""A read-only MCP server over stdio, so an agent can see the board it works under.

Deliberately READ-ONLY and CREDENTIAL-FREE. `acp claim`, `heartbeat`, `submit`, `qc`
and `integrate` are all authenticated by a runner credential, and `runner_identity.py`
exists to keep worker, critic and integrator authority apart so nobody approves their
own work. A long-lived stdio server that an editor spawns and holds open would have to
keep such a credential for the life of the session; if it held more than one role's, it
would erase that separation in a process whose lifetime nobody is watching. The CLI is
careful about this — `_read_credential` takes a 0600 file or an already-open descriptor
and never an environment variable — so putting one in a server's environment would undo
the care rather than reuse it.

Every tool here therefore calls a method that takes no credential, against a supervisor
opened `read_only=True`. That is not a promise in a docstring: `mode=ro` makes a stray
write raise, and the dispatch table maps names to bound methods that a test asserts
against by identity.

No third-party dependency. The wire format is newline-delimited JSON-RPC 2.0 on stdin
and stdout, which is small enough to implement honestly and keeps `acp`'s import graph
free of an SDK it would otherwise carry for one subcommand.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Iterator
from typing import Any

from .git_supervisor import GitSupervisor, SupervisorError

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "acp"

# name -> (GitSupervisor method name, description, JSON Schema for arguments)
TOOLS: dict[str, tuple[str, str, dict[str, Any]]] = {
    "acp_status": (
        "status",
        "Operator snapshot: what needs a human, what is running, what failed cleanup.",
        {"type": "object", "additionalProperties": False, "properties": {}},
    ),
    "acp_queue": (
        "ready_queue",
        "Ordered ready queue with overlap and dependency blockers.",
        {"type": "object", "additionalProperties": False, "properties": {}},
    ),
    "acp_merge_plan": (
        "merge_plan",
        "Integration ordering preview for approved work.",
        {"type": "object", "additionalProperties": False, "properties": {}},
    ),
    "acp_reviewers": (
        "reviewers",
        "Declared reviewers and the evaluation policy state.",
        {"type": "object", "additionalProperties": False, "properties": {}},
    ),
    "acp_verify_events": (
        "verify_event_chain",
        "Verify the hash-chained event log.",
        {"type": "object", "additionalProperties": False, "properties": {}},
    ),
    "acp_show": (
        "task",
        "One task: status, write set, acceptance criteria, current attempt.",
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["task_id"],
            "properties": {"task_id": {"type": "string"}},
        },
    ),
    "acp_plan": (
        "plan_claim",
        "Dry-run a claim and report what would block it. Changes nothing.",
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["task_id"],
            "properties": {"task_id": {"type": "string"}},
        },
    ),
    "acp_bundle": (
        "reproduction_bundle",
        "The signed, deterministic reproduction bundle for one QC verdict.",
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["qc_id"],
            "properties": {"qc_id": {"type": "string"}},
        },
    ),
    "acp_guard_context": (
        "guard_context",
        "The worktree and declared write set for an attempt — what you may edit.",
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["attempt_id"],
            "properties": {"attempt_id": {"type": "string"}},
        },
    ),
    "acp_guard": (
        "guard",
        "May this attempt write this path? Answers allow/deny with a reason.",
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["attempt_id", "path"],
            "properties": {"attempt_id": {"type": "string"}, "path": {"type": "string"}},
        },
    ),
}


def tool_descriptors() -> list[dict[str, Any]]:
    return [
        {"name": name, "description": description, "inputSchema": schema}
        for name, (_, description, schema) in sorted(TOOLS.items())
    ]


def dispatch(supervisor: GitSupervisor, tool: str, arguments: dict[str, Any]) -> Any:
    """Call the one supervisor method this tool names, with no logic in between.

    Adapters ask; the supervisor decides. Re-implementing any check here would create a
    second enforcement path that could disagree with the one that matters.
    """

    if tool not in TOOLS:
        raise SupervisorError("unknown_tool", f"no such tool: {tool}")
    method_name, _, schema = TOOLS[tool]
    required = schema.get("required", [])
    missing = [key for key in required if key not in arguments]
    if missing:
        raise SupervisorError("invalid_arguments", f"{tool} needs {', '.join(missing)}")
    allowed = set(schema.get("properties", {}))
    extra = set(arguments) - allowed
    if extra:
        raise SupervisorError("invalid_arguments", f"{tool} rejects {', '.join(sorted(extra))}")
    method: Callable[..., Any] = getattr(supervisor, method_name)
    return method(**{key: arguments[key] for key in allowed if key in arguments})


def _response(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def handle(request: dict[str, Any], open_supervisor: Callable[[], GitSupervisor]) -> dict | None:
    """One JSON-RPC message in, at most one out. None means "no reply" (a notification)."""

    request_id = request.get("id")
    method = request.get("method")

    if method == "initialize":
        return _response(
            request_id,
            {
                # Echo the client's version when it names one; a hand-written server
                # should follow the client rather than pin a version it cannot track.
                "protocolVersion": (request.get("params") or {}).get(
                    "protocolVersion", PROTOCOL_VERSION
                ),
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": __import__("agent_control_plane").__version__,
                },
            },
        )
    if method in {"notifications/initialized", "initialized"}:
        return None
    if method == "tools/list":
        return _response(request_id, {"tools": tool_descriptors()})
    if method == "tools/call":
        params = request.get("params") or {}
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        try:
            result = dispatch(open_supervisor(), name, arguments)
        except SupervisorError as error:
            return _response(
                request_id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {"ok": False, "error": error.code, "message": str(error)}
                            ),
                        }
                    ],
                    "isError": True,
                },
            )
        return _response(
            request_id,
            {
                "content": [{"type": "text", "text": json.dumps(result, default=str)}],
                "isError": False,
            },
        )
    if request_id is None:
        return None
    return _error(request_id, -32601, f"method not found: {method}")


def serve(repo: str, stdin: Iterator[str] | None = None, stdout: Any = None) -> int:
    """Read newline-delimited JSON-RPC from stdin, write replies to stdout.

    stdout carries protocol only. Anything diagnostic goes to stderr, because one
    stray line corrupts the stream for the rest of the session — which is why this
    module never calls print().
    """

    source = sys.stdin if stdin is None else stdin
    sink = sys.stdout if stdout is None else stdout

    def open_supervisor() -> GitSupervisor:
        # Per call, so a schema upgrade or a repository that moves under the server is
        # noticed rather than cached for the lifetime of an editor session.
        return GitSupervisor(repo, read_only=True)

    for line in source:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            sink.write(json.dumps(_error(None, -32700, "parse error")) + "\n")
            sink.flush()
            continue
        if not isinstance(request, dict):
            sink.write(json.dumps(_error(None, -32600, "invalid request")) + "\n")
            sink.flush()
            continue
        try:
            reply = handle(request, open_supervisor)
        except SupervisorError as error:
            reply = _error(request.get("id"), -32603, f"{error.code}: {error}")
        except Exception as error:  # noqa: BLE001 - a server must not die on one message
            reply = _error(request.get("id"), -32603, f"{type(error).__name__}: {error}")
        if reply is not None:
            sink.write(json.dumps(reply) + "\n")
            sink.flush()
    return 0
