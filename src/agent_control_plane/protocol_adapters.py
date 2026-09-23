"""MCP Tasks and A2A views of an ACP task (board #568).

Both protocols describe a long-running unit of work, which is what an ACP task already is.
What neither may become is a second way to change one. So these adapters READ, and the two
operations that would write are refused for stated reasons rather than quietly implemented:

- **A2A ``SendMessage``** would create work. Creating an ACP task is an administrator action,
  and an A2A caller holds a worker mandate. Refused with ``UnsupportedOperationError``.
- **A2A ``CancelTask`` and MCP ``tasks/cancel``** would end a claim. Ending one is fenced —
  resources must stay reserved until the revoked runner's last attempt token expires — and
  that is what ``POST /v1/tasks/{id}/revoke-claim`` does, under the administrator key.
  A2A answers ``TaskNotCancelableError``; MCP does not declare ``tasks.cancel`` at all, so the
  method is simply absent.

That is invariant 4c of docs/ARCHITECTURE.md applied to transports: protocol identity is
mapped into the same authenticated service, never into a parallel one.

Status mapping is the delicate part. ACP statuses are not terminal: ``blocked`` and
``conflicted`` return to ``open`` when an operator reopens them, and an orphaned task is
reclaimed. MCP says a terminal status MUST NOT transition, and A2A says the same of its
terminal states, so neither mapping may report anything terminal for a status that can move
again. ``done`` is the only ACP status that never changes, and it is the only one mapped to
``completed``/``TASK_STATE_COMPLETED``. Statuses awaiting a person map to ``input_required``,
which both protocols define as interrupted rather than terminal. An unknown status raises:
a status added later must not silently become "working".
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Mapping
from typing import Any

# --- MCP (specification 2025-11-25, "Tasks") ------------------------------------------------

MCP_WORKING = "working"
MCP_INPUT_REQUIRED = "input_required"
MCP_COMPLETED = "completed"
MCP_FAILED = "failed"
MCP_CANCELLED = "cancelled"
MCP_TERMINAL = frozenset({MCP_COMPLETED, MCP_FAILED, MCP_CANCELLED})
MCP_RELATED_TASK_KEY = "io.modelcontextprotocol/related-task"
# Declared to clients at initialize. `list` is absent because a stdio server cannot bind tasks
# to an authorization context, and the specification says such a receiver SHOULD NOT declare
# it; `cancel` is absent because cancelling is a fenced write (see the module docstring).
MCP_TASKS_CAPABILITY: dict[str, Any] = {"requests": {"tools": {"call": {}}}}
MCP_DEFAULT_POLL_INTERVAL_MS = 5_000

# --- A2A (specification 1.0.0) --------------------------------------------------------------

A2A_PROTOCOL_VERSION = "1.0"
A2A_VERSION_HEADER = "A2A-Version"
A2A_AGENT_CARD_PATH = "/.well-known/agent-card.json"
A2A_SUBMITTED = "TASK_STATE_SUBMITTED"
A2A_WORKING = "TASK_STATE_WORKING"
A2A_INPUT_REQUIRED = "TASK_STATE_INPUT_REQUIRED"
A2A_COMPLETED = "TASK_STATE_COMPLETED"
A2A_FAILED = "TASK_STATE_FAILED"
A2A_TERMINAL = frozenset({A2A_COMPLETED, A2A_FAILED, "TASK_STATE_CANCELED", "TASK_STATE_REJECTED"})
# Numeric codes from the specification's error table.
A2A_TASK_NOT_FOUND = -32001
A2A_TASK_NOT_CANCELABLE = -32002
A2A_UNSUPPORTED_OPERATION = -32004
A2A_VERSION_NOT_SUPPORTED = -32009
JSON_RPC_METHOD_NOT_FOUND = -32601
JSON_RPC_INVALID_PARAMS = -32602

# Every status either service can report. Kept as one table so the two protocol views cannot
# drift apart, and so a new ACP status has to be classified here before it can be exported.
_STATUS_KIND: dict[str, str] = {
    # not started
    "open": "queued",
    # in flight
    "claimed": "running",
    "provisioning": "running",
    "working": "running",
    "submitted": "running",
    "qc_running": "running",
    "qc_review": "running",
    "changes_requested": "running",
    "approved": "running",
    "merging": "running",
    "integrating": "running",
    "orphaned": "running",
    "terminating": "running",
    "cleanup_pending": "running",
    # waiting for a person; reopenable, therefore NOT terminal in either protocol
    "blocked": "waiting",
    "conflicted": "waiting",
    "quarantined": "waiting",
    # terminal
    "done": "done",
    "failed": "failed",
}


class UnknownTaskStatus(ValueError):
    """An ACP status with no protocol classification. Classify it in ``_STATUS_KIND``."""


class A2AError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


def _kind(status: str) -> str:
    try:
        return _STATUS_KIND[status]
    except KeyError:
        raise UnknownTaskStatus(
            f"{status!r} has no MCP/A2A classification; add it to protocol_adapters._STATUS_KIND"
        ) from None


def mcp_task_status(acp_status: str) -> str:
    kind = _kind(acp_status)
    if kind == "done":
        return MCP_COMPLETED
    if kind == "failed":
        return MCP_FAILED
    if kind == "waiting":
        return MCP_INPUT_REQUIRED
    return MCP_WORKING


def a2a_task_state(acp_status: str) -> str:
    kind = _kind(acp_status)
    if kind == "done":
        return A2A_COMPLETED
    if kind == "failed":
        return A2A_FAILED
    if kind == "waiting":
        return A2A_INPUT_REQUIRED
    if kind == "queued":
        return A2A_SUBMITTED
    return A2A_WORKING


def mcp_task(
    task: Mapping[str, Any],
    *,
    ttl_ms: int | None = None,
    poll_interval_ms: int = MCP_DEFAULT_POLL_INTERVAL_MS,
) -> dict[str, Any]:
    """The MCP ``Task`` object. ``taskId`` is the ACP task id: receiver-generated and unique."""

    status = mcp_task_status(task["status"])
    return {
        "taskId": task["id"],
        "status": status,
        "statusMessage": f"ACP task status: {task['status']}",
        "createdAt": task["created_at"],
        "lastUpdatedAt": task["updated_at"],
        "ttl": ttl_ms,
        "pollInterval": poll_interval_ms,
    }


def mcp_related_task(task_id: str) -> dict[str, Any]:
    return {MCP_RELATED_TASK_KEY: {"taskId": task_id}}


def a2a_task(task: Mapping[str, Any], *, include_artifacts: bool = True) -> dict[str, Any]:
    """The A2A ``Task`` object, ProtoJSON: camelCase fields, enums as their SCREAMING_SNAKE names.

    A submission becomes an artifact because an A2A ``artifactId`` is durable across attempts,
    which is the same property the side-effect adapter already maps onto a fencing resource.
    ACP's fencing generations travel in ``metadata`` so a client can present them back.
    """

    view: dict[str, Any] = {
        "id": task["id"],
        "contextId": task["id"],
        "status": {
            "state": a2a_task_state(task["status"]),
            "timestamp": task["updated_at"],
        },
        "metadata": {
            "acp.status": task["status"],
            "acp.version": task.get("version"),
            "acp.claimFencingToken": task.get("claim_fencing_token"),
            "acp.resources": list(task.get("resources") or []),
            "acp.ownerAgentId": task.get("owner_agent_id"),
        },
    }
    submission = task.get("latest_submission") if include_artifacts else None
    if submission:
        view["artifacts"] = [
            {
                "artifactId": submission["id"],
                "name": "submission",
                "description": submission["summary"],
                "parts": [{"text": submission["artifact_uri"]}],
                "metadata": {
                    "acp.artifactHash": submission["artifact_hash"],
                    "acp.baseRevision": submission["base_revision"],
                    "acp.resourceFencingTokens": submission["resource_fencing_tokens"],
                    "acp.status": submission["status"],
                },
            }
        ]
    return view


def agent_card(*, url: str, version: str, name: str = "agent-control-plane") -> dict[str, Any]:
    return {
        "name": name,
        "description": (
            "Read fenced task state from an Agent Control Plane authority. "
            "Work is created and ended by an operator, not over A2A."
        ),
        "version": version,
        "supportedInterfaces": [
            {
                "url": url,
                "protocolBinding": "JSONRPC",
                "protocolVersion": A2A_PROTOCOL_VERSION,
            }
        ],
        "capabilities": {"streaming": False, "pushNotifications": False},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": [
            {
                "id": "acp.tasks.read",
                "name": "Read task state",
                "description": (
                    "Fetch or list tasks with their fencing generations, within the "
                    "caller's mandate scope."
                ),
                "tags": ["tasks", "fencing", "coordination"],
            }
        ],
    }


def supported_version(header_value: str | None) -> bool:
    """A2A 1.0: clients MUST send A2A-Version, and an empty value means 0.3, which we are not."""

    if not header_value:
        return False
    major_minor = ".".join(header_value.strip().split(".")[:2])
    return major_minor == A2A_PROTOCOL_VERSION


class A2ATaskAdapter:
    """A2A's read surface over the same authenticated coordination service the HTTP API uses."""

    def __init__(
        self, coordination: Any, control_plane: Any, *, scope_action: str = "coordination.read"
    ):
        self.coordination = coordination
        self.control_plane = control_plane
        self.scope_action = scope_action

    def _authorize(self, token: str, task_id: str) -> None:
        from .policy import scope_allows
        from .service import ControlPlaneError

        try:
            claims, _mandate, _agent = self.control_plane.authenticated_agent(token)
        except ControlPlaneError as error:
            raise A2AError(A2A_UNSUPPORTED_OPERATION, error.message) from error
        if not scope_allows(claims["scopes"], self.scope_action, f"task:{task_id}"):
            # Deliberately the same answer as a missing task: scope must not be an oracle.
            raise A2AError(A2A_TASK_NOT_FOUND, "task not found")

    def get_task(self, token: str, params: Mapping[str, Any]) -> dict[str, Any]:
        from .service import ControlPlaneError

        task_id = params.get("id")
        if not isinstance(task_id, str) or not task_id:
            raise A2AError(JSON_RPC_INVALID_PARAMS, "GetTask requires a string id")
        self._authorize(token, task_id)
        try:
            task = self.coordination.task(task_id)
        except ControlPlaneError as error:
            raise A2AError(A2A_TASK_NOT_FOUND, "task not found") from error
        return a2a_task(task, include_artifacts=bool(params.get("includeArtifacts", True)))

    def list_tasks(self, token: str, params: Mapping[str, Any]) -> dict[str, Any]:
        from .policy import scope_allows
        from .service import ControlPlaneError

        try:
            claims, _mandate, _agent = self.control_plane.authenticated_agent(token)
        except ControlPlaneError as error:
            raise A2AError(A2A_UNSUPPORTED_OPERATION, error.message) from error
        status = params.get("status")
        acp_status = None
        if status:
            acp_status = _acp_status_for(status)
        tasks = [
            task
            for task in self.coordination.list_tasks(acp_status)
            if scope_allows(claims["scopes"], self.scope_action, f"task:{task['id']}")
        ]
        page_size = int(params.get("pageSize") or 50)
        page = tasks[:page_size]
        return {
            "tasks": [
                a2a_task(task, include_artifacts=bool(params.get("includeArtifacts", False)))
                for task in page
            ],
            "nextPageToken": "",
            "pageSize": page_size,
            "totalSize": len(tasks),
        }

    def handle(
        self, method: str, params: Mapping[str, Any], *, token: str, version: str | None
    ) -> dict[str, Any]:
        if not supported_version(version):
            raise A2AError(
                A2A_VERSION_NOT_SUPPORTED,
                f"this interface speaks A2A {A2A_PROTOCOL_VERSION}; "
                f"send the {A2A_VERSION_HEADER} header",
            )
        if method == "GetTask":
            return {"task": self.get_task(token, params)}
        if method == "ListTasks":
            return self.list_tasks(token, params)
        if method == "CancelTask":
            raise A2AError(
                A2A_TASK_NOT_CANCELABLE,
                "ACP tasks are not cancelled over A2A: ending a claim is fenced and is the "
                "administrator's POST /v1/tasks/{id}/revoke-claim",
            )
        if method == "SendMessage":
            raise A2AError(
                A2A_UNSUPPORTED_OPERATION,
                "ACP work is created by an operator, not by an A2A message",
            )
        raise A2AError(JSON_RPC_METHOD_NOT_FOUND, f"method not found: {method}")

    def dispatch(
        self, request: Mapping[str, Any], *, token: str, version: str | None
    ) -> dict[str, Any]:
        """One JSON-RPC request in, one response out."""

        request_id = request.get("id")
        try:
            result = self.handle(
                str(request.get("method", "")),
                request.get("params") or {},
                token=token,
                version=version,
            )
        except A2AError as error:
            body: dict[str, Any] = {"code": error.code, "message": error.message}
            if error.data is not None:
                body["data"] = error.data
            return {"jsonrpc": "2.0", "id": request_id, "error": body}
        return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _acp_status_for(a2a_state: str) -> str | None:
    """Best-effort filter: A2A states are coarser than ACP statuses, so several map to none."""

    matches = [status for status in _STATUS_KIND if a2a_task_state(status) == a2a_state]
    return matches[0] if len(matches) == 1 else None


class McpTaskBridge:
    """Expose ACP tasks as MCP tasks over an existing MCP server.

    ``create`` answers a task-augmented ``tools/call``; ``get`` answers ``tasks/get``;
    ``result`` answers ``tasks/result``, which the specification says MUST block until the task
    is terminal. It blocks by polling ``load_task`` at ``pollInterval``, bounded by
    ``max_wait_seconds`` — an unbounded wait in a single-threaded stdio server would stop it
    answering anything else, which is a worse failure than a bounded one.
    """

    def __init__(
        self,
        load_task: Callable[[str], Mapping[str, Any]],
        *,
        poll_interval_ms: int = MCP_DEFAULT_POLL_INTERVAL_MS,
        ttl_ms: int | None = None,
        max_wait_seconds: float = 300.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.load_task = load_task
        self.poll_interval_ms = poll_interval_ms
        self.ttl_ms = ttl_ms
        self.max_wait_seconds = max_wait_seconds
        self.sleep = sleep
        self.clock = clock

    def _view(self, task_id: str) -> dict[str, Any]:
        return mcp_task(
            self.load_task(task_id), ttl_ms=self.ttl_ms, poll_interval_ms=self.poll_interval_ms
        )

    def create(self, task_id: str) -> dict[str, Any]:
        return {"task": self._view(task_id)}

    def get(self, task_id: str) -> dict[str, Any]:
        return self._view(task_id)

    def result(self, task_id: str) -> dict[str, Any]:
        deadline = self.clock() + self.max_wait_seconds
        while True:
            view = self._view(task_id)
            if view["status"] in MCP_TERMINAL:
                return {
                    "content": [{"type": "text", "text": view["statusMessage"]}],
                    "isError": view["status"] != MCP_COMPLETED,
                    "structuredContent": view,
                    "_meta": mcp_related_task(task_id),
                }
            if self.clock() >= deadline:
                raise TimeoutError(
                    f"task {task_id} was still {view['status']} after "
                    f"{self.max_wait_seconds:g}s; poll tasks/get instead"
                )
            self.sleep(self.poll_interval_ms / 1000)


def classified_statuses() -> Iterable[str]:
    return tuple(_STATUS_KIND)


__all__ = [
    "A2A_AGENT_CARD_PATH",
    "A2A_COMPLETED",
    "A2A_INPUT_REQUIRED",
    "A2A_PROTOCOL_VERSION",
    "A2A_SUBMITTED",
    "A2A_TASK_NOT_CANCELABLE",
    "A2A_TASK_NOT_FOUND",
    "A2A_TERMINAL",
    "A2A_UNSUPPORTED_OPERATION",
    "A2A_VERSION_HEADER",
    "A2A_VERSION_NOT_SUPPORTED",
    "A2A_WORKING",
    "JSON_RPC_INVALID_PARAMS",
    "JSON_RPC_METHOD_NOT_FOUND",
    "MCP_COMPLETED",
    "MCP_DEFAULT_POLL_INTERVAL_MS",
    "MCP_INPUT_REQUIRED",
    "MCP_RELATED_TASK_KEY",
    "MCP_TASKS_CAPABILITY",
    "MCP_TERMINAL",
    "MCP_WORKING",
    "A2AError",
    "A2ATaskAdapter",
    "McpTaskBridge",
    "UnknownTaskStatus",
    "a2a_task",
    "a2a_task_state",
    "agent_card",
    "classified_statuses",
    "mcp_related_task",
    "mcp_task",
    "mcp_task_status",
    "supported_version",
]
