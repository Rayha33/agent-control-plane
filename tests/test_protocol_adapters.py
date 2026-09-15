"""Board #568: MCP Tasks and A2A views of ACP tasks — and the writes they refuse.

The mapping tests are the load-bearing ones. Both protocols define terminal statuses that
MUST NOT transition, while most ACP statuses can move again: a blocked or conflicted task is
reopened, an orphaned task is reclaimed. Reporting any of those as terminal would tell a
client the work had finished when an operator is about to restart it. ``done`` is the only
ACP status that never changes.

The adapter tests check the other half of the contract: neither protocol may become a second
way to create or end fenced work.
"""

from __future__ import annotations

import inspect
import json
import subprocess
import sys
from pathlib import Path
from typing import get_args

import pytest
from support import approve, init_repo, make_task
from test_coordination import (
    claim_task,
    create_agent,
    create_task,
    issue_coordination_mandate,
    submit_task,
)

from agent_control_plane import mcp_server
from agent_control_plane.coordination_schemas import TaskStatus
from agent_control_plane.git_supervisor import GitSupervisor
from agent_control_plane.protocol_adapters import (
    A2A_AGENT_CARD_PATH,
    A2A_COMPLETED,
    A2A_INPUT_REQUIRED,
    A2A_PROTOCOL_VERSION,
    A2A_SUBMITTED,
    A2A_TASK_NOT_CANCELABLE,
    A2A_TASK_NOT_FOUND,
    A2A_TERMINAL,
    A2A_UNSUPPORTED_OPERATION,
    A2A_VERSION_HEADER,
    A2A_VERSION_NOT_SUPPORTED,
    A2A_WORKING,
    JSON_RPC_INVALID_PARAMS,
    JSON_RPC_METHOD_NOT_FOUND,
    MCP_COMPLETED,
    MCP_INPUT_REQUIRED,
    MCP_TERMINAL,
    MCP_WORKING,
    McpTaskBridge,
    UnknownTaskStatus,
    a2a_task,
    a2a_task_state,
    agent_card,
    classified_statuses,
    mcp_task,
    mcp_task_status,
    supported_version,
)

pytestmark = pytest.mark.storage_portable

# Statuses the Git supervisor writes, which the HTTP service's TaskStatus does not name.
# Derived by grepping the supervisor for status literals; the first test fails loudly if
# either vocabulary gains one this table has never classified.
SUPERVISOR_STATUSES = {
    "provisioning",
    "submitted",
    "qc_running",
    "integrating",
    "quarantined",
    "terminating",
    "cleanup_pending",
    "failed",
}
# Every HTTP status except `done` can move again, so none of them may be reported terminal.
REOPENABLE = set(get_args(TaskStatus)) - {"done"}


def rpc(client, method, params=None, *, token, version=A2A_PROTOCOL_VERSION, request_id=1):
    headers = {"Authorization": f"Bearer {token}"}
    if version is not None:
        headers[A2A_VERSION_HEADER] = version
    return client.post(
        "/a2a",
        headers=headers,
        json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}},
    )


# ----------------------------------------------------------------------- status mapping ----


def test_every_status_either_service_can_report_is_classified():
    classified = set(classified_statuses())
    unclassified = (set(get_args(TaskStatus)) | SUPERVISOR_STATUSES) - classified
    assert unclassified == set(), unclassified
    for status in classified:
        assert mcp_task_status(status)
        assert a2a_task_state(status)


def test_a_status_with_no_classification_is_loud():
    """The control: a status added later must not quietly become "working"."""

    for translate in (mcp_task_status, a2a_task_state):
        with pytest.raises(UnknownTaskStatus, match="cancelling"):
            translate("cancelling")


def test_no_reopenable_status_is_reported_as_terminal():
    for status in REOPENABLE:
        assert mcp_task_status(status) not in MCP_TERMINAL, status
        assert a2a_task_state(status) not in A2A_TERMINAL, status
    assert mcp_task_status("done") == MCP_COMPLETED
    assert a2a_task_state("done") == A2A_COMPLETED
    assert mcp_task_status("blocked") == MCP_INPUT_REQUIRED
    assert a2a_task_state("conflicted") == A2A_INPUT_REQUIRED
    assert a2a_task_state("open") == A2A_SUBMITTED
    assert mcp_task_status("open") == MCP_WORKING  # MCP has no "queued"; work is in progress


def test_version_header_rules_follow_the_specification():
    assert supported_version("1.0") and supported_version("1.0.7")
    # "Agents MUST interpret empty value as 0.3", which this interface does not speak.
    assert not supported_version("") and not supported_version(None)
    assert not supported_version("0.3") and not supported_version("2.0")


# ------------------------------------------------------------------------ MCP over stdio ----


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return init_repo(tmp_path)


def drive(repo: Path, *messages: dict) -> list[dict]:
    payload = "".join(json.dumps(message) + "\n" for message in messages)
    process = subprocess.run(
        [sys.executable, "-m", "agent_control_plane.cli", "--repo", str(repo), "mcp-serve"],
        input=payload,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    return [json.loads(line) for line in process.stdout.splitlines() if line.strip()]


def reply(replies: list[dict], request_id: int) -> dict:
    return next(message for message in replies if message.get("id") == request_id)


def test_the_server_declares_task_support_for_tool_calls_only(repo: Path):
    handshake = reply(
        drive(repo, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}), 1
    )
    tasks = handshake["result"]["capabilities"]["tasks"]
    assert tasks == {"requests": {"tools": {"call": {}}}}
    assert "list" not in tasks and "cancel" not in tasks


def test_the_watch_tool_is_task_only_and_hands_back_a_task_handle(repo: Path):
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    tools = reply(drive(repo, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}), 1)["result"]
    by_name = {tool["name"]: tool for tool in tools["tools"]}
    assert by_name["acp_watch_task"]["execution"] == {"taskSupport": "required"}
    assert "execution" not in by_name["acp_show"]

    bare, augmented, wrong = drive(
        repo,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "acp_watch_task", "arguments": {"task_id": created["id"]}},
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "acp_watch_task",
                "arguments": {"task_id": created["id"]},
                "task": {"ttl": 60000},
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "acp_show", "arguments": {"task_id": created["id"]}, "task": {}},
        },
    )
    assert bare["error"]["code"] == JSON_RPC_METHOD_NOT_FOUND
    assert wrong["error"]["code"] == JSON_RPC_METHOD_NOT_FOUND
    handle = augmented["result"]["task"]
    assert handle["taskId"] == created["id"]
    assert handle["status"] == MCP_WORKING
    assert handle["createdAt"] and handle["lastUpdatedAt"] and handle["pollInterval"]


def test_tasks_get_polls_and_tasks_result_returns_the_finished_task(repo: Path):
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")

    polled, unknown, listed, cancelled = drive(
        repo,
        {"jsonrpc": "2.0", "id": 1, "method": "tasks/get", "params": {"taskId": created["id"]}},
        {"jsonrpc": "2.0", "id": 2, "method": "tasks/get", "params": {"taskId": "nope"}},
        {"jsonrpc": "2.0", "id": 3, "method": "tasks/list", "params": {}},
        {"jsonrpc": "2.0", "id": 4, "method": "tasks/cancel", "params": {"taskId": created["id"]}},
    )
    assert polled["result"]["status"] == MCP_WORKING
    assert unknown["error"]["code"] == JSON_RPC_INVALID_PARAMS
    # Neither capability was declared, so neither method exists.
    assert listed["error"]["code"] == JSON_RPC_METHOD_NOT_FOUND
    assert cancelled["error"]["code"] == JSON_RPC_METHOD_NOT_FOUND

    approve(supervisor, created["id"], "alpha.txt", "finished\n")
    supervisor.integrate(created["id"])
    assert supervisor.task(created["id"])["status"] == "done"

    finished = reply(
        drive(
            repo,
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tasks/result",
                "params": {"taskId": created["id"]},
            },
        ),
        5,
    )["result"]
    assert finished["isError"] is False
    assert finished["structuredContent"]["status"] == MCP_COMPLETED
    assert finished["_meta"]["io.modelcontextprotocol/related-task"] == {"taskId": created["id"]}


def test_the_task_tools_are_still_read_only_and_credential_free():
    for name in mcp_server.TASK_TOOLS:
        method_name, _description, _schema = mcp_server.TOOLS[name]
        signature = inspect.signature(getattr(GitSupervisor, method_name))
        assert "credential" not in signature.parameters, name


def test_the_bridge_blocks_for_a_result_until_the_task_is_terminal_then_gives_up():
    statuses = iter(["working", "working", "done"])
    current = {"status": "working"}

    def load(_task_id):
        current["status"] = next(statuses, current["status"])
        return {
            "id": "t1",
            "status": current["status"],
            "created_at": "2026-09-15T00:00:00+00:00",
            "updated_at": "2026-09-15T00:00:01+00:00",
        }

    slept: list[float] = []
    bridge = McpTaskBridge(load, poll_interval_ms=10, sleep=slept.append, clock=lambda: 0.0)
    assert bridge.result("t1")["structuredContent"]["status"] == MCP_COMPLETED
    assert slept == [0.01, 0.01]

    stuck = McpTaskBridge(
        lambda _id: {
            "id": "t1",
            "status": "working",
            "created_at": "2026-09-15T00:00:00+00:00",
            "updated_at": "2026-09-15T00:00:01+00:00",
        },
        poll_interval_ms=10,
        max_wait_seconds=0.0,
        sleep=lambda _seconds: None,
        clock=lambda: 0.0,
    )
    with pytest.raises(TimeoutError, match="poll tasks/get instead"):
        stuck.result("t1")


# ------------------------------------------------------------------------- A2A over HTTP ----


def test_the_agent_card_is_served_at_the_well_known_path(client):
    card = client.get(A2A_AGENT_CARD_PATH)
    assert card.status_code == 200, card.text
    body = card.json()
    assert {
        "name",
        "description",
        "version",
        "supportedInterfaces",
        "capabilities",
        "defaultInputModes",
        "defaultOutputModes",
        "skills",
    } <= set(body)
    interface = body["supportedInterfaces"][0]
    assert interface["protocolBinding"] == "JSONRPC"
    assert interface["protocolVersion"] == A2A_PROTOCOL_VERSION
    assert interface["url"].endswith("/a2a")
    assert body == agent_card(url=interface["url"], version=body["version"])


def test_get_task_returns_the_a2a_view_with_the_fencing_generations(client, admin_headers):
    worker = create_agent(client, admin_headers, "a2a-worker", "worker")
    token = issue_coordination_mandate(client, admin_headers, worker["id"])
    task = create_task(client, admin_headers, resources=["src/a2a.py"])
    claim = claim_task(client, task["id"], token).json()
    submission = submit_task(client, task["id"], token, claim).json()

    answer = rpc(client, "GetTask", {"id": task["id"]}, token=token).json()
    view = answer["result"]["task"]
    assert view["id"] == task["id"]
    assert view["status"]["state"] == A2A_WORKING
    assert view["metadata"]["acp.claimFencingToken"] == claim["task"]["claim_fencing_token"]
    assert view["metadata"]["acp.resources"] == ["src/a2a.py"]
    artifact = view["artifacts"][0]
    assert artifact["artifactId"] == submission["id"]
    assert artifact["metadata"]["acp.artifactHash"] == submission["artifact_hash"]

    listed = rpc(client, "ListTasks", {}, token=token).json()["result"]
    assert [entry["id"] for entry in listed["tasks"]] == [task["id"]]
    assert listed["totalSize"] == 1 and listed["nextPageToken"] == ""


def test_the_version_header_is_required_and_checked(client, admin_headers):
    worker = create_agent(client, admin_headers, "a2a-version", "worker")
    token = issue_coordination_mandate(client, admin_headers, worker["id"])
    task = create_task(client, admin_headers, resources=["src/version.py"])

    missing = rpc(client, "GetTask", {"id": task["id"]}, token=token, version=None).json()
    assert missing["error"]["code"] == A2A_VERSION_NOT_SUPPORTED
    old = rpc(client, "GetTask", {"id": task["id"]}, token=token, version="0.3").json()
    assert old["error"]["code"] == A2A_VERSION_NOT_SUPPORTED
    patch = rpc(client, "GetTask", {"id": task["id"]}, token=token, version="1.0.9").json()
    assert patch["result"]["task"]["id"] == task["id"]


def test_a2a_cannot_create_or_end_work(client, admin_headers):
    worker = create_agent(client, admin_headers, "a2a-writer", "worker")
    token = issue_coordination_mandate(client, admin_headers, worker["id"])
    task = create_task(client, admin_headers, resources=["src/refused.py"])

    send = rpc(client, "SendMessage", {"message": {"parts": []}}, token=token).json()
    assert send["error"]["code"] == A2A_UNSUPPORTED_OPERATION
    cancel = rpc(client, "CancelTask", {"id": task["id"]}, token=token).json()
    assert cancel["error"]["code"] == A2A_TASK_NOT_CANCELABLE
    assert "revoke-claim" in cancel["error"]["message"]
    unknown = rpc(client, "DeleteTask", {"id": task["id"]}, token=token).json()
    assert unknown["error"]["code"] == JSON_RPC_METHOD_NOT_FOUND
    malformed = rpc(client, "GetTask", {}, token=token).json()
    assert malformed["error"]["code"] == JSON_RPC_INVALID_PARAMS
    # The task is untouched by any of it.
    assert client.get(f"/v1/tasks/{task['id']}", headers=admin_headers).json()["status"] == "open"


def test_a2a_needs_a_mandate_and_shows_only_tasks_within_its_scope(client, admin_headers):
    worker = create_agent(client, admin_headers, "a2a-scoped", "worker")
    mine = create_task(client, admin_headers, resources=["src/mine.py"], title="mine")
    theirs = create_task(client, admin_headers, resources=["src/theirs.py"], title="theirs")
    scoped = client.post(
        "/v1/mandates",
        headers=admin_headers,
        json={
            "agent_id": worker["id"],
            "subject": f"agent:{worker['id']}",
            "scopes": [{"action": "coordination.*", "resource": f"task:{mine['id']}"}],
            "ttl_seconds": 3600,
        },
    ).json()["token"]

    assert (
        client.post("/a2a", json={"jsonrpc": "2.0", "id": 1, "method": "GetTask"}).status_code
        == 401
    )
    assert (
        rpc(client, "GetTask", {"id": mine["id"]}, token=scoped).json()["result"]["task"]["id"]
        == mine["id"]
    )
    hidden = rpc(client, "GetTask", {"id": theirs["id"]}, token=scoped).json()
    # Out of scope answers exactly as a missing task does: scope must not be an oracle.
    assert hidden["error"]["code"] == A2A_TASK_NOT_FOUND
    assert hidden["error"]["message"] == "task not found"
    listed = rpc(client, "ListTasks", {}, token=scoped).json()["result"]
    assert [entry["id"] for entry in listed["tasks"]] == [mine["id"]]


def test_the_view_helpers_are_pure_functions_of_a_task_row():
    row = {
        "id": "task-1",
        "status": "qc_review",
        "created_at": "2026-09-15T10:00:00+00:00",
        "updated_at": "2026-09-15T10:05:00+00:00",
        "version": 3,
        "claim_fencing_token": 2,
        "resources": ["src/a.py"],
        "owner_agent_id": None,
        "latest_submission": None,
    }
    assert mcp_task(row, ttl_ms=60_000) == {
        "taskId": "task-1",
        "status": MCP_WORKING,
        "statusMessage": "ACP task status: qc_review",
        "createdAt": row["created_at"],
        "lastUpdatedAt": row["updated_at"],
        "ttl": 60_000,
        "pollInterval": 5_000,
    }
    view = a2a_task(row)
    assert view["status"] == {"state": A2A_WORKING, "timestamp": row["updated_at"]}
    assert "artifacts" not in view
