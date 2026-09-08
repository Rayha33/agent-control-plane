"""`acp mcp-serve` — read-only, credential-free, and provably so.

The row that asked for this proposed exposing claim/heartbeat/submit as tools with the
runner credential read from an environment variable. That would put a credential which
`_read_credential` deliberately accepts only from a 0600 file or an open descriptor into
the environment of a long-lived process an editor spawns — and a server holding more
than one role's credential erases the worker/critic/integrator separation
`runner_identity.py` exists to create.

So the write half is not built. These tests are the ones that keep it that way: not
"the tool names look read-only", which stays green if `acp_status` is implemented as
`claim()`, but assertions about which bound methods the dispatch table reaches and
which parameters they take.
"""

from __future__ import annotations

import inspect
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest
from support import init_repo, make_task

from agent_control_plane import mcp_server
from agent_control_plane.git_supervisor import GitSupervisor

WRITE_METHODS = {
    "claim",
    "heartbeat",
    "submit",
    "run_qc",
    "integrate",
    "reap_expired",
    "gc",
    "create_task",
    "migrate",
    "run_worker",
    "terminate",
    "runtime_down",
    "runtime_restart",
    "ratify_reviewers",
}


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return init_repo(tmp_path)


def drive(repo: Path, *messages: dict) -> list[dict]:
    """Run the server as a subprocess over pipes; the transport is part of the contract."""

    payload = "".join(json.dumps(message) + "\n" for message in messages)
    process = subprocess.run(
        [sys.executable, "-m", "agent_control_plane.cli", "--repo", str(repo), "mcp-serve"],
        input=payload,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return [json.loads(line) for line in process.stdout.splitlines() if line.strip()]


def call(repo: Path, name: str, arguments: dict | None = None) -> dict:
    replies = drive(
        repo,
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        },
    )
    return next(reply for reply in replies if reply.get("id") == 2)["result"]


def body(result: dict) -> dict:
    return json.loads(result["content"][0]["text"])


def test_the_handshake_and_tool_list_work_over_a_pipe(repo: Path) -> None:
    replies = drive(
        repo,
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    )
    ids = [reply.get("id") for reply in replies]
    assert ids == [1, 2], "a notification must not be answered"
    tools = {tool["name"] for tool in replies[1]["result"]["tools"]}
    assert tools == set(mcp_server.TOOLS)


def test_every_tool_reaches_the_supervisor_method_it_names(repo: Path) -> None:
    """A capability check, not a name check.

    `acp_status` implemented as `claim` would satisfy any assertion about tool NAMES.
    This pins the actual attribute each tool dispatches to.
    """

    supervisor = GitSupervisor(repo, read_only=True)
    for tool, (method_name, _, _) in mcp_server.TOOLS.items():
        method = getattr(supervisor, method_name, None)
        assert callable(method), f"{tool} names a method that does not exist: {method_name}"
        assert method_name not in WRITE_METHODS, f"{tool} reaches a writing method"


def test_no_tool_reaches_a_method_that_takes_a_credential() -> None:
    """The signal that would differ if the write half crept in.

    Every authenticated operation takes a `credential` parameter, so a tool wired to one
    is visible in the signature whether or not anyone passes it.
    """

    for tool, (method_name, _, _) in mcp_server.TOOLS.items():
        signature = inspect.signature(getattr(GitSupervisor, method_name))
        assert "credential" not in signature.parameters, f"{tool} can be authenticated"


def test_no_write_tool_is_exposed(repo: Path) -> None:
    for name in ("acp_claim", "acp_submit", "acp_heartbeat", "acp_integrate", "acp_gc"):
        assert body(call(repo, name))["error"] == "unknown_tool"


def test_the_server_holds_a_read_only_supervisor(repo: Path) -> None:
    """The stale-stamp gate: a read-only open refuses to migrate, so it must report.

    A server that had opened read-write would silently upgrade the database and answer
    normally, which is exactly the difference this asserts.
    """

    connection = __import__("sqlite3").connect(repo / ".acp" / "control.db")
    connection.execute("DELETE FROM meta WHERE key = 'schema_version'")
    connection.commit()
    connection.close()

    assert body(call(repo, "acp_queue"))["error"] == "schema_upgrade_required"

    still_unstamped = __import__("sqlite3").connect(repo / ".acp" / "control.db")
    try:
        rows = still_unstamped.execute(
            "SELECT COUNT(*) FROM meta WHERE key = 'schema_version'"
        ).fetchone()[0]
    finally:
        still_unstamped.close()
    assert rows == 0, "the server migrated the database it was only supposed to read"


def test_a_real_query_returns_real_data(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")

    result = call(repo, "acp_show", {"task_id": created["id"]})

    assert result["isError"] is False
    assert body(result)["id"] == created["id"]


def test_the_bundle_tool_cannot_be_used_to_read_other_files(repo: Path) -> None:
    """The traversal an untrusted caller would reach for (board #1709)."""

    (repo / ".acp" / "bundles").mkdir(parents=True, exist_ok=True)
    (repo / "outside.json").write_text('{"secret": 1}', encoding="utf-8")

    assert body(call(repo, "acp_bundle", {"qc_id": "../../outside"}))["error"] == "invalid_qc_id"


def test_undeclared_arguments_are_refused(repo: Path) -> None:
    """`additionalProperties: false` has to be enforced, not merely advertised."""

    assert body(call(repo, "acp_status", {"limit": 1}))["error"] == "invalid_arguments"
    assert body(call(repo, "acp_show", {}))["error"] == "invalid_arguments"


def test_a_malformed_line_does_not_kill_the_session(repo: Path) -> None:
    process = subprocess.run(
        [sys.executable, "-m", "agent_control_plane.cli", "--repo", str(repo), "mcp-serve"],
        input='not json\n{"jsonrpc":"2.0","id":9,"method":"tools/list"}\n',
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    replies = [json.loads(line) for line in process.stdout.splitlines() if line.strip()]
    assert replies[0]["error"]["code"] == -32700
    assert replies[1]["id"] == 9, "the server stopped after one bad line"


def test_stdout_carries_protocol_only(repo: Path) -> None:
    """One stray print corrupts the stream for the rest of the session."""

    sink = io.StringIO()
    mcp_server.serve(
        str(repo), stdin=iter(['{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n']), stdout=sink
    )
    for line in sink.getvalue().splitlines():
        json.loads(line)  # every line must parse as JSON-RPC
