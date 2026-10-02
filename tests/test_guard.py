"""`acp guard` — the check an editor asks before a tool call writes.

ACP allocates a worktree and a write set, then has no way to stop an agent editing the
base checkout instead. README's own "Honest boundaries" says so. The guard closes that
by answering the same question `submit` answers about the finished diff, with the same
`_path_matches`: two enforcement implementations that could disagree would be worse
than one, so the adapter asks and the supervisor decides.
"""

from __future__ import annotations

import io
import json
import shlex
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
from support import init_repo, make_task

from agent_control_plane.cli import main
from agent_control_plane.editor_hooks import (
    ACP_MANAGED_HOOK_FLAG,
    DENY_EXIT_CODE,
    GUARDED_TOOLS,
    install_claude_code_hooks,
    install_codex_hooks,
    parse_codex_patch_paths,
    path_from_hook_payload,
)
from agent_control_plane.git_supervisor import GitSupervisor, SupervisorError
from agent_control_plane.supervisor.claims import (
    FILE_SNAPSHOT_TTL_SECONDS,
    MAX_FILE_SNAPSHOTS_PER_ATTEMPT,
    WRITE_RESERVATION_TTL_SECONDS,
    _file_snapshot,
)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return init_repo(tmp_path)


@pytest.fixture
def claimed(repo: Path):
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    return supervisor, attempt


def test_a_declared_path_is_allowed(claimed) -> None:
    supervisor, attempt = claimed
    worktree = Path(attempt["worktree"])

    absolute = supervisor.guard(attempt["id"], str(worktree / "alpha.txt"), caller_cwd=worktree)
    relative = supervisor.guard(attempt["id"], "alpha.txt", caller_cwd=worktree)

    assert absolute["allow"] is True
    assert relative["allow"] is True
    assert relative["relative_path"] == "alpha.txt"


def test_same_attempt_write_reservations_block_until_the_tool_finishes(claimed) -> None:
    supervisor, attempt = claimed
    worktree = Path(attempt["worktree"])
    first = supervisor._reserve_write(
        attempt["id"],
        "alpha.txt",
        caller_cwd=worktree,
        tool_use_id="tool-1",
        agent_id="subagent-1",
    )
    competing = supervisor._reserve_write(
        attempt["id"],
        "alpha.txt",
        caller_cwd=worktree,
        tool_use_id="tool-2",
        agent_id="subagent-2",
    )

    assert first["allow"] is True
    assert first["write_reservation"] == "held"
    assert competing["allow"] is False
    assert competing["reason"] == "concurrent_write_conflict"
    assert competing["retry_after_seconds"] == WRITE_RESERVATION_TTL_SECONDS
    assert supervisor._release_write(attempt["id"], "tool-1", agent_id="subagent-1") is True
    assert supervisor._release_write(attempt["id"], "tool-1", agent_id="subagent-1") is False
    assert (
        supervisor._reserve_write(
            attempt["id"],
            "alpha.txt",
            caller_cwd=worktree,
            tool_use_id="tool-2",
            agent_id="subagent-2",
        )["allow"]
        is True
    )


def test_same_tool_use_id_cannot_cross_agent_boundaries_or_release_another_agent(
    claimed,
) -> None:
    supervisor, attempt = claimed
    worktree = Path(attempt["worktree"])
    first = supervisor._reserve_write(
        attempt["id"],
        "alpha.txt",
        caller_cwd=worktree,
        tool_use_id="reused-tool-id",
        agent_id="subagent-1",
    )
    duplicate = supervisor._reserve_write(
        attempt["id"],
        "alpha.txt",
        caller_cwd=worktree,
        tool_use_id="reused-tool-id",
        agent_id="subagent-2",
    )

    assert first["allow"] is True
    assert duplicate["allow"] is False
    assert duplicate["reason"] == "write_identity_conflict"
    assert (
        supervisor._release_write(attempt["id"], "reused-tool-id", agent_id="subagent-2") is False
    )
    assert (
        supervisor._reserve_write(
            attempt["id"],
            "alpha.txt",
            caller_cwd=worktree,
            tool_use_id="other-tool-id",
            agent_id="subagent-2",
        )["reason"]
        == "concurrent_write_conflict"
    )
    assert supervisor._release_write(attempt["id"], "reused-tool-id", agent_id="subagent-1") is True
    assert (
        supervisor._reserve_write(
            attempt["id"],
            "alpha.txt",
            caller_cwd=worktree,
            tool_use_id="reused-tool-id",
            agent_id="subagent-2",
        )["allow"]
        is True
    )


def test_same_attempt_write_reservations_allow_disjoint_paths_and_expire_after_crash(
    repo: Path,
) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "src/**", "docs/**")
    attempt = supervisor.claim(
        created["id"], "worker", lease_seconds=WRITE_RESERVATION_TTL_SECONDS * 2
    )
    worktree = Path(attempt["worktree"])
    now = int(time.time())

    source = supervisor._reserve_write(
        attempt["id"], "src/main.py", caller_cwd=worktree, tool_use_id="tool-src", now=now
    )
    reused_identity = supervisor._reserve_write(
        attempt["id"], "docs/readme.md", caller_cwd=worktree, tool_use_id="tool-src", now=now
    )
    docs = supervisor._reserve_write(
        attempt["id"], "docs/readme.md", caller_cwd=worktree, tool_use_id="tool-docs", now=now
    )
    assert source["allow"] is True
    assert reused_identity["allow"] is False
    assert reused_identity["reason"] == "write_identity_conflict"
    assert docs["allow"] is True

    expired_retry = supervisor._reserve_write(
        attempt["id"],
        "src/main.py",
        caller_cwd=worktree,
        tool_use_id="tool-after-crash",
        now=now + WRITE_RESERVATION_TTL_SECONDS,
    )
    assert expired_retry["allow"] is True


def test_simultaneous_same_attempt_reservations_are_atomic(claimed, monkeypatch) -> None:
    supervisor, attempt = claimed
    worktree = Path(attempt["worktree"])
    barrier = Barrier(2)
    original_guard = supervisor.guard

    def synchronized_guard(path_attempt, path, *, caller_cwd=None, now=None):
        result = original_guard(path_attempt, path, caller_cwd=caller_cwd, now=now)
        barrier.wait(timeout=5)
        return result

    monkeypatch.setattr(supervisor, "guard", synchronized_guard)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(
                supervisor._reserve_write,
                attempt["id"],
                "alpha.txt",
                caller_cwd=worktree,
                tool_use_id=f"tool-{index}",
                agent_id=f"agent-{index}",
            )
            for index in (1, 2)
        ]
        results = [future.result(timeout=10) for future in futures]

    assert sum(result["allow"] for result in results) == 1
    assert sum(result.get("reason") == "concurrent_write_conflict" for result in results) == 1


def test_an_undeclared_path_in_the_worktree_is_denied(claimed) -> None:
    supervisor, attempt = claimed
    decision = supervisor.guard(
        attempt["id"], str(Path(attempt["worktree"]) / "beta.txt"), caller_cwd=attempt["worktree"]
    )

    assert decision["allow"] is False
    assert decision["reason"] == "undeclared_write"
    # The agent is told what it MAY write, so it can correct itself in one turn.
    assert decision["declared"] == ["alpha.txt"]


def test_the_base_checkout_is_denied_even_for_a_declared_file(claimed, repo: Path) -> None:
    """The hole this exists to close.

    alpha.txt IS in the write set — but the copy in the base checkout is not the one
    the attempt leased, and editing it is exactly how an agent defeats every claim and
    fence without ACP noticing.
    """

    decision = claimed[0].guard(
        claimed[1]["id"], str(repo / "alpha.txt"), caller_cwd=claimed[1]["worktree"]
    )

    assert decision["allow"] is False
    assert decision["reason"] == "outside_worktree"


@pytest.mark.parametrize("escape", ["../../../etc/passwd", "/etc/passwd"])
def test_paths_outside_the_worktree_are_denied(claimed, escape: str) -> None:
    decision = claimed[0].guard(claimed[1]["id"], escape, caller_cwd=claimed[1]["worktree"])
    assert decision["allow"] is False
    assert decision["reason"] == "outside_worktree"


def test_a_symlink_out_of_the_worktree_is_denied(claimed) -> None:
    """A link planted inside the worktree must not launder a write out of it."""

    supervisor, attempt = claimed
    link = Path(attempt["worktree"]) / "alpha.txt"
    link.unlink()
    link.symlink_to("/etc/passwd")

    decision = supervisor.guard(attempt["id"], str(link), caller_cwd=attempt["worktree"])

    assert decision["allow"] is False
    assert decision["reason"] == "outside_worktree"


def test_a_glob_write_set_is_matched_the_same_way_submit_matches_it(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "src/**")
    attempt = supervisor.claim(created["id"], "worker")

    assert (
        supervisor.guard(attempt["id"], "src/deep/module.py", caller_cwd=attempt["worktree"])[
            "allow"
        ]
        is True
    )
    assert (
        supervisor.guard(attempt["id"], "alpha.txt", caller_cwd=attempt["worktree"])["allow"]
        is False
    )


def test_guard_and_submit_agree(claimed) -> None:
    """The single-implementation claim, asserted rather than asserted-in-a-comment.

    If these ever diverge, an agent is allowed to write something its own submission
    will be rejected for — the worst of both, discovered at the end of the work.
    """

    supervisor, attempt = claimed
    worktree = Path(attempt["worktree"])
    assert (
        supervisor.guard(attempt["id"], str(worktree / "beta.txt"), caller_cwd=worktree)["allow"]
        is False
    )

    (worktree / "beta.txt").write_text("undeclared\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(worktree), "add", "-A"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(worktree), "commit", "-m", "undeclared"],
        check=True,
        capture_output=True,
    )
    with pytest.raises(SupervisorError) as error:
        supervisor.submit(attempt["id"], attempt["claim_token"])
    assert error.value.code == "undeclared_write"


def test_a_stale_lease_is_denied(claimed) -> None:
    supervisor, attempt = claimed
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET lease_expires_at = 0 WHERE id = ?", (attempt["id"],)
        )

    decision = supervisor.guard(attempt["id"], "alpha.txt", caller_cwd=attempt["worktree"])

    assert decision["allow"] is False
    assert decision["reason"] == "lease_expired"


def test_an_attempt_that_is_not_live_is_denied(claimed) -> None:
    supervisor, attempt = claimed
    with supervisor.connect() as connection:
        connection.execute("UPDATE attempts SET status = 'orphaned' WHERE id = ?", (attempt["id"],))

    decision = supervisor.guard(attempt["id"], "alpha.txt", caller_cwd=attempt["worktree"])

    assert decision["allow"] is False
    assert decision["reason"] == "attempt_not_live"


def test_an_unknown_attempt_is_denied(repo: Path) -> None:
    decision = GitSupervisor(repo).guard("no-such-attempt", "alpha.txt", caller_cwd=repo)
    assert decision["allow"] is False
    assert decision["reason"] == "attempt_not_found"


def test_guard_runs_on_a_read_only_supervisor(claimed, repo: Path) -> None:
    """A pre-write check must never itself be a reason the state changed."""

    viewer = GitSupervisor(repo, read_only=True)
    assert (
        viewer.guard(claimed[1]["id"], "alpha.txt", caller_cwd=claimed[1]["worktree"])["allow"]
        is True
    )


def test_guard_context_reports_the_boundary(claimed) -> None:
    supervisor, attempt = claimed
    context = supervisor.guard_context(attempt["id"])
    assert context["declared"] == ["alpha.txt"]
    assert context["worktree"] == attempt["worktree"]
    assert context["branch"] == attempt["branch"]


def run_hook(repo: Path, attempt_id: str, payload: str, monkeypatch) -> int:
    monkeypatch.setenv("ACP_ATTEMPT_ID", attempt_id)
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    return main(["--repo", str(repo), "guard", "--hook"])


def run_snapshot_hook(repo: Path, attempt_id: str, payload: str, monkeypatch) -> int:
    monkeypatch.setenv("ACP_ATTEMPT_ID", attempt_id)
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    return main(["--repo", str(repo), "snapshot", "--hook", "--acp-managed-hook"])


def run_freshness_guard(repo: Path, attempt_id: str, payload: str, monkeypatch) -> int:
    monkeypatch.setenv("ACP_ATTEMPT_ID", attempt_id)
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    return main(["--repo", str(repo), "guard", "--hook", "--freshness", "--acp-managed-hook"])


def run_codex_hook(repo: Path, attempt_id: str, payload: str, monkeypatch) -> int:
    monkeypatch.setenv("ACP_ATTEMPT_ID", attempt_id)
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    return main(["--repo", str(repo), "guard", "--codex-hook"])


def test_hook_mode_exit_codes(claimed, repo: Path, monkeypatch) -> None:
    _, attempt = claimed
    worktree = Path(attempt["worktree"])

    allowed = json.dumps(
        {
            "cwd": str(worktree),
            "tool_name": "Edit",
            "tool_input": {"file_path": str(worktree / "alpha.txt")},
        }
    )
    denied = json.dumps(
        {
            "cwd": str(worktree),
            "tool_name": "Edit",
            "tool_input": {"file_path": str(worktree / "beta.txt")},
        }
    )

    assert run_hook(repo, attempt["id"], allowed, monkeypatch) == 0
    assert run_hook(repo, attempt["id"], denied, monkeypatch) == DENY_EXIT_CODE


def test_opt_in_freshness_hook_denies_a_full_write_after_the_file_changes(
    claimed, repo: Path, monkeypatch, capsys
) -> None:
    supervisor, attempt = claimed
    worktree = Path(attempt["worktree"])
    target = worktree / "alpha.txt"
    target.write_text("agent read this\n", encoding="utf-8")
    read_payload = json.dumps(
        {"cwd": str(worktree), "tool_name": "Read", "tool_input": {"file_path": str(target)}}
    )
    write_payload = json.dumps(
        {
            "cwd": str(worktree),
            "tool_name": "Write",
            "tool_input": {"file_path": str(target), "content": "stale agent content\n"},
        }
    )

    assert run_snapshot_hook(repo, attempt["id"], read_payload, monkeypatch) == 0
    assert run_freshness_guard(repo, attempt["id"], write_payload, monkeypatch) == 0
    capsys.readouterr()

    target.write_text("newer human edit\n", encoding="utf-8")
    assert run_freshness_guard(repo, attempt["id"], write_payload, monkeypatch) == DENY_EXIT_CODE
    denial = json.loads(capsys.readouterr().out)
    assert denial["reason"] == "stale_file_snapshot"
    assert target.read_text(encoding="utf-8") == "newer human edit\n"

    assert run_snapshot_hook(repo, attempt["id"], read_payload, monkeypatch) == 0
    assert run_freshness_guard(repo, attempt["id"], write_payload, monkeypatch) == 0
    capsys.readouterr()


def test_opt_in_freshness_detects_a_changed_file_restored_to_the_same_bytes(
    claimed, repo: Path, monkeypatch, capsys
) -> None:
    _, attempt = claimed
    worktree = Path(attempt["worktree"])
    target = worktree / "alpha.txt"
    original = "contents Claude read\n"
    target.write_text(original, encoding="utf-8")
    read_payload = json.dumps(
        {"cwd": str(worktree), "tool_name": "Read", "tool_input": {"file_path": str(target)}}
    )
    write_payload = json.dumps(
        {
            "cwd": str(worktree),
            "tool_name": "Write",
            "tool_input": {"file_path": str(target), "content": "stale replacement\n"},
        }
    )

    assert run_snapshot_hook(repo, attempt["id"], read_payload, monkeypatch) == 0
    target.write_text("intervening edit\n", encoding="utf-8")
    target.write_text(original, encoding="utf-8")

    assert run_freshness_guard(repo, attempt["id"], write_payload, monkeypatch) == DENY_EXIT_CODE
    assert json.loads(capsys.readouterr().out)["reason"] == "stale_file_snapshot"
    assert target.read_text(encoding="utf-8") == original


def test_opt_in_freshness_detects_a_swapped_and_restored_parent_directory(
    claimed, repo: Path
) -> None:
    supervisor, _ = claimed
    created = make_task(supervisor, "nested/alpha.txt")
    attempt = supervisor.claim(created["id"], "worker-two")
    worktree = Path(attempt["worktree"])
    parent = worktree / "nested"
    parent.mkdir()
    target = parent / "alpha.txt"
    target.write_text("contents Claude read\n", encoding="utf-8")
    assert supervisor.record_file_snapshot(attempt["id"], "nested/alpha.txt", caller_cwd=worktree)[
        "recorded"
    ]

    moved_original = worktree / "nested.original"
    replacement = worktree / "nested.replacement"
    parent.rename(moved_original)
    parent.mkdir()
    (parent / "alpha.txt").write_text("different file Claude actually read\n", encoding="utf-8")
    assert target.read_text(encoding="utf-8") == "different file Claude actually read\n"

    parent.rename(replacement)
    moved_original.rename(parent)
    assert target.read_text(encoding="utf-8") == "contents Claude read\n"
    decision = supervisor.check_file_snapshot(
        attempt["id"], "nested/alpha.txt", caller_cwd=worktree
    )
    assert decision["reason"] == "stale_file_snapshot"


def test_opt_in_freshness_requires_snapshot_for_existing_file_but_allows_creation(
    repo: Path, monkeypatch, capsys
) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt", "new.txt")
    attempt = supervisor.claim(created["id"], "worker")
    worktree = Path(attempt["worktree"])
    existing_payload = json.dumps(
        {
            "cwd": str(worktree),
            "tool_name": "Write",
            "tool_input": {"file_path": str(worktree / "alpha.txt"), "content": "replacement"},
        }
    )
    new_payload = json.dumps(
        {
            "cwd": str(worktree),
            "tool_name": "Write",
            "tool_input": {"file_path": str(worktree / "new.txt"), "content": "new"},
        }
    )

    assert run_freshness_guard(repo, attempt["id"], existing_payload, monkeypatch) == DENY_EXIT_CODE
    assert json.loads(capsys.readouterr().out)["reason"] == "freshness_snapshot_missing"
    assert run_freshness_guard(repo, attempt["id"], new_payload, monkeypatch) == 0
    capsys.readouterr()


def test_absent_file_snapshot_denies_when_another_writer_creates_the_path(
    repo: Path, monkeypatch, capsys
) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "new.txt")
    attempt = supervisor.claim(created["id"], "worker")
    worktree = Path(attempt["worktree"])
    target = worktree / "new.txt"
    read_payload = json.dumps(
        {"cwd": str(worktree), "tool_name": "Read", "tool_input": {"file_path": str(target)}}
    )
    write_payload = json.dumps(
        {
            "cwd": str(worktree),
            "tool_name": "Write",
            "tool_input": {"file_path": str(target), "content": "agent contents\n"},
        }
    )

    assert run_snapshot_hook(repo, attempt["id"], read_payload, monkeypatch) == 0
    target.write_text("another writer created this\n", encoding="utf-8")
    assert run_freshness_guard(repo, attempt["id"], write_payload, monkeypatch) == DENY_EXIT_CODE
    assert json.loads(capsys.readouterr().out)["reason"] == "stale_file_snapshot"


def test_a_successful_write_requires_a_new_read_before_another_full_replacement(
    claimed, repo: Path, monkeypatch, capsys
) -> None:
    _, attempt = claimed
    worktree = Path(attempt["worktree"])
    target = worktree / "alpha.txt"
    target.write_text("initial contents\n", encoding="utf-8")
    read_payload = json.dumps(
        {"cwd": str(worktree), "tool_name": "Read", "tool_input": {"file_path": str(target)}}
    )
    write_payload = json.dumps(
        {
            "cwd": str(worktree),
            "tool_name": "Write",
            "tool_input": {"file_path": str(target), "content": "agent replacement\n"},
        }
    )

    assert run_snapshot_hook(repo, attempt["id"], read_payload, monkeypatch) == 0
    target.write_text("agent replacement\n", encoding="utf-8")
    assert run_freshness_guard(repo, attempt["id"], write_payload, monkeypatch) == DENY_EXIT_CODE
    assert json.loads(capsys.readouterr().out)["reason"] == "stale_file_snapshot"

    assert run_snapshot_hook(repo, attempt["id"], read_payload, monkeypatch) == 0
    assert run_freshness_guard(repo, attempt["id"], write_payload, monkeypatch) == 0
    capsys.readouterr()


def test_file_snapshot_rejects_a_symlink_instead_of_following_it(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("private contents\n", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(outside)

    with pytest.raises(ValueError, match="regular files"):
        _file_snapshot(link, root=tmp_path)

    assert outside.read_text(encoding="utf-8") == "private contents\n"


def test_file_snapshot_rejects_a_file_that_changes_while_being_hashed(
    tmp_path: Path, monkeypatch
) -> None:
    import os

    target = tmp_path / "changing.txt"
    target.write_text("initial contents\n", encoding="utf-8")
    real_fstat = os.fstat
    calls = 0

    def change_before_second_stat(descriptor):
        nonlocal calls
        calls += 1
        if calls == 2:
            target.write_text("changed while hashing\n", encoding="utf-8")
        return real_fstat(descriptor)

    monkeypatch.setattr("agent_control_plane.supervisor.claims.os.fstat", change_before_second_stat)
    with pytest.raises(OSError, match="changed while"):
        _file_snapshot(target, root=tmp_path)


def test_file_snapshot_rejects_parent_symlink_swap_after_guard(
    repo: Path, tmp_path: Path, monkeypatch
) -> None:
    supervisor = GitSupervisor(repo)
    task = make_task(supervisor, "nested/**")
    attempt = supervisor.claim(task["id"], "worker")
    worktree = Path(attempt["worktree"])
    parent = worktree / "nested"
    parent.mkdir()
    target = parent / "alpha.txt"
    target.write_text("same snapshot bytes\n", encoding="utf-8")
    external = tmp_path / "external"
    external.mkdir()
    (external / target.name).write_text("same snapshot bytes\n", encoding="utf-8")
    assert supervisor.record_file_snapshot(attempt["id"], "nested/alpha.txt", caller_cwd=worktree)[
        "recorded"
    ]

    moved_parent = worktree / "nested.original"
    from agent_control_plane.supervisor import claims

    real_snapshot = claims._file_snapshot

    def swap_then_snapshot(path: Path, *, root: Path):
        parent.rename(moved_parent)
        parent.symlink_to(external, target_is_directory=True)
        try:
            return real_snapshot(path, root=root)
        finally:
            parent.unlink()
            moved_parent.rename(parent)

    monkeypatch.setattr(claims, "_file_snapshot", swap_then_snapshot)
    decision = supervisor.check_file_snapshot(
        attempt["id"], "nested/alpha.txt", caller_cwd=worktree
    )

    assert decision["allow"] is False
    assert decision["reason"] == "freshness_snapshot_unavailable"
    assert (external / target.name).read_text(encoding="utf-8") == "same snapshot bytes\n"
    assert target.read_text(encoding="utf-8") == "same snapshot bytes\n"


def test_file_snapshots_are_isolated_per_attempt(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    first_task = make_task(supervisor, "alpha.txt", title="first")
    second_task = make_task(supervisor, "beta.txt", title="second")
    first = supervisor.claim(first_task["id"], "worker-first")
    second = supervisor.claim(second_task["id"], "worker-second")
    first_worktree = Path(first["worktree"])
    second_worktree = Path(second["worktree"])

    assert supervisor.record_file_snapshot(first["id"], "alpha.txt", caller_cwd=first_worktree)[
        "recorded"
    ]
    decision = supervisor.check_file_snapshot(second["id"], "beta.txt", caller_cwd=second_worktree)
    assert decision["allow"] is False
    assert decision["reason"] == "freshness_snapshot_missing"
    assert supervisor.record_file_snapshot(second["id"], "beta.txt", caller_cwd=second_worktree)[
        "recorded"
    ]
    with supervisor.connect() as connection:
        rows = connection.execute(
            "SELECT attempt_id, path FROM file_snapshots ORDER BY attempt_id"
        ).fetchall()
    assert {(row["attempt_id"], Path(row["path"]).name) for row in rows} == {
        (first["id"], "alpha.txt"),
        (second["id"], "beta.txt"),
    }


def test_snapshot_cannot_bypass_attempt_write_set(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    task = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(task["id"], "worker")
    worktree = Path(attempt["worktree"])
    outside_write_set = supervisor.record_file_snapshot(
        attempt["id"], "beta.txt", caller_cwd=worktree
    )

    assert outside_write_set["recorded"] is False
    assert outside_write_set["reason"] == "undeclared_write"
    with supervisor.connect() as connection:
        rows = connection.execute(
            "SELECT COUNT(*) FROM file_snapshots WHERE attempt_id = ?", (attempt["id"],)
        ).fetchone()[0]
    assert rows == 0


def test_expired_snapshot_is_denied_even_when_the_attempt_lease_is_live(repo: Path) -> None:
    import time

    supervisor = GitSupervisor(repo)
    task = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(task["id"], "worker", lease_seconds=FILE_SNAPSHOT_TTL_SECONDS * 2)
    worktree = Path(attempt["worktree"])
    now = int(time.time())
    assert supervisor.record_file_snapshot(
        attempt["id"], "alpha.txt", caller_cwd=worktree, now=now
    )["recorded"]

    decision = supervisor.check_file_snapshot(
        attempt["id"], "alpha.txt", caller_cwd=worktree, now=now + FILE_SNAPSHOT_TTL_SECONDS + 1
    )
    assert decision["allow"] is False
    assert decision["reason"] == "freshness_snapshot_expired"


def test_snapshot_history_is_bounded_per_attempt(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    task = make_task(supervisor, "src/**")
    attempt = supervisor.claim(task["id"], "worker")
    worktree = Path(attempt["worktree"])
    source_dir = worktree / "src"
    source_dir.mkdir()

    for index in range(MAX_FILE_SNAPSHOTS_PER_ATTEMPT + 1):
        relative = f"src/file-{index}.txt"
        (worktree / relative).write_text(str(index), encoding="utf-8")
        result = supervisor.record_file_snapshot(attempt["id"], relative, caller_cwd=worktree)
        assert result["recorded"]

    with supervisor.connect() as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM file_snapshots WHERE attempt_id = ?", (attempt["id"],)
        ).fetchone()[0]
    assert count == MAX_FILE_SNAPSHOTS_PER_ATTEMPT


@pytest.mark.parametrize("payload", ["not json at all", "{}", '{"tool_input": {}}', "[]"])
def test_an_unreadable_payload_fails_closed(claimed, repo: Path, monkeypatch, payload: str) -> None:
    """Allowing what it cannot parse would let the boundary vanish on a schema change."""

    assert run_hook(repo, claimed[1]["id"], payload, monkeypatch) == DENY_EXIT_CODE


def test_path_from_hook_payload_reads_the_editing_tools() -> None:
    assert path_from_hook_payload({"tool_input": {"file_path": "a.py"}}) == "a.py"
    assert path_from_hook_payload({"tool_input": {"notebook_path": "n.ipynb"}}) == "n.ipynb"
    assert path_from_hook_payload({"tool_input": {"command": "rm -rf /"}}) is None
    assert path_from_hook_payload("nonsense") is None


@pytest.mark.parametrize(
    ("patch", "expected"),
    [
        ("*** Add File: nested/new.py\n+new\n", ["nested/new.py"]),
        ("*** Update File: alpha.txt\n@@\n-old\n+new\n", ["alpha.txt"]),
        ("*** Update File: alpha.txt\n@@\n context line\n+new line\n", ["alpha.txt"]),
        (
            "*** Update File: alpha.txt\n@@\n-old\n+new\n*** End of File\n   \n",
            ["alpha.txt"],
        ),
        (
            "*** Update File: alpha.txt\n*** End of File\n@@\n+new line\n",
            ["alpha.txt"],
        ),
        ("*** Delete File: old.py\n", ["old.py"]),
        (
            "*** Update File: old.py\n*** Move to: nested/new.py\n@@\n-old\n+new\n",
            ["old.py", "nested/new.py"],
        ),
        ("*** Add File: /tmp/outside.py\n", ["/tmp/outside.py"]),
        ("*** Add File:  leading-space.py\n", [" leading-space.py"]),
        ("*** Add File: trailing-space.py \n", ["trailing-space.py"]),
        ("*** Add File: trailing-space.py   \n", ["trailing-space.py"]),
    ],
)
def test_parse_codex_patch_paths(patch: str, expected: list[str]) -> None:
    wrapped = f"*** Begin Patch\n{patch}*** End Patch"
    assert parse_codex_patch_paths(wrapped) == expected


@pytest.mark.parametrize(
    "patch",
    [
        "",
        "*** Add File: alpha.txt\n+no envelope\n",
        "*** Begin Patch\n*** End Patch",
        "*** Begin Patch\n*** Copy File: alpha.txt\n*** End Patch",
        "*** Begin Patch\n*** Add File: \n*** End Patch",
        "*** Begin Patch\n*** Update File: alpha.txt\n*** End Patch",
        "*** Begin Patch\n*** Update File: alpha.txt\nraw context line\n*** End Patch",
        "*** Begin Patch\n*** Update File: alpha.txt\n@@\n*** End Patch",
        "*** Begin Patch\n*** Update File: old.py\n*** Move to: new.py\n*** End Patch",
        "*** Begin Patch\n*** Update File: alpha.txt\n@@\n-old\n+new\n@@\n*** End Patch",
        "*** Begin Patch\n*** Update File: alpha.txt\n@@\n-old\n+new\n@@\n*** End of File\n*** End Patch",
        "*** Begin Patch\n*** Environment ID: \n*** Add File: alpha.txt\n+x\n*** End Patch",
        "*** Begin Patch\n*** Environment ID: remote-env\n*** Add File: alpha.txt\n+x\n*** End Patch",
        "*** Begin Patch\n*** Add File: alpha.txt\n+x\n*** Environment ID: too-late\n*** End Patch",
        "*** Begin Patch\n*** Update File: alpha.txt\n@@\n-old\n+new\n*** Move to: moved.txt\n*** End Patch",
        "*** Begin Patch\n*** Delete File: alpha.txt\nunexpected\n*** End Patch",
    ],
)
def test_parse_codex_patch_paths_rejects_unrecognized_or_malformed_input(patch: str) -> None:
    with pytest.raises(ValueError):
        parse_codex_patch_paths(patch)


@pytest.mark.parametrize("control", ["\x1c", "\x1d", "\x1e", "\x1f"])
@pytest.mark.parametrize(
    "operation_patch",
    [
        "*** Add File: safe.txt{control}\n+content\n",
        "*** Update File: safe.txt{control}\n@@\n+content\n",
        "*** Delete File: safe.txt{control}\n",
        "*** Update File: old.txt\n*** Move to: safe.txt{control}\n@@\n+content\n",
    ],
)
def test_parse_codex_patch_paths_rejects_python_rust_trim_mismatch_controls(
    control: str, operation_patch: str
) -> None:
    patch = f"*** Begin Patch\n{operation_patch.format(control=control)}*** End Patch"
    with pytest.raises(ValueError, match="control characters"):
        parse_codex_patch_paths(patch)


def test_parse_codex_patch_paths_bounds_input_size_and_file_count() -> None:
    from agent_control_plane.editor_hooks import CODEX_MAX_PATCH_CHARS

    with pytest.raises(ValueError, match="character safety limit"):
        parse_codex_patch_paths("x" * (CODEX_MAX_PATCH_CHARS + 1))

    operations = "\n".join(f"*** Add File: file-{index}.txt" for index in range(129))
    patch = f"*** Begin Patch\n{operations}\n*** End Patch"
    with pytest.raises(ValueError, match="128-path"):
        parse_codex_patch_paths(patch)


def test_parse_codex_patch_paths_keeps_unicode_line_separator_inside_filename() -> None:
    path = "safe/\u2028+../../../../outside.txt"
    patch = f"*** Begin Patch\n*** Add File: {path}\n+escaped\n*** End Patch"
    assert parse_codex_patch_paths(patch) == [path]


def test_codex_hook_checks_every_path_and_denies_entire_mixed_patch(
    claimed, repo: Path, monkeypatch, capsys
) -> None:
    import sqlite3

    supervisor, attempt = claimed
    worktree = Path(attempt["worktree"])
    patch = (
        "*** Begin Patch\n"
        "*** Update File: alpha.txt\n@@\n-old\n+new\n"
        "*** Add File: beta.txt\n+new\n"
        "*** End Patch"
    )
    payload = json.dumps(
        {
            "cwd": str(worktree),
            "hook_event_name": "PreToolUse",
            "tool_name": "apply_patch",
            "tool_input": {"command": patch},
        }
    )
    calls: list[str] = []
    original_guard = GitSupervisor.guard

    def record_guard(self, attempt_id, path, *, caller_cwd=None, now=None):
        calls.append(path)
        return original_guard(self, attempt_id, path, caller_cwd=caller_cwd, now=now)

    monkeypatch.setattr(GitSupervisor, "guard", record_guard)
    with sqlite3.connect(repo / ".acp" / "control.db") as connection:
        before_events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    assert run_codex_hook(repo, attempt["id"], payload, monkeypatch) == 0
    assert calls == ["alpha.txt", "beta.txt"]
    response = json.loads(capsys.readouterr().out)
    assert response["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"

    with sqlite3.connect(repo / ".acp" / "control.db") as connection:
        after_events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert after_events == before_events
    assert supervisor.attempt(attempt["id"])["status"] == "working"


def test_codex_hook_allows_a_declared_patch_without_output_or_side_effects(
    claimed, repo: Path, monkeypatch, capsys
) -> None:
    import sqlite3

    _, attempt = claimed
    worktree = Path(attempt["worktree"])
    patch = "*** Begin Patch\n*** Update File: alpha.txt\n@@\n-old\n+new\n*** End Patch"
    payload = json.dumps(
        {
            "cwd": str(worktree),
            "hook_event_name": "PreToolUse",
            "tool_name": "apply_patch",
            "tool_input": {"command": patch},
        }
    )
    with sqlite3.connect(repo / ".acp" / "control.db") as connection:
        before_events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    assert run_codex_hook(repo, attempt["id"], payload, monkeypatch) == 0
    assert capsys.readouterr().out == ""
    with sqlite3.connect(repo / ".acp" / "control.db") as connection:
        after_events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert after_events == before_events


def test_codex_hook_denies_environment_scoped_patch(
    claimed, repo: Path, monkeypatch, capsys
) -> None:
    attempt = claimed[1]
    worktree = Path(attempt["worktree"])
    patch = (
        "*** Begin Patch\n"
        "*** Environment ID: another-environment\n"
        "*** Update File: alpha.txt\n@@\n-old\n+new\n"
        "*** End Patch"
    )
    payload = json.dumps(
        {
            "cwd": str(worktree),
            "hook_event_name": "PreToolUse",
            "tool_name": "apply_patch",
            "tool_input": {"command": patch},
        }
    )

    assert run_codex_hook(repo, attempt["id"], payload, monkeypatch) == 0
    response = json.loads(capsys.readouterr().out)
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "environment-scoped" in response["hookSpecificOutput"]["permissionDecisionReason"]


def test_codex_hook_denies_unicode_line_separator_traversal(
    repo: Path, monkeypatch, capsys
) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "safe/**")
    attempt = supervisor.claim(created["id"], "worker")
    worktree = Path(attempt["worktree"])
    path = "safe/\u2028+../../../../outside.txt"
    patch = f"*** Begin Patch\n*** Add File: {path}\n+escaped\n*** End Patch"
    payload = json.dumps(
        {
            "cwd": str(worktree),
            "hook_event_name": "PreToolUse",
            "tool_name": "apply_patch",
            "tool_input": {"command": patch},
        }
    )
    calls: list[str] = []
    original_guard = GitSupervisor.guard

    def record_guard(self, attempt_id, target_path, *, caller_cwd=None, now=None):
        calls.append(target_path)
        return original_guard(self, attempt_id, target_path, caller_cwd=caller_cwd, now=now)

    monkeypatch.setattr(GitSupervisor, "guard", record_guard)

    assert run_codex_hook(repo, attempt["id"], payload, monkeypatch) == 0
    response = json.loads(capsys.readouterr().out)
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert calls == [path]


@pytest.mark.parametrize("path", ["../escape.py", "/tmp/escape.py"])
def test_codex_hook_denies_paths_outside_attempt_worktree(
    claimed, repo: Path, monkeypatch, capsys, path: str
) -> None:
    worktree = Path(claimed[1]["worktree"])
    patch = f"*** Begin Patch\n*** Add File: {path}\n+outside\n*** End Patch"
    payload = json.dumps(
        {
            "cwd": str(worktree),
            "hook_event_name": "PreToolUse",
            "tool_name": "apply_patch",
            "tool_input": {"command": patch},
        }
    )
    assert run_codex_hook(repo, claimed[1]["id"], payload, monkeypatch) == 0
    response = json.loads(capsys.readouterr().out)
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize(
    "payload",
    [
        "not json",
        "{}",
        json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "cwd": "/tmp",
                "tool_input": {"command": "echo hi"},
            }
        ),
        json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "apply_patch",
                "cwd": "/tmp",
                "tool_input": {},
            }
        ),
        json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "apply_patch",
                "cwd": "/tmp",
                "tool_input": {
                    "command": "*** Begin Patch\n*** Add File: alpha.txt\n+x\n*** End Patch"
                },
            }
        ),
        json.dumps(
            {
                "tool_name": "apply_patch",
                "cwd": "/tmp",
                "tool_input": {
                    "command": "*** Begin Patch\n*** Add File: alpha.txt\n+x\n*** End Patch"
                },
            }
        ),
    ],
)
def test_codex_hook_denies_missing_context_and_malformed_payload(
    claimed, repo: Path, monkeypatch, capsys, payload: str
) -> None:
    assert run_codex_hook(repo, claimed[1]["id"], payload, monkeypatch) == 0
    response = json.loads(capsys.readouterr().out)
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_codex_hook_denies_guard_exceptions(claimed, repo: Path, monkeypatch, capsys) -> None:
    def fail_guard(*args, **kwargs):
        raise RuntimeError("simulated unreadable control state")

    monkeypatch.setattr(GitSupervisor, "guard", fail_guard)
    worktree = Path(claimed[1]["worktree"])
    patch = "*** Begin Patch\n*** Update File: alpha.txt\n@@\n-old\n+new\n*** End Patch"
    payload = json.dumps(
        {
            "cwd": str(worktree),
            "hook_event_name": "PreToolUse",
            "tool_name": "apply_patch",
            "tool_input": {"command": patch},
        }
    )
    assert run_codex_hook(repo, claimed[1]["id"], payload, monkeypatch) == 0
    response = json.loads(capsys.readouterr().out)
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "could not decide" in response["hookSpecificOutput"]["permissionDecisionReason"]


def test_guard_requires_caller_context_and_resolves_relative_paths_from_it(claimed) -> None:
    supervisor, attempt = claimed
    worktree = Path(attempt["worktree"])
    nested = worktree / "nested"
    nested.mkdir()
    assert supervisor.guard(attempt["id"], "alpha.txt")["reason"] == "caller_context_missing"
    assert supervisor.guard(attempt["id"], "../alpha.txt", caller_cwd=nested)["allow"] is True


def test_guard_denies_caller_in_base_or_sibling_worktree(
    claimed, repo: Path, tmp_path: Path
) -> None:
    supervisor, attempt = claimed
    sibling = tmp_path / "sibling"
    sibling.mkdir()
    for cwd in (repo, sibling):
        decision = supervisor.guard(attempt["id"], "alpha.txt", caller_cwd=cwd)
        assert decision["allow"] is False
        assert decision["reason"] == "caller_outside_worktree"


def test_hook_payload_requires_cwd(claimed, repo: Path, monkeypatch) -> None:
    _, attempt = claimed
    payload = json.dumps({"tool_name": "Edit", "tool_input": {"file_path": "alpha.txt"}})
    assert run_hook(repo, attempt["id"], payload, monkeypatch) == DENY_EXIT_CODE


def test_bash_is_not_claimed_to_be_guarded() -> None:
    """Guarding Bash by pattern-matching the command string would be theatre.

    A regex catches `rm -rf /etc` and misses `sh -c "$(...)"`, `tee`, a redirect built
    from a variable, or an editor invocation. Pretending otherwise would be worse than
    the gap, because it reads as coverage.
    """

    assert "Bash" not in GUARDED_TOOLS


def test_install_preserves_the_users_settings(tmp_path: Path) -> None:
    settings_path = tmp_path / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(
        json.dumps(
            {
                "model": "opus",
                "hooks": {
                    "PreToolUse": [
                        {"matcher": "Bash", "hooks": [{"type": "command", "command": "mine"}]}
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    install_claude_code_hooks(tmp_path)
    install_claude_code_hooks(tmp_path)  # twice: must not accumulate

    written = json.loads(settings_path.read_text(encoding="utf-8"))
    pre = written["hooks"]["PreToolUse"]
    assert written["model"] == "opus"
    assert any(hook["command"] == "mine" for entry in pre for hook in entry["hooks"])
    acp_entries = [
        hook for entry in pre for hook in entry["hooks"] if hook["command"].startswith("acp guard")
    ]
    assert len(acp_entries) == 1


def test_install_refuses_to_overwrite_unreadable_settings(tmp_path: Path) -> None:
    settings_path = tmp_path / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text("{ this is not json", encoding="utf-8")

    with pytest.raises(ValueError, match="not valid JSON"):
        install_claude_code_hooks(tmp_path)
    # The user's file is still theirs.
    assert settings_path.read_text(encoding="utf-8") == "{ this is not json"


def test_install_creates_settings_when_absent(tmp_path: Path) -> None:
    result = install_claude_code_hooks(tmp_path)
    written = json.loads(Path(result["settings"]).read_text(encoding="utf-8"))
    assert written["hooks"]["PreToolUse"][0]["matcher"] == "Edit|Write|MultiEdit|NotebookEdit"


def test_same_attempt_write_serialization_hooks_are_opt_in_and_idempotent(tmp_path: Path) -> None:
    install_claude_code_hooks(tmp_path, serialize_write_tools=True)
    settings_path = tmp_path / ".claude" / "settings.json"
    hooks = json.loads(settings_path.read_text(encoding="utf-8"))["hooks"]
    pre_commands = [
        hook["command"] for entry in hooks["PreToolUse"] for hook in entry.get("hooks", [])
    ]
    assert any("guard --hook --reserve-write" in command for command in pre_commands)
    for event in ("PostToolUse", "PostToolUseFailure", "PermissionDenied"):
        entries = hooks[event]
        assert len(entries) == 1
        assert entries[0]["matcher"] == "Edit|Write|MultiEdit|NotebookEdit"
        assert "write-finish --hook" in entries[0]["hooks"][0]["command"]

    install_claude_code_hooks(tmp_path, serialize_write_tools=True)
    hooks = json.loads(settings_path.read_text(encoding="utf-8"))["hooks"]
    assert (
        sum(
            "write-finish --hook" in hook.get("command", "")
            for entries in hooks.values()
            for entry in entries
            for hook in entry.get("hooks", [])
        )
        == 3
    )


def test_stale_write_guard_is_opt_in_and_reinstall_removes_only_acp_snapshot_hooks(
    tmp_path: Path,
) -> None:
    settings_path = tmp_path / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Read",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "/old/venv/acp snapshot --hook",
                                },
                                {
                                    "type": "command",
                                    "command": "echo acp guard --hook",
                                },
                                {
                                    "type": "command",
                                    "command": f"echo guard --hook {ACP_MANAGED_HOOK_FLAG}",
                                },
                                {"type": "command", "command": "my-read-audit"},
                            ],
                        }
                    ],
                    "PostToolUse": [
                        {"matcher": "Write", "hooks": [{"type": "command", "command": "my-audit"}]}
                    ],
                    "SessionStart": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "/old/venv/acp guard --describe",
                                }
                            ]
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )

    install_claude_code_hooks(tmp_path, command="/old/venv/acp", stale_write_guard=True)
    enabled = json.loads(settings_path.read_text(encoding="utf-8"))["hooks"]
    pre_hooks = [hook for entry in enabled["PreToolUse"] for hook in entry["hooks"]]
    assert any("guard --hook --freshness" in hook["command"] for hook in pre_hooks)
    assert any("snapshot --hook" in hook["command"] for hook in pre_hooks)
    assert any(hook["command"] == "my-read-audit" for hook in pre_hooks)
    assert enabled["PostToolUse"][0]["hooks"][0]["command"] == "my-audit"
    assert not any(
        "snapshot --hook" in hook["command"]
        for entry in enabled["PostToolUse"]
        for hook in entry.get("hooks", [])
    )

    install_claude_code_hooks(tmp_path, command="acp")
    disabled = json.loads(settings_path.read_text(encoding="utf-8"))["hooks"]
    commands = [
        hook["command"]
        for event in disabled.values()
        for entry in event
        for hook in entry.get("hooks", [])
    ]
    assert "my-audit" in commands
    assert "my-read-audit" in commands
    assert "echo acp guard --hook" in commands
    assert f"echo guard --hook {ACP_MANAGED_HOOK_FLAG}" in commands
    assert any(command.startswith("acp guard --describe ") for command in commands)
    assert not any(command.startswith("/old/venv/acp ") for command in commands)
    assert not any("snapshot --hook" in command for command in commands)
    assert not any("guard --hook --freshness" in command for command in commands)


def test_managed_hook_marker_removes_a_changed_wrapper_but_not_an_echo_hook(
    tmp_path: Path,
) -> None:
    settings_path = tmp_path / ".claude" / "settings.json"
    install_claude_code_hooks(tmp_path, command="uv run acp", stale_write_guard=True)
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    settings["hooks"]["PreToolUse"].append(
        {
            "matcher": "Read",
            "hooks": [
                {
                    "type": "command",
                    "command": f"echo guard --hook {ACP_MANAGED_HOOK_FLAG}",
                }
            ],
        }
    )
    python_user_command = (
        f"python -c 'print(1)' -m agent_control_plane.cli guard --hook {ACP_MANAGED_HOOK_FLAG}"
    )
    settings["hooks"]["PreToolUse"].append(
        {
            "matcher": "Read",
            "hooks": [{"type": "command", "command": python_user_command}],
        }
    )
    settings["hooks"]["SessionStart"].append(
        {
            "hooks": [
                {
                    "type": "command",
                    "command": (
                        f"python -m agent_control_plane.cli guard --describe "
                        f"{ACP_MANAGED_HOOK_FLAG}"
                    ),
                }
            ]
        }
    )
    settings_path.write_text(json.dumps(settings), encoding="utf-8")

    install_claude_code_hooks(tmp_path, command="acp")
    installed = json.loads(settings_path.read_text(encoding="utf-8"))["hooks"]
    commands = [
        hook["command"]
        for event in installed.values()
        for entry in event
        for hook in entry.get("hooks", [])
    ]
    assert f"echo guard --hook {ACP_MANAGED_HOOK_FLAG}" in commands
    assert python_user_command in commands
    assert not any(command.startswith("uv run acp ") for command in commands)
    assert not any(command.startswith("python -m agent_control_plane.cli ") for command in commands)


def test_codex_install_preserves_user_hooks_and_replaces_its_own_entry(tmp_path: Path) -> None:
    root = init_repo(tmp_path)
    hooks_path = root / ".codex" / "hooks.json"
    hooks_path.parent.mkdir(parents=True)
    hooks_path.write_text(
        json.dumps(
            {
                "description": "user hooks",
                "hooks": {
                    "SessionStart": [{"hooks": [{"type": "command", "command": "mine-start"}]}],
                    "PreToolUse": [
                        {"matcher": "^Bash$", "hooks": [{"type": "command", "command": "mine"}]},
                        {
                            "matcher": "^Bash$",
                            "hooks": [{"type": "command", "command": "custom guard --codex-hook"}],
                        },
                        {
                            "matcher": "^apply_patch$",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "acp --repo /path with spaces guard --codex-hook",
                                },
                                {"type": "command", "command": "notify-policy"},
                            ],
                        },
                        {
                            "matcher": "^apply_patch$",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "python3 /hooks/policy.py guard --codex-hook",
                                }
                            ],
                        },
                    ],
                },
            }
        ),
        encoding="utf-8",
    )

    result = install_codex_hooks(root, "acp --repo /path with spaces")
    install_codex_hooks(root, "acp --repo /path with spaces")

    written = json.loads(hooks_path.read_text(encoding="utf-8"))
    assert result["guarded_tools"] == ["apply_patch"]
    assert written["description"] == "user hooks"
    assert written["hooks"]["SessionStart"][0]["hooks"][0]["command"] == "mine-start"
    pre = written["hooks"]["PreToolUse"]
    assert any(entry["hooks"][0]["command"] == "mine" for entry in pre)
    assert any(entry["hooks"][0]["command"] == "custom guard --codex-hook" for entry in pre)
    assert any(
        entry["hooks"][0]["command"] == "python3 /hooks/policy.py guard --codex-hook"
        for entry in pre
    )
    assert any(hook["command"] == "notify-policy" for entry in pre for hook in entry["hooks"])
    acp_entries = [
        hook
        for entry in pre
        for hook in entry["hooks"]
        if hook.get("statusMessage") == "Checking ACP write scope"
    ]
    assert len(acp_entries) == 1
    assert acp_entries[0]["timeout"] == 15


def test_attempt_codex_hook_install_is_private_and_pins_base_repo(
    claimed, repo: Path, monkeypatch
) -> None:
    attempt = claimed[1]
    worktree = Path(attempt["worktree"])
    existing = worktree / ".codex" / "hooks.json"
    existing.parent.mkdir(parents=True)
    existing.write_text(
        json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": []}]}}),
        encoding="utf-8",
    )
    existing.chmod(0o600)

    assert (
        main(
            [
                "--repo",
                str(repo),
                "hooks",
                "install",
                "--codex-code",
                "--attempt",
                attempt["id"],
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "--repo",
                str(repo),
                "hooks",
                "install",
                "--codex-code",
                "--attempt",
                attempt["id"],
            ]
        )
        == 0
    )
    written = json.loads(existing.read_text(encoding="utf-8"))
    hook = written["hooks"]["PreToolUse"][-1]["hooks"][0]["command"]
    assert f"--repo {repo}" in hook
    assert f"--attempt {attempt['id']}" in hook
    assert len(written["hooks"]["PreToolUse"]) == 2
    assert existing.stat().st_mode & 0o777 == 0o600
    assert (
        subprocess.run(
            ["git", "-C", str(worktree), "check-ignore", "--no-index", "-q", ".codex/hooks.json"],
            check=False,
        ).returncode
        == 0
    )
    assert (
        subprocess.run(
            ["git", "-C", str(worktree), "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        == ""
    )

    monkeypatch.setenv("ACP_ATTEMPT_ID", attempt["id"])
    patch = "*** Begin Patch\n*** Update File: alpha.txt\n@@\n-old\n+new\n*** End Patch"
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "cwd": str(worktree),
                    "hook_event_name": "PreToolUse",
                    "tool_name": "apply_patch",
                    "tool_input": {"command": patch},
                }
            )
        ),
    )
    assert main(shlex.split(hook)[1:]) == 0


@pytest.mark.parametrize("contents", ["[]", "null", '"settings"'])
def test_install_refuses_non_object_settings_without_mutation(
    tmp_path: Path, contents: str
) -> None:
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(contents, encoding="utf-8")

    with pytest.raises(ValueError, match="must contain a JSON object"):
        install_claude_code_hooks(tmp_path, local=True)

    assert settings.read_text(encoding="utf-8") == contents
    exclude = tmp_path / ".git" / "info" / "exclude"
    assert not exclude.exists()


def test_attempt_install_refuses_symlinked_claude_directory(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    init_repo(root)
    exclude = root / ".git" / "info" / "exclude"
    exclude_before = exclude.read_bytes() if exclude.exists() else None
    external = tmp_path / "external"
    external.mkdir()
    (root / ".claude").symlink_to(external, target_is_directory=True)

    with pytest.raises(ValueError, match="symlinked settings directory"):
        install_claude_code_hooks(root, local=True)

    assert list(external.iterdir()) == []
    assert (exclude.read_bytes() if exclude.exists() else None) == exclude_before


def test_attempt_install_refuses_symlinked_local_settings_file(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    init_repo(root)
    external = tmp_path / "external-settings.json"
    external.write_text('{"model":"private"}\n', encoding="utf-8")
    settings = root / ".claude" / "settings.local.json"
    settings.parent.mkdir()
    settings.symlink_to(external)
    exclude = root / ".git" / "info" / "exclude"
    exclude_before = exclude.read_bytes() if exclude.exists() else None

    with pytest.raises(ValueError, match="symlinked local settings"):
        install_claude_code_hooks(root, local=True)

    assert external.read_text(encoding="utf-8") == '{"model":"private"}\n'
    assert settings.is_symlink()
    assert (exclude.read_bytes() if exclude.exists() else None) == exclude_before


def test_attempt_hooks_use_local_ignored_settings_and_canonical_state_root(
    claimed, repo: Path, monkeypatch
) -> None:
    supervisor, attempt = claimed
    worktree = Path(attempt["worktree"])
    local_settings = worktree / ".claude" / "settings.local.json"
    local_settings.parent.mkdir(parents=True)
    local_settings.write_text(
        json.dumps({"model": "sonnet", "hooks": {"PreToolUse": []}}), encoding="utf-8"
    )
    local_settings.chmod(0o600)

    assert (
        main(
            [
                "--repo",
                str(repo),
                "hooks",
                "install",
                "--claude-code",
                "--attempt",
                attempt["id"],
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "--repo",
                str(repo),
                "hooks",
                "install",
                "--claude-code",
                "--attempt",
                attempt["id"],
            ]
        )
        == 0
    )

    written = json.loads(local_settings.read_text(encoding="utf-8"))
    assert written["model"] == "sonnet"
    assert local_settings.stat().st_mode & 0o777 == 0o600
    hook = written["hooks"]["PreToolUse"][-1]["hooks"][0]["command"]
    assert f"--repo {repo}" in hook
    assert not (repo / ".claude" / "settings.local.json").exists()
    assert (
        subprocess.run(
            [
                "git",
                "-C",
                str(worktree),
                "check-ignore",
                "--no-index",
                "-q",
                ".claude/settings.local.json",
            ],
            check=False,
        ).returncode
        == 0
    )

    assert (
        subprocess.run(
            ["git", "-C", str(worktree), "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        == ""
    )

    monkeypatch.setenv("ACP_ATTEMPT_ID", attempt["id"])
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(json.dumps({"cwd": str(worktree), "tool_input": {"file_path": "alpha.txt"}})),
    )
    monkeypatch.chdir(worktree)
    assert main(shlex.split(hook)[1:]) == 0

    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(json.dumps({"cwd": str(worktree), "tool_input": {"file_path": "beta.txt"}})),
    )
    assert main(shlex.split(hook)[1:]) == DENY_EXIT_CODE

    monkeypatch.chdir(repo)
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps({"cwd": str(repo), "tool_input": {"file_path": str(worktree / "alpha.txt")}})
        ),
    )
    assert main(shlex.split(hook)[1:]) == DENY_EXIT_CODE


def test_attempt_hook_cli_enables_stale_write_guard_only_when_requested(
    claimed, repo: Path
) -> None:
    attempt = claimed[1]
    worktree = Path(attempt["worktree"])
    assert (
        main(
            [
                "--repo",
                str(repo),
                "hooks",
                "install",
                "--claude-code",
                "--attempt",
                attempt["id"],
                "--stale-write-guard",
            ]
        )
        == 0
    )
    settings = json.loads(
        (worktree / ".claude" / "settings.local.json").read_text(encoding="utf-8")
    )["hooks"]
    commands = [
        hook["command"]
        for event in settings.values()
        for entry in event
        for hook in entry.get("hooks", [])
    ]
    assert any("guard --hook --freshness" in command for command in commands)
    assert any("snapshot --hook" in command for command in commands)


def test_attempt_hook_cli_installs_same_attempt_write_reservations(claimed, repo: Path) -> None:
    attempt = claimed[1]
    assert (
        main(
            [
                "--repo",
                str(repo),
                "hooks",
                "install",
                "--claude-code",
                "--attempt",
                attempt["id"],
                "--serialize-write-tools",
            ]
        )
        == 0
    )
    hooks = json.loads(
        (Path(attempt["worktree"]) / ".claude" / "settings.local.json").read_text(encoding="utf-8")
    )["hooks"]
    pre_commands = [
        hook["command"] for entry in hooks["PreToolUse"] for hook in entry.get("hooks", [])
    ]
    assert any("guard --hook --reserve-write" in command for command in pre_commands)
    assert all(
        event in hooks for event in ("PostToolUse", "PostToolUseFailure", "PermissionDenied")
    )


def test_cli_pre_hook_serializes_same_attempt_writes_and_fails_closed_without_identity(
    claimed, repo: Path, monkeypatch, capsys
) -> None:
    supervisor, attempt = claimed
    worktree = Path(attempt["worktree"])

    def unexpected_read_write_open(self):
        raise AssertionError("hook reservations must not run read-write supervisor reconciliation")

    monkeypatch.setattr(GitSupervisor, "_open_read_write", unexpected_read_write_open)
    monkeypatch.setenv("ACP_ATTEMPT_ID", attempt["id"])
    command = ["--repo", str(repo), "guard", "--hook", "--reserve-write"]

    base_payload = {
        "cwd": str(worktree),
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "alpha.txt", "content": "new"},
    }
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(base_payload)))
    assert main(command) == DENY_EXIT_CODE
    assert json.loads(capsys.readouterr().out)["reason"] == "write_identity_missing"

    invalid_agent_payload = {
        **base_payload,
        "tool_use_id": "tool-bad-agent",
        "agent_id": 7,
    }
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(invalid_agent_payload)))
    assert main(command) == DENY_EXIT_CODE
    assert json.loads(capsys.readouterr().out)["reason"] == "write_identity_invalid"

    first_payload = {**base_payload, "tool_use_id": "tool-1"}
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(first_payload)))
    assert main(command) == 0
    assert json.loads(capsys.readouterr().out)["write_reservation"] == "held"

    second_payload = {**base_payload, "tool_use_id": "tool-2", "agent_id": "agent-2"}
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(second_payload)))
    assert main(command) == DENY_EXIT_CODE
    assert json.loads(capsys.readouterr().out)["reason"] == "concurrent_write_conflict"

    finish = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Write",
        "tool_use_id": "tool-1",
    }
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(finish)))
    assert main(["--repo", str(repo), "write-finish", "--hook"]) == 0
    retry = supervisor._reserve_write(
        attempt["id"],
        "alpha.txt",
        caller_cwd=worktree,
        tool_use_id="tool-2",
        agent_id="agent-2",
    )
    assert retry["allow"] is True


@pytest.mark.parametrize("hook_event", ["PostToolUse", "PostToolUseFailure", "PermissionDenied"])
def test_write_finish_hook_releases_success_failure_and_permission_denial(
    claimed, repo: Path, monkeypatch, hook_event: str
) -> None:
    supervisor, attempt = claimed
    worktree = Path(attempt["worktree"])
    held = supervisor._reserve_write(
        attempt["id"], "alpha.txt", caller_cwd=worktree, tool_use_id="tool-1", agent_id="agent-1"
    )
    assert held["allow"] is True
    monkeypatch.setenv("ACP_ATTEMPT_ID", attempt["id"])
    wrong_agent_finish = {
        "hook_event_name": hook_event,
        "tool_name": "Write",
        "tool_use_id": "tool-1",
        "agent_id": "agent-2",
    }
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(wrong_agent_finish)))
    assert main(["--repo", str(repo), "write-finish", "--hook"]) == 0
    still_held = supervisor._reserve_write(
        attempt["id"], "alpha.txt", caller_cwd=worktree, tool_use_id="tool-2", agent_id="agent-2"
    )
    assert still_held["allow"] is False
    assert still_held["reason"] == "concurrent_write_conflict"

    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": hook_event,
                    "tool_name": "Write",
                    "tool_use_id": "tool-1",
                    "agent_id": "agent-1",
                }
            )
        ),
    )
    assert main(["--repo", str(repo), "write-finish", "--hook"]) == 0
    retry = supervisor._reserve_write(
        attempt["id"], "alpha.txt", caller_cwd=worktree, tool_use_id="tool-2", agent_id="agent-2"
    )
    assert retry["allow"] is True


def test_write_finish_releases_using_tool_use_id_when_agent_id_is_absent(
    claimed, repo: Path, monkeypatch
) -> None:
    supervisor, attempt = claimed
    worktree = Path(attempt["worktree"])
    assert supervisor._reserve_write(
        attempt["id"],
        "alpha.txt",
        caller_cwd=worktree,
        tool_use_id="tool-with-optional-agent-id",
    )["allow"]
    monkeypatch.setenv("ACP_ATTEMPT_ID", attempt["id"])
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PostToolUse",
                    "tool_name": "Write",
                    "tool_use_id": "tool-with-optional-agent-id",
                }
            )
        ),
    )

    assert main(["--repo", str(repo), "write-finish", "--hook"]) == 0
    retry = supervisor._reserve_write(
        attempt["id"], "alpha.txt", caller_cwd=worktree, tool_use_id="tool-next"
    )
    assert retry["allow"] is True


def test_hook_mode_fails_closed_when_the_supervisor_cannot_open(tmp_path, monkeypatch) -> None:
    """A guard that errors must BLOCK, not wave the write through.

    Claude Code blocks a PreToolUse tool call on exit 2 and treats any other non-zero
    exit as a hook error it reports and moves past. So `return 1` — the CLI's generic
    SupervisorError path — is an ALLOW. Every way the guard can fail before it reaches
    a decision therefore has to exit 2: a missing ACP_ATTEMPT_ID, a repository it
    cannot open, and `schema_upgrade_required`, which one `SCHEMA_VERSION` bump would
    return for every hook invocation on the fleet at once.
    """

    monkeypatch.setenv("ACP_ATTEMPT_ID", "some-attempt")
    monkeypatch.setattr("sys.stdin", io.StringIO('{"tool_input": {"file_path": "a.py"}}'))
    assert main(["--repo", str(tmp_path / "not-a-repo"), "guard", "--hook"]) == DENY_EXIT_CODE


def test_hook_mode_fails_closed_without_an_attempt_id(repo: Path, monkeypatch) -> None:
    monkeypatch.delenv("ACP_ATTEMPT_ID", raising=False)
    monkeypatch.setattr("sys.stdin", io.StringIO('{"tool_input": {"file_path": "alpha.txt"}}'))
    assert main(["--repo", str(repo), "guard", "--hook"]) == DENY_EXIT_CODE


def test_hook_mode_fails_closed_on_a_stale_schema(claimed, repo: Path, monkeypatch) -> None:
    """The bump that would have opened the gate fleet-wide."""

    import sqlite3

    connection = sqlite3.connect(repo / ".acp" / "control.db")
    connection.execute("DELETE FROM meta WHERE key = 'schema_version'")
    connection.commit()
    connection.close()

    worktree = Path(claimed[1]["worktree"])
    monkeypatch.setenv("ACP_ATTEMPT_ID", claimed[1]["id"])
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(json.dumps({"tool_input": {"file_path": str(worktree / "alpha.txt")}})),
    )
    assert main(["--repo", str(repo), "guard", "--hook"]) == DENY_EXIT_CODE


def test_non_hook_guard_keeps_the_ordinary_error_exit_code(repo: Path, monkeypatch) -> None:
    """Only the hook contract needs 2. A human at a terminal still gets the usual 1."""

    monkeypatch.delenv("ACP_ATTEMPT_ID", raising=False)
    assert main(["--repo", str(repo), "guard", "--path", "alpha.txt"]) == 1
