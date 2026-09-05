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
import subprocess
from pathlib import Path

import pytest
from support import init_repo, make_task

from agent_control_plane.cli import main
from agent_control_plane.editor_hooks import (
    DENY_EXIT_CODE,
    GUARDED_TOOLS,
    install_claude_code_hooks,
    path_from_hook_payload,
)
from agent_control_plane.git_supervisor import GitSupervisor, SupervisorError


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

    absolute = supervisor.guard(attempt["id"], str(worktree / "alpha.txt"))
    relative = supervisor.guard(attempt["id"], "alpha.txt")

    assert absolute["allow"] is True
    assert relative["allow"] is True
    assert relative["relative_path"] == "alpha.txt"


def test_an_undeclared_path_in_the_worktree_is_denied(claimed) -> None:
    supervisor, attempt = claimed
    decision = supervisor.guard(attempt["id"], str(Path(attempt["worktree"]) / "beta.txt"))

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

    decision = claimed[0].guard(claimed[1]["id"], str(repo / "alpha.txt"))

    assert decision["allow"] is False
    assert decision["reason"] == "outside_worktree"


@pytest.mark.parametrize("escape", ["../../../etc/passwd", "/etc/passwd"])
def test_paths_outside_the_worktree_are_denied(claimed, escape: str) -> None:
    decision = claimed[0].guard(claimed[1]["id"], escape)
    assert decision["allow"] is False
    assert decision["reason"] == "outside_worktree"


def test_a_symlink_out_of_the_worktree_is_denied(claimed) -> None:
    """A link planted inside the worktree must not launder a write out of it."""

    supervisor, attempt = claimed
    link = Path(attempt["worktree"]) / "alpha.txt"
    link.unlink()
    link.symlink_to("/etc/passwd")

    decision = supervisor.guard(attempt["id"], str(link))

    assert decision["allow"] is False
    assert decision["reason"] == "outside_worktree"


def test_a_glob_write_set_is_matched_the_same_way_submit_matches_it(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "src/**")
    attempt = supervisor.claim(created["id"], "worker")

    assert supervisor.guard(attempt["id"], "src/deep/module.py")["allow"] is True
    assert supervisor.guard(attempt["id"], "alpha.txt")["allow"] is False


def test_guard_and_submit_agree(claimed) -> None:
    """The single-implementation claim, asserted rather than asserted-in-a-comment.

    If these ever diverge, an agent is allowed to write something its own submission
    will be rejected for — the worst of both, discovered at the end of the work.
    """

    supervisor, attempt = claimed
    worktree = Path(attempt["worktree"])
    assert supervisor.guard(attempt["id"], str(worktree / "beta.txt"))["allow"] is False

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

    decision = supervisor.guard(attempt["id"], "alpha.txt")

    assert decision["allow"] is False
    assert decision["reason"] == "lease_expired"


def test_an_attempt_that_is_not_live_is_denied(claimed) -> None:
    supervisor, attempt = claimed
    with supervisor.connect() as connection:
        connection.execute("UPDATE attempts SET status = 'orphaned' WHERE id = ?", (attempt["id"],))

    decision = supervisor.guard(attempt["id"], "alpha.txt")

    assert decision["allow"] is False
    assert decision["reason"] == "attempt_not_live"


def test_an_unknown_attempt_is_denied(repo: Path) -> None:
    decision = GitSupervisor(repo).guard("no-such-attempt", "alpha.txt")
    assert decision["allow"] is False
    assert decision["reason"] == "attempt_not_found"


def test_guard_runs_on_a_read_only_supervisor(claimed, repo: Path) -> None:
    """A pre-write check must never itself be a reason the state changed."""

    viewer = GitSupervisor(repo, read_only=True)
    assert viewer.guard(claimed[1]["id"], "alpha.txt")["allow"] is True


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


def test_hook_mode_exit_codes(claimed, repo: Path, monkeypatch) -> None:
    _, attempt = claimed
    worktree = Path(attempt["worktree"])

    allowed = json.dumps(
        {"tool_name": "Edit", "tool_input": {"file_path": str(worktree / "alpha.txt")}}
    )
    denied = json.dumps(
        {"tool_name": "Edit", "tool_input": {"file_path": str(worktree / "beta.txt")}}
    )

    assert run_hook(repo, attempt["id"], allowed, monkeypatch) == 0
    assert run_hook(repo, attempt["id"], denied, monkeypatch) == DENY_EXIT_CODE


@pytest.mark.parametrize("payload", ["not json at all", "{}", '{"tool_input": {}}', "[]"])
def test_an_unreadable_payload_fails_closed(claimed, repo: Path, monkeypatch, payload: str) -> None:
    """Allowing what it cannot parse would let the boundary vanish on a schema change."""

    assert run_hook(repo, claimed[1]["id"], payload, monkeypatch) == DENY_EXIT_CODE


def test_path_from_hook_payload_reads_the_editing_tools() -> None:
    assert path_from_hook_payload({"tool_input": {"file_path": "a.py"}}) == "a.py"
    assert path_from_hook_payload({"tool_input": {"notebook_path": "n.ipynb"}}) == "n.ipynb"
    assert path_from_hook_payload({"tool_input": {"command": "rm -rf /"}}) is None
    assert path_from_hook_payload("nonsense") is None


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
