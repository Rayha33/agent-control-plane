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
from pathlib import Path

import pytest
from support import init_repo, make_task

from agent_control_plane.cli import main
from agent_control_plane.editor_hooks import (
    DENY_EXIT_CODE,
    GUARDED_TOOLS,
    install_claude_code_hooks,
    install_codex_hooks,
    parse_codex_patch_paths,
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

    absolute = supervisor.guard(attempt["id"], str(worktree / "alpha.txt"), caller_cwd=worktree)
    relative = supervisor.guard(attempt["id"], "alpha.txt", caller_cwd=worktree)

    assert absolute["allow"] is True
    assert relative["allow"] is True
    assert relative["relative_path"] == "alpha.txt"


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
