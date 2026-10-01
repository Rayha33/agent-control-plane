from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest
from support import commit_change, event_count, init_repo, make_task, state_fingerprint

from agent_control_plane.git_supervisor import GitSupervisor, SupervisorError
from agent_control_plane.supervisor import change_preview as change_preview_module


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return init_repo(tmp_path)


def git(repo: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def make_attempt(repo: Path) -> tuple[GitSupervisor, dict]:
    supervisor = GitSupervisor(repo)
    task = make_task(
        supervisor,
        "alpha.txt",
        "beta.txt",
        "renamed-alpha.txt",
        "private-notes/**",
        "concurrent.txt",
    )
    return supervisor, supervisor.claim(task["id"], "preview-worker")


def _file_snapshot(path: Path) -> tuple | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if path.is_symlink():
        return ("symlink", os.readlink(path), metadata.st_mtime_ns)
    if path.is_file():
        return (
            "file",
            metadata.st_size,
            metadata.st_mtime_ns,
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
    return ("other", metadata.st_mode, metadata.st_size, metadata.st_mtime_ns)


def _tree_snapshot(root: Path) -> dict[str, tuple | None]:
    snapshot: dict[str, tuple | None] = {}
    for directory, directories, files in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in directories + files:
            path = base / name
            snapshot[path.relative_to(root).as_posix()] = _file_snapshot(path)
    return snapshot


def _db_snapshot(supervisor: GitSupervisor) -> dict[str, tuple | None]:
    snapshots = {
        suffix: _file_snapshot(Path(f"{supervisor.db_path}{suffix}"))
        for suffix in ("", "-wal", "-shm")
    }
    # SQLite may refresh transient WAL shared-memory lock metadata while a mode=ro
    # connection opens/closes. Its bytes, the durable database, and the WAL must not
    # change; the shared-memory file's mtime is not durable database state.
    shm = snapshots["-shm"]
    if shm is not None:
        snapshots["-shm"] = (shm[0], shm[1], shm[3])
    return snapshots


def test_preview_separates_committed_changes_from_working_tree_without_contents(
    repo: Path,
) -> None:
    supervisor, attempt = make_attempt(repo)
    worktree = Path(attempt["worktree"])
    git(worktree, "mv", "alpha.txt", "renamed-alpha.txt")
    git(worktree, "commit", "-m", "rename tracked file")
    (worktree / "beta.txt").write_text("private payload must not be returned\n", encoding="utf-8")
    (worktree / "renamed-alpha.txt").unlink()
    private_path = "private-notes/with\nnewline.txt"
    private_file = worktree / private_path
    private_file.parent.mkdir()
    private_file.write_text("another secret payload\n", encoding="utf-8")

    preview = GitSupervisor(repo, read_only=True).change_preview(attempt["id"])
    encoded = json.dumps(preview)

    assert preview["start_sha"] == attempt["start_sha"]
    assert preview["observed_head"] == preview["observed_head_after"]
    assert preview["stable"] is True
    assert preview["file_contents_included"] is False
    assert preview["committed"]["paths"] == [
        {"status": "R100", "path": "renamed-alpha.txt", "previous_path": "alpha.txt"}
    ]
    assert {item["path"] for item in preview["working_tree"]["paths"]} == {
        "beta.txt",
        "renamed-alpha.txt",
        private_path,
    }
    assert "private payload must not be returned" not in encoded
    assert "another secret payload" not in encoded


def test_preview_uses_nul_framing_and_caps_only_the_returned_path_list(repo: Path) -> None:
    supervisor, attempt = make_attempt(repo)
    worktree = Path(attempt["worktree"])
    for index in range(1003):
        path = worktree / f"generated-{index:04}.txt"
        path.write_text("x", encoding="utf-8")

    preview = GitSupervisor(repo, read_only=True).change_preview(attempt["id"])

    assert preview["working_tree"]["path_count"] == 1003
    assert len(preview["working_tree"]["paths"]) == 1000
    assert preview["working_tree"]["paths_truncated"] is True


def test_preview_is_structurally_read_only_for_db_events_refs_index_and_worktree(
    repo: Path,
) -> None:
    writable, attempt = make_attempt(repo)
    worktree = Path(attempt["worktree"])
    commit_change(attempt, "alpha.txt", "committed\n")
    (worktree / "beta.txt").write_text("uncommitted\n", encoding="utf-8")
    (worktree / "untracked.txt").write_text("untracked\n", encoding="utf-8")
    index = Path(git(worktree, "rev-parse", "--git-path", "index"))
    if not index.is_absolute():
        index = (worktree / index).resolve()

    observer = GitSupervisor(repo, read_only=True)
    before = {
        "db": _db_snapshot(writable),
        "state_children": sorted(path.name for path in writable.state_dir.iterdir()),
        "state": state_fingerprint(observer),
        "events": event_count(observer),
        "event_chain": observer.verify_event_chain(),
        "refs": git(worktree, "for-each-ref", "--format=%(refname) %(objectname)"),
        "index": _file_snapshot(index),
        "worktree": _tree_snapshot(worktree),
    }

    preview = observer.change_preview(attempt["id"])

    after = {
        "db": _db_snapshot(writable),
        "state_children": sorted(path.name for path in writable.state_dir.iterdir()),
        "refs": git(worktree, "for-each-ref", "--format=%(refname) %(objectname)"),
        "index": _file_snapshot(index),
        "worktree": _tree_snapshot(worktree),
    }

    assert preview["stable"] is True
    assert {key: before[key] for key in after} == after
    assert state_fingerprint(observer) == before["state"]
    assert event_count(observer) == before["events"]
    assert observer.verify_event_chain() == before["event_chain"]


def test_preview_disables_external_diff_textconv_pager_and_fsmonitor_commands(repo: Path) -> None:
    supervisor, attempt = make_attempt(repo)
    worktree = Path(attempt["worktree"])
    marker = repo.parent / "external-command-ran"
    filter_marker = repo.parent / "external-filter-ran"
    worktree_filter_marker = repo.parent / "worktree-external-filter-ran"
    command = f"touch {marker}"
    filter_command = f"touch {filter_marker}"
    (worktree / ".gitattributes").write_text(
        "alpha.txt diff=preview-test filter=preview-test\nbeta.txt filter=worktree-test\n",
        encoding="utf-8",
    )
    (worktree / "alpha.txt").write_text("changed\n", encoding="utf-8")
    (worktree / "beta.txt").write_text("also changed\n", encoding="utf-8")
    git(repo, "config", "diff.preview-test.command", command)
    git(repo, "config", "diff.preview-test.textconv", command)
    git(repo, "config", "pager.diff", command)
    git(repo, "config", "core.fsmonitor", command)
    git(repo, "config", "filter.preview-test.clean", filter_command)
    git(repo, "config", "filter.preview-test.required", "true")
    git(repo, "config", "extensions.worktreeConfig", "true")
    git(
        worktree,
        "config",
        "--worktree",
        "filter.worktree-test.clean",
        f"touch {worktree_filter_marker}",
    )
    git(worktree, "config", "--worktree", "filter.worktree-test.required", "true")

    GitSupervisor(repo, read_only=True).change_preview(attempt["id"])

    assert not marker.exists()
    assert not filter_marker.exists()
    assert not worktree_filter_marker.exists()


def test_preview_lists_symlinks_without_traversing_their_targets(repo: Path) -> None:
    _supervisor, attempt = make_attempt(repo)
    worktree = Path(attempt["worktree"])
    outside = repo.parent / f"outside-attempt-{attempt['id']}"
    outside.mkdir()
    (outside / "private.txt").write_text("outside path must not be enumerated\n", encoding="utf-8")
    (worktree / "external-link").symlink_to(outside, target_is_directory=True)

    preview = GitSupervisor(repo, read_only=True).change_preview(attempt["id"])

    paths = [item["path"] for item in preview["working_tree"]["paths"]]
    assert "external-link" in paths
    assert not any(path.startswith("external-link/") for path in paths)
    assert "outside-attempt/private.txt" not in paths


def test_preview_rejects_recorded_worktree_redirect_before_inspecting_it(repo: Path) -> None:
    writable, attempt = make_attempt(repo)
    outside = repo.parent / f"outside-attempt-{attempt['id']}"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("must remain untouched\n", encoding="utf-8")
    before = _file_snapshot(sentinel)
    with writable.connect() as connection:
        connection.execute(
            "UPDATE attempts SET worktree = ? WHERE id = ?", (str(outside), attempt["id"])
        )

    with pytest.raises(SupervisorError, match="missing or unsafe"):
        GitSupervisor(repo, read_only=True).change_preview(attempt["id"])

    assert _file_snapshot(sentinel) == before


def test_preview_rejects_git_marker_escape_before_invoking_git_on_attempt(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _supervisor, attempt = make_attempt(repo)
    worktree = Path(attempt["worktree"])
    outside_git = repo.parent / f"outside-git-{attempt['id']}"
    outside_git.mkdir()
    (worktree / ".git").write_text(f"gitdir: {outside_git}\n", encoding="utf-8")
    original = GitSupervisor._git_output

    def refuse_attempt_git(self, path: Path, *args, **kwargs) -> bytes:
        if path == worktree:
            pytest.fail("Git must not follow an attempt .git pointer before validation")
        return original(self, path, *args, **kwargs)

    monkeypatch.setattr(GitSupervisor, "_git_output", refuse_attempt_git)

    with pytest.raises(SupervisorError, match="attempt Git metadata is missing or unsafe"):
        GitSupervisor(repo, read_only=True).change_preview(attempt["id"])


def test_preview_refuses_external_git_config_includes(repo: Path) -> None:
    _supervisor, attempt = make_attempt(repo)
    worktree = Path(attempt["worktree"])
    marker = repo.parent / f"included-config-command-{attempt['id']}"
    included_config = repo.parent / f"included-config-{attempt['id']}.cfg"
    included_config.write_text(
        f'[filter "included"]\nclean = touch {marker}\nrequired = true\n',
        encoding="utf-8",
    )
    (worktree / ".gitattributes").write_text("*.txt filter=included\n", encoding="utf-8")
    (worktree / "alpha.txt").write_text("changed\n", encoding="utf-8")
    git(repo, "config", "include.path", str(included_config))

    with pytest.raises(SupervisorError, match="config includes are not supported"):
        GitSupervisor(repo, read_only=True).change_preview(attempt["id"])

    assert not marker.exists()


def test_preview_marks_racing_worktree_unstable(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor, attempt = make_attempt(repo)
    read_only = GitSupervisor(repo, read_only=True)
    original = read_only._working_tree_status
    calls = 0

    def change_after_first_snapshot(
        worktree: Path,
        *,
        expected_identity: tuple[int, int] | None = None,
        config_overrides: list[str] | tuple[str, ...] = (),
        git_context: tuple[Path, Path] | None = None,
    ) -> list[dict[str, str]]:
        nonlocal calls
        result = original(
            worktree,
            expected_identity=expected_identity,
            config_overrides=config_overrides,
            git_context=git_context,
        )
        calls += 1
        if calls == 1:
            (worktree / "concurrent.txt").write_text("arrived during preview\n", encoding="utf-8")
        return result

    monkeypatch.setattr(read_only, "_working_tree_status", change_after_first_snapshot)

    preview = read_only.change_preview(attempt["id"])

    assert preview["stable"] is False
    assert preview["stability"] == "unstable"


def test_preview_pins_directory_and_fails_closed_during_worktree_symlink_swap(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _supervisor, attempt = make_attempt(repo)
    worktree = Path(attempt["worktree"])
    moved = worktree.with_name(f"{worktree.name}-displaced")
    outside = repo.parent / f"outside-attempt-{attempt['id']}"
    outside.mkdir()
    (outside / "outside-only.txt").write_text("outside\n", encoding="utf-8")
    original_run = change_preview_module.subprocess.run
    captured_status: list[bytes] = []
    swapped = False

    def swap_while_running_git(command: list[str], *args, **kwargs):
        nonlocal swapped
        if not swapped and "status" in command:
            swapped = True
            worktree.rename(moved)
            worktree.symlink_to(outside, target_is_directory=True)
            result = original_run(command, *args, **kwargs)
            captured_status.append(result.stdout)
            return result
        return original_run(command, *args, **kwargs)

    monkeypatch.setattr(change_preview_module.subprocess, "run", swap_while_running_git)
    try:
        with pytest.raises(SupervisorError, match="changed during inspection"):
            GitSupervisor(repo, read_only=True).change_preview(attempt["id"])
    finally:
        if worktree.is_symlink():
            worktree.unlink()
        if moved.exists():
            moved.rename(worktree)

    assert swapped
    assert captured_status
    assert b"outside-only.txt" not in captured_status[0]


def test_preview_fails_closed_for_missing_worktree_and_invalid_start_ref(repo: Path) -> None:
    supervisor, attempt = make_attempt(repo)
    worktree = Path(attempt["worktree"])
    detached = worktree.with_name("temporarily-moved")
    worktree.rename(detached)
    with pytest.raises(SupervisorError, match="missing or unsafe"):
        GitSupervisor(repo, read_only=True).change_preview(attempt["id"])
    detached.rename(worktree)

    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET start_sha = ? WHERE id = ?", ("bad-ref", attempt["id"])
        )
    with pytest.raises(SupervisorError, match="start revision is invalid"):
        GitSupervisor(repo, read_only=True).change_preview(attempt["id"])


def test_preview_requires_read_only_mode_and_known_attempt(repo: Path) -> None:
    writable, _attempt = make_attempt(repo)
    with pytest.raises(SupervisorError, match="requires a read-only supervisor"):
        writable.change_preview("00000000-0000-0000-0000-000000000000")
    with pytest.raises(SupervisorError, match="not found"):
        GitSupervisor(repo, read_only=True).change_preview("00000000-0000-0000-0000-000000000000")
