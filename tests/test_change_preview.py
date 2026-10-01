from __future__ import annotations

import hashlib
import json
import os
import shutil
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


def test_preview_reads_packed_objects_from_its_isolated_database(repo: Path) -> None:
    _supervisor, attempt = make_attempt(repo)
    git(repo, "gc", "--prune=now")
    common = Path(git(repo, "rev-parse", "--git-common-dir"))
    if not common.is_absolute():
        common = repo / common
    assert list((common / "objects" / "pack").glob("*.pack"))

    preview = GitSupervisor(repo, read_only=True).change_preview(attempt["id"])

    assert preview["stable"] is True
    assert preview["start_sha"] == attempt["start_sha"]
    assert preview["committed"]["path_count"] == 0


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
        "objects": _tree_snapshot(repo / ".git" / "objects"),
        "refs": git(worktree, "for-each-ref", "--format=%(refname) %(objectname)"),
        "index": _file_snapshot(index),
        "worktree": _tree_snapshot(worktree),
    }

    preview = observer.change_preview(attempt["id"])

    after = {
        "db": _db_snapshot(writable),
        "state_children": sorted(path.name for path in writable.state_dir.iterdir()),
        "objects": _tree_snapshot(repo / ".git" / "objects"),
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


def test_preview_isolates_late_filter_config_added_before_status(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _supervisor, attempt = make_attempt(repo)
    worktree = Path(attempt["worktree"])
    marker = repo.parent / f"late-filter-ran-{attempt['id']}"
    excluded_path = "late-external-exclude.txt"
    external_excludes = repo.parent / f"late-excludes-{attempt['id']}"
    git(repo, "config", "extensions.worktreeConfig", "true")
    original = GitSupervisor._working_tree_status
    injected = False

    def add_filter_then_status(self, path: Path, **kwargs) -> list[dict[str, str]]:
        nonlocal injected
        if not injected:
            injected = True
            (worktree / ".gitattributes").write_text(
                "alpha.txt filter=late-race\n", encoding="utf-8"
            )
            (worktree / "alpha.txt").write_text("changed while preview starts\n", encoding="utf-8")
            git(
                worktree,
                "config",
                "--worktree",
                "filter.late-race.clean",
                f"touch {marker}",
            )
            git(worktree, "config", "--worktree", "filter.late-race.required", "true")
            external_excludes.write_text(f"/{excluded_path}\n", encoding="utf-8")
            git(
                worktree,
                "config",
                "--worktree",
                "core.excludesFile",
                str(external_excludes),
            )
            (worktree / excluded_path).write_text("must stay visible\n", encoding="utf-8")
        return original(self, path, **kwargs)

    monkeypatch.setattr(GitSupervisor, "_working_tree_status", add_filter_then_status)

    preview = GitSupervisor(repo, read_only=True).change_preview(attempt["id"])

    assert injected
    assert not marker.exists()
    assert preview["git_config_isolated"] is True
    assert {item["path"] for item in preview["working_tree"]["paths"]} >= {
        "alpha.txt",
        ".gitattributes",
        excluded_path,
    }


def test_preview_does_not_apply_external_excludes_file(repo: Path) -> None:
    _supervisor, attempt = make_attempt(repo)
    worktree = Path(attempt["worktree"])
    excluded_path = "listed-despite-external-exclude.txt"
    external_excludes = repo.parent / f"external-excludes-{attempt['id']}"
    external_excludes.write_text(f"/{excluded_path}\n", encoding="utf-8")
    git(repo, "config", "core.excludesFile", str(external_excludes))
    info_excluded_path = "listed-despite-repository-info-exclude.txt"
    info_exclude = repo / ".git" / "info" / "exclude"
    info_exclude.write_text(f"/{info_excluded_path}\n", encoding="utf-8")
    (worktree / excluded_path).write_text("path name only\n", encoding="utf-8")
    (worktree / info_excluded_path).write_text("path name only\n", encoding="utf-8")

    preview = GitSupervisor(repo, read_only=True).change_preview(attempt["id"])

    paths = {item["path"] for item in preview["working_tree"]["paths"]}
    assert excluded_path in paths
    assert info_excluded_path in paths


def test_preview_does_not_apply_default_home_excludes(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _supervisor, attempt = make_attempt(repo)
    worktree = Path(attempt["worktree"])
    fake_home = repo.parent / f"home-{attempt['id']}"
    global_ignore = fake_home / ".config" / "git" / "ignore"
    global_ignore.parent.mkdir(parents=True)
    excluded_path = "listed-despite-home-ignore.txt"
    global_ignore.write_text(f"/{excluded_path}\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(fake_home))
    (worktree / excluded_path).write_text("path name only\n", encoding="utf-8")

    preview = GitSupervisor(repo, read_only=True).change_preview(attempt["id"])

    assert excluded_path in {item["path"] for item in preview["working_tree"]["paths"]}


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


def test_preview_ignores_external_git_config_includes(repo: Path) -> None:
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

    preview = GitSupervisor(repo, read_only=True).change_preview(attempt["id"])

    assert not marker.exists()
    assert preview["git_config_isolated"] is True
    assert "alpha.txt" in {item["path"] for item in preview["working_tree"]["paths"]}


@pytest.mark.parametrize("alternate_source", ["repository", "environment"])
def test_preview_never_resolves_commits_from_external_object_alternates(
    repo: Path, monkeypatch: pytest.MonkeyPatch, alternate_source: str
) -> None:
    _supervisor, attempt = make_attempt(repo)
    external = repo.parent / f"external-objects-{alternate_source}-{attempt['id']}"
    external.mkdir()
    git(external, "init")
    git(external, "config", "user.name", "External Repository")
    git(external, "config", "user.email", "external@example.invalid")
    secret_file = external / "outside-private-project" / "external-only.txt"
    secret_file.parent.mkdir()
    secret_file.write_text("external object payload\n", encoding="utf-8")
    git(external, "add", ".")
    git(external, "commit", "-m", "external-only object")
    external_head = git(external, "rev-parse", "HEAD")
    external_objects = external / ".git" / "objects"

    common = Path(git(repo, "rev-parse", "--git-common-dir"))
    if not common.is_absolute():
        common = repo / common
    admin = common / "worktrees" / attempt["id"]
    if alternate_source == "repository":
        info = common / "objects" / "info"
        info.mkdir(exist_ok=True)
        (info / "alternates").write_text(f"{external_objects}\n", encoding="utf-8")
    else:
        monkeypatch.setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", str(external_objects))
        original_env_builder = GitSupervisor._supervisor_git_env

        def add_external_alternate(self: GitSupervisor) -> dict[str, str]:
            environment = original_env_builder(self)
            environment["GIT_ALTERNATE_OBJECT_DIRECTORIES"] = str(external_objects)
            return environment

        monkeypatch.setattr(GitSupervisor, "_supervisor_git_env", add_external_alternate)
    (admin / "HEAD").write_text(f"{external_head}\n", encoding="ascii")

    with pytest.raises(SupervisorError, match="Git could not read attempt metadata") as error:
        GitSupervisor(repo, read_only=True).change_preview(attempt["id"])

    assert "outside-private-project" not in str(error.value)
    assert "external-only.txt" not in str(error.value)


def test_preview_ignores_temporary_directory_environment_inside_attempt(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _supervisor, attempt = make_attempt(repo)
    worktree = Path(attempt["worktree"])
    before = _tree_snapshot(worktree)
    for variable in ("TMPDIR", "TMP", "TEMP"):
        monkeypatch.setenv(variable, str(worktree))

    preview = GitSupervisor(repo, read_only=True).change_preview(attempt["id"])

    assert preview["stable"] is True
    assert _tree_snapshot(worktree) == before
    assert all(
        not item["path"].startswith("acp-change-preview-")
        for section in (preview["committed"], preview["working_tree"])
        for item in section["paths"]
    )


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
        git_context: change_preview_module._IsolatedGitContext | None = None,
    ) -> list[dict[str, str]]:
        nonlocal calls
        result = original(
            worktree,
            expected_identity=expected_identity,
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


def test_preview_marks_index_only_change_unstable(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _supervisor, attempt = make_attempt(repo)
    worktree = Path(attempt["worktree"])
    read_only = GitSupervisor(repo, read_only=True)
    original = read_only._working_tree_status
    calls = 0

    def change_index_after_first_snapshot(
        path: Path,
        *,
        expected_identity: tuple[int, int] | None = None,
        git_context: change_preview_module._IsolatedGitContext | None = None,
    ) -> list[dict[str, str]]:
        nonlocal calls
        result = original(
            path,
            expected_identity=expected_identity,
            git_context=git_context,
        )
        calls += 1
        if calls == 1:
            git(worktree, "update-index", "--assume-unchanged", "alpha.txt")
        return result

    monkeypatch.setattr(read_only, "_working_tree_status", change_index_after_first_snapshot)

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
    original_popen = change_preview_module.subprocess.Popen
    original_read = change_preview_module.os.read
    status_fds: set[int] = set()
    captured_status = bytearray()
    swapped = False

    def swap_before_git_starts(command: list[str], *args, **kwargs):
        nonlocal swapped
        if not swapped and "status" in command:
            swapped = True
            worktree.rename(moved)
            worktree.symlink_to(outside, target_is_directory=True)
        process = original_popen(command, *args, **kwargs)
        if swapped and "status" in command and process.stdout is not None:
            status_fds.add(process.stdout.fileno())
        return process

    def capture_status_output(fd: int, size: int) -> bytes:
        chunk = original_read(fd, size)
        if fd in status_fds:
            captured_status.extend(chunk)
        return chunk

    monkeypatch.setattr(change_preview_module.subprocess, "Popen", swap_before_git_starts)
    monkeypatch.setattr(change_preview_module.os, "read", capture_status_output)
    try:
        with pytest.raises(SupervisorError, match="changed during inspection"):
            GitSupervisor(repo, read_only=True).change_preview(attempt["id"])
    finally:
        if worktree.is_symlink():
            worktree.unlink()
        if moved.exists():
            moved.rename(worktree)

    assert swapped
    assert status_fds
    assert b"outside-only.txt" not in captured_status


def test_preview_rejects_oversized_working_tree_path_inventory(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo, read_only=True)
    output = b"?? file\0" * (change_preview_module._MAX_INVENTORY_RECORDS + 1)
    monkeypatch.setattr(supervisor, "_git_output", lambda *_args, **_kwargs: output)

    with pytest.raises(SupervisorError, match="working-tree path inventory exceeds safe limits"):
        supervisor._working_tree_status(repo)


def test_preview_rejects_oversized_committed_path_inventory(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo, read_only=True)
    output = b"M\0file\0" * (change_preview_module._MAX_INVENTORY_RECORDS + 1)
    monkeypatch.setattr(supervisor, "_git_output", lambda *_args, **_kwargs: output)

    with pytest.raises(SupervisorError, match="committed path inventory exceeds safe limits"):
        supervisor._committed_paths(repo, "0" * 40, "1" * 40)


def test_preview_stops_directory_inventory_when_its_bound_is_reached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Entry:
        def __init__(self, name: str) -> None:
            self.name = name

    class Entries:
        yielded = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

        def __iter__(self):
            return self

        def __next__(self) -> Entry:
            self.yielded += 1
            return Entry(f"entry-{self.yielded}")

    entries = Entries()
    monkeypatch.setattr(change_preview_module.os, "scandir", lambda _fd: entries)

    with pytest.raises(OSError, match="safe entry limit"):
        change_preview_module.ChangePreviewMixin._list_git_directory(123, 2)

    assert entries.yielded == 3


def test_preview_fails_closed_if_scratch_git_config_changes_during_status(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _supervisor, attempt = make_attempt(repo)
    worktree = Path(attempt["worktree"])
    tracked = worktree / "alpha.txt"
    tracked.chmod(tracked.stat().st_mode | 0o100)
    original_popen = change_preview_module.subprocess.Popen
    injected = False

    def inject_status_config(command: list[str], *args, **kwargs):
        nonlocal injected
        if not injected and "status" in command:
            injected = True
            git_directory = Path(kwargs["env"]["GIT_DIR"])
            with (git_directory / "config").open("ab") as config_file:
                config_file.write(b"\n[core]\n\tfilemode = false\n")
        return original_popen(command, *args, **kwargs)

    monkeypatch.setattr(change_preview_module.subprocess, "Popen", inject_status_config)

    with pytest.raises(SupervisorError, match="isolated Git metadata changed"):
        GitSupervisor(repo, read_only=True).change_preview(attempt["id"])

    assert injected


def test_preview_does_not_execute_filter_from_raced_scratch_metadata(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _supervisor, attempt = make_attempt(repo)
    worktree = Path(attempt["worktree"])
    marker = repo.parent / f"raced-filter-executed-{attempt['id']}"
    (worktree / ".gitattributes").write_text("alpha.txt filter=raced\n", encoding="utf-8")
    git(worktree, "add", ".gitattributes")
    tracked = worktree / "alpha.txt"
    metadata = tracked.stat()
    tracked.write_bytes(b"x" * len(tracked.read_bytes()))
    os.utime(tracked, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    original_popen = change_preview_module.subprocess.Popen
    injected = False

    def inject_filter_before_git(command: list[str], *args, **kwargs):
        nonlocal injected
        if not injected and "status" in command:
            injected = True
            git_directory = Path(kwargs["env"]["GIT_DIR"])
            with (git_directory / "config").open("ab") as config_file:
                config_file.write(
                    f'\n[filter "raced"]\n\tclean = touch {marker}\n\trequired = true\n'.encode()
                )
            (git_directory / "info" / "attributes").write_bytes(b"alpha.txt filter=raced\n")
            assert any(argument.startswith("--attr-source=") for argument in command)
        return original_popen(command, *args, **kwargs)

    monkeypatch.setattr(change_preview_module.subprocess, "Popen", inject_filter_before_git)

    with pytest.raises(SupervisorError, match="isolated Git metadata changed"):
        GitSupervisor(repo, read_only=True).change_preview(attempt["id"])

    assert injected
    assert not marker.exists(), "untrusted filter executed before scratch config was rejected"


def test_preview_fails_closed_if_scratch_object_is_injected_during_git(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _supervisor, attempt = make_attempt(repo)
    original_popen = change_preview_module.subprocess.Popen
    injected = False

    def inject_loose_object(command: list[str], *args, **kwargs):
        nonlocal injected
        if not injected and "status" in command:
            injected = True
            object_directory = Path(kwargs["env"]["GIT_DIR"]) / "objects"
            prefix = next(
                f"{value:02x}"
                for value in range(256)
                if not (object_directory / f"{value:02x}").exists()
            )
            shard = object_directory / prefix
            shard.mkdir()
            (shard / ("0" * 38)).write_bytes(b"injected unreferenced object")
        return original_popen(command, *args, **kwargs)

    monkeypatch.setattr(change_preview_module.subprocess, "Popen", inject_loose_object)

    with pytest.raises(SupervisorError, match="isolated Git"):
        GitSupervisor(repo, read_only=True).change_preview(attempt["id"])

    assert injected


def test_preview_fails_closed_if_scratch_parent_is_swapped_around_git(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _supervisor, attempt = make_attempt(repo)
    original_popen = change_preview_module.subprocess.Popen
    swapped = False

    class FinishedProcess:
        def __init__(self, process, restore) -> None:
            self._process = process
            self._restore = restore
            self.stdout = process.stdout

        @property
        def returncode(self) -> int | None:
            return self._process.returncode

        def poll(self) -> int | None:
            return self._process.poll()

        def wait(self, timeout: float | None = None) -> int:
            result = self._process.wait(timeout)
            self._restore()
            return result

        def kill(self) -> None:
            self._process.kill()

    def swap_parent_during_status(command: list[str], *args, **kwargs):
        nonlocal swapped
        if not swapped and "status" in command:
            swapped = True
            scratch_parent = Path(kwargs["env"]["GIT_DIR"]).parent
            saved_parent = scratch_parent.with_name(f"{scratch_parent.name}-saved")
            replacement_parent = scratch_parent.with_name(f"{scratch_parent.name}-replacement")
            shutil.copytree(scratch_parent, replacement_parent)
            os.rename(scratch_parent, saved_parent)
            os.rename(replacement_parent, scratch_parent)

            def restore() -> None:
                if scratch_parent.exists():
                    os.rename(scratch_parent, replacement_parent)
                os.rename(saved_parent, scratch_parent)
                shutil.rmtree(replacement_parent, ignore_errors=True)

            try:
                child = original_popen(command, *args, **kwargs)
            except Exception:
                restore()
                raise
            return FinishedProcess(child, restore)
        return original_popen(command, *args, **kwargs)

    monkeypatch.setattr(change_preview_module.subprocess, "Popen", swap_parent_during_status)

    with pytest.raises(SupervisorError, match="isolated Git"):
        GitSupervisor(repo, read_only=True).change_preview(attempt["id"])

    assert swapped


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
