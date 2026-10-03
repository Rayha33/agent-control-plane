from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from agent_control_plane.supervisor.common import SupervisorError
from agent_control_plane.supervisor.result_import import build_candidate_tree
from agent_control_plane.supervisor.sandbox_workspace import collect_changes, copy_snapshot


def _git(repository: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr.decode("utf-8", errors="replace"))
    return result.stdout


def _repository(path: Path, *, object_format: str = "sha1") -> Path:
    path.mkdir()
    initialized = subprocess.run(
        ["git", "init", "--quiet", "--object-format", object_format, str(path)],
        capture_output=True,
        check=False,
    )
    if initialized.returncode != 0:
        if object_format == "sha256":
            pytest.skip("installed Git does not support SHA-256 repositories")
        raise AssertionError(initialized.stderr.decode("utf-8", errors="replace"))
    return path.resolve()


def _commit_initial(repository: Path) -> None:
    _git(repository, "add", "-A")
    _git(
        repository,
        "-c",
        "user.name=ACP tests",
        "-c",
        "user.email=acp-tests@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "baseline",
    )


def _all_paths() -> list[tuple[str, bool, bool]]:
    return [("**", True, False)]


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
def test_candidate_tree_is_host_built_and_does_not_mutate_worktree(
    tmp_path: Path, object_format: str
) -> None:
    repository = _repository(tmp_path / "repo", object_format=object_format)
    (repository / "delete.bin").write_bytes(b"remove me\x00")
    (repository / "modify.bin").write_bytes(b"old\x00bytes")
    (repository / "node").write_text("old node\n")
    (repository / "keep.txt").write_text("unchanged\n")
    _commit_initial(repository)

    baseline = copy_snapshot(repository, tmp_path / "baseline")
    output = copy_snapshot(repository, tmp_path / "worker-output").root
    (output / "delete.bin").unlink()
    (output / "modify.bin").write_bytes(b"new\x00binary\xff")
    (output / "modify.bin").chmod(0o755)
    (output / "node").unlink()
    (output / "node").mkdir()
    (output / "node" / "child.txt").write_text("directory transition\n")
    (output / "new-link").symlink_to("keep.txt")
    (output / "empty-directory").mkdir()
    change_set = collect_changes(
        baseline.manifest,
        output,
        write_set_rules=_all_paths(),
    )

    head_before = _git(repository, "rev-parse", "HEAD")
    status_before = _git(repository, "status", "--porcelain=v1", "-z")
    index_path = Path(
        os.fsdecode(
            _git(repository, "rev-parse", "--path-format=absolute", "--git-path", "index").strip()
        )
    )
    index_before = index_path.read_bytes()

    base_sha = os.fsdecode(_git(repository, "rev-parse", "HEAD").strip())
    candidate = build_candidate_tree(
        repository,
        baseline,
        change_set,
        base_sha=base_sha,
        write_set_rules=_all_paths(),
    )

    assert candidate.baseline_digest == baseline.manifest.digest
    assert candidate.base_sha == base_sha
    assert candidate.result_digest == change_set.result_digest
    assert candidate.change_digest == change_set.digest
    assert len(candidate.tree_sha) == (64 if object_format == "sha256" else 40)
    assert _git(repository, "cat-file", "-t", candidate.tree_sha).strip() == b"tree"
    assert _git(repository, "cat-file", "blob", f"{candidate.tree_sha}:modify.bin") == (
        b"new\x00binary\xff"
    )
    assert _git(repository, "cat-file", "blob", f"{candidate.tree_sha}:node/child.txt") == (
        b"directory transition\n"
    )
    assert _git(repository, "cat-file", "blob", f"{candidate.tree_sha}:new-link") == b"keep.txt"
    assert _git(repository, "ls-tree", candidate.tree_sha, "modify.bin").startswith(b"100755 blob ")
    assert _git(repository, "ls-tree", candidate.tree_sha, "new-link").startswith(b"120000 blob ")
    tree_listing = _git(repository, "ls-tree", "-r", "--name-only", candidate.tree_sha).splitlines()
    assert tree_listing == [b"keep.txt", b"modify.bin", b"new-link", b"node/child.txt"]
    assert _git(repository, "rev-parse", "HEAD") == head_before
    assert _git(repository, "status", "--porcelain=v1", "-z") == status_before == b""
    assert index_path.read_bytes() == index_before


def test_candidate_tree_rejects_snapshot_drift_before_writing_objects(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "repo")
    (repository / "owned.txt").write_text("baseline\n")
    _commit_initial(repository)
    baseline = copy_snapshot(repository, tmp_path / "baseline")
    output = copy_snapshot(repository, tmp_path / "worker-output").root
    (output / "owned.txt").write_text("result\n")
    change_set = collect_changes(baseline.manifest, output, write_set_rules=_all_paths())
    (baseline.root / "owned.txt").write_text("tampered\n")

    with pytest.raises(SupervisorError) as raised:
        build_candidate_tree(
            repository,
            baseline,
            change_set,
            base_sha=os.fsdecode(_git(repository, "rev-parse", "HEAD").strip()),
            write_set_rules=_all_paths(),
        )

    assert raised.value.code == "snapshot_changed"
    assert _git(repository, "status", "--porcelain=v1", "-z") == b""


def test_candidate_tree_rejects_non_root_repository_path(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "repo")
    (repository / "owned.txt").write_text("baseline\n")
    _commit_initial(repository)
    baseline = copy_snapshot(repository, tmp_path / "baseline")
    output = copy_snapshot(repository, tmp_path / "worker-output").root
    (output / "owned.txt").write_text("result\n")
    change_set = collect_changes(baseline.manifest, output, write_set_rules=_all_paths())

    with pytest.raises(SupervisorError) as raised:
        build_candidate_tree(
            repository / "owned.txt",
            baseline,
            change_set,
            base_sha=os.fsdecode(_git(repository, "rev-parse", "HEAD").strip()),
            write_set_rules=_all_paths(),
        )

    assert raised.value.code == "invalid_git_repository"


def test_candidate_tree_rechecks_every_changed_path_against_write_set(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "repo")
    (repository / "owned.txt").write_text("baseline\n")
    _commit_initial(repository)
    baseline = copy_snapshot(repository, tmp_path / "baseline")
    output = copy_snapshot(repository, tmp_path / "worker-output").root
    (output / "owned.txt").write_text("result\n")
    change_set = collect_changes(baseline.manifest, output, write_set_rules=_all_paths())

    with pytest.raises(SupervisorError) as raised:
        build_candidate_tree(
            repository,
            baseline,
            change_set,
            base_sha=os.fsdecode(_git(repository, "rev-parse", "HEAD").strip()),
            write_set_rules=[("not-owned.txt", True, False)],
        )

    assert raised.value.code == "undeclared_write"
    assert _git(repository, "status", "--porcelain=v1", "-z") == b""


def test_candidate_tree_rejects_untracked_snapshot_content(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "repo")
    (repository / "tracked.txt").write_text("tracked\n")
    (repository / ".gitignore").write_text("ignored.local\n")
    _commit_initial(repository)
    (repository / "ignored.local").write_text("must not enter the candidate\n")
    baseline = copy_snapshot(repository, tmp_path / "baseline")
    output = copy_snapshot(repository, tmp_path / "worker-output").root
    (output / "tracked.txt").write_text("changed\n")
    change_set = collect_changes(baseline.manifest, output, write_set_rules=_all_paths())

    with pytest.raises(SupervisorError) as raised:
        build_candidate_tree(
            repository,
            baseline,
            change_set,
            base_sha=os.fsdecode(_git(repository, "rev-parse", "HEAD").strip()),
            write_set_rules=_all_paths(),
        )

    assert raised.value.code == "stale_worker_result"
    assert _git(repository, "status", "--porcelain=v1", "-z") == b""


def test_candidate_tree_rejects_worktree_advanced_past_worker_base(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "repo")
    (repository / "owned.txt").write_text("baseline\n")
    _commit_initial(repository)
    base_sha = os.fsdecode(_git(repository, "rev-parse", "HEAD").strip())
    baseline = copy_snapshot(repository, tmp_path / "baseline")
    output = copy_snapshot(repository, tmp_path / "worker-output").root
    (output / "owned.txt").write_text("result\n")
    change_set = collect_changes(baseline.manifest, output, write_set_rules=_all_paths())
    (repository / "later.txt").write_text("later\n")
    _git(repository, "add", "later.txt")
    _git(
        repository,
        "-c",
        "user.name=ACP tests",
        "-c",
        "user.email=acp-tests@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "advanced",
    )

    with pytest.raises(SupervisorError) as raised:
        build_candidate_tree(
            repository,
            baseline,
            change_set,
            base_sha=base_sha,
            write_set_rules=_all_paths(),
        )

    assert raised.value.code == "stale_worker_result"
