from __future__ import annotations

import os
import shlex
import subprocess
import uuid
from pathlib import Path

import pytest

from agent_control_plane.supervisor.common import SupervisorError
from agent_control_plane.supervisor.result_import import (
    CandidateTree,
    build_candidate_tree,
    candidate_commit_object,
    candidate_commit_payload,
    candidate_ref_target,
    publish_candidate_ref,
    result_ref_name,
    verify_candidate_objects,
)
from agent_control_plane.supervisor.sandbox_workspace import (
    SnapshotLimits,
    collect_changes,
    copy_snapshot,
)


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


def _shared_index_snapshot(repository: Path) -> dict[str, bytes]:
    git_directory = Path(
        os.fsdecode(_git(repository, "rev-parse", "--path-format=absolute", "--git-dir").strip())
    )
    return {path.name: path.read_bytes() for path in git_directory.glob("sharedindex.*")}


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
    _git(repository, "update-index", "--split-index")
    _git(repository, "config", "core.splitIndex", "true")
    hook_directory = tmp_path / "host-hooks"
    hook_directory.mkdir()
    hook_marker = tmp_path / "host-hook-ran"
    post_index_hook = hook_directory / "post-index-change"
    post_index_hook.write_text(f"#!/bin/sh\nprintf x > {shlex.quote(str(hook_marker))}\n")
    post_index_hook.chmod(0o700)
    _git(repository, "config", "core.hooksPath", str(hook_directory))

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
    shared_indexes_before = _shared_index_snapshot(repository)
    assert shared_indexes_before
    _git(repository, "config", "splitIndex.sharedIndexExpire", "now")
    hook_marker.unlink(missing_ok=True)

    base_sha = os.fsdecode(_git(repository, "rev-parse", "HEAD").strip())
    candidate = build_candidate_tree(
        repository,
        baseline,
        change_set,
        base_sha=base_sha,
        write_set_rules=_all_paths(),
    )
    assert not hook_marker.exists()
    assert _shared_index_snapshot(repository) == shared_indexes_before

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


def test_candidate_tree_fails_closed_on_git_without_config_environment_support(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "repo")
    (repository / "owned.txt").write_text("baseline\n")
    _commit_initial(repository)
    baseline = copy_snapshot(repository, tmp_path / "baseline")
    output = copy_snapshot(repository, tmp_path / "worker-output").root
    (output / "owned.txt").write_text("result\n")
    change_set = collect_changes(baseline.manifest, output, write_set_rules=_all_paths())

    invoked_marker = tmp_path / "old-git-command-ran"
    old_git = tmp_path / "old-git"
    old_git.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then\n'
        "  printf '%s\\n' 'git version 2.31.9'\n"
        "  exit 0\n"
        "fi\n"
        f"printf x > {shlex.quote(str(invoked_marker))}\n"
        "exit 99\n"
    )
    old_git.chmod(0o700)

    with pytest.raises(SupervisorError) as raised:
        build_candidate_tree(
            repository,
            baseline,
            change_set,
            base_sha=os.fsdecode(_git(repository, "rev-parse", "HEAD").strip()),
            write_set_rules=_all_paths(),
            git_executable=old_git,
        )

    assert raised.value.code == "git_version_unsupported"
    assert not invoked_marker.exists()
    assert _git(repository, "status", "--porcelain=v1", "-z") == b""


@pytest.mark.parametrize("bound", ["entries", "path"])
def test_candidate_tree_bounds_base_tree_enumeration(tmp_path: Path, bound: str) -> None:
    limits = (
        SnapshotLimits(max_entries=2, max_total_bytes=1024, max_file_bytes=1024)
        if bound == "entries"
        else SnapshotLimits(
            max_entries=4,
            max_total_bytes=1024,
            max_file_bytes=1024,
            max_path_bytes=8,
        )
    )
    repository = _repository(tmp_path / "repo")
    (repository / "one.txt").write_text("one\n")
    (repository / "two.txt").write_text("two\n")
    extra_path = "extra.txt" if bound == "entries" else "long-extra-name.txt"
    (repository / extra_path).write_text("not in the bounded snapshot\n")
    _commit_initial(repository)

    snapshot_source = tmp_path / "snapshot-source"
    snapshot_source.mkdir()
    (snapshot_source / "one.txt").write_text("one\n")
    (snapshot_source / "two.txt").write_text("two\n")
    baseline = copy_snapshot(snapshot_source, tmp_path / "baseline", limits=limits)
    output = copy_snapshot(baseline.root, tmp_path / "out", limits=limits).root
    (output / "one.txt").write_text("changed\n")
    change_set = collect_changes(
        baseline.manifest,
        output,
        write_set_rules=_all_paths(),
        limits=limits,
    )

    with pytest.raises(SupervisorError) as raised:
        build_candidate_tree(
            repository,
            baseline,
            change_set,
            base_sha=os.fsdecode(_git(repository, "rev-parse", "HEAD").strip()),
            write_set_rules=_all_paths(),
            limits=limits,
        )

    assert raised.value.code == "workspace_limit_exceeded"
    assert _git(repository, "status", "--porcelain=v1", "-z") == b""


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


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
def test_host_result_commit_uses_immutable_compare_and_swap_ref(
    tmp_path: Path, object_format: str
) -> None:
    repository = _repository(tmp_path / "repo", object_format=object_format)
    (repository / "tracked.txt").write_text("base\n")
    _commit_initial(repository)
    base_sha = os.fsdecode(_git(repository, "rev-parse", "HEAD").strip())
    tree_sha = os.fsdecode(_git(repository, "rev-parse", "HEAD^{tree}").strip())
    attempt_id = str(uuid.uuid4())
    result_digest = "d" * 64
    candidate = CandidateTree(
        tree_sha=tree_sha,
        base_sha=base_sha,
        baseline_digest="a" * 64,
        result_digest="b" * 64,
        change_digest="c" * 64,
    )
    payload = candidate_commit_payload(
        candidate,
        attempt_id=attempt_id,
        claim_token=7,
        result_digest=result_digest,
        committed_at=123456,
    )
    reference = result_ref_name(attempt_id, 7, result_digest)

    commit_sha = candidate_commit_object(repository, payload, write=False)
    assert candidate_ref_target(repository, reference) is None
    assert candidate_commit_object(repository, payload, write=True) == commit_sha
    verify_candidate_objects(repository, candidate, commit_sha=commit_sha)
    publish_candidate_ref(repository, reference, commit_sha)
    publish_candidate_ref(repository, reference, commit_sha)
    assert candidate_ref_target(repository, reference) == commit_sha

    conflicting_payload = candidate_commit_payload(
        candidate,
        attempt_id=attempt_id,
        claim_token=7,
        result_digest=result_digest,
        committed_at=123457,
    )
    conflicting_sha = candidate_commit_object(repository, conflicting_payload, write=True)
    with pytest.raises(SupervisorError) as raised:
        publish_candidate_ref(repository, reference, conflicting_sha)
    assert raised.value.code == "result_import_ambiguous"
    assert os.fsdecode(_git(repository, "rev-parse", "HEAD").strip()) == base_sha
    assert _git(repository, "status", "--porcelain=v1", "-z") == b""
