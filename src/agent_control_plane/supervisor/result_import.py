"""Host-built Git candidate trees for validated worker result deltas.

This module writes only content-addressed objects and a temporary index. It
does not read worker Git metadata, create commits or refs, or mutate a
registered worktree. Durable import/recovery remains a separate requirement.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .common import SupervisorError
from .sandbox_workspace import (
    _DEFAULT_LIMITS,
    ChangeSet,
    Snapshot,
    SnapshotLimits,
    read_snapshot_files,
    validate_change_set_write_set,
)


@dataclass(frozen=True)
class CandidateTree:
    """Git tree constructed from a validated host-side result change set."""

    tree_sha: str
    base_sha: str
    baseline_digest: str
    result_digest: str
    change_digest: str


def build_candidate_tree(
    repository: str | Path,
    baseline: Snapshot,
    change_set: ChangeSet,
    *,
    base_sha: str,
    write_set_rules: Sequence[tuple[str, bool, bool]],
    git_executable: str | Path = "git",
    limits: SnapshotLimits = _DEFAULT_LIMITS,
) -> CandidateTree:
    """Create a trusted Git tree without changing a checkout, ref, or real index.

    The result is reconstructed from the immutable baseline snapshot plus the
    captured change-set bytes. Git receives only host-generated blob objects;
    the worker's `.git`, object IDs, configuration, attributes, filters, hooks,
    and index are never opened or consumed.
    """

    if type(baseline) is not Snapshot or type(change_set) is not ChangeSet:
        raise SupervisorError("invalid_worker_result", "snapshot or change set is invalid")
    baseline.manifest.validate(limits)
    change_set.validate(limits)
    result_manifest = validate_change_set_write_set(
        baseline.manifest,
        change_set,
        write_set_rules=write_set_rules,
        limits=limits,
    )
    baseline_files = read_snapshot_files(baseline, limits=limits)
    changes = {change.path: change for change in change_set.changes}

    try:
        resolved_repository = Path(repository).resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        raise SupervisorError(
            "invalid_git_repository", "registered repository path is invalid"
        ) from error
    if not resolved_repository.is_dir():
        raise SupervisorError("invalid_git_repository", "registered repository is not a directory")
    executable = shutil.which(os.fspath(git_executable))
    if executable is None or not os.access(executable, os.X_OK):
        raise SupervisorError("git_unavailable", "trusted Git executable is unavailable")

    with tempfile.TemporaryDirectory(prefix="acp-candidate-index-") as temporary_directory:
        index_path = Path(temporary_directory) / "index"
        environment = _git_environment(index_path)
        raw_top_level = _run_git(
            executable,
            resolved_repository,
            ("rev-parse", "--show-toplevel"),
            environment,
        )
        if not raw_top_level.endswith(b"\n"):
            raise SupervisorError("invalid_git_repository", "Git returned an invalid worktree root")
        top_level = raw_top_level[:-1].decode("utf-8", errors="strict")
        if Path(top_level).resolve(strict=True) != resolved_repository:
            raise SupervisorError(
                "invalid_git_repository", "repository path is not the worktree root"
            )

        object_format = (
            _run_git(
                executable,
                resolved_repository,
                ("rev-parse", "--show-object-format"),
                environment,
            )
            .decode("ascii", errors="strict")
            .strip()
        )
        if object_format not in {"sha1", "sha256"}:
            raise SupervisorError("invalid_git_repository", "Git object format is unsupported")
        object_id_length = 40 if object_format == "sha1" else 64
        if not re.fullmatch(rf"[0-9a-f]{{{object_id_length}}}", base_sha):
            raise SupervisorError("stale_worker_result", "candidate base commit ID is invalid")
        resolved_base = (
            _run_git(
                executable,
                resolved_repository,
                ("rev-parse", "--verify", f"{base_sha}^{{commit}}"),
                environment,
            )
            .decode("ascii", errors="strict")
            .strip()
        )
        current_head = (
            _run_git(
                executable,
                resolved_repository,
                ("rev-parse", "--verify", "HEAD"),
                environment,
            )
            .decode("ascii", errors="strict")
            .strip()
        )
        if resolved_base != base_sha or current_head != base_sha:
            raise SupervisorError(
                "stale_worker_result", "registered worktree no longer matches candidate base"
            )
        _assert_snapshot_matches_tree(
            executable,
            resolved_repository,
            base_sha,
            baseline,
            baseline_files,
            object_format,
            environment,
        )

        _run_git(executable, resolved_repository, ("read-tree", "--empty"), environment)
        object_ids: dict[tuple[int, str], str] = {}
        index_records: list[bytes] = []
        for entry in result_manifest.entries:
            if entry.kind == "directory":
                # Git trees do not represent empty directories. Non-empty
                # parents are created implicitly by their indexed descendants.
                continue
            change = changes.get(entry.path)
            if entry.kind == "file":
                content = (
                    change.content
                    if change is not None and change.action != "delete" and change.kind == "file"
                    else baseline_files.get(entry.path)
                )
                if content is None or len(content) != entry.size:
                    raise SupervisorError(
                        "invalid_worker_result", "result file bytes do not match the manifest"
                    )
                content_digest = hashlib.sha256(content).hexdigest()
                if content_digest != entry.content_sha256:
                    raise SupervisorError(
                        "invalid_worker_result", "result file digest does not match the manifest"
                    )
                mode = "100755" if entry.mode == 0o755 else "100644"
            else:
                content = entry.symlink_target.encode("utf-8")
                if len(content) != entry.size:
                    raise SupervisorError(
                        "invalid_worker_result", "result symlink bytes do not match the manifest"
                    )
                content_digest = hashlib.sha256(content).hexdigest()
                mode = "120000"

            content_key = (len(content), content_digest)
            object_id = object_ids.get(content_key)
            if object_id is None:
                object_id = (
                    _run_git(
                        executable,
                        resolved_repository,
                        ("hash-object", "-w", "--no-filters", "--stdin"),
                        environment,
                        input_bytes=content,
                    )
                    .decode("ascii", errors="strict")
                    .strip()
                )
                if not re.fullmatch(rf"[0-9a-f]{{{object_id_length}}}", object_id):
                    raise SupervisorError(
                        "candidate_tree_failed", "Git returned an invalid blob object ID"
                    )
                object_ids[content_key] = object_id
            index_records.append(
                f"{mode} blob {object_id}\t".encode("ascii") + entry.path.encode("utf-8") + b"\0"
            )

        if index_records:
            _run_git(
                executable,
                resolved_repository,
                ("update-index", "--add", "-z", "--index-info"),
                environment,
                input_bytes=b"".join(index_records),
            )
        tree_sha = (
            _run_git(
                executable,
                resolved_repository,
                ("write-tree",),
                environment,
            )
            .decode("ascii", errors="strict")
            .strip()
        )
        if not re.fullmatch(rf"[0-9a-f]{{{object_id_length}}}", tree_sha):
            raise SupervisorError("candidate_tree_failed", "Git returned an invalid tree object ID")
        object_type = (
            _run_git(
                executable,
                resolved_repository,
                ("cat-file", "-t", tree_sha),
                environment,
            )
            .decode("ascii", errors="strict")
            .strip()
        )
        if object_type != "tree":
            raise SupervisorError("candidate_tree_failed", "Git candidate object is not a tree")
        current_head = (
            _run_git(
                executable,
                resolved_repository,
                ("rev-parse", "--verify", "HEAD"),
                environment,
            )
            .decode("ascii", errors="strict")
            .strip()
        )
        if current_head != base_sha:
            raise SupervisorError(
                "stale_worker_result", "registered worktree changed while candidate tree was built"
            )

    return CandidateTree(
        tree_sha=tree_sha,
        base_sha=base_sha,
        baseline_digest=baseline.manifest.digest,
        result_digest=result_manifest.digest,
        change_digest=change_set.digest,
    )


def _assert_snapshot_matches_tree(
    executable: str,
    repository: Path,
    base_sha: str,
    baseline: Snapshot,
    baseline_files: dict[str, bytes],
    object_format: str,
    environment: dict[str, str],
) -> None:
    raw_entries = _run_git(
        executable,
        repository,
        ("ls-tree", "-r", "-z", "--full-tree", f"{base_sha}^{{tree}}"),
        environment,
    )
    git_entries: dict[str, tuple[str, str, str]] = {}
    for record in raw_entries.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", maxsplit=1)
            raw_mode, raw_kind, raw_oid = metadata.split(b" ", maxsplit=2)
            path = raw_path.decode("utf-8", errors="strict")
            mode = raw_mode.decode("ascii", errors="strict")
            kind = raw_kind.decode("ascii", errors="strict")
            object_id = raw_oid.decode("ascii", errors="strict")
        except (UnicodeDecodeError, ValueError) as error:
            raise SupervisorError(
                "stale_worker_result", "base Git tree contains an unsupported path or entry"
            ) from error
        if path in git_entries:
            raise SupervisorError("stale_worker_result", "base Git tree has duplicate paths")
        git_entries[path] = (mode, kind, object_id)

    manifest_entries = {entry.path: entry for entry in baseline.manifest.entries}
    manifest_leaves = {
        path: entry for path, entry in manifest_entries.items() if entry.kind != "directory"
    }
    if set(git_entries) != set(manifest_leaves):
        raise SupervisorError(
            "stale_worker_result",
            "snapshot paths differ from the tracked base tree; untracked files are not importable",
        )

    expected_directories: set[str] = set()
    for path, entry in manifest_leaves.items():
        parts = path.split("/")
        expected_directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
        git_mode, git_kind, git_oid = git_entries[path]
        expected_mode = (
            "100755"
            if entry.kind == "file" and entry.mode == 0o755
            else "100644"
            if entry.kind == "file"
            else "120000"
        )
        if git_kind != "blob" or git_mode != expected_mode:
            raise SupervisorError(
                "stale_worker_result", f"base Git entry {path!r} differs from its snapshot type"
            )
        content = (
            baseline_files[path] if entry.kind == "file" else entry.symlink_target.encode("utf-8")
        )
        header = f"blob {len(content)}\0".encode("ascii")
        expected_oid = hashlib.new(object_format, header + content).hexdigest()
        if expected_oid != git_oid:
            raise SupervisorError(
                "stale_worker_result", f"base Git blob {path!r} differs from its snapshot"
            )

    snapshot_directories = {
        path for path, entry in manifest_entries.items() if entry.kind == "directory"
    }
    if snapshot_directories != expected_directories:
        raise SupervisorError(
            "stale_worker_result",
            "snapshot has empty or missing directories that are absent from the Git tree",
        )


def _git_environment(index_path: Path) -> dict[str, str]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name == "GIT" or name.startswith("GIT_"):
            environment.pop(name, None)
    environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_COUNT": "0",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_INDEX_FILE": str(index_path),
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _run_git(
    executable: str,
    repository: Path,
    arguments: tuple[str, ...],
    environment: dict[str, str],
    *,
    input_bytes: bytes | None = None,
) -> bytes:
    try:
        result = subprocess.run(
            [executable, "-C", str(repository), *arguments],
            input=input_bytes,
            capture_output=True,
            env=environment,
            check=False,
            close_fds=True,
        )
    except OSError as error:
        raise SupervisorError(
            "candidate_tree_failed", "trusted Git command could not start"
        ) from error
    if result.returncode != 0:
        raise SupervisorError("candidate_tree_failed", "trusted Git rejected candidate tree input")
    return result.stdout
