"""Host-built Git trees and immutable refs for validated worker result deltas.

This module never reads worker Git metadata or mutates a registered worktree.
It constructs candidate trees from host-validated bytes, creates deterministic
host-authored commits, and publishes only absent-only refs in ACP's result
namespace. The supervisor owns the durable journal and submission transaction.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import uuid
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


def result_ref_name(attempt_id: str, claim_token: int, result_digest: str) -> str:
    """Return the immutable, attempt-fenced ref for one imported result."""

    try:
        if str(uuid.UUID(attempt_id)) != attempt_id:
            raise ValueError
    except (AttributeError, TypeError, ValueError):
        raise SupervisorError("invalid_worker_result", "attempt ID is invalid") from None
    if type(claim_token) is not int or claim_token < 1:
        raise SupervisorError("invalid_worker_result", "claim token is invalid")
    if re.fullmatch(r"[0-9a-f]{64}", result_digest) is None:
        raise SupervisorError("invalid_worker_result", "result digest is invalid")
    return f"refs/acp/worker-results/{attempt_id}/{claim_token}/{result_digest}"


def _validate_result_ref(reference: str) -> None:
    if not isinstance(reference, str):
        raise SupervisorError("invalid_worker_result", "result ref is invalid")
    parts = reference.split("/")
    if len(parts) != 6 or parts[:3] != ["refs", "acp", "worker-results"]:
        raise SupervisorError("invalid_worker_result", "result ref namespace is invalid")
    try:
        claim_token = int(parts[4])
    except ValueError:
        raise SupervisorError(
            "invalid_worker_result", "result ref claim token is invalid"
        ) from None
    if result_ref_name(parts[3], claim_token, parts[5]) != reference:
        raise SupervisorError("invalid_worker_result", "result ref is not canonical")


def candidate_commit_payload(
    candidate: CandidateTree,
    *,
    attempt_id: str,
    claim_token: int,
    result_digest: str,
    committed_at: int,
) -> bytes:
    """Serialize a deterministic host-authored commit from a validated tree."""

    result_ref_name(attempt_id, claim_token, result_digest)
    if type(candidate) is not CandidateTree:
        raise SupervisorError("invalid_worker_result", "candidate tree is invalid")
    if any(
        re.fullmatch(r"[0-9a-f]{64}", digest) is None
        for digest in (
            candidate.baseline_digest,
            candidate.result_digest,
            candidate.change_digest,
            result_digest,
        )
    ):
        raise SupervisorError("invalid_worker_result", "candidate result digests are invalid")
    object_id_length = len(candidate.base_sha)
    if object_id_length not in {40, 64} or len(candidate.tree_sha) != object_id_length:
        raise SupervisorError("invalid_worker_result", "candidate Git object IDs are invalid")
    if any(
        re.fullmatch(rf"[0-9a-f]{{{object_id_length}}}", object_id) is None
        for object_id in (candidate.base_sha, candidate.tree_sha)
    ):
        raise SupervisorError("invalid_worker_result", "candidate Git object IDs are invalid")
    if type(committed_at) is not int or committed_at < 0:
        raise SupervisorError("invalid_worker_result", "candidate commit timestamp is invalid")
    identity = f"Agent Control Plane <acp-worker-result@invalid> {committed_at} +0000"
    message = (
        "Agent Control Plane worker result\n\n"
        f"Attempt: {attempt_id}\n"
        f"Claim-Token: {claim_token}\n"
        f"Result-SHA256: {result_digest}\n"
        f"Baseline-SHA256: {candidate.baseline_digest}\n"
        f"Change-SHA256: {candidate.change_digest}\n"
    )
    return (
        f"tree {candidate.tree_sha}\nparent {candidate.base_sha}\n"
        f"author {identity}\ncommitter {identity}\n\n{message}"
    ).encode()


def candidate_commit_object(
    repository: str | Path,
    payload: bytes,
    *,
    write: bool,
    git_executable: str | Path = "git",
) -> str:
    """Compute or write a commit object using isolated, trusted Git settings."""

    try:
        resolved_repository = Path(repository).resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        raise SupervisorError(
            "invalid_git_repository", "registered repository path is invalid"
        ) from error
    executable = shutil.which(os.fspath(git_executable))
    if executable is None or not os.access(executable, os.X_OK):
        raise SupervisorError("git_unavailable", "trusted Git executable is unavailable")

    with tempfile.TemporaryDirectory(prefix="acp-result-commit-") as temporary_directory:
        index_path = Path(temporary_directory) / "index"
        hooks_path = Path(temporary_directory) / "empty-hooks"
        hooks_path.mkdir(mode=0o700)
        environment = _git_environment(index_path, hooks_path)
        _assert_supported_git_version(executable, environment)
        arguments = ("hash-object", *(("-w",) if write else ()), "-t", "commit", "--stdin")
        object_id = (
            _run_git(
                executable,
                resolved_repository,
                arguments,
                environment,
                input_bytes=payload,
            )
            .decode("ascii", errors="strict")
            .strip()
        )
    object_id_length = 40 if len(object_id) == 40 else 64 if len(object_id) == 64 else 0
    if object_id_length == 0 or re.fullmatch(rf"[0-9a-f]{{{object_id_length}}}", object_id) is None:
        raise SupervisorError("candidate_tree_failed", "Git returned an invalid commit object ID")
    return object_id


def verify_candidate_objects(
    repository: str | Path,
    candidate: CandidateTree,
    *,
    commit_sha: str | None = None,
    git_executable: str | Path = "git",
) -> None:
    """Verify the exact base/tree objects, and optionally the host commit's edges."""

    if type(candidate) is not CandidateTree:
        raise SupervisorError("invalid_worker_result", "candidate tree is invalid")
    try:
        resolved_repository = Path(repository).resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        raise SupervisorError(
            "invalid_git_repository", "registered repository path is invalid"
        ) from error
    executable = shutil.which(os.fspath(git_executable))
    if executable is None or not os.access(executable, os.X_OK):
        raise SupervisorError("git_unavailable", "trusted Git executable is unavailable")

    with tempfile.TemporaryDirectory(prefix="acp-result-verify-") as temporary_directory:
        index_path = Path(temporary_directory) / "index"
        hooks_path = Path(temporary_directory) / "empty-hooks"
        hooks_path.mkdir(mode=0o700)
        environment = _git_environment(index_path, hooks_path)
        _assert_supported_git_version(executable, environment)
        base_type = (
            _run_git(
                executable,
                resolved_repository,
                ("cat-file", "-t", candidate.base_sha),
                environment,
            )
            .decode("ascii", errors="strict")
            .strip()
        )
        tree_type = (
            _run_git(
                executable,
                resolved_repository,
                ("cat-file", "-t", candidate.tree_sha),
                environment,
            )
            .decode("ascii", errors="strict")
            .strip()
        )
        if base_type != "commit" or tree_type != "tree":
            raise SupervisorError(
                "result_import_ambiguous", "candidate base or tree object is invalid"
            )
        if commit_sha is None:
            return
        commit_type = (
            _run_git(
                executable,
                resolved_repository,
                ("cat-file", "-t", commit_sha),
                environment,
            )
            .decode("ascii", errors="strict")
            .strip()
        )
        if commit_type != "commit":
            raise SupervisorError("result_import_ambiguous", "result ref does not name a commit")
        commit_tree = (
            _run_git(
                executable,
                resolved_repository,
                ("rev-parse", "--verify", f"{commit_sha}^{{tree}}"),
                environment,
            )
            .decode("ascii", errors="strict")
            .strip()
        )
        parent = (
            _run_git(
                executable,
                resolved_repository,
                ("rev-parse", "--verify", f"{commit_sha}^"),
                environment,
            )
            .decode("ascii", errors="strict")
            .strip()
        )
        if commit_tree != candidate.tree_sha or parent != candidate.base_sha:
            raise SupervisorError(
                "result_import_ambiguous", "host result commit edges do not match"
            )


def candidate_ref_target(
    repository: str | Path,
    reference: str,
    *,
    git_executable: str | Path = "git",
) -> str | None:
    """Read the exact result ref, rejecting unexpected nested or duplicate refs."""

    _validate_result_ref(reference)
    try:
        resolved_repository = Path(repository).resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        raise SupervisorError(
            "invalid_git_repository", "registered repository path is invalid"
        ) from error
    executable = shutil.which(os.fspath(git_executable))
    if executable is None or not os.access(executable, os.X_OK):
        raise SupervisorError("git_unavailable", "trusted Git executable is unavailable")

    with tempfile.TemporaryDirectory(prefix="acp-result-ref-") as temporary_directory:
        index_path = Path(temporary_directory) / "index"
        hooks_path = Path(temporary_directory) / "empty-hooks"
        hooks_path.mkdir(mode=0o700)
        environment = _git_environment(index_path, hooks_path)
        _assert_supported_git_version(executable, environment)
        raw = _run_git(
            executable,
            resolved_repository,
            ("for-each-ref", "--format=%(refname) %(objectname)", reference),
            environment,
        )
    rows = [line.split() for line in raw.splitlines() if line]
    if not rows:
        return None
    if len(rows) != 1 or len(rows[0]) != 2:
        raise SupervisorError("result_import_ambiguous", "result ref namespace is ambiguous")
    try:
        row_reference = rows[0][0].decode("ascii")
        object_id = rows[0][1].decode("ascii")
    except UnicodeDecodeError:
        raise SupervisorError(
            "result_import_ambiguous", "result ref target is unreadable"
        ) from None
    if row_reference != reference:
        raise SupervisorError("result_import_ambiguous", "result ref namespace is ambiguous")
    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", object_id) is None:
        raise SupervisorError("result_import_ambiguous", "result ref target is invalid")
    return object_id


def publish_candidate_ref(
    repository: str | Path,
    reference: str,
    commit_sha: str,
    *,
    git_executable: str | Path = "git",
) -> None:
    """Publish an immutable result ref with an absent-only compare-and-swap."""

    _validate_result_ref(reference)
    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit_sha) is None:
        raise SupervisorError("invalid_worker_result", "candidate commit ID is invalid")
    current = candidate_ref_target(repository, reference, git_executable=git_executable)
    if current == commit_sha:
        return
    if current is not None:
        raise SupervisorError("result_import_ambiguous", "result ref already names another commit")

    try:
        resolved_repository = Path(repository).resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        raise SupervisorError(
            "invalid_git_repository", "registered repository path is invalid"
        ) from error
    executable = shutil.which(os.fspath(git_executable))
    if executable is None or not os.access(executable, os.X_OK):
        raise SupervisorError("git_unavailable", "trusted Git executable is unavailable")
    zero = "0" * len(commit_sha)
    with tempfile.TemporaryDirectory(prefix="acp-result-ref-write-") as temporary_directory:
        index_path = Path(temporary_directory) / "index"
        hooks_path = Path(temporary_directory) / "empty-hooks"
        hooks_path.mkdir(mode=0o700)
        environment = _git_environment(index_path, hooks_path)
        _assert_supported_git_version(executable, environment)
        try:
            _run_git(
                executable,
                resolved_repository,
                ("update-ref", reference, commit_sha, zero),
                environment,
            )
        except SupervisorError:
            if (
                candidate_ref_target(resolved_repository, reference, git_executable=executable)
                == commit_sha
            ):
                return
            raise


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
        hooks_path = Path(temporary_directory) / "empty-hooks"
        hooks_path.mkdir(mode=0o700)
        environment = _git_environment(index_path, hooks_path)
        _assert_supported_git_version(executable, environment)
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
            limits,
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
    limits: SnapshotLimits,
    environment: dict[str, str],
) -> None:
    git_entries = _read_base_tree_entries(
        executable,
        repository,
        base_sha,
        object_id_length=40 if object_format == "sha1" else 64,
        limits=limits,
        environment=environment,
    )

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


def _read_base_tree_entries(
    executable: str,
    repository: Path,
    base_sha: str,
    *,
    object_id_length: int,
    limits: SnapshotLimits,
    environment: dict[str, str],
) -> dict[str, tuple[str, str, str]]:
    """Stream a base tree with hard per-record and entry-count bounds."""

    try:
        process = subprocess.Popen(
            [
                executable,
                "-C",
                str(repository),
                "ls-tree",
                "-r",
                "-z",
                "--full-tree",
                f"{base_sha}^{{tree}}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            close_fds=True,
        )
    except OSError as error:
        raise SupervisorError(
            "candidate_tree_failed", "trusted Git tree enumeration could not start"
        ) from error

    if process.stdout is None:
        process.kill()
        process.wait()
        raise SupervisorError("candidate_tree_failed", "trusted Git tree output is unavailable")

    entries: dict[str, tuple[str, str, str]] = {}
    record = bytearray()
    max_record_bytes = limits.max_path_bytes + 128

    def add_entry(raw_record: bytes) -> None:
        try:
            metadata, raw_path = raw_record.split(b"\t", maxsplit=1)
            raw_mode, raw_kind, raw_oid = metadata.split(b" ", maxsplit=2)
            if len(raw_path) > limits.max_path_bytes:
                raise SupervisorError(
                    "workspace_limit_exceeded", "base Git tree path exceeds configured limit"
                )
            if len(raw_oid) != object_id_length or re.fullmatch(rb"[0-9a-f]+", raw_oid) is None:
                raise ValueError("Git object ID is invalid")
            path = raw_path.decode("utf-8", errors="strict")
            mode = raw_mode.decode("ascii", errors="strict")
            kind = raw_kind.decode("ascii", errors="strict")
            object_id = raw_oid.decode("ascii", errors="strict")
        except (UnicodeDecodeError, ValueError) as error:
            raise SupervisorError(
                "stale_worker_result", "base Git tree contains an unsupported path or entry"
            ) from error
        if path in entries:
            raise SupervisorError("stale_worker_result", "base Git tree has duplicate paths")
        if len(entries) >= limits.max_entries:
            raise SupervisorError(
                "workspace_limit_exceeded", "base Git tree exceeds configured entry limit"
            )
        entries[path] = (mode, kind, object_id)

    try:
        while chunk := process.stdout.read(64 * 1024):
            start = 0
            while start < len(chunk):
                delimiter = chunk.find(b"\0", start)
                if delimiter < 0:
                    record.extend(chunk[start:])
                    if len(record) > max_record_bytes:
                        raise SupervisorError(
                            "workspace_limit_exceeded",
                            "base Git tree record exceeds configured path limit",
                        )
                    break
                record.extend(chunk[start:delimiter])
                if len(record) > max_record_bytes:
                    raise SupervisorError(
                        "workspace_limit_exceeded",
                        "base Git tree record exceeds configured path limit",
                    )
                if record:
                    add_entry(bytes(record))
                record.clear()
                start = delimiter + 1
        if record:
            raise SupervisorError("candidate_tree_failed", "base Git tree output is malformed")
        if process.wait() != 0:
            raise SupervisorError(
                "candidate_tree_failed", "trusted Git rejected base tree enumeration"
            )
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise
    finally:
        process.stdout.close()

    return entries


def _assert_supported_git_version(executable: str, environment: dict[str, str]) -> None:
    """Fail closed unless Git honors the configuration isolation variables."""

    try:
        result = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            env=environment,
            check=False,
            close_fds=True,
        )
    except OSError as error:
        raise SupervisorError(
            "git_unavailable", "trusted Git executable could not start"
        ) from error
    if result.returncode != 0:
        raise SupervisorError("git_unavailable", "trusted Git version could not be verified")
    match = re.match(rb"git version (\d+)\.(\d+)\.(\d+)(?:\D.*)?$", result.stdout.strip())
    if match is None:
        raise SupervisorError("git_version_unsupported", "trusted Git version is unrecognized")
    version = tuple(int(part) for part in match.groups())
    if version < (2, 32, 0):
        raise SupervisorError(
            "git_version_unsupported", "candidate result import requires Git 2.32.0 or newer"
        )


def _git_environment(index_path: Path, hooks_path: Path) -> dict[str, str]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name == "GIT" or name.startswith("GIT_"):
            environment.pop(name, None)
    environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_COUNT": "5",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": str(hooks_path),
            "GIT_CONFIG_KEY_1": "core.fsmonitor",
            "GIT_CONFIG_VALUE_1": "false",
            "GIT_CONFIG_KEY_2": "maintenance.auto",
            "GIT_CONFIG_VALUE_2": "false",
            "GIT_CONFIG_KEY_3": "gc.auto",
            "GIT_CONFIG_VALUE_3": "0",
            "GIT_CONFIG_KEY_4": "core.splitIndex",
            "GIT_CONFIG_VALUE_4": "false",
            "GIT_INDEX_FILE": str(index_path),
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
            "PAGER": "cat",
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
