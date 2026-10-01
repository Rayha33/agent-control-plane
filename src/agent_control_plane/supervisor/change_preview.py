"""Read-only, metadata-only previews of an ACP attempt's Git changes."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import sys as _sys
import tempfile
import uuid
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .common import SupervisorError

_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_REF_NAME = re.compile(r"refs/[A-Za-z0-9._/-]{1,1024}\Z")
_SHARED_INDEX = re.compile(r"sharedindex\.(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_MAX_RETURNED_PATHS = 1000
_MAX_INDEX_FILE_BYTES = 64 * 1024 * 1024
_MAX_INDEX_TOTAL_BYTES = 128 * 1024 * 1024
_MAX_INDEX_FILES = 128
_MAX_PACKED_REFS_BYTES = 16 * 1024 * 1024
_GIT_TIMEOUT_SECONDS = 30
_EXEC_GIT_FROM_DIR_FD = (
    "import os,sys; fd=int(sys.argv[1]); executable=sys.argv[2]; "
    "os.fchdir(fd); os.execve(executable, [executable, *sys.argv[3:]], os.environ)"
)


class ChangePreviewMixin:
    """Inspect changed path names without exposing contents or changing Git state."""

    def change_preview(self, attempt_id: str) -> dict[str, Any]:
        """Return committed and working-tree path metadata for one attempt.

        A preview is deliberately refused on a read-write supervisor. Git runs against
        disposable metadata and a captured index, not the attempt's config or Git directory.
        Fixed path/status commands also disable external diff, textconv, pager, fsmonitor,
        optional index locking, replacement objects and submodule traversal.
        """

        if not self.read_only:
            raise SupervisorError(
                "read_only_required", "change preview requires a read-only supervisor"
            )
        if not isinstance(attempt_id, str):
            raise SupervisorError("invalid_attempt_id", "attempt_id must be a UUID")
        try:
            canonical_id = str(uuid.UUID(attempt_id))
        except (ValueError, AttributeError):
            raise SupervisorError("invalid_attempt_id", "attempt_id must be a UUID") from None
        if canonical_id != attempt_id:
            raise SupervisorError("invalid_attempt_id", "attempt_id must be a canonical UUID")

        with self.connect() as connection:
            attempt = connection.execute(
                "SELECT id, start_sha, worktree FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
        if attempt is None:
            raise SupervisorError("attempt_not_found", f"attempt {attempt_id} not found")

        worktree, identity = self._preview_worktree(attempt_id, attempt["worktree"])
        self._assert_no_git_grafts()
        base_common = self._git_common_dir
        attempt_common = self._validate_attempt_git_context(
            worktree, attempt_id, base_common, identity
        )
        if base_common != attempt_common:
            raise SupervisorError(
                "change_preview_incomplete",
                "attempt worktree is not attached to this ACP repository",
            )
        head_before = self._resolve_attempt_head(attempt_id, attempt_common)
        start_sha = attempt["start_sha"]
        if not isinstance(start_sha, str) or not _OBJECT_ID.fullmatch(start_sha):
            raise SupervisorError("change_preview_incomplete", "attempt start revision is invalid")

        with self._isolated_git_metadata(attempt_id, attempt_common, head_before) as (
            git_directory,
            initial_index_digest,
        ):
            git_context = (git_directory, git_directory)
            start_sha = self._resolve_preview_commit(
                worktree,
                start_sha,
                expected_identity=identity,
                git_context=git_context,
            )
            head_before = self._resolve_preview_commit(
                worktree,
                head_before,
                expected_identity=identity,
                git_context=git_context,
            )
            status_before = self._working_tree_status(
                worktree,
                expected_identity=identity,
                git_context=git_context,
            )
            committed_paths = self._committed_paths(
                worktree,
                start_sha,
                head_before,
                expected_identity=identity,
                git_context=git_context,
            )
            status_after = self._working_tree_status(
                worktree,
                expected_identity=identity,
                git_context=git_context,
            )
            head_after = self._resolve_attempt_head(attempt_id, attempt_common)
            final_index_digest = self._attempt_index_digest(attempt_id, attempt_common)

            stable = (
                head_before == head_after
                and status_before == status_after
                and initial_index_digest == final_index_digest
                and self._preview_path_still_matches(worktree, identity)
            )
            committed = self._path_summary(committed_paths)
            working_tree = self._path_summary(status_before)
            return {
                "attempt_id": attempt_id,
                "start_sha": start_sha,
                "observed_head": head_before,
                "observed_head_after": head_after,
                "stable": stable,
                "stability": "stable" if stable else "unstable",
                "committed": committed,
                "working_tree": working_tree,
                "git_config_isolated": True,
                "file_contents_included": False,
            }

    def _preview_worktree(
        self, attempt_id: str, recorded: str | None
    ) -> tuple[Path, tuple[int, int]]:
        expected_state = self.root / ".acp"
        expected_worktrees = expected_state / "worktrees"
        try:
            if (
                self.state_dir.is_symlink()
                or self.state_dir.resolve(strict=True) != expected_state
                or expected_worktrees.is_symlink()
                or expected_worktrees.resolve(strict=True) != expected_worktrees
            ):
                raise ValueError("ACP worktree directory is redirected")
            state_stat = expected_state.lstat()
            worktrees_stat = expected_worktrees.lstat()
            if not stat.S_ISDIR(state_stat.st_mode) or not stat.S_ISDIR(worktrees_stat.st_mode):
                raise ValueError("ACP worktree directory is not a real directory")
            worktree = expected_worktrees / attempt_id
            worktree_stat = worktree.lstat()
            if not stat.S_ISDIR(worktree_stat.st_mode) or stat.S_ISLNK(worktree_stat.st_mode):
                raise ValueError("attempt worktree is not a real directory")
            if not isinstance(recorded, str) or not Path(recorded).is_absolute():
                raise ValueError("recorded attempt path is not absolute")
            if Path(recorded) != worktree:
                raise ValueError("recorded attempt path differs from its allocated worktree")
            git_marker = worktree / ".git"
            if not stat.S_ISREG(git_marker.lstat().st_mode):
                raise ValueError("attempt worktree Git marker is not a regular file")
        except (OSError, ValueError, RuntimeError):
            raise SupervisorError(
                "change_preview_incomplete", "attempt worktree is missing or unsafe"
            ) from None
        return worktree, (worktree_stat.st_dev, worktree_stat.st_ino)

    @staticmethod
    def _preview_path_still_matches(worktree: Path, identity: tuple[int, int]) -> bool:
        try:
            current = worktree.lstat()
        except OSError:
            return False
        return (
            stat.S_ISDIR(current.st_mode)
            and not stat.S_ISLNK(current.st_mode)
            and identity == (current.st_dev, current.st_ino)
        )

    @classmethod
    def _validate_attempt_git_context(
        cls, worktree: Path, attempt_id: str, common: Path, worktree_identity: tuple[int, int]
    ) -> Path:
        """Validate the worktree marker and no-follow Git admin pointers."""

        try:
            admin = common / "worktrees" / attempt_id
            admin_fd = cls._open_git_directory(common, f"worktrees/{attempt_id}")
            os.close(admin_fd)

            marker = cls._read_git_relative(
                worktree, ".git", 4096, expected_identity=worktree_identity
            )
            if not marker.startswith(b"gitdir: "):
                raise OSError("attempt Git marker is malformed")
            marker_path = Path(os.fsdecode(marker[8:].rstrip(b"\r\n")))
            if not marker_path.is_absolute():
                marker_path = worktree / marker_path
            if Path(os.path.normpath(marker_path)) != admin:
                raise OSError("attempt Git marker points outside its allocated admin directory")

            back_pointer = cls._read_git_relative(common, f"worktrees/{attempt_id}/gitdir", 4096)
            back_path = Path(os.fsdecode(back_pointer.rstrip(b"\r\n")))
            if not back_path.is_absolute():
                back_path = admin / back_path
            if Path(os.path.normpath(back_path)) != worktree / ".git":
                raise OSError("Git admin directory points at a different worktree")

            common_pointer = cls._read_git_relative(
                common, f"worktrees/{attempt_id}/commondir", 4096
            )
            common_path = Path(os.fsdecode(common_pointer.rstrip(b"\r\n")))
            if not common_path.is_absolute():
                common_path = admin / common_path
            if Path(os.path.normpath(common_path)) != common:
                raise OSError("Git admin directory points at a different common directory")
        except (OSError, ValueError, RuntimeError):
            raise SupervisorError(
                "change_preview_incomplete", "attempt Git metadata is missing or unsafe"
            ) from None
        return common

    def _git_environment(self) -> dict[str, str]:
        environment = self._supervisor_git_env()
        for key in tuple(environment):
            if key.startswith("GIT_CONFIG_") or key in {
                "GIT_CONFIG",
                "GIT_TRACE",
                "GIT_TRACE_SETUP",
                "GIT_TRACE_PACKET",
                "GIT_TRACE_PERFORMANCE",
                "GIT_TRACE_PACK_ACCESS",
                "GIT_TRACE_PACKFILE",
                "GIT_TRACE_REFS",
                "GIT_TRACE_CURL",
                "GIT_TRACE_CURL_NO_DATA",
                "GIT_TRACE2",
                "GIT_TRACE2_EVENT",
                "GIT_TRACE2_PERF",
            }:
                environment.pop(key, None)
        environment.update(
            {
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_ATTR_NOSYSTEM": "1",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_PAGER": "cat",
                "PAGER": "cat",
            }
        )
        return environment

    def _git_output(
        self,
        worktree: Path,
        *arguments: str,
        expected_identity: tuple[int, int] | None = None,
        git_context: tuple[Path, Path] | None = None,
    ) -> bytes:
        git = str(self._system_git_executable(self.root))
        command = [
            git,
            "--no-pager",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.pager=cat",
            "-c",
            f"core.attributesFile={os.devnull}",
            "-c",
            f"core.excludesFile={os.devnull}",
            "-c",
            "maintenance.auto=false",
            "-c",
            "gc.auto=0",
        ]
        environment = self._git_environment()
        if git_context is not None:
            admin_directory, common_directory = git_context
            environment.update(
                {
                    "GIT_DIR": str(admin_directory),
                    "GIT_COMMON_DIR": str(common_directory),
                    "GIT_WORK_TREE": str(worktree),
                }
            )
        worktree_fd: int | None = None
        if expected_identity is not None:
            if (
                git_context is None
                or not hasattr(os, "O_DIRECTORY")
                or not hasattr(os, "O_NOFOLLOW")
            ):
                raise SupervisorError(
                    "change_preview_incomplete", "attempt worktree cannot be pinned safely"
                )
            if not self._preview_path_still_matches(worktree, expected_identity):
                raise SupervisorError(
                    "change_preview_incomplete", "attempt worktree changed or became unsafe"
                )
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            try:
                worktree_fd = os.open(worktree, flags)
                metadata = os.fstat(worktree_fd)
            except OSError:
                if worktree_fd is not None:
                    os.close(worktree_fd)
                raise SupervisorError(
                    "change_preview_incomplete", "attempt worktree could not be pinned safely"
                ) from None
            if not stat.S_ISDIR(metadata.st_mode) or expected_identity != (
                metadata.st_dev,
                metadata.st_ino,
            ):
                os.close(worktree_fd)
                raise SupervisorError(
                    "change_preview_incomplete", "attempt worktree changed or became unsafe"
                )
            environment["GIT_WORK_TREE"] = "."
        try:
            if worktree_fd is None:
                command.extend(["-C", str(worktree), *arguments])
            else:
                # On macOS subprocess cwd cannot be an fd. A tiny isolated interpreter
                # changes directory through the inherited fd, then execs trusted Git;
                # using the worktree pathname here would permit a rename/symlink TOCTOU.
                command = [
                    _sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    _EXEC_GIT_FROM_DIR_FD,
                    str(worktree_fd),
                    git,
                    *command[1:],
                    *arguments,
                ]
            result = subprocess.run(
                command,
                cwd=self.root,
                env=environment,
                capture_output=True,
                timeout=_GIT_TIMEOUT_SECONDS,
                check=False,
                pass_fds=(worktree_fd,) if worktree_fd is not None else (),
            )
        except (OSError, subprocess.TimeoutExpired):
            raise SupervisorError(
                "change_preview_incomplete", "Git could not read attempt metadata safely"
            ) from None
        finally:
            if worktree_fd is not None:
                os.close(worktree_fd)
        if expected_identity is not None and not self._preview_path_still_matches(
            worktree, expected_identity
        ):
            raise SupervisorError(
                "change_preview_incomplete", "attempt worktree changed during inspection"
            )
        if result.returncode:
            raise SupervisorError(
                "change_preview_incomplete",
                f"Git could not read attempt metadata (command {arguments[0]} failed)",
            )
        return result.stdout

    @staticmethod
    def _git_file_signature(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    @classmethod
    def _open_git_directory(cls, root: Path, relative: str = ".") -> int:
        """Open a directory beneath root without following any path symlinks."""

        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            raise OSError("no-follow directory opens are unavailable")
        parts = () if relative == "." else Path(relative).parts
        if (
            Path(relative).is_absolute()
            or any(part in {"", ".", ".."} for part in parts)
            or (relative != "." and not parts)
        ):
            raise OSError("unsafe relative Git directory path")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(root, flags)
        try:
            for component in parts:
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    @classmethod
    def _read_git_relative(
        cls,
        root: Path,
        relative: str,
        max_bytes: int,
        *,
        expected_identity: tuple[int, int] | None = None,
    ) -> bytes:
        """Read one small Git metadata file without following symlink components."""

        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            raise OSError("no-follow directory opens are unavailable")
        parts = Path(relative).parts
        if (
            not parts
            or Path(relative).is_absolute()
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise OSError("unsafe relative Git metadata path")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        directory_fd = cls._open_git_directory(root)
        try:
            root_metadata = os.fstat(directory_fd)
            if expected_identity is not None and expected_identity != (
                root_metadata.st_dev,
                root_metadata.st_ino,
            ):
                raise OSError("Git metadata root changed")
            for component in parts[:-1]:
                next_fd = os.open(component, flags, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
            file_fd = os.open(
                parts[-1],
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_fd,
            )
            try:
                before = os.fstat(file_fd)
                if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
                    raise OSError("Git metadata file is not a bounded regular file")
                chunks: list[bytes] = []
                remaining = max_bytes + 1
                while remaining:
                    chunk = os.read(file_fd, min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                content = b"".join(chunks)
                after = os.fstat(file_fd)
                if len(content) > max_bytes or cls._git_file_signature(
                    before
                ) != cls._git_file_signature(after):
                    raise OSError("Git metadata changed during read")
                return content
            finally:
                os.close(file_fd)
        finally:
            os.close(directory_fd)

    @classmethod
    def _resolve_attempt_head(cls, attempt_id: str, common: Path) -> str:
        """Resolve an attempt HEAD using only no-follow reads of its Git metadata."""

        try:
            head = (
                cls._read_git_relative(common, f"worktrees/{attempt_id}/HEAD", 4096)
                .decode("ascii")
                .strip()
            )
            seen: set[str] = set()
            for _ in range(8):
                if _OBJECT_ID.fullmatch(head):
                    return head
                if not head.startswith("ref: "):
                    break
                ref = head[5:]
                if (
                    not _REF_NAME.fullmatch(ref)
                    or ".." in ref
                    or "//" in ref
                    or "@{" in ref
                    or any(
                        part.startswith(".") or part.endswith(".lock") for part in ref.split("/")
                    )
                    or ref in seen
                ):
                    break
                seen.add(ref)
                try:
                    head = cls._read_git_relative(common, ref, 4096).decode("ascii").strip()
                    continue
                except FileNotFoundError:
                    packed = cls._read_git_relative(common, "packed-refs", _MAX_PACKED_REFS_BYTES)
                    resolved = None
                    for line in packed.splitlines():
                        if not line or line.startswith((b"#", b"^")):
                            continue
                        object_id, separator, packed_ref = line.partition(b" ")
                        if separator and packed_ref == ref.encode("ascii"):
                            try:
                                candidate = object_id.decode("ascii")
                            except UnicodeDecodeError:
                                break
                            if _OBJECT_ID.fullmatch(candidate):
                                resolved = candidate
                            break
                    if resolved is None:
                        break
                    return resolved
            raise OSError("attempt HEAD does not resolve to a commit object name")
        except (OSError, UnicodeDecodeError, ValueError):
            raise SupervisorError(
                "change_preview_incomplete", "attempt HEAD is missing or unsafe"
            ) from None

    @classmethod
    def _index_snapshot(cls, attempt_id: str, common: Path, destination: Path | None = None) -> str:
        """Hash (and optionally copy) a stable, no-follow snapshot of a worktree index."""

        try:
            directory_fd = cls._open_git_directory(common, f"worktrees/{attempt_id}")
        except OSError:
            raise SupervisorError(
                "change_preview_incomplete", "attempt Git index directory is unsafe"
            ) from None
        digest = hashlib.sha256()
        total_bytes = 0
        try:
            names = os.listdir(directory_fd)
            shared = sorted(name for name in names if _SHARED_INDEX.fullmatch(name))
            selected = ["index", *shared]
            if len(selected) > _MAX_INDEX_FILES or "index.lock" in names:
                raise SupervisorError(
                    "change_preview_incomplete", "attempt Git index is changing or too large"
                )
            for name in selected:
                try:
                    file_fd = os.open(
                        name,
                        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                        dir_fd=directory_fd,
                    )
                except OSError:
                    raise SupervisorError(
                        "change_preview_incomplete", "attempt Git index is missing or unsafe"
                    ) from None
                try:
                    before = os.fstat(file_fd)
                    if (
                        not stat.S_ISREG(before.st_mode)
                        or before.st_size > _MAX_INDEX_FILE_BYTES
                        or total_bytes + before.st_size > _MAX_INDEX_TOTAL_BYTES
                    ):
                        raise SupervisorError(
                            "change_preview_incomplete", "attempt Git index exceeds safe limits"
                        )
                    chunks: list[bytes] = []
                    remaining = _MAX_INDEX_FILE_BYTES + 1
                    while remaining:
                        chunk = os.read(file_fd, min(1024 * 1024, remaining))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        remaining -= len(chunk)
                    content = b"".join(chunks)
                    after = os.fstat(file_fd)
                    if len(content) > _MAX_INDEX_FILE_BYTES or cls._git_file_signature(
                        before
                    ) != cls._git_file_signature(after):
                        raise SupervisorError(
                            "change_preview_incomplete", "attempt Git index changed during read"
                        )
                finally:
                    os.close(file_fd)
                total_bytes += len(content)
                digest.update(name.encode("ascii") + b"\0")
                digest.update(len(content).to_bytes(8, "big"))
                digest.update(hashlib.sha256(content).digest())
                if destination is not None:
                    target_fd = os.open(
                        destination / name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                        0o600,
                    )
                    try:
                        view = memoryview(content)
                        while view:
                            written = os.write(target_fd, view)
                            view = view[written:]
                    finally:
                        os.close(target_fd)
            return digest.hexdigest()
        finally:
            os.close(directory_fd)

    def _attempt_index_digest(self, attempt_id: str, common: Path) -> str:
        return self._index_snapshot(attempt_id, common)

    @contextmanager
    def _isolated_git_metadata(
        self, attempt_id: str, common: Path, head: str
    ) -> Iterator[tuple[Path, str]]:
        """Create disposable Git metadata with no attempt/repository config or excludes."""

        try:
            objects = common / "objects"
            objects_stat = objects.lstat()
            if not stat.S_ISDIR(objects_stat.st_mode) or stat.S_ISLNK(objects_stat.st_mode):
                raise OSError("repository object store is unsafe")
            object_path = os.fsencode(objects)
            if b"\n" in object_path or b"\r" in object_path:
                raise OSError("repository object path cannot be represented safely")
            with tempfile.TemporaryDirectory(prefix="acp-change-preview-") as scratch:
                git_directory = Path(scratch) / "git"
                (git_directory / "objects" / "info").mkdir(parents=True, mode=0o700)
                (git_directory / "refs" / "heads").mkdir(parents=True, mode=0o700)
                (git_directory / "refs" / "tags").mkdir(parents=True, mode=0o700)
                object_format = "sha256" if len(head) == 64 else "sha1"
                format_version = "1" if object_format == "sha256" else "0"
                config = (
                    "[core]\n"
                    f"\trepositoryformatversion = {format_version}\n"
                    "\tbare = false\n"
                    "\tfilemode = true\n"
                )
                if object_format == "sha256":
                    config += f"[extensions]\n\tobjectformat = {object_format}\n"
                (git_directory / "config").write_text(config, encoding="ascii")
                (git_directory / "HEAD").write_text(f"{head}\n", encoding="ascii")
                (git_directory / "objects" / "info" / "alternates").write_bytes(object_path + b"\n")
                index_digest = self._index_snapshot(attempt_id, common, git_directory)
                yield git_directory, index_digest
        except SupervisorError:
            raise
        except (OSError, ValueError):
            raise SupervisorError(
                "change_preview_incomplete", "isolated Git metadata could not be created safely"
            ) from None

    def _resolve_preview_commit(
        self,
        worktree: Path,
        revision: str | None,
        *,
        expected_identity: tuple[int, int] | None = None,
        git_context: tuple[Path, Path] | None = None,
    ) -> str:
        if revision != "HEAD" and (
            not isinstance(revision, str) or not _OBJECT_ID.fullmatch(revision)
        ):
            raise SupervisorError("change_preview_incomplete", "attempt start revision is invalid")
        raw = self._git_output(
            worktree,
            "rev-parse",
            "--verify",
            "--end-of-options",
            f"{revision}^{{commit}}",
            expected_identity=expected_identity,
            git_context=git_context,
        ).strip()
        try:
            commit = raw.decode("ascii")
        except UnicodeDecodeError:
            commit = ""
        if not _OBJECT_ID.fullmatch(commit):
            raise SupervisorError("change_preview_incomplete", "attempt revision is not a commit")
        return commit

    def _working_tree_status(
        self,
        worktree: Path,
        *,
        expected_identity: tuple[int, int] | None = None,
        git_context: tuple[Path, Path] | None = None,
    ) -> list[dict[str, str]]:
        raw = self._git_output(
            worktree,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=all",
            "--no-renames",
            expected_identity=expected_identity,
            git_context=git_context,
        )
        records: list[dict[str, str]] = []
        fields = raw.split(b"\0")
        if fields and fields[-1] == b"":
            fields.pop()
        for field in fields:
            if len(field) < 4 or field[2:3] != b" ":
                raise SupervisorError(
                    "change_preview_incomplete", "Git returned malformed path metadata"
                )
            try:
                status = field[:2].decode("ascii")
            except UnicodeDecodeError:
                raise SupervisorError(
                    "change_preview_incomplete", "Git returned malformed status metadata"
                ) from None
            path = os.fsdecode(field[3:])
            if not path:
                raise SupervisorError("change_preview_incomplete", "Git returned an empty path")
            records.append({"status": status, "path": path})
        return records

    def _committed_paths(
        self,
        worktree: Path,
        start_sha: str,
        head_sha: str,
        *,
        expected_identity: tuple[int, int] | None = None,
        git_context: tuple[Path, Path] | None = None,
    ) -> list[dict[str, str]]:
        raw = self._git_output(
            worktree,
            "diff",
            "--name-status",
            "-z",
            "--find-renames=50%",
            "-l1000",
            "--no-ext-diff",
            "--no-textconv",
            "--ignore-submodules=all",
            start_sha,
            head_sha,
            "--",
            expected_identity=expected_identity,
            git_context=git_context,
        )
        fields = raw.split(b"\0")
        if fields and fields[-1] == b"":
            fields.pop()
        records: list[dict[str, str]] = []
        index = 0
        while index < len(fields):
            try:
                status = fields[index].decode("ascii")
            except UnicodeDecodeError:
                raise SupervisorError(
                    "change_preview_incomplete", "Git returned malformed status metadata"
                ) from None
            index += 1
            if not status or index >= len(fields):
                raise SupervisorError(
                    "change_preview_incomplete", "Git returned incomplete path metadata"
                )
            if status[0] in {"R", "C"}:
                if index + 1 >= len(fields):
                    raise SupervisorError(
                        "change_preview_incomplete", "Git returned an incomplete rename record"
                    )
                previous = os.fsdecode(fields[index])
                path = os.fsdecode(fields[index + 1])
                index += 2
                records.append({"status": status, "path": path, "previous_path": previous})
            else:
                path = os.fsdecode(fields[index])
                index += 1
                records.append({"status": status, "path": path})
        return records

    @staticmethod
    def _path_summary(records: list[dict[str, str]]) -> dict[str, Any]:
        counts = dict(sorted(Counter(record["status"] for record in records).items()))
        return {
            "path_count": len(records),
            "status_counts": counts,
            "paths": records[:_MAX_RETURNED_PATHS],
            "paths_truncated": len(records) > _MAX_RETURNED_PATHS,
        }
