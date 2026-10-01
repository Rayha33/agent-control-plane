"""Read-only, metadata-only previews of an ACP attempt's Git changes."""

from __future__ import annotations

import hashlib
import os
import re
import selectors
import stat
import subprocess
import sys as _sys
import tempfile
import time
import uuid
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
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
_MAX_INDEX_DIRECTORY_ENTRIES = 1024
_MAX_PACKED_REFS_BYTES = 16 * 1024 * 1024
_MAX_GIT_OUTPUT_BYTES = 16 * 1024 * 1024
_MAX_INVENTORY_RECORDS = 10_000
_MAX_OBJECT_FILES = 250_000
_MAX_OBJECT_SNAPSHOT_BYTES = 1024 * 1024 * 1024
_GIT_TIMEOUT_SECONDS = 30
_LOOSE_OBJECT_NAME = re.compile(r"(?:[0-9a-f]{38}|[0-9a-f]{62})\Z")
_PACK_INDEX_NAME = re.compile(r"pack-([0-9a-f]{40}|[0-9a-f]{64})\.(?:pack|idx)\Z")
_EXEC_GIT_FROM_DIR_FD = (
    "import os,sys; fd=int(sys.argv[1]); executable=sys.argv[2]; "
    "os.fchdir(fd); os.execve(executable, [executable, *sys.argv[3:]], os.environ)"
)


@dataclass(frozen=True)
class _IsolatedGitContext:
    git_directory: Path
    common_directory: Path
    directory_identity: tuple[int, int]
    metadata_fingerprint: str
    config_content: bytes
    head_content: bytes
    index_digest: str


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
            git_context,
            initial_index_digest,
        ):
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
            if key.startswith("GIT_"):
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
        git_context: _IsolatedGitContext | None = None,
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
            environment.update(
                {
                    "GIT_DIR": str(git_context.git_directory),
                    "GIT_COMMON_DIR": str(git_context.common_directory),
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
        if git_context is not None:
            self._assert_isolated_git_metadata(git_context)
        process: subprocess.Popen[bytes] | None = None
        selector: selectors.BaseSelector | None = None
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
            process = subprocess.Popen(
                command,
                cwd=self.root,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                pass_fds=(worktree_fd,) if worktree_fd is not None else (),
            )
            if process.stdout is None:
                raise OSError("Git stdout pipe was not created")
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + _GIT_TIMEOUT_SECONDS
            output = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise subprocess.TimeoutExpired(command, _GIT_TIMEOUT_SECONDS)
                chunk = os.read(
                    process.stdout.fileno(),
                    min(1024 * 1024, _MAX_GIT_OUTPUT_BYTES + 1 - len(output)),
                )
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > _MAX_GIT_OUTPUT_BYTES:
                    raise SupervisorError(
                        "change_preview_incomplete", "Git output exceeds the safe byte limit"
                    )
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
            return_code = process.returncode
        except SupervisorError:
            raise
        except (OSError, subprocess.TimeoutExpired):
            raise SupervisorError(
                "change_preview_incomplete", "Git could not read attempt metadata safely"
            ) from None
        finally:
            if selector is not None:
                selector.close()
            if process is not None:
                if process.poll() is None:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                    process.wait()
                if process.stdout is not None:
                    process.stdout.close()
            if worktree_fd is not None:
                os.close(worktree_fd)
        if expected_identity is not None and not self._preview_path_still_matches(
            worktree, expected_identity
        ):
            raise SupervisorError(
                "change_preview_incomplete", "attempt worktree changed during inspection"
            )
        if return_code:
            raise SupervisorError(
                "change_preview_incomplete",
                f"Git could not read attempt metadata (command {arguments[0]} failed)",
            )
        if git_context is not None:
            self._assert_isolated_git_metadata(git_context)
        return bytes(output)

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
            names = cls._list_git_directory(directory_fd, _MAX_INDEX_DIRECTORY_ENTRIES)
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

    @classmethod
    def _isolated_git_fingerprint(
        cls,
        git_directory: Path,
        config_content: bytes,
        head_content: bytes,
        index_digest: str,
        expected_directory_identity: tuple[int, int] | None = None,
    ) -> tuple[str, tuple[int, int]]:
        """Fingerprint and validate mutable scratch metadata used by Git commands."""

        directory_fd = cls._open_git_directory(git_directory)
        try:
            directory_stat = os.fstat(directory_fd)
            directory_identity = (directory_stat.st_dev, directory_stat.st_ino)
            if (
                expected_directory_identity is not None
                and directory_identity != expected_directory_identity
            ):
                raise OSError("isolated Git directory changed")
            names = cls._list_git_directory(directory_fd, _MAX_INDEX_DIRECTORY_ENTRIES)
            shared = sorted(name for name in names if _SHARED_INDEX.fullmatch(name))
            selected = ["config", "HEAD", "index", *shared]
            if any(name not in names for name in selected[:3]):
                raise OSError("isolated Git metadata is incomplete")

            digest = hashlib.sha256()
            digest.update(repr(cls._git_file_signature(directory_stat)).encode("ascii"))
            total_bytes = 0
            actual_index_digest = hashlib.sha256()
            for name in selected:
                try:
                    file_fd = os.open(
                        name,
                        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                        dir_fd=directory_fd,
                    )
                except OSError:
                    raise OSError("isolated Git metadata is unsafe") from None
                try:
                    before = os.fstat(file_fd)
                    max_bytes = 4096 if name in {"config", "HEAD"} else _MAX_INDEX_FILE_BYTES
                    if (
                        not stat.S_ISREG(before.st_mode)
                        or before.st_size > max_bytes
                        or total_bytes + before.st_size > _MAX_INDEX_TOTAL_BYTES + 8192
                    ):
                        raise OSError("isolated Git metadata exceeds safe limits")
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
                    signature = cls._git_file_signature(before)
                    if len(content) > max_bytes or signature != cls._git_file_signature(after):
                        raise OSError("isolated Git metadata changed during inspection")
                finally:
                    os.close(file_fd)
                total_bytes += len(content)
                if name == "config" and content != config_content:
                    raise OSError("isolated Git config changed")
                if name == "HEAD" and content != head_content:
                    raise OSError("isolated Git HEAD changed")
                if name == "index" or _SHARED_INDEX.fullmatch(name):
                    actual_index_digest.update(name.encode("ascii") + b"\0")
                    actual_index_digest.update(len(content).to_bytes(8, "big"))
                    actual_index_digest.update(hashlib.sha256(content).digest())
                digest.update(name.encode("ascii") + b"\0")
                digest.update(repr(signature).encode("ascii"))
                digest.update(hashlib.sha256(content).digest())
            if actual_index_digest.hexdigest() != index_digest:
                raise OSError("isolated Git index changed")

            for relative in ("objects/info", "refs/heads", "refs/tags"):
                child_fd = cls._open_git_directory(git_directory, relative)
                try:
                    child_stat = os.fstat(child_fd)
                    cls._list_git_directory(child_fd, 0)
                    digest.update(relative.encode("ascii") + b"\0")
                    digest.update(repr(cls._git_file_signature(child_stat)).encode("ascii"))
                finally:
                    os.close(child_fd)
            return digest.hexdigest(), directory_identity
        finally:
            os.close(directory_fd)

    @classmethod
    def _assert_isolated_git_metadata(cls, context: _IsolatedGitContext) -> None:
        try:
            fingerprint, _identity = cls._isolated_git_fingerprint(
                context.git_directory,
                context.config_content,
                context.head_content,
                context.index_digest,
                context.directory_identity,
            )
        except OSError:
            raise SupervisorError(
                "change_preview_incomplete", "isolated Git metadata changed or became unsafe"
            ) from None
        if fingerprint != context.metadata_fingerprint:
            raise SupervisorError(
                "change_preview_incomplete", "isolated Git metadata changed during inspection"
            )

    def _attempt_index_digest(self, attempt_id: str, common: Path) -> str:
        return self._index_snapshot(attempt_id, common)

    @staticmethod
    def _list_git_directory(directory_fd: int, max_entries: int) -> list[str]:
        """Enumerate a Git directory incrementally and stop at its safe bound."""

        names: list[str] = []
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > max_entries:
                    raise OSError("Git metadata directory exceeds the safe entry limit")
        return names

    @classmethod
    def _copy_object_file(
        cls,
        source_fd: int,
        destination_fd: int,
        name: str,
        copied_bytes: list[int],
    ) -> bool:
        """Copy one bounded object file without following a replaced path."""

        try:
            source_file_fd = os.open(
                name,
                os.O_RDONLY
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=source_fd,
            )
        except FileNotFoundError:
            return False
        except OSError:
            # An unreadable or unsafe object is omitted. Git will fail closed if it
            # is needed to resolve the selected commits.
            return False
        try:
            before = os.fstat(source_file_fd)
            if not stat.S_ISREG(before.st_mode):
                return False
            if before.st_size > _MAX_OBJECT_SNAPSHOT_BYTES - copied_bytes[0]:
                raise OSError("Git object snapshot exceeds the safe byte limit")
            destination_file_fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=destination_fd,
            )
            try:
                copied = 0
                while True:
                    chunk = os.read(source_file_fd, 1024 * 1024)
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied_bytes[0] + copied > _MAX_OBJECT_SNAPSHOT_BYTES:
                        raise OSError("Git object snapshot exceeds the safe byte limit")
                    view = memoryview(chunk)
                    while view:
                        written = os.write(destination_file_fd, view)
                        view = view[written:]
                copied_metadata = os.fstat(destination_file_fd)
                after = os.fstat(source_file_fd)
                if (
                    copied != before.st_size
                    or not stat.S_ISREG(copied_metadata.st_mode)
                    or copied_metadata.st_size != copied
                    or cls._git_file_signature(before) != cls._git_file_signature(after)
                ):
                    raise OSError("Git object changed while taking a safe snapshot")
                copied_bytes[0] += copied
                return True
            except Exception:
                try:
                    os.unlink(name, dir_fd=destination_fd)
                except FileNotFoundError:
                    pass
                raise
            finally:
                os.close(destination_file_fd)
        finally:
            os.close(source_file_fd)

    @classmethod
    def _snapshot_object_database(
        cls, common: Path, destination: Path, object_id_length: int
    ) -> None:
        """Copy the local loose/packed object namespace without Git alternates.

        The temporary object database contains bounded copies of regular files
        found directly under the repository's pack directory and loose-object
        fanout directories. In particular, it does not copy or read objects/info,
        where Git can configure recursive external alternates.
        """

        if object_id_length not in {40, 64}:
            raise OSError("unsupported Git object format")
        objects_fd = cls._open_git_directory(common, "objects")
        pack_fd: int | None = None
        destination_pack_fd: int | None = None
        file_count = 0
        scanned_entries = 0
        copied_bytes = [0]
        try:
            destination_pack_fd = os.open(
                destination / "pack", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            )
            try:
                pack_fd = os.open(
                    "pack",
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=objects_fd,
                )
            except FileNotFoundError:
                pack_fd = None
            if pack_fd is not None:
                pack_names = cls._list_git_directory(pack_fd, _MAX_OBJECT_FILES)
                scanned_entries += len(pack_names)
                paired: set[str] = set()
                for name in pack_names:
                    match = _PACK_INDEX_NAME.fullmatch(name)
                    if match is not None:
                        paired.add(match.group(1))
                for pack_hash in sorted(paired):
                    if len(pack_hash) != object_id_length:
                        continue
                    pack_name = f"pack-{pack_hash}.pack"
                    index_name = f"pack-{pack_hash}.idx"
                    if pack_name not in pack_names or index_name not in pack_names:
                        continue
                    if not cls._copy_object_file(
                        pack_fd, destination_pack_fd, pack_name, copied_bytes
                    ):
                        continue
                    if not cls._copy_object_file(
                        pack_fd, destination_pack_fd, index_name, copied_bytes
                    ):
                        os.unlink(pack_name, dir_fd=destination_pack_fd)
                        continue
                    file_count += 2
                    if file_count > _MAX_OBJECT_FILES:
                        raise OSError("Git object database exceeds the safe snapshot limit")

            for prefix_value in range(256):
                prefix = f"{prefix_value:02x}"
                try:
                    shard_fd = os.open(
                        prefix,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=objects_fd,
                    )
                except (FileNotFoundError, NotADirectoryError):
                    continue
                try:
                    shard_names = cls._list_git_directory(
                        shard_fd, _MAX_OBJECT_FILES - scanned_entries
                    )
                    scanned_entries += len(shard_names)
                    candidates = [
                        name
                        for name in shard_names
                        if len(name) == object_id_length - 2 and _LOOSE_OBJECT_NAME.fullmatch(name)
                    ]
                    if not candidates:
                        continue
                    destination_shard = destination / prefix
                    destination_shard.mkdir(mode=0o700)
                    shard_destination_fd = os.open(
                        destination_shard,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    )
                    try:
                        for name in candidates:
                            if not cls._copy_object_file(
                                shard_fd, shard_destination_fd, name, copied_bytes
                            ):
                                continue
                            file_count += 1
                            if file_count > _MAX_OBJECT_FILES:
                                raise OSError("Git object database exceeds the safe snapshot limit")
                    finally:
                        os.close(shard_destination_fd)
                finally:
                    os.close(shard_fd)
        finally:
            if destination_pack_fd is not None:
                os.close(destination_pack_fd)
            if pack_fd is not None:
                os.close(pack_fd)
            os.close(objects_fd)

    @contextmanager
    def _isolated_git_metadata(
        self, attempt_id: str, common: Path, head: str
    ) -> Iterator[tuple[_IsolatedGitContext, str]]:
        """Create disposable Git metadata with no inherited paths or config."""

        try:
            objects = common / "objects"
            objects_stat = objects.lstat()
            if not stat.S_ISDIR(objects_stat.st_mode) or stat.S_ISLNK(objects_stat.st_mode):
                raise OSError("repository object store is unsafe")
            # Do not honor TMPDIR/TMP/TEMP: a caller could otherwise place the
            # temporary repository inside the live attempt worktree being scanned.
            with tempfile.TemporaryDirectory(prefix="acp-change-preview-", dir="/tmp") as scratch:
                git_directory = Path(scratch) / "git"
                object_directory = git_directory / "objects"
                (object_directory / "info").mkdir(parents=True, mode=0o700)
                (object_directory / "pack").mkdir(mode=0o700)
                (git_directory / "refs" / "heads").mkdir(parents=True, mode=0o700)
                (git_directory / "refs" / "tags").mkdir(parents=True, mode=0o700)
                object_format = "sha256" if len(head) == 64 else "sha1"
                format_version = "1" if object_format == "sha256" else "0"
                config_content = (
                    "[core]\n"
                    f"\trepositoryformatversion = {format_version}\n"
                    "\tbare = false\n"
                    "\tfilemode = true\n"
                ).encode("ascii")
                if object_format == "sha256":
                    config_content += f"[extensions]\n\tobjectformat = {object_format}\n".encode(
                        "ascii"
                    )
                head_content = f"{head}\n".encode("ascii")
                (git_directory / "config").write_bytes(config_content)
                (git_directory / "HEAD").write_bytes(head_content)
                self._snapshot_object_database(common, object_directory, len(head))
                index_digest = self._index_snapshot(attempt_id, common, git_directory)
                fingerprint, directory_identity = self._isolated_git_fingerprint(
                    git_directory, config_content, head_content, index_digest
                )
                yield (
                    _IsolatedGitContext(
                        git_directory=git_directory,
                        common_directory=git_directory,
                        directory_identity=directory_identity,
                        metadata_fingerprint=fingerprint,
                        config_content=config_content,
                        head_content=head_content,
                        index_digest=index_digest,
                    ),
                    index_digest,
                )
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
        git_context: _IsolatedGitContext | None = None,
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
        git_context: _IsolatedGitContext | None = None,
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
        fields = raw.split(b"\0", _MAX_INVENTORY_RECORDS + 1)
        if len(fields) > _MAX_INVENTORY_RECORDS + 1:
            raise SupervisorError(
                "change_preview_incomplete", "working-tree path inventory exceeds safe limits"
            )
        if fields and fields[-1] == b"":
            fields.pop()
        for field in fields:
            if len(records) >= _MAX_INVENTORY_RECORDS:
                raise SupervisorError(
                    "change_preview_incomplete", "working-tree path inventory exceeds safe limits"
                )
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
        git_context: _IsolatedGitContext | None = None,
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
        fields = raw.split(b"\0", 3 * _MAX_INVENTORY_RECORDS + 1)
        if len(fields) > 3 * _MAX_INVENTORY_RECORDS + 1:
            raise SupervisorError(
                "change_preview_incomplete", "committed path inventory exceeds safe limits"
            )
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
                if len(records) >= _MAX_INVENTORY_RECORDS:
                    raise SupervisorError(
                        "change_preview_incomplete", "committed path inventory exceeds safe limits"
                    )
                records.append({"status": status, "path": path, "previous_path": previous})
            else:
                path = os.fsdecode(fields[index])
                index += 1
                if len(records) >= _MAX_INVENTORY_RECORDS:
                    raise SupervisorError(
                        "change_preview_incomplete", "committed path inventory exceeds safe limits"
                    )
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
