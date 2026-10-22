from __future__ import annotations

import errno
import hashlib
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

MAX_WORKSPACE_FILE_BYTES = 1_048_576


class WorkspaceFileError(Exception):
    def __init__(self, status_code: int, code: str, message: str):
        self.status_code = status_code
        self.code = code
        self.message = message
        super().__init__(message)


def canonical_relative_path(value: str) -> str:
    if (
        not value
        or len(value) > 2048
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or ":" in value
        or any(ord(character) < 32 for character in value)
    ):
        raise WorkspaceFileError(
            422,
            "invalid_workspace_path",
            "path must be a canonical relative POSIX path",
        )
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise WorkspaceFileError(
            422,
            "invalid_workspace_path",
            "path must not contain empty, dot, or parent components",
        )
    if any(part.casefold() == ".git" for part in parts):
        raise WorkspaceFileError(
            422, "protected_workspace_path", "writes to Git metadata are not supported"
        )
    if any(part.casefold().startswith(".acp-") for part in parts):
        raise WorkspaceFileError(
            422, "protected_workspace_path", "ACP staging paths are reserved"
        )
    normalized = PurePosixPath(value).as_posix()
    if normalized != value:
        raise WorkspaceFileError(
            422, "invalid_workspace_path", "path must use canonical POSIX separators"
        )
    return value


class WorkspaceFileStore:
    """Small, path-safe writer for one configured workspace root.

    All mediated writers are serialized by the control-plane SQLite write
    transaction. Directory file descriptors and O_NOFOLLOW keep path traversal
    anchored to the configured root. External writers that do not use the
    control plane are deliberately outside this service's serialization contract.
    """

    def __init__(self, root: str | Path):
        try:
            resolved = Path(root).expanduser().resolve(strict=True)
        except OSError as error:
            raise ValueError(
                "ACP_WORKSPACE_ROOT must be an existing directory"
            ) from error
        if not resolved.is_dir():
            raise ValueError("ACP_WORKSPACE_ROOT must be an existing directory")
        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            raise ValueError(
                "workspace writes require O_NOFOLLOW and O_DIRECTORY support"
            )
        self.root = resolved

    @contextmanager
    def _open_parent(self, relative_path: str) -> Iterator[tuple[int, str]]:
        path = canonical_relative_path(relative_path)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            directory_fd = os.open(self.root, flags)
        except OSError as error:
            raise WorkspaceFileError(
                503, "workspace_unavailable", "configured workspace cannot be opened"
            ) from error

        try:
            for component in path.split("/")[:-1]:
                try:
                    next_fd = os.open(component, flags, dir_fd=directory_fd)
                except FileNotFoundError as error:
                    raise WorkspaceFileError(
                        404,
                        "workspace_path_not_found",
                        "workspace parent directory not found",
                    ) from error
                except OSError as error:
                    if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                        raise WorkspaceFileError(
                            422,
                            "unsafe_workspace_path",
                            "workspace path contains a symlink or non-directory",
                        ) from error
                    raise WorkspaceFileError(
                        403,
                        "workspace_path_denied",
                        "workspace parent directory cannot be opened",
                    ) from error
                os.close(directory_fd)
                directory_fd = next_fd
            yield directory_fd, path.split("/")[-1]
        finally:
            os.close(directory_fd)

    @staticmethod
    def _hash_fd(file_fd: int) -> tuple[str, int]:
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode):
            raise WorkspaceFileError(
                422,
                "workspace_target_not_regular",
                "workspace target must be a regular file",
            )
        if before.st_size > MAX_WORKSPACE_FILE_BYTES:
            raise WorkspaceFileError(
                413,
                "workspace_file_too_large",
                "workspace files are limited to 1 MiB",
            )
        digest = hashlib.sha256()
        os.lseek(file_fd, 0, os.SEEK_SET)
        total_bytes = 0
        while block := os.read(file_fd, 128 * 1024):
            total_bytes += len(block)
            if total_bytes > MAX_WORKSPACE_FILE_BYTES:
                raise WorkspaceFileError(
                    413,
                    "workspace_file_too_large",
                    "workspace files are limited to 1 MiB",
                )
            digest.update(block)
        after = os.fstat(file_fd)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity:
            raise WorkspaceFileError(
                409,
                "workspace_file_changed_during_read",
                "workspace file changed while being checked",
            )
        return digest.hexdigest(), stat.S_IMODE(after.st_mode) & 0o777

    def current(self, relative_path: str) -> tuple[str | None, int | None]:
        with self._open_parent(relative_path) as (directory_fd, name):
            try:
                file_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=directory_fd,
                )
            except FileNotFoundError:
                return None, None
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise WorkspaceFileError(
                        422,
                        "unsafe_workspace_target",
                        "workspace target cannot be a symlink or directory",
                    ) from error
                raise WorkspaceFileError(
                    403, "workspace_target_denied", "workspace target cannot be opened"
                ) from error
            try:
                return self._hash_fd(file_fd)
            finally:
                os.close(file_fd)

    def atomic_replace(
        self,
        relative_path: str,
        operation_id: str,
        expected_sha256: str | None,
        content: bytes,
        new_sha256: str,
    ) -> None:
        with self._open_parent(relative_path) as (directory_fd, name):
            current_sha256, mode = self._current_at(directory_fd, name)
            if current_sha256 != expected_sha256:
                raise WorkspaceFileError(
                    409,
                    "stale_file_version",
                    f"workspace file version changed; current sha256 is {current_sha256 or 'missing'}",
                )

            # New workspace files are private by default. Existing targets keep
            # their current permission bits, including across crash recovery.
            target_mode = mode if mode is not None else 0o600

            temp_name = f".acp-{operation_id}.tmp"
            temp_fd: int | None = None
            stage_created = False
            stage_identity: tuple[int, int] | None = None
            replaced = False

            def stage_conflict(cause: BaseException | None = None) -> None:
                conflict = WorkspaceFileError(
                    409,
                    "workspace_stage_conflict",
                    "staging path is not a safe, matching retry file",
                )
                if cause is not None:
                    raise conflict from cause
                raise conflict

            try:
                try:
                    temp_fd = os.open(
                        temp_name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        target_mode,
                        dir_fd=directory_fd,
                    )
                    stage_created = True
                    created_stat = os.fstat(temp_fd)
                    stage_identity = (created_stat.st_dev, created_stat.st_ino)
                    view = memoryview(content)
                    while view:
                        written = os.write(temp_fd, view)
                        if written <= 0:
                            raise OSError("short write to workspace staging file")
                        view = view[written:]
                    os.fchmod(temp_fd, target_mode)
                    os.fsync(temp_fd)
                except FileExistsError as error:
                    # A retry may reuse a complete staging file left before a
                    # process crash. Keep it only when it is a single-link
                    # regular file with the exact bytes; never mutate a hardlink.
                    try:
                        temp_fd = os.open(
                            temp_name,
                            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                            dir_fd=directory_fd,
                        )
                    except OSError as stage_error:
                        stage_conflict(stage_error)
                    staged_stat = os.fstat(temp_fd)
                    if (
                        not stat.S_ISREG(staged_stat.st_mode)
                        or staged_stat.st_nlink != 1
                    ):
                        stage_conflict(error)
                    stage_identity = (staged_stat.st_dev, staged_stat.st_ino)
                    try:
                        staged_sha256, staged_mode = self._hash_fd(temp_fd)
                    except WorkspaceFileError as stage_error:
                        stage_conflict(stage_error)
                    if staged_sha256 != new_sha256:
                        stage_conflict(error)
                    if staged_mode != target_mode:
                        os.fchmod(temp_fd, target_mode)
                        os.fsync(temp_fd)

                try:
                    current_stage = os.stat(
                        temp_name, dir_fd=directory_fd, follow_symlinks=False
                    )
                except OSError as error:
                    stage_conflict(error)
                if stage_identity != (current_stage.st_dev, current_stage.st_ino):
                    stage_conflict()

                if temp_fd is not None:
                    staged_fd = temp_fd
                    temp_fd = None
                    os.close(staged_fd)

                os.replace(
                    temp_name,
                    name,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                )
                replaced = True
                os.fsync(directory_fd)
            except WorkspaceFileError:
                raise
            except OSError as error:
                raise WorkspaceFileError(
                    500, "workspace_write_failed", "atomic workspace replacement failed"
                ) from error
            finally:
                if temp_fd is not None:
                    os.close(temp_fd)
                if not replaced and stage_created and stage_identity is not None:
                    try:
                        current_stage = os.stat(
                            temp_name, dir_fd=directory_fd, follow_symlinks=False
                        )
                    except OSError:
                        # On uncertain path state, leave the entry for a safe retry.
                        current_stage = None
                    if current_stage is not None and stage_identity == (
                        current_stage.st_dev,
                        current_stage.st_ino,
                    ):
                        try:
                            os.unlink(temp_name, dir_fd=directory_fd)
                        except OSError:
                            pass

    def sync_directory(self, relative_path: str) -> None:
        with self._open_parent(relative_path) as (directory_fd, _name):
            os.fsync(directory_fd)

    def _current_at(
        self, directory_fd: int, name: str
    ) -> tuple[str | None, int | None]:
        try:
            file_fd = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            return None, None
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise WorkspaceFileError(
                    422,
                    "unsafe_workspace_target",
                    "workspace target cannot be a symlink or directory",
                ) from error
            raise WorkspaceFileError(
                403, "workspace_target_denied", "workspace target cannot be opened"
            ) from error
        try:
            return self._hash_fd(file_fd)
        finally:
            os.close(file_fd)
