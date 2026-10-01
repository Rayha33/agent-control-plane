"""Read-only, metadata-only previews of an ACP attempt's Git changes."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys as _sys
import uuid
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .common import SupervisorError

_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_FILTER_KEY = re.compile(
    r"filter\.([A-Za-z0-9_.-]{1,128})\.(?:clean|process|smudge|required)\Z", re.I
)
_MAX_RETURNED_PATHS = 1000
_MAX_FILTER_DRIVERS = 64
_GIT_TIMEOUT_SECONDS = 30
_EXEC_GIT_FROM_DIR_FD = (
    "import os,sys; fd=int(sys.argv[1]); executable=sys.argv[2]; "
    "os.fchdir(fd); os.execve(executable, [executable, *sys.argv[3:]], os.environ)"
)


class ChangePreviewMixin:
    """Inspect changed path names without exposing contents or changing Git state."""

    def change_preview(self, attempt_id: str) -> dict[str, Any]:
        """Return committed and working-tree path metadata for one attempt.

        A preview is deliberately refused on a read-write supervisor. Git is invoked only
        for fixed path/status commands with external diff, textconv, pager, fsmonitor,
        filters, optional index locking, replacement objects and submodule traversal disabled.
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
        base_common = self._git_common_directory(self.root)
        git_context = self._validate_attempt_git_context(worktree, attempt_id, base_common)
        filter_overrides = self._disabled_filter_overrides(
            worktree, expected_identity=identity, git_context=git_context
        )
        attempt_common = self._git_common_directory(
            worktree, expected_identity=identity, git_context=git_context
        )
        if base_common != attempt_common:
            raise SupervisorError(
                "change_preview_incomplete",
                "attempt worktree is not attached to this ACP repository",
            )
        top_level = (
            self._git_output(
                worktree,
                "rev-parse",
                "--show-toplevel",
                expected_identity=identity,
                git_context=git_context,
            )
            .decode("utf-8", errors="surrogateescape")
            .strip()
        )
        if Path(os.path.normpath(top_level)) != worktree:
            raise SupervisorError(
                "change_preview_incomplete",
                "Git resolved the attempt outside its allocated worktree",
            )

        start_sha = self._resolve_preview_commit(
            worktree,
            attempt["start_sha"],
            expected_identity=identity,
            git_context=git_context,
        )
        head_before = self._resolve_preview_commit(
            worktree, "HEAD", expected_identity=identity, git_context=git_context
        )
        status_before = self._working_tree_status(
            worktree,
            expected_identity=identity,
            config_overrides=filter_overrides,
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
            config_overrides=filter_overrides,
            git_context=git_context,
        )
        head_after = self._resolve_preview_commit(
            worktree, "HEAD", expected_identity=identity, git_context=git_context
        )

        stable = (
            head_before == head_after
            and status_before == status_after
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
            "filter_drivers_disabled": len(filter_overrides) // 4,
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

    @staticmethod
    def _read_git_metadata(path: Path) -> bytes:
        if not hasattr(os, "O_NOFOLLOW"):
            raise OSError("no-follow file opens are unavailable")
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 4096:
                raise OSError("Git metadata file is not a small regular file")
            content = os.read(descriptor, 4097)
            if len(content) > 4096:
                raise OSError("Git metadata file exceeds the size limit")
            return content
        finally:
            os.close(descriptor)

    @classmethod
    def _validate_attempt_git_context(
        cls, worktree: Path, attempt_id: str, common: Path
    ) -> tuple[Path, Path]:
        """Pin a worktree's Git admin directory before asking Git to read it."""

        try:
            admin_root = common / "worktrees"
            admin_root_stat = admin_root.lstat()
            if not stat.S_ISDIR(admin_root_stat.st_mode) or stat.S_ISLNK(admin_root_stat.st_mode):
                raise OSError("Git worktree admin root is unsafe")
            admin = admin_root / attempt_id
            admin_stat = admin.lstat()
            if not stat.S_ISDIR(admin_stat.st_mode) or stat.S_ISLNK(admin_stat.st_mode):
                raise OSError("attempt Git admin directory is unsafe")

            marker = cls._read_git_metadata(worktree / ".git")
            if not marker.startswith(b"gitdir: "):
                raise OSError("attempt Git marker is malformed")
            marker_path = Path(os.fsdecode(marker[8:].rstrip(b"\r\n")))
            if not marker_path.is_absolute():
                marker_path = worktree / marker_path
            if Path(os.path.normpath(marker_path)) != admin:
                raise OSError("attempt Git marker points outside its allocated admin directory")

            back_pointer = cls._read_git_metadata(admin / "gitdir")
            back_path = Path(os.fsdecode(back_pointer.rstrip(b"\r\n")))
            if not back_path.is_absolute():
                back_path = admin / back_path
            if Path(os.path.normpath(back_path)) != worktree / ".git":
                raise OSError("Git admin directory points at a different worktree")

            common_pointer = cls._read_git_metadata(admin / "commondir")
            common_path = Path(os.fsdecode(common_pointer.rstrip(b"\r\n")))
            if not common_path.is_absolute():
                common_path = admin / common_path
            if Path(os.path.normpath(common_path)) != common:
                raise OSError("Git admin directory points at a different common directory")
        except (OSError, ValueError, RuntimeError):
            raise SupervisorError(
                "change_preview_incomplete", "attempt Git metadata is missing or unsafe"
            ) from None
        return admin, common

    def _git_environment(self) -> dict[str, str]:
        environment = self._supervisor_git_env()
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
        config_overrides: Sequence[str] = (),
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
            "maintenance.auto=false",
            "-c",
            "gc.auto=0",
        ]
        for setting in config_overrides:
            command.extend(["-c", setting])
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

    def _disabled_filter_overrides(
        self,
        worktree: Path,
        *,
        expected_identity: tuple[int, int],
        git_context: tuple[Path, Path],
    ) -> list[str]:
        """Disable repository/worktree external clean/process/smudge filter commands.

        `git status` can invoke a clean filter when comparing a modified path to the
        index. Reading config names is inert; `--no-includes` prevents this inventory
        from following arbitrary include paths outside the repository.
        """

        raw = self._git_output(
            worktree,
            "config",
            "--no-includes",
            "--name-only",
            "--list",
            "--null",
            expected_identity=expected_identity,
            git_context=git_context,
        )
        fields = raw.split(b"\0")
        if fields and fields[-1] == b"":
            fields.pop()
        drivers: set[str] = set()
        for field in fields:
            try:
                key = field.decode("ascii")
            except UnicodeDecodeError:
                if field.lower().startswith(b"filter."):
                    raise SupervisorError(
                        "change_preview_incomplete", "Git filter configuration is unsafe"
                    ) from None
                continue
            if key.lower().startswith(("include.", "includeif.")):
                raise SupervisorError(
                    "change_preview_incomplete",
                    "Git config includes are not supported for a safe preview",
                )
            if not key.lower().startswith("filter."):
                continue
            match = _FILTER_KEY.fullmatch(key)
            if not match:
                raise SupervisorError(
                    "change_preview_incomplete", "Git filter configuration is unsafe"
                )
            drivers.add(match.group(1))
        if len(drivers) > _MAX_FILTER_DRIVERS:
            raise SupervisorError(
                "change_preview_incomplete", "too many Git filter drivers to inspect safely"
            )
        overrides = []
        for driver in sorted(drivers, key=str.casefold):
            overrides.extend(
                [
                    f"filter.{driver}.clean=",
                    f"filter.{driver}.process=",
                    f"filter.{driver}.smudge=",
                    f"filter.{driver}.required=false",
                ]
            )
        return overrides

    def _git_common_directory(
        self,
        worktree: Path,
        *,
        expected_identity: tuple[int, int] | None = None,
        git_context: tuple[Path, Path] | None = None,
    ) -> Path:
        raw = (
            self._git_output(
                worktree,
                "rev-parse",
                "--git-common-dir",
                expected_identity=expected_identity,
                git_context=git_context,
            )
            .decode("utf-8", errors="surrogateescape")
            .strip()
        )
        directory = Path(raw)
        if not directory.is_absolute():
            directory = worktree / directory
        try:
            return directory.resolve(strict=True)
        except OSError:
            raise SupervisorError(
                "change_preview_incomplete", "Git common directory is missing or unsafe"
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
        config_overrides: Sequence[str] = (),
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
            config_overrides=config_overrides,
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
