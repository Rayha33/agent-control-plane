"""Opt-in checkout identity and fenced write adapter primitives.

These primitives are cooperative: only operations invoked through
``CheckoutWriteLease.run`` are mediated. They do not sandbox a process or stop a
different tool from writing to the same checkout directly.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised by unsupported-platform tests
    fcntl = None  # type: ignore[assignment]


CheckoutOperation = Literal["write", "attach", "switch", "sync", "cleanup"]
_DESTRUCTIVE_OPERATIONS = frozenset({"attach", "switch", "sync", "cleanup"})
_GIT_ENV_ALLOWLIST = frozenset({"PATH", "HOME", "TMPDIR", "SYSTEMROOT", "WINDIR"})


class CheckoutAdapterError(RuntimeError):
    """A fail-closed checkout identity, lock, or write-gate refusal."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CheckoutIdentity:
    """Local filesystem identity for one Git worktree, excluding its path string."""

    root: Path
    common_dir: Path
    git_dir: Path
    repository_id: str
    checkout_id: str
    resource: str

    def public_view(self) -> dict[str, str]:
        """Return opaque IDs only; do not disclose local checkout paths."""

        return {
            "identity_version": "1",
            "repository_id": self.repository_id,
            "checkout_id": self.checkout_id,
            "resource": self.resource,
            "identity_scope": "local_filesystem_device_inode",
        }


def identify_checkout(path: str | os.PathLike[str]) -> CheckoutIdentity:
    """Identify a real Git worktree by its common-dir and worktree git-dir inodes.

    Resolving Git's own directories makes symlink aliases equivalent. Device/inode
    pairs remain stable across ordinary renames on one filesystem and distinguish
    linked worktrees by their per-worktree Git directory. Filesystems without stable
    nonzero inode evidence are refused rather than falling back to a path-only key.
    """

    try:
        requested_path = Path(path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        raise CheckoutAdapterError(
            "checkout_unavailable", "checkout path is unavailable"
        ) from error
    if not requested_path.is_dir():
        raise CheckoutAdapterError("not_a_git_checkout", "checkout path is not a directory")

    git = shutil.which("git")
    if not git:
        raise CheckoutAdapterError("git_unavailable", "Git executable is unavailable")
    environment = {key: value for key, value in os.environ.items() if key in _GIT_ENV_ALLOWLIST}
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    resolved: dict[str, Path] = {}
    for field, argument in (
        ("root", "--show-toplevel"),
        ("common_dir", "--git-common-dir"),
        ("git_dir", "--git-dir"),
    ):
        result = subprocess.run(
            [git, "-C", str(requested_path), "rev-parse", "--path-format=absolute", argument],
            env=environment,
            capture_output=True,
            check=False,
        )
        if result.returncode:
            raise CheckoutAdapterError(
                "not_a_git_checkout", "Git could not resolve checkout identity"
            )
        try:
            value = result.stdout.decode("utf-8", errors="strict").strip()
            resolved[field] = Path(value).resolve(strict=True)
        except (UnicodeError, OSError, RuntimeError, ValueError) as error:
            raise CheckoutAdapterError(
                "checkout_identity_unavailable", "Git checkout identity is unreadable"
            ) from error

    canonical_root = resolved["root"]
    common_dir = resolved["common_dir"]
    git_dir = resolved["git_dir"]
    if (
        (requested_path != canonical_root and canonical_root not in requested_path.parents)
        or not common_dir.is_dir()
        or not git_dir.is_dir()
    ):
        raise CheckoutAdapterError(
            "checkout_identity_unavailable", "Git checkout directories are inconsistent"
        )
    try:
        common_stat = common_dir.stat()
        git_stat = git_dir.stat()
    except OSError as error:
        raise CheckoutAdapterError(
            "checkout_identity_unavailable", "Git checkout filesystem identity is unreadable"
        ) from error
    for value in (common_stat, git_stat):
        if not stat.S_ISDIR(value.st_mode) or value.st_dev <= 0 or value.st_ino <= 0:
            raise CheckoutAdapterError(
                "checkout_identity_unavailable",
                "filesystem does not provide stable checkout identity evidence",
            )

    repository_id = _digest(("acp-checkout-repository-v1", common_stat.st_dev, common_stat.st_ino))
    checkout_id = _digest(
        (
            "acp-checkout-worktree-v1",
            common_stat.st_dev,
            common_stat.st_ino,
            git_stat.st_dev,
            git_stat.st_ino,
        )
    )
    return CheckoutIdentity(
        root=canonical_root,
        common_dir=common_dir,
        git_dir=git_dir,
        repository_id=repository_id,
        checkout_id=checkout_id,
        resource=f"checkout:v1:{repository_id}:{checkout_id}",
    )


def _digest(parts: tuple[str | int, ...]) -> str:
    canonical = json.dumps(parts, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()[:32]


class CheckoutWriteLease:
    """Hold a local OS lock and a durable ACP resource fence around mediated writes.

    ``acquire_fence`` must obtain the durable checkout resource lease after the local
    lock is held and return its positive fencing token. ``validate_fence`` must check
    that exact resource/token against the authoritative coordination store before each
    operation. The OS lock is held for this context, so another adapter cannot take
    over locally until it is released. This ordering is important: callers must not
    obtain a durable checkout lease outside this adapter and then treat it as write
    authority.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        acquire_fence: Callable[[str], int],
        validate_fence: Callable[[str, int], bool],
        release_fence: Callable[[str, int], None],
    ) -> None:
        self.path = path
        self.acquire_fence = acquire_fence
        self.validate_fence = validate_fence
        self.release_fence = release_fence
        self.identity: CheckoutIdentity | None = None
        self.fencing_token: int | None = None
        self._lock_fd: int | None = None
        self._run_lock = threading.RLock()
        self._active_thread: int | None = None
        self._operation_failed = False
        self._closed = False

    def __enter__(self) -> CheckoutWriteLease:
        with self._run_lock:
            return self._enter_locked()

    def _enter_locked(self) -> CheckoutWriteLease:
        if fcntl is None:
            raise CheckoutAdapterError(
                "checkout_lock_unsupported", "this platform cannot enforce checkout write locks"
            )
        if self._lock_fd is not None or self._closed:
            raise CheckoutAdapterError("checkout_lock_state", "checkout lease cannot be reused")
        identity = identify_checkout(self.path)
        self._lock_fd = _open_checkout_lock(identity.git_dir)
        try:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise CheckoutAdapterError(
                    "checkout_busy", "another mediated writer holds this checkout"
                ) from error
            if identify_checkout(self.path).resource != identity.resource:
                raise CheckoutAdapterError(
                    "checkout_identity_changed", "checkout identity changed while locking"
                )
            try:
                token = self.acquire_fence(identity.resource)
            except BaseException as error:
                error.add_note(
                    "ACP checkout fence acquisition outcome may be unknown; wait for "
                    "authoritative lease expiry before retrying"
                )
                raise
            if type(token) is not int or token < 1:
                raise CheckoutAdapterError(
                    "checkout_fence_invalid",
                    "coordination returned an invalid checkout fence; any remote lease may "
                    "remain held until its authoritative expiry",
                )
            self.identity = identity
            self.fencing_token = token
            if not self.validate_fence(identity.resource, token):
                raise CheckoutAdapterError(
                    "checkout_fence_stale", "checkout resource fence is no longer current"
                )
            return self
        except BaseException as original_error:
            release_error: BaseException | None = None
            if self.identity is not None and self.fencing_token is not None:
                try:
                    self.release_fence(self.identity.resource, self.fencing_token)
                except BaseException as error:
                    release_error = error
            self._unlock()
            if release_error is not None:
                original_error.add_note(
                    "ACP checkout fence release failed during acquisition rollback; "
                    "wait for authoritative lease expiry before retrying"
                )
            raise

    def run(self, operation: CheckoutOperation, action: Callable[[], object]) -> object:
        """Run one mediated action, refusing stale fences and dirty replacement work."""

        with self._run_lock:
            thread_id = threading.get_ident()
            if self._active_thread == thread_id:
                raise CheckoutAdapterError(
                    "checkout_operation_reentrant",
                    "a checkout action cannot recursively use the same lease",
                )
            self._active_thread = thread_id
            try:
                return self._run_locked(operation, action)
            finally:
                self._active_thread = None

    def _run_locked(self, operation: CheckoutOperation, action: Callable[[], object]) -> object:

        identity = self.identity
        token = self.fencing_token
        if self._lock_fd is None or identity is None or token is None or self._closed:
            raise CheckoutAdapterError("checkout_lock_missing", "checkout lease is not active")
        if operation not in {"write", "attach", "switch", "sync", "cleanup"}:
            raise CheckoutAdapterError(
                "checkout_operation_invalid", "unsupported checkout operation"
            )
        if not callable(action):
            raise CheckoutAdapterError(
                "checkout_action_invalid", "checkout action must be callable"
            )
        if self._operation_failed:
            raise CheckoutAdapterError(
                "checkout_operation_blocked",
                "a prior mediated operation failed; inspect before further writes",
            )
        try:
            if identify_checkout(self.path).resource != identity.resource:
                raise CheckoutAdapterError(
                    "checkout_identity_changed", "checkout identity changed before mutation"
                )
            if not self.validate_fence(identity.resource, token):
                raise CheckoutAdapterError(
                    "checkout_fence_stale", "stale checkout owner cannot mutate this checkout"
                )
            if operation in _DESTRUCTIVE_OPERATIONS:
                _require_clean_checkout(identity)
            result = action()
            if (
                operation != "cleanup"
                and identify_checkout(self.path).resource != identity.resource
            ):
                raise CheckoutAdapterError(
                    "checkout_identity_changed", "checkout identity changed during mutation"
                )
            return result
        except BaseException:
            # An interrupted write may have left partial state. Do not retry or continue
            # mutating under the same lease; a new owner must inspect it first.
            self._operation_failed = True
            raise

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        with self._run_lock:
            token = self.fencing_token
            identity = self.identity
            release_error: BaseException | None = None
            if token is not None and identity is not None:
                try:
                    self.release_fence(identity.resource, token)
                except BaseException as error:  # fail closed; the durable lease may expire later
                    release_error = error
            self._unlock()
            if release_error is not None and exc is None:
                raise CheckoutAdapterError(
                    "checkout_fence_release_unknown",
                    "checkout fence release failed; wait for authoritative lease expiry",
                ) from release_error
            if release_error is not None and isinstance(exc, BaseException):
                exc.add_note(
                    "ACP checkout fence release failed; wait for authoritative lease expiry"
                )
        return False

    def _unlock(self) -> None:
        self._closed = True
        descriptor = self._lock_fd
        self._lock_fd = None
        if descriptor is None:
            return
        try:
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _open_checkout_lock(git_dir: Path) -> int:
    try:
        parent = git_dir.stat()
    except OSError as error:
        raise CheckoutAdapterError(
            "checkout_lock_unavailable", "Git directory cannot be validated for locking"
        ) from error
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.geteuid()
        or parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise CheckoutAdapterError(
            "checkout_lock_unavailable",
            "Git directory is not privately owned by this user; refusing checkout lock",
        )
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(git_dir, flags)
        metadata = os.fstat(descriptor)
        path_metadata = git_dir.stat()
    except OSError as error:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise CheckoutAdapterError(
            "checkout_lock_unavailable", "Git directory cannot be opened safely for locking"
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or (metadata.st_dev, metadata.st_ino) != (path_metadata.st_dev, path_metadata.st_ino)
    ):
        os.close(descriptor)
        raise CheckoutAdapterError(
            "checkout_lock_unavailable", "Git directory changed or has unsafe ownership"
        )
    return descriptor


def _require_clean_checkout(identity: CheckoutIdentity) -> None:
    git = shutil.which("git")
    if not git:
        raise CheckoutAdapterError("git_unavailable", "Git executable is unavailable")
    environment = {key: value for key, value in os.environ.items() if key in _GIT_ENV_ALLOWLIST}
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    index_result = subprocess.run(
        [git, "-C", str(identity.root), "ls-files", "--stage", "-z"],
        env=environment,
        capture_output=True,
        check=False,
    )
    if index_result.returncode:
        raise CheckoutAdapterError(
            "checkout_state_unknown", "Git could not establish whether submodules are present"
        )
    for entry in index_result.stdout.split(b"\0"):
        if not entry:
            continue
        metadata, separator, _path = entry.partition(b"\t")
        fields = metadata.split()
        if not separator or len(fields) != 3:
            raise CheckoutAdapterError(
                "checkout_state_unknown", "Git returned an unreadable tracked-file index entry"
            )
        if fields[0] == b"160000":
            raise CheckoutAdapterError(
                "checkout_submodules_unsupported",
                "destructive checkout operation refused because recursive submodule state "
                "is not yet verified",
            )
    result = subprocess.run(
        [
            git,
            "-c",
            "core.filemode=true",
            "-c",
            "core.ignoreCase=false",
            "-c",
            "core.symlinks=true",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-C",
            str(identity.root),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
            "--ignore-submodules=none",
        ],
        env=environment,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise CheckoutAdapterError(
            "checkout_state_unknown", "Git could not prove the checkout is clean"
        )
    if result.stdout:
        raise CheckoutAdapterError(
            "checkout_dirty", "destructive checkout operation refused because state is not clean"
        )
    index_result = subprocess.run(
        [git, "-C", str(identity.root), "ls-files", "-v", "-z"],
        env=environment,
        capture_output=True,
        check=False,
    )
    if index_result.returncode:
        raise CheckoutAdapterError(
            "checkout_state_unknown", "Git could not prove tracked-file index flags are clear"
        )
    for entry in index_result.stdout.split(b"\0"):
        if not entry:
            continue
        if len(entry) < 3 or entry[1:2] != b" ":
            raise CheckoutAdapterError(
                "checkout_state_unknown", "Git returned an unreadable tracked-file index entry"
            )
        tag = entry[:1]
        if tag.islower() or tag.upper() == b"S":
            raise CheckoutAdapterError(
                "checkout_index_flags",
                "destructive checkout operation refused because tracked files have "
                "assume-unchanged or skip-worktree flags",
            )
