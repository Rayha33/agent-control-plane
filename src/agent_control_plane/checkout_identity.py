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


def _pending_operation_name(identity: CheckoutIdentity) -> str:
    return f".acp-checkout-{identity.checkout_id}.pending"


def _require_no_pending_operation(identity: CheckoutIdentity) -> None:
    directory_fd = _open_checkout_lock(identity.common_dir)
    try:
        try:
            marker = os.stat(
                _pending_operation_name(identity),
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        except OSError as error:
            raise CheckoutAdapterError(
                "checkout_recovery_unknown",
                "the prior checkout operation state cannot be verified; inspect before retrying",
            ) from error
        if (
            not stat.S_ISREG(marker.st_mode)
            or marker.st_uid != os.geteuid()
            or marker.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
        ):
            raise CheckoutAdapterError(
                "checkout_recovery_unknown",
                "the prior checkout operation marker is unsafe; inspect before retrying",
            )
        raise CheckoutAdapterError(
            "checkout_recovery_required",
            "a prior mediated operation has unresolved recovery state; inspect and resolve "
            "the checkout before removing its marker",
        )
    finally:
        os.close(directory_fd)


def _begin_pending_operation(
    identity: CheckoutIdentity, operation: CheckoutOperation, fencing_token: int
) -> tuple[int, int]:
    directory_fd = _open_checkout_lock(identity.common_dir)
    marker_fd: int | None = None
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        try:
            marker_fd = os.open(
                _pending_operation_name(identity), flags, 0o600, dir_fd=directory_fd
            )
        except FileExistsError as error:
            raise CheckoutAdapterError(
                "checkout_recovery_required",
                "a prior mediated operation may have been interrupted; inspect and resolve "
                "the checkout before retrying",
            ) from error
        except OSError as error:
            raise CheckoutAdapterError(
                "checkout_recovery_unavailable",
                "cannot durably record the pending checkout operation; no action was run",
            ) from error

        payload = json.dumps(
            {
                "identity_version": 1,
                "state": "pending",
                "resource": identity.resource,
                "operation": operation,
                "fencing_token": fencing_token,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        remaining = memoryview(payload)
        while remaining:
            written = os.write(marker_fd, remaining)
            if written <= 0:
                raise OSError("short write while recording checkout operation")
            remaining = remaining[written:]
        os.fsync(marker_fd)
        os.fsync(directory_fd)
        return directory_fd, marker_fd
    except BaseException:
        if marker_fd is not None:
            os.close(marker_fd)
        os.close(directory_fd)
        raise


def _mark_pending_operation_complete(
    identity: CheckoutIdentity,
    operation: CheckoutOperation,
    fencing_token: int,
    handles: tuple[int, int],
) -> None:
    directory_fd, marker_fd = handles
    marker_name = _pending_operation_name(identity)
    try:
        opened = os.fstat(marker_fd)
        current = os.stat(marker_name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as error:
        raise CheckoutAdapterError(
            "checkout_recovery_marker_changed",
            "the pending checkout marker changed during the operation; inspect before retrying",
        ) from error
    if not stat.S_ISREG(current.st_mode) or (opened.st_dev, opened.st_ino) != (
        current.st_dev,
        current.st_ino,
    ):
        raise CheckoutAdapterError(
            "checkout_recovery_marker_changed",
            "the pending checkout marker changed during the operation; inspect before retrying",
        )

    payload = json.dumps(
        {
            "fencing_token": fencing_token,
            "identity_version": 1,
            "operation": operation,
            "resource": identity.resource,
            "state": "complete",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    try:
        os.ftruncate(marker_fd, 0)
        os.lseek(marker_fd, 0, os.SEEK_SET)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(marker_fd, remaining)
            if written <= 0:
                raise OSError("short write while recording completed checkout operation")
            remaining = remaining[written:]
        # The pending directory entry was already synchronized before the callback.
        # Syncing this state before unlink means an ambiguous directory fsync after
        # unlink cannot turn a completed callback into an ambiguous API failure.
        os.fsync(marker_fd)
    except OSError as error:
        raise CheckoutAdapterError(
            "checkout_recovery_completion_failed",
            "the callback completed but its outcome could not be recorded durably; inspect "
            "the checkout before retrying",
        ) from error


def _clear_pending_operation(identity: CheckoutIdentity, handles: tuple[int, int]) -> None:
    directory_fd, marker_fd = handles
    marker_name = _pending_operation_name(identity)
    try:
        opened = os.fstat(marker_fd)
        current = os.stat(marker_name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        # Completion is already durable. If cleanup status is unavailable, do not
        # turn a known callback result into an ambiguous exception; the next owner
        # independently checks for any marker and fails closed if one remains.
        return
    if not stat.S_ISREG(current.st_mode) or (opened.st_dev, opened.st_ino) != (
        current.st_dev,
        current.st_ino,
    ):
        raise CheckoutAdapterError(
            "checkout_recovery_marker_changed",
            "the pending checkout marker changed during the operation; inspect before retrying",
        )
    try:
        os.unlink(marker_name, dir_fd=directory_fd)
    except OSError as error:
        try:
            current = os.stat(marker_name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            # The completed state was fsynced before cleanup. If the entry is absent,
            # the callback result is not ambiguous; if status is unavailable, the
            # next owner's no-follow check still fails closed when a marker remains.
            return
        if stat.S_ISREG(current.st_mode) and (opened.st_dev, opened.st_ino) == (
            current.st_dev,
            current.st_ino,
        ):
            raise CheckoutAdapterError(
                "checkout_recovery_marker_clear_failed",
                "the callback completed durably but its recovery marker remains; inspect "
                "the checkout before retrying",
            ) from error
        return
    try:
        os.fsync(directory_fd)
    except OSError:
        # The callback completion was fsynced first. After a crash, the marker may
        # reappear (and safely block) or remain absent (the completed callback is safe).
        # Do not report an error after a successful callback when its result is known.
        return


def _close_pending_operation(handles: tuple[int, int]) -> None:
    for descriptor in handles:
        try:
            os.close(descriptor)
        except OSError:
            pass


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
            _require_no_pending_operation(identity)
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
        pending_handles: tuple[int, int] | None = None
        try:
            if identify_checkout(self.path).resource != identity.resource:
                raise CheckoutAdapterError(
                    "checkout_identity_changed", "checkout identity changed before mutation"
                )
            if not self.validate_fence(identity.resource, token):
                raise CheckoutAdapterError(
                    "checkout_fence_stale", "stale checkout owner cannot mutate this checkout"
                )
            _require_no_pending_operation(identity)
            if operation in _DESTRUCTIVE_OPERATIONS:
                _require_clean_checkout(identity)
            pending_handles = _begin_pending_operation(identity, operation, token)
            result = action()
            if (
                operation != "cleanup"
                and identify_checkout(self.path).resource != identity.resource
            ):
                raise CheckoutAdapterError(
                    "checkout_identity_changed", "checkout identity changed during mutation"
                )
            if operation == "cleanup" and not identity.common_dir.exists():
                _close_pending_operation(pending_handles)
                pending_handles = None
            else:
                _mark_pending_operation_complete(identity, operation, token, pending_handles)
                _clear_pending_operation(identity, pending_handles)
            return result
        except BaseException:
            # The durable marker survives process death; this flag also prevents a
            # caught failure from being retried through the same adapter instance.
            self._operation_failed = True
            raise
        finally:
            if pending_handles is not None:
                _close_pending_operation(pending_handles)

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
