"""Running contained child processes: the kernel monitor, fork containment, process
identity, and the supervisor's own Git invocations.

What stayed in git_supervisor, on purpose: `_process_has_exited` names
`GitSupervisor._process_identity` explicitly, and tests monkeypatch that attribute on the
GitSupervisor class, so it stays where that name resolves.

Moved verbatim out of `git_supervisor` (board #1630). `GitSupervisor` inherits this mixin, so
every call site, CLI path and `GitSupervisor.<name>` lookup resolves exactly as before.
"""

from __future__ import annotations

import fcntl
import os
import re
import select
import signal
import stat
import subprocess
import sys
import time
import uuid as _uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ..worker_trampoline import LIFECYCLE_FDS_PREFIX, MONITOR_MODE
from .common import FORK_DENIED_EXIT_CODE, FORK_DENIED_SIGNATURE, SupervisorError


class ProcessMixin:
    """Contained process execution, kernel monitor handling and the supervisor's Git calls."""

    def _run_command(
        self,
        command: str,
        cwd: Path,
        extra_env: dict[str, str] | None = None,
        pass_fds: Sequence[int] = (),
    ) -> dict[str, Any]:
        env = self._child_env(extra_env)
        return self._run_process(
            ["/bin/sh", "-c", command],
            command,
            cwd,
            env,
            lifecycle_fds=pass_fds,
        )

    def _run_process(
        self,
        arguments: Sequence[str],
        label: str,
        cwd: Path,
        env: dict[str, str],
        *,
        timeout_seconds: int | None = None,
        pass_fds: Sequence[int] = (),
        lifecycle_fds: Sequence[int] = (),
    ) -> dict[str, Any]:
        if sys.platform == "darwin":
            sandbox = Path("/usr/bin/sandbox-exec")
            if not sandbox.is_file():
                raise SupervisorError(
                    "process_containment_unavailable",
                    "Darwin requires sandbox-exec for fail-closed command containment",
                )
            # EVFILT_PROC descendant tracking is unsupported on current Darwin.
            # Denying fork in the kernel leaves exactly one process identity to
            # supervise; the session leader cannot setsid() and escape.
            arguments = [
                str(sandbox),
                "-p",
                "(version 1)(allow default)(deny process-fork)(deny signal (target others))",
                *arguments,
            ]
        elif not sys.platform.startswith("linux"):
            raise SupervisorError(
                "process_containment_unavailable",
                "hard process-tree containment is supported only on Linux and Darwin",
            )
        started = time.monotonic()
        handshake_read, handshake_write = os.pipe()
        target_read, target_write = os.pipe()
        start_read, start_write = os.pipe()
        trampoline = Path(__file__).parent.with_name("worker_trampoline.py").resolve()
        inherited_fds = tuple(
            sorted({handshake_read, target_write, start_read, *pass_fds, *lifecycle_fds})
        )
        lifecycle_argument = LIFECYCLE_FDS_PREFIX + ",".join(
            str(descriptor) for descriptor in sorted(set(lifecycle_fds))
        )
        try:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    str(trampoline),
                    str(handshake_read),
                    str(target_write),
                    str(start_read),
                    MONITOR_MODE,
                    lifecycle_argument,
                    *arguments,
                ],
                cwd=cwd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
                pass_fds=inherited_fds,
            )
        except BaseException:
            os.close(handshake_write)
            os.close(target_read)
            os.close(start_write)
            raise
        finally:
            os.close(handshake_read)
            os.close(target_write)
            os.close(start_read)
        try:
            os.write(handshake_write, b"G")
        except BaseException:
            os.close(handshake_write)
            self._stop_kernel_monitor(process)
            os.close(target_read)
            os.close(start_write)
            raise
        os.close(handshake_write)
        target_pid = 0
        target_identity: str | None = None
        try:
            ready, _, _ = select.select([target_read], [], [], 3)
            raw_target = os.read(target_read, 32) if ready else b""
            if not re.fullmatch(rb"[1-9][0-9]*\n", raw_target):
                raise SupervisorError(
                    "process_containment_failed",
                    "kernel process monitor did not report its command identity",
                )
            target_pid = int(raw_target)
            target_identity = self._process_identity(target_pid)
            if target_identity is None:
                raise SupervisorError(
                    "process_containment_failed",
                    "kernel command identity could not be recorded before execution",
                )
            os.write(start_write, b"G")
        except BaseException:
            os.close(start_write)
            self._stop_kernel_monitor(process)
            raise
        finally:
            os.close(target_read)
        os.close(start_write)
        timed_out = False
        deadline = time.monotonic() + (timeout_seconds or self.config.timeout_seconds)
        while True:
            remaining = deadline - time.monotonic()
            try:
                stdout, stderr = process.communicate(timeout=max(0.01, min(0.1, remaining)))
                break
            except subprocess.TimeoutExpired:
                if process.poll() is not None:
                    if process.returncode is not None and process.returncode < 0:
                        self._terminate_unexpected_monitor_target(target_pid, target_identity)
                    stdout, stderr = process.communicate(timeout=3)
                    break
                if remaining <= 0:
                    timed_out = True
                    self._stop_kernel_monitor(process)
                    stdout, stderr = process.communicate(timeout=3)
                    break
        if process.returncode is not None and process.returncode < 0:
            self._terminate_unexpected_monitor_target(target_pid, target_identity)
        return {
            "command": label,
            "exit_code": 124 if timed_out else process.returncode,
            "stdout": stdout[-12000:],
            "stderr": stderr[-12000:],
            "duration_ms": int((time.monotonic() - started) * 1000),
            "timed_out": timed_out,
        }

    def _run_trusted_contained(
        self,
        arguments: Sequence[str],
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: int,
        pass_fds: Sequence[int],
        lifecycle_fds: Sequence[int],
    ) -> dict[str, Any]:
        return self._run_process(
            arguments,
            str(arguments[0]),
            cwd,
            dict(env),
            timeout_seconds=timeout_seconds,
            pass_fds=pass_fds,
            lifecycle_fds=lifecycle_fds,
        )

    @staticmethod
    def _stop_kernel_monitor(process: subprocess.Popen[Any]) -> None:
        if process.poll() is not None:
            return
        try:
            process.terminate()
            process.wait(timeout=3)
        except ProcessLookupError:
            return
        except subprocess.TimeoutExpired as error:
            raise SupervisorError(
                "process_containment_failed",
                "kernel process monitor did not reap its descendants",
            ) from error

    def _terminate_unexpected_monitor_target(self, pid: int, identity: str) -> None:
        """Kill the exact command PID if its trusted monitor was terminated."""

        if self._process_has_exited(pid, identity):
            return
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if self._process_has_exited(pid, identity):
                return
            time.sleep(0.01)
        raise SupervisorError(
            "process_containment_failed",
            "command survived unexpected kernel monitor termination",
        )

    def _containment_permits_fork(self) -> bool:
        """Can a contained command spawn a subprocess on this platform?

        Two canaries through the real `_run_process`, because the answer has to be a
        measurement of this machine's containment and not a belief about its name:

          control  `exit 7` must come back 7. If it does not, containment is broken
                   rather than restrictive, and a False answer here would be a guess.
          probe    a command that must fork.

        A non-zero probe is NOT evidence on its own. Measured on Darwin: a missing
        binary exits 127 with fork fully available, while a denied fork exits 128 with
        `fork: Operation not permitted` on stderr. Only the second pair is a denial, so
        both halves of the signature are required.
        """

        if self._fork_support is None:
            control = self._run_process(
                ["/bin/sh", "-c", "exit 7"], "fork canary control", self.root, self._child_env()
            )
            if control["exit_code"] != 7:
                raise SupervisorError(
                    "process_containment_unavailable",
                    "the contained-process path cannot run a trivial command "
                    f"(expected exit 7, got {control['exit_code']}); refusing to guess "
                    "whether this platform allows a command to fork",
                )
            probe = self._run_process(
                ["/bin/sh", "-c", "/usr/bin/true && /usr/bin/true"],
                "fork canary probe",
                self.root,
                self._child_env(),
            )
            denied = probe["exit_code"] == FORK_DENIED_EXIT_CODE and (
                FORK_DENIED_SIGNATURE in (probe["stderr"] or "")
            )
            self._fork_support = not denied
        return self._fork_support

    @staticmethod
    def _process_state(pid: int) -> str | None:
        """The kernel's single-letter state for a PID, or None if it cannot be read."""

        if sys.platform.startswith("linux"):
            try:
                raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
                # After the comm field the next token is the state; the identity check
                # reads the start time from this same line and skips straight past it.
                return raw.rsplit(")", 1)[1].split()[0]
            except (FileNotFoundError, IndexError, OSError, ValueError):
                return None
        if sys.platform == "darwin":
            try:
                result = subprocess.run(
                    ["/bin/ps", "-o", "state=", "-p", str(pid)],
                    env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                    capture_output=True,
                    text=True,
                    timeout=2,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                return None
            state = result.stdout.strip()
            return state[:1] if result.returncode == 0 and state else None
        return None

    @staticmethod
    def _process_identity(pid: int) -> str | None:
        """Return a PID-reuse-resistant process start identity."""

        if sys.platform.startswith("linux"):
            try:
                raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
                fields = raw.rsplit(")", 1)[1].split()
                return f"linux:{pid}:{fields[19]}"
            except (FileNotFoundError, IndexError, OSError, ValueError):
                return None
        if sys.platform == "darwin":
            try:
                result = subprocess.run(
                    ["/bin/ps", "-o", "lstart=", "-p", str(pid)],
                    env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                    capture_output=True,
                    text=True,
                    timeout=2,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                return None
            started = result.stdout.strip()
            return f"darwin:{pid}:{started}" if result.returncode == 0 and started else None
        return None

    def _remove_worktree(
        self, path: Path, delete_branch: bool, expected_branch: str | None
    ) -> bool:
        """Remove only the exact registered worktree and branch owned by the caller.

        Registration, branch validation, removal, and the optional branch deletion are
        serialized as one ACP Git operation. In particular, cleanup never derives the
        branch to delete from a fresh path that may have been replaced since its owner
        was surveyed.
        """

        canonical = path.resolve(strict=False)
        with self._git_operation_guard():
            listed = self._run_git_while_locked("worktree", "list", "--porcelain", "-z")
            if listed.returncode:
                return False
            registered = self._parse_registered_worktrees(
                listed.stdout.decode("utf-8", errors="surrogateescape")
            )
            canonical_text = str(canonical)
            if canonical_text not in registered or registered[canonical_text] != expected_branch:
                return False
            if path.is_symlink():
                return False
            if path.exists():
                try:
                    if path.resolve(strict=True) != canonical:
                        return False
                except (OSError, RuntimeError):
                    return False
                current = self._run_git_while_locked("-C", str(path), "branch", "--show-current")
                if current.returncode:
                    return False
                actual_branch = current.stdout.decode("utf-8", errors="surrogateescape").strip()
                if (actual_branch or None) != expected_branch:
                    return False

            removed = self._run_git_while_locked("worktree", "remove", "--force", str(path))
            if removed.returncode or path.exists() or path.is_symlink():
                # Git did not prove it removed the registered worktree. Never use a
                # recursive fallback: the path could have been replaced by user data.
                return False
            self._run_git_while_locked("worktree", "prune")
            listed_after = self._run_git_while_locked("worktree", "list", "--porcelain", "-z")
            if listed_after.returncode:
                return False
            remaining = self._parse_registered_worktrees(
                listed_after.stdout.decode("utf-8", errors="surrogateescape")
            )
            if canonical_text in remaining:
                return False
            if delete_branch and expected_branch:
                # Git refuses to delete a branch still checked out in another worktree.
                # A failure may leave an orphaned ref, but cannot redirect deletion.
                self._run_git_while_locked("branch", "-D", "--", expected_branch)
            return True

    def _run_git_while_locked(self, *arguments: str) -> subprocess.CompletedProcess[bytes]:
        """Run one system-Git command while the caller holds `_git_operation_guard`."""

        git = str(self._system_git_executable(self.root))
        argv = [
            *self._supervisor_git_prefix(git, self._disabled_git_hooks_dir()),
            "-C",
            str(self.root),
            *arguments,
        ]
        return subprocess.run(
            argv,
            env=self._supervisor_git_env(),
            capture_output=True,
            check=False,
        )

    def _registered_worktrees(self) -> dict[str, str | None]:
        """Return Git-registered worktree paths and their checked-out branch names."""

        output = self._git_bytes("worktree", "list", "--porcelain", "-z").decode(
            "utf-8", errors="surrogateescape"
        )
        return self._parse_registered_worktrees(output)

    @staticmethod
    def _parse_registered_worktrees(output: str) -> dict[str, str | None]:
        registered: dict[str, str | None] = {}
        record: dict[str, str] = {}

        def add_record() -> None:
            worktree = record.get("worktree")
            if worktree:
                branch = record.get("branch", "")
                if branch.startswith("refs/heads/"):
                    branch = branch.removeprefix("refs/heads/")
                registered[str(Path(worktree).resolve(strict=False))] = branch or None
            record.clear()

        for field in output.split("\0"):
            if not field:
                add_record()
            elif field.startswith("worktree "):
                record["worktree"] = field.removeprefix("worktree ")
            elif field.startswith("branch "):
                record["branch"] = field.removeprefix("branch ")
        add_record()
        return registered

    def _attempt_worktree_is_managed(self, attempt_id: str, worktree: Path, root: Path) -> bool:
        """Validate the exact registered-root child an attempt is allowed to own."""

        try:
            if str(_uuid.UUID(attempt_id)) != attempt_id:
                return False
            if not worktree.is_absolute() or not root.is_absolute():
                return False
            if worktree != root / attempt_id or root.resolve(strict=False) != root:
                return False
            default_root = (self.state_dir / "worktrees").resolve(strict=False)
            if root != default_root and self._paths_overlap(root, self.root):
                return False
            if root.is_symlink() or worktree.is_symlink():
                return False
            if root.exists() and (not root.is_dir() or root.resolve(strict=True) != root):
                return False
            if worktree.exists() and worktree.resolve(strict=True) != worktree:
                return False
            return True
        except (OSError, RuntimeError, ValueError):
            return False

    def _attempt_worktree_head(
        self,
        attempt_id: str,
        worktree: Path,
        root: Path,
        expected_branch: str | None,
    ) -> str | None:
        """Read recovery HEAD only while path, repository and branch ownership hold."""

        try:
            with self._git_operation_guard():
                canonical = str(worktree.resolve(strict=False))

                def owned_registration() -> bool:
                    if not self._attempt_worktree_is_managed(attempt_id, worktree, root):
                        return False
                    listed = self._run_git_while_locked("worktree", "list", "--porcelain", "-z")
                    if listed.returncode:
                        return False
                    registered = self._parse_registered_worktrees(
                        listed.stdout.decode("utf-8", errors="surrogateescape")
                    )
                    return canonical in registered and registered[canonical] == expected_branch

                def worktree_identity_holds() -> bool:
                    if not owned_registration():
                        return False
                    branch = self._run_git_while_locked(
                        "-C", str(worktree), "branch", "--show-current"
                    )
                    top = self._run_git_while_locked(
                        "-C", str(worktree), "rev-parse", "--show-toplevel"
                    )
                    common = self._run_git_while_locked(
                        "-C",
                        str(worktree),
                        "rev-parse",
                        "--path-format=absolute",
                        "--git-common-dir",
                    )
                    repository_common = self._run_git_while_locked(
                        "rev-parse", "--path-format=absolute", "--git-common-dir"
                    )
                    if any(
                        result.returncode for result in (branch, top, common, repository_common)
                    ):
                        return False
                    branch_name = branch.stdout.decode("utf-8", errors="surrogateescape").strip()
                    top_path = Path(
                        top.stdout.decode("utf-8", errors="surrogateescape").rstrip("\r\n")
                    ).resolve(strict=True)
                    worktree_common = Path(
                        common.stdout.decode("utf-8", errors="surrogateescape").rstrip("\r\n")
                    ).resolve(strict=True)
                    repository_common_path = Path(
                        repository_common.stdout.decode("utf-8", errors="surrogateescape").rstrip(
                            "\r\n"
                        )
                    ).resolve(strict=True)
                    return (
                        (branch_name or None) == expected_branch
                        and top_path == worktree
                        and worktree_common == repository_common_path
                    )

                if not worktree_identity_holds():
                    return None
                head = self._run_git_while_locked("-C", str(worktree), "rev-parse", "HEAD")
                if head.returncode or not worktree_identity_holds():
                    return None
                return head.stdout.decode("utf-8", errors="surrogateescape").strip() or None
        except (OSError, RuntimeError, SupervisorError, ValueError):
            return None

    @contextmanager
    def _git_operation_guard(self) -> Iterator[int]:
        """Serialize Git's shared administrative files across workers/processes."""

        lock_path = self.state_dir / "git-operations.lock"
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            lock_fd = os.open(lock_path, flags, 0o600)
        except OSError as error:
            raise SupervisorError(
                "git_lock_unavailable", "Git operation lock could not be opened"
            ) from error
        try:
            metadata = os.fstat(lock_fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise SupervisorError(
                    "git_lock_unsafe",
                    "Git operation lock must be a current-user-owned 0600 regular file",
                )
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            yield lock_fd
        finally:
            os.close(lock_fd)

    def _git_text(self, *arguments: str, check: bool = True) -> str:
        git = str(self._system_git_executable(self.root))
        argv = [
            *self._supervisor_git_prefix(git, self._disabled_git_hooks_dir()),
            "-C",
            str(self.root),
            *arguments,
        ]
        with self._git_operation_guard():
            result = subprocess.run(
                argv,
                env=self._supervisor_git_env(),
                capture_output=True,
                text=True,
                check=False,
            )
        if check and result.returncode:
            raise SupervisorError(
                "git_error",
                result.stderr.strip() or result.stdout.strip() or "git failed",
            )
        return result.stdout.strip()

    def _git_bytes(self, *arguments: str, check: bool = True) -> bytes:
        git = str(self._system_git_executable(self.root))
        argv = [
            *self._supervisor_git_prefix(git, self._disabled_git_hooks_dir()),
            "-C",
            str(self.root),
            *arguments,
        ]
        with self._git_operation_guard():
            result = subprocess.run(
                argv,
                env=self._supervisor_git_env(),
                capture_output=True,
                check=False,
            )
        if check and result.returncode:
            raise SupervisorError(
                "git_error",
                result.stderr.decode(errors="replace").strip() or "git failed",
            )
        return result.stdout

    def _git(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        git = str(self._system_git_executable(self.root))
        argv = [
            *self._supervisor_git_prefix(git, self._disabled_git_hooks_dir()),
            "-C",
            str(self.root),
            *arguments,
        ]
        with self._git_operation_guard():
            result = subprocess.run(
                argv,
                env=self._supervisor_git_env(),
                capture_output=True,
                check=False,
            )
        if check and result.returncode:
            raise SupervisorError(
                "git_error",
                result.stderr.decode(errors="replace").strip()
                or result.stdout.decode(errors="replace").strip()
                or "git failed",
            )
        return result
