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
import shutil
import signal
import stat
import subprocess
import sys
import time
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

    def _remove_worktree(self, path: Path, delete_branch: bool) -> None:
        branch = (
            self._git_text("-C", str(path), "branch", "--show-current", check=False)
            if path.exists()
            else ""
        )
        self._git("worktree", "remove", "--force", str(path), check=False)
        if path.exists():
            shutil.rmtree(path)
        self._git("worktree", "prune", check=False)
        if delete_branch and branch:
            self._git("branch", "-D", branch, check=False)

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
