"""Trusted, phase-scoped runtime drivers with cleanup proofs.

Shell lifecycle hooks are flexible but they cannot *prove* that a database
schema, Compose project or browser profile was actually deleted, and because
they run as ``/bin/sh -c`` with the candidate's worktree as the working
directory, a relative script name resolves to candidate-controlled code. A
worker that is asked to clean up after itself therefore both supplies and
grades its own cleanup.

Drivers close that gap with three rules:

1. **Trusted executables only.** A driver names an absolute executable that
   lives outside the repository and is not writable by anyone but its owner.
   The path is validated when configuration loads *and* immediately before
   every exec, because a file that passed a check minutes ago is not evidence
   about the file being run now.
2. **No shell, never in the worktree.** Drivers are invoked as an argv vector
   with the runtime directory as the working directory. Nothing is word-split,
   glob-expanded, or resolved relative to candidate content.
3. **Cleanup is proven, not asserted.** ``teardown`` is always followed by an
   independent ``verify`` that must observe the resource *absent*. A teardown
   that exits 0 while the resource still exists produces no proof, and an
   allocation without proof is quarantined rather than recycled.

A deliberate consequence of the adapter design: the security-critical half of
each driver — ``teardown`` and ``verify`` — is addressed purely by resource
*name*, so it never reads a compose file, SQL script or profile template from
the candidate. Only ``setup`` consumes candidate-adjacent input.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from .credential_providers import (
    CredentialError,
    CredentialHandle,
    CredentialMaterial,
    CredentialRegistry,
)

PHASES: tuple[str, ...] = ("setup", "verify", "teardown")
DRIVER_KINDS: tuple[str, ...] = (
    "docker_compose",
    "postgres_schema",
    "browser_profile",
    "namespace_runtime",
)

# Drivers are infrastructure operations; they get a bounded, generous budget.
DEFAULT_PHASE_TIMEOUT_SECONDS = 300
TRUSTED_DRIVER_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
SENSITIVE_ENV_NAMES = {
    "PGDATABASE",
    "PGPASSWORD",
    "PGPASSFILE",
    "DATABASE_URL",
    "DSN",
}


class DriverError(Exception):
    """Raised for driver configuration and execution faults."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# Trust boundary
# ---------------------------------------------------------------------------


def _validate_trusted_path(
    resolved: Path, expected_owners: set[int] | None = None
) -> os.stat_result:
    """Validate the executable and its directory chain.

    A safe file inside a replaceable directory is not safe. Root-owned sticky
    temporary directories are accepted as anchors because sticky semantics
    prevent another user from replacing an owner-controlled entry beneath
    them; other group/world-writable parents are rejected.
    """

    # Candidate commands run as the ACP user in the local alpha. A same-UID
    # executable is therefore candidate-replaceable and cannot be a trust root.
    expected_owners = expected_owners or {0}
    file_stat = resolved.stat()
    if file_stat.st_uid not in expected_owners:
        raise DriverError(
            "untrusted_driver",
            f"driver executable has an unexpected owner: {resolved}",
        )
    if file_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise DriverError(
            "untrusted_driver",
            f"driver executable is group/world writable and cannot be trusted: {resolved}",
        )

    parent = resolved.parent
    while True:
        parent_stat = parent.stat()
        if parent_stat.st_uid not in expected_owners:
            raise DriverError(
                "untrusted_driver",
                f"driver parent has an unexpected owner: {parent}",
            )
        writable = parent_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        sticky_root_anchor = parent_stat.st_uid == 0 and bool(parent_stat.st_mode & stat.S_ISVTX)
        if writable and not sticky_root_anchor:
            raise DriverError(
                "untrusted_driver",
                f"driver parent is group/world writable: {parent}",
            )
        if sticky_root_anchor or parent == parent.parent:
            break
        parent = parent.parent
    return file_stat


def resolve_trusted_executable(
    raw: str, repo_root: Path, expected_owners: set[int] | None = None
) -> Path:
    """Resolve *raw* to an executable that a candidate cannot influence.

    Mirrors the existing ``critic_command`` contract and adds a writability
    check: an executable that any group or other user can rewrite is not a
    trust anchor, it is a hook with extra steps.
    """

    if not raw:
        raise DriverError("invalid_config", "driver executable must be set")
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise DriverError(
            "invalid_config",
            f"driver executable must be one absolute path, got {raw!r}",
        )
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as error:
        raise DriverError("invalid_config", f"driver executable does not exist: {raw}") from error

    # resolve() has already collapsed symlinks, so a link pointing into the
    # repository is caught here rather than at exec time.
    try:
        resolved.relative_to(repo_root.resolve())
    except ValueError:
        pass
    else:
        raise DriverError(
            "untrusted_driver",
            f"driver executable must live outside the repository: {resolved}",
        )

    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise DriverError(
            "invalid_config", f"driver executable is not an executable file: {resolved}"
        )

    _validate_trusted_path(resolved, expected_owners)
    return resolved


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DriverDefinition:
    name: str
    kind: str
    executable: Path | None
    options: Mapping[str, str]

    def option(self, key: str, default: str | None = None) -> str | None:
        value = self.options.get(key, default)
        return value


@dataclass(frozen=True)
class DriverContext:
    attempt_id: str
    task_id: str
    runtime_dir: Path
    expires_at: int
    secret: bytes
    environment: Mapping[str, str]
    credential_registry: CredentialRegistry | None = None
    credential_handles: Mapping[str, CredentialHandle] | None = None


@dataclass(frozen=True)
class PhaseEvidence:
    driver: str
    kind: str
    phase: str
    resource_id: str
    ownership_token: str
    expires_at: int
    exit_code: int
    present: bool | None
    proof: dict[str, Any]
    credential_handle: CredentialHandle | None = None

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "driver": self.driver,
            "kind": self.kind,
            "phase": self.phase,
            "resource_id": self.resource_id,
            "ownership_token": self.ownership_token,
            "expires_at": self.expires_at,
            "exit_code": self.exit_code,
            "present": self.present,
            "proof": self.proof,
        }


def ownership_token(secret: bytes, attempt_id: str, kind: str, resource_id: str) -> str:
    """Bind a resource to the attempt that allocated it.

    Teardown refuses to act on a resource whose token does not match, so a
    stale or forged record cannot make the supervisor delete a resource that
    belongs to another attempt.
    """

    message = f"{attempt_id}\x00{kind}\x00{resource_id}".encode()
    return hmac.new(secret, message, sha256).hexdigest()


def _sanitize(value: str, *, allow: str) -> str:
    return "".join(char if char.isalnum() or char in allow else "-" for char in value)


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


CommandRunner = Callable[
    [Sequence[str], Path, Mapping[str, str], int, CredentialMaterial | None],
    dict[str, Any],
]
ContainedProcessRunner = Callable[
    [Sequence[str], Path, Mapping[str, str], int, Sequence[int], Sequence[int]],
    dict[str, Any],
]


def run_trusted(
    argv: Sequence[str],
    cwd: Path,
    env: Mapping[str, str],
    timeout: int = DEFAULT_PHASE_TIMEOUT_SECONDS,
    credential: CredentialMaterial | None = None,
    *,
    guard_fd: int | None = None,
    expected_owners: set[int] | None = None,
    process_runner: ContainedProcessRunner | None = None,
) -> dict[str, Any]:
    """Execute *argv* directly — no shell, no PATH search, no worktree cwd.

    ``guard_fd`` is a supervisor-owned lifetime lock. A contained process
    runner retains it in its trusted monitor but closes it before executing the
    external command, so recovery remains fenced without giving the command an
    unlock capability.
    """

    if not argv:
        raise DriverError("invalid_driver_invocation", "empty driver argv")
    requested_executable = Path(argv[0])
    if not requested_executable.is_absolute():
        raise DriverError(
            "invalid_driver_invocation",
            f"driver argv[0] must be absolute, got {argv[0]!r}",
        )
    try:
        # Normalize a platform alias such as Ubuntu's /bin/sh -> /usr/bin/dash
        # before the O_NOFOLLOW open. The final inode is still validated and
        # executed by its resolved absolute path, never by the mutable alias.
        executable = requested_executable.resolve(strict=True)
    except OSError as error:
        raise DriverError(
            "untrusted_driver",
            f"driver executable could not be resolved: {requested_executable}",
        ) from error
    try:
        cwd.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise DriverError(
            "driver_staging_failed", "driver runtime directory is unavailable"
        ) from error
    # Re-check immediately before exec. Validation at config load proves nothing
    # about the file we are about to run.
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise DriverError(
            "untrusted_driver",
            f"driver executable disappeared or lost its exec bit: {executable}",
        )
    expected = _validate_trusted_path(executable, expected_owners)

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        executable_fd = os.open(executable, flags)
    except OSError as error:
        raise DriverError(
            "untrusted_driver", f"could not open trusted executable: {executable}"
        ) from error
    opened = os.fstat(executable_fd)
    if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
        os.close(executable_fd)
        raise DriverError("untrusted_driver", "driver executable changed while it was being opened")

    safe_env = {
        "PATH": TRUSTED_DRIVER_PATH,
        "LANG": "C",
        "LC_ALL": "C",
    }
    for name, value in env.items():
        if name != "ACP_RUNNER_CREDENTIAL" and (
            name.startswith("ACP_") or name in SENSITIVE_ENV_NAMES
        ):
            safe_env[name] = value

    secrets = [
        value
        for name, value in safe_env.items()
        if value
        and (
            name in SENSITIVE_ENV_NAMES
            or any(marker in name for marker in ("PASSWORD", "TOKEN", "SECRET", "CREDENTIAL"))
        )
    ]
    if credential is not None:
        secrets.extend(credential.redactions)

    def redact(value: str) -> str:
        for secret in secrets:
            value = value.replace(secret, "[REDACTED]")
        return value

    execution_argv = [str(executable), *argv[1:]]
    # Linux can execute the inode we opened and checked through /proc. Darwin
    # rejects executable /dev/fd entries; there the non-writable, privileged
    # parent chain is what makes the already-verified path non-replaceable.
    descriptor_root = Path("/proc/self/fd")
    descriptor_execution = sys.platform.startswith("linux") and descriptor_root.is_dir()
    started = time.monotonic()
    try:
        command_fds = {
            fd for fd in (credential.fd if credential is not None else None,) if fd is not None
        }
        if process_runner is not None:
            contained_argv = list(execution_argv)
            if descriptor_execution:
                contained_argv[0] = str(descriptor_root / str(executable_fd))
                command_fds.add(executable_fd)
            contained = process_runner(
                contained_argv,
                cwd,
                safe_env,
                timeout,
                tuple(sorted(command_fds)),
                (guard_fd,) if guard_fd is not None else (),
            )
            return {
                "argv": [redact(value) for value in execution_argv],
                "exit_code": int(contained["exit_code"]),
                "stdout": redact(str(contained.get("stdout", ""))),
                "stderr": redact(str(contained.get("stderr", ""))),
                "duration_ms": int(contained["duration_ms"]),
                "timed_out": bool(contained.get("timed_out", False)),
            }
        if guard_fd is not None:
            raise DriverError(
                "lifecycle_monitor_required",
                "a guard descriptor requires a contained process monitor",
            )
        execution_options: dict[str, Any] = {}
        if descriptor_execution:
            execution_options["executable"] = str(descriptor_root / str(executable_fd))
            command_fds.add(executable_fd)
        process = subprocess.run(
            execution_argv,
            **execution_options,
            cwd=str(cwd),
            env=safe_env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            pass_fds=tuple(sorted(command_fds)),
        )
    except subprocess.TimeoutExpired:
        return {
            "argv": [redact(value) for value in execution_argv],
            "exit_code": 124,
            "stdout": "",
            "stderr": f"driver timed out after {timeout}s",
            "duration_ms": int((time.monotonic() - started) * 1000),
            "timed_out": True,
        }
    except OSError as error:
        raise DriverError(
            "driver_execution_failed", "verified driver executable could not start"
        ) from error
    finally:
        os.close(executable_fd)
    return {
        "argv": [redact(value) for value in execution_argv],
        "exit_code": process.returncode,
        "stdout": redact(process.stdout),
        "stderr": redact(process.stderr),
        "duration_ms": int((time.monotonic() - started) * 1000),
        "timed_out": False,
    }


# ---------------------------------------------------------------------------
# Adapters
# ---------------------------------------------------------------------------


class ResourceDriver:
    """Base adapter. Subclasses describe one class of disposable resource."""

    kind = ""

    def __init__(self, definition: DriverDefinition) -> None:
        self.definition = definition

    # -- identity ----------------------------------------------------------
    def resource_id(self, context: DriverContext) -> str:  # pragma: no cover
        raise NotImplementedError

    # -- phases ------------------------------------------------------------
    def setup(self, context: DriverContext, runner: CommandRunner) -> dict[str, Any]:
        raise NotImplementedError

    def probe(self, context: DriverContext, runner: CommandRunner) -> tuple[bool, dict[str, Any]]:
        """Return ``(present, observation)``."""
        raise NotImplementedError

    def teardown(self, context: DriverContext, runner: CommandRunner) -> dict[str, Any]:
        raise NotImplementedError

    # -- shared ------------------------------------------------------------
    def _env(self, context: DriverContext) -> dict[str, str]:
        env = {
            name: value for name, value in context.environment.items() if name.startswith("ACP_")
        }
        env["ACP_RESOURCE_ID"] = self.resource_id(context)
        return env

    def ownership_identity(self, context: DriverContext) -> str:
        """Secret input bound into the non-disclosing ownership capability."""
        return self.resource_id(context)

    def ownership_token(self, context: DriverContext) -> str:
        return ownership_token(
            context.secret,
            context.attempt_id,
            self.kind,
            self.ownership_identity(context),
        )

    def credential_handle(self, context: DriverContext) -> CredentialHandle | None:
        return (context.credential_handles or {}).get(self.definition.name)

    def run_phase(
        self,
        phase: str,
        context: DriverContext,
        runner: CommandRunner,
    ) -> PhaseEvidence:
        if phase not in PHASES:
            raise DriverError("invalid_phase", f"unknown driver phase {phase!r}")
        resource = self.resource_id(context)
        token = self.ownership_token(context)
        credential_handle = self.credential_handle(context)

        if phase == "setup":
            result = self.setup(context, runner)
            present, observation = self.probe(context, runner)
            proof = {"action": result, "observation": observation}
            action_ok = result.get("exit_code", 0) == 0
            probe_ok = observation.get("exit_code", 0) == 0
            exit_code = 0 if action_ok and probe_ok and present else 1
            if action_ok and not probe_ok:
                proof["error"] = "setup probe failed; resource presence is unproven"
            elif action_ok and not present:
                proof["error"] = "setup reported success but resource is absent"
            return PhaseEvidence(
                driver=self.definition.name,
                kind=self.kind,
                phase=phase,
                resource_id=resource,
                ownership_token=token,
                expires_at=context.expires_at,
                exit_code=exit_code,
                present=present,
                proof=proof,
                credential_handle=credential_handle,
            )

        if phase == "verify":
            present, observation = self.probe(context, runner)
            return PhaseEvidence(
                driver=self.definition.name,
                kind=self.kind,
                phase=phase,
                resource_id=resource,
                ownership_token=token,
                expires_at=context.expires_at,
                exit_code=0 if observation.get("exit_code", 0) == 0 else 1,
                present=present,
                proof={"observation": observation},
                credential_handle=credential_handle,
            )

        result = self.teardown(context, runner)
        present, observation = self.probe(context, runner)
        proof: dict[str, Any] = {
            "action": result,
            "observation": observation,
            "cleanup_proved": (not present) and observation.get("exit_code", 0) == 0,
        }
        # THE central rule: exit code 0 is not cleanup. Absence is cleanup.
        if present:
            proof["error"] = "teardown reported success but resource is still present"
        exit_code = result.get("exit_code", 0)
        if exit_code == 0 and not proof["cleanup_proved"]:
            exit_code = 1
        return PhaseEvidence(
            driver=self.definition.name,
            kind=self.kind,
            phase="teardown",
            resource_id=resource,
            ownership_token=token,
            expires_at=context.expires_at,
            exit_code=exit_code,
            present=present,
            proof=proof,
            credential_handle=credential_handle,
        )


class DockerComposeDriver(ResourceDriver):
    kind = "docker_compose"

    def resource_id(self, context: DriverContext) -> str:
        prefix = self.definition.option("project_prefix", "acp") or "acp"
        return _sanitize(f"{prefix}-{context.attempt_id}", allow="-_").lower()

    def _base(self, context: DriverContext) -> list[str]:
        if self.definition.executable is None:
            raise DriverError("invalid_config", "compose driver executable is missing")
        return [
            str(self.definition.executable),
            "compose",
            "-p",
            self.resource_id(context),
        ]

    def setup(self, context: DriverContext, runner: CommandRunner) -> dict[str, Any]:
        argv = list(self._base(context))
        compose_file = self.definition.option("compose_file")
        if compose_file:
            argv.extend(["-f", compose_file])
        argv.extend(["up", "-d", "--remove-orphans"])
        return runner(argv, context.runtime_dir, self._env(context), self._timeout(), None)

    def probe(self, context: DriverContext, runner: CommandRunner) -> tuple[bool, dict[str, Any]]:
        # Addressed by project name only — no compose file, so the proof cannot
        # be steered by candidate content.
        argv = [*self._base(context), "ps", "--all", "--quiet"]
        result = runner(argv, context.runtime_dir, self._env(context), self._timeout(), None)
        present = bool(result.get("stdout", "").strip())
        return present, result

    def teardown(self, context: DriverContext, runner: CommandRunner) -> dict[str, Any]:
        argv = [*self._base(context), "down", "--volumes", "--remove-orphans"]
        return runner(argv, context.runtime_dir, self._env(context), self._timeout(), None)

    def _timeout(self) -> int:
        return int(
            self.definition.option("timeout_seconds", str(DEFAULT_PHASE_TIMEOUT_SECONDS))
            or DEFAULT_PHASE_TIMEOUT_SECONDS
        )


class PostgresSchemaDriver(ResourceDriver):
    kind = "postgres_schema"

    def resource_id(self, context: DriverContext) -> str:
        prefix = self.definition.option("schema_prefix", "acp") or "acp"
        raw = _sanitize(f"{prefix}_{context.attempt_id}", allow="_").lower()
        return raw.replace("-", "_")

    def _psql(
        self,
        context: DriverContext,
        sql: str,
        variables: Mapping[str, str] | None = None,
    ) -> list[str]:
        if self.definition.executable is None:
            raise DriverError("invalid_config", "postgres driver executable is missing")
        # -X prevents candidate-writable ~/.psqlrc from executing backslash
        # commands inside the otherwise trusted psql process while its
        # credential descriptor is live. --no-password prevents an inherited
        # terminal from becoming an implicit credential/input channel.
        argv = [str(self.definition.executable), "-X", "--no-password"]
        for option, flag in (
            ("host", "--host"),
            ("port", "--port"),
            ("database", "--dbname"),
            ("user", "--username"),
        ):
            value = self.definition.option(option)
            if value:
                argv.extend([flag, value])
        argv.extend(["-v", "ON_ERROR_STOP=1"])
        for name, value in sorted((variables or {}).items()):
            argv.extend(["--set", f"{name}={value}"])
        argv.extend(["-tAc", sql])
        return argv

    def ownership_identity(self, context: DriverContext) -> str:
        handle = self.credential_handle(context)
        if handle is None:
            raise DriverError("credential_unavailable", "postgres credential handle is missing")
        target = "\x00".join(
            self.definition.option(name, "") or "" for name in ("host", "port", "database", "user")
        )
        # The stored capability binds both the public connection target and a
        # keyed fingerprint of the exact credential version. Neither plaintext
        # nor a guessable raw digest is persisted.
        return (
            f"{self.resource_id(context)}\x00{target}\x00{handle.version}"
            f"\x00{handle.target_fingerprint}"
        )

    @contextmanager
    def _connection(self, context: DriverContext) -> Any:
        handle = self.credential_handle(context)
        if handle is None or context.credential_registry is None:
            raise DriverError("credential_unavailable", "postgres credential is unavailable")
        try:
            with context.credential_registry.materialize(handle, context.runtime_dir) as material:
                env = super()._env(context)
                # PGPASSFILE contains only a descriptor path. The password is
                # passed on that descriptor and never becomes an env value.
                env["PGPASSFILE"] = material.path
                yield env, material
        except CredentialError as error:
            raise DriverError(error.code, error.message) from error

    def setup(self, context: DriverContext, runner: CommandRunner) -> dict[str, Any]:
        schema = self.resource_id(context)
        with self._connection(context) as (env, material):
            return runner(
                self._psql(
                    context,
                    'CREATE SCHEMA IF NOT EXISTS :"schema"',
                    {"schema": schema},
                ),
                context.runtime_dir,
                env,
                DEFAULT_PHASE_TIMEOUT_SECONDS,
                material,
            )

    def probe(self, context: DriverContext, runner: CommandRunner) -> tuple[bool, dict[str, Any]]:
        schema = self.resource_id(context)
        with self._connection(context) as (env, material):
            result = runner(
                self._psql(
                    context,
                    "SELECT 1 FROM information_schema.schemata WHERE schema_name = :'schema'",
                    {"schema": schema},
                ),
                context.runtime_dir,
                env,
                DEFAULT_PHASE_TIMEOUT_SECONDS,
                material,
            )
        present = result.get("stdout", "").strip() == "1"
        return present, result

    def teardown(self, context: DriverContext, runner: CommandRunner) -> dict[str, Any]:
        schema = self.resource_id(context)
        with self._connection(context) as (env, material):
            return runner(
                self._psql(
                    context,
                    'DROP SCHEMA IF EXISTS :"schema" CASCADE',
                    {"schema": schema},
                ),
                context.runtime_dir,
                env,
                DEFAULT_PHASE_TIMEOUT_SECONDS,
                material,
            )


class BrowserProfileDriver(ResourceDriver):
    """Filesystem-backed driver — no external executable, so it is always available."""

    kind = "browser_profile"

    def resource_id(self, context: DriverContext) -> str:
        prefix = self.definition.option("profile_prefix", "profile") or "profile"
        name = _sanitize(f"{prefix}-{context.attempt_id}", allow="-_")
        return str(context.runtime_dir / "profiles" / name)

    def setup(self, context: DriverContext, runner: CommandRunner) -> dict[str, Any]:
        target = Path(self.resource_id(context))
        try:
            target.mkdir(parents=True, exist_ok=True)
            (target / "acp-owner.json").write_text(
                json.dumps(
                    {
                        "attempt_id": context.attempt_id,
                        "task_id": context.task_id,
                        "expires_at": context.expires_at,
                    },
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
        except OSError as error:
            return {
                "argv": ["<builtin>", "mkdir", str(target)],
                "exit_code": 1,
                "stderr": str(error),
                "stdout": "",
            }
        return {
            "argv": ["<builtin>", "mkdir", str(target)],
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
        }

    def probe(self, context: DriverContext, runner: CommandRunner) -> tuple[bool, dict[str, Any]]:
        target = Path(self.resource_id(context))
        present = target.exists()
        return present, {
            "argv": ["<builtin>", "stat", str(target)],
            "exit_code": 0,
            "stdout": "present" if present else "absent",
            "stderr": "",
        }

    def teardown(self, context: DriverContext, runner: CommandRunner) -> dict[str, Any]:
        target = Path(self.resource_id(context))
        try:
            shutil.rmtree(target)
        except FileNotFoundError:
            # Idempotent: tearing down what is already gone is success.
            pass
        except OSError as error:
            return {
                "argv": ["<builtin>", "rmtree", str(target)],
                "exit_code": 1,
                "stderr": str(error),
                "stdout": "",
            }
        return {
            "argv": ["<builtin>", "rmtree", str(target)],
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
        }


class NamespaceRuntimeDriver(ResourceDriver):
    """Containment backend: one transient systemd user unit per attempt.

    Local port allocation coordinates cooperative processes; this contains
    uncooperative ones. Every quota is a cgroup v2 attribute on a delegated
    user slice, so no root, no daemon and no container image is involved.

    🔴 THE UNIT IS A SERVICE, NEVER A ``--scope``, and that is the whole design
    rather than a preference. A scope hands lifetime to its caller and does not
    kill the cgroup members that remain, so a ``setsid nohup`` grandchild
    outlives it. Measured on the target host with both arms of the same payload:
    under ``--scope`` the daemon was ALIVE afterwards (survivors=1); under a
    service unit, whose default ``KillMode=control-group`` kills the whole
    cgroup once the main process exits, it was dead (survivors=0). A mocked
    test cannot catch that difference, so the choice is pinned here in code.
    """

    kind = "namespace_runtime"

    # cgroup v2 on a delegated user slice carries cpu/memory/pids. It does NOT
    # carry io unless the host delegates it, so a disk quota cannot be spelled
    # as a cgroup attribute here; the writable layer is bounded by inspection
    # instead, and `probe` reports its size as evidence rather than pretending.
    _QUOTA_PROPERTIES: tuple[tuple[str, str], ...] = (
        ("memory_max", "MemoryMax"),
        ("memory_swap_max", "MemorySwapMax"),
        ("tasks_max", "TasksMax"),
        ("cpu_quota", "CPUQuota"),
        ("wall_clock_seconds", "RuntimeMaxSec"),
    )
    _DEFAULT_DISK_MAX = "64M"

    def resource_id(self, context: DriverContext) -> str:
        prefix = self.definition.option("unit_prefix", "acp") or "acp"
        return _sanitize(f"{prefix}-{context.attempt_id}", allow="-_").lower()

    def _unit(self, context: DriverContext) -> str:
        return f"{self.resource_id(context)}.service"

    def _systemctl(self) -> str:
        # Resolved and ownership-checked at config load, exactly like
        # `executable`; probe and teardown need a second trusted binary.
        return (
            self.definition.option("systemctl_path", "/usr/bin/systemctl") or "/usr/bin/systemctl"
        )

    def setup(self, context: DriverContext, runner: CommandRunner) -> dict[str, Any]:
        if self.definition.executable is None:
            raise DriverError("invalid_config", "namespace runtime driver executable is missing")
        payload = self.definition.option("payload")
        if not payload:
            raise DriverError(
                "invalid_config",
                f"driver {self.definition.name!r} needs a payload to run inside the runtime",
            )
        argv = [
            str(self.definition.executable),
            "--user",
            f"--unit={self.resource_id(context)}",
            "--property=KillMode=control-group",
            "--property=UMask=0077",
            "--working-directory=/",
        ]
        for option_name, property_name in self._QUOTA_PROPERTIES:
            value = self.definition.option(option_name)
            if value:
                argv.append(f"--property={property_name}={value}")
        read_only = self._read_only_paths()
        disk_max = self.definition.option("disk_max", self._DEFAULT_DISK_MAX)

        # Environment is copied explicitly into the service. systemd-run is a
        # client of the user manager; its own env/FD table is not the service's
        # env/FD table. Paths are translated to the sandbox mounts, and runtime
        # pool values (for example APP_PORT) remain available to the payload.
        service_env = dict(context.environment)
        service_env.update(self._env(context))
        service_env["ACP_WORKTREE"] = "/workspace"
        service_env["ACP_REPO_ROOT"] = "/workspace"
        service_env["ACP_RUNTIME_DIR"] = "/work"
        service_env["HOME"] = "/work"
        service_env["TMPDIR"] = "/tmp"
        for index, _path in enumerate(read_only):
            service_env[f"ACP_READ_ONLY_{index}"] = f"/readonly/{index}"
        for name, value in sorted(service_env.items()):
            if re.fullmatch(r"[A-Z_][A-Z0-9_]*", name):
                argv.append(f"--setenv={name}={value}")

        # PrivateNetwork= is privileged for user units. A user namespace gives
        # this wrapper CAP_SYS_ADMIN only long enough to build its private mount,
        # PID and optional network namespaces. The payload is exec'd after every
        # capability is removed, so it cannot undo those mounts.
        argv.extend(
            [
                self._unshare(),
                "--user",
                "--map-root-user",
                "--mount",
                "--pid",
                "--fork",
            ]
        )
        if self._egress_denied():
            argv.append("--net")
        argv.append("--")

        with self._scoped_credential(context) as (cred_env, material):
            del cred_env
            if material is not None:
                argv.insert(
                    argv.index(self._unshare()),
                    f"--property=LoadCredential=acp-runtime:/proc/{os.getpid()}/fd/{material.fd}",
                )
            return self._launch(
                argv,
                payload,
                read_only,
                disk_max or self._DEFAULT_DISK_MAX,
                context,
                runner,
                self._env(context),
                material,
            )

    # -- credential policy -------------------------------------------------
    @contextmanager
    def _scoped_credential(self, context: DriverContext) -> Any:
        """Deny by default: a runtime sees ONLY the credential its definition names.

        The whole point of a containment backend is that the contained thing gets
        what it was granted and nothing else, so "no credential named" must mean
        no credential — not "inherits whatever the supervisor has". That direction
        is already half-held by run_trusted, which forwards only ACP_*/known-
        sensitive names and explicitly drops ACP_RUNNER_CREDENTIAL (the
        supervisor's own); this closes the other half by never introducing one
        unless asked.

        When one IS named it is materialized as an anonymous descriptor. The
        systemd user manager copies that descriptor with LoadCredential= during
        activation; the service then bind-mounts only that file into its private
        tmpfs. This bridge is required because descriptors and client env do not
        cross the systemd-run manager boundary.
        """
        handle = self.credential_handle(context)
        if handle is None:
            yield {}, None
            return
        if context.credential_registry is None:
            raise DriverError(
                "credential_unavailable",
                f"driver {self.definition.name!r} names a credential but no registry was provided",
            )
        try:
            with context.credential_registry.materialize(handle, context.runtime_dir) as material:
                yield {}, material
        except CredentialError as error:
            raise DriverError(error.code, error.message) from error

    def _launch(
        self,
        argv: list[str],
        payload: str,
        read_only: list[str],
        disk_max: str,
        context: DriverContext,
        runner: CommandRunner,
        env: dict[str, str],
        material: CredentialMaterial | None,
    ) -> dict[str, Any]:
        worktree = str(context.environment.get("ACP_WORKTREE", ""))
        if not worktree:
            raise DriverError("invalid_runtime", "namespace runtime worktree is missing")
        mount = shlex.quote(self._mount())
        root = "/tmp/acp-root"
        prelude = [
            "set -eu",
            f"{mount} --make-rprivate /",
            # Build a new root instead of trying to sanitize the host root.
            # NAS hosts contain overlay/nsfs/Btrfs mounts that an unprivileged
            # user namespace cannot self-remount. A private root exposes only
            # enumerated read-only system trees and no host /home, /run, /var,
            # Docker mounts or NAS volumes at all.
            f"{mount} -t tmpfs -o size={disk_max},mode=0700 tmpfs /tmp",
            (
                f"mkdir -p {root}/usr {root}/bin {root}/sbin {root}/lib "
                f"{root}/lib64 {root}/etc {root}/dev {root}/proc {root}/sys "
                f"{root}/workspace {root}/work {root}/tmp {root}/readonly "
                f"{root}/home {root}/root {root}/run {root}/var"
            ),
            f"chmod 0700 {root}/work && chmod 1777 {root}/tmp",
            (
                "for acp_path in /usr /bin /sbin /lib /lib64 /etc; do "
                'if [ -e "$acp_path" ]; then '
                f'{mount} --bind "$acp_path" "{root}$acp_path"; '
                f'{mount} -o remount,bind,ro "{root}$acp_path"; '
                "fi; done"
            ),
            f"mkdir -p {root}/dev/shm {root}/dev/pts",
            (
                "for acp_dev in null zero random urandom tty; do "
                f': > "{root}/dev/$acp_dev"; '
                f'{mount} --bind "/dev/$acp_dev" "{root}/dev/$acp_dev"; '
                f'{mount} -o remount,bind,ro "{root}/dev/$acp_dev"; '
                "done"
            ),
            f"ln -s /proc/self/fd {root}/dev/fd",
            f"ln -s /proc/self/fd/0 {root}/dev/stdin",
            f"ln -s /proc/self/fd/1 {root}/dev/stdout",
            f"ln -s /proc/self/fd/2 {root}/dev/stderr",
            f"{mount} --bind {shlex.quote(worktree)} {root}/workspace",
            f"{mount} -o remount,bind,ro {root}/workspace",
        ]
        for index, path in enumerate(read_only):
            target = f"{root}/readonly/{index}"
            prelude.extend(
                [
                    f"mkdir -p {target}",
                    f"{mount} --bind {shlex.quote(path)} {target}",
                    f"{mount} -o remount,bind,ro {target}",
                ]
            )
        if material is not None:
            prelude.extend(
                [
                    f": > {root}/credential",
                    (f'{mount} --bind "$CREDENTIALS_DIRECTORY/acp-runtime" {root}/credential'),
                    f"{mount} -o remount,bind,ro {root}/credential",
                    "export ACP_RUNTIME_CREDENTIAL=/credential",
                    "unset CREDENTIALS_DIRECTORY",
                ]
            )
        prelude.extend(
            [
                f"{mount} -t proc -o ro,nosuid,nodev,noexec proc {root}/proc",
                (
                    f"exec {shlex.quote(self._chroot())} {root} "
                    f"{shlex.quote(self._setpriv())} "
                    "--no-new-privs --bounding-set=-all --inh-caps=-all "
                    "--ambient-caps=-all -- /bin/sh -c "
                    f"{shlex.quote('cd /work && exec /bin/sh -c ' + shlex.quote(payload))}"
                ),
            ]
        )
        # Newlines matter: placing a compound `for` before `&&` disables
        # POSIX `set -e` inside that loop, which would let a failed read-only
        # bind continue into the payload. Each setup command must fail closed.
        argv.extend([self._shell(), "-c", "\n".join(prelude)])
        return runner(argv, context.runtime_dir, env, self._timeout(), material)

    def probe(self, context: DriverContext, runner: CommandRunner) -> tuple[bool, dict[str, Any]]:
        # Addressed by unit name only, so the proof cannot be steered by
        # candidate content. Absence of the unit is what teardown must prove.
        argv = [
            self._systemctl(),
            "--user",
            "show",
            self._unit(context),
            "--property=LoadState",
            "--property=ActiveState",
            "--property=Result",
            "--property=ExecMainStatus",
            "--property=TasksMax",
            "--property=MemoryMax",
            "--property=MemoryCurrent",
        ]
        result = runner(
            argv,
            context.runtime_dir,
            self._env(context) | {"LC_ALL": "C"},
            self._timeout(),
            None,
        )
        load_state = self._show_value(result.get("stdout", ""), "LoadState")
        stderr = str(result.get("stderr", ""))
        missing = load_state == "not-found" or (
            result.get("exit_code", 0) != 0
            and self._unit(context).casefold() in stderr.casefold()
            and ("not found" in stderr.casefold() or "could not be found" in stderr.casefold())
        )
        if missing:
            # A transient unit is normally garbage-collected after stop and
            # reset-failed. systemctl versions differ: some report
            # LoadState=not-found, while others return non-zero with a
            # unit-specific not-found diagnostic. Both are positive absence
            # proof because the trusted query names only this owned unit.
            result = {
                **result,
                "original_exit_code": result.get("exit_code", 0),
                "exit_code": 0,
                "absence_proved_by": "systemd-unit-not-found",
            }
        state = self._show_value(result.get("stdout", ""), "ActiveState")
        present = state in {"active", "activating", "deactivating", "reloading"}
        finding = self._quota_finding(result.get("stdout", ""))
        if finding:
            result = {**result, "quota_violation": finding}
        memory_current = self._show_value(result.get("stdout", ""), "MemoryCurrent")
        result = {
            **result,
            # The writable tmpfs exists only inside the unit's mount namespace.
            # Reporting the old host staging directory as its usage was false
            # evidence, so probe states the accounting boundary explicitly.
            "writable_layer_bytes": None,
            "writable_layer_accounting": "kernel-enforced-tmpfs-cap",
            "memory_current_bytes": int(memory_current) if memory_current.isdigit() else None,
        }
        return present, result

    def teardown(self, context: DriverContext, runner: CommandRunner) -> dict[str, Any]:
        stop = runner(
            [self._systemctl(), "--user", "stop", self._unit(context)],
            context.runtime_dir,
            self._env(context),
            self._timeout(),
            None,
        )
        # A unit that failed its quota lingers in `failed` and would keep the
        # name; clearing it is what makes teardown idempotent and the next
        # attempt's setup possible. Its exit code is deliberately not fatal —
        # absence, proved by probe, is the cleanup criterion, not this call.
        reset = runner(
            [self._systemctl(), "--user", "reset-failed", self._unit(context)],
            context.runtime_dir,
            self._env(context),
            self._timeout(),
            None,
        )
        return {**stop, "reset_failed": {"exit_code": reset.get("exit_code")}}

    # -- helpers -----------------------------------------------------------
    def _read_only_paths(self) -> list[str]:
        raw = self.definition.option("read_only_paths", "") or ""
        return [item for item in (part.strip() for part in raw.split(",")) if item]

    def _egress_denied(self) -> bool:
        return (self.definition.option("egress", "deny") or "deny").lower() == "deny"

    def _unshare(self) -> str:
        return self.definition.option("unshare_path", "/usr/bin/unshare") or "/usr/bin/unshare"

    def _shell(self) -> str:
        # Only used to run the read-only bind prelude before exec'ing the
        # payload; trusted-resolved at config load like every other binary here.
        return self.definition.option("shell_path", "/bin/sh") or "/bin/sh"

    def _setpriv(self) -> str:
        return self.definition.option("setpriv_path", "/usr/bin/setpriv") or "/usr/bin/setpriv"

    def _mount(self) -> str:
        return self.definition.option("mount_path", "/usr/bin/mount") or "/usr/bin/mount"

    def _chroot(self) -> str:
        return self.definition.option("chroot_path", "/usr/sbin/chroot") or "/usr/sbin/chroot"

    @staticmethod
    def _show_value(stdout: str, key: str) -> str:
        for line in stdout.splitlines():
            name, separator, value = line.partition("=")
            if separator and name.strip() == key:
                return value.strip()
        return ""

    def _quota_finding(self, stdout: str) -> dict[str, Any] | None:
        """Structured finding for a quota kill, so a violation is never silent."""
        result = self._show_value(stdout, "Result")
        status = self._show_value(stdout, "ExecMainStatus")
        if result in {"oom-kill", "timeout", "exit-code", "signal"} and result != "success":
            return {
                "result": result,
                "exec_main_status": status,
                # 137 = 128+SIGKILL, what a MemoryMax kill reports.
                "reason": {
                    "oom-kill": "memory quota exceeded",
                    "timeout": "wall-clock quota exceeded",
                }.get(result, "runtime terminated abnormally"),
            }
        return None

    def _timeout(self) -> int:
        return int(
            self.definition.option("timeout_seconds", str(DEFAULT_PHASE_TIMEOUT_SECONDS))
            or DEFAULT_PHASE_TIMEOUT_SECONDS
        )


_ADAPTERS: dict[str, type[ResourceDriver]] = {
    DockerComposeDriver.kind: DockerComposeDriver,
    PostgresSchemaDriver.kind: PostgresSchemaDriver,
    BrowserProfileDriver.kind: BrowserProfileDriver,
    NamespaceRuntimeDriver.kind: NamespaceRuntimeDriver,
}


def build_driver(definition: DriverDefinition) -> ResourceDriver:
    adapter = _ADAPTERS.get(definition.kind)
    if adapter is None:
        raise DriverError(
            "invalid_config",
            f"unknown driver kind {definition.kind!r}; expected one of {', '.join(DRIVER_KINDS)}",
        )
    if adapter is not BrowserProfileDriver and definition.executable is None:
        raise DriverError(
            "invalid_config",
            f"driver {definition.name!r} of kind {definition.kind} requires an executable",
        )
    return adapter(definition)


def parse_driver_definitions(
    entries: Sequence[Mapping[str, Any]],
    repo_root: Path,
    credential_names: set[str] | None = None,
    expected_owners: set[int] | None = None,
) -> tuple[DriverDefinition, ...]:
    """Validate ``[[runtime.drivers]]`` entries at configuration load."""

    definitions: list[DriverDefinition] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        name = str(entry.get("name") or "").strip()
        if not name:
            raise DriverError("invalid_config", f"runtime driver #{index} needs a name")
        if name in seen:
            raise DriverError("invalid_config", f"duplicate runtime driver name {name!r}")
        seen.add(name)
        kind = str(entry.get("kind") or "").strip()
        if kind not in DRIVER_KINDS:
            raise DriverError(
                "invalid_config",
                f"runtime driver {name!r} has unknown kind {kind!r}",
            )
        raw_executable = entry.get("executable")
        executable: Path | None = None
        if kind != BrowserProfileDriver.kind:
            executable = resolve_trusted_executable(
                str(raw_executable or ""), repo_root, expected_owners
            )
        elif raw_executable:
            raise DriverError(
                "invalid_config",
                f"driver {name!r} of kind browser_profile must not name an executable",
            )
        options = {
            str(key): str(value)
            for key, value in entry.items()
            if key not in {"name", "kind", "executable"}
        }
        if kind == NamespaceRuntimeDriver.kind:
            if not options.get("payload", "").strip():
                raise DriverError(
                    "invalid_config",
                    f"namespace runtime driver {name!r} requires a payload",
                )
            egress = options.get("egress", "deny").strip().lower() or "deny"
            if egress not in {"deny", "allow"}:
                raise DriverError(
                    "invalid_config",
                    f"namespace runtime driver {name!r} egress must be 'deny' or 'allow'",
                )
            options["egress"] = egress
            disk_max = options.get("disk_max", NamespaceRuntimeDriver._DEFAULT_DISK_MAX).strip()
            if not re.fullmatch(r"[1-9][0-9]{0,8}[KMG]", disk_max, re.IGNORECASE):
                raise DriverError(
                    "invalid_config",
                    f"namespace runtime driver {name!r} disk_max must be a positive K/M/G size",
                )
            options["disk_max"] = disk_max.upper()
            read_only = options.get("read_only_paths", "")
            for raw_path in (part.strip() for part in read_only.split(",")):
                if raw_path and not Path(raw_path).is_absolute():
                    raise DriverError(
                        "invalid_config",
                        f"namespace runtime driver {name!r} read_only_paths must be absolute",
                    )
            # probe/teardown and the egress wrapper each exec a SECOND binary.
            # Validating only `executable` would leave those three unchecked,
            # which is the whole trust boundary this module exists to hold, so
            # they get the identical ownership and writability treatment.
            # Checked last: the cheap config faults above should not depend on
            # a systemd binary being present to be reported.
            for option_name, default in (
                ("systemctl_path", "/usr/bin/systemctl"),
                ("unshare_path", "/usr/bin/unshare"),
                ("shell_path", "/bin/sh"),
                ("setpriv_path", "/usr/bin/setpriv"),
                ("mount_path", "/usr/bin/mount"),
                ("chroot_path", "/usr/sbin/chroot"),
            ):
                candidate = options.get(option_name, "").strip() or default
                resolve_trusted_executable(candidate, repo_root, expected_owners)
                options[option_name] = candidate

        if kind == PostgresSchemaDriver.kind:
            if options.get("dsn") or options.get("dsn_env"):
                raise DriverError(
                    "invalid_config",
                    "postgres driver requires a credential handle; DSNs and dsn_env are forbidden",
                )
            credential = options.get("credential", "").strip()
            if not credential:
                raise DriverError(
                    "invalid_config", "postgres driver requires a credential reference"
                )
            if credential_names is not None and credential not in credential_names:
                raise DriverError(
                    "invalid_config",
                    f"postgres driver references unknown credential {credential!r}",
                )
            for required in ("host", "database", "user"):
                if not options.get(required, "").strip():
                    raise DriverError(
                        "invalid_config", f"postgres driver requires a {required} target"
                    )
            database = options["database"]
            user = options["user"]
            host = options["host"]
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,62}", database):
                raise DriverError(
                    "invalid_config",
                    "postgres database must be a plain name, not URI or conninfo",
                )
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,62}", user):
                raise DriverError("invalid_config", "postgres user must be a plain role name")
            if (
                not re.fullmatch(r"[A-Za-z0-9._:/-]{1,255}", host)
                or "://" in host
                or host.startswith("-")
            ):
                raise DriverError("invalid_config", "postgres host is not a safe plain target")
            port = options.get("port", "5432")
            if not port.isdigit() or not 1 <= int(port) <= 65535:
                raise DriverError("invalid_config", "postgres driver port must be 1..65535")
            options["port"] = port
        definitions.append(
            DriverDefinition(name=name, kind=kind, executable=executable, options=options)
        )
    return tuple(definitions)
