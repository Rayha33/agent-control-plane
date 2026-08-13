"""Trusted, phase-scoped runtime drivers with cleanup proofs.

Shell lifecycle hooks are flexible but they cannot *prove* that a database
schema, Compose project or browser profile was actually deleted, and because
they run as ``/bin/sh -lc`` with the candidate's worktree as the working
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
import shutil
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

PHASES: tuple[str, ...] = ("setup", "verify", "teardown")
DRIVER_KINDS: tuple[str, ...] = (
    "docker_compose",
    "postgres_schema",
    "browser_profile",
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


CommandRunner = Callable[[Sequence[str], Path, Mapping[str, str], int], dict[str, Any]]


def run_trusted(
    argv: Sequence[str],
    cwd: Path,
    env: Mapping[str, str],
    timeout: int = DEFAULT_PHASE_TIMEOUT_SECONDS,
    *,
    expected_owners: set[int] | None = None,
) -> dict[str, Any]:
    """Execute *argv* directly — no shell, no PATH search, no worktree cwd."""

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
        process = subprocess.run(
            execution_argv,
            **(
                {
                    "executable": str(descriptor_root / str(executable_fd)),
                    "pass_fds": (executable_fd,),
                }
                if descriptor_execution
                else {}
            ),
            cwd=str(cwd),
            env=safe_env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
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
        return runner(argv, context.runtime_dir, self._env(context), self._timeout())

    def probe(self, context: DriverContext, runner: CommandRunner) -> tuple[bool, dict[str, Any]]:
        # Addressed by project name only — no compose file, so the proof cannot
        # be steered by candidate content.
        argv = [*self._base(context), "ps", "--all", "--quiet"]
        result = runner(argv, context.runtime_dir, self._env(context), self._timeout())
        present = bool(result.get("stdout", "").strip())
        return present, result

    def teardown(self, context: DriverContext, runner: CommandRunner) -> dict[str, Any]:
        argv = [*self._base(context), "down", "--volumes", "--remove-orphans"]
        return runner(argv, context.runtime_dir, self._env(context), self._timeout())

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
        argv = [str(self.definition.executable)]
        argv.extend(["-v", "ON_ERROR_STOP=1"])
        for name, value in sorted((variables or {}).items()):
            argv.extend(["--set", f"{name}={value}"])
        argv.extend(["-tAc", sql])
        return argv

    def _dsn(self) -> str | None:
        dsn = self.definition.option("dsn")
        dsn_env = self.definition.option("dsn_env")
        if dsn and dsn_env:
            raise DriverError(
                "invalid_config", "postgres driver accepts only one of dsn or dsn_env"
            )
        if dsn_env:
            if not dsn_env.isidentifier() or dsn_env not in os.environ:
                raise DriverError(
                    "invalid_config", f"postgres credential environment is unavailable: {dsn_env}"
                )
            dsn = os.environ[dsn_env]
        return dsn

    def ownership_identity(self, context: DriverContext) -> str:
        dsn = self._dsn()
        if not dsn:
            raise DriverError("invalid_config", "postgres credential target is unavailable")
        # The DSN never leaves this HMAC input. The stored token binds cleanup
        # to the exact database target without disclosing or guessably hashing it.
        return f"{self.resource_id(context)}\x00{dsn}"

    def _env(self, context: DriverContext) -> dict[str, str]:
        env = super()._env(context)
        dsn = self._dsn()
        if dsn:
            # libpq accepts a URI or keyword connection string in PGDATABASE.
            # Keeping it out of argv prevents process-list and evidence leaks.
            env["PGDATABASE"] = dsn
        return env

    def setup(self, context: DriverContext, runner: CommandRunner) -> dict[str, Any]:
        schema = self.resource_id(context)
        return runner(
            self._psql(
                context,
                'CREATE SCHEMA IF NOT EXISTS :"schema"',
                {"schema": schema},
            ),
            context.runtime_dir,
            self._env(context),
            DEFAULT_PHASE_TIMEOUT_SECONDS,
        )

    def probe(self, context: DriverContext, runner: CommandRunner) -> tuple[bool, dict[str, Any]]:
        schema = self.resource_id(context)
        result = runner(
            self._psql(
                context,
                "SELECT 1 FROM information_schema.schemata WHERE schema_name = :'schema'",
                {"schema": schema},
            ),
            context.runtime_dir,
            self._env(context),
            DEFAULT_PHASE_TIMEOUT_SECONDS,
        )
        present = result.get("stdout", "").strip() == "1"
        return present, result

    def teardown(self, context: DriverContext, runner: CommandRunner) -> dict[str, Any]:
        schema = self.resource_id(context)
        return runner(
            self._psql(
                context,
                'DROP SCHEMA IF EXISTS :"schema" CASCADE',
                {"schema": schema},
            ),
            context.runtime_dir,
            self._env(context),
            DEFAULT_PHASE_TIMEOUT_SECONDS,
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


_ADAPTERS: dict[str, type[ResourceDriver]] = {
    DockerComposeDriver.kind: DockerComposeDriver,
    PostgresSchemaDriver.kind: PostgresSchemaDriver,
    BrowserProfileDriver.kind: BrowserProfileDriver,
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
        if kind == PostgresSchemaDriver.kind:
            if options.get("dsn"):
                raise DriverError(
                    "invalid_config",
                    "postgres driver requires dsn_env; literal DSNs are forbidden",
                )
            if not options.get("dsn_env"):
                raise DriverError(
                    "invalid_config", "postgres driver requires a dsn_env credential reference"
                )
        definitions.append(
            DriverDefinition(name=name, kind=kind, executable=executable, options=options)
        )
    return tuple(definitions)
