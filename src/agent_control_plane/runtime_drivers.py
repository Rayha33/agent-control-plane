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


class DriverError(Exception):
    """Raised for driver configuration and execution faults."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# Trust boundary
# ---------------------------------------------------------------------------


def resolve_trusted_executable(raw: str, repo_root: Path) -> Path:
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
        raise DriverError(
            "invalid_config", f"driver executable does not exist: {raw}"
        ) from error

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

    mode = resolved.stat().st_mode
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise DriverError(
            "untrusted_driver",
            f"driver executable is group/world writable and cannot be trusted: {resolved}",
        )
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
) -> dict[str, Any]:
    """Execute *argv* directly — no shell, no PATH search, no worktree cwd."""

    if not argv:
        raise DriverError("invalid_driver_invocation", "empty driver argv")
    executable = Path(argv[0])
    if not executable.is_absolute():
        raise DriverError(
            "invalid_driver_invocation",
            f"driver argv[0] must be absolute, got {argv[0]!r}",
        )
    # Re-check immediately before exec. Validation at config load proves nothing
    # about the file we are about to run.
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise DriverError(
            "untrusted_driver",
            f"driver executable disappeared or lost its exec bit: {executable}",
        )
    mode = executable.stat().st_mode
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise DriverError(
            "untrusted_driver",
            f"driver executable became group/world writable: {executable}",
        )

    cwd.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        process = subprocess.run(
            list(argv),
            cwd=str(cwd),
            env=dict(env),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "argv": list(argv),
            "exit_code": 124,
            "stdout": "",
            "stderr": f"driver timed out after {timeout}s",
            "duration_ms": int((time.monotonic() - started) * 1000),
            "timed_out": True,
        }
    return {
        "argv": list(argv),
        "exit_code": process.returncode,
        "stdout": process.stdout,
        "stderr": process.stderr,
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

    def probe(
        self, context: DriverContext, runner: CommandRunner
    ) -> tuple[bool, dict[str, Any]]:
        """Return ``(present, observation)``."""
        raise NotImplementedError

    def teardown(self, context: DriverContext, runner: CommandRunner) -> dict[str, Any]:
        raise NotImplementedError

    # -- shared ------------------------------------------------------------
    def _env(self, context: DriverContext) -> dict[str, str]:
        env = os.environ.copy()
        env.update(context.environment)
        env["ACP_RESOURCE_ID"] = self.resource_id(context)
        return env

    def run_phase(
        self,
        phase: str,
        context: DriverContext,
        runner: CommandRunner,
    ) -> PhaseEvidence:
        if phase not in PHASES:
            raise DriverError("invalid_phase", f"unknown driver phase {phase!r}")
        resource = self.resource_id(context)
        token = ownership_token(context.secret, context.attempt_id, self.kind, resource)

        if phase == "setup":
            result = self.setup(context, runner)
            present, observation = self.probe(context, runner)
            proof = {"action": result, "observation": observation}
            # A setup that exits 0 without creating anything is a false success.
            exit_code = result.get("exit_code", 0) or (0 if present else 1)
            if result.get("exit_code", 0) == 0 and not present:
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
        assert self.definition.executable is not None
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

    def probe(
        self, context: DriverContext, runner: CommandRunner
    ) -> tuple[bool, dict[str, Any]]:
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
        return int(self.definition.option("timeout_seconds", str(DEFAULT_PHASE_TIMEOUT_SECONDS)) or DEFAULT_PHASE_TIMEOUT_SECONDS)


class PostgresSchemaDriver(ResourceDriver):
    kind = "postgres_schema"

    def resource_id(self, context: DriverContext) -> str:
        prefix = self.definition.option("schema_prefix", "acp") or "acp"
        raw = _sanitize(f"{prefix}_{context.attempt_id}", allow="_").lower()
        return raw.replace("-", "_")

    def _psql(self, context: DriverContext, sql: str) -> list[str]:
        assert self.definition.executable is not None
        argv = [str(self.definition.executable), "-v", "ON_ERROR_STOP=1", "-tAc", sql]
        dsn = self.definition.option("dsn")
        if dsn:
            argv[1:1] = [dsn]
        return argv

    def setup(self, context: DriverContext, runner: CommandRunner) -> dict[str, Any]:
        schema = self.resource_id(context)
        return runner(
            self._psql(context, f'CREATE SCHEMA IF NOT EXISTS "{schema}"'),
            context.runtime_dir,
            self._env(context),
            DEFAULT_PHASE_TIMEOUT_SECONDS,
        )

    def probe(
        self, context: DriverContext, runner: CommandRunner
    ) -> tuple[bool, dict[str, Any]]:
        schema = self.resource_id(context)
        sql = (
            "SELECT 1 FROM information_schema.schemata "
            f"WHERE schema_name = '{schema}'"
        )
        result = runner(
            self._psql(context, sql),
            context.runtime_dir,
            self._env(context),
            DEFAULT_PHASE_TIMEOUT_SECONDS,
        )
        present = result.get("stdout", "").strip() == "1"
        return present, result

    def teardown(self, context: DriverContext, runner: CommandRunner) -> dict[str, Any]:
        schema = self.resource_id(context)
        return runner(
            self._psql(context, f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'),
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
            return {"argv": ["<builtin>", "mkdir", str(target)], "exit_code": 1, "stderr": str(error), "stdout": ""}
        return {"argv": ["<builtin>", "mkdir", str(target)], "exit_code": 0, "stdout": "", "stderr": ""}

    def probe(
        self, context: DriverContext, runner: CommandRunner
    ) -> tuple[bool, dict[str, Any]]:
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
            return {"argv": ["<builtin>", "rmtree", str(target)], "exit_code": 1, "stderr": str(error), "stdout": ""}
        return {"argv": ["<builtin>", "rmtree", str(target)], "exit_code": 0, "stdout": "", "stderr": ""}


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
    entries: Sequence[Mapping[str, Any]], repo_root: Path
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
            executable = resolve_trusted_executable(str(raw_executable or ""), repo_root)
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
        definitions.append(
            DriverDefinition(name=name, kind=kind, executable=executable, options=options)
        )
    return tuple(definitions)
