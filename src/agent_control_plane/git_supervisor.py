from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import tomllib
import unicodedata
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from .runner_identity import (
    IdentityError,
    assert_distinct,
    credential_digest,
    issue_credential,
    validate_role,
    verify_credential,
)
from .runtime_drivers import (
    DriverContext,
    DriverDefinition,
    DriverError,
    PhaseEvidence,
    build_driver,
    parse_driver_definitions,
    run_trusted,
)

GENESIS_HASH = "0" * 64


class SupervisorError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class RuntimePortPool:
    env_name: str
    start: int
    end: int


@dataclass(frozen=True)
class Config:
    lease_seconds: int
    timeout_seconds: int
    qc_commands: tuple[str, ...]
    integration_commands: tuple[str, ...]
    critic_command: str
    critic_identity: str
    require_critic: bool
    runtime_setup_commands: tuple[str, ...]
    runtime_teardown_commands: tuple[str, ...]
    runtime_port_pools: tuple[RuntimePortPool, ...]
    runtime_drivers: tuple[DriverDefinition, ...]


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  acceptance_json TEXT NOT NULL,
  resources_json TEXT NOT NULL,
  dependencies_json TEXT NOT NULL,
  base_branch TEXT NOT NULL,
  base_sha TEXT NOT NULL,
  priority INTEGER NOT NULL,
  status TEXT NOT NULL,
  current_attempt_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attempts (
  id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES tasks(id),
  number INTEGER NOT NULL,
  agent_id TEXT NOT NULL,
  branch TEXT NOT NULL,
  worktree TEXT NOT NULL,
  claim_token INTEGER NOT NULL,
  start_sha TEXT NOT NULL,
  latest_sha TEXT,
  checkpoint_json TEXT NOT NULL,
  pid INTEGER,
  log_path TEXT,
  status TEXT NOT NULL,
  lease_expires_at INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(task_id, number)
);
CREATE TABLE IF NOT EXISTS resource_leases (
  resource TEXT PRIMARY KEY,
  task_id TEXT,
  attempt_id TEXT,
  fencing_token INTEGER NOT NULL,
  lease_expires_at INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS submissions (
  id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES tasks(id),
  attempt_id TEXT NOT NULL REFERENCES attempts(id),
  worker_agent_id TEXT NOT NULL,
  commit_sha TEXT NOT NULL,
  tree_sha TEXT NOT NULL,
  patch_sha256 TEXT NOT NULL,
  changed_paths_json TEXT NOT NULL,
  resource_tokens_json TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS qc_runs (
  id TEXT PRIMARY KEY,
  submission_id TEXT NOT NULL REFERENCES submissions(id),
  reviewer_id TEXT NOT NULL,
  commit_sha TEXT NOT NULL,
  verdict TEXT NOT NULL,
  findings_json TEXT NOT NULL,
  results_json TEXT NOT NULL,
  packet_sha256 TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS integrations (
  id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES tasks(id),
  submission_id TEXT NOT NULL REFERENCES submissions(id),
  branch TEXT,
  commit_sha TEXT,
  verdict TEXT NOT NULL,
  results_json TEXT NOT NULL,
  error TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runtime_environments (
  attempt_id TEXT PRIMARY KEY REFERENCES attempts(id),
  state TEXT NOT NULL,
  env_json TEXT NOT NULL,
  setup_results_json TEXT NOT NULL,
  teardown_results_json TEXT NOT NULL,
  log_path TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runner_identities (
  agent_id TEXT PRIMARY KEY,
  role TEXT NOT NULL,
  credential_digest TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS runtime_driver_resources (
  attempt_id TEXT NOT NULL REFERENCES attempts(id),
  driver TEXT NOT NULL,
  kind TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  ownership_token TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  state TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(attempt_id, driver)
);
CREATE TABLE IF NOT EXISTS runtime_allocations (
  pool_name TEXT NOT NULL,
  value INTEGER NOT NULL,
  attempt_id TEXT NOT NULL REFERENCES attempts(id),
  lease_expires_at INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(pool_name, value)
);
CREATE TABLE IF NOT EXISTS events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  event_type TEXT NOT NULL,
  actor TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  previous_hash TEXT NOT NULL,
  event_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status, priority DESC);
CREATE INDEX IF NOT EXISTS idx_attempts_task ON attempts(task_id, number DESC);
CREATE INDEX IF NOT EXISTS idx_submissions_task ON submissions(task_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_runtime_allocations_attempt
  ON runtime_allocations(attempt_id);
"""


class GitSupervisor:
    def __init__(self, repo: str | Path = "."):
        self.root = self._root(Path(repo).resolve())
        self.config_path = self.root / "acp.toml"
        self.state_dir = self.root / ".acp"
        self.db_path = self.state_dir / "control.db"
        if not self.config_path.exists():
            raise SupervisorError("not_initialized", "acp.toml is missing; run acp init")
        self.config = self._load_config()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        (self.state_dir / "worktrees").mkdir(exist_ok=True)
        (self.state_dir / "logs").mkdir(exist_ok=True)
        (self.state_dir / "runtime").mkdir(exist_ok=True)
        with self.connect() as connection:
            connection.executescript(SCHEMA)
            connection.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('claim_counter', '0')"
            )

    @classmethod
    def initialize(cls, repo: str | Path = ".") -> GitSupervisor:
        root = cls._root(Path(repo).resolve())
        config = root / "acp.toml"
        if not config.exists():
            config.write_text(
                "[supervisor]\n"
                "lease_seconds = 300\n"
                "qc_timeout_seconds = 900\n"
                'critic_identity = "independent-qc"\n'
                "require_critic = true\n\n"
                "[qc]\n"
                'commands = ["python -m pytest -q"]\n'
                'critic_command = "builtin"\n\n'
                "[integration]\n"
                'commands = ["python -m pytest -q"]\n\n'
                "[runtime]\n"
                "setup_commands = []\n"
                "teardown_commands = []\n",
                encoding="utf-8",
            )
        ignore = root / ".gitignore"
        old = ignore.read_text(encoding="utf-8") if ignore.exists() else ""
        if ".acp/" not in {line.strip() for line in old.splitlines()}:
            joiner = "" if not old or old.endswith("\n") else "\n"
            ignore.write_text(f"{old}{joiner}.acp/\n", encoding="utf-8")
        return cls(root)

    @staticmethod
    def _root(candidate: Path) -> Path:
        result = subprocess.run(
            ["git", "-C", str(candidate), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            raise SupervisorError(
                "not_git_repository", result.stderr.strip() or "not a Git repository"
            )
        return Path(result.stdout.strip()).resolve()

    def _load_config(self) -> Config:
        with self.config_path.open("rb") as handle:
            raw = tomllib.load(handle)
        supervisor = raw.get("supervisor", {})
        qc = raw.get("qc", {})
        integration = raw.get("integration", {})
        runtime = raw.get("runtime", {})
        lease = int(supervisor.get("lease_seconds", 300))
        timeout = int(supervisor.get("qc_timeout_seconds", 900))
        if lease < 10 or timeout < 1:
            raise SupervisorError("invalid_config", "lease must be >= 10 and timeout >= 1")
        qc_commands = tuple(map(str, qc.get("commands", [])))
        integration_commands = tuple(map(str, integration.get("commands", qc.get("commands", []))))
        critic_command = str(qc.get("critic_command", "")).strip()
        require_critic = bool(supervisor.get("require_critic", False))
        if not qc_commands or any(not command.strip() for command in qc_commands):
            raise SupervisorError(
                "invalid_config",
                "every deterministic QC gate must contain a command",
            )
        if not integration_commands or any(not command.strip() for command in integration_commands):
            raise SupervisorError("invalid_config", "every integration gate must contain a command")
        if require_critic and not critic_command:
            raise SupervisorError(
                "invalid_config", "require_critic needs a non-empty critic_command"
            )
        if critic_command and critic_command != "builtin":
            critic_path = Path(critic_command).expanduser()
            if not critic_path.is_absolute():
                raise SupervisorError(
                    "invalid_config",
                    "external critic_command must be one absolute executable path",
                )
            try:
                critic_path = critic_path.resolve(strict=True)
            except FileNotFoundError as error:
                raise SupervisorError(
                    "invalid_config", "external critic executable does not exist"
                ) from error
            try:
                critic_path.relative_to(self.root)
            except ValueError:
                pass
            else:
                raise SupervisorError(
                    "invalid_config",
                    "external critic executable must be outside the repository",
                )
            if not critic_path.is_file() or not os.access(critic_path, os.X_OK):
                raise SupervisorError(
                    "invalid_config",
                    "external critic_command must name an executable file",
                )
            critic_command = str(critic_path)
        runtime_setup_commands = tuple(map(str, runtime.get("setup_commands", [])))
        runtime_teardown_commands = tuple(map(str, runtime.get("teardown_commands", [])))
        # Drivers are validated here, against the supervisor's OWN acp.toml at the
        # repository root — never a copy inside a candidate worktree.
        raw_drivers = runtime.get("drivers", [])
        if not isinstance(raw_drivers, list):
            raise SupervisorError(
                "invalid_config", "runtime.drivers must be an array of tables"
            )
        try:
            runtime_drivers = parse_driver_definitions(raw_drivers, self.root)
        except DriverError as error:
            raise SupervisorError(error.code, error.message) from error
        for label, commands in (
            ("runtime setup", runtime_setup_commands),
            ("runtime teardown", runtime_teardown_commands),
        ):
            if any(not command.strip() for command in commands):
                raise SupervisorError(
                    "invalid_config", f"every {label} command must contain a command"
                )
        raw_ports = runtime.get("ports", {})
        if not isinstance(raw_ports, dict):
            raise SupervisorError("invalid_config", "runtime.ports must be a table")
        reserved_env = {
            "ACP_ATTEMPT_ID",
            "ACP_TASK_ID",
            "ACP_WORKTREE",
            "ACP_REPO_ROOT",
            "ACP_RUNTIME_DIR",
            "ACP_PHASE",
            "PATH",
            "HOME",
            "SHELL",
            "USER",
            "LOGNAME",
            "PWD",
            "OLDPWD",
            "TMPDIR",
            "PYTHONPATH",
            "VIRTUAL_ENV",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "SSH_AUTH_SOCK",
        }
        runtime_port_pools: list[RuntimePortPool] = []
        for env_name, bounds in sorted(raw_ports.items()):
            if (
                not re.fullmatch(r"[A-Z_][A-Z0-9_]*", env_name)
                or env_name in reserved_env
                or env_name.startswith("ACP_")
            ):
                raise SupervisorError(
                    "invalid_config",
                    f"runtime port name {env_name!r} is not a safe environment variable",
                )
            if (
                not isinstance(bounds, list)
                or len(bounds) != 2
                or any(isinstance(value, bool) or not isinstance(value, int) for value in bounds)
            ):
                raise SupervisorError(
                    "invalid_config", f"runtime port pool {env_name} must be [start, end]"
                )
            start, end = bounds
            if start < 1024 or end > 65535 or start > end:
                raise SupervisorError(
                    "invalid_config",
                    f"runtime port pool {env_name} must stay within 1024..65535",
                )
            runtime_port_pools.append(RuntimePortPool(env_name, start, end))
        for index, pool in enumerate(runtime_port_pools):
            for other in runtime_port_pools[:index]:
                if max(pool.start, other.start) <= min(pool.end, other.end):
                    raise SupervisorError(
                        "invalid_config",
                        f"runtime port pools {other.env_name} and {pool.env_name} overlap",
                    )
        return Config(
            lease_seconds=lease,
            timeout_seconds=timeout,
            qc_commands=qc_commands,
            integration_commands=integration_commands,
            critic_command=critic_command,
            critic_identity=str(supervisor.get("critic_identity", "independent-qc")),
            require_critic=require_critic,
            runtime_setup_commands=runtime_setup_commands,
            runtime_teardown_commands=runtime_teardown_commands,
            runtime_port_pools=tuple(runtime_port_pools),
            runtime_drivers=runtime_drivers,
        )

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 30000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _event(
        self,
        connection: sqlite3.Connection,
        event_type: str,
        actor: str,
        payload: dict[str, Any],
    ) -> None:
        event_id = str(uuid.uuid4())
        created = utc_now()
        prior = connection.execute(
            "SELECT event_hash FROM events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = prior["event_hash"] if prior else GENESIS_HASH
        material = canonical_json(
            {
                "actor": actor,
                "created_at": created,
                "event_id": event_id,
                "event_type": event_type,
                "payload": payload,
                "previous_hash": previous_hash,
            }
        )
        connection.execute(
            """
            INSERT INTO events
              (id, event_type, actor, payload_json, previous_hash, event_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                event_type,
                actor,
                canonical_json(payload),
                previous_hash,
                sha256(material.encode()),
                created,
            ),
        )

    @staticmethod
    def normalize_resource(raw: str, repo: Path | None = None) -> str:
        value = unicodedata.normalize("NFC", raw.strip().replace("\\", "/"))
        if not value:
            raise SupervisorError("invalid_resource", "resource cannot be empty")
        if value.startswith("logical:"):
            suffix = value.removeprefix("logical:").strip().casefold()
            if not suffix or any(part in {"", ".", ".."} for part in suffix.split("/")):
                raise SupervisorError("invalid_resource", f"invalid logical resource: {raw}")
            return f"logical:{suffix}"
        directory = value.endswith("/")
        path = PurePosixPath(value)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise SupervisorError("invalid_resource", f"resource must be repo-relative: {raw}")
        value = path.as_posix()
        lowered = value.casefold()
        if lowered in {".git", ".acp"} or lowered.startswith((".git/", ".acp/")):
            raise SupervisorError("invalid_resource", f"internal resource forbidden: {raw}")
        directory = directory or bool(repo and (repo / value).is_dir())
        return (value.rstrip("/") + "/**" if directory else value).casefold()

    @staticmethod
    def resources_overlap(left: str, right: str) -> bool:
        if left.startswith("logical:") or right.startswith("logical:"):
            return left == right
        if left == right:
            return True
        for pattern, candidate in ((left, right), (right, left)):
            if pattern.endswith("/**"):
                prefix = pattern[:-3].rstrip("/")
                if candidate == prefix or candidate.startswith(prefix + "/"):
                    return True
        if any(character in left + right for character in "*?["):
            left_prefix = GitSupervisor._literal_prefix(left)
            right_prefix = GitSupervisor._literal_prefix(right)
            return (
                not left_prefix
                or not right_prefix
                or left_prefix == right_prefix
                or left_prefix.startswith(right_prefix + "/")
                or right_prefix.startswith(left_prefix + "/")
            )
        return False

    @staticmethod
    def _literal_prefix(resource: str) -> str:
        wildcard = min(
            (resource.find(character) for character in "*?[" if character in resource),
            default=len(resource),
        )
        prefix = resource[:wildcard]
        if wildcard < len(resource) and "/" in prefix:
            prefix = prefix.rsplit("/", 1)[0]
        elif wildcard < len(resource):
            prefix = ""
        return prefix.rstrip("/")

    def create_task(
        self,
        title: str,
        description: str,
        acceptance: Sequence[str],
        resources: Sequence[str],
        dependencies: Sequence[str] = (),
        priority: int = 50,
        base_branch: str = "HEAD",
    ) -> dict[str, Any]:
        if not title.strip() or not acceptance:
            raise SupervisorError("invalid_task", "title and acceptance criteria are required")
        normalized = sorted({self.normalize_resource(item, self.root) for item in resources})
        if not normalized:
            raise SupervisorError("invalid_task", "at least one write resource is required")
        base_sha = self._git_text("rev-parse", base_branch)
        resolved_branch = base_branch
        if base_branch == "HEAD":
            symbolic = self._git_text("symbolic-ref", "--quiet", "--short", "HEAD", check=False)
            resolved_branch = symbolic or base_sha
        task_id = str(uuid.uuid4())
        now = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for dependency in dependencies:
                if not connection.execute(
                    "SELECT 1 FROM tasks WHERE id = ?", (dependency,)
                ).fetchone():
                    raise SupervisorError(
                        "dependency_not_found", f"task {dependency} does not exist"
                    )
            connection.execute(
                """
                INSERT INTO tasks
                  (id, title, description, acceptance_json, resources_json,
                   dependencies_json, base_branch, base_sha, priority, status,
                   current_attempt_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', NULL, ?, ?)
                """,
                (
                    task_id,
                    title.strip(),
                    description.strip(),
                    canonical_json(list(acceptance)),
                    canonical_json(normalized),
                    canonical_json(list(dependencies)),
                    resolved_branch,
                    base_sha,
                    priority,
                    now,
                    now,
                ),
            )
            self._event(
                connection,
                "task.created",
                "operator",
                {"task_id": task_id, "resources": normalized, "base_sha": base_sha},
            )
        return self.task(task_id)

    def task(self, task_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            return self._task_view(connection, self._task_row(connection, task_id))

    def list_tasks(self) -> list[dict[str, Any]]:
        self.reap_expired()
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM tasks ORDER BY priority DESC, created_at"
            ).fetchall()
            return [self._task_view(connection, row) for row in rows]

    @staticmethod
    def _port_available(port: int) -> bool:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
        finally:
            probe.close()
        return True

    def _allocate_runtime(
        self,
        connection: sqlite3.Connection,
        attempt_id: str,
        task_id: str,
        worktree: Path,
        expires: int,
        stamp: str,
    ) -> None:
        runtime_dir = self.state_dir / "runtime" / attempt_id
        log_path = self.state_dir / "logs" / f"runtime-{attempt_id}.log"
        environment = {
            "ACP_ATTEMPT_ID": attempt_id,
            "ACP_TASK_ID": task_id,
            "ACP_WORKTREE": str(worktree),
            "ACP_REPO_ROOT": str(self.root),
            "ACP_RUNTIME_DIR": str(runtime_dir),
        }
        for pool in self.config.runtime_port_pools:
            allocated = None
            for value in range(pool.start, pool.end + 1):
                held = connection.execute(
                    "SELECT 1 FROM runtime_allocations WHERE pool_name = ? AND value = ?",
                    (pool.env_name, value),
                ).fetchone()
                if not held and self._port_available(value):
                    allocated = value
                    break
            if allocated is None:
                raise SupervisorError(
                    "runtime_pool_exhausted",
                    f"no available value remains in runtime port pool {pool.env_name}",
                )
            connection.execute(
                """
                INSERT INTO runtime_allocations
                  (pool_name, value, attempt_id, lease_expires_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (pool.env_name, allocated, attempt_id, expires, stamp),
            )
            environment[pool.env_name] = str(allocated)
        connection.execute(
            """
            INSERT INTO runtime_environments
              (attempt_id, state, env_json, setup_results_json,
               teardown_results_json, log_path, updated_at)
            VALUES (?, 'allocated', ?, '[]', '[]', ?, ?)
            """,
            (attempt_id, canonical_json(environment), str(log_path), stamp),
        )
        self._event(
            connection,
            "runtime.allocated",
            "supervisor",
            {
                "attempt_id": attempt_id,
                "ports": {
                    pool.env_name: environment[pool.env_name]
                    for pool in self.config.runtime_port_pools
                },
            },
        )

    def runtime_environment(self, attempt_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM runtime_environments WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if not row:
                raise SupervisorError(
                    "runtime_not_found", f"attempt {attempt_id} has no runtime environment"
                )
            return self._runtime_view(connection, row)

    def _runtime_env(self, attempt_id: str, require_ready: bool = True) -> dict[str, str]:
        runtime = self.runtime_environment(attempt_id)
        if require_ready and runtime["state"] != "ready":
            raise SupervisorError(
                "runtime_not_ready",
                f"attempt runtime state is {runtime['state']}",
            )
        return runtime["environment"]

    def _run_runtime_commands(
        self,
        commands: Sequence[str],
        cwd: Path,
        environment: dict[str, str],
        log_path: Path,
        stop_on_failure: bool,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        log_path.parent.mkdir(parents=True, exist_ok=True)
        for command in commands:
            result = self._run_command(command, cwd, environment)
            with log_path.open("a", encoding="utf-8") as log:
                log.write(json.dumps(result, sort_keys=True) + "\n")
            results.append(
                {
                    "command": command,
                    "exit_code": result["exit_code"],
                    "duration_ms": result["duration_ms"],
                }
            )
            if result["exit_code"] and stop_on_failure:
                break
        return results

    @staticmethod
    def _phase_runtime_env(environment: dict[str, str], phase: str, cwd: Path) -> dict[str, str]:
        return environment | {"ACP_PHASE": phase, "ACP_WORKTREE": str(cwd)}

    # -- authenticated runner identities -----------------------------------

    def enroll_runner(self, agent_id: str, role: str) -> dict[str, Any]:
        """Register a runner and return its credential exactly once.

        Only the digest is stored, so the state file never holds a usable
        credential — losing the returned value means re-enrolling, not reading
        it back out of the database.
        """

        if not agent_id.strip():
            raise SupervisorError("invalid_agent", "agent_id is required")
        try:
            validate_role(role)
        except IdentityError as error:
            raise SupervisorError(error.code, error.message) from error
        credential = issue_credential()
        stamp = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT agent_id FROM runner_identities WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            if existing:
                raise SupervisorError(
                    "runner_already_enrolled",
                    f"{agent_id} is already enrolled; revoke it before re-enrolling",
                )
            connection.execute(
                """
                INSERT INTO runner_identities
                  (agent_id, role, credential_digest, created_at, revoked_at)
                VALUES (?, ?, ?, ?, NULL)
                """,
                (agent_id, role, credential_digest(credential), stamp),
            )
            self._event(
                connection,
                "runner.enrolled",
                "supervisor",
                {"agent_id": agent_id, "role": role},
            )
        return {"agent_id": agent_id, "role": role, "credential": credential}

    def revoke_runner(self, agent_id: str) -> dict[str, Any]:
        stamp = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM runner_identities WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            if not row:
                raise SupervisorError("runner_not_found", f"{agent_id} is not enrolled")
            connection.execute(
                "UPDATE runner_identities SET revoked_at = ? WHERE agent_id = ?",
                (stamp, agent_id),
            )
            self._event(
                connection, "runner.revoked", "supervisor", {"agent_id": agent_id}
            )
        return {"agent_id": agent_id, "revoked_at": stamp}

    def runners(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT agent_id, role, created_at, revoked_at FROM runner_identities "
                "ORDER BY agent_id"
            ).fetchall()
        # credential_digest is deliberately not returned.
        return [dict(row) for row in rows]

    def _identity_enforced(self) -> bool:
        """Authentication activates once anything is enrolled.

        An empty registry keeps the single-host default behaviour, so enabling
        this is a deliberate act rather than a breaking upgrade.
        """
        with self.connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM runner_identities WHERE revoked_at IS NULL LIMIT 1"
            ).fetchone()
        return bool(row)

    def _authenticate(self, agent_id: str, role: str, credential: str | None) -> None:
        if not self._identity_enforced():
            return
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM runner_identities WHERE agent_id = ?", (agent_id,)
            ).fetchone()
        if not row:
            raise SupervisorError(
                "runner_not_enrolled",
                f"{agent_id} is not an enrolled runner; enroll it or revoke the registry",
            )
        if row["revoked_at"] is not None:
            raise SupervisorError("runner_revoked", f"{agent_id} credential is revoked")
        if row["role"] != role:
            raise SupervisorError(
                "runner_role_mismatch",
                f"{agent_id} is enrolled as {row['role']}, not {role}",
            )
        if not credential or not verify_credential(credential, row["credential_digest"]):
            raise SupervisorError(
                "runner_authentication_failed",
                f"{agent_id} did not present a valid {role} credential",
            )

    # -- trusted runtime drivers -------------------------------------------

    def _driver_secret(self) -> bytes:
        """Per-supervisor secret backing resource ownership tokens."""
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT value FROM meta WHERE key = 'driver_secret'"
            ).fetchone()
            if row:
                return bytes.fromhex(row["value"])
            secret = os.urandom(32)
            connection.execute(
                "INSERT INTO meta (key, value) VALUES ('driver_secret', ?)",
                (secret.hex(),),
            )
            return secret

    def _driver_context(self, attempt_id: str, environment: dict[str, str]) -> DriverContext:
        attempt = self.attempt(attempt_id)
        runtime_dir = Path(environment["ACP_RUNTIME_DIR"])
        return DriverContext(
            attempt_id=attempt_id,
            task_id=str(attempt["task_id"]),
            runtime_dir=runtime_dir,
            expires_at=int(time.time()) + self.config.lease_seconds,
            secret=self._driver_secret(),
            environment=environment,
        )

    def _run_driver_phase(
        self, phase: str, attempt_id: str, environment: dict[str, str]
    ) -> list[PhaseEvidence]:
        """Run *phase* for every configured driver.

        Drivers execute with the runtime directory as cwd — never the candidate
        worktree — and through ``run_trusted``, which re-validates argv[0]
        immediately before exec.
        """

        if not self.config.runtime_drivers:
            return []
        context = self._driver_context(attempt_id, environment)
        evidence: list[PhaseEvidence] = []
        for definition in self.config.runtime_drivers:
            driver = build_driver(definition)
            try:
                evidence.append(driver.run_phase(phase, context, run_trusted))
            except DriverError as error:
                evidence.append(
                    PhaseEvidence(
                        driver=definition.name,
                        kind=definition.kind,
                        phase=phase,
                        resource_id="",
                        ownership_token="",
                        expires_at=context.expires_at,
                        exit_code=1,
                        present=None,
                        proof={"error": error.message, "code": error.code},
                    )
                )
        self._record_driver_evidence(attempt_id, phase, evidence)
        return evidence

    def _record_driver_evidence(
        self, attempt_id: str, phase: str, evidence: Sequence[PhaseEvidence]
    ) -> None:
        if not evidence:
            return
        stamp = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for item in evidence:
                if phase == "teardown":
                    state = "released" if item.proof.get("cleanup_proved") else "quarantined"
                elif phase == "setup":
                    state = "active" if item.ok else "setup_failed"
                else:
                    state = "active" if item.present else "absent"
                connection.execute(
                    """
                    INSERT INTO runtime_driver_resources
                      (attempt_id, driver, kind, resource_id, ownership_token,
                       expires_at, state, evidence_json, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(attempt_id, driver) DO UPDATE SET
                      resource_id = excluded.resource_id,
                      ownership_token = excluded.ownership_token,
                      expires_at = excluded.expires_at,
                      state = excluded.state,
                      evidence_json = excluded.evidence_json,
                      updated_at = excluded.updated_at
                    """,
                    (
                        attempt_id,
                        item.driver,
                        item.kind,
                        item.resource_id,
                        item.ownership_token,
                        item.expires_at,
                        state,
                        canonical_json(item.as_dict()),
                        stamp,
                    ),
                )
                self._event(
                    connection,
                    f"runtime.driver.{phase}",
                    "supervisor",
                    {
                        "attempt_id": attempt_id,
                        "driver": item.driver,
                        "kind": item.kind,
                        "resource_id": item.resource_id,
                        "state": state,
                        "exit_code": item.exit_code,
                        "present": item.present,
                        "cleanup_proved": item.proof.get("cleanup_proved"),
                    },
                )

    def driver_resources(self, attempt_id: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM runtime_driver_resources WHERE attempt_id = ? ORDER BY driver",
                (attempt_id,),
            ).fetchall()
        return [
            {
                "driver": row["driver"],
                "kind": row["kind"],
                "resource_id": row["resource_id"],
                "ownership_token": row["ownership_token"],
                "expires_at": row["expires_at"],
                "state": row["state"],
                "evidence": json.loads(row["evidence_json"]),
            }
            for row in rows
        ]

    def quarantined_resources(self) -> list[dict[str, Any]]:
        """Allocations whose cleanup could not be proven.

        These are deliberately NOT recycled: an unproven teardown is the case
        where something may still be running, so reuse is the one thing that
        must not happen automatically.
        """
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM runtime_driver_resources WHERE state = 'quarantined' "
                "ORDER BY updated_at"
            ).fetchall()
        return [
            {
                "attempt_id": row["attempt_id"],
                "driver": row["driver"],
                "kind": row["kind"],
                "resource_id": row["resource_id"],
                "state": row["state"],
                "evidence": json.loads(row["evidence_json"]),
            }
            for row in rows
        ]

    def runtime_restart(self, attempt_id: str) -> dict[str, Any]:
        """Tear down and re-create driver resources between phases.

        QC must not be able to reach a service the worker left running: a stale
        app server can make a reviewer pass a candidate whose code never
        actually starts.
        """
        environment = self._runtime_env(attempt_id, require_ready=False)
        teardown = self._run_driver_phase("teardown", attempt_id, environment)
        unproven = [item for item in teardown if not item.proof.get("cleanup_proved")]
        if unproven:
            raise SupervisorError(
                "runtime_cleanup_unproven",
                "cannot restart runtime: cleanup proof missing for "
                + ", ".join(sorted(item.driver for item in unproven)),
            )
        setup = self._run_driver_phase("setup", attempt_id, environment)
        failed = [item for item in setup if not item.ok]
        if failed:
            raise SupervisorError(
                "runtime_setup_failed",
                "driver setup failed for " + ", ".join(sorted(item.driver for item in failed)),
            )
        return {
            "attempt_id": attempt_id,
            "restarted": [item.driver for item in setup],
            "resources": self.driver_resources(attempt_id),
        }

    def _runtime_up(self, attempt_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM runtime_environments WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if not row:
                raise SupervisorError("runtime_not_found", "runtime allocation is missing")
            if row["state"] != "allocated":
                raise SupervisorError(
                    "runtime_not_ready", f"runtime cannot start from state {row['state']}"
                )
            connection.execute(
                "UPDATE runtime_environments SET state = 'setting_up', updated_at = ? "
                "WHERE attempt_id = ?",
                (utc_now(), attempt_id),
            )
            self._event(
                connection,
                "runtime.setup_started",
                "supervisor",
                {"attempt_id": attempt_id},
            )
        attempt = self.attempt(attempt_id)
        environment = json.loads(row["env_json"])
        runtime_dir = Path(environment["ACP_RUNTIME_DIR"])
        runtime_dir.mkdir(parents=True, exist_ok=True)
        results = self._run_runtime_commands(
            self.config.runtime_setup_commands,
            Path(attempt["worktree"]),
            self._phase_runtime_env(environment, "setup", Path(attempt["worktree"])),
            Path(row["log_path"]),
            stop_on_failure=True,
        )
        failed = any(result["exit_code"] for result in results)
        if not failed:
            driver_evidence = self._run_driver_phase("setup", attempt_id, environment)
            failed = any(not item.ok for item in driver_evidence)
            results = results + [
                {
                    "command": f"driver:{item.driver}:setup",
                    "exit_code": item.exit_code,
                    "duration_ms": 0,
                }
                for item in driver_evidence
            ]
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            state = "setup_failed" if failed else "ready"
            connection.execute(
                """
                UPDATE runtime_environments
                SET state = ?, setup_results_json = ?, updated_at = ?
                WHERE attempt_id = ?
                """,
                (state, canonical_json(results), utc_now(), attempt_id),
            )
            self._event(
                connection,
                "runtime.setup_failed" if failed else "runtime.ready",
                "supervisor",
                {"attempt_id": attempt_id, "results": results},
            )
        if failed:
            raise SupervisorError(
                "runtime_setup_failed",
                f"runtime setup failed; log: {row['log_path']}",
            )
        return self.runtime_environment(attempt_id)

    def _abandon_runtime(self, attempt_id: str) -> None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT state FROM runtime_environments WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if not row or row["state"] == "released":
                return
            stamp = utc_now()
            connection.execute(
                "DELETE FROM runtime_allocations WHERE attempt_id = ?", (attempt_id,)
            )
            connection.execute(
                "UPDATE runtime_environments SET state = 'released', updated_at = ? "
                "WHERE attempt_id = ?",
                (stamp, attempt_id),
            )
            self._event(
                connection,
                "runtime.released",
                "supervisor",
                {"attempt_id": attempt_id, "reason": "provision_abandoned"},
            )

    def runtime_down(
        self,
        attempt_id: str,
        force: bool = False,
        _allow_active: bool = False,
    ) -> dict[str, Any]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM runtime_environments WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if not row:
                raise SupervisorError("runtime_not_found", "runtime environment is missing")
            if row["state"] == "released":
                return self._runtime_view(connection, row)
            task = connection.execute(
                """
                SELECT task.status FROM tasks AS task
                JOIN attempts AS attempt ON attempt.task_id = task.id
                WHERE attempt.id = ?
                """,
                (attempt_id,),
            ).fetchone()
            active_states = {"provisioning", "working", "qc_review", "approved", "integrating"}
            if task and task["status"] in active_states and not _allow_active:
                raise SupervisorError(
                    "runtime_in_use",
                    f"runtime is still required while task status is {task['status']}",
                )
            if row["state"] == "tearing_down" and not force:
                raise SupervisorError(
                    "runtime_cleanup_in_progress",
                    "runtime cleanup is already in progress; use force only after a crashed cleanup",
                )
            connection.execute(
                "UPDATE runtime_environments SET state = 'tearing_down', updated_at = ? "
                "WHERE attempt_id = ?",
                (utc_now(), attempt_id),
            )
            self._event(
                connection,
                "runtime.teardown_started",
                "supervisor",
                {"attempt_id": attempt_id, "force": force},
            )
            environment = json.loads(row["env_json"])
        attempt = self.attempt(attempt_id)
        worktree = Path(attempt["worktree"])
        cwd = worktree if worktree.is_dir() else self.root
        results = self._run_runtime_commands(
            self.config.runtime_teardown_commands,
            cwd,
            self._phase_runtime_env(environment, "teardown", cwd),
            Path(row["log_path"]),
            stop_on_failure=False,
        )
        # Drivers tear down AFTER the shell hooks and are then independently
        # re-probed. A hook that exits 0 proves only that a process exited 0.
        driver_evidence = self._run_driver_phase("teardown", attempt_id, environment)
        unproven = [
            item.driver for item in driver_evidence if not item.proof.get("cleanup_proved")
        ]
        results = results + [
            {
                "command": f"driver:{item.driver}:teardown",
                "exit_code": item.exit_code,
                "duration_ms": 0,
                "cleanup_proved": bool(item.proof.get("cleanup_proved")),
            }
            for item in driver_evidence
        ]
        with self.connect() as connection:
            allocations = connection.execute(
                "SELECT pool_name, value FROM runtime_allocations "
                "WHERE attempt_id = ? ORDER BY pool_name",
                (attempt_id,),
            ).fetchall()
        occupied = [
            f"{allocation['pool_name']}={allocation['value']}"
            for allocation in allocations
            if not self._port_available(allocation["value"])
        ]
        # Missing cleanup proof quarantines the allocation: the ports are NOT
        # returned to the pool, so nothing is handed to a later attempt while a
        # resource from this one may still be alive.
        failed = (
            any(result["exit_code"] for result in results)
            or bool(occupied)
            or bool(unproven)
        )
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            stamp = utc_now()
            state = "teardown_failed" if failed else "released"
            connection.execute(
                """
                UPDATE runtime_environments
                SET state = ?, teardown_results_json = ?, updated_at = ?
                WHERE attempt_id = ?
                """,
                (state, canonical_json(results), stamp, attempt_id),
            )
            if not failed:
                connection.execute(
                    "DELETE FROM runtime_allocations WHERE attempt_id = ?", (attempt_id,)
                )
            self._event(
                connection,
                "runtime.teardown_failed" if failed else "runtime.released",
                "supervisor",
                {
                    "attempt_id": attempt_id,
                    "results": results,
                    "occupied": occupied,
                    "unproven_cleanup": unproven,
                },
            )
        if not failed:
            shutil.rmtree(environment["ACP_RUNTIME_DIR"], ignore_errors=True)
        return self.runtime_environment(attempt_id)

    def claim(
        self,
        task_id: str,
        agent_id: str,
        lease_seconds: int | None = None,
        credential: str | None = None,
    ) -> dict[str, Any]:
        if not agent_id.strip():
            raise SupervisorError("invalid_agent", "agent_id is required")
        self._authenticate(agent_id, "worker", credential)
        self.reap_expired()
        ttl = lease_seconds or self.config.lease_seconds
        if ttl < 10:
            raise SupervisorError("invalid_lease", "lease must be at least 10 seconds")
        expires = int(time.time()) + ttl
        attempt_id = str(uuid.uuid4())
        worktree = self.state_dir / "worktrees" / attempt_id
        now = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            task = self._task_row(connection, task_id)
            if task["status"] not in {"open", "orphaned", "changes_requested"}:
                raise SupervisorError("task_unavailable", f"task status is {task['status']}")
            for dependency in json.loads(task["dependencies_json"]):
                row = connection.execute(
                    "SELECT status FROM tasks WHERE id = ?", (dependency,)
                ).fetchone()
                if not row or row["status"] != "done":
                    raise SupervisorError(
                        "dependency_incomplete", f"dependency {dependency} is not done"
                    )
            requested = json.loads(task["resources_json"])
            leases = connection.execute(
                """
                SELECT resource, task_id FROM resource_leases
                WHERE task_id IS NOT NULL AND lease_expires_at > ?
                """,
                (int(time.time()),),
            ).fetchall()
            for resource in requested:
                for lease in leases:
                    if lease["task_id"] != task_id and self.resources_overlap(
                        resource, lease["resource"]
                    ):
                        raise SupervisorError(
                            "resource_busy",
                            f"{resource} overlaps active lease {lease['resource']}",
                        )
            counter_row = connection.execute(
                "SELECT value FROM meta WHERE key = 'claim_counter'"
            ).fetchone()
            counter = int(counter_row["value"]) + 1
            connection.execute(
                "UPDATE meta SET value = ? WHERE key = 'claim_counter'", (str(counter),)
            )
            number = connection.execute(
                """
                SELECT COALESCE(MAX(number), 0) + 1 AS value
                FROM attempts WHERE task_id = ?
                """,
                (task_id,),
            ).fetchone()["value"]
            resume = connection.execute(
                """
                SELECT latest_sha FROM attempts
                WHERE task_id = ? AND latest_sha IS NOT NULL
                ORDER BY number DESC LIMIT 1
                """,
                (task_id,),
            ).fetchone()
            start_sha = resume["latest_sha"] if resume else task["base_sha"]
            branch = f"acp/task-{task_id[:8]}-a{number}"
            connection.execute(
                """
                INSERT INTO attempts
                  (id, task_id, number, agent_id, branch, worktree, claim_token,
                   start_sha, latest_sha, checkpoint_json, pid, log_path, status,
                   lease_expires_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', NULL, NULL,
                        'provisioning', ?, ?, ?)
                """,
                (
                    attempt_id,
                    task_id,
                    number,
                    agent_id,
                    branch,
                    str(worktree),
                    counter,
                    start_sha,
                    start_sha,
                    expires,
                    now,
                    now,
                ),
            )
            self._allocate_runtime(
                connection,
                attempt_id,
                task_id,
                worktree,
                expires,
                now,
            )
            for resource in requested:
                prior = connection.execute(
                    "SELECT fencing_token FROM resource_leases WHERE resource = ?",
                    (resource,),
                ).fetchone()
                token = (prior["fencing_token"] if prior else 0) + 1
                connection.execute(
                    """
                    INSERT INTO resource_leases
                      (resource, task_id, attempt_id, fencing_token,
                       lease_expires_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(resource) DO UPDATE SET
                      task_id = excluded.task_id,
                      attempt_id = excluded.attempt_id,
                      fencing_token = excluded.fencing_token,
                      lease_expires_at = excluded.lease_expires_at,
                      updated_at = excluded.updated_at
                    """,
                    (resource, task_id, attempt_id, token, expires, now),
                )
            connection.execute(
                """
                UPDATE tasks SET status = 'provisioning',
                  current_attempt_id = ?, updated_at = ? WHERE id = ?
                """,
                (attempt_id, now, task_id),
            )
            self._event(
                connection,
                "attempt.claimed",
                agent_id,
                {
                    "task_id": task_id,
                    "attempt_id": attempt_id,
                    "claim_token": counter,
                    "start_sha": start_sha,
                },
            )
        worktree_created = False
        try:
            self._git("worktree", "add", "-b", branch, str(worktree), start_sha)
            worktree_created = True
            self._runtime_up(attempt_id)
        except (OSError, subprocess.SubprocessError, SupervisorError):
            if worktree_created:
                try:
                    self.runtime_down(attempt_id, force=True, _allow_active=True)
                except (OSError, subprocess.SubprocessError, SupervisorError):
                    pass
            else:
                self._abandon_runtime(attempt_id)
            self._git("worktree", "remove", "--force", str(worktree), check=False)
            if worktree.exists():
                shutil.rmtree(worktree)
            self._git("worktree", "prune", check=False)
            self._git("branch", "-D", branch, check=False)
            self._rollback_provision(task_id, attempt_id)
            raise
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE attempts SET status = 'working', updated_at = ? WHERE id = ?",
                (utc_now(), attempt_id),
            )
            connection.execute(
                "UPDATE tasks SET status = 'working', updated_at = ? WHERE id = ?",
                (utc_now(), task_id),
            )
            self._event(
                connection,
                "attempt.ready",
                "supervisor",
                {"attempt_id": attempt_id, "worktree": str(worktree)},
            )
        return self.attempt(attempt_id)

    def _rollback_provision(self, task_id: str, attempt_id: str) -> None:
        now = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE attempts SET status = 'failed', updated_at = ? WHERE id = ?",
                (now, attempt_id),
            )
            connection.execute(
                """
                UPDATE tasks SET status = 'open', current_attempt_id = NULL,
                  updated_at = ? WHERE id = ? AND current_attempt_id = ?
                """,
                (now, task_id, attempt_id),
            )
            connection.execute(
                """
                UPDATE resource_leases SET task_id = NULL, attempt_id = NULL,
                  lease_expires_at = 0, updated_at = ? WHERE attempt_id = ?
                """,
                (now, attempt_id),
            )
            self._event(
                connection,
                "attempt.provision_failed",
                "supervisor",
                {"attempt_id": attempt_id},
            )

    def heartbeat(
        self,
        attempt_id: str,
        claim_token: int,
        checkpoint: dict[str, Any] | None = None,
        lease_seconds: int | None = None,
    ) -> dict[str, Any]:
        ttl = lease_seconds or self.config.lease_seconds
        expires = int(time.time()) + ttl
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            task = self._task_row(connection, attempt["task_id"])
            runtime = connection.execute(
                "SELECT state FROM runtime_environments WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if not runtime or runtime["state"] != "ready":
                raise SupervisorError(
                    "runtime_not_ready",
                    f"attempt runtime state is {runtime['state'] if runtime else 'missing'}",
                )
            expected = set(json.loads(task["resources_json"]))
            rows = connection.execute(
                "SELECT * FROM resource_leases WHERE attempt_id = ?", (attempt_id,)
            ).fetchall()
            active = {
                row["resource"]
                for row in rows
                if row["task_id"] == task["id"] and row["lease_expires_at"] > int(time.time())
            }
            if active != expected:
                raise SupervisorError("stale_fencing_token", "resource lease set changed")
            head = self._git_text("-C", attempt["worktree"], "rev-parse", "HEAD")
            now = utc_now()
            connection.execute(
                """
                UPDATE attempts SET latest_sha = ?, checkpoint_json = ?,
                  lease_expires_at = ?, updated_at = ? WHERE id = ?
                """,
                (head, canonical_json(checkpoint or {}), expires, now, attempt_id),
            )
            count = connection.execute(
                """
                UPDATE resource_leases SET lease_expires_at = ?, updated_at = ?
                WHERE attempt_id = ? AND task_id = ?
                """,
                (expires, now, attempt_id, task["id"]),
            ).rowcount
            if count != len(expected):
                raise SupervisorError("stale_fencing_token", "resource lease set changed")
            connection.execute(
                """
                UPDATE runtime_allocations SET lease_expires_at = ?, updated_at = ?
                WHERE attempt_id = ?
                """,
                (expires, now, attempt_id),
            )
            self._event(
                connection,
                "attempt.heartbeat",
                attempt["agent_id"],
                {"attempt_id": attempt_id, "latest_sha": head},
            )
        return self.attempt(attempt_id)

    def attempt(self, attempt_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
            if not row:
                raise SupervisorError("attempt_not_found", f"attempt {attempt_id} not found")
            return self._attempt_view(connection, row)

    def reap_expired(self, now: int | None = None) -> dict[str, Any]:
        epoch = int(time.time()) if now is None else now
        orphaned: list[str] = []
        conflicted: list[str] = []
        cleanup_attempts: set[str] = set()
        workers_to_stop: list[tuple[str, int]] = []
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempts = connection.execute(
                """
                SELECT * FROM attempts
                WHERE status IN ('provisioning', 'working')
                  AND lease_expires_at <= ?
                """,
                (epoch,),
            ).fetchall()
            for attempt in attempts:
                latest = attempt["latest_sha"]
                if Path(attempt["worktree"]).exists():
                    latest = (
                        self._git_text(
                            "-C",
                            attempt["worktree"],
                            "rev-parse",
                            "HEAD",
                            check=False,
                        )
                        or latest
                    )
                stamp = utc_now()
                connection.execute(
                    """
                    UPDATE attempts SET status = 'orphaned', latest_sha = ?,
                      pid = NULL, updated_at = ? WHERE id = ?
                    """,
                    (latest, stamp, attempt["id"]),
                )
                connection.execute(
                    """
                    UPDATE tasks SET status = 'orphaned',
                      current_attempt_id = NULL, updated_at = ?
                    WHERE id = ? AND current_attempt_id = ?
                    """,
                    (stamp, attempt["task_id"], attempt["id"]),
                )
                connection.execute(
                    """
                    UPDATE resource_leases SET task_id = NULL, attempt_id = NULL,
                      lease_expires_at = 0, updated_at = ? WHERE attempt_id = ?
                    """,
                    (stamp, attempt["id"]),
                )
                orphaned.append(attempt["task_id"])
                cleanup_attempts.add(attempt["id"])
                if attempt["pid"] and attempt["pid"] > 0:
                    workers_to_stop.append((attempt["id"], attempt["pid"]))
                self._event(
                    connection,
                    "attempt.orphaned",
                    "reaper",
                    {"attempt_id": attempt["id"], "latest_sha": latest},
                )
            expired = connection.execute(
                """
                SELECT DISTINCT task.id
                FROM tasks AS task
                JOIN resource_leases AS lease ON lease.task_id = task.id
                WHERE task.status IN ('qc_review', 'approved', 'integrating')
                  AND lease.lease_expires_at <= ?
                """,
                (epoch,),
            ).fetchall()
            for row in expired:
                stamp = utc_now()
                connection.execute(
                    "UPDATE tasks SET status = 'conflicted', updated_at = ? WHERE id = ?",
                    (stamp, row["id"]),
                )
                connection.execute(
                    """
                    UPDATE resource_leases SET task_id = NULL, attempt_id = NULL,
                      lease_expires_at = 0, updated_at = ? WHERE task_id = ?
                    """,
                    (stamp, row["id"]),
                )
                conflicted.append(row["id"])
                submission = connection.execute(
                    """
                    SELECT attempt_id FROM submissions WHERE task_id = ?
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    (row["id"],),
                ).fetchone()
                if submission:
                    cleanup_attempts.add(submission["attempt_id"])
                self._event(
                    connection,
                    "reservation.expired",
                    "reaper",
                    {"task_id": row["id"]},
                )
            expired_runtime = connection.execute(
                """
                SELECT DISTINCT attempt_id FROM runtime_allocations
                WHERE lease_expires_at <= ?
                """,
                (epoch,),
            ).fetchall()
            cleanup_attempts.update(row["attempt_id"] for row in expired_runtime)
        terminated_workers: list[dict[str, Any]] = []
        for attempt_id, pid in workers_to_stop:
            self._terminate_registered_group(pid)
            terminated_workers.append({"attempt_id": attempt_id, "pid": pid})
        runtime_cleanup: list[dict[str, Any]] = []
        for attempt_id in sorted(cleanup_attempts):
            try:
                runtime = self.runtime_down(attempt_id)
                runtime_cleanup.append({"attempt_id": attempt_id, "state": runtime["state"]})
            except (OSError, subprocess.SubprocessError, SupervisorError) as error:
                runtime_cleanup.append(
                    {"attempt_id": attempt_id, "state": "cleanup_error", "error": str(error)}
                )
        return {
            "orphaned": orphaned,
            "conflicted": conflicted,
            "terminated_workers": terminated_workers,
            "runtime_cleanup": runtime_cleanup,
        }

    def submit(self, attempt_id: str, claim_token: int) -> dict[str, Any]:
        return self._submit(attempt_id, claim_token, expected_worker_pid=None)

    def _submit(
        self,
        attempt_id: str,
        claim_token: int,
        expected_worker_pid: int | None,
    ) -> dict[str, Any]:
        epoch = int(time.time())
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, epoch)
            if expected_worker_pid is None and attempt["pid"] is not None:
                raise SupervisorError(
                    "worker_still_running",
                    "manual submit is forbidden while a supervised worker is registered",
                )
            if expected_worker_pid is not None and attempt["pid"] != expected_worker_pid:
                raise SupervisorError(
                    "worker_registration_lost",
                    "supervised submit does not own the registered worker PID",
                )
            task = self._task_row(connection, attempt["task_id"])
            worktree = Path(attempt["worktree"])
            if self._git_bytes("-C", str(worktree), "status", "--porcelain=v1", "-z"):
                raise SupervisorError("dirty_worktree", "submission requires committed work")
            commit = self._git_text("-C", str(worktree), "rev-parse", "HEAD")
            if commit == task["base_sha"]:
                raise SupervisorError("empty_submission", "submission has no commits")
            self._git(
                "-C",
                str(worktree),
                "merge-base",
                "--is-ancestor",
                task["base_sha"],
                commit,
            )
            raw = self._git_bytes(
                "-C",
                str(worktree),
                "diff",
                "--name-only",
                "-z",
                task["base_sha"],
                commit,
            )
            changed = sorted(value.decode("utf-8") for value in raw.split(b"\0") if value)
            if not changed:
                raise SupervisorError("empty_submission", "no changed paths")
            declared = json.loads(task["resources_json"])
            undeclared = [
                path
                for path in changed
                if not any(self._path_matches(path, resource) for resource in declared)
            ]
            if undeclared:
                raise SupervisorError(
                    "undeclared_write",
                    "changed paths are not leased: " + ", ".join(undeclared),
                )
            for path in changed:
                self._assert_safe_symlink(worktree, commit, path)
            rows = connection.execute(
                "SELECT * FROM resource_leases WHERE attempt_id = ?", (attempt_id,)
            ).fetchall()
            tokens = {
                row["resource"]: row["fencing_token"]
                for row in rows
                if row["task_id"] == task["id"] and row["lease_expires_at"] > epoch
            }
            if set(tokens) != set(declared):
                raise SupervisorError("stale_fencing_token", "resource lease set is stale")
            tree = self._git_text("-C", str(worktree), "rev-parse", f"{commit}^{{tree}}")
            patch = self._git_bytes(
                "-C",
                str(worktree),
                "diff",
                "--binary",
                task["base_sha"],
                commit,
            )
            submission_id = str(uuid.uuid4())
            stamp = utc_now()
            connection.execute(
                """
                INSERT INTO submissions
                  (id, task_id, attempt_id, worker_agent_id, commit_sha, tree_sha,
                   patch_sha256, changed_paths_json, resource_tokens_json,
                   status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_qc', ?)
                """,
                (
                    submission_id,
                    task["id"],
                    attempt_id,
                    attempt["agent_id"],
                    commit,
                    tree,
                    sha256(patch),
                    canonical_json(changed),
                    canonical_json(tokens),
                    stamp,
                ),
            )
            connection.execute(
                """
                UPDATE attempts SET status = 'submitted', latest_sha = ?,
                  pid = NULL, updated_at = ? WHERE id = ?
                """,
                (commit, stamp, attempt_id),
            )
            connection.execute(
                "UPDATE tasks SET status = 'qc_review', updated_at = ? WHERE id = ?",
                (stamp, task["id"]),
            )
            reserve_until = epoch + max(3600, self.config.timeout_seconds * 3)
            connection.execute(
                """
                UPDATE resource_leases SET attempt_id = NULL,
                  lease_expires_at = ?, updated_at = ?
                WHERE task_id = ? AND attempt_id = ?
                """,
                (reserve_until, stamp, task["id"], attempt_id),
            )
            connection.execute(
                """
                UPDATE runtime_allocations SET lease_expires_at = ?, updated_at = ?
                WHERE attempt_id = ?
                """,
                (reserve_until, stamp, attempt_id),
            )
            self._event(
                connection,
                "submission.created",
                attempt["agent_id"],
                {
                    "submission_id": submission_id,
                    "commit_sha": commit,
                    "patch_sha256": sha256(patch),
                    "resource_tokens": tokens,
                },
            )
        return self.submission(submission_id)

    def submission(self, submission_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            row = self._submission_row(connection, submission_id)
            return self._submission_view(connection, row)

    def run_qc(
        self,
        submission_id: str,
        reviewer_id: str,
        credential: str | None = None,
    ) -> dict[str, Any]:
        # Prove the reviewer holds the critic credential before anything else.
        # Until this existed, "independent QC" was a string a worker could type.
        self._authenticate(reviewer_id, "critic", credential)
        if reviewer_id != self.config.critic_identity:
            raise SupervisorError(
                "reviewer_identity_mismatch",
                f"reviewer must be configured identity {self.config.critic_identity}",
            )
        started = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            submission = self._submission_row(connection, submission_id)
            task = self._task_row(connection, submission["task_id"])
            if submission["status"] != "pending_qc" or task["status"] != "qc_review":
                raise SupervisorError("submission_not_reviewable", "submission is not pending QC")
            try:
                assert_distinct(submission["worker_agent_id"], reviewer_id)
            except IdentityError as error:
                raise SupervisorError(error.code, error.message) from error
            self._assert_reservations(connection, task, submission)
            runtime = connection.execute(
                "SELECT * FROM runtime_environments WHERE attempt_id = ?",
                (submission["attempt_id"],),
            ).fetchone()
            if not runtime or runtime["state"] != "ready":
                raise SupervisorError(
                    "runtime_not_ready",
                    f"submission runtime state is {runtime['state'] if runtime else 'missing'}",
                )
            runtime_env = json.loads(runtime["env_json"])

        qc_dir = self.state_dir / "worktrees" / f"qc-{uuid.uuid4().hex}"
        packet_path = self.state_dir / "logs" / f"review-{submission_id}.json"
        results: list[dict[str, Any]] = []
        findings: list[dict[str, str]] = []
        critic_verdict = "pass"
        try:
            self._git("worktree", "add", "--detach", str(qc_dir), submission["commit_sha"])
            packet = self._review_packet(task, submission, qc_dir)
            packet_path.write_text(json.dumps(packet, indent=2), encoding="utf-8")
            # Fresh services before review. Otherwise QC can pass against an app
            # server the worker left running, which proves the worker's old code
            # works, not the code being reviewed.
            if self.config.runtime_drivers:
                try:
                    self.runtime_restart(submission["attempt_id"])
                except SupervisorError as error:
                    findings.append(
                        {
                            "severity": "high",
                            "requirement": "review runs against freshly started services",
                            "finding": f"runtime restart before QC failed: {error.code}",
                            "evidence": error.message,
                            "required_fix": (
                                "resolve the runtime cleanup/startup failure; a review against a "
                                "stale or unproven runtime is not evidence"
                            ),
                        }
                    )
                else:
                    runtime_env = self._runtime_env(
                        submission["attempt_id"], require_ready=False
                    )
            for command in self.config.qc_commands:
                self._restore_candidate(qc_dir, submission["commit_sha"])
                result = self._run_command(
                    command,
                    qc_dir,
                    self._phase_runtime_env(runtime_env, "qc", qc_dir),
                )
                results.append(result)
                if result["exit_code"]:
                    findings.append(self._command_finding(command, result))
                elif not self._worktree_matches(qc_dir, submission["commit_sha"]):
                    findings.append(
                        {
                            "severity": "high",
                            "requirement": "QC observes the submitted commit",
                            "finding": f"command mutated the candidate: {command}",
                            "evidence": "HEAD, index, or tracked files changed during QC",
                            "required_fix": "make the command read-only for tracked source",
                        }
                    )
            if self.config.critic_command:
                packet["deterministic_results"] = results
                packet_path.write_text(json.dumps(packet, indent=2), encoding="utf-8")
                self._restore_candidate(qc_dir, submission["commit_sha"])
                result_path = (
                    self.state_dir / "logs" / f"critic-{submission_id}-{uuid.uuid4().hex}.json"
                )
                critic = self._run_critic(
                    self.config.critic_command,
                    qc_dir,
                    self._phase_runtime_env(runtime_env, "critic", qc_dir)
                    | {
                        "ACP_REVIEW_PACKET": str(packet_path),
                        "ACP_REVIEW_RESULT": str(result_path),
                    },
                )
                results.append(critic)
                if critic["exit_code"] or not self._worktree_matches(
                    qc_dir, submission["commit_sha"]
                ):
                    findings.append(self._command_finding("independent critic", critic))
                    critic_verdict = "block"
                else:
                    try:
                        payload = self._critic_payload(result_path)
                    finally:
                        result_path.unlink(missing_ok=True)
                    critic_verdict = payload["verdict"]
                    findings.extend(payload["findings"])
            elif self.config.require_critic:
                findings.append(
                    {
                        "severity": "high",
                        "requirement": "independent critic is mandatory",
                        "finding": "require_critic is true but critic_command is empty",
                        "evidence": "acp.toml policy evaluation",
                        "required_fix": "configure a structured critic command",
                    }
                )
                critic_verdict = "block"
        except (OSError, subprocess.SubprocessError, SupervisorError, ValueError) as error:
            critic_verdict = "block"
            findings.append(
                {
                    "severity": "high",
                    "requirement": "QC execution is trustworthy",
                    "finding": "QC execution failed",
                    "evidence": str(error),
                    "required_fix": "repair QC and rerun it on the immutable commit",
                }
            )
        finally:
            if qc_dir.exists():
                self._remove_worktree(qc_dir, delete_branch=False)

        serious = {"critical", "high", "medium"}
        if any(result["exit_code"] for result in results):
            verdict = "block"
        elif any(item.get("severity") in serious for item in findings):
            verdict = "revise"
        else:
            verdict = critic_verdict
        if verdict not in {"pass", "revise", "block", "human_required"}:
            verdict = "block"
            findings.append(
                {
                    "severity": "high",
                    "requirement": "critic output follows the contract",
                    "finding": "critic returned an unsupported verdict",
                    "evidence": str(critic_verdict),
                    "required_fix": "emit pass, revise, block, or human_required",
                }
            )
        finished = utc_now()
        qc_id = str(uuid.uuid4())
        packet_hash = sha256(packet_path.read_bytes()) if packet_path.exists() else sha256(b"")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._submission_row(connection, submission_id)
            current_task = self._task_row(connection, current["task_id"])
            if current["status"] != "pending_qc" or current_task["status"] != "qc_review":
                raise SupervisorError("submission_not_reviewable", "submission changed during QC")
            self._assert_reservations(connection, current_task, current)
            connection.execute(
                """
                INSERT INTO qc_runs
                  (id, submission_id, reviewer_id, commit_sha, verdict,
                   findings_json, results_json, packet_sha256, started_at, finished_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    qc_id,
                    submission_id,
                    reviewer_id,
                    current["commit_sha"],
                    verdict,
                    canonical_json(findings),
                    canonical_json(results),
                    packet_hash,
                    started,
                    finished,
                ),
            )
            submission_status = {
                "pass": "approved",
                "revise": "changes_requested",
                "block": "blocked",
                "human_required": "human_required",
            }[verdict]
            task_status = (
                "approved"
                if verdict == "pass"
                else "changes_requested"
                if verdict == "revise"
                else "blocked"
            )
            connection.execute(
                "UPDATE submissions SET status = ? WHERE id = ?",
                (submission_status, submission_id),
            )
            connection.execute(
                "UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?",
                (task_status, finished, current_task["id"]),
            )
            if verdict == "pass":
                reserve_until = int(time.time()) + max(3600, self.config.timeout_seconds * 3)
                connection.execute(
                    """
                    UPDATE resource_leases SET lease_expires_at = ?, updated_at = ?
                    WHERE task_id = ?
                    """,
                    (
                        reserve_until,
                        finished,
                        current_task["id"],
                    ),
                )
                connection.execute(
                    """
                    UPDATE runtime_allocations SET lease_expires_at = ?, updated_at = ?
                    WHERE attempt_id = ?
                    """,
                    (reserve_until, finished, current["attempt_id"]),
                )
            else:
                self._release_task_leases(connection, current_task["id"], finished)
            self._event(
                connection,
                "qc.completed",
                reviewer_id,
                {
                    "qc_id": qc_id,
                    "submission_id": submission_id,
                    "verdict": verdict,
                    "finding_count": len(findings),
                },
            )
        result = self.qc_run(qc_id)
        if verdict != "pass":
            result["runtime_cleanup"] = self.runtime_down(submission["attempt_id"])
        return result

    def qc_run(self, qc_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM qc_runs WHERE id = ?", (qc_id,)).fetchone()
            if not row:
                raise SupervisorError("qc_not_found", f"QC run {qc_id} not found")
            return self._qc_view(row)

    def integrate(self, task_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            task = self._task_row(connection, task_id)
            if task["status"] != "approved":
                raise SupervisorError("qc_gate_not_passed", "task is not approved")
            submission = connection.execute(
                """
                SELECT * FROM submissions
                WHERE task_id = ? AND status = 'approved'
                ORDER BY created_at DESC LIMIT 1
                """,
                (task_id,),
            ).fetchone()
            if not submission:
                raise SupervisorError("qc_evidence_missing", "approved submission is missing")
            qc = connection.execute(
                """
                SELECT * FROM qc_runs
                WHERE submission_id = ? AND verdict = 'pass'
                ORDER BY finished_at DESC LIMIT 1
                """,
                (submission["id"],),
            ).fetchone()
            if not qc or qc["commit_sha"] != submission["commit_sha"]:
                raise SupervisorError("qc_evidence_missing", "QC did not pass this commit")
            self._assert_reservations(connection, task, submission)
            runtime = connection.execute(
                "SELECT * FROM runtime_environments WHERE attempt_id = ?",
                (submission["attempt_id"],),
            ).fetchone()
            if not runtime or runtime["state"] != "ready":
                raise SupervisorError(
                    "runtime_not_ready",
                    f"submission runtime state is {runtime['state'] if runtime else 'missing'}",
                )
            runtime_env = json.loads(runtime["env_json"])
            connection.execute(
                "UPDATE tasks SET status = 'integrating', updated_at = ? WHERE id = ?",
                (utc_now(), task_id),
            )
            self._event(
                connection,
                "integration.started",
                "integration",
                {"task_id": task_id, "submission_id": submission["id"]},
            )

        integration_id = str(uuid.uuid4())
        branch = f"acp/integrate-{task_id[:8]}-{integration_id[:8]}"
        worktree = self.state_dir / "worktrees" / f"integrate-{integration_id}"
        results: list[dict[str, Any]] = []
        verdict = "failed"
        commit: str | None = None
        error_message = ""
        try:
            current_base = self._git_text("rev-parse", task["base_branch"])
            self._git("worktree", "add", "-b", branch, str(worktree), current_base)
            started = time.monotonic()
            merge = subprocess.run(
                [
                    "git",
                    "-C",
                    str(worktree),
                    "merge",
                    "--no-ff",
                    "--no-edit",
                    submission["commit_sha"],
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            results.append(
                {
                    "command": f"git merge {submission['commit_sha']}",
                    "exit_code": merge.returncode,
                    "stdout": merge.stdout[-12000:],
                    "stderr": merge.stderr[-12000:],
                    "duration_ms": int((time.monotonic() - started) * 1000),
                }
            )
            if merge.returncode:
                raise SupervisorError(
                    "merge_conflict",
                    merge.stderr.strip() or merge.stdout.strip() or "merge failed",
                )
            integration_commit = self._git_text("-C", str(worktree), "rev-parse", "HEAD")
            for command in self.config.integration_commands:
                self._restore_candidate(worktree, integration_commit)
                result = self._run_command(
                    command,
                    worktree,
                    self._phase_runtime_env(runtime_env, "integration", worktree),
                )
                results.append(result)
                if result["exit_code"]:
                    raise SupervisorError(
                        "integration_gate_failed",
                        f"integration command failed: {command}",
                    )
                if not self._worktree_matches(worktree, integration_commit):
                    raise SupervisorError(
                        "integration_gate_mutated_source",
                        f"integration command mutated tracked source: {command}",
                    )
            commit = self._git_text("-C", str(worktree), "rev-parse", "HEAD")
            verdict = "pass"
        except (OSError, subprocess.SubprocessError, SupervisorError) as error:
            error_message = str(error)
            verdict = (
                "conflict"
                if isinstance(error, SupervisorError) and error.code == "merge_conflict"
                else "failed"
            )
        created = utc_now()
        recorded = False
        try:
            with self.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                current_task = self._task_row(connection, task_id)
                reservation_valid = current_task["status"] == "integrating"
                if reservation_valid:
                    try:
                        self._assert_reservations(connection, current_task, submission)
                    except SupervisorError as error:
                        reservation_valid = False
                        error_message = str(error)
                else:
                    error_message = "task or reservation changed while integration was running"
                if not reservation_valid:
                    verdict = "stale"
                connection.execute(
                    """
                    INSERT INTO integrations
                      (id, task_id, submission_id, branch, commit_sha, verdict,
                       results_json, error, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        integration_id,
                        task_id,
                        submission["id"],
                        branch if verdict == "pass" else None,
                        commit,
                        verdict,
                        canonical_json(results),
                        error_message,
                        created,
                    ),
                )
                if current_task["status"] == "integrating":
                    connection.execute(
                        "UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?",
                        (
                            "done" if verdict == "pass" else "conflicted",
                            created,
                            task_id,
                        ),
                    )
                self._release_task_leases(connection, task_id, created)
                self._event(
                    connection,
                    "integration.completed",
                    "integration",
                    {
                        "integration_id": integration_id,
                        "task_id": task_id,
                        "verdict": verdict,
                        "commit_sha": commit,
                        "error": error_message,
                    },
                )
            recorded = True
        finally:
            if worktree.exists():
                self._remove_worktree(worktree, delete_branch=not recorded or verdict != "pass")
            elif not recorded or verdict != "pass":
                self._git("branch", "-D", branch, check=False)
        try:
            runtime_cleanup: dict[str, Any] = self.runtime_down(submission["attempt_id"])
        except (OSError, subprocess.SubprocessError, SupervisorError) as cleanup_error:
            runtime_cleanup = {
                "attempt_id": submission["attempt_id"],
                "state": "cleanup_error",
                "error": str(cleanup_error),
            }
        return {
            "id": integration_id,
            "task_id": task_id,
            "submission_id": submission["id"],
            "branch": branch if verdict == "pass" else None,
            "commit_sha": commit,
            "verdict": verdict,
            "error": error_message,
            "command_results": results,
            "runtime_cleanup": runtime_cleanup,
        }

    def run_worker(
        self,
        attempt_id: str,
        claim_token: int,
        command: Sequence[str],
    ) -> dict[str, Any]:
        if not command:
            raise SupervisorError("invalid_command", "worker command is required")
        attempt = self.heartbeat(
            attempt_id,
            claim_token,
            {"phase": "launching", "command": list(command)},
        )
        worker_env = os.environ.copy()
        worker_env.update(
            self._phase_runtime_env(
                self._runtime_env(attempt_id), "worker", Path(attempt["worktree"])
            )
        )
        log_path = self.state_dir / "logs" / f"worker-{attempt_id}.log"
        with log_path.open("ab") as log:
            process: subprocess.Popen[bytes] | None = None
            handshake_read = -1
            handshake_write = -1
            launch_reserved = False
            try:
                handshake_read, handshake_write = os.pipe()
                self._reserve_worker_launch(attempt_id, claim_token, str(log_path))
                launch_reserved = True
                trampoline = Path(__file__).with_name("worker_trampoline.py").resolve()
                process = subprocess.Popen(
                    [
                        sys.executable,
                        "-I",
                        str(trampoline),
                        str(handshake_read),
                        *command,
                    ],
                    cwd=attempt["worktree"],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                    pass_fds=(handshake_read,),
                    env=worker_env,
                )
                os.close(handshake_read)
                handshake_read = -1
                with self.connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    active = self._active_attempt(
                        connection, attempt_id, claim_token, int(time.time())
                    )
                    changed = connection.execute(
                        """
                        UPDATE attempts SET pid = ?, log_path = ?, updated_at = ?
                        WHERE id = ? AND pid = -1
                        """,
                        (process.pid, str(log_path), utc_now(), attempt_id),
                    ).rowcount
                    if changed != 1:
                        raise SupervisorError(
                            "worker_registration_lost",
                            "worker launch reservation was lost",
                        )
                    self._event(
                        connection,
                        "worker.started",
                        active["agent_id"],
                        {
                            "attempt_id": attempt_id,
                            "pid": process.pid,
                            "command": list(command),
                        },
                    )
                os.write(handshake_write, b"G")
                os.close(handshake_write)
                handshake_write = -1
                interval = max(2, min(10, self.config.lease_seconds // 3))
                while True:
                    try:
                        process.wait(timeout=interval)
                        break
                    except subprocess.TimeoutExpired:
                        self.heartbeat(
                            attempt_id,
                            claim_token,
                            {"pid": process.pid, "command": list(command)},
                        )
            except BaseException:
                for descriptor in (handshake_read, handshake_write):
                    if descriptor >= 0:
                        os.close(descriptor)
                if process is not None and process.poll() is None:
                    self._stop_process_group(process)
                if launch_reserved:
                    self._clear_worker_registration(
                        attempt_id,
                        {-1, process.pid if process is not None else -1},
                        "worker.launch_aborted",
                        process.returncode if process is not None else None,
                    )
                raise
        if process is None:
            raise SupervisorError("worker_launch_failed", "worker was not started")
        if process.returncode:
            self._clear_worker_registration(
                attempt_id,
                {process.pid},
                "worker.exited",
                process.returncode,
            )
            raise SupervisorError(
                "worker_failed",
                f"worker exited {process.returncode}; log: {log_path}",
            )
        self._record_worker_exit(attempt_id, process.pid, process.returncode)
        try:
            return self._submit(
                attempt_id,
                claim_token,
                expected_worker_pid=process.pid,
            )
        except BaseException:
            self._clear_worker_registration(
                attempt_id,
                {process.pid},
                "worker.submission_failed",
                process.returncode,
            )
            raise

    def _reserve_worker_launch(self, attempt_id: str, claim_token: int, log_path: str) -> None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            if attempt["pid"] is not None:
                raise SupervisorError(
                    "worker_already_running",
                    "this attempt already has a launching or running worker",
                )
            changed = connection.execute(
                """
                UPDATE attempts SET pid = -1, log_path = ?, updated_at = ?
                WHERE id = ? AND pid IS NULL
                """,
                (log_path, utc_now(), attempt_id),
            ).rowcount
            if changed != 1:
                raise SupervisorError(
                    "worker_already_running",
                    "this attempt already has a launching or running worker",
                )
            self._event(
                connection,
                "worker.launch_reserved",
                attempt["agent_id"],
                {"attempt_id": attempt_id, "command_log": log_path},
            )

    def _clear_worker_registration(
        self,
        attempt_id: str,
        expected_pids: set[int],
        event_type: str,
        exit_code: int | None,
    ) -> None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
            if not attempt or attempt["pid"] not in expected_pids:
                return
            connection.execute(
                "UPDATE attempts SET pid = NULL, updated_at = ? WHERE id = ?",
                (utc_now(), attempt_id),
            )
            self._event(
                connection,
                event_type,
                attempt["agent_id"],
                {"attempt_id": attempt_id, "exit_code": exit_code},
            )

    def _record_worker_exit(self, attempt_id: str, pid: int, exit_code: int) -> None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
            if not attempt or attempt["pid"] != pid:
                raise SupervisorError(
                    "worker_registration_lost",
                    "worker PID ownership changed before submission",
                )
            self._event(
                connection,
                "worker.exited",
                attempt["agent_id"],
                {
                    "attempt_id": attempt_id,
                    "pid": pid,
                    "exit_code": exit_code,
                },
            )

    def terminate_worker(self, attempt_id: str) -> dict[str, Any]:
        attempt = self.attempt(attempt_id)
        if not attempt["pid"]:
            raise SupervisorError("worker_not_running", "attempt has no running worker")
        if attempt["pid"] < 0:
            raise SupervisorError(
                "worker_launching", "worker launch is reserved but has no PID yet"
            )
        try:
            os.killpg(attempt["pid"], signal.SIGTERM)
        except ProcessLookupError as error:
            raise SupervisorError(
                "worker_not_running", "worker process no longer exists"
            ) from error
        return {"attempt_id": attempt_id, "pid": attempt["pid"], "signal": "SIGTERM"}

    @staticmethod
    def _stop_process_group(process: subprocess.Popen[bytes]) -> None:
        GitSupervisor._terminate_process_group(process)

    @staticmethod
    def _terminate_registered_group(pid: int) -> None:
        try:
            os.killpg(pid, signal.SIGTERM)
        except (PermissionError, ProcessLookupError):
            return
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.killpg(pid, 0)
            except (PermissionError, ProcessLookupError):
                return
            time.sleep(0.05)
        try:
            os.killpg(pid, signal.SIGKILL)
        except (PermissionError, ProcessLookupError):
            pass

    def doctor(self) -> dict[str, Any]:
        checks: list[dict[str, Any]] = [
            {"name": "git", "ok": shutil.which("git") is not None},
            {"name": "config", "ok": self.config_path.exists()},
        ]
        try:
            self._git_text("rev-parse", "--is-inside-work-tree")
            checks.append({"name": "repository", "ok": True})
        except SupervisorError as error:
            checks.append({"name": "repository", "ok": False, "detail": str(error)})
        try:
            with self.connect() as connection:
                integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            checks.append({"name": "sqlite", "ok": integrity == "ok", "detail": integrity})
        except sqlite3.Error as error:
            checks.append({"name": "sqlite", "ok": False, "detail": str(error)})
        with self.connect() as connection:
            runtime_rows = connection.execute(
                """
                SELECT runtime.attempt_id, runtime.state, task.status AS task_status
                FROM runtime_environments AS runtime
                JOIN attempts AS attempt ON attempt.id = runtime.attempt_id
                JOIN tasks AS task ON task.id = attempt.task_id
                ORDER BY runtime.updated_at
                """
            ).fetchall()
        active_states = {"provisioning", "working", "qc_review", "approved", "integrating"}
        unhealthy_runtime = [
            {
                "attempt_id": row["attempt_id"],
                "runtime_state": row["state"],
                "task_status": row["task_status"],
            }
            for row in runtime_rows
            if (row["task_status"] in active_states and row["state"] != "ready")
            or (row["task_status"] not in active_states and row["state"] != "released")
        ]
        checks.append(
            {
                "name": "runtime_environments",
                "ok": not unhealthy_runtime,
                "detail": unhealthy_runtime
                or f"{sum(row['state'] == 'ready' for row in runtime_rows)} active environments",
            }
        )
        checks.append({"name": "event_chain", **self.verify_event_chain()})
        return {"ok": all(check["ok"] for check in checks), "checks": checks}

    def verify_event_chain(self) -> dict[str, Any]:
        previous = GENESIS_HASH
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM events ORDER BY sequence").fetchall()
        for row in rows:
            try:
                payload = json.loads(row["payload_json"])
            except (json.JSONDecodeError, TypeError, UnicodeError):
                return {
                    "ok": False,
                    "detail": f"event payload is invalid at sequence {row['sequence']}",
                }
            material = canonical_json(
                {
                    "actor": row["actor"],
                    "created_at": row["created_at"],
                    "event_id": row["id"],
                    "event_type": row["event_type"],
                    "payload": payload,
                    "previous_hash": previous,
                }
            )
            expected = sha256(material.encode())
            if row["previous_hash"] != previous or row["event_hash"] != expected:
                return {
                    "ok": False,
                    "detail": f"event chain breaks at sequence {row['sequence']}",
                }
            previous = row["event_hash"]
        return {"ok": True, "detail": f"{len(rows)} events verified"}

    def _task_view(self, connection: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        attempt = connection.execute(
            """
            SELECT * FROM attempts WHERE task_id = ?
            ORDER BY number DESC LIMIT 1
            """,
            (row["id"],),
        ).fetchone()
        submission = connection.execute(
            """
            SELECT * FROM submissions WHERE task_id = ?
            ORDER BY created_at DESC LIMIT 1
            """,
            (row["id"],),
        ).fetchone()
        return {
            "id": row["id"],
            "title": row["title"],
            "description": row["description"],
            "acceptance": json.loads(row["acceptance_json"]),
            "resources": json.loads(row["resources_json"]),
            "dependencies": json.loads(row["dependencies_json"]),
            "base_branch": row["base_branch"],
            "base_sha": row["base_sha"],
            "priority": row["priority"],
            "status": row["status"],
            "current_attempt_id": row["current_attempt_id"],
            "latest_attempt": self._attempt_view(connection, attempt) if attempt else None,
            "latest_submission": self._submission_view(connection, submission)
            if submission
            else None,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _attempt_view(self, connection: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        leases = connection.execute(
            """
            SELECT resource, fencing_token, lease_expires_at
            FROM resource_leases WHERE attempt_id = ? ORDER BY resource
            """,
            (row["id"],),
        ).fetchall()
        runtime = connection.execute(
            "SELECT * FROM runtime_environments WHERE attempt_id = ?", (row["id"],)
        ).fetchone()
        return {
            "id": row["id"],
            "task_id": row["task_id"],
            "number": row["number"],
            "agent_id": row["agent_id"],
            "branch": row["branch"],
            "worktree": row["worktree"],
            "claim_token": row["claim_token"],
            "start_sha": row["start_sha"],
            "latest_sha": row["latest_sha"],
            "checkpoint": json.loads(row["checkpoint_json"]),
            "pid": row["pid"],
            "log_path": row["log_path"],
            "status": row["status"],
            "lease_expires_at": row["lease_expires_at"],
            "resource_leases": [dict(lease) for lease in leases],
            "runtime": self._runtime_view(connection, runtime) if runtime else None,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _runtime_view(connection: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        allocations = connection.execute(
            "SELECT pool_name, value, lease_expires_at FROM runtime_allocations "
            "WHERE attempt_id = ? ORDER BY pool_name",
            (row["attempt_id"],),
        ).fetchall()
        return {
            "attempt_id": row["attempt_id"],
            "state": row["state"],
            "environment": json.loads(row["env_json"]),
            "allocations": [dict(allocation) for allocation in allocations],
            "setup_results": json.loads(row["setup_results_json"]),
            "teardown_results": json.loads(row["teardown_results_json"]),
            "log_path": row["log_path"],
            "updated_at": row["updated_at"],
        }

    def _submission_view(self, connection: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        qc = connection.execute(
            """
            SELECT * FROM qc_runs WHERE submission_id = ?
            ORDER BY finished_at DESC LIMIT 1
            """,
            (row["id"],),
        ).fetchone()
        return {
            "id": row["id"],
            "task_id": row["task_id"],
            "attempt_id": row["attempt_id"],
            "worker_agent_id": row["worker_agent_id"],
            "commit_sha": row["commit_sha"],
            "tree_sha": row["tree_sha"],
            "patch_sha256": row["patch_sha256"],
            "changed_paths": json.loads(row["changed_paths_json"]),
            "resource_tokens": json.loads(row["resource_tokens_json"]),
            "status": row["status"],
            "latest_qc": self._qc_view(qc) if qc else None,
            "created_at": row["created_at"],
        }

    @staticmethod
    def _qc_view(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "submission_id": row["submission_id"],
            "reviewer_id": row["reviewer_id"],
            "commit_sha": row["commit_sha"],
            "verdict": row["verdict"],
            "findings": json.loads(row["findings_json"]),
            "command_results": json.loads(row["results_json"]),
            "review_packet_sha256": row["packet_sha256"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
        }

    @staticmethod
    def _task_row(connection: sqlite3.Connection, task_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not row:
            raise SupervisorError("task_not_found", f"task {task_id} not found")
        return row

    @staticmethod
    def _submission_row(connection: sqlite3.Connection, submission_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM submissions WHERE id = ?", (submission_id,)
        ).fetchone()
        if not row:
            raise SupervisorError("submission_not_found", f"submission {submission_id} not found")
        return row

    @staticmethod
    def _active_attempt(
        connection: sqlite3.Connection,
        attempt_id: str,
        claim_token: int,
        epoch: int,
    ) -> sqlite3.Row:
        attempt = connection.execute(
            "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
        ).fetchone()
        if not attempt:
            raise SupervisorError("attempt_not_found", f"attempt {attempt_id} not found")
        if attempt["status"] != "working":
            raise SupervisorError("claim_inactive", f"attempt status is {attempt['status']}")
        if attempt["claim_token"] != claim_token:
            raise SupervisorError("stale_fencing_token", "claim token is stale")
        if attempt["lease_expires_at"] <= epoch:
            raise SupervisorError("lease_expired", "claim lease expired")
        task = connection.execute(
            "SELECT * FROM tasks WHERE id = ?", (attempt["task_id"],)
        ).fetchone()
        if not task or task["current_attempt_id"] != attempt_id or task["status"] != "working":
            raise SupervisorError("claim_inactive", "task no longer owns this attempt")
        return attempt

    def _assert_reservations(
        self,
        connection: sqlite3.Connection,
        task: sqlite3.Row,
        submission: sqlite3.Row,
    ) -> None:
        expected = json.loads(submission["resource_tokens_json"])
        rows = connection.execute(
            "SELECT * FROM resource_leases WHERE task_id = ?", (task["id"],)
        ).fetchall()
        actual = {
            row["resource"]: row["fencing_token"]
            for row in rows
            if row["lease_expires_at"] > int(time.time())
        }
        if actual != expected:
            raise SupervisorError(
                "reservation_lost",
                "resource reservation or fencing token changed",
            )

    @staticmethod
    def _release_task_leases(connection: sqlite3.Connection, task_id: str, stamp: str) -> None:
        connection.execute(
            """
            UPDATE resource_leases SET task_id = NULL, attempt_id = NULL,
              lease_expires_at = 0, updated_at = ? WHERE task_id = ?
            """,
            (stamp, task_id),
        )

    @staticmethod
    def _path_matches(path: str, resource: str) -> bool:
        candidate = unicodedata.normalize("NFC", PurePosixPath(path).as_posix()).casefold()
        if resource.startswith("logical:"):
            return False
        if resource.endswith("/**"):
            prefix = resource[:-3].rstrip("/")
            return candidate == prefix or candidate.startswith(prefix + "/")
        if any(character in resource for character in "*?["):
            return PurePosixPath(candidate).match(resource)
        return candidate == resource

    def _restore_candidate(self, worktree: Path, commit_sha: str) -> None:
        self._git("-C", str(worktree), "reset", "--hard", commit_sha)
        self._git("-C", str(worktree), "clean", "-fdx")

    def _worktree_matches(self, worktree: Path, commit_sha: str) -> bool:
        head = self._git_text("-C", str(worktree), "rev-parse", "HEAD", check=False)
        unstaged = self._git(
            "-C",
            str(worktree),
            "diff",
            "--quiet",
            commit_sha,
            "--",
            check=False,
        )
        staged = self._git(
            "-C",
            str(worktree),
            "diff",
            "--cached",
            "--quiet",
            commit_sha,
            "--",
            check=False,
        )
        return head == commit_sha and unstaged.returncode == 0 and staged.returncode == 0

    def _assert_safe_symlink(self, worktree: Path, commit_sha: str, path: str) -> None:
        listing = self._git_text(
            "-C", str(worktree), "ls-tree", commit_sha, "--", path, check=False
        )
        if not listing.startswith("120000 "):
            return
        target = self._git_text("-C", str(worktree), "show", f"{commit_sha}:{path}")
        resolved = (worktree / path).parent.joinpath(target).resolve()
        try:
            resolved.relative_to(worktree.resolve())
        except ValueError as error:
            raise SupervisorError(
                "symlink_escape", f"symlink {path} points outside its worktree"
            ) from error

    def _review_packet(
        self,
        task: sqlite3.Row,
        submission: sqlite3.Row,
        worktree: Path,
    ) -> dict[str, Any]:
        diff_stat = self._git_text(
            "-C",
            str(worktree),
            "diff",
            "--stat",
            task["base_sha"],
            submission["commit_sha"],
        )
        commits = self._git_text(
            "-C",
            str(worktree),
            "log",
            "--format=%H %s",
            f"{task['base_sha']}..{submission['commit_sha']}",
        )
        return {
            "task": {
                "id": task["id"],
                "title": task["title"],
                "description": task["description"],
                "acceptance": json.loads(task["acceptance_json"]),
                "declared_resources": json.loads(task["resources_json"]),
                "base_sha": task["base_sha"],
            },
            "submission": {
                "id": submission["id"],
                "commit_sha": submission["commit_sha"],
                "tree_sha": submission["tree_sha"],
                "patch_sha256": submission["patch_sha256"],
                "changed_paths": json.loads(submission["changed_paths_json"]),
                "commits": commits.splitlines(),
                "diff_stat": diff_stat,
            },
            "policy": {
                "inspect_repository": True,
                "reproduce_acceptance": True,
                "worker_conclusions_excluded": True,
            },
        }

    def _run_command(
        self,
        command: str,
        cwd: Path,
        extra_env: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        env = os.environ.copy()
        env.update(extra_env or {})
        return self._run_process(["/bin/sh", "-lc", command], command, cwd, env)

    def _run_critic(
        self,
        command: str,
        cwd: Path,
        extra_env: dict[str, str],
    ) -> dict[str, Any]:
        if command != "builtin":
            env = os.environ.copy()
            env.update(extra_env)
            return self._run_process([command], command, cwd, env)
        env = os.environ.copy()
        env.update(extra_env)
        critic_path = Path(__file__).with_name("critic.py").resolve()
        return self._run_process(
            [sys.executable, "-I", str(critic_path)],
            "builtin:structural-critic",
            cwd,
            env,
        )

    def _run_process(
        self,
        arguments: Sequence[str],
        label: str,
        cwd: Path,
        env: dict[str, str],
    ) -> dict[str, Any]:
        started = time.monotonic()
        process = subprocess.Popen(
            list(arguments),
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        timed_out = False
        try:
            stdout, stderr = process.communicate(timeout=self.config.timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._terminate_process_group(process)
            stdout, stderr = process.communicate()
        return {
            "command": label,
            "exit_code": 124 if timed_out else process.returncode,
            "stdout": stdout[-12000:],
            "stderr": stderr[-12000:],
            "duration_ms": int((time.monotonic() - started) * 1000),
        }

    @staticmethod
    def _terminate_process_group(
        process: subprocess.Popen[Any],
    ) -> None:
        descendants = GitSupervisor._descendant_pids(process.pid)
        for pid in reversed(descendants):
            try:
                os.kill(pid, signal.SIGTERM)
            except (PermissionError, ProcessLookupError):
                pass
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=2)
        except PermissionError:
            try:
                process.terminate()
                process.wait(timeout=2)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                process.kill()
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (PermissionError, ProcessLookupError):
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
        for pid in reversed(descendants):
            try:
                os.kill(pid, signal.SIGKILL)
            except (PermissionError, ProcessLookupError):
                pass

    @staticmethod
    def _descendant_pids(root_pid: int) -> list[int]:
        result = subprocess.run(
            ["ps", "-axo", "pid=,ppid="],
            capture_output=True,
            text=True,
            check=False,
        )
        children: dict[int, list[int]] = {}
        for line in result.stdout.splitlines():
            try:
                pid, parent = map(int, line.split())
            except (TypeError, ValueError):
                continue
            children.setdefault(parent, []).append(pid)
        descendants: list[int] = []
        pending = list(children.get(root_pid, []))
        while pending:
            pid = pending.pop()
            descendants.append(pid)
            pending.extend(children.get(pid, []))
        return descendants

    @staticmethod
    def _command_finding(command: str, result: dict[str, Any]) -> dict[str, str]:
        output = (result["stderr"] or result["stdout"]).strip()[-2000:]
        return {
            "severity": "high",
            "requirement": "deterministic QC command passes",
            "finding": f"command failed: {command}",
            "evidence": f"exit={result['exit_code']}; {output}",
            "required_fix": "fix the failure and submit a new committed attempt",
        }

    @staticmethod
    def _critic_payload(path: Path) -> dict[str, Any]:
        if not path.is_file():
            raise SupervisorError(
                "invalid_critic_output",
                "critic did not create its unique result file",
            )
        raw = path.read_text(encoding="utf-8")
        payload = json.loads(raw)
        verdicts = {"pass", "revise", "block", "human_required"}
        if not isinstance(payload, dict) or payload.get("verdict") not in verdicts:
            raise SupervisorError("invalid_critic_output", "critic verdict is invalid")
        findings = payload.get("findings", [])
        required = {
            "severity",
            "requirement",
            "finding",
            "evidence",
            "required_fix",
        }
        severities = {"critical", "high", "medium", "low", "info"}
        if not isinstance(findings, list):
            raise SupervisorError("invalid_critic_output", "critic findings must be a list")
        for finding in findings:
            if (
                not isinstance(finding, dict)
                or not required.issubset(finding)
                or finding.get("severity") not in severities
            ):
                raise SupervisorError("invalid_critic_output", "critic finding is invalid")
        if payload["verdict"] in {"revise", "block"} and not findings:
            raise SupervisorError("invalid_critic_output", "negative verdict requires findings")
        return {"verdict": payload["verdict"], "findings": findings}

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

    def _git_text(self, *arguments: str, check: bool = True) -> str:
        result = subprocess.run(
            ["git", "-C", str(self.root), *arguments],
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
        result = subprocess.run(
            ["git", "-C", str(self.root), *arguments],
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
        result = subprocess.run(
            ["git", "-C", str(self.root), *arguments],
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
