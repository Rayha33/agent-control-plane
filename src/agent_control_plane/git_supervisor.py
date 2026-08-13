from __future__ import annotations

import errno
import fcntl
import hashlib
import hmac
import json
import os
import re
import shutil
import signal
import socket
import sqlite3
import stat
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

from .assurance import REJECT_VERDICTS, Assurance, Reviewer, load_policy
from .credential_providers import (
    CredentialDefinition,
    CredentialError,
    CredentialHandle,
    CredentialRegistry,
    parse_credential_definitions,
)
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
    resolve_trusted_executable,
    run_trusted,
)
from .scheduling import Scheduler, normalize_artifact
from .status import DEFAULT_LEASE_RISK_SECONDS, StatusView
from .trust_bundles import (
    TrustBundleError,
    executable_from_pin,
    load_current_bundle,
    verify_bundle_pin,
)

GENESIS_HASH = "0" * 64
SUPERVISOR_SECRET_ENV = {"ACP_RUNNER_CREDENTIAL"}
PUBLIC_CHILD_ENV = {
    "HOME",
    "LANG",
    "LC_ALL",
    "LOGNAME",
    "PATH",
    "SHELL",
    "TERM",
    "TMPDIR",
    "USER",
}


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
    credentials: tuple[CredentialDefinition, ...]
    runtime_drivers: tuple[DriverDefinition, ...]
    runtime_driver_entries: tuple[dict[str, Any], ...]
    critic_selector: str
    trust_root: Path | None
    trust_owner_uid: int


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
  produces_json TEXT NOT NULL DEFAULT '[]',
  consumes_json TEXT NOT NULL DEFAULT '[]',
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
  runner_credential_digest TEXT,
  branch TEXT NOT NULL,
  worktree TEXT NOT NULL,
  claim_token INTEGER NOT NULL,
  start_sha TEXT NOT NULL,
  latest_sha TEXT,
  checkpoint_json TEXT NOT NULL,
  trust_bundle_json TEXT NOT NULL DEFAULT '{}',
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
  reviewer_provenance_json TEXT NOT NULL DEFAULT '{}',
  reviewer_signature TEXT NOT NULL DEFAULT '',
  bundle_sha256 TEXT NOT NULL DEFAULT '',
  policy_fingerprint TEXT NOT NULL DEFAULT '',
  trust_bundle_json TEXT NOT NULL DEFAULT '{}',
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS calibration_runs (
  id TEXT PRIMARY KEY,
  policy_fingerprint TEXT NOT NULL,
  reviewer_id TEXT NOT NULL,
  results_json TEXT NOT NULL,
  summary_json TEXT NOT NULL,
  created_at TEXT NOT NULL
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
  restart_token TEXT NOT NULL DEFAULT '',
  restart_started_at INTEGER NOT NULL DEFAULT 0,
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
  definition_json TEXT NOT NULL DEFAULT '{}',
  credential_handle_json TEXT NOT NULL DEFAULT '{}',
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
    def __init__(self, repo: str | Path = ".", *, diagnostic: bool = False):
        self.root = self._root(Path(repo).resolve())
        self._diagnostic = diagnostic
        self._trust_config_error: str | None = None
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
            self._migrate(connection)
            connection.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('claim_counter', '0')"
            )
            attempt_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(attempts)")
            }
            if "runner_credential_digest" not in attempt_columns:
                connection.execute("ALTER TABLE attempts ADD COLUMN runner_credential_digest TEXT")
            driver_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(runtime_driver_resources)")
            }
            if "definition_json" not in driver_columns:
                connection.execute(
                    "ALTER TABLE runtime_driver_resources "
                    "ADD COLUMN definition_json TEXT NOT NULL DEFAULT '{}'"
                )
            if "credential_handle_json" not in driver_columns:
                connection.execute(
                    "ALTER TABLE runtime_driver_resources "
                    "ADD COLUMN credential_handle_json TEXT NOT NULL DEFAULT '{}'"
                )
            runtime_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(runtime_environments)")
            }
            if "restart_token" not in runtime_columns:
                connection.execute(
                    "ALTER TABLE runtime_environments "
                    "ADD COLUMN restart_token TEXT NOT NULL DEFAULT ''"
                )
            if "restart_started_at" not in runtime_columns:
                connection.execute(
                    "ALTER TABLE runtime_environments "
                    "ADD COLUMN restart_started_at INTEGER NOT NULL DEFAULT 0"
                )
            # Upgrade registries created before the explicit flag existed. Once
            # enabled, authentication never silently downgrades because the last
            # credential was revoked.
            if connection.execute("SELECT 1 FROM runner_identities LIMIT 1").fetchone():
                connection.execute(
                    "INSERT OR IGNORE INTO meta(key, value) VALUES('runner_auth_enabled', '1')"
                )

    @staticmethod
    def _migrate(connection: sqlite3.Connection) -> None:
        """Add columns introduced after a database was first created.

        CREATE TABLE IF NOT EXISTS silently leaves an older table alone, so new
        columns have to be added explicitly. Each step is idempotent.
        """
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(tasks)").fetchall()}
        for column in ("produces_json", "consumes_json"):
            if column not in columns:
                connection.execute(
                    f"ALTER TABLE tasks ADD COLUMN {column} TEXT NOT NULL DEFAULT '[]'"
                )
        attempt_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(attempts)").fetchall()
        }
        if "trust_bundle_json" not in attempt_columns:
            connection.execute(
                "ALTER TABLE attempts ADD COLUMN trust_bundle_json TEXT NOT NULL DEFAULT '{}'"
            )
        qc_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(qc_runs)").fetchall()
        }
        for column, default in (
            ("reviewer_provenance_json", "'{}'"),
            ("reviewer_signature", "''"),
            ("bundle_sha256", "''"),
            ("policy_fingerprint", "''"),
            ("trust_bundle_json", "'{}'"),
        ):
            if column not in qc_columns:
                connection.execute(
                    f"ALTER TABLE qc_runs ADD COLUMN {column} TEXT NOT NULL DEFAULT {default}"
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

    def _resolve_critic_command(
        self, critic_command: str, trust_pin: dict[str, Any] | None = None
    ) -> str:
        """Every reviewer command obeys the same rule: `builtin`, or one absolute
        executable outside the candidate worktree so a candidate cannot replace it."""
        if not critic_command or critic_command == "builtin":
            return critic_command
        if critic_command.startswith("trusted:"):
            if trust_pin is None:
                raise SupervisorError(
                    "invalid_config", "trusted: commands require a configured trust bundle"
                )
            name = critic_command.removeprefix("trusted:")
            try:
                return str(executable_from_pin(trust_pin, name))
            except TrustBundleError as error:
                raise SupervisorError(error.code, error.message) from error
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
        try:
            return str(resolve_trusted_executable(str(critic_path), self.root))
        except DriverError as error:
            raise SupervisorError(error.code, error.message) from error

    def _load_config(self) -> Config:
        with self.config_path.open("rb") as handle:
            raw = tomllib.load(handle)
        supervisor = raw.get("supervisor", {})
        qc = raw.get("qc", {})
        integration = raw.get("integration", {})
        runtime = raw.get("runtime", {})
        trust = raw.get("trust")
        if trust is not None and not isinstance(trust, dict):
            raise SupervisorError("invalid_config", "trust must be a table")
        trust_root: Path | None = None
        trust_owner_uid = 0
        trust_pin: dict[str, Any] | None = None
        if trust is not None:
            root_value = str(trust.get("root", "")).strip()
            if not root_value:
                raise SupervisorError("invalid_config", "trust.root must be an absolute path")
            trust_root = Path(root_value).expanduser()
            if not trust_root.is_absolute():
                raise SupervisorError("invalid_config", "trust.root must be an absolute path")
            trust_owner_uid = int(trust.get("owner_uid", 0))
            try:
                trust_pin = load_current_bundle(trust_root, owner_uid=trust_owner_uid)
            except TrustBundleError as error:
                if not self._diagnostic:
                    raise SupervisorError(error.code, error.message) from error
                self._trust_config_error = f"{error.code}: {error.message}"
        lease = int(supervisor.get("lease_seconds", 300))
        timeout = int(supervisor.get("qc_timeout_seconds", 900))
        if lease < 10 or timeout < 1:
            raise SupervisorError("invalid_config", "lease must be >= 10 and timeout >= 1")
        qc_commands = tuple(map(str, qc.get("commands", [])))
        integration_commands = tuple(map(str, integration.get("commands", qc.get("commands", []))))
        critic_selector = str(qc.get("critic_command", "")).strip()
        require_critic = bool(supervisor.get("require_critic", False))
        if not qc_commands or any(not command.strip() for command in qc_commands):
            raise SupervisorError(
                "invalid_config",
                "every deterministic QC gate must contain a command",
            )
        if not integration_commands or any(not command.strip() for command in integration_commands):
            raise SupervisorError("invalid_config", "every integration gate must contain a command")
        if require_critic and not critic_selector:
            raise SupervisorError(
                "invalid_config", "require_critic needs a non-empty critic_command"
            )
        if self._diagnostic and trust_pin is None and critic_selector.startswith("trusted:"):
            critic_command = critic_selector
        else:
            critic_command = self._resolve_critic_command(critic_selector, trust_pin)
        runtime_setup_commands = tuple(map(str, runtime.get("setup_commands", [])))
        runtime_teardown_commands = tuple(map(str, runtime.get("teardown_commands", [])))
        raw_credentials = raw.get("credentials", [])
        if not isinstance(raw_credentials, list):
            raise SupervisorError("invalid_config", "credentials must be an array of tables")
        try:
            credentials = parse_credential_definitions(raw_credentials, self.root)
        except CredentialError as error:
            raise SupervisorError(error.code, error.message) from error
        # Drivers are validated here, against the supervisor's OWN acp.toml at the
        # repository root — never a copy inside a candidate worktree.
        raw_drivers = runtime.get("drivers", [])
        if not isinstance(raw_drivers, list):
            raise SupervisorError("invalid_config", "runtime.drivers must be an array of tables")
        if any(not isinstance(entry, dict) for entry in raw_drivers):
            raise SupervisorError("invalid_config", "each runtime driver must be a table")
        driver_entries = tuple(dict(entry) for entry in raw_drivers)
        resolved_driver_entries: list[dict[str, Any]] = []
        for entry in driver_entries:
            resolved = dict(entry)
            executable = str(resolved.get("executable", ""))
            if executable.startswith("trusted:") and not (self._diagnostic and trust_pin is None):
                resolved["executable"] = self._resolve_critic_command(executable, trust_pin)
            resolved_driver_entries.append(resolved)
        if (
            self._diagnostic
            and trust_pin is None
            and any(
                str(entry.get("executable", "")).startswith("trusted:") for entry in driver_entries
            )
        ):
            runtime_drivers = ()
        else:
            try:
                runtime_drivers = parse_driver_definitions(
                    resolved_driver_entries,
                    self.root,
                    credential_names={item.name for item in credentials},
                    expected_owners={0, trust_owner_uid} if trust_pin else None,
                )
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
        # Loaded here so a reviewer's command obeys the same trust rule as the
        # legacy single critic, and so a bad policy fails at construction.
        policy = load_policy(
            raw, str(supervisor.get("critic_identity", "")).strip(), critic_selector
        )
        # Validate every declared command now, but retain its logical selector
        # in policy provenance. A safe bundle rotation must not silently mutate
        # the reviewer-policy fingerprint.
        for reviewer in policy.reviewers:
            if not (
                self._diagnostic and trust_pin is None and reviewer.command.startswith("trusted:")
            ):
                self._resolve_critic_command(reviewer.command, trust_pin)
        self.assurance_policy = policy
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
            credentials=credentials,
            runtime_drivers=runtime_drivers,
            runtime_driver_entries=driver_entries,
            critic_selector=critic_selector,
            trust_root=trust_root,
            trust_owner_uid=trust_owner_uid,
        )

    def _current_trust_pin(self) -> dict[str, Any]:
        if self.config.trust_root is None:
            return {}
        try:
            return load_current_bundle(
                self.config.trust_root, owner_uid=self.config.trust_owner_uid
            )
        except TrustBundleError as error:
            raise SupervisorError(error.code, error.message) from error

    def _driver_definitions_for_pin(
        self, pin: dict[str, Any] | None
    ) -> tuple[DriverDefinition, ...]:
        entries: list[dict[str, Any]] = []
        for configured in self.config.runtime_driver_entries:
            entry = dict(configured)
            selector = str(entry.get("executable", ""))
            if selector.startswith("trusted:"):
                entry["executable"] = self._resolve_critic_command(selector, pin)
            entries.append(entry)
        try:
            return parse_driver_definitions(
                entries,
                self.root,
                credential_names={item.name for item in self.config.credentials},
                expected_owners={0, self.config.trust_owner_uid} if pin else None,
            )
        except DriverError as error:
            raise SupervisorError(error.code, error.message) from error

    def _attempt_trust_pin(self, attempt_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT trust_bundle_json FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
        if not row:
            raise SupervisorError("attempt_not_found", f"attempt {attempt_id} not found")
        try:
            value = json.loads(row["trust_bundle_json"] or "{}")
        except (json.JSONDecodeError, TypeError) as error:
            self._quarantine_trust_attempt(attempt_id, ["stored trust pin is invalid JSON"])
            raise SupervisorError(
                "trust_bundle_invalid", "stored trust pin is invalid JSON"
            ) from error
        if not isinstance(value, dict):
            self._quarantine_trust_attempt(attempt_id, ["stored trust pin is not an object"])
            raise SupervisorError("trust_bundle_invalid", "stored trust pin is not an object")
        return value

    def _quarantine_trust_attempt(self, attempt_id: str, errors: Sequence[str]) -> None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._quarantine_trust_attempt_in(connection, attempt_id, errors)

    def _quarantine_trust_attempt_in(
        self,
        connection: sqlite3.Connection,
        attempt_id: str,
        errors: Sequence[str],
    ) -> None:
        """Quarantine a pin inside the caller's finalization transaction."""

        stamp = utc_now()
        attempt = connection.execute(
            "SELECT task_id FROM attempts WHERE id = ?", (attempt_id,)
        ).fetchone()
        if not attempt:
            return
        connection.execute(
            "UPDATE attempts SET status = 'quarantined', pid = NULL, updated_at = ? WHERE id = ?",
            (stamp, attempt_id),
        )
        connection.execute(
            "UPDATE tasks SET status = 'blocked', updated_at = ? WHERE id = ?",
            (stamp, attempt["task_id"]),
        )
        connection.execute(
            "UPDATE runtime_environments SET state = 'teardown_failed', updated_at = ? "
            "WHERE attempt_id = ?",
            (stamp, attempt_id),
        )
        connection.execute(
            "UPDATE runtime_driver_resources SET state = 'quarantined', updated_at = ? "
            "WHERE attempt_id = ?",
            (stamp, attempt_id),
        )
        self._event(
            connection,
            "trust_bundle.quarantined",
            "supervisor",
            {"attempt_id": attempt_id, "errors": list(errors)},
        )

    def _verify_attempt_trust_in(
        self,
        connection: sqlite3.Connection,
        attempt_id: str,
    ) -> dict[str, Any]:
        """Verify the exact pin while fencing a final state transition."""

        row = connection.execute(
            "SELECT trust_bundle_json FROM attempts WHERE id = ?", (attempt_id,)
        ).fetchone()
        if not row:
            raise SupervisorError("attempt_not_found", f"attempt {attempt_id} not found")
        try:
            pin = json.loads(row["trust_bundle_json"] or "{}")
        except (json.JSONDecodeError, TypeError) as error:
            errors = ["stored trust pin is invalid JSON"]
            self._quarantine_trust_attempt_in(connection, attempt_id, errors)
            raise SupervisorError("trust_bundle_invalid", errors[0]) from error
        if not isinstance(pin, dict):
            errors = ["stored trust pin is not an object"]
            self._quarantine_trust_attempt_in(connection, attempt_id, errors)
            raise SupervisorError("trust_bundle_invalid", errors[0])
        if not pin:
            if self.config.trust_root is not None:
                errors = ["attempt has no trust pin; refusing to adopt the current bundle"]
                self._quarantine_trust_attempt_in(connection, attempt_id, errors)
                raise SupervisorError("trust_bundle_quarantined", errors[0])
            return {}
        result = verify_bundle_pin(pin)
        if result["ok"]:
            return pin
        self._quarantine_trust_attempt_in(connection, attempt_id, result["errors"])
        raise SupervisorError(
            "trust_bundle_quarantined",
            "pinned trust bundle failed: " + "; ".join(result["errors"]),
        )

    def _verify_attempt_trust(self, attempt_id: str) -> dict[str, Any]:
        pin = self._attempt_trust_pin(attempt_id)
        if not pin:
            if self.config.trust_root is not None:
                errors = ["attempt has no trust pin; refusing to adopt the current bundle"]
                self._quarantine_trust_attempt(attempt_id, errors)
                raise SupervisorError("trust_bundle_quarantined", errors[0])
            return {}
        result = verify_bundle_pin(pin)
        if result["ok"]:
            return pin
        self._quarantine_trust_attempt(attempt_id, result["errors"])
        raise SupervisorError(
            "trust_bundle_quarantined",
            "pinned trust bundle failed: " + "; ".join(result["errors"]),
        )

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA secure_delete = ON")
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
        produces: Sequence[str] = (),
        consumes: Sequence[str] = (),
    ) -> dict[str, Any]:
        if not title.strip() or not acceptance:
            raise SupervisorError("invalid_task", "title and acceptance criteria are required")
        normalized = sorted({self.normalize_resource(item, self.root) for item in resources})
        if not normalized:
            raise SupervisorError("invalid_task", "at least one write resource is required")
        produced = sorted({normalize_artifact(item) for item in produces})
        consumed = sorted({normalize_artifact(item) for item in consumes})
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
                   dependencies_json, produces_json, consumes_json, base_branch,
                   base_sha, priority, status, current_attempt_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', NULL, ?, ?)
                """,
                (
                    task_id,
                    title.strip(),
                    description.strip(),
                    canonical_json(list(acceptance)),
                    canonical_json(normalized),
                    canonical_json(list(dependencies)),
                    canonical_json(produced),
                    canonical_json(consumed),
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
                {
                    "task_id": task_id,
                    "resources": normalized,
                    "produces": produced,
                    "consumes": consumed,
                    "base_sha": base_sha,
                },
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

    def plan_claim(self, task_id: str) -> dict[str, Any]:
        """Dry-run a claim. Read-only: it never reaps, claims, or provisions."""
        return Scheduler(self).plan_claim(task_id)

    def ready_queue(self) -> dict[str, Any]:
        """Deterministic launch plan for every claimable task. Read-only."""
        return Scheduler(self).ready_queue()

    def merge_plan(self) -> dict[str, Any]:
        """Integration ordering preview for approved submissions. Read-only."""
        return Scheduler(self).merge_plan()

    @property
    def assurance(self) -> Assurance:
        return Assurance(self)

    def reviewers(self) -> dict[str, Any]:
        """Declared reviewers, the policy fingerprint, and whether it is ratified."""
        ratified = self.assurance.ratified_fingerprint()
        described = self.assurance_policy.describe()
        return {
            **described,
            "ratified_fingerprint": ratified,
            "ratified": ratified == described["fingerprint"],
        }

    def ratify_reviewers(
        self,
        integrator_id: str = "integration",
        credential: str | None = None,
    ) -> dict[str, Any]:
        """Accept the current evaluation policy under integrator authority.

        Ratification changes which reviewer evidence can release code, so it is
        a privileged transition rather than a read-only operator convenience.
        """
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._authenticate(integrator_id, "integrator", credential, connection)
            return self.assurance.ratify(integrator_id, connection)

    def _policy_reviewer(self, reviewer_id: str) -> Reviewer | None:
        reviewer = self.assurance_policy.reviewer(reviewer_id)
        if reviewer is not None:
            return reviewer
        if reviewer_id == self.config.critic_identity:
            return Reviewer(
                identity=reviewer_id,
                provider="unknown",
                model="unknown",
                prompt_policy="unset",
                command=self.config.critic_selector,
            )
        return None

    def _current_policy_passes(
        self,
        connection: sqlite3.Connection,
        submission: sqlite3.Row | dict[str, Any],
    ) -> list[dict[str, str]]:
        """Return unique passes made by the current declared reviewer versions."""
        attempt = connection.execute(
            "SELECT trust_bundle_json FROM attempts WHERE id = ?",
            (submission["attempt_id"],),
        ).fetchone()
        if not attempt:
            return []
        try:
            expected_trust_pin = json.loads(attempt["trust_bundle_json"] or "{}")
        except (json.JSONDecodeError, TypeError):
            return []
        rows = connection.execute(
            """
            SELECT reviewer_id, reviewer_provenance_json, trust_bundle_json FROM qc_runs
            WHERE submission_id = ? AND commit_sha = ? AND verdict = 'pass'
              AND policy_fingerprint = ?
            ORDER BY finished_at
            """,
            (
                submission["id"],
                submission["commit_sha"],
                self.assurance_policy.fingerprint,
            ),
        ).fetchall()
        passes: list[dict[str, str]] = []
        seen: set[str] = set()
        for row in rows:
            reviewer_id = row["reviewer_id"]
            reviewer = self._policy_reviewer(reviewer_id)
            if reviewer is None or reviewer_id in seen:
                continue
            try:
                provenance = json.loads(row["reviewer_provenance_json"] or "{}")
                review_trust_pin = json.loads(row["trust_bundle_json"] or "{}")
            except (json.JSONDecodeError, TypeError):
                continue
            if provenance != reviewer.provenance() or review_trust_pin != expected_trust_pin:
                continue
            passes.append({"reviewer_id": reviewer_id, "provider": reviewer.provider})
            seen.add(reviewer_id)
        return passes

    def _submission_assurance(
        self,
        connection: sqlite3.Connection,
        submission: sqlite3.Row | dict[str, Any],
    ) -> dict[str, Any]:
        current = self.assurance_policy.fingerprint
        ratified = self.assurance.ratified_fingerprint(connection)
        if ratified != current:
            return {
                "ready": False,
                "policy_fingerprint": current,
                "ratified_fingerprint": ratified,
                "passes": [],
                "blocker": "reviewer_policy_changed",
                "reason": "the current reviewer policy has not been ratified",
            }
        passes = self._current_policy_passes(connection, submission)
        if not passes:
            return {
                "ready": False,
                "policy_fingerprint": current,
                "ratified_fingerprint": ratified,
                "passes": [],
                "blocker": "qc_policy_stale",
                "reason": "no passing review matches this commit and current reviewer policy",
            }
        requirement = self.assurance.review_requirement(
            json.loads(submission["changed_paths_json"]), passes
        )
        if requirement["high_risk"] and not requirement["satisfied"]:
            return {
                "ready": False,
                "policy_fingerprint": current,
                "ratified_fingerprint": ratified,
                "passes": passes,
                "blocker": "qc_assurance_incomplete",
                "reason": requirement["reason"],
            }
        return {
            "ready": True,
            "policy_fingerprint": current,
            "ratified_fingerprint": ratified,
            "passes": passes,
            "blocker": None,
            "reason": "",
        }

    def _assert_submission_assurance(
        self,
        connection: sqlite3.Connection,
        submission: sqlite3.Row | dict[str, Any],
    ) -> dict[str, Any]:
        assurance = self._submission_assurance(connection, submission)
        if not assurance["ready"]:
            raise SupervisorError(assurance["blocker"], assurance["reason"])
        return assurance

    def calibrate(self, reviewer_id: str | None = None) -> dict[str, Any]:
        """Measure the reviewer against repository-specific golden cases.

        Each case is materialised in a detached worktree at HEAD, mutated to
        seed a known defect (or left clean), and handed to the *real* configured
        critic through the same entry point QC uses. Anything else would measure
        a simulation of the reviewer rather than the reviewer.
        """
        reviewer = self._calibration_reviewer(reviewer_id)
        self.assurance.assert_policy_ratified()
        cases = self.assurance.golden_cases()
        if not cases:
            raise SupervisorError(
                "no_golden_cases",
                f"no golden cases in {self.assurance_policy.golden_dir}/; "
                "add *.toml cases with an expected verdict",
            )
        head = self._git_text("rev-parse", "HEAD")
        results: list[dict[str, Any]] = []
        for case in cases:
            worktree = self.state_dir / "worktrees" / f"golden-{uuid.uuid4().hex}"
            packet_path = self.state_dir / "logs" / f"golden-{uuid.uuid4().hex}.json"
            result_path = self.state_dir / "logs" / f"golden-result-{uuid.uuid4().hex}.json"
            verdict = "block"
            error = ""
            touched: list[str] = []
            try:
                self._git("worktree", "add", "--detach", str(worktree), head)
                touched = self.assurance.apply_mutations(worktree, case.mutations)
                packet_path.write_text(
                    json.dumps(self._golden_packet(case, head, touched), indent=2),
                    encoding="utf-8",
                )
                critic = self._run_critic(
                    reviewer.command or "builtin",
                    worktree,
                    {
                        "ACP_PHASE": "calibration",
                        "ACP_WORKTREE": str(worktree),
                        "ACP_REPO_ROOT": str(self.root),
                        "ACP_REVIEW_PACKET": str(packet_path),
                        "ACP_REVIEW_RESULT": str(result_path),
                    },
                )
                if critic["exit_code"]:
                    error = f"critic exited {critic['exit_code']}"
                else:
                    verdict = self._critic_payload(result_path)["verdict"]
            except (OSError, subprocess.SubprocessError, SupervisorError, ValueError) as failure:
                error = str(failure)
            finally:
                result_path.unlink(missing_ok=True)
                packet_path.unlink(missing_ok=True)
                if worktree.exists():
                    self._remove_worktree(worktree, delete_branch=False)
            results.append(
                {
                    "name": case.name,
                    "description": case.description,
                    "expected": case.expect,
                    "verdict": verdict,
                    "rejected": verdict in REJECT_VERDICTS,
                    "correct": (verdict in REJECT_VERDICTS) == case.expects_rejection,
                    "mutated_paths": touched,
                    "error": error,
                }
            )
        summary = self.assurance.summarize(results)
        calibration_id = str(uuid.uuid4())
        created = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO calibration_runs
                  (id, policy_fingerprint, reviewer_id, results_json, summary_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    calibration_id,
                    self.assurance_policy.fingerprint,
                    reviewer.identity,
                    canonical_json(results),
                    canonical_json(summary),
                    created,
                ),
            )
            self._event(
                connection,
                "calibration.completed",
                reviewer.identity,
                {
                    "calibration_id": calibration_id,
                    "fingerprint": self.assurance_policy.fingerprint,
                    "summary": summary,
                },
            )
        return {
            "id": calibration_id,
            "reviewer": reviewer.provenance(),
            "policy_fingerprint": self.assurance_policy.fingerprint,
            "created_at": created,
            "results": results,
            "summary": summary,
        }

    def _calibration_reviewer(self, reviewer_id: str | None) -> Reviewer:
        if reviewer_id:
            reviewer = self.assurance_policy.reviewer(reviewer_id)
            if reviewer is None:
                raise SupervisorError(
                    "reviewer_identity_mismatch", f"{reviewer_id} is not a declared reviewer"
                )
            return reviewer
        if self.assurance_policy.reviewers:
            return self.assurance_policy.reviewers[0]
        return Reviewer(
            identity=self.config.critic_identity or "independent-qc",
            provider="unknown",
            model="unknown",
            prompt_policy="unset",
            command=self.config.critic_selector or "builtin",
        )

    def _golden_packet(self, case: Any, head: str, touched: list[str]) -> dict[str, Any]:
        """A review packet shaped exactly like a real one, for a synthetic candidate."""
        return {
            "task": {
                "id": f"golden:{case.name}",
                "title": f"calibration case {case.name}",
                "description": case.description,
                "acceptance": ["the seeded repository state is judged correctly"],
                "declared_resources": sorted(touched),
                "base_sha": head,
            },
            "submission": {
                "id": f"golden:{case.name}",
                "commit_sha": head,
                "tree_sha": head,
                "patch_sha256": "",
                "changed_paths": sorted(touched),
                "commits": [],
                "diff_stat": "",
            },
            "deterministic_results": [],
            "policy": {
                "inspect_repository": True,
                "reproduce_acceptance": True,
                "worker_conclusions_excluded": True,
            },
        }

    def reproduction_bundle(self, qc_id: str) -> dict[str, Any]:
        """The signed, deterministic bundle for one QC verdict."""
        return self.assurance.read_bundle(qc_id)

    def status(
        self,
        limit: int | None = None,
        lease_risk_seconds: int = DEFAULT_LEASE_RISK_SECONDS,
    ) -> dict[str, Any]:
        """Operator snapshot: attention queue, phases, runtimes, blockers. Read-only."""
        return StatusView(self).snapshot(limit, lease_risk_seconds)

    @staticmethod
    def render_status(snapshot: dict[str, Any]) -> str:
        """Human-readable rendering of a `status()` snapshot; JSON stays canonical."""
        return StatusView.render(snapshot)

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

    @staticmethod
    def _child_env(extra_env: dict[str, str] | None = None) -> dict[str, str]:
        """Build candidate/driver child env without ACP's own bearer secret."""
        env = {name: value for name, value in os.environ.items() if name in PUBLIC_CHILD_ENV}
        env.update(extra_env or {})
        for name in SUPERVISOR_SECRET_ENV:
            env.pop(name, None)
        return env

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
                "SELECT * FROM runner_identities WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            if existing and existing["revoked_at"] is None:
                raise SupervisorError(
                    "runner_already_enrolled",
                    f"{agent_id} is already enrolled; revoke it before re-enrolling",
                )
            digest = credential_digest(credential)
            if existing:
                connection.execute(
                    """
                    UPDATE runner_identities
                    SET role = ?, credential_digest = ?, created_at = ?, revoked_at = NULL
                    WHERE agent_id = ?
                    """,
                    (role, digest, stamp, agent_id),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO runner_identities
                      (agent_id, role, credential_digest, created_at, revoked_at)
                    VALUES (?, ?, ?, ?, NULL)
                    """,
                    (agent_id, role, digest, stamp),
                )
            connection.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('runner_auth_enabled', '1')"
            )
            self._event(
                connection,
                "runner.enrolled",
                "supervisor",
                {"agent_id": agent_id, "role": role, "rotated": bool(existing)},
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
            self._event(connection, "runner.revoked", "supervisor", {"agent_id": agent_id})
        return {"agent_id": agent_id, "revoked_at": stamp}

    def runners(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT agent_id, role, created_at, revoked_at FROM runner_identities "
                "ORDER BY agent_id"
            ).fetchall()
        # credential_digest is deliberately not returned.
        return [dict(row) for row in rows]

    def _identity_enforced(self, connection: sqlite3.Connection | None = None) -> bool:
        """Authentication activates permanently after the first enrollment.

        An empty registry keeps the single-host default behaviour, so enabling
        this is a deliberate act rather than a breaking upgrade. Revocation
        cannot turn authentication back off.
        """
        if connection is not None:
            row = connection.execute(
                "SELECT value FROM meta WHERE key = 'runner_auth_enabled'"
            ).fetchone()
            return bool(row and row["value"] == "1")
        with self.connect() as owned_connection:
            row = owned_connection.execute(
                "SELECT value FROM meta WHERE key = 'runner_auth_enabled'"
            ).fetchone()
        return bool(row)

    def _authenticate(
        self,
        agent_id: str,
        role: str,
        credential: str | None,
        connection: sqlite3.Connection | None = None,
    ) -> sqlite3.Row | None:
        if not self._identity_enforced(connection):
            return None
        if connection is None:
            with self.connect() as owned_connection:
                row = owned_connection.execute(
                    "SELECT * FROM runner_identities WHERE agent_id = ?", (agent_id,)
                ).fetchone()
        else:
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
        return row

    def _authenticate_attempt(
        self,
        connection: sqlite3.Connection,
        attempt: sqlite3.Row,
        credential: str | None,
    ) -> None:
        identity = self._authenticate(attempt["agent_id"], "worker", credential, connection)
        if identity is None:
            return
        bound_digest = attempt["runner_credential_digest"]
        if not bound_digest:
            raise SupervisorError(
                "attempt_identity_unbound",
                "attempt predates runner authentication and cannot cross the trust boundary",
            )
        if not hmac.compare_digest(bound_digest, identity["credential_digest"]):
            raise SupervisorError(
                "attempt_identity_stale",
                "attempt is bound to an older runner credential",
            )

    def _reauthenticate_bound(
        self,
        connection: sqlite3.Connection,
        agent_id: str,
        role: str,
        credential: str | None,
        expected_digest: str | None,
    ) -> None:
        identity = self._authenticate(agent_id, role, credential, connection)
        if identity is None:
            return
        if not expected_digest or not hmac.compare_digest(
            expected_digest, identity["credential_digest"]
        ):
            raise SupervisorError(
                "runner_identity_stale",
                f"{role} credential changed while the operation was running",
            )

    # -- trusted runtime drivers -------------------------------------------

    def _driver_secret(self) -> bytes:
        """Per-supervisor key stored separately from the SQLite evidence DB.

        Keeping the HMAC key in the same backup as keyed credential
        fingerprints would turn weak credential material into an offline
        guessing oracle. Older databases are migrated by writing their key to
        the protected file before deleting the meta row.
        """

        key_path = self.state_dir / "driver.key"

        def read_key() -> bytes:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                fd = os.open(key_path, flags)
            except OSError as error:
                raise SupervisorError(
                    "driver_key_unavailable", "driver key file is unavailable"
                ) from error
            try:
                info = os.fstat(fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or info.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
                ):
                    raise SupervisorError(
                        "driver_key_unsafe",
                        "driver key must be a current-user-owned 0600 regular file",
                    )
                value = os.read(fd, 33)
                if len(value) != 32:
                    raise SupervisorError(
                        "driver_key_invalid", "driver key must contain exactly 32 bytes"
                    )
                return value
            finally:
                os.close(fd)

        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if key_path.exists():
                secret = read_key()
                connection.execute("DELETE FROM meta WHERE key = 'driver_secret'")
                return secret
            row = connection.execute(
                "SELECT value FROM meta WHERE key = 'driver_secret'"
            ).fetchone()
            try:
                secret = bytes.fromhex(row["value"]) if row else os.urandom(32)
            except ValueError as error:
                raise SupervisorError(
                    "driver_key_invalid", "legacy driver key is invalid"
                ) from error
            if len(secret) != 32:
                raise SupervisorError("driver_key_invalid", "legacy driver key is invalid")
            temporary = self.state_dir / f".driver-key-{uuid.uuid4().hex}.tmp"
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                fd = os.open(temporary, flags, 0o600)
                try:
                    os.fchmod(fd, 0o600)
                    written = os.write(fd, secret)
                    if written != len(secret):
                        raise OSError("short driver key write")
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.replace(temporary, key_path)
                directory_fd = os.open(self.state_dir, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError as error:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
                raise SupervisorError(
                    "driver_key_unavailable", "could not persist protected driver key"
                ) from error
            connection.execute("DELETE FROM meta WHERE key = 'driver_secret'")
            return secret

    def _driver_context(
        self,
        attempt_id: str,
        environment: dict[str, str],
        registry: CredentialRegistry | None = None,
        handles: dict[str, CredentialHandle] | None = None,
    ) -> DriverContext:
        attempt = self.attempt(attempt_id)
        runtime_dir = Path(environment["ACP_RUNTIME_DIR"])
        return DriverContext(
            attempt_id=attempt_id,
            task_id=str(attempt["task_id"]),
            runtime_dir=runtime_dir,
            expires_at=int(time.time()) + self.config.lease_seconds,
            secret=self._driver_secret(),
            environment=environment,
            credential_registry=registry,
            credential_handles=handles or {},
        )

    @staticmethod
    def _driver_definition_json(definition: DriverDefinition) -> str:
        return canonical_json(
            {
                "name": definition.name,
                "kind": definition.kind,
                "executable": str(definition.executable) if definition.executable else None,
                "options": dict(definition.options),
            }
        )

    @staticmethod
    def _driver_definition_from_json(value: str) -> DriverDefinition:
        raw = json.loads(value)
        return DriverDefinition(
            name=str(raw["name"]),
            kind=str(raw["kind"]),
            executable=Path(raw["executable"]) if raw.get("executable") else None,
            options={str(key): str(item) for key, item in raw.get("options", {}).items()},
        )

    def _stored_driver_rows(self, attempt_id: str) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return connection.execute(
                "SELECT * FROM runtime_driver_resources WHERE attempt_id = ? ORDER BY driver",
                (attempt_id,),
            ).fetchall()

    def _quarantine_driver_attempt(self, attempt_id: str, code: str) -> None:
        stamp = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE runtime_driver_resources SET state = 'quarantined', updated_at = ? "
                "WHERE attempt_id = ?",
                (stamp, attempt_id),
            )
            connection.execute(
                "UPDATE runtime_environments SET state = 'teardown_failed', updated_at = ? "
                "WHERE attempt_id = ?",
                (stamp, attempt_id),
            )
            self._event(
                connection,
                "runtime.driver.quarantined",
                "supervisor",
                {"attempt_id": attempt_id, "reason": code},
            )

    def _assert_driver_config_unchanged(self, attempt_id: str) -> None:
        rows = self._stored_driver_rows(attempt_id)
        if not rows:
            return
        pin = self._verify_attempt_trust(attempt_id)
        stored = {
            row["driver"]: row["definition_json"] for row in rows if row["definition_json"] != "{}"
        }
        current = {
            definition.name: self._driver_definition_json(definition)
            for definition in self._driver_definitions_for_pin(pin)
        }
        if stored == current:
            return
        stamp = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE runtime_driver_resources SET state = 'quarantined', updated_at = ? "
                "WHERE attempt_id = ?",
                (stamp, attempt_id),
            )
            self._event(
                connection,
                "runtime.driver.config_drift",
                "supervisor",
                {"attempt_id": attempt_id, "stored": sorted(stored), "current": sorted(current)},
            )
        raise SupervisorError(
            "runtime_driver_config_drift",
            "driver configuration changed after allocation; restore it before restart",
        )

    def _run_driver_phase(
        self,
        phase: str,
        attempt_id: str,
        environment: dict[str, str],
        only_drivers: set[str] | None = None,
        restart_token: str | None = None,
        restart_guard_fd: int | None = None,
    ) -> list[PhaseEvidence]:
        """Run *phase* for every configured driver.

        Drivers execute with the runtime directory as cwd — never the candidate
        worktree — and through ``run_trusted``, which re-validates argv[0]
        immediately before exec.
        """

        pin = self._verify_attempt_trust(attempt_id)
        stored_rows = self._stored_driver_rows(attempt_id)
        stored_by_name = {row["driver"]: row for row in stored_rows}
        if stored_rows:
            try:
                definitions = tuple(
                    self._driver_definition_from_json(row["definition_json"]) for row in stored_rows
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                self._quarantine_driver_attempt(attempt_id, "runtime_driver_definition_missing")
                raise SupervisorError(
                    "runtime_driver_definition_missing",
                    "stored driver definition is unavailable; cleanup is quarantined",
                ) from error
        else:
            definitions = self._driver_definitions_for_pin(pin)
        if only_drivers is not None:
            definitions = tuple(
                definition for definition in definitions if definition.name in only_drivers
            )
        if not definitions:
            return []
        registry = CredentialRegistry(self.config.credentials, self.root, self._driver_secret())
        handles: dict[str, CredentialHandle] = {}
        handle_errors: dict[str, DriverError] = {}
        for definition in definitions:
            credential_name = definition.option("credential")
            if not credential_name:
                continue
            stored = stored_by_name.get(definition.name)
            use_stored = stored is not None and not (
                phase == "setup" and stored["state"] == "released"
            )
            try:
                if use_stored:
                    raw_handle = json.loads(stored["credential_handle_json"])
                    if not raw_handle:
                        raise CredentialError(
                            "credential_handle_missing",
                            "stored credential handle is unavailable",
                        )
                    handles[definition.name] = CredentialHandle.from_internal_dict(raw_handle)
                else:
                    handles[definition.name] = registry.resolve_current(credential_name)
            except (CredentialError, json.JSONDecodeError) as error:
                if isinstance(error, CredentialError):
                    handle_errors[definition.name] = DriverError(error.code, error.message)
                else:
                    handle_errors[definition.name] = DriverError(
                        "credential_handle_invalid",
                        "stored credential handle is invalid",
                    )
        context = self._driver_context(attempt_id, environment, registry=registry, handles=handles)
        evidence: list[PhaseEvidence] = []
        definitions_by_name = {definition.name: definition for definition in definitions}
        trusted_owners = {0, self.config.trust_owner_uid} if pin else None

        def trusted_runner(  # type: ignore[no-untyped-def]
            argv, cwd, env, timeout, credential
        ) -> dict[str, Any]:
            execution_options: dict[str, Any] = {}
            if restart_guard_fd is not None:
                execution_options["guard_fd"] = restart_guard_fd
            if trusted_owners is not None:
                execution_options["expected_owners"] = trusted_owners
            return run_trusted(
                argv,
                cwd,
                env,
                timeout,
                credential,
                **execution_options,
            )

        for definition in definitions:
            if restart_token is not None:
                self._assert_restart_owner(attempt_id, restart_token)
            driver = build_driver(definition)
            intent_resource = ""
            intent_token = ""
            intent_recorded = False
            try:
                if definition.name in handle_errors:
                    raise handle_errors[definition.name]
                stored = stored_by_name.get(definition.name)
                intent_resource = driver.resource_id(context)
                intent_token = driver.ownership_token(context)
                if stored:
                    replacing_released = phase == "setup" and stored["state"] == "released"
                    if not replacing_released and (
                        stored["kind"] != definition.kind
                        or stored["resource_id"] != intent_resource
                        or not hmac.compare_digest(stored["ownership_token"], intent_token)
                    ):
                        raise DriverError(
                            "runtime_driver_identity_mismatch",
                            f"stored ownership proof does not match driver {definition.name}",
                        )
                if phase == "setup":
                    self._record_driver_setup_intent(
                        attempt_id,
                        definition,
                        intent_resource,
                        intent_token,
                        handles.get(definition.name),
                        context.expires_at,
                        restart_token=restart_token,
                    )
                    intent_recorded = True
                evidence.append(driver.run_phase(phase, context, trusted_runner))
            except DriverError as error:
                stored = stored_by_name.get(definition.name)
                evidence.append(
                    PhaseEvidence(
                        driver=definition.name,
                        kind=definition.kind,
                        phase=phase,
                        resource_id=(
                            intent_resource
                            if intent_recorded
                            else stored["resource_id"]
                            if stored
                            else ""
                        ),
                        ownership_token=(
                            intent_token
                            if intent_recorded
                            else stored["ownership_token"]
                            if stored
                            else ""
                        ),
                        expires_at=context.expires_at,
                        exit_code=1,
                        present=None,
                        proof={"error": error.message, "code": error.code},
                        credential_handle=handles.get(definition.name),
                    )
                )
        self._record_driver_evidence(
            attempt_id,
            phase,
            evidence,
            definitions_by_name,
            restart_token=restart_token,
        )
        return evidence

    def _record_driver_setup_intent(
        self,
        attempt_id: str,
        definition: DriverDefinition,
        resource_id: str,
        capability: str,
        handle: CredentialHandle | None,
        expires_at: int,
        restart_token: str | None = None,
    ) -> None:
        """Persist exact cleanup identity before any external setup action."""

        stamp = utc_now()
        evidence = canonical_json(
            {
                "driver": definition.name,
                "kind": definition.kind,
                "phase": "setup",
                "resource_id": resource_id,
                "expires_at": expires_at,
                "exit_code": 1,
                "present": None,
                "proof": {"pending": True},
            }
        )
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._assert_restart_owner_in(connection, attempt_id, restart_token)
            connection.execute(
                """
                INSERT INTO runtime_driver_resources
                  (attempt_id, driver, kind, resource_id, ownership_token,
                   definition_json, credential_handle_json, expires_at, state,
                   evidence_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'setup_pending', ?, ?)
                ON CONFLICT(attempt_id, driver) DO UPDATE SET
                  kind = excluded.kind,
                  resource_id = excluded.resource_id,
                  ownership_token = excluded.ownership_token,
                  definition_json = excluded.definition_json,
                  credential_handle_json = excluded.credential_handle_json,
                  expires_at = excluded.expires_at,
                  state = excluded.state,
                  evidence_json = excluded.evidence_json,
                  updated_at = excluded.updated_at
                """,
                (
                    attempt_id,
                    definition.name,
                    definition.kind,
                    resource_id,
                    capability,
                    self._driver_definition_json(definition),
                    canonical_json(handle.as_internal_dict()) if handle else "{}",
                    expires_at,
                    evidence,
                    stamp,
                ),
            )
            self._event(
                connection,
                "runtime.driver.setup_pending",
                "supervisor",
                {
                    "attempt_id": attempt_id,
                    "driver": definition.name,
                    "kind": definition.kind,
                    "resource_id": resource_id,
                },
            )

    def _record_driver_evidence(
        self,
        attempt_id: str,
        phase: str,
        evidence: Sequence[PhaseEvidence],
        definitions: dict[str, DriverDefinition],
        restart_token: str | None = None,
    ) -> None:
        if not evidence:
            return
        stamp = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._assert_restart_owner_in(connection, attempt_id, restart_token)
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
                       definition_json, credential_handle_json, expires_at, state,
                       evidence_json, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(attempt_id, driver) DO UPDATE SET
                      kind = excluded.kind,
                      resource_id = excluded.resource_id,
                      ownership_token = excluded.ownership_token,
                      definition_json = excluded.definition_json,
                      credential_handle_json = CASE
                        WHEN excluded.credential_handle_json = '{}'
                        THEN runtime_driver_resources.credential_handle_json
                        ELSE excluded.credential_handle_json
                      END,
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
                        self._driver_definition_json(definitions[item.driver]),
                        canonical_json(item.credential_handle.as_internal_dict())
                        if item.credential_handle
                        else "{}",
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
        resources: list[dict[str, Any]] = []
        for row in rows:
            evidence = json.loads(row["evidence_json"])
            evidence.pop("ownership_token", None)
            resources.append(
                {
                    "driver": row["driver"],
                    "kind": row["kind"],
                    "resource_id": row["resource_id"],
                    "expires_at": row["expires_at"],
                    "state": row["state"],
                    "evidence": evidence,
                }
            )
        return resources

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
        resources: list[dict[str, Any]] = []
        for row in rows:
            evidence = json.loads(row["evidence_json"])
            evidence.pop("ownership_token", None)
            resources.append(
                {
                    "attempt_id": row["attempt_id"],
                    "driver": row["driver"],
                    "kind": row["kind"],
                    "resource_id": row["resource_id"],
                    "state": row["state"],
                    "evidence": evidence,
                }
            )
        return resources

    @staticmethod
    def _assert_restart_owner_in(
        connection: sqlite3.Connection,
        attempt_id: str,
        restart_token: str | None,
    ) -> None:
        if restart_token is None:
            return
        row = connection.execute(
            "SELECT state, restart_token FROM runtime_environments WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone()
        if (
            not row
            or row["state"] != "restarting"
            or not hmac.compare_digest(row["restart_token"], restart_token)
        ):
            raise SupervisorError("runtime_restart_stale", "restart generation is no longer active")

    def _assert_restart_owner(self, attempt_id: str, restart_token: str) -> None:
        with self.connect() as connection:
            self._assert_restart_owner_in(connection, attempt_id, restart_token)

    @contextmanager
    def _runtime_restart_guard(self, attempt_id: str, recover: bool) -> Iterator[int]:
        """Hold a kernel lifetime lock across every restart side effect.

        The descriptor is also inherited by each trusted driver process. If
        the supervisor dies while a teardown is running, the kernel therefore
        keeps the lock until that process (and any inheriting descendants)
        exits. A recovery may age out a DB generation, but it may never run
        concurrently with an executor that can still mutate the resource.
        """

        lock_dir = self.state_dir / "restart-locks"
        lock_dir.mkdir(mode=0o700, exist_ok=True)
        lock_path = lock_dir / f"{sha256(attempt_id.encode())}.lock"
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            lock_fd = os.open(lock_path, flags, 0o600)
        except OSError as error:
            raise SupervisorError(
                "runtime_restart_lock_unavailable",
                "runtime restart lock could not be opened",
            ) from error
        try:
            opened = os.fstat(lock_fd)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
            ):
                raise SupervisorError(
                    "runtime_restart_lock_unsafe",
                    "runtime restart lock must be a current-user-owned 0600 regular file",
                )
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno not in {errno.EACCES, errno.EAGAIN}:
                    raise SupervisorError(
                        "runtime_restart_lock_unavailable",
                        "runtime restart lock could not be acquired",
                    ) from error
                code = (
                    "runtime_restart_executor_alive" if recover else "runtime_restart_in_progress"
                )
                raise SupervisorError(
                    code,
                    "runtime restart executor is still alive; recovery is unsafe",
                ) from error
            yield lock_fd
        finally:
            # Do not issue LOCK_UN: a trusted child may still hold an inherited
            # duplicate after an interrupted supervisor. Closing only our copy
            # keeps the kernel lock alive until every such executor exits.
            os.close(lock_fd)

    def runtime_restart(self, attempt_id: str, recover: bool = False) -> dict[str, Any]:
        """Tear down and re-create driver resources between phases.

        QC must not be able to reach a service the worker left running: a stale
        app server can make a reviewer pass a candidate whose code never
        actually starts.
        """
        self._assert_driver_config_unchanged(attempt_id)
        if recover:
            now = int(time.time())
            with self.connect() as connection:
                runtime = connection.execute(
                    "SELECT state, restart_started_at FROM runtime_environments "
                    "WHERE attempt_id = ?",
                    (attempt_id,),
                ).fetchone()
            if not runtime:
                raise SupervisorError("runtime_not_found", "runtime environment is missing")
            if runtime["state"] != "restarting":
                raise SupervisorError(
                    "runtime_recovery_not_needed",
                    "runtime has no interrupted restart to recover",
                )
            if now - int(runtime["restart_started_at"]) < self.config.lease_seconds:
                raise SupervisorError(
                    "runtime_restart_not_stale",
                    "runtime restart is still within its recovery lease",
                )
        with self._runtime_restart_guard(attempt_id, recover) as guard_fd:
            return self._runtime_restart_locked(attempt_id, recover, guard_fd)

    def _runtime_restart_locked(
        self,
        attempt_id: str,
        recover: bool,
        guard_fd: int,
    ) -> dict[str, Any]:
        """Restart while holding the kernel guard returned above."""

        restart_token = uuid.uuid4().hex
        now = int(time.time())
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            runtime = connection.execute(
                "SELECT * FROM runtime_environments WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if not runtime:
                raise SupervisorError("runtime_not_found", "runtime environment is missing")
            recovering = runtime["state"] == "restarting"
            if recovering and not recover:
                raise SupervisorError(
                    "runtime_restart_in_progress",
                    "runtime restart is already in progress; use --recover only after its lease",
                )
            if recovering and now - int(runtime["restart_started_at"]) < self.config.lease_seconds:
                raise SupervisorError(
                    "runtime_restart_not_stale",
                    "runtime restart is still within its recovery lease",
                )
            if recover and not recovering:
                raise SupervisorError(
                    "runtime_recovery_not_needed",
                    "runtime has no interrupted restart to recover",
                )
            if runtime["state"] not in {"ready", "restarting"}:
                raise SupervisorError(
                    "runtime_not_ready",
                    f"runtime cannot restart from state {runtime['state']}",
                )
            connection.execute(
                "UPDATE runtime_environments "
                "SET state = 'restarting', restart_token = ?, restart_started_at = ?, updated_at = ? "
                "WHERE attempt_id = ?",
                (restart_token, now, utc_now(), attempt_id),
            )
            self._event(
                connection,
                "runtime.restart_started",
                "supervisor",
                {"attempt_id": attempt_id, "recovery": recovering},
            )
            environment = json.loads(runtime["env_json"])

        # A crash after cleanup proof but before setup must not require the old
        # credential again. Released rows are durable proof that teardown has
        # already completed; retry proceeds directly to current-version setup.
        rows = self._stored_driver_rows(attempt_id)
        teardown_names = {row["driver"] for row in rows if row["state"] != "released"}
        teardown = self._run_driver_phase(
            "teardown",
            attempt_id,
            environment,
            teardown_names,
            restart_token=restart_token,
            restart_guard_fd=guard_fd,
        )
        self._assert_restart_owner(attempt_id, restart_token)
        unproven = [item for item in teardown if not item.proof.get("cleanup_proved")]
        if unproven:
            with self.connect() as connection:
                updated = connection.execute(
                    "UPDATE runtime_environments SET state = 'teardown_failed', updated_at = ? "
                    "WHERE attempt_id = ? AND state = 'restarting' AND restart_token = ?",
                    (utc_now(), attempt_id, restart_token),
                )
                if updated.rowcount != 1:
                    raise SupervisorError(
                        "runtime_restart_stale", "restart generation lost during teardown"
                    )
            raise SupervisorError(
                "runtime_cleanup_unproven",
                "cannot restart runtime: cleanup proof missing for "
                + ", ".join(sorted(item.driver for item in unproven)),
            )
        setup = self._run_driver_phase(
            "setup",
            attempt_id,
            environment,
            restart_token=restart_token,
            restart_guard_fd=guard_fd,
        )
        self._assert_restart_owner(attempt_id, restart_token)
        failed = [item for item in setup if not item.ok]
        if failed:
            with self.connect() as connection:
                updated = connection.execute(
                    "UPDATE runtime_environments SET state = 'setup_failed', updated_at = ? "
                    "WHERE attempt_id = ? AND state = 'restarting' AND restart_token = ?",
                    (utc_now(), attempt_id, restart_token),
                )
                if updated.rowcount != 1:
                    raise SupervisorError(
                        "runtime_restart_stale", "restart generation lost during setup"
                    )
            raise SupervisorError(
                "runtime_setup_failed",
                "driver setup failed for " + ", ".join(sorted(item.driver for item in failed)),
            )
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                "UPDATE runtime_environments "
                "SET state = 'ready', restart_token = '', restart_started_at = 0, updated_at = ? "
                "WHERE attempt_id = ? AND state = 'restarting' AND restart_token = ?",
                (utc_now(), attempt_id, restart_token),
            )
            if updated.rowcount != 1:
                raise SupervisorError(
                    "runtime_restart_stale", "restart generation lost before completion"
                )
            self._event(
                connection,
                "runtime.restart_completed",
                "supervisor",
                {"attempt_id": attempt_id, "drivers": [item.driver for item in setup]},
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
        unproven = [item.driver for item in driver_evidence if not item.proof.get("cleanup_proved")]
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
        failed = any(result["exit_code"] for result in results) or bool(occupied) or bool(unproven)
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
        # Resolve ``current`` once, before the attempt exists. Every later phase
        # reads this stored pin, so a rotation affects only subsequent claims.
        trust_pin = self._current_trust_pin()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            identity = self._authenticate(agent_id, "worker", credential, connection)
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
            for artifact in json.loads(task["consumes_json"]):
                producer = connection.execute(
                    """
                    SELECT id, status FROM tasks
                    WHERE id != ? AND status != 'done'
                      AND EXISTS (
                        SELECT 1 FROM json_each(tasks.produces_json) WHERE value = ?
                      )
                    ORDER BY id LIMIT 1
                    """,
                    (task_id, artifact),
                ).fetchone()
                if producer:
                    raise SupervisorError(
                        "dependency_incomplete",
                        f"artifact {artifact} is produced by task {producer['id']} "
                        f"which is {producer['status']}",
                    )
            requested = json.loads(task["resources_json"])
            leases = connection.execute(
                """
                SELECT lease.resource, lease.task_id, lease.attempt_id,
                       attempt.agent_id AS agent_id
                FROM resource_leases AS lease
                LEFT JOIN attempts AS attempt ON attempt.id = lease.attempt_id
                WHERE lease.task_id IS NOT NULL AND lease.lease_expires_at > ?
                """,
                (int(time.time()),),
            ).fetchall()
            for resource in requested:
                for lease in leases:
                    if lease["task_id"] != task_id and self.resources_overlap(
                        resource, lease["resource"]
                    ):
                        overlap = "exact" if resource == lease["resource"] else "potential"
                        raise SupervisorError(
                            "resource_busy",
                            f"{resource} has an {overlap} overlap with active lease "
                            f"{lease['resource']} held by task {lease['task_id']} "
                            f"(agent {lease['agent_id'] or 'unknown'}, "
                            f"attempt {lease['attempt_id'] or 'unknown'})",
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
                  (id, task_id, number, agent_id, runner_credential_digest,
                   branch, worktree, claim_token,
                   start_sha, latest_sha, checkpoint_json, trust_bundle_json,
                   pid, log_path, status,
                   lease_expires_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', ?, NULL, NULL,
                        'provisioning', ?, ?, ?)
                """,
                (
                    attempt_id,
                    task_id,
                    number,
                    agent_id,
                    identity["credential_digest"] if identity else None,
                    branch,
                    str(worktree),
                    counter,
                    start_sha,
                    start_sha,
                    canonical_json(trust_pin),
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
        credential: str | None = None,
    ) -> dict[str, Any]:
        ttl = lease_seconds or self.config.lease_seconds
        expires = int(time.time()) + ttl
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            self._authenticate_attempt(connection, attempt, credential)
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

    def submit(
        self,
        attempt_id: str,
        claim_token: int,
        credential: str | None = None,
    ) -> dict[str, Any]:
        return self._submit(
            attempt_id,
            claim_token,
            expected_worker_pid=None,
            credential=credential,
        )

    def _submit(
        self,
        attempt_id: str,
        claim_token: int,
        expected_worker_pid: int | None,
        credential: str | None,
    ) -> dict[str, Any]:
        epoch = int(time.time())
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, epoch)
            self._authenticate_attempt(connection, attempt, credential)
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
        reviewer_identity = self._authenticate(reviewer_id, "critic", credential)
        reviewer_digest = reviewer_identity["credential_digest"] if reviewer_identity else None
        with self.connect() as connection:
            pending_submission = self._submission_row(connection, submission_id)
        trust_pin = self._verify_attempt_trust(pending_submission["attempt_id"])
        reviewer = self.assurance_policy.reviewer(reviewer_id)
        if reviewer is None:
            if reviewer_id != self.config.critic_identity:
                raise SupervisorError(
                    "reviewer_identity_mismatch",
                    f"reviewer must be a declared reviewer or {self.config.critic_identity}",
                )
            reviewer = Reviewer(
                identity=reviewer_id,
                provider="unknown",
                model="unknown",
                prompt_policy="unset",
                command=self.config.critic_selector,
            )
        # A reviewer upgrade must be ratified before it can judge anything.
        self.assurance.assert_policy_ratified()
        started = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._authenticate(reviewer_id, "critic", credential, connection)
            submission = self._submission_row(connection, submission_id)
            task = self._task_row(connection, submission["task_id"])
            if (
                submission["status"] not in {"pending_qc", "pending_second_review"}
                or task["status"] != "qc_review"
            ):
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
                    runtime_env = self._runtime_env(submission["attempt_id"], require_ready=False)
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
            if reviewer.command:
                packet["deterministic_results"] = results
                packet_path.write_text(json.dumps(packet, indent=2), encoding="utf-8")
                self._restore_candidate(qc_dir, submission["commit_sha"])
                if reviewer.command.startswith("trusted:"):
                    trust_pin = self._verify_attempt_trust(submission["attempt_id"])
                result_path = (
                    self.state_dir / "logs" / f"critic-{submission_id}-{uuid.uuid4().hex}.json"
                )
                critic = self._run_critic(
                    reviewer.command,
                    qc_dir,
                    self._phase_runtime_env(runtime_env, "critic", qc_dir)
                    | {
                        "ACP_REVIEW_PACKET": str(packet_path),
                        "ACP_REVIEW_RESULT": str(result_path),
                    },
                    trust_pin,
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
        bundle = self.assurance.bundle(
            qc_id,
            dict(submission),
            task["base_sha"],
            [*self.config.qc_commands, *([reviewer.command] if reviewer.command else [])],
            reviewer,
            verdict,
            packet_hash,
        )
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._reauthenticate_bound(
                connection,
                reviewer_id,
                "critic",
                credential,
                reviewer_digest,
            )
            try:
                trust_pin = self._verify_attempt_trust_in(connection, submission["attempt_id"])
            except SupervisorError:
                # Preserve the quarantine even though this verdict must not be
                # recorded. The context manager's later rollback is then a no-op.
                connection.commit()
                raise
            if self.assurance.ratified_fingerprint(connection) != self.assurance_policy.fingerprint:
                raise SupervisorError(
                    "reviewer_policy_changed",
                    "reviewer policy changed while QC was running; discard this verdict and rerun",
                )
            current = self._submission_row(connection, submission_id)
            current_task = self._task_row(connection, current["task_id"])
            if (
                current["status"] not in {"pending_qc", "pending_second_review"}
                or current_task["status"] != "qc_review"
            ):
                raise SupervisorError("submission_not_reviewable", "submission changed during QC")
            self._assert_reservations(connection, current_task, current)
            connection.execute(
                """
                INSERT INTO qc_runs
                  (id, submission_id, reviewer_id, commit_sha, verdict,
                   findings_json, results_json, packet_sha256,
                   reviewer_provenance_json, reviewer_signature, bundle_sha256,
                   policy_fingerprint, trust_bundle_json, started_at, finished_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    canonical_json(reviewer.provenance()),
                    bundle["record"]["signature"],
                    bundle["sha256"],
                    self.assurance_policy.fingerprint,
                    canonical_json(trust_pin),
                    started,
                    finished,
                ),
            )
            passing = self._current_policy_passes(connection, current)
            requirement = self.assurance.review_requirement(
                json.loads(current["changed_paths_json"]), passing
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
            if verdict == "pass" and requirement["high_risk"] and not requirement["satisfied"]:
                # A passing verdict is not an approval while policy still owes a
                # second reviewer, a second provider, or a human.
                findings = [
                    *findings,
                    {
                        "severity": "low",
                        "requirement": "high-risk paths satisfy the reviewer policy",
                        "finding": requirement["reason"],
                        "evidence": ", ".join(requirement["paths"][:20]),
                        "required_fix": "obtain the additional review the policy requires",
                    },
                ]
                if self.assurance_policy.high_risk_mode == "human":
                    submission_status, task_status = "human_required", "blocked"
                else:
                    submission_status, task_status = "pending_second_review", "qc_review"
                connection.execute(
                    "UPDATE qc_runs SET findings_json = ? WHERE id = ?",
                    (canonical_json(findings), qc_id),
                )
            connection.execute(
                "UPDATE submissions SET status = ? WHERE id = ?",
                (submission_status, submission_id),
            )
            connection.execute(
                "UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?",
                (task_status, finished, current_task["id"]),
            )
            if verdict == "pass" and submission_status != "human_required":
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

    def integrate(
        self,
        task_id: str,
        integrator_id: str = "integration",
        credential: str | None = None,
    ) -> dict[str, Any]:
        integrator_identity = self._authenticate(integrator_id, "integrator", credential)
        integrator_digest = (
            integrator_identity["credential_digest"] if integrator_identity else None
        )
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._authenticate(integrator_id, "integrator", credential, connection)
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
            try:
                self._verify_attempt_trust_in(connection, submission["attempt_id"])
            except SupervisorError:
                # Persist quarantine while rejecting integration before it can
                # create a branch or invoke an external gate.
                connection.commit()
                raise
            self._assert_submission_assurance(connection, submission)
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
                integrator_id,
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
                try:
                    self._reauthenticate_bound(
                        connection,
                        integrator_id,
                        "integrator",
                        credential,
                        integrator_digest,
                    )
                except SupervisorError as auth_error:
                    verdict = "stale"
                    error_message = f"{auth_error.code}: {auth_error}"
                trust_valid = True
                try:
                    self._verify_attempt_trust_in(connection, submission["attempt_id"])
                except SupervisorError as trust_error:
                    trust_valid = False
                    error_message = f"{trust_error.code}: {trust_error}"
                current_task = self._task_row(connection, task_id)
                reservation_valid = trust_valid and current_task["status"] == "integrating"
                if reservation_valid:
                    try:
                        self._assert_submission_assurance(connection, submission)
                    except SupervisorError as error:
                        reservation_valid = False
                        error_message = f"{error.code}: {error}"
                if reservation_valid:
                    try:
                        self._assert_reservations(connection, current_task, submission)
                    except SupervisorError as error:
                        reservation_valid = False
                        error_message = str(error)
                elif not error_message:
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
                    integrator_id,
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
        credential: str | None = None,
    ) -> dict[str, Any]:
        if not command:
            raise SupervisorError("invalid_command", "worker command is required")
        attempt = self.heartbeat(
            attempt_id,
            claim_token,
            {"phase": "launching", "command": list(command)},
            credential=credential,
        )
        worker_env = self._child_env(
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
                self._reserve_worker_launch(attempt_id, claim_token, str(log_path), credential)
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
                    self._authenticate_attempt(connection, active, credential)
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
                            credential=credential,
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
                credential=credential,
            )
        except BaseException:
            self._clear_worker_registration(
                attempt_id,
                {process.pid},
                "worker.submission_failed",
                process.returncode,
            )
            raise

    def _reserve_worker_launch(
        self,
        attempt_id: str,
        claim_token: int,
        log_path: str,
        credential: str | None,
    ) -> None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            self._authenticate_attempt(connection, attempt, credential)
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

    def terminate_worker(self, attempt_id: str, credential: str | None = None) -> dict[str, Any]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
            if not row:
                raise SupervisorError("attempt_not_found", f"attempt {attempt_id} not found")
            self._authenticate_attempt(connection, row, credential)
            attempt = self._attempt_view(connection, row)
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
        if self.config.trust_root is not None:
            try:
                current_pin = load_current_bundle(
                    self.config.trust_root, owner_uid=self.config.trust_owner_uid
                )
                current_health = verify_bundle_pin(current_pin)
            except TrustBundleError as error:
                current_health = {
                    "ok": False,
                    "bundle_id": None,
                    "errors": [f"{error.code}: {item}" for item in error.errors],
                }
            checks.append(
                {
                    "name": "trust_current",
                    "ok": current_health["ok"],
                    "detail": current_health,
                }
            )
        referenced_pins: dict[tuple[str, str], dict[str, Any]] = {}
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
            trust_queries = (
                (
                    "attempts",
                    "SELECT trust_bundle_json FROM attempts WHERE trust_bundle_json != '{}'",
                ),
                (
                    "qc_runs",
                    "SELECT trust_bundle_json FROM qc_runs WHERE trust_bundle_json != '{}'",
                ),
            )
            for table, query in trust_queries:
                for row in connection.execute(query):
                    try:
                        pin = json.loads(row["trust_bundle_json"])
                        key = (str(pin.get("bundle_id", "?")), str(pin.get("manifest_sha256", "?")))
                        referenced_pins[key] = pin
                    except (json.JSONDecodeError, TypeError, AttributeError):
                        key = (f"invalid-{table}", str(len(referenced_pins)))
                        referenced_pins[key] = {}
        for (bundle_id, manifest_digest), pin in sorted(referenced_pins.items()):
            health = (
                verify_bundle_pin(pin)
                if pin
                else {"ok": False, "bundle_id": bundle_id, "errors": ["stored pin is invalid"]}
            )
            checks.append(
                {
                    "name": f"trust_pinned:{bundle_id}:{manifest_digest[:12]}",
                    "ok": health["ok"],
                    "detail": health,
                }
            )
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
            "produces": json.loads(row["produces_json"]),
            "consumes": json.loads(row["consumes_json"]),
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
        trust_pin = json.loads(row["trust_bundle_json"] or "{}")
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
            "trust_bundle": (
                {
                    "bundle_id": trust_pin.get("bundle_id"),
                    "manifest_sha256": trust_pin.get("manifest_sha256"),
                }
                if trust_pin
                else None
            ),
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
        trust_pin = json.loads(row["trust_bundle_json"] or "{}")
        return {
            "id": row["id"],
            "submission_id": row["submission_id"],
            "reviewer_id": row["reviewer_id"],
            "commit_sha": row["commit_sha"],
            "verdict": row["verdict"],
            "findings": json.loads(row["findings_json"]),
            "command_results": json.loads(row["results_json"]),
            "review_packet_sha256": row["packet_sha256"],
            "reviewer_provenance": json.loads(row["reviewer_provenance_json"] or "{}"),
            "reviewer_signature": row["reviewer_signature"],
            "bundle_sha256": row["bundle_sha256"],
            "policy_fingerprint": row["policy_fingerprint"],
            "trust_bundle": (
                {
                    "bundle_id": trust_pin.get("bundle_id"),
                    "manifest_sha256": trust_pin.get("manifest_sha256"),
                }
                if trust_pin
                else None
            ),
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
        env = self._child_env(extra_env)
        return self._run_process(["/bin/sh", "-lc", command], command, cwd, env)

    def _run_critic(
        self,
        command: str,
        cwd: Path,
        extra_env: dict[str, str],
        trust_pin: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if command != "builtin":
            env = self._child_env(extra_env)
            resolved = self._resolve_critic_command(
                command,
                trust_pin if trust_pin is not None else self._current_trust_pin(),
            )
            try:
                result = run_trusted(
                    [resolved],
                    cwd,
                    env,
                    self.config.timeout_seconds,
                    expected_owners=(
                        {0, self.config.trust_owner_uid} if command.startswith("trusted:") else None
                    ),
                )
            except DriverError as error:
                raise SupervisorError(error.code, error.message) from error
            return {"command": command, **result}
        env = self._child_env(extra_env)
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
