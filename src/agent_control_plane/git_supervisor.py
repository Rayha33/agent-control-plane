from __future__ import annotations

import base64
import errno
import fcntl
import hashlib
import hmac
import json
import os
import re
import select
import shlex
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
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from . import __version__
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
    ownership_token,
    parse_driver_definitions,
    resolve_trusted_executable,
    run_trusted,
)
from .scheduling import Scheduler, normalize_artifact
from .status import (
    ACTIVE_STATUSES,
    DEFAULT_LEASE_RISK_SECONDS,
    LIVE_ATTEMPT_STATUSES,
    StatusView,
    _age_seconds,
)
from .trust_bundles import (
    TrustBundleError,
    executable_from_pin,
    load_current_bundle,
    verify_bundle_pin,
)
from .worker_trampoline import LIFECYCLE_FDS_PREFIX, MONITOR_MODE

GENESIS_HASH = "0" * 64
CLEANUP_FENCE_EPOCH = 2**62
SUBMISSION_OBJECT_CONTRACT = "replacement-free-v1"
MAX_ATTRIBUTE_BYTES = 1024 * 1024
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
MERGE_SEMANTIC_CONFIG = (
    "core.autocrlf",
    "core.bigfilethreshold",
    "core.checkroundtripencoding",
    "core.eol",
    "core.filemode",
    "core.ignorecase",
    "core.precomposeunicode",
    "core.protecthfs",
    "core.protectntfs",
    "core.safecrlf",
    "core.symlinks",
    "diff.algorithm",
    "diff.indentheuristic",
    "diff.renamelimit",
    "diff.renames",
    "merge.conflictstyle",
    "merge.directoryrenames",
    "merge.renamelimit",
    "merge.renames",
    "merge.renormalize",
)


class SupervisorError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


SCHEMA_VERSION = 1
"""Schema this binary understands. Raise it in the same commit that adds a MIGRATIONS entry."""

GC_RECLAIMABLE_TASK_STATUSES = frozenset(
    {"done", "orphaned", "blocked", "conflicted", "changes_requested"}
)
"""Task states whose attempt worktree is no longer the working copy of anything.

Keyed on the TASK, not the attempt. An attempt that was submitted and integrated stays
at `submitted` forever — nothing ever moves it to a terminal state — so an attempt-keyed
sweep would find nothing to reclaim on exactly the tasks that finished cleanly.
"""

DEFAULT_GC_RETENTION_SECONDS = 7 * 24 * 3600

SCHEMA_VERSION_KEY = "schema_version"
SCHEMA_WRITTEN_BY_KEY = "written_by"

# Numbered upgrades from SCHEMA_VERSION - 1 to SCHEMA_VERSION, applied in order, each
# inside one transaction. Version 1 is the baseline: the idempotent CREATE TABLE IF NOT
# EXISTS script plus the column adds that predate stamping, so an unstamped database is
# brought to 1 by the code that already existed rather than by a ledger entry. Anything
# after 1 goes here — including index, rename, backfill and data transforms, which the
# PRAGMA/ALTER pattern cannot express.
MIGRATIONS: tuple[tuple[int, Callable[[sqlite3.Connection], None]], ...] = ()


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    """Column names of `table`, empty when the table does not exist yet."""

    return {row["name"] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}


def stored_schema_version(connection: sqlite3.Connection) -> int | None:
    """Schema version recorded in the database, or None when it predates stamping.

    None is "older than 1", not "unknown": a database written before versioning has
    no meta row, and one written before `meta` existed has no table. A stamp that is
    present but not an integer is a different thing entirely — that is corruption, and
    guessing a version for it would migrate a database we cannot identify.
    """

    try:
        row = connection.execute(
            "SELECT value FROM meta WHERE key = ?", (SCHEMA_VERSION_KEY,)
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    if row is None:
        return None
    try:
        return int(row["value"])
    except (TypeError, ValueError):
        raise SupervisorError(
            "schema_version_unreadable",
            f"meta.{SCHEMA_VERSION_KEY} is {row['value']!r}, which is not a version number; "
            "the control database is corrupt or was not written by acp",
        ) from None


def assert_schema_not_newer(stored: int | None) -> None:
    """Refuse a database written by a newer binary than this one.

    Opening it anyway is the quiet failure: CREATE TABLE IF NOT EXISTS leaves the newer
    tables alone and every PRAGMA check finds its column already present, so the open
    succeeds and the newer columns simply stay invisible to this code. A critic running
    an older contract would then approve work the newer contract rejects.
    """

    if stored is not None and stored > SCHEMA_VERSION:
        raise SupervisorError(
            "schema_newer_than_binary",
            f"control database is at schema version {stored}; this acp ({__version__}) "
            f"understands version {SCHEMA_VERSION}. Upgrade acp — an older binary cannot "
            "see the newer columns and would operate on a partial view of the state.",
        )


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
class IntegrationGitBoundary:
    git: str
    git_dir: Path
    object_dir: Path
    env: Mapping[str, str]
    git_digest: str
    git_size: int
    config_digest: str
    alternates_text: str
    global_attributes: bytes | None
    info_attributes: bytes | None
    merge_input_evidence: Mapping[str, Any]
    oid_length: int


@dataclass(frozen=True)
class AttributeSnapshot:
    content: bytes | None
    evidence: Mapping[str, Any]


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
  cleanup_target_status TEXT NOT NULL DEFAULT '',
  cleanup_error TEXT NOT NULL DEFAULT '',
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
  pid_identity TEXT NOT NULL DEFAULT '',
  termination_target_status TEXT NOT NULL DEFAULT '',
  termination_proof TEXT NOT NULL DEFAULT '',
  launch_owner_pid INTEGER,
  launch_owner_identity TEXT NOT NULL DEFAULT '',
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
  object_contract TEXT NOT NULL DEFAULT '',
  patch_sha256 TEXT NOT NULL,
  changed_paths_json TEXT NOT NULL,
  resource_tokens_json TEXT NOT NULL,
  status TEXT NOT NULL,
  qc_resume_status TEXT NOT NULL DEFAULT '',
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
  recovery_action TEXT NOT NULL DEFAULT '',
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
CREATE TABLE IF NOT EXISTS runtime_quarantine_receipts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  attempt_id TEXT NOT NULL REFERENCES attempts(id),
  driver TEXT NOT NULL,
  kind TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  action TEXT NOT NULL,
  operator TEXT NOT NULL,
  reason TEXT NOT NULL,
  absence_proved INTEGER NOT NULL,
  recorded_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_quarantine_receipts_attempt
  ON runtime_quarantine_receipts(attempt_id, recorded_at DESC);
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
    def __init__(
        self,
        repo: str | Path = ".",
        *,
        diagnostic: bool = False,
        read_only: bool = False,
    ):
        self.root = self._root(Path(repo).resolve())
        self._diagnostic = diagnostic
        self.read_only = read_only
        self.schema_version_on_open: int | None = None
        self._trust_config_error: str | None = None
        self.config_path = self.root / "acp.toml"
        self.state_dir = self.root / ".acp"
        self.db_path = self.state_dir / "control.db"
        if not self.config_path.exists():
            raise SupervisorError("not_initialized", "acp.toml is missing; run acp init")
        self.config = self._load_config()
        if read_only:
            self._open_read_only()
        else:
            self._open_read_write()
        self._finish_open()

    def _open_read_only(self) -> None:
        """Attach to an existing database without creating, migrating or reconciling it.

        docs/ARCHITECTURE.md promises planning is a preview and never a mutation. That
        was only true of the queries: constructing the supervisor created directories and
        ALTERed the schema before the first SELECT ran. A read-only open refuses instead
        of upgrading, so `acp status` on a database that needs work says so rather than
        silently doing it under an operator who asked to look.
        """

        if not self.db_path.exists():
            raise SupervisorError("not_initialized", f"{self.db_path} is missing; run acp init")
        with self.connect() as connection:
            self.schema_version_on_open = stored_schema_version(connection)
        assert_schema_not_newer(self.schema_version_on_open)
        if self.schema_version_on_open is None or self.schema_version_on_open < SCHEMA_VERSION:
            found = (
                "unstamped (predates schema versioning)"
                if self.schema_version_on_open is None
                else str(self.schema_version_on_open)
            )
            raise SupervisorError(
                "schema_upgrade_required",
                f"control database is at schema version {found} and this acp "
                f"({__version__}) expects {SCHEMA_VERSION}. Read-only commands do not "
                "migrate; run `acp migrate` to upgrade it.",
            )

    def _open_read_write(self) -> None:
        """Create state directories, bring the schema up to date, and stamp the version."""

        self.state_dir.mkdir(parents=True, exist_ok=True)
        (self.state_dir / "worktrees").mkdir(exist_ok=True)
        (self.state_dir / "logs").mkdir(exist_ok=True)
        (self.state_dir / "runtime").mkdir(exist_ok=True)
        with self.connect() as connection:
            # Read the stamp before the first CREATE/ALTER. Checking afterwards would be
            # checking a database this binary had already written to.
            self.schema_version_on_open = stored_schema_version(connection)
            assert_schema_not_newer(self.schema_version_on_open)
            connection.executescript(SCHEMA)
            self._migrate(connection)
            connection.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('claim_counter', '0')"
            )
            attempt_columns = _columns(connection, "attempts")
            legacy_worker_identity_missing = "pid_identity" not in attempt_columns
            if "runner_credential_digest" not in attempt_columns:
                connection.execute("ALTER TABLE attempts ADD COLUMN runner_credential_digest TEXT")
            if legacy_worker_identity_missing:
                connection.execute(
                    "ALTER TABLE attempts ADD COLUMN pid_identity TEXT NOT NULL DEFAULT ''"
                )
            if "termination_target_status" not in attempt_columns:
                connection.execute(
                    "ALTER TABLE attempts ADD COLUMN termination_target_status "
                    "TEXT NOT NULL DEFAULT ''"
                )
            if "termination_proof" not in attempt_columns:
                connection.execute(
                    "ALTER TABLE attempts ADD COLUMN termination_proof TEXT NOT NULL DEFAULT ''"
                )
            if "launch_owner_pid" not in attempt_columns:
                connection.execute("ALTER TABLE attempts ADD COLUMN launch_owner_pid INTEGER")
            if "launch_owner_identity" not in attempt_columns:
                connection.execute(
                    "ALTER TABLE attempts ADD COLUMN launch_owner_identity TEXT NOT NULL DEFAULT ''"
                )
            if legacy_worker_identity_missing:
                # Older databases stored a PID without the kernel start-time
                # identity needed to distinguish the worker from PID reuse.
                # Fence every such live registration during the one-time
                # migration. Guessing or clearing it could signal an unrelated
                # process or release resources while the original worker lives.
                stamp = utc_now()
                legacy_workers = connection.execute(
                    "SELECT id, task_id, agent_id FROM attempts WHERE pid > 0"
                ).fetchall()
                for worker in legacy_workers:
                    connection.execute(
                        "UPDATE attempts SET status = 'terminating', "
                        "termination_target_status = 'quarantined', "
                        "termination_proof = '', updated_at = ? WHERE id = ?",
                        (stamp, worker["id"]),
                    )
                    connection.execute(
                        "UPDATE tasks SET status = 'cleanup_pending', "
                        "cleanup_target_status = 'blocked', cleanup_error = ?, "
                        "updated_at = ? WHERE id = ? AND current_attempt_id = ?",
                        (
                            "legacy worker PID has no verifiable kernel identity; cleanup remains fenced",
                            stamp,
                            worker["task_id"],
                            worker["id"],
                        ),
                    )
                    connection.execute(
                        "UPDATE resource_leases SET lease_expires_at = ?, updated_at = ? "
                        "WHERE attempt_id = ?",
                        (CLEANUP_FENCE_EPOCH, stamp, worker["id"]),
                    )
                    connection.execute(
                        "UPDATE runtime_allocations SET lease_expires_at = ?, updated_at = ? "
                        "WHERE attempt_id = ?",
                        (CLEANUP_FENCE_EPOCH, stamp, worker["id"]),
                    )
                    self._event(
                        connection,
                        "worker.identity_migration_fenced",
                        "supervisor",
                        {"attempt_id": worker["id"], "agent_id": worker["agent_id"]},
                    )
            driver_columns = _columns(connection, "runtime_driver_resources")
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
            runtime_columns = _columns(connection, "runtime_environments")
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
            if "recovery_action" not in runtime_columns:
                connection.execute(
                    "ALTER TABLE runtime_environments "
                    "ADD COLUMN recovery_action TEXT NOT NULL DEFAULT ''"
                )
            # Upgrade registries created before the explicit flag existed. Once
            # enabled, authentication never silently downgrades because the last
            # credential was revoked.
            if connection.execute("SELECT 1 FROM runner_identities LIMIT 1").fetchone():
                connection.execute(
                    "INSERT OR IGNORE INTO meta(key, value) VALUES('runner_auth_enabled', '1')"
                )
            self._apply_migration_ledger(connection, self.schema_version_on_open)
            connection.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)",
                (SCHEMA_VERSION_KEY, str(SCHEMA_VERSION)),
            )
            connection.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)",
                (SCHEMA_WRITTEN_BY_KEY, __version__),
            )

    @staticmethod
    def _apply_migration_ledger(connection: sqlite3.Connection, stored: int | None) -> None:
        """Apply every numbered upgrade the database has not seen, in order.

        `stored` is None for a database that predates stamping; the baseline above has
        just brought it to version 1, so it starts here from 1 like any other.

        The caller's `connect()` block is the transaction, and it is deliberately one
        transaction for the whole ledger rather than one per entry: an upgrade that fails
        halfway should leave the database at the version it arrived at, not at whichever
        entry happened to be the last to succeed. Each stamp is written next to the
        change it describes, so both roll back together.
        """

        current = 1 if stored is None else stored
        for version, upgrade in MIGRATIONS:
            if version <= current:
                continue
            upgrade(connection)
            connection.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)",
                (SCHEMA_VERSION_KEY, str(version)),
            )
            current = version

    def _finish_open(self) -> None:
        common_value = self._git_text("rev-parse", "--path-format=absolute", "--git-common-dir")
        self._git_common_dir = Path(common_value)
        if not self._git_common_dir.is_absolute():
            self._git_common_dir = (self.root / self._git_common_dir).resolve()
        self._assert_no_git_grafts()
        if self.read_only:
            # Both of the calls below write. A read-only open leaves reconciliation to a
            # command that admits it mutates, rather than doing it under `acp status`.
            return
        self._invalidate_legacy_submissions()
        self._reconcile_pending_integrations()

    def schema_state(self) -> dict[str, Any]:
        """Schema version found when this supervisor opened, against what the binary expects."""

        return {
            "database": self.schema_version_on_open,
            "binary": SCHEMA_VERSION,
            "written_by": __version__,
        }

    def migrate(self) -> dict[str, Any]:
        """Report the upgrade that opening this supervisor read-write already performed.

        `version_changed` describes the stamp, not whether any SQL ran. The baseline
        column adds are idempotent repairs of a database already at its recorded
        version, so a legacy database can gain a column here and still report the same
        version on both sides. A version number cannot detect that drift — which is the
        reason changes after version 1 go through the ledger instead.
        """

        if self.read_only:
            raise SupervisorError("read_only", "migrate needs a read-write supervisor")
        previous = self.schema_version_on_open
        return {
            "ok": True,
            "previous": previous,
            "current": SCHEMA_VERSION,
            "version_changed": previous != SCHEMA_VERSION,
        }

    @staticmethod
    def _migrate(connection: sqlite3.Connection) -> None:
        """Add columns introduced after a database was first created.

        CREATE TABLE IF NOT EXISTS silently leaves an older table alone, so new
        columns have to be added explicitly. Each step is idempotent.
        """
        columns = _columns(connection, "tasks")
        for column in ("produces_json", "consumes_json"):
            if column not in columns:
                connection.execute(
                    f"ALTER TABLE tasks ADD COLUMN {column} TEXT NOT NULL DEFAULT '[]'"
                )
        if "cleanup_target_status" not in columns:
            connection.execute(
                "ALTER TABLE tasks ADD COLUMN cleanup_target_status TEXT NOT NULL DEFAULT ''"
            )
        if "cleanup_error" not in columns:
            connection.execute(
                "ALTER TABLE tasks ADD COLUMN cleanup_error TEXT NOT NULL DEFAULT ''"
            )
        attempt_columns = _columns(connection, "attempts")
        if "trust_bundle_json" not in attempt_columns:
            connection.execute(
                "ALTER TABLE attempts ADD COLUMN trust_bundle_json TEXT NOT NULL DEFAULT '{}'"
            )
        submission_columns = _columns(connection, "submissions")
        if "qc_resume_status" not in submission_columns:
            connection.execute(
                "ALTER TABLE submissions ADD COLUMN qc_resume_status TEXT NOT NULL DEFAULT ''"
            )
        if "object_contract" not in submission_columns:
            connection.execute(
                "ALTER TABLE submissions ADD COLUMN object_contract TEXT NOT NULL DEFAULT ''"
            )
        qc_columns = _columns(connection, "qc_runs")
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
            pytest_command = f"{shlex.quote(sys.executable)} -m pytest -q"
            config.write_text(
                "[supervisor]\n"
                "lease_seconds = 300\n"
                "qc_timeout_seconds = 900\n"
                'critic_identity = "independent-qc"\n'
                "require_critic = true\n\n"
                "[qc]\n"
                f"commands = {json.dumps([pytest_command])}\n"
                'critic_command = "builtin"\n\n'
                "[integration]\n"
                f"commands = {json.dumps([pytest_command])}\n\n"
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
        git = GitSupervisor._system_git_executable(candidate)
        env = {name: value for name, value in os.environ.items() if name in PUBLIC_CHILD_ENV}
        env.update(
            {
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_ATTR_NOSYSTEM": "1",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_TERMINAL_PROMPT": "0",
            }
        )
        result = subprocess.run(
            [
                str(git),
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(candidate),
                "rev-parse",
                "--show-toplevel",
            ],
            env=env,
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
            "SELECT task_id, status, pid, pid_identity, termination_target_status "
            "FROM attempts WHERE id = ?",
            (attempt_id,),
        ).fetchone()
        if not attempt:
            return
        worker_slot_fenced = attempt["pid"] is not None
        if worker_slot_fenced:
            # A registered PID is evidence, not disposable metadata. Keep the
            # exact kernel identity and let the reaper prove it gone before the
            # attempt reaches its terminal quarantine state. This also retains
            # pid=-1 launch reservations until the blocked monitor either
            # registers its real PID or observes the closed handshake.
            connection.execute(
                "UPDATE attempts SET status = 'terminating', "
                "termination_target_status = 'quarantined', updated_at = ? "
                "WHERE id = ?",
                (stamp, attempt_id),
            )
        else:
            connection.execute(
                "UPDATE attempts SET status = 'quarantined', pid = NULL, "
                "pid_identity = '', termination_target_status = '', termination_proof = '', "
                "launch_owner_pid = NULL, launch_owner_identity = '', updated_at = ? WHERE id = ?",
                (stamp, attempt_id),
            )
        self._fence_task_cleanup(
            connection,
            attempt["task_id"],
            attempt_id,
            "blocked",
            "supervisor",
            "trust_bundle_quarantined",
        )
        connection.execute(
            "UPDATE tasks SET cleanup_error = ?, updated_at = ? WHERE id = ?",
            ("trust bundle invalid: " + "; ".join(errors), stamp, attempt["task_id"]),
        )
        connection.execute(
            "UPDATE submissions SET status = 'blocked', qc_resume_status = '' "
            "WHERE task_id = ? AND status = 'qc_running'",
            (attempt["task_id"],),
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
            {
                "attempt_id": attempt_id,
                "errors": list(errors),
                "worker_slot_fenced": worker_slot_fenced,
                "worker_pid": attempt["pid"],
                "worker_identity_retained": bool(attempt["pid_identity"]),
            },
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
        if self.read_only:
            # mode=ro makes the refusal structural rather than a matter of discipline:
            # a stray INSERT raises instead of landing. journal_mode and secure_delete
            # are omitted because setting them writes the database header — which is
            # exactly how a "read-only" command used to leave fingerprints.
            connection = sqlite3.connect(f"{self.db_path.as_uri()}?mode=ro", uri=True, timeout=30)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 30000")
            try:
                yield connection
            finally:
                connection.close()
            return
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
        self._assert_no_git_grafts()
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

    @staticmethod
    def _assert_submission_object_contract(
        submission: sqlite3.Row | dict[str, Any],
    ) -> None:
        if submission["object_contract"] != SUBMISSION_OBJECT_CONTRACT:
            raise SupervisorError(
                "submission_evidence_contract_stale",
                "submission predates the replacement-free object contract; resubmit and rerun QC",
            )

    def _invalidate_legacy_submissions(self) -> None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """
                SELECT submission.* FROM submissions AS submission
                JOIN tasks AS task ON task.id = submission.task_id
                WHERE submission.object_contract != ?
                  AND submission.status IN
                    ('pending_qc', 'qc_running', 'pending_second_review', 'approved',
                     'human_required')
                  AND task.status IN ('qc_review', 'approved', 'integrating')
                ORDER BY submission.created_at, submission.id
                """,
                (SUBMISSION_OBJECT_CONTRACT,),
            ).fetchall()
            for submission in rows:
                self._invalidate_legacy_submission_in(connection, submission, "migration")

    def _invalidate_legacy_submission_in(
        self,
        connection: sqlite3.Connection,
        submission: sqlite3.Row,
        actor: str,
    ) -> None:
        connection.execute(
            "UPDATE submissions SET status = 'changes_requested', qc_resume_status = '' "
            "WHERE id = ?",
            (submission["id"],),
        )
        task = self._task_row(connection, submission["task_id"])
        if task["status"] != "cleanup_pending":
            self._fence_task_cleanup(
                connection,
                submission["task_id"],
                submission["attempt_id"],
                "changes_requested",
                actor,
                "submission_object_contract_changed",
            )
        self._event(
            connection,
            "submission.object_contract_invalidated",
            actor,
            {
                "submission_id": submission["id"],
                "task_id": submission["task_id"],
                "old_contract": submission["object_contract"],
                "required_contract": SUBMISSION_OBJECT_CONTRACT,
            },
        )

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
                self._assert_safe_git_execution_config()
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
        snapshot = StatusView(self).snapshot(limit, lease_risk_seconds)
        with self.connect() as connection:
            reclaimable, _ = self._gc_survey(connection, time.time(), DEFAULT_GC_RETENTION_SECONDS)
        snapshot["disk"] = {
            "state_bytes": self._directory_bytes(self.state_dir),
            "reclaimable_worktrees": len(reclaimable),
            "reclaimable_bytes": sum(entry["bytes"] for entry in reclaimable),
        }
        return snapshot

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
        pass_fds: Sequence[int] = (),
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        log_path.parent.mkdir(parents=True, exist_ok=True)
        for command in commands:
            result = self._run_command(command, cwd, environment, pass_fds=pass_fds)
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
        env["GIT_ATTR_NOSYSTEM"] = "1"
        env["GIT_NO_REPLACE_OBJECTS"] = "1"
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

    def _driver_secret_read_only(self) -> bytes:
        """Read the driver HMAC key without migrating or creating state.

        Operator views call this path. A diagnostic command must not turn a
        missing key into a new key or perform the legacy meta-table migration;
        either mutation would make ``runtime-quarantine explain`` an unsafe
        recovery operation disguised as a read.
        """

        key_path = self.state_dir / "driver.key"
        if key_path.exists():
            flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            try:
                descriptor = os.open(key_path, flags)
            except OSError as error:
                raise SupervisorError(
                    "driver_key_unavailable", "driver key file is unavailable"
                ) from error
            try:
                info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or info.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
                ):
                    raise SupervisorError(
                        "driver_key_unsafe",
                        "driver key must be a current-user-owned 0600 regular file",
                    )
                value = os.read(descriptor, 33)
                if len(value) != 32:
                    raise SupervisorError(
                        "driver_key_invalid", "driver key must contain exactly 32 bytes"
                    )
                return value
            finally:
                os.close(descriptor)

        with self.connect() as connection:
            row = connection.execute(
                "SELECT value FROM meta WHERE key = 'driver_secret'"
            ).fetchone()
        if not row:
            raise SupervisorError("driver_key_unavailable", "driver key file is unavailable")
        try:
            value = bytes.fromhex(row["value"])
        except ValueError as error:
            raise SupervisorError("driver_key_invalid", "legacy driver key is invalid") from error
        if len(value) != 32:
            raise SupervisorError("driver_key_invalid", "legacy driver key is invalid")
        return value

    def _driver_secret(self) -> bytes:
        """Per-supervisor key stored separately from the SQLite evidence DB.

        Keeping the HMAC key in the same backup as keyed credential
        fingerprints would turn weak credential material into an offline
        guessing oracle. Older databases are migrated by writing their key to
        the protected file before deleting the meta row.
        """

        key_path = self.state_dir / "driver.key"

        def read_key() -> bytes:
            flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
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
            execution_options["process_runner"] = self._run_trusted_contained
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

    # ------------------------------------------------------------------ #
    # Quarantine explain / recover (#740)
    #
    # Quarantine is deliberately fail-closed: an unproven teardown parks the
    # allocation rather than recycling it. That is correct, and it was also a
    # dead end — reading WHY a resource was parked, or getting it out, needed
    # someone to open the SQLite file by hand. These two entry points are the
    # supported path, and they keep every guarantee the fail-closed design
    # exists to provide:
    #
    #   * explain NEVER exposes an ownership token or credential material. The
    #     token is the capability that authorises teardown of a real resource;
    #     an operator diagnosing a stuck row has no need of it.
    #   * recover NEVER rewrites immutable allocation identity. attempt_id,
    #     driver, kind, resource_id and ownership_token are what bind a row to
    #     the thing it allocated; rewriting any of them to make a mismatch go
    #     away would forge exactly the proof the mismatch is reporting.
    #   * recover NEVER releases an allocation on an assertion. A port returns
    #     to the pool only against a POSITIVE ABSENCE PROOF — the driver's own
    #     verify phase reporting present=False, or the port failing to accept a
    #     bind. An operator receipt is authenticated and recorded, but it is
    #     testimony, not proof, and it cannot release anything on its own.
    # ------------------------------------------------------------------ #

    _QUARANTINE_ACTIONS: tuple[str, ...] = (
        "restore-definition",
        "retry-cleanup",
        "manual-receipt",
    )

    @staticmethod
    def _public_evidence(raw: str) -> dict[str, Any]:
        """Evidence with every capability and secret stripped.

        Redaction is by ALLOW-list on the nested credential handle and by
        explicit removal of the token, because evidence is driver-authored: a
        deny-list would silently start leaking the day a driver adds a field.
        """

        try:
            evidence = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            return {"unreadable": True}
        if not isinstance(evidence, dict):
            return {"unreadable": True}
        evidence.pop("ownership_token", None)
        handle = evidence.get("credential_handle")
        if isinstance(handle, dict):
            evidence["credential_handle"] = {
                key: handle[key] for key in ("name", "version") if key in handle
            }
        return evidence

    def _identity_proved(self, row: sqlite3.Row) -> bool:
        """Does this row still prove it owns the resource it names?

        Recomputes the HMAC over the immutable triple. A legacy or corrupted
        row whose token still verifies is provably the same allocation and may
        be migrated; one whose token does not verify is NOT, and no amount of
        operator intent can make it so.
        """

        stored = row["ownership_token"] or ""
        if not stored:
            return False
        try:
            secret = self._driver_secret_read_only()
        except SupervisorError:
            return False
        expected = ownership_token(secret, row["attempt_id"], row["kind"], row["resource_id"])
        return hmac.compare_digest(stored, expected)

    def _pinned_definitions(self, attempt_id: str) -> tuple[dict[str, str], str | None]:
        """Current pinned definition JSON by driver name, or why it is unavailable.

        Never raises: explain must keep working on exactly the broken attempts
        it exists to describe, including ones whose trust pin no longer
        verifies.
        """

        with self.connect() as connection:
            row = connection.execute(
                "SELECT trust_bundle_json FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
        if not row:
            return {}, "attempt_not_found"
        try:
            pin = json.loads(row["trust_bundle_json"] or "{}")
        except (json.JSONDecodeError, TypeError):
            return {}, "trust_bundle_invalid"
        if not isinstance(pin, dict):
            return {}, "trust_bundle_invalid"
        if not pin and self.config.trust_root is not None:
            return {}, "trust_bundle_quarantined"
        if pin:
            try:
                verified = verify_bundle_pin(pin)
            except TrustBundleError as error:
                return {}, error.code
            if not verified["ok"]:
                return {}, "trust_bundle_quarantined"
        try:
            return {
                definition.name: self._driver_definition_json(definition)
                for definition in self._driver_definitions_for_pin(pin)
            }, None
        except (SupervisorError, TrustBundleError) as error:
            return {}, error.code

    def _mismatch_class(
        self, row: sqlite3.Row, pinned: dict[str, str], pin_error: str | None
    ) -> str:
        stored_definition = row["definition_json"]
        if stored_definition == "{}":
            return "definition_missing"
        try:
            self._driver_definition_from_json(stored_definition)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return "definition_corrupt"
        if pin_error:
            return "trust_pin_unavailable"
        current = pinned.get(row["driver"])
        if current is None:
            return "driver_removed_from_config"
        if current != stored_definition:
            return "config_drift"
        evidence = self._public_evidence(row["evidence_json"])
        proof = evidence.get("proof")
        if isinstance(proof, dict) and not proof.get("cleanup_proved"):
            return "cleanup_unproven"
        if evidence.get("present"):
            return "resource_still_present"
        return "unclassified"

    @staticmethod
    def _quarantine_severity(mismatch: str, evidence: dict[str, Any]) -> str:
        """Severity is about what may still be RUNNING, not about tidiness."""

        if evidence.get("present"):
            return "critical"
        if mismatch in {"cleanup_unproven", "resource_still_present"}:
            return "critical"
        if mismatch in {
            "definition_missing",
            "definition_corrupt",
            "config_drift",
            "driver_removed_from_config",
            "trust_pin_unavailable",
        }:
            return "high"
        return "normal"

    @staticmethod
    def _safe_next_actions(mismatch: str, identity_proved: bool) -> list[str]:
        if not identity_proved:
            return [
                (
                    "identity is NOT proven for this row: its ownership token does "
                    "not match the attempt/kind/resource it names"
                ),
                (
                    "do NOT recover it — recovery would have to forge the binding it "
                    "is failing to prove"
                ),
                (
                    "investigate by hand, then record an authenticated manual receipt "
                    "once the real resource is confirmed gone"
                ),
            ]
        if mismatch in {"definition_missing", "definition_corrupt", "config_drift"}:
            return [
                (
                    "acp runtime-quarantine recover ATTEMPT --action restore-definition "
                    "(re-pins the stored definition from the trusted bundle; identity "
                    "is verified first and never rewritten)"
                ),
                "then: --action retry-cleanup",
            ]
        if mismatch in {"cleanup_unproven", "resource_still_present"}:
            return [
                (
                    "acp runtime-quarantine recover ATTEMPT --action retry-cleanup "
                    "(re-runs the exact stored teardown and re-probes)"
                ),
                (
                    "if the resource is genuinely gone but the driver cannot prove it: "
                    "--action manual-receipt --operator ID --reason TEXT (records the "
                    "claim; releases nothing without a positive absence proof)"
                ),
            ]
        if mismatch == "driver_removed_from_config":
            return [
                (
                    "the driver is no longer configured, so its definition cannot be "
                    "re-pinned: restore it in acp.toml, or clean up by hand and record "
                    "a manual receipt"
                ),
            ]
        if mismatch == "trust_pin_unavailable":
            return [
                (
                    "the attempt's trust pin does not verify, so no definition can be "
                    "restored from it: fix trust first (acp trust list)"
                ),
            ]
        return ["inspect the evidence below; no automatic action is safe"]

    def quarantine_explain(self, attempt_id: str) -> dict[str, Any]:
        """Why each resource on *attempt_id* is parked, and what is safe next.

        Read-only by construction: it opens no driver, runs no phase and takes
        no lock. Diagnosing a stuck runtime must never be able to change it.
        """

        with self.connect() as connection:
            attempt = connection.execute(
                "SELECT id, agent_id, task_id FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
            if not attempt:
                raise SupervisorError("attempt_not_found", "attempt does not exist")
            runtime = connection.execute(
                "SELECT state, updated_at FROM runtime_environments WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            rows = connection.execute(
                "SELECT * FROM runtime_driver_resources WHERE attempt_id = ? ORDER BY driver",
                (attempt_id,),
            ).fetchall()
            receipts = connection.execute(
                "SELECT driver, action, operator, reason, absence_proved, recorded_at "
                "FROM runtime_quarantine_receipts WHERE attempt_id = ? "
                "ORDER BY recorded_at DESC",
                (attempt_id,),
            ).fetchall()
            allocations = connection.execute(
                "SELECT pool_name, value FROM runtime_allocations WHERE attempt_id = ? "
                "ORDER BY pool_name",
                (attempt_id,),
            ).fetchall()

        pinned, pin_error = self._pinned_definitions(attempt_id)
        now = time.time()
        resources: list[dict[str, Any]] = []
        for row in rows:
            if row["state"] != "quarantined":
                continue
            evidence = self._public_evidence(row["evidence_json"])
            mismatch = self._mismatch_class(row, pinned, pin_error)
            proved = self._identity_proved(row)
            resources.append(
                {
                    "driver": row["driver"],
                    "kind": row["kind"],
                    "resource_id": row["resource_id"],
                    "state": row["state"],
                    "owner": attempt["agent_id"],
                    "quarantined_at": row["updated_at"],
                    "age_seconds": _age_seconds(row["updated_at"], now),
                    "severity": self._quarantine_severity(mismatch, evidence),
                    "mismatch_class": mismatch,
                    "identity_proved": proved,
                    "last_trusted_evidence": evidence,
                    "safe_next_actions": self._safe_next_actions(mismatch, proved),
                }
            )
        return {
            "ok": True,
            "attempt_id": attempt_id,
            "task_id": attempt["task_id"],
            "owner": attempt["agent_id"],
            "runtime_state": runtime["state"] if runtime else None,
            "trust_pin_error": pin_error,
            "quarantined": len(resources),
            "resources": resources,
            "held_allocations": [
                {
                    "pool": allocation["pool_name"],
                    "value": allocation["value"],
                    "port_free_now": self._port_available(allocation["value"]),
                }
                for allocation in allocations
            ],
            "receipts": [dict(receipt) for receipt in receipts],
        }

    def _restore_pinned_definitions(self, attempt_id: str) -> dict[str, Any]:
        pinned, pin_error = self._pinned_definitions(attempt_id)
        if pin_error:
            raise SupervisorError(
                "runtime_trust_pin_unavailable",
                f"cannot restore definitions while the trust pin is unusable ({pin_error})",
            )
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM runtime_driver_resources WHERE attempt_id = ? "
                "AND state = 'quarantined' ORDER BY driver",
                (attempt_id,),
            ).fetchall()
        restored: list[str] = []
        refused: list[dict[str, str]] = []
        for row in rows:
            if not self._identity_proved(row):
                refused.append({"driver": row["driver"], "reason": "identity_unproved"})
                continue
            current = pinned.get(row["driver"])
            if current is None:
                refused.append({"driver": row["driver"], "reason": "driver_not_in_pin"})
                continue
            if current == row["definition_json"]:
                continue
            restored.append(row["driver"])
            with self.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                # Identity columns are absent from this UPDATE on purpose.
                connection.execute(
                    "UPDATE runtime_driver_resources SET definition_json = ?, updated_at = ? "
                    "WHERE attempt_id = ? AND driver = ?",
                    (current, utc_now(), attempt_id, row["driver"]),
                )
                self._event(
                    connection,
                    "runtime.quarantine.definition_restored",
                    "supervisor",
                    {
                        "attempt_id": attempt_id,
                        "driver": row["driver"],
                        "kind": row["kind"],
                    },
                )
        if refused:
            # A row we could not prove stays parked, and the runtime is pinned to
            # teardown_failed atomically so nothing downstream reads it as healthy.
            self._quarantine_driver_attempt(attempt_id, "runtime_quarantine_identity_unproved")
        return {"restored": restored, "refused": refused}

    def _retry_quarantined_cleanup(self, attempt_id: str, guard_fd: int) -> dict[str, Any]:
        with self.connect() as connection:
            runtime = connection.execute(
                "SELECT env_json FROM runtime_environments WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if not runtime:
                raise SupervisorError("runtime_not_found", "runtime environment is missing")
            drivers = [
                row["driver"]
                for row in connection.execute(
                    "SELECT driver FROM runtime_driver_resources WHERE attempt_id = ? "
                    "AND state = 'quarantined'",
                    (attempt_id,),
                ).fetchall()
            ]
        if not drivers:
            return {"retried": [], "still_quarantined_drivers": [], "released": []}
        environment = json.loads(runtime["env_json"])
        # The exact stored definition is re-run — _run_driver_phase reads
        # definition_json for an attempt that already has rows, so this is a
        # retry of the recorded cleanup and not a fresh interpretation of config.
        evidence = self._run_driver_phase(
            "teardown",
            attempt_id,
            environment,
            only_drivers=set(drivers),
            restart_guard_fd=guard_fd,
        )
        released = [item.driver for item in evidence if item.proof.get("cleanup_proved")]
        still = [item.driver for item in evidence if not item.proof.get("cleanup_proved")]
        # Named *_drivers so it cannot collide with the integer count the caller
        # adds; an earlier revision returned both under one key and the list won.
        return {"retried": drivers, "released": released, "still_quarantined_drivers": still}

    def _authenticate_operator(self, operator: str, credential: str) -> None:
        if not operator or not credential:
            raise SupervisorError(
                "quarantine_receipt_unauthenticated",
                "a manual cleanup receipt requires an operator id and its runner credential",
            )
        with self.connect() as connection:
            row = connection.execute(
                "SELECT role, credential_digest, revoked_at FROM runner_identities "
                "WHERE agent_id = ?",
                (operator,),
            ).fetchone()
        if not row or row["revoked_at"] or row["role"] != "integrator":
            raise SupervisorError(
                "quarantine_receipt_unauthenticated",
                "operator is not an enrolled, unrevoked integrator identity",
            )
        if not verify_credential(credential, row["credential_digest"]):
            raise SupervisorError(
                "quarantine_receipt_unauthenticated",
                "operator credential does not verify",
            )

    def _authenticate_recovery_operator(self, operator: str, credential: str) -> None:
        """Require a privileged identity once runner authentication is enabled."""

        if not self._identity_enforced():
            return
        try:
            self._authenticate(operator, "integrator", credential or None)
        except SupervisorError as error:
            raise SupervisorError(
                "quarantine_recovery_unauthenticated",
                "quarantine recovery requires a valid integrator credential",
            ) from error

    def _record_manual_receipt(
        self,
        attempt_id: str,
        operator: str,
        credential: str,
        reason: str,
        guard_fd: int,
    ) -> dict[str, Any]:
        if not reason.strip():
            raise SupervisorError(
                "quarantine_receipt_invalid", "a manual cleanup receipt requires a reason"
            )
        self._authenticate_operator(operator, credential)
        with self.connect() as connection:
            runtime = connection.execute(
                "SELECT env_json FROM runtime_environments WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            rows = connection.execute(
                "SELECT * FROM runtime_driver_resources WHERE attempt_id = ? "
                "AND state = 'quarantined' ORDER BY driver",
                (attempt_id,),
            ).fetchall()
        if not rows:
            return {"receipts": [], "released": []}

        # THE RECEIPT IS TESTIMONY; THE VERIFY PHASE IS THE PROOF. An operator
        # saying "I removed it" is recorded either way, but a row is only
        # released when the driver itself reports the resource absent.
        absent: set[str] = set()
        probe_error: str | None = None
        eligible = {row["driver"] for row in rows if self._identity_proved(row)}
        if runtime is not None and eligible:
            try:
                evidence = self._run_driver_phase(
                    "verify",
                    attempt_id,
                    json.loads(runtime["env_json"]),
                    only_drivers=eligible,
                    restart_guard_fd=guard_fd,
                )
                absent = {
                    item.driver
                    for item in evidence
                    if item.present is False and item.exit_code == 0
                }
            except (SupervisorError, DriverError) as error:
                probe_error = error.code

        stamp = utc_now()
        receipts: list[dict[str, Any]] = []
        released: list[str] = []
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for row in rows:
                proved = row["driver"] in absent
                connection.execute(
                    "INSERT INTO runtime_quarantine_receipts"
                    "  (attempt_id, driver, kind, resource_id, action, operator, reason,"
                    "   absence_proved, recorded_at)"
                    " VALUES (?, ?, ?, ?, 'manual-receipt', ?, ?, ?, ?)",
                    (
                        attempt_id,
                        row["driver"],
                        row["kind"],
                        row["resource_id"],
                        operator,
                        reason.strip(),
                        1 if proved else 0,
                        stamp,
                    ),
                )
                receipts.append(
                    {
                        "driver": row["driver"],
                        "absence_proved": proved,
                        "operator": operator,
                    }
                )
                # 🔴 THE PROBE ITSELF MOVES STATE, so this re-asserts it. The verify
                # phase records evidence like any other phase, and
                # _record_driver_evidence maps a verify result to active/absent —
                # which silently lifts the quarantine on a row we have NOT proved
                # absent. Caught by the test that files a false receipt against a
                # profile still on disk: released was correctly empty, yet the row
                # had stopped being quarantined. State is therefore set explicitly
                # here, in the same transaction as the receipt, for both outcomes.
                connection.execute(
                    "UPDATE runtime_driver_resources SET state = ?, updated_at = ? "
                    "WHERE attempt_id = ? AND driver = ?",
                    ("released" if proved else "quarantined", stamp, attempt_id, row["driver"]),
                )
                if proved:
                    released.append(row["driver"])
                self._event(
                    connection,
                    "runtime.quarantine.manual_receipt",
                    "supervisor",
                    {
                        "attempt_id": attempt_id,
                        "driver": row["driver"],
                        "operator": operator,
                        "absence_proved": proved,
                    },
                )
        return {"receipts": receipts, "released": released, "probe_error": probe_error}

    def _release_proven_allocations(self, attempt_id: str) -> list[str]:
        """Return ports to the pool ONLY where absence is positively proved.

        A quarantined driver row anywhere on the attempt keeps every allocation
        parked: the ports and the resources belong to one runtime, and a port
        that merely looks free is not evidence that the thing which was using it
        is gone.
        """

        with self.connect() as connection:
            runtime = connection.execute(
                "SELECT state FROM runtime_environments WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            unsafe = connection.execute(
                "SELECT COUNT(*) FROM runtime_driver_resources WHERE attempt_id = ? "
                "AND state NOT IN ('released', 'absent')",
                (attempt_id,),
            ).fetchone()[0]
            allocations = connection.execute(
                "SELECT pool_name, value FROM runtime_allocations WHERE attempt_id = ? "
                "ORDER BY pool_name",
                (attempt_id,),
            ).fetchall()
        if not runtime or runtime["state"] != "teardown_failed" or unsafe or not allocations:
            return []
        freed: list[str] = []
        for allocation in allocations:
            if not self._port_available(allocation["value"]):
                continue
            if self._release_proven_allocation(
                attempt_id,
                allocation["pool_name"],
                allocation["value"],
            ):
                freed.append(f"{allocation['pool_name']}={allocation['value']}")
        return freed

    def _release_proven_allocation(self, attempt_id: str, pool: str, value: int) -> bool:
        """Delete one allocation durably so a crash can resume at the next row."""

        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            deleted = connection.execute(
                "DELETE FROM runtime_allocations WHERE attempt_id = ? AND pool_name = ? "
                "AND value = ?",
                (attempt_id, pool, value),
            )
            if deleted.rowcount != 1:
                return False
            self._event(
                connection,
                "runtime.quarantine.allocation_released",
                "supervisor",
                {
                    "attempt_id": attempt_id,
                    "pool": pool,
                    "value": value,
                    "proof": "port_bind_succeeded",
                },
            )
        return True

    def quarantine_recover(
        self,
        attempt_id: str,
        action: str,
        operator: str = "",
        credential: str = "",
        reason: str = "",
    ) -> dict[str, Any]:
        """Supported recovery for a quarantined runtime.

        Idempotent by construction: every action re-reads current state and is a
        no-op once its condition already holds, so repeating a recovery after a
        crash mid-way is always safe.
        """

        if action not in self._QUARANTINE_ACTIONS:
            raise SupervisorError(
                "quarantine_action_invalid",
                f"action must be one of {', '.join(self._QUARANTINE_ACTIONS)}",
            )
        with self._runtime_restart_guard(attempt_id, recover=False) as guard_fd:
            with self.connect() as connection:
                attempt = connection.execute(
                    "SELECT id FROM attempts WHERE id = ?", (attempt_id,)
                ).fetchone()
                runtime = connection.execute(
                    "SELECT state, recovery_action FROM runtime_environments WHERE attempt_id = ?",
                    (attempt_id,),
                ).fetchone()
                quarantined = connection.execute(
                    "SELECT COUNT(*) FROM runtime_driver_resources WHERE attempt_id = ? "
                    "AND state = 'quarantined'",
                    (attempt_id,),
                ).fetchone()[0]
            if not attempt:
                raise SupervisorError("attempt_not_found", "attempt does not exist")
            if not runtime:
                raise SupervisorError("runtime_not_found", "runtime environment is missing")
            if runtime["state"] == "released" and not quarantined:
                result: dict[str, Any] = {
                    "ok": True,
                    "attempt_id": attempt_id,
                    "action": action,
                    "still_quarantined": 0,
                    "held_allocations": 0,
                    "allocations_released": [],
                    "noop": True,
                }
                if action == "restore-definition":
                    result.update({"restored": [], "refused": []})
                elif action == "retry-cleanup":
                    result.update({"retried": [], "released": [], "still_quarantined_drivers": []})
                else:
                    result.update({"receipts": [], "released": []})
                return result
            if runtime["state"] != "teardown_failed":
                raise SupervisorError(
                    "runtime_not_quarantined",
                    f"runtime state is {runtime['state']}; recovery is only valid after failed teardown",
                )
            recovery_action = runtime["recovery_action"]
            if not quarantined and recovery_action != action:
                raise SupervisorError(
                    "runtime_quarantine_empty",
                    "failed teardown has no quarantined driver proof or resumable recovery intent",
                )
            if recovery_action and recovery_action != action:
                raise SupervisorError(
                    "runtime_recovery_action_mismatch",
                    f"resume the interrupted {recovery_action} action before starting {action}",
                )
            if action != "manual-receipt":
                self._authenticate_recovery_operator(operator, credential)
            else:
                if not reason.strip():
                    raise SupervisorError(
                        "quarantine_receipt_invalid",
                        "a manual cleanup receipt requires a reason",
                    )
                self._authenticate_operator(operator, credential)
            with self.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                changed = connection.execute(
                    "UPDATE runtime_environments SET recovery_action = ?, updated_at = ? "
                    "WHERE attempt_id = ? AND state = 'teardown_failed' "
                    "AND recovery_action IN ('', ?)",
                    (action, utc_now(), attempt_id, action),
                )
                if changed.rowcount != 1:
                    raise SupervisorError(
                        "runtime_recovery_stale",
                        "runtime recovery intent changed before it could be fenced",
                    )
            outcome: dict[str, Any]
            if action == "restore-definition":
                outcome = self._restore_pinned_definitions(attempt_id)
            elif action == "retry-cleanup":
                outcome = self._retry_quarantined_cleanup(attempt_id, guard_fd)
            else:
                outcome = self._record_manual_receipt(
                    attempt_id, operator, credential, reason, guard_fd
                )

            freed = self._release_proven_allocations(attempt_id)
            with self.connect() as connection:
                remaining = connection.execute(
                    "SELECT COUNT(*) FROM runtime_driver_resources WHERE attempt_id = ? "
                    "AND state = 'quarantined'",
                    (attempt_id,),
                ).fetchone()[0]
                held_allocations = connection.execute(
                    "SELECT COUNT(*) FROM runtime_allocations WHERE attempt_id = ?",
                    (attempt_id,),
                ).fetchone()[0]
            if not remaining and not held_allocations:
                runtime_dir = self.state_dir / "runtime" / attempt_id
                try:
                    shutil.rmtree(runtime_dir)
                except FileNotFoundError:
                    pass
                except OSError as error:
                    raise SupervisorError(
                        "runtime_staging_cleanup_failed",
                        "recovered runtime staging directory could not be removed",
                    ) from error
                with self.connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    updated = connection.execute(
                        "UPDATE runtime_environments SET state = 'released', "
                        "recovery_action = '', updated_at = ? "
                        "WHERE attempt_id = ? AND state = 'teardown_failed' "
                        "AND recovery_action = ?",
                        (utc_now(), attempt_id, action),
                    )
                    if updated.rowcount != 1:
                        raise SupervisorError(
                            "runtime_recovery_stale",
                            "runtime recovery intent changed before completion",
                        )
                    self._event(
                        connection,
                        "runtime.quarantine.cleared",
                        "supervisor",
                        {"attempt_id": attempt_id, "action": action},
                    )
            elif remaining:
                with self.connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute(
                        "UPDATE runtime_environments SET recovery_action = '', updated_at = ? "
                        "WHERE attempt_id = ? AND state = 'teardown_failed' "
                        "AND recovery_action = ?",
                        (utc_now(), attempt_id, action),
                    )
        return {
            "ok": True,
            "attempt_id": attempt_id,
            "action": action,
            "still_quarantined": remaining,
            "held_allocations": held_allocations,
            "allocations_released": freed,
            **outcome,
        }

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

        The trusted process monitor retains the descriptor and closes it in the
        command child before exec. If the supervisor dies during teardown, the
        kernel therefore keeps the lock until the monitor proves the command
        tree exited. The command can never inherit or unlock the fence.
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
            # Do not issue LOCK_UN: the trusted monitor may still hold the same
            # open-file description after an interrupted supervisor.
            os.close(lock_fd)

    @contextmanager
    def _task_operation_guard(self, task_id: str, recover: bool = False) -> Iterator[int]:
        """Serialize every QC/integration side effect for one task.

        The trusted monitor retains the descriptor but closes it in the command
        child before exec. A crashed supervisor therefore cannot make an
        expired reservation reusable while a command tree is still active, and
        candidate code cannot inherit or unlock the fence.
        """

        lock_dir = self.state_dir / "operation-locks"
        lock_dir.mkdir(mode=0o700, exist_ok=True)
        lock_path = lock_dir / f"{sha256(task_id.encode())}.lock"
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            lock_fd = os.open(lock_path, flags, 0o600)
        except OSError as error:
            raise SupervisorError(
                "task_operation_lock_unavailable",
                "task operation lock could not be opened",
            ) from error
        try:
            opened = os.fstat(lock_fd)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
            ):
                raise SupervisorError(
                    "task_operation_lock_unsafe",
                    "task operation lock must be a current-user-owned 0600 regular file",
                )
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno not in {errno.EACCES, errno.EAGAIN}:
                    raise SupervisorError(
                        "task_operation_lock_unavailable",
                        "task operation lock could not be acquired",
                    ) from error
                code = "task_operation_executor_alive" if recover else "task_operation_in_progress"
                raise SupervisorError(
                    code,
                    "another QC or integration operation for this task is still alive",
                ) from error
            yield lock_fd
        finally:
            # Closing our copy cannot drop a lock still retained by the monitor.
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
        with self._runtime_restart_guard(attempt_id, recover=False) as guard_fd:
            return self._runtime_up_locked(attempt_id, guard_fd)

    def _runtime_up_locked(self, attempt_id: str, guard_fd: int) -> dict[str, Any]:
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
            pass_fds=(guard_fd,),
        )
        failed = any(result["exit_code"] for result in results)
        if not failed:
            driver_evidence = self._run_driver_phase(
                "setup",
                attempt_id,
                environment,
                restart_guard_fd=guard_fd,
            )
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
        with self._runtime_restart_guard(attempt_id, recover=False) as guard_fd:
            return self._runtime_down_locked(attempt_id, force, _allow_active, guard_fd)

    def _runtime_down_locked(
        self,
        attempt_id: str,
        force: bool,
        _allow_active: bool,
        guard_fd: int,
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
            if row["recovery_action"]:
                raise SupervisorError(
                    "runtime_quarantine_recovery_in_progress",
                    "an interrupted quarantine recovery must be resumed through runtime-quarantine",
                )
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
            pass_fds=(guard_fd,),
        )
        # Drivers tear down AFTER the shell hooks and are then independently
        # re-probed. A hook that exits 0 proves only that a process exited 0.
        driver_evidence = self._run_driver_phase(
            "teardown",
            attempt_id,
            environment,
            restart_guard_fd=guard_fd,
        )
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
        staging_failed = False
        if not failed:
            try:
                shutil.rmtree(environment["ACP_RUNTIME_DIR"])
            except FileNotFoundError:
                pass
            except OSError:
                staging_failed = True
                failed = True
                results.append(
                    {
                        "command": "runtime-staging:remove",
                        "exit_code": 1,
                        "duration_ms": 0,
                    }
                )
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            stamp = utc_now()
            state = "teardown_failed" if failed else "released"
            connection.execute(
                """
                UPDATE runtime_environments
                SET state = ?, teardown_results_json = ?, recovery_action = ?, updated_at = ?
                WHERE attempt_id = ?
                """,
                (
                    state,
                    canonical_json(results),
                    "retry-cleanup" if staging_failed else "",
                    stamp,
                    attempt_id,
                ),
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
            self._assert_safe_git_execution_config()
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
        # Authenticate before a verification failure is allowed to change state.
        with self.connect() as connection:
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            self._authenticate_attempt(connection, attempt, credential)
        # A long-running worker must not retain authority after its immutable
        # trust bundle disappears. Quarantine commits in its own transaction so
        # the following claim-inactive error cannot roll the fence back.
        self._verify_attempt_trust(attempt_id)
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

    @staticmethod
    def _directory_bytes(path: Path) -> int:
        total = 0
        for entry in path.rglob("*"):
            if entry.is_file() and not entry.is_symlink():
                try:
                    total += entry.stat().st_size
                except OSError:
                    continue
        return total

    def _gc_survey(
        self,
        connection: sqlite3.Connection,
        now: float,
        older_than_seconds: int,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Classify every attempt worktree as reclaimable or retained. Reads only.

        Returns (reclaimable, retained). `status()` calls this to report disk without
        touching anything, and `gc()` calls it to decide what to remove, so the two can
        never disagree about what is safe.
        """

        fenced_attempts = {
            row["attempt_id"]
            for row in connection.execute(
                "SELECT attempt_id FROM resource_leases "
                "WHERE attempt_id IS NOT NULL AND lease_expires_at > ?",
                (now,),
            )
        }
        allocated_attempts = {
            row["attempt_id"]
            for row in connection.execute("SELECT attempt_id FROM runtime_allocations")
        }
        rows = connection.execute(
            """
            SELECT attempt.id AS attempt_id, attempt.task_id, attempt.branch,
                   attempt.worktree, attempt.status AS attempt_status,
                   attempt.updated_at AS attempt_updated_at,
                   task.status AS task_status, task.updated_at AS task_updated_at,
                   task.cleanup_target_status, task.cleanup_error
            FROM attempts AS attempt
            JOIN tasks AS task ON task.id = attempt.task_id
            ORDER BY attempt.created_at, attempt.id
            """
        ).fetchall()

        reclaimable: list[dict[str, Any]] = []
        retained: list[dict[str, Any]] = []
        for row in rows:
            worktree = Path(row["worktree"])
            entry = {
                "attempt_id": row["attempt_id"],
                "task_id": row["task_id"],
                "task_status": row["task_status"],
                "attempt_status": row["attempt_status"],
                "branch": row["branch"],
                "worktree": str(worktree),
            }
            age = _age_seconds(row["task_updated_at"], now)
            reason = self._gc_retain_reason(
                row,
                age=age,
                older_than_seconds=older_than_seconds,
                fenced=row["attempt_id"] in fenced_attempts,
                allocated=row["attempt_id"] in allocated_attempts,
                exists=worktree.exists(),
            )
            if reason is not None:
                retained.append({**entry, "reason": reason})
                continue
            reclaimable.append(
                {**entry, "age_seconds": age, "bytes": self._directory_bytes(worktree)}
            )
        return reclaimable, retained

    @staticmethod
    def _gc_retain_reason(
        row: sqlite3.Row,
        *,
        age: int | None,
        older_than_seconds: int,
        fenced: bool,
        allocated: bool,
        exists: bool,
    ) -> str | None:
        """Why this worktree must survive, or None if it is safe to reclaim.

        Ordered most-dangerous first so the reported reason is the one that matters. Any
        doubt retains: an unparseable timestamp is treated as "too recent" rather than
        as zero age, because guessing old on a clock we cannot read would delete a live
        agent's working copy.
        """

        if not exists:
            return "worktree_already_gone"
        if row["task_status"] in ACTIVE_STATUSES or row["task_status"] in {
            "integrating",
            "qc_review",
        }:
            return "task_active"
        if row["attempt_status"] in LIVE_ATTEMPT_STATUSES:
            return "attempt_live"
        if row["attempt_status"] == "quarantined":
            return "attempt_quarantined"
        if row["cleanup_target_status"] or row["cleanup_error"]:
            return "cleanup_unproven"
        if fenced:
            # Covers CLEANUP_FENCE_EPOCH, which is a lease expiry far in the future
            # precisely so that a fenced attempt is never treated as reclaimable.
            return "resource_lease_held"
        if allocated:
            return "runtime_allocation_held"
        if row["task_status"] not in GC_RECLAIMABLE_TASK_STATUSES:
            return "task_not_terminal"
        if age is None:
            return "age_unknown"
        if age < older_than_seconds:
            return "within_retention"
        return None

    def gc(
        self,
        *,
        dry_run: bool = False,
        older_than_seconds: int = DEFAULT_GC_RETENTION_SECONDS,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Reclaim the worktrees and task branches of attempts nothing is using.

        Integration branches are reported but never deleted: their commits are the
        published evidence for an approved task, and reclaiming disk is not a good
        enough reason to remove the record of what was merged.
        """

        moment = time.time() if now is None else now
        with self.connect() as connection:
            reclaimable, retained = self._gc_survey(connection, moment, older_than_seconds)
            integration_branches = [
                {"task_id": row["task_id"], "branch": row["branch"], "verdict": row["verdict"]}
                for row in connection.execute(
                    "SELECT task_id, branch, verdict FROM integrations ORDER BY created_at, id"
                )
            ]

        removed: list[str] = []
        if not dry_run and reclaimable:
            # No outer _git_operation_guard here: _git() takes it per invocation, and the
            # flock is not reentrant, so wrapping the loop deadlocks against the first
            # `git worktree remove`. The other _remove_worktree call sites are unguarded
            # for the same reason.
            for entry in reclaimable:
                self._remove_worktree(Path(entry["worktree"]), delete_branch=True)
                removed.append(entry["attempt_id"])
            with self.connect() as connection:
                for entry in reclaimable:
                    self._event(
                        connection,
                        "worktree.reclaimed",
                        "supervisor",
                        {
                            "attempt_id": entry["attempt_id"],
                            "task_id": entry["task_id"],
                            "branch": entry["branch"],
                            "bytes": entry["bytes"],
                        },
                    )

        return {
            "ok": True,
            "dry_run": dry_run,
            "older_than_seconds": older_than_seconds,
            "reclaimable": reclaimable,
            "removed": removed,
            "bytes": sum(entry["bytes"] for entry in reclaimable),
            "retained": retained,
            "integration_branches": integration_branches,
        }

    def reap_expired(self, now: int | None = None) -> dict[str, Any]:
        epoch = int(time.time()) if now is None else now
        orphaned: list[str] = []
        conflicted: list[str] = []
        cleanup_attempts: set[str] = set()
        workers_to_stop: list[tuple[str, int, str]] = []
        task_cleanups: dict[str, str] = {}
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempts = connection.execute(
                """
                SELECT * FROM attempts
                WHERE (status IN ('provisioning', 'working') AND lease_expires_at <= ?)
                   OR status = 'terminating'
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
                    UPDATE attempts SET status = 'terminating', latest_sha = ?,
                      updated_at = ? WHERE id = ?
                    """,
                    (latest, stamp, attempt["id"]),
                )
                if not attempt["termination_target_status"]:
                    connection.execute(
                        """
                        UPDATE tasks SET status = 'terminating', updated_at = ?
                        WHERE id = ? AND current_attempt_id = ?
                        """,
                        (stamp, attempt["task_id"], attempt["id"]),
                    )
                connection.execute(
                    """
                    UPDATE resource_leases SET lease_expires_at = ?, updated_at = ?
                    WHERE attempt_id = ?
                    """,
                    (CLEANUP_FENCE_EPOCH, stamp, attempt["id"]),
                )
                connection.execute(
                    "UPDATE runtime_allocations SET lease_expires_at = ?, updated_at = ? "
                    "WHERE attempt_id = ?",
                    (CLEANUP_FENCE_EPOCH, stamp, attempt["id"]),
                )
                cleanup_attempts.add(attempt["id"])
                if attempt["pid"] and attempt["pid"] > 0 and not attempt["termination_proof"]:
                    workers_to_stop.append((attempt["id"], attempt["pid"], attempt["pid_identity"]))
                if attempt["status"] != "terminating":
                    self._event(
                        connection,
                        "attempt.termination_started",
                        "reaper",
                        {"attempt_id": attempt["id"], "latest_sha": latest},
                    )
            expired = connection.execute(
                """
                SELECT DISTINCT task.id, task.status, task.cleanup_target_status,
                  task.current_attempt_id
                FROM tasks AS task
                JOIN resource_leases AS lease ON lease.task_id = task.id
                WHERE (
                    lease.attempt_id IS NULL
                    AND
                    (task.status IN ('qc_review', 'approved', 'integrating')
                     AND lease.lease_expires_at <= ?)
                  )
                  OR task.status = 'cleanup_pending'
                """,
                (epoch,),
            ).fetchall()
            for row in expired:
                submission = connection.execute(
                    """
                    SELECT attempt_id FROM submissions WHERE task_id = ?
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    (row["id"],),
                ).fetchone()
                cleanup_attempt_id = (
                    submission["attempt_id"] if submission else row["current_attempt_id"]
                )
                if cleanup_attempt_id:
                    task_cleanups[row["id"]] = cleanup_attempt_id
                    if row["status"] != "cleanup_pending":
                        self._fence_task_cleanup(
                            connection,
                            row["id"],
                            cleanup_attempt_id,
                            "conflicted",
                            "reaper",
                            "reservation_expired",
                        )
                        connection.execute(
                            "UPDATE submissions SET status = 'blocked', qc_resume_status = '' "
                            "WHERE task_id = ? AND status = 'qc_running'",
                            (row["id"],),
                        )
                        self._event(
                            connection,
                            "reservation.expired",
                            "reaper",
                            {"task_id": row["id"], "cleanup_fenced": True},
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
        workers = {attempt_id: (pid, identity) for attempt_id, pid, identity in workers_to_stop}
        runtime_cleanup: list[dict[str, Any]] = []
        completed_cleanup: set[str] = set()
        for attempt_id in sorted(cleanup_attempts):
            try:
                with self._runtime_restart_guard(attempt_id, recover=False) as guard_fd:
                    worker = workers.get(attempt_id)
                    if worker:
                        pid, identity = worker
                        termination = self._terminate_registered_group(pid, identity)
                        terminated_workers.append(
                            {
                                "attempt_id": attempt_id,
                                "pid": pid,
                                "termination": termination,
                            }
                        )
                        if termination == "failed":
                            raise SupervisorError(
                                "worker_containment_failed",
                                "worker subreaper did not terminate; cleanup fence remains held",
                            )
                        if not self._record_registered_worker_termination(
                            attempt_id,
                            pid,
                            identity,
                            termination,
                        ):
                            raise SupervisorError(
                                "worker_registration_lost",
                                "worker identity changed before termination proof was recorded",
                            )
                    self._prepare_terminated_attempt_cleanup(attempt_id)
                    runtime = self._runtime_down_locked(
                        attempt_id,
                        force=True,
                        _allow_active=False,
                        guard_fd=guard_fd,
                    )
                runtime_cleanup.append({"attempt_id": attempt_id, "state": runtime["state"]})
                if runtime["state"] == "released":
                    self._finalize_registered_worker_cleanup(attempt_id)
                    completed_cleanup.add(attempt_id)
            except (OSError, subprocess.SubprocessError, SupervisorError) as error:
                runtime_cleanup.append(
                    {"attempt_id": attempt_id, "state": "cleanup_error", "error": str(error)}
                )
                with self.connect() as connection:
                    connection.execute(
                        "UPDATE tasks SET cleanup_error = ?, updated_at = ? "
                        "WHERE current_attempt_id = ?",
                        (str(error), utc_now(), attempt_id),
                    )
        for task_id, attempt_id in sorted(task_cleanups.items()):
            try:
                with self._task_operation_guard(task_id, recover=True):
                    if attempt_id in cleanup_attempts:
                        # The attempt pass above owns process termination and
                        # the one teardown try for this reap. Reuse its durable
                        # state instead of executing non-idempotent hooks twice.
                        runtime = self.runtime_environment(attempt_id)
                        if runtime["state"] != "released":
                            continue
                    else:
                        with self._runtime_restart_guard(attempt_id, recover=False) as guard_fd:
                            self._prepare_terminated_attempt_cleanup(attempt_id)
                            runtime = self._runtime_down_locked(
                                attempt_id,
                                force=True,
                                _allow_active=False,
                                guard_fd=guard_fd,
                            )
                    if runtime["state"] != "released":
                        raise SupervisorError(
                            "runtime_cleanup_unproven",
                            "runtime cleanup did not reach released state",
                        )
                    self._finalize_registered_worker_cleanup(attempt_id)
                    with self.connect() as connection:
                        connection.execute("BEGIN IMMEDIATE")
                        target = self._complete_task_cleanup(
                            connection,
                            task_id,
                            attempt_id,
                            "reaper",
                        )
                    runtime_cleanup.append(
                        {"task_id": task_id, "attempt_id": attempt_id, "state": "released"}
                    )
                    if target == "conflicted":
                        conflicted.append(task_id)
            except (OSError, subprocess.SubprocessError, SupervisorError) as error:
                runtime_cleanup.append(
                    {
                        "task_id": task_id,
                        "attempt_id": attempt_id,
                        "state": "cleanup_error",
                        "error": str(error),
                    }
                )
                with self.connect() as connection:
                    connection.execute(
                        "UPDATE tasks SET cleanup_error = ?, updated_at = ? WHERE id = ? "
                        "AND status = 'cleanup_pending'",
                        (str(error), utc_now(), task_id),
                    )
        if completed_cleanup:
            with self.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                for attempt_id in sorted(completed_cleanup):
                    attempt = connection.execute(
                        "SELECT task_id, status, pid, termination_target_status, "
                        "termination_proof "
                        "FROM attempts WHERE id = ?",
                        (attempt_id,),
                    ).fetchone()
                    runtime = connection.execute(
                        "SELECT state FROM runtime_environments WHERE attempt_id = ?",
                        (attempt_id,),
                    ).fetchone()
                    if (
                        not attempt
                        or attempt["status"] != "terminating"
                        or attempt["termination_target_status"]
                        or (attempt["pid"] is not None and not attempt["termination_proof"])
                        or not runtime
                        or runtime["state"] != "released"
                    ):
                        continue
                    stamp = utc_now()
                    connection.execute(
                        "UPDATE attempts SET status = 'orphaned', pid = NULL, "
                        "pid_identity = '', termination_target_status = '', "
                        "termination_proof = '', launch_owner_pid = NULL, "
                        "launch_owner_identity = '', "
                        "updated_at = ? WHERE id = ?",
                        (stamp, attempt_id),
                    )
                    connection.execute(
                        "UPDATE tasks SET status = 'orphaned', current_attempt_id = NULL, "
                        "updated_at = ? WHERE id = ? AND current_attempt_id = ?",
                        (stamp, attempt["task_id"], attempt_id),
                    )
                    connection.execute(
                        "UPDATE resource_leases SET task_id = NULL, attempt_id = NULL, "
                        "lease_expires_at = 0, updated_at = ? WHERE attempt_id = ?",
                        (stamp, attempt_id),
                    )
                    orphaned.append(attempt["task_id"])
                    self._event(
                        connection,
                        "attempt.orphaned",
                        "reaper",
                        {"attempt_id": attempt_id, "cleanup_proved": True},
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
        self._assert_no_git_grafts()
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
            if self._git_text("cat-file", "-t", commit) != "commit":
                raise SupervisorError(
                    "invalid_submission_object", "submission HEAD is not a commit object"
                )
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
            if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", tree):
                raise SupervisorError(
                    "invalid_submission_object", "submission tree object id is invalid"
                )
            patch = self._git_bytes(
                "-C",
                str(worktree),
                "diff",
                "--binary",
                task["base_sha"],
                commit,
            )
            try:
                # This is the worker-completion authority boundary. Verify in
                # the same write transaction immediately before creating the
                # submission. On failure the quarantine mutations must survive
                # the rejected submit, so commit them before propagating the
                # error; nothing in this transaction has written before here.
                self._verify_attempt_trust_in(connection, attempt_id)
            except SupervisorError:
                connection.commit()
                raise
            submission_id = str(uuid.uuid4())
            stamp = utc_now()
            connection.execute(
                """
                INSERT INTO submissions
                  (id, task_id, attempt_id, worker_agent_id, commit_sha, tree_sha,
                   object_contract, patch_sha256, changed_paths_json, resource_tokens_json,
                   status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_qc', ?)
                """,
                (
                    submission_id,
                    task["id"],
                    attempt_id,
                    attempt["agent_id"],
                    commit,
                    tree,
                    SUBMISSION_OBJECT_CONTRACT,
                    sha256(patch),
                    canonical_json(changed),
                    canonical_json(tokens),
                    stamp,
                ),
            )
            connection.execute(
                """
                UPDATE attempts SET status = 'submitted', latest_sha = ?,
                  pid = NULL, pid_identity = '', termination_target_status = '',
                  termination_proof = '', launch_owner_pid = NULL,
                  launch_owner_identity = '',
                  updated_at = ? WHERE id = ?
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
        # Authenticate before looking up the task whose operation lock must be
        # taken; this keeps submission identifiers from becoming an oracle.
        self._authenticate(reviewer_id, "critic", credential)
        self._assert_no_git_grafts()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            pending_submission = self._submission_row(connection, submission_id)
            try:
                self._assert_submission_object_contract(pending_submission)
            except SupervisorError:
                self._invalidate_legacy_submission_in(connection, pending_submission, reviewer_id)
                connection.commit()
                raise
        with self._task_operation_guard(pending_submission["task_id"]) as operation_guard_fd:
            try:
                return self._run_qc_locked(
                    submission_id,
                    reviewer_id,
                    credential,
                    operation_guard_fd,
                )
            except Exception:
                # A normal exception unwinds only after every contained child
                # has ended, so the same process can safely restore the exact
                # sequential-review state it claimed. Process death cannot run
                # this block; the durable qc_running state then goes through
                # the reaper's fenced crash-recovery path.
                with self.connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    current = self._submission_row(connection, submission_id)
                    current_task = self._task_row(connection, current["task_id"])
                    if (
                        current["status"] == "qc_running"
                        and current["qc_resume_status"] in {"pending_qc", "pending_second_review"}
                        and current_task["status"] == "qc_review"
                    ):
                        connection.execute(
                            "UPDATE submissions SET status = qc_resume_status, "
                            "qc_resume_status = '' WHERE id = ?",
                            (submission_id,),
                        )
                raise

    def _run_qc_locked(
        self,
        submission_id: str,
        reviewer_id: str,
        credential: str | None,
        operation_guard_fd: int,
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
            self._assert_submission_object_contract(submission)
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
            operation_until = int(time.time()) + max(
                3600,
                self.config.timeout_seconds * (len(self.config.qc_commands) + 2) * 2,
            )
            connection.execute(
                "UPDATE submissions SET status = 'qc_running', qc_resume_status = ? WHERE id = ?",
                (submission["status"], submission_id),
            )
            connection.execute(
                "UPDATE resource_leases SET lease_expires_at = ?, updated_at = ? WHERE task_id = ?",
                (operation_until, utc_now(), task["id"]),
            )
            connection.execute(
                "UPDATE runtime_allocations SET lease_expires_at = ?, updated_at = ? "
                "WHERE attempt_id = ?",
                (operation_until, utc_now(), submission["attempt_id"]),
            )

        qc_dir = self.state_dir / "worktrees" / f"qc-{uuid.uuid4().hex}"
        packet_path = self.state_dir / "logs" / f"review-{submission_id}.json"
        results: list[dict[str, Any]] = []
        findings: list[dict[str, str]] = []
        critic_verdict = "pass"
        try:
            self._assert_safe_git_execution_config()
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
                    raise
                else:
                    runtime_env = self._runtime_env(submission["attempt_id"], require_ready=False)
            for command in self.config.qc_commands:
                self._restore_candidate(qc_dir, submission["commit_sha"])
                result = self._run_command(
                    command,
                    qc_dir,
                    self._phase_runtime_env(runtime_env, "qc", qc_dir),
                    pass_fds=(operation_guard_fd,),
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
                    pass_fds=(operation_guard_fd,),
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
                current["status"] != "qc_running"
                or current["qc_resume_status"] not in {"pending_qc", "pending_second_review"}
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
                "UPDATE submissions SET status = ?, qc_resume_status = '' WHERE id = ?",
                (submission_status, submission_id),
            )
            cleanup_required = not (verdict == "pass" and submission_status != "human_required")
            if not cleanup_required:
                connection.execute(
                    "UPDATE tasks SET status = ?, cleanup_target_status = '', "
                    "cleanup_error = '', updated_at = ? WHERE id = ?",
                    (task_status, finished, current_task["id"]),
                )
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
                self._fence_task_cleanup(
                    connection,
                    current_task["id"],
                    current["attempt_id"],
                    task_status,
                    reviewer_id,
                    "qc_completed_without_approval",
                )
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
        if cleanup_required:
            try:
                result["runtime_cleanup"] = self.runtime_down(submission["attempt_id"])
            except (OSError, subprocess.SubprocessError, SupervisorError) as cleanup_error:
                result["runtime_cleanup"] = {
                    "attempt_id": submission["attempt_id"],
                    "state": "cleanup_error",
                    "error": str(cleanup_error),
                }
                with self.connect() as connection:
                    connection.execute(
                        "UPDATE tasks SET cleanup_error = ?, updated_at = ? "
                        "WHERE id = ? AND status = 'cleanup_pending'",
                        (str(cleanup_error), utc_now(), task["id"]),
                    )
            if result["runtime_cleanup"]["state"] == "released":
                with self.connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    self._complete_task_cleanup(
                        connection,
                        task["id"],
                        submission["attempt_id"],
                        reviewer_id,
                    )
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
        self._authenticate(integrator_id, "integrator", credential)
        self._assert_no_git_grafts()
        with self._task_operation_guard(task_id) as operation_guard_fd:
            return self._integrate_locked(
                task_id,
                integrator_id,
                credential,
                operation_guard_fd,
            )

    def _integrate_locked(
        self,
        task_id: str,
        integrator_id: str,
        credential: str | None,
        operation_guard_fd: int,
    ) -> dict[str, Any]:
        integrator_identity = self._authenticate(integrator_id, "integrator", credential)
        integrator_digest = (
            integrator_identity["credential_digest"] if integrator_identity else None
        )
        integration_id = str(uuid.uuid4())
        branch = f"acp/integrate-{task_id[:8]}-{integration_id[:8]}"
        worktree = self.state_dir / "worktrees" / f"integrate-{integration_id}"
        created = utc_now()
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
                self._assert_submission_object_contract(submission)
            except SupervisorError:
                self._invalidate_legacy_submission_in(connection, submission, integrator_id)
                connection.commit()
                raise
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
            operation_until = int(time.time()) + max(
                3600,
                self.config.timeout_seconds * (len(self.config.integration_commands) + 2) * 2,
            )
            connection.execute(
                "UPDATE resource_leases SET lease_expires_at = ?, updated_at = ? WHERE task_id = ?",
                (operation_until, utc_now(), task_id),
            )
            connection.execute(
                "UPDATE runtime_allocations SET lease_expires_at = ?, updated_at = ? "
                "WHERE attempt_id = ?",
                (operation_until, utc_now(), submission["attempt_id"]),
            )
            connection.execute(
                """
                INSERT INTO integrations
                  (id, task_id, submission_id, branch, commit_sha, verdict,
                   results_json, error, created_at)
                VALUES (?, ?, ?, NULL, NULL, 'running', '[]', '', ?)
                """,
                (integration_id, task_id, submission["id"], created),
            )
            self._event(
                connection,
                "integration.started",
                integrator_id,
                {
                    "integration_id": integration_id,
                    "task_id": task_id,
                    "submission_id": submission["id"],
                },
            )

        results: list[dict[str, Any]] = []
        verdict = "failed"
        commit: str | None = None
        error_message = ""
        try:
            if (
                self._git_text("cat-file", "-t", submission["commit_sha"]) != "commit"
                or self._git_text("rev-parse", f"{submission['commit_sha']}^{{tree}}")
                != submission["tree_sha"]
            ):
                raise SupervisorError(
                    "submission_evidence_mismatch",
                    "replacement-free submission object no longer matches reviewed evidence",
                )
            current_base = self._git_text("rev-parse", task["base_branch"])
            with self._isolated_integration_git(worktree, current_base) as git_boundary:
                merge_results, integration_commit = self._run_integration_merge(
                    current_base,
                    submission["commit_sha"],
                    operation_guard_fd,
                    git_boundary,
                )
                results.extend(merge_results)
                results.append(
                    self._integration_merge_input_result(
                        current_base,
                        submission["commit_sha"],
                        git_boundary,
                    )
                )
                if integration_commit is None:
                    merge = merge_results[-1]
                    code = (
                        "merge_conflict"
                        if merge.get("phase") == "merge-tree" and merge["exit_code"] == 1
                        else "integration_merge_failed"
                    )
                    raise SupervisorError(
                        code,
                        merge["stderr"].strip()
                        or merge["stdout"].strip()
                        or "isolated merge failed",
                    )
                for command in self.config.integration_commands:
                    self._restore_integration_workspace(
                        worktree,
                        integration_commit,
                        operation_guard_fd,
                        git_boundary,
                    )
                    result = self._run_command(
                        command,
                        worktree,
                        self._phase_runtime_env(runtime_env, "integration", worktree),
                        pass_fds=(operation_guard_fd,),
                    )
                    results.append(result)
                    if result["exit_code"]:
                        raise SupervisorError(
                            "integration_gate_failed",
                            f"integration command failed: {command}",
                        )
                    if not self._integration_workspace_matches(
                        worktree,
                        integration_commit,
                        operation_guard_fd,
                        git_boundary,
                    ):
                        raise SupervisorError(
                            "integration_gate_mutated_source",
                            f"integration command mutated tracked source or Git controls: {command}",
                        )
                self._assert_integration_git_boundary(
                    worktree,
                    integration_commit,
                    git_boundary,
                )
            commit = integration_commit
            verdict = "ready_to_publish"
        except (OSError, subprocess.SubprocessError, SupervisorError) as error:
            error_message = str(error)
            verdict = (
                "conflict"
                if isinstance(error, SupervisorError) and error.code == "merge_conflict"
                else "failed"
            )
        recorded = True
        publication_pending = False
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
                publication_pending = verdict == "ready_to_publish"
                stored_verdict = "publish_pending" if publication_pending else verdict
                updated = connection.execute(
                    """
                    UPDATE integrations
                    SET branch = ?, commit_sha = ?, verdict = ?, results_json = ?, error = ?
                    WHERE id = ? AND verdict = 'running'
                    """,
                    (
                        branch if publication_pending else None,
                        commit,
                        stored_verdict,
                        canonical_json(results),
                        error_message,
                        integration_id,
                    ),
                ).rowcount
                if updated != 1:
                    raise SupervisorError(
                        "integration_record_state_changed",
                        "durable integration execution record changed before completion",
                    )
                if not publication_pending and current_task["status"] == "integrating":
                    self._fence_task_cleanup(
                        connection,
                        task_id,
                        submission["attempt_id"],
                        "conflicted",
                        integrator_id,
                        "integration_completed",
                    )
                self._event(
                    connection,
                    (
                        "integration.publish_pending"
                        if publication_pending
                        else "integration.completed"
                    ),
                    integrator_id,
                    {
                        "integration_id": integration_id,
                        "task_id": task_id,
                        "verdict": stored_verdict,
                        "commit_sha": commit,
                        "error": error_message,
                    },
                )
            if publication_pending:
                try:
                    assert commit is not None
                    self._publish_integration_ref(branch, commit, operation_guard_fd)
                except (OSError, subprocess.SubprocessError, SupervisorError) as publish_error:
                    verdict = "failed"
                    error_message = f"integration publication failed: {publish_error}"
                    with self.connect() as connection:
                        connection.execute("BEGIN IMMEDIATE")
                        pending = connection.execute(
                            "SELECT verdict FROM integrations WHERE id = ?", (integration_id,)
                        ).fetchone()
                        if pending and pending["verdict"] == "publish_pending":
                            connection.execute(
                                "UPDATE integrations SET verdict = 'delete_pending', "
                                "error = ? WHERE id = ? AND verdict = 'publish_pending'",
                                (error_message, integration_id),
                            )
                            current_task = self._task_row(connection, task_id)
                            if current_task["status"] == "integrating":
                                self._fence_task_cleanup(
                                    connection,
                                    task_id,
                                    submission["attempt_id"],
                                    "conflicted",
                                    integrator_id,
                                    "integration_publication_failed",
                                )
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
                    try:
                        self._finalize_integration_ref_deletion(
                            integration_id,
                            branch,
                            commit,
                            operation_guard_fd,
                        )
                    except (OSError, subprocess.SubprocessError, SupervisorError) as delete_error:
                        publication_pending = True
                        error_message = f"{error_message}; ref cleanup pending: {delete_error}"
                        with self.connect() as connection:
                            connection.execute(
                                "UPDATE integrations SET error = ? "
                                "WHERE id = ? AND verdict = 'delete_pending'",
                                (error_message, integration_id),
                            )
                    else:
                        publication_pending = False
                else:
                    with self.connect() as connection:
                        connection.execute("BEGIN IMMEDIATE")
                        pending = connection.execute(
                            "SELECT verdict FROM integrations WHERE id = ?", (integration_id,)
                        ).fetchone()
                        if not pending or pending["verdict"] != "publish_pending":
                            raise SupervisorError(
                                "integration_publication_state_changed",
                                "durable integration publication intent changed",
                            )
                        current_task = self._task_row(connection, task_id)
                        if current_task["status"] != "integrating":
                            raise SupervisorError(
                                "integration_publication_state_changed",
                                "task changed after integration publication intent",
                            )
                        connection.execute(
                            "UPDATE integrations SET verdict = 'pass', error = '' "
                            "WHERE id = ? AND verdict = 'publish_pending'",
                            (integration_id,),
                        )
                        self._fence_task_cleanup(
                            connection,
                            task_id,
                            submission["attempt_id"],
                            "done",
                            integrator_id,
                            "integration_published",
                        )
                        self._event(
                            connection,
                            "integration.completed",
                            integrator_id,
                            {
                                "integration_id": integration_id,
                                "task_id": task_id,
                                "verdict": "pass",
                                "commit_sha": commit,
                                "error": "",
                            },
                        )
                    verdict = "pass"
                    publication_pending = False
        finally:
            if worktree.is_symlink():
                worktree.unlink()
            elif worktree.exists():
                shutil.rmtree(worktree)
            if (not recorded or verdict != "pass") and not publication_pending:
                self._delete_integration_ref(branch, commit, operation_guard_fd)
        try:
            runtime_cleanup: dict[str, Any] = self.runtime_down(submission["attempt_id"])
        except (OSError, subprocess.SubprocessError, SupervisorError) as cleanup_error:
            runtime_cleanup = {
                "attempt_id": submission["attempt_id"],
                "state": "cleanup_error",
                "error": str(cleanup_error),
            }
            with self.connect() as connection:
                connection.execute(
                    "UPDATE tasks SET cleanup_error = ?, updated_at = ? "
                    "WHERE id = ? AND status = 'cleanup_pending'",
                    (str(cleanup_error), utc_now(), task_id),
                )
        if runtime_cleanup["state"] == "released":
            with self.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._complete_task_cleanup(
                    connection,
                    task_id,
                    submission["attempt_id"],
                    integrator_id,
                )
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

    @staticmethod
    def _integration_merge_input_result(
        base_sha: str,
        candidate_sha: str,
        boundary: IntegrationGitBoundary,
    ) -> dict[str, Any]:
        evidence = json.loads(canonical_json(boundary.merge_input_evidence))
        evidence.update({"base_sha": base_sha, "candidate_sha": candidate_sha})
        return {
            "command": "isolated merge input snapshot",
            "phase": "merge-input-evidence",
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "timed_out": False,
            "security_boundary": "synthetic-config+empty-exec-path+contained",
            "evidence": evidence,
        }

    def _publish_integration_ref(
        self, branch: str, commit_sha: str, operation_guard_fd: int
    ) -> None:
        """Create the public ref after its durable publication intent exists."""

        reference = f"refs/heads/{branch}"
        result = self._run_ref_git_contained(
            ["update-ref", reference, commit_sha, "0" * len(commit_sha)],
            f"git update-ref {reference}",
            operation_guard_fd,
        )
        if result["exit_code"] == 0:
            return
        verify = self._run_ref_git_contained(
            ["rev-parse", "--verify", reference],
            f"git rev-parse --verify {reference}",
            operation_guard_fd,
        )
        if verify["exit_code"] == 0 and verify["stdout"].strip() == commit_sha:
            return
        raise SupervisorError(
            "integration_publication_failed",
            result["stderr"].strip() or "integration ref could not be created",
        )

    def _delete_integration_ref(
        self, branch: str, commit_sha: str | None, operation_guard_fd: int
    ) -> None:
        reference = f"refs/heads/{branch}"
        arguments = ["update-ref", "-d", reference]
        if commit_sha:
            arguments.append(commit_sha)
        self._run_ref_git_contained(
            arguments,
            f"git update-ref -d {reference}",
            operation_guard_fd,
        )
        verify = self._run_ref_git_contained(
            ["show-ref", "--verify", "--quiet", reference],
            f"git show-ref --verify --quiet {reference}",
            operation_guard_fd,
        )
        if verify["exit_code"] == 0:
            raise SupervisorError(
                "integration_ref_deletion_failed",
                f"integration ref still exists after deletion: {reference}",
            )
        if verify["exit_code"] != 1:
            raise SupervisorError(
                "integration_ref_deletion_unverified",
                verify["stderr"].strip()
                or f"integration ref absence could not be verified: {reference}",
            )

    def _finalize_integration_ref_deletion(
        self,
        integration_id: str,
        branch: str,
        commit_sha: str,
        operation_guard_fd: int,
    ) -> None:
        self._delete_integration_ref(branch, commit_sha, operation_guard_fd)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE integrations SET branch = NULL, verdict = 'failed' "
                "WHERE id = ? AND verdict = 'delete_pending'",
                (integration_id,),
            )

    def _run_ref_git_contained(
        self, arguments: Sequence[str], label: str, operation_guard_fd: int
    ) -> dict[str, Any]:
        git = str(self._system_git_executable(self.root))
        argv = [
            *self._supervisor_git_prefix(git, self._disabled_git_hooks_dir()),
            "-C",
            str(self.root),
            *arguments,
        ]
        with self._git_operation_guard() as git_guard_fd:
            return self._run_process(
                argv,
                label,
                self.root,
                self._supervisor_git_env(),
                lifecycle_fds=(operation_guard_fd, git_guard_fd),
            )

    def _reconcile_pending_integrations(self) -> None:
        """Finish durable publications and remove residue for every recorded integration."""

        with self.connect() as connection:
            pending_rows = connection.execute(
                """
                SELECT integration.id, integration.task_id, integration.branch,
                  integration.commit_sha, integration.verdict, submission.attempt_id
                FROM integrations AS integration
                JOIN submissions AS submission ON submission.id = integration.submission_id
                ORDER BY integration.created_at, integration.id
                """
            ).fetchall()
        for pending in pending_rows:
            try:
                with self._task_operation_guard(
                    pending["task_id"], recover=True
                ) as operation_guard_fd:
                    self._reconcile_pending_integration_locked(pending, operation_guard_fd)
            except SupervisorError as error:
                if error.code != "task_operation_executor_alive":
                    raise

    def _reconcile_pending_integration_locked(
        self, pending: sqlite3.Row, operation_guard_fd: int
    ) -> None:
        try:
            if pending["verdict"] == "publish_pending":
                self._reconcile_pending_integration_state(pending, operation_guard_fd)
            elif pending["verdict"] == "running":
                self._reconcile_interrupted_integration_state(pending)
            elif pending["verdict"] == "delete_pending":
                self._reconcile_pending_ref_deletion(pending, operation_guard_fd)
        finally:
            self._remove_integration_residue(pending["id"])

    def _reconcile_interrupted_integration_state(self, pending: sqlite3.Row) -> None:
        error_message = "integration process stopped before recording a terminal result"
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT verdict FROM integrations WHERE id = ?", (pending["id"],)
            ).fetchone()
            if not row or row["verdict"] != "running":
                return
            task = self._task_row(connection, pending["task_id"])
            recovered_verdict = "failed" if task["status"] == "integrating" else "stale"
            connection.execute(
                "UPDATE integrations SET verdict = ?, error = ? "
                "WHERE id = ? AND verdict = 'running'",
                (recovered_verdict, error_message, pending["id"]),
            )
            if task["status"] == "integrating":
                self._fence_task_cleanup(
                    connection,
                    pending["task_id"],
                    pending["attempt_id"],
                    "conflicted",
                    "recovery",
                    "integration_execution_interrupted",
                )
            self._event(
                connection,
                "integration.execution_recovered",
                "recovery",
                {
                    "integration_id": pending["id"],
                    "task_id": pending["task_id"],
                    "verdict": recovered_verdict,
                    "error": error_message,
                },
            )

    def _reconcile_pending_ref_deletion(
        self, pending: sqlite3.Row, operation_guard_fd: int
    ) -> None:
        branch = pending["branch"]
        commit_sha = pending["commit_sha"]
        if not branch or not commit_sha:
            raise SupervisorError(
                "integration_ref_cleanup_invalid",
                "durable integration ref cleanup intent is incomplete",
            )
        self._finalize_integration_ref_deletion(
            pending["id"], branch, commit_sha, operation_guard_fd
        )

    def _reconcile_pending_integration_state(
        self, pending: sqlite3.Row, operation_guard_fd: int
    ) -> None:
        branch = pending["branch"]
        commit_sha = pending["commit_sha"]
        if not branch or not commit_sha:
            raise SupervisorError(
                "integration_publication_invalid",
                "durable integration publication intent is incomplete",
            )
        try:
            self._publish_integration_ref(branch, commit_sha, operation_guard_fd)
        except (OSError, subprocess.SubprocessError, SupervisorError) as error:
            error_message = f"restart publication failed: {error}"
            with self.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT verdict FROM integrations WHERE id = ?", (pending["id"],)
                ).fetchone()
                if not row or row["verdict"] != "publish_pending":
                    return
                connection.execute(
                    "UPDATE integrations SET verdict = 'delete_pending', error = ? "
                    "WHERE id = ? AND verdict = 'publish_pending'",
                    (error_message, pending["id"]),
                )
                task = self._task_row(connection, pending["task_id"])
                if task["status"] == "integrating":
                    self._fence_task_cleanup(
                        connection,
                        pending["task_id"],
                        pending["attempt_id"],
                        "conflicted",
                        "recovery",
                        "integration_publication_failed",
                    )
                self._event(
                    connection,
                    "integration.publication_recovered",
                    "recovery",
                    {
                        "integration_id": pending["id"],
                        "task_id": pending["task_id"],
                        "verdict": "failed",
                        "error": error_message,
                    },
                )
            self._finalize_integration_ref_deletion(
                pending["id"], branch, commit_sha, operation_guard_fd
            )
            return
        delete_ref = False
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT verdict FROM integrations WHERE id = ?", (pending["id"],)
            ).fetchone()
            if not row or row["verdict"] != "publish_pending":
                return
            task = self._task_row(connection, pending["task_id"])
            if task["status"] == "integrating":
                connection.execute(
                    "UPDATE integrations SET verdict = 'pass', error = '' "
                    "WHERE id = ? AND verdict = 'publish_pending'",
                    (pending["id"],),
                )
                self._fence_task_cleanup(
                    connection,
                    pending["task_id"],
                    pending["attempt_id"],
                    "done",
                    "recovery",
                    "integration_publication_recovered",
                )
                recovered_verdict = "pass"
            elif task["status"] == "cleanup_pending" and task["cleanup_target_status"] == "done":
                connection.execute(
                    "UPDATE integrations SET verdict = 'pass', error = '' "
                    "WHERE id = ? AND verdict = 'publish_pending'",
                    (pending["id"],),
                )
                recovered_verdict = "pass"
            else:
                error_message = "task changed before publication recovery"
                connection.execute(
                    "UPDATE integrations SET verdict = 'delete_pending', error = ? "
                    "WHERE id = ? AND verdict = 'publish_pending'",
                    (error_message, pending["id"]),
                )
                recovered_verdict = "failed"
                delete_ref = True
            self._event(
                connection,
                "integration.publication_recovered",
                "recovery",
                {
                    "integration_id": pending["id"],
                    "task_id": pending["task_id"],
                    "verdict": recovered_verdict,
                },
            )
        if delete_ref:
            self._finalize_integration_ref_deletion(
                pending["id"], branch, commit_sha, operation_guard_fd
            )

    def _remove_integration_residue(self, integration_id: str) -> None:
        for path in (
            self.state_dir / "worktrees" / f"integrate-{integration_id}",
            self.state_dir / "integration-git" / f"integrate-{integration_id}",
        ):
            if path.is_symlink():
                path.unlink()
            elif path.exists():
                shutil.rmtree(path)

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
        if not sys.platform.startswith("linux"):
            raise SupervisorError(
                "process_containment_unavailable",
                "long-running workers require Linux child-subreaper containment",
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
                        "-1",
                        "-1",
                        MONITOR_MODE,
                        LIFECYCLE_FDS_PREFIX,
                        *command,
                    ],
                    cwd=attempt["worktree"],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                    pass_fds=(handshake_read,),
                    env=worker_env,
                )
                process_identity = self._process_identity(process.pid)
                if process_identity is None:
                    raise SupervisorError(
                        "worker_identity_unavailable",
                        "worker kernel identity could not be recorded",
                    )
                os.close(handshake_read)
                handshake_read = -1
                launch_fenced = False
                with self.connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    registered = connection.execute(
                        "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
                    ).fetchone()
                    if not registered:
                        raise SupervisorError(
                            "attempt_not_found", f"attempt {attempt_id} not found"
                        )
                    self._authenticate_attempt(connection, registered, credential)
                    if registered["claim_token"] != claim_token:
                        raise SupervisorError("stale_fencing_token", "claim token is stale")
                    if registered["status"] != "working" and registered["pid"] == -1:
                        target_status = (
                            registered["termination_target_status"] or registered["status"]
                        )
                        changed = connection.execute(
                            "UPDATE attempts SET status = 'terminating', "
                            "termination_target_status = ?, pid = ?, pid_identity = ?, "
                            "launch_owner_pid = NULL, launch_owner_identity = '', "
                            "log_path = ?, updated_at = ? WHERE id = ? AND status = ? AND pid = -1",
                            (
                                target_status,
                                process.pid,
                                process_identity,
                                str(log_path),
                                utc_now(),
                                attempt_id,
                                registered["status"],
                            ),
                        ).rowcount
                        if changed != 1:
                            raise SupervisorError(
                                "worker_registration_lost",
                                "terminated worker launch reservation changed",
                            )
                        launch_fenced = True
                        self._event(
                            connection,
                            "worker.launch_fenced",
                            registered["agent_id"],
                            {"attempt_id": attempt_id, "pid": process.pid},
                        )
                    else:
                        active = self._active_attempt(
                            connection, attempt_id, claim_token, int(time.time())
                        )
                        changed = connection.execute(
                            """
                            UPDATE attempts SET pid = ?, pid_identity = ?, log_path = ?,
                              launch_owner_pid = NULL, launch_owner_identity = '', updated_at = ?
                            WHERE id = ? AND status = 'working' AND pid = -1
                            """,
                            (
                                process.pid,
                                process_identity,
                                str(log_path),
                                utc_now(),
                                attempt_id,
                            ),
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
                if launch_fenced:
                    raise SupervisorError(
                        "worker_launch_fenced",
                        "trust quarantine fenced the worker before launch authorization",
                    )
                # Revalidate after the kernel identity is durable but before the
                # handshake authorizes candidate code. If the pin disappeared,
                # quarantine retains this PID until the monitor is reaped.
                self._verify_attempt_trust(attempt_id)
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
                if process is not None:
                    self._stop_kernel_monitor(process)
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
        launch_owner_pid = os.getpid()
        launch_owner_identity = self._process_identity(launch_owner_pid)
        if not launch_owner_identity:
            raise SupervisorError(
                "worker_identity_unavailable",
                "worker launcher kernel identity could not be recorded",
            )
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
                UPDATE attempts SET pid = -1, pid_identity = '', termination_proof = '',
                  launch_owner_pid = ?, launch_owner_identity = ?, log_path = ?, updated_at = ?
                WHERE id = ? AND pid IS NULL
                """,
                (
                    launch_owner_pid,
                    launch_owner_identity,
                    log_path,
                    utc_now(),
                    attempt_id,
                ),
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
            terminating = attempt["status"] == "terminating"
            if terminating:
                # The monitor is gone, but the runtime is not yet proven down.
                # Retain the exact registration until that second proof is
                # durable, so a failed cleanup remains safely retryable.
                connection.execute(
                    "UPDATE attempts SET termination_proof = ?, "
                    "launch_owner_pid = NULL, launch_owner_identity = '', "
                    "updated_at = ? WHERE id = ?",
                    (event_type, utc_now(), attempt_id),
                )
            else:
                connection.execute(
                    "UPDATE attempts SET pid = NULL, pid_identity = '', "
                    "termination_target_status = '', termination_proof = '', "
                    "launch_owner_pid = NULL, launch_owner_identity = '', "
                    "updated_at = ? WHERE id = ?",
                    (utc_now(), attempt_id),
                )
            self._event(
                connection,
                event_type,
                attempt["agent_id"],
                {
                    "attempt_id": attempt_id,
                    "exit_code": exit_code,
                    "termination_target_status": attempt["termination_target_status"],
                    "termination_proved": terminating,
                },
            )

    def _record_registered_worker_termination(
        self,
        attempt_id: str,
        expected_pid: int,
        expected_identity: str,
        proof: str,
    ) -> bool:
        """Durably record process death without releasing its cleanup identity."""

        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
            if (
                not attempt
                or attempt["status"] != "terminating"
                or attempt["pid"] != expected_pid
                or attempt["pid_identity"] != expected_identity
            ):
                return False
            stamp = utc_now()
            connection.execute(
                "UPDATE attempts SET termination_proof = ?, launch_owner_pid = NULL, "
                "launch_owner_identity = '', updated_at = ? WHERE id = ? "
                "AND status = 'terminating' AND pid = ? AND pid_identity = ?",
                (proof, stamp, attempt_id, expected_pid, expected_identity),
            )
            self._event(
                connection,
                "worker.termination_proved",
                "reaper",
                {
                    "attempt_id": attempt_id,
                    "pid": expected_pid,
                    "proof": proof,
                    "target_status": attempt["termination_target_status"],
                },
            )
            return True

    def _prepare_terminated_attempt_cleanup(self, attempt_id: str) -> None:
        """Require process-death proof before runtime teardown may start."""

        with self.connect() as connection:
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
        if not attempt or attempt["status"] != "terminating" or attempt["pid"] is None:
            return
        if attempt["termination_proof"]:
            return
        if attempt["pid"] == -1:
            owner_pid = attempt["launch_owner_pid"]
            owner_identity = attempt["launch_owner_identity"]
            if not owner_pid or not owner_identity:
                raise SupervisorError(
                    "worker_launch_identity_unavailable",
                    "launch reservation has no verifiable owner; cleanup fence remains held",
                )
            if self._process_identity(owner_pid) == owner_identity:
                raise SupervisorError(
                    "worker_launch_unresolved",
                    "launch owner is still active; cleanup fence remains held",
                )
            if not self._record_registered_worker_termination(
                attempt_id,
                -1,
                "",
                "launch-owner-gone",
            ):
                raise SupervisorError(
                    "worker_registration_lost",
                    "launch reservation changed before owner-death proof was recorded",
                )
            return
        if attempt["pid"] > 0:
            raise SupervisorError(
                "worker_termination_unproven",
                "registered worker death is unproven; cleanup fence remains held",
            )
        raise SupervisorError(
            "worker_registration_invalid",
            "worker registration is invalid; cleanup fence remains held",
        )

    def _finalize_registered_worker_cleanup(self, attempt_id: str) -> str | None:
        """Clear worker identity only after runtime release is also durable."""

        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
            if (
                not attempt
                or attempt["status"] != "terminating"
                or not attempt["termination_target_status"]
            ):
                return None
            runtime = connection.execute(
                "SELECT state FROM runtime_environments WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if not attempt["termination_proof"] or not runtime or runtime["state"] != "released":
                raise SupervisorError(
                    "worker_cleanup_unproven",
                    "worker identity and runtime cleanup are not both proven",
                )
            target = attempt["termination_target_status"]
            stamp = utc_now()
            changed = connection.execute(
                "UPDATE attempts SET status = ?, pid = NULL, pid_identity = '', "
                "termination_target_status = '', termination_proof = '', "
                "launch_owner_pid = NULL, launch_owner_identity = '', updated_at = ? "
                "WHERE id = ? AND status = 'terminating' AND pid IS ? "
                "AND pid_identity = ? AND termination_proof = ?",
                (
                    target,
                    stamp,
                    attempt_id,
                    attempt["pid"],
                    attempt["pid_identity"],
                    attempt["termination_proof"],
                ),
            ).rowcount
            if changed != 1:
                raise SupervisorError(
                    "worker_registration_lost",
                    "worker cleanup identity changed before finalization",
                )
            self._event(
                connection,
                "worker.cleanup_proved",
                "reaper",
                {
                    "attempt_id": attempt_id,
                    "pid": attempt["pid"],
                    "termination_proof": attempt["termination_proof"],
                    "target_status": target,
                },
            )
            return target

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
        pidfd = self._open_registered_pidfd(attempt["pid"], attempt["pid_identity"])
        if pidfd is None:
            raise SupervisorError(
                "worker_identity_mismatch",
                "registered worker PID was reused; refusing to signal it",
            )
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        except ProcessLookupError as error:
            raise SupervisorError(
                "worker_not_running", "worker process no longer exists"
            ) from error
        finally:
            os.close(pidfd)
        return {"attempt_id": attempt_id, "pid": attempt["pid"], "signal": "SIGTERM"}

    @staticmethod
    def _terminate_registered_group(pid: int, identity: str) -> str:
        if not identity:
            # A PID without its kernel birth identity may now name an unrelated
            # process. It is neither safe to signal nor safe to call gone.
            return "failed"
        try:
            pidfd = GitSupervisor._open_registered_pidfd(pid, identity)
        except SupervisorError as error:
            if error.code == "worker_identity_unreadable":
                return "failed"
            raise
        if pidfd is None:
            return "identity-gone"
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        except PermissionError:
            os.close(pidfd)
            return "failed"
        except ProcessLookupError:
            os.close(pidfd)
            return "identity-gone"
        try:
            poller = select.poll()
            poller.register(pidfd, select.POLLIN)
            if poller.poll(2000):
                return "terminated"
            # Never SIGKILL the subreaper: doing so would orphan exactly the tree
            # it exists to contain. The cleanup fence remains held instead.
            return "failed"
        finally:
            os.close(pidfd)

    @staticmethod
    def _open_registered_pidfd(pid: int, identity: str) -> int | None:
        """Open an identity-bound signal handle, then revalidate its process."""

        if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
            raise SupervisorError(
                "worker_pidfd_unavailable",
                "identity-safe worker signalling requires Linux pidfd support",
            )
        try:
            pidfd = os.pidfd_open(pid, 0)
        except ProcessLookupError:
            return None
        current_identity = GitSupervisor._process_identity(pid)
        if current_identity is None:
            os.close(pidfd)
            raise SupervisorError(
                "worker_identity_unreadable",
                "registered worker kernel identity could not be revalidated",
            )
        if current_identity != identity:
            os.close(pidfd)
            return None
        return pidfd

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
        opened_at = self.schema_version_on_open
        checks.append(
            {
                "name": "schema",
                # A database newer than this binary never reaches doctor: the open
                # refuses. A database older is upgraded by the same open. So by the time
                # this runs the two agree, and the useful fact is what it was beforehand.
                "ok": True,
                "detail": (
                    f"version {SCHEMA_VERSION}, binary {SCHEMA_VERSION} (acp {__version__}); "
                    + (
                        "stamped on this open — it predated schema versioning"
                        if opened_at is None
                        else f"was {opened_at} when opened"
                    )
                ),
            }
        )
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
            "cleanup_target_status": row["cleanup_target_status"],
            "cleanup_error": row["cleanup_error"],
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
            "pid_identity": row["pid_identity"],
            "termination_target_status": row["termination_target_status"],
            "termination_proof": row["termination_proof"],
            "launch_owner_pid": row["launch_owner_pid"],
            "launch_owner_identity": row["launch_owner_identity"],
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
            "recovery_action": row["recovery_action"],
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
            "object_contract": row["object_contract"],
            "patch_sha256": row["patch_sha256"],
            "changed_paths": json.loads(row["changed_paths_json"]),
            "resource_tokens": json.loads(row["resource_tokens_json"]),
            "status": row["status"],
            "qc_resume_status": row["qc_resume_status"],
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

    def _fence_task_cleanup(
        self,
        connection: sqlite3.Connection,
        task_id: str,
        attempt_id: str,
        target_status: str,
        actor: str,
        reason: str,
    ) -> None:
        """Persist a collision fence before any runtime cleanup side effect."""

        stamp = utc_now()
        connection.execute(
            "UPDATE tasks SET status = 'cleanup_pending', cleanup_target_status = ?, "
            "cleanup_error = '', updated_at = ? WHERE id = ?",
            (target_status, stamp, task_id),
        )
        connection.execute(
            "UPDATE resource_leases SET lease_expires_at = ?, updated_at = ? WHERE task_id = ?",
            (CLEANUP_FENCE_EPOCH, stamp, task_id),
        )
        connection.execute(
            "UPDATE runtime_allocations SET lease_expires_at = ?, updated_at = ? "
            "WHERE attempt_id = ?",
            (CLEANUP_FENCE_EPOCH, stamp, attempt_id),
        )
        self._event(
            connection,
            "task.cleanup_started",
            actor,
            {
                "task_id": task_id,
                "attempt_id": attempt_id,
                "target_status": target_status,
                "reason": reason,
            },
        )

    def _complete_task_cleanup(
        self,
        connection: sqlite3.Connection,
        task_id: str,
        attempt_id: str,
        actor: str,
    ) -> str | None:
        """Release reservations only after durable runtime-release proof."""

        task = connection.execute(
            "SELECT status, cleanup_target_status FROM tasks WHERE id = ?",
            (task_id,),
        ).fetchone()
        runtime = connection.execute(
            "SELECT state FROM runtime_environments WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone()
        attempt = connection.execute(
            "SELECT pid, termination_target_status FROM attempts WHERE id = ?",
            (attempt_id,),
        ).fetchone()
        if (
            not task
            or task["status"] != "cleanup_pending"
            or not task["cleanup_target_status"]
            or not runtime
            or runtime["state"] != "released"
            or not attempt
            or attempt["pid"] is not None
            or attempt["termination_target_status"]
        ):
            return None
        target = task["cleanup_target_status"]
        stamp = utc_now()
        connection.execute(
            "UPDATE tasks SET status = ?, cleanup_target_status = '', cleanup_error = '', "
            "updated_at = ? "
            "WHERE id = ? AND status = 'cleanup_pending'",
            (target, stamp, task_id),
        )
        self._release_task_leases(connection, task_id, stamp)
        self._event(
            connection,
            "task.cleanup_completed",
            actor,
            {"task_id": task_id, "attempt_id": attempt_id, "target_status": target},
        )
        return target

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
        self._assert_no_git_grafts()
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

    def _run_integration_merge(
        self,
        base_sha: str,
        commit_sha: str,
        operation_guard_fd: int,
        boundary: IntegrationGitBoundary,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Create one real merge commit through candidate-inert Git plumbing.

        The synthetic GIT_DIR has no repository/user/system configuration, no
        hooks and an empty Git exec path. `merge-tree` and `commit-tree` are
        built-ins, so Darwin can enforce the same no-fork kernel policy used by
        every other bounded command instead of exempting porcelain `git merge`.
        """

        self._assert_integration_git_boundary(None, None, boundary)
        ancestry = self._run_isolated_git(
            boundary,
            ["merge-base", "--is-ancestor", commit_sha, base_sha],
            f"git merge-base --is-ancestor {commit_sha} {base_sha}",
            operation_guard_fd,
        )
        ancestry["phase"] = "ancestry-check"
        results = [ancestry]
        if ancestry["exit_code"] == 0:
            head = boundary.git_dir / "HEAD"
            head.write_text(base_sha + "\n", encoding="ascii")
            head.chmod(0o600)
            self._assert_integration_git_boundary(None, base_sha, boundary)
            return results, base_sha
        if ancestry["exit_code"] != 1:
            return results, None
        merge = self._run_isolated_git(
            boundary,
            ["merge-tree", "--write-tree", "--no-messages", base_sha, commit_sha],
            f"git merge-tree {base_sha} {commit_sha}",
            operation_guard_fd,
        )
        merge["phase"] = "merge-tree"
        results.append(merge)
        if merge["exit_code"]:
            return results, None
        tree_sha = merge["stdout"].strip()
        if not re.fullmatch(rf"[0-9a-f]{{{boundary.oid_length}}}", tree_sha):
            raise SupervisorError(
                "integration_merge_invalid_output",
                "isolated merge-tree did not return exactly one tree object id",
            )
        commit = self._run_isolated_git(
            boundary,
            [
                "-c",
                "user.name=Agent Control Plane",
                "-c",
                "user.email=acp@localhost.invalid",
                "commit-tree",
                tree_sha,
                "-p",
                base_sha,
                "-p",
                commit_sha,
                "-m",
                f"ACP integration merge of {commit_sha[:12]}",
                "--no-gpg-sign",
            ],
            f"git commit-tree {tree_sha}",
            operation_guard_fd,
        )
        commit["phase"] = "commit-tree"
        results.append(commit)
        if commit["exit_code"]:
            return results, None
        integration_commit = commit["stdout"].strip()
        if not re.fullmatch(rf"[0-9a-f]{{{boundary.oid_length}}}", integration_commit):
            raise SupervisorError(
                "integration_commit_invalid_output",
                "isolated commit-tree did not return exactly one commit object id",
            )
        verify = self._run_isolated_git(
            boundary,
            ["cat-file", "-p", integration_commit],
            f"git cat-file -p {integration_commit}",
            operation_guard_fd,
        )
        verify["phase"] = "verify-commit"
        results.append(verify)
        if verify["exit_code"]:
            return results, None
        headers = verify["stdout"].split("\n\n", 1)[0].splitlines()
        tree_headers = [line.removeprefix("tree ") for line in headers if line.startswith("tree ")]
        parents = [line.removeprefix("parent ") for line in headers if line.startswith("parent ")]
        if tree_headers != [tree_sha] or parents != [base_sha, commit_sha]:
            raise SupervisorError(
                "integration_commit_invalid",
                "isolated merge commit tree or parents do not match the requested merge",
            )
        head = boundary.git_dir / "HEAD"
        head.write_text(integration_commit + "\n", encoding="ascii")
        head.chmod(0o600)
        self._assert_integration_git_boundary(None, integration_commit, boundary)
        return results, integration_commit

    @contextmanager
    def _isolated_integration_git(
        self, worktree: Path, base_sha: str
    ) -> Iterator[IntegrationGitBoundary]:
        """Build a minimal Git control directory that cannot load repo config."""

        git_source = self._system_git_executable(self.root)
        common_value = self._git_text("rev-parse", "--path-format=absolute", "--git-common-dir")
        common_dir = Path(common_value)
        if not common_dir.is_absolute():
            common_dir = (self.root / common_dir).resolve()
        try:
            object_dir = (common_dir / "objects").resolve(strict=True)
        except FileNotFoundError as error:
            raise SupervisorError(
                "git_object_store_missing", "repository object store is missing"
            ) from error
        object_format = self._git_text("rev-parse", "--show-object-format")
        if object_format not in {"sha1", "sha256"}:
            raise SupervisorError(
                "git_object_format_unsupported",
                f"unsupported Git object format: {object_format}",
            )
        merge_config = self._integration_merge_config()
        git_version = self._git_text("--version")
        global_snapshot = self._read_core_attributes_file(base_sha)
        info_snapshot = self._read_integration_info_attributes(common_dir)
        global_attributes = global_snapshot.content
        info_attributes = info_snapshot.content
        for path in (object_dir, worktree):
            if "\n" in str(path) or "\r" in str(path):
                raise SupervisorError(
                    "unsafe_git_path", "integration Git paths cannot contain newlines"
                )
        boundary_root = self.state_dir / "integration-git"
        boundary_root.mkdir(mode=0o700, exist_ok=True)
        boundary_root.chmod(0o700)
        git_dir = boundary_root / worktree.name
        try:
            git_dir.mkdir(mode=0o700)
        except FileExistsError as error:
            raise SupervisorError(
                "integration_git_boundary_exists",
                "stale integration Git boundary must be reconciled before reuse",
            ) from error
        try:
            git_dir.chmod(0o700)
            source_digest = sha256(git_source.read_bytes())
            git = git_dir / "supervisor-git"
            shutil.copyfile(git_source, git)
            git.chmod(0o500)
            if (
                sha256(git.read_bytes()) != source_digest
                or sha256(git_source.read_bytes()) != source_digest
            ):
                raise SupervisorError(
                    "git_executable_changed",
                    "the system Git executable changed while its private snapshot was created",
                )
            for directory in (
                git_dir / "objects" / "info",
                git_dir / "objects" / "pack",
                git_dir / "info",
                git_dir / "refs" / "heads",
                git_dir / "hooks",
                git_dir / "empty-exec",
            ):
                directory.mkdir(parents=True, exist_ok=True)
                directory.chmod(0o700)
            repository_version = 1 if object_format == "sha256" else 0
            extensions = (
                f"[extensions]\n\tobjectFormat = {object_format}\n"
                if object_format != "sha1"
                else ""
            )
            config_text = (
                "[core]\n"
                f"\trepositoryFormatVersion = {repository_version}\n"
                "\tbare = false\n"
                f"\tworktree = {json.dumps(str(worktree))}\n"
                f"\thooksPath = {json.dumps(str(git_dir / 'hooks'))}\n"
                "\tfsmonitor = false\n"
                f"\tattributesFile = {json.dumps(str(git_dir / 'info' / 'global-attributes') if global_attributes is not None else os.devnull)}\n"
                "[commit]\n"
                "\tgpgSign = false\n"
                "[merge]\n"
                "\tverifySignatures = false\n"
                "[maintenance]\n"
                "\tauto = false\n"
                "[gc]\n"
                "\tauto = 0\n"
                f"{extensions}"
                f"{merge_config}"
            )
            config = git_dir / "config"
            config.write_text(config_text, encoding="utf-8")
            config.chmod(0o600)
            head = git_dir / "HEAD"
            head.write_text("ref: refs/heads/acp-isolated\n", encoding="ascii")
            head.chmod(0o600)
            alternates_text = str(object_dir) + "\n"
            alternates = git_dir / "objects" / "info" / "alternates"
            alternates.write_text(alternates_text, encoding="utf-8")
            alternates.chmod(0o600)
            if info_attributes is not None:
                attributes = git_dir / "info" / "attributes"
                attributes.write_bytes(info_attributes)
                attributes.chmod(0o600)
            if global_attributes is not None:
                attributes = git_dir / "info" / "global-attributes"
                attributes.write_bytes(global_attributes)
                attributes.chmod(0o600)
            env = self._supervisor_git_env()
            env.update(
                {
                    "HOME": str(git_dir),
                    "GIT_ATTR_NOSYSTEM": "1",
                    "GIT_CONFIG_COUNT": "0",
                    "GIT_DIR": str(git_dir),
                    "GIT_EXEC_PATH": str(git_dir / "empty-exec"),
                    "GIT_INDEX_FILE": str(git_dir / "index"),
                    "GIT_OBJECT_DIRECTORY": str(object_dir),
                    "GIT_PAGER": "",
                    "GIT_WORK_TREE": str(worktree),
                    "PAGER": "",
                }
            )
            boundary = IntegrationGitBoundary(
                git=str(git),
                git_dir=git_dir,
                object_dir=object_dir,
                env=env,
                git_digest=source_digest,
                git_size=git.stat().st_size,
                config_digest=sha256(config_text.encode()),
                alternates_text=alternates_text,
                global_attributes=global_attributes,
                info_attributes=info_attributes,
                merge_input_evidence={
                    "contract": "isolated-merge-input-v1",
                    "git": {
                        "sha256": source_digest,
                        "size": git.stat().st_size,
                        "version": git_version,
                    },
                    "object_format": object_format,
                    "semantic_config": merge_config,
                    "core_attributes": dict(global_snapshot.evidence),
                    "info_attributes": dict(info_snapshot.evidence),
                    "system_attributes": "disabled",
                },
                oid_length=64 if object_format == "sha256" else 40,
            )
            self._assert_integration_git_boundary(None, None, boundary)
            yield boundary
        finally:
            if git_dir.is_symlink():
                git_dir.unlink()
            elif git_dir.exists():
                shutil.rmtree(git_dir)

    def _integration_merge_config(self) -> str:
        """Copy only data-only settings that affect ort's merge result."""

        copied: list[str] = []
        for key in MERGE_SEMANTIC_CONFIG:
            result = self._git(
                "config",
                "--local",
                "--null",
                "--get-all",
                key,
                check=False,
            )
            if result.returncode == 1:
                continue
            if result.returncode:
                raise SupervisorError(
                    "git_config_unreadable",
                    result.stderr.decode(errors="replace").strip()
                    or f"local Git setting {key} could not be read",
                )
            raw_values = result.stdout.split(b"\0")
            if raw_values and raw_values[-1] == b"":
                raw_values.pop()
            if not raw_values:
                continue
            try:
                value = raw_values[-1].decode("utf-8")
            except UnicodeDecodeError as error:
                raise SupervisorError(
                    "unsafe_git_merge_config", f"local Git setting {key} is not UTF-8"
                ) from error
            if len(value.encode()) > 1024 or any(character in value for character in "\0\r\n"):
                raise SupervisorError(
                    "unsafe_git_merge_config", f"local Git setting {key} is not bounded"
                )
            if value == "":
                value = "true"
            section, name = key.split(".", 1)
            copied.append(f"[{section}]\n\t{name} = {json.dumps(value)}\n")
        return "".join(copied)

    @staticmethod
    def _read_integration_info_attributes(common_dir: Path) -> AttributeSnapshot:
        source = common_dir / "info" / "attributes"
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(source, flags)
        except FileNotFoundError:
            return GitSupervisor._attribute_snapshot(
                "info_attributes", ".git/info/attributes", None
            )
        except OSError as error:
            raise SupervisorError(
                "unsafe_git_attributes", "repository info attributes could not be opened"
            ) from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_ATTRIBUTE_BYTES:
                raise SupervisorError(
                    "unsafe_git_attributes",
                    "repository info attributes must be a regular file no larger than 1 MiB",
                )
            with os.fdopen(descriptor, "rb", closefd=False) as opened:
                content = opened.read(MAX_ATTRIBUTE_BYTES + 1)
            if len(content) > MAX_ATTRIBUTE_BYTES:
                raise SupervisorError(
                    "unsafe_git_attributes",
                    "repository info attributes must be no larger than 1 MiB",
                )
            return GitSupervisor._attribute_snapshot(
                "info_attributes", ".git/info/attributes", content
            )
        finally:
            os.close(descriptor)

    def _read_core_attributes_file(self, base_sha: str) -> AttributeSnapshot:
        result = self._git(
            "config",
            "--local",
            "--path",
            "--get",
            "core.attributesFile",
            check=False,
        )
        if result.returncode == 1:
            return self._attribute_snapshot("core_attributes", "unset", None)
        if result.returncode:
            raise SupervisorError(
                "git_config_unreadable",
                result.stderr.decode(errors="replace").strip()
                or "core.attributesFile could not be read",
            )
        try:
            value = result.stdout.decode("utf-8").rstrip("\n")
        except UnicodeDecodeError as error:
            raise SupervisorError(
                "unsafe_git_attributes", "core.attributesFile is not UTF-8"
            ) from error
        if not value or any(character in value for character in "\0\r\n"):
            raise SupervisorError("unsafe_git_attributes", "core.attributesFile path is invalid")
        source = Path(value).expanduser()
        if not source.is_absolute():
            relative = PurePosixPath(value)
            if relative.is_absolute() or ".." in relative.parts:
                raise SupervisorError(
                    "unsafe_git_attributes",
                    "relative core.attributesFile must stay within the integration tree",
                )
            tree_path = relative.as_posix()
            entry = self._git(
                "ls-tree",
                "--full-tree",
                "-z",
                base_sha,
                "--",
                f":(literal){tree_path}",
                check=False,
            )
            if entry.returncode:
                raise SupervisorError(
                    "unsafe_git_attributes",
                    entry.stderr.decode(errors="replace").strip()
                    or "relative core.attributesFile could not be read from the base tree",
                )
            if not entry.stdout:
                return self._attribute_snapshot("core_attributes", f"base-tree:{tree_path}", None)
            metadata, separator, returned_path = entry.stdout.partition(b"\t")
            fields = metadata.split()
            try:
                decoded_path = returned_path.removesuffix(b"\0").decode("utf-8")
            except UnicodeDecodeError as error:
                raise SupervisorError(
                    "unsafe_git_attributes", "relative core.attributesFile is not UTF-8"
                ) from error
            if (
                separator != b"\t"
                or not returned_path.endswith(b"\0")
                or len(fields) != 3
                or fields[0] not in {b"100644", b"100755"}
                or fields[1] != b"blob"
                or decoded_path != tree_path
            ):
                raise SupervisorError(
                    "unsafe_git_attributes",
                    "relative core.attributesFile must identify one regular file in the base tree",
                )
            object_id = fields[2].decode("ascii")
            size_text = self._git_text("cat-file", "-s", object_id)
            if not size_text.isascii() or not size_text.isdecimal():
                raise SupervisorError(
                    "unsafe_git_attributes",
                    "relative core.attributesFile size is invalid",
                )
            if int(size_text) > MAX_ATTRIBUTE_BYTES:
                raise SupervisorError(
                    "unsafe_git_attributes",
                    "core.attributesFile must be no larger than 1 MiB",
                )
            content = self._git_bytes("cat-file", "blob", object_id)
            return self._attribute_snapshot(
                "core_attributes",
                f"base-tree:{tree_path}",
                content,
                {"blob_oid": object_id, "base_sha": base_sha},
            )
        if source == Path(os.devnull):
            return self._attribute_snapshot("core_attributes", "disabled", None)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(source, flags)
        except FileNotFoundError:
            return self._attribute_snapshot("core_attributes", f"absolute:{source}", None)
        except OSError as error:
            raise SupervisorError(
                "unsafe_git_attributes", "core.attributesFile could not be opened"
            ) from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_ATTRIBUTE_BYTES:
                raise SupervisorError(
                    "unsafe_git_attributes",
                    "core.attributesFile must be a regular file no larger than 1 MiB",
                )
            with os.fdopen(descriptor, "rb", closefd=False) as opened:
                content = opened.read(MAX_ATTRIBUTE_BYTES + 1)
            if len(content) > MAX_ATTRIBUTE_BYTES:
                raise SupervisorError(
                    "unsafe_git_attributes",
                    "core.attributesFile must be no larger than 1 MiB",
                )
            return self._attribute_snapshot("core_attributes", f"absolute:{source}", content)
        finally:
            os.close(descriptor)

    @staticmethod
    def _attribute_snapshot(
        kind: str,
        source: str,
        content: bytes | None,
        extra: Mapping[str, Any] | None = None,
    ) -> AttributeSnapshot:
        evidence: dict[str, Any] = {
            "kind": kind,
            "source": source,
            "present": content is not None,
            "size": len(content) if content is not None else 0,
            "sha256": sha256(content) if content is not None else None,
            "content_b64": (
                base64.b64encode(content).decode("ascii") if content is not None else None
            ),
        }
        if extra:
            evidence.update(extra)
        return AttributeSnapshot(content=content, evidence=evidence)

    @staticmethod
    def _system_git_executable(repo_root: Path | None = None) -> Path:
        """Resolve Git without ever executing a PATH-selected candidate wrapper."""

        raw = shutil.which("git")
        candidates: list[Path] = []
        if sys.platform == "darwin":
            # /usr/bin/git is an xcrun launcher and needs a child process. Use
            # the actual Apple Git binary so the no-fork sandbox can stay on.
            candidates.extend(
                [
                    Path("/Library/Developer/CommandLineTools/usr/bin/git"),
                    Path("/Applications/Xcode.app/Contents/Developer/usr/bin/git"),
                ]
            )
            if raw and Path(raw) != Path("/usr/bin/git"):
                candidates.append(Path(raw))
        else:
            candidates.extend([Path("/usr/bin/git"), Path("/usr/local/bin/git")])
            if raw:
                candidates.append(Path(raw))
        seen: set[Path] = set()
        for path in candidates:
            try:
                resolved = path.resolve(strict=True)
                metadata = resolved.stat()
            except OSError:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            if repo_root is not None:
                try:
                    resolved.relative_to(repo_root.resolve())
                except ValueError:
                    pass
                else:
                    continue
            if (
                stat.S_ISREG(metadata.st_mode)
                and metadata.st_uid == 0
                and not metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                and os.access(resolved, os.X_OK)
            ):
                return resolved
        raise SupervisorError(
            "untrusted_git_executable",
            "a root-owned, non-writable system Git executable is required",
        )

    def _run_isolated_git(
        self,
        boundary: IntegrationGitBoundary,
        arguments: Sequence[str],
        label: str,
        operation_guard_fd: int,
    ) -> dict[str, Any]:
        with self._git_operation_guard() as git_guard_fd:
            result = self._run_process(
                [
                    *self._supervisor_git_prefix(boundary.git, boundary.git_dir / "hooks"),
                    "-c",
                    "submodule.recurse=false",
                    *arguments,
                ],
                label,
                self.root,
                dict(boundary.env),
                lifecycle_fds=(operation_guard_fd, git_guard_fd),
            )
        result["security_boundary"] = "synthetic-config+empty-exec-path+contained"
        return result

    def _restore_integration_workspace(
        self,
        worktree: Path,
        commit_sha: str,
        operation_guard_fd: int,
        boundary: IntegrationGitBoundary,
    ) -> None:
        if worktree.exists():
            if (worktree / ".git").exists():
                self._assert_integration_git_boundary(worktree, commit_sha, boundary)
            for entry in worktree.iterdir():
                if entry.is_symlink() or not entry.is_dir():
                    entry.unlink()
                else:
                    shutil.rmtree(entry)
        else:
            worktree.mkdir(mode=0o700, parents=True)
        (boundary.git_dir / "HEAD").write_text(commit_sha + "\n", encoding="ascii")
        (boundary.git_dir / "HEAD").chmod(0o600)
        read_tree = self._run_isolated_git(
            boundary,
            ["read-tree", "--reset", commit_sha],
            f"git read-tree {commit_sha}",
            operation_guard_fd,
        )
        if read_tree["exit_code"]:
            raise SupervisorError(
                "integration_materialization_failed",
                read_tree["stderr"].strip() or "isolated read-tree failed",
            )
        checkout = self._run_isolated_git(
            boundary,
            ["checkout-index", "--all", "--force", f"--prefix={worktree}{os.sep}"],
            f"git checkout-index {commit_sha}",
            operation_guard_fd,
        )
        if checkout["exit_code"]:
            raise SupervisorError(
                "integration_materialization_failed",
                checkout["stderr"].strip() or "isolated checkout-index failed",
            )
        git_file = worktree / ".git"
        git_file.write_text(f"gitdir: {boundary.git_dir}\n", encoding="utf-8")
        git_file.chmod(0o600)
        self._assert_integration_git_boundary(worktree, commit_sha, boundary)

    def _integration_workspace_matches(
        self,
        worktree: Path,
        commit_sha: str,
        operation_guard_fd: int,
        boundary: IntegrationGitBoundary,
    ) -> bool:
        self._assert_no_git_grafts()
        try:
            self._assert_integration_git_boundary(worktree, commit_sha, boundary)
        except SupervisorError:
            return False
        for arguments, label in (
            (["diff", "--no-ext-diff", "--quiet", commit_sha, "--"], "git diff --quiet"),
            (
                ["diff", "--cached", "--no-ext-diff", "--quiet", commit_sha, "--"],
                "git diff --cached --quiet",
            ),
        ):
            if self._run_isolated_git(
                boundary,
                arguments,
                label,
                operation_guard_fd,
            )["exit_code"]:
                return False
        return True

    def _assert_integration_git_boundary(
        self,
        worktree: Path | None,
        commit_sha: str | None,
        boundary: IntegrationGitBoundary,
    ) -> None:
        def require_file(path: Path, expected: bytes) -> None:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(path, flags)
            except OSError as error:
                raise SupervisorError(
                    "integration_git_boundary_changed",
                    f"isolated Git control file is unavailable: {path.name}",
                ) from error
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_size != len(expected)
                ):
                    raise SupervisorError(
                        "integration_git_boundary_changed",
                        f"isolated Git control file changed: {path.name}",
                    )
                with os.fdopen(descriptor, "rb", closefd=False) as opened:
                    actual = opened.read(len(expected) + 1)
            finally:
                os.close(descriptor)
            if actual != expected:
                raise SupervisorError(
                    "integration_git_boundary_changed",
                    f"isolated Git control file changed: {path.name}",
                )

        metadata = boundary.git_dir.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise SupervisorError(
                "integration_git_boundary_changed", "isolated Git directory changed"
            )
        try:
            git_metadata = Path(boundary.git).lstat()
        except OSError as error:
            raise SupervisorError(
                "integration_git_boundary_changed", "private Git executable is unavailable"
            ) from error
        if (
            not stat.S_ISREG(git_metadata.st_mode)
            or git_metadata.st_uid != os.getuid()
            or stat.S_IMODE(git_metadata.st_mode) != 0o500
            or git_metadata.st_size != boundary.git_size
        ):
            raise SupervisorError(
                "integration_git_boundary_changed", "private Git executable changed"
            )
        try:
            git_bytes = Path(boundary.git).read_bytes()
        except OSError as error:
            raise SupervisorError(
                "integration_git_boundary_changed", "private Git executable is unavailable"
            ) from error
        if sha256(git_bytes) != boundary.git_digest:
            raise SupervisorError(
                "integration_git_boundary_changed", "private Git executable changed"
            )
        config = boundary.git_dir / "config"
        try:
            config_bytes = config.read_bytes()
        except OSError as error:
            raise SupervisorError(
                "integration_git_boundary_changed", "isolated Git config is unavailable"
            ) from error
        require_file(config, config_bytes)
        if sha256(config_bytes) != boundary.config_digest:
            raise SupervisorError("integration_git_boundary_changed", "isolated Git config changed")
        expected_head = (
            (commit_sha + "\n").encode() if commit_sha else b"ref: refs/heads/acp-isolated\n"
        )
        require_file(boundary.git_dir / "HEAD", expected_head)
        require_file(
            boundary.git_dir / "objects" / "info" / "alternates",
            boundary.alternates_text.encode(),
        )
        info_dir = boundary.git_dir / "info"
        info_metadata = info_dir.lstat()
        expected_info_names: set[str] = set()
        if boundary.info_attributes is not None:
            expected_info_names.add("attributes")
        if boundary.global_attributes is not None:
            expected_info_names.add("global-attributes")
        if (
            not stat.S_ISDIR(info_metadata.st_mode)
            or info_metadata.st_uid != os.getuid()
            or stat.S_IMODE(info_metadata.st_mode) != 0o700
            or {entry.name for entry in info_dir.iterdir()} != expected_info_names
        ):
            raise SupervisorError(
                "integration_git_boundary_changed", "isolated Git info directory changed"
            )
        if boundary.info_attributes is not None:
            require_file(info_dir / "attributes", boundary.info_attributes)
        if boundary.global_attributes is not None:
            require_file(info_dir / "global-attributes", boundary.global_attributes)
        for directory in (boundary.git_dir / "hooks", boundary.git_dir / "empty-exec"):
            opened = directory.lstat()
            if (
                not stat.S_ISDIR(opened.st_mode)
                or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o700
                or any(directory.iterdir())
            ):
                raise SupervisorError(
                    "integration_git_boundary_changed",
                    f"isolated Git {directory.name} directory changed",
                )
        if any(
            entry.is_file() or entry.is_symlink()
            for entry in (boundary.git_dir / "refs").rglob("*")
        ):
            raise SupervisorError("integration_git_boundary_changed", "isolated Git refs changed")
        allowed = {
            "HEAD",
            "config",
            "empty-exec",
            "hooks",
            "index",
            "info",
            "objects",
            "refs",
            "supervisor-git",
        }
        if any(entry.name not in allowed for entry in boundary.git_dir.iterdir()):
            raise SupervisorError(
                "integration_git_boundary_changed", "isolated Git control files changed"
            )
        if worktree is not None:
            require_file(
                worktree / ".git",
                f"gitdir: {boundary.git_dir}\n".encode(),
            )

    def _assert_safe_git_execution_config(self) -> None:
        executable_config = self._git(
            "config",
            "--local",
            "--name-only",
            "--get-regexp",
            (
                r"^(filter\..*\.(clean|smudge|process|required)|merge\..*\.driver|"
                r"core\.(fsmonitor|sshcommand)|diff\.external|difftool\..*\.cmd|"
                r"mergetool\..*\.cmd|gpg(\..*)?\.program|credential(\..*)?\.helper|"
                r"include\.path|includeif\..*\.path)$"
            ),
            check=False,
        )
        if executable_config.returncode not in {0, 1}:
            raise SupervisorError(
                "git_config_unreadable",
                executable_config.stderr.decode(errors="replace").strip()
                or "local Git execution config could not be inspected",
            )
        configured = executable_config.stdout.decode(errors="replace").splitlines()
        if configured:
            raise SupervisorError(
                "unsafe_git_execution_config",
                "integration refuses executable Git config: " + ", ".join(configured),
            )

    def _assert_no_git_grafts(self) -> None:
        """Grafts cannot participate in ACP's replacement-free object contract."""

        grafts = self._git_common_dir / "info" / "grafts"
        try:
            grafts.lstat()
        except FileNotFoundError:
            return
        except OSError as error:
            raise SupervisorError(
                "git_grafts_unreadable", "repository graft metadata could not be inspected"
            ) from error
        raise SupervisorError(
            "git_grafts_unsupported",
            "repository .git/info/grafts must be removed; ACP disables replacement objects",
        )

    def _disabled_git_hooks_dir(self) -> Path:
        hooks_dir = self.state_dir / "disabled-hooks"
        hooks_dir.mkdir(mode=0o700, exist_ok=True)
        opened = hooks_dir.stat()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
            or any(hooks_dir.iterdir())
        ):
            raise SupervisorError(
                "unsafe_git_hooks_directory",
                "the supervisor's disabled-hooks directory must be empty, current-user-owned 0700",
            )
        return hooks_dir

    @staticmethod
    def _supervisor_git_prefix(git: str, hooks_dir: Path) -> list[str]:
        return [
            git,
            "-c",
            f"core.hooksPath={hooks_dir}",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "commit.gpgSign=false",
            "-c",
            "merge.verifySignatures=false",
            "-c",
            "maintenance.auto=false",
            "-c",
            "gc.auto=0",
        ]

    def _supervisor_git_env(self) -> dict[str, str]:
        env = self._child_env()
        env.update(
            {
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_ATTR_NOSYSTEM": "1",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_TERMINAL_PROMPT": "0",
            }
        )
        return env

    def _run_critic(
        self,
        command: str,
        cwd: Path,
        extra_env: dict[str, str],
        trust_pin: dict[str, Any] | None = None,
        pass_fds: Sequence[int] = (),
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
                    guard_fd=pass_fds[0] if pass_fds else None,
                    process_runner=self._run_trusted_contained,
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
        trampoline = Path(__file__).with_name("worker_trampoline.py").resolve()
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

        if self._process_identity(pid) != identity:
            return
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if self._process_identity(pid) != identity:
                return
            time.sleep(0.01)
        raise SupervisorError(
            "process_containment_failed",
            "command survived unexpected kernel monitor termination",
        )

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
