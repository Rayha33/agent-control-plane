from __future__ import annotations

import base64
import errno as errno
import fcntl as fcntl
import hashlib as hashlib
import hmac
import json
import os
import re
import select
import shlex
import shutil
import signal
import socket as socket
import sqlite3
import stat
import subprocess
import sys
import time
import tomllib as tomllib
import unicodedata
import uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass as dataclass
from datetime import UTC as UTC
from datetime import datetime as datetime
from pathlib import Path, PurePosixPath
from typing import Any

from . import __version__
from .assurance import REJECT_VERDICTS as REJECT_VERDICTS
from .assurance import Assurance as Assurance
from .assurance import Reviewer as Reviewer
from .assurance import load_policy as load_policy
from .credential_providers import (
    CredentialDefinition as CredentialDefinition,
)
from .credential_providers import (
    CredentialError,
    CredentialHandle,
    CredentialRegistry,
)
from .credential_providers import (
    parse_credential_definitions as parse_credential_definitions,
)
from .runner_identity import (
    IdentityError as IdentityError,
)
from .runner_identity import (
    assert_distinct as assert_distinct,
)
from .runner_identity import (
    credential_digest as credential_digest,
)
from .runner_identity import (
    issue_credential as issue_credential,
)
from .runner_identity import (
    validate_role as validate_role,
)
from .runner_identity import (
    verify_credential as verify_credential,
)
from .runtime_drivers import (
    DriverContext as DriverContext,
)
from .runtime_drivers import (
    DriverDefinition as DriverDefinition,
)
from .runtime_drivers import (
    DriverError,
    PhaseEvidence,
    build_driver,
    run_trusted,
)
from .runtime_drivers import (
    ownership_token as ownership_token,
)
from .runtime_drivers import (
    parse_driver_definitions as parse_driver_definitions,
)
from .runtime_drivers import (
    resolve_trusted_executable as resolve_trusted_executable,
)
from .scheduling import Scheduler, normalize_artifact
from .scheduling import declared_resources as declared_resources
from .schema_version import (
    Migration,
    SchemaVersionError,
)
from .schema_version import apply_migration_ledger as _apply_ledger
from .schema_version import assert_schema_not_newer as _assert_not_newer
from .schema_version import stamp_schema_version as _stamp
from .schema_version import stored_schema_version as _stored_version
from .status import (
    ACTIVE_STATUSES as ACTIVE_STATUSES,
)
from .status import (
    DEFAULT_LEASE_RISK_SECONDS,
    StatusView,
)
from .status import (
    LIVE_ATTEMPT_STATUSES as LIVE_ATTEMPT_STATUSES,
)
from .status import (
    _age_seconds as _age_seconds,
)
from .supervisor.claims import ClaimsMixin
from .supervisor.common import (
    CLEANUP_FENCE_EPOCH,
    DEFAULT_GC_RETENTION_SECONDS,
    GENESIS_HASH,
    MAX_ATTRIBUTE_BYTES,
    MERGE_SEMANTIC_CONFIG,
    PUBLIC_CHILD_ENV,
    AttributeSnapshot,
    IntegrationGitBoundary,
    SupervisorError,
    canonical_json,
    sha256,
    utc_now,
)
from .supervisor.common import (
    EVIDENCE_STREAM_BUDGET as EVIDENCE_STREAM_BUDGET,
)
from .supervisor.common import (
    FORK_DENIED_EXIT_CODE as FORK_DENIED_EXIT_CODE,
)
from .supervisor.common import (
    FORK_DENIED_SIGNATURE as FORK_DENIED_SIGNATURE,
)
from .supervisor.common import (
    GC_RECLAIMABLE_TASK_STATUSES as GC_RECLAIMABLE_TASK_STATUSES,
)
from .supervisor.common import (
    SUBMISSION_OBJECT_CONTRACT as SUBMISSION_OBJECT_CONTRACT,
)
from .supervisor.common import (
    SUPERVISOR_SECRET_ENV as SUPERVISOR_SECRET_ENV,
)
from .supervisor.common import (
    RuntimePortPool as RuntimePortPool,
)
from .supervisor.config import (
    Config as Config,
)
from .supervisor.config import (
    ConfigMixin,
)
from .supervisor.identity import IdentityMixin
from .supervisor.process import ProcessMixin
from .supervisor.qc import QcMixin
from .supervisor.reaper import ReaperMixin
from .supervisor.runtime import RuntimeMixin

# Board #1630: the table definitions, the idempotent column upgrade and the
# case-sensitivity probe now live in `supervisor.schema`. They are imported back into this
# namespace rather than referenced through the package because callers and tests import
# them FROM `agent_control_plane.git_supervisor`; scripts/check_public_surface.py pins that.
from .supervisor.schema import (
    META_CASE_SENSITIVE,
    SCHEMA,
    _columns,
    probe_case_sensitive_paths,
)
from .supervisor.schema import migrate as _schema_migrate
from .supervisor.views import ViewsMixin
from .supervisor.workers import WorkersMixin
from .trust_bundles import (
    TrustBundleError,
    load_current_bundle,
    verify_bundle_pin,
)
from .trust_bundles import (
    executable_from_pin as executable_from_pin,
)
from .worker_trampoline import LIFECYCLE_FDS_PREFIX as LIFECYCLE_FDS_PREFIX
from .worker_trampoline import MONITOR_MODE as MONITOR_MODE

SCHEMA_VERSION = 2
"""Schema this binary understands. Raise it in the same commit that adds a MIGRATIONS entry."""


# Numbered upgrades from SCHEMA_VERSION - 1 to SCHEMA_VERSION, applied in order, each
# inside one transaction. Version 1 is the baseline: the idempotent CREATE TABLE IF NOT
# EXISTS script plus the column adds that predate stamping, so an unstamped database is
# brought to 1 by the code that already existed rather than by a ledger entry. Anything
# after 1 goes here — including index, rename, backfill and data transforms, which the
# PRAGMA/ALTER pattern cannot express.
def _add_declared_resources(connection: sqlite3.Connection) -> None:
    """Keep the resource string the operator actually typed, for display only.

    `normalize_resource` casefolds, and the folded string is the PRIMARY KEY of
    `resource_leases`, so it cannot be changed without rewriting lease identity. This
    column sits beside it: a folded -> raw map, read by the operator-facing surfaces so
    they stop printing `changelog.md` at someone who wrote `CHANGELOG.md`. Matching is
    untouched and still case-insensitive.

    Idempotent: a fresh database already has the column from SCHEMA.
    """

    if "declared_resources_json" not in _columns(connection, "tasks"):
        connection.execute(
            "ALTER TABLE tasks ADD COLUMN declared_resources_json TEXT NOT NULL DEFAULT '{}'"
        )


MIGRATIONS: tuple[Migration, ...] = ((2, _add_declared_resources),)


def stored_schema_version(connection: sqlite3.Connection) -> int | None:
    """Shared implementation, re-raised as a SupervisorError.

    The CLI's error path catches SupervisorError, so the translation keeps the exit
    code and JSON shape while the check itself lives in one place with the service
    database's copy.
    """

    try:
        return _stored_version(connection)
    except SchemaVersionError as error:
        raise SupervisorError(error.code, str(error)) from None


def assert_schema_not_newer(stored: int | None) -> None:
    try:
        _assert_not_newer(
            stored,
            binary_version=SCHEMA_VERSION,
            component="control database",
            package_version=__version__,
        )
    except SchemaVersionError as error:
        raise SupervisorError(error.code, str(error)) from None


class GitSupervisor(
    ConfigMixin,
    IdentityMixin,
    ViewsMixin,
    ProcessMixin,
    WorkersMixin,
    RuntimeMixin,
    QcMixin,
    ClaimsMixin,
    ReaperMixin,
):
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
        self._fork_support: bool | None = None
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
            # Probed rather than re-probed: the answer is a property of the volume, and
            # running it on every open would create and delete two files per command.
            if not connection.execute(
                "SELECT 1 FROM meta WHERE key = ?", (META_CASE_SENSITIVE,)
            ).fetchone():
                connection.execute(
                    "INSERT INTO meta(key, value) VALUES(?, ?)",
                    (
                        META_CASE_SENSITIVE,
                        "1" if probe_case_sensitive_paths(self.state_dir) else "0",
                    ),
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
            _stamp(connection, version=SCHEMA_VERSION, package_version=__version__)

    @staticmethod
    def _apply_migration_ledger(connection: sqlite3.Connection, stored: int | None) -> None:
        _apply_ledger(connection, stored, MIGRATIONS)

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

        The body moved to `supervisor.schema.migrate` (board #1630). This delegate keeps
        `GitSupervisor._migrate` callable exactly as it was.
        """

        _schema_migrate(connection)

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
    def normalize_resource(raw: str, repo: Path | None = None, *, fold: bool = True) -> str:
        """Canonical form of a declared resource.

        `fold=True` is the storage form and the lease PRIMARY KEY, and it stays folded.
        `fold=False` is the same canonicalisation — NFC, `\\` to `/`, the `/**` suffix on
        a directory, the same refusals — with the operator's capitalisation intact, for
        matching on a filesystem that distinguishes it. A `logical:` resource is an
        identity rather than a path and stays folded either way, because folding is what
        makes `logical:Deploy` and `logical:deploy` one lock.
        """

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
        canonical = value.rstrip("/") + "/**" if directory else value
        return canonical.casefold() if fold else canonical

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
        declared: dict[str, str] = {}
        for item in resources:
            folded = self.normalize_resource(item, self.root)
            declared.setdefault(folded, item.strip())
        normalized = sorted(declared)
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
                   declared_resources_json,
                   dependencies_json, produces_json, consumes_json, base_branch,
                   base_sha, priority, status, current_attempt_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', NULL, ?, ?)
                """,
                (
                    task_id,
                    title.strip(),
                    description.strip(),
                    canonical_json(list(acceptance)),
                    canonical_json(normalized),
                    canonical_json(declared),
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

    # -- authenticated runner identities -----------------------------------

    # -- trusted runtime drivers -------------------------------------------

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

    @staticmethod
    def _process_has_exited(pid: int, identity: str) -> bool:
        """Whether this exact process has stopped running.

        A zombie is not running. It has already exited and is only waiting for its
        parent to collect the status, but its /proc entry and its start time both
        survive that wait — so an identity check alone cannot tell a zombie from a live
        process, and reports a successful kill as a survival.

        Measured: running ACP's suite under ACP's own QC, the containment tests failed
        with "command survived unexpected kernel monitor termination" on a PID whose
        state was `Z` both before the SIGKILL and after the three-second wait. The
        process had died; nothing in the nested arrangement reaped it, and "still in
        /proc" was being read as "still running".
        """

        if GitSupervisor._process_identity(pid) != identity:
            return True
        return GitSupervisor._process_state(pid) == "Z"

    @staticmethod
    def _command_finding(command: str, result: dict[str, Any]) -> dict[str, str]:
        """Evidence for a failed QC command, from BOTH streams.

        This used to be `stderr or stdout`, so stdout was read only when stderr was
        empty. Every mainstream test runner reports failures on stdout while writing
        something incidental to stderr, so in the normal case the finding carried the
        incidental half and discarded the diagnosis: a real run reported
        "Creating virtual environment at: .venv / Installed 35 packages" as the entire
        evidence for a suite that had named two failing tests on stdout.

        stdout is listed first because it is where the failure summary lives and the
        evidence is read top-down.
        """

        sections = []
        for stream in ("stdout", "stderr"):
            body = GitSupervisor._evidence_window(result[stream] or "")
            if body:
                sections.append(f"--- {stream} ---\n{body}")
        output = "\n".join(sections) or "(no output on either stream)"
        evidence = f"exit={result['exit_code']}; {output}"

        if GitSupervisor._is_fork_denial(result):
            # The command never ran: this platform's containment refused it a
            # subprocess. Saying "fix the failure and submit a new committed attempt"
            # here would be a false attribution — durable, signed, and pointing at a
            # worker who cannot do anything about the host. A verdict that is
            # confidently wrong about WHOSE fault something is, is worse than one that
            # says plainly that it could not run.
            return {
                "severity": "high",
                "requirement": "the host can run the configured gate",
                "finding": f"command could not run on this host: {command}",
                "evidence": evidence,
                "required_fix": (
                    "not a defect in the submitted work: this platform's command "
                    "containment denies fork, so the command was never executed. Run "
                    "the gate where a contained command may spawn a subprocess "
                    "(scripts/test-linux.sh, a Linux host, or CI), or configure a gate "
                    "command that spawns nothing."
                ),
            }
        return {
            "severity": "high",
            "requirement": "deterministic QC command passes",
            "finding": f"command failed: {command}",
            "evidence": evidence,
            "required_fix": "fix the failure and submit a new committed attempt",
        }
