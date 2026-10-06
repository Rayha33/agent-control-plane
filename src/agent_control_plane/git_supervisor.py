from __future__ import annotations

import base64 as base64
import errno as errno
import fcntl as fcntl
import hashlib as hashlib
import hmac
import json
import os
import re as re
import select
import shlex
import shutil
import signal
import socket as socket
import sqlite3
import stat
import subprocess
import sys
import time as time
import tomllib as tomllib
import unicodedata as unicodedata
import uuid as uuid
from collections.abc import Iterator as Iterator
from collections.abc import Mapping as Mapping
from collections.abc import Sequence
from contextlib import contextmanager as contextmanager
from dataclasses import dataclass as dataclass
from datetime import UTC as UTC
from datetime import datetime as datetime
from pathlib import Path
from pathlib import PurePosixPath as PurePosixPath
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
from .scheduling import Scheduler as Scheduler
from .scheduling import declared_resources as declared_resources
from .scheduling import normalize_artifact as normalize_artifact
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
    DEFAULT_LEASE_RISK_SECONDS as DEFAULT_LEASE_RISK_SECONDS,
)
from .status import (
    LIVE_ATTEMPT_STATUSES as LIVE_ATTEMPT_STATUSES,
)
from .status import (
    StatusView as StatusView,
)
from .status import (
    _age_seconds as _age_seconds,
)
from .supervisor.claims import ClaimsMixin
from .supervisor.common import (
    CLEANUP_FENCE_EPOCH,
    MAX_ATTRIBUTE_BYTES,
    PUBLIC_CHILD_ENV,
    AttributeSnapshot,
    SupervisorError,
    utc_now,
)
from .supervisor.common import (
    DEFAULT_GC_RETENTION_SECONDS as DEFAULT_GC_RETENTION_SECONDS,
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
from .supervisor.common import GENESIS_HASH as GENESIS_HASH
from .supervisor.common import (
    MERGE_SEMANTIC_CONFIG as MERGE_SEMANTIC_CONFIG,
)
from .supervisor.common import (
    SUBMISSION_OBJECT_CONTRACT as SUBMISSION_OBJECT_CONTRACT,
)
from .supervisor.common import (
    SUPERVISOR_SECRET_ENV as SUPERVISOR_SECRET_ENV,
)
from .supervisor.common import (
    IntegrationGitBoundary as IntegrationGitBoundary,
)
from .supervisor.common import (
    RuntimePortPool as RuntimePortPool,
)
from .supervisor.common import canonical_json as canonical_json
from .supervisor.common import sha256 as sha256
from .supervisor.config import (
    Config as Config,
)
from .supervisor.config import (
    ConfigMixin,
)
from .supervisor.identity import IdentityMixin
from .supervisor.integration import IntegrationMixin
from .supervisor.process import ProcessMixin
from .supervisor.qc import QcMixin
from .supervisor.reaper import ReaperMixin
from .supervisor.runtime import RuntimeMixin
from .supervisor.sandbox_execution_journal import SandboxExecutionJournalMixin

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
from .supervisor.store import StoreMixin
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

SCHEMA_VERSION = 21
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


def _add_attempt_progress_timestamps(connection: sqlite3.Connection) -> None:
    """Separate attempt liveness from explicit checkpoint freshness.

    Old heartbeats rewrote both ``updated_at`` and ``checkpoint_json``. A v2
    worker that survives this migration also cannot refresh the new dedicated
    timestamps. Leave both ages unknown until a v3 heartbeat/checkpoint records
    them; neither a legacy update nor lease renewal proves fresh liveness here.
    """

    columns = {row[1] for row in connection.execute("PRAGMA table_info(attempts)")}
    if "heartbeat_at" not in columns:
        connection.execute("ALTER TABLE attempts ADD COLUMN heartbeat_at TEXT NOT NULL DEFAULT ''")
    if "checkpoint_at" not in columns:
        connection.execute("ALTER TABLE attempts ADD COLUMN checkpoint_at TEXT NOT NULL DEFAULT ''")


def _add_base_checkout_snapshot(connection: sqlite3.Connection) -> None:
    """Persist a claim-time fingerprint for the shared base checkout.

    Existing active attempts cannot be assigned a truthful past baseline, so the
    empty sentinel deliberately leaves them on the legacy path. New claims always
    write a non-empty snapshot before they become working.
    """

    columns = {row[1] for row in connection.execute("PRAGMA table_info(attempts)")}
    if "base_checkout_snapshot_json" not in columns:
        connection.execute(
            "ALTER TABLE attempts ADD COLUMN base_checkout_snapshot_json TEXT NOT NULL DEFAULT ''"
        )


def _require_base_checkout_snapshot(connection: sqlite3.Connection) -> None:
    """Mark new attempts as requiring a claim-time snapshot.

    Existing attempts retain the default false value because a truthful historical
    baseline cannot be reconstructed during migration.
    """

    columns = {row[1] for row in connection.execute("PRAGMA table_info(attempts)")}
    if "base_checkout_snapshot_required" not in columns:
        connection.execute(
            "ALTER TABLE attempts ADD COLUMN base_checkout_snapshot_required "
            "INTEGER NOT NULL DEFAULT 0"
        )


def _fence_legacy_attempt_inserts(connection: sqlite3.Connection) -> None:
    """Reject claim rows from supervisors predating the snapshot contract.

    A supervisor may stay alive across a database migration. It passed its schema
    check before the upgrade, so a version check alone cannot prevent it from
    inserting a new row afterward. Its old INSERT omits the marker, which defaults
    to zero; the trigger makes that stale claim fail closed while leaving existing
    legacy rows untouched.
    """

    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS attempts_require_base_checkout_snapshot
        BEFORE INSERT ON attempts
        WHEN NEW.base_checkout_snapshot_required != 1
          OR NEW.base_checkout_snapshot_json = ''
        BEGIN
          SELECT RAISE(ABORT, 'attempt_base_checkout_snapshot_required');
        END
        """
    )


def _add_attempt_worktree_root(connection: sqlite3.Connection) -> None:
    """Persist the managed root with each attempt's already-persisted worktree path.

    Empty is the legacy sentinel: those attempts remain pinned to the original
    ``.acp/worktrees`` root. Never backfill from an arbitrary database path.
    """

    columns = {row[1] for row in connection.execute("PRAGMA table_info(attempts)")}
    if "worktree_root" not in columns:
        connection.execute("ALTER TABLE attempts ADD COLUMN worktree_root TEXT NOT NULL DEFAULT ''")


def _add_qc_runs_latest_lookup_index(connection: sqlite3.Connection) -> None:
    """Index each submission's latest QC query for status and recurrence views."""

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_qc_runs_submission_latest
          ON qc_runs(submission_id, finished_at DESC, id DESC)
        """
    )


def _add_read_dependency_snapshots(connection: sqlite3.Connection) -> None:
    """Store optional task read scopes and their per-attempt Git snapshots."""

    task_columns = _columns(connection, "tasks")
    if "read_resources_json" not in task_columns:
        connection.execute(
            "ALTER TABLE tasks ADD COLUMN read_resources_json TEXT NOT NULL DEFAULT '[]'"
        )
    if "declared_read_resources_json" not in task_columns:
        connection.execute(
            "ALTER TABLE tasks ADD COLUMN declared_read_resources_json TEXT NOT NULL DEFAULT '{}'"
        )
    attempt_columns = _columns(connection, "attempts")
    if "read_resources_snapshot_json" not in attempt_columns:
        connection.execute(
            "ALTER TABLE attempts ADD COLUMN read_resources_snapshot_json TEXT NOT NULL DEFAULT ''"
        )


def _add_qc_acceptance_coverage(connection: sqlite3.Connection) -> None:
    """Persist criterion-level QC outcomes and fence pre-contract binaries."""

    columns = {row["name"] for row in connection.execute("PRAGMA table_info(qc_runs)")}
    if "acceptance_coverage_json" not in columns:
        connection.execute(
            "ALTER TABLE qc_runs ADD COLUMN acceptance_coverage_json TEXT NOT NULL DEFAULT '[]'"
        )
    if "acceptance_coverage_contract_version" not in columns:
        connection.execute(
            "ALTER TABLE qc_runs ADD COLUMN acceptance_coverage_contract_version "
            "INTEGER NOT NULL DEFAULT 0"
        )


def _add_submission_result_manifest(connection: sqlite3.Connection) -> None:
    """Store a bounded completion receipt beside its immutable candidate submission."""

    columns = {row["name"] for row in connection.execute("PRAGMA table_info(submissions)")}
    if "result_manifest_json" not in columns:
        connection.execute(
            "ALTER TABLE submissions ADD COLUMN result_manifest_json TEXT NOT NULL DEFAULT ''"
        )


def _add_result_import_journal(connection: sqlite3.Connection) -> None:
    """Persist a claim-fenced write-ahead record for host-validated worker results."""

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS result_imports (
          id TEXT PRIMARY KEY,
          attempt_id TEXT NOT NULL REFERENCES attempts(id),
          claim_token INTEGER NOT NULL,
          worker_pid INTEGER NOT NULL,
          worker_identity TEXT NOT NULL,
          worker_exit_receipt_json TEXT NOT NULL,
          base_sha TEXT NOT NULL,
          tree_sha TEXT NOT NULL,
          baseline_digest TEXT NOT NULL,
          result_digest TEXT NOT NULL,
          change_digest TEXT NOT NULL,
          result_ref TEXT NOT NULL UNIQUE,
          commit_timestamp INTEGER NOT NULL,
          commit_sha TEXT NOT NULL,
          phase TEXT NOT NULL CHECK (phase IN (
            'prepared', 'ref_published', 'submitted', 'ambiguous'
          )),
          submission_id TEXT REFERENCES submissions(id),
          error TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          UNIQUE(attempt_id, claim_token, result_digest)
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_result_imports_submission ON result_imports(submission_id)"
    )


def _add_result_import_object_staging(connection: sqlite3.Connection) -> None:
    """Bind private staged object provenance to each prepared result import."""

    columns = {row["name"] for row in connection.execute("PRAGMA table_info(result_imports)")}
    additions = (
        ("staging_path", "TEXT NOT NULL DEFAULT ''"),
        ("object_ids_json", "TEXT NOT NULL DEFAULT '[]'"),
        ("promote_object_ids_json", "TEXT NOT NULL DEFAULT '[]'"),
    )
    for name, definition in additions:
        if name not in columns:
            connection.execute(f"ALTER TABLE result_imports ADD COLUMN {name} {definition}")


def _add_result_import_source_discriminator(connection: sqlite3.Connection) -> None:
    """Separate direct-process receipts from future sandbox-execution receipts.

    Existing worker result journals remain ``direct_worker`` rows. Sandbox rows
    have no worker PID or direct-worker receipt; their durable identity is the
    exact sandbox execution plus a cleanup-verification receipt digest.
    """

    columns = {row["name"]: row for row in connection.execute("PRAGMA table_info(result_imports)")}
    if "source_kind" in columns:
        return
    if not columns:
        raise sqlite3.DatabaseError("result_imports must exist before source migration")

    if connection.execute(
        """
        SELECT 1
        FROM result_imports AS result
        JOIN sandbox_executions AS execution ON execution.attempt_id = result.attempt_id
        LIMIT 1
        """
    ).fetchone():
        raise sqlite3.IntegrityError("result_import_source_execution_mismatch")

    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_sandbox_execution_attempt_identity "
        "ON sandbox_executions(attempt_id, execution_id)"
    )
    connection.execute(
        """
        CREATE TABLE result_imports_source_v19 (
          id TEXT PRIMARY KEY,
          attempt_id TEXT NOT NULL REFERENCES attempts(id),
          claim_token INTEGER NOT NULL,
          source_kind TEXT NOT NULL DEFAULT 'direct_worker'
            CHECK (source_kind IN ('direct_worker', 'sandbox_execution')),
          worker_pid INTEGER,
          worker_identity TEXT NOT NULL DEFAULT '',
          worker_exit_receipt_json TEXT NOT NULL DEFAULT '',
          sandbox_execution_id TEXT,
          sandbox_cleanup_receipt_digest TEXT,
          base_sha TEXT NOT NULL,
          tree_sha TEXT NOT NULL,
          baseline_digest TEXT NOT NULL,
          result_digest TEXT NOT NULL,
          change_digest TEXT NOT NULL,
          result_ref TEXT NOT NULL UNIQUE,
          commit_timestamp INTEGER NOT NULL,
          commit_sha TEXT NOT NULL,
          phase TEXT NOT NULL CHECK (phase IN (
            'prepared', 'ref_published', 'submitted', 'ambiguous'
          )),
          submission_id TEXT REFERENCES submissions(id),
          error TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          staging_path TEXT NOT NULL DEFAULT '',
          object_ids_json TEXT NOT NULL DEFAULT '[]',
          promote_object_ids_json TEXT NOT NULL DEFAULT '[]',
          UNIQUE(attempt_id, claim_token, result_digest),
          UNIQUE(sandbox_execution_id),
          FOREIGN KEY (attempt_id, sandbox_execution_id)
            REFERENCES sandbox_executions(attempt_id, execution_id),
          CHECK (
            (source_kind = 'direct_worker'
              AND worker_pid IS NOT NULL
              AND sandbox_execution_id IS NULL
              AND sandbox_cleanup_receipt_digest IS NULL)
            OR
            (source_kind = 'sandbox_execution'
              AND worker_pid IS NULL
              AND worker_identity = ''
              AND worker_exit_receipt_json = ''
              AND sandbox_execution_id IS NOT NULL
              AND sandbox_cleanup_receipt_digest IS NOT NULL
              AND length(sandbox_cleanup_receipt_digest) = 64
              AND sandbox_cleanup_receipt_digest NOT GLOB '*[^0-9a-f]*')
          )
        )
        """
    )
    connection.execute(
        """
        INSERT INTO result_imports_source_v19 (
          id, attempt_id, claim_token, source_kind, worker_pid, worker_identity,
          worker_exit_receipt_json, sandbox_execution_id, sandbox_cleanup_receipt_digest,
          base_sha, tree_sha, baseline_digest, result_digest, change_digest, result_ref,
          commit_timestamp, commit_sha, phase, submission_id, error, created_at, updated_at,
          staging_path, object_ids_json, promote_object_ids_json
        )
        SELECT id, attempt_id, claim_token, 'direct_worker', worker_pid, worker_identity,
          worker_exit_receipt_json, NULL, NULL, base_sha, tree_sha, baseline_digest,
          result_digest, change_digest, result_ref, commit_timestamp, commit_sha, phase,
          submission_id, error, created_at, updated_at, staging_path, object_ids_json,
          promote_object_ids_json
        FROM result_imports
        """
    )
    # A database rebuilt from a historical schema stamp can still carry these
    # triggers from an earlier schema shape. They reference the table being
    # replaced, so remove and recreate them around the transactional table swap.
    connection.execute("DROP TRIGGER IF EXISTS sandbox_execution_direct_result_guard")
    connection.execute("DROP TRIGGER IF EXISTS sandbox_execution_direct_result_update_guard")
    connection.execute("DROP TABLE result_imports")
    connection.execute("ALTER TABLE result_imports_source_v19 RENAME TO result_imports")
    connection.execute(
        "CREATE INDEX idx_result_imports_submission ON result_imports(submission_id)"
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS result_import_direct_source_insert_guard
        BEFORE INSERT ON result_imports
        WHEN NEW.source_kind = 'direct_worker'
          AND EXISTS (
            SELECT 1 FROM sandbox_executions WHERE attempt_id = NEW.attempt_id
          )
        BEGIN
          SELECT RAISE(ABORT, 'result_import_source_execution_mismatch');
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS result_import_direct_source_update_guard
        BEFORE UPDATE OF attempt_id, source_kind ON result_imports
        WHEN NEW.source_kind = 'direct_worker'
          AND EXISTS (
            SELECT 1 FROM sandbox_executions WHERE attempt_id = NEW.attempt_id
          )
        BEGIN
          SELECT RAISE(ABORT, 'result_import_source_execution_mismatch');
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS result_import_source_identity_immutable
        BEFORE UPDATE OF attempt_id, claim_token, source_kind, worker_pid,
          worker_identity, worker_exit_receipt_json, sandbox_execution_id,
          sandbox_cleanup_receipt_digest ON result_imports
        WHEN OLD.attempt_id IS NOT NEW.attempt_id
          OR OLD.claim_token IS NOT NEW.claim_token
          OR OLD.source_kind IS NOT NEW.source_kind
          OR OLD.worker_pid IS NOT NEW.worker_pid
          OR OLD.worker_identity IS NOT NEW.worker_identity
          OR OLD.worker_exit_receipt_json IS NOT NEW.worker_exit_receipt_json
          OR OLD.sandbox_execution_id IS NOT NEW.sandbox_execution_id
          OR OLD.sandbox_cleanup_receipt_digest IS NOT NEW.sandbox_cleanup_receipt_digest
        BEGIN
          SELECT RAISE(ABORT, 'result_import_source_identity_immutable');
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS sandbox_execution_direct_result_guard
        BEFORE INSERT ON sandbox_executions
        WHEN EXISTS (
          SELECT 1 FROM result_imports
          WHERE attempt_id = NEW.attempt_id AND source_kind = 'direct_worker'
        )
        BEGIN
          SELECT RAISE(ABORT, 'result_import_source_execution_mismatch');
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS sandbox_execution_direct_result_update_guard
        BEFORE UPDATE OF attempt_id ON sandbox_executions
        WHEN EXISTS (
          SELECT 1 FROM result_imports
          WHERE attempt_id = NEW.attempt_id AND source_kind = 'direct_worker'
        )
        BEGIN
          SELECT RAISE(ABORT, 'result_import_source_execution_mismatch');
        END
        """
    )


def _add_sandbox_execution_journal(connection: sqlite3.Connection) -> None:
    """Persist OCI worker identities before adding any launch integration.

    A cleanup report is intentionally distinct from independently verified cleanup.
    The reaper only accepts ``cleanup_verified``; no launcher or verifier advances
    that phase in this migration.
    """

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS sandbox_executions (
          attempt_id TEXT PRIMARY KEY REFERENCES attempts(id),
          claim_token INTEGER NOT NULL CHECK (claim_token > 0),
          execution_id TEXT NOT NULL UNIQUE,
          backend TEXT NOT NULL CHECK (backend = 'oci-runc'),
          container_id TEXT NOT NULL UNIQUE,
          bundle_digest TEXT NOT NULL CHECK (length(bundle_digest) = 64),
          rootfs_digest TEXT NOT NULL CHECK (length(rootfs_digest) = 64),
          runtime_version TEXT NOT NULL,
          oci_version TEXT NOT NULL,
          bundle_path TEXT NOT NULL,
          state_path TEXT NOT NULL,
          phase TEXT NOT NULL CHECK (phase IN (
            'reserved', 'launched', 'running', 'stopping', 'exited',
            'cleanup_reported', 'cleanup_verified', 'ambiguous'
          )),
          monitor_pid INTEGER,
          monitor_identity TEXT NOT NULL DEFAULT '',
          runc_client_pid INTEGER,
          runc_client_identity TEXT NOT NULL DEFAULT '',
          init_pid INTEGER,
          init_identity TEXT NOT NULL DEFAULT '',
          wrapper_unit TEXT NOT NULL DEFAULT '',
          wrapper_invocation_id TEXT NOT NULL DEFAULT '',
          scope_unit TEXT NOT NULL DEFAULT '',
          scope_invocation_id TEXT NOT NULL DEFAULT '',
          cgroup_path TEXT NOT NULL DEFAULT '',
          stop_reason TEXT NOT NULL DEFAULT '',
          runc_exit_code INTEGER,
          runc_exit_observed_by TEXT NOT NULL DEFAULT '',
          cleanup_receipt_json TEXT NOT NULL DEFAULT '{}',
          failure_reason TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          UNIQUE (attempt_id, claim_token),
          CHECK (
            phase NOT IN (
              'launched', 'running', 'stopping', 'exited',
              'cleanup_reported', 'cleanup_verified'
            ) OR (
              monitor_pid IS NOT NULL AND monitor_pid > 0 AND monitor_identity != ''
              AND runc_client_pid IS NOT NULL AND runc_client_pid > 0
              AND runc_client_identity != ''
              AND wrapper_unit != '' AND wrapper_invocation_id != ''
              AND scope_unit != '' AND scope_invocation_id != '' AND cgroup_path != ''
            )
          ),
          CHECK (
            phase NOT IN (
              'running', 'stopping', 'exited', 'cleanup_reported', 'cleanup_verified'
            ) OR (init_pid IS NOT NULL AND init_pid > 0 AND init_identity != '')
          ),
          CHECK (phase != 'stopping' OR stop_reason != ''),
          CHECK (
            phase NOT IN ('exited', 'cleanup_reported', 'cleanup_verified')
            OR runc_exit_code IS NOT NULL
          ),
          CHECK (
            phase NOT IN ('exited', 'cleanup_reported', 'cleanup_verified')
            OR runc_exit_observed_by = 'runc_client_popen_wait'
          ),
          CHECK (
            phase NOT IN ('cleanup_reported', 'cleanup_verified')
            OR cleanup_receipt_json != '{}'
          )
        )
        """
    )
    # Re-running the migration repairs trigger definitions while schema v14 is
    # still unreleased. Dropping only these names keeps the migration idempotent.
    for trigger in (
        "sandbox_execution_insert_reserved",
        "sandbox_execution_identity_immutable",
        "sandbox_execution_evidence_immutable",
        "sandbox_execution_evidence_phase_guard",
        "sandbox_execution_phase_transition",
        "sandbox_execution_no_delete",
        "attempts_no_direct_worker_with_sandbox",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")

    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_sandbox_executions_phase "
        "ON sandbox_executions(phase, updated_at)"
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS sandbox_execution_insert_reserved
        BEFORE INSERT ON sandbox_executions
        WHEN NEW.phase != 'reserved'
          OR NEW.monitor_pid IS NOT NULL OR NEW.monitor_identity != ''
          OR NEW.runc_client_pid IS NOT NULL OR NEW.runc_client_identity != ''
          OR NEW.init_pid IS NOT NULL OR NEW.init_identity != ''
          OR NEW.wrapper_unit != '' OR NEW.wrapper_invocation_id != ''
          OR NEW.scope_unit != '' OR NEW.scope_invocation_id != '' OR NEW.cgroup_path != ''
          OR NEW.stop_reason != '' OR NEW.runc_exit_code IS NOT NULL
          OR NEW.runc_exit_observed_by != '' OR NEW.cleanup_receipt_json != '{}'
          OR NEW.failure_reason != ''
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_execution_must_start_reserved');
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS sandbox_execution_identity_immutable
        BEFORE UPDATE ON sandbox_executions
        WHEN OLD.attempt_id IS NOT NEW.attempt_id
          OR OLD.claim_token IS NOT NEW.claim_token
          OR OLD.execution_id IS NOT NEW.execution_id
          OR OLD.backend IS NOT NEW.backend
          OR OLD.container_id IS NOT NEW.container_id
          OR OLD.bundle_digest IS NOT NEW.bundle_digest
          OR OLD.rootfs_digest IS NOT NEW.rootfs_digest
          OR OLD.runtime_version IS NOT NEW.runtime_version
          OR OLD.oci_version IS NOT NEW.oci_version
          OR OLD.bundle_path IS NOT NEW.bundle_path
          OR OLD.state_path IS NOT NEW.state_path
          OR OLD.created_at IS NOT NEW.created_at
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_execution_identity_immutable');
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS sandbox_execution_evidence_immutable
        BEFORE UPDATE ON sandbox_executions
        WHEN (OLD.monitor_pid IS NOT NULL AND NEW.monitor_pid IS NOT OLD.monitor_pid)
          OR (OLD.monitor_identity != '' AND NEW.monitor_identity IS NOT OLD.monitor_identity)
          OR (OLD.runc_client_pid IS NOT NULL AND NEW.runc_client_pid IS NOT OLD.runc_client_pid)
          OR (OLD.runc_client_identity != '' AND NEW.runc_client_identity IS NOT OLD.runc_client_identity)
          OR (OLD.init_pid IS NOT NULL AND NEW.init_pid IS NOT OLD.init_pid)
          OR (OLD.init_identity != '' AND NEW.init_identity IS NOT OLD.init_identity)
          OR (OLD.wrapper_unit != '' AND NEW.wrapper_unit IS NOT OLD.wrapper_unit)
          OR (OLD.wrapper_invocation_id != '' AND NEW.wrapper_invocation_id IS NOT OLD.wrapper_invocation_id)
          OR (OLD.scope_unit != '' AND NEW.scope_unit IS NOT OLD.scope_unit)
          OR (OLD.scope_invocation_id != '' AND NEW.scope_invocation_id IS NOT OLD.scope_invocation_id)
          OR (OLD.cgroup_path != '' AND NEW.cgroup_path IS NOT OLD.cgroup_path)
          OR (OLD.stop_reason != '' AND NEW.stop_reason IS NOT OLD.stop_reason)
          OR (OLD.runc_exit_code IS NOT NULL AND NEW.runc_exit_code IS NOT OLD.runc_exit_code)
          OR (OLD.runc_exit_observed_by != '' AND NEW.runc_exit_observed_by IS NOT OLD.runc_exit_observed_by)
          OR (OLD.cleanup_receipt_json != '{}' AND NEW.cleanup_receipt_json IS NOT OLD.cleanup_receipt_json)
          OR (OLD.failure_reason != '' AND NEW.failure_reason IS NOT OLD.failure_reason)
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_execution_evidence_immutable');
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS sandbox_execution_evidence_phase_guard
        BEFORE UPDATE ON sandbox_executions
        WHEN OLD.phase = NEW.phase AND (
          OLD.monitor_pid IS NOT NEW.monitor_pid
          OR OLD.monitor_identity IS NOT NEW.monitor_identity
          OR OLD.runc_client_pid IS NOT NEW.runc_client_pid
          OR OLD.runc_client_identity IS NOT NEW.runc_client_identity
          OR OLD.init_pid IS NOT NEW.init_pid
          OR OLD.init_identity IS NOT NEW.init_identity
          OR OLD.wrapper_unit IS NOT NEW.wrapper_unit
          OR OLD.wrapper_invocation_id IS NOT NEW.wrapper_invocation_id
          OR OLD.scope_unit IS NOT NEW.scope_unit
          OR OLD.scope_invocation_id IS NOT NEW.scope_invocation_id
          OR OLD.cgroup_path IS NOT NEW.cgroup_path
          OR OLD.stop_reason IS NOT NEW.stop_reason
          OR OLD.runc_exit_code IS NOT NEW.runc_exit_code
          OR OLD.runc_exit_observed_by IS NOT NEW.runc_exit_observed_by
          OR OLD.cleanup_receipt_json IS NOT NEW.cleanup_receipt_json
          OR OLD.failure_reason IS NOT NEW.failure_reason
        )
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_execution_evidence_requires_phase_transition');
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS sandbox_execution_phase_transition
        BEFORE UPDATE OF phase ON sandbox_executions
        WHEN OLD.phase != NEW.phase AND NOT (
          (OLD.phase = 'reserved' AND NEW.phase IN ('launched', 'ambiguous'))
          OR (OLD.phase = 'launched' AND NEW.phase IN ('running', 'stopping', 'exited', 'ambiguous'))
          OR (OLD.phase = 'running' AND NEW.phase IN ('stopping', 'exited', 'ambiguous'))
          OR (OLD.phase = 'stopping' AND NEW.phase IN ('exited', 'ambiguous'))
          OR (OLD.phase = 'exited' AND NEW.phase IN ('cleanup_reported', 'ambiguous'))
          OR (OLD.phase = 'cleanup_reported' AND NEW.phase = 'ambiguous')
        )
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_execution_phase_transition_invalid');
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS sandbox_execution_no_delete
        BEFORE DELETE ON sandbox_executions
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_execution_journal_retained');
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS attempts_no_direct_worker_with_sandbox
        BEFORE UPDATE OF pid ON attempts
        WHEN NEW.pid IS NOT NULL
          AND EXISTS (
            SELECT 1 FROM sandbox_executions
            WHERE attempt_id = NEW.id
          )
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_execution_owns_attempt_slot');
        END
        """
    )


def _add_sandbox_workspace_binding(connection: sqlite3.Connection) -> None:
    """Persist the workspace inode and baseline manifest before OCI launch."""

    columns = {row["name"] for row in connection.execute("PRAGMA table_info(sandbox_executions)")}
    additions = (
        ("workspace_binding_version", "INTEGER NOT NULL DEFAULT 0"),
        ("baseline_root_path", "TEXT NOT NULL DEFAULT ''"),
        ("baseline_root_dev", "INTEGER"),
        ("baseline_root_ino", "INTEGER"),
        ("workspace_root_path", "TEXT NOT NULL DEFAULT ''"),
        ("workspace_root_dev", "INTEGER"),
        ("workspace_root_ino", "INTEGER"),
        ("baseline_manifest_json", "TEXT NOT NULL DEFAULT ''"),
        ("baseline_manifest_digest", "TEXT NOT NULL DEFAULT ''"),
    )
    for name, definition in additions:
        if name not in columns:
            connection.execute(f"ALTER TABLE sandbox_executions ADD COLUMN {name} {definition}")

    for trigger in (
        "sandbox_execution_workspace_binding_insert_guard",
        "sandbox_execution_workspace_binding_write_once",
        "sandbox_execution_launch_requires_workspace",
        "sandbox_execution_phase_transition",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")

    connection.execute(
        """
        CREATE TRIGGER sandbox_execution_workspace_binding_insert_guard
        BEFORE INSERT ON sandbox_executions
        WHEN NEW.workspace_binding_version != 0
          OR NEW.baseline_root_path != '' OR NEW.baseline_root_dev IS NOT NULL
          OR NEW.baseline_root_ino IS NOT NULL OR NEW.workspace_root_path != ''
          OR NEW.workspace_root_dev IS NOT NULL OR NEW.workspace_root_ino IS NOT NULL
          OR NEW.baseline_manifest_json != '' OR NEW.baseline_manifest_digest != ''
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_workspace_binding_must_be_recorded');
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER sandbox_execution_workspace_binding_write_once
        BEFORE UPDATE OF workspace_binding_version, baseline_root_path, baseline_root_dev,
          baseline_root_ino, workspace_root_path, workspace_root_dev, workspace_root_ino,
          baseline_manifest_json, baseline_manifest_digest ON sandbox_executions
        WHEN NOT (
          OLD.workspace_binding_version = 0
          AND NEW.workspace_binding_version = 1
          AND OLD.phase = 'reserved' AND NEW.phase = 'reserved'
          AND NEW.baseline_root_path != '' AND NEW.workspace_root_path != ''
          AND NEW.baseline_root_dev IS NOT NULL AND NEW.baseline_root_dev >= 0
          AND NEW.baseline_root_ino IS NOT NULL AND NEW.baseline_root_ino > 0
          AND NEW.workspace_root_dev IS NOT NULL AND NEW.workspace_root_dev >= 0
          AND NEW.workspace_root_ino IS NOT NULL AND NEW.workspace_root_ino > 0
          AND length(NEW.baseline_manifest_json) > 0
          AND length(NEW.baseline_manifest_digest) = 64
        )
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_workspace_binding_immutable');
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER sandbox_execution_launch_requires_workspace
        BEFORE UPDATE OF phase ON sandbox_executions
        WHEN OLD.phase = 'reserved' AND NEW.phase = 'launched'
          AND NEW.workspace_binding_version != 1
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_workspace_binding_required');
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER sandbox_execution_phase_transition
        BEFORE UPDATE OF phase ON sandbox_executions
        WHEN OLD.phase != NEW.phase AND NOT (
          (OLD.phase = 'reserved' AND NEW.phase = 'launched'
            AND NEW.workspace_binding_version = 1)
          OR (OLD.phase = 'reserved' AND NEW.phase = 'ambiguous')
          OR (OLD.phase = 'launched' AND NEW.phase IN ('running', 'stopping', 'exited', 'ambiguous'))
          OR (OLD.phase = 'running' AND NEW.phase IN ('stopping', 'exited', 'ambiguous'))
          OR (OLD.phase = 'stopping' AND NEW.phase IN ('exited', 'ambiguous'))
          OR (OLD.phase = 'exited' AND NEW.phase IN ('cleanup_reported', 'ambiguous'))
          OR (OLD.phase = 'cleanup_reported' AND NEW.phase = 'ambiguous')
        )
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_execution_phase_transition_invalid');
        END
        """
    )


def _add_sandbox_result_candidate_evidence(connection: sqlite3.Connection) -> None:
    """Persist a versioned candidate-result receipt without authorizing import."""

    columns = {row["name"] for row in connection.execute("PRAGMA table_info(sandbox_executions)")}
    additions = (
        (
            "result_candidate_version",
            "INTEGER NOT NULL DEFAULT 0 CHECK (result_candidate_version IN (0, 1))",
        ),
        ("result_candidate_json", "TEXT NOT NULL DEFAULT ''"),
        ("result_candidate_digest", "TEXT NOT NULL DEFAULT ''"),
    )
    for name, definition in additions:
        if name not in columns:
            connection.execute(f"ALTER TABLE sandbox_executions ADD COLUMN {name} {definition}")

    connection.execute("DROP TRIGGER IF EXISTS sandbox_result_candidate_insert_guard")
    connection.execute("DROP TRIGGER IF EXISTS sandbox_result_candidate_write_once")
    connection.execute(
        """
        CREATE TRIGGER sandbox_result_candidate_insert_guard
        BEFORE INSERT ON sandbox_executions
        WHEN NEW.result_candidate_version != 0
          OR NEW.result_candidate_json != '' OR NEW.result_candidate_digest != ''
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_result_candidate_must_be_host_captured');
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER sandbox_result_candidate_write_once
        BEFORE UPDATE OF result_candidate_version, result_candidate_json,
          result_candidate_digest ON sandbox_executions
        WHEN (
          OLD.result_candidate_version = 0 AND NOT (
            NEW.result_candidate_version = 1
            AND NEW.result_candidate_json != ''
            AND length(NEW.result_candidate_json) <= 65536
            AND length(NEW.result_candidate_digest) = 64
            AND OLD.phase = 'cleanup_reported' AND NEW.phase = 'cleanup_reported'
            AND NEW.runc_exit_code = 0
            AND NEW.runc_exit_observed_by = 'runc_client_popen_wait'
            AND NEW.workspace_binding_version = 1
            AND NEW.baseline_manifest_digest != ''
            AND NEW.workspace_root_path != ''
            AND NEW.workspace_root_dev IS NOT NULL
            AND NEW.workspace_root_ino IS NOT NULL
            AND NEW.cleanup_receipt_json != '{}'
            AND instr(NEW.result_candidate_json, '"authorization":"none"') > 0
            AND instr(NEW.result_candidate_json, '"status":"unverified"') > 0
          )
        ) OR (
          OLD.result_candidate_version != 0 AND (
            NEW.result_candidate_version IS NOT OLD.result_candidate_version
            OR NEW.result_candidate_json IS NOT OLD.result_candidate_json
            OR NEW.result_candidate_digest IS NOT OLD.result_candidate_digest
          )
        )
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_result_candidate_immutable');
        END
        """
    )


def _add_sandbox_runtime_content_pins(connection: sqlite3.Connection) -> None:
    """Bind each future OCI execution to its complete rootfs and runc bytes.

    Existing journal rows keep empty sentinels: their runtime content identities
    cannot be reconstructed after the fact, and a separate launch guard keeps
    such rows from advancing into execution.
    """

    columns = {row["name"] for row in connection.execute("PRAGMA table_info(sandbox_executions)")}
    additions = (
        ("rootfs_closure_digest", "TEXT NOT NULL DEFAULT ''"),
        ("runc_executable_digest", "TEXT NOT NULL DEFAULT ''"),
    )
    for name, definition in additions:
        if name not in columns:
            connection.execute(f"ALTER TABLE sandbox_executions ADD COLUMN {name} {definition}")

    connection.execute("DROP TRIGGER IF EXISTS sandbox_execution_insert_reserved")
    connection.execute(
        """
        CREATE TRIGGER sandbox_execution_insert_reserved
        BEFORE INSERT ON sandbox_executions
        WHEN NEW.phase != 'reserved'
          OR NEW.monitor_pid IS NOT NULL OR NEW.monitor_identity != ''
          OR NEW.runc_client_pid IS NOT NULL OR NEW.runc_client_identity != ''
          OR NEW.init_pid IS NOT NULL OR NEW.init_identity != ''
          OR NEW.wrapper_unit != '' OR NEW.wrapper_invocation_id != ''
          OR NEW.scope_unit != '' OR NEW.scope_invocation_id != '' OR NEW.cgroup_path != ''
          OR NEW.stop_reason != '' OR NEW.runc_exit_code IS NOT NULL
          OR NEW.runc_exit_observed_by != '' OR NEW.cleanup_receipt_json != '{}'
          OR NEW.failure_reason != ''
          OR length(NEW.bundle_digest) != 64 OR NEW.bundle_digest GLOB '*[^0-9a-f]*'
          OR length(NEW.rootfs_digest) != 64 OR NEW.rootfs_digest GLOB '*[^0-9a-f]*'
          OR length(NEW.rootfs_closure_digest) != 64
          OR NEW.rootfs_closure_digest GLOB '*[^0-9a-f]*'
          OR length(NEW.runc_executable_digest) != 64
          OR NEW.runc_executable_digest GLOB '*[^0-9a-f]*'
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_execution_must_start_reserved');
        END
        """
    )

    connection.execute("DROP TRIGGER IF EXISTS sandbox_execution_identity_immutable")
    connection.execute(
        """
        CREATE TRIGGER sandbox_execution_identity_immutable
        BEFORE UPDATE ON sandbox_executions
        WHEN OLD.attempt_id IS NOT NEW.attempt_id
          OR OLD.claim_token IS NOT NEW.claim_token
          OR OLD.execution_id IS NOT NEW.execution_id
          OR OLD.backend IS NOT NEW.backend
          OR OLD.container_id IS NOT NEW.container_id
          OR OLD.bundle_digest IS NOT NEW.bundle_digest
          OR OLD.rootfs_digest IS NOT NEW.rootfs_digest
          OR OLD.rootfs_closure_digest IS NOT NEW.rootfs_closure_digest
          OR OLD.runc_executable_digest IS NOT NEW.runc_executable_digest
          OR OLD.runtime_version IS NOT NEW.runtime_version
          OR OLD.oci_version IS NOT NEW.oci_version
          OR OLD.bundle_path IS NOT NEW.bundle_path
          OR OLD.state_path IS NOT NEW.state_path
          OR OLD.created_at IS NOT NEW.created_at
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_execution_identity_immutable');
        END
        """
    )

    connection.execute("DROP TRIGGER IF EXISTS sandbox_execution_launch_requires_content_pins")
    connection.execute(
        """
        CREATE TRIGGER sandbox_execution_launch_requires_content_pins
        BEFORE UPDATE OF phase ON sandbox_executions
        WHEN OLD.phase = 'reserved' AND NEW.phase = 'launched'
          AND (
            length(NEW.rootfs_closure_digest) != 64
            OR NEW.rootfs_closure_digest GLOB '*[^0-9a-f]*'
            OR length(NEW.runc_executable_digest) != 64
            OR NEW.runc_executable_digest GLOB '*[^0-9a-f]*'
          )
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_execution_content_pins_required');
        END
        """
    )


def _add_sandbox_execution_private_path_binding(connection: sqlite3.Connection) -> None:
    """Bind private bundle/state directory inode identities before any OCI launch."""

    columns = {row["name"] for row in connection.execute("PRAGMA table_info(sandbox_executions)")}
    additions = (
        (
            "private_path_binding_version",
            "INTEGER NOT NULL DEFAULT 0 CHECK (private_path_binding_version IN (0, 1))",
        ),
        ("execution_root_dev", "INTEGER"),
        ("execution_root_ino", "INTEGER"),
        ("bundle_root_dev", "INTEGER"),
        ("bundle_root_ino", "INTEGER"),
        ("state_root_dev", "INTEGER"),
        ("state_root_ino", "INTEGER"),
    )
    for name, definition in additions:
        if name not in columns:
            connection.execute(f"ALTER TABLE sandbox_executions ADD COLUMN {name} {definition}")

    connection.execute("DROP TRIGGER IF EXISTS sandbox_private_path_binding_insert_guard")
    connection.execute(
        """
        CREATE TRIGGER sandbox_private_path_binding_insert_guard
        BEFORE INSERT ON sandbox_executions
        WHEN NEW.private_path_binding_version != 0
          OR NEW.execution_root_dev IS NOT NULL OR NEW.execution_root_ino IS NOT NULL
          OR NEW.bundle_root_dev IS NOT NULL OR NEW.bundle_root_ino IS NOT NULL
          OR NEW.state_root_dev IS NOT NULL OR NEW.state_root_ino IS NOT NULL
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_private_path_binding_must_be_recorded');
        END
        """
    )
    connection.execute("DROP TRIGGER IF EXISTS sandbox_private_path_binding_write_once")
    connection.execute(
        """
        CREATE TRIGGER sandbox_private_path_binding_write_once
        BEFORE UPDATE OF private_path_binding_version, execution_root_dev,
          execution_root_ino, bundle_root_dev, bundle_root_ino, state_root_dev,
          state_root_ino ON sandbox_executions
        WHEN NOT (
          OLD.private_path_binding_version = 0
          AND NEW.private_path_binding_version = 1
          AND OLD.workspace_binding_version = 0 AND NEW.workspace_binding_version = 1
          AND OLD.phase = 'reserved' AND NEW.phase = 'reserved'
          AND NEW.execution_root_dev IS NOT NULL AND NEW.execution_root_dev >= 0
          AND NEW.execution_root_ino IS NOT NULL AND NEW.execution_root_ino > 0
          AND NEW.bundle_root_dev IS NOT NULL AND NEW.bundle_root_dev >= 0
          AND NEW.bundle_root_ino IS NOT NULL AND NEW.bundle_root_ino > 0
          AND NEW.state_root_dev IS NOT NULL AND NEW.state_root_dev >= 0
          AND NEW.state_root_ino IS NOT NULL AND NEW.state_root_ino > 0
        )
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_private_path_binding_immutable');
        END
        """
    )
    connection.execute("DROP TRIGGER IF EXISTS sandbox_execution_launch_requires_private_paths")
    connection.execute(
        """
        CREATE TRIGGER sandbox_execution_launch_requires_private_paths
        BEFORE UPDATE OF phase ON sandbox_executions
        WHEN OLD.phase = 'reserved' AND NEW.phase = 'launched'
          AND (
            NEW.private_path_binding_version != 1
            OR NEW.execution_root_dev IS NULL OR NEW.execution_root_ino IS NULL
            OR NEW.bundle_root_dev IS NULL OR NEW.bundle_root_ino IS NULL
            OR NEW.state_root_dev IS NULL OR NEW.state_root_ino IS NULL
          )
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_execution_private_paths_required');
        END
        """
    )
    connection.execute("DROP TRIGGER IF EXISTS sandbox_result_candidate_requires_private_paths")
    connection.execute(
        """
        CREATE TRIGGER sandbox_result_candidate_requires_private_paths
        BEFORE UPDATE OF result_candidate_version, result_candidate_json,
          result_candidate_digest ON sandbox_executions
        WHEN NEW.result_candidate_version = 1
          AND NEW.private_path_binding_version != 1
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_result_private_paths_required');
        END
        """
    )


def _add_sandbox_kernel_wait_evidence(connection: sqlite3.Connection) -> None:
    """Separate exact kernel wait evidence from the legacy schema marker.

    Prior schema versions constrain ``runc_exit_observed_by`` to the historical
    ``runc_client_popen_wait`` value. SQLite cannot update that CHECK in place,
    so retain that field as a compatibility marker and store the exact
    waitpid-derived source in a new, immutable column. Existing rows are not
    backfilled: their original evidence cannot be upgraded retroactively.
    """

    columns = {row["name"] for row in connection.execute("PRAGMA table_info(sandbox_executions)")}
    if not columns:
        raise sqlite3.DatabaseError(
            "sandbox_executions must exist before kernel-wait evidence migration"
        )
    if "runc_exit_evidence_source" not in columns:
        connection.execute(
            "ALTER TABLE sandbox_executions ADD COLUMN runc_exit_evidence_source "
            "TEXT NOT NULL DEFAULT '' CHECK (runc_exit_evidence_source IN "
            "('', 'runc_client_kernel_waitpid'))"
        )

    connection.execute("DROP TRIGGER IF EXISTS sandbox_execution_insert_reserved")
    connection.execute(
        """
        CREATE TRIGGER sandbox_execution_insert_reserved
        BEFORE INSERT ON sandbox_executions
        WHEN NEW.phase != 'reserved'
          OR NEW.monitor_pid IS NOT NULL OR NEW.monitor_identity != ''
          OR NEW.runc_client_pid IS NOT NULL OR NEW.runc_client_identity != ''
          OR NEW.init_pid IS NOT NULL OR NEW.init_identity != ''
          OR NEW.wrapper_unit != '' OR NEW.wrapper_invocation_id != ''
          OR NEW.scope_unit != '' OR NEW.scope_invocation_id != '' OR NEW.cgroup_path != ''
          OR NEW.stop_reason != '' OR NEW.runc_exit_code IS NOT NULL
          OR NEW.runc_exit_observed_by != '' OR NEW.runc_exit_evidence_source != ''
          OR NEW.cleanup_receipt_json != '{}' OR NEW.failure_reason != ''
          OR length(NEW.bundle_digest) != 64 OR NEW.bundle_digest GLOB '*[^0-9a-f]*'
          OR length(NEW.rootfs_digest) != 64 OR NEW.rootfs_digest GLOB '*[^0-9a-f]*'
          OR length(NEW.rootfs_closure_digest) != 64
          OR NEW.rootfs_closure_digest GLOB '*[^0-9a-f]*'
          OR length(NEW.runc_executable_digest) != 64
          OR NEW.runc_executable_digest GLOB '*[^0-9a-f]*'
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_execution_must_start_reserved');
        END
        """
    )

    connection.execute("DROP TRIGGER IF EXISTS sandbox_execution_evidence_immutable")
    connection.execute(
        """
        CREATE TRIGGER sandbox_execution_evidence_immutable
        BEFORE UPDATE ON sandbox_executions
        WHEN (OLD.monitor_pid IS NOT NULL AND NEW.monitor_pid IS NOT OLD.monitor_pid)
          OR (OLD.monitor_identity != '' AND NEW.monitor_identity IS NOT OLD.monitor_identity)
          OR (OLD.runc_client_pid IS NOT NULL AND NEW.runc_client_pid IS NOT OLD.runc_client_pid)
          OR (OLD.runc_client_identity != '' AND NEW.runc_client_identity IS NOT OLD.runc_client_identity)
          OR (OLD.init_pid IS NOT NULL AND NEW.init_pid IS NOT OLD.init_pid)
          OR (OLD.init_identity != '' AND NEW.init_identity IS NOT OLD.init_identity)
          OR (OLD.wrapper_unit != '' AND NEW.wrapper_unit IS NOT OLD.wrapper_unit)
          OR (OLD.wrapper_invocation_id != '' AND NEW.wrapper_invocation_id IS NOT OLD.wrapper_invocation_id)
          OR (OLD.scope_unit != '' AND NEW.scope_unit IS NOT OLD.scope_unit)
          OR (OLD.scope_invocation_id != '' AND NEW.scope_invocation_id IS NOT OLD.scope_invocation_id)
          OR (OLD.cgroup_path != '' AND NEW.cgroup_path IS NOT OLD.cgroup_path)
          OR (OLD.stop_reason != '' AND NEW.stop_reason IS NOT OLD.stop_reason)
          OR (OLD.runc_exit_code IS NOT NULL AND NEW.runc_exit_code IS NOT OLD.runc_exit_code)
          OR (OLD.runc_exit_observed_by != '' AND NEW.runc_exit_observed_by IS NOT OLD.runc_exit_observed_by)
          OR (OLD.runc_exit_evidence_source != '' AND NEW.runc_exit_evidence_source IS NOT OLD.runc_exit_evidence_source)
          OR (OLD.cleanup_receipt_json != '{}' AND NEW.cleanup_receipt_json IS NOT OLD.cleanup_receipt_json)
          OR (OLD.failure_reason != '' AND NEW.failure_reason IS NOT OLD.failure_reason)
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_execution_evidence_immutable');
        END
        """
    )

    connection.execute("DROP TRIGGER IF EXISTS sandbox_execution_evidence_phase_guard")
    connection.execute(
        """
        CREATE TRIGGER sandbox_execution_evidence_phase_guard
        BEFORE UPDATE ON sandbox_executions
        WHEN OLD.phase = NEW.phase AND (
          OLD.monitor_pid IS NOT NEW.monitor_pid
          OR OLD.monitor_identity IS NOT NEW.monitor_identity
          OR OLD.runc_client_pid IS NOT NEW.runc_client_pid
          OR OLD.runc_client_identity IS NOT NEW.runc_client_identity
          OR OLD.init_pid IS NOT NEW.init_pid
          OR OLD.init_identity IS NOT NEW.init_identity
          OR OLD.wrapper_unit IS NOT NEW.wrapper_unit
          OR OLD.wrapper_invocation_id IS NOT NEW.wrapper_invocation_id
          OR OLD.scope_unit IS NOT NEW.scope_unit
          OR OLD.scope_invocation_id IS NOT NEW.scope_invocation_id
          OR OLD.cgroup_path IS NOT NEW.cgroup_path
          OR OLD.stop_reason IS NOT NEW.stop_reason
          OR OLD.runc_exit_code IS NOT NEW.runc_exit_code
          OR OLD.runc_exit_observed_by IS NOT NEW.runc_exit_observed_by
          OR OLD.runc_exit_evidence_source IS NOT NEW.runc_exit_evidence_source
          OR OLD.cleanup_receipt_json IS NOT NEW.cleanup_receipt_json
          OR OLD.failure_reason IS NOT NEW.failure_reason
        )
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_execution_evidence_requires_phase_transition');
        END
        """
    )

    connection.execute("DROP TRIGGER IF EXISTS sandbox_execution_exit_requires_kernel_waitpid")
    connection.execute(
        """
        CREATE TRIGGER sandbox_execution_exit_requires_kernel_waitpid
        BEFORE UPDATE OF phase ON sandbox_executions
        WHEN OLD.phase IN ('launched', 'running', 'stopping')
          AND NEW.phase = 'exited'
          AND (
            NEW.runc_exit_observed_by != 'runc_client_popen_wait'
            OR NEW.runc_exit_evidence_source != 'runc_client_kernel_waitpid'
          )
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_execution_kernel_wait_evidence_required');
        END
        """
    )

    connection.execute("DROP TRIGGER IF EXISTS sandbox_execution_exit_evidence_write_guard")
    connection.execute(
        """
        CREATE TRIGGER sandbox_execution_exit_evidence_write_guard
        BEFORE UPDATE OF runc_exit_code, runc_exit_observed_by,
          runc_exit_evidence_source ON sandbox_executions
        WHEN (
          OLD.runc_exit_code IS NOT NEW.runc_exit_code
          OR OLD.runc_exit_observed_by IS NOT NEW.runc_exit_observed_by
          OR OLD.runc_exit_evidence_source IS NOT NEW.runc_exit_evidence_source
        ) AND NOT (
          OLD.phase IN ('launched', 'running', 'stopping')
          AND NEW.phase = 'exited'
          AND OLD.runc_exit_code IS NULL
          AND OLD.runc_exit_observed_by = ''
          AND OLD.runc_exit_evidence_source = ''
          AND NEW.runc_exit_code IS NOT NULL
          AND NEW.runc_exit_observed_by = 'runc_client_popen_wait'
          AND NEW.runc_exit_evidence_source = 'runc_client_kernel_waitpid'
        )
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_execution_exit_evidence_write_requires_exit');
        END
        """
    )

    connection.execute("DROP TRIGGER IF EXISTS sandbox_result_candidate_write_once")
    connection.execute(
        """
        CREATE TRIGGER sandbox_result_candidate_write_once
        BEFORE UPDATE OF result_candidate_version, result_candidate_json,
          result_candidate_digest ON sandbox_executions
        WHEN (
          OLD.result_candidate_version = 0 AND NOT (
            NEW.result_candidate_version = 1
            AND NEW.result_candidate_json != ''
            AND length(NEW.result_candidate_json) <= 65536
            AND length(NEW.result_candidate_digest) = 64
            AND OLD.phase = 'cleanup_reported' AND NEW.phase = 'cleanup_reported'
            AND NEW.runc_exit_code = 0
            AND NEW.runc_exit_evidence_source = 'runc_client_kernel_waitpid'
            AND NEW.workspace_binding_version = 1
            AND NEW.baseline_manifest_digest != ''
            AND NEW.workspace_root_path != ''
            AND NEW.workspace_root_dev IS NOT NULL
            AND NEW.workspace_root_ino IS NOT NULL
            AND NEW.cleanup_receipt_json != '{}'
            AND instr(NEW.result_candidate_json, '"authorization":"none"') > 0
            AND instr(NEW.result_candidate_json, '"status":"unverified"') > 0
          )
        ) OR (
          OLD.result_candidate_version != 0 AND (
            NEW.result_candidate_version IS NOT OLD.result_candidate_version
            OR NEW.result_candidate_json IS NOT OLD.result_candidate_json
            OR NEW.result_candidate_digest IS NOT OLD.result_candidate_digest
          )
        )
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_result_candidate_immutable');
        END
        """
    )


def _add_sandbox_exit_receipt_guard(connection: sqlite3.Connection) -> None:
    """Require the receipt-validating application path for new exit transitions."""

    connection.execute("DROP TRIGGER IF EXISTS sandbox_execution_exit_receipt_guard")
    connection.execute(
        """
        CREATE TRIGGER sandbox_execution_exit_receipt_guard
        BEFORE UPDATE OF phase ON sandbox_executions
        WHEN OLD.phase IN ('launched', 'running', 'stopping')
          AND NEW.phase = 'exited'
          AND acp_sandbox_exit_receipt_authorized(
            OLD.attempt_id, OLD.claim_token, OLD.execution_id,
            OLD.runc_client_pid, OLD.runc_client_identity, NEW.runc_exit_code
          ) != 1
        BEGIN
          SELECT RAISE(ABORT, 'sandbox_execution_wait_receipt_required');
        END
        """
    )


MIGRATIONS: tuple[Migration, ...] = (
    (2, _add_declared_resources),
    (3, _add_attempt_progress_timestamps),
    (4, _add_base_checkout_snapshot),
    (5, _require_base_checkout_snapshot),
    (6, _fence_legacy_attempt_inserts),
    (7, _add_attempt_worktree_root),
    (8, _add_qc_runs_latest_lookup_index),
    (9, _add_read_dependency_snapshots),
    (10, _add_qc_acceptance_coverage),
    (11, _add_submission_result_manifest),
    (12, _add_result_import_journal),
    (13, _add_result_import_object_staging),
    (14, _add_sandbox_execution_journal),
    (15, _add_sandbox_workspace_binding),
    (16, _add_sandbox_result_candidate_evidence),
    (17, _add_sandbox_runtime_content_pins),
    (18, _add_sandbox_execution_private_path_binding),
    (19, _add_result_import_source_discriminator),
    (20, _add_sandbox_kernel_wait_evidence),
    (21, _add_sandbox_exit_receipt_guard),
)


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
    StoreMixin,
    ConfigMixin,
    IdentityMixin,
    ViewsMixin,
    ProcessMixin,
    WorkersMixin,
    SandboxExecutionJournalMixin,
    RuntimeMixin,
    QcMixin,
    ClaimsMixin,
    ReaperMixin,
    IntegrationMixin,
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
        (self.state_dir / "result-import-staging").mkdir(mode=0o700, exist_ok=True)
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
        arguments = ("rev-parse", "--path-format=absolute", "--git-common-dir")
        if self.read_only:
            common_value = (
                self._git_readonly_bytes(*arguments)
                .decode("utf-8", errors="surrogateescape")
                .rstrip("\r\n")
            )
        else:
            common_value = self._git_text(*arguments)
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

    @staticmethod
    def resources_overlap(
        left: str,
        right: str,
        *,
        left_declared: str | None = None,
        right_declared: str | None = None,
    ) -> bool:
        # Exact canonical keys always conflict. `resource_leases` has one global
        # primary-key namespace, so a pre-v3 path/logical alias with the same folded
        # key must be serialized rather than allowed to overwrite its fencing row.
        # This is a conservative legacy-only exact conflict; distinct keys never
        # inherit logical ancestry across path/logical types.
        if left == right:
            return True

        def is_logical(resource: str, declared: str | None) -> bool:
            if declared is None:
                return resource.startswith("logical:")
            raw = unicodedata.normalize("NFC", declared.strip().replace("\\", "/"))
            return raw.startswith("logical:")

        left_is_logical = is_logical(left, left_declared)
        right_is_logical = is_logical(right, right_declared)
        if left_is_logical or right_is_logical:
            if not left_is_logical or not right_is_logical:
                return False
            left_scope = left.removeprefix("logical:")
            right_scope = right.removeprefix("logical:")
            return (
                left_scope == right_scope
                or left_scope.startswith(right_scope + "/")
                or right_scope.startswith(left_scope + "/")
            )
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
        persist_evidence: bool = True,
        read_only: bool = False,
    ) -> list[PhaseEvidence]:
        """Run *phase* for every configured driver.

        Drivers execute with the runtime directory as cwd — never the candidate
        worktree — and through ``run_trusted``, which re-validates argv[0]
        immediately before exec.
        """

        if not persist_evidence and not read_only:
            raise SupervisorError(
                "runtime_probe_mode_invalid",
                "non-persisted driver probes must use the read-only path",
            )
        if read_only and (
            phase != "verify"
            or persist_evidence
            or restart_token is not None
            or restart_guard_fd is not None
            or only_drivers is None
        ):
            raise SupervisorError(
                "runtime_probe_mode_invalid",
                "read-only driver probes may only verify without persistence",
            )

        pin = (
            self._verify_attempt_trust_read_only(attempt_id)
            if read_only
            else self._verify_attempt_trust(attempt_id)
        )
        stored_rows = self._stored_driver_rows(attempt_id)
        stored_by_name = {row["driver"]: row for row in stored_rows}
        if stored_rows:
            try:
                definitions = tuple(
                    self._driver_definition_from_json(row["definition_json"]) for row in stored_rows
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                if not read_only:
                    self._quarantine_driver_attempt(attempt_id, "runtime_driver_definition_missing")
                raise SupervisorError(
                    "runtime_driver_definition_missing",
                    "stored driver definition is unavailable",
                ) from error
        else:
            definitions = self._driver_definitions_for_pin(pin)
        if only_drivers is not None:
            definitions = tuple(
                definition for definition in definitions if definition.name in only_drivers
            )
        if read_only and any(definition.kind != "namespace_runtime" for definition in definitions):
            raise SupervisorError(
                "runtime_probe_mode_invalid",
                "read-only resource sampling only supports namespace runtime drivers",
            )
        if not definitions:
            return []
        secret = self._driver_secret_read_only() if read_only else self._driver_secret()
        registry = CredentialRegistry(self.config.credentials, self.root, secret)
        handles: dict[str, CredentialHandle] = {}
        handle_errors: dict[str, DriverError] = {}
        for definition in definitions:
            credential_name = definition.option("credential")
            if not credential_name:
                continue
            if read_only and phase == "verify" and definition.kind == "namespace_runtime":
                # A cgroup usage probe only asks systemd for its owned unit's
                # accounting properties; it must never materialize payload
                # credentials merely to inspect process/resource counters.
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
        prior_driver_states: dict[str, str] = {}
        prior_driver_evidence: dict[str, dict[str, Any]] = {}
        for name, row in stored_by_name.items():
            prior_driver_states[name] = str(row["state"])
            try:
                prior = json.loads(row["evidence_json"])
            except (TypeError, json.JSONDecodeError):
                continue
            if isinstance(prior, dict):
                prior.pop("ownership_token", None)
                prior_driver_evidence[name] = prior
        context = self._driver_context(
            attempt_id,
            environment,
            registry=registry,
            handles=handles,
            phase=phase,
            prior_driver_states=prior_driver_states,
            prior_driver_evidence=prior_driver_evidence,
            read_only=read_only,
        )
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
            if read_only:
                execution_options["create_cwd"] = False
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
        if persist_evidence:
            self._record_driver_evidence(
                attempt_id,
                phase,
                evidence,
                definitions_by_name,
                environment=environment,
                restart_token=restart_token,
            )
        return evidence

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

    def _run_critic(
        self,
        command: str,
        cwd: Path,
        extra_env: dict[str, str],
        trust_pin: dict[str, Any] | None = None,
        pass_fds: Sequence[int] = (),
        review_packet_fd: int | None = None,
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
                    pass_fds=(review_packet_fd,) if review_packet_fd is not None else (),
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
            pass_fds=(review_packet_fd,) if review_packet_fd is not None else (),
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
