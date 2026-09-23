"""The control database's table definitions, its column upgrades, and the case probe.

Moved verbatim out of `git_supervisor` (board #1630). This module deliberately holds only
what has NO dependency on the supervisor: the DDL, the idempotent ADD COLUMN pass, and the
filesystem probe. It imports nothing from `git_supervisor`, so there is no cycle and no
need to route anything back through it.

What stayed behind, on purpose: SCHEMA_VERSION, MIGRATIONS, stored_schema_version and
assert_schema_not_newer. Those are the BINARY's version policy rather than the database's
shape, they read `git_supervisor.SCHEMA_VERSION` as a module global, and tests monkeypatch
that global to inject upgrade ledgers. Moving them would have silently broken those patches
— the patched name and the read name would no longer be the same binding — so the version
policy moves with the schema-version row, not with this one.
"""

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

META_CASE_SENSITIVE = "path_case_sensitive"
"""`meta` key holding whether this repository's filesystem distinguishes `X` from `x`.

Written once, from a measurement, the first time the database is opened for writing.
Absent means "not measured yet", which reads as case-INSENSITIVE — the behaviour that
was there before the key existed, so an old database keeps matching the way it did
until a write command probes it.
"""


def probe_case_sensitive_paths(directory: Path) -> bool:
    """Does this filesystem keep `X` and `x` apart? Measured, never guessed.

    `sys.platform` is the wrong oracle in both directions: a case-sensitive APFS volume
    on macOS and a case-insensitive volume on Linux both exist, and what matters is the
    volume ACP's own state directory sits on, not the kernel's usual habit.

    The probe writes one uniquely named file and asks whether the lowercased name finds
    it. A random token in the name keeps a pre-existing file from answering for us. On
    an unwritable directory the answer is "insensitive", which is the conservative one:
    it keeps folded matching, which allows too much for the guard but never rewrites
    lease identity on a filesystem we could not measure.
    """

    token = uuid.uuid4().hex
    upper = directory / f".acpCaseProbe{token}"
    try:
        upper.write_text("", encoding="utf-8")
    except OSError:
        return False
    try:
        return not (directory / f".acpcaseprobe{token}").exists()
    finally:
        upper.unlink(missing_ok=True)


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    """Column names of `table`, empty when the table does not exist yet."""

    return {row["name"] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}


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
  declared_resources_json TEXT NOT NULL DEFAULT '{}',
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


def migrate(connection: sqlite3.Connection) -> None:
    """Add columns introduced after a database was first created.

    CREATE TABLE IF NOT EXISTS silently leaves an older table alone, so new
    columns have to be added explicitly. Each step is idempotent.
    """
    columns = _columns(connection, "tasks")
    for column in ("produces_json", "consumes_json"):
        if column not in columns:
            connection.execute(f"ALTER TABLE tasks ADD COLUMN {column} TEXT NOT NULL DEFAULT '[]'")
    if "cleanup_target_status" not in columns:
        connection.execute(
            "ALTER TABLE tasks ADD COLUMN cleanup_target_status TEXT NOT NULL DEFAULT ''"
        )
    if "cleanup_error" not in columns:
        connection.execute("ALTER TABLE tasks ADD COLUMN cleanup_error TEXT NOT NULL DEFAULT ''")
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
