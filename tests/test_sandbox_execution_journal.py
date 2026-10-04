from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from support import init_repo, make_task

from agent_control_plane.git_supervisor import (
    CLEANUP_FENCE_EPOCH,
    MIGRATIONS,
    SCHEMA_VERSION,
    GitSupervisor,
    SupervisorError,
)
from agent_control_plane.supervisor import claims as claims_module
from agent_control_plane.supervisor import sandbox_execution_journal as journal_module
from agent_control_plane.supervisor.common import canonical_json
from agent_control_plane.supervisor.sandbox_workspace import (
    ManifestEntry,
    _make_manifest,
    _tree_manifest_from_json,
    collect_changes,
    copy_snapshot,
    read_snapshot_files,
)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return init_repo(tmp_path)


def claimed(supervisor: GitSupervisor) -> dict:
    task = make_task(supervisor, "alpha.txt", title="sandbox journal test")
    return supervisor.claim(task["id"], "sandbox-worker")


def reserve(supervisor: GitSupervisor, attempt: dict) -> dict:
    row = supervisor._sandbox_execution_reserve(
        attempt["id"],
        attempt["claim_token"],
        "a" * 64,
        rootfs_digest="b" * 64,
        runtime_version="runc 1.3.5",
        oci_version="1.2.1",
    )
    execution_root = Path(row["bundle_path"]).parent
    execution_root.mkdir(mode=0o700, parents=True)
    baseline = copy_snapshot(attempt["worktree"], execution_root / "baseline")
    workspace = copy_snapshot(baseline.root, execution_root / "workspace")
    return supervisor._sandbox_execution_bind_workspace(
        attempt["id"], attempt["claim_token"], baseline, workspace
    )


def record_launch(supervisor: GitSupervisor, attempt: dict) -> dict:
    return supervisor._sandbox_execution_record_launch(
        attempt["id"],
        attempt["claim_token"],
        monitor_pid=101,
        monitor_identity="monitor-start-101",
        runc_client_pid=202,
        runc_client_identity="runc-start-202",
        wrapper_unit="acp-worker.service",
        wrapper_invocation_id="1" * 32,
        scope_unit="acp-container.scope",
        scope_invocation_id="2" * 32,
        cgroup_path=("/user.slice/user-1000.slice/user@1000.service/app.slice/acp-container.scope"),
    )


def cleanup_receipt(supervisor: GitSupervisor, attempt_id: str) -> dict:
    with supervisor.connect() as connection:
        row = connection.execute(
            "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
        ).fetchone()
    assert row is not None
    return supervisor._sandbox_cleanup_receipt(row)


def result_fixture(attempt: dict, tmp_path: Path):
    baseline = copy_snapshot(attempt["worktree"], tmp_path / "baseline")
    output = copy_snapshot(attempt["worktree"], tmp_path / "worker-output").root
    (output / "alpha.txt").write_text("sandbox result\n", encoding="utf-8")
    change_set = collect_changes(
        baseline.manifest,
        output,
        write_set_rules=[("alpha.txt", True, False)],
    )
    return baseline, change_set


def test_schema_v16_requires_durable_workspace_binding_before_launch(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)

    assert SCHEMA_VERSION == 16
    assert row["phase"] == "reserved"
    assert row["workspace_binding_version"] == 1
    assert row["baseline_manifest_digest"]
    assert row["baseline_root_path"].endswith("/baseline")
    assert row["workspace_root_path"].endswith("/workspace")
    assert row["claim_token"] == attempt["claim_token"]
    assert row["backend"] == "oci-runc"
    assert row["runtime_version"] == "runc 1.3.5"
    assert row["oci_version"] == "1.2.1"
    assert row["rootfs_digest"] == "b" * 64
    assert row["result_candidate_version"] == 0
    assert row["bundle_path"].startswith(str((repo / ".acp" / "sandbox-executions").resolve()))
    assert row["state_path"].endswith("/state")

    with supervisor.connect() as connection:
        migration = dict(MIGRATIONS)[15]
        migration(connection)
        migration(connection)
        result_migration = dict(MIGRATIONS)[16]
        result_migration(connection)
        result_migration(connection)
        with pytest.raises(sqlite3.IntegrityError, match="result_candidate_immutable"):
            connection.execute(
                "UPDATE sandbox_executions SET result_candidate_version = 1, "
                "result_candidate_json = '{}', result_candidate_digest = ? WHERE attempt_id = ?",
                ("c" * 64, attempt["id"]),
            )
        with pytest.raises(sqlite3.IntegrityError, match="phase_transition_invalid"):
            connection.execute(
                "UPDATE sandbox_executions SET phase = 'cleanup_verified' WHERE attempt_id = ?",
                (attempt["id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="must_start_reserved"):
            connection.execute(
                """
                INSERT INTO sandbox_executions
                  (attempt_id, claim_token, execution_id, backend, container_id,
                   bundle_digest, rootfs_digest, runtime_version, oci_version,
                   bundle_path, state_path, phase, created_at, updated_at)
                SELECT attempt_id, claim_token, 'direct-insert', backend, 'direct-container',
                       bundle_digest, rootfs_digest, runtime_version, oci_version,
                       bundle_path, state_path, 'cleanup_verified', created_at, updated_at
                FROM sandbox_executions WHERE attempt_id = ?
                """,
                (attempt["id"],),
            )
    with supervisor.connect() as connection:
        with pytest.raises(sqlite3.IntegrityError, match="identity_immutable"):
            connection.execute(
                "UPDATE sandbox_executions SET claim_token = claim_token + 1 WHERE attempt_id = ?",
                (attempt["id"],),
            )
    with supervisor.connect() as connection:
        with pytest.raises(sqlite3.IntegrityError, match="journal_retained"):
            connection.execute(
                "DELETE FROM sandbox_executions WHERE attempt_id = ?", (attempt["id"],)
            )
    assert supervisor.verify_event_chain()["ok"] is True


def test_v15_to_v16_migration_adds_non_authorizing_candidate_fields() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("CREATE TABLE attempts (id TEXT PRIMARY KEY, pid INTEGER)")
        connection.execute("INSERT INTO attempts (id, pid) VALUES ('attempt-1', NULL)")
        migrations = dict(MIGRATIONS)
        migrations[14](connection)
        migrations[15](connection)

        v15_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(sandbox_executions)")
        }
        candidate_columns = {
            "result_candidate_version",
            "result_candidate_json",
            "result_candidate_digest",
        }
        assert candidate_columns.isdisjoint(v15_columns)
        connection.execute(
            """
            INSERT INTO sandbox_executions
              (attempt_id, claim_token, execution_id, backend, container_id,
               bundle_digest, rootfs_digest, runtime_version, oci_version,
               bundle_path, state_path, phase, created_at, updated_at)
            VALUES (?, 1, 'execution-1', 'oci-runc', 'container-1', ?, ?,
                    'runc 1.3.5', '1.2.1', '/bundle', '/state', 'reserved', 'now', 'now')
            """,
            ("attempt-1", "a" * 64, "b" * 64),
        )

        migrations[16](connection)
        migrations[16](connection)
        v16_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(sandbox_executions)")
        }
        assert candidate_columns.issubset(v16_columns)
        migrated = connection.execute(
            "SELECT result_candidate_version, result_candidate_json, result_candidate_digest "
            "FROM sandbox_executions WHERE attempt_id = 'attempt-1'"
        ).fetchone()
        assert migrated["result_candidate_version"] == 0
        assert migrated["result_candidate_json"] == ""
        assert migrated["result_candidate_digest"] == ""
    finally:
        connection.close()


def test_sandbox_launch_cannot_bypass_workspace_binding(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = supervisor._sandbox_execution_reserve(
        attempt["id"],
        attempt["claim_token"],
        "a" * 64,
        rootfs_digest="b" * 64,
        runtime_version="runc 1.3.5",
        oci_version="1.2.1",
    )
    assert row["workspace_binding_version"] == 0

    with pytest.raises(SupervisorError) as error:
        record_launch(supervisor, attempt)
    assert error.value.code == "sandbox_workspace_unbound"

    with (
        supervisor.connect() as connection,
        pytest.raises(
            sqlite3.IntegrityError, match="workspace_binding_required|phase_transition_invalid"
        ),
    ):
        connection.execute(
            "UPDATE sandbox_executions SET phase = 'launched' WHERE attempt_id = ?",
            (attempt["id"],),
        )


def test_workspace_binding_restores_after_process_local_snapshot_registry_is_lost(
    repo: Path,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)
    assert row["workspace_binding_version"] == 1

    with (
        supervisor.connect() as connection,
        pytest.raises(sqlite3.IntegrityError, match="workspace_binding_immutable"),
    ):
        replacement = "0" * 64
        if replacement == row["baseline_manifest_digest"]:
            replacement = "1" * 64
        connection.execute(
            "UPDATE sandbox_executions SET baseline_manifest_digest = ? WHERE attempt_id = ?",
            (replacement, attempt["id"]),
        )

    from agent_control_plane.supervisor import sandbox_workspace

    # Simulate a fresh process: durable journal values, not the in-memory weak
    # reference registry, must re-establish the baseline handle.
    sandbox_workspace._SNAPSHOT_ORIGINS.clear()
    restored = supervisor._sandbox_execution_restore_workspace_binding(
        attempt["id"], attempt["claim_token"]
    )
    assert restored["version"] == 1
    assert restored["execution_id"] == row["execution_id"]
    assert restored["baseline"].manifest.digest == row["baseline_manifest_digest"]
    assert read_snapshot_files(restored["baseline"])["alpha.txt"] == b"base\n"
    assert restored["workspace_root"] == Path(row["workspace_root_path"])

    (restored["workspace_root"] / "alpha.txt").write_text("sandbox result\n", encoding="utf-8")
    changes = collect_changes(
        restored["baseline"].manifest,
        restored["workspace_root"],
        write_set_rules=[("alpha.txt", True, False)],
    )
    assert changes.baseline_digest == restored["baseline"].manifest.digest
    assert [change.path for change in changes.changes] == ["alpha.txt"]


def test_workspace_binding_restore_rejects_replaced_output_root(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)
    workspace_root = Path(row["workspace_root_path"])
    saved_root = workspace_root.with_name("workspace-saved")
    workspace_root.rename(saved_root)
    workspace_root.mkdir(mode=0o700)

    with pytest.raises(SupervisorError) as error:
        supervisor._sandbox_execution_restore_workspace_binding(
            attempt["id"], attempt["claim_token"]
        )
    assert error.value.code == "invalid_snapshot"


def test_workspace_binding_restore_rejects_changed_baseline_content(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)
    (Path(row["baseline_root_path"]) / "alpha.txt").write_text("forged\n", encoding="utf-8")

    with pytest.raises(SupervisorError) as error:
        supervisor._sandbox_execution_restore_workspace_binding(
            attempt["id"], attempt["claim_token"]
        )
    assert error.value.code == "snapshot_changed"


def test_workspace_binding_restore_rechecks_claim_fence_after_baseline_scan(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    restore = journal_module._restore_snapshot_from_record

    def expire_claim_during_restore(*args, **kwargs):
        snapshot = restore(*args, **kwargs)
        with supervisor.connect() as connection:
            connection.execute(
                "UPDATE attempts SET lease_expires_at = 0 WHERE id = ?", (attempt["id"],)
            )
        return snapshot

    monkeypatch.setattr(
        journal_module, "_restore_snapshot_from_record", expire_claim_during_restore
    )

    with pytest.raises(SupervisorError) as error:
        supervisor._sandbox_execution_restore_workspace_binding(
            attempt["id"], attempt["claim_token"]
        )
    assert error.value.code == "lease_expired"


def test_durable_manifest_parser_accepts_valid_manifest_above_old_32_mib_cap() -> None:
    target = "a" * 4_096
    count = 8_500
    entries = tuple(
        ManifestEntry(f"link-{index:05d}", "symlink", 0o777, len(target), symlink_target=target)
        for index in range(count)
    )
    manifest = _make_manifest(entries, count * len(target))
    encoded = canonical_json(manifest.as_json())
    assert len(encoded.encode("utf-8")) > 32 * 1024 * 1024

    assert _tree_manifest_from_json(encoded) == manifest


def test_schema_13_read_only_open_refuses_until_journal_migration(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    with supervisor.connect() as connection:
        connection.execute("DROP TABLE sandbox_executions")
        connection.execute("UPDATE meta SET value = '13' WHERE key = 'schema_version'")

    with pytest.raises(SupervisorError) as error:
        GitSupervisor(repo, read_only=True)
    assert error.value.code == "schema_upgrade_required"

    migrated = GitSupervisor(repo)
    assert migrated.schema_version_on_open == 13
    with migrated.connect() as connection:
        tables = {
            row["name"]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    assert "sandbox_executions" in tables


def test_reservation_requires_exact_live_fence_and_no_registered_direct_worker(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)

    with pytest.raises(SupervisorError) as stale:
        supervisor._sandbox_execution_reserve(
            attempt["id"],
            attempt["claim_token"] + 1,
            "a" * 64,
            rootfs_digest="b" * 64,
            runtime_version="runc 1.3.5",
            oci_version="1.2.1",
        )
    assert stale.value.code == "stale_fencing_token"
    with pytest.raises(SupervisorError) as invalid:
        supervisor._sandbox_execution_reserve(
            attempt["id"],
            attempt["claim_token"],
            "not-a-digest",
            rootfs_digest="b" * 64,
            runtime_version="runc 1.3.5",
            oci_version="1.2.1",
        )
    assert invalid.value.code == "sandbox_execution_invalid"

    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET pid = 12345, pid_identity = 'direct-worker' WHERE id = ?",
            (attempt["id"],),
        )
    with pytest.raises(SupervisorError) as registered:
        reserve(supervisor, attempt)
    assert registered.value.code == "worker_already_running"
    assert supervisor._sandbox_execution_get(attempt["id"]) is None


def test_journal_reservation_prevents_later_direct_worker_launch(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)

    with pytest.raises(SupervisorError) as launch:
        supervisor._reserve_worker_launch(
            attempt["id"], attempt["claim_token"], ".acp/logs/direct.log", None
        )
    assert launch.value.code == "sandbox_execution_reserved"
    assert supervisor.attempt(attempt["id"])["pid"] is None


def test_journaled_result_import_and_manual_submission_fail_closed(
    repo: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    result_root = tmp_path_factory.mktemp("worker-result")
    baseline, change_set = result_fixture(attempt, result_root)

    with pytest.raises(SupervisorError) as imported:
        supervisor.import_worker_result(attempt["id"], attempt["claim_token"], baseline, change_set)
    assert imported.value.code == "sandbox_result_unverified"

    with pytest.raises(SupervisorError) as submitted:
        supervisor._submit(
            attempt["id"],
            attempt["claim_token"],
            expected_worker_pid=None,
            credential=None,
        )
    assert submitted.value.code == "sandbox_result_unverified"
    with supervisor.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM result_imports").fetchone()[0] == 0
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "reserved"


def test_result_import_rechecks_journal_at_result_write_boundary(
    repo: Path, tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    worker_pid = 9876
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET pid = ?, pid_identity = ? WHERE id = ?",
            (worker_pid, "synthetic-worker-identity", attempt["id"]),
        )
    monkeypatch.setattr(
        supervisor,
        "_worker_exit_receipt_in",
        lambda connection, current, expected_pid: "synthetic-exit-receipt",
    )
    result_root = tmp_path_factory.mktemp("worker-result")
    baseline, change_set = result_fixture(attempt, result_root)
    original_guard = claims_module._require_sandbox_execution_result_eligible
    guard_calls = 0

    def add_journal_before_second_check(connection, attempt_id: str) -> None:
        nonlocal guard_calls
        guard_calls += 1
        if guard_calls == 2:
            stamp = "2026-10-04T00:00:00Z"
            connection.execute(
                """
                INSERT INTO sandbox_executions
                  (attempt_id, claim_token, execution_id, backend, container_id,
                   bundle_digest, rootfs_digest, runtime_version, oci_version,
                   bundle_path, state_path, phase, created_at, updated_at)
                VALUES (?, ?, 'race-execution', 'oci-runc', 'race-container', ?, ?,
                        'test-runc', '1.2.1', '/bundle', '/state', 'reserved', ?, ?)
                """,
                (attempt_id, attempt["claim_token"], "a" * 64, "b" * 64, stamp, stamp),
            )
        original_guard(connection, attempt_id)

    monkeypatch.setattr(
        claims_module,
        "_require_sandbox_execution_result_eligible",
        add_journal_before_second_check,
    )
    with pytest.raises(SupervisorError) as imported:
        supervisor.import_worker_result(attempt["id"], attempt["claim_token"], baseline, change_set)

    assert imported.value.code == "sandbox_result_unverified"
    assert guard_calls == 2
    with supervisor.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM result_imports").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM sandbox_executions").fetchone()[0] == 0


def test_journaled_result_recovery_is_fenced_before_staging_cleanup(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    import_id = "untrusted-result-import"
    stamp = "2026-10-04T00:00:00Z"
    with supervisor.connect() as connection:
        connection.execute(
            """
            INSERT INTO result_imports
              (id, attempt_id, claim_token, worker_pid, worker_identity,
               worker_exit_receipt_json, base_sha, tree_sha, baseline_digest,
               result_digest, change_digest, result_ref, commit_timestamp,
               commit_sha, phase, created_at, updated_at)
            VALUES (?, ?, ?, 41, 'worker-identity', '{}', 'base', 'tree', 'baseline',
                    'result', 'changes', 'refs/acp/result', 0, 'commit',
                    'prepared', ?, ?)
            """,
            (
                import_id,
                attempt["id"],
                attempt["claim_token"],
                stamp,
                stamp,
            ),
        )
    cleanup_called = False

    def record_cleanup() -> None:
        nonlocal cleanup_called
        cleanup_called = True

    monkeypatch.setattr(supervisor, "_cleanup_result_import_staging_locked", record_cleanup)
    with pytest.raises(SupervisorError) as recovered:
        supervisor.recover_worker_result_import(import_id)

    assert recovered.value.code == "sandbox_result_unverified"
    assert cleanup_called is False
    with supervisor.connect() as connection:
        row = connection.execute(
            "SELECT phase FROM result_imports WHERE id = ?", (import_id,)
        ).fetchone()
    assert row["phase"] == "prepared"


def test_missing_result_journal_still_cleans_unowned_staging(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    import_id = "00000000-0000-4000-8000-000000000001"
    stage = supervisor._result_import_stage_path(import_id, create=True)
    (stage / "objects" / "orphan-marker").write_text("orphan", encoding="utf-8")

    with pytest.raises(SupervisorError) as recovered:
        supervisor.recover_worker_result_import(import_id)

    assert recovered.value.code == "result_import_not_found"
    assert not stage.exists()


def test_concurrent_reservations_have_one_winner(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    barrier = threading.Barrier(2)

    def try_reserve() -> dict | str:
        barrier.wait(timeout=5)
        try:
            return reserve(supervisor, attempt)
        except SupervisorError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: try_reserve(), range(2)))

    assert sum(isinstance(result, dict) for result in results) == 1
    assert sum(result == "sandbox_execution_exists" for result in results) == 1
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "reserved"


def test_concurrent_direct_and_sandbox_reservations_serialize(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    barrier = threading.Barrier(2)

    def reserve_sandbox() -> str:
        barrier.wait(timeout=5)
        try:
            reserve(supervisor, attempt)
        except SupervisorError as error:
            return error.code
        return "sandbox"

    def reserve_direct() -> str:
        barrier.wait(timeout=5)
        try:
            supervisor._reserve_worker_launch(
                attempt["id"], attempt["claim_token"], ".acp/logs/direct.log", None
            )
        except SupervisorError as error:
            return error.code
        return "direct"

    with ThreadPoolExecutor(max_workers=2) as pool:
        sandbox_result, direct_result = list(
            pool.map(lambda function: function(), (reserve_sandbox, reserve_direct))
        )

    assert (sandbox_result, direct_result) in {
        ("sandbox", "sandbox_execution_reserved"),
        ("worker_already_running", "direct"),
    }
    journal = supervisor._sandbox_execution_get(attempt["id"])
    direct_pid = supervisor.attempt(attempt["id"])["pid"]
    if sandbox_result == "sandbox":
        assert journal is not None
        assert direct_pid is None
    else:
        assert journal is None
        assert direct_pid == -1


def test_sql_phase_checks_reject_nullable_process_identities(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    launch_fields = (
        "monitor_identity = 'monitor-start-101', runc_client_pid = 202, "
        "runc_client_identity = 'runc-start-202', wrapper_unit = 'acp-worker.service', "
        "wrapper_invocation_id = '11111111111111111111111111111111', "
        "scope_unit = 'acp-container.scope', "
        "scope_invocation_id = '22222222222222222222222222222222', "
        "cgroup_path = '/user.slice/user-1000.slice/user@1000.service/app.slice/acp-container.scope'"
    )
    with supervisor.connect() as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                f"UPDATE sandbox_executions SET phase = 'launched', monitor_pid = NULL, "
                f"{launch_fields} WHERE attempt_id = ?",
                (attempt["id"],),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                f"UPDATE sandbox_executions SET phase = 'launched', monitor_pid = 101, "
                f"{launch_fields.replace('runc_client_pid = 202', 'runc_client_pid = NULL')} "
                "WHERE attempt_id = ?",
                (attempt["id"],),
            )

    record_launch(supervisor, attempt)
    with supervisor.connect() as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE sandbox_executions SET phase = 'running', init_pid = NULL, "
                "init_identity = 'init-start-303' WHERE attempt_id = ?",
                (attempt["id"],),
            )
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"


def test_recorded_execution_evidence_is_immutable(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    record_launch(supervisor, attempt)
    supervisor._sandbox_execution_record_running(
        attempt["id"], attempt["claim_token"], init_pid=303, init_identity="init-start-303"
    )

    mutations = (
        "monitor_pid = 404",
        "monitor_identity = 'replacement-monitor'",
        "scope_invocation_id = '33333333333333333333333333333333'",
        "cgroup_path = '/different/scope'",
        "init_pid = 505",
    )
    for mutation in mutations:
        with supervisor.connect() as connection:
            with pytest.raises(sqlite3.IntegrityError, match="sandbox_execution_evidence"):
                connection.execute(
                    f"UPDATE sandbox_executions SET {mutation} WHERE attempt_id = ?",
                    (attempt["id"],),
                )

    supervisor._sandbox_execution_record_exit(attempt["id"], attempt["claim_token"], 0)
    with supervisor.connect() as connection:
        with pytest.raises(sqlite3.IntegrityError, match="sandbox_execution_evidence"):
            connection.execute(
                "UPDATE sandbox_executions SET runc_exit_code = 1 WHERE attempt_id = ?",
                (attempt["id"],),
            )

    receipt = cleanup_receipt(supervisor, attempt["id"])
    supervisor._sandbox_execution_record_cleanup_report(
        attempt["id"], attempt["claim_token"], receipt
    )
    with supervisor.connect() as connection:
        with pytest.raises(sqlite3.IntegrityError, match="sandbox_execution_evidence"):
            connection.execute(
                "UPDATE sandbox_executions SET cleanup_receipt_json = '{}' WHERE attempt_id = ?",
                (attempt["id"],),
            )


def test_transition_order_keeps_monitor_runc_and_init_identities_distinct(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)

    with pytest.raises(SupervisorError) as out_of_order:
        supervisor._sandbox_execution_record_running(
            attempt["id"], attempt["claim_token"], init_pid=303, init_identity="init-start-303"
        )
    assert out_of_order.value.code == "sandbox_execution_transition_invalid"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "reserved"

    row = record_launch(supervisor, attempt)
    assert row["phase"] == "launched"
    with pytest.raises(SupervisorError) as pid_alias:
        supervisor._sandbox_execution_record_running(
            attempt["id"], attempt["claim_token"], init_pid=202, init_identity="runc-start-202"
        )
    assert pid_alias.value.code == "sandbox_execution_invalid"

    row = supervisor._sandbox_execution_record_running(
        attempt["id"], attempt["claim_token"], init_pid=303, init_identity="init-start-303"
    )
    assert row["phase"] == "running"
    row = supervisor._sandbox_execution_request_stop(
        attempt["id"], attempt["claim_token"], "attempt cancellation"
    )
    assert row["phase"] == "stopping"
    assert (
        supervisor._sandbox_execution_request_stop(
            attempt["id"], attempt["claim_token"], "attempt cancellation"
        )["phase"]
        == "stopping"
    )

    row = supervisor._sandbox_execution_record_exit(attempt["id"], attempt["claim_token"], 0)
    assert row["phase"] == "exited"
    assert row["runc_exit_code"] == 0
    assert supervisor.verify_event_chain()["ok"] is True


def test_reported_cleanup_is_not_verification_and_cannot_release_attempt(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    record_launch(supervisor, attempt)
    supervisor._sandbox_execution_record_running(
        attempt["id"], attempt["claim_token"], init_pid=303, init_identity="init-start-303"
    )
    supervisor._sandbox_execution_record_exit(attempt["id"], attempt["claim_token"], 0)

    receipt = cleanup_receipt(supervisor, attempt["id"])
    assert receipt["version"] == 2
    assert receipt["verification_status"] == "unverified"
    assert all(observation is None for observation in receipt["observations"].values())
    counterfeit = json.loads(json.dumps(receipt))
    counterfeit["observations"]["runc_delete_exit_code"] = 0
    with pytest.raises(SupervisorError) as invalid:
        supervisor._sandbox_execution_record_cleanup_report(
            attempt["id"], attempt["claim_token"], counterfeit
        )
    assert invalid.value.code == "sandbox_cleanup_report_invalid"
    forged_status = json.loads(json.dumps(receipt))
    forged_status["verification_status"] = "verified"
    with pytest.raises(SupervisorError) as invalid_status:
        supervisor._sandbox_execution_record_cleanup_report(
            attempt["id"], attempt["claim_token"], forged_status
        )
    assert invalid_status.value.code == "sandbox_cleanup_report_invalid"

    row = supervisor._sandbox_execution_record_cleanup_report(
        attempt["id"], attempt["claim_token"], receipt
    )
    assert row["phase"] == "cleanup_reported"

    with supervisor.connect() as connection:
        with pytest.raises(sqlite3.IntegrityError, match="phase_transition_invalid"):
            connection.execute(
                "UPDATE sandbox_executions SET phase = 'cleanup_verified' WHERE attempt_id = ?",
                (attempt["id"],),
            )
    with pytest.raises(SupervisorError) as unavailable:
        supervisor._sandbox_execution_transition(
            attempt["id"],
            attempt["claim_token"],
            expected_phase="cleanup_reported",
            next_phase="cleanup_verified",
            updates={},
            event_type="sandbox.execution_cleanup_verified",
            event_payload={},
        )
    assert unavailable.value.code == "sandbox_execution_transition_invalid"

    with pytest.raises(SupervisorError) as teardown:
        supervisor.runtime_down(attempt["id"], force=True)
    assert teardown.value.code == "sandbox_cleanup_unverified"

    result = supervisor.reap_expired(now=attempt["lease_expires_at"] + 1)
    assert result["terminated_workers"] == []
    assert result["runtime_cleanup"] == []
    assert supervisor.attempt(attempt["id"])["termination_target_status"] == "quarantined"
    assert supervisor.task(attempt["task_id"])["status"] == "cleanup_pending"
    with supervisor.connect() as connection:
        with pytest.raises(SupervisorError) as task_cleanup:
            supervisor._complete_task_cleanup(connection, attempt["task_id"], attempt["id"], "test")
    assert task_cleanup.value.code == "sandbox_cleanup_unverified"
    with supervisor.connect() as connection:
        lease = connection.execute(
            "SELECT lease_expires_at FROM resource_leases WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()
    assert lease["lease_expires_at"] == CLEANUP_FENCE_EPOCH
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "cleanup_reported"


def test_result_candidate_is_versioned_bound_and_never_authorizes_import(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)
    workspace = Path(row["workspace_root_path"])
    record_launch(supervisor, attempt)
    supervisor._sandbox_execution_record_running(
        attempt["id"], attempt["claim_token"], init_pid=303, init_identity="init-start-303"
    )
    (workspace / "alpha.txt").write_text("candidate result\n", encoding="utf-8")
    supervisor._sandbox_execution_record_exit(attempt["id"], attempt["claim_token"], 0)
    supervisor._sandbox_execution_record_cleanup_report(
        attempt["id"], attempt["claim_token"], cleanup_receipt(supervisor, attempt["id"])
    )

    captured = supervisor._sandbox_execution_capture_result_candidate(
        attempt["id"], attempt["claim_token"]
    )
    candidate = captured["candidate"]
    change_set = captured["change_set"]
    assert candidate["version"] == 1
    assert candidate["authorization"] == "none"
    assert candidate["attempt_id"] == attempt["id"]
    assert candidate["claim_token"] == attempt["claim_token"]
    assert candidate["execution_id"] == row["execution_id"]
    assert candidate["workspace_binding"]["baseline"]["manifest_digest"] == (
        change_set.baseline_digest
    )
    assert candidate["workspace_binding"]["workspace"]["path"] == str(workspace)
    assert candidate["workspace_binding"]["workspace"]["device"] == row["workspace_root_dev"]
    assert candidate["workspace_binding"]["workspace"]["inode"] == row["workspace_root_ino"]
    assert candidate["result"]["tree_digest"] == change_set.result_digest
    assert candidate["result"]["change_digest"] == change_set.digest
    assert candidate["result"]["import_digest"]
    recorded = supervisor._sandbox_execution_get(attempt["id"])
    assert candidate["exit"] == {
        "code": 0,
        "observed_by": "runc_client_popen_wait",
        "runc_client_pid": recorded["runc_client_pid"],
        "runc_client_identity": recorded["runc_client_identity"],
    }
    assert candidate["cleanup"]["status"] == "unverified"
    assert (
        captured["candidate_digest"]
        == hashlib.sha256(canonical_json(candidate).encode("utf-8")).hexdigest()
    )

    binding = supervisor._sandbox_execution_restore_workspace_binding(
        attempt["id"], attempt["claim_token"]
    )
    with supervisor.connect() as connection:
        supervisor._sandbox_execution_require_result_candidate_matches(
            connection,
            attempt["id"],
            baseline_digest=change_set.baseline_digest,
            import_digest=candidate["result"]["import_digest"],
            change_digest=change_set.digest,
        )
        with pytest.raises(SupervisorError) as mismatch:
            supervisor._sandbox_execution_require_result_candidate_matches(
                connection,
                attempt["id"],
                baseline_digest=change_set.baseline_digest,
                import_digest="0" * 64,
                change_digest=change_set.digest,
            )
    assert mismatch.value.code == "sandbox_result_evidence_mismatch"

    with pytest.raises(SupervisorError) as imported:
        supervisor.import_worker_result(
            attempt["id"], attempt["claim_token"], binding["baseline"], change_set
        )
    assert imported.value.code == "sandbox_result_unverified"
    with supervisor.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM result_imports").fetchone()[0] == 0
    reopened = GitSupervisor(repo)
    persisted = reopened._sandbox_execution_get(attempt["id"])
    assert persisted["result_candidate"] == candidate
    assert persisted["result_candidate_digest"] == captured["candidate_digest"]


def test_result_candidate_is_idempotent_but_cannot_be_replaced(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)
    workspace = Path(row["workspace_root_path"])
    record_launch(supervisor, attempt)
    supervisor._sandbox_execution_record_running(
        attempt["id"], attempt["claim_token"], init_pid=303, init_identity="init-start-303"
    )
    (workspace / "alpha.txt").write_text("candidate v1\n", encoding="utf-8")
    supervisor._sandbox_execution_record_exit(attempt["id"], attempt["claim_token"], 0)
    supervisor._sandbox_execution_record_cleanup_report(
        attempt["id"], attempt["claim_token"], cleanup_receipt(supervisor, attempt["id"])
    )

    first = supervisor._sandbox_execution_capture_result_candidate(
        attempt["id"], attempt["claim_token"]
    )
    replay = supervisor._sandbox_execution_capture_result_candidate(
        attempt["id"], attempt["claim_token"]
    )
    assert replay["candidate"] == first["candidate"]
    assert replay["candidate_digest"] == first["candidate_digest"]

    (workspace / "alpha.txt").write_text("candidate v2\n", encoding="utf-8")
    with pytest.raises(SupervisorError) as conflict:
        supervisor._sandbox_execution_capture_result_candidate(
            attempt["id"], attempt["claim_token"]
        )
    assert conflict.value.code == "sandbox_result_evidence_conflict"
    persisted = supervisor._sandbox_execution_get(attempt["id"])
    assert persisted["result_candidate"] == first["candidate"]
    assert persisted["result_candidate_digest"] == first["candidate_digest"]


def test_persisted_v1_cleanup_receipt_replays_read_only_but_never_proves_cleanup(
    repo: Path, tmp_path: Path
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    record_launch(supervisor, attempt)
    supervisor._sandbox_execution_record_running(
        attempt["id"], attempt["claim_token"], init_pid=303, init_identity="init-start-303"
    )
    supervisor._sandbox_execution_record_exit(attempt["id"], attempt["claim_token"], 0)

    legacy_receipt = cleanup_receipt(supervisor, attempt["id"])
    legacy_receipt["version"] = 1
    legacy_receipt.pop("verification_status")
    legacy_receipt["observations"] = {
        "runc_delete_exit_code": 0,
        "runc_state_absent": True,
        "bundle_absent": True,
        "state_directory_absent": True,
        "wrapper_unit_absent": True,
        "scope_unit_absent": True,
        "cgroup_absent": True,
        "monitor_identity_absent": True,
        "runc_client_identity_absent": True,
        "container_init_identity_absent": True,
    }
    encoded = canonical_json(legacy_receipt)
    supervisor._sandbox_execution_transition(
        attempt["id"],
        attempt["claim_token"],
        expected_phase="exited",
        next_phase="cleanup_reported",
        updates={"cleanup_receipt_json": encoded},
        event_type="sandbox.execution_cleanup_reported",
        event_payload={"receipt_sha256": hashlib.sha256(encoded.encode()).hexdigest()},
    )

    replayed = supervisor._sandbox_execution_record_cleanup_report(
        attempt["id"], attempt["claim_token"], legacy_receipt
    )
    assert replayed["phase"] == "cleanup_reported"
    assert replayed["cleanup_receipt"]["version"] == 1

    current_receipt = cleanup_receipt(supervisor, attempt["id"])
    with pytest.raises(SupervisorError) as replace_legacy:
        supervisor._sandbox_execution_record_cleanup_report(
            attempt["id"], attempt["claim_token"], current_receipt
        )
    assert replace_legacy.value.code == "sandbox_execution_transition_conflict"

    baseline, change_set = result_fixture(attempt, tmp_path)
    with pytest.raises(SupervisorError) as import_unverified:
        supervisor.import_worker_result(attempt["id"], attempt["claim_token"], baseline, change_set)
    assert import_unverified.value.code == "sandbox_result_unverified"


def test_ambiguous_execution_is_durably_quarantined(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)

    row = supervisor._sandbox_execution_mark_ambiguous(
        attempt["id"], attempt["claim_token"], "runc state readback disagreed"
    )
    assert row["phase"] == "ambiguous"
    assert supervisor.attempt(attempt["id"])["termination_target_status"] == "quarantined"
    assert supervisor.task(attempt["task_id"])["status"] == "cleanup_pending"
    result = supervisor.reap_expired(now=attempt["lease_expires_at"] + 1)
    assert result["terminated_workers"] == []
    assert result["runtime_cleanup"] == []
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "ambiguous"
