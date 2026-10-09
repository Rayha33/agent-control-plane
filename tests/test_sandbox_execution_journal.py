from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
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
from agent_control_plane.supervisor import oci_worker
from agent_control_plane.supervisor import sandbox_attestation as sandbox_attestation_module
from agent_control_plane.supervisor import sandbox_execution_journal as journal_module
from agent_control_plane.supervisor.common import canonical_json
from agent_control_plane.supervisor.sandbox_attestation import (
    ProcessSnapshot,
    collect_running_runtime_attestation,
    running_attestation_has_collector_provenance,
    running_attestation_is_self_consistent,
    validate_running_runtime_attestation,
)
from agent_control_plane.supervisor.sandbox_workspace import (
    ManifestEntry,
    _make_manifest,
    _tree_manifest_from_json,
    collect_changes,
    copy_snapshot,
    read_snapshot_files,
)
from agent_control_plane.supervisor.store import _authorize_sandbox_reservation_write


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return init_repo(tmp_path)


def claimed(supervisor: GitSupervisor, path: str = "alpha.txt") -> dict:
    task = make_task(supervisor, path, title="sandbox journal test")
    return supervisor.claim(task["id"], "sandbox-worker")


def configure_test_sandbox_pins(supervisor: GitSupervisor) -> None:
    if (
        supervisor.config.oci_rootfs_pin is not None
        and supervisor.config.oci_runc_executable is not None
        and supervisor.config.oci_runc_version is not None
    ):
        return
    rootfs = supervisor.root.parent / f"{supervisor.root.name}-test-rootfs"
    (rootfs / "bin").mkdir(parents=True, mode=0o700, exist_ok=True)
    fixture_executable = rootfs / "bin" / "sh"
    if not fixture_executable.exists():
        fixture_executable.write_text("sandbox journal test rootfs\n", encoding="ascii")
        fixture_executable.chmod(0o700)
    manifest = oci_worker.rootfs_tree_manifest(rootfs)
    rootfs_pin = oci_worker._pin_trusted_rootfs(
        rootfs,
        manifest["rootfs_sha256"],
        supervisor.root,
        expected_closure_sha256=manifest["closure_sha256"],
    )
    runc_pin = oci_worker._pin_trusted_runc_executable("/bin/sh", supervisor.root)
    supervisor.config = replace(
        supervisor.config,
        oci_rootfs_pin=rootfs_pin,
        oci_runc_executable=runc_pin,
        oci_runc_version="1.3.5",
    )


def configured_sandbox_claims(supervisor: GitSupervisor) -> dict[str, str]:
    configure_test_sandbox_pins(supervisor)
    return {
        "rootfs_digest": supervisor.config.oci_rootfs_pin.sha256,
        "rootfs_closure_digest": supervisor.config.oci_rootfs_pin.closure_sha256,
        "runc_executable_digest": supervisor.config.oci_runc_executable.sha256,
        "runtime_version": supervisor.config.oci_runc_version,
        "oci_version": "1.2.1",
    }


class _TestRuncProcess:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.returncode: int | None = None


def _test_runc_handle(
    *,
    target: oci_worker._RuncLaunchTarget | None = None,
    start_ticks: int = 1202,
    exit_code: int = 0,
    sealed: bool = True,
    gate_writer: int | None = None,
) -> oci_worker.RuncLaunchHandle:
    process = _TestRuncProcess(202)
    identity = f"linux:{process.pid}:{start_ticks}"
    if gate_writer is None:
        gate_read, gate_writer = os.pipe()
        os.close(gate_read)
    handle = oci_worker.RuncLaunchHandle(_gate_writer=gate_writer)
    if sealed:
        assert target is not None

        def test_waitpid(pid: int, _options: int) -> tuple[int, int]:
            return pid, exit_code << 8

        oci_worker._register_runc_launch_handle(
            handle,
            process=process,
            process_identity=identity,
            target=target,
            _test_waitpid=test_waitpid,
            _test_identity_reader=lambda pid: identity if pid == process.pid else None,
        )
    return handle


def _test_runc_target(
    execution: dict, *, launch_mode: str = "private_bundle", container_id: str | None = None
) -> oci_worker._RuncLaunchTarget:
    state_path = execution["state_path"]
    return oci_worker._RuncLaunchTarget(
        launch_mode=launch_mode,
        argv=(
            "/usr/bin/runc",
            "--root",
            "/proc/self/fd/66",
            "--systemd-cgroup",
            "run",
            "--bundle",
            "/proc/self/fd/64",
            "--pid-file",
            "/proc/self/fd/66/init.pid",
            "--preserve-fds",
            "1",
            "--keep",
            container_id or execution["container_id"],
        ),
        runc_executable_path="/usr/bin/runc",
        runc_executable_sha256=execution["runc_executable_digest"],
        config_sha256="b" * 64,
        bundle_path=execution["bundle_path"],
        bundle_device=execution["bundle_root_dev"],
        bundle_inode=execution["bundle_root_ino"],
        rootfs_path=str(Path(execution["bundle_path"]) / "rootfs"),
        rootfs_device=1,
        rootfs_inode=1202,
        rootfs_sha256=execution["rootfs_digest"],
        rootfs_closure_sha256=execution["rootfs_closure_digest"],
        rootfs_entry_count=3,
        rootfs_bytes=25,
        rootfs_snapshot_limit_bytes=4 * 1024 * 1024,
        rootfs_snapshot_device=2,
        rootfs_snapshot_inode=1203,
        rootfs_snapshot_sha256=execution["rootfs_digest"],
        rootfs_snapshot_closure_sha256=execution["rootfs_closure_digest"],
        rootfs_snapshot_entry_count=3,
        rootfs_snapshot_bytes=25,
        state_path=state_path,
        state_device=execution["state_root_dev"],
        state_inode=execution["state_root_ino"],
        workspace_path=execution["workspace_root_path"],
        workspace_device=execution["workspace_root_dev"],
        workspace_inode=execution["workspace_root_ino"],
        pid_file_path=str(Path(state_path) / "init.pid"),
        container_id=container_id or execution["container_id"],
        memory_limit_bytes=1_073_741_824,
        cpu_quota=100_000,
        cpu_period=100_000,
        pids_limit=256,
    )


def reserve(supervisor: GitSupervisor, attempt: dict) -> dict:
    runtime_claims = configured_sandbox_claims(supervisor)
    row = supervisor._sandbox_execution_reserve(
        attempt["id"],
        attempt["claim_token"],
        **runtime_claims,
    )
    execution_root = Path(row["bundle_path"]).parent
    execution_root.mkdir(mode=0o700, parents=True)
    Path(row["bundle_path"]).mkdir(mode=0o700)
    Path(row["state_path"]).mkdir(mode=0o700)
    baseline = copy_snapshot(attempt["worktree"], execution_root / "baseline")
    workspace = copy_snapshot(baseline.root, execution_root / "workspace")
    return supervisor._sandbox_execution_bind_workspace(
        attempt["id"], attempt["claim_token"], baseline, workspace
    )


def test_launch_record_requires_pinned_runc_handle(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)

    with pytest.raises(SupervisorError) as unsealed:
        record_launch(
            supervisor,
            attempt,
            runc_handle=_test_runc_handle(target=_test_runc_target(execution), sealed=False),
        )

    assert unsealed.value.code == "sandbox_execution_launch_handle_required"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "reserved"


def test_pinned_runc_handle_cannot_be_rebound_to_another_attempt(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    first_attempt = claimed(supervisor)
    first_execution = reserve(supervisor, first_attempt)
    handle = _test_runc_handle(target=_test_runc_target(first_execution))
    record_launch(supervisor, first_attempt, runc_handle=handle)

    second_attempt = claimed(supervisor, "beta.txt")
    reserve(supervisor, second_attempt)
    with pytest.raises(SupervisorError) as rebound:
        record_launch(supervisor, second_attempt, runc_handle=handle)

    assert rebound.value.code == "sandbox_execution_launch_target_mismatch"
    assert supervisor._sandbox_execution_get(second_attempt["id"])["phase"] == "reserved"


def test_wrong_first_attempt_cannot_claim_runc_handle_provenance(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    first_attempt = claimed(supervisor)
    first_execution = reserve(supervisor, first_attempt)
    second_attempt = claimed(supervisor, "beta.txt")
    second_execution = reserve(supervisor, second_attempt)
    handle = _test_runc_handle(target=_test_runc_target(first_execution))

    with pytest.raises(SupervisorError) as wrong_first_binding:
        record_launch(supervisor, second_attempt, runc_handle=handle)

    assert wrong_first_binding.value.code == "sandbox_execution_launch_target_mismatch"
    assert supervisor._sandbox_execution_get(second_attempt["id"])["phase"] == "reserved"
    assert record_launch(supervisor, first_attempt, runc_handle=handle)["phase"] == "launched"
    assert second_execution["phase"] == "reserved"


def test_diagnostic_runc_handle_cannot_be_recorded_as_supervised(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    handle = _test_runc_handle(
        target=_test_runc_target(execution, launch_mode="unisolated_diagnostic")
    )

    with pytest.raises(SupervisorError) as diagnostic:
        record_launch(supervisor, attempt, runc_handle=handle)

    assert diagnostic.value.code == "sandbox_execution_launch_target_mismatch"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "reserved"


def test_launch_binds_rootfs_pins_and_persists_exact_config_digest(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    target = _test_runc_target(execution)
    handle = _test_runc_handle(target=target)

    assert record_launch(supervisor, attempt, runc_handle=handle)["phase"] == "launched"
    with supervisor.connect() as connection:
        event = connection.execute(
            "SELECT payload_json FROM events WHERE event_type = 'sandbox.execution_launched'"
        ).fetchone()
    assert event is not None
    launch = json.loads(event["payload_json"])["launch_target"]
    assert launch["config_sha256"] == target.config_sha256
    assert launch["config_sha256_semantics"] == "sha256-exact-config-json-bytes"
    assert launch["rootfs"]["sha256"] == execution["rootfs_digest"]
    assert launch["rootfs"]["closure_sha256"] == execution["rootfs_closure_digest"]
    assert launch["rootfs"]["device"] == target.rootfs_device
    assert launch["rootfs"]["inode"] == target.rootfs_inode
    assert launch["rootfs"]["snapshot"]["device"] == target.rootfs_snapshot_device
    assert launch["rootfs"]["snapshot"]["inode"] == target.rootfs_snapshot_inode
    assert launch["rootfs"]["snapshot"]["sha256"] == execution["rootfs_digest"]
    durable = supervisor._sandbox_execution_get(attempt["id"])
    assert durable["launch_plan_required"] == 1
    assert durable["launch_plan_binding_version"] == 1
    assert durable["bundle_digest"] == journal_module._sandbox_reservation_bundle_digest(durable)
    assert durable["bundle_digest_semantics"] == "oci-reservation-v1"
    assert durable["launch_config_digest"] == target.config_sha256
    assert (
        durable["launch_argv_digest"]
        == hashlib.sha256(canonical_json(list(target.argv)).encode("utf-8")).hexdigest()
    )
    assert (
        durable["launch_plan_digest"]
        == hashlib.sha256(canonical_json(durable["launch_plan"]).encode("utf-8")).hexdigest()
    )
    assert durable["launch_plan"]["reservation"]["bundle_digest"] == execution["bundle_digest"]
    assert durable["launch_plan"]["version"] == 4
    assert durable["launch_plan"]["reservation"]["bundle_digest_semantics"] == "oci-reservation-v1"
    assert durable["launch_plan"]["launch"]["argv"] == list(target.argv)
    assert durable["launch_plan"]["launch"]["resource_limits"] == {
        "memory_max_bytes": target.memory_limit_bytes,
        "cpu_quota": target.cpu_quota,
        "cpu_period": target.cpu_period,
        "pids_max": target.pids_limit,
    }
    assert journal_module._sandbox_launch_plan_binding_is_self_consistent(durable)
    event_plan = json.loads(event["payload_json"])["launch_plan"]
    assert event_plan == durable["launch_plan"]
    assert supervisor.verify_event_chain()["ok"] is True

    # Earlier plan versions did not bind an attempt-slice identity and cannot
    # authorize the stronger current launch/running evidence.
    legacy_plan = json.loads(canonical_json(durable["launch_plan"]))
    legacy_plan["version"] = 1
    legacy_plan["reservation"].pop("bundle_digest_semantics")
    legacy_row = dict(durable)
    legacy_row["bundle_digest_semantics"] = "legacy-caller-asserted-v0"
    legacy_row["launch_plan_json"] = canonical_json(legacy_plan)
    legacy_row["launch_plan_digest"] = hashlib.sha256(
        legacy_row["launch_plan_json"].encode("utf-8")
    ).hexdigest()
    assert not journal_module._sandbox_launch_plan_binding_is_self_consistent(legacy_row)
    legacy_plan["version"] = True
    legacy_row["launch_plan_json"] = canonical_json(legacy_plan)
    legacy_row["launch_plan_digest"] = hashlib.sha256(
        legacy_row["launch_plan_json"].encode("utf-8")
    ).hexdigest()
    assert not journal_module._sandbox_launch_plan_binding_is_self_consistent(legacy_row)


def test_launch_rejects_forged_reservation_bundle_digest(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    handle = _test_runc_handle(target=_test_runc_target(execution))

    # Simulate a tampered/legacy reservation row; the immutable trigger is
    # tested separately, while this proves launch independently re-derives it.
    with supervisor.connect() as connection:
        connection.execute("DROP TRIGGER sandbox_execution_identity_immutable")
        connection.execute(
            "UPDATE sandbox_executions SET bundle_digest = ? WHERE attempt_id = ?",
            ("a" * 64, attempt["id"]),
        )

    with pytest.raises(SupervisorError) as mismatch:
        record_launch(supervisor, attempt, runc_handle=handle)

    assert mismatch.value.code == "sandbox_execution_bundle_digest_mismatch"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "reserved"


def test_launch_rejects_legacy_caller_asserted_reservation_digest(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    handle = _test_runc_handle(target=_test_runc_target(execution))

    # Model a schema-24 reserved row migrated with the legacy default marker.
    with supervisor.connect() as connection:
        connection.execute("DROP TRIGGER sandbox_execution_identity_immutable")
        connection.execute(
            "UPDATE sandbox_executions SET bundle_digest = ?, bundle_digest_semantics = ? "
            "WHERE attempt_id = ?",
            ("a" * 64, "legacy-caller-asserted-v0", attempt["id"]),
        )

    with pytest.raises(SupervisorError) as legacy:
        record_launch(supervisor, attempt, runc_handle=handle)

    assert legacy.value.code == "sandbox_execution_legacy_bundle_digest"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "reserved"


def test_direct_sql_cannot_claim_host_derived_reservation_provenance(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = {
        "attempt_id": attempt["id"],
        "claim_token": attempt["claim_token"],
        "execution_id": "forged-execution",
        "backend": "oci-runc",
        "container_id": "forged-container",
        "rootfs_digest": "a" * 64,
        "rootfs_closure_digest": "b" * 64,
        "runc_executable_digest": "c" * 64,
        "runtime_version": "1.3.5",
        "oci_version": "1.2.1",
        "bundle_path": f"{repo}/.acp/sandbox-executions/forged/bundle",
        "state_path": f"{repo}/.acp/sandbox-executions/forged/state",
    }
    bundle_digest = journal_module._sandbox_reservation_bundle_digest(execution)

    with supervisor.connect() as connection:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="sandbox_execution_reservation_authorization_required",
        ):
            connection.execute(
                """
                INSERT INTO sandbox_executions
                  (attempt_id, claim_token, execution_id, backend, container_id,
                   bundle_digest, bundle_digest_semantics, launch_plan_required,
                   rootfs_digest, rootfs_closure_digest, runc_executable_digest,
                   runtime_version, oci_version, bundle_path, state_path, phase,
                   created_at, updated_at)
                VALUES (?, ?, ?, 'oci-runc', ?, ?, 'oci-reservation-v1', 1,
                        ?, ?, ?, ?, ?, ?, ?, 'reserved', 'now', 'now')
                """,
                (
                    execution["attempt_id"],
                    execution["claim_token"],
                    execution["execution_id"],
                    execution["container_id"],
                    bundle_digest,
                    execution["rootfs_digest"],
                    execution["rootfs_closure_digest"],
                    execution["runc_executable_digest"],
                    execution["runtime_version"],
                    execution["oci_version"],
                    execution["bundle_path"],
                    execution["state_path"],
                ),
            )

    assert supervisor._sandbox_execution_get(attempt["id"]) is None


def test_v25_bundle_digest_semantics_migration_preserves_and_freezes_legacy_rows() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.execute(
            """
            CREATE TABLE sandbox_executions (
              attempt_id TEXT PRIMARY KEY,
              claim_token INTEGER NOT NULL,
              execution_id TEXT NOT NULL,
              backend TEXT NOT NULL,
              container_id TEXT NOT NULL,
              bundle_digest TEXT NOT NULL,
              rootfs_digest TEXT NOT NULL,
              rootfs_closure_digest TEXT NOT NULL,
              runc_executable_digest TEXT NOT NULL,
              runtime_version TEXT NOT NULL,
              oci_version TEXT NOT NULL,
              bundle_path TEXT NOT NULL,
              state_path TEXT NOT NULL,
              phase TEXT NOT NULL DEFAULT 'reserved',
              created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO sandbox_executions VALUES
              ('attempt-old', 7, 'execution-old', 'oci-runc', 'container-old', ?, ?, ?, ?,
               '1.3.5', '1.2.1', '/bundle-old', '/state-old', 'reserved', 'now')
            """,
            ("f" * 64, "a" * 64, "b" * 64, "c" * 64),
        )

        migrations = dict(MIGRATIONS)
        migrations[25](connection)
        migrations[25](connection)
        migrations[26](connection)
        migrations[26](connection)

        row = connection.execute(
            "SELECT bundle_digest, bundle_digest_semantics, phase, wrapper_cgroup_path, "
            "attempt_slice_unit, attempt_slice_invocation_id, attempt_slice_cgroup_path "
            "FROM sandbox_executions "
            "WHERE attempt_id = 'attempt-old'"
        ).fetchone()
        assert row["bundle_digest"] == "f" * 64
        assert row["bundle_digest_semantics"] == "legacy-caller-asserted-v0"
        assert row["phase"] == "reserved"
        assert row["wrapper_cgroup_path"] == ""
        assert row["attempt_slice_unit"] == ""
        assert row["attempt_slice_invocation_id"] == ""
        assert row["attempt_slice_cgroup_path"] == ""
        with pytest.raises(sqlite3.IntegrityError, match="identity_immutable"):
            connection.execute(
                "UPDATE sandbox_executions SET bundle_digest_semantics = 'oci-reservation-v1' "
                "WHERE attempt_id = 'attempt-old'"
            )
        with pytest.raises(
            sqlite3.IntegrityError, match="sandbox_execution_attempt_slice_identity_required"
        ):
            connection.execute(
                "UPDATE sandbox_executions SET phase = 'launched' WHERE attempt_id = 'attempt-old'"
            )
        assert (
            connection.execute(
                "SELECT phase FROM sandbox_executions WHERE attempt_id = 'attempt-old'"
            ).fetchone()["phase"]
            == "reserved"
        )
    finally:
        connection.close()


def test_generic_transition_cannot_forge_launch_plan_binding(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    target = _test_runc_target(execution)
    updates = launch_transition_updates(execution, target)

    with pytest.raises(sqlite3.IntegrityError, match="sandbox_launch_plan_binding_required"):
        supervisor._sandbox_execution_transition(
            attempt["id"],
            attempt["claim_token"],
            expected_phase="reserved",
            next_phase="launched",
            updates=updates,
            event_type="sandbox.execution_launched",
            event_payload=updates,
        )

    columns = ", ".join(f"{name} = ?" for name in updates)
    with (
        supervisor.connect() as connection,
        pytest.raises(sqlite3.IntegrityError, match="sandbox_launch_plan_binding_required"),
    ):
        connection.execute(
            f"UPDATE sandbox_executions SET {columns}, phase = 'launched' "
            "WHERE attempt_id = ? AND claim_token = ? AND phase = 'reserved'",
            (*updates.values(), attempt["id"], attempt["claim_token"]),
        )

    row = supervisor._sandbox_execution_get(attempt["id"])
    assert row["phase"] == "reserved"
    assert row["launch_plan_binding_version"] == 0
    assert row["launch_plan_json"] == ""
    assert row["wrapper_cgroup_path"] == ""
    assert row["attempt_slice_unit"] == ""
    assert row["attempt_slice_invocation_id"] == ""
    assert row["attempt_slice_cgroup_path"] == ""


@pytest.mark.parametrize("mismatch", ["config", "argv"])
def test_launch_transition_rejects_mismatched_config_or_argv(repo: Path, mismatch: str) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    target = _test_runc_target(execution)
    updates = launch_transition_updates(execution, target)
    plan = json.loads(updates["launch_plan_json"])
    if mismatch == "config":
        plan["launch"]["config_sha256"] = "f" * 64
    else:
        plan["launch"]["argv"].append("--unexpected")
        plan["launch"]["argv_sha256"] = hashlib.sha256(
            canonical_json(plan["launch"]["argv"]).encode("utf-8")
        ).hexdigest()
    updates["launch_plan_json"] = canonical_json(plan)
    updates["launch_plan_digest"] = hashlib.sha256(
        updates["launch_plan_json"].encode("utf-8")
    ).hexdigest()

    with pytest.raises(SupervisorError) as error:
        supervisor._sandbox_execution_transition(
            attempt["id"],
            attempt["claim_token"],
            expected_phase="reserved",
            next_phase="launched",
            updates=updates,
            event_type="sandbox.execution_launched",
            event_payload=updates,
        )

    assert error.value.code == "sandbox_execution_launch_plan_invalid"
    row = supervisor._sandbox_execution_get(attempt["id"])
    assert row["phase"] == "reserved"
    assert row["launch_plan_binding_version"] == 0


def test_launch_plan_binding_is_write_once(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    record_launch(supervisor, attempt)
    original = supervisor._sandbox_execution_get(attempt["id"])["launch_plan_digest"]
    changed = ("1" if original[0] == "0" else "0") * 64

    with (
        supervisor.connect() as connection,
        pytest.raises(sqlite3.IntegrityError, match="sandbox_launch_plan_binding_required"),
    ):
        connection.execute(
            "UPDATE sandbox_executions SET launch_plan_digest = ? WHERE attempt_id = ?",
            (changed, attempt["id"]),
        )

    row = supervisor._sandbox_execution_get(attempt["id"])
    assert row["phase"] == "launched"
    assert row["launch_plan_digest"] == original
    assert row["launch_plan_digest"] != changed
    assert journal_module._sandbox_launch_plan_binding_is_self_consistent(row)


def test_launch_plan_transition_rolls_back_and_replays_after_event_failure(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    handle = _test_runc_handle(target=_test_runc_target(execution))
    original_event = supervisor._event

    def fail_launch_event(connection, event_type: str, actor: str, payload: dict) -> None:
        if event_type == "sandbox.execution_launched":
            raise RuntimeError("injected crash before launch transaction commit")
        original_event(connection, event_type, actor, payload)

    monkeypatch.setattr(supervisor, "_event", fail_launch_event)
    with pytest.raises(RuntimeError, match="injected crash"):
        record_launch(supervisor, attempt, runc_handle=handle)
    after_failure = supervisor._sandbox_execution_get(attempt["id"])
    assert after_failure["phase"] == "reserved"
    assert after_failure["launch_plan_binding_version"] == 0
    assert after_failure["launch_plan_json"] == ""
    with supervisor.connect() as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM events WHERE event_type = 'sandbox.execution_launched'"
            ).fetchone()[0]
            == 0
        )

    monkeypatch.setattr(supervisor, "_event", original_event)
    replayed = record_launch(supervisor, attempt, runc_handle=handle)
    assert replayed["phase"] == "launched"
    assert journal_module._sandbox_launch_plan_binding_is_self_consistent(replayed)
    assert supervisor.verify_event_chain()["ok"] is True


def test_launch_plan_survives_reopen_but_does_not_recover_dead_handle(
    repo: Path,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    handle = _test_runc_handle(target=_test_runc_target(execution))
    record_launch(supervisor, attempt, runc_handle=handle)
    registry_entry = oci_worker._RUNC_LAUNCH_RECORDS.pop(id(handle))
    try:
        reopened = GitSupervisor(repo)
        durable = reopened._sandbox_execution_get(attempt["id"])
        assert durable["phase"] == "launched"
        assert journal_module._sandbox_launch_plan_binding_is_self_consistent(durable)
        with pytest.raises(SupervisorError) as missing_handle:
            reopened._sandbox_execution_record_running(
                attempt["id"],
                attempt["claim_token"],
                attestation=running_attestation(reopened, attempt),
                runc_handle=handle,
            )
        assert missing_handle.value.code == "sandbox_execution_launch_handle_required"
        assert reopened._sandbox_execution_get(attempt["id"])["phase"] == "launched"
    finally:
        oci_worker._RUNC_LAUNCH_RECORDS[id(handle)] = registry_entry


def test_concurrent_launch_plan_binding_has_one_durable_winner(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    handle = _test_runc_handle(target=_test_runc_target(execution))
    barrier = threading.Barrier(2)

    def race_launch() -> tuple[str, object]:
        barrier.wait(timeout=3)
        try:
            return "ok", record_launch(supervisor, attempt, runc_handle=handle)
        except SupervisorError as error:
            return "error", error

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [
            future.result(timeout=5)
            for future in (pool.submit(race_launch), pool.submit(race_launch))
        ]

    assert [kind for kind, _ in results].count("ok") == 1
    errors = [value for kind, value in results if kind == "error"]
    assert len(errors) == 1
    assert isinstance(errors[0], SupervisorError)
    assert errors[0].code == "sandbox_execution_transition_invalid"
    durable = supervisor._sandbox_execution_get(attempt["id"])
    assert durable["phase"] == "launched"
    assert durable["launch_plan_binding_version"] == 1
    assert journal_module._sandbox_launch_plan_binding_is_self_consistent(durable)
    with supervisor.connect() as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM events WHERE event_type = 'sandbox.execution_launched'"
            ).fetchone()[0]
            == 1
        )


def test_public_gate_release_requires_exact_durable_running_transition(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    try:
        record_launch(supervisor, attempt, runc_handle=handle)

        with pytest.raises(SupervisorError) as premature:
            handle.release_gate()
        assert premature.value.code == "sandbox_launch_gate_not_authorized"
        assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"

        unrelated = _test_runc_handle(target=_test_runc_target(execution))
        with pytest.raises(SupervisorError) as wrong_handle:
            supervisor._sandbox_execution_record_running(
                attempt["id"],
                attempt["claim_token"],
                attestation=running_attestation(supervisor, attempt),
                runc_handle=unrelated,
            )
        assert wrong_handle.value.code == "sandbox_execution_launch_handle_required"
        assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"

        running = record_running(supervisor, attempt)
        assert running["phase"] == "running"
        handle.release_gate()
        assert os.read(gate_read, 3) == b"go\n"
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_running_transition_rejects_caller_constructed_receipt_before_gate_release(
    repo: Path,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        caller_constructed = running_attestation(supervisor, attempt, register_collected=False)

        assert running_attestation_is_self_consistent(caller_constructed)
        assert not running_attestation_has_collector_provenance(caller_constructed)
        with pytest.raises(SupervisorError) as rejected:
            supervisor._sandbox_execution_record_running(
                attempt["id"],
                attempt["claim_token"],
                attestation=caller_constructed,
                runc_handle=handle,
            )

        assert rejected.value.code == "sandbox_runtime_attestation_invalid"
        assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"
        with pytest.raises(SupervisorError) as gate_rejected:
            handle.release_gate()
        assert gate_rejected.value.code == "sandbox_launch_gate_not_authorized"
        os.set_blocking(gate_read, False)
        with pytest.raises(BlockingIOError):
            os.read(gate_read, 3)
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_running_transition_rejects_forged_cgroup_limit_before_gate_release(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        attestation = running_attestation(supervisor, attempt)
        forged = replace(attestation, memory_max_bytes=attestation.memory_max_bytes + 1)
        payload = forged.audit_payload()
        payload.pop("evidence_sha256")
        forged = replace(
            forged,
            evidence_sha256=hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest(),
        )
        # Isolate the durable-limit comparison after the provenance guard; replacing
        # a collector receipt ordinarily discards its process-local provenance.
        monkeypatch.setattr(
            journal_module,
            "running_attestation_has_collector_provenance",
            lambda candidate: candidate is forged,
        )

        with pytest.raises(SupervisorError) as mismatch:
            supervisor._sandbox_execution_record_running(
                attempt["id"],
                attempt["claim_token"],
                attestation=forged,
                runc_handle=handle,
            )

        assert mismatch.value.code == "sandbox_runtime_attestation_stale"
        assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"
        with pytest.raises(SupervisorError) as rejected:
            handle.release_gate()
        assert rejected.value.code == "sandbox_launch_gate_not_authorized"
        os.set_blocking(gate_read, False)
        with pytest.raises(BlockingIOError):
            os.read(gate_read, 3)
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_running_transition_rechecks_live_limits_under_gate_lock(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        attestation = running_attestation(supervisor, attempt)
        monkeypatch.setattr(
            sandbox_attestation_module,
            "read_cgroup_resource_controls",
            lambda _path: {
                "memory.max": b"1073741825\n",
                "cpu.max": b"100000 100000\n",
                "pids.max": b"256\n",
            },
        )
        verify_resources = journal_module.verify_running_runtime_resource_controls

        def verify_resources_under_gate_lock(receipt) -> None:
            assert handle._gate_lock.locked()
            verify_resources(receipt)

        monkeypatch.setattr(
            journal_module,
            "verify_running_runtime_resource_controls",
            verify_resources_under_gate_lock,
        )

        with pytest.raises(SupervisorError) as changed:
            supervisor._sandbox_execution_record_running(
                attempt["id"],
                attempt["claim_token"],
                attestation=attestation,
                runc_handle=handle,
            )

        assert changed.value.code == "sandbox_runtime_attestation_stale"
        assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"
        with pytest.raises(SupervisorError) as rejected:
            handle.release_gate()
        assert rejected.value.code == "sandbox_launch_gate_not_authorized"
        os.set_blocking(gate_read, False)
        with pytest.raises(BlockingIOError):
            os.read(gate_read, 3)
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_stop_before_running_transition_is_rejected_without_gate_release(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        with pytest.raises(SupervisorError) as not_running:
            supervisor._sandbox_execution_request_stop(
                attempt["id"], attempt["claim_token"], "cancel before init"
            )
        assert not_running.value.code == "sandbox_execution_transition_invalid"
        assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"
        with pytest.raises(SupervisorError) as rejected:
            handle.release_gate()
        assert rejected.value.code == "sandbox_launch_gate_not_authorized"
        os.set_blocking(gate_read, False)
        with pytest.raises(BlockingIOError):
            os.read(gate_read, 3)
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_stop_after_running_transition_revokes_unconsumed_gate_permit(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        assert record_running(supervisor, attempt)["phase"] == "running"
        assert (
            supervisor._sandbox_execution_request_stop(
                attempt["id"], attempt["claim_token"], "cancel before release"
            )["phase"]
            == "stopping"
        )

        with pytest.raises(SupervisorError) as rejected:
            handle.release_gate()
        assert rejected.value.code == "sandbox_launch_gate_not_authorized"
        os.set_blocking(gate_read, False)
        with pytest.raises(BlockingIOError):
            os.read(gate_read, 3)
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_stop_cannot_commit_between_running_and_gate_authorization(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    original_transition = GitSupervisor._sandbox_execution_transition
    running_commit_finished = threading.Event()
    allow_running_transition_to_return = threading.Event()
    stop_started = threading.Event()
    stop_finished = threading.Event()
    results: dict[str, object] = {}

    def pause_after_running_commit(self, *args, **kwargs):
        updated = original_transition(self, *args, **kwargs)
        if kwargs.get("expected_phase") == "launched" and kwargs.get("next_phase") == "running":
            running_commit_finished.set()
            assert allow_running_transition_to_return.wait(timeout=3)
        return updated

    def run_running_transition() -> None:
        try:
            results["running"] = record_running(supervisor, attempt)
        except BaseException as error:
            results["running_error"] = error

    def request_stop() -> None:
        stop_started.set()
        try:
            results["stopped"] = supervisor._sandbox_execution_request_stop(
                attempt["id"], attempt["claim_token"], "concurrent cancel"
            )
        except BaseException as error:
            results["stop_error"] = error
        finally:
            stop_finished.set()

    monkeypatch.setattr(GitSupervisor, "_sandbox_execution_transition", pause_after_running_commit)
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        with ThreadPoolExecutor(max_workers=2) as pool:
            running_future = pool.submit(run_running_transition)
            assert running_commit_finished.wait(timeout=3)
            stop_future = pool.submit(request_stop)
            assert stop_started.wait(timeout=3)
            assert not stop_finished.wait(timeout=0.05)
            allow_running_transition_to_return.set()
            running_future.result(timeout=3)
            stop_future.result(timeout=3)

        assert "running_error" not in results
        assert results["running"]["phase"] == "running"
        assert results["stopped"]["phase"] == "stopping"
        with pytest.raises(SupervisorError) as rejected:
            handle.release_gate()
        assert rejected.value.code == "sandbox_launch_gate_not_authorized"
        os.set_blocking(gate_read, False)
        with pytest.raises(BlockingIOError):
            os.read(gate_read, 3)
    finally:
        allow_running_transition_to_return.set()
        handle.close_gate()
        os.close(gate_read)


@pytest.mark.parametrize("terminal_transition", ["exit", "ambiguous"])
def test_terminal_journal_transition_revokes_unconsumed_gate_permit(
    repo: Path, terminal_transition: str
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    gate_read, gate_write = os.pipe()
    handle = _test_runc_handle(target=_test_runc_target(execution), gate_writer=gate_write)
    try:
        record_launch(supervisor, attempt, runc_handle=handle)
        record_running(supervisor, attempt)
        if terminal_transition == "exit":
            assert record_exit(supervisor, attempt)["phase"] == "exited"
        else:
            assert (
                supervisor._sandbox_execution_mark_ambiguous(
                    attempt["id"], attempt["claim_token"], "ambiguous test quarantine"
                )["phase"]
                == "ambiguous"
            )

        with pytest.raises(SupervisorError) as rejected:
            handle.release_gate()
        assert rejected.value.code == "sandbox_launch_gate_not_authorized"
        os.set_blocking(gate_read, False)
        with pytest.raises(BlockingIOError):
            os.read(gate_read, 3)
    finally:
        handle.close_gate()
        os.close(gate_read)


def test_launch_rejects_rootfs_content_that_differs_from_reservation(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    target = replace(_test_runc_target(execution), rootfs_sha256="c" * 64)
    handle = _test_runc_handle(target=target)

    with pytest.raises(SupervisorError) as rootfs_mismatch:
        record_launch(supervisor, attempt, runc_handle=handle)

    assert rootfs_mismatch.value.code == "sandbox_execution_launch_target_mismatch"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "reserved"


def record_launch(
    supervisor: GitSupervisor,
    attempt: dict,
    *,
    runc_handle: oci_worker.RuncLaunchHandle | None = None,
) -> dict:
    if runc_handle is None:
        execution = supervisor._sandbox_execution_get(attempt["id"])
        assert execution is not None
        runc_handle = _test_runc_handle(target=_test_runc_target(execution))
    attempt["_test_runc_handle"] = runc_handle
    execution = supervisor._sandbox_execution_get(attempt["id"])
    assert execution is not None
    slice_unit = oci_worker._oci_worker_systemd_slice(execution["container_id"])
    slice_cgroup = "/user.slice/user-1000.slice/user@1000.service/app.slice/" + slice_unit
    return supervisor._sandbox_execution_record_launch(
        attempt["id"],
        attempt["claim_token"],
        monitor_pid=101,
        monitor_identity="linux:101:1101",
        runc_handle=runc_handle,
        wrapper_unit="acp-worker.service",
        wrapper_invocation_id="1" * 32,
        wrapper_cgroup_path=f"{slice_cgroup}/acp-worker.service",
        attempt_slice_unit=slice_unit,
        attempt_slice_invocation_id="3" * 32,
        attempt_slice_cgroup_path=slice_cgroup,
        scope_unit="acp-container.scope",
        scope_invocation_id="2" * 32,
        cgroup_path=f"{slice_cgroup}/acp-container.scope",
    )


def launch_transition_updates(execution: dict, target: oci_worker._RuncLaunchTarget) -> dict:
    plan = journal_module._sandbox_launch_plan_material(execution, target)
    slice_unit = oci_worker._oci_worker_systemd_slice(target.container_id)
    slice_cgroup = "/user.slice/user-1000.slice/user@1000.service/app.slice/" + slice_unit
    plan["launch"]["systemd_ownership"] = {
        "wrapper_control_group": f"{slice_cgroup}/acp-worker.service",
        "attempt_slice_unit": slice_unit,
        "attempt_slice_invocation_id": "3" * 32,
        "attempt_slice_control_group": slice_cgroup,
    }
    plan_json = canonical_json(plan)
    argv_digest = hashlib.sha256(canonical_json(list(target.argv)).encode("utf-8")).hexdigest()
    return {
        "monitor_pid": 101,
        "monitor_identity": "linux:101:1101",
        "runc_client_pid": 202,
        "runc_client_identity": "linux:202:1202",
        "wrapper_unit": "acp-worker.service",
        "wrapper_invocation_id": "1" * 32,
        "wrapper_cgroup_path": f"{slice_cgroup}/acp-worker.service",
        "attempt_slice_unit": slice_unit,
        "attempt_slice_invocation_id": "3" * 32,
        "attempt_slice_cgroup_path": slice_cgroup,
        "scope_unit": "acp-container.scope",
        "scope_invocation_id": "2" * 32,
        "cgroup_path": f"{slice_cgroup}/acp-container.scope",
        "launch_plan_binding_version": 1,
        "launch_plan_json": plan_json,
        "launch_config_digest": target.config_sha256,
        "launch_argv_digest": argv_digest,
        "launch_plan_digest": hashlib.sha256(plan_json.encode("utf-8")).hexdigest(),
    }


def record_exit(supervisor: GitSupervisor, attempt: dict, exit_code: int = 0) -> dict:
    handle = attempt.get("_test_runc_handle")
    assert isinstance(handle, oci_worker.RuncLaunchHandle)
    receipt = handle.wait()
    assert receipt.returncode == exit_code
    return supervisor._sandbox_execution_record_exit(attempt["id"], attempt["claim_token"], receipt)


def running_attestation(
    supervisor: GitSupervisor,
    attempt: dict,
    init_pid: int = 303,
    *,
    register_collected: bool = True,
):
    row = supervisor._sandbox_execution_get(attempt["id"])
    assert row is not None and row["phase"] == "launched"
    init_start = 1303
    wrapper_cgroup = row["wrapper_cgroup_path"]
    slice_cgroup = row["attempt_slice_cgroup_path"]
    scope_cgroup = row["cgroup_path"]
    resource_limits = (
        json.loads(row["launch_plan_json"])["launch"]["resource_limits"]
        if row["launch_plan_json"]
        else {
            "memory_max_bytes": 1_073_741_824,
            "cpu_quota": 100_000,
            "cpu_period": 100_000,
            "pids_max": 256,
        }
    )

    def stat(pid: int, start: int) -> bytes:
        fields = [b"S", *([b"0"] * 18), str(start).encode("ascii")]
        return f"{pid} (worker (gate)) ".encode("ascii") + b" ".join(fields) + b"\n"

    snapshots = {
        row["monitor_pid"]: ProcessSnapshot(
            stat(row["monitor_pid"], 1101),
            f"0::{wrapper_cgroup}\n".encode("ascii"),
            stat(row["monitor_pid"], 1101),
        ),
        row["runc_client_pid"]: ProcessSnapshot(
            stat(
                row["runc_client_pid"],
                int(row["runc_client_identity"].rsplit(":", 1)[1]),
            ),
            f"0::{wrapper_cgroup}\n".encode("ascii"),
            stat(
                row["runc_client_pid"],
                int(row["runc_client_identity"].rsplit(":", 1)[1]),
            ),
        ),
        init_pid: ProcessSnapshot(
            stat(init_pid, init_start),
            f"0::{scope_cgroup}\n".encode("ascii"),
            stat(init_pid, init_start),
        ),
    }
    resource_control_files = {
        "memory.max": f"{resource_limits['memory_max_bytes']}\n".encode("ascii"),
        "cpu.max": (f"{resource_limits['cpu_quota']} {resource_limits['cpu_period']}\n").encode(
            "ascii"
        ),
        "pids.max": f"{resource_limits['pids_max']}\n".encode("ascii"),
    }
    expected = {
        "expected_container_id": row["container_id"],
        "expected_bundle_path": row["bundle_path"],
        "expected_monitor_pid": row["monitor_pid"],
        "expected_monitor_identity": row["monitor_identity"],
        "expected_runc_client_pid": row["runc_client_pid"],
        "expected_runc_client_identity": row["runc_client_identity"],
        "expected_wrapper_unit": row["wrapper_unit"],
        "expected_wrapper_invocation_id": row["wrapper_invocation_id"],
        "expected_attempt_slice_unit": row["attempt_slice_unit"],
        "expected_attempt_slice_invocation_id": row["attempt_slice_invocation_id"],
        "expected_scope_unit": row["scope_unit"],
        "expected_scope_invocation_id": row["scope_invocation_id"],
        "expected_cgroup_path": scope_cgroup,
        "expected_memory_max_bytes": resource_limits["memory_max_bytes"],
        "expected_cpu_quota": resource_limits["cpu_quota"],
        "expected_cpu_period": resource_limits["cpu_period"],
        "expected_pids_max": resource_limits["pids_max"],
    }
    runc_state = json.dumps(
        {
            "id": row["container_id"],
            "status": "running",
            "pid": init_pid,
            "bundle": row["bundle_path"],
        }
    ).encode("utf-8")
    wrapper_properties = (
        "ActiveState=active\n"
        f"ControlGroup={wrapper_cgroup}\n"
        f"Id={row['wrapper_unit']}\n"
        f"InvocationID={row['wrapper_invocation_id']}\n"
    ).encode("ascii")
    attempt_slice_properties = (
        "ActiveState=active\n"
        f"ControlGroup={slice_cgroup}\n"
        f"Id={row['attempt_slice_unit']}\n"
        f"InvocationID={row['attempt_slice_invocation_id']}\n"
    ).encode("ascii")
    scope_properties = (
        "ActiveState=active\n"
        f"ControlGroup={scope_cgroup}\n"
        f"Id={row['scope_unit']}\n"
        f"InvocationID={row['scope_invocation_id']}\n"
    ).encode("ascii")
    validation_args = {
        **expected,
        "runc_state": runc_state,
        "pid_file": f"{init_pid}\n".encode("ascii"),
        "process_snapshots": snapshots,
        "wrapper_properties": wrapper_properties,
        "attempt_slice_properties": attempt_slice_properties,
        "scope_properties": scope_properties,
        "resource_control_files": resource_control_files,
    }
    if not register_collected:
        return validate_running_runtime_attestation(**validation_args)

    state_root = Path(row["bundle_path"]).parent
    pid_file_path = state_root / "init.pid"
    pid_file_path.write_bytes(validation_args["pid_file"])
    pid_file_path.chmod(0o600)

    def read_proc_file(path: str) -> bytes:
        snapshot = snapshots[int(path.split("/")[2])]
        return snapshot.cgroup if path.endswith("/cgroup") else snapshot.stat_before

    collector_args = {
        key: value
        for key, value in validation_args.items()
        if key not in {"pid_file", "process_snapshots", "resource_control_files"}
    }
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(sandbox_attestation_module.sys, "platform", "linux")
        patch.setattr(sandbox_attestation_module, "_read_proc_file", read_proc_file)
        patch.setattr(
            sandbox_attestation_module,
            "read_cgroup_resource_controls",
            lambda _path: resource_control_files,
        )
        return collect_running_runtime_attestation(
            pid_file_path=pid_file_path,
            state_root=state_root,
            **collector_args,
        )


def record_running(supervisor: GitSupervisor, attempt: dict) -> dict:
    handle = attempt.get("_test_runc_handle")
    assert isinstance(handle, oci_worker.RuncLaunchHandle)
    attestation = running_attestation(supervisor, attempt)
    controls = {
        "memory.max": f"{attestation.memory_max_bytes}\n".encode("ascii"),
        "cpu.max": f"{attestation.cpu_quota} {attestation.cpu_period}\n".encode("ascii"),
        "pids.max": f"{attestation.pids_max}\n".encode("ascii"),
    }
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            sandbox_attestation_module,
            "read_cgroup_resource_controls",
            lambda _path: controls,
        )
        return supervisor._sandbox_execution_record_running(
            attempt["id"],
            attempt["claim_token"],
            attestation=attestation,
            runc_handle=handle,
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


def test_current_schema_requires_durable_workspace_and_private_path_binding_before_launch(
    repo: Path,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)

    assert SCHEMA_VERSION == 26
    assert row["phase"] == "reserved"
    assert row["workspace_binding_version"] == 1
    assert row["private_path_binding_version"] == 1
    assert row["execution_root_ino"] == Path(row["bundle_path"]).parent.stat().st_ino
    assert row["bundle_root_ino"] == Path(row["bundle_path"]).stat().st_ino
    assert row["state_root_ino"] == Path(row["state_path"]).stat().st_ino
    assert row["baseline_manifest_digest"]
    assert row["baseline_root_path"].endswith("/baseline")
    assert row["workspace_root_path"].endswith("/workspace")
    assert row["claim_token"] == attempt["claim_token"]
    assert row["backend"] == "oci-runc"
    assert row["runtime_version"] == "1.3.5"
    assert row["oci_version"] == "1.2.1"
    assert row["rootfs_digest"] == supervisor.config.oci_rootfs_pin.sha256
    assert row["rootfs_closure_digest"] == supervisor.config.oci_rootfs_pin.closure_sha256
    assert row["runc_executable_digest"] == supervisor.config.oci_runc_executable.sha256
    assert row["result_candidate_version"] == 0
    assert row["launch_plan_required"] == 1
    assert row["launch_plan_binding_version"] == 0
    assert row["bundle_path"].startswith(str((repo / ".acp" / "sandbox-executions").resolve()))
    assert row["state_path"].endswith("/state")

    with supervisor.connect() as connection:
        migration = dict(MIGRATIONS)[15]
        migration(connection)
        migration(connection)
        result_migration = dict(MIGRATIONS)[16]
        result_migration(connection)
        result_migration(connection)
        runtime_pin_migration = dict(MIGRATIONS)[17]
        runtime_pin_migration(connection)
        runtime_pin_migration(connection)
        private_path_migration = dict(MIGRATIONS)[18]
        private_path_migration(connection)
        private_path_migration(connection)
        kernel_wait_migration = dict(MIGRATIONS)[20]
        kernel_wait_migration(connection)
        kernel_wait_migration(connection)
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
        with _authorize_sandbox_reservation_write(
            connection,
            attempt["id"],
            attempt["claim_token"],
            "direct-insert",
            row["bundle_digest"],
            row["bundle_digest_semantics"],
        ):
            with pytest.raises(sqlite3.IntegrityError, match="must_start_reserved"):
                connection.execute(
                    """
                    INSERT INTO sandbox_executions
                      (attempt_id, claim_token, execution_id, backend, container_id,
                       bundle_digest, bundle_digest_semantics, rootfs_digest,
                       runtime_version, oci_version, bundle_path, state_path, phase,
                       created_at, updated_at)
                    SELECT attempt_id, claim_token, 'direct-insert', backend, 'direct-container',
                           bundle_digest, bundle_digest_semantics, rootfs_digest,
                           runtime_version, oci_version, bundle_path, state_path,
                           'cleanup_verified', created_at, updated_at
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
                    '1.3.5', '1.2.1', '/bundle', '/state', 'reserved', 'now', 'now')
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


def test_v19_to_v20_migration_preserves_legacy_check_and_does_not_backfill_evidence() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("CREATE TABLE attempts (id TEXT PRIMARY KEY, pid INTEGER)")
        connection.execute("INSERT INTO attempts (id, pid) VALUES ('attempt-1', NULL)")
        connection.execute("CREATE TABLE submissions (id TEXT PRIMARY KEY)")
        migrations = dict(MIGRATIONS)
        for version in (14, 15, 16, 17, 18):
            migrations[version](connection)
        connection.execute(
            """
            CREATE TABLE result_imports (
              id TEXT PRIMARY KEY,
              attempt_id TEXT NOT NULL REFERENCES attempts(id),
              claim_token INTEGER NOT NULL,
              worker_pid INTEGER,
              worker_identity TEXT NOT NULL DEFAULT '',
              worker_exit_receipt_json TEXT NOT NULL DEFAULT '',
              base_sha TEXT NOT NULL,
              tree_sha TEXT NOT NULL,
              baseline_digest TEXT NOT NULL,
              result_digest TEXT NOT NULL,
              change_digest TEXT NOT NULL,
              result_ref TEXT NOT NULL UNIQUE,
              commit_timestamp INTEGER NOT NULL,
              commit_sha TEXT NOT NULL,
              phase TEXT NOT NULL,
              submission_id TEXT REFERENCES submissions(id),
              error TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              staging_path TEXT NOT NULL DEFAULT '',
              object_ids_json TEXT NOT NULL DEFAULT '[]',
              promote_object_ids_json TEXT NOT NULL DEFAULT '[]'
            )
            """
        )
        migrations[19](connection)
        connection.execute(
            """
            INSERT INTO sandbox_executions
              (attempt_id, claim_token, execution_id, backend, container_id,
               bundle_digest, rootfs_digest, rootfs_closure_digest,
               runc_executable_digest, runtime_version, oci_version,
               bundle_path, state_path, phase, created_at, updated_at)
            VALUES (?, 1, 'execution-1', 'oci-runc', 'container-1', ?, ?, ?, ?,
                    '1.3.5', '1.2.1', '/bundle', '/state', 'reserved', 'now', 'now')
            """,
            ("attempt-1", "a" * 64, "b" * 64, "c" * 64, "d" * 64),
        )
        before_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'sandbox_executions'"
        ).fetchone()["sql"]
        assert "runc_exit_observed_by = 'runc_client_popen_wait'" in before_sql

        migrations[20](connection)
        migrations[20](connection)
        migrations[21](connection)
        migrations[21](connection)

        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(sandbox_executions)")
        }
        assert "runc_exit_evidence_source" in columns
        migrated = connection.execute(
            "SELECT runc_exit_observed_by, runc_exit_evidence_source "
            "FROM sandbox_executions WHERE attempt_id = 'attempt-1'"
        ).fetchone()
        assert migrated["runc_exit_observed_by"] == ""
        assert migrated["runc_exit_evidence_source"] == ""
        after_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'sandbox_executions'"
        ).fetchone()["sql"]
        assert "runc_exit_observed_by = 'runc_client_popen_wait'" in after_sql
        candidate_trigger = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' "
            "AND name = 'sandbox_result_candidate_write_once'"
        ).fetchone()["sql"]
        assert "NEW.runc_exit_evidence_source = 'runc_client_kernel_waitpid'" in candidate_trigger
        assert "NEW.runc_exit_observed_by = 'runc_client_kernel_waitpid'" not in candidate_trigger
        receipt_guard = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' "
            "AND name = 'sandbox_execution_exit_receipt_guard'"
        ).fetchone()["sql"]
        assert "acp_sandbox_exit_receipt_authorized" in receipt_guard

        with pytest.raises(sqlite3.IntegrityError, match="evidence"):
            connection.execute(
                "UPDATE sandbox_executions SET runc_exit_evidence_source = "
                "'runc_client_kernel_waitpid' WHERE attempt_id = 'attempt-1'"
            )
    finally:
        connection.close()


def test_v16_to_v18_migrations_keep_unknown_content_and_path_pins_non_authorizing() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("CREATE TABLE attempts (id TEXT PRIMARY KEY, pid INTEGER)")
        connection.execute("INSERT INTO attempts (id, pid) VALUES ('attempt-1', NULL)")
        migrations = dict(MIGRATIONS)
        for version in (14, 15, 16):
            migrations[version](connection)
        connection.execute(
            """
            INSERT INTO sandbox_executions
              (attempt_id, claim_token, execution_id, backend, container_id,
               bundle_digest, rootfs_digest, runtime_version, oci_version,
               bundle_path, state_path, phase, created_at, updated_at)
            VALUES (?, 1, 'execution-1', 'oci-runc', 'container-1', ?, ?,
                    '1.3.5', '1.2.1', '/bundle', '/state', 'reserved', 'now', 'now')
            """,
            ("attempt-1", "a" * 64, "b" * 64),
        )

        migrations[17](connection)
        migrations[17](connection)
        migrated = connection.execute(
            "SELECT rootfs_closure_digest, runc_executable_digest "
            "FROM sandbox_executions WHERE attempt_id = 'attempt-1'"
        ).fetchone()
        assert migrated["rootfs_closure_digest"] == ""
        assert migrated["runc_executable_digest"] == ""

        connection.execute(
            """
            UPDATE sandbox_executions
            SET workspace_binding_version = 1,
                baseline_root_path = '/baseline', baseline_root_dev = 1,
                baseline_root_ino = 2, workspace_root_path = '/workspace',
                workspace_root_dev = 1, workspace_root_ino = 3,
                baseline_manifest_json = '{}', baseline_manifest_digest = ?
            WHERE attempt_id = 'attempt-1'
            """,
            ("c" * 64,),
        )
        migrations[18](connection)
        migrations[18](connection)
        legacy_path_binding = connection.execute(
            "SELECT private_path_binding_version, execution_root_ino, bundle_root_ino, "
            "state_root_ino FROM sandbox_executions WHERE attempt_id = 'attempt-1'"
        ).fetchone()
        assert legacy_path_binding["private_path_binding_version"] == 0
        assert legacy_path_binding["execution_root_ino"] is None
        with pytest.raises(sqlite3.IntegrityError, match="sandbox_private_path_binding_immutable"):
            connection.execute(
                "UPDATE sandbox_executions SET private_path_binding_version = 1, "
                "execution_root_dev = 1, execution_root_ino = 2, bundle_root_dev = 1, "
                "bundle_root_ino = 3, state_root_dev = 1, state_root_ino = 4 "
                "WHERE attempt_id = 'attempt-1'"
            )
        with pytest.raises(
            sqlite3.IntegrityError,
            match="sandbox_execution_(content_pins|private_paths)_required",
        ):
            connection.execute(
                """
                UPDATE sandbox_executions
                SET phase = 'launched', monitor_pid = 101,
                    monitor_identity = 'linux:101:1101', runc_client_pid = 202,
                    runc_client_identity = 'linux:202:1202', wrapper_unit = 'acp-worker.service',
                    wrapper_invocation_id = '11111111111111111111111111111111',
                    scope_unit = 'acp-container.scope',
                    scope_invocation_id = '22222222222222222222222222222222',
                    cgroup_path = '/user.slice/acp-container.scope'
                WHERE attempt_id = 'attempt-1'
                """
            )
    finally:
        connection.close()


def test_sandbox_launch_cannot_bypass_workspace_binding(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    runtime_claims = configured_sandbox_claims(supervisor)
    row = supervisor._sandbox_execution_reserve(
        attempt["id"],
        attempt["claim_token"],
        **runtime_claims,
    )
    assert row["workspace_binding_version"] == 0

    with pytest.raises(SupervisorError) as error:
        record_launch(supervisor, attempt)
    assert error.value.code == "sandbox_workspace_unbound"

    with (
        supervisor.connect() as connection,
        pytest.raises(
            sqlite3.IntegrityError,
            match=(
                "workspace_binding_required|private_paths_required|"
                "sandbox_execution_launch_plan_required|attempt_slice_identity_required|"
                "phase_transition_invalid"
            ),
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


@pytest.mark.parametrize("phase", ["reserved", "launched"])
def test_v21_rows_migrate_unattested_and_remain_fail_closed(repo: Path, phase: str) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    execution = reserve(supervisor, attempt)
    handle = _test_runc_handle(target=_test_runc_target(execution))
    if phase == "launched":
        record_launch(supervisor, attempt, runc_handle=handle)

    # Recreate the pre-v22 table: the migration must not infer that a historical
    # caller-supplied digest was a trusted config/argv binding.
    with supervisor.connect() as connection:
        for trigger in (
            "sandbox_launch_plan_insert_guard",
            "sandbox_launch_plan_required_immutable",
            "sandbox_launch_plan_write_once",
            "sandbox_execution_launch_requires_plan",
            "sandbox_execution_running_requires_plan",
            "sandbox_execution_exit_requires_plan",
        ):
            connection.execute(f"DROP TRIGGER {trigger}")
        for column in (
            "launch_plan_digest",
            "launch_argv_digest",
            "launch_config_digest",
            "launch_plan_json",
            "launch_plan_binding_version",
            "launch_plan_required",
        ):
            connection.execute(f"ALTER TABLE sandbox_executions DROP COLUMN {column}")
        connection.execute("UPDATE meta SET value = '21' WHERE key = 'schema_version'")

    migrated = GitSupervisor(repo)
    assert migrated.schema_version_on_open == 21
    legacy = migrated._sandbox_execution_get(attempt["id"])
    assert legacy["phase"] == phase
    assert legacy["launch_plan_required"] == 0
    assert legacy["launch_plan_binding_version"] == 0
    assert legacy["launch_plan_json"] == ""
    assert legacy["launch_plan_digest"] == ""

    if phase == "reserved":
        with pytest.raises(SupervisorError) as error:
            record_launch(migrated, attempt, runc_handle=handle)
    else:
        with pytest.raises(SupervisorError) as error:
            migrated._sandbox_execution_record_running(
                attempt["id"],
                attempt["claim_token"],
                attestation=running_attestation(migrated, attempt),
                runc_handle=handle,
            )
    assert error.value.code == "sandbox_execution_launch_plan_required"
    assert migrated._sandbox_execution_get(attempt["id"])["phase"] == phase


def test_reservation_requires_exact_live_fence_and_no_registered_direct_worker(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    runtime_claims = configured_sandbox_claims(supervisor)

    with pytest.raises(SupervisorError) as stale:
        supervisor._sandbox_execution_reserve(
            attempt["id"],
            attempt["claim_token"] + 1,
            **runtime_claims,
        )
    assert stale.value.code == "stale_fencing_token"

    for field in ("rootfs_closure_digest", "runc_executable_digest"):
        options = dict(runtime_claims)
        options[field] = "not-a-digest"
        with pytest.raises(SupervisorError) as malformed:
            supervisor._sandbox_execution_reserve(attempt["id"], attempt["claim_token"], **options)
        assert malformed.value.code == "sandbox_execution_invalid"
    assert supervisor._sandbox_execution_get(attempt["id"]) is None

    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET pid = 12345, pid_identity = 'direct-worker' WHERE id = ?",
            (attempt["id"],),
        )
    with pytest.raises(SupervisorError) as registered:
        reserve(supervisor, attempt)
    assert registered.value.code == "worker_already_running"
    assert supervisor._sandbox_execution_get(attempt["id"]) is None


def test_sandbox_reservation_requires_configured_sealed_runtime_pins(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    with pytest.raises(SupervisorError) as missing:
        supervisor._sandbox_execution_reserve(
            attempt["id"],
            attempt["claim_token"],
            rootfs_digest="b" * 64,
            rootfs_closure_digest="c" * 64,
            runc_executable_digest="d" * 64,
            runtime_version="1.3.5",
            oci_version="1.2.1",
        )
    assert missing.value.code == "sandbox_execution_pin_unavailable"
    assert supervisor._sandbox_execution_get(attempt["id"]) is None


@pytest.mark.parametrize(
    "field",
    (
        "rootfs_digest",
        "rootfs_closure_digest",
        "runc_executable_digest",
        "runtime_version",
    ),
)
def test_sandbox_reservation_binds_claims_to_configured_runtime_pins(
    repo: Path, field: str
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    runtime_claims = configured_sandbox_claims(supervisor)
    mismatched_claims = dict(runtime_claims)
    original = mismatched_claims[field]
    mismatched_claims[field] = (
        "1.3.4"
        if field == "runtime_version"
        else ("0" if original[0] != "0" else "1") + original[1:]
    )

    with pytest.raises(SupervisorError) as mismatch:
        supervisor._sandbox_execution_reserve(
            attempt["id"],
            attempt["claim_token"],
            **mismatched_claims,
        )
    assert mismatch.value.code == "sandbox_execution_pin_mismatch"
    assert supervisor._sandbox_execution_get(attempt["id"]) is None


def test_journal_reservation_prevents_later_direct_worker_launch(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)

    with pytest.raises(SupervisorError) as launch:
        supervisor._reserve_worker_launch(
            attempt["id"], attempt["claim_token"], ".acp/logs/direct.log", None
        )
    assert launch.value.code == "sandbox_execution_reserved"
    assert supervisor.attempt(attempt["id"])["pid"] is None

    before = supervisor.attempt(attempt["id"])
    # Exercise a later configuration downgrade/restart: the journal survives,
    # but the current process no longer has an OCI pin and must not touch the
    # attempt through the direct-worker path.
    supervisor.config = replace(
        supervisor.config,
        oci_rootfs_pin=None,
        oci_runc_executable=None,
        oci_runc_version=None,
    )

    def direct_launch_must_not_start(*_args, **_kwargs):
        pytest.fail("a journaled sandbox reservation must stop direct worker setup")

    monkeypatch.setattr(supervisor, "heartbeat", direct_launch_must_not_start)
    monkeypatch.setattr(supervisor, "_reserve_worker_launch", direct_launch_must_not_start)
    with pytest.raises(SupervisorError) as worker:
        supervisor.run_worker(attempt["id"], attempt["claim_token"], ["/bin/true"])

    assert worker.value.code == "sandbox_execution_reserved"
    after = supervisor.attempt(attempt["id"])
    assert after["pid"] is None
    assert after["updated_at"] == before["updated_at"]


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


def test_journaled_sandbox_never_aliases_into_direct_worker_result_receipts(
    repo: Path,
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    result_root = tmp_path_factory.mktemp("worker-result")
    baseline, change_set = result_fixture(attempt, result_root)

    # Simulate an open eligibility gate to isolate the independent identity
    # source check. It must reject the direct-worker route before PID or
    # worker.exit receipts can be consulted, even after a future verifier exists.
    monkeypatch.setattr(
        claims_module,
        "_require_sandbox_execution_result_eligible",
        lambda _connection, _attempt_id: None,
    )
    with pytest.raises(SupervisorError) as imported:
        supervisor.import_worker_result(attempt["id"], attempt["claim_token"], baseline, change_set)

    assert imported.value.code == "sandbox_result_import_route_required"
    with supervisor.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM result_imports").fetchone()[0] == 0

        # Deliberately bypass the new database guard so the application-level
        # recovery/submit fence also gets exercised against a corrupt legacy row.
        connection.execute("DROP TRIGGER result_import_direct_source_insert_guard")
        connection.execute(
            """
            INSERT INTO result_imports
              (id, attempt_id, claim_token, worker_pid, worker_identity,
               worker_exit_receipt_json, base_sha, tree_sha, baseline_digest,
               result_digest, change_digest, result_ref, commit_timestamp,
               commit_sha, phase, created_at, updated_at)
            VALUES ('untrusted-direct-import', ?, ?, 202, 'synthetic-pid-identity', '{}',
                    'base', 'tree', 'baseline', 'result', 'change', 'refs/acp/untrusted',
                    0, 'commit', 'prepared', 'now', 'now')
            """,
            (attempt["id"], attempt["claim_token"]),
        )

    staging_cleanup_called = False

    def record_staging_cleanup() -> None:
        nonlocal staging_cleanup_called
        staging_cleanup_called = True

    monkeypatch.setattr(supervisor, "_cleanup_result_import_staging_locked", record_staging_cleanup)
    with pytest.raises(SupervisorError) as recovered:
        supervisor.recover_worker_result_import("untrusted-direct-import")
    assert recovered.value.code == "sandbox_result_import_route_required"
    assert staging_cleanup_called is False

    with pytest.raises(SupervisorError) as submitted:
        supervisor._submit(
            attempt["id"],
            attempt["claim_token"],
            expected_worker_pid=202,
            credential=None,
            imported_result_id="untrusted-direct-import",
        )
    assert submitted.value.code == "sandbox_result_import_route_required"


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
            execution = {
                "attempt_id": attempt_id,
                "claim_token": attempt["claim_token"],
                "execution_id": "race-execution",
                "backend": "oci-runc",
                "container_id": "race-container",
                "rootfs_digest": "a" * 64,
                "rootfs_closure_digest": "b" * 64,
                "runc_executable_digest": "c" * 64,
                "runtime_version": "test-runc",
                "oci_version": "1.2.1",
                "bundle_path": "/bundle",
                "state_path": "/state",
            }
            bundle_digest = journal_module._sandbox_reservation_bundle_digest(execution)
            with _authorize_sandbox_reservation_write(
                connection,
                attempt_id,
                attempt["claim_token"],
                execution["execution_id"],
                bundle_digest,
                "oci-reservation-v1",
            ):
                connection.execute(
                    """
                    INSERT INTO sandbox_executions
                      (attempt_id, claim_token, execution_id, backend, container_id,
                       bundle_digest, bundle_digest_semantics, rootfs_digest,
                       rootfs_closure_digest, runc_executable_digest, runtime_version,
                       oci_version, bundle_path, state_path, phase, created_at, updated_at)
                    VALUES (?, ?, ?, 'oci-runc', ?, ?, 'oci-reservation-v1', ?, ?, ?, ?,
                            ?, ?, ?, 'reserved', ?, ?)
                    """,
                    (
                        execution["attempt_id"],
                        execution["claim_token"],
                        execution["execution_id"],
                        execution["container_id"],
                        bundle_digest,
                        execution["rootfs_digest"],
                        execution["rootfs_closure_digest"],
                        execution["runc_executable_digest"],
                        execution["runtime_version"],
                        execution["oci_version"],
                        execution["bundle_path"],
                        execution["state_path"],
                        stamp,
                        stamp,
                    ),
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
        # Simulate a corrupt pre-v19 database row; current schema writes reject it.
        connection.execute("DROP TRIGGER result_import_direct_source_insert_guard")
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
    # Provision the shared config once; the race under test is journal
    # reservation, not concurrent issuance of process-local OCI pin handles.
    configured_sandbox_claims(supervisor)
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
        "monitor_identity = 'linux:101:1101', runc_client_pid = 202, "
        "runc_client_identity = 'linux:202:1202', wrapper_unit = 'acp-worker.service', "
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
                "init_identity = 'linux:303:1303' WHERE attempt_id = ?",
                (attempt["id"],),
            )
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"


def test_recorded_execution_evidence_is_immutable(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    record_launch(supervisor, attempt)
    record_running(supervisor, attempt)

    mutations = (
        ("rootfs_closure_digest = 'e' || substr(rootfs_closure_digest, 2)", "identity"),
        ("runc_executable_digest = 'e' || substr(runc_executable_digest, 2)", "identity"),
        ("monitor_pid = 404", "evidence"),
        ("monitor_identity = 'replacement-monitor'", "evidence"),
        ("scope_invocation_id = '33333333333333333333333333333333'", "evidence"),
        ("cgroup_path = '/different/scope'", "evidence"),
        ("init_pid = 505", "evidence"),
    )
    for mutation, identity_or_evidence in mutations:
        expected_error = (
            "sandbox_execution_identity_immutable"
            if identity_or_evidence == "identity"
            else "sandbox_execution_evidence"
        )
        with supervisor.connect() as connection:
            with pytest.raises(
                sqlite3.IntegrityError,
                match=expected_error,
            ):
                connection.execute(
                    f"UPDATE sandbox_executions SET {mutation} WHERE attempt_id = ?",
                    (attempt["id"],),
                )

    record_exit(supervisor, attempt)
    with supervisor.connect() as connection:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="sandbox_execution_exit_evidence_write_requires_exit",
        ):
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
        with pytest.raises(sqlite3.IntegrityError, match="sandbox_private_path_binding_immutable"):
            connection.execute(
                "UPDATE sandbox_executions SET bundle_root_ino = bundle_root_ino + 1 "
                "WHERE attempt_id = ?",
                (attempt["id"],),
            )


def test_transition_order_keeps_monitor_runc_and_init_identities_distinct(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)

    with pytest.raises(SupervisorError) as out_of_order:
        supervisor._sandbox_execution_record_running(
            attempt["id"], attempt["claim_token"], attestation=None
        )
    assert out_of_order.value.code == "sandbox_execution_transition_invalid"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "reserved"

    row = record_launch(supervisor, attempt)
    assert row["phase"] == "launched"
    with pytest.raises(SupervisorError) as pid_alias:
        supervisor._sandbox_execution_record_running(
            attempt["id"],
            attempt["claim_token"],
            attestation=replace(running_attestation(supervisor, attempt), init_pid=202),
        )
    assert pid_alias.value.code == "sandbox_runtime_attestation_invalid"

    row = record_running(supervisor, attempt)
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

    with pytest.raises(SupervisorError) as caller_supplied:
        supervisor._sandbox_execution_record_exit(attempt["id"], attempt["claim_token"], 0)
    assert caller_supplied.value.code == "sandbox_execution_wait_receipt_required"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "stopping"

    row = record_exit(supervisor, attempt)
    assert row["phase"] == "exited"
    assert row["runc_exit_code"] == 0
    assert row["runc_exit_observed_by"] == "runc_client_kernel_waitpid"
    assert row["runc_exit_evidence_source"] == "runc_client_kernel_waitpid"
    with supervisor.connect() as connection:
        stored = connection.execute(
            "SELECT runc_exit_observed_by, runc_exit_evidence_source "
            "FROM sandbox_executions WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()
    assert stored["runc_exit_observed_by"] == "runc_client_popen_wait"
    assert stored["runc_exit_evidence_source"] == "runc_client_kernel_waitpid"
    assert supervisor.verify_event_chain()["ok"] is True


def test_exit_evidence_cannot_be_stamped_before_kernel_wait(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    record_launch(supervisor, attempt)

    with supervisor.connect() as connection:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="sandbox_execution_exit_evidence_write_requires_exit",
        ):
            connection.execute(
                """
                UPDATE sandbox_executions
                SET phase = 'running', init_pid = 4242, init_identity = 'synthetic-start',
                    runc_exit_evidence_source = 'runc_client_kernel_waitpid'
                WHERE attempt_id = ?
                """,
                (attempt["id"],),
            )

    still_launched = supervisor._sandbox_execution_get(attempt["id"])
    assert still_launched is not None
    assert still_launched["phase"] == "launched"
    assert still_launched["runc_exit_evidence_source"] == ""

    record_running(supervisor, attempt)
    exited = record_exit(supervisor, attempt)
    assert exited["runc_exit_evidence_source"] == "runc_client_kernel_waitpid"


def test_generic_transition_cannot_forge_exit_without_registered_wait_receipt() -> None:
    # Exit persistence is not part of the generic transition surface. Keep this
    # regression independent of a Git checkout so it runs on the NAS Linux lane.
    supervisor = GitSupervisor.__new__(GitSupervisor)
    attempt_id = "sandbox-attempt-receipt-gate"
    claim_token = 7
    with pytest.raises(SupervisorError) as rejected:
        supervisor._sandbox_execution_transition(
            attempt_id,
            claim_token,
            expected_phase="launched",
            next_phase="exited",
            updates={
                "runc_exit_code": 0,
                "runc_exit_observed_by": "runc_client_popen_wait",
                "runc_exit_evidence_source": "runc_client_kernel_waitpid",
            },
            event_type="sandbox.execution_exited",
            event_payload={
                "runc_exit_code": 0,
                "observed_by": "runc_client_kernel_waitpid",
            },
        )
    assert rejected.value.code == "sandbox_execution_transition_invalid"


def test_sql_exit_transition_cannot_forge_kernel_wait_receipt(tmp_path: Path) -> None:
    database_path = tmp_path / "receipt-guard.db"
    raw_connection = sqlite3.connect(database_path)
    try:
        raw_connection.execute(
            """
            CREATE TABLE sandbox_executions (
              attempt_id TEXT PRIMARY KEY,
              claim_token INTEGER NOT NULL,
              execution_id TEXT NOT NULL,
              phase TEXT NOT NULL,
              runc_client_pid INTEGER,
              runc_client_identity TEXT NOT NULL,
              runc_exit_code INTEGER,
              runc_exit_observed_by TEXT NOT NULL DEFAULT '',
              runc_exit_evidence_source TEXT NOT NULL DEFAULT ''
            )
            """
        )
        raw_connection.commit()
    finally:
        raw_connection.close()

    supervisor = GitSupervisor.__new__(GitSupervisor)
    supervisor.read_only = False
    supervisor.db_path = database_path
    with supervisor.connect() as connection:
        dict(MIGRATIONS)[21](connection)
        connection.execute(
            "INSERT INTO sandbox_executions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "sandbox-attempt-sql-guard",
                11,
                "sandbox-execution-sql-guard",
                "launched",
                202,
                "linux:202:1202",
                None,
                "",
                "",
            ),
        )

    with supervisor.connect() as connection:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="sandbox_execution_wait_receipt_required",
        ):
            connection.execute(
                "UPDATE sandbox_executions SET runc_exit_code = 0, "
                "runc_exit_observed_by = 'runc_client_popen_wait', "
                "runc_exit_evidence_source = 'runc_client_kernel_waitpid', "
                "phase = 'exited' WHERE attempt_id = ?",
                ("sandbox-attempt-sql-guard",),
            )

    with supervisor.connect() as connection:
        row = connection.execute(
            "SELECT phase, runc_exit_evidence_source FROM sandbox_executions WHERE attempt_id = ?",
            ("sandbox-attempt-sql-guard",),
        ).fetchone()
    assert row["phase"] == "launched"
    assert row["runc_exit_evidence_source"] == ""


def test_runc_wait_receipt_must_match_durable_pid_start_identity(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    record_launch(supervisor, attempt)
    record_running(supervisor, attempt)

    execution = supervisor._sandbox_execution_get(attempt["id"])
    assert execution is not None
    wrong_handle = _test_runc_handle(target=_test_runc_target(execution), start_ticks=9999)
    oci_worker._runc_launch_handle_bind_execution(
        wrong_handle,
        attempt["id"],
        attempt["claim_token"],
        execution["execution_id"] + "-different",
    )
    reused_pid = wrong_handle.wait()
    with pytest.raises(SupervisorError) as mismatched:
        supervisor._sandbox_execution_record_exit(attempt["id"], attempt["claim_token"], reused_pid)

    assert mismatched.value.code == "sandbox_execution_wait_receipt_stale"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "running"
    assert record_exit(supervisor, attempt)["phase"] == "exited"


@pytest.mark.parametrize("path_field", ["execution_root", "bundle_path", "state_path"])
@pytest.mark.parametrize("replacement_kind", ["symlink", "directory"])
def test_workspace_restore_and_launch_reject_replaced_private_runtime_paths(
    repo: Path,
    tmp_path: Path,
    path_field: str,
    replacement_kind: str,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)
    runtime_path = (
        Path(row["bundle_path"]).parent if path_field == "execution_root" else Path(row[path_field])
    )
    moved_path = runtime_path.with_name(f"{runtime_path.name}-original")
    runtime_path.rename(moved_path)
    if replacement_kind == "symlink":
        runtime_path.symlink_to(tmp_path, target_is_directory=True)
    else:
        runtime_path.mkdir(mode=0o700)
        if path_field == "execution_root":
            (runtime_path / "bundle").mkdir(mode=0o700)
            (runtime_path / "state").mkdir(mode=0o700)

    with pytest.raises(SupervisorError) as restore:
        supervisor._sandbox_execution_restore_workspace_binding(
            attempt["id"], attempt["claim_token"]
        )
    assert restore.value.code in {
        "sandbox_private_path_invalid",
        "sandbox_private_path_conflict",
        "invalid_snapshot",
    }

    with pytest.raises(SupervisorError) as launch:
        record_launch(supervisor, attempt)
    assert launch.value.code in {
        "sandbox_private_path_invalid",
        "invalid_snapshot",
        "unsafe_workspace_root",
    }


def test_private_runtime_path_binding_is_required_and_write_once(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)

    with supervisor.connect() as connection:
        with pytest.raises(sqlite3.IntegrityError, match="sandbox_private_path_binding_immutable"):
            connection.execute(
                "UPDATE sandbox_executions SET state_root_ino = state_root_ino + 1 "
                "WHERE attempt_id = ?",
                (attempt["id"],),
            )

    restored = supervisor._sandbox_execution_restore_workspace_binding(
        attempt["id"], attempt["claim_token"]
    )
    assert restored["private_path_binding_version"] == 1
    assert restored["bundle_root_inode"] == row["bundle_root_ino"]
    assert restored["state_root_inode"] == row["state_root_ino"]
    assert supervisor.verify_event_chain()["ok"] is True


def test_running_transition_requires_intact_attestation_bound_to_launch(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    record_launch(supervisor, attempt)

    with pytest.raises(SupervisorError) as untyped:
        supervisor._sandbox_execution_record_running(
            attempt["id"], attempt["claim_token"], attestation={"init_pid": 303}
        )
    assert untyped.value.code == "sandbox_runtime_attestation_invalid"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"

    receipt = running_attestation(supervisor, attempt)
    tampered = replace(receipt, init_identity="linux:303:9999")
    with pytest.raises(SupervisorError) as invalid:
        supervisor._sandbox_execution_record_running(
            attempt["id"], attempt["claim_token"], attestation=tampered
        )
    assert invalid.value.code == "sandbox_runtime_attestation_invalid"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"

    stale = replace(receipt, container_id="different-container")
    stale_payload = stale.audit_payload()
    stale_payload.pop("evidence_sha256")
    stale = replace(
        stale,
        evidence_sha256=hashlib.sha256(canonical_json(stale_payload).encode("utf-8")).hexdigest(),
    )
    assert not running_attestation_is_self_consistent(stale)
    with pytest.raises(SupervisorError) as mismatched_launch:
        supervisor._sandbox_execution_record_running(
            attempt["id"], attempt["claim_token"], attestation=stale
        )
    assert mismatched_launch.value.code == "sandbox_runtime_attestation_invalid"
    assert supervisor._sandbox_execution_get(attempt["id"])["phase"] == "launched"

    monkeypatch.setattr(
        sandbox_attestation_module,
        "read_cgroup_resource_controls",
        lambda _path: {
            "memory.max": f"{receipt.memory_max_bytes}\n".encode("ascii"),
            "cpu.max": f"{receipt.cpu_quota} {receipt.cpu_period}\n".encode("ascii"),
            "pids.max": f"{receipt.pids_max}\n".encode("ascii"),
        },
    )
    running = supervisor._sandbox_execution_record_running(
        attempt["id"],
        attempt["claim_token"],
        attestation=receipt,
        runc_handle=attempt["_test_runc_handle"],
    )
    assert running["phase"] == "running"
    assert running["init_pid"] == 303
    assert running["init_identity"] == "linux:303:1303"


def test_reported_cleanup_is_not_verification_and_cannot_release_attempt(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    record_launch(supervisor, attempt)
    record_running(supervisor, attempt)
    record_exit(supervisor, attempt)

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
    record_running(supervisor, attempt)
    (workspace / "alpha.txt").write_text("candidate result\n", encoding="utf-8")
    record_exit(supervisor, attempt)
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
        "observed_by": "runc_client_kernel_waitpid",
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


def test_sandbox_import_route_fails_closed_before_cleanup_verification(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)
    record_launch(supervisor, attempt)
    record_running(supervisor, attempt)
    (Path(row["workspace_root_path"]) / "alpha.txt").write_text(
        "sandbox result\n", encoding="utf-8"
    )
    record_exit(supervisor, attempt)
    supervisor._sandbox_execution_record_cleanup_report(
        attempt["id"], attempt["claim_token"], cleanup_receipt(supervisor, attempt["id"])
    )

    with pytest.raises(SupervisorError) as rejected:
        supervisor.import_sandbox_execution_result(attempt["id"], attempt["claim_token"])

    assert rejected.value.code == "sandbox_result_unverified"
    assert supervisor._sandbox_execution_get(attempt["id"])["result_candidate_version"] == 0
    with supervisor.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM result_imports").fetchone()[0] == 0


def test_sandbox_import_rejects_stale_claim_before_candidate_capture(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET claim_token = claim_token + 1 WHERE id = ?",
            (attempt["id"],),
        )
        connection.commit()

    with pytest.raises(SupervisorError) as stale:
        supervisor.import_sandbox_execution_result(attempt["id"], attempt["claim_token"])

    assert stale.value.code == "stale_fencing_token"
    assert supervisor._sandbox_execution_get(attempt["id"])["result_candidate_version"] == 0
    with supervisor.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM result_imports").fetchone()[0] == 0


def test_sandbox_import_uses_distinct_source_and_recovers_published_ref(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)
    record_launch(supervisor, attempt)
    record_running(supervisor, attempt)
    (Path(row["workspace_root_path"]) / "alpha.txt").write_text(
        "sandbox result\n", encoding="utf-8"
    )
    record_exit(supervisor, attempt)
    supervisor._sandbox_execution_record_cleanup_report(
        attempt["id"], attempt["claim_token"], cleanup_receipt(supervisor, attempt["id"])
    )
    supervisor._sandbox_execution_capture_result_candidate(attempt["id"], attempt["claim_token"])

    # Exercise the downstream import boundary with a synthetic already-verified
    # journal state. No production method currently writes cleanup_verified, so
    # this is not cleanup-verifier or live-runtime evidence.
    Path(row["bundle_path"]).rmdir()
    Path(row["state_path"]).rmdir()
    with supervisor.connect() as connection:
        connection.execute("DROP TRIGGER sandbox_execution_phase_transition")
        connection.execute(
            "UPDATE sandbox_executions SET phase = 'cleanup_verified' WHERE attempt_id = ?",
            (attempt["id"],),
        )
        # Model a corrupt/legacy mixed-source journal with a different claim
        # token and result digest; healthy-schema guards normally prevent it.
        connection.execute("DROP TRIGGER result_import_direct_source_insert_guard")
        connection.execute(
            """
            INSERT INTO result_imports
              (id, attempt_id, claim_token, source_kind, worker_pid, worker_identity,
               worker_exit_receipt_json, base_sha, tree_sha, baseline_digest,
               result_digest, change_digest, result_ref, commit_timestamp,
               commit_sha, phase, created_at, updated_at)
            VALUES ('corrupt-direct-import', ?, ?, 'direct_worker', 202,
                    'synthetic-pid-identity', '{}', 'base', 'tree', 'baseline',
                    ?, 'changes', 'refs/acp/corrupt-direct', 0, 'commit',
                    'prepared', 'now', 'now')
            """,
            (attempt["id"], attempt["claim_token"] + 1, "f" * 64),
        )
        connection.commit()

    with pytest.raises(SupervisorError) as mixed_source:
        supervisor.import_sandbox_execution_result(attempt["id"], attempt["claim_token"])
    assert mixed_source.value.code == "sandbox_result_source_mismatch"
    with supervisor.connect() as connection:
        connection.execute("DELETE FROM result_imports WHERE id = 'corrupt-direct-import'")

    def interrupt_before_submit(*args, **kwargs):
        raise RuntimeError("simulated crash after result ref publication")

    monkeypatch.setattr(supervisor, "_submit", interrupt_before_submit)
    with pytest.raises(RuntimeError, match="simulated crash"):
        supervisor.import_sandbox_execution_result(attempt["id"], attempt["claim_token"])

    with supervisor.connect() as connection:
        imported = connection.execute(
            "SELECT * FROM result_imports WHERE attempt_id = ?", (attempt["id"],)
        ).fetchone()
        assert imported["phase"] == "ref_published"
        assert imported["source_kind"] == "sandbox_execution"
        assert imported["worker_pid"] is None
        assert imported["worker_identity"] == ""
        assert imported["worker_exit_receipt_json"] == ""
        assert imported["sandbox_execution_id"] == row["execution_id"]
        assert len(imported["sandbox_cleanup_receipt_digest"]) == 64

    reopened = GitSupervisor(repo)
    expected_cleanup_digest = imported["sandbox_cleanup_receipt_digest"]
    with reopened.connect() as connection:
        connection.execute("DROP TRIGGER result_import_source_identity_immutable")
        connection.execute(
            "UPDATE result_imports SET sandbox_cleanup_receipt_digest = ? WHERE id = ?",
            ("a" * 64, imported["id"]),
        )
        connection.commit()
    with pytest.raises(SupervisorError) as digest_conflict:
        reopened.recover_worker_result_import(imported["id"])
    assert digest_conflict.value.code == "sandbox_result_source_mismatch"
    with reopened.connect() as connection:
        persisted = connection.execute(
            "SELECT phase FROM result_imports WHERE id = ?", (imported["id"],)
        ).fetchone()
        assert persisted["phase"] == "ref_published"
        connection.execute(
            "UPDATE result_imports SET sandbox_cleanup_receipt_digest = ? WHERE id = ?",
            (expected_cleanup_digest, imported["id"]),
        )
        connection.commit()

    with reopened.connect() as connection:
        connection.execute(
            """
            INSERT INTO result_imports
              (id, attempt_id, claim_token, source_kind, worker_pid, worker_identity,
               worker_exit_receipt_json, base_sha, tree_sha, baseline_digest,
               result_digest, change_digest, result_ref, commit_timestamp,
               commit_sha, phase, created_at, updated_at)
            VALUES ('corrupt-direct-recovery', ?, ?, 'direct_worker', 203,
                    'other-pid-identity', '{}', 'base', 'tree', 'baseline',
                    ?, 'changes', 'refs/acp/corrupt-recovery', 0, 'commit',
                    'prepared', 'now', 'now')
            """,
            (attempt["id"], attempt["claim_token"] + 1, "e" * 64),
        )
        connection.commit()
    with pytest.raises(SupervisorError) as recovery_conflict:
        reopened.recover_worker_result_import(imported["id"])
    assert recovery_conflict.value.code == "sandbox_result_source_mismatch"
    with pytest.raises(SupervisorError) as submit_conflict:
        reopened._submit(
            attempt["id"],
            attempt["claim_token"],
            expected_worker_pid=None,
            credential=None,
            imported_result_id=imported["id"],
        )
    assert submit_conflict.value.code == "sandbox_result_source_mismatch"
    with reopened.connect() as connection:
        connection.execute("DELETE FROM result_imports WHERE id = 'corrupt-direct-recovery'")

    submission = reopened.recover_worker_result_import(imported["id"])
    repeated = reopened.import_sandbox_execution_result(attempt["id"], attempt["claim_token"])
    assert repeated["id"] == submission["id"]
    with reopened.connect() as connection:
        persisted = connection.execute(
            "SELECT phase, submission_id, source_kind FROM result_imports WHERE id = ?",
            (imported["id"],),
        ).fetchone()
        assert persisted["phase"] == "submitted"
        assert persisted["submission_id"] == submission["id"]
        assert persisted["source_kind"] == "sandbox_execution"
    assert reopened.verify_event_chain()["ok"] is True


def test_result_candidate_is_idempotent_but_cannot_be_replaced(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    row = reserve(supervisor, attempt)
    workspace = Path(row["workspace_root_path"])
    record_launch(supervisor, attempt)
    record_running(supervisor, attempt)
    (workspace / "alpha.txt").write_text("candidate v1\n", encoding="utf-8")
    record_exit(supervisor, attempt)
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


@pytest.mark.parametrize("legacy_version", [1, 2])
def test_persisted_pre_schema17_cleanup_receipt_replays_but_never_proves_cleanup(
    repo: Path, tmp_path: Path, legacy_version: int
) -> None:
    supervisor = GitSupervisor(repo)
    attempt = claimed(supervisor)
    reserve(supervisor, attempt)
    record_launch(supervisor, attempt)
    record_running(supervisor, attempt)
    record_exit(supervisor, attempt)

    legacy_receipt = cleanup_receipt(supervisor, attempt["id"])
    legacy_receipt.pop("rootfs_closure_digest")
    legacy_receipt.pop("runc_executable_digest")
    if legacy_version == 1:
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

    # Recreate the pre-17 table shape, then exercise the real version-16 upgrade
    # with a cleanup_reported row already carrying its historical receipt.
    with supervisor.connect() as connection:
        for trigger in (
            "sandbox_execution_insert_reserved",
            "sandbox_execution_identity_immutable",
            "sandbox_execution_launch_requires_content_pins",
        ):
            connection.execute(f"DROP TRIGGER {trigger}")
        connection.execute("ALTER TABLE sandbox_executions DROP COLUMN runc_executable_digest")
        connection.execute("ALTER TABLE sandbox_executions DROP COLUMN rootfs_closure_digest")
        connection.execute("UPDATE meta SET value = '16' WHERE key = 'schema_version'")
    supervisor = GitSupervisor(repo)
    assert supervisor.schema_version_on_open == 16
    migrated = supervisor._sandbox_execution_get(attempt["id"])
    assert migrated["rootfs_closure_digest"] == ""
    assert migrated["runc_executable_digest"] == ""

    replayed = supervisor._sandbox_execution_record_cleanup_report(
        attempt["id"], attempt["claim_token"], legacy_receipt
    )
    assert replayed["phase"] == "cleanup_reported"
    assert replayed["cleanup_receipt"]["version"] == legacy_version

    workspace = Path(supervisor._sandbox_execution_get(attempt["id"])["workspace_root_path"])
    (workspace / "alpha.txt").write_text("legacy cleanup receipt candidate\n", encoding="utf-8")
    candidate = supervisor._sandbox_execution_capture_result_candidate(
        attempt["id"], attempt["claim_token"]
    )
    assert candidate["candidate"]["cleanup"]["status"] == "unverified"

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
