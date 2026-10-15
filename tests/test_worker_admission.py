from __future__ import annotations

import json
import multiprocessing
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from support import init_repo, make_task

from agent_control_plane.git_supervisor import GitSupervisor, SupervisorError
from agent_control_plane.supervisor import host_memory as host_memory_module
from agent_control_plane.supervisor import workers as workers_module
from agent_control_plane.supervisor.host_memory import HostMemorySnapshot


def _supervisor_with_policy(
    root: Path,
    *,
    max_active_workers: int | bool | str | None = None,
    min_available_memory_bytes: int | bool | str | None = None,
) -> GitSupervisor:
    root.mkdir(parents=True, exist_ok=True)
    init_repo(root)
    settings = []
    if max_active_workers is not None:
        settings.append(f"max_active_workers = {json.dumps(max_active_workers)}")
    if min_available_memory_bytes is not None:
        settings.append(f"min_available_memory_bytes = {json.dumps(min_available_memory_bytes)}")
    if settings:
        config_path = root / "acp.toml"
        config = config_path.read_text(encoding="utf-8")
        config_path.write_text(
            config.replace("[supervisor]\n", "[supervisor]\n" + "\n".join(settings) + "\n", 1),
            encoding="utf-8",
        )
    return GitSupervisor(root)


def _claim_pair(supervisor: GitSupervisor) -> tuple[dict, dict]:
    first = make_task(supervisor, "alpha.txt", title="first worker")
    second = make_task(supervisor, "beta.txt", title="second worker")
    return (
        supervisor.claim(first["id"], "first-agent"),
        supervisor.claim(second["id"], "second-agent"),
    )


def _stub_launcher_identity(monkeypatch: pytest.MonkeyPatch, supervisor: GitSupervisor) -> None:
    monkeypatch.setattr(supervisor, "_process_identity", lambda pid: f"test-process:{pid}")


def _reserve_worker_process(
    root: str,
    attempt_id: str,
    claim_token: int,
    barrier: object,
    results: object,
) -> None:
    supervisor = GitSupervisor(Path(root))
    supervisor._process_identity = lambda pid: f"test-process:{pid}"
    barrier.wait(timeout=10)
    try:
        supervisor._reserve_worker_launch(attempt_id, claim_token, f"/tmp/{attempt_id}.log", None)
    except SupervisorError as error:
        results.put((attempt_id, error.code))
    else:
        results.put((attempt_id, "reserved"))


def _memory_sample(
    available_bytes: int | None,
    *,
    status: str = "available",
    age_seconds: int = 0,
    error: str | None = None,
) -> HostMemorySnapshot:
    return HostMemorySnapshot(
        status=status,
        source="linux.proc_meminfo.MemAvailable",
        observed_at=(datetime.now(UTC) - timedelta(seconds=age_seconds)).isoformat()
        if status == "available"
        else None,
        available_bytes=available_bytes,
        error=error,
    )


@pytest.mark.parametrize(
    ("contents", "expected_status", "expected_bytes", "expected_error"),
    [
        (b"MemTotal: 4 kB\nMemAvailable: 1024 kB\n", "available", 1024 * 1024, None),
        (b"MemTotal: 4 kB\n", "unavailable", None, "memavailable_missing_or_duplicate"),
        (
            b"MemAvailable: 1 kB\nMemAvailable: 2 kB\n",
            "unavailable",
            None,
            "memavailable_missing_or_duplicate",
        ),
        (
            b"MemAvailable: yesterday\n",
            "unavailable",
            None,
            "malformed_memavailable",
        ),
        (
            b"MemAvailable: 999999999999999999999999 kB\n",
            "unavailable",
            None,
            "memavailable_out_of_range",
        ),
        (
            b"MemAvailable: " + b"9" * 5000 + b" kB\n",
            "unavailable",
            None,
            "memavailable_out_of_range",
        ),
        (b"MemAvailable: 1 kB\n" + b"x" * 65_537, "unavailable", None, "sample_too_large"),
    ],
)
def test_linux_memavailable_parser_is_exact_and_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    contents: bytes,
    expected_status: str,
    expected_bytes: int | None,
    expected_error: str | None,
) -> None:
    meminfo = tmp_path / "meminfo"
    meminfo.write_bytes(contents)
    monkeypatch.setattr(host_memory_module.sys, "platform", "linux")
    monkeypatch.setattr(host_memory_module, "_MEMINFO_PATH", meminfo)

    snapshot = host_memory_module.read_host_memory_snapshot()

    assert snapshot.status == expected_status
    assert snapshot.available_bytes == expected_bytes
    assert snapshot.error == expected_error


def test_host_memory_reader_reports_unsupported_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(host_memory_module.sys, "platform", "darwin")

    snapshot = host_memory_module.read_host_memory_snapshot()

    assert snapshot.status == "unsupported"
    assert snapshot.available_bytes is None
    assert snapshot.error == "platform_unsupported"


def test_host_memory_reader_does_not_follow_meminfo_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    target.write_text("MemAvailable: 4096 kB\n", encoding="ascii")
    meminfo = tmp_path / "meminfo"
    meminfo.symlink_to(target)
    monkeypatch.setattr(host_memory_module.sys, "platform", "linux")
    monkeypatch.setattr(host_memory_module, "_MEMINFO_PATH", meminfo)

    snapshot = host_memory_module.read_host_memory_snapshot()

    assert snapshot.status == "unavailable"
    assert snapshot.available_bytes is None
    assert snapshot.error == "read_failed"


@pytest.mark.parametrize(
    ("max_workers", "minimum_memory", "invalid_key"),
    [
        (0, None, "supervisor.max_active_workers"),
        (True, None, "supervisor.max_active_workers"),
        (65_536, None, "supervisor.max_active_workers"),
        (None, 0, "supervisor.min_available_memory_bytes"),
        (None, True, "supervisor.min_available_memory_bytes"),
        (None, 2**63, "supervisor.min_available_memory_bytes"),
    ],
)
def test_worker_admission_config_rejects_invalid_limits(
    tmp_path: Path,
    max_workers: int | bool | None,
    minimum_memory: int | bool | None,
    invalid_key: str,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    init_repo(root)
    setting = (
        f"max_active_workers = {json.dumps(max_workers)}"
        if max_workers is not None
        else f"min_available_memory_bytes = {json.dumps(minimum_memory)}"
    )
    config_path = root / "acp.toml"
    config = config_path.read_text(encoding="utf-8")
    config_path.write_text(
        config.replace("[supervisor]\n", "[supervisor]\n" + setting + "\n", 1),
        encoding="utf-8",
    )

    with pytest.raises(SupervisorError, match=invalid_key) as error:
        GitSupervisor(root)

    assert error.value.code == "invalid_config"


def test_legacy_config_keeps_unlimited_worker_admission(tmp_path: Path) -> None:
    supervisor = _supervisor_with_policy(tmp_path / "repo")
    first, second = _claim_pair(supervisor)

    assert supervisor.config.max_active_workers is None
    assert supervisor.config.min_available_memory_bytes is None
    supervisor._reserve_worker_launch(first["id"], first["claim_token"], "/tmp/first.log", None)
    supervisor._reserve_worker_launch(second["id"], second["claim_token"], "/tmp/second.log", None)


def test_concurrent_reservations_share_one_atomic_worker_slot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    supervisor = _supervisor_with_policy(root, max_active_workers=1)
    first, second = _claim_pair(supervisor)
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(2)
    results_queue = context.Queue()
    processes = [
        context.Process(
            target=_reserve_worker_process,
            args=(root.as_posix(), attempt["id"], attempt["claim_token"], barrier, results_queue),
        )
        for attempt in (first, second)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=20)
    results = dict(results_queue.get(timeout=2) for _ in processes)

    assert all(process.exitcode == 0 for process in processes)
    assert sorted(results.values()) == ["reserved", "worker_concurrency_exhausted"]
    with supervisor.connect() as connection:
        retained = connection.execute(
            "SELECT COUNT(*) FROM attempts WHERE pid IS NOT NULL"
        ).fetchone()[0]
    assert retained == 1

    # The durable pid=-1 reservation still consumes capacity after reopening the
    # supervisor and database connection; no in-memory semaphore is involved.
    restarted = GitSupervisor(root)
    _stub_launcher_identity(monkeypatch, restarted)
    denied_attempt = next(
        attempt
        for attempt in (first, second)
        if results[attempt["id"]] == "worker_concurrency_exhausted"
    )
    with pytest.raises(SupervisorError) as error:
        restarted._reserve_worker_launch(
            denied_attempt["id"], denied_attempt["claim_token"], "/tmp/restarted.log", None
        )
    assert error.value.code == "worker_concurrency_exhausted"
    assert restarted.attempt(denied_attempt["id"])["pid"] is None


@pytest.mark.parametrize(
    ("sample_kind", "expected_code"),
    [
        ("low", "worker_memory_below_minimum"),
        ("unavailable", "worker_memory_unavailable"),
        ("unsupported", "worker_memory_unavailable"),
        ("stale", "worker_memory_stale"),
        ("malformed", "worker_memory_stale"),
        ("untrusted_source", "worker_memory_stale"),
    ],
)
def test_configured_memory_floor_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sample_kind: str,
    expected_code: str,
) -> None:
    supervisor = _supervisor_with_policy(
        tmp_path / "repo", min_available_memory_bytes=2 * 1024 * 1024
    )
    attempt = supervisor.claim(make_task(supervisor, "alpha.txt")["id"], "worker")
    _stub_launcher_identity(monkeypatch, supervisor)
    snapshots = {
        "low": _memory_sample(1),
        "unavailable": _memory_sample(None, status="unavailable", error="read_failed"),
        "unsupported": _memory_sample(None, status="unsupported", error="platform_unsupported"),
        "stale": _memory_sample(1024 * 1024, age_seconds=10),
        "malformed": _memory_sample(True),
        "untrusted_source": HostMemorySnapshot(
            status="available",
            source="untrusted.memory.signal",
            observed_at=_memory_sample(1).observed_at,
            available_bytes=4 * 1024 * 1024,
        ),
    }
    snapshot = snapshots[sample_kind]
    monkeypatch.setattr(workers_module, "read_host_memory_snapshot", lambda: snapshot)

    with pytest.raises(SupervisorError) as error:
        supervisor._reserve_worker_launch(
            attempt["id"], attempt["claim_token"], "/tmp/memory-floor.log", None
        )

    assert error.value.code == expected_code
    assert supervisor.attempt(attempt["id"])["pid"] is None
    with supervisor.connect() as connection:
        event = connection.execute(
            "SELECT payload_json FROM events WHERE event_type = 'worker.launch_denied' "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
    assert json.loads(event["payload_json"])["reason"] == expected_code


def test_mixed_admission_settings_fail_closed_until_retained_slot_clears(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    capped = _supervisor_with_policy(root, max_active_workers=1)
    first, second = _claim_pair(capped)
    _stub_launcher_identity(monkeypatch, capped)
    capped._reserve_worker_launch(first["id"], first["claim_token"], "/tmp/first.log", None)

    config_path = root / "acp.toml"
    config = config_path.read_text(encoding="utf-8")
    config_path.write_text(config.replace("max_active_workers = 1\n", "", 1), encoding="utf-8")
    uncapped = GitSupervisor(root)
    _stub_launcher_identity(monkeypatch, uncapped)

    with pytest.raises(SupervisorError) as error:
        uncapped._reserve_worker_launch(
            second["id"], second["claim_token"], "/tmp/second.log", None
        )

    assert error.value.code == "worker_admission_policy_conflict"
    assert uncapped.attempt(second["id"])["pid"] is None
    snapshot = uncapped.status()
    assert snapshot["worker_admission"]["policy_conflict"] is True
    assert "launches blocked" in uncapped.render_status(snapshot)


def test_sufficient_fresh_memory_reserves_slot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = _supervisor_with_policy(
        tmp_path / "repo", min_available_memory_bytes=2 * 1024 * 1024
    )
    attempt = supervisor.claim(make_task(supervisor, "alpha.txt")["id"], "worker")
    _stub_launcher_identity(monkeypatch, supervisor)
    monkeypatch.setattr(
        workers_module,
        "read_host_memory_snapshot",
        lambda: _memory_sample(4 * 1024 * 1024),
    )

    supervisor._reserve_worker_launch(
        attempt["id"], attempt["claim_token"], "/tmp/memory-floor.log", None
    )

    assert supervisor.attempt(attempt["id"])["pid"] == -1


def test_full_capacity_denies_before_heartbeat_log_or_process_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Exercise the pre-child refusal branch on every development platform.
    monkeypatch.setattr(workers_module.sys, "platform", "linux")
    root = tmp_path / "repo"
    supervisor = _supervisor_with_policy(root, max_active_workers=1)
    first, second = _claim_pair(supervisor)
    _stub_launcher_identity(monkeypatch, supervisor)
    supervisor._reserve_worker_launch(first["id"], first["claim_token"], "/tmp/first.log", None)
    before = supervisor.attempt(second["id"])
    popen_called = False

    def forbidden_popen(*args: object, **kwargs: object) -> None:
        nonlocal popen_called
        popen_called = True
        raise AssertionError("worker process must not start after admission refusal")

    monkeypatch.setattr(workers_module.subprocess, "Popen", forbidden_popen)
    log_path = supervisor.state_dir / "logs" / f"worker-{second['id']}.log"

    with pytest.raises(SupervisorError) as error:
        supervisor.run_worker(second["id"], second["claim_token"], [sys.executable, "-c", "pass"])

    after = supervisor.attempt(second["id"])
    assert error.value.code == "worker_concurrency_exhausted"
    assert not popen_called
    assert not log_path.exists()
    assert after["heartbeat_at"] == before["heartbeat_at"]
    assert after["pid"] is None


def test_low_memory_denies_before_heartbeat_log_or_process_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(workers_module.sys, "platform", "linux")
    root = tmp_path / "repo"
    supervisor = _supervisor_with_policy(root, min_available_memory_bytes=1024)
    task = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(task["id"], "worker")
    monkeypatch.setattr(workers_module, "read_host_memory_snapshot", lambda: _memory_sample(0))
    before = supervisor.attempt(attempt["id"])
    popen_called = False

    def forbidden_popen(*args: object, **kwargs: object) -> None:
        nonlocal popen_called
        popen_called = True
        raise AssertionError("worker process must not start below the memory floor")

    monkeypatch.setattr(workers_module.subprocess, "Popen", forbidden_popen)
    log_path = supervisor.state_dir / "logs" / f"worker-{attempt['id']}.log"

    with pytest.raises(SupervisorError) as error:
        supervisor.run_worker(attempt["id"], attempt["claim_token"], [sys.executable, "-c", "pass"])

    after = supervisor.attempt(attempt["id"])
    assert error.value.code == "worker_memory_below_minimum"
    assert not popen_called
    assert not log_path.exists()
    assert after["heartbeat_at"] == before["heartbeat_at"]
    assert after["pid"] is None


def test_racing_capacity_denial_does_not_heartbeat_or_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The capacity refusal happens before any Linux-only containment code.
    monkeypatch.setattr(workers_module.sys, "platform", "linux")
    root = tmp_path / "repo"
    supervisor = _supervisor_with_policy(root, max_active_workers=1)
    first, second = _claim_pair(supervisor)
    _stub_launcher_identity(monkeypatch, supervisor)
    original_reserve = supervisor._reserve_worker_launch
    raced = False

    def fill_slot_then_reserve(
        attempt_id: str, claim_token: int, log_path: str, credential: str | None
    ) -> None:
        nonlocal raced
        if not raced:
            raced = True
            original_reserve(first["id"], first["claim_token"], "/tmp/first.log", None)
        original_reserve(attempt_id, claim_token, log_path, credential)

    monkeypatch.setattr(supervisor, "_reserve_worker_launch", fill_slot_then_reserve)
    before = supervisor.attempt(second["id"])
    popen_called = False

    def forbidden_popen(*args: object, **kwargs: object) -> None:
        nonlocal popen_called
        popen_called = True
        raise AssertionError("worker process must not start after admission refusal")

    monkeypatch.setattr(workers_module.subprocess, "Popen", forbidden_popen)
    log_path = supervisor.state_dir / "logs" / f"worker-{second['id']}.log"

    with pytest.raises(SupervisorError) as error:
        supervisor.run_worker(second["id"], second["claim_token"], [sys.executable, "-c", "pass"])

    after = supervisor.attempt(second["id"])
    assert error.value.code == "worker_concurrency_exhausted"
    assert not popen_called
    assert not log_path.exists()
    assert after["heartbeat_at"] == before["heartbeat_at"]
    assert after["pid"] is None
    assert supervisor.attempt(first["id"])["pid"] == -1


def test_status_exposes_policy_sample_and_latest_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = _supervisor_with_policy(
        tmp_path / "repo", max_active_workers=1, min_available_memory_bytes=1024
    )
    first, second = _claim_pair(supervisor)
    _stub_launcher_identity(monkeypatch, supervisor)
    sample = _memory_sample(2048)
    monkeypatch.setattr(workers_module, "read_host_memory_snapshot", lambda: sample)
    supervisor._reserve_worker_launch(first["id"], first["claim_token"], "/tmp/first.log", None)
    with pytest.raises(SupervisorError):
        supervisor._reserve_worker_launch(
            second["id"], second["claim_token"], "/tmp/second.log", None
        )

    snapshot = supervisor.status()
    admission = snapshot["worker_admission"]

    assert admission["configured_max_active_workers"] == 1
    assert admission["configured_min_available_memory_bytes"] == 1024
    assert admission["retained_slots"] == 1
    assert admission["available_slots"] == 0
    assert admission["host_memory"]["source"] == "linux.proc_meminfo.MemAvailable"
    assert admission["host_memory"]["available_bytes"] == 2048
    assert admission["last_refusal"]["reason"] == "worker_concurrency_exhausted"
    assert "WORKER ADMISSION" in supervisor.render_status(snapshot)
