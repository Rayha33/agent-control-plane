from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from support import requires_linux_worker

from agent_control_plane import cli
from agent_control_plane.trust_bundles import install_bundle


def run_cli(
    repo: Path,
    *arguments: str,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    process_env = os.environ.copy()
    process_env.update(env or {})
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_control_plane.cli",
            "--repo",
            str(repo),
            *arguments,
        ],
        capture_output=True,
        text=True,
        check=False,
        env=process_env,
    )


def test_quarantine_recovery_accepts_only_non_argv_credential_sources() -> None:
    parsed = cli.parser().parse_args(
        [
            "runtime-quarantine",
            "recover",
            "attempt-1",
            "--action",
            "retry-cleanup",
            "--credential-fd",
            "9",
        ]
    )
    assert parsed.credential_fd == 9

    with pytest.raises(SystemExit):
        cli.parser().parse_args(
            [
                "runtime-quarantine",
                "recover",
                "attempt-1",
                "--action",
                "retry-cleanup",
                "--credential",
                "plaintext-secret",
            ]
        )


def test_cli_submit_and_run_accept_a_result_manifest_path() -> None:
    submit = cli.parser().parse_args(
        [
            "submit",
            "attempt-1",
            "--token",
            "7",
            "--result-manifest",
            "reports/result-manifest.json",
        ]
    )
    assert submit.result_manifest == "reports/result-manifest.json"

    run = cli.parser().parse_args(
        [
            "run",
            "--token",
            "8",
            "--result-manifest",
            "reports/result-manifest.json",
            "attempt-1",
            "--",
            "python",
            "worker.py",
        ]
    )
    assert run.result_manifest == "reports/result-manifest.json"
    assert run.command == ["python", "worker.py"]


def test_cli_submit_persists_a_bounded_completion_receipt(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    task = _add(repo, "CLI completion receipt", "owned.txt", "--resource", "reports/**")
    claimed = json.loads(run_cli(repo, "claim", task["id"], "--agent", "cli-worker").stdout)
    worktree = Path(claimed["worktree"])
    report = worktree / "reports" / "findings.md"
    report.parent.mkdir(parents=True)
    report.write_text("Keep this complete report out of the receipt.\n", encoding="utf-8")
    report_oid = subprocess.run(
        ["git", "-C", str(worktree), "hash-object", str(report)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    manifest = worktree / "reports" / "result-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "summary": "CLI task complete.",
                "artifacts": [{"path": "reports/findings.md", "blob_oid": report_oid}],
            }
        ),
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(worktree), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(worktree), "commit", "-m", "complete report"], check=True)

    completed = run_cli(
        repo,
        "submit",
        claimed["id"],
        "--token",
        str(claimed["claim_token"]),
        "--result-manifest",
        "reports/result-manifest.json",
    )

    assert completed.returncode == 0, completed.stderr
    receipt = json.loads(completed.stdout)["completion_receipt"]
    assert receipt["state"] == "provided"
    assert receipt["summary"] == "CLI task complete."
    assert receipt["artifacts"][0]["blob_oid"] == report_oid
    assert "Keep this complete report" not in completed.stdout


@requires_linux_worker
def test_cli_run_passes_result_manifest_to_supervised_submit(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    task = _add(repo, "Supervised completion receipt", "owned.txt", "--resource", "reports/**")
    claimed = json.loads(run_cli(repo, "claim", task["id"], "--agent", "cli-worker").stdout)
    worker_script = (
        "import json, subprocess\n"
        "from pathlib import Path\n"
        "report = Path('reports/findings.md')\n"
        "report.parent.mkdir(parents=True, exist_ok=True)\n"
        "report.write_text('Persist this report in the commit.\\n', encoding='utf-8')\n"
        "blob_oid = subprocess.check_output(['git', 'hash-object', str(report)], text=True).strip()\n"
        "Path('reports/result-manifest.json').write_text(json.dumps({\n"
        "  'version': 1, 'summary': 'Supervised task complete.',\n"
        "  'artifacts': [{'path': 'reports/findings.md', 'blob_oid': blob_oid}]\n"
        "}), encoding='utf-8')\n"
        "subprocess.run(['git', 'add', '-A'], check=True)\n"
        "subprocess.run(['git', 'commit', '-m', 'write supervised result'], check=True)\n"
    )

    completed = run_cli(
        repo,
        "run",
        "--token",
        str(claimed["claim_token"]),
        "--result-manifest",
        "reports/result-manifest.json",
        claimed["id"],
        "--",
        sys.executable,
        "-c",
        worker_script,
    )

    assert completed.returncode == 0, completed.stderr
    receipt = json.loads(completed.stdout)["completion_receipt"]
    assert receipt["state"] == "provided"
    assert receipt["summary"] == "Supervised task complete."
    assert receipt["artifacts"][0]["path"] == "reports/findings.md"


def test_cli_run_forwards_result_manifest_to_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _repo(tmp_path)
    observed: dict = {}

    def fake_run_worker(
        _supervisor,
        attempt_id: str,
        claim_token: int,
        command: list[str],
        credential: str | None = None,
        result_manifest_path: str | None = None,
    ) -> dict:
        observed.update(
            {
                "attempt_id": attempt_id,
                "claim_token": claim_token,
                "command": command,
                "credential": credential,
                "result_manifest_path": result_manifest_path,
            }
        )
        return {"ok": True}

    monkeypatch.setattr(cli.GitSupervisor, "run_worker", fake_run_worker)

    result = cli.main(
        [
            "--repo",
            str(repo),
            "run",
            "--token",
            "8",
            "--result-manifest",
            "reports/result-manifest.json",
            "attempt-1",
            "--",
            "python",
            "worker.py",
        ]
    )
    capsys.readouterr()

    assert result == 0
    assert observed == {
        "attempt_id": "attempt-1",
        "claim_token": 8,
        "command": ["python", "worker.py"],
        "credential": None,
        "result_manifest_path": "reports/result-manifest.json",
    }


def test_cli_init_create_claim_and_doctor(tmp_path: Path) -> None:
    subprocess.run(["git", "-C", str(tmp_path), "init", "-b", "main"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.name", "CLI Test"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "cli@example.test"],
        check=True,
    )
    (tmp_path / "owned.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "owned.txt"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-m", "base"], check=True)

    initialized = run_cli(tmp_path, "init")
    assert initialized.returncode == 0, initialized.stderr
    assert (tmp_path / "acp.toml").is_file()
    assert ".acp/" in (tmp_path / ".gitignore").read_text(encoding="utf-8")

    created = run_cli(
        tmp_path,
        "task-add",
        "--title",
        "CLI task",
        "--accept",
        "owned.txt changes",
        "--resource",
        "owned.txt",
    )
    assert created.returncode == 0, created.stderr
    task = json.loads(created.stdout)
    claimed = run_cli(tmp_path, "claim", task["id"], "--agent", "cli-worker")
    assert claimed.returncode == 0, claimed.stderr
    attempt = json.loads(claimed.stdout)
    assert Path(attempt["worktree"]).is_dir()
    assert attempt["claim_token"] >= 1
    environment = run_cli(tmp_path, "environment", attempt["id"])
    assert environment.returncode == 0, environment.stderr
    assert json.loads(environment.stdout)["state"] == "ready"

    doctor = run_cli(tmp_path, "doctor")
    assert doctor.returncode == 0, doctor.stderr
    assert json.loads(doctor.stdout)["ok"] is True

    with sqlite3.connect(tmp_path / ".acp" / "control.db") as connection:
        connection.execute("UPDATE events SET payload_json = '{}' WHERE sequence = 1")
    verify = run_cli(tmp_path, "verify-events")
    assert verify.returncode == 1
    assert json.loads(verify.stdout)["ok"] is False
    failed_doctor = run_cli(tmp_path, "doctor")
    assert failed_doctor.returncode == 1
    assert json.loads(failed_doctor.stdout)["ok"] is False

    with sqlite3.connect(tmp_path / ".acp" / "control.db") as connection:
        connection.execute("UPDATE events SET payload_json = 'not-json' WHERE sequence = 1")
    invalid_json = run_cli(tmp_path, "verify-events")
    assert invalid_json.returncode == 1
    assert json.loads(invalid_json.stdout)["ok"] is False
    assert not invalid_json.stderr


def test_cli_trust_list_does_not_require_supervisor_initialization(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    driver = source / "driver"
    driver.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    driver.chmod(0o755)
    trust_root = tmp_path / "trust"
    pin = install_bundle(
        source,
        trust_root,
        "v1",
        {"driver": "driver"},
        owner_uid=os.geteuid(),
        require_privilege=False,
    )

    listed = run_cli(
        tmp_path,
        "trust",
        "list",
        "--root",
        str(trust_root),
        "--owner-uid",
        str(os.geteuid()),
    )

    assert listed.returncode == 0, listed.stderr
    payload = json.loads(listed.stdout)
    assert payload["current"] == pin["bundle_id"]
    assert payload["bundles"] == [
        {
            "bundle_id": pin["bundle_id"],
            "current": True,
            "retired": False,
            "health": {
                "bundle_id": pin["bundle_id"],
                "errors": [],
                "ok": True,
            },
        }
    ]


def test_cli_trust_install_invokes_validated_helper_without_a_shell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        cli,
        "resolve_trusted_executable",
        lambda raw, repo, owners: Path("/trusted/acp-trust-helper"),
    )
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0, '{"bundle_id":"v1-digest"}', "")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    args = SimpleNamespace(
        repo=str(tmp_path),
        helper="/configured/helper",
        trust_action="install",
        root=str(tmp_path / "trust"),
        owner_uid=0,
        source=str(tmp_path / "release"),
        version="v1",
        executable=["critic=bin/critic", "docker=bin/docker"],
    )

    result = cli._run_trust_helper(args)

    assert result == {"bundle_id": "v1-digest"}
    assert captured["command"] == [
        "/trusted/acp-trust-helper",
        "install",
        "--root",
        str(tmp_path / "trust"),
        "--owner-uid",
        "0",
        "--source",
        str(tmp_path / "release"),
        "--version",
        "v1",
        "--executable",
        "critic=bin/critic",
        "--executable",
        "docker=bin/docker",
    ]
    assert captured["check"] is False
    assert "shell" not in captured


def _repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "-C", str(tmp_path), "init", "-b", "main"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "CLI Test"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "cli@example.test"], check=True
    )
    (tmp_path / "owned.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "owned.txt"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-m", "base"], check=True)
    assert run_cli(tmp_path, "init").returncode == 0
    return tmp_path


def test_cli_task_add_accepts_optional_normalized_read_resources(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    created = run_cli(
        repo,
        "task-add",
        "--title",
        "Read-dependent task",
        "--accept",
        "generated client passes",
        "--resource",
        "client/**",
        "--read-resource",
        "./owned.txt",
        "--read-resource",
        "owned.txt",
        "--read-resource",
        "Owned.txt",
    )

    assert created.returncode == 0, created.stderr
    task = json.loads(created.stdout)
    assert task["resources"] == ["client/**"]
    assert task["read_resources"] == ["Owned.txt", "owned.txt"]
    assert task["declared_read_resources"] == ["Owned.txt", "owned.txt"]

    logical = run_cli(
        repo,
        "task-add",
        "--title",
        "Reject logical read inputs",
        "--accept",
        "checks pass",
        "--resource",
        "client/**",
        "--read-resource",
        "logical:api-schema",
    )
    assert logical.returncode == 1
    assert json.loads(logical.stderr)["error"] == "invalid_resource"


def test_cli_credentials_use_private_sinks_and_never_argv_or_json(tmp_path: Path) -> None:
    repo = _repo(tmp_path)

    credential_path = repo / "worker.credential"
    enrolled = run_cli(
        repo,
        "runner-enroll",
        "cli-worker",
        "--role",
        "worker",
        "--credential-output-file",
        str(credential_path),
    )
    assert enrolled.returncode == 0, enrolled.stderr
    credential = credential_path.read_text(encoding="utf-8").strip()
    assert len(credential) == 64
    assert credential not in enrolled.stdout + enrolled.stderr
    assert credential_path.stat().st_mode & 0o077 == 0

    unsafe_sink = run_cli(
        repo,
        "runner-enroll",
        "must-not-enroll",
        "--role",
        "worker",
        "--credential-output-fd",
        "1",
    )
    assert unsafe_sink.returncode == 1
    assert json.loads(unsafe_sink.stderr)["error"] == "invalid_credential_fd"
    listed = run_cli(repo, "runner-list")
    assert "must-not-enroll" not in listed.stdout

    created = run_cli(
        repo,
        "task-add",
        "--title",
        "Authenticated CLI task",
        "--accept",
        "owned.txt changes",
        "--resource",
        "owned.txt",
    )
    task = json.loads(created.stdout)
    rejected = run_cli(repo, "claim", task["id"], "--agent", "cli-worker")
    assert rejected.returncode == 1
    assert json.loads(rejected.stderr)["error"] == "runner_authentication_failed"

    claimed = run_cli(
        repo,
        "claim",
        task["id"],
        "--agent",
        "cli-worker",
        "--credential-file",
        str(credential_path),
    )
    assert claimed.returncode == 0, claimed.stderr
    attempt = json.loads(claimed.stdout)
    renewed = run_cli(
        repo,
        "heartbeat",
        attempt["id"],
        "--token",
        str(attempt["claim_token"]),
        env={"ACP_RUNNER_CREDENTIAL": credential},
    )
    assert renewed.returncode == 0, renewed.stderr
    assert credential not in renewed.stdout + renewed.stderr


def _add(repo: Path, title: str, resource: str, *extra: str) -> dict:
    created = run_cli(
        repo, "task-add", "--title", title, "--accept", "it works", "--resource", resource, *extra
    )
    assert created.returncode == 0, created.stderr
    return json.loads(created.stdout)


def test_cli_heartbeat_without_checkpoint_only_renews_liveness(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    task = _add(repo, "heartbeat keeps progress", "owned.txt")
    claimed = run_cli(repo, "claim", task["id"], "--agent", "cli-worker")
    assert claimed.returncode == 0, claimed.stderr
    attempt = json.loads(claimed.stdout)

    explicit = run_cli(
        repo,
        "heartbeat",
        attempt["id"],
        "--token",
        str(attempt["claim_token"]),
        "--checkpoint",
        '{"phase":"tests"}',
    )
    assert explicit.returncode == 0, explicit.stderr

    database = repo / ".acp" / "control.db"
    connection = sqlite3.connect(database)
    old = "2020-01-01T00:00:00Z"
    connection.execute(
        "UPDATE attempts SET heartbeat_at = ?, checkpoint_at = ?, updated_at = ? WHERE id = ?",
        (old, old, old, attempt["id"]),
    )
    connection.commit()
    connection.close()

    renewed = run_cli(repo, "heartbeat", attempt["id"], "--token", str(attempt["claim_token"]))
    assert renewed.returncode == 0, renewed.stderr

    connection = sqlite3.connect(database)
    row = connection.execute(
        "SELECT checkpoint_json, heartbeat_at, checkpoint_at FROM attempts WHERE id = ?",
        (attempt["id"],),
    ).fetchone()
    connection.close()
    assert json.loads(row[0]) == {"phase": "tests"}
    assert row[1] != old
    assert row[2] == old

    status = run_cli(repo, "status", "--checkpoint-stale-seconds", "60")
    assert status.returncode == 0, status.stderr
    snapshot = json.loads(status.stdout)
    entry = next(item for item in snapshot["tasks"] if item["task_id"] == task["id"])
    assert entry["heartbeat_age_seconds"] < 60
    assert entry["checkpoint_stale_advisory"] is True
    assert entry["category"] == "checkpoint_stale"

    invalid = run_cli(repo, "status", "--checkpoint-stale-seconds", "0")
    assert invalid.returncode == 2


def test_cli_plan_queue_and_status_are_read_only_previews(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    holder = _add(repo, "holder", "owned.txt")
    waiting = _add(repo, "waiting", "owned.txt")
    assert run_cli(repo, "claim", holder["id"], "--agent", "cli-worker").returncode == 0

    plan = run_cli(repo, "plan", waiting["id"])
    assert plan.returncode == 0, plan.stderr
    preview = json.loads(plan.stdout)
    assert preview["ready"] is False
    conflict = next(item for item in preview["blockers"] if item["kind"] == "resource_conflict")
    assert conflict["owner_task_id"] == holder["id"]
    assert conflict["owner_agent_id"] == "cli-worker"

    queue = json.loads(run_cli(repo, "queue").stdout)
    assert [entry["task_id"] for entry in queue["blocked"]] == [waiting["id"]]

    status = run_cli(repo, "status")
    assert status.returncode == 0, status.stderr
    snapshot = json.loads(status.stdout)
    assert snapshot["counts"]["active"] == 1
    assert snapshot["attention"][0]["task_id"] == holder["id"]

    text = run_cli(repo, "status", "--format", "text")
    assert text.returncode == 0
    assert "ATTENTION" in text.stdout
    assert "cli-worker" in text.stdout


def test_cli_status_read_only_open_does_not_create_git_coordination_state(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    state_dir = repo / ".acp"
    lock_path = state_dir / "git-operations.lock"
    hooks_path = state_dir / "disabled-hooks"
    database_path = state_dir / "control.db"
    lock_path.unlink(missing_ok=True)
    shutil.rmtree(hooks_path, ignore_errors=True)
    assert not lock_path.exists()
    assert not hooks_path.exists()

    def git_output(*arguments: str) -> bytes:
        result = subprocess.run(
            ["git", "-C", str(repo), *arguments], capture_output=True, check=True
        )
        return result.stdout

    before_database = database_path.read_bytes()
    before_index = (repo / ".git" / "index").read_bytes()
    before_config = (repo / ".git" / "config").read_bytes()
    before_refs = git_output("show-ref")
    before_registrations = git_output("worktree", "list", "--porcelain")
    before_repository_status = git_output("status", "--porcelain")

    status = run_cli(repo, "status")

    assert status.returncode == 0, status.stderr
    assert json.loads(status.stdout)["git_worktrees"]["status"] == "available"
    assert not lock_path.exists()
    assert not hooks_path.exists()
    assert database_path.read_bytes() == before_database
    assert (repo / ".git" / "index").read_bytes() == before_index
    assert (repo / ".git" / "config").read_bytes() == before_config
    assert git_output("show-ref") == before_refs
    assert git_output("worktree", "list", "--porcelain") == before_registrations
    assert git_output("status", "--porcelain") == before_repository_status


def test_cli_status_watch_stops_after_requested_iterations(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _add(repo, "idle", "owned.txt")

    watched = run_cli(
        repo, "status", "--watch", "--iterations", "2", "--interval", "0.1", "--format", "text"
    )

    assert watched.returncode == 0, watched.stderr
    assert watched.stdout.count("ATTENTION") == 2


@pytest.mark.parametrize(
    ("until_status", "next_status", "expected_result"),
    [(None, "working", "changed"), ("done", "done", "status_reached")],
)
def test_cli_wait_observes_a_second_connection_transition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    until_status: str | None,
    next_status: str,
    expected_result: str,
) -> None:
    repo = _repo(tmp_path)
    task = _add(repo, "transition while waiting", "owned.txt")
    supervisor = cli.GitSupervisor(repo, read_only=True)
    original_task = supervisor.task
    baseline_read = threading.Event()
    writer_errors: list[BaseException] = []

    def observe_baseline(task_id: str) -> dict:
        snapshot = original_task(task_id)
        baseline_read.set()
        return snapshot

    def update_from_second_connection() -> None:
        try:
            if not baseline_read.wait(timeout=3):
                raise AssertionError("waiter did not take its initial snapshot")
            with sqlite3.connect(repo / ".acp" / "control.db") as connection:
                connection.execute(
                    "UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?",
                    (next_status, "2026-10-02T00:00:00Z", task["id"]),
                )
        except BaseException as error:  # propagate background-thread assertion failures
            writer_errors.append(error)

    monkeypatch.setattr(supervisor, "task", observe_baseline)
    writer = threading.Thread(target=update_from_second_connection, daemon=True)
    writer.start()
    result = cli._wait_for_task(
        supervisor,
        SimpleNamespace(
            task_id=task["id"],
            until_status=until_status,
            timeout_seconds=2.0,
            interval_seconds=0.05,
        ),
    )
    writer.join(timeout=3)

    assert not writer.is_alive()
    assert not writer_errors
    assert result["wait_result"] == expected_result
    assert result["initial_status"] == "open"
    assert result["current_status"] == next_status
    assert result["task"]["id"] == task["id"]


def test_cli_wait_returns_immediately_for_matching_status_and_reports_unknown_task(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    task = _add(repo, "already open", "owned.txt")

    immediate = run_cli(repo, "wait", task["id"], "--until-status", "open")

    assert immediate.returncode == 0, immediate.stderr
    assert json.loads(immediate.stdout)["wait_result"] == "status_reached"
    assert immediate.stdout.count('"wait_result"') == 1

    missing = run_cli(repo, "wait", "not-a-task", "--timeout-seconds", "0.1")

    assert missing.returncode == 1
    assert json.loads(missing.stderr)["error"] == "task_not_found"
    assert not missing.stdout


def test_cli_wait_timeout_does_not_reap_expired_attempt_but_explicit_reap_does(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    task = _add(repo, "expired but observable", "owned.txt")
    claimed = run_cli(repo, "claim", task["id"], "--agent", "cli-worker")
    assert claimed.returncode == 0, claimed.stderr
    attempt_id = json.loads(claimed.stdout)["id"]
    database = repo / ".acp" / "control.db"
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE attempts SET lease_expires_at = 1 WHERE id = ?", (attempt_id,))

    def state() -> tuple:
        with sqlite3.connect(database) as connection:
            return (
                connection.execute(
                    "SELECT status, current_attempt_id FROM tasks WHERE id = ?", (task["id"],)
                ).fetchone(),
                connection.execute(
                    "SELECT status, lease_expires_at FROM attempts WHERE id = ?", (attempt_id,)
                ).fetchone(),
                connection.execute(
                    "SELECT COUNT(*) FROM resource_leases WHERE attempt_id = ?", (attempt_id,)
                ).fetchone(),
                connection.execute("SELECT COUNT(*) FROM events").fetchone(),
            )

    before = state()
    waited = run_cli(
        repo,
        "wait",
        task["id"],
        "--timeout-seconds",
        "0.1",
        "--interval-seconds",
        "0.1",
    )
    assert waited.returncode == 0, waited.stderr
    assert json.loads(waited.stdout)["wait_result"] == "timeout"
    assert state() == before

    reaped = run_cli(repo, "reap")
    assert reaped.returncode == 0, reaped.stderr
    assert task["id"] in json.loads(reaped.stdout)["orphaned"]
    assert state() != before


@pytest.mark.parametrize("late_phase", ["sleep", "read"])
def test_cli_wait_does_not_accept_a_transition_after_its_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, late_phase: str
) -> None:
    repo = _repo(tmp_path)
    task = _add(repo, "transition after deadline", "owned.txt")
    supervisor = cli.GitSupervisor(repo, read_only=True)
    read_task = supervisor.task
    clock = 0.0
    task_reads = 0

    def fake_monotonic() -> float:
        return clock

    def set_status_after_deadline() -> None:
        with sqlite3.connect(repo / ".acp" / "control.db") as connection:
            connection.execute(
                "UPDATE tasks SET status = 'working', updated_at = ? WHERE id = ?",
                ("2026-10-02T00:00:00Z", task["id"]),
            )

    def wait(seconds: float) -> None:
        nonlocal clock
        if late_phase == "sleep":
            set_status_after_deadline()
            clock = 0.11
        else:
            clock += seconds

    def delayed_task(task_id: str) -> dict:
        nonlocal clock, task_reads
        task_reads += 1
        if late_phase == "read" and task_reads == 2:
            set_status_after_deadline()
            observed = read_task(task_id)
            clock = 0.11
            return observed
        return read_task(task_id)

    monkeypatch.setattr(cli.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(cli.time, "sleep", wait)
    monkeypatch.setattr(supervisor, "task", delayed_task)
    result = cli._wait_for_task(
        supervisor,
        SimpleNamespace(
            task_id=task["id"],
            until_status=None,
            timeout_seconds=0.1,
            interval_seconds=0.05,
        ),
    )

    assert result["wait_result"] == "timeout"
    assert result["current_status"] == "open"
    assert result["task"]["status"] == "open"


def test_cli_wait_ignores_heartbeat_and_checkpoint_churn_until_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    task = _add(repo, "heartbeat only", "owned.txt")
    claimed = run_cli(repo, "claim", task["id"], "--agent", "cli-worker")
    attempt_id = json.loads(claimed.stdout)["id"]
    supervisor = cli.GitSupervisor(repo, read_only=True)
    clock = 0.0
    progress_writes = 0

    def monotonic() -> float:
        return clock

    def heartbeat_only(seconds: float) -> None:
        nonlocal clock, progress_writes
        with sqlite3.connect(repo / ".acp" / "control.db") as connection:
            connection.execute(
                "UPDATE attempts SET heartbeat_at = ?, checkpoint_at = ?, updated_at = ?, "
                "checkpoint_json = ? WHERE id = ?",
                (
                    "2040-01-01T00:00:00Z",
                    "2040-01-01T00:00:00Z",
                    "2040-01-01T00:00:00Z",
                    '{"phase":"still-running"}',
                    attempt_id,
                ),
            )
        progress_writes += 1
        clock += seconds

    monkeypatch.setattr(cli.time, "monotonic", monotonic)
    monkeypatch.setattr(cli.time, "sleep", heartbeat_only)
    result = cli._wait_for_task(
        supervisor,
        SimpleNamespace(
            task_id=task["id"],
            until_status=None,
            timeout_seconds=0.1,
            interval_seconds=0.04,
        ),
    )

    assert progress_writes >= 2
    assert result["wait_result"] == "timeout"
    assert result["task"]["latest_attempt"]["checkpoint"] == {"phase": "still-running"}


def test_cli_wait_interrupt_is_a_distinct_non_failure_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    task = _add(repo, "interruptible", "owned.txt")
    supervisor = cli.GitSupervisor(repo, read_only=True)

    def interrupt(_seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.time, "sleep", interrupt)
    result = cli._wait_for_task(
        supervisor,
        SimpleNamespace(
            task_id=task["id"],
            until_status=None,
            timeout_seconds=1.0,
            interval_seconds=0.1,
        ),
    )

    assert result["wait_result"] == "interrupted"
    assert result["current_status"] == "open"


def test_cli_wait_interrupt_before_initial_snapshot_returns_null_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    task = _add(repo, "interrupt before first read", "owned.txt")
    supervisor = cli.GitSupervisor(repo, read_only=True)

    def interrupt(_task_id: str) -> dict:
        raise KeyboardInterrupt

    monkeypatch.setattr(supervisor, "task", interrupt)
    result = cli._wait_for_task(
        supervisor,
        SimpleNamespace(
            task_id=task["id"],
            until_status=None,
            timeout_seconds=1.0,
            interval_seconds=0.1,
        ),
    )

    assert result["wait_result"] == "interrupted"
    assert result["initial_status"] is None
    assert result["current_status"] is None
    assert result["task"] is None


def test_cli_wait_bounds_are_finite_and_documented() -> None:
    defaults = cli.parser().parse_args(["wait", "task-id"])
    assert defaults.timeout_seconds == 300.0
    assert defaults.interval_seconds == 1.0

    for arguments in (
        ["wait", "task-id", "--timeout-seconds", "nan"],
        ["wait", "task-id", "--timeout-seconds", "0.09"],
        ["wait", "task-id", "--timeout-seconds", "86400.1"],
        ["wait", "task-id", "--interval-seconds", "30.1"],
    ):
        with pytest.raises(SystemExit) as error:
            cli.parser().parse_args(arguments)
        assert error.value.code == 2


def test_cli_artifact_dependency_blocks_a_claim(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    producer = _add(repo, "producer", "owned.txt", "--produces", "schema")
    consumer = _add(repo, "consumer", "other.txt", "--consumes", "schema")
    assert producer["produces"] == ["schema"]
    assert consumer["consumes"] == ["schema"]

    refused = run_cli(repo, "claim", consumer["id"], "--agent", "cli-worker")

    assert refused.returncode == 1
    assert json.loads(refused.stderr)["error"] == "dependency_incomplete"
    assert json.loads(run_cli(repo, "merge-plan").stdout)["count"] == 0


def test_cli_reviewers_ratify_and_bundle(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    config = (repo / "acp.toml").read_text(encoding="utf-8")
    (repo / "acp.toml").write_text(
        config + '\n[reviewers."independent-qc"]\nprovider = "builtin"\nmodel = "v1"\n',
        encoding="utf-8",
    )

    listed = json.loads(run_cli(repo, "reviewers").stdout)
    assert listed["ratified"] is False
    assert listed["reviewers"][0]["model"] == "v1"

    ratified = run_cli(repo, "ratify-reviewers")
    assert ratified.returncode == 0, ratified.stderr
    assert json.loads(run_cli(repo, "reviewers").stdout)["ratified"] is True

    calibrated = run_cli(repo, "calibrate")
    assert calibrated.returncode == 1
    assert json.loads(calibrated.stderr)["error"] == "no_golden_cases"

    task = _add(repo, "reviewed", "owned.txt")
    claimed = json.loads(run_cli(repo, "claim", task["id"], "--agent", "cli-worker").stdout)
    worktree = Path(claimed["worktree"])
    (worktree / "owned.txt").write_text("changed\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(worktree), "commit", "-am", "change"], check=True)
    submission = json.loads(
        run_cli(repo, "submit", claimed["id"], "--token", str(claimed["claim_token"])).stdout
    )
    review = json.loads(run_cli(repo, "qc", submission["id"]).stdout)
    assert review["reviewer_provenance"]["model"] == "v1"

    bundle = json.loads(run_cli(repo, "bundle", review["id"]).stdout)
    assert bundle["signature_valid"] is True
    assert bundle["bundle"]["commit_sha"] == submission["commit_sha"]
