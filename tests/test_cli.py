from __future__ import annotations

import json
import os
import sqlite3
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

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
            "python",
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


def test_cli_status_watch_stops_after_requested_iterations(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _add(repo, "idle", "owned.txt")

    watched = run_cli(
        repo, "status", "--watch", "--iterations", "2", "--interval", "0.1", "--format", "text"
    )

    assert watched.returncode == 0, watched.stderr
    assert watched.stdout.count("ATTENTION") == 2


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
