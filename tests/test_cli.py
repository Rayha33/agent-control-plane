from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path


def run_cli(repo: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
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
