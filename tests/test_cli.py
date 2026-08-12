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
