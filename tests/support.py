from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from agent_control_plane.git_supervisor import GitSupervisor
from agent_control_plane.trust_bundles import install_bundle


def python_command(source: str) -> str:
    """Run test code with the interpreter that is running pytest."""
    return f"{shlex.quote(sys.executable)} -c {shlex.quote(source)}"


def passing_critic_script() -> str:
    """Source for a version-2 critic used by fixtures that need a passing review."""
    return (
        f"#!{sys.executable}\n"
        "import json, os\n"
        "from pathlib import Path\n"
        "packet = json.loads(Path(os.environ['ACP_REVIEW_PACKET']).read_text())\n"
        "evidence_id = packet['evidence_catalog'][0]['id']\n"
        "coverage = [\n"
        "    {'criterion_id': item['id'], 'status': 'pass',\n"
        "     'rationale': 'Test reviewer covers the fixture criterion.',\n"
        "     'evidence_refs': [evidence_id]}\n"
        "    for item in packet['task']['acceptance_criteria']\n"
        "]\n"
        "Path(os.environ['ACP_REVIEW_RESULT']).write_text(json.dumps({\n"
        "    'contract_version': 2, 'verdict': 'pass', 'findings': [],\n"
        "    'acceptance_coverage': coverage}))\n"
    )


def install_passing_critic(repo: Path) -> tuple[str, Path]:
    """Install a test-only version-2 reviewer through ACP's pinned trust bundle."""
    source = repo.parent / f"{repo.name}-pass-critic-source"
    trust_root = repo.parent / f"{repo.name}-pass-critic-trust"
    if not trust_root.exists():
        source.mkdir(mode=0o700)
        executable = source / "critic"
        executable.write_text(passing_critic_script(), encoding="utf-8")
        executable.chmod(0o700)
        install_bundle(
            source,
            trust_root,
            "test-v1",
            {"critic": "critic"},
            owner_uid=os.geteuid(),
            require_privilege=False,
        )
    return "trusted:critic", trust_root


def git(repo: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def write_config(
    repo: Path,
    qc_commands: list[str] | None = None,
    integration_commands: list[str] | None = None,
    critic_command: str | None = None,
    require_critic: bool = False,
    timeout_seconds: int = 30,
) -> None:
    trust_root = None
    if critic_command is None:
        critic_command, trust_root = install_passing_critic(repo)
    qc = qc_commands if qc_commands is not None else [python_command("pass")]
    integration = integration_commands if integration_commands is not None else qc
    (repo / "acp.toml").write_text(
        "[supervisor]\n"
        "lease_seconds = 60\n"
        f"qc_timeout_seconds = {timeout_seconds}\n"
        'critic_identity = "independent-qc"\n'
        f"require_critic = {str(require_critic).lower()}\n\n"
        "[qc]\n"
        f"commands = {json.dumps(qc)}\n"
        f"critic_command = {json.dumps(critic_command)}\n\n"
        "[integration]\n"
        f"commands = {json.dumps(integration)}\n\n"
        "[runtime]\n"
        "setup_commands = []\n"
        "teardown_commands = []\n",
        encoding="utf-8",
    )
    if trust_root is not None:
        with (repo / "acp.toml").open("a", encoding="utf-8") as handle:
            handle.write(
                f"\n[trust]\nroot = {json.dumps(str(trust_root))}\nowner_uid = {os.geteuid()}\n"
            )


def init_repo(root: Path) -> Path:
    git(root, "init", "-b", "main")
    git(root, "config", "user.name", "ACP Test")
    git(root, "config", "user.email", "acp@example.test")
    (root / "alpha.txt").write_text("base\n", encoding="utf-8")
    (root / "beta.txt").write_text("base\n", encoding="utf-8")
    git(root, "add", "alpha.txt", "beta.txt")
    git(root, "commit", "-m", "base")
    GitSupervisor.initialize(root)
    write_config(root)
    return root


def make_task(
    supervisor: GitSupervisor,
    *resources: str,
    title: str = "bounded change",
    priority: int = 50,
    dependencies: list[str] | None = None,
    produces: list[str] | None = None,
    consumes: list[str] | None = None,
) -> dict[str, Any]:
    return supervisor.create_task(
        title,
        "Change only the declared path.",
        ["The declared content is correct", "QC passes"],
        list(resources),
        dependencies or [],
        priority,
        "HEAD",
        produces=produces or [],
        consumes=consumes or [],
    )


def commit_change(
    attempt: dict[str, Any], path: str, content: str, message: str = "implement"
) -> str:
    worktree = Path(attempt["worktree"])
    destination = worktree / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8")
    git(worktree, "add", path)
    git(worktree, "commit", "-m", message)
    return git(worktree, "rev-parse", "HEAD")


def approve(supervisor: GitSupervisor, task_id: str, path: str, content: str) -> dict[str, Any]:
    """Drive one task from claim through a passing QC verdict."""
    attempt = supervisor.claim(task_id, f"agent-{task_id[:4]}")
    commit_change(attempt, path, content)
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    supervisor.run_qc(submission["id"], "independent-qc")
    return submission


def event_count(supervisor: GitSupervisor) -> int:
    with supervisor.connect() as connection:
        return connection.execute("SELECT COUNT(*) AS total FROM events").fetchone()["total"]


def state_fingerprint(supervisor: GitSupervisor) -> str:
    """Every row that a read-only view is forbidden to change."""
    with supervisor.connect() as connection:
        return json.dumps(
            {
                "tasks": [
                    dict(row)
                    for row in connection.execute(
                        "SELECT id, status, current_attempt_id, updated_at FROM tasks ORDER BY id"
                    )
                ],
                "attempts": [
                    dict(row)
                    for row in connection.execute(
                        "SELECT id, status, pid, lease_expires_at, updated_at "
                        "FROM attempts ORDER BY id"
                    )
                ],
                "leases": [
                    dict(row)
                    for row in connection.execute(
                        "SELECT resource, task_id, attempt_id, fencing_token, lease_expires_at "
                        "FROM resource_leases ORDER BY resource"
                    )
                ],
                "runtime": [
                    dict(row)
                    for row in connection.execute(
                        "SELECT attempt_id, state FROM runtime_environments ORDER BY attempt_id"
                    )
                ],
                "events": connection.execute("SELECT COUNT(*) AS total FROM events").fetchone()[
                    "total"
                ],
            },
            sort_keys=True,
        )


def requires_linux_worker(test):
    """Skip off Linux, and mark the test so a Linux run can prove it actually ran.

    `acp run` supervises workers through a Linux child subreaper and /proc; macOS
    fails closed and refuses them. The skip is correct everywhere else — but on a
    Linux runner these tests MUST execute, and a plain skipif cannot tell the
    difference between "not applicable here" and "the platform support went away".
    The `linux_worker` marker is what ACP_REQUIRE_LINUX_WORKER=1 checks, so the
    control survives someone rewording the reason string.
    """

    marked = pytest.mark.linux_worker(test)
    return pytest.mark.skipif(
        not sys.platform.startswith("linux"),
        reason="long-running worker containment requires Linux child-subreaper support",
    )(marked)
