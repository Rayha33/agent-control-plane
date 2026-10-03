from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import uuid
from pathlib import Path

import pytest
from support import (
    approve,
    commit_change,
    git,
    init_repo,
    make_task,
    python_command,
    state_fingerprint,
    write_config,
)

from agent_control_plane.git_supervisor import GitSupervisor
from agent_control_plane.status import StatusView, _format_bytes


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return init_repo(tmp_path)


def entry_for(snapshot: dict, task_id: str) -> dict:
    return next(item for item in snapshot["tasks"] if item["task_id"] == task_id)


def _install_revising_critic(supervisor: GitSupervisor, monkeypatch: pytest.MonkeyPatch) -> None:
    def run_critic(
        command: str,
        cwd: Path,
        environment: dict[str, str],
        _trust_pin: dict | None = None,
        **_kwargs: object,
    ) -> dict:
        case = (cwd / "alpha.txt").read_text(encoding="utf-8").strip()
        if case == "pass":
            payload = {"verdict": "pass", "findings": []}
        else:
            if case == "case2":
                requirement, finding, required_fix = (
                    " tests   PASS ",
                    " SAME gap ",
                    " Fix before retry ",
                )
            elif case == "different":
                requirement, finding, required_fix = (
                    "Tests pass",
                    "a different gap",
                    "Fix before retry",
                )
            else:
                requirement, finding, required_fix = (
                    "Tests pass",
                    "same gap",
                    "Fix before retry",
                )
            payload = {
                "verdict": "revise",
                "findings": [
                    {
                        "severity": "high",
                        "requirement": requirement,
                        "finding": finding,
                        "required_fix": required_fix,
                        "evidence": uuid.uuid4().hex,
                    }
                ],
            }
        with os.fdopen(
            os.dup(int(environment["ACP_REVIEW_PACKET_FD"])), "r", encoding="utf-8"
        ) as packet_stream:
            packet = json.load(packet_stream)
        evidence_id = packet["evidence_catalog"][0]["id"]
        payload["contract_version"] = 2
        payload["acceptance_coverage"] = [
            {
                "criterion_id": criterion["id"],
                "status": "pass",
                "rationale": "The test reviewer covers the criterion.",
                "evidence_refs": [evidence_id],
            }
            for criterion in packet["task"]["acceptance_criteria"]
        ]
        Path(environment["ACP_REVIEW_RESULT"]).write_text(json.dumps(payload), encoding="utf-8")
        return {
            "command": command,
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "duration_seconds": 0.0,
        }

    monkeypatch.setattr(supervisor, "_run_critic", run_critic)


def _submit_revised_commit(
    supervisor: GitSupervisor, task_id: str, content: str
) -> tuple[dict, dict]:
    attempt = supervisor.claim(task_id, "worker-a")
    commit_sha = commit_change(attempt, "alpha.txt", f"{content}\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    qc = supervisor.run_qc(submission["id"], "independent-qc")
    assert qc["verdict"] == "revise"
    assert submission["commit_sha"] == commit_sha
    return submission, qc


def test_byte_formatter_switches_units_at_binary_boundaries() -> None:
    assert _format_bytes(1023) == "1023.0 B"
    assert _format_bytes(1024) == "1.0 KiB"
    assert _format_bytes(1024**3) == "1.0 GiB"


def test_status_reports_phase_paths_and_runtime_for_a_working_attempt(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt", title="live work")
    attempt = supervisor.claim(created["id"], "agent-a")

    entry = entry_for(supervisor.status(), created["id"])

    assert entry["phase"] == "working"
    assert entry["agent_id"] == "agent-a"
    assert entry["attempt_id"] == attempt["id"]
    assert entry["claimed_paths"] == ["alpha.txt"]
    assert entry["runtime"]["state"] == "ready"
    assert entry["heartbeat_age_seconds"] >= 0
    assert entry["checkpoint_age_seconds"] is None
    assert entry["checkpoint_stale_advisory"] is False
    assert entry["read_dependency_advisory"] is None
    assert entry["worker"]["status"] == "working"


def test_status_tracks_only_declared_glob_read_inputs_and_is_read_only(repo: Path) -> None:
    (repo / "src" / "api").mkdir(parents=True)
    (repo / "src" / "ui").mkdir(parents=True)
    (repo / "src" / "api" / "schema.py").write_text("schema v1\n", encoding="utf-8")
    (repo / "src" / "ui" / "client.py").write_text("client v1\n", encoding="utf-8")
    git(repo, "add", "src")
    git(repo, "commit", "-m", "add API and client")
    git(repo, "branch", "integration", "HEAD")
    supervisor = GitSupervisor(repo)
    task = supervisor.create_task(
        "Update client",
        "Use the API schema to update the generated client.",
        ["client checks pass"],
        ["beta.txt"],
        base_branch="integration",
        read_resources=["src/**", "src/"],
    )
    attempt = supervisor.claim(task["id"], "worker-a")

    assert task["read_resources"] == ["src/**"]
    assert task["declared_read_resources"] == ["src/**"]
    with supervisor.connect() as connection:
        baseline = json.loads(
            connection.execute(
                "SELECT read_resources_snapshot_json FROM attempts WHERE id = ?",
                (attempt["id"],),
            ).fetchone()["read_resources_snapshot_json"]
        )
    expected_schema_oid = git(repo, "rev-parse", f"{task['base_sha']}:src/api/schema.py")
    assert baseline["base_sha"] == task["base_sha"]
    assert baseline["files"]["src/api/schema.py"] == expected_schema_oid
    assert baseline["files"]["src/ui/client.py"]

    before_view = state_fingerprint(supervisor)
    unchanged = entry_for(supervisor.status(), task["id"])["read_dependency_advisory"]
    assert unchanged["state"] == "unchanged"
    assert state_fingerprint(supervisor) == before_view

    unrelated_commit = commit_change(attempt, "beta.txt", "parallel edit\n")
    git(repo, "update-ref", "refs/heads/integration", unrelated_commit)
    before_view = state_fingerprint(supervisor)
    unrelated = entry_for(supervisor.status(), task["id"])["read_dependency_advisory"]
    assert unrelated["state"] == "unchanged"
    assert state_fingerprint(supervisor) == before_view

    changed_commit = commit_change(
        attempt, "src/api/schema.py", "schema v2\n", message="change API schema"
    )
    git(repo, "update-ref", "refs/heads/integration", changed_commit)
    before_view = state_fingerprint(supervisor)
    changed_snapshot = supervisor.status()
    changed = entry_for(changed_snapshot, task["id"])["read_dependency_advisory"]
    assert changed["state"] == "changed"
    assert changed["changed_path_count"] == 1
    assert "read inputs changed 1" in StatusView.render(changed_snapshot)
    assert changed["changed_paths"] == [
        {
            "path": "src/api/schema.py",
            "before_object_oid": expected_schema_oid,
            "after_object_oid": git(repo, "rev-parse", "integration:src/api/schema.py"),
        }
    ]
    assert state_fingerprint(supervisor) == before_view


def test_status_exposes_only_the_bounded_completion_receipt_and_is_read_only(
    repo: Path,
) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt", title="receipt status")
    submission = approve(supervisor, created["id"], "alpha.txt", "candidate\n")
    receipt = {
        "version": 1,
        "summary": "The check passed; inspect the pinned artifact.",
        "manifest_path": "reports/result-manifest.json",
        "manifest_blob_oid": "1" * 40,
        "artifacts": [
            {
                "path": "reports/findings.md",
                "blob_oid": "2" * 40,
                "size_bytes": 19,
            }
        ],
    }
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE submissions SET result_manifest_json = ? WHERE id = ?",
            (json.dumps(receipt), submission["id"]),
        )
    with supervisor.connect() as connection:
        before_row = connection.execute(
            "SELECT result_manifest_json FROM submissions WHERE id = ?", (submission["id"],)
        ).fetchone()["result_manifest_json"]
    before_state = state_fingerprint(supervisor)

    snapshot = supervisor.status()

    entry = entry_for(snapshot, created["id"])
    assert entry["completion_receipt"] == {"state": "provided", **receipt}
    serialized = json.dumps(snapshot)
    assert "The check passed" in serialized
    assert state_fingerprint(supervisor) == before_state
    with supervisor.connect() as connection:
        after_row = connection.execute(
            "SELECT result_manifest_json FROM submissions WHERE id = ?", (submission["id"],)
        ).fetchone()["result_manifest_json"]
    assert after_row == before_row


def test_recursive_glob_tracks_deeply_nested_read_inputs(repo: Path) -> None:
    (repo / "src" / "api" / "v2").mkdir(parents=True)
    (repo / "src" / "api" / "schema.py").write_text("schema v1\n", encoding="utf-8")
    (repo / "src" / "api" / "v2" / "schema.py").write_text("nested schema v1\n", encoding="utf-8")
    git(repo, "add", "src")
    git(repo, "commit", "-m", "add shallow and nested schemas")
    git(repo, "branch", "integration", "HEAD")
    supervisor = GitSupervisor(repo)
    task = supervisor.create_task(
        "Update generated API files",
        "Use every Python schema under the API directory.",
        ["client checks pass"],
        ["client/**"],
        base_branch="integration",
        read_resources=["src/api/**/*.py"],
    )
    attempt = supervisor.claim(task["id"], "worker-a")
    with supervisor.connect() as connection:
        baseline = json.loads(
            connection.execute(
                "SELECT read_resources_snapshot_json FROM attempts WHERE id = ?",
                (attempt["id"],),
            ).fetchone()["read_resources_snapshot_json"]
        )
    assert set(baseline["files"]) == {
        "src/api/schema.py",
        "src/api/v2/schema.py",
    }

    changed_commit = commit_change(
        attempt,
        "src/api/v2/schema.py",
        "nested schema v2\n",
        message="change deeply nested schema",
    )
    git(repo, "update-ref", "refs/heads/integration", changed_commit)
    advisory = entry_for(supervisor.status(), task["id"])["read_dependency_advisory"]

    assert advisory["state"] == "changed"
    assert advisory["changed_paths"] == [
        {
            "path": "src/api/v2/schema.py",
            "before_object_oid": baseline["files"]["src/api/v2/schema.py"],
            "after_object_oid": git(repo, "rev-parse", "integration:src/api/v2/schema.py"),
        }
    ]


def test_recursive_glob_after_wildcard_directory_tracks_nested_inputs(repo: Path) -> None:
    (repo / "src" / "api" / "v2").mkdir(parents=True)
    (repo / "src" / "api" / "schema.py").write_text("schema v1\n", encoding="utf-8")
    (repo / "src" / "api" / "v2" / "nested.py").write_text("nested v1\n", encoding="utf-8")
    git(repo, "add", "src")
    git(repo, "commit", "-m", "add API files")
    git(repo, "branch", "integration", "HEAD")
    supervisor = GitSupervisor(repo)
    task = supervisor.create_task(
        "Update API consumers",
        "Read files below any immediate src directory.",
        ["consumer checks pass"],
        ["client/**"],
        base_branch="integration",
        read_resources=["src/*/**"],
    )
    attempt = supervisor.claim(task["id"], "worker-a")
    with supervisor.connect() as connection:
        baseline = json.loads(
            connection.execute(
                "SELECT read_resources_snapshot_json FROM attempts WHERE id = ?",
                (attempt["id"],),
            ).fetchone()["read_resources_snapshot_json"]
        )
    assert set(baseline["files"]) == {
        "src/api/schema.py",
        "src/api/v2/nested.py",
    }

    changed_commit = commit_change(
        attempt,
        "src/api/v2/nested.py",
        "nested v2\n",
        message="change wildcard child input",
    )
    git(repo, "update-ref", "refs/heads/integration", changed_commit)
    advisory = entry_for(supervisor.status(), task["id"])["read_dependency_advisory"]

    assert advisory["state"] == "changed"
    assert [item["path"] for item in advisory["changed_paths"]] == ["src/api/v2/nested.py"]


def test_root_wide_read_glob_is_unknown_instead_of_scanning_repository(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    task = supervisor.create_task(
        "Use all Python inputs",
        "Declare the broad input as a glob.",
        ["checks pass"],
        ["beta.txt"],
        read_resources=["**/*.py"],
    )
    attempt = supervisor.claim(task["id"], "worker-a")
    with supervisor.connect() as connection:
        baseline = json.loads(
            connection.execute(
                "SELECT read_resources_snapshot_json FROM attempts WHERE id = ?",
                (attempt["id"],),
            ).fetchone()["read_resources_snapshot_json"]
        )

    advisory = entry_for(supervisor.status(), task["id"])["read_dependency_advisory"]

    assert baseline["state"] == "unknown"
    assert "root-wide glob" in baseline["reason"]
    assert advisory["state"] == "unknown"
    assert "root-wide glob" in advisory["reason"]


def test_read_resource_prefix_scan_limit_is_unknown(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (repo / "src").mkdir()
    (repo / "src" / "a.py").write_text("a\n", encoding="utf-8")
    (repo / "src" / "b.py").write_text("b\n", encoding="utf-8")
    git(repo, "add", "src")
    git(repo, "commit", "-m", "add source files")
    supervisor = GitSupervisor(repo)
    monkeypatch.setattr("agent_control_plane.supervisor.claims._READ_RESOURCE_MAX_PATHS", 1)
    task = supervisor.create_task(
        "Update Python inputs",
        "Declare the directory-scoped input.",
        ["checks pass"],
        ["beta.txt"],
        read_resources=["src/**/*.py"],
    )
    attempt = supervisor.claim(task["id"], "worker-a")
    with supervisor.connect() as connection:
        baseline = json.loads(
            connection.execute(
                "SELECT read_resources_snapshot_json FROM attempts WHERE id = ?",
                (attempt["id"],),
            ).fetchone()["read_resources_snapshot_json"]
        )

    advisory = entry_for(supervisor.status(), task["id"])["read_dependency_advisory"]

    assert baseline["state"] == "unknown"
    assert "exceeded 1 tracked paths" in baseline["reason"]
    assert advisory["state"] == "unknown"
    assert "exceeded 1 tracked paths" in advisory["reason"]


def test_read_resource_listing_byte_limit_is_unknown(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    monkeypatch.setattr("agent_control_plane.supervisor.claims._READ_RESOURCE_MAX_LISTING_BYTES", 1)
    task = supervisor.create_task(
        "Use a tracked input",
        "Declare an exact file input.",
        ["checks pass"],
        ["beta.txt"],
        read_resources=["alpha.txt"],
    )
    attempt = supervisor.claim(task["id"], "worker-a")
    with supervisor.connect() as connection:
        baseline = json.loads(
            connection.execute(
                "SELECT read_resources_snapshot_json FROM attempts WHERE id = ?",
                (attempt["id"],),
            ).fetchone()["read_resources_snapshot_json"]
        )

    advisory = entry_for(supervisor.status(), task["id"])["read_dependency_advisory"]

    assert baseline["state"] == "unknown"
    assert "listing exceeded 1 bytes" in baseline["reason"]
    assert advisory["state"] == "unknown"
    assert "listing exceeded 1 bytes" in advisory["reason"]


def test_unmatched_read_resource_is_unknown_not_unchanged(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    task = supervisor.create_task(
        "Use an external schema",
        "Declare the interface input.",
        ["checks pass"],
        ["beta.txt"],
        read_resources=["missing/schema.json"],
    )
    supervisor.claim(task["id"], "worker-a")
    before_view = state_fingerprint(supervisor)

    advisory = entry_for(supervisor.status(), task["id"])["read_dependency_advisory"]

    assert advisory["state"] == "unknown"
    assert advisory["unmatched_resources"] == ["missing/schema.json"]
    assert "did not match" in advisory["reason"]
    assert state_fingerprint(supervisor) == before_view


def test_deleted_declared_file_is_unknown_with_deletion_identity(repo: Path) -> None:
    git(repo, "branch", "integration", "HEAD")
    supervisor = GitSupervisor(repo)
    task = supervisor.create_task(
        "Read a file removed upstream",
        "Declare a tracked input.",
        ["checks pass"],
        ["beta.txt"],
        base_branch="integration",
        read_resources=["alpha.txt"],
    )
    attempt = supervisor.claim(task["id"], "worker-a")
    before_oid = git(repo, "rev-parse", f"{task['base_sha']}:alpha.txt")
    worktree = Path(attempt["worktree"])
    git(worktree, "rm", "alpha.txt")
    git(worktree, "commit", "-m", "remove declared input")
    deleted_commit = git(worktree, "rev-parse", "HEAD")
    git(repo, "update-ref", "refs/heads/integration", deleted_commit)
    before_view = state_fingerprint(supervisor)

    advisory = entry_for(supervisor.status(), task["id"])["read_dependency_advisory"]

    assert advisory["state"] == "unknown"
    assert advisory["unmatched_resources"] == ["alpha.txt"]
    assert advisory["changed_paths"] == [
        {
            "path": "alpha.txt",
            "before_object_oid": before_oid,
            "after_object_oid": None,
        }
    ]
    assert state_fingerprint(supervisor) == before_view


def test_unavailable_integration_base_is_unknown(repo: Path) -> None:
    git(repo, "branch", "integration", "HEAD")
    supervisor = GitSupervisor(repo)
    task = supervisor.create_task(
        "Use an interface on integration",
        "Declare the tracked input.",
        ["checks pass"],
        ["beta.txt"],
        base_branch="integration",
        read_resources=["alpha.txt"],
    )
    supervisor.claim(task["id"], "worker-a")
    git(repo, "update-ref", "-d", "refs/heads/integration")
    before_view = state_fingerprint(supervisor)

    advisory = entry_for(supervisor.status(), task["id"])["read_dependency_advisory"]

    assert advisory["state"] == "unknown"
    assert advisory["current_base_sha"] is None
    assert advisory["reason"] == "configured integration base is unavailable"
    assert state_fingerprint(supervisor) == before_view


def test_retry_preserves_original_read_resource_snapshot(repo: Path) -> None:
    git(repo, "branch", "integration", "HEAD")
    supervisor = GitSupervisor(repo)
    task = supervisor.create_task(
        "Retry consumer",
        "Use the declared API input.",
        ["checks pass"],
        ["beta.txt"],
        base_branch="integration",
        read_resources=["alpha.txt"],
    )
    first = supervisor.claim(task["id"], "worker-a")
    with supervisor.connect() as connection:
        first_snapshot = connection.execute(
            "SELECT read_resources_snapshot_json FROM attempts WHERE id = ?", (first["id"],)
        ).fetchone()["read_resources_snapshot_json"]
    changed_commit = commit_change(first, "alpha.txt", "changed API input\n")
    git(repo, "update-ref", "refs/heads/integration", changed_commit)
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET latest_sha = ?, lease_expires_at = 1 WHERE id = ?",
            (changed_commit, first["id"]),
        )
        connection.execute(
            "UPDATE resource_leases SET lease_expires_at = 1 WHERE attempt_id = ?",
            (first["id"],),
        )

    second = supervisor.claim(task["id"], "worker-b")

    with supervisor.connect() as connection:
        second_snapshot = connection.execute(
            "SELECT read_resources_snapshot_json FROM attempts WHERE id = ?", (second["id"],)
        ).fetchone()["read_resources_snapshot_json"]
    assert second_snapshot == first_snapshot
    advisory = entry_for(supervisor.status(), task["id"])["read_dependency_advisory"]
    assert advisory["state"] == "changed"
    assert advisory["changed_paths"][0]["before_object_oid"] == git(
        repo, "rev-parse", f"{task['base_sha']}:alpha.txt"
    )


def test_status_inventories_git_worktrees_without_guessing_unmatched_owners(
    repo: Path,
) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt", title="known attempt")
    attempt = supervisor.claim(created["id"], "worker-alpha")
    detached = repo.parent / "detached external\nworktree \x1b[31m"
    attached = repo.parent / "attached external worktree"
    git(repo, "worktree", "add", "--detach", str(detached), "HEAD")
    git(repo, "worktree", "add", "-b", "inventory-branch", str(attached), "HEAD")
    before_database = state_fingerprint(supervisor)
    before_registrations = git(repo, "worktree", "list", "--porcelain")
    before_repository_status = git(repo, "status", "--porcelain")
    before_refs = git(repo, "show-ref")

    snapshot = supervisor.status()

    inventory = snapshot["git_worktrees"]
    assert inventory["status"] == "available"
    paths = [entry["path"] for entry in inventory["entries"]]
    assert all(entry["owner"] == "unknown" for entry in inventory["entries"])
    assert paths == sorted(
        paths, key=lambda path: os.path.normcase(os.path.abspath(os.path.normpath(path)))
    )
    by_path = {entry["path"]: entry for entry in inventory["entries"]}
    primary = by_path[str(repo)]
    assert primary["managed_by_acp"] is False
    assert primary["owner"] == "unknown"
    assert primary["mapping_status"] == "unmatched"
    managed = by_path[attempt["worktree"]]
    assert managed["managed_by_acp"] is True
    assert managed["mapping_status"] == "matched"
    assert managed["owner"] == "unknown"
    assert managed["recorded_agent_id"] == "worker-alpha"
    assert managed["attempts"] == [
        {
            "attempt_id": attempt["id"],
            "task_id": created["id"],
            "status": "working",
            "recorded_agent_id": "worker-alpha",
            "branch": attempt["branch"],
        }
    ]
    assert len(managed["head"]) >= 40

    detached_entry = by_path[str(detached)]
    assert detached_entry["detached"] is True
    assert detached_entry["branch"] is None
    assert detached_entry["managed_by_acp"] is False
    assert detached_entry["owner"] == "unknown"
    assert detached_entry["mapping_status"] == "unmatched"

    attached_entry = by_path[str(attached)]
    assert attached_entry["branch"] == "inventory-branch"
    assert attached_entry["detached"] is False
    assert attached_entry["managed_by_acp"] is False
    assert attached_entry["owner"] == "unknown"
    rendered = supervisor.render_status(snapshot)
    assert "owner=unknown" in rendered
    assert all(json.dumps(path, ensure_ascii=True) in rendered for path in paths)
    assert "\x1b" not in rendered
    assert "\\u001b[31m" in rendered

    assert state_fingerprint(supervisor) == before_database
    assert git(repo, "worktree", "list", "--porcelain") == before_registrations
    assert git(repo, "status", "--porcelain") == before_repository_status
    assert git(repo, "show-ref") == before_refs


def test_status_does_not_attribute_path_when_attempt_branch_mismatches(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker-alpha")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET branch = ? WHERE id = ?",
            ("stale-recorded-branch", attempt["id"]),
        )

    entry = next(
        entry
        for entry in supervisor.status()["git_worktrees"]["entries"]
        if entry["path"] == attempt["worktree"]
    )

    assert entry["managed_by_acp"] is False
    assert entry["mapping_status"] == "branch_mismatch"
    assert entry["owner"] == "unknown"
    assert entry["attempts"][0]["attempt_id"] == attempt["id"]


def test_status_does_not_resolve_relative_persisted_attempt_path(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker-alpha")
    relative_path = Path(attempt["worktree"]).relative_to(repo.parent)
    monkeypatch.chdir(repo.parent)
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET worktree = ? WHERE id = ?",
            (str(relative_path), attempt["id"]),
        )

    entry = next(
        entry
        for entry in supervisor.status()["git_worktrees"]["entries"]
        if entry["path"] == attempt["worktree"]
    )

    assert entry["managed_by_acp"] is False
    assert entry["mapping_status"] == "unmatched"
    assert entry["owner"] == "unknown"
    assert entry["attempts"] == []


def test_status_marks_malformed_git_worktree_listing_unavailable(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)

    def malformed_listing(*arguments: object, **_kwargs: object) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=arguments,
            returncode=0,
            stdout=b"not a valid worktree record\0",
            stderr=b"",
        )

    monkeypatch.setattr(subprocess, "run", malformed_listing)

    snapshot = supervisor.status()

    assert snapshot["git_worktrees"] == {
        "status": "unavailable",
        "error": "git_worktree_list_unavailable",
        "entries": [],
    }
    assert "inventory unavailable (git_worktree_list_unavailable)" in supervisor.render_status(
        snapshot
    )


def test_status_rejects_unrecognized_git_object_id_width(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    listing = (
        b"\0".join(
            [
                b"worktree " + str(repo).encode(),
                b"HEAD " + b"a" * 42,
                b"branch refs/heads/main",
                b"",
            ]
        )
        + b"\0"
    )

    def malformed_listing(*arguments: object, **_kwargs: object) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(args=arguments, returncode=0, stdout=listing, stderr=b"")

    monkeypatch.setattr(subprocess, "run", malformed_listing)

    inventory = supervisor.status()["git_worktrees"]

    assert inventory == {
        "status": "unavailable",
        "error": "git_worktree_list_unavailable",
        "entries": [],
    }


@pytest.mark.parametrize("duplicate_field", ["worktree", "HEAD", "branch", "detached"])
def test_status_rejects_duplicate_git_identity_fields(
    repo: Path, monkeypatch: pytest.MonkeyPatch, duplicate_field: str
) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker-alpha")
    branch = f"branch refs/heads/{attempt['branch']}".encode()
    head = b"a" * 40
    fields = [f"worktree {attempt['worktree']}".encode(), b"HEAD " + head, branch]
    if duplicate_field == "worktree":
        fields[0:1] = [b"worktree /foreign/worktree", fields[0]]
    elif duplicate_field == "HEAD":
        fields[2:2] = [b"HEAD " + head]
    elif duplicate_field == "branch":
        fields[2:2] = [branch]
    else:
        fields.extend([b"detached", b"detached"])
    listing = b"\0".join(fields) + b"\0\0"

    def duplicate_listing(*arguments: object, **_kwargs: object) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(args=arguments, returncode=0, stdout=listing, stderr=b"")

    monkeypatch.setattr(subprocess, "run", duplicate_listing)

    inventory = supervisor.status()["git_worktrees"]

    assert inventory == {
        "status": "unavailable",
        "error": "git_worktree_list_unavailable",
        "entries": [],
    }


def test_status_reports_git_listing_failure_as_unavailable(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)

    def failed_listing(*arguments: object, **_kwargs: object) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=arguments, returncode=128, stdout=b"", stderr=b"simulated Git failure"
        )

    monkeypatch.setattr(subprocess, "run", failed_listing)

    inventory = supervisor.status()["git_worktrees"]

    assert inventory == {"status": "unavailable", "error": "git_error", "entries": []}


def test_status_rejects_duplicate_git_worktree_paths(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    record = b"\0".join(
        [b"worktree " + str(repo).encode(), b"HEAD " + b"a" * 40, b"branch refs/heads/main"]
    )
    listing = record + b"\0\0" + record + b"\0\0"

    def duplicate_listing(*arguments: object, **_kwargs: object) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(args=arguments, returncode=0, stdout=listing, stderr=b"")

    monkeypatch.setattr(subprocess, "run", duplicate_listing)

    inventory = supervisor.status()["git_worktrees"]

    assert inventory == {
        "status": "unavailable",
        "error": "git_worktree_list_unavailable",
        "entries": [],
    }


def test_first_explicit_empty_checkpoint_establishes_age(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "agent-a")

    assert entry_for(supervisor.status(), created["id"])["checkpoint_age_seconds"] is None

    supervisor.heartbeat(attempt["id"], attempt["claim_token"], {})

    entry = entry_for(supervisor.status(), created["id"])
    assert entry["checkpoint"] == {}
    assert entry["checkpoint_age_seconds"] is not None
    assert entry["checkpoint_age_seconds"] < 60


def test_status_never_mutates_even_with_an_expired_attempt(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "agent-a")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET lease_expires_at = 1 WHERE id = ?", (attempt["id"],)
        )
    before = state_fingerprint(supervisor)

    snapshot = supervisor.status()

    assert state_fingerprint(supervisor) == before
    entry = entry_for(snapshot, created["id"])
    assert entry["lease_expired"] is True
    assert entry["awaiting_reap"] is True
    assert entry["phase"] == "working"


def test_heartbeat_age_shrinks_after_a_heartbeat(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "agent-a")
    with supervisor.connect() as connection:
        connection.execute(
            """
            UPDATE attempts
            SET heartbeat_at = '2020-01-01T00:00:00Z',
                checkpoint_at = '2020-01-01T00:00:00Z',
                updated_at = '2020-01-01T00:00:00Z'
            WHERE id = ?
            """,
            (attempt["id"],),
        )
    stale = entry_for(supervisor.status(), created["id"])["heartbeat_age_seconds"]
    assert stale > 100000

    supervisor.heartbeat(attempt["id"], attempt["claim_token"], {"phase": "tests"})

    entry = entry_for(supervisor.status(), created["id"])
    assert entry["heartbeat_age_seconds"] < 60
    assert entry["checkpoint"] == {"phase": "tests"}
    assert entry["checkpoint_age_seconds"] < 60


def test_liveness_renewal_preserves_checkpoint_and_its_age(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "agent-a")
    supervisor.heartbeat(attempt["id"], attempt["claim_token"], {"phase": "editing"})

    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET checkpoint_at = '2020-01-01T00:00:00Z' WHERE id = ?",
            (attempt["id"],),
        )

    supervisor.heartbeat(attempt["id"], attempt["claim_token"])
    entry = entry_for(supervisor.status(), created["id"])
    assert entry["checkpoint"] == {"phase": "editing"}
    assert entry["heartbeat_age_seconds"] < 60
    assert entry["checkpoint_age_seconds"] > 100000

    supervisor.heartbeat(attempt["id"], attempt["claim_token"], {"phase": "editing"})
    same = entry_for(supervisor.status(), created["id"])
    assert same["checkpoint_age_seconds"] > 100000

    supervisor.heartbeat(attempt["id"], attempt["claim_token"], {"phase": "tests"})
    changed = entry_for(supervisor.status(), created["id"])
    assert changed["checkpoint"] == {"phase": "tests"}
    assert changed["checkpoint_age_seconds"] < 60


def test_checkpoint_stale_threshold_is_advisory_only(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt", title="slow test run")
    attempt = supervisor.claim(created["id"], "agent-a")
    supervisor.heartbeat(attempt["id"], attempt["claim_token"], {"phase": "tests"})
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET checkpoint_at = '2020-01-01T00:00:00Z' WHERE id = ?",
            (attempt["id"],),
        )

    without_threshold = entry_for(supervisor.status(), created["id"])
    assert without_threshold["category"] == "active"
    assert without_threshold["checkpoint_stale_advisory"] is False

    snapshot = supervisor.status(checkpoint_stale_seconds=60)
    entry = entry_for(snapshot, created["id"])
    assert entry["checkpoint_stale_advisory"] is True
    assert entry["status"] == "working"
    item = next(item for item in snapshot["attention"] if item["task_id"] == created["id"])
    assert item["category"] == "checkpoint_stale"
    assert "does not establish progress" in item["reason"]
    assert entry["heartbeat_age_seconds"] < 60
    assert supervisor.render_status(snapshot).count("checkpoint unchanged") == 1


def test_status_reports_repeated_qc_finding_only_within_same_task(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_config(
        repo,
        qc_commands=[python_command("pass")],
        critic_command="builtin",
    )
    supervisor = GitSupervisor(repo)
    _install_revising_critic(supervisor, monkeypatch)
    repeated_task = make_task(supervisor, "alpha.txt", title="repeated finding")

    first, first_qc = _submit_revised_commit(supervisor, repeated_task["id"], "case1")
    latest, latest_qc = _submit_revised_commit(supervisor, repeated_task["id"], "case2")
    assert first_qc["findings"][0]["evidence"] != latest_qc["findings"][0]["evidence"]

    separate_task = make_task(supervisor, "alpha.txt", title="single finding")
    _submit_revised_commit(supervisor, separate_task["id"], "case2")

    def reject_candidate_execution(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("status must not execute candidate or QC code")

    monkeypatch.setattr(supervisor, "_run_command", reject_candidate_execution)
    monkeypatch.setattr(supervisor, "_run_critic", reject_candidate_execution)
    before = state_fingerprint(supervisor)
    snapshot = supervisor.status()
    after = state_fingerprint(supervisor)

    repeated_entry = entry_for(snapshot, repeated_task["id"])
    assert repeated_entry["status"] == "changes_requested"
    assert repeated_entry["qc"]["verdict"] == "revise"
    assert len(repeated_entry["repeated_qc_findings"]) == 1
    finding = repeated_entry["repeated_qc_findings"][0]
    assert finding["advisory"] is True
    assert finding["fingerprint"]
    assert finding["requirement"] == " tests   PASS "
    assert finding["finding"] == " SAME gap "
    assert finding["required_fix"] == " Fix before retry "
    assert finding["distinct_commit_count"] == 2
    assert finding["latest_commit_sha"] == latest["commit_sha"]
    assert finding["matching_prior_commit_count"] == 1
    assert finding["matching_prior_commit_shas"] == [first["commit_sha"]]
    assert finding["prior_commit_shas_truncated"] is False
    assert finding["latest_qc_at"] == latest_qc["finished_at"]
    assert "evidence" not in finding
    assert json.loads(json.dumps(finding)) == finding
    assert entry_for(snapshot, separate_task["id"])["repeated_qc_findings"] == []
    assert state_fingerprint(supervisor) == before == after
    assert "qc recurring findings 1" in supervisor.render_status(snapshot)
    repeated_attention = next(
        item for item in snapshot["attention"] if item["task_id"] == repeated_task["id"]
    )
    assert (
        "QC feedback recurs for 1 finding(s) across distinct commits (advisory)"
        in (repeated_attention["reason"])
    )


def test_status_hides_old_recurrence_when_latest_qc_passes(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_config(
        repo,
        qc_commands=[python_command("pass")],
        critic_command="builtin",
    )
    supervisor = GitSupervisor(repo)
    _install_revising_critic(supervisor, monkeypatch)
    task = make_task(supervisor, "alpha.txt", title="resolved finding")

    _submit_revised_commit(supervisor, task["id"], "case1")
    _submit_revised_commit(supervisor, task["id"], "case2")

    attempt = supervisor.claim(task["id"], "worker-a")
    commit_change(attempt, "alpha.txt", "pass\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    qc = supervisor.run_qc(submission["id"], "independent-qc")
    assert qc["verdict"] == "pass"

    entry = entry_for(supervisor.status(), task["id"])
    assert entry["qc"]["verdict"] == "pass"
    assert entry["repeated_qc_findings"] == []


def test_status_does_not_match_a_different_stable_finding(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_config(
        repo,
        qc_commands=[python_command("pass")],
        critic_command="builtin",
    )
    supervisor = GitSupervisor(repo)
    _install_revising_critic(supervisor, monkeypatch)
    task = make_task(supervisor, "alpha.txt", title="different finding")

    _submit_revised_commit(supervisor, task["id"], "case1")
    _submit_revised_commit(supervisor, task["id"], "different")

    entry = entry_for(supervisor.status(), task["id"])
    assert entry["qc"]["verdict"] == "revise"
    assert entry["repeated_qc_findings"] == []


def test_status_ignores_repeated_review_of_same_commit(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_config(
        repo,
        qc_commands=[python_command("pass")],
        critic_command="builtin",
    )
    supervisor = GitSupervisor(repo)
    _install_revising_critic(supervisor, monkeypatch)
    task = make_task(supervisor, "alpha.txt", title="one submitted commit")
    submission, _ = _submit_revised_commit(supervisor, task["id"], "case1")

    with supervisor.connect() as connection:
        connection.execute(
            """
            INSERT INTO qc_runs
              (id, submission_id, reviewer_id, commit_sha, verdict, findings_json,
               results_json, packet_sha256, reviewer_provenance_json, reviewer_signature,
               bundle_sha256, policy_fingerprint, trust_bundle_json, started_at, finished_at)
            SELECT ?, submission_id, reviewer_id, commit_sha, verdict, findings_json,
                   results_json, packet_sha256, reviewer_provenance_json, reviewer_signature,
                   bundle_sha256, policy_fingerprint, trust_bundle_json, started_at, finished_at
            FROM qc_runs WHERE submission_id = ?
            """,
            (f"duplicate-{uuid.uuid4()}", submission["id"]),
        )

    entry = entry_for(supervisor.status(), task["id"])
    assert entry["repeated_qc_findings"] == []


def test_status_uses_newest_submission_outcome_for_duplicate_commit_sha(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_config(
        repo,
        qc_commands=[python_command("pass")],
        critic_command="builtin",
    )
    supervisor = GitSupervisor(repo)
    _install_revising_critic(supervisor, monkeypatch)
    task = make_task(supervisor, "alpha.txt", title="duplicate commit submission")

    older, _ = _submit_revised_commit(supervisor, task["id"], "case1")
    latest, _ = _submit_revised_commit(supervisor, task["id"], "case2")
    resubmission_id = f"resubmission-{uuid.uuid4()}"
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE submissions SET created_at = '2020-01-01T00:00:00Z' WHERE id = ?",
            (older["id"],),
        )
        connection.execute(
            """
            INSERT INTO submissions
              (id, task_id, attempt_id, worker_agent_id, commit_sha, tree_sha,
               object_contract, patch_sha256, changed_paths_json, resource_tokens_json,
               status, qc_resume_status, created_at)
            SELECT ?, task_id, attempt_id, worker_agent_id, commit_sha, tree_sha,
                   object_contract, patch_sha256, changed_paths_json, resource_tokens_json,
                   status, qc_resume_status, '2020-01-02T00:00:00Z'
            FROM submissions WHERE id = ?
            """,
            (resubmission_id, older["id"]),
        )
        connection.execute(
            """
            INSERT INTO qc_runs
              (id, submission_id, reviewer_id, commit_sha, verdict, findings_json,
               results_json, packet_sha256, started_at, finished_at)
            VALUES (?, ?, 'independent-qc', ?, 'pass', '[]', '{}', 'test', ?, ?)
            """,
            (
                f"pass-{uuid.uuid4()}",
                resubmission_id,
                older["commit_sha"],
                "2020-01-02T00:00:00Z",
                "2020-01-02T00:00:01Z",
            ),
        )

    entry = entry_for(supervisor.status(), task["id"])
    assert entry["qc"]["verdict"] == "revise"
    assert entry["qc"]["submission_id"] == latest["id"]
    assert entry["repeated_qc_findings"] == []


def test_qc_finding_identity_rejects_missing_fields_and_normalizes_text() -> None:
    first = {
        "requirement": "QC passes",
        "finding": " same gap ",
        "required_fix": "Fix this now",
    }
    equivalent = {
        "requirement": " qc   PASSES ",
        "finding": "SAME  gap",
        "required_fix": " fix THIS now ",
        "evidence": "different details are not identity",
    }

    assert StatusView._qc_finding_identity(first) == StatusView._qc_finding_identity(equivalent)
    assert StatusView._qc_finding_identity({"requirement": "only one field"}) is None
    assert StatusView._parse_qc_findings("not json") == []


def test_qc_latest_lookup_has_a_covering_index(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    with supervisor.connect() as connection:
        columns = connection.execute(
            "PRAGMA index_info('idx_qc_runs_submission_latest')"
        ).fetchall()

    assert [row["name"] for row in columns] == [
        "submission_id",
        "finished_at",
        "id",
    ]


def test_unknown_legacy_checkpoint_age_is_not_marked_stale(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt", title="legacy checkpoint")
    attempt = supervisor.claim(created["id"], "agent-a")
    with supervisor.connect() as connection:
        connection.execute("UPDATE attempts SET checkpoint_at = '' WHERE id = ?", (attempt["id"],))

    snapshot = supervisor.status(checkpoint_stale_seconds=1)
    entry = entry_for(snapshot, created["id"])

    assert entry["heartbeat_age_seconds"] is not None
    assert entry["checkpoint_age_seconds"] is None
    assert entry["checkpoint_stale_advisory"] is False
    assert entry["category"] == "active"
    assert "cp unknown" in supervisor.render_status(snapshot)


def test_attention_queue_ranks_human_required_above_active_work(repo: Path) -> None:
    write_config(repo, qc_commands=[python_command("raise SystemExit(1)")])
    supervisor = GitSupervisor(repo)
    failing = make_task(supervisor, "alpha.txt", title="needs a human")
    busy = make_task(supervisor, "beta.txt", title="ordinary work")
    attempt = supervisor.claim(failing["id"], "agent-a")
    commit_change(attempt, "alpha.txt", "change\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    supervisor.run_qc(submission["id"], "independent-qc")
    supervisor.claim(busy["id"], "agent-b")

    attention = supervisor.status()["attention"]

    assert attention[0]["task_id"] == failing["id"]
    assert attention[0]["category"] == "human_required"
    assert attention[0]["rank"] < attention[-1]["rank"]
    assert attention[-1]["task_id"] == busy["id"]
    assert attention[-1]["category"] == "active"
    assert attention[0]["reason"]


def test_failed_cleanup_outranks_review_and_is_listed(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt", title="leaky runtime")
    attempt = supervisor.claim(created["id"], "agent-a")
    reviewing = make_task(supervisor, "beta.txt", title="waiting on review")
    approve(supervisor, reviewing["id"], "beta.txt", "reviewed\n")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE runtime_environments SET state = 'teardown_failed' WHERE attempt_id = ?",
            (attempt["id"],),
        )

    snapshot = supervisor.status()

    categories = [item["category"] for item in snapshot["attention"]]
    assert categories.index("cleanup_failed") < categories.index("review")
    assert snapshot["cleanup_failures"] == [
        {
            "attempt_id": attempt["id"],
            "task_id": created["id"],
            "state": "teardown_failed",
            "owner": "agent-a",
            "severity": None,
            "age_seconds": None,
            "quarantined_resources": 0,
        }
    ]


def test_lease_risk_is_reported_before_expiry(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "agent-a")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET lease_expires_at = ? WHERE id = ?",
            (int(time.time()) + 5, attempt["id"]),
        )

    snapshot = supervisor.status(lease_risk_seconds=30)

    item = next(entry for entry in snapshot["attention"] if entry["task_id"] == created["id"])
    assert item["category"] == "lease_risk"
    assert entry_for(snapshot, created["id"])["lease_seconds_remaining"] <= 5


def test_status_reports_runtime_allocations_and_blockers(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    holder = make_task(supervisor, "alpha.txt", title="holder")
    waiting = make_task(supervisor, "alpha.txt", title="waiting")
    supervisor.claim(holder["id"], "agent-a")

    snapshot = supervisor.status()

    blocked = entry_for(snapshot, waiting["id"])
    assert blocked["ready"] is False
    conflict = next(item for item in blocked["blockers"] if item["kind"] == "resource_conflict")
    assert conflict["owner_task_id"] == holder["id"]
    assert snapshot["counts"]["blocked"] == 1
    assert snapshot["counts"]["active"] == 1


def test_status_is_bounded_and_machine_readable(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    for index in range(6):
        make_task(supervisor, f"file-{index}.txt", title=f"task {index}", priority=index)

    snapshot = supervisor.status(limit=3)

    assert len(snapshot["tasks"]) == 3
    assert snapshot["truncated"] is True
    assert snapshot["counts"]["tasks"] == 6
    assert json.loads(json.dumps(snapshot, sort_keys=True))["truncated"] is True
    assert [item["title"] for item in snapshot["tasks"]] == ["task 5", "task 4", "task 3"]


def test_status_survives_a_dead_worker_pid(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "agent-a")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET pid = 999999, pid_identity = 'kernel-start-dead' WHERE id = ?",
            (attempt["id"],),
        )

    entry = entry_for(supervisor.status(), created["id"])

    assert entry["worker"]["pid"] == 999999
    assert entry["worker"]["liveness"] == "dead"
    assert entry["worker"]["alive"] is False


def test_status_marks_missing_worker_identity_unproven(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "agent-a")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET pid = ?, pid_identity = '' WHERE id = ?",
            (os.getpid(), attempt["id"]),
        )

    entry = entry_for(supervisor.status(), created["id"])

    assert entry["worker"]["liveness"] == "unproven"
    assert entry["worker"]["alive"] is None


@pytest.mark.parametrize("reader_result", [None, OSError("identity unavailable")])
def test_status_marks_unreadable_worker_identity_unproven(
    repo: Path, monkeypatch: pytest.MonkeyPatch, reader_result: str | Exception | None
) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "agent-a")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET pid = ?, pid_identity = 'kernel-start-current' WHERE id = ?",
            (os.getpid(), attempt["id"]),
        )

    def identity_reader(_pid: int) -> str | None:
        if isinstance(reader_result, Exception):
            raise reader_result
        return reader_result

    monkeypatch.setattr(supervisor, "_process_identity", identity_reader)

    entry = entry_for(supervisor.status(), created["id"])

    assert entry["worker"]["liveness"] == "unproven"
    assert entry["worker"]["alive"] is None


def test_status_rejects_a_recycled_worker_pid(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "agent-a")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET pid = ?, pid_identity = 'kernel-start-old' WHERE id = ?",
            (os.getpid(), attempt["id"]),
        )
    monkeypatch.setattr(supervisor, "_process_identity", lambda _pid: "kernel-start-new")

    entry = entry_for(supervisor.status(), created["id"])

    assert entry["worker"]["pid"] == os.getpid()
    assert entry["worker"]["pid_identity"] == "kernel-start-old"
    assert entry["worker"]["liveness"] == "dead"
    assert entry["worker"]["alive"] is False


def test_status_accepts_only_the_registered_worker_identity(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "agent-a")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET pid = ?, pid_identity = 'kernel-start-current' WHERE id = ?",
            (os.getpid(), attempt["id"]),
        )
    monkeypatch.setattr(supervisor, "_process_identity", lambda _pid: "kernel-start-current")

    entry = entry_for(supervisor.status(), created["id"])

    assert entry["worker"]["liveness"] == "alive"
    assert entry["worker"]["alive"] is True


@pytest.mark.parametrize(
    ("task_status", "attempt_status"),
    [("terminating", "terminating"), ("cleanup_pending", "submitted")],
)
def test_status_surfaces_collision_fences_and_cleanup_error(
    repo: Path,
    task_status: str,
    attempt_status: str,
) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt", title="fenced cleanup")
    attempt = supervisor.claim(created["id"], "agent-a")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE tasks SET status = ?, cleanup_target_status = 'conflicted', "
            "cleanup_error = 'termination proof missing' WHERE id = ?",
            (task_status, created["id"]),
        )
        connection.execute(
            "UPDATE attempts SET status = ?, pid = ?, pid_identity = 'kernel-start-7' WHERE id = ?",
            (attempt_status, os.getpid(), attempt["id"]),
        )
        connection.execute(
            "UPDATE resource_leases SET lease_expires_at = ? WHERE task_id = ?",
            (2**62, created["id"]),
        )

    snapshot = supervisor.status()
    entry = entry_for(snapshot, created["id"])
    attention = next(item for item in snapshot["attention"] if item["task_id"] == created["id"])

    assert snapshot["counts"]["active"] == 1
    assert entry["awaiting_reap"] is True
    assert entry["held_resources"] == ["alpha.txt"]
    assert entry["cleanup_error"] == "termination proof missing"
    assert entry["worker"]["pid_identity"] == "kernel-start-7"
    assert attention["category"] == "cleanup_failed"
    assert "1 collision fence(s) held" in attention["reason"]
    assert "last error: termination proof missing" in attention["reason"]


def test_render_text_is_a_single_screen_summary(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt", title="live work")
    supervisor.claim(created["id"], "agent-a")

    text = supervisor.render_status(supervisor.status())

    assert "live work" in text
    assert "ATTENTION" in text
    assert "agent-a" in text
    assert "DISK" in text
    assert "filesystem at" in text
    assert len(text.splitlines()) < 40


def test_status_discloses_configured_disk_admission_floor(repo: Path) -> None:
    config_path = repo / "acp.toml"
    config_path.write_text(
        config_path.read_text(encoding="utf-8") + "\n[worktrees]\nmin_free_bytes = 1024\n",
        encoding="utf-8",
    )
    supervisor = GitSupervisor(repo)

    snapshot = supervisor.status()
    text = supervisor.render_status(snapshot)

    assert snapshot["disk"]["admission_min_free_bytes"] == 1024
    assert "minimum available space before new worktree: 1.0 KiB" in text


def test_status_reports_ports_held_by_an_attempt(repo: Path) -> None:
    port = _free_port()
    (repo / "acp.toml").write_text(
        (repo / "acp.toml").read_text(encoding="utf-8")
        + f"\n[runtime.ports]\nAPP_PORT = [{port}, {port}]\n",
        encoding="utf-8",
    )
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "alpha.txt")
    supervisor.claim(created["id"], "agent-a")

    entry = entry_for(supervisor.status(), created["id"])

    assert entry["runtime"]["allocations"] == [{"pool_name": "APP_PORT", "value": port}]


def _free_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])
    finally:
        probe.close()


def test_status_and_queue_agree_about_what_is_launchable(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    make_task(supervisor, "src/**", title="wide", priority=90)
    make_task(supervisor, "src/module.py", title="narrow", priority=80)
    make_task(supervisor, "beta.txt", title="separate", priority=70)

    snapshot = supervisor.status()
    queue = supervisor.ready_queue()

    assert snapshot["counts"]["ready"] == len(queue["ready"]) == 2
    assert snapshot["counts"]["blocked"] == len(queue["blocked"]) == 1
    assert {entry["task_id"] for entry in snapshot["tasks"] if entry["ready"] is True} == {
        entry["task_id"] for entry in queue["ready"]
    }
