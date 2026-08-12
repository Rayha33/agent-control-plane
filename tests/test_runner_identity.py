from __future__ import annotations

import sqlite3
import subprocess
from pathlib import Path

import pytest

from agent_control_plane.git_supervisor import GitSupervisor, SupervisorError
from agent_control_plane.runner_identity import (
    IdentityError,
    assert_distinct,
    credential_digest,
    issue_credential,
    validate_role,
    verify_credential,
)

CONFIG = """
[supervisor]
lease_seconds = 60
qc_timeout_seconds = 30
critic_identity = "independent-qc"
require_critic = false

[qc]
commands = ["python -c 'pass'"]
critic_command = ""

[integration]
commands = ["python -c 'pass'"]

[runtime]
setup_commands = []
teardown_commands = []
"""


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    def git(*arguments: str) -> None:
        subprocess.run(
            ["git", "-C", str(tmp_path), *arguments], check=True, capture_output=True
        )

    git("init", "-b", "main")
    git("config", "user.name", "ACP Test")
    git("config", "user.email", "acp@example.test")
    (tmp_path / "alpha.txt").write_text("base\n", encoding="utf-8")
    git("add", "alpha.txt")
    git("commit", "-m", "base")
    (tmp_path / "acp.toml").write_text(CONFIG, encoding="utf-8")
    return tmp_path


def make_task(supervisor: GitSupervisor) -> dict:
    return supervisor.create_task(
        "bounded change",
        "Change only the declared path.",
        ["The declared content is correct"],
        ["alpha.txt"],
    )


def commit_change(attempt: dict, content: str) -> None:
    worktree = Path(attempt["worktree"])
    (worktree / "alpha.txt").write_text(content, encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(worktree), "add", "alpha.txt"], check=True, capture_output=True
    )
    subprocess.run(
        ["git", "-C", str(worktree), "commit", "-m", "implement"],
        check=True,
        capture_output=True,
    )


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------


def test_credentials_are_high_entropy_and_unique() -> None:
    issued = {issue_credential() for _ in range(200)}
    assert len(issued) == 200
    assert all(len(value) == 64 for value in issued)


def test_verification_accepts_only_the_issued_credential() -> None:
    credential = issue_credential()
    digest = credential_digest(credential)
    assert verify_credential(credential, digest)
    assert not verify_credential(issue_credential(), digest)
    assert not verify_credential("", digest)


def test_role_validation_rejects_unknown_roles() -> None:
    assert validate_role("critic") == "critic"
    with pytest.raises(IdentityError):
        validate_role("reviewer")


def test_assert_distinct_blocks_self_review() -> None:
    assert_distinct("worker-a", "critic-b")
    with pytest.raises(IdentityError) as error:
        assert_distinct("same-agent", "same-agent")
    assert error.value.code == "self_review_forbidden"


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_credential_is_returned_once_and_never_stored(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    enrolled = supervisor.enroll_runner("critic-1", "critic")
    credential = enrolled["credential"]

    # The registry listing must never expose credential material.
    listed = supervisor.runners()
    assert listed == [
        {
            "agent_id": "critic-1",
            "role": "critic",
            "created_at": listed[0]["created_at"],
            "revoked_at": None,
        }
    ]

    # Neither must the database itself.
    connection = sqlite3.connect(supervisor.db_path)
    try:
        blob = "\n".join(str(row) for row in connection.execute("SELECT * FROM runner_identities"))
    finally:
        connection.close()
    assert credential not in blob, "state file must not contain a usable credential"
    assert credential_digest(credential) in blob


def test_double_enrollment_is_rejected(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    supervisor.enroll_runner("critic-1", "critic")
    with pytest.raises(SupervisorError) as error:
        supervisor.enroll_runner("critic-1", "critic")
    assert error.value.code == "runner_already_enrolled"


# ---------------------------------------------------------------------------
# The invariant this task exists for
# ---------------------------------------------------------------------------


def test_worker_cannot_review_by_asserting_the_critic_name(repo: Path) -> None:
    """The whole point: independence must rest on key material, not a string."""
    supervisor = GitSupervisor(repo)
    worker = supervisor.enroll_runner("worker-1", "worker")
    supervisor.enroll_runner("independent-qc", "critic")

    created = make_task(supervisor)
    attempt = supervisor.claim(created["id"], "worker-1", credential=worker["credential"])
    commit_change(attempt, "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])

    # The worker knows the critic's NAME — it is in acp.toml — but not its key.
    with pytest.raises(SupervisorError) as error:
        supervisor.run_qc(submission["id"], "independent-qc", credential=worker["credential"])
    assert error.value.code == "runner_authentication_failed"

    # And with no credential at all.
    with pytest.raises(SupervisorError) as bare:
        supervisor.run_qc(submission["id"], "independent-qc")
    assert bare.value.code == "runner_authentication_failed"


def test_enrolled_critic_can_review(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    worker = supervisor.enroll_runner("worker-1", "worker")
    critic = supervisor.enroll_runner("independent-qc", "critic")

    created = make_task(supervisor)
    attempt = supervisor.claim(created["id"], "worker-1", credential=worker["credential"])
    commit_change(attempt, "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])

    review = supervisor.run_qc(
        submission["id"], "independent-qc", credential=critic["credential"]
    )
    assert review["verdict"] == "pass"


def test_revoked_critic_cannot_review(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    worker = supervisor.enroll_runner("worker-1", "worker")
    critic = supervisor.enroll_runner("independent-qc", "critic")
    created = make_task(supervisor)
    attempt = supervisor.claim(created["id"], "worker-1", credential=worker["credential"])
    commit_change(attempt, "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])

    supervisor.revoke_runner("independent-qc")

    with pytest.raises(SupervisorError) as error:
        supervisor.run_qc(
            submission["id"], "independent-qc", credential=critic["credential"]
        )
    assert error.value.code == "runner_revoked"


def test_role_confusion_is_rejected(repo: Path) -> None:
    """A valid worker credential must not authorise a critic action.

    Authentication runs before the submission is even looked up, so this holds
    regardless of what is being reviewed.
    """
    supervisor = GitSupervisor(repo)
    misrole = supervisor.enroll_runner("independent-qc", "worker")
    with pytest.raises(SupervisorError) as error:
        supervisor.run_qc(
            "any-submission", "independent-qc", credential=misrole["credential"]
        )
    assert error.value.code == "runner_role_mismatch"


def test_unenrolled_agent_is_rejected_once_the_registry_is_active(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    supervisor.enroll_runner("critic-1", "critic")
    created = make_task(supervisor)
    with pytest.raises(SupervisorError) as error:
        supervisor.claim(created["id"], "stranger")
    assert error.value.code == "runner_not_enrolled"


def test_empty_registry_keeps_single_host_behaviour(repo: Path) -> None:
    """Enabling authentication must be deliberate, not a breaking upgrade."""
    supervisor = GitSupervisor(repo)
    created = make_task(supervisor)
    attempt = supervisor.claim(created["id"], "worker-without-credentials")
    commit_change(attempt, "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    review = supervisor.run_qc(submission["id"], "independent-qc")
    assert review["verdict"] == "pass"


def test_one_identity_cannot_hold_both_worker_and_critic_roles(repo: Path) -> None:
    """Self-review is blocked structurally as well as by the explicit check.

    An agent_id carries exactly one role, so no single identity can ever hold
    both a worker and a critic credential — the two ways to review your own
    work are closed independently of each other.
    """
    supervisor = GitSupervisor(repo)
    supervisor.enroll_runner("ambidextrous", "worker")
    with pytest.raises(SupervisorError) as error:
        supervisor.enroll_runner("ambidextrous", "critic")
    assert error.value.code == "runner_already_enrolled"
