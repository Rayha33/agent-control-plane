from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from support import event_count, init_repo, make_task

from agent_control_plane.git_supervisor import GitSupervisor, SupervisorError
from agent_control_plane.supervisor import messaging


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return init_repo(tmp_path)


def test_messages_cross_sibling_worktrees_and_survive_worktree_removal(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    first_runner = supervisor.enroll_runner("worker-first", "worker")
    second_runner = supervisor.enroll_runner("worker-second", "worker")
    first_task = make_task(supervisor, "alpha.txt", title="first parallel task")
    second_task = make_task(supervisor, "beta.txt", title="second parallel task")
    first = supervisor.claim(
        first_task["id"], "worker-first", credential=first_runner["credential"]
    )
    second = supervisor.claim(
        second_task["id"], "worker-second", credential=second_runner["credential"]
    )
    assert first["worktree"] != second["worktree"]

    direct = supervisor.post_message(
        first["id"],
        first["claim_token"],
        "I found the shared API caller; please update its renamed field.",
        kind="handoff",
        recipient_attempt_id=second["id"],
        credential=first_runner["credential"],
    )
    reader = GitSupervisor(repo, read_only=True)
    second_inbox = reader.list_messages(second["id"])
    first_inbox = reader.list_messages(first["id"])
    assert second_inbox["messages"] == [direct]
    assert first_inbox["messages"] == []
    assert direct["sender"] == "worker-first"
    assert direct["task_id"] == first_task["id"]
    assert direct["attempt_id"] == first["id"]
    assert direct["commit_sha"]
    assert direct["content_trust"] == "untrusted_agent_content"

    broadcast = supervisor.post_message(
        first["id"],
        first["claim_token"],
        "Exploration checkpoint: the renamed field is only consumed by the serializer.",
        kind="finding",
        credential=first_runner["credential"],
    )
    assert [item["message_id"] for item in reader.list_messages(first["id"])["messages"]] == [
        broadcast["message_id"]
    ]
    assert [item["message_id"] for item in reader.list_messages(second["id"])["messages"]] == [
        direct["message_id"],
        broadcast["message_id"],
    ]

    assert (repo / ".acp" / "control.db").is_file()
    assert not (Path(first["worktree"]) / ".acp").exists()
    assert not (Path(second["worktree"]) / ".acp").exists()
    subprocess.run(
        ["git", "-C", str(repo), "worktree", "remove", "--force", second["worktree"]],
        check=True,
        capture_output=True,
        text=True,
    )
    reopened = GitSupervisor(repo, read_only=True)
    assert [item["message_id"] for item in reopened.list_messages(second["id"])["messages"]] == [
        direct["message_id"],
        broadcast["message_id"],
    ]


def test_message_append_requires_current_worker_identity_and_fence(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    first_runner = supervisor.enroll_runner("worker-first", "worker")
    second_runner = supervisor.enroll_runner("worker-second", "worker")
    first_task = make_task(supervisor, "alpha.txt", title="first worker")
    second_task = make_task(supervisor, "beta.txt", title="second worker")
    first = supervisor.claim(
        first_task["id"], "worker-first", credential=first_runner["credential"]
    )
    second = supervisor.claim(
        second_task["id"], "worker-second", credential=second_runner["credential"]
    )

    before = event_count(supervisor)
    with pytest.raises(SupervisorError) as stale:
        supervisor.post_message(
            first["id"],
            first["claim_token"] + 1,
            "must not persist",
            credential=first_runner["credential"],
        )
    assert stale.value.code == "stale_fencing_token"
    assert event_count(supervisor) == before

    with pytest.raises(SupervisorError) as wrong_identity:
        supervisor.post_message(
            second["id"],
            second["claim_token"],
            "must not spoof another runner",
            credential=first_runner["credential"],
        )
    assert wrong_identity.value.code == "runner_authentication_failed"
    assert event_count(supervisor) == before

    with pytest.raises(SupervisorError) as no_credential:
        supervisor.post_message(first["id"], first["claim_token"], "missing auth")
    assert no_credential.value.code == "credential_required"

    with pytest.raises(SupervisorError) as missing_recipient:
        supervisor.post_message(
            first["id"],
            first["claim_token"],
            "must not cross project scope",
            recipient_attempt_id="00000000-0000-0000-0000-000000000000",
            credential=first_runner["credential"],
        )
    assert missing_recipient.value.code == "invalid_recipient"
    assert event_count(supervisor) == before

    supervisor.revoke_runner("worker-first")
    after_revoke = event_count(supervisor)
    with pytest.raises(SupervisorError) as revoked:
        supervisor.post_message(
            first["id"],
            first["claim_token"],
            "revoked runner must not append",
            credential=first_runner["credential"],
        )
    assert revoked.value.code == "runner_revoked"
    assert event_count(supervisor) == after_revoke


def test_messages_are_bounded_and_paginated(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    supervisor = GitSupervisor(repo)
    sender = supervisor.enroll_runner("worker-sender", "worker")
    recipient = supervisor.enroll_runner("worker-recipient", "worker")
    sender_task = make_task(supervisor, "alpha.txt", title="sender")
    recipient_task = make_task(supervisor, "beta.txt", title="recipient")
    source = supervisor.claim(sender_task["id"], "worker-sender", credential=sender["credential"])
    target = supervisor.claim(
        recipient_task["id"], "worker-recipient", credential=recipient["credential"]
    )
    for text in ("one", "two", "three"):
        supervisor.post_message(
            source["id"],
            source["claim_token"],
            text,
            recipient_attempt_id=target["id"],
            credential=sender["credential"],
        )

    reader = GitSupervisor(repo, read_only=True)
    first_page = reader.list_messages(target["id"], limit=2)
    assert [item["body"] for item in first_page["messages"]] == ["one", "two"]
    assert first_page["has_more"] is True
    second_page = reader.list_messages(
        target["id"], after_sequence=first_page["next_after_sequence"], limit=2
    )
    assert [item["body"] for item in second_page["messages"]] == ["three"]
    assert second_page["has_more"] is False

    before = event_count(supervisor)
    with pytest.raises(SupervisorError) as too_large:
        supervisor.post_message(
            source["id"],
            source["claim_token"],
            "x" * 4097,
            credential=sender["credential"],
        )
    assert too_large.value.code == "message_too_large"
    with pytest.raises(SupervisorError) as bad_control:
        supervisor.post_message(
            source["id"],
            source["claim_token"],
            "unsafe\x1b[31m text",
            credential=sender["credential"],
        )
    assert bad_control.value.code == "invalid_message"

    monkeypatch.setattr(messaging, "MESSAGE_PROJECT_MAX", 3)
    with pytest.raises(SupervisorError) as quota:
        supervisor.post_message(
            source["id"],
            source["claim_token"],
            "project quota must fail closed",
            credential=sender["credential"],
        )
    assert quota.value.code == "message_quota_exhausted"
    assert event_count(supervisor) == before


def test_message_read_fails_closed_when_event_chain_is_invalid(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    runner = supervisor.enroll_runner("worker", "worker")
    task = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(task["id"], "worker", credential=runner["credential"])
    message = supervisor.post_message(
        attempt["id"],
        attempt["claim_token"],
        "checked before display",
        credential=runner["credential"],
    )
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE events SET payload_json = '{}' WHERE id = ("
            "SELECT id FROM events WHERE event_type = 'agent.message' ORDER BY sequence DESC LIMIT 1)"
        )

    with pytest.raises(SupervisorError) as invalid_chain:
        GitSupervisor(repo, read_only=True).list_messages(attempt["id"])
    assert invalid_chain.value.code == "event_chain_invalid"
    assert message["message_id"]


def test_inbox_verification_and_read_share_one_snapshot(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    writer = GitSupervisor(repo)
    runner = writer.enroll_runner("worker", "worker")
    task = make_task(writer, "alpha.txt")
    attempt = writer.claim(task["id"], "worker", credential=runner["credential"])
    initial = writer.post_message(
        attempt["id"],
        attempt["claim_token"],
        "present before the inbox snapshot",
        credential=runner["credential"],
    )
    reader = GitSupervisor(repo, read_only=True)
    verify_snapshot = reader._verify_event_chain_in

    def append_after_verification(connection):
        verified = verify_snapshot(connection)
        writer.post_message(
            attempt["id"],
            attempt["claim_token"],
            "appended after verification, outside this snapshot",
            credential=runner["credential"],
        )
        return verified

    monkeypatch.setattr(reader, "_verify_event_chain_in", append_after_verification)
    first_read = reader.list_messages(attempt["id"])
    assert [item["message_id"] for item in first_read["messages"]] == [initial["message_id"]]

    next_read = GitSupervisor(repo, read_only=True).list_messages(attempt["id"])
    assert [item["body"] for item in next_read["messages"]] == [
        "present before the inbox snapshot",
        "appended after verification, outside this snapshot",
    ]
