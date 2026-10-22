from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from agent_control_plane.coordination_schemas import WorkspaceFileWriteRequest
from agent_control_plane.service import ControlPlaneError
from agent_control_plane.workspace_files import MAX_WORKSPACE_FILE_BYTES


def worker_and_claim(client, admin_headers, task_resources: list[str]):
    agent_response = client.post(
        "/v1/agents",
        headers=admin_headers,
        json={
            "name": f"writer-{uuid.uuid4()}",
            "owner": "operator@example.com",
            "role": "worker",
        },
    )
    assert agent_response.status_code == 201, agent_response.text
    agent = agent_response.json()
    mandate_response = client.post(
        "/v1/mandates",
        headers=admin_headers,
        json={
            "agent_id": agent["id"],
            "subject": f"agent:{agent['id']}",
            "scopes": [{"action": "coordination.*", "resource": "task:*"}],
            "ttl_seconds": 3600,
        },
    )
    assert mandate_response.status_code == 201, mandate_response.text
    token = mandate_response.json()["token"]
    task_response = client.post(
        "/v1/tasks",
        headers=admin_headers,
        json={
            "title": "Update a workspace file",
            "description": "Write a version-checked file within the configured workspace.",
            "acceptance_criteria": ["A stale version is never overwritten"],
            "resources": task_resources,
        },
    )
    assert task_response.status_code == 201, task_response.text
    task = task_response.json()
    claim_response = client.post(
        f"/v1/tasks/{task['id']}/claim",
        headers={"Authorization": f"Bearer {token}"},
        json={"ttl_seconds": 300},
    )
    assert claim_response.status_code == 200, claim_response.text
    claim = claim_response.json()
    return {
        "token": token,
        "agent_id": agent["id"],
        "task_id": task["id"],
        "claim_fencing_token": claim["task"]["claim_fencing_token"],
        "resource_fencing_tokens": {
            lease["resource"]: lease["fencing_token"]
            for lease in claim["resource_leases"]
        },
    }


def write_payload(context, path: str, old: bytes | None, new: bytes, operation_id=None):
    return {
        "operation_id": str(operation_id or uuid.uuid4()),
        "path": path,
        "expected_sha256": hashlib.sha256(old).hexdigest() if old is not None else None,
        "content_base64": base64.b64encode(new).decode("ascii"),
        "claim_fencing_token": context["claim_fencing_token"],
        "resource_fencing_tokens": context["resource_fencing_tokens"],
    }


def prepare_workspace_file(app, relative_path: str, content: bytes | None) -> Path:
    path = Path(app.state.settings.workspace_root) / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    if content is not None:
        path.write_bytes(content)
    return path


def test_file_write_is_atomic_audited_and_idempotent(client, app, admin_headers):
    path = "src/example.py"
    original = b"value = 1\n"
    updated = b"value = 2\n"
    workspace_path = prepare_workspace_file(app, path, original)
    context = worker_and_claim(client, admin_headers, [f"workspace-file:{path}"])
    payload = write_payload(context, path, original, updated)
    headers = {"Authorization": f"Bearer {context['token']}"}

    response = client.post(
        f"/v1/tasks/{context['task_id']}/file-writes", headers=headers, json=payload
    )
    assert response.status_code == 200, response.text
    receipt = response.json()
    assert receipt["status"] == "committed"
    assert receipt["expected_sha256"] == hashlib.sha256(original).hexdigest()
    assert receipt["observed_sha256"] == hashlib.sha256(original).hexdigest()
    assert receipt["new_sha256"] == hashlib.sha256(updated).hexdigest()
    assert "content_base64" not in receipt
    assert workspace_path.read_bytes() == updated

    replay = client.post(
        f"/v1/tasks/{context['task_id']}/file-writes", headers=headers, json=payload
    )
    assert replay.status_code == 200
    assert replay.json() == receipt

    stored = client.get(
        f"/v1/tasks/{context['task_id']}/file-writes/{payload['operation_id']}",
        headers=headers,
    )
    assert stored.status_code == 200
    assert stored.json() == receipt
    assert client.get("/v1/audit/verify", headers=admin_headers).json()["valid"]


def test_concurrent_writers_using_same_version_have_exactly_one_winner(
    client, app, admin_headers
):
    path = "src/shared.py"
    original = b"value = 0\n"
    first_content = b"value = 1\n"
    second_content = b"value = 2\n"
    workspace_path = prepare_workspace_file(app, path, original)
    context = worker_and_claim(client, admin_headers, [f"workspace-file:{path}"])
    headers = {"Authorization": f"Bearer {context['token']}"}
    requests = [
        write_payload(context, path, original, first_content),
        write_payload(context, path, original, second_content),
    ]
    start = Barrier(2)

    def send(payload):
        start.wait()
        return client.post(
            f"/v1/tasks/{context['task_id']}/file-writes",
            headers=headers,
            json=payload,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(send, requests))

    assert sorted(response.status_code for response in responses) == [200, 409]
    assert workspace_path.read_bytes() in {first_content, second_content}
    receipts = [
        client.get(
            f"/v1/tasks/{context['task_id']}/file-writes/{payload['operation_id']}",
            headers=headers,
        ).json()
        for payload in requests
    ]
    assert sorted(receipt["status"] for receipt in receipts) == [
        "committed",
        "conflict",
    ]


def test_stale_hash_and_unleased_path_fail_without_mutation(client, app, admin_headers):
    path = "src/stale.py"
    original = b"current\n"
    workspace_path = prepare_workspace_file(app, path, original)
    context = worker_and_claim(client, admin_headers, [])
    headers = {"Authorization": f"Bearer {context['token']}"}
    payload = write_payload(context, path, b"old\n", b"must not replace\n")

    stale = client.post(
        f"/v1/tasks/{context['task_id']}/file-writes", headers=headers, json=payload
    )
    assert stale.status_code == 409
    assert stale.json()["error"] == "file_resource_not_leased"
    assert workspace_path.read_bytes() == original

    leased_context = worker_and_claim(client, admin_headers, [f"workspace-file:{path}"])
    stale_payload = write_payload(leased_context, path, b"old\n", b"must not replace\n")
    stale_response = client.post(
        f"/v1/tasks/{leased_context['task_id']}/file-writes",
        headers={"Authorization": f"Bearer {leased_context['token']}"},
        json=stale_payload,
    )
    assert stale_response.status_code == 409
    assert stale_response.json()["error"] == "stale_file_version"
    assert workspace_path.read_bytes() == original
    receipt = client.get(
        f"/v1/tasks/{leased_context['task_id']}/file-writes/{stale_payload['operation_id']}",
        headers={"Authorization": f"Bearer {leased_context['token']}"},
    )
    assert receipt.status_code == 200
    assert receipt.json()["status"] == "conflict"


def test_new_file_requires_expected_missing_and_symlinks_are_rejected(
    client, app, admin_headers, tmp_path
):
    path = "src/new.py"
    prepare_workspace_file(app, path, None)
    context = worker_and_claim(client, admin_headers, [f"workspace-file:{path}"])
    headers = {"Authorization": f"Bearer {context['token']}"}
    payload = write_payload(context, path, None, b"created\n")
    response = client.post(
        f"/v1/tasks/{context['task_id']}/file-writes", headers=headers, json=payload
    )
    assert response.status_code == 200, response.text
    assert (Path(app.state.settings.workspace_root) / path).read_bytes() == b"created\n"
    assert (
        Path(app.state.settings.workspace_root) / path
    ).stat().st_mode & 0o777 == 0o600

    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"preserve\n")
    link_path = Path(app.state.settings.workspace_root) / "src/link.py"
    link_path.symlink_to(outside)
    link_context = worker_and_claim(
        client, admin_headers, ["workspace-file:src/link.py"]
    )
    link_payload = write_payload(link_context, "src/link.py", None, b"nope\n")
    link_response = client.post(
        f"/v1/tasks/{link_context['task_id']}/file-writes",
        headers={"Authorization": f"Bearer {link_context['token']}"},
        json=link_payload,
    )
    assert link_response.status_code == 422
    assert outside.read_bytes() == b"preserve\n"

    fifo_path = Path(app.state.settings.workspace_root) / "src/pipe.py"
    os.mkfifo(fifo_path)
    fifo_context = worker_and_claim(
        client, admin_headers, ["workspace-file:src/pipe.py"]
    )
    fifo_payload = write_payload(fifo_context, "src/pipe.py", None, b"nope\n")
    fifo_response = client.post(
        f"/v1/tasks/{fifo_context['task_id']}/file-writes",
        headers={"Authorization": f"Bearer {fifo_context['token']}"},
        json=fifo_payload,
    )
    assert fifo_response.status_code == 422
    assert fifo_response.json()["error"] == "workspace_target_not_regular"

    outside_dir = tmp_path / "outside-dir"
    outside_dir.mkdir()
    outside_file = outside_dir / "parent-link.py"
    outside_file.write_bytes(b"keep\n")
    parent_link = Path(app.state.settings.workspace_root) / "src/jump"
    parent_link.mkdir()
    parent_context = worker_and_claim(
        client, admin_headers, ["workspace-file:src/jump/parent-link.py"]
    )
    parent_link.rmdir()
    parent_link.symlink_to(outside_dir, target_is_directory=True)
    parent_payload = write_payload(
        parent_context, "src/jump/parent-link.py", None, b"nope\n"
    )
    parent_response = client.post(
        f"/v1/tasks/{parent_context['task_id']}/file-writes",
        headers={"Authorization": f"Bearer {parent_context['token']}"},
        json=parent_payload,
    )
    assert parent_response.status_code == 422
    assert parent_response.json()["error"] == "unsafe_workspace_path"
    assert outside_file.read_bytes() == b"keep\n"


def test_path_escape_and_stale_fencing_fail_closed(client, app, admin_headers):
    path = "src/guarded.py"
    original = b"keep\n"
    workspace_path = prepare_workspace_file(app, path, original)
    context = worker_and_claim(client, admin_headers, [f"workspace-file:{path}"])
    headers = {"Authorization": f"Bearer {context['token']}"}
    traversal = write_payload(context, "../escape.txt", original, b"escape\n")
    invalid = client.post(
        f"/v1/tasks/{context['task_id']}/file-writes", headers=headers, json=traversal
    )
    assert invalid.status_code == 422
    assert workspace_path.read_bytes() == original

    app.state.database.execute(
        "UPDATE tasks SET claim_expires_at = 0 WHERE id = ?", (context["task_id"],)
    )
    stale_claim = write_payload(context, path, original, b"stale worker\n")
    refused = client.post(
        f"/v1/tasks/{context['task_id']}/file-writes",
        headers=headers,
        json=stale_claim,
    )
    assert refused.status_code == 409
    assert refused.json()["error"] == "stale_claim_fencing_token"


def test_oversized_existing_file_is_rejected_before_hashing(client, app, admin_headers):
    path = "src/large.bin"
    workspace_path = prepare_workspace_file(app, path, None)
    with workspace_path.open("wb") as target:
        target.truncate(MAX_WORKSPACE_FILE_BYTES + 1)

    context = worker_and_claim(client, admin_headers, [f"workspace-file:{path}"])
    payload = write_payload(context, path, None, b"replacement\n")
    response = client.post(
        f"/v1/tasks/{context['task_id']}/file-writes",
        headers={"Authorization": f"Bearer {context['token']}"},
        json=payload,
    )
    assert response.status_code == 413
    assert response.json()["error"] == "workspace_file_too_large"
    assert workspace_path.stat().st_size == MAX_WORKSPACE_FILE_BYTES + 1


def test_staging_fifo_is_rejected_without_blocking(client, app, admin_headers):
    path = "src/staging.py"
    original = b"before\n"
    workspace_path = prepare_workspace_file(app, path, original)
    operation_id = uuid.uuid4()
    staging_path = workspace_path.parent / f".acp-{operation_id}.tmp"
    os.mkfifo(staging_path)

    context = worker_and_claim(client, admin_headers, [f"workspace-file:{path}"])
    payload = write_payload(context, path, original, b"after\n", operation_id)
    staging_inode = staging_path.lstat().st_ino
    response = client.post(
        f"/v1/tasks/{context['task_id']}/file-writes",
        headers={"Authorization": f"Bearer {context['token']}"},
        json=payload,
    )
    assert response.status_code == 409
    assert response.json()["error"] == "workspace_stage_conflict"
    assert workspace_path.read_bytes() == original
    assert staging_path.is_fifo()
    assert staging_path.lstat().st_ino == staging_inode


def test_conflicting_preexisting_stage_is_preserved(client, app, admin_headers):
    path = "src/stage-conflict.py"
    original = b"before\n"
    workspace_path = prepare_workspace_file(app, path, original)
    operation_id = uuid.uuid4()
    staging_path = workspace_path.parent / f".acp-{operation_id}.tmp"
    staging_path.write_bytes(b"foreign bytes\n")
    staging_inode = staging_path.stat().st_ino

    context = worker_and_claim(client, admin_headers, [f"workspace-file:{path}"])
    payload = write_payload(context, path, original, b"after\n", operation_id)
    response = client.post(
        f"/v1/tasks/{context['task_id']}/file-writes",
        headers={"Authorization": f"Bearer {context['token']}"},
        json=payload,
    )

    assert response.status_code == 409
    assert response.json()["error"] == "workspace_stage_conflict"
    assert workspace_path.read_bytes() == original
    assert staging_path.read_bytes() == b"foreign bytes\n"
    assert staging_path.stat().st_ino == staging_inode


def test_hardlinked_preexisting_stage_is_rejected_and_preserved(
    client, app, admin_headers, tmp_path
):
    path = "src/stage-hardlink.py"
    original = b"before\n"
    updated = b"after\n"
    workspace_path = prepare_workspace_file(app, path, original)
    outside = tmp_path / "outside-hardlink"
    outside.write_bytes(updated)
    operation_id = uuid.uuid4()
    staging_path = workspace_path.parent / f".acp-{operation_id}.tmp"
    os.link(outside, staging_path)
    staging_inode = staging_path.stat().st_ino

    context = worker_and_claim(client, admin_headers, [f"workspace-file:{path}"])
    payload = write_payload(context, path, original, updated, operation_id)
    response = client.post(
        f"/v1/tasks/{context['task_id']}/file-writes",
        headers={"Authorization": f"Bearer {context['token']}"},
        json=payload,
    )

    assert response.status_code == 409
    assert response.json()["error"] == "workspace_stage_conflict"
    assert workspace_path.read_bytes() == original
    assert staging_path.stat().st_ino == staging_inode
    assert outside.stat().st_ino == staging_inode
    assert outside.read_bytes() == updated


def test_matching_preexisting_stage_preserves_target_mode(client, app, admin_headers):
    path = "src/stage-mode.py"
    original = b"before\n"
    updated = b"after\n"
    workspace_path = prepare_workspace_file(app, path, original)
    workspace_path.chmod(0o600)
    operation_id = uuid.uuid4()
    staging_path = workspace_path.parent / f".acp-{operation_id}.tmp"
    staging_path.write_bytes(updated)
    staging_path.chmod(0o644)

    context = worker_and_claim(client, admin_headers, [f"workspace-file:{path}"])
    payload = write_payload(context, path, original, updated, operation_id)
    response = client.post(
        f"/v1/tasks/{context['task_id']}/file-writes",
        headers={"Authorization": f"Bearer {context['token']}"},
        json=payload,
    )

    assert response.status_code == 200, response.text
    assert workspace_path.read_bytes() == updated
    assert workspace_path.stat().st_mode & 0o777 == 0o600
    assert not staging_path.exists()


def test_matching_preexisting_stage_for_new_file_uses_private_mode(
    client, app, admin_headers
):
    path = "src/new-stage-mode.py"
    workspace_path = prepare_workspace_file(app, path, None)
    updated = b"new private file\n"
    operation_id = uuid.uuid4()
    staging_path = workspace_path.parent / f".acp-{operation_id}.tmp"
    staging_path.write_bytes(updated)
    staging_path.chmod(0o777)

    context = worker_and_claim(client, admin_headers, [f"workspace-file:{path}"])
    payload = write_payload(context, path, None, updated, operation_id)
    response = client.post(
        f"/v1/tasks/{context['task_id']}/file-writes",
        headers={"Authorization": f"Bearer {context['token']}"},
        json=payload,
    )

    assert response.status_code == 200, response.text
    assert workspace_path.read_bytes() == updated
    assert workspace_path.stat().st_mode & 0o777 == 0o600
    assert not staging_path.exists()


@pytest.mark.parametrize("existing_target", [False, True])
def test_new_stage_is_private_before_first_write(
    client, app, admin_headers, monkeypatch, existing_target
):
    path = (
        "src/first-write-mode-existing.py"
        if existing_target
        else "src/first-write-mode-new.py"
    )
    original = b"before\n" if existing_target else None
    workspace_path = prepare_workspace_file(app, path, original)
    if existing_target:
        workspace_path.chmod(0o600)
    updated = b"content written only after stage is private\n"
    context = worker_and_claim(client, admin_headers, [f"workspace-file:{path}"])
    payload = write_payload(context, path, original, updated)
    staging_name = f".acp-{payload['operation_id']}.tmp"
    stage_identity = []
    stage_open_modes = []
    first_write_modes = []
    real_open = os.open
    real_write = os.write

    def capture_stage_open(file_path, flags, mode=0o777, *args, **kwargs):
        file_descriptor = real_open(file_path, flags, mode, *args, **kwargs)
        if file_path == staging_name and flags & os.O_CREAT:
            file_stat = os.fstat(file_descriptor)
            stage_identity.append((file_stat.st_dev, file_stat.st_ino))
            stage_open_modes.append(file_stat.st_mode & 0o777)
        return file_descriptor

    def observe_stage_mode_before_write(file_descriptor, data):
        file_stat = os.fstat(file_descriptor)
        if stage_identity == [(file_stat.st_dev, file_stat.st_ino)]:
            first_write_modes.append(file_stat.st_mode & 0o777)
        return real_write(file_descriptor, data)

    previous_umask = os.umask(0)
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(os, "open", capture_stage_open)
            patcher.setattr(os, "write", observe_stage_mode_before_write)
            response = client.post(
                f"/v1/tasks/{context['task_id']}/file-writes",
                headers={"Authorization": f"Bearer {context['token']}"},
                json=payload,
            )
    finally:
        os.umask(previous_umask)

    assert response.status_code == 200, response.text
    assert stage_open_modes == [0o600]
    assert set(first_write_modes) == {0o600}
    assert workspace_path.read_bytes() == updated
    assert workspace_path.stat().st_mode & 0o777 == 0o600


def test_failed_matching_stage_retry_keeps_bytes_and_normalizes_mode(
    client, app, admin_headers, monkeypatch
):
    path = "src/stage-fsync-failure.py"
    original = b"before\n"
    updated = b"after\n"
    workspace_path = prepare_workspace_file(app, path, original)
    workspace_path.chmod(0o600)
    operation_id = uuid.uuid4()
    staging_path = workspace_path.parent / f".acp-{operation_id}.tmp"
    staging_path.write_bytes(updated)
    staging_path.chmod(0o644)
    staging_inode = staging_path.stat().st_ino

    context = worker_and_claim(client, admin_headers, [f"workspace-file:{path}"])
    payload = write_payload(context, path, original, updated, operation_id)
    real_fsync = os.fsync

    def fail_stage_fsync(file_descriptor):
        if os.fstat(file_descriptor).st_ino == staging_inode:
            raise OSError("simulated stage fsync failure")
        return real_fsync(file_descriptor)

    with monkeypatch.context() as patcher:
        patcher.setattr(os, "fsync", fail_stage_fsync)
        response = client.post(
            f"/v1/tasks/{context['task_id']}/file-writes",
            headers={"Authorization": f"Bearer {context['token']}"},
            json=payload,
        )

    assert response.status_code == 500
    assert response.json()["error"] == "workspace_write_failed"
    assert workspace_path.read_bytes() == original
    assert workspace_path.stat().st_mode & 0o777 == 0o600
    assert staging_path.read_bytes() == updated
    assert staging_path.stat().st_ino == staging_inode
    assert staging_path.stat().st_mode & 0o777 == 0o600


def test_symlink_stage_is_rejected_and_preserved(client, app, admin_headers, tmp_path):
    path = "src/stage-symlink.py"
    original = b"before\n"
    workspace_path = prepare_workspace_file(app, path, original)
    outside = tmp_path / "outside-stage"
    outside.write_bytes(b"outside bytes\n")
    operation_id = uuid.uuid4()
    staging_path = workspace_path.parent / f".acp-{operation_id}.tmp"
    staging_path.symlink_to(outside)
    staging_inode = staging_path.lstat().st_ino
    staging_target = staging_path.readlink()

    context = worker_and_claim(client, admin_headers, [f"workspace-file:{path}"])
    payload = write_payload(context, path, original, b"after\n", operation_id)
    response = client.post(
        f"/v1/tasks/{context['task_id']}/file-writes",
        headers={"Authorization": f"Bearer {context['token']}"},
        json=payload,
    )

    assert response.status_code == 409
    assert response.json()["error"] == "workspace_stage_conflict"
    assert workspace_path.read_bytes() == original
    assert staging_path.is_symlink()
    assert staging_path.lstat().st_ino == staging_inode
    assert staging_path.readlink() == staging_target
    assert outside.read_bytes() == b"outside bytes\n"


def test_stale_resource_fencing_is_rejected(client, app, admin_headers):
    path = "src/lease.py"
    original = b"before\n"
    workspace_path = prepare_workspace_file(app, path, original)
    context = worker_and_claim(client, admin_headers, [f"workspace-file:{path}"])
    app.state.database.execute(
        "UPDATE resource_leases SET fencing_token = fencing_token + 1 WHERE resource = ?",
        (f"workspace-file:{path}",),
    )
    payload = write_payload(context, path, original, b"after\n")
    response = client.post(
        f"/v1/tasks/{context['task_id']}/file-writes",
        headers={"Authorization": f"Bearer {context['token']}"},
        json=payload,
    )
    assert response.status_code == 409
    assert response.json()["error"] == "stale_fencing_token"
    assert workspace_path.read_bytes() == original


def test_write_receipt_requires_worker_scope_and_owning_agent(
    client, app, admin_headers
):
    path = "src/private.py"
    original = b"before\n"
    prepare_workspace_file(app, path, original)
    owner = worker_and_claim(client, admin_headers, [f"workspace-file:{path}"])
    payload = write_payload(owner, path, original, b"after\n")
    response = client.post(
        f"/v1/tasks/{owner['task_id']}/file-writes",
        headers={"Authorization": f"Bearer {owner['token']}"},
        json=payload,
    )
    assert response.status_code == 200

    other = worker_and_claim(client, admin_headers, [])
    receipt_url = f"/v1/tasks/{owner['task_id']}/file-writes/{payload['operation_id']}"
    cross_agent = client.get(
        receipt_url, headers={"Authorization": f"Bearer {other['token']}"}
    )
    assert cross_agent.status_code == 404

    restricted_mandate = client.post(
        "/v1/mandates",
        headers=admin_headers,
        json={
            "agent_id": other["agent_id"],
            "subject": f"agent:{other['agent_id']}",
            "scopes": [{"action": "coordination.claim", "resource": "task:*"}],
            "ttl_seconds": 3600,
        },
    )
    assert restricted_mandate.status_code == 201, restricted_mandate.text
    denied_scope = client.get(
        receipt_url,
        headers={"Authorization": f"Bearer {restricted_mandate.json()['token']}"},
    )
    assert denied_scope.status_code == 403
    assert denied_scope.json()["error"] == "coordination_scope_denied"

    qc_agent_response = client.post(
        "/v1/agents",
        headers=admin_headers,
        json={
            "name": f"qc-{uuid.uuid4()}",
            "owner": "reviewer@example.com",
            "role": "qc",
        },
    )
    assert qc_agent_response.status_code == 201
    qc_agent = qc_agent_response.json()
    qc_mandate = client.post(
        "/v1/mandates",
        headers=admin_headers,
        json={
            "agent_id": qc_agent["id"],
            "subject": f"agent:{qc_agent['id']}",
            "scopes": [{"action": "coordination.*", "resource": "task:*"}],
            "ttl_seconds": 3600,
        },
    )
    assert qc_mandate.status_code == 201
    denied_role = client.get(
        receipt_url,
        headers={"Authorization": f"Bearer {qc_mandate.json()['token']}"},
    )
    assert denied_role.status_code == 403
    assert denied_role.json()["error"] == "role_forbidden"


def test_retry_recovers_failure_before_atomic_replace(
    client, app, admin_headers, monkeypatch
):
    path = "src/before.py"
    original = b"before\n"
    updated = b"after\n"
    workspace_path = prepare_workspace_file(app, path, original)
    context = worker_and_claim(client, admin_headers, [f"workspace-file:{path}"])
    payload = write_payload(context, path, original, updated)
    request = WorkspaceFileWriteRequest.model_validate(payload)

    with monkeypatch.context() as patcher:
        patcher.setattr(
            os,
            "replace",
            lambda *args, **kwargs: (_ for _ in ()).throw(OSError("before rename")),
        )
        with pytest.raises(ControlPlaneError) as error:
            app.state.coordination.write_workspace_file(
                context["task_id"], context["token"], request
            )
        assert error.value.code == "workspace_write_failed"
        assert workspace_path.read_bytes() == original

    receipt = app.state.coordination.write_workspace_file(
        context["task_id"], context["token"], request
    )
    assert receipt["status"] == "committed"
    assert workspace_path.read_bytes() == updated


def test_retry_recovers_stage_after_process_crash_before_replace(
    client, app, admin_headers
):
    path = "src/process-crash.py"
    original = b"before\n"
    updated = b"after\n"
    workspace_path = prepare_workspace_file(app, path, original)
    workspace_path.chmod(0o640)
    operation_id = uuid.uuid4()
    context = worker_and_claim(client, admin_headers, [f"workspace-file:{path}"])
    payload = write_payload(context, path, original, updated, operation_id)
    request = WorkspaceFileWriteRequest.model_validate(payload)
    staging_path = workspace_path.parent / f".acp-{operation_id}.tmp"

    child_code = (
        "import os, sys\n"
        "sys.path.insert(0, sys.argv[1])\n"
        "from agent_control_plane.workspace_files import WorkspaceFileStore\n"
        "workspace_root, relative_path, operation_id, expected_sha256, content_hex, new_sha256 = sys.argv[2:]\n"
        "store = WorkspaceFileStore(workspace_root)\n"
        "os.replace = lambda *args, **kwargs: os._exit(73)\n"
        "store.atomic_replace(relative_path, operation_id, expected_sha256, bytes.fromhex(content_hex), new_sha256)\n"
    )
    source_root = Path(__file__).resolve().parents[1] / "src"
    workspace_root = str(app.state.settings.workspace_root)
    crashed = subprocess.run(
        [
            sys.executable,
            "-c",
            child_code,
            str(source_root),
            workspace_root,
            path,
            str(operation_id),
            request.expected_sha256,
            updated.hex(),
            hashlib.sha256(updated).hexdigest(),
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert crashed.returncode == 73, crashed.stderr
    assert staging_path.read_bytes() == updated
    assert workspace_path.read_bytes() == original

    # Reuse must honor the target mode as it exists at retry time, not the mode
    # captured in the crash-left stage.
    workspace_path.chmod(0o600)
    response = client.post(
        f"/v1/tasks/{context['task_id']}/file-writes",
        headers={"Authorization": f"Bearer {context['token']}"},
        json=payload,
    )

    assert response.status_code == 200, response.text
    assert workspace_path.read_bytes() == updated
    assert workspace_path.stat().st_mode & 0o777 == 0o600
    assert not staging_path.exists()


def test_retry_recovers_crash_after_replace_before_receipt_commit(
    client, app, admin_headers, monkeypatch
):
    path = "src/after.py"
    original = b"before\n"
    updated = b"after\n"
    workspace_path = prepare_workspace_file(app, path, original)
    context = worker_and_claim(client, admin_headers, [f"workspace-file:{path}"])
    request = WorkspaceFileWriteRequest.model_validate(
        write_payload(context, path, original, updated)
    )
    real_fsync = os.fsync
    calls = 0

    def fail_directory_sync_after_replace(file_descriptor):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("after rename")
        return real_fsync(file_descriptor)

    with monkeypatch.context() as patcher:
        patcher.setattr(os, "fsync", fail_directory_sync_after_replace)
        with pytest.raises(ControlPlaneError) as error:
            app.state.coordination.write_workspace_file(
                context["task_id"], context["token"], request
            )
        assert error.value.code == "workspace_write_failed"
        assert workspace_path.read_bytes() == updated

    pending = app.state.coordination.workspace_file_write(
        context["task_id"], str(request.operation_id), context["token"]
    )
    assert pending["status"] == "prepared"
    recovered = app.state.coordination.write_workspace_file(
        context["task_id"], context["token"], request
    )
    assert recovered["status"] == "committed"
    assert workspace_path.read_bytes() == updated
