from __future__ import annotations

import json
import os
import stat
import subprocess
from multiprocessing import get_context
from pathlib import Path
from threading import Barrier, Lock, Thread
from time import sleep
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import agent_control_plane.checkout_identity as checkout_identity_module
from agent_control_plane.app import create_app
from agent_control_plane.checkout_identity import (
    CheckoutAdapterError,
    CheckoutWriteLease,
    _has_active_checkout_write_lease,
    _open_checkout_lock,
    identify_checkout,
)
from agent_control_plane.cli import main


def git(repo: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def init_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    git(path, "config", "user.email", "checkout-test@example.invalid")
    git(path, "config", "user.name", "Checkout identity test")
    (path / "tracked.txt").write_text("initial\n", encoding="utf-8")
    git(path, "add", "tracked.txt")
    git(path, "commit", "-m", "initial")
    return path


def fencing_callbacks():
    state = {"token": 0, "released": []}

    def acquire(_resource: str) -> int:
        state["token"] += 1
        return state["token"]

    def validate(_resource: str, token: int) -> bool:
        return token == state["token"]

    def release(_resource: str, token: int) -> None:
        state["released"].append(token)

    return state, acquire, validate, release


def lease_for(repo: Path, acquire, validate, release) -> CheckoutWriteLease:
    return CheckoutWriteLease(
        repo,
        acquire_fence=acquire,
        validate_fence=validate,
        release_fence=release,
    )


def _fixed_acquire(_resource: str) -> int:
    return 1


def _fixed_validate(_resource: str, token: int) -> bool:
    return token == 1


def _fixed_release(_resource: str, _token: int) -> None:
    return None


def _hold_checkout_lock(path: str, entered, finish) -> None:
    with CheckoutWriteLease.local(path):
        entered.set()
        if not finish.wait(15):
            raise TimeoutError("test did not release child checkout lock")


def _hold_interrupted_checkout_write(path: str, target: str, entered) -> None:
    with CheckoutWriteLease.local(path) as owner:

        def partial_write() -> None:
            Path(target).write_text("partial write\n", encoding="utf-8")
            entered.set()
            while True:
                sleep(0.01)

        owner.run("write", partial_write)


def test_checkout_identity_is_stable_for_symlink_alias_and_same_filesystem_move(tmp_path):
    repo = init_repo(tmp_path / "repo")
    original = identify_checkout(repo)
    alias = tmp_path / "repo-alias"
    alias.symlink_to(repo, target_is_directory=True)

    assert identify_checkout(alias).resource == original.resource

    moved = tmp_path / "renamed-repo"
    repo.rename(moved)
    renamed = identify_checkout(moved)
    assert renamed.resource == original.resource
    assert renamed.root == moved.resolve()


def test_checkout_directory_lock_closes_descriptor_if_metadata_path_disappears(
    tmp_path, monkeypatch
):
    repo = init_repo(tmp_path / "repo")
    git_dir = identify_checkout(repo).git_dir
    original_stat = Path.stat
    original_open = os.open
    stat_calls = 0
    descriptors = []

    def disappear_after_open(path, *args, **kwargs):
        nonlocal stat_calls
        if path == git_dir:
            stat_calls += 1
            if stat_calls == 2:
                raise FileNotFoundError("simulated metadata directory removal")
        return original_stat(path, *args, **kwargs)

    def capture_descriptor(*args, **kwargs):
        descriptor = original_open(*args, **kwargs)
        descriptors.append(descriptor)
        return descriptor

    monkeypatch.setattr(Path, "stat", disappear_after_open)
    monkeypatch.setattr("agent_control_plane.checkout_identity.os.open", capture_descriptor)

    with pytest.raises(CheckoutAdapterError) as unavailable:
        _open_checkout_lock(git_dir)

    assert unavailable.value.code == "checkout_lock_unavailable"
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


def test_linked_worktrees_have_distinct_checkout_resources(tmp_path):
    repo = init_repo(tmp_path / "repo")
    linked = tmp_path / "linked"
    git(repo, "worktree", "add", "-q", "-b", "second", str(linked))

    primary_identity = identify_checkout(repo)
    linked_identity = identify_checkout(linked)

    assert primary_identity.repository_id == linked_identity.repository_id
    assert primary_identity.checkout_id != linked_identity.checkout_id
    assert primary_identity.resource != linked_identity.resource


def test_checkout_resource_cli_is_read_only_and_does_not_expose_paths(tmp_path, capsys):
    repo = init_repo(tmp_path / "repo")

    assert main(["--repo", str(repo), "checkout-resource"]) == 0
    view = json.loads(capsys.readouterr().out)

    assert view == identify_checkout(repo).public_view()
    assert view["resource"].startswith("checkout:v1:")
    assert str(repo) not in json.dumps(view)
    assert not (repo / ".acp").exists()


def test_local_checkout_lease_performs_mediated_write_and_advances_fence(tmp_path):
    repo = init_repo(tmp_path / "repo")
    alias = tmp_path / "repo-alias"
    alias.symlink_to(repo, target_is_directory=True)
    identity = identify_checkout(repo)
    fence_state = identity.git_dir / f".acp-checkout-{identity.checkout_id}.fence-v1"
    target = repo / "tracked.txt"

    with CheckoutWriteLease.local(alias) as first_owner:
        first_token = first_owner.fencing_token
        assert first_token == 1
        first_owner.run("write", lambda: target.write_text("mediated through local adapter\n"))

    first_record = json.loads(fence_state.read_text(encoding="utf-8"))
    assert first_record == {
        "fencing_token": first_token,
        "identity_version": 1,
        "resource": identity.resource,
    }
    assert stat.S_IMODE(fence_state.stat().st_mode) == 0o600

    with CheckoutWriteLease.local(repo) as next_owner:
        assert next_owner.fencing_token == first_token + 1
        next_owner.run("write", lambda: target.write_text("second owner\n"))

    assert target.read_text(encoding="utf-8") == "second owner\n"


def test_checkout_run_write_resolves_relative_targets_from_leased_root(tmp_path, monkeypatch):
    repo = init_repo(tmp_path / "repo")
    outside = tmp_path / "outside"
    outside.mkdir()
    alias = tmp_path / "repo-alias"
    alias.symlink_to(repo, target_is_directory=True)
    observed_targets: list[Path] = []

    def write(target: Path) -> int:
        observed_targets.append(target)
        return target.write_text("target-bound write\n", encoding="utf-8")

    with CheckoutWriteLease.local(alias) as owner:
        monkeypatch.chdir(outside)
        result = owner.run_write("tracked.txt", write)

    assert result == len("target-bound write\n")
    assert observed_targets == [(repo / "tracked.txt").resolve()]
    assert (repo / "tracked.txt").read_text(encoding="utf-8") == "target-bound write\n"
    assert not (outside / "tracked.txt").exists()


def test_active_checkout_write_lease_requires_matching_marker_and_held_fence(tmp_path):
    repo = init_repo(tmp_path / "repo")
    identity = identify_checkout(repo)
    owner = CheckoutWriteLease.local(repo)

    assert not _has_active_checkout_write_lease(repo, identity.resource, 1)

    with owner:
        token = owner.fencing_token
        assert token is not None
        checks = {}

        def inspect_active_lease():
            checks["exact"] = _has_active_checkout_write_lease(repo, identity.resource, token)
            checks["stale_token"] = _has_active_checkout_write_lease(
                repo, identity.resource, token + 1
            )
            checks["wrong_resource"] = _has_active_checkout_write_lease(
                repo, "checkout:other", token
            )

        owner.run("write", inspect_active_lease)

    assert checks == {"exact": True, "stale_token": False, "wrong_resource": False}
    assert not _has_active_checkout_write_lease(repo, identity.resource, token)


def test_checkout_run_write_rejects_a_different_linked_worktree_before_mutation(tmp_path):
    repo = init_repo(tmp_path / "repo")
    linked = tmp_path / "linked"
    git(repo, "worktree", "add", "-q", "-b", "secondary", str(linked))
    target = linked / "tracked.txt"
    original_primary = (repo / "tracked.txt").read_text(encoding="utf-8")
    original_linked = target.read_text(encoding="utf-8")
    identity = identify_checkout(repo)

    with CheckoutWriteLease.local(repo) as owner:
        with pytest.raises(CheckoutAdapterError) as mismatch:
            owner.run_write(target, lambda resolved: resolved.write_text("wrong tree\n"))

    assert mismatch.value.code == "checkout_target_mismatch"
    assert (repo / "tracked.txt").read_text(encoding="utf-8") == original_primary
    assert target.read_text(encoding="utf-8") == original_linked
    assert not (identity.common_dir / f".acp-checkout-{identity.checkout_id}.pending").exists()

    # A rejected target does not leave recovery-required state for the actual owner.
    with CheckoutWriteLease.local(repo) as next_owner:
        next_owner.run_write(repo / "tracked.txt", lambda resolved: resolved.write_text("safe\n"))
    assert (repo / "tracked.txt").read_text(encoding="utf-8") == "safe\n"


def test_checkout_run_write_rejects_symlink_escape_and_checkout_root(tmp_path):
    repo = init_repo(tmp_path / "repo")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside stays intact\n", encoding="utf-8")
    (repo / "escape.txt").symlink_to(outside)
    identity = identify_checkout(repo)

    with CheckoutWriteLease.local(repo) as owner:
        with pytest.raises(CheckoutAdapterError) as escape:
            owner.run_write(repo / "escape.txt", lambda resolved: resolved.write_text("bad\n"))
        assert escape.value.code == "checkout_target_mismatch"

    with CheckoutWriteLease.local(repo) as owner:
        with pytest.raises(CheckoutAdapterError) as root_target:
            owner.run_write(repo, lambda resolved: resolved.write_text("bad\n"))
        assert root_target.value.code == "checkout_target_ambiguous"

    assert outside.read_text(encoding="utf-8") == "outside stays intact\n"
    assert not (identity.common_dir / f".acp-checkout-{identity.checkout_id}.pending").exists()


def test_checkout_run_write_rejects_none_without_poisoning_lease(tmp_path):
    repo = init_repo(tmp_path / "repo")
    identity = identify_checkout(repo)

    with CheckoutWriteLease.local(repo) as owner:
        with pytest.raises(CheckoutAdapterError) as invalid_target:
            owner.run_write(None, lambda target: target.write_text("unsafe\n"))

        assert invalid_target.value.code == "checkout_target_invalid"
        assert not (identity.common_dir / f".acp-checkout-{identity.checkout_id}.pending").exists()
        owner.run_write("tracked.txt", lambda target: target.write_text("safe\n"))

    assert (repo / "tracked.txt").read_text(encoding="utf-8") == "safe\n"


def test_checkout_run_write_rejects_missing_path_below_file_before_marker(tmp_path):
    repo = init_repo(tmp_path / "repo")
    identity = identify_checkout(repo)
    target = repo / "tracked.txt" / "child.txt"
    called = False

    def write(resolved: Path) -> None:
        nonlocal called
        called = True
        resolved.write_text("unexpected\n")

    with CheckoutWriteLease.local(repo) as owner:
        with pytest.raises(CheckoutAdapterError) as invalid_parent:
            owner.run_write(target, write)

    assert invalid_parent.value.code == "checkout_target_unavailable"
    assert not called
    assert not (identity.common_dir / f".acp-checkout-{identity.checkout_id}.pending").exists()


def test_checkout_run_write_checks_existing_file_device_before_parent(tmp_path, monkeypatch):
    repo = init_repo(tmp_path / "repo")
    target = repo / "tracked.txt"
    identity = identify_checkout(repo)
    real_stat = Path.stat

    def mounted_file_stat(path: Path, *, follow_symlinks: bool = True):
        result = real_stat(path, follow_symlinks=follow_symlinks)
        if path == target:
            return SimpleNamespace(st_dev=result.st_dev + 1, st_mode=result.st_mode)
        return result

    monkeypatch.setattr(Path, "stat", mounted_file_stat)
    called = False

    def write(resolved: Path) -> None:
        nonlocal called
        called = True
        resolved.write_text("unexpected\n")

    with CheckoutWriteLease.local(repo) as owner:
        with pytest.raises(CheckoutAdapterError) as boundary:
            owner.run_write(target, write)

    assert boundary.value.code == "checkout_target_mismatch"
    assert not called
    assert not (identity.common_dir / f".acp-checkout-{identity.checkout_id}.pending").exists()


def test_local_checkout_lease_refuses_corrupt_fence_state_before_action(tmp_path):
    repo = init_repo(tmp_path / "repo")
    identity = identify_checkout(repo)
    fence_state = identity.git_dir / f".acp-checkout-{identity.checkout_id}.fence-v1"
    fence_state.write_text("not valid fencing state\n", encoding="utf-8")
    fence_state.chmod(0o600)

    owner = CheckoutWriteLease.local(repo)
    with pytest.raises(CheckoutAdapterError) as state_error:
        owner.__enter__()

    assert state_error.value.code == "checkout_fence_state_unknown"
    assert owner._lock_fd is None


@pytest.mark.parametrize("boolean_field", ["identity_version", "fencing_token"])
def test_local_checkout_lease_rejects_boolean_integer_fields(tmp_path, boolean_field):
    repo = init_repo(tmp_path / "repo")
    identity = identify_checkout(repo)
    fence_state = identity.git_dir / f".acp-checkout-{identity.checkout_id}.fence-v1"
    record = {
        "identity_version": 1,
        "resource": identity.resource,
        "fencing_token": 1,
    }
    record[boolean_field] = True
    fence_state.write_text(json.dumps(record), encoding="utf-8")
    fence_state.chmod(0o600)

    with pytest.raises(CheckoutAdapterError) as state_error:
        CheckoutWriteLease.local(repo).__enter__()

    assert state_error.value.code == "checkout_fence_state_unknown"


def test_local_checkout_lease_requires_fence_state_sync_before_authority(tmp_path, monkeypatch):
    repo = init_repo(tmp_path / "repo")
    identity = identify_checkout(repo)
    fence_state = identity.git_dir / f".acp-checkout-{identity.checkout_id}.fence-v1"
    owner = CheckoutWriteLease.local(repo)

    def fail_sync(_descriptor):
        raise OSError("simulated local fence sync failure")

    monkeypatch.setattr(checkout_identity_module.os, "fsync", fail_sync)

    with pytest.raises(CheckoutAdapterError) as state_error:
        owner.__enter__()

    assert state_error.value.code == "checkout_fence_state_unavailable"
    assert owner._lock_fd is None
    assert not fence_state.exists()


def test_non_git_directory_fails_closed(tmp_path):
    with pytest.raises(CheckoutAdapterError) as error:
        identify_checkout(tmp_path)

    assert error.value.code == "not_a_git_checkout"


def test_generated_checkout_resource_serializes_task_claims_and_fences_stale_owner(
    client, app, admin_headers, tmp_path
):
    repo = init_repo(tmp_path / "repo")
    resource = identify_checkout(repo).resource
    agents = []
    mandates = []
    tasks = []
    for name in ("checkout-worker-a", "checkout-worker-b"):
        agent_response = client.post(
            "/v1/agents",
            headers=admin_headers,
            json={"name": name, "owner": "checkout-test@example.invalid", "role": "worker"},
        )
        assert agent_response.status_code == 201, agent_response.text
        agent = agent_response.json()
        agents.append(agent)
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
        mandates.append(mandate_response.json()["token"])
        task_response = client.post(
            "/v1/tasks",
            headers=admin_headers,
            json={
                "title": name,
                "description": "Serialize mediated writers by canonical checkout identity.",
                "acceptance_criteria": ["Only one active checkout writer"],
                "resources": [resource],
                "priority": 50,
            },
        )
        assert task_response.status_code == 201, task_response.text
        tasks.append(task_response.json())

    first_claim = client.post(
        f"/v1/tasks/{tasks[0]['id']}/claim",
        headers={"Authorization": f"Bearer {mandates[0]}"},
        json={"ttl_seconds": 300},
    )
    assert first_claim.status_code == 200, first_claim.text
    first_fence = first_claim.json()["resource_leases"][0]["fencing_token"]

    restarted_app = create_app(app.state.settings)
    assert restarted_app.state.database.path == app.state.database.path
    assert restarted_app.state.database is not app.state.database
    assert restarted_app.state.coordination is not app.state.coordination
    with TestClient(restarted_app) as restarted_client:
        blocked_claim = restarted_client.post(
            f"/v1/tasks/{tasks[1]['id']}/claim",
            headers={"Authorization": f"Bearer {mandates[1]}"},
            json={"ttl_seconds": 300},
        )
        assert blocked_claim.status_code == 409
        assert blocked_claim.json()["error"] == "resource_busy"

        with restarted_app.state.database.connect() as connection:
            connection.execute(
                "UPDATE resource_leases SET expires_at = 0 WHERE resource = ?", (resource,)
            )
        next_claim = restarted_client.post(
            f"/v1/tasks/{tasks[1]['id']}/claim",
            headers={"Authorization": f"Bearer {mandates[1]}"},
            json={"ttl_seconds": 300},
        )
        assert next_claim.status_code == 200, next_claim.text
        next_fence = next_claim.json()["resource_leases"][0]["fencing_token"]
        assert next_fence > first_fence

        stale_heartbeat = restarted_client.post(
            f"/v1/tasks/{tasks[0]['id']}/heartbeat",
            headers={"Authorization": f"Bearer {mandates[0]}"},
            json={
                "claim_fencing_token": first_claim.json()["task"]["claim_fencing_token"],
                "resource_fencing_tokens": {resource: first_fence},
                "ttl_seconds": 300,
                "checkpoint": {},
            },
        )
        assert stale_heartbeat.status_code == 409
        assert stale_heartbeat.json()["error"] == "stale_fencing_token"


def test_checkout_lease_serializes_adapters_and_rejects_stale_fence(tmp_path):
    repo = init_repo(tmp_path / "repo")
    state, acquire, validate, release = fencing_callbacks()
    first = lease_for(repo, acquire, validate, release)
    first.__enter__()

    try:
        second = lease_for(repo, acquire, validate, release)
        with pytest.raises(CheckoutAdapterError) as busy:
            second.__enter__()
        assert busy.value.code == "checkout_busy"
        assert state["token"] == 1

        state["token"] = 2
        called = []
        with pytest.raises(CheckoutAdapterError) as stale:
            first.run("write", lambda: called.append("mutated"))
        assert stale.value.code == "checkout_fence_stale"
        assert called == []
    finally:
        first.__exit__(None, None, None)

    assert state["released"] == [1]
    with lease_for(repo, acquire, validate, release) as next_owner:
        assert next_owner.fencing_token == 3
        assert next_owner.run("write", lambda: "committed") == "committed"
        assert next_owner.run("write", lambda: "second mediated write") == "second mediated write"


def test_checkout_lease_reports_remote_release_ambiguity_on_acquire_rollback(tmp_path):
    repo = init_repo(tmp_path / "repo")
    released = []

    def fail_release(resource: str, token: int) -> None:
        released.append((resource, token))
        raise RuntimeError("coordinator unavailable")

    owner = lease_for(repo, _fixed_acquire, lambda _resource, _token: False, fail_release)
    with pytest.raises(CheckoutAdapterError) as stale:
        owner.__enter__()

    assert stale.value.code == "checkout_fence_stale"
    assert released == [(identify_checkout(repo).resource, 1)]
    assert any("wait for authoritative lease expiry" in note for note in stale.value.__notes__)
    assert owner._lock_fd is None


def test_checkout_lease_reports_unknown_acquisition_outcome(tmp_path):
    repo = init_repo(tmp_path / "repo")

    def uncertain_acquire(_resource: str) -> int:
        raise TimeoutError("coordinator response was lost")

    owner = lease_for(repo, uncertain_acquire, _fixed_validate, _fixed_release)
    with pytest.raises(TimeoutError) as outcome:
        owner.__enter__()

    assert any("acquisition outcome may be unknown" in note for note in outcome.value.__notes__)
    assert owner._lock_fd is None


def test_one_checkout_lease_serializes_concurrent_threads(tmp_path):
    repo = init_repo(tmp_path / "repo")
    state, acquire, validate, release = fencing_callbacks()
    start = Barrier(3)
    counts_lock = Lock()
    active = 0
    max_active = 0
    completed = []

    def worker(owner: CheckoutWriteLease, name: str) -> None:
        nonlocal active, max_active
        start.wait(timeout=5)

        def action() -> str:
            nonlocal active, max_active
            with counts_lock:
                active += 1
                max_active = max(max_active, active)
            sleep(0.03)
            with counts_lock:
                active -= 1
            return name

        completed.append(owner.run("write", action))

    with lease_for(repo, acquire, validate, release) as owner:
        threads = [Thread(target=worker, args=(owner, name)) for name in ("a", "b")]
        for thread in threads:
            thread.start()
        start.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=5)
        assert all(not thread.is_alive() for thread in threads)

    assert sorted(completed) == ["a", "b"]
    assert max_active == 1


@pytest.mark.parametrize("index_flag", ["--assume-unchanged", "--skip-worktree"])
def test_destructive_checkout_operations_refuse_hidden_tracked_changes(tmp_path, index_flag):
    repo = init_repo(tmp_path / "repo")
    git(repo, "update-index", index_flag, "tracked.txt")
    (repo / "tracked.txt").write_text("modified behind index flag\n", encoding="utf-8")
    state, acquire, validate, release = fencing_callbacks()
    called = []

    with lease_for(repo, acquire, validate, release) as owner:
        with pytest.raises(CheckoutAdapterError) as dirty:
            owner.run("sync", lambda: called.append("mutated"))

    assert dirty.value.code == "checkout_index_flags"
    assert called == []
    assert (repo / "tracked.txt").read_text(encoding="utf-8") == "modified behind index flag\n"


def test_destructive_checkout_operations_fail_closed_for_dirty_ignored_submodule(tmp_path):
    submodule_source = init_repo(tmp_path / "submodule-source")
    repo = init_repo(tmp_path / "repo")
    subprocess.run(
        [
            "git",
            "-c",
            "protocol.file.allow=always",
            "-C",
            str(repo),
            "submodule",
            "add",
            str(submodule_source),
            "child",
        ],
        capture_output=True,
        check=True,
    )
    git(repo, "config", "submodule.child.ignore", "all")
    git(repo, "commit", "-am", "add submodule")
    (repo / "child" / "tracked.txt").write_text("dirty nested worktree\n", encoding="utf-8")
    state, acquire, validate, release = fencing_callbacks()
    called = []

    with lease_for(repo, acquire, validate, release) as owner:
        with pytest.raises(CheckoutAdapterError) as dirty:
            owner.run("sync", lambda: called.append("mutated"))

    assert dirty.value.code == "checkout_submodules_unsupported"
    assert called == []
    assert (repo / "child" / "tracked.txt").read_text(encoding="utf-8") == "dirty nested worktree\n"


@pytest.mark.skipif(os.name != "posix", reason="executable mode bits require POSIX")
def test_destructive_checkout_operations_detect_mode_change_when_git_config_hides_it(tmp_path):
    repo = init_repo(tmp_path / "repo")
    tracked = repo / "tracked.txt"
    tracked.chmod(tracked.stat().st_mode | stat.S_IXUSR)
    git(repo, "add", "tracked.txt")
    git(repo, "commit", "-m", "mark tracked file executable")
    git(repo, "config", "core.filemode", "false")
    tracked.chmod(tracked.stat().st_mode & ~stat.S_IXUSR)
    state, acquire, validate, release = fencing_callbacks()
    called = []

    with lease_for(repo, acquire, validate, release) as owner:
        with pytest.raises(CheckoutAdapterError) as dirty:
            owner.run("sync", lambda: called.append("mutated"))

    assert dirty.value.code == "checkout_dirty"
    assert called == []
    assert not (tracked.stat().st_mode & stat.S_IXUSR)


def test_destructive_checkout_operations_detect_case_only_rename(tmp_path):
    case_probe = tmp_path / "case-probe"
    case_probe.write_text("probe\n", encoding="utf-8")
    is_case_insensitive = (tmp_path / "CASE-PROBE").exists()
    case_probe.unlink()
    if not is_case_insensitive:
        pytest.skip("case-only rename semantics require a case-insensitive filesystem")

    repo = init_repo(tmp_path / "repo")
    tracked = repo / "foo"
    tracked.write_text("tracked\n", encoding="utf-8")
    git(repo, "add", "foo")
    git(repo, "commit", "-m", "add lowercase path")
    git(repo, "config", "core.ignoreCase", "true")
    tracked.rename(repo / "Foo")
    state, acquire, validate, release = fencing_callbacks()
    called = []

    with lease_for(repo, acquire, validate, release) as owner:
        with pytest.raises(CheckoutAdapterError) as dirty:
            owner.run("sync", lambda: called.append("mutated"))

    assert dirty.value.code == "checkout_dirty"
    assert called == []
    assert (repo / "Foo").read_text(encoding="utf-8") == "tracked\n"


@pytest.mark.skipif(os.name != "posix", reason="POSIX advisory locks are not available")
def test_checkout_write_lock_is_shared_across_processes(tmp_path):
    repo = init_repo(tmp_path / "repo")
    context = get_context("spawn")
    entered = context.Event()
    finish = context.Event()
    process = context.Process(target=_hold_checkout_lock, args=(str(repo), entered, finish))
    process.start()
    try:
        assert entered.wait(15), "child did not acquire the checkout lock"
        second = CheckoutWriteLease.local(repo)
        with pytest.raises(CheckoutAdapterError) as busy:
            second.__enter__()
        assert busy.value.code == "checkout_busy"
        finish.set()
        process.join(15)
        assert process.exitcode == 0
        with CheckoutWriteLease.local(repo):
            pass
    finally:
        if process.is_alive():
            process.terminate()
        process.join(15)


@pytest.mark.skipif(os.name != "posix", reason="POSIX advisory locks are not available")
def test_process_crash_during_mediated_write_blocks_next_owner(tmp_path):
    repo = init_repo(tmp_path / "repo")
    target = repo / "tracked.txt"
    context = get_context("spawn")
    entered = context.Event()
    process = context.Process(
        target=_hold_interrupted_checkout_write,
        args=(str(repo), str(target), entered),
    )
    process.start()
    try:
        assert entered.wait(15), "child did not reach the partial write"
        process.terminate()
        process.join(15)
        assert not process.is_alive()
        assert process.exitcode != 0
    finally:
        if process.is_alive():
            process.terminate()
        process.join(15)

    identity = identify_checkout(repo)
    marker = identity.common_dir / f".acp-checkout-{identity.checkout_id}.pending"
    assert marker.is_file()
    assert json.loads(marker.read_text(encoding="utf-8")) == {
        "fencing_token": 1,
        "identity_version": 1,
        "operation": "write",
        "resource": identity.resource,
        "state": "pending",
    }
    assert target.read_text(encoding="utf-8") == "partial write\n"

    next_owner = CheckoutWriteLease.local(repo)
    with pytest.raises(CheckoutAdapterError) as recovery:
        next_owner.__enter__()
    assert recovery.value.code == "checkout_recovery_required"
    fence_state = identity.git_dir / f".acp-checkout-{identity.checkout_id}.fence-v1"
    assert json.loads(fence_state.read_text(encoding="utf-8"))["fencing_token"] == 1


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO markers require POSIX")
def test_active_checkout_fence_rejects_fifo_marker_without_blocking(tmp_path):
    repo = init_repo(tmp_path / "repo")
    identity = identify_checkout(repo)
    marker = identity.common_dir / f".acp-checkout-{identity.checkout_id}.pending"
    os.mkfifo(marker, 0o600)

    assert not _has_active_checkout_write_lease(repo, identity.resource, 1)


@pytest.mark.skipif(
    os.name != "posix" or checkout_identity_module.fcntl is None,
    reason="POSIX advisory locks are not available",
)
def test_active_checkout_fence_rejects_unlocked_marker_while_checkout_lock_is_held(tmp_path):
    repo = init_repo(tmp_path / "repo")
    identity = identify_checkout(repo)
    marker = identity.common_dir / f".acp-checkout-{identity.checkout_id}.pending"
    marker.write_text(
        json.dumps(
            {
                "fencing_token": 1,
                "identity_version": 1,
                "operation": "write",
                "resource": identity.resource,
                "state": "pending",
            }
        ),
        encoding="utf-8",
    )
    marker.chmod(0o600)
    flock = checkout_identity_module.fcntl.flock
    lock_fd = _open_checkout_lock(identity.git_dir)
    flock(lock_fd, checkout_identity_module.fcntl.LOCK_EX | checkout_identity_module.fcntl.LOCK_NB)
    try:
        assert not _has_active_checkout_write_lease(repo, identity.resource, 1)
    finally:
        flock(lock_fd, checkout_identity_module.fcntl.LOCK_UN)
        os.close(lock_fd)


@pytest.mark.skipif(
    os.name != "posix" or checkout_identity_module.fcntl is None,
    reason="POSIX advisory locks are not available",
)
def test_active_checkout_fence_rejects_marker_replaced_during_lock_contention(
    tmp_path, monkeypatch
):
    repo = init_repo(tmp_path / "repo")
    identity = identify_checkout(repo)
    marker = identity.common_dir / f".acp-checkout-{identity.checkout_id}.pending"

    def write_marker(token: int) -> None:
        marker.write_text(
            json.dumps(
                {
                    "fencing_token": token,
                    "identity_version": 1,
                    "operation": "write",
                    "resource": identity.resource,
                    "state": "pending",
                }
            ),
            encoding="utf-8",
        )
        marker.chmod(0o600)

    write_marker(1)
    original_flock = checkout_identity_module.fcntl.flock
    replaced = False

    def replace_marker_then_report_contention(descriptor: int, operation: int) -> None:
        nonlocal replaced
        if operation & checkout_identity_module.fcntl.LOCK_NB and not replaced:
            replaced = True
            marker.unlink()
            write_marker(2)
            raise BlockingIOError("simulated active marker owner")
        original_flock(descriptor, operation)

    monkeypatch.setattr(
        checkout_identity_module.fcntl, "flock", replace_marker_then_report_contention
    )

    assert not _has_active_checkout_write_lease(repo, identity.resource, 1)
    assert replaced


def test_completion_sync_failure_keeps_marker_and_blocks_next_owner(tmp_path, monkeypatch):
    repo = init_repo(tmp_path / "repo")
    identity = identify_checkout(repo)
    marker = identity.common_dir / f".acp-checkout-{identity.checkout_id}.pending"
    real_fsync = os.fsync
    fsync_calls = 0

    def fail_completion_sync(descriptor):
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 3:
            raise OSError("simulated completion fsync failure")
        return real_fsync(descriptor)

    monkeypatch.setattr(checkout_identity_module.os, "fsync", fail_completion_sync)
    state, acquire, validate, release = fencing_callbacks()
    with lease_for(repo, acquire, validate, release) as owner:
        with pytest.raises(CheckoutAdapterError) as completion:
            owner.run("write", lambda: "callback completed")

    assert completion.value.code == "checkout_recovery_completion_failed"
    assert fsync_calls == 3
    assert marker.is_file()
    next_owner = lease_for(repo, acquire, validate, release)
    with pytest.raises(CheckoutAdapterError) as recovery:
        next_owner.__enter__()
    assert recovery.value.code == "checkout_recovery_required"
    assert state["token"] == 1


def test_marker_directory_sync_failure_after_completion_is_not_ambiguous(tmp_path, monkeypatch):
    repo = init_repo(tmp_path / "repo")
    identity = identify_checkout(repo)
    marker = identity.common_dir / f".acp-checkout-{identity.checkout_id}.pending"
    real_fsync = os.fsync
    fsync_calls = 0

    def fail_marker_directory_sync(descriptor):
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 4:
            raise OSError("simulated marker directory fsync failure")
        return real_fsync(descriptor)

    monkeypatch.setattr(checkout_identity_module.os, "fsync", fail_marker_directory_sync)
    state, acquire, validate, release = fencing_callbacks()
    with lease_for(repo, acquire, validate, release) as owner:
        assert owner.run("write", lambda: "callback completed") == "callback completed"

    assert fsync_calls == 4
    assert not marker.exists()
    with lease_for(repo, acquire, validate, release) as next_owner:
        assert next_owner.run("write", lambda: "next operation") == "next operation"
    assert state["token"] == 2


@pytest.mark.parametrize("relative_path", ["new.txt", "ignored.bin"])
def test_destructive_checkout_operations_refuse_untracked_or_ignored_state(tmp_path, relative_path):
    repo = init_repo(tmp_path / "repo")
    (repo / ".gitignore").write_text("ignored.bin\n", encoding="utf-8")
    git(repo, "add", ".gitignore")
    git(repo, "commit", "-m", "ignore test artifact")
    state, acquire, validate, release = fencing_callbacks()
    called = []

    with lease_for(repo, acquire, validate, release) as owner:
        (repo / relative_path).write_text("preserve me\n", encoding="utf-8")
        with pytest.raises(CheckoutAdapterError) as dirty:
            owner.run("sync", lambda: called.append("mutated"))

    assert dirty.value.code == "checkout_dirty"
    assert called == []
    assert (repo / relative_path).read_text(encoding="utf-8") == "preserve me\n"


def test_ambiguous_cleanup_is_not_retried_and_recovery_marker_blocks_next_owner(tmp_path):
    repo = init_repo(tmp_path / "repo")
    state, acquire, validate, release = fencing_callbacks()
    with lease_for(repo, acquire, validate, release) as owner:

        def interrupted_cleanup():
            (repo / "tracked.txt").unlink()
            raise RuntimeError("simulated interruption")

        with pytest.raises(RuntimeError, match="simulated interruption"):
            owner.run("cleanup", interrupted_cleanup)
        with pytest.raises(CheckoutAdapterError) as blocked:
            owner.run("write", lambda: None)
        assert blocked.value.code == "checkout_operation_blocked"

    called = []
    next_owner = lease_for(repo, acquire, validate, release)
    with pytest.raises(CheckoutAdapterError) as recovery:
        next_owner.__enter__()

    assert recovery.value.code == "checkout_recovery_required"
    assert called == []
    assert not (repo / "tracked.txt").exists()
