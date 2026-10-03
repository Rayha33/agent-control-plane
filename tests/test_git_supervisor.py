from __future__ import annotations

import base64
import hashlib
import json
import multiprocessing
import os
import shlex
import signal
import socket
import subprocess
import sys
import time
import uuid as _uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, Event
from types import SimpleNamespace

import pytest
from support import (
    install_passing_critic,
    passing_critic_script,
    python_command,
    requires_linux_worker,
)

from agent_control_plane import worker_trampoline
from agent_control_plane.git_supervisor import (
    CLEANUP_FENCE_EPOCH,
    GitSupervisor,
    SupervisorError,
)
from agent_control_plane.supervisor import claims as claims_module
from agent_control_plane.supervisor import process as process_module
from agent_control_plane.trust_bundles import install_bundle, verify_bundle_pin


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
    runtime_setup_commands: list[str] | None = None,
    runtime_teardown_commands: list[str] | None = None,
    runtime_ports: dict[str, tuple[int, int]] | None = None,
    attempts_root: Path | str | None = None,
    min_free_bytes: int | bool | str | None = None,
) -> None:
    trust_root = None
    if critic_command is None:
        critic_command, trust_root = install_passing_critic(repo)
    qc = qc_commands if qc_commands is not None else [python_command("pass")]
    integration = integration_commands if integration_commands is not None else qc
    content = {
        "qc": json.dumps(qc),
        "integration": json.dumps(integration),
        "critic": json.dumps(critic_command),
        "required": str(require_critic).lower(),
        "runtime_setup": json.dumps(runtime_setup_commands or []),
        "runtime_teardown": json.dumps(runtime_teardown_commands or []),
    }
    port_lines = "".join(
        f"{name} = [{bounds[0]}, {bounds[1]}]\n"
        for name, bounds in sorted((runtime_ports or {}).items())
    )
    worktree_lines = []
    if attempts_root is not None:
        worktree_lines.append(f"attempts_root = {json.dumps(str(attempts_root))}\n")
    if min_free_bytes is not None:
        if isinstance(min_free_bytes, bool):
            serialized_min_free = str(min_free_bytes).lower()
        elif isinstance(min_free_bytes, str):
            serialized_min_free = json.dumps(min_free_bytes)
        else:
            serialized_min_free = str(min_free_bytes)
        worktree_lines.append(f"min_free_bytes = {serialized_min_free}\n")
    config_path = repo / "acp.toml"
    config_path.write_text(
        "[supervisor]\n"
        "lease_seconds = 60\n"
        f"qc_timeout_seconds = {timeout_seconds}\n"
        'critic_identity = "independent-qc"\n'
        f"require_critic = {content['required']}\n\n"
        "[qc]\n"
        f"commands = {content['qc']}\n"
        f"critic_command = {content['critic']}\n\n"
        "[integration]\n"
        f"commands = {content['integration']}\n\n"
        "[runtime]\n"
        f"setup_commands = {content['runtime_setup']}\n"
        f"teardown_commands = {content['runtime_teardown']}\n\n"
        "[runtime.ports]\n"
        f"{port_lines}" + (f"\n[worktrees]\n{''.join(worktree_lines)}" if worktree_lines else ""),
        encoding="utf-8",
    )
    if trust_root is not None:
        with config_path.open("a", encoding="utf-8") as handle:
            handle.write(
                f"\n[trust]\nroot = {json.dumps(str(trust_root))}\nowner_uid = {os.geteuid()}\n"
            )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-b", "main")
    git(tmp_path, "config", "user.name", "ACP Test")
    git(tmp_path, "config", "user.email", "acp@example.test")
    (tmp_path / "alpha.txt").write_text("base\n", encoding="utf-8")
    (tmp_path / "beta.txt").write_text("base\n", encoding="utf-8")
    git(tmp_path, "add", "alpha.txt", "beta.txt")
    git(tmp_path, "commit", "-m", "base")
    GitSupervisor.initialize(tmp_path)
    write_config(tmp_path)
    return tmp_path


def task(supervisor: GitSupervisor, resource: str, title: str = "bounded change") -> dict:
    return supervisor.create_task(
        title,
        "Change only the declared path.",
        ["The declared content is correct", "QC passes"],
        [resource],
    )


def test_external_attempt_worktree_root_rejects_relative_repository_and_symlink_paths(
    repo: Path,
) -> None:
    write_config(repo, attempts_root="relative/worktrees")
    with pytest.raises(SupervisorError) as relative:
        GitSupervisor(repo)
    assert relative.value.code == "invalid_config"

    write_config(repo, attempts_root=repo / "external-worktrees")
    with pytest.raises(SupervisorError) as internal:
        GitSupervisor(repo)
    assert internal.value.code == "invalid_config"

    redirected = repo.parent / f"{repo.name}-redirected-worktrees"
    redirected.symlink_to(repo / "outside", target_is_directory=True)
    write_config(repo, attempts_root=redirected)
    with pytest.raises(SupervisorError) as symlink_escape:
        GitSupervisor(repo)
    assert symlink_escape.value.code == "invalid_config"


def test_external_attempt_worktree_root_rejects_linked_worktree_git_common_dir(
    repo: Path,
) -> None:
    linked = repo.parent / f"{repo.name}-linked-worktree"
    git(repo, "worktree", "add", "-b", "linked-config-test", str(linked))
    common_dir = Path(git(linked, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    write_config(linked, attempts_root=common_dir / "worktrees" / "attempts")

    with pytest.raises(SupervisorError, match="Git administrative data") as error:
        GitSupervisor(linked)

    assert error.value.code == "invalid_config"
    assert not (common_dir / "worktrees" / "attempts").exists()


@pytest.mark.parametrize("min_free_bytes", [True, 0, -1, "1024"])
def test_worktree_min_free_bytes_requires_a_positive_integer(
    repo: Path, min_free_bytes: int | bool | str
) -> None:
    write_config(repo, min_free_bytes=min_free_bytes)

    with pytest.raises(SupervisorError, match="worktrees.min_free_bytes") as error:
        GitSupervisor(repo)

    assert error.value.code == "invalid_config"


def test_worktree_min_free_bytes_is_opt_in(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    supervisor = GitSupervisor(repo)
    assert supervisor.config.min_free_bytes is None
    created = task(supervisor, "alpha.txt")

    def unexpected_probe(_path: Path) -> object:
        raise AssertionError("unset disk floor must not probe capacity")

    monkeypatch.setattr(process_module.os, "statvfs", unexpected_probe)

    attempt = supervisor.claim(created["id"], "worker")

    assert attempt["status"] == "working"


def test_disk_headroom_boundary_deduplicates_same_filesystem_and_holds_git_lock(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    minimum = 1024
    write_config(repo, min_free_bytes=minimum)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    usage_paths: list[Path] = []
    lock_path = supervisor.state_dir / "git-operations.lock"
    lock_probe = (
        "import fcntl, os, sys; "
        "fd=os.open(sys.argv[1], os.O_RDWR); "
        "\ntry: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)"
        "\nexcept BlockingIOError: print('locked')"
        "\nelse: print('unlocked')"
    )

    def statvfs(path: Path) -> SimpleNamespace:
        usage_paths.append(Path(path))
        probe = subprocess.run(
            [sys.executable, "-c", lock_probe, str(lock_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        assert probe.stdout.strip() == "locked"
        return SimpleNamespace(f_bavail=minimum, f_frsize=1)

    monkeypatch.setattr(process_module.os, "statvfs", statvfs)

    attempt = supervisor.claim(created["id"], "worker")

    assert attempt["status"] == "working"
    assert len(usage_paths) == 1
    assert usage_paths[0] == supervisor._attempt_worktree_root


def test_disk_headroom_preserves_trailing_spaces_in_git_common_directory(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_config(repo, min_free_bytes=1)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    root = supervisor._attempt_worktree_root
    common_dir_with_space = Path(f"{repo / '.git'} ")
    common_dir_with_space.mkdir()
    original_stat = Path.stat
    usage_paths: list[Path] = []
    original_run_git = supervisor._run_git_while_locked

    def fake_run_git(*arguments: str) -> subprocess.CompletedProcess[bytes]:
        if arguments[:2] == ("rev-parse", "--path-format=absolute"):
            return subprocess.CompletedProcess(
                args=list(arguments),
                returncode=0,
                stdout=f"{common_dir_with_space}\n".encode(),
                stderr=b"",
            )
        return original_run_git(*arguments)

    def fake_stat(path: Path, *args, **kwargs):
        result = original_stat(path, *args, **kwargs)
        selected_device = (
            101 if Path(path) == root else 202 if Path(path) == common_dir_with_space else None
        )
        if selected_device is None:
            return result
        values = list(result)
        values[2] = selected_device
        return os.stat_result(values)

    def statvfs(path: Path) -> SimpleNamespace:
        usage_paths.append(Path(path))
        return SimpleNamespace(f_bavail=1, f_frsize=1)

    monkeypatch.setattr(supervisor, "_run_git_while_locked", fake_run_git)
    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(process_module.os, "statvfs", statvfs)

    attempt = supervisor.claim(created["id"], "worker")

    assert attempt["status"] == "working"
    assert usage_paths == [root, common_dir_with_space]


def test_disk_headroom_checks_distinct_git_filesystem_and_rolls_back_low_space(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    minimum = 1024
    write_config(repo, min_free_bytes=minimum)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    root = supervisor._attempt_worktree_root
    common_dir = Path(git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    original_stat = Path.stat
    usage_paths: list[Path] = []

    def fake_stat(path: Path, *args, **kwargs):
        result = original_stat(path, *args, **kwargs)
        selected_device = 101 if Path(path) == root else 202 if Path(path) == common_dir else None
        if selected_device is None:
            return result
        values = list(result)
        values[2] = selected_device
        return os.stat_result(values)

    def statvfs(path: Path) -> SimpleNamespace:
        path = Path(path)
        usage_paths.append(path)
        free = minimum if path == root else minimum - 1
        return SimpleNamespace(f_bavail=free, f_frsize=1)

    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(process_module.os, "statvfs", statvfs)

    with pytest.raises(SupervisorError) as error:
        supervisor.claim(created["id"], "worker-low-space")

    assert error.value.code == "insufficient_disk_headroom"
    assert "Git common directory" in str(error.value)
    assert usage_paths == [root, common_dir]
    assert supervisor.task(created["id"])["status"] == "open"
    assert supervisor.task(created["id"])["current_attempt_id"] is None
    with supervisor.connect() as connection:
        attempt = connection.execute(
            "SELECT branch, worktree, status FROM attempts WHERE task_id = ?",
            (created["id"],),
        ).fetchone()
        lease = connection.execute(
            "SELECT task_id, attempt_id, lease_expires_at FROM resource_leases WHERE resource = ?",
            ("alpha.txt",),
        ).fetchone()
    assert attempt["status"] == "failed"
    assert not Path(attempt["worktree"]).exists()
    assert git(repo, "branch", "--list", attempt["branch"]) == ""
    assert lease["task_id"] is None
    assert lease["attempt_id"] is None
    assert lease["lease_expires_at"] == 0


def test_disk_headroom_probe_failure_fails_closed(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_config(repo, min_free_bytes=1)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")

    def unavailable(_path: Path) -> SimpleNamespace:
        raise OSError("injected filesystem capacity failure")

    monkeypatch.setattr(process_module.os, "statvfs", unavailable)

    with pytest.raises(SupervisorError) as error:
        supervisor.claim(created["id"], "worker-unavailable-space")

    assert error.value.code == "disk_headroom_unavailable"
    assert supervisor.task(created["id"])["status"] == "open"
    with supervisor.connect() as connection:
        attempt = connection.execute(
            "SELECT branch, worktree FROM attempts WHERE task_id = ?",
            (created["id"],),
        ).fetchone()
    assert not Path(attempt["worktree"]).exists()
    assert git(repo, "branch", "--list", attempt["branch"]) == ""


def test_disk_headroom_git_directory_probe_failure_fails_closed(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_config(repo, min_free_bytes=1)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    original = supervisor._run_git_while_locked

    def unavailable(*arguments: str) -> subprocess.CompletedProcess[bytes]:
        if arguments[:2] == ("rev-parse", "--path-format=absolute"):
            raise OSError("injected Git common-directory probe failure")
        return original(*arguments)

    monkeypatch.setattr(supervisor, "_run_git_while_locked", unavailable)

    with pytest.raises(SupervisorError) as error:
        supervisor.claim(created["id"], "worker-git-probe-failure")

    assert error.value.code == "disk_headroom_unavailable"
    assert supervisor.task(created["id"])["status"] == "open"
    with supervisor.connect() as connection:
        attempt = connection.execute(
            "SELECT branch, worktree, status FROM attempts WHERE task_id = ?",
            (created["id"],),
        ).fetchone()
    assert attempt["status"] == "failed"
    assert not Path(attempt["worktree"]).exists()
    assert git(repo, "branch", "--list", attempt["branch"]) == ""


def test_attempt_worktree_collision_is_rejected_without_removing_existing_data(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    external_root = repo.parent / f"{repo.name}-collision-worktrees"
    attempt_id = _uuid.UUID("00000000-0000-4000-8000-000000000233")
    collision = external_root / str(attempt_id)
    collision.mkdir(parents=True)
    sentinel = collision / "keep.txt"
    sentinel.write_text("unrelated", encoding="utf-8")
    write_config(repo, attempts_root=external_root)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    monkeypatch.setattr(claims_module.uuid, "uuid4", lambda: attempt_id)

    with pytest.raises(SupervisorError) as error:
        supervisor.claim(created["id"], "worker")

    assert error.value.code == "worktree_collision"
    assert sentinel.read_text(encoding="utf-8") == "unrelated"
    assert supervisor.task(created["id"])["status"] == "open"
    with supervisor.connect() as connection:
        assert connection.execute("SELECT count(*) FROM attempts").fetchone()[0] == 0


def _claim_in_process(repo_root: str, task_id: int, agent_id: str, gate, results) -> None:
    try:
        gate.wait(timeout=20)
        attempt = GitSupervisor(Path(repo_root)).claim(task_id, agent_id)
        results.put(
            {
                "ok": True,
                "attempt_id": attempt["id"],
                "worktree": attempt["worktree"],
                "branch": attempt["branch"],
            }
        )
    except BaseException as error:
        results.put({"ok": False, "error": f"{type(error).__name__}: {error}"})


def _probe_git_operation_lock(repo_root: str, results) -> None:
    from agent_control_plane.supervisor import process as process_module

    original_flock = process_module.fcntl.flock

    def try_nonblocking(fd: int, operation: int) -> None:
        original_flock(fd, operation | process_module.fcntl.LOCK_NB)

    process_module.fcntl.flock = try_nonblocking
    try:
        with GitSupervisor(Path(repo_root))._git_operation_guard():
            results.put("acquired")
    except BlockingIOError:
        results.put("blocked_by_parent_lock")
    except BaseException as error:
        results.put(f"error: {type(error).__name__}: {error}")


def commit_change(attempt: dict, path: str, content: str, message: str = "implement") -> str:
    worktree = Path(attempt["worktree"])
    destination = worktree / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8")
    git(worktree, "add", path)
    git(worktree, "commit", "-m", message)
    return git(worktree, "rev-parse", "HEAD")


def commit_main_change(
    repo: Path,
    *,
    updates: dict[str, str] | None = None,
    renames: tuple[tuple[str, str], ...] = (),
    message: str,
) -> str:
    """Advance main in a second checkout without writing into ACP's base checkout."""

    base_head = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "--detach", base_head)
    worktree = repo.parent / f"{repo.name}-main-advance"
    git(repo, "worktree", "add", str(worktree), "main")
    try:
        for source, destination in renames:
            git(worktree, "mv", source, destination)
        for path, content in (updates or {}).items():
            target = worktree / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        git(worktree, "add", "-A")
        git(worktree, "commit", "-m", message)
        return git(worktree, "rev-parse", "HEAD")
    finally:
        git(repo, "worktree", "remove", "--force", str(worktree))


def reference_porcelain_merge(
    repo: Path, base_sha: str, candidate_sha: str, label: str
) -> tuple[subprocess.CompletedProcess[str], str | None]:
    worktree = repo.parent / f"reference-merge-{label}"
    branch = f"reference-merge-{label}"
    hooks = repo.parent / f"empty-hooks-{label}"
    hooks.mkdir(mode=0o700)
    git(repo, "worktree", "add", "-b", branch, str(worktree), base_sha)
    result = subprocess.run(
        [
            "git",
            "-c",
            f"core.hooksPath={hooks}",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "commit.gpgSign=false",
            "-c",
            "merge.verifySignatures=false",
            "-c",
            "maintenance.auto=false",
            "-c",
            "gc.auto=0",
            "-c",
            "submodule.recurse=false",
            "-c",
            "user.name=Agent Control Plane",
            "-c",
            "user.email=acp@localhost.invalid",
            "-C",
            str(worktree),
            "merge",
            "--strategy=ort",
            "--no-ff",
            "--no-edit",
            candidate_sha,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    head = git(worktree, "rev-parse", "HEAD") if result.returncode == 0 else None
    return result, head


def free_port_range(count: int) -> tuple[int, int]:
    for start in range(30000, 60000 - count):
        sockets = [socket.socket(socket.AF_INET, socket.SOCK_STREAM) for _ in range(count)]
        try:
            for offset, candidate in enumerate(sockets):
                candidate.bind(("127.0.0.1", start + offset))
            return start, start + count - 1
        except OSError:
            continue
        finally:
            for candidate in sockets:
                candidate.close()
    raise AssertionError("no adjacent test ports available")


def two_free_ports() -> tuple[int, int]:
    return free_port_range(2)


def install_test_bundle(
    source: Path,
    root: Path,
    version: str,
    message: str,
    script: str | None = None,
) -> dict:
    source.mkdir(exist_ok=True)
    executable = source / "critic"
    default_script = passing_critic_script().replace(
        "\nimport json, os\n", f"\n# {message}\nimport json, os\n", 1
    )
    executable.write_text(
        script or default_script,
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return install_bundle(
        source,
        root,
        version,
        {"critic": "critic"},
        owner_uid=os.geteuid(),
        require_privilege=False,
    )


def configure_trust(repo: Path, root: Path) -> None:
    config_path = repo / "acp.toml"
    lines = config_path.read_text(encoding="utf-8").splitlines()
    kept: list[str] = []
    skipping_trust = False
    for line in lines:
        if line.strip() == "[trust]":
            skipping_trust = True
            continue
        if skipping_trust and line.lstrip().startswith("["):
            skipping_trust = False
        if not skipping_trust:
            kept.append(line)
    config_path.write_text("\n".join(kept).rstrip() + "\n", encoding="utf-8")
    with config_path.open("a", encoding="utf-8") as handle:
        handle.write(f"\n[trust]\nroot = {json.dumps(str(root))}\nowner_uid = {os.geteuid()}\n")


def require_trusted_critic(repo: Path) -> None:
    config = (repo / "acp.toml").read_text(encoding="utf-8")
    (repo / "acp.toml").write_text(
        config.replace("require_critic = false", "require_critic = true").replace(
            'critic_command = ""', 'critic_command = "trusted:critic"'
        ),
        encoding="utf-8",
    )


def test_twenty_colliding_tasks_have_exactly_one_winner(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    tasks = [task(supervisor, "alpha.txt", f"task-{index}") for index in range(20)]
    barrier = Barrier(20)

    def compete(index: int) -> str:
        barrier.wait()
        try:
            supervisor.claim(tasks[index]["id"], f"agent-{index}")
            return "won"
        except SupervisorError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=20) as pool:
        outcomes = list(pool.map(compete, range(20)))
    assert outcomes.count("won") == 1
    assert outcomes.count("resource_busy") == 19


def test_non_overlapping_tasks_get_parallel_worktrees(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    first = task(supervisor, "alpha.txt", "alpha")
    second = task(supervisor, "beta.txt", "beta")
    barrier = Barrier(2)

    def claim_one(spec: tuple[dict, str]) -> dict:
        barrier.wait()
        return supervisor.claim(spec[0]["id"], spec[1])

    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(claim_one, [(first, "agent-alpha"), (second, "agent-beta")]))
    assert all(Path(claim["worktree"]).is_dir() for claim in claims)
    assert all(Path(claim["worktree"]).parent == repo / ".acp" / "worktrees" for claim in claims)
    assert all(claim["worktree_root"] == str(repo / ".acp" / "worktrees") for claim in claims)
    assert claims[0]["worktree"] != claims[1]["worktree"]


def test_git_operation_lock_is_shared_across_processes(repo: Path) -> None:
    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    probe = context.Process(target=_probe_git_operation_lock, args=(str(repo), results))
    supervisor = GitSupervisor(repo)
    started = False
    try:
        with supervisor._git_operation_guard():
            probe.start()
            started = True
            assert results.get(timeout=20) == "blocked_by_parent_lock"
    finally:
        if started:
            probe.join(timeout=20)
            if probe.is_alive():
                probe.terminate()
                probe.join(timeout=20)
        results.close()
        results.join_thread()

    assert not probe.is_alive()
    assert probe.exitcode == 0


def test_concurrent_process_claims_get_independent_registered_worktrees(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    tasks = [
        task(supervisor, f"parallel/agent-{index}.py", f"parallel claim {index}")
        for index in range(3)
    ]
    base_head = git(repo, "rev-parse", "HEAD")
    base_status = git(repo, "status", "--porcelain")
    context = multiprocessing.get_context("spawn")
    gate = context.Barrier(len(tasks) + 1)
    results = context.Queue()
    processes = [
        context.Process(
            target=_claim_in_process,
            args=(str(repo), item["id"], f"agent-{index}", gate, results),
        )
        for index, item in enumerate(tasks)
    ]
    started = []
    try:
        for process in processes:
            process.start()
            started.append(process)
        gate.wait(timeout=20)
        deadline = time.monotonic() + 60
        for process in started:
            process.join(timeout=max(0, deadline - time.monotonic()))
        assert not any(process.is_alive() for process in started)
        outcomes = [results.get(timeout=10) for _ in tasks]
        assert all(outcome["ok"] for outcome in outcomes), outcomes
        assert all(process.exitcode == 0 for process in started)
    finally:
        for process in started:
            if process.is_alive():
                process.terminate()
            process.join(timeout=5)
        results.close()
        results.join_thread()

    assert len({outcome["attempt_id"] for outcome in outcomes}) == len(tasks)
    assert len({outcome["branch"] for outcome in outcomes}) == len(tasks)
    assert len({outcome["worktree"] for outcome in outcomes}) == len(tasks)
    registered = {
        Path(line.removeprefix("worktree ")).resolve()
        for line in git(repo, "worktree", "list", "--porcelain").splitlines()
        if line.startswith("worktree ")
    }
    for outcome in outcomes:
        attempt = supervisor.attempt(outcome["attempt_id"])
        worktree = Path(outcome["worktree"]).resolve()
        assert attempt["status"] == "working"
        assert attempt["branch"] == outcome["branch"]
        assert worktree.is_dir()
        assert worktree in registered
        assert git(worktree, "branch", "--show-current") == outcome["branch"]
        assert git(worktree, "rev-parse", "HEAD") == base_head

    assert git(repo, "rev-parse", "HEAD") == base_head
    assert git(repo, "branch", "--show-current") == "main"
    assert git(repo, "status", "--porcelain") == base_status
    assert not (repo / ".git" / "config.lock").exists()


@pytest.mark.parametrize("external_root", [False, True])
def test_worktree_add_failure_after_creation_rolls_back_partial_claim(
    repo: Path, monkeypatch, external_root: bool
) -> None:
    port, _ = free_port_range(1)
    attempts_root = (
        repo.parent / f"{repo.name}-failed-external-worktrees" if external_root else None
    )
    write_config(repo, runtime_ports={"APP_PORT": (port, port)}, attempts_root=attempts_root)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt", "injected provisioning failure")
    original_git = supervisor._git

    def fail_worktree_add(*arguments, **options):
        if arguments[:2] == ("worktree", "add"):
            original_git(*arguments, **options)
            raise SupervisorError("git_error", "injected post-creation provisioning failure")
        return original_git(*arguments, **options)

    monkeypatch.setattr(supervisor, "_git", fail_worktree_add)
    with pytest.raises(SupervisorError, match="injected post-creation provisioning failure"):
        supervisor.claim(created["id"], "agent-provisioning-failure")

    rolled_back_task = supervisor.task(created["id"])
    assert rolled_back_task["status"] == "open"
    assert rolled_back_task["current_attempt_id"] is None
    with supervisor.connect() as connection:
        attempt = connection.execute(
            "SELECT id, branch, worktree, status FROM attempts WHERE task_id = ?",
            (created["id"],),
        ).fetchone()
        runtime = connection.execute(
            "SELECT state FROM runtime_environments WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()
        lease = connection.execute(
            "SELECT task_id, attempt_id, lease_expires_at FROM resource_leases WHERE resource = ?",
            ("alpha.txt",),
        ).fetchone()
        allocations = connection.execute(
            "SELECT pool_name, value, attempt_id FROM runtime_allocations WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchall()

    assert attempt["status"] == "failed"
    assert runtime["state"] == "released"
    assert lease["task_id"] is None
    assert lease["attempt_id"] is None
    assert lease["lease_expires_at"] == 0
    assert allocations == []
    assert not Path(attempt["worktree"]).exists()
    assert git(repo, "branch", "--list", attempt["branch"]) == ""
    registered = {
        Path(line.removeprefix("worktree ")).resolve()
        for line in git(repo, "worktree", "list", "--porcelain").splitlines()
        if line.startswith("worktree ")
    }
    assert registered == {repo.resolve()}
    if attempts_root is not None:
        assert attempts_root.is_dir()
        assert list(attempts_root.iterdir()) == []
    assert not (repo / ".git" / "config.lock").exists()


def test_claim_refuses_overlapping_write_sets(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    first_task = task(supervisor, "alpha.txt", "first writer")
    second_task = task(supervisor, "alpha.txt", "second writer")
    attempt = supervisor.claim(first_task["id"], "agent-first")

    with pytest.raises(SupervisorError) as collision:
        supervisor.claim(second_task["id"], "agent-second")

    assert collision.value.code == "resource_busy"
    assert supervisor.task(second_task["id"])["status"] == "open"
    assert supervisor.attempt(attempt["id"])["status"] == "working"


def test_submit_accepts_an_unchanged_dirty_base_checkout(repo: Path) -> None:
    """A pre-existing dirty checkout is preserved as baseline, not mistaken for escape."""

    (repo / "alpha.txt").write_text("pre-existing staged secret\n", encoding="utf-8")
    git(repo, "add", "alpha.txt")
    (repo / "beta.txt").write_text("pre-existing unstaged secret\n", encoding="utf-8")
    (repo / "preexisting.txt").write_text("pre-existing untracked secret\n", encoding="utf-8")
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "beta.txt")
    attempt = supervisor.claim(created["id"], "worker")
    with supervisor.connect() as connection:
        snapshot_json = connection.execute(
            "SELECT base_checkout_snapshot_json FROM attempts WHERE id = ?",
            (attempt["id"],),
        ).fetchone()[0]
    assert "pre-existing staged secret" not in snapshot_json
    assert "pre-existing unstaged secret" not in snapshot_json
    assert "pre-existing untracked secret" not in snapshot_json

    commit_change(attempt, "beta.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])

    assert submission["status"] == "pending_qc"
    assert (repo / "alpha.txt").read_text(encoding="utf-8") == "pre-existing staged secret\n"
    assert (repo / "beta.txt").read_text(encoding="utf-8") == "pre-existing unstaged secret\n"
    assert (repo / "preexisting.txt").read_text(
        encoding="utf-8"
    ) == "pre-existing untracked secret\n"


def _commit_result_manifest(
    supervisor: GitSupervisor,
    manifest: dict | str,
    *,
    artifacts: dict[str, str] | None = None,
    symlinks: dict[str, str] | None = None,
    credential: str | None = None,
) -> tuple[dict, dict]:
    created = supervisor.create_task(
        "submit a bounded completion receipt",
        "Change the candidate and report paths only.",
        ["The immutable receipt resolves to the submitted commit"],
        ["beta.txt", "reports/**"],
    )
    attempt = supervisor.claim(created["id"], "worker")
    worktree = Path(attempt["worktree"])
    (worktree / "beta.txt").write_text("candidate\n", encoding="utf-8")
    for path, content in (artifacts or {}).items():
        destination = worktree / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
    for path, target in (symlinks or {}).items():
        destination = worktree / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.symlink_to(target)
    manifest_path = worktree / "reports" / "result-manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(manifest, dict):
        for artifact in manifest.get("artifacts", []):
            if (
                isinstance(artifact, dict)
                and artifact.get("blob_oid") == "PENDING"
                and isinstance(artifact.get("path"), str)
                and (worktree / artifact["path"]).is_file()
            ):
                artifact["blob_oid"] = git(worktree, "hash-object", artifact["path"])
        text_manifest = json.dumps(manifest)
    else:
        text_manifest = manifest
    manifest_path.write_text(text_manifest, encoding="utf-8")
    git(worktree, "add", "-A")
    git(worktree, "commit", "-m", "submit result manifest")
    return attempt, {
        "commit": git(worktree, "rev-parse", "HEAD"),
        "credential": credential,
        "task_id": created["id"],
        "worktree": worktree,
        "base_sha": created["base_sha"],
    }


def test_completion_receipt_is_commit_pinned_and_survives_worktree_cleanup(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    artifact_content = "The substantive findings stay in this tracked file.\n"
    attempt, context = _commit_result_manifest(
        supervisor,
        {
            "version": 1,
            "summary": "Audit complete; see the findings table.",
            "artifacts": [
                {
                    "path": "reports/findings.md",
                    "blob_oid": "PENDING",
                }
            ],
        },
        artifacts={"reports/findings.md": artifact_content},
    )
    worktree = context["worktree"]
    expected_oid = git(worktree, "rev-parse", "HEAD:reports/findings.md")

    submission = supervisor.submit(
        attempt["id"], attempt["claim_token"], result_manifest_path="reports/result-manifest.json"
    )
    receipt = submission["completion_receipt"]
    assert receipt == {
        "state": "provided",
        "version": 1,
        "summary": "Audit complete; see the findings table.",
        "manifest_path": "reports/result-manifest.json",
        "manifest_blob_oid": git(
            repo, "rev-parse", f"{context['commit']}:reports/result-manifest.json"
        ),
        "artifacts": [
            {
                "path": "reports/findings.md",
                "blob_oid": expected_oid,
                "size_bytes": len(artifact_content.encode("utf-8")),
            }
        ],
    }
    assert artifact_content not in json.dumps(receipt)
    qc = supervisor.run_qc(submission["id"], "independent-qc")
    assert qc["verdict"] == "pass"
    (worktree / "reports/findings.md").write_text("uncommitted replacement\n", encoding="utf-8")

    if worktree.exists():
        git(repo, "worktree", "remove", "--force", str(worktree))
    reopened = GitSupervisor(repo)
    reopened_submission = reopened.submission(submission["id"])
    assert reopened_submission["completion_receipt"] == receipt
    task_view = reopened.task(context["task_id"])
    assert task_view["latest_submission"]["completion_receipt"] == receipt
    status_entry = next(
        item for item in reopened.status()["tasks"] if item["task_id"] == context["task_id"]
    )
    assert status_entry["completion_receipt"] == receipt
    assert artifact_content not in json.dumps(status_entry)
    merge_entry = next(
        item for item in reopened.merge_plan()["order"] if item["task_id"] == context["task_id"]
    )
    assert merge_entry["completion_receipt"] == receipt
    assert git(repo, "show", f"{context['commit']}:reports/findings.md") == artifact_content.strip()


@pytest.mark.parametrize(
    ("manifest", "artifacts", "credential"),
    [
        ('{"version":', {}, None),
        ("[" * 1500 + "]" * 1500, {}, None),
        (
            {
                "version": 1,
                "summary": "Traversal must fail.",
                "artifacts": [{"path": "../outside", "blob_oid": "0" * 40}],
            },
            {},
            None,
        ),
        (
            {
                "version": 1,
                "summary": "Path bytes are bounded.",
                "artifacts": [{"path": "reports/" + "x" * 1025, "blob_oid": "0" * 40}],
            },
            {},
            None,
        ),
        (
            {
                "version": 1,
                "summary": "Missing file must fail.",
                "artifacts": [{"path": "reports/missing.md", "blob_oid": "0" * 40}],
            },
            {},
            None,
        ),
        (
            {
                "version": 1,
                "summary": "Digest must match candidate content.",
                "artifacts": [{"path": "reports/findings.md", "blob_oid": "0" * 40}],
            },
            {"reports/findings.md": "actual content\n"},
            None,
        ),
        (
            {
                "version": 1,
                "summary": "Duplicate refs must fail.",
                "artifacts": [
                    {"path": "reports/findings.md", "blob_oid": "PENDING"},
                    {"path": "reports/findings.md", "blob_oid": "PENDING"},
                ],
            },
            {"reports/findings.md": "body\n"},
            None,
        ),
        (
            {
                "version": 1,
                "summary": "secret-token must not be recorded",
                "artifacts": [{"path": "reports/findings.md", "blob_oid": "0" * 40}],
            },
            {"reports/findings.md": "body\n"},
            "secret-token",
        ),
        (
            {
                "version": 1,
                "summary": "x" * (4 * 1024 + 1),
                "artifacts": [{"path": "reports/findings.md", "blob_oid": "0" * 40}],
            },
            {"reports/findings.md": "body\n"},
            None,
        ),
        (
            {
                "version": 1,
                "summary": "Too many references.",
                "artifacts": [
                    {"path": f"reports/{index}.md", "blob_oid": "0" * 40} for index in range(17)
                ],
            },
            {},
            None,
        ),
        (" " * (64 * 1024 + 1), {}, None),
    ],
)
def test_completion_receipt_rejects_invalid_or_unbounded_manifests(
    repo: Path,
    manifest: dict | str,
    artifacts: dict[str, str],
    credential: str | None,
) -> None:
    supervisor = GitSupervisor(repo)
    attempt, context = _commit_result_manifest(
        supervisor,
        manifest,
        artifacts=artifacts,
        credential=credential,
    )

    with pytest.raises(SupervisorError) as error:
        supervisor.submit(
            attempt["id"],
            attempt["claim_token"],
            context["credential"],
            result_manifest_path="reports/result-manifest.json",
        )

    assert error.value.code == "invalid_result_manifest"
    assert supervisor.attempt(attempt["id"])["status"] == "working"
    with supervisor.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM submissions").fetchone()[0] == 0


def test_ordinary_submit_reports_completion_receipt_as_not_provided(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "beta.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "beta.txt", "candidate\n")

    submission = supervisor.submit(attempt["id"], attempt["claim_token"])

    assert submission["completion_receipt"] == {"state": "not_provided"}


def test_completion_receipt_rejects_symlink_artifacts(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    attempt, _context = _commit_result_manifest(
        supervisor,
        {
            "version": 1,
            "summary": "Symlinks are not artifacts.",
            "artifacts": [{"path": "reports/link.md", "blob_oid": "0" * 40}],
        },
        symlinks={"reports/link.md": "findings.md"},
    )

    with pytest.raises(SupervisorError) as error:
        supervisor.submit(
            attempt["id"],
            attempt["claim_token"],
            result_manifest_path="reports/result-manifest.json",
        )

    assert error.value.code == "invalid_result_manifest"


@pytest.mark.parametrize(
    ("artifact_count", "reported_size"),
    [
        (1, 64 * 1024 * 1024 + 1),
        (5, 52 * 1024 * 1024),
    ],
)
def test_completion_receipt_enforces_artifact_size_limits(
    repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_count: int,
    reported_size: int,
) -> None:
    supervisor = GitSupervisor(repo)
    artifact_paths = [f"reports/findings-{index}.md" for index in range(artifact_count)]
    attempt, context = _commit_result_manifest(
        supervisor,
        {
            "version": 1,
            "summary": "Exercise byte limits without materializing large test blobs.",
            "artifacts": [{"path": path, "blob_oid": "PENDING"} for path in artifact_paths],
        },
        artifacts={path: "tiny fixture\n" for path in artifact_paths},
    )
    artifact_oids = {
        git(context["worktree"], "rev-parse", f"HEAD:{path}") for path in artifact_paths
    }
    original_git_text = supervisor._git_text

    def synthetic_sizes(*arguments: str) -> str:
        if len(arguments) == 3 and arguments[:2] == ("cat-file", "-s"):
            if arguments[2] in artifact_oids:
                return str(reported_size)
        return original_git_text(*arguments)

    monkeypatch.setattr(supervisor, "_git_text", synthetic_sizes)

    with pytest.raises(SupervisorError) as error:
        supervisor._completion_receipt_json(
            context["commit"],
            ["reports/result-manifest.json"],
            "reports/result-manifest.json",
            None,
        )

    assert error.value.code == "invalid_result_manifest"
    assert supervisor.attempt(attempt["id"])["status"] == "working"


@pytest.mark.parametrize("mutation", ["tracked", "staged", "hidden_tracked", "untracked"])
def test_submit_rejects_base_checkout_source_mutation_without_cleanup(
    repo: Path, mutation: str
) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "beta.txt")
    attempt = supervisor.claim(created["id"], "worker")
    secret = "private-root-content-must-not-appear-in-error"
    if mutation in {"tracked", "staged", "hidden_tracked"}:
        (repo / "alpha.txt").write_text(secret + "\n", encoding="utf-8")
        if mutation == "staged":
            git(repo, "add", "alpha.txt")
        elif mutation == "hidden_tracked":
            git(repo, "update-index", "--assume-unchanged", "alpha.txt")
        changed_path = "alpha.txt"
    else:
        (repo / "new-root-source.txt").write_text(secret + "\n", encoding="utf-8")
        changed_path = "new-root-source.txt"
    commit_change(attempt, "beta.txt", "candidate\n")

    with pytest.raises(SupervisorError) as error:
        supervisor.submit(attempt["id"], attempt["claim_token"])

    assert error.value.code == "base_checkout_mutated"
    assert json.dumps(changed_path) in str(error.value)
    assert secret not in str(error.value)
    assert (repo / changed_path).exists()
    assert Path(attempt["worktree"]).exists()
    assert supervisor.attempt(attempt["id"])["status"] == "working"
    with supervisor.connect() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM submissions WHERE attempt_id = ?", (attempt["id"],)
            ).fetchone()[0]
            == 0
        )


def test_submit_detects_symlink_target_change_in_base_checkout(repo: Path) -> None:
    link = repo / "source-link"
    link.symlink_to("alpha.txt")
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "beta.txt")
    attempt = supervisor.claim(created["id"], "worker")
    link.unlink()
    link.symlink_to("beta.txt")
    commit_change(attempt, "beta.txt", "candidate\n")

    with pytest.raises(SupervisorError) as error:
        supervisor.submit(attempt["id"], attempt["claim_token"])

    assert error.value.code == "base_checkout_mutated"
    assert json.dumps("source-link") in str(error.value)
    assert link.is_symlink()
    assert os.readlink(link) == "beta.txt"
    assert Path(attempt["worktree"]).exists()


def test_snapshot_does_not_follow_parent_swapped_to_symlink(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_dir = repo / "source-dir"
    source_dir.mkdir()
    (source_dir / "source.txt").write_text("inside base checkout\n", encoding="utf-8")
    git(repo, "add", "source-dir/source.txt")
    git(repo, "commit", "-m", "add nested source")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "source.txt").write_text("external secret\n", encoding="utf-8")
    supervisor = GitSupervisor(repo)
    saved_dir = repo / "source-dir-original"
    real_open = os.open
    swapped = False
    attempted_external_leaf_open = False

    def swapping_open(path, flags, *args, **kwargs):
        nonlocal attempted_external_leaf_open, swapped
        if path == "source.txt" and kwargs.get("dir_fd") is not None:
            attempted_external_leaf_open = True
        descriptor = real_open(path, flags, *args, **kwargs)
        if (
            path == "source-dir"
            and kwargs.get("dir_fd") is not None
            and flags & getattr(os, "O_DIRECTORY", 0)
            and not swapped
        ):
            source_dir.rename(saved_dir)
            source_dir.symlink_to(outside, target_is_directory=True)
            swapped = True
        return descriptor

    monkeypatch.setattr(os, "open", swapping_open)
    try:
        with pytest.raises(SupervisorError) as error:
            supervisor._fingerprint_base_path(
                repo.resolve(), b"source-dir/source.txt", b"source-dir/source.txt"
            )
    finally:
        monkeypatch.setattr(os, "open", real_open)
        if source_dir.is_symlink():
            source_dir.unlink()
        if saved_dir.exists():
            saved_dir.rename(source_dir)

    assert swapped
    assert not attempted_external_leaf_open
    assert error.value.code == "base_checkout_uninspectable"
    assert json.dumps("source-dir/source.txt") in str(error.value)
    assert (source_dir / "source.txt").read_text(encoding="utf-8") == "inside base checkout\n"


def test_submit_detects_source_change_inside_nonignored_untracked_repository(repo: Path) -> None:
    nested = repo / "vendor-source"
    nested.mkdir()
    git(nested, "init", "-b", "main")
    git(nested, "config", "user.name", "ACP Test")
    git(nested, "config", "user.email", "acp@example.test")
    nested_file = nested / "lib.txt"
    nested_file.write_text("nested baseline\n", encoding="utf-8")
    git(nested, "add", "lib.txt")
    git(nested, "commit", "-m", "nested baseline")
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "beta.txt")
    attempt = supervisor.claim(created["id"], "worker")
    nested_file.write_text("nested escaped write\n", encoding="utf-8")
    commit_change(attempt, "beta.txt", "candidate\n")

    with pytest.raises(SupervisorError) as error:
        supervisor.submit(attempt["id"], attempt["claim_token"])

    assert error.value.code == "base_checkout_mutated"
    assert json.dumps("vendor-source/lib.txt") in str(error.value)
    assert nested_file.read_text(encoding="utf-8") == "nested escaped write\n"
    assert Path(attempt["worktree"]).exists()


def test_claim_refuses_unsafe_root_git_filter_before_scanning(repo: Path) -> None:
    git(repo, "config", "filter.acp-test.clean", "true")
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "beta.txt")

    with pytest.raises(SupervisorError) as error:
        supervisor.claim(created["id"], "worker")

    assert error.value.code == "unsafe_git_execution_config"
    assert supervisor.task(created["id"])["status"] == "open"
    with supervisor.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 0


def test_claim_refuses_unsafe_root_worktree_git_filter_before_scanning(repo: Path) -> None:
    git(repo, "config", "extensions.worktreeConfig", "true")
    git(repo, "config", "--worktree", "filter.acp-test.clean", "true")
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "beta.txt")

    with pytest.raises(SupervisorError) as error:
        supervisor.claim(created["id"], "worker")

    assert error.value.code == "unsafe_git_execution_config"
    assert supervisor.task(created["id"])["status"] == "open"
    with supervisor.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 0


def test_claim_refuses_unsafe_nested_git_filter_before_scanning(repo: Path) -> None:
    nested = repo / "vendor-source"
    nested.mkdir()
    git(nested, "init", "-b", "main")
    git(nested, "config", "user.name", "ACP Test")
    git(nested, "config", "user.email", "acp@example.test")
    (nested / "lib.txt").write_text("nested baseline\n", encoding="utf-8")
    git(nested, "add", "lib.txt")
    git(nested, "commit", "-m", "nested baseline")
    git(nested, "config", "filter.acp-test.clean", "true")
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "beta.txt")

    with pytest.raises(SupervisorError) as error:
        supervisor.claim(created["id"], "worker")

    assert error.value.code == "unsafe_git_execution_config"
    assert supervisor.task(created["id"])["status"] == "open"
    with supervisor.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 0


def test_claim_refuses_unsafe_nested_worktree_git_filter_before_scanning(repo: Path) -> None:
    nested = repo / "vendor-source"
    nested.mkdir()
    git(nested, "init", "-b", "main")
    git(nested, "config", "user.name", "ACP Test")
    git(nested, "config", "user.email", "acp@example.test")
    git(nested, "config", "extensions.worktreeConfig", "true")
    (nested / "lib.txt").write_text("nested baseline\n", encoding="utf-8")
    git(nested, "add", "lib.txt")
    git(nested, "commit", "-m", "nested baseline")
    git(nested, "config", "--worktree", "filter.acp-test.clean", "true")
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "beta.txt")

    with pytest.raises(SupervisorError) as error:
        supervisor.claim(created["id"], "worker")

    assert error.value.code == "unsafe_git_execution_config"
    assert supervisor.task(created["id"])["status"] == "open"
    with supervisor.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 0


def test_submit_rejects_tampered_claim_snapshot(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "beta.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "beta.txt", "candidate\n")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET base_checkout_snapshot_json = '' WHERE id = ?",
            (attempt["id"],),
        )

    with pytest.raises(SupervisorError) as error:
        supervisor.submit(attempt["id"], attempt["claim_token"])

    assert error.value.code == "base_checkout_snapshot_invalid"
    assert Path(attempt["worktree"]).exists()
    assert supervisor.attempt(attempt["id"])["status"] == "working"


def test_submit_rejects_snapshot_downgrade_to_legacy(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "beta.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "beta.txt", "candidate\n")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET base_checkout_snapshot_json = '' WHERE id = ?",
            (attempt["id"],),
        )
        event = connection.execute(
            "SELECT id, payload_json FROM events WHERE event_type = 'attempt.ready' "
            "AND json_extract(payload_json, '$.attempt_id') = ? ORDER BY sequence DESC LIMIT 1",
            (attempt["id"],),
        ).fetchone()
        payload = json.loads(event["payload_json"])
        payload.pop("base_checkout_snapshot_sha256")
        connection.execute(
            "UPDATE events SET payload_json = ? WHERE id = ?",
            (json.dumps(payload, sort_keys=True, separators=(",", ":")), event["id"]),
        )

    with pytest.raises(SupervisorError) as error:
        supervisor.submit(attempt["id"], attempt["claim_token"])

    assert error.value.code == "base_checkout_snapshot_invalid"
    assert supervisor.verify_event_chain()["ok"] is False
    assert Path(attempt["worktree"]).exists()
    assert supervisor.attempt(attempt["id"])["status"] == "working"


def test_submit_rejects_tampered_claim_event_chain(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "beta.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "beta.txt", "candidate\n")
    with supervisor.connect() as connection:
        event = connection.execute(
            "SELECT id, payload_json FROM events WHERE event_type = 'attempt.ready' "
            "AND json_extract(payload_json, '$.attempt_id') = ? ORDER BY sequence DESC LIMIT 1",
            (attempt["id"],),
        ).fetchone()
        payload = json.loads(event["payload_json"])
        payload["tampered"] = True
        connection.execute(
            "UPDATE events SET payload_json = ? WHERE id = ?",
            (json.dumps(payload, sort_keys=True, separators=(",", ":")), event["id"]),
        )

    with pytest.raises(SupervisorError) as error:
        supervisor.submit(attempt["id"], attempt["claim_token"])

    assert error.value.code == "base_checkout_snapshot_invalid"
    assert supervisor.verify_event_chain()["ok"] is False
    assert Path(attempt["worktree"]).exists()
    assert supervisor.attempt(attempt["id"])["status"] == "working"


def test_concurrent_claims_ignore_git_registration_and_acp_metadata(repo: Path) -> None:
    (repo / "gamma.txt").write_text("base\n", encoding="utf-8")
    git(repo, "add", "gamma.txt")
    git(repo, "commit", "-m", "add third isolated resource")
    supervisor = GitSupervisor(repo)
    paths = ("alpha.txt", "beta.txt", "gamma.txt")
    attempts = [
        supervisor.claim(task(supervisor, path)["id"], f"worker-{index}")
        for index, path in enumerate(paths)
    ]
    root_status = git(repo, "status", "--porcelain=v1", "-z")

    for attempt, path in zip(attempts, paths, strict=True):
        commit_change(attempt, path, f"candidate-{path}\n")
    submissions = [supervisor.submit(attempt["id"], attempt["claim_token"]) for attempt in attempts]

    assert [submission["status"] for submission in submissions] == [
        "pending_qc",
        "pending_qc",
        "pending_qc",
    ]
    assert git(repo, "status", "--porcelain=v1", "-z") == root_status


def test_persistent_write_racing_a_claim_snapshot_is_blocked_before_qc(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    original = supervisor._fingerprint_base_path
    changed = False
    secret = "root-write-during-snapshot"

    def write_after_path_was_fingerprinted(
        root_real: Path, relative: bytes, display: bytes
    ) -> dict:
        nonlocal changed
        result = original(root_real, relative, display)
        if relative == b"alpha.txt" and not changed:
            changed = True
            (repo / "alpha.txt").write_text(secret + "\n", encoding="utf-8")
        return result

    monkeypatch.setattr(supervisor, "_fingerprint_base_path", write_after_path_was_fingerprinted)
    attempt = supervisor.claim(task(supervisor, "beta.txt")["id"], "worker")
    commit_change(attempt, "beta.txt", "candidate\n")

    with pytest.raises(SupervisorError) as error:
        supervisor.submit(attempt["id"], attempt["claim_token"])

    assert changed
    assert error.value.code == "base_checkout_mutated"
    assert json.dumps("alpha.txt") in str(error.value)
    assert secret not in str(error.value)
    assert (repo / "alpha.txt").read_text(encoding="utf-8") == secret + "\n"


@requires_linux_worker
def test_parallel_non_overlapping_workers_stay_in_their_own_worktrees(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Accepted parallel writes keep separate checkouts and Git state."""
    external_root = repo.parent / f"{repo.name}-attempt-worktrees"
    write_config(repo, attempts_root=external_root)
    supervisor = GitSupervisor(repo)
    first = supervisor.claim(task(supervisor, "alpha.txt", "first agent")["id"], "agent-first")
    second = supervisor.claim(task(supervisor, "beta.txt", "second agent")["id"], "agent-second")
    assert first["worktree"] != second["worktree"]
    assert Path(first["worktree"]).parent == external_root.resolve()
    assert Path(second["worktree"]).parent == external_root.resolve()
    assert first["worktree_root"] == str(external_root.resolve())
    assert second["worktree_root"] == str(external_root.resolve())
    assert first["branch"] != second["branch"]
    base_head = git(repo, "rev-parse", "HEAD")
    base_status = git(repo, "status", "--porcelain")

    worker = """
import os
import socket
import subprocess
import sys
from pathlib import Path

cwd = Path.cwd().resolve()
assert cwd == Path(os.environ["ACP_WORKTREE"]).resolve()
assert os.environ["ACP_ATTEMPT_ID"] == sys.argv[1]
assert not any(name.upper().startswith("GIT_") for name in os.environ if name not in {
    "GIT_ATTR_NOSYSTEM", "GIT_NO_REPLACE_OBJECTS"
})
git_root = Path(subprocess.check_output(
    ["git", "rev-parse", "--show-toplevel"], text=True
).strip()).resolve()
assert git_root == cwd
with socket.create_connection(("127.0.0.1", int(sys.argv[4])), timeout=30) as gate:
    assert gate.recv(1) == b"G", "parallel peer did not reach the worker gate"
Path(sys.argv[2]).write_text(sys.argv[3] + "\\n", encoding="utf-8")
subprocess.run(["git", "add", sys.argv[2]], check=True)
subprocess.run(["git", "commit", "-m", "isolated non-overlapping write"], check=True)
"""

    def run(attempt: dict, value: str) -> dict:
        return supervisor.run_worker(
            attempt["id"],
            attempt["claim_token"],
            [
                sys.executable,
                "-c",
                worker,
                attempt["id"],
                "alpha.txt" if attempt["id"] == first["id"] else "beta.txt",
                value,
                str(gate_port),
            ],
        )

    with monkeypatch.context() as poisoned_environment:
        poisoned_environment.setenv("GIT_DIR", str(repo / ".git"))
        poisoned_environment.setenv("GIT_WORK_TREE", str(repo))
        poisoned_environment.setenv("GIT_INDEX_FILE", str(repo / ".git" / "index"))
        with socket.socket() as start_gate:
            start_gate.bind(("127.0.0.1", 0))
            start_gate.listen(2)
            start_gate.settimeout(30)
            gate_port = start_gate.getsockname()[1]

            def release_workers() -> None:
                peers = []
                try:
                    for _ in range(2):
                        peer, _ = start_gate.accept()
                        peers.append(peer)
                    for peer in peers:
                        peer.sendall(b"G")
                finally:
                    for peer in peers:
                        peer.close()

            with ThreadPoolExecutor(max_workers=3) as pool:
                gate = pool.submit(release_workers)
                submissions = list(pool.map(run, (first, second), ("first", "second")))
                gate.result(timeout=32)

    assert [submission["status"] for submission in submissions] == [
        "pending_qc",
        "pending_qc",
    ]
    assert (repo / "alpha.txt").read_text(encoding="utf-8") == "base\n"
    assert (repo / "beta.txt").read_text(encoding="utf-8") == "base\n"
    assert (Path(first["worktree"]) / "alpha.txt").read_text(encoding="utf-8") == "first\n"
    assert (Path(second["worktree"]) / "beta.txt").read_text(encoding="utf-8") == "second\n"
    assert git(Path(first["worktree"]), "branch", "--show-current") == first["branch"]
    assert git(Path(second["worktree"]), "branch", "--show-current") == second["branch"]
    assert git(Path(first["worktree"]), "rev-parse", "HEAD^") == base_head
    assert git(Path(second["worktree"]), "rev-parse", "HEAD^") == base_head
    assert git(repo, "rev-parse", "HEAD") == base_head
    assert git(repo, "status", "--porcelain") == base_status


@requires_linux_worker
def test_runtime_ports_are_unique_and_reach_supervised_worker(repo: Path) -> None:
    start, end = two_free_ports()
    write_config(repo, runtime_ports={"APP_PORT": (start, end)})
    supervisor = GitSupervisor(repo)
    first = supervisor.claim(task(supervisor, "alpha.txt")["id"], "agent-a")
    second = supervisor.claim(task(supervisor, "beta.txt")["id"], "agent-b")

    first_port = first["runtime"]["environment"]["APP_PORT"]
    second_port = second["runtime"]["environment"]["APP_PORT"]
    assert first_port != second_port
    worker = (
        "import os, pathlib, subprocess; "
        "assert os.environ['ACP_PHASE'] == 'worker'; "
        "assert pathlib.Path(os.environ['ACP_WORKTREE']).resolve() == pathlib.Path.cwd().resolve(); "
        "pathlib.Path('alpha.txt').write_text(os.environ['APP_PORT'] + '\\n'); "
        "subprocess.run(['git', 'add', 'alpha.txt'], check=True); "
        "subprocess.run(['git', 'commit', '-m', 'record isolated port'], check=True)"
    )
    submission = supervisor.run_worker(
        first["id"], first["claim_token"], [sys.executable, "-c", worker]
    )

    assert submission["status"] == "pending_qc"
    assert (Path(first["worktree"]) / "alpha.txt").read_text().strip() == first_port
    with pytest.raises(SupervisorError) as active_cleanup:
        supervisor.runtime_down(first["id"])
    assert active_cleanup.value.code == "runtime_in_use"


@requires_linux_worker
def test_supervised_worker_heartbeat_does_not_replace_explicit_checkpoint(repo: Path) -> None:
    config = repo / "acp.toml"
    config.write_text(
        config.read_text(encoding="utf-8").replace("lease_seconds = 60", "lease_seconds = 15"),
        encoding="utf-8",
    )
    supervisor = GitSupervisor(repo)
    attempt = supervisor.claim(task(supervisor, "alpha.txt")["id"], "agent-a")
    command = (
        "import pathlib,subprocess,time; "
        "pathlib.Path('alpha.txt').write_text('worker\\n'); "
        "subprocess.run(['git','add','alpha.txt'],check=True); "
        "subprocess.run(['git','commit','-m','slow worker'],check=True); "
        "time.sleep(12)"
    )

    submission = supervisor.run_worker(
        attempt["id"], attempt["claim_token"], [sys.executable, "-c", command]
    )

    assert submission["status"] == "pending_qc"
    final_attempt = supervisor.attempt(attempt["id"])
    assert final_attempt["checkpoint"]["phase"] == "launching"
    assert final_attempt["checkpoint_at"] < final_attempt["heartbeat_at"]


def test_parallel_runtime_claims_receive_unique_ports(repo: Path) -> None:
    start, end = free_port_range(6)
    write_config(repo, runtime_ports={"APP_PORT": (start, end)})
    supervisor = GitSupervisor(repo)
    created = [
        task(supervisor, f"logical:runtime/{index}", f"runtime {index}") for index in range(6)
    ]

    with ThreadPoolExecutor(max_workers=6) as pool:
        attempts = list(
            pool.map(
                lambda item: supervisor.claim(item[1]["id"], f"agent-{item[0]}"),
                enumerate(created),
            )
        )

    ports = [attempt["runtime"]["environment"]["APP_PORT"] for attempt in attempts]
    assert len(set(ports)) == len(attempts)


def test_runtime_lifecycle_is_shared_with_qc_and_integration(repo: Path) -> None:
    start, end = two_free_ports()
    gate = python_command(
        "import os; from pathlib import Path; "
        'assert os.environ.get("APP_PORT"); '
        'assert Path(os.environ["ACP_WORKTREE"]).resolve() == Path.cwd().resolve(); '
        'assert os.environ["ACP_PHASE"] in {"qc", "integration"}'
    )
    write_config(
        repo,
        qc_commands=[gate],
        integration_commands=[gate],
        runtime_ports={"APP_PORT": (start, end)},
        runtime_setup_commands=['printf "%s" "$APP_PORT" > "$ACP_RUNTIME_DIR/setup-port"'],
        runtime_teardown_commands=['printf done > "$ACP_REPO_ROOT/.acp/teardown-$ACP_ATTEMPT_ID"'],
    )
    supervisor = GitSupervisor(repo)
    attempt = supervisor.claim(task(supervisor, "alpha.txt")["id"], "worker")
    runtime_dir = Path(attempt["runtime"]["environment"]["ACP_RUNTIME_DIR"])
    assert (runtime_dir / "setup-port").read_text() == attempt["runtime"]["environment"]["APP_PORT"]

    commit_change(attempt, "alpha.txt", "isolated\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.runtime_environment(attempt["id"])["state"] == "ready"
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"
    integration = supervisor.integrate(attempt["task_id"])

    assert integration["verdict"] == "pass"
    assert integration["runtime_cleanup"]["state"] == "released"
    assert not runtime_dir.exists()
    assert (repo / ".acp" / f"teardown-{attempt['id']}").read_text() == "done"


def test_occupied_runtime_port_is_quarantined_until_cleanup(repo: Path) -> None:
    start, _ = two_free_ports()
    write_config(repo, runtime_ports={"APP_PORT": (start, start)})
    supervisor = GitSupervisor(repo)
    first = supervisor.claim(task(supervisor, "alpha.txt")["id"], "agent-a")
    second_task = task(supervisor, "beta.txt")
    port = int(first["runtime"]["environment"]["APP_PORT"])
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", port))
    try:
        reaped = supervisor.reap_expired(now=first["lease_expires_at"])
        assert reaped["runtime_cleanup"] == [
            {"attempt_id": first["id"], "state": "teardown_failed"}
        ]
        with pytest.raises(SupervisorError, match="runtime port pool") as exhausted:
            supervisor.claim(second_task["id"], "agent-b")
        assert exhausted.value.code == "runtime_pool_exhausted"
    finally:
        listener.close()

    assert supervisor.runtime_down(first["id"])["state"] == "released"
    second = supervisor.claim(second_task["id"], "agent-b")
    assert second["runtime"]["environment"]["APP_PORT"] == str(port)


def test_reaper_tears_down_expired_runtime(repo: Path) -> None:
    start, _ = two_free_ports()
    write_config(repo, runtime_ports={"APP_PORT": (start, start)})
    supervisor = GitSupervisor(repo)
    attempt = supervisor.claim(task(supervisor, "alpha.txt")["id"], "worker")

    result = supervisor.reap_expired(now=attempt["lease_expires_at"])

    assert attempt["task_id"] in result["orphaned"]
    assert result["runtime_cleanup"] == [{"attempt_id": attempt["id"], "state": "released"}]
    assert supervisor.runtime_environment(attempt["id"])["state"] == "released"


@requires_linux_worker
def test_reaper_stops_supervised_worker_before_releasing_runtime(repo: Path) -> None:
    start, _ = two_free_ports()
    write_config(repo, runtime_ports={"APP_PORT": (start, start)})
    supervisor = GitSupervisor(repo)
    attempt = supervisor.claim(task(supervisor, "alpha.txt")["id"], "worker")
    port = int(attempt["runtime"]["environment"]["APP_PORT"])
    command = [
        sys.executable,
        "-c",
        (
            "import os,socket,time; "
            "listener=socket.socket(); "
            "listener.bind(('127.0.0.1',int(os.environ['APP_PORT']))); "
            "listener.listen(); time.sleep(60)"
        ),
    ]

    with ThreadPoolExecutor(max_workers=1) as pool:
        worker = pool.submit(supervisor.run_worker, attempt["id"], attempt["claim_token"], command)
        deadline = time.time() + 5
        while supervisor._port_available(port) and time.time() < deadline:
            time.sleep(0.02)
        assert not supervisor._port_available(port)
        result = supervisor.reap_expired(now=supervisor.attempt(attempt["id"])["lease_expires_at"])
        with pytest.raises(SupervisorError):
            worker.result(timeout=5)

    assert result["terminated_workers"][0]["attempt_id"] == attempt["id"]
    assert result["runtime_cleanup"] == [{"attempt_id": attempt["id"], "state": "released"}]
    assert supervisor._port_available(port)


def test_failed_worker_termination_keeps_cleanup_fence_and_runtime(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    first_task = task(supervisor, "alpha.txt", "first")
    second_task = task(supervisor, "alpha.txt", "second")
    attempt = supervisor.claim(first_task["id"], "agent-a")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET pid = 424242, pid_identity = 'linux:424242:1' WHERE id = ?",
            (attempt["id"],),
        )
    monkeypatch.setattr(supervisor, "_terminate_registered_group", lambda *_: "failed")

    result = supervisor.reap_expired(now=attempt["lease_expires_at"])

    assert result["orphaned"] == []
    assert result["runtime_cleanup"][0]["state"] == "cleanup_error"
    retained = supervisor.attempt(attempt["id"])
    assert retained["status"] == "terminating"
    assert retained["runtime"]["state"] == "ready"
    assert retained["resource_leases"][0]["lease_expires_at"] > 2**61
    with pytest.raises(SupervisorError) as collision:
        supervisor.claim(second_task["id"], "agent-b")
    assert collision.value.code == "resource_busy"


def test_worker_termination_fails_closed_without_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        GitSupervisor,
        "_open_registered_pidfd",
        lambda *_: pytest.fail("an identity-less PID must never be opened for signalling"),
    )

    assert GitSupervisor._terminate_registered_group(424242, "") == "failed"


def test_worker_termination_permission_denial_is_not_death_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_fd, write_fd = os.pipe()
    monkeypatch.setattr(GitSupervisor, "_open_registered_pidfd", lambda *_: read_fd)

    def denied(*_args: object) -> None:
        raise PermissionError

    monkeypatch.setattr(signal, "pidfd_send_signal", denied, raising=False)
    try:
        assert GitSupervisor._terminate_registered_group(424242, "linux:424242:1") == "failed"
    finally:
        os.close(write_fd)


def test_live_pidfd_with_unreadable_identity_is_not_death_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_fd, write_fd = os.pipe()
    monkeypatch.setattr(os, "pidfd_open", lambda *_: read_fd, raising=False)
    monkeypatch.setattr(signal, "pidfd_send_signal", lambda *_: None, raising=False)
    monkeypatch.setattr(GitSupervisor, "_process_identity", lambda _pid: None)
    try:
        assert GitSupervisor._terminate_registered_group(424242, "linux:424242:1") == "failed"
        with pytest.raises(OSError):
            os.fstat(read_fd)
    finally:
        os.close(write_fd)


def test_legacy_registered_pid_without_identity_is_migration_fenced(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "legacy-worker")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET pid = 424242, pid_identity = 'unavailable' WHERE id = ?",
            (attempt["id"],),
        )
        connection.execute("ALTER TABLE attempts DROP COLUMN pid_identity")

    upgraded = GitSupervisor(repo)
    fenced = upgraded.attempt(attempt["id"])

    assert fenced["status"] == "terminating"
    assert fenced["termination_target_status"] == "quarantined"
    assert fenced["termination_proof"] == ""
    assert fenced["pid"] == 424242
    assert fenced["pid_identity"] == ""
    task_state = upgraded.task(created["id"])
    assert task_state["status"] == "cleanup_pending"
    assert task_state["cleanup_target_status"] == "blocked"
    assert "no verifiable kernel identity" in task_state["cleanup_error"]
    assert fenced["resource_leases"][0]["lease_expires_at"] == CLEANUP_FENCE_EPOCH

    result = upgraded.reap_expired()
    assert result["terminated_workers"][0]["termination"] == "failed"
    assert upgraded.attempt(attempt["id"])["pid"] == 424242


def test_concurrent_claim_cannot_pass_a_reaper_blocked_on_worker_termination(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    first_task = task(supervisor, "alpha.txt", "first")
    second_task = task(supervisor, "alpha.txt", "second")
    attempt = supervisor.claim(first_task["id"], "agent-a")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET pid = 424242, pid_identity = 'linux:424242:1' WHERE id = ?",
            (attempt["id"],),
        )
    termination_entered = Event()
    release_termination = Event()

    def blocked_termination(_pid: int, _identity: str) -> str:
        termination_entered.set()
        assert release_termination.wait(timeout=5)
        return "failed"

    monkeypatch.setattr(supervisor, "_terminate_registered_group", blocked_termination)
    with ThreadPoolExecutor(max_workers=1) as pool:
        reaping = pool.submit(supervisor.reap_expired, attempt["lease_expires_at"])
        assert termination_entered.wait(timeout=5)
        with pytest.raises(SupervisorError) as collision:
            supervisor.claim(second_task["id"], "agent-b")
        assert collision.value.code == "resource_busy"
        assert supervisor.attempt(attempt["id"])["status"] == "terminating"
        release_termination.set()
        result = reaping.result(timeout=5)

    assert result["orphaned"] == []
    assert supervisor.task(second_task["id"])["status"] == "open"


def test_directory_aliases_overlap_and_internal_paths_are_rejected(
    repo: Path,
) -> None:
    (repo / "src").mkdir()
    (repo / "src" / "one.py").write_text("value = 1\n", encoding="utf-8")
    supervisor = GitSupervisor(repo)
    assert supervisor.normalize_resource("src/", repo) == "src/**"
    assert supervisor.resources_overlap("src/**", "src/one.py")
    assert supervisor.resources_overlap("src/*.py", "src/one.*")
    assert not supervisor.resources_overlap("src/*.py", "tests/*.py")
    with pytest.raises(SupervisorError, match="internal resource"):
        supervisor.normalize_resource(".git/config")
    with pytest.raises(SupervisorError, match="repo-relative"):
        supervisor.normalize_resource("../escape")


def test_claim_rejects_nested_logical_scope_and_keeps_waiting_task_open(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    holder = task(supervisor, "logical:auth", title="auth subsystem")
    waiting = task(supervisor, "logical:auth/session-migration", title="session migration")
    attempt = supervisor.claim(holder["id"], "agent-holder")

    with pytest.raises(SupervisorError) as busy:
        supervisor.claim(waiting["id"], "agent-waiting")

    assert busy.value.code == "resource_busy"
    assert supervisor.attempt(attempt["id"])["status"] == "working"
    assert supervisor.task(waiting["id"])["status"] == "open"


@pytest.mark.parametrize(
    "legacy_declared_path", ["Logical:auth", "./Logical:auth", "./logical:auth"]
)
def test_claim_keeps_legacy_case_variant_prefix_path_separate_from_logical_scope(
    repo: Path, legacy_declared_path: str
) -> None:
    supervisor = GitSupervisor(repo)
    legacy_path = task(supervisor, "logical:auth", title="legacy path alias")
    logical_child = task(supervisor, "logical:auth/session", title="logical child")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE tasks SET declared_resources_json = ? WHERE id = ?",
            (json.dumps({"logical:auth": legacy_declared_path}), legacy_path["id"]),
        )

    supervisor.claim(legacy_path["id"], "agent-path")
    child_attempt = supervisor.claim(logical_child["id"], "agent-logical")

    assert supervisor.attempt(child_attempt["id"])["status"] == "working"


def test_claim_serializes_identical_legacy_path_and_logical_keys(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    legacy_path = task(supervisor, "logical:auth", title="legacy path alias")
    logical_scope = task(supervisor, "logical:auth", title="logical namespace")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE tasks SET declared_resources_json = ? WHERE id = ?",
            (json.dumps({"logical:auth": "Logical:auth"}), legacy_path["id"]),
        )

    supervisor.claim(legacy_path["id"], "agent-path")
    with pytest.raises(SupervisorError) as busy:
        supervisor.claim(logical_scope["id"], "agent-logical")

    assert busy.value.code == "resource_busy"
    assert supervisor.task(logical_scope["id"])["status"] == "open"


def test_claim_allows_sibling_logical_scopes(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    session = task(supervisor, "logical:auth/session", title="session flow")
    tokens = task(supervisor, "logical:auth/tokens", title="token format")

    session_attempt = supervisor.claim(session["id"], "agent-session")
    token_attempt = supervisor.claim(tokens["id"], "agent-tokens")

    assert session_attempt["id"] != token_attempt["id"]


def test_submission_derives_diff_and_rejects_undeclared_write(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    worktree = Path(attempt["worktree"])
    (worktree / "alpha.txt").write_text("allowed\n", encoding="utf-8")
    (worktree / "beta.txt").write_text("not allowed\n", encoding="utf-8")
    git(worktree, "add", "alpha.txt", "beta.txt")
    git(worktree, "commit", "-m", "overbroad change")
    with pytest.raises(SupervisorError) as captured:
        supervisor.submit(attempt["id"], attempt["claim_token"])
    assert captured.value.code == "undeclared_write"


def test_external_symlink_is_rejected(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "escape-link")
    attempt = supervisor.claim(created["id"], "worker")
    worktree = Path(attempt["worktree"])
    (worktree / "escape-link").symlink_to("../../outside")
    git(worktree, "add", "escape-link")
    git(worktree, "commit", "-m", "unsafe symlink")
    with pytest.raises(SupervisorError) as captured:
        supervisor.submit(attempt["id"], attempt["claim_token"])
    assert captured.value.code == "symlink_escape"


def test_crash_recovery_preserves_commit_and_fences_zombie(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    first = supervisor.claim(created["id"], "crashed-worker")
    checkpoint_sha = commit_change(first, "alpha.txt", "checkpoint\n")
    supervisor.heartbeat(first["id"], first["claim_token"], {"phase": "committed"})
    with supervisor.connect() as connection:
        connection.execute("UPDATE attempts SET lease_expires_at = 0 WHERE id = ?", (first["id"],))
        connection.execute(
            "UPDATE resource_leases SET lease_expires_at = 0 WHERE attempt_id = ?",
            (first["id"],),
        )
    report = supervisor.reap_expired()
    assert created["id"] in report["orphaned"]
    replacement = supervisor.claim(created["id"], "replacement")
    assert replacement["start_sha"] == checkpoint_sha
    assert replacement["claim_token"] > first["claim_token"]
    with pytest.raises(SupervisorError) as captured:
        supervisor.submit(first["id"], first["claim_token"])
    assert captured.value.code == "claim_inactive"


def test_qc_uses_real_commit_and_failure_cannot_pass(repo: Path) -> None:
    write_config(repo, [python_command("raise SystemExit(7)")])
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "bad\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    review = supervisor.run_qc(submission["id"], "independent-qc")
    assert review["verdict"] == "block"
    assert review["commit_sha"] == submission["commit_sha"]
    assert review["command_results"][0]["exit_code"] == 7
    assert supervisor.task(created["id"])["status"] == "blocked"


def test_qc_command_that_mutates_candidate_cannot_pass(repo: Path) -> None:
    write_config(
        repo,
        [python_command('from pathlib import Path; Path("alpha.txt").write_text("cheat")')],
    )
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    review = supervisor.run_qc(submission["id"], "independent-qc")
    assert review["verdict"] == "revise"
    assert "mutated the candidate" in review["findings"][0]["finding"]


def test_builtin_independent_critic_runs_as_separate_process(repo: Path) -> None:
    write_config(
        repo,
        critic_command="builtin",
        require_critic=True,
    )
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    review = supervisor.run_qc(submission["id"], "independent-qc")
    assert review["verdict"] == "human_required"
    assert {item["status"] for item in review["acceptance_coverage"]} == {"human_required"}
    assert len(review["command_results"]) == 2
    assert review["command_results"][-1]["command"] == "builtin:structural-critic"


def test_qc_acceptance_coverage_is_visible_and_signed(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])

    review = supervisor.run_qc(submission["id"], "independent-qc")

    assert review["verdict"] == "pass"
    assert review["acceptance_coverage_contract_version"] == 2
    assert len(review["acceptance_coverage"]) == 2
    assert {item["status"] for item in review["acceptance_coverage"]} == {"pass"}
    assert all(item["evidence_refs"] for item in review["acceptance_coverage"])
    bundle = supervisor.reproduction_bundle(review["id"])
    assert bundle["signature_valid"] is True
    assert bundle["bundle"]["acceptance_coverage"] == review["acceptance_coverage"]
    assert bundle["bundle"]["acceptance_coverage_contract_version"] == 2


def test_qc_records_deleted_changed_paths_as_evidence(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    (Path(attempt["worktree"]) / "alpha.txt").unlink()
    git(Path(attempt["worktree"]), "add", "-A")
    git(Path(attempt["worktree"]), "commit", "-m", "remove alpha")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])

    review = supervisor.run_qc(submission["id"], "independent-qc")

    assert review["verdict"] == "pass"
    packet_path = supervisor.state_dir / "logs" / f"review-{submission['id']}-{review['id']}.json"
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    deletion = next(item for item in packet["evidence_catalog"] if item["kind"] == "deleted_path")
    assert deletion["path"] == "alpha.txt"
    assert deletion["commit_sha"] == submission["commit_sha"]
    assert deletion["previous_git_object_oid"]


def test_pass_verdict_cannot_override_unknown_criterion_coverage(repo: Path) -> None:
    trust_root = repo.parent / f"unknown-coverage-trust-{repo.name}"
    source = repo.parent / f"unknown-coverage-source-{repo.name}"
    script = passing_critic_script().replace("'status': 'pass'", "'status': 'unknown'")
    install_test_bundle(source, trust_root, "v1", "unknown criterion disposition", script)
    write_config(repo, critic_command="trusted:critic", require_critic=True)
    configure_trust(repo, trust_root)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])

    review = supervisor.run_qc(submission["id"], "independent-qc")

    assert review["verdict"] == "human_required"
    assert {item["status"] for item in review["acceptance_coverage"]} == {"unknown"}
    assert supervisor.task(created["id"])["status"] == "blocked"


def test_critic_packet_mutation_is_blocked_and_original_is_restored(repo: Path) -> None:
    trust_root = repo.parent / f"packet-mutation-trust-{repo.name}"
    source = repo.parent / f"packet-mutation-source-{repo.name}"
    script = passing_critic_script().replace(
        "evidence_id = packet['evidence_catalog'][0]['id']\n",
        "evidence_id = packet['evidence_catalog'][0]['id']\n"
        "packet_path = Path(os.environ['ACP_REVIEW_PACKET_ARCHIVE'])\n"
        "packet_path.unlink()\n"
        "packet_path.mkdir()\n"
        "(packet_path / 'tampered').write_text('altered')\n",
        1,
    )
    install_test_bundle(source, trust_root, "v1", "mutates review packet", script)
    write_config(repo, critic_command="trusted:critic", require_critic=True)
    configure_trust(repo, trust_root)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])

    review = supervisor.run_qc(submission["id"], "independent-qc")

    packet_path = supervisor.state_dir / "logs" / f"review-{submission['id']}-{review['id']}.json"
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    bundle = supervisor.reproduction_bundle(review["id"])
    packet_hash = hashlib.sha256(packet_path.read_bytes()).hexdigest()
    assert review["verdict"] == "block"
    assert review["acceptance_coverage"]
    assert "modified or removed" in review["findings"][0]["finding"]
    assert packet["task"]["acceptance_criteria"]
    assert packet_hash == review["review_packet_sha256"]
    assert bundle["bundle"]["packet_sha256"] == packet_hash
    quarantined = list(packet_path.parent.glob(f"{packet_path.name}.tampered-*"))
    assert len(quarantined) == 1
    assert (quarantined[0] / "tampered").read_text(encoding="utf-8") == "altered"


def test_missing_independent_critic_is_explicitly_unassessed(repo: Path) -> None:
    write_config(repo, critic_command="")
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])

    review = supervisor.run_qc(submission["id"], "independent-qc")

    assert review["verdict"] == "human_required"
    assert {item["status"] for item in review["acceptance_coverage"]} == {"unknown"}
    assert "not assessed" in review["findings"][0]["finding"]
    assert supervisor.task(created["id"])["status"] == "blocked"


def test_malformed_acceptance_coverage_fails_closed(repo: Path) -> None:
    trust_root = repo.parent / f"malformed-coverage-trust-{repo.name}"
    source = repo.parent / f"malformed-coverage-source-{repo.name}"
    script = passing_critic_script().replace(
        "Path(os.environ['ACP_REVIEW_RESULT']).write_text(json.dumps({",
        "coverage[1]['criterion_id'] = coverage[0]['criterion_id']\n"
        "Path(os.environ['ACP_REVIEW_RESULT']).write_text(json.dumps({",
        1,
    )
    install_test_bundle(source, trust_root, "v1", "duplicate acceptance ID", script)
    write_config(repo, critic_command="trusted:critic", require_critic=True)
    configure_trust(repo, trust_root)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])

    review = supervisor.run_qc(submission["id"], "independent-qc")

    assert review["verdict"] == "block"
    assert {item["status"] for item in review["acceptance_coverage"]} == {"unknown"}
    assert any(
        "duplicate acceptance criterion ID" in item["evidence"] for item in review["findings"]
    )
    assert supervisor.task(created["id"])["status"] == "blocked"


def test_candidate_cannot_shadow_builtin_critic(repo: Path) -> None:
    write_config(repo, critic_command="builtin", require_critic=True)
    supervisor = GitSupervisor(repo)
    created = supervisor.create_task(
        "critic shadow",
        "Candidate package must not become the reviewer.",
        ["trusted critic runs"],
        ["owned.txt", "agent_control_plane/**"],
    )
    attempt = supervisor.claim(created["id"], "worker")
    worktree = Path(attempt["worktree"])
    (worktree / "owned.txt").write_text("candidate\n", encoding="utf-8")
    fake = worktree / "agent_control_plane"
    fake.mkdir()
    (fake / "__init__.py").write_text("", encoding="utf-8")
    (fake / "critic.py").write_text(
        "from pathlib import Path\n"
        "Path('.HIJACKED').write_text('yes')\n"
        "import json, os\n"
        "Path(os.environ['ACP_REVIEW_RESULT']).write_text("
        "json.dumps({'verdict':'pass','findings':[]}))\n",
        encoding="utf-8",
    )
    git(worktree, "add", ".")
    git(worktree, "commit", "-m", "try to shadow critic")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    review = supervisor.run_qc(submission["id"], "independent-qc")
    assert review["command_results"][-1]["command"] == "builtin:structural-critic"
    assert not (worktree / ".HIJACKED").exists()


def test_empty_gate_configuration_fails_closed(repo: Path) -> None:
    write_config(repo, [], [])
    with pytest.raises(SupervisorError) as captured:
        GitSupervisor(repo)
    assert captured.value.code == "invalid_config"


@pytest.mark.parametrize(
    ("qc_commands", "integration_commands"),
    [(["   "], [python_command("pass")]), ([python_command("pass")], ["\t"])],
)
def test_whitespace_gate_configuration_fails_closed(
    repo: Path,
    qc_commands: list[str],
    integration_commands: list[str],
) -> None:
    write_config(repo, qc_commands, integration_commands)
    with pytest.raises(SupervisorError) as captured:
        GitSupervisor(repo)
    assert captured.value.code == "invalid_config"


def test_runtime_configuration_rejects_unsafe_names_and_blank_hooks(repo: Path) -> None:
    write_config(repo, runtime_ports={"bad-name": (41000, 41001)})
    with pytest.raises(SupervisorError) as unsafe:
        GitSupervisor(repo)
    assert unsafe.value.code == "invalid_config"

    write_config(repo, runtime_setup_commands=["   "])
    with pytest.raises(SupervisorError) as blank:
        GitSupervisor(repo)
    assert blank.value.code == "invalid_config"

    write_config(
        repo,
        runtime_ports={"APP_PORT": (41000, 41002), "TEST_PORT": (41002, 41004)},
    )
    with pytest.raises(SupervisorError) as overlap:
        GitSupervisor(repo)
    assert overlap.value.code == "invalid_config"

    write_config(repo, runtime_ports={"PATH": (41000, 41001)})
    with pytest.raises(SupervisorError) as reserved:
        GitSupervisor(repo)
    assert reserved.value.code == "invalid_config"


def test_external_critic_must_be_trusted_absolute_executable(
    repo: Path,
) -> None:
    candidate_critic = repo / "candidate-critic"
    candidate_critic.write_text(
        '#!/bin/sh\nprintf \'{"verdict":"pass","findings":[]}\' > "$ACP_REVIEW_RESULT"\n',
        encoding="utf-8",
    )
    candidate_critic.chmod(0o755)
    write_config(
        repo,
        critic_command=str(candidate_critic),
        require_critic=True,
    )
    with pytest.raises(SupervisorError) as captured:
        GitSupervisor(repo)
    assert captured.value.code == "invalid_config"

    write_config(
        repo,
        critic_command="candidate-critic",
        require_critic=True,
    )
    with pytest.raises(SupervisorError) as captured:
        GitSupervisor(repo)
    assert captured.value.code == "invalid_config"


def test_critic_must_create_fresh_unique_result(repo: Path) -> None:
    write_config(repo, critic_command="/usr/bin/true", require_critic=True)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    stale = supervisor.state_dir / "logs" / f"critic-{submission['id']}.json"
    stale.write_text('{"verdict":"pass","findings":[]}', encoding="utf-8")
    review = supervisor.run_qc(submission["id"], "independent-qc")
    assert review["verdict"] == "block"
    assert review["findings"][0]["finding"] == "QC execution failed"


def test_passed_qc_creates_gated_integration_branch(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "good\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    review = supervisor.run_qc(submission["id"], "independent-qc")
    assert review["verdict"] == "pass"
    integration = supervisor.integrate(created["id"])
    assert integration["verdict"] == "pass"
    assert integration["branch"].startswith("acp/integrate-")
    assert git(repo, "show", f"{integration['commit_sha']}:alpha.txt") == "good"
    assert git(repo, "rev-parse", "main") != integration["commit_sha"]
    assert [result["phase"] for result in integration["command_results"][:4]] == [
        "ancestry-check",
        "merge-tree",
        "commit-tree",
        "verify-commit",
    ]
    assert all(
        result["security_boundary"] == "synthetic-config+empty-exec-path+contained"
        for result in integration["command_results"][:4]
    )
    assert supervisor.task(created["id"])["status"] == "done"


def test_integration_rechecks_base_checkout_after_qc_without_touching_it(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "reviewed candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"

    private_root_change = "leave-this-user-edit-alone"
    (repo / "beta.txt").write_text(private_root_change + "\n", encoding="utf-8")
    with pytest.raises(SupervisorError) as error:
        supervisor.integrate(created["id"])

    assert error.value.code == "base_checkout_mutated"
    assert json.dumps("beta.txt") in str(error.value)
    assert private_root_change not in str(error.value)
    assert (repo / "beta.txt").read_text(encoding="utf-8") == private_root_change + "\n"
    assert supervisor.task(created["id"])["status"] == "approved"
    with supervisor.connect() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM integrations WHERE task_id = ?", (created["id"],)
            ).fetchone()[0]
            == 0
        )


def test_integration_gate_cannot_leave_a_detached_child(repo: Path) -> None:
    marker = repo / "integration-detached-child"
    daemon = (
        f"import pathlib,time; time.sleep(1); pathlib.Path({str(marker)!r}).write_text('leaked')"
    )
    root = (
        "import subprocess,sys; "
        f"subprocess.Popen([sys.executable, '-c', {daemon!r}], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL, start_new_session=True)"
    )
    write_config(repo, integration_commands=[python_command(root)])
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "good\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"

    integration = supervisor.integrate(created["id"])

    if sys.platform == "darwin":
        assert integration["verdict"] != "pass"
    else:
        assert integration["verdict"] == "pass"
    time.sleep(1.2)
    assert not marker.exists()


def test_candidate_cannot_unlock_the_task_lifecycle_guard(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    marker = repo / "guard-fd-result"
    guard = supervisor._task_operation_guard(created["id"])
    guard_fd = guard.__enter__()
    guard_open = True
    command = python_command(
        "import fcntl,pathlib,time; "
        "outcome='unlocked'; "
        f"descriptor={guard_fd}; "
        "\ntry:\n fcntl.flock(descriptor, fcntl.LOCK_UN)\n"
        "except OSError:\n outcome='closed'\n"
        f"pathlib.Path({str(marker)!r}).write_text(outcome); time.sleep(0.6)"
    )
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            running = executor.submit(
                supervisor._run_command,
                command,
                repo,
                None,
                (guard_fd,),
            )
            deadline = time.monotonic() + 3
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert marker.read_text(encoding="utf-8") == "closed"
            guard.__exit__(None, None, None)
            guard_open = False
            with (
                pytest.raises(SupervisorError) as captured,
                supervisor._task_operation_guard(created["id"], recover=True),
            ):
                pass
            assert captured.value.code == "task_operation_executor_alive"
            assert running.result(timeout=3)["exit_code"] == 0
        with supervisor._task_operation_guard(created["id"], recover=True):
            pass
    finally:
        if guard_open:
            guard.__exit__(None, None, None)


@pytest.mark.parametrize("close_stdio", [False, True])
def test_command_cannot_escape_by_terminating_its_monitor(repo: Path, close_stdio: bool) -> None:
    supervisor = GitSupervisor(repo)
    marker = repo / "monitor-escape-marker"
    escaped = (
        "import os,pathlib,time; "
        + ("[os.close(fd) for fd in (0,1,2)]; " if close_stdio else "")
        + (f"time.sleep(0.8); pathlib.Path({str(marker)!r}).write_text('escaped')")
    )
    command = f"kill -9 $PPID && exec {python_command(escaped)}"

    result = supervisor._run_process(
        ["/bin/sh", "-c", command],
        command,
        repo,
        supervisor._child_env(),
    )

    assert result["exit_code"] != 0
    time.sleep(1)
    assert not marker.exists()


def test_integration_merge_disables_detached_and_blocking_repository_hooks(repo: Path) -> None:
    marker = repo / "post-merge-hook-escaped"
    hook = repo / ".git" / "hooks" / "post-merge"
    hook.write_text(
        f"#!/bin/sh\n(sleep 1; printf leaked > {str(marker)!r}) &\nsleep 5\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)
    write_config(repo, timeout_seconds=1)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "good\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"

    started = time.monotonic()
    integration = supervisor.integrate(created["id"])

    assert integration["verdict"] == "pass"
    assert time.monotonic() - started < 3
    time.sleep(1.2)
    assert not marker.exists()


def test_integration_ignores_hostile_local_merge_driver(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (repo / ".gitattributes").write_text("alpha.txt merge=hostile\n", encoding="utf-8")
    git(repo, "add", ".gitattributes")
    git(repo, "commit", "-m", "declare hostile merge attribute")
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"
    commit_main_change(
        repo,
        updates={"alpha.txt": "main moved\n"},
        message="conflicting main change",
    )
    marker = repo / "hostile-driver-ran"
    driver = repo.parent / "hostile-merge-driver"
    driver.write_text(
        "#!/bin/sh\n"
        f"printf '%s' \"${{ACP_RUNNER_CREDENTIAL:-missing}}\" > {marker}\n"
        f"(sleep 1; printf detached >> {marker}) &\n"
        "exit 0\n",
        encoding="utf-8",
    )
    driver.chmod(0o755)
    git(repo, "config", "merge.hostile.driver", f"{driver} %O %A %B %L %P")
    monkeypatch.setenv("ACP_RUNNER_CREDENTIAL", "integration-secret")

    integration = supervisor.integrate(created["id"])

    assert integration["verdict"] == "conflict"
    time.sleep(1.2)
    assert not marker.exists()
    assert supervisor.task(created["id"])["status"] == "conflicted"


def test_isolated_merge_matches_git_tree_and_parent_semantics(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    candidate = commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"
    commit_main_change(
        repo,
        updates={"beta.txt": "main moved\n"},
        message="non-conflicting main change",
    )
    current_base = git(repo, "rev-parse", "main")
    expected_tree = git(
        repo,
        "merge-tree",
        "--write-tree",
        "--no-messages",
        current_base,
        candidate,
    )

    integration = supervisor.integrate(created["id"])

    assert integration["verdict"] == "pass"
    assert git(repo, "rev-parse", f"{integration['commit_sha']}^{{tree}}") == expected_tree
    assert git(repo, "rev-list", "--parents", "-n", "1", integration["commit_sha"]).split() == [
        integration["commit_sha"],
        current_base,
        candidate,
    ]
    assert git(repo, "show", f"{integration['commit_sha']}:alpha.txt") == "candidate"
    assert git(repo, "show", f"{integration['commit_sha']}:beta.txt") == "main moved"


def test_integration_never_executes_a_replaced_private_git(repo: Path) -> None:
    marker = repo / "replacement-git-ran"
    mutation = python_command(
        "from pathlib import Path; "
        "git_dir=Path(Path('.git').read_text().split(': ', 1)[1].strip()); "
        "binary=git_dir/'supervisor-git'; binary.chmod(0o700); "
        f"binary.write_text('#!/bin/sh\\nprintf leaked > {marker}\\n')"
    )
    write_config(repo, integration_commands=[mutation, python_command("pass")])
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"

    integration = supervisor.integrate(created["id"])

    assert integration["verdict"] == "failed"
    assert "mutated tracked source or Git controls" in integration["error"]
    assert not marker.exists()


def test_integration_never_executes_path_selected_git(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"
    marker = repo.parent / "path-git-ran"
    candidate_bin = repo.parent / "candidate-bin"
    candidate_bin.mkdir()
    wrapper = candidate_bin / "git"
    wrapper.write_text(
        f'#!/bin/sh\nprintf leaked > {marker}\nexec /usr/bin/git "$@"\n',
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    monkeypatch.setenv("PATH", f"{candidate_bin}{os.pathsep}{os.environ['PATH']}")

    integration = supervisor.integrate(created["id"])

    assert integration["verdict"] == "pass"
    assert not marker.exists()


def test_publication_intent_recovers_a_crash_after_ref_creation(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"
    published: dict[str, str] = {}
    real_publish = supervisor._publish_integration_ref

    def crash_after_publish(branch: str, commit_sha: str, operation_guard_fd: int) -> None:
        real_publish(branch, commit_sha, operation_guard_fd)
        published.update(branch=branch, commit=commit_sha)
        raise KeyboardInterrupt("simulated supervisor crash")

    monkeypatch.setattr(supervisor, "_publish_integration_ref", crash_after_publish)

    with pytest.raises(KeyboardInterrupt, match="simulated supervisor crash"):
        supervisor.integrate(created["id"])

    with supervisor.connect() as connection:
        pending = connection.execute(
            "SELECT id, branch, commit_sha, verdict FROM integrations WHERE task_id = ?",
            (created["id"],),
        ).fetchone()
    assert {key: pending[key] for key in ("branch", "commit_sha", "verdict")} == {
        "branch": published["branch"],
        "commit_sha": published["commit"],
        "verdict": "publish_pending",
    }
    assert git(repo, "rev-parse", f"refs/heads/{published['branch']}") == published["commit"]
    residue = [
        supervisor.state_dir / "worktrees" / f"integrate-{pending['id']}",
        supervisor.state_dir / "integration-git" / f"integrate-{pending['id']}",
    ]
    for path in residue:
        path.mkdir(parents=True)
        (path / "crash-residue").write_text("left behind", encoding="utf-8")

    recovered = GitSupervisor(repo)

    assert not any(path.exists() for path in residue)
    with recovered.connect() as connection:
        assert (
            connection.execute(
                "SELECT verdict FROM integrations WHERE task_id = ?", (created["id"],)
            ).fetchone()["verdict"]
            == "pass"
        )
    assert recovered.task(created["id"])["status"] == "cleanup_pending"
    recovered.reap_expired()
    assert recovered.task(created["id"])["status"] == "done"


def test_ref_publication_retains_task_and_git_locks_in_its_monitor(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    lifecycle_fds: tuple[int, ...] = ()

    def record_containment(
        arguments: list[str],
        label: str,
        cwd: Path,
        env: dict[str, str],
        **options: object,
    ) -> dict[str, object]:
        nonlocal lifecycle_fds
        lifecycle_fds = tuple(options["lifecycle_fds"])  # type: ignore[arg-type]
        return {
            "command": label,
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "timed_out": False,
        }

    monkeypatch.setattr(supervisor, "_run_process", record_containment)

    with supervisor._task_operation_guard(created["id"]) as operation_guard_fd:
        supervisor._publish_integration_ref(
            "acp/test-publication-lock", "0" * 40, operation_guard_fd
        )

    assert operation_guard_fd in lifecycle_fds
    assert len(lifecycle_fds) == 2


def test_failed_ref_cleanup_remains_durable_until_restart(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"
    real_publish = supervisor._publish_integration_ref
    real_delete = supervisor._delete_integration_ref
    published: dict[str, str] = {}
    deletion_attempts = 0

    def publish_then_report_failure(branch: str, commit_sha: str, operation_guard_fd: int) -> None:
        real_publish(branch, commit_sha, operation_guard_fd)
        published.update(branch=branch, commit=commit_sha)
        raise SupervisorError("simulated_publication_verification_failure", "verification failed")

    def fail_first_delete(branch: str, commit_sha: str | None, operation_guard_fd: int) -> None:
        nonlocal deletion_attempts
        deletion_attempts += 1
        if deletion_attempts == 1:
            raise SupervisorError("simulated_ref_delete_failure", "delete failed")
        real_delete(branch, commit_sha, operation_guard_fd)

    monkeypatch.setattr(supervisor, "_publish_integration_ref", publish_then_report_failure)
    monkeypatch.setattr(supervisor, "_delete_integration_ref", fail_first_delete)

    integration = supervisor.integrate(created["id"])

    assert integration["verdict"] == "failed"
    with supervisor.connect() as connection:
        pending = connection.execute(
            "SELECT id, branch, commit_sha, verdict FROM integrations WHERE task_id = ?",
            (created["id"],),
        ).fetchone()
    assert pending["verdict"] == "delete_pending"
    assert pending["branch"] == published["branch"]
    assert pending["commit_sha"] == published["commit"]
    assert git(repo, "rev-parse", f"refs/heads/{published['branch']}") == published["commit"]

    recovered = GitSupervisor(repo)

    with recovered.connect() as connection:
        terminal = connection.execute(
            "SELECT branch, verdict FROM integrations WHERE id = ?", (pending["id"],)
        ).fetchone()
    assert terminal["verdict"] == "failed"
    assert terminal["branch"] is None
    absent = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", f"refs/heads/{published['branch']}"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert absent.returncode != 0


def test_ref_verification_error_does_not_clear_delete_pending_evidence(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    candidate = commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    integration_id = "delete-verification-error"
    branch = "acp/delete-verification-error"
    with supervisor.connect() as connection:
        connection.execute(
            """
            INSERT INTO integrations
              (id, task_id, submission_id, branch, commit_sha, verdict,
               results_json, error, created_at)
            VALUES (?, ?, ?, ?, ?, 'delete_pending', '[]', 'cleanup pending', ?)
            """,
            (
                integration_id,
                created["id"],
                submission["id"],
                branch,
                candidate,
                "2026-08-25T00:00:00+00:00",
            ),
        )

    def fail_absence_proof(
        arguments: list[str], label: str, operation_guard_fd: int
    ) -> dict[str, object]:
        return {
            "command": label,
            "exit_code": 128 if arguments[0] == "show-ref" else 0,
            "stdout": "",
            "stderr": "verification unavailable" if arguments[0] == "show-ref" else "",
            "duration_ms": 0,
            "timed_out": False,
        }

    monkeypatch.setattr(supervisor, "_run_ref_git_contained", fail_absence_proof)

    with (
        supervisor._task_operation_guard(created["id"]) as operation_guard_fd,
        pytest.raises(SupervisorError) as captured,
    ):
        supervisor._finalize_integration_ref_deletion(
            integration_id, branch, candidate, operation_guard_fd
        )

    assert captured.value.code == "integration_ref_deletion_unverified"
    with supervisor.connect() as connection:
        pending = connection.execute(
            "SELECT branch, commit_sha, verdict FROM integrations WHERE id = ?",
            (integration_id,),
        ).fetchone()
    assert pending["verdict"] == "delete_pending"
    assert pending["branch"] == branch
    assert pending["commit_sha"] == candidate


def test_restart_recovers_a_crash_before_merge_side_effects_are_recorded(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"
    child = """
import inspect
import os
import sys

from agent_control_plane.git_supervisor import GitSupervisor

generator = GitSupervisor._isolated_integration_git.__wrapped__
source, start = inspect.getsourcelines(generator)
target = [start + offset for offset, line in enumerate(source) if line.strip() == "git_dir.chmod(0o700)"]
assert len(target) == 1

def hard_exit_after_boundary_creation(frame, event, argument):
    if (
        event == "line"
        and frame.f_code is generator.__code__
        and frame.f_lineno == target[0]
    ):
        os._exit(89)
    return hard_exit_after_boundary_creation

instance = GitSupervisor(sys.argv[1])
sys.settrace(hard_exit_after_boundary_creation)
instance.integrate(sys.argv[2])
"""

    crashed = subprocess.run(
        [sys.executable, "-c", child, str(repo), created["id"]],
        capture_output=True,
        text=True,
        check=False,
    )

    assert crashed.returncode == 89, crashed.stderr
    with supervisor.connect() as connection:
        interrupted = connection.execute(
            "SELECT id, verdict FROM integrations WHERE task_id = ?", (created["id"],)
        ).fetchone()
    assert interrupted["verdict"] == "running"
    residue = supervisor.state_dir / "integration-git" / f"integrate-{interrupted['id']}"
    assert residue.exists()

    recovered = GitSupervisor(repo)

    assert not residue.exists()
    with recovered.connect() as connection:
        assert (
            connection.execute(
                "SELECT verdict FROM integrations WHERE id = ?", (interrupted["id"],)
            ).fetchone()["verdict"]
            == "failed"
        )
    assert recovered.task(created["id"])["status"] == "cleanup_pending"


def test_restart_removes_residue_after_terminal_integration_commit(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"
    child = """
import inspect
import os
import sys

from agent_control_plane.git_supervisor import GitSupervisor

source, start = inspect.getsourcelines(GitSupervisor._integrate_locked)
target = [start + offset for offset, line in enumerate(source) if line.strip() == 'verdict = "pass"']
assert len(target) == 1

def hard_exit_after_terminal_commit(frame, event, argument):
    if (
        event == "line"
        and frame.f_code is GitSupervisor._integrate_locked.__code__
        and frame.f_lineno == target[0]
    ):
        os._exit(88)
    return hard_exit_after_terminal_commit

instance = GitSupervisor(sys.argv[1])
sys.settrace(hard_exit_after_terminal_commit)
instance.integrate(sys.argv[2])
"""

    crashed = subprocess.run(
        [sys.executable, "-c", child, str(repo), created["id"]],
        capture_output=True,
        text=True,
        check=False,
    )

    assert crashed.returncode == 88, crashed.stderr
    with supervisor.connect() as connection:
        terminal = connection.execute(
            "SELECT id, verdict FROM integrations WHERE task_id = ?", (created["id"],)
        ).fetchone()
    assert terminal["verdict"] == "pass"
    residue = supervisor.state_dir / "worktrees" / f"integrate-{terminal['id']}"
    assert residue.exists()

    GitSupervisor(repo)

    assert not residue.exists()


def test_merge_renames_setting_matches_porcelain_merge(repo: Path) -> None:
    git(repo, "config", "merge.renames", "false")
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    candidate = commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"
    commit_main_change(
        repo,
        renames=(("alpha.txt", "renamed.txt"),),
        message="rename on main",
    )
    current_base = git(repo, "rev-parse", "main")
    reference, reference_head = reference_porcelain_merge(
        repo, current_base, candidate, "renames-off"
    )

    integration = supervisor.integrate(created["id"])

    # Read the expectation off porcelain instead of hardcoding one. What `git merge`
    # does to a rename/edit with merge.renames=false moved between Git versions — it
    # conflicts on 2.50.1 and merges cleanly on 2.47.3 — and this test's name promises
    # the two AGREE, not that either produces one particular answer. Hardcoding
    # `!= 0` meant a green here read as "ACP matches porcelain" while actually saying
    # "ACP matches what porcelain did on the maintainer's Git".
    if reference.returncode:
        assert integration["verdict"] == "conflict"
    else:
        # Not a weaker branch: when both merge, the merged CONTENT has to match too,
        # which is a stronger claim than agreeing on a conflict.
        assert integration["verdict"] == "pass"
        assert reference_head is not None
        reference_tree = git(repo, "rev-parse", f"{reference_head}^{{tree}}")
        assert git(repo, "rev-parse", f"{integration['commit_sha']}^{{tree}}") == reference_tree


def test_info_attributes_union_matches_porcelain_merge(repo: Path) -> None:
    info_attributes = repo / ".git" / "info" / "attributes"
    info_attributes.write_text("alpha.txt merge=union\n", encoding="utf-8")
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    candidate = commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"
    commit_main_change(
        repo,
        updates={"alpha.txt": "main moved\n"},
        message="main content",
    )
    current_base = git(repo, "rev-parse", "main")
    reference, reference_head = reference_porcelain_merge(
        repo, current_base, candidate, "info-union"
    )
    assert reference.returncode == 0
    assert reference_head is not None
    reference_tree = git(repo, "rev-parse", f"{reference_head}^{{tree}}")

    integration = supervisor.integrate(created["id"])

    assert integration["verdict"] == "pass"
    assert git(repo, "rev-parse", f"{integration['commit_sha']}^{{tree}}") == reference_tree


def test_core_attributes_file_matches_porcelain_merge(repo: Path) -> None:
    attributes = repo / "operator-attributes"
    attributes.write_text("alpha.txt merge=union\n", encoding="utf-8")
    git(repo, "add", "operator-attributes")
    git(repo, "commit", "-m", "add operator attributes")
    git(repo, "config", "core.attributesFile", "operator-attributes")
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    candidate = commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"
    commit_main_change(
        repo,
        updates={"alpha.txt": "main moved\n"},
        message="main content",
    )
    current_base = git(repo, "rev-parse", "main")
    reference, reference_head = reference_porcelain_merge(
        repo, current_base, candidate, "core-attributes"
    )
    assert reference.returncode == 0
    assert reference_head is not None
    reference_tree = git(repo, "rev-parse", f"{reference_head}^{{tree}}")

    integration = supervisor.integrate(created["id"])

    assert integration["verdict"] == "pass"
    assert git(repo, "rev-parse", f"{integration['commit_sha']}^{{tree}}") == reference_tree


def test_integration_persists_replayable_merge_input_evidence(repo: Path) -> None:
    core_content = b"alpha.txt merge=union\n"
    info_content = b"beta.txt -text\n"
    core_attributes = repo / "operator-attributes"
    core_attributes.write_bytes(core_content)
    info_attributes = repo / ".git" / "info" / "attributes"
    info_attributes.write_bytes(info_content)
    git(repo, "config", "core.attributesFile", str(core_attributes))
    git(repo, "config", "merge.renames", "false")
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    candidate = commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"
    base_sha = git(repo, "rev-parse", "main")

    integration = supervisor.integrate(created["id"])
    recorded = next(
        result
        for result in integration["command_results"]
        if result.get("phase") == "merge-input-evidence"
    )["evidence"]
    core_attributes.write_text("changed after integration\n", encoding="utf-8")
    info_attributes.write_text("changed after integration\n", encoding="utf-8")
    git(repo, "config", "merge.renames", "true")
    with supervisor.connect() as connection:
        durable_results = json.loads(
            connection.execute(
                "SELECT results_json FROM integrations WHERE id = ?", (integration["id"],)
            ).fetchone()["results_json"]
        )
    durable = next(
        result for result in durable_results if result.get("phase") == "merge-input-evidence"
    )["evidence"]

    assert durable == recorded
    assert durable["base_sha"] == base_sha
    assert durable["candidate_sha"] == candidate
    assert durable["contract"] == "isolated-merge-input-v1"
    assert durable["core_attributes"]["content_b64"] == base64.b64encode(core_content).decode(
        "ascii"
    )
    assert durable["info_attributes"]["content_b64"] == base64.b64encode(info_content).decode(
        "ascii"
    )
    assert "merge.renames" not in durable["semantic_config"]
    assert '[merge]\n\trenames = "false"\n' in durable["semantic_config"]


@pytest.mark.parametrize("attributes_state", ["dirty", "untracked"])
def test_relative_core_attributes_ignores_live_worktree_only_bytes(
    repo: Path, attributes_state: str
) -> None:
    attributes = repo / "operator-attributes"
    if attributes_state == "dirty":
        attributes.write_text("# no merge override\n", encoding="utf-8")
        git(repo, "add", "operator-attributes")
        git(repo, "commit", "-m", "add baseline operator attributes")
    attributes.write_text("alpha.txt merge=union\n", encoding="utf-8")
    git(repo, "config", "core.attributesFile", "operator-attributes")
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    candidate = commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"
    commit_main_change(
        repo,
        updates={"alpha.txt": "main moved\n"},
        message="main content",
    )
    current_base = git(repo, "rev-parse", "main")
    reference, _ = reference_porcelain_merge(
        repo, current_base, candidate, f"core-attributes-{attributes_state}"
    )
    assert reference.returncode != 0

    integration = supervisor.integrate(created["id"])

    assert integration["verdict"] == "conflict"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO regression requires POSIX")
@pytest.mark.parametrize("attribute_source", ["core", "info"])
def test_attribute_fifo_fails_closed_without_blocking(repo: Path, attribute_source: str) -> None:
    fifo = (
        repo / "attributes-fifo"
        if attribute_source == "core"
        else repo / ".git" / "info" / "attributes"
    )
    os.mkfifo(fifo)
    if attribute_source == "core":
        git(repo, "config", "core.attributesFile", str(fifo))
    child = """
import sys
from pathlib import Path

from agent_control_plane.git_supervisor import GitSupervisor, SupervisorError

instance = GitSupervisor(sys.argv[1])
try:
    if sys.argv[2] == "core":
        instance._read_core_attributes_file(instance._git_text("rev-parse", "HEAD"))
    else:
        common = Path(instance._git_text("rev-parse", "--path-format=absolute", "--git-common-dir"))
        instance._read_integration_info_attributes(common)
except SupervisorError as error:
    print(error.code)
    raise SystemExit(0)
raise SystemExit(3)
"""

    result = subprocess.run(
        [sys.executable, "-c", child, str(repo), attribute_source],
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "unsafe_git_attributes"


def test_oversized_tracked_core_attributes_is_rejected_before_blob_read(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attributes = repo / "operator-attributes"
    attributes.write_bytes(b"#" + b"x" * (1024 * 1024))
    git(repo, "add", "operator-attributes")
    git(repo, "commit", "-m", "add oversized operator attributes")
    git(repo, "config", "core.attributesFile", "operator-attributes")
    supervisor = GitSupervisor(repo)
    blob_read = False

    def fail_blob_read(*arguments: str, **keywords: object) -> bytes:
        nonlocal blob_read
        blob_read = True
        pytest.fail("oversized attribute blob was materialized")

    monkeypatch.setattr(supervisor, "_git_bytes", fail_blob_read)

    with pytest.raises(SupervisorError) as captured:
        supervisor._read_core_attributes_file(git(repo, "rev-parse", "HEAD"))

    assert captured.value.code == "unsafe_git_attributes"
    assert not blob_read


def test_unreadable_linux_child_snapshot_is_not_treated_as_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshots: list[list[int] | None] = [None, []]
    monkeypatch.setattr(worker_trampoline, "_linux_children", lambda: snapshots.pop(0))
    monkeypatch.setattr(worker_trampoline.time, "sleep", lambda _seconds: None)

    worker_trampoline._kill_adopted_processes()

    assert snapshots == []


def test_replace_refs_cannot_change_reviewed_submission_content(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    candidate = commit_change(attempt, "alpha.txt", "reviewed candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"
    replacement = commit_change(attempt, "alpha.txt", "replacement content\n", "replacement")
    git(repo, "replace", candidate, replacement)

    integration = supervisor.integrate(created["id"])

    assert integration["verdict"] == "pass"
    assert git(repo, "show", f"{integration['commit_sha']}:alpha.txt") == "reviewed candidate"


def test_graft_metadata_fails_closed_before_integration(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"
    (repo / ".git" / "info" / "grafts").write_text(
        f"{submission['commit_sha']}\n", encoding="utf-8"
    )

    with pytest.raises(SupervisorError) as captured:
        supervisor.integrate(created["id"])

    assert captured.value.code == "git_grafts_unsupported"
    assert supervisor.task(created["id"])["status"] == "approved"


def test_child_git_contract_cannot_be_overridden(repo: Path) -> None:
    supervisor = GitSupervisor(repo)

    environment = supervisor._child_env({"GIT_NO_REPLACE_OBJECTS": "0", "GIT_ATTR_NOSYSTEM": "0"})

    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert environment["GIT_ATTR_NOSYSTEM"] == "1"
    assert supervisor._supervisor_git_env()["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert supervisor._supervisor_git_env()["GIT_ATTR_NOSYSTEM"] == "1"


def test_pre_contract_approval_migrates_to_a_resubmittable_state(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE submissions SET object_contract = '' WHERE id = ?", (submission["id"],)
        )

    migrated = GitSupervisor(repo)
    assert migrated.task(created["id"])["status"] == "cleanup_pending"
    with pytest.raises(SupervisorError) as captured:
        migrated.integrate(created["id"])

    assert captured.value.code == "qc_gate_not_passed"
    replacement = migrated.claim(created["id"], "replacement-worker")
    commit_change(replacement, "alpha.txt", "replacement-free candidate\n")
    replacement_submission = migrated.submit(replacement["id"], replacement["claim_token"])
    assert replacement_submission["object_contract"] == "replacement-free-v1"
    assert migrated.run_qc(replacement_submission["id"], "independent-qc")["verdict"] == "pass"


@pytest.mark.parametrize("advance_main", [False, True])
def test_already_integrated_candidate_preserves_current_head(
    repo: Path, advance_main: bool
) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    candidate = commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"
    git(repo, "checkout", "--detach", git(repo, "rev-parse", "HEAD"))
    git(repo, "branch", "-f", "main", candidate)
    if advance_main:
        commit_main_change(
            repo,
            updates={"beta.txt": "later main\n"},
            message="advance main after candidate",
        )
    current_base = git(repo, "rev-parse", "main")

    integration = supervisor.integrate(created["id"])

    assert integration["verdict"] == "pass"
    assert integration["commit_sha"] == current_base


def test_task_resolves_head_to_stable_base_branch(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    assert created["base_branch"] == "main"


def test_expired_worker_is_never_spawned(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    marker = repo / "unsupervised-marker"
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET lease_expires_at = 0 WHERE id = ?",
            (attempt["id"],),
        )
        connection.execute(
            "UPDATE resource_leases SET lease_expires_at = 0 WHERE attempt_id = ?",
            (attempt["id"],),
        )
    command = [
        sys.executable,
        "-c",
        (
            "import pathlib,time; time.sleep(0.2); "
            f"pathlib.Path({str(marker)!r}).write_text('leaked')"
        ),
    ]
    with pytest.raises(SupervisorError) as captured:
        supervisor.run_worker(attempt["id"], attempt["claim_token"], command)
    assert captured.value.code == "lease_expired"
    time.sleep(0.4)
    assert not marker.exists()


@pytest.mark.skipif(
    sys.platform.startswith("linux"),
    reason="Darwin-specific fail-closed platform contract",
)
def test_long_running_worker_fails_closed_without_linux_subreaper(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")

    with pytest.raises(SupervisorError) as error:
        supervisor.run_worker(attempt["id"], attempt["claim_token"], ["/bin/true"])

    assert error.value.code == "process_containment_unavailable"
    assert supervisor.attempt(attempt["id"])["pid"] is None


@requires_linux_worker
def test_worker_subreaper_contains_rapid_double_fork_on_success(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    marker = repo / "double-fork-worker-leak"
    command = f"""
import os
import pathlib
import subprocess
import time

first = os.fork()
if first == 0:
    os.setsid()
    second = os.fork()
    if second > 0:
        os._exit(0)
    time.sleep(1)
    pathlib.Path({str(marker)!r}).write_text("leaked")
    os._exit(0)

pathlib.Path("alpha.txt").write_text("contained\\n")
subprocess.run(["git", "add", "alpha.txt"], check=True)
subprocess.run(["git", "commit", "-m", "contained worker"], check=True)
"""

    submission = supervisor.run_worker(
        attempt["id"], attempt["claim_token"], [sys.executable, "-c", command]
    )

    assert submission["status"] == "pending_qc"
    time.sleep(1.2)
    assert not marker.exists()


@requires_linux_worker
def test_registration_failure_terminates_spawned_worker(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    marker = repo / "registration-leak"
    original_popen = subprocess.Popen

    def spawn_then_expire(*arguments, **keywords):
        process = original_popen(*arguments, **keywords)
        if arguments[0][0] == sys.executable:
            with supervisor.connect() as connection:
                connection.execute(
                    "UPDATE attempts SET lease_expires_at = 0 WHERE id = ?",
                    (attempt["id"],),
                )
            time.sleep(0.25)
        return process

    monkeypatch.setattr(
        "agent_control_plane.git_supervisor.subprocess.Popen",
        spawn_then_expire,
    )
    command = [
        sys.executable,
        "-c",
        f"import pathlib; pathlib.Path({str(marker)!r}).write_text('leaked')",
    ]
    with pytest.raises(SupervisorError) as captured:
        supervisor.run_worker(attempt["id"], attempt["claim_token"], command)
    assert captured.value.code == "lease_expired"
    time.sleep(0.6)
    assert not marker.exists()


@requires_linux_worker
def test_pipe_failure_does_not_leave_launch_reservation(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    with monkeypatch.context() as patch:
        patch.setattr(
            "agent_control_plane.git_supervisor.os.pipe",
            lambda: (_ for _ in ()).throw(OSError("injected pipe failure")),
        )
        with pytest.raises(OSError, match="injected pipe failure"):
            supervisor.run_worker(
                attempt["id"],
                attempt["claim_token"],
                [sys.executable, "-c", "raise SystemExit(0)"],
            )
    assert supervisor.attempt(attempt["id"])["pid"] is None
    command = [
        "/bin/sh",
        "-lc",
        ("printf 'recovered\\n' > alpha.txt && git add alpha.txt && git commit -m recovered"),
    ]
    submission = supervisor.run_worker(attempt["id"], attempt["claim_token"], command)
    assert submission["status"] == "pending_qc"


@pytest.mark.parametrize("_round", range(5))
@requires_linux_worker
def test_duplicate_run_starts_exactly_one_process(repo: Path, _round: int) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    barrier = Barrier(2)
    markers = [repo / "run-one", repo / "run-two"]

    def launch(index: int) -> str:
        barrier.wait()
        command = [
            sys.executable,
            "-c",
            (
                "import pathlib,time; time.sleep(0.5); "
                f"pathlib.Path({str(markers[index])!r}).write_text('ran')"
            ),
        ]
        try:
            supervisor.run_worker(attempt["id"], attempt["claim_token"], command)
            return "submitted"
        except SupervisorError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(launch, range(2)))
    assert outcomes.count("worker_already_running") == 1
    assert sum(marker.exists() for marker in markers) == 1


@requires_linux_worker
def test_run_reservation_remains_held_until_submit(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    submit_entered = Event()
    allow_submit = Event()
    original_submit = supervisor._submit

    def delayed_submit(
        attempt_id: str,
        claim_token: int,
        expected_worker_pid: int | None,
        credential: str | None,
    ) -> dict:
        submit_entered.set()
        assert allow_submit.wait(timeout=5)
        return original_submit(attempt_id, claim_token, expected_worker_pid, credential)

    monkeypatch.setattr(supervisor, "_submit", delayed_submit)
    command = [
        "/bin/sh",
        "-lc",
        ("printf 'worker\\n' > alpha.txt && git add alpha.txt && git commit -m worker"),
    ]
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(
            supervisor.run_worker,
            attempt["id"],
            attempt["claim_token"],
            command,
        )
        assert submit_entered.wait(timeout=5)
        with pytest.raises(SupervisorError) as captured:
            supervisor.run_worker(
                attempt["id"],
                attempt["claim_token"],
                [sys.executable, "-c", "raise SystemExit(0)"],
            )
        assert captured.value.code == "worker_already_running"
        allow_submit.set()
        submission = first.result(timeout=5)
    assert submission["status"] == "pending_qc"


@requires_linux_worker
def test_manual_submit_cannot_consume_running_worker(
    repo: Path,
) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    # This is process-coordination state, not repository source; keep it under
    # ACP's administrative directory so the base-checkout fence ignores it.
    ready = repo / ".acp" / "worker-ready"
    command = [
        "/bin/sh",
        "-lc",
        (
            "printf 'worker\\n' > alpha.txt && "
            "git add alpha.txt && git commit -m worker && "
            f"touch {ready} && sleep 1"
        ),
    ]
    with ThreadPoolExecutor(max_workers=1) as pool:
        running = pool.submit(
            supervisor.run_worker,
            attempt["id"],
            attempt["claim_token"],
            command,
        )
        deadline = time.time() + 5
        while not ready.exists() and time.time() < deadline:
            time.sleep(0.02)
        assert ready.exists()
        registered_pid = supervisor.attempt(attempt["id"])["pid"]
        assert registered_pid and registered_pid > 0
        with pytest.raises(SupervisorError) as captured:
            supervisor.submit(attempt["id"], attempt["claim_token"])
        assert captured.value.code == "worker_still_running"
        assert supervisor.attempt(attempt["id"])["pid"] == registered_pid
        submission = running.result(timeout=5)
    assert submission["status"] == "pending_qc"


def test_timed_out_qc_kills_detached_child(repo: Path) -> None:
    marker = repo / "timeout-child"
    child = (
        "import subprocess,time; "
        f"subprocess.Popen(['sh','-c','sleep 2; echo leaked > {marker}'], "
        "start_new_session=True); time.sleep(5)"
    )
    command = f"{sys.executable} -c {json.dumps(child)}"
    write_config(repo, [command], timeout_seconds=1)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    review = supervisor.run_qc(submission["id"], "independent-qc")
    assert review["verdict"] == "block"
    if sys.platform == "darwin":
        assert review["command_results"][0]["exit_code"] != 0
        assert "Operation not permitted" in review["command_results"][0]["stderr"]
    else:
        assert review["command_results"][0]["exit_code"] == 124
    time.sleep(2.2)
    assert not marker.exists()


def test_successful_qc_kills_detached_child(repo: Path) -> None:
    marker = repo / "successful-qc-child"
    daemon = (
        f"import pathlib,time; time.sleep(1); pathlib.Path({str(marker)!r}).write_text('leaked')"
    )
    root = (
        "import subprocess,sys; "
        f"subprocess.Popen([sys.executable, '-c', {daemon!r}], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL, start_new_session=True)"
    )
    write_config(repo, [python_command(root)], timeout_seconds=5)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])

    review = supervisor.run_qc(submission["id"], "independent-qc")

    if sys.platform == "darwin":
        # Current Darwin has no supported recursive process tracking primitive.
        # The kernel sandbox therefore denies fork and fails the review closed.
        assert review["verdict"] == "block"
        assert review["command_results"][0]["exit_code"] != 0
    else:
        assert review["verdict"] == "pass"
        assert review["command_results"][0]["exit_code"] == 0
    time.sleep(1.2)
    assert not marker.exists()


def test_trusted_external_critic_cannot_leave_a_detached_child(repo: Path) -> None:
    marker = repo / "critic-detached-child"
    trust_root = repo.parent / "critic-containment-trust"
    source = repo.parent / "critic-containment-source"
    detached_command = f"/bin/sleep 1; /usr/bin/touch {shlex.quote(str(marker))}"
    script = passing_critic_script().replace(
        "\nimport json, os\n",
        "\nimport json, os, subprocess\n"
        f"subprocess.Popen(['/bin/sh', '-c', {detached_command!r}], "
        "start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n",
        1,
    )
    install_test_bundle(source, trust_root, "v1", "daemon critic", script)
    configure_trust(repo, trust_root)
    require_trusted_critic(repo)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])

    review = supervisor.run_qc(submission["id"], "independent-qc")

    if sys.platform == "darwin":
        assert review["verdict"] != "pass", "Darwin must deny critic forks"
    else:
        diagnostic = {
            "verdict": review.get("verdict"),
            "findings": review.get("findings"),
            "acceptance_coverage": review.get("acceptance_coverage"),
            "command_results": [
                {
                    key: value[:2_000] if isinstance(value, str) else value
                    for key, value in result.items()
                    if key in {"command", "exit_code", "stdout", "stderr"}
                }
                for result in review.get("command_results", [])
            ],
        }
        assert review["verdict"] == "pass", json.dumps(diagnostic, indent=2)
    time.sleep(1.2)
    assert not marker.exists()


def test_timed_out_external_critic_cannot_leave_a_detached_child(repo: Path) -> None:
    marker = repo / "critic-timeout-child"
    trust_root = repo.parent / "critic-timeout-trust"
    source = repo.parent / "critic-timeout-source"
    script = (
        "#!/bin/sh\n"
        f"(/bin/sleep 2; /usr/bin/touch '{marker}') >/dev/null 2>&1 &\n"
        "/bin/sleep 5\n"
        'printf \'{"verdict":"pass","findings":[]}\' > "$ACP_REVIEW_RESULT"\n'
    )
    write_config(repo, timeout_seconds=1)
    install_test_bundle(source, trust_root, "v1", "timeout critic", script)
    configure_trust(repo, trust_root)
    require_trusted_critic(repo)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])

    review = supervisor.run_qc(submission["id"], "independent-qc")

    assert review["verdict"] != "pass"
    time.sleep(2.2)
    assert not marker.exists()


def test_expired_approval_cannot_integrate(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "approved\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE resource_leases SET lease_expires_at = 0 WHERE task_id = ?",
            (created["id"],),
        )
    with pytest.raises(SupervisorError) as captured:
        supervisor.integrate(created["id"])
    assert captured.value.code == "reservation_lost"


def test_merge_conflict_blocks_integration(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"
    commit_main_change(
        repo,
        updates={"alpha.txt": "main moved\n"},
        message="conflicting main change",
    )
    integration = supervisor.integrate(created["id"])
    assert integration["verdict"] == "conflict"
    assert supervisor.task(created["id"])["status"] == "conflicted"


def test_expiry_during_integration_deletes_branch_and_records_stale(
    repo: Path,
) -> None:
    write_config(
        repo,
        integration_commands=[python_command("import time; time.sleep(0.8)")],
    )
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(supervisor.integrate, created["id"])
        deadline = time.time() + 5
        while supervisor.task(created["id"])["status"] != "integrating" and time.time() < deadline:
            time.sleep(0.02)
        with supervisor.connect() as connection:
            connection.execute(
                "UPDATE resource_leases SET lease_expires_at = 0 WHERE task_id = ?",
                (created["id"],),
            )
        reaped = supervisor.reap_expired()
        assert created["id"] not in reaped["conflicted"]
        assert supervisor.task(created["id"])["status"] == "cleanup_pending"
        with supervisor.connect() as connection:
            held = connection.execute(
                "SELECT lease_expires_at FROM resource_leases WHERE task_id = ?",
                (created["id"],),
            ).fetchone()
        assert held and held["lease_expires_at"] == CLEANUP_FENCE_EPOCH
        result = future.result(timeout=15)

    assert result["verdict"] == "stale"
    assert supervisor.task(created["id"])["status"] == "conflicted"
    assert result["branch"] is None
    assert not git(repo, "branch", "--list", "acp/integrate-*")


def test_concurrent_qc_is_rejected_before_a_second_worktree_starts(repo: Path) -> None:
    write_config(repo, qc_commands=[python_command("import time; time.sleep(0.6)")])
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(supervisor.run_qc, submission["id"], "independent-qc")
        deadline = time.time() + 5
        while time.time() < deadline:
            current = supervisor.submission(submission["id"])
            if current["status"] == "qc_running":
                break
            time.sleep(0.02)
        assert current["status"] == "qc_running"
        assert current["qc_resume_status"] == "pending_qc"
        qc_worktrees = repo / ".acp" / "worktrees"
        while len(list(qc_worktrees.glob("qc-*"))) != 1 and time.time() < deadline:
            time.sleep(0.02)
        assert len(list(qc_worktrees.glob("qc-*"))) == 1
        with pytest.raises(SupervisorError) as captured:
            supervisor.run_qc(submission["id"], "independent-qc")
        assert captured.value.code == "task_operation_in_progress"
        assert future.result(timeout=15)["verdict"] == "pass"

    with supervisor.connect() as connection:
        count = connection.execute(
            "SELECT COUNT(*) AS count FROM qc_runs WHERE submission_id = ?",
            (submission["id"],),
        ).fetchone()["count"]
    assert count == 1


def test_expired_live_qc_keeps_collision_fence_until_executor_and_runtime_end(
    repo: Path,
) -> None:
    write_config(repo, qc_commands=[python_command("import time; time.sleep(0.6)")])
    supervisor = GitSupervisor(repo)
    first = task(supervisor, "alpha.txt")
    second = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(first["id"], "worker")
    commit_change(attempt, "alpha.txt", "candidate\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(supervisor.run_qc, submission["id"], "independent-qc")
        deadline = time.time() + 5
        while supervisor.submission(submission["id"])["status"] != "qc_running":
            assert time.time() < deadline
            time.sleep(0.02)
        with supervisor.connect() as connection:
            connection.execute(
                "UPDATE resource_leases SET lease_expires_at = 0 WHERE task_id = ?",
                (first["id"],),
            )
        first_reap = supervisor.reap_expired()
        assert first_reap["conflicted"] == []
        assert supervisor.task(first["id"])["status"] == "cleanup_pending"
        with pytest.raises(SupervisorError) as captured:
            supervisor.claim(second["id"], "other-worker")
        assert captured.value.code == "resource_busy"
        with pytest.raises(SupervisorError) as qc_error:
            future.result(timeout=15)
        assert qc_error.value.code == "submission_not_reviewable"

    second_reap = supervisor.reap_expired()
    assert first["id"] in second_reap["conflicted"]
    assert supervisor.runtime_environment(attempt["id"])["state"] == "released"
    assert supervisor.claim(second["id"], "other-worker")["status"] == "working"


def test_critic_identity_and_event_chain_are_enforced(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "review me\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    with pytest.raises(SupervisorError) as captured:
        supervisor.run_qc(submission["id"], "worker")
    assert captured.value.code == "reviewer_identity_mismatch"
    assert supervisor.verify_event_chain()["ok"] is True
    with supervisor.connect() as connection:
        connection.execute("UPDATE events SET payload_json = '{}' WHERE sequence = 1")
    assert supervisor.verify_event_chain()["ok"] is False


def test_rotation_pins_old_attempt_and_qc_while_new_claim_uses_current(repo: Path) -> None:
    trust_root = repo.parent / f"trust-{repo.name}"
    source = repo.parent / f"bundle-source-{repo.name}"
    old = install_test_bundle(source, trust_root, "v1", "old")
    configure_trust(repo, trust_root)
    require_trusted_critic(repo)
    supervisor = GitSupervisor(repo)
    old_task = task(supervisor, "alpha.txt", "old bundle task")
    new_task = task(supervisor, "beta.txt", "new bundle task")
    old_attempt = supervisor.claim(old_task["id"], "worker-old")

    new = install_test_bundle(source, trust_root, "v2", "new")
    new_attempt = supervisor.claim(new_task["id"], "worker-new")

    assert old_attempt["trust_bundle"]["bundle_id"] == old["bundle_id"]
    assert new_attempt["trust_bundle"]["bundle_id"] == new["bundle_id"]
    assert verify_bundle_pin(old)["ok"] is True
    commit_change(old_attempt, "alpha.txt", "old remains pinned\n")
    submission = supervisor.submit(old_attempt["id"], old_attempt["claim_token"])
    review = supervisor.run_qc(submission["id"], "independent-qc")
    assert review["trust_bundle"]["bundle_id"] == old["bundle_id"]
    assert review["reviewer_provenance"]["command"] == "trusted:critic"


def test_missing_old_pin_quarantines_instead_of_switching_to_current(repo: Path) -> None:
    trust_root = repo.parent / f"trust-{repo.name}"
    source = repo.parent / f"bundle-source-{repo.name}"
    old = install_test_bundle(source, trust_root, "v1", "old")
    configure_trust(repo, trust_root)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    new = install_test_bundle(source, trust_root, "v2", "new")
    old_directory = trust_root / "bundles" / old["bundle_id"]
    old_directory.rename(trust_root / "bundles" / f"gone-{old['bundle_id']}")

    with pytest.raises(SupervisorError) as error:
        supervisor.runtime_restart(attempt["id"])

    assert error.value.code == "trust_bundle_quarantined"
    quarantined = supervisor.attempt(attempt["id"])
    assert quarantined["status"] == "quarantined"
    assert supervisor.task(created["id"])["status"] == "cleanup_pending"
    assert supervisor.task(created["id"])["cleanup_target_status"] == "blocked"
    assert quarantined["trust_bundle"]["bundle_id"] != new["bundle_id"]
    doctor = supervisor.doctor()
    failed = [check for check in doctor["checks"] if check["name"].startswith("trust_pinned:")]
    assert failed and any(not check["ok"] for check in failed)
    assert any("missing" in error for check in failed for error in check["detail"]["errors"])

    current_directory = trust_root / "bundles" / new["bundle_id"]
    current_driver = current_directory / "critic"
    current_directory.chmod(0o755)
    current_driver.chmod(0o777)
    current_driver.write_text("tampered", encoding="utf-8")
    diagnostic = GitSupervisor(repo, diagnostic=True).doctor()
    current_check = next(
        check for check in diagnostic["checks"] if check["name"] == "trust_current"
    )
    joined = "\n".join(current_check["detail"]["errors"])
    assert current_check["ok"] is False
    assert "group/world-writable" in joined
    assert "digest mismatch" in joined
    assert "size mismatch" in joined


def test_trust_loss_on_heartbeat_retains_worker_identity_until_termination_proof(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trust_root = repo.parent / f"trust-{repo.name}"
    source = repo.parent / f"bundle-source-{repo.name}"
    pin = install_test_bundle(source, trust_root, "v1", "old")
    configure_trust(repo, trust_root)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt", "fenced worker")
    colliding = task(supervisor, "alpha.txt", "collision")
    attempt = supervisor.claim(created["id"], "worker")
    identity = "linux:424242:1"
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET pid = 424242, pid_identity = ? WHERE id = ?",
            (identity, attempt["id"]),
        )

    bundle = trust_root / "bundles" / pin["bundle_id"]
    gone_bundle = bundle.with_name(f"gone-{pin['bundle_id']}")
    bundle.rename(gone_bundle)
    with pytest.raises(SupervisorError) as error:
        supervisor.heartbeat(attempt["id"], attempt["claim_token"])

    assert error.value.code == "trust_bundle_quarantined"
    fenced = supervisor.attempt(attempt["id"])
    assert fenced["status"] == "terminating"
    assert fenced["termination_target_status"] == "quarantined"
    assert fenced["pid"] == 424242
    assert fenced["pid_identity"] == identity
    task_state = supervisor.task(created["id"])
    assert task_state["status"] == "cleanup_pending"
    assert task_state["cleanup_target_status"] == "blocked"
    assert "trust bundle invalid" in task_state["cleanup_error"]
    entry = next(item for item in supervisor.status()["tasks"] if item["task_id"] == created["id"])
    assert entry["worker"]["status"] == "terminating"
    assert entry["worker"]["pid"] == 424242
    assert entry["worker"]["pid_identity"] == identity
    assert "last error: trust bundle invalid" in entry["reason"]

    monkeypatch.setattr(supervisor, "_terminate_registered_group", lambda *_: "failed")
    failed = supervisor.reap_expired()
    assert failed["terminated_workers"][0]["termination"] == "failed"
    retained = supervisor.attempt(attempt["id"])
    assert retained["status"] == "terminating"
    assert retained["pid"] == 424242
    install_test_bundle(source, trust_root, "v2", "replacement")
    with pytest.raises(SupervisorError) as collision:
        supervisor.claim(colliding["id"], "other-worker")
    assert collision.value.code == "resource_busy"

    restarted = GitSupervisor(repo)
    monkeypatch.setattr(restarted, "_terminate_registered_group", lambda *_: "identity-gone")
    recovered = restarted.reap_expired()

    assert recovered["terminated_workers"][0]["termination"] == "identity-gone"
    retained_after_death = restarted.attempt(attempt["id"])
    assert retained_after_death["status"] == "terminating"
    assert retained_after_death["termination_target_status"] == "quarantined"
    assert retained_after_death["termination_proof"] == "identity-gone"
    assert retained_after_death["pid"] == 424242
    assert retained_after_death["pid_identity"] == identity
    assert restarted.task(created["id"])["status"] == "cleanup_pending"
    with pytest.raises(SupervisorError) as still_fenced:
        restarted.claim(colliding["id"], "other-worker")
    assert still_fenced.value.code == "resource_busy"

    gone_bundle.rename(bundle)
    finalized = restarted.reap_expired()

    assert finalized["terminated_workers"] == []
    quarantined = restarted.attempt(attempt["id"])
    assert quarantined["status"] == "quarantined"
    assert quarantined["termination_target_status"] == ""
    assert quarantined["termination_proof"] == ""
    assert quarantined["pid"] is None
    assert quarantined["pid_identity"] == ""
    assert restarted.task(created["id"])["status"] == "blocked"
    replacement = restarted.claim(colliding["id"], "other-worker")
    assert replacement["status"] == "working"


def test_submit_revalidates_trust_and_commits_quarantine_before_rejection(repo: Path) -> None:
    trust_root = repo.parent / f"trust-{repo.name}"
    source = repo.parent / f"bundle-source-{repo.name}"
    pin = install_test_bundle(source, trust_root, "v1", "old")
    configure_trust(repo, trust_root)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "completed before trust loss\n")
    identity = "linux:424242:1"
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET pid = 424242, pid_identity = ? WHERE id = ?",
            (identity, attempt["id"]),
        )

    bundle = trust_root / "bundles" / pin["bundle_id"]
    bundle.rename(bundle.with_name(f"gone-{pin['bundle_id']}"))
    with pytest.raises(SupervisorError) as error:
        supervisor._submit(
            attempt["id"],
            attempt["claim_token"],
            expected_worker_pid=424242,
            credential=None,
        )

    assert error.value.code == "trust_bundle_quarantined"
    fenced = supervisor.attempt(attempt["id"])
    assert fenced["status"] == "terminating"
    assert fenced["termination_target_status"] == "quarantined"
    assert fenced["pid"] == 424242
    assert fenced["pid_identity"] == identity
    assert supervisor.task(created["id"])["status"] == "cleanup_pending"
    with supervisor.connect() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM submissions WHERE attempt_id = ?", (attempt["id"],)
            ).fetchone()[0]
            == 0
        )


def test_launch_reservation_recovers_only_after_recorded_owner_is_gone(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trust_root = repo.parent / f"trust-{repo.name}"
    source = repo.parent / f"bundle-source-{repo.name}"
    pin = install_test_bundle(source, trust_root, "v1", "old")
    configure_trust(repo, trust_root)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    colliding = task(supervisor, "alpha.txt", "collision")
    attempt = supervisor.claim(created["id"], "worker")
    owner_pid = 31337
    owner_identity = "linux:31337:9"
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET pid = -1, launch_owner_pid = ?, "
            "launch_owner_identity = ? WHERE id = ?",
            (owner_pid, owner_identity, attempt["id"]),
        )

    bundle = trust_root / "bundles" / pin["bundle_id"]
    bundle.rename(bundle.with_name(f"gone-{pin['bundle_id']}"))
    with pytest.raises(SupervisorError):
        supervisor.heartbeat(attempt["id"], attempt["claim_token"])
    install_test_bundle(source, trust_root, "v2", "replacement")
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE runtime_environments SET state = 'released' WHERE attempt_id = ?",
            (attempt["id"],),
        )

    monkeypatch.setattr(
        supervisor,
        "_process_identity",
        lambda pid: owner_identity if pid == owner_pid else None,
    )
    unresolved = supervisor.reap_expired()

    assert any(
        item["state"] == "cleanup_error" and "launch owner is still active" in item["error"]
        for item in unresolved["runtime_cleanup"]
    )
    retained = supervisor.attempt(attempt["id"])
    assert retained["status"] == "terminating"
    assert retained["termination_target_status"] == "quarantined"
    assert retained["termination_proof"] == ""
    assert retained["pid"] == -1
    assert retained["launch_owner_pid"] == owner_pid
    assert retained["launch_owner_identity"] == owner_identity
    assert supervisor.task(created["id"])["status"] == "cleanup_pending"
    assert retained["resource_leases"][0]["lease_expires_at"] == CLEANUP_FENCE_EPOCH
    with pytest.raises(SupervisorError) as collision:
        supervisor.claim(colliding["id"], "other-worker")
    assert collision.value.code == "resource_busy"

    restarted = GitSupervisor(repo)
    monkeypatch.setattr(restarted, "_process_identity", lambda _pid: None)
    recovered = restarted.reap_expired()

    assert any(item["state"] == "released" for item in recovered["runtime_cleanup"])
    final = restarted.attempt(attempt["id"])
    assert final["status"] == "quarantined"
    assert final["termination_target_status"] == ""
    assert final["termination_proof"] == ""
    assert final["pid"] is None
    assert final["launch_owner_pid"] is None
    assert final["launch_owner_identity"] == ""
    assert restarted.task(created["id"])["status"] == "blocked"
    replacement = restarted.claim(colliding["id"], "other-worker")
    assert replacement["status"] == "working"


@requires_linux_worker
def test_trust_loss_during_worker_launch_fences_before_candidate_execution(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trust_root = repo.parent / f"trust-{repo.name}"
    source = repo.parent / f"bundle-source-{repo.name}"
    pin = install_test_bundle(source, trust_root, "v1", "old")
    configure_trust(repo, trust_root)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    marker = repo.parent / f"worker-launch-escaped-{repo.name}"
    identity_started = Event()
    release_identity = Event()
    original_identity = supervisor._process_identity
    first_call = True

    def blocked_identity(pid: int) -> str | None:
        nonlocal first_call
        if pid != os.getpid() and first_call:
            first_call = False
            identity_started.set()
            assert release_identity.wait(timeout=5)
        return original_identity(pid)

    monkeypatch.setattr(supervisor, "_process_identity", blocked_identity)
    command = [
        sys.executable,
        "-c",
        f"import pathlib; pathlib.Path({str(marker)!r}).write_text('escaped')",
    ]
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            supervisor.run_worker,
            attempt["id"],
            attempt["claim_token"],
            command,
        )
        assert identity_started.wait(timeout=5)
        bundle = trust_root / "bundles" / pin["bundle_id"]
        bundle.rename(bundle.with_name(f"gone-{pin['bundle_id']}"))
        with pytest.raises(SupervisorError) as quarantine:
            supervisor.runtime_restart(attempt["id"])
        assert quarantine.value.code == "trust_bundle_quarantined"
        reserved = supervisor.attempt(attempt["id"])
        assert reserved["status"] == "terminating"
        assert reserved["pid"] == -1
        release_identity.set()
        with pytest.raises(SupervisorError) as worker_error:
            future.result(timeout=10)

    assert worker_error.value.code == "worker_launch_fenced"
    assert not marker.exists()
    final = supervisor.attempt(attempt["id"])
    assert final["status"] == "terminating"
    assert final["termination_target_status"] == "quarantined"
    assert final["termination_proof"] == "worker.launch_aborted"
    assert final["pid"] and final["pid"] > 0
    assert final["pid_identity"]
    assert supervisor.task(created["id"])["status"] == "cleanup_pending"


@requires_linux_worker
def test_trust_loss_after_worker_exit_blocks_submission_and_retains_proved_identity(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trust_root = repo.parent / f"trust-{repo.name}"
    source = repo.parent / f"bundle-source-{repo.name}"
    pin = install_test_bundle(source, trust_root, "v1", "old")
    configure_trust(repo, trust_root)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    worker_exited = Event()
    release_exit = Event()
    original_record_exit = supervisor._record_worker_exit

    def blocked_record_exit(attempt_id: str, pid: int, exit_code: int) -> None:
        worker_exited.set()
        assert release_exit.wait(timeout=5)
        original_record_exit(attempt_id, pid, exit_code)

    monkeypatch.setattr(supervisor, "_record_worker_exit", blocked_record_exit)
    command = [
        sys.executable,
        "-c",
        (
            "import pathlib,subprocess; "
            "pathlib.Path('alpha.txt').write_text('complete\\n'); "
            "subprocess.run(['git','add','alpha.txt'],check=True); "
            "subprocess.run(['git','commit','-m','worker complete'],check=True)"
        ),
    ]
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            supervisor.run_worker,
            attempt["id"],
            attempt["claim_token"],
            command,
        )
        assert worker_exited.wait(timeout=10)
        bundle = trust_root / "bundles" / pin["bundle_id"]
        bundle.rename(bundle.with_name(f"gone-{pin['bundle_id']}"))
        with pytest.raises(SupervisorError) as quarantine:
            supervisor.runtime_restart(attempt["id"])
        assert quarantine.value.code == "trust_bundle_quarantined"
        retained = supervisor.attempt(attempt["id"])
        assert retained["status"] == "terminating"
        assert retained["pid"] and retained["pid"] > 0
        assert retained["pid_identity"]
        release_exit.set()
        with pytest.raises(SupervisorError) as worker_error:
            future.result(timeout=10)

    assert worker_error.value.code == "claim_inactive"
    final = supervisor.attempt(attempt["id"])
    assert final["status"] == "terminating"
    assert final["termination_target_status"] == "quarantined"
    assert final["termination_proof"] == "worker.submission_failed"
    assert final["pid"] and final["pid"] > 0
    assert final["pid_identity"]
    assert supervisor.task(created["id"])["status"] == "cleanup_pending"


def test_missing_qc_trust_pin_blocks_integration_before_branch_creation(repo: Path) -> None:
    trust_root = repo.parent / f"trust-{repo.name}"
    source = repo.parent / f"bundle-source-{repo.name}"
    pin = install_test_bundle(source, trust_root, "v1", "review")
    configure_trust(repo, trust_root)
    require_trusted_critic(repo)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    colliding = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "reviewed\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"

    bundle = trust_root / "bundles" / pin["bundle_id"]
    bundle.rename(bundle.with_name(f"gone-{pin['bundle_id']}"))

    with pytest.raises(SupervisorError) as error:
        supervisor.integrate(created["id"])
    assert error.value.code == "trust_bundle_quarantined"
    fenced = supervisor.task(created["id"])
    assert fenced["status"] == "cleanup_pending"
    assert fenced["cleanup_target_status"] == "blocked"
    install_test_bundle(source, trust_root, "v2", "replacement")
    with supervisor.connect() as connection:
        lease = connection.execute(
            "SELECT lease_expires_at FROM resource_leases WHERE task_id = ?",
            (created["id"],),
        ).fetchone()
    assert lease and lease["lease_expires_at"] == CLEANUP_FENCE_EPOCH
    assert any(
        item["state"] == "cleanup_error" for item in supervisor.reap_expired()["runtime_cleanup"]
    )
    with pytest.raises(SupervisorError) as claim_error:
        supervisor.claim(colliding["id"], "other-worker")
    assert claim_error.value.code == "resource_busy"
    assert not git(repo, "branch", "--list", "acp/integrate-*")


def test_trust_pin_invalidated_during_integration_records_stale_and_deletes_branch(
    repo: Path,
) -> None:
    marker = repo.parent / f"integration-running-{repo.name}"
    integration_command = python_command(
        f"import pathlib,time; pathlib.Path({str(marker)!r}).write_text('running'); time.sleep(0.8)"
    )
    write_config(
        repo,
        integration_commands=[integration_command],
    )
    trust_root = repo.parent / f"trust-{repo.name}"
    source = repo.parent / f"bundle-source-{repo.name}"
    pin = install_test_bundle(source, trust_root, "v1", "review")
    configure_trust(repo, trust_root)
    require_trusted_critic(repo)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    colliding = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "reviewed\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(supervisor.integrate, created["id"])
        deadline = time.time() + 5
        while not marker.exists() and time.time() < deadline:
            time.sleep(0.02)
        assert marker.exists()
        bundle = trust_root / "bundles" / pin["bundle_id"]
        bundle.rename(bundle.with_name(f"gone-{pin['bundle_id']}"))
        result = future.result(timeout=15)

    assert result["verdict"] == "stale"
    assert result["branch"] is None
    assert "trust_bundle_quarantined" in result["error"]
    fenced = supervisor.task(created["id"])
    assert fenced["status"] == "cleanup_pending"
    assert fenced["cleanup_target_status"] == "blocked"
    install_test_bundle(source, trust_root, "v2", "replacement")
    with supervisor.connect() as connection:
        lease = connection.execute(
            "SELECT lease_expires_at FROM resource_leases WHERE task_id = ?",
            (created["id"],),
        ).fetchone()
    assert lease and lease["lease_expires_at"] == CLEANUP_FENCE_EPOCH
    assert any(
        item["state"] == "cleanup_error" for item in supervisor.reap_expired()["runtime_cleanup"]
    )
    with pytest.raises(SupervisorError) as claim_error:
        supervisor.claim(colliding["id"], "other-worker")
    assert claim_error.value.code == "resource_busy"
    assert not git(repo, "branch", "--list", "acp/integrate-*")


def test_trust_pin_invalidated_during_qc_cannot_record_approval(repo: Path) -> None:
    marker = repo.parent / f"qc-running-{repo.name}"
    qc_command = python_command(
        f"import pathlib,time; pathlib.Path({str(marker)!r}).write_text('running'); time.sleep(0.8)"
    )
    write_config(repo, qc_commands=[qc_command])
    trust_root = repo.parent / f"trust-{repo.name}"
    source = repo.parent / f"bundle-source-{repo.name}"
    pin = install_test_bundle(source, trust_root, "v1", "review")
    configure_trust(repo, trust_root)
    require_trusted_critic(repo)
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    colliding = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "reviewed\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(supervisor.run_qc, submission["id"], "independent-qc")
        deadline = time.time() + 5
        while not marker.exists() and time.time() < deadline:
            time.sleep(0.02)
        assert marker.exists()
        bundle = trust_root / "bundles" / pin["bundle_id"]
        bundle.rename(bundle.with_name(f"gone-{pin['bundle_id']}"))
        with pytest.raises(SupervisorError) as error:
            future.result(timeout=15)

    assert error.value.code == "trust_bundle_quarantined"
    fenced = supervisor.task(created["id"])
    assert fenced["status"] == "cleanup_pending"
    assert fenced["cleanup_target_status"] == "blocked"
    install_test_bundle(source, trust_root, "v2", "replacement")
    current_submission = supervisor.submission(submission["id"])
    assert current_submission["status"] == "blocked"
    assert current_submission["qc_resume_status"] == ""
    with supervisor.connect() as connection:
        lease = connection.execute(
            "SELECT lease_expires_at FROM resource_leases WHERE task_id = ?",
            (created["id"],),
        ).fetchone()
    assert lease and lease["lease_expires_at"] == CLEANUP_FENCE_EPOCH
    assert any(
        item["state"] == "cleanup_error" for item in supervisor.reap_expired()["runtime_cleanup"]
    )
    with pytest.raises(SupervisorError) as claim_error:
        supervisor.claim(colliding["id"], "other-worker")
    assert claim_error.value.code == "resource_busy"
    with supervisor.connect() as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM qc_runs WHERE submission_id = ?", (submission["id"],)
        ).fetchone()[0]
    assert count == 0
