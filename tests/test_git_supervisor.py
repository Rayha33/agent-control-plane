from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, Event

import pytest
from support import python_command

from agent_control_plane.git_supervisor import (
    CLEANUP_FENCE_EPOCH,
    GitSupervisor,
    SupervisorError,
)
from agent_control_plane.trust_bundles import install_bundle, verify_bundle_pin

requires_linux_worker = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="long-running worker containment requires Linux child-subreaper support",
)


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
    critic_command: str = "",
    require_critic: bool = False,
    timeout_seconds: int = 30,
    runtime_setup_commands: list[str] | None = None,
    runtime_teardown_commands: list[str] | None = None,
    runtime_ports: dict[str, tuple[int, int]] | None = None,
) -> None:
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
    (repo / "acp.toml").write_text(
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
        f"{port_lines}",
        encoding="utf-8",
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


def commit_change(attempt: dict, path: str, content: str, message: str = "implement") -> str:
    worktree = Path(attempt["worktree"])
    destination = worktree / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8")
    git(worktree, "add", path)
    git(worktree, "commit", "-m", message)
    return git(worktree, "rev-parse", "HEAD")


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
    executable.write_text(
        script
        or (
            "#!/bin/sh\n"
            f"# {message}\n"
            'printf \'{"verdict":"pass","findings":[]}\' > "$ACP_REVIEW_RESULT"\n'
        ),
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
    with (repo / "acp.toml").open("a", encoding="utf-8") as handle:
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
    assert claims[0]["worktree"] != claims[1]["worktree"]


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
    assert review["verdict"] == "pass"
    assert len(review["command_results"]) == 2
    assert review["command_results"][-1]["command"] == "builtin:structural-critic"


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
    assert review["verdict"] == "revise"
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
    assert supervisor.task(created["id"])["status"] == "done"


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


def test_integration_rejects_local_git_merge_driver(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    created = task(supervisor, "alpha.txt")
    attempt = supervisor.claim(created["id"], "worker")
    commit_change(attempt, "alpha.txt", "good\n")
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert supervisor.run_qc(submission["id"], "independent-qc")["verdict"] == "pass"
    subprocess.run(
        ["git", "-C", str(repo), "config", "merge.hostile.driver", "/usr/bin/true"],
        check=True,
    )

    integration = supervisor.integrate(created["id"])

    assert integration["verdict"] == "failed"
    assert "refuses executable Git config" in integration["error"]
    assert supervisor.task(created["id"])["status"] == "conflicted"


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

pathlib.Path("alpha.txt").write_text("contained\n")
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
    ready = repo / "worker-ready"
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
    script = (
        "#!/bin/sh\n"
        f"(/bin/sleep 1; /usr/bin/touch '{marker}') >/dev/null 2>&1 &\n"
        'printf \'{"verdict":"pass","findings":[]}\' > "$ACP_REVIEW_RESULT"\n'
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
        assert review["verdict"] == "pass"
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
    (repo / "alpha.txt").write_text("main moved\n", encoding="utf-8")
    git(repo, "add", "alpha.txt")
    git(repo, "commit", "-m", "conflicting main change")
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
