from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import agent_control_plane.git_supervisor as supervisor_module
from agent_control_plane.credential_providers import (
    CredentialDefinition,
    CredentialHandle,
    CredentialRegistry,
)
from agent_control_plane.git_supervisor import GitSupervisor, SupervisorError
from agent_control_plane.runtime_drivers import (
    BrowserProfileDriver,
    DockerComposeDriver,
    DriverContext,
    DriverDefinition,
    DriverError,
    PostgresSchemaDriver,
    build_driver,
    ownership_token,
    parse_driver_definitions,
    resolve_trusted_executable,
    run_trusted,
)


def make_executable(path: Path, body: str = "#!/bin/sh\nexit 0\n") -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


def context(
    tmp_path: Path,
    attempt_id: str = "attempt-1",
    credential_registry: CredentialRegistry | None = None,
    credential_handles: dict[str, CredentialHandle] | None = None,
) -> DriverContext:
    return DriverContext(
        attempt_id=attempt_id,
        task_id="task-1",
        runtime_dir=tmp_path / "runtime",
        expires_at=1_800_000_000,
        secret=b"test-secret",
        environment={"ACP_ATTEMPT_ID": attempt_id},
        credential_registry=credential_registry,
        credential_handles=credential_handles,
    )


def postgres_context(
    tmp_path: Path,
    attempt_id: str = "attempt-1",
    password: str = "postgres-password",
) -> DriverContext:
    store = tmp_path / "credential-store"
    store.mkdir(mode=0o700, exist_ok=True)
    version = store / "version-1"
    version.write_text(f"*:*:*:*:{password}\n", encoding="utf-8")
    version.chmod(0o600)
    current = store / "current"
    if current.exists() or current.is_symlink():
        current.unlink()
    current.symlink_to(version.name)
    registry = CredentialRegistry(
        (
            CredentialDefinition(
                name="postgres-main",
                provider="versioned_file",
                options={"current": str(current)},
            ),
        ),
        tmp_path / "repo",
        b"test-secret",
    )
    handle = registry.resolve_current("postgres-main")
    return context(
        tmp_path,
        attempt_id,
        credential_registry=registry,
        credential_handles={"database": handle},
    )


# ---------------------------------------------------------------------------
# Trust boundary
# ---------------------------------------------------------------------------


def test_relative_executable_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(DriverError) as error:
        resolve_trusted_executable("./scripts/teardown.sh", tmp_path)
    assert error.value.code == "invalid_config"


def test_missing_executable_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(DriverError) as error:
        resolve_trusted_executable(str(tmp_path / "absent"), tmp_path)
    assert error.value.code == "invalid_config"


def test_executable_inside_repository_is_rejected(tmp_path: Path) -> None:
    """A candidate can edit anything in the repo, so nothing there is a trust anchor."""
    repo = tmp_path / "repo"
    repo.mkdir()
    candidate_tool = make_executable(repo / "teardown.sh")
    with pytest.raises(DriverError) as error:
        resolve_trusted_executable(str(candidate_tool), repo)
    assert error.value.code == "untrusted_driver"


def test_symlink_pointing_into_repository_is_rejected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    make_executable(repo / "real.sh")
    link = tmp_path / "outside-link"
    link.symlink_to(repo / "real.sh")
    with pytest.raises(DriverError) as error:
        resolve_trusted_executable(str(link), repo)
    assert error.value.code == "untrusted_driver"


def test_group_or_world_writable_executable_is_rejected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    tool = make_executable(tmp_path / "tool.sh")
    tool.chmod(0o777)
    with pytest.raises(DriverError) as error:
        resolve_trusted_executable(str(tool), repo)
    assert error.value.code == "untrusted_driver"


def test_executable_below_world_writable_parent_is_rejected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir()
    tool = make_executable(unsafe / "tool.sh")
    unsafe.chmod(0o777)
    with pytest.raises(DriverError) as error:
        resolve_trusted_executable(str(tool), repo)
    assert error.value.code == "untrusted_driver"


def test_valid_executable_is_accepted(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    assert resolve_trusted_executable("/bin/echo", repo) == Path("/bin/echo").resolve()


# ---------------------------------------------------------------------------
# Execution safety
# ---------------------------------------------------------------------------


def test_run_trusted_refuses_relative_argv(tmp_path: Path) -> None:
    with pytest.raises(DriverError) as error:
        run_trusted(["docker", "ps"], tmp_path, {})
    assert error.value.code == "invalid_driver_invocation"


def test_run_trusted_revalidates_immediately_before_exec(tmp_path: Path) -> None:
    """A same-UID file cannot become trusted merely by having an exec bit."""
    tool = make_executable(tmp_path / "tool.sh")
    with pytest.raises(DriverError) as error:
        run_trusted([str(tool)], tmp_path / "wd", {})
    assert error.value.code == "untrusted_driver"


def test_run_trusted_executes_platform_binary_without_copying_it(tmp_path: Path) -> None:
    result = run_trusted(["/bin/echo", "ok"], tmp_path / "wd", {})
    assert result["exit_code"] == 0
    assert result["stdout"] == "ok\n"
    assert result["argv"][0] == str(Path("/bin/echo").resolve())


def test_run_trusted_resolves_platform_symlink_before_nofollow_open(tmp_path: Path) -> None:
    shell = Path("/bin/sh").resolve()
    shell_alias = tmp_path / "shell-alias"
    shell_alias.symlink_to(shell)

    result = run_trusted([str(shell_alias), "-c", "exit 0"], tmp_path / "wd", {})

    assert result["exit_code"] == 0
    assert result["argv"][0] == str(shell)


def test_run_trusted_does_not_use_a_shell(tmp_path: Path) -> None:
    """Metacharacters must be inert argv text, not shell syntax."""
    marker = tmp_path / "pwned"
    result = run_trusted(
        ["/usr/bin/printf", "%s", f"; touch {marker}"],
        tmp_path / "wd",
        os.environ.copy(),
    )
    assert result["exit_code"] == 0
    assert not marker.exists()
    assert result["stdout"] == f"; touch {marker}"


def test_run_trusted_scrubs_inherited_path_and_loader_environment(tmp_path: Path) -> None:
    marker = tmp_path / "path-injected"
    evil = tmp_path / "evil"
    evil.mkdir()
    make_executable(evil / "helper", f"#!/bin/sh\ntouch {marker}\n")
    result = run_trusted(
        ["/bin/sh", "-c", "helper"],
        tmp_path / "wd",
        {
            "PATH": str(evil),
            "PYTHONPATH": str(evil),
            "DYLD_INSERT_LIBRARIES": str(evil / "payload.dylib"),
            "ACP_ATTEMPT_ID": "attempt-1",
        },
    )
    assert result["exit_code"] != 0
    assert not marker.exists()


def test_run_trusted_redacts_secret_environment_from_evidence(tmp_path: Path) -> None:
    secret = "postgresql://user:literal-password@localhost/app"
    result = run_trusted(
        ["/bin/sh", "-c", 'printf "%s" "$PGDATABASE"; printf "%s" "$PGDATABASE" >&2'],
        tmp_path / "wd",
        {"PGDATABASE": secret},
    )
    assert result["exit_code"] == 0
    assert secret not in str(result)
    assert result["stdout"] == "[REDACTED]"
    assert result["stderr"] == "[REDACTED]"


def test_run_trusted_never_forwards_supervisor_runner_credential(tmp_path: Path) -> None:
    secret = "runner-secret-must-not-enter-driver"
    result = run_trusted(
        ["/bin/sh", "-c", 'test -z "${ACP_RUNNER_CREDENTIAL:-}"'],
        tmp_path / "wd",
        {"ACP_RUNNER_CREDENTIAL": secret, "ACP_ATTEMPT_ID": "attempt-1"},
    )
    assert result["exit_code"] == 0
    assert secret not in str(result)


def test_run_trusted_inherits_restart_guard_fd(tmp_path: Path) -> None:
    lock_path = tmp_path / "restart.lock"
    guard_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        result = run_trusted(
            [
                "/bin/sh",
                "-c",
                f"test -e /proc/self/fd/{guard_fd} || test -e /dev/fd/{guard_fd}",
            ],
            tmp_path / "wd",
            {},
            guard_fd=guard_fd,
        )
    finally:
        os.close(guard_fd)
    assert result["exit_code"] == 0


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux /proc FD execution")
def test_run_trusted_executes_open_inode_during_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trusted = tmp_path / "trusted"
    trusted.mkdir(mode=0o755)
    tool = make_executable(trusted / "tool", "#!/bin/sh\necho safe\n")
    attacker = make_executable(tmp_path / "attacker", "#!/bin/sh\necho replaced\n")
    real_run = subprocess.run

    def racing_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        attacker.replace(tool)
        return real_run(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(subprocess, "run", racing_run)
    result = run_trusted(
        [str(tool)],
        tmp_path / "wd",
        {},
        expected_owners={0, os.geteuid()},
    )

    assert result["exit_code"] == 0
    assert result["stdout"] == "safe\n"


# ---------------------------------------------------------------------------
# Ownership
# ---------------------------------------------------------------------------


def test_ownership_token_binds_attempt_and_resource() -> None:
    first = ownership_token(b"secret", "attempt-1", "browser_profile", "/tmp/a")
    same = ownership_token(b"secret", "attempt-1", "browser_profile", "/tmp/a")
    other_attempt = ownership_token(b"secret", "attempt-2", "browser_profile", "/tmp/a")
    other_resource = ownership_token(b"secret", "attempt-1", "browser_profile", "/tmp/b")
    assert first == same
    assert first != other_attempt
    assert first != other_resource


# ---------------------------------------------------------------------------
# Lifecycle and cleanup proof
# ---------------------------------------------------------------------------


def browser_driver() -> BrowserProfileDriver:
    return BrowserProfileDriver(
        DriverDefinition(name="browser", kind="browser_profile", executable=None, options={})
    )


def test_setup_creates_and_teardown_proves_absence(tmp_path: Path) -> None:
    driver = browser_driver()
    ctx = context(tmp_path)

    setup = driver.run_phase("setup", ctx, run_trusted)
    assert setup.ok and setup.present is True
    assert Path(setup.resource_id).is_dir()

    teardown = driver.run_phase("teardown", ctx, run_trusted)
    assert teardown.ok
    assert teardown.present is False
    assert teardown.proof["cleanup_proved"] is True
    assert not Path(teardown.resource_id).exists()


def test_teardown_is_idempotent_and_crash_retryable(tmp_path: Path) -> None:
    driver = browser_driver()
    ctx = context(tmp_path)
    driver.run_phase("setup", ctx, run_trusted)

    first = driver.run_phase("teardown", ctx, run_trusted)
    second = driver.run_phase("teardown", ctx, run_trusted)
    assert first.proof["cleanup_proved"] is True
    # Tearing down what is already gone must succeed, so a crashed supervisor
    # can simply run teardown again.
    assert second.ok and second.proof["cleanup_proved"] is True


def test_setup_is_idempotent_and_resource_id_is_deterministic(tmp_path: Path) -> None:
    driver = browser_driver()
    ctx = context(tmp_path)
    first = driver.run_phase("setup", ctx, run_trusted)
    second = driver.run_phase("setup", ctx, run_trusted)
    assert first.resource_id == second.resource_id
    assert second.ok and second.present is True


class FalseSuccessTeardownDriver(BrowserProfileDriver):
    """Reports a clean teardown while leaving the resource in place."""

    def teardown(self, context, runner):  # type: ignore[override]
        return {"argv": ["<fake>"], "exit_code": 0, "stdout": "removed", "stderr": ""}


def test_false_success_teardown_yields_no_cleanup_proof(tmp_path: Path) -> None:
    """The central rule: exit code 0 is not cleanup — absence is cleanup."""
    driver = FalseSuccessTeardownDriver(
        DriverDefinition(name="browser", kind="browser_profile", executable=None, options={})
    )
    ctx = context(tmp_path)
    driver.run_phase("setup", ctx, run_trusted)

    teardown = driver.run_phase("teardown", ctx, run_trusted)
    assert teardown.proof["cleanup_proved"] is False
    assert teardown.present is True
    assert teardown.exit_code != 0, "a lying teardown must not report success"
    assert "still present" in teardown.proof["error"]


class FalseSuccessSetupDriver(BrowserProfileDriver):
    """Reports a clean setup without creating anything."""

    def setup(self, context, runner):  # type: ignore[override]
        return {"argv": ["<fake>"], "exit_code": 0, "stdout": "created", "stderr": ""}


def test_false_success_setup_is_detected(tmp_path: Path) -> None:
    driver = FalseSuccessSetupDriver(
        DriverDefinition(name="browser", kind="browser_profile", executable=None, options={})
    )
    setup = driver.run_phase("setup", context(tmp_path), run_trusted)
    assert setup.present is False
    assert setup.exit_code != 0
    assert "absent" in setup.proof["error"]


class FailedSetupProbeDriver(BrowserProfileDriver):
    def probe(self, context, runner):  # type: ignore[override]
        return True, {"argv": ["<fake>"], "exit_code": 1, "stdout": "present", "stderr": ""}


def test_setup_requires_successful_independent_probe(tmp_path: Path) -> None:
    driver = FailedSetupProbeDriver(
        DriverDefinition(name="browser", kind="browser_profile", executable=None, options={})
    )
    setup = driver.run_phase("setup", context(tmp_path), run_trusted)
    assert setup.present is True
    assert setup.exit_code != 0
    assert "probe failed" in setup.proof["error"]


def test_restart_discards_state_a_worker_left_behind(tmp_path: Path) -> None:
    """A stale worker service must not survive into review."""
    driver = browser_driver()
    ctx = context(tmp_path)
    driver.run_phase("setup", ctx, run_trusted)
    stale = Path(driver.resource_id(ctx)) / "worker-left-this.txt"
    stale.write_text("stale server state", encoding="utf-8")

    teardown = driver.run_phase("teardown", ctx, run_trusted)
    assert teardown.proof["cleanup_proved"] is True
    driver.run_phase("setup", ctx, run_trusted)

    assert Path(driver.resource_id(ctx)).is_dir()
    assert not stale.exists()


# ---------------------------------------------------------------------------
# Compose adapter: cleanup proof must not depend on candidate content
# ---------------------------------------------------------------------------


def test_compose_teardown_and_probe_never_read_a_compose_file(tmp_path: Path) -> None:
    recorded: list[list[str]] = []

    def recorder(argv, cwd, env, timeout, credential):  # type: ignore[no-untyped-def]
        recorded.append(list(argv))
        return {"argv": list(argv), "exit_code": 0, "stdout": "", "stderr": ""}

    tool = make_executable(tmp_path / "docker")
    driver = DockerComposeDriver(
        DriverDefinition(
            name="stack",
            kind="docker_compose",
            executable=tool,
            options={"compose_file": "/candidate/docker-compose.yml"},
        )
    )
    ctx = context(tmp_path)
    driver.run_phase("teardown", ctx, recorder)

    assert recorded, "teardown must invoke the driver"
    for argv in recorded:
        assert "-f" not in argv, (
            "teardown/probe must address the project by name only, so the proof "
            "cannot be steered by candidate-supplied compose content"
        )
        assert "-p" in argv


def test_compose_project_name_is_deterministic_and_scoped(tmp_path: Path) -> None:
    tool = make_executable(tmp_path / "docker")
    driver = DockerComposeDriver(
        DriverDefinition(name="stack", kind="docker_compose", executable=tool, options={})
    )
    assert driver.resource_id(context(tmp_path, "Attempt-XYZ")) == "acp-attempt-xyz"


def test_postgres_schema_is_passed_as_psql_variable_not_sql_text(tmp_path: Path) -> None:
    recorded: list[list[str]] = []
    environments: list[dict[str, str]] = []
    credential_payloads: list[str] = []

    def recorder(argv, cwd, env, timeout, credential):  # type: ignore[no-untyped-def]
        recorded.append(list(argv))
        environments.append(dict(env))
        assert credential is not None
        credential_payloads.append(os.pread(credential.fd, 1024, 0).decode())
        stdout = "1\n" if "information_schema.schemata" in argv[-1] else ""
        return {"argv": list(argv), "exit_code": 0, "stdout": stdout, "stderr": ""}

    tool = make_executable(tmp_path / "psql")
    driver = PostgresSchemaDriver(
        DriverDefinition(
            name="database",
            kind="postgres_schema",
            executable=tool,
            options={
                "credential": "postgres-main",
                "host": "database.internal",
                "port": "5432",
                "database": "app",
                "user": "acp",
            },
        )
    )
    ctx = postgres_context(tmp_path, "Attempt-XYZ", "fd-only-password")
    schema = driver.resource_id(ctx)

    for phase in ("setup", "verify", "teardown"):
        driver.run_phase(phase, ctx, recorder)

    assert recorded
    for argv in recorded:
        sql = argv[-1]
        assert argv[1:3] == ["-X", "--no-password"]
        assert schema not in sql
        assert ["--set", f"schema={schema}"] == argv[argv.index("--set") :][:2]
        assert "fd-only-password" not in argv
    assert environments
    assert all("PGDATABASE" not in env for env in environments)
    assert all(env["PGPASSFILE"].startswith(("/dev/fd/", "/proc/self/fd/")) for env in environments)
    assert credential_payloads == ["*:*:*:*:fd-only-password\n"] * 5


def test_postgres_ownership_capability_binds_credential_version(tmp_path: Path) -> None:
    driver = PostgresSchemaDriver(
        DriverDefinition(
            name="database",
            kind="postgres_schema",
            executable=Path("/bin/echo"),
            options={
                "credential": "postgres-main",
                "host": "database.internal",
                "port": "5432",
                "database": "app",
                "user": "acp",
            },
        )
    )
    base = {
        "provider": "versioned_file",
        "credential": "postgres-main",
        "provider_fingerprint": "provider-fingerprint",
        "source_reference": "/secure/version",
        "source_device": 1,
        "source_inode": 2,
    }
    first_handle = CredentialHandle(
        **base,
        version="version-a",
        target_fingerprint="target-a",  # type: ignore[arg-type]
    )
    second_handle = CredentialHandle(
        **base,
        version="version-b",
        target_fingerprint="target-b",  # type: ignore[arg-type]
    )
    first = driver.ownership_token(context(tmp_path, credential_handles={"database": first_handle}))
    second = driver.ownership_token(
        context(tmp_path, credential_handles={"database": second_handle})
    )
    assert first != second
    assert "target-a" not in first + second
    assert "target-b" not in first + second


# ---------------------------------------------------------------------------
# Configuration parsing
# ---------------------------------------------------------------------------


def test_parse_rejects_unknown_kind(tmp_path: Path) -> None:
    with pytest.raises(DriverError) as error:
        parse_driver_definitions([{"name": "x", "kind": "kubernetes"}], tmp_path)
    assert error.value.code == "invalid_config"


def test_parse_rejects_duplicate_names(tmp_path: Path) -> None:
    entries = [
        {"name": "dup", "kind": "browser_profile"},
        {"name": "dup", "kind": "browser_profile"},
    ]
    with pytest.raises(DriverError):
        parse_driver_definitions(entries, tmp_path)


def test_parse_rejects_candidate_owned_executable(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    tool = make_executable(repo / "docker")
    with pytest.raises(DriverError) as error:
        parse_driver_definitions(
            [{"name": "stack", "kind": "docker_compose", "executable": str(tool)}], repo
        )
    assert error.value.code == "untrusted_driver"


def test_browser_profile_driver_must_not_declare_an_executable(tmp_path: Path) -> None:
    tool = make_executable(tmp_path / "tool.sh")
    with pytest.raises(DriverError):
        parse_driver_definitions(
            [{"name": "p", "kind": "browser_profile", "executable": str(tool)}],
            tmp_path / "repo",
        )


def test_build_driver_requires_executable_for_external_kinds() -> None:
    with pytest.raises(DriverError):
        build_driver(
            DriverDefinition(name="stack", kind="docker_compose", executable=None, options={})
        )


# ---------------------------------------------------------------------------
# Supervisor integration: allocations must be quarantined without proof
# ---------------------------------------------------------------------------


DRIVER_CONFIG = """
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

[[runtime.drivers]]
name = "browser"
kind = "browser_profile"
"""


@pytest.fixture
def driver_repo(tmp_path: Path) -> Path:
    def git(*arguments: str) -> None:
        subprocess.run(["git", "-C", str(tmp_path), *arguments], check=True, capture_output=True)

    git("init", "-b", "main")
    git("config", "user.name", "ACP Test")
    git("config", "user.email", "acp@example.test")
    (tmp_path / "alpha.txt").write_text("base\n", encoding="utf-8")
    git("add", "alpha.txt")
    git("commit", "-m", "base")
    (tmp_path / "acp.toml").write_text(DRIVER_CONFIG, encoding="utf-8")
    return tmp_path


def claimed_attempt(supervisor: GitSupervisor) -> dict:
    created = supervisor.create_task(
        "bounded change",
        "Change only the declared path.",
        ["The declared content is correct"],
        ["alpha.txt"],
    )
    return supervisor.claim(created["id"], "agent-a")


def test_supervisor_sets_up_and_proves_driver_cleanup(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)

    resources = supervisor.driver_resources(attempt["id"])
    assert len(resources) == 1
    assert resources[0]["state"] == "active"
    profile = Path(resources[0]["resource_id"])
    assert profile.is_dir(), "driver setup must actually create the resource"
    assert "ownership_token" not in resources[0], "capability token must not be public"
    assert "ownership_token" not in resources[0]["evidence"]
    with sqlite3.connect(supervisor.db_path) as connection:
        token = connection.execute(
            "SELECT ownership_token FROM runtime_driver_resources WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()[0]
    assert token, "resource must remain internally bound to the attempt"

    supervisor.runtime_down(attempt["id"], _allow_active=True)

    released = supervisor.driver_resources(attempt["id"])
    assert released[0]["state"] == "released"
    assert released[0]["evidence"]["proof"]["cleanup_proved"] is True
    assert not profile.exists()


def test_runtime_restart_fails_closed_on_driver_config_drift(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    old_profile = Path(supervisor.driver_resources(attempt["id"])[0]["resource_id"])
    config = (driver_repo / "acp.toml").read_text(encoding="utf-8")
    (driver_repo / "acp.toml").write_text(
        config.replace(
            'kind = "browser_profile"', 'kind = "browser_profile"\nprofile_prefix = "changed"'
        ),
        encoding="utf-8",
    )
    reopened = GitSupervisor(driver_repo)
    with pytest.raises(SupervisorError) as error:
        reopened.runtime_restart(attempt["id"])
    assert error.value.code == "runtime_driver_config_drift"
    assert old_profile.exists()
    resources = reopened.driver_resources(attempt["id"])
    assert resources[0]["state"] == "quarantined"


def test_legacy_driver_definition_is_operator_visible_quarantine(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    profile = Path(supervisor.driver_resources(attempt["id"])[0]["resource_id"])
    with sqlite3.connect(supervisor.db_path) as connection:
        connection.execute(
            "UPDATE runtime_driver_resources SET definition_json = '{}' WHERE attempt_id = ?",
            (attempt["id"],),
        )
        connection.execute(
            "UPDATE tasks SET status = 'blocked' WHERE id = ?", (attempt["task_id"],)
        )

    with pytest.raises(SupervisorError) as error:
        supervisor.runtime_down(attempt["id"])
    assert error.value.code == "runtime_driver_definition_missing"
    assert profile.exists()
    assert supervisor.runtime_environment(attempt["id"])["state"] == "teardown_failed"
    quarantine = supervisor.quarantined_resources()
    assert quarantine and quarantine[0]["attempt_id"] == attempt["id"]


def test_postgres_literal_secret_is_rejected_before_state_creation(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-b", "main"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Driver Test"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "driver@example.test"],
        check=True,
    )
    (repo / "owned.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "owned.txt"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "base"], check=True)

    secret = "postgresql://user:literal-secret@127.0.0.1/app"
    (repo / "acp.toml").write_text(
        DRIVER_CONFIG
        + "\n[[runtime.drivers]]\n"
        + 'name = "database"\n'
        + 'kind = "postgres_schema"\n'
        + 'executable = "/bin/echo"\n'
        + f'dsn = "{secret}"\n',
        encoding="utf-8",
    )
    with pytest.raises(SupervisorError) as error:
        GitSupervisor(repo)
    assert error.value.code == "invalid_config"
    assert not (repo / ".acp" / "control.db").exists()


@pytest.mark.parametrize(
    ("field", "unsafe"),
    [
        ("database", "postgresql://user:literal-secret@db.internal/app"),
        ("database", "host=db.internal password=literal-secret"),
        ("user", "role password=literal-secret"),
        ("host", "postgresql://literal-secret@db.internal"),
    ],
)
def test_postgres_connection_target_rejects_conninfo_and_uri_before_state(
    tmp_path: Path, field: str, unsafe: str
) -> None:
    current, _, _ = postgres_versions(tmp_path)
    repo = postgres_repo(tmp_path, current)
    config = (repo / "acp.toml").read_text(encoding="utf-8")
    original = {
        "database": 'database = "app"',
        "user": 'user = "acp"',
        "host": 'host = "database.internal"',
    }[field]
    (repo / "acp.toml").write_text(
        config.replace(original, f'{field} = "{unsafe}"'), encoding="utf-8"
    )

    with pytest.raises(SupervisorError) as error:
        GitSupervisor(repo)
    assert error.value.code == "invalid_config"
    assert not (repo / ".acp" / "control.db").exists()


def test_driver_hmac_key_is_separate_from_sqlite_and_private(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    secret = supervisor._driver_secret()
    key_path = supervisor.state_dir / "driver.key"

    assert key_path.read_bytes() == secret
    assert key_path.stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(supervisor.db_path) as connection:
        assert (
            connection.execute("SELECT value FROM meta WHERE key = 'driver_secret'").fetchone()
            is None
        )
    assert secret.hex().encode() not in supervisor.db_path.read_bytes()


def postgres_repo(tmp_path: Path, current: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-b", "main"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Driver Test"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "driver@example.test"],
        check=True,
    )
    (repo / "owned.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "owned.txt"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "base"], check=True)
    (repo / "acp.toml").write_text(
        f"""
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

[[credentials]]
name = "postgres-main"
provider = "versioned_file"
current = "{current}"

[runtime]
setup_commands = []
teardown_commands = []

[[runtime.drivers]]
name = "database"
kind = "postgres_schema"
executable = "/bin/echo"
credential = "postgres-main"
host = "database.internal"
port = "5432"
database = "app"
user = "acp"
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return repo


def postgres_versions(tmp_path: Path) -> tuple[Path, Path, Path]:
    store = tmp_path / "credentials"
    store.mkdir(mode=0o700)
    first = store / "version-1"
    second = store / "version-2"
    first.write_text("*:*:*:*:old-target-password\n", encoding="utf-8")
    second.write_text("*:*:*:*:new-target-password\n", encoding="utf-8")
    first.chmod(0o600)
    second.chmod(0o600)
    current = store / "current"
    current.symlink_to(first.name)
    return current, first, second


def rotate_version(current: Path, version: Path) -> None:
    replacement = current.with_name("replacement")
    replacement.symlink_to(version.name)
    os.replace(replacement, current)


def fake_postgres_runner(active: set[str], operations: list[tuple[str, str]]):
    def runner(  # type: ignore[no-untyped-def]
        argv, cwd, env, timeout, credential, *, guard_fd=None, expected_owners=None
    ):
        assert credential is not None
        target = os.pread(credential.fd, 1024, 0).decode().strip()
        sql = argv[-1]
        if sql.startswith("CREATE SCHEMA"):
            operation = "create"
            active.add(target)
            stdout = ""
        elif sql.startswith("DROP SCHEMA"):
            operation = "drop"
            active.discard(target)
            stdout = ""
        else:
            operation = "probe"
            stdout = "1\n" if target in active else ""
        operations.append((operation, target))
        return {
            "argv": list(argv),
            "exit_code": 0,
            "stdout": stdout,
            "stderr": "",
        }

    return runner


def test_rotation_cleans_old_credential_target_before_using_new_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    current, first, second = postgres_versions(tmp_path)
    repo = postgres_repo(tmp_path, current)
    active: set[str] = set()
    operations: list[tuple[str, str]] = []
    monkeypatch.setattr(supervisor_module, "run_trusted", fake_postgres_runner(active, operations))
    supervisor = GitSupervisor(repo)
    attempt = claimed_attempt(supervisor)
    with sqlite3.connect(supervisor.db_path) as connection:
        before = connection.execute(
            "SELECT credential_handle_json FROM runtime_driver_resources WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()[0]

    rotate_version(current, second)
    supervisor.runtime_restart(attempt["id"])

    old = first.read_text(encoding="utf-8").strip()
    new = second.read_text(encoding="utf-8").strip()
    assert old not in active
    assert new in active
    assert operations.index(("drop", old)) < operations.index(("create", new))
    with sqlite3.connect(supervisor.db_path) as connection:
        after = connection.execute(
            "SELECT credential_handle_json FROM runtime_driver_resources WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()[0]
    assert before != after
    assert "old-target-password" not in before + after
    assert "new-target-password" not in before + after


def test_interrupted_restart_resumes_after_durable_cleanup_without_old_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    current, first, second = postgres_versions(tmp_path)
    repo = postgres_repo(tmp_path, current)
    active: set[str] = set()
    operations: list[tuple[str, str]] = []
    monkeypatch.setattr(supervisor_module, "run_trusted", fake_postgres_runner(active, operations))
    supervisor = GitSupervisor(repo)
    attempt = claimed_attempt(supervisor)
    environment = supervisor.runtime_environment(attempt["id"])["environment"]
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE runtime_environments "
            "SET state = 'restarting', restart_token = 'crashed', restart_started_at = 0 "
            "WHERE attempt_id = ?",
            (attempt["id"],),
        )
    teardown = supervisor._run_driver_phase("teardown", attempt["id"], environment)
    assert all(item.proof.get("cleanup_proved") for item in teardown)
    assert supervisor.driver_resources(attempt["id"])[0]["state"] == "released"

    rotate_version(current, second)
    first.unlink()
    restarted = supervisor.runtime_restart(attempt["id"], recover=True)

    new = second.read_text(encoding="utf-8").strip()
    assert new in active
    assert restarted["resources"][0]["state"] == "active"
    assert supervisor.runtime_environment(attempt["id"])["state"] == "ready"


def test_concurrent_restart_is_rejected_and_cannot_remove_fresh_resource(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    current, _, _ = postgres_versions(tmp_path)
    repo = postgres_repo(tmp_path, current)
    active: set[str] = set()
    operations: list[tuple[str, str]] = []
    monkeypatch.setattr(supervisor_module, "run_trusted", fake_postgres_runner(active, operations))
    supervisor = GitSupervisor(repo)
    attempt = claimed_attempt(supervisor)
    original = supervisor._run_driver_phase
    entered = threading.Event()
    release = threading.Event()
    failures: list[SupervisorError] = []

    def paused_phase(phase, attempt_id, environment, *args, **kwargs):  # type: ignore[no-untyped-def]
        if phase == "teardown" and not entered.is_set():
            entered.set()
            assert release.wait(5)
        return original(phase, attempt_id, environment, *args, **kwargs)

    monkeypatch.setattr(supervisor, "_run_driver_phase", paused_phase)

    def first_restart() -> None:
        try:
            supervisor.runtime_restart(attempt["id"])
        except SupervisorError as error:  # pragma: no cover - asserted below
            failures.append(error)

    worker = threading.Thread(target=first_restart)
    worker.start()
    assert entered.wait(5)
    with pytest.raises(SupervisorError) as concurrent:
        supervisor.runtime_restart(attempt["id"])
    assert concurrent.value.code == "runtime_restart_in_progress"
    with pytest.raises(SupervisorError) as fresh_recovery:
        supervisor.runtime_restart(attempt["id"], recover=True)
    assert fresh_recovery.value.code == "runtime_restart_not_stale"
    release.set()
    worker.join(5)

    assert not worker.is_alive()
    assert failures == []
    assert supervisor.runtime_environment(attempt["id"])["state"] == "ready"
    assert supervisor.driver_resources(attempt["id"])[0]["state"] == "active"
    assert len(active) == 1


def test_stale_recovery_refuses_live_executor_before_overlapping_teardown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    current, _, _ = postgres_versions(tmp_path)
    repo = postgres_repo(tmp_path, current)
    active: set[str] = set()
    operations: list[tuple[str, str]] = []
    delegate = fake_postgres_runner(active, operations)
    teardown_entered = threading.Event()
    release_teardown = threading.Event()

    def blocked_runner(  # type: ignore[no-untyped-def]
        argv, cwd, env, timeout, credential, *, guard_fd=None, expected_owners=None
    ):
        if argv[-1].startswith("DROP SCHEMA") and not teardown_entered.is_set():
            teardown_entered.set()
            assert release_teardown.wait(5)
        return delegate(
            argv,
            cwd,
            env,
            timeout,
            credential,
            guard_fd=guard_fd,
            expected_owners=expected_owners,
        )

    monkeypatch.setattr(supervisor_module, "run_trusted", blocked_runner)
    first = GitSupervisor(repo)
    attempt = claimed_attempt(first)
    failures: list[SupervisorError] = []

    def restart() -> None:
        try:
            first.runtime_restart(attempt["id"])
        except SupervisorError as error:  # pragma: no cover - asserted below
            failures.append(error)

    worker = threading.Thread(target=restart)
    worker.start()
    assert teardown_entered.wait(5)
    with first.connect() as connection:
        connection.execute(
            "UPDATE runtime_environments SET restart_started_at = 0 WHERE attempt_id = ?",
            (attempt["id"],),
        )

    recovery = GitSupervisor(repo)
    with pytest.raises(SupervisorError) as blocked:
        recovery.runtime_restart(attempt["id"], recover=True)
    assert blocked.value.code == "runtime_restart_executor_alive"

    release_teardown.set()
    worker.join(5)
    assert not worker.is_alive()
    assert failures == []
    assert first.runtime_environment(attempt["id"])["state"] == "ready"
    assert first.driver_resources(attempt["id"])[0]["state"] == "active"
    assert len(active) == 1


def test_setup_intent_pins_cleanup_handle_before_external_side_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    current, first, second = postgres_versions(tmp_path)
    repo = postgres_repo(tmp_path, current)
    active: set[str] = set()
    operations: list[tuple[str, str]] = []
    monkeypatch.setattr(supervisor_module, "run_trusted", fake_postgres_runner(active, operations))
    supervisor = GitSupervisor(repo)
    attempt = claimed_attempt(supervisor)
    original_record = supervisor._record_driver_evidence

    def crash_before_evidence(attempt_id, phase, evidence, definitions, **kwargs):  # type: ignore[no-untyped-def]
        if phase == "setup":
            raise RuntimeError("simulated supervisor death before setup evidence")
        return original_record(attempt_id, phase, evidence, definitions, **kwargs)

    monkeypatch.setattr(supervisor, "_record_driver_evidence", crash_before_evidence)
    with pytest.raises(RuntimeError, match="simulated supervisor death"):
        supervisor.runtime_restart(attempt["id"])
    pending = supervisor.driver_resources(attempt["id"])[0]
    assert pending["state"] == "setup_pending"

    rotate_version(current, second)
    monkeypatch.setattr(supervisor, "_record_driver_evidence", original_record)
    runtime = supervisor.runtime_down(attempt["id"], force=True, _allow_active=True)

    old = first.read_text(encoding="utf-8").strip()
    new = second.read_text(encoding="utf-8").strip()
    assert runtime["state"] == "released"
    assert old not in active
    assert ("drop", old) in operations
    assert ("drop", new) not in operations


def test_unavailable_retained_cleanup_credential_quarantines_resource(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    current, first, second = postgres_versions(tmp_path)
    repo = postgres_repo(tmp_path, current)
    active: set[str] = set()
    operations: list[tuple[str, str]] = []
    monkeypatch.setattr(supervisor_module, "run_trusted", fake_postgres_runner(active, operations))
    supervisor = GitSupervisor(repo)
    attempt = claimed_attempt(supervisor)
    old = first.read_text(encoding="utf-8").strip()
    rotate_version(current, second)
    first.unlink()

    runtime = supervisor.runtime_down(attempt["id"], _allow_active=True)

    assert runtime["state"] == "teardown_failed"
    assert old in active, "cleanup could not authenticate to the retained target"
    quarantine = supervisor.quarantined_resources()
    assert quarantine[0]["state"] == "quarantined"
    assert quarantine[0]["evidence"]["proof"]["code"] == "credential_unavailable"


def test_literal_secret_absent_from_state_events_cli_and_public_json(tmp_path: Path) -> None:
    current, first, _ = postgres_versions(tmp_path)
    secret = "old-target-password"
    repo = postgres_repo(tmp_path, current)
    supervisor = GitSupervisor(repo)
    task = supervisor.create_task(
        "credential isolation",
        "Exercise the descriptor-only driver path.",
        ["no secret persists"],
        ["owned.txt"],
    )
    with pytest.raises(SupervisorError) as failure:
        supervisor.claim(task["id"], "agent-a")
    assert secret not in str(failure.value)
    with sqlite3.connect(supervisor.db_path) as connection:
        attempt_id = connection.execute(
            "SELECT id FROM attempts WHERE task_id = ?", (task["id"],)
        ).fetchone()[0]
        rows = connection.execute("SELECT payload_json FROM events ORDER BY sequence").fetchall()
    surfaces = {
        "resources": supervisor.driver_resources(attempt_id),
        "quarantine": supervisor.quarantined_resources(),
        "environment": supervisor.runtime_environment(attempt_id),
        "events": [row[0] for row in rows],
    }
    assert secret not in json.dumps(surfaces, sort_keys=True)

    for path in (repo / ".acp").rglob("*"):
        if path.is_file():
            assert secret.encode() not in path.read_bytes(), path

    command = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_control_plane.cli",
            "--repo",
            str(repo),
            "runtime-resources",
            attempt_id,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert command.returncode == 0
    assert secret not in command.stdout + command.stderr
    assert first.exists(), "the retained version is external to ACP state"


def test_credential_handle_and_secret_absent_from_qc_reproduction_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    current, _, _ = postgres_versions(tmp_path)
    secret = "old-target-password"
    repo = postgres_repo(tmp_path, current)
    active: set[str] = set()
    operations: list[tuple[str, str]] = []
    monkeypatch.setattr(supervisor_module, "run_trusted", fake_postgres_runner(active, operations))
    supervisor = GitSupervisor(repo)
    task = supervisor.create_task(
        "bundle credential isolation",
        "Change one file and run independent QC.",
        ["bundle has no driver credential"],
        ["owned.txt"],
    )
    attempt = supervisor.claim(task["id"], "agent-a")
    worktree = Path(attempt["worktree"])
    (worktree / "owned.txt").write_text("candidate\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(worktree), "add", "owned.txt"], check=True)
    subprocess.run(["git", "-C", str(worktree), "commit", "-m", "candidate"], check=True)
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])

    review = supervisor.run_qc(submission["id"], "independent-qc")
    bundle = supervisor.reproduction_bundle(review["id"])

    serialized = json.dumps({"review": review, "bundle": bundle}, sort_keys=True)
    assert review["verdict"] == "pass"
    assert secret not in serialized
    assert "source_reference" not in serialized
    for path in (repo / ".acp" / "bundles").glob("*"):
        assert secret.encode() not in path.read_bytes()


def test_unproven_cleanup_quarantines_the_allocation(
    driver_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A teardown that lies must not return the allocation to the pool."""
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    profile = Path(supervisor.driver_resources(attempt["id"])[0]["resource_id"])
    assert profile.is_dir()

    monkeypatch.setattr(
        BrowserProfileDriver,
        "teardown",
        lambda self, context, runner: {
            "argv": ["<fake>"],
            "exit_code": 0,
            "stdout": "removed",
            "stderr": "",
        },
    )

    runtime = supervisor.runtime_down(attempt["id"], _allow_active=True)

    assert runtime["state"] == "teardown_failed"
    quarantined = supervisor.quarantined_resources()
    assert [item["attempt_id"] for item in quarantined] == [attempt["id"]]
    assert quarantined[0]["evidence"]["proof"]["cleanup_proved"] is False
    assert profile.is_dir(), "the resource really is still there"


def test_restart_refuses_to_proceed_without_cleanup_proof(
    driver_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    monkeypatch.setattr(
        BrowserProfileDriver,
        "teardown",
        lambda self, context, runner: {
            "argv": ["<fake>"],
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
        },
    )
    with pytest.raises(SupervisorError) as error:
        supervisor.runtime_restart(attempt["id"])
    assert error.value.code == "runtime_cleanup_unproven"


def test_restart_gives_review_a_fresh_resource(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    profile = Path(supervisor.driver_resources(attempt["id"])[0]["resource_id"])
    stale = profile / "worker-left-this.txt"
    stale.write_text("stale server state", encoding="utf-8")

    supervisor.runtime_restart(attempt["id"])

    assert profile.is_dir()
    assert not stale.exists(), "review must not inherit worker state"
