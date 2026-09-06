"""#740 — quarantine explain, recovery, and legacy migration.

Quarantine is fail-closed by design: an unproven teardown parks the allocation
rather than recycling it. These tests cover the supported way back out, and —
more importantly — the things recovery must refuse to do. The interesting
assertions here are the negative ones: no ownership token in operator output, no
identity rewritten to make a mismatch disappear, and no allocation released on
an operator's word alone.
"""

from __future__ import annotations

import json
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest
from support import python_command, state_fingerprint

from agent_control_plane.git_supervisor import GitSupervisor, SupervisorError

DRIVER_CONFIG = f"""
[supervisor]
lease_seconds = 60
qc_timeout_seconds = 30
critic_identity = "independent-qc"
require_critic = false

[qc]
commands = {json.dumps([python_command("pass")])}
critic_command = ""

[integration]
commands = {json.dumps([python_command("pass")])}

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


def quarantine_attempt(supervisor: GitSupervisor, attempt_id: str) -> None:
    """Park the attempt the way a real unproven teardown does."""

    supervisor._quarantine_driver_attempt(attempt_id, "test_induced")


def blank_definition(supervisor: GitSupervisor, attempt_id: str) -> None:
    with sqlite3.connect(supervisor.db_path) as connection:
        connection.execute(
            "UPDATE runtime_driver_resources SET definition_json = '{}' WHERE attempt_id = ?",
            (attempt_id,),
        )


class InjectedCrash(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# explain
# --------------------------------------------------------------------------- #


def test_explain_reports_identity_evidence_mismatch_and_next_actions(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    quarantine_attempt(supervisor, attempt["id"])

    before = state_fingerprint(supervisor)
    resources_before = supervisor.driver_resources(attempt["id"])
    explained = supervisor.quarantine_explain(attempt["id"])

    assert explained["ok"] is True
    assert explained["quarantined"] == 1
    assert state_fingerprint(supervisor) == before
    assert supervisor.driver_resources(attempt["id"]) == resources_before
    assert explained["runtime_state"] == "teardown_failed"
    resource = explained["resources"][0]
    assert resource["driver"] == "browser"
    assert resource["kind"] == "browser_profile"
    assert resource["resource_id"]
    assert resource["owner"] == "agent-a", "operators need to know whose attempt this was"
    assert resource["age_seconds"] is not None and resource["age_seconds"] >= 0
    assert resource["severity"] in {"critical", "high", "normal"}
    assert resource["mismatch_class"]
    assert resource["last_trusted_evidence"], "the last trusted evidence must survive"
    assert resource["safe_next_actions"], "an operator must be told what is safe next"


def test_explain_never_discloses_ownership_token_or_credential_material(
    driver_repo: Path,
) -> None:
    """The token authorises teardown of a real resource. Diagnosis does not need it."""

    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    quarantine_attempt(supervisor, attempt["id"])
    with sqlite3.connect(supervisor.db_path) as connection:
        token = connection.execute(
            "SELECT ownership_token FROM runtime_driver_resources WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()[0]
    assert token, "precondition: the row really does carry a token"

    rendered = json.dumps(supervisor.quarantine_explain(attempt["id"]))

    assert token not in rendered
    assert "ownership_token" not in rendered
    assert "secret" not in rendered.lower()


def test_explain_still_works_when_the_trust_pin_is_broken(driver_repo: Path) -> None:
    """Explain must describe exactly the broken attempts it exists for."""

    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    quarantine_attempt(supervisor, attempt["id"])
    with sqlite3.connect(supervisor.db_path) as connection:
        connection.execute(
            "UPDATE attempts SET trust_bundle_json = '{\"broken\": true}' WHERE id = ?",
            (attempt["id"],),
        )

    before = state_fingerprint(supervisor)
    resources_before = supervisor.driver_resources(attempt["id"])
    explained = supervisor.quarantine_explain(attempt["id"])

    assert explained["ok"] is True
    assert explained["quarantined"] == 1
    assert state_fingerprint(supervisor) == before
    assert supervisor.driver_resources(attempt["id"]) == resources_before


def test_explain_is_read_only(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    quarantine_attempt(supervisor, attempt["id"])
    before = supervisor.driver_resources(attempt["id"])

    supervisor.quarantine_explain(attempt["id"])
    supervisor.quarantine_explain(attempt["id"])

    assert supervisor.driver_resources(attempt["id"]) == before


def test_explain_rejects_an_unknown_attempt(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    with pytest.raises(SupervisorError) as error:
        supervisor.quarantine_explain("no-such-attempt")
    assert error.value.code == "attempt_not_found"


# --------------------------------------------------------------------------- #
# legacy migration — only when identity can be proven
# --------------------------------------------------------------------------- #


def test_legacy_blank_definition_migrates_when_identity_is_proved(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    blank_definition(supervisor, attempt["id"])
    quarantine_attempt(supervisor, attempt["id"])
    assert supervisor.quarantine_explain(attempt["id"])["resources"][0]["mismatch_class"] == (
        "definition_missing"
    )

    recovered = supervisor.quarantine_recover(attempt["id"], "restore-definition")

    assert recovered["restored"] == ["browser"]
    assert recovered["refused"] == []
    with sqlite3.connect(supervisor.db_path) as connection:
        definition = connection.execute(
            "SELECT definition_json FROM runtime_driver_resources WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()[0]
    assert definition != "{}", "a provable legacy row must be migrated, not left stranded"


def test_unprovable_identity_is_refused_and_atomically_stays_quarantined(
    driver_repo: Path,
) -> None:
    """The one case recovery must never 'fix': a row that cannot prove what it owns."""

    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    with sqlite3.connect(supervisor.db_path) as connection:
        connection.execute(
            "UPDATE runtime_driver_resources SET definition_json = '{}', "
            "ownership_token = 'forged-token' WHERE attempt_id = ?",
            (attempt["id"],),
        )
    quarantine_attempt(supervisor, attempt["id"])

    recovered = supervisor.quarantine_recover(attempt["id"], "restore-definition")

    assert recovered["restored"] == []
    assert recovered["refused"] == [{"driver": "browser", "reason": "identity_unproved"}]
    assert recovered["still_quarantined"] == 1
    resources = supervisor.driver_resources(attempt["id"])
    assert resources[0]["state"] == "quarantined"
    assert supervisor.runtime_environment(attempt["id"])["state"] == "teardown_failed"
    explained = supervisor.quarantine_explain(attempt["id"])
    assert explained["resources"][0]["identity_proved"] is False
    assert any(
        "do NOT recover" in action for action in explained["resources"][0]["safe_next_actions"]
    )


def test_recovery_never_rewrites_immutable_allocation_identity(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    blank_definition(supervisor, attempt["id"])
    quarantine_attempt(supervisor, attempt["id"])

    def identity() -> tuple:
        with sqlite3.connect(supervisor.db_path) as connection:
            return connection.execute(
                "SELECT attempt_id, driver, kind, resource_id, ownership_token "
                "FROM runtime_driver_resources WHERE attempt_id = ?",
                (attempt["id"],),
            ).fetchone()

    before = identity()
    supervisor.quarantine_recover(attempt["id"], "restore-definition")
    supervisor.quarantine_recover(attempt["id"], "retry-cleanup")

    assert identity() == before, "identity columns are the binding; recovery may not touch them"


# --------------------------------------------------------------------------- #
# retry cleanup
# --------------------------------------------------------------------------- #


def test_retry_cleanup_releases_a_resource_that_is_genuinely_gone(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    profile = Path(supervisor.driver_resources(attempt["id"])[0]["resource_id"])
    quarantine_attempt(supervisor, attempt["id"])
    assert supervisor.driver_resources(attempt["id"])[0]["state"] == "quarantined"

    recovered = supervisor.quarantine_recover(attempt["id"], "retry-cleanup")

    assert recovered["released"] == ["browser"]
    assert recovered["still_quarantined"] == 0
    assert not profile.exists(), "a proved cleanup really removed the resource"
    assert supervisor.driver_resources(attempt["id"])[0]["state"] == "released"


def test_retry_cleanup_is_idempotent_when_repeated(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    quarantine_attempt(supervisor, attempt["id"])

    first = supervisor.quarantine_recover(attempt["id"], "retry-cleanup")
    second = supervisor.quarantine_recover(attempt["id"], "retry-cleanup")
    third = supervisor.quarantine_recover(attempt["id"], "retry-cleanup")

    assert first["still_quarantined"] == 0
    assert second["still_quarantined"] == 0
    assert third["still_quarantined"] == 0
    assert second["retried"] == [] and third["retried"] == []


def test_recovery_clears_the_runtime_only_once_nothing_is_quarantined(
    driver_repo: Path,
) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    quarantine_attempt(supervisor, attempt["id"])
    assert supervisor.runtime_environment(attempt["id"])["state"] == "teardown_failed"

    supervisor.quarantine_recover(attempt["id"], "retry-cleanup")

    assert supervisor.runtime_environment(attempt["id"])["state"] == "released"


def test_recovery_rejects_a_live_runtime_and_keeps_its_port_allocation(
    driver_repo: Path,
) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config = (driver_repo / "acp.toml").read_text(encoding="utf-8")
    (driver_repo / "acp.toml").write_text(
        config + f"\n[runtime.ports]\nAPP_PORT = [{port}, {port}]\n",
        encoding="utf-8",
    )
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)

    with pytest.raises(SupervisorError) as error:
        supervisor.quarantine_recover(attempt["id"], "retry-cleanup")

    assert error.value.code == "runtime_not_quarantined"
    assert supervisor.runtime_environment(attempt["id"])["state"] == "ready"
    with supervisor.connect() as connection:
        allocation = connection.execute(
            "SELECT value FROM runtime_allocations WHERE attempt_id = ?",
            (attempt["id"],),
        ).fetchone()
    assert allocation is not None and allocation["value"] == port


def test_recovery_refuses_teardown_failure_without_quarantined_driver_proof(
    driver_repo: Path,
) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    with supervisor.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "UPDATE runtime_driver_resources SET state = 'released' WHERE attempt_id = ?",
            (attempt["id"],),
        )
        connection.execute(
            "UPDATE runtime_environments SET state = 'teardown_failed' WHERE attempt_id = ?",
            (attempt["id"],),
        )

    with pytest.raises(SupervisorError) as error:
        supervisor.quarantine_recover(attempt["id"], "retry-cleanup")

    assert error.value.code == "runtime_quarantine_empty"


def test_successful_recovery_removes_attempt_staging_directory(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    runtime_dir = supervisor.state_dir / "runtime" / attempt["id"]
    assert runtime_dir.is_dir()
    quarantine_attempt(supervisor, attempt["id"])

    recovered = supervisor.quarantine_recover(attempt["id"], "retry-cleanup")

    assert recovered["still_quarantined"] == 0
    assert not runtime_dir.exists()


def test_ordinary_teardown_never_hides_staging_cleanup_failure(
    driver_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_control_plane.git_supervisor as supervisor_module

    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    runtime_dir = supervisor.state_dir / "runtime" / attempt["id"]
    real_rmtree = supervisor_module.shutil.rmtree

    def refuse_runtime_staging(path: str | Path, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if Path(path) == runtime_dir:
            raise OSError("injected staging failure")
        real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(supervisor_module.shutil, "rmtree", refuse_runtime_staging)
    failed = supervisor.runtime_down(attempt["id"], _allow_active=True)

    assert failed["state"] == "teardown_failed"
    assert failed["recovery_action"] == "retry-cleanup"
    assert runtime_dir.exists()
    assert any(
        result["command"] == "runtime-staging:remove" for result in failed["teardown_results"]
    )

    monkeypatch.setattr(supervisor_module.shutil, "rmtree", real_rmtree)
    recovered = GitSupervisor(driver_repo).quarantine_recover(attempt["id"], "retry-cleanup")
    assert recovered["still_quarantined"] == 0
    assert supervisor.runtime_environment(attempt["id"])["state"] == "released"


def test_recovery_uses_the_attempt_lifetime_lock(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    quarantine_attempt(supervisor, attempt["id"])

    with (
        supervisor._runtime_restart_guard(attempt["id"], recover=False),
        pytest.raises(SupervisorError) as error,
    ):
        supervisor.quarantine_recover(attempt["id"], "retry-cleanup")

    assert error.value.code == "runtime_restart_in_progress"


def test_runtime_down_uses_the_same_attempt_lifetime_lock(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)

    with (
        supervisor._runtime_restart_guard(attempt["id"], recover=False),
        pytest.raises(SupervisorError) as error,
    ):
        supervisor.runtime_down(attempt["id"], force=True, _allow_active=True)

    assert error.value.code == "runtime_restart_in_progress"


def test_crashed_supervisor_leaves_teardown_hook_holding_lifetime_lock(
    driver_repo: Path,
) -> None:
    marker = driver_repo / "teardown-hook-started"
    config = (driver_repo / "acp.toml").read_text(encoding="utf-8")
    hook = python_command(
        f"import pathlib,time; pathlib.Path({str(marker)!r}).touch(); time.sleep(1.5)"
    )
    (driver_repo / "acp.toml").write_text(
        config.replace("teardown_commands = []", f"teardown_commands = {json.dumps([hook])}"),
        encoding="utf-8",
    )
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "from agent_control_plane.git_supervisor import GitSupervisor; "
                f"GitSupervisor({str(driver_repo)!r}).runtime_down("
                f"{attempt['id']!r}, force=True, _allow_active=True)"
            ),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 5
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert marker.exists(), "teardown hook never started"
    child.kill()
    child.wait(timeout=5)

    with (
        pytest.raises(SupervisorError) as locked,
        supervisor._runtime_restart_guard(attempt["id"], recover=False),
    ):
        pass
    assert locked.value.code == "runtime_restart_in_progress"

    deadline = time.monotonic() + 5
    while True:
        try:
            with supervisor._runtime_restart_guard(attempt["id"], recover=False):
                break
        except SupervisorError as error:
            assert error.code == "runtime_restart_in_progress"
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)
    assert supervisor.runtime_down(attempt["id"], force=True, _allow_active=True)["state"] == (
        "released"
    )


@pytest.mark.parametrize("action", ["restore-definition", "retry-cleanup"])
def test_automatic_recovery_requires_an_integrator_when_auth_is_enabled(
    driver_repo: Path, action: str
) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    worker = supervisor.enroll_runner("worker-a", "worker")
    quarantine_attempt(supervisor, attempt["id"])

    with pytest.raises(SupervisorError) as missing:
        supervisor.quarantine_recover(attempt["id"], action)
    with pytest.raises(SupervisorError) as wrong_role:
        supervisor.quarantine_recover(
            attempt["id"], action, operator="worker-a", credential=worker["credential"]
        )

    assert missing.value.code == "quarantine_recovery_unauthenticated"
    assert wrong_role.value.code == "quarantine_recovery_unauthenticated"


# --------------------------------------------------------------------------- #
# manual receipt — authenticated, and testimony rather than proof
# --------------------------------------------------------------------------- #


def test_manual_receipt_requires_an_enrolled_operator(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    quarantine_attempt(supervisor, attempt["id"])

    with pytest.raises(SupervisorError) as error:
        supervisor.quarantine_recover(
            attempt["id"],
            "manual-receipt",
            operator="nobody",
            credential="made-up",
            reason="I cleaned it",
        )
    assert error.value.code == "quarantine_receipt_unauthenticated"


def test_manual_receipt_rejects_a_wrong_credential_for_a_real_operator(
    driver_repo: Path,
) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    supervisor.enroll_runner("operator-a", "integrator")
    quarantine_attempt(supervisor, attempt["id"])

    with pytest.raises(SupervisorError) as error:
        supervisor.quarantine_recover(
            attempt["id"],
            "manual-receipt",
            operator="operator-a",
            credential="not-the-real-credential",
            reason="I cleaned it",
        )
    assert error.value.code == "quarantine_receipt_unauthenticated"


def test_manual_receipt_requires_a_reason(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    enrolled = supervisor.enroll_runner("operator-a", "integrator")
    quarantine_attempt(supervisor, attempt["id"])

    with pytest.raises(SupervisorError) as error:
        supervisor.quarantine_recover(
            attempt["id"],
            "manual-receipt",
            operator="operator-a",
            credential=enrolled["credential"],
            reason="   ",
        )
    assert error.value.code == "quarantine_receipt_invalid"


def test_manual_receipt_is_recorded_and_surfaced_by_explain(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    enrolled = supervisor.enroll_runner("operator-a", "integrator")
    quarantine_attempt(supervisor, attempt["id"])

    recovered = supervisor.quarantine_recover(
        attempt["id"],
        "manual-receipt",
        operator="operator-a",
        credential=enrolled["credential"],
        reason="removed the profile directory by hand",
    )

    assert recovered["receipts"][0]["operator"] == "operator-a"
    explained = supervisor.quarantine_explain(attempt["id"])
    assert explained["receipts"][0]["operator"] == "operator-a"
    assert explained["receipts"][0]["reason"] == "removed the profile directory by hand"
    assert enrolled["credential"] not in json.dumps(explained), "never store or echo the secret"


def test_manual_receipt_does_not_release_a_resource_that_is_still_present(
    driver_repo: Path,
) -> None:
    """The core of the acceptance line: a receipt is testimony, not absence proof."""

    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    enrolled = supervisor.enroll_runner("operator-a", "integrator")
    profile = Path(supervisor.driver_resources(attempt["id"])[0]["resource_id"])
    assert profile.is_dir(), "precondition: the resource really is still there"
    quarantine_attempt(supervisor, attempt["id"])

    recovered = supervisor.quarantine_recover(
        attempt["id"],
        "manual-receipt",
        operator="operator-a",
        credential=enrolled["credential"],
        reason="I promise it is gone",
    )

    assert recovered["released"] == []
    assert recovered["still_quarantined"] == 1
    assert recovered["receipts"][0]["absence_proved"] is False
    assert supervisor.driver_resources(attempt["id"])[0]["state"] == "quarantined"
    assert profile.is_dir(), "a false claim must not have removed anything either"


def test_manual_receipt_cannot_turn_a_forged_identity_into_absence_proof(
    driver_repo: Path,
) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    enrolled = supervisor.enroll_runner("operator-a", "integrator")
    profile = Path(supervisor.driver_resources(attempt["id"])[0]["resource_id"])
    subprocess.run(["rm", "-rf", str(profile)], check=True)
    with supervisor.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "UPDATE runtime_driver_resources SET ownership_token = 'forged-token' "
            "WHERE attempt_id = ?",
            (attempt["id"],),
        )
    quarantine_attempt(supervisor, attempt["id"])

    recovered = supervisor.quarantine_recover(
        attempt["id"],
        "manual-receipt",
        operator="operator-a",
        credential=enrolled["credential"],
        reason="resource removed out of band",
    )

    assert recovered["released"] == []
    assert recovered["receipts"][0]["absence_proved"] is False
    assert recovered["still_quarantined"] == 1
    assert supervisor.driver_resources(attempt["id"])[0]["state"] == "quarantined"


def test_manual_receipt_releases_only_once_absence_is_positively_proved(
    driver_repo: Path,
) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    enrolled = supervisor.enroll_runner("operator-a", "integrator")
    profile = Path(supervisor.driver_resources(attempt["id"])[0]["resource_id"])
    quarantine_attempt(supervisor, attempt["id"])
    # The operator really did remove it out of band; now the driver can prove it.
    subprocess.run(["rm", "-rf", str(profile)], check=True)

    recovered = supervisor.quarantine_recover(
        attempt["id"],
        "manual-receipt",
        operator="operator-a",
        credential=enrolled["credential"],
        reason="removed by hand after the driver crashed",
    )

    assert recovered["released"] == ["browser"]
    assert recovered["receipts"][0]["absence_proved"] is True
    assert supervisor.driver_resources(attempt["id"])[0]["state"] == "released"


def test_repeated_manual_receipts_are_idempotent(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    enrolled = supervisor.enroll_runner("operator-a", "integrator")
    profile = Path(supervisor.driver_resources(attempt["id"])[0]["resource_id"])
    quarantine_attempt(supervisor, attempt["id"])
    subprocess.run(["rm", "-rf", str(profile)], check=True)

    first = supervisor.quarantine_recover(
        attempt["id"],
        "manual-receipt",
        operator="operator-a",
        credential=enrolled["credential"],
        reason="removed by hand",
    )
    second = supervisor.quarantine_recover(
        attempt["id"],
        "manual-receipt",
        operator="operator-a",
        credential=enrolled["credential"],
        reason="removed by hand",
    )

    assert first["still_quarantined"] == 0
    assert second["still_quarantined"] == 0
    assert second["receipts"] == [], "nothing left quarantined means nothing left to attest"


# --------------------------------------------------------------------------- #
# crash at every transition
# --------------------------------------------------------------------------- #


def test_recovery_resumes_after_crash_following_driver_release(
    driver_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    quarantine_attempt(supervisor, attempt["id"])
    original = supervisor._retry_quarantined_cleanup

    def crash_after_driver_proof(attempt_id: str, guard_fd: int) -> dict:
        original(attempt_id, guard_fd)
        raise InjectedCrash("after driver release")

    monkeypatch.setattr(supervisor, "_retry_quarantined_cleanup", crash_after_driver_proof)
    with pytest.raises(InjectedCrash):
        supervisor.quarantine_recover(attempt["id"], "retry-cleanup")

    interrupted = supervisor.runtime_environment(attempt["id"])
    assert interrupted["state"] == "teardown_failed"
    assert interrupted["recovery_action"] == "retry-cleanup"
    assert supervisor.driver_resources(attempt["id"])[0]["state"] == "released"

    reopened = GitSupervisor(driver_repo)
    resumed = reopened.quarantine_recover(attempt["id"], "retry-cleanup")

    assert resumed["still_quarantined"] == 0
    assert reopened.runtime_environment(attempt["id"])["state"] == "released"


@pytest.mark.parametrize("crash_after", [1, 2])
def test_recovery_resumes_after_each_allocation_deletion(
    driver_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_after: int,
) -> None:
    ports: list[int] = []
    while len(ports) < 2:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            candidate = probe.getsockname()[1]
            if candidate not in ports:
                ports.append(candidate)
    config = (driver_repo / "acp.toml").read_text(encoding="utf-8")
    (driver_repo / "acp.toml").write_text(
        config
        + "\n[runtime.ports]\n"
        + f"APP_PORT = [{ports[0]}, {ports[0]}]\n"
        + f"AUX_PORT = [{ports[1]}, {ports[1]}]\n",
        encoding="utf-8",
    )
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    quarantine_attempt(supervisor, attempt["id"])
    original = supervisor._release_proven_allocation
    calls = 0

    def crash_after_delete(attempt_id: str, pool: str, value: int) -> bool:
        nonlocal calls
        deleted = original(attempt_id, pool, value)
        calls += 1
        if calls == crash_after:
            raise InjectedCrash(f"after allocation {calls}")
        return deleted

    monkeypatch.setattr(supervisor, "_release_proven_allocation", crash_after_delete)
    with pytest.raises(InjectedCrash):
        supervisor.quarantine_recover(attempt["id"], "retry-cleanup")

    interrupted = supervisor.runtime_environment(attempt["id"])
    assert interrupted["state"] == "teardown_failed"
    assert interrupted["recovery_action"] == "retry-cleanup"

    reopened = GitSupervisor(driver_repo)
    resumed = reopened.quarantine_recover(attempt["id"], "retry-cleanup")

    assert resumed["held_allocations"] == 0
    assert reopened.runtime_environment(attempt["id"])["state"] == "released"


def test_recovery_resumes_after_crash_between_staging_removal_and_final_state(
    driver_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    runtime_dir = supervisor.state_dir / "runtime" / attempt["id"]
    quarantine_attempt(supervisor, attempt["id"])
    original = subprocess.run

    # Driver teardown uses subprocess, while staging deletion does not. Crash at
    # the exact durable boundary by replacing the supervisor module's rmtree.
    import agent_control_plane.git_supervisor as supervisor_module

    real_rmtree = supervisor_module.shutil.rmtree

    def remove_then_crash(path: str | Path, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        real_rmtree(path, *args, **kwargs)
        if Path(path) == runtime_dir:
            raise InjectedCrash("after staging removal")

    monkeypatch.setattr(supervisor_module.shutil, "rmtree", remove_then_crash)
    with pytest.raises(InjectedCrash):
        supervisor.quarantine_recover(attempt["id"], "retry-cleanup")
    assert not runtime_dir.exists()
    assert supervisor.runtime_environment(attempt["id"])["recovery_action"] == "retry-cleanup"

    monkeypatch.setattr(supervisor_module.shutil, "rmtree", real_rmtree)
    reopened = GitSupervisor(driver_repo)
    resumed = reopened.quarantine_recover(attempt["id"], "retry-cleanup")

    assert resumed["still_quarantined"] == 0
    assert reopened.runtime_environment(attempt["id"])["state"] == "released"
    assert original is subprocess.run


@pytest.mark.parametrize(
    "action",
    ["restore-definition", "retry-cleanup", "manual-receipt"],
)
def test_recovery_survives_a_crash_and_reopen_at_every_transition(
    driver_repo: Path, action: str
) -> None:
    """Every action is re-entrant: a fresh supervisor resumes without wedging."""

    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    enrolled = supervisor.enroll_runner("operator-a", "integrator")
    if action == "restore-definition":
        blank_definition(supervisor, attempt["id"])
    quarantine_attempt(supervisor, attempt["id"])
    kwargs = {"operator": "operator-a", "credential": enrolled["credential"]}
    if action == "manual-receipt":
        kwargs["reason"] = "by hand"

    first = supervisor.quarantine_recover(attempt["id"], action, **kwargs)
    assert first["ok"] is True

    # Simulate the crash: drop the process and reopen the state from disk.
    reopened = GitSupervisor(driver_repo)
    second = reopened.quarantine_recover(attempt["id"], action, **kwargs)

    assert second["ok"] is True
    assert reopened.quarantine_explain(attempt["id"])["ok"] is True


# --------------------------------------------------------------------------- #
# the operator status view surfaces age / severity / owner
# --------------------------------------------------------------------------- #


def test_status_surfaces_quarantine_age_severity_and_owner(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    quarantine_attempt(supervisor, attempt["id"])

    snapshot = supervisor.status()

    failure = snapshot["counts"]["cleanup_failures"]
    assert failure == 1
    listed = [item for item in snapshot["cleanup_failures"] if item["attempt_id"] == attempt["id"]]
    assert listed, "a quarantined runtime must appear in cleanup_failures"
    assert listed[0]["owner"] == "agent-a"
    assert listed[0]["severity"] in {"critical", "high"}
    assert listed[0]["age_seconds"] is not None
    assert listed[0]["quarantined_resources"] == 1

    entry = next(item for item in snapshot["tasks"] if item["attempt_id"] == attempt["id"])
    quarantine = entry["runtime"]["quarantine"]
    assert quarantine["count"] == 1
    assert quarantine["drivers"] == ["browser"]
    assert entry["category"] == "cleanup_failed"
    assert "agent-a" in entry["reason"], "the reason must name the owner"
    assert "runtime-quarantine explain" in entry["reason"], "and point at the next command"


def test_status_reason_stays_generic_when_nothing_is_quarantined(driver_repo: Path) -> None:
    """A teardown_failed runtime with no quarantined rows must not invent detail."""

    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    with sqlite3.connect(supervisor.db_path) as connection:
        connection.execute(
            "UPDATE runtime_environments SET state = 'teardown_failed' WHERE attempt_id = ?",
            (attempt["id"],),
        )

    snapshot = supervisor.status()
    entry = next(item for item in snapshot["tasks"] if item["attempt_id"] == attempt["id"])

    assert entry["category"] == "cleanup_failed"
    assert entry["reason"] == "runtime teardown failed; resources stay quarantined"


def test_status_points_to_the_durable_recovery_intent(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    with sqlite3.connect(supervisor.db_path) as connection:
        connection.execute(
            "UPDATE runtime_driver_resources SET state = 'released' WHERE attempt_id = ?",
            (attempt["id"],),
        )
        connection.execute(
            "UPDATE runtime_environments SET state = 'teardown_failed', "
            "recovery_action = 'retry-cleanup' WHERE attempt_id = ?",
            (attempt["id"],),
        )

    snapshot = supervisor.status()
    entry = next(item for item in snapshot["tasks"] if item["attempt_id"] == attempt["id"])

    assert entry["runtime"]["recovery_action"] == "retry-cleanup"
    assert "interrupted retry-cleanup recovery" in entry["reason"]
    assert "--action retry-cleanup" in entry["reason"]


def test_recover_rejects_an_unknown_action(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    attempt = claimed_attempt(supervisor)
    with pytest.raises(SupervisorError) as error:
        supervisor.quarantine_recover(attempt["id"], "delete-everything")
    assert error.value.code == "quarantine_action_invalid"


def test_recover_rejects_an_unknown_attempt(driver_repo: Path) -> None:
    supervisor = GitSupervisor(driver_repo)
    with pytest.raises(SupervisorError) as error:
        supervisor.quarantine_recover("no-such-attempt", "retry-cleanup")
    assert error.value.code == "attempt_not_found"
