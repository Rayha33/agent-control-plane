from __future__ import annotations

import json
from pathlib import Path

import pytest
from support import commit_change, git, init_repo, make_task

from agent_control_plane.assurance import wilson_interval
from agent_control_plane.git_supervisor import GitSupervisor, SupervisorError


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return init_repo(tmp_path)


def write_assurance_config(
    repo: Path,
    reviewers: dict[str, dict[str, str]] | None = None,
    high_risk_paths: list[str] | None = None,
    high_risk_mode: str = "off",
    require_provider_diversity: bool = False,
    golden_dir: str = "acp-golden",
    qc_commands: list[str] | None = None,
) -> None:
    commands = json.dumps(qc_commands or ["python -c 'pass'"])
    reviewers = reviewers or {}
    blocks = ""
    for identity, entry in sorted(reviewers.items()):
        blocks += f'\n[reviewers."{identity}"]\n'
        for key, value in sorted(entry.items()):
            blocks += f'{key} = "{value}"\n'
    (repo / "acp.toml").write_text(
        "[supervisor]\n"
        "lease_seconds = 60\n"
        "qc_timeout_seconds = 30\n"
        'critic_identity = "independent-qc"\n'
        "require_critic = false\n\n"
        "[qc]\n"
        f"commands = {commands}\n"
        'critic_command = "builtin"\n\n'
        "[integration]\n"
        f"commands = {commands}\n\n"
        "[runtime]\n"
        "setup_commands = []\n"
        "teardown_commands = []\n\n"
        "[policy]\n"
        f"high_risk_paths = {json.dumps(high_risk_paths or [])}\n"
        f'high_risk_mode = "{high_risk_mode}"\n'
        f"require_provider_diversity = {str(require_provider_diversity).lower()}\n\n"
        "[calibration]\n"
        f'golden_dir = "{golden_dir}"\n' + blocks,
        encoding="utf-8",
    )


def golden_case(
    repo: Path, name: str, expect: str, mutations: str = "", directory: str = "acp-golden"
) -> None:
    folder = repo / directory
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{name}.toml").write_text(
        f'name = "{name}"\nexpect = "{expect}"\ndescription = "seeded"\n{mutations}',
        encoding="utf-8",
    )


def submit_for_review(supervisor: GitSupervisor, path: str = "alpha.txt") -> dict:
    created = make_task(supervisor, path, title="under review")
    attempt = supervisor.claim(created["id"], "worker-agent")
    commit_change(attempt, path, "reviewed change\n")
    return supervisor.submit(attempt["id"], attempt["claim_token"])


def submit_authenticated(supervisor: GitSupervisor, credential: str, path: str) -> dict:
    created = make_task(supervisor, path, title="authenticated review")
    attempt = supervisor.claim(created["id"], "worker-agent", credential=credential)
    commit_change(attempt, path, "authenticated change\n")
    return supervisor.submit(attempt["id"], attempt["claim_token"], credential)


# --------------------------------------------------------------------- provenance


def test_qc_records_signed_reviewer_provenance(repo: Path) -> None:
    write_assurance_config(
        repo,
        reviewers={
            "independent-qc": {
                "provider": "builtin",
                "model": "structural-v1",
                "prompt_policy": "policy-2026-08",
                "command": "builtin",
            }
        },
    )
    supervisor = GitSupervisor(repo)
    submission = submit_for_review(supervisor)

    review = supervisor.run_qc(submission["id"], "independent-qc")

    provenance = review["reviewer_provenance"]
    assert provenance["provider"] == "builtin"
    assert provenance["model"] == "structural-v1"
    assert provenance["prompt_policy"] == "policy-2026-08"
    assert provenance["command_sha256"]
    assert review["policy_fingerprint"] == supervisor.assurance_policy.fingerprint
    assert review["reviewer_signature"]


def test_reproduction_bundle_is_written_and_signature_verifies(repo: Path) -> None:
    write_assurance_config(repo)
    supervisor = GitSupervisor(repo)
    submission = submit_for_review(supervisor)
    review = supervisor.run_qc(submission["id"], "independent-qc")

    found = supervisor.reproduction_bundle(review["id"])

    assert found["signature_valid"] is True
    bundle = found["bundle"]
    assert bundle["commit_sha"] == submission["commit_sha"]
    assert bundle["verdict"] == review["verdict"]
    assert bundle["reviewer"]["identity"] == "independent-qc"
    assert any("git worktree add --detach" in step for step in bundle["replay"])
    assert bundle["environment"]["git"].startswith("git version")


def test_tampering_with_a_bundle_breaks_its_signature(repo: Path) -> None:
    write_assurance_config(repo)
    supervisor = GitSupervisor(repo)
    submission = submit_for_review(supervisor)
    review = supervisor.run_qc(submission["id"], "independent-qc")
    path = repo / ".acp" / "bundles" / f"{review['id']}.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    record["verdict"] = "pass-but-forged"
    path.write_text(json.dumps(record), encoding="utf-8")

    assert supervisor.reproduction_bundle(review["id"])["signature_valid"] is False


# ------------------------------------------------------------------- ratification


def test_a_reviewer_upgrade_blocks_qc_until_it_is_ratified(repo: Path) -> None:
    write_assurance_config(
        repo, reviewers={"independent-qc": {"provider": "builtin", "model": "v1"}}
    )
    supervisor = GitSupervisor(repo)
    first = submit_for_review(supervisor, "alpha.txt")
    assert supervisor.run_qc(first["id"], "independent-qc")["verdict"] == "pass"
    original = supervisor.assurance_policy.fingerprint

    # Silently "upgrade" the model behind the same reviewer identity.
    write_assurance_config(
        repo, reviewers={"independent-qc": {"provider": "builtin", "model": "v2"}}
    )
    upgraded = GitSupervisor(repo)
    second = submit_for_review(upgraded, "beta.txt")

    with pytest.raises(SupervisorError) as blocked:
        upgraded.run_qc(second["id"], "independent-qc")
    assert blocked.value.code == "reviewer_policy_changed"
    assert upgraded.reviewers()["ratified"] is False

    ratified = upgraded.ratify_reviewers()

    assert ratified["changed"] is True
    assert ratified["previous_fingerprint"] == original
    assert upgraded.run_qc(second["id"], "independent-qc")["verdict"] == "pass"


def test_first_policy_is_adopted_and_recorded(repo: Path) -> None:
    write_assurance_config(repo)
    supervisor = GitSupervisor(repo)

    assert supervisor.reviewers()["ratified"] is False
    submission = submit_for_review(supervisor)
    supervisor.run_qc(submission["id"], "independent-qc")

    state = supervisor.reviewers()
    assert state["ratified"] is True
    assert state["ratified_fingerprint"] == supervisor.assurance_policy.fingerprint
    assert supervisor.verify_event_chain()["ok"] is True


def test_ratification_requires_integrator_and_old_policy_passes_do_not_carry_forward(
    repo: Path,
) -> None:
    reviewers_v1 = {
        "independent-qc": {"provider": "vendor-a", "model": "v1"},
        "second-opinion": {"provider": "vendor-b", "model": "v1"},
    }
    write_assurance_config(
        repo,
        reviewers=reviewers_v1,
        high_risk_paths=["alpha.txt"],
        high_risk_mode="two_reviewer",
        require_provider_diversity=True,
    )
    supervisor = GitSupervisor(repo)
    worker = supervisor.enroll_runner("worker-agent", "worker")
    first_critic = supervisor.enroll_runner("independent-qc", "critic")
    second_critic = supervisor.enroll_runner("second-opinion", "critic")
    integrator = supervisor.enroll_runner("release-integrator", "integrator")
    submission = submit_authenticated(supervisor, worker["credential"], "alpha.txt")
    supervisor.run_qc(submission["id"], "independent-qc", credential=first_critic["credential"])

    reviewers_v2 = {
        **reviewers_v1,
        "independent-qc": {"provider": "vendor-a", "model": "v2"},
    }
    write_assurance_config(
        repo,
        reviewers=reviewers_v2,
        high_risk_paths=["alpha.txt"],
        high_risk_mode="two_reviewer",
        require_provider_diversity=True,
    )
    upgraded = GitSupervisor(repo)

    with pytest.raises(SupervisorError) as unauthenticated:
        upgraded.ratify_reviewers("release-integrator")
    assert unauthenticated.value.code == "runner_authentication_failed"
    upgraded.ratify_reviewers("release-integrator", integrator["credential"])
    upgraded.run_qc(submission["id"], "second-opinion", credential=second_critic["credential"])

    # The first review used v1. It cannot combine with B's v2-policy review.
    assert upgraded.submission(submission["id"])["status"] == "pending_second_review"


def test_policy_change_during_qc_discards_the_inflight_verdict(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_assurance_config(
        repo, reviewers={"independent-qc": {"provider": "builtin", "model": "v1"}}
    )
    supervisor = GitSupervisor(repo)
    worker = supervisor.enroll_runner("worker-agent", "worker")
    critic = supervisor.enroll_runner("independent-qc", "critic")
    integrator = supervisor.enroll_runner("release-integrator", "integrator")
    submission = submit_authenticated(supervisor, worker["credential"], "alpha.txt")

    original = supervisor._run_command
    changed = False

    def change_policy_during_gate(*args: object, **kwargs: object) -> dict:
        nonlocal changed
        result = original(*args, **kwargs)
        if not changed:
            changed = True
            write_assurance_config(
                repo,
                reviewers={"independent-qc": {"provider": "builtin", "model": "v2"}},
            )
            GitSupervisor(repo).ratify_reviewers("release-integrator", integrator["credential"])
        return result

    monkeypatch.setattr(supervisor, "_run_command", change_policy_during_gate)

    with pytest.raises(SupervisorError) as stale:
        supervisor.run_qc(submission["id"], "independent-qc", credential=critic["credential"])
    assert stale.value.code == "reviewer_policy_changed"
    assert supervisor.submission(submission["id"])["status"] == "pending_qc"


def test_integration_and_merge_plan_reject_approval_from_stale_policy(repo: Path) -> None:
    write_assurance_config(
        repo, reviewers={"independent-qc": {"provider": "builtin", "model": "v1"}}
    )
    supervisor = GitSupervisor(repo)
    worker = supervisor.enroll_runner("worker-agent", "worker")
    critic = supervisor.enroll_runner("independent-qc", "critic")
    integrator = supervisor.enroll_runner("release-integrator", "integrator")
    submission = submit_authenticated(supervisor, worker["credential"], "alpha.txt")
    supervisor.run_qc(submission["id"], "independent-qc", credential=critic["credential"])

    write_assurance_config(
        repo, reviewers={"independent-qc": {"provider": "builtin", "model": "v2"}}
    )
    upgraded = GitSupervisor(repo)
    task_id = submission["task_id"]

    with pytest.raises(SupervisorError) as stale:
        upgraded.integrate(task_id, "release-integrator", integrator["credential"])
    assert stale.value.code == "reviewer_policy_changed"
    plan = upgraded.merge_plan()
    assert plan["count"] == 0
    assert plan["excluded"][0]["blocker"] == "reviewer_policy_changed"


# --------------------------------------------------------------------- high risk


def test_high_risk_change_needs_a_second_reviewer_from_another_provider(repo: Path) -> None:
    write_assurance_config(
        repo,
        reviewers={
            "independent-qc": {"provider": "builtin", "model": "v1"},
            "second-opinion": {"provider": "other-vendor", "model": "v9"},
        },
        high_risk_paths=["alpha.txt"],
        high_risk_mode="two_reviewer",
        require_provider_diversity=True,
    )
    supervisor = GitSupervisor(repo)
    submission = submit_for_review(supervisor, "alpha.txt")

    first = supervisor.run_qc(submission["id"], "independent-qc")

    assert first["verdict"] == "pass"
    assert supervisor.submission(submission["id"])["status"] == "pending_second_review"
    task_id = supervisor.submission(submission["id"])["task_id"]
    assert supervisor.task(task_id)["status"] == "qc_review"
    with pytest.raises(SupervisorError) as premature:
        supervisor.integrate(task_id)
    assert premature.value.code == "qc_gate_not_passed"

    second = supervisor.run_qc(submission["id"], "second-opinion")

    assert second["verdict"] == "pass"
    assert supervisor.submission(submission["id"])["status"] == "approved"


def test_same_reviewer_twice_cannot_satisfy_the_two_reviewer_rule(repo: Path) -> None:
    write_assurance_config(
        repo,
        reviewers={
            "independent-qc": {"provider": "builtin", "model": "v1"},
            "second-opinion": {"provider": "other-vendor", "model": "v9"},
        },
        high_risk_paths=["alpha.txt"],
        high_risk_mode="two_reviewer",
    )
    supervisor = GitSupervisor(repo)
    submission = submit_for_review(supervisor, "alpha.txt")

    supervisor.run_qc(submission["id"], "independent-qc")
    supervisor.run_qc(submission["id"], "independent-qc")

    assert supervisor.submission(submission["id"])["status"] == "pending_second_review"


def test_low_risk_change_is_approved_by_one_reviewer(repo: Path) -> None:
    write_assurance_config(
        repo,
        reviewers={
            "independent-qc": {"provider": "builtin", "model": "v1"},
            "second-opinion": {"provider": "other-vendor", "model": "v9"},
        },
        high_risk_paths=["src/auth/**"],
        high_risk_mode="two_reviewer",
    )
    supervisor = GitSupervisor(repo)
    submission = submit_for_review(supervisor, "alpha.txt")

    supervisor.run_qc(submission["id"], "independent-qc")

    assert supervisor.submission(submission["id"])["status"] == "approved"


def test_human_mode_holds_a_high_risk_change_for_a_person(repo: Path) -> None:
    write_assurance_config(
        repo,
        reviewers={"independent-qc": {"provider": "builtin", "model": "v1"}},
        high_risk_paths=["alpha.txt"],
        high_risk_mode="human",
    )
    supervisor = GitSupervisor(repo)
    submission = submit_for_review(supervisor, "alpha.txt")

    review = supervisor.run_qc(submission["id"], "independent-qc")

    assert review["verdict"] == "pass"
    assert supervisor.submission(submission["id"])["status"] == "human_required"
    assert any(
        "human approval" in item["finding"] for item in supervisor.qc_run(review["id"])["findings"]
    )


def test_provider_diversity_config_needs_two_providers(repo: Path) -> None:
    write_assurance_config(
        repo,
        reviewers={
            "independent-qc": {"provider": "builtin", "model": "v1"},
            "second-opinion": {"provider": "builtin", "model": "v9"},
        },
        high_risk_paths=["alpha.txt"],
        high_risk_mode="two_reviewer",
        require_provider_diversity=True,
    )

    with pytest.raises(SupervisorError) as invalid:
        GitSupervisor(repo)

    assert invalid.value.code == "invalid_config"


# ------------------------------------------------------------------- calibration


def test_calibration_catches_a_seeded_defect_and_reports_intervals(repo: Path) -> None:
    write_assurance_config(repo)
    golden_case(
        repo,
        "conflict-markers",
        "reject",
        mutations=(
            "[[mutations]]\n"
            'path = "alpha.txt"\n'
            'content = "<<<<<<< HEAD\\nours\\n=======\\ntheirs\\n>>>>>>> branch\\n"\n'
        ),
    )
    golden_case(
        repo,
        "clean-change",
        "pass",
        mutations='[[mutations]]\npath = "beta.txt"\ncontent = "a harmless edit\\n"\n',
    )
    supervisor = GitSupervisor(repo)

    report = supervisor.calibrate()

    by_name = {item["name"]: item for item in report["results"]}
    assert by_name["conflict-markers"]["rejected"] is True
    assert by_name["conflict-markers"]["correct"] is True
    assert by_name["clean-change"]["rejected"] is False
    summary = report["summary"]
    assert summary["seeded_defects"] == 1
    assert summary["caught_defects"] == 1
    assert summary["false_pass"]["rate"] == 0.0
    assert summary["false_pass"]["high"] > 0.0  # one sample cannot prove certainty
    assert summary["false_block"]["samples"] == 1
    assert summary["missed_cases"] == []
    assert report["policy_fingerprint"] == supervisor.assurance_policy.fingerprint


def test_calibration_reports_a_missed_defect_as_a_false_pass(repo: Path) -> None:
    write_assurance_config(repo)
    golden_case(
        repo,
        "subtle-logic-bug",
        "reject",
        mutations='[[mutations]]\npath = "alpha.txt"\ncontent = "return not valid\\n"\n',
    )
    supervisor = GitSupervisor(repo)

    summary = supervisor.calibrate()["summary"]

    assert summary["caught_defects"] == 0
    assert summary["false_pass"]["rate"] == 1.0
    assert summary["missed_cases"] == ["subtle-logic-bug"]


def test_calibration_leaves_no_worktrees_behind(repo: Path) -> None:
    write_assurance_config(repo)
    golden_case(
        repo,
        "clean",
        "pass",
        mutations='[[mutations]]\npath = "beta.txt"\ncontent = "edit\\n"\n',
    )
    supervisor = GitSupervisor(repo)

    supervisor.calibrate()

    assert "golden-" not in git(repo, "worktree", "list")
    assert not list((repo / ".acp" / "worktrees").glob("golden-*"))
    # the calibration mutated beta.txt inside a throwaway worktree, never here
    assert (repo / "beta.txt").read_text(encoding="utf-8") == "base\n"


def test_calibration_without_golden_cases_is_an_explicit_error(repo: Path) -> None:
    write_assurance_config(repo)
    supervisor = GitSupervisor(repo)

    with pytest.raises(SupervisorError) as missing:
        supervisor.calibrate()

    assert missing.value.code == "no_golden_cases"


def test_wilson_interval_widens_on_small_samples() -> None:
    small = wilson_interval(0, 1)
    large = wilson_interval(0, 100)

    assert small["rate"] == large["rate"] == 0.0
    assert small["high"] > large["high"]
    assert wilson_interval(0, 0)["high"] == 1.0
    assert 0.0 <= wilson_interval(5, 10)["low"] <= 0.5 <= wilson_interval(5, 10)["high"] <= 1.0
