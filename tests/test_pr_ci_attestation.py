from __future__ import annotations

import io
import json
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / ".github" / "scripts" / "pr_ci_attestation.py"
SPEC = spec_from_file_location("pr_ci_attestation", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ATTESTATION = module_from_spec(SPEC)
SPEC.loader.exec_module(ATTESTATION)

BASE_SHA = "1" * 40
HEAD_SHA = "2" * 40
MERGE_SHA = "3" * 40
ADVANCED_SHA = "4" * 40
PR49_OLD_BASE = "e112b2ec463958251cec5fb9486309e9b2ed8ef3"
PR49_MID_BASE = "cf3e9383f7f5931faf0f1324b83019306b319fcb"
PR49_HEAD = "543506e1b232dae9cbab82982f871f7accbe1a9e"
PR49_OLD_MERGE = "fe79f60d84b45621937e64868a453786bc54bba0"
PR49_MID_MERGE = "e7779a8ca475c410a10452854e938d14ad38417d"
PR49_LIVE_BASE = "71d2b94eae2054587a339af76fea07f68f9d9635"


def event_payload() -> dict:
    return {
        "pull_request": {
            "number": 42,
            "base": {
                "repo": {"id": 101, "full_name": "acme/control-plane"},
                "ref": "main",
                "sha": BASE_SHA,
            },
            "head": {
                "repo": {"id": 101, "full_name": "acme/control-plane"},
                "ref": "feature/fix",
                "sha": HEAD_SHA,
            },
        }
    }


def run_env(**updates: str) -> dict[str, str]:
    env = {
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY_ID": "101",
        "GITHUB_REPOSITORY": "acme/control-plane",
        "GITHUB_SHA": MERGE_SHA,
        "GITHUB_WORKFLOW": "CI",
        "GITHUB_WORKFLOW_REF": "acme/control-plane/.github/workflows/ci.yml@refs/heads/main",
        "GITHUB_RUN_ID": "9001",
        "GITHUB_RUN_ATTEMPT": "1",
        "CI_JOB_RESULT": "success",
    }
    env.update(updates)
    return env


def stable_lookup(base_sha: str = BASE_SHA, head_sha: str = HEAD_SHA):
    values = iter([base_sha, head_sha, base_sha, head_sha])
    return lambda _repository, _ref: next(values)


def current_pull_request(event: dict | None = None) -> dict:
    pr = (event if event is not None else event_payload())["pull_request"]
    return {
        "number": pr["number"],
        "state": "open",
        "base": {
            "repo": pr["base"]["repo"],
            "ref": pr["base"]["ref"],
            # GitHub's base.sha may lag the live target ref and is not authoritative.
            "sha": "9" * 40,
        },
        "head": {
            "repo": pr["head"]["repo"],
            "ref": pr["head"]["ref"],
            "sha": pr["head"]["sha"],
        },
    }


def evaluate(
    *,
    event: dict | None = None,
    env: dict[str, str] | None = None,
    checkout_sha: str = MERGE_SHA,
    parents: list[str] | None = None,
    ref_lookup=None,
    pull_request_lookup=None,
):
    return ATTESTATION.evaluate_attestation(
        event if event is not None else event_payload(),
        env if env is not None else run_env(),
        checkout_sha,
        parents if parents is not None else [BASE_SHA, HEAD_SHA],
        ref_lookup if ref_lookup is not None else stable_lookup(),
        pull_request_lookup=(
            pull_request_lookup
            if pull_request_lookup is not None
            else lambda _repository, _number: current_pull_request(
                event if event is not None else event_payload()
            )
        ),
        checked_at="2026-10-21T12:00:00Z",
    )


def test_same_repository_pr_is_fresh_for_exact_merge_pair():
    report = evaluate()

    assert report["status"] == "fresh"
    assert report["reason"] == "exact_pair_matches_live_refs"
    assert report["target"] == {
        "repository_id": 101,
        "repository": "acme/control-plane",
        "pr_number": 42,
    }
    assert report["checkout"]["parents"] == [BASE_SHA, HEAD_SHA]
    assert report["workflow"]["run_attempt"] == 1


def test_fork_pr_resolves_head_repository_and_ref_separately():
    event = event_payload()
    event["pull_request"]["head"]["repo"] = {
        "id": 202,
        "full_name": "contributor/control-plane",
    }
    calls: list[tuple[str, str]] = []

    def lookup(repository: str, ref: str) -> str:
        calls.append((repository, ref))
        return HEAD_SHA if repository.startswith("contributor/") else BASE_SHA

    report = evaluate(event=event, ref_lookup=lookup)

    assert report["status"] == "fresh"
    assert report["head"]["repository_id"] == 202
    assert report["head"]["repository"] == "contributor/control-plane"
    assert calls == [
        ("acme/control-plane", "main"),
        ("contributor/control-plane", "feature/fix"),
        ("acme/control-plane", "main"),
        ("contributor/control-plane", "feature/fix"),
    ]


def test_stacked_pr_uses_event_base_branch_not_default_branch():
    event = event_payload()
    parent_pr_sha = "5" * 40
    event["pull_request"]["base"]["ref"] = "agent/parent-pr"
    event["pull_request"]["base"]["sha"] = parent_pr_sha
    calls: list[tuple[str, str]] = []

    def lookup(repository: str, ref: str) -> str:
        calls.append((repository, ref))
        return parent_pr_sha if ref == "agent/parent-pr" else HEAD_SHA

    report = evaluate(
        event=event,
        parents=[parent_pr_sha, HEAD_SHA],
        ref_lookup=lookup,
    )

    assert report["status"] == "fresh"
    assert report["base"]["ref"] == "agent/parent-pr"
    assert calls[0] == ("acme/control-plane", "agent/parent-pr")


def test_base_advanced_before_evaluation_is_stale():
    report = evaluate(ref_lookup=stable_lookup(ADVANCED_SHA, HEAD_SHA))

    assert report["status"] == "stale"
    assert report["reason"] == "event_pair_is_not_live"
    assert report["base"]["live_sha"] == ADVANCED_SHA


def test_base_advanced_between_snapshots_is_stale():
    values = iter([BASE_SHA, HEAD_SHA, ADVANCED_SHA, HEAD_SHA])
    report = evaluate(ref_lookup=lambda _repository, _ref: next(values))

    assert report["status"] == "stale"
    assert report["reason"] == "live_refs_changed_during_evaluation"
    assert report["live_ref_snapshots"][0]["base_sha"] == BASE_SHA
    assert report["live_ref_snapshots"][1]["base_sha"] == ADVANCED_SHA


def test_head_advanced_between_snapshots_is_stale():
    values = iter([BASE_SHA, HEAD_SHA, BASE_SHA, ADVANCED_SHA])
    report = evaluate(ref_lookup=lambda _repository, _ref: next(values))

    assert report["status"] == "stale"
    assert report["reason"] == "live_refs_changed_during_evaluation"
    assert report["head"]["live_sha"] == ADVANCED_SHA


def test_retargeted_pr_is_stale_before_live_ref_lookup():
    event = event_payload()
    current = current_pull_request(event)
    current["base"]["ref"] = "agent/new-parent"
    calls = []

    report = evaluate(
        event=event,
        ref_lookup=lambda *_args: calls.append("ref") or BASE_SHA,
        pull_request_lookup=lambda *_args: current,
    )

    assert report["status"] == "stale"
    assert report["reason"] == "pull_request_metadata_changed"
    assert calls == []


def test_retarget_during_live_ref_checks_is_stale():
    event = event_payload()
    current = current_pull_request(event)
    snapshots = iter(
        [current, {**current, "base": {**current["base"], "ref": "other"}}]
    )

    report = evaluate(
        event=event,
        pull_request_lookup=lambda *_args: next(snapshots),
    )

    assert report["status"] == "stale"
    assert report["reason"] == "pull_request_changed_during_evaluation"
    assert len(report["live_ref_snapshots"]) == 2
    assert len(report["pull_request_snapshots"]) == 2
    assert report["pull_request_snapshots"][1]["base_ref"] == "other"


def test_pr_closed_during_live_ref_checks_is_stale_and_records_second_snapshot():
    current = current_pull_request()
    closed = {**current, "state": "closed"}
    snapshots = iter([current, closed])

    report = evaluate(pull_request_lookup=lambda *_args: next(snapshots))

    assert report["status"] == "stale"
    assert report["reason"] == "pull_request_changed_during_evaluation"
    assert [row["state"] for row in report["pull_request_snapshots"]] == [
        "open",
        "closed",
    ]


def test_closed_pr_is_stale_before_live_ref_lookup():
    current = current_pull_request()
    current["state"] = "closed"
    calls = []

    report = evaluate(
        pull_request_lookup=lambda *_args: current,
        ref_lookup=lambda *_args: calls.append("ref") or BASE_SHA,
    )

    assert report["status"] == "stale"
    assert report["reason"] == "pull_request_not_open"
    assert calls == []


def test_missing_event_sha_fails_closed_without_live_lookup():
    event = event_payload()
    del event["pull_request"]["head"]["sha"]

    report = evaluate(event=event)

    assert report["status"] == "invalid"
    assert report["reason"] == "missing_head_sha"
    assert report["live_ref_snapshots"] == []


def test_fractional_repository_ids_are_not_silently_truncated():
    event = event_payload()
    event["pull_request"]["head"]["repo"]["id"] = 202.5

    report = evaluate(event=event)

    assert report["status"] == "invalid"
    assert report["reason"] == "invalid_repository_id"


def test_wrong_synthetic_merge_parents_fail_closed():
    report = evaluate(parents=[HEAD_SHA, BASE_SHA])

    assert report["status"] == "invalid"
    assert report["reason"] == "merge_parent_mismatch"


def test_checkout_must_match_reported_event_merge_sha():
    report = evaluate(checkout_sha=ADVANCED_SHA)

    assert report["status"] == "invalid"
    assert report["reason"] == "checkout_sha_mismatch"


def test_rerun_attempt_is_recorded_without_changing_pair_verdict():
    report = evaluate(env=run_env(GITHUB_RUN_ATTEMPT="2"))

    assert report["status"] == "fresh"
    assert report["workflow"]["run_id"] == "9001"
    assert report["workflow"]["run_attempt"] == 2


def test_pr49_historical_green_pair_is_stale_against_later_base():
    event = event_payload()
    event["pull_request"]["base"]["sha"] = PR49_OLD_BASE
    event["pull_request"]["head"]["sha"] = PR49_HEAD
    env = run_env(GITHUB_SHA=PR49_OLD_MERGE)
    live = iter([PR49_MID_BASE, PR49_HEAD, PR49_MID_BASE, PR49_HEAD])

    report = evaluate(
        event=event,
        env=env,
        checkout_sha=PR49_OLD_MERGE,
        parents=[PR49_OLD_BASE, PR49_HEAD],
        ref_lookup=lambda _repository, _ref: next(live),
    )

    assert report["status"] == "stale"
    assert report["reason"] == "event_pair_is_not_live"


def test_pr49_observed_merge_ref_is_stale_after_parent_branch_advances():
    event = event_payload()
    event["pull_request"]["base"]["sha"] = PR49_MID_BASE
    event["pull_request"]["head"]["sha"] = PR49_HEAD
    env = run_env(GITHUB_SHA=PR49_MID_MERGE)
    live = iter([PR49_LIVE_BASE, PR49_HEAD, PR49_LIVE_BASE, PR49_HEAD])

    report = evaluate(
        event=event,
        env=env,
        checkout_sha=PR49_MID_MERGE,
        parents=[PR49_MID_BASE, PR49_HEAD],
        ref_lookup=lambda _repository, _ref: next(live),
    )

    assert report["status"] == "stale"
    assert report["reason"] == "event_pair_is_not_live"
    assert report["base"]["live_sha"] == PR49_LIVE_BASE


def test_pr49_prospective_rerun_pair_is_fresh_for_latest_live_base():
    event = event_payload()
    event["pull_request"]["base"]["sha"] = PR49_LIVE_BASE
    event["pull_request"]["head"]["sha"] = PR49_HEAD
    new_merge = "6" * 40
    env = run_env(GITHUB_SHA=new_merge)

    report = evaluate(
        event=event,
        env=env,
        checkout_sha=new_merge,
        parents=[PR49_LIVE_BASE, PR49_HEAD],
        ref_lookup=stable_lookup(PR49_LIVE_BASE, PR49_HEAD),
    )

    assert report["status"] == "fresh"
    assert report["checkout"]["parents"] == [PR49_LIVE_BASE, PR49_HEAD]


def test_unsupported_privileged_event_is_rejected():
    report = evaluate(env=run_env(GITHUB_EVENT_NAME="pull_request_target"))

    assert report["status"] == "invalid"
    assert report["reason"] == "unsupported_event"


def test_freshness_is_separate_from_failed_ci_matrix_result(tmp_path):
    report = evaluate(env=run_env(CI_JOB_RESULT="failure"))
    summary_path = tmp_path / "summary.md"
    ATTESTATION._write_report(
        report,
        {
            "GITHUB_STEP_SUMMARY": str(summary_path),
            "PR_CI_ATTESTATION_PATH": str(tmp_path / "attestation.json"),
        },
    )

    summary = summary_path.read_text(encoding="utf-8")
    assert report["status"] == "fresh"
    assert report["ci"]["test_matrix_job_result"] == "failure"
    assert "Result: **FRESH**" in summary
    assert "CI test/build matrix job result: **failure**" in summary


def test_missing_ci_matrix_result_is_operator_visible_as_unknown(tmp_path):
    report = evaluate(env=run_env(CI_JOB_RESULT=""))
    summary_path = tmp_path / "summary.md"
    ATTESTATION._write_report(
        report,
        {
            "GITHUB_STEP_SUMMARY": str(summary_path),
            "PR_CI_ATTESTATION_PATH": str(tmp_path / "attestation.json"),
        },
    )

    assert report["ci"]["test_matrix_job_result"] == ""
    assert "CI test/build matrix job result: **UNKNOWN**" in summary_path.read_text(
        encoding="utf-8"
    )


def test_summary_escapes_untrusted_html_from_branch_names(tmp_path):
    event = event_payload()
    event["pull_request"]["head"]["ref"] = "feature/<img src=x>"
    report = evaluate(event=event)
    summary_path = tmp_path / "summary.md"
    ATTESTATION._write_report(
        report,
        {
            "GITHUB_STEP_SUMMARY": str(summary_path),
            "PR_CI_ATTESTATION_PATH": str(tmp_path / "attestation.json"),
        },
    )

    summary = summary_path.read_text(encoding="utf-8")
    assert "&lt;img" in summary
    assert "<img" not in summary


def test_fetch_github_ref_encodes_nested_branch_refs(monkeypatch):
    requests = []

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.close()

    def fake_urlopen(request, timeout):
        requests.append((request, timeout))
        return Response(json.dumps({"object": {"sha": HEAD_SHA}}).encode())

    monkeypatch.setattr(ATTESTATION, "urlopen", fake_urlopen)

    assert (
        ATTESTATION.fetch_github_ref(
            "acme/control-plane", "agent/parent-pr", token="read-only-token"
        )
        == HEAD_SHA
    )
    assert requests[0][0].full_url.endswith("/heads/agent%2Fparent-pr")
    assert requests[0][1] == 10


def test_fetch_github_ref_hides_api_error_body_and_credentials(monkeypatch):
    def fail_urlopen(request, timeout):
        raise ATTESTATION.HTTPError(
            request.full_url,
            404,
            "not found",
            {},
            io.BytesIO(b"sensitive response body"),
        )

    monkeypatch.setattr(ATTESTATION, "urlopen", fail_urlopen)

    with pytest.raises(ATTESTATION.AttestationProblem) as error:
        ATTESTATION.fetch_github_ref(
            "contributor/control-plane", "feature/fix", token="secret-token"
        )

    assert error.value.code == "live_ref_unavailable"
    assert "secret-token" not in str(error.value)
    assert "sensitive response body" not in str(error.value)


def test_inaccessible_fork_ref_fails_closed():
    event = event_payload()
    event["pull_request"]["head"]["repo"] = {
        "id": 202,
        "full_name": "contributor/control-plane",
    }

    def lookup(repository: str, _ref: str) -> str:
        if repository.startswith("contributor/"):
            raise ATTESTATION.AttestationProblem("live_ref_unavailable")
        return BASE_SHA

    report = evaluate(event=event, ref_lookup=lookup)

    assert report["status"] == "invalid"
    assert report["reason"] == "live_ref_unavailable"


def test_main_writes_fresh_report_and_records_failure_of_test_matrix(
    tmp_path, monkeypatch, capsys
):
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps(event_payload()), encoding="utf-8")
    report_path = tmp_path / "attestation.json"
    summary_path = tmp_path / "summary.md"
    tested_workspace = tmp_path / "tested"
    tested_workspace.mkdir()
    env = run_env(CI_JOB_RESULT="failure")
    env.update(
        GITHUB_EVENT_PATH=str(event_path),
        GITHUB_WORKSPACE=str(tmp_path),
        PR_CI_TESTED_WORKSPACE=str(tested_workspace),
        PR_CI_ATTESTATION_PATH=str(report_path),
        GITHUB_STEP_SUMMARY=str(summary_path),
        GITHUB_TOKEN="read-only-token",
    )
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    def checkout_metadata(workspace):
        assert workspace == str(tested_workspace)
        return MERGE_SHA, [BASE_SHA, HEAD_SHA]

    monkeypatch.setattr(ATTESTATION, "_checkout_metadata", checkout_metadata)

    def lookup(repository, ref, *, token, api_url):
        assert token == "read-only-token"
        if repository == "acme/control-plane" and ref == "main":
            return BASE_SHA
        if repository == "acme/control-plane" and ref == "feature/fix":
            return HEAD_SHA
        raise AssertionError("unexpected ref lookup")

    monkeypatch.setattr(ATTESTATION, "fetch_github_ref", lookup)
    monkeypatch.setattr(
        ATTESTATION,
        "fetch_github_pull_request",
        lambda *_args, **_kwargs: current_pull_request(),
    )

    assert ATTESTATION.main() == 1
    result = json.loads(report_path.read_text(encoding="utf-8"))
    assert result["status"] == "fresh"
    assert result["ci"]["test_matrix_job_result"] == "failure"
    assert "secret" not in capsys.readouterr().out
    summary = summary_path.read_text(encoding="utf-8")
    assert "CI test/build matrix job result: **failure**" in summary
    assert r"Event/workflow: pull\_request / CI" in summary
    assert "Workflow ref:" in summary


def test_main_fails_closed_and_writes_report_for_wrong_merge_parents(
    tmp_path, monkeypatch
):
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps(event_payload()), encoding="utf-8")
    report_path = tmp_path / "attestation.json"
    summary_path = tmp_path / "summary.md"
    env = run_env()
    env.update(
        GITHUB_EVENT_PATH=str(event_path),
        GITHUB_WORKSPACE=str(tmp_path),
        PR_CI_ATTESTATION_PATH=str(report_path),
        GITHUB_STEP_SUMMARY=str(summary_path),
    )
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(
        ATTESTATION,
        "_checkout_metadata",
        lambda _workspace: (MERGE_SHA, [HEAD_SHA, BASE_SHA]),
    )
    monkeypatch.setattr(
        ATTESTATION,
        "fetch_github_ref",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("bad merge parents must short-circuit live lookup")
        ),
    )

    assert ATTESTATION.main() == 1
    result = json.loads(report_path.read_text(encoding="utf-8"))
    assert result["status"] == "invalid"
    assert result["reason"] == "merge_parent_mismatch"
    assert "Result: **INVALID**" in summary_path.read_text(encoding="utf-8")


def test_main_returns_success_only_for_fresh_pair_and_successful_matrix(
    tmp_path, monkeypatch
):
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps(event_payload()), encoding="utf-8")
    report_path = tmp_path / "attestation.json"
    env = run_env(CI_JOB_RESULT="success")
    env.update(
        GITHUB_EVENT_PATH=str(event_path),
        GITHUB_WORKSPACE=str(tmp_path),
        PR_CI_ATTESTATION_PATH=str(report_path),
        GITHUB_TOKEN="read-only-token",
    )
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(
        ATTESTATION,
        "_checkout_metadata",
        lambda _workspace: (MERGE_SHA, [BASE_SHA, HEAD_SHA]),
    )
    monkeypatch.setattr(
        ATTESTATION,
        "fetch_github_ref",
        lambda _repo, ref, **_kwargs: BASE_SHA if ref == "main" else HEAD_SHA,
    )
    monkeypatch.setattr(
        ATTESTATION,
        "fetch_github_pull_request",
        lambda *_args, **_kwargs: current_pull_request(),
    )

    assert ATTESTATION.main() == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"] == "fresh"
    assert report["ci"]["test_matrix_job_result"] == "success"


def test_fetch_github_pull_request_uses_read_only_pr_endpoint(monkeypatch):
    requests = []

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.close()

    def fake_urlopen(request, timeout):
        requests.append((request, timeout))
        return Response(json.dumps({"number": 42, "state": "open"}).encode())

    monkeypatch.setattr(ATTESTATION, "urlopen", fake_urlopen)

    result = ATTESTATION.fetch_github_pull_request(
        "acme/control-plane", 42, token="read-only-token"
    )

    assert result == {"number": 42, "state": "open"}
    assert requests[0][0].full_url.endswith("/repos/acme/control-plane/pulls/42")
    assert requests[0][0].get_header("Authorization") == "Bearer read-only-token"
    assert requests[0][1] == 10
