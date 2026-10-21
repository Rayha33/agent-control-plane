"""Fail-closed freshness report for GitHub pull-request CI runs.

This is a read-only reporting check. It does not change refs, update PRs, or
configure repository merge protection.
"""

from __future__ import annotations

import html
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

SHA_PATTERN = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$", re.IGNORECASE)
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class AttestationProblem(Exception):
    """A stable, non-sensitive failure code for an incomplete attestation."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _positive_integer(value: Any, *, missing_code: str, invalid_code: str) -> int:
    if value is None or value == "":
        raise AttestationProblem(missing_code)
    if isinstance(value, bool):
        raise AttestationProblem(invalid_code)
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and value.strip().isdecimal():
        result = int(value.strip())
    else:
        raise AttestationProblem(invalid_code)
    if result <= 0:
        raise AttestationProblem(invalid_code)
    return result


def _positive_id(value: Any) -> int:
    return _positive_integer(
        value,
        missing_code="missing_repository_id",
        invalid_code="invalid_repository_id",
    )


def _required_text(value: Any, code: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AttestationProblem(code)
    return value.strip()


def _valid_sha(value: Any, code: str) -> str:
    text = _required_text(value, code)
    if not SHA_PATTERN.fullmatch(text):
        raise AttestationProblem(code)
    return text.lower()


def _repository(repo: Any) -> tuple[int, str]:
    if not isinstance(repo, dict):
        raise AttestationProblem("missing_repository")
    repository_id = _positive_id(repo.get("id"))
    full_name = _required_text(repo.get("full_name"), "missing_repository_name")
    if not REPOSITORY_PATTERN.fullmatch(full_name):
        raise AttestationProblem("invalid_repository_name")
    return repository_id, full_name


def _branch_ref(value: Any, code: str) -> str:
    ref = _required_text(value, code)
    if any(part in {"", ".", ".."} for part in ref.split("/")):
        raise AttestationProblem("invalid_branch_ref")
    if ref.startswith("refs/") or any(
        ord(char) < 32 or ord(char) == 127 for char in ref
    ):
        raise AttestationProblem("invalid_branch_ref")
    return ref


def _summary_value(value: Any) -> str:
    text = str(value) if value is not None else "UNKNOWN"
    text = " ".join(text.split())
    if not text:
        text = "UNKNOWN"
    text = html.escape(text, quote=False)
    markdown_chars = set("\\*_{}[]()#+-.!|>") | {chr(96)}
    return "".join(f"\\{char}" if char in markdown_chars else char for char in text)


def _event_metadata(event: Any, env: Mapping[str, str]) -> dict[str, Any]:
    if env.get("GITHUB_EVENT_NAME") != "pull_request":
        raise AttestationProblem("unsupported_event")
    if not isinstance(event, dict) or not isinstance(event.get("pull_request"), dict):
        raise AttestationProblem("missing_pull_request_event")

    pull_request = event["pull_request"]
    number = pull_request.get("number", event.get("number"))
    number = _positive_integer(
        number,
        missing_code="missing_pull_request_number",
        invalid_code="invalid_pull_request_number",
    )

    base = pull_request.get("base")
    head = pull_request.get("head")
    if not isinstance(base, dict) or not isinstance(head, dict):
        raise AttestationProblem("missing_base_or_head")

    base_repo_id, base_repo_name = _repository(base.get("repo"))
    head_repo_id, head_repo_name = _repository(head.get("repo"))
    target_repo_id = _positive_id(
        env.get("GITHUB_REPOSITORY_ID") or env.get("PR_CI_TARGET_REPOSITORY_ID")
    )
    target_repo_name = _required_text(
        env.get("GITHUB_REPOSITORY"), "missing_target_repository"
    )
    if target_repo_id != base_repo_id:
        raise AttestationProblem("target_repository_id_mismatch")
    if target_repo_name.casefold() != base_repo_name.casefold():
        raise AttestationProblem("target_repository_name_mismatch")

    base_ref = _branch_ref(base.get("ref"), "missing_base_ref")
    head_ref = _branch_ref(head.get("ref"), "missing_head_ref")
    base_sha = _valid_sha(base.get("sha"), "missing_base_sha")
    head_sha = _valid_sha(head.get("sha"), "missing_head_sha")
    event_sha = _valid_sha(env.get("GITHUB_SHA"), "missing_event_merge_sha")

    workflow_name = _required_text(env.get("GITHUB_WORKFLOW"), "missing_workflow_name")
    workflow_ref = _required_text(
        env.get("GITHUB_WORKFLOW_REF"), "missing_workflow_ref"
    )
    run_id = _required_text(env.get("GITHUB_RUN_ID"), "missing_run_id")
    run_attempt = _required_text(env.get("GITHUB_RUN_ATTEMPT"), "missing_run_attempt")
    if not run_attempt.isdecimal() or int(run_attempt) < 1:
        raise AttestationProblem("invalid_run_attempt")

    return {
        "target_repo_id": target_repo_id,
        "target_repo_name": base_repo_name,
        "pull_request_number": number,
        "base_repo_id": base_repo_id,
        "base_repo_name": base_repo_name,
        "base_ref": base_ref,
        "base_sha": base_sha,
        "head_repo_id": head_repo_id,
        "head_repo_name": head_repo_name,
        "head_ref": head_ref,
        "head_sha": head_sha,
        "event_sha": event_sha,
        "workflow_name": workflow_name,
        "workflow_ref": workflow_ref,
        "run_id": run_id,
        "run_attempt": int(run_attempt),
    }


def _github_api_json(url: str, *, token: str) -> dict[str, Any]:
    if not token:
        raise AttestationProblem("github_token_missing")
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "agent-control-plane-pr-ci-attestation",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urlopen(request, timeout=10) as response:
            payload = json.load(response)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
        raise AttestationProblem("github_api_unavailable") from error
    if not isinstance(payload, dict):
        raise AttestationProblem("github_api_unavailable")
    return payload


def fetch_github_ref(
    repository: str,
    ref: str,
    *,
    token: str,
    api_url: str = "https://api.github.com",
) -> str:
    """Resolve a live branch tip without logging credentials or response data."""
    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise AttestationProblem("invalid_repository_name")
    url = (
        f"{api_url.rstrip('/')}/repos/{repository}/git/ref/heads/{quote(ref, safe='')}"
    )
    try:
        payload = _github_api_json(url, token=token)
    except AttestationProblem as error:
        raise AttestationProblem("live_ref_unavailable") from error
    obj = payload.get("object")
    if not isinstance(obj, dict):
        raise AttestationProblem("live_ref_unavailable")
    return _valid_sha(obj.get("sha"), "live_ref_unavailable")


def fetch_github_pull_request(
    repository: str,
    number: int,
    *,
    token: str,
    api_url: str = "https://api.github.com",
) -> dict[str, Any]:
    """Read current PR routing/head metadata without logging API details."""
    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise AttestationProblem("invalid_repository_name")
    if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
        raise AttestationProblem("invalid_pull_request_number")
    url = f"{api_url.rstrip('/')}/repos/{repository}/pulls/{number}"
    try:
        return _github_api_json(url, token=token)
    except AttestationProblem as error:
        raise AttestationProblem("live_pull_request_unavailable") from error


def _current_pull_request_fingerprint(pull_request: Any) -> dict[str, Any]:
    if not isinstance(pull_request, dict):
        raise AttestationProblem("live_pull_request_unavailable")
    number = _positive_integer(
        pull_request.get("number"),
        missing_code="live_pull_request_unavailable",
        invalid_code="live_pull_request_unavailable",
    )
    state = _required_text(
        pull_request.get("state"), "live_pull_request_unavailable"
    ).casefold()

    base = pull_request.get("base")
    head = pull_request.get("head")
    if not isinstance(base, dict) or not isinstance(head, dict):
        raise AttestationProblem("live_pull_request_unavailable")
    base_repo_id, base_repo_name = _repository(base.get("repo"))
    head_repo_id, head_repo_name = _repository(head.get("repo"))
    try:
        base_ref = _branch_ref(base.get("ref"), "live_pull_request_unavailable")
        head_ref = _branch_ref(head.get("ref"), "live_pull_request_unavailable")
        head_sha = _valid_sha(head.get("sha"), "live_pull_request_unavailable")
    except AttestationProblem as error:
        raise AttestationProblem("live_pull_request_unavailable") from error

    current = {
        "number": number,
        "state": state,
        "base_repo_id": base_repo_id,
        "base_repo_name": base_repo_name,
        "base_ref": base_ref,
        "head_repo_id": head_repo_id,
        "head_repo_name": head_repo_name,
        "head_ref": head_ref,
        "head_sha": head_sha,
    }
    return current


def _pull_request_matches_event(
    current: Mapping[str, Any], expected: Mapping[str, Any]
) -> bool:
    return (
        current["number"] == expected["pull_request_number"]
        and current["base_repo_id"] == expected["base_repo_id"]
        and current["base_repo_name"].casefold()
        == expected["base_repo_name"].casefold()
        and current["base_ref"] == expected["base_ref"]
        and current["head_repo_id"] == expected["head_repo_id"]
        and current["head_repo_name"].casefold()
        == expected["head_repo_name"].casefold()
        and current["head_ref"] == expected["head_ref"]
        and current["head_sha"] == expected["head_sha"]
    )


def _read_live_pair(
    metadata: Mapping[str, Any],
    ref_lookup: Callable[[str, str], str],
) -> dict[str, str]:
    base_sha = ref_lookup(metadata["base_repo_name"], metadata["base_ref"])
    head_sha = ref_lookup(metadata["head_repo_name"], metadata["head_ref"])
    return {
        "base_sha": _valid_sha(base_sha, "live_ref_unavailable"),
        "head_sha": _valid_sha(head_sha, "live_ref_unavailable"),
    }


def evaluate_attestation(
    event: Any,
    env: Mapping[str, str],
    checkout_sha: str | None,
    checkout_parents: list[str] | None,
    ref_lookup: Callable[[str, str], str],
    *,
    pull_request_lookup: Callable[[str, int], dict[str, Any]] | None = None,
    checked_at: str | None = None,
) -> dict[str, Any]:
    """Evaluate event provenance, checkout parents, and two live ref snapshots."""
    report: dict[str, Any] = {
        "schema_version": 1,
        "status": "invalid",
        "reason": "incomplete_attestation",
        "checked_at_utc": checked_at or _utc_now(),
        "target": {"repository_id": None, "repository": None, "pr_number": None},
        "base": {
            "repository_id": None,
            "repository": None,
            "ref": None,
            "event_sha": None,
            "live_sha": None,
        },
        "head": {
            "repository_id": None,
            "repository": None,
            "ref": None,
            "event_sha": None,
            "live_sha": None,
        },
        "workflow": {
            "event": env.get("GITHUB_EVENT_NAME"),
            "name": env.get("GITHUB_WORKFLOW"),
            "ref": env.get("GITHUB_WORKFLOW_REF"),
            "run_id": env.get("GITHUB_RUN_ID"),
            "run_attempt": env.get("GITHUB_RUN_ATTEMPT"),
        },
        "checkout": {
            "reported_sha": env.get("GITHUB_SHA"),
            "actual_sha": checkout_sha,
            "parents": checkout_parents,
        },
        "live_ref_snapshots": [],
        "pull_request_snapshots": [],
        "ci": {"test_matrix_job_result": env.get("CI_JOB_RESULT")},
        "next_step": (
            "Rerun CI for the current base/head pair; no ref mutation is attempted."
        ),
    }

    try:
        metadata = _event_metadata(event, env)
    except AttestationProblem as error:
        report["reason"] = error.code
        return report

    report["target"] = {
        "repository_id": metadata["target_repo_id"],
        "repository": metadata["target_repo_name"],
        "pr_number": metadata["pull_request_number"],
    }
    report["workflow"].update(
        name=metadata["workflow_name"],
        ref=metadata["workflow_ref"],
        run_id=metadata["run_id"],
        run_attempt=metadata["run_attempt"],
    )
    report["base"].update(
        repository_id=metadata["base_repo_id"],
        repository=metadata["base_repo_name"],
        ref=metadata["base_ref"],
        event_sha=metadata["base_sha"],
    )
    report["head"].update(
        repository_id=metadata["head_repo_id"],
        repository=metadata["head_repo_name"],
        ref=metadata["head_ref"],
        event_sha=metadata["head_sha"],
    )

    try:
        actual_sha = _valid_sha(checkout_sha, "missing_checkout_sha")
        parents = [
            _valid_sha(parent, "invalid_checkout_parents")
            for parent in checkout_parents or []
        ]
    except AttestationProblem as error:
        report["reason"] = error.code
        return report

    if actual_sha != metadata["event_sha"]:
        report["reason"] = "checkout_sha_mismatch"
        return report
    if len(parents) != 2 or parents != [
        metadata["base_sha"],
        metadata["head_sha"],
    ]:
        report["reason"] = "merge_parent_mismatch"
        return report

    if pull_request_lookup is None:
        report["reason"] = "live_pull_request_unavailable"
        return report

    def current_pull_request_snapshot() -> dict[str, Any]:
        try:
            current = pull_request_lookup(
                metadata["target_repo_name"], metadata["pull_request_number"]
            )
            return _current_pull_request_fingerprint(current)
        except AttestationProblem:
            raise
        except Exception as error:
            raise AttestationProblem("live_pull_request_unavailable") from error

    try:
        current_before = current_pull_request_snapshot()
    except AttestationProblem as error:
        report["reason"] = error.code
        return report
    report["pull_request_snapshots"].append(current_before)
    if current_before["state"] != "open":
        report["status"] = "stale"
        report["reason"] = "pull_request_not_open"
        return report
    if not _pull_request_matches_event(current_before, metadata):
        report["status"] = "stale"
        report["reason"] = "pull_request_metadata_changed"
        return report

    try:
        first = _read_live_pair(metadata, ref_lookup)
        second = _read_live_pair(metadata, ref_lookup)
    except AttestationProblem as error:
        report["reason"] = error.code
        return report
    except Exception:
        report["reason"] = "live_ref_unavailable"
        return report

    try:
        current_after = current_pull_request_snapshot()
    except AttestationProblem as error:
        report["reason"] = error.code
        report["live_ref_snapshots"] = [first, second]
        report["base"]["live_sha"] = second["base_sha"]
        report["head"]["live_sha"] = second["head_sha"]
        return report

    report["pull_request_snapshots"].append(current_after)
    if current_after != current_before:
        report["status"] = "stale"
        report["reason"] = "pull_request_changed_during_evaluation"
        report["live_ref_snapshots"] = [first, second]
        report["base"]["live_sha"] = second["base_sha"]
        report["head"]["live_sha"] = second["head_sha"]
        return report

    report["live_ref_snapshots"] = [first, second]
    report["base"]["live_sha"] = second["base_sha"]
    report["head"]["live_sha"] = second["head_sha"]

    expected = {"base_sha": metadata["base_sha"], "head_sha": metadata["head_sha"]}
    if first != second:
        report["status"] = "stale"
        report["reason"] = "live_refs_changed_during_evaluation"
    elif second != expected:
        report["status"] = "stale"
        report["reason"] = "event_pair_is_not_live"
    else:
        report["status"] = "fresh"
        report["reason"] = "exact_pair_matches_live_refs"
    return report


def _git_value(args: list[str], workspace: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=workspace,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise AttestationProblem("checkout_metadata_unavailable") from error
    return result.stdout.strip()


def _checkout_metadata(workspace: str) -> tuple[str, list[str]]:
    sha = _git_value(["rev-parse", "HEAD"], workspace)
    line = _git_value(["rev-list", "--parents", "-n", "1", "HEAD"], workspace)
    parts = line.split()
    if not parts or parts[0].lower() != sha.lower():
        raise AttestationProblem("checkout_metadata_unavailable")
    return sha, parts[1:]


def _load_event(path: str | None) -> Any:
    if not path:
        raise AttestationProblem("event_path_missing")
    try:
        with Path(path).open(encoding="utf-8") as event_file:
            return json.load(event_file)
    except (OSError, ValueError) as error:
        raise AttestationProblem("event_payload_unavailable") from error


def _write_report(report: Mapping[str, Any], env: Mapping[str, str]) -> None:
    output_path = Path(
        env.get("PR_CI_ATTESTATION_PATH")
        or Path(env.get("RUNNER_TEMP", ".")).joinpath("pr-ci-attestation.json")
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    summary_path = env.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    status = report.get("status", "invalid")
    reason = report.get("reason", "incomplete_attestation")
    target = report.get("target", {})
    base = report.get("base", {})
    head = report.get("head", {})
    workflow = report.get("workflow", {})
    ci = report.get("ci", {})
    lines = [
        "## PR CI freshness attestation",
        "",
        f"- Result: **{status.upper()}** ({reason})",
        (
            f"- Target: {_summary_value(target.get('repository'))}"
            f"#{target.get('pr_number') or 'UNKNOWN'}"
            f" (repo ID {target.get('repository_id') or 'UNKNOWN'})"
        ),
        (
            f"- Base: {_summary_value(base.get('repository'))}"
            f" (ID {base.get('repository_id') or 'UNKNOWN'})"
            f" at {_summary_value(base.get('ref'))}"
            f" event {base.get('event_sha') or 'UNKNOWN'}"
            f" / live {base.get('live_sha') or 'UNKNOWN'}"
        ),
        (
            f"- Head: {_summary_value(head.get('repository'))}"
            f" (ID {head.get('repository_id') or 'UNKNOWN'})"
            f" at {_summary_value(head.get('ref'))}"
            f" event {head.get('event_sha') or 'UNKNOWN'}"
            f" / live {head.get('live_sha') or 'UNKNOWN'}"
        ),
        (
            "- Tested checkout: "
            f"{report.get('checkout', {}).get('actual_sha') or 'UNKNOWN'}"
        ),
        (
            f"- Event/workflow: {_summary_value(workflow.get('event'))} / "
            f"{_summary_value(workflow.get('name'))}"
        ),
        f"- Workflow ref: {_summary_value(workflow.get('ref'))}",
        (
            f"- Run: {_summary_value(workflow.get('name'))}"
            f" #{workflow.get('run_id') or 'UNKNOWN'}"
            f" attempt {workflow.get('run_attempt') or 'UNKNOWN'}"
        ),
        (
            "- CI test/build matrix job result: "
            f"**{_summary_value(ci.get('test_matrix_job_result'))}**"
        ),
        (
            "- Freshness is separate from test success. This job fails unless"
            " both the exact-pair attestation and test/build matrix succeed."
        ),
    ]
    if status != "fresh":
        lines.extend(
            [
                "",
                "Safe next step: rerun CI against the current base/head pair."
                " No ref mutation was attempted.",
            ]
        )
    with Path(summary_path).open("a", encoding="utf-8") as summary_file:
        summary_file.write("\n".join(lines) + "\n")


def main() -> int:
    env = os.environ
    try:
        event = _load_event(env.get("GITHUB_EVENT_PATH"))
    except AttestationProblem as error:
        event = None
        event_error = error.code
    else:
        event_error = None

    try:
        workspace = env.get(
            "PR_CI_TESTED_WORKSPACE", env.get("GITHUB_WORKSPACE", os.getcwd())
        )
        checkout_sha, parents = _checkout_metadata(workspace)
    except AttestationProblem:
        checkout_sha, parents = None, None

    token = env.get("GITHUB_TOKEN", "")
    api_url = env.get("GITHUB_API_URL", "https://api.github.com")

    def lookup(repository: str, ref: str) -> str:
        return fetch_github_ref(repository, ref, token=token, api_url=api_url)

    def pull_request_lookup(repository: str, number: int) -> dict[str, Any]:
        return fetch_github_pull_request(
            repository, number, token=token, api_url=api_url
        )

    report = evaluate_attestation(
        event,
        env,
        checkout_sha,
        parents,
        lookup,
        pull_request_lookup=pull_request_lookup,
    )
    if event_error:
        report["reason"] = event_error

    try:
        _write_report(report, env)
    except OSError:
        print(
            "PR CI attestation could not write its report or step summary.",
            file=sys.stderr,
        )
        return 1

    print(
        json.dumps(
            {"status": report["status"], "reason": report["reason"]},
            sort_keys=True,
        )
    )
    return (
        0
        if report["status"] == "fresh"
        and report.get("ci", {}).get("test_matrix_job_result") == "success"
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
