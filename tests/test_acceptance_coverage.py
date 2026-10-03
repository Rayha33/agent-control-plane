from __future__ import annotations

import pytest

from agent_control_plane.supervisor.acceptance import (
    ACCEPTANCE_COVERAGE_CONTRACT_VERSION,
    acceptance_criteria,
    validate_acceptance_coverage,
)

RUN_ID = "run-123"
COMMIT = "a" * 40


def catalog(run_id: str = RUN_ID, commit_sha: str = COMMIT) -> list[dict[str, str]]:
    return [
        {
            "id": f"{run_id}:diff",
            "kind": "candidate_diff",
            "run_id": run_id,
            "commit_sha": commit_sha,
            "sha256": "b" * 64,
        }
    ]


def coverage(criteria: list[dict[str, str]]) -> list[dict[str, object]]:
    return [
        {
            "criterion_id": item["id"],
            "status": "pass",
            "rationale": "Inspected the exact candidate diff.",
            "evidence_refs": [f"{RUN_ID}:diff"],
        }
        for item in criteria
    ]


def validate(raw, criteria=None, evidence=None, run_id=RUN_ID, commit_sha=COMMIT):
    return validate_acceptance_coverage(
        raw,
        criteria or acceptance_criteria(["First", "Second"]),
        evidence or catalog(run_id, commit_sha),
        run_id=run_id,
        commit_sha=commit_sha,
    )


def test_criteria_have_stable_unique_ids_even_when_text_repeats() -> None:
    first = acceptance_criteria(["same", "same"])
    second = acceptance_criteria(["same", "same"])

    assert first == second
    assert first[0]["id"] != first[1]["id"]
    assert first[0]["id"].startswith("AC-001-")
    assert ACCEPTANCE_COVERAGE_CONTRACT_VERSION == 2


def test_exact_coverage_normalizes_against_the_task_text() -> None:
    criteria = acceptance_criteria(["First", "Second"])

    result = validate(coverage(criteria), criteria)

    assert [item["criterion"] for item in result] == ["First", "Second"]
    assert all(item["status"] == "pass" for item in result)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda value: value[:-1], "exactly one"),
        (lambda value: [value[0], value[0]], "duplicate"),
        (
            lambda value: [
                {**value[0], "criterion_id": "AC-999-unknown"},
                value[1],
            ],
            "unknown",
        ),
        (lambda value: [{**value[0], "evidence_refs": ["made-up"]}, value[1]], "evidence"),
        (lambda value: [{**value[0], "evidence_refs": []}, value[1]], "evidence"),
        (lambda value: [{**value[0], "status": "pass-ish"}, value[1]], "status"),
        (lambda value: [{**value[0], "rationale": " "}, value[1]], "rationale"),
    ],
)
def test_incomplete_or_unresolvable_coverage_is_rejected(change, message) -> None:
    criteria = acceptance_criteria(["First", "Second"])

    with pytest.raises(ValueError, match=message):
        validate(change(coverage(criteria)), criteria)


@pytest.mark.parametrize("status", ["revise", "unknown", "human_required"])
def test_nonpass_dispositions_are_preserved(status: str) -> None:
    criteria = acceptance_criteria(["First", "Second"])
    raw = coverage(criteria)
    raw[0]["status"] = status

    result = validate(raw, criteria)

    assert result[0]["status"] == status


def test_stale_run_or_commit_evidence_is_rejected() -> None:
    criteria = acceptance_criteria(["First", "Second"])
    old_catalog = catalog(run_id="old-run", commit_sha=COMMIT)
    old_commit_catalog = catalog(run_id=RUN_ID, commit_sha="c" * 40)

    with pytest.raises(ValueError, match="bound to this QC run"):
        validate(coverage(criteria), criteria, old_catalog)
    with pytest.raises(ValueError, match="bound to this QC run"):
        validate(coverage(criteria), criteria, old_commit_catalog)
