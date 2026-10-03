"""Versioned acceptance-coverage contract for independent QC reviewers."""

from __future__ import annotations

import hashlib
from typing import Any

ACCEPTANCE_COVERAGE_CONTRACT_VERSION = 2
ACCEPTANCE_COVERAGE_STATUSES = frozenset({"pass", "revise", "unknown", "human_required"})


def acceptance_criteria(items: list[str]) -> list[dict[str, str]]:
    """Give each task criterion a stable, unique identifier for the review packet."""
    if not isinstance(items, list) or not items:
        raise ValueError("task acceptance criteria must be a non-empty list")

    records: list[dict[str, str]] = []
    for index, item in enumerate(items, start=1):
        if not isinstance(item, str) or not item.strip():
            raise ValueError("task acceptance criteria must be non-empty strings")
        digest = hashlib.sha256(item.encode("utf-8")).hexdigest()[:10]
        records.append({"id": f"AC-{index:03d}-{digest}", "text": item})
    return records


def validate_acceptance_coverage(
    raw: Any,
    expected: list[dict[str, str]],
    evidence_catalog: list[dict[str, Any]],
    *,
    run_id: str,
    commit_sha: str,
) -> list[dict[str, Any]]:
    """Validate exact criterion coverage and references to this run's evidence."""
    if not expected:
        raise ValueError("QC cannot pass a task with no acceptance criteria")
    if not isinstance(evidence_catalog, list) or not evidence_catalog:
        raise ValueError("review packet has no evidence catalog")

    evidence: dict[str, dict[str, Any]] = {}
    for item in evidence_catalog:
        if not isinstance(item, dict):
            raise ValueError("review packet evidence catalog is malformed")
        evidence_id = item.get("id")
        if not isinstance(evidence_id, str) or not evidence_id:
            raise ValueError("review packet evidence catalog contains an invalid ID")
        if evidence_id in evidence:
            raise ValueError("review packet evidence catalog contains duplicate IDs")
        if item.get("run_id") != run_id or item.get("commit_sha") != commit_sha:
            raise ValueError("review packet evidence is not bound to this QC run and commit")
        evidence[evidence_id] = item

    if not isinstance(raw, list) or len(raw) != len(expected):
        raise ValueError("critic must return exactly one acceptance result per criterion")

    by_id = {item["id"]: item for item in expected}
    seen: set[str] = set()
    validated: list[dict[str, Any]] = []
    required = {"criterion_id", "status", "rationale", "evidence_refs"}
    for result in raw:
        if not isinstance(result, dict) or set(result) != required:
            raise ValueError("acceptance result must contain only the version 2 fields")
        criterion_id = result.get("criterion_id")
        if not isinstance(criterion_id, str) or criterion_id not in by_id:
            raise ValueError("critic returned an unknown acceptance criterion ID")
        if criterion_id in seen:
            raise ValueError("critic returned a duplicate acceptance criterion ID")
        seen.add(criterion_id)

        status = result.get("status")
        if status not in ACCEPTANCE_COVERAGE_STATUSES:
            raise ValueError("acceptance status must be pass, revise, unknown, or human_required")
        rationale = result.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip() or len(rationale) > 4000:
            raise ValueError("acceptance rationale must be non-empty and at most 4000 characters")
        references = result.get("evidence_refs")
        if (
            not isinstance(references, list)
            or not references
            or len(references) > 20
            or any(not isinstance(ref, str) or ref not in evidence for ref in references)
            or len(set(references)) != len(references)
        ):
            raise ValueError(
                "acceptance evidence references must resolve uniquely in this QC packet"
            )

        validated.append(
            {
                "criterion_id": criterion_id,
                "criterion": by_id[criterion_id]["text"],
                "status": status,
                "rationale": rationale.strip(),
                "evidence_refs": references,
            }
        )

    if seen != set(by_id):
        raise ValueError("critic omitted an acceptance criterion")
    return sorted(validated, key=lambda item: item["criterion_id"])
