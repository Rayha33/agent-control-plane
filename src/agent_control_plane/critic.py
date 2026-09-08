from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".py",
    ".rb",
    ".rs",
    ".swift",
    ".ts",
    ".tsx",
}
SENSITIVE_PARTS = {
    ".github",
    "auth",
    "authorization",
    "migration",
    "permissions",
    "security",
}


def finding(
    severity: str,
    requirement: str,
    message: str,
    evidence: str,
    required_fix: str,
) -> dict[str, str]:
    return {
        "severity": severity,
        "requirement": requirement,
        "finding": message,
        "evidence": evidence,
        "required_fix": required_fix,
    }


def review(packet: dict[str, Any], root: Path) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    task = packet.get("task", {})
    submission = packet.get("submission", {})
    changed = [Path(value) for value in submission.get("changed_paths", [])]
    acceptance = task.get("acceptance", [])

    if not acceptance:
        findings.append(
            finding(
                "high",
                "the task has objective acceptance criteria",
                "the review packet has no acceptance criteria",
                "task.acceptance is empty",
                "add measurable acceptance criteria and resubmit",
            )
        )
    if not changed:
        findings.append(
            finding(
                "high",
                "the candidate contains a bounded change",
                "the review packet has no changed paths",
                "submission.changed_paths is empty",
                "submit a non-empty committed change",
            )
        )
    if len(changed) > 100:
        findings.append(
            finding(
                "medium",
                "the change remains reviewable",
                "the candidate changes more than 100 paths",
                f"changed_path_count={len(changed)}",
                "split the task or require explicit human review",
            )
        )

    source_changed = any(path.suffix.casefold() in SOURCE_SUFFIXES for path in changed)
    test_changed = any(
        "test" in {part.casefold() for part in path.parts}
        or path.name.casefold().startswith(("test_", "spec_"))
        for path in changed
    )
    if source_changed and not test_changed:
        findings.append(
            finding(
                "low",
                "behavioral changes have regression evidence",
                "source changed without a changed test file",
                ", ".join(str(path) for path in changed[:20]),
                "confirm existing tests cover the change or add a focused regression test",
            )
        )

    sensitive = sorted(
        str(path)
        for path in changed
        if SENSITIVE_PARTS.intersection(part.casefold() for part in path.parts)
    )
    if sensitive:
        findings.append(
            finding(
                "low",
                "security-sensitive changes receive extra scrutiny",
                "the candidate touches security-sensitive paths",
                ", ".join(sensitive[:20]),
                "consider a specialist or human security review",
            )
        )

    for path in changed:
        candidate = root / path
        if not candidate.is_file() or candidate.stat().st_size > 1_000_000:
            continue
        try:
            text = candidate.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if "<<<<<<<" in text and "=======" in text and ">>>>>>>" in text:
            findings.append(
                finding(
                    "high",
                    "the candidate contains no unresolved merge conflict",
                    f"conflict markers remain in {path}",
                    str(path),
                    "resolve the conflict markers and submit a new commit",
                )
            )

    failed = [
        result for result in packet.get("deterministic_results", []) if result.get("exit_code") != 0
    ]
    if failed:
        findings.append(
            finding(
                "high",
                "all deterministic gates pass",
                "one or more deterministic commands failed",
                ", ".join(f"{item.get('command')}={item.get('exit_code')}" for item in failed),
                "fix the deterministic failures before approval",
            )
        )

    serious = {"critical", "high", "medium"}
    verdict = "revise" if any(item["severity"] in serious for item in findings) else "pass"
    return {"verdict": verdict, "findings": findings}


def main() -> int:
    packet_path = os.environ.get("ACP_REVIEW_PACKET")
    result_path = os.environ.get("ACP_REVIEW_RESULT")
    if not packet_path or not result_path:
        raise SystemExit("ACP_REVIEW_PACKET and ACP_REVIEW_RESULT are required")
    packet = json.loads(Path(packet_path).read_text(encoding="utf-8"))
    result = review(packet, Path.cwd())
    Path(result_path).write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
