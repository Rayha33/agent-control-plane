"""Evaluator calibration and reviewer provenance.

Independent review reduces self-approval, but a model critic can share the
worker's blind spots, prefer its own output, or silently drift when someone
upgrades the model behind it. This module makes the reviewer itself auditable:

- every QC verdict carries signed provenance (identity, provider, model, prompt
  policy, resolved command hash) and a deterministic reproduction bundle;
- the reviewer *policy* is fingerprinted, so swapping a model or prompt policy
  stops QC until a human ratifies the change instead of quietly taking effect;
- repository-specific golden cases with seeded defects measure false-pass and
  false-block rates, reported with Wilson confidence intervals per reviewer
  fingerprint, so "the critic is fine" becomes a number with an error bar;
- high-risk paths can demand two reviewers, distinct providers, or a human.

The signature is a local HMAC. It is tamper-evident bookkeeping for a single
trusted host, in the same spirit as the event hash chain — not external
non-repudiation. Hardware- or SSO-backed reviewer identity is a later layer.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import platform
import secrets
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .git_supervisor import GitSupervisor

REJECT_VERDICTS = frozenset({"revise", "block", "human_required"})
HIGH_RISK_MODES = frozenset({"two_reviewer", "human", "off"})


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Reviewer:
    identity: str
    provider: str
    model: str
    prompt_policy: str
    command: str

    def provenance(self) -> dict[str, str]:
        return {
            "identity": self.identity,
            "provider": self.provider,
            "model": self.model,
            "prompt_policy": self.prompt_policy,
            "command": self.command,
            "command_sha256": digest(self.command),
        }

    @property
    def fingerprint(self) -> str:
        return digest(canonical(self.provenance()))


@dataclass(frozen=True)
class AssurancePolicy:
    reviewers: tuple[Reviewer, ...] = ()
    high_risk_paths: tuple[str, ...] = ()
    high_risk_mode: str = "off"
    require_provider_diversity: bool = False
    golden_dir: str = "acp-golden"

    def reviewer(self, identity: str) -> Reviewer | None:
        return next((item for item in self.reviewers if item.identity == identity), None)

    @property
    def fingerprint(self) -> str:
        """Identifies the whole evaluation policy, not just one reviewer.

        A model swap, a prompt-policy bump, a new reviewer, or a relaxed
        high-risk rule all change this value — which is what makes a silent
        reviewer upgrade impossible.
        """
        return digest(
            canonical(
                {
                    "reviewers": [item.provenance() for item in self.reviewers],
                    "high_risk_paths": list(self.high_risk_paths),
                    "high_risk_mode": self.high_risk_mode,
                    "require_provider_diversity": self.require_provider_diversity,
                }
            )
        )

    def describe(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "reviewers": [item.provenance() for item in self.reviewers],
            "high_risk_paths": list(self.high_risk_paths),
            "high_risk_mode": self.high_risk_mode,
            "require_provider_diversity": self.require_provider_diversity,
            "golden_dir": self.golden_dir,
        }


@dataclass
class GoldenCase:
    """A seeded repository state with a known-correct verdict."""

    name: str
    expect: str
    description: str = ""
    mutations: list[dict[str, str]] = field(default_factory=list)

    @property
    def expects_rejection(self) -> bool:
        return self.expect == "reject"


def load_policy(raw: dict[str, Any], critic_identity: str, critic_command: str) -> AssurancePolicy:
    """Read `[reviewers.*]`, `[policy]` and `[calibration]`.

    A config written before this feature has no `[reviewers]` table; rather than
    failing, its single configured critic is adopted with explicitly unknown
    provenance. `unknown` is honest and still fingerprinted, so the first real
    declaration registers as a policy change instead of passing unnoticed.
    """
    from .git_supervisor import SupervisorError

    declared = raw.get("reviewers", {})
    if not isinstance(declared, dict):
        raise SupervisorError("invalid_config", "reviewers must be a table")
    reviewers: list[Reviewer] = []
    for identity, entry in sorted(declared.items()):
        if not isinstance(entry, dict):
            raise SupervisorError("invalid_config", f"reviewers.{identity} must be a table")
        command = str(entry.get("command", critic_command)).strip()
        if not command:
            raise SupervisorError("invalid_config", f"reviewers.{identity} needs a command")
        reviewers.append(
            Reviewer(
                identity=identity,
                provider=str(entry.get("provider", "unknown")).strip() or "unknown",
                model=str(entry.get("model", "unknown")).strip() or "unknown",
                prompt_policy=str(entry.get("prompt_policy", "unset")).strip() or "unset",
                command=command,
            )
        )
    if not reviewers and critic_command:
        reviewers.append(
            Reviewer(
                identity=critic_identity,
                provider="unknown",
                model="unknown",
                prompt_policy="unset",
                command=critic_command,
            )
        )

    policy = raw.get("policy", {})
    if not isinstance(policy, dict):
        raise SupervisorError("invalid_config", "policy must be a table")
    mode = str(policy.get("high_risk_mode", "off")).strip() or "off"
    if mode not in HIGH_RISK_MODES:
        raise SupervisorError(
            "invalid_config", f"policy.high_risk_mode must be one of {sorted(HIGH_RISK_MODES)}"
        )
    high_risk = tuple(str(item) for item in policy.get("high_risk_paths", []))
    diversity = bool(policy.get("require_provider_diversity", False))
    if mode == "two_reviewer" and len(reviewers) < 2:
        raise SupervisorError(
            "invalid_config",
            "policy.high_risk_mode = two_reviewer needs at least two declared reviewers",
        )
    if diversity and len({item.provider for item in reviewers}) < 2:
        raise SupervisorError(
            "invalid_config",
            "policy.require_provider_diversity needs reviewers from two providers",
        )
    calibration = raw.get("calibration", {})
    if not isinstance(calibration, dict):
        raise SupervisorError("invalid_config", "calibration must be a table")
    return AssurancePolicy(
        reviewers=tuple(reviewers),
        high_risk_paths=high_risk,
        high_risk_mode=mode,
        require_provider_diversity=diversity,
        golden_dir=str(calibration.get("golden_dir", "acp-golden")),
    )


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> dict[str, float]:
    """95% Wilson score interval.

    Chosen over the normal approximation because calibration sets are small and
    often hit 0 or 100%, where the naive interval collapses to zero width and
    reports false certainty.
    """
    if total <= 0:
        return {"rate": 0.0, "low": 0.0, "high": 1.0, "samples": 0}
    proportion = successes / total
    denominator = 1 + z**2 / total
    center = (proportion + z**2 / (2 * total)) / denominator
    margin = (
        z * math.sqrt(proportion * (1 - proportion) / total + z**2 / (4 * total**2)) / denominator
    )
    return {
        "rate": round(proportion, 6),
        "low": round(max(0.0, center - margin), 6),
        "high": round(min(1.0, center + margin), 6),
        "samples": total,
    }


class Assurance:
    def __init__(self, supervisor: GitSupervisor):
        self.supervisor = supervisor

    # ------------------------------------------------------------------ signing

    def signing_key(self) -> bytes:
        """Per-repository HMAC key, created on first use inside ignored state."""
        path = self.supervisor.state_dir / "reviewer-key"
        if not path.exists():
            path.write_text(secrets.token_hex(32), encoding="utf-8")
            path.chmod(0o600)
        return path.read_text(encoding="utf-8").strip().encode("utf-8")

    def sign(self, payload: dict[str, Any]) -> str:
        return hmac.new(
            self.signing_key(), canonical(payload).encode("utf-8"), "sha256"
        ).hexdigest()

    def verify(self, payload: dict[str, Any], signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)

    # ------------------------------------------------------------------- policy

    def ratified_fingerprint(self, connection: Any | None = None) -> str | None:
        if connection is None:
            with self.supervisor.connect() as owned:
                return self.ratified_fingerprint(owned)
        row = connection.execute(
            "SELECT value FROM meta WHERE key = 'reviewer_policy_fingerprint'"
        ).fetchone()
        return row["value"] if row else None

    def assert_policy_ratified(self) -> dict[str, Any]:
        """Refuse to review under an unratified evaluation policy.

        The first policy seen is adopted automatically — there is nothing to
        compare it against. Every later change must be ratified explicitly, so a
        reviewer upgrade cannot take effect merely because someone edited
        acp.toml.
        """
        from .git_supervisor import SupervisorError

        policy = self.supervisor.assurance_policy
        current = policy.fingerprint
        known = self.ratified_fingerprint()
        if known == current:
            return {"fingerprint": current, "ratified": True, "adopted": False}
        if known is None:
            self._record_fingerprint(current, None, "policy.adopted")
            return {"fingerprint": current, "ratified": True, "adopted": True}
        raise SupervisorError(
            "reviewer_policy_changed",
            f"the reviewer policy changed from {known[:12]} to {current[:12]}; "
            f"run `acp ratify-reviewers` to accept it before reviewing again "
            f"(current: {canonical(policy.describe())[:400]})",
        )

    def ratify(self, actor: str = "operator", connection: Any | None = None) -> dict[str, Any]:
        policy = self.supervisor.assurance_policy
        previous = self.ratified_fingerprint(connection)
        current = policy.fingerprint
        if previous == current:
            return {"fingerprint": current, "changed": False, **policy.describe()}
        self._record_fingerprint(current, previous, "policy.ratified", actor, connection)
        return {
            "fingerprint": current,
            "changed": True,
            "previous_fingerprint": previous,
            **policy.describe(),
        }

    def _record_fingerprint(
        self,
        current: str,
        previous: str | None,
        event: str,
        actor: str = "operator",
        connection: Any | None = None,
    ) -> None:
        if connection is None:
            with self.supervisor.connect() as owned:
                owned.execute("BEGIN IMMEDIATE")
                self._record_fingerprint(current, previous, event, actor, owned)
            return
        connection.execute(
            "INSERT INTO meta(key, value) VALUES('reviewer_policy_fingerprint', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (current,),
        )
        self.supervisor._event(
            connection,
            event,
            actor,
            {
                "fingerprint": current,
                "previous_fingerprint": previous,
                "policy": self.supervisor.assurance_policy.describe(),
            },
        )

    # ---------------------------------------------------------------- high risk

    def high_risk_paths(self, changed_paths: list[str]) -> list[str]:
        policy = self.supervisor.assurance_policy
        if policy.high_risk_mode == "off" or not policy.high_risk_paths:
            return []
        matched: list[str] = []
        for path in changed_paths:
            for scope in policy.high_risk_paths:
                normalized = self.supervisor.normalize_resource(scope)
                if self.supervisor._path_matches(path.casefold(), normalized):
                    matched.append(path)
                    break
        return sorted(set(matched))

    def review_requirement(
        self, changed_paths: list[str], prior: list[dict[str, str]]
    ) -> dict[str, Any]:
        """What must still happen before a high-risk change may be approved.

        `prior` holds the passing reviews already recorded for this submission,
        as {reviewer_id, provider} pairs.
        """
        policy = self.supervisor.assurance_policy
        matched = self.high_risk_paths(changed_paths)
        if not matched:
            return {"high_risk": False, "satisfied": True, "paths": [], "reason": ""}
        if policy.high_risk_mode == "human":
            return {
                "high_risk": True,
                "satisfied": False,
                "paths": matched,
                "reason": "policy.high_risk_mode = human requires explicit human approval",
            }
        identities = {item["reviewer_id"] for item in prior}
        providers = {item["provider"] for item in prior}
        if len(identities) < 2:
            return {
                "high_risk": True,
                "satisfied": False,
                "paths": matched,
                "reason": (
                    f"high-risk paths need two independent reviewers; "
                    f"{len(identities)} of 2 have passed"
                ),
            }
        if policy.require_provider_diversity and len(providers) < 2:
            return {
                "high_risk": True,
                "satisfied": False,
                "paths": matched,
                "reason": (
                    "high-risk paths need reviewers from different providers; "
                    f"both passes came from {sorted(providers)}"
                ),
            }
        return {"high_risk": True, "satisfied": True, "paths": matched, "reason": ""}

    # ----------------------------------------------------------- repro bundles

    def bundle(
        self,
        qc_id: str,
        submission: dict[str, Any],
        task_base_sha: str,
        commands: list[str],
        reviewer: Reviewer,
        verdict: str,
        packet_sha256: str,
    ) -> dict[str, Any]:
        """Everything needed to re-run this verdict, and its signature."""
        payload = {
            "qc_id": qc_id,
            "submission_id": submission["id"],
            "commit_sha": submission["commit_sha"],
            "tree_sha": submission["tree_sha"],
            "patch_sha256": submission["patch_sha256"],
            "base_sha": task_base_sha,
            "packet_sha256": packet_sha256,
            "verdict": verdict,
            "commands": commands,
            "reviewer": reviewer.provenance(),
            "policy_fingerprint": self.supervisor.assurance_policy.fingerprint,
            "environment": {
                "python": platform.python_version(),
                "platform": platform.platform(),
                "git": self._git_version(),
            },
            "replay": [
                f"git worktree add --detach <dir> {submission['commit_sha']}",
                *commands,
                f"acp qc {submission['id']} --reviewer {reviewer.identity}",
            ],
        }
        signature = self.sign(payload)
        record = {**payload, "signature": signature}
        path = self.supervisor.state_dir / "bundles" / f"{qc_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
        return {"record": record, "sha256": digest(canonical(record)), "path": str(path)}

    def read_bundle(self, qc_id: str) -> dict[str, Any]:
        from .git_supervisor import SupervisorError

        path = self.supervisor.state_dir / "bundles" / f"{qc_id}.json"
        if not path.is_file():
            raise SupervisorError("bundle_not_found", f"no reproduction bundle for {qc_id}")
        record = json.loads(path.read_text(encoding="utf-8"))
        signature = record.pop("signature", "")
        return {
            "bundle": {**record, "signature": signature},
            "signature_valid": self.verify(record, signature),
        }

    def _git_version(self) -> str:
        result = subprocess.run(["git", "--version"], capture_output=True, text=True, check=False)
        return result.stdout.strip()

    # ----------------------------------------------------------- calibration

    def golden_cases(self) -> list[GoldenCase]:
        from .git_supervisor import SupervisorError

        directory = self.supervisor.root / self.supervisor.assurance_policy.golden_dir
        if not directory.is_dir():
            return []
        cases: list[GoldenCase] = []
        for path in sorted(directory.glob("*.toml")):
            with path.open("rb") as handle:
                raw = tomllib.load(handle)
            expect = str(raw.get("expect", "")).strip()
            if expect not in {"pass", "reject"}:
                raise SupervisorError(
                    "invalid_golden_case", f"{path.name}: expect must be 'pass' or 'reject'"
                )
            mutations = raw.get("mutations", [])
            if not isinstance(mutations, list) or any(
                not isinstance(item, dict) for item in mutations
            ):
                raise SupervisorError(
                    "invalid_golden_case", f"{path.name}: mutations must be a list of tables"
                )
            cases.append(
                GoldenCase(
                    name=str(raw.get("name", path.stem)),
                    expect=expect,
                    description=str(raw.get("description", "")),
                    mutations=[{str(k): str(v) for k, v in item.items()} for item in mutations],
                )
            )
        return cases

    @staticmethod
    def apply_mutations(worktree: Path, mutations: list[dict[str, str]]) -> list[str]:
        """Seed a defect. Returns the paths it touched."""
        from .git_supervisor import SupervisorError

        touched: list[str] = []
        for mutation in mutations:
            relative = mutation.get("path", "").strip()
            if not relative:
                raise SupervisorError("invalid_golden_case", "each mutation needs a path")
            target = worktree / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if "content" in mutation:
                target.write_text(mutation["content"], encoding="utf-8")
            elif "find" in mutation:
                if not target.is_file():
                    raise SupervisorError(
                        "invalid_golden_case", f"cannot mutate missing file {relative}"
                    )
                text = target.read_text(encoding="utf-8")
                if mutation["find"] not in text:
                    raise SupervisorError(
                        "invalid_golden_case",
                        f"mutation anchor not found in {relative}: {mutation['find']!r}",
                    )
                target.write_text(
                    text.replace(mutation["find"], mutation.get("replace", "")), encoding="utf-8"
                )
            else:
                raise SupervisorError(
                    "invalid_golden_case", "each mutation needs 'content' or 'find'"
                )
            touched.append(relative)
        return touched

    @staticmethod
    def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
        """False-pass and false-block rates with intervals.

        A false PASS is a seeded defect the reviewer approved — the dangerous
        direction. A false BLOCK is clean work the reviewer rejected — the
        expensive one. They are reported separately because a critic that
        rejects everything scores perfectly on one and uselessly on the other.
        """
        seeded = [item for item in results if item["expected"] == "reject"]
        clean = [item for item in results if item["expected"] == "pass"]
        false_pass = [item for item in seeded if not item["rejected"]]
        false_block = [item for item in clean if item["rejected"]]
        return {
            "cases": len(results),
            "seeded_defects": len(seeded),
            "clean_cases": len(clean),
            "caught_defects": len(seeded) - len(false_pass),
            "false_pass": wilson_interval(len(false_pass), len(seeded)),
            "false_block": wilson_interval(len(false_block), len(clean)),
            "missed_cases": sorted(item["name"] for item in false_pass + false_block),
        }
