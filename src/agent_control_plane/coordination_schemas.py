from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

TaskStatus = Literal[
    "open",
    "claimed",
    "working",
    "qc_review",
    "changes_requested",
    "approved",
    "merging",
    "done",
    "blocked",
    "orphaned",
    "conflicted",
]


class ReviewFinding(BaseModel):
    severity: Literal["critical", "high", "medium", "low", "info"]
    requirement: str = Field(min_length=1, max_length=1000)
    finding: str = Field(min_length=1, max_length=4000)
    evidence: str = Field(min_length=1, max_length=8000)
    required_fix: str = Field(min_length=1, max_length=4000)


class QCReviewCreate(BaseModel):
    verdict: Literal["pass", "revise", "block", "human_required"]
    summary: str = Field(min_length=1, max_length=4000)
    findings: list[ReviewFinding] = Field(default_factory=list, max_length=200)

    @model_validator(mode="after")
    def validate_verdict(self) -> QCReviewCreate:
        serious = {"critical", "high", "medium"}
        if self.verdict == "pass" and any(finding.severity in serious for finding in self.findings):
            raise ValueError("pass reviews cannot contain medium-or-higher findings")
        if self.verdict in {"revise", "block"} and not self.findings:
            raise ValueError(f"{self.verdict} reviews require at least one finding")
        return self


class ReviewView(QCReviewCreate):
    id: str
    submission_id: str
    qc_agent_id: str
    created_at: str


class SubmissionCreate(BaseModel):
    task_version: int = Field(ge=1)
    claim_fencing_token: int = Field(ge=1)
    resource_fencing_tokens: dict[str, int]
    base_revision: str = Field(min_length=1, max_length=500)
    artifact_uri: str = Field(min_length=1, max_length=2000)
    artifact_hash: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    summary: str = Field(min_length=1, max_length=4000)
    evidence: list[str] = Field(default_factory=list, max_length=200)


class SubmissionView(BaseModel):
    id: str
    task_id: str
    worker_agent_id: str
    task_version: int
    claim_fencing_token: int
    resource_fencing_tokens: dict[str, int]
    base_revision: str
    artifact_uri: str
    artifact_hash: str
    summary: str
    evidence: list[str]
    status: str
    created_at: str


class TaskCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=300)
    description: str = Field(min_length=1, max_length=8000)
    acceptance_criteria: list[str] = Field(min_length=1, max_length=200)
    resources: list[str] = Field(default_factory=list, max_length=500)
    dependencies: list[str] = Field(default_factory=list, max_length=200)
    priority: int = Field(default=50, ge=0, le=100)
    parent_task_id: str | None = Field(default=None, min_length=1, max_length=200)
    max_claims: int | None = Field(
        default=None,
        strict=True,
        gt=0,
        le=2**63 - 1,
        description=(
            "Maximum successful Coordination API claim reservations for this task. "
            "This does not limit worker starts or provider usage."
        ),
    )
    max_descendant_claims: int | None = Field(
        default=None,
        strict=True,
        ge=0,
        le=2**63 - 1,
        description=(
            "Maximum successful Coordination API claim reservations across descendants "
            "at any depth; the task's own claims are excluded."
        ),
    )
    max_dispatch_attempts: int | None = Field(
        default=None,
        strict=True,
        ge=0,
        le=2**63 - 1,
        description=(
            "Maximum cooperative dispatch-attempt reservations for this task. "
            "This counts reservations, not verified provider requests or spend."
        ),
    )
    max_descendant_dispatch_attempts: int | None = Field(
        default=None,
        strict=True,
        ge=0,
        le=2**63 - 1,
        description=(
            "Maximum cooperative dispatch-attempt reservations across descendants "
            "at any depth; the task's own reservations are excluded."
        ),
    )
    provider_cost_limit_usd_micros: int | None = Field(
        default=None,
        strict=True,
        gt=0,
        le=2**63 - 1,
        description=(
            "Requested hard provider-cost limit in USD micros. This deployment has no "
            "authenticated provider meter or request gate, so a non-null value is refused."
        ),
    )

    @field_validator("acceptance_criteria", "resources", "dependencies")
    @classmethod
    def require_unique_nonempty_values(cls, values: list[str]) -> list[str]:
        normalized = [value.strip() for value in values]
        if any(not value for value in normalized):
            raise ValueError("list values cannot be empty")
        if len(set(normalized)) != len(normalized):
            raise ValueError("list values must be unique")
        return normalized

    @field_validator("parent_task_id")
    @classmethod
    def require_nonempty_parent_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("parent_task_id cannot be empty")
        return normalized


class ClaimBudgetView(BaseModel):
    scope: Literal["task", "descendant_tree"]
    unit: Literal["successful_claim_reservations"]
    limit: int | None
    consumed: int | None
    remaining: int | None
    status: Literal["available", "exhausted", "unlimited", "invalid"]
    source: Literal["tasks.claim_fencing_token"]
    enforcement: Literal["BEGIN IMMEDIATE task claim and SQLite trigger"]
    observed_at: str


class ProviderUsageEvidence(BaseModel):
    status: Literal["unsupported"]
    unit: None
    source: None
    scope: Literal["provider calls and provider-internal fan-out"]
    observed_at: None
    freshness: Literal["unknown"]
    enforcement_point: None
    reason: Literal["no authenticated provider meter or request gate are wired to this supervisor"]


class ProviderUsageReport(BaseModel):
    """One unverified, report-only provider response usage observation."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["reported", "missing", "invalid"]
    provider: Literal["openai", "anthropic", "gemini", "unknown"]
    adapter: Literal["responses", "messages", "generate_content", "unknown"]
    source: Literal["client_reported"]
    scope: Literal["single_response"]
    unit: Literal["tokens"] | None
    observed_at: str = Field(min_length=20, max_length=40)
    response_id: str | None = Field(
        default=None, min_length=6, max_length=256, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$"
    )
    model: str | None = Field(
        default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"
    )
    response_created_at: StrictInt | None = Field(default=None, ge=0, le=253402300799)
    measurements: dict[str, StrictInt] = Field(default_factory=dict, max_length=16)
    freshness: Literal["unknown"]
    enforcement: Literal["report_only"]
    reason: (
        Literal[
            "provider_response_usage_object_missing",
            "provider_response_metadata_malformed",
            "provider_response_not_terminal",
            "provider_usage_missing",
            "provider_usage_malformed",
            "provider_usage_inconsistent_total",
            "provider_usage_extractor_failed",
        ]
        | None
    ) = None

    @field_validator("observed_at")
    @classmethod
    def require_timestamp(cls, value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("observed_at must be an ISO-8601 timestamp") from None
        if parsed.tzinfo is None:
            raise ValueError("observed_at must include a timezone")
        try:
            parsed.astimezone(UTC)
        except (OverflowError, ValueError):
            raise ValueError("observed_at must normalize to UTC") from None
        return value

    @model_validator(mode="after")
    def validate_measurements(self) -> ProviderUsageReport:
        allowed_measurements = {
            "input_tokens",
            "output_tokens",
            "total_tokens",
            "cached_input_tokens",
            "cache_write_input_tokens",
            "tool_use_prompt_tokens",
            "reasoning_output_tokens",
        }
        if any(
            not key.isascii()
            or not key
            or len(key) > 64
            or key not in allowed_measurements
            or any(not (char.isalnum() or char == "_") for char in key)
            or not 0 <= value <= 2**63 - 1
            for key, value in self.measurements.items()
        ):
            raise ValueError("provider usage measurement is invalid")

        if self.status == "reported":
            required = {"input_tokens", "output_tokens", "total_tokens"}
            if (
                (self.provider, self.adapter)
                not in {
                    ("openai", "responses"),
                    ("anthropic", "messages"),
                    ("gemini", "generate_content"),
                }
                or self.unit != "tokens"
                or self.response_id is None
                or self.model is None
                or not required <= self.measurements.keys()
                or self.measurements["total_tokens"]
                != self.measurements["input_tokens"] + self.measurements["output_tokens"]
                or self.reason is not None
            ):
                raise ValueError("reported usage requires consistent per-response token counts")
        elif self.unit is not None or self.measurements or self.reason is None:
            raise ValueError("missing or invalid usage cannot carry token counts")
        return self


class ProviderUsageSummaryGroup(BaseModel):
    """Sampled report-only totals for one provider, adapter, and model."""

    model_config = ConfigDict(extra="forbid")

    provider: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_-]*$")
    adapter: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_-]*$")
    model: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    response_count: StrictInt = Field(ge=1, le=1000)
    latest_client_observed_at: str = Field(min_length=20, max_length=40)
    measurements: dict[str, StrictInt] = Field(min_length=1, max_length=16)
    measurement_response_counts: dict[str, StrictInt] = Field(min_length=1, max_length=16)

    @field_validator("latest_client_observed_at")
    @classmethod
    def require_zoned_timestamp(cls, value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("latest client observation must be an ISO-8601 timestamp") from None
        if parsed.tzinfo is None:
            raise ValueError("latest client observation must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_measurement_counts(self) -> ProviderUsageSummaryGroup:
        allowed = {
            "input_tokens",
            "output_tokens",
            "total_tokens",
            "cached_input_tokens",
            "cache_write_input_tokens",
            "tool_use_prompt_tokens",
            "reasoning_output_tokens",
        }
        if (
            set(self.measurements) != set(self.measurement_response_counts)
            or not set(self.measurements) <= allowed
            or any(
                not 0 <= count <= self.response_count
                for count in self.measurement_response_counts.values()
            )
            or any(value < 0 for value in self.measurements.values())
        ):
            raise ValueError("provider usage summary measurements are invalid")
        return self


class ReportedProviderUsageView(BaseModel):
    """Bounded summaries of client-reported dispatch receipts, not provider metering."""

    scope: Literal["task", "descendant_tree"]
    status: Literal["none", "observed", "partial", "invalid"]
    source: Literal["client_reported"]
    capture_scope: Literal["ACP dispatch receipts only"]
    unit: Literal["tokens"]
    reservation_count: StrictInt | None = Field(default=None, ge=0)
    sampled_reservation_count: StrictInt | None = Field(default=None, ge=0, le=1000)
    reported_response_count: StrictInt | None = Field(default=None, ge=0, le=1000)
    missing_report_count: StrictInt | None = Field(default=None, ge=0, le=1000)
    invalid_report_count: StrictInt | None = Field(default=None, ge=0, le=1000)
    receipt_without_report_count: StrictInt | None = Field(default=None, ge=0, le=1000)
    reservation_without_receipt_count: StrictInt | None = Field(default=None, ge=0, le=1000)
    latest_receipt_received_at_in_sample: str | None = Field(
        default=None, min_length=20, max_length=40
    )
    truncated: bool
    sample_limit: StrictInt = Field(ge=1, le=1000)
    freshness: Literal["unknown"]
    enforcement: Literal["report_only"]
    reasons: list[
        Literal[
            "descendant_lineage_invalid",
            "stored_usage_report_invalid",
            "summary_truncated",
        ]
    ] = Field(default_factory=list)
    groups: list[ProviderUsageSummaryGroup] = Field(default_factory=list, max_length=1000)


class DispatchAttemptBudgetView(BaseModel):
    scope: Literal["task", "descendant_tree"]
    unit: Literal["dispatch_attempt_reservations"]
    limit: int | None
    consumed: int | None
    remaining: int | None
    reserved: Literal[0]
    released: Literal[0]
    status: Literal["available", "exhausted", "unlimited", "invalid"]
    source: Literal["dispatch_attempt_reservations"]
    enforcement: Literal["BEGIN IMMEDIATE reservation and SQLite trigger"]
    observed_at: str
    provider_usage: ProviderUsageEvidence
    reported_provider_usage: ReportedProviderUsageView | None = None


class DispatchAttemptReceiptCreate(BaseModel):
    claim_fencing_token: StrictInt = Field(ge=1)
    http_status_code: int = Field(strict=True, ge=100, le=599)
    retry_after_seconds: int | None = Field(default=None, strict=True, ge=0, le=86400)
    provider_usage_report: ProviderUsageReport | None = None


class DispatchAttemptReceiptView(BaseModel):
    dispatch_attempt_id: str
    source: Literal["client_reported"]
    http_status_code: int
    retry_after_seconds: int | None
    received_at: str
    provider_usage: ProviderUsageEvidence
    provider_usage_report: ProviderUsageReport | None = None


class DispatchAttemptReceiptResult(BaseModel):
    receipt: DispatchAttemptReceiptView
    created: bool


class DispatchAttemptReservationCreate(BaseModel):
    claim_fencing_token: StrictInt = Field(ge=1)
    resource_fencing_tokens: dict[str, StrictInt]
    idempotency_key: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9._:-]+$")


class DispatchAttemptView(BaseModel):
    id: str
    task_id: str
    agent_id: str
    claim_fencing_token: int
    resource_fencing_tokens: dict[str, int]
    idempotency_key: str
    status: Literal["reserved", "reported"]
    created_at: str
    receipt: DispatchAttemptReceiptView | None = None


class DispatchAttemptReservationResult(BaseModel):
    reservation: DispatchAttemptView
    created: bool


class TaskView(BaseModel):
    id: str
    title: str
    description: str
    acceptance_criteria: list[str]
    resources: list[str]
    dependencies: list[str]
    priority: int
    status: TaskStatus
    owner_agent_id: str | None
    claim_expires_at: int | None
    claim_fencing_token: int
    parent_task_id: str | None
    ancestor_lineage_integrity: Literal["valid", "invalid"]
    max_claims: int | None
    max_descendant_claims: int | None
    claim_budget: ClaimBudgetView
    descendant_claim_budget: ClaimBudgetView
    max_dispatch_attempts: int | None
    max_descendant_dispatch_attempts: int | None
    dispatch_attempt_budget: DispatchAttemptBudgetView
    descendant_dispatch_attempt_budget: DispatchAttemptBudgetView
    version: int
    created_at: str
    updated_at: str
    latest_submission: SubmissionView | None = None
    latest_review: ReviewView | None = None


class TaskClaimRequest(BaseModel):
    ttl_seconds: int = Field(default=300, ge=30, le=3600)


class ResourceLeaseView(BaseModel):
    resource: str
    task_id: str
    holder_agent_id: str
    fencing_token: int
    expires_at: int


class TaskClaimView(BaseModel):
    task: TaskView
    resource_leases: list[ResourceLeaseView]


class HeartbeatRequest(BaseModel):
    claim_fencing_token: int = Field(ge=1)
    resource_fencing_tokens: dict[str, int]
    ttl_seconds: int = Field(default=300, ge=30, le=3600)
    checkpoint: dict[str, Any] = Field(default_factory=dict)


class HeartbeatView(BaseModel):
    task_id: str
    agent_id: str
    claim_fencing_token: int
    expires_at: int
    checkpoint: dict[str, Any]


class TaskCompleteRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)


class TaskReopenRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)


class ReapReport(BaseModel):
    orphaned_task_ids: list[str]
    conflicted_task_ids: list[str]
    released_resources: int
