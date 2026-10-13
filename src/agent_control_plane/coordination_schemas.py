from __future__ import annotations

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


class DispatchAttemptReceiptCreate(BaseModel):
    claim_fencing_token: StrictInt = Field(ge=1)
    http_status_code: int = Field(strict=True, ge=100, le=599)
    retry_after_seconds: int | None = Field(default=None, strict=True, ge=0, le=86400)


class DispatchAttemptReceiptView(BaseModel):
    dispatch_attempt_id: str
    source: Literal["client_reported"]
    http_status_code: int
    retry_after_seconds: int | None
    received_at: str


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
