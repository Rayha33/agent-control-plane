from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class Scope(BaseModel):
    action: str = Field(min_length=1, max_length=200)
    resource: str = Field(min_length=1, max_length=500)


class AgentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    owner: str = Field(min_length=1, max_length=300)
    parent_agent_id: str | None = None
    role: Literal["worker", "qc", "planner", "integration"] = "worker"


class AgentView(AgentCreate):
    id: str
    disabled: bool
    created_at: str


class MandateCreate(BaseModel):
    agent_id: str
    subject: str = Field(min_length=1, max_length=300)
    scopes: list[Scope] = Field(min_length=1, max_length=100)
    ttl_seconds: int = Field(default=3600, ge=60, le=86_400)
    max_amount_cents: int | None = Field(default=None, ge=0)
    parent_mandate_id: str | None = None


class MandateIssued(BaseModel):
    id: str
    agent_id: str
    token: str
    scopes: list[Scope]
    expires_at: int
    max_amount_cents: int | None
    parent_mandate_id: str | None


class PolicyCreate(BaseModel):
    agent_id: str | None = None
    action_pattern: str = Field(min_length=1, max_length=200)
    resource_pattern: str = Field(min_length=1, max_length=500)
    effect: Literal["allow", "deny"] = "allow"
    requires_approval: bool = False
    max_amount_cents: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_deny_policy(self) -> PolicyCreate:
        if self.effect == "deny" and self.requires_approval:
            raise ValueError("deny policies cannot also require approval")
        return self


class PolicyView(PolicyCreate):
    id: str
    created_at: str


class AuthorizationRequest(BaseModel):
    action: str = Field(min_length=1, max_length=200)
    resource: str = Field(min_length=1, max_length=500)
    context: dict[str, Any] = Field(default_factory=dict)
    approval_id: str | None = None


class AuthorizationDecision(BaseModel):
    decision: Literal["allowed", "denied", "approval_required"]
    reason: str
    agent_id: str | None = None
    mandate_id: str | None = None
    action_request_id: str | None = None


class ApprovalResolve(BaseModel):
    approved: bool
    reason: str = Field(min_length=1, max_length=1000)


class ActionRequestView(BaseModel):
    id: str
    mandate_id: str
    agent_id: str
    action: str
    resource: str
    context: dict[str, Any]
    status: str
    resolution_reason: str | None
    created_at: str
    resolved_at: str | None


class AgentStateChange(BaseModel):
    disabled: bool
    reason: str = Field(min_length=1, max_length=1000)


class RevokeMandate(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)


class AuditEventView(BaseModel):
    sequence: int
    event_id: str
    event_type: str
    actor: str
    payload: dict[str, Any]
    previous_hash: str
    event_hash: str
    created_at: str


class AuditVerification(BaseModel):
    valid: bool
    events_checked: int
    broken_at_sequence: int | None = None
