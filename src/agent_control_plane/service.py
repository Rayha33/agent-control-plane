from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

from .config import Settings
from .database import Database, canonical_json, utc_now
from .policy import (
    amount_from_context,
    policy_matches,
    scope_allows,
    scope_is_delegable,
)
from .schemas import (
    AgentCreate,
    ApprovalResolve,
    AuthorizationRequest,
    MandateCreate,
    PolicyCreate,
)
from .security import TokenError, decode_token, issue_token


@dataclass
class ControlPlaneError(Exception):
    status_code: int
    code: str
    message: str

    def __str__(self) -> str:
        return self.message


class ControlPlaneService:
    def __init__(self, database: Database, settings: Settings):
        self.database = database
        self.settings = settings

    def create_agent(self, request: AgentCreate) -> dict[str, Any]:
        if request.parent_agent_id and not self._agent(request.parent_agent_id):
            raise ControlPlaneError(404, "parent_not_found", "parent agent not found")
        agent_id = str(uuid.uuid4())
        created_at = utc_now()
        self.database.execute(
            """
            INSERT INTO agents
                (id, name, owner, parent_agent_id, role, disabled, created_at)
            VALUES (?, ?, ?, ?, ?, 0, ?)
            """,
            (
                agent_id,
                request.name,
                request.owner,
                request.parent_agent_id,
                request.role,
                created_at,
            ),
        )
        agent = {
            "id": agent_id,
            "name": request.name,
            "owner": request.owner,
            "parent_agent_id": request.parent_agent_id,
            "role": request.role,
            "disabled": False,
            "created_at": created_at,
        }
        self.database.append_audit("agent.created", request.owner, agent)
        return agent

    def create_policy(self, request: PolicyCreate) -> dict[str, Any]:
        if request.agent_id and not self._agent(request.agent_id):
            raise ControlPlaneError(404, "agent_not_found", "agent not found")
        policy_id = str(uuid.uuid4())
        created_at = utc_now()
        self.database.execute(
            """
            INSERT INTO policies
                (id, agent_id, action_pattern, resource_pattern, effect,
                 requires_approval, max_amount_cents, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                policy_id,
                request.agent_id,
                request.action_pattern,
                request.resource_pattern,
                request.effect,
                int(request.requires_approval),
                request.max_amount_cents,
                created_at,
            ),
        )
        policy = request.model_dump() | {"id": policy_id, "created_at": created_at}
        self.database.append_audit("policy.created", "admin", policy)
        return policy

    def issue_mandate(
        self, request: MandateCreate, delegator_token: str | None = None
    ) -> dict[str, Any]:
        agent = self._agent(request.agent_id)
        if not agent:
            raise ControlPlaneError(404, "agent_not_found", "agent not found")
        if agent["disabled"]:
            raise ControlPlaneError(409, "agent_disabled", "agent is disabled")

        expires_at = int(time.time()) + request.ttl_seconds
        parent = None
        if request.parent_mandate_id:
            if not delegator_token:
                raise ControlPlaneError(
                    401, "delegator_token_required", "parent mandate token is required"
                )
            parent_claims, parent = self.authenticate(delegator_token)
            if parent["id"] != request.parent_mandate_id:
                raise ControlPlaneError(
                    403,
                    "parent_token_mismatch",
                    "token does not represent parent mandate",
                )
            if agent["parent_agent_id"] != parent["agent_id"]:
                raise ControlPlaneError(
                    403,
                    "invalid_delegation_chain",
                    "mandates may only delegate to a direct child agent",
                )
            parent_scopes = parent_claims["scopes"]
            requested_scopes = [scope.model_dump() for scope in request.scopes]
            if not all(scope_is_delegable(scope, parent_scopes) for scope in requested_scopes):
                raise ControlPlaneError(
                    403, "scope_escalation", "child scopes exceed parent authority"
                )
            if expires_at > parent["expires_at"]:
                raise ControlPlaneError(
                    403, "expiry_escalation", "child mandate outlives parent mandate"
                )
            parent_max = parent["max_amount_cents"]
            if parent_max is not None and (
                request.max_amount_cents is None or request.max_amount_cents > parent_max
            ):
                raise ControlPlaneError(
                    403,
                    "amount_escalation",
                    "child amount limit exceeds parent authority",
                )

        mandate_id = str(uuid.uuid4())
        scopes = [scope.model_dump() for scope in request.scopes]
        created_at = utc_now()
        self.database.execute(
            """
            INSERT INTO mandates
                (id, agent_id, subject, parent_mandate_id, scopes_json,
                 max_amount_cents, expires_at, revoked, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
            """,
            (
                mandate_id,
                request.agent_id,
                request.subject,
                request.parent_mandate_id,
                canonical_json(scopes),
                request.max_amount_cents,
                expires_at,
                created_at,
            ),
        )
        token = issue_token(
            signing_key=self.settings.signing_key,
            issuer=self.settings.issuer,
            agent_id=request.agent_id,
            mandate_id=mandate_id,
            subject=request.subject,
            scopes=scopes,
            expires_at=expires_at,
        )
        self.database.append_audit(
            "mandate.issued",
            request.subject,
            {
                "agent_id": request.agent_id,
                "expires_at": expires_at,
                "mandate_id": mandate_id,
                "max_amount_cents": request.max_amount_cents,
                "parent_mandate_id": request.parent_mandate_id,
                "scopes": scopes,
            },
        )
        return {
            "id": mandate_id,
            "agent_id": request.agent_id,
            "token": token,
            "scopes": scopes,
            "expires_at": expires_at,
            "max_amount_cents": request.max_amount_cents,
            "parent_mandate_id": request.parent_mandate_id,
        }

    def authenticate(self, token: str) -> tuple[dict[str, Any], dict[str, Any]]:
        try:
            claims = decode_token(
                token=token,
                signing_key=self.settings.signing_key,
                issuer=self.settings.issuer,
            )
        except TokenError as exc:
            raise ControlPlaneError(401, "invalid_token", str(exc)) from exc

        row = self.database.one("SELECT * FROM mandates WHERE id = ?", (claims["mid"],))
        if not row or row["agent_id"] != claims["sub"]:
            raise ControlPlaneError(401, "unknown_mandate", "mandate does not exist")
        mandate = dict(row)
        if mandate["revoked"]:
            raise ControlPlaneError(401, "mandate_revoked", "mandate is revoked")
        if mandate["expires_at"] <= int(time.time()):
            raise ControlPlaneError(401, "mandate_expired", "mandate is expired")
        self._assert_mandate_chain_active(mandate)
        if json.loads(mandate["scopes_json"]) != claims["scopes"]:
            raise ControlPlaneError(401, "scope_mismatch", "token scopes do not match mandate")
        return claims, mandate

    def authenticated_agent(
        self, token: str
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        claims, mandate = self.authenticate(token)
        agent = self._agent(mandate["agent_id"])
        if not agent or not self._agent_lineage_is_active(agent):
            raise ControlPlaneError(
                401, "agent_lineage_disabled", "agent lineage is missing or disabled"
            )
        return claims, mandate, agent

    def authorize(self, token: str, request: AuthorizationRequest) -> dict[str, Any]:
        claims, mandate = self.authenticate(token)
        agent = self._agent(mandate["agent_id"])
        base = {
            "agent_id": mandate["agent_id"],
            "mandate_id": mandate["id"],
        }

        if not agent or not self._agent_lineage_is_active(agent):
            return self._decision(
                "denied", "agent lineage is disabled", claims["actor"], request, base
            )
        if not scope_allows(claims["scopes"], request.action, request.resource):
            return self._decision(
                "denied",
                "action is outside mandate scope",
                claims["actor"],
                request,
                base,
            )

        try:
            amount = amount_from_context(request.context)
        except ValueError as exc:
            raise ControlPlaneError(400, "invalid_context", str(exc)) from exc
        mandate_max = mandate["max_amount_cents"]
        if mandate_max is not None and (amount is None or amount > mandate_max):
            return self._decision(
                "denied", "amount exceeds mandate limit", claims["actor"], request, base
            )

        policies = self.database.all(
            "SELECT * FROM policies WHERE agent_id IS NULL OR agent_id = ?",
            (mandate["agent_id"],),
        )
        matching = [
            policy
            for policy in policies
            if policy_matches(policy, request.action, request.resource)
        ]
        if any(policy["effect"] == "deny" for policy in matching):
            return self._decision("denied", "denied by policy", claims["actor"], request, base)

        limits = [
            policy["max_amount_cents"]
            for policy in matching
            if policy["max_amount_cents"] is not None
        ]
        if limits and (amount is None or amount > min(limits)):
            return self._decision(
                "denied", "amount exceeds policy limit", claims["actor"], request, base
            )

        requires_approval = any(policy["requires_approval"] for policy in matching)
        if requires_approval:
            if request.approval_id:
                return self._consume_approval(
                    request.approval_id, mandate, claims["actor"], request, base
                )
            action_id = self._create_action_request(mandate, request)
            return self._decision(
                "approval_required",
                "matching policy requires human approval",
                claims["actor"],
                request,
                base | {"action_request_id": action_id},
            )

        return self._decision("allowed", "authorized", claims["actor"], request, base)

    def resolve_approval(self, action_id: str, request: ApprovalResolve) -> dict[str, Any]:
        row = self.database.one("SELECT * FROM action_requests WHERE id = ?", (action_id,))
        if not row:
            raise ControlPlaneError(404, "action_not_found", "action request not found")
        if row["status"] != "pending":
            raise ControlPlaneError(
                409, "action_already_resolved", "action request is already resolved"
            )
        status = "approved" if request.approved else "denied"
        resolved_at = utc_now()
        self.database.execute(
            """
            UPDATE action_requests
            SET status = ?, resolution_reason = ?, resolved_at = ?
            WHERE id = ?
            """,
            (status, request.reason, resolved_at, action_id),
        )
        self.database.append_audit(
            f"approval.{status}",
            "admin",
            {"action_request_id": action_id, "reason": request.reason},
        )
        return self.action_request(action_id)

    def action_request(self, action_id: str) -> dict[str, Any]:
        row = self.database.one("SELECT * FROM action_requests WHERE id = ?", (action_id,))
        if not row:
            raise ControlPlaneError(404, "action_not_found", "action request not found")
        return {
            "id": row["id"],
            "mandate_id": row["mandate_id"],
            "agent_id": row["agent_id"],
            "action": row["action"],
            "resource": row["resource"],
            "context": json.loads(row["context_json"]),
            "status": row["status"],
            "resolution_reason": row["resolution_reason"],
            "created_at": row["created_at"],
            "resolved_at": row["resolved_at"],
        }

    def set_agent_state(self, agent_id: str, *, disabled: bool, reason: str) -> dict[str, Any]:
        agent = self._agent(agent_id)
        if not agent:
            raise ControlPlaneError(404, "agent_not_found", "agent not found")
        self.database.execute(
            "UPDATE agents SET disabled = ? WHERE id = ?", (int(disabled), agent_id)
        )
        self.database.append_audit(
            "agent.disabled" if disabled else "agent.enabled",
            "admin",
            {"agent_id": agent_id, "reason": reason},
        )
        updated = self._agent(agent_id)
        return self._agent_view(updated)

    def revoke_mandate(self, mandate_id: str, reason: str) -> None:
        row = self.database.one("SELECT * FROM mandates WHERE id = ?", (mandate_id,))
        if not row:
            raise ControlPlaneError(404, "mandate_not_found", "mandate not found")
        if row["revoked"]:
            raise ControlPlaneError(409, "mandate_revoked", "mandate is already revoked")
        self.database.execute("UPDATE mandates SET revoked = 1 WHERE id = ?", (mandate_id,))
        self.database.append_audit(
            "mandate.revoked",
            "admin",
            {"mandate_id": mandate_id, "reason": reason},
        )

    def _agent(self, agent_id: str) -> dict[str, Any] | None:
        row = self.database.one("SELECT * FROM agents WHERE id = ?", (agent_id,))
        return dict(row) if row else None

    def _agent_lineage_is_active(self, agent: dict[str, Any]) -> bool:
        seen: set[str] = set()
        current: dict[str, Any] | None = agent
        while current:
            if current["id"] in seen or current["disabled"]:
                return False
            seen.add(current["id"])
            parent_id = current["parent_agent_id"]
            current = self._agent(parent_id) if parent_id else None
        return True

    def _assert_mandate_chain_active(self, mandate: dict[str, Any]) -> None:
        seen = {mandate["id"]}
        parent_id = mandate["parent_mandate_id"]
        now = int(time.time())
        while parent_id:
            if parent_id in seen:
                raise ControlPlaneError(
                    401, "invalid_mandate_chain", "mandate delegation cycle detected"
                )
            seen.add(parent_id)
            row = self.database.one("SELECT * FROM mandates WHERE id = ?", (parent_id,))
            if not row or row["revoked"] or row["expires_at"] <= now:
                raise ControlPlaneError(
                    401,
                    "ancestor_mandate_inactive",
                    "an ancestor mandate is missing, revoked, or expired",
                )
            parent_id = row["parent_mandate_id"]

    @staticmethod
    def _agent_view(agent: dict[str, Any]) -> dict[str, Any]:
        return agent | {"disabled": bool(agent["disabled"])}

    def _create_action_request(self, mandate: dict[str, Any], request: AuthorizationRequest) -> str:
        action_id = str(uuid.uuid4())
        self.database.execute(
            """
            INSERT INTO action_requests
                (id, mandate_id, agent_id, action, resource, context_json,
                 status, resolution_reason, created_at, resolved_at)
            VALUES (?, ?, ?, ?, ?, ?, 'pending', NULL, ?, NULL)
            """,
            (
                action_id,
                mandate["id"],
                mandate["agent_id"],
                request.action,
                request.resource,
                canonical_json(request.context),
                utc_now(),
            ),
        )
        return action_id

    def _consume_approval(
        self,
        approval_id: str,
        mandate: dict[str, Any],
        actor: str,
        request: AuthorizationRequest,
        base: dict[str, Any],
    ) -> dict[str, Any]:
        row = self.database.one("SELECT * FROM action_requests WHERE id = ?", (approval_id,))
        if not row:
            return self._decision("denied", "approval does not exist", actor, request, base)
        matches_request = (
            row["mandate_id"] == mandate["id"]
            and row["action"] == request.action
            and row["resource"] == request.resource
            and row["context_json"] == canonical_json(request.context)
        )
        if not matches_request:
            return self._decision(
                "denied", "approval does not match this action", actor, request, base
            )
        if row["status"] != "approved":
            return self._decision(
                "denied", f"approval status is {row['status']}", actor, request, base
            )
        updated = self.database.execute_count(
            """
            UPDATE action_requests SET status = 'consumed'
            WHERE id = ? AND status = 'approved'
            """,
            (approval_id,),
        )
        if updated != 1:
            return self._decision("denied", "approval was already consumed", actor, request, base)
        return self._decision(
            "allowed",
            "authorized with one-time approval",
            actor,
            request,
            base | {"action_request_id": approval_id},
        )

    def _decision(
        self,
        decision: str,
        reason: str,
        actor: str,
        request: AuthorizationRequest,
        extra: dict[str, Any],
    ) -> dict[str, Any]:
        result = {"decision": decision, "reason": reason} | extra
        self.database.append_audit(
            "authorization.decided",
            actor,
            {
                "action": request.action,
                "context": request.context,
                "decision": decision,
                "reason": reason,
                "resource": request.resource,
                **extra,
            },
        )
        return result
