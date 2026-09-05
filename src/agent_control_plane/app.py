from __future__ import annotations

import secrets
from collections.abc import Mapping
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _distribution_version

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import Settings
from .coordination import CoordinationService
from .coordination_schemas import (
    HeartbeatRequest,
    HeartbeatView,
    QCReviewCreate,
    ReapReport,
    ReviewView,
    SubmissionCreate,
    SubmissionView,
    TaskClaimRequest,
    TaskClaimView,
    TaskCompleteRequest,
    TaskCreate,
    TaskStatus,
    TaskView,
)
from .database import Database
from .schemas import (
    A2ASideEffectMutation,
    ActionRequestView,
    AgentCreate,
    AgentStateChange,
    AgentView,
    ApprovalResolve,
    AuditEventView,
    AuditVerification,
    AuthorizationDecision,
    AuthorizationRequest,
    MandateCreate,
    MandateIssued,
    PolicyCreate,
    PolicyView,
    RevokeMandate,
    SideEffectMutation,
    SideEffectReceiptView,
)
from .service import ControlPlaneError, ControlPlaneService
from .side_effects import (
    A2ASideEffectEnvelope,
    AuthenticatedSideEffectService,
    CoordinationClaimVerifier,
    FencedGateway,
    MCPA2ASideEffectAdapter,
    ProviderDriver,
    default_side_effect_adapters,
)

bearer = HTTPBearer(auto_error=False)


def _resolve_version() -> str:
    """Report the installed distribution version.

    The literal used to live in two places in this file and drifted from
    pyproject (0.1.0 vs 0.2.0). Read the distribution metadata instead, and fall
    back to the package attribute for a source checkout that was never installed.
    """
    try:
        return _distribution_version("agent-control-plane")
    except PackageNotFoundError:  # pragma: no cover - source checkout, not installed
        from . import __version__

        return __version__


API_VERSION = _resolve_version()


def create_app(
    settings: Settings | None = None,
    side_effect_drivers: Mapping[str, ProviderDriver] | None = None,
) -> FastAPI:
    active_settings = settings or Settings.from_env()
    database = Database(active_settings.database_path)
    database.initialize()
    service = ControlPlaneService(database, active_settings)
    coordination = CoordinationService(database, service)
    side_effect_gateway = FencedGateway(
        database,
        CoordinationClaimVerifier(coordination),
        default_side_effect_adapters(side_effect_drivers),
    )
    side_effects = AuthenticatedSideEffectService(service, side_effect_gateway)
    a2a_side_effects = MCPA2ASideEffectAdapter(side_effects)

    app = FastAPI(
        title="Agent Control Plane",
        version=API_VERSION,
        description=(
            "Delegated mandates, collision-free task coordination, independent QC, "
            "kill switches, and tamper-evident evidence for AI agents."
        ),
    )
    app.state.database = database
    app.state.service = service
    app.state.coordination = coordination
    app.state.side_effect_gateway = side_effect_gateway
    app.state.side_effects = side_effects
    app.state.a2a_side_effects = a2a_side_effects
    app.state.settings = active_settings

    @app.exception_handler(ControlPlaneError)
    async def control_plane_error_handler(
        _request: Request, error: ControlPlaneError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=error.status_code,
            content={"error": error.code, "message": error.message},
        )

    def require_admin(x_control_plane_key: str = Header(default="")) -> None:
        if not secrets.compare_digest(x_control_plane_key, active_settings.admin_key):
            raise ControlPlaneError(401, "invalid_admin_key", "invalid control-plane key")

    def require_mandate(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    ) -> str:
        if not credentials or credentials.scheme.lower() != "bearer":
            raise ControlPlaneError(401, "mandate_required", "bearer mandate is required")
        return credentials.credentials

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": API_VERSION}

    @app.post(
        "/v1/agents",
        response_model=AgentView,
        status_code=201,
        dependencies=[Depends(require_admin)],
    )
    def create_agent(request: AgentCreate) -> dict:
        return service.create_agent(request)

    @app.post("/v1/mandates", response_model=MandateIssued, status_code=201)
    def issue_mandate(
        request: MandateCreate,
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
        x_control_plane_key: str = Header(default=""),
    ) -> dict:
        if request.parent_mandate_id:
            delegator_token = credentials.credentials if credentials else None
        else:
            if not secrets.compare_digest(x_control_plane_key, active_settings.admin_key):
                raise ControlPlaneError(
                    401,
                    "invalid_admin_key",
                    "root mandates require the control-plane key",
                )
            delegator_token = None
        return service.issue_mandate(request, delegator_token)

    @app.post(
        "/v1/policies",
        response_model=PolicyView,
        status_code=201,
        dependencies=[Depends(require_admin)],
    )
    def create_policy(request: PolicyCreate) -> dict:
        return service.create_policy(request)

    @app.post("/v1/authorize", response_model=AuthorizationDecision)
    def authorize(
        request: AuthorizationRequest,
        token: str = Depends(require_mandate),
    ) -> dict:
        return service.authorize(token, request)

    @app.get(
        "/v1/actions/{action_id}",
        response_model=ActionRequestView,
        dependencies=[Depends(require_admin)],
    )
    def get_action(action_id: str) -> dict:
        return service.action_request(action_id)

    @app.post(
        "/v1/approvals/{action_id}",
        response_model=ActionRequestView,
        dependencies=[Depends(require_admin)],
    )
    def resolve_approval(action_id: str, request: ApprovalResolve) -> dict:
        return service.resolve_approval(action_id, request)

    @app.post(
        "/v1/agents/{agent_id}/state",
        response_model=AgentView,
        dependencies=[Depends(require_admin)],
    )
    def set_agent_state(agent_id: str, request: AgentStateChange) -> dict:
        return service.set_agent_state(agent_id, disabled=request.disabled, reason=request.reason)

    @app.post(
        "/v1/mandates/{mandate_id}/revoke",
        status_code=204,
        dependencies=[Depends(require_admin)],
    )
    def revoke_mandate(mandate_id: str, request: RevokeMandate) -> None:
        service.revoke_mandate(mandate_id, request.reason)

    @app.get(
        "/v1/audit",
        response_model=list[AuditEventView],
        dependencies=[Depends(require_admin)],
    )
    def audit_events(limit: int = 100) -> list[dict]:
        return database.audit_events(limit=max(1, min(limit, 1000)))

    @app.get(
        "/v1/audit/verify",
        response_model=AuditVerification,
        dependencies=[Depends(require_admin)],
    )
    def verify_audit() -> dict:
        valid, checked, broken_at = database.verify_audit_chain()
        return {
            "valid": valid,
            "events_checked": checked,
            "broken_at_sequence": broken_at,
        }

    @app.post(
        "/v1/tasks",
        response_model=TaskView,
        status_code=201,
        dependencies=[Depends(require_admin)],
    )
    def create_task(request: TaskCreate) -> dict:
        return coordination.create_task(request)

    @app.get(
        "/v1/tasks",
        response_model=list[TaskView],
        dependencies=[Depends(require_admin)],
    )
    def list_tasks(status: TaskStatus | None = None) -> list[dict]:
        return coordination.list_tasks(status)

    @app.get(
        "/v1/tasks/{task_id}",
        response_model=TaskView,
        dependencies=[Depends(require_admin)],
    )
    def get_task(task_id: str) -> dict:
        return coordination.task(task_id)

    @app.post("/v1/tasks/{task_id}/claim", response_model=TaskClaimView)
    def claim_task(
        task_id: str,
        request: TaskClaimRequest,
        token: str = Depends(require_mandate),
    ) -> dict:
        return coordination.claim_task(task_id, token, request.ttl_seconds)

    @app.post("/v1/tasks/{task_id}/heartbeat", response_model=HeartbeatView)
    def task_heartbeat(
        task_id: str,
        request: HeartbeatRequest,
        token: str = Depends(require_mandate),
    ) -> dict:
        return coordination.heartbeat(task_id, token, request)

    @app.post(
        "/v1/side-effects/{operation}",
        response_model=SideEffectReceiptView,
        status_code=201,
    )
    def execute_side_effect(
        operation: str,
        request: SideEffectMutation,
        token: str = Depends(require_mandate),
    ) -> dict:
        return side_effects.execute(
            token,
            task_id=request.task_id,
            operation=operation,
            claim_fencing_token=request.claim_fencing_token,
            resource_fencing_tokens=request.resource_fencing_tokens,
            target_resource=request.target_resource,
            idempotency_key=request.idempotency_key,
            payload=request.payload,
        ).to_dict()

    @app.post(
        "/v1/a2a/side-effects/{operation}",
        response_model=SideEffectReceiptView,
        status_code=201,
    )
    def execute_a2a_side_effect(
        operation: str,
        request: A2ASideEffectMutation,
        token: str = Depends(require_mandate),
    ) -> dict:
        return a2a_side_effects.execute(
            token,
            A2ASideEffectEnvelope(
                task_id=request.task_id,
                artifact_id=request.artifact_id,
                kind=request.kind,
                operation=operation,
                claim_fencing_token=request.claim_fencing_token,
                resource_fencing_tokens=request.resource_fencing_tokens,
                idempotency_key=request.idempotency_key,
                payload=request.payload,
            ),
        ).to_dict()

    @app.get(
        "/v1/tasks/{task_id}/side-effect-receipts",
        response_model=list[SideEffectReceiptView],
        dependencies=[Depends(require_admin)],
    )
    def side_effect_receipts(task_id: str) -> list[dict]:
        return side_effect_gateway.receipts(task_id)

    @app.post(
        "/v1/tasks/{task_id}/submissions",
        response_model=SubmissionView,
        status_code=201,
    )
    def submit_task(
        task_id: str,
        request: SubmissionCreate,
        token: str = Depends(require_mandate),
    ) -> dict:
        return coordination.submit(task_id, token, request)

    @app.get(
        "/v1/submissions/{submission_id}",
        response_model=SubmissionView,
        dependencies=[Depends(require_admin)],
    )
    def get_submission(submission_id: str) -> dict:
        return coordination.submission(submission_id)

    @app.post(
        "/v1/submissions/{submission_id}/reviews",
        response_model=ReviewView,
        status_code=201,
    )
    def review_submission(
        submission_id: str,
        request: QCReviewCreate,
        token: str = Depends(require_mandate),
    ) -> dict:
        return coordination.review(submission_id, token, request)

    @app.post(
        "/v1/tasks/{task_id}/complete",
        response_model=TaskView,
        dependencies=[Depends(require_admin)],
    )
    def complete_task(task_id: str, request: TaskCompleteRequest) -> dict:
        return coordination.complete_task(task_id, request.reason)

    @app.post(
        "/v1/coordination/reap",
        response_model=ReapReport,
        dependencies=[Depends(require_admin)],
    )
    def reap_expired_claims() -> dict:
        return coordination.reap_expired()

    return app
