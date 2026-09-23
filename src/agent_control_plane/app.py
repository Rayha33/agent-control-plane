from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
from collections.abc import AsyncIterator

from fastapi import Depends, FastAPI, Header, Query, Request, Response
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import __version__
from .config import Settings
from .coordination import TASK_PAGE_MAX, CoordinationService
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
    TaskReopenRequest,
    TaskStatus,
    TaskView,
)
from .database import Database
from .schemas import (
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
)
from .service import ControlPlaneError, ControlPlaneService

bearer = HTTPBearer(auto_error=False)
logger = logging.getLogger(__name__)


async def reap_periodically(coordination: CoordinationService, interval: float) -> None:
    """Run the same reap as POST /v1/coordination/reap every ``interval`` seconds."""
    while True:
        await asyncio.sleep(interval)
        try:
            await asyncio.to_thread(coordination.reap_expired)
        except Exception:
            logger.exception("scheduled reap failed; retrying in %ss", interval)


def create_app(settings: Settings | None = None) -> FastAPI:
    active_settings = settings or Settings.from_env()
    if active_settings.insecure_defaults:
        logger.warning(
            "development defaults are active for %s; set real values before "
            "exposing this service",
            ", ".join(active_settings.insecure_defaults),
        )
    database = Database(active_settings.database_path)
    database.initialize()
    service = ControlPlaneService(database, active_settings)
    coordination = CoordinationService(database, service)

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        interval = active_settings.reap_interval_seconds
        if not interval:
            yield
            return
        reaper = asyncio.create_task(reap_periodically(coordination, interval))
        try:
            yield
        finally:
            reaper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reaper

    app = FastAPI(
        title="Agent Control Plane",
        version=__version__,
        lifespan=lifespan,
        description=(
            "Delegated mandates, collision-free task coordination, independent QC, "
            "kill switches, and tamper-evident evidence for AI agents."
        ),
    )
    app.state.database = database
    app.state.service = service
    app.state.coordination = coordination
    app.state.settings = active_settings

    @app.exception_handler(ControlPlaneError)
    async def control_plane_error_handler(
        _request: Request, error: ControlPlaneError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=error.status_code,
            content={"error": error.code, "message": error.message},
        )

    expected_admin_key = active_settings.admin_key.encode("utf-8")

    def admin_key_matches(candidate: str) -> bool:
        # Compared as bytes: secrets.compare_digest raises TypeError on a str with
        # non-ASCII characters, which turned an accented passphrase, or any client
        # sending one, into an unhandled 500 instead of a 401. Starlette decodes
        # header bytes as latin-1, so re-encoding as latin-1 recovers exactly what
        # the client sent; clients send UTF-8, which is what the configured key is
        # compared as.
        try:
            wire = candidate.encode("latin-1")
        except UnicodeEncodeError:
            wire = candidate.encode("utf-8")
        return secrets.compare_digest(wire, expected_admin_key)

    def require_admin(x_control_plane_key: str = Header(default="")) -> None:
        if not admin_key_matches(x_control_plane_key):
            raise ControlPlaneError(
                401, "invalid_admin_key", "invalid control-plane key"
            )

    def require_mandate(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    ) -> str:
        if not credentials or credentials.scheme.lower() != "bearer":
            raise ControlPlaneError(
                401, "mandate_required", "bearer mandate is required"
            )
        return credentials.credentials

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

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
            if not admin_key_matches(x_control_plane_key):
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
        return service.set_agent_state(
            agent_id, disabled=request.disabled, reason=request.reason
        )

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
    def verify_audit(
        after_sequence: int = Query(default=0, ge=0),
        anchor_hash: str | None = Query(default=None, pattern=r"^[0-9a-f]{64}$"),
    ) -> dict:
        if bool(after_sequence) != (anchor_hash is not None):
            raise ControlPlaneError(
                400,
                "invalid_anchor",
                "after_sequence and anchor_hash must be given together",
            )
        if anchor_hash is None:
            return database.verify_audit_chain()
        return database.verify_audit_chain(after_sequence, anchor_hash)

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
    def list_tasks(
        response: Response,
        status: TaskStatus | None = None,
        limit: int = 100,
        after: str | None = None,
    ) -> list[dict]:
        tasks, next_cursor = coordination.list_tasks(
            status, limit=max(1, min(limit, TASK_PAGE_MAX)), after=after
        )
        if next_cursor:
            response.headers["X-Next-Cursor"] = next_cursor
        return tasks

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
        "/v1/tasks/{task_id}/reopen",
        response_model=TaskView,
        dependencies=[Depends(require_admin)],
    )
    def reopen_task(task_id: str, request: TaskReopenRequest) -> dict:
        return coordination.reopen_task(task_id, request.reason)

    @app.post(
        "/v1/coordination/reap",
        response_model=ReapReport,
        dependencies=[Depends(require_admin)],
    )
    def reap_expired_claims() -> dict:
        return coordination.reap_expired()

    return app
