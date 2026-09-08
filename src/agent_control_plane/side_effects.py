"""Fenced gateway for side effects that a git worktree cannot isolate.

Board task #741.

Two agents on separate worktrees cannot collide in the filesystem. They collide everywhere else:
the same Postgres schema, the same preview namespace, the same artifact tag. ACP already mints the
tokens that make ordering decidable -- a monotonic ``claim_fencing_token`` per task claim and a
monotonic ``fencing_token`` per resource lease -- but until now nothing stood between a holder of a
*stale* token and the external system. This module is that gate.

The shape is deliberately provider-neutral: every mutating call arrives as a
:class:`SideEffectRequest` carrying task, actor, claim token and the full set of resource tokens,
and every adapter is a thin :class:`SideEffectAdapter` over an injected driver. Postgres, deploy
namespaces and artifact publication differ only in how they name a resource and what they do once
admitted -- so the enforcement is written once, and a new provider cannot accidentally acquire its
own weaker rules.

Ordering is the whole product
-----------------------------
Every rejection reason -- wrong role, undeclared target, expired claim, superseded token,
cross-task token -- is decided **before** the adapter is reachable. That is not a stylistic
preference: a gate that validates after the fact is not a gate, it is a log. The tests assert this
directly by giving every rejection path an adapter that raises if it is ever invoked.

Reuse over reimplementation
---------------------------
The claim/lease predicate is NOT copied here. :class:`CoordinationClaimVerifier` delegates to
``CoordinationService._assert_active_claim``, the same function that guards heartbeats and
submissions. Restating those rules in a second place would let the two drift, and a fencing check
that disagrees with the one that issued the token is worse than none. The cost is a dependency on
a private name; that is deliberate, and if upstream renames it these tests fail loudly, which is
the correct outcome.
"""

from __future__ import annotations

import hashlib
import sqlite3
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import quote

from .database import Database, canonical_json, utc_now
from .policy import scope_allows
from .service import ControlPlaneError

# Roles permitted to drive external side effects. Reviewers observe; they do not mutate.
MUTATING_ROLES: frozenset[str] = frozenset({"worker"})

# Resource-name prefixes. A resource string is the SHARED identity two agents contend over, so it
# must be derivable from the payload alone -- never from an adapter's internal state, or two
# callers could name the same external object differently and both be admitted.
RESOURCE_KIND_DATABASE = "db"
RESOURCE_KIND_DEPLOY = "deploy"
RESOURCE_KIND_ARTIFACT = "artifact"


@dataclass(frozen=True)
class SideEffectRequest:
    """One mutating call, carrying everything needed to decide admission."""

    task_id: str
    agent_id: str
    role: str
    claim_fencing_token: int
    resource_fencing_tokens: dict[str, int]
    target_resource: str
    operation: str
    idempotency_key: str
    payload: dict[str, Any] = field(default_factory=dict)

    def digest_source(self) -> str:
        """Canonical form used for the receipt digest.

        The payload is included so a replayed idempotency key that carries DIFFERENT arguments can
        be detected rather than silently served the old receipt.
        """
        return canonical_json(
            {
                "task_id": self.task_id,
                "agent_id": self.agent_id,
                "target_resource": self.target_resource,
                "operation": self.operation,
                "payload": self.payload,
            }
        )


@dataclass(frozen=True)
class Receipt:
    """Evidence that a side effect happened, bound to who asked and what changed.

    🔴 Holds digests and identities only -- never the payload, never a DSN, token or key. A receipt
    is the thing most likely to be shipped to an auditor or pasted into a ticket, so it is the
    worst possible place to keep a credential.
    """

    id: str
    idempotency_key: str
    task_id: str
    actor_agent_id: str
    target_resource: str
    operation: str
    status: str
    request_digest: str
    result_digest: str
    claim_fencing_token: int
    resource_fencing_token: int
    created_at: str
    replayed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "idempotency_key": self.idempotency_key,
            "task_id": self.task_id,
            "actor_agent_id": self.actor_agent_id,
            "target_resource": self.target_resource,
            "operation": self.operation,
            "status": self.status,
            "request_digest": self.request_digest,
            "result_digest": self.result_digest,
            "claim_fencing_token": self.claim_fencing_token,
            "resource_fencing_token": self.resource_fencing_token,
            "created_at": self.created_at,
            "replayed": self.replayed,
        }


@dataclass(frozen=True)
class ProviderCall:
    """Transport-credential-free context used to fence and deduplicate a mutation.

    The provider gets the idempotency key and monotonically increasing resource
    token explicitly. A real database/deploy/registry adapter should forward
    both to the provider-native transaction or compare-and-set boundary.
    """

    payload: Mapping[str, Any]
    idempotency_key: str
    request_digest: str
    task_id: str
    actor_agent_id: str
    target_resource: str
    operation: str
    claim_fencing_token: int
    resource_fencing_token: int


ProviderDriver = Callable[[ProviderCall], dict[str, Any]]


class ClaimVerifier(Protocol):
    """Decides whether a request's tokens still describe a live, owning claim."""

    def verify(
        self, connection: sqlite3.Connection, request: SideEffectRequest, now: int
    ) -> None: ...


class CoordinationClaimVerifier:
    """Delegates to the coordination service's own claim predicate. See the module docstring."""

    def __init__(self, coordination: Any):
        self._coordination = coordination

    def verify(self, connection: sqlite3.Connection, request: SideEffectRequest, now: int) -> None:
        task = connection.execute("SELECT * FROM tasks WHERE id = ?", (request.task_id,)).fetchone()
        if task is None:
            raise ControlPlaneError(404, "task_not_found", f"unknown task {request.task_id}")
        agent = connection.execute(
            "SELECT id, role, disabled FROM agents WHERE id = ?", (request.agent_id,)
        ).fetchone()
        if agent is None or agent["disabled"]:
            raise ControlPlaneError(
                401, "agent_inactive", "side-effect actor is missing or disabled"
            )
        if agent["role"] != request.role:
            raise ControlPlaneError(
                403,
                "role_mismatch",
                "request role does not match the authoritative agent registry",
            )
        if agent["role"] not in MUTATING_ROLES:
            raise ControlPlaneError(
                403,
                "role_forbidden",
                f"agent role {agent['role']} cannot drive side effects",
            )
        self._coordination._assert_active_claim(
            connection,
            task,
            request.agent_id,
            request.claim_fencing_token,
            request.resource_fencing_tokens,
            now,
        )


class SideEffectAdapter(Protocol):
    """A provider. ``resource_for`` must be a pure function of the payload."""

    kind: str

    def resource_for(self, payload: dict[str, Any]) -> str: ...

    def apply(self, request: SideEffectRequest) -> dict[str, Any]: ...


@dataclass
class ProviderAdapter:
    kind: str
    driver: ProviderDriver
    key_fields: tuple[str, ...]

    def resource_for(self, payload: dict[str, Any]) -> str:
        missing = [name for name in self.key_fields if not payload.get(name)]
        if missing:
            raise ControlPlaneError(
                400,
                "invalid_side_effect_payload",
                f"{self.kind} side effect requires {', '.join(missing)}",
            )
        parts = "/".join(quote(str(payload[name]), safe="") for name in self.key_fields)
        return f"{self.kind}:{parts}"

    def apply(self, request: SideEffectRequest) -> dict[str, Any]:
        return self.driver(
            ProviderCall(
                payload=dict(request.payload),
                idempotency_key=request.idempotency_key,
                request_digest=_digest(request.digest_source()),
                task_id=request.task_id,
                actor_agent_id=request.agent_id,
                target_resource=request.target_resource,
                operation=request.operation,
                claim_fencing_token=request.claim_fencing_token,
                resource_fencing_token=request.resource_fencing_tokens[request.target_resource],
            )
        )


class PostgresSchemaAdapter(ProviderAdapter):
    def __init__(self, driver: ProviderDriver):
        super().__init__(RESOURCE_KIND_DATABASE, driver, ("database", "schema"))


class DeployNamespaceAdapter(ProviderAdapter):
    def __init__(self, driver: ProviderDriver):
        super().__init__(RESOURCE_KIND_DEPLOY, driver, ("environment", "namespace"))


class ArtifactPublicationAdapter(ProviderAdapter):
    def __init__(self, driver: ProviderDriver):
        super().__init__(RESOURCE_KIND_ARTIFACT, driver, ("repository", "tag"))


def postgres_schema_adapter(driver: ProviderDriver) -> PostgresSchemaAdapter:
    """Schema/migration operations. Contended identity is database + schema, not the migration id:
    two different migrations against one schema are exactly the collision worth refusing."""
    return PostgresSchemaAdapter(driver)


def deploy_namespace_adapter(driver: ProviderDriver) -> DeployNamespaceAdapter:
    """Preview/deploy namespaces. Identity is environment + namespace."""
    return DeployNamespaceAdapter(driver)


def artifact_publication_adapter(
    driver: ProviderDriver,
) -> ArtifactPublicationAdapter:
    """Artifact/tag publication. Identity is repository + tag: publishing a DIFFERENT digest to the
    same tag is the mutation that needs fencing, so the digest is deliberately not part of it."""
    return ArtifactPublicationAdapter(driver)


SUPPORTED_OPERATIONS: Mapping[str, Callable[[ProviderDriver], ProviderAdapter]] = {
    "db.schema": postgres_schema_adapter,
    "db.migrate": postgres_schema_adapter,
    "deploy.publish": deploy_namespace_adapter,
    "deploy.delete": deploy_namespace_adapter,
    "artifact.publish": artifact_publication_adapter,
    "artifact.tag": artifact_publication_adapter,
}


def default_side_effect_adapters(
    drivers: Mapping[str, ProviderDriver] | None = None,
) -> dict[str, ProviderAdapter]:
    """Build the supported adapter set; absent providers fail closed at apply time."""

    configured = drivers or {}

    def unavailable(operation: str) -> ProviderDriver:
        def fail(_call: ProviderCall) -> dict[str, Any]:
            raise ControlPlaneError(
                503,
                "side_effect_provider_unavailable",
                f"no provider driver is configured for {operation}",
            )

        return fail

    return {
        operation: factory(configured.get(operation, unavailable(operation)))
        for operation, factory in SUPPORTED_OPERATIONS.items()
    }


def mcp_resource_identity(kind: str, task_id: str, artifact_id: str) -> str:
    """Map MCP / A2A durable identity onto the same resource strings.

    An A2A ``artifact_id`` is durable across attempts, which is exactly the property a fencing
    resource needs. Mapping it here -- rather than letting the MCP adapter invent its own naming --
    is what stops a call arriving over MCP from bypassing a lease that an HTTP call would honour.
    """
    if not task_id or not artifact_id:
        raise ControlPlaneError(
            400, "invalid_mcp_identity", "MCP side effects require task and artifact identity"
        )
    if kind not in {RESOURCE_KIND_DATABASE, RESOURCE_KIND_DEPLOY, RESOURCE_KIND_ARTIFACT}:
        raise ControlPlaneError(400, "unknown_resource_kind", f"unknown resource kind {kind}")
    return f"{kind}:{artifact_id}"


class AuthenticatedSideEffectService:
    """Authenticate a transport request and derive actor/role from durable state."""

    def __init__(self, control_plane: Any, gateway: FencedGateway):
        self.control_plane = control_plane
        self.gateway = gateway

    def execute(
        self,
        token: str,
        *,
        task_id: str,
        operation: str,
        claim_fencing_token: int,
        resource_fencing_tokens: dict[str, int],
        target_resource: str,
        idempotency_key: str,
        payload: dict[str, Any],
    ) -> Receipt:
        claims, _mandate, agent = self.control_plane.authenticated_agent(token)
        if agent["role"] not in MUTATING_ROLES:
            raise ControlPlaneError(
                403,
                "role_forbidden",
                f"agent role {agent['role']} cannot drive side effects",
            )
        action = f"side_effect.{operation}"
        if not scope_allows(claims["scopes"], action, target_resource):
            raise ControlPlaneError(
                403,
                "side_effect_scope_denied",
                f"mandate does not allow {action} on {target_resource}",
            )
        return self.gateway.execute(
            SideEffectRequest(
                task_id=task_id,
                agent_id=agent["id"],
                role=agent["role"],
                claim_fencing_token=claim_fencing_token,
                resource_fencing_tokens=resource_fencing_tokens,
                target_resource=target_resource,
                operation=operation,
                idempotency_key=idempotency_key,
                payload=payload,
            )
        )


@dataclass(frozen=True)
class A2ASideEffectEnvelope:
    """MCP/A2A transport data mapped into the ordinary side-effect gate."""

    task_id: str
    artifact_id: str
    kind: str
    operation: str
    claim_fencing_token: int
    resource_fencing_tokens: dict[str, int]
    idempotency_key: str
    payload: dict[str, Any] = field(default_factory=dict)


class MCPA2ASideEffectAdapter:
    """Translate durable protocol identity, then reuse the authenticated gateway."""

    def __init__(self, service: AuthenticatedSideEffectService):
        self.service = service

    def execute(self, token: str, envelope: A2ASideEffectEnvelope) -> Receipt:
        target = mcp_resource_identity(envelope.kind, envelope.task_id, envelope.artifact_id)
        return self.service.execute(
            token,
            task_id=envelope.task_id,
            operation=envelope.operation,
            claim_fencing_token=envelope.claim_fencing_token,
            resource_fencing_tokens=envelope.resource_fencing_tokens,
            target_resource=target,
            idempotency_key=envelope.idempotency_key,
            payload=envelope.payload,
        )


class FencedGateway:
    """Admit-then-act gateway for external mutations."""

    def __init__(
        self,
        database: Database,
        verifier: ClaimVerifier,
        adapters: dict[str, SideEffectAdapter],
        clock: Callable[[], int] = lambda: int(time.time()),
    ):
        self.database = database
        self.verifier = verifier
        self.adapters = adapters
        self.clock = clock
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with self.database.connect() as connection:
            connection.executescript(RECEIPT_SCHEMA)

    def execute(self, request: SideEffectRequest) -> Receipt:
        adapter = self.adapters.get(request.operation)
        if adapter is None:
            raise ControlPlaneError(
                400, "unknown_side_effect", f"no adapter for operation {request.operation}"
            )
        if not request.idempotency_key or len(request.idempotency_key) > 300:
            raise ControlPlaneError(
                400,
                "invalid_idempotency_key",
                "idempotency key must contain 1..300 characters",
            )

        # 1. Role. Cheapest check, and the one whose failure says least about internal state.
        if request.role not in MUTATING_ROLES:
            raise ControlPlaneError(
                403,
                "role_forbidden",
                f"agent role {request.role} cannot drive side effects",
            )

        # 2. The target must be one the adapter itself derives from the payload. A caller cannot
        #    name a resource it holds a lease for and then act on a different one.
        derived = adapter.resource_for(request.payload)
        if derived != request.target_resource:
            raise ControlPlaneError(
                409,
                "resource_mismatch",
                f"payload targets {derived}, request declared {request.target_resource}",
            )

        # 3. The target must be among the tokens presented. `_assert_active_claim` already refuses
        #    a token set that does not exactly match the task's declared resources, so this is the
        #    narrower question: is the thing we are about to mutate actually one of them?
        if request.target_resource not in request.resource_fencing_tokens:
            raise ControlPlaneError(
                409,
                "undeclared_resource",
                f"{request.target_resource} was not leased by this task",
            )

        now = self.clock()
        with self.database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")

            # 4. Idempotency, INSIDE the same transaction that validates. Checking outside it would
            #    let two concurrent retries both miss the row and both execute.
            existing = connection.execute(
                "SELECT * FROM side_effect_receipts WHERE idempotency_key = ?",
                (request.idempotency_key,),
            ).fetchone()
            if existing is not None:
                if existing["request_digest"] != _digest(request.digest_source()):
                    raise ControlPlaneError(
                        409,
                        "idempotency_key_reused",
                        "this idempotency key was used for a different request",
                    )
                return _receipt_from_row(existing, replayed=True)

            # 5. Claim and lease freshness -- expired, superseded, cross-task and incomplete token
            #    sets all fail here, still before any adapter call.
            self.verifier.verify(connection, request, now)

            # 6. Only now is the external system reachable.
            result = adapter.apply(request)

            receipt = Receipt(
                id=f"sfx-{uuid.uuid4().hex[:16]}",
                idempotency_key=request.idempotency_key,
                task_id=request.task_id,
                actor_agent_id=request.agent_id,
                target_resource=request.target_resource,
                operation=request.operation,
                status="applied",
                request_digest=_digest(request.digest_source()),
                result_digest=_digest(canonical_json(result)),
                claim_fencing_token=request.claim_fencing_token,
                resource_fencing_token=request.resource_fencing_tokens[request.target_resource],
                created_at=utc_now(),
            )
            connection.execute(
                """
                INSERT INTO side_effect_receipts
                    (id, idempotency_key, task_id, actor_agent_id, target_resource, operation,
                     status, request_digest, result_digest, claim_fencing_token,
                     resource_fencing_token, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.id,
                    receipt.idempotency_key,
                    receipt.task_id,
                    receipt.actor_agent_id,
                    receipt.target_resource,
                    receipt.operation,
                    receipt.status,
                    receipt.request_digest,
                    receipt.result_digest,
                    receipt.claim_fencing_token,
                    receipt.resource_fencing_token,
                    receipt.created_at,
                ),
            )

        self.database.append_audit(
            "side_effect.applied",
            f"agent:{request.agent_id}",
            {
                "operation": receipt.operation,
                "receipt_id": receipt.id,
                "request_digest": receipt.request_digest,
                "resource_fencing_token": receipt.resource_fencing_token,
                "target_resource": receipt.target_resource,
                "task_id": receipt.task_id,
            },
        )
        return receipt

    def receipts(self, task_id: str) -> list[dict[str, Any]]:
        rows = self.database.all(
            "SELECT * FROM side_effect_receipts WHERE task_id = ? ORDER BY created_at, id",
            (task_id,),
        )
        return [_receipt_from_row(row).to_dict() for row in rows]


RECEIPT_SCHEMA = """
CREATE TABLE IF NOT EXISTS side_effect_receipts (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    task_id TEXT NOT NULL,
    actor_agent_id TEXT NOT NULL,
    target_resource TEXT NOT NULL,
    operation TEXT NOT NULL,
    status TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    result_digest TEXT NOT NULL,
    claim_fencing_token INTEGER NOT NULL,
    resource_fencing_token INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_side_effect_receipts_task
    ON side_effect_receipts (task_id);
"""


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _receipt_from_row(row: sqlite3.Row, replayed: bool = False) -> Receipt:
    return Receipt(
        id=row["id"],
        idempotency_key=row["idempotency_key"],
        task_id=row["task_id"],
        actor_agent_id=row["actor_agent_id"],
        target_resource=row["target_resource"],
        operation=row["operation"],
        status=row["status"],
        request_digest=row["request_digest"],
        result_digest=row["result_digest"],
        claim_fencing_token=row["claim_fencing_token"],
        resource_fencing_token=row["resource_fencing_token"],
        created_at=row["created_at"],
        replayed=replayed,
    )


__all__ = [
    "MUTATING_ROLES",
    "RESOURCE_KIND_ARTIFACT",
    "RESOURCE_KIND_DATABASE",
    "RESOURCE_KIND_DEPLOY",
    "SUPPORTED_OPERATIONS",
    "A2ASideEffectEnvelope",
    "ArtifactPublicationAdapter",
    "AuthenticatedSideEffectService",
    "CoordinationClaimVerifier",
    "DeployNamespaceAdapter",
    "FencedGateway",
    "MCPA2ASideEffectAdapter",
    "PostgresSchemaAdapter",
    "ProviderAdapter",
    "ProviderCall",
    "ProviderDriver",
    "Receipt",
    "SideEffectRequest",
    "artifact_publication_adapter",
    "default_side_effect_adapters",
    "deploy_namespace_adapter",
    "mcp_resource_identity",
    "postgres_schema_adapter",
]
