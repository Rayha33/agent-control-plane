# Agent Control Plane

[![CI](https://github.com/Rayha33/agent-control-plane/actions/workflows/ci.yml/badge.svg)](https://github.com/Rayha33/agent-control-plane/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB.svg)](pyproject.toml)

An open-source reference control plane for AI-agent teams: delegated authority,
collision-free work ownership, independent quality control, and tamper-evident
audit.

Agent Control Plane is designed around two failure modes that become more
expensive as agents become more capable:

- an agent acts with more authority than it should; and
- multiple agents edit or ship the same thing without a reliable owner or
  independent reviewer.

The service provides the coordination primitives needed to prevent both.

## What it guarantees

### Authority

- Signed, expiring mandate tokens
- User → agent → child-agent delegation chains
- Scope attenuation: a child cannot receive more authority than its parent
- Deny-first policy overlays, transaction limits, and one-time approvals
- Immediate agent kill switches and mandate revocation

### Collision-free coordination

- Dependency-aware task DAGs
- Atomic task claims
- Exact-resource leases for files, services, datasets, or deployment targets
- Monotonic fencing tokens that reject stale or “zombie” workers
- Heartbeats, checkpoints, expired-claim recovery, and explicit conflict states
- Immutable artifact submissions tied to the claim and resource versions

### Independent QC

- Separate worker and QC roles
- A worker cannot review its own submission
- Structured findings with severity, evidence, and required fixes
- Resources stay reserved during review, preventing another agent from
  overwriting work that has not passed QC
- Completion remains closed until the latest submission receives an independent
  pass

### Evidence

- Append-only, hash-chained audit events
- Audit-chain verification endpoint
- Review and submission history attached to every task

## Architecture

```text
 planner / admin
       │ creates task DAG + declares exact resources
       ▼
┌──────────────────────── Agent Control Plane ─────────────────────────┐
│ authority │ atomic claims + leases │ submissions │ independent QC   │
│ mandates  │ fencing + heartbeats   │ evidence    │ completion gate  │
└─────┬──────────────┬────────────────────┬───────────────────┬────────┘
      │              │                    │                   │
      ▼              ▼                    ▼                   ▼
 worker A       isolated workspace   QC agent B        hash-chain audit
      │              │                    │
      └──── artifact + test evidence ─────┘
```

The control plane owns coordination state. Agent runners should give each claim
its own branch, worktree, container, or sandbox. Every write-capable operation
must carry the current fencing tokens; a stale token is rejected even if an old
worker resumes after a crash.

See [Architecture](docs/ARCHITECTURE.md) for the state machine, invariants, and
production boundaries.

## Run locally

Prerequisites: Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/Rayha33/agent-control-plane.git
cd agent-control-plane
uv sync --extra dev

export ACP_ADMIN_KEY="replace-with-a-long-random-value"
export ACP_SIGNING_KEY="replace-with-an-independent-long-random-value"
export ACP_DATABASE_PATH="agent_control_plane.db"

uv run uvicorn agent_control_plane.app:create_app --factory --reload
```

Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) for the interactive
API. The built-in defaults are intentionally obvious and must only be used for
local development.

## Minimal coordinated-work flow

1. An administrator registers one `worker` agent and a different `qc` agent.
2. Each agent receives a mandate containing `coordination.*` on `task:*`.
3. The administrator creates a task with acceptance criteria, dependencies, and
   every resource it may mutate.
4. The worker atomically claims the task and receives task/resource fencing
   tokens.
5. The worker heartbeats while working and submits an artifact hash plus test
   evidence.
6. The independent QC agent returns `pass`, `revise`, `block`, or
   `human_required`.
7. Only a passing review lets the administrator mark the task complete and
   release its resources.

The OpenAPI document contains the complete request schemas. Important endpoints:

| Endpoint | Purpose |
|---|---|
| `POST /v1/tasks` | Create a task with dependencies and resources |
| `POST /v1/tasks/{id}/claim` | Atomically claim work and obtain fencing tokens |
| `POST /v1/tasks/{id}/heartbeat` | Renew the claim and store a checkpoint |
| `POST /v1/tasks/{id}/submissions` | Submit immutable artifact evidence |
| `POST /v1/submissions/{id}/reviews` | Record independent structured QC |
| `POST /v1/tasks/{id}/complete` | Open the completion gate after QC passes |
| `POST /v1/coordination/reap` | Recover expired workers and reservations |
| `POST /v1/authorize` | Evaluate an intended agent action |
| `GET /v1/audit/verify` | Verify the audit hash chain |

## Development

```bash
uv sync --extra dev
uvx ruff format --check src tests
uvx ruff check src tests
uv run pytest
```

The tests cover delegation attenuation, approval replay, kill switches,
hash-chain tampering, atomic collision rejection, independent QC, fencing-token
rollover, dependency gates, and crash recovery.

## Current boundaries

This is a reference implementation, not a production security product.

- SQLite is intentionally single-node. Use a transactional shared database for
  a distributed deployment.
- Resource names are exact strings; hierarchical and intent-level conflict
  detection are future work.
- The service coordinates work but does not itself create Git worktrees,
  containers, or merge commits.
- Artifact URIs and hashes are recorded but artifact storage is external.
- Shared HMAC signing should be replaced by asymmetric keys or managed KMS.
- Multi-tenant isolation, SSO/RBAC, authenticated human approvers, rate limits,
  durable event export, and gateway enforcement remain production work.

## Project

- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [License](LICENSE): Apache-2.0

The commercial research brief is deliberately kept out of the public package;
this repository contains the open implementation and technical design.
