# Architecture

Agent Control Plane separates authority, work ownership, evidence, and quality
control. The separation matters: a worker that can silently expand its own
authority, overwrite another worker, or approve its own output has no meaningful
control boundary.

## Planes

| Plane | Owns | Primary controls |
|---|---|---|
| Authority | Who may do what | mandates, delegation, policies, approvals, kill switches |
| Coordination | Who owns which work | task DAG, atomic claim, leases, fencing, heartbeat |
| Evidence | What was produced | immutable submissions, hashes, test evidence, checkpoints |
| Quality | Whether it is acceptable | separate QC role, structured findings, completion gate |
| Audit | What happened | append-only hash chain and verification |

The implementation is one FastAPI service backed by SQLite. These are logical
boundaries; a production deployment can split them into independently scaled
services.

## Task state machine

```text
                     ┌──────────────┐
        dependencies │              │ claim
        incomplete ──┤     open     ├──────────────┐
                     └──────────────┘              ▼
                                           ┌─────────────┐
                                           │   claimed   ├──────┐
                                           └──────┬──────┘      │
                                        heartbeat │             │
                                                  ▼             │
                                           ┌─────────────┐      │
                          heartbeat ──────►│   working   │      │
                                           └──────┬──────┘      │
                             claim expiry         │ submit      │ submit
                                  │               ▼             │
                                  ▼        ┌─────────────┐      │
                           ┌──────────┐    │  qc_review  │◄─────┘
                           │ orphaned │    └──┬───────┬──┘
                           └──────────┘ revise│       │pass
                             claim →          ▼       ▼
                             claimed     changes_   approved
                                         requested      │
                                         claim →        │complete
                                         claimed        ▼
                                                       done
```

A claim puts the task in `claimed`; only the first heartbeat promotes it to
`working`. A worker that never heartbeats stays `claimed` until it submits or its
claim expires, and both states accept a submission. Every transition:

| From | Event | To |
|---|---|---|
| `open`, `orphaned`, `changes_requested` | claim (all dependencies `done`) | `claimed` |
| `claimed`, `working` | heartbeat | `working` |
| `claimed`, `working` | submit | `qc_review` |
| `claimed`, `working` | claim expires, reaper runs | `orphaned` |
| `qc_review` | review `pass` | `approved` |
| `qc_review` | review `revise` | `changes_requested` |
| `qc_review` | review `block` or `human_required` | `blocked` |
| `qc_review`, `approved` | resource reservation expires, reaper runs | `conflicted` |
| `approved` | complete | `done` |
| `blocked`, `conflicted` | reopen | `open` |

`blocked` records a QC rejection, while `conflicted` records a task whose
post-submission resource reservation expired before safe completion. Both require
operator or planner action, and that action is explicit: `POST /v1/tasks/{id}/reopen`
returns either state to `open` with a new version, releases any remaining
reservation, and appends a `task.reopened` audit event carrying the reason. The
next claim then mints fresh fencing tokens, so nothing produced under the old claim
can be written back.

## Coordination invariants

### 1. A task has one active owner

Claims execute inside `BEGIN IMMEDIATE`. The status check, dependency check,
resource availability check, owner update, and lease assignment are one atomic
transaction.

### 2. A declared resource has one active task

Tasks declare exact resources before execution, for example:

```text
repo:payments:file:src/checkout.py
database:billing:schema
deployment:production:api
```

A claim fails if any resource is reserved by another unexpired task. Resource
names are currently exact strings; callers should use a canonical namespace.

### 3. Time alone never establishes write authority

Each successful claim increments a task fencing token. Each resource also has a
persistent, monotonic fencing token. Heartbeats and submissions must present all
current tokens. Therefore an old worker that wakes after a crash cannot renew or
submit after a replacement has claimed the work.

External systems must apply the same rule: a deployment gateway or artifact
writer should reject any request carrying a fencing token below the latest token
it has observed.

### 4. A submission freezes the review candidate

Submissions are immutable records containing:

- task version and claim fencing token;
- every resource fencing token;
- base revision and artifact URI;
- SHA-256 artifact hash;
- summary and evidence.

On submission, the worker claim ends but the resources remain reserved. This
prevents another worker from modifying the candidate while QC reviews it.

### 5. The author cannot approve the artifact

Only an enabled agent with role `qc` and sufficient mandate scope can review.
The reviewer agent ID must differ from the submission's worker agent ID.

A `pass` moves the task to `approved`, but resources remain reserved until
the administrator opens the completion gate. `revise`, `block`, and
`human_required` release the reservation and preserve the findings for the next
worker.

### 6. Recovery is explicit

Workers heartbeat with a checkpoint and renewed TTL. The reaper runs on each
`POST /v1/coordination/reap`, and also every `ACP_REAP_INTERVAL_SECONDS` inside the
service when that is set (off by default; a failed run is logged and retried on
the next tick). Each run:

- marks expired active work `orphaned`;
- releases its resources;
- rejects later writes using the old fencing tokens; and
- marks expired review/completion reservations `conflicted` instead of silently
  treating unreviewed work as safe; and
- clears the task's heartbeat rows, as every other end of a claim does
  (submission, review, completion, reopen).

## Recommended runner topology

```text
planner
  └── task claim
       ├── isolated branch/worktree/container
       ├── worker process
       ├── heartbeat + checkpoint loop
       └── immutable artifact submission
             └── separate QC process
                   ├── acceptance-criteria checks
                   ├── tests/security review
                   └── pass/revise/block/human_required
```

The runner, not this service, should create the isolated workspace. A practical
Git integration uses one branch and worktree per task, forbids direct writes to
the integration branch, and lets a separate integration agent merge only an
approved artifact.

## Threat model and non-goals

The MVP protects coordination decisions inside one service process and database.
It does not sandbox arbitrary code, store artifacts, authenticate humans through
SSO, or guarantee that an external tool honors a lease. Production enforcement
must be placed at the tool/API/deployment gateway so bypassing the control plane
is not possible.

See [SECURITY.md](../SECURITY.md) for vulnerability reporting and supported
versions.
