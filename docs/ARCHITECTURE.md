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
                          heartbeat ───────►│   working   │
                                           └──────┬──────┘
                             lease expiry         │ submit
                                  │               ▼
                                  ▼        ┌─────────────┐
                           ┌──────────┐     │  qc_review  │
                           │ orphaned │     └──┬───────┬──┘
                           └────┬─────┘  revise│       │pass
                                │ claim        ▼       ▼
                                └──────► changes_   approved
                                          requested      │
                                             │ claim      │complete
                                             └──────►     ▼
                                                        done
```

`blocked` records a QC rejection, while `conflicted` records a task whose
post-submission resource reservation expired before safe completion. Both require
operator or planner action.

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

Workers heartbeat with a checkpoint and renewed TTL. The reaper:

- marks expired active work `orphaned`;
- releases its resources;
- rejects later writes using the old fencing tokens; and
- marks expired review/completion reservations `conflicted` instead of silently
  treating unreviewed work as safe.

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
