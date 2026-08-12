# Architecture

ACP is a Git work-safety kernel, not an agent scheduler. Any planner or coding
agent can sit above it. ACP owns the smaller set of decisions that must remain
correct when several processes race or crash.

## Lifecycle

~~~text
open
  │ atomic claim + write-set reservation
  ▼
provisioning ── failure ──► open
  │ branch + worktree created
  ▼
working ── lease expiry ──► orphaned ── replacement claim ──► working
  │ clean committed Git evidence
  ▼
qc_review ── revise ──► changes_requested ── new claim ──► working
  │ pass                       │
  ▼                            └─ block/human ──► blocked
approved
  │ fresh merge + integration commands
  ▼
integrating ── conflict/failure ──► conflicted
  │ pass
  ▼
done + preserved integration branch
~~~

Resources remain reserved from claim through QC and integration. A negative QC
verdict releases them. An expired post-submission reservation makes the task
conflicted; ACP never treats the old approval as current.

## Durable records

| Record | Purpose |
|---|---|
| task | specification, acceptance criteria, dependencies, declared resources, base |
| attempt | agent, branch, worktree, claim token, checkpoint, PID, latest commit |
| resource lease | normalized resource, owner, monotonic fencing token, expiry |
| submission | immutable commit/tree/patch hashes, changed paths, resource tokens |
| QC run | reviewer, immutable commit, commands, outputs, structured findings |
| integration | merge result, integration commands, branch and commit |
| event | same-transaction domain event in a hash chain |

## Invariants

### 1. Overlapping write scopes cannot be active together

Claims run under a SQLite immediate transaction. ACP normalizes path separators
and case, rejects absolute/traversing/internal paths, converts directories to
recursive scopes, and compares exact paths, globs, and directory prefixes.

Examples that collide:

~~~text
src/auth/**
src/auth/token.py

config/*.toml
config/runtime.toml

logical:deployment/production
logical:deployment/production
~~~

Logical resources collide only by exact normalized name. They model non-file
side effects, but downstream gateways must enforce their fencing tokens.

### 2. Time is not authority

Each successful claim increments a global claim token. Each exact normalized
resource independently increments its fencing token. An attempt must still own
the task, have an unexpired lease, and present its current claim token.

Submissions persist the complete resource-token map. QC and integration compare
that map with the live reservation. An expired or replaced reservation closes
the gate even if the candidate previously passed.

### 3. Git, not the worker, supplies evidence

The submit interface accepts an attempt ID and claim token—no caller-provided
artifact hash or changed-file list. ACP derives:

- current commit and tree SHA;
- changed paths relative to the task base SHA;
- SHA-256 of the binary Git diff; and
- current resource fencing tokens.

The worktree must be clean and committed. Every changed path must match the
declared write set. A changed symlink resolving outside the assigned worktree is
rejected.

### 4. A crash does not erase committed work

Heartbeats persist the latest commit and arbitrary JSON checkpoint. The reaper
also reads the old worktree's current HEAD when possible. It does not delete the
old branch or worktree. A replacement starts from the latest durable commit and
receives new fencing tokens.

Uncommitted editor state is deliberately not treated as recoverable evidence.
Agent runners should commit checkpoints or use an external snapshot layer.

### 5. QC observes an immutable candidate

ACP checks out the submission commit into a fresh detached worktree. It runs
trusted deterministic commands and then, if configured, starts the critic
command itself. The review packet contains the original task and Git-derived
facts, not the worker's claims about correctness.

Deterministic command failure always blocks. Medium-or-higher critic findings
prevent a pass. The reviewer identity must equal the configured critic identity
and differ from the worker identity.

### 6. Integration cannot mutate the base branch

ACP creates a fresh worktree and new integration branch from the current base,
merges the immutable candidate, reruns integration commands, and preserves the
branch only on success. Merge conflict or command failure moves the task to
<code>conflicted</code> and releases its reservation.

Promotion of that branch is left to the user's existing human review or merge
queue.

### 7. Events cannot be lost independently of state

Every Git-supervisor state mutation and its event append occur in the same
transaction. Events include the previous event hash. The verify-events command
recomputes the chain.

This is tamper-evident bookkeeping, not external non-repudiation. A future
deployment can export or anchor event hashes.

## Process topology

~~~text
planner / issue tracker / user
           │ task specification
           ▼
      ACP local kernel
      ├── SQLite state + leases + event chain
      ├── task worktree ── worker process
      ├── detached QC worktree ── commands + critic
      └── integration worktree ── merge + commands
                                   │
                                   ▼
                         integration branch / merge queue
~~~

ACP can supervise a worker command and heartbeat it. It can also hand the
worktree and token to an external session. The latter must call heartbeat and
submit explicitly.

## Deployment evolution

The data model is intentionally portable:

1. Replace SQLite transactions with PostgreSQL serializable transactions and
   advisory locks for multi-host use.
2. Authenticate runner, worker, critic, and integrator identities.
3. Put each worktree and QC command in a filesystem/network sandbox.
4. Enforce logical-resource fencing in deployment, database, and artifact
   gateways.
5. Export lifecycle through MCP Tasks or A2A and telemetry through
   OpenTelemetry.
6. Anchor event-chain heads in an external append-only store.

Those layers strengthen enforcement without changing the task, attempt, lease,
submission, QC, or integration contracts.
