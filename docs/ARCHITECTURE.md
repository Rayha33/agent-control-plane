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
  │ branch + worktree + runtime environment created
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

Source and runtime resources remain reserved from claim through QC and
integration. A negative QC verdict releases them. An expired post-submission
reservation makes the task conflicted and triggers teardown; ACP never treats
the old approval as current.

## Durable records

| Record | Purpose |
|---|---|
| task | specification, acceptance criteria, dependencies, declared resources, base |
| attempt | agent, branch, worktree, claim token, checkpoint, PID, latest commit |
| resource lease | normalized resource, owner, monotonic fencing token, expiry |
| runtime environment | generated environment, setup/teardown evidence and lifecycle state |
| runtime allocation | unique local port-pool value, attempt owner and expiry |
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

Enforcement is fail-closed at claim time, but an operator should not have to
launch an agent to discover a collision. `acp plan` and `acp queue` answer the
same question in advance, classifying each collision as `exact` (identical
normalized scopes) or `potential` (different scopes that can still match one
path), and naming the owning task, attempt, and agent.

### 1b. Planning is a preview, never a mutation

`plan`, `queue`, `merge-plan`, and `status` are read-only. They deliberately do
not call `reap_expired()`, unlike `claim` and `list`: a view that reaped would
orphan an attempt merely because an operator looked at the dashboard, and would
change the state it was asked to report. Expired-but-unreaped attempts are
reported as `awaiting_reap` instead. Expired leases are ignored when previewing
a claim, so a preview and the claim that follows agree.

The ready queue reserves each admitted task's scopes for the remainder of the
pass. Its `ready` list is therefore a set of tasks that can run *concurrently*,
not a list of tasks that could each run alone.

### 1c. Artifact dependencies are derived, not declared twice

A task may declare `--produces` and `--consumes` logical artifact names. A
consumer depends on every non-`done` producer of an artifact it consumes; those
edges are derived at read time and enforced at claim time alongside explicit
`--depends-on` edges. Cycles — reachable once artifacts create edges the
operator never wrote — are reported as a `dependency_cycle` blocker with the
concrete cycle, never followed into an infinite walk.

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

### 4. Runtime isolation follows the attempt

Worktree isolation stops direct file overwrites but does not isolate ports,
database schemas, browser profiles, or service state. During the same claim
transaction, ACP allocates one available value from every configured local port
pool and persists the assignment against the attempt.

After the worktree exists, ACP creates a private runtime directory and runs
configured setup commands with generated environment variables. The environment
is then injected into the supervised worker, deterministic QC, the critic, and
integration commands. This prevents a verifier from accidentally testing
another attempt's localhost service or database configuration.

Runtime teardown is triggered by negative QC, completed integration, or lease
expiry. Port values are released only after every teardown command passes and
the OS confirms that the ports can be rebound. Failed cleanup remains durable
as <code>teardown_failed</code> and keeps the allocation quarantined for an
operator retry.

Port allocation is a local coordination guarantee, not a kernel reservation.
An unrelated process can still bind after ACP's availability check. Database or
container isolation is provided by the configured idempotent hooks, not inferred
by ACP.

### 5. A crash does not erase committed work

Heartbeats persist the latest commit and arbitrary JSON checkpoint. The reaper
also reads the old worktree's current HEAD when possible. It does not delete the
old branch or worktree. It stops a registered supervised process group before
tearing down and recycling runtime allocations. A replacement starts from the
latest durable commit and receives new fencing tokens.

Uncommitted editor state is deliberately not treated as recoverable evidence.
Agent runners should commit checkpoints or use an external snapshot layer.

### 6. QC observes an immutable candidate

ACP checks out the submission commit into a fresh detached worktree. It runs
trusted deterministic commands and then, if configured, starts the critic
command itself. The review packet contains the original task and Git-derived
facts, not the worker's claims about correctness.

Deterministic command failure always blocks. Medium-or-higher critic findings
prevent a pass. The reviewer identity must equal the configured critic identity
and differ from the worker identity.

### 7. Integration cannot mutate the base branch

ACP creates a fresh worktree and new integration branch from the current base,
merges the immutable candidate, reruns integration commands, and preserves the
branch only on success. Merge conflict or command failure moves the task to
<code>conflicted</code> and releases its reservation.

Promotion of that branch is left to the user's existing human review or merge
queue.

`acp merge-plan` previews that promotion order before anyone runs it. Approved
submissions are ordered topologically by dependency and then deterministically
by priority, creation time, and id. Each entry reports the paths it shares with
earlier entries as `predicted_conflict_paths`, and is marked `stale` with an
`upstream_commits` count once commits land on the base branch beneath it —
approval is evidence about a base that may since have moved. Conflict prediction
against the current base uses `git merge-tree --write-tree`, which computes the
merge in memory: it writes only unreferenced objects and touches no worktree,
index, or ref. Where the installed Git is too old, `base_conflicts` is `null`
rather than a silently empty list.

### 8. Events cannot be lost independently of state

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
      ├── runtime allocator ── ports + setup/teardown hooks
      ├── task worktree ── worker process + runtime env
      ├── detached QC worktree ── commands + critic + runtime env
      └── integration worktree ── merge + commands + runtime env
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
4. Add container/network namespace drivers behind the runtime lifecycle
   contract.
5. Enforce logical-resource fencing in deployment, database, and artifact
   gateways.
6. Export lifecycle through MCP Tasks or A2A and telemetry through
   OpenTelemetry.
7. Anchor event-chain heads in an external append-only store.

Those layers strengthen enforcement without changing the task, attempt, lease,
submission, QC, or integration contracts.
