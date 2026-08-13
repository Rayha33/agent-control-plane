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
| attempt | agent, bound credential digest, branch, worktree, claim token, checkpoint, PID, latest commit, pinned trust manifest and executable identities |
| resource lease | normalized resource, owner, monotonic fencing token, expiry |
| runtime environment | generated environment, setup/teardown evidence and lifecycle state |
| runtime allocation | unique local port-pool value, attempt owner and expiry |
| runtime driver resource | scoped resource, internal ownership capability, lifecycle state and cleanup proof |
| credential handle | provider/name/version, exact internal source reference, and keyed target fingerprint—never plaintext |
| runner identity | one role, credential digest, enrollment and revocation state |
| submission | immutable commit/tree/patch hashes, changed paths, resource tokens |
| QC run | reviewer, immutable commit, commands, outputs, structured findings, inherited attempt trust pin |
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
configured setup commands or trusted resource drivers with generated environment variables. The environment
is then injected into the supervised worker, deterministic QC, the critic, and
integration commands. This prevents a verifier from accidentally testing
another attempt's localhost service or database configuration.

Runtime teardown is triggered by negative QC, completed integration, or lease
expiry. Port values are released only after every teardown command passes and
the OS confirms that the ports can be rebound. Failed cleanup remains durable
as <code>teardown_failed</code> and keeps the allocation quarantined for an
operator retry.

Port allocation is a local coordination guarantee, not a kernel reservation.
An unrelated process can still bind after ACP's availability check. Drivers
scope Compose projects, PostgreSQL schemas, and browser profiles by attempt and
require a post-teardown absence observation. Executables are outside the repo
with a root-owned, non-writable parent chain, opened and identity-checked
immediately before execution, and run without a shell under a fixed PATH and
allowlisted environment. Definitions and resource identities are immutable per
attempt. Secret-bearing drivers resolve one named provider to an opaque version
handle at setup. PostgreSQL receives the private libpq passfile through a sealed
or unlinked descriptor; argv and environment values contain only the public
connection target and descriptor path, and startup files/interactive password
fallback are disabled. The handle and ownership capability are persisted as a
<code>setup_pending</code> intent before the external action, so a crash cannot
create an untracked target. The handle is persisted internally so
teardown reopens the exact old version even after <code>current</code> rotates.
Its keyed target/version fingerprint participates in the ownership capability,
without disclosing a raw or guessable digest; the HMAC key is a separate
<code>0600</code> state file rather than part of SQLite. Restart generations are
exclusive and intent/evidence/final-state writes are token-fenced. Explicit
recovery can replace only a stale generation after an inherited kernel
lifetime lock proves that its prior supervisor and driver executors are dead.
Restart must prove teardown on
the old handle before resolving the new one; missing or modified versions and
provider drift quarantine the allocation. Generic shell
hooks remain operator-trusted and do not provide a cleanup proof.

### 4b. Trust rotation is attempt-scoped

The privileged helper stages each release under
`trust/bundles/VERSION-MANIFEST_DIGEST`, fsyncs its files and manifest, removes
write bits from the immutable version directory, and only then replaces the
regular `trust/current` pointer with `rename(2)`. Source components and final
files are opened with no-follow semantics; identity metadata before and after a
copy exposes concurrent in-place mutation. A path replacement after open does
not alter the bytes copied from that descriptor.

Claim reads `current` exactly once and persists a complete pin in the attempt:
bundle ID, canonical manifest SHA-256, and every executable's absolute path,
device, inode, size, and SHA-256. Runtime phases and QC read only that stored
pin and revalidate it immediately before privileged use. They never resolve
`current` as fallback. Therefore rotation has two simultaneous truths: claims
after the atomic pointer swap use the new bundle, while existing attempts keep
the old directory until they drain. Missing or changed old evidence moves the
attempt to `quarantined`, its task to `blocked`, and its runtime resources to
quarantine.

QC copies the attempt pin into its own durable row. Retirement/uninstall is a
monotonic marker, not deletion. The helper has no physical-delete operation,
so upgrades cannot erase an executable still referenced by either table.
`doctor` audits the current pointer and every distinct durable pin and returns
the full set of owner, mode, symlink, manifest, inode, size, and digest errors.

### 4c. External mutations cross one fenced gateway

Worktree and runtime isolation do not stop a delayed process from reaching a
shared database schema, deploy namespace, or artifact tag. Every supported
external mutation therefore carries its task ID, authenticated actor, claim
fencing token, complete resource fencing-token map, target resource,
idempotency key, and payload through one provider-neutral gate.

The order is an invariant: authenticate and authorize the mandate, derive the
actor and role from durable state, derive the target identity from the payload,
prove it is an exact task resource, and re-run the coordination service's live
claim predicate inside an immediate transaction. Only then may an adapter call
its provider. Expired, superseded, incomplete, wrong-role, undeclared, and
cross-task requests cannot reach provider code. A delayed zombie therefore
loses even if its token was valid when its work began; the later owner's higher
claim and resource generations are authoritative when the call lands.

PostgreSQL schema/migration, deploy/preview namespace, and artifact/tag adapters
only differ in their canonical resource derivation and injected driver. A
driver receives a `ProviderCall` containing the request digest, idempotency key,
identity, and both generations, with no transport credential. It must carry the
idempotency key and resource generation to the remote provider's native
transaction or compare-and-set boundary. The local transaction serializes
concurrent retries and persists a single credential-free receipt binding the
request, actor, target, operation, result digest, and generations. Remote
idempotency closes the crash interval between the external effect and local
receipt commit.

MCP/A2A requests supply durable task and artifact identity. Their adapter maps
that identity into the same canonical resource namespace and invokes the same
authenticated service; protocol transport does not create an alternate
authority path.

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
prevent a pass. The reviewer identity must be a declared reviewer (or the
configured critic identity) and differ from the worker identity.

### 6b. The reviewer is itself evidence

A verdict is only as trustworthy as the thing that issued it, so every QC row
stores signed provenance — identity, provider, model, prompt policy, logical
command-selector hash — plus the fingerprint of the evaluation policy in force and the
hash of a deterministic reproduction bundle.

The evaluation policy is fingerprinted as a whole. Swapping a model, editing a
prompt policy, adding a reviewer, or relaxing a high-risk rule all change that
fingerprint, and QC fails closed with <code>reviewer_policy_changed</code> until
an operator ratifies it. The first policy is adopted automatically because there
is nothing to compare it against; every later change is an explicit event. This
is what stops a reviewer upgrade from silently replacing the policy that
approved earlier work.

Calibration closes the loop: golden cases seed known defects, run the real
critic through the same entry point QC uses, and report false-pass and
false-block rates separately with Wilson 95% intervals. Separately, because a
critic that rejects everything has a perfect false-pass rate and no value.

High-risk paths escalate rather than trust one opinion: a passing verdict parks
the submission in <code>pending_second_review</code> until a second distinct
reviewer — optionally from a different provider — also passes, or in
<code>human_required</code> when policy demands a person.

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

### 9. Names are not runner authority

The first enrollment permanently enables local runner authentication. Worker,
critic, and integrator identities have one role and store only a credential
digest. Claims bind the exact worker credential digest into the attempt;
heartbeat, run, terminate, and submit re-authenticate both the identity and that
binding. A revoked-and-rotated secret cannot adopt an attempt claimed by its
predecessor. QC authenticates the configured critic and integration
authenticates its integrator. Credentials enter the CLI through environment,
private files, or file descriptors—not argv or JSON output.

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
2. Replace local bearer identities with asymmetric workload identity and remote
   attestation where the threat model requires it.
3. Put each worktree and QC command in a filesystem/network sandbox.
4. Replace local version files with native secret-manager providers behind the
   same opaque handle/materialize contract.
5. Add container/network namespace drivers behind the runtime lifecycle
   contract.
6. Enforce logical-resource fencing in deployment, database, and artifact
   gateways.
7. Export lifecycle through MCP Tasks or A2A and telemetry through
   OpenTelemetry.
8. Anchor event-chain heads in an external append-only store.

Those layers strengthen enforcement without changing the task, attempt, lease,
submission, QC, or integration contracts.
