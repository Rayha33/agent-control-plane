# ACP: Git work safety for AI coding agents

[![CI](https://github.com/Rayha33/agent-control-plane/actions/workflows/ci.yml/badge.svg)](https://github.com/Rayha33/agent-control-plane/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB.svg)](pyproject.toml)

ACP is a provider-neutral safety kernel for teams running several coding agents
against one Git repository.

It sits below Claude Code, Codex, Cursor, custom runners, and CI. ACP gives each
task an exclusive write set and dedicated worktree, rejects stale workers with
monotonic fencing tokens, preserves committed work after crashes, derives
submission evidence from Git, allocates a per-attempt runtime environment,
and runs quality control in a fresh detached checkout before creating an
integration branch.

The narrow promise is:

> Parallel agents may fail, restart, or disagree. Only work that still owns its
> resources and passes independent, reproducible gates can reach integration.

## Why this exists

Worktrees solve checkout isolation, but not ownership or acceptance:

- two agents can still be assigned overlapping files;
- a delayed agent can resume after a replacement and publish stale work;
- a crashed session can leave useful commits but no durable recovery record;
- the worker's own summary is not independent evidence; and
- review can inspect the wrong checkout or a mutable branch;
- separate worktrees still collide on ports, databases, services, and test data;
  and
- abandoned environments survive unless teardown is durable and retryable.

Vendor documentation acknowledges these failure classes. Anthropic warns that
same-file edits can overwrite, task status can lag, and in-process teammates
cannot be resumed. OpenAI recommends parallel subagents mainly for read-heavy
work because write-heavy work creates conflicts and coordination overhead.
Existing worktree products isolate execution but generally leave overlap
partitioning and final review to the operator.

See [Research](docs/RESEARCH.md) for the evidence, alternatives, and product
wedge.

## What is implemented

| Control | Enforced behavior |
|---|---|
| Normalized resources | Repo-relative paths, globs, directory scopes, and logical resources |
| Atomic claims | SQLite immediate transactions make a colliding claim fail closed |
| Fencing | Every attempt and exact resource receives a monotonic token |
| Worktree ownership | Every successful claim provisions a dedicated branch and worktree |
| Crash recovery | Expired attempts become orphaned; their branch and latest committed SHA remain |
| Runtime isolation | Attempts receive unique configured ports, a runtime directory, and setup/teardown hooks |
| Trusted resource drivers | Compose projects, PostgreSQL schemas, and browser profiles have scoped setup/probe/teardown proofs |
| Scoped credential handles | Drivers receive one immutable credential version over a private descriptor; plaintext never enters argv, inherited env values, state, or evidence |
| Privileged trust bundles | Versioned critic/driver executables are installed by a narrow helper and pinned per attempt/QC by manifest, inode, and content digest |
| Fenced side effects | Database schema/migration, deploy namespace, and artifact/tag mutations require the live task and resource fencing tokens and emit durable, credential-free receipts |
| Runner authentication | Worker, critic, and integrator credentials are role-scoped and attempts bind to the credential version that claimed them |
| Overlap preview | A dry-run claim reports exact and potential scope collisions, and who owns them, before an agent starts |
| Dependency scheduling | Declared and artifact producer/consumer edges gate claims and order a deterministic ready queue |
| Merge scheduling | Approved submissions get an ordering preview, shared-path conflict prediction, and staleness when the base moves |
| Operator status | One read-only screen ranks what needs a human, what failed cleanup, and what is merely running |
| Reviewer provenance | Signed identity/provider/model/prompt-policy on every verdict, with a replayable bundle |
| Policy ratification | A reviewer or prompt upgrade stops QC until a human ratifies the new fingerprint |
| Evaluator calibration | Golden seeded defects score false-pass/false-block rates with Wilson intervals |
| High-risk review | Configured paths can demand two reviewers, provider diversity, or a human |
| Server-derived evidence | Commit, tree, binary patch hash, and changed paths come from Git |
| Write-set validation | Undeclared changed paths and escaping symlinks are rejected |
| Independent QC | A configured reviewer runs deterministic commands in a fresh detached worktree |
| Structured critic | An optional external critic returns evidence-based findings |
| Process lifecycle boundary | Linux subreaper monitors retain descendants and lifecycle locks; Darwin QC/critics run in a no-fork kernel sandbox |
| Integration gate | ACP merges into a new integration branch and reruns configured commands |
| Audit | Git-supervisor mutations and hash-chained events share a transaction |

ACP never pushes or updates the base branch. A passing integration leaves a
named integration branch for a human or existing merge queue.

## Quick start

Requirements: Git, Python 3.11+, and
[uv](https://docs.astral.sh/uv/).

Linux with `/proc` is the production platform for `acp run`: its monitor uses
the kernel child-subreaper contract and does not exit until every adopted
descendant is reaped. Current macOS has no supported recursive process-tracking
primitive, so ACP fails closed instead of polling: QC, critic, hook, and driver
commands run under a kernel no-fork sandbox, while long-running supervised
workers are rejected. Manually operated macOS agents can still use claim,
heartbeat, submit, QC, and integration. CI exercises the complete worker path
on Linux.

Supervisor-owned Git operations disable repository hooks, signing, background
maintenance, global/system Git configuration, and filesystem monitors.
Integration also rejects local filters, custom merge drivers, external diff or
merge tools, credential helpers, and config includes because those settings can
launch processes outside the declared gate lifecycle.

~~~bash
git clone https://github.com/Rayha33/agent-control-plane.git
cd agent-control-plane
uv sync --extra dev
uv run --extra dev acp doctor
~~~

Initialize another repository:

~~~bash
uv run --project /path/to/agent-control-plane acp --repo /path/to/your-repo init
~~~

Create and claim bounded work:

~~~bash
uv run --extra dev acp task-add --title "Harden token refresh" --accept "refresh regression tests pass" --resource "src/auth/**" --resource "tests/auth/**"

uv run --extra dev acp claim TASK_ID --agent codex-session-17
~~~

The zero-configuration local mode is intentionally unauthenticated. Enable
role-scoped authentication by enrolling the first runner. Authentication then
stays enabled even if every credential is revoked. Credentials are written only
to a caller-selected private file or file descriptor—never argv or JSON:

~~~bash
uv run --extra dev acp runner-enroll codex-session-17 --role worker --credential-output-file ../codex-session-17.credential
uv run --extra dev acp runner-enroll independent-qc --role critic --credential-output-file ../independent-qc.credential
uv run --extra dev acp runner-enroll release-integrator --role integrator --credential-output-file ../release-integrator.credential

uv run --extra dev acp claim TASK_ID --agent codex-session-17 --credential-file ../codex-session-17.credential
~~~

The claim response contains <code>worktree</code>, <code>claim_token</code>,
per-resource fencing tokens, and a <code>runtime</code> environment. Run your
agent in that worktree, or let ACP supervise it:

~~~bash
uv run --extra dev acp run ATTEMPT_ID --token CLAIM_TOKEN --credential-file ../codex-session-17.credential -- your-agent-command
~~~

The command must leave a clean, committed worktree. A successful supervised run
submits automatically. For a manually operated agent:

~~~bash
uv run --extra dev acp heartbeat ATTEMPT_ID --token CLAIM_TOKEN --credential-file ../codex-session-17.credential --checkpoint '{"phase":"tests"}'
uv run --extra dev acp submit ATTEMPT_ID --token CLAIM_TOKEN --credential-file ../codex-session-17.credential
uv run --extra dev acp qc SUBMISSION_ID --credential-file ../independent-qc.credential
uv run --extra dev acp integrate TASK_ID --integrator release-integrator --credential-file ../release-integrator.credential
~~~

For ephemeral automation, pass the same secret through
<code>ACP_RUNNER_CREDENTIAL</code> or <code>--credential-fd</code>. Never commit
credential files to the repository. Revoking and re-enrolling an identity
rotates its secret; attempts claimed by the old secret remain fenced.

All commands emit JSON. Local runtime state and logs live under ignored
<code>.acp/</code>; configuration is tracked in <code>acp.toml</code>.

## Privileged critic and driver bundles

Production critic and runtime-driver executables should live outside both the
candidate repository and the ACP service account's writable paths. The package
exports a narrow second entry point, `acp-trust-helper`. Install that entry
point and every interpreter/library it needs from a root-controlled OS package;
do not point it at a development virtual environment.

Linux packages should place the helper at
`/usr/local/libexec/acp-trust-helper` (or patch `DEFAULT_HELPER` to the distro's
libexec directory), owned by root and mode `0755`. Create
`/var/lib/agent-control-plane/trust` and its `bundles` and `retired`
subdirectories root-owned and mode `0755`. A dedicated trust UID may own the
tree instead; pass its numeric UID consistently and keep the candidate runner
under a different account. `/proc/self/fd` lets Linux execute the exact
descriptor ACP validated.

~~~bash
sudo install -d -o root -g root -m 0755 \
  /var/lib/agent-control-plane/trust/bundles \
  /var/lib/agent-control-plane/trust/retired
~~~

macOS packages should place the helper at
`/Library/PrivilegedHelperTools/acp-trust-helper` and pre-create
`/Library/Application Support/AgentControlPlane/trust/{bundles,retired}` as
root, mode `0755`; those are ACP's macOS defaults. Keep both outside
Homebrew/user-writable prefixes. Darwin does not execute Mach-O files through
`/dev/fd`, so the root/dedicated-UID-owned, non-writable directory chain is the
enforcement that prevents replacement between validation and launch. A package
using another location passes `--helper`/`--root` and records the same root in
`acp.toml`.

~~~bash
sudo install -d -o root -g wheel -m 0755 \
  "/Library/Application Support/AgentControlPlane/trust/bundles" \
  "/Library/Application Support/AgentControlPlane/trust/retired"
~~~

Stage and atomically activate a bundle:

~~~bash
acp trust install --source /secure/release/acp-tools-2026.08 \
  --version 2026.08 \
  --executable critic=bin/critic \
  --executable docker=bin/docker
~~~

`acp` validates the installed helper before invoking it directly or through
`sudo`; no shell or inherited secret environment is used. The helper rejects
absolute/traversing source names and symlinks, copies from no-follow open file
descriptors, detects in-place mutation, writes a canonical manifest, freezes
the version directory, and atomically replaces a regular `current` pointer.

Reference bundle members from `acp.toml` by logical name:

~~~toml
[trust]
root = "/var/lib/agent-control-plane/trust"
owner_uid = 0

[qc]
commands = ["python -m pytest -q"]
critic_command = "trusted:critic"

[[runtime.drivers]]
name = "compose"
kind = "docker_compose"
executable = "trusted:docker"
compose_file = "compose.yaml"
~~~

Every new claim snapshots the current bundle's manifest digest and each used
executable's device, inode, size, and SHA-256. Rotating by installing another
version affects only later claims. Live attempts and their QC keep the old pin;
if it disappears or changes, ACP quarantines the attempt and blocks its task
instead of switching to `current`.

`acp trust retire BUNDLE_ID` and `acp trust uninstall BUNDLE_ID` only create a
retirement marker. They never remove the version directory, so attempts and QC
records cannot lose referenced evidence. `acp trust list` shows health and
retirement state. Physical garbage collection is intentionally outside ACP;
packaging must first prove that no `attempts.trust_bundle_json` or
`qc_runs.trust_bundle_json` record references the bundle. `acp doctor` reports
every ownership, mode, manifest, inode, size, digest, missing-file, and symlink
failure it observes.

## Planning before launch

Deciding what to run in parallel is the operator's remaining manual step. ACP
answers it from state it already holds, without launching anything:

~~~bash
uv run --extra dev acp plan TASK_ID     # would this claim succeed, and if not, who is in the way?
uv run --extra dev acp queue            # ordered set of tasks that can run concurrently
uv run --extra dev acp merge-plan       # integration order for approved work
~~~

`plan` classifies every collision as <code>exact</code> (identical normalized
scopes) or <code>potential</code> (different scopes that can still match one
path) and names the owning task, attempt, and agent, so the fix — re-partition
or re-order — is obvious from the output.

`queue` reserves each admitted task's scopes as it goes. Its <code>ready</code>
list is a set of tasks that can run **at the same time**, not a list of tasks
that could each run alone.

Tasks can also declare logical artifacts instead of restating task ids:

~~~bash
uv run --extra dev acp task-add --title "Publish the API schema" \
  --accept "schema is generated" --resource "schema/**" --produces api-schema

uv run --extra dev acp task-add --title "Generate the client" \
  --accept "client compiles" --resource "client/**" --consumes api-schema
~~~

The consumer cannot be claimed until every producer of <code>api-schema</code>
is <code>done</code>. Cycles are reported as a <code>dependency_cycle</code>
blocker naming the cycle, not followed.

`merge-plan` orders approved submissions topologically by dependency, then
deterministically by priority, creation time, and id. Each entry reports the
paths it shares with earlier entries, and becomes <code>stale</code> with an
<code>upstream_commits</code> count when commits land on the base branch after
approval.

All four planning commands are read-only. Unlike <code>claim</code> and
<code>list</code>, they never reap: looking at the board does not orphan an
agent's attempt.

## Operator status

Running three to six agents turns attention itself into the bottleneck — which
session is stuck, which finished, which is quietly holding a resource.

~~~bash
uv run --extra dev acp status                      # canonical JSON
uv run --extra dev acp status --format text        # one screen
uv run --extra dev acp status --watch --interval 2 --format text
~~~

The attention queue is ranked, worst first: <code>human_required</code>,
<code>cleanup_failed</code>, <code>lease_risk</code>, <code>review</code>, then
<code>active</code>. Every task reports its phase, heartbeat age, checkpoint,
claimed paths, runtime allocations, worker liveness, latest QC verdict, and
blockers. Attempts whose lease has expired but which no reaper has visited yet
are reported as <code>awaiting_reap</code> rather than being reaped by the act
of looking at them.

JSON remains canonical; <code>--format text</code> renders that same snapshot.
Use <code>--limit</code> to bound large boards.

## Runtime isolation

Git worktrees do not isolate localhost ports, databases, browser profiles, or
service state. ACP can allocate unique local ports and run idempotent lifecycle
hooks for every attempt:

~~~toml
[runtime]
setup_commands = [
  "/absolute/trusted/path/agent-env-up",
]
teardown_commands = [
  "/absolute/trusted/path/agent-env-down",
]

[runtime.ports]
APP_PORT = [41000, 41999]
TEST_PORT = [42000, 42999]
~~~

Hooks and supervised workers receive <code>ACP_ATTEMPT_ID</code>,
<code>ACP_TASK_ID</code>, <code>ACP_WORKTREE</code>,
<code>ACP_REPO_ROOT</code>, <code>ACP_RUNTIME_DIR</code>, and every configured
port variable. <code>ACP_PHASE</code> identifies setup, worker, QC, critic,
integration, or teardown; <code>ACP_WORKTREE</code> always names that phase's
checkout. The same allocated environment is injected into deterministic QC and
integration commands.

Allocations are stored transactionally and follow the attempt through review
and integration. Teardown runs after a negative QC verdict, completed
integration, or lease expiry. ACP probes every assigned port before recycling
it; a port still in use is quarantined as <code>teardown_failed</code> instead
of being assigned to another agent.

Inspect or retry cleanup:

~~~bash
uv run --extra dev acp environment ATTEMPT_ID
uv run --extra dev acp runtime-down ATTEMPT_ID
uv run --extra dev acp runtime-restart ATTEMPT_ID --recover
~~~

Use <code>--force</code> only to recover a cleanup left in-progress by a crashed
ACP process. Setup and teardown commands must be idempotent. Prefer trusted
absolute wrappers outside the candidate worktree. Put local database schema
creation, Compose project setup, config copying, and removal in those hooks; do
not print secrets because hook output is written to ignored local logs.

For resources with stronger cleanup requirements, use phase-scoped drivers:

~~~toml
[[credentials]]
name = "postgres-main"
provider = "versioned_file"
current = "/etc/acp/credentials/postgres-main/current"

[[runtime.drivers]]
name = "database"
kind = "postgres_schema"
executable = "/usr/local/bin/psql"
credential = "postgres-main"
host = "database.internal"
port = "5432"
database = "app"
user = "acp"

[[runtime.drivers]]
name = "browser"
kind = "browser_profile"
profile_prefix = "acp"
~~~

External driver executables and their parent chain must be root-owned and not
group/world writable because candidate code runs as the ACP user. ACP opens and verifies the exact
executable identity immediately before invoking it without a shell, from the
runtime directory, with a fixed PATH and a scrubbed
environment. PostgreSQL drivers reject literal DSNs and environment-secret
references. Their named credential must point to an atomic <code>current</code>
symlink outside the repository; the symlink target is a private, immutable
<code>0600</code> libpq password file containing
<code>host:port:database:user:password</code>. ACP stores only an opaque version
handle and keyed target fingerprint. It materializes the exact version as a
sealed memory file on Linux, or an immediately unlinked private file elsewhere,
and gives psql only a <code>PGPASSFILE=/dev/fd/…</code> descriptor path. Psql runs
with <code>-X --no-password</code>, so user startup files cannot execute while
that descriptor is live and no interactive fallback can request another
credential. Public target fields accept only plain host/name/role values; URI
and conninfo smuggling is rejected. Plaintext
never becomes argv or an environment value, and literal output is redacted from
observations. Every
teardown is followed by an independent absence probe; an unproven cleanup is
quarantined rather than recycled. <code>runtime-resources</code> exposes the
proof but not its internal ownership capability or credential handle.

Before setup touches an external resource, ACP durably writes a
<code>setup_pending</code> record containing its exact internal cleanup handle
and ownership capability. A crash after creation but before evidence therefore
cannot make cleanup resolve a newly rotated credential. The fingerprint HMAC
key lives in a separate ignored <code>.acp/driver.key</code> file with
<code>0600</code> permissions—not in SQLite—so a database snapshot alone is not
an offline credential verifier.

Rotate by writing a new immutable version, setting it to <code>0600</code>, and
atomically replacing the <code>current</code> symlink. Retain every old version
while an ACP attempt may still reference it. Restart first tears down and probes
the old target through its stored handle; only after cleanup proof does setup
resolve the new version. A missing, modified, or provider-mismatched old version
quarantines the allocation instead of probing a different target.
Restart is single-owner and generation-fenced. A second call fails while one is
live; <code>--recover</code> works only after the prior restart lease is stale and
only after a kernel lifetime lock proves no old supervisor or inherited driver
executor remains alive.

## Independent critic contract

Deterministic QC commands are always authoritative: a failing command cannot be
overridden by a critic.

ACP init enables a separate built-in structural critic process and requires at
least one deterministic QC command, one integration command, and a critic.
Replace the baseline critic with a different model/provider wrapper for semantic
or high-assurance review:

~~~toml
[supervisor]
critic_identity = "independent-qc"
require_critic = true

[qc]
commands = [
  "uv run --extra dev ruff check .",
  "uv run --extra dev pytest -q",
]
critic_command = "/absolute/path/outside/the/repository/critic-wrapper"
~~~

ACP starts the critic itself in the detached candidate worktree. It provides:

- <code>ACP_REVIEW_PACKET</code>: task specification and Git-derived evidence;
- <code>ACP_REVIEW_RESULT</code>: destination for structured JSON.

The worker's conclusion is deliberately excluded. The critic must emit:

~~~json
{
  "verdict": "pass",
  "findings": []
}
~~~

Negative verdicts require findings with severity, requirement, finding,
evidence, and required fix. Use a different provider/model in the wrapper when
correlated model bias is unacceptable.

External critic configuration is deliberately strict: it must be a single
absolute executable path outside the repository with a root-owned,
non-group/world-writable parent chain. ACP invokes it directly, not
through the candidate's shell or import path. Put model/provider arguments and
credentials inside that trusted wrapper.

The built-in critic checks review scope, regression-test signals, sensitive
paths, conflict markers, and deterministic results. It is an independent
process, but it is rule-based—not a substitute for a separately credentialed AI
or human reviewer when semantic judgment matters.

## Reviewer provenance and calibration

Independent review reduces self-approval, but a critic can share the worker's
blind spots, prefer its own output, or drift when someone upgrades the model
behind it. ACP makes the reviewer itself auditable.

Declare who is reviewing, with what:

~~~toml
[reviewers."independent-qc"]
provider = "builtin"
model = "structural-v1"
prompt_policy = "policy-2026-08"
command = "builtin"

[reviewers."second-opinion"]
provider = "other-vendor"
model = "reviewer-9"
command = "/absolute/path/outside/the/repository/second-critic"

[policy]
high_risk_paths = ["src/auth/**", "migrations/**"]
high_risk_mode = "two_reviewer"   # off | two_reviewer | human
require_provider_diversity = true

[calibration]
golden_dir = "acp-golden"
~~~

Every QC record then carries signed provenance — identity, provider, model,
prompt policy, and the hash of the resolved command — plus a deterministic
reproduction bundle written to ignored <code>.acp/bundles/</code>:

~~~bash
uv run --extra dev acp reviewers          # who reviews, and is the policy ratified?
uv run --extra dev acp bundle QC_ID       # signed, replayable record of one verdict
~~~

**A reviewer upgrade cannot take effect silently.** The whole evaluation policy
is fingerprinted. Changing a model, a prompt policy, a command, a reviewer, or a
high-risk rule changes that fingerprint, and QC then refuses to run until a
human accepts the change:

~~~bash
uv run --extra dev acp ratify-reviewers --integrator release-integrator --credential-file ../release-integrator.credential
~~~

The first policy a repository sees is adopted automatically — there is nothing
to compare it against — and every later change is an authenticated,
event-logged ratification. Old-policy passes never count toward the new policy,
and integration refuses an approval whose policy is no longer current.

### High-risk paths

When a submission touches <code>high_risk_paths</code>, a single passing verdict
is not an approval. Under <code>two_reviewer</code> the submission parks in
<code>pending_second_review</code> until a *second, distinct* reviewer also
passes — and if <code>require_provider_diversity</code> is set, a reviewer from
a different provider. Under <code>human_required</code> mode it parks for a
person. The same reviewer running twice never satisfies the rule.

### Calibration

"The critic is fine" should be a number with an error bar. Golden cases are
repository-specific seeded defects:

~~~toml
# acp-golden/conflict-markers.toml
name = "conflict-markers"
expect = "reject"          # or "pass" for a known-clean case

[[mutations]]
path = "src/app.py"
content = "<<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> branch\n"
~~~

~~~bash
uv run --extra dev acp calibrate --reviewer independent-qc
~~~

Each case is materialised in a detached worktree, mutated, and handed to the
*real* configured critic through the same entry point QC uses. The report gives
false-pass and false-block rates separately — a critic that rejects everything
scores perfectly on one and uselessly on the other — each with a **Wilson 95%
confidence interval**, keyed by the policy fingerprint that produced it. Wilson
rather than the normal approximation because calibration sets are small and
often land on 0% or 100%, where the naive interval collapses to zero width and
reports false certainty.

## Recovery model

<code>acp reap</code> or any new claim discovers expired attempts. ACP:

1. records the old worktree's current committed SHA;
2. moves it to <code>terminating</code> and raises every resource/runtime lease
   to a cleanup fence that cannot expire;
3. signals the registered kernel process identity and waits for its pidfd;
4. acquires the operation and runtime lifetime locks, then tears down until the
   runtime has durable <code>released</code> proof;
5. only then marks it orphaned and releases the collision lease while preserving
   its branch and worktree; and
6. increments fencing for a replacement started from the last recorded commit.

Expired QC and integration reservations use the same two-phase path through
<code>cleanup_pending</code>. A lock-busy condition, failed signal, invalid trust
pin, quarantine, or teardown error keeps the fence held and appears in
<code>acp status</code>; it never makes the resource claimable.

An old process is either terminated before replacement admission or its cleanup
fence remains held. Its stale token cannot heartbeat, submit, pass QC, or
integrate.

## API and authority layer

The repository also retains the FastAPI authority prototype from v0.1: signed
mandates, delegation attenuation, policy checks, approvals, agent kill
switches, and coordination endpoints.

~~~bash
export ACP_ADMIN_KEY="replace-with-a-long-random-value"
export ACP_SIGNING_KEY="replace-with-an-independent-long-random-value"
export ACP_DATABASE_PATH="agent_control_plane.db"
uv run uvicorn agent_control_plane.app:create_app --factory
~~~

The Git supervisor is the primary v0.2 product path. The HTTP authority API is a
separate reference layer and does not create Git worktrees.

### Fenced external side effects

The authority API exposes a provider-neutral gate for mutations that worktrees
cannot isolate:

- `POST /v1/side-effects/{operation}` for ordinary HTTP callers; and
- `POST /v1/a2a/side-effects/{operation}` for durable MCP/A2A task and artifact
  identities.

Supported operations are `db.schema`, `db.migrate`, `deploy.publish`,
`deploy.delete`, `artifact.publish`, and `artifact.tag`. Database resources use
`db:DATABASE/SCHEMA`, deploy resources use `deploy:ENVIRONMENT/NAMESPACE`, and
artifact resources use `artifact:REPOSITORY/TAG`; individual components are URL
encoded so one external object has one unambiguous lease identity.

Callers present their mandate, task claim token, complete resource-token map,
target resource, idempotency key, and provider payload. Actor and role are
derived from the signed mandate and current agent registry, never accepted from
the body. The gate checks mandate scope, the live task owner, lease expiry,
claim and resource generations, the exact declared target, and provider-derived
resource identity before the provider is reachable. The MCP/A2A adapter maps
durable protocol identity into that same path; it is not a second enforcement
implementation.

Applications inject provider drivers into `create_app(side_effect_drivers=...)`.
Each driver receives a `ProviderCall` with the durable idempotency key, request
digest, task/actor/target identity, and both fencing generations. Drivers must
forward the idempotency key and resource token to a provider-native
transaction, compare-and-set, or equivalent boundary. ACP's SQLite transaction
serializes local retries and records one receipt, but provider-native
idempotency is what closes a service-crash window after the remote mutation and
before the receipt commits. Receipts bind request, actor, target, operation,
result, and fencing generations by identity or digest without storing payloads
or credentials. Administrators can read them at
`GET /v1/tasks/{task_id}/side-effect-receipts`.

## Honest boundaries

ACP v0.2 is a local-first alpha, not a complete sandbox or distributed lock
service.

- SQLite assumes one trusted host and filesystem.
- Agents should be launched through ACP or another gateway; direct writes to the
  base checkout happen outside ACP's enforcement boundary.
- Tests and critic commands execute candidate code. Linux uses a child subreaper
  to adopt and kill double-fork/`setsid` descendants on both success and timeout;
  Darwin denies process creation for these short commands and fails the gate if
  a command tries to fork. Repositories whose tests need subprocesses therefore
  need the Linux path or a configured container runtime.
- The lifecycle monitor prevents accidental daemon escape; it is not a hostile
  same-UID security boundary. A same-UID process can attack its supervisor or
  sibling processes directly. Run untrusted candidates under a separate OS
  identity and the namespace/systemd driver or another container/cgroup
  boundary.
- Runtime port pools coordinate ACP attempts on one host, but they are not
  kernel-level reservations. ACP checks OS availability at allocation and
  teardown; unrelated processes can still race between those checks.
- Lifecycle hooks are trusted operator configuration. They can create isolated
  database schemas or containers. The fenced gateway covers only calls routed
  through configured provider drivers; ACP cannot infer or fence side effects
  performed directly or by hooks that do not declare them.
- Runner credentials are local bearer secrets hashed in SQLite, not SSO,
  hardware identity, or remote attestation. Protect the host and credential
  sinks; a process that steals a live bearer secret can act as that role.
- Descriptor delivery prevents accidental argv, environment, log, and state
  exposure; it is not cross-UID isolation by itself. In production run ACP and
  candidate code in separate OS/container identities so the candidate cannot
  inspect ACP memory, its retained credential store, or another same-UID
  process's descriptors.
- Scheduling previews are advisory and point-in-time. `plan` and `queue` report
  the board as it was read; only `claim` is authoritative, and it re-checks
  under an immediate transaction. A preview that says "ready" can still lose a
  race to a concurrent claim.
- Conflict prediction is textual, not semantic. Shared changed paths and
  `git merge-tree` catch overlapping edits; two submissions that break each
  other without touching the same line merge cleanly and still fail
  integration, which is why integration reruns the configured commands.
- Reviewer identity is policy-enforced locally, not backed by SSO or hardware
  identity. Provenance signatures are a local HMAC whose key lives in ignored
  `.acp/`: tamper-evident on one trusted host, like the event chain, not
  external non-repudiation.
- Calibration measures the reviewer against the golden cases a repository
  actually wrote. It is a floor, not a guarantee: a defect class with no golden
  case is unmeasured, and the confidence interval reflects sample size only —
  not whether the sample resembles real submissions.
- The hash chain detects accidental or partial tampering; a database
  administrator can rewrite the database and recompute it.
- ACP coordinates configured local runtime resources and validates submitted
  Git changes. Its gateway fences the supported database, deployment, and
  artifact operations only when providers honor the passed idempotency and
  fencing context; arbitrary direct network side effects remain outside ACP.

Distributed leases, asymmetric/remote runner identity, container isolation,
merge-queue adapters, production provider drivers, a TUI over the status JSON,
and externally anchored audit receipts are logical next layers. The core model
is intentionally provider-neutral.

## Development

~~~bash
uv sync --extra dev
uv run --extra dev ruff format --check src tests
uv run --extra dev ruff check src tests
uv run --extra dev pytest
uv build
~~~

The test suite uses real temporary Git repositories, branches, worktrees,
commits, processes, port allocations, runtime hooks, QC commands, and merges.

- [Architecture](docs/ARCHITECTURE.md)
- [Research](docs/RESEARCH.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)
- [License](LICENSE): Apache-2.0
