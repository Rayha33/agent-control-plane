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
| Server-derived evidence | Commit, tree, binary patch hash, and changed paths come from Git |
| Write-set validation | Undeclared changed paths and escaping symlinks are rejected |
| Independent QC | A configured reviewer runs deterministic commands in a fresh detached worktree |
| Structured critic | An optional external critic returns evidence-based findings |
| Integration gate | ACP merges into a new integration branch and reruns configured commands |
| Audit | Git-supervisor mutations and hash-chained events share a transaction |

ACP never pushes or updates the base branch. A passing integration leaves a
named integration branch for a human or existing merge queue.

## Quick start

Requirements: Git, Python 3.11+, and
[uv](https://docs.astral.sh/uv/).

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

The claim response contains <code>worktree</code>, <code>claim_token</code>,
per-resource fencing tokens, and a <code>runtime</code> environment. Run your
agent in that worktree, or let ACP supervise it:

~~~bash
uv run --extra dev acp run ATTEMPT_ID --token CLAIM_TOKEN -- your-agent-command
~~~

The command must leave a clean, committed worktree. A successful supervised run
submits automatically. For a manually operated agent:

~~~bash
uv run --extra dev acp heartbeat ATTEMPT_ID --token CLAIM_TOKEN --checkpoint '{"phase":"tests"}'
uv run --extra dev acp submit ATTEMPT_ID --token CLAIM_TOKEN
uv run --extra dev acp qc SUBMISSION_ID
uv run --extra dev acp integrate TASK_ID
~~~

All commands emit JSON. Local runtime state and logs live under ignored
<code>.acp/</code>; configuration is tracked in <code>acp.toml</code>.

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
~~~

Use <code>--force</code> only to recover a cleanup left in-progress by a crashed
ACP process. Setup and teardown commands must be idempotent. Prefer trusted
absolute wrappers outside the candidate worktree. Put local database schema
creation, Compose project setup, config copying, and removal in those hooks; do
not print secrets because hook output is written to ignored local logs.

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
absolute executable path outside the repository. ACP invokes it directly, not
through the candidate's shell or import path. Put model/provider arguments and
credentials inside that trusted wrapper.

The built-in critic checks review scope, regression-test signals, sensitive
paths, conflict markers, and deterministic results. It is an independent
process, but it is rule-based—not a substitute for a separately credentialed AI
or human reviewer when semantic judgment matters.

## Recovery model

<code>acp reap</code> or any new claim discovers expired attempts. ACP:

1. records the old worktree's current committed SHA;
2. marks the attempt orphaned;
3. stops its registered supervised process group;
4. releases its lease but preserves its branch and worktree;
5. tears down and releases its configured runtime environment;
6. increments fencing for the replacement; and
7. starts the replacement from the last recorded commit.

An old process may continue modifying its isolated worktree, but its stale token
cannot heartbeat, submit, pass QC, or integrate.

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

## Honest boundaries

ACP v0.2 is a local-first alpha, not a complete sandbox or distributed lock
service.

- SQLite assumes one trusted host and filesystem.
- Agents should be launched through ACP or another gateway; direct writes to the
  base checkout happen outside ACP's enforcement boundary.
- Tests and critic commands execute candidate code. Use a container or sandbox
  for untrusted repositories.
- Process-group cleanup covers ordinary descendants, including detached children
  present at timeout. Adversarial processes can escape host-level process
  supervision; a container/cgroup boundary is required for guaranteed
  containment.
- Runtime port pools coordinate ACP attempts on one host, but they are not
  kernel-level reservations. ACP checks OS availability at allocation and
  teardown; unrelated processes can still race between those checks.
- Lifecycle hooks are trusted operator configuration. They can create isolated
  database schemas or containers, but ACP cannot infer or fence side effects
  the hooks do not declare.
- Reviewer identity is policy-enforced locally, not backed by SSO or hardware
  identity.
- The hash chain detects accidental or partial tampering; a database
  administrator can rewrite the database and recompute it.
- ACP coordinates configured local runtime resources and validates submitted
  Git changes. It does not automatically fence arbitrary network, database, or
  deployment side effects; put fencing checks at those gateways too.

Distributed leases, authenticated runners, container isolation, merge-queue
adapters, MCP/A2A adapters, and externally anchored audit receipts are logical
next layers. The core model is intentionally provider-neutral.

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
