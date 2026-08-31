# Research: the missing safety layer for parallel coding agents

Research updated: 2026-08-31.

## Verdict

The market does not need another broad agent orchestrator first. Claude Code,
Codex, Cursor, Conductor, Augment Intent, and open-source orchestrators already
provide some combination of spawning, parallel sessions, worktrees, sandboxes,
specification, dashboards, and merge workflows.

The stronger open-source wedge is the layer those systems can call:

> Provider-neutral concurrency control and CI for AI coding agents.

The unmet job is to make overlapping ownership, stale writers, recovery, and
independent acceptance mechanically enforceable across vendors.

## What practitioners are talking about

A second research pass focused on first-hand issue reports and practitioner
threads rather than product positioning. Nine themes recur:

| Rank | Repeated challenge | Evidence | Product response |
|---|---|---|---|
| 1 | Runtime and test-data collisions | In the [Parallel agents in Zed discussion](https://news.ycombinator.com/item?id=47866750), users describe port conflicts, copied secrets, separate services, shared migrations, and abandoning parallel agents because test-data isolation became too costly. [Trigger.dev's account](https://trigger.dev/blog/parallel-agents-gitbutler) reports the same PostgreSQL, Redis, ClickHouse, port, dependency, and disk duplication problems in a production monorepo. | Allocate per-attempt runtime resources and carry them through verification |
| 2 | Missing setup and teardown lifecycle | The same Zed thread asks for VM-like create/destroy hooks and automatic cleanup. [Claude Code issue #26725](https://github.com/anthropics/claude-code/issues/26725) reports stale worktrees after interrupted sessions. | Durable idempotent setup/teardown with reaper-triggered cleanup |
| 3 | Verification is still manual or correlated | A practitioner in the Zed thread says manual verification is the largest remaining burden and that agents can encode the bug into their own tests. [Anthropic's evaluation guidance](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents) recommends combining deterministic, rubric-based, and state-based evaluation. | Immutable evidence, deterministic gates, independent critic, no self-approval |
| 4 | Operator attention becomes the bottleneck | A [multi-agent terminal discussion](https://news.ycombinator.com/item?id=47268777) describes 3–6 agents spread across terminals and asks how overlapping changes, merge timing, accountability, and traceability should work. | One durable task/attempt state model and machine-readable status |
| 5 | Cross-session coordination remains fragile | [Claude Code issue #24798](https://github.com/anthropics/claude-code/issues/24798) asks for inter-session coordination and describes readers seeing partial files after a writer crashes. [Codex issue #23515](https://github.com/openai/codex/issues/23515) reports one worktree session being interrupted by another. | Atomic write scopes, checkpoints, fencing, and one worktree per attempt |
| 6 | Parallelism can erase its own economics | User reports include [202 GB of unreaped run copies](https://github.com/openai/codex/issues/35383) and [128 GB memory exhaustion](https://github.com/openai/codex/issues/23749). Trigger.dev also reports duplicated dependencies and service stacks. | Bounded pools, explicit cleanup state, quotas and telemetry next |
| 7 | Credentials cross the candidate boundary | A [Claude Code issue](https://github.com/anthropics/claude-code/issues/58173) reports a shell hook dumping GitHub, Vercel, Slack, Supabase, Anthropic, and search credentials into a transcript despite explicit prompt rules. An [MCP implementer](https://github.com/orgs/modelcontextprotocol/discussions/561) asks how a remote multi-API proxy can safely retain per-user keys without token passthrough. | Hard tool-boundary controls: minimal candidate env, scoped version handles, descriptor-only delivery, and literal-secret absence tests |
| 8 | The reviewer can be correlated, stale, or silently changed | [Self-preference research](https://arxiv.org/abs/2410.21819) finds that model judges can favor outputs from the same model family; production guidance recommends calibration and multiple evaluation modes. | Signed reviewer provenance, policy fingerprints, explicit ratification, golden cases, provider diversity, and rejection of old-policy passes |
| 9 | Stale process records and PID reuse corrupt lifecycle truth | An [Omnigent host report](https://github.com/omnigent-ai/omnigent/issues/4819) attributes 18,503 accumulated zombies to stale runner entries, a wedged reaper, and a recycled PID. A [Hermes Agent report](https://github.com/NousResearch/hermes-agent/issues/7131) describes 10–18 idle processes retaining 100–370 MB each after sessions ended. | Bind liveness, termination, and cleanup decisions to a PID-reuse-resistant process-start identity; report identity failures as unproven rather than dead or alive |

The most important new finding is that a worktree is only source isolation. A
credible safety kernel also needs a runtime lifecycle: unique ports and
namespaces, setup evidence, teardown evidence, and quarantine when cleanup
cannot prove that a resource is free.

## Evidence of the need

| Evidence | What the source says | Product implication |
|---|---|---|
| [Anthropic agent teams](https://code.claude.com/docs/en/agent-teams) | Same-file edits can overwrite; task status can lag; in-process teammates cannot resume; users should split work by file | Work partitioning needs enforceable ownership and durable attempts |
| [Anthropic multi-agent research](https://www.anthropic.com/engineering/multi-agent-research-system) | Vague tasks duplicate work; stateful errors compound; production needs checkpoints, retries, and tracing | Recovery and evidence must be first-class |
| [Anthropic C compiler project](https://www.anthropic.com/engineering/building-c-compiler) | The team used task locks; merge conflicts and duplicate implementations remained common; strong tests/verifiers were essential | Locks, Git isolation, and verification belong in one gate |
| [OpenAI Codex worktrees](https://developers.openai.com/codex/environments/git-worktrees) | Worktrees provide separate repository checkouts | Checkout isolation is useful but does not itself arbitrate overlapping assignments |
| [OpenAI Codex subagents](https://developers.openai.com/codex/subagents) | Parallel agents are useful for focused roles; write-heavy parallelism can cause conflicts and coordination overhead | Parallel writes need a narrower safety contract |
| [GitHub Agent HQ mission control](https://github.blog/ai-and-ml/github-copilot/how-to-orchestrate-agents-using-mission-control/) | Operators are told to partition overlapping work and inspect sessions, files, and checks | Human partitioning is still carrying correctness |
| [Conductor parallel agents](https://www.conductor.build/docs/concepts/parallel-agents) | Workspaces use worktrees, while agents in one workspace can edit the same files | A pre-write overlap gate remains valuable |
| [Augment Intent](https://www.augmentcode.com/blog/intent-a-workspace-for-agent-orchestration) | Coordinator, implementors, verifier, worktrees, living specification, and bring-your-own-agent | This validates demand; ACP should interoperate rather than duplicate the workspace |
| [Neon worktree/database branching guide](https://neon.com/guides/git-worktrees-neon-branching) | Parallel tests and migrations collide when worktrees share one database | Runtime and data isolation must accompany source isolation |
| [Ecluse](https://github.com/hefgi/ecluse) | Gives each worktree isolated ports, services, data, and teardown across Docker/host stacks | Environment lifecycle is a validated adjacent category; ACP should provide a small policy kernel and hooks rather than own every stack |

The pattern is consistent: products are improving how agents are launched and
observed. The weakest common layer is the correctness protocol between task
assignment and merge.

## User reports that sharpened the threat model

These issue reports are evidence of user experience, not independently verified
vendor root-cause analyses:

- [Delayed process overwrote newer work](https://github.com/anthropics/claude-code/issues/79354)
- [One session deleted another session's active worktree](https://github.com/anthropics/claude-code/issues/40850)
- [Reviewer inspected the wrong worktree or diff](https://github.com/openai/codex/issues/33144)
- [Continued session wrote to the original checkout](https://github.com/openai/codex/issues/34352)
- [Unreaped run copies consumed 202 GB](https://github.com/openai/codex/issues/35383)
- [Parallel sessions exhausted 128 GB memory](https://github.com/openai/codex/issues/23749)
- [Stale runner records plus PID reuse wedged an orphan reaper](https://github.com/omnigent-ai/omnigent/issues/4819)
- [Agent processes remained alive after sessions ended](https://github.com/NousResearch/hermes-agent/issues/7131)

The product response is not to special-case those tools. It is to make the
candidate commit, ownership token, checkout, and review evidence explicit and
verifiable.

## Credential delivery findings

Prompt instructions and redaction after the fact are insufficient controls for
agent credentials. The practitioner issue above asks for hard tool-call
blocking because a memory rule was repeatedly ignored, and the MCP discussion
shows that environment variables remain the default precisely because a
portable scoped alternative is unclear.

The platform primitives support a narrow provider-neutral contract:

- Linux [<code>memfd_create</code>](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
  creates an anonymous descriptor that can be inherited across exec and sealed
  against writes.
- Python [<code>subprocess pass_fds</code>](https://docs.python.org/3/library/subprocess.html#subprocess.Popen)
  keeps only explicitly named descriptors open in a POSIX child.
- PostgreSQL [password files](https://www.postgresql.org/docs/current/libpq-pgpass.html)
  require private permissions and can be selected with <code>PGPASSFILE</code>
  or the <code>passfile</code> connection option.
- systemd's [credential model](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Credentials)
  similarly presents service secrets as files in a private credential
  directory instead of ordinary environment values.

ACP therefore treats the provider output as an opaque version handle, not a
string. Plaintext exists only while materializing a short-lived private
descriptor for a trusted driver. The exact handle remains attached to the
attempt until teardown is proved, which turns secret rotation from a global
environment mutation into an ordered old-target-cleanup/new-target-setup
transition.

## Competitive boundary

| Category | Strong at | Gap ACP targets |
|---|---|---|
| Vendor agent teams | Delegation, context sharing, native UX | Cross-vendor ownership and fencing |
| Worktree managers | Filesystem isolation and parallel sessions | Overlap arbitration and stale-writer rejection |
| Environment managers | Per-worktree ports, services, data and teardown | Durable ownership, fencing, evidence and QC integration |
| Orchestrators | Planning, spawning, dashboards, queues | Small embeddable safety kernel |
| CI systems | Deterministic tests after push | Pre-integration task ownership and recovery |
| Code review agents | Semantic critique | Immutable candidate selection and no-self-approval policy |

ACP should not compete on chat UI, planning intelligence, model routing, IDE
experience, or cloud build infrastructure. It should be callable from all of
them.

## Product requirements derived from research

1. **Atomic normalized resource claims.** Exact-string locks are insufficient;
   directory, glob, alias, and internal-path behavior must be defined.
2. **Monotonic fencing.** Expiry alone cannot stop a delayed process. Every
   acceptance boundary must reject old attempt and resource tokens.
3. **Durable attempt recovery.** Preserve branch, worktree, latest commit, logs,
   checkpoint, and process identity.
4. **Server-derived Git evidence.** Never trust a worker to report its own
   changed files, patch hash, or candidate revision.
5. **Per-attempt runtime lifecycle.** Allocate collision-free local resources,
   inject one environment from worker through integration, and fail closed when
   teardown leaves a resource occupied.
6. **Independent QC in a fresh checkout.** Run deterministic gates and a
   separately configured critic against one immutable commit.
7. **Integration against current base.** Re-merge and rerun gates before marking
   done; do not update the base branch directly.
8. **Honest boundaries.** Local worktree safety is not a code sandbox,
   distributed lock, or deployment gateway.
9. **Role-bound authority and secret isolation.** Worker, critic, and integrator
   transitions need distinct credentials; candidate-facing processes receive a
   minimal public environment, never the supervisor's ambient secrets.
10. **Versioned assurance policy.** Reviewer identity, provider, model, prompt
    policy, and command are one ratified fingerprint. A pass is valid only for
    its exact commit and current policy, including at integration time.
11. **Versioned, scoped credential material.** Persist opaque provider handles
    and keyed target fingerprints; deliver plaintext only over protected
    descriptors; retain old versions until cleanup is proved.

## Why the design is future-proof

The durable concepts are protocol-level, not model-specific:

- task specification and acceptance criteria;
- attempt identity and checkpoints;
- resource ownership and fencing;
- runtime allocation and lifecycle evidence;
- immutable artifacts and provenance;
- independent verification; and
- integration outcome.

Emerging standards complement this:

- [MCP Tasks](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/tasks)
  standardizes durable, pollable task state but does not define resource
  ownership, Git evidence, or QC policy.
- [A2A](https://a2a-protocol.org/latest/specification/) standardizes agent task
  and artifact exchange; ACP can act as a safety-aware task backend.
- [OpenTelemetry GenAI agent spans](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/)
  provide a natural export format for attempt/QC/integration telemetry.

ACP can add adapters for those transports without changing its core invariants.

## QC design basis

[Anthropic's agent-evaluation guidance](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents)
supports combining deterministic tests and static analysis with rubric-based
and state-based evaluation. ACP therefore makes deterministic commands
authoritative and treats model critique as an additional structured gate.

Research on
[self-preference bias in LLM evaluators](https://arxiv.org/abs/2410.21819)
also supports configuring a different model or provider for high-assurance
review. ACP keeps the critic external so users can choose that independence
level.

## Initial user

The first credible user is a developer or small engineering team running roughly
3–20 concurrent coding-agent sessions against one repository. They already feel
the pain of manually assigning directories, checking which worktree contains
the real patch, recovering crashed sessions, and repeating review after merges.

The adoption path should stay local and incremental:

1. initialize ACP in an existing Git repository;
2. wrap current agents with task-add, claim, heartbeat, and submit;
3. reuse existing test commands;
4. add an external critic when required; and
5. hand the passing integration branch to the existing pull-request workflow.

No vendor migration is required.
