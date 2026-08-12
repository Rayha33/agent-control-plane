# Research: the missing safety layer for parallel coding agents

Research date: 2026-08-12.

## Verdict

The market does not need another broad agent orchestrator first. Claude Code,
Codex, Cursor, Conductor, Augment Intent, and open-source orchestrators already
provide some combination of spawning, parallel sessions, worktrees, sandboxes,
specification, dashboards, and merge workflows.

The stronger open-source wedge is the layer those systems can call:

> Provider-neutral concurrency control and CI for AI coding agents.

The unmet job is to make overlapping ownership, stale writers, recovery, and
independent acceptance mechanically enforceable across vendors.

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

The product response is not to special-case those tools. It is to make the
candidate commit, ownership token, checkout, and review evidence explicit and
verifiable.

## Competitive boundary

| Category | Strong at | Gap ACP targets |
|---|---|---|
| Vendor agent teams | Delegation, context sharing, native UX | Cross-vendor ownership and fencing |
| Worktree managers | Filesystem isolation and parallel sessions | Overlap arbitration and stale-writer rejection |
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
5. **Independent QC in a fresh checkout.** Run deterministic gates and a
   separately configured critic against one immutable commit.
6. **Integration against current base.** Re-merge and rerun gates before marking
   done; do not update the base branch directly.
7. **Honest boundaries.** Local worktree safety is not a code sandbox,
   distributed lock, or deployment gateway.

## Why the design is future-proof

The durable concepts are protocol-level, not model-specific:

- task specification and acceptance criteria;
- attempt identity and checkpoints;
- resource ownership and fencing;
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
