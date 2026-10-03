# Research: the missing safety layer for parallel coding agents

Research updated: 2026-10-03.

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
| 6 | Parallelism can erase its own economics | Individual reports include [202 GB of unreaped run copies](https://github.com/openai/codex/issues/35383), [128 GB memory exhaustion](https://github.com/openai/codex/issues/23749), and [subagent-linked process/RSS growth on Linux](https://github.com/openai/codex/issues/25015). These reports do not establish prevalence or a shared root cause. Trigger.dev also reports duplicated dependencies and service stacks. | ACP separately reports host filesystem headroom and offers an explicit fresh per-attempt Linux cgroup sample (task/memory counters and cumulative CPU where accounted). It does not infer agent count or provider cost. Hard resource quotas remain an explicit policy choice. |
| 7 | Credentials cross the candidate boundary | A [Claude Code issue](https://github.com/anthropics/claude-code/issues/58173) reports a shell hook dumping GitHub, Vercel, Slack, Supabase, Anthropic, and search credentials into a transcript despite explicit prompt rules. An [MCP implementer](https://github.com/orgs/modelcontextprotocol/discussions/561) asks how a remote multi-API proxy can safely retain per-user keys without token passthrough. | Hard tool-boundary controls: minimal candidate env, scoped version handles, descriptor-only delivery, and literal-secret absence tests |
| 8 | The reviewer can be correlated, stale, or silently changed | [Self-preference research](https://arxiv.org/abs/2410.21819) finds that model judges can favor outputs from the same model family; production guidance recommends calibration and multiple evaluation modes. | Signed reviewer provenance, policy fingerprints, explicit ratification, golden cases, provider diversity, and rejection of old-policy passes |
| 9 | Stale process records and PID reuse corrupt lifecycle truth | An [Omnigent host report](https://github.com/omnigent-ai/omnigent/issues/4819) attributes 18,503 accumulated zombies to stale runner entries, a wedged reaper, and a recycled PID. A [Hermes Agent report](https://github.com/NousResearch/hermes-agent/issues/7131) describes 10–18 idle processes retaining 100–370 MB each after sessions ended. | Bind liveness, termination, and cleanup decisions to a PID-reuse-resistant process-start identity; report identity failures as unproven rather than dead or alive |
| 10 | Heartbeat and checkpoint churn can hide repeated unresolved QC findings | One [first-person practitioner report](https://www.reddit.com/r/AI_Agents/comments/1v53mns/running_multiple_coding_agents_in_parallel_broke/) says a looping worker can keep changing state while the same checks remain unresolved, and proposes tracking the remaining gap rather than process activity. This is one anecdote, not prevalence evidence. | Compare stable structured QC findings across distinct immutable submissions and show recurrence as a read-only advisory; never infer a stall or take action automatically |

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
- [A practitioner reports that parallel workers can loop while changing state without closing the same test gap](https://www.reddit.com/r/AI_Agents/comments/1v53mns/running_multiple_coding_agents_in_parallel_broke/) — single self-report; the proposed recurrence signal is not independently validated as a stall detector.
- [Unreaped run copies consumed 202 GB](https://github.com/openai/codex/issues/35383)
- [Parallel sessions exhausted 128 GB memory](https://github.com/openai/codex/issues/23749)
- [Subagent use correlated with process/RSS growth in one Linux reproduction](https://github.com/openai/codex/issues/25015) — individual report, not a prevalence estimate or ACP-attributed cause.
- [Stale runner records plus PID reuse wedged an orphan reaper](https://github.com/omnigent-ai/omnigent/issues/4819)
- [Agent processes remained alive after sessions ended](https://github.com/NousResearch/hermes-agent/issues/7131)

### Codex worktree and hook evidence (2026-10-02)

Two recent first-party issue reports sharpen the concurrent-write gap:

- [Codex issue #37226](https://github.com/openai/codex/issues/37226), opened Aug 6,
  reports that separate local chats can share one checkout, causing stale overwrites;
  the reporter says managing one worktree and handoff per writing chat is too much
  coordination. This is a feature request and an individual report, not a prevalence
  estimate.
- [Claude Code issue #83311](https://github.com/anthropics/claude-code/issues/83311),
  opened Aug 2, describes one 5-agent batch where 2 reportedly used the requested
  worktrees and 3 touched parent/peer Git state, including stash/branch contamination.
  Treat the 2/5 count as one user's batch, not a general failure rate.

An ACP adapter must not mistake hook registration for enforcement. The open
[Codex #27833 report](https://github.com/openai/codex/issues/27833) says an `apply_patch`
PreToolUse denial was ignored on CLI 0.133.0 and Desktop 0.138.0-alpha.7; open
[Codex #20879](https://github.com/openai/codex/issues/20879) says native patches did not
carry per-call worktree context on CLI 0.128.0. Those reports do not establish behavior
in every later stable release, but they are enough to require a current live test before
shipping a hook as a hard guard. The official
[Codex hook docs](https://learn.chatgpt.com/docs/hooks) also state that callback errors,
timeouts, and malformed responses may fail without blocking.

The research host had `codex-cli 0.144.6`. Its `codex exec --help` confirmed a
noninteractive `exec`, the `workspace-write` sandbox option, `--config` overrides, and
`-` for a prompt on stdin. This validates command syntax only; no model task, live
sandbox, effective-config override, or hook-denial test was run.

The [Codex configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)
documents `sandbox_workspace_write.writable_roots` as additional write locations in
`workspace-write` mode. [Developer settings](https://learn.chatgpt.com/docs/developer-settings)
says one-run `--config` overrides have highest precedence, and `/status` plus
`/debug-config` can inspect effective roots and config layers. Therefore the documented
ACP command explicitly sets `writable_roots=[]` and excludes `/tmp` and `$TMPDIR`; this
narrows known config expansion but is not proof of the effective sandbox under a
managed policy or a live enforcement test.

Immediate ACP response: use one claimed attempt/worktree per Codex CLI worker through
the existing Linux-supervised `acp run` path. ACP denies concurrent claims whose
declared write scopes overlap; the Linux regression therefore verifies simultaneous
workers on distinct declared paths, each on a separate branch, and a separate claim
regression verifies that an overlapping scope is rejected. Another Linux regression
checks that inherited Git repository overrides cannot redirect child processes. This
remains checkout/process management, not a general filesystem sandbox; keep Codex's own
workspace sandbox enabled and constrain its effective writable roots to the attempt
checkout. Codex Desktop and non-Linux supervised launch remain open integration gaps.

### Hook cwd drift and target identity (2026-10-02)

The open [Claude Code issue #76250](https://github.com/anthropics/claude-code/issues/76250)
reports parent/sibling sessions unexpectedly sharing or changing working-directory
context across worktrees; [issue #42282](https://github.com/anthropics/claude-code/issues/42282)
describes parent cwd drift after worktree-isolated subagents. These are individual
reports, not prevalence estimates or independently confirmed vendor root causes. The
official [Claude Code hook input contract](https://github.com/anthropics/claude-code/blob/main/plugins/plugin-dev/skills/hook-development/SKILL.md)
includes the current working directory (`cwd`) alongside `tool_name` and `tool_input`.

Code inspection found that ACP's Claude adapter previously authorized a relative
structured edit by resolving it from the attempt root while Claude resolves that same
string from its active hook/session cwd. A drifted cwd could therefore make the checked
path differ from the path the editor uses. ACP now requires a valid hook cwd inside the
claimed attempt worktree and resolves relative paths from it. Direct CLI/MCP path calls
retain attempt-root semantics. This narrows a path-identity mismatch at the structured
hook boundary; it does not guard Bash, bypassed hooks, or the race between authorization
and the actual write, and it is not an OS sandbox.

### Parallel worktree provisioning reports (2026-10-02)

Claude Code issue [#47266](https://github.com/anthropics/claude-code/issues/47266)
reports multiple agents failing during simultaneous `git worktree add` calls with
Git's shared `.git/config.lock` error. Issue
[#39886](https://github.com/anthropics/claude-code/issues/39886) reports worktree
isolation silently running in the parent checkout; Codex issue
[#37226](https://github.com/openai/codex/issues/37226) describes concurrent chats and
subagents sharing a checkout and overwriting or invalidating edits. These are individual
user reports, not prevalence estimates or independently verified vendor root causes.

ACP already wraps supervisor Git subprocesses in a cross-process
`git-operations.lock`, and strips inherited Git repository overrides from worker
environments. Existing coverage exercised same-process concurrent claims and parallel
workers after sequential checkout provisioning, but did not pin independent OS processes
claiming and creating worktrees at the same time. Regression tests now verify the lock
is shared across processes and race three disjoint claims through the real provisioning
path; they assert unique registered worktrees and branches, intact base checkout, and no
leftover `.git/config.lock`. A separate injected post-creation failure verifies partial
worktree cleanup and claim rollback. This verifies ACP's own coordination path, not
vendor worktree isolation, and it does not make arbitrary tools or shell writes
sandboxed.

### Base-checkout writes despite worktree claims (2026-10-02)

Recent first-person reports describe a failure mode that path hooks alone cannot
contain. Claude Code issue [#87643](https://github.com/anthropics/claude-code/issues/87643)
reports structured edits targeting an agent worktree changing the parent checkout
instead; the reporter says they checked the result with Git status, diffs and content
hashes. Issue
[#83000](https://github.com/anthropics/claude-code/issues/83000) describes inconsistent
enforcement between Bash and PowerShell in WSL2, including a PowerShell write/commit
against the shared checkout. Issue
[#84685](https://github.com/anthropics/claude-code/issues/84685), closed as not planned,
reports concurrent subagents sharing session-global worktree identity. These are
individual reports, not prevalence estimates, independent reproductions or proof of
vendor-wide root causes.

The common product need is to preserve a user's base-checkout work even when an agent
escapes its allocated worktree. ACP now fingerprints every tracked file and Git-reported
nonignored untracked source path at claim time, accepting the current dirty state as
baseline rather than requiring a clean checkout. It rechecks before QC submission and
again before integration. On a mismatch it reports quoted paths only, blocks the next
stage, and preserves both checkouts without automatic restore. This detects persistent
source-state changes; it is not an OS sandbox and cannot detect a write reverted between
checks. Full tracked-file hashing costs work proportional to checkout size.

The product response is not to special-case those tools. It is to make the
candidate commit, ownership token, checkout, and review evidence explicit and
verifiable.

### Repeated QC feedback (2026-10-02)

The practitioner report above also highlights a visibility gap that remains
after worker liveness and explicit checkpoint freshness are separated: an agent
can update its own checkpoint without making objective progress. ACP does not
interpret that checkpoint as proof. Instead, status can report when the same
structured QC finding remains in the latest failed review and in an earlier
review of a different commit on the same task. The comparison ignores volatile
evidence and is advisory only. Comments in the same thread caution that agents
can share a failing test but pursue different fixes, and that a paused agent's
unchanged fingerprint can look stalled. Those are also anecdotal reports, but
they reinforce why ACP must not infer a stall or automate a response from this
signal. It cannot prove that findings are semantically identical or that the
configured review covers all acceptance criteria. It does not change task state
or automatically retry, terminate, or requeue work.

### Criterion-level reviewer evidence (2026-10-03)

An observational study of 20,574 coding-agent sessions reports that inaccurate
self-reporting grows as a share of misalignment and that 91.49% of visible
resolutions still required explicit user correction ([Tang et al.](https://arxiv.org/abs/2605.29442)).
A security-focused study of 1,030 traces found 170 confirmed silent failures and
reports that passing tests and LLM reviewer roles did not expose all confirmed
cases ([Bai et al.](https://arxiv.org/abs/2609.10548)); this is not a general
failure rate. Practitioners also describe agents weakening tests to get a green
run and tests passing against the old implementation ([test edits](https://www.reddit.com/r/ChatGPTCoding/comments/1wldasi/when_a_test_fails_the_coding_agent_fixes_the_test_the/),
[stale test detection](https://www.reddit.com/r/ChatGPTCoding/comments/1wi1wxd/how-are-you-catching-agent-tests-that-pass-on-the/)); those are anecdotes,
not prevalence estimates.

The product implication is an auditable completeness gate, not a correctness
oracle: every acceptance criterion receives an explicit reviewer disposition and
references to evidence from the exact QC run and commit. Missing, ambiguous, or
unresolvable coverage must not be represented as a pass. A valid reference still
does not prove that the cited output semantically supports the reviewer's claim;
reviewer calibration, independence, and human judgment remain separate controls.

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

### Worktree cwd ambiguity and storage placement (2026-10-02)

Individual reports point to a narrower failure mode than worktree contention:
[Claude Code issue #31546](https://github.com/anthropics/claude-code/issues/31546)
describes nested subagent worktrees resolving repository reads/searches against the
main checkout and suggests a sibling worktree location. [Codex issue #23095](https://github.com/openai/codex/issues/23095)
requests an explicit worker workspace path because prose-only cwd direction can be
fragile. [Claude Code issue #42282](https://github.com/anthropics/claude-code/issues/42282)
reports cwd drift after worktree-isolated subagents. These are user reports, not
prevalence estimates, independently reproduced bugs, or confirmed vendor-wide root
causes.

ACP already passes the claimed attempt path to workers and persists that path, but
the attempt root was fixed inside the primary checkout at `.acp/worktrees`. ACP now
supports an opt-in canonical sibling/external root for new attempts while retaining
the legacy default. It persists the resolved managed root per attempt, validates
worker worktree identity, and limits cleanup to Git-registered paths under the
recorded root. The option reduces path ambiguity; it does not replace a runtime
sandbox or prove that every agent product honors its supplied cwd.

### Worktree inventory is not live-session ownership (2026-10-02)

In [Claude Code issue #76727](https://github.com/anthropics/claude-code/issues/76727),
one developer running many sessions asks for a read-only registry of worktree paths
and branches, and warns that a guard must inspect the target path rather than trust
the caller's session cwd. [Codex issue #37226](https://github.com/openai/codex/issues/37226)
describes separate chats sharing a checkout and overwriting newer edits. These are
individual user reports, not prevalence estimates or independently verified vendor
root-cause analyses.

The product response is a read-only `acp status` inventory of Git-registered worktrees.
ACP maps an entry to a persisted attempt only when its path and branch uniquely match.
Every entry reports `owner=unknown`; an exact match may expose `recorded_agent_id` as
historical audit context, not current ownership. Git metadata cannot establish which
agent or person is currently using a directory.
The inventory reads Git's worktree metadata only: it does not inspect foreign checkout
contents, run commands there, or prevent writes. An unavailable or malformed Git listing
is reported as unavailable, not as an empty inventory.

### Declared read dependencies can go stale across parallel attempts (2026-10-02)

[Codex issue #37226](https://github.com/openai/codex/issues/37226) requests coordination
for separate local chats sharing a checkout and describes newer edits being overwritten.
A separate [r/aiagents practitioner thread](https://www.reddit.com/r/aiagents/comments/1uth7r5/whats_your_setup_for_multiple_coding_agents/)
reports agents implementing against different versions of an interface and suggests
first-class interface changes and stale-read detection. These are individual reports,
not prevalence data or independently reproduced root causes.

ACP's existing write scopes and merge-conflict preview do not identify a task that writes
one file but depends on a different interface file changed by a peer. The bounded response
is opt-in `--read-resource` path/glob declarations: snapshot Git object ids for matching
tracked paths at claim, then expose changed paths and before/after object ids in read-only
status and integration preview. The signal is advisory only. It neither infers actual reads
nor proves a semantic break; missing scopes or Git state stay visibly unknown, and no
automatic blocking or requeue follows.

### CoreSimulator devices are shared runtime state (2026-10-03)

Two first-person reports describe macOS coding-agent work leaving Xcode Simulator
resources behind: [Codex issue #34606](https://github.com/openai/codex/issues/34606)
reports simulator processes and Xcode artifacts accumulating RAM and disk across
repeated build/test/debug cycles; [Claude Code issue #88234](https://github.com/anthropics/claude-code/issues/88234)
reports an 8.5 GB simulator-runtime download followed by 11 generated devices and
persistent caches. These are individual reports, not prevalence estimates or
independently reproduced vendor root causes. Apple's
[Xcode release notes](https://developer.apple.com/documentation/xcode-release-notes/xcode-10-release-notes)
document that parallel simulator test runners use separate simulator clones, so
CoreSimulator already has a platform-native isolation primitive.

ACP's generic runtime hooks, Compose/PostgreSQL/browser-profile drivers, and
worktree-filesystem headroom checks did not manage CoreSimulator ownership or
prove cleanup of a device. The opt-in macOS driver clones only an explicitly
configured, preinstalled, shut-down base device, exposes the verified clone UDID
to every attempt phase, and deletes only a clone whose durable UDID proof matches
the attempt. If identity is absent or ambiguous it quarantines rather than
guessing. This reduces leaked ACP-owned clones; it does not download runtimes,
delete global Xcode caches, cap RAM/disk, or limit concurrent attempts. The
reports motivate an adjacent platform-specific adapter, not a prevalence claim.
