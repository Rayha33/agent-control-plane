# Run budgets and usage provenance

**Status:** design contract plus local per-task and hierarchical descendant-
attempt enforcement slices for task #2998. Provider adapters, provider quota
handling, and budget-exhaustion checkpoint recovery are not implemented. This
document is not a provider billing cap or evidence that ACP meters model work.

## Problem

Multi-agent work can fan out or retry faster than an operator can observe it.
The relevant control must sit outside model instructions and must distinguish
what the control plane can actually stop from values that a provider merely
reports.

Current ACP controls cover only parts of that boundary:

- max_descendant_mandates bounds lifetime descendant mandates issued through
  ACP. It does not see provider-internal subagents or provider SDK retries.
- Fresh runtime-resource samples can report attempt-owned cgroup task count,
  memory, and sometimes cumulative CPU. They do not count agents or measure
  tokens, billing, or model work.
- Completion receipts and worker checkpoints provide provenance, but there is
  not yet a budget-exhaustion path that safely preserves partial output.
- The local Git supervisor can optionally cap durable attempts per task with
  `--max-attempts`. Its serialized claim transaction prevents oversubscription
  by concurrent claimers. This counts only ACP attempt records (including
  attempts whose provisioning later fails).
- The local Git supervisor can also attach a task to an explicit parent with
  `--parent-task-id` and set `--max-descendant-attempts`. Each capped ancestor
  bounds durable attempt rows across all descendants at every depth, independent
  of dependency edges. The ancestor's own attempts do not consume that cap.
  Claim checks run inside the serialized write transaction; failed provisioning
  and expired attempts still consume the slot. Plan/queue simulate slot use for
  their proposed concurrent-ready set, but do not persist reservations.
- The separate public Coordination `POST /v1/tasks` API does not implement the
  local supervisor's attempt counters. It rejects unknown request fields, so an
  unsupported attempt-cap field cannot be silently ignored there.
- The supervised OCI worker launch, independent cleanup verification, and
  sandbox-aware result import remain unproven end to end (#2370 and #2439).

Public reports provide concrete examples, not prevalence estimates: one
Codex report describes a worker tree exhausting a fresh weekly allowance in
about 44 minutes with a stale usage reading; a Claude Code report describes a
63-hour 429 retry loop; another reports parallel results lost after usage
exhaustion. A study of coding-agent token consumption reports high
run-to-run variability on its evaluated tasks. These reports motivate
controls; they do not establish rates or generalize provider pricing.

## Budget and usage contract

Every value has an explicit scope, unit, source, observation time, and status.
Do not collapse unlike units into a synthetic dollar or token total.

| Kind | Example | Permitted use |
| --- | --- | --- |
| Enforceable local limit | ACP-issued child launches; measured CPU seconds inside an owned cgroup | Hard admission or stop only at the exact ACP/OS boundary that enforces it |
| Provider-authoritative limit or measurement | Provider-defined quota window or usage response bound to the account/project and returned by an authenticated provider API | Hard enforcement only when all relevant requests cross a trusted gate that can deny them; otherwise report-only |
| Estimate | Predicted token or currency cost | Planning and display only; never hard-cap admission or a safety claim |
| Unknown or unsupported | Provider hides its internal fan-out, exposes no reliable counter, or ACP cannot stop the request | Fail closed when a policy requires this dimension; show the missing capability and scope |

Suggested evidence statuses are enforced, reported, estimated, stale,
unknown, unsupported, and exhausted. Reported is not enforced. A value without
a trustworthy source or current timestamp is not current evidence. Raw token
counts are not billable currency: model, cache, input/output mix, provider
pricing version, plan, and quota window may differ. Do not calculate dollars
without an authoritative rate card and its version.

A hard constraint is admissible only when a control point can observe and
prevent every operation that could consume that budget. If the operator asks
for a hard provider-spend ceiling but the configured adapter cannot enforce
one, refuse launch with a structured unsupported-capability reason. A prompt,
estimate, dashboard warning, or post-run receipt does not enforce a ceiling.

## Hierarchy and enforcement

Budgets inherit down the ACP-controlled task/attempt tree. Before a child
attempt, retry, or other controlled launch, reserve its applicable units for
every capped ancestor in one durable transaction. A concurrent reservation
must not overrun a shared cap. Bind each reservation to the current claim and
resource fencing tokens; a stale owner cannot spend, release, or refund it.
Commit measured use from trusted receipts. Release unused reservation only
after the operation's terminal state is independently established; ambiguous
cleanup keeps the reservation held or quarantined rather than making capacity
available twice.

The local supervisor now has two distinct attempt dimensions:

- `--max-attempts` limits attempts for the task itself.
- `--parent-task-id` creates an immutable parent link, separate from
  `--depends-on`; `--max-descendant-attempts` on a task limits durable attempts
  for its full descendant subtree. Every capped ancestor is checked, so a
  nested cap cannot expand an outer cap.

For each dimension, inserting the durable attempt row consumes one slot in the
same SQLite `BEGIN IMMEDIATE` transaction as the authoritative claim. There is
no separate reservation to release and no refund/reset path; a failed
provisioning attempt remains consumed. A first refusal writes one exhaustion
marker/event on the exhausted task or ancestor. Repeated refusals roll back and
do not grow the event log without bound. The `plan`/`queue` admission pass
accounts for slots it proposes to launch concurrently, but those are advisory
simulations, not durable reservations; the claim transaction remains the source
of truth. These controls do not implement provider usage or quota-exhaustion
recovery.

Task, plan, queue, and status views expose per-task evidence as `attempt_budget`
and subtree evidence as `descendant_attempt_budget`. Each names its unit, scope,
configured cap, consumed/remaining amounts, source, observation time/freshness,
and serialized claim enforcement point. Task details carry the current
observation time; plan, queue, and status entries refer to their parent
`generated_at`. An individual attempt receipt retains its per-task historical
`attempt_budget`; it is not a historical snapshot of every ancestor cap. Both
current dimensions report zero held reservations and zero releases because a
durable attempt row consumes the slot atomically. Provider usage remains
explicitly unsupported with unknown freshness: no authenticated provider meter
or request gate is wired to this supervisor. This is not a provider quota
snapshot and cannot satisfy a requested hard provider-spend limit. Legacy
top-level per-task counter fields remain for compatibility.

Status also reports `parent_task_id`, nearest-first `ancestor_attempt_budgets`,
and `ancestor_lineage_integrity`. A missing, blank (empty or whitespace-only),
non-text, or cyclic parent link marks
the lineage invalid, suppresses inherited budget rows, and marks the task's
descendant-budget evidence `invalid` with no remaining value. In that invalid
state, `consumed` is retained only as a raw diagnostic and may be inaccurate;
consumers must not use it as authoritative cap evidence. Status renders a
corrupt non-text parent ID as a type-only placeholder so the JSON view remains
serializable. Plan and claim validate the full ancestor chain before recording
any budget refusal; for a valid chain, the task-local cap keeps precedence over
ancestor caps.

In the operator attention queue, a claimable task (`open`, `orphaned`, or
`changes_requested`) whose task-local attempt budget is exhausted is ranked as
`human_required`, with the consumed/configured count and the fact that retry is
not claimable. Active attempts and completed tasks are not promoted by this
rule; their budget evidence remains visible without implying a failed task.

The CLI `task-add --provider-cost-limit-usd-micros` and public `POST /v1/tasks`
API accept an explicit `provider_cost_limit_usd_micros` request so unsupported
hard limits are not silently ignored. In this build every such request fails with
`budget_capability_unsupported` before resolving the task's base revision or
inserting a task/event: there is no authenticated provider meter or request
gate. No estimate, prompt instruction, stale quota snapshot, or provider-internal
usage claim is read or accepted as enforcement evidence. This is a fail-closed
request guard, not a functioning provider-spend cap.

The public Coordination `TaskCreate` request rejects unrecognized fields. It has
no durable attempt ledger or parent/child task hierarchy, so `max_attempts` and
`max_descendant_attempts` are rejected as extra fields there rather than being
accepted as local-supervisor guarantees.

The counter must match the operation:

- ACP can count mandate/attempt launches that pass through its own issuance
  boundary. It cannot claim this count includes provider-internal agents.
- Local CPU, memory, process, and elapsed-time limits require an owned runtime
  boundary and a live identity binding. A cgroup sample is useful evidence but
  does not by itself prove the worker is stopped or safe to signal.
- Provider tokens, quota units, and cost require an adapter or request broker
  with authenticated, account-scoped telemetry and a stop boundary covering
  the charged requests. A provider snapshot that is advisory, delayed, or
  scoped to a different account cannot authorize more work under a hard cap.

Keep these dimensions separate in configuration, API responses, audit events,
and operator views. Preserve the exact unit, source, scope, timestamp, age,
configured cap, consumed/reserved/released amount, enforcement point, and
reason for any unknown or refused decision. Never record credentials.

## Exhaustion and partial work

When an enforceable cap is reached, deny further controlled launches and
retries before they are dispatched. A provider 429 or Retry-After response
must consume a bounded retry allowance and cannot by itself create an
unlimited retry loop. Do not automatically restart or expand work when a
provider quota later resets.

Where a controlled graceful stop is supported, first persist bounded,
host-authored partial progress with its attempt, claim fence, exact tree/base,
usage receipt, and checkpoint digest. After a crash or forced termination,
retain only the last durable checkpoint and state plainly that newer output
may be missing; never synthesize a final result. Record the attempt as
interrupted or budget-exhausted, never successful. It must not be promoted,
integrated, or reported complete without the existing review and submission
gates. Request cancellation only when the exact process/sandbox identity is
independently verified. If identity or cleanup is ambiguous, stop granting new
authority and surface the state for recovery; do not signal a guessed PID or
recycle the runtime.

## Delivery gates

1. Local per-task and descendant-attempt caps are implemented separately from
   provider meters, retry/quota lifecycle, and partial-result recovery; these
   slices and this document do not complete #2998.
2. Local launch/resource-budget enforcement must use existing ACP fencing and
   durable state, and must not duplicate or weaken #2316's descendant cap or
   #2366's truthful runtime-resource reporting.
3. Real worker cancellation and safe partial-result import remain gated by the
   accepted evidence for #2370 and #2439. Until then, do not wire OCI worker
   execution, elevate cleanup_reported, or claim an integrated cancellation
   path.
4. Provider-specific hard spend control is a separate adapter capability. If
   no trustworthy adapter/gate exists, keep that budget dimension
   unsupported instead of implying generic protection.
5. Acceptance requires deterministic offline tests for concurrent reservations,
   stale fences/telemetry, quota exhaustion, bounded retries, crash recovery,
   partial-result non-promotion, and cancellation/cleanup ambiguity, followed
   by independent exact-hash QC and exact-head hosted CI.

## Research references

- [OpenAI Codex issue #46819](https://github.com/openai/codex/issues/46819):
  reported worker fan-out, stale quota reporting, and continued launches near
  exhaustion; one report, not a prevalence estimate.
- [Claude Code issue #85422](https://github.com/anthropics/claude-code/issues/85422):
  user reports of a long 429 loop and runaway retry consumption; provider
  internals are not generalized here.
- [Claude Code issue #78231](https://github.com/anthropics/claude-code/issues/78231):
  reported parallel work discarded at spend exhaustion with a request for
  budget preflight and partial-result recovery.
- [How Do AI Agents Spend Your Money?](https://arxiv.org/abs/2604.22750):
  research on token use in evaluated coding-agent tasks; results are specific
  to its dataset and setup.
- Existing ACP references: README runtime-resource and mandate-limit sections;
  tasks #2316, #2362, #2366, #2370, and #2439.
