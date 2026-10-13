# Run budgets and usage provenance

**Status:** design contract plus local supervisor attempt caps and public
Coordination claim- and dispatch-attempt-reservation caps for task #2998.
Provider adapters, provider quota handling, and budget-exhaustion checkpoint
recovery are not implemented. This document is not a provider billing cap or
evidence that ACP meters model work.

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
- The public Coordination API has its own durable claim and cooperative
  dispatch-attempt reservations. These are separate from the local supervisor's
  `--max-attempts` counters and do not meter provider requests, SDK retries,
  provider-internal fan-out, tokens, or spend.
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

## Provider capability examples

Provider controls are not interchangeable. This snapshot was checked against
official documentation on 2026-10-13; it is an adapter-design input, not a
guarantee that any particular account has the feature enabled.

| Provider | Documented control | Boundary that ACP must preserve |
| --- | --- | --- |
| OpenAI API | Monthly organization/project spend limits can be set as alerts or explicitly configured with “Enforce a hard limit”; hard-limit requests return `429` after tracked spend reaches the limit. | Enforcement is not instantaneous and recorded spend can slightly exceed the configured limit. Provider usage/cost reporting does not establish that every request for one ACP task is isolated or stopped. [Spend limits](https://developers.openai.com/api/docs/guides/spend-limits) · [Usage API](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/usage) |
| Anthropic Claude API | Usage reports can be filtered by workspace, model, and API key; cost reports can be filtered by workspace, model, and month. Prepaid organizations stop accepting new API calls after credits are depleted. | The documented cost report does not provide per-user attribution. A timed-out/disconnected request that was on track to succeed can still be charged. Invoiced accounts are billed monthly rather than stopped by a prepaid-credit balance. [Usage and cost reports](https://support.claude.com/en/articles/9534590-cost-and-usage-reporting-in-the-claude-console) · [API billing and credits](https://support.claude.com/en/articles/8977456-how-do-i-pay-for-my-claude-api-usage) |
| Google Gemini API | AI Studio offers monthly project spend caps, but not for Invoiced/Offline accounts. Cloud Billing spend caps are monthly and scoped to one project plus one eligible service for first-party billing accounts. | AI Studio project caps are experimental and may lag by about ten minutes; long-running agent sessions may exceed them. Cloud spend caps use estimated gross costs, block new usage only after enforcement, and allow in-flight requests to finish; overage remains possible. [Gemini API billing](https://ai.google.dev/gemini-api/docs/billing) · [Cloud Billing spend caps](https://docs.cloud.google.com/billing/docs/how-to/budgets-spend-caps) |

### Per-request token controls

Token APIs make useful preflight and reconciliation evidence available, but they
do not create a portable task-level spend cap:

| Provider | Preflight and request controls | Limit that matters for ACP |
| --- | --- | --- |
| OpenAI Responses API | `POST /v1/responses/input_tokens` counts the submitted input for a selected model; `max_output_tokens` bounds generated tokens for one response, including non-visible tokens. A completed response returns usage. | Input counting does not reserve output or tool-loop usage. The output bound is per response, not across an agent turn, retries, or descendants. [Token counting](https://developers.openai.com/api/docs/guides/token-counting) · [Responses API](https://developers.openai.com/api/reference/resources/responses/methods/create) |
| Anthropic Messages API | `messages.count_tokens` estimates model-specific input; `max_tokens` bounds generated tokens for one request. The beta `task_budget` gives Claude an advisory token countdown across an agentic turn. | Counts can differ from actual usage, and token counting does not support some valid inputs, including server tools/MCP connectors and some URL/file sources. If required preflight is unsupported, block dispatch for a strict budget; only reporting-only budgets may proceed with usage marked unknown. Task budgets are not enforced, may be exceeded mid-action, have no remaining-budget field in response usage, and are not supported in Claude Code or Cowork; treat them as a pacing hint, not an ACP admission gate. [Token counting](https://platform.claude.com/docs/en/build-with-claude/token-counting) · [Task budgets](https://platform.claude.com/docs/en/build-with-claude/task-budgets) |
| Gemini API | `countTokens` provides a preflight count; `maxOutputTokens` bounds each response candidate; `usageMetadata` reports usage after generation, including thinking-token fields where applicable. | With multiple candidates, aggregate response usage can exceed the per-candidate limit. These request-scoped controls do not reserve or cap usage across ACP retries, tools, or parallel descendants. [Count tokens](https://ai.google.dev/gemini-api/docs/tokens) · [Generate content](https://ai.google.dev/api/generate-content) |

These controls support a provider adapter's estimate → dispatch → receipt loop.
The adapter must preserve model, request/task scope, unit, provider, and
observation time; count preflight values as estimates where the provider says
they are estimates; and record post-call usage as reported evidence. A trusted
ACP broker still has to reserve shared task capacity before every billable
dispatch and reconcile all returned receipts. Token budgets and per-request
output limits are not dollar limits, and raw token totals must not be converted
to currency without the applicable versioned rate card.

The cross-provider design implication is that native spend controls are useful
account/project backstops, but they are not a portable per-task reservation
protocol. An isolated provider scope can reduce cross-run interference only
when its vendor-specific lag, in-flight behavior, reset, and overage semantics
are explicitly accepted and surfaced; it must not be presented as an exact
spend ceiling. An ACP-enforced per-task dispatch limit additionally requires a
trusted request gate through which every billable call must pass. The gate must
reserve before dispatch and fail closed when usage, scope, or freshness is
unsupported. Provider dashboards and delayed usage reports remain `reported`
evidence, not per-task enforcement. ACP must not enable, change, or lift account
spend controls implicitly.

### CLI routing as a broker seam

Official CLI configuration shows a practical integration seam for a future
ACP-owned provider broker: launch the CLI against a configured gateway endpoint
and make that gateway the only route to the provider. The endpoint setting by
itself is not proof that all inference, retries, or internal fan-out crossed the
broker. This is feasibility evidence only; the current ACP worker has no
integrated provider broker or provider-route egress proof.

| CLI surface | Documented route | Scope and limitation |
| --- | --- | --- |
| Codex CLI | A custom `model_providers.<id>.base_url` can select a gateway, with a provider key supplied via `env_key` or command-backed auth. | Custom providers use the Responses wire API. Request retries default to 4 and stream retries to 5, so a broker design must account for these retry paths; a configured base URL alone does not prove there is no direct fallback or other billable path. Do not confuse Codex CLI's provider URL with the separate OpenAI API CLI's `OPENAI_BASE_URL`. [Configuration](https://developers.openai.com/codex/config-advanced) · [Reference](https://developers.openai.com/codex/config-reference) · [OpenAI API CLI](https://developers.openai.com/api/reference/cli) |
| Claude Code | Current docs support `ANTHROPIC_BASE_URL` plus an explicit gateway credential (`ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_API_KEY`, or `apiKeyHelper`). | While a gateway credential is active, it replaces the saved subscription login; requests are billed per token to the account that owns the upstream provider credential the gateway forwards, and the subscription's usage limits do not apply. Managed `allowedProviders` settings can pin a custom endpoint and reject other Claude Code provider routes, but do not establish containment for the whole worker or other traffic. Anthropic does not endorse, maintain, or audit third-party gateway products. [Gateway overview](https://code.claude.com/docs/en/llm-gateway) · [Connect to a gateway](https://code.claude.com/docs/en/llm-gateway-connect) |
| Gemini CLI | `GOOGLE_GEMINI_BASE_URL` overrides the Gemini API endpoint when using `gemini-api-key` auth; `GOOGLE_VERTEX_BASE_URL` is the corresponding Vertex override. | The documented Gemini endpoint override is auth-mode-specific; it is not a universal interception setting for OAuth/consumer sign-in. Never piggyback a user's OAuth session through a third-party broker. [Configuration](https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md) · [Authentication FAQ](https://github.com/google-gemini/gemini-cli/blob/main/docs/resources/faq.md) |

For any provider hard cap, ACP would need to materialize a per-attempt
configuration and narrowly scoped gateway credential from trusted settings,
remove inherited provider credentials that could bypass the gateway, and
enforce network egress so the worker cannot connect directly to provider
endpoints. The gateway must reserve against the task-tree budget before each
upstream request, account for automatic retries and concurrent descendants,
and return attributable usage receipts. A hard dollar cap additionally needs
enforced per-request usage ceilings and a conservative maximum billable
reservation for every in-flight request and its retry path, covering every
billable feature with a versioned rate card. If any feature or usage bound is
unknown, refuse the dollar cap instead of promising an exact ceiling. Exercise
the actual CLI binary against an offline fake gateway, including retry and
streaming interruption cases, and prove direct egress is denied before
advertising the capability. If the worker cannot establish these conditions, a
configured endpoint is routing metadata only and provider usage remains
`unsupported` for hard-cap admission.

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

The separate public Coordination API now supports `max_claims` and
`max_descendant_claims`. These count successful claim reservations represented
by `tasks.claim_fencing_token`; they do not count worker starts, provider
requests, or provider-internal fan-out. `parent_task_id` is immutable and
separate from dependency edges. A task's `max_descendant_claims` covers all
descendants at every depth and excludes the task's own claims.

Each public API reservation increments the fencing token in the same
`BEGIN IMMEDIATE` transaction as the task status/owner, resource leases,
heartbeat, and `task.claimed` audit event. A database trigger repeats the local
and ancestor-cap checks, so an already-running service binary that only knows
the old claim update cannot bypass the cap. Failed claims consume no slot;
expired, reopened, or reworked tasks do not refund a successful reservation.
Budget configuration and parentage cannot be changed after task creation.

Coordination task views expose `claim_budget` and `descendant_claim_budget`
with unit `successful_claim_reservations`, current consumed/remaining values,
status, source, enforcement point, and observation time. The local supervisor's
`attempt_budget` evidence remains a different unit and enforcement boundary.
These Coordination counters are durable claim generations, not a worker
attempt ledger or proof that any worker actually started.

Coordination also accepts immutable `max_dispatch_attempts` and
`max_descendant_dispatch_attempts` caps on `POST /v1/tasks`. A worker with a
live task claim and current resource fences reserves a slot through
`POST /v1/tasks/{task_id}/dispatch-attempts` before a cooperative outbound
call. The reservation and local/ancestor cap checks run under `BEGIN IMMEDIATE`,
and the SQLite insert trigger rechecks live task/resource fences and cap limits.
Descendant caps include every descendant depth and exclude the capped task's
own reservations. A cap of zero denies all new reservations.

These are **dispatch-attempt reservation slots**, not proof that an HTTP request
was sent, reached a provider, or incurred cost. Each new idempotency key
permanently consumes a slot even if the process crashes before sending or the
outcome is ambiguous. While the original claim remains active, replaying the
same task/idempotency key returns the existing reservation with `created:
false`; clients must not send on that replay. A deliberate retry requires a
new key and another available slot. Slots are never released or refunded.
Reservations retain the task and resource fencing-token snapshot that was
checked at creation. Reservation and client-reported receipt rows survive a
service restart; task views recompute consumed slots from those persisted rows.

The optional receipt endpoint records one immutable response observation and
labels it `source: client_reported`. In particular, a client-reported 429 or
Retry-After is evidence only: it does not authorize, schedule, or perform a
retry, and it never restores a slot. ACP does not yet run a provider adapter,
observe whether the client actually sent a request, or control provider/CLI
internal retries and fan-out. A worker that calls a provider directly can
bypass these cooperative reservations. Therefore these counters are not a
provider request limit, egress gate, quota control, token budget, or spend cap.

Python clients may opt into `agent_control_plane.dispatch_client.dispatch_once`
with `CoordinationHttpDispatchLedger` to use the reference API directly:

~~~python
from agent_control_plane.dispatch_client import CoordinationHttpDispatchLedger

ledger = CoordinationHttpDispatchLedger(
    base_url="https://acp.example",
    bearer_token=coordination_mandate,
)
~~~

The adapter calls the published reservation/receipt routes, keeps the bearer
token in the Authorization header, URL-escapes path IDs, bounds JSON response
reads, refuses redirects, and does not retry. Keep the coordination base URL
under operator control and use HTTPS for remote services; the adapter rejects
plain HTTP except to loopback hosts. `dispatch_once`
refuses an idempotent reservation replay without calling `send_once`; a
reservation error also propagates before the callback. It accepts standard
`status_code`/`headers` responses and normalizes numeric or HTTP-date
`Retry-After` values for the client-reported receipt. Invalid or greater-than-
24-hour retry hints are represented as `null`; the valid HTTP status receipt is
still recorded. A 429 is never retried automatically. If sending or receipt
recording is ambiguous, the helper raises a sanitized error without resending;
the durable slot remains consumed. A deliberate retry must be a new call with
a fresh idempotency key and another reservation. The supplied provider
transport must itself disable retries and redirects: the helper invokes a
callback once but cannot inspect or control behavior inside that transport.
This is not a provider adapter, universal request gate, or protection against
direct calls or provider-internal fan-out.

Task views expose local and descendant dispatch-attempt budgets with unit
`dispatch_attempt_reservations`, consumed/remaining counts, status, source,
enforcement point, and observation time. `reserved` and `released` remain zero:
the slot is consumed atomically when its immutable reservation row is written.
Each budget and receipt also carries a typed `provider_usage` record with
`status: unsupported`, null unit/source/observation/enforcement point, and
`freshness: unknown`. This is distinct from the current local reservation
observation and any client-reported HTTP response, making clear that neither
local counters nor a reported 429 are provider usage. The receipt is separately
identified as `client_reported`, not provider-verified; recording it does not
change `provider_usage` or turn it into trusted provider telemetry.

The task, ancestor chain, descendants, dependencies, and latest submission/review
are read from one SQLite snapshot; `ancestor_lineage_integrity` is `invalid` if
an ancestor link, cap, or fencing counter is corrupt. Invalid lineage is never
evidence that inherited caps are available.

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
`changes_requested`) is ranked as `human_required` when its local cap is
exhausted/invalid, an ancestor cap is exhausted/invalid, or its lineage is
corrupt. Exhausted caps include the relevant consumed/configured count; invalid
lineage and cap evidence is never treated as authoritative usage. Active attempts
and completed tasks are not promoted by this rule; their budget evidence remains
visible without implying a failed task.

The CLI `task-add --provider-cost-limit-usd-micros` and public `POST /v1/tasks`
API accept an explicit `provider_cost_limit_usd_micros` request so unsupported
hard limits are not silently ignored. In this build every such request fails with
`budget_capability_unsupported` before resolving the task's base revision or
inserting a task/event: there is no authenticated provider meter or request
gate. No estimate, prompt instruction, stale quota snapshot, or provider-internal
usage claim is read or accepted as enforcement evidence. This is a fail-closed
request guard, not a functioning provider-spend cap.

The public Coordination `TaskCreate` request rejects unrecognized fields.
`max_attempts` and `max_descendant_attempts` remain rejected there: they are
local-supervisor controls, not aliases for the API's `max_claims` and
`max_descendant_claims`. The API's claim counters still do not cap worker starts
or any provider usage; no authenticated provider meter or request gate is wired
to the Coordination service.

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

1. Local per-task and descendant-attempt caps and cooperative public API
   reservation slots are implemented separately from provider meters,
   provider-enforced retries/quota lifecycle, and partial-result recovery;
   these slices and this document do not complete #2998.
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
