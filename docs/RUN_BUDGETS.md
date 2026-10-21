# Run budgets and usage provenance

**Status:** design contract plus local supervisor attempt caps and public
Coordination claim- and dispatch-attempt-reservation caps for task #2998.
Report-only response parsing and opt-in one-shot HTTP adapters cover OpenAI
Responses, Anthropic Messages, and Gemini Developer API GenerateContent.
Provider-side quota/spend enforcement and host-authored crash-durable recovery
from budget exhaustion are not implemented. The Coordination API can persist a
bounded client-reported interruption checkpoint, but it is not a crash-durable
partial-result recovery or import path. This document is not a provider billing
cap or evidence that ACP meters model work.

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
- Completion receipts and worker checkpoints provide provenance. A bounded
  client-reported interruption checkpoint can be recorded through Coordination,
  but it cannot recover host-authored partial output or authorize its promotion.
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

A recent Codex desktop report records 8.95 billion input-plus-output tokens
over a fixed 36-hour window, including compaction responses omitted from a
legacy counter. Its source-audited correction attributes 8,788,141,824 tokens
(98.197% of the total) to cached input. The report says the inspected large
goals had no configured token budget; for the inspected runtime, its
goal-budget metric also excluded cached input. These are distinct processed-
token and task-budget measurements, not an invoice. The author explicitly
does not establish billed cost, incorrect billing, a configured-budget
violation, or a concurrency-limit breach. The companion feature request
proposes one shared reserve-before-request budget for root and descendant
model calls, including compaction and retries, with honest units and
conservative handling of unresolved requests. This is a bounded practitioner
report plus a proposed safeguard, not prevalence or proof of the incident's
root cause.

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
official documentation on 2026-10-15 UTC; it is an adapter-design input, not a
guarantee that any particular account has the feature enabled.

| Provider | Documented control | Boundary that ACP must preserve |
| --- | --- | --- |
| OpenAI API | Monthly organization/project spend limits can be set as alerts or explicitly configured with “Enforce a hard limit”; hard-limit requests return `429` after tracked spend reaches the limit. | Enforcement is not instantaneous and recorded spend can slightly exceed the configured limit. Provider usage/cost reporting does not establish that every request for one ACP task is isolated or stopped. [Spend limits](https://developers.openai.com/api/docs/guides/spend-limits) · [Usage API](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/usage) |
| Anthropic Claude Platform and Enterprise | Claude Platform Usage reports can filter by workspace, model, month, and API key; Cost reports by workspace, model, and month. Non-default workspaces can have monthly spend caps; only the Claude Code workspace supports per-user monthly workspace limits. Separate Claude Enterprise Analytics provides per-user cost/usage on usage-based plans (seat-based plans report usage credits only), and the Enterprise Spend Limits API exposes effective monthly limits and period-to-date spend per member. | The Spend Limits API requires an Enterprise organization, usage credits, and a scoped Admin API key; its member-level controls are not a Claude Console/API per-task cap. `period_to_date_spend` may temporarily report `"0"` when unavailable, so it is informational rather than a trustworthy live stop signal. Analytics cost/usage data is typically available within four hours but can take 24 hours; an open-ended recent tail past `data_refreshed_at` is incomplete, and values may be revised until about seven days after month-end. These member/workspace/month controls do not isolate an ACP task or run. A timed-out/disconnected request that was on track to succeed can still be charged; invoiced API accounts are not stopped by prepaid-credit depletion. [Spend Limits API](https://platform.claude.com/docs/en/manage-claude/spend-limits-api) · [Analytics APIs](https://platform.claude.com/docs/en/manage-claude/analytics-api) · [Workspaces](https://platform.claude.com/docs/en/manage-claude/workspaces) · [Usage and cost reports](https://support.claude.com/en/articles/9534590-cost-and-usage-reporting-in-the-claude-console) · [API billing and credits](https://support.claude.com/en/articles/8977456-how-do-i-pay-for-my-claude-api-usage) |
| Google Gemini API | AI Studio offers monthly project spend caps, but not for Invoiced/Offline accounts. Cloud Billing spend caps are monthly and scoped to one project plus one eligible service for first-party billing accounts. | AI Studio project caps are experimental and may lag by about ten minutes; long-running agent sessions may exceed them. Cloud spend caps use estimated gross costs and enforce faster than billing reports, but enforcement is not instantaneous and overage remains possible. Actual Cloud Billing cost details are typically available within a day and can take more than 24 hours, so they are reconciliation evidence, not an in-flight gate. Gemini Prepay's monthly auto-charge limit caps automatic reloads only; manually initiated credit purchases do not count toward it. Since May 28, 2026, all new API keys created in Google AI Studio are automatically authorization keys; Google documents that requests authenticated by authorization keys are not recorded in Cloud service-account usage metrics, so ACP must not assume that metric provides per-agent request attribution. [Gemini API billing](https://ai.google.dev/gemini-api/docs/billing) · [Gemini API keys](https://ai.google.dev/gemini-api/docs/api-key) · [Cloud Billing spend caps](https://docs.cloud.google.com/billing/docs/how-to/budgets-spend-caps) |

### Provider error and retry semantics

Anthropic API spend-limit responses are not uniform: an organization tier spend
cap pauses API usage until the next monthly reset or a tier increase. On the
Messages API, its `429` has no `retry-after` and carries
`error.details.error_code: "enforced_spend_limit_reached"`; a user-set API spend
limit instead returns HTTP `400`. Claude Code workspace limits are separate and
can return `429` with `retry-after`, so inspect the response before treating an
Anthropic `429` as transient rate limiting. [Anthropic rate-limit and spend-limit behavior](https://platform.claude.com/docs/en/api/rate-limits)

OpenAI also uses HTTP `429` for both temporary request-rate errors and blocking
credit, spend, or usage-limit errors. Treat request-rate `429`s, including
`slow_down`, as pacing signals: reduce rate, honor `Retry-After` when present,
and bound retries. Inspect `error.code`: `credit_balance_exhausted`,
`organization_spend_limit_exceeded`, `project_spend_limit_exceeded`, and
`organization_usage_limit_exceeded` require a billing or limit action; retrying
quota or billing errors will not restore access. The broader `error.type` may
still be `insufficient_quota`. [API error codes](https://developers.openai.com/api/docs/guides/error-codes) · [Retry guidance](https://developers.openai.com/api/docs/guides/rate-limits)

Gemini GenerateContent uses `429 RESOURCE_EXHAUSTED` for several limits,
including per-minute request/token rates, per-day quotas, and rolling 10-minute
spend rates. Daily quotas reset at midnight Pacific, while spend-rate limits can
clear after a short wait, so the status alone does not identify recovery time;
check the project's model-specific limits and keep transient retries bounded.
Depleted Prepay credit returns `402 RESOURCE_EXHAUSTED` and will not recover
until credits are added. [GenerateContent API errors](https://ai.google.dev/gemini-api/docs/generate-content/api-errors) · [Rate limits](https://ai.google.dev/gemini-api/docs/rate-limits) · [Troubleshooting](https://ai.google.dev/gemini-api/docs/troubleshooting)

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

The optional response extractors now cover OpenAI Responses,
Anthropic Messages, and the Google AI Gemini Developer API `generateContent`
(not Vertex AI). Each normalizes one
non-streaming response into `input_tokens`, `output_tokens`, `total_tokens`,
and known token-detail fields with a provider response ID, model, and
client-observed time; provider-created time is retained when the provider
supplies it. Anthropic's documented total input is the sum of ordinary input,
cache-read, and cache-creation tokens; ACP retains the cache components as
details. OpenAI Responses exposes `cached_tokens` and `cache_write_tokens` as
input details and `reasoning_tokens` as an output detail; ACP retains and
parent-bounds them ([Responses API reference](https://developers.openai.com/api/reference/resources/responses/methods/create)).
Gemini thinking tokens are included in normalized output and retained as
details; `toolUsePromptTokenCount` is included in normalized input while
remaining available as a detail. Both Gemini Developer API GenerateContent and
Vertex AI document totals that include prompt, tool-use prompt, thoughts, and
response candidates. ACP currently implements only the Developer API response
adapter; matching token accounting does not imply Vertex adapter support. Each
report is `reported`, `missing`, or `invalid`; the API
also timestamps receipt ingestion.
These are client-reported observations: ACP does not authenticate response
bodies or infer billing. ACP can aggregate a bounded sample of these
client-reported receipts by task, but does not treat reports as fresh for
admission. `provider_usage` therefore remains `unsupported` for
hard-limit decisions even when a per-call `provider_usage_report` is present.
Missing and malformed fields produce bounded reason codes without storing raw
responses or credentials. Streaming, SDK retries, and provider-internal fan-out
remain outside these extractors. The opt-in `dispatch_*_once` HTTP adapters
reserve through the dispatch ledger, make one synchronous, non-streaming request
through the provider's standard-library HTTP transport, and attach parsed usage to
the receipt. They currently cover fixed OpenAI Responses and Anthropic Messages
endpoints plus the Google AI Gemini Developer API `generateContent` endpoint;
the Gemini adapter does not cover Vertex AI or the Gemini Interactions API.
The default transports refuse redirects and do not retry; 429 is recorded and
returned, never retried. They reject streaming (and OpenAI background mode),
bound decoded response bodies at 16 MiB, and never copy response bodies or API
keys into the receipt. Keys are sent only in provider-specific headers. A
caller-supplied opener is a transport seam and must preserve no-retry/no-redirect
behavior. The returned response marks its body `available`, `invalid_json`,
`too_large`, or `unavailable`; unavailable or invalid usage still leaves a
receipt when an HTTP status was observed.

These adapters do not authenticate response usage, calculate cost, gate every
provider call, control provider-internal fan-out, or enforce quota/spend.
Callers can bypass them, and an ambiguous network outcome consumes its ACP slot
without an automatic resend. Direct `dispatch_once` users may still pass the
matching parser as `usage_report_from_response` after decoding their own
response. These parsers accept decoded JSON mappings, not HTTP/SDK response
wrappers. See the provider references for [OpenAI Responses](https://developers.openai.com/api/reference/resources/responses/methods/create), [Anthropic Messages](https://platform.claude.com/docs/en/api/messages/create) and [rate-limit token accounting](https://platform.claude.com/docs/en/api/rate-limits), [Gemini Developer API GenerateContent](https://ai.google.dev/api/generate-content?hl=en) and [Gemini API authentication](https://ai.google.dev/api), and [Vertex AI GenerateContent usage](https://cloud.google.com/vertex-ai/generative-ai/docs/reference/rest/v1/GenerateContentResponse).

Task status includes a separate `reported_provider_usage` roll-up for the task
and its descendant tree. It groups observed token sums by provider, adapter,
and model, and reports counts for reported, missing, invalid, receipt-without-
report, and reservation-without-receipt cases. Each scope returns and aggregates
at most its latest 1,000 dispatch reservations; each provider/adapter/model group carries
the latest client-reported observation timestamp among its reported responses.
That timestamp is not provider-authenticated. `truncated` and
`sampled_reservation_count` make the sample limit explicit. This bounds sample
size and application-side aggregation work, not database work: the descendant
summary and exact reservation count may still scan or sort the full descendant
history, so read cost can grow with task-tree history.
The unpaginated `/v1/tasks` collection leaves both roll-ups `null` and skips
per-task report aggregation. It still computes the existing exact descendant
dispatch-budget counts, which can traverse task-tree history; fetch
`/v1/tasks/{id}` for the report summary.
`latest_receipt_received_at_in_sample` is when ACP recorded the response
receipt, not when the provider measured or billed it. `observed` means the
sampled receipts contain reports without known gaps; it does not prove all
model traffic was intercepted. `partial`, `none`, and `invalid` are distinct
from the separate `provider_usage` hard-limit field, which remains
`unsupported`.

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

For fan-out control, tasks may also set `max_unreceipted_dispatch_attempts`
and `max_descendant_unreceipted_dispatch_attempts`. These cap durable
reservations that do not yet have a response receipt, independently for one
task or across all descendants. Reservation admission checks run in the same
serialized transaction and are repeated by a SQLite trigger, so concurrent
sibling launches cannot consume the same last outstanding slot. A persisted
receipt releases that slot; an unreceipted reservation remains held across
service restarts and blocks further work until a receipt is recorded. There is
no timeout-based release or automatic retry because a missing receipt may mean
the provider request is still running or its outcome is ambiguous.

Task views expose `outstanding_dispatch_budget` and
`descendant_outstanding_dispatch_budget` with the unresolved count (`reserved`),
receipt-resolved count (`released`), remaining capacity, source, freshness, and
enforcement point. These are reservations at the ACP coordination boundary, not
verified provider concurrency: callers can bypass the ledger, one request may
fan out inside a provider, and a client-reported receipt is not a provider
attestation. Provider usage therefore remains `unsupported` for hard-limit
decisions.

These are **dispatch-attempt reservation slots**, not proof that an HTTP request
was sent, reached a provider, or incurred cost. Each new idempotency key
permanently consumes a slot even if the process crashes before sending or the
outcome is ambiguous. While the original claim remains active, replaying the
same task/idempotency key returns the existing reservation with `created:
false`; clients must not send on that replay. If that claim generation has
reported an interruption, the interruption fence takes precedence: all further
reservation requests, including replay of an existing key, fail with
`claim_interrupted` in the current service. Migration 9 also rejects new
reservation and submission inserts at the database layer, including writes
from an older service process sharing the migrated database. A pre-migration
process can still return an already-existing reservation on a read-only
idempotency replay; that does not create a reservation, and clients must never
send on a replay. A deliberate retry requires a new key and another available
slot under a newly fenced claim. Slots are never released or refunded. When
that claim expires, the coordination reaper moves the task to `blocked` instead
of making it automatically claimable, and reports it in
`blocked_interruption_task_ids`. An administrator must explicitly reopen the
task with a reason before a new claim can start; a provider quota reset alone
does not resume it. Migration 10 installs a SQLite status-transition guard as
well: a pre-migration reaper cannot orphan the interrupted generation, and an
older claimant cannot automatically resume an already-orphaned generation.
Migration 11 parks any pre-existing `orphaned` task whose interruption report
matches its current claim fence as `blocked`, so the normal audited reopen path
can recover it. Each migrated task transition is appended to the hash-chained audit
log inside the same schema transaction; an audit write failure rolls the migration
back. The current reaper may park it as `blocked`; only the audited
`blocked` → `open` reopen followed by a fresh claim is allowed. This lifecycle
fence does not stop an active local process or prove sandbox cleanup; those
remain separate runtime gates. If an older reaper encounters an interrupted
task, the database guard rejects its legacy transition and may roll back that
reaper transaction as a whole, delaying cleanup of other expired claims until
the upgraded reaper runs.
Reservations retain the task and resource fencing-token snapshot that was
checked at creation. Reservation and client-reported receipt rows survive a
service restart; task views recompute consumed slots from those persisted rows.
If a later reservation is denied, or a later attempt ends in an ambiguous send,
invalid response, or unconfirmed receipt, `dispatch_with_retries` raises
`DispatchRetryStopped` with the already-receipted attempt results and the
current attempt's reservation state, provider-send state, and ID when
available. A recognized 409 for either total-attempt cap or either
unreceipted-reservation cap means admission was denied; a lost or malformed
reservation response is marked unknown because the server may already have
committed the slot. The exception separately identifies whether
the provider send was not started, received a response, or has an unknown
outcome. For coordinator HTTP failures it also carries the status and a bounded
machine error code when supplied. The coordination API error body and provider
credentials are not copied into the exception; prior provider response objects
remain available in `attempts`. The current attempt is never labeled receipted
or retried by this helper. This makes partial responses recoverable by the
caller; it does not resume the sequence, release a consumed slot, or make an
incomplete task successful.

The optional receipt endpoint records one immutable response observation and
labels it `source: client_reported`. In particular, a client-reported 429 or
Retry-After is evidence only: it does not authorize, schedule, or perform a
retry, and it never restores a slot. The opt-in
`dispatch_openai_responses_once` helper covers only calls explicitly routed
through that fixed-endpoint adapter. ACP does not observe whether the client
actually sent a request or control provider/CLI internal retries and fan-out.
A worker that calls a provider directly can bypass these cooperative
reservations. Therefore these counters are not a
provider request limit, egress gate, quota control, token budget, or spend cap.

Python clients may opt into `agent_control_plane.dispatch_client.dispatch_once`
with `CoordinationHttpDispatchLedger` to use the reference API directly, or use
`dispatch_openai_responses_once` to send one fixed-endpoint OpenAI Responses
request and persist its client-reported usage:

~~~python
from agent_control_plane.dispatch_client import (
    CoordinationHttpDispatchLedger,
    dispatch_openai_responses_once,
)

ledger = CoordinationHttpDispatchLedger(
    base_url="https://acp.example",
    bearer_token=coordination_mandate,
)

result = dispatch_openai_responses_once(
    ledger=ledger,
    task_id=task_id,
    claim_fencing_token=claim_fencing_token,
    resource_fencing_tokens=resource_fencing_tokens,
    idempotency_key="task-attempt-1",
    api_key=api_key_from_secret_store,
    request_payload={"model": "gpt-5.6", "input": "Review this change."},
)
~~~

Do not hard-code either credential in source. The `idempotency_key` above is
for the ACP reservation only; the adapter does not claim provider-side
deduplication or make retries safe.

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
the durable slot remains consumed. A deliberate retry through `dispatch_once`
must be a new call with a fresh idempotency key and another reservation.

Callers that need bounded transient-server retries may explicitly use
`dispatch_with_retries` with a `DispatchRetryPolicy` and a provider-native
idempotency key. Use a fresh provider key for each logical operation, then pass
that same key to every callback for retries of that operation. The callback
must submit it with the same semantic operation/payload to a provider that
guarantees deduplication. ACP cannot verify provider support or that the
callback uses the key; if those conditions are not met, use `dispatch_once`
instead. The policy requires a finite maximum of 1–10 attempts, caps each
requested delay, and also caps cumulative retry waiting at up to 24 hours (60
seconds by default). Each wait charges the greater of its requested
`Retry-After` delay and the elapsed time measured monotonically around the
wait. If a sleeper overshoots the total cap, the sequence stops before another
provider callback; provider request time is not part of this wait-only cap. It
retries only HTTP 500, 502, 503, or 504 when the response contains a valid
`Retry-After` within both caps; every attempt uses a distinct ACP
reservation/idempotency key, and each response with a confirmed receipt write
gets its own immutable client-reported receipt. An ambiguous send or receipt failure ends the sequence
without a confirmed receipt; its durable slot remains consumed. HTTP 429 is
always returned without an automatic retry, even when it includes
`Retry-After`, because the response may represent exhausted quota and
the reset boundary is not known here. Missing, invalid, or too-long retry hints
also stop the sequence. A reservation denial prevents the next callback.
Restarting the same sequence replays its first key and is refused before the
transport is called; the helper does not resume or schedule work after a quota
reset. A retry may still consume provider usage, which ACP cannot meter or cap.

The supplied provider transport must itself disable retries and redirects: the
helper invokes a callback once per reserved attempt but cannot inspect or
control behavior inside that transport. This is not a provider adapter,
universal request gate, or protection against direct calls or provider-internal
fan-out.

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
- A model-request budget must reserve at the shared request-admission boundary,
  not at worker launch: sampling, compaction, and each retry can incur another
  provider request across the root and descendants. Settle each confirmed
  response once; keep an unresolved reservation outstanding after timeout,
  cancellation, or missing usage until reconciled. A request/token ceiling is
  not a dollar ceiling unless the provider supplies a trustworthy unit and a
  conservative pre-request bound or enforces the cap itself.
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

The Coordination API provides an opt-in
`POST /v1/tasks/{task_id}/interruption-reports` receipt for a worker that can
report a partial checkpoint before it exits. It is claim- and resource-fenced,
immutable per claim generation, survives service restart, and is bounded to an
8 KiB JSON checkpoint plus a 2,000-character summary. The checkpoint digest is
computed by the service. Linked dispatch IDs must already have client-reported
response receipts for the same task; the view includes those exact receipts and
their provider-usage provenance. Task detail shows the latest report as
`interruption_status: interrupted`, `status: partial`, `source: client_reported`,
and `promotable: false`; recording it does not change task status or create a
submission. Once recorded, that claim generation cannot reserve another
mediated dispatch or submit; resumption requires the normal expiry/recovery
path and a newly fenced claim. This is a cooperative API boundary, not a
provider cancellation mechanism: already-running calls, unmediated client
calls, and read-only replay of an already-existing reservation by a
pre-migration service process are unaffected. Migration 9 installs database
guards against fresh reservation and submission inserts for the reported
claim. The report is not host-authored evidence, a verified worktree/tree
snapshot, or a provider meter. Callers must not include credentials or raw
provider response bodies. The API rejects common
sensitive field names and credential-like values in the summary/checkpoint and
rejects nesting deeper than 32 levels. Validation responses for this endpoint
omit submitted values. These are guardrails, not comprehensive secret scanning
or DLP: unknown formats may pass, so callers must still minimize and redact
content before submission.
Existing submission and independent-QC gates remain the only route to
completion. This is a recovery breadcrumb, not full crash-durable result
recovery.

ACP task, attempt, and checkpoint records are separate from an interactive
agent's conversation transcript. A chat application's restored history does
not establish that ACP's durable task records rolled back, and ACP records do
not automatically capture or reconstruct that transcript. Caller-supplied
checkpoint fields may retain text, but they are not a complete or authoritative
transcript backup. Keep checkpoints bounded to task-relevant progress and
evidence; do not use the interruption-report API as transcript backup.

Example request (the checkpoint is caller-supplied JSON and is not host-verified):

```json
{
  "claim_fencing_token": 3,
  "resource_fencing_tokens": {"repo:file:src/example.py": 2},
  "reason": "retry_exhausted",
  "summary": "Tests were not completed; resume from the listed phase.",
  "checkpoint": {"phase": "tests", "next_step": "rerun focused suite"},
  "dispatch_attempt_ids": ["reservation-id-with-a-client-receipt"]
}
```

An exact repeat for the same claim returns the existing report; a different
payload for that claim conflicts. Expired claims can replay an already-created
report idempotently but cannot create a new one.

Python clients using `CoordinationHttpDispatchLedger` can call
`record_budget_interruption_report` to validate and send this request once.
The adapter verifies the returned task and claim/resource fences, echoed
checkpoint and digest, and every linked attempt/receipt ID and fence before it
returns the report. This protects the caller from a malformed or misbound API
response; it does not upgrade client-reported content into host-verified or
promotable evidence.

## Delivery gates

1. Local per-task and descendant-attempt caps and cooperative public API
   reservation slots, including hierarchical unreceipted-reservation caps, are
   implemented separately from provider meters, provider-enforced
   retries/quota lifecycle, host-authored worker checkpoints, and full
   crash-durable partial-result recovery; this client-reported interruption
   receipt is deliberately non-promotable and does not complete #2998.
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
- [OpenAI Codex issue #39129](https://github.com/openai/codex/issues/39129):
  a feature request for bounded batch fan-out calls out active-worker limits,
  aggregate budgets, and preserving successful results on partial failure.
- [Claude Code issue #72672](https://github.com/anthropics/claude-code/issues/72672):
  one reported rate-limit retry storm consumed 8.6 million subagent tokens in
  226 seconds without usable output; a single issue report, not a prevalence
  estimate.
- [OpenAI Codex issue #43885](https://github.com/openai/codex/issues/43885):
  opened 2026-09-08, this individual report describes completed post-recovery
  conversation history appearing to roll back after a desktop restart; later
  comments include Mac and Windows reports. A commenter alleges that the
  source rollout log retained later messages while a derived SQLite history
  view was stale. These are unverified user reports, not evidence of ACP data
  loss or a confirmed product root cause.
- [OpenAI Codex issue #53101](https://github.com/openai/codex/issues/53101):
  opened 2026-10-11, one user reports apparent agent activity and file changes
  after a conversation was interrupted and another agent messaged it while the
  user was conserving quota. The reporter cannot establish whether messaging
  restarted execution or pending work continued, and a commenter cautions that
  quota use cannot be attributed from the report alone. This is an unverified
  interruption-control case, not prevalence or causal proof.
- [OpenAI Codex issue #46704](https://github.com/openai/codex/issues/46704):
  opened 2026-09-19, one report says Codex CLI 0.155.1 allowed a depth-2
  worker-to-leaf spawn with configured `max_depth = 1`; a separate probe with
  `max_depth = 0` also allowed a spawn, although the reporter notes that zero's
  intended semantics were unclear. This is bounded to the reported version and
  environment; it does not establish current behavior across products or ACP,
  but supports requiring evidence at the actual spawn boundary before claiming
  a depth limit is enforced.
- [OpenAI Codex issue #55168](https://github.com/openai/codex/issues/55168) and
  its [request-budget companion #55180](https://github.com/openai/codex/issues/55180):
  opened 2026-10-19. A sanitized, source-audited local ledger reports 8.95B
  processed input-plus-output tokens over 36 hours across 50,465 unique
  responses, including compaction omitted from a legacy usage counter. The
  report does not establish billed cost, incorrect billing, a configured-cap
  breach, or a concurrency-limit breach. The companion proposes atomic shared
  admission before each model request, including sampling, compaction, and
  retries, and retaining uncertain reservations across timeout/cancellation.
  Treat this as one practitioner evidence package and a proposed engineering
  contract, not as prevalence or proof of root cause.
- [How Do AI Agents Spend Your Money?](https://arxiv.org/abs/2604.22750):
  research on token use in evaluated coding-agent tasks; results are specific
  to its dataset and setup.
- Existing ACP references: README runtime-resource and mandate-limit sections;
  tasks #2316, #2362, #2366, #2370, and #2439.
