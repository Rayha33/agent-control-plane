# Integrations

ACP's enforcement boundary is only real if the agent's edits pass through it. Claiming
a task allocates a worktree and a write set, but nothing stops a session editing the
base checkout instead — and a write that never reached ACP cannot be fenced, reviewed,
or attributed. These adapters put the kernel in front of the tool calls that write.

Every adapter **asks**; it never decides. `acp guard` answers with the same
`_path_matches` that `acp submit` applies to the finished diff. A second implementation
of the rule would eventually disagree with the one that matters, and an agent allowed
to write something its own submission is later rejected for is the worst of both.

## `acp guard`

```bash
acp guard --attempt ATTEMPT_ID --path src/thing.py   # exit 0 allows, exit 2 denies
acp guard --hook                                     # PreToolUse payload on stdin
acp guard --describe                                 # worktree + write set, for context
```

`--attempt` defaults to `$ACP_ATTEMPT_ID`. The decision is JSON on stdout; on a denial
the reason is also a sentence on stderr, because that is what a runner shows the model.
An agent told *"beta.txt is not in the task's declared write set; declared: alpha.txt"*
corrects itself in one turn. Guard is read-only — a pre-write check must never itself
become a reason the state changed.

Denials, in the order they are checked:

| reason | meaning |
| --- | --- |
| `attempt_not_found` | no such attempt |
| `attempt_not_live` | the attempt is orphaned, submitted or quarantined |
| `lease_expired` | the claim lease has run out; heartbeat or re-claim |
| `outside_worktree` | the path resolves outside the allocated worktree |
| `undeclared_write` | inside the worktree, but not in the task's write set |
| `unreadable_hook_payload` | the request could not be parsed, so it is refused |

`outside_worktree` covers three things worth stating plainly: `../` traversal, absolute
paths elsewhere on the machine, and **the base checkout** — even for a file that IS in
the write set, because the copy in the base checkout is not the one the attempt leased.
Paths are resolved before comparison, so a symlink planted inside the worktree cannot
launder a write out of it.

## Claude Code

```bash
acp hooks install --claude-code
```

Writes `.claude/settings.json` in the repository:

- **PreToolUse** on `Edit|Write|MultiEdit|NotebookEdit` → `acp guard --hook`. Exit 2
  blocks the tool call and returns the reason to the model.
- **SessionStart** → `acp guard --describe`, so the session starts knowing its worktree
  and write set rather than discovering the boundary by hitting it.

The install **merges**. Hooks you already have — including your own `PreToolUse`
entries — are preserved, previous ACP entries are replaced rather than duplicated, and
a `settings.json` that is not valid JSON is left untouched with an error instead of
being overwritten.

Export the attempt id from the claim before starting the session:

```bash
ATTEMPT=$(acp claim "$TASK" --agent me | jq -r .id)
export ACP_ATTEMPT_ID=$ATTEMPT
cd "$(acp guard --describe | jq -r .worktree)"
```

### Bash is not guarded, deliberately

`Bash` is absent from the matcher. Deciding what an arbitrary shell command writes means
parsing the shell: a pattern that catches `rm -rf /etc` misses `sh -c "$(printf ...)"`,
`tee`, an editor invocation, or a redirect built from a variable. A guard that can be
walked around by rephrasing is worse than an absent one, because it reads as coverage
in a review.

Confine a shell with the worktree and the OS instead — run the agent under an identity
that cannot write the base checkout, or use `acp run` on Linux, where the supervised
worker path exists for exactly this reason.

## `acp mcp-serve`

A read-only MCP server over stdio, so a session can read the board it works under
without shelling out:

```json
{"mcpServers": {"acp": {"command": "acp", "args": ["--repo", "/path/to/repo", "mcp-serve"]}}}
```

Ten tools, each a one-line delegation to a supervisor method: `acp_status`,
`acp_queue`, `acp_merge_plan`, `acp_reviewers`, `acp_verify_events`, `acp_show`,
`acp_plan`, `acp_bundle`, `acp_guard_context`, `acp_guard`.

**No writes and no credential, on purpose.** `claim`, `heartbeat`, `submit`, `qc` and
`integrate` are authenticated, and `runner_identity.py` keeps worker, critic and
integrator authority apart so nobody approves their own work. A server an editor spawns
and holds open would have to keep a credential for the whole session; one holding more
than one role's would erase that separation in a process nobody is watching. The CLI
takes credentials only from a 0600 file or an open descriptor, never the environment —
putting one in a server's environment would undo that care rather than reuse it.

The server opens `GitSupervisor(read_only=True)` per call, so `mode=ro` makes a stray
write raise rather than depend on discipline, and a database needing migration is
reported instead of silently upgraded. Tests assert which bound method each tool
reaches and that none of them takes a `credential` parameter — a tool-name check would
stay green if `acp_status` were implemented as `claim`.

There is no third-party dependency: the wire format is newline-delimited JSON-RPC 2.0,
small enough to implement honestly and not worth an SDK in `acp`'s import graph for one
subcommand.

### MCP Tasks

An ACP task already is the long-running unit MCP Tasks describes, so the server declares
`tasks` for tool calls and exposes one task-augmented tool:

```json
{"capabilities": {"tasks": {"requests": {"tools": {"call": {}}}}}}
```

`acp_watch_task` carries `execution.taskSupport: "required"`. A task-augmented call
returns a `CreateTaskResult` whose `taskId` is the ACP task id; the client then polls
`tasks/get`, and `tasks/result` returns the finished task. Calling it without task
augmentation — or augmenting a tool that does not support it — is `-32601`, as the
specification requires. It dispatches to the same read-only `task` method `acp_show` uses,
so the server is still credential-free.

`tasks/list` and `tasks/cancel` are **not declared**, for two different reasons. A stdio
server cannot bind tasks to an authorization context, and the specification says such a
receiver SHOULD NOT declare `tasks.list`; listing would expose every task to anyone who can
spawn the process. Cancelling would be a write, and ending a claim is fenced — resources
must stay reserved until the revoked runner's last attempt token expires — so it belongs to
the administrator's `POST /v1/tasks/{id}/revoke-claim`, not to a tool.

Status mapping is deliberately conservative. Both protocols require terminal statuses never
to transition, while most ACP statuses can: `blocked` and `conflicted` are reopened,
`orphaned` is reclaimed. `done` is the only ACP status that never changes, so it is the only
one reported as `completed`; anything waiting for a person is `input_required`, which is
interrupted rather than terminal. A status with no classification raises rather than
defaulting to `working`.

`tasks/result` must block until the task is terminal. It polls at `pollInterval` and gives
up after five minutes with `-32603` rather than blocking a single-threaded stdio server
forever — a bounded deviation, in preference to a server that stops answering.

## A2A

The HTTP authority serves an agent card at `/.well-known/agent-card.json` and A2A 1.0
JSON-RPC at `POST /a2a`, authenticated with the same bearer mandate as every other
endpoint. Clients must send the `A2A-Version` header; an absent value means 0.3 by
specification, which this interface does not speak, so it answers
`VersionNotSupportedError` (`-32009`).

| Method | Answer |
| --- | --- |
| `GetTask` | the task, with its fencing generations in `metadata` and its latest submission as an artifact |
| `ListTasks` | only the tasks the caller's mandate scope allows |
| `CancelTask` | `TaskNotCancelableError` (`-32002`) — ending a claim is fenced; see `revoke-claim` |
| `SendMessage` | `UnsupportedOperationError` (`-32004`) — creating work is an operator action |

A task outside the mandate's scope answers exactly as a missing task does (`-32001`), so
scope cannot be used as an oracle for which tasks exist. Enum values are ProtoJSON names
(`TASK_STATE_WORKING`), matching the 1.0 binding.

Neither adapter re-implements a check. They map protocol identity onto the same
authenticated service — the property `ARCHITECTURE.md` invariant 4c asks for: protocol
transport must not create an alternate authority path.

### What this does not do yet

- **No write tools.** Claiming and submitting through MCP needs the credential question
  above answered first, and a narrower shipped thing beats a broad unshipped one.
- **No heartbeat hook.** `acp heartbeat` is a write needing the claim token and the
  runner credential, so wiring it into a hook means deciding how a secret reaches a hook
  process. Until then an expired lease surfaces as a `lease_expired` denial — loud
  rather than silent.
- **No MCP server.** `acp_plan` / `acp_claim` / `acp_submit` as callable tools would let
  an agent drive the lifecycle itself rather than being placed in a worktree by a human.
  Guarding writes was the part that closes a hole; that part adds a capability.
- **No Codex or Cursor adapter.** The `guard` command is runner-agnostic — `--path` with
  an exit code is all an adapter needs — but nobody has written and tested those hook
  configurations.
