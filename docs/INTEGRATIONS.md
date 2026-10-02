# Integrations

ACP's enforcement boundary is only real if the agent's edits pass through it. Claiming
a task allocates a worktree and a write set, but nothing stops a session editing the
base checkout instead — and a write that never reached ACP cannot be fenced, reviewed,
or attributed. These adapters put the kernel in front of the tool calls that write.

Every adapter **asks**; it never decides. `acp guard` answers with the same
`_path_matches` that `acp submit` applies to the finished diff. A second implementation
of the rule would eventually disagree with the one that matters, and an agent allowed
to write something its own submission is later rejected for is the worst of both.
For Claude Code structured-write hooks, the supervisor also checks the hook's
host-reported working directory and resolves relative targets from that directory.

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

For hook calls, the adapter first validates the payload. If it cannot extract both a
supported writable path and a non-empty string `cwd`, it denies with
`unreadable_hook_payload` before looking up the attempt or checking its lease. The
supervisor denials below are then checked in this order:

| reason | meaning |
| --- | --- |
| `attempt_not_found` | no such attempt |
| `attempt_not_live` | the attempt is orphaned, submitted or quarantined |
| `lease_expired` | the claim lease has run out; heartbeat or re-claim |
| `invalid_working_directory` | hook cwd is not absolute, an existing directory, or resolvable |
| `cwd_outside_worktree` | hook cwd is outside this attempt's worktree |
| `invalid_path` | the target path cannot be resolved |
| `outside_worktree` | the path resolves outside the allocated worktree |
| `undeclared_write` | inside the worktree, but not in the task's write set |
`outside_worktree` covers three things worth stating plainly: `../` traversal, absolute
paths elsewhere on the machine, and **the base checkout** — even for a file that IS in
the write set, because the copy in the base checkout is not the one the attempt leased.
Paths are resolved before comparison, so a symlink planted inside the worktree cannot
launder a write out of it. A Claude Code hook must include its absolute `cwd`; ACP
requires it to resolve to the attempt worktree or one of its subdirectories. Relative
tool paths are resolved from that reported directory, not silently re-rooted to the
attempt root. An absolute target does not bypass the cwd check. Direct `acp guard
--path` and read-only MCP `acp_guard` calls omit hook context and keep their existing
attempt-root-relative path semantics.

## Claude Code

```bash
acp hooks install --claude-code
```

Writes `.claude/settings.json` in the repository:

- **PreToolUse** on `Edit|Write|MultiEdit|NotebookEdit` → `acp guard --hook`. Exit 2
  blocks the tool call and returns the reason to the model. The adapter requires the
  hook's `cwd`, verifies it is within the claimed worktree, and resolves relative edit
  paths from it.
- **SessionStart** → `acp guard --describe`, so the session starts knowing its worktree
  and write set rather than discovering the boundary by hitting it.

The install **merges**. Hooks you already have — including your own `PreToolUse`
entries — are preserved, previous ACP entries are replaced rather than duplicated, and
a `settings.json` that is not valid JSON is left untouched with an error instead of
being overwritten.

This check addresses reported Claude Code cwd drift: one session or subagent can appear
to enter another worktree. The official hook payload provides a `cwd` field, which lets
ACP reject an invocation whose reported context is outside its claim. This is still a
pre-write hook, not filesystem isolation: it does not cover Bash, unhooked tools, hook
bypass, or a race after the check. Treat issue reports as individual experiences, not
prevalence estimates.

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
- **No Codex pre-write hook.** We are not installing a project-local Codex hook as a
  write boundary. The official hook contract supports denials, but first-party reports
  describe `apply_patch` denials not being enforced and the hook lacking the effective
  patch worktree. Those reports cover older Codex builds; the current stable behavior
  has not been independently verified. Codex's own docs also warn that hook errors,
  timeouts, and malformed responses may continue without blocking. See the supervised
  CLI workflow below instead. There is no Cursor adapter.

## Codex CLI through an ACP worker (Linux only)

For a noninteractive Codex CLI run, ACP can allocate a distinct attempt worktree and
launch Codex from that checkout through the existing supervised worker. Each accepted
parallel attempt gets a different filesystem checkout and branch; the worker environment
drops Git repository/index override variables so ambient `GIT_DIR` or `GIT_WORK_TREE`
cannot redirect its Git operations. ACP refuses a new claim while its declared write
scope overlaps a live claim (`resource_busy`), so tasks writing the same file are
serialized rather than run simultaneously. When Codex exits successfully, ACP submits
the attempt for the independent QC gate.

The following assumes the task already has a bounded resource/write set and the named
worker identity is enrolled. The credential file must be private (mode `0600`). Keep
the prompt on stdin rather than a command argument so it is not recorded in the worker
launch checkpoint:

```bash
CLAIM=$(acp --repo "$REPO" claim "$TASK_ID" --agent codex-worker \
  --credential-file "$ACP_CREDENTIAL_FILE")
ATTEMPT=$(printf '%s' "$CLAIM" | jq -r .id)
TOKEN=$(printf '%s' "$CLAIM" | jq -r .claim_token)
printf '%s\n' "$PROMPT" | acp --repo "$REPO" run "$ATTEMPT" --token "$TOKEN" \
  --credential-file "$ACP_CREDENTIAL_FILE" -- \
  codex exec --sandbox workspace-write \
    --config 'sandbox_workspace_write.writable_roots=[]' \
    --config 'sandbox_workspace_write.exclude_tmpdir_env_var=true' \
    --config 'sandbox_workspace_write.exclude_slash_tmp=true' \
    -
```

`acp run` is a noninteractive supervised worker, not a Codex Desktop session. It
requires Linux child-subreaper support, captures Codex output in
`.acp/logs/worker-ATTEMPT_ID.log`, and submits after a successful exit. The example
selects Codex's workspace-write sandbox and uses one-run config overrides to clear
configured extra writable roots and exclude `/tmp` and `$TMPDIR`. Codex otherwise reads
user and trusted-project config; a pre-existing `sandbox_workspace_write.writable_roots`
could grant writes outside the attempt checkout. The documented CLI overrides have
higher precedence than those config layers, but do not bypass organization-managed
policy. Confirm the effective writable roots are limited to the attempt workspace; for
an interactive diagnostic, Codex `/status` reports writable roots and `/debug-config`
shows config-layer precedence and managed requirements. Use a noninteractive approval
policy already appropriate for the job. Do not add `--add-dir`, disable sandboxing, or
use dangerous bypass flags. ACP worktrees are source isolation, not a general filesystem
sandbox: keep Codex's own sandbox enabled. Codex Desktop, ordinary local chats, and
non-Linux `acp run` remain outside this integration.

Why there is no Codex hook installer yet:

- [Codex issue #27833](https://github.com/openai/codex/issues/27833) is open and reports
  that supported PreToolUse deny outputs were ignored for `apply_patch` on CLI 0.133.0
  and Desktop 0.138.0-alpha.7. This is one user report on those versions, not proof of
  behavior in every current release; this machine's Codex CLI 0.144.6 was help-checked
  but not live-probed.
- [Codex issue #20879](https://github.com/openai/codex/issues/20879) is open and reports
  native `apply_patch` lacks per-call workdir context on CLI 0.128.0, so a hook may not
  see the worktree that will receive the patch.
- [Codex's official hook documentation](https://learn.chatgpt.com/docs/hooks) describes
  hook trust and supported denial responses, and explicitly notes that hook callback
  errors, timeouts, or malformed responses can fail without blocking the tool.
- [Codex configuration documentation](https://learn.chatgpt.com/docs/config-file/config-reference)
  defines `sandbox_workspace_write.writable_roots` as extra writable paths;
  [developer settings](https://learn.chatgpt.com/docs/developer-settings) documents
  one-run CLI override precedence and ways to inspect effective roots.

Until the current supported releases pass a disposable live denial/worktree test, do not
describe Codex PreToolUse hooks as an ACP safety boundary.
