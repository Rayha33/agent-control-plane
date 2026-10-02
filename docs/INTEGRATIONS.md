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
corrects itself in one turn. The normal guard is read-only. The opt-in
`--serialize-write-tools` mode below adds only a short-lived reservation record around
each supported structured edit.

The `--hook` payload must include the editor's `cwd` as well as the target path. Missing,
malformed, nonexistent, or out-of-attempt working directories deny before the editor
call. Relative paths are resolved against that caller cwd; nested directories inside the
attempt worktree are allowed. The direct `--path` form uses the CLI process's actual
working directory. MCP `acp_guard` callers must provide `caller_cwd` for the same check
and an absolute target path. MCP's `caller_cwd` is caller-supplied context, not an
attestation of the client process's directory; clients must write the exact absolute
path ACP approved, never reinterpret it relative to another cwd.

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

For an ACP attempt, install the hook into that attempt's personal local settings. This
keeps the settings out of the submitted task diff and points every invocation at the
base checkout's canonical control database:

```bash
BASE=$(git rev-parse --show-toplevel)
ATTEMPT=$(acp --repo "$BASE" claim "$TASK" --agent me | jq -r .id)
export ACP_ATTEMPT_ID=$ATTEMPT
WORKTREE=$(acp --repo "$BASE" guard --describe | jq -r .worktree)
acp --repo "$BASE" hooks install --claude-code --attempt "$ATTEMPT"
cd "$WORKTREE"
```

`--attempt` writes `.claude/settings.local.json` inside the attempt worktree, merges
existing personal settings, and adds that local settings path to this repository's
`.git/info/exclude`. The generated hook command pins `--repo` to `BASE`; this is
necessary because each attempt is its own Git root while `.acp/control.db` belongs to
the base checkout. Re-running the installer is idempotent. The no-`--attempt` form
continues to write shared project settings at `.claude/settings.json` for use in the
checkout where it is installed.

- **PreToolUse** on `Edit|Write|MultiEdit|NotebookEdit` → `acp guard --hook`. Exit 2
  blocks the tool call and returns the reason to the model.
- **SessionStart** → `acp guard --describe`, so the session starts knowing its worktree
  and write set rather than discovering the boundary by hitting it.

Generated Claude commands carry a private `--acp-managed-hook` ownership flag. The
installer uses it to recognize ACP hooks after the executable path changes, without
mistaking a user command such as `echo acp guard --hook` for an ACP hook.

### Optional stale full-file write check

Install with `--stale-write-guard` to add a conservative freshness check for Claude
Code's structured `Write` tool:

```bash
acp --repo "$BASE" hooks install --claude-code --attempt "$ATTEMPT" \
  --stale-write-guard
```

The `Read` pre-hook stores a bounded SHA-256 snapshot plus filesystem identity/change-time
tokens for the file and each directory from the attempt worktree root through its parent.
Before a full `Write` replacement, ACP compares them with the current path; edits restored
to identical bytes and parent-directory swaps are detected on filesystems with normal POSIX
ctime behavior. Other directory-entry changes along that path can conservatively require a
fresh read. An expired/missing baseline for an existing file, or an unreadable/oversized
file, denies the write and tells the agent to read again. A still-absent path may be created.
Snapshot traversal is anchored at the attempt worktree, opens each path component without
following symlinks, and verifies the directory chain stayed unchanged while hashing; if
those safe descriptor-relative APIs are not available, snapshot recording fails and
replacement of an existing file fails closed. Only a subsequent supported `Read` refreshes
the snapshot; an agent that writes a file must read it again before another full-file
replacement. Snapshots are scoped to one attempt and path, expire after 24 hours, are capped
at 256 paths per attempt, and are limited to 16 MiB per file. The option is off by default.

This is an optimistic stale-content check, not a filesystem lock or atomic compare-and-
swap: another process can still change a file in the small interval between the pre-write
check and Claude Code's write. It covers only structured Claude `Write` operations whose
`Read`/`Write` hooks actually run. It does not cover `Edit`, `MultiEdit`, Bash, MCP or
custom clients, reads through other tools or `@` prompt references, or disabled/untrusted
hooks. Do not treat it as a security boundary or as proof that every agent write was
checked.

### Optional same-attempt structured-write serialization

Claude Code subagents inherit the session's configured hooks and tool events carry
`tool_use_id`; tool events inside subagents additionally carry `agent_id` for attribution.
If several subagents share one ACP attempt, they share its worktree and task lease too. Install with
`--serialize-write-tools` to add an atomic, attempt-scoped reservation around the
structured file tools:

```bash
acp --repo "$BASE" hooks install --claude-code --attempt "$ATTEMPT" \
  --serialize-write-tools
```

The pre-hook reserves the resolved path for that invocation before the editor runs. A
second invocation in the same attempt that targets the same path or an ancestor/child
path is denied with `concurrent_write_conflict`; a disjoint path may proceed. The
reservation is keyed by `(attempt_id, tool_use_id)` and bound to the same `agent_id` for
idempotent reserve/release; `agent_id` may be absent on main-thread calls. Reusing one
`tool_use_id` across agent identities fails closed. `PostToolUse` and `PostToolUseFailure`
release after success or execution failure. `PermissionDenied` also releases auto-mode
denials, but Claude Code does not emit that event for a manually denied permission dialog.
If a completion event is not emitted (including manual denial, interruption, or crash),
the reservation expires after five minutes and is removed on the next reservation request.
Missing or malformed `tool_use_id` fails closed for a new write.

This is opt-in and covers only the structured Claude Code tools in the matcher above. It
does not mediate Bash, MCP/custom tools, external processes, or untrusted/disabled hooks;
it is a control-plane reservation, not an OS filesystem lock or a protection against a
same-user process that writes outside the hook. ACP does not enforce a Claude Code
version number: it relies on the documented event payloads and fails closed when a
pre-write event lacks `tool_use_id`. Verify the documented events in the installed
client. See the [Claude Code hooks reference](https://code.claude.com/docs/en/hooks).

The install **merges**. Hooks you already have — including your own `PreToolUse`
entries — are preserved, previous ACP entries are replaced rather than duplicated, and
a `settings.json` that is not valid JSON is left untouched with an error instead of
being overwritten.

Start Claude Code from the displayed worktree after installing the attempt-scoped hook.

## Codex

Codex's supported PreToolUse hook can match apply_patch, and its payload includes
the session cwd plus the patch in tool_input.command. Following the
[upstream apply_patch grammar](https://github.com/openai/codex/blob/main/codex-rs/apply-patch/src/parser.rs),
ACP parses the structured <code>*** Begin Patch</code> / <code>*** End Patch</code>
request, extracts every Add/Delete/Update path and an optional Move to destination,
then asks the same guard used at submission for each path. One denied path blocks the
entire patch; unknown or malformed syntax, missing context, no paths, patches over
2,000,000 characters, or more than 128 paths are denied.
Patch input containing U+001C through U+001F is also denied because Python and Codex's
Rust parser trim these control characters differently, which could otherwise make
their interpreted filenames disagree.
Patches carrying Codex's `*** Environment ID:` marker are also denied: ACP does not
yet bind a Codex-selected environment identity to the attempt worktree.

Install into the live attempt worktree, not the base checkout:

    BASE=$(git rev-parse --show-toplevel)
    ATTEMPT=$(acp --repo "$BASE" claim "$TASK" --agent me | jq -r .id)
    WORKTREE=$(acp --repo "$BASE" guard --attempt "$ATTEMPT" --describe | jq -r .worktree)
    acp --repo "$BASE" hooks install --codex-code --attempt "$ATTEMPT"
    cd "$WORKTREE"

The attempt form writes .codex/hooks.json inside the worktree, pins both the base
checkout where .acp/control.db lives and the attempt id, merges existing hook entries,
replaces an earlier ACP Codex entry only when its command prefix still matches, and
adds this local config file to the shared Git exclude file so it does not enter the
candidate diff. Tracked config,
invalid JSON, invalid top-level hook structure, and symlinked config paths are rejected
without replacing the existing config. The project-wide form is acp --repo PATH hooks
install --codex-code; it relies on ACP_ATTEMPT_ID being set in the Codex process
environment at launch.

Codex requires project-local config to be trusted and each non-managed hook definition
to be reviewed before it runs. Review and trust the exact entry in Codex's /hooks
interface. Codex loads matching hooks from all active sources; higher-precedence
settings do not replace lower-precedence hook sources. See the
[Codex hooks documentation](https://learn.chatgpt.com/docs/hooks) for current config,
trust, and hook-response behavior. Hooks are enabled by default, but a local
features.hooks=false setting disables them; verify the hook is active before relying
on it.

An allowed guard returns success without changing stdout. A denied guard emits
Codex's explicit PreToolUse permissionDecision: deny response. ACP-side parsing
or guard exceptions also produce that explicit denial. However, Codex documents that
a hook timeout, failed launch, malformed hook response, or other hook error may be
reported without blocking the tool call. Treat this adapter as a useful guardrail, not
a complete security boundary.

### What the Codex hook does not guard

The matcher is only apply_patch. Codex also supports separate hooks for Bash and MCP
tools, but this adapter does not configure them: shell redirections, editors launched
from a shell, MCP tools, specialized tool paths that opt out of hooks, and other write
paths are outside its coverage. A project hook may also be untrusted or disabled until
reviewed. For enforcement against those bypasses, use an OS identity/sandbox that
cannot write outside the attempt worktree (or the supported supervised Linux worker
path), not a pattern-matching shell hook.

### Bash is not guarded, deliberately

`Bash` is absent from the matcher. Deciding what an arbitrary shell command writes means
parsing the shell: a pattern that catches `rm -rf /etc` misses `sh -c "$(printf ...)"`,
`tee`, an editor invocation, or a redirect built from a variable. A guard that can be
walked around by rephrasing is worse than an absent one, because it reads as coverage
in a review.

Confine a shell with the worktree and the OS instead — run the agent under an identity
that cannot write the base checkout, or use `acp run` on Linux, where the supervised
worker path exists for exactly this reason.

## Cross-worktree messages

Agents working in separate attempt worktrees can leave a small checkpoint, finding,
blocker, question, or handoff in the base checkout's `.acp/control.db`. The database
is outside every attempt worktree, so the message does not become a file conflict or
disappear when an attempt worktree is removed. Messages are append-only, hash-chained
events; each is attributed to the sender's active attempt and current worker identity.

Use the base checkout for both commands. The numeric claim token fences the attempt;
prefer a private 0600 file or an open descriptor for the credential, never a command
argument. For compatibility, the CLI also accepts `ACP_RUNNER_CREDENTIAL`; avoid that
fallback in shared or inherited process environments:

```bash
BASE=/path/to/repo
ATTEMPT=sender-attempt-id
OTHER_ATTEMPT=recipient-attempt-id
CLAIM_TOKEN=1
RUNNER_CREDENTIAL_FILE=/path/to/private/runner-credential

acp --repo "$BASE" message send "$ATTEMPT" --token "$CLAIM_TOKEN" \
  --kind handoff --to "$OTHER_ATTEMPT" \
  --text "I renamed the serializer field; the remaining caller is in api.py." \
  --credential-file "$RUNNER_CREDENTIAL_FILE"
acp --repo "$BASE" message list --attempt "$OTHER_ATTEMPT" --limit 50
```

Omit `--to` to broadcast to attempts in the same ACP project. `message list` and the
read-only MCP `acp_inbox` tool return broadcasts plus messages addressed to the given
attempt; paginate with `after_sequence`/`--after`. The CLI `message send` path requires
a live worker credential bound to the attempt, an active claim lease, and the current claim
token. An unknown recipient, expired or replaced attempt, revoked credential, invalid
kind, control character, or body above 4,096 UTF-8 bytes is rejected. Supported kinds
are `finding`, `blocker`, `handoff`, `question`, and `checkpoint`. A project accepts at
most 10,000 messages; after that cap, further sends fail closed. There is no TTL or
message-only pruning, so the cap bounds message growth and retained entries live as
long as the control database.

Runner authentication must be enabled for message sending. Legacy auth-disabled
attempts fail closed even if a caller supplies arbitrary credential text; enroll the
worker and start a new attempt before using this channel.

Message bodies are untrusted agent-authored text, not ACP instructions or authority.
The MCP tool labels them untrusted; they are never injected automatically into a
prompt. Do not send secrets, credentials, whole diffs, or private user data. This is
pollable coordination, not guaranteed delivery or a security boundary. `--to` is
routing, not confidentiality: any local process with access to the project's control
database can inspect its event chain. Messages remain in that log as long as
`.acp/control.db` is retained.

## `acp mcp-serve`

A read-only MCP server over stdio, so a session can read the board it works under
without shelling out:

```json
{"mcpServers": {"acp": {"command": "acp", "args": ["--repo", "/path/to/repo", "mcp-serve"]}}}
```

Twelve tools, each a one-line delegation to a supervisor method: `acp_status`,
`acp_queue`, `acp_merge_plan`, `acp_reviewers`, `acp_verify_events`, `acp_show`,
`acp_plan`, `acp_bundle`, `acp_guard_context`, `acp_guard`, `acp_inbox`, and
`acp_changes`.

**No writes and no credential, on purpose.** `claim`, `heartbeat`, `submit`, `qc` and
`integrate` are authenticated, and `runner_identity.py` keeps worker, critic and
integrator authority apart so nobody approves their own work. The CLI accepts credentials
from a 0600 file, an open descriptor, or the `ACP_RUNNER_CREDENTIAL` compatibility
fallback. The MCP server never reads that variable or calls credential-taking methods;
because it inherits its launch environment like any child process, launch it with a
sanitized environment and leave `ACP_RUNNER_CREDENTIAL` unset.

The server opens `GitSupervisor(read_only=True)` per call, so `mode=ro` makes a stray
write raise rather than depend on discipline, and a database needing migration is
reported instead of silently upgraded. Tests assert which bound method each tool
reaches and that none of them takes a `credential` parameter — a tool-name check would
stay green if `acp_status` were implemented as `claim`.

There is no third-party dependency: the wire format is newline-delimited JSON-RPC 2.0,
small enough to implement honestly and not worth an SDK in `acp`'s import graph for one
subcommand.

### Read-only change previews

Use the base checkout to inspect one known attempt; the command does not change or
reconcile its worktree:

```bash
acp --repo "$BASE" changes "$ATTEMPT"
```

The preview separates committed path/status changes from the current index/worktree and
untracked path names. It reports the attempt's start SHA, the HEAD observed before and
after the scan, and per-status path counts. Output is path metadata only: no file contents,
line-level diff, credential, or claim token. Lists are capped at 1,000 paths per section;
counts cover inventories up to 10,000 records per section and `paths_truncated` identifies a
capped list. Larger inventories or Git output over 16 MiB fail closed. Git reads the
captured index in disposable metadata and an isolated object directory containing copies of
regular loose objects and paired pack/index files in the ACP repository's local object store.
The preview does not copy or follow `objects/info/alternates` (including transitive
alternates), and the temporary object database has no alternate path of its own; commits
available only through an external alternate therefore fail closed. A snapshot with more than
250,000 object-store directory entries or over 1 GiB of object data fails closed. Git index
directories are incrementally capped at 1,024 entries. It does not load
repository/worktree/global/system Git config,
configured worker filters, external excludes files, `.git/info/exclude`, or external attribute
files. Attribute lookup is pinned to a generated empty tree using Git's
`--attr-source=<tree-ish>` option, and the isolated Git metadata contains a guarded
`info/attributes` file that unsets `filter`. Git versions without `--attr-source` fail
closed. Consequently, a path excluded only through those settings can appear in the
preview, and paths marked with a filter attribute may be conservatively reported as
modified. This intentionally favors a bounded inventory over exact parity with a user's
normal `git status` configuration.

Live worktrees can change during inspection. `stable: false` means HEAD, index, or the
path/status inventory changed between observations; even `stable: true` is best-effort,
not a snapshot guarantee (content can change without changing the observed path/status set).
Treat the displayed file and directory names as potentially sensitive. This view does not
make an uncommitted file safe to reuse and does not authorize checkout, cherry-pick, copy,
or merge.

The CLI and `acp_changes` MCP tool call the same supervisor method on a `mode=ro` database.
Git is invoked with optional index writes disabled, external diff/textconv/pager and
fsmonitor disabled, external attribute files ignored, and submodule traversal suppressed.
The scratch repository is created under `/tmp` rather than honoring `TMPDIR`, `TMP`, or
`TEMP`, so caller-controlled temporary-directory settings cannot write metadata into the
attempt being inspected.
Repository and worktree Git config are not loaded, so changes there cannot supply preview
settings or filter executables. Git uses fixed command-line overrides and isolated scratch
metadata. The index is copied via no-follow reads into temporary metadata and checked again
afterward; a changing HEAD, index, status inventory, or allocated worktree makes the result
unstable or fails closed.
The isolated Git config, HEAD, guarded `info/attributes`, copied index, scratch-parent
identity/signature, and empty alternates/ref directories are fingerprinted around every
Git invocation. Immediately before exec, the pinned-worktree launcher rechecks the scratch
parent and Git-directory identities, config digest, and filter guard. Those checks are not
atomic with Git opening its metadata paths, so the isolated child also receives a verified
zero soft and hard process-creation limits before Git runs. It rejects set-user-ID and
set-group-ID Git executables. On Linux it also rejects relevant effective, permitted,
inheritable, or ambient capabilities, sets and verifies `no_new_privs` before exec, and
probes that a fork is actually denied. If the platform cannot prove these conditions or
the process runs as root, the launcher fails closed. A hostile same-UID process can still
cause denial of service by racing scratch files, but Git cannot start a clean filter or
other helper from that race, and the post-invocation metadata fingerprints reject observed
changes. This is not isolation from arbitrary code already running as the same OS user.
The copied object store is checked against its copy-time file inventory; file bytes are
compared while copying, the trusted empty-tree attribute source is added to that inventory,
and the complete object-file signature inventory is rechecked before returning. Observed
scratch-parent swaps, injected objects, or other metadata changes fail closed.
An active index lock or index snapshot beyond the bounded per-file/aggregate size limits
fails closed. The temporary metadata is removed at the end. The preview does not create
Git locks or touch refs, index entries, worktree files, ACP rows, or audit events.

### What this does not do yet

- **The MCP server is read-only today.** `acp mcp-serve` is shipped and exposes
  twelve read-only tools, including `acp_plan`, `acp_guard`, and `acp_changes`; it does not expose the
  authenticated lifecycle mutations (`claim`, `heartbeat`, `submit`, `qc`, or
  `integrate`). Adding those requires resolving the credential boundary above first.
- **No heartbeat hook.** `acp heartbeat` is a write needing the claim token and the
  runner credential, so wiring it into a hook means deciding how a secret reaches a hook
  process. Until then an expired lease surfaces as a `lease_expired` denial — loud
  rather than silent.
- **No Cursor native hook adapter.** The guard command remains runner-agnostic, but only
  Claude Code and Codex apply_patch hook configurations are implemented and tested.
