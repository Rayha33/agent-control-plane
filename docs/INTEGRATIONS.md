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

- **The MCP server is read-only today.** `acp mcp-serve` is shipped and exposes
  ten read-only tools, including `acp_plan` and `acp_guard`; it does not expose the
  authenticated lifecycle mutations (`claim`, `heartbeat`, `submit`, `qc`, or
  `integrate`). Adding those requires resolving the credential boundary above first.
- **No heartbeat hook.** `acp heartbeat` is a write needing the claim token and the
  runner credential, so wiring it into a hook means deciding how a secret reaches a hook
  process. Until then an expired lease surfaces as a `lease_expired` denial — loud
  rather than silent.
- **No Cursor native hook adapter.** The guard command remains runner-agnostic, but only
  Claude Code and Codex apply_patch hook configurations are implemented and tested.
