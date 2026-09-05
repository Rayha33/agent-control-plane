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

### What this does not do yet

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
