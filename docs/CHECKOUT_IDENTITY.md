# Checkout identity and mediated write adapter

Status: opt-in prototype. This provides an opaque checkout resource key and a
cooperative Python write gate. It is not a filesystem sandbox and does not protect
operations that bypass the adapter.

## Identity

Run `acp --repo /path/to/checkout checkout-resource`. The command is read-only and
prints an opaque `checkout:v1:...` resource value. It does not initialize ACP state or
modify Git metadata.

The key is derived from Git's resolved common directory and per-worktree Git directory,
then from their filesystem device/inode pairs. It does not hash a path string. A symlink
alias resolves to the same key; renaming a checkout or linked worktree on the same
filesystem preserves the relevant directory identities. Linked worktrees have distinct
checkout IDs; clones have distinct repository IDs. The helper fails closed if Git or
the filesystem cannot provide the required identity evidence.

This is a local-filesystem identity, not a portable repository UUID. A cross-device
move, copy, clone, filesystem restore, or filesystem with unstable inode semantics may
produce a different key. Do not use this as cross-host identity for a shared network
filesystem; its lock and inode semantics must be independently qualified first.

## Opt-in coordination contract

For a same-host integration that does not have a shared coordinator, use the built-in
local backend:

```python
from agent_control_plane.checkout_identity import CheckoutWriteLease

with CheckoutWriteLease.local(checkout_path) as lease:
    lease.run("write", lambda: typed_editor_write(...))
```

For a path-specific editor adapter, bind each write to an explicit target and use
the canonical path supplied to the callback:

```python
with CheckoutWriteLease.local(checkout_path) as lease:
    lease.run_write("src/module.py", lambda target: typed_editor_write(target, patch))
```

Relative targets resolve from the leased checkout root, not the process cwd. Before
recording a pending operation, ACP resolves symlinks, checks the nearest existing
directory's Git worktree identity, and verifies the filesystem device of the existing
target (when present) or its nearest existing ancestor. It refuses a missing path
whose existing parent is not a directory, the checkout root, an external path, a
nested/different worktree, or a different-device crossing. The callback receives the
canonical absolute path. A typed adapter must actually use that supplied path; the
lease cannot stop a callback from ignoring it, and it does not contain hard-link
aliases, same-device mount aliases (including bind mounts), or other direct filesystem
writers.

It combines the per-worktree Git-directory lock with a monotonically increasing,
0600 fencing-token record in that worktree's Git metadata. It is usable across
cooperating processes on the same local filesystem, including after a process restart.
It does not coordinate separate clones, other hosts, or independent copies of the
repository. Those require callbacks backed by the same authoritative coordinator; a
local token must never be described as a distributed lease.

To serialize whole same-host agent sessions without writing a custom launcher, use the
CLI wrapper:

```bash
acp --repo /path/to/checkout checkout-exec -- claude
```

The advisory lock is held while the foreground child runs. A zero exit clears the
recovery marker; a nonzero exit returns that status and leaves the marker pending. The
foreground child inherits the checkout-lock file descriptor. If the wrapper is
interrupted or killed, its descriptor closes but the child retains the lock while it is
alive, so cooperating invocations fail with `checkout_busy`. The durable pending marker
also remains; after the child exits, cooperating invocations fail with
`checkout_recovery_required` until the worktree is inspected and the exact marker is
resolved as described below. Forced termination of the wrapper does not guarantee that
its descendants stopped: confirm the agent process tree has stopped and the worktree is
safe before resolving the marker. Use separate ACP attempt worktrees when agents should
run in parallel.

This wraps one foreground agent process, not each native editor write, and is not an OS
sandbox. The agent command must not daemonize or leave background writers behind after
the foreground process exits. Commands that bypass the wrapper, write outside the
selected checkout, close the inherited lock descriptor, or leave writers that do not
inherit it running are outside this lock's guarantee.

For a multi-host or centrally coordinated integration:

1. Compute the checkout resource key and include it in the Coordination API task's
   `resources` list along with any other resources.
2. Construct `CheckoutWriteLease` with callbacks that claim, validate, and release
   that exact durable resource lease using the Coordination API. The adapter takes its
   local OS lock first, then calls `acquire_fence(resource)`. The callback must return
   the positive fencing token issued by the authoritative coordinator.
3. Pass each write-capable operation as a callback to `lease.run(...)`. The adapter
   rechecks checkout identity and the current fencing token immediately before
   invoking each callback. Keep one context open for the write-capable session.

The durable task resource lease serializes compliant claims; the per-worktree Git
directory lock serializes cooperating adapter instances across processes, and a
per-instance mutex also serializes concurrent calls from threads. Fencing makes an old
adapter fail its next operation after its token is superseded. A new adapter must get
the local lock before asking the coordinator for authority. Callers that claim or write
outside this ordering are outside the guarantee. If acquisition rollback cannot release
a valid remote token, or acquisition fails after a possible coordinator-side claim, the
raised error records that it may remain held until coordinator expiry; an invalid token
response is likewise treated as an unknown remote lease.

## Exact mediation boundary

`CheckoutWriteLease.run` mediates only the callback passed to it for one of these
operation labels: `write`, `attach`, `switch`, `sync`, or `cleanup`. It does not parse
or constrain shell commands inside a callback; integrations should call a narrow,
typed operation, not pass arbitrary model-generated shell text. `run_write(target,
callback)` is the target-bound path-specific form: it resolves and checks the target
before the pending marker or callback begins, then supplies that canonical path to
the callback. It improves adapter correctness when the caller honors the supplied
path; it does not make a native editor or patch API use ACP unless that API is
actually routed through this method.

The adapter is opt-in. For Claude Code, install its structured editor hooks in
checkout-fence-required mode and start the session through the wrapper:

```bash
acp --repo /path/to/checkout hooks install --claude-code --require-checkout-exec
acp --repo /path/to/checkout checkout-exec -- claude
```

In this mode, `checkout-exec` holds the checkout lease for the foreground Claude Code
process and passes its resource and fencing token to that process. The synchronous
`PreToolUse` guard verifies that the matching pending write marker itself is still
locked by the active session before allowing a structured editor write; an unrelated
checkout lock is not sufficient. A session started without the wrapper and without a
matching token fails closed for those tools. This cooperative
check does not authenticate process ancestry: another same-user process that can read
the marker can copy its token while the wrapper's lock is active. The hook itself does
not own or release the lock; the wrapper covers the whole session, including tool
execution and permission prompts. This is session-level same-host serialization, not a
per-file or distributed lease. The default hook installation remains path-only and
does not imply checkout serialization.

This design follows Claude Code's documented lifecycle: `PreToolUse` runs before a tool
call, `PostToolUse` only runs after success, and `PostToolUseFailure` does not run for
permission denials. A command hook is therefore not a reliable acquire/action/release
wrapper by itself; the enclosing `checkout-exec` process owns the lock instead. See the
[Claude Code hooks reference](https://code.claude.com/docs/en/hooks).

`attach`, `switch`, `sync`, and `cleanup` are replacement/destructive categories. They
run only when Git reports no tracked changes, untracked files, or ignored files. If Git
cannot establish that state, the adapter refuses. It also rejects tracked paths marked
`assume-unchanged` or `skip-worktree`, which can otherwise hide worktree edits from a
normal Git status check. It overrides local settings that suppress executable/symlink
mode and case checks, filesystem monitoring, or the untracked cache for this cleanliness
check. This is refusal, not automatic stash, reset, or recovery. If a callback fails or
is interrupted, the adapter never retries or cleans up on its own; inspect the checkout
before the next destructive operation.

Repositories with registered submodules are currently refused for these operations.
Git's local submodule-ignore settings can hide dirty nested worktrees; recursive
submodule cleanliness has not yet been implemented.

## Interrupted-operation recovery

Before every mediated callback, the adapter creates and synchronizes a per-worktree
pending marker in Git's common directory. After the callback returns and the checkout
identity is revalidated, it synchronizes a completed state to that marker before removing
it. If the process exits during a callback or completion cannot be synchronized, the
marker remains. A new adapter refuses before acquiring a coordinator fence, including for
ordinary `write` operations; it never assumes that a partial write is safe to continue.
If directory synchronization fails after the marker is unlinked, the callback result is
still reported as successful because its completed state was already synchronized. A
crash may restore the marker, which conservatively blocks the next owner.
This detects process interruption; it is not a transaction over arbitrary callback
outputs and does not establish power-loss durability for worktree files. Callbacks remain
responsible for synchronizing their own data when that guarantee is required.

The marker is named `.acp-checkout-<checkout_id>.pending`. Inspect and preserve or recover
the worktree contents first. Remove that exact marker manually only after the checkout is
safe to resume. ACP does not automatically discard, stash, reset, or replay interrupted
work. A cleanup operation that removes the entire common Git directory leaves no
checkout to resume; subsequent identity resolution fails closed.

The Claude Code hook integration can check structured Edit/Write/MultiEdit/NotebookEdit
targets against the attempt write set and, when explicitly configured, require the
session-level `checkout-exec` token and active marker lock. This remains cooperative,
not an authentication boundary between same-user processes. Bash, direct Git commands,
native editor patches that bypass the hook, other MCP/file APIs, direct filesystem
writes, tools that do not use this adapter, and agents that ignore the wrapper remain
outside this guarantee.
Consequently this prototype does not claim general protection against unmediated writers.

## Limits

- The write lease currently requires POSIX `flock`; unsupported platforms fail closed.
- The advisory lock is held on the per-worktree Git metadata directory inode; the
  metadata directory must be owned by the current user and not group/world-writable.
  This avoids a separate lock-file pathname being unlinked and recreated into a second
  lock domain. Advisory locks remain cooperative and local-filesystem-only.
- Callbacks are synchronous and Python-local. This release does not ship a built-in
  Coordination HTTP callback implementation or automatically install this adapter in
  an editor.
- There is no cross-host/network-filesystem guarantee, no attempt to salvage partial
  writes, and no claim that advisory editor hooks are an OS sandbox.
