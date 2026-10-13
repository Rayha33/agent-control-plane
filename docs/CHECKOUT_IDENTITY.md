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

For a task intended to write through this adapter:

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
typed operation, not pass arbitrary model-generated shell text.

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

The current Claude Code hook integration still mediates only its documented structured
Edit/Write/MultiEdit/NotebookEdit targets in the attempt worktree. It does not route
those hooks through `CheckoutWriteLease` yet. Bash, direct Git commands, native editor
patches that bypass the hook, other MCP/file APIs, direct filesystem writes, and tools
that do not use this adapter remain unmediated. Consequently this prototype does not
claim general protection against two sessions that ignore the adapter.

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
