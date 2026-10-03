# Worker result object staging and retention

ACP builds imported worker results from the host-validated snapshot and change set. It does
not trust the worker's Git index, refs, object IDs, configuration, or hooks.

## Write protocol

Each import has a deterministic ID derived from its attempt ID, claim token, and result
digest. Before constructing the tree, ACP creates a private object database at
`<state-dir>/result-import-staging/<import-id>/objects`. That database may read the
repository's common object database as an alternate, but candidate blobs, trees, and the
host-authored commit are written to the private store. Candidate tree traversal records the
exact sorted tree/blob/commit object-ID inventory.

ACP flushes the staged objects, then commits a `prepared` `result_imports` row before any
candidate object is promoted to the repository object database. The row binds the attempt,
claim token, result digest, candidate tree and commit, exact object inventory, exact IDs
missing from the shared database at preparation time, worker PID, kernel-start identity,
and the supervisor's successful process-exit receipt. A hash-chained event binds the
same import identity plus digests of both the full candidate inventory and the exact
promotion inventory. Cleanup validates the intact event chain and both digests before
trusting any object ID from an ambiguous journal.

Recovery rechecks the deterministic import/ref identity, active claim fence, worker PID and
kernel-start identity, exit receipt, clean base worktree, staged tree closure, and
deterministic commit before promotion. Each missing loose object is verified and installed
at its exact fanout path via an atomic same-directory link. POSIX fanout access uses
no-follow directory handles. The object file and containing directory are flushed before
ref publication. The promotion temporary name
includes the import ID and object ID, so recovery can safely remove an incomplete copy and
retry. Only after all objects are readable does ACP publish the absent-only immutable result
ref and advance the journal. Submission remains governed by the existing claim-fenced
submission transaction.

| Stop point | Durable state | Recovery behavior |
| --- | --- | --- |
| Blob/tree/commit staging, before journal commit | Private unjournaled directory only | No journal means no recovery or submission. The next import/recovery removes the exact unjournaled directory before reuse. |
| Journal committed, before promotion | `prepared` row plus private object inventory | Revalidate the exact worker/claim receipt, then promote the listed missing objects. |
| During object promotion | `prepared` row; some exact loose objects may exist | Verify already-present objects, retry the remaining IDs, and continue. An invalidated claim becomes `ambiguous`, never submitted. |
| Ref published, before phase/submission commit | Journal plus immutable ref and promoted objects | Recovery accepts only the journaled commit at the canonical ref, then completes the existing submission flow. |

Identical retries resolve to the same deterministic import ID and return the existing
submission. A later claim has a different fencing token and therefore cannot adopt an
unjournaled stage or an older result.

## Bounded staging and cleanup

Private staging is capped at 512 MiB per import and 2 GiB across the state directory. The
existing result snapshot contract caps uncompressed file content at 256 MiB. ACP checks
the stage size before journaling; when capacity is exhausted it fails closed and does not
promote objects. Stages are reconciled under the repository Git-operation lock before new
imports and during recovery.

Cleanup removes only direct UUID-named directories in ACP's private staging root when no
matching journal exists or the journal is terminal (`ref_published`, `submitted`, or
`ambiguous`). For ambiguous imports, ACP may unlink only the exact loose object paths named
by that row's `promote_object_ids_json` after proving this list is a subset of the
event-authenticated candidate inventory; it first protects objects named by every non-
ambiguous import and computes reachability from all refs and reflogs, every registered
worktree HEAD, and every registered worktree index. If any reachability input is unreadable,
object cleanup is skipped. Packed objects, unrelated loose objects, refs, indexes, worktrees,
and user files are never removed. ACP does not run repository-wide `git gc`, `git prune`, or
`repack` as result-import cleanup.

The Git-operation lock serializes ACP imports, recovery, and supported ACP ref/index writes.
The unreachable-object proof assumes no concurrent out-of-band Git client mutates refs,
worktrees, or indexes during cleanup. Integrations that permit direct Git writes must
coordinate them with ACP or disable automatic ambiguous-object deletion; Git clients do not
honor ACP's lock by themselves.

Pre-v13 journals have empty staging provenance and retain their existing shared-object
recovery behavior. Unjournaled shared objects left by an older binary have no ACP-owned
inventory; this change does not guess their provenance or remove them. They require a
separate read-only reachability audit before any cleanup.
