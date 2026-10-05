# Per-attempt worker sandbox decision

**Status:** proposed end-to-end architecture. Standalone bounded snapshot and
change-set primitives, exact host-side manifest replay validation, secure
snapshot readback, an isolated-index candidate-tree builder, and a claim-fenced
result-import journal/recovery path are implemented. The import API consumes
host-captured `Snapshot` and `ChangeSet` objects; it is not wired into a worker
executor, CLI transport, or the existing `run_worker` path. It writes a
deterministic host-authored commit to an immutable per-attempt ref in
`refs/acp/worker-results/`, then uses ACP's ordinary submission checks. It does
not mutate the registered attempt worktree or its real index. Its write-ahead
record binds the attempt ID, claim token, worker PID plus kernel start identity,
successful supervisor `Popen.wait` audit receipt, base/tree and result digests.
It does not use the namespace runtime's systemd unit ID as worker identity.
Recovery adopts only the exact journaled commit/ref; a stale claim, missing
object, or conflicting ref remains fenced as ambiguous. Candidate objects are
constructed in bounded per-import private object stores; the prepared journal
commits before ACP promotes exact object IDs into the common repository store.
Unjournaled private stages and ambiguous promotions have scoped reconciliation;
committed result refs remain retained pending a separate retention policy, and
ACP does not run repository-wide GC. See
[`RESULT_IMPORT_OBJECTS.md`](RESULT_IMPORT_OBJECTS.md) for the current staging,
retention, and cleanup contract. End-to-end worker isolation proof remains
incomplete. The OCI policy compiler now stages init behind an inherited pipe
descriptor, but no supervisor executor passes or releases that descriptor. This
record does not authorize `externalSandbox` for ACP workers.

**Descriptor transport primitive (2026-10-04; not integrated).** The trusted
process trampoline now accepts an internal `fd3_source` and maps that open
descriptor to fd 3 only in the command child, after ACP records the target PID
identity and releases its existing start gate. When the source is distinct from
fd 3, the child closes the original source descriptor after remapping; if the
source is already fd 3, it keeps that descriptor inheritable. The monitor
parent closes its duplicate. A behavioral test verifies fd-3 delivery, no
source-descriptor leak, and closure of the monitor's duplicate. When remapping a
different descriptor, fd 3 and the source are reserved and cannot also be
requested through `pass_fds`. This remains process plumbing, not an executor:
the existing `run_worker` path does not launch runc, `_run_process` is
synchronous, and no code reads back runtime state before releasing the OCI init
gate. It proves no namespace, mount, credential, egress, cancellation, or
result-import property.

**Private Git bootstrap policy (compiler only; not integrated).** The OCI
policy compiler now has an opt-in `private_git` mode for a rootfs that includes
Git. Its fixed PID-1 script waits on the inherited launch gate, then initializes
a new repository inside the mutable `/workspace` before starting the candidate
command. It disables system/global Git config and system attributes, disables
terminal prompts and hooks, and passes an explicitly empty template directory
on the attempt's private `/tmp` tmpfs so Git's installed or user-selected
templates cannot seed refs, alternates, hooks, or config. Before candidate exec,
the script rejects unexpected alternates, remotes, refs, or baseline history and
creates one fresh input-snapshot commit without host repository history. The
host snapshot is copied without `.git`; after execution, result capture ignores
only the root `.git` entry and derives changes from captured file bytes, never
from worker Git metadata. This does not yet provide an execution route: no
supervisor passes or releases fd 3, and configured `run_worker` remains
fail-closed. The private repository is untrusted worker state, not a submission
receipt or authorization source.

The namespace runtime probe records a validated
`systemd_unit_invocation_id` in its runtime-driver evidence and append-only
runtime audit event when systemd provides one, so a later teardown sample cannot
erase the setup identity. This is the identity of the runtime driver's transient
unit only: the current supervised worker launcher still uses a direct
process/trampoline path, and no evidence shows that worker is executing inside
that unit. Do not use this runtime-unit ID as a worker fence or result-import
receipt until the executor binds the worker to that exact unit and persists the
binding.

The replay helper reconstructs and compares the complete result manifest;
directory changes are represented so empty directories affect the result
digest. The candidate-tree builder takes that validated delta plus the baseline
snapshot, verifies the snapshot again with no-follow descriptor-relative reads,
binds the operation to the exact current base commit, and rejects any snapshot
whose tracked paths, modes, blob bytes, or directory shape differ from that Git
tree (including ignored or untracked local files). It hashes host-generated
blob bytes with Git filters disabled and uses a temporary `GIT_INDEX_FILE` to
create a candidate tree. Git 2.32 or newer is required so the command-scope
configuration isolation is honored; split-index and other repo-local side
effects are disabled, and base-tree enumeration is bounded by snapshot entry
and path limits. It ignores empty directories, as Git trees do. It does not
import the tree into a registered worktree, create a commit, or journal/recover
a crash. A newly created parent directory may inherit
authorization only from a directly authorized changed leaf below it; a removed
directory may inherit it only when every removed descendant leaf is directly
authorized. Standalone empty-directory changes require an explicit write-set
grant.

## Decision

Build an opt-in `SandboxedWorkerExecutor` as a separate supervised-worker
execution backend. Do not treat `NamespaceRuntimeDriver` as the worker sandbox
and do not put a worker command inside its current resource-driver lifecycle.
Keep the direct execution backend and routing unchanged apart from the bounded
host-log capture described below until the new backend passes the gates; an
unsupported or partially configured sandbox must fail before candidate code
starts.

The existing worker lifecycle registers a host PID and process identity,
launches `worker_trampoline.py` directly with the registered worktree as its
cwd, and submits a committed worktree through ACP's existing checks. The
namespace resource driver instead launches a transient systemd service, builds
a private root, and binds `ACP_WORKTREE` read-only at `/workspace`. It has
separate setup/probe/teardown semantics; it does not own the registered worker
PID, cancellation, or recovery lifecycle. A `systemd-run` client PID is not a
durable identity for the service it started.

The direct worker's host-log capture is now bounded separately from sandboxing:
`run_worker` gives the trampoline a parent-drained stdout/stderr pipe rather
than the open host log descriptor. The candidate sees a pipe, not that log
descriptor. ACP caps each attempt log at 8 MiB across retries, reserves space
for a truncation marker, drains and discards output beyond the cap, and refuses
launch before process reservation when existing bytes leave insufficient room
for the marker. Exact-head CI for code commit `aa1e03a` (run
[`37154338869`](https://github.com/Rayha33/agent-control-plane/actions/runs/37154338869))
passed Ubuntu/macOS × Python 3.11/3.12; Ubuntu executed the Linux-only output
and retry-cap cases. This proves bounded capture and removes the inherited log
descriptor capability only. It does not prove that a candidate cannot open the
host log path or other host paths, and it is not filesystem read isolation.

Codex App Server `externalSandbox` is a delegation mode: Codex skips its own
command sandbox. It is safe only after ACP has proved that every untrusted
command path is already inside the outer boundary. It creates no namespace,
mount policy, network filter, or worker lifecycle control by itself.

### Provider and executor boundary

The current official Codex integration paths are distinct and neither proves
ACP's worker boundary:

- App Server is the rich-client protocol; its `command/exec` runs under the
  server's sandbox, while `externalSandbox` tells Codex to skip that command
  sandbox because an outer boundary is already in force. If ACP uses App Server
  later, its process still has to run inside the independently enforced
  per-attempt sandbox. Keep its control transport local (stdio or Unix socket);
  the documented WebSocket listener is experimental and unsupported for
  production. See [Codex App Server](https://learn.chatgpt.com/docs/app-server).
- The Agents API self-hosted-environment path instead keeps OpenAI's harness
  outside and runs `codex exec-server` in the supplied environment. The
  executor receives a separate environment key as `CODEX_API_KEY`; generated
  code can read that key, but it can only connect environments, while the
  application's API key stays outside. This is a useful least-privilege
  reference, not a drop-in replacement for ACP's current local CLI worker: it
  changes the harness/protocol and requires the Agents API. See [Self-hosted
  sandboxes](https://developers.openai.com/api/docs/guides/agents-api/environments/self-hosted).
- Running a command with Codex's sandbox bypass inside a container is only as
  safe as the container mounts and credentials. OpenAI's security guide warns
  that untrusted code can exfiltrate credentials available inside the
  container. Do not mount a user's home or Codex authentication state as a
  shortcut; the future provider adapter needs a separately scoped credential
  or trusted credential broker plus enforced egress. See [Agent approvals &
  security](https://learn.chatgpt.com/docs/agent-approvals-security).

The architecture choice remains a provider-neutral `SandboxedWorkerExecutor`
owned by ACP, separate from `NamespaceRuntimeDriver`'s resource lifecycle. The
first OS-boundary proof should use a registered no-model fake worker; each
provider adapter must then prove its own auth and egress contract before launch
is enabled. No provider adapter or `externalSandbox` opt-in is selected yet.

## Threat model

Assume the worker command, model-generated scripts, project files, symlinks,
Git metadata supplied by the worker, and output manifest are hostile. The worker
must not read or modify the host checkout, sibling attempts, other projects,
host home/configuration, host temporary directories, credentials not explicitly
granted, the supervisor database, or host Unix sockets. It must not persist
processes after cancellation, forge a successful completion receipt, or cause
unvalidated output to enter ACP's QC/submission path.

The boundary does not defend against a kernel/systemd vulnerability, a
compromised host administrator, or deliberate access to a provider beyond the
explicitly granted proxy capability. These are residual host/provider trust
assumptions, not properties proved by a namespace test.

## Proposed execution contract

1. **Snapshot before launch.** Under the attempt's existing fencing and Git
   operation guards, materialize an attempt-specific input tree. Copy regular
   files (never hard-link), preserve executable bits, preserve but do not follow
   symlinks, and reject devices, sockets, FIFOs, path traversal, and special
   files. Exclude the registered root `.git` file/directory and reject nested
   `.git` administration, including linked-worktree and submodule gitfiles that
   can point into `.git/modules`. The first version rejects submodules rather
   than reading their host-side metadata. Record a canonical, bounded baseline
   manifest before authorizing the worker.
2. **Private Git state.** If the coding CLI needs Git, initialize a repository
   wholly inside the private attempt root with an isolated `HOME`, empty hooks,
   scrubbed system/global config, and no alternates, shared object directory,
   worktree pointer, credential helper, or host repository path. A private
   sandbox commit is input convenience, not submission authority. The current
   OCI compiler's opt-in post-gate bootstrap implements this Git policy inside
   `/workspace`; it is not yet connected to the supervisor's `run_worker`
   lifecycle or result-import route.
3. **Proposed OS-owned lifecycle (partial composition evidence; ACP integration
   unproven).** The feasibility
   result makes a rootless OCI boundary the leading model/provider-independent
   candidate; this initial engine adapter is runc-specific until another OCI
   runtime is tested. The probe does not qualify the architecture. Construct
   one trusted OCI bundle per attempt/fencing epoch: readonly rootfs from an
   audited executable/library closure, minimal
   generated non-secret `/etc`, private `/proc`, bounded tmpfs `/tmp`, one
   writable attempt bind, and a host-controlled launch gate. Never bind the
   whole host `/etc` or broad `/usr`: readonly mounts still disclose readable
   files. The existing resource driver broadly binds both and is not suitable
   unchanged for workers. Test that host `/etc` sentinels and all other
   ungranted paths are absent.

   The bundle model follows the [OCI Runtime Specification v1.2.1](https://github.com/opencontainers/runtime-spec/blob/v1.2.1/config.md)
   and its [Linux-specific extensions](https://github.com/opencontainers/runtime-spec/blob/v1.2.1/config-linux.md);
   rootless cgroup delegation constraints for the tested runtime are described
   in the [runc 1.3.5 cgroup v2 guide](https://github.com/opencontainers/runc/blob/v1.3.5/docs/cgroup-v2.md).
   These specifications describe runtime configuration, not ACP integration
   proof.

   Cgroup ownership is measured to differ from the initial wrapper-only
   proposal. With rootless runc's default cgroup driver, the container init
   landed in a sibling cgroup outside the transient service's `ControlGroup`;
   stopping that service left the container running. Do not rely on the
   wrapper's `KillMode=control-group` to own or stop the OCI process tree.
   With `runc --systemd-cgroup` and
   `linux.cgroupsPath=user.slice:acp:<container-id>`, runc created a unique
   `acp-<container-id>.scope`. In the bounded probe, the host init PID's
   `/proc/<pid>/cgroup` exactly matched that scope's `ControlGroup`; the
   wrapper service and container scope had distinct `InvocationID` values.
   The runc systemd driver documents the `slice:prefix:name` form and rootless
   placement under `user.slice` ([runc 1.3.5 systemd cgroup driver](https://github.com/opencontainers/runc/blob/v1.3.5/docs/systemd.md),
   [runc 1.3.5 rootless cgroup v2 guide](https://github.com/opencontainers/runc/blob/v1.3.5/docs/cgroup-v2.md)).

   This probe measured cgroup placement and signal/stop behavior only. It did
   not inspect which resource controllers were delegated or configure, read
   back, or test any CPU, memory, process-count, or I/O limit. Rootless runc
   commonly receives only the `memory` and `pids` controllers by default, so
   controller availability must be measured on each supported host; it cannot
   be inferred from scope creation or process placement ([runc 1.3.5 cgroup v2
   guide](https://github.com/opencontainers/runc/blob/v1.3.5/docs/cgroup-v2.md)).
   Before releasing the launch gate, integration must preflight every product-
   required controller and delegation, apply each configured limit, read it
   back from the exact attempt cgroup, and fail closed if a requested limit is
   unavailable or differs. No resource quota is proven by this composition
   probe.

   **Executor lifecycle contract (gate compiler implemented; executor not
   integrated).** Keep runc attached in the foreground with `runc
   --systemd-cgroup --root <state-root> run --bundle <bundle-path> --keep
   --pid-file <host-only-pid-file> --preserve-fds 1 <container-id>`. The
   explicit bundle path avoids relying on runc's current-working-directory
   default. The OCI policy compiler requires a real `/bin/sh` in the audited
   rootfs and places a fixed shell trampoline at PID 1. It blocks reading fd 3,
   exits 125 on EOF, closes fd 3, then `exec`s the candidate's original argv
   without interpolating it into shell source. Runc's `--preserve-fds` option
   passes extra descriptors after stdio and any `LISTEN_FDS` descriptors ([runc
   1.3.5 run manual](https://github.com/opencontainers/runc/blob/v1.3.5/man/runc-run.8.md)).
   The future executor must sanitize activation variables, map exactly the
   launch-pipe read end to fd 3, pass only that descriptor, and keep its paired
   writer private. It may write a newline-terminated release value and close
   the writer only after matching `runc state` to the host PID, checking its
   start identity and exact cgroup/scope, persisting the journal, and
   revalidating the attempt fence. No executor
   currently maps, passes, or releases this descriptor, so the compiler output
   is not yet a worker launch route. `runc run --keep` preserves stopped
   state/cgroup for post-exit inspection and requires a later manual
   `runc delete`; the pid file identifies the initial container process. The
   `runc` client PID, ACP's supervisor/monitor PID, and container-init PID are
   distinct identities and must not be substituted for one another. Before
   releasing the inner gate, the supervisor must match the pid file against
   `runc state`, sample the host PID/start-time identity, and verify that PID's
   cgroup matches the exact per-attempt scope. The durable write-ahead
   execution record must bind the attempt/fencing epoch to the ACP monitor
   PID/start identity, runc-client PID/start identity, container-init PID/start
   identity, container ID, state root, bundle/image digests, runtime version,
   wrapper service unit name and InvocationID, container scope unit name and
   InvocationID, and exact cgroup path. These are separate identities; existing
   direct-worker receipts alone do not constitute this OCI execution record.
   Revalidate the claim/fencing token before gate release. Any missing or
   conflicting value fails closed with the gate held. The attached `runc run`
   completion supplies the candidate exit status; cancellation and restart
   recovery must target the recorded exact scope/container, not just the wrapper process
   group. Keep the execution fence until the runtime reports stopped, exact
   `runc delete` succeeds, the ID is absent from the configured state root,
   the recorded container-init PID/start identity is absent, and the exact
   scope/cgroup is gone. Independently persist the attached runc client's wait
   result and prove that client has been reaped. The ACP monitor may remain
   alive while it coordinates cleanup; its parent must reap it with
   `Popen.wait()`, persist the matching hash-chained `worker.exited` monitor
   receipt (`observed_by=supervisor_popen_wait`), and only then release the
   attempt fence. That receipt does not replace the separate runc-client wait
   result or container-init absence proof. Never use monitor absence as a
   substitute for container-init absence.
   Unknown cleanup state retains the fence. This protocol is derived from the
   [runc 1.3.5 `run` manual](https://github.com/opencontainers/runc/blob/v1.3.5/man/runc-run.8.md)
   and [systemd cgroup driver](https://github.com/opencontainers/runc/blob/v1.3.5/docs/systemd.md),
   plus the bounded NAS fixture above; it is an implementation contract, not
   proof that ACP currently performs these steps.

### Trusted runc pin and version-probe slices (2026-10-04)

`build_runc_run_argv` now requires a process-local sealed handle minted by
`_pin_trusted_runc_executable`; a raw path, caller-constructed handle, or
modified handle is rejected. Pinning uses the trusted-executable path/parent
checks, requires a root-owned non-group/world-writable regular file, hashes it
through a no-follow descriptor, records its canonical path and file identity
(device, inode, size, owner, mode, mtime, ctime), and repeats those checks
before building argv. It also checks effective-ID write access to the binary
and every parent directory, failing closed if the platform cannot perform that
check; this covers ACL grants that mode bits do not show. Regression tests
cover untrusted paths, forged or modified handles, simulated ACL write grants,
and a simulated changed binary identity.

The same opt-in configuration now requires an operator-selected
`rootfs_path`, `rootfs_sha256`, and `rootfs_closure_sha256`. Generate both on
the target Linux host against the final provisioned rootfs. The tree digest
includes host UID/GID metadata, so values generated on macOS or before
copying/chowning the image may differ. Generate the review artifact with:

```sh
uv run acp oci-rootfs-manifest --rootfs /absolute/path/to/rootfs
```

The command prints a deterministic filesystem inventory: relative path, type,
mode, UID/GID, size, and either a regular-file content SHA-256 or the literal
symlink target and its hash. It never prints regular-file contents. Review the
`entries` list to identify every path available in the rootfs; it is not a
runtime library/dependency resolver. Inspect the bytes of generated `etc/`
configuration separately through the trusted image-build/audit process to
establish that it is minimal and non-secret. Then copy `rootfs_sha256` and
`closure_sha256` into `[sandbox.oci]` as `rootfs_sha256` and
`rootfs_closure_sha256`. The closure digest binds the schema and complete
ordered filesystem inventory, and configuration load recomputes both pins from
the same secure scan. A missing, malformed, or mismatched closure pin fails
closed. The manifest makes paths and hashes reviewable and repeatable; it does
not prove vendor provenance, that a human audit was good, or that `etc/`
content is non-secret. The output may be large and path names can be sensitive,
so generate and handle it only for an operator-selected rootfs.

The version-1 tree digest binds relative paths, entry types, mode bits, UID/GID,
regular-file contents, and symlink targets. Linux POSIX access/default ACLs
are rejected so they cannot silently add permission grants. Nested Linux mounts
are checked using `/proc/self/mountinfo` (including same-device bind mounts), with
mount-table snapshots required to match before and after the scan. The verifier
also rejects special files, cross-device trees, hard-linked files, escaping
symlinks, set-id entries, Linux file capabilities, and trees over its fixed
entry/byte limits; directory enumeration stops before collecting an entry
beyond the global count limit. Other extended attributes and non-Linux ACL
mechanisms are not part of the digest. The configured rootfs and repository
paths must be disjoint. Configuration load seals the canonical path, the
device/inode actually opened by the scan, and both digests in a process-local
handle; verification repeats those checks before OCI config compilation and
checks that any per-attempt bundle copy has the same tree and closure digests.
This detects substitution in the fields and content bound by these pins
relative to the operator's configured values; changes only to excluded
extended attributes are not detected. It does not establish image provenance,
prove the contents are safe, make a writable source immutable, detect a
transient mount that appears and disappears between identical mount-table
snapshots, or close a concurrent writer/path-replacement race (including
same-UID writers) at a future path-based runc handoff. Use an independently
audited, controlled, read-only provisioned rootfs before enabling execution.

The optional `[sandbox.oci]` config now consumes the pin for an exact stable
release-version check. That bounded probe opens the checked inode, revalidates
the descriptor's content and file identity, and uses Linux fd-based `execve`
through the timeout guardian. Only the held executable descriptor is passed to
the probe child, then closed. Non-Linux hosts fail closed because `/dev/fd`
existence does not establish that it is executable. This removes the
path-replacement window for the configuration probe only. When `[sandbox.oci]`
is configured, `run_worker` now fails before heartbeat or process reservation
with `sandbox_executor_unavailable`; it cannot silently fall back to host
execution. The argv builder still returns a path-based command and no worker-
launch path calls it; no held descriptor spans an actual `runc run`, no runtime
path/digest is persisted in the execution journal, and no OCI enforcement is
established. These slices do not authorize launching candidate code.

### Durable execution-journal slice (2026-10-04)

Schema 14 introduced a private, per-attempt `sandbox_executions` journal. Reservation
binds the current claim token, an ACP-generated container ID, attempt-specific
bundle/state paths, the bundle and rootfs digests, and exact runc/OCI versions.
The transition contract keeps the ACP monitor, attached runc client, and
container-init PID/start identities separate, and also records the wrapper and
scope unit names plus InvocationIDs and exact cgroup path. SQLite prevents edits
to recorded reservation/runtime evidence, illegal phase jumps, and row deletion.
Supervisor lifecycle methods pair their transitions with ACP hash-chained event
entries. Direct database writes are outside the supported API and threat model;
these constraints are not a defense against a writer who can alter the database.

This slice deliberately adds no launcher, command route, OCI feature flag, or
trusted cleanup verifier. Its version-2 cleanup receipt binds the recorded
identities but labels every cleanup observation `null` and the verification
status `unverified`: no runtime readback has occurred. A new version-2 report
cannot supply positive observations. An exact persisted version-1 receipt may
replay for retry compatibility, but its historical claims remain unverified
and cannot be replaced. After schema 17, exact persisted pre-17 version-1 and
version-2 receipts may replay in their original shape; replay does not add the
new content pins or upgrade their evidence. `cleanup_reported` is therefore not
`cleanup_verified`. Existing reaper, worker-finalization, and runtime-teardown
paths refuse to release a journaled attempt until a future trusted verifier
records `cleanup_verified`.
This is only a fail-closed hold: the reaper does not stop a live container or
perform cancellation/restart recovery for this journal-only slice. Ambiguous
journal state moves the attempt to quarantine and extends its resource fences.
No application method currently writes `cleanup_verified`, so this work cannot
enable or complete an OCI worker sandbox; attempts with such journal rows remain
intentionally fenced pending separate executor, targeted-stop, recovery, and
verifier work. The legacy `attempts.pid` slot remains reserved for direct workers;
a future sandbox monitor must use a distinct journal-backed registration path.
Result import, import recovery, and submission also fail closed for a journaled
attempt unless the recorded runc exit code is zero and cleanup is independently
verified. A caller-supplied cleanup report is not sufficient; legacy attempts
without a sandbox journal retain their existing direct-worker result path.

**Durable workspace-binding slice (schema 15; still not an executor).** Before
the journal can advance from `reserved` to `launched`, ACP now requires a
version-1 binding made from two host-copier-minted, initially identical
snapshots: an immutable baseline and a separate mutable workspace. The
durable journal stores both canonical root paths and device/inode identities
plus the canonical baseline manifest and its digest. SQLite rejects launch
without the binding and prevents rewriting it after capture. A restore method
reconstructs the baseline handle after process restart from that durable row,
then reopens the exact baseline and workspace roots without following the root
symlink, checks their saved inode identities, and verifies the complete
baseline tree. After that filesystem work it revalidates the live claim,
credential, and exact persisted binding fields in a serialized transaction before returning;
any later result capture or import must still perform its own transactional
fence check. The restore step checks only the workspace root identity;
future result capture must recheck that identity and still pass the mutable
tree through `collect_changes` as hostile output. This closes the process-local
`Snapshot`-provenance gap for baseline recovery; it does not close same-UID path
races, impose an aggregate workspace disk quota, produce a worker-exit/cleanup
attestation, or enable result import. No worker launch route, trusted cleanup
verifier, or sandbox result-import route is added here, and direct-worker
behavior is unchanged. Schema 16 adds a separate non-authorizing candidate
receipt, described below. The SQLite triggers enforce ordinary journal transition
and write-once invariants; they are not an adversarial boundary against a
same-UID process with raw database-write access. A future executor must keep the
supervisor database outside the worker's mount namespace.

**Versioned result-candidate evidence (schema 16; non-authorizing).** After a
successful recorded runc-client exit and an exact `cleanup_reported` row, the
host can reopen the durable workspace binding, scan the mutable tree through
`collect_changes` against the task's current write set, and recheck the saved
workspace root device/inode. The write-once version-1 receipt binds the
attempt, claim token, execution ID, baseline and workspace paths/device/inode,
baseline manifest digest, resulting tree digest, change-set digest, the
deterministic result-import digest, the recorded runc-client wait identity, and
the digest of the cleanup report. It explicitly records `authorization: none`
and `cleanup.status: unverified`; its SHA-256 is an integrity checksum, not a
signature, independent attestation, or import authority. An identical retry is
idempotent; a changed workspace result conflicts with the stored candidate
instead of replacing it.

For journaled sandbox attempts, import, recovery, and submission require a
matching candidate receipt in addition to the existing `cleanup_verified` gate.
This schema adds no trusted cleanup verifier and no sandbox result-import route,
so a journaled candidate still cannot create or submit a result. Direct-worker
behavior remains unchanged. Same-UID raw database writers, workspace path
races, and runtime cleanup are not proved safe by this receipt.

**Runtime content-identity slice (schema 17; still not an executor).** New
execution reservations now require the configured rootfs tree digest, the
rootfs closure-manifest digest, and the trusted `runc` executable digest.
Before writing a reservation, the journal revalidates the process-local sealed
rootfs and `runc` handles and rejects any digest or runtime-version claim that
does not exactly match those configured pins.
SQLite treats all three as immutable execution identity, the hash-chained
reservation event and cleanup receipt include the closure and executable pins,
and both the journal API and database launch guard refuse to advance a row
without them. Schema-16 rows migrate with empty/unknown sentinels; reserved rows
cannot transition to launched, while already-launched rows retain their recorded
phase. Their old content identities cannot be truthfully reconstructed
retroactively. This binds later lifecycle evidence to the exact operator-pinned
filesystem inventory and runtime executable bytes, but proves neither image
provenance nor runtime policy application. No `run_worker` executor is wired,
and the configured-OCI path continues to fail before heartbeat or host fallback.

**Runtime-attestation validator and partial host collector (2026-10-04; still
no launcher).** The `sandbox_attestation` module binds bounded observations into
one typed receipt: unique-key `runc state` JSON, the private PID-file value,
before/after `/proc/<pid>/stat` samples around each process cgroup read, and
exact systemd wrapper/scope `Id`, `InvocationID`, `ActiveState`, and
`ControlGroup` properties. `collect_running_runtime_attestation` reads the PID
file itself and gathers all three live process snapshots from procfs; the
future executor must still obtain and supply the bounded runc/systemd command
outputs. The validator requires runc's container ID, bundle, running status,
state PID, and PID-file PID to match; the monitor and runc client must remain in
the wrapper cgroup, while a live, non-zombie init must remain in the exact
recorded scope cgroup. The journal accepts only a self-consistent normalized
receipt matching its durable launch identities and appends the normalized
evidence plus its digest to the hash-chained running event.

The PID reader requires the state root and parent to pass the private OCI
directory policy, rejects symlinked ancestors, and opens only a single-link
regular file with `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`. It checks owner/mode/size
and the same device, inode, and metadata before open, after open, and after the
bounded read. The executor must use a restrictive umask; group/other-writable
PID files are rejected. These path-based checks are not directory-FD-anchored,
so replacement by another process with the same UID remains outside this
helper's guarantee. Likewise, the collector reads process snapshots
sequentially: they are observations over an interval, not an atomic snapshot.
Before using this receipt as a live gate, an executor must revalidate the
identities and cgroups at the end. This is observation hardening, not an atomic
launch reservation: upstream runc 1.3.5 creates a hidden sibling PID file with
`O_EXCL` and then renames it to the requested path ([pinned implementation](https://github.com/opencontainers/runc/blob/v1.3.5/utils_linux.go#L149-L169)); Go's `os.Rename` replaces an existing non-directory target ([API contract](https://go.dev/src/os/file.go#L431-L435)).
The executor therefore needs a fresh, private state/metadata directory before
launch; pre-creating the final PID path is not a substitute.

No worker executor currently calls the collector, no gate is released, and
only synthetic runc/systemd outputs are tested. The Python receipt type and
unkeyed digest can detect accidental inconsistency only; an in-process caller
can construct a receipt and recompute its digest. They do not prove the
observations' provenance, provide a signature, or form a boundary against a
compromised supervisor process. The feature remains fail-closed and no runtime
enforcement or real-host attestation is claimed.

   **Repeat fixture and exact cleanup (2026-10-03).** A separate no-model
   rootless OCI composition run on the NAS added runtime-only evidence. The
   measured host was Debian 12,
   Linux 6.18.15, cgroup v2, runc 1.3.5 / OCI 1.2.1 and systemd 252.39. Its
   readonly rootfs contained BusyBox and its three dynamic libraries (libc,
   libresolv and the ELF loader) as its only executable/runtime-library
   closure, with an empty generated `/etc`; the OCI `config.json` SHA-256 was
   `1e715ea5ae3d0eae4a0d82f52e8536c22be6f43d6125257962ce388becbbb31a`.
   The explicit mount allowlist was readonly `/proc`, one writable fixture
   workspace, and two readonly single-file mounts for the host-controlled
   launch gate and client-PID metadata. No host `/etc`, `/usr`, home, `/run`,
   `/tmp` parent, Git metadata, or socket tree was mounted; the workspace was
   the only host writable bind. After runc setup, the private root contained
   mode-000 `/dev` placeholder files; no host `/dev` mount was present.

   The fake command wrote its expected markers only under the fixture
   workspace. It verified that `/etc/hostname`, `/etc/passwd`, representative
   home/Codex-config and D-Bus/Docker-socket paths, and a host-temp canary were
   absent; an absolute workspace symlink to that host canary was unreadable;
   writes to the readonly root and `/tmp` failed; its host runc-client PID was
   absent from container `/proc`; and `/proc/net/dev` exposed only loopback.
   While held at the launch gate, the host init PID's cgroup exactly matched
   `acp-smoke-goal-20261001-f.scope`; readback from that exact cgroup was
   `memory.max=67108864`, `pids.max=32`, and `cpu.max=100000 100000`. The host
   and container PID/network namespace inodes differed. The attached `runc
   run --keep` returned 0 after host gate release; the client PID/start-time
   and init PID/start-time were recorded separately. Afterward, `runc state`
   was stopped with PID 0; an explicit `runc delete` removed the exact ID,
   its state-root entry and systemd scope were absent, and both recorded
   process identities were absent.

   This closes the earlier probe's missing exact-delete/state-root evidence
   for this bounded fixture and proves exact quota configuration readback,
   not quota-violation enforcement. It is still not an ACP registered-worker
   test: no base/sibling-worktree comparison, actual host `/etc` sentinel,
   readonly-gate write attempt, provider credentials/egress, worker cancel or
   restart recovery, concurrent attempt, or result import/QC was exercised.
   The fixture rootfs is not an audited Codex toolchain. The worker still
   launches directly on the host; its bounded 8 MiB log capture is a separate
   existing hardening change, not filesystem isolation. Strict worker mode and
   `externalSandbox` remain disabled.

   Treat the wrapper service as the runc-client lifecycle, and the exact
   per-container scope as the container-process/cancellation target. A normal
   gated fixture wrote its expected result; the wrapper service and scope were
   both unloaded afterward. For a gated fixture with an init and child,
   sending `SIGTERM` to all processes in the exact scope did not stop it within
   the 3-second probe grace; sending `SIGKILL` to that exact scope then produced
   runc state `stopped`, removed the recorded init PID/start-time identity, and
   collected both exact units. This validates only a bounded no-model
   scope/cancel feasibility path on this host; it is not a crash/restart
   recovery test.
   Before accepting an integration, persist a write-ahead execution row and
   bind the ACP monitor PID/start identity, runc-client PID/start identity,
   host container-init PID/start identity, wrapper service unit name and
   InvocationID, container scope unit name and InvocationID, container ID,
   state root, bundle/image digests, exact cgroup path, runtime version, and
   attached runc exit receipt to the same attempt/fencing epoch. Keep the launch
   gate closed until these identities and the attempt/trust fence are durably
   checked. Cancel/recover/reap the exact scope with a finite TERM grace
   followed by KILL escalation, and positively verify stopped state, absence
   of the container-init PID/start identity, state-root ID absence, and exact
   unit/cgroup absence. Persist and reap the runc client separately. The ACP
   parent then waits for/reaps its monitor with `Popen.wait()`, records the
   hash-chained `worker.exited` monitor receipt, and only then releases the
   attempt fence. The runc-client wait status, monitor receipt, and
   container-init identity are distinct evidence; never conflate them. Any
   uncertain identity or absence retains the attempt and resource fences.
4. **Credential and network boundary.** Do not mount host home, Codex config,
   SSH agents, D-Bus sockets, or inherited provider variables. A future provider
   adapter must grant a named, short-lived credential through the existing
   credential-handle mechanism and a separate egress proxy that enforces the
   provider destination policy. Direct network access and host sockets remain
   denied. Without a supported credential/proxy configuration, refuse launch.
5. **Host-validated result transfer.** After the unit is stopped and positively
   absent, the trusted supervisor—not worker Git—walks the output tree without
   following symlinks, checks it against the baseline manifest and declared
   write set, rejects unsafe paths/types/size/count and final-tree path
   collisions, and computes changed file contents and modes. Validate every
   symlink target and every destination parent before mutating the registered
   worktree. Prefer keeping the result as a host-built commit on an immutable
   attempt ref and avoid checkout mutation entirely; if a future implementation
   materializes files, it must first persist intent and use descriptor-relative
   `openat`/`O_NOFOLLOW` writes with parent-identity checks. A post-import
   `_submit` symlink check is too late to prevent a redirected host write.
   Ignore worker `.git` state and worker-reported hashes. The import journal is
   keyed by attempt ID, claim/fencing token, the exact worker PID/start identity,
   successful supervisor exit receipt, and result digest. The systemd unit ID is
   supplemental service evidence only, never worker identity. Recovery must
   recognize the exact already-imported tree/commit, refuse replay into a later
   claim, and retain the fence on ambiguous state.

This design separates the OS containment identity from the worker's
untrusted Git metadata and from ACP's submission authority. It also changes
the current direct-PID lifecycle and requires a schema/recovery design before
implementation; a wrapper around `Popen` alone is insufficient.

## Measured host assumptions (2026-10-03)

An earlier read-only NAS inventory sample reported Debian GNU/Linux 12
(bookworm), Linux kernel 6.18.15, systemd 252.38 (`252.38-1~deb12u1`), cgroup v2 (`cgroup2fs`),
`/usr/bin/systemd-run`, `/usr/bin/unshare`, rootless `/usr/bin/runc` 1.3.5,
and delegated user namespaces. No Codex executable was found on the NAS `PATH`.
The separate repeat-fixture preflight later queried the user manager at
2026-10-03 22:00 UTC and returned `252.39-1~deb12u2` from
`systemctl --user show --property=Version --value`. These are time-separated
observations from different systemd queries; the available record does not
establish a package transition, so neither result is substituted for the
other.
The user manager reported degraded, although a transient user service, rootless
OCI run, and runc-created per-container systemd scope all worked in this
session. The wrapper-only cgroup arrangement failed ownership/cancellation
placement; do not infer fleet-wide reliability from this sample. Distro and
systemd versions were
read over SSH from `/etc/os-release` and `systemctl --version`; kernel, cgroup
filesystem, command paths, and namespace availability were queried separately.
The sanitized values and provenance are recorded in the shared #2370 task
notes/log. A local macOS suite cannot prove Linux child-subreaper behavior;
exact-head Linux CI is required. The current source-generated NAS probe
exercised the resource-driver command boundary against synthetic fixtures
only; it did not launch an installed ACP worker or Codex/App Server. See
[integration limits](INTEGRATIONS.md#outer-sandbox-status) and
[PR #40](https://github.com/Rayha33/agent-control-plane/pull/40).

### Read-only preflight recheck (2026-10-04)

A read-only SSH check around 02:47 UTC returned Linux 6.18.15 x86_64, rootless
`runc` 1.3.5 (OCI runtime spec 1.2.1), `cgroup2fs`, and
`/proc/sys/user/max_user_namespaces=62761`. The command
below succeeded, confirming those namespaces can be created for a short-lived
no-op on this host:

```sh
unshare --user --map-root-user --mount --pid --fork --ipc --uts --net /bin/true
```

Around 02:52 UTC, the user manager reported `degraded`; the only failed unit
listed by `systemctl --user --failed` was `hermes-search-lint.service`. A
uniquely named transient user service was configured with
`KillMode=control-group` and `UMask=0077`; `systemd-run --wait --collect`
reported success for `/usr/bin/true` in 146 ms. A subsequent readback returned
`LoadState=not-found`. Thus the degraded summary did not prevent this bounded
service operation. The probe did not exercise descendant termination or verify
cgroup ownership/placement.

These no-op probes establish namespace/service-manager preconditions only;
they do not test OCI mounts, cgroup-controller delegation, worker containment,
cancellation, credentials, egress, or result import.

### Rootless OCI feasibility probe (2026-10-03)

A separate disposable no-model probe on that NAS used rootless `runc` 1.3.5
(OCI runtime spec 1.2.1) and an ephemeral BusyBox rootfs copied from the host.
The bundle enabled a readonly root, empty capability sets, `noNewPrivileges`,
user/mount/PID/network/IPC/UTS/cgroup namespaces, and only four explicit mounts:
private `/proc`, a 1 MiB tmpfs `/tmp`, one writable attempt-workspace bind, and
one readonly host-controlled launch-gate file. It did not bind host `/usr`,
`/etc`, home, `/run`, or a host socket. This demonstrates that the installed
rootless runtime can realize a narrow OCI mount policy on this host; it does
not qualify the copied rootfs as a production toolchain image.

The process was observed in `running` state behind the empty gate, with the
container-init host PID/start-time identity sampled from `runc state` (not the
`runc run` client PID) and no workspace result yet. After the
host released the gate, foreground `runc run --keep` returned exit 0; the
process wrote the expected result only into the workspace and exited. Checks
also observed failed writes to the readonly root and gate, absent synthetic
host-temp/home canaries, blocked workspace-symlink escape, absent Docker
socket, distinct PID and network namespaces, and no default route. Runc then
reported `stopped` with PID 0 and the recorded process identity absent. A
separate no-model exit-23 probe returned 23 from the attached `runc run`
process; installed runc has no `runc wait` subcommand, so detached
`create`/`start` is not an established exit-receipt path here. All temporary
containers and probe files were removed.

The `runc run` process exit and the separately sampled container-init
PID/start identity are distinct observations. They were not bound to an ACP
execution record or hash-chained `worker.exited` receipt in this probe.
The probe used `runc run --keep`; the [runc 1.3.5 run manual](https://github.com/opencontainers/runc/blob/v1.3.5/man/runc-run.8.md)
says this retains the container state and cgroup until a manual `runc delete`.
The available probe note records that the temporary containers were removed,
but not the exact delete command or a post-delete state-root absence check.
Therefore the deletion mechanism is not independently reproducible from that
record and must be captured in a repeat before cleanup is treated as proven.

This composition probe did not inspect delegated cgroup controllers or set
resource limits. Rootless delegation commonly exposes only `memory` and
`pids`; the presence and enforcement of every product-required controller and
limit remain host-specific and unproven here. The integrated proof must check
the exact controller set, apply limits, and read back their effective values
before releasing the worker gate.

This is runtime feasibility evidence only, not the required registered-ACP
worker proof: it does not exercise `run_worker`, an audited rootfs/toolchain,
Codex/App Server, credentials or provider egress, ACP crash/cancel/recovery,
concurrent attempts, or the host-validated result-import path. Worker
execution remains direct-host with bounded log capture only; no filesystem
isolation is integrated, and `externalSandbox` remains disabled.

### Bounded direct-runc descriptor and isolation rerun (2026-10-04; one NAS host)

The opt-in no-model fixture was rerun from a disposable `/tmp` checkout using
the exact `tests/test_oci_worker_runtime.py` SHA-256
`69a8b60d240a89630f9482498fb16d90750850fb33b672031bb8c9736c3afdaa`. Preflight
observed uid 1000, Linux 6.18.15, rootless runc 1.3.5, active user systemd,
two user processes in D state (below the stop threshold of five), and a `/tmp`
tmpfs at 19% use. The host-provided BusyBox was 1.35.0; the copied rootfs tree
SHA-256 was
`0fd9d84bf185648243c7734df37a43ab3d3f74e50eef7526b49c1e764179b6cc`.

The generated OCI configuration requested a read-only rootfs, empty capability
sets, and `noNewPrivileges`; its configured mount destinations were only
`/proc`, `/workspace`, `/tmp`, and `/home/agent`. The run verified the specific
write and path denials below, but did not read back effective capabilities,
`NoNewPrivs`, or runtime mountinfo. Immediately before release, the exact init
PID's host-side descriptor table was read twice, bracketed before/between/after
by live PID/start-time and cgroup checks. It was stable and contained exactly
fd 0/1/2, each a pipe; no non-stdio or socket descriptor was present. The
fixture's path probes denied
the source checkout, sibling attempt, unrelated project, host home/config,
synthetic credential marker, host `/tmp` sentinel, host `/etc/os-release`, and
absolute/relative symlink escapes. It also confirmed the assigned workspace,
private tmpfs, and private home were writable. The candidate-visible interfaces
were only `lo`, no default route was present, the host-NIC connection probe
returned 1, and the test-owned host listener was not reached.

The exact attempt scope was
`acp-acp-live-b59dfca6b2e6415387c3f52e1fc61300.scope`; its cgroup readbacks
were `memory.max=134217728`, `pids.max=16`, and `cpu.max=50000 100000`. The
test completed with exit 0 after exact-ID runtime teardown and verified the
container PID/start identity, state, cgroup, and systemd scope absent; an
independent postflight also found no matching process/scope or checkout write
canary. This rerun supplies the explicit cleanup evidence missing from the
earlier feasibility note.

The second workspace-file marker only synchronizes this fixed BusyBox fixture;
because the worker-writable workspace contains it, hostile candidate code could
release itself. This is not a host-owned gate for an arbitrary worker. The
test still launches direct `runc` from a no-model harness, not the registered
supervised worker executor. It does not prove Codex/App Server authentication,
real-provider egress, generated-diff transfer, worker cancellation/crash
recovery, or complete task #2370 acceptance. The feature remains unintegrated
and `externalSandbox` remains disabled.

### Host-side effective privilege and mount readback (2026-10-05; one NAS host)

The same opt-in, no-model direct-runc fixture was extended to inspect the
running init through host procfs while the trusted fd-3 launcher was still
blocked, before candidate code ran. Exact test-source SHA-256:
`5869d7785595576c28a9d402cc7e5f968d29ab16d878e69a178d94ed47586313`; the
unchanged `oci_worker.py` source matched SHA-256
`de4493632ced1877b6aee6e28d5b385b73a448a7de20d19f252a3f9f09b2ae10`. The
host brackets the `/proc/<pid>/status` and `/proc/<pid>/mountinfo` reads with
live PID/start-time/cgroup snapshots and requires the exact previously recorded
identity.

On uid 1000, Linux 6.18.15, rootless runc 1.3.5, and BusyBox 1.35.0, the
host-read status showed `CapInh=0`, `CapPrm=0`, `CapEff=0`, `CapBnd=0`,
`CapAmb=0`, and `NoNewPrivs=1`. The selected mountinfo entries reported:

- `/`: `tmpfs`, `ro`, `noatime`;
- `/proc`: `proc`, `ro`, `nosuid`, `nodev`, `noexec`, `relatime`;
- `/workspace`: `tmpfs`, `rw`, `nosuid`, `nodev`, `noatime`;
- `/tmp` and `/home/agent`: `tmpfs`, `rw`, `nosuid`, `nodev`, `relatime`.

The host-side assertion requires read-only `/` and `/proc`, writable
`/workspace`, `/tmp`, and `/home/agent`, the configured `proc`/`tmpfs` types,
`nosuid`/`nodev` on non-root mounts, and exactly those five mountpoints: every
additional mountpoint is rejected before the fd-3 candidate gate is released.
The parser retains mount root, source, propagation tags, mount options, and
super-options for diagnostics. `/workspace` reported its backing filesystem
as `tmpfs` because the test snapshot resides below host `/tmp`; this readback
does not establish bind-source identity. Although `/proc` reported `noexec`,
the assertion does not require it. This follow-up supersedes the prior run's
“not read back” statement only for these selected status and mount properties
on this one host.

The scope was
`acp-acp-live-638dd00a8f504f25bdb8b28037181bd7.scope`, with cgroup
readbacks `memory.max=134217728`, `pids.max=16`, and `cpu.max=50000 100000`.
The fixture exited 0; its selected host-path, symlink, process-marker, and
network probes passed (`interfaces=lo`, no default route, host-NIC probe exit
1, test listener not reached). Internal cleanup checks passed. Independent
postflight found the exact systemd unit `LoadState=not-found`, the cgroup path
absent, no checkout canary, and two user processes in D state (below the
stop threshold of five).

An independent read-only reviewer gave GO on the exact readback code/docs diff
at this test-source SHA after the live run; that reviewer did not run tests or
access the NAS. The measurements above come from the separately recorded
exact-hash execution. At this source SHA, the validator required exactly the
five configured mountpoints; it did not assert their propagation tags,
bind-source identity, tmpfs super-options or sizes, and rejected `/proc/sys`
submounts as extra mounts rather than validating their read-only state. The
test remains direct `runc`
with a fixed no-model fixture—not the registered
supervised worker executor. It does not prove real-provider authentication or
egress, arbitrary hostile-worker behavior, result transfer, cancellation,
crash recovery, concurrency, or task #2370 acceptance. Worker execution stays
unintegrated and `externalSandbox` remains disabled.

### Strict runtime-added mount diagnostic (2026-10-05; source SHA `97c0bb16`; fail-closed)

The exact test source SHA-256
`97c0bb16870253258c0a62fcc052eeb8de15a07f65f0708723841f1bea626e3b` was
copied to the leased NAS scratch checkout and run once with rootless runc
1.3.5. The host-side mount allowlist rejected the runtime-created additions
before writing the trusted fd-3 release value; the candidate command did not
run and no model/provider was invoked. The observed additions were:

- `/dev/full`, `/dev/null`, `/dev/random`, `/dev/tty`, `/dev/urandom`, and
  `/dev/zero`: `devtmpfs`, source `udev`, each with a corresponding device path
  as its mount root, `rw,nosuid,relatime`, and optional propagation tag
  `master:10`;
- `/proc/kcore` and `/proc/keys`: `devtmpfs`, source `udev`, mount root
  `/null`, with the same mount options and propagation tag;
- `/proc/sys` and `/proc/sysrq-trigger`: `proc` submounts rooted at `/sys` and
  `/sysrq-trigger`, respectively, each `ro,nodev,noexec,nosuid,relatime` with
  read-only super-options.

These are not safe to accept solely by destination name or `mountinfo`'s
major:minor field: that field identifies the backing filesystem device, not a
character device's `st_rdev`. The [OCI v1.2.1 default-device
requirements](https://github.com/opencontainers/runtime-spec/blob/v1.2.1/config-linux.md#default-devices)
explain why the six `/dev` nodes are created; [runc v1.3.5's rootfs
implementation](https://github.com/opencontainers/runc/blob/v1.3.5/libcontainer/rootfs_linux.go#L952-L964)
uses host-device bind mounts for user-namespace operation. Its [default device
rules](https://github.com/opencontainers/runc/blob/v1.3.5/libcontainer/specconv/spec_linux.go#L174-L324)
are [appended to the configured resource rules](https://github.com/opencontainers/runc/blob/v1.3.5/libcontainer/specconv/spec_linux.go#L938-L941),
so an OCI deny-all device list alone does not prove runc-added `mknod`
permissions are absent.

At this source SHA, no additional mount was accepted. The diagnostic
identified checks required before any version-pinned test-only expansion:
bind the readback to the exact init PID/start identity; verify device file
type, `st_rdev`, owner/mode and inode identity; prove `/proc/kcore` and
`/proc/keys` are the intended `/dev/null` masks; verify `/proc/sys` and sysrq
mount roots/options; and account for propagation. `master:10` identifies a
slave mount: mount and unmount events can propagate inward from its master
shared peer group, while events under the slave do not propagate back. Whether
such inbound events can alter the worker's effective device mounts, or how to
sever them reliably, remains unverified; this source SHA therefore keeps
rejecting the extra mounts
([Linux mount-namespace propagation semantics](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)).
The later recursive-private recheck below removed those optional propagation
tags in its mountinfo snapshot, but did not exercise host mount/unmount events
or validate device identity. That source SHA still rejects the extra mounts;
if any property is unsupported or ambiguous, keep rejecting it.
Postflight after this failed diagnostic found no matching runc scope, cgroup,
process, or checkout canary; the user's default target remained active, the
non-helper D-state count was zero, and `/tmp` remained at 19%. This diagnostic
is not a worker-executor or sandbox-acceptance result.

### Recursive-private propagation recheck (2026-10-05; fail-closed)

The opt-in fixture gained a test-only `ACP_OCI_TEST_ROOTFS_PROPAGATION`
override. The default remains the compiler's OCI-standard `private`; selecting
`rprivate` is accepted only when the pinned executable reports runc 1.3.5.
Runc 1.3.5 maps that implementation-specific spelling to
`MS_PRIVATE|MS_REC`, while OCI Runtime Specification v1.2.1 lists only
`shared`, `slave`, `private`, and `unbindable` for `rootfsPropagation`
([runc mapping](https://github.com/opencontainers/runc/blob/v1.3.5/libcontainer/specconv/spec_linux.go),
[OCI field](https://github.com/opencontainers/runtime-spec/blob/v1.2.1/config-linux.md#configlinuxrootfsmountpropagation)).
No production compiler or launch path changed.

On uid 1000, Linux 6.18.15, and rootless runc 1.3.5, the exact test source
SHA-256 was
`1d30bd03705c7b45ba39bed70f2f8ee5b1fa44d15b20b192c80bd2bf291ab702` (base
commit `b0b02a5824e55ca45b1ce0d78431c1320b81ba78`). The host bracketed the
init's mountinfo read with the exact PID/start-time/cgroup identity. The same
ten runtime-created mountpoints remained outside the unchanged five-point
allowlist, so the audit rejected the attempt before fd 3 was released:

- `/dev/full`, `/dev/null`, `/dev/random`, `/dev/tty`, `/dev/urandom`, and
  `/dev/zero`: `devtmpfs`, source `udev`, each rooted at its corresponding
  device path, `rw,nosuid,relatime`;
- `/proc/kcore` and `/proc/keys`: `devtmpfs`, source `udev`, root `/null`,
  `rw,nosuid,relatime`;
- `/proc/sys` and `/proc/sysrq-trigger`: `proc`, roots `/sys` and
  `/sysrq-trigger`, `ro,nodev,noexec,nosuid,relatime`, read-only super-options.

Unlike the earlier `private` readback, none of these ten entries had a
propagation optional field (including `master:10`). This is mountinfo evidence
for the tested snapshot; no host mount/unmount event was injected. Recursive
private propagation therefore removes the observed slave-group relationship,
but it does not remove runc's device and proc mounts or authorize them. The
strict audit still fails closed; the candidate and its egress probe did not
run, and no model or provider was called. Device `st_rdev`, owner/mode/inode
identity, `/proc` mask identity, and the read-only path behavior still require
their own exact-init checks before any allowlist expansion.

The bounded test teardown and a separate read-only postflight found no matching
`acp-live` systemd scope, zero user processes in D state, an active user
`default.target`, and `/tmp` at 19%. This diagnostic narrows the propagation
hypothesis only; it is not a positive isolation result, an integrated worker
executor, or completion of task #2370.

### Exact default-device identity preflight (2026-10-05; fail-closed)

On uid 1000, Linux 6.18.15, and rootless runc 1.3.5, the updated test source
SHA-256 was
`90f74895091f8af47bf2be6c01c5ce6b6c8060d2f7d013e03d2b2837f7a4601e`.
All non-generated Python package sources in the NAS scratch checkout matched
the local checkout, and the copied test file matched this hash. The run used
the test-only `rootfsPropagation=rprivate` override. PID namespace, capability,
and exact runc 1.3.5 mount metadata checks passed while the candidate remained
behind fd 3; device-node identity validation then failed closed at `/dev/tty`
before releasing that gate.

The host `/dev/tty` node was a character device with `st_rdev=5:0`,
`st_dev=6`, inode 12, owner/group `0:5`, and mode `0666`. The diagnostic
incorrectly required every approved device node to have owner/group `0:0`, so
it rejected the valid host `root:tty` group before comparing the guest bind's
exact inode metadata. This is a diagnostic predicate defect, not a successful
device-bind proof: the guest `/dev/tty` comparison and later device/mask checks
were not reached. No candidate payload, model, or provider ran.

The test's teardown reported no secondary cleanup error; a read-only postflight
found no active `acp-*` scope or `runc` process, the unique attempt root was
absent, `default.target` remained active, uid-1000 D-state count was zero, and
`/tmp` remained at 19%. The test-only correction keeps root ownership and mode
`0666` requirements, but binds GID through exact host-versus-guest node identity
rather than assuming every Linux host assigns `/dev/tty` to GID 0. This failure
does not authorize the device mounts or establish sandbox acceptance. The
independently reviewed correction and separately gated run are recorded below.

### Corrected default-device identity and bounded live probe (2026-10-05; pass)

The test-only validator now requires each approved node to be a root-owned
character device with mode `0666` and the expected `st_rdev`; it compares the
exact host and guest `st_dev`, inode, `st_rdev`, mode, UID, and GID. This keeps
the host's legitimate `/dev/tty` group (`0:5`) without treating arbitrary guest
metadata as trusted. Regression tests reject a wrong inode or GID, wrong device
type or number, non-root owner, unsafe mode, and a mount whose device identity
does not match the host node. Independent adversarial QC gave GO on exact test
SHA-256
`7598af2be5409203198bc2a3e497adc0793642bb92ad482e6efbd9859631dc9d`.

On uid 1000, Linux 6.18.15, rootless runc 1.3.5, and BusyBox 1.35.0, the exact
test file was copied into the leased disposable NAS checkout and verified at
that SHA. Every non-generated file under `src/agent_control_plane` matched the
local checkout. The single live invocation set
`ACP_RUN_OCI_INTEGRATION=1`, `ACP_OCI_TEST_RUNC_VERSION=1.3.5`, and the
test-only `ACP_OCI_TEST_ROOTFS_PROPAGATION=rprivate`. It exited 0 (`1 passed`)
in 6.52 seconds. The pre-exec policy and identity checks passed before the
host released fd 3. The candidate then signaled readiness and waited at a
separate workspace gate; while it waited, the host-side fd audit observed only
descriptors 0, 1, and 2, each targeting a pipe, before releasing that gate.
The fd audit asserts the descriptor set and rejects socket targets; pipe-target
types are recorded observations, not an asserted invariant.

The exact init reported zero `CapInh`, `CapPrm`, `CapEff`, `CapBnd`, and
`CapAmb`, with `NoNewPrivs=1`; its host PID mapped to namespace PID 1, and
worker `/proc/1` exposed only the namespace-relative PID 1. The audited mount
table had exactly `/`, `/proc`, `/workspace`, `/tmp`, `/home/agent`, the six
runc default device nodes under `/dev`, the `/proc/kcore` and `/proc/keys`
`/dev/null` masks, and read-only `/proc/sys` plus `/proc/sysrq-trigger`. All
ten runc-added entries had no propagation fields under `rprivate`. The
validator matched source, root, filesystem, and mount options against the
pinned runc 1.3.5 expectations; it also required the six devtmpfs nodes and two
`/dev/null` masks to share one device ID, and the proc masks to share `/proc`'s
device ID. For super-options, it required devtmpfs to include `rw` and exclude
`ro` (additional tokens were allowed), while each proc mask had to equal
`{ro}`. The host `/dev/tty` identity was `st_rdev=5:0`, `st_dev=6`, inode 12,
UID:GID `0:5`, mode `0666`; all eight device and `/proc` mask identity
comparisons passed.

The test confirmed writable assigned workspace, `/tmp`, and agent-home
tmpfs, plus the expected result; it denied reads/writes to the base checkout,
sibling attempt, unrelated project, host home/config/credential sentinels,
host `/etc`, host `/tmp`, and absolute/relative symlink targets. The candidate
saw only `lo`, had no default route, its network probe returned 1, and the
host-NIC listener was not reached. The test-owned checkout canary was removed
during teardown. The exact cgroup was
`/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/user.slice/acp-acp-live-0ff8b1e177b84fca937715c236b876e6.scope`,
with `memory.max=134217728`, `pids.max=16`, and `cpu.max=50000 100000`. The
reported rootfs tree digest was
`0fd9d84bf185648243c7734df37a43ab3d3f74e50eef7526b49c1e764179b6cc`.

Teardown and separate postflight succeeded: the exact scope was `not-found`,
its cgroup and attempt root were absent, no runc process or other `acp-*`
scope remained, the user's `default.target` was active, uid-1000 D-state count
was zero, and `/tmp` remained at 19%. No model or provider was called.

This is a bounded direct-runc proof using ACP's current OCI config builder,
not integration with the registered worker executor (`run_worker` remains
fail-closed for configured OCI). It does not prove real-provider credentials
or egress, hostile long-running process behavior, cancellation/restart
recovery, concurrent attempts, result transfer/QC, or end-to-end sandbox
acceptance; task #2370 remains open.

### systemd/runc cgroup composition probe (2026-10-03)

The first wrapper-only test used rootless runc under a transient service with
`Delegate=yes` and `KillMode=control-group`, but without
`--systemd-cgroup`. The init cgroup was a sibling of the service cgroup, not
inside it. Stopping that exact service left the container in `running` state
after the bounded 10-second observation; cleanup explicitly killed and removed
that exact container. This rejects the wrapper-only kill assumption.

The follow-up used runc's documented systemd cgroup driver and
`linux.cgroupsPath=user.slice:acp:<container-id>`. It created a distinct
`acp-<container-id>.scope`; the cgroup recorded for the container init exactly
matched the scope `ControlGroup`, rather than the wrapping service. The normal
two-gate fixture wrote the expected result; read-only postchecks confirmed the
wrapper service and scope were unloaded. In the cancellation fixture,
`systemctl kill --kill-whom=all --signal=SIGTERM` against the exact scope did
not stop the shell-plus-child fixture within 3 seconds. Exact-scope
`SIGKILL` escalation then yielded `runc state=stopped`, the init PID/start-time
identity was absent, and both the exact container scope and wrapper service
were unloaded. The saved task note reports that all test containers and the
exact leased temporary root were removed, but runtime-state absence was not
independently recorded.

The earlier saved note does not preserve whether this probe used `--keep`, its
exact `runc delete` invocation, or a post-delete check that the container ID
was absent from the configured runc state root; that historical record remains
incomplete. The separate repeat fixture above records an explicit delete and
positive state-root, PID-identity, and systemd-scope absence checks. This is
cleanup evidence for that disposable fixture only, not supervisor-managed
crash/cancel recovery or release of an ACP execution fence.

**OCI policy compiler slice (2026-10-04; not integrated).** The new
`supervisor/oci_worker.py` compiles an OCI 1.2 config and an attached `runc`
argv for a future executor. It encodes a readonly root, a single non-recursive
private workspace bind, private tmpfs mounts, an empty capability set,
`noNewPrivileges`, a non-root effective UID/GID mapping, and finite requested
memory/CPU/PID/tmpfs values. It rejects non-private or replaceable-by-other-UID
path ancestors, non-canonical or mount-shadowed executable paths, and binaries
or parent directories that are not executable/searchable by the mapped
identity. The argument builder specifies the bundle, state root and PID-file
paths, retains runc state with `--keep`, and remains attached (no `--detach`).
These are compile-time checks and requested settings, not runtime observations.

The 2026-10-04 snapshot-provenance follow-up changes the workspace input from
an arbitrary path to the host copier's `Snapshot` handle. A process-local
weak-reference registry binds that exact handle to its host path, directory
device/inode, original manifest object and manifest digest. Before selecting
the bind source, the builder reopens and checks the complete tree against that
captured manifest. Regression tests reject raw paths, forged or retargeted
handles, post-capture content changes, and forced manifest substitution. This
proves input provenance at config-compilation time only.

Important gaps are intentional and must remain launch gates: the module does
not create/provenance-check a rootfs, launch or supervise a worker, reserve the
PID path atomically, bind execution to the claim fence, enforce egress or
credentials, read back cgroups/devices, or integrate result import and
recovery. Owner-only path modes do not isolate untrusted processes sharing the
same host UID. The config still names the workspace by host path, so this
check-then-bind sequence does not stop a same-UID process from changing or
replacing the source before `runc` opens it. The executor must close that race
with per-attempt host identity isolation or an equivalently pinned mount and
prove the result. The host-backed workspace also has no aggregate disk quota.
The compiler now emits a native-ABI seccomp denylist as defense in depth. It
returns `EPERM` for mount/namespace-management, module, keyring, tracing,
process-memory, io_uring and related high-risk syscalls; denies `clone` when
any namespace flag is set; returns `ENOSYS` for `clone3` so libc can fall back
to the filtered `clone`; and returns `EPERM` when `socket` or `socketpair`
requests a family other than `AF_UNIX`. It uses `SCMP_ACT_ALLOW` by default,
so it is not a complete syscall allowlist or sandbox. The profile omits OCI's
optional `architectures` field: runc permits the native ABI by default and
treats listed architectures as additional ABIs; compat ABIs are intentionally
not enabled ([runc 1.3.5 seccomp setup](https://github.com/opencontainers/runc/blob/v1.3.5/libcontainer/seccomp/seccomp_linux.go),
[OCI seccomp configuration](https://github.com/opencontainers/runtime-spec/blob/v1.2.1/config-linux.md#seccomp)).
This compiler change is not runtime proof: exact-host filter installation and
behavior remain launch gates. The socket rules do not restrict inherited file
descriptors or AF_UNIX paths that a future executor exposes. The pinned runc
1.3.5 specification states that it supplies no default filter
([runc security specification](https://github.com/opencontainers/runc/blob/v1.3.5/libcontainer/SPEC.md)).
The device-cgroup deny entry is only a request: OCI requires default device
nodes and runc/rootless cgroup behavior needs exact-runtime readback before any
device-isolation claim ([OCI Linux configuration](https://github.com/opencontainers/runtime-spec/blob/v1.2.1/config-linux.md),
[runc cgroup v2 guide](https://github.com/opencontainers/runc/blob/v1.3.5/docs/cgroup-v2.md)).
The emitted config is now checked by
tests/test_oci_worker.py::test_compiled_oci_worker_config_matches_pinned_oci_schema
against the unmodified OCI Runtime Specification v1.2.1 Draft 4 schemas, pinned
to upstream commit 524fc0e1b8ab0180e2fc9abd31837a0f4ed1fd6b. The four test-only
schema files include the core and Linux schemas plus their transitive
definitions; validation resolves references only from a local registry and has
no network fallback. Reproduce with
uv run pytest tests/test_oci_worker.py -k pinned_oci_schema (the test name
contains pinned_oci_schema). It also confirms an invalid memory-limit type is
rejected. This proves schema conformance of the emitted JSON only, not a Linux
launch, syscall/device/cgroup enforcement, or per-attempt worker-isolation.

The compiler's denylist shape and unsupported-native-architecture rejection
are covered by
`tests/test_oci_worker.py::test_oci_worker_seccomp_profile_is_native_only_and_denies_high_risk_syscalls`
and
`test_oci_worker_seccomp_profile_rejects_unsupported_native_architecture`.
These are structural tests, not runtime tests. Linux CI also runs
`tests/test_oci_seccomp_runtime.py`: it resolves every emitted syscall name
through libseccomp, loads the generated argument rules into the kernel, and
checks each denylisted syscall with inert arguments. For deny rules, the test
uses `EACCES` as a distinctive marker so a kernel-side `EPERM` cannot look like
a filter hit; it separately loads the production action and checks `clone3`
returns `ENOSYS`. It also checks every namespace flag, non-`AF_UNIX` socket
denials, permitted local `AF_UNIX` socket/socketpair, ordinary fork/thread
creation, and `/proc/self/status` reporting `Seccomp: 2`. Reproduce with
`uv run pytest tests/test_oci_seccomp_runtime.py` on Linux with libseccomp.
This exercises the profile's syscall names, comparisons, and kernel behavior
through libseccomp; it does not parse the OCI JSON through runc and is not a
container-launch or integrated-worker proof. Before launch is enabled, run the
exact emitted profile through the pinned runc version on each supported Linux
architecture/runtime; verify
`/proc/self/status` reports `Seccomp: 2`, ordinary process/thread behavior
still works, every configured syscall name resolves on the target runtime, and
each required deny rule is individually behavior-tested: namespace-creating
`clone` flags are denied, `clone3` returns `ENOSYS`, and non-`AF_UNIX` socket
families are denied. Also verify an approved local AF_UNIX use case works
without exposing host sockets or inherited network-capable descriptors. A
`Seccomp: 2` readback alone is insufficient because runc may silently ignore
syscall names it cannot resolve
([runc 1.3.5 rule handling](https://github.com/opencontainers/runc/blob/v1.3.5/libcontainer/seccomp/seccomp_linux.go#L1364-L1373)).
If the runtime cannot install the profile, fail closed rather than silently
running without it.

**Paired exact-profile runc observation (2026-10-04; one NAS host).**
On NAS, hash-verified copies of the relevant source files from commit
`17e6bba` generated the config for the same fixed, no-model BusyBox fixture in
two sequential `runc --systemd-cgroup run`
launches on x86_64/Linux 6.18.15 with runc 1.3.5. The configs were identical
except for `linux.seccomp`: the generated profile versus an explicit
`SCMP_ACT_ALLOW` default with no syscall rules. Both init processes reported
`Seccomp: 2`. The generated-profile `nc -l -p 49152` probe failed at socket
creation with `EPERM`; the allow-all control created and bound the same local
listener until its one-second timeout (exit 143). No connection was attempted.
Exact `runc delete --force` succeeded after each run, the
unique state root listed no container, both sampled init PIDs were absent, and
the leased scratch tree was removed. This paired observation attributes that
single listener socket-creation denial to the generated profile in this setup;
it does not establish broader egress control, other syscall rules, cgroup or
device enforcement, or worker isolation. The integrated-worker and per-rule
runtime gates below remain open.

This does not prove that ACP persists either systemd invocation, captures an
attached runc exit receipt, coordinates cancellation/recovery across supervisor
restart, or safely releases its execution/result-import fences. It also does
not prove credential or provider egress policy. Worker execution is still
direct-host with bounded log capture only; no OCI filesystem isolation is
integrated, and `externalSandbox` remains disabled.

## Required proof gates

- **Fake worker in the integrated path:** run a no-model registered worker
  through the executor, not just generated driver commands. Prove that the
  assigned tree is writable; base/sibling/unrelated roots, home/config, host
  temp and credential markers, Unix sockets, and host processes are not
  reachable; prove symlink/canonical-path escape attempts fail. Verify the
  worker receives only the reviewed toolchain closure and generated minimal
  `/etc`, never a broad host `/etc` or `/usr` mount, and cannot read a sentinel
  placed in host `/etc`.
- **Git and transfer:** prove the sandbox contains no host `.git` pointer,
  alternate, common object store, or credential helper. Exercise add/modify/
  delete/rename/binary/executable/symlink cases, undeclared writes, malicious
  paths, nested `.git`, linked worktrees, submodule gitfiles, and oversized
  output. Prove the host outside sentinel remains unchanged on malicious
  symlink/parent-path output. Inject crashes after export, after object/tree or
  worktree import, and before journal/DB completion; replay must be idempotent
  for the same fencing epoch and refused for a later one. Only a valid bounded
  diff may reach the existing QC path.
- **Lifecycle:** test cancellation, abrupt supervisor restart, timeout,
  failed systemd setup, stale unit, and concurrent attempts. A missing or
  ambiguous unit identity is `unknown` and retains the fence; it is not cleanup
  proof. After a stopped container, explicitly run `runc delete` and verify
  that its exact ID is absent from the configured runc state root and its
  cgroup/unit is absent before releasing the fence. Preflight every required
  cgroup controller and verify configured resource limits by reading them back
  from the attempt cgroup; fail closed when delegation or enforcement is not
  available.
- **Credentials and egress:** with fake credentials and a local test proxy,
  prove only the named handle reaches the worker and only approved destinations
  can be contacted. Do not make a paid inference call for this no-model proof.
- **Release gate:** independent criterion-level adversarial QC, focused and full
  supported test suites, lint/format/package build, and exact-head Linux/macOS
  CI must pass. Keep the feature disabled by default and do not claim worker
  read isolation until every gate is met.

Until then, the supported claim is narrower: ACP's resource driver can create a
constrained systemd unit around a configured payload on the measured NAS; the
supervised coding worker still executes directly in its registered worktree.
