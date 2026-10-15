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
incomplete. The OCI policy compiler stages init behind fd 3, and a reusable
launcher now starts the pinned runc client through a held executable FD while
retaining that gate. No `run_worker` path yet connects launch to the durable
journal, runtime attestation, cleanup verification, or result import. This
record does not authorize `externalSandbox` for ACP workers.

## Codex adapter contract (2026-10-15; OpenAI Docs)

OpenAI positions the Codex SDK for automated coding jobs and CI, and the App
Server for custom clients that need authentication, conversation history,
approvals, and streamed events. ACP's worker is an automated job, so the SDK is
the default adapter to evaluate; choosing either interface does not provide
the per-attempt isolation required here.

The App Server's `sandboxPolicy.type = "externalSandbox"` explicitly tells
Codex to skip its own sandbox because the server/command is already sandboxed.
It is a delegation contract, not a sandbox implementation. ACP must put the
agent process and all descendants inside its independently enforced namespace
before opting into this mode. The App Server's `networkAccess` value is not
packet-filter evidence. Likewise, Codex permission-profile domain rules only
constrain command traffic when the network proxy is enabled; merely setting
domains does not start that proxy. ACP must enforce and test provider egress at
the outer boundary, fail closed when that policy is unavailable, and must not
mount or copy the host's Codex auth/config directory into an attempt.

The documented interface split is in [OpenAI's Codex SDK
guide](https://learn.chatgpt.com/docs/codex-sdk) and [App Server
guide](https://learn.chatgpt.com/docs/app-server#command-execution). The
external-sandbox contract is described under [App Server command
execution](https://learn.chatgpt.com/docs/app-server#command-execution); the
network-proxy requirement is in [Agent approvals & security](https://learn.chatgpt.com/docs/agent-approvals-security#network-isolation)
and [Permissions](https://learn.chatgpt.com/docs/permissions).

**Runtime security requalification (2026-10-10).** The implementation and prior
live evidence were pinned to runc 1.3.5. Upstream lists `<=1.3.5`, `<=1.4.2`,
and `<=1.5.0-rc.2` as affected by
[GHSA-xjvp-4fhw-gc47](https://github.com/opencontainers/runc/security/advisories/GHSA-xjvp-4fhw-gc47),
with fixes in 1.3.6, 1.4.3, and 1.5.0-rc.3. We evaluated the patched 1.3 and
1.4 lines at source level and selected 1.5.2, the latest stable release at
selection time (1.6.0-rc.1 is a prerelease). Both [1.4.3](https://github.com/opencontainers/runc/blob/v1.4.3/libcontainer/specconv/spec_linux.go#L2290-L2294)
and [1.5.2](https://github.com/opencontainers/runc/blob/v1.5.2/libcontainer/specconv/spec_linux.go#L2290-L2294)
retain the adapter's `rprivate` to `MS_PRIVATE|MS_REC` mapping. The
[1.5.2 release](https://github.com/opencontainers/runc/releases/tag/v1.5.2)
also includes a workaround for a cgroup-v2 device-rules kernel bug present in
Linux 6.17. The adapter contract now targets exact runc 1.5.2 and its upstream
`runc.amd64` digest
`sha256:599f6f94ff8c5057241eff0d54c3c74f95c34935b6457b33fe545defc61e9488`.
That upstream digest is verified when the dedicated CI job acquires its test
binary. Production configuration validates the exact release string and pins
the configured executable's observed bytes; it does not hard-code this upstream
asset digest, so deployments remain responsible for sourcing and configuring
their own trusted runc binary.
The opt-in live boundary probe passed on 2026-10-10 in a disposable Lima VZ
guest (Ubuntu 24.04.5 LTS, aarch64, kernel 6.8.0-142-generic), using the
upstream `runc.arm64` asset with digest
`sha256:d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`.
It launched a bounded BusyBox payload through `spawn_pinned_runc()` and verified
the read-only private root, expected mount policy, CPU/memory/PID cgroup
readback, zero effective capabilities, `NoNewPrivs`, a loopback-only network
namespace, and that a host-NIC listener was not reached. Checks confirmed that
host checkout, sibling and unrelated project, home/config/credential, `/etc`,
and `/tmp` file paths were denied; the exact host Unix-socket sentinel path was
not visible; and absolute/relative symlink escapes were denied. The probe also
passed the same-UID bundle/config and state/workspace path-replacement attacks;
the exact runc scope, process, cgroup, and test-owned temporary paths were
verified absent after teardown. BusyBox is installed as the dynamic package so
the test can audit and copy its exact loader/library closure.

This is primitive-level evidence, not end-to-end worker acceptance: it does
not launch through `run_worker()`, supply model credentials, establish a
provider egress policy, or test unattended supervisor-restart recovery and
result import. `run_worker()` remains fail-closed as
`sandbox_executor_unavailable`. This manual guest run is not exact-head hosted
Actions evidence for the live probe. Any hosted job must install dependencies
before relaxing Ubuntu's `kernel.apparmor_restrict_unprivileged_userns`, do so
only on a secret-free disposable VM, install and verify its restore trap before
the sysctl change, and fail on missing user-namespace or delegated-cgroup
prerequisites rather than accepting a skip. Its archived checkout must carry a
`.git` pointer to the real checkout gitdir so host-metadata denial is
non-vacuous.

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
the existing `run_worker` path does not use this transport or launch runc, and
no supervisor call path reads back runtime state and durably validates it before
releasing the OCI init gate. It proves no namespace, mount, credential, egress,
cancellation, or result-import property.

**Private-bundle runc handoff (historical exact-source NAS replay, independent QC, and hosted CI passed on the implementation/test-fixture commit).**
The public `spawn_pinned_runc()` path now validates the sealed policy/runtime
binding, opens stable descriptors for the bundle and rootfs, and starts an
isolated helper. The helper maps only the caller's UID/GID to the same host IDs
in a new user namespace and creates a recursively private mount namespace. It
creates a bounded detached tmpfs using Linux's fd-based mount API, attaches it
to the opened bundle directory with empty-path `move_mount`, writes the exact
compiler-sealed config, and marks the bundle read-only. The compiler policy
also places a `nosuid,noexec` tmpfs at `/dev`, bounded to 1 MiB of data and 64
inodes: Linux tmpfs enforces `size` and `nr_inodes` as separate limits
([kernel tmpfs documentation](https://docs.kernel.org/filesystems/tmpfs.html)).
Runc 1.3.5 creates device mountpoint inodes and its `ptmx` link there during
bootstrap, before applying the OCI `root.readonly` setting to `/`. This keeps
those setup writes off the read-only rootfs; the runtime audit verifies the
actual `/` mount is read-only before the init gate opens. Because mount targets
must belong to the helper's new mount namespace, it reopens the bundle there
and compares its device/inode identity to the parent's pinned descriptor.
Exact runc 1.3.5
receives `--bundle /proc/self/fd/N`; a same-UID host-path replacement therefore
does not redirect its config handoff. The launcher fails closed if the required
fd-based mount API is unavailable; it has no path-based mount fallback.
The helper and parent use bounded status/map/exec handshakes, and the OCI init
still blocks behind fd 3. Setup failures before runc exec kill and reap the
helper; after the runc-exec acknowledgement, an unavailable handle is reported
as `sandbox_launch_submission_unverified`, not as proof that no runtime started.
That exception carries the runc client PID and a separate reap result; unknown
or negative reap evidence makes the integration harness preserve its bundle and
state instead of treating the missing process handle as proof of absence.

Those replay/QC/CI results apply only to the named historical hashes and commit;
they do not validate the current uncommitted candidate. The 2026-10-06 exact-
hash review found that the old read-only rootfs mount still shared mutable host
inodes, and that the public handle exposed mutable `Popen.returncode`. The
current candidate replaces the rootfs mount with a bounded (256 MiB maximum)
tmpfs content copy, rejects rootfs entries not owned by the caller or carrying
extended attributes, makes the helper non-dumpable, returns the read-only
snapshot FD to the parent for a tree/closure comparison, and adds a deterministic
post-hash source-mutation attack to the Linux runtime test. It also removes
`Popen` from the launch handle and requires a kernel `waitpid` reap before
issuing a receipt. It also captures state/workspace device+inode identities,
opens and revalidates those exact directories, and passes descriptors to the
private helper. Runc's `--root`, PID-file parent, and `/workspace` bind source
are rebound before exec; the state root and PID file use `/proc/self/fd/N`. In
its private mount namespace, the helper creates a detached workspace mount
with `open_tree` from the captured absolute path, verifies its root
device/inode against the inherited workspace FD, applies `nosuid,nodev`, and
attaches it to a namespace-private anchor with empty-path `move_mount`. A
concurrent path replacement therefore fails closed before runc exec. The
anchor is a 1 MiB tmpfs created over root-owned `/dev/shm`; the config points
to that namespace-private path so runc's container-init child does not need to
inherit the FD. A deterministic Linux test first replaces the workspace path
at the helper's pre-`open_tree` handshake and requires an inode mismatch to
fail closed and reap the helper; the successful launch test then renames each
host path after binding and checks state/PID-file writes and workspace output
stay on the pinned directories despite a same-name host `/dev/shm` marker. On
2026-10-06, the hash-verified NAS staging replay passed both this runtime test
and the setup-failure reap test (2 passed in 7.67 seconds) on Linux 6.18.15
with runc 1.3.5; Ruff format and lint also passed. The replay covered
`oci_worker.py` SHA-256 `0db5a646aeec7905b721f17cfc32aeaff54748d670c243f877cc8937270f13f3`,
`test_oci_worker.py` SHA-256
`aebdce1ef87bcf6f488efbae85a69a9ccb2826edd89fa1446510d5dd59a10a1e`, and
`test_oci_worker_runtime.py` SHA-256
`57bddbb0f76c3526973adc5419cfc71a110cf9cca519f3c3ecd83e9efab01c34`.
The full repository workflow passed on macOS/Python 3.12.8 after this handshake
change: 1,161 tests passed, 57 platform/runtime-gated tests skipped, Ruff format
and lint passed, and `uv build` produced both wheel and source distribution.
Independent exact-hash QC and the hosted GitHub Actions matrix remain pending.

A subsequent exact-hash review found a P1 gap: the launch binding did not carry
the operator's rootfs tree/closure pins from config compilation to spawn, so a
same-UID rootfs replacement could be re-hashed as if it were pinned. The
current revision seals both digests in the compiler and launch registries,
passes them through the public spawn API, and compares bundle content against
those original pins before starting the private helper. A regression mutates
the bundle rootfs after compilation and requires rejection before helper or
candidate startup. The reviewer also found that the journal called kernel
`waitpid` evidence `Popen.wait`, and then found that changing old migration
definitions would not repair already-migrated databases. Schema 20 adds
immutable `runc_exit_evidence_source`, requires `runc_client_kernel_waitpid`
there for new exit transitions and result candidates, and keeps the old
`runc_exit_observed_by` value `runc_client_popen_wait` solely for the existing
SQLite CHECK. Schema 21 adds a forward migration installing a receipt gate on
the database transition itself. The app's SQLite UDF authorizes one exact
connection/receipt tuple only while the journal persists a receipt already
validated against the durable attempt, fencing token, execution, PID, and
process identity. The generic transition helper no longer exposes `* -> exited`;
the receipt-validating exit method performs that update inside the scoped
authorization. Direct SQL with the expected marker strings is rejected unless
that validated receipt scope is active. Both the generic helper and raw-SQL
bypass have dedicated regressions, and the lifecycle test covers valid receipt
persistence. The forward migration leaves old evidence blank rather than
backfilling proof it cannot reconstruct; old rows cannot produce a new
candidate. On 2026-10-06, the refreshed exact-hash NAS staging replay passed six
tests: the v19-to-v20 and v20-to-v21 migrations, direct-SQL exit forgery
rejection, generic-transition rejection, rootfs path-swap rejection, bounded
setup-failure helper reap, and the live rootless-runc boundary. The host was
Linux 6.18.15 with runc 1.3.5; pytest used an external `/tmp` basetemp. Ruff
format and lint passed across all 87 source/test files. Replay source hashes
were `git_supervisor.py`
`13c1f82c420c6e115cfd51d15082aa6049f0bcf802be77b0b993d4b820ecf74d`,
`sandbox_execution_journal.py`
`232b07f8e4beb12a8c7fc744f7cfab50b5c8d77b0320ad953665f3bc0d33b405`,
`store.py`
`998b769c32df6b5d3f49e4a8795c1c7bcdee699ef23d9e00d607fc1daa5d26f4`,
`test_sandbox_execution_journal.py`
`21deae240ff6f825374ae50aeb6f66693b873a047708f062d085144fce65becb`,
`oci_worker.py`
`0002d15cc32f638cec2231e1a2e81f4a2a2af7372a4ab0588992416c267f150c`,
`test_oci_worker.py`
`9095ed962311d797223464e5c8598febda16f492c9ab2fa58731bc488abaf6f6`, and
`test_oci_worker_runtime.py`
`57bddbb0f76c3526973adc5419cfc71a110cf9cca519f3c3ecd83e9efab01c34`.
The full local suite passed against this schema-21 candidate (1,165 passed,
57 platform/runtime-gated skips, 388.54 seconds); local Ruff and `uv build`
passed. Independent exact-hash re-review returned GO on 2026-10-06: all eight
supplied hashes matched, and the reviewer confirmed the connection-scoped
receipt gate, sole validating exit writer, generic-transition restriction,
and direct-SQL regression. The reviewer did not rerun the reported suites.
GitHub Actions run `37438363183` was triggered on published implementation
commit `0d4f45be2d52f540fc424d619ecea1af1af07f33`; its four matrix jobs were
in progress when this evidence note was written. Any follow-up commit requires
its own exact-head CI check.

Schema 22 adds a one-time launch-plan binding. A fresh reservation opts into the
binding; only the exact process-local, registered runc handle already bound to
that attempt may persist the canonical plan through a connection-scoped SQLite
capability. The plan includes exact config-byte and frozen-argv digests, the
complete argv, the reserved caller bundle digest, and attempt/claim/execution,
container, rootfs, private-path, state, and workspace identities. The row stores
the canonical plan and its digest, and the append-only launch event records the
same plan. A database trigger rejects direct SQL and generic transitions on
ACP-managed SQLite connections unless the journal activates the exact
process-local capability for the registered runc handle. This is an
application-integrity guard, not a security boundary against a privileged
process with arbitrary write access to the SQLite database file: such a process
can register a same-named SQLite function or remove/replace the triggers.
Database-file writers are outside this slice's threat model. Migrated rows
retain empty plan fields and an unattested marker; they cannot be advanced
through a new launch, running, or successful exit transition and cannot
authorize result import. This binds the
caller-supplied bundle digest to observed launch inputs but does not independently
prove the semantic correctness of that caller claim. The configured `run_worker`
path remains fail-closed and this is not runtime isolation evidence.

This remains an implementation slice, not a complete security claim. On
2026-10-05, two opt-in no-model tests passed on NAS Linux 6.18.15 with runc
1.3.5: a pre-exec setup failure reaped the helper, and the public
`spawn_pinned_runc()` path completed the same-UID bundle replacement/rename
attack before reporting live runc state, cgroup controls, effective mount and
capability policy. The exact-host replay source hashes were `oci_worker.py`
`c2025d00a43fcc04661c8f13edaf0f70c166705260bf8d4ec02cf0c6f42927cf`,
`test_oci_worker.py`
`38db6651a479dc13baa542e290cc9da5ed81cd9cea94b1491015e6a5957b1013`, and
`test_oci_worker_runtime.py`
`e860647fb1e0a13265a09bc4d313ee5b3d9d4f2e355e87d2a11c0a6226eb8b2d`. The
exact runc client and worker cgroup were absent after teardown; the external
pytest evidence directory was retained. Two independent reviewers gave GO for
the bounded launcher and cleanup-guard slice. GitHub Actions run `37320832762`
passed all four Ubuntu/macOS × Python 3.11/3.12 jobs on implementation/test-
fixture commit `9a6368d`; this receipt does not cover later documentation-only
commits. Task #2417 records the current PR head and its latest check. The test-only
pre-exec hook exercises same-UID proc-root writes, host config replacement,
bundle rename/recreation, and `setns`; it is not available through the public
API. The `_spawn_pinned_runc_for_unisolated_diagnostic()` and its host-path
`_spawn_pinned_runc()` remain unsafe diagnostic paths and must not be used for
workers.

The current candidate aims to bind the exact bytes and directory objects runc
consumes. The Linux attack test passes, and the independent exact-hash review
returned GO for the schema-21 source/test state described above; that reviewer
did not rerun the test suites. State and workspace remain host-backed directories:
descriptor pinning prevents a launch-time pathname replacement from redirecting
runc, but it does not create a per-attempt filesystem boundary against another
same-UID process that can access those directories. The descriptor-bound config
hash is over the exact rewritten bytes sent to runc, not the compiler's original
path-based bytes. PID-file integrity beyond the pinned state directory,
lifecycle-journal integration, cancellation, crash recovery, cleanup
verification, credential/egress policy, and result import remain separate
gates. `run_worker` remains fail-closed and is not connected to this low-level
launch API.

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
from worker Git metadata. This does not yet provide a registered-worker
execution route: configured `run_worker` does not use the runc launcher and
remains fail-closed. The private repository is untrusted worker state, not a
submission receipt or authorization source.

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
  sandbox only when an outer boundary is already in force. It creates no ACP
  namespace and is not a documented caller-supplied remote executor. The
  current docs classify the App Server command and WebSocket transport as
  experimental and unsupported for production workloads; do not select this as
  ACP's supported production worker path. If that status changes, the App Server
  process must still run inside ACP's independently enforced per-attempt
  boundary, with a local stdio or Unix-socket control channel. See [Codex App
  Server](https://learn.chatgpt.com/docs/app-server).
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

### Lifecycle ownership decision (2026-10-10)

The durable owner must be a systemd-managed transient **service** for each
attempt/fencing epoch, not the API process, its `systemd-run` client, or a
transient scope around a client-launched monitor. Put that service in a
dedicated monitor slice outside the worker attempt slice. It owns the pinned
runc launch handle and its one-shot init gate, observes the exact worker scope,
and is the only component allowed to advance launch/running/exit journal
receipts. Give each execution a non-reusable unit identity bound to the
attempt, claim token, and execution ID. The manager's unit name alone is not
enough: durable adoption must also match the exact invocation ID, control-group
path, main-process start identity, and journaled fencing epoch. If any evidence
is absent or conflicts, classify the execution as unknown and retain the
attempt fence.

The worker scope is a separate systemd object: launch rootless runc with the
qualified systemd cgroup driver into the exact attempt slice, then independently
reconcile/stop that scope and container. `KillMode=control-group` governs the
processes in its own service unit; it is not evidence that a sibling runc scope
was killed. A controller restart may reconnect to the still-active exact
monitor service, but a new controller must never reconstruct the monitor's
in-process runc handle or gate from a PID, path, or self-reported receipt. This
only covers a controller-process restart while the system manager remains
alive: a `systemd --user` manager normally terminates its services after the
last login session ends unless lingering is enabled. The deployment preflight
must therefore prove the chosen manager's lifetime (for example, require
lingering for a user manager); this is not a reboot-survival claim. If the
monitor is gone, recovery must use a separate trusted cleanup/reconciliation
path to prove the exact init identity absent, the stopped container deleted,
the state entry absent, and the worker cgroup empty before recording
`cleanup_verified` or importing results. Ambiguous cleanup stays fenced.

**Production monitor receipt codec (2026-10-11; identity primitive only).** The
durable receipt codec and exact service-reconciliation checks now live in
`supervisor/sandbox_monitor_receipt.py` and are consumed by the opt-in systemd
integration probe. A receipt binds the monitor unit and worker slice to the
full `(attempt_id, claim_token, execution_id)` tuple, plus InvocationID,
ControlGroup, and the monitor PID start identity. Receipt files are bounded,
canonical, no-follow reads from an owner-private directory and create-only
writes; an exact replay is idempotent, while a conflicting replacement is
rejected. Reconnect requires exact active service/slice properties and a fresh
PID-start identity match. This is a reusable production identity primitive,
not a monitor launcher or worker executor: the integration probe still uses a
placeholder service, does not transfer a live runc handle, and does not attest
cleanup or result import. `run_worker()` remains fail-closed.

**Monitor control IPC slice (2026-10-11; not wired to the worker executor).**
`supervisor/sandbox_monitor_ipc.py` adds a Linux Unix-domain server/client around
the request codec. The server checks `SO_PEERCRED` UID and HMAC-fences the full
execution tuple; the client checks peer UID against the configured service
owner and pins PID plus fresh `/proc` start-time identity to the durable monitor
receipt. Status/cancel responses are bounded, allow-listed,
HMAC-authenticated values. The durable request ledger
applies to cancellation only: it creates a mode-0600 acceptance record and
fsyncs it before invoking the monitor-owned handler, then creates a signed
response record. The controller can reuse the same cancellation request ID to
retry; exact retries return the original response. An accepted cancellation
without a durable response returns `unknown` and is never re-applied. Read-only
status polling does not consume ledger capacity. Cancellation requires the
caller to provide and retain a stable 32-hex request ID before sending, so an
ambiguous timeout can be retried with the exact same ID; the client does not
hide a generated ID that the caller could not recover. The ledger is bounded
to 256 cancellation IDs per attempt. The socket and ledger require owner-private
mode-0700 directories; a pre-existing socket path is not removed or replaced.
The server rejects a second concurrent `serve_forever()` loop and cannot be
restarted after its serving loop exits, including unexpected exits.

The IPC permits only `status` and `cancel`: systemd starts the monitor service,
so a controller request cannot ask an already-running service to launch a
worker. Callers must first reconcile exact systemd service/slice properties
against the receipt. The monitor-side cancel callback must act only on its
retained execution handle and exact worker slice, and must be idempotent. The
32-byte capability remains host-private and outside all worker mounts.

This is now a concrete transport/replay primitive, not the production monitor
service: it is not yet launched by systemd, connected to the runc handle or
execution journal, provisioned with a durable capability, or used by
`run_worker()`. It proves neither cancellation nor cleanup nor result import.
`run_worker()` remains fail-closed, and the lifecycle acceptance criteria below
remain open.

**Systemd-owned monitor IPC live slice (2026-10-11; test-only monitor).** The
opt-in `test_live_systemd_monitor_ipc_survives_controller_crash_and_cancels_exact_scope`
now composes the production receipt codec, control-key store, and authenticated
Unix-socket IPC with a real transient user-systemd service. That test-only
monitor places a `/usr/bin/sleep` scope in the exact per-attempt worker slice,
while its own service remains in the separate `user-acp.slice`. A separate
controller writes and validates the durable service receipt, performs an
authenticated status call, then is killed with `SIGKILL`. The fresh controller
uses `reconnect_sandbox_monitor()` to reconcile the exact unit InvocationID,
ControlGroup, MainPID/start identity, and sibling-slice placement before it
reads the existing capability and obtains authenticated status; it then cancels
the exact scope. Repeating the same cancellation request ID returns the
original response; the worker PID and scope cgroup are absent while the monitor
remains active. Status reports `unknown` for activation drift even when a
same-name scope is inactive. Teardown snapshots each unit cgroup before
placement assertions, verifies the original cgroups are empty, and retains the
private fixture if a launched unit lacks a captured cgroup.

The exact replay passed all five tests in
`tests/test_systemd_slice_integration.py` (one identity-drift unit test and four
opt-in live tests) and all twelve
`tests/test_sandbox_monitor_ipc.py` tests on the dedicated no-host-share Lima
guest `acp-sandbox-monitor-20261010`: Ubuntu 24.04.5 LTS ARM64, Linux
`6.8.0-142-generic`, systemd `255.4`, Python `3.12.3`, cgroup v2, and an active
user manager. The controller/monitor IPC test source SHA-256 is
`5445863306b6c0eb04ea7ca6f45e1cc2e27722f5dc6df4409cbda71d7bc3809c`; the
production IPC module is `72f7eea3f9cde1ffacd264465a2ac960f683f78d0279384fc5d797a18bc39a89`,
and the receipt/key module is
`9bb50e5c52fcfeffd494a7f0b7e1489e43b598c24a8542e0d0fa8131020dbe29`. Guest
and checkout hashes matched. Postflight found zero failed units, zero probe
units, zero runc processes, and zero temporary control directories.

This is an IPC/service-lifecycle integration proof only. The monitor is still a
test helper, and its owned process is not an OCI container. It does not prove a
production monitor owning `RuncLaunchHandle`, journal-authorized gate release,
OCI scope enforcement, `cleanup_verified`, result import, provider auth/egress,
or the registered `run_worker()` path. `run_worker()` remains fail-closed.

**Controller restart adoption helper (2026-10-11; production recovery primitive).**
`supervisor/sandbox_monitor_lifecycle.py` now provides a controller-side
reconnect path for an already-running monitor. The caller must supply the
attempt/claim/execution tuple read from its durable execution journal; the
helper requires it to match the immutable service receipt, then re-queries the
trusted user-systemd manager for the exact active service and both sibling
slice identities, including InvocationID, ControlGroup, MainPID, and fresh
PID-start identity. Only after that proof does it read the existing per-execution
control key and validate the monitor socket. Recovery never calls the key
creator: a missing/corrupt key fails closed and leaves the execution fenced.
The helper only reconnects for authenticated status/cancel; it cannot start a
worker or reconstruct `RuncLaunchHandle`. Focused tests cover wrong-fence and
same-name activation drift, exact unit queries, successful reconnect, and
missing-key refusal. The live test above now exercises this production recovery
helper against a placeholder monitor; this remains an adoption primitive, not
an integrated OCI worker path, and `run_worker()` remains fail-closed.

**Monitor producer at the launch-record boundary (2026-10-15; worker still
disabled).** `sandbox_execution_journal._sandbox_execution_record_launch()` now
starts or adopts `start_sandbox_execution_monitor()` only after binding the
exact process-local runc handle, while holding the same per-execution launch
gate lock used by the running transition and cancellation. It passes the
reserved state directory and exact scope/slice identities, then sources the
monitor PID, process-start identity, systemd unit, InvocationID and cgroup only
from the authenticated typed service receipt. A status request must confirm
the exact live scope before the journal records `launched`. Startup ambiguity
leaves the row `reserved`, keeps the launch gate closed and retains its fences.
The service persists its scope binding and control key in the execution's
private monitor directory; adoption reuses the existing receipt and key, while
partial, stale or ambiguous state refuses replacement. The control key is
absent from argv, environment and receipt in the opt-in Linux integration
proof.

The production component, authenticated reconnect and exact-scope cancellation
passed 134 focused tests on the disposable Ubuntu 24.04.5 ARM64 / Linux
`6.8.0-142-generic` / systemd `255.4` guest with cgroup v2 and an active user
manager. The live no-model OCI fixture now exercises this producer through
`_sandbox_execution_record_launch()` while the exact runc init gate is held;
candidate payload writes remain absent until the durable `running` transition.
This is a fixture-driven trusted launch-record path, not a call from
`WorkersMixin.run_worker()`, which remains fail-closed. Journaled termination
`terminate_worker()` records stop intent and revokes the one-shot launch permit
under the registered handle's gate lock. The original controller then closes
an unreleased init gate under that same lock so its fixed trampoline exits on
EOF, and reuses the exact authenticated startup client; it does not run restart
reconciliation from the client-creating PID. If the gate has already been
released, the monitor requests `systemctl stop --no-block` for the exact scope
and only acknowledges a freshly observed `stopping` or `exited` state.
Reconnected controllers use the authenticated recovery path; a supervisor
without the exact process-local handle fails closed before monitor IPC because
it cannot serialize against that handle's gate. Monitor clients bind to their
creating PID and reject status/cancel calls from a forked child. The fork hook
replaces inherited launch registries and global/handle/wait locks, clears
cached key-bearing clients, and closes copied gate writers. Gate-pipe creation
and close bookkeeping are serialized with fork, so a child also closes a
tracked writer in the pre-handle-registration window and cannot delay gate EOF.

A launch still in phase `launched` has no init PID, so its journal phase remains
`launched`; the pre-init stop intent is an append-only hash-chained event rather
than the row's `stop_reason` field. The running transition checks that event
before and under the same lock. A successful monitor acknowledgement in this
case is reported as `stop_pending`, not as a phase change or cleanup proof.
Ambiguous responses retain the durable stop intent and resource fences;
results report journal phase separately from monitor phase and do not infer
`cleanup_verified`. Terminal journal responses reflect durable stop intent in
`stop_requested` and leave `monitor_phase` unset when no monitor query was
made.

The opt-in live no-model OCI fixture passed both
`test_live_monitor_journal_holds_payload_until_durable_running_transition`
branches (`release` and `terminate`) on the disposable Ubuntu 26.04 ARM64 guest
with pinned `runc-1.5.2`, dynamic BusyBox, systemd and cgroup v2. The terminate
branch calls `WorkersMixin.terminate_worker()` after the durable `running`
transition but before the one-shot init-gate release; it verifies the payload
never ran, the exact runc client exited, and the journal records exit without
claiming `cleanup_verified`. To permit this disposable-VM test, the
unprivileged-user-namespace AppArmor sysctl was temporarily set to `0` and
restored to `1` afterward; this is not evidence for operation under the
original AppArmor restriction. Monitor IPC/service unit tests also passed on
that Linux guest. This does not prove production worker integration, real-OCI
cleanup verification, credential/egress policy, result import or
`cleanup_verified`; #2370 remains open. Independent review is rechecking the
final cancellation and fork-safety diff and found no P1/P2 blocker. The
same-user systemd stop-by-name time-of-check/time-of-use race remains a
separate hardening item.

Do not add a lazy producer call to `terminate_worker()`: launch recording is
the safe integration point because it runs with the registered handle and
exact lock after scope creation but before the durable running transition and
one-shot permit release. `run_worker()` still has no supported OCI launch
caller and must remain fail-closed. Likewise, a monitor's `exited` status is
not the journal's independent `cleanup_verified` proof; monitor retirement
must follow that verifier and reconcile the exact unit activation. Those
worker-path and cleanup requirements remain open.

**Per-attempt coding-agent architecture decision (2026-10-11; NO-GO to wire
unchanged).** Do not treat the existing namespace resource driver as the
supervised coding-agent sandbox. [`WorkersMixin.run_worker()`](../src/agent_control_plane/supervisor/workers.py)
launches the candidate through the process trampoline with the attempt worktree
as `cwd` but does not enter the namespace resource-driver path or an outer
filesystem/network namespace. When OCI is configured it refuses the launch
rather than falling back to host execution. [`NamespaceRuntimeDriver`](../src/agent_control_plane/runtime_drivers.py)
is a separate systemd resource-payload path: it requires rootless user/mount/PID
namespaces (plus a network namespace for deny-egress), mounts `ACP_WORKTREE`
read-only at `/workspace`, provides a separate writable `/work`, and currently
bind-mounts host `/usr`, `/bin`, `/sbin`, and `/lib*` read-only. It now creates
a minimal fixed `/etc/os-release` instead of mounting host `/etc` (2026-10-11;
structural tests added and a disposable Ubuntu 26.04 guest probe passed;
exact-head hosted CI and target-host qualification remain pending). The
remaining broad host `/usr` and toolchain exposure, read-only workspace, and
lack of private Git metadata still fail the coding-agent contract. Reuse is
rejected until those gaps are closed and measured.

Codex's `externalSandbox` is not an enforcement mechanism: App Server
documentation says to use it only when the server process is already
sandboxed, because it skips Codex's own sandbox for the command. The supported
boundary must therefore be independently enforced around each attempt before
that policy is considered. In particular, if Codex App Server remains the
trusted host-side harness, do not use `externalSandbox` on the assumption that
it isolates only a child command; it disables Codex's own command sandbox and
does not create the attempt boundary ([Codex App Server](https://learn.chatgpt.com/docs/app-server),
[Agent approvals and security](https://learn.chatgpt.com/docs/agent-approvals-security)).
The first architecture candidate is a provider-independent ACP executor
contract running in a per-attempt Linux namespace, with the trusted harness,
credential broker, and result importer outside that namespace. The worker gets
only an attempt-private writable file tree, a minimal generated `/etc`, an
audited read-only executable/library closure, and no host home, temp, socket,
credential, or shared Git-object paths. Attempt egress is denied by default;
trusted harness/model traffic remains outside the attempt namespace, and any
worker-side provider access must go through an independently authenticated,
narrowly scoped broker. This namespace candidate trusts the target host kernel:
Linux namespaces isolate selected resources, not the kernel itself. If host
kernel compromise is in scope, require a disposable VM/microVM (or another
separate-kernel boundary) before accepting the design; namespace-only tests do
not prove kernel-escape resistance. A snapshot/patch is validated and staged by the host-side
supervisor; candidate processes never receive the shared checkout's `.git`
pointer or object database. This is a hypothesis to prove, not implemented
behavior. OpenAI's self-hosted executor is a provider-specific alternative:
the harness remains outside the environment and the inside environment key is
limited to environment-connection actions (not other API actions), but the key
itself is readable by agent-generated code; the cited documentation does not
establish that a key is restricted to exactly one environment ([Self-hosted
sandboxes](https://developers.openai.com/api/docs/guides/agents-api/environments/self-hosted)).

Current source-level constraints and deployment evidence:

| Item | Current evidence | Required before launch |
| --- | --- | --- |
| OS/runtime | Linux user, mount, PID, and optionally network namespaces; systemd user service and delegated cgroup v2 are required by the current resource driver. | Disposable target-host probe of namespace, cgroup, systemd-manager lifetime, and mount policy. |
| Kernel/distribution | **MISSING** for the target NAS; no live-host version or capability result is claimed. Namespace isolation also trusts the host kernel. | Record exact kernel/distribution and required namespace/cgroup settings from an approved disposable Linux lane; use a VM/microVM if the host kernel is not in the trust boundary. |
| Codex adapter | The repository has no pinned Codex CLI/App Server in this execution path. The current App Server docs describe stdio/Unix socket transports; WebSocket transport is marked experimental/unsupported. | Pin an exact binary/version and protocol schema, then test it inside the proven boundary without a model call. |
| Authentication | No host Codex config, OAuth file, API key, or Git credential may be mounted into the candidate tree. | Prove a brokered/least-privilege auth path or reject the adapter; no credential material has been tested here. |

**Evidence update (2026-10-15).** The primitive-level Linux boundary checks are
now demonstrated by the opt-in
[`test_live_rootless_runc_enforces_minimal_worker_boundary`](../tests/test_oci_worker_runtime.py),
in a disposable Linux guest. The recorded Ubuntu 26.04 replay used test source
SHA-256 `4942bff7abed3b4e9b65562711cb2c3847b09b766539825f4da9d718a0e34b7c`
and `oci_worker.py` SHA-256
`7d68fb55375ab167b73a6cf49ca86a30aa84933d7eb7ed2a9d590dafe78e8236` (PR-42
snapshot `cedfecdaa59affb19edd68a2d8173be2b1f17b5d` with the test file
overlaid; detailed receipt below). It audits the exact mount set and rejects
broad `/etc` or `/usr` mounts; the compiled OCI `process.env` check asserts the
enumerated credential/config variable names are absent (it is not a runtime
`/proc/environ` readback). Current `oci_worker.py` also has a subsequent
optional pre-exec submission callback; this direct probe does not supply it, so
the callback is outside this live-runtime evidence. The payload cannot read the
host checkout, sibling attempt, unrelated project, host-home path, synthetic
config/credential sentinels, or host `/etc` and `/tmp` sentinels; separate
probes deny writes to the checkout, the image's `/etc`, and host `/tmp`. It
confirms the host Unix-socket sentinel path is absent. Absolute and relative
symlink targets cannot be read, and the absolute host-`/tmp` symlink cannot be
used for a write.
The probe also checks the worker's namespace-relative `/proc` identity and
proves loopback-only interfaces plus failure to reach a host-NIC listener. The
markers are synthetic, not real credentials. This closes those direct-runc
boundary checks only; it is not an exact-head hosted replay of the live probe
and does not exercise the registered production worker lifecycle.

The architecture decision remains **NO-GO for production worker integration**.
Do not set `externalSandbox`, mount host credential/config paths, or change the
fail-closed `run_worker()` behavior. Still open are a supervisor-owned
`run_worker()` executor, least-privilege provider authentication and enforced
provider egress, restart/cancellation recovery, action-bound cleanup proof,
concurrent-attempt fencing, and validated isolated Git result transfer into
the existing QC/submission path. Exact-head hosted CI is required for code
changes, but it does not replace the separate live Linux boundary evidence.

This choice is consistent with systemd's distinct transient service/scope
lifecycles and unit-level cgroup controls ([`systemd-run(1)`](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html),
[`systemd.kill(5)`](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html),
[`systemd.resource-control(5)`](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html)).
The opt-in [`test_systemd_slice_integration.py`](../tests/test_systemd_slice_integration.py)
does prove that a systemd-owned monitor service can be reconciled after its
controller is SIGKILLed and can survive a separate worker-slice stop. Its own
module documentation correctly limits that evidence: it does not launch or
attest the ACP OCI worker, recover its runc handle, exercise authenticated
cancellation, or verify cleanup/result import. The service-owner pattern is
therefore the integration direction, not a completed executor; `run_worker`
remains fail-closed.

New v6 launch plans derive the monitor unit name from the complete
`(attempt_id, claim_token, execution_id)` identity; the journal rejects launch
receipts that reuse a generic service name. Existing v5 plans retain their previous
read/validation semantics. The unit name is only a collision-resistant
lookup key: adoption still requires its exact systemd invocation ID, cgroup,
and live monitor identity, plus the durable launch-plan binding. The monitor
must load and revalidate operator configuration in its own process; serializing
the caller's `_PinnedRuncWorkerConfig` or `RuncLaunchHandle` would not transfer
their process-local provenance. This naming guard narrows one adoption/replay
ambiguity but does not implement monitor startup, authenticated reconnect, or
worker execution.

**Write-ahead runc submission latch (schema v28; fail-closed primitive).** A
supervised monitor must now commit a one-time receipt for the exact pinned
private-bundle target immediately before the launcher's exec acknowledgement.
The `reserved -> launched` journal transition requires that receipt, and the
SQLite write guard prevents a second authorization for the same fenced
execution. If the monitor dies after the latch but before it records the
returned process handle, a restarted process cannot resubmit; it must reconcile
the exact runtime state or retain the attempt fence. This deliberately favors
duplicate-launch safety over automatic retry when the crash point is ambiguous.
The callback returns a process-local capability that the private launcher
stores in the registry record for the exact returned handle; journal recording
checks object identity against that handle. Before sending the exec
acknowledgement, the launcher rejects missing, unrelated, or differently
targeted callback results. A capability minted after an unjournaled handle
already exists cannot be paired with it. Unit coverage exercises
commit-before-marker ordering, post-launch pairing rejection, invalid callback
results, and cross-process at-most-once authorization. It does not substitute
for a live Linux launcher test.
The callback and journal primitive are not wired to `run_worker`, and no
production monitor owns the callback yet. They do not prove restart recovery,
cleanup, cancellation, or worker isolation; OCI worker execution remains
fail-closed.

### Provider egress destination-policy primitive (2026-10-15; unit proof only)

`supervisor/provider_egress.py` adds a provider-neutral exact host/port policy
and destination resolver for a future supervisor-owned HTTPS CONNECT proxy.
It accepts ASCII DNS names (including caller-supplied A-labels), rejects
Unicode U-label input rather than applying IDNA2003 folding, accepts a single
trailing dot, and rejects IP-literal authorities. Exact allowlist matching
precedes an absolute-name system-resolver invocation. Every address returned
by that resolver is classified; a mixed public and forbidden result fails as a
whole. Private, loopback, link-local, multicast, reserved, unspecified,
IPv4-mapped IPv6, and other non-global addresses are rejected. The policy-owned
`connect_authority()` path resolves and classifies before dialing the numeric
socket address, without a second hostname lookup. The original hostname is
retained for the eventual worker client's TLS SNI and certificate validation.
The public dial API accepts an authority, not a caller-supplied pin; its
private helper is trusted process code, not an isolation boundary against other
code running inside the same supervisor process.

The explicit special-use network snapshot follows the [IANA IPv4 registry](https://www.iana.org/assignments/iana-ipv4-special-registry)
and [IANA IPv6 registry](https://www.iana.org/assignments/iana-ipv6-special-registry),
both last updated 2025-10-09. It deliberately rejects all listed special-use
blocks, including a small number the registry marks globally reachable. Review
and refresh the snapshot when the registries change; `ipaddress.is_global`
alone is not sufficient for this deny policy.

The 33 focused tests passed with `uv run --frozen pytest -q
tests/test_provider_egress.py`; Ruff check and format checks passed. They cover
authority normalization and exact matching, invalid policy, bounded port
parsing, empty and mixed resolver results, special-use address rejection,
A/AAAA pin construction, the trailing-dot resolver argument, and a fake-socket
assertion that policy-authorized dialing uses the vetted numeric sockaddr with
no second hostname lookup.

The policy primitive alone does not prove worker reachability is restricted to
a per-attempt proxy, same-UID denial in a disposable worker guest, socket-FD
hygiene, TLS CONNECT behavior, redirect handling, real DNS resolver behavior,
credential delivery, or provider authentication. A blind HTTPS CONNECT proxy
gates only the requested authority and pinned IP. It cannot inspect encrypted
SNI, HTTP `Host`, URL/path, API method, or redirects, nor stop exfiltration to
an explicitly allowed provider hostname. A redirect destination requires a
fresh CONNECT request and its own policy decision.
The existing systemd `LoadCredential=` evidence establishes read-only
per-unit visibility only, not secrecy from the host UID or root. No code here
is wired to `run_worker()`, and configured OCI worker execution remains
fail-closed.

### Provider CONNECT handler primitive (2026-10-15; socketpair/TLS unit proof)

`supervisor/provider_proxy.py` adds a one-CONNECT-per-channel handler and an
`attempt_scoped_peer_authorizer()` callback factory. The factory requires a
collector-issued, self-consistent runtime attestation; on Linux it checks the
accepted Unix stream's `SO_PEERCRED` UID/GID against the supervisor's mapped
host UID/GID, then verifies the peer PID's stable start identity and exact
attempt cgroup through before/after `/proc/<pid>/stat` reads around
`/proc/<pid>/cgroup`. Before resolving that numeric PID, it acquires Linux
`SO_PEERPIDFD` (UAPI option 77) and holds the close-on-exec descriptor through
the procfs check, preventing PID reuse between the `SO_PEERCRED` snapshot and
the first `/proc` lookup. The Linux v6.5 UAPI header defines the option
([source](https://github.com/torvalds/linux/blob/v6.5/include/uapi/asm-generic/socket.h#L128-L130));
the kernel's coredump path documents using it to guard `/proc/<pid>` against
PID recycling ([source](https://github.com/torvalds/linux/blob/master/fs/coredump.c)).
Python need not expose a named constant; unsupported kernels or failed
`getsockopt` probes deny authorization. The supervisor's `/proc` view must use
the same PID namespace as `SO_PEERCRED`. A same-UID process outside the exact
cgroup is denied. PID pinning does not make the cgroup observation atomic or
prevent a process with sufficient cgroup permissions from moving after the
check. This primitive does not bind or protect a listener, distribute its
socket to the worker, or manage socket lifecycle. `SO_PEERCRED` and
`SO_PEERPIDFD` identify the process that established the Unix connection, not
a later process that receives the connected channel through `SCM_RIGHTS` or
inherits its descriptor. Any worker integration must control channel
distribution and clear unintended inherited descriptors before launch. The
handler still requires the caller to install the callback before request
parsing or dialing. It
rejects malformed CONNECT requests, request bodies, proxy credentials, mismatching
`Host` fields, tunnel bytes co-read with the CONNECT headers, and tunnel bytes
already queued when a post-dial preflight runs before the 200 response. A byte
that arrives after that check races acceptance and is relayed unchanged; the
protocol handler cannot provide a strict temporal boundary on a TCP stream.
After policy approval it relays raw TLS bytes bidirectionally with bounded
buffers and idle timeout. A redirect therefore needs a fresh channel and a
second independent authority decision.

The local TLS mock test proves the handler can tunnel a TLS request, return an
HTTP 302 received inside TLS, and reject the client's next CONNECT to a
non-allowlisted host before DNS or a second dial. The test injects a dial to
its loopback TLS fixture only through a private test monkeypatch; the
production policy still classifies a public test address, and production code
cannot select the local target through policy configuration. Linux unit tests
exercise real `SO_PEERCRED` and `SO_PEERPIDFD` on a same-process socketpair,
confirm the PIDFD fdinfo PID matches `SO_PEERCRED`, run the actual `/proc`
membership verifier while that PIDFD is open, and verify it is closed on
return. A separate child-process test terminates and reaps the peer immediately
after PIDFD acquisition, confirms the pinned PIDFD reports an exited process,
and verifies that the real proc check rejects it. This does not force numeric
PID reuse; the no-reuse claim rests on the cited kernel PIDFD semantics. The
tests also fail closed when the option is unavailable and deny a peer whose
cgroup differs. They do not prove an actual worker socket in a disposable
guest, listener-path or FD hygiene, provider-SDK compatibility, credential
delivery, or authentication.
No live guest, systemd integration, credential handoff, or `run_worker()`
integration is claimed; configured OCI execution remains fail-closed.

### Supervisor restart: public cancellation and launch-gate fencing (2026-10-15)

The public `terminate_worker()` path now survives loss of the supervisor's
process-local launch handle without falling back to a host PID. Gate release,
the launched-to-running transition, stop intent, exit, and ambiguity transitions
share an exclusive advisory lock on the exact private execution state
directory. The directory must still match its durable device/inode identity,
owner, and `0700` mode, both before and immediately after lock acquisition. A
busy lock or identity mismatch leaves the journal unchanged. The gate writer
re-reads the matching attempt and execution under that lock and requires
`working` + `running` with no durable stop intent before writing `go`; therefore
a fresh supervisor's stop intent fences a still-live parent's delayed gate
write. Fork children close inherited lock descriptors so they cannot retain the
kernel lock after the owning process exits. This is cooperative lifecycle
fencing, not protection from a hostile same-UID process that can mutate the
supervisor-owned state directory outside this API.

No-model regression coverage now includes a spawned fresh `GitSupervisor`
calling public `terminate_worker()` twice, authenticating the exact execution
and scope, checking status, and replaying the same deterministic cancel ID.
Separate checks prove busy-lock non-mutation, wrong-state-root rejection, and
fork-child lock-FD cleanup. A test double models only monitor IPC in this
public-API regression; the disposable systemd producer/reconnect/cancel test
above remains the independent real-service evidence. Cancellation returns
`stopping` and retains cleanup/resource fences; it does not imply the vanished
supervisor's runc `Popen` handle was recovered or cleanup verified. Configured
OCI `run_worker()` remains fail-closed.

After this fence change, the disposable Linux/systemd production monitor test
was rerun on Ubuntu 26.04 ARM64, Linux 7.0.0-38-generic, Python 3.14.4,
systemd 259.5, and cgroup v2: **1 passed, 7 deselected**. Host and guest
SHA-256 matched for all eight copied production source/test files in the
production-monitor section below. The exact monitor fixture and unit cleanup
passed; postflight found the user manager running, no matching ACP test units,
and no `acp-production-monitor-*` fixture roots. That live test validates the
monitor producer/reconnect/cancel only; fresh `terminate_worker()` recovery is
separately covered by the spawned no-model supervisor regression above.

### Cleanup proof boundary (2026-10-11; architecture/QC decision)

Do not add an observer that writes `cleanup_verified` from absence checks alone.
The current `cleanup_reported` receipt is an identity-bound template: its
observations are null, and it contains no trusted receipt for the exact pinned
`runc delete` invocation or its exit. `runc --root` selects the runtime state
store, while `runc state` and `runc list` are read commands; absence from a later query does
not prove which actor performed deletion or that no actor can recreate state
before the journal commit. The command semantics are documented by upstream
[runc](https://github.com/opencontainers/runc/blob/main/man/runc.8.md) and
[runc-delete](https://github.com/opencontainers/runc/blob/main/man/runc-delete.8.md).
Bind the delete action, kernel wait result, and post-delete observations to the
same fenced monitor execution; no observation-only receipt may release the
attempt fence.

Systemd absence checks must also be conjunctive. `systemctl show` can succeed
for an unknown unit and report `LoadState=not-found`
([systemd issue #1105](https://github.com/systemd/systemd/issues/1105)); an
upstream edge report also demonstrates `LoadState=not-found` alongside
`ActiveState=active`
([systemd issue #43442](https://github.com/systemd/systemd/issues/43442)).
Therefore `not-found` alone is not cleanup evidence. First bind the expected
unit name, invocation ID, control group, and (for the monitor) main-process
start identity to the durable launch receipt. Then query that exact unit name:
if it is `not-found`, require the response to be internally consistent
(`ActiveState=inactive`, empty `ControlGroup` and `InvocationID`; for the
monitor service, `MainPID=0`) and independently verify the original PID-start
identities are absent. Also verify the exact attempt cgroup subtree and private
paths are empty/absent under their recorded root identities. Any command error,
timeout, permission gap, reused/mismatched identity, or contradictory property
retains the fence.

Those checks are still point-in-time observations. The verifier may commit only
after the monitor has durably recorded its exact delete/wait outcome and can no
longer launch, stop, or recreate execution resources for that fencing epoch.
Serialize final verification and the immutable proof-digest journal transition
against that owner; inject crashes and state/unit ABA changes between delete,
observation, and commit. Until this owner/serialization path exists, keep
`cleanup_verified` transitions guarded and OCI `run_worker` fail-closed. This
decision deliberately does not add a cleanup collector: a typed snapshot would
not solve the missing action provenance or close the probe-to-commit race.

**Systemd post-stop boundary (2026-10-11; disposable Linux probe).** Upstream
systemd documents that `ExecStopPost=` also runs after unexpected service exit.
In the task's disposable Ubuntu guest (kernel `6.8.0-142-generic`,
systemd `255.4-1ubuntu8.17`), an exact `systemd-run --user --wait` probe observed
the hook under `<unit-cgroup>/.control`; systemd may place delegated hooks there.
Only after the hook and wait returned
did `systemctl show` report `LoadState=not-found`, `ActiveState=inactive`,
`MainPID=0`, and empty `ControlGroup` and `InvocationID`. Thus `ExecStopPost=`
cannot certify that its own unit or cgroup is absent. The monitor main process
must durably persist an immutable receipt for its pinned `runc delete` action
and wait result before exiting. A finalizer must run after the complete stop
job (including any `ExecStopPost=`) returns, verify the pre-bound unit/process
identities and empty cgroup/private paths, and require that action receipt as
well as those fresh observations before committing `cleanup_verified`. The
captured InvocationID must remain bound to the unique fencing-epoch unit name;
a missing or contradictory live unit state is not, by itself, evidence of a
matching stop. A crash before the action receipt is durable remains ambiguous;
later `runc state` absence must not trigger a retry or release the fence. The
opt-in regression is
`test_exec_stop_post_is_not_final_unit_absence_evidence`; this is systemd
lifecycle evidence only, not a cleanup verifier or integrated-worker proof.
See upstream [systemd service lifecycle documentation](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
and [cgroup delegation documentation](https://github.com/systemd/systemd/blob/main/docs/CGROUP_DELEGATION.md).

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
path-replacement window for the configuration probe. The following describes
the earlier hold, superseded by the private-bundle implementation above:
`spawn_pinned_runc()` originally refused to launch while bundle ownership was
unproved. The current candidate path uses a private read-only tmpfs and
descriptor-anchored `--bundle`. A direct exact-host adversarial replay for this
handoff is recorded in the evidence history below. The current runtime/test
sources passed the exact-host replay, and two independent reviewers gave GO for
the bounded launcher and cleanup-guard slice. GitHub Actions run `37320832762`
passed all four Ubuntu/macOS × Python 3.11/3.12 jobs on implementation/test-
fixture commit `9a6368d`; this receipt does not cover later documentation-only
commits. Task #2417 records the current PR head and its latest check. The
unisolated diagnostic helper remains unsafe and is not called by `run_worker`.
The earlier statement that no runtime path/digest was tied to the journal before
candidate exec is superseded: the current journal commits a one-use
`launch_submission_digest` over every descriptor-backed target field, including
the verified pinned-runc path/digest, config digest, argv, bundle/rootfs/state/
workspace path identities, and resource limits, before the private launcher's
exec acknowledgement. This is a commitment to the launch target, not to every
reservation field. After the returned handle is bound, the journal persists the
canonical readable launch plan and the `launch_target` payload in
`sandbox.execution_launched`. These records bind launch intent; they do not
prove successful production `run_worker()` execution, and an ambiguous
post-latch crash remains fenced and cannot resubmit. The attempt journal still
cannot reach `cleanup_verified`.
When `[sandbox.oci]` is configured, `run_worker` continues to fail before
heartbeat or process reservation with `sandbox_executor_unavailable`; it cannot
silently fall back to host execution. The direct live test exercises a claimed
attempt and journaled launch components through a test fixture, not the
production `run_worker()` lifecycle; it establishes no result-import or
crash/cancel recovery claim.

The contained process trampoline now has an opt-in Linux `exec_fd` input: the
trusted monitor passes a caller-held regular-file descriptor to its blocked
command child, executes that inode with `execve(fd, ...)`, and closes both the
monitor's copy and the descriptor across the final exec. A regression unlinks
the opened interpreter before launch, successfully executes it despite the
missing pathname and nonexistent `argv[0]`, and confirms the descriptor is not
visible to the target.
This closes the generic path-substitution gap for a future held-runc launch,
but no current `run_worker` route uses the configured runc pin; OCI worker
execution remains unavailable and fail-closed.

### Durable execution-journal slice (2026-10-04)

Schema 14 introduced a private, per-attempt `sandbox_executions` journal. Reservation
binds the current claim token, an ACP-generated container ID, attempt-specific
bundle/state paths, the bundle and rootfs digests, and exact runc/OCI versions.
New container IDs are `acp-` plus a 240-bit SHA-256 prefix over the canonical
full `(attempt_id, claim_token, execution_id)` tuple; they do not use a short
execution-ID prefix as a cross-attempt discriminator.
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
and cannot be replaced. After schema 17 or later migrations, exact persisted
pre-17 version-1 and version-2 receipts may replay in their original shape;
replay does not add the new content pins or upgrade their evidence.
`cleanup_reported` is therefore not
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
then reopens the exact baseline and workspace roots by walking every path
component without following symlinks, checks their saved inode identities, and
verifies the complete baseline tree. Directory opening rejects lexical `..`
components; relative source paths are anchored to the current directory without
resolving symlinked ancestors. After that filesystem work it revalidates the live claim,
credential, and exact persisted binding fields in a serialized transaction
before returning; any later result capture or import must still perform its own
transactional fence check. The restore step also reopens the exact execution, bundle, and
runc-state roots by saved device/inode; future result capture must recheck the
workspace root identity and still pass the mutable tree through `collect_changes`
as hostile output. This closes the process-local `Snapshot`-provenance gap for
baseline recovery and detects replaced runtime paths at each check; it does not
close same-UID races between revalidation and later use, impose an aggregate
workspace disk quota, produce a worker-exit/cleanup attestation, or enable result
import. No worker launch route, trusted cleanup verifier, or sandbox
result-import route is added here, and direct-worker
behavior is unchanged. Schema 16 adds a separate non-authorizing candidate
receipt, described below. The SQLite triggers enforce ordinary journal transition
and write-once invariants; they are not an adversarial boundary against a
same-UID process with raw database-write access. A future executor must keep the
supervisor database outside the worker's mount namespace.

**Versioned result-candidate evidence (schema 16; non-authorizing).** After a
successful recorded runc-client exit and cleanup verification, the host can
reopen the durable workspace binding, scan the mutable tree through
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

**Candidate-capture quiescence gate (2026-10-10; fail-closed hardening).** The
capture API now requires `cleanup_verified` both before scanning the mutable
workspace and again before persisting the candidate; `cleanup_reported` alone
is rejected without writing a receipt. This closes the supported-API path that
could run while cleanup was still unverified and a surviving process might
still mutate the workspace. Schema 27 migrates the write-once SQLite trigger
to enforce the same `cleanup_verified` phase. There is still no production writer for
`cleanup_verified`, so production candidate capture remains unavailable. Tests
that exercise downstream capture/import deliberately synthesize that phase by
dropping the transition trigger and remove the private bundle/state directories;
they are not verifier, monitor, or live-runtime evidence. A future verifier
must establish durable workspace quiescence and bind its own immutable proof
digest to candidate/import evidence before this gate can become reachable in
production. The unkeyed cleanup-report digest remains insufficient for that
purpose.

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

**Private runtime-path binding (schema 18; still not an executor).** The
reserved-to-bound workspace transaction now also records device/inode identities
for the private execution root, OCI bundle root, and runc state root. The
launcher transition and post-restart workspace restore reopen these exact
directories without following symlinks in any path component and reject a
replacement at the same pathname. Legacy rows have unknown path identities and
are not backfilled; they cannot advance to launch or produce a new candidate. This enables a future
cleanup collector to address only the paths created for its exact attempt. It
does not remove those paths, verify runtime teardown, close same-UID races
between check and use, or write `cleanup_verified`. `run_worker` remains
fail-closed for configured OCI.

**Source-discriminated result-import journal (schema 19; sandbox import remains
cleanup-gated).** Existing result-import rows migrate as `direct_worker`, preserving
their worker PID/receipt and staged-object inventory. New sandbox-source rows
have no direct-worker PID or worker-exit receipt and are structurally bound to
the exact `(attempt_id, execution_id)` plus a cleanup-receipt digest. Database
guards reject direct-worker rows for attempts with a sandbox journal in either
insertion order and reject ordinary `UPDATE` statements that change persisted
source identity; a pre-migration mixed-source row stops the upgrade rather than
being relabeled. The existing direct-worker INSERT shape remains compatible.
These SQLite triggers are not a boundary against raw database writers; for
example, replacement-style writes can bypass update-only immutability checks.
These constraints separate receipt identities but do not produce or authenticate
a cleanup receipt. `import_sandbox_execution_result` now reconstructs a
candidate from the durable claim-time baseline and sandbox workspace, then
imports it through the common host-built tree/commit, staging, ref-publication,
and idempotent recovery path. Its import row carries `source_kind`, the exact
execution ID, and the digest of the persisted cleanup report; it carries no
worker PID, identity, or exit receipt. Recovery and submission recheck that
source binding, candidate digests, and the `cleanup_verified` eligibility gate.
For a `cleanup_verified` row, workspace restore additionally requires the
private bundle and runc state directories to be absent while the recorded
execution-root identity and workspace/baseline bindings still match. The
cleanup-report digest identifies the journaled report; it is not proof that the
report is trusted or verified. No trusted cleanup verifier or production writer
for `cleanup_verified` exists yet, so the new route still fails closed for real
executions and `run_worker` remains fail-closed for configured OCI. The route's
success/recovery test constructs synthetic already-verified journal state only
to cover downstream import logic; it is not cleanup-verifier or live-runtime
evidence.

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

No worker executor currently calls the collector or integrates public gate
release. Collector tests use synthetic runc/systemd values; opt-in OCI tests
exercise the launcher/policy only and do not provide observation provenance.
The Python receipt type and unkeyed digest can detect accidental inconsistency
only; an in-process caller can construct a receipt and recompute its digest.
They do not prove the observations' provenance, provide a signature, or form a
boundary against a compromised supervisor process. The feature remains
fail-closed and no worker isolation or authenticated runtime attestation is
claimed.

**Journal-gated init release (2026-10-06).** The public
`RuncLaunchHandle.release_gate()` now refuses release until the exact registered
handle is bound to the attempt/execution and `_sandbox_execution_record_running`
has committed the matching `running` transition. The same per-handle lock now
serializes that transition and permit issue with supported cancellation
(`running` to `stopping`), exit, and quarantine transitions; those transitions
revoke any unconsumed permit before releasing the lock. Gate release consumes
its permit and writes `go\n` under that lock. A stop request before `running`
remains rejected by the journal's phase constraints.
Thus a stop that commits first cannot be followed by gate release, while a gate
release that wins first may start the command before a later stop commits; the
actual process-kill/reaper path remains unimplemented. This is sequencing
hardening only: the running transition still accepts a self-consistent receipt
whose observation provenance is unauthenticated, so it is not proof of
independent runtime attestation. The low-level launcher tests keep their bypass
inside test modules; it is not shipped as a production helper and is not
evidence of a supervised worker path. `run_worker` remains fail-closed for
configured OCI; no supervisor-managed runc launch or result import is claimed.

**Release-time process/cgroup recheck (2026-10-09; guard hardening only).**
Before the journal records `running` or authorizes the one-shot gate permit, it
now re-reads `/proc/<pid>/stat`, `/proc/<pid>/cgroup`, and `/proc/<pid>/stat`
for the recorded monitor, runc client, and container init while holding the
exact launch-gate lock. Each process must retain its collected start identity
and live state; monitor and runc client must remain in the wrapper cgroup, and
init must remain in the recorded runc scope. The same release-locked path also
re-reads the cgroup-v2 memory, CPU, and PID limits. Synthetic regressions cover
PID reuse, process exit, cgroup movement, gate-lock ordering, and a shut gate on
drift. These sequential reads narrow a stale-receipt window; they are not an
atomic procfs/cgroup snapshot, and process exit or movement after the reads
remains a race. At the time of this 2026-10-09 change, systemd invocation
properties were not re-queried at release; the 2026-10-10 release-time identity
gate below adds that check. No production worker calls this path: OCI
`run_worker` remains fail-closed and end-to-end worker isolation is unproven.

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

### Fresh host-facts recheck (2026-10-05; read-only)

A fresh SSH inventory returned Debian 12 (bookworm), Linux 6.18.15 x86_64,
`systemd 252.39-1~deb12u2`, rootless `runc` 1.3.5 / OCI spec 1.2.1,
`cgroup2fs`, and caller UID 1000. This updates the current binary-version
observation; it does not establish when systemd changed from the earlier
252.38 sample, prove that the user manager is healthy, or qualify any worker
execution path. These are host assumptions for bounded no-model tests only.

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

### Exact-head cleanup revalidation (2026-10-09; pass)

The opt-in live test was rerun from exact PR #42 head
`1d78813a96af210da4cf096053dff097c6b6e1a8` in a disposable Lima 2.2.1 VZ
Ubuntu 24.04.5 ARM64 guest (kernel `6.8.0-142-generic`, uid 501) with no host
mounts. The test file SHA-256 was
`9a54375ea682aea68ee8ce9630da0b82c264dca89335edbc0abc5fb623487c95`; the
unchanged OCI worker module was
`5aed95084724828544b0c6f09ac17653983caff57f16498fd31950b5b42c4092`.
Root-owned runc 1.3.5 was verified against the official ARM64 release asset
SHA-256
`bd843d75a788e612c9df286b1fa519a44fcbb7a7b8d01e2268431433cc7c718c`, with
Ubuntu dynamic BusyBox 1.36.1. The single invocation of
`test_live_rootless_runc_enforces_minimal_worker_boundary` passed.

The live receipt reported `rootfsPropagation=rprivate`, the expected
`memory.max=134217728`, `pids.max=16`, and `cpu.max=50000 100000`, all five
capability sets zero, and `NoNewPrivs=true`. The candidate saw only `lo`; its
probe could not reach the host-NIC listener. Checkout, sibling-attempt,
unrelated-project, home/config/credential, host `/etc` and `/tmp` sentinels,
and absolute/relative symlink targets were denied. Teardown removed the
attempt tree and checkout canary; postflight found no runc process or ACP
systemd scope. The guest-only
`kernel.apparmor_restrict_unprivileged_userns` value was restored from `0` to
its original `1`.

This rerun exercises the changed test-harness cleanup on its successful live
path; identity-replacement failures are covered by the focused regressions and
exact-head CI. The receipt still reports `worker_executor_integrated=false`.
It is not evidence of `run_worker` isolation, provider authentication or
egress, result transfer, crash/cancellation recovery, or full task #2370
acceptance.

### AppArmor-gated OCI boundary replay on runc 1.5.2 (2026-10-10; pass)

The exact `d22483ce6c566df514936c83f7bd500a7f1fb594` source and test were
copied into the no-host-share Lima guest `acp-oci-qc-20261009` (Ubuntu 24.04.5
ARM64, Linux `6.8.0-142-generic`, cgroup v2, active user manager, Python
3.12.3, pytest 7.4.4). The 48-file package-source tree digest was
`6f0c9f40249f42ffc22ad61274f8a0837c3d76b21a66da8be12f875bf83aaa1a`; the
tested `oci_worker.py` SHA-256 was
`d3891165e4ec1b11c4997188cfdea3108e3fb8edff17a0ec7f92f5d541d1991d`, and
`test_oci_worker_runtime.py` was
`697b39229d436cf65bf0984921ed4513e1d47d3fa324938d4af34317f177e824`. A
separate root-owned `/usr/local/bin/runc-1.5.2` was installed from the
[official runc v1.5.2 ARM64 release asset](https://github.com/opencontainers/runc/releases/tag/v1.5.2)
only after its SHA-256 matched the GitHub release API digest
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`;
the pre-existing runc binary was not replaced. BusyBox was 1.36.1.

With the guest's default `kernel.apparmor_restrict_unprivileged_userns=1`,
the live integration attempt from an unconfined shell stopped before runc exec:
the private bundle helper received `EPERM` at mount-namespace setup (phase 4).
A direct `unshare` check also failed under that policy. The guest already had
AppArmor 4.0.1's packaged `/etc/apparmor.d/runc` profile (SHA-256
`e97400404d8b8e85ce3e458558105ec218276efab10b355c7a6086a90ad0b4c6`): it is
`flags=(unconfined)` with an explicit `userns,` rule. The upstream AppArmor
[user-namespace policy notes](https://gitlab.com/apparmor/apparmor/-/wikis/unprivileged_userns_restriction)
describe this per-profile permission path. `aa-exec -p runc -- unshare
--user --map-root-user --mount --fork -- /bin/true` passed while the sysctl
remained `1`.

The first profile replay exposed an unclosed `Popen` pipe when private-bundle
setup failed before a launch handle could be returned. `_reap_failed_runc_launch`
now closes the caller-unreachable stdin/stdout/stderr handles in `finally`, with
a regression test. Only `oci_worker.py` and `test_oci_worker_runtime.py` were
then overlaid into the same guest; their tested SHA-256 values were
`60e5b1ef264de00be2c486a55f3db4eccd211a7b94fbe8207486e1688428778c` and
`d15ff55c5f4202655f51158bf9a907588708df5b10457f8d5db54fe2da5a7d44`.
With the sysctl still `1`, the exact live test
`test_live_rootless_runc_enforces_minimal_worker_boundary` passed 1/1 under
`aa-exec -p runc`, with resource warnings visible and none emitted. Postflight
found no attempt tree, matching user slice, or runc process; the user manager
remained active and the sysctl remained `1`. No host settings were changed.

After that guest replay, the source received a compatibility-only adjustment:
cleanup now uses `getattr(..., None)` for optional Popen stream attributes so
structural process doubles without those attributes do not mask the bounded
reap error. The final local source SHA-256 is
`020f35c85285740fa0df6c78e05b12eae1c1860df01240a0bd99141ebe7faa7e`; it was
not overlaid or replayed in the guest. The final source passed both focused
cleanup tests locally, including
`test_failed_runc_launch_cleanup_reports_bounded_unreaped_child`.

This proves the low-level test can run with the default sysctl when its caller
is assigned a profile granting user-namespace creation; it does not establish
a production-ready profile. The packaged `runc` profile is unconfined apart
from naming and its userns rule, and this replay placed the entire pytest
controller and descendants under that label. It therefore does not prove the
permission is restricted to the trusted setup helper or absent from the worker.
The profile-separated prototype below addresses that low-level boundary, but
does not provide a production profile or policy lifecycle. The executor is
still not wired to registered `run_worker`; lifecycle ownership, cleanup
verification, credential/provider egress, result import, and full task #2370
acceptance remain open. Keep OCI `run_worker` fail-closed.

### OCI helper/worker AppArmor profile separation (2026-10-10; bounded pass)

The OCI compiler now optionally emits the standard `process.apparmorProfile`
field. The [OCI Runtime Specification v1.2.1](https://github.com/opencontainers/runtime-spec/blob/v1.2.1/config.md)
defines this as a Linux process profile name, and pinned [runc v1.5.2 applies
the profile during init, before exec](https://github.com/opencontainers/runc/blob/v1.5.2/libcontainer/standard_init_linux.go#L1016).
The compiler validates a single plain profile name; it does not load, verify,
attest to, or audit the named policy. The name must refer to a profile already
loaded by the host, and the actual runtime must still be independently checked.

In the disposable no-host-share guest above, a temporary **confined** enforce
profile named `acp-worker-qc` (flags `attach_disconnected,mediate_deleted`, no
`userns` rule) was loaded from stdin. A direct probe without the worker's
seccomp filter distinguished the profiles: `unshare --user --map-root-user`
under the packaged `runc` profile succeeded, while the same command under
`acp-worker-qc` failed with `Operation not permitted`. This is consistent with
the [AppArmor user-namespace policy](https://apparmor.net/man/4.0/apparmor.d/).
An earlier scratch profile using `flags=(unconfined)` but omitting `userns`
unexpectedly still allowed the operation with the global restriction enabled;
absence of a rule in an unconfined profile is not a worker denial. Do not use
that profile shape for this separation.

The exact `oci_worker.py` and `test_oci_worker_runtime.py` overlay passed the
opt-in rootless live test using pinned `runc-1.5.2` and
`ACP_OCI_TEST_APPARMOR_PROFILE=acp-worker-qc`. The host read
`/proc/<init-pid>/attr/current` and asserted `acp-worker-qc (enforce)` before
releasing the candidate-code gate; the payload independently read its own
label. The guest test environment was Python 3.12.3 / pytest 9.1.1. Its
user-namespace attempt was denied, though the worker seccomp policy
also denies namespace syscalls, so that payload result alone cannot attribute
the denial to AppArmor. The preceding direct no-seccomp contrast isolates the
AppArmor result. Tested file SHA-256 values:

- `src/agent_control_plane/supervisor/oci_worker.py`:
  `1a5559be722334c5797e2d908621a289adea11e55e46c69b16c43cbfbcdeedfd`
- `tests/test_oci_worker.py`:
  `b53e107889dd984c5f279ead9f542a20d9aaa929c5571833f6ad9b006b3f15ec`
- `tests/test_oci_worker_runtime.py`:
  `40ed1181d28ca585907a52c555b353a8a768a95373f4f8728a6a1972011eeb17`

`tests/test_oci_worker.py` was also overlaid (hash above), but its compiler
unit tests were exercised by the local suite rather than this live runtime
test. After the guest replay, the source docstring alone was clarified to state
that the compiler does not provision or attest to the named profile. The final
local source SHA-256 is
`7d68fb55375ab167b73a6cf49ca86a30aa84933d7eb7ed2a9d590dafe78e8236`; these
comment-only bytes were not recopied to the guest. The full local suite passed
on the final source tree.

Postflight confirmed `kernel.apparmor_restrict_unprivileged_userns=1`, removed
the temporary profile, and found no matching runc/unshare processes, ACP systemd
units, or live-attempt tree. This establishes optional OCI-field compilation
and profile application for this pinned low-level replay—not production policy
provisioning/discovery, integration with registered `run_worker`, complete
cleanup/recovery, or result handling. The temporary profile was intentionally
minimal for the experiment and is not production policy. Keep OCI `run_worker`
fail-closed until those remaining boundaries are independently implemented
and verified.

### NamespaceRuntimeDriver live payload boundary (2026-10-09; pass)

Added opt-in regression `test_live_namespace_runtime_hosts_payload_but_exposes_worker_boundary_gaps`
and ran it against the unchanged `runtime_drivers.py` from PR #42 source commit
`7b5c9acd787b4f946936ca8193d79b875567e788` (module SHA-256
`20ab594a414574d8575c437be54821fe681b0dbe2749ebff089dccc2dcec2852`). The
test file used for the run had SHA-256
`a127d774dba706a7ebd1c7f04361e9dfa1af50200342421b83b790241736fad1`. The
test ran rootlessly as uid 501 in a disposable Lima 2.2.1 VZ Ubuntu 24.04.5
ARM64 guest (kernel `6.8.0-142-generic`, Python 3.12.3, pytest 7.4.4), using
unified cgroup v2. `ACP_RUN_NAMESPACE_INTEGRATION=1` selected this single
test; result: 1 passed, 101 deselected. The VM's
`kernel.apparmor_restrict_unprivileged_userns` was temporarily set from 1 to 0
for the run and restored to 1 by an EXIT trap; the test itself does not change
host settings.

The fake payload ran in the transient per-attempt user service: the test read
its marker through `/proc/<host-pid>/root/work`, confirmed a distinct PID
namespace, `HOME=/work`, and cwd `/work`. It also confirmed `/workspace` was
read-only and that host `/etc/os-release` remained readable. `teardown()` plus
the driver's independent postflight proved the exact unit absent; afterward
the guest setting was restored, no matching service remained, and the unique
fixture directory was removed only after positive cleanup proof and a
device/inode identity check, using a parent-directory FD and fd-safe recursive
removal. Fixture creation and driver setup are inside the cleanup guard; if
cleanup cannot be proven, the test retains the fixture for inspection. The
observed `/tmp` setup initially obscured a fixture placed under `/tmp`; the
regression now keeps that disposable source outside `/tmp`, matching the
driver's private-tmpfs mount sequence. Cgroup paths from the unit are checked
for traversal and resolved
beneath the cgroup-v2 root before their process list is read.

**Follow-up hardening (2026-10-11; live probe passed, hosted CI pending).**
`NamespaceRuntimeDriver` no longer bind-mounts host `/etc`; it generates a
fixed, read-only `/etc/os-release` inside the private root. The structural test
rejects reintroduction of `/etc` into the host bind loop. The opt-in Linux test
now checks the generated identity, requires representative host `/etc/passwd`
to be unreadable, and compares generated `/etc/os-release` bytes with the
host's current file. These checks do not create a unique sentinel or inspect
the mount table, so they are narrower than full host-`/etc` isolation proof.
The helper default now prefers `/usr/sbin/chroot` and falls back to
`/usr/bin/chroot`, with either path still subject to trusted-binary validation.
The exact source/test pair passed the opt-in probe rootlessly in Lima 2.2.1
Ubuntu 26.04.1 ARM64 (kernel `7.0.0-34-generic`, systemd `259.5`, Python
`3.14.4`, unified cgroup v2, uid 501): 1 passed. The test temporarily changed
`kernel.apparmor_restrict_unprivileged_userns` from 1 to 0; the live-run wrapper
restored it to 1 with an exit trap (the pytest test itself made no sysctl
changes). Postflight found zero `acp-ns-it` units and zero test
worktree fixtures. The first attempt surfaced the guest's `/usr/bin/chroot`
layout; the final pass exercised the driver's adaptive default without a
test-only path override. Local full pytest passed (1,377 passed, 78 expected
platform/opt-in skips); Ruff format/check and package build passed. Exact-head
hosted CI remains pending. The generated `/etc` also omits resolver and CA
configuration: `egress=allow` does not guarantee DNS name resolution or HTTPS
certificate validation. Broad `/usr` exposure and all registered-worker/Git,
credential, egress, monitor, and cleanup integration gaps remain open.

**Interpretation (historical source under test, 2026-10-09):** the recorded
live run proves that the resource driver could host and clean up a generic
no-model payload in that measured guest. At that tested revision, host
`/etc/os-release` was readable. The 2026-10-11 source follow-up above removes
that broad bind, and its opt-in probe passed the generated-identity and
representative-file checks described above. Exact-head hosted CI remains
pending. The read-only coding workspace and other gaps still disqualify this
driver as the worker boundary.
It does not exercise ACP's registered `run_worker` reservation, worker PID,
cancel/recovery, Git transfer, or validated result import; it is not acceptance
criterion #3 or end-to-end sandbox proof. The driver must remain disconnected
from coding workers and task #2370 stays open.

**AppArmor prerequisite and preflight hardening (2026-10-10; same disposable
guest).** Before the change below, the guest's default
`kernel.apparmor_restrict_unprivileged_userns=1` policy caused
`unshare --user --map-root-user true` to fail with
`write failed /proc/self/uid_map: Operation not permitted`; systemd then
created a transient unit that failed before the payload. The kernel audit log
attributed user-namespace creation to AppArmor's `unprivileged_userns` profile.
This is a host prerequisite failure, not a successful runtime probe.

`NamespaceRuntimeDriver.setup` now runs the exact required rootless namespace
combination (`--user --map-root-user --mount --pid --fork`, plus `--net` when
egress is denied) with a trusted no-op command before invoking `systemd-run`.
A nonzero or timed-out preflight raises typed `namespace_unavailable`; no
transient unit is started. Opt-in live test
`test_live_namespace_runtime_refuses_unit_when_rootless_namespaces_are_unavailable`
passed under the guest's default policy and verified positive
`systemd-unit-not-found` absence afterward. To recheck the supported positive
path, the sysctl was temporarily changed to `0` only inside this no-host-share
VZ guest; the live generic-payload test passed, and an EXIT trap restored the
original value `1`. The full `tests/test_runtime_drivers.py` module passed on
Linux with live opt-in unset (the two live tests were explicitly skipped).
Postflight found no matching systemd unit or fixture worktree, and the guest
policy still read back as `1`.

The driver now also accepts an optional `apparmor_profile` name. When set,
preflight and the service's actual namespace command are both wrapped with the
trusted `/usr/bin/aa-exec` (or configured trusted `apparmor_exec_path`) and the
same named profile. This intentionally does not use systemd's
`AppArmorProfile=` unit property: systemd documents mandatory-access-control
properties as unavailable to per-user service managers
([systemd.exec(5)](https://manpages.ubuntu.com/manpages/noble/man5/systemd.exec.5.html)),
while ACP launches transient user services. The profile is not invented or installed by ACP; it
must already exist and be administrator-reviewed. Names are restricted to a
single plain token. This lets a host grant the namespace helper an explicit
user-namespace policy without turning off Ubuntu's global AppArmor restriction.
Do not copy the disposable test profile into production without independent
review: the Ubuntu `lxc-unshare` profile used for local validation is an
`unconfined` profile with a `userns` rule, not a complete ACP confinement
policy. A missing or insufficient profile fails closed: a missing profile
fails preflight before unit launch; a profile that permits preflight but not
the full mount sequence can still make unit setup fail, after which normal
teardown and positive-absence verification remain required.

**AppArmor-profile live recheck (2026-10-10; pass).** Exact source SHA-256
`e4a0cd58f8f6f5bf4491febe88926ac31586b21ee88c9f1c5643a79e18bf8aeb` and test
SHA-256 `398950fd966a202e06a21de1b888b970969e2259fde89c0762fbb03445b9b588`
were copied into the no-host-share Lima 2.2.1 VZ Ubuntu 24.04.5 ARM64 guest.
With `ACP_RUN_NAMESPACE_INTEGRATION=1`,
`ACP_NAMESPACE_TEST_APPARMOR_PROFILE=lxc-unshare`, and
`ACP_NAMESPACE_TEST_APPARMOR_EXEC=/usr/bin/aa-exec`, the exact live test passed
(`1 passed, 107 deselected in 0.12s`) and the full Linux `tests/test_runtime_drivers.py` module
passed (`106 passed, 2 opt-in integration tests skipped`). The guest remained
rootless (uid 501), on kernel `6.8.0-142-generic` / systemd 255.4, with unified
cgroup v2 and `kernel.apparmor_restrict_unprivileged_userns=1` before and after;
no global AppArmor setting was changed. The live test reads
`/proc/<host-pid>/attr/current` for the process holding the payload marker and
asserts that its effective label matches the configured profile name; the guest
reported `lxc-unshare (unconfined)`. Postflight found no matching ACP unit,
fixture worktree, or worker service. The payload again confirmed
`workspace_write=denied` while host `/etc/os-release` remained readable.

This proves the named profile transition reaches the payload process under this
Ubuntu policy; it does not establish that the selected profile is restrictive
or suitable for production. It also does not make the workspace mutable or hide
the host's enumerated `/etc`, and it does not exercise registered `run_worker`,
cancellation/recovery, Git transfer, or result import. The feature therefore
improves platform compatibility only; #2370 remains open and OCI worker
execution remains fail-closed.

For the earlier sysctl-based live run, the tested source and test SHA-256 values are
`66e937ec6cc2a4b11bd6c8f526695a7c94dc45d642865391355418f72e4e5ba3` and
`2a6afa465ece4426b8f599dac8be59426454228d82c6b9358b98ecadfd8b2e38`.
Environment: Lima 2.2.1 VZ, Ubuntu 24.04.5 ARM64, kernel `6.8.0-142-generic`,
systemd 255.4, uid 501, Python 3.12.3, pytest 9.1.1, unified cgroup v2; the
guest had no host-shared folders. The test venv used the project's declared
development extras, not the exact `uv.lock` environment; hosted CI remains the
locked-dependency matrix. Never relax this AppArmor setting on a shared host
to make a test pass.

**Ubuntu 26.04 rootless OCI boundary recheck (2026-10-11; pass).** To avoid
the active NAS I/O alert and leave the two existing ACP VMs untouched, the
source was copied into a new Lima 2.2.1 VZ `--plain` guest with no host mounts
or port forwards. The tested snapshot was based on PR-42 commit
`cedfecdaa59affb19edd68a2d8173be2b1f17b5d`, with only
`tests/test_oci_worker_runtime.py` overlaid; `oci_worker.py` SHA-256 was
`7d68fb55375ab167b73a6cf49ca86a30aa84933d7eb7ed2a9d590dafe78e8236`, and the
tested file SHA-256 was
`4942bff7abed3b4e9b65562711cb2c3847b09b766539825f4da9d718a0e34b7c`. The
guest was Ubuntu 26.04 ARM64, kernel `7.0.0-34-generic`, systemd 259.5, uid
501, Python 3.14.4, pytest 9.1.1, and unified cgroup v2. The installed
`runc.arm64` came from the [official runc v1.5.2 release](https://github.com/opencontainers/runc/releases/tag/v1.5.2)
after its SHA-256 matched the release-asset digest
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`.
Dynamic BusyBox 1.37.0-7ubuntu1 was separately extracted from the signed
Ubuntu package so the test could audit and copy its loader/library closure.

With `ACP_RUN_OCI_INTEGRATION=1`, runc 1.5.2 explicitly pinned, and the test's
normal bounded fake payload (no model or provider credentials),
`test_live_rootless_runc_enforces_minimal_worker_boundary` passed 1/1. The
Ubuntu image labels device-node bind mounts' devtmpfs source as `devtmpfs`
and omits `relatime`; the validator now accepts only the source labels
`udev`/`devtmpfs` and only the exact `rw,nosuid` option set with optional
`relatime`. It rejects unapproved source labels and every other per-mount
option set. This exact allowlist applies to mountinfo's per-mount options; for
these device binds the validator separately requires `rw` and rejects `ro` in
`super_options`, but does not exact-allowlist other superblock options. It also
checks the root/filesystem, filesystem device identity, shared devtmpfs
identity, device numbers, read-only proc masks, cgroup limits, PID namespace,
and bundle/path replacement attacks. The default guest AppArmor userns
restriction was `1`; a 10-minute systemd restore timer was armed before a
temporary guest-only change to `0`, and a shell exit trap restored and read
back `1`. At the end of this focused run, independent postflight confirmed the
setting was `1`, the live attempt tree absent, no runc process, and the user
manager active; its fallback timer remained armed to repeat the same safe
restore. Neither the Mac host nor NAS policy was changed.

As a follow-up on the same guest snapshot and exact source hashes above, the
entire `tests/test_oci_worker_runtime.py` module was run with
`ACP_RUN_OCI_INTEGRATION=1`: **47 passed in 5.67 seconds**, including the live
rootless-runc test (not skipped). For this run, two 10-minute fallback restore
timers were armed before the guest-only sysctl change; the shell exit path
restored and read back `1`, and both timers were stopped only after that
readback. Postflight found the user manager active and no runc process. The
live test's exact pytest directory
`/tmp/pytest-of-rayha/pytest-7/test_live_rootless_runc_enforc0` had no
`live-oci-attempt` child. A read-only scan of `/tmp/pytest-of-rayha/pytest-7`
found four adversarial pytest fixtures that intentionally retained their
markers: `test_checkout_write_probe_clea1/checkout-write-probe`,
`test_private_attempt_tree_clea1/live-oci-attempt`,
`test_private_attempt_tree_clea2/live-oci-attempt`, and
`test_private_attempt_tree_fina0/live-oci-attempt`. Their unexpected or
replacement marker entries remain by design; these fixture directories are
distinct from the live test's attempt tree and were preserved, not deleted.

**Ubuntu 26.04 systemd 259 monitor/attestation primitive recheck (2026-10-11; pass).**
In the same no-host-mount Lima guest (Ubuntu 26.04 ARM64, Linux
`7.0.0-34-generic`, systemd 259.5, Python 3.14.4, pytest 9.1.1, cgroup v2),
the exact `tests/test_systemd_slice_integration.py` SHA-256
`94eb48cc486c1e174d697ec01767701576a257f52a7a52bb74359773fbbba7e9` was run
with `ACP_RUN_SYSTEMD_SLICE_INTEGRATION=1`; the two selected live tests passed
(2 passed, 3 deselected, 0.48 seconds). The first test killed its creating
controller, reconciled the exact service receipt from a fresh controller, and
verified the monitor service survived stopping the worker slice while the scope
cgroup emptied. The second verified that the live systemd attestation rejects
a restarted wrapper. The imported `sandbox_attestation.py` and `oci_worker.py`
SHA-256 values were `c64ef56def1dc4cd9fc58c2db62560b6f1da33076483c2b460dee78ad3044b22`
and `7d68fb55375ab167b73a6cf49ca86a30aa84933d7eb7ed2a9d590dafe78e8236`.
Postflight found the user manager running, no matching `acp-live-*` or
`user-acp-*.slice` units, and no `/usr/bin/sleep 90` or `runc` process.

These systemd tests use placeholder sleep processes, and their scope is started
by an external controller; they do not test a monitor that owns the runc client
and its wait/reconciliation. This extends primitive-level coverage to systemd
259.5 only; it is not durable monitor integration, supervisor-restart recovery,
or registered `run_worker()` acceptance.

This is a successful low-level OCI-boundary probe on a second Linux/kernel
profile, not end-to-end supervised-worker acceptance. It does not connect the
container launch to registered `run_worker`, provide least-privilege provider
authentication/egress, or demonstrate supervisor-crash recovery, cancellation,
and result import. `run_worker()` therefore remains fail-closed with
`sandbox_executor_unavailable`; task #2370 remains open.

**Target NAS capability spot check (2026-10-10; no unit or worker started).**
From the regular uid-1000 account on `DXP4800PLUS-RING` (`Linux 6.18.15
x86_64`), the exact default-deny namespace flags, including `--net`, ran a
trusted `/bin/sh -c "exit 0"` no-op and returned exit 0. The user's
`default.target` was active. The AppArmor userns sysctl path was absent on this
host (unlike the disposable Lima guest); `/sys/fs/cgroup/cgroup.controllers`
listed `cpuset cpu io memory hugetlb pids rdma misc`. This was a direct
capability probe, not `NamespaceRuntimeDriver`, `systemd-run`, or `run_worker`.
The root controller list does not prove per-user delegation or limit
enforcement, and this probe establishes no workspace, credential, egress,
cleanup, or worker-isolation property.

**Credential and host-socket isolation gate.** Namespace and cgroup capability
checks do not establish which Unix socket paths a worker can reach. The
integrated no-model probe must capture the worker's effective uid, gid,
supplementary groups, and open descriptors; it must hide or deny host
container-engine, system/user D-Bus, SSH-agent, and credential-agent sockets,
then prove those endpoints are unavailable while any explicitly supplied
test-only socket remains usable. Environment-variable filtering and a socket
path's filesystem mode are not substitutes for this negative runtime test.
Do not enable the OCI worker path until the integrated executor proves this
boundary together with the other gates below.

This preflight proves namespace creation prerequisites and prevents the
measured failed-unit case; it does not verify the later mount/chroot prelude or
establish a coding-worker boundary. Separately, `run_worker` still refuses any
OCI-configured worker before heartbeat, reservation, or `Popen`; focused test
`test_oci_configured_worker_fails_closed_before_host_fallback` passed on this
source. That proves refusal rather than a working OCI worker executor.

### NAS-host rootless-runc boundary probe (2026-10-09; partial pass)

The opt-in `test_live_rootless_runc_enforces_minimal_worker_boundary` passed
once in 7.7 seconds on the NAS (`Linux 6.18.15` x86_64, uid 1000, rootless
runc 1.3.5, BusyBox 1.35.0, unified cgroup v2). The source branch was verified
at exact public head `18de1e32c96dd2dc5c319549c349b2a30bc58266`; the test file
SHA-256 was
`9a54375ea682aea68ee8ce9630da0b82c264dca89335edbc0abc5fb623487c95` and
`src/agent_control_plane/supervisor/oci_worker.py` was
`5aed95084724828544b0c6f09ac17653983caff57f16498fd31950b5b42c4092`. The
rootless user-namespace preflight succeeded. The no-model invocation cleared
its environment and used Python 3.11 / pytest 9.1.1; no provider credentials
or model call were used.

The test observed only `lo`, no IPv4 default route, and one TCP probe that did
not reach its test-owned host-NIC listener. It denied the specified source
checkout (including `.git`), sibling worktree, unrelated project, home,
synthetic config/credential markers, host `/etc/os-release`, `/tmp`, and
absolute/relative symlink targets. Its FD check asserted exactly descriptors
0, 1, and 2, with no additional or socket descriptors; pipe targets were
observed but not asserted. The process had zero capability sets and
`NoNewPrivs=true`; read-back limits were `cpu.max=50000 100000`,
`memory.max=134217728`, and `pids.max=16`. The test and separate postflight
found the attempt tree, `/dev/shm` anchor, exact scope cgroup, and checkout
canary absent, with no runc process or matching scope remaining.

Pytest emitted a nonfatal warning because the optional Starlette dependency
was absent, so this invocation did not validate that warning filter or the
full suite. More importantly, the test used a test-only unjournaled gate
release. This is partial direct-runc runtime evidence, not a journal-authorized
launch or registered `run_worker` acceptance. It is not general egress proof,
provider-authentication evidence, `cleanup_verified` evidence, result-import or
crash/recovery proof, or a pass of task #2370's integrated-worker criteria;
`worker_executor_integrated=false`. Keep OCI fail-closed and task #2370 open.

### Trusted runtime-attestation source boundary (2026-10-09; code-only)

`collect_running_runtime_attestation()` no longer accepts caller-provided
`runc state` or systemd property bytes when issuing the collector provenance
that the journal requires. It revalidates the configured root-owned runc pin,
executes `runc state` through the held executable descriptor, resolves only a
root-owned non-replaceable host `systemctl`, and queries the exact wrapper,
attempt-slice, and scope units with a fixed property set. Both command paths
use the existing bounded guardian (three-second deadline and 64 KiB output
ceiling); the systemd bus path is fixed to the current user's private runtime
directory. Each collector-issued receipt also binds the state-root
path/device/inode, exact PID-file path, and pinned runc digest. Under the
launch-gate lock, the journal compares every source-binding field with the
durable plan and rechecks the state-root identity before authorizing release.
Unit names and invocation IDs are validated before commands run. The internal
observation normalizer can still validate fixture/supplied bytes, but it cannot
mint journal-accepted collector provenance.

Focused tests exercise command construction, descriptor-bound runc execution,
source-output parsing, wrong-state-root, wrong-PID-file, and wrong-executable
rejection, plus the provenance boundary with a fake bounded-command runner.
They do not prove a live systemd bus, a production monitor service, or restart
reconciliation. The bus check validates path ownership/type but does not
authenticate the D-Bus peer or exclude a hostile same-UID host process; the
future worker boundary must keep the host bus inaccessible. These observations
are sequential, not a durable monitor. The collector is not wired into
`run_worker`; the registered OCI path remains fail-closed, and task #2370
remains open.

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

**2026-10-09 wrapper and parent-slice follow-up (architecture evidence only).**
The exact-source opt-in test was rerun under a transient user service with
`Delegate=yes`, `KillMode=control-group`, and a 90-second runtime bound. It
passed once on the NAS using source snapshot `f9de9b16b06cc776565192f71a7117b234daf883`
(test SHA-256 `9a54375ea682aea68ee8ce9630da0b82c264dca89335edbc0abc5fb623487c95`)
and the committed `uv.lock` (`uv --frozen`). Host: Linux 6.18.15 x86_64,
systemd 252, uid 1000, rootless runc 1.3.5, BusyBox 1.35.0. The service got a
sanitized environment and no provider credentials. The emitted evidence again
reported `worker_executor_integrated=false`; this remains the test-only,
unjournaled direct-runc gate, not a registered worker lifecycle.

The new evidence also sharpens the containment gap: the runc scope was reported
under `user@1000.service/user.slice/`, whereas a separate ordinary transient
user service was under `user@1000.service/app.slice/`. `Delegate=yes` on that
wrapper therefore does not make its `KillMode=control-group` cover the
systemd-created runc scope. This matches runc's documented
`linux.cgroupsPath=[slice]:[prefix]:[name]` placement contract and the current
compiler's fixed `user.slice:acp:<container-id>` value
([runc systemd cgroup documentation](https://github.com/opencontainers/runc/blob/main/docs/systemd.md)).

A bounded no-model `sleep` probe then placed both a transient service and a
transient scope beneath one unique `user-acp-…slice`; their reported cgroup
paths were descendants of that slice. Stopping the parent slice transitioned
both units to inactive. This validates a possible per-attempt containment
mechanism, not process-absence proof, OCI cleanup, crash recovery, or ACP
integration. The policy compiler now binds each runc scope beneath a unique
parent slice, but neither the supervisor wrapper nor a journal-authorized
launch is placed there. The executor still needs a restart-safe lifecycle that
proves all attempt descendants and runtime state absent before writing
`cleanup_verified`. Keep OCI fail-closed and task #2370 open.

**2026-10-09 exact-source per-container slice binding and teardown (not worker integration).**
Commit `fbb205e3d714f9e7bcd73a3e1026d5a8338d412a` makes the policy compiler emit
`linux.cgroupsPath=user-acp-<sha256(container-id)>.slice:acp:<container-id>`.
The complete-policy validator and private-bundle launch check require that exact
deterministic slice, rejecting the former shared `user.slice` parent and a slice
derived from another container ID. The opt-in test at that exact commit has
source SHA-256 `8770605a9dd64ecdd5a167b619462c349d53aae0b7bb59ad08688e202ca0011c`
and test SHA-256
`93656c531a20a517a829b1249950107323921dd6e324ff69e58c266f67c6731a`.

On 2026-10-09, the opt-in test passed once on that exact snapshot; the bounded
systemd service ran for 6.997 seconds under a transient user service
with `Delegate=yes`, `KillMode=control-group`, a 300-second runtime bound,
sanitized environment, no provider credentials, `uv run --frozen`, and runc
1.3.5 pinned. Host: Linux 6.18.15 x86_64, systemd 252, BusyBox 1.35.0. The
runtime receipt reported
`user-acp-55dc0feb0b79615c6d1288993f4427ce709c4f84413b457ae7050b71c054936e.slice`
and asserted that the exact runc scope
`acp-acp-live-28cbdd46b9ed4876b63220b5d90c501f.scope` `ControlGroup` was a
descendant of that slice. The receipt again reported
`worker_executor_integrated=false`.

The test teardown performed a sequential, point-in-time scan requiring
`cgroup.events populated=0` and empty `cgroup.procs` throughout the exact slice
subtree, then requested stop of that slice; if the observed state was
ambiguous, it preserved the attempt evidence. The scan and stop are not atomic
against a concurrent same-UID systemd actor adding a unit between them, and
this test did not exercise or exclude that race. After this run, the transient
service and runc scope were `not-found`; the parent slice was loaded but
inactive with an empty `ControlGroup`, and its cgroup path was absent.
The test attempt root was absent. Its 4,415-node source snapshot was removed
only after matching the recorded device/inode and owner/mode, finding no process
cwd/open-fd/mapped-file references or mountpoints, and using descriptor-relative
symlink-safe removal. This proves scope placement and test teardown for the
compiled policy on one NAS host only. It does not place the supervisor inside
the slice or prove journal authorization, full attempt descendant containment,
cancellation/crash recovery, result import, provider egress, or registered
`run_worker` behavior. Keep OCI fail-closed and task #2370 open.

**2026-10-09 systemd ownership and restart decision (research; not integration).**
The supported-host assumption is systemd 252, so this check used the v252
interface docs rather than relying only on current `main`. systemd documents a
single-writer rule for cgroup v2. In v252, the manager D-Bus interface exposes
`StartTransientUnit`, `GetUnitByInvocationID`, and `GetUnitByControlGroup`; the
systemd control-group API documents the unit's `ControlGroup` property. Resolve
exact unit/invocation identities and read reported properties instead of
deriving cgroup paths from unit names. `systemd-run` is a wrapper for
transient-unit creation, not a separate lifecycle owner. Sources:
[systemd v252 D-Bus interface](https://github.com/systemd/systemd/blob/v252/man/org.freedesktop.systemd1.xml),
[systemd control-group API](https://systemd.io/CONTROL_GROUP_INTERFACE/), and
[systemd v252 cgroup delegation guide](https://github.com/systemd/systemd/blob/v252/docs/CGROUP_DELEGATION.md).

The v252 D-Bus XML declares `GetUnitByInvocationID` and
`GetUnitByControlGroup`, but comments that both methods are not documented; it
also marks the `InvocationID` property undocumented. Do not treat these
declarations as compatibility guarantees. The monitor should query the
durable exact unit name and compare the returned `Id`, `InvocationID`,
`ControlGroup`, `Slice`, and state with its receipt; any unavailable or
mismatched identity keeps the attempt fenced. Required property readback must
be tested for each supported systemd version, and reverse-lookup methods need
an explicit version/behavior test before use.

The recovery design must not use `systemd-run --scope` as the durable monitor:
in v252 the command remains a child of the `systemd-run` client and the client
waits synchronously for it. Instead, the candidate architecture is one
systemd-owned transient **monitor service** per attempt/fencing epoch, outside
the unique worker attempt slice. That trusted service owns the pinned
foreground-runc client, gate authorization, wait, and durable lifecycle
receipts. The runc-created scope and container init belong inside the exact
attempt slice; the monitor service must not. Stopping the worker slice must
terminate the scope while leaving the trusted monitor alive to reap runc,
observe teardown, and record cleanup. The service is intended to outlive an ACP
supervisor-process restart while the same user manager remains active; that
recovery property is not yet proven. For the user-manager deployment, verify
the host's logout/linger and manager-restart behavior rather than assuming
persistence across logout or reboot.
The untrusted worker must never receive the host systemd bus socket or a route
to the control API.

`KillMode=control-group` covers one unit's control group, not an runc scope in
the separate worker slice; stopping the monitor service alone is therefore
insufficient. The trusted service must serialize start/cancel/recovery, query
the exact monitor and scope invocation IDs and `ControlGroup` values, and use
the manager to stop only the exact per-attempt worker slice. An owner restart,
missing or reused invocation, unexpected cgroup ancestry, or ambiguous cleanup
must leave the execution fence held and prohibit result import. A sequential
cgroup scan followed by stop is still only point-in-time evidence, not an
atomic cleanup proof. No durable monitor service or integrated worker path has
been implemented. The earlier same-slice probe below is historical; the new
split-placement probe validates that the trusted service survives stopping the
worker slice, but it uses `/usr/bin/sleep` and an external scope controller,
not a monitor that owns runc wait/reconciliation. Manager-restart recovery
remains untested and OCI remains fail-closed. Sources:
[systemd v252 `systemd-run`](https://github.com/systemd/systemd/blob/v252/man/systemd-run.xml),
[systemd v252 unit dependencies](https://github.com/systemd/systemd/blob/v252/man/systemd.unit.xml),
[systemd v252 resource control](https://github.com/systemd/systemd/blob/v252/man/systemd.resource-control.xml),
and [systemd v252 `systemd.kill`](https://github.com/systemd/systemd/blob/v252/man/systemd.kill.xml).

**Version-5 placement contract (2026-10-10; source tests only).** The running
attestation and launch-plan version 5 now require the trusted wrapper/monitor
cgroup to be disjoint from the exact per-attempt slice; only the runc scope is
required to be a direct child of that slice. This rejects both a monitor inside
the worker slice and a monitor cgroup that would own the worker slice. Older
launch-plan versions remain readable for audit, but cannot enter the running
phase under the new contract. Unit tests verify the accepted split and reject
wrong-slice nesting. The opt-in disposable-VM probe below also validates the
split cgroup placement and monitor survival at the systemd primitive level.
There is still no integrated service launcher or production monitor, and the
public `run_worker` OCI route remains fail-closed.

**Per-execution monitor control-key storage (2026-10-11; code-only).** The
receipt/control-codec module now provides an atomic, durable 32-byte key store
whose filename is derived from the full attempt, claim-token and execution
identity. It rejects non-private directories, symlinks, unsafe metadata and
malformed keys. A per-key advisory lock serializes cooperating callers, while
the published secret remains bound to the exact attempt, claim token and
execution identity. This is only a prerequisite: no monitor service or
controller calls it yet, the worker-mount exclusion is a caller obligation, a
same-host-UID process remains in the trust boundary, and lifecycle key cleanup
is not integrated. It does not establish monitor-owned runc execution,
reconnect, authentication delivery, or cleanup.
An abrupt exit after the temporary key is fsynced but before publication can
leave a private temporary key file. A subsequent helper call acquires the
per-key lock, removes only a safe private single-link temp for that identity,
and then loads an already-published key or creates one. A published two-link
orphan is preserved for the existing same-inode recovery path. The empty
mode-0600 lock file remains until lifecycle cleanup is wired.

**Historical same-slice stop propagation probe (2026-10-09; opt-in regression).**
The systemd v252 resource-control contract says units assigned with `Slice=`
automatically acquire `Requires=` and `After=` dependencies on that slice;
systemd v252 says a unit with `Requires=` is stopped when its required unit is
explicitly stopped. Therefore stopping only the wrapper service is insufficient,
but stopping the exact attempt slice is expected to stop both its monitor service
and sibling runc scope. This is dependency propagation, not `KillMode=` reaching
across unit cgroups. Sources:
[v252 resource control](https://github.com/systemd/systemd/blob/v252/man/systemd.resource-control.xml),
[v252 unit dependencies](https://github.com/systemd/systemd/blob/v252/man/systemd.unit.xml),
and [v252 kill behavior](https://github.com/systemd/systemd/blob/v252/man/systemd.kill.xml).

A bounded probe in the task-owned, no-host-mount Lima VM (Lima 2.2.1 VZ,
Ubuntu 24.04 ARM64, Linux 6.8.0-142, systemd 255.4, active user manager,
cgroup v2) started a transient service and sibling scope using the candidate
`user-acp-<sha256>.slice` name. Before stop, systemd-reported `Slice=` values
matched exactly and both `ControlGroup` paths were direct children of the slice
`ControlGroup`; each had a non-empty `InvocationID`. Stopping that slice returned
success. In the recorded opt-in test run, all three units became inactive, each
recorded cgroup was empty or absent, and the `systemd-run --scope` client exited
with `-15` (SIGTERM). The regression requires the client to exit before its
timeout but does not require a particular exit code. It does not assert that
post-stop `InvocationID` or `ControlGroup` properties are cleared or that the
cgroup directories are removed. The test-only processes were `/usr/bin/sleep`
with a 45-second runtime ceiling; exact units were explicitly stopped in a
finally cleanup as well.

**Split monitor/worker slice probe (2026-10-10; opt-in regression).** The
updated opt-in test assigns the transient trusted service to `app.slice` and a
separate transient scope to the generated `user-acp-<sha256>.slice`. The
service's exact `InvocationID`, `MainPID`, and `ControlGroup` were durably
recorded; a fresh controller reconciled those values after the creating
controller received `SIGKILL`. On the disposable no-host-mount Lima VM (Lima
2.2.1 VZ, Ubuntu 24.04 ARM64, Linux 6.8.0-142, systemd 255.4, Python 3.12.3,
active user manager, cgroup v2), the opt-in test passed (3 passed). Systemd
reported the service directly under `app.slice` and the scope directly under
the exact attempt slice. Stopping the attempt slice made the scope inactive
and emptied its cgroup while the monitor service remained active with its
recorded identity and a populated cgroup; explicitly stopping the monitor then
emptied its cgroup too. In the recorded run, the scope client exited `-15`
(SIGTERM); the test requires exit before timeout, not that exact code. The
service and payload are still `/usr/bin/sleep`, and the controller starts the
scope independently: this proves cgroup placement, controller-crash receipt
reconciliation, and slice-stop survival only—not monitor-owned wait/reaping,
OCI enforcement, production cleanup verification, supervisor recovery, or
result transfer.

`tests/test_systemd_slice_integration.py` records this as an opt-in regression
(`ACP_RUN_SYSTEMD_SLICE_INTEGRATION=1`). It is not part of default CI and does
not by itself prove runc-created scope behavior, race-free cleanup,
manager-restart recovery, or `run_worker` integration.

**Exact-floor follow-up (systemd 252.39; 2026-10-09).** The same opt-in probe
was run from the exact test file in a disposable Lima 2.2.1 VZ Debian 12 ARM64
guest with `mounts: null` (no host-shared mounts), Linux 6.1.0-53-cloud-arm64,
cgroup v2, and an active user manager. The guest reported
`systemd 252 (252.39-1~deb12u2)`. Before stopping the candidate slice, the test
observed the service and sibling scope assigned to that slice, direct-child
`ControlGroup` paths, invocation IDs, and populated cgroups. After the stop, the
slice, service, and scope were inactive; all three recorded cgroups were empty
or absent; and the scope client exited `-15` (SIGTERM). A separate post-run
check found the service and scope not loaded, the slice inactive, no
`/usr/bin/sleep 45` process, and no cgroup directory for the probe slice. The
guest copy matched the host test SHA-256
`50198c007b9354dc18f9e2cd75d994d51ca5528e2d8f0cb27d76c7f8fd9cd28f` and
`oci_worker.py` SHA-256
`8770605a9dd64ecdd5a167b619462c349d53aae0b7bb59ad08688e202ca0011c`.

This adds live coverage of the unit-dependency/teardown behavior on systemd 252
as well as 255. It still does not prove runc-created scope behavior, race-free
cleanup, manager-restart recovery, or `run_worker` integration. After any stop
request, the integrated executor must independently confirm the exact attempt,
service, and scope invocation identities and prove their cgroups empty before
recording `cleanup_verified`.

**Controller-crash receipt reconciliation probe (systemd 255; 2026-10-09).**
The opt-in test was extended and run from an exact file copy in the disposable
Ubuntu 24.04 ARM64 Lima guest above (Linux 6.8.0-142, systemd 255.4, active user
manager, cgroup v2; no host-shared mounts). A short-lived controller started a
systemd-owned transient service running only `/usr/bin/sleep 45` in a unique
attempt slice, then atomically persisted and `fsync`ed a private receipt with
the exact unit, `InvocationID`, service and slice `ControlGroup`, `MainPID`, and
controller PID. The parent waited for the post-directory-`fsync` acknowledgment,
required that PID to match the process handle, then sent `SIGKILL` to that
controller. A fresh Python process reconciled the receipt against systemd's
reported unit properties,
including the unchanged `InvocationID`, `ControlGroup`, `Slice`, and `MainPID`,
and verified the service cgroup was a direct child of the recorded slice and
the recorded PID still existed. The probe next started a sibling scope and
stopped the exact attempt slice; all three units became inactive, all recorded
cgroups were empty or absent, and the scope client exited `-15` (`SIGTERM`).
The guest test file matched host SHA-256
`3d37f45f1b83c9be338f8869280b09c3813d899c55903992732c0561f3123670`. A
post-run inspection found no probe service/scope, `/usr/bin/sleep 45` process,
or hashed attempt-slice cgroup. The test finalizer also checks each exact unit's
non-active/absent state and any recorded cgroup; inability to prove cleanup
fails the probe.

This demonstrates only that this systemd-owned placeholder service and its
exact receipt survived abrupt exit of a separate controller process without
intentionally restarting the user manager, and that stopping the recorded slice
tears down its service and sibling scope in this test environment. The test
checks manager availability before launch and uses it again for reconciliation;
it does not independently attest manager identity across those steps. It does
not test ACP supervisor restart, a monitor daemon that owns/waits for runc,
systemd manager restart/logout/reboot, a concurrent cleanup race, runc-created
scope behavior, or `run_worker` integration. The opt-in test is not default CI
and does not authorize setting `cleanup_verified`; OCI remains fail-closed.

**PID-start-identity receipt revalidation (2026-10-10; exact-source replay).**
Receipt schema v3 records the Linux process identity
`linux:<MainPID>:<starttime>` using ACP's PID-reuse-resistant process helper.
Receipt parsing rejects malformed or PID-mismatched identities, and a fresh
reconciler compares the current process start identity after checking the
systemd-reported unit identity. A deterministic regression keeps all mocked
systemd properties, including `MainPID`, unchanged while changing the start
identity; reconciliation rejects it. This simulates PID reuse at the identity
boundary, not actual kernel PID reuse.

The exact updated test file and package wheel were replayed in the disposable
no-host-mount Lima guest above (Ubuntu 24.04.5 ARM64, Linux 6.8.0-142,
systemd 255.4, Python 3.12.3, active user manager, cgroup v2). The test file
SHA-256 was
`282427fbbe67345ee3d8c404c35a110ce3cc55c7cbe7344e2469fe76e1f966f0` and the
package wheel SHA-256 was
`b285d3c387b36acb05652d63b331f2e27f40d5ac57e679607cf336fb68a82134`; both
matched between host and guest. The opt-in pytest passed (1 passed), and a
direct script replay returned `monitor_reconciled_after_controller_sigkill`,
`monitor_survived_worker_slice_stop`, and `cgroups_empty` as true. The unique
service and scope became `not-found`/`inactive`, the attempt slice became
`inactive`, their three recorded cgroup paths were absent, the recorded monitor
PID was absent, and the scope client exited `-15` (`SIGTERM`). The host's exact
commit `ad63e2d` also passed all four Ubuntu/macOS × Python 3.11/3.12 CI jobs
(run `38085103683`). This is still a `/usr/bin/sleep 45` placeholder and
controller-process recovery only: it does not prove kernel PID reuse,
fencing-epoch binding, an ACP monitor owning runc, cleanup/result-import
integration, manager restart/logout/reboot recovery, or `run_worker`; OCI
remains fail-closed.

**Systemd monitor MainPID binding (2026-10-10; source-level gate).** The
trusted runtime collector now requests `MainPID` for the wrapper service and
requires it to equal the expected monitor PID. Existing procfs observations
then bind that PID to its kernel start identity and the service cgroup; absent
or mismatched `MainPID` fails attestation. Slice and scope queries do not ask
for the service-only property. Unit regressions cover missing and mismatched
values and verify the collector requests it only for the wrapper. This closes
the attestation ambiguity where another process in the same wrapper cgroup
could be passed as the monitor. The collector re-queries all three exact units
after process and cgroup sampling, requires systemd properties to be byte-identical,
then rechecks process membership and resource controls before issuing collector
provenance. At the journal's gate-release boundary, the same launch-gate lock
now protects another exact wrapper/slice/scope property read, including wrapper
`MainPID`; drift leaves the row at `launched` and the one-shot gate closed.
Systemd, procfs, and cgroup reads remain sequential, not an atomic snapshot; an
ABA transition or change after the final read is not ruled out. This narrows the
observation window, not a kernel-level race. It does not establish that a
production ACP monitor owns or waits for runc, is crash-recoverable, or is
connected to `run_worker`; OCI remains fail-closed.

**Gate-release systemd identity recheck (2026-10-10; exact-source live replay).**
The journal now re-reads the exact wrapper service, attempt slice, and runc
scope while holding the launch-gate lock, immediately before the durable
`launched` to `running` transition and one-shot gate authorization. A new
opt-in regression starts unique transient units under the disposable user
manager, builds a self-consistent test receipt from their live unit properties
and process snapshots, accepts the original identities, restarts the wrapper,
and requires the old receipt to fail with `sandbox_runtime_attestation_stale`.
Its runc-state and resource-limit bytes are fixtures: this proves the trusted
`systemctl` observation path and replacement rejection, not a live runc launch
or resource enforcement. The test's `finally` gate stops the exact scope,
attempt slice, and wrapper and verifies their cgroups empty or absent.

The exact test and source copy ran in the no-host-share Lima 2.2.1 VZ guest
`acp-sandbox-monitor-20261010` (Ubuntu 24.04.5 LTS ARM64, Linux 6.8.0-142,
systemd 255.4, Python 3.12.3, active user manager, cgroup v2). The live test
alone passed (`1 passed, 4 deselected`) in 0.18 seconds; the complete opt-in
systemd test file passed (`5 passed`) in 0.50 seconds. The test file SHA-256 was
`94eb48cc486c1e174d697ec01767701576a257f52a7a52bb74359773fbbba7e9`; the
48-file `src/agent_control_plane` Python-source manifest SHA-256 was
`d59e1d78a9150a5c2a962831b4d35aef9d82bfb5f34e88f0b2c5d6cdf24ab710` on both
host and guest. The test cleanup asserts that each exact unit is no longer
active/activating/deactivating and each recorded cgroup is empty or absent. A
separate postflight `systemctl --user list-units --all` query found no loaded
probe service or scope; that loaded-state observation is not an assertion in
the test. This remains a test of the systemd verifier in isolation: it does
not establish durable monitor recovery, production cleanup verification, real
runc scope behavior, result import, or `run_worker` integration. OCI remains
fail-closed.

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
  failed systemd setup, stale unit, and concurrent attempts. Separately test
  controller death while the system manager stays live and the selected
  `systemd --user` manager's logout/linger lifecycle on a disposable host; a
  manager shutdown or vanished unit is not proof of worker cleanup. A missing
  or ambiguous unit identity is `unknown` and retains the fence; it is not
  cleanup proof. After a stopped container, explicitly run `runc delete` and verify
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

### Pinned runc recursive-propagation adapter (2026-10-05)

The live mountinfo audit established that the portable OCI value "private" is
not sufficient for the tested rootless runc 1.3.5 runtime: nested /dev and
/proc mounts retained master:10 propagation metadata, and the test rejected
that state while the candidate remained behind fd 3. The exact-version
diagnostic using "rprivate" passed the live policy and isolation checks. Runc
1.3.5 maps that implementation-specific spelling to MS_PRIVATE|MS_REC, but
the OCI v1.2.1 enum does not include rprivate
([runc mapping](https://github.com/opencontainers/runc/blob/v1.3.5/libcontainer/specconv/spec_linux.go),
[OCI field](https://github.com/opencontainers/runtime-spec/blob/v1.2.1/config-linux.md#configlinuxrootfsmountpropagation)).

The generic OCI compiler therefore keeps emitting the standards-listed
"private" value. A separate compatibility adapter requires the exact live
compiler-issued config object, checks its process-local identity and canonical
digest, rejects copies/forgeries/mutations, validates the complete supported
worker-policy shape, and then derives the runc-specific `rprivate` bytes from
the sealed compiler snapshot. The compiler output is checked against the
vendored OCI v1.2.1 JSON schema in the test suite. The adapter re-probes the
same root-owned executable pin and rejects other releases or any policy outside
ACP's narrow OCI subset. This runc-specific output must not be passed to a
generic OCI runtime.

The input-provenance/full-policy gap is closed for the adapter. The former
host-path config race is now addressed in the candidate `spawn_pinned_runc()`
implementation by the private read-only tmpfs and inherited bundle FD described
above. Exact-source NAS replay and independent QC have passed for the bounded
launcher/cleanup slice. GitHub Actions run `37320832762` passed all four
Ubuntu/macOS × Python 3.11/3.12 jobs on implementation/test-fixture commit
`9a6368d`; this receipt does not cover later documentation-only commits. Task
#2417 records the current PR head and its latest check. The
underscored `_spawn_pinned_runc_for_unisolated_diagnostic()` is retained only
for explicit no-model host-path diagnostics and is not a safe worker launch
path. Do not connect either low-level launcher to `run_worker`: lifecycle,
runtime attestation, cleanup, result-import, credential, and provider-egress
safety remain separate open gates.

### Exact-source rootless OCI boundary recheck (2026-10-11; pass)

On the dedicated Lima VM `acp-oci-qc-20261009` (Ubuntu 24.04.5 LTS ARM64,
Linux 6.8.0-142-generic, systemd 255.4, Python 3.12.3, cgroup v2), the
current opt-in `test_live_rootless_runc_enforces_minimal_worker_boundary`
passed (`1 passed`) against the copied ACP Python-source manifest at test time
`ebbd1b29e845c1b5fbd5556624d02d846a2caf09f1f9a4c3d7b11ed3468ab5e8` and
test-source hash `4942bff7abed3b4e9b65562711cb2c3847b09b766539825f4da9d718a0e34b7c`.
The test used BusyBox 1.36.1 and rootless runc 1.5.2. The upstream ARM64
release binary matched SHA-256
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`
([runc v1.5.2 release](https://github.com/opencontainers/runc/releases/tag/v1.5.2)).
An initial 1.3.5 run was rejected by ACP's version guard before worker launch;
the existing runc binary was left untouched, and the test used a separate
versioned executable. The VM denies unprivileged user namespaces when
unconfined, but its already-loaded `lxc-unshare` AppArmor profile permits the
namespace preflight; the opt-in test ran under that profile. The test's
assertions covered the bounded no-model payload, mutable workspace, host/base
and credential sentinels, symlink/path attacks, mount policy, process
visibility, network isolation, cgroup controls, and cleanup. A separate exact
`NamespaceRuntimeDriver` fake-agent integration also passed (`1 passed`): the
payload ran in the private root, could not write its read-only workspace, and
could still read host `/etc/os-release`, confirming that this resource driver
is not itself the worker-read-isolation boundary; its test-source hash was
`c6efabd7ecafde1691ad35e53f938c2bb176d436218c3bb6c7dac92c3d36622c`.
The extra versioned runc executable and scratch checkout/venv were removed
afterward; the VM's original runc 1.3.5 remained unchanged. The monitor-key
hardening added after this run is outside the OCI fixture's exercised code.

These are low-level OCI and resource-driver proofs, not registered-worker
integration. The OCI test does not exercise `run_worker`, monitor ownership,
durable journal transitions, provider authentication, Git/result transfer, or
supervisor-restart cancellation/recovery. The configured-OCI `run_worker`
route remains fail-closed, and the broader proof gates above remain open.

### Explicit process and Git-metadata visibility follow-up (2026-10-15; pass)

The direct-runc no-model fixture now starts a live host-only process with a
unique command-line marker, verifies the marker through host `/proc` before
launch, captures the candidate-visible `/proc/*/cmdline` entries inside the
fresh PID namespace, and has the trusted test harness verify that a known
in-container process-table control was captured, that the host marker is
absent, and that the marked host process is still alive with the marker after
the snapshot. Failed reads of extant `/proc` entries fail the probe; only
entries that disappear during enumeration are skipped. The marker is not
passed to the worker. The candidate-facing `/workspace` also fails closed if
any `.git` file, directory, or symlink is present at launch; this establishes
that the mounted file snapshot does not present shared Git administration or
object metadata. This remains a primitive-level visibility proof, not an
integrated result-transfer proof. The exact test passed twice (`1 passed` each)
on the disposable Lima guest `acp-2370-live-sandbox-20261010` after the process
assertions were added. After adding the `.git` visibility assertion, the full
opt-in runtime-test module passed `47 passed in 5.69s`; the exact test-source
hash is recorded below:
Ubuntu 26.04.1 ARM64, Linux `7.0.0-38-generic`, Python 3.14.4, systemd 259.5,
cgroup v2, rootless runc 1.5.2 (SHA-256
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`). The
audited toolchain was Ubuntu BusyBox 1.37.0 from package
`1:1.37.0-7ubuntu1` (package SHA-256
`ce7930cba8ab534f67e64229287863ba6c8f35a28831b5d6a8b2a5b81bdc480d`); the
fixture copied only its executable and resolved loader/library closure into
the private rootfs.

Exact hashes for the exercised source are:

| File | SHA-256 |
| --- | --- |
| `tests/test_oci_worker_runtime.py` | `7c311fa94b9a9ac7aebcdfacbceb25c8f50b0e201167b040e08ab152a6cfb857` |
| `src/agent_control_plane/supervisor/oci_worker.py` | `bcd015a23f3bbd0293d6d8fc864f31e5add53bfad33c592588c3f6ce1191a90d` |
| `src/agent_control_plane/supervisor/sandbox_attestation.py` | `f842834dfd47ac1bd124c36604e8124fc9f9b8e747128bc4cd6671d7f4afa9f0` |
| `src/agent_control_plane/supervisor/sandbox_workspace.py` | `793ab9000dadd310af81867395f476bb69e7cb2e64d923f1b542277c992ce188` |
| `src/agent_control_plane/runtime_drivers.py` | `ade6bbbec9bfdaaf3043a46e9957dba7692afd29421d3ebe9c1e70b62621c46c` |

For this disposable guest only, rootless user-namespace creation required
temporarily setting `kernel.apparmor_restrict_unprivileged_userns` from `1` to
`0`; an exit/signal restore trap was installed first, and postflight confirmed
the value returned to `1`. No AppArmor profile was applied, so this is not
AppArmor-confinement evidence. The systemd user manager remained running. After
the full module replay, postflight found no runc or host-marker process and no
ACP test unit; the live test's own attempt tree was removed by its verified
finalizer. Other synthetic roots left by the module's
`test_private_attempt_tree_*` unit cases are not live attempts and were left
untouched. No model, provider credential, paid inference, or NAS host was used.
This adds explicit process-visibility evidence to the primitive-level probe
only: it does not exercise `run_worker()`, monitor-owned cleanup, provider
authentication/egress, crash recovery, or result import; configured OCI worker
execution remains fail-closed.

### systemd credential handoff primitive (2026-10-11; opt-in proof only)

The supported systemd 252 contract provides `LoadCredential=`: a service reads
the credential from a read-only file under `$CREDENTIALS_DIRECTORY`, with
access limited to that unit's UID and root. The same version's documentation
explicitly warns that unit environment variables are not a secret channel
because they are exposed through D-Bus and propagated down the process tree.
This makes `LoadCredential=` a viable *monitor-service handoff primitive*; it
does not isolate secrets from other trusted processes running as the same host
UID, and it does not permit the worker to inherit the credential directory or
descriptor. See the pinned [systemd v252 execution
contract](https://github.com/systemd/systemd/blob/v252/man/systemd.exec.xml#L2259-L2266)
and [credential contract](https://github.com/systemd/systemd/blob/v252/man/systemd.exec.xml#L2717-L2735).

`test_live_systemd_loadcredential_is_read_only_and_not_environment` now
performs an opt-in no-model test with a randomly generated fake value in the
dedicated disposable VM. On Ubuntu 26.04.1 ARM64, Linux 7.0.0-34, Python 3.14.4,
systemd 259.5, cgroup v2, and a running user manager, the exact copied test
source (SHA-256
`d086b4de4ad7b6916b0c5d657c829fe4808993d9d94d8bf87a599bffcf62740f`) passed
(`1 passed in 0.10s`). The child read the credential, verified the per-unit
file was read-only and user-owned, and returned only its digest and boolean
checks; the test also checked that the value was absent from the child
environment and `systemd-run` output. It captures the exact live unit,
invocation, process identity, and cgroup before stopping the service; cleanup
requires the exact transient unit to become `not-found`, the captured process
identity to be absent, and captured cgroups to be empty. The private fixture is
retained if any of those checks fail. Post-run inspection found no transient
unit, process, cgroup, or fixture directory. This proves systemd's
credential-file transport only—not provider authentication, worker access
separation, secret rotation, or the production monitor path, which does not
yet use `LoadCredential=`.

Do not equate `Restart=on-failure` with ACP recovery. systemd documents restart
as a stop followed by a start and subjects it to start-rate limits; the monitor
must re-read the exact journaled fencing epoch and reconcile the exact units
before it can observe or cancel a worker. A service restart must never blindly
repeat the launch request. The service's credential-source lifetime and
restart behavior is now tested on exact systemd 252.39 below. Monitor-owned
`RuncLaunchHandle` lifecycle and registered-worker integration remain open.
See the pinned [systemd v252 service restart
semantics](https://github.com/systemd/systemd/blob/v252/man/systemd.service.xml#L493-L495)
and [restart rate-limit behavior](https://github.com/systemd/systemd/blob/v252/man/systemd.service.xml#L818-L823).

**Credential source lifetime and restart fail-closed proof (2026-10-11; systemd
252.39).** The opt-in
`test_live_systemd_loadcredential_restart_requires_source_again` ran twice in a
new no-host-share Lima 2.2.1 VZ Debian 12 ARM64 guest: kernel
`6.1.0-53-cloud-arm64`, systemd `252.39-1~deb12u2`, Python 3.11.2, pytest 9.1.1,
and cgroup v2. The exact test-file SHA-256 was
`de735a8d37a8b6c5a8cd3e636285474c03bfd58b5d5a17022d48da435c447930`; both
opt-in runs passed. It used only a random fake value and a private mode-0700
fixture. After the first service process was active, the test unlinked the
identity-checked source, let that process read the same credential copy again,
and then forced an exit to exercise systemd's automatic restart. The child
reported only the digest and boolean checks: its credential stayed unchanged
and read-only and the fake value was absent from its environment. systemd
recorded an automatic restart and failed at `CREDENTIALS` (`243/CREDENTIALS`)
before a second worker process ran; the fixture's process-start marker contained
exactly one activation. This matches systemd's contract that credentials are
acquired at activation, immutable while the service runs, and released on
deactivation ([systemd v252 service credentials](https://github.com/systemd/systemd/blob/v252/docs/CREDENTIALS.md#system-and-service-credentials)).

Post-run checks found no transient unit, populated cgroup, original process
identity, or fixture directory. This closes only the systemd credential
transport/lifecycle primitive: ACP's production monitor still does not use
`LoadCredential=`, and this does not isolate credentials from other trusted
processes under the same host UID, prove provider authentication, or wire the
monitor into `run_worker()`. Keep configured OCI worker execution fail-closed.

### No-model sandbox output collection gate (2026-10-15; opt-in proof only)

The exact test source SHA-256
`be106719ac42c9f87f187072b570513e888ca63098253f17bce56d2b2ceedc5e`
passed the complete `test_sandbox_worker_lifecycle_integration.py`
module (3/3) on the dedicated disposable Lima guest: Ubuntu 26.04 ARM64,
kernel 7.0.0-38-generic, Python 3.14.4, systemd 259.5, cgroup v2, BusyBox
1.37.0, and rootless runc 1.5.2 (SHA-256
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`).
No model, provider, or credential was used.

The worker checked that `/workspace/.git` and its HEAD were absent,
then wrote two disposable result paths declared by the persisted task. The
host collector derived its write-set matcher from that persisted task,
validated the exact output bytes, and produced a bounded change-set digest. A
separate undeclared-output probe was rejected with `undeclared_write` and
removed. After the run, a fresh safe snapshot of the registered source
worktree matched the baseline manifest for all non-root-`.git` entries. The
journal remained at `exited`; after candidate capture was rejected with
`sandbox_result_evidence_unverified` because trusted cleanup had not been
recorded, a second journal read confirmed phase `exited` and no stored result
candidate. `cleanup_verified_written` remains false. This demonstrates
bounded output scanning and preserves the import fence; it does not
demonstrate successful result import, `run_worker()`, monitor-owned cleanup
verification, cancellation/restart recovery, or provider credentials/egress.

The guest's `kernel.apparmor_restrict_unprivileged_userns` was 1 and
initially denied namespace creation. For this disposable test only, it was
temporarily set to 0 and restored to 1 by an exit trap; postflight confirmed the
restored value, no remaining ACP test units or fixture roots, and zero
D-state processes. This run had no AppArmor profile applied to the monitor and
is not evidence of AppArmor confinement or a production prerequisite policy.
Keep configured OCI worker execution fail-closed.

### Exact launch-driver cgroup attestation (2026-10-15)

The runc client must run in the deterministic systemd service
`acp-launch-driver-{execution_id}.service`, derived from the reserved durable
execution ID. The service must be active with a valid invocation ID, and its
cgroup must be a direct child of that attempt's exact slice. The runc client
PID/start-time identity is checked in the same cgroup. This is separate from
the monitor's wrapper service/cgroup and the container init's runc scope.

The collector reads the launch-driver service identity along with the wrapper,
attempt slice, and runc scope, then re-reads them to reject drift. The journal
compares the collector-issued service name against the durable execution ID
both before and while holding the launch-gate lock; it rechecks process
membership and all four systemd identities immediately before recording the
running transition and authorizing the one-shot gate. A valid receipt for a
different reserved-prefix service is stale and cannot release the gate.

The opt-in live runc lifecycle test passed on the disposable Ubuntu 26.04
ARM64 / Linux 7.0.0-38 / Python 3.14.4 / systemd 259.5 / cgroup v2 guest with
rootless runc 1.5.2 and BusyBox 1.37.0. The complete opt-in systemd slice
integration module passed 8/8 on the same guest. SHA-256 of the exact source
and test files copied to and run in that guest:

| File | SHA-256 |
| --- | --- |
| `sandbox_attestation.py` | `f842834dfd47ac1bd124c36604e8124fc9f9b8e747128bc4cd6671d7f4afa9f0` |
| `sandbox_execution_journal.py` | `cae1b00f54032fe334d50bc696c30d1fe7b0a670bde1efceca8f785e7f217c96` |
| `sandbox_monitor_service.py` | `90f42cc0191845465d65acc3d1a6e441ca3dc85fa1b3d966466706383b4c3e20` |
| `test_sandbox_worker_lifecycle_integration.py` | `3aa8bddfd31344d20e19ff72b4f95bf90c40de505e1c9e0c2cdaa6982514625f` |
| `test_systemd_slice_integration.py` | `2cff01f66464fd6ad9d966fb5b9c67887f4c690a9b4edf417f1b124a481601d8` |

Postflight confirmed the guest manager remained running, the temporary
`kernel.apparmor_restrict_unprivileged_userns` change was restored to `1`, and
no fixture roots, ACP test units, or D-state processes remained. These live
tests prove the attested systemd/runc launch boundary and its negative cases;
they do not qualify `run_worker()`, which remains fail-closed.

This closes the arbitrary-sibling-cgroup gap for the launch client. It does
not prove worker registration, monitor-owned cleanup, recovery after monitor
crash, provider isolation, or end-to-end `run_worker()` acceptance; configured
OCI worker execution remains disabled.

### Production monitor producer and controller reconnect (2026-10-15)

The opt-in
`test_live_production_monitor_service_survives_controller_crash_and_cancels_exact_scope`
passed (`1 passed`) on the dedicated disposable Lima guest: Ubuntu 26.04 ARM64,
Linux 7.0.0-38-generic, Python 3.14.4, systemd 259.5, cgroup v2, and a running
user manager. The test started the in-repo monitor service for a unique,
no-model `/usr/bin/sleep` scope; checked exact scope/slice invocation and cgroup
identity plus key-file permissions and absence from the receipt, monitor
command line, and environment; killed the starting controller; reconnected
through the durable receipt; observed the exact running scope; canceled it;
replayed the same cancellation ID; and verified the scope and cgroup were
inactive/empty. The fixture's `finally` path verified the exact unit
activations and removed its private temporary directory. No model, provider,
paid call, or external credential was used.

The source files copied into the guest matched the host worktree byte-for-byte:

| File | SHA-256 |
| --- | --- |
| `oci_worker.py` | `bcd015a23f3bbd0293d6d8fc864f31e5add53bfad33c592588c3f6ce1191a90d` |
| `sandbox_execution_journal.py` | `1e74e092d316bd4c3eac4553c25e668d521a87d042142f2e83a5a6a56f876258` |
| `sandbox_monitor_ipc.py` | `b9147858a1cd30f04bb9273f6f26b9382970414366f929cb526525941b48fead` |
| `sandbox_monitor_service.py` | `2bdc15107039447422c5d24f5970eb7a651d59f58f04a4d48ae511ca6aaf1058` |
| `sandbox_monitor_lifecycle.py` | `b00dd5c714890aee467f6a2ab187ae1b12847780eaf5c004532dbd17fe4fb5db` |
| `sandbox_monitor_receipt.py` | `ce03104fd7132baf8c8b34e5d45421c8dd899ac7bc35a60373191b3d1810af66` |
| `workers.py` | `4a9dc7c87c351dbbe2c62e0964627096f2f33182136d8a14bbe353cec856d92e` |
| `test_systemd_slice_integration.py` | `2cff01f66464fd6ad9d966fb5b9c67887f4c690a9b4edf417f1b124a481601d8` |

Postflight found the AppArmor user-namespace setting restored to `1`, no
failed or active ACP units, no ACP monitor processes or sockets, and no
`acp-production-monitor-*` fixture. This proves the in-repo monitor producer,
authenticated durable-receipt reconnect, exact-scope cancellation, and
idempotent cancel replay. It does not prove the supervised worker boundary,
provider credential/egress policy, validated result import, or production
`run_worker()` integration; configured OCI worker execution remains
fail-closed.
