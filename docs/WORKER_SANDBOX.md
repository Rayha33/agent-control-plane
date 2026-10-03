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
incomplete. This record does not authorize `externalSandbox` for ACP workers.

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
Keep the existing direct worker path unchanged until the new backend passes the
gates below; an unsupported or partially configured sandbox must fail before
candidate code starts.

The existing worker lifecycle registers a host PID and process identity,
launches `worker_trampoline.py` directly with the registered worktree as its
cwd, and submits a committed worktree through ACP's existing checks. The
namespace resource driver instead launches a transient systemd service, builds
a private root, and binds `ACP_WORKTREE` read-only at `/workspace`. It has
separate setup/probe/teardown semantics; it does not own the registered worker
PID, cancellation, or recovery lifecycle. A `systemd-run` client PID is not a
durable identity for the service it started.

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
   sandbox commit is input convenience, not submission authority.
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
   bind both the wrapper service invocation ID and container scope invocation
   ID, container ID, bundle/image digests, exact cgroup path, host
   container-init PID/start identity, and attached runc exit receipt to the same
   attempt/fencing epoch. Keep the launch gate closed until these identities
   and the attempt/trust fence are durably checked. Cancel/recover/reap the
   exact scope with a finite TERM grace followed by KILL escalation, and
   positively verify stopped state, identity absence, and unit/cgroup absence
   before releasing fences. The runc client wait status and container-init
   identity are separate evidence; never conflate them. Any uncertain identity
   or absence retains the attempt and resource fences.
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

Read-only NAS inventory reported Debian GNU/Linux 12 (bookworm), Linux kernel
6.18.15, systemd 252.38 (`252.38-1~deb12u1`), cgroup v2 (`cgroup2fs`),
`/usr/bin/systemd-run`, `/usr/bin/unshare`, rootless `/usr/bin/runc` 1.3.5,
and delegated user namespaces. No Codex executable was found on the NAS `PATH`.
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
concurrent attempts, or the host-validated result-import path. The current
direct worker path remains unchanged and `externalSandbox` remains disabled.

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

The note does not preserve whether this probe used `--keep`, the exact `runc
delete` invocation, or a post-delete check that the container ID was absent
from the configured runc state root. Unloaded systemd units do not prove runc
state-root cleanup. If `--keep` was used, runc requires manual deletion; on a
repeat, record the exact cleanup command and verify state-root, cgroup, and unit
absence before counting cleanup as proven.

This does not prove that ACP persists either systemd invocation, captures an
attached runc exit receipt, coordinates cancellation/recovery across supervisor
restart, or safely releases its execution/result-import fences. It also does
not prove credential or provider egress policy. The direct worker path remains
unchanged and `externalSandbox` remains disabled.

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
