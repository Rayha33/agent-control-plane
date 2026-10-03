# Per-attempt worker sandbox decision

**Status:** proposed end-to-end architecture. Standalone bounded snapshot and
change-set primitives, exact host-side manifest replay validation, secure
snapshot readback, and an isolated-index candidate-tree builder are implemented.
They are not integrated into a worker executor or registered-worktree import.
The candidate builder writes host-generated blobs and a tree into the trusted
repository's object store but does not create a commit/ref or modify the
registered worktree or its real index; without a durable import journal those
objects are provisional and must not be treated as imported. End-to-end proof
remains incomplete. This record does not authorize `externalSandbox` for ACP
workers.

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
3. **OS-owned lifecycle.** Run one uniquely named systemd *service* per
   attempt/fencing epoch, with a user/mount/PID namespace, a private `/proc`,
   private tmpfs root, an explicitly audited executable/library closure, and
   exactly one writable attempt bind. Do not bind the whole host `/etc` or
   broad `/usr` tree: read-only mounts still disclose every readable file.
   Generate a minimal private `/etc` from reviewed non-secret inputs; never
   copy host credentials, private keys, provider configuration, or user config.
   The existing resource driver broadly binds `/etc` and `/usr`, so it is not
   suitable unchanged for workers. Test that a host-readable `/etc` sentinel
   is absent and that only reviewed toolchain/configuration files are visible.
   Keep `KillMode=control-group` and a finite runtime bound. Persist the service
   identity/invocation evidence with the attempt; recover, heartbeat, cancel,
   and reap via that unit identity rather than assuming the `systemd-run`
   client PID is the worker. Do not release the attempt or runtime reservations
   until the unit is positively absent.
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
   worktree. Prefer constructing a candidate tree with a temporary trusted Git
   index and host-generated objects, then materialize only that validated tree;
   alternatively use descriptor-relative `openat`/`O_NOFOLLOW` writes with
   parent-identity checks. A post-import `_submit` symlink check is too late to
   prevent a redirected host write. Ignore worker `.git` state and
   worker-reported hashes. Before import, persist a write-ahead journal keyed
   by attempt ID, claim/fencing epoch, systemd unit invocation ID, and result
   digest. Recovery must recognize the exact already-imported tree/commit,
   refuse replay into a later claim, and retain the fence on ambiguous state.

This design separates the OS containment identity from the worker's
untrusted Git metadata and from ACP's submission authority. It also changes
the current direct-PID lifecycle and requires a schema/recovery design before
implementation; a wrapper around `Popen` alone is insufficient.

## Measured host assumptions (2026-10-03)

Read-only NAS inventory reported Debian GNU/Linux 12 (bookworm), Linux kernel
6.18.15, systemd 252.38 (`252.38-1~deb12u1`), cgroup v2 (`cgroup2fs`),
`/usr/bin/systemd-run`, `/usr/bin/unshare`, and delegated user namespaces. No
Codex executable was found on the NAS `PATH`. Distro and systemd versions were
read over SSH from `/etc/os-release` and `systemctl --version`; kernel, cgroup
filesystem, command paths, and namespace availability were queried separately.
The sanitized values and provenance are recorded in the shared #2370 task
notes/log. A local macOS suite cannot prove Linux child-subreaper behavior;
exact-head Linux CI is required. The current source-generated NAS probe
exercised the resource-driver command boundary against synthetic fixtures
only; it did not launch an installed ACP worker or Codex/App Server. See
[integration limits](INTEGRATIONS.md#outer-sandbox-status) and
[PR #40](https://github.com/Rayha33/agent-control-plane/pull/40).

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
  proof.
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
