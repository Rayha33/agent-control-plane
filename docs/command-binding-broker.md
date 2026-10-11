# Command-binding broker design (proposal)

**Status: not implemented; not a security guarantee.** As of 2026-10-10,
`require_command_binding = true` deliberately returns `unknown` and blocks QC or
integration. A disposable Ubuntu 24.04 / systemd 255 experiment showed that
system-manager-owned `PrivateNetwork=yes` units can receive distinct network
namespaces and that their children share their unit's namespace. In a separate
lifecycle probe, stopping two exact root-created services with
`KillMode=control-group` removed all recorded owner/server/phase-child PIDs;
the manager then reported the units not-found with an empty `ControlGroup`
field. That probe did not sample each unit's `cgroup.events`, so per-unit
cgroup emptiness remained an acceptance gate at that point. These low-level
probes did not exercise an ACP broker or production worker path. Independent
adversarial review rejected the proposed single-UID descendant tree as an ACP
backend.

A follow-up disposable-VM probe on the same date used systemd 255 transient
units with distinct `DynamicUser=yes` identities. Its first iteration used
`NetworkNamespacePath=/proc/<holder-pid>/ns/net`; that supports the explicit
namespace-path mechanism only, not the proposed `JoinsNamespaceOf=` mechanism.
Dynamic UIDs are runtime identities, not durable attempt identities; bind
authorization and receipts to the attempt generation and each unit's
`InvocationID`, never only to a numeric UID or namespace inode.

**Validation correction (2026-10-11):** an adversarial audit found that the
original harness read `journalctl --output=cat`. systemd can include its own
`Starting` record with the complete `python -c` command source in that output,
so source-code marker strings could satisfy assertions without being emitted by
the phase process. The original manager check looked for a generic
`permission denied` phrase plus a nonzero result, but did not require the phrase
to occur in a manager-connection diagnostic. The earlier systemd 255 harness
results and their command-output, denied-manager, endpoint-reachability, and
holder-visibility assertions are withdrawn as evidence. The separate
`NetworkNamespacePath=` experiment does not establish `JoinsNamespaceOf=`
behavior.

The corrected opt-in harness parses journal JSON and accepts output only from
records whose `_SYSTEMD_UNIT` and `_PID` match the observed phase unit and
`MainPID`. It fails if the phase process emits no journal records. Its manager
probe requires a nonzero exit plus both a manager-connection failure context
and a recognized access-denial diagnostic; regression tests reject unrelated
CLI errors, connection refusal, and a denial phrase in the wrong context. On
2026-10-11, the exact checked-in test file at commit
`d4bd2f773042ed6a237cec4cc0307f4098674362` (SHA-256
`8c35c1b6b6e39d4da62a6054003ac4ded8ef48c950b6ebf1a84aaee09e609565`) ran on a
disposable Ubuntu 26.04.1 VM (kernel `7.0.0-34`, systemd `259.5`, cgroup v2):
`8 passed in 6.84s` (seven diagnostic-check unit cases and one opt-in live test).
The manager diagnostic was `Failed to connect to system scope bus via local
transport: Operation not permitted`. The live test observed phase output from
the phase PID, confirmed sibling attempt ports were unreachable, rejected a
healthy wrong-attempt response before fake DB/queue mutation, checked the
holder's process visibility/signaling boundary, and verified exact transient
unit/cgroup cleanup. It requires root plus the exact root-owned
`/run/acp-disposable-systemd-test` marker before creating transient units; on
Ubuntu the marker is created as root with:
`printf '%s\n' 'acp-systemd-network-binding-v1' | sudo tee /run/acp-disposable-systemd-test >/dev/null && sudo chmod 600 /run/acp-disposable-systemd-test`.
Postflight found no `acp-netbind-*` units or matching cgroups, and the marker,
copied test file, and three packages installed solely for pytest on the
disposable VM were removed. This remains primitive-level evidence, not a
supported ACP executor result.

**Hosted root-probe admission gate (design; not yet implemented, 2026-10-11):**
A live GitHub API read reports `agent/2523-network-binding` as unprotected and
the repository has no active rulesets. Do not run the opt-in probe as root from
this ref until repository review and push restrictions are configured and
verified. GitHub-hosted Linux VM runners provide passwordless `sudo`;
`ubuntu-slim` is an unprivileged container runner and is unsuitable for this
systemd probe. The branch name alone is not a trust boundary, and a pushed
workflow can execute code from its checkout. A future hosted probe should run
only on a protected ref and for an explicitly trusted actor. It should avoid
pull-request triggers that execute fork-controlled code with root access,
declare only `contents: read`, disable
checkout credential persistence and dependency caches, install dependencies
without elevation, then run only the exact opt-in test as root. Require a
machine-readable result with exactly one pass and no skips, failures, or
errors; a skipped job or test is not evidence. `github.ref_protected` only
indicates that some branch protection or ruleset applies, so inspect the
configured review and push restrictions separately. When enabled on a
GitHub-hosted multi-CPU Ubuntu runner, each job uses a fresh VM. This gate
provides repeatable primitive-level evidence only, not broker/worker
integration or production command/network binding.

See GitHub's [hosted-runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
[workflow security guidance](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target),
[`ref_protected` context](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#github-context),
[protected-branch controls](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches),
and [dependency-cache security](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching).

**Current-source follow-up (2026-10-11):** the updated checked-in harness at
PR #43 commit `ddac29f33085cc5c84eddd349510b578aabfa8fc` (test-file SHA-256
`e10b2db67f552e85237833ed4d8809f96e953b833a0d3f0a2a914c9341d0b9e8`) was
rerun on the same disposable Ubuntu 26.04.1 guest: kernel
`7.0.0-34-generic`, systemd `259.5`, Python `3.14.4`, cgroup v2. The opt-in
suite passed `26 passed in 6.88s`, including its manager-denial and cleanup
regressions plus the live two-attempt binding probe. That probe rejected
sibling-port access and a healthy wrong-attempt identity before fake DB/queue
writes, checked manager-socket denial and holder visibility/signaling, then
verified restart invalidation and exact unit/cgroup cleanup. Postflight found no
`acp-netbind-*` units, cgroups, or test fixtures; the root-owned opt-in marker
and copied source snapshot were removed. No packages were installed for this
run. This still proves only the systemd primitive, not an ACP command executor.

This is evidence for a systemd primitive with local HTTP fakes—not proof that
ACP launches real app/DB/queue services or QC/integration commands through it.
It does not establish broker authorization, immutable policy on an installed
host, task/claim/fence/source-command binding, filesystem/workspace isolation,
real database or queue behavior, broker restart recovery, or production worker
execution. Until those gates pass, the production target remains `unknown` and
strict QC/integration stays blocked.

Runtime-target preflight receipts now include `command_set_sha256` and the command
count plus `command_set_scope`, which explicitly limits the digest to the configured
deterministic QC/integration gate commands for that phase. It excludes the critic
command and runtime setup/teardown commands. The digest uses contract
`acp-command-set-v1` over the ordered exact shell-command strings, the scope, and
the supervisor shell-runner contract. Do not embed credentials in command strings;
use the separate credential handles. The digest makes this planned command set
auditable alongside the attempt/task/claim/phase/source and resource identities.
For a phase with runtime-target receipts enabled, config loading limits its
hashed gate command set to 128 commands and each command to 65,536 characters.
Phases without target receipts retain the existing configuration behavior.
It is not execution attestation: it does not bind executable bytes, the effective
environment, workspace immutability, or the process's live network namespace.
`require_command_binding=true` therefore remains `unknown` and blocks command
execution until a trusted executor supplies those proofs.

**Sampled freshness guard (2026-10-11):** when a non-strict phase has a successful
runtime-target preflight, ACP repeats the live app identity probe and refreshes
the trusted runtime-driver resource view before each configured QC/integration
command. For `namespace_runtime` resources, this invokes the read-only systemd
probe and requires a valid active `InvocationID`; the ID is bound into the target
resource snapshot and its hash. The sample time is recorded separately on the
overall manifest and receipt and covered by their full evidence hashes; it is
not part of `resource_snapshot_sha256`. Missing or inconsistent live identity
blocks a required target; samples older than 30 seconds or more than 5 seconds
in the future are treated as unavailable. A changed invocation ID invalidates
the preflight snapshot. Other driver kinds, including Docker, still use their
latest persisted trusted-driver evidence. Each `runtime_target_revalidation`
receipt references the exact preflight receipt and command-plan digest. This
detects sampled unit replacement after preflight; it is not atomic with command
launch, does not constrain which endpoint the command can reach, and does not
make a target verified. A command can race the sample or ignore the provided
manifest. `require_command_binding=true` remains fail-closed until the
broker-owned executor enforces and attests command networking.

## Claims that must not be conflated

1. **Allocation:** ACP assigned a port, database/schema, queue, or unit name.
2. **Application report:** an HTTP endpoint claims an attempt or namespace ID.
3. **Command configuration:** ACP gave a test command the intended URL and
   environment manifest.
4. **Enforcement:** the OS prevents that exact command from reaching another
   attempt's endpoint and writing its state.

Only the fourth claim can turn command binding into a security boundary. The
current runtime-target receipt provides at most corroboration for the first two;
the configured test process can ignore its manifest. No receipt may be called
verified while the enforcement evidence is unknown.

## Threat model

Treat agent, build, and test code as untrusted: it may deliberately choose a
sibling endpoint, forge self-reported identity, inspect inherited descriptors,
signal same-UID processes, use a user service manager, or connect to a host Unix
socket. Also handle accidental cross-wiring, service replacement between
preflight and execution, and supervisor or broker crashes. Select one explicit
trust model: either the authenticated ACP supervisor is trusted and included in
the trusted computing base with the host kernel, system manager, and small
root-owned broker; or the supervisor is not trusted and the broker independently
validates task/claim/fence authority against a trusted source rather than claims
supplied by the supervisor. A worktree, port allocator, environment variable,
app response, `NoNewPrivileges`, or network namespace by itself does not
establish all these properties.

## Candidate Linux architecture

This is the smallest direction supported by current evidence, not an approval to
ship it:

1. A root-owned broker is the sole ACP component allowed to use the system
   manager. Its local API accepts only validated high-level operations
   (`create_attempt`, `run_phase`, `stop_attempt`) with opaque attempt and phase
   IDs. It generates unit names and all unit properties. It never accepts an
   arbitrary command, UID, unit property, unit name, namespace path, or
   `ExecStart` from the agent. Authenticate the ACP supervisor and independently
   validate task/claim-fence authority unless the selected trust model explicitly
   places that supervisor in the trusted computing base. Do not give the
   untrusted worker the broker socket, system bus, namespace FD, or a
   usable user-manager path. An authentication prompt is not proof of denial:
   the exact worker UID must be tested without an interactive authorization
   agent.
2. The system manager starts one fixed, trusted namespace-holder unit per
   attempt with `PrivateNetwork=yes`. It is not the untrusted worker and exposes
   no worker-writable control channel. Start worker, application/service, and
   QC commands as separate units with distinct UIDs. Test `ProtectProc=invisible`
   and narrowly chosen `InaccessiblePaths=` entries as part of the fixed worker
   policy; the VM probe showed they can hide the holder process and block access
   to the tested manager sockets. Set
   `JoinsNamespaceOf=<exact-holder-unit>` and `PrivateNetwork=yes` on each
   joining unit; ACP must verify the live namespace identity of every command,
   not infer it from unit configuration. Only one eligible namespace owner may
   be active for a join operation; systemd documents the result as undefined
   when multiple active candidates have different namespaces. Set fixed
   `KillMode=control-group` and `Delegate=no` properties on every attempt unit;
   hold each untrusted payload behind a trusted, immutable broker-controlled
   pre-exec gate bound to the exact unit `InvocationID` and attempt generation.
   Read back and verify the effective properties before releasing that gate. On
   any mismatch or lost broker state, never release the payload, stop the unit,
   and verify cleanup. A platform that cannot enforce this barrier fails closed.
3. Give the agent only its attempt's writable workspace and required service
   endpoints. Run QC under a different identity against a frozen, read-only
   source/result snapshot. Hide host DBus, container-runtime, SSH-agent, and
   other filesystem-backed sockets; audit inherited descriptors and prove there
   are no inherited network or host-control socket FDs except explicitly
   permitted pipes/stdout/stderr. A network namespace does not isolate host
   files or filesystem-backed Unix sockets. Abstract Unix sockets are
   network-namespace scoped. Inherited socket FDs and reachable host socket
   paths must be denied; audit the FD and path policy to verify that only
   explicitly permitted endpoints remain. Keep the broker, namespace owner,
   QC input, and evidence paths unwritable and unsignalable by the worker. If
   `DynamicUser=` is used, prove that any state writable by the transient UID is removed or
   isolated before that UID can be recycled; do not leave attempt files in a
   shared host directory owned only by a reusable numeric UID.
4. Allocate actual database/schema and queue state per attempt. Keep local fake
   services inside the attempt namespace for isolation tests; a distinct port
   or schema label alone does not block writes to a shared backend. Do not point
   this prototype at production or shared services.
5. Bind a command receipt to boot ID, attempt generation, task and claim fence,
   phase, source/tree revision, and a command digest covering executable bytes,
   canonical arguments, allowlisted environment, working directory, and the
   immutable input snapshot. Enforce that the command and interpreter/runtime
   actually executed are the measured objects: use an immutable read-only
   snapshot or pinned file identities, keep measured content non-writable between
   measurement and exec, and prevent replacement between measurement and exec.
   Include script interpreters and relevant runtime dependencies. Any mutation
   or identity mismatch invalidates the receipt and produces `unknown`. Also
   bind service/resource identities,
   systemd unit `InvocationID`, command PID plus start time, cgroup, and the
   command process's live network-namespace identity. Compare the identities
   immediately before and after launch/preflight and at completion. A restarted
   unit, changed target, PID reuse, missing observation, or ambiguous join
   invalidates the old receipt and produces `unknown`.
6. Persist enough broker state to reconcile after broker restart. On startup,
   fence old generations, stop orphaned attempt units, and verify each exact
   cgroup is empty before accepting new work for that attempt. Cleanup is not
   verified merely because `StopUnit` returned or the unit became inactive.
   Keep resource ceilings (CPU, memory, tasks, block-I/O bandwidth, workspace
   disk capacity, and wall time) in the tested fixed policy. Block-I/O controls
   are not a disk-capacity quota: enforce a separate workspace quota or fail
   closed if disk growth is unbounded. A required limit unsupported by the host
   is a failed preflight, not an omitted limit.

systemd provides relevant primitives, including `PrivateNetwork=`,
`JoinsNamespaceOf=`, execution/filesystem restrictions, and cgroup resource
controls. These are separate mechanisms and must be composed and verified by
the broker. The v255 namespace-joining contract states that both the joining
and target units need the matching namespace setting, and that the selected
namespace is undefined if multiple listed active units have different
namespaces; the broker must keep the join target singular and verify live
identities ([systemd v255 unit docs](https://github.com/systemd/systemd/blob/v255/man/systemd.unit.xml#L3588-L3617)).
`NoNewPrivileges=` does not prevent a process from asking a separate
IPC service to start work, and read-only filesystem settings do not alone hide
Unix sockets. See [systemd execution and sandboxing directives](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml),
[unit namespace joining](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml),
[resource-control directives](https://github.com/systemd/systemd/blob/main/man/systemd.resource-control.xml),
and the [systemd control-group interface](https://systemd.io/CONTROL_GROUP_INTERFACE/).

## Required adversarial acceptance before enabling it

- Test as the exact worker UID that a direct `StartTransientUnit` request cannot
  launch a unit or trigger interactive authorization; prove there is no
  worker-controllable user manager, broker channel, system bus, namespace FD,
  inherited network/host-control socket FD, or other privileged descriptor
  (except explicitly allowed pipes/stdout/stderr). The VM probe hid system bus
  sockets; it did not establish a D-Bus authorization denial when those sockets
  are available.
- Prove the worker cannot signal or inspect the broker, namespace holder,
  sibling attempt, or QC process. Prove host files, writable shared state, and
  filesystem-backed control sockets are inaccessible.
- Start two disposable attempts with distinct app, DB/schema, and queue
  resources. Each command must reach its own service and mutate only its own
  state. Deliberately direct a command to the sibling port/database/queue; it
  must fail before mutation. Use local fakes only.
- Run QC under a separate UID on an immutable read-only snapshot. Demonstrate
  that worker edits and signals cannot alter its input, executable, result, or
  receipt.
- If transient UIDs are used, force a UID-reuse scenario and prove old attempt
  files, sockets, and credentials are not accessible to the later unit. A UID
  number is not a durable attempt identity; bind evidence to generation and
  `InvocationID`.
- Exercise stale unit, wrong port, wrong DB/schema, shared queue, forged or
  missing self-report, endpoint substitution, preflight-to-launch replacement,
  unsupported namespace enforcement, PID reuse, and unit restart. Every
  missing/mismatched observation must fail closed.
- Kill the command, worker, supervisor, and broker at each lifecycle boundary;
  restart and reconcile; verify the old receipt is invalid and every exact
  attempt unit's cgroup is empty (`cgroup.events` reports `populated 0`) before
  cleanup can be marked verified.
- Measure the effective resource limits and exercise the separate workspace
  disk-capacity quota. Run focused and full supported tests,
  lint/format/build, exact-head CI, and independent adversarial review.

Until all gates pass on a supported host, the platform capability is
`unsupported`/`unknown`, `verified` remains false, and strict QC/integration
commands do not run. This Linux proposal does not complete or weaken the
separate outer worker-sandbox acceptance in [Worker sandbox](WORKER_SANDBOX.md).
