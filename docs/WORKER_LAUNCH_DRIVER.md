# OCI launch-driver and recovery-monitor architecture

**Status:** revised architecture decision for task #3142, correcting an earlier
draft that assigned process-local launch ownership to the out-of-slice monitor.
Independent review of the earlier draft was **NO-GO**. The corrected ownership
decision received independent **GO** on 2026-10-16 for the two-service topology
and supervisor-owned final cleanup verification (reviewed ADR SHA-256
`8be47037cdf9ecc807621892ea18ed8123857449a967fbcbe3d3df7fd00aae55`). This is
architecture approval only, not implementation or lifecycle acceptance. No
production integration is authorized by this document. Configured OCI
`run_worker()` still fails closed with `sandbox_executor_unavailable`.

## Decision

Use two systemd-owned services for each exact execution tuple
`(attempt_id, claim_token, execution_id)`:

- The `acp-launch-driver-<execution_id>.service` runs **inside the exact attempt
  slice**. It owns launch-plan redemption, the one-shot launch submission,
  process-local `RuncLaunchHandle`, the local init gate, collection of trusted
  runtime evidence, the durable `running` transition, cancellation execution,
  runc wait/reap, and an unverified cleanup report.
- The authenticated recovery monitor service runs **outside the attempt
  slice**. It owns only its authenticated status/cancel endpoint and durable
  request ledger and service receipt. It is the sole authenticated status/cancel
  IPC endpoint; status is sourced from the exact driver's response
  and durable journal, and cancellation is forwarded with replay-safe IPC. It
  never executes runc operations, signals a host PID, reconstructs or receives
  the launch handle, collector-issued attestation object, or gate permit.
- The ACP supervisor/recovery verifier is the **only owner** of the final
  `cleanup_verified` transition and fence release. It acts only after both
  services have exited, validates the driver's unverified cleanup report, and
  independently reads back exact process, unit, invocation, cgroup, container,
  bundle, and state absence. Neither service can attest its own absence or
  release the cleanup fence.

The sealed launcher is started by the launch-driver service. Its runc client
remains in that exact service cgroup, as required by the existing attestation
contract. Runc creates the worker `.scope` directly under the same attempt
slice; that scope contains the container init. No `StartTransientUnit(PIDs=...)`
move of the runc client is used by this architecture.

```text
systemd user manager
└── user-acp.slice
    ├── exact recovery-monitor.service       outside the attempt slice
    └── exact attempt.slice                  execution resource boundary
        ├── exact launch-driver.service      owns handle, gate, collector, wait/reap
        │   └── runc client                  remains in this service cgroup
        └── exact worker.scope               created by runc; contains init
```

The monitor and driver each use `Restart=no`; an uncertain activation or
redemption is adopted only by exact unit identity, invocation, process start
identity, cgroup, and execution tuple. A retry that could create a second runc
client is forbidden. Credentials used to start/redeem these services must be
single-execution, narrowly scoped, absent from argv/environment, and distinct
from provider credentials. The user-manager deployment must prove the manager
remains alive for the required controller-restart window (for example, by
checking lingering); this is not a logout, manager-restart, or reboot-survival
claim.

This split follows the repository's existing source contract: the collector
binds `runc_client_pid` to the exact `launch-driver.service` cgroup, while the
journal accepts the exact registered handle and collector-issued object in the
same process. Moving the runc client out of that service cgroup or serializing
either process-local capability would invalidate that contract.

## Lifecycle and failure contract

1. The supervisor reserves the exact execution tuple and immutable launch plan,
   then durably records one at-most-once driver-start intent before requesting
   systemd activation. It starts the recovery monitor outside the attempt slice
   and the launch-driver inside the exact attempt slice. An uncertain start is
   adopted by exact unit/invocation and tuple; it is never retried blindly.
2. The launch-driver proves that its own `MainPID`, kernel start identity,
   `InvocationID`, unit name, and `ControlGroup` match the exact active service
   directly beneath the recorded attempt slice. It redeems the single-use
   intent, validates the pinned plan, and invokes the existing sealed launcher.
   The runc child stays inside the launch-driver cgroup. If startup, redemption,
   or service identity is ambiguous, the gate remains closed and the execution
   fence remains held.
3. While init is gated, the launch-driver obtains the existing collector-issued
   runtime attestation for the exact recovery monitor, launch-driver service,
   attempt slice, runc client, worker scope, init, process-start identities,
   and resource controls. In the same process, the exact local handle and exact
   attestation object authorize the durable `running` transition. Only after
   that journal commit succeeds may that handle release its one-shot gate.
   Collection, transition, or cancellation races fail closed under the existing
   gate/journal fences.
4. A fresh supervisor authenticates to the recovery monitor. The monitor
   routes status/cancel over authenticated, replay-safe IPC to the exact
   driver. The driver serializes cancellation against gate release, revokes an
   unreleased gate, and stops only the exact worker scope; it never falls back
   to host-PID signaling. It waits/reaps with its local handle, performs
   container deletion, and writes only the journal's unverified cleanup report.
   A scope-empty observation or systemd `Result=success` is not a substitute
   for the kernel wait receipt. After durably recording the terminal replay
   response and observing the exact driver activation stopped, the recovery
   monitor closes its endpoint and exits; it cannot attest its own absence.
5. After both exact service activations are absent, the ACP supervisor/recovery
   verifier independently checks the persisted wait receipt and cleanup
   report, runc-client and container-init start identities, exact monitor and
   driver invocation/PID identities, worker-scope and attempt-slice identities,
   and empty cgroups for all four units. It also reads back runc state/container
   absence and private bundle/state removal. Only this verifier may add the
   final verified observations and advance `cleanup_reported` to
   `cleanup_verified`. Missing or conflicting evidence remains fenced and
   prohibits result import. If the driver dies before its
   wait receipt or unverified report is durable, the monitor cannot fabricate
   either or recover the process-local handle; the execution stays ambiguous.
   Same-UID compromise and manager restart/logout/reboot recovery are not
   implied.

## Evidence and non-evidence

The independent review of the prior ADR found a blocking mismatch: it placed the
handle-owning monitor outside the attempt slice and proposed migrating attestation
from the exact launch-driver service to a runc-client scope. Independent review
of the corrected decision returned **GO** on 2026-10-16 after assigning final
cleanup verification and fence release only to the supervisor/recovery verifier,
which waits for both services to exit and independently verifies exact
identities and absence evidence. That review was limited to architecture; the
production lifecycle and cleanup verifier remain unimplemented.

A separate `StartTransientUnit(PIDs=...)` experiment passed live on 2026-10-16
in disposable Ubuntu 26.04.1 ARM64 / Linux `7.0.0-38` / systemd 259.5 / cgroup
v2. The blocked child was moved into a deterministic transient scope and exact
unit, invocation, cgroup, PID start identity, stop, and wait/reap were checked.
At that run, `sandbox_monitor_service.py` SHA-256 was
`7fff5fb9fc086f81b1b945493b982443598585cbb01242a9aa274ee21b1b4f30` and the
test SHA-256 was
`c7a4031866c4297716f29757b5476f42fe304648f2fe51982dda385e02912a67`. The
current helper SHA-256 is
`3954ba738a64a7e849d22b0e329e9c6b314a999fa0c854443238b494f7ff5d4f` and the
current test SHA-256 is
`2797b52f3227501f1c75504ec6a1fe93e6547b723e8389dc03348fdc1bdafe27`; neither
current revision was included in that live run. The current helper was not
rerun live, and the current test was not rerun after its local-only edit. This
experiment proves only that the earlier helper revision could attach a blocked
PID to a transient scope; it is **not part of the selected launch-driver
architecture** and does not prove monitor/driver integration. The helper also
does not itself prove or retain the private launcher's exec gate: a caller must
hold that gate across the call. Calling the helper for the production runc
client would violate the current attestation requirement that the client remain
in the exact launch-driver service cgroup.

The local cleanup regression uses a real held child and injected kill/first-wait
failures; it verifies EOF exits 126 and an unverified scope binding preserves
the attempt slice. This is test-harness cleanup evidence only, not production
driver cleanup evidence.

## Required implementation and proof

Current production code does not implement this decision. In particular,
`start_sandbox_execution_monitor()` still starts after a worker scope is live;
there is no launch-driver service producer that starts before execution; the
durable journal has no at-most-once driver-start redemption path; and the
existing handle/attestation/running flow is not yet owned by the launch-driver
service. The journal intentionally has no production `cleanup_verified`
writer; a separately authorized, exact-identity verifier is required after
both services exit. The existing `run_worker()` refusal must remain unchanged.

Implement the driver-start intent and redemption around the existing
one-shot launch-submission journal without serializing a `RuncLaunchHandle`,
collector-issued attestation object, or gate permit. Bind every service,
process, cgroup, and receipt to the exact execution tuple. Keep init blocked
until trusted collection and the same-process durable `running` transition
succeed. Route fresh-supervisor cancellation only through authenticated
monitor-to-driver IPC. If the driver exits before kernel wait/reap and
cleanup evidence are durable, keep the execution fenced and reject result
import.

The opt-in disposable Linux/systemd test must use the real pinned launcher for
a bounded no-model payload and prove exact two-service placement, one driver
activation/no duplicate runc launch, held gate until attestation plus journal
commit, fresh-controller authenticated cancellation, local wait/reap, separate
cleanup observations, and a fenced/no-import outcome if the driver dies before
the wait receipt. Component tests, the separate PIDs-scope experiment, and
exact-head CI are not substitutes for this lifecycle proof.

Parent task #2370 remains open until workspace isolation, provider
authentication/egress, validated result transfer, and all independent safety
gates pass. This ADR does not enable OCI in `run_worker()` or weaken the macOS
execution path.
