# OCI launch-driver and recovery-monitor architecture

**Status:** revised architecture decision for task #3142, correcting an earlier
draft that assigned process-local launch ownership to the out-of-slice monitor.
Independent review of the earlier draft was **NO-GO**. The corrected ownership
decision received independent **GO** on 2026-10-16 for the two-service topology
and supervisor-owned final cleanup verification (reviewed ADR SHA-256
`8be47037cdf9ecc807621892ea18ed8123857449a967fbcbe3d3df7fd00aae55`). A
production launch-driver producer and exact pinned-runc delete-action receipt
are now implemented and passed an opt-in disposable Debian/systemd test. This
is not full lifecycle acceptance: the fresh-process cancellation path also
passed its opt-in disposable Debian/systemd test. The supervisor-owned cleanup
verifier, schema-33 write-once verification receipt, and reaper retry path are
implemented; unit and mocked SQLite integration tests pass. Post-stop verifier
now rejects cgroup paths unless mountinfo maps `/sys/fs/cgroup` to the complete
cgroup-v2 hierarchy, and safely removes only the execution-derived monitor
socket from the private runtime directory. Natural completion and
fresh-process cancellation both passed the opt-in production-launcher test
through the real `reap_expired()` path (`cleanup_verified` and runtime/fence
release, one pass per mode). Each run now starts the real producer in a spawned
process that exits abruptly after the durable handoff receipt; fresh spawned
supervisor processes perform cancellation (when requested) and reaping. The
original pytest harness remains alive, so those runs prove producer-process
loss after handoff—not a full supervisor-daemon restart. A separate
manager-acceptance crash mode now proves the specific interruption after
successful `systemd-run` return and before receipt propagation; broader crash
windows and daemon restart remain unproven.
The journal suite also now has a spawned-process regression for launch-driver
death after the recovery-monitor starter reports acceptance but before the
durable `launched` receipt commits; that test uses synthetic systemd
observations and is not live manager evidence. A distinct opt-in live
systemd-252 mode now exercises that same monitor-accepted/pre-receipt crash
window against real manager and runc processes; it proves fail-closed
containment, not successful cleanup or restart recovery.
The code-bearing commit `2383221c1a84cf52c08f42043465baea2ed4d487` passed
[exact-head hosted CI run 38884017803](https://github.com/Rayha33/agent-control-plane/actions/runs/38884017803)
with all four Ubuntu/macOS × Python 3.11/3.12 jobs green. Result import is not
connected to the worker.
`cleanup_verified` certifies resource cleanup, not worker success; every result
consumer continues to require runc exit code 0. Configured OCI
`run_worker()` still fails closed with
`sandbox_executor_unavailable`.

## Decision

Use two systemd-owned services for each exact execution tuple
`(attempt_id, claim_token, execution_id)`:

- The `acp-launch-driver-<execution_id>.service` runs **inside the exact attempt
  slice**. It owns launch-plan redemption, the one-shot launch submission,
  process-local `RuncLaunchHandle`, the local init gate, collection of trusted
  runtime evidence, the durable `running` transition, runc wait/reap after the
  monitor stops the exact worker scope, and an unverified cleanup report.
- The authenticated recovery monitor service runs **outside the attempt
  slice**. It owns its authenticated status/cancel endpoint, durable request
  ledger, and service receipt. It validates cancellation against the exact
  journaled worker scope and stops only that scope; it does not own or receive
  the process-local launch handle, collector-issued attestation object, gate
  permit, or runc wait/reap authority, and it never falls back to host-PID
  signaling. It remains serving after a terminal response; the supervisor's
  cleanup verifier performs exact unit retirement after the driver's
  unverified report is durable.
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

1. The supervisor reserves the exact execution tuple and immutable launch
   inputs, then durably records one at-most-once driver-start intent before an
   out-of-slice producer requests systemd activation of the launch-driver inside
   the exact attempt slice. Redemption alone does not transfer ownership: the
   producer waits while the journal remains `reserved`. Activation is
   synchronous with `Type=exec` so systemd consumes its one-shot credential FD
   before the producer closes it; `--no-block` is unsafe for this handoff.
   Once the exact worker
   scope exists, the launch-driver starts the recovery monitor outside the
   attempt slice; one journal transition commits the scope, monitor receipt,
   and launch plan. The recorder holds the inode-pinned process-shared
   execution fence across monitor activation, authenticated receipt/status
   checks, and the durable `launched` commit. The producer returns only after
   that durable handoff. If the driver exits first or the producer is
   interrupted before handoff, the producer must win durable revocation before
   stopping any exact service. If the shared fence is busy, it waits for the
   serialized journal outcome: a committed handoff is adopted; a committed
   revocation permits exact driver/monitor/slice reconciliation. It must not
   infer quiescence from a momentary `not-found` read or return while the row
   remains reserved and another owner still holds the fence. Because the
   producer does not own the process-local runc handle or wait receipt,
   revoked executions remain ambiguous and fenced; this is containment, not
   cleanup proof. An uncertain start is never replayed blindly.
2. The launch-driver proves that its own `MainPID`, kernel start identity,
   `InvocationID`, unit name, and `ControlGroup` match the exact active service
   directly beneath the recorded attempt slice. It redeems the single-use
   intent, validates the pinned plan, and invokes the existing sealed launcher.
   Immediately before authorizing the one runc submission, it rereads the exact
   service and slice properties and process identity; a stopped, deactivating,
   restarted, or otherwise changed activation is stale. The runc child stays
   inside the launch-driver cgroup. If startup, redemption, or service identity
   is ambiguous, the gate remains closed and the execution fence remains held.
3. While init is gated, the launch-driver obtains the existing collector-issued
   runtime attestation for the exact recovery monitor, launch-driver service,
   attempt slice, runc client, worker scope, init, process-start identities,
   and resource controls. In the same process, the exact local handle and exact
   attestation object authorize the durable `running` transition. Only after
   that journal commit succeeds may that handle release its one-shot gate.
   Collection, transition, or cancellation races fail closed under the existing
   gate/journal fences.
4. A fresh supervisor first validates the runner credential and durably records
   stop intent under the execution fence. It then reconnects to the exact
   recovery monitor, authenticates the IPC request, and asks it to stop only the
   bound worker scope. The monitor never signals a host PID. The launch-driver
   retains the local handle, waits/reaps the exact runc client, performs
   container deletion, and writes only the journal's unverified cleanup report.
   A scope-empty observation or systemd `Result=success` is not a substitute for
   the kernel wait receipt. The monitor continues serving beyond the cancel
   response. The supervisor's cleanup verifier stops or reconciles the exact
   recorded monitor, driver, and scope activations after the driver's
   unverified report is durable.
5. The ACP supervisor/recovery verifier stops or reconciles the exact recorded
   service activations, then independently checks the persisted wait receipt
   and cleanup report, runc-client and container-init start identities, exact
   monitor and driver invocation/PID identities, worker-scope and attempt-slice
   identities, and empty cgroups for all four units. It also reads back runc
   state/container absence and removes only the inode-bound private bundle and
   state trees. A second post-removal systemd/process/cgroup observation is
   required before the write-once receipt advances `cleanup_reported` to
   `cleanup_verified`. Missing or conflicting evidence remains fenced and
   prohibits result import. If the driver dies before its
   wait receipt or unverified report is durable, the monitor cannot fabricate
   either or recover the process-local handle; the execution stays ambiguous.
   Same-UID compromise and manager restart/logout/reboot recovery are not
   implied.

## Evidence and non-evidence

Schema 31 provides two journal primitives: one write-once pre-activation start
intent and one write-once redemption receipt. The start intent binds the
attempt/claim/execution tuple, derived driver unit, pinned runtime, and
inode-bound private bundle/state/workspace roots. Redemption is accepted only
from a collector-issued observation whose systemd MainPID is the current
process and whose exact service invocation, process-start identity, cgroup,
attempt-slice invocation, and cgroup match. Launch submission and the
`reserved` → `launched` transition are fenced on that receipt; the final
`running` attestation must match it again. The SQL-scoped write capability binds
the complete receipt, including its redemption timestamp. The launch-submission
gate also recollects and compares the live service/slice activation immediately
before consuming the sole runc submission.

Schema 32 adds a scoped SQL write guard for a v3 cleanup report's process-local
pinned-runc delete receipt. The launch-driver owns the handle, gate, attestation,
kernel wait/reap, and exact `runc --root <state> delete --force <container>` action;
the receipt binds the command digest, pinned executable digest/version, exact
execution tuple, driver identity, command result, and immediate runc-state
absence. This action report remains explicitly `unverified`. It cannot prove
that the driver/monitor units, processes, cgroups, bundle, or state root are
absent after both services exit, and it cannot advance `cleanup_verified` or
authorize import.

Schema 33 adds a separate write-once verification receipt. Its SQL write guard
accepts the transition only with a process-local capability registered by the
supervisor-owned verifier, bound to the exact cleanup-report digest and current
execution tuple. Recovery can retry an eligible `cleanup_reported` row from the
reaper; failed or unavailable observations leave the attempt fenced. The
positive reaper retry/fence-release regression now drives the real verifier
with deterministic OS observations and a runtime-teardown double. The live
Linux/systemd lifecycle results below additionally exercise reaper-driven
verification and runtime/fence release after natural exit and cancellation,
after the producer process has exited and in a fresh supervisor process.

The independent review of the prior ADR found a blocking mismatch: it placed the
handle-owning monitor outside the attempt slice and proposed migrating attestation
from the exact launch-driver service to a runc-client scope. Independent review
of the corrected decision returned **GO** on 2026-10-16 after assigning final
cleanup verification and fence release only to the supervisor/recovery verifier,
which waits for both services to exit and independently verifies exact
identities and absence evidence. That review was limited to architecture; the
verifier implementation and mocked integration are additional source-level
evidence, not live lifecycle acceptance.

A separate `StartTransientUnit(PIDs=...)` experiment passed live on 2026-10-16
in disposable Ubuntu 26.04.1 ARM64 / Linux `7.0.0-38` / systemd 259.5 / cgroup
v2. The blocked child was moved into a deterministic transient scope and exact
unit, invocation, cgroup, PID start identity, stop, and wait/reap were checked.
At that run, `sandbox_monitor_service.py` SHA-256 was
`7fff5fb9fc086f81b1b945493b982443598585cbb01242a9aa274ee21b1b4f30` and the
test SHA-256 was
`c7a4031866c4297716f29757b5476f42fe304648f2fe51982dda385e02912a67`. The
PIDs-scope experiment exercised only those historical hashes; the test case has
not been rerun at current hashes. It proves only that the earlier helper
revision could attach a blocked PID to a transient scope; it is **not part of
the selected launch-driver architecture** and does not prove monitor/driver
integration. The helper also does not itself prove or retain the private
launcher's exec gate: a caller must hold that gate across the call. Calling the
helper for the production runc client would violate the current attestation
requirement that the client remain in the exact launch-driver service cgroup.

### Current-branch production monitor baseline (2026-10-16; pass, monitor only)

At commit `89c114e277963745c497a95025a2ca30e0257667`, the opt-in
`test_live_production_monitor_service_survives_controller_crash_and_cancels_exact_scope`
passed on the disposable `acp-2370-live-sandbox-20261010` Lima guest: Ubuntu
26.04.1 ARM64, Linux `7.0.0-38-generic`, Python 3.14.4, systemd 259.5, and cgroup
v2. The test ran the existing monitor producer against a harmless `/usr/bin/sleep`
scope; no model, provider credential, or network egress was used. Host and guest
SHA-256 matched for the test module (`88d9b9fef49261a1921a766f11b54a1f7714cd5a75115c35eb64cb651753cef5`),
`sandbox_monitor_service.py` (`3954ba738a64a7e849d22b0e329e9c6b314a999fa0c854443238b494f7ff5d4f`),
`sandbox_monitor_ipc.py` (`b9147858a1cd30f04bb9273f6f26b9382970414366f929cb526525941b48fead`),
`sandbox_monitor_lifecycle.py` (`b00dd5c714890aee467f6a2ab187ae1b12847780eaf5c004532dbd17fe4fb5db`),
`sandbox_monitor_receipt.py` (`ce03104fd7132baf8c8b34e5d45421c8dd899ac7bc35a60373191b3d1810af66`),
and `sandbox_attestation.py` (`de275b7c7a808d7ea78be8f683efc02b2fa671ef60a5c394ff6971ea50acb0bf`).
Postflight found no matching ACP service/scope units and no
`acp-production-monitor-*` fixture roots. This is a current live regression for
the monitor only. It does **not** exercise a launch-driver producer, journal
redemption in a service process, pinned-runc submission, same-process `running`
transition, fresh-process cancellation of the exact worker scope, or
supervisor-owned cleanup verification; the integrated lifecycle remains
unimplemented.

### Current-branch producer-process loss and fresh-supervisor recovery (2026-10-16; live reaper cleanup/fence-release pass)

The opt-in
`test_live_production_launch_driver_runs_exact_pinned_runc_request` passed in
both natural-completion and `ACP_LIVE_CANCEL_AFTER_START=1` modes on the
disposable Debian 12 / Linux 6.1 ARM64 guest with systemd 252.39, cgroup v2,
rootless pinned runc 1.5.2
(`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`), and
BusyBox 1.35.0. Each mode reported `1 passed`.
Natural completion started the exact driver service, ran a bounded no-model
payload, observed the same-process `running` transition and kernel wait/reap,
executed pinned `runc delete --force`, and verified the container-state entry
absent immediately after deletion. The test then passed the cleanup-reported
attempt to `reap_expired()` with an expired lease; the reaper ran the
independent post-stop verifier, persisted `cleanup_verified`, released the
runtime, and released the terminal attempt/resource fence. The live test
queried SQLite before and after that handoff: before, the task/attempt-owned
lease and one allocated test-port row matched the attempt expiry; afterward,
the lease owner fields were null with expiry zero, the runtime was `released`,
and the allocation row was absent.

The cancellation mode waited for the bounded payload's start marker, rejected
a wrong runner credential before monitor contact, then used a spawned fresh
controller process with the enrolled credential. That process reconnected to
the live monitor exactly once; a test hook made any legacy host-PID path fail.
The monitor stopped only the journal-bound worker scope. The launch-driver
waited/reaped with a nonzero task exit and persisted its exact v3 delete
receipt; `reap_expired()` then observed cleanup and wrote `cleanup_verified`
before releasing the runtime and terminal fence. The start marker existed and
the payload completion marker did not. A direct result-eligibility check still
rejected the nonzero exit.
In both modes, the real launch API ran inside a spawned producer process. After
the durable receipt returned, that process sent the exact receipt fields to the
test harness and exited via `os._exit(73)`; the test asserted the producer PID
and exit code. This is abrupt producer-process loss after committed handoff,
not a crash during the handoff itself. Cancellation mode then used another
spawned process for `terminate_worker()`, and both modes used a separate fresh
spawned process for the real `reap_expired()` call. The original pytest harness
and its `GitSupervisor` stayed alive throughout; there was no systemd user
manager restart or full supervisor-daemon restart.

After producer loss, both modes also started a fresh producer with the same
launch request. The test blocked any `systemd-run` submission and observed
`SandboxLaunchDriverServiceError`, zero second-start calls, and unchanged
durable start ID, digest, invocation ID, and driver PID. This is live no-replay
evidence after committed handoff; ambiguous pre-handoff recovery remains
covered by separate journal/producer tests.

### Manager-accepted, pre-receipt producer crash (2026-10-16)

The opt-in `ACP_LIVE_CRASH_AFTER_MANAGER_ACCEPTANCE=1` mode passed 1/1 on the
same disposable Debian 12 ARM64 / Linux 6.1 / systemd 252.39 guest, with cgroup
v2 and pinned rootless runc 1.5.2. The producer calls the real `systemd-run`
with the launcher's `Type=exec` behavior; once the command returns
successfully, a test hook reports manager acceptance and terminates that
producer with `os._exit(74)` before receipt propagation. The test waits for the
durable launch identity, then retries from a fresh producer. The retry is
rejected with `SandboxLaunchDriverServiceError` before any `systemd-run` call;
the second-submission count remains zero, and the durable start ID, digest,
unit invocation ID, driver PID, process identity, and cgroup path are unchanged.
The same exact test module was also rerun in natural-completion and
fresh-process cancellation modes (1/1 each). Its host and guest SHA-256 was
`9c9cfe950f937e5317c1461022dbc561804852f5bc09c20eb3d88f25c4f0ad1c`.

This proves the specific manager-accepted/pre-receipt interruption point. It
does not prove all possible interruptions during handoff, a restart of the
pytest harness or `GitSupervisor`, a systemd user-manager restart/logout/reboot,
result import, provider access, or `run_worker()` enablement. Postflight found
only the same two pre-existing failed launch-driver units, no running runc
processes, and no matching live fixture directories; those pre-existing units
were left untouched. Code-bearing commit
`e5f664f538996738cd310c482c778d08f9ee0440` passed
[exact-head hosted CI run 38888249380](https://github.com/Rayha33/agent-control-plane/actions/runs/38888249380):
all four Ubuntu/macOS × Python 3.11/3.12 jobs passed.

### Live monitor-accepted, pre-receipt launch-driver crash (2026-10-16)

The opt-in `ACP_LIVE_CRASH_AFTER_MONITOR_ACCEPTANCE=1` mode passed 1/1 on the
disposable Debian 12 ARM64 / Linux 6.1 / systemd 252.39 guest, with cgroup v2,
Python 3.11.2, pytest 9.1.1, and pinned rootless runc 1.5.2. The test wraps the
real launch-driver entry point only to inject `os._exit(74)` immediately after
the production monitor starter returns its real manager-accepted receipt and
before the launch-driver can durably commit `launched`. The marker records the
driver PID/start identity plus its unit/invocation/cgroup/slice; the monitor
receipt's PID/start identity, unit/invocation/cgroup, and execution tuple; the
attempt-slice unit/cgroup; the runc-client PID/start identity; and the worker
scope unit/invocation/cgroup. It does not claim that every component has every
kind of identity field.

A separate fresh `GitSupervisor` process then ran the production exact-start
reconciliation path. It stopped/reconciled only the bound driver, monitor,
scope, and attempt slice; verified their exact processes and cgroups quiescent;
and preserved the execution as `ambiguous`. Cleanup verification remained
absent, the durable start/submission identities were unchanged, resource and
runtime-allocation fences remained held, result-candidate capture was rejected,
and a fresh retry failed before any second `systemd-run` submission. On this
systemd version the closed gate's EOF could reap the blocked runc client and
make the scope inactive before reconciliation; the test checks exact identity
when it is still active and requires absence afterward.

The exact host/guest test-module SHA-256 was
`17a1a927d4058419fbe896cfba654dbdd6b35914db8aff8fe58bf42ea4aac6cf`.
Postflight found no matching fixture root, no running runc process, and no new
live ACP launch-driver units. The two pre-existing failed transient units were
left untouched. No model, provider credential, outbound network call, or paid
inference was used. This is live evidence for one handoff crash window and
fail-closed containment only: it does not prove successful runc wait/delete,
`cleanup_verified`, fence release, every crash window, restart of the pytest
harness or supervisor daemon, systemd user-manager restart/logout/reboot,
result import, provider access, or `run_worker()` enablement.

### Spawned journal crash during monitor handoff (2026-10-16; synthetic systemd)

`test_fresh_supervisor_contains_driver_crash_after_monitor_acceptance` now
crashes a spawned launch-driver with `os._exit(74)` after its fake monitor
starter signals manager acceptance and before `record_launch()` can commit the
durable `launched` receipt. A fresh `GitSupervisor` process runs the real
revocation and exact-unit reconciliation path against stubbed systemd
observations. In the quiescent case it stops only the exact launch-driver,
recovery-monitor, and attempt-slice units; the row remains `ambiguous`, the
one-shot launch submission and start identity remain unchanged, cleanup
verification is absent, and the resource lease remains fenced. In the
uncertain-driver case, a still-active post-stop observation raises and retains
the same fences without proceeding to stop the monitor or slice. A retry is
rejected before monitor start.

The exact test-module SHA-256 is
`63829a2d83d66d08363061653722f32ba57771c33107a71cffedc97291f2203f`.
This is real process loss, SQLite state, and process-shared locking, but the
manager acceptance and unit states are test doubles: it does not validate live
systemd start/stop behavior, a supervisor-daemon or user-manager restart,
result import, provider access, or `run_worker()` enablement.

All three live modes used no model, provider credential, network egress, or paid call.
Postflight found no running ACP test units, pinned-runc process, or
`acp-live-launch-driver-*` fixture root. Two pre-existing failed transient
launch-driver units had `MainPID=0` and empty cgroups; they were not changed or
removed. On a failure path, the harness joins every spawned controller child
before teardown; if a child remains alive after 30 seconds, it fails without
stopping units or deleting the fixture, leaving the fixture and units in place
for manual recovery on the disposable guest.

The table below records hashes for the earlier post-handoff natural/cancel
runs. The manager-acceptance crash increment above separately records the
exact current test-module hash. This proves the tested post-handoff
producer-process loss, manager-accepted/pre-receipt crash, cancellation
request, separate pinned-runc
action receipt, exact process/unit/cgroup/state/path absence checks, and
fresh-process reaper-driven `cleanup_verified` plus runtime/fence release on
this guest. It still does not prove full supervisor-daemon restart recovery,
manager restart/logout/reboot recovery, every crash-during-handoff window,
result import, provider access, or `run_worker()` enablement. Exact-head hosted
CI run 38884017803 passed all four Ubuntu/macOS × Python 3.11/3.12 jobs for
code-bearing commit `2383221c1a84cf52c08f42043465baea2ed4d487`. The later
manager-acceptance increment at `e5f664f538996738cd310c482c778d08f9ee0440`
also passed all four jobs in exact-head CI run 38888249380. The older
direct-monitor lifecycle fixture is explicitly skipped because it predates
exact launch-driver redemption; it must be rebuilt around the production start
API before it can be re-enabled.

The exact source and integration-test files below were SHA-256 matched between
this worktree and the disposable guest before the passing run:

| File | SHA-256 |
| --- | --- |
| `git_supervisor.py` | `138cbe89018d748728c9c97d95b91f129c1548260cb4211b442d64f510729f7d` |
| `oci_worker.py` | `2451885b35f3e3646537df2972504206dd5db7cc0c9834cd7af2117dc0f7a2ec` |
| `reaper.py` | `09aacc9c0d6c4e0e04e63e92ef03793a77fbfd9560bfafd9b82163e79df7b0c9` |
| `sandbox_attestation.py` | `205485f0dee05b9250658139f07364214cbdc9f5fcf22ccebd135b8d0c013b67` |
| `sandbox_execution_journal.py` | `4b40be3eb4e6502b9be807f99e500d2d9c6692318eeabab4e67d65d44d2914eb` |
| `sandbox_cleanup_verifier.py` | `c9feadb387dc6e325716975a933c14ea37ccfb1fdeeb422473a7cd232abe3553` |
| `sandbox_launch_driver_service.py` | `f7deb8d2fe6f36b4e9281a61e72e7e33cc400212627186d2a7d6c96273815b67` |
| `sandbox_monitor_service.py` | `c27fe68d764bfde7067195d64bee1a9056c5b73356849161b60ece9c76a4197a` |
| `store.py` | `c712b56ee1155db9b89c9321bc6bf90d7f581ab5a8ead41cb9e125c4744b977a` |
| `test_sandbox_worker_lifecycle_integration.py` | `b3764e287f2a00dfceead1ffdfed6ef6538e2e5ac9e1ff77c65c8c245e1a3df5` |

The live run closed a systemd-252-specific startup defect: `systemd-run
--no-block` returned before `LoadCredential=` consumed its `/proc/<pid>/fd/`
source, so the producer closed the descriptor before the service could read
it. A disposable synthetic-credential probe reproduced the failed unit; the
same probe with synchronous `Type=exec` reached `ExecStart` successfully. The
producer now keeps the descriptor open through that exec boundary. This fixes
credential delivery but does not expand the lifecycle proof above.

The local cleanup regression uses a real held child and injected kill/first-wait
failures; it verifies EOF exits 126 and an unverified scope binding preserves
the attempt slice. This is test-harness cleanup evidence only, not production
driver cleanup evidence.

## Required implementation and proof

The production launch-driver now starts before the runc submission and owns the
process-local handle/attestation/running/wait path plus exact pinned-runc delete
action. The authenticated fresh-process cancellation path is implemented and
passed the live disposable-systemd test above as supervisor → monitor → exact
worker scope. Exact launch-driver adoption/reconciliation, monitor retirement,
and the supervisor-owned post-stop verifier are implemented in source. The
verifier serializes against the execution owner, requires the durable delete
action and kernel-wait receipts, then checks exact process/unit/invocation/cgroup,
container, and path identities before writing `cleanup_verified`. Natural and
cancelled runs both passed the live verifier on the disposable Debian guest.
The 2026-10-16 producer-loss/no-replay increment passed exact-head hosted CI on
code-bearing commit `2383221c1a84cf52c08f42043465baea2ed4d487`; this does not
replace the separate live lifecycle evidence. If any evidence is incomplete or
the driver dies before action/wait receipts are durable, keep the execution
fenced.
The existing `run_worker()` refusal must remain unchanged.

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
