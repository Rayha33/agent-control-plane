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
observations and is not live manager evidence. Distinct opt-in live
systemd-252 modes now exercise both a crash before monitor activation and a
crash after monitor acceptance but before the receipt commits, against real
manager and runc processes. They prove fail-closed containment, not successful
cleanup or restart recovery.
The code-bearing commit `2383221c1a84cf52c08f42043465baea2ed4d487` passed
[exact-head hosted CI run 38884017803](https://github.com/Rayha33/agent-control-plane/actions/runs/38884017803)
with all four Ubuntu/macOS × Python 3.11/3.12 jobs green. An explicitly opted-in
no-provider `run_worker()` bridge now composes the registered launch service,
independent cleanup verification, and host-validated result import. It does not
enable provider authentication or egress, and the default OCI worker path
continues to fail closed.
`cleanup_verified` certifies resource cleanup, not worker success; every result
consumer continues to require runc exit code 0. Configured OCI
`run_worker()` without `--sandbox-experimental-opt-in` still fails closed with
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

### Live driver crash before recovery-monitor activation (2026-10-16)

The opt-in `ACP_LIVE_CRASH_BEFORE_MONITOR_START=1` mode passed 1/1 on the
disposable Debian 12 ARM64 / Linux 6.1 / systemd 252.39 guest, with cgroup v2,
Python 3.11.2, pytest 9.1.1, and pinned rootless runc 1.5.2. After the real
launch-driver starts the pinned runc client and creates its exact gated worker
scope, a test hook exits the driver immediately before calling the production
recovery-monitor starter.
The marker proves the exact driver, attempt slice, runc-client, and scope
identities at that point; the monitor unit remains `not-found` before recovery.

A fresh `GitSupervisor` runs the production exact-start reconciliation and
proves that it accepts the absent monitor as quiescent, then retires only the
bound driver, scope, and attempt slice. The test asserts the monitor unit stays
`not-found` and inactive after reconciliation as well. The execution remains
`ambiguous`, cleanup verification is absent, result capture is blocked, fences
remain held, and a fresh retry is rejected before a second `systemd-run`
submission. As in the post-monitor crash case, the closed gate may reap the
runc client and make the scope inactive before reconciliation; the test
verifies exact scope identity while active and requires no cgroup/process
afterward. This does not prove cleanup verification, fence release, monitor
recovery (no monitor was started), supervisor/user-manager restart, result
import, provider access, or `run_worker()` enablement. No model, provider
credential, outbound network call, or paid inference was used. This mode used
the exact host/guest test-module hash recorded in the following subsection.

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

Before adding timeout coverage, the exact host/guest test-module SHA-256 was
`07a3c8c4a08b0f46e05c1e13d532798d8ffa8a3a0719cac87f1e04d61e437533`. That
version was exercised in five opt-in live modes on the disposable guest:
natural completion, fresh-process cancellation, manager-accepted/pre-receipt
crash, monitor-accepted/pre-receipt crash, and pre-monitor-start crash. Each
mode passed 1/1. Postflight after the five-mode run found no matching fixture
root, active ACP launch-driver unit, running runc process, or D-state process;
the two pre-existing failed transient units were left untouched. No model,
provider credential, outbound network call, or paid inference was used. The
crash mode in this subsection proves one handoff crash window and fail-closed
containment only; it does not prove successful runc wait/delete,
`cleanup_verified`, fence release, every crash window, restart of the pytest
harness or supervisor daemon, systemd user-manager restart/logout/reboot,
result import, provider access, or `run_worker()` enablement. The launch-driver
timeout mode is now live-tested; its exact run and scope are recorded below.

### Live launch-driver timeout and cleanup (2026-10-16; pass)

The opt-in `ACP_LIVE_TIMEOUT_AFTER_START=1` mode passed 1/1 on the disposable
Debian 12 ARM64 / Linux 6.1 / systemd 252.39 guest with cgroup v2, Python
3.11.2, pytest 9.1.1, and rootless runc 1.5.2 (SHA-256
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`). The
live run used `src/agent_control_plane/supervisor/sandbox_launch_driver_service.py`
SHA-256 `7f4de61acb83653269683a1ae14593e849f65d78e11a36411560244f0113a243` and
`tests/test_sandbox_worker_lifecycle_integration.py` SHA-256
`a4e81f27e692bf238c11af8dcacb476718066d66a7da2c19982aaaf45c29125f`; the
host and guest copies matched. The one-second timeout persisted the exact
`execution_timeout` stop intent, cancelled through the launch handle's cached
authenticated monitor client, reaped runc, and reached `cleanup_verified`
after independent process/unit/cgroup absence checks and resource/runtime
fence release. The timed-out result remained ineligible for import.

Postflight found no live fixture root, active ACP unit, runc/driver/pytest
process, or D-state process. The same two pre-existing failed transient units
(`acp-launch-driver-32fa5c47-cd84-4bfd-a7c8-5fca996e76bb.service` and
`acp-launch-driver-691a278d-fcb8-4127-9729-6be157313772.service`) remained
untouched. This proves the opt-in timeout cleanup path on this guest, not
provider access, result import, successful worker output, broad crash recovery,
or `run_worker()` enablement.

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

## 2026-10-16 exact-head launch-driver lifecycle refresh

The code-bearing head `29758f8f1455167877397334279a2df8e58d282f` passed
GitHub Actions run [38923445474](https://github.com/Rayha33/agent-control-plane/actions/runs/38923445474):
all four Ubuntu/macOS × Python 3.11/3.12 jobs completed successfully, including
tests, Ruff lint/format checks, and package build. This run used the workflow's
then-current `ubuntu-latest` image. It predates this documentation-only
increment.

On the disposable Debian 12 ARM64 guest (Linux 6.1, systemd 252.39, cgroup v2,
active private user manager), the production launch-driver test passed
individually in each mode below. The test and service source were SHA-256
matched between host and guest (`a4e81f27e692bf238c11af8dcacb476718066d66a7da2c19982aaaf45c29125f`
and `976355e6575b590a72c2fc7bdf0db3e82170252a5fd323fd38f76ff2453785ce`,
respectively); pinned runc was v1.5.2 with release digest
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`.

| Live mode | Result | Evidence boundary |
| --- | --- | --- |
| Normal completion | 1 passed | Bounded BusyBox payload through production launch-driver; normal completion and cleanup path. |
| `ACP_LIVE_TIMEOUT_AFTER_START=1` | 1 passed | Timeout path persisted stop intent before monitor cancellation and completed exact cleanup verification. |
| `ACP_LIVE_CANCEL_AFTER_START=1` | 1 passed | Fresh-supervisor authenticated cancellation used the exact service; no host-PID fallback. |
| `ACP_LIVE_CRASH_AFTER_MANAGER_ACCEPTANCE=1` | 1 passed | Fail-closed containment and no replay after the injected manager-acceptance crash window. |
| `ACP_LIVE_CRASH_AFTER_MONITOR_ACCEPTANCE=1` | 1 passed | Fail-closed containment and no replay after the injected monitor-acceptance crash window. |
| `ACP_LIVE_CRASH_BEFORE_MONITOR_START=1` | 1 passed | Fail-closed containment; monitor remained unstarted and the launch was not replayed. |

These were six separate opt-in invocations, not one aggregated run. They used
no model, provider credentials, network egress, or paid calls. An initial
attempt to stage runc under world-writable `/tmp` was correctly rejected by
the production executable-trust check before any unit or container launch;
the identical verified binary was then staged under root-owned
`/var/lib/acp-runc-29758f8` and accepted. No trust rule was relaxed. Postflight
found no test fixture roots, driver/runc processes, or new units. Two
pre-existing failed units remained `MainPID=0` and unchanged; they were not
removed or restarted. Manual postflight removed the temporary checkout and
pinned binary; binary removal is an operator observation, not an assertion in
the test's fixture finalizer.

Independent source-level adversarial QC is GO for the
`launch_driver_failure` stop-intent fix, but NO-GO for closing broader #3142 or
#2370. In particular, the exception-path regression stubs the monitor cancel
IPC; live timeout and fresh-supervisor cancellation exercise production IPC
separately, but the exact post-launch-exception branch has not been injected
through real monitor IPC. This guest run also does not prove daemon/user-manager
restart, logout, reboot, arbitrary crash timing, or result import. Workspace
isolation, production provider authentication/egress, and validated result
transfer remain open acceptance gates. The default `run_worker()` path must
remain fail-closed; this evidence does not enable the later experimental
opt-in or weaken the macOS execution path.

Parent task #2370 remains open until workspace isolation, provider
authentication/egress, validated result transfer, and all independent safety
gates pass. At the time of this ADR evidence, OCI was not enabled in
`run_worker()`; the later explicit no-provider experiment is recorded below.
This ADR does not weaken the macOS execution path.

## Supervisor composition boundary (updated 2026-10-21; task #3268/#2370)

The launch-driver/journal lifecycle has an explicit no-model composition
entrypoint, but it is not the registered worker's default API.
`WorkersMixin.run_worker()` first validates a non-empty command and computes its
digest. With OCI configured and no opt-in it still returns
`sandbox_executor_unavailable`, before heartbeat, reservation, or host
`Popen`; without OCI configuration, it uses its separate direct-host process
path subject to the existing reservation preflight and Linux containment
guard. The CLI can forward `--sandbox-experimental-opt-in` plus explicit
resource limits; that opt-in is currently limited to this no-provider
experiment and is not a production-provider enablement claim.

`start_registered_no_model_sandbox_worker()` requires
`experimental_opt_in=True`, reserves the claimed attempt, copies and
re-verifies the pinned rootfs, mints the baseline and disjoint workspace
without `.git`, binds them in the journal, and calls
`start_sandbox_launch_driver()`. It makes no model/provider calls; callers
supply a local fake-worker command. The direct helper returns its execution
and launch receipt for explicit composition. The opted-in `run_worker()` path
waits for the exact execution identity, requires independent cleanup
verification and exit code zero, then calls the existing host-validated
workspace importer and returns its `pending_qc` result.

The durable ownership boundaries that a caller must compose are:

- The supervisor owns the registered attempt tuple and must create the
  host-minted baseline and disjoint mutable workspace before launch. The
  sandbox test confirms `.git` is absent from the copied worker tree, but that
  alone does not prove the complete host-path isolation gate.
- The launch-driver service owns the process-local runc handle, gate,
  attestation, wait/reap, and unverified cleanup report; the out-of-slice
  monitor owns authenticated stop/status IPC. The supervisor-owned verifier
  alone records `cleanup_verified`; the reaper consumes that proof to release
  runtime and leases/fences. These owners cannot be collapsed into the
  direct-worker PID fields or host-PID cleanup.
- Result import is always a separate supervisor action after verified cleanup.
  It rejects an attempt that aliases a direct worker PID, captures a
  write-once candidate, and produces a `pending_qc` submission. The direct
  helper leaves this call to its caller; the explicit `run_worker()` opt-in
  performs it only after exact cleanup verification and exit code zero. The
  launch-driver itself never imports results.

The opt-in function renews the attempt lease during preparation and keeps
renewing until the launch driver has itself renewed the lease and durably
published `running`; the driver renews it while it owns the wait/reap path. If
the attempt lease has already expired, the driver first quarantines the exact
execution under its release lock, with the accepted phase set rechecked by the
journal transaction, then asks only its identity-bound authenticated monitor to
cancel the exact scope. If that cancellation is followed by the sealed runc
kernel-wait receipt, the lease-loss path may advance only that exact quarantined
execution to `exited`, perform the pinned-runc delete, and submit its cleanup
action receipt. The independent verifier still owns `cleanup_verified`; the
reaper releases fences only after that proof. If cancellation, wait, deletion,
or verification evidence is unavailable, the execution remains fenced. A
preparation failure after durable reservation intentionally retains the
attempt and resource fences for reaper quarantine; partial private trees are
not automatically cleaned. There is no host fallback or unverified rollback.
The launch-driver retains process-local wait/reap ownership; the supervisor
verifier and reaper retain cleanup authority; the caller retains the explicit
QC import handoff.
This narrow composition does not enable provider workers, prove provider
egress, or eliminate the parent #2370 acceptance gates. The default
`run_worker()` path remains fail-closed; the separate experimental opt-in
requires explicit resource limits, waits for the exact execution identity,
requires the independent `cleanup_verified` transition, and only then invokes
the existing host-validated workspace importer. It rejects `--result-manifest`
because sandbox imports use the validated private-workspace diff instead.

### Registered-worker host-path probe

`ACP_LIVE_ISOLATION_PROBES=1` extends the same no-model registered-worker run on
a disposable Linux VM. It requires
`ACP_LIVE_ISOLATION_DISPOSABLE_HOST` to equal the VM's exact current hostname,
an active rootless systemd/runc setup, and passwordless `sudo`. The fixture
creates unique synthetic sentinels in host `/etc`, `/usr/local/share`, the host
home, `~/.config`, `~/.ssh`, host `/tmp`, the test harness checkout, the
registered task's base checkout, a real sibling Git worktree in the same
`.acp/worktrees` attempts root as the claimed attempt, and an unrelated project.
The `/etc` and `/usr/local/share` sentinels are created
and removed by exact inode and content through `sudo`. When both worker units
are quiescent and every fixture still has its recorded identity, the finalizer
removes fixtures even if an assertion failed; if quiescence or exact cleanup
cannot be proved, it preserves the test tree and fails. Sentinel candidate
paths are registered before creation; the helper removes a partially written
sentinel on ordinary post-create exceptions using the open inode identity. If
the helper exits or times out before returning an identity and leaves an
artifact, the finalizer preserves and reports that path (and does not remove a
containing sibling worktree). Token-specific `/tmp`
and `/home/agent` scratch probes are removed only when they are regular files
owned by the test user with the exact expected content and unchanged inode;
unexpected artifacts are preserved and reported. The worker must not read
those sentinels or create adjacent write probes. The payload creates an
absolute symlink inside its workspace to the host config sentinel, attempts to
read through it, and removes it; it also tries a `..`-based canonical-path
traversal. The live payload checks
the test controller PID is absent from its private procfs, host Unix socket
paths are not visible, `/tmp` and `/home/agent` are tmpfs, the rootfs is
read-only, `/usr` is absent, `/workspace` is writable, and a direct IPv4 TCP
socket is denied by the worker's seccomp policy. Run it with:

```sh
ACP_RUN_SANDBOX_WORKER_LIFECYCLE=1 \
ACP_OCI_TEST_RUNC=/usr/local/bin/runc-1.5.2 \
ACP_OCI_TEST_RUNC_VERSION=1.5.2 \
ACP_LIVE_ISOLATION_PROBES=1 \
ACP_LIVE_IMPORT_RESULT_AFTER_CLEANUP=1 \
ACP_LIVE_ISOLATION_DISPOSABLE_HOST="$(hostname)" \
uv run --extra dev pytest -q tests/test_sandbox_worker_lifecycle_integration.py
```

To run these same host-path probes through the public `run_worker()` path,
also set both `ACP_LIVE_IMPORT_RESULT_AFTER_CLEANUP=1` and
`ACP_LIVE_SUPERVISED_RUN_WORKER=1`. This mode requires natural completion and
imports the validated diff only after independent cleanup verification:

```sh
ACP_RUN_SANDBOX_WORKER_LIFECYCLE=1 \
ACP_OCI_TEST_RUNC=/usr/local/bin/runc-1.5.2 \
ACP_OCI_TEST_RUNC_VERSION=1.5.2 \
ACP_LIVE_ISOLATION_PROBES=1 \
ACP_LIVE_IMPORT_RESULT_AFTER_CLEANUP=1 \
ACP_LIVE_SUPERVISED_RUN_WORKER=1 \
ACP_LIVE_ISOLATION_DISPOSABLE_HOST="$(hostname)" \
uv run --extra dev pytest -q tests/test_sandbox_worker_lifecycle_integration.py::test_live_production_launch_driver_runs_exact_pinned_runc_request
```

To exercise the full explicit supervisor `run_worker()` lifecycle bridge on a
disposable host, use the coding-task import fixture. Add
`ACP_LIVE_ISOLATION_PROBES=1` and
`ACP_LIVE_ISOLATION_DISPOSABLE_HOST="$(hostname)"` to combine it with the
host-path sentinels above:

```sh
ACP_RUN_SANDBOX_WORKER_LIFECYCLE=1 \
ACP_OCI_TEST_RUNC=/usr/local/bin/runc-1.5.2 \
ACP_OCI_TEST_RUNC_VERSION=1.5.2 \
ACP_LIVE_IMPORT_RESULT_AFTER_CLEANUP=1 \
ACP_LIVE_SUPERVISED_RUN_WORKER=1 \
uv run --extra dev pytest -q \
  tests/test_sandbox_worker_lifecycle_integration.py::test_live_production_launch_driver_runs_exact_pinned_runc_request
```

This mode is intended to prove the no-provider end-to-end path only: launch,
completion, independent cleanup verification, and exact validated import to
`pending_qc`. Do not interpret it as provider authentication/egress proof or
as permission to enable the experimental flag on a shared production host.

The import assertion requires the complete imported commit path set to equal
the two expected worker outputs; the probe script is already in the task base
commit. The hostname variable is an operator self-attestation, not automatic
VM detection.

This is targeted evidence for this pinned BusyBox rootfs, Linux kernel, and
runc 1.5.2 configuration—not proof against every same-UID host actor, every
kernel/runtime, provider authentication, or approved provider egress. Only the
explicit no-provider test mode enables the experimental `run_worker()` bridge;
the default path remains fail-closed and parent task #2370 remains open.

### Provider-proxy primitive live probe

The separate live test
`live_rootless_runc_mounts_attempt_proxy_socket_directory_read_only` exercises
the attempt-bound provider-proxy socket under rootless runc. It requires the
same pinned runc, BusyBox, and compiler as the proxy test setup:

```sh
ACP_RUN_OCI_INTEGRATION=1 \
ACP_OCI_TEST_RUNC=/usr/local/bin/runc-1.5.2 \
ACP_OCI_TEST_RUNC_VERSION=1.5.2 \
ACP_OCI_TEST_BUSYBOX=/usr/bin/busybox \
ACP_OCI_TEST_CC=/usr/bin/cc \
PYTHONPATH=src \
uv run --extra dev pytest -q tests/test_oci_worker_runtime.py \
  -k live_rootless_runc_mounts_attempt_proxy_socket_directory_read_only
```

On 2026-10-16 this passed on a disposable Debian 12 ARM64 VM running kernel
`6.12.95+deb12-cloud-arm64`, systemd 252.39, runc 1.5.2 (SHA-256
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`), and
BusyBox 1.35.0. Debian's [Bookworm Backports cloud kernel package](https://packages.debian.org/bookworm-backports/kernel/linux-image-cloud-arm64)
provided the newer kernel. The same probe first failed closed on kernel
`6.1.0-53-cloud-arm64` because the kernel returned `Protocol not available`
for `SO_PEERPIDFD`; the security check was not weakened or given a fallback.

This proxy test uses a test-only attestation receipt and redirects resolver and
dial operations to local TCP fixtures. It verifies the kernel/runtime proxy
primitive and attempt binding; it does **not** prove real provider
authentication, provider credentials, or controlled external provider egress.
The registered worker host-path probe separately passed on the same upgraded
VM, including cleanup and exact two-path result import (`launch-driver-marker`
and `launch-driver-started`). These are narrow, reproducible environment
results, not a claim that all parent #2370 acceptance gates are closed.

### Deterministic coding edit/test/import replay (2026-10-21; no model)

The updated `test_live_production_launch_driver_runs_exact_pinned_runc_request`
passed on a fresh, plain Lima 2.2.1 Debian 12 ARM64 guest with no host mounts:
Linux `6.1.0-53-cloud-arm64`, systemd `252.39`, cgroup v2, Python `3.11.2`,
rootless runc `1.5.2` (SHA-256
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`), and
BusyBox `1.35.0`. The exact source tree was staged over SSH under guest `/tmp`;
the live test module SHA-256 was
`f85cb6a0eaad368196742214832cfdf90233ff779bec99ee4a2c558ee08cc305`, matching
the host copy. The run used the test-only diff atop commit
`c652f66cff083295e151c10321334405e29a00b7` and the lockfile dependency set via
uv `0.12.21` with `--frozen` (no lockfile was edited).

The run enabled both `ACP_LIVE_ISOLATION_PROBES=1` and
`ACP_LIVE_IMPORT_RESULT_AFTER_CLEANUP=1` and passed **1/1**. The deterministic
no-model task wrote a shell source file into the private writable workspace,
executed it with the pinned BusyBox closure, and checked its output. After
production cleanup verification, result import reached `pending_qc`; the
imported path set was exactly `launch-driver-marker`,
`launch-driver-started`, `sandbox-coding-task.sh`, and
`sandbox-coding-task.test`. Raw Git blob bytes matched both the expected source
and test output and the corresponding private workspace files. The same run
exercised the documented host-path, symlink/canonical-path, process, socket,
direct-network, read-only-rootfs, and writable-workspace probes. Postflight
found no ACP test units/processes or `acp-live-*` fixture directories.

This is still a deterministic no-model fixture, not a provider/model coding
agent or the default `run_worker()` path. It does not prove provider
authentication/egress, or close the remaining #2370 recovery and integrated
worker acceptance gates; configured OCI `run_worker()` without
`--sandbox-experimental-opt-in` remains fail-closed.

### Explicit `run_worker()` bridge replay (2026-10-21; no model)

The same production launch-driver test passed **1/1** with
`ACP_LIVE_IMPORT_RESULT_AFTER_CLEANUP=1` and
`ACP_LIVE_SUPERVISED_RUN_WORKER=1`. This exercises the public supervisor path:
the opt-in `run_worker()` reserves and launches the exact attempt, waits for
the execution identity, requires independently verified cleanup and exit code
zero, then imports the validated workspace diff to `pending_qc`. The fixture
asserted its expected four imported paths. The default OCI path remains
fail-closed; this proves neither provider authentication/egress nor the
production provider-enabled worker.

The isolated test source was staged under guest `/tmp` without host mounts.
Host and guest SHA-256 matched for `workers.py`
(`c9cabd34d052578252aa55ae096e65d9c079223ead7d8a701aa72dfe1e74dd1f`),
`sandbox_launch_driver_service.py`
(`3f9a3b9fe515074b5542518b44a4473f994c956c695d2d5fec047ff0ebb049ff`),
`cli.py` (`70abb22d81933f27938f2eb4a62f14c8d01b2c6f90df1c5be671fbace411b2a1`),
and the test module
(`cdbaf024abd1bab8a5b7a04984b8481bdf670e627c6d41c90cf6ea89deafcf58`). The
guest was Debian 12 ARM64, Linux `6.1.0-53-cloud-arm64`, systemd `252.39`,
Python `3.11.2`, uv `0.12.21`, cgroup v2, and rootless runc `1.5.2` with SHA-256
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`. No
provider credentials or egress were configured. Postflight found no ACP test
units or `acp-live-launch-driver-*` fixture roots.

### Supervisor `run_worker()` plus host-path isolation replay (2026-10-21; no model)

The combined command above passed **1/1** on the same disposable Debian 12
ARM64 guest, Linux `6.1.0-53-cloud-arm64`, systemd `252.39`, Python `3.11.2`,
uv `0.12.21`, and pinned rootless runc `1.5.2` (SHA-256
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`). The exact
test-module SHA-256 on host and guest was
`997a11d3ae4b7084e4636eaf284d03497b726e6833d29c6b131e2032ca526b60`; the live
worker/helper/CLI source hashes matched those recorded in the preceding
replay.

This combined run exercised the public experimental `run_worker()` API with
no provider or model. It checked unique sentinels in host `/etc`,
`/usr/local/share`, home/config, a synthetic credential, host `/tmp`, the
harness checkout, task-base checkout, sibling worktree, and unrelated project.
It also checked workspace symlink and canonical-path escapes, private procfs,
host Unix sockets, tmpfs `/tmp` and `/home/agent`, read-only rootfs, writable
workspace, and denied direct IPv4 networking. The deterministic coding task
completed; after exact cleanup verification, import reached `pending_qc` with
only the four expected fixture output paths. Postflight found no active ACP
test services, runc/launch-driver processes, fixture roots, scratch files, or
sentinels.

This closes the earlier test-coverage gap between a separate lower-level
isolation probe and the explicit `run_worker()` lifecycle replay for this
pinned fixture. It does not establish provider authentication or restricted
provider egress, reboot/daemon-restart recovery, safety against every same-UID
host actor, or support across other kernels/rootfs/runtime versions. The
default OCI `run_worker()` path remains fail-closed and parent task #2370
remains open.

### Launch-driver handoff crash recovery (2026-10-21; no model)

The production launch-driver integration test was run separately with each of
`ACP_LIVE_CRASH_AFTER_MANAGER_ACCEPTANCE=1`,
`ACP_LIVE_CRASH_BEFORE_MONITOR_START=1`, and
`ACP_LIVE_CRASH_AFTER_MONITOR_ACCEPTANCE=1`. All three runs passed (**1/1**;
2.47s, 1.22s, and 1.59s respectively) on a disposable Debian 12 ARM64 guest:
Linux `6.12.95+deb12-cloud-arm64`, systemd `252.39`, Python `3.11.2`, cgroup
v2, and rootless runc `1.5.2` (SHA-256
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`). The
tests used uv `0.5.9` with `--frozen`; the test module and launch-driver source
matched the staged commit `1beda4356df307c2c32a640e795b7ed4683b3254` at
SHA-256 `997a11d3ae4b7084e4636eaf284d03497b726e6833d29c6b131e2032ca526b60`
and `3f9a3b9fe515074b5542518b44a4473f994c956c695d2d5fec047ff0ebb049ff`.

The manager-acceptance mode exits the producer after `systemd-run` accepts the
launch but before receipt propagation. A fresh retry controller then rejects
the duplicate one-shot start before invoking `systemd-run` (the recorded call
count is zero); this mode does not exercise the monitor-crash reconciliation
path.

The two monitor modes (`BEFORE_MONITOR_START` and `AFTER_MONITOR_ACCEPTANCE`)
exercise reconciliation from a fresh supervisor process. They assert the
selected crash phase and exact attempt/runtime identities, keep the untrusted
payload behind the unreleased launch gate, quarantine ambiguous execution,
retain cleanup fences, and reject result capture/replay. The fixture uses a
local ACP runner credential for enrollment, claim, and launch; it uses no
provider credentials, provider endpoint, model, or model API call. Postflight
across all three runs found no active test launch-driver or monitor unit,
worker scope, runc process, or `acp-live-launch-driver-*` fixture root.

This does not simulate a crash/restart of the supervisor daemon or systemd user
manager, logout/linger, or reboot; it therefore does not close #2370's broader
recovery gate. Provider authentication and destination-restricted external
egress also remain unproven, and the default OCI `run_worker()` path remains
fail-closed.

### User-manager daemon-reexec after launch-driver crash (2026-10-21; no model)

The two monitor crash modes above were repeated with
`ACP_LIVE_USER_MANAGER_REEXEC_AFTER_DRIVER_CRASH=1` on the same disposable
Debian 12 ARM64 environment (Linux `6.12.95+deb12-cloud-arm64`, systemd
`252.39`, Python `3.11.2`, cgroup v2, rootless runc `1.5.2`, SHA-256
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`). The
frozen test source staged from `2f8cf15dc7dffcd332fed333a9b35dcfaa23ea94`
had SHA-256 `a99ce18638695d33f8ab92bc91507d65ab08e39f713d4d9031f0ec2a89d8f8e4`;
the launch-driver source remained SHA-256
`3f9a3b9fe515074b5542518b44a4473f994c956c695d2d5fec047ff0ebb049ff`.

| Injected launch-driver crash phase | Result | Assertions |
| --- | --- | --- |
| `ACP_LIVE_CRASH_AFTER_MONITOR_ACCEPTANCE=1` | 1 passed (1.69s) | Trusted `systemctl --user daemon-reexec` returned 0; exact launch-driver unit properties were unchanged; active monitor/scope identity checks, slice unit/cgroup checks, and fresh-supervisor reconciliation passed. |
| `ACP_LIVE_CRASH_BEFORE_MONITOR_START=1` | 1 passed (1.22s) | Same re-exec and state/reconciliation checks passed; the monitor remained unstarted at the injected crash point. |

The test first confirms the exact launch-driver unit is inactive, performs one
user-manager `daemon-reexec`, then compares the launch-driver unit properties
before and after re-exec. Post-re-exec checks verify monitor identity when the
monitor is active, compare the slice unit ID and cgroup, and assert that the
monitor is absent in the pre-monitor case; they run before fresh-supervisor
reconciliation. Postflight found the user manager reachable and no active
`acp-*` units, launch-driver/monitor/runc processes, or
`acp-live-launch-driver-*` / `acp-live-sandbox-lifecycle-*` fixture roots. The
run used no model, provider credential, provider endpoint, or provider API
call; it made no changes to the NAS.

This proves state retention across `systemctl --user daemon-reexec` only. It
does not simulate supervisor-daemon failure, systemd user-manager shutdown or
restart, logout/linger, reboot, provider authentication, or destination-
restricted provider egress. It does not close #2370's broader recovery or
integrated-agent-isolation gates, and the default OCI `run_worker()` path
remains fail-closed.

### Guarded user-manager service restart after launch-driver crash (live proof; 2026-10-21)

The production lifecycle test also has an explicit disposable-VM-only mode,
`ACP_LIVE_USER_MANAGER_RESTART_AFTER_DRIVER_CRASH=1`, paired with exactly one
monitor-acceptance or before-monitor-start crash point, the exact guest
hostname, and the literal
`ACP_LIVE_USER_MANAGER_RESTART_ACK=RESTART_ONLY_THIS_DISPOSABLE_GUEST`. It is
restricted to a VM with passwordless `sudo -n` and an exact Debian 12 Lima
baseline inventory. Before launching the fixture it compares structured JSON
rows from `systemctl --user list-units --all`—including device units and any
otherwise unrecognized unit type and state—to the exact Debian 12 Lima
allowlist. The CIDATA UUID device unit is derived only after verifying that its
sole `/dev/disk/by-uuid` alias resolves to the same `/dev/vdb` block device as
`/dev/disk/by-label/cidata`. A successful `busctl --user status` first exercises
the user's normal D-Bus socket activation. The optional `user.slice` and
`user-acp.slice` must be absent or exact implicit slices below the test
manager; loaded/inactive instances must have no cgroup or unit file. Active
instances must have their exact manager-relative cgroup path and no unit file;
`user-acp.slice` must be nested under `user.slice`. Both parent slices are
checked separately from the otherwise exact baseline.
Structured rows prevent multiline unit descriptions from being mistaken for
extra units. It captures the exact `init.scope` and `dbus.service` PID sets and
verifies the single direct `(sd-pam)` child of the manager. Immediately before
restart it rechecks the full unit inventory and requires those baseline PID
sets to be unchanged, then proves every process under the manager cgroup
belongs to those baseline units or the fixture's exact driver, monitor,
attempt-slice, and worker-scope cgroups. Parent-slice hierarchy and cgroup
identity are verified separately; parent slices are not process-allowlist
entries, so a direct process in either slice fails closed. Any other unit,
state, or process also fails closed.

The mode restarts only the current test user's `user@<uid>.service`. Before
fresh-supervisor reconciliation it requires a successful replacement-manager
PID query, a reachable manager control socket, and a successful `busctl
--user status` check (which exercises normal D-Bus socket activation). The
driver and monitor services and worker scope must be absent; there may be no
test process left in the manager cgroup. Systemd can retain the exact
attempt-specific slice as `loaded/inactive/dead` after restart, but only with an
empty control group; no other fixture unit may remain. Either parent slice may
be absent after restart or remain loaded/inactive with no cgroup or unit file.
All other baseline unit states remain exact. If the restart command times out,
returns nonzero, or its outcome cannot be verified, the test preserves the VM
and exact fixture, performs no retry or automatic unit cleanup, and requires
manual inspection before any recovery or rerun.

Two live attempts on 2026-10-21 reached the manager-restart postflight but did
not complete the end-to-end test. On Debian 12 ARM64 / kernel 6.12.95 / systemd
252.39 / runc 1.5.2, attempt one restarted the user-manager PID from 645 to
1699, then failed because the fresh manager lazily unloaded empty baseline
slices and D-Bus/session units. The fixture was preserved; read-only inspection
found no driver, monitor, runc process, or worker cgroup. After D-Bus socket
activation and restoration of the two empty user slices, the exact 84-unit
baseline and process inventory matched. Attempt two restarted the manager PID
from 1699 to 2067, but failed closed because its exact attempt-specific slice
remained `loaded/inactive/dead` with no control group; driver and monitor units
were absent and the manager-cgroup process audit passed. Both failed run roots
remain preserved, and neither reached supervisor recovery or automatic
cleanup. These observations are partial restart evidence, not a successful
recovery proof. The focused postflight now permits only this exact empty slice
state while keeping service, scope, process, and eventual cleanup checks strict.

Two additional guarded runs passed the complete opt-in test on the same Debian
12 ARM64 guest (kernel `6.12.95+deb12-cloud-arm64`, systemd
`252.39-1~deb12u2`, Python `3.11.2`, rootless runc `1.5.2`, runc SHA-256
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`). Both
used test-source SHA-256
`d48ade517f3275df27f2f2adf15d43c242039a317d2b304ec86b5512f0ac8930`.

| Successful attempt | Injected crash phase | User-manager PID | Additional assertion |
| --- | --- | --- | --- |
| Third run | `ACP_LIVE_CRASH_AFTER_MONITOR_ACCEPTANCE=1` | 2067 → 2397 | The accepted monitor was gone after manager restart. |
| Fourth run | `ACP_LIVE_CRASH_BEFORE_MONITOR_START=1` | 2397 → 2718 | The monitor had never started and remained absent. |

For both runs, the replacement manager and user D-Bus became reachable; the
driver, monitor, and scope were absent before recovery. A fresh supervisor
reconciled the interrupted handoff, recorded the durable `ambiguous` phase with
the attempt quarantined and task blocked, and rejected result capture and
launch replay. A fresh-process reaper then finalized the nonrecoverable attempt
as orphaned, released its runtime allocation, and reached `cleanup_verified`;
process, cgroup, runc-state, socket, and bundle checks were clear. Postflight
found only `init.scope` and D-Bus processes under the manager cgroup, no ACP
test units, and the two expected empty user slices unloaded. Both successful
fixture roots were removed after their exact cleanup checks; the two earlier
failed roots remain preserved. These no-model runs used no provider
credentials, endpoint, or API call.

An initial probe on this guest exposed a per-VM CIDATA UUID and lazily
activated empty parent slices, so the allowlist was narrowed around the stable
device-label identity and those exact implicit slices. A fifth guarded run
then passed the same monitor-accepted crash/restart path on this guest. It used
test-source SHA-256
`154348ab69d04ea11ae0652c1b8f13a39b377e6eb2c170b6a9b746a614324a68` and
restarted the user-manager PID from 546 to 1371. The replacement manager and
D-Bus were reachable; fresh-supervisor reconciliation and independent cleanup
verification completed. Postflight found no ACP units, runc containers, worker
processes, or this run's launch-driver fixture root under `/tmp`; the
user-manager cgroup contained only `systemd --user`, its one direct `(sd-pam)`
child, and the D-Bus daemon in their exact baseline cgroups. This no-model run
used no provider credentials, endpoint, or API call.

This closes the specifically tested user-manager service-restart recovery paths
for monitor-accepted and before-monitor-start launch-driver crashes on this
disposable Debian 12 guest. It does not prove supervisor-daemon failure,
logout/linger, reboot recovery, provider authentication, or destination-
restricted provider egress, and does not close #2370's broader isolation gate
or enable the default OCI `run_worker()` path.

### Explicit supervised `run_worker()` path with isolation and result import (live proof; 2026-10-21)

On exact code-bearing commit `6df4b16c2f6b75e29d7598e15d4bb1905cc2fa08`,
the opt-in `test_live_production_launch_driver_runs_exact_pinned_runc_request`
passed 1/1 on disposable VM
`lima-acp-2370-live-sandbox-kernel612-20261021` (Debian 12 ARM64, Linux
`6.12.95+deb12-cloud-arm64`, systemd `252.39-1~deb12u2`, Python 3.11.2).
It used root-owned runc 1.5.2 at `/usr/local/bin/runc`, SHA-256
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`, with
`ACP_LIVE_SUPERVISED_RUN_WORKER=1`,
`ACP_LIVE_IMPORT_RESULT_AFTER_CLEANUP=1`, and
`ACP_LIVE_ISOLATION_PROBES=1`, with the exact guest name supplied through
`ACP_LIVE_ISOLATION_DISPOSABLE_HOST`.

This exercised the explicit experimental `WorkersMixin.run_worker()` route,
not just a direct launch-driver call. A deterministic no-model coding task ran
in its attempt-private workspace; the production cleanup verifier completed,
and host-side validation/import placed only the expected fixture changes into
the normal pending-QC path. All live isolation assertions passed: writable
attempt workspace without shared `.git`, read-only rootfs/toolchain closure,
denial of base/harness/sibling/unrelated-project, home/config/credential and
host-temp sentinels, and symlink and canonical-path escapes. The fixture also
confirmed that its specific controller-PID path and two host Unix-socket paths
were absent from the worker view. Its direct-IP probe to `192.0.2.1:443` got the
required `EPERM`/`EACCES` denial. These checks do not establish general
process/socket isolation or broad network-egress denial. No real provider
credentials, provider endpoint, or model call was used.

Postflight found no ACP user units, test roots, or sentinels; the exact VM was
stopped. An initial invocation omitted the required result-import mode and was
rejected by the fixture guard before worker launch; its read-only postflight
found the temporary-root, ACP-unit, and sentinel sets empty (captured output:
`tmp_roots=`; `acp_units=sentinels=`). This proves one no-model execution
through the explicit opt-in supervisor route and its verified-import boundary.
It does not prove a provider/model worker, brokered authentication or allowed
provider egress, supervisor-daemon restart, logout/linger, or reboot recovery. The
default OCI worker path remains fail-closed unless the experimental opt-in and
all required pinned runtime/resource inputs are supplied; #2370 remains open.

### Follow-up known-host PID visibility probe (2026-10-21; no model)

The exact opt-in live test was extended by test-only unified-zero diff
`abeb50625fb9c8c3b7746bd855b82c2218e6de91b53ff41791988f662a3bfbb9` on top of
source commit `7597bf92c904cb25eeb745d3f997ed746e4b061c`. The new fixture starts
one synthetic host-side Python process whose PID exceeds the worker's configured
PID limit; the worker asserts that both the supervising test PID and this
sentinel PID are absent from its `/proc` view. The test asserts that this
sentinel remains alive through worker completion and stops/reaps it only after
the launch-driver and monitor units are verified quiescent. It retains the
existing two host-socket path absence checks and direct-IP denial probe.

The opt-in `test_live_production_launch_driver_runs_exact_pinned_runc_request`
passed 1/1 on the same disposable Debian 12 ARM64 / Linux
`6.12.95+deb12-cloud-arm64` / systemd 252.39 / Python 3.11.2 guest with
root-owned runc 1.5.2 (SHA-256
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`). It used
`ACP_LIVE_SUPERVISED_RUN_WORKER=1`,
`ACP_LIVE_IMPORT_RESULT_AFTER_CLEANUP=1`,
`ACP_LIVE_ISOLATION_PROBES=1`, and the exact guest hostname. The no-model worker
completed the cleanup-gated result import. After verifying the launch-driver
and monitor units quiescent, the harness terminated and reaped the synthetic
host process; independent postflight found no runc process, ACP service unit,
live-launch root, or sentinel process. The exact VM was stopped, and the
temporary source checkout and virtual environment were removed.

This establishes absence of the two specifically checked host PIDs inside this
test namespace, not a general process enumeration guarantee. The socket and
direct-IP probes remain limited to their exact paths/address; broad socket or
network-egress isolation is not claimed. No provider credential, endpoint, or
model call was used. The default OCI `run_worker()` path remains fail-closed,
and task #2370 remains open.

### Follow-up concurrent no-model scope probe (2026-10-21)

`test_live_concurrent_attempts_use_distinct_scopes_and_clean_up` passed 1/1 on
the same disposable Debian 12 ARM64 / Linux `6.12.95+deb12-cloud-arm64` /
systemd 252.39 / Python 3.11.2 VM with root-owned runc 1.5.2 (the SHA-256 is
recorded above). The opt-in started two fresh cancellation-mode pytest
processes at the same time. Its assertions require distinct attempt, container,
execution, PID, repository, run-root, scope-unit, source-worktree, and workspace
identities, plus two consecutive samples where the active ACP scopes exactly
match those two workers' reported scope units. Both child lifecycle tests
completed their cancellation and exact-unit cleanup checks.

Postflight found no runc or Python worker process, active ACP scope,
`acp-live-launch-driver-*` root, or `acp-live-concurrent-control-*` directory.
The VM was stopped and the temporary guest checkout and virtual environment
were removed. This is evidence for simultaneous per-attempt scope and identity
separation during cancellation; it does not establish cross-attempt workspace
read/write isolation, shared Git-metadata isolation, provider/model execution,
or use of the public `run_worker()` entry point. No model or credential was
used, and task #2370 remains open.

### Same-repository concurrent workspace and Git-metadata probe (2026-10-22)

The opt-in `test_live_concurrent_attempts_use_distinct_scopes_and_clean_up`
passed 1/1 on the same disposable Debian 12 ARM64 / Linux
`6.12.95+deb12-cloud-arm64` / systemd 252.39 / Python 3.11.2 guest with
root-owned runc 1.5.2 (SHA-256
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`). Run it
with `ACP_RUN_SANDBOX_WORKER_LIFECYCLE=1`,
`ACP_LIVE_CONCURRENT_ATTEMPTS=1`,
`ACP_OCI_TEST_RUNC=/usr/local/bin/runc`,
`ACP_OCI_TEST_RUNC_VERSION=1.5.2`, and
`ACP_OCI_TEST_BUSYBOX=/usr/bin/busybox` on that disposable supported host.

Unlike the earlier concurrent probe above, this fixture creates one shared
repository and one pinned rootfs for both child processes. It provisions
distinct declared task resources and two runtime-port values, then requires
distinct attempt, task, claim, execution, container, workspace, and active
systemd-scope identities. After two stable scope samples, the host writes a
readable sentinel into each peer workspace and a common sentinel under the
repository `.git` directory. Each worker records its own `/proc/self/mountinfo`
into its private assigned workspace while both scopes are active. The parent
test verifies that the `/workspace` mount root equals that attempt's exact
host workspace path, that `/tmp`, `/dev`, and `/home/agent` are tmpfs and
`/proc` is procfs, and that no mount root from the shared fixture is exposed
outside `/workspace`. The assigned workspace contains no `.git`. Each worker
directly looked up the host-absolute peer-workspace and shared-`.git` sentinels.
It also looked up the peer-workspace sentinel through an absolute symlink and a
`..` path resolving into guest `/tmp`. Those direct paths and peer-workspace
variants were not visible in the worker namespace; direct overwrite probes
found no visible target to write. The host confirmed all three sentinel inodes
and bytes stayed unchanged.

Both child processes then independently verified exact cleanup and synchronize
at a test-only barrier before either invokes the shared-repository reaper. This
avoids one test's simulated future timestamp prematurely expiring its peer.
Each attempt finished orphaned with its runtime allocation released. Postflight
found no active ACP scopes, runc or test processes, launch roots, control
directory, or shared fixture. The VM was stopped, not deleted; the temporary
guest checkout and virtual environment were removed. No model, provider
credential, or provider endpoint was used.

This establishes the observed live mount roots and that these specific shared
repository paths were not visible through the tested lookups on one guest. It
does not establish general kernel isolation, broader host-filesystem coverage,
network-egress policy, provider/model execution, another kernel or
architecture, or default `run_worker()` activation. Task #2370 remains open.

### Supervised `run_worker()` interrupt cancellation (2026-10-24; no provider)

On code-bearing commit `0dbf9622a615732275daf365ba9abb311265da60`,
`test_live_production_launch_driver_runs_exact_pinned_runc_request` passed
1/1 in 13.76s on disposable Debian 12 ARM64, Linux
`6.1.0-53-cloud-arm64`, Python 3.11.2, unified cgroup v2, and an active private
systemd user manager. Root-owned `/usr/local/bin/runc` was version 1.5.2 with
SHA-256 `d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`;
`/usr/bin/busybox` supplied the test payload. The exact test-module SHA-256
matched between the source checkout and guest:
`7a5ba0f6562edd474a19ac87b660c884c317322e834e9fafeb32377349d3feb7`.

The command ran from the disposable checkout beneath `/tmp`:

```sh
ACP_RUN_SANDBOX_WORKER_LIFECYCLE=1 \
ACP_OCI_TEST_RUNC=/usr/local/bin/runc \
ACP_OCI_TEST_RUNC_VERSION=1.5.2 \
ACP_OCI_TEST_BUSYBOX=/usr/bin/busybox \
ACP_LIVE_SUPERVISED_RUN_WORKER=1 \
ACP_LIVE_CANCEL_AFTER_START=1 \
uv run --frozen --extra dev pytest -vv \
  tests/test_sandbox_worker_lifecycle_integration.py::test_live_production_launch_driver_runs_exact_pinned_runc_request
```

The run enabled `ACP_LIVE_SUPERVISED_RUN_WORKER=1` and
`ACP_LIVE_CANCEL_AFTER_START=1`; it did not enable result import. The test
waited for the supervised payload to reach `running`, delivered SIGINT to the
producer blocked in `run_worker()`, and verified exact monitor cancellation,
`cleanup_verified`, a nonzero runc exit, and absence of a `result_imports` row.
It also checked that wrong-credential cancellation was rejected before monitor
reconnection. The interrupted attempt did not produce or import a successful
coding-task result: this cancellation mode uses the sleep payload, not the
coding-task fixture, and imported no result. No provider credentials or
endpoint were configured or used, and no model/provider call was made.

Postflight found no ACP test unit, runc process, test cgroup, or live-attempt
root. The task-specific VM was stopped and the temporary source checkout,
virtual environment, and package cache were removed. Exact-head GitHub Actions
run [40122434656](https://github.com/Rayha33/agent-control-plane/actions/runs/40122434656)
passed all four Ubuntu/macOS x Python 3.11/3.12 jobs, including tests, lint,
formatting, and package build. This is evidence for the explicit opt-in
supervised cancellation path only; it does not prove provider execution or
egress, general hostile-kernel isolation, supervisor restart recovery, or
default OCI-worker activation. Task #2370 remains open.

### Supervised provider-UDS cancellation through `run_worker()` (2026-10-24; no provider)

At code-bearing commit `4e103857a489ea739b8aa7cc7a5e6fa63d8c0f07`,
`test_live_production_launch_driver_runs_exact_pinned_runc_request` passed
1/1 in 14.28s on disposable Debian 12 ARM64, Linux
`6.12.95+deb12-cloud-arm64`, Python 3.11.2, unified cgroup v2, and an active
private systemd user manager. Root-owned `/usr/local/bin/runc` was version
1.5.2 with SHA-256
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`; the
test used `/usr/bin/busybox`. The exact test-module SHA-256 matched between
the source checkout and guest:
`244731600bcd044dde569c5a7962e0bfd6ae14017faea47c58ff58856b3f4643`.

The test ran from the disposable checkout beneath `/tmp` with this cleared
invocation environment (task-specific tool/cache paths are shown verbatim):

```sh
cd /tmp/acp-2370-provider-uds-run-worker-cancel-20261024/repo && \
env -i \
  HOME=/home/rayha.guest \
  PATH=/tmp/acp-2370-provider-uds-run-worker-cancel-20261024/tooling/bin:/usr/local/bin:/usr/bin:/bin \
  XDG_RUNTIME_DIR=/run/user/501 \
  DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/501/bus \
  UV_CACHE_DIR=/tmp/acp-2370-provider-uds-run-worker-cancel-20261024/uv-cache \
  ACP_RUN_SANDBOX_WORKER_LIFECYCLE=1 \
  ACP_OCI_TEST_RUNC=/usr/local/bin/runc \
  ACP_OCI_TEST_RUNC_VERSION=1.5.2 \
  ACP_OCI_TEST_BUSYBOX=/usr/bin/busybox \
  ACP_LIVE_SUPERVISED_RUN_WORKER=1 \
  ACP_LIVE_CANCEL_AFTER_START=1 \
  ACP_LIVE_PROVIDER_PROXY_UDS=1 \
  ACP_LIVE_PROVIDER_PROXY_CANCEL=1 \
  /tmp/acp-2370-provider-uds-run-worker-cancel-20261024/tooling/bin/uv \
  run --frozen --extra dev pytest -vv \
  tests/test_sandbox_worker_lifecycle_integration.py::test_live_production_launch_driver_runs_exact_pinned_runc_request
```

The opt-in test seam injected the named `live-uds-only` policy
(`allowed.example.invalid:443`) into the registered launch call; it did not
add a public provider-egress API or change the default worker path. The worker
verified the read-only attempt socket mount, received 400 for a malformed
request and 403 for the blocked `.invalid` authority, then held a partial UDS
request open. A same-UID peer outside the exact worker cgroup was rejected.
The controller interrupted the process blocked in `run_worker()` with SIGINT;
the attempt reached `cleanup_verified`, the proxy socket and directory were
removed, the wrong runner credential was rejected before monitor reconnection,
and no result-import row was created. The test proves the client held a
connected partial request, not that the server accepted that specific partial
request before cancellation.

This run configured no provider credential or endpoint and made no approved
CONNECT, DNS lookup, external request, TLS handshake, model call, or paid call.
`env -i` cleared the test runner's inherited environment; it supplied only the
shown test flags plus task-scoped tool/cache paths and the active user-manager
socket coordinates. This does not claim that the systemd manager's own
environment was cleared. Postflight found no ACP test unit, runc process,
attempt cgroup, or live fixture root; the task-specific guest files were
removed and the VM was stopped. This composes opt-in provider-socket lifecycle with supervised
cancellation only; it does not prove fake-credential delivery, provider
authentication/egress, TLS redirect behavior, crash recovery through
`run_worker()`, general hostile-kernel isolation, or default OCI-worker
activation. Tasks #2370 and #3441 remain open.

### Supervised `run_worker()` post-wait reaper-race recovery (2026-10-24; no provider)

Code-bearing commit `3da9257bb47486e1d5d3e70796bd7b5cc9906499` adds a bounded
retry when the independent cleanup verifier reports only
`sandbox_execution_gate_busy` for an exact `cleanup_reported` execution. The
worker loop re-reads the durable attempt identity and continues polling; other
verification errors still fail closed. The ordinary wait and interrupt-cleanup
deadlines are unchanged, and result import still requires exact-identity
`cleanup_verified`.

The source and test files reviewed and staged into the guest had these exact
SHA-256 values (host and guest matched):

| File | SHA-256 |
| --- | --- |
| `src/agent_control_plane/supervisor/workers.py` | `641fbb91d4447e95328e5096065e22ec0055260e3136772ff142caff09747cbb` |
| `tests/test_git_supervisor.py` | `d867b4d2a812eccaca0e056ac2401c9f6474fd1523cf58fb5f73dead5adecf14` |
| `tests/test_sandbox_worker_lifecycle_integration.py` | `a9e125022abf2ebd4be99821f7b4016d4f5d1384b5716ea0bfcf8143ac6fb1fe` |

Independent exact-hash review returned GO with no blockers; the reviewer
confirmed the retry remains restricted to the explicit busy-gate error and that
both timeout messages describe incomplete independent verification rather than
claiming no cleanup report exists. The focused unit test passed both normal-wait
and interrupt-cleanup cases. The full local suite exited 0 with 92 expected
platform/opt-in skips; Ruff check/format and `git diff --check` passed.

The exact opt-in
`test_live_production_launch_driver_runs_exact_pinned_runc_request` passed 1/1
on disposable VM `acp-2370-live-sandbox-kernel612-20261021`: Debian 12 ARM64,
Linux `6.12.95+deb12-cloud-arm64`, Python 3.11.2, unified cgroup v2, active
private systemd user manager (`systemd 252.39-1~deb12u2`), root-owned
`/usr/local/bin/runc` 1.5.2 with SHA-256
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`, and
`/usr/bin/busybox`. Its source root was staged from parent commit `6cdf497` plus
the three hash-matched files above. The run used this cleared test-runner
environment (the host invoked the command through `limactl shell`):

```sh
limactl shell acp-2370-live-sandbox-kernel612-20261021 -- env -i \
  HOME=/home/rayha.guest \
  LANG=C.UTF-8 \
  PATH=/tmp/acp-2370-supervised-postwait-recovery-20261024/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  XDG_RUNTIME_DIR=/run/user/501 \
  DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/501/bus \
  ACP_RUN_SANDBOX_WORKER_LIFECYCLE=1 \
  ACP_OCI_TEST_RUNC_VERSION=1.5.2 \
  ACP_OCI_TEST_RUNC=/usr/local/bin/runc \
  ACP_OCI_TEST_BUSYBOX=/usr/bin/busybox \
  ACP_LIVE_SUPERVISED_RUN_WORKER=1 \
  ACP_LIVE_PROVIDER_PROXY_UDS=1 \
  ACP_LIVE_CRASH_AFTER_EXIT_BEFORE_CLEANUP_REPORT=1 \
  /tmp/acp-2370-supervised-postwait-recovery-20261024/tooling/bin/uv run \
  --frozen --extra dev \
  --project /tmp/acp-2370-supervised-postwait-recovery-20261024 \
  --cache-dir /tmp/acp-2370-supervised-postwait-recovery-20261024/uv-cache \
  pytest -q \
  /tmp/acp-2370-supervised-postwait-recovery-20261024/tests/test_sandbox_worker_lifecycle_integration.py::test_live_production_launch_driver_runs_exact_pinned_runc_request
```

The test injected a crash after the kernel wait durably recorded synthetic
worker exit code 17 and the proxy listener was closed/socket removed, but before
pinned-runc deletion or a cleanup report. The OCI config records the read-only
`/run/acp` bind mount, and the stopped runc state entry remained before reaper
recovery; the test does not inspect the mount namespace after worker exit. A
fresh production reaper recovered the exact execution, verified cleanup, and
released its runtime resources. `run_worker()` remained blocked until recovery,
then raised `SupervisorError` reporting `sandbox worker exited 17`; no result
was imported. The live test does not assert that its independent verifier
actually received `sandbox_execution_gate_busy`; the focused unit test
deterministically injects one such transient response in both normal-wait and
interrupt-cleanup paths. Assertions confirmed the provider request was absent
and no result-import row was written. No real provider credential or real
provider endpoint was configured. The test-only policy includes the synthetic
authority `allowed.example.invalid:443`, but no proxy request or DNS lookup was
made; there was no TLS handshake, model call, or paid API call.

Postflight found no `acp-live-launch-driver-*` fixture root, ACP launch/monitor
unit, `runc` or `python3` process, ACP-named cgroup, or open descriptor under
the task staging tree; the test also asserted the exact runc state root was
removed. The guest staging tree was removed and the VM stopped. The host-side
staging archive was moved to Trash after the test, so it remains recoverable.
This proves only the explicit
opt-in no-provider post-wait recovery path and its no-import behavior. It does
not prove provider authentication/egress, supervisor-daemon restart, reboot or
logout recovery, hostile-kernel isolation, or default OCI-worker activation.
Tasks #2370 and #3441 remain open; PR #42 remains draft/open/unmerged.

### CI readiness-test follow-up (2026-10-24; test-only)

The first hosted run of code commit `3da9257bb47486e1d5d3e70796bd7b5cc9906499`
was mixed: one Ubuntu/Python 3.12 attempt failed in the unrelated
`test_reaper_stops_supervised_worker_before_releasing_runtime` test while its
five-second readiness poll checked only that the port was still available. It
did not check whether the worker future had already completed with an error.
Rerunning only that failed job, without changing the commit, passed: 1,742
passed, 22 skipped, one warning, in 316.61 seconds. The evidence supports a
test-observability/readiness race; the first failure did not establish a
production regression.

Test-only commit `00b971d8eb50d15a56554b38fe386e0e7a7cc264` makes that poll
monotonic and bounded at 15 seconds, checks `worker.done()` during and after
polling, and retrieves `worker.result()` so startup exceptions are surfaced.
It does not change product or sandbox runtime behavior. The exact modified
test file SHA-256 is
`d4512f4300e154f74b1aeba85153ccd0dcd99feeecfa14c458b38fc949ec1222`;
independent exact-hash QC returned GO. The focused regression test
`tests/test_git_supervisor.py::test_reaper_stops_supervised_worker_before_releasing_runtime`
passed in 10/10 repeated invocations on disposable Debian 12 ARM64 with Python
3.11.2, and again in 10/10 repeated invocations with Python 3.12.15. These are
ten repetitions of that single test per interpreter, not ten distinct tests.

The full exact-head GitHub Actions matrix for test-only commit
`00b971d8eb50d15a56554b38fe386e0e7a7cc264` passed in [run
40129800793](https://github.com/Rayha33/agent-control-plane/actions/runs/40129800793):

| Runner | Tests | Result |
| --- | --- | --- |
| Ubuntu / Python 3.11 | 1,742 passed, 22 skipped | Success; lint, format, and package build passed |
| Ubuntu / Python 3.12 | 1,742 passed, 22 skipped, 1 warning | Success; lint, format, and package build passed |
| macOS / Python 3.11 | 1,672 passed, 92 skipped | Success; lint, format, and package build passed |
| macOS / Python 3.12 | 1,672 passed, 92 skipped | Success; lint, format, and package build passed |

This matrix checks the repository test suite; it is not additional
sandbox-isolation, provider-egress, activation, or crash-recovery evidence.

### Forced exact-scope SIGKILL cancellation mode (opt-in)

To make fresh-supervisor cancellation prove the monitor's forced branch rather
than allowing a graceful exit, combine
`ACP_LIVE_CANCEL_AFTER_START=1` with
`ACP_LIVE_FORCE_CANCEL_AFTER_START=1` on the disposable Linux guest:

```sh
ACP_RUN_SANDBOX_WORKER_LIFECYCLE=1 \
ACP_OCI_TEST_RUNC=/usr/local/bin/runc \
ACP_OCI_TEST_RUNC_VERSION=1.5.2 \
ACP_OCI_TEST_BUSYBOX=/usr/bin/busybox \
ACP_LIVE_CANCEL_AFTER_START=1 \
ACP_LIVE_FORCE_CANCEL_AFTER_START=1 \
uv run --frozen --extra dev pytest -s -vv \
  tests/test_sandbox_worker_lifecycle_integration.py::test_live_production_launch_driver_runs_exact_pinned_runc_request
```

The isolated submode runs a TERM-ignoring BusyBox sleep payload without
provider/model features. It requires the fresh supervisor's authenticated
cancel result to report `phase=exited`, then reconnects to the same monitor and
replays the identity-bound request ID. The IPC v1 response schema remains
unchanged; the client may attach a separately verified, private monitor
attestation bound to the request digest, execution identity, outcome phase,
method, and exact scope tuple. The test requires that attestation to report
`sigkill` and match the journaled scope. A missing or invalid sidecar does not
undo cancellation success, but this forced-attestation mode fails unless the
method evidence is valid. After independent cleanup verification it emits
`ACP_LIVE_FORCE_CANCEL_RECEIPT=...`; the JSON receipt is written outside the
worker workspace and excludes the enrolled harness credential. The harness
credential authorizes the control-plane attempt only; no provider credential
or provider request is used. A passing test log is required before this mode
can be cited as live SIGKILL evidence.

### Forced exact-scope cancellation replay (2026-10-25 UTC; no provider)

The forced-cancel mode passed 1/1 on the disposable Debian 12 ARM64 Lima guest
`acp-2370-live-sandbox-kernel612-20261021` (Linux
`6.12.95+deb12-cloud-arm64`, systemd `252.39`, rootless runc `1.5.2`, SHA-256
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`). The
guest used CPython `3.12.15` and the frozen development environment. The exact
forced-cancel environment was `ACP_RUN_SANDBOX_WORKER_LIFECYCLE=1`,
`ACP_LIVE_CANCEL_AFTER_START=1`, and
`ACP_LIVE_FORCE_CANCEL_AFTER_START=1`, with the pinned runc and BusyBox paths
above. It finished in 16.24 seconds and emitted this non-secret receipt:

| Evidence | Value |
| --- | --- |
| Attempt / execution / claim fence | `4eb4cc6e-3902-4c14-8a58-a82bc65ee5ee` / `8be9dc6e-4ea7-4291-a798-97925d2ff26c` / `1` |
| Cancel request / request SHA-256 | `c639ddd3174cfb499b20158b966f8929` / `e050148a4c6bea12797b4a7af9e01dd24a1ded9eef5edacf2a583c05886e948f` |
| Monitor result | `ok`, `exited`, `sigkill`; authenticated v1 response replay plus verified attestation sidecar |
| Exact systemd scope | `acp-acp-215afab494c3c86448d99764bfa8fadca83cc3eac64fafee7fd7b34bd4e9.scope`; invocation `ca50dab8dbf74b08b951aed9fad3c761` |
| Exact cgroup | `/user.slice/user-501.slice/user@501.service/user.slice/user-acp.slice/user-acp-088cad51d91aeadfc5e060cac7292a441bc128b57834700471e9b03ee4fe23a1.slice/acp-acp-215afab494c3c86448d99764bfa8fadca83cc3eac64fafee7fd7b34bd4e9.scope` |
| Cleanup / evidence boundaries | `cleanup_verified=true`; provider proxy disabled; no real-provider request; worker output not used as evidence |

Host and guest SHA-256 values matched for all eight changed source/test files
staged for the replay:

| File | SHA-256 |
| --- | --- |
| `src/agent_control_plane/supervisor/sandbox_monitor_ipc.py` | `40f5ff805bc56ce9348c3fe23fc5f35525bd5ac115b8fc18df4d9d91b07b996c` |
| `src/agent_control_plane/supervisor/sandbox_monitor_lifecycle.py` | `41fea59aed41c2381dcc87d9f26e1c684f192f88a6b7e3175d76c41aa1ee2b43` |
| `src/agent_control_plane/supervisor/sandbox_monitor_service.py` | `696e377c33cda461c264ec351fd472718fcc2c3410b18a259eeb887517e4b0cd` |
| `src/agent_control_plane/supervisor/workers.py` | `51d1b9586dc8bee873a2b74bfabe281b960261dd36eb1696698a7bca267f9488` |
| `tests/test_sandbox_execution_journal.py` | `a25faea4361dc798009e5337d00c6f8a8def3e91687a12a5c93a6fe5c25457f9` |
| `tests/test_sandbox_monitor_ipc.py` | `b8a66d713ba7574edee8982d98b33ba437404f55e99275b58c55546518e690e9` |
| `tests/test_sandbox_monitor_service.py` | `43c66258096c93b2c36986033407447dbe4785b3f6ef96b46fe2a40cf2ba81e7` |
| `tests/test_sandbox_worker_lifecycle_integration.py` | `d46b897c1d25e3c95a44a80cb970bbae1179ac44ec1994b806dccb59b838c51b` |

A second 1/1 live run enabled only `ACP_LIVE_PROVIDER_PROXY_UDS=1`. It
exercised the `cleanup_reported` inode-fenced, empty-directory check before
independent verification and the directory-absence check after
`cleanup_verified`. Its worker sent the synthetic blocked-domain CONNECT probe
only over the local test UDS and received the expected HTTP 403; it made no
external DNS lookup or request to a real provider endpoint. Two unrelated,
pre-existing monitor services were also unchanged before and after both
replays: PID `1435`, invocation `d531078c38064b5fbba59d53452bb512`, and PID
`858`, invocation `407e326439354d3d8964a8a5228f8864`. Neither was signaled.

### Exact-head provider UDS cancellation replay (2026-10-24; no provider)

After PR #42 advanced to code commit
`6fe68c36d9521c52c3abacd92bbc906ea7c0e81e`, the opt-in
`test_live_production_launch_driver_runs_exact_pinned_runc_request` passed
1/1 with exit code 0 on the disposable Debian 12 ARM64 Lima VM
`acp-2370-live-sandbox-kernel612-20261021` (Linux
`6.12.95+deb12-cloud-arm64`, systemd `252.39`, rootless runc `1.5.2`, SHA-256
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`). The
fixture ran under CPython 3.12.15 selected by `uv 0.5.9`; its Linux ARM64 uv
binary matched the official [release asset checksum](https://github.com/astral-sh/uv/releases/download/0.5.9/uv-aarch64-unknown-linux-gnu.tar.gz.sha256)
`376d5d52a4b3a9875d66898261e2ce2d31d36c095a1d81cb88d953f5bf7273eb`.

The exact opt-in combination was
`ACP_RUN_SANDBOX_WORKER_LIFECYCLE=1`,
`ACP_LIVE_SUPERVISED_RUN_WORKER=1`, `ACP_LIVE_CANCEL_AFTER_START=1`,
`ACP_LIVE_PROVIDER_PROXY_UDS=1`, and
`ACP_LIVE_PROVIDER_PROXY_CANCEL=1`, with the pinned runc 1.5.2 path/version.
The test injected the synthetic policy authority
`allowed.example.invalid:443`, but the worker never requested that authority.
It reached the attempt-scoped provider UDS and produced the expected
connected/open-partial-request marker. The provider proxy rejected a same-UID
peer outside the exact worker cgroup, which the test asserted as HTTP 403.
Interrupting `run_worker()` reached
`cleanup_verified`; assertions confirmed the provider socket and directory were
removed, all observed worker processes were absent, the required cgroups were
empty, runtime state was `released`, allocations were empty, and the cancelled
result was ineligible for import.

Host and guest SHA-256 values matched for every staged source/test file used by
this proof:

| File | SHA-256 |
| --- | --- |
| `src/agent_control_plane/supervisor/provider_egress.py` | `e6a8bced5a3f284751e69f0da54afc2d2f408e471af5ea3a595aa9313a5139b1` |
| `src/agent_control_plane/supervisor/provider_proxy.py` | `fa8119eb1e4fb1c81f856178a6227569c554049f9ac8e032984d796db0535fca` |
| `src/agent_control_plane/supervisor/sandbox_launch_driver_service.py` | `d68c16bbdf0ad86fbbdc6fb6df6bca07db399fa9c61214f159d5e3e867820865` |
| `src/agent_control_plane/supervisor/sandbox_execution_journal.py` | `0000645f92f783fc45cd86b3d5da9d28e56da261f44e84f17391eafea474f70a` |
| `src/agent_control_plane/supervisor/oci_worker.py` | `9731bedf92ffc0d6e0f368e23db722bc66d358f9cc025926154eb8c2f2f4f134` |
| `src/agent_control_plane/supervisor/workers.py` | `641fbb91d4447e95328e5096065e22ec0055260e3136772ff142caff09747cbb` |
| `tests/test_sandbox_worker_lifecycle_integration.py` | `a9e125022abf2ebd4be99821f7b4016d4f5d1384b5716ea0bfcf8143ac6fb1fe` |

Postflight found no pytest, runc, or launch-driver process; the loaded
`user-acp.slice` had an empty `cgroup.procs`, and no test-specific unit or
fixture root remained. This session removed its temporary guest staging tree
and stopped the VM. `limactl shell` printed two pre-existing guest `.profile`
warnings for helper files under `/tmp` that had already been cleaned; the
test command used `env -i`, and no profile change was made. No provider
credential or real provider endpoint was configured/contacted, and the
synthetic authority above was not requested; the worker communicated only with
the local test UDS. No DNS lookup, TLS handshake, model call, or paid call was
made by the live worker. (The temporary test setup used the official uv asset
and the repository's frozen development dependencies.)
This is fresh evidence for the no-provider UDS cancellation path only; it does
not establish provider authentication/egress, production credential delivery,
crash/reboot recovery, general hostile-kernel isolation, or default-worker
activation. Tasks #2370 and #3441 remain open; PR #42 remains draft/open/unmerged.

### TLS redirect replay: host egress-gate correction (2026-10-24 UTC; pending rerun)

The first composed TLS/canary replay used test-only
`PrivateNetwork=yes` on the systemd user launch-driver unit. On the disposable
Debian 12 ARM64 guest (Linux `6.12.95+deb12-cloud-arm64`, systemd `252.39`),
the unit reported that property but retained the host network-namespace inode.
The live request reached the local TLS mock, verified the synthetic canary,
followed the 302, received denial for the redirected CONNECT, and opened the
third approved UDS tunnel. The test then failed at the namespace-inode
assertion; its 30-second sandbox timeout elapsed before the test's explicit
SIGINT/cancellation path.

That exact fixture is preserved, not cleaned by direct process signaling. A
fresh authenticated read of its attempt monitor returned `phase=unknown` for
the exact failed scope; the durable execution is `stopping` with
`stop_reason=execution_timeout` and no runc kernel-wait/exit evidence or cleanup
receipt. The production `reap_expired()` path moved the expired attempt to
`terminating` / `quarantined` and its task to `cleanup_pending` / `blocked`; it
reported no worker termination or runtime cleanup. The monitor service remains
present, so this fixture and VM are not represented as cleanup-verified.

Read-only loopback probes then showed that `IPAddressDeny=any` on another
transient user service did not block a local control connection, while
`RestrictAddressFamilies=AF_UNIX AF_NETLINK` did allow AF_UNIX and deny creation
of AF_INET/AF_INET6 sockets with `EAFNOSUPPORT`. These probes created no socket
connection to any network address. The test-only TLS replay now requests that
address-family restriction and probes it from inside the exact launch-driver
service before starting the production driver. It also gives that replay a
150-second sandbox timeout so the cancellation assertion has headroom. This is
a syscall-family gate, not a separate network namespace, and this correction
was included in the passing fresh disposable replay recorded below.
Independent static/source QC returned GO on the exact code diff.
Tasks #2370 and #3441 remain open; PR #42 remains draft/open/unmerged.

The fresh kernel-6.12 replay reached the worker's `provider-probe-result` and
`provider-probe-open` markers, but did not reach durable cleanup verification.
Attempt `056c420f-2086-49a6-affd-fce50aedb9a3` remained `stopping` with
`stop_reason=terminate_worker`, no observed runc exit code, and empty cleanup
receipts. Pytest preserved `/tmp/acp-live-launch-driver-zf3u4i15`; its finalizer
reported the exact test units non-quiescent. Read-only inspection then found the
attempt slice inactive, its scope `failed` with `Result=timeout`, and the
attempt monitor still active. Authenticated monitor reconnection refused the
attempt-slice mismatch, so no direct cancellation, unit stop, or fixture
cleanup was attempted afterward. The exact production reaper then returned no
worker terminations or runtime cleanup; it quarantined this attempt, kept its
task `cleanup_pending` / `blocked`, and retained the provider artifact. The
earlier attempt remains a separate quarantined fixture.

This run exposed a test-finalizer hazard: it could request teardown of the
attempt slice while the exact durable execution was still stopping, invalidating
the monitor's durable slice binding before cleanup verification. The test now
checks the attempt/claim/execution identity and exact `cleanup_verified` phase
before any ACP unit stop; otherwise it preserves the fixture and units.
That guard has local tests and was exercised by the passing fresh disposable
replay recorded below. Independent static/source QC returned GO on the exact
code diff. Tasks #2370 and #3441 remain open; PR #42 remains
draft/open/unmerged.

### Bounded cancellation escalation (2026-10-24 UTC; replay pass)

Read-only systemd journal inspection of the second failed fixture established
the cancellation timing: the authenticated monitor's durable cancel response
was `outcome=ok, phase=stopping`; the exact scope began stopping at
23:13:27 UTC, then systemd logged `Stopping timed out. Killing.` at 23:14:57
UTC and sent SIGKILL to the held `provider-tls-redirect-probe`. The scope had
inherited `TimeoutStopUSec=1min 30s` and ended with `Result=timeout`. This is
why the controller's 30-second cancellation cleanup deadline expired before
the original graceful-stop job escalated. The test's earlier finalizer then
requested attempt-slice teardown while the execution was still unverified;
the new `cleanup_verified` identity guard prevents that secondary hazard.

The monitor now allows a two-second graceful stop, then sends SIGKILL only to
the exact scope unit after rereading and confirming its invocation, cgroup, and
attempt-slice binding; it never targets a controller-supplied PID or the parent
slice. It polls that same identity for up to five seconds after escalation and
fails closed on unknown/replaced scope state or anything other than verified
`stopping` or `exited`. Focused monitor-service tests and local Ruff/format
checks pass. Independent static/source QC of the exact code diff is GO. The
fresh exact-source replay passed the composed supervised FD4-canary, provider
UDS, TLS-redirect-denial, and cancellation test 1/1 (exit 0) on the disposable
Debian 12 ARM64 guest (Linux 6.12.95, systemd 252.39, runc 1.5.2). Its exact
cleanup-identity assertion passed. Post-run read-only inspection found no new
attempt runroot, provider-proxy directory, active test service, or scope; the
two earlier quarantined fixtures remain untouched. The replay used only the
synthetic provider canary and local mock; it made no provider request and used
no real provider credentials. The harness used its enrolled test-runner
credential for control-plane authorization. The live test proves cancellation
and verified cleanup; it does not emit a separate receipt identifying whether
graceful stop or forced SIGKILL completed the scope. The focused
monitor-service unit tests separately assert exact-scope SIGKILL escalation
and fail-closed identity checks. Tasks #2370 and #3441 remain open; PR #42
remains draft/open/unmerged.

### Live synthetic FD4 worker-canary replay (2026-10-24; no provider)

The opt-in `test_live_production_launch_driver_runs_exact_pinned_runc_request`
passed 1/1 (exit 0) from an archive of PR head
`631d55819beab784bff4896eb9f434eaff0767a1` on the same disposable Debian 12
ARM64 / Linux 6.12.95 / systemd 252.39 VM, using CPython 3.11.2, checksum-
verified uv 0.5.9, and rootless runc 1.5.2. Host and guest SHA-256 matched for
`oci_worker.py`, `sandbox_launch_driver_service.py`,
`sandbox_execution_journal.py`, the integration test, `pyproject.toml`, and
`uv.lock` (the source and lock hashes match the preceding tables).

The worker-delivered credential payload was a random test canary, with
`ACP_LIVE_WORKER_CANARY_FD4=1` and the explicit test-only
`ACP_TEST_ALLOW_WORKER_CANARY=1`; no provider endpoint, provider credential,
provider proxy, model inference, or paid call was configured. The worker's
static probe read the canary through the test FD4 path and returned its
expected SHA-256 digest. Assertions kept the raw canary out of launch-driver
systemd argv/environment, supervisor event payloads, SQLite database bytes,
and the launch-driver service log. The isolated execution workspace's named
`worker-canary-fd4-result` artifact contained the expected digest, not the raw
canary. This invocation omitted both supervised-worker and import-after-cleanup
flags, so it did not exercise registered `run_worker()` composition or create
an imported result commit. The synthetic enrolled test-runner credential used
for control-plane authorization remained on the harness path, distinct from
the worker-delivered canary.

Postflight found no `acp-` scope or `acp-live-*` fixture root; the exact
owner-private source/uv staging tree was removed and the VM stopped. This is
test-only FD4 transport evidence for the production launch-driver path. It
does not establish registered `run_worker()` composition, real credential
delivery, provider proxy policy/egress, or absence of canary bytes from every
possible host path. Task #3441 remains open; PR #42 remains draft/open/unmerged.

### Supervised `run_worker()` FD4 canary and result-import replay (2026-10-24 UTC; no provider)

The follow-up used a `git archive` of PR head
`9c25c8983d2346e1950bbc262361d6e880ab04f4` in the same disposable Debian 12
ARM64 / Linux `6.12.95+deb12-cloud-arm64` VM, with systemd `252.39`, CPython
`3.12.15`, uv `0.5.9`, and rootless runc `1.5.2` (binary SHA-256
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`). The
Linux ARM64 uv release asset matched its official SHA-256
`376d5d52a4b3a9875d66898261e2ce2d31d36c095a1d81cb88d953f5bf7273eb`.

Host and guest source SHA-256 values matched:

| File | SHA-256 |
| --- | --- |
| `pyproject.toml` | `cfb987509711316640f448b0b87eeee3cd9ffe396bd30bac25cdd62b6299acca` |
| `uv.lock` | `f3314012c2d1fcf5f05949a5c15c07e20be43283d8c927d5d676a24ea29f78b8` |
| `src/agent_control_plane/supervisor/oci_worker.py` | `9731bedf92ffc0d6e0f368e23db722bc66d358f9cc025926154eb8c2f2f4f134` |
| `src/agent_control_plane/supervisor/sandbox_launch_driver_service.py` | `d68c16bbdf0ad86fbbdc6fb6df6bca07db399fa9c61214f159d5e3e867820865` |
| `src/agent_control_plane/supervisor/sandbox_execution_journal.py` | `0000645f92f783fc45cd86b3d5da9d28e56da261f44e84f17391eafea474f70a` |
| `tests/test_sandbox_worker_lifecycle_integration.py` | `a9e125022abf2ebd4be99821f7b4016d4f5d1384b5716ea0bfcf8143ac6fb1fe` |

With `ACP_RUN_SANDBOX_WORKER_LIFECYCLE=1`,
`ACP_LIVE_WORKER_CANARY_FD4=1`, `ACP_TEST_ALLOW_WORKER_CANARY=1`,
`ACP_LIVE_SUPERVISED_RUN_WORKER=1`, and
`ACP_LIVE_IMPORT_RESULT_AFTER_CLEANUP=1` (plus the pinned runc and BusyBox
paths), `test_live_production_launch_driver_runs_exact_pinned_runc_request`
passed 1/1 in 2.36s (exit 0). Unlike the preceding isolated launch-driver
replay, this mode exercised registered `run_worker()`, verified
`cleanup_verified`, then imported the synthetic result into its temporary
fixture repository; the submission reached `pending_qc` and the fixture task
reached `qc_review`. Assertions checked the expected imported paths and that
`worker-canary-fd4-result` contained only the expected SHA-256 digest.

The synthetic worker-delivered canary remained absent from launch-driver
systemd argv/environment, supervisor event payloads, SQLite database bytes,
and the launch-driver service log. The enrolled test-runner credential stayed
on the harness authorization path, separate from the worker canary. The guest
command piped combined pytest stdout/stderr through a regex replacement for the
random canary pattern before returning it to the host; no raw log was saved.
No provider endpoint,
provider credential, provider-proxy request, model inference, or paid call was
configured or used. The canary is test data, not a real secret: worker-controlled
stdout/stderr or result files could contain it if worker code printed it; this
replay's result contained only the digest.

Postflight found zero `acp-*` user units, no runc process, no `acp-live-*`
fixture root, and an empty `user-acp.slice` cgroup. The exact mode-0700
owner-private source/uv staging tree was removed, and the VM was stopped. This
proves the test-only FD4 path through supervised `run_worker()` and
cleanup-verified fixture result import on this Linux tuple. It does not prove
real provider credentials/authentication or egress, broad absence of canary
bytes from every host path, reboot recovery, hostile-kernel isolation, or
default-worker activation. Tasks #2370 and #3441 remain open; PR #42 remains
draft/open/unmerged.

### Supervised FD4 canary with provider-UDS cancellation (2026-10-24 UTC; no provider)

At code head `9ce0abd812d01cdd3da8a3031e5b68a884ad43b6`, the integration test
module was updated only in the disposable test checkout and matched host to
guest at SHA-256
`c299873fe5f186d8273a219094f5b57f7938b9a322b771b761e55912991650b9`. Runtime
source remained at the PR head. The replay used Debian 12 ARM64, Linux
`6.12.95+deb12-cloud-arm64`, systemd `252.39`, CPython `3.12.15`, checksum-
verified uv `0.5.9` (Linux ARM64 release asset SHA-256
`376d5d52a4b3a9875d66898261e2ce2d31d36c095a1d81cb88d953f5bf7273eb`), BusyBox
`1.35.0`, and rootless runc `1.5.2` (binary SHA-256
`d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`). The
other staged source hashes matched the preceding supervised canary replay.

The exact live-test flags were:

```sh
ACP_RUN_SANDBOX_WORKER_LIFECYCLE=1 \
ACP_OCI_TEST_RUNC=/usr/local/bin/runc \
ACP_OCI_TEST_RUNC_VERSION=1.5.2 \
ACP_OCI_TEST_BUSYBOX=/usr/bin/busybox \
ACP_LIVE_SUPERVISED_RUN_WORKER=1 \
ACP_LIVE_CANCEL_AFTER_START=1 \
ACP_LIVE_PROVIDER_PROXY_UDS=1 \
ACP_LIVE_PROVIDER_PROXY_CANCEL=1 \
ACP_LIVE_WORKER_CANARY_FD4=1 \
ACP_TEST_ALLOW_WORKER_CANARY=1 \
uv run --frozen --extra dev pytest -vv \
  tests/test_sandbox_worker_lifecycle_integration.py::test_live_production_launch_driver_runs_exact_pinned_runc_request
```

The actual guest invocation used `env -i` with only task-scoped `HOME`, `PATH`,
user-manager socket coordinates, `UV_CACHE_DIR`, and the flags above; the
verified uv 0.5.9 binary was first on `PATH`.

`test_live_production_launch_driver_runs_exact_pinned_runc_request` passed
1/1 in 14.19 seconds. It exercised the registered `run_worker()` path: the
worker read the synthetic FD4 canary and wrote only its SHA-256 digest, then
used its attempt-scoped provider UDS for the malformed-request and blocked
`.invalid` policy probes. It opened a partial local UDS request; a same-UID
peer outside the exact worker cgroup received HTTP 403. SIGINT cancellation
reached `cleanup_verified`; the test asserted the canary digest result existed
in the temporary workspace, but the cancelled result was not imported. No
approved CONNECT, DNS lookup, external network request, TLS session, provider
authentication, model inference, or paid call occurred.

The first composite run exposed a fixture-only conflict: the ordinary canary
probe wrote the success marker before the cancellation assertion expected it
absent. The test harness now compiles that probe without the success marker in
this exact cancellation combination; the rerun passed. Canary assertions still
check the covered launcher argv/environment, supervisor events/database bytes,
and service log. This synthetic value is not a real secret, and worker-owned
stdout/stderr or result files remain capable of containing it if worker code
prints it; this replay did not establish absence from every possible host path.

Postflight found no ACP test unit, no runc process, no `acp-live-*` fixture
root, and an empty `user-acp.slice` cgroup. The exact mode-0700 source/uv
staging tree was removed and the VM was stopped. This is evidence for composing
the test-only FD4 canary with supervised proxy-UDS cancellation and cleanup on
this Linux tuple. It does not prove a successful approved tunnel, TLS redirect
handling, real provider credentials/authentication/egress, reboot recovery,
hostile-kernel isolation, or default-worker activation. Tasks #2370 and #3441
remain open; PR #42 remains draft/open/unmerged.

### Live concurrent-workspace and post-wait recovery replay (2026-10-24; no provider)

The source archive was taken from docs-only PR head
`4ccef712f16943f39c48e3de155e9836cc02578f`; its runtime and integration-test
files matched the seven host/guest hashes in the preceding replay table.
`pyproject.toml` (`cfb987509711316640f448b0b87eeee3cd9ffe396bd30bac25cdd62b6299acca`)
and `uv.lock` (`f3314012c2d1fcf5f05949a5c15c07e20be43283d8c927d5d676a24ea29f78b8`)
also matched. Both runs used the same disposable Debian 12 ARM64 VM, Linux
`6.12.95+deb12-cloud-arm64`, systemd `252.39`, rootless runc `1.5.2`, and
CPython `3.11.2`.

`test_live_concurrent_attempts_use_distinct_scopes_and_clean_up` passed 1/1
(exit 0) with `ACP_RUN_SANDBOX_WORKER_LIFECYCLE=1` and
`ACP_LIVE_CONCURRENT_ATTEMPTS=1`. It held two no-model supervised cancellation
runs active against the same synthetic repository. The test required distinct
attempt, container, execution, process, run-root, systemd-scope, source-worktree,
and workspace identities, plus different simultaneously held runtime-port
allocations. Both active scope identities remained stable across two samples.
Each private mode-0700 workspace was under the repository's sandbox-execution
root, had no `.git`, and was the exact `/workspace` mount source. Live probes
could not read or write the other attempt's sentinel or a sentinel under the
shared repository `.git`; sibling symlink and canonical `../../` probes were
also not visible. Both host sentinels retained their original inode and bytes.
Worker mountinfo showed one `/proc`, `/dev`, `/workspace`, `/tmp`, and
`/home/agent` mount; the only visible test-fixture host mount was that attempt's
own workspace, with no broad `/etc`, `/usr`, `/home`, or `/root` mount. The
fixture's cancellation and post-cleanup assertions passed for both children.

`test_live_production_launch_driver_runs_exact_pinned_runc_request` also passed
1/1 (exit 0) with `ACP_LIVE_PROVIDER_PROXY_UDS=1`,
`ACP_LIVE_CRASH_AFTER_EXIT_BEFORE_CLEANUP_REPORT=1`, and
`ACP_LIVE_SUPERVISED_RUN_WORKER=1`. Its test-only wrapper exited after the
kernel wait was durably recorded and the provider proxy closed, but before
pinned-runc deletion and the cleanup report. A fresh production reaper finished
the exact cleanup and resource release; `run_worker()` rejected the synthetic
exit-code-17 result without importing it. This mode created the provider UDS
but made no proxy request. Neither live worker used a provider credential,
real provider endpoint, DNS/TLS provider connection, model inference, or paid
call. The setup fetched the checksum-verified official uv asset and used the
repository's frozen development dependencies.

Postflight found no pytest, runc, or launch-driver process, no active `acp-`
systemd scope, and no concurrent-test or launch-driver fixture roots; the two
test suites also verified their exact units and fixture cleanup before exit.
This session removed its staged source and uv directories and stopped the VM;
both task VMs are stopped. `limactl shell` printed the same pre-existing guest
`.profile` warnings for helper paths already removed under `/tmp`; the test
processes used `env -i`, and no profile was changed. These are bounded proofs
of two concurrent attempt workspaces and one post-wait recovery boundary on
this Linux tuple, not proof of provider egress/authentication, real credential
delivery, reboot recovery, general hostile-kernel isolation, Codex CLI
read-isolation, or default-worker activation. Tasks #2370 and #3441 remain
open; PR #42 remains draft/open/unmerged.

### Live readable-host-sentinel isolation replay (2026-10-24; no provider)

From the same source archive and matching runtime/test hashes, the opt-in
`test_live_production_launch_driver_runs_exact_pinned_runc_request` passed 1/1
(exit 0) on the disposable Debian 12 ARM64 VM above, under CPython 3.11.2 and
rootless runc 1.5.2. The run set
`ACP_RUN_SANDBOX_WORKER_LIFECYCLE=1`, `ACP_LIVE_ISOLATION_PROBES=1`, and
`ACP_LIVE_ISOLATION_DISPOSABLE_HOST` to the exact VM hostname; no provider,
endpoint or provider credential was configured, and neither supervised
`run_worker()` nor FD4 worker-credential delivery was enabled. The test
harness still used its enrolled test-runner credential for control-plane
authorization.

The worker probe rejected the unique synthetic sentinels at host `/etc`,
`/usr/local/share`, the VM host user's home/config/SSH paths, host temporary
storage, the harness checkout, task base checkout, sibling worktree, and an
unrelated project. It also asserted the rootfs was read-only, `/usr` absent,
`/tmp` and `/home/agent` were private tmpfs mounts, the harness PID and a
synthetic host-process sentinel PID plus the host-only and systemd sockets were
invisible, symlink and canonical-path escapes failed, and direct TCP to a
reserved external-test IP was denied while workspace scratch remained
writable. Teardown removed privileged sentinels only after identity-and-content
verification and completed without preserving an uncertain fixture.

Postflight found no remaining test sentinels, `acp-live-*` fixture roots, or
ACP scope in the guest; the test-owned source/uv staging tree was removed and
the VM stopped. The guest printed the same pre-existing `.profile` warnings
for deleted `/tmp` helper paths; commands used a cleared environment after
shell startup and did not modify the profile. This proves the tested host-path
denials on this exact disposable Linux tuple; it does not prove confinement
against a hostile kernel, other hosts/runtimes, Codex CLI profile-path reads,
provider egress/authentication, real credential delivery, or default-worker
activation. Tasks #2370 and #3441 remain open; PR #42 remains draft/open/unmerged.

### Exact-head Linux 6.12 PIDFD-gated TLS/cancellation replay (2026-10-25)

At exact PR #42 head
`747c32988be7dbf72ffba4f042986848bed43533`, the opt-in
`test_live_production_launch_driver_runs_exact_pinned_runc_request` passed on
the existing disposable Debian 12 ARM64 Linux `6.12.95+deb12-cloud-arm64`
guest (systemd `252.39`, CPython `3.11.2`, root-owned runc `1.5.2`). The exact
source archive SHA-256 was
`a21c09a9d5d8f3a12867bbfec0a2b71b1c15e0f7f30ee4cbe46302be0b299903`; host and
guest hashes matched for `provider_proxy.py`
(`02036e6d427c1ae5a4dcac580e3107bfafd668600607cfa50805b54e188c582f`),
`sandbox_launch_driver_service.py`
(`4f3c03a15881c0816219f6df027c1512f64a2af4f6f717ed0b24292ac2c3fc67`), the
integration test (`d46b897c1d25e3c95a44a80cb970bbae1179ac44ec1994b806dccb59b838c51b`),
`pyproject.toml`, and `uv.lock`. The runtime kernel returned a real
`SO_PEERPIDFD` descriptor; the exact same code's Linux 6.1 path is separately
verified to reject before provider attempt reservation.

The cleared environment enabled supervised `run_worker()`, the explicit
test-only FD4 canary, the production per-attempt UDS proxy, TLS redirect
handling, and cancellation. The local TLS mock matched the synthetic bearer;
the redirected disallowed CONNECT was rejected before resolver/dial, and the
in-cgroup worker peer was authorized while a same-UID outside peer was denied.
Cancellation reached exact `cleanup_verified`, removed the attempt proxy
artifacts, and left the cancelled result unimported. No public network socket,
external DNS, real provider credential/endpoint, model inference, or paid call
was used. This is not production credential delivery or external-provider
acceptance.

The run exited 0 for the single targeted live test. Postflight found no new
ACP service, test worker, runc process, or test-specific launch-driver root;
the two previously quarantined monitors and older failed unit were left
untouched. Exact-head hosted CI run `40154200500` passed all four
Ubuntu/macOS × Python 3.11/3.12 jobs; independent exact-diff QC was GO. The
default OCI worker remains disabled/fail-closed; #2370/#3441 remain open and
PR #42 remains draft/open/unmerged.

### Experimental named provider credential channel (2026-10-25)

The experimental `run_worker()` path accepts a separate
`sandbox_provider_credential_fd` only with policy name `read-only-fd4-v1` and a
named UDS egress policy. The source must be an anonymous regular descriptor
with `st_nlink == 0`, 8–4096 bytes, and all four required memfd seals. Invalid
policy pairs, missing or unsealed descriptors, and command collisions fail
before attempt reservation. The launch request persists the policy name, not
secret bytes. The API caller retains ownership of the source descriptor and
must close it when finished; ACP snapshots it before handing off to systemd.

The producer snapshots the sealed descriptor into an anonymous FD, starts the
service with `LoadCredential=`, and passes the credential only through its
read-only private credential directory. The launch driver writes a bounded
read-only pipe at FD 4; the worker receives no credential in argv or
environment. The journal records the transport kind. Where CPython omits the
`F_SEAL_*` constants, Linux UAPI values are used while still requiring the full
seal mask.

FD 4 is a delivery mechanism, not an isolation boundary: the worker, root, or
another process with the same UID can read it, and worker output/result data
can disclose it. Evidence is synthetic/fake-only. The opt-in remains limited
to the named UDS/CONNECT path; it does not add a generic TCP or SDK bridge or
inspect encrypted URLs/TLS redirects inside the proxy. See
`WORKER_SANDBOX.md` for the exact replay and its limits.
