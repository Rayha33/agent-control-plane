# QC and integration runtime-target provenance

Git worktrees isolate files; they do not prove which API, database, worker, or
queue a test reached. ACP's unique runtime ports and trusted resource drivers
help allocate those resources, but allocation alone is not target identity. The
opt-in contract below adds a phase-specific preflight receipt before configured
QC or integration commands run.

## Configure a target

First configure an attempt-scoped port and trusted runtime drivers as described
in [Runtime isolation](../README.md#runtime-isolation). Then add a target that
binds the endpoint to its service driver and, when applicable, to database and
queue namespace drivers:

```toml
[runtime.ports]
APP_PORT = [41000, 41999]

[[runtime.targets]]
name = "api"
port_env = "APP_PORT"
driver = "api-compose"
database_driver = "postgres-schema"
queue_driver = "worker-compose"
identity_path = "/.well-known/acp/runtime-target"
schema_version = "v7"
phases = ["qc", "integration"]
required = true
```

`name` is a unique lowercase identifier. `port_env` must name a unique entry in
`runtime.ports`; the URL is always constructed as
`http://127.0.0.1:<allocated-port>`, never from an arbitrary URL. `driver` and the optional database/queue
drivers must be configured trusted drivers. `phases` may contain `qc`,
`integration`, or both. `required` defaults to true. `schema_version` is an
optional expected value.

The identity endpoint must return a small JSON object with
`contract: "acp-runtime-target-v1"`. Required fields for a fully corroborated
target are `attempt_id`, `task_id`, numeric `claim_token`, `phase`, exact Git
`source_revision`, assigned numeric `port`, and `driver_resource_id`. If a
database or queue driver is configured, also report `database_namespace` or
`queue_namespace`, matching that driver's active resource ID. When
`schema_version` is configured, report the exact value. For example:

```json
{
  "contract": "acp-runtime-target-v1",
  "attempt_id": "attempt-uuid",
  "task_id": "task-uuid",
  "claim_token": 12,
  "phase": "qc",
  "source_revision": "0123456789abcdef0123456789abcdef01234567",
  "port": 41023,
  "driver_resource_id": "acp-attempt-uuid",
  "database_namespace": "acp_attempt_uuid",
  "schema_version": "v7",
  "queue_namespace": "acp-attempt-uuid-worker"
}
```

When a trusted driver exposes host-captured container IDs or a systemd
invocation ID, ACP includes them as `host_identity` evidence and compares a
single known ID if the app reports `container_id` or `process_identity`. If the
driver cannot expose that identity, the receipt says
`host_identity.status = "unknown"`; ACP does not invent a PID or container ID.

During a target-aware restart ACP supplies the attempt/task/claim identity,
phase, phase checkout, and exact source revision to the trusted runtime drivers
as `ACP_ATTEMPT_ID`, `ACP_TASK_ID`, `ACP_CLAIM_TOKEN`, `ACP_PHASE`,
`ACP_WORKTREE`, and `ACP_SOURCE_REVISION`. Driver-specific configuration must
pass through the fields its service needs. Test commands receive
`ACP_TARGET_<NAME>_URL`, `ACP_RUNTIME_TARGETS_FILE`, and
`ACP_RUNTIME_TARGETS_SHA256`. The manifest is created mode `0400` outside the
checkout and the receipt records its hash. These permissions and hashes detect
accidental mutation; a same-UID command is not prevented from changing the
file.

After a `postgres_schema` driver creates and independently probes its
driver- and attempt-specific schema, the worker also receives
`ACP_DATABASE_SCHEMA_<DRIVER>_<SHA256>` (with a bounded readable driver slug
and the full SHA-256 of the configured driver name) set to that schema name.
This value is non-secret and lets a cooperating test or service select its
namespace. ACP validates the key and value against the driver receipt, persists
it across worker launch and recovery, and removes it only after teardown proves
the schema absent. This routes cooperating clients; it does not restrict what a
database role can access. Use per-attempt roles/grants and database-side policy
when isolation from a non-cooperating or hostile client is required.

## Resource support and limits

The backing control planes remain host-global: local TCP/port space, the
PostgreSQL server and role, the Docker daemon, installed browser binaries, and
the CoreSimulator service. ACP scopes only the attempt-owned allocation or
namespace listed below; it does not make those host services private.

| Resource | Namespace classification | Cleanup / limit |
| --- | --- | --- |
| Local TCP services | Attempt-private port assignment from each configured pool. | ACP probes before recycling and quarantines a port still in use. Assignment is not socket-ownership proof; use the process/container runtime for that. |
| PostgreSQL | Attempt-private schema per driver and attempt on a shared-global server/role. | Cleanup drops the schema and independently probes for absence. Schemas route cooperating clients only; the configured role can still access other schemas unless database grants or policies restrict it. |
| Compose-backed services / queues | Attempt-private Compose project on the shared-global Docker daemon. A runtime target's `queue_driver`, when present, must use this adapter. | Teardown issues `down --volumes --remove-orphans` and verifies the project's containers are absent. External queues (for example, shared Redis, SQS, or a hosted broker) have no per-attempt adapter here: a declared non-Compose queue driver fails configuration. Treat undeclared external queues as unsupported for mutating tests, or shared-read-only only when the test is demonstrably read-only. |
| Browser profiles | Attempt-private browser data directory; browser binaries remain host-global. The path is passed to the worker as `ACP_BROWSER_PROFILE_<DRIVER>_<SHA256>`. | The browser/test command must consume that variable. ACP removes the directory only after its absence proof; the directory does not force a browser binary to use it or provide a browser process sandbox by itself. Use process-tree containment and do not launch detached host browsers. |
| CoreSimulator | Attempt-private cloned UDID on the shared-global CoreSimulator service, on supported macOS hosts. | The clone is shut down and deleted through the simulator driver's lifecycle. Availability and capacity are host-dependent; other simulator profiles are unsupported. |

ACP cannot discover arbitrary service access hidden inside candidate code. A
target receipt is therefore not permission to mutate an undeclared global
service; shared third-party services must be disabled or restricted to
read-only by the selected execution profile.

Driver allocations, fencing tokens, setup/teardown receipts, and cleanup probes
are owned by the supervisor and survive worker restart/recovery. On Linux, use
the supervised worker trampoline or `namespace_runtime` when test processes
must be contained and reaped on cancellation/expiry. Without process-tree
containment, ACP can prove resource setup and cleanup but cannot claim that an
arbitrary detached process stopped using an external service. A worker or
service that ignores its supplied namespace remains outside the isolation
guarantee; do not run mutating tests against shared external services.

QC and integration hold the task-operation lock continuously across target preflight
and their configured commands. Public runtime restart and recovery acquire that same
lock, so they fail closed instead of replacing a target after its receipt is checked.
The internal phase restart reuses the lock already held by QC or integration. Trusted
process monitors retain the lock while driver and phase-command process trees are
alive, but close it before command execution; a crashed supervisor therefore cannot
release the fence while a monitored command is still running, and the command itself
cannot unlock it.

## Gate and evidence semantics

ACP probes only the allocated loopback port, makes one bounded HTTP GET, accepts
only a small JSON response, does not follow redirects or use HTTP proxies, and
persists only an allowlist of identity fields. Required target mismatch or
missing evidence blocks the phase before tests. A missing response or field is
`unknown`, not a match. Receipts are stored with the QC or integration run and
include the attempt, task, claim counter, digest of the resource fencing-token
map, phase, source revision, expected endpoint, driver resource state, available
host identity, and expected-versus-observed identity fields. Secret values, arbitrary response
bodies, process command lines, credentials, and endpoint tokens are not stored.

An exact report is labeled `corroborated`, with `verified: false`. The service
controls its own report; this contract does not authenticate that report, prove
which process owns the listening socket, prove that the app connected to the
reported database/queue, or enforce that an arbitrary test command uses the
declared endpoint. The endpoint and manifest are available for the command to
use, but a command may ignore them. Use OS-level process/container attribution
and network policy when those stronger guarantees are required. Projects that
do not configure `runtime.targets` keep their existing QC and integration
behavior and make no target-identity claim.
