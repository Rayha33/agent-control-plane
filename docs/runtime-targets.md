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
