# Security Policy

Agent Control Plane is an early reference implementation. Do not treat it as a
production security boundary without the hardening described in the README and
architecture document.

The Git supervisor executes configured runtime setup/teardown, QC, critic,
worker, and integration commands. Those commands may execute candidate
repository code. Use an OS/container sandbox and restricted network credentials
for untrusted code. Only trusted maintainers should change
<code>acp.toml</code>. Runtime hook output is stored under ignored local
<code>.acp/logs/</code>; hooks must not print credentials. Legacy shell hooks
remain trusted operator configuration. Prefer phase-scoped runtime drivers for
supported resource types: their executable and parent chain must be root-owned
and non-group/world-writable,
execution uses a scrubbed environment and immediate open/stat identity check, and teardown
must prove resource absence.

For production, configure `[trust]` and use `trusted:NAME` selectors instead of
loose executable paths. The root-owned `acp-trust-helper` installs immutable,
versioned bundles from no-follow file descriptors and atomically rotates a
regular `current` pointer. ACP stores the manifest digest plus executable
device/inode/content digest on the attempt and QC row. A missing, writable,
replaced, or digest-mismatched old bundle quarantines the attempt; ACP never
falls forward to the current version. Retirement and uninstall create markers
only and never delete bundle evidence. Treat manual deletion as destructive:
first prove no attempt or QC record references that bundle ID and manifest.

On Linux, trusted execution uses the already-open `/proc/self/fd` descriptor to
close the final path-to-exec race. macOS does not support executable `/dev/fd`
entries, so its guarantee depends on a root/dedicated-UID-owned directory chain
with no group/world write bit. The trust UID must not be the candidate runner
UID. The helper, its Python interpreter and imported package files must also be
installed in root-controlled paths; a root-owned wrapper importing user-writable
Python is not a privilege boundary.

Runtime port pools prevent two cooperating ACP attempts from receiving the same
configured TCP port. They are not kernel reservations: an unrelated local
process can race the availability probe. ACP quarantines a port that remains
occupied after teardown. Built-in drivers prove cleanup of their declared
Compose project, PostgreSQL schema, or browser profile; ACP cannot prove
undeclared cloud or application side effects. Use provider-native
deletion/fencing for those resources.

Database schema/migration, deploy namespace, and artifact/tag mutations routed
through the side-effect gateway are checked against the authenticated worker,
mandate scope, live task claim, complete resource-token map, and
provider-derived target before a driver can run. HTTP bodies cannot supply an
actor or role, and the MCP/A2A path maps durable task/artifact identity into the
same gate. The provider call carries the idempotency key and both fencing
generations; a production driver must enforce them at the remote mutation
boundary. The local receipt transaction prevents duplicate concurrent calls on
one ACP host, but it cannot roll back a remote mutation if ACP crashes before
committing the receipt. Provider-native idempotency closes that window. Treat
payload and provider result data as secret-bearing: drivers must not log or
return credentials. Receipts persist only identities, generations, and
request/result digests.

After the first runner enrollment, every worker heartbeat/submission/process
transition, critic review, and integration transition requires a role-scoped
bearer credential. Attempts bind to the credential digest used at claim, and
revocation cannot disable authentication. These are local bearer identities,
not cryptographically authenticated humans, model providers, or remote hosts.
Use distinct credential sinks and OS accounts or an external identity gateway
for higher assurance.

Candidate-facing child environments use a small public allowlist plus explicit
ACP runtime variables; arbitrary host secrets are not inherited. The CLI
accepts credentials from a private file, inherited environment, or
file descriptor and never from argv. Enrollment writes the one-time secret to a
private file or descriptor rather than JSON. Runtime-driver credentials are
separate versioned handles: PostgreSQL rejects DSNs and environment-secret
references, retains the exact private version needed for cleanup, and supplies
the password as an anonymous descriptor-backed <code>PGPASSFILE</code>. Psql
startup files and interactive password fallback are disabled, and public target
fields reject URI/conninfo syntax. Only a
keyed fingerprint and opaque internal handle reach SQLite; handles are omitted
from CLI/API views and literal material is redacted from driver observations.
Missing or changed retained versions quarantine cleanup.

The fingerprint HMAC key is stored separately in the ignored,
current-user-owned <code>0600 .acp/driver.key</code>, never in SQLite. Protect
backups created by older ACP versions whose database and key previously
co-resided.

Descriptor delivery reduces accidental disclosure but does not stop a hostile
process with the same OS identity from inspecting ACP memory, the credential
store, or open descriptors through host debugging interfaces. Use separate
container/OS identities and a root- or supervisor-owned private credential
store when candidate code is untrusted. Credential versions must remain
available until every referencing attempt has proved teardown.

Restart is single-owner and generation-fenced. A kernel lifetime lock is held
by the supervisor and inherited by every trusted driver process, so
<code>--recover</code> refuses takeover while any old executor capable of a side
effect remains alive. The database lease determines when recovery may be
attempted; it never overrides the kernel liveness proof. Container/cgroup
supervision or a provider-native fenced gateway is still recommended for
host-loss and distributed deployments where a local file lock is unavailable.

The local event hash chain detects missing or modified records but is not
tamper-proof against a database administrator who can rewrite and recompute the
chain. Export chain heads to an independent append-only store when that threat
matters.

## Supported versions

Security fixes are applied to the latest commit on `main`. No released version
is currently covered by a long-term support policy.

## Report a vulnerability

Please use GitHub's private vulnerability reporting for this repository:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**.
3. Include affected versions, reproduction steps, impact, and a suggested fix if
   available.

Do not open a public issue for an undisclosed vulnerability. Maintainers will
acknowledge a complete report, investigate it, and coordinate disclosure through
the private advisory.

## High-value review areas

- mandate or policy bypass;
- delegation that expands authority;
- approval replay;
- stale fencing-token acceptance;
- double claims or resource-lease races;
- duplicate runtime allocation, unsafe environment-variable override, cleanup
  races, or premature port reuse;
- candidate-controlled lifecycle hooks or teardown that reports success while
  external state remains;
- worker self-approval;
- undeclared Git writes, path traversal, or symlink escape;
- QC that observes the wrong or mutable commit;
- arbitrary code execution through untrusted QC configuration;
- trust-helper substitution, source/destination symlink races, mutable bundle
  parents, non-atomic rotation, or deletion/fallback of a pinned old bundle;
- side-effect target aliasing, idempotency bypass, stale/cross-task fencing,
  provider calls before admission, or secrets exposed through receipts;
- audit-chain corruption or evidence replacement;
- authentication, injection, or denial-of-service flaws; and
- secrets committed to the repository or logs.
