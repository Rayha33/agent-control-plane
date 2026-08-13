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

Runtime port pools prevent two cooperating ACP attempts from receiving the same
configured TCP port. They are not kernel reservations: an unrelated local
process can race the availability probe. ACP quarantines a port that remains
occupied after teardown. Built-in drivers prove cleanup of their declared
Compose project, PostgreSQL schema, or browser profile; ACP cannot prove
undeclared cloud or application side effects. Use provider-native
deletion/fencing for those resources.

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
private file or descriptor rather than JSON. PostgreSQL driver DSNs stay out of
argv and are redacted from evidence; drivers require <code>dsn_env</code> and
reject literal DSNs in tracked configuration.

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
- audit-chain corruption or evidence replacement;
- authentication, injection, or denial-of-service flaws; and
- secrets committed to the repository or logs.
