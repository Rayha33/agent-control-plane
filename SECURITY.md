# Security Policy

Agent Control Plane is an early reference implementation. Do not treat it as a
production security boundary without the hardening described in the README and
architecture document.

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
- worker self-approval;
- audit-chain corruption or evidence replacement;
- authentication, injection, or denial-of-service flaws; and
- secrets committed to the repository or logs.
