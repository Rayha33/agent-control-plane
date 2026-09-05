# Changelog

All notable changes to Agent Control Plane.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The project is `Development Status :: 3 - Alpha` and local-first. There are no
published releases and no git tags yet — see *Releases* at the bottom before
adding one.

## [Unreleased]

### Fixed
- The HTTP app reported version `0.1.0` from two hardcoded literals in `app.py`
  while `pyproject.toml` declared `0.2.0`, so `/health` and the OpenAPI document
  both advertised a version the built artifact did not have. Version is now
  resolved once from distribution metadata (`importlib.metadata`), falling back
  to `agent_control_plane.__version__` for an uninstalled source checkout.
  (#1633)

### Added
- `tests/test_version.py` — asserts `/health` and the OpenAPI version match
  `pyproject.toml`, and scans `src/` for any reintroduced hardcoded version
  literal. Verified to fail against the pre-fix source before being accepted.
  (#1633)
- CI now runs on pushes to **every** branch. It previously triggered only on
  `main` and on pull requests, so a push to a working branch with no open PR ran
  nothing at all. (#1633)
- Coverage measurement on the Linux / Python 3.12 matrix cell, uploaded as a
  `coverage-xml` artifact. One cell only — the other cells would report the same
  numbers. (#1633)

## [0.2.0] — unreleased, current `pyproject` version

Work landed on `agent/git-work-safety-kernel` (25 commits). Grouped by theme
rather than by commit, since the branch was developed as one program:

### Added
- Git work safety kernel: worktree isolation, crash recovery and independent QC
  for agent-authored changes.
- Runner identity is cryptographic, so reviewer independence is verifiable
  rather than asserted; reviewer is auditable, ratified and calibrated.
- Trusted phase-scoped runtime drivers with cleanup proofs; per-agent runtime
  resource isolation; scoped, versioned credential handles; fenced side-effect
  gateways.
- Privileged trust-bundle rotation, hardened trust-bundle security checks, and
  trusted-executable alias resolution before `O_NOFOLLOW` open.
- Operator preview of overlap and merge order on one screen.
- Continuous integration on Linux and macOS, with pinned (SHA-hashed) actions.

### Fixed
- Worker status is bound to process identity, and worker identity survives trust
  quarantine.
- Linux double-fork regression fixture; deterministic inode-replacement and Git
  integration tests.
- `httpx2` pinned for the Starlette `TestClient` transport.

## [0.1.0]

- Initial `Release agent control plane` commit.

## Releases

No git tag exists for any version (`git tag` is empty) and nothing publishes the
wheels. `dist/` currently holds both `0.1.0` and `0.2.0` wheel+sdist pairs, built
2026-08-12 and 2026-08-31, and is gitignored. Before cutting a first real
release, decide deliberately: either wire `uv build` + `gh release create` on tag
push, or delete `dist/` and state that releases are not a thing yet. Do not tag
retroactively from this file — it was reconstructed from commit subjects, not
from a release process. (#1633)
