# Changelog

All notable changes to Agent Control Plane.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The project is `Development Status :: 3 - Alpha` and local-first. There are no
published releases and no git tags yet — see *Releases* at the bottom before
adding one.

## [Unreleased]

### Security
- `Settings.from_env()` defaulted `admin_key` to the published `dev-admin-key` and
  `signing_key` to a published development key, and `create_app()` calls it whenever
  given no settings — so starting the server with nothing exported produced an API
  administered by a string printed in the README. It now raises
  `InsecureSettingsError` on unset, published-dev, or under-length signing keys,
  reporting every problem at once. `ACP_INSECURE_DEV=1` opts back in explicitly and
  `/health` then reports `"auth": "insecure-dev"` instead of `"enforced"`. (#1624)
- `acp guard` refuses a write outside the attempt's worktree or outside the task's
  declared write set, using the same `_path_matches` that `submit` applies to the
  diff. `acp hooks install --claude-code` puts it in front of Claude Code's
  file-editing tools, closing the gap *Honest boundaries* described: an agent editing
  the base checkout defeated every claim and fence without ACP noticing. `Bash` is
  deliberately not guarded — what a shell command writes cannot be read off the
  command string, and a pattern that can be walked around by rephrasing would read as
  coverage without being any. (#1627)

### Added
- `meta.schema_version` and `meta.written_by`. A control database newer than the
  binary is refused with `schema_newer_than_binary` rather than opened — previously
  an older acp opened it successfully and simply did not see the newer columns, so a
  critic on an older contract could approve what the newer contract rejects. A
  numbered `MIGRATIONS` ledger carries changes after version 1 and can express
  indexes, renames and backfills, which the `ALTER TABLE ADD COLUMN` pattern could
  not. `acp migrate` upgrades a database; `acp doctor` reports its version against
  the binary's. (#1629)
- `acp gc [--dry-run] [--older-than 7d]` reclaims the worktree and task branch of
  attempts nothing is using. A completed task previously left its worktree, its
  `git worktree` registration and its branch on disk indefinitely. It refuses, in
  order, a worktree whose task is active, whose attempt is live or quarantined, whose
  cleanup is unproven, that holds a resource lease or runtime allocation, or that is
  inside the retention window; integration branches are reported and never deleted.
  `acp status` gained a `disk` section computed by the same survey. (#1628)
- `scripts/test-linux.sh` and `tests/linux/Dockerfile` run the suite on the Linux
  worker path from any host with Docker — 16 tests covering `acp run` skip everywhere
  else. `ACP_REQUIRE_LINUX_WORKER=1` turns a skipped `linux_worker` test into a
  failure and CI sets it on the Linux jobs, so a runner image that lost `/proc` or
  child-subreaper support fails loudly instead of going green having tested nothing.
  pytest now also prints what it skipped and why on every run. (#1631)
- `acp mcp-serve` — a read-only, credential-free, dependency-free MCP server over
  stdio exposing ten look-only tools. Writes are deliberately absent: authenticated
  operations need a runner credential, and a long-lived server holding one (let alone
  two roles') would erase the worker/critic/integrator separation. It opens
  `read_only=True` per call, so a database needing migration is reported rather than
  silently upgraded. (#1703)
- The service database is versioned too, from one shared implementation
  (`schema_version.py`). The two databases version independently. (#1700)
- `tasks.declared_resources_json` keeps the write set as the operator typed it.
  `normalize_resource` casefolds and that folded string is the `resource_leases`
  PRIMARY KEY, so the stored form cannot carry capitalisation without rewriting lease
  identity; a separate column carries it for display only, and matching stays
  case-insensitive. Schema version 2, the migration ledger's first entry. (#1708)
- `docs/INTEGRATIONS.md`. (#1627)

### Changed
- Read-only commands (`status`, `show`, `plan`, `queue`, `merge-plan`, `reviewers`,
  `bundle`, `verify-events`, `guard`) open the database `mode=ro` and never migrate
  it, making *Planning is a preview, never a mutation* structural rather than a matter
  of discipline. Constructing the supervisor previously ran `CREATE TABLE IF NOT
  EXISTS` and every pending `ALTER TABLE` before the first `SELECT`, so `acp status`
  on a database written by an older acp rewrote its schema. `list` is excluded because
  `list_tasks()` reaps, and `doctor` because it must be able to open a database that
  needs upgrading in order to report it. (#1629)

### Fixed
- `acp guard --hook` failed OPEN. A PreToolUse hook blocks on exit 2 and any other
  non-zero exit is treated as a hook error and stepped past, so the CLI's generic
  `return 1` for `SupervisorError` was an ALLOW: a missing `ACP_ATTEMPT_ID`, an
  unopenable repository, or `schema_upgrade_required` all waved the write through.
  The last is the dangerous one — read-only commands refuse to migrate, so a single
  `SCHEMA_VERSION` bump would return it for every hook on every machine at once. Hook
  mode now exits 2 whenever it cannot decide; non-hook `guard` keeps exit 1.
- Path traversal in `acp bundle`. `read_bundle` interpolated the caller's `qc_id`
  straight into `state_dir/bundles/<id>.json`, so `acp bundle '../../outside'` read and
  printed any reachable `.json`. It only worked once `.acp/bundles/` existed, which is
  why it looked like a correct `bundle_not_found` on a fresh repository. The id is now
  checked as a uuid4 AND the resolved path asserted to sit in the bundles directory.
- A denied fork is recorded against the host, not the candidate. Under the Darwin
  no-fork sandbox a QC command that forks never runs, and ACP wrote a signed verdict
  reading `required_fix: fix the failure and submit a new committed attempt` — blaming
  a worker for the host. The finding now says the command could not run here and that
  the work is not at fault. Recognised by exit 128 AND `fork: Operation not permitted`,
  because a missing binary exits 127 with fork fully available.
- `test_merge_renames_setting_matches_porcelain_merge` read its expectation off
  porcelain instead of hardcoding a conflict, which differs between Git versions
  (2.50.1 conflicts, 2.47.3 merges cleanly). When both merge, the trees must match —
  a stronger claim than agreeing on a conflict.
- `acp.toml` and `runtime_drivers.py` documented `/bin/sh -lc`; the code runs
  `/bin/sh -c`. A login shell reads `~/.profile`, so the comment could send an
  operator debugging against the wrong shell.
- A failed QC command's finding built its evidence from `stderr or stdout`, so stdout
  was read only when stderr was empty. Every mainstream test runner reports failures
  on stdout while writing something incidental to stderr, so the finding routinely
  kept the incidental half and discarded the diagnosis — one real run reported
  "Creating virtual environment at: .venv / Installed 35 packages" as the entire
  evidence for a suite that had named two failing tests. Evidence now carries both
  streams, labelled, stdout first, truncated with both ends kept and the gap marked.
  (#1706)

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
