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
- On a case-sensitive filesystem, a task declaring `Makefile` was ALLOWED by `acp
  guard` to write `makefile`, and `submit` accepted a diff touching it: the declared
  resource is stored casefolded and both checks casefolded the candidate to match, so
  two distinct files answered to one declaration. That is an undeclared write passing
  the exact check the guard and `submit` exist to enforce. Both now match by the
  measured case sensitivity of the volume, against the declared capitalisation kept in
  `declared_resources_json`. Case-INSENSITIVE volumes are unchanged and still match
  either spelling, because there `README.md` and `readme.md` are one file and denying
  the second would deny an agent the file it leased. Lease identity is deliberately
  untouched and stays folded: making the two cases two leases would let two attempts
  hold exclusive claims on one file wherever the filesystem does not distinguish them,
  so overlap keeps over-blocking, which fails closed. A task predating
  `declared_resources_json` has no recoverable capitalisation and keeps case-insensitive
  matching rather than being denied its own declared write. (#1708)

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
  (The workflow half of that sentence is not live yet — see the CI note under
  #1633 below: the workflow file cannot be pushed from this machine.)
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
  identity; a separate column carries it for display. Schema version 2, the migration
  ledger's first entry. (#1708)
- `meta.path_case_sensitive`, measured once against the volume `.acp` sits on rather
  than guessed from `sys.platform` — a case-sensitive APFS volume on macOS and a
  case-insensitive volume on Linux both exist. Absent means not yet measured and reads
  as case-insensitive, so an existing database keeps its previous matching until the
  next command that opens it for writing. (#1708)
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
  numbers. Local baseline at the time of writing: 80% overall,
  `git_supervisor.py` 82%, with `critic.py` and `trust_helper.py` at 0% and
  `worker_trampoline.py` at 13%. (#1633)
- CI sets `ACP_REQUIRE_LINUX_WORKER` on the Linux cells. `tests/conftest.py`
  has implemented this switch — a skipped `linux_worker` test becomes a failure —
  since the worker work landed, but no workflow ever set it, so the mechanism
  was inert and the Linux job would have stayed green with the whole `acp run`
  path silently skipped. Measuring coverage over silently-skipped tests would
  have put a number on the wrong object. (#1633)

  🔴 **These three CI entries describe a workflow file that is NOT on this
  branch and NOT what GitHub is running.** Pushing any file under
  `.github/workflows/` from this machine is refused — `refusing to allow an
  OAuth App to create or update workflow ... without 'workflow' scope`; the
  token carries `gist`, `read:org`, `repo`. The change is therefore parked on
  the local branch `ci/workflow-1633-needs-scope` (one commit on top of this
  one, touching `ci.yml` only) rather than committed here, so that this branch
  stays pushable — committing it here once left the branch permanently one
  commit ahead and the next session had to rebuild the branch by cherry-pick to
  land anything else. The remote still carries `push: branches: [main]`, no
  `ACP_REQUIRE_LINUX_WORKER`, and no coverage step, and every CI run on this
  branch to date has `event: pull_request`. To land it:

  ```
  gh auth refresh -s workflow
  git cherry-pick ci/workflow-1633-needs-scope
  git push origin agent/git-work-safety-kernel
  ```

  Do not read these entries as describing production CI until that is done.

## [0.2.0] — unreleased, current `pyproject` version

Work landed on `agent/git-work-safety-kernel` (25 commits). Grouped by theme
rather than by commit, since the branch was developed as one program. Board task
ids are given so the single 40-commit pull request can be read against the work
that was actually requested:

### Added
- Git work safety kernel: worktree isolation, crash recovery and independent QC
  for agent-authored changes. (#1043)
- Runner identity is cryptographic, so reviewer independence is verifiable
  rather than asserted; reviewer is auditable, ratified and calibrated. (#569)
- Trusted phase-scoped runtime drivers with cleanup proofs (#564); container and
  network-namespace runtime backend with quotas (#567, disk quota descoped by
  #863 — `io` is not a delegated cgroup controller); scoped, versioned
  credential handles replacing environment secrets (#739); fenced side-effect
  gateways for database, deploy and artifact operations (#741).
- Privileged trust-bundle installer and atomic rotation (#738), hardened
  trust-bundle security checks, and trusted-executable alias resolution before
  `O_NOFOLLOW` open.
- Quarantine explain, recovery and legacy migration workflow. (#740)
- Operator status view for parallel-agent attention management (#565) and
  operator preview of overlap and merge order on one screen (#566).
- Continuous integration on Linux and macOS, with actions pinned to immutable
  Node 24-compatible releases by SHA. (#1363)

### Fixed
- Worker status is bound to process-start identity (#1436), and registered
  worker identity is preserved and terminated correctly during trust
  quarantine. (#1143)
- The macOS Git integration subprocess trust gap. (#1144)
- QC configs invoked bare `python`, which does not exist on macOS, so the suite
  was red there for a purely environmental reason. The default config template
  now derives the interpreter from `sys.executable` rather than hardcoding any
  name. (#864)
- Linux double-fork regression fixture; deterministic inode-replacement and Git
  integration tests.
- The Starlette `TestClient` deprecation warning, by pinning `httpx2` in the dev
  extra so `TestClient` uses the supported transport, and promoting the warning
  to an error so dropping that pin fails the suite instead of going quiet.
  (#1592)

## [0.1.0]

- Initial `Release agent control plane` commit.

## Releases

**There are no releases, and that is the decision, not an omission.** No git tag
exists for any version (`git tag` is empty), nothing publishes the wheels, and
nothing will until the project has a consumer that is not this repository.

`dist/` used to hold `0.1.0` and `0.2.0` wheel+sdist pairs side by side, built
2026-08-12 and 2026-08-31. The stale `0.1.0` pair was deleted: it was pre-fix
code — including the version drift this task is named for — sitting under a glob
that `pip install dist/*.whl` resolves by sort order, so the older artifact was
installable by accident. `dist/` is gitignored build output and `uv build`
regenerates it in seconds, so nothing was lost.

Publishing was considered and rejected for now. A release pipeline needs a
registry credential or a trusted-publisher binding, which is a real supply-chain
surface, and this is a `Development Status :: 3 - Alpha` local-first project with
one open pull request and no downstream users. CI already runs `uv build` on
every push, so the package is continuously proven buildable without a release
process existing. When a first external consumer appears, wire `uv build` +
`gh release create` on tag push then — and do not tag retroactively from this
file, which was reconstructed from commit subjects rather than from releases.
(#1633)
