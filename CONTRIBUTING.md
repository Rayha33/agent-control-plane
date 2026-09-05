# Contributing

Thank you for helping make multi-agent systems safer and easier to operate.

## Start here

1. Search existing issues before opening a new one.
2. Open an issue before a large architectural change.
3. Keep pull requests focused on one behavior or control boundary.
4. Add tests for success, denial, expiry, replay, and concurrency paths where
   relevant.

## Local setup

```bash
git clone https://github.com/Rayha33/agent-control-plane.git
cd agent-control-plane
uv sync --extra dev
```

Run the same checks as CI:

```bash
uv run --extra dev ruff format --check src tests
uv run --extra dev ruff check src tests
uv run --extra dev pytest
uv build
```

Use <code>uv run --extra dev ruff format src tests</code> to apply formatting.

### Testing the Linux worker path

16 tests skip on macOS. They cover `acp run` — the Linux child-subreaper and `/proc`
path the README calls the production platform — so on a Mac they are exactly the tests
you cannot run and most need to. They carry the `linux_worker` marker
(`uv run --extra dev pytest -m linux_worker --collect-only` lists them).

Anywhere Docker is available:

```bash
scripts/test-linux.sh            # whole suite on Linux
scripts/test-linux.sh -k monitor # extra arguments go to pytest
```

It copies your working tree into the container, so uncommitted edits are tested. Two
run flags, one of which is load-bearing:

- **`--init`.** Ordinary hygiene for a container running process trees, so orphans get
  reaped. Not required by any failure that reproduces: the containment tests pass
  without it, 12 runs out of 12 in isolation and for the whole suite.
- **A non-root user.** As root, `test_run_trusted_revalidates_immediately_before_exec`
  passes when it should fail — root satisfies ownership and permission questions the
  check exists to ask.

Known: `test_command_cannot_escape_by_terminating_its_monitor` passes when you run the
suite this way, and fails when the same suite runs *under* `acp qc` — nesting the
supervisor inside itself, not a container flag. See board #1707 before chasing it.

Set `ACP_REQUIRE_LINUX_WORKER=1` and a skipped `linux_worker` test becomes a failure.
CI sets it on the Linux jobs, so a runner image that lost `/proc` or subreaper support
fails loudly instead of going green having tested nothing. The script sets it for you.

`test_merge_renames_setting_matches_porcelain_merge` reads its expectation off
porcelain rather than hardcoding one, because what `git merge` does to a rename/edit
with `merge.renames=false` differs between Git versions — it conflicts on 2.50.1 and
merges cleanly on 2.47.3. Both branches are exercised: macOS takes the first, this
container the second.

### What a QC command inherits

QC, critic, hook and driver commands run with a nine-variable environment
(`PUBLIC_CHILD_ENV` in `git_supervisor.py`): `HOME`, `LANG`, `LC_ALL`, `LOGNAME`,
`PATH`, `SHELL`, `TERM`, `TMPDIR`, `USER`. `VIRTUAL_ENV` and `PYTHONPATH` are
reserved and cannot be set from config — they would let a candidate redirect which
interpreter and which packages its own gate runs against.

`HOME` is on that list, so tool caches under it are already shared. A QC child sees
the same `uv cache dir` (`~/.cache/uv`) as you do, and installs into a fresh checkout
by hardlinking out of it.

**Do not add `UV_PROJECT_ENVIRONMENT` or a general env passthrough to make this
faster.** Measured on this repository's own tree — 102 pinned packages, warm cache:

| | |
|---|---|
| fresh `uv sync --extra dev` in a QC-shaped checkout | 0.24 s steady state (1.08 s first) |
| the venv it builds | 51 MB, deleted with the checkout |
| the QC run that follows it | ~158 s |

So the per-attempt environment costs about 0.15% of a QC run, and it is not leaking —
`_remove_worktree` takes the checkout and its `.venv` together when QC finishes.
Pointing every attempt at one shared `UV_PROJECT_ENVIRONMENT` would trade that 0.24 s
for concurrent QC runs mutating a single virtualenv, which is the isolation the fresh
detached checkout exists to provide. (Board #1701.)

## Pull requests

A pull request should include:

- the problem and intended invariant;
- the implementation approach;
- tests or other reproducible evidence;
- security and compatibility implications; and
- documentation updates for API or behavior changes.

Avoid mixing generated artifacts or unrelated refactors into the same change.
Never commit credentials, production data, private prompts, or customer
artifacts.

## Design principles

- Deny when authority or state is ambiguous.
- Prefer atomic state transitions over check-then-write sequences.
- Treat fencing tokens as write authority, not metadata.
- Preserve evidence across retries and reassignments.
- Keep the worker and its reviewer independent.
- Make crash recovery observable and auditable.
- Derive changed paths and immutable candidate evidence from Git, not workers.

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
