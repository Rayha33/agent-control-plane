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
run flags were measured, not guessed, and both are load-bearing:

- **`--init`.** Without a reaping PID 1, a process ACP `SIGKILL`s stays a zombie with
  the same `/proc` start time, the identity check still matches, and the containment
  tests fail with *"command survived unexpected kernel monitor termination"*.
- **A non-root user.** As root, `test_run_trusted_revalidates_immediately_before_exec`
  passes when it should fail — root satisfies ownership and permission questions the
  check exists to ask.

Set `ACP_REQUIRE_LINUX_WORKER=1` and a skipped `linux_worker` test becomes a failure.
CI sets it on the Linux jobs, so a runner image that lost `/proc` or subreaper support
fails loudly instead of going green having tested nothing. The script sets it for you.

One test, `test_merge_renames_setting_matches_porcelain_merge`, compares ACP's merge
against porcelain `git merge` and its expected outcome depends on the ambient Git
version: it passes on Git 2.50.1 and fails on 2.47.3. If it is your only failure,
check `git --version` before assuming you broke something.

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
