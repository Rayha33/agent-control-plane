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
uvx ruff format --check src tests
uvx ruff check src tests
uv run pytest
uv build
```

Use `uvx ruff format src tests` to apply formatting.

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

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
