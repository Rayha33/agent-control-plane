#!/bin/sh
# Run the suite on the production platform, from any machine with Docker.
#
#   scripts/test-linux.sh                 # whole suite
#   scripts/test-linux.sh -k subreaper    # extra args go to pytest
#
# Why this exists: 16 tests skip on macOS because supervised workers need a Linux
# child subreaper and /proc. Those 16 cover `acp run` — the path the README calls the
# production platform — so on a Mac they were only ever exercised by GitHub CI.
#
# The working tree is copied into the container rather than bind-mounted read-write,
# so an uncommitted edit IS tested while nothing in the container can write into the
# repository (a root-owned .venv or .acp appearing in your checkout would be a nasty
# parting gift). .venv is excluded because a host virtualenv is built for the host's
# platform, and .acp because container state must not inherit a half-finished attempt.

set -eu

IMAGE=acp-linux-tests
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if ! command -v docker >/dev/null 2>&1; then
    echo "test-linux: docker is required; this is the point of the script." >&2
    echo "  No Docker locally? Run it on any Linux host with the repo synced there." >&2
    exit 127
fi

docker build -t "$IMAGE" "$REPO/tests/linux" >/dev/null

# --init is required, not optional. Without a reaping PID 1, a process ACP SIGKILLs
# stays a zombie: its /proc entry keeps the same start time, so the identity check
# still matches and the containment assertion fails with "command survived unexpected
# kernel monitor termination". Measured — it is the difference between two failures
# and none. tini does not conflict with the supervisor's own child-subreaper role;
# it only reaps what re-parents all the way up to PID 1.
exec docker run --rm --init \
    -v "$REPO:/src:ro" \
    -e ACP_REQUIRE_LINUX_WORKER=1 \
    "$IMAGE" \
    sh -c '
        set -eu
        tar -C /src -cf - \
            --exclude=./.venv \
            --exclude=./.acp \
            --exclude=./.git \
            --exclude=__pycache__ \
            --exclude=.pytest_cache \
            --exclude=.ruff_cache \
            --exclude=._\* \
            . | tar -C /work -xf -
        uv sync --extra dev --quiet
        exec uv run --extra dev pytest "$@"
    ' -- "$@"
