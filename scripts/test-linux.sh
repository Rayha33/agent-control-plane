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

# --init gives the container a reaping PID 1, which is ordinary hygiene for a container
# that runs process trees. It is NOT load-bearing for any failure I can reproduce: the
# containment tests pass without it, 12 runs out of 12 in isolation and twice for the
# whole suite. An earlier version of this comment claimed --init was required and cited
# two failures; those runs also had other tests failing, and the containment failures
# went away when those were fixed rather than when --init was added. The real
# distinguishing variable turned out to be running the suite UNDER acp qc, which still
# fails these tests on an otherwise-green suite — see board #1707.
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
