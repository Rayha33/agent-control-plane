# The production platform, runnable before pushing.
#
# `acp run` supervises workers with a Linux child subreaper and /proc; macOS fails
# closed and refuses supervised workers. That means 16 tests skip on a Mac, and the
# code path the README sells was only ever exercised by GitHub CI — every iteration
# on the monitor/subreaper/quarantine code was a push-and-wait cycle.
#
# Build context is this directory; the repository is supplied at run time by
# scripts/test-linux.sh, so an edited working tree is tested, not just HEAD.

FROM python:3.12-slim

# git: the supervisor shells out to it and requires a root-owned executable, which
#   is what the distro package gives us here.
# procps: the subreaper tests inspect /proc for descendants.
# ca-certificates: uv resolves over TLS.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        procps \
    && rm -rf /var/lib/apt/lists/*

# From PyPI rather than a second registry: this image already depends on PyPI being
# reachable, and adding ghcr.io would add a failure mode for no benefit.
RUN pip install --no-cache-dir uv

# Keep the virtualenv off the bind-mounted source so a host .venv built for another
# platform is never consulted, and nothing in the container writes into the repo.
ENV UV_PROJECT_ENVIRONMENT=/opt/acp-venv \
    UV_LINK_MODE=copy \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_SYSTEM=/dev/null

# Run as a normal user. ACP's trust checks ask whether things are owned or writable
# by someone other than the caller, and root satisfies far too many of those
# questions by accident — a suite run as root can pass checks that would fail for the
# operator it is meant to protect.
RUN useradd --create-home --uid 1000 acp \
    && mkdir -p /work /opt/acp-venv \
    && chown -R acp:acp /work /opt/acp-venv
USER acp
WORKDIR /work
