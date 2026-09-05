from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from agent_control_plane.app import create_app
from agent_control_plane.config import Settings


@pytest.fixture
def app(tmp_path):
    settings = Settings(
        database_path=str(tmp_path / "test.db"),
        admin_key="test-admin",
        signing_key="test-signing-key-with-enough-entropy",
        issuer="test-control-plane",
    )
    return create_app(settings)


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def admin_headers():
    return {"X-Control-Plane-Key": "test-admin"}


REQUIRE_LINUX_WORKER_ENV = "ACP_REQUIRE_LINUX_WORKER"

_skipped: list[tuple[str, str]] = []
_skipped_linux_worker: list[tuple[str, str]] = []


def pytest_runtest_logreport(report) -> None:
    if report.skipped and report.when == "setup":
        reason = ""
        if isinstance(report.longrepr, tuple) and len(report.longrepr) == 3:
            reason = str(report.longrepr[2]).removeprefix("Skipped: ")
        _skipped.append((report.nodeid, reason))
        if "linux_worker" in report.keywords:
            _skipped_linux_worker.append((report.nodeid, reason))


def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:
    """Say what did not run, always.

    A skip is invisible in `-q` output beyond a single `s`, so a platform gate that
    silently stopped matching would look exactly like a passing run.
    """

    if not _skipped:
        return
    terminalreporter.write_sep("-", f"{len(_skipped)} skipped")
    for nodeid, reason in _skipped:
        terminalreporter.write_line(f"  {nodeid}: {reason}")


def pytest_sessionfinish(session, exitstatus) -> None:
    """Fail a run that promised to exercise the Linux worker path and then skipped it.

    `acp run` supervises workers through a Linux child subreaper and /proc; those
    tests skip everywhere else. On a Linux runner they must actually execute — if a
    future image lost /proc or subreaper support, every one of them would skip and CI
    would stay green while the path the README sells went untested. Set
    ACP_REQUIRE_LINUX_WORKER=1 there and a skip becomes a failure.

    Only tests carrying the `linux_worker` marker count. Measured on Linux: exactly
    one test skips there legitimately — a Darwin-specific fail-closed contract — so
    "assert zero skips" would be a control that cries wolf on every green run.
    """

    if os.getenv(REQUIRE_LINUX_WORKER_ENV) != "1" or not _skipped_linux_worker:
        return
    print(
        f"\n{REQUIRE_LINUX_WORKER_ENV}=1 was set, but "
        f"{len(_skipped_linux_worker)} Linux worker test(s) skipped.\n"
        "This run promised to exercise the Linux worker path and did not:"
    )
    for nodeid, reason in _skipped_linux_worker:
        print(f"  {nodeid}: {reason}")
    session.exitstatus = 1
