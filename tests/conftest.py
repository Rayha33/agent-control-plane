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
_selected_linux_worker: set[str] = set()
_deselected_linux_worker: set[str] = set()
_passed_linux_worker: set[str] = set()


def pytest_sessionstart(session) -> None:
    # pytest.main() can run more than once in one process. Never let an earlier
    # run's passes satisfy this run's execution gate (or its skips fail it).
    _skipped.clear()
    _skipped_linux_worker.clear()
    _selected_linux_worker.clear()
    _deselected_linux_worker.clear()
    _passed_linux_worker.clear()


def pytest_collection_finish(session) -> None:
    _selected_linux_worker.update(
        item.nodeid for item in session.items if item.get_closest_marker("linux_worker")
    )


def pytest_deselected(items) -> None:
    _deselected_linux_worker.update(
        item.nodeid for item in items if item.get_closest_marker("linux_worker")
    )


def pytest_runtest_logreport(report) -> None:
    if report.skipped:
        reason = str(getattr(report, "wasxfail", ""))
        if isinstance(report.longrepr, tuple) and len(report.longrepr) == 3:
            reason = str(report.longrepr[2]).removeprefix("Skipped: ")
        _skipped.append((report.nodeid, reason))
        if "linux_worker" in report.keywords:
            _skipped_linux_worker.append((report.nodeid, reason))
    if report.when == "call" and report.passed and "linux_worker" in report.keywords:
        _passed_linux_worker.add(report.nodeid)


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
    """Fail a run that promised to exercise the Linux worker path but did not.

    `acp run` supervises workers through a Linux child subreaper and /proc; those
    tests skip everywhere else. On a Linux runner they must actually execute — if a
    future image lost /proc or subreaper support, every one of them would skip and CI
    would stay green while the path the README sells went untested. Set
    ACP_REQUIRE_LINUX_WORKER=1 there and a skip in any phase becomes a failure,
    including xfail. Every selected worker test must reach a passing call phase;
    an empty selection, deselection, or collect-only run cannot satisfy the gate.

    Only tests carrying the `linux_worker` marker count. Measured on Linux: exactly
    one test skips there legitimately — a Darwin-specific fail-closed contract — so
    "assert zero skips" would be a control that cries wolf on every green run.
    """

    if os.getenv(REQUIRE_LINUX_WORKER_ENV) != "1":
        return
    problems = []
    if not _selected_linux_worker:
        problems.append("no linux_worker tests were selected")
    for nodeid in sorted(_deselected_linux_worker):
        problems.append(f"{nodeid}: required worker test was deselected")
    for nodeid, reason in _skipped_linux_worker:
        problems.append(f"{nodeid}: skipped: {reason}")
    for nodeid in sorted(_selected_linux_worker - _passed_linux_worker):
        problems.append(f"{nodeid}: required worker test did not pass its call phase")
    if not problems:
        return
    print(f"\n{REQUIRE_LINUX_WORKER_ENV}=1: Linux worker execution gate failed:")
    for problem in problems:
        print(f"  {problem}")
    # Keep collection errors, interrupts and other nonzero pytest diagnoses intact.
    if session.exitstatus == pytest.ExitCode.OK:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
