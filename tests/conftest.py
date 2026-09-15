from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from agent_control_plane.app import create_app
from agent_control_plane.config import Settings

POSTGRES_URL_ENV = "ACP_TEST_POSTGRES_URL"
REQUIRE_POSTGRES_ENV = "ACP_REQUIRE_POSTGRES"
STORAGE_BACKENDS = ("sqlite", "postgresql")


def pytest_generate_tests(metafunc) -> None:
    """Run `storage_portable` modules against every backend this run can reach.

    Without ACP_TEST_POSTGRES_URL nothing is parametrized, so node ids stay exactly what
    they were before the PostgreSQL backend existed. With it, each portable test runs once
    per backend, and the terminal summary says how many PostgreSQL runs actually passed.
    """

    if "storage_backend" not in metafunc.fixturenames:
        return
    if metafunc.definition.get_closest_marker("storage_portable") is None:
        return
    if not os.getenv(POSTGRES_URL_ENV):
        return
    metafunc.parametrize("storage_backend", STORAGE_BACKENDS, indirect=True)


@pytest.fixture
def storage_backend(request) -> str:
    return getattr(request, "param", "sqlite")


@pytest.fixture
def postgres_url(request):
    """A private schema on the test server, dropped afterwards. Skips without a server.

    Reaching the `yield` is the ONLY true evidence that a test talked to a live PostgreSQL,
    so that is where the execution gate's set is filled. Counting by marker or module name
    instead measures the wrong object: every test in `test_postgres_backend.py` carries
    `postgres_backend` among its keywords, including the translation tests that need no
    server, so `ACP_REQUIRE_POSTGRES=1` passed on CI — which has no server at all — and the
    summary line claimed "1 tests passed against a live server".
    """

    base = os.getenv(POSTGRES_URL_ENV)
    if not base:
        pytest.skip(f"PostgreSQL backend not exercised: set {POSTGRES_URL_ENV}")
    from pg_support import postgres_schema

    with postgres_schema(base) as url:
        _used_postgres.add(request.node.nodeid)
        yield url


@pytest.fixture
def app(tmp_path, storage_backend, request):
    database_path = str(tmp_path / "test.db")
    if storage_backend == "postgresql":
        database_path = request.getfixturevalue("postgres_url")
    settings = Settings(
        database_path=database_path,
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
_passed_postgres: set[str] = set()
# Node ids that actually reached a live PostgreSQL, filled by the `postgres_url` fixture.
_used_postgres: set[str] = set()


def _exercises_postgres(report) -> bool:
    return report.nodeid in _used_postgres


def pytest_sessionstart(session) -> None:
    # pytest.main() can run more than once in one process. Never let an earlier
    # run's passes satisfy this run's execution gate (or its skips fail it).
    _passed_postgres.clear()
    _used_postgres.clear()
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
    if report.when == "call" and report.passed and _exercises_postgres(report):
        _passed_postgres.add(report.nodeid)


def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:
    """Say what did not run, always.

    A skip is invisible in `-q` output beyond a single `s`, so a platform gate that
    silently stopped matching would look exactly like a passing run.
    """

    # Always said, pass or fail: a backend that silently stopped being exercised would
    # otherwise look exactly like a green run on both.
    if _passed_postgres:
        terminalreporter.write_line(
            f"postgresql backend: {len(_passed_postgres)} tests passed against a live server"
        )
    elif os.getenv(POSTGRES_URL_ENV):
        # The server is configured, so the reason is the selection, not the environment.
        terminalreporter.write_line(
            "postgresql backend: NOT exercised — this session selected no PostgreSQL test"
        )
    else:
        terminalreporter.write_line(
            f"postgresql backend: NOT exercised (set {POSTGRES_URL_ENV} to a scratch server)"
        )
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

    if os.getenv(REQUIRE_POSTGRES_ENV) == "1" and not _passed_postgres:
        reason = (
            "this session selected no PostgreSQL test"
            if os.getenv(POSTGRES_URL_ENV)
            else f"{POSTGRES_URL_ENV} is not set"
        )
        print(f"\n{REQUIRE_POSTGRES_ENV}=1: no test passed against PostgreSQL — {reason}")
        if session.exitstatus == pytest.ExitCode.OK:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED

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
