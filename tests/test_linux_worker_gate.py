import sys
from pathlib import Path

import pytest

pytest_plugins = ["pytester"]


@pytest.fixture
def worker_gate(pytester, monkeypatch):
    """Exercise the real hooks in a fresh pytest process, not a hook simulation."""
    monkeypatch.setenv("ACP_REQUIRE_LINUX_WORKER", "1")
    pytester.makeconftest(Path(__file__).with_name("conftest.py").read_text())
    pytester.makeini("[pytest]\nmarkers = linux_worker: required worker test\n")
    return pytester


@pytest.mark.parametrize(
    "source",
    [
        "@pytest.mark.skip(reason='setup unavailable')\ndef test_worker(): pass",
        "def test_worker(): pytest.skip('runtime unavailable')",
        (
            "@pytest.fixture\ndef resource():\n"
            "    yield\n"
            "    pytest.skip('teardown unavailable')\n"
            "def test_worker(resource): pass"
        ),
        "@pytest.mark.xfail(reason='worker unavailable')\ndef test_worker(): assert False",
    ],
    ids=["setup-skip", "call-skip", "teardown-skip", "xfail"],
)
def test_required_worker_cannot_skip_in_any_phase(worker_gate, source):
    worker_gate.makepyfile("import pytest\npytestmark = pytest.mark.linux_worker\n" + source)
    result = worker_gate.runpytest_subprocess("-q")
    assert result.ret == pytest.ExitCode.TESTS_FAILED
    result.stdout.fnmatch_lines(["*ACP_REQUIRE_LINUX_WORKER=1*", "*test_worker*"])


def test_required_gate_rejects_no_selected_workers(worker_gate):
    worker_gate.makepyfile("def test_ordinary(): pass")
    result = worker_gate.runpytest_subprocess("-q")
    assert result.ret == pytest.ExitCode.TESTS_FAILED
    result.stdout.fnmatch_lines(["*no linux_worker tests were selected*"])


def test_required_gate_rejects_deselected_workers(worker_gate):
    worker_gate.makepyfile(
        "import pytest\n"
        "@pytest.mark.linux_worker\ndef test_worker(): pass\n"
        "def test_ordinary(): pass\n"
    )
    result = worker_gate.runpytest_subprocess("-q", "-m", "not linux_worker")
    assert result.ret == pytest.ExitCode.TESTS_FAILED


def test_required_gate_rejects_collection_only(worker_gate):
    worker_gate.makepyfile("import pytest\n@pytest.mark.linux_worker\ndef test_worker(): pass")
    result = worker_gate.runpytest_subprocess("--collect-only", "-q")
    assert result.ret == pytest.ExitCode.TESTS_FAILED


def test_required_gate_rejects_partial_worker_deselection(worker_gate):
    worker_gate.makepyfile(
        "import pytest\npytestmark = pytest.mark.linux_worker\n"
        "def test_worker_one(): pass\ndef test_worker_two(): pass"
    )
    result = worker_gate.runpytest_subprocess("-q", "-k", "one")
    result.assert_outcomes(passed=1, deselected=1)
    assert result.ret == pytest.ExitCode.TESTS_FAILED
    result.stdout.fnmatch_lines(["*test_worker_two: required worker test was deselected*"])


def test_required_workers_can_pass_with_unrelated_platform_skip(worker_gate):
    worker_gate.makepyfile(
        "import pytest\n"
        "@pytest.mark.linux_worker\ndef test_worker(): pass\n"
        "@pytest.mark.skip(reason='other platform')\ndef test_other_platform(): pass\n"
    )
    result = worker_gate.runpytest_subprocess("-q")
    result.assert_outcomes(passed=1, skipped=1)
    assert result.ret == pytest.ExitCode.OK


@pytest.mark.parametrize("setting", [None, "0"])
def test_optional_gate_allows_platform_skip(worker_gate, monkeypatch, setting):
    if setting is None:
        monkeypatch.delenv("ACP_REQUIRE_LINUX_WORKER", raising=False)
    else:
        monkeypatch.setenv("ACP_REQUIRE_LINUX_WORKER", setting)
    worker_gate.makepyfile(
        "import pytest\n@pytest.mark.linux_worker\ndef test_worker(): pytest.skip('other platform')"
    )
    result = worker_gate.runpytest_subprocess("-q")
    result.assert_outcomes(skipped=1)
    assert result.ret == pytest.ExitCode.OK


def test_required_gate_preserves_collection_error_exit_code(worker_gate):
    worker_gate.makepyfile("raise RuntimeError('collection failed')")
    result = worker_gate.runpytest_subprocess("-q")
    assert result.ret == pytest.ExitCode.INTERRUPTED


def test_previous_pytest_session_cannot_satisfy_worker_gate(worker_gate):
    worker_gate.makepyfile(test_sample="def test_ordinary(): pass")
    script = worker_gate.makepyfile(
        run_twice="""
        import pytest

        class OneWorker:
            def pytest_collection_modifyitems(self, items):
                item = pytest.Function.from_parent(
                    items[0].parent, name="test_worker", callobj=lambda: None
                )
                item.add_marker("linux_worker")
                items[:] = [item]

        first = pytest.main(["-q"], plugins=[OneWorker()])
        second = pytest.main(["-q"])
        assert first == pytest.ExitCode.OK, first
        assert second == pytest.ExitCode.TESTS_FAILED, second
        """
    )
    result = worker_gate.run(sys.executable, str(script))
    assert result.ret == 0
    result.stdout.fnmatch_lines(["*no linux_worker tests were selected*"])
