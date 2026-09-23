import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest_plugins = ["pytester"]


@pytest.fixture
def worker_gate(pytester, monkeypatch):
    """Exercise the real hooks in a fresh pytest process, not a hook simulation."""
    monkeypatch.setenv("ACP_REQUIRE_LINUX_WORKER", "1")
    # These nested sessions run one synthetic test and are expected to exit OK, so no
    # execution gate from the OUTER run may leak in through the environment. The linux
    # worker gate is set explicitly above; the PostgreSQL gate (board #568) is cleared
    # here for the same reason — inherited, it would fail every nested session.
    monkeypatch.delenv("ACP_REQUIRE_POSTGRES", raising=False)
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


@pytest.mark.parametrize("setting, expected", [(None, "1"), ("1", "1"), ("0", "0")])
@pytest.mark.parametrize("docker_exit", [0, 23])
def test_linux_script_threads_explicit_gate_into_docker(tmp_path, setting, expected, docker_exit):
    """Verify shell argument wiring; this deliberately does not claim to run Docker."""
    docker = tmp_path / "docker"
    docker.write_text(
        '#!/bin/sh\nif [ "$1" = run ]; then\n'
        '    printf "%s\\n" "$@"\n    exit "$ACP_DOCKER_EXIT"\nfi\n'
    )
    docker.chmod(0o700)
    environment = dict(os.environ, PATH=f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    environment.pop("ACP_REQUIRE_LINUX_WORKER", None)
    if setting is not None:
        environment["ACP_REQUIRE_LINUX_WORKER"] = setting
    environment["ACP_DOCKER_EXIT"] = str(docker_exit)
    script = Path(__file__).resolve().parents[1] / "scripts" / "test-linux.sh"
    result = subprocess.run(
        ["sh", str(script), "-k", "subreaper or duplicate_run"],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == docker_exit
    arguments = result.stdout.splitlines()
    assert arguments[arguments.index("-e") + 1] == f"ACP_REQUIRE_LINUX_WORKER={expected}"
    assert arguments[-2:] == ["-k", "subreaper or duplicate_run"]
    assert "--init" in arguments
    assert arguments[arguments.index("-v") + 1].endswith(":/src:ro")
    assert ("NOT full Linux worker acceptance" in result.stderr) == (expected == "0")


@pytest.mark.parametrize("setting", ["", "typo", "true", " 1"])
def test_linux_script_rejects_invalid_gate_setting(tmp_path, setting):
    marker = tmp_path / "docker-invoked"
    docker = tmp_path / "docker"
    docker.write_text('#!/bin/sh\nprintf called > "$ACP_DOCKER_PROBE"\n')
    docker.chmod(0o700)
    script = Path(__file__).resolve().parents[1] / "scripts" / "test-linux.sh"
    result = subprocess.run(
        ["sh", str(script)],
        env=dict(
            os.environ,
            PATH=f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
            ACP_REQUIRE_LINUX_WORKER=setting,
            ACP_DOCKER_PROBE=str(marker),
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "ACP_REQUIRE_LINUX_WORKER must be 0 or 1" in result.stderr
    assert not marker.exists()
