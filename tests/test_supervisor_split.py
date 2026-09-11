"""Pin the one way a pure move out of git_supervisor.py can change behaviour silently.

Board #1630 splits git_supervisor.py into supervisor/*.py. A move is behaviour-preserving
except in one respect the rest of the suite cannot see: a MODULE-LEVEL MONKEYPATCH.

`monkeypatch.setattr(git_supervisor, "SCHEMA_VERSION", ...)` rebinds the name in
git_supervisor's namespace, and a function only sees that if it looks the name up in THAT
namespace, which means it was defined in git_supervisor.py. Move the reader into
supervisor/<phase>.py with its own import of the name and the test that patches it keeps
passing while the patch no longer reaches the code it was written to steer. Measured during
module 1: four such patch sites, and only one of them went red.

So this test finds every name the suite patches on git_supervisor and asserts that every
function reading one of those names still resolves its globals in git_supervisor.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import re
import types
from collections.abc import Callable, Iterator
from pathlib import Path

import agent_control_plane.git_supervisor as git_supervisor
import agent_control_plane.supervisor as supervisor_package

TESTS = Path(__file__).resolve().parent
ALIAS = re.compile(r"import\s+agent_control_plane\.git_supervisor\s+as\s+(\w+)")
DOTTED = re.compile(r"[\"']agent_control_plane\.git_supervisor\.(\w+)[\"']")


def patched_names() -> set[str]:
    """Names some test rebinds on the git_supervisor module itself.

    `setattr(git_supervisor.shutil, "rmtree", ...)` is not one: it patches the shared
    `shutil` module, which every importer sees. Only `setattr(<the module>, "NAME")` and the
    one-component dotted-string form rebind a git_supervisor global.
    """

    names: set[str] = set()
    for path in TESTS.rglob("*.py"):
        if path.resolve() == Path(__file__).resolve():
            continue
        text = path.read_text(encoding="utf-8")
        aliases = {"git_supervisor", *ALIAS.findall(text)}
        pattern = re.compile(
            r"setattr\(\s*(?:" + "|".join(sorted(aliases)) + r")\s*,\s*[\"'](\w+)[\"']"
        )
        names.update(pattern.findall(text))
        names.update(DOTTED.findall(text))
    return names


def _code_objects(code: types.CodeType) -> Iterator[types.CodeType]:
    yield code
    for constant in code.co_consts:
        if isinstance(constant, types.CodeType):
            yield from _code_objects(constant)


def reads(function: Callable, name: str) -> bool:
    return any(name in code.co_names for code in _code_objects(function.__code__))


def _members(cls: type) -> Iterator[Callable]:
    for member in vars(cls).values():
        if isinstance(member, (staticmethod, classmethod)):
            member = member.__func__
        if isinstance(member, property):
            candidates = [member.fget, member.fset, member.fdel]
        else:
            candidates = [member]
        for candidate in candidates:
            if isinstance(candidate, types.FunctionType):
                # @contextmanager wraps the generator in contextlib's helper, whose
                # globals are contextlib's; the code that reads names is underneath.
                yield inspect.unwrap(candidate)


def supervisor_functions() -> list[Callable]:
    modules = [git_supervisor] + [
        importlib.import_module(f"{supervisor_package.__name__}.{info.name}")
        for info in pkgutil.iter_modules(supervisor_package.__path__)
    ]
    found: list[Callable] = []
    for module in modules:
        for value in vars(module).values():
            if getattr(value, "__module__", None) != module.__name__:
                continue
            if isinstance(value, types.FunctionType):
                found.append(inspect.unwrap(value))
            elif isinstance(value, type):
                found.extend(_members(value))
    return found


def unbound_readers(functions: list[Callable], names: set[str], home: dict) -> list[str]:
    return sorted(
        f"{function.__module__}.{function.__qualname__} reads {name}"
        for function in functions
        for name in names
        if reads(function, name) and function.__globals__ is not home
    )


def test_the_scan_finds_the_patches_the_suite_is_known_to_make() -> None:
    # Without this, a scan that matched nothing would make the real check pass vacuously.
    assert {"SCHEMA_VERSION", "MIGRATIONS", "run_trusted"} <= patched_names()


def test_every_reader_of_a_patched_global_resolves_it_in_git_supervisor() -> None:
    assert unbound_readers(supervisor_functions(), patched_names(), vars(git_supervisor)) == []


def test_every_patched_global_still_has_a_reader_the_patch_reaches() -> None:
    # Catches the other half: every reader moved away AND re-imported the name under an
    # alias, so nothing reads the patched spelling any more and the check above sees nothing.
    home = vars(git_supervisor)
    functions = supervisor_functions()
    orphaned = sorted(
        name
        for name in patched_names()
        if not any(reads(f, name) and f.__globals__ is home for f in functions)
    )
    assert orphaned == []


def test_the_check_flags_a_reader_that_moved_out_of_git_supervisor() -> None:
    namespace: dict = {"run_trusted": None}
    exec("def moved():\n    return run_trusted()\n", namespace)
    moved = namespace["moved"]

    assert unbound_readers([moved], {"run_trusted"}, vars(git_supervisor)) == [
        f"{moved.__module__}.{moved.__qualname__} reads run_trusted"
    ]
    # And a reader that stayed is recognised as a reader, so the empty result above is
    # not the detector simply never firing.
    staying = git_supervisor.assert_schema_not_newer
    assert reads(staying, "SCHEMA_VERSION")
    assert unbound_readers([staying], {"SCHEMA_VERSION"}, vars(git_supervisor)) == []
