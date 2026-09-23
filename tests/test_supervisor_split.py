"""Pin the two ways a pure move out of git_supervisor.py can change behaviour silently.

Board #1630 splits git_supervisor.py into supervisor/*.py. A move is behaviour-preserving
except where the text depends on WHICH MODULE it sits in. Two such cases are pinned here.

The first is a MODULE-LEVEL MONKEYPATCH.

`monkeypatch.setattr(git_supervisor, "SCHEMA_VERSION", ...)` rebinds the name in
git_supervisor's namespace, and a function only sees that if it looks the name up in THAT
namespace, which means it was defined in git_supervisor.py. Move the reader into
supervisor/<phase>.py with its own import of the name and the test that patches it keeps
passing while the patch no longer reaches the code it was written to steer. Measured during
module 1: four such patch sites, and only one of them went red.

So this test finds every name the suite patches on git_supervisor and asserts that every
function reading one of those names still resolves its globals in git_supervisor.

The second is `__file__`: a `Path(__file__)` expression moved verbatim names a different
directory afterwards. test_file_relative_paths_still_name_files_that_exist pins that.
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
# Every spelling that binds the module to a local name: `import a.git_supervisor as X` and
# `from agent_control_plane import git_supervisor as X`. The unaliased forms bind
# `git_supervisor` or `agent_control_plane.git_supervisor`, which names_patched_in always tries.
ALIAS = re.compile(
    r"(?:import\s+agent_control_plane\.git_supervisor"
    r"|from\s+agent_control_plane\s+import\s+git_supervisor)\s+as\s+(\w+)"
)
DOTTED = re.compile(r"[\"']agent_control_plane\.git_supervisor\.(\w+)[\"']")


def names_patched_in(text: str) -> set[str]:
    """Names one test file rebinds on the git_supervisor module itself.

    `setattr(git_supervisor.shutil, "rmtree", ...)` is not one: it patches the shared
    `shutil` module, which every importer sees. Only `setattr(<the module>, "NAME")` and the
    one-component dotted-string form rebind a git_supervisor global.
    """

    aliases = {"git_supervisor", "agent_control_plane.git_supervisor", *ALIAS.findall(text)}
    pattern = re.compile(
        r"setattr\(\s*(?:"
        + "|".join(re.escape(alias) for alias in sorted(aliases))
        + r")\s*,\s*[\"'](\w+)[\"']"
    )
    return set(pattern.findall(text)) | set(DOTTED.findall(text))


def patched_names() -> set[str]:
    names: set[str] = set()
    for path in TESTS.rglob("*.py"):
        if path.resolve() == Path(__file__).resolve():
            continue
        names |= names_patched_in(path.read_text(encoding="utf-8"))
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


FILE_RELATIVE = re.compile(
    r"Path\(__file__\)(?:\.parent|\.parents\[\d+\]|\.resolve\(\))*"
    r"(?:\.with_name\(\s*[\"'][\w./-]+[\"']\s*\)|\s*/\s*[\"'][\w./-]+[\"'])"
)


def file_relative_targets() -> list[tuple[str, Path]]:
    """Every `Path(__file__)...` expression in the package that names a file, evaluated
    against the file it is written in."""

    package = Path(git_supervisor.__file__).resolve().parent
    targets = []
    for source in sorted(package.rglob("*.py")):
        for match in FILE_RELATIVE.finditer(source.read_text(encoding="utf-8")):
            # The regex admits only Path(__file__), .parent/.parents[n]/.resolve() and one
            # string literal, so evaluating the matched text is evaluating that and no more.
            target = eval(match.group(0), {"Path": Path, "__file__": str(source)})
            targets.append((f"{source.relative_to(package)}: {match.group(0)}", target))
    return targets


def test_file_relative_paths_still_name_files_that_exist() -> None:
    """The second way a byte-identical move changes behaviour: `__file__` moves with it.

    Measured 2026-09-11 during #1630: `_run_process` and `run_worker` moved into
    supervisor/process.py and supervisor/workers.py with their text unchanged, and
    `Path(__file__).with_name("worker_trampoline.py")` quietly started naming
    supervisor/worker_trampoline.py, which does not exist. 72 tests went red in the full
    macOS suite, because every contained QC and integration run failed; the workers.py copy
    sits on the Linux worker path, which only runs in Linux CI.
    """

    targets = file_relative_targets()
    # Without this a regex that matched nothing would pass vacuously.
    assert {"worker_trampoline.py", "critic.py"} <= {target.name for _where, target in targets}
    assert [where for where, target in targets if not target.is_file()] == []


def test_the_scan_finds_the_patches_the_suite_is_known_to_make() -> None:
    # Without this, a scan that matched nothing would make the real check pass vacuously.
    assert {"SCHEMA_VERSION", "MIGRATIONS", "run_trusted"} <= patched_names()


def test_the_scan_follows_every_spelling_of_the_module() -> None:
    # Before 2026-09-16 only `import agent_control_plane.git_supervisor as X` was followed, so a
    # patch through `from agent_control_plane import git_supervisor as X` pinned nothing.
    text = (
        "import agent_control_plane.git_supervisor\n"
        "import agent_control_plane.git_supervisor as gs_a\n"
        "from agent_control_plane import git_supervisor as gs_b\n"
        "from agent_control_plane import git_supervisor\n"
        "monkeypatch.setattr(gs_a, 'VIA_IMPORT_AS', 1)\n"
        "monkeypatch.setattr(gs_b, 'VIA_FROM_IMPORT_AS', 1)\n"
        "monkeypatch.setattr(git_supervisor, 'VIA_FROM_IMPORT', 1)\n"
        "monkeypatch.setattr(agent_control_plane.git_supervisor, 'VIA_DOTTED_MODULE', 1)\n"
        "monkeypatch.setattr('agent_control_plane.git_supervisor.VIA_STRING', 1)\n"
        "monkeypatch.setattr(git_supervisor.shutil, 'rmtree', 1)\n"
        "monkeypatch.setattr(unrelated, 'NOT_THE_MODULE', 1)\n"
    )
    assert names_patched_in(text) == {
        "VIA_IMPORT_AS",
        "VIA_FROM_IMPORT_AS",
        "VIA_FROM_IMPORT",
        "VIA_DOTTED_MODULE",
        "VIA_STRING",
    }


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


# The open path is what a facade is for: the constructor, the classmethod that writes acp.toml
# and then constructs, the step that finishes opening, and the one-line delegate to
# supervisor.schema. They stay by design, not because a move would rebind anything.
FACADE_BY_DESIGN = frozenset({"__init__", "initialize", "_finish_open", "_migrate"})


def facade_methods_without_a_reason(cls: type, names: set[str]) -> list[str]:
    """Methods defined on `cls` itself that could move to a phase module unchanged.

    A method has to stay in git_supervisor.py when moving it would change what it binds:
    it reads a global the suite patches on git_supervisor, or it names `GitSupervisor`
    (tests patch attributes on the class, and a mixin cannot name its subclass without a
    text edit). Anything else left on the class is facade weight a verbatim move removes.
    """

    left = []
    for name, member in vars(cls).items():
        if name in FACADE_BY_DESIGN:
            continue
        if isinstance(member, (staticmethod, classmethod)):
            member = member.__func__
        if not isinstance(member, types.FunctionType):
            continue
        function = inspect.unwrap(member)
        pinned = any(reads(function, patched) for patched in names)
        if not pinned and not reads(function, "GitSupervisor"):
            left.append(name)
    return sorted(left)


def test_the_facade_keeps_only_what_a_move_would_rebind() -> None:
    """GitSupervisor stays a thin facade (#1630).

    Measured before the facade moves (cd5b476): this listed 13 methods, among them connect,
    create_task and status, all of which moved verbatim to store, claims and views.
    """

    assert facade_methods_without_a_reason(git_supervisor.GitSupervisor, patched_names()) == []


def test_the_facade_check_flags_a_movable_method() -> None:
    namespace: dict = {}
    exec(
        "class Facade:\n"
        "    def movable(self):\n        return len('x')\n"
        "    def pinned(self):\n        return run_trusted()\n"
        "    def names_class(self):\n        return GitSupervisor.x\n",
        namespace,
    )
    assert facade_methods_without_a_reason(namespace["Facade"], {"run_trusted"}) == ["movable"]


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
