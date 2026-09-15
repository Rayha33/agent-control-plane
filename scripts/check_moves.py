"""Prove a git_supervisor split commit is moves + imports only, at the AST level.

Board #1630 moves code out of `git_supervisor.py` into `supervisor/*.py`. A reviewer should
not have to trust that a 1,600-line diff is "just a move": this compares every definition
before and after, ignoring source positions, and reports the four ways a move can go wrong.

    MISSING    defined before, defined nowhere after (a method was dropped)
    DUPLICATE  defined in more than one place after (one copy silently shadows the other
               through the MRO, and the one that wins may be the stale one)
    CHANGED    defined in both, but the AST differs (an edit rode along with the move)
    ADDED      defined after, not before (new code rode along with the move)

Imports are not compared: a move has to add them in the destination and may remove them
from the source. Methods of GitSupervisor and of every *Mixin class are keyed by method name
alone, because moving between those classes is exactly what the split does; methods of any
other class are keyed as Class.method.

Usage:

    python scripts/check_moves.py OLD NEW [--allow NAME ...]

OLD and NEW are git revisions, or `WORKTREE` for the files on disk. Exit 0 when nothing is
MISSING or DUPLICATE and every CHANGED/ADDED key is named with --allow; exit 1 otherwise.
"""

from __future__ import annotations

import argparse
import ast
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "src/agent_control_plane"
SOURCE = f"{PACKAGE}/git_supervisor.py"
PHASES = f"{PACKAGE}/supervisor"
WORKTREE = "WORKTREE"


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=True
    ).stdout


def files_at(revision: str) -> dict[str, str]:
    """git_supervisor.py plus every supervisor/*.py module, as text, at `revision`."""

    if revision == WORKTREE:
        paths = [ROOT / SOURCE, *sorted((ROOT / PHASES).glob("*.py"))]
        return {
            str(path.relative_to(ROOT)): path.read_text(encoding="utf-8")
            for path in paths
            if path.is_file()
        }
    listed = _git("ls-tree", "-r", "--name-only", revision, "--", SOURCE, PHASES).split()
    return {
        path: _git("show", f"{revision}:{path}")
        for path in listed
        if path == SOURCE or (path.startswith(PHASES + "/") and path.endswith(".py"))
    }


def _supervisor_family(node: ast.ClassDef) -> bool:
    return node.name == "GitSupervisor" or node.name.endswith("Mixin")


def _class_header(node: ast.ClassDef) -> str:
    # The body is compared member by member, so the class itself is only its header.
    header = ast.ClassDef(
        name=node.name,
        bases=node.bases,
        keywords=node.keywords,
        body=[],
        decorator_list=node.decorator_list,
        type_params=getattr(node, "type_params", []),
    )
    return ast.dump(header, include_attributes=False)


def _docstring(statement: ast.stmt) -> bool:
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    )


def definitions(files: dict[str, str]) -> dict[str, list[tuple[str, str]]]:
    """key -> [(where, ast dump without positions)] for every definition in `files`."""

    found: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for path, text in sorted(files.items()):
        module = ast.parse(text, filename=path)
        for index, statement in enumerate(module.body):
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                continue
            if index == 0 and _docstring(statement):
                continue  # a module docstring describes the file, not moved code
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found[f"def {statement.name}"].append(
                    (path, ast.dump(statement, include_attributes=False))
                )
            elif isinstance(statement, ast.ClassDef):
                family = _supervisor_family(statement)
                if not family:
                    found[f"class {statement.name}"].append(
                        (path, ast.dump(statement, include_attributes=False))
                    )
                    continue
                found[f"class {statement.name}"].append((path, _class_header(statement)))
                for position, member in enumerate(statement.body):
                    if position == 0 and _docstring(member):
                        continue
                    if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        key = f"GitSupervisor.{member.name}"
                    elif isinstance(member, (ast.Assign, ast.AnnAssign)):
                        targets = (
                            member.targets if isinstance(member, ast.Assign) else [member.target]
                        )
                        key = "GitSupervisor." + ",".join(ast.unparse(t) for t in targets)
                    else:
                        key = f"GitSupervisor.<{type(member).__name__}>{ast.unparse(member)[:60]}"
                    found[key].append(
                        (f"{path}:{statement.name}", ast.dump(member, include_attributes=False))
                    )
            elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = (
                    statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                )
                key = "assign " + ",".join(ast.unparse(target) for target in targets)
                found[key].append((path, ast.dump(statement, include_attributes=False)))
            else:
                dump = ast.dump(statement, include_attributes=False)
                found[f"stmt {ast.unparse(statement)[:60]!r}"].append((path, dump))
    return found


def compare(old: dict, new: dict) -> dict[str, list[str]]:
    report: dict[str, list[str]] = {"MISSING": [], "DUPLICATE": [], "CHANGED": [], "ADDED": []}
    for key in sorted(set(old) | set(new)):
        before, after = old.get(key, []), new.get(key, [])
        if len(after) > max(1, len(before)):
            report["DUPLICATE"].append(f"{key}: {', '.join(where for where, _ in after)}")
        if before and not after:
            report["MISSING"].append(key)
        elif after and not before:
            report["ADDED"].append(f"{key} ({after[0][0]})")
        elif sorted(dump for _, dump in before) != sorted(dump for _, dump in after):
            report["CHANGED"].append(f"{key} ({', '.join(where for where, _ in after)})")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("old", help="git revision, or WORKTREE")
    parser.add_argument("new", help="git revision, or WORKTREE")
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="KEY",
        help="a CHANGED or ADDED key that is intended (the key as printed, without the location)",
    )
    args = parser.parse_args(argv)

    old = definitions(files_at(args.old))
    new = definitions(files_at(args.new))
    report = compare(old, new)
    allowed = set(args.allow)

    def is_allowed(line: str) -> bool:
        return line.rsplit(" (", 1)[0] in allowed

    print(f"{args.old}: {sum(map(len, old.values()))} definitions")
    print(f"{args.new}: {sum(map(len, new.values()))} definitions")
    failed = False
    for kind in ("MISSING", "DUPLICATE", "CHANGED", "ADDED"):
        for line in report[kind]:
            tolerated = kind in {"CHANGED", "ADDED"} and is_allowed(line)
            failed = failed or not tolerated
            print(f"{kind:9s} {line}{'  [allowed]' if tolerated else ''}")
    unused = sorted(
        allowed
        - {line.rsplit(" (", 1)[0] for kind in ("CHANGED", "ADDED") for line in report[kind]}
    )
    for key in unused:
        # An --allow that matches nothing is a stale expectation; say so rather than
        # letting it silently widen what a later run tolerates.
        print(f"UNUSED    --allow {key}")
        failed = True
    print("moves only" if not failed else "NOT moves only")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
