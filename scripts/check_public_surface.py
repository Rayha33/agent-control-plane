"""Pin the public surface of the modules #1630 is splitting.

The split is behaviour-preserving by construction: code MOVES between modules and
nothing else changes. The risk is therefore not "does it still work" — the suite
answers that — but "did a name quietly stop being importable from where callers
import it from". A moved symbol that is no longer re-exported breaks callers the
test suite does not happen to exercise, and it breaks them at import time in
someone else's session rather than here.

So this records the surface as data and diffs it. Usage:

    python scripts/check_public_surface.py --write    # record the baseline
    python scripts/check_public_surface.py            # fail if it changed

Deliberately records more than GitSupervisor's method names, which is all the
board row asked for: module-level names count too, because `from
agent_control_plane.git_supervisor import SupervisorError` is exactly the kind of
import a move silently breaks.
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path

BASELINE = Path(__file__).resolve().parent.parent / "tests" / "public_surface.json"

# Every module a caller may import from. git_supervisor is the one being split;
# the rest are recorded so a move that lands a name in the wrong module is caught
# from both directions.
MODULES = [
    "agent_control_plane.git_supervisor",
    "agent_control_plane.scheduling",
    "agent_control_plane.status",
    "agent_control_plane.side_effects",
    "agent_control_plane.trust_bundles",
    "agent_control_plane.runtime_drivers",
    "agent_control_plane.coordination",
    "agent_control_plane.service",
    "agent_control_plane.assurance",
]


def _public(names) -> list[str]:
    return sorted(n for n in names if not n.startswith("__"))


def surface() -> dict[str, dict[str, list[str]]]:
    result: dict[str, dict[str, list[str]]] = {}
    for name in MODULES:
        module = importlib.import_module(name)
        entry: dict[str, list[str]] = {"module": _public(vars(module))}
        for attr in _public(vars(module)):
            value = getattr(module, attr, None)
            if isinstance(value, type):
                # Include private methods too. `_integrate_locked` and friends are
                # private by name but are the actual subject of the split, and a
                # rename during a move is exactly the mistake worth catching.
                entry[f"class:{attr}"] = _public(vars(value))
        result[name] = entry
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write", action="store_true", help="record the current surface as the baseline"
    )
    args = parser.parse_args()

    current = surface()
    if args.write:
        BASELINE.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
        print(f"recorded {sum(len(v) for v in current.values())} entries to {BASELINE}")
        return 0

    if not BASELINE.exists():
        print(f"no baseline at {BASELINE}; run with --write first", file=sys.stderr)
        return 2

    expected = json.loads(BASELINE.read_text())
    if expected == current:
        print("public surface unchanged")
        return 0

    for module in sorted(set(expected) | set(current)):
        want = expected.get(module, {})
        have = current.get(module, {})
        for key in sorted(set(want) | set(have)):
            lost = sorted(set(want.get(key, [])) - set(have.get(key, [])))
            gained = sorted(set(have.get(key, [])) - set(want.get(key, [])))
            if lost:
                print(f"REMOVED {module}.{key}: {', '.join(lost)}")
            if gained:
                print(f"ADDED   {module}.{key}: {', '.join(gained)}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
