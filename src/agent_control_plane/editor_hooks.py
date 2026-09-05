"""Editor-side adapters that call the kernel; they never re-decide anything.

ACP's enforcement boundary is only real if the agent's edits pass through it. The CLI
and API are the only surfaces today, so a Claude Code session editing the base
checkout defeats every claim and fence without ACP noticing. These hooks put `acp
guard` in front of the tool calls that write, and `guard` is the same `_path_matches`
check `submit` applies to the diff — the adapter asks, the supervisor answers.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

GUARDED_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")
"""Tools whose target path is a structured field we can read.

Bash is deliberately absent. Deciding what an arbitrary shell command writes means
parsing the shell, and a regex over the command string would deny `rm -rf /etc` while
missing `sh -c "$(printf ...)"`, `tee`, an editor invocation, or a redirect built from
a variable. A guard that can be walked around by rephrasing is worse than an absent
one, because it reads as coverage. Confine an agent's shell with the worktree and the
OS, not with a pattern match — see docs/INTEGRATIONS.md.
"""

HOOK_TOOL_MATCHER = "|".join(GUARDED_TOOLS)
SETTINGS_RELATIVE_PATH = Path(".claude") / "settings.json"
DENY_EXIT_CODE = 2
"""Claude Code blocks a PreToolUse hook's tool call on exit 2 and shows it stderr."""


def path_from_hook_payload(payload: Any) -> str | None:
    """The file a PreToolUse payload is about, or None if it names no single path.

    Every tool in GUARDED_TOOLS carries a path, so None means the payload was not what
    we expected. The caller denies on None rather than allowing: a guard that cannot
    read the request cannot tell whether it is in scope, and allowing there would let
    the boundary disappear quietly on a schema change. Loud is recoverable.
    """

    if not isinstance(payload, dict):
        return None
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    for key in ("file_path", "notebook_path", "path"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def claude_code_hooks(command: str) -> dict[str, Any]:
    """The hook block ACP owns, keyed so an update can replace it in place."""

    return {
        "PreToolUse": [
            {
                "matcher": HOOK_TOOL_MATCHER,
                "hooks": [{"type": "command", "command": f"{command} guard --hook"}],
            }
        ],
        "SessionStart": [
            {"hooks": [{"type": "command", "command": f"{command} guard --describe"}]}
        ],
        # No heartbeat hook yet. `acp heartbeat` is a write that needs the claim token
        # and the runner credential, so wiring it here means deciding how a secret
        # reaches a hook process — a credential-handling design, not an env var read.
        # An expired lease is currently visible as a `lease_expired` denial from the
        # guard, which is a loud failure rather than a silent one.
    }


def _merge_hook_events(
    existing: dict[str, Any], generated: dict[str, Any], command: str
) -> dict[str, Any]:
    """Add ACP's entries to whatever hooks are already configured.

    A settings file is the user's, and it is normal for it to carry hooks that have
    nothing to do with ACP. Replacing the file — or even the `hooks` key — to install
    an integration would be a destructive act performed on the user's behalf, so this
    drops only previous ACP entries (recognised by the command prefix) and appends the
    current ones, leaving every other hook untouched.
    """

    merged = dict(existing)
    for event, entries in generated.items():
        kept = [entry for entry in merged.get(event, []) if not _is_acp_entry(entry, command)]
        merged[event] = kept + entries
    return merged


def _is_acp_entry(entry: Any, command: str) -> bool:
    if not isinstance(entry, dict):
        return False
    return any(
        isinstance(hook, dict)
        and isinstance(hook.get("command"), str)
        and hook["command"].startswith(f"{command} guard")
        for hook in entry.get("hooks", [])
    )


def install_claude_code_hooks(root: Path, command: str = "acp") -> dict[str, Any]:
    """Write ACP's hooks into `<root>/.claude/settings.json`, preserving the rest."""

    settings_path = root / SETTINGS_RELATIVE_PATH
    settings: dict[str, Any] = {}
    if settings_path.exists():
        try:
            loaded = json.loads(settings_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise ValueError(f"{settings_path} is not valid JSON: {error}") from error
        if isinstance(loaded, dict):
            settings = loaded

    settings["hooks"] = _merge_hook_events(
        settings.get("hooks") if isinstance(settings.get("hooks"), dict) else {},
        claude_code_hooks(command),
        command,
    )
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    return {
        "ok": True,
        "settings": str(settings_path),
        "guarded_tools": list(GUARDED_TOOLS),
        "unguarded": ["Bash"],
        "note": (
            "Bash is not guarded: what a shell command writes cannot be read off the "
            "command string. Confine the agent to the worktree instead."
        ),
    }
