"""Editor-side adapters that call the kernel; they never re-decide anything.

ACP's enforcement boundary is only real if the agent's edits pass through it. The CLI
and API are the only surfaces today, so a Claude Code session editing the base
checkout defeats every claim and fence without ACP noticing. These hooks put `acp
guard` in front of the tool calls that write, and `guard` is the same `_path_matches`
check `submit` applies to the diff — the adapter asks, the supervisor answers.
"""

from __future__ import annotations

import json
import shlex
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
ACP_MANAGED_COMMAND_MARKER = " # acp-managed-hook:v1"


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


def claude_code_hooks(command: str, *, require_checkout_exec: bool = False) -> dict[str, Any]:
    """The hook block ACP owns, keyed so an update can replace it in place."""

    guard_command = f"{command} guard --hook"
    if require_checkout_exec:
        guard_command += " --require-checkout-exec"
    # Claude Code only blocks a PreToolUse call on exit 2. If the executable cannot
    # launch (126/127), the ACP CLI never gets a chance to translate its own errors
    # into that blocking status; map every unsuccessful invocation to exit 2 here.
    guard_command += " || exit 2"
    guard_command += ACP_MANAGED_COMMAND_MARKER
    return {
        "PreToolUse": [
            {
                "matcher": HOOK_TOOL_MATCHER,
                "hooks": [{"type": "command", "command": guard_command}],
            }
        ],
        "SessionStart": [
            {
                "hooks": [
                    {
                        "type": "command",
                        "command": f"{command} guard --describe{ACP_MANAGED_COMMAND_MARKER}",
                    }
                ]
            }
        ],
        # No heartbeat hook yet. `acp heartbeat` is a write that needs the claim token
        # and the runner credential, so wiring it here means deciding how a secret
        # reaches a hook process — a credential-handling design, not an env var read.
        # An expired lease is currently visible as a `lease_expired` denial from the
        # guard, which is a loud failure rather than a silent one.
    }


def _merge_hook_events(existing: dict[str, Any], generated: dict[str, Any]) -> dict[str, Any]:
    """Add ACP's entries to whatever hooks are already configured.

    A settings file is the user's, and it is normal for it to carry hooks that have
    nothing to do with ACP. Replacing the file — or even the `hooks` key — to install
    an integration would be a destructive act performed on the user's behalf, so this
    drops only previous ACP entries (recognised by a stable marker or exact legacy
    command shape) and appends the current ones, leaving every other hook untouched.
    """

    merged = dict(existing)
    for event, entries in generated.items():
        kept = []
        for entry in merged.get(event, []):
            if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
                kept.append(entry)
                continue
            hooks = entry["hooks"]
            remaining_hooks = [hook for hook in hooks if not _is_acp_hook(hook)]
            if len(remaining_hooks) == len(hooks):
                kept.append(entry)
            elif remaining_hooks:
                preserved_entry = dict(entry)
                preserved_entry["hooks"] = remaining_hooks
                kept.append(preserved_entry)
        merged[event] = kept + entries
    return merged


def _is_acp_hook(hook: Any) -> bool:
    if not isinstance(hook, dict) or not isinstance(hook.get("command"), str):
        return False
    hook_command = hook["command"]
    return hook_command.endswith(ACP_MANAGED_COMMAND_MARKER) or _is_legacy_acp_hook_command(
        hook_command
    )


def _is_legacy_acp_hook_command(command: str) -> bool:
    """Recognize exact ACP hook commands emitted before the stable marker existed.

    Older releases accepted a custom command such as ``python -m
    agent_control_plane.cli --repo /project``. Recognize that explicit module form
    as well as the ``acp`` executable, but do not classify arbitrary user commands
    merely because they mention ACP or start with ``acp guard``.
    """

    try:
        words = shlex.split(command)
    except ValueError:
        return False
    if not words:
        return False

    executable = Path(words[0]).name.lower()
    if executable == "acp":
        arguments = words[1:]
    elif (executable == "python" or _is_versioned_python(executable)) and words[1:3] == [
        "-m",
        "agent_control_plane.cli",
    ]:
        arguments = words[3:]
    else:
        return False

    while arguments and arguments[0] != "guard":
        if arguments[0] == "--repo" and len(arguments) > 1:
            arguments = arguments[2:]
        elif arguments[0].startswith("--repo="):
            arguments = arguments[1:]
        else:
            return False
    if not arguments or arguments[0] != "guard":
        return False

    generated_arguments = tuple(arguments[1:])
    return generated_arguments in {
        ("--describe",),
        ("--hook",),
        ("--hook", "||", "exit", "2"),
        ("--hook", "--require-checkout-exec"),
        ("--hook", "--require-checkout-exec", "||", "exit", "2"),
    }


def _is_versioned_python(executable: str) -> bool:
    suffix = executable.removeprefix("python")
    return executable.startswith("python") and bool(suffix) and suffix.replace(".", "").isdigit()


def install_claude_code_hooks(
    root: Path, command: str = "acp", *, require_checkout_exec: bool = False
) -> dict[str, Any]:
    """Write ACP's hooks into `<root>/.claude/settings.json`, preserving the rest."""

    settings_path = root / SETTINGS_RELATIVE_PATH
    settings: dict[str, Any] = {}
    if settings_path.exists():
        try:
            loaded = json.loads(settings_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise ValueError(f"{settings_path} is not valid JSON: {error}") from error
        if not isinstance(loaded, dict):
            raise ValueError(f"{settings_path} must contain a JSON object")
        settings = loaded

    existing_hooks = settings.get("hooks", {})
    if not isinstance(existing_hooks, dict):
        raise ValueError(f"{settings_path} has a non-object 'hooks' value")
    for entries in existing_hooks.values():
        if not isinstance(entries, list):
            raise ValueError(f"{settings_path} has a non-list hook event value")
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError(f"{settings_path} has a non-object hook matcher entry")
            configured_hooks = entry.get("hooks")
            if not isinstance(configured_hooks, list):
                raise ValueError(f"{settings_path} has a non-list 'hooks' entry value")
            if any(not isinstance(hook, dict) for hook in configured_hooks):
                raise ValueError(f"{settings_path} has a non-object hook command entry")

    settings["hooks"] = _merge_hook_events(
        existing_hooks,
        claude_code_hooks(command, require_checkout_exec=require_checkout_exec),
    )
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    return {
        "ok": True,
        "settings": str(settings_path),
        "guarded_tools": list(GUARDED_TOOLS),
        "checkout_fence": "required" if require_checkout_exec else "not_required",
        "unguarded": ["Bash"],
        "note": (
            "Bash is not guarded: what a shell command writes cannot be read off the "
            "command string. Confine the agent to the worktree instead."
        ),
    }
