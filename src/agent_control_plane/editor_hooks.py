"""Editor-side adapters that call the kernel; they never re-decide anything.

ACP's enforcement boundary is only real if the agent's edits pass through it. The CLI
and API are the only surfaces today, so a Claude Code session editing the base
checkout defeats every claim and fence without ACP noticing. These hooks put `acp
guard` in front of the tool calls that write, and `guard` is the same `_path_matches`
check `submit` applies to the diff — the adapter asks, the supervisor answers.
"""

from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
import uuid
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
SETTINGS_LOCAL_RELATIVE_PATH = Path(".claude") / "settings.local.json"
CODEX_HOOKS_RELATIVE_PATH = Path(".codex") / "hooks.json"
CODEX_MAX_PATCH_CHARS = 2_000_000
CODEX_MAX_HOOK_INPUT_CHARS = 2_250_000
CODEX_MAX_PATCH_PATHS = 128
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


def cwd_from_hook_payload(payload: Any) -> str | None:
    """The editor's actual working directory, or None when the payload omits it."""

    if not isinstance(payload, dict):
        return None
    cwd = payload.get("cwd")
    return cwd if isinstance(cwd, str) and cwd.strip() else None


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


def parse_codex_patch_paths(command: str) -> list[str]:
    """Extract every path changed by Codex's structured apply_patch input.

    This intentionally accepts only the documented apply_patch envelope and its
    Add/Delete/Update/Move operations. A new operation or malformed section must
    block rather than silently shrink the path set we authorize.
    """

    if not isinstance(command, str):
        raise ValueError("apply_patch command must be text")
    if len(command) > CODEX_MAX_PATCH_CHARS:
        raise ValueError("apply_patch command exceeds the 2,000,000 character safety limit")
    lines = command.splitlines()
    if len(lines) < 3 or lines[0] != "*** Begin Patch" or lines[-1] != "*** End Patch":
        raise ValueError("apply_patch command must have Begin Patch and End Patch markers")

    paths: list[str] = []
    index = 1
    end = len(lines) - 1
    seen_environment_id = False
    while index < end:
        line = lines[index]
        if not line:
            index += 1
            continue

        # Codex trims top-level hunk headers before interpreting them. Match that
        # behavior when extracting a target: checking a filename with trailing
        # whitespace while apply_patch writes the trimmed filename would authorize
        # a different path from the one we actually inspected.
        header = line.strip()
        environment_prefix = "*** Environment ID: "
        if not paths and header.startswith("*** Environment ID:"):
            if seen_environment_id or not header.startswith(environment_prefix):
                raise ValueError("malformed or duplicate apply_patch environment id")
            environment_id = header[len(environment_prefix) :].strip()
            if not environment_id or "\x00" in environment_id:
                raise ValueError("apply_patch environment id must be non-empty text")
            seen_environment_id = True
            index += 1
            continue

        operation: str | None = None
        for candidate in ("Add", "Delete", "Update"):
            prefix = f"*** {candidate} File: "
            if header.startswith(prefix):
                operation = candidate.lower()
                source = header[len(prefix) :]
                break
        if operation is None:
            raise ValueError(f"unsupported apply_patch operation: {line[:120]}")
        if not source or "\x00" in source:
            raise ValueError("apply_patch file operation has an empty or invalid path")

        paths.append(source)
        index += 1
        has_hunk = False
        has_move = False
        while index < end:
            line = lines[index]
            if not line:
                index += 1
                continue
            # In Codex's update state, trailing whitespace is ignored but leading
            # whitespace is retained; in the other states operation headers are
            # trimmed on both sides. Preserve that distinction to avoid authorizing
            # a filename different from the path Codex will write.
            marker_line = line.rstrip() if operation == "update" else line.strip()
            if marker_line.startswith(("*** Add File: ", "*** Delete File: ", "*** Update File: ")):
                break
            if marker_line.startswith("*** Move to: "):
                if operation != "update" or has_move or has_hunk:
                    raise ValueError("Move to is supported once, before Update File content")
                destination = marker_line[len("*** Move to: ") :]
                if not destination or "\x00" in destination:
                    raise ValueError("apply_patch move has an empty or invalid destination")
                paths.append(destination)
                has_move = True
                index += 1
                continue
            if marker_line == "*** End of File" and (
                operation != "update" or line.rstrip() == "*** End of File"
            ):
                if operation == "update" and not has_hunk:
                    raise ValueError("End of File cannot replace an Update File hunk")
                index += 1
                continue
            if line.startswith("*** "):
                raise ValueError(f"unsupported apply_patch marker: {line[:120]}")

            if operation == "add":
                if not line.startswith("+"):
                    raise ValueError("Add File content must use + lines")
            elif operation == "delete":
                raise ValueError("Delete File must not contain patch content")
            elif line.rstrip().startswith("@@"):
                has_hunk = True
            else:
                # Codex's lenient update parser accepts unprefixed context lines.
                # They carry no additional target path, but count as update content.
                has_hunk = True
            index += 1

        if operation == "update" and not (has_hunk or has_move):
            raise ValueError("Update File must contain a hunk or Move to destination")
        if len(paths) > CODEX_MAX_PATCH_PATHS:
            raise ValueError("apply_patch command exceeds the 128-path safety limit")

    if not paths:
        raise ValueError("apply_patch command contains no file operations")
    return paths


def codex_hooks(command: str, attempt_id: str | None = None) -> dict[str, Any]:
    """The attempt-scoped Codex hook block ACP owns."""

    attempt_argument = f" --attempt {shlex.quote(attempt_id)}" if attempt_id else ""
    return {
        "PreToolUse": [
            {
                "matcher": "^apply_patch$",
                "hooks": [
                    {
                        "type": "command",
                        "command": f"{command} guard{attempt_argument} --codex-hook",
                        "timeout": 15,
                        "statusMessage": "Checking ACP write scope",
                    }
                ],
            }
        ]
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


def _ensure_local_settings_ignored(root: Path) -> None:
    """Keep attempt-local Claude settings out of the candidate diff."""

    _ensure_local_hook_file_ignored(
        root,
        SETTINGS_LOCAL_RELATIVE_PATH,
        ".claude/.settings.local.json.*.tmp",
    )


def _ensure_local_hook_file_ignored(root: Path, relative: Path, temporary_pattern: str) -> None:
    """Keep attempt-local editor hook configuration out of a candidate diff."""

    relative_path = relative.as_posix()
    tracked = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--error-unmatch", "--", relative_path],
        capture_output=True,
        text=True,
        check=False,
    )
    if tracked.returncode == 0:
        raise ValueError(f"refusing to modify tracked attempt-local hook config: {relative_path}")

    common = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--path-format=absolute", "--git-common-dir"],
        capture_output=True,
        text=True,
        check=False,
    )
    if common.returncode != 0 or not common.stdout.strip():
        raise ValueError(f"cannot locate Git's shared exclude file from {root}")

    exclude_path = Path(common.stdout.strip()) / "info" / "exclude"
    if exclude_path.is_symlink():
        raise ValueError(f"refusing to modify symlinked Git exclude file: {exclude_path}")
    exclude_path.parent.mkdir(parents=True, exist_ok=True)
    patterns = (f"/{relative_path}", f"/{temporary_pattern}")
    current = exclude_path.read_text(encoding="utf-8") if exclude_path.exists() else ""
    current_lines = current.splitlines()
    missing = [pattern for pattern in patterns if pattern not in current_lines]
    if missing:
        with exclude_path.open("a", encoding="utf-8") as exclude:
            if current and not current.endswith("\n"):
                exclude.write("\n")
            exclude.write("".join(f"{pattern}\n" for pattern in missing))

    temporary_check = temporary_pattern.replace(".*.tmp", ".check.tmp")
    for path in (relative_path, temporary_check):
        ignored = subprocess.run(
            ["git", "-C", str(root), "check-ignore", "--no-index", "-q", "--", path],
            capture_output=True,
            check=False,
        )
        if ignored.returncode != 0:
            raise ValueError(f"Git does not ignore local hook settings at {path}")


def install_claude_code_hooks(
    root: Path, command: str = "acp", *, local: bool = False
) -> dict[str, Any]:
    """Write ACP hooks into project or personal-local settings, preserving the rest."""

    root = root.resolve()
    settings_path = root / (SETTINGS_LOCAL_RELATIVE_PATH if local else SETTINGS_RELATIVE_PATH)
    if local:
        settings_parent = settings_path.parent
        if settings_parent.is_symlink():
            raise ValueError(
                f"refusing to install through symlinked settings directory: {settings_parent}"
            )
        if settings_path.is_symlink():
            raise ValueError(f"refusing to read symlinked local settings: {settings_path}")
        try:
            settings_parent.resolve(strict=False).relative_to(root)
        except ValueError as error:
            raise ValueError(
                f"settings directory escapes the attempt worktree: {settings_parent}"
            ) from error
    settings: dict[str, Any] = {}
    previous_mode: int | None = None
    if settings_path.exists():
        try:
            loaded = json.loads(settings_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise ValueError(f"{settings_path} is not valid JSON: {error}") from error
        if not isinstance(loaded, dict):
            raise ValueError(f"{settings_path} must contain a JSON object; refusing to replace it")
        settings = loaded
        previous_mode = stat.S_IMODE(settings_path.stat().st_mode)

    if local:
        _ensure_local_settings_ignored(root)

    settings["hooks"] = _merge_hook_events(
        settings.get("hooks") if isinstance(settings.get("hooks"), dict) else {},
        claude_code_hooks(command),
        command,
    )
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = settings_path.with_name(f".settings.local.json.{uuid.uuid4().hex}.tmp")
    try:
        descriptor = os.open(
            temporary_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as temporary_file:
            temporary_file.write(json.dumps(settings, indent=2) + "\n")
        if previous_mode is not None:
            temporary_path.chmod(previous_mode)
        os.replace(temporary_path, settings_path)
    finally:
        temporary_path.unlink(missing_ok=True)
    return {
        "ok": True,
        "settings": str(settings_path),
        "scope": "project-local" if local else "project",
        "guarded_tools": list(GUARDED_TOOLS),
        "unguarded": ["Bash"],
        "note": (
            "Bash is not guarded: what a shell command writes cannot be read off the "
            "command string. Confine the agent to the worktree instead."
        ),
    }


def install_codex_hooks(
    root: Path, command: str = "acp", *, local: bool = False, attempt_id: str | None = None
) -> dict[str, Any]:
    """Write Codex hooks, preserving unrelated project hooks and metadata."""

    root = root.resolve()
    hooks_path = root / CODEX_HOOKS_RELATIVE_PATH
    hooks_parent = hooks_path.parent
    if hooks_parent.is_symlink():
        raise ValueError(f"refusing to install through symlinked hooks directory: {hooks_parent}")
    if hooks_path.is_symlink():
        raise ValueError(f"refusing to read symlinked hooks file: {hooks_path}")
    if local:
        try:
            hooks_parent.resolve(strict=False).relative_to(root)
        except ValueError as error:
            raise ValueError(
                f"hooks directory escapes the attempt worktree: {hooks_parent}"
            ) from error

    settings: dict[str, Any] = {}
    previous_mode: int | None = None
    if hooks_path.exists():
        try:
            loaded = json.loads(hooks_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise ValueError(f"{hooks_path} is not valid JSON: {error}") from error
        if not isinstance(loaded, dict):
            raise ValueError(f"{hooks_path} must contain a JSON object; refusing to replace it")
        settings = loaded
        previous_mode = stat.S_IMODE(hooks_path.stat().st_mode)

    existing_hooks = settings.get("hooks", {})
    if not isinstance(existing_hooks, dict):
        raise ValueError(f"{hooks_path} hooks field must be an object; refusing to replace it")
    merged_hooks = dict(existing_hooks)
    existing_pre = merged_hooks.get("PreToolUse", [])
    if not isinstance(existing_pre, list):
        raise ValueError(f"{hooks_path} PreToolUse field must be a list; refusing to replace it")
    kept = [entry for entry in existing_pre if not _is_codex_acp_entry(entry)]
    merged_hooks["PreToolUse"] = kept + codex_hooks(command, attempt_id)["PreToolUse"]
    settings["hooks"] = merged_hooks

    if local:
        _ensure_local_hook_file_ignored(
            root,
            CODEX_HOOKS_RELATIVE_PATH,
            ".codex/.hooks.json.*.tmp",
        )

    hooks_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = hooks_path.with_name(f".hooks.json.{uuid.uuid4().hex}.tmp")
    try:
        descriptor = os.open(temporary_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as temporary_file:
            temporary_file.write(json.dumps(settings, indent=2) + "\n")
        if previous_mode is not None:
            temporary_path.chmod(previous_mode)
        os.replace(temporary_path, hooks_path)
    finally:
        temporary_path.unlink(missing_ok=True)
    return {
        "ok": True,
        "settings": str(hooks_path),
        "scope": "project-local" if local else "project",
        "guarded_tools": ["apply_patch"],
        "unguarded": ["Bash", "other tools and non-hook write paths"],
        "note": (
            "Codex project hooks require project trust and hook review. This hook only "
            "checks structured apply_patch calls; it is not an OS sandbox."
        ),
    }


def _is_codex_acp_entry(entry: Any) -> bool:
    if not isinstance(entry, dict) or entry.get("matcher") != "^apply_patch$":
        return False
    handlers = entry.get("hooks")
    if not isinstance(handlers, list):
        return False
    for hook in handlers:
        if not isinstance(hook, dict) or not isinstance(hook.get("command"), str):
            continue
        try:
            tokens = shlex.split(hook["command"])
        except ValueError:
            continue
        if len(tokens) >= 2 and tokens[-1] == "--codex-hook":
            for index, token in enumerate(tokens[:-1]):
                remainder = tokens[index + 1 :]
                if token == "guard" and (
                    remainder == ["--codex-hook"]
                    or (len(remainder) == 3 and remainder[0] == "--attempt")
                ):
                    return True
    return False
