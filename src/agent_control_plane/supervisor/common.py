"""Constants, the error type and the small value types every supervisor phase shares.

Moved verbatim out of `git_supervisor` (board #1630) so the phase modules beside this one can
import them without importing `git_supervisor`, which imports the phase modules.
`git_supervisor` imports every name back, so `from agent_control_plane.git_supervisor import
SupervisorError` and friends keep working; scripts/check_public_surface.py pins that.

SCHEMA_VERSION is NOT here: tests monkeypatch it on `git_supervisor`, so it has to stay in the
namespace its readers look it up in.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64
CLEANUP_FENCE_EPOCH = 2**62
SUBMISSION_OBJECT_CONTRACT = "replacement-free-v1"
MAX_ATTRIBUTE_BYTES = 1024 * 1024
SUPERVISOR_SECRET_ENV = {"ACP_RUNNER_CREDENTIAL"}
PUBLIC_CHILD_ENV = {
    "HOME",
    "LANG",
    "LC_ALL",
    "LOGNAME",
    "PATH",
    "SHELL",
    "TERM",
    "TMPDIR",
    "USER",
}
MERGE_SEMANTIC_CONFIG = (
    "core.autocrlf",
    "core.bigfilethreshold",
    "core.checkroundtripencoding",
    "core.eol",
    "core.filemode",
    "core.ignorecase",
    "core.precomposeunicode",
    "core.protecthfs",
    "core.protectntfs",
    "core.safecrlf",
    "core.symlinks",
    "diff.algorithm",
    "diff.indentheuristic",
    "diff.renamelimit",
    "diff.renames",
    "merge.conflictstyle",
    "merge.directoryrenames",
    "merge.renamelimit",
    "merge.renames",
    "merge.renormalize",
)


class SupervisorError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


GC_RECLAIMABLE_TASK_STATUSES = frozenset(
    {"done", "orphaned", "blocked", "conflicted", "changes_requested"}
)
"""Task states whose attempt worktree is no longer the working copy of anything.

Keyed on the TASK, not the attempt. An attempt that was submitted and integrated stays
at `submitted` forever — nothing ever moves it to a terminal state — so an attempt-keyed
sweep would find nothing to reclaim on exactly the tasks that finished cleanly.
"""

DEFAULT_GC_RETENTION_SECONDS = 7 * 24 * 3600

FORK_DENIED_EXIT_CODE = 128
FORK_DENIED_SIGNATURE = "fork: Operation not permitted"
"""The two halves of a denied fork, together.

Measured on Darwin under this repository's own containment profile: a command that
must fork exits 128 with `/bin/sh: fork: Operation not permitted`, while a missing
binary exits 127 with `No such file or directory` and fork fully available. The exit
code alone does not distinguish them.
"""

EVIDENCE_STREAM_BUDGET = 2000
"""Characters kept per output stream in a QC finding's evidence.

Per stream, not in total: a run that fails loudly on both is exactly the one whose
evidence must not be half-truncated.
"""


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class RuntimePortPool:
    env_name: str
    start: int
    end: int


@dataclass(frozen=True)
class IntegrationGitBoundary:
    git: str
    git_dir: Path
    object_dir: Path
    env: Mapping[str, str]
    git_digest: str
    git_size: int
    config_digest: str
    alternates_text: str
    global_attributes: bytes | None
    info_attributes: bytes | None
    merge_input_evidence: Mapping[str, Any]
    oid_length: int


@dataclass(frozen=True)
class AttributeSnapshot:
    content: bytes | None
    evidence: Mapping[str, Any]
