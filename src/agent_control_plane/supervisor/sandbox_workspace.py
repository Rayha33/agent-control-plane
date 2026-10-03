"""Bounded, no-follow snapshots and host-validated worker change sets.

This module is a filesystem primitive only. It does not launch a worker, create
an OS sandbox, mutate a registered worktree, or claim that worker isolation has
been proved.
"""

from __future__ import annotations

import hashlib
import os
import stat
import unicodedata
from bisect import bisect_left
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .common import SupervisorError, canonical_json, sha256

_COPY_CHUNK_BYTES = 64 * 1024
_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
_SAFE_OPEN_FLAGS = os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


@dataclass(frozen=True)
class SnapshotLimits:
    """Hard limits for a single input snapshot or worker result."""

    max_entries: int = 10_000
    max_total_bytes: int = 256 * 1024 * 1024
    max_file_bytes: int = 64 * 1024 * 1024
    max_path_bytes: int = 1_024
    max_symlink_bytes: int = 4_096
    max_depth: int = 256

    def __post_init__(self) -> None:
        values = (
            self.max_entries,
            self.max_total_bytes,
            self.max_file_bytes,
            self.max_path_bytes,
            self.max_symlink_bytes,
            self.max_depth,
        )
        if any(type(value) is not int or value < 1 for value in values):
            raise ValueError("snapshot limits must be positive integers")
        if self.max_file_bytes > self.max_total_bytes:
            raise ValueError("per-file limit cannot exceed total byte limit")


_DEFAULT_LIMITS = SnapshotLimits()


@dataclass(frozen=True)
class ManifestEntry:
    path: str
    kind: str
    mode: int
    size: int = 0
    content_sha256: str = ""
    symlink_target: str = ""

    def as_json(self) -> dict[str, Any]:
        result: dict[str, Any] = {"kind": self.kind, "mode": self.mode, "path": self.path}
        if self.kind == "file":
            result.update(size=self.size, sha256=self.content_sha256)
        elif self.kind == "symlink":
            result.update(size=self.size, target=self.symlink_target)
        return result


@dataclass(frozen=True)
class TreeManifest:
    entries: tuple[ManifestEntry, ...]
    total_bytes: int
    digest: str

    def validate(self, limits: SnapshotLimits = _DEFAULT_LIMITS) -> None:
        if type(self.entries) is not tuple:
            raise SupervisorError("invalid_snapshot_manifest", "snapshot entries are invalid")
        if type(self.total_bytes) is not int or self.total_bytes < 0:
            raise SupervisorError("invalid_snapshot_manifest", "snapshot byte count is invalid")
        if len(self.entries) > limits.max_entries or self.total_bytes > limits.max_total_bytes:
            raise SupervisorError(
                "workspace_limit_exceeded", "snapshot manifest exceeds configured limits"
            )
        if (
            type(self.digest) is not str
            or len(self.digest) != 64
            or any(character not in "0123456789abcdef" for character in self.digest)
        ):
            raise SupervisorError("invalid_snapshot_manifest", "snapshot digest is invalid")

        measured_bytes = 0
        previous_path: bytes | None = None
        for entry in self.entries:
            if (
                type(entry) is not ManifestEntry
                or type(entry.path) is not str
                or type(entry.kind) is not str
                or type(entry.mode) is not int
                or type(entry.size) is not int
                or type(entry.content_sha256) is not str
                or type(entry.symlink_target) is not str
            ):
                raise SupervisorError("invalid_snapshot_manifest", "snapshot entry is invalid")
            _validate_relative_path(entry.path, max_bytes=limits.max_path_bytes)
            path_bytes = entry.path.encode("utf-8")
            if previous_path is not None and path_bytes <= previous_path:
                raise SupervisorError(
                    "invalid_snapshot_manifest", "snapshot manifest paths are not canonical"
                )
            previous_path = path_bytes
            if len(entry.path.split("/")) > limits.max_depth:
                raise SupervisorError(
                    "workspace_limit_exceeded", "snapshot manifest nesting exceeds configured limit"
                )
            if entry.kind == "file":
                if (
                    entry.mode not in {0o644, 0o755}
                    or entry.size < 0
                    or entry.size > limits.max_file_bytes
                    or len(entry.content_sha256) != 64
                    or any(
                        character not in "0123456789abcdef" for character in entry.content_sha256
                    )
                    or entry.symlink_target
                ):
                    raise SupervisorError(
                        "invalid_snapshot_manifest", "file manifest entry is invalid"
                    )
                measured_bytes += entry.size
            elif entry.kind == "symlink":
                _validate_link_target(entry.path, entry.symlink_target, limits.max_symlink_bytes)
                if (
                    entry.mode != 0o777
                    or entry.content_sha256
                    or entry.size != len(entry.symlink_target.encode("utf-8"))
                ):
                    raise SupervisorError(
                        "invalid_snapshot_manifest", "symlink manifest entry is invalid"
                    )
                measured_bytes += entry.size
            elif (
                entry.kind != "directory"
                or entry.mode != 0o755
                or entry.size
                or entry.content_sha256
                or entry.symlink_target
            ):
                raise SupervisorError(
                    "invalid_snapshot_manifest", "directory manifest entry is invalid"
                )
            if measured_bytes > limits.max_total_bytes:
                raise SupervisorError(
                    "workspace_limit_exceeded", "snapshot manifest exceeds configured limits"
                )
        if measured_bytes != self.total_bytes:
            raise SupervisorError("invalid_snapshot_manifest", "snapshot byte count mismatch")
        _validate_tree_shape(self.entries)
        _validate_symlink_graph(self.entries)
        rebuilt = _make_manifest(self.entries, self.total_bytes)
        if rebuilt.digest != self.digest:
            raise SupervisorError("invalid_snapshot_manifest", "snapshot manifest digest mismatch")

    def as_json(self) -> dict[str, Any]:
        return {
            "version": 1,
            "total_bytes": self.total_bytes,
            "entries": [entry.as_json() for entry in self.entries],
            "sha256": self.digest,
        }


@dataclass(frozen=True)
class Snapshot:
    root: Path
    manifest: TreeManifest


@dataclass(frozen=True)
class Change:
    path: str
    action: str
    kind: str
    mode: int = 0
    content: bytes = b""
    symlink_target: str = ""

    @property
    def content_sha256(self) -> str:
        return sha256(self.content) if self.kind == "file" and self.action != "delete" else ""

    def as_json(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "action": self.action,
            "kind": self.kind,
            "mode": self.mode,
            "path": self.path,
        }
        if self.kind == "file" and self.action != "delete":
            result.update(size=len(self.content), sha256=self.content_sha256)
        elif self.kind == "symlink" and self.action != "delete":
            result.update(size=len(self.symlink_target.encode("utf-8")), target=self.symlink_target)
        return result


@dataclass(frozen=True)
class ChangeSet:
    baseline_digest: str
    result_digest: str
    changes: tuple[Change, ...]
    total_bytes: int
    digest: str

    def validate(self, limits: SnapshotLimits = _DEFAULT_LIMITS) -> None:
        if type(self.changes) is not tuple:
            raise SupervisorError("invalid_change_set", "change set entries are invalid")
        if type(self.total_bytes) is not int or self.total_bytes < 0:
            raise SupervisorError("invalid_change_set", "change set byte count is invalid")
        if len(self.changes) > limits.max_entries or self.total_bytes > limits.max_total_bytes:
            raise SupervisorError(
                "workspace_limit_exceeded", "change set exceeds configured limits"
            )
        for digest in (self.baseline_digest, self.result_digest, self.digest):
            if (
                type(digest) is not str
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                raise SupervisorError("invalid_change_set", "change set digest is invalid")

        measured_bytes = 0
        previous_path: bytes | None = None
        for change in self.changes:
            if (
                type(change) is not Change
                or type(change.path) is not str
                or type(change.action) is not str
                or type(change.kind) is not str
                or type(change.mode) is not int
                or type(change.content) is not bytes
                or type(change.symlink_target) is not str
            ):
                raise SupervisorError("invalid_change_set", "change set entry is invalid")
            _validate_relative_path(change.path, max_bytes=limits.max_path_bytes)
            path_bytes = change.path.encode("utf-8")
            if previous_path is not None and path_bytes <= previous_path:
                raise SupervisorError("invalid_change_set", "change set paths are not canonical")
            previous_path = path_bytes
            if len(change.path.split("/")) > limits.max_depth:
                raise SupervisorError("workspace_limit_exceeded", "change path is too deep")
            if change.action not in {"create", "modify", "delete"}:
                raise SupervisorError("invalid_change_set", "change set action is invalid")
            if change.kind not in {"file", "directory", "symlink"}:
                raise SupervisorError("invalid_change_set", "change set node type is invalid")
            if change.action == "delete":
                if change.content or change.symlink_target or change.mode:
                    raise SupervisorError("invalid_change_set", "delete change carries output data")
            elif change.kind == "file":
                if (
                    change.symlink_target
                    or change.mode not in {0o644, 0o755}
                    or len(change.content) > limits.max_file_bytes
                ):
                    raise SupervisorError("invalid_change_set", "file change metadata is invalid")
            elif change.kind == "directory":
                if change.content or change.symlink_target or change.mode != 0o755:
                    raise SupervisorError(
                        "invalid_change_set", "directory change metadata is invalid"
                    )
            elif (
                change.content
                or change.mode != 0o777
                or _validate_link_target(
                    change.path, change.symlink_target, limits.max_symlink_bytes
                )
                is None
            ):
                raise SupervisorError("invalid_change_set", "symlink change metadata is invalid")
            if change.action != "delete":
                measured_bytes += (
                    len(change.content)
                    if change.kind == "file"
                    else len(change.symlink_target.encode("utf-8"))
                )
                if measured_bytes > limits.max_total_bytes:
                    raise SupervisorError(
                        "workspace_limit_exceeded", "change set exceeds configured limits"
                    )
        if measured_bytes != self.total_bytes:
            raise SupervisorError("invalid_change_set", "change set byte count mismatch")
        rebuilt = _make_change_set(
            self.baseline_digest,
            self.result_digest,
            self.changes,
            self.total_bytes,
        )
        if rebuilt.digest != self.digest:
            raise SupervisorError("invalid_change_set", "change set digest mismatch")


@dataclass
class _CaptureState:
    limits: SnapshotLimits
    baseline: dict[str, ManifestEntry] | None = None
    entries: list[ManifestEntry] | None = None
    changed_content: dict[str, bytes] | None = None
    root_device: int | None = None
    total_bytes: int = 0
    changed_bytes: int = 0
    entry_count: int = 0
    pending_names: int = 0
    created_nodes: dict[str, os.stat_result] | None = None


def copy_snapshot(
    source: str | Path,
    destination: str | Path,
    *,
    limits: SnapshotLimits = _DEFAULT_LIMITS,
) -> Snapshot:
    """Copy a registered tree to a new private directory without following links.

    The source root's top-level .git entry is omitted. Nested Git administration,
    unsafe links, special nodes, unstable reads, and limit overflow fail closed.
    Files are copied into new inodes; hard-link relationships are never retained.
    """

    destination_path = Path(destination)
    destination_parent = destination_path.parent.resolve(strict=True)
    destination_name = destination_path.name
    _validate_component(destination_name, max_bytes=limits.max_path_bytes)
    source_parent_fd, source_name, source_fd = _open_existing_directory(source)
    destination_parent_fd: int | None = None
    created_stat: os.stat_result | None = None
    destination_fd: int | None = None
    state = _CaptureState(limits, entries=[], changed_content={}, created_nodes={})
    try:
        destination_parent_fd = _open_directory_path(destination_parent)
        source_root_path = Path(source).parent.resolve(strict=True) / source_name
        destination_root_path = destination_parent / destination_name
        if (
            source_root_path == destination_root_path
            or source_root_path in destination_root_path.parents
            or destination_root_path in source_root_path.parents
        ):
            raise SupervisorError(
                "invalid_snapshot_destination", "snapshot source and destination overlap"
            )
        try:
            os.stat(destination_name, dir_fd=destination_parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise SupervisorError(
                "snapshot_destination_exists", "snapshot destination must not already exist"
            )
        try:
            os.mkdir(destination_name, 0o700, dir_fd=destination_parent_fd)
        except OSError as error:
            raise SupervisorError(
                "snapshot_destination_unavailable", "snapshot destination could not be created"
            ) from error
        created_stat = os.stat(
            destination_name, dir_fd=destination_parent_fd, follow_symlinks=False
        )
        destination_fd = os.open(
            destination_name,
            _DIRECTORY_FLAGS | _SAFE_OPEN_FLAGS,
            dir_fd=destination_parent_fd,
        )
        if not _same_node(created_stat, os.fstat(destination_fd), directory=True):
            raise SupervisorError(
                "snapshot_destination_race", "snapshot destination changed during creation"
            )

        if state.created_nodes is not None:
            state.created_nodes[""] = created_stat
        _walk_tree(
            source_fd,
            destination_fd,
            parent_fd=source_parent_fd,
            node_name=source_name,
            relative="",
            state=state,
            root=True,
        )
        _assert_source_stable(source_parent_fd, source_name, os.fstat(source_fd))
        manifest = _make_manifest(tuple(state.entries or ()), state.total_bytes)
        manifest.validate(limits)
        _validate_tree_shape(manifest.entries)
        _validate_symlink_graph(manifest.entries)
        verification_state = _CaptureState(limits, entries=[], changed_content={})
        _walk_tree(
            destination_fd,
            None,
            parent_fd=destination_parent_fd,
            node_name=destination_name,
            relative="",
            state=verification_state,
            root=True,
            exclude_root_git=False,
            require_canonical_modes=True,
        )
        verified_manifest = _make_manifest(
            tuple(verification_state.entries or ()), verification_state.total_bytes
        )
        if verified_manifest != manifest:
            raise SupervisorError(
                "snapshot_destination_mismatch",
                "private snapshot does not match its source manifest",
            )
        os.fsync(destination_fd)
        assert destination_parent_fd is not None and created_stat is not None
        _assert_destination_directory_stable(
            destination_parent_fd,
            destination_name,
            destination_fd,
            created_stat,
        )
        canonical_destination = destination_parent / destination_name
        return Snapshot(canonical_destination, manifest)
    except BaseException:
        if created_stat is not None:
            if destination_parent_fd is not None:
                _remove_created_tree(
                    destination_parent_fd,
                    destination_name,
                    created_stat,
                    expected_nodes=state.created_nodes,
                )
        raise
    finally:
        if destination_fd is not None:
            os.close(destination_fd)
        if destination_parent_fd is not None:
            os.close(destination_parent_fd)
        os.close(source_fd)
        os.close(source_parent_fd)


def read_snapshot_files(
    snapshot: Snapshot,
    *,
    limits: SnapshotLimits = _DEFAULT_LIMITS,
) -> dict[str, bytes]:
    """Read and verify every regular file in an immutable private snapshot.

    This reopens each path with no-follow descriptor-relative traversal, checks
    file and directory identity while reading, and requires the complete tree
    to reproduce the snapshot's original manifest. It is intended for trusted
    host-side consumers such as candidate Git-object construction.
    """

    if type(snapshot) is not Snapshot:
        raise SupervisorError("invalid_snapshot", "snapshot handle is invalid")
    snapshot.manifest.validate(limits)
    parent_fd, name, root_fd = _open_existing_directory(snapshot.root)
    try:
        state = _CaptureState(limits, baseline={}, entries=[], changed_content={})
        _walk_tree(
            root_fd,
            None,
            parent_fd=parent_fd,
            node_name=name,
            relative="",
            state=state,
            root=True,
            exclude_root_git=False,
            require_canonical_modes=True,
        )
        _assert_source_stable(parent_fd, name, os.fstat(root_fd))
        observed = _make_manifest(tuple(state.entries or ()), state.total_bytes)
        observed.validate(limits)
        if observed != snapshot.manifest:
            raise SupervisorError(
                "snapshot_changed", "private snapshot no longer matches its captured manifest"
            )
        files = state.changed_content or {}
        if set(files) != {entry.path for entry in observed.entries if entry.kind == "file"}:
            raise SupervisorError(
                "snapshot_changed", "private snapshot file contents are incomplete"
            )
        return files
    finally:
        os.close(root_fd)
        os.close(parent_fd)


def collect_changes(
    baseline: TreeManifest,
    output_root: str | Path,
    *,
    write_set_rules: Sequence[tuple[str, bool, bool]],
    limits: SnapshotLimits = _DEFAULT_LIMITS,
    path_matches: Callable[..., bool] | None = None,
) -> ChangeSet:
    """Capture bounded output and validate every changed path against write-set rules.

    Worker .git metadata at the output root is ignored and never parsed. Worker
    object IDs, configuration, hooks, filters, and hashes are not consumed.
    """

    baseline.validate(limits)
    baseline_map = {entry.path: entry for entry in baseline.entries}
    parent_fd, name, root_fd = _open_existing_directory(output_root)
    try:
        state = _CaptureState(
            limits,
            baseline=baseline_map,
            entries=[],
            changed_content={},
        )
        _walk_tree(
            root_fd,
            None,
            parent_fd=parent_fd,
            node_name=name,
            relative="",
            state=state,
            root=True,
        )
        _assert_source_stable(parent_fd, name, os.fstat(root_fd))
        result_manifest = _make_manifest(tuple(state.entries or ()), state.total_bytes)
        result_manifest.validate(limits)
        after = {entry.path: entry for entry in result_manifest.entries}
        before = {entry.path: entry for entry in baseline.entries}
        rules = tuple(write_set_rules)
        if any(
            not isinstance(rule, (tuple, list))
            or len(rule) != 3
            or not isinstance(rule[0], str)
            or not isinstance(rule[1], bool)
            or not isinstance(rule[2], bool)
            for rule in rules
        ):
            raise SupervisorError("invalid_write_set", "declared write-set rules are invalid")
        matcher = path_matches or _existing_write_set_matcher
        changes: list[Change] = []
        changed_paths = [
            path
            for path in sorted(set(before) | set(after), key=lambda value: value.encode("utf-8"))
            if before.get(path) != after.get(path)
        ]
        directly_authorized = {
            path: any(
                matcher(path, resource, fold=fold, is_logical=is_logical)
                for resource, fold, is_logical in rules
            )
            for path in changed_paths
        }
        authorized_created_leaf_paths = sorted(
            candidate
            for candidate in changed_paths
            if before.get(candidate) is None
            and after.get(candidate) is not None
            and after[candidate].kind != "directory"
            and directly_authorized[candidate]
        )
        baseline_leaf_change_paths = sorted(
            candidate
            for candidate in changed_paths
            if before.get(candidate) is not None and before[candidate].kind != "directory"
        )
        authorized_deleted_leaf_paths = sorted(
            candidate
            for candidate in baseline_leaf_change_paths
            if after.get(candidate) is None and directly_authorized[candidate]
        )
        for path in changed_paths:
            previous = before.get(path)
            current = after.get(path)
            authorized = directly_authorized[path]
            if (
                not authorized
                and previous is None
                and current is not None
                and current.kind == "directory"
            ):
                # A new nonempty parent directory is structural when it is an
                # ancestor of a directly authorized changed leaf. Every other
                # changed descendant is checked independently; an empty
                # directory still needs an explicit write-set grant.
                created_start, created_end = _descendant_path_range(
                    authorized_created_leaf_paths, path
                )
                authorized = created_start < created_end
            if (
                not authorized
                and previous is not None
                and previous.kind == "directory"
                and current is None
            ):
                # Removing a directory is structural only when every changed
                # baseline leaf below it is an explicitly authorized deletion.
                # An empty directory deletion still needs an explicit grant.
                leaves_start, leaves_end = _descendant_path_range(baseline_leaf_change_paths, path)
                deleted_start, deleted_end = _descendant_path_range(
                    authorized_deleted_leaf_paths, path
                )
                descendant_leaf_count = leaves_end - leaves_start
                authorized_deletion_count = deleted_end - deleted_start
                authorized = (
                    descendant_leaf_count > 0 and descendant_leaf_count == authorized_deletion_count
                )
            if not authorized:
                raise SupervisorError(
                    "undeclared_write",
                    f"worker result path {path!r} is outside the declared write set",
                )
            action = "create" if previous is None else "delete" if current is None else "modify"
            if current is None:
                changes.append(Change(path, action, previous.kind))
            elif current.kind == "directory":
                changes.append(Change(path, action, "directory", 0o755))
            elif current.kind == "file":
                content = (state.changed_content or {}).get(path)
                if content is None or sha256(content) != current.content_sha256:
                    raise SupervisorError(
                        "unstable_worker_output", "worker file changed while result was captured"
                    )
                changes.append(Change(path, action, "file", current.mode, content))
            else:
                target_bytes = len(current.symlink_target.encode("utf-8"))
                state.changed_bytes += target_bytes
                if state.changed_bytes > state.limits.max_total_bytes:
                    raise SupervisorError(
                        "workspace_limit_exceeded",
                        "worker change set exceeds configured byte limit",
                    )
                changes.append(Change(path, action, "symlink", 0o777, b"", current.symlink_target))
        change_set = _make_change_set(
            baseline.digest,
            result_manifest.digest,
            tuple(changes),
            state.changed_bytes,
        )
        change_set.validate(limits)
        reconstructed = apply_changes_to_manifest(baseline, change_set, limits=limits)
        if reconstructed != result_manifest:
            raise SupervisorError(
                "incomplete_change_set", "change set did not reproduce captured worker output"
            )
        return change_set
    finally:
        os.close(root_fd)
        os.close(parent_fd)


def apply_changes_to_manifest(
    baseline: TreeManifest,
    change_set: ChangeSet,
    *,
    limits: SnapshotLimits = _DEFAULT_LIMITS,
) -> TreeManifest:
    """Rebuild and verify the exact result manifest from a baseline and changes.

    This is a host-side validation primitive, not a filesystem or Git importer.
    It proves that the declared change set is complete enough to reproduce the
    worker result digest, including directory-only changes.
    """

    baseline.validate(limits)
    change_set.validate(limits)
    if baseline.digest != change_set.baseline_digest:
        raise SupervisorError("stale_worker_result", "change set baseline does not match")

    entries = {entry.path: entry for entry in baseline.entries}
    for change in change_set.changes:
        existing = entries.get(change.path)
        if change.action == "create" and existing is not None:
            raise SupervisorError("invalid_change_set", "create change already exists in baseline")
        if change.action in {"modify", "delete"} and existing is None:
            raise SupervisorError("invalid_change_set", "change path is absent from baseline")

    # Remove old nodes deepest-first so directory deletions and type changes do
    # not leave descendants under a non-directory parent during reconstruction.
    removals = sorted(
        (change for change in change_set.changes if change.action in {"modify", "delete"}),
        key=lambda change: (-change.path.count("/"), change.path.encode("utf-8")),
    )
    for change in removals:
        entries.pop(change.path)

    additions = sorted(
        (change for change in change_set.changes if change.action != "delete"),
        key=lambda change: (change.path.count("/"), change.path.encode("utf-8")),
    )
    for change in additions:
        if change.kind == "directory":
            entry = ManifestEntry(change.path, "directory", 0o755)
        elif change.kind == "file":
            entry = ManifestEntry(
                change.path,
                "file",
                change.mode,
                len(change.content),
                sha256(change.content),
            )
        else:
            entry = ManifestEntry(
                change.path,
                "symlink",
                0o777,
                len(change.symlink_target.encode("utf-8")),
                "",
                change.symlink_target,
            )
        if change.path in entries:
            raise SupervisorError("path_collision", "change set result contains a path collision")
        entries[change.path] = entry

    ordered = tuple(sorted(entries.values(), key=lambda entry: entry.path.encode("utf-8")))
    _validate_tree_shape(ordered)
    _validate_symlink_graph(ordered)
    total_bytes = sum(entry.size for entry in ordered if entry.kind in {"file", "symlink"})
    result = _make_manifest(ordered, total_bytes)
    result.validate(limits)
    if result.digest != change_set.result_digest:
        raise SupervisorError(
            "incomplete_change_set", "change set does not reproduce the declared result digest"
        )
    return result


def validate_change_set_write_set(
    baseline: TreeManifest,
    change_set: ChangeSet,
    *,
    write_set_rules: Sequence[tuple[str, bool, bool]],
    limits: SnapshotLimits = _DEFAULT_LIMITS,
    path_matches: Callable[..., bool] | None = None,
) -> TreeManifest:
    """Revalidate a complete change set against the declared write set.

    This is deliberately callable by host-side import code even when the
    change-set object did not originate in ``collect_changes``. Nonempty
    directory ancestors may inherit authority from an authorized changed
    leaf; directory deletion is structural only when every changed baseline
    leaf below it is an authorized deletion.
    """

    result = apply_changes_to_manifest(baseline, change_set, limits=limits)
    rules = tuple(write_set_rules)
    if any(
        not isinstance(rule, (tuple, list))
        or len(rule) != 3
        or not isinstance(rule[0], str)
        or not isinstance(rule[1], bool)
        or not isinstance(rule[2], bool)
        for rule in rules
    ):
        raise SupervisorError("invalid_write_set", "declared write-set rules are invalid")

    before = {entry.path: entry for entry in baseline.entries}
    after = {entry.path: entry for entry in result.entries}
    changed_paths = sorted(
        (path for path in set(before) | set(after) if before.get(path) != after.get(path)),
        key=lambda value: value.encode("utf-8"),
    )
    matcher = path_matches or _existing_write_set_matcher
    directly_authorized = {
        path: any(
            matcher(path, resource, fold=fold, is_logical=is_logical)
            for resource, fold, is_logical in rules
        )
        for path in changed_paths
    }
    authorized_created_leaf_paths = sorted(
        path
        for path in changed_paths
        if before.get(path) is None
        and after.get(path) is not None
        and after[path].kind != "directory"
        and directly_authorized[path]
    )
    baseline_leaf_change_paths = sorted(
        path
        for path in changed_paths
        if before.get(path) is not None and before[path].kind != "directory"
    )
    authorized_deleted_leaf_paths = sorted(
        path
        for path in baseline_leaf_change_paths
        if after.get(path) is None and directly_authorized[path]
    )

    for path in changed_paths:
        previous = before.get(path)
        current = after.get(path)
        authorized = directly_authorized[path]
        if (
            not authorized
            and previous is None
            and current is not None
            and current.kind == "directory"
        ):
            start, end = _descendant_path_range(authorized_created_leaf_paths, path)
            authorized = start < end
        if (
            not authorized
            and previous is not None
            and previous.kind == "directory"
            and current is None
        ):
            leaf_start, leaf_end = _descendant_path_range(baseline_leaf_change_paths, path)
            deleted_start, deleted_end = _descendant_path_range(authorized_deleted_leaf_paths, path)
            leaf_count = leaf_end - leaf_start
            authorized_deletion_count = deleted_end - deleted_start
            authorized = leaf_count > 0 and leaf_count == authorized_deletion_count
        if not authorized:
            raise SupervisorError(
                "undeclared_write",
                f"worker result path {path!r} is outside the declared write set",
            )
    return result


def _walk_tree(
    source_fd: int,
    destination_fd: int | None,
    *,
    parent_fd: int,
    node_name: str,
    relative: str,
    state: _CaptureState,
    root: bool = False,
    depth: int = 0,
    exclude_root_git: bool = True,
    require_canonical_modes: bool = False,
) -> None:
    source_before = os.fstat(source_fd)
    if not stat.S_ISDIR(source_before.st_mode):
        raise SupervisorError(
            "unsafe_workspace_node", "workspace root or parent is not a directory"
        )
    if require_canonical_modes and root and stat.S_IMODE(source_before.st_mode) != 0o700:
        raise SupervisorError(
            "snapshot_destination_mismatch", "private snapshot root permissions changed"
        )
    if state.root_device is None:
        state.root_device = source_before.st_dev
    elif source_before.st_dev != state.root_device:
        raise SupervisorError("unsafe_workspace_mount", "workspace crosses a filesystem boundary")
    if depth > state.limits.max_depth:
        raise SupervisorError(
            "workspace_limit_exceeded", "workspace nesting exceeds configured limit"
        )

    names: list[str] = []
    try:
        with os.scandir(source_fd) as children:
            for child in children:
                name = child.name
                if root and exclude_root_git and name == ".git":
                    continue
                if name.casefold() == ".git":
                    raise SupervisorError(
                        "nested_git_metadata", "Git administration aliases are not accepted"
                    )
                if state.entry_count + state.pending_names >= state.limits.max_entries:
                    raise SupervisorError(
                        "workspace_limit_exceeded", "workspace exceeds configured entry limit"
                    )
                names.append(name)
                state.pending_names += 1
        names.sort(key=lambda value: value.encode("utf-8"))
    except SupervisorError:
        raise
    except (OSError, UnicodeEncodeError) as error:
        raise SupervisorError(
            "unstable_workspace", "workspace directory could not be listed"
        ) from error

    for name in names:
        state.pending_names -= 1
        _validate_component(name, max_bytes=state.limits.max_path_bytes)
        path = f"{relative}/{name}" if relative else name
        _validate_relative_path(path, max_bytes=state.limits.max_path_bytes)
        try:
            item_stat = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        except OSError as error:
            raise SupervisorError(
                "unstable_workspace", "workspace entry changed during capture"
            ) from error
        if item_stat.st_dev != state.root_device:
            raise SupervisorError(
                "unsafe_workspace_mount", "workspace crosses a filesystem boundary"
            )

        if stat.S_ISDIR(item_stat.st_mode):
            if require_canonical_modes and stat.S_IMODE(item_stat.st_mode) != 0o755:
                raise SupervisorError(
                    "snapshot_destination_mismatch",
                    "private snapshot directory permissions changed",
                )
            child_source_fd = _open_child_directory(source_fd, name, item_stat)
            child_destination_fd: int | None = None
            created_child: os.stat_result | None = None
            try:
                if destination_fd is not None:
                    try:
                        os.mkdir(name, 0o700, dir_fd=destination_fd)
                        created_child = os.stat(name, dir_fd=destination_fd, follow_symlinks=False)
                        if not stat.S_ISDIR(created_child.st_mode):
                            raise SupervisorError(
                                "snapshot_destination_race",
                                "snapshot directory changed during creation",
                            )
                        if state.created_nodes is not None:
                            state.created_nodes[path] = created_child
                        child_destination_fd = os.open(
                            name,
                            _DIRECTORY_FLAGS | _SAFE_OPEN_FLAGS,
                            dir_fd=destination_fd,
                        )
                        opened_child = os.fstat(child_destination_fd)
                        current_child = os.stat(name, dir_fd=destination_fd, follow_symlinks=False)
                        if not (
                            _same_identity(created_child, opened_child, directory=True)
                            and _same_identity(opened_child, current_child, directory=True)
                        ):
                            raise SupervisorError(
                                "snapshot_destination_race",
                                "snapshot directory changed while opening",
                            )
                    except SupervisorError:
                        if child_destination_fd is not None:
                            os.close(child_destination_fd)
                            child_destination_fd = None
                        raise
                    except OSError as error:
                        if child_destination_fd is not None:
                            os.close(child_destination_fd)
                            child_destination_fd = None
                        raise SupervisorError(
                            "snapshot_copy_failed", "snapshot directory could not be created"
                        ) from error
                _append_entry(
                    state,
                    ManifestEntry(path, "directory", 0o755),
                )
                _walk_tree(
                    child_source_fd,
                    child_destination_fd,
                    parent_fd=source_fd,
                    node_name=name,
                    relative=path,
                    state=state,
                    depth=depth + 1,
                    require_canonical_modes=require_canonical_modes,
                )
                if destination_fd is not None and child_destination_fd is not None:
                    os.fchmod(child_destination_fd, 0o755)
                    os.fsync(child_destination_fd)
                    assert created_child is not None
                    _assert_destination_directory_stable(
                        destination_fd,
                        name,
                        child_destination_fd,
                        created_child,
                    )
            finally:
                if child_destination_fd is not None:
                    os.close(child_destination_fd)
                os.close(child_source_fd)
            _assert_source_stable(source_fd, name, item_stat)
            continue

        if stat.S_ISREG(item_stat.st_mode):
            expected_mode = 0o755 if item_stat.st_mode & 0o111 else 0o644
            if require_canonical_modes and stat.S_IMODE(item_stat.st_mode) != expected_mode:
                raise SupervisorError(
                    "snapshot_destination_mismatch",
                    "private snapshot file permissions changed",
                )
            entry, captured_content = _capture_regular_file(
                source_fd,
                name,
                item_stat,
                destination_fd,
                path,
                state,
            )
            _append_entry(state, entry)
            if captured_content is not None and state.baseline is not None:
                previous = state.baseline.get(path)
                if previous != entry:
                    state.changed_bytes += len(captured_content)
                    if state.changed_bytes > state.limits.max_total_bytes:
                        raise SupervisorError(
                            "workspace_limit_exceeded",
                            "worker change set exceeds configured byte limit",
                        )
                    assert state.changed_content is not None
                    state.changed_content[path] = captured_content
            continue

        if stat.S_ISLNK(item_stat.st_mode):
            try:
                target = os.readlink(name, dir_fd=source_fd)
                _validate_link_target(path, target, state.limits.max_symlink_bytes)
                after = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
            except (OSError, UnicodeEncodeError) as error:
                raise SupervisorError(
                    "unsafe_symlink", "workspace symlink changed or has an invalid target"
                ) from error
            if not _same_node(item_stat, after, symlink=True):
                raise SupervisorError(
                    "unstable_workspace", "workspace symlink changed during capture"
                )
            target_bytes = target.encode("utf-8")
            state.total_bytes += len(target_bytes)
            if state.total_bytes > state.limits.max_total_bytes:
                raise SupervisorError(
                    "workspace_limit_exceeded", "workspace exceeds configured byte limit"
                )
            if destination_fd is not None:
                try:
                    os.symlink(target, name, dir_fd=destination_fd)
                    if state.created_nodes is not None:
                        state.created_nodes[path] = os.stat(
                            name, dir_fd=destination_fd, follow_symlinks=False
                        )
                except OSError as error:
                    raise SupervisorError(
                        "snapshot_copy_failed", "snapshot symlink could not be created"
                    ) from error
            entry = ManifestEntry(path, "symlink", 0o777, len(target_bytes), "", target)
            _append_entry(state, entry)
            continue

        raise SupervisorError(
            "unsafe_workspace_node",
            f"special filesystem node at {path!r} is not accepted",
        )

    source_after = os.fstat(source_fd)
    if not _same_node(source_before, source_after, directory=True):
        raise SupervisorError("unstable_workspace", "workspace directory changed during capture")


def _capture_regular_file(
    parent_fd: int,
    name: str,
    item_stat: os.stat_result,
    destination_parent_fd: int | None,
    path: str,
    state: _CaptureState,
) -> tuple[ManifestEntry, bytes | None]:
    if item_stat.st_size < 0 or item_stat.st_size > state.limits.max_file_bytes:
        raise SupervisorError(
            "workspace_limit_exceeded", f"workspace file {path!r} exceeds configured per-file limit"
        )
    state.total_bytes += item_stat.st_size
    if state.total_bytes > state.limits.max_total_bytes:
        raise SupervisorError("workspace_limit_exceeded", "workspace exceeds configured byte limit")
    flags = os.O_RDONLY | _SAFE_OPEN_FLAGS | getattr(os, "O_NONBLOCK", 0)
    try:
        source_file_fd = os.open(name, flags, dir_fd=parent_fd)
    except OSError as error:
        raise SupervisorError(
            "unstable_workspace", "workspace file could not be opened safely"
        ) from error

    destination_file_fd: int | None = None
    try:
        before = os.fstat(source_file_fd)
        if not _same_node(item_stat, before, regular=True):
            raise SupervisorError("unstable_workspace", "workspace file changed before it was read")
        if destination_parent_fd is not None:
            try:
                destination_file_fd = os.open(
                    name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | _SAFE_OPEN_FLAGS
                    | getattr(os, "O_NONBLOCK", 0),
                    0o600,
                    dir_fd=destination_parent_fd,
                )
                if state.created_nodes is not None:
                    state.created_nodes[path] = os.fstat(destination_file_fd)
            except OSError as error:
                raise SupervisorError(
                    "snapshot_copy_failed", "snapshot file could not be created"
                ) from error

        digest = hashlib.sha256()
        captured = bytearray()
        actual_size = 0
        while True:
            chunk = os.read(source_file_fd, _COPY_CHUNK_BYTES)
            if not chunk:
                break
            actual_size += len(chunk)
            if actual_size > state.limits.max_file_bytes:
                raise SupervisorError(
                    "workspace_limit_exceeded", f"workspace file {path!r} grew beyond its limit"
                )
            digest.update(chunk)
            if destination_file_fd is not None:
                _write_all(destination_file_fd, chunk)
            else:
                captured.extend(chunk)
        after = os.fstat(source_file_fd)
        _assert_source_stable(parent_fd, name, item_stat)
        if actual_size != item_stat.st_size or not _same_node(before, after, regular=True):
            raise SupervisorError("unstable_workspace", "workspace file changed during capture")

        mode = 0o755 if item_stat.st_mode & 0o111 else 0o644
        if destination_file_fd is not None:
            os.fchmod(destination_file_fd, mode)
            os.fsync(destination_file_fd)
        entry = ManifestEntry(path, "file", mode, actual_size, digest.hexdigest())
        previous = state.baseline.get(path) if state.baseline is not None else None
        changed = previous != entry
        return entry, bytes(captured) if destination_file_fd is None and changed else None
    finally:
        if destination_file_fd is not None:
            os.close(destination_file_fd)
        os.close(source_file_fd)


def _append_entry(state: _CaptureState, entry: ManifestEntry) -> None:
    state.entry_count += 1
    if state.entry_count > state.limits.max_entries:
        raise SupervisorError(
            "workspace_limit_exceeded", "workspace exceeds configured entry limit"
        )
    assert state.entries is not None
    state.entries.append(entry)


def _make_manifest(entries: Sequence[ManifestEntry], total_bytes: int) -> TreeManifest:
    ordered = tuple(sorted(entries, key=lambda entry: entry.path.encode("utf-8")))
    payload = {
        "version": 1,
        "total_bytes": total_bytes,
        "entries": [entry.as_json() for entry in ordered],
    }
    digest = sha256(canonical_json(payload).encode("utf-8"))
    return TreeManifest(ordered, total_bytes, digest)


def _make_change_set(
    baseline_digest: str,
    result_digest: str,
    changes: Sequence[Change],
    total_bytes: int,
) -> ChangeSet:
    ordered = tuple(sorted(changes, key=lambda change: change.path.encode("utf-8")))
    payload = {
        "version": 1,
        "baseline_sha256": baseline_digest,
        "result_sha256": result_digest,
        "total_bytes": total_bytes,
        "changes": [change.as_json() for change in ordered],
    }
    digest = sha256(canonical_json(payload).encode("utf-8"))
    return ChangeSet(baseline_digest, result_digest, ordered, total_bytes, digest)


def _descendant_path_range(sorted_paths: Sequence[str], directory: str) -> tuple[int, int]:
    """Return the sorted-path slice strictly below a canonical directory path."""

    # '/' sorts before '0', so this bounds the prefix range without scanning
    # descendants. All paths were validated as relative UTF-8 before indexing.
    return bisect_left(sorted_paths, directory + "/"), bisect_left(sorted_paths, directory + "0")


def _validate_tree_shape(entries: Sequence[ManifestEntry]) -> None:
    by_path: dict[str, ManifestEntry] = {}
    for entry in entries:
        _validate_relative_path(entry.path, max_bytes=1_024)
        if entry.path in by_path:
            raise SupervisorError("path_collision", "snapshot manifest contains duplicate paths")
        by_path[entry.path] = entry
    for path, entry in by_path.items():
        parts = path.split("/")
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            parent_entry = by_path.get(parent)
            if parent_entry is None or parent_entry.kind != "directory":
                raise SupervisorError(
                    "path_collision", f"missing or non-directory parent {parent!r}"
                )
        if entry.kind not in {"file", "directory", "symlink"}:
            raise SupervisorError("unsafe_workspace_node", "manifest node type is invalid")


def _validate_symlink_graph(entries: Sequence[ManifestEntry]) -> None:
    links = {entry.path: entry.symlink_target for entry in entries if entry.kind == "symlink"}
    for link_path in links:
        parent = link_path.split("/")[:-1]
        pending = deque(links[link_path].split("/"))
        current = list(parent)
        seen = {link_path}
        hops = 0
        while pending:
            part = pending.popleft()
            if part in {"", "."}:
                continue
            if part == "..":
                if not current:
                    raise SupervisorError("unsafe_symlink", "symlink target escapes its root")
                current.pop()
                continue
            current.append(part)
            prefix = "/".join(current)
            chained = links.get(prefix)
            if chained is not None:
                if prefix in seen or hops >= 40:
                    raise SupervisorError("unsafe_symlink", "symlink chain cycles or is too deep")
                seen.add(prefix)
                current.pop()
                pending = deque(chained.split("/") + list(pending))
                hops += 1


def _validate_link_target(path: str, target: str, max_bytes: int) -> str:
    try:
        encoded = target.encode("utf-8")
    except UnicodeEncodeError as error:
        raise SupervisorError("unsafe_symlink", "symlink target is not valid UTF-8") from error
    if (
        not target
        or len(encoded) > max_bytes
        or target.startswith("/")
        or "\\" in target
        or any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in target)
    ):
        raise SupervisorError("unsafe_symlink", "symlink target is absolute or invalid")
    stack = path.split("/")[:-1]
    for part in target.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not stack:
                raise SupervisorError("unsafe_symlink", "symlink target escapes its root")
            stack.pop()
        else:
            if part.casefold() == ".git":
                raise SupervisorError("nested_git_metadata", "symlink target names Git metadata")
            stack.append(part)
    return "/".join(stack)


def _validate_relative_path(path: str, *, max_bytes: int) -> None:
    try:
        encoded = path.encode("utf-8")
    except (AttributeError, UnicodeEncodeError) as error:
        raise SupervisorError(
            "unsafe_workspace_path", "workspace path is not valid UTF-8"
        ) from error
    parts = path.split("/")
    if (
        not path
        or len(encoded) > max_bytes
        or path.startswith("/")
        or "\\" in path
        or unicodedata.normalize("NFC", path) != path
        or any(part in {"", ".", ".."} for part in parts)
        or any(part.casefold() == ".git" for part in parts)
        or any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in path)
    ):
        raise SupervisorError(
            "unsafe_workspace_path", "workspace path is not canonical and relative"
        )


def _validate_component(name: str, *, max_bytes: int) -> None:
    if "/" in name or name in {"", ".", ".."}:
        raise SupervisorError("unsafe_workspace_path", "workspace entry name is invalid")
    _validate_relative_path(name, max_bytes=max_bytes)


def _open_existing_directory(path: str | Path) -> tuple[int, str, int]:
    value = Path(path)
    name = value.name
    parent = value.parent.resolve(strict=True)
    parent_fd = _open_directory_path(parent)
    root_fd = -1
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            raise SupervisorError("unsafe_workspace_root", "workspace root is not a real directory")
        root_fd = os.open(name, _DIRECTORY_FLAGS | _SAFE_OPEN_FLAGS, dir_fd=parent_fd)
        if not _same_node(before, os.fstat(root_fd), directory=True):
            raise SupervisorError("unstable_workspace", "workspace root changed while opening")
        return parent_fd, name, root_fd
    except BaseException:
        if root_fd >= 0:
            try:
                os.close(root_fd)
            except OSError:
                pass
        os.close(parent_fd)
        raise


def _open_directory_path(path: str | Path) -> int:
    flags = _DIRECTORY_FLAGS | _SAFE_OPEN_FLAGS
    value = Path(path)
    if not value.is_absolute():
        raise SupervisorError("unsafe_workspace_root", "workspace parent path is not absolute")
    try:
        current_fd = os.open(os.path.sep, flags)
        for component in value.parts[1:]:
            if component in {"", ".", ".."}:
                raise SupervisorError(
                    "unsafe_workspace_root", "workspace parent path is not canonical"
                )
            child_fd = -1
            try:
                before = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
                if not stat.S_ISDIR(before.st_mode):
                    raise SupervisorError(
                        "unsafe_workspace_root", "workspace parent contains a non-directory"
                    )
                child_fd = os.open(component, flags, dir_fd=current_fd)
                opened = os.fstat(child_fd)
                after = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
                if not (
                    _same_identity(before, opened, directory=True)
                    and _same_identity(opened, after, directory=True)
                ):
                    raise SupervisorError(
                        "unstable_workspace", "workspace parent changed while opening"
                    )
            except BaseException:
                if child_fd >= 0:
                    os.close(child_fd)
                raise
            os.close(current_fd)
            current_fd = child_fd
        return current_fd
    except SupervisorError:
        if "current_fd" in locals():
            os.close(current_fd)
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        if "current_fd" in locals():
            os.close(current_fd)
        raise SupervisorError("unsafe_workspace_root", "workspace parent is unavailable") from error


def _open_child_directory(parent_fd: int, name: str, expected: os.stat_result) -> int:
    child_fd = -1
    try:
        child_fd = os.open(name, _DIRECTORY_FLAGS | _SAFE_OPEN_FLAGS, dir_fd=parent_fd)
        if not _same_node(expected, os.fstat(child_fd), directory=True):
            raise SupervisorError(
                "unstable_workspace", "workspace directory changed during capture"
            )
        return child_fd
    except BaseException as error:
        if child_fd >= 0:
            try:
                os.close(child_fd)
            except OSError:
                pass
        if isinstance(error, SupervisorError):
            raise
        if isinstance(error, OSError):
            raise SupervisorError(
                "unstable_workspace", "workspace directory changed during capture"
            ) from error
        raise


def _assert_source_stable(parent_fd: int, name: str, expected: os.stat_result) -> None:
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        raise SupervisorError(
            "unstable_workspace", "workspace entry disappeared during capture"
        ) from error
    if not _same_node(expected, current):
        raise SupervisorError("unstable_workspace", "workspace entry changed during capture")


def _assert_destination_directory_stable(
    parent_fd: int,
    name: str,
    directory_fd: int,
    expected: os.stat_result,
) -> None:
    try:
        opened = os.fstat(directory_fd)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        raise SupervisorError(
            "snapshot_destination_race", "snapshot directory disappeared during copy"
        ) from error
    if not (
        _same_identity(expected, opened, directory=True)
        and _same_identity(opened, current, directory=True)
    ):
        raise SupervisorError("snapshot_destination_race", "snapshot directory changed during copy")


def _same_node(
    left: os.stat_result,
    right: os.stat_result,
    *,
    directory: bool = False,
    regular: bool = False,
    symlink: bool = False,
) -> bool:
    expected_type = (
        stat.S_IFDIR
        if directory
        else stat.S_IFREG
        if regular
        else stat.S_IFLNK
        if symlink
        else None
    )
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
        and stat.S_IMODE(left.st_mode) == stat.S_IMODE(right.st_mode)
        and (expected_type is None or stat.S_IFMT(right.st_mode) == expected_type)
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_ctime_ns == right.st_ctime_ns
    )


def _write_all(fd: int, value: bytes) -> None:
    view = memoryview(value)
    offset = 0
    while offset < len(view):
        written = os.write(fd, view[offset:])
        if written <= 0:
            raise SupervisorError("snapshot_copy_failed", "snapshot file write made no progress")
        offset += written


def _remove_created_tree(
    parent_fd: int,
    name: str,
    expected_root: os.stat_result,
    *,
    expected_nodes: dict[str, os.stat_result] | None = None,
) -> None:
    root_fd = -1
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_identity(expected_root, current, directory=True):
            return
        root_fd = os.open(name, _DIRECTORY_FLAGS | _SAFE_OPEN_FLAGS, dir_fd=parent_fd)
        if not _same_identity(expected_root, os.fstat(root_fd), directory=True):
            os.close(root_fd)
            root_fd = -1
            return
    except OSError:
        if root_fd >= 0:
            try:
                os.close(root_fd)
            except OSError:
                pass
        return
    if root_fd < 0:
        return
    try:
        with os.scandir(root_fd) as children:
            for child_entry in children:
                child = child_entry.name
                try:
                    item = os.stat(child, dir_fd=root_fd, follow_symlinks=False)
                    expected = expected_nodes.get(child) if expected_nodes is not None else item
                    if expected is None or not _same_identity(expected, item):
                        continue
                    if stat.S_ISDIR(item.st_mode):
                        child_fd = os.open(
                            child, _DIRECTORY_FLAGS | _SAFE_OPEN_FLAGS, dir_fd=root_fd
                        )
                        try:
                            if not (
                                _same_identity(item, os.fstat(child_fd), directory=True)
                                and _same_identity(expected, os.fstat(child_fd), directory=True)
                            ):
                                return
                            _remove_tree_contents(
                                child_fd,
                                expected_nodes=expected_nodes,
                                relative=child,
                            )
                        finally:
                            os.close(child_fd)
                        current = os.stat(child, dir_fd=root_fd, follow_symlinks=False)
                        if not (
                            _same_identity(item, current, directory=True)
                            and _same_identity(expected, current, directory=True)
                        ):
                            return
                        os.rmdir(child, dir_fd=root_fd)
                    else:
                        current = os.stat(child, dir_fd=root_fd, follow_symlinks=False)
                        if _same_identity(expected, current):
                            os.unlink(child, dir_fd=root_fd)
                except OSError:
                    return
    finally:
        os.close(root_fd)
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if _same_identity(expected_root, current, directory=True):
            os.rmdir(name, dir_fd=parent_fd)
    except OSError:
        pass


def _remove_tree_contents(
    directory_fd: int,
    *,
    expected_nodes: dict[str, os.stat_result] | None = None,
    relative: str = "",
) -> None:
    with os.scandir(directory_fd) as children:
        for child_entry in children:
            name = child_entry.name
            path = f"{relative}/{name}" if relative else name
            item = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            expected = expected_nodes.get(path) if expected_nodes is not None else item
            if expected is None or not _same_identity(expected, item):
                continue
            if stat.S_ISDIR(item.st_mode):
                child_fd = os.open(name, _DIRECTORY_FLAGS | _SAFE_OPEN_FLAGS, dir_fd=directory_fd)
                try:
                    if not _same_identity(item, os.fstat(child_fd), directory=True):
                        raise OSError("cleanup entry changed")
                    _remove_tree_contents(
                        child_fd,
                        expected_nodes=expected_nodes,
                        relative=path,
                    )
                finally:
                    os.close(child_fd)
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if not (
                    _same_identity(item, current, directory=True)
                    and _same_identity(expected, current, directory=True)
                ):
                    raise OSError("cleanup entry changed")
                os.rmdir(name, dir_fd=directory_fd)
            else:
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if _same_identity(expected, current):
                    os.unlink(name, dir_fd=directory_fd)


def _same_identity(
    left: os.stat_result,
    right: os.stat_result,
    *,
    directory: bool = False,
) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
        and (not directory or stat.S_ISDIR(right.st_mode))
    )


def _existing_write_set_matcher(
    path: str, resource: str, *, fold: bool = True, is_logical: bool | None = None
) -> bool:
    # Import lazily so this helper uses the supervisor's one canonical write-set
    # matcher without introducing an eager phase-module dependency.
    from .claims import ClaimsMixin

    return ClaimsMixin._path_matches(path, resource, fold=fold, is_logical=is_logical)
