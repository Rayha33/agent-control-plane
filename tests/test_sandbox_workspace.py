from __future__ import annotations

import os
import stat
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest

import agent_control_plane.supervisor.sandbox_workspace as sandbox_workspace
from agent_control_plane.supervisor.common import SupervisorError
from agent_control_plane.supervisor.sandbox_workspace import (
    SnapshotLimits,
    apply_changes_to_manifest,
    collect_changes,
    copy_snapshot,
    read_snapshot_files,
)


def _all_paths() -> list[tuple[str, bool, bool]]:
    return [("**", True, False)]


def _codes(function: object, *args: object, **kwargs: object) -> str:
    with pytest.raises(SupervisorError) as raised:
        function(*args, **kwargs)  # type: ignore[operator]
    return raised.value.code


def test_snapshot_is_private_bounded_copy_and_excludes_only_root_git(tmp_path: Path) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    (source / ".git").mkdir()
    (source / ".git" / "config").write_text("private git metadata")
    (source / "bin").mkdir()
    executable = source / "bin" / "runner"
    executable.write_bytes(b"\x00binary\xff")
    executable.chmod(0o751)
    first = source / "first.txt"
    first.write_text("same bytes")
    os.link(first, source / "second.txt")
    (source / "runner-link").symlink_to("bin/runner")

    snapshot = copy_snapshot(source, tmp_path / "private")
    copied = snapshot.root

    assert not (copied / ".git").exists()
    assert (copied / "bin" / "runner").read_bytes() == b"\x00binary\xff"
    assert stat.S_IMODE((copied / "bin" / "runner").stat().st_mode) == 0o755
    assert os.readlink(copied / "runner-link") == "bin/runner"
    assert os.stat(first).st_ino != os.stat(copied / "first.txt").st_ino
    assert os.stat(copied / "first.txt").st_ino != os.stat(copied / "second.txt").st_ino
    assert snapshot.manifest.digest == snapshot.manifest.as_json()["sha256"]
    snapshot.manifest.validate()


def test_snapshot_accepts_relative_source_path_from_real_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "relative-source"
    source.mkdir()
    (source / "owned.txt").write_text("source bytes")
    monkeypatch.chdir(tmp_path)

    snapshot = copy_snapshot("relative-source", tmp_path / "private-copy")

    assert (snapshot.root / "owned.txt").read_text() == "source bytes"


def test_read_snapshot_files_verifies_and_returns_only_regular_file_bytes(tmp_path: Path) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    (source / "nested").mkdir()
    (source / "nested" / "binary").write_bytes(b"\x00payload\xff")
    (source / "link").symlink_to("nested/binary")
    snapshot = copy_snapshot(source, tmp_path / "private")

    assert read_snapshot_files(snapshot) == {"nested/binary": b"\x00payload\xff"}

    (snapshot.root / "nested" / "binary").write_bytes(b"tampered!")
    assert _codes(read_snapshot_files, snapshot) == "snapshot_changed"


def test_root_git_file_is_excluded_and_never_interpreted(tmp_path: Path) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    (source / ".git").write_text("gitdir: /outside/host/.git/worktrees/secret")
    (source / "owned.py").write_text("pass\n")

    snapshot = copy_snapshot(source, tmp_path / "private")

    assert not (snapshot.root / ".git").exists()
    assert [entry.path for entry in snapshot.manifest.entries] == ["owned.py"]


def test_root_git_case_alias_is_rejected_instead_of_silently_omitted(tmp_path: Path) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    (source / ".GIT").write_text("tracked project data")

    destination = tmp_path / "private"
    assert _codes(copy_snapshot, source, destination) == "nested_git_metadata"
    assert not destination.exists()


def test_directory_enumeration_stops_at_the_remaining_entry_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    for number in range(12):
        (source / f"file-{number:02}.txt").write_text("x")

    real_scandir = sandbox_workspace.os.scandir
    observed: list[str] = []

    @contextmanager
    def counted_scandir(directory_fd: int):
        with real_scandir(directory_fd) as entries:

            def counted_entries():
                for entry in entries:
                    observed.append(entry.name)
                    yield entry

            yield counted_entries()

    monkeypatch.setattr(sandbox_workspace.os, "scandir", counted_scandir)
    assert (
        _codes(
            copy_snapshot,
            source,
            tmp_path / "private",
            limits=SnapshotLimits(max_entries=2),
        )
        == "workspace_limit_exceeded"
    )
    assert len(observed) == 3


def test_nested_enumeration_uses_one_shared_pending_name_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "registered"
    nested = source / "a"
    nested.mkdir(parents=True)
    for number in range(5):
        (source / f"sibling-{number}.txt").write_text("x")
    for number in range(20):
        (nested / f"nested-{number:02}.txt").write_text("x")

    real_scandir = sandbox_workspace.os.scandir
    observed: list[str] = []

    @contextmanager
    def counted_scandir(directory_fd: int):
        with real_scandir(directory_fd) as entries:

            def counted_entries():
                for entry in entries:
                    observed.append(entry.name)
                    yield entry

            yield counted_entries()

    monkeypatch.setattr(sandbox_workspace.os, "scandir", counted_scandir)
    assert (
        _codes(
            copy_snapshot,
            source,
            tmp_path / "private",
            limits=SnapshotLimits(max_entries=10),
        )
        == "workspace_limit_exceeded"
    )
    # Five root siblings stay pending while the first directory is counted.
    # The global budget allows four nested names plus one overflow probe.
    scanned_source_names = [name for name in observed if name.startswith(("sibling-", "nested-"))]
    assert sum(name.startswith("sibling-") for name in scanned_source_names) == 5
    assert sum(name.startswith("nested-") for name in scanned_source_names) == 5


@pytest.mark.parametrize("node", ["nested_git", "fifo", "unsafe_link"])
def test_snapshot_rejects_git_admin_special_nodes_and_escaping_links(
    tmp_path: Path, node: str
) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    if node == "nested_git":
        nested = source / "nested"
        nested.mkdir()
        (nested / ".git").write_text("gitdir: ../../.git/modules/secret")
    elif node == "fifo":
        os.mkfifo(source / "pipe")
    else:
        (source / "escape").symlink_to("../outside-secret")

    destination = tmp_path / "private"
    assert _codes(copy_snapshot, source, destination) in {
        "nested_git",
        "nested_git_metadata",
        "unsafe_workspace_node",
        "unsafe_symlink",
    }
    assert not destination.exists()


def test_snapshot_enforces_entry_byte_and_path_limits(tmp_path: Path) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    (source / "payload.bin").write_bytes(b"x" * 32)
    (source / "second.bin").write_bytes(b"y")

    assert (
        _codes(
            copy_snapshot,
            source,
            tmp_path / "too-large",
            limits=SnapshotLimits(max_entries=4, max_total_bytes=16, max_file_bytes=16),
        )
        == "workspace_limit_exceeded"
    )
    assert not (tmp_path / "too-large").exists()
    assert (
        _codes(
            copy_snapshot,
            source,
            tmp_path / "too-many",
            limits=SnapshotLimits(max_entries=1),
        )
        == "workspace_limit_exceeded"
    )
    assert not (tmp_path / "too-many").exists()
    assert (
        _codes(
            copy_snapshot,
            source,
            tmp_path / "path-limited",
            limits=SnapshotLimits(max_path_bytes=5),
        )
        == "unsafe_workspace_path"
    )
    assert not (tmp_path / "path-limited").exists()


def test_snapshot_rejects_overlapping_source_and_destination(tmp_path: Path) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    (source / "owned.txt").write_text("safe\n")

    assert _codes(copy_snapshot, source, source / "private") == "invalid_snapshot_destination"
    assert not (source / "private").exists()


def test_snapshot_detects_source_mutation_during_file_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    target = source / "large.bin"
    target.write_bytes(b"a" * (128 * 1024))
    real_read = sandbox_workspace.os.read
    mutated = False

    def mutate_after_first_read(fd: int, size: int) -> bytes:
        nonlocal mutated
        result = real_read(fd, size)
        if result and not mutated:
            mutated = True
            target.write_bytes(b"b" * (128 * 1024))
        return result

    monkeypatch.setattr(sandbox_workspace.os, "read", mutate_after_first_read)
    destination = tmp_path / "private"

    assert _codes(copy_snapshot, source, destination) == "unstable_workspace"
    assert not destination.exists()


def test_snapshot_readback_detects_replaced_file_leaf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    (source / "owned.txt").write_text("source bytes")
    substitute = tmp_path / "substitute.txt"
    substitute.write_text("replacement bytes")
    destination = tmp_path / "private"
    real_walk = sandbox_workspace._walk_tree
    replaced = False

    def replace_after_capture(source_fd: int, destination_fd: int | None, **kwargs: object) -> None:
        nonlocal replaced
        real_walk(source_fd, destination_fd, **kwargs)  # type: ignore[arg-type]
        if destination_fd is not None and kwargs.get("root") and not replaced:
            (destination / "owned.txt").unlink()
            substitute.rename(destination / "owned.txt")
            replaced = True

    monkeypatch.setattr(sandbox_workspace, "_walk_tree", replace_after_capture)
    assert _codes(copy_snapshot, source, destination) == "snapshot_destination_mismatch"
    assert replaced
    assert (destination / "owned.txt").read_text() == "replacement bytes"


def test_snapshot_readback_rejects_replaced_escaping_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    (source / "inside.txt").write_text("safe")
    (source / "link").symlink_to("inside.txt")
    outside = tmp_path / "outside-sentinel"
    outside.write_text("must remain unchanged")
    destination = tmp_path / "private"
    real_walk = sandbox_workspace._walk_tree
    replaced = False

    def replace_after_capture(source_fd: int, destination_fd: int | None, **kwargs: object) -> None:
        nonlocal replaced
        real_walk(source_fd, destination_fd, **kwargs)  # type: ignore[arg-type]
        if destination_fd is not None and kwargs.get("root") and not replaced:
            (destination / "link").unlink()
            (destination / "link").symlink_to("../outside-sentinel")
            replaced = True

    monkeypatch.setattr(sandbox_workspace, "_walk_tree", replace_after_capture)
    assert _codes(copy_snapshot, source, destination) == "unsafe_symlink"
    assert replaced
    assert outside.read_text() == "must remain unchanged"


def test_snapshot_readback_rejects_injected_root_git_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    (source / "owned.txt").write_text("source bytes")
    destination = tmp_path / "private"
    real_walk = sandbox_workspace._walk_tree
    injected = False

    def inject_root_git(source_fd: int, destination_fd: int | None, **kwargs: object) -> None:
        nonlocal injected
        real_walk(source_fd, destination_fd, **kwargs)  # type: ignore[arg-type]
        if destination_fd is not None and kwargs.get("root") and not injected:
            (destination / ".git").mkdir()
            (destination / ".git" / "config").write_text("injected metadata")
            injected = True

    monkeypatch.setattr(sandbox_workspace, "_walk_tree", inject_root_git)
    assert _codes(copy_snapshot, source, destination) == "nested_git_metadata"
    assert injected


@pytest.mark.parametrize("target", ["root", "file"])
def test_snapshot_readback_rejects_permission_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    (source / "owned.txt").write_text("source bytes")
    destination = tmp_path / "private"
    real_walk = sandbox_workspace._walk_tree
    changed = False

    def broaden_permissions(source_fd: int, destination_fd: int | None, **kwargs: object) -> None:
        nonlocal changed
        real_walk(source_fd, destination_fd, **kwargs)  # type: ignore[arg-type]
        if destination_fd is not None and kwargs.get("root") and not changed:
            if target == "root":
                destination.chmod(0o755)
            else:
                (destination / "owned.txt").chmod(0o666)
            changed = True

    monkeypatch.setattr(sandbox_workspace, "_walk_tree", broaden_permissions)
    assert _codes(copy_snapshot, source, destination) == "snapshot_destination_mismatch"
    assert changed
    assert not destination.exists()


def test_parent_open_rejects_intermediate_symlink_substitution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ancestor = tmp_path / "ancestor"
    ancestor.mkdir()
    (ancestor / "child").mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "sentinel").write_text("must remain private")
    saved = tmp_path / "ancestor-saved"
    expected_parent = tmp_path.stat()
    real_open = sandbox_workspace.os.open
    substituted = False

    def substitute_before_open(
        path: str | bytes,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal substituted
        if path == "ancestor" and dir_fd is not None and not substituted:
            parent = os.fstat(dir_fd)
            if (parent.st_dev, parent.st_ino) == (expected_parent.st_dev, expected_parent.st_ino):
                ancestor.rename(saved)
                ancestor.symlink_to(outside, target_is_directory=True)
                substituted = True
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(sandbox_workspace.os, "open", substitute_before_open)
    try:
        assert _codes(sandbox_workspace._open_directory_path, ancestor / "child") in {
            "unsafe_workspace_root",
            "unstable_workspace",
        }
        assert substituted
        assert (outside / "sentinel").read_text() == "must remain private"
    finally:
        if ancestor.is_symlink():
            ancestor.unlink()
        if saved.exists():
            saved.rename(ancestor)


@pytest.mark.parametrize("relative_path", [False, True])
def test_existing_directory_open_rejects_preexisting_symlink_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative_path: bool
) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir(mode=0o700)
    root = real_parent / "private-root"
    root.mkdir(mode=0o700)
    alias_parent = tmp_path / "alias-parent"
    alias_parent.symlink_to(real_parent, target_is_directory=True)
    if relative_path:
        monkeypatch.chdir(tmp_path)
        candidate = Path(alias_parent.name) / root.name
    else:
        candidate = alias_parent / root.name
    assert _codes(sandbox_workspace._open_existing_directory, candidate) == "unsafe_workspace_root"


def test_existing_directory_open_rejects_parent_traversal_components(tmp_path: Path) -> None:
    parent = tmp_path / "private-parent"
    root = parent / "private-root"
    root.mkdir(parents=True, mode=0o700)
    candidate = parent / ".." / parent.name / root.name

    assert _codes(sandbox_workspace._open_existing_directory, candidate) == "unsafe_workspace_root"


@pytest.mark.parametrize("relative_path", [False, True])
def test_existing_directory_open_rejects_terminal_parent_component(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative_path: bool
) -> None:
    if relative_path:
        monkeypatch.chdir(tmp_path)
        candidate = Path("..")
    else:
        candidate = tmp_path / ".."

    assert _codes(sandbox_workspace._open_existing_directory, candidate) == "unsafe_workspace_root"


def test_open_child_directory_closes_descriptor_when_fstat_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "parent"
    child = parent / "child"
    child.mkdir(parents=True)
    parent_fd = os.open(parent, sandbox_workspace._DIRECTORY_FLAGS)
    expected = os.stat("child", dir_fd=parent_fd, follow_symlinks=False)
    real_open = sandbox_workspace.os.open
    real_fstat = sandbox_workspace.os.fstat
    opened_fds: list[int] = []

    def track_open(
        path: str | bytes,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == "child" and dir_fd == parent_fd:
            opened_fds.append(descriptor)
        return descriptor

    def fail_child_fstat(descriptor: int) -> os.stat_result:
        if descriptor in opened_fds:
            raise OSError("injected fstat failure")
        return real_fstat(descriptor)

    monkeypatch.setattr(sandbox_workspace.os, "open", track_open)
    monkeypatch.setattr(sandbox_workspace.os, "fstat", fail_child_fstat)
    try:
        assert (
            _codes(sandbox_workspace._open_child_directory, parent_fd, "child", expected)
            == "unstable_workspace"
        )
        assert opened_fds
        with pytest.raises(OSError):
            real_fstat(opened_fds[0])
    finally:
        os.close(parent_fd)


def test_nested_snapshot_directory_open_checks_created_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "registered"
    (source / "child").mkdir(parents=True)
    (source / "child" / "payload.txt").write_text("source content")
    destination = tmp_path / "private"
    external = tmp_path / "external"
    external.mkdir()
    (external / "sentinel.txt").write_text("must not be overwritten")
    saved = destination / "saved-child"
    real_open = sandbox_workspace.os.open
    destination_root_identity: tuple[int, int] | None = None
    substituted = False
    destination_parent_stat = tmp_path.stat()

    def substitute_after_created_stat(
        path: str | bytes,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal destination_root_identity, substituted
        if path == "private" and dir_fd is not None:
            parent = os.fstat(dir_fd)
            if (parent.st_dev, parent.st_ino) == (
                destination_parent_stat.st_dev,
                destination_parent_stat.st_ino,
            ):
                descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                root = os.fstat(descriptor)
                destination_root_identity = (root.st_dev, root.st_ino)
                return descriptor
        if path == "child" and dir_fd is not None and destination_root_identity is not None:
            parent = os.fstat(dir_fd)
            if (parent.st_dev, parent.st_ino) == destination_root_identity and not substituted:
                (destination / "child").rename(saved)
                external.rename(destination / "child")
                substituted = True
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(sandbox_workspace.os, "open", substitute_after_created_stat)
    assert _codes(copy_snapshot, source, destination) == "snapshot_destination_race"
    assert substituted
    # Cleanup only removes paths whose inodes this snapshot created; the
    # substituted directory is preserved, so the incomplete root remains.
    assert (destination / "child" / "sentinel.txt").read_text() == "must not be overwritten"
    assert (destination / "saved-child").is_dir()


def test_cleanup_does_not_recurse_into_a_substituted_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "created"
    child = root / "child"
    root.mkdir()
    child.mkdir()
    (child / "original.txt").write_text("created by snapshot")
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "sentinel.txt").write_text("must not be deleted")
    saved = root / "child-saved"
    parent_fd = os.open(tmp_path, sandbox_workspace._DIRECTORY_FLAGS)
    root_stat = os.stat(root, follow_symlinks=False)
    real_open = sandbox_workspace.os.open
    substituted = False

    def substitute_before_open(
        path: str | bytes,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal substituted
        if path == "child" and dir_fd is not None and not substituted:
            parent = os.fstat(dir_fd)
            if (parent.st_dev, parent.st_ino) == (root_stat.st_dev, root_stat.st_ino):
                child.rename(saved)
                replacement.rename(child)
                substituted = True
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(sandbox_workspace.os, "open", substitute_before_open)
    try:
        sandbox_workspace._remove_created_tree(parent_fd, "created", root_stat)
        assert substituted
        assert (child / "sentinel.txt").read_text() == "must not be deleted"
        assert (saved / "original.txt").read_text() == "created by snapshot"
        assert root.exists()
    finally:
        os.close(parent_fd)
        if child.exists() and saved.exists():
            child.rename(replacement)
            saved.rename(child)


def test_collect_changes_captures_create_modify_delete_rename_binary_exec_and_symlink(
    tmp_path: Path,
) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    (source / "src").mkdir()
    (source / "src" / "modify.txt").write_text("before\n")
    (source / "src" / "delete.txt").write_text("remove\n")
    (source / "src" / "rename-old.txt").write_text("rename\n")
    (source / "src" / "program").write_text("#!/bin/sh\n")
    (source / "src" / "program").chmod(0o644)
    (source / "src" / "binary.bin").write_bytes(b"\x00\xff")
    (source / "src" / "link").symlink_to("modify.txt")

    baseline = copy_snapshot(source, tmp_path / "baseline").manifest
    output = copy_snapshot(source, tmp_path / "output").root
    (output / "src" / "modify.txt").write_text("after\n")
    (output / "src" / "delete.txt").unlink()
    (output / "src" / "rename-old.txt").rename(output / "src" / "rename-new.txt")
    (output / "src" / "program").chmod(0o755)
    (output / "src" / "binary.bin").write_bytes(b"\x00\xfe\xff")
    (output / "src" / "link").unlink()
    (output / "src" / "link").symlink_to("rename-new.txt")
    (output / "src" / "created.txt").write_text("new\n")
    (output / ".git").mkdir()
    (output / ".git" / "config").write_text("untrusted worker config")

    changes = collect_changes(
        baseline,
        output,
        write_set_rules=_all_paths(),
    )
    by_path = {change.path: change for change in changes.changes}

    assert by_path["src/modify.txt"].action == "modify"
    assert by_path["src/delete.txt"].action == "delete"
    assert by_path["src/rename-old.txt"].action == "delete"
    assert by_path["src/rename-new.txt"].action == "create"
    assert by_path["src/program"].mode == 0o755
    assert by_path["src/binary.bin"].content == b"\x00\xfe\xff"
    assert by_path["src/link"].symlink_target == "rename-new.txt"
    assert by_path["src/created.txt"].content == b"new\n"
    assert ".git/config" not in by_path
    repeated = collect_changes(
        baseline,
        output,
        write_set_rules=_all_paths(),
    )
    assert changes.digest == repeated.digest
    changes.validate()


def test_change_set_replays_directory_only_changes_to_exact_result_manifest(
    tmp_path: Path,
) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    (source / "old-empty").mkdir()
    baseline = copy_snapshot(source, tmp_path / "baseline").manifest
    output = copy_snapshot(source, tmp_path / "output").root
    (output / "old-empty").rmdir()
    (output / "new-empty").mkdir()

    changes = collect_changes(baseline, output, write_set_rules=_all_paths())
    by_path = {change.path: change for change in changes.changes}
    assert by_path["old-empty"].action == "delete"
    assert by_path["old-empty"].kind == "directory"
    assert by_path["new-empty"].action == "create"
    assert by_path["new-empty"].kind == "directory"
    assert (
        apply_changes_to_manifest(baseline, changes)
        == copy_snapshot(output, tmp_path / "expected").manifest
    )


def test_manifest_replay_rejects_change_set_missing_empty_directory_operation(
    tmp_path: Path,
) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    baseline = copy_snapshot(source, tmp_path / "baseline").manifest
    output = copy_snapshot(source, tmp_path / "output").root
    (output / "empty").mkdir()
    complete = collect_changes(baseline, output, write_set_rules=_all_paths())
    assert [change.path for change in complete.changes] == ["empty"]

    incomplete = sandbox_workspace._make_change_set(
        complete.baseline_digest,
        complete.result_digest,
        (),
        0,
    )
    assert _codes(apply_changes_to_manifest, baseline, incomplete) == "incomplete_change_set"


def test_change_set_replay_applies_directory_type_transitions_bottom_up(
    tmp_path: Path,
) -> None:
    directory_source = tmp_path / "directory-source"
    directory_source.mkdir()
    (directory_source / "slot").mkdir()
    (directory_source / "slot" / "child.txt").write_text("child\n")
    directory_baseline = copy_snapshot(directory_source, tmp_path / "directory-baseline").manifest
    file_output = copy_snapshot(directory_source, tmp_path / "file-output").root
    (file_output / "slot" / "child.txt").unlink()
    (file_output / "slot").rmdir()
    (file_output / "slot").write_text("replacement\n")
    directory_to_file = collect_changes(
        directory_baseline,
        file_output,
        write_set_rules=_all_paths(),
    )
    assert [change.path for change in directory_to_file.changes] == ["slot", "slot/child.txt"]
    assert (
        apply_changes_to_manifest(directory_baseline, directory_to_file)
        == copy_snapshot(file_output, tmp_path / "file-expected").manifest
    )

    file_source = tmp_path / "file-source"
    file_source.mkdir()
    (file_source / "slot").write_text("original\n")
    file_baseline = copy_snapshot(file_source, tmp_path / "file-baseline").manifest
    directory_output = copy_snapshot(file_source, tmp_path / "directory-output").root
    (directory_output / "slot").unlink()
    (directory_output / "slot").mkdir()
    (directory_output / "slot" / "child.txt").write_text("child\n")
    file_to_directory = collect_changes(
        file_baseline,
        directory_output,
        write_set_rules=_all_paths(),
    )
    assert (
        apply_changes_to_manifest(file_baseline, file_to_directory)
        == copy_snapshot(directory_output, tmp_path / "directory-expected").manifest
    )


def test_write_set_allows_only_structural_directories_for_claimed_leaves(
    tmp_path: Path,
) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    baseline = copy_snapshot(source, tmp_path / "baseline").manifest
    output = copy_snapshot(source, tmp_path / "output").root
    nested = output / "src" / "generated"
    nested.mkdir(parents=True)
    (nested / "result.txt").write_text("claimed result\n")
    rules = [("src/generated/result.txt", False, False)]

    changes = collect_changes(baseline, output, write_set_rules=rules)
    assert (
        apply_changes_to_manifest(baseline, changes)
        == copy_snapshot(output, tmp_path / "expected").manifest
    )

    (output / "unclaimed-empty").mkdir()
    assert _codes(collect_changes, baseline, output, write_set_rules=rules) == "undeclared_write"


def test_write_set_allows_directory_removal_only_for_claimed_descendant_deletions(
    tmp_path: Path,
) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    (source / "nested" / "deep").mkdir(parents=True)
    (source / "nested" / "deep" / "result.txt").write_text("remove me\n")
    baseline = copy_snapshot(source, tmp_path / "baseline").manifest
    output = copy_snapshot(source, tmp_path / "output").root
    (output / "nested" / "deep" / "result.txt").unlink()
    (output / "nested" / "deep").rmdir()
    (output / "nested").rmdir()

    changes = collect_changes(
        baseline,
        output,
        write_set_rules=[("nested/deep/result.txt", False, False)],
    )
    assert (
        apply_changes_to_manifest(baseline, changes)
        == copy_snapshot(output, tmp_path / "expected").manifest
    )


def test_descendant_path_range_excludes_prefix_similar_siblings() -> None:
    paths = sorted(["a/b", "a/b-", "a/b/child", "a/b/child/grand", "a/b0", "a/c"])
    start, end = sandbox_workspace._descendant_path_range(paths, "a/b")
    assert paths[start:end] == ["a/b/child", "a/b/child/grand"]


def test_collect_changes_uses_existing_case_sensitive_write_set_rules(tmp_path: Path) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    (source / "Makefile").write_text("before\n")
    baseline = copy_snapshot(source, tmp_path / "baseline").manifest
    output = copy_snapshot(source, tmp_path / "output").root
    (output / "Makefile").unlink()
    (output / "makefile").write_text("case changed\n")

    assert (
        _codes(
            collect_changes,
            baseline,
            output,
            write_set_rules=[("Makefile", False, False)],
        )
        == "undeclared_write"
    )


def test_collect_changes_rejects_undeclared_paths_and_unsafe_symlink_without_touching_sentinel(
    tmp_path: Path,
) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    (source / "allowed.txt").write_text("before\n")
    baseline = copy_snapshot(source, tmp_path / "baseline").manifest
    output = copy_snapshot(source, tmp_path / "output").root
    (output / "unlisted.txt").write_text("not declared\n")

    assert (
        _codes(
            collect_changes,
            baseline,
            output,
            write_set_rules=[("allowed.txt", False, False)],
        )
        == "undeclared_write"
    )

    (output / "unlisted.txt").unlink()
    sentinel = tmp_path / "outside-sentinel"
    sentinel.write_text("unchanged\n")
    (output / "escape").symlink_to("../outside-sentinel")
    assert (
        _codes(collect_changes, baseline, output, write_set_rules=_all_paths()) == "unsafe_symlink"
    )
    assert sentinel.read_text() == "unchanged\n"


def test_collect_changes_rejects_nested_git_and_symlink_cycles(tmp_path: Path) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    baseline = copy_snapshot(source, tmp_path / "baseline").manifest
    output = copy_snapshot(source, tmp_path / "output").root
    nested = output / "nested"
    nested.mkdir()
    (nested / ".git").write_text("gitdir: ../../.git/modules/host")

    assert _codes(collect_changes, baseline, output, write_set_rules=_all_paths()) == (
        "nested_git_metadata"
    )

    (nested / ".git").unlink()
    nested.rmdir()
    (output / "first").symlink_to("second")
    (output / "second").symlink_to("first")
    assert _codes(collect_changes, baseline, output, write_set_rules=_all_paths()) == (
        "unsafe_symlink"
    )


def test_manifest_rejects_tampering_and_destination_must_be_new(tmp_path: Path) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    (source / "owned.txt").write_text("x")
    manifest = copy_snapshot(source, tmp_path / "snapshot").manifest

    with pytest.raises(SupervisorError, match="digest mismatch"):
        replace(manifest, digest="0" * 64).validate()
    assert _codes(copy_snapshot, source, tmp_path / "snapshot") == "snapshot_destination_exists"


def test_oversized_manifest_is_rejected_before_digest_rebuild(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "registered"
    source.mkdir()
    (source / "owned.txt").write_text("x")
    manifest = copy_snapshot(source, tmp_path / "snapshot").manifest
    oversized = replace(manifest, entries=manifest.entries * 2)

    def unexpected_rebuild(*_args: object, **_kwargs: object) -> object:
        pytest.fail("oversized manifest was serialized before its entry limit was checked")

    monkeypatch.setattr(sandbox_workspace, "_make_manifest", unexpected_rebuild)
    assert _codes(oversized.validate, SnapshotLimits(max_entries=1)) == ("workspace_limit_exceeded")
