from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import replace
from pathlib import Path

import pytest

import agent_control_plane.supervisor.sandbox_monitor_receipt as receipt_module
from agent_control_plane.supervisor.sandbox_monitor_receipt import (
    SandboxMonitorReceipt,
    SandboxMonitorReceiptError,
    read_sandbox_monitor_receipt,
    sandbox_attempt_slice_unit,
    sandbox_monitor_service_unit,
    validate_monitor_service_reconciliation,
    write_sandbox_monitor_receipt,
)


def _receipt() -> SandboxMonitorReceipt:
    attempt_id = "attempt-1"
    claim_token = 7
    execution_id = "execution-1"
    monitor_slice_unit = "app.slice"
    monitor_slice_cgroup = "/user.slice/user-1000.slice/user@1000.service/app.slice"
    unit = sandbox_monitor_service_unit(attempt_id, claim_token, execution_id)
    attempt_slice_unit = sandbox_attempt_slice_unit(attempt_id, claim_token, execution_id)
    return SandboxMonitorReceipt(
        version=1,
        controller_pid=101,
        attempt_id=attempt_id,
        claim_token=claim_token,
        execution_id=execution_id,
        unit=unit,
        invocation_id="a" * 32,
        control_group=f"{monitor_slice_cgroup}/{unit}",
        main_pid=102,
        main_identity="linux:102:12345",
        monitor_slice_unit=monitor_slice_unit,
        monitor_slice_control_group=monitor_slice_cgroup,
        attempt_slice_unit=attempt_slice_unit,
        attempt_slice_control_group=f"{monitor_slice_cgroup}/{attempt_slice_unit}",
    )


def _systemd_properties(receipt: SandboxMonitorReceipt) -> tuple[dict[str, str], ...]:
    service = {
        "Id": receipt.unit,
        "LoadState": "loaded",
        "ActiveState": "active",
        "InvocationID": receipt.invocation_id,
        "ControlGroup": receipt.control_group,
        "Slice": receipt.monitor_slice_unit,
        "MainPID": str(receipt.main_pid),
    }
    monitor_slice = {
        "Id": receipt.monitor_slice_unit,
        "LoadState": "loaded",
        "ActiveState": "active",
        "ControlGroup": receipt.monitor_slice_control_group,
    }
    attempt_slice = {
        "Id": receipt.attempt_slice_unit,
        "LoadState": "loaded",
        "ActiveState": "active",
        "Slice": receipt.monitor_slice_unit,
        "ControlGroup": receipt.attempt_slice_control_group,
    }
    return service, monitor_slice, attempt_slice


def test_monitor_receipt_is_fenced_immutable_and_durable(tmp_path: Path) -> None:
    receipt = _receipt()
    path = tmp_path / "monitor-receipt.json"

    write_sandbox_monitor_receipt(path, receipt)
    write_sandbox_monitor_receipt(path, receipt)
    with pytest.raises(SandboxMonitorReceiptError, match="conflicting monitor receipt"):
        write_sandbox_monitor_receipt(path, replace(receipt, invocation_id="b" * 32))

    assert read_sandbox_monitor_receipt(path) == receipt
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.stat().st_nlink == 1
    assert (
        sandbox_monitor_service_unit(receipt.attempt_id, receipt.claim_token, receipt.execution_id)
        == receipt.unit
    )
    assert (
        sandbox_monitor_service_unit(
            receipt.attempt_id, receipt.claim_token + 1, receipt.execution_id
        )
        != receipt.unit
    )


def test_reader_recovers_writer_crash_after_publishing_target_link(tmp_path: Path) -> None:
    receipt = _receipt()
    path = tmp_path / "monitor-receipt.json"
    orphan = tmp_path / f".{path.name}.0123456789abcdef0123456789abcdef.tmp"
    write_sandbox_monitor_receipt(path, receipt)
    os.link(path, orphan)
    assert path.stat().st_nlink == 2

    assert read_sandbox_monitor_receipt(path) == receipt
    assert path.stat().st_nlink == 1
    assert not orphan.exists()


def test_exact_replay_recovers_crashed_writer_temporary_link(tmp_path: Path) -> None:
    receipt = _receipt()
    path = tmp_path / "monitor-receipt.json"
    orphan = tmp_path / f".{path.name}.0123456789abcdef0123456789abcdef.tmp"
    write_sandbox_monitor_receipt(path, receipt)
    os.link(path, orphan)

    write_sandbox_monitor_receipt(path, receipt)

    assert read_sandbox_monitor_receipt(path) == receipt
    assert path.stat().st_nlink == 1
    assert not orphan.exists()


def test_reader_and_live_writer_tolerate_recovery_winning_unlink_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = _receipt()
    path = tmp_path / "monitor-receipt.json"
    original_link = os.link
    recovered: list[SandboxMonitorReceipt] = []

    def publish_then_read(*args: object, **kwargs: object) -> None:
        original_link(*args, **kwargs)
        recovered.append(read_sandbox_monitor_receipt(path))

    monkeypatch.setattr(receipt_module.os, "link", publish_then_read)
    write_sandbox_monitor_receipt(path, receipt)

    assert recovered == [receipt]
    assert path.stat().st_nlink == 1
    assert len(list(tmp_path.glob(".*.tmp"))) == 0


def test_reader_tolerates_writer_unlink_before_orphan_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = _receipt()
    path = tmp_path / "monitor-receipt.json"
    original_link = os.link
    original_listdir = os.listdir
    recovered: list[SandboxMonitorReceipt] = []

    def publisher_advances_before_reader(*args: object, **kwargs: object) -> None:
        original_link(*args, **kwargs)
        recovered.append(read_sandbox_monitor_receipt(path))

    def writer_unlinks_before_scan(directory_fd: int) -> list[str]:
        entries = original_listdir(directory_fd)
        for entry in entries:
            if entry.startswith(f".{path.name}.") and entry.endswith(".tmp"):
                os.unlink(entry, dir_fd=directory_fd)
                break
        return original_listdir(directory_fd)

    monkeypatch.setattr(receipt_module.os, "link", publisher_advances_before_reader)
    monkeypatch.setattr(receipt_module.os, "listdir", writer_unlinks_before_scan)
    write_sandbox_monitor_receipt(path, receipt)

    assert recovered == [receipt]
    assert path.stat().st_nlink == 1
    assert len(list(tmp_path.glob(".*.tmp"))) == 0


def test_reader_ignores_private_prelink_temp_while_recovering_published_receipt(
    tmp_path: Path,
) -> None:
    receipt = _receipt()
    path = tmp_path / "monitor-receipt.json"
    linked_orphan = tmp_path / f".{path.name}.0123456789abcdef0123456789abcdef.tmp"
    unlinked_orphan = tmp_path / f".{path.name}.fedcba9876543210fedcba9876543210.tmp"
    write_sandbox_monitor_receipt(path, receipt)
    os.link(path, linked_orphan)
    unlinked_orphan.write_text("pre-link crash residue", encoding="ascii")
    unlinked_orphan.chmod(0o600)

    assert read_sandbox_monitor_receipt(path) == receipt

    assert path.stat().st_nlink == 1
    assert not linked_orphan.exists()
    assert unlinked_orphan.exists()


def test_reader_rejects_unrelated_matching_temporary_link(tmp_path: Path) -> None:
    receipt = _receipt()
    path = tmp_path / "monitor-receipt.json"
    unrelated = tmp_path / "unrelated"
    orphan = tmp_path / f".{path.name}.0123456789abcdef0123456789abcdef.tmp"
    write_sandbox_monitor_receipt(path, receipt)
    unrelated.write_text("not the receipt", encoding="ascii")
    unrelated.chmod(0o600)
    os.link(unrelated, orphan)
    os.link(path, tmp_path / "unrecognized-link")

    with pytest.raises(SandboxMonitorReceiptError, match="unrelated or unsafe temporary entry"):
        read_sandbox_monitor_receipt(path)

    assert orphan.exists()
    assert path.stat().st_nlink == 2


def test_exact_replay_fsyncs_directory_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = _receipt()
    path = tmp_path / "monitor-receipt.json"
    write_sandbox_monitor_receipt(path, receipt)
    original_fsync = os.fsync
    directory_syncs: list[int] = []

    def record_fsync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            directory_syncs.append(descriptor)
        original_fsync(descriptor)

    monkeypatch.setattr(receipt_module.os, "fsync", record_fsync)
    write_sandbox_monitor_receipt(path, receipt)

    assert directory_syncs


def test_reader_fsyncs_existing_target_after_interrupted_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = _receipt()
    path = tmp_path / "monitor-receipt.json"
    write_sandbox_monitor_receipt(path, receipt)
    original_fsync = os.fsync
    directory_syncs: list[int] = []

    def record_fsync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            directory_syncs.append(descriptor)
        original_fsync(descriptor)

    monkeypatch.setattr(receipt_module.os, "fsync", record_fsync)

    assert read_sandbox_monitor_receipt(path) == receipt
    assert directory_syncs


def test_monitor_receipt_rejects_symlinks_and_nonprivate_directories(tmp_path: Path) -> None:
    receipt = _receipt()
    target = tmp_path / "target.json"
    link = tmp_path / "link.json"
    write_sandbox_monitor_receipt(target, receipt)
    link.symlink_to(target)

    with pytest.raises(OSError):
        read_sandbox_monitor_receipt(link)

    public_dir = tmp_path / "public"
    public_dir.mkdir(mode=0o700)
    public_dir.chmod(0o755)
    with pytest.raises(SandboxMonitorReceiptError, match="directory is not private"):
        write_sandbox_monitor_receipt(public_dir / "receipt.json", receipt)


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("version", True, "unsupported version"),
        ("claim_token", True, "field types"),
        ("attempt_id", "../other", "safe component"),
        ("unit", "acp-monitor-generic.service", "not bound"),
        ("invocation_id", "A" * 32, "invocation ID"),
        ("main_identity", "linux:103:12345", "PID start identity"),
        (
            "control_group",
            "/user.slice/app.slice/../worker.service",
            "canonical absolute cgroup path",
        ),
        (
            "attempt_slice_control_group",
            "/user.slice/user-1000.slice/user@1000.service/app.slice/other.slice",
            "sibling placement",
        ),
    ],
)
def test_monitor_receipt_rejects_forged_identity_fields(
    field: str, replacement: object, message: str
) -> None:
    value = _receipt().as_dict()
    value[field] = replacement

    with pytest.raises(SandboxMonitorReceiptError, match=message):
        SandboxMonitorReceipt.from_dict(value)


def test_monitor_receipt_rejects_duplicate_and_noncanonical_json(tmp_path: Path) -> None:
    path = tmp_path / "monitor-receipt.json"
    receipt = _receipt().as_dict()
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    path.write_text(encoded[:-1] + ',"version":1}', encoding="ascii")
    path.chmod(0o600)

    with pytest.raises(SandboxMonitorReceiptError, match="duplicate JSON keys"):
        read_sandbox_monitor_receipt(path)

    path.write_text(json.dumps(receipt, indent=2), encoding="ascii")
    path.chmod(0o600)
    with pytest.raises(SandboxMonitorReceiptError, match="canonical JSON"):
        read_sandbox_monitor_receipt(path)


def test_monitor_service_reconnect_requires_all_exact_systemd_identities() -> None:
    receipt = _receipt()
    service, monitor_slice, attempt_slice = _systemd_properties(receipt)
    validate_monitor_service_reconciliation(
        receipt,
        service,
        monitor_slice,
        attempt_slice,
        observed_main_identity=receipt.main_identity,
        reconciler_pid=999,
    )

    changed = dict(service, InvocationID="b" * 32)
    with pytest.raises(SandboxMonitorReceiptError, match="monitor service no longer"):
        validate_monitor_service_reconciliation(
            receipt,
            changed,
            monitor_slice,
            attempt_slice,
            observed_main_identity=receipt.main_identity,
            reconciler_pid=999,
        )

    with pytest.raises(SandboxMonitorReceiptError, match="PID start identity changed"):
        validate_monitor_service_reconciliation(
            receipt,
            service,
            monitor_slice,
            attempt_slice,
            observed_main_identity="linux:102:12346",
            reconciler_pid=999,
        )

    with pytest.raises(SandboxMonitorReceiptError, match="original controller"):
        validate_monitor_service_reconciliation(
            receipt,
            service,
            monitor_slice,
            attempt_slice,
            observed_main_identity=receipt.main_identity,
            reconciler_pid=receipt.controller_pid,
        )

    with pytest.raises(SandboxMonitorReceiptError, match="monitor slice no longer"):
        validate_monitor_service_reconciliation(
            receipt,
            service,
            dict(monitor_slice, ActiveState="inactive"),
            attempt_slice,
            observed_main_identity=receipt.main_identity,
            reconciler_pid=999,
        )

    with pytest.raises(SandboxMonitorReceiptError, match="attempt slice no longer"):
        validate_monitor_service_reconciliation(
            receipt,
            service,
            monitor_slice,
            dict(attempt_slice, Slice="default.slice"),
            observed_main_identity=receipt.main_identity,
            reconciler_pid=999,
        )


def test_receipt_fields_match_journal_unit_derivation() -> None:
    receipt = _receipt()
    identity = json.dumps(
        {
            "attempt_id": receipt.attempt_id,
            "claim_token": receipt.claim_token,
            "execution_id": receipt.execution_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    expected_container_id = f"acp-{hashlib.sha256(identity.encode()).hexdigest()[:60]}"
    assert receipt.unit == f"acp-monitor-{expected_container_id.removeprefix('acp-')}.service"
