from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

import agent_control_plane.supervisor.sandbox_monitor_receipt as receipt_module
from agent_control_plane.supervisor.sandbox_monitor_receipt import (
    SandboxMonitorControlRequest,
    SandboxMonitorReceipt,
    SandboxMonitorReceiptError,
    decode_sandbox_monitor_control_request,
    encode_sandbox_monitor_control_request,
    load_or_create_sandbox_monitor_control_key,
    read_sandbox_monitor_receipt,
    sandbox_attempt_slice_unit,
    sandbox_container_id,
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


def test_monitor_control_key_is_durable_and_bound_to_the_fenced_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "control-keys"
    directory.mkdir(mode=0o700)
    key = load_or_create_sandbox_monitor_control_key(
        directory,
        attempt_id="attempt-1",
        claim_token=7,
        execution_id="execution-1",
    )
    with monkeypatch.context() as patcher:
        patcher.setattr(
            receipt_module.secrets,
            "token_bytes",
            lambda *_args: pytest.fail("existing monitor key must be loaded without reminting"),
        )
        replayed = load_or_create_sandbox_monitor_control_key(
            directory,
            attempt_id="attempt-1",
            claim_token=7,
            execution_id="execution-1",
        )
    next_fence = load_or_create_sandbox_monitor_control_key(
        directory,
        attempt_id="attempt-1",
        claim_token=8,
        execution_id="execution-2",
    )

    key_path = directory / f"{sandbox_container_id('attempt-1', 7, 'execution-1')}.control-key"
    assert len(key) == 32
    assert replayed == key
    assert next_fence != key
    assert key_path.read_bytes() == key
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    assert key_path.stat().st_nlink == 1
    assert len(list(directory.glob("*.control-key"))) == 2
    assert len(list(directory.glob(".*.control-key.lock"))) == 2
    encoded = encode_sandbox_monitor_control_request(
        attempt_id="attempt-1",
        claim_token=7,
        execution_id="execution-1",
        request_id="a" * 32,
        operation="cancel",
        key=key,
    )
    decoded = decode_sandbox_monitor_control_request(
        encoded,
        key=replayed,
        expected_identity=("attempt-1", 7, "execution-1"),
    )
    assert decoded.operation == "cancel"
    with pytest.raises(SandboxMonitorReceiptError, match="authentication failed"):
        decode_sandbox_monitor_control_request(
            encoded,
            key=next_fence,
            expected_identity=("attempt-1", 7, "execution-1"),
        )
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            "import hashlib, sys; from agent_control_plane.supervisor.sandbox_monitor_receipt "
            "import load_or_create_sandbox_monitor_control_key; key = "
            "load_or_create_sandbox_monitor_control_key(sys.argv[1], attempt_id=sys.argv[2], "
            "claim_token=int(sys.argv[3]), execution_id=sys.argv[4]); "
            "print(hashlib.sha256(key).hexdigest())",
            str(directory),
            "attempt-1",
            "7",
            "execution-1",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert child.stdout.strip() == hashlib.sha256(key).hexdigest()


def test_monitor_control_key_concurrent_creation_returns_one_durable_secret(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "control-keys"
    directory.mkdir(mode=0o700)

    def load() -> bytes:
        return load_or_create_sandbox_monitor_control_key(
            directory,
            attempt_id="attempt-race",
            claim_token=3,
            execution_id="execution-race",
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        keys = list(pool.map(lambda _index: load(), range(32)))

    assert len(set(keys)) == 1
    assert len(list(directory.glob("*.control-key"))) == 1
    assert len(list(directory.glob(".*.control-key.lock"))) == 1


def test_monitor_control_key_reclaims_private_prepublication_crash_residue(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "control-keys"
    directory.mkdir(mode=0o700)
    key_name = f"{sandbox_container_id('attempt-crash', 4, 'execution-crash')}.control-key"
    project = Path(__file__).resolve().parents[1]
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            "import os, sys; import agent_control_plane.supervisor.sandbox_monitor_receipt as r; "
            "r.os.link = lambda *args, **kwargs: os._exit(77); "
            "r.load_or_create_sandbox_monitor_control_key(sys.argv[1], attempt_id='attempt-crash', "
            "claim_token=4, execution_id='execution-crash'); raise SystemExit(1)",
            str(directory),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        cwd=project,
    )
    assert child.returncode == 77, child.stderr
    stale_files = list(directory.glob(f".{key_name}.*.tmp"))
    assert len(stale_files) == 1
    stale = stale_files[0]
    assert stale.stat().st_nlink == 1
    assert stale.stat().st_size == 32

    key = load_or_create_sandbox_monitor_control_key(
        directory,
        attempt_id="attempt-crash",
        claim_token=4,
        execution_id="execution-crash",
    )

    assert len(key) == 32
    assert not stale.exists()
    assert (directory / key_name).read_bytes() == key


def test_monitor_control_key_cross_process_creation_is_serialized(tmp_path: Path) -> None:
    directory = tmp_path / "control-keys"
    directory.mkdir(mode=0o700)
    project = Path(__file__).resolve().parents[1]
    ready_directory = directory / "ready"
    ready_directory.mkdir(mode=0o700)
    gate = directory / "start"
    mint_log = directory / "mint.log"
    child_program = textwrap.dedent(
        r"""
        import hashlib
        import os
        import pathlib
        import sys
        import time

        import agent_control_plane.supervisor.sandbox_monitor_receipt as receipt

        directory = pathlib.Path(sys.argv[1])
        worker_id = sys.argv[2]
        ready_directory = pathlib.Path(sys.argv[3])
        gate = pathlib.Path(sys.argv[4])
        mint_log = pathlib.Path(sys.argv[5])
        (ready_directory / worker_id).write_text("ready", encoding="utf-8")
        while not gate.exists():
            time.sleep(0.005)

        original_token_bytes = receipt.secrets.token_bytes

        def counted_token_bytes(length):
            descriptor = os.open(
                mint_log,
                os.O_WRONLY | os.O_APPEND | os.O_CREAT,
                0o600,
            )
            try:
                os.write(descriptor, b"mint\n")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            time.sleep(0.05)
            return original_token_bytes(length)

        receipt.secrets.token_bytes = counted_token_bytes
        key = receipt.load_or_create_sandbox_monitor_control_key(
            directory,
            attempt_id="attempt-process-race",
            claim_token=5,
            execution_id="execution-process-race",
        )
        print(hashlib.sha256(key).hexdigest())
        """
    )
    processes: list[subprocess.Popen[str]] = []
    try:
        for index in range(4):
            processes.append(
                subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        child_program,
                        str(directory),
                        str(index),
                        str(ready_directory),
                        str(gate),
                        str(mint_log),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=project,
                )
            )

        deadline = time.monotonic() + 10
        while len(list(ready_directory.iterdir())) != len(processes):
            assert all(process.poll() is None for process in processes), (
                "child exited before reaching the start barrier"
            )
            assert time.monotonic() < deadline, "children did not reach the start barrier"
            time.sleep(0.01)
        gate.touch()
        results = [process.communicate(timeout=20) for process in processes]
        for process, (_stdout, stderr) in zip(processes, results, strict=True):
            assert process.returncode == 0, stderr
        digests = [stdout.strip() for stdout, _stderr in results]
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.communicate()

    assert len(set(digests)) == 1
    assert mint_log.read_text(encoding="utf-8").splitlines() == ["mint"]
    assert len(list(directory.glob("*.control-key"))) == 1
    assert len(list(directory.glob(".*.control-key.lock"))) == 1


def test_monitor_control_key_recovers_a_published_orphan_link(tmp_path: Path) -> None:
    directory = tmp_path / "control-keys"
    directory.mkdir(mode=0o700)
    key_name = f"{sandbox_container_id('attempt-orphan', 9, 'execution-orphan')}.control-key"
    key_path = directory / key_name
    expected = b"k" * 32
    key_path.write_bytes(expected)
    key_path.chmod(0o600)
    orphan = directory / f".{key_name}.{'a' * 32}.tmp"
    os.link(key_path, orphan)

    actual = load_or_create_sandbox_monitor_control_key(
        directory,
        attempt_id="attempt-orphan",
        claim_token=9,
        execution_id="execution-orphan",
    )

    assert actual == expected
    assert not orphan.exists()
    assert key_path.stat().st_nlink == 1


@pytest.mark.parametrize("unsafe_entry", ["symlink", "wrong_mode", "unrelated_hardlink"])
def test_monitor_control_key_rejects_unsafe_persisted_entries(
    tmp_path: Path, unsafe_entry: str
) -> None:
    directory = tmp_path / "control-keys"
    directory.mkdir(mode=0o700)
    key_name = f"{sandbox_container_id('attempt-unsafe', 1, 'execution-unsafe')}.control-key"
    key_path = directory / key_name
    source = directory / "source"
    source.write_bytes(b"s" * 32)
    source.chmod(0o600)
    if unsafe_entry == "symlink":
        key_path.symlink_to(source)
    else:
        key_path.write_bytes(b"k" * 32)
        key_path.chmod(0o600)
        if unsafe_entry == "wrong_mode":
            key_path.chmod(0o644)
        else:
            os.link(key_path, directory / "unrelated-link")

    with pytest.raises(SandboxMonitorReceiptError):
        load_or_create_sandbox_monitor_control_key(
            directory,
            attempt_id="attempt-unsafe",
            claim_token=1,
            execution_id="execution-unsafe",
        )


def test_monitor_control_key_requires_canonical_private_directory(tmp_path: Path) -> None:
    public = tmp_path / "public-control-keys"
    public.mkdir(mode=0o700)
    public.chmod(0o755)

    with pytest.raises(SandboxMonitorReceiptError, match="directory must be owned and mode 0700"):
        load_or_create_sandbox_monitor_control_key(
            public,
            attempt_id="attempt-public",
            claim_token=1,
            execution_id="execution-public",
        )

    link = tmp_path / "control-key-link"
    private = tmp_path / "private-control-keys"
    private.mkdir(mode=0o700)
    link.symlink_to(private, target_is_directory=True)
    with pytest.raises(OSError):
        load_or_create_sandbox_monitor_control_key(
            link,
            attempt_id="attempt-link",
            claim_token=1,
            execution_id="execution-link",
        )


@pytest.mark.parametrize("unsafe_lock", ["symlink", "wrong_mode", "unrelated_hardlink"])
def test_monitor_control_key_rejects_unsafe_lock_entries(tmp_path: Path, unsafe_lock: str) -> None:
    directory = tmp_path / "control-keys"
    directory.mkdir(mode=0o700)
    key_name = f"{sandbox_container_id('attempt-lock', 2, 'execution-lock')}.control-key"
    lock_path = directory / f".{key_name}.lock"
    source = directory / "lock-source"
    source.write_bytes(b"")
    source.chmod(0o600)
    if unsafe_lock == "symlink":
        lock_path.symlink_to(source)
    else:
        lock_path.write_bytes(b"")
        lock_path.chmod(0o600)
        if unsafe_lock == "wrong_mode":
            lock_path.chmod(0o644)
        else:
            os.link(lock_path, directory / "unrelated-lock-link")

    with pytest.raises(SandboxMonitorReceiptError):
        load_or_create_sandbox_monitor_control_key(
            directory,
            attempt_id="attempt-lock",
            claim_token=2,
            execution_id="execution-lock",
        )

    assert not (directory / key_name).exists()


def test_monitor_control_key_fsyncs_key_and_directory_before_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "control-keys"
    directory.mkdir(mode=0o700)
    original_fsync = os.fsync
    directory_syncs: list[int] = []

    def record_fsync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            directory_syncs.append(descriptor)
        original_fsync(descriptor)

    monkeypatch.setattr(receipt_module.os, "fsync", record_fsync)
    key = load_or_create_sandbox_monitor_control_key(
        directory,
        attempt_id="attempt-fsync",
        claim_token=1,
        execution_id="execution-fsync",
    )

    assert len(key) == 32
    assert len(directory_syncs) >= 2


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


_CONTROL_KEY = b"monitor-control-test-key-0000000"


def _control_request(operation: str = "status", **overrides: object) -> bytes:
    receipt = _receipt()
    values: dict[str, object] = {
        "attempt_id": receipt.attempt_id,
        "claim_token": receipt.claim_token,
        "execution_id": receipt.execution_id,
        "request_id": "c" * 32,
        "operation": operation,
        "key": _CONTROL_KEY,
    }
    values.update(overrides)
    return encode_sandbox_monitor_control_request(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize("operation", ["status", "cancel"])
def test_monitor_control_request_round_trips_only_fenced_control_intent(operation: str) -> None:
    receipt = _receipt()
    encoded = _control_request(operation)
    request = decode_sandbox_monitor_control_request(
        encoded,
        key=_CONTROL_KEY,
        expected_identity=(receipt.attempt_id, receipt.claim_token, receipt.execution_id),
    )

    assert type(request) is SandboxMonitorControlRequest
    assert request.operation == operation
    assert request.request_id == "c" * 32
    assert request.attempt_id == receipt.attempt_id
    assert request.claim_token == receipt.claim_token
    assert request.execution_id == receipt.execution_id


@pytest.mark.parametrize("operation", ["status", "cancel"])
def test_monitor_control_read_and_cancel_requests_carry_no_launch_plan(
    operation: str,
) -> None:
    receipt = _receipt()
    request = decode_sandbox_monitor_control_request(
        _control_request(operation),
        key=_CONTROL_KEY,
        expected_identity=(receipt.attempt_id, receipt.claim_token, receipt.execution_id),
    )
    assert request.operation == operation


@pytest.mark.parametrize("operation", ["start", "exec", "launch", "release_gate", "delete"])
def test_monitor_control_codec_rejects_arbitrary_execution_operations(operation: str) -> None:
    with pytest.raises(SandboxMonitorReceiptError, match="operation is not allowed"):
        _control_request(operation)


def test_monitor_control_request_rejects_mac_or_key_tampering() -> None:
    receipt = _receipt()
    encoded = _control_request("status")
    changed = json.loads(encoded)
    changed["operation"] = "cancel"
    changed_bytes = json.dumps(changed, sort_keys=True, separators=(",", ":")).encode("ascii")

    with pytest.raises(SandboxMonitorReceiptError, match="authentication failed"):
        decode_sandbox_monitor_control_request(
            changed_bytes,
            key=_CONTROL_KEY,
            expected_identity=(receipt.attempt_id, receipt.claim_token, receipt.execution_id),
        )
    with pytest.raises(SandboxMonitorReceiptError, match="authentication failed"):
        decode_sandbox_monitor_control_request(
            encoded,
            key=b"x" * 32,
            expected_identity=(receipt.attempt_id, receipt.claim_token, receipt.execution_id),
        )


def test_monitor_control_request_rejects_stale_execution_fence() -> None:
    receipt = _receipt()
    with pytest.raises(SandboxMonitorReceiptError, match="another execution"):
        decode_sandbox_monitor_control_request(
            _control_request("cancel"),
            key=_CONTROL_KEY,
            expected_identity=(receipt.attempt_id, receipt.claim_token + 1, receipt.execution_id),
        )


def test_monitor_control_request_rejects_duplicate_and_noncanonical_json() -> None:
    receipt = _receipt()
    encoded = _control_request("status")
    duplicate = encoded[:-1] + b',"version":1}'
    with pytest.raises(SandboxMonitorReceiptError, match="duplicate JSON keys"):
        decode_sandbox_monitor_control_request(
            duplicate,
            key=_CONTROL_KEY,
            expected_identity=(receipt.attempt_id, receipt.claim_token, receipt.execution_id),
        )

    noncanonical = json.dumps(json.loads(encoded), indent=2).encode("ascii")
    with pytest.raises(SandboxMonitorReceiptError, match="not canonical JSON"):
        decode_sandbox_monitor_control_request(
            noncanonical,
            key=_CONTROL_KEY,
            expected_identity=(receipt.attempt_id, receipt.claim_token, receipt.execution_id),
        )


@pytest.mark.parametrize("key", [b"short", b"x" * 33, bytearray(b"x" * 32)])
def test_monitor_control_codec_requires_a_fixed_length_byte_key(key: object) -> None:
    receipt = _receipt()
    with pytest.raises(SandboxMonitorReceiptError, match="exactly 32 bytes"):
        encode_sandbox_monitor_control_request(
            attempt_id=receipt.attempt_id,
            claim_token=receipt.claim_token,
            execution_id=receipt.execution_id,
            request_id="c" * 32,
            operation="status",
            key=key,  # type: ignore[arg-type]
        )
