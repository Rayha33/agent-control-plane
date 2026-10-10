from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_control_plane.supervisor import oci_worker, sandbox_attestation
from agent_control_plane.supervisor.common import SupervisorError, canonical_json
from agent_control_plane.supervisor.oci_worker import _oci_worker_systemd_slice
from agent_control_plane.supervisor.sandbox_attestation import (
    ProcessSnapshot,
    collect_running_runtime_attestation,
    read_private_runc_pid_file,
    running_attestation_has_collector_provenance,
    running_attestation_is_self_consistent,
    validate_running_runtime_attestation,
    verify_running_runtime_process_membership,
)

_ATTEMPT_SLICE_UNIT = _oci_worker_systemd_slice("acp-test-container")
_ATTEMPT_SLICE_CGROUP = (
    f"/user.slice/user-1000.slice/user@1000.service/app.slice/{_ATTEMPT_SLICE_UNIT}"
)
_MONITOR_PARENT_CGROUP = "/user.slice/user-1000.slice/user@1000.service/app.slice"
_WRAPPER_CGROUP = f"{_MONITOR_PARENT_CGROUP}/acp-worker.service"
_SCOPE_CGROUP = f"{_ATTEMPT_SLICE_CGROUP}/acp-container.scope"


def _proc_stat(pid: int, state: str, start: int, comm: str = "worker (gate)") -> bytes:
    fields = [state.encode("ascii"), *([b"0"] * 18), str(start).encode("ascii")]
    return f"{pid} ({comm}) ".encode("ascii") + b" ".join(fields) + b"\n"


def _properties(*, unit: str, invocation: str, cgroup: str, active: str = "active") -> bytes:
    return f"ActiveState={active}\nControlGroup={cgroup}\nId={unit}\nInvocationID={invocation}\n".encode(
        "ascii"
    )


def _valid_observations() -> dict:
    pids = (101, 202, 303)
    starts = {101: 1101, 202: 1202, 303: 1303}
    groups = {101: _WRAPPER_CGROUP, 202: _WRAPPER_CGROUP, 303: _SCOPE_CGROUP}
    return {
        "runc_state": json.dumps(
            {
                "id": "acp-test-container",
                "status": "running",
                "pid": 303,
                "bundle": "/state/attempt/bundle",
                "annotations": {"example": "ignored but bounded"},
            }
        ).encode("utf-8"),
        "pid_file": b"303\n",
        "process_snapshots": {
            pid: ProcessSnapshot(
                stat_before=_proc_stat(pid, "S", starts[pid]),
                cgroup=f"0::{groups[pid]}\n".encode("ascii"),
                stat_after=_proc_stat(pid, "S", starts[pid]),
            )
            for pid in pids
        },
        "wrapper_properties": _properties(
            unit="acp-worker.service", invocation="1" * 32, cgroup=_WRAPPER_CGROUP
        ),
        "attempt_slice_properties": _properties(
            unit=_ATTEMPT_SLICE_UNIT,
            invocation="3" * 32,
            cgroup=_ATTEMPT_SLICE_CGROUP,
        ),
        "scope_properties": _properties(
            unit="acp-container.scope", invocation="2" * 32, cgroup=_SCOPE_CGROUP
        ),
        "expected_container_id": "acp-test-container",
        "expected_bundle_path": "/state/attempt/bundle",
        "expected_monitor_pid": 101,
        "expected_monitor_identity": "linux:101:1101",
        "expected_runc_client_pid": 202,
        "expected_runc_client_identity": "linux:202:1202",
        "expected_wrapper_unit": "acp-worker.service",
        "expected_wrapper_invocation_id": "1" * 32,
        "expected_attempt_slice_unit": _ATTEMPT_SLICE_UNIT,
        "expected_attempt_slice_invocation_id": "3" * 32,
        "expected_scope_unit": "acp-container.scope",
        "expected_scope_invocation_id": "2" * 32,
        "expected_cgroup_path": _SCOPE_CGROUP,
        "resource_control_files": {
            "memory.max": b"1073741824\n",
            "cpu.max": b"100000 100000\n",
            "pids.max": b"256\n",
        },
        "expected_memory_max_bytes": 1_073_741_824,
        "expected_cpu_quota": 100_000,
        "expected_cpu_period": 100_000,
        "expected_pids_max": 256,
    }


def _validate(**overrides):
    observations = _valid_observations()
    observations.update(overrides)
    return validate_running_runtime_attestation(**observations)


def _private_pid_file(tmp_path, content: bytes = b"303\n"):
    state_root = tmp_path / "runc-state"
    state_root.mkdir(mode=0o700)
    state_root.chmod(0o700)
    metadata = state_root / "metadata"
    metadata.mkdir(mode=0o700)
    metadata.chmod(0o700)
    pid_file = metadata / "init.pid"
    pid_file.write_bytes(content)
    pid_file.chmod(0o600)
    return state_root, pid_file


def test_attestation_binds_runtime_state_pid_start_identities_and_cgroups() -> None:
    receipt = _validate()

    assert receipt.container_id == "acp-test-container"
    assert receipt.monitor_placement == "outside_attempt_slice"
    assert receipt.init_pid == 303
    assert receipt.init_identity == "linux:303:1303"
    assert receipt.wrapper_control_group == _WRAPPER_CGROUP
    assert receipt.attempt_slice_unit == _ATTEMPT_SLICE_UNIT
    assert receipt.attempt_slice_invocation_id == "3" * 32
    assert receipt.attempt_slice_control_group == _ATTEMPT_SLICE_CGROUP
    assert receipt.cgroup_path == _SCOPE_CGROUP
    assert receipt.memory_max_bytes == 1_073_741_824
    assert receipt.cpu_quota == 100_000
    assert receipt.cpu_period == 100_000
    assert receipt.pids_max == 256
    assert len(receipt.runc_state_sha256) == 64
    assert len(receipt.evidence_sha256) == 64
    assert receipt.audit_payload()["init_identity"] == "linux:303:1303"


def test_release_verifier_rereads_all_execution_processes(monkeypatch: pytest.MonkeyPatch) -> None:
    receipt = _validate()
    snapshots = _valid_observations()["process_snapshots"]
    observed: list[int] = []

    def read_snapshot(pid: int) -> ProcessSnapshot:
        observed.append(pid)
        return snapshots[pid]

    monkeypatch.setattr(sandbox_attestation, "read_linux_process_snapshot", read_snapshot)
    verify_running_runtime_process_membership(receipt)

    assert set(observed) == {receipt.monitor_pid, receipt.runc_client_pid, receipt.init_pid}
    assert len(observed) == 3


@pytest.mark.parametrize("drift", ["pid_reuse", "moved_cgroup", "exited"])
def test_release_verifier_rejects_process_identity_or_cgroup_drift(
    drift: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = _validate()
    snapshots = _valid_observations()["process_snapshots"]
    init = snapshots[receipt.init_pid]
    if drift == "pid_reuse":
        changed = ProcessSnapshot(
            _proc_stat(receipt.init_pid, "S", 9999),
            init.cgroup,
            _proc_stat(receipt.init_pid, "S", 9999),
        )
    elif drift == "moved_cgroup":
        changed = ProcessSnapshot(
            init.stat_before,
            b"0::/user.slice/foreign.scope\n",
            init.stat_after,
        )
    else:
        changed = ProcessSnapshot(
            _proc_stat(receipt.init_pid, "Z", 1303),
            init.cgroup,
            _proc_stat(receipt.init_pid, "Z", 1303),
        )
    snapshots[receipt.init_pid] = changed
    monkeypatch.setattr(
        sandbox_attestation,
        "read_linux_process_snapshot",
        lambda pid: snapshots[pid],
    )

    with pytest.raises(SupervisorError) as stale:
        verify_running_runtime_process_membership(receipt)

    assert stale.value.code == "sandbox_runtime_attestation_stale"


def test_private_runc_pid_file_reader_accepts_stable_file(tmp_path) -> None:
    state_root, pid_file = _private_pid_file(tmp_path)

    assert read_private_runc_pid_file(pid_file, state_root) == b"303\n"


@pytest.mark.parametrize("content", [b"", b"0303\n", b"0\n", b"303\n304\n", b"1" * 12])
def test_private_runc_pid_file_reader_rejects_noncanonical_or_oversized_content(
    tmp_path, content: bytes
) -> None:
    state_root, pid_file = _private_pid_file(tmp_path, content)

    with pytest.raises(SupervisorError) as invalid:
        read_private_runc_pid_file(pid_file, state_root)

    assert invalid.value.code == "sandbox_runtime_attestation_invalid"


def test_private_runc_pid_file_reader_rejects_group_or_other_writable_file(tmp_path) -> None:
    state_root, pid_file = _private_pid_file(tmp_path)
    pid_file.chmod(0o620)

    with pytest.raises(SupervisorError, match="single-link regular file"):
        read_private_runc_pid_file(pid_file, state_root)


def test_private_runc_pid_file_reader_rejects_symlinks_and_hardlinks(tmp_path) -> None:
    state_root, pid_file = _private_pid_file(tmp_path)
    outside = tmp_path / "outside.pid"
    outside.write_bytes(b"303\n")
    pid_file.unlink()
    pid_file.symlink_to(outside)

    with pytest.raises(SupervisorError, match="single-link regular file"):
        read_private_runc_pid_file(pid_file, state_root)
    assert outside.read_bytes() == b"303\n"

    pid_file.unlink()
    pid_file.write_bytes(b"303\n")
    pid_file.chmod(0o600)
    os.link(pid_file, pid_file.with_name("alias.pid"))
    with pytest.raises(SupervisorError, match="single-link regular file"):
        read_private_runc_pid_file(pid_file, state_root)


def test_private_runc_pid_file_reader_rejects_writable_parent_and_external_path(tmp_path) -> None:
    state_root, pid_file = _private_pid_file(tmp_path)
    pid_file.parent.chmod(0o755)
    with pytest.raises(SupervisorError, match="accessible only to that user"):
        read_private_runc_pid_file(pid_file, state_root)

    pid_file.parent.chmod(0o700)
    outside_root = tmp_path / "other-state"
    outside_root.mkdir(mode=0o700)
    outside_root.chmod(0o700)
    outside_pid = outside_root / "init.pid"
    outside_pid.write_bytes(b"303\n")
    outside_pid.chmod(0o600)
    with pytest.raises(SupervisorError, match="inside the private state root"):
        read_private_runc_pid_file(outside_pid, state_root)


def test_private_runc_pid_file_reader_detects_replacement_after_open(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_root, pid_file = _private_pid_file(tmp_path)
    read_descriptor = sandbox_attestation._read_pid_file_bytes

    def replace_after_read(descriptor: int) -> bytes:
        raw = read_descriptor(descriptor)
        pid_file.unlink()
        pid_file.write_bytes(b"404\n")
        pid_file.chmod(0o600)
        return raw

    monkeypatch.setattr(sandbox_attestation, "_read_pid_file_bytes", replace_after_read)
    with pytest.raises(SupervisorError, match="changed while it was read"):
        read_private_runc_pid_file(pid_file, state_root)


def test_private_runc_pid_file_reader_opens_nonblocking_after_fifo_swap(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_root, pid_file = _private_pid_file(tmp_path)
    real_open = os.open
    swapped = False

    def swap_to_fifo(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if os.fspath(path) == str(pid_file) and not swapped:
            swapped = True
            pid_file.unlink()
            os.mkfifo(pid_file, 0o600)
            assert flags & os.O_NONBLOCK
            assert flags & os.O_NOFOLLOW
            assert flags & os.O_CLOEXEC
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(sandbox_attestation.os, "open", swap_to_fifo)
    with pytest.raises(SupervisorError, match="changed while it was opened"):
        read_private_runc_pid_file(pid_file, state_root)
    assert swapped


def test_observation_normalization_cannot_mint_collector_provenance(tmp_path, monkeypatch) -> None:
    observations = _valid_observations()
    state_root, pid_file = _private_pid_file(tmp_path)
    proc_observations = {
        101: (_proc_stat(101, "S", 1101), _WRAPPER_CGROUP.encode("ascii")),
        202: (_proc_stat(202, "S", 1202), _WRAPPER_CGROUP.encode("ascii")),
        303: (_proc_stat(303, "S", 1303), _SCOPE_CGROUP.encode("ascii")),
    }

    monkeypatch.setattr(sandbox_attestation.sys, "platform", "linux")

    def read_proc(path: str) -> bytes:
        parts = path.split("/")
        pid = int(parts[2])
        before_or_after_stat, cgroup = proc_observations[pid]
        return b"0::" + cgroup + b"\n" if parts[-1] == "cgroup" else before_or_after_stat

    monkeypatch.setattr(sandbox_attestation, "_read_proc_file", read_proc)
    monkeypatch.setattr(
        sandbox_attestation,
        "read_cgroup_resource_controls",
        lambda _path, **_kwargs: observations["resource_control_files"],
    )
    receipt = sandbox_attestation._collect_running_runtime_attestation_from_observations(
        runc_state=observations["runc_state"],
        pid_file_path=pid_file,
        state_root=state_root,
        wrapper_properties=observations["wrapper_properties"],
        attempt_slice_properties=observations["attempt_slice_properties"],
        scope_properties=observations["scope_properties"],
        expected_container_id=observations["expected_container_id"],
        expected_bundle_path=observations["expected_bundle_path"],
        expected_monitor_pid=observations["expected_monitor_pid"],
        expected_monitor_identity=observations["expected_monitor_identity"],
        expected_runc_client_pid=observations["expected_runc_client_pid"],
        expected_runc_client_identity=observations["expected_runc_client_identity"],
        expected_wrapper_unit=observations["expected_wrapper_unit"],
        expected_wrapper_invocation_id=observations["expected_wrapper_invocation_id"],
        expected_attempt_slice_unit=observations["expected_attempt_slice_unit"],
        expected_attempt_slice_invocation_id=observations["expected_attempt_slice_invocation_id"],
        expected_scope_unit=observations["expected_scope_unit"],
        expected_scope_invocation_id=observations["expected_scope_invocation_id"],
        expected_cgroup_path=observations["expected_cgroup_path"],
        expected_memory_max_bytes=observations["expected_memory_max_bytes"],
        expected_cpu_quota=observations["expected_cpu_quota"],
        expected_cpu_period=observations["expected_cpu_period"],
        expected_pids_max=observations["expected_pids_max"],
    )

    assert receipt.init_pid == 303
    assert receipt.init_identity == "linux:303:1303"
    assert running_attestation_is_self_consistent(receipt)
    assert not running_attestation_has_collector_provenance(receipt)


def test_trusted_collector_reads_pinned_runc_and_exact_systemd_units(tmp_path, monkeypatch) -> None:
    observations = _valid_observations()
    state_root, pid_file = _private_pid_file(tmp_path)
    proc_observations = {
        101: (_proc_stat(101, "S", 1101), _WRAPPER_CGROUP.encode("ascii")),
        202: (_proc_stat(202, "S", 1202), _WRAPPER_CGROUP.encode("ascii")),
        303: (_proc_stat(303, "S", 1303), _SCOPE_CGROUP.encode("ascii")),
    }
    commands: list[tuple[list[str], dict]] = []
    executable_fd = os.open(os.devnull, os.O_RDONLY)
    monkeypatch.setattr(sandbox_attestation.sys, "platform", "linux")
    monkeypatch.setattr(
        sandbox_attestation, "_trusted_systemctl_executable", lambda: Path("/usr/bin/systemctl")
    )
    monkeypatch.setattr(
        sandbox_attestation,
        "_trusted_systemd_command_environment",
        lambda: {"LANG": "C", "LC_ALL": "C"},
    )
    monkeypatch.setattr(
        oci_worker,
        "_verify_trusted_runc_executable",
        lambda _pin: Path("/usr/bin/runc"),
    )
    monkeypatch.setattr(
        oci_worker,
        "_open_verified_runc_executable",
        lambda _pin: executable_fd,
    )

    def run_bounded(argv, **kwargs):
        command = list(argv)
        commands.append((command, kwargs))
        if command[0] == "/usr/bin/runc":
            assert command[1:] == [
                "--root",
                str(state_root),
                "state",
                "acp-test-container",
            ]
            assert kwargs["pass_fds"] == (executable_fd,)
            assert kwargs["exec_fd"] == executable_fd
            return 0, observations["runc_state"].decode("utf-8")
        assert command[:5] == [
            "/usr/bin/systemctl",
            "--user",
            "show",
            "--no-pager",
            "--property=ActiveState,ControlGroup,Id,InvocationID",
        ]
        assert command[5] == "--"
        assert kwargs.get("exec_fd") is None
        return 0, {
            "acp-worker.service": observations["wrapper_properties"],
            _ATTEMPT_SLICE_UNIT: observations["attempt_slice_properties"],
            "acp-container.scope": observations["scope_properties"],
        }[command[-1]].decode("ascii")

    monkeypatch.setattr(oci_worker, "_run_bounded_command", run_bounded)

    def read_proc(path: str) -> bytes:
        parts = path.split("/")
        pid = int(parts[2])
        before_or_after_stat, cgroup = proc_observations[pid]
        return b"0::" + cgroup + b"\n" if parts[-1] == "cgroup" else before_or_after_stat

    monkeypatch.setattr(sandbox_attestation, "_read_proc_file", read_proc)
    monkeypatch.setattr(
        sandbox_attestation,
        "read_cgroup_resource_controls",
        lambda _path, **_kwargs: observations["resource_control_files"],
    )
    expected = {
        key: value
        for key, value in observations.items()
        if key
        not in {
            "runc_state",
            "pid_file",
            "process_snapshots",
            "wrapper_properties",
            "attempt_slice_properties",
            "scope_properties",
            "resource_control_files",
        }
    }
    runc_pin = SimpleNamespace(sha256="a" * 64)
    receipt = collect_running_runtime_attestation(
        runc_executable_pin=runc_pin,
        state_root=state_root,
        pid_file_path=pid_file,
        **expected,
    )

    assert receipt.init_pid == 303
    assert receipt.init_identity == "linux:303:1303"
    assert running_attestation_has_collector_provenance(receipt)
    assert len(commands) == 4
    assert {command[-1] for command, _kwargs in commands[1:]} == {
        "acp-worker.service",
        _ATTEMPT_SLICE_UNIT,
        "acp-container.scope",
    }


def _write_cgroup_controls(
    directory, *, memory=b"1073741824\n", cpu=b"100000 100000\n", pids=b"256\n"
):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "memory.max").write_bytes(memory)
    (directory / "cpu.max").write_bytes(cpu)
    (directory / "pids.max").write_bytes(pids)


def test_cgroup_resource_reader_uses_exact_no_follow_cgroup_path(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sandbox_attestation.sys, "platform", "linux")
    cgroup_root = tmp_path / "cgroup"
    scope = cgroup_root / _SCOPE_CGROUP.lstrip("/")
    _write_cgroup_controls(scope)

    assert (
        sandbox_attestation.read_cgroup_resource_controls(_SCOPE_CGROUP, cgroup_root=cgroup_root)
        == _valid_observations()["resource_control_files"]
    )


def test_cgroup_resource_reader_rejects_symlinked_scope_component(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sandbox_attestation.sys, "platform", "linux")
    cgroup_root = tmp_path / "cgroup"
    parts = _SCOPE_CGROUP.strip("/").split("/")
    parent = cgroup_root.joinpath(*parts[:-1])
    parent.mkdir(parents=True)
    outside = tmp_path / "outside"
    _write_cgroup_controls(outside)
    (parent / parts[-1]).symlink_to(outside, target_is_directory=True)

    with pytest.raises(SupervisorError, match="could not be read safely"):
        sandbox_attestation.read_cgroup_resource_controls(_SCOPE_CGROUP, cgroup_root=cgroup_root)


def test_cgroup_resource_reader_rejects_symlinked_control_file(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sandbox_attestation.sys, "platform", "linux")
    cgroup_root = tmp_path / "cgroup"
    scope = cgroup_root / _SCOPE_CGROUP.lstrip("/")
    scope.mkdir(parents=True)
    external = tmp_path / "memory-control"
    external.write_bytes(b"1073741824\n")
    (scope / "memory.max").symlink_to(external)
    (scope / "cpu.max").write_bytes(b"100000 100000\n")
    (scope / "pids.max").write_bytes(b"256\n")

    with pytest.raises(SupervisorError, match="could not be read safely"):
        sandbox_attestation.read_cgroup_resource_controls(_SCOPE_CGROUP, cgroup_root=cgroup_root)


@pytest.mark.parametrize(
    ("filesystem", "accepted"),
    [(b"cgroup2", True), (b"cgroup", False)],
)
def test_cgroup_root_mount_must_be_cgroup_v2(
    monkeypatch: pytest.MonkeyPatch, filesystem: bytes, accepted: bool
) -> None:
    monkeypatch.setattr(
        sandbox_attestation,
        "_read_proc_file",
        lambda _path: b"36 25 0:32 / /sys/fs/cgroup rw - " + filesystem + b" cgroup rw\n",
    )

    if accepted:
        sandbox_attestation._require_cgroup2_mount("/sys/fs/cgroup")
    else:
        with pytest.raises(SupervisorError, match="not mounted as cgroup v2"):
            sandbox_attestation._require_cgroup2_mount("/sys/fs/cgroup")


def test_default_cgroup_reader_rejects_non_v2_mount_before_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sandbox_attestation.sys, "platform", "linux")
    opened: list[str] = []
    real_open = sandbox_attestation.os.open

    def record_open(path, *args, **kwargs):
        opened.append(os.fspath(path))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(
        sandbox_attestation,
        "_read_proc_file",
        lambda _path: b"36 25 0:32 / /sys/fs/cgroup rw - cgroup cgroup rw\n",
    )
    monkeypatch.setattr(sandbox_attestation.os, "open", record_open)

    with pytest.raises(SupervisorError, match="not mounted as cgroup v2"):
        sandbox_attestation.read_cgroup_resource_controls(_SCOPE_CGROUP)
    assert opened == []


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("memory.max", b"1073741825\n"),
        ("cpu.max", b"100000 100001\n"),
        ("pids.max", b"257\n"),
    ],
)
def test_runtime_attestation_rejects_cgroup_control_mismatch(name: str, value: bytes) -> None:
    observations = _valid_observations()
    observations["resource_control_files"][name] = value

    with pytest.raises(SupervisorError, match="exact OCI launch limit"):
        validate_running_runtime_attestation(**observations)


def test_unkeyed_digest_checks_consistency_but_not_receipt_provenance() -> None:
    forged = replace(_validate(), init_pid=404, init_identity="linux:404:9999")
    payload = forged.audit_payload()
    payload.pop("evidence_sha256")
    recomputed = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    forged = replace(forged, evidence_sha256=recomputed)

    assert running_attestation_is_self_consistent(forged)
    assert not running_attestation_has_collector_provenance(forged)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("runc_state", b'{"id":"acp-test-container","id":"other"}'),
        (
            "runc_state",
            b'{"id":"acp-test-container","status":"running","pid":303,"bundle":"/state/attempt/bundle","ignored":NaN}',
        ),
        (
            "runc_state",
            b'{"id":"acp-test-container","status":"running","pid":303,"bundle":"/state/attempt/bundle","ignored":Infinity}',
        ),
        (
            "runc_state",
            json.dumps(
                {
                    "id": "acp-test-container",
                    "status": "stopped",
                    "pid": 303,
                    "bundle": "/state/attempt/bundle",
                }
            ).encode(),
        ),
        (
            "runc_state",
            json.dumps(
                {
                    "id": "wrong-container",
                    "status": "running",
                    "pid": 303,
                    "bundle": "/state/attempt/bundle",
                }
            ).encode(),
        ),
        ("pid_file", b"0303\n"),
        ("pid_file", b"303\n304\n"),
        ("pid_file", b"303\x00"),
        (
            "wrapper_properties",
            _properties(unit="different.service", invocation="1" * 32, cgroup=_WRAPPER_CGROUP),
        ),
        (
            "scope_properties",
            _properties(unit="acp-container.scope", invocation="2" * 32, cgroup="/other/scope"),
        ),
        (
            "scope_properties",
            _properties(
                unit="acp-container.scope",
                invocation="2" * 32,
                cgroup=_SCOPE_CGROUP,
                active="inactive",
            ),
        ),
        (
            "scope_properties",
            _properties(unit="acp-container.scope", invocation="2" * 32, cgroup=_SCOPE_CGROUP)
            + b"ActiveState=active\n",
        ),
        ("expected_cgroup_path", "/user.slice/../acp-container.scope"),
    ],
)
def test_attestation_rejects_mismatched_or_ambiguous_runtime_evidence(
    field: str, value: bytes | str
) -> None:
    with pytest.raises(SupervisorError) as invalid:
        _validate(**{field: value})

    assert invalid.value.code == "sandbox_runtime_attestation_invalid"


def test_attestation_rejects_pid_reuse_between_proc_observations() -> None:
    observations = _valid_observations()
    observations["process_snapshots"][303] = ProcessSnapshot(
        stat_before=_proc_stat(303, "S", 1303),
        cgroup=f"0::{_SCOPE_CGROUP}\n".encode(),
        stat_after=_proc_stat(303, "S", 9999),
    )

    with pytest.raises(SupervisorError, match="identity changed"):
        validate_running_runtime_attestation(**observations)


def test_attestation_rejects_process_cgroup_escape_and_non_live_pid() -> None:
    observations = _valid_observations()
    observations["process_snapshots"][202] = replace(
        observations["process_snapshots"][202], cgroup=b"0::/other.slice\n"
    )
    with pytest.raises(SupervisorError, match="outside"):
        validate_running_runtime_attestation(**observations)

    observations = _valid_observations()
    observations["process_snapshots"][303] = replace(
        observations["process_snapshots"][303], stat_before=_proc_stat(303, "Z", 1303)
    )
    with pytest.raises(SupervisorError, match="no longer live"):
        validate_running_runtime_attestation(**observations)


def test_attestation_rejects_units_outside_the_exact_attempt_slice() -> None:
    observations = _valid_observations()
    other_scope_cgroup = (
        "/user.slice/user-1000.slice/user@1000.service/app.slice/"
        "user-acp-unexpected.slice/acp-container.scope"
    )
    observations["scope_properties"] = _properties(
        unit="acp-container.scope", invocation="2" * 32, cgroup=other_scope_cgroup
    )
    observations["expected_cgroup_path"] = other_scope_cgroup
    observations["process_snapshots"][303] = replace(
        observations["process_snapshots"][303],
        cgroup=f"0::{other_scope_cgroup}\n".encode("ascii"),
    )

    with pytest.raises(SupervisorError, match="exact attempt slice"):
        validate_running_runtime_attestation(**observations)


@pytest.mark.parametrize(
    "monitor_cgroup",
    [
        f"{_ATTEMPT_SLICE_CGROUP}/acp-worker.service",
        f"{_ATTEMPT_SLICE_CGROUP}/nested/acp-worker.service",
        f"{_MONITOR_PARENT_CGROUP}/user-acp-{'f' * 64}.slice/acp-worker.service",
        _MONITOR_PARENT_CGROUP,
    ],
)
def test_attestation_rejects_monitor_inside_or_owning_worker_slice(monitor_cgroup: str) -> None:
    observations = _valid_observations()
    observations["wrapper_properties"] = _properties(
        unit="acp-worker.service", invocation="1" * 32, cgroup=monitor_cgroup
    )
    for pid in (101, 202):
        observations["process_snapshots"][pid] = replace(
            observations["process_snapshots"][pid],
            cgroup=f"0::{monitor_cgroup}\n".encode("ascii"),
        )

    with pytest.raises(SupervisorError, match="separate cgroups"):
        validate_running_runtime_attestation(**observations)


def test_self_consistency_rejects_monitor_cgroup_moved_into_worker_slice() -> None:
    receipt = _validate()
    forged = replace(
        receipt,
        wrapper_control_group=f"{_ATTEMPT_SLICE_CGROUP}/acp-worker.service",
    )
    payload = forged.audit_payload()
    payload.pop("evidence_sha256")
    forged = replace(
        forged,
        evidence_sha256=hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest(),
    )

    assert not running_attestation_is_self_consistent(forged)


def test_self_consistency_rejects_monitor_inside_sibling_attempt_slice() -> None:
    receipt = _validate()
    forged = replace(
        receipt,
        wrapper_control_group=(
            f"{_MONITOR_PARENT_CGROUP}/user-acp-{'f' * 64}.slice/acp-worker.service"
        ),
    )
    payload = forged.audit_payload()
    payload.pop("evidence_sha256")
    forged = replace(
        forged,
        evidence_sha256=hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest(),
    )

    assert not running_attestation_is_self_consistent(forged)


def test_attestation_rejects_attempt_slice_invocation_reuse() -> None:
    with pytest.raises(SupervisorError, match="invocation identity changed"):
        _validate(
            attempt_slice_properties=_properties(
                unit=_ATTEMPT_SLICE_UNIT,
                invocation="4" * 32,
                cgroup=_ATTEMPT_SLICE_CGROUP,
            )
        )


def test_attestation_rejects_duplicate_unified_cgroup_hierarchy() -> None:
    observations = _valid_observations()
    observations["process_snapshots"][303] = replace(
        observations["process_snapshots"][303],
        cgroup=f"0::{_SCOPE_CGROUP}\n0::{_SCOPE_CGROUP}\n".encode(),
    )

    with pytest.raises(SupervisorError, match="exactly one unified"):
        validate_running_runtime_attestation(**observations)


def test_attestation_bounds_untrusted_observations() -> None:
    with pytest.raises(SupervisorError) as oversized:
        _validate(runc_state=b"{" + b" " * (64 * 1024))
    assert oversized.value.code == "sandbox_runtime_attestation_invalid"

    with pytest.raises(SupervisorError) as malformed:
        _validate(runc_state=b"[" * 200 + b"]" * 200)
    assert malformed.value.code == "sandbox_runtime_attestation_invalid"
