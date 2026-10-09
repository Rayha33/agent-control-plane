from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace

import pytest

from agent_control_plane.supervisor import sandbox_attestation
from agent_control_plane.supervisor.common import SupervisorError, canonical_json
from agent_control_plane.supervisor.oci_worker import _oci_worker_systemd_slice
from agent_control_plane.supervisor.sandbox_attestation import (
    ProcessSnapshot,
    collect_running_runtime_attestation,
    read_private_runc_pid_file,
    running_attestation_is_self_consistent,
    validate_running_runtime_attestation,
)

_ATTEMPT_SLICE_UNIT = _oci_worker_systemd_slice("acp-test-container")
_ATTEMPT_SLICE_CGROUP = (
    f"/user.slice/user-1000.slice/user@1000.service/app.slice/{_ATTEMPT_SLICE_UNIT}"
)
_WRAPPER_CGROUP = f"{_ATTEMPT_SLICE_CGROUP}/acp-worker.service"
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
    assert receipt.init_pid == 303
    assert receipt.init_identity == "linux:303:1303"
    assert receipt.wrapper_control_group == _WRAPPER_CGROUP
    assert receipt.attempt_slice_unit == _ATTEMPT_SLICE_UNIT
    assert receipt.attempt_slice_invocation_id == "3" * 32
    assert receipt.attempt_slice_control_group == _ATTEMPT_SLICE_CGROUP
    assert receipt.cgroup_path == _SCOPE_CGROUP
    assert len(receipt.runc_state_sha256) == 64
    assert len(receipt.evidence_sha256) == 64
    assert receipt.audit_payload()["init_identity"] == "linux:303:1303"


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


def test_collector_reads_pid_and_proc_observations_itself(tmp_path, monkeypatch) -> None:
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
    receipt = collect_running_runtime_attestation(
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
    )

    assert receipt.init_pid == 303
    assert receipt.init_identity == "linux:303:1303"


def test_unkeyed_digest_checks_consistency_but_not_receipt_provenance() -> None:
    forged = replace(_validate(), init_pid=404, init_identity="linux:404:9999")
    payload = forged.audit_payload()
    payload.pop("evidence_sha256")
    recomputed = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    forged = replace(forged, evidence_sha256=recomputed)

    assert running_attestation_is_self_consistent(forged)


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
