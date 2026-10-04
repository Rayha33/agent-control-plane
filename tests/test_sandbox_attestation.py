from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from agent_control_plane.supervisor.common import SupervisorError, canonical_json
from agent_control_plane.supervisor.sandbox_attestation import (
    ProcessSnapshot,
    running_attestation_is_self_consistent,
    validate_running_runtime_attestation,
)

_WRAPPER_CGROUP = "/user.slice/user-1000.slice/user@1000.service/app.slice/acp-worker.service"
_SCOPE_CGROUP = "/user.slice/user-1000.slice/user@1000.service/app.slice/acp-container.scope"


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
        "expected_scope_unit": "acp-container.scope",
        "expected_scope_invocation_id": "2" * 32,
        "expected_cgroup_path": _SCOPE_CGROUP,
    }


def _validate(**overrides):
    observations = _valid_observations()
    observations.update(overrides)
    return validate_running_runtime_attestation(**observations)


def test_attestation_binds_runtime_state_pid_start_identities_and_cgroups() -> None:
    receipt = _validate()

    assert receipt.container_id == "acp-test-container"
    assert receipt.init_pid == 303
    assert receipt.init_identity == "linux:303:1303"
    assert receipt.wrapper_control_group == _WRAPPER_CGROUP
    assert receipt.cgroup_path == _SCOPE_CGROUP
    assert len(receipt.runc_state_sha256) == 64
    assert len(receipt.evidence_sha256) == 64
    assert receipt.audit_payload()["init_identity"] == "linux:303:1303"


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
