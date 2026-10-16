from __future__ import annotations

import hashlib
import json
import os
import socket
import tempfile
from pathlib import Path

import pytest

from agent_control_plane.git_supervisor import SupervisorError
from agent_control_plane.supervisor import sandbox_cleanup_verifier as verifier
from agent_control_plane.supervisor.common import canonical_json


def _proof(report_json: str) -> str:
    report_digest = hashlib.sha256(report_json.encode("utf-8")).hexdigest()
    container_id = verifier.sandbox_monitor_receipt.sandbox_container_id("attempt-1", 7, "exec-1")

    def snapshot(unit: str, invocation: str, cgroup: str, active: str = "inactive"):
        return {
            "id": unit,
            "load_state": "loaded",
            "active_state": active,
            "invocation_id": invocation,
            "control_group": cgroup,
            "main_pid": "0",
        }

    return canonical_json(
        {
            "version": 1,
            "attempt_id": "attempt-1",
            "claim_token": 7,
            "execution_id": "exec-1",
            "cleanup_report_sha256": report_digest,
            "verified_at": "2026-10-16T00:00:00Z",
            "verifier": {"pid": 42, "identity": "linux:42:99"},
            "observations": {
                "units": {
                    "monitor": snapshot("monitor.service", "a" * 32, "/user.slice/monitor.service"),
                    "launch_driver": snapshot(
                        "driver.service",
                        "b" * 32,
                        "/user.slice/user-acp.slice/test.slice/driver.service",
                    ),
                    "scope": snapshot(
                        "worker.scope",
                        "c" * 32,
                        "/user.slice/user-acp.slice/test.slice/worker.scope",
                    ),
                    "attempt_slice": snapshot(
                        "test.slice",
                        "d" * 32,
                        "/user.slice/user-acp.slice/test.slice",
                        active="active",
                    ),
                },
                "processes": {
                    "monitor_identity_absent": {
                        "pid": 21,
                        "identity": "linux:21:101",
                        "absent": True,
                    },
                    "launch_driver_identity_absent": {
                        "pid": 22,
                        "identity": "linux:22:102",
                        "absent": True,
                    },
                    "runc_client_identity_absent": {
                        "pid": 23,
                        "identity": "linux:23:103",
                        "absent": True,
                    },
                    "container_init_identity_absent": {
                        "pid": 24,
                        "identity": "linux:24:104",
                        "absent": True,
                    },
                },
                "cgroups": {
                    "/user.slice/user-acp.slice/test.slice": True,
                    "/user.slice/user-acp.slice/test.slice/worker.scope": True,
                    "/user.slice/user-acp.slice/test.slice/driver.service": True,
                    "/user.slice/monitor.service": True,
                },
                "paths": {
                    "runc_state_entry_absent": True,
                    "bundle_absent": True,
                    "state_root_absent": True,
                    "execution_root": {
                        "path": "/tmp/acp/attempt-1",
                        "device": 1,
                        "inode": 2,
                    },
                    "monitor_socket": {
                        "path": f"/run/user/1000/acpmon-{container_id.removeprefix('acp-')}.sock",
                        "parent_device": 1,
                        "parent_inode": 2,
                        "socket_device": None,
                        "socket_inode": None,
                        "removed": False,
                        "absent": True,
                    },
                },
            },
        }
    )


def _report(exit_code: int = 0) -> str:
    return canonical_json(
        {
            "version": 3,
            "verification_status": "unverified",
            "attempt_id": "attempt-1",
            "claim_token": 7,
            "execution_id": "exec-1",
            "runc_exit_code": exit_code,
            "action": {
                "returncode": 0,
                "state_entry_absent_immediately_after_delete": True,
            },
        }
    )


def _verification_row(report_json: str, exit_code: int = 0) -> dict[str, object]:
    return {
        "phase": "cleanup_verified",
        "runc_exit_code": exit_code,
        "runc_exit_evidence_source": "runc_client_kernel_waitpid",
        "cleanup_receipt_json": report_json,
        "attempt_id": "attempt-1",
        "claim_token": 7,
        "execution_id": "exec-1",
        "wrapper_unit": "monitor.service",
        "wrapper_invocation_id": "a" * 32,
        "wrapper_cgroup_path": "/user.slice/monitor.service",
        "launch_driver_unit": "driver.service",
        "launch_driver_invocation_id": "b" * 32,
        "launch_driver_cgroup_path": "/user.slice/user-acp.slice/test.slice/driver.service",
        "scope_unit": "worker.scope",
        "scope_invocation_id": "c" * 32,
        "cgroup_path": "/user.slice/user-acp.slice/test.slice/worker.scope",
        "attempt_slice_unit": "test.slice",
        "attempt_slice_invocation_id": "d" * 32,
        "attempt_slice_cgroup_path": "/user.slice/user-acp.slice/test.slice",
        "monitor_pid": 21,
        "monitor_identity": "linux:21:101",
        "launch_driver_pid": 22,
        "launch_driver_identity": "linux:22:102",
        "runc_client_pid": 23,
        "runc_client_identity": "linux:23:103",
        "init_pid": 24,
        "init_identity": "linux:24:104",
        "bundle_path": "/tmp/acp/attempt-1/bundle",
        "execution_root_dev": 1,
        "execution_root_ino": 2,
    }


@pytest.mark.parametrize("exit_code", [0, 1, 137, -15])
def test_persisted_verification_receipt_is_bound_to_exact_cleanup_report(exit_code: int) -> None:
    report_json = _report(exit_code)
    row = _verification_row(report_json, exit_code)
    proof = _proof(report_json)
    assert verifier._sandbox_cleanup_verification_json_is_self_consistent(row, proof)

    mismatched = proof.replace(hashlib.sha256(report_json.encode()).hexdigest(), "0" * 64)
    assert not verifier._sandbox_cleanup_verification_json_is_self_consistent(row, mismatched)

    forged = json.loads(proof)
    forged["observations"]["paths"]["monitor_socket"]["path"] = "/run/user/1000/acpmon-wrong.sock"
    assert not verifier._sandbox_cleanup_verification_json_is_self_consistent(
        row, canonical_json(forged)
    )


@pytest.mark.parametrize("bad_returncode", [False, 0.0])
def test_persisted_verification_rejects_noninteger_cleanup_returncode(
    bad_returncode: bool | float,
) -> None:
    report = json.loads(_report())
    report["action"]["returncode"] = bad_returncode
    report_json = canonical_json(report)
    row = _verification_row(report_json)
    proof = _proof(report_json)

    assert not verifier._sandbox_cleanup_verification_json_is_self_consistent(row, proof)


@pytest.mark.parametrize(
    "mutation",
    ["cleanup_claim_token", "verification_claim_token", "execution_root_device", "process_pid"],
)
def test_persisted_verification_rejects_integer_float_equivalence(mutation: str) -> None:
    report_json = _report()
    proof = json.loads(_proof(report_json))
    if mutation == "cleanup_claim_token":
        report = json.loads(report_json)
        report["claim_token"] = 7.0
        report_json = canonical_json(report)
        proof = json.loads(_proof(report_json))
    elif mutation == "verification_claim_token":
        proof["claim_token"] = 7.0
    elif mutation == "execution_root_device":
        proof["observations"]["paths"]["execution_root"]["device"] = 1.0
    else:
        proof["observations"]["processes"]["monitor_identity_absent"]["pid"] = 21.0
    row = _verification_row(report_json)

    assert not verifier._sandbox_cleanup_verification_json_is_self_consistent(
        row, canonical_json(proof)
    )


def test_private_tree_cleanup_is_inode_pinned_and_does_not_follow_symlinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    execution_root = tmp_path / "execution"
    bundle = execution_root / "bundle"
    state = execution_root / "state"
    outside = tmp_path / "outside.txt"
    execution_root.mkdir(mode=0o700)
    bundle.mkdir(mode=0o700)
    state.mkdir(mode=0o700)
    (bundle / "nested").mkdir()
    (bundle / "nested" / "payload").write_text("owned", encoding="utf-8")
    outside.write_text("must survive", encoding="utf-8")
    (bundle / "outside-link").symlink_to(outside)
    monkeypatch.setattr(verifier, "_assert_no_mounts_below", lambda _paths: None)

    execution_info = execution_root.lstat()
    bundle_info = bundle.lstat()
    state_info = state.lstat()
    removed = verifier._remove_bound_private_paths(
        {
            "bundle_path": str(bundle),
            "state_path": str(state),
            "execution_root_dev": execution_info.st_dev,
            "execution_root_ino": execution_info.st_ino,
            "bundle_root_dev": bundle_info.st_dev,
            "bundle_root_ino": bundle_info.st_ino,
            "state_root_dev": state_info.st_dev,
            "state_root_ino": state_info.st_ino,
        }
    )

    assert removed == {"bundle_absent": True, "state_root_absent": True}
    assert execution_root.is_dir()
    assert not bundle.exists() and not state.exists()
    assert outside.read_text(encoding="utf-8") == "must survive"


def test_private_tree_cleanup_refuses_replaced_inode(tmp_path: Path, monkeypatch) -> None:
    execution_root = tmp_path / "execution"
    bundle = execution_root / "bundle"
    state = execution_root / "state"
    execution_root.mkdir(mode=0o700)
    bundle.mkdir(mode=0o700)
    state.mkdir(mode=0o700)
    (bundle / "content").write_text("keep", encoding="utf-8")
    monkeypatch.setattr(verifier, "_assert_no_mounts_below", lambda _paths: None)
    execution_info = execution_root.lstat()
    bundle_info = bundle.lstat()
    state_info = state.lstat()
    replacement = execution_root / "bundle.displaced"
    bundle.rename(replacement)
    bundle.mkdir(mode=0o700)

    with pytest.raises(SupervisorError, match="identity changed"):
        verifier._remove_bound_private_paths(
            {
                "bundle_path": str(bundle),
                "state_path": str(state),
                "execution_root_dev": execution_info.st_dev,
                "execution_root_ino": execution_info.st_ino,
                "bundle_root_dev": bundle_info.st_dev,
                "bundle_root_ino": bundle_info.st_ino,
                "state_root_dev": state_info.st_dev,
                "state_root_ino": state_info.st_ino,
            }
        )
    assert (replacement / "content").read_text(encoding="utf-8") == "keep"


def test_mismatched_active_systemd_invocation_is_never_stopped(monkeypatch) -> None:
    stop_calls: list[list[str]] = []
    monkeypatch.setattr(
        verifier.sandbox_monitor_lifecycle,
        "_read_unit_properties",
        lambda *_args: {
            "Id": "worker.scope",
            "LoadState": "loaded",
            "ActiveState": "active",
            "InvocationID": "b" * 32,
            "ControlGroup": "/user.slice/other.scope",
            "MainPID": "0",
        },
    )
    monkeypatch.setattr(
        verifier,
        "_run_trusted_runtime_command",
        lambda argv, **_kwargs: stop_calls.append(argv) or b"",
    )

    with pytest.raises(SupervisorError, match="unit changed identity"):
        verifier._unit_snapshot(
            "worker.scope",
            invocation_id="a" * 32,
            control_group="/user.slice/worker.scope",
            main_pid=None,
            stop_if_active=True,
            systemctl=Path("/usr/bin/systemctl"),
            environment={},
        )
    assert stop_calls == []


def test_exact_active_unit_is_stopped_then_requeried(monkeypatch) -> None:
    stop_calls: list[list[str]] = []
    reads = 0

    def read_unit(*_args):
        nonlocal reads
        reads += 1
        active = reads == 1
        return {
            "Id": "monitor.service",
            "LoadState": "loaded",
            "ActiveState": "active" if active else "inactive",
            "InvocationID": "a" * 32,
            "ControlGroup": "/user.slice/monitor.service",
            "MainPID": "42" if active else "0",
        }

    monkeypatch.setattr(verifier.sandbox_monitor_lifecycle, "_read_unit_properties", read_unit)
    monkeypatch.setattr(
        verifier,
        "_run_trusted_runtime_command",
        lambda argv, **_kwargs: stop_calls.append(argv) or b"",
    )
    snapshot = verifier._unit_snapshot(
        "monitor.service",
        invocation_id="a" * 32,
        control_group="/user.slice/monitor.service",
        main_pid=42,
        stop_if_active=True,
        systemctl=Path("/usr/bin/systemctl"),
        environment={},
    )

    assert reads == 2
    assert stop_calls == [
        ["/usr/bin/systemctl", "--user", "--no-block", "stop", "--", "monitor.service"]
    ]
    assert snapshot["active_state"] == "inactive"
    assert snapshot["main_pid"] == "0"


def test_not_found_unit_allows_systemd_omitted_properties_only_after_exact_state_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads: list[tuple[str, ...]] = []

    def sparse_systemd_read(_systemctl, _environment, _unit, properties):
        requested = tuple(properties)
        reads.append(requested)
        if requested == verifier._SYSTEMD_PROPERTIES:
            raise ValueError("systemd omits MainPID for an unloaded transient unit")
        assert requested == ("LoadState",)
        return {"LoadState": "not-found"}

    monkeypatch.setattr(
        verifier.sandbox_monitor_lifecycle, "_read_unit_properties", sparse_systemd_read
    )
    snapshot = verifier._unit_snapshot(
        "worker.scope",
        invocation_id="a" * 32,
        control_group="/user.slice/worker.scope",
        main_pid=None,
        stop_if_active=True,
        systemctl=Path("/usr/bin/systemctl"),
        environment={},
    )

    assert reads == [verifier._SYSTEMD_PROPERTIES, ("LoadState",)]
    assert snapshot["load_state"] == "not-found"
    assert snapshot["main_pid"] == "0"


def test_missing_systemd_properties_for_loaded_unit_remain_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def sparse_loaded_read(_systemctl, _environment, _unit, properties):
        if tuple(properties) == ("LoadState",):
            return {"LoadState": "loaded"}
        raise ValueError("loaded unit response is incomplete")

    monkeypatch.setattr(
        verifier.sandbox_monitor_lifecycle, "_read_unit_properties", sparse_loaded_read
    )
    with pytest.raises(SupervisorError, match="unit identity is unavailable"):
        verifier._unit_snapshot(
            "worker.scope",
            invocation_id="a" * 32,
            control_group="/user.slice/worker.scope",
            main_pid=None,
            stop_if_active=True,
            systemctl=Path("/usr/bin/systemctl"),
            environment={},
        )


def test_cgroup_verifier_recurses_and_fails_on_any_populated_descendant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "cgroup"
    leaf = root / "user.slice" / "worker.scope"
    nested = leaf / "child"
    nested.mkdir(parents=True)
    leaf.joinpath("cgroup.events").write_text("populated 0\nfrozen 0\n", encoding="ascii")
    leaf.joinpath("cgroup.procs").write_text("", encoding="ascii")
    nested.joinpath("cgroup.events").write_text("populated 0\nfrozen 0\n", encoding="ascii")
    nested.joinpath("cgroup.procs").write_text("", encoding="ascii")
    mountinfo = b"36 25 0:32 / " + os.fsencode(root) + b" rw - cgroup2 cgroup rw\n"
    monkeypatch.setattr(verifier.sandbox_attestation, "_read_proc_file", lambda _path: mountinfo)

    assert verifier._cgroup_tree_is_unpopulated("/user.slice/worker.scope", cgroup_root=root)
    nested.joinpath("cgroup.events").write_text("populated 1\nfrozen 0\n", encoding="ascii")
    with pytest.raises(SupervisorError, match="still contains processes"):
        verifier._cgroup_tree_is_unpopulated("/user.slice/worker.scope", cgroup_root=root)


def test_cgroup_verifier_rejects_unmapped_mount_even_for_missing_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "cgroup"
    root.mkdir()
    mountinfo = b"36 25 0:32 /delegated " + os.fsencode(root) + b" rw - cgroup2 cgroup rw\n"
    monkeypatch.setattr(verifier.sandbox_attestation, "_read_proc_file", lambda _path: mountinfo)

    with pytest.raises(SupervisorError, match="mount root could not be verified"):
        verifier._cgroup_tree_is_unpopulated("/user.slice/missing.scope", cgroup_root=root)


def test_stale_monitor_socket_is_removed_only_at_exact_private_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    runtime_context = tempfile.TemporaryDirectory(prefix="a-", dir="/private/tmp")
    request.addfinalizer(runtime_context.cleanup)
    runtime = Path(runtime_context.name)
    row = {
        "attempt_id": "attempt-1",
        "claim_token": 7,
        "execution_id": "exec-1",
        "state_path": str(tmp_path / "state"),
    }
    environment = {"XDG_RUNTIME_DIR": str(runtime)}
    monkeypatch.setattr(
        verifier.sandbox_monitor_lifecycle,
        "_trusted_systemd_command_environment",
        lambda: environment,
    )
    _, _, socket_path = verifier.sandbox_monitor_lifecycle.sandbox_monitor_control_paths(
        state_path=row["state_path"],
        expected_identity=(row["attempt_id"], row["claim_token"], row["execution_id"]),
    )
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.close()

    evidence = verifier._remove_monitor_socket(row)

    assert evidence["removed"] is True
    assert evidence["absent"] is True
    assert evidence["socket_inode"] is not None
    assert not socket_path.exists()


def test_monitor_socket_cleanup_refuses_non_socket_target(
    tmp_path: Path, monkeypatch, request: pytest.FixtureRequest
) -> None:
    runtime_context = tempfile.TemporaryDirectory(prefix="a-", dir="/private/tmp")
    request.addfinalizer(runtime_context.cleanup)
    runtime = Path(runtime_context.name)
    row = {
        "attempt_id": "attempt-1",
        "claim_token": 7,
        "execution_id": "exec-1",
        "state_path": str(tmp_path / "state"),
    }
    monkeypatch.setattr(
        verifier.sandbox_monitor_lifecycle,
        "_trusted_systemd_command_environment",
        lambda: {"XDG_RUNTIME_DIR": str(runtime)},
    )
    _, _, socket_path = verifier.sandbox_monitor_lifecycle.sandbox_monitor_control_paths(
        state_path=row["state_path"],
        expected_identity=(row["attempt_id"], row["claim_token"], row["execution_id"]),
    )
    socket_path.write_text("keep", encoding="ascii")

    with pytest.raises(SupervisorError, match="socket identity is unsafe"):
        verifier._remove_monitor_socket(row)
    assert socket_path.read_text(encoding="ascii") == "keep"
