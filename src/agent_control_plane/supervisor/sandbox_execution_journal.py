"""Durable, fail-closed identity journal for a future OCI worker executor.

Launch and exit records are bound to the pinned-runc process handle and its
wait receipt. The public OCI-init gate can be released only after the exact
registered handle is durably recorded as running, but this module does not
orchestrate a worker lifecycle, authenticate observation provenance, or
establish a sandbox. A cleanup report is not accepted as cleanup verification.
The existing reaper and runtime teardown stay fenced until a separate trusted
verifier advances the journal to ``cleanup_verified``.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import stat
import time
import uuid
from contextlib import nullcontext
from pathlib import Path, PurePosixPath
from typing import Any

from .common import CLEANUP_FENCE_EPOCH, SupervisorError, canonical_json, utc_now
from .oci_worker import (
    RuncLaunchHandle,
    _authorize_runc_launch_gate_release_locked,
    _revoke_runc_launch_gate_release_locked,
    _runc_client_wait_receipt_is_self_consistent,
    _runc_launch_gate_lock_for_execution,
    _runc_launch_handle_bind_execution,
    _runc_launch_handle_is_bound_to_execution,
    _runc_launch_handle_is_self_consistent,
    _runc_launch_pid,
    _runc_launch_process_identity,
    _runc_launch_target,
    _RuncClientWaitReceipt,
)
from .sandbox_attestation import (
    RunningRuntimeAttestation,
    running_attestation_is_self_consistent,
)
from .sandbox_workspace import (
    _MAX_DURABLE_MANIFEST_BYTES,
    _restore_snapshot_from_record,
    _verify_directory_identity,
)
from .sandbox_workspace import Snapshot as _Snapshot
from .sandbox_workspace import _snapshot_origin as _snapshot_origin
from .sandbox_workspace import collect_changes as _collect_changes
from .store import (
    _authorize_sandbox_exit_receipt_write,
    _authorize_sandbox_launch_plan_write,
    _authorize_sandbox_reservation_write,
)

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_OCI_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SYSTEMD_UNIT = re.compile(r"[A-Za-z0-9_.:@\\-]+\.(?:service|scope)\Z")
_INVOCATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_LEGACY_BUNDLE_DIGEST_SEMANTICS = "legacy-caller-asserted-v0"
_BUNDLE_DIGEST_SEMANTICS = "oci-reservation-v1"
_PHASES = frozenset(
    {
        "reserved",
        "launched",
        "running",
        "stopping",
        "exited",
        "cleanup_reported",
        "cleanup_verified",
        "ambiguous",
    }
)
_TRANSITION_FIELDS = {
    ("reserved", "launched"): frozenset(
        {
            "monitor_pid",
            "monitor_identity",
            "runc_client_pid",
            "runc_client_identity",
            "wrapper_unit",
            "wrapper_invocation_id",
            "scope_unit",
            "scope_invocation_id",
            "cgroup_path",
            "launch_plan_binding_version",
            "launch_plan_json",
            "launch_config_digest",
            "launch_argv_digest",
            "launch_plan_digest",
        }
    ),
    ("launched", "running"): frozenset({"init_pid", "init_identity"}),
    ("running", "stopping"): frozenset({"stop_reason"}),
    ("exited", "cleanup_reported"): frozenset({"cleanup_receipt_json"}),
}


def _sandbox_launch_plan_material(execution: Any, target: Any) -> dict[str, Any]:
    """Canonical, durable projection of a registered runc handle and reservation."""

    argv = list(target.argv)
    argv_digest = hashlib.sha256(canonical_json(argv).encode("utf-8")).hexdigest()
    return {
        "version": 2,
        "reservation": {
            "bundle_digest_semantics": _BUNDLE_DIGEST_SEMANTICS,
            **{
                key: execution[key]
                for key in (
                    "attempt_id",
                    "claim_token",
                    "execution_id",
                    "backend",
                    "container_id",
                    "bundle_digest",
                    "rootfs_digest",
                    "rootfs_closure_digest",
                    "runc_executable_digest",
                    "runtime_version",
                    "oci_version",
                    "bundle_path",
                    "state_path",
                    "workspace_binding_version",
                    "baseline_manifest_digest",
                    "workspace_root_path",
                    "workspace_root_dev",
                    "workspace_root_ino",
                    "private_path_binding_version",
                    "execution_root_dev",
                    "execution_root_ino",
                    "bundle_root_dev",
                    "bundle_root_ino",
                    "state_root_dev",
                    "state_root_ino",
                )
            },
        },
        "launch": {
            "mode": target.launch_mode,
            "runc_executable_path": target.runc_executable_path,
            "runc_executable_sha256": target.runc_executable_sha256,
            "config_sha256": target.config_sha256,
            "argv": argv,
            "argv_sha256": argv_digest,
            "container_id": target.container_id,
            "bundle": {
                "path": target.bundle_path,
                "device": target.bundle_device,
                "inode": target.bundle_inode,
            },
            "rootfs": {
                "path": target.rootfs_path,
                "device": target.rootfs_device,
                "inode": target.rootfs_inode,
                "sha256": target.rootfs_sha256,
                "closure_sha256": target.rootfs_closure_sha256,
                "snapshot": {
                    "device": target.rootfs_snapshot_device,
                    "inode": target.rootfs_snapshot_inode,
                    "sha256": target.rootfs_snapshot_sha256,
                    "closure_sha256": target.rootfs_snapshot_closure_sha256,
                    "entry_count": target.rootfs_snapshot_entry_count,
                    "bytes": target.rootfs_snapshot_bytes,
                },
            },
            "state": {
                "path": target.state_path,
                "device": target.state_device,
                "inode": target.state_inode,
            },
            "workspace": {
                "path": target.workspace_path,
                "device": target.workspace_device,
                "inode": target.workspace_inode,
            },
            "pid_file_path": target.pid_file_path,
        },
    }


def _sandbox_reservation_bundle_digest(execution: Any) -> str:
    """Hash host-derived reservation identity, not caller-asserted bundle bytes.

    The launch config does not exist when the reservation is inserted. This
    versioned digest therefore commits only the immutable execution identity and
    configured runtime pins. The exact OCI config and argv are bound separately
    by the later launch-plan receipt; this value is never treated as their hash.
    """

    material = {
        "version": 1,
        "kind": _BUNDLE_DIGEST_SEMANTICS,
        **{
            key: execution[key]
            for key in (
                "attempt_id",
                "claim_token",
                "execution_id",
                "backend",
                "container_id",
                "rootfs_digest",
                "rootfs_closure_digest",
                "runc_executable_digest",
                "runtime_version",
                "oci_version",
                "bundle_path",
                "state_path",
            )
        },
    }
    return hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()


def _sandbox_launch_plan_binding_is_self_consistent(row: Any) -> bool:
    """Verify the durable plan digest and every reservation identity it commits."""

    try:
        if (
            row["launch_plan_required"] != 1
            or row["launch_plan_binding_version"] != 1
            or _DIGEST.fullmatch(row["launch_config_digest"] or "") is None
            or _DIGEST.fullmatch(row["launch_argv_digest"] or "") is None
            or _DIGEST.fullmatch(row["launch_plan_digest"] or "") is None
        ):
            return False
        raw_plan = row["launch_plan_json"]
        plan = json.loads(raw_plan)
        if not isinstance(plan, dict) or canonical_json(plan) != raw_plan:
            return False
        if hashlib.sha256(raw_plan.encode("utf-8")).hexdigest() != row["launch_plan_digest"]:
            return False
        plan_version = plan.get("version")
        if type(plan_version) is not int or plan_version not in {1, 2}:
            return False
        reservation = plan.get("reservation")
        expected_reservation = {
            key: row[key]
            for key in (
                "attempt_id",
                "claim_token",
                "execution_id",
                "backend",
                "container_id",
                "bundle_digest",
                "rootfs_digest",
                "rootfs_closure_digest",
                "runc_executable_digest",
                "runtime_version",
                "oci_version",
                "bundle_path",
                "state_path",
                "workspace_binding_version",
                "baseline_manifest_digest",
                "workspace_root_path",
                "workspace_root_dev",
                "workspace_root_ino",
                "private_path_binding_version",
                "execution_root_dev",
                "execution_root_ino",
                "bundle_root_dev",
                "bundle_root_ino",
                "state_root_dev",
                "state_root_ino",
            )
        }
        if plan_version == 2:
            if row["bundle_digest_semantics"] != _BUNDLE_DIGEST_SEMANTICS:
                return False
            if row["bundle_digest"] != _sandbox_reservation_bundle_digest(row):
                return False
            expected_reservation["bundle_digest_semantics"] = _BUNDLE_DIGEST_SEMANTICS
        elif row["bundle_digest_semantics"] != _LEGACY_BUNDLE_DIGEST_SEMANTICS:
            return False
        launch = plan.get("launch")
        if reservation != expected_reservation or not isinstance(launch, dict):
            return False
        argv = launch.get("argv")
        bundle = launch.get("bundle")
        rootfs = launch.get("rootfs")
        state = launch.get("state")
        workspace = launch.get("workspace")
        if not all(isinstance(value, dict) for value in (bundle, rootfs, state, workspace)):
            return False
        pid_file_path = launch.get("pid_file_path")
        snapshot = rootfs.get("snapshot")
        if not isinstance(pid_file_path, str) or not isinstance(snapshot, dict):
            return False
        argv_shape_matches = (
            isinstance(argv, list)
            and len(argv) == 13
            and all(isinstance(value, str) and value for value in argv)
            and argv[0] == launch.get("runc_executable_path")
            and argv[1] == "--root"
            and re.fullmatch(r"/proc/self/fd/[1-9][0-9]*", argv[2]) is not None
            and argv[3:6] == ["--systemd-cgroup", "run", "--bundle"]
            and re.fullmatch(r"/proc/self/fd/[1-9][0-9]*", argv[6]) is not None
            and argv[7] == "--pid-file"
            and argv[8] == f"{argv[2]}/{Path(pid_file_path).name}"
            and argv[9:12] == ["--preserve-fds", "1", "--keep"]
            and argv[12] == row["container_id"]
            and argv[2] != argv[6]
        )
        return (
            launch.get("mode") == "private_bundle"
            and launch.get("runc_executable_sha256") == row["runc_executable_digest"]
            and launch.get("container_id") == row["container_id"]
            and launch.get("config_sha256") == row["launch_config_digest"]
            and launch.get("argv_sha256") == row["launch_argv_digest"]
            and argv_shape_matches
            and hashlib.sha256(canonical_json(argv).encode("utf-8")).hexdigest()
            == row["launch_argv_digest"]
            and bundle
            == {
                "path": row["bundle_path"],
                "device": row["bundle_root_dev"],
                "inode": row["bundle_root_ino"],
            }
            and rootfs.get("path") == str(Path(row["bundle_path"]) / "rootfs")
            and rootfs.get("sha256") == row["rootfs_digest"]
            and rootfs.get("closure_sha256") == row["rootfs_closure_digest"]
            and snapshot.get("sha256") == row["rootfs_digest"]
            and snapshot.get("closure_sha256") == row["rootfs_closure_digest"]
            and state
            == {
                "path": row["state_path"],
                "device": row["state_root_dev"],
                "inode": row["state_root_ino"],
            }
            and workspace
            == {
                "path": row["workspace_root_path"],
                "device": row["workspace_root_dev"],
                "inode": row["workspace_root_ino"],
            }
            and Path(pid_file_path).parent == Path(row["state_path"])
        )
    except (IndexError, KeyError, TypeError, ValueError, UnicodeError):
        return False


_CLEANUP_OBSERVATIONS = {
    "runc_delete_exit_code": None,
    "runc_state_absent": None,
    "bundle_absent": None,
    "state_directory_absent": None,
    "wrapper_unit_absent": None,
    "scope_unit_absent": None,
    "cgroup_absent": None,
    "monitor_identity_absent": None,
    "runc_client_identity_absent": None,
    "container_init_identity_absent": None,
}
_LEGACY_CLEANUP_OBSERVATIONS = {
    "runc_delete_exit_code": 0,
    "runc_state_absent": True,
    "bundle_absent": True,
    "state_directory_absent": True,
    "wrapper_unit_absent": True,
    "scope_unit_absent": True,
    "cgroup_absent": True,
    "monitor_identity_absent": True,
    "runc_client_identity_absent": True,
    "container_init_identity_absent": True,
}


def _private_directory_identity(path: Path, label: str) -> tuple[int, int]:
    """Capture one private directory inode without accepting a symlink root."""

    try:
        observed = path.lstat()
    except OSError as error:
        raise SupervisorError(
            "sandbox_private_path_invalid", f"{label} is unavailable for identity binding"
        ) from error
    if not stat.S_ISDIR(observed.st_mode):
        raise SupervisorError("sandbox_private_path_invalid", f"{label} must be a real directory")
    _verify_directory_identity(
        path,
        expected_device=observed.st_dev,
        expected_inode=observed.st_ino,
    )
    return observed.st_dev, observed.st_ino


def _require_private_path_absent(path: Path, label: str) -> None:
    """Treat only a positively missing private path as cleanup evidence."""

    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise SupervisorError(
            "sandbox_private_path_invalid", f"{label} absence could not be verified"
        ) from error
    raise SupervisorError(
        "sandbox_private_path_conflict", f"{label} remains after cleanup verification"
    )


def _sandbox_execution_cleanup_is_verified(connection: Any, attempt_id: str) -> bool:
    """Old/direct attempts have no journal; journaled attempts require verification."""

    row = connection.execute(
        "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
    ).fetchone()
    return row is None or (
        row["phase"] == "cleanup_verified" and _sandbox_launch_plan_binding_is_self_consistent(row)
    )


def _require_sandbox_execution_result_eligible(connection: Any, attempt_id: str) -> None:
    """Fence result import/submission until a journaled worker exited cleanly."""

    row = connection.execute(
        "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
    ).fetchone()
    if row is not None and not (
        row["phase"] == "cleanup_verified"
        and row["runc_exit_code"] == 0
        and _sandbox_launch_plan_binding_is_self_consistent(row)
    ):
        raise SupervisorError(
            "sandbox_result_unverified",
            "sandbox result requires successful runc exit and independently verified cleanup",
        )


def _require_direct_worker_result_source(connection: Any, attempt_id: str) -> None:
    """Keep a journaled sandbox out of the direct-worker PID/receipt protocol.

    This remains a separate fence even after cleanup verification exists: a
    sandbox execution is identified by its execution journal, not by aliasing
    its monitor, runc client, or container-init PID into ``attempts.pid``.
    """

    row = connection.execute(
        "SELECT 1 FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
    ).fetchone()
    if row is not None:
        raise SupervisorError(
            "sandbox_result_import_route_required",
            "journaled sandbox results cannot use the direct-worker PID receipt route",
        )


class SandboxExecutionJournalMixin:
    """Private persistence API; no worker-launch or user-facing route is wired yet."""

    @staticmethod
    def _sandbox_text(value: Any, field: str, *, limit: int = 256) -> str:
        if not isinstance(value, str):
            raise SupervisorError("sandbox_execution_invalid", f"{field} must be text")
        normalized = value.strip()
        try:
            encoded = normalized.encode("utf-8")
        except UnicodeEncodeError:
            raise SupervisorError(
                "sandbox_execution_invalid", f"{field} is not valid UTF-8"
            ) from None
        if (
            not normalized
            or len(encoded) > limit
            or any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in normalized)
        ):
            raise SupervisorError("sandbox_execution_invalid", f"{field} is invalid")
        return normalized

    @staticmethod
    def _sandbox_pid(value: Any, field: str) -> int:
        if type(value) is not int or not 1 <= value <= 2**31 - 1:
            raise SupervisorError("sandbox_execution_invalid", f"{field} is not a valid PID")
        return value

    @classmethod
    def _sandbox_process_identity(cls, value: Any, field: str) -> str:
        return cls._sandbox_text(value, field, limit=256)

    @classmethod
    def _sandbox_systemd_unit(cls, value: Any, field: str, suffix: str) -> str:
        value = cls._sandbox_text(value, field, limit=255)
        if _SYSTEMD_UNIT.fullmatch(value) is None or not value.endswith(suffix):
            raise SupervisorError("sandbox_execution_invalid", f"{field} is not a systemd unit")
        return value

    @classmethod
    def _sandbox_invocation_id(cls, value: Any, field: str) -> str:
        value = cls._sandbox_text(value, field, limit=32)
        if _INVOCATION_ID.fullmatch(value) is None:
            raise SupervisorError("sandbox_execution_invalid", f"{field} is invalid")
        return value

    @staticmethod
    def _sandbox_validate_attempt_id(attempt_id: Any) -> str:
        if not isinstance(attempt_id, str) or _COMPONENT.fullmatch(attempt_id) is None:
            raise SupervisorError("sandbox_execution_invalid", "attempt_id is not a safe component")
        return attempt_id

    def _sandbox_execution_reserve(
        self,
        attempt_id: str,
        claim_token: int,
        *,
        rootfs_digest: str,
        rootfs_closure_digest: str,
        runc_executable_digest: str,
        runtime_version: str,
        oci_version: str,
        credential: str | None = None,
    ) -> dict[str, Any]:
        """Reserve one journal row before launch; paths and container ID are host-derived."""

        attempt_id = self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        if not isinstance(rootfs_digest, str) or _DIGEST.fullmatch(rootfs_digest) is None:
            raise SupervisorError("sandbox_execution_invalid", "rootfs digest must be SHA-256")
        if (
            not isinstance(rootfs_closure_digest, str)
            or _DIGEST.fullmatch(rootfs_closure_digest) is None
        ):
            raise SupervisorError(
                "sandbox_execution_invalid", "rootfs closure digest must be SHA-256"
            )
        if (
            not isinstance(runc_executable_digest, str)
            or _DIGEST.fullmatch(runc_executable_digest) is None
        ):
            raise SupervisorError(
                "sandbox_execution_invalid", "trusted runc executable digest must be SHA-256"
            )
        runtime_version = self._sandbox_text(runtime_version, "runtime_version", limit=128)
        oci_version = self._sandbox_text(oci_version, "oci_version", limit=32)
        if _OCI_VERSION.fullmatch(oci_version) is None:
            raise SupervisorError("sandbox_execution_invalid", "OCI version must be numeric semver")

        config = self.config
        rootfs_pin = config.oci_rootfs_pin
        runc_pin = config.oci_runc_executable
        configured_runtime_version = config.oci_runc_version
        if (
            rootfs_pin is None
            or runc_pin is None
            or not isinstance(configured_runtime_version, str)
            or not configured_runtime_version
        ):
            raise SupervisorError(
                "sandbox_execution_pin_unavailable",
                "sandbox reservation requires configured rootfs and runc pins",
            )

        # Hash-shaped caller claims are not evidence. Revalidate the process-local
        # sealed handles, then require every persisted runtime identity to match
        # those exact configured values before the reservation can be journaled.
        from . import oci_worker

        try:
            oci_worker._verify_trusted_rootfs(rootfs_pin)
            oci_worker._verify_trusted_runc_executable(runc_pin)
        except SupervisorError as error:
            raise SupervisorError(
                "sandbox_execution_pin_invalid",
                "configured rootfs or runc pin could not be verified",
            ) from error
        if (
            rootfs_digest != rootfs_pin.sha256
            or rootfs_closure_digest != rootfs_pin.closure_sha256
            or runc_executable_digest != runc_pin.sha256
            or runtime_version != configured_runtime_version
        ):
            raise SupervisorError(
                "sandbox_execution_pin_mismatch",
                "reservation runtime identity does not match configured OCI pins",
            )

        execution_id = str(uuid.uuid4())
        container_id = f"acp-{attempt_id[:24]}-{claim_token}-{execution_id[:8]}"
        execution_root = (
            self.state_dir.resolve() / "sandbox-executions" / f"{attempt_id}-{claim_token}"
        )
        bundle_path = str(execution_root / "bundle")
        state_path = str(execution_root / "state")
        bundle_digest = _sandbox_reservation_bundle_digest(
            {
                "attempt_id": attempt_id,
                "claim_token": claim_token,
                "execution_id": execution_id,
                "backend": "oci-runc",
                "container_id": container_id,
                "rootfs_digest": rootfs_digest,
                "rootfs_closure_digest": rootfs_closure_digest,
                "runc_executable_digest": runc_executable_digest,
                "runtime_version": runtime_version,
                "oci_version": oci_version,
                "bundle_path": bundle_path,
                "state_path": state_path,
            }
        )
        stamp = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            if attempt["status"] != "working":
                raise SupervisorError(
                    "claim_inactive", "sandbox execution requires a fully provisioned attempt"
                )
            self._authenticate_attempt(connection, attempt, credential)
            if attempt["pid"] is not None or attempt["launch_owner_pid"] is not None:
                raise SupervisorError(
                    "worker_already_running",
                    "sandbox execution cannot be reserved beside a registered direct worker",
                )
            try:
                with _authorize_sandbox_reservation_write(
                    connection,
                    attempt_id,
                    claim_token,
                    execution_id,
                    bundle_digest,
                    _BUNDLE_DIGEST_SEMANTICS,
                ):
                    connection.execute(
                        """
                        INSERT INTO sandbox_executions
                          (attempt_id, claim_token, execution_id, backend, container_id,
                           bundle_digest, bundle_digest_semantics, launch_plan_required,
                           rootfs_digest, rootfs_closure_digest, runc_executable_digest,
                           runtime_version, oci_version,
                           bundle_path, state_path, phase, created_at, updated_at)
                        VALUES (?, ?, ?, 'oci-runc', ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?)
                        """,
                        (
                            attempt_id,
                            claim_token,
                            execution_id,
                            container_id,
                            bundle_digest,
                            _BUNDLE_DIGEST_SEMANTICS,
                            rootfs_digest,
                            rootfs_closure_digest,
                            runc_executable_digest,
                            runtime_version,
                            oci_version,
                            bundle_path,
                            state_path,
                            stamp,
                            stamp,
                        ),
                    )
            except sqlite3.IntegrityError as error:
                if "UNIQUE constraint failed" in str(error):
                    raise SupervisorError(
                        "sandbox_execution_exists",
                        "this attempt already has a reserved or historical sandbox execution",
                    ) from None
                raise
            self._event(
                connection,
                "sandbox.execution_reserved",
                attempt["agent_id"],
                {
                    "attempt_id": attempt_id,
                    "claim_token": claim_token,
                    "execution_id": execution_id,
                    "backend": "oci-runc",
                    "container_id": container_id,
                    "bundle_digest": bundle_digest,
                    "bundle_digest_semantics": _BUNDLE_DIGEST_SEMANTICS,
                    "rootfs_digest": rootfs_digest,
                    "rootfs_closure_digest": rootfs_closure_digest,
                    "runc_executable_digest": runc_executable_digest,
                    "runtime_version": runtime_version,
                    "oci_version": oci_version,
                },
            )
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        return self._sandbox_execution_view(row)

    def _sandbox_execution_bind_workspace(
        self,
        attempt_id: str,
        claim_token: int,
        baseline: _Snapshot,
        workspace: _Snapshot,
        *,
        credential: str | None = None,
    ) -> dict[str, Any]:
        """Durably bind the immutable baseline and mutable workspace before launch.

        Both roots must be host-copier-minted, disjoint siblings of the reserved
        execution directory and initially reproduce the same manifest. This
        records their inode identities and the canonical baseline manifest so a
        later process can re-establish the binding without the copier's
        process-local weak-reference registry. It does not launch a worker or
        authorize result import.
        """

        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        if type(baseline) is not _Snapshot or type(workspace) is not _Snapshot:
            raise SupervisorError(
                "sandbox_workspace_invalid", "workspace binding needs host-created snapshots"
            )
        if baseline.manifest != workspace.manifest:
            raise SupervisorError(
                "sandbox_workspace_invalid", "baseline and mutable workspace differ before launch"
            )
        baseline_root, baseline_device, baseline_inode = _snapshot_origin(baseline)
        workspace_root, workspace_device, workspace_inode = _snapshot_origin(workspace)
        if (
            baseline_root == workspace_root
            or baseline_root in workspace_root.parents
            or workspace_root in baseline_root.parents
        ):
            raise SupervisorError(
                "sandbox_workspace_invalid", "baseline and mutable workspace must be disjoint"
            )
        baseline.manifest.validate()

        # Authenticate and pin the expected per-execution paths before walking
        # any caller-supplied snapshot tree. Recheck transactionally below
        # before writing the immutable binding.
        with self.connect() as connection:
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            self._authenticate_attempt(connection, attempt, credential)
            reserved = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        if reserved is None or reserved["claim_token"] != claim_token:
            raise SupervisorError("sandbox_execution_not_found", "execution reservation is missing")
        execution_root = Path(reserved["bundle_path"]).parent
        bundle_root = Path(reserved["bundle_path"])
        state_root = Path(reserved["state_path"])
        if (
            baseline_root != execution_root / "baseline"
            or workspace_root != execution_root / "workspace"
            or bundle_root != execution_root / "bundle"
            or state_root != execution_root / "state"
        ):
            raise SupervisorError(
                "sandbox_workspace_invalid",
                "workspace, bundle, and state roots must be reserved execution children",
            )
        execution_root_identity = _private_directory_identity(execution_root, "execution root")
        bundle_root_identity = _private_directory_identity(bundle_root, "bundle root")
        state_root_identity = _private_directory_identity(state_root, "runc state root")
        _verify_directory_identity(
            baseline_root,
            expected_device=baseline_device,
            expected_inode=baseline_inode,
        )
        _verify_directory_identity(
            workspace_root,
            expected_device=workspace_device,
            expected_inode=workspace_inode,
        )
        manifest_json = canonical_json(baseline.manifest.as_json())
        if len(manifest_json.encode("utf-8")) > _MAX_DURABLE_MANIFEST_BYTES:
            raise SupervisorError(
                "workspace_limit_exceeded", "durable baseline manifest exceeds its storage limit"
            )
        baseline_check = _collect_changes(baseline.manifest, baseline_root, write_set_rules=[])
        workspace_check = _collect_changes(workspace.manifest, workspace_root, write_set_rules=[])
        if (
            baseline_check.changes
            or workspace_check.changes
            or baseline_check.result_digest != baseline.manifest.digest
            or workspace_check.result_digest != baseline.manifest.digest
        ):
            raise SupervisorError(
                "sandbox_workspace_invalid", "workspace changed while its baseline was bound"
            )
        _verify_directory_identity(
            baseline_root,
            expected_device=baseline_device,
            expected_inode=baseline_inode,
        )
        _verify_directory_identity(
            workspace_root,
            expected_device=workspace_device,
            expected_inode=workspace_inode,
        )

        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            if attempt["status"] != "working":
                raise SupervisorError("claim_inactive", "sandbox attempt is no longer working")
            self._authenticate_attempt(connection, attempt, credential)
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if row is None or row["claim_token"] != claim_token:
                raise SupervisorError(
                    "sandbox_execution_not_found", "execution reservation is missing"
                )
            execution_root = Path(row["bundle_path"]).parent
            expected_baseline = execution_root / "baseline"
            expected_workspace = execution_root / "workspace"
            if (
                baseline_root != expected_baseline
                or workspace_root != expected_workspace
                or bundle_root != execution_root / "bundle"
                or state_root != execution_root / "state"
            ):
                raise SupervisorError(
                    "sandbox_workspace_invalid",
                    "workspace, bundle, and state roots must be reserved execution children",
                )
            current_path_identities = (
                _private_directory_identity(execution_root, "execution root"),
                _private_directory_identity(bundle_root, "bundle root"),
                _private_directory_identity(state_root, "runc state root"),
            )
            if current_path_identities != (
                execution_root_identity,
                bundle_root_identity,
                state_root_identity,
            ):
                raise SupervisorError(
                    "sandbox_private_path_conflict",
                    "private execution directories changed while workspace binding was recorded",
                )
            values = (
                str(baseline_root),
                baseline_device,
                baseline_inode,
                str(workspace_root),
                workspace_device,
                workspace_inode,
                manifest_json,
                baseline.manifest.digest,
                1,
                *execution_root_identity,
                *bundle_root_identity,
                *state_root_identity,
            )
            if row["workspace_binding_version"] == 1:
                recorded = (
                    row["baseline_root_path"],
                    row["baseline_root_dev"],
                    row["baseline_root_ino"],
                    row["workspace_root_path"],
                    row["workspace_root_dev"],
                    row["workspace_root_ino"],
                    row["baseline_manifest_json"],
                    row["baseline_manifest_digest"],
                    row["private_path_binding_version"],
                    row["execution_root_dev"],
                    row["execution_root_ino"],
                    row["bundle_root_dev"],
                    row["bundle_root_ino"],
                    row["state_root_dev"],
                    row["state_root_ino"],
                )
                if recorded != values:
                    raise SupervisorError(
                        "sandbox_workspace_conflict", "workspace binding conflicts with its journal"
                    )
                return self._sandbox_execution_view(row)
            if row["phase"] != "reserved":
                raise SupervisorError(
                    "sandbox_execution_transition_invalid",
                    "workspace binding must be recorded before runtime launch",
                )
            changed = connection.execute(
                """
                UPDATE sandbox_executions SET
                  workspace_binding_version = 1,
                  baseline_root_path = ?, baseline_root_dev = ?, baseline_root_ino = ?,
                  workspace_root_path = ?, workspace_root_dev = ?, workspace_root_ino = ?,
                  baseline_manifest_json = ?, baseline_manifest_digest = ?,
                  private_path_binding_version = ?,
                  execution_root_dev = ?, execution_root_ino = ?,
                  bundle_root_dev = ?, bundle_root_ino = ?,
                  state_root_dev = ?, state_root_ino = ?, updated_at = ?
                WHERE attempt_id = ? AND claim_token = ? AND phase = 'reserved'
                  AND workspace_binding_version = 0
                """,
                (*values, utc_now(), attempt_id, claim_token),
            ).rowcount
            if changed != 1:
                raise SupervisorError(
                    "sandbox_workspace_conflict", "workspace binding changed concurrently"
                )
            self._event(
                connection,
                "sandbox.workspace_bound",
                attempt["agent_id"],
                {
                    "attempt_id": attempt_id,
                    "claim_token": claim_token,
                    "execution_id": row["execution_id"],
                    "workspace_binding_version": 1,
                    "baseline_manifest_digest": baseline.manifest.digest,
                    "baseline_root_dev": baseline_device,
                    "baseline_root_ino": baseline_inode,
                    "workspace_root_dev": workspace_device,
                    "workspace_root_ino": workspace_inode,
                    "private_path_binding_version": 1,
                    "execution_root_dev": execution_root_identity[0],
                    "execution_root_ino": execution_root_identity[1],
                    "bundle_root_dev": bundle_root_identity[0],
                    "bundle_root_ino": bundle_root_identity[1],
                    "state_root_dev": state_root_identity[0],
                    "state_root_ino": state_root_identity[1],
                    "entry_count": len(baseline.manifest.entries),
                    "total_bytes": baseline.manifest.total_bytes,
                },
            )
            updated = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        return self._sandbox_execution_view(updated)

    def _sandbox_execution_restore_workspace_binding(
        self,
        attempt_id: str,
        claim_token: int,
        *,
        credential: str | None = None,
    ) -> dict[str, Any]:
        """Restore the baseline and re-check both roots after a supervisor restart."""

        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        with self.connect() as connection:
            connection.execute("BEGIN")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            self._authenticate_attempt(connection, attempt, credential)
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        if row is None or row["claim_token"] != claim_token:
            raise SupervisorError("sandbox_execution_not_found", "execution reservation is missing")
        if row["workspace_binding_version"] != 1 or row["private_path_binding_version"] != 1:
            raise SupervisorError(
                "sandbox_workspace_unbound",
                "execution lacks a complete durable workspace/private-path binding",
            )
        if row["phase"] == "ambiguous":
            raise SupervisorError(
                "sandbox_execution_ambiguous", "ambiguous sandbox cannot restore a result workspace"
            )
        execution_root = Path(row["bundle_path"]).parent
        baseline_path = execution_root / "baseline"
        workspace_path = execution_root / "workspace"
        if (
            Path(row["baseline_root_path"]) != baseline_path
            or Path(row["workspace_root_path"]) != workspace_path
            or Path(row["bundle_path"]) != execution_root / "bundle"
            or Path(row["state_path"]) != execution_root / "state"
        ):
            raise SupervisorError(
                "sandbox_workspace_invalid", "journaled workspace paths do not match execution root"
            )
        execution_root_identity = _private_directory_identity(execution_root, "execution root")
        if execution_root_identity != (row["execution_root_dev"], row["execution_root_ino"]):
            raise SupervisorError(
                "sandbox_private_path_conflict",
                "execution root identity no longer matches the durable journal",
            )
        if row["phase"] == "cleanup_verified":
            _require_private_path_absent(Path(row["bundle_path"]), "bundle root")
            _require_private_path_absent(Path(row["state_path"]), "runc state root")
        else:
            bundle_root_identity = _private_directory_identity(
                Path(row["bundle_path"]), "bundle root"
            )
            state_root_identity = _private_directory_identity(
                Path(row["state_path"]), "runc state root"
            )
            if bundle_root_identity != (
                row["bundle_root_dev"],
                row["bundle_root_ino"],
            ) or state_root_identity != (row["state_root_dev"], row["state_root_ino"]):
                raise SupervisorError(
                    "sandbox_private_path_conflict",
                    "private execution directory identity no longer matches the durable journal",
                )
        baseline = _restore_snapshot_from_record(
            baseline_path,
            row["baseline_manifest_json"],
            expected_device=row["baseline_root_dev"],
            expected_inode=row["baseline_root_ino"],
            expected_digest=row["baseline_manifest_digest"],
        )
        current_workspace = _verify_directory_identity(
            workspace_path,
            expected_device=row["workspace_root_dev"],
            expected_inode=row["workspace_root_ino"],
        )
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            self._authenticate_attempt(connection, attempt, credential)
            current = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            binding_columns = (
                "execution_id",
                "claim_token",
                "phase",
                "bundle_path",
                "workspace_binding_version",
                "private_path_binding_version",
                "execution_root_dev",
                "execution_root_ino",
                "bundle_root_dev",
                "bundle_root_ino",
                "state_root_dev",
                "state_root_ino",
                "baseline_root_path",
                "baseline_root_dev",
                "baseline_root_ino",
                "workspace_root_path",
                "workspace_root_dev",
                "workspace_root_ino",
                "baseline_manifest_json",
                "baseline_manifest_digest",
            )
            if current is None or any(current[name] != row[name] for name in binding_columns):
                raise SupervisorError(
                    "sandbox_workspace_conflict", "durable workspace binding changed during restore"
                )
            if current["phase"] == "ambiguous":
                raise SupervisorError(
                    "sandbox_execution_ambiguous",
                    "ambiguous sandbox cannot restore a result workspace",
                )
        return {
            "version": 1,
            "private_path_binding_version": row["private_path_binding_version"],
            "execution_id": row["execution_id"],
            "attempt_id": attempt_id,
            "claim_token": claim_token,
            "baseline": baseline,
            "workspace_root": current_workspace,
            "workspace_device": row["workspace_root_dev"],
            "workspace_inode": row["workspace_root_ino"],
            "execution_root": execution_root,
            "execution_root_device": row["execution_root_dev"],
            "execution_root_inode": row["execution_root_ino"],
            "bundle_root": Path(row["bundle_path"]),
            "bundle_root_device": row["bundle_root_dev"],
            "bundle_root_inode": row["bundle_root_ino"],
            "state_root": Path(row["state_path"]),
            "state_root_device": row["state_root_dev"],
            "state_root_inode": row["state_root_ino"],
        }

    def _sandbox_execution_capture_result_candidate(
        self,
        attempt_id: str,
        claim_token: int,
        credential: str | None = None,
    ) -> dict[str, Any]:
        """Host-scan and write once a non-authorizing result-candidate receipt."""

        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        binding = self._sandbox_execution_restore_workspace_binding(
            attempt_id, claim_token, credential=credential
        )
        baseline_root, baseline_device, baseline_inode = _snapshot_origin(binding["baseline"])
        with self.connect() as connection:
            connection.execute("BEGIN")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            if attempt["status"] != "working":
                raise SupervisorError(
                    "claim_inactive", "sandbox result attempt is no longer working"
                )
            self._authenticate_attempt(connection, attempt, credential)
            execution = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if (
                execution is None
                or execution["execution_id"] != binding["execution_id"]
                or execution["phase"] not in {"cleanup_reported", "cleanup_verified"}
                or execution["runc_exit_code"] != 0
                or execution["runc_exit_evidence_source"] != "runc_client_kernel_waitpid"
                or execution["baseline_root_path"] != str(baseline_root)
                or execution["baseline_root_dev"] != baseline_device
                or execution["baseline_root_ino"] != baseline_inode
                or execution["workspace_root_path"] != str(binding["workspace_root"])
                or execution["workspace_root_dev"] != binding["workspace_device"]
                or execution["workspace_root_ino"] != binding["workspace_inode"]
            ):
                raise SupervisorError(
                    "sandbox_result_evidence_unverified",
                    "candidate capture requires the exact exited, cleanup-reported workspace",
                )
            task = self._task_row(connection, attempt["task_id"])
            write_set_rules = self._write_set_rules(task, self._case_sensitive_paths(connection))

        change_set = _collect_changes(
            binding["baseline"].manifest,
            binding["workspace_root"],
            write_set_rules=write_set_rules,
        )
        change_set.validate()
        _verify_directory_identity(
            binding["workspace_root"],
            expected_device=binding["workspace_device"],
            expected_inode=binding["workspace_inode"],
        )
        workspace_path = str(binding["workspace_root"])
        workspace_device = binding["workspace_device"]
        workspace_inode = binding["workspace_inode"]

        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            if attempt["status"] != "working":
                raise SupervisorError(
                    "claim_inactive", "sandbox result attempt is no longer working"
                )
            self._authenticate_attempt(connection, attempt, credential)
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if row is None or row["claim_token"] != claim_token:
                raise SupervisorError(
                    "sandbox_execution_not_found", "execution reservation is missing"
                )
            if (
                row["phase"] not in {"cleanup_reported", "cleanup_verified"}
                or row["runc_exit_code"] != 0
                or row["runc_exit_evidence_source"] != "runc_client_kernel_waitpid"
                or row["workspace_binding_version"] != 1
                or row["baseline_root_path"] != str(baseline_root)
                or row["baseline_root_dev"] != baseline_device
                or row["baseline_root_ino"] != baseline_inode
                or row["workspace_root_path"] != workspace_path
                or row["workspace_root_dev"] != workspace_device
                or row["workspace_root_ino"] != workspace_inode
                or row["baseline_manifest_digest"] != change_set.baseline_digest
            ):
                raise SupervisorError(
                    "sandbox_result_evidence_unverified",
                    "candidate result is not bound to the exited execution workspace",
                )
            task = self._task_row(connection, attempt["task_id"])
            current_write_set_rules = self._write_set_rules(
                task, self._case_sensitive_paths(connection)
            )
            if current_write_set_rules != write_set_rules:
                raise SupervisorError(
                    "sandbox_result_evidence_conflict",
                    "task write set changed while the candidate was captured",
                )

            cleanup_json = row["cleanup_receipt_json"]
            if cleanup_json not in {
                canonical_json(self._sandbox_cleanup_receipt(row)),
                canonical_json(self._sandbox_cleanup_receipt_v2_legacy(row)),
                canonical_json(self._sandbox_cleanup_receipt_v1(row)),
            }:
                raise SupervisorError(
                    "sandbox_result_evidence_unverified",
                    "cleanup report is not the exact unverified journal receipt",
                )
            import_digest = hashlib.sha256(
                canonical_json(
                    {
                        "baseline_digest": change_set.baseline_digest,
                        "result_digest": change_set.result_digest,
                        "change_digest": change_set.digest,
                    }
                ).encode("utf-8")
            ).hexdigest()
            candidate = {
                "version": 1,
                "authorization": "none",
                "attempt_id": attempt_id,
                "claim_token": claim_token,
                "execution_id": row["execution_id"],
                "workspace_binding": {
                    "version": row["workspace_binding_version"],
                    "baseline": {
                        "path": row["baseline_root_path"],
                        "device": row["baseline_root_dev"],
                        "inode": row["baseline_root_ino"],
                        "manifest_digest": row["baseline_manifest_digest"],
                    },
                    "workspace": {
                        "path": row["workspace_root_path"],
                        "device": row["workspace_root_dev"],
                        "inode": row["workspace_root_ino"],
                    },
                },
                "result": {
                    "baseline_digest": change_set.baseline_digest,
                    "tree_digest": change_set.result_digest,
                    "change_digest": change_set.digest,
                    "import_digest": import_digest,
                },
                "exit": {
                    "code": row["runc_exit_code"],
                    "observed_by": row["runc_exit_evidence_source"],
                    "runc_client_pid": row["runc_client_pid"],
                    "runc_client_identity": row["runc_client_identity"],
                },
                "cleanup": {
                    "status": "unverified",
                    "report_digest": hashlib.sha256(cleanup_json.encode("utf-8")).hexdigest(),
                },
            }
            encoded = canonical_json(candidate)
            digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            if row["result_candidate_version"] == 1:
                if (
                    row["result_candidate_json"] != encoded
                    or row["result_candidate_digest"] != digest
                ):
                    raise SupervisorError(
                        "sandbox_result_evidence_conflict",
                        "captured candidate differs from the immutable journal receipt",
                    )
                return {
                    "candidate": candidate,
                    "candidate_digest": digest,
                    "baseline": binding["baseline"],
                    "change_set": change_set,
                }
            if row["result_candidate_version"] != 0:
                raise SupervisorError(
                    "sandbox_result_evidence_invalid", "candidate receipt version is unsupported"
                )
            changed = connection.execute(
                """
                UPDATE sandbox_executions
                SET result_candidate_version = 1, result_candidate_json = ?,
                    result_candidate_digest = ?, updated_at = ?
                WHERE attempt_id = ? AND claim_token = ?
                  AND phase IN ('cleanup_reported', 'cleanup_verified')
                  AND result_candidate_version = 0
                """,
                (encoded, digest, utc_now(), attempt_id, claim_token),
            ).rowcount
            if changed != 1:
                raise SupervisorError(
                    "sandbox_result_evidence_conflict", "candidate receipt changed concurrently"
                )
            self._event(
                connection,
                "sandbox.result_candidate_captured",
                "supervisor",
                {
                    "attempt_id": attempt_id,
                    "claim_token": claim_token,
                    "execution_id": row["execution_id"],
                    "candidate_digest": digest,
                    "import_digest": import_digest,
                    "authorization": "none",
                    "cleanup_status": "unverified",
                },
            )
        return {
            "candidate": candidate,
            "candidate_digest": digest,
            "baseline": binding["baseline"],
            "change_set": change_set,
        }

    def _sandbox_execution_result_import_source(
        self,
        connection: Any,
        attempt_id: str,
        claim_token: int,
    ) -> dict[str, str]:
        """Return journal identities usable only after trusted cleanup verification."""

        row = connection.execute(
            "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
        ).fetchone()
        if row is None or row["claim_token"] != claim_token:
            raise SupervisorError(
                "sandbox_execution_not_found", "matching sandbox execution is missing"
            )
        _require_sandbox_execution_result_eligible(connection, attempt_id)
        direct_import = connection.execute(
            "SELECT id FROM result_imports WHERE attempt_id = ? "
            "AND source_kind = 'direct_worker' LIMIT 1",
            (attempt_id,),
        ).fetchone()
        if direct_import is not None:
            raise SupervisorError(
                "sandbox_result_source_mismatch",
                "attempt already has a direct-worker result import",
            )
        cleanup_json = row["cleanup_receipt_json"]
        if cleanup_json not in {
            canonical_json(self._sandbox_cleanup_receipt(row)),
            canonical_json(self._sandbox_cleanup_receipt_v2_legacy(row)),
            canonical_json(self._sandbox_cleanup_receipt_v1(row)),
        }:
            raise SupervisorError(
                "sandbox_cleanup_report_invalid",
                "verified execution does not retain its exact journaled cleanup report",
            )
        return {
            "execution_id": row["execution_id"],
            "cleanup_receipt_digest": hashlib.sha256(cleanup_json.encode("utf-8")).hexdigest(),
        }

    def _sandbox_execution_require_result_candidate_matches(
        self,
        connection: Any,
        attempt_id: str,
        *,
        baseline_digest: str,
        import_digest: str,
        change_digest: str,
    ) -> None:
        """Match a sandbox import to its immutable, still non-authorizing capture."""

        row = connection.execute(
            "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
        ).fetchone()
        if row is None:
            return
        if row["result_candidate_version"] != 1 or not row["result_candidate_json"]:
            raise SupervisorError(
                "sandbox_result_evidence_missing", "sandbox import has no captured result candidate"
            )
        encoded = row["result_candidate_json"]
        if not isinstance(encoded, str):
            raise SupervisorError(
                "sandbox_result_evidence_invalid", "sandbox result candidate is not bounded text"
            )
        try:
            encoded_bytes = encoded.encode("utf-8")
        except UnicodeEncodeError:
            raise SupervisorError(
                "sandbox_result_evidence_invalid", "sandbox result candidate is not valid UTF-8"
            ) from None
        if len(encoded_bytes) > 65536:
            raise SupervisorError(
                "sandbox_result_evidence_invalid", "sandbox result candidate is not bounded text"
            )
        try:
            candidate = json.loads(encoded)
        except (TypeError, ValueError):
            candidate = None
        digest = hashlib.sha256(encoded_bytes).hexdigest()
        if (
            not isinstance(candidate, dict)
            or set(candidate)
            != {
                "version",
                "authorization",
                "attempt_id",
                "claim_token",
                "execution_id",
                "workspace_binding",
                "result",
                "exit",
                "cleanup",
            }
            or canonical_json(candidate) != encoded
            or row["result_candidate_digest"] != digest
        ):
            raise SupervisorError(
                "sandbox_result_evidence_invalid", "sandbox result candidate digest is invalid"
            )
        result = candidate.get("result")
        tree_digest = result.get("tree_digest") if isinstance(result, dict) else ""
        if not all(
            isinstance(value, str) and _DIGEST.fullmatch(value) is not None
            for value in (baseline_digest, import_digest, change_digest, tree_digest)
        ):
            raise SupervisorError(
                "sandbox_result_evidence_invalid", "sandbox result candidate digest is invalid"
            )
        expected_import_digest = hashlib.sha256(
            canonical_json(
                {
                    "baseline_digest": baseline_digest,
                    "result_digest": tree_digest,
                    "change_digest": change_digest,
                }
            ).encode("utf-8")
        ).hexdigest()
        expected_binding = {
            "version": row["workspace_binding_version"],
            "baseline": {
                "path": row["baseline_root_path"],
                "device": row["baseline_root_dev"],
                "inode": row["baseline_root_ino"],
                "manifest_digest": row["baseline_manifest_digest"],
            },
            "workspace": {
                "path": row["workspace_root_path"],
                "device": row["workspace_root_dev"],
                "inode": row["workspace_root_ino"],
            },
        }
        expected_exit = {
            "code": row["runc_exit_code"],
            "observed_by": row["runc_exit_evidence_source"],
            "runc_client_pid": row["runc_client_pid"],
            "runc_client_identity": row["runc_client_identity"],
        }
        expected_cleanup = {
            "status": "unverified",
            "report_digest": hashlib.sha256(
                row["cleanup_receipt_json"].encode("utf-8")
            ).hexdigest(),
        }
        if (
            candidate.get("version") != 1
            or type(candidate.get("version")) is not int
            or candidate.get("authorization") != "none"
            or candidate.get("attempt_id") != attempt_id
            or type(candidate.get("claim_token")) is not int
            or candidate.get("claim_token") != row["claim_token"]
            or candidate.get("execution_id") != row["execution_id"]
            or candidate.get("workspace_binding") != expected_binding
            or candidate.get("exit") != expected_exit
            or candidate.get("cleanup") != expected_cleanup
            or baseline_digest != row["baseline_manifest_digest"]
            or not isinstance(result, dict)
            or set(result) != {"baseline_digest", "tree_digest", "change_digest", "import_digest"}
            or result.get("baseline_digest") != row["baseline_manifest_digest"]
            or result.get("change_digest") != change_digest
            or result.get("import_digest") != import_digest
            or expected_import_digest != import_digest
        ):
            raise SupervisorError(
                "sandbox_result_evidence_mismatch",
                "sandbox import does not match its captured execution candidate",
            )

    def _sandbox_execution_transition(
        self,
        attempt_id: str,
        claim_token: int,
        *,
        expected_phase: str,
        next_phase: str,
        updates: dict[str, Any],
        event_type: str,
        event_payload: dict[str, Any],
        credential: str | None = None,
        _connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        allowed_fields = _TRANSITION_FIELDS.get((expected_phase, next_phase))
        if (
            allowed_fields is None
            or not isinstance(updates, dict)
            or set(updates) != allowed_fields
        ):
            raise SupervisorError(
                "sandbox_execution_transition_invalid",
                f"transition {expected_phase} -> {next_phase} is not available in this journal slice",
            )
        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        connection_context = self.connect() if _connection is None else nullcontext(_connection)
        with connection_context as connection:
            if _connection is None:
                connection.execute("BEGIN IMMEDIATE")
            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            if attempt["status"] != "working":
                raise SupervisorError("claim_inactive", "sandbox attempt is no longer working")
            self._authenticate_attempt(connection, attempt, credential)
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if not row:
                raise SupervisorError("sandbox_execution_not_found", "execution was not reserved")
            if row["claim_token"] != claim_token:
                raise SupervisorError("stale_fencing_token", "sandbox claim token is stale")
            if row["phase"] != expected_phase:
                raise SupervisorError(
                    "sandbox_execution_transition_invalid",
                    f"expected phase {expected_phase}, found {row['phase']}; fence retained",
                )
            if expected_phase == "reserved" and next_phase == "launched":
                if row["launch_plan_required"] != 1:
                    raise SupervisorError(
                        "sandbox_execution_launch_plan_required",
                        "legacy reservation has no trusted launch-plan requirement",
                    )
                if row["workspace_binding_version"] != 1:
                    raise SupervisorError(
                        "sandbox_workspace_unbound",
                        "sandbox launch requires a durable baseline/workspace binding",
                    )
                if row["private_path_binding_version"] != 1:
                    raise SupervisorError(
                        "sandbox_private_path_unbound",
                        "sandbox launch requires exact private bundle/state directory identities",
                    )
                execution_root = Path(row["bundle_path"]).parent
                expected_paths = (
                    (execution_root, row["execution_root_dev"], row["execution_root_ino"]),
                    (Path(row["bundle_path"]), row["bundle_root_dev"], row["bundle_root_ino"]),
                    (Path(row["state_path"]), row["state_root_dev"], row["state_root_ino"]),
                )
                if (
                    Path(row["bundle_path"]) != execution_root / "bundle"
                    or Path(row["state_path"]) != execution_root / "state"
                    or any(device is None or inode is None for _, device, inode in expected_paths)
                ):
                    raise SupervisorError(
                        "sandbox_private_path_unbound",
                        "journaled private execution paths are incomplete or noncanonical",
                    )
                for path, device, inode in expected_paths:
                    _verify_directory_identity(path, expected_device=device, expected_inode=inode)
                candidate = dict(row)
                candidate.update(updates)
                if not _sandbox_launch_plan_binding_is_self_consistent(candidate):
                    raise SupervisorError(
                        "sandbox_execution_launch_plan_invalid",
                        "launch transition lacks a self-consistent durable launch-plan binding",
                    )
                if any(
                    _DIGEST.fullmatch(row[name] or "") is None
                    for name in ("rootfs_closure_digest", "runc_executable_digest")
                ):
                    raise SupervisorError(
                        "sandbox_execution_content_pins_required",
                        "sandbox launch requires pinned rootfs closure and runc executable digests",
                    )
            fields = ", ".join(f"{name} = ?" for name in updates)
            changed = connection.execute(
                f"UPDATE sandbox_executions SET {fields}, phase = ?, updated_at = ? "
                "WHERE attempt_id = ? AND claim_token = ? AND phase = ?",
                (
                    *updates.values(),
                    next_phase,
                    utc_now(),
                    attempt_id,
                    claim_token,
                    expected_phase,
                ),
            ).rowcount
            if changed != 1:
                raise SupervisorError(
                    "sandbox_execution_transition_conflict",
                    "execution journal changed concurrently; attempt fence retained",
                )
            self._event(
                connection,
                event_type,
                attempt["agent_id"],
                {
                    "attempt_id": attempt_id,
                    "claim_token": claim_token,
                    "execution_id": row["execution_id"],
                    "phase": next_phase,
                    **event_payload,
                },
            )
            updated = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        return self._sandbox_execution_view(updated)

    def _sandbox_execution_record_launch(
        self,
        attempt_id: str,
        claim_token: int,
        *,
        monitor_pid: int,
        monitor_identity: str,
        runc_handle: RuncLaunchHandle,
        wrapper_unit: str,
        wrapper_invocation_id: str,
        scope_unit: str,
        scope_invocation_id: str,
        cgroup_path: str,
        credential: str | None = None,
    ) -> dict[str, Any]:
        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        monitor_pid = self._sandbox_pid(monitor_pid, "monitor_pid")
        launch_target = _runc_launch_target(runc_handle)
        if not _runc_launch_handle_is_self_consistent(runc_handle) or launch_target is None:
            raise SupervisorError(
                "sandbox_execution_launch_handle_required",
                "sandbox launch requires registered provenance from a pinned-runc launcher",
            )
        if launch_target.launch_mode != "private_bundle":
            raise SupervisorError(
                "sandbox_execution_launch_target_mismatch",
                "diagnostic runc launches cannot be recorded as supervised attempts",
            )
        runc_client_pid = self._sandbox_pid(_runc_launch_pid(runc_handle), "runc_client_pid")
        monitor_identity = self._sandbox_process_identity(monitor_identity, "monitor_identity")
        runc_client_identity = self._sandbox_process_identity(
            _runc_launch_process_identity(runc_handle), "runc_client_identity"
        )
        wrapper_unit = self._sandbox_systemd_unit(wrapper_unit, "wrapper_unit", ".service")
        wrapper_invocation_id = self._sandbox_invocation_id(
            wrapper_invocation_id, "wrapper_invocation_id"
        )
        scope_unit = self._sandbox_systemd_unit(scope_unit, "scope_unit", ".scope")
        scope_invocation_id = self._sandbox_invocation_id(
            scope_invocation_id, "scope_invocation_id"
        )
        if monitor_pid == runc_client_pid or wrapper_unit == scope_unit:
            raise SupervisorError(
                "sandbox_execution_invalid", "monitor, runc client, and scope identities conflict"
            )
        cgroup_path = self._sandbox_text(cgroup_path, "cgroup_path", limit=4096)
        cgroup = PurePosixPath(cgroup_path)
        if (
            not cgroup.is_absolute()
            or cgroup.as_posix() != cgroup_path
            or any(part in {".", ".."} for part in cgroup.parts)
            or cgroup.name != scope_unit
        ):
            raise SupervisorError(
                "sandbox_execution_invalid", "cgroup path must name the exact recorded scope"
            )
        with self.connect() as connection:
            durable_execution = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
        if not durable_execution:
            raise SupervisorError("sandbox_execution_not_found", "execution reservation is missing")
        if durable_execution["claim_token"] != claim_token:
            raise SupervisorError("stale_fencing_token", "claim token is stale")
        if durable_execution["launch_plan_required"] != 1:
            raise SupervisorError(
                "sandbox_execution_launch_plan_required",
                "legacy reservation has no trusted launch-plan requirement",
            )
        if durable_execution["workspace_binding_version"] != 1:
            raise SupervisorError(
                "sandbox_workspace_unbound",
                "sandbox launch requires a durable baseline/workspace binding",
            )
        if durable_execution["private_path_binding_version"] != 1:
            raise SupervisorError(
                "sandbox_private_path_unbound",
                "sandbox launch requires exact private bundle/state directory identities",
            )
        if durable_execution["phase"] != "reserved":
            raise SupervisorError(
                "sandbox_execution_transition_invalid",
                f"expected phase reserved, found {durable_execution['phase']}; fence retained",
            )
        if durable_execution["bundle_digest_semantics"] == _LEGACY_BUNDLE_DIGEST_SEMANTICS:
            raise SupervisorError(
                "sandbox_execution_legacy_bundle_digest",
                "legacy caller-asserted reservation digest is not eligible for a new launch",
            )
        if durable_execution["bundle_digest_semantics"] != _BUNDLE_DIGEST_SEMANTICS:
            raise SupervisorError(
                "sandbox_execution_bundle_digest_semantics_invalid",
                "reservation digest semantics are not recognized",
            )
        if durable_execution["bundle_digest"] != _sandbox_reservation_bundle_digest(
            durable_execution
        ):
            raise SupervisorError(
                "sandbox_execution_bundle_digest_mismatch",
                "reservation bundle digest does not match its host-derived identity and pins",
            )
        target_paths_match = (
            launch_target.bundle_path == durable_execution["bundle_path"]
            and launch_target.bundle_device == durable_execution["bundle_root_dev"]
            and launch_target.bundle_inode == durable_execution["bundle_root_ino"]
            and launch_target.rootfs_path == str(Path(durable_execution["bundle_path"]) / "rootfs")
            and launch_target.rootfs_sha256 == durable_execution["rootfs_digest"]
            and launch_target.rootfs_closure_sha256 == durable_execution["rootfs_closure_digest"]
            and launch_target.state_path == durable_execution["state_path"]
            and launch_target.state_device == durable_execution["state_root_dev"]
            and launch_target.state_inode == durable_execution["state_root_ino"]
            and launch_target.workspace_path == durable_execution["workspace_root_path"]
            and launch_target.workspace_device == durable_execution["workspace_root_dev"]
            and launch_target.workspace_inode == durable_execution["workspace_root_ino"]
            and launch_target.container_id == durable_execution["container_id"]
            and launch_target.runc_executable_sha256 == durable_execution["runc_executable_digest"]
        )
        if (
            not target_paths_match
            or launch_target.pid_file_path is None
            or Path(launch_target.pid_file_path).parent != Path(durable_execution["state_path"])
            or launch_target.config_sha256 is None
            or _DIGEST.fullmatch(launch_target.config_sha256) is None
            or type(launch_target.rootfs_device) is not int
            or type(launch_target.rootfs_inode) is not int
            or type(launch_target.rootfs_snapshot_device) is not int
            or type(launch_target.rootfs_snapshot_inode) is not int
            or launch_target.rootfs_snapshot_sha256 != launch_target.rootfs_sha256
            or launch_target.rootfs_snapshot_closure_sha256 != launch_target.rootfs_closure_sha256
            or launch_target.rootfs_snapshot_entry_count != launch_target.rootfs_entry_count
            or launch_target.rootfs_snapshot_bytes != launch_target.rootfs_bytes
            or (launch_target.rootfs_snapshot_device, launch_target.rootfs_snapshot_inode)
            == (launch_target.rootfs_device, launch_target.rootfs_inode)
        ):
            raise SupervisorError(
                "sandbox_execution_launch_target_mismatch",
                "pinned-runc launch target does not match the exact durable reservation",
            )
        launch_plan = _sandbox_launch_plan_material(durable_execution, launch_target)
        launch_plan_json = canonical_json(launch_plan)
        launch_config_digest = launch_target.config_sha256
        launch_argv_digest = hashlib.sha256(
            canonical_json(list(launch_target.argv)).encode("utf-8")
        ).hexdigest()
        launch_plan_digest = hashlib.sha256(launch_plan_json.encode("utf-8")).hexdigest()
        _runc_launch_handle_bind_execution(
            runc_handle, attempt_id, claim_token, durable_execution["execution_id"]
        )
        updates = {
            "monitor_pid": monitor_pid,
            "monitor_identity": monitor_identity,
            "runc_client_pid": runc_client_pid,
            "runc_client_identity": runc_client_identity,
            "wrapper_unit": wrapper_unit,
            "wrapper_invocation_id": wrapper_invocation_id,
            "scope_unit": scope_unit,
            "scope_invocation_id": scope_invocation_id,
            "cgroup_path": cgroup_path,
            "launch_plan_binding_version": 1,
            "launch_plan_json": launch_plan_json,
            "launch_config_digest": launch_config_digest,
            "launch_argv_digest": launch_argv_digest,
            "launch_plan_digest": launch_plan_digest,
        }
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            with _authorize_sandbox_launch_plan_write(
                connection,
                runc_handle,
                attempt_id,
                claim_token,
                durable_execution["execution_id"],
                launch_plan_json,
                launch_plan_digest,
            ):
                return self._sandbox_execution_transition(
                    attempt_id,
                    claim_token,
                    expected_phase="reserved",
                    next_phase="launched",
                    updates=updates,
                    event_type="sandbox.execution_launched",
                    event_payload={
                        **updates,
                        "launch_plan": launch_plan,
                        "launch_target": {
                            "mode": launch_target.launch_mode,
                            "runc_executable_path": launch_target.runc_executable_path,
                            "runc_executable_sha256": launch_target.runc_executable_sha256,
                            "config_sha256": launch_target.config_sha256,
                            "config_sha256_semantics": "sha256-exact-config-json-bytes",
                            "argv_sha256": launch_argv_digest,
                            "container_id": launch_target.container_id,
                            "bundle": {
                                "path": launch_target.bundle_path,
                                "device": launch_target.bundle_device,
                                "inode": launch_target.bundle_inode,
                            },
                            "rootfs": {
                                "path": launch_target.rootfs_path,
                                "device": launch_target.rootfs_device,
                                "inode": launch_target.rootfs_inode,
                                "sha256": launch_target.rootfs_sha256,
                                "closure_sha256": launch_target.rootfs_closure_sha256,
                                "snapshot": {
                                    "device": launch_target.rootfs_snapshot_device,
                                    "inode": launch_target.rootfs_snapshot_inode,
                                    "sha256": launch_target.rootfs_snapshot_sha256,
                                    "closure_sha256": launch_target.rootfs_snapshot_closure_sha256,
                                    "entry_count": launch_target.rootfs_snapshot_entry_count,
                                    "bytes": launch_target.rootfs_snapshot_bytes,
                                },
                            },
                            "state": {
                                "path": launch_target.state_path,
                                "device": launch_target.state_device,
                                "inode": launch_target.state_inode,
                            },
                            "workspace": {
                                "path": launch_target.workspace_path,
                                "device": launch_target.workspace_device,
                                "inode": launch_target.workspace_inode,
                            },
                            "pid_file_path": launch_target.pid_file_path,
                        },
                    },
                    credential=credential,
                    _connection=connection,
                )

    def _sandbox_execution_record_running(
        self,
        attempt_id: str,
        claim_token: int,
        *,
        attestation: RunningRuntimeAttestation,
        runc_handle: RuncLaunchHandle | None = None,
        credential: str | None = None,
    ) -> dict[str, Any]:
        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        if not row or row["claim_token"] != claim_token:
            raise SupervisorError("sandbox_execution_not_found", "execution reservation is missing")
        if row["phase"] != "launched":
            raise SupervisorError(
                "sandbox_execution_transition_invalid",
                f"cannot record running from phase {row['phase']}; fence retained",
            )
        if not _sandbox_launch_plan_binding_is_self_consistent(row):
            raise SupervisorError(
                "sandbox_execution_launch_plan_required",
                "running transition requires a durable trusted launch-plan binding",
            )
        if not running_attestation_is_self_consistent(attestation):
            raise SupervisorError(
                "sandbox_runtime_attestation_invalid",
                "running transition requires a self-consistent typed receipt",
            )
        expected = {
            "container_id": row["container_id"],
            "bundle_path": row["bundle_path"],
            "monitor_pid": row["monitor_pid"],
            "monitor_identity": row["monitor_identity"],
            "runc_client_pid": row["runc_client_pid"],
            "runc_client_identity": row["runc_client_identity"],
            "wrapper_unit": row["wrapper_unit"],
            "wrapper_invocation_id": row["wrapper_invocation_id"],
            "scope_unit": row["scope_unit"],
            "scope_invocation_id": row["scope_invocation_id"],
            "cgroup_path": row["cgroup_path"],
        }
        if any(getattr(attestation, key) != value for key, value in expected.items()):
            raise SupervisorError(
                "sandbox_runtime_attestation_stale",
                "runtime evidence does not match the durable launch identities",
            )
        init_pid = self._sandbox_pid(attestation.init_pid, "init_pid")
        init_identity = self._sandbox_process_identity(attestation.init_identity, "init_identity")
        if init_pid in {row["monitor_pid"], row["runc_client_pid"]}:
            raise SupervisorError(
                "sandbox_execution_invalid", "container init must have a distinct host PID"
            )
        if not _runc_launch_handle_is_bound_to_execution(
            runc_handle, attempt_id, claim_token, row["execution_id"]
        ):
            raise SupervisorError(
                "sandbox_execution_launch_handle_required",
                "running transition requires the exact registered launch handle",
            )
        with _runc_launch_gate_lock_for_execution(
            attempt_id, claim_token, row["execution_id"]
        ) as locked_handle:
            if locked_handle is not runc_handle:
                raise SupervisorError(
                    "sandbox_execution_launch_handle_required",
                    "running transition requires the exact locked launch handle",
                )
            updated = self._sandbox_execution_transition(
                attempt_id,
                claim_token,
                expected_phase="launched",
                next_phase="running",
                updates={"init_pid": init_pid, "init_identity": init_identity},
                event_type="sandbox.execution_running",
                event_payload={"attestation": attestation.audit_payload()},
                credential=credential,
            )
            # The same lock covers the durable transition and one-shot permit
            # issue. A stop/quarantine cannot commit between these operations.
            _authorize_runc_launch_gate_release_locked(
                locked_handle, attempt_id, claim_token, row["execution_id"]
            )
            return updated

    def _sandbox_execution_request_stop(
        self,
        attempt_id: str,
        claim_token: int,
        reason: str,
        *,
        credential: str | None = None,
    ) -> dict[str, Any]:
        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        reason = self._sandbox_text(reason, "stop_reason", limit=512)
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        if not row or row["claim_token"] != claim_token:
            raise SupervisorError("sandbox_execution_not_found", "execution reservation is missing")
        execution_id = row["execution_id"]
        with _runc_launch_gate_lock_for_execution(
            attempt_id, claim_token, execution_id
        ) as locked_handle:
            # Re-read after acquiring the release lock: this closes both the
            # launched->stopping and running->stopping races against gate open.
            with self.connect() as connection:
                row = connection.execute(
                    "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
                ).fetchone()
            if not row or row["claim_token"] != claim_token:
                raise SupervisorError(
                    "sandbox_execution_not_found", "execution reservation is missing"
                )
            if row["execution_id"] != execution_id:
                raise SupervisorError(
                    "sandbox_execution_transition_conflict",
                    "durable execution identity changed while requesting stop",
                )
            if row["phase"] == "stopping":
                if row["stop_reason"] != reason:
                    raise SupervisorError(
                        "sandbox_execution_transition_conflict",
                        "a different stop reason is already durable; fence retained",
                    )
                updated = self._sandbox_execution_view(row)
            else:
                if row["phase"] != "running":
                    raise SupervisorError(
                        "sandbox_execution_transition_invalid",
                        f"cannot request stop from phase {row['phase']}; fence retained",
                    )
                updated = self._sandbox_execution_transition(
                    attempt_id,
                    claim_token,
                    expected_phase=row["phase"],
                    next_phase="stopping",
                    updates={"stop_reason": reason},
                    event_type="sandbox.execution_stop_requested",
                    event_payload={"stop_reason": reason},
                    credential=credential,
                )
            if locked_handle is not None:
                _revoke_runc_launch_gate_release_locked(
                    locked_handle, attempt_id, claim_token, execution_id
                )
            return updated

    def _sandbox_execution_record_exit(
        self,
        attempt_id: str,
        claim_token: int,
        wait_receipt: _RuncClientWaitReceipt,
        *,
        credential: str | None = None,
    ) -> dict[str, Any]:
        if not _runc_client_wait_receipt_is_self_consistent(wait_receipt):
            raise SupervisorError(
                "sandbox_execution_wait_receipt_required",
                "runc exit recording requires a sealed receipt issued by the pinned-runc wait handle",
            )
        with _runc_launch_gate_lock_for_execution(
            attempt_id, claim_token, wait_receipt.execution_id
        ) as locked_handle:
            updated = self._sandbox_execution_record_exit_under_gate_lock(
                attempt_id, claim_token, wait_receipt, credential=credential
            )
            if locked_handle is not None:
                _revoke_runc_launch_gate_release_locked(
                    locked_handle,
                    attempt_id,
                    claim_token,
                    wait_receipt.execution_id,
                )
            return updated

    def _sandbox_execution_record_exit_under_gate_lock(
        self,
        attempt_id: str,
        claim_token: int,
        wait_receipt: _RuncClientWaitReceipt,
        *,
        credential: str | None = None,
    ) -> dict[str, Any]:
        """Persist exit evidence while its release gate cannot be opened."""

        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        if not _runc_client_wait_receipt_is_self_consistent(wait_receipt):
            raise SupervisorError(
                "sandbox_execution_wait_receipt_required",
                "runc exit recording requires a sealed receipt issued by the pinned-runc wait handle",
            )
        exit_code = wait_receipt.returncode
        if type(exit_code) is not int or not -255 <= exit_code <= 255:
            raise SupervisorError("sandbox_execution_invalid", "runc exit code is invalid")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if not row:
                raise SupervisorError(
                    "sandbox_execution_not_found", "execution reservation is missing"
                )
            if row["claim_token"] != claim_token:
                raise SupervisorError("stale_fencing_token", "sandbox claim token is stale")
            if row["phase"] in {"launched", "running", "stopping"} and not (
                _sandbox_launch_plan_binding_is_self_consistent(row)
            ):
                raise SupervisorError(
                    "sandbox_execution_launch_plan_required",
                    "exit transition requires a durable trusted launch-plan binding",
                )
            if (
                wait_receipt.pid != row["runc_client_pid"]
                or wait_receipt.process_identity != row["runc_client_identity"]
                or wait_receipt.attempt_id != row["attempt_id"]
                or wait_receipt.claim_token != row["claim_token"]
                or wait_receipt.execution_id != row["execution_id"]
            ):
                raise SupervisorError(
                    "sandbox_execution_wait_receipt_stale",
                    "runc wait receipt does not match the durable launch process identity",
                )
            if row["phase"] in {"exited", "cleanup_reported", "cleanup_verified"}:
                if row["runc_exit_code"] == exit_code:
                    if row["runc_exit_evidence_source"] == "runc_client_kernel_waitpid":
                        return self._sandbox_execution_view(row)
                    raise SupervisorError(
                        "sandbox_execution_evidence_unverified",
                        "legacy exit row has no durable kernel-wait evidence",
                    )
                raise SupervisorError(
                    "sandbox_execution_transition_conflict", "conflicting runc exit receipt"
                )
            if row["phase"] not in {"launched", "running", "stopping"}:
                raise SupervisorError(
                    "sandbox_execution_transition_invalid",
                    f"cannot record exit from phase {row['phase']}; fence retained",
                )

            attempt = self._active_attempt(connection, attempt_id, claim_token, int(time.time()))
            if attempt["status"] != "working":
                raise SupervisorError("claim_inactive", "sandbox attempt is no longer working")
            self._authenticate_attempt(connection, attempt, credential)
            with _authorize_sandbox_exit_receipt_write(connection, wait_receipt):
                changed = connection.execute(
                    "UPDATE sandbox_executions SET runc_exit_code = ?, "
                    "runc_exit_observed_by = 'runc_client_popen_wait', "
                    "runc_exit_evidence_source = 'runc_client_kernel_waitpid', "
                    "phase = 'exited', updated_at = ? "
                    "WHERE attempt_id = ? AND claim_token = ? AND phase = ?",
                    (exit_code, utc_now(), attempt_id, claim_token, row["phase"]),
                ).rowcount
            if changed != 1:
                raise SupervisorError(
                    "sandbox_execution_transition_conflict",
                    "execution journal changed concurrently; fence retained",
                )
            self._event(
                connection,
                "sandbox.execution_exited",
                attempt["agent_id"],
                {
                    "attempt_id": attempt_id,
                    "claim_token": claim_token,
                    "execution_id": row["execution_id"],
                    "phase": "exited",
                    "runc_exit_code": exit_code,
                    "observed_by": "runc_client_kernel_waitpid",
                },
            )
            updated = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        return self._sandbox_execution_view(updated)

    def _sandbox_execution_record_cleanup_report(
        self,
        attempt_id: str,
        claim_token: int,
        receipt: dict[str, Any],
        *,
        credential: str | None = None,
    ) -> dict[str, Any]:
        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        if not row or row["claim_token"] != claim_token:
            raise SupervisorError("sandbox_execution_not_found", "execution reservation is missing")
        if not isinstance(receipt, dict):
            raise SupervisorError(
                "sandbox_cleanup_report_invalid",
                "cleanup report is incomplete or is not bound to the recorded identities",
            )
        encoded = canonical_json(receipt)
        if len(encoded.encode("utf-8")) > 64 * 1024:
            raise SupervisorError("sandbox_cleanup_report_invalid", "cleanup report is too large")
        expected = self._sandbox_cleanup_receipt(row)
        expected_encoded = canonical_json(expected)
        if row["phase"] == "cleanup_reported":
            persisted = row["cleanup_receipt_json"]
            legacy_v2_encoded = canonical_json(self._sandbox_cleanup_receipt_v2_legacy(row))
            legacy_encoded = canonical_json(self._sandbox_cleanup_receipt_v1(row))
            if encoded == persisted and persisted in {
                expected_encoded,
                legacy_v2_encoded,
                legacy_encoded,
            }:
                return self._sandbox_execution_view(row)
            if encoded != expected_encoded:
                raise SupervisorError(
                    "sandbox_cleanup_report_invalid",
                    "cleanup report is incomplete or is not bound to the recorded identities",
                )
            raise SupervisorError(
                "sandbox_execution_transition_conflict",
                "cleanup receipt is already recorded and cannot be replaced",
            )
        if encoded != expected_encoded:
            raise SupervisorError(
                "sandbox_cleanup_report_invalid",
                "cleanup report is incomplete or is not bound to the recorded identities",
            )
        return self._sandbox_execution_transition(
            attempt_id,
            claim_token,
            expected_phase="exited",
            next_phase="cleanup_reported",
            updates={"cleanup_receipt_json": encoded},
            event_type="sandbox.execution_cleanup_reported",
            event_payload={"receipt_sha256": hashlib.sha256(encoded.encode()).hexdigest()},
            credential=credential,
        )

    def _sandbox_cleanup_receipt(self, row: Any) -> dict[str, Any]:
        return {
            "version": 2,
            "verification_status": "unverified",
            "attempt_id": row["attempt_id"],
            "claim_token": row["claim_token"],
            "execution_id": row["execution_id"],
            "container_id": row["container_id"],
            "bundle_digest": row["bundle_digest"],
            "rootfs_digest": row["rootfs_digest"],
            "rootfs_closure_digest": row["rootfs_closure_digest"],
            "runc_executable_digest": row["runc_executable_digest"],
            "runtime_version": row["runtime_version"],
            "oci_version": row["oci_version"],
            "runc_exit_code": row["runc_exit_code"],
            "runc_exit_observed_by": (
                row["runc_exit_evidence_source"] or row["runc_exit_observed_by"]
            ),
            "processes": {
                "monitor": {"pid": row["monitor_pid"], "identity": row["monitor_identity"]},
                "runc_client": {
                    "pid": row["runc_client_pid"],
                    "identity": row["runc_client_identity"],
                },
                "container_init": {"pid": row["init_pid"], "identity": row["init_identity"]},
            },
            "systemd": {
                "wrapper_unit": row["wrapper_unit"],
                "wrapper_invocation_id": row["wrapper_invocation_id"],
                "scope_unit": row["scope_unit"],
                "scope_invocation_id": row["scope_invocation_id"],
                "cgroup_path": row["cgroup_path"],
            },
            "paths": {"bundle": row["bundle_path"], "state": row["state_path"]},
            "observations": dict(_CLEANUP_OBSERVATIONS),
        }

    def _sandbox_cleanup_receipt_v1(self, row: Any) -> dict[str, Any]:
        """Reconstruct the historical receipt solely for immutable replay checks."""

        receipt = self._sandbox_cleanup_receipt_v2_legacy(row)
        receipt["version"] = 1
        receipt.pop("verification_status")
        receipt["observations"] = dict(_LEGACY_CLEANUP_OBSERVATIONS)
        return receipt

    def _sandbox_cleanup_receipt_v2_legacy(self, row: Any) -> dict[str, Any]:
        """Reconstruct a schema-16 v2 receipt for exact post-migration replay."""

        receipt = self._sandbox_cleanup_receipt(row)
        receipt.pop("rootfs_closure_digest")
        receipt.pop("runc_executable_digest")
        return receipt

    def _sandbox_execution_mark_ambiguous(
        self,
        attempt_id: str,
        claim_token: int,
        reason: str,
    ) -> dict[str, Any]:
        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        reason = self._sandbox_text(reason, "ambiguity_reason", limit=512)
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        if not row or row["claim_token"] != claim_token:
            return self._sandbox_execution_mark_ambiguous_under_gate_lock(
                attempt_id, claim_token, reason
            )
        execution_id = row["execution_id"]
        with _runc_launch_gate_lock_for_execution(
            attempt_id, claim_token, execution_id
        ) as locked_handle:
            updated = self._sandbox_execution_mark_ambiguous_under_gate_lock(
                attempt_id, claim_token, reason
            )
            if locked_handle is not None:
                _revoke_runc_launch_gate_release_locked(
                    locked_handle, attempt_id, claim_token, execution_id
                )
            return updated

    def _sandbox_execution_mark_ambiguous_under_gate_lock(
        self,
        attempt_id: str,
        claim_token: int,
        reason: str,
    ) -> dict[str, Any]:
        """Quarantine an unresolved execution and extend all attempt resource fences."""

        reason = self._sandbox_text(reason, "ambiguity_reason", limit=512)
        self._sandbox_validate_attempt_id(attempt_id)
        self._sandbox_claim_token(claim_token)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if not attempt or not row:
                raise SupervisorError(
                    "sandbox_execution_not_found", "execution reservation is missing"
                )
            if attempt["claim_token"] != claim_token or row["claim_token"] != claim_token:
                raise SupervisorError("stale_fencing_token", "sandbox claim token is stale")
            task = connection.execute(
                "SELECT current_attempt_id FROM tasks WHERE id = ?", (attempt["task_id"],)
            ).fetchone()
            if not task or task["current_attempt_id"] != attempt_id:
                raise SupervisorError("stale_fencing_token", "attempt no longer owns its task")
            if row["phase"] == "cleanup_verified":
                raise SupervisorError(
                    "sandbox_execution_terminal", "verified execution cannot be re-quarantined"
                )
            if row["phase"] != "ambiguous":
                connection.execute(
                    "UPDATE sandbox_executions SET phase = 'ambiguous', failure_reason = ?, "
                    "updated_at = ? WHERE attempt_id = ? AND claim_token = ?",
                    (reason, utc_now(), attempt_id, claim_token),
                )
            stamp = utc_now()
            connection.execute(
                "UPDATE attempts SET status = 'terminating', "
                "termination_target_status = 'quarantined', updated_at = ? WHERE id = ?",
                (stamp, attempt_id),
            )
            connection.execute(
                "UPDATE tasks SET status = 'cleanup_pending', cleanup_target_status = 'blocked', "
                "cleanup_error = ?, updated_at = ? WHERE id = ? AND current_attempt_id = ?",
                (
                    "sandbox execution cleanup is ambiguous; attempt and resources remain fenced",
                    stamp,
                    attempt["task_id"],
                    attempt_id,
                ),
            )
            connection.execute(
                "UPDATE resource_leases SET lease_expires_at = ?, updated_at = ? "
                "WHERE attempt_id = ?",
                (CLEANUP_FENCE_EPOCH, stamp, attempt_id),
            )
            connection.execute(
                "UPDATE runtime_allocations SET lease_expires_at = ?, updated_at = ? "
                "WHERE attempt_id = ?",
                (CLEANUP_FENCE_EPOCH, stamp, attempt_id),
            )
            self._event(
                connection,
                "sandbox.execution_ambiguous",
                "supervisor",
                {
                    "attempt_id": attempt_id,
                    "claim_token": claim_token,
                    "execution_id": row["execution_id"],
                    "reason": reason,
                },
            )
            updated = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        return self._sandbox_execution_view(updated)

    def _sandbox_execution_get(self, attempt_id: str) -> dict[str, Any] | None:
        self._sandbox_validate_attempt_id(attempt_id)
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM sandbox_executions WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        return self._sandbox_execution_view(row) if row else None

    @staticmethod
    def _sandbox_execution_view(row: Any) -> dict[str, Any]:
        value = dict(row)
        if value.get("runc_exit_evidence_source"):
            # Keep the historical API field useful while the database column is
            # retained only to satisfy the immutable pre-v20 SQLite CHECK.
            value["runc_exit_observed_by"] = value["runc_exit_evidence_source"]
        raw = value.pop("cleanup_receipt_json", "{}")
        try:
            value["cleanup_receipt"] = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            value["cleanup_receipt"] = {"state": "unavailable"}
        raw_candidate = value.pop("result_candidate_json", "")
        try:
            value["result_candidate"] = json.loads(raw_candidate) if raw_candidate else None
        except (TypeError, ValueError, json.JSONDecodeError):
            value["result_candidate"] = {"state": "unavailable"}
        raw_launch_plan = value.get("launch_plan_json", "")
        try:
            value["launch_plan"] = json.loads(raw_launch_plan) if raw_launch_plan else None
        except (TypeError, ValueError, json.JSONDecodeError):
            value["launch_plan"] = {"state": "unavailable"}
        return value

    @staticmethod
    def _sandbox_claim_token(value: Any) -> int:
        if type(value) is not int or value <= 0:
            raise SupervisorError("stale_fencing_token", "claim token must be positive")
        return value
