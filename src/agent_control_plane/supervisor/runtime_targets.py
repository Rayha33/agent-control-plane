"""Opt-in, claim-fenced evidence that QC and integration address their intended services.

The app's identity endpoint is deliberately treated as corroboration, never as a
security boundary. The receipt separately records ACP's allocated endpoint and
trusted runtime-driver resource identity; without OS/network attribution, the
strongest result this module can produce is ``corroborated``.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .common import SupervisorError, canonical_json, sha256

TARGET_CONTRACT = "acp-runtime-target-v1"
COMMAND_SET_SCOPE = (
    "configured deterministic QC/integration gate commands only; excludes critic, "
    "runtime setup, and runtime teardown commands"
)
MAX_COMMAND_SET_COUNT = 128
MAX_COMMAND_LENGTH = 65536
MAX_LIVE_RUNTIME_SAMPLE_AGE_SECONDS = 30
MAX_LIVE_RUNTIME_SAMPLE_FUTURE_SKEW_SECONDS = 5
IDENTITY_FIELDS = (
    "attempt_id",
    "task_id",
    "claim_token",
    "phase",
    "source_revision",
    "port",
    "driver_resource_id",
    "container_id",
    "process_identity",
    "database_namespace",
    "schema_version",
    "queue_namespace",
)
_NAME = re.compile(r"[a-z][a-z0-9_-]{0,47}\Z")
_ENV_NAME = re.compile(r"[A-Z_][A-Z0-9_]*\Z")
_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_MAX_IDENTITY_BYTES = 8192
_UTC_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?\+00:00\Z")


@dataclass(frozen=True)
class RuntimeTargetDefinition:
    name: str
    port_env: str
    driver: str
    database_driver: str | None
    queue_driver: str | None
    identity_path: str
    phases: tuple[str, ...]
    required: bool
    schema_version: str | None
    require_command_binding: bool


def parse_runtime_target_definitions(
    raw: Any,
    *,
    port_envs: set[str],
    driver_names: set[str],
) -> tuple[RuntimeTargetDefinition, ...]:
    """Validate ``[[runtime.targets]]`` against attempt-owned ports and drivers."""

    if not isinstance(raw, list):
        raise SupervisorError("invalid_config", "runtime.targets must be an array of tables")
    definitions: list[RuntimeTargetDefinition] = []
    names: set[str] = set()
    ports: set[str] = set()
    environment_names: set[str] = set()
    allowed_keys = {
        "name",
        "port_env",
        "driver",
        "database_driver",
        "queue_driver",
        "identity_path",
        "phases",
        "required",
        "schema_version",
        "require_command_binding",
    }
    for entry in raw:
        if not isinstance(entry, dict) or set(entry) - allowed_keys:
            raise SupervisorError(
                "invalid_config", "each runtime target must use only documented fields"
            )
        name = entry.get("name")
        port_env = entry.get("port_env")
        driver = entry.get("driver")
        if not isinstance(name, str) or not _NAME.fullmatch(name) or name in names:
            raise SupervisorError("invalid_config", "runtime target names must be unique safe ids")
        environment_name = f"ACP_TARGET_{name.upper().replace('-', '_')}_URL"
        if environment_name in environment_names:
            raise SupervisorError(
                "invalid_config", "runtime target names must map to unique environment variables"
            )
        if not isinstance(port_env, str) or not _ENV_NAME.fullmatch(port_env):
            raise SupervisorError("invalid_config", f"runtime target {name} needs a safe port_env")
        if port_env not in port_envs or port_env in ports:
            raise SupervisorError(
                "invalid_config",
                f"runtime target {name} must use a unique runtime.ports allocation",
            )
        if not isinstance(driver, str) or driver not in driver_names:
            raise SupervisorError(
                "invalid_config", f"runtime target {name} must name a configured runtime driver"
            )
        database_driver = entry.get("database_driver")
        queue_driver = entry.get("queue_driver")
        for field, related in (
            ("database_driver", database_driver),
            ("queue_driver", queue_driver),
        ):
            if related is not None and (
                not isinstance(related, str) or related not in driver_names
            ):
                raise SupervisorError(
                    "invalid_config", f"runtime target {name} has an unknown {field}"
                )
        identity_path = entry.get("identity_path", "/.well-known/acp/runtime-target")
        if (
            not isinstance(identity_path, str)
            or len(identity_path) > 128
            or not identity_path.startswith("/")
            or "//" in identity_path
            or any(part in {".", ".."} for part in identity_path.split("/"))
            or not re.fullmatch(r"/[A-Za-z0-9._~/-]*", identity_path)
        ):
            raise SupervisorError(
                "invalid_config", f"runtime target {name} identity_path must be a safe local path"
            )
        phases = entry.get("phases", ["qc", "integration"])
        if (
            not isinstance(phases, list)
            or not phases
            or any(
                not isinstance(phase, str) or phase not in {"qc", "integration"} for phase in phases
            )
            or len(set(phases)) != len(phases)
        ):
            raise SupervisorError(
                "invalid_config",
                f"runtime target {name} phases must be unique qc/integration values",
            )
        required = entry.get("required", True)
        if not isinstance(required, bool):
            raise SupervisorError(
                "invalid_config", f"runtime target {name} required must be boolean"
            )
        require_command_binding = entry.get("require_command_binding", False)
        if not isinstance(require_command_binding, bool):
            raise SupervisorError(
                "invalid_config",
                f"runtime target {name} require_command_binding must be boolean",
            )
        schema_version = entry.get("schema_version")
        if schema_version is not None and (
            not isinstance(schema_version, str)
            or not schema_version
            or len(schema_version) > 64
            or any(ord(char) < 32 for char in schema_version)
        ):
            raise SupervisorError(
                "invalid_config", f"runtime target {name} schema_version must be short text"
            )
        definitions.append(
            RuntimeTargetDefinition(
                name=name,
                port_env=port_env,
                driver=driver,
                database_driver=database_driver,
                queue_driver=queue_driver,
                identity_path=identity_path,
                phases=tuple(phases),
                required=required,
                schema_version=schema_version,
                require_command_binding=require_command_binding,
            )
        )
        names.add(name)
        ports.add(port_env)
        environment_names.add(environment_name)
    return tuple(definitions)


def runtime_target_phase(
    *,
    definitions: tuple[RuntimeTargetDefinition, ...],
    commands: Sequence[str],
    runtime_environment: Mapping[str, str],
    driver_resources: list[Mapping[str, Any]],
    attempt_id: str,
    task_id: str,
    claim_token: int,
    reservation_fence_sha256: str,
    phase: str,
    source_revision: str,
    runtime_dir: Path,
    receipt_id: str,
    live_runtime_sample: Mapping[str, Any] | None = None,
    baseline_receipt: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, str], bool]:
    """Probe configured loopback targets and write a read-only manifest.

    Returns ``(durable_receipt, command_environment, blocked)``. Missing fields
    remain unknown. Required targets block unless every declared identity field
    matches; even a full match is only corroboration because the app controls its
    own report. When baseline resource hashes are supplied, a required target
    also blocks if its latest trusted-driver evidence differs from the phase
    preflight. Namespace-runtime resources additionally require a current,
    successful systemd invocation-ID sample; a missing or stale identity blocks
    a required target. These samples detect unit replacement but do not prove
    command routing or close the race between checking and command execution.
    """

    if phase not in {"qc", "integration"}:
        raise SupervisorError("runtime_target_phase_invalid", "unsupported target phase")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", receipt_id):
        raise SupervisorError("runtime_target_receipt_id_invalid", "target receipt id is invalid")
    if not _REVISION.fullmatch(source_revision):
        raise SupervisorError(
            "runtime_target_revision_invalid", "target source revision is invalid"
        )
    if not re.fullmatch(r"[0-9a-f]{64}", reservation_fence_sha256):
        raise SupervisorError(
            "runtime_target_fence_invalid", "target claim fence digest is invalid"
        )
    command_set_sha256 = _command_set_sha256(commands)
    baseline_resource_snapshot_sha256: dict[str, str] | None = None
    baseline_evidence_id: str | None = None
    baseline_evidence_sha256: str | None = None
    if baseline_receipt is not None:
        expected_target_names = {
            definition.name for definition in definitions if phase in definition.phases
        }
        baseline_payload = dict(baseline_receipt) if isinstance(baseline_receipt, Mapping) else {}
        baseline_evidence_sha256 = baseline_payload.pop("evidence_sha256", None)
        baseline_evidence_id = baseline_payload.get("evidence_id")
        baseline_targets = (
            baseline_receipt.get("targets") if isinstance(baseline_receipt, Mapping) else None
        )
        baseline_hashes = (
            {
                str(target.get("name")): target.get("resource_snapshot_sha256")
                for target in baseline_targets
                if isinstance(target, Mapping)
            }
            if isinstance(baseline_targets, list)
            else {}
        )
        if (
            not isinstance(baseline_receipt, Mapping)
            or baseline_payload.get("contract") != TARGET_CONTRACT
            or baseline_payload.get("status") != "complete"
            or baseline_payload.get("phase") != phase
            or baseline_payload.get("attempt_id") != attempt_id
            or baseline_payload.get("task_id") != task_id
            or baseline_payload.get("claim_token") != claim_token
            or baseline_payload.get("reservation_fence_sha256") != reservation_fence_sha256
            or baseline_payload.get("source_revision") != source_revision
            or baseline_payload.get("command_set_sha256") != command_set_sha256
            or baseline_payload.get("command_count") != len(commands)
            or not isinstance(baseline_evidence_id, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}:runtime-target:[a-z]+", baseline_evidence_id)
            or not isinstance(baseline_evidence_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", baseline_evidence_sha256)
            or baseline_evidence_sha256 != sha256(canonical_json(baseline_payload).encode("utf-8"))
            or set(baseline_hashes) != expected_target_names
            or not isinstance(baseline_targets, list)
            or len(baseline_targets) != len(expected_target_names)
            or any(
                not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                for value in baseline_hashes.values()
            )
        ):
            raise SupervisorError(
                "runtime_target_baseline_invalid",
                "phase target preflight receipt is invalid or belongs to another execution",
            )
        baseline_resource_snapshot_sha256 = {
            str(name): str(value) for name, value in baseline_hashes.items()
        }
    resources = {str(item.get("driver", "")): item for item in driver_resources}
    live_systemd_invocation_ids, live_runtime_sampled_at = _live_systemd_invocation_ids(
        live_runtime_sample
    )
    manifest_targets: list[dict[str, Any]] = []
    receipt_targets: list[dict[str, Any]] = []
    blocked = False
    resource_replacement_blocked = False
    live_runtime_identity_unavailable = False
    live_runtime_identity_mismatch_detected = False
    live_runtime_identity_sampled = False
    for definition in definitions:
        if phase not in definition.phases:
            continue
        raw_port = runtime_environment.get(definition.port_env)
        try:
            port = int(raw_port) if raw_port is not None else 0
        except (TypeError, ValueError):
            port = 0
        if not 1024 <= port <= 65535:
            port = 0
        driver = resources.get(definition.driver)
        host_identity = _host_resource_identity(driver)
        target_resource_names = [definition.driver]
        if definition.database_driver:
            target_resource_names.append(definition.database_driver)
        if definition.queue_driver:
            target_resource_names.append(definition.queue_driver)
        namespace_resource_names = [
            name
            for name in target_resource_names
            if (resource := resources.get(name)) and resource.get("kind") == "namespace_runtime"
        ]
        live_runtime_identity_sampled = live_runtime_identity_sampled or bool(
            namespace_resource_names
        )
        missing_live_runtime_identities = [
            name for name in namespace_resource_names if name not in live_systemd_invocation_ids
        ]
        mismatched_persisted_live_identities = [
            name
            for name in namespace_resource_names
            if (stored_identity := _host_resource_identity(resources.get(name))["process_identity"])
            and (live_identity := live_systemd_invocation_ids.get(name))
            and stored_identity != live_identity
        ]
        if definition.required or definition.require_command_binding:
            live_runtime_identity_unavailable = live_runtime_identity_unavailable or bool(
                missing_live_runtime_identities
            )
            live_runtime_identity_mismatch_detected = (
                live_runtime_identity_mismatch_detected
                or bool(mismatched_persisted_live_identities)
            )
        if driver and driver.get("kind") == "namespace_runtime":
            live_process_identity = live_systemd_invocation_ids.get(definition.driver)
            host_identity = {
                **host_identity,
                "status": "host_captured" if live_process_identity else "unknown",
                "process_identity": live_process_identity,
            }
        expected: dict[str, Any] = {
            "attempt_id": attempt_id,
            "task_id": task_id,
            "claim_token": claim_token,
            "phase": phase,
            "source_revision": source_revision,
            "port": port or None,
            "driver_resource_id": (
                driver.get("resource_id")
                if driver and driver.get("state") == "active" and driver.get("resource_id")
                else None
            ),
        }
        if len(host_identity["container_ids"]) == 1:
            expected["container_id"] = host_identity["container_ids"][0]
        if host_identity["process_identity"]:
            expected["process_identity"] = host_identity["process_identity"]
        elif driver and driver.get("kind") == "namespace_runtime":
            expected["process_identity"] = None
        related_resources: dict[str, Mapping[str, Any] | None] = {}
        if definition.database_driver:
            related_resources["database_namespace"] = resources.get(definition.database_driver)
            database = related_resources["database_namespace"]
            expected["database_namespace"] = (
                database.get("resource_id")
                if database and database.get("state") == "active"
                else None
            )
        if definition.queue_driver:
            related_resources["queue_namespace"] = resources.get(definition.queue_driver)
            queue = related_resources["queue_namespace"]
            expected["queue_namespace"] = (
                queue.get("resource_id") if queue and queue.get("state") == "active" else None
            )
        if definition.schema_version is not None:
            expected["schema_version"] = definition.schema_version

        resource_snapshots = [
            _resource_binding_snapshot(
                "service", definition.driver, resources, live_systemd_invocation_ids
            )
        ]
        if definition.database_driver:
            resource_snapshots.append(
                _resource_binding_snapshot(
                    "database", definition.database_driver, resources, live_systemd_invocation_ids
                )
            )
        if definition.queue_driver:
            resource_snapshots.append(
                _resource_binding_snapshot(
                    "queue", definition.queue_driver, resources, live_systemd_invocation_ids
                )
            )
        resource_snapshot_sha256 = sha256(canonical_json(resource_snapshots).encode("utf-8"))
        resource_snapshot_matches_preflight = (
            None
            if baseline_resource_snapshot_sha256 is None
            else baseline_resource_snapshot_sha256[definition.name] == resource_snapshot_sha256
        )

        endpoint = f"http://127.0.0.1:{port}" if port else None
        observed, probe_status = (
            probe_target_identity(port, definition.identity_path) if port else ({}, "invalid_port")
        )
        observed = _safe_identity(observed)
        expected_fields = [key for key, value in expected.items() if value is not None]
        missing_expected = [key for key in expected if expected[key] is None]
        missing_expected.extend(
            f"{name}.live_systemd_invocation_id" for name in missing_live_runtime_identities
        )
        missing_observed = [key for key in expected_fields if key not in observed]
        mismatches = [
            key for key in expected_fields if key in observed and observed[key] != expected[key]
        ]
        if resource_snapshot_matches_preflight is False:
            mismatches.append("resource_snapshot_sha256")
        if mismatched_persisted_live_identities:
            mismatches.append("persisted_live_systemd_invocation_id")
        if (
            host_identity["container_ids"]
            and "container_id" in observed
            and observed["container_id"] not in host_identity["container_ids"]
        ):
            mismatches.append("container_id")
        missing_driver = (
            not driver
            or driver.get("state") != "active"
            or not driver.get("resource_id")
            or not driver.get("kind")
        )
        missing_related = [
            field
            for field, resource in related_resources.items()
            if not resource or resource.get("state") != "active" or not resource.get("resource_id")
        ]
        if missing_driver:
            missing_expected.append("driver_resource_id")
        missing_expected.extend(missing_related)
        command_binding_status = (
            "unknown" if definition.require_command_binding else "not_requested"
        )
        if definition.require_command_binding:
            missing_expected.append("command_network_binding")
        if mismatches:
            status = "mismatch"
        elif (
            probe_status != "ok"
            or missing_expected
            or missing_observed
            or definition.require_command_binding
        ):
            status = "unknown"
        else:
            status = "corroborated"
        target_blocked = (definition.required and status != "corroborated") or (
            definition.require_command_binding
        )
        blocked = blocked or target_blocked
        resource_replacement_blocked = resource_replacement_blocked or (
            definition.required
            and resource_snapshot_matches_preflight is False
            and not missing_live_runtime_identities
            and not mismatched_persisted_live_identities
        )
        entry = {
            "name": definition.name,
            "required": definition.required,
            "require_command_binding": definition.require_command_binding,
            "command_binding_status": command_binding_status,
            "status": status,
            "verified": False,
            "expected": expected,
            "observed": _receipt_identity(observed, expected),
            "host_identity": host_identity,
            "resource_snapshots": resource_snapshots,
            "resource_snapshot_sha256": resource_snapshot_sha256,
            "resource_snapshot_matches_preflight": resource_snapshot_matches_preflight,
            "live_runtime_identity_unavailable": bool(missing_live_runtime_identities),
            "live_runtime_identity_mismatch": bool(mismatched_persisted_live_identities),
            "live_runtime_sampled_at": live_runtime_sampled_at,
            "probe_status": probe_status,
            "missing_evidence": sorted(set(missing_expected + missing_observed)),
            "mismatches": mismatches,
            "endpoint": endpoint,
            "identity_path": definition.identity_path,
            "driver": definition.driver,
            "database_driver": definition.database_driver,
            "queue_driver": definition.queue_driver,
        }
        receipt_targets.append(entry)
        manifest_targets.append(
            {
                "name": definition.name,
                "endpoint": endpoint,
                "expected": expected,
                "host_identity": host_identity,
                "resource_snapshots": resource_snapshots,
                "resource_snapshot_sha256": resource_snapshot_sha256,
                "resource_snapshot_matches_preflight": resource_snapshot_matches_preflight,
                "identity_path": definition.identity_path,
                "required": definition.required,
                "require_command_binding": definition.require_command_binding,
                "command_binding_status": command_binding_status,
                "status": status,
                "verified": False,
            }
        )

    limitations = [
        "app-reported identity is corroborating only",
        "no OS process/container-to-socket attribution was performed",
        "no network policy proved which endpoint each test command used",
    ]
    if live_runtime_identity_sampled:
        limitations.append(
            "live systemd invocation IDs detect sampled unit-incarnation changes only; "
            "they do not bind command traffic or close the check-to-launch race"
        )
    if any(
        definition.require_command_binding and phase in definition.phases
        for definition in definitions
    ):
        limitations.append(
            "required command network binding is unavailable; the phase is blocked as unknown"
        )
    manifest = {
        "contract": "acp-runtime-target-manifest-v1",
        "receipt_id": receipt_id,
        "attempt_id": attempt_id,
        "task_id": task_id,
        "claim_token": claim_token,
        "reservation_fence_sha256": reservation_fence_sha256,
        "phase": phase,
        "source_revision": source_revision,
        "command_set_scope": COMMAND_SET_SCOPE,
        "command_set_sha256": command_set_sha256,
        "command_count": len(commands),
        "baseline_evidence_id": baseline_evidence_id,
        "baseline_evidence_sha256": baseline_evidence_sha256,
        "live_runtime_sampled_at": live_runtime_sampled_at,
        "targets": manifest_targets,
        "limitations": limitations,
    }
    manifest_bytes = (canonical_json(manifest) + "\n").encode("utf-8")
    manifest_path = _write_manifest(runtime_dir, receipt_id, phase, manifest_bytes)
    manifest_sha256 = sha256(manifest_bytes)
    target_env = {
        "ACP_RUNTIME_TARGETS_FILE": str(manifest_path),
        "ACP_RUNTIME_TARGETS_SHA256": manifest_sha256,
    }
    for target in manifest_targets:
        env_name = f"ACP_TARGET_{target['name'].upper().replace('-', '_')}_URL"
        if target["endpoint"]:
            target_env[env_name] = str(target["endpoint"])
    receipt = {
        "kind": (
            "runtime_target_revalidation"
            if baseline_receipt is not None
            else "runtime_target_preflight"
        ),
        "exit_code": 1 if blocked else 0,
        "duration_ms": 0,
        "contract": TARGET_CONTRACT,
        "receipt_id": receipt_id,
        "attempt_id": attempt_id,
        "task_id": task_id,
        "claim_token": claim_token,
        "reservation_fence_sha256": reservation_fence_sha256,
        "phase": phase,
        "source_revision": source_revision,
        "command_set_scope": COMMAND_SET_SCOPE,
        "command_set_sha256": command_set_sha256,
        "command_count": len(commands),
        "baseline_evidence_id": baseline_evidence_id,
        "baseline_evidence_sha256": baseline_evidence_sha256,
        "live_runtime_sampled_at": live_runtime_sampled_at,
        "status": "blocked" if blocked else "complete",
        "blocking_reason": (
            "runtime_target_command_binding_unavailable"
            if blocked
            and any(
                definition.require_command_binding and phase in definition.phases
                for definition in definitions
            )
            else "runtime_target_live_identity_unavailable"
            if blocked and live_runtime_identity_unavailable
            else "runtime_target_live_identity_mismatch"
            if blocked and live_runtime_identity_mismatch_detected
            else "runtime_target_resource_replaced"
            if blocked and resource_replacement_blocked
            else "runtime_target_identity_mismatch"
            if blocked
            else None
        ),
        "resource_replacement_detected": any(
            target["resource_snapshot_matches_preflight"] is False
            and not target["live_runtime_identity_unavailable"]
            and not target["live_runtime_identity_mismatch"]
            for target in receipt_targets
        ),
        "verified": False,
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_sha256,
        "targets": receipt_targets,
        "limitations": manifest["limitations"],
    }
    receipt["evidence_id"] = f"{receipt_id}:runtime-target:{phase}"
    receipt["evidence_sha256"] = sha256(canonical_json(receipt).encode("utf-8"))
    return receipt, target_env, blocked


def _command_set_sha256(commands: Sequence[str]) -> str:
    """Hash the exact ordered shell commands named for this preflight.

    This is plan provenance only. It does not prove which executable bytes ran,
    which environment reached the process, or which endpoint the process used.
    """

    if isinstance(commands, (str, bytes)) or not isinstance(commands, Sequence):
        raise SupervisorError(
            "runtime_target_commands_invalid", "phase commands must be a sequence"
        )
    if len(commands) > MAX_COMMAND_SET_COUNT or any(
        not isinstance(command, str) or len(command) > MAX_COMMAND_LENGTH for command in commands
    ):
        raise SupervisorError("runtime_target_commands_invalid", "phase command set is invalid")
    payload = {
        "contract": "acp-command-set-v1",
        "scope": COMMAND_SET_SCOPE,
        "runner": "supervisor-shell-c-v1",
        "commands": list(commands),
    }
    return sha256(canonical_json(payload).encode("utf-8"))


def probe_target_identity(port: int, identity_path: str) -> tuple[dict[str, Any], str]:
    """Read a bounded JSON identity response directly over loopback, without proxies."""

    if not 1024 <= port <= 65535:
        return {}, "invalid_port"
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1.0)
    try:
        connection.request(
            "GET",
            identity_path,
            headers={"Accept": "application/json", "Connection": "close"},
        )
        response = connection.getresponse()
        if response.status != 200:
            return {}, "http_status"
        content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            return {}, "content_type"
        raw = response.read(_MAX_IDENTITY_BYTES + 1)
        if len(raw) > _MAX_IDENTITY_BYTES:
            return {}, "response_too_large"
        try:
            parsed = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}, "invalid_json"
        if not isinstance(parsed, dict) or parsed.get("contract") != TARGET_CONTRACT:
            return {}, "contract_mismatch"
        return parsed, "ok"
    except (OSError, http.client.HTTPException, TimeoutError):
        return {}, "unavailable"
    finally:
        connection.close()


def _safe_identity(value: Mapping[str, Any]) -> dict[str, Any]:
    """Keep only bounded identity scalars; never persist arbitrary service payloads."""

    clean: dict[str, Any] = {}
    for field in IDENTITY_FIELDS:
        item = value.get(field)
        if isinstance(item, bool):
            continue
        if isinstance(item, int):
            if field == "claim_token" and 0 <= item < 2**63:
                clean[field] = item
            elif field == "port" and 0 <= item <= 65535:
                clean[field] = item
            continue
        if (
            isinstance(item, str)
            and item
            and len(item) <= 256
            and not any(ord(char) < 32 for char in item)
        ):
            clean[field] = item
    return clean


def _receipt_identity(observed: Mapping[str, Any], expected: Mapping[str, Any]) -> dict[str, Any]:
    """Redact unexpected opaque IDs so a hostile service cannot smuggle secrets into logs."""

    opaque_fields = {"driver_resource_id", "database_namespace", "queue_namespace"}
    safe: dict[str, Any] = {}
    for field, value in observed.items():
        if field in opaque_fields and value != expected.get(field):
            safe[field] = {
                "sha256": sha256(str(value).encode("utf-8")),
                "redacted": True,
            }
        else:
            safe[field] = value
    return safe


def _live_systemd_invocation_ids(
    sample: Mapping[str, Any] | None,
) -> tuple[dict[str, str], str | None]:
    """Keep only validated invocation IDs from a current successful unit sample."""

    if not isinstance(sample, Mapping):
        return {}, None
    sampled_at = sample.get("sampled_at")
    if not isinstance(sampled_at, str) or not _UTC_TIMESTAMP.fullmatch(sampled_at):
        return {}, None
    try:
        sampled_time = datetime.fromisoformat(sampled_at)
    except ValueError:
        return {}, None
    age_seconds = (datetime.now(UTC) - sampled_time).total_seconds()
    if (
        age_seconds > MAX_LIVE_RUNTIME_SAMPLE_AGE_SECONDS
        or age_seconds < -MAX_LIVE_RUNTIME_SAMPLE_FUTURE_SKEW_SECONDS
    ):
        return {}, sampled_at
    drivers = sample.get("drivers")
    if not isinstance(drivers, list):
        return {}, sampled_at
    identities: dict[str, str] = {}
    ambiguous: set[str] = set()
    for driver in drivers:
        if not isinstance(driver, Mapping):
            continue
        name = driver.get("driver")
        invocation_id = driver.get("systemd_unit_invocation_id")
        if (
            not isinstance(name, str)
            or not _NAME.fullmatch(name)
            or driver.get("identity_available") is not True
            or driver.get("available") is not True
            or driver.get("present") is not True
            or driver.get("active_state") != "active"
            or not isinstance(invocation_id, str)
            or not re.fullmatch(r"[0-9a-f]{32}", invocation_id)
        ):
            continue
        if name in identities and identities[name] != invocation_id:
            identities.pop(name, None)
            ambiguous.add(name)
        elif name not in ambiguous:
            identities[name] = invocation_id
    return identities, sampled_at


def _host_resource_identity(resource: Mapping[str, Any] | None) -> dict[str, Any]:
    """Extract narrowly typed identity captured by a trusted runtime-driver probe."""

    empty = {
        "status": "unknown",
        "container_ids": [],
        "process_identity": None,
    }
    if not resource or resource.get("state") != "active":
        return empty
    evidence = resource.get("evidence")
    if not isinstance(evidence, Mapping):
        return empty
    proof = evidence.get("proof")
    observation = proof.get("observation") if isinstance(proof, Mapping) else None
    observation = observation if isinstance(observation, Mapping) else {}
    container_ids: list[str] = []
    if resource.get("kind") == "docker_compose":
        raw_ids = observation.get("stdout")
        if isinstance(raw_ids, str) and len(raw_ids) <= 8192:
            container_ids = sorted(
                {line for line in raw_ids.splitlines() if re.fullmatch(r"[0-9a-f]{12,64}", line)}
            )
    process_identity = None
    if resource.get("kind") == "namespace_runtime":
        candidate = observation.get("systemd_unit_invocation_id")
        if isinstance(candidate, str) and re.fullmatch(r"[0-9a-f]{32}", candidate):
            process_identity = candidate
    if not container_ids and not process_identity:
        return empty
    return {
        "status": "host_captured",
        "container_ids": container_ids,
        "process_identity": process_identity,
    }


def _resource_binding_snapshot(
    role: str,
    driver_name: str,
    resources: Mapping[str, Mapping[str, Any]],
    live_systemd_invocation_ids: Mapping[str, str],
) -> dict[str, Any]:
    """Return an allowlisted snapshot of one target's configured resource.

    Resource IDs alone can stay stable across a driver-observed container or
    systemd service replacement. Preserve host-captured evidence and the current
    validated systemd invocation ID separately; never copy raw driver output or
    credential evidence. Repeated phase checks compare these snapshots to the
    preflight to detect sampled replacement, but do not prove command routing or
    close the race between the check and command execution.
    """

    resource = resources.get(driver_name)
    if not isinstance(resource, Mapping):
        resource = None
    resource_id = resource.get("resource_id") if resource else None
    if (
        not isinstance(resource_id, str)
        or not resource_id
        or len(resource_id) > 256
        or any(ord(char) < 32 for char in resource_id)
    ):
        resource_id = None
    kind = resource.get("kind") if resource else None
    if not isinstance(kind, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,47}", kind):
        kind = None
    state = resource.get("state") if resource else None
    if not isinstance(state, str) or state not in {
        "active",
        "stopped",
        "quarantined",
        "setup_failed",
        "unknown",
    }:
        state = "unknown"
    snapshot = {
        "role": role,
        "driver": driver_name,
        "resource_id": resource_id,
        "kind": kind,
        "state": state,
        "host_identity": _host_resource_identity(resource),
    }
    if kind == "namespace_runtime":
        snapshot["live_systemd_invocation_id"] = live_systemd_invocation_ids.get(driver_name)
    return snapshot


def _write_manifest(runtime_dir: Path, receipt_id: str, phase: str, content: bytes) -> Path:
    directory = runtime_dir / "target-manifests"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink() or not directory.is_dir():
        raise SupervisorError(
            "runtime_target_manifest_unsafe", "target manifest directory is unsafe"
        )
    directory.chmod(0o700)
    path = directory / f"{receipt_id}-{phase}.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o400)
    except OSError as error:
        raise SupervisorError(
            "runtime_target_manifest_write_failed", "cannot create target manifest"
        ) from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o400:
            raise SupervisorError(
                "runtime_target_manifest_unsafe", "target manifest file is unsafe"
            )
        remaining = memoryview(content)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise SupervisorError(
                    "runtime_target_manifest_write_failed", "target manifest write was incomplete"
                )
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return path
