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
) -> tuple[dict[str, Any], dict[str, str], bool]:
    """Probe configured loopback targets and write a read-only manifest.

    Returns ``(durable_receipt, command_environment, blocked)``. Missing fields
    remain unknown. Required targets block unless every declared identity field
    matches; even a full match is only corroboration because the app controls its
    own report.
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
    resources = {str(item.get("driver", "")): item for item in driver_resources}
    manifest_targets: list[dict[str, Any]] = []
    receipt_targets: list[dict[str, Any]] = []
    blocked = False
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

        endpoint = f"http://127.0.0.1:{port}" if port else None
        observed, probe_status = (
            probe_target_identity(port, definition.identity_path) if port else ({}, "invalid_port")
        )
        observed = _safe_identity(observed)
        expected_fields = [key for key, value in expected.items() if value is not None]
        missing_expected = [key for key in expected if expected[key] is None]
        missing_observed = [key for key in expected_fields if key not in observed]
        mismatches = [
            key for key in expected_fields if key in observed and observed[key] != expected[key]
        ]
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
        "kind": "runtime_target_preflight",
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
        "status": "blocked" if blocked else "complete",
        "blocking_reason": (
            "runtime_target_command_binding_unavailable"
            if any(
                definition.require_command_binding and phase in definition.phases
                for definition in definitions
            )
            else "runtime_target_identity_mismatch"
            if blocked
            else None
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
