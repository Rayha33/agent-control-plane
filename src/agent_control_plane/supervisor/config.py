"""Loading and validating `.acp/config.toml`, and the trust pins an attempt is held to.

Moved verbatim out of `git_supervisor` (board #1630). `GitSupervisor` inherits this mixin, so
every call site, CLI path and `GitSupervisor.<name>` lookup resolves exactly as before.
"""

from __future__ import annotations

import json
import re
import sqlite3
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..assurance import load_policy
from ..credential_providers import (
    CredentialDefinition,
    CredentialError,
    parse_credential_definitions,
)
from ..runtime_drivers import (
    DriverDefinition,
    DriverError,
    parse_driver_definitions,
    resolve_trusted_executable,
)
from ..trust_bundles import (
    TrustBundleError,
    executable_from_pin,
    load_current_bundle,
    verify_bundle_pin,
)
from .common import RuntimePortPool, SupervisorError, utc_now


@dataclass(frozen=True)
class Config:
    lease_seconds: int
    timeout_seconds: int
    qc_commands: tuple[str, ...]
    integration_commands: tuple[str, ...]
    critic_command: str
    critic_identity: str
    require_critic: bool
    runtime_setup_commands: tuple[str, ...]
    runtime_teardown_commands: tuple[str, ...]
    runtime_port_pools: tuple[RuntimePortPool, ...]
    credentials: tuple[CredentialDefinition, ...]
    runtime_drivers: tuple[DriverDefinition, ...]
    runtime_driver_entries: tuple[dict[str, Any], ...]
    critic_selector: str
    trust_root: Path | None
    trust_owner_uid: int


class ConfigMixin:
    """Config loading and validation, the critic command, and per-attempt trust pins."""

    def _resolve_critic_command(
        self, critic_command: str, trust_pin: dict[str, Any] | None = None
    ) -> str:
        """Every reviewer command obeys the same rule: `builtin`, or one absolute
        executable outside the candidate worktree so a candidate cannot replace it."""
        if not critic_command or critic_command == "builtin":
            return critic_command
        if critic_command.startswith("trusted:"):
            if trust_pin is None:
                raise SupervisorError(
                    "invalid_config", "trusted: commands require a configured trust bundle"
                )
            name = critic_command.removeprefix("trusted:")
            try:
                return str(executable_from_pin(trust_pin, name))
            except TrustBundleError as error:
                raise SupervisorError(error.code, error.message) from error
        critic_path = Path(critic_command).expanduser()
        if not critic_path.is_absolute():
            raise SupervisorError(
                "invalid_config",
                "external critic_command must be one absolute executable path",
            )
        try:
            critic_path = critic_path.resolve(strict=True)
        except FileNotFoundError as error:
            raise SupervisorError(
                "invalid_config", "external critic executable does not exist"
            ) from error
        try:
            critic_path.relative_to(self.root)
        except ValueError:
            pass
        else:
            raise SupervisorError(
                "invalid_config",
                "external critic executable must be outside the repository",
            )
        try:
            return str(resolve_trusted_executable(str(critic_path), self.root))
        except DriverError as error:
            raise SupervisorError(error.code, error.message) from error

    def _load_config(self) -> Config:
        with self.config_path.open("rb") as handle:
            raw = tomllib.load(handle)
        supervisor = raw.get("supervisor", {})
        qc = raw.get("qc", {})
        integration = raw.get("integration", {})
        runtime = raw.get("runtime", {})
        trust = raw.get("trust")
        if trust is not None and not isinstance(trust, dict):
            raise SupervisorError("invalid_config", "trust must be a table")
        trust_root: Path | None = None
        trust_owner_uid = 0
        trust_pin: dict[str, Any] | None = None
        if trust is not None:
            root_value = str(trust.get("root", "")).strip()
            if not root_value:
                raise SupervisorError("invalid_config", "trust.root must be an absolute path")
            trust_root = Path(root_value).expanduser()
            if not trust_root.is_absolute():
                raise SupervisorError("invalid_config", "trust.root must be an absolute path")
            trust_owner_uid = int(trust.get("owner_uid", 0))
            try:
                trust_pin = load_current_bundle(trust_root, owner_uid=trust_owner_uid)
            except TrustBundleError as error:
                if not self._diagnostic:
                    raise SupervisorError(error.code, error.message) from error
                self._trust_config_error = f"{error.code}: {error.message}"
        lease = int(supervisor.get("lease_seconds", 300))
        timeout = int(supervisor.get("qc_timeout_seconds", 900))
        if lease < 10 or timeout < 1:
            raise SupervisorError("invalid_config", "lease must be >= 10 and timeout >= 1")
        qc_commands = tuple(map(str, qc.get("commands", [])))
        integration_commands = tuple(map(str, integration.get("commands", qc.get("commands", []))))
        critic_selector = str(qc.get("critic_command", "")).strip()
        require_critic = bool(supervisor.get("require_critic", False))
        if not qc_commands or any(not command.strip() for command in qc_commands):
            raise SupervisorError(
                "invalid_config",
                "every deterministic QC gate must contain a command",
            )
        if not integration_commands or any(not command.strip() for command in integration_commands):
            raise SupervisorError("invalid_config", "every integration gate must contain a command")
        if require_critic and not critic_selector:
            raise SupervisorError(
                "invalid_config", "require_critic needs a non-empty critic_command"
            )
        if self._diagnostic and trust_pin is None and critic_selector.startswith("trusted:"):
            critic_command = critic_selector
        else:
            critic_command = self._resolve_critic_command(critic_selector, trust_pin)
        runtime_setup_commands = tuple(map(str, runtime.get("setup_commands", [])))
        runtime_teardown_commands = tuple(map(str, runtime.get("teardown_commands", [])))
        raw_credentials = raw.get("credentials", [])
        if not isinstance(raw_credentials, list):
            raise SupervisorError("invalid_config", "credentials must be an array of tables")
        try:
            credentials = parse_credential_definitions(raw_credentials, self.root)
        except CredentialError as error:
            raise SupervisorError(error.code, error.message) from error
        # Drivers are validated here, against the supervisor's OWN acp.toml at the
        # repository root — never a copy inside a candidate worktree.
        raw_drivers = runtime.get("drivers", [])
        if not isinstance(raw_drivers, list):
            raise SupervisorError("invalid_config", "runtime.drivers must be an array of tables")
        if any(not isinstance(entry, dict) for entry in raw_drivers):
            raise SupervisorError("invalid_config", "each runtime driver must be a table")
        driver_entries = tuple(dict(entry) for entry in raw_drivers)
        resolved_driver_entries: list[dict[str, Any]] = []
        for entry in driver_entries:
            resolved = dict(entry)
            executable = str(resolved.get("executable", ""))
            if executable.startswith("trusted:") and not (self._diagnostic and trust_pin is None):
                resolved["executable"] = self._resolve_critic_command(executable, trust_pin)
            resolved_driver_entries.append(resolved)
        if (
            self._diagnostic
            and trust_pin is None
            and any(
                str(entry.get("executable", "")).startswith("trusted:") for entry in driver_entries
            )
        ):
            runtime_drivers = ()
        else:
            try:
                runtime_drivers = parse_driver_definitions(
                    resolved_driver_entries,
                    self.root,
                    credential_names={item.name for item in credentials},
                    expected_owners={0, trust_owner_uid} if trust_pin else None,
                )
            except DriverError as error:
                raise SupervisorError(error.code, error.message) from error
        for label, commands in (
            ("runtime setup", runtime_setup_commands),
            ("runtime teardown", runtime_teardown_commands),
        ):
            if any(not command.strip() for command in commands):
                raise SupervisorError(
                    "invalid_config", f"every {label} command must contain a command"
                )
        raw_ports = runtime.get("ports", {})
        if not isinstance(raw_ports, dict):
            raise SupervisorError("invalid_config", "runtime.ports must be a table")
        reserved_env = {
            "ACP_ATTEMPT_ID",
            "ACP_TASK_ID",
            "ACP_WORKTREE",
            "ACP_REPO_ROOT",
            "ACP_RUNTIME_DIR",
            "ACP_PHASE",
            "PATH",
            "HOME",
            "SHELL",
            "USER",
            "LOGNAME",
            "PWD",
            "OLDPWD",
            "TMPDIR",
            "PYTHONPATH",
            "VIRTUAL_ENV",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "SSH_AUTH_SOCK",
        }
        runtime_port_pools: list[RuntimePortPool] = []
        for env_name, bounds in sorted(raw_ports.items()):
            if (
                not re.fullmatch(r"[A-Z_][A-Z0-9_]*", env_name)
                or env_name in reserved_env
                or env_name.startswith("ACP_")
            ):
                raise SupervisorError(
                    "invalid_config",
                    f"runtime port name {env_name!r} is not a safe environment variable",
                )
            if (
                not isinstance(bounds, list)
                or len(bounds) != 2
                or any(isinstance(value, bool) or not isinstance(value, int) for value in bounds)
            ):
                raise SupervisorError(
                    "invalid_config", f"runtime port pool {env_name} must be [start, end]"
                )
            start, end = bounds
            if start < 1024 or end > 65535 or start > end:
                raise SupervisorError(
                    "invalid_config",
                    f"runtime port pool {env_name} must stay within 1024..65535",
                )
            runtime_port_pools.append(RuntimePortPool(env_name, start, end))
        for index, pool in enumerate(runtime_port_pools):
            for other in runtime_port_pools[:index]:
                if max(pool.start, other.start) <= min(pool.end, other.end):
                    raise SupervisorError(
                        "invalid_config",
                        f"runtime port pools {other.env_name} and {pool.env_name} overlap",
                    )
        # Loaded here so a reviewer's command obeys the same trust rule as the
        # legacy single critic, and so a bad policy fails at construction.
        policy = load_policy(
            raw, str(supervisor.get("critic_identity", "")).strip(), critic_selector
        )
        # Validate every declared command now, but retain its logical selector
        # in policy provenance. A safe bundle rotation must not silently mutate
        # the reviewer-policy fingerprint.
        for reviewer in policy.reviewers:
            if not (
                self._diagnostic and trust_pin is None and reviewer.command.startswith("trusted:")
            ):
                self._resolve_critic_command(reviewer.command, trust_pin)
        self.assurance_policy = policy
        return Config(
            lease_seconds=lease,
            timeout_seconds=timeout,
            qc_commands=qc_commands,
            integration_commands=integration_commands,
            critic_command=critic_command,
            critic_identity=str(supervisor.get("critic_identity", "independent-qc")),
            require_critic=require_critic,
            runtime_setup_commands=runtime_setup_commands,
            runtime_teardown_commands=runtime_teardown_commands,
            runtime_port_pools=tuple(runtime_port_pools),
            credentials=credentials,
            runtime_drivers=runtime_drivers,
            runtime_driver_entries=driver_entries,
            critic_selector=critic_selector,
            trust_root=trust_root,
            trust_owner_uid=trust_owner_uid,
        )

    def _current_trust_pin(self) -> dict[str, Any]:
        if self.config.trust_root is None:
            return {}
        try:
            return load_current_bundle(
                self.config.trust_root, owner_uid=self.config.trust_owner_uid
            )
        except TrustBundleError as error:
            raise SupervisorError(error.code, error.message) from error

    def _driver_definitions_for_pin(
        self, pin: dict[str, Any] | None
    ) -> tuple[DriverDefinition, ...]:
        entries: list[dict[str, Any]] = []
        for configured in self.config.runtime_driver_entries:
            entry = dict(configured)
            selector = str(entry.get("executable", ""))
            if selector.startswith("trusted:"):
                entry["executable"] = self._resolve_critic_command(selector, pin)
            entries.append(entry)
        try:
            return parse_driver_definitions(
                entries,
                self.root,
                credential_names={item.name for item in self.config.credentials},
                expected_owners={0, self.config.trust_owner_uid} if pin else None,
            )
        except DriverError as error:
            raise SupervisorError(error.code, error.message) from error

    def _attempt_trust_pin(self, attempt_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT trust_bundle_json FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
        if not row:
            raise SupervisorError("attempt_not_found", f"attempt {attempt_id} not found")
        try:
            value = json.loads(row["trust_bundle_json"] or "{}")
        except (json.JSONDecodeError, TypeError) as error:
            self._quarantine_trust_attempt(attempt_id, ["stored trust pin is invalid JSON"])
            raise SupervisorError(
                "trust_bundle_invalid", "stored trust pin is invalid JSON"
            ) from error
        if not isinstance(value, dict):
            self._quarantine_trust_attempt(attempt_id, ["stored trust pin is not an object"])
            raise SupervisorError("trust_bundle_invalid", "stored trust pin is not an object")
        return value

    def _quarantine_trust_attempt(self, attempt_id: str, errors: Sequence[str]) -> None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._quarantine_trust_attempt_in(connection, attempt_id, errors)

    def _quarantine_trust_attempt_in(
        self,
        connection: sqlite3.Connection,
        attempt_id: str,
        errors: Sequence[str],
    ) -> None:
        """Quarantine a pin inside the caller's finalization transaction."""

        stamp = utc_now()
        attempt = connection.execute(
            "SELECT task_id, status, pid, pid_identity, termination_target_status "
            "FROM attempts WHERE id = ?",
            (attempt_id,),
        ).fetchone()
        if not attempt:
            return
        worker_slot_fenced = attempt["pid"] is not None
        if worker_slot_fenced:
            # A registered PID is evidence, not disposable metadata. Keep the
            # exact kernel identity and let the reaper prove it gone before the
            # attempt reaches its terminal quarantine state. This also retains
            # pid=-1 launch reservations until the blocked monitor either
            # registers its real PID or observes the closed handshake.
            connection.execute(
                "UPDATE attempts SET status = 'terminating', "
                "termination_target_status = 'quarantined', updated_at = ? "
                "WHERE id = ?",
                (stamp, attempt_id),
            )
        else:
            connection.execute(
                "UPDATE attempts SET status = 'quarantined', pid = NULL, "
                "pid_identity = '', termination_target_status = '', termination_proof = '', "
                "launch_owner_pid = NULL, launch_owner_identity = '', updated_at = ? WHERE id = ?",
                (stamp, attempt_id),
            )
        self._fence_task_cleanup(
            connection,
            attempt["task_id"],
            attempt_id,
            "blocked",
            "supervisor",
            "trust_bundle_quarantined",
        )
        connection.execute(
            "UPDATE tasks SET cleanup_error = ?, updated_at = ? WHERE id = ?",
            ("trust bundle invalid: " + "; ".join(errors), stamp, attempt["task_id"]),
        )
        connection.execute(
            "UPDATE submissions SET status = 'blocked', qc_resume_status = '' "
            "WHERE task_id = ? AND status = 'qc_running'",
            (attempt["task_id"],),
        )
        connection.execute(
            "UPDATE runtime_environments SET state = 'teardown_failed', updated_at = ? "
            "WHERE attempt_id = ?",
            (stamp, attempt_id),
        )
        connection.execute(
            "UPDATE runtime_driver_resources SET state = 'quarantined', updated_at = ? "
            "WHERE attempt_id = ?",
            (stamp, attempt_id),
        )
        self._event(
            connection,
            "trust_bundle.quarantined",
            "supervisor",
            {
                "attempt_id": attempt_id,
                "errors": list(errors),
                "worker_slot_fenced": worker_slot_fenced,
                "worker_pid": attempt["pid"],
                "worker_identity_retained": bool(attempt["pid_identity"]),
            },
        )

    def _verify_attempt_trust_in(
        self,
        connection: sqlite3.Connection,
        attempt_id: str,
    ) -> dict[str, Any]:
        """Verify the exact pin while fencing a final state transition."""

        row = connection.execute(
            "SELECT trust_bundle_json FROM attempts WHERE id = ?", (attempt_id,)
        ).fetchone()
        if not row:
            raise SupervisorError("attempt_not_found", f"attempt {attempt_id} not found")
        try:
            pin = json.loads(row["trust_bundle_json"] or "{}")
        except (json.JSONDecodeError, TypeError) as error:
            errors = ["stored trust pin is invalid JSON"]
            self._quarantine_trust_attempt_in(connection, attempt_id, errors)
            raise SupervisorError("trust_bundle_invalid", errors[0]) from error
        if not isinstance(pin, dict):
            errors = ["stored trust pin is not an object"]
            self._quarantine_trust_attempt_in(connection, attempt_id, errors)
            raise SupervisorError("trust_bundle_invalid", errors[0])
        if not pin:
            if self.config.trust_root is not None:
                errors = ["attempt has no trust pin; refusing to adopt the current bundle"]
                self._quarantine_trust_attempt_in(connection, attempt_id, errors)
                raise SupervisorError("trust_bundle_quarantined", errors[0])
            return {}
        result = verify_bundle_pin(pin)
        if result["ok"]:
            return pin
        self._quarantine_trust_attempt_in(connection, attempt_id, result["errors"])
        raise SupervisorError(
            "trust_bundle_quarantined",
            "pinned trust bundle failed: " + "; ".join(result["errors"]),
        )

    def _verify_attempt_trust(self, attempt_id: str) -> dict[str, Any]:
        pin = self._attempt_trust_pin(attempt_id)
        if not pin:
            if self.config.trust_root is not None:
                errors = ["attempt has no trust pin; refusing to adopt the current bundle"]
                self._quarantine_trust_attempt(attempt_id, errors)
                raise SupervisorError("trust_bundle_quarantined", errors[0])
            return {}
        result = verify_bundle_pin(pin)
        if result["ok"]:
            return pin
        self._quarantine_trust_attempt(attempt_id, result["errors"])
        raise SupervisorError(
            "trust_bundle_quarantined",
            "pinned trust bundle failed: " + "; ".join(result["errors"]),
        )
