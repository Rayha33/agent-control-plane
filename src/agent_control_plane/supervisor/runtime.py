"""Runtime allocation, driver secrets and evidence, and runtime up/down/restart.

What stayed in git_supervisor, on purpose: `_run_driver_phase` calls `run_trusted`, and
tests/test_runtime_drivers.py monkeypatches `git_supervisor.run_trusted`. A copy of that
method here would import its own `run_trusted` and the patch would stop reaching it.

Moved verbatim out of `git_supervisor` (board #1630). `GitSupervisor` inherits this mixin, so
every call site, CLI path and `GitSupervisor.<name>` lookup resolves exactly as before.
"""

from __future__ import annotations

import errno
import fcntl
import hmac
import json
import os
import shutil
import socket
import sqlite3
import stat
import time
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ..credential_providers import CredentialHandle, CredentialRegistry
from ..runtime_drivers import DriverContext, DriverDefinition, PhaseEvidence
from .common import (
    PUBLIC_CHILD_ENV,
    SUPERVISOR_SECRET_ENV,
    SupervisorError,
    canonical_json,
    sha256,
    utc_now,
)


class RuntimeMixin:
    """Runtime port allocation, driver secrets and evidence, and runtime lifecycle."""

    @staticmethod
    def _port_available(port: int) -> bool:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
        finally:
            probe.close()
        return True

    def _allocate_runtime(
        self,
        connection: sqlite3.Connection,
        attempt_id: str,
        task_id: str,
        worktree: Path,
        expires: int,
        stamp: str,
    ) -> None:
        runtime_dir = self.state_dir / "runtime" / attempt_id
        log_path = self.state_dir / "logs" / f"runtime-{attempt_id}.log"
        environment = {
            "ACP_ATTEMPT_ID": attempt_id,
            "ACP_TASK_ID": task_id,
            "ACP_WORKTREE": str(worktree),
            "ACP_REPO_ROOT": str(self.root),
            "ACP_RUNTIME_DIR": str(runtime_dir),
        }
        for pool in self.config.runtime_port_pools:
            allocated = None
            for value in range(pool.start, pool.end + 1):
                held = connection.execute(
                    "SELECT 1 FROM runtime_allocations WHERE pool_name = ? AND value = ?",
                    (pool.env_name, value),
                ).fetchone()
                if not held and self._port_available(value):
                    allocated = value
                    break
            if allocated is None:
                raise SupervisorError(
                    "runtime_pool_exhausted",
                    f"no available value remains in runtime port pool {pool.env_name}",
                )
            connection.execute(
                """
                INSERT INTO runtime_allocations
                  (pool_name, value, attempt_id, lease_expires_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (pool.env_name, allocated, attempt_id, expires, stamp),
            )
            environment[pool.env_name] = str(allocated)
        connection.execute(
            """
            INSERT INTO runtime_environments
              (attempt_id, state, env_json, setup_results_json,
               teardown_results_json, log_path, updated_at)
            VALUES (?, 'allocated', ?, '[]', '[]', ?, ?)
            """,
            (attempt_id, canonical_json(environment), str(log_path), stamp),
        )
        self._event(
            connection,
            "runtime.allocated",
            "supervisor",
            {
                "attempt_id": attempt_id,
                "ports": {
                    pool.env_name: environment[pool.env_name]
                    for pool in self.config.runtime_port_pools
                },
            },
        )

    def runtime_environment(self, attempt_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM runtime_environments WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if not row:
                raise SupervisorError(
                    "runtime_not_found", f"attempt {attempt_id} has no runtime environment"
                )
            return self._runtime_view(connection, row)

    def _runtime_env(self, attempt_id: str, require_ready: bool = True) -> dict[str, str]:
        runtime = self.runtime_environment(attempt_id)
        if require_ready and runtime["state"] != "ready":
            raise SupervisorError(
                "runtime_not_ready",
                f"attempt runtime state is {runtime['state']}",
            )
        return runtime["environment"]

    def _run_runtime_commands(
        self,
        commands: Sequence[str],
        cwd: Path,
        environment: dict[str, str],
        log_path: Path,
        stop_on_failure: bool,
        pass_fds: Sequence[int] = (),
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        log_path.parent.mkdir(parents=True, exist_ok=True)
        for command in commands:
            result = self._run_command(command, cwd, environment, pass_fds=pass_fds)
            with log_path.open("a", encoding="utf-8") as log:
                log.write(json.dumps(result, sort_keys=True) + "\n")
            results.append(
                {
                    "command": command,
                    "exit_code": result["exit_code"],
                    "duration_ms": result["duration_ms"],
                }
            )
            if result["exit_code"] and stop_on_failure:
                break
        return results

    @staticmethod
    def _phase_runtime_env(environment: dict[str, str], phase: str, cwd: Path) -> dict[str, str]:
        return environment | {"ACP_PHASE": phase, "ACP_WORKTREE": str(cwd)}

    @staticmethod
    def _child_env(extra_env: dict[str, str] | None = None) -> dict[str, str]:
        """Build candidate/driver child env without ACP's own bearer secret."""
        env = {name: value for name, value in os.environ.items() if name in PUBLIC_CHILD_ENV}
        env.update(extra_env or {})
        env["GIT_ATTR_NOSYSTEM"] = "1"
        env["GIT_NO_REPLACE_OBJECTS"] = "1"
        for name in SUPERVISOR_SECRET_ENV:
            env.pop(name, None)
        return env

    def _driver_secret_read_only(self) -> bytes:
        """Read the driver HMAC key without migrating or creating state.

        Operator views call this path. A diagnostic command must not turn a
        missing key into a new key or perform the legacy meta-table migration;
        either mutation would make ``runtime-quarantine explain`` an unsafe
        recovery operation disguised as a read.
        """

        key_path = self.state_dir / "driver.key"
        if key_path.exists():
            flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            try:
                descriptor = os.open(key_path, flags)
            except OSError as error:
                raise SupervisorError(
                    "driver_key_unavailable", "driver key file is unavailable"
                ) from error
            try:
                info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or info.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
                ):
                    raise SupervisorError(
                        "driver_key_unsafe",
                        "driver key must be a current-user-owned 0600 regular file",
                    )
                value = os.read(descriptor, 33)
                if len(value) != 32:
                    raise SupervisorError(
                        "driver_key_invalid", "driver key must contain exactly 32 bytes"
                    )
                return value
            finally:
                os.close(descriptor)

        with self.connect() as connection:
            row = connection.execute(
                "SELECT value FROM meta WHERE key = 'driver_secret'"
            ).fetchone()
        if not row:
            raise SupervisorError("driver_key_unavailable", "driver key file is unavailable")
        try:
            value = bytes.fromhex(row["value"])
        except ValueError as error:
            raise SupervisorError("driver_key_invalid", "legacy driver key is invalid") from error
        if len(value) != 32:
            raise SupervisorError("driver_key_invalid", "legacy driver key is invalid")
        return value

    def _driver_secret(self) -> bytes:
        """Per-supervisor key stored separately from the SQLite evidence DB.

        Keeping the HMAC key in the same backup as keyed credential
        fingerprints would turn weak credential material into an offline
        guessing oracle. Older databases are migrated by writing their key to
        the protected file before deleting the meta row.
        """

        key_path = self.state_dir / "driver.key"

        def read_key() -> bytes:
            flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            try:
                fd = os.open(key_path, flags)
            except OSError as error:
                raise SupervisorError(
                    "driver_key_unavailable", "driver key file is unavailable"
                ) from error
            try:
                info = os.fstat(fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or info.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
                ):
                    raise SupervisorError(
                        "driver_key_unsafe",
                        "driver key must be a current-user-owned 0600 regular file",
                    )
                value = os.read(fd, 33)
                if len(value) != 32:
                    raise SupervisorError(
                        "driver_key_invalid", "driver key must contain exactly 32 bytes"
                    )
                return value
            finally:
                os.close(fd)

        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if key_path.exists():
                secret = read_key()
                connection.execute("DELETE FROM meta WHERE key = 'driver_secret'")
                return secret
            row = connection.execute(
                "SELECT value FROM meta WHERE key = 'driver_secret'"
            ).fetchone()
            try:
                secret = bytes.fromhex(row["value"]) if row else os.urandom(32)
            except ValueError as error:
                raise SupervisorError(
                    "driver_key_invalid", "legacy driver key is invalid"
                ) from error
            if len(secret) != 32:
                raise SupervisorError("driver_key_invalid", "legacy driver key is invalid")
            temporary = self.state_dir / f".driver-key-{uuid.uuid4().hex}.tmp"
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                fd = os.open(temporary, flags, 0o600)
                try:
                    os.fchmod(fd, 0o600)
                    written = os.write(fd, secret)
                    if written != len(secret):
                        raise OSError("short driver key write")
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.replace(temporary, key_path)
                directory_fd = os.open(self.state_dir, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError as error:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
                raise SupervisorError(
                    "driver_key_unavailable", "could not persist protected driver key"
                ) from error
            connection.execute("DELETE FROM meta WHERE key = 'driver_secret'")
            return secret

    def _driver_context(
        self,
        attempt_id: str,
        environment: dict[str, str],
        registry: CredentialRegistry | None = None,
        handles: dict[str, CredentialHandle] | None = None,
    ) -> DriverContext:
        attempt = self.attempt(attempt_id)
        runtime_dir = Path(environment["ACP_RUNTIME_DIR"])
        return DriverContext(
            attempt_id=attempt_id,
            task_id=str(attempt["task_id"]),
            runtime_dir=runtime_dir,
            expires_at=int(time.time()) + self.config.lease_seconds,
            secret=self._driver_secret(),
            environment=environment,
            credential_registry=registry,
            credential_handles=handles or {},
        )

    @staticmethod
    def _driver_definition_json(definition: DriverDefinition) -> str:
        return canonical_json(
            {
                "name": definition.name,
                "kind": definition.kind,
                "executable": str(definition.executable) if definition.executable else None,
                "options": dict(definition.options),
            }
        )

    @staticmethod
    def _driver_definition_from_json(value: str) -> DriverDefinition:
        raw = json.loads(value)
        return DriverDefinition(
            name=str(raw["name"]),
            kind=str(raw["kind"]),
            executable=Path(raw["executable"]) if raw.get("executable") else None,
            options={str(key): str(item) for key, item in raw.get("options", {}).items()},
        )

    def _stored_driver_rows(self, attempt_id: str) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return connection.execute(
                "SELECT * FROM runtime_driver_resources WHERE attempt_id = ? ORDER BY driver",
                (attempt_id,),
            ).fetchall()

    def _quarantine_driver_attempt(self, attempt_id: str, code: str) -> None:
        stamp = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE runtime_driver_resources SET state = 'quarantined', updated_at = ? "
                "WHERE attempt_id = ?",
                (stamp, attempt_id),
            )
            connection.execute(
                "UPDATE runtime_environments SET state = 'teardown_failed', updated_at = ? "
                "WHERE attempt_id = ?",
                (stamp, attempt_id),
            )
            self._event(
                connection,
                "runtime.driver.quarantined",
                "supervisor",
                {"attempt_id": attempt_id, "reason": code},
            )

    def _assert_driver_config_unchanged(self, attempt_id: str) -> None:
        rows = self._stored_driver_rows(attempt_id)
        if not rows:
            return
        pin = self._verify_attempt_trust(attempt_id)
        stored = {
            row["driver"]: row["definition_json"] for row in rows if row["definition_json"] != "{}"
        }
        current = {
            definition.name: self._driver_definition_json(definition)
            for definition in self._driver_definitions_for_pin(pin)
        }
        if stored == current:
            return
        stamp = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE runtime_driver_resources SET state = 'quarantined', updated_at = ? "
                "WHERE attempt_id = ?",
                (stamp, attempt_id),
            )
            self._event(
                connection,
                "runtime.driver.config_drift",
                "supervisor",
                {"attempt_id": attempt_id, "stored": sorted(stored), "current": sorted(current)},
            )
        raise SupervisorError(
            "runtime_driver_config_drift",
            "driver configuration changed after allocation; restore it before restart",
        )

    def _record_driver_setup_intent(
        self,
        attempt_id: str,
        definition: DriverDefinition,
        resource_id: str,
        capability: str,
        handle: CredentialHandle | None,
        expires_at: int,
        restart_token: str | None = None,
    ) -> None:
        """Persist exact cleanup identity before any external setup action."""

        stamp = utc_now()
        evidence = canonical_json(
            {
                "driver": definition.name,
                "kind": definition.kind,
                "phase": "setup",
                "resource_id": resource_id,
                "expires_at": expires_at,
                "exit_code": 1,
                "present": None,
                "proof": {"pending": True},
            }
        )
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._assert_restart_owner_in(connection, attempt_id, restart_token)
            connection.execute(
                """
                INSERT INTO runtime_driver_resources
                  (attempt_id, driver, kind, resource_id, ownership_token,
                   definition_json, credential_handle_json, expires_at, state,
                   evidence_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'setup_pending', ?, ?)
                ON CONFLICT(attempt_id, driver) DO UPDATE SET
                  kind = excluded.kind,
                  resource_id = excluded.resource_id,
                  ownership_token = excluded.ownership_token,
                  definition_json = excluded.definition_json,
                  credential_handle_json = excluded.credential_handle_json,
                  expires_at = excluded.expires_at,
                  state = excluded.state,
                  evidence_json = excluded.evidence_json,
                  updated_at = excluded.updated_at
                """,
                (
                    attempt_id,
                    definition.name,
                    definition.kind,
                    resource_id,
                    capability,
                    self._driver_definition_json(definition),
                    canonical_json(handle.as_internal_dict()) if handle else "{}",
                    expires_at,
                    evidence,
                    stamp,
                ),
            )
            self._event(
                connection,
                "runtime.driver.setup_pending",
                "supervisor",
                {
                    "attempt_id": attempt_id,
                    "driver": definition.name,
                    "kind": definition.kind,
                    "resource_id": resource_id,
                },
            )

    def _record_driver_evidence(
        self,
        attempt_id: str,
        phase: str,
        evidence: Sequence[PhaseEvidence],
        definitions: dict[str, DriverDefinition],
        restart_token: str | None = None,
    ) -> None:
        if not evidence:
            return
        stamp = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._assert_restart_owner_in(connection, attempt_id, restart_token)
            for item in evidence:
                if phase == "teardown":
                    state = "released" if item.proof.get("cleanup_proved") else "quarantined"
                elif phase == "setup":
                    state = "active" if item.ok else "setup_failed"
                else:
                    state = "active" if item.present else "absent"
                connection.execute(
                    """
                    INSERT INTO runtime_driver_resources
                      (attempt_id, driver, kind, resource_id, ownership_token,
                       definition_json, credential_handle_json, expires_at, state,
                       evidence_json, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(attempt_id, driver) DO UPDATE SET
                      kind = excluded.kind,
                      resource_id = excluded.resource_id,
                      ownership_token = excluded.ownership_token,
                      definition_json = excluded.definition_json,
                      credential_handle_json = CASE
                        WHEN excluded.credential_handle_json = '{}'
                        THEN runtime_driver_resources.credential_handle_json
                        ELSE excluded.credential_handle_json
                      END,
                      expires_at = excluded.expires_at,
                      state = excluded.state,
                      evidence_json = excluded.evidence_json,
                      updated_at = excluded.updated_at
                    """,
                    (
                        attempt_id,
                        item.driver,
                        item.kind,
                        item.resource_id,
                        item.ownership_token,
                        self._driver_definition_json(definitions[item.driver]),
                        canonical_json(item.credential_handle.as_internal_dict())
                        if item.credential_handle
                        else "{}",
                        item.expires_at,
                        state,
                        canonical_json(item.as_dict()),
                        stamp,
                    ),
                )
                self._event(
                    connection,
                    f"runtime.driver.{phase}",
                    "supervisor",
                    {
                        "attempt_id": attempt_id,
                        "driver": item.driver,
                        "kind": item.kind,
                        "resource_id": item.resource_id,
                        "state": state,
                        "exit_code": item.exit_code,
                        "present": item.present,
                        "cleanup_proved": item.proof.get("cleanup_proved"),
                    },
                )

    def driver_resources(self, attempt_id: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM runtime_driver_resources WHERE attempt_id = ? ORDER BY driver",
                (attempt_id,),
            ).fetchall()
        resources: list[dict[str, Any]] = []
        for row in rows:
            evidence = json.loads(row["evidence_json"])
            evidence.pop("ownership_token", None)
            resources.append(
                {
                    "driver": row["driver"],
                    "kind": row["kind"],
                    "resource_id": row["resource_id"],
                    "expires_at": row["expires_at"],
                    "state": row["state"],
                    "evidence": evidence,
                }
            )
        return resources

    def quarantined_resources(self) -> list[dict[str, Any]]:
        """Allocations whose cleanup could not be proven.

        These are deliberately NOT recycled: an unproven teardown is the case
        where something may still be running, so reuse is the one thing that
        must not happen automatically.
        """
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM runtime_driver_resources WHERE state = 'quarantined' "
                "ORDER BY updated_at"
            ).fetchall()
        resources: list[dict[str, Any]] = []
        for row in rows:
            evidence = json.loads(row["evidence_json"])
            evidence.pop("ownership_token", None)
            resources.append(
                {
                    "attempt_id": row["attempt_id"],
                    "driver": row["driver"],
                    "kind": row["kind"],
                    "resource_id": row["resource_id"],
                    "state": row["state"],
                    "evidence": evidence,
                }
            )
        return resources

    @staticmethod
    def _assert_restart_owner_in(
        connection: sqlite3.Connection,
        attempt_id: str,
        restart_token: str | None,
    ) -> None:
        if restart_token is None:
            return
        row = connection.execute(
            "SELECT state, restart_token FROM runtime_environments WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone()
        if (
            not row
            or row["state"] != "restarting"
            or not hmac.compare_digest(row["restart_token"], restart_token)
        ):
            raise SupervisorError("runtime_restart_stale", "restart generation is no longer active")

    def _assert_restart_owner(self, attempt_id: str, restart_token: str) -> None:
        with self.connect() as connection:
            self._assert_restart_owner_in(connection, attempt_id, restart_token)

    @contextmanager
    def _runtime_restart_guard(self, attempt_id: str, recover: bool) -> Iterator[int]:
        """Hold a kernel lifetime lock across every restart side effect.

        The trusted process monitor retains the descriptor and closes it in the
        command child before exec. If the supervisor dies during teardown, the
        kernel therefore keeps the lock until the monitor proves the command
        tree exited. The command can never inherit or unlock the fence.
        """

        lock_dir = self.state_dir / "restart-locks"
        lock_dir.mkdir(mode=0o700, exist_ok=True)
        lock_path = lock_dir / f"{sha256(attempt_id.encode())}.lock"
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            lock_fd = os.open(lock_path, flags, 0o600)
        except OSError as error:
            raise SupervisorError(
                "runtime_restart_lock_unavailable",
                "runtime restart lock could not be opened",
            ) from error
        try:
            opened = os.fstat(lock_fd)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
            ):
                raise SupervisorError(
                    "runtime_restart_lock_unsafe",
                    "runtime restart lock must be a current-user-owned 0600 regular file",
                )
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno not in {errno.EACCES, errno.EAGAIN}:
                    raise SupervisorError(
                        "runtime_restart_lock_unavailable",
                        "runtime restart lock could not be acquired",
                    ) from error
                code = (
                    "runtime_restart_executor_alive" if recover else "runtime_restart_in_progress"
                )
                raise SupervisorError(
                    code,
                    "runtime restart executor is still alive; recovery is unsafe",
                ) from error
            yield lock_fd
        finally:
            # Do not issue LOCK_UN: the trusted monitor may still hold the same
            # open-file description after an interrupted supervisor.
            os.close(lock_fd)

    @contextmanager
    def _task_operation_guard(self, task_id: str, recover: bool = False) -> Iterator[int]:
        """Serialize every QC/integration side effect for one task.

        The trusted monitor retains the descriptor but closes it in the command
        child before exec. A crashed supervisor therefore cannot make an
        expired reservation reusable while a command tree is still active, and
        candidate code cannot inherit or unlock the fence.
        """

        lock_dir = self.state_dir / "operation-locks"
        lock_dir.mkdir(mode=0o700, exist_ok=True)
        lock_path = lock_dir / f"{sha256(task_id.encode())}.lock"
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            lock_fd = os.open(lock_path, flags, 0o600)
        except OSError as error:
            raise SupervisorError(
                "task_operation_lock_unavailable",
                "task operation lock could not be opened",
            ) from error
        try:
            opened = os.fstat(lock_fd)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
            ):
                raise SupervisorError(
                    "task_operation_lock_unsafe",
                    "task operation lock must be a current-user-owned 0600 regular file",
                )
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno not in {errno.EACCES, errno.EAGAIN}:
                    raise SupervisorError(
                        "task_operation_lock_unavailable",
                        "task operation lock could not be acquired",
                    ) from error
                code = "task_operation_executor_alive" if recover else "task_operation_in_progress"
                raise SupervisorError(
                    code,
                    "another QC or integration operation for this task is still alive",
                ) from error
            yield lock_fd
        finally:
            # Closing our copy cannot drop a lock still retained by the monitor.
            os.close(lock_fd)

    def runtime_restart(self, attempt_id: str, recover: bool = False) -> dict[str, Any]:
        """Tear down and re-create driver resources between phases.

        QC must not be able to reach a service the worker left running: a stale
        app server can make a reviewer pass a candidate whose code never
        actually starts.
        """
        self._assert_driver_config_unchanged(attempt_id)
        if recover:
            now = int(time.time())
            with self.connect() as connection:
                runtime = connection.execute(
                    "SELECT state, restart_started_at FROM runtime_environments "
                    "WHERE attempt_id = ?",
                    (attempt_id,),
                ).fetchone()
            if not runtime:
                raise SupervisorError("runtime_not_found", "runtime environment is missing")
            if runtime["state"] != "restarting":
                raise SupervisorError(
                    "runtime_recovery_not_needed",
                    "runtime has no interrupted restart to recover",
                )
            if now - int(runtime["restart_started_at"]) < self.config.lease_seconds:
                raise SupervisorError(
                    "runtime_restart_not_stale",
                    "runtime restart is still within its recovery lease",
                )
        with self._runtime_restart_guard(attempt_id, recover) as guard_fd:
            return self._runtime_restart_locked(attempt_id, recover, guard_fd)

    def _runtime_restart_locked(
        self,
        attempt_id: str,
        recover: bool,
        guard_fd: int,
    ) -> dict[str, Any]:
        """Restart while holding the kernel guard returned above."""

        restart_token = uuid.uuid4().hex
        now = int(time.time())
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            runtime = connection.execute(
                "SELECT * FROM runtime_environments WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if not runtime:
                raise SupervisorError("runtime_not_found", "runtime environment is missing")
            recovering = runtime["state"] == "restarting"
            if recovering and not recover:
                raise SupervisorError(
                    "runtime_restart_in_progress",
                    "runtime restart is already in progress; use --recover only after its lease",
                )
            if recovering and now - int(runtime["restart_started_at"]) < self.config.lease_seconds:
                raise SupervisorError(
                    "runtime_restart_not_stale",
                    "runtime restart is still within its recovery lease",
                )
            if recover and not recovering:
                raise SupervisorError(
                    "runtime_recovery_not_needed",
                    "runtime has no interrupted restart to recover",
                )
            if runtime["state"] not in {"ready", "restarting"}:
                raise SupervisorError(
                    "runtime_not_ready",
                    f"runtime cannot restart from state {runtime['state']}",
                )
            connection.execute(
                "UPDATE runtime_environments "
                "SET state = 'restarting', restart_token = ?, restart_started_at = ?, updated_at = ? "
                "WHERE attempt_id = ?",
                (restart_token, now, utc_now(), attempt_id),
            )
            self._event(
                connection,
                "runtime.restart_started",
                "supervisor",
                {"attempt_id": attempt_id, "recovery": recovering},
            )
            environment = json.loads(runtime["env_json"])

        # A crash after cleanup proof but before setup must not require the old
        # credential again. Released rows are durable proof that teardown has
        # already completed; retry proceeds directly to current-version setup.
        rows = self._stored_driver_rows(attempt_id)
        teardown_names = {row["driver"] for row in rows if row["state"] != "released"}
        teardown = self._run_driver_phase(
            "teardown",
            attempt_id,
            environment,
            teardown_names,
            restart_token=restart_token,
            restart_guard_fd=guard_fd,
        )
        self._assert_restart_owner(attempt_id, restart_token)
        unproven = [item for item in teardown if not item.proof.get("cleanup_proved")]
        if unproven:
            with self.connect() as connection:
                updated = connection.execute(
                    "UPDATE runtime_environments SET state = 'teardown_failed', updated_at = ? "
                    "WHERE attempt_id = ? AND state = 'restarting' AND restart_token = ?",
                    (utc_now(), attempt_id, restart_token),
                )
                if updated.rowcount != 1:
                    raise SupervisorError(
                        "runtime_restart_stale", "restart generation lost during teardown"
                    )
            raise SupervisorError(
                "runtime_cleanup_unproven",
                "cannot restart runtime: cleanup proof missing for "
                + ", ".join(sorted(item.driver for item in unproven)),
            )
        setup = self._run_driver_phase(
            "setup",
            attempt_id,
            environment,
            restart_token=restart_token,
            restart_guard_fd=guard_fd,
        )
        self._assert_restart_owner(attempt_id, restart_token)
        failed = [item for item in setup if not item.ok]
        if failed:
            with self.connect() as connection:
                updated = connection.execute(
                    "UPDATE runtime_environments SET state = 'setup_failed', updated_at = ? "
                    "WHERE attempt_id = ? AND state = 'restarting' AND restart_token = ?",
                    (utc_now(), attempt_id, restart_token),
                )
                if updated.rowcount != 1:
                    raise SupervisorError(
                        "runtime_restart_stale", "restart generation lost during setup"
                    )
            raise SupervisorError(
                "runtime_setup_failed",
                "driver setup failed for " + ", ".join(sorted(item.driver for item in failed)),
            )
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                "UPDATE runtime_environments "
                "SET state = 'ready', restart_token = '', restart_started_at = 0, updated_at = ? "
                "WHERE attempt_id = ? AND state = 'restarting' AND restart_token = ?",
                (utc_now(), attempt_id, restart_token),
            )
            if updated.rowcount != 1:
                raise SupervisorError(
                    "runtime_restart_stale", "restart generation lost before completion"
                )
            self._event(
                connection,
                "runtime.restart_completed",
                "supervisor",
                {"attempt_id": attempt_id, "drivers": [item.driver for item in setup]},
            )
        return {
            "attempt_id": attempt_id,
            "restarted": [item.driver for item in setup],
            "resources": self.driver_resources(attempt_id),
        }

    def _runtime_up(self, attempt_id: str) -> dict[str, Any]:
        with self._runtime_restart_guard(attempt_id, recover=False) as guard_fd:
            return self._runtime_up_locked(attempt_id, guard_fd)

    def _runtime_up_locked(self, attempt_id: str, guard_fd: int) -> dict[str, Any]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM runtime_environments WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if not row:
                raise SupervisorError("runtime_not_found", "runtime allocation is missing")
            if row["state"] != "allocated":
                raise SupervisorError(
                    "runtime_not_ready", f"runtime cannot start from state {row['state']}"
                )
            connection.execute(
                "UPDATE runtime_environments SET state = 'setting_up', updated_at = ? "
                "WHERE attempt_id = ?",
                (utc_now(), attempt_id),
            )
            self._event(
                connection,
                "runtime.setup_started",
                "supervisor",
                {"attempt_id": attempt_id},
            )
        attempt = self.attempt(attempt_id)
        environment = json.loads(row["env_json"])
        runtime_dir = Path(environment["ACP_RUNTIME_DIR"])
        runtime_dir.mkdir(parents=True, exist_ok=True)
        results = self._run_runtime_commands(
            self.config.runtime_setup_commands,
            Path(attempt["worktree"]),
            self._phase_runtime_env(environment, "setup", Path(attempt["worktree"])),
            Path(row["log_path"]),
            stop_on_failure=True,
            pass_fds=(guard_fd,),
        )
        failed = any(result["exit_code"] for result in results)
        if not failed:
            driver_evidence = self._run_driver_phase(
                "setup",
                attempt_id,
                environment,
                restart_guard_fd=guard_fd,
            )
            failed = any(not item.ok for item in driver_evidence)
            results = results + [
                {
                    "command": f"driver:{item.driver}:setup",
                    "exit_code": item.exit_code,
                    "duration_ms": 0,
                }
                for item in driver_evidence
            ]
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            state = "setup_failed" if failed else "ready"
            connection.execute(
                """
                UPDATE runtime_environments
                SET state = ?, setup_results_json = ?, updated_at = ?
                WHERE attempt_id = ?
                """,
                (state, canonical_json(results), utc_now(), attempt_id),
            )
            self._event(
                connection,
                "runtime.setup_failed" if failed else "runtime.ready",
                "supervisor",
                {"attempt_id": attempt_id, "results": results},
            )
        if failed:
            raise SupervisorError(
                "runtime_setup_failed",
                f"runtime setup failed; log: {row['log_path']}",
            )
        return self.runtime_environment(attempt_id)

    def _abandon_runtime(self, attempt_id: str) -> None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT state FROM runtime_environments WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if not row or row["state"] == "released":
                return
            stamp = utc_now()
            connection.execute(
                "DELETE FROM runtime_allocations WHERE attempt_id = ?", (attempt_id,)
            )
            connection.execute(
                "UPDATE runtime_environments SET state = 'released', updated_at = ? "
                "WHERE attempt_id = ?",
                (stamp, attempt_id),
            )
            self._event(
                connection,
                "runtime.released",
                "supervisor",
                {"attempt_id": attempt_id, "reason": "provision_abandoned"},
            )

    def runtime_down(
        self,
        attempt_id: str,
        force: bool = False,
        _allow_active: bool = False,
    ) -> dict[str, Any]:
        with self._runtime_restart_guard(attempt_id, recover=False) as guard_fd:
            return self._runtime_down_locked(attempt_id, force, _allow_active, guard_fd)

    def _runtime_down_locked(
        self,
        attempt_id: str,
        force: bool,
        _allow_active: bool,
        guard_fd: int,
    ) -> dict[str, Any]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM runtime_environments WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if not row:
                raise SupervisorError("runtime_not_found", "runtime environment is missing")
            if row["state"] == "released":
                return self._runtime_view(connection, row)
            if row["recovery_action"]:
                raise SupervisorError(
                    "runtime_quarantine_recovery_in_progress",
                    "an interrupted quarantine recovery must be resumed through runtime-quarantine",
                )
            task = connection.execute(
                """
                SELECT task.status FROM tasks AS task
                JOIN attempts AS attempt ON attempt.task_id = task.id
                WHERE attempt.id = ?
                """,
                (attempt_id,),
            ).fetchone()
            active_states = {"provisioning", "working", "qc_review", "approved", "integrating"}
            if task and task["status"] in active_states and not _allow_active:
                raise SupervisorError(
                    "runtime_in_use",
                    f"runtime is still required while task status is {task['status']}",
                )
            if row["state"] == "tearing_down" and not force:
                raise SupervisorError(
                    "runtime_cleanup_in_progress",
                    "runtime cleanup is already in progress; use force only after a crashed cleanup",
                )
            connection.execute(
                "UPDATE runtime_environments SET state = 'tearing_down', updated_at = ? "
                "WHERE attempt_id = ?",
                (utc_now(), attempt_id),
            )
            self._event(
                connection,
                "runtime.teardown_started",
                "supervisor",
                {"attempt_id": attempt_id, "force": force},
            )
            environment = json.loads(row["env_json"])
        attempt = self.attempt(attempt_id)
        worktree = Path(attempt["worktree"])
        cwd = worktree if worktree.is_dir() else self.root
        results = self._run_runtime_commands(
            self.config.runtime_teardown_commands,
            cwd,
            self._phase_runtime_env(environment, "teardown", cwd),
            Path(row["log_path"]),
            stop_on_failure=False,
            pass_fds=(guard_fd,),
        )
        # Drivers tear down AFTER the shell hooks and are then independently
        # re-probed. A hook that exits 0 proves only that a process exited 0.
        driver_evidence = self._run_driver_phase(
            "teardown",
            attempt_id,
            environment,
            restart_guard_fd=guard_fd,
        )
        unproven = [item.driver for item in driver_evidence if not item.proof.get("cleanup_proved")]
        results = results + [
            {
                "command": f"driver:{item.driver}:teardown",
                "exit_code": item.exit_code,
                "duration_ms": 0,
                "cleanup_proved": bool(item.proof.get("cleanup_proved")),
            }
            for item in driver_evidence
        ]
        with self.connect() as connection:
            allocations = connection.execute(
                "SELECT pool_name, value FROM runtime_allocations "
                "WHERE attempt_id = ? ORDER BY pool_name",
                (attempt_id,),
            ).fetchall()
        occupied = [
            f"{allocation['pool_name']}={allocation['value']}"
            for allocation in allocations
            if not self._port_available(allocation["value"])
        ]
        # Missing cleanup proof quarantines the allocation: the ports are NOT
        # returned to the pool, so nothing is handed to a later attempt while a
        # resource from this one may still be alive.
        failed = any(result["exit_code"] for result in results) or bool(occupied) or bool(unproven)
        staging_failed = False
        if not failed:
            try:
                shutil.rmtree(environment["ACP_RUNTIME_DIR"])
            except FileNotFoundError:
                pass
            except OSError:
                staging_failed = True
                failed = True
                results.append(
                    {
                        "command": "runtime-staging:remove",
                        "exit_code": 1,
                        "duration_ms": 0,
                    }
                )
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            stamp = utc_now()
            state = "teardown_failed" if failed else "released"
            connection.execute(
                """
                UPDATE runtime_environments
                SET state = ?, teardown_results_json = ?, recovery_action = ?, updated_at = ?
                WHERE attempt_id = ?
                """,
                (
                    state,
                    canonical_json(results),
                    "retry-cleanup" if staging_failed else "",
                    stamp,
                    attempt_id,
                ),
            )
            if not failed:
                connection.execute(
                    "DELETE FROM runtime_allocations WHERE attempt_id = ?", (attempt_id,)
                )
            self._event(
                connection,
                "runtime.teardown_failed" if failed else "runtime.released",
                "supervisor",
                {
                    "attempt_id": attempt_id,
                    "results": results,
                    "occupied": occupied,
                    "unproven_cleanup": unproven,
                },
            )
        return self.runtime_environment(attempt_id)
