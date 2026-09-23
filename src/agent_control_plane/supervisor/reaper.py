"""Expiry and cleanup: reap_expired, two-phase task cleanup, garbage collection, and
quarantine explain/recover.

Moved verbatim out of `git_supervisor` (board #1630). `GitSupervisor` inherits this mixin, so
every call site, CLI path and `GitSupervisor.<name>` lookup resolves exactly as before.
"""

from __future__ import annotations

import hmac
import json
import shutil
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Any

from ..runner_identity import verify_credential
from ..runtime_drivers import DriverError, ownership_token
from ..status import ACTIVE_STATUSES, LIVE_ATTEMPT_STATUSES, _age_seconds
from ..trust_bundles import TrustBundleError, verify_bundle_pin
from .common import (
    CLEANUP_FENCE_EPOCH,
    DEFAULT_GC_RETENTION_SECONDS,
    GC_RECLAIMABLE_TASK_STATUSES,
    SupervisorError,
    utc_now,
)


class ReaperMixin:
    """Lease expiry, two-phase cleanup, worktree GC and quarantine recovery."""

    # ------------------------------------------------------------------ #
    # Quarantine explain / recover (#740)
    #
    # Quarantine is deliberately fail-closed: an unproven teardown parks the
    # allocation rather than recycling it. That is correct, and it was also a
    # dead end — reading WHY a resource was parked, or getting it out, needed
    # someone to open the SQLite file by hand. These two entry points are the
    # supported path, and they keep every guarantee the fail-closed design
    # exists to provide:
    #
    #   * explain NEVER exposes an ownership token or credential material. The
    #     token is the capability that authorises teardown of a real resource;
    #     an operator diagnosing a stuck row has no need of it.
    #   * recover NEVER rewrites immutable allocation identity. attempt_id,
    #     driver, kind, resource_id and ownership_token are what bind a row to
    #     the thing it allocated; rewriting any of them to make a mismatch go
    #     away would forge exactly the proof the mismatch is reporting.
    #   * recover NEVER releases an allocation on an assertion. A port returns
    #     to the pool only against a POSITIVE ABSENCE PROOF — the driver's own
    #     verify phase reporting present=False, or the port failing to accept a
    #     bind. An operator receipt is authenticated and recorded, but it is
    #     testimony, not proof, and it cannot release anything on its own.
    # ------------------------------------------------------------------ #

    _QUARANTINE_ACTIONS: tuple[str, ...] = (
        "restore-definition",
        "retry-cleanup",
        "manual-receipt",
    )

    @staticmethod
    def _public_evidence(raw: str) -> dict[str, Any]:
        """Evidence with every capability and secret stripped.

        Redaction is by ALLOW-list on the nested credential handle and by
        explicit removal of the token, because evidence is driver-authored: a
        deny-list would silently start leaking the day a driver adds a field.
        """

        try:
            evidence = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            return {"unreadable": True}
        if not isinstance(evidence, dict):
            return {"unreadable": True}
        evidence.pop("ownership_token", None)
        handle = evidence.get("credential_handle")
        if isinstance(handle, dict):
            evidence["credential_handle"] = {
                key: handle[key] for key in ("name", "version") if key in handle
            }
        return evidence

    def _identity_proved(self, row: sqlite3.Row) -> bool:
        """Does this row still prove it owns the resource it names?

        Recomputes the HMAC over the immutable triple. A legacy or corrupted
        row whose token still verifies is provably the same allocation and may
        be migrated; one whose token does not verify is NOT, and no amount of
        operator intent can make it so.
        """

        stored = row["ownership_token"] or ""
        if not stored:
            return False
        try:
            secret = self._driver_secret_read_only()
        except SupervisorError:
            return False
        expected = ownership_token(secret, row["attempt_id"], row["kind"], row["resource_id"])
        return hmac.compare_digest(stored, expected)

    def _pinned_definitions(self, attempt_id: str) -> tuple[dict[str, str], str | None]:
        """Current pinned definition JSON by driver name, or why it is unavailable.

        Never raises: explain must keep working on exactly the broken attempts
        it exists to describe, including ones whose trust pin no longer
        verifies.
        """

        with self.connect() as connection:
            row = connection.execute(
                "SELECT trust_bundle_json FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
        if not row:
            return {}, "attempt_not_found"
        try:
            pin = json.loads(row["trust_bundle_json"] or "{}")
        except (json.JSONDecodeError, TypeError):
            return {}, "trust_bundle_invalid"
        if not isinstance(pin, dict):
            return {}, "trust_bundle_invalid"
        if not pin and self.config.trust_root is not None:
            return {}, "trust_bundle_quarantined"
        if pin:
            try:
                verified = verify_bundle_pin(pin)
            except TrustBundleError as error:
                return {}, error.code
            if not verified["ok"]:
                return {}, "trust_bundle_quarantined"
        try:
            return {
                definition.name: self._driver_definition_json(definition)
                for definition in self._driver_definitions_for_pin(pin)
            }, None
        except (SupervisorError, TrustBundleError) as error:
            return {}, error.code

    def _mismatch_class(
        self, row: sqlite3.Row, pinned: dict[str, str], pin_error: str | None
    ) -> str:
        stored_definition = row["definition_json"]
        if stored_definition == "{}":
            return "definition_missing"
        try:
            self._driver_definition_from_json(stored_definition)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return "definition_corrupt"
        if pin_error:
            return "trust_pin_unavailable"
        current = pinned.get(row["driver"])
        if current is None:
            return "driver_removed_from_config"
        if current != stored_definition:
            return "config_drift"
        evidence = self._public_evidence(row["evidence_json"])
        proof = evidence.get("proof")
        if isinstance(proof, dict) and not proof.get("cleanup_proved"):
            return "cleanup_unproven"
        if evidence.get("present"):
            return "resource_still_present"
        return "unclassified"

    @staticmethod
    def _quarantine_severity(mismatch: str, evidence: dict[str, Any]) -> str:
        """Severity is about what may still be RUNNING, not about tidiness."""

        if evidence.get("present"):
            return "critical"
        if mismatch in {"cleanup_unproven", "resource_still_present"}:
            return "critical"
        if mismatch in {
            "definition_missing",
            "definition_corrupt",
            "config_drift",
            "driver_removed_from_config",
            "trust_pin_unavailable",
        }:
            return "high"
        return "normal"

    @staticmethod
    def _safe_next_actions(mismatch: str, identity_proved: bool) -> list[str]:
        if not identity_proved:
            return [
                (
                    "identity is NOT proven for this row: its ownership token does "
                    "not match the attempt/kind/resource it names"
                ),
                (
                    "do NOT recover it — recovery would have to forge the binding it "
                    "is failing to prove"
                ),
                (
                    "investigate by hand, then record an authenticated manual receipt "
                    "once the real resource is confirmed gone"
                ),
            ]
        if mismatch in {"definition_missing", "definition_corrupt", "config_drift"}:
            return [
                (
                    "acp runtime-quarantine recover ATTEMPT --action restore-definition "
                    "(re-pins the stored definition from the trusted bundle; identity "
                    "is verified first and never rewritten)"
                ),
                "then: --action retry-cleanup",
            ]
        if mismatch in {"cleanup_unproven", "resource_still_present"}:
            return [
                (
                    "acp runtime-quarantine recover ATTEMPT --action retry-cleanup "
                    "(re-runs the exact stored teardown and re-probes)"
                ),
                (
                    "if the resource is genuinely gone but the driver cannot prove it: "
                    "--action manual-receipt --operator ID --reason TEXT (records the "
                    "claim; releases nothing without a positive absence proof)"
                ),
            ]
        if mismatch == "driver_removed_from_config":
            return [
                (
                    "the driver is no longer configured, so its definition cannot be "
                    "re-pinned: restore it in acp.toml, or clean up by hand and record "
                    "a manual receipt"
                ),
            ]
        if mismatch == "trust_pin_unavailable":
            return [
                (
                    "the attempt's trust pin does not verify, so no definition can be "
                    "restored from it: fix trust first (acp trust list)"
                ),
            ]
        return ["inspect the evidence below; no automatic action is safe"]

    def quarantine_explain(self, attempt_id: str) -> dict[str, Any]:
        """Why each resource on *attempt_id* is parked, and what is safe next.

        Read-only by construction: it opens no driver, runs no phase and takes
        no lock. Diagnosing a stuck runtime must never be able to change it.
        """

        with self.connect() as connection:
            attempt = connection.execute(
                "SELECT id, agent_id, task_id FROM attempts WHERE id = ?", (attempt_id,)
            ).fetchone()
            if not attempt:
                raise SupervisorError("attempt_not_found", "attempt does not exist")
            runtime = connection.execute(
                "SELECT state, updated_at FROM runtime_environments WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            rows = connection.execute(
                "SELECT * FROM runtime_driver_resources WHERE attempt_id = ? ORDER BY driver",
                (attempt_id,),
            ).fetchall()
            receipts = connection.execute(
                "SELECT driver, action, operator, reason, absence_proved, recorded_at "
                "FROM runtime_quarantine_receipts WHERE attempt_id = ? "
                "ORDER BY recorded_at DESC",
                (attempt_id,),
            ).fetchall()
            allocations = connection.execute(
                "SELECT pool_name, value FROM runtime_allocations WHERE attempt_id = ? "
                "ORDER BY pool_name",
                (attempt_id,),
            ).fetchall()

        pinned, pin_error = self._pinned_definitions(attempt_id)
        now = time.time()
        resources: list[dict[str, Any]] = []
        for row in rows:
            if row["state"] != "quarantined":
                continue
            evidence = self._public_evidence(row["evidence_json"])
            mismatch = self._mismatch_class(row, pinned, pin_error)
            proved = self._identity_proved(row)
            resources.append(
                {
                    "driver": row["driver"],
                    "kind": row["kind"],
                    "resource_id": row["resource_id"],
                    "state": row["state"],
                    "owner": attempt["agent_id"],
                    "quarantined_at": row["updated_at"],
                    "age_seconds": _age_seconds(row["updated_at"], now),
                    "severity": self._quarantine_severity(mismatch, evidence),
                    "mismatch_class": mismatch,
                    "identity_proved": proved,
                    "last_trusted_evidence": evidence,
                    "safe_next_actions": self._safe_next_actions(mismatch, proved),
                }
            )
        return {
            "ok": True,
            "attempt_id": attempt_id,
            "task_id": attempt["task_id"],
            "owner": attempt["agent_id"],
            "runtime_state": runtime["state"] if runtime else None,
            "trust_pin_error": pin_error,
            "quarantined": len(resources),
            "resources": resources,
            "held_allocations": [
                {
                    "pool": allocation["pool_name"],
                    "value": allocation["value"],
                    "port_free_now": self._port_available(allocation["value"]),
                }
                for allocation in allocations
            ],
            "receipts": [dict(receipt) for receipt in receipts],
        }

    def _restore_pinned_definitions(self, attempt_id: str) -> dict[str, Any]:
        pinned, pin_error = self._pinned_definitions(attempt_id)
        if pin_error:
            raise SupervisorError(
                "runtime_trust_pin_unavailable",
                f"cannot restore definitions while the trust pin is unusable ({pin_error})",
            )
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM runtime_driver_resources WHERE attempt_id = ? "
                "AND state = 'quarantined' ORDER BY driver",
                (attempt_id,),
            ).fetchall()
        restored: list[str] = []
        refused: list[dict[str, str]] = []
        for row in rows:
            if not self._identity_proved(row):
                refused.append({"driver": row["driver"], "reason": "identity_unproved"})
                continue
            current = pinned.get(row["driver"])
            if current is None:
                refused.append({"driver": row["driver"], "reason": "driver_not_in_pin"})
                continue
            if current == row["definition_json"]:
                continue
            restored.append(row["driver"])
            with self.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                # Identity columns are absent from this UPDATE on purpose.
                connection.execute(
                    "UPDATE runtime_driver_resources SET definition_json = ?, updated_at = ? "
                    "WHERE attempt_id = ? AND driver = ?",
                    (current, utc_now(), attempt_id, row["driver"]),
                )
                self._event(
                    connection,
                    "runtime.quarantine.definition_restored",
                    "supervisor",
                    {
                        "attempt_id": attempt_id,
                        "driver": row["driver"],
                        "kind": row["kind"],
                    },
                )
        if refused:
            # A row we could not prove stays parked, and the runtime is pinned to
            # teardown_failed atomically so nothing downstream reads it as healthy.
            self._quarantine_driver_attempt(attempt_id, "runtime_quarantine_identity_unproved")
        return {"restored": restored, "refused": refused}

    def _retry_quarantined_cleanup(self, attempt_id: str, guard_fd: int) -> dict[str, Any]:
        with self.connect() as connection:
            runtime = connection.execute(
                "SELECT env_json FROM runtime_environments WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if not runtime:
                raise SupervisorError("runtime_not_found", "runtime environment is missing")
            drivers = [
                row["driver"]
                for row in connection.execute(
                    "SELECT driver FROM runtime_driver_resources WHERE attempt_id = ? "
                    "AND state = 'quarantined'",
                    (attempt_id,),
                ).fetchall()
            ]
        if not drivers:
            return {"retried": [], "still_quarantined_drivers": [], "released": []}
        environment = json.loads(runtime["env_json"])
        # The exact stored definition is re-run — _run_driver_phase reads
        # definition_json for an attempt that already has rows, so this is a
        # retry of the recorded cleanup and not a fresh interpretation of config.
        evidence = self._run_driver_phase(
            "teardown",
            attempt_id,
            environment,
            only_drivers=set(drivers),
            restart_guard_fd=guard_fd,
        )
        released = [item.driver for item in evidence if item.proof.get("cleanup_proved")]
        still = [item.driver for item in evidence if not item.proof.get("cleanup_proved")]
        # Named *_drivers so it cannot collide with the integer count the caller
        # adds; an earlier revision returned both under one key and the list won.
        return {"retried": drivers, "released": released, "still_quarantined_drivers": still}

    def _authenticate_operator(self, operator: str, credential: str) -> None:
        if not operator or not credential:
            raise SupervisorError(
                "quarantine_receipt_unauthenticated",
                "a manual cleanup receipt requires an operator id and its runner credential",
            )
        with self.connect() as connection:
            row = connection.execute(
                "SELECT role, credential_digest, revoked_at FROM runner_identities "
                "WHERE agent_id = ?",
                (operator,),
            ).fetchone()
        if not row or row["revoked_at"] or row["role"] != "integrator":
            raise SupervisorError(
                "quarantine_receipt_unauthenticated",
                "operator is not an enrolled, unrevoked integrator identity",
            )
        if not verify_credential(credential, row["credential_digest"]):
            raise SupervisorError(
                "quarantine_receipt_unauthenticated",
                "operator credential does not verify",
            )

    def _authenticate_recovery_operator(self, operator: str, credential: str) -> None:
        """Require a privileged identity once runner authentication is enabled."""

        if not self._identity_enforced():
            return
        try:
            self._authenticate(operator, "integrator", credential or None)
        except SupervisorError as error:
            raise SupervisorError(
                "quarantine_recovery_unauthenticated",
                "quarantine recovery requires a valid integrator credential",
            ) from error

    def _record_manual_receipt(
        self,
        attempt_id: str,
        operator: str,
        credential: str,
        reason: str,
        guard_fd: int,
    ) -> dict[str, Any]:
        if not reason.strip():
            raise SupervisorError(
                "quarantine_receipt_invalid", "a manual cleanup receipt requires a reason"
            )
        self._authenticate_operator(operator, credential)
        with self.connect() as connection:
            runtime = connection.execute(
                "SELECT env_json FROM runtime_environments WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            rows = connection.execute(
                "SELECT * FROM runtime_driver_resources WHERE attempt_id = ? "
                "AND state = 'quarantined' ORDER BY driver",
                (attempt_id,),
            ).fetchall()
        if not rows:
            return {"receipts": [], "released": []}

        # THE RECEIPT IS TESTIMONY; THE VERIFY PHASE IS THE PROOF. An operator
        # saying "I removed it" is recorded either way, but a row is only
        # released when the driver itself reports the resource absent.
        absent: set[str] = set()
        probe_error: str | None = None
        eligible = {row["driver"] for row in rows if self._identity_proved(row)}
        if runtime is not None and eligible:
            try:
                evidence = self._run_driver_phase(
                    "verify",
                    attempt_id,
                    json.loads(runtime["env_json"]),
                    only_drivers=eligible,
                    restart_guard_fd=guard_fd,
                )
                absent = {
                    item.driver
                    for item in evidence
                    if item.present is False and item.exit_code == 0
                }
            except (SupervisorError, DriverError) as error:
                probe_error = error.code

        stamp = utc_now()
        receipts: list[dict[str, Any]] = []
        released: list[str] = []
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for row in rows:
                proved = row["driver"] in absent
                connection.execute(
                    "INSERT INTO runtime_quarantine_receipts"
                    "  (attempt_id, driver, kind, resource_id, action, operator, reason,"
                    "   absence_proved, recorded_at)"
                    " VALUES (?, ?, ?, ?, 'manual-receipt', ?, ?, ?, ?)",
                    (
                        attempt_id,
                        row["driver"],
                        row["kind"],
                        row["resource_id"],
                        operator,
                        reason.strip(),
                        1 if proved else 0,
                        stamp,
                    ),
                )
                receipts.append(
                    {
                        "driver": row["driver"],
                        "absence_proved": proved,
                        "operator": operator,
                    }
                )
                # 🔴 THE PROBE ITSELF MOVES STATE, so this re-asserts it. The verify
                # phase records evidence like any other phase, and
                # _record_driver_evidence maps a verify result to active/absent —
                # which silently lifts the quarantine on a row we have NOT proved
                # absent. Caught by the test that files a false receipt against a
                # profile still on disk: released was correctly empty, yet the row
                # had stopped being quarantined. State is therefore set explicitly
                # here, in the same transaction as the receipt, for both outcomes.
                connection.execute(
                    "UPDATE runtime_driver_resources SET state = ?, updated_at = ? "
                    "WHERE attempt_id = ? AND driver = ?",
                    ("released" if proved else "quarantined", stamp, attempt_id, row["driver"]),
                )
                if proved:
                    released.append(row["driver"])
                self._event(
                    connection,
                    "runtime.quarantine.manual_receipt",
                    "supervisor",
                    {
                        "attempt_id": attempt_id,
                        "driver": row["driver"],
                        "operator": operator,
                        "absence_proved": proved,
                    },
                )
        return {"receipts": receipts, "released": released, "probe_error": probe_error}

    def _release_proven_allocations(self, attempt_id: str) -> list[str]:
        """Return ports to the pool ONLY where absence is positively proved.

        A quarantined driver row anywhere on the attempt keeps every allocation
        parked: the ports and the resources belong to one runtime, and a port
        that merely looks free is not evidence that the thing which was using it
        is gone.
        """

        with self.connect() as connection:
            runtime = connection.execute(
                "SELECT state FROM runtime_environments WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            unsafe = connection.execute(
                "SELECT COUNT(*) FROM runtime_driver_resources WHERE attempt_id = ? "
                "AND state NOT IN ('released', 'absent')",
                (attempt_id,),
            ).fetchone()[0]
            allocations = connection.execute(
                "SELECT pool_name, value FROM runtime_allocations WHERE attempt_id = ? "
                "ORDER BY pool_name",
                (attempt_id,),
            ).fetchall()
        if not runtime or runtime["state"] != "teardown_failed" or unsafe or not allocations:
            return []
        freed: list[str] = []
        for allocation in allocations:
            if not self._port_available(allocation["value"]):
                continue
            if self._release_proven_allocation(
                attempt_id,
                allocation["pool_name"],
                allocation["value"],
            ):
                freed.append(f"{allocation['pool_name']}={allocation['value']}")
        return freed

    def _release_proven_allocation(self, attempt_id: str, pool: str, value: int) -> bool:
        """Delete one allocation durably so a crash can resume at the next row."""

        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            deleted = connection.execute(
                "DELETE FROM runtime_allocations WHERE attempt_id = ? AND pool_name = ? "
                "AND value = ?",
                (attempt_id, pool, value),
            )
            if deleted.rowcount != 1:
                return False
            self._event(
                connection,
                "runtime.quarantine.allocation_released",
                "supervisor",
                {
                    "attempt_id": attempt_id,
                    "pool": pool,
                    "value": value,
                    "proof": "port_bind_succeeded",
                },
            )
        return True

    def quarantine_recover(
        self,
        attempt_id: str,
        action: str,
        operator: str = "",
        credential: str = "",
        reason: str = "",
    ) -> dict[str, Any]:
        """Supported recovery for a quarantined runtime.

        Idempotent by construction: every action re-reads current state and is a
        no-op once its condition already holds, so repeating a recovery after a
        crash mid-way is always safe.
        """

        if action not in self._QUARANTINE_ACTIONS:
            raise SupervisorError(
                "quarantine_action_invalid",
                f"action must be one of {', '.join(self._QUARANTINE_ACTIONS)}",
            )
        with self._runtime_restart_guard(attempt_id, recover=False) as guard_fd:
            with self.connect() as connection:
                attempt = connection.execute(
                    "SELECT id FROM attempts WHERE id = ?", (attempt_id,)
                ).fetchone()
                runtime = connection.execute(
                    "SELECT state, recovery_action FROM runtime_environments WHERE attempt_id = ?",
                    (attempt_id,),
                ).fetchone()
                quarantined = connection.execute(
                    "SELECT COUNT(*) FROM runtime_driver_resources WHERE attempt_id = ? "
                    "AND state = 'quarantined'",
                    (attempt_id,),
                ).fetchone()[0]
            if not attempt:
                raise SupervisorError("attempt_not_found", "attempt does not exist")
            if not runtime:
                raise SupervisorError("runtime_not_found", "runtime environment is missing")
            if runtime["state"] == "released" and not quarantined:
                result: dict[str, Any] = {
                    "ok": True,
                    "attempt_id": attempt_id,
                    "action": action,
                    "still_quarantined": 0,
                    "held_allocations": 0,
                    "allocations_released": [],
                    "noop": True,
                }
                if action == "restore-definition":
                    result.update({"restored": [], "refused": []})
                elif action == "retry-cleanup":
                    result.update({"retried": [], "released": [], "still_quarantined_drivers": []})
                else:
                    result.update({"receipts": [], "released": []})
                return result
            if runtime["state"] != "teardown_failed":
                raise SupervisorError(
                    "runtime_not_quarantined",
                    f"runtime state is {runtime['state']}; recovery is only valid after failed teardown",
                )
            recovery_action = runtime["recovery_action"]
            if not quarantined and recovery_action != action:
                raise SupervisorError(
                    "runtime_quarantine_empty",
                    "failed teardown has no quarantined driver proof or resumable recovery intent",
                )
            if recovery_action and recovery_action != action:
                raise SupervisorError(
                    "runtime_recovery_action_mismatch",
                    f"resume the interrupted {recovery_action} action before starting {action}",
                )
            if action != "manual-receipt":
                self._authenticate_recovery_operator(operator, credential)
            else:
                if not reason.strip():
                    raise SupervisorError(
                        "quarantine_receipt_invalid",
                        "a manual cleanup receipt requires a reason",
                    )
                self._authenticate_operator(operator, credential)
            with self.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                changed = connection.execute(
                    "UPDATE runtime_environments SET recovery_action = ?, updated_at = ? "
                    "WHERE attempt_id = ? AND state = 'teardown_failed' "
                    "AND recovery_action IN ('', ?)",
                    (action, utc_now(), attempt_id, action),
                )
                if changed.rowcount != 1:
                    raise SupervisorError(
                        "runtime_recovery_stale",
                        "runtime recovery intent changed before it could be fenced",
                    )
            outcome: dict[str, Any]
            if action == "restore-definition":
                outcome = self._restore_pinned_definitions(attempt_id)
            elif action == "retry-cleanup":
                outcome = self._retry_quarantined_cleanup(attempt_id, guard_fd)
            else:
                outcome = self._record_manual_receipt(
                    attempt_id, operator, credential, reason, guard_fd
                )

            freed = self._release_proven_allocations(attempt_id)
            with self.connect() as connection:
                remaining = connection.execute(
                    "SELECT COUNT(*) FROM runtime_driver_resources WHERE attempt_id = ? "
                    "AND state = 'quarantined'",
                    (attempt_id,),
                ).fetchone()[0]
                held_allocations = connection.execute(
                    "SELECT COUNT(*) FROM runtime_allocations WHERE attempt_id = ?",
                    (attempt_id,),
                ).fetchone()[0]
            if not remaining and not held_allocations:
                runtime_dir = self.state_dir / "runtime" / attempt_id
                try:
                    shutil.rmtree(runtime_dir)
                except FileNotFoundError:
                    pass
                except OSError as error:
                    raise SupervisorError(
                        "runtime_staging_cleanup_failed",
                        "recovered runtime staging directory could not be removed",
                    ) from error
                with self.connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    updated = connection.execute(
                        "UPDATE runtime_environments SET state = 'released', "
                        "recovery_action = '', updated_at = ? "
                        "WHERE attempt_id = ? AND state = 'teardown_failed' "
                        "AND recovery_action = ?",
                        (utc_now(), attempt_id, action),
                    )
                    if updated.rowcount != 1:
                        raise SupervisorError(
                            "runtime_recovery_stale",
                            "runtime recovery intent changed before completion",
                        )
                    self._event(
                        connection,
                        "runtime.quarantine.cleared",
                        "supervisor",
                        {"attempt_id": attempt_id, "action": action},
                    )
            elif remaining:
                with self.connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute(
                        "UPDATE runtime_environments SET recovery_action = '', updated_at = ? "
                        "WHERE attempt_id = ? AND state = 'teardown_failed' "
                        "AND recovery_action = ?",
                        (utc_now(), attempt_id, action),
                    )
        return {
            "ok": True,
            "attempt_id": attempt_id,
            "action": action,
            "still_quarantined": remaining,
            "held_allocations": held_allocations,
            "allocations_released": freed,
            **outcome,
        }

    @staticmethod
    def _directory_bytes(path: Path) -> int:
        total = 0
        for entry in path.rglob("*"):
            if entry.is_file() and not entry.is_symlink():
                try:
                    total += entry.stat().st_size
                except OSError:
                    continue
        return total

    def _gc_survey(
        self,
        connection: sqlite3.Connection,
        now: float,
        older_than_seconds: int,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Classify every attempt worktree as reclaimable or retained. Reads only.

        Returns (reclaimable, retained). `status()` calls this to report disk without
        touching anything, and `gc()` calls it to decide what to remove, so the two can
        never disagree about what is safe.
        """

        fenced_attempts = {
            row["attempt_id"]
            for row in connection.execute(
                "SELECT attempt_id FROM resource_leases "
                "WHERE attempt_id IS NOT NULL AND lease_expires_at > ?",
                (now,),
            )
        }
        allocated_attempts = {
            row["attempt_id"]
            for row in connection.execute("SELECT attempt_id FROM runtime_allocations")
        }
        rows = connection.execute(
            """
            SELECT attempt.id AS attempt_id, attempt.task_id, attempt.branch,
                   attempt.worktree, attempt.status AS attempt_status,
                   attempt.updated_at AS attempt_updated_at,
                   task.status AS task_status, task.updated_at AS task_updated_at,
                   task.cleanup_target_status, task.cleanup_error
            FROM attempts AS attempt
            JOIN tasks AS task ON task.id = attempt.task_id
            ORDER BY attempt.created_at, attempt.id
            """
        ).fetchall()

        reclaimable: list[dict[str, Any]] = []
        retained: list[dict[str, Any]] = []
        for row in rows:
            worktree = Path(row["worktree"])
            entry = {
                "attempt_id": row["attempt_id"],
                "task_id": row["task_id"],
                "task_status": row["task_status"],
                "attempt_status": row["attempt_status"],
                "branch": row["branch"],
                "worktree": str(worktree),
            }
            age = _age_seconds(row["task_updated_at"], now)
            reason = self._gc_retain_reason(
                row,
                age=age,
                older_than_seconds=older_than_seconds,
                fenced=row["attempt_id"] in fenced_attempts,
                allocated=row["attempt_id"] in allocated_attempts,
                exists=worktree.exists(),
            )
            if reason is not None:
                retained.append({**entry, "reason": reason})
                continue
            reclaimable.append(
                {**entry, "age_seconds": age, "bytes": self._directory_bytes(worktree)}
            )
        return reclaimable, retained

    @staticmethod
    def _gc_retain_reason(
        row: sqlite3.Row,
        *,
        age: int | None,
        older_than_seconds: int,
        fenced: bool,
        allocated: bool,
        exists: bool,
    ) -> str | None:
        """Why this worktree must survive, or None if it is safe to reclaim.

        Ordered most-dangerous first so the reported reason is the one that matters. Any
        doubt retains: an unparseable timestamp is treated as "too recent" rather than
        as zero age, because guessing old on a clock we cannot read would delete a live
        agent's working copy.
        """

        if not exists:
            return "worktree_already_gone"
        if row["task_status"] in ACTIVE_STATUSES or row["task_status"] in {
            "integrating",
            "qc_review",
        }:
            return "task_active"
        if row["attempt_status"] in LIVE_ATTEMPT_STATUSES:
            return "attempt_live"
        if row["attempt_status"] == "quarantined":
            return "attempt_quarantined"
        if row["cleanup_target_status"] or row["cleanup_error"]:
            return "cleanup_unproven"
        if fenced:
            # Covers CLEANUP_FENCE_EPOCH, which is a lease expiry far in the future
            # precisely so that a fenced attempt is never treated as reclaimable.
            return "resource_lease_held"
        if allocated:
            return "runtime_allocation_held"
        if row["task_status"] not in GC_RECLAIMABLE_TASK_STATUSES:
            return "task_not_terminal"
        if age is None:
            return "age_unknown"
        if age < older_than_seconds:
            return "within_retention"
        return None

    def gc(
        self,
        *,
        dry_run: bool = False,
        older_than_seconds: int = DEFAULT_GC_RETENTION_SECONDS,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Reclaim the worktrees and task branches of attempts nothing is using.

        Integration branches are reported but never deleted: their commits are the
        published evidence for an approved task, and reclaiming disk is not a good
        enough reason to remove the record of what was merged.
        """

        moment = time.time() if now is None else now
        with self.connect() as connection:
            reclaimable, retained = self._gc_survey(connection, moment, older_than_seconds)
            integration_branches = [
                {"task_id": row["task_id"], "branch": row["branch"], "verdict": row["verdict"]}
                for row in connection.execute(
                    "SELECT task_id, branch, verdict FROM integrations ORDER BY created_at, id"
                )
            ]

        removed: list[str] = []
        if not dry_run and reclaimable:
            # No outer _git_operation_guard here: _git() takes it per invocation, and the
            # flock is not reentrant, so wrapping the loop deadlocks against the first
            # `git worktree remove`. The other _remove_worktree call sites are unguarded
            # for the same reason.
            for entry in reclaimable:
                self._remove_worktree(Path(entry["worktree"]), delete_branch=True)
                removed.append(entry["attempt_id"])
            with self.connect() as connection:
                for entry in reclaimable:
                    self._event(
                        connection,
                        "worktree.reclaimed",
                        "supervisor",
                        {
                            "attempt_id": entry["attempt_id"],
                            "task_id": entry["task_id"],
                            "branch": entry["branch"],
                            "bytes": entry["bytes"],
                        },
                    )

        return {
            "ok": True,
            "dry_run": dry_run,
            "older_than_seconds": older_than_seconds,
            "reclaimable": reclaimable,
            "removed": removed,
            "bytes": sum(entry["bytes"] for entry in reclaimable),
            "retained": retained,
            "integration_branches": integration_branches,
        }

    def reap_expired(self, now: int | None = None) -> dict[str, Any]:
        epoch = int(time.time()) if now is None else now
        orphaned: list[str] = []
        conflicted: list[str] = []
        cleanup_attempts: set[str] = set()
        workers_to_stop: list[tuple[str, int, str]] = []
        task_cleanups: dict[str, str] = {}
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            attempts = connection.execute(
                """
                SELECT * FROM attempts
                WHERE (status IN ('provisioning', 'working') AND lease_expires_at <= ?)
                   OR status = 'terminating'
                """,
                (epoch,),
            ).fetchall()
            for attempt in attempts:
                latest = attempt["latest_sha"]
                if Path(attempt["worktree"]).exists():
                    latest = (
                        self._git_text(
                            "-C",
                            attempt["worktree"],
                            "rev-parse",
                            "HEAD",
                            check=False,
                        )
                        or latest
                    )
                stamp = utc_now()
                connection.execute(
                    """
                    UPDATE attempts SET status = 'terminating', latest_sha = ?,
                      updated_at = ? WHERE id = ?
                    """,
                    (latest, stamp, attempt["id"]),
                )
                if not attempt["termination_target_status"]:
                    connection.execute(
                        """
                        UPDATE tasks SET status = 'terminating', updated_at = ?
                        WHERE id = ? AND current_attempt_id = ?
                        """,
                        (stamp, attempt["task_id"], attempt["id"]),
                    )
                connection.execute(
                    """
                    UPDATE resource_leases SET lease_expires_at = ?, updated_at = ?
                    WHERE attempt_id = ?
                    """,
                    (CLEANUP_FENCE_EPOCH, stamp, attempt["id"]),
                )
                connection.execute(
                    "UPDATE runtime_allocations SET lease_expires_at = ?, updated_at = ? "
                    "WHERE attempt_id = ?",
                    (CLEANUP_FENCE_EPOCH, stamp, attempt["id"]),
                )
                cleanup_attempts.add(attempt["id"])
                if attempt["pid"] and attempt["pid"] > 0 and not attempt["termination_proof"]:
                    workers_to_stop.append((attempt["id"], attempt["pid"], attempt["pid_identity"]))
                if attempt["status"] != "terminating":
                    self._event(
                        connection,
                        "attempt.termination_started",
                        "reaper",
                        {"attempt_id": attempt["id"], "latest_sha": latest},
                    )
            expired = connection.execute(
                """
                SELECT DISTINCT task.id, task.status, task.cleanup_target_status,
                  task.current_attempt_id
                FROM tasks AS task
                JOIN resource_leases AS lease ON lease.task_id = task.id
                WHERE (
                    lease.attempt_id IS NULL
                    AND
                    (task.status IN ('qc_review', 'approved', 'integrating')
                     AND lease.lease_expires_at <= ?)
                  )
                  OR task.status = 'cleanup_pending'
                """,
                (epoch,),
            ).fetchall()
            for row in expired:
                submission = connection.execute(
                    """
                    SELECT attempt_id FROM submissions WHERE task_id = ?
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    (row["id"],),
                ).fetchone()
                cleanup_attempt_id = (
                    submission["attempt_id"] if submission else row["current_attempt_id"]
                )
                if cleanup_attempt_id:
                    task_cleanups[row["id"]] = cleanup_attempt_id
                    if row["status"] != "cleanup_pending":
                        self._fence_task_cleanup(
                            connection,
                            row["id"],
                            cleanup_attempt_id,
                            "conflicted",
                            "reaper",
                            "reservation_expired",
                        )
                        connection.execute(
                            "UPDATE submissions SET status = 'blocked', qc_resume_status = '' "
                            "WHERE task_id = ? AND status = 'qc_running'",
                            (row["id"],),
                        )
                        self._event(
                            connection,
                            "reservation.expired",
                            "reaper",
                            {"task_id": row["id"], "cleanup_fenced": True},
                        )
            expired_runtime = connection.execute(
                """
                SELECT DISTINCT attempt_id FROM runtime_allocations
                WHERE lease_expires_at <= ?
                """,
                (epoch,),
            ).fetchall()
            cleanup_attempts.update(row["attempt_id"] for row in expired_runtime)
        terminated_workers: list[dict[str, Any]] = []
        workers = {attempt_id: (pid, identity) for attempt_id, pid, identity in workers_to_stop}
        runtime_cleanup: list[dict[str, Any]] = []
        completed_cleanup: set[str] = set()
        for attempt_id in sorted(cleanup_attempts):
            try:
                with self._runtime_restart_guard(attempt_id, recover=False) as guard_fd:
                    worker = workers.get(attempt_id)
                    if worker:
                        pid, identity = worker
                        termination = self._terminate_registered_group(pid, identity)
                        terminated_workers.append(
                            {
                                "attempt_id": attempt_id,
                                "pid": pid,
                                "termination": termination,
                            }
                        )
                        if termination == "failed":
                            raise SupervisorError(
                                "worker_containment_failed",
                                "worker subreaper did not terminate; cleanup fence remains held",
                            )
                        if not self._record_registered_worker_termination(
                            attempt_id,
                            pid,
                            identity,
                            termination,
                        ):
                            raise SupervisorError(
                                "worker_registration_lost",
                                "worker identity changed before termination proof was recorded",
                            )
                    self._prepare_terminated_attempt_cleanup(attempt_id)
                    runtime = self._runtime_down_locked(
                        attempt_id,
                        force=True,
                        _allow_active=False,
                        guard_fd=guard_fd,
                    )
                runtime_cleanup.append({"attempt_id": attempt_id, "state": runtime["state"]})
                if runtime["state"] == "released":
                    self._finalize_registered_worker_cleanup(attempt_id)
                    completed_cleanup.add(attempt_id)
            except (OSError, subprocess.SubprocessError, SupervisorError) as error:
                runtime_cleanup.append(
                    {"attempt_id": attempt_id, "state": "cleanup_error", "error": str(error)}
                )
                with self.connect() as connection:
                    connection.execute(
                        "UPDATE tasks SET cleanup_error = ?, updated_at = ? "
                        "WHERE current_attempt_id = ?",
                        (str(error), utc_now(), attempt_id),
                    )
        for task_id, attempt_id in sorted(task_cleanups.items()):
            try:
                with self._task_operation_guard(task_id, recover=True):
                    if attempt_id in cleanup_attempts:
                        # The attempt pass above owns process termination and
                        # the one teardown try for this reap. Reuse its durable
                        # state instead of executing non-idempotent hooks twice.
                        runtime = self.runtime_environment(attempt_id)
                        if runtime["state"] != "released":
                            continue
                    else:
                        with self._runtime_restart_guard(attempt_id, recover=False) as guard_fd:
                            self._prepare_terminated_attempt_cleanup(attempt_id)
                            runtime = self._runtime_down_locked(
                                attempt_id,
                                force=True,
                                _allow_active=False,
                                guard_fd=guard_fd,
                            )
                    if runtime["state"] != "released":
                        raise SupervisorError(
                            "runtime_cleanup_unproven",
                            "runtime cleanup did not reach released state",
                        )
                    self._finalize_registered_worker_cleanup(attempt_id)
                    with self.connect() as connection:
                        connection.execute("BEGIN IMMEDIATE")
                        target = self._complete_task_cleanup(
                            connection,
                            task_id,
                            attempt_id,
                            "reaper",
                        )
                    runtime_cleanup.append(
                        {"task_id": task_id, "attempt_id": attempt_id, "state": "released"}
                    )
                    if target == "conflicted":
                        conflicted.append(task_id)
            except (OSError, subprocess.SubprocessError, SupervisorError) as error:
                runtime_cleanup.append(
                    {
                        "task_id": task_id,
                        "attempt_id": attempt_id,
                        "state": "cleanup_error",
                        "error": str(error),
                    }
                )
                with self.connect() as connection:
                    connection.execute(
                        "UPDATE tasks SET cleanup_error = ?, updated_at = ? WHERE id = ? "
                        "AND status = 'cleanup_pending'",
                        (str(error), utc_now(), task_id),
                    )
        if completed_cleanup:
            with self.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                for attempt_id in sorted(completed_cleanup):
                    attempt = connection.execute(
                        "SELECT task_id, status, pid, termination_target_status, "
                        "termination_proof "
                        "FROM attempts WHERE id = ?",
                        (attempt_id,),
                    ).fetchone()
                    runtime = connection.execute(
                        "SELECT state FROM runtime_environments WHERE attempt_id = ?",
                        (attempt_id,),
                    ).fetchone()
                    if (
                        not attempt
                        or attempt["status"] != "terminating"
                        or attempt["termination_target_status"]
                        or (attempt["pid"] is not None and not attempt["termination_proof"])
                        or not runtime
                        or runtime["state"] != "released"
                    ):
                        continue
                    stamp = utc_now()
                    connection.execute(
                        "UPDATE attempts SET status = 'orphaned', pid = NULL, "
                        "pid_identity = '', termination_target_status = '', "
                        "termination_proof = '', launch_owner_pid = NULL, "
                        "launch_owner_identity = '', "
                        "updated_at = ? WHERE id = ?",
                        (stamp, attempt_id),
                    )
                    connection.execute(
                        "UPDATE tasks SET status = 'orphaned', current_attempt_id = NULL, "
                        "updated_at = ? WHERE id = ? AND current_attempt_id = ?",
                        (stamp, attempt["task_id"], attempt_id),
                    )
                    connection.execute(
                        "UPDATE resource_leases SET task_id = NULL, attempt_id = NULL, "
                        "lease_expires_at = 0, updated_at = ? WHERE attempt_id = ?",
                        (stamp, attempt_id),
                    )
                    orphaned.append(attempt["task_id"])
                    self._event(
                        connection,
                        "attempt.orphaned",
                        "reaper",
                        {"attempt_id": attempt_id, "cleanup_proved": True},
                    )
        return {
            "orphaned": orphaned,
            "conflicted": conflicted,
            "terminated_workers": terminated_workers,
            "runtime_cleanup": runtime_cleanup,
        }

    @staticmethod
    def _release_task_leases(connection: sqlite3.Connection, task_id: str, stamp: str) -> None:
        connection.execute(
            """
            UPDATE resource_leases SET task_id = NULL, attempt_id = NULL,
              lease_expires_at = 0, updated_at = ? WHERE task_id = ?
            """,
            (stamp, task_id),
        )

    def _fence_task_cleanup(
        self,
        connection: sqlite3.Connection,
        task_id: str,
        attempt_id: str,
        target_status: str,
        actor: str,
        reason: str,
    ) -> None:
        """Persist a collision fence before any runtime cleanup side effect."""

        stamp = utc_now()
        connection.execute(
            "UPDATE tasks SET status = 'cleanup_pending', cleanup_target_status = ?, "
            "cleanup_error = '', updated_at = ? WHERE id = ?",
            (target_status, stamp, task_id),
        )
        connection.execute(
            "UPDATE resource_leases SET lease_expires_at = ?, updated_at = ? WHERE task_id = ?",
            (CLEANUP_FENCE_EPOCH, stamp, task_id),
        )
        connection.execute(
            "UPDATE runtime_allocations SET lease_expires_at = ?, updated_at = ? "
            "WHERE attempt_id = ?",
            (CLEANUP_FENCE_EPOCH, stamp, attempt_id),
        )
        self._event(
            connection,
            "task.cleanup_started",
            actor,
            {
                "task_id": task_id,
                "attempt_id": attempt_id,
                "target_status": target_status,
                "reason": reason,
            },
        )

    def _complete_task_cleanup(
        self,
        connection: sqlite3.Connection,
        task_id: str,
        attempt_id: str,
        actor: str,
    ) -> str | None:
        """Release reservations only after durable runtime-release proof."""

        task = connection.execute(
            "SELECT status, cleanup_target_status FROM tasks WHERE id = ?",
            (task_id,),
        ).fetchone()
        runtime = connection.execute(
            "SELECT state FROM runtime_environments WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone()
        attempt = connection.execute(
            "SELECT pid, termination_target_status FROM attempts WHERE id = ?",
            (attempt_id,),
        ).fetchone()
        if (
            not task
            or task["status"] != "cleanup_pending"
            or not task["cleanup_target_status"]
            or not runtime
            or runtime["state"] != "released"
            or not attempt
            or attempt["pid"] is not None
            or attempt["termination_target_status"]
        ):
            return None
        target = task["cleanup_target_status"]
        stamp = utc_now()
        connection.execute(
            "UPDATE tasks SET status = ?, cleanup_target_status = '', cleanup_error = '', "
            "updated_at = ? "
            "WHERE id = ? AND status = 'cleanup_pending'",
            (target, stamp, task_id),
        )
        self._release_task_leases(connection, task_id, stamp)
        self._event(
            connection,
            "task.cleanup_completed",
            actor,
            {"task_id": task_id, "attempt_id": attempt_id, "target_status": target},
        )
        return target
