"""The supervisor kernel, split by lifecycle phase (board #1630).

`git_supervisor.py` was one 9,000-line module holding a 7,900-line class, so no reviewer
could hold an integration or cleanup path in their head well enough to check the fencing
and trust claims that ARE this product. Each module here was lifted out of it verbatim,
and `GitSupervisor` inherits the phase mixins, so `from agent_control_plane.git_supervisor
import GitSupervisor` and every other import path keep working.
scripts/check_public_surface.py pins that.

Where each phase lives:

    common       constants, SupervisorError, small value types
    store        the database connection and the hash-chained audit event log
    schema       table DDL, the idempotent column upgrade, the case probe
    config       Config, .acp/config.toml loading, per-attempt trust pins
    identity     runner enrollment and authentication
    claims       claim, heartbeat, the write-set guard, submit
    runtime      runtime allocation, driver secrets/evidence, runtime up/down/restart
    workers      worker launch, registration and termination
    process      contained child processes, the kernel monitor, the supervisor's Git calls
    qc           reviewer policy, assurance, calibration, QC runs
    integration  the merge, the isolated integration Git boundary, crash reconciliation
    reaper       lease expiry, two-phase cleanup, worktree GC, quarantine recovery
    views        row lookups and JSON views

What stays in git_supervisor.py, and why. A function reads module globals from the module
it was defined in, so moving a reader changes which binding it sees:

  * SCHEMA_VERSION, MIGRATIONS and their readers (the open/migrate path, doctor) — tests
    monkeypatch those names on git_supervisor.
  * _run_driver_phase and _run_critic — they call run_trusted, which tests monkeypatch on
    git_supervisor.
  * Methods that name `GitSupervisor.` explicitly (_root, resources_overlap,
    _open_registered_pidfd, _terminate_registered_group, _process_has_exited,
    _command_finding, _read_integration_info_attributes, initialize) — tests monkeypatch
    attributes on the GitSupervisor class itself.

tests/test_supervisor_split.py fails if a reader of a patched global ever moves out.
"""
