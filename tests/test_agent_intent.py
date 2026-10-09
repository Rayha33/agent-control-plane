from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from support import init_repo, make_task

import agent_control_plane.supervisor.intent as intent_module
from agent_control_plane.git_supervisor import (
    MIGRATIONS,
    SCHEMA_VERSION,
    GitSupervisor,
    SupervisorError,
)
from agent_control_plane.mcp_server import dispatch


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return init_repo(tmp_path)


def intent(
    *,
    paths: list[dict] | None = None,
    surfaces: list[dict] | None = None,
    depends_on: list[str] | None = None,
    phase: str = "planned",
) -> dict:
    return {
        "version": 1,
        "responsibility": "Update the repository data flow",
        "paths": paths or [],
        "surfaces": surfaces or [],
        "depends_on": depends_on or [],
        "phase": phase,
        "confidence": 0.75,
    }


def test_intent_revisions_are_append_only_and_fenced_to_the_live_claim(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    task = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(task["id"], "worker")
    first = intent(paths=[{"pattern": "alpha.txt", "change": "write"}])
    second = intent(paths=[{"pattern": "alpha.txt", "change": "write"}], phase="implementing")

    assert supervisor.publish_intent(attempt["id"], attempt["claim_token"], first)["revision"] == 1
    assert supervisor.publish_intent(attempt["id"], attempt["claim_token"], second)["revision"] == 2
    with pytest.raises(SupervisorError, match="claim token is stale"):
        supervisor.publish_intent(attempt["id"], attempt["claim_token"] + 1, second)

    with supervisor.connect() as connection:
        rows = connection.execute(
            "SELECT revision, intent_json FROM agent_intent_revisions "
            "WHERE attempt_id = ? ORDER BY revision",
            (attempt["id"],),
        ).fetchall()
        assert [row["revision"] for row in rows] == [1, 2]
        for statement in (
            "UPDATE agent_intent_revisions SET intent_json = '{}' WHERE attempt_id = ?",
            "DELETE FROM agent_intent_revisions WHERE attempt_id = ?",
        ):
            with pytest.raises(sqlite3.IntegrityError, match="agent_intent_revision_immutable"):
                connection.execute(statement, (attempt["id"],))
        with pytest.raises(sqlite3.IntegrityError, match="agent_intent_revision_immutable"):
            connection.execute(
                "INSERT OR REPLACE INTO agent_intent_revisions "
                "(attempt_id, claim_token, revision, intent_json, created_at) "
                "VALUES (?, ?, 1, '{}', 'replacement')",
                (attempt["id"], attempt["claim_token"]),
            )

    history = supervisor.intent_history(attempt["id"])
    assert [item["revision"] for item in history["revisions"]] == [1, 2]
    assert history["latest_revision"]["intent"]["phase"] == "implementing"
    first_page = supervisor.intent_history(attempt["id"], limit=1)
    assert first_page["has_more"] is True
    assert first_page["next_after_revision"] == 1
    second_page = supervisor.intent_history(attempt["id"], limit=1, after_revision=1)
    assert [item["revision"] for item in second_page["revisions"]] == [2]
    assert second_page["has_more"] is False


def test_active_intents_classify_read_overlap_shared_writes_and_dependencies(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    left_task = make_task(supervisor, "alpha.txt", title="data model")
    right_task = make_task(supervisor, "beta.txt", title="API layer")
    left = supervisor.claim(left_task["id"], "model-agent")
    right = supervisor.claim(right_task["id"], "api-agent")
    supervisor.publish_intent(
        left["id"],
        left["claim_token"],
        intent(
            paths=[{"pattern": "src/**", "change": "read"}],
            surfaces=[{"kind": "schema", "name": "UserRecord", "change": "write", "shared": True}],
        ),
    )
    supervisor.publish_intent(
        right["id"],
        right["claim_token"],
        intent(
            paths=[{"pattern": "src/api.py", "change": "read"}],
            surfaces=[
                {"kind": "schema", "name": "UserRecord", "change": "additive", "shared": True}
            ],
            depends_on=["schema:UserRecord"],
        ),
    )

    snapshot = supervisor.intent_snapshot()
    path_overlap = next(item for item in snapshot["overlaps"] if item["kind"] == "path")
    surface_overlap = next(item for item in snapshot["overlaps"] if item["kind"] == "schema")
    assert path_overlap["overlap"] == "potential"
    assert path_overlap["classification"] == "read_read"
    assert path_overlap["conflict"] is False
    assert surface_overlap["classification"] == "deliberate_shared"
    assert surface_overlap["conflict"] is False
    assert snapshot["dependency_matches"] == [
        {
            "dependent_attempt_id": right["id"],
            "dependent_task_id": right_task["id"],
            "dependency": "schema:UserRecord",
            "provider_attempt_id": left["id"],
            "provider_task_id": left_task["id"],
            "provider_surface": {"kind": "schema", "name": "UserRecord"},
            "compatibility": "not_assessed",
        }
    ]
    supervisor.publish_intent(
        right["id"],
        right["claim_token"],
        intent(
            paths=[{"pattern": "src/api.py", "change": "write"}],
            surfaces=[{"kind": "schema", "name": "UserRecord", "change": "additive"}],
            depends_on=["schema:UserRecord"],
        ),
    )
    conflict = next(
        item for item in supervisor.intent_snapshot()["overlaps"] if item["kind"] == "schema"
    )
    assert conflict["classification"] == "conflicting_write_intent"
    assert conflict["conflict"] is True


def test_missing_intent_is_unknown_and_server_observes_changed_paths_read_only(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    task = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(task["id"], "worker")
    (Path(attempt["worktree"]) / "alpha.txt").write_text("changed in worktree\n", encoding="utf-8")
    before_events = connection_count(supervisor, "events")
    before_revisions = connection_count(supervisor, "agent_intent_revisions")

    snapshot = supervisor.intent_snapshot()

    assert snapshot["active_attempts"][0]["intent_state"] == "missing"
    assert snapshot["active_attempts"][0]["observed"] == {
        "status": "not_requested",
        "reason": "use_explicit_observation",
        "paths": [],
    }
    assert snapshot["unknown_attempts"] == [{"attempt_id": attempt["id"], "state": "missing"}]
    observed_snapshot = supervisor.intent_snapshot(include_observed=True)
    assert observed_snapshot["active_attempts"][0]["observed"] == {
        "status": "available",
        "source": "supervisor_git_observation",
        "paths": ["alpha.txt"],
    }
    assert connection_count(supervisor, "events") == before_events
    assert connection_count(supervisor, "agent_intent_revisions") == before_revisions

    read_only = GitSupervisor(repo, read_only=True)
    assert dispatch(read_only, "acp_intents", {}) == snapshot
    assert dispatch(read_only, "acp_intents", {"include_observed": True}) == observed_snapshot

    with supervisor.connect() as connection:
        connection.execute(
            "INSERT INTO agent_intent_revisions "
            "(attempt_id, claim_token, revision, intent_json, created_at) VALUES (?, ?, 1, ?, ?)",
            (attempt["id"], attempt["claim_token"], "{unparseable", "now"),
        )
    malformed = supervisor.intent_snapshot()
    assert malformed["active_attempts"][0]["intent_state"] == "unparseable"
    assert malformed["unknown_attempts"] == [{"attempt_id": attempt["id"], "state": "unparseable"}]
    with supervisor.connect() as connection:
        connection.execute(
            "INSERT INTO agent_intent_revisions "
            "(attempt_id, claim_token, revision, intent_json, created_at) VALUES (?, ?, 2, ?, ?)",
            (attempt["id"], attempt["claim_token"] + 1, "{}", "stale"),
        )
    stale = supervisor.intent_snapshot()
    assert stale["active_attempts"][0]["intent_state"] == "stale"
    assert stale["unknown_attempts"] == [{"attempt_id": attempt["id"], "state": "stale"}]

    current = supervisor.publish_intent(
        attempt["id"],
        attempt["claim_token"],
        intent(paths=[{"pattern": "alpha.txt", "change": "write"}]),
    )
    assert current["revision"] == 3
    history = supervisor.intent_history(attempt["id"], limit=2)
    assert [item["revision"] for item in history["revisions"]] == [1, 2]
    assert history["next_after_revision"] == 2
    next_page = supervisor.intent_history(attempt["id"], limit=2, after_revision=2)
    assert [item["revision"] for item in next_page["revisions"]] == [3]
    assert next_page["latest_revision"]["claim_token"] == attempt["claim_token"]
    current_snapshot = supervisor.intent_snapshot()
    assert current_snapshot["active_attempts"][0]["intent_state"] == "declared"
    assert current_snapshot["unknown_attempts"] == []


def test_terminal_attempt_leaves_history_but_drops_out_of_active_board(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    task = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(task["id"], "worker")
    supervisor.publish_intent(
        attempt["id"],
        attempt["claim_token"],
        intent(paths=[{"pattern": "alpha.txt", "change": "write"}]),
    )
    with supervisor.connect() as connection:
        connection.execute("UPDATE attempts SET status = 'failed' WHERE id = ?", (attempt["id"],))
        connection.execute(
            "UPDATE tasks SET status = 'open', current_attempt_id = NULL WHERE id = ?",
            (task["id"],),
        )

    assert supervisor.intent_snapshot()["active_attempts"] == []
    history = supervisor.intent_history(attempt["id"])
    assert history["active"] is False
    assert len(history["revisions"]) == 1
    resumed = supervisor.claim(task["id"], "replacement-worker")
    assert [entry["attempt_id"] for entry in supervisor.intent_snapshot()["active_attempts"]] == [
        resumed["id"]
    ]
    assert len(supervisor.intent_history(attempt["id"])["revisions"]) == 1


def test_path_overlap_uses_the_repository_filesystem_case_rule(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    left_task = make_task(supervisor, "alpha.txt")
    right_task = make_task(supervisor, "beta.txt")
    left = supervisor.claim(left_task["id"], "left")
    right = supervisor.claim(right_task["id"], "right")
    with supervisor.connect() as connection:
        connection.execute("UPDATE meta SET value = '0' WHERE key = 'path_case_sensitive'")
    supervisor.publish_intent(
        left["id"],
        left["claim_token"],
        intent(paths=[{"pattern": "src/Shared.py", "change": "read"}]),
    )
    supervisor.publish_intent(
        right["id"],
        right["claim_token"],
        intent(paths=[{"pattern": "src/shared.py", "change": "read"}]),
    )

    overlap = next(
        item for item in supervisor.intent_snapshot()["overlaps"] if item["kind"] == "path"
    )

    assert overlap["overlap"] == "exact"
    assert overlap["classification"] == "read_read"


def test_observer_rejects_option_like_untrusted_start_revision(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    task = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(task["id"], "worker")
    would_be_output = repo.parent / "intent-observer-must-not-write"
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE attempts SET start_sha = ? WHERE id = ?",
            (f"--output={would_be_output}", attempt["id"]),
        )

    observed = supervisor.intent_snapshot(include_observed=True)["active_attempts"][0]["observed"]

    assert observed["status"] == "unavailable"
    assert observed["reason"] == "invalid_start_revision"
    assert not would_be_output.exists()


def test_duplicate_intent_scopes_are_normalized_without_erasing_distinct_changes(
    repo: Path,
) -> None:
    supervisor = GitSupervisor(repo)
    task = make_task(supervisor, "alpha.txt")
    attempt = supervisor.claim(task["id"], "worker")
    supervisor.publish_intent(
        attempt["id"],
        attempt["claim_token"],
        intent(
            paths=[
                {"pattern": "src/api.py", "change": "write"},
                {"pattern": "src/api.py", "change": "write"},
                {"pattern": "src/api.py", "change": "read"},
            ],
            surfaces=[
                {"kind": "schema", "name": "UserRecord", "change": "write"},
                {"kind": "schema", "name": "userrecord", "change": "write"},
            ],
            depends_on=["schema:UserRecord", "SCHEMA:userrecord"],
        ),
    )

    declaration = supervisor.intent_snapshot()["active_attempts"][0]["intent"]

    assert declaration["paths"] == [
        {"pattern": "src/api.py", "change": "write", "shared": False},
        {"pattern": "src/api.py", "change": "read", "shared": False},
    ]
    assert declaration["surfaces"] == [
        {"kind": "schema", "name": "UserRecord", "change": "write", "shared": False}
    ]
    assert declaration["depends_on"] == ["schema:UserRecord"]


def test_intent_snapshot_avoids_git_by_default_and_bounds_optional_observation(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    attempts = []
    for key in ("alpha", "beta"):
        task = make_task(supervisor, f"{key}.txt")
        attempts.append(supervisor.claim(task["id"], f"{key}-worker"))

    def unexpected_observer(*_args: object, **_kwargs: object) -> dict:
        raise AssertionError("default intent snapshot must not observe Git")

    monkeypatch.setattr(supervisor, "_observed_changed_paths", unexpected_observer)
    default_snapshot = supervisor.intent_snapshot()
    assert all(
        item["observed"]["status"] == "not_requested"
        for item in default_snapshot["active_attempts"]
    )
    assert default_snapshot["observation_summary"]["requested"] is False
    monkeypatch.delattr(supervisor, "_observed_changed_paths")

    observed_attempt_ids: list[str] = []

    def bounded_observer(_self: object, attempt: sqlite3.Row, *, deadline: float) -> dict:
        assert deadline > 0
        observed_attempt_ids.append(attempt["id"])
        return {"status": "available", "source": "test", "paths": []}

    monkeypatch.setattr(intent_module, "_OBSERVATION_ATTEMPT_LIMIT", 1)
    monkeypatch.setattr(GitSupervisor, "_observed_changed_paths", bounded_observer)
    observed = supervisor.intent_snapshot(include_observed=True)

    assert len(observed_attempt_ids) == 1
    observed_entries = observed["active_attempts"]
    assert sum(item["observed"]["status"] == "available" for item in observed_entries) == 1
    assert (
        sum(
            item["observed"].get("reason") == "observation_attempt_limit"
            for item in observed_entries
        )
        == 1
    )
    assert observed["observation_summary"]["truncated"] is True


def test_overlap_scan_marks_comparison_truncation_instead_of_no_conflict(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    first_task = make_task(supervisor, "alpha.txt")
    second_task = make_task(supervisor, "beta.txt")
    first = supervisor.claim(first_task["id"], "first")
    second = supervisor.claim(second_task["id"], "second")
    supervisor.publish_intent(
        first["id"],
        first["claim_token"],
        intent(
            paths=[
                {"pattern": "src/one.py", "change": "write"},
                {"pattern": "src/two.py", "change": "write"},
            ]
        ),
    )
    supervisor.publish_intent(
        second["id"],
        second["claim_token"],
        intent(
            paths=[
                {"pattern": "other/one.py", "change": "write"},
                {"pattern": "other/two.py", "change": "write"},
            ]
        ),
    )
    monkeypatch.setattr(intent_module, "_OVERLAP_COMPARISON_LIMIT", 1)

    snapshot = supervisor.intent_snapshot()

    assert snapshot["overlaps"] == []
    assert snapshot["overlap_analysis"]["status"] == "truncated"
    assert snapshot["overlap_analysis"]["reason"] == "comparison_limit"
    assert snapshot["overlap_analysis"]["comparisons"] == 1


def test_active_intent_list_reports_its_attempt_limit(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    supervisor = GitSupervisor(repo)
    for key in ("alpha", "beta"):
        task = make_task(supervisor, f"{key}.txt")
        supervisor.claim(task["id"], f"{key}-worker")
    monkeypatch.setattr(intent_module, "_ACTIVE_INTENT_LIMIT", 1)

    snapshot = supervisor.intent_snapshot()

    assert len(snapshot["active_attempts"]) == 1
    assert snapshot["active_attempt_summary"] == {
        "included": 1,
        "limit": 1,
        "truncated": True,
    }
    assert snapshot["overlap_analysis"]["status"] == "truncated"
    assert snapshot["overlap_analysis"]["reason"] == "active_attempt_limit"
    assert snapshot["dependency_analysis"]["status"] == "truncated"
    assert snapshot["dependency_analysis"]["reason"] == "active_attempt_limit"


def test_intent_schema_migration_is_versioned_and_installs_immutability_guards() -> None:
    assert SCHEMA_VERSION == 25
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE attempts(id TEXT PRIMARY KEY)")

    dict(MIGRATIONS)[23](connection)

    trigger_names = {
        row[0]
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")
    }
    assert {
        "agent_intent_revisions_no_update",
        "agent_intent_revisions_no_delete",
        "agent_intent_revisions_no_replace",
    } <= trigger_names
    connection.close()


def test_latest_intent_revision_index_uses_attempt_and_revision_order() -> None:
    connection = sqlite3.connect(":memory:")
    connection.execute(
        """CREATE TABLE agent_intent_revisions(
            attempt_id TEXT, claim_token INTEGER, revision INTEGER, intent_json TEXT,
            created_at TEXT, PRIMARY KEY(attempt_id, claim_token, revision)
        )"""
    )

    dict(MIGRATIONS)[24](connection)

    plan = connection.execute(
        "EXPLAIN QUERY PLAN SELECT revision FROM agent_intent_revisions "
        "WHERE attempt_id = 'a' ORDER BY revision DESC LIMIT 1"
    ).fetchall()
    assert any("idx_agent_intent_revisions_attempt_latest" in row[3] for row in plan)
    connection.close()


def test_schema_22_control_database_upgrades_to_intent_schema_25(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    with supervisor.connect() as connection:
        for trigger in (
            "agent_intent_revisions_no_update",
            "agent_intent_revisions_no_delete",
            "agent_intent_revisions_no_replace",
        ):
            connection.execute(f"DROP TRIGGER {trigger}")
        connection.execute("DROP INDEX idx_agent_intent_revisions_latest")
        connection.execute("DROP TABLE agent_intent_revisions")
        connection.execute("UPDATE meta SET value = '22' WHERE key = 'schema_version'")

    upgraded = GitSupervisor(repo)
    assert upgraded.schema_version_on_open == 22
    read_only = GitSupervisor(repo, read_only=True)
    assert read_only.schema_version_on_open == 25
    with read_only.connect() as connection:
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'agent_intent_revisions'"
        ).fetchone()
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'index' "
            "AND name = 'idx_agent_intent_revisions_attempt_latest'"
        ).fetchone()


def connection_count(supervisor: GitSupervisor, table: str) -> int:
    with supervisor.connect() as connection:
        return connection.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()["count"]
