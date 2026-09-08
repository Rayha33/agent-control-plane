"""Resource case: the write set must mean what the operator declared.

`normalize_resource` casefolds, so `Makefile` is stored as `makefile` and `_path_matches`
casefolds the candidate to compensate. On a case-INSENSITIVE filesystem that is right:
`README.md` and `readme.md` are one file, and treating them as two resources would let
two attempts lease the same bytes. On a case-SENSITIVE one it is a hole: a task declaring
`Makefile` is ALLOWED to write `makefile`, an undeclared write passing the exact check
the guard and `submit` exist to enforce.

The fix is not "stop casefolding" — that would regress the case-insensitive behaviour the
folding was added for. It is to measure the filesystem and match by its rules.

WHAT THESE TESTS EXECUTE, AND WHERE THE REST WAS EXECUTED. The tests below drive the
recorded case-sensitivity answer directly, because a checkout's volume is whatever CI
gives it and a gate that only fires on one kind of filesystem is a gate that usually
does not run. `test_the_case_probe_agrees_with_the_filesystem` is the one that binds the
recorded answer to reality, and it asserts agreement rather than any particular answer,
so it is meaningful on either volume.

The end-to-end case WAS reproduced, on a case-sensitive APFS volume created for it, and
is not merely reasoned about. `hdiutil create -fs "Case-sensitive APFS"` mounts one on
macOS; on it `Makefile` and `makefile` hold different bytes at once, `acp init` probed
`meta.path_case_sensitive = 1` with nothing forced, `acp guard --path makefile` against a
task declaring `Makefile` returned `undeclared_write`, and `acp submit` on a commit
touching `makefile` returned `changed paths are not leased: makefile`. The same script
run against the pre-fix source on the same volume allowed both.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from support import git, init_repo, make_task

from agent_control_plane.git_supervisor import (
    META_CASE_SENSITIVE,
    GitSupervisor,
    SupervisorError,
    probe_case_sensitive_paths,
)
from agent_control_plane.scheduling import declared_resources


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return init_repo(tmp_path)


def record_case_sensitivity(supervisor: GitSupervisor, sensitive: bool) -> None:
    """Set the recorded answer the way `_open_read_write`'s probe would have."""

    with supervisor.connect() as connection:
        connection.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)",
            (META_CASE_SENSITIVE, "1" if sensitive else "0"),
        )


def filesystem_is_case_sensitive(directory: Path) -> bool:
    """Ground truth, measured without going through the code under test."""

    token = uuid.uuid4().hex
    upper = directory / f"Ground{token}"
    upper.write_text("", encoding="utf-8")
    try:
        return not (directory / f"ground{token}").exists()
    finally:
        upper.unlink()


# --------------------------------------------------------------------- the probe


def test_the_case_probe_agrees_with_the_filesystem(tmp_path: Path) -> None:
    """`sys.platform` is the wrong oracle; this asserts against the volume itself.

    Passes on either kind of filesystem on purpose: the claim is that the probe MATCHES
    reality, not that reality is any particular way. A probe hardcoded to a platform
    guess fails this on the machine whose volume disagrees with its platform.
    """

    assert probe_case_sensitive_paths(tmp_path) is filesystem_is_case_sensitive(tmp_path)


def test_the_probe_leaves_nothing_behind(tmp_path: Path) -> None:
    before = sorted(item.name for item in tmp_path.iterdir())
    probe_case_sensitive_paths(tmp_path)
    assert sorted(item.name for item in tmp_path.iterdir()) == before


def test_the_probed_answer_is_recorded_at_open(repo: Path) -> None:
    supervisor = GitSupervisor(repo)
    with supervisor.connect() as connection:
        row = connection.execute(
            "SELECT value FROM meta WHERE key = ?", (META_CASE_SENSITIVE,)
        ).fetchone()
    assert row is not None
    assert (row["value"] == "1") is filesystem_is_case_sensitive(repo / ".acp")


# ------------------------------------------------------------------ normalisation


def test_normalize_resource_can_preserve_the_declared_case() -> None:
    assert GitSupervisor.normalize_resource("Makefile") == "makefile"
    assert GitSupervisor.normalize_resource("Makefile", fold=False) == "Makefile"


def test_case_preserving_normalisation_still_normalises_everything_else() -> None:
    """Only the folding is dropped. Separators, NFC and the directory suffix stay."""

    assert GitSupervisor.normalize_resource("docs\\Guide.md", fold=False) == "docs/Guide.md"
    assert GitSupervisor.normalize_resource("Src/", fold=False) == "Src/**"
    with pytest.raises(SupervisorError, match="repo-relative"):
        GitSupervisor.normalize_resource("../Escape", fold=False)
    with pytest.raises(SupervisorError, match="internal resource"):
        GitSupervisor.normalize_resource(".GIT/config", fold=False)


def test_logical_resources_stay_folded_even_when_asked_not_to() -> None:
    """A logical resource is an identity, not a path; folding is what makes it stable."""

    assert GitSupervisor.normalize_resource("logical:Deploy", fold=False) == "logical:deploy"


def test_path_matches_is_case_sensitive_when_folding_is_off() -> None:
    assert GitSupervisor._path_matches("makefile", "makefile") is True
    assert GitSupervisor._path_matches("Makefile", "makefile") is True

    assert GitSupervisor._path_matches("Makefile", "Makefile", fold=False) is True
    assert GitSupervisor._path_matches("makefile", "Makefile", fold=False) is False
    assert GitSupervisor._path_matches("docs/Guide.md", "Docs/**", fold=False) is False
    assert GitSupervisor._path_matches("Docs/Guide.md", "Docs/**", fold=False) is True
    assert GitSupervisor._path_matches("Docs/g.txt", "Docs/*.txt", fold=False) is True
    assert GitSupervisor._path_matches("docs/g.txt", "Docs/*.txt", fold=False) is False


# ------------------------------------------------------- THE GATE: guard, both ways


@pytest.fixture
def declared_makefile(repo: Path):
    """A task whose write set is `Makefile`, claimed and ready to write."""

    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "Makefile")
    attempt = supervisor.claim(created["id"], "worker")
    return supervisor, created, attempt


def test_guard_denies_the_other_case_on_a_case_sensitive_filesystem(declared_makefile) -> None:
    """The hole this row exists to close.

    On a case-sensitive volume `Makefile` and `makefile` are two files. A task that
    declared one must not be waved through to write the other.
    """

    supervisor, _created, attempt = declared_makefile
    record_case_sensitivity(supervisor, True)

    allowed = supervisor.guard(attempt["id"], "Makefile")
    denied = supervisor.guard(attempt["id"], "makefile")

    assert allowed["allow"] is True
    assert denied["allow"] is False
    assert denied["reason"] == "undeclared_write"


def test_guard_still_allows_the_other_case_on_a_case_insensitive_filesystem(
    declared_makefile,
) -> None:
    """The half that stops the fix regressing what the folding was added for.

    Here the two names ARE one file. Denying `makefile` would deny the agent the very
    file it leased, under a different spelling.
    """

    supervisor, _created, attempt = declared_makefile
    record_case_sensitivity(supervisor, False)

    assert supervisor.guard(attempt["id"], "Makefile")["allow"] is True
    assert supervisor.guard(attempt["id"], "makefile")["allow"] is True


def test_a_task_predating_the_declared_map_keeps_case_insensitive_matching(
    declared_makefile,
) -> None:
    """Rows written before schema 2 have no raw form, and it is not recoverable.

    Matching such a row's folded string case-sensitively would deny it its own declared
    write. The per-row rule is carried by whether the raw form is there, so an old row
    keeps the old behaviour instead of being broken by a schema it never saw.
    """

    supervisor, created, attempt = declared_makefile
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE tasks SET declared_resources_json = '{}' WHERE id = ?", (created["id"],)
        )
    record_case_sensitivity(supervisor, True)

    assert supervisor.guard(attempt["id"], "makefile")["allow"] is True


def test_a_declared_map_that_does_not_fold_to_its_key_is_not_trusted(
    declared_makefile,
) -> None:
    """A map entry is only usable if it really is the unfolded form of its own key.

    Anything else — a hand-edited database, a future writer with different conventions —
    must fall back to the folded string rather than silently matching against a resource
    the task never declared.
    """

    supervisor, created, attempt = declared_makefile
    with supervisor.connect() as connection:
        connection.execute(
            "UPDATE tasks SET declared_resources_json = ? WHERE id = ?",
            (json.dumps({"makefile": "Cargo.toml"}), created["id"]),
        )
    record_case_sensitivity(supervisor, True)

    decision = supervisor.guard(attempt["id"], "Cargo.toml")
    assert decision["allow"] is False
    assert supervisor.guard(attempt["id"], "makefile")["allow"] is True


# ------------------------------------------------------ THE GATE: submit, both ways


def _commit_lowercase_makefile(attempt: dict) -> None:
    worktree = Path(attempt["worktree"])
    (worktree / "makefile").write_text("all:\n\t@true\n", encoding="utf-8")
    git(worktree, "add", "makefile")
    git(worktree, "commit", "-m", "write the other case")


def test_submit_rejects_the_other_case_on_a_case_sensitive_filesystem(
    declared_makefile,
) -> None:
    supervisor, _created, attempt = declared_makefile
    _commit_lowercase_makefile(attempt)
    record_case_sensitivity(supervisor, True)

    with pytest.raises(SupervisorError) as captured:
        supervisor.submit(attempt["id"], attempt["claim_token"])
    assert captured.value.code == "undeclared_write"


def test_submit_still_accepts_the_other_case_on_a_case_insensitive_filesystem(
    declared_makefile,
) -> None:
    supervisor, _created, attempt = declared_makefile
    _commit_lowercase_makefile(attempt)
    record_case_sensitivity(supervisor, False)

    submission = supervisor.submit(attempt["id"], attempt["claim_token"])
    assert submission["changed_paths"] == ["makefile"]


# ------------------------------------------------------------- the operator surfaces


def test_the_task_view_carries_the_declared_case_beside_the_lease_key(repo: Path) -> None:
    """`acp show`, `acp queue` and `acp status` all render this view.

    The folded string stays under `resources` because overlap and lease identity are
    keyed off it. What an operator copies into a command comes from `declared_resources`,
    which on a case-sensitive checkout is the only one of the two that exists.
    """

    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "Makefile", "Docs/")

    view = supervisor.task(created["id"])

    assert view["resources"] == ["docs/**", "makefile"]
    assert view["declared_resources"] == ["Docs/", "Makefile"]


def test_the_guard_denial_names_the_path_that_exists(declared_makefile) -> None:
    """A denial that answered `makefile` would point the agent at what it just refused."""

    supervisor, _created, attempt = declared_makefile
    record_case_sensitivity(supervisor, True)

    assert supervisor.guard(attempt["id"], "makefile")["declared"] == ["Makefile"]


# ------------------------------------------------------------------ lease identity


def test_lease_identity_is_still_the_folded_string(declared_makefile) -> None:
    """Deliberately unchanged, and pinned so a later change has to mean it.

    The folded string is the PRIMARY KEY of `resource_leases`. Storing the declared case
    instead would rewrite the identity of every lease in every existing database, and it
    would make `Makefile` and `makefile` two leases — which on a case-INSENSITIVE volume
    is two attempts holding exclusive claims on one file. Overlap therefore stays folded:
    it over-blocks on a case-sensitive volume, which fails closed.
    """

    supervisor, created, attempt = declared_makefile
    with supervisor.connect() as connection:
        task = connection.execute("SELECT * FROM tasks WHERE id = ?", (created["id"],)).fetchone()
        leases = connection.execute(
            "SELECT resource FROM resource_leases WHERE attempt_id = ?", (attempt["id"],)
        ).fetchall()

    assert json.loads(task["resources_json"]) == ["makefile"]
    assert json.loads(task["declared_resources_json"]) == {"makefile": "Makefile"}
    assert [row["resource"] for row in leases] == ["makefile"]
    # Two tasks declaring the two cases still collide, because both normalise to one key.
    assert GitSupervisor.resources_overlap(
        GitSupervisor.normalize_resource("Makefile"),
        GitSupervisor.normalize_resource("makefile"),
    )


# ------------------------------------------------- #1764: the operator surfaces

# #1708 fixed the GUARD. These cover the other half: every surface that PRINTS a resource
# was still emitting the folded string, so on a case-sensitive checkout `acp queue`,
# `acp status`, `acp plan` and the QC review packet named files that do not exist.
# The invariant under test in every one of them: the LEASE KEY stays folded (overlap and
# lease identity are keyed off it) while the DISPLAYED form keeps the operator's case.


def test_the_shared_helper_returns_the_declared_case() -> None:
    row = {
        "resources_json": json.dumps(["makefile", "docs/readme.md"]),
        "declared_resources_json": json.dumps(
            {"makefile": "Makefile", "docs/readme.md": "docs/README.md"}
        ),
    }
    assert declared_resources(row) == ["Makefile", "docs/README.md"]


def test_a_row_predating_the_column_falls_back_to_the_folded_form() -> None:
    """Not a guess at capitalisation — the raw form is unrecoverable for those rows."""

    row = {"resources_json": json.dumps(["makefile"]), "declared_resources_json": "{}"}
    assert declared_resources(row) == ["makefile"]


def test_the_qc_review_packet_field_holds_what_its_name_says(repo: Path) -> None:
    """Drives the REAL `_review_packet`, not the helper it calls.

    The packet's field is named `declared_resources`; before #1764 it held the FOLDED set,
    contradicting the same field name in `_task_view` — two fields, one name, opposite
    meanings. Asserting on the helper would have tested my own new code and passed no
    matter what the packet emitted, so this builds the packet itself with `_git_text`
    stubbed (it only shells out for a diff and a stat, neither of which this is about).
    """

    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "Makefile")
    with supervisor.connect() as connection:
        task = connection.execute("SELECT * FROM tasks WHERE id = ?", (created["id"],)).fetchone()

    class Stubbed(GitSupervisor):
        def _git_text(self, *args: str) -> str:
            return ""

    stub = Stubbed(repo)
    submission = {
        "id": "sub-1",
        "commit_sha": "0" * 40,
        "tree_sha": "1" * 40,
        "patch_sha256": "2" * 64,
        "changed_paths_json": json.dumps(["Makefile"]),
    }
    packet = stub._review_packet(task, submission, repo)

    # the field says "declared", so it must carry what the operator declared
    assert packet["task"]["declared_resources"] == ["Makefile"]
    # and the folded lease key is still exposed, under its own honest name
    assert packet["task"]["resources"] == ["makefile"]


def test_the_lease_key_is_still_folded(repo: Path) -> None:
    """The load-bearing half. If this ever goes green while the key is unfolded, overlap
    detection and lease identity have silently changed meaning."""

    supervisor = GitSupervisor(repo)
    created = make_task(supervisor, "Makefile")
    with supervisor.connect() as connection:
        row = connection.execute("SELECT * FROM tasks WHERE id = ?", (created["id"],)).fetchone()
    assert json.loads(row["resources_json"]) == ["makefile"]
