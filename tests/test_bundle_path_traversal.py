"""`acp bundle` must read reproduction bundles, and nothing else.

`read_bundle` built its path as `state_dir / "bundles" / f"{qc_id}.json"` with the
caller's string interpolated straight in. Measured before the fix, with `bundles/`
present as any completed QC leaves it:

    acp bundle '../../outside'   -> printed the contents of outside.json
    acp bundle '../../../esc'    -> printed a file three directories up

An arbitrary-JSON-file read through a path parameter. Today's caller is a local
operator with their own privileges, so it escalates nothing by itself — but `bundle`
is in READ_ONLY_ACTIONS, the set a read-only MCP server would expose to a model
(board #1703), and that is the caller it must not be an oracle for.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from support import init_repo

from agent_control_plane.git_supervisor import GitSupervisor, SupervisorError

ESCAPES = [
    "../../outside",
    "../../../esc",
    "../bundles/../../outside",
    "/etc/hosts",
    "sub/../../../outside",
]


@pytest.fixture
def repo_with_bundles(tmp_path: Path) -> Path:
    repo = init_repo(tmp_path)
    # Exactly what the first completed QC creates.
    (repo / ".acp" / "bundles").mkdir(parents=True, exist_ok=True)
    (tmp_path / "outside.json").write_text(json.dumps({"secret": "not a bundle"}), "utf-8")
    return repo


@pytest.mark.parametrize("qc_id", ESCAPES)
def test_a_traversing_qc_id_is_refused(repo_with_bundles: Path, qc_id: str) -> None:
    supervisor = GitSupervisor(repo_with_bundles)
    with pytest.raises(SupervisorError) as error:
        supervisor.reproduction_bundle(qc_id)
    assert error.value.code == "invalid_qc_id"


def test_the_refusal_is_not_just_a_missing_file(repo_with_bundles: Path) -> None:
    """The control: the target really is readable, so a pass is not an accident.

    Before the fix this exact call returned the file's contents.
    """

    target = repo_with_bundles / "outside.json"  # .acp/bundles/../../ lands here
    assert json.loads(target.read_text(encoding="utf-8"))["secret"] == "not a bundle"

    supervisor = GitSupervisor(repo_with_bundles)
    with pytest.raises(SupervisorError) as error:
        supervisor.reproduction_bundle("../../outside")
    assert error.value.code == "invalid_qc_id"


def test_a_well_formed_id_that_does_not_exist_still_says_so(repo_with_bundles: Path) -> None:
    """The other control: real ids must not be swept up by the validation.

    A shape check that rejected valid UUIDs would turn a working command into a
    permanent error and look just as green.
    """

    supervisor = GitSupervisor(repo_with_bundles)
    with pytest.raises(SupervisorError) as error:
        supervisor.reproduction_bundle("0f9a1f1e-9d3a-4d0e-8a1b-2c3d4e5f6a7b")
    assert error.value.code == "bundle_not_found"


def test_a_real_bundle_is_still_readable(repo_with_bundles: Path) -> None:
    qc_id = "6b1c2d3e-4f50-4a6b-8c9d-0e1f2a3b4c5d"
    written = {"qc_id": qc_id, "verdict": "pass", "signature": ""}
    (repo_with_bundles / ".acp" / "bundles" / f"{qc_id}.json").write_text(
        json.dumps(written), encoding="utf-8"
    )

    bundle = GitSupervisor(repo_with_bundles).reproduction_bundle(qc_id)

    assert bundle["bundle"]["qc_id"] == qc_id
