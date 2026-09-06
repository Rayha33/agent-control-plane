"""The reported version must be the packaged version, from one source.

Board #1633. `app.py` carried the literal "0.1.0" in two places while
pyproject declared 0.2.0, so `/health` and the OpenAPI document both advertised
a version the artifact did not have. A literal cannot drift from itself, which
is why nothing caught it — these tests give the claim an external referent.
"""

from __future__ import annotations

import pathlib
import tomllib

import pytest

from agent_control_plane import __version__
from agent_control_plane.app import API_VERSION

PYPROJECT = pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml"


def declared_version() -> str:
    with PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)["project"]["version"]


def test_health_reports_the_declared_version(client):
    response = client.get("/health")
    assert response.status_code == 200
    # Deliberately still EXACT equality rather than a subset check. /health gained an
    # "auth" field in board #1624 (it reports insecure-dev when the published
    # development credentials are in use), and the honest way to absorb that is to state
    # the whole expected body — loosening this to `>=` or popping the new key would give
    # up the whole-shape pin that makes this test worth having.
    assert response.json() == {
        "status": "ok",
        "version": declared_version(),
        "auth": "enforced",
    }


def test_openapi_reports_the_declared_version(app):
    assert app.version == declared_version()


def test_resolver_itself_reports_the_declared_version():
    # Tests the resolver directly rather than only through the endpoints, so a
    # future caller that reads API_VERSION is covered too.
    assert API_VERSION == declared_version()


def test_package_attribute_matches_pyproject():
    # The fallback path in _resolve_version() reads __version__, so an
    # uninstalled source checkout must not report something different either.
    assert __version__ == declared_version()


@pytest.mark.parametrize("literal", ["0.1.0"])
def test_no_stale_version_literal_in_source(literal):
    # The specific regression: a hardcoded version string outside pyproject.
    # Scans real source, so it fails if someone reintroduces one anywhere.
    source_root = PYPROJECT.parent / "src"
    offenders = [
        f"{path.relative_to(source_root)}:{number}"
        for path in source_root.rglob("*.py")
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if literal in line and not line.lstrip().startswith("#") and "pyproject" not in line
    ]
    assert offenders == []
