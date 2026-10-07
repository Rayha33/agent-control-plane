from __future__ import annotations

import hashlib
import json
import socket
import stat
import subprocess
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from support import init_repo, python_command, write_config

from agent_control_plane.git_supervisor import GitSupervisor, SupervisorError
from agent_control_plane.supervisor import runtime_targets
from agent_control_plane.supervisor.common import canonical_json, sha256

SOURCE_REVISION = "0123456789abcdef0123456789abcdef01234567"


def target_definition(**overrides: Any) -> runtime_targets.RuntimeTargetDefinition:
    entry = {
        "name": "api",
        "port_env": "APP_PORT",
        "driver": "api",
        "database_driver": "postgres",
        "queue_driver": "queue",
        "identity_path": "/.well-known/acp/runtime-target",
        "phases": ["qc", "integration"],
        "required": True,
        "schema_version": "v7",
    }
    entry.update(overrides)
    return runtime_targets.parse_runtime_target_definitions(
        [entry],
        port_envs={"APP_PORT"},
        driver_names={"api", "postgres", "queue"},
    )[0]


def driver_resources() -> list[dict[str, Any]]:
    return [
        {
            "driver": "api",
            "kind": "docker_compose",
            "resource_id": "api-project-attempt-17",
            "state": "active",
        },
        {
            "driver": "postgres",
            "kind": "postgres_schema",
            "resource_id": "acp_attempt_17",
            "state": "active",
        },
        {
            "driver": "queue",
            "kind": "docker_compose",
            "resource_id": "queue-project-attempt-17",
            "state": "active",
        },
    ]


def expected_report(
    *,
    phase: str = "qc",
    attempt_id: str = "attempt-17",
    task_id: str = "task-17",
    claim_token: int = 9,
    source_revision: str = SOURCE_REVISION,
    port: int = 43123,
) -> dict[str, Any]:
    return {
        "contract": runtime_targets.TARGET_CONTRACT,
        "attempt_id": attempt_id,
        "task_id": task_id,
        "claim_token": claim_token,
        "phase": phase,
        "source_revision": source_revision,
        "port": port,
        "driver_resource_id": "api-project-attempt-17",
        "database_namespace": "acp_attempt_17",
        "schema_version": "v7",
        "queue_namespace": "queue-project-attempt-17",
    }


def evaluate_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    report: dict[str, Any] | None = None,
    *,
    probe_status: str = "ok",
    resources: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], dict[str, str], bool]:
    observed = expected_report() if report is None else report
    monkeypatch.setattr(
        runtime_targets,
        "probe_target_identity",
        lambda _port, _path: (observed, probe_status),
    )
    return runtime_targets.runtime_target_phase(
        definitions=(target_definition(),),
        runtime_environment={"APP_PORT": "43123", "ACP_RUNTIME_DIR": str(tmp_path)},
        driver_resources=driver_resources() if resources is None else resources,
        attempt_id="attempt-17",
        task_id="task-17",
        claim_token=9,
        reservation_fence_sha256="a" * 64,
        phase="qc",
        source_revision=SOURCE_REVISION,
        runtime_dir=tmp_path,
        receipt_id="qc-run-17",
    )


def test_matching_app_report_is_only_corroboration_and_manifest_is_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt, environment, blocked = evaluate_target(tmp_path, monkeypatch)

    target = receipt["targets"][0]
    manifest_path = Path(environment["ACP_RUNTIME_TARGETS_FILE"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert blocked is False
    assert receipt["status"] == "complete"
    assert receipt["verified"] is False
    receipt_payload = dict(receipt)
    receipt_hash = receipt_payload.pop("evidence_sha256")
    assert receipt_hash == sha256(canonical_json(receipt_payload).encode("utf-8"))
    assert target["status"] == "corroborated"
    assert target["verified"] is False
    assert target["expected"]["port"] == 43123
    assert target["expected"]["database_namespace"] == "acp_attempt_17"
    assert target["expected"]["queue_namespace"] == "queue-project-attempt-17"
    assert manifest["phase"] == "qc"
    assert manifest["source_revision"] == SOURCE_REVISION
    assert manifest["targets"][0]["endpoint"] == "http://127.0.0.1:43123"
    assert environment["ACP_TARGET_API_URL"] == "http://127.0.0.1:43123"
    assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o400
    assert (
        hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        == environment["ACP_RUNTIME_TARGETS_SHA256"]
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("attempt_id", "old-attempt"),
        ("task_id", "other-task"),
        ("claim_token", 8),
        ("phase", "setup"),
        ("source_revision", "f" * 40),
        ("port", 3000),
        ("driver_resource_id", "another-compose-project"),
        ("database_namespace", "shared-production"),
        ("schema_version", "v6"),
        ("queue_namespace", "shared-worker-queue"),
    ],
)
def test_required_target_identity_mismatch_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: Any,
) -> None:
    report = expected_report()
    report[field] = value
    receipt, _environment, blocked = evaluate_target(tmp_path, monkeypatch, report)

    assert blocked is True
    assert receipt["status"] == "blocked"
    assert receipt["targets"][0]["status"] == "mismatch"
    assert field in receipt["targets"][0]["mismatches"]
    assert receipt["verified"] is False


@pytest.mark.parametrize(
    ("report", "probe_status", "resources"),
    [
        ({**expected_report(), "source_revision": None}, "ok", None),
        ({}, "unavailable", None),
        (expected_report(), "ok", [{**driver_resources()[0], "state": "released"}]),
    ],
)
def test_required_target_missing_evidence_is_unknown_not_verified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    report: dict[str, Any],
    probe_status: str,
    resources: list[dict[str, Any]] | None,
) -> None:
    receipt, _environment, blocked = evaluate_target(
        tmp_path,
        monkeypatch,
        report,
        probe_status=probe_status,
        resources=resources,
    )

    assert blocked is True
    assert receipt["targets"][0]["status"] == "unknown"
    assert receipt["targets"][0]["verified"] is False
    assert receipt["targets"][0]["missing_evidence"]


def test_identity_report_is_allowlisted_and_does_not_persist_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = expected_report() | {"api_key": "never-persist-this", "connection_string": "secret"}
    receipt, _environment, _blocked = evaluate_target(tmp_path, monkeypatch, report)

    serialized = json.dumps(receipt)
    assert "never-persist-this" not in serialized
    assert "connection_string" not in serialized
    assert receipt["targets"][0]["observed"]["attempt_id"] == "attempt-17"

    report = expected_report() | {"driver_resource_id": "private-endpoint-token-value"}
    second_runtime_dir = tmp_path / "second-run"
    second_runtime_dir.mkdir()
    receipt, _environment, blocked = evaluate_target(second_runtime_dir, monkeypatch, report)
    observed_id = receipt["targets"][0]["observed"]["driver_resource_id"]
    assert blocked is True
    assert observed_id["redacted"] is True
    assert "private-endpoint-token-value" not in json.dumps(receipt)


class _TargetIdentityServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        status_code: int,
        content_type: str,
        body: bytes | Callable[[], bytes],
        port: int = 0,
    ) -> None:
        super().__init__(("127.0.0.1", port), _TargetIdentityHandler)
        self.status_code = status_code
        self.content_type = content_type
        self.body = body


class _TargetIdentityHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        server = self.server
        body = server.body() if callable(server.body) else server.body
        self.send_response(server.status_code)
        self.send_header("Content-Type", server.content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


@pytest.mark.parametrize(
    ("status_code", "content_type", "body", "expected_status"),
    [
        (
            200,
            "application/json",
            json.dumps({"contract": runtime_targets.TARGET_CONTRACT}).encode(),
            "ok",
        ),
        (302, "application/json", b"{}", "http_status"),
        (200, "text/plain", b"{}", "content_type"),
        (200, "application/json", b"x" * 8193, "response_too_large"),
        (200, "application/json", b'{"contract":"other"}', "contract_mismatch"),
    ],
)
def test_target_identity_probe_is_loopback_bounded_and_does_not_follow_redirects(
    status_code: int,
    content_type: str,
    body: bytes,
    expected_status: str,
) -> None:
    server = _TargetIdentityServer(status_code, content_type, body)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        _identity, status = runtime_targets.probe_target_identity(
            int(server.server_address[1]), "/.well-known/acp/runtime-target"
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    assert status == expected_status


def test_host_captured_container_identity_is_exposed_but_not_overstated() -> None:
    resource = {
        "driver": "api",
        "kind": "docker_compose",
        "resource_id": "api-project-attempt-17",
        "state": "active",
        "evidence": {
            "proof": {
                "observation": {
                    "stdout": "0123456789ab\nabcdef012345\n",
                    "stderr": "ignored",
                }
            }
        },
    }
    identity = runtime_targets._host_resource_identity(resource)

    assert identity == {
        "status": "host_captured",
        "container_ids": ["0123456789ab", "abcdef012345"],
        "process_identity": None,
    }


def test_single_host_captured_container_must_match_the_app_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resources = driver_resources()
    resources[0]["evidence"] = {"proof": {"observation": {"stdout": "0123456789ab\n"}}}
    report = expected_report() | {"container_id": "0123456789ab"}
    receipt, _environment, blocked = evaluate_target(
        tmp_path, monkeypatch, report, resources=resources
    )

    assert blocked is False
    assert receipt["targets"][0]["expected"]["container_id"] == "0123456789ab"
    assert receipt["targets"][0]["host_identity"]["status"] == "host_captured"
    assert receipt["verified"] is False

    second_runtime_dir = tmp_path / "second-container"
    second_runtime_dir.mkdir()
    report["container_id"] = "fedcba987654"
    receipt, _environment, blocked = evaluate_target(
        second_runtime_dir, monkeypatch, report, resources=resources
    )
    assert blocked is True
    assert "container_id" in receipt["targets"][0]["mismatches"]


@pytest.mark.parametrize(
    ("entry", "port_envs", "driver_names"),
    [
        ({"name": "api", "port_env": "MISSING", "driver": "api"}, {"APP_PORT"}, {"api"}),
        ({"name": "api", "port_env": "APP_PORT", "driver": "missing"}, {"APP_PORT"}, {"api"}),
        (
            {
                "name": "api",
                "port_env": "APP_PORT",
                "driver": "api",
                "identity_path": "https://example.test",
            },
            {"APP_PORT"},
            {"api"},
        ),
        (
            {"name": "api", "port_env": "APP_PORT", "driver": "api", "phases": ["worker"]},
            {"APP_PORT"},
            {"api"},
        ),
        (
            {"name": "api", "port_env": "APP_PORT", "driver": "api", "unexpected": "value"},
            {"APP_PORT"},
            {"api"},
        ),
    ],
)
def test_target_config_rejects_unbound_or_unsafe_declarations(
    entry: dict[str, Any], port_envs: set[str], driver_names: set[str]
) -> None:
    with pytest.raises(SupervisorError) as rejected:
        runtime_targets.parse_runtime_target_definitions(
            [entry], port_envs=port_envs, driver_names=driver_names
        )
    assert rejected.value.code == "invalid_config"


def test_target_names_must_not_alias_environment_variables() -> None:
    entries = [
        {"name": "api-prod", "port_env": "APP_PORT", "driver": "api"},
        {"name": "api_prod", "port_env": "ADMIN_PORT", "driver": "api"},
    ]
    with pytest.raises(SupervisorError) as rejected:
        runtime_targets.parse_runtime_target_definitions(
            entries,
            port_envs={"APP_PORT", "ADMIN_PORT"},
            driver_names={"api"},
        )

    assert rejected.value.code == "invalid_config"


@pytest.mark.parametrize("stale_qc_worktree", [False, True])
def test_qc_and_integration_receive_claim_fenced_target_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stale_qc_worktree: bool,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    init_repo(repo)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    gate = python_command(
        "import hashlib,json,os,stat; from pathlib import Path; "
        "p=Path(os.environ['ACP_RUNTIME_TARGETS_FILE']); raw=p.read_bytes(); "
        "m=json.loads(raw); "
        "assert not (p.stat().st_mode & 0o222); "
        "assert hashlib.sha256(raw).hexdigest()==os.environ['ACP_RUNTIME_TARGETS_SHA256']; "
        "assert m['phase']==os.environ['ACP_PHASE']; "
        "assert m['claim_token']==int(os.environ['ACP_CLAIM_TOKEN']); "
        "assert m['source_revision']==os.environ['ACP_SOURCE_REVISION']; "
        "assert m['targets'][0]['endpoint']==os.environ['ACP_TARGET_API_URL']; "
        "Path(os.environ['ACP_RUNTIME_DIR'],'target-gate-ran').write_text(os.environ['ACP_PHASE'])"
    )
    write_config(repo, qc_commands=[gate], integration_commands=[gate])
    with (repo / "acp.toml").open("a", encoding="utf-8") as config:
        config.write(
            f"\n[runtime.ports]\nAPP_PORT = [{port}, {port}]\n"
            '\n[[runtime.drivers]]\nname = "api"\nkind = "browser_profile"\n'
            '\n[[runtime.targets]]\nname = "api"\nport_env = "APP_PORT"\n'
            'driver = "api"\nphases = ["qc", "integration"]\n'
        )
    supervisor = GitSupervisor(repo)
    created = supervisor.create_task(
        "target identity fixture",
        "Exercise opt-in target identity receipts.",
        ["The tests use the allocated service endpoint"],
        ["alpha.txt"],
    )
    attempt = supervisor.claim(created["id"], "worker")
    server = _TargetIdentityServer(200, "application/json", b"{}", port=port)
    context: dict[str, Any] = {}
    original_restart = supervisor.runtime_restart

    def capture_phase(attempt_id: str, recover: bool = False, *, phase_context=None):
        restarted = original_restart(attempt_id, recover=recover, phase_context=phase_context)
        if phase_context:
            resource = next(
                item for item in supervisor.driver_resources(attempt_id) if item["driver"] == "api"
            )
            context.clear()
            context.update(phase_context)
            context["driver_resource_id"] = resource["resource_id"]
            context["port"] = int(
                supervisor.runtime_environment(attempt_id)["environment"]["APP_PORT"]
            )
        return restarted

    def report() -> bytes:
        source_revision = context["ACP_SOURCE_REVISION"]
        if stale_qc_worktree and context["ACP_PHASE"] == "qc":
            source_revision = "0" * 40
        return json.dumps(
            {
                "contract": runtime_targets.TARGET_CONTRACT,
                "attempt_id": attempt["id"],
                "task_id": attempt["task_id"],
                "claim_token": attempt["claim_token"],
                "phase": context["ACP_PHASE"],
                "source_revision": source_revision,
                "port": context["port"],
                "driver_resource_id": context["driver_resource_id"],
            }
        ).encode("utf-8")

    monkeypatch.setattr(supervisor, "runtime_restart", capture_phase)
    server.body = report

    worktree = Path(attempt["worktree"])
    (worktree / "alpha.txt").write_text("candidate\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(worktree), "add", "alpha.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(worktree), "commit", "-m", "candidate"],
        check=True,
        capture_output=True,
    )
    submission = supervisor.submit(attempt["id"], attempt["claim_token"])

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        qc_result = supervisor.run_qc(submission["id"], "independent-qc")
        if stale_qc_worktree:
            assert qc_result["verdict"] == "block"
            with supervisor.connect() as connection:
                qc = connection.execute(
                    "SELECT id, packet_sha256, results_json FROM qc_runs "
                    "WHERE submission_id = ? ORDER BY finished_at DESC LIMIT 1",
                    (submission["id"],),
                ).fetchone()
            packet_path = (
                supervisor.state_dir / "logs" / f"review-{submission['id']}-{qc['id']}.json"
            )
            packet_bytes = packet_path.read_bytes()
            packet = json.loads(packet_bytes)
            assert hashlib.sha256(packet_bytes).hexdigest() == qc["packet_sha256"]
            qc_results = json.loads(qc["results_json"])
            qc_receipt = next(
                item for item in qc_results if item.get("kind") == "runtime_target_preflight"
            )
            assert qc_receipt["exit_code"] == 1
            assert qc_receipt["targets"][0]["probe_status"] == "ok"
            assert qc_receipt["targets"][0]["mismatches"] == ["source_revision"]
            assert (
                packet["runtime_target_preflight"]["evidence_sha256"]
                == qc_receipt["evidence_sha256"]
            )
            assert any(
                item.get("sha256") == qc_receipt["evidence_sha256"]
                for item in packet["evidence_catalog"]
            )
            assert not (
                Path(attempt["runtime"]["environment"]["ACP_RUNTIME_DIR"]) / "target-gate-ran"
            ).exists()
            return
        assert qc_result["verdict"] == "pass"
        with supervisor.connect() as connection:
            qc = connection.execute(
                "SELECT results_json FROM qc_runs "
                "WHERE submission_id = ? ORDER BY finished_at DESC LIMIT 1",
                (submission["id"],),
            ).fetchone()
        qc_results = json.loads(qc["results_json"])
        qc_receipt = next(
            item for item in qc_results if item.get("kind") == "runtime_target_preflight"
        )
        assert qc_receipt["phase"] == "qc"
        assert qc_receipt["source_revision"] == submission["commit_sha"]
        assert qc_receipt["claim_token"] == attempt["claim_token"]
        assert qc_receipt["targets"][0]["status"] == "corroborated"
        assert qc_receipt["verified"] is False

        integrated = supervisor.integrate(attempt["task_id"])
        assert integrated["verdict"] == "pass", integrated["error"]
        with supervisor.connect() as connection:
            integration = connection.execute(
                "SELECT results_json FROM integrations "
                "WHERE task_id = ? ORDER BY created_at DESC LIMIT 1",
                (attempt["task_id"],),
            ).fetchone()
        integration_results = json.loads(integration["results_json"])
        integration_receipt = next(
            item for item in integration_results if item.get("kind") == "runtime_target_preflight"
        )
        assert integration_receipt["phase"] == "integration"
        assert integration_receipt["source_revision"] == integrated["commit_sha"]
        assert integration_receipt["claim_token"] == attempt["claim_token"]
        assert integration_receipt["targets"][0]["status"] == "corroborated"
        assert integration_receipt["verified"] is False
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
