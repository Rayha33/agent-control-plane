from __future__ import annotations

import os
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path
from shutil import which
from types import SimpleNamespace

import pytest

from agent_control_plane.supervisor import provider_egress, provider_proxy
from agent_control_plane.supervisor.provider_egress import (
    PinnedConnection,
    PinnedEndpoint,
    ProviderEgressPolicy,
)
from agent_control_plane.supervisor.provider_proxy import (
    _ConnectRequestError,
    _read_connect_request,
    _serve_connect_connection,
    attempt_scoped_peer_authorizer,
    serve_connect_connection,
)


def _policy() -> ProviderEgressPolicy:
    return ProviderEgressPolicy({"api.example.com": {443}})


def _require_peer_pidfd(channel: socket.socket) -> None:
    try:
        peer_pidfd = provider_proxy._get_peer_pidfd(channel)
    except OSError as error:
        pytest.skip(f"Linux kernel does not provide SO_PEERPIDFD: {error}")
    try:
        os.fstat(peer_pidfd)
    finally:
        os.close(peer_pidfd)


def _request(authority: str = "api.example.com:443", *, headers: bytes = b"") -> bytes:
    return (
        b"CONNECT "
        + authority.encode("ascii")
        + b" HTTP/1.1\r\nHost: "
        + authority.encode("ascii")
        + b"\r\n"
        + headers
        + b"\r\n"
    )


def _read_response_headers(client: socket.socket) -> bytes:
    response = bytearray()
    client.settimeout(3)
    while b"\r\n\r\n" not in response:
        chunk = client.recv(4096)
        if not chunk:
            break
        response.extend(chunk)
    return bytes(response)


def _start_handler(
    proxy_channel: socket.socket,
    *,
    dial,
    authorized: bool = True,
) -> threading.Thread:
    thread = threading.Thread(
        target=_serve_connect_connection,
        args=(proxy_channel,),
        kwargs={"dial": dial, "authorize_peer": lambda _channel: authorized},
        daemon=True,
    )
    thread.start()
    return thread


def _make_test_certificate(tmp_path: Path) -> tuple[Path, Path]:
    openssl = which("openssl")
    if openssl is None:
        pytest.skip("OpenSSL is needed for the local TLS CONNECT test")
    config_path = tmp_path / "openssl.cnf"
    config_path.write_text(
        "[req]\n"
        "distinguished_name=dn\n"
        "x509_extensions=v3_req\n"
        "prompt=no\n"
        "[dn]\n"
        "CN=api.example.com\n"
        "[v3_req]\n"
        "subjectAltName=@alt_names\n"
        "[alt_names]\n"
        "DNS.1=api.example.com\n",
        encoding="ascii",
    )
    certificate_path = tmp_path / "server.crt"
    key_path = tmp_path / "server.key"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key_path),
            "-out",
            str(certificate_path),
            "-days",
            "1",
            "-config",
            str(config_path),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return certificate_path, key_path


def test_peer_authorization_precedes_request_parsing_and_dial() -> None:
    worker, proxy = socket.socketpair()
    dial_calls: list[str] = []
    thread = _start_handler(
        proxy, dial=lambda authority: dial_calls.append(authority), authorized=False
    )

    response = _read_response_headers(worker)

    assert response.startswith(b"HTTP/1.1 403 Forbidden\r\n")
    assert dial_calls == []
    thread.join(timeout=2)
    assert not thread.is_alive()
    worker.close()


@pytest.mark.skipif(
    not sys.platform.startswith("linux") or not hasattr(socket, "SO_PEERCRED"),
    reason="attempt peer authorization requires Linux SO_PEERCRED",
)
def test_attempt_peer_authorizer_rejects_unproven_receipt() -> None:
    worker, proxy = socket.socketpair()
    try:
        authorizer = attempt_scoped_peer_authorizer(SimpleNamespace(cgroup_path="/attempt.scope"))
        assert not authorizer(proxy)
    finally:
        worker.close()
        proxy.close()


@pytest.mark.skipif(
    not sys.platform.startswith("linux") or not hasattr(socket, "SO_PEERCRED"),
    reason="attempt peer authorization requires Linux SO_PEERCRED",
)
def test_attempt_peer_authorizer_requires_peer_in_exact_attempt_cgroup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        provider_proxy, "running_attestation_has_collector_provenance", lambda _: True
    )
    monkeypatch.setattr(provider_proxy, "running_attestation_is_self_consistent", lambda _: True)
    worker, proxy = socket.socketpair()
    try:
        _require_peer_pidfd(proxy)
        authorizer = attempt_scoped_peer_authorizer(
            SimpleNamespace(cgroup_path="/agent-control-plane-unreachable-test/worker.scope")
        )
        # The local process has the same host UID/GID as this test server, but
        # its live cgroup is not the nominated attempt scope.
        assert not authorizer(proxy)
    finally:
        worker.close()
        proxy.close()


@pytest.mark.skipif(
    not sys.platform.startswith("linux") or not hasattr(socket, "SO_PEERCRED"),
    reason="attempt peer authorization requires Linux SO_PEERCRED",
)
def test_attempt_peer_authorizer_holds_peer_pidfd_through_real_proc_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        provider_proxy, "running_attestation_has_collector_provenance", lambda _: True
    )
    monkeypatch.setattr(provider_proxy, "running_attestation_is_self_consistent", lambda _: True)
    observed: dict[str, object] = {}
    unified_cgroups = []
    for line in Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines():
        fields = line.split(":", 2)
        if len(fields) == 3 and fields[0] == "0" and fields[1] == "":
            unified_cgroups.append(fields[2])
    if len(unified_cgroups) != 1 or not unified_cgroups[0].startswith("/"):
        pytest.skip("real peer verification test requires a unified cgroup v2 entry")
    expected_cgroup = unified_cgroups[0]
    worker, proxy = socket.socketpair()
    opened_pidfds: list[int] = []
    get_peer_pidfd = provider_proxy._get_peer_pidfd
    real_verifier = provider_proxy.verify_linux_process_membership

    def track_peer_pidfd(channel: socket.socket) -> int:
        peer_pidfd = get_peer_pidfd(channel)
        opened_pidfds.append(peer_pidfd)
        return peer_pidfd

    def verify_peer(pid: int, *, expected_cgroup: str) -> str:
        assert len(opened_pidfds) == 1
        # The PIDFD must remain live through the procfs identity/cgroup read.
        os.fstat(opened_pidfds[0])
        assert not os.get_inheritable(opened_pidfds[0])
        fdinfo = Path(f"/proc/self/fdinfo/{opened_pidfds[0]}").read_text(encoding="ascii")
        assert f"Pid:\t{pid}\n" in fdinfo
        observed["pid"] = pid
        observed["cgroup"] = expected_cgroup
        return real_verifier(pid, expected_cgroup=expected_cgroup)

    try:
        _require_peer_pidfd(proxy)
        monkeypatch.setattr(provider_proxy, "_get_peer_pidfd", track_peer_pidfd)
        monkeypatch.setattr(provider_proxy, "verify_linux_process_membership", verify_peer)
        authorizer = attempt_scoped_peer_authorizer(SimpleNamespace(cgroup_path=expected_cgroup))
        assert authorizer(proxy)
        assert observed["pid"] == os.getpid()
        assert observed["cgroup"] == expected_cgroup
        with pytest.raises(OSError):
            os.fstat(opened_pidfds[0])
    finally:
        worker.close()
        proxy.close()


@pytest.mark.skipif(
    not sys.platform.startswith("linux") or not hasattr(socket, "SO_PEERCRED"),
    reason="attempt peer authorization requires Linux SO_PEERCRED",
)
def test_attempt_peer_authorizer_rejects_peer_reaped_after_pidfd_acquisition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        provider_proxy, "running_attestation_has_collector_provenance", lambda _: True
    )
    monkeypatch.setattr(provider_proxy, "running_attestation_is_self_consistent", lambda _: True)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server_path = tmp_path / "peer.sock"
    server.bind(str(server_path))
    server.listen(1)
    server.settimeout(5)
    connect_script = (
        "import socket,sys,time; "
        "peer=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); "
        "peer.connect(sys.argv[1]); time.sleep(30)"
    )
    child = subprocess.Popen(
        [sys.executable, "-c", connect_script, str(server_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    channel: socket.socket | None = None
    opened_pidfds: list[int] = []
    verified_pids: list[int] = []
    get_peer_pidfd = provider_proxy._get_peer_pidfd
    real_verifier = provider_proxy.verify_linux_process_membership

    def acquire_then_reap(peer_channel: socket.socket) -> int:
        peer_pidfd = get_peer_pidfd(peer_channel)
        opened_pidfds.append(peer_pidfd)
        child.terminate()
        child.wait(timeout=5)
        fdinfo = Path(f"/proc/self/fdinfo/{peer_pidfd}").read_text(encoding="ascii")
        assert "Pid:\t-1\n" in fdinfo
        return peer_pidfd

    def track_verification(pid: int, *, expected_cgroup: str) -> str:
        verified_pids.append(pid)
        return real_verifier(pid, expected_cgroup=expected_cgroup)

    try:
        channel, _ = server.accept()
        _require_peer_pidfd(channel)
        monkeypatch.setattr(provider_proxy, "_get_peer_pidfd", acquire_then_reap)
        monkeypatch.setattr(provider_proxy, "verify_linux_process_membership", track_verification)
        authorizer = attempt_scoped_peer_authorizer(
            SimpleNamespace(cgroup_path="/user.slice/attempt.scope")
        )
        assert not authorizer(channel)
        assert verified_pids == [child.pid]
        with pytest.raises(OSError):
            os.fstat(opened_pidfds[0])
    finally:
        if channel is not None:
            channel.close()
        server.close()
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=5)


@pytest.mark.skipif(
    not sys.platform.startswith("linux") or not hasattr(socket, "SO_PEERCRED"),
    reason="attempt peer authorization requires Linux SO_PEERCRED",
)
def test_attempt_peer_authorizer_fails_closed_without_peer_pidfd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        provider_proxy, "running_attestation_has_collector_provenance", lambda _: True
    )
    monkeypatch.setattr(provider_proxy, "running_attestation_is_self_consistent", lambda _: True)
    process_checks: list[int] = []

    def unsupported(_channel: socket.socket) -> int:
        raise OSError("SO_PEERPIDFD is unavailable")

    monkeypatch.setattr(provider_proxy, "_get_peer_pidfd", unsupported)
    monkeypatch.setattr(
        provider_proxy,
        "verify_linux_process_membership",
        lambda pid, **_kwargs: process_checks.append(pid),
    )
    worker, proxy = socket.socketpair()
    try:
        authorizer = attempt_scoped_peer_authorizer(
            SimpleNamespace(cgroup_path="/user.slice/attempt.scope")
        )
        assert not authorizer(proxy)
        assert process_checks == []
    finally:
        worker.close()
        proxy.close()


def test_disallowed_authority_is_rejected_before_dns_or_dial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker, proxy = socket.socketpair()

    def forbidden_lookup(*_args: object, **_kwargs: object) -> list[object]:
        pytest.fail("DNS must not run for a disallowed CONNECT authority")

    monkeypatch.setattr(provider_egress.socket, "getaddrinfo", forbidden_lookup)
    thread = _start_handler(proxy, dial=_policy().connect_authority)
    worker.sendall(_request("outside.example:443"))

    response = _read_response_headers(worker)

    assert response.startswith(b"HTTP/1.1 403 Forbidden\r\n")
    thread.join(timeout=2)
    assert not thread.is_alive()
    worker.close()


def test_connect_body_and_ambiguous_headers_are_rejected_before_dial() -> None:
    worker, proxy = socket.socketpair()
    dial_calls: list[str] = []
    thread = _start_handler(proxy, dial=lambda authority: dial_calls.append(authority))
    worker.sendall(_request(headers=b"Transfer-Encoding: chunked\r\n"))

    response = _read_response_headers(worker)

    assert response.startswith(b"HTTP/1.1 400 Bad Request\r\n")
    assert dial_calls == []
    thread.join(timeout=2)
    assert not thread.is_alive()
    worker.close()


def test_tunnel_bytes_co_read_with_connect_headers_are_rejected() -> None:
    worker, proxy = socket.socketpair()
    worker.sendall(_request() + b"early-tunnel-bytes")

    with pytest.raises(_ConnectRequestError, match="with CONNECT headers"):
        _read_connect_request(proxy)

    worker.close()
    proxy.close()


def test_tunnel_bytes_queued_while_upstream_dial_is_in_flight_are_rejected() -> None:
    worker, proxy = socket.socketpair()
    upstream, target = socket.socketpair()
    dial_started = threading.Event()
    allow_dial = threading.Event()
    endpoint = PinnedEndpoint("api.example.com", 443, socket.AF_INET, ("192.0.2.10", 443))

    def dial(_authority: str) -> PinnedConnection:
        dial_started.set()
        assert allow_dial.wait(3)
        return PinnedConnection(endpoint, upstream)

    thread = _start_handler(proxy, dial=dial)
    worker.sendall(_request())
    assert dial_started.wait(2)
    worker.sendall(b"bytes queued while dial is blocked")
    allow_dial.set()

    response = _read_response_headers(worker)

    assert response.startswith(b"HTTP/1.1 400 Bad Request\r\n")
    target.settimeout(2)
    assert target.recv(1) == b""
    thread.join(timeout=2)
    assert not thread.is_alive()
    worker.close()
    target.close()


class _RelayTestSocket:
    def __init__(self, incoming: bytes = b"") -> None:
        self.incoming = bytearray(incoming)
        self.recv_sizes: list[int] = []
        self.sent = bytearray()

    def setblocking(self, _enabled: bool) -> None:
        pass

    def recv(self, size: int) -> bytes:
        self.recv_sizes.append(size)
        if len(self.recv_sizes) == 16:
            size = min(size, 65_528)
        chunk = bytes(self.incoming[:size])
        del self.incoming[:size]
        return chunk

    def send(self, data: bytes | bytearray) -> int:
        self.sent.extend(data)
        return len(data)

    def shutdown(self, _how: int) -> None:
        pass


class _RelayTestSelector:
    def __init__(self, plan: list[tuple[object, int]]) -> None:
        self.plan = iter(plan)
        self.interests: dict[object, int] = {}

    def register(self, stream: object, events: int) -> None:
        self.interests[stream] = events

    def modify(self, stream: object, events: int) -> None:
        if stream not in self.interests:
            raise KeyError(stream)
        self.interests[stream] = events

    def unregister(self, stream: object) -> None:
        del self.interests[stream]

    def select(self, _timeout: float) -> list[tuple[SimpleNamespace, int]]:
        stream, mask = next(self.plan)
        assert self.interests[stream] & mask
        return [(SimpleNamespace(fileobj=stream), mask)]

    def close(self) -> None:
        pass


def test_relay_caps_reads_to_remaining_buffer_capacity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = bytes(index % 251 for index in range(provider_proxy._MAX_BUFFERED_BYTES + 65_536))
    client = _RelayTestSocket(payload)
    upstream = _RelayTestSocket()
    read = provider_proxy.selectors.EVENT_READ
    write = provider_proxy.selectors.EVENT_WRITE
    plan = [(client, read)] * 17 + [
        (upstream, write),
        (client, read),
        (client, read),
        (upstream, write),
        (upstream, read),
    ]
    selector = _RelayTestSelector(plan)
    monkeypatch.setattr(provider_proxy.selectors, "DefaultSelector", lambda: selector)

    provider_proxy._relay(client, upstream)

    assert client.recv_sizes[16] == 8
    assert upstream.sent == payload


def test_authorized_connect_relays_bidirectionally_and_preserves_half_close() -> None:
    worker, proxy = socket.socketpair()
    upstream, target = socket.socketpair()
    dialed: list[str] = []
    endpoint = PinnedEndpoint("api.example.com", 443, socket.AF_INET, ("192.0.2.10", 443))

    def dial(authority: str) -> PinnedConnection:
        dialed.append(authority)
        return PinnedConnection(endpoint, upstream)

    thread = _start_handler(proxy, dial=dial)
    worker.sendall(_request())
    response = _read_response_headers(worker)
    assert response == b"HTTP/1.1 200 Connection Established\r\n\r\n"
    assert dialed == ["api.example.com:443"]

    worker.sendall(b"client-tls-record")
    assert target.recv(64) == b"client-tls-record"
    worker.shutdown(socket.SHUT_WR)
    assert target.recv(1) == b""
    target.sendall(b"server-tls-record")
    assert worker.recv(64) == b"server-tls-record"
    target.shutdown(socket.SHUT_WR)

    assert worker.recv(1) == b""
    thread.join(timeout=2)
    assert not thread.is_alive()
    worker.close()
    target.close()


def test_tls_redirect_requires_a_second_connect_and_only_that_authority_is_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    certificate_path, key_path = _make_test_certificate(tmp_path)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certfile=certificate_path, keyfile=key_path)
    target_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    target_listener.bind(("127.0.0.1", 0))
    target_listener.settimeout(5)
    target_listener.listen(1)
    target_address = target_listener.getsockname()
    target_errors: list[BaseException] = []

    def run_tls_target() -> None:
        try:
            raw_connection, _address = target_listener.accept()
            with server_context.wrap_socket(raw_connection, server_side=True) as tls:
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    request.extend(tls.recv(4096))
                assert request.startswith(b"GET / HTTP/1.1\r\n")
                tls.sendall(
                    b"HTTP/1.1 302 Found\r\n"
                    b"Location: https://blocked.example/redirected\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
        except BaseException as error:
            target_errors.append(error)
        finally:
            target_listener.close()

    target_thread = threading.Thread(target=run_tls_target, daemon=True)
    target_thread.start()
    resolver_calls: list[str] = []
    dial_calls: list[tuple[str, int]] = []

    def fake_resolver(host: str, port: int, **_kwargs: object) -> list[tuple[object, ...]]:
        resolver_calls.append(host)
        assert host == "api.example.com."
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", port))]

    def test_only_dial(endpoint: PinnedEndpoint, *, timeout: float) -> socket.socket:
        # The production classifier sees a public address. Only this test
        # redirects the dial to its local TLS fixture.
        dial_calls.append((str(endpoint.sockaddr[0]), endpoint.port))
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.settimeout(timeout)
        connection.connect(target_address)
        return connection

    monkeypatch.setattr(provider_egress.socket, "getaddrinfo", fake_resolver)
    monkeypatch.setattr(provider_egress, "_connect_pinned", test_only_dial)
    policy = ProviderEgressPolicy({"api.example.com": {443}})

    worker, proxy = socket.socketpair()
    first_handler = threading.Thread(
        target=serve_connect_connection,
        args=(proxy, policy),
        kwargs={"authorize_peer": lambda _channel: True},
        daemon=True,
    )
    first_handler.start()
    worker.settimeout(5)
    worker.sendall(_request())
    assert _read_response_headers(worker) == b"HTTP/1.1 200 Connection Established\r\n\r\n"
    client_context = ssl.create_default_context()
    client_context.load_verify_locations(cafile=str(certificate_path))
    with client_context.wrap_socket(worker, server_hostname="api.example.com") as tls_client:
        tls_client.sendall(b"GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
        redirect_response = bytearray()
        while b"\r\n\r\n" not in redirect_response:
            redirect_response.extend(tls_client.recv(4096))
    first_handler.join(timeout=2)
    target_thread.join(timeout=2)
    assert not first_handler.is_alive()
    assert not target_thread.is_alive()
    assert target_errors == []
    assert redirect_response.startswith(b"HTTP/1.1 302 Found\r\n")
    assert b"Location: https://blocked.example/redirected\r\n" in redirect_response

    redirected_worker, redirected_proxy = socket.socketpair()
    second_handler = threading.Thread(
        target=serve_connect_connection,
        args=(redirected_proxy, policy),
        kwargs={"authorize_peer": lambda _channel: True},
        daemon=True,
    )
    second_handler.start()
    redirected_worker.settimeout(3)
    redirected_worker.sendall(_request("blocked.example:443"))
    denied_response = _read_response_headers(redirected_worker)
    second_handler.join(timeout=2)

    assert denied_response.startswith(b"HTTP/1.1 403 Forbidden\r\n")
    assert resolver_calls == ["api.example.com."]
    assert dial_calls == [("8.8.8.8", 443)]
    assert not second_handler.is_alive()
    redirected_worker.close()
