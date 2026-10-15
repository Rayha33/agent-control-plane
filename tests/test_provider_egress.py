from __future__ import annotations

import ipaddress
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from contextlib import ExitStack
from pathlib import Path

import pytest

from agent_control_plane.supervisor import provider_egress
from agent_control_plane.supervisor.provider_egress import (
    EgressPolicyError,
    ProviderEgressPolicy,
    normalize_hostname,
    parse_connect_authority,
)


def policy() -> ProviderEgressPolicy:
    return ProviderEgressPolicy({"API.Example.com.": {443}})


def record(
    address: str, family: int | None = None
) -> tuple[int, int, int, str, tuple[object, ...]]:
    actual_family = family or (socket.AF_INET6 if ":" in address else socket.AF_INET)
    sockaddr: tuple[object, ...]
    if actual_family == socket.AF_INET6:
        sockaddr = (address, 443, 0, 0)
    else:
        sockaddr = (address, 443)
    return actual_family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr


def test_hostname_normalization_is_ascii_only_and_exact() -> None:
    assert normalize_hostname("API.Example.com.") == "api.example.com"
    assert normalize_hostname("xn--bcher-kva.example") == "xn--bcher-kva.example"
    for value in (
        "bücher.example",
        "faß.de",
        "api.example.com/path",
        "api.example.com@evil.test",
        "127.0.0.1",
        "localhost",
    ):
        with pytest.raises(EgressPolicyError):
            normalize_hostname(value)


@pytest.mark.parametrize(
    ("authority", "expected"),
    [
        ("API.Example.com.:443", ("api.example.com", 443)),
        ("api.example.com:8443", ("api.example.com", 8443)),
    ],
)
def test_connect_authority_parsing(authority: str, expected: tuple[str, int]) -> None:
    assert parse_connect_authority(authority) == expected


@pytest.mark.parametrize(
    "authority",
    [
        "api.example.com",
        "api.example.com:0",
        "api.example.com:65536",
        "api.example.com:443/path",
        "[::1]:443",
        "[api.example.com]:443",
    ],
)
def test_connect_authority_rejects_ambiguous_or_ip_literal_forms(authority: str) -> None:
    with pytest.raises(EgressPolicyError):
        parse_connect_authority(authority)


def test_connect_authority_bounds_port_text_before_integer_conversion() -> None:
    with pytest.raises(EgressPolicyError) as result:
        parse_connect_authority(f"api.example.com:{'9' * 5000}")
    assert result.value.code == "invalid_authority"


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.0",
        "10.1.2.3",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "192.0.2.1",
        "192.0.0.9",
        "192.31.196.1",
        "224.0.0.1",
        "::",
        "::1",
        "fe80::1",
        "ff02::1",
        "2001:db8::1",
        "2001:1::1",
        "64:ff9b::808:808",
        "::ffff:8.8.8.8",
    ],
)
def test_private_local_reserved_and_mapped_addresses_are_denied(
    monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    monkeypatch.setattr(provider_egress.socket, "getaddrinfo", lambda *_a, **_kw: [record(address)])

    with pytest.raises(EgressPolicyError) as result:
        policy().resolve_connect_authority("api.example.com:443")
    assert result.value.code == "destination_address_denied"


def test_empty_dns_answers_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(provider_egress.socket, "getaddrinfo", lambda *_a, **_kw: [])

    with pytest.raises(EgressPolicyError) as result:
        policy().resolve_connect_authority("api.example.com:443")
    assert result.value.code == "dns_empty"


def test_mixed_public_and_forbidden_dns_answers_fail_as_a_whole(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        provider_egress.socket,
        "getaddrinfo",
        lambda *_a, **_kw: [record("8.8.8.8"), record("127.0.0.1")],
    )

    with pytest.raises(EgressPolicyError) as result:
        policy().resolve_connect_authority("api.example.com:443")
    assert result.value.code == "destination_address_denied"


def test_host_and_port_allowlist_is_exact_and_precedes_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_lookup(*_args: object, **_kwargs: object) -> list[object]:
        pytest.fail("DNS must not run for a denied CONNECT authority")

    monkeypatch.setattr(provider_egress.socket, "getaddrinfo", forbidden_lookup)
    for authority in (
        "sub.api.example.com:443",
        "api.example.com:80",
        "api.example.com.evil.test:443",
    ):
        with pytest.raises(EgressPolicyError) as result:
            policy().resolve_connect_authority(authority)
        assert result.value.code == "destination_denied"


def test_policy_rejects_invalid_or_empty_destination_config() -> None:
    for destinations in (
        {},
        {"api.example.com": set()},
        {"api.example.com": {0}},
        {"api.example.com": {True}},
    ):
        with pytest.raises(EgressPolicyError) as result:
            ProviderEgressPolicy(destinations)
        assert result.value.code == "invalid_policy"


def test_resolver_returns_numeric_pins_only_after_validating_every_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lookups: list[tuple[object, ...]] = []

    def fake_getaddrinfo(host: str, port: int, **kwargs: object) -> list[tuple[object, ...]]:
        lookups.append((host, port, kwargs.get("type"), kwargs.get("proto")))
        return [record("8.8.8.8"), record("2606:4700:4700::1111")]

    monkeypatch.setattr(provider_egress.socket, "getaddrinfo", fake_getaddrinfo)
    endpoints = policy().resolve_connect_authority("api.example.com:443")

    assert lookups == [("api.example.com.", 443, socket.SOCK_STREAM, socket.IPPROTO_TCP)]
    assert [(endpoint.family, endpoint.sockaddr) for endpoint in endpoints] == [
        (socket.AF_INET, ("8.8.8.8", 443)),
        (socket.AF_INET6, ("2606:4700:4700::1111", 443, 0, 0)),
    ]
    assert all(endpoint.host == "api.example.com" for endpoint in endpoints)


def test_connect_uses_vetted_numeric_sockaddr_without_second_dns_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lookup_calls: list[tuple[object, ...]] = []
    connected: list[tuple[object, ...]] = []

    def fake_getaddrinfo(host: str, port: int, **kwargs: object) -> list[tuple[object, ...]]:
        lookup_calls.append((host, port, kwargs.get("type"), kwargs.get("proto")))
        # Simulate a rebinding answer if production resolves again. The socket
        # must use the public numeric endpoint vetted by the first lookup.
        return [record("8.8.8.8" if len(lookup_calls) == 1 else "127.0.0.1")]

    class FakeSocket:
        def __init__(self, *_args: object) -> None:
            self.closed = False

        def settimeout(self, _timeout: float) -> None:
            pass

        def connect(self, address: tuple[object, ...]) -> None:
            connected.append(address)

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(provider_egress.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(provider_egress.socket, "socket", FakeSocket)
    connection = policy().connect_authority("api.example.com:443")

    assert lookup_calls == [("api.example.com.", 443, socket.SOCK_STREAM, socket.IPPROTO_TCP)]
    assert connected == [("8.8.8.8", 443)]
    assert connection.endpoint.sockaddr == ("8.8.8.8", 443)
    assert not connection.socket.closed


def _dns_wire_name(name: str) -> bytes:
    return (
        b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.split(".")) + b"\0"
    )


def _run_cname_dns_child() -> int:
    """Exercise getaddrinfo against a CNAME server in private mount/net namespaces."""
    subprocess.run(["mount", "--make-rprivate", "/"], check=True, capture_output=True, timeout=3)
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True, capture_output=True, timeout=3)

    temp_root = Path(os.environ["ACP_CNAME_RESOLVER_TMP"])
    with ExitStack() as mounted:
        resolver_config = temp_root / "resolv.conf"
        resolver_config.write_text(
            "nameserver 127.0.0.1\noptions attempts:1 timeout:1\n", encoding="ascii"
        )
        nsswitch_config = temp_root / "nsswitch.conf"
        nss_lines = Path("/etc/nsswitch.conf").read_text(encoding="utf-8").splitlines()
        nss_lines = [line for line in nss_lines if not line.lstrip().startswith("hosts:")]
        nss_lines.append("hosts: files dns")
        nsswitch_config.write_text("\n".join(nss_lines) + "\n", encoding="utf-8")

        resolver_target = Path("/etc/resolv.conf").resolve(strict=True)
        for source, target in zip(
            (resolver_config, nsswitch_config),
            (resolver_target, Path("/etc/nsswitch.conf")),
            strict=True,
        ):
            subprocess.run(
                ["mount", "--bind", str(source), str(target)],
                check=True,
                capture_output=True,
                timeout=3,
            )
            mounted.callback(
                subprocess.run,
                ["umount", str(target)],
                check=True,
                capture_output=True,
                timeout=3,
            )

        queries: list[tuple[str, int]] = []
        errors: list[str] = []
        stop = threading.Event()
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 53))
        server.settimeout(0.1)

        def answer_dns() -> None:
            try:
                while not stop.is_set():
                    try:
                        packet, peer = server.recvfrom(4096)
                    except TimeoutError:
                        continue
                    position = 12
                    labels: list[str] = []
                    while packet[position] != 0:
                        length = packet[position]
                        position += 1
                        labels.append(packet[position : position + length].decode("ascii"))
                        position += length
                    position += 1
                    query_type, _query_class = struct.unpack("!HH", packet[position : position + 4])
                    question_end = position + 4
                    query_name = ".".join(labels).lower()
                    queries.append((query_name, query_type))

                    cname_targets = {
                        "api.example.com": "gateway.test",
                        "mixed.example.com": "mixed-gateway.test",
                    }
                    target_addresses = {
                        "gateway.test": {1: "8.8.8.8", 28: "2606:4700:4700::1111"},
                        "mixed-gateway.test": {1: "8.8.8.8", 28: "::1"},
                    }
                    target_name = cname_targets.get(query_name, query_name)
                    answers = []
                    if query_name in cname_targets:
                        target_wire_name = _dns_wire_name(target_name)
                        answers.append(
                            b"\xc0\x0c"
                            + struct.pack("!HHIH", 5, 1, 60, len(target_wire_name))
                            + target_wire_name
                        )
                    address_text = target_addresses.get(target_name, {}).get(query_type)
                    if address_text is not None:
                        address = ipaddress.ip_address(address_text).packed
                        owner = (
                            b"\xc0\x0c"
                            if query_name == target_name
                            else _dns_wire_name(target_name)
                        )
                        answers.append(
                            owner + struct.pack("!HHIH", query_type, 1, 60, len(address)) + address
                        )

                    flags = 0x8580  # response, authoritative, recursion-desired/available
                    response = (
                        packet[:2]
                        + struct.pack("!HHHHH", flags, 1, len(answers), 0, 0)
                        + packet[12:question_end]
                        + b"".join(answers)
                    )
                    server.sendto(response, peer)
            except BaseException as error:
                errors.append(f"{type(error).__name__}: {error}")

        thread = threading.Thread(target=answer_dns, daemon=True)
        thread.start()
        try:
            egress_policy = ProviderEgressPolicy(
                {"api.example.com": {443}, "mixed.example.com": {443}}
            )
            endpoints = egress_policy.resolve_connect_authority("api.example.com:443")
            with pytest.raises(EgressPolicyError) as denied:
                egress_policy.resolve_connect_authority("mixed.example.com:443")
        finally:
            stop.set()
            thread.join(timeout=2)
            server.close()

        assert not errors, errors
        assert thread.is_alive() is False
        assert denied.value.code == "destination_address_denied"
        for queried_host in ("api.example.com", "mixed.example.com"):
            assert {query_type for name, query_type in queries if name == queried_host} >= {
                1,
                28,
            }
        assert all(
            name
            in {
                "api.example.com",
                "gateway.test",
                "mixed.example.com",
                "mixed-gateway.test",
            }
            for name, _ in queries
        )
        assert {(endpoint.family, endpoint.sockaddr) for endpoint in endpoints} == {
            (socket.AF_INET, ("8.8.8.8", 443)),
            (socket.AF_INET6, ("2606:4700:4700::1111", 443, 0, 0)),
        }
    return 0


def test_system_resolver_follows_cname_and_policy_pins_a_and_aaaa() -> None:
    if os.environ.get("ACP_RUN_LIVE_CNAME_DNS") != "1":
        pytest.skip("requires explicit opt-in in a disposable root Linux guest")
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        pytest.skip("requires Linux root for private network and mount namespaces")
    unshare = shutil.which("unshare")
    if unshare is None:
        pytest.skip("requires unshare in the disposable Linux guest")

    repo_root = Path(__file__).resolve().parents[1]
    python_path = os.pathsep.join(
        part for part in (str(repo_root / "src"), os.environ.get("PYTHONPATH", "")) if part
    )
    with tempfile.TemporaryDirectory(prefix="acp-cname-dns-") as temp_dir:
        env = {
            **os.environ,
            "ACP_CNAME_RESOLVER_TMP": temp_dir,
            "PYTHONPATH": python_path,
        }
        result = subprocess.run(
            [
                unshare,
                "--mount",
                "--net",
                "--fork",
                "--kill-child",
                sys.executable,
                str(Path(__file__).resolve()),
                "--cname-dns-child",
            ],
            capture_output=True,
            check=False,
            env=env,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, f"CNAME DNS probe failed:\n{result.stdout}\n{result.stderr}"


if __name__ == "__main__" and sys.argv[1:] == ["--cname-dns-child"]:
    raise SystemExit(_run_cname_dns_child())
