from __future__ import annotations

import socket

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
    lookup_calls = 0
    connected: list[tuple[object, ...]] = []

    def fake_getaddrinfo(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
        nonlocal lookup_calls
        lookup_calls += 1
        # A hypothetical later DNS response is forbidden. The socket must use
        # the numeric endpoint already returned by the first validated lookup.
        return [record("8.8.8.8")]

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

    assert lookup_calls == 1
    assert connected == [("8.8.8.8", 443)]
    assert connection.endpoint.sockaddr == ("8.8.8.8", 443)
    assert not connection.socket.closed
