"""Fail-closed destination policy primitives for the opt-in provider proxy.

This module does not create a proxy or grant a worker network access. The
explicit ``start_registered_no_model_sandbox_worker`` helper can bind a named
policy into an attempt-scoped UDS proxy; generic ``run_worker`` exposes no
provider options. This module provides the part that must be independently
correct before the proxy can safely dial a provider: exact CONNECT-authority
matching, whole-answer IP classification, and a numeric endpoint that can be
connected without another DNS lookup. TLS and certificate validation remain
the worker client's responsibility.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType


class EgressPolicyError(ValueError):
    """A destination cannot be safely authorized or pinned."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class PinnedEndpoint:
    """One validated numeric TCP destination; ``host`` is retained for TLS SNI."""

    host: str
    port: int
    family: int
    sockaddr: tuple[object, ...]


@dataclass(frozen=True)
class PinnedConnection:
    """A connected socket paired with the authority used for TLS validation."""

    endpoint: PinnedEndpoint
    socket: socket.socket


_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

# Snapshot of the IANA IPv4/IPv6 Special-Purpose Address Registries (both last
# updated 2025-10-09). Reject the entire registered blocks, including entries
# marked globally reachable: they are special-use destinations, not arbitrary
# provider endpoints. Refresh this list when updating the registry snapshot.
_IANA_SPECIAL_PURPOSE_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.31.196.0/24",
        "192.52.193.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "192.175.48.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "::/128",
        "::1/128",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "100:0:0:1::/64",
        "2001::/23",
        "2001:2::/48",
        "2001:3::/32",
        "2001:4:112::/48",
        "2001:10::/28",
        "2001:20::/28",
        "2001:30::/28",
        "2001:db8::/32",
        "2002::/16",
        "2620:4f:8000::/48",
        "3fff::/20",
        "5f00::/16",
        "fc00::/7",
        "fe80::/10",
    )
)


def normalize_hostname(host: str) -> str:
    """Return one canonical DNS name; reject IP literals and ambiguous syntax."""
    if not isinstance(host, str) or not host or host != host.strip():
        raise EgressPolicyError("invalid_authority", "hostname is empty or has whitespace")
    if any(character in host for character in "/\\@?#%\x00"):
        raise EgressPolicyError("invalid_authority", "hostname contains authority syntax")
    candidate = host[:-1] if host.endswith(".") else host
    if not candidate or candidate.endswith("."):
        raise EgressPolicyError("invalid_authority", "hostname has an empty DNS label")
    if not candidate.isascii():
        raise EgressPolicyError(
            "invalid_authority",
            "Unicode hostnames must be supplied as an ASCII IDNA A-label",
        )
    ascii_name = candidate.lower()
    if len(ascii_name) > 253 or "." not in ascii_name:
        raise EgressPolicyError("invalid_authority", "hostname must be a fully qualified DNS name")
    labels = ascii_name.split(".")
    if any(not _LABEL.fullmatch(label) for label in labels):
        raise EgressPolicyError("invalid_authority", "hostname contains an invalid DNS label")
    try:
        ipaddress.ip_address(ascii_name)
    except ValueError:
        return ascii_name
    raise EgressPolicyError("invalid_authority", "IP-literal destinations are not permitted")


def parse_connect_authority(authority: str) -> tuple[str, int]:
    """Parse the host:port form used by HTTP CONNECT, without accepting a URL."""
    if not isinstance(authority, str) or not authority or authority != authority.strip():
        raise EgressPolicyError("invalid_authority", "CONNECT authority is empty or has whitespace")
    if authority.startswith("["):
        raise EgressPolicyError("invalid_authority", "bracketed IP literals are not permitted")
    raw_host, separator, raw_port = authority.rpartition(":")
    if not separator or ":" in raw_host:
        raise EgressPolicyError("invalid_authority", "CONNECT authority must be host:port")
    if not raw_port.isascii() or not raw_port.isdecimal():
        raise EgressPolicyError("invalid_authority", "CONNECT port must be decimal")
    if len(raw_port) > 5:
        raise EgressPolicyError("invalid_authority", "CONNECT port text is too long")
    port = int(raw_port)
    if not 1 <= port <= 65535:
        raise EgressPolicyError("invalid_authority", "CONNECT port is out of range")
    return normalize_hostname(raw_host), port


def _validated_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(value, str) or "%" in value:
        raise EgressPolicyError("invalid_dns_answer", "DNS answer is not an unscoped IP address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise EgressPolicyError("invalid_dns_answer", "DNS answer is not an IP address") from error
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        raise EgressPolicyError("destination_address_denied", "IPv4-mapped IPv6 answers are denied")
    if any(
        address.version == network.version and address in network
        for network in _IANA_SPECIAL_PURPOSE_NETWORKS
    ):
        raise EgressPolicyError(
            "destination_address_denied", "IANA special-purpose answers are denied"
        )
    if (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise EgressPolicyError(
            "destination_address_denied",
            "DNS answer is private, local, link-local, multicast, reserved, or non-global",
        )
    return address


def _endpoint(
    host: str, port: int, address: ipaddress.IPv4Address | ipaddress.IPv6Address
) -> PinnedEndpoint:
    if isinstance(address, ipaddress.IPv4Address):
        return PinnedEndpoint(host, port, socket.AF_INET, (str(address), port))
    return PinnedEndpoint(host, port, socket.AF_INET6, (str(address), port, 0, 0))


class ProviderEgressPolicy:
    """Exact host/port allowlist with fail-closed DNS classification and pinning."""

    def __init__(self, destinations: Mapping[str, Iterable[int]]) -> None:
        normalized: dict[str, frozenset[int]] = {}
        for raw_host, raw_ports in destinations.items():
            host = normalize_hostname(raw_host)
            if host in normalized:
                raise EgressPolicyError("invalid_policy", "duplicate normalized destination")
            ports = frozenset(raw_ports)
            if not ports or any(
                not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535
                for port in ports
            ):
                raise EgressPolicyError("invalid_policy", "every destination needs valid TCP ports")
            normalized[host] = ports
        if not normalized:
            raise EgressPolicyError("invalid_policy", "at least one exact destination is required")
        self._destinations = MappingProxyType(normalized)

    @property
    def destinations(self) -> dict[str, tuple[int, ...]]:
        """Return a canonical, detached representation suitable for sealing.

        The mutable input mapping is never retained. This copy is safe to place
        in the authenticated launch request; each hostname and port set is
        normalized and deterministically ordered.
        """

        return {host: tuple(sorted(ports)) for host, ports in sorted(self._destinations.items())}

    def resolve_connect_authority(self, authority: str) -> tuple[PinnedEndpoint, ...]:
        """Authorize a CONNECT authority and pin every system-resolver answer.

        Every returned A/AAAA address must be global. A mixed public/private
        result fails as a whole; callers must connect to one returned numeric
        sockaddr and must not resolve the hostname again before dialing. This is
        one system-resolver invocation, not proof of one authoritative DNS query.
        """
        host, port = parse_connect_authority(authority)
        if port not in self._destinations.get(host, frozenset()):
            raise EgressPolicyError("destination_denied", "CONNECT host or port is not allowlisted")
        try:
            # The trailing dot makes the query absolute and avoids resolver
            # search-suffix expansion changing the allowlisted DNS name.
            records = socket.getaddrinfo(
                f"{host}.", port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
            )
        except OSError as error:
            raise EgressPolicyError("dns_unavailable", "destination DNS lookup failed") from error
        if not records:
            raise EgressPolicyError("dns_empty", "destination DNS lookup returned no addresses")

        endpoints: dict[tuple[int, tuple[object, ...]], PinnedEndpoint] = {}
        for family, _socktype, _protocol, _canonical_name, sockaddr in records:
            if family not in (socket.AF_INET, socket.AF_INET6) or not sockaddr:
                raise EgressPolicyError(
                    "invalid_dns_answer", "DNS returned an unsupported address family"
                )
            address = _validated_address(str(sockaddr[0]))
            if (family == socket.AF_INET) != isinstance(address, ipaddress.IPv4Address):
                raise EgressPolicyError(
                    "invalid_dns_answer", "DNS address family does not match its answer"
                )
            pinned = _endpoint(host, port, address)
            endpoints[(pinned.family, pinned.sockaddr)] = pinned
        if not endpoints:
            raise EgressPolicyError(
                "dns_empty", "destination DNS lookup returned no usable addresses"
            )
        return tuple(
            sorted(
                endpoints.values(),
                key=lambda item: (item.family, int(ipaddress.ip_address(str(item.sockaddr[0])))),
            )
        )

    def connect_authority(self, authority: str, *, timeout: float = 10.0) -> PinnedConnection:
        """Authorize, resolve/classify once, and dial only a validated pin."""
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        endpoints = self.resolve_connect_authority(authority)
        last_error: OSError | None = None
        for endpoint in endpoints:
            try:
                connection = _connect_pinned(endpoint, timeout=timeout)
            except OSError as error:
                last_error = error
                continue
            return PinnedConnection(endpoint, connection)
        raise EgressPolicyError(
            "connection_unavailable", "all vetted destination addresses failed"
        ) from last_error


def _connect_pinned(endpoint: PinnedEndpoint, *, timeout: float) -> socket.socket:
    """Open one TCP socket to an internally vetted numeric sockaddr."""
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if endpoint.family not in (socket.AF_INET, socket.AF_INET6):
        raise ValueError("unsupported pinned address family")
    connection = socket.socket(endpoint.family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    try:
        connection.settimeout(timeout)
        connection.connect(endpoint.sockaddr)
    except BaseException:
        connection.close()
        raise
    return connection
