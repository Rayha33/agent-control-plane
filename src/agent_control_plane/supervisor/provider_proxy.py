"""Single-connection HTTP CONNECT tunnelling for a trusted provider broker.

This module deliberately does not bind a socket or configure a worker. It
provides an attempt-scoped Unix peer-authorizer primitive, but the caller must
still own listener setup, channel distribution, and worker integration. The
CONNECT authority is checked by
``ProviderEgressPolicy`` before any upstream connection is made; after the
200 response, bytes are relayed unchanged so TLS and certificate validation
remain the worker client's responsibility.
"""

from __future__ import annotations

import os
import selectors
import socket
import struct
import sys
import time
from collections.abc import Callable

from .common import SupervisorError
from .provider_egress import EgressPolicyError, PinnedConnection, ProviderEgressPolicy
from .sandbox_attestation import (
    RunningRuntimeAttestation,
    running_attestation_has_collector_provenance,
    running_attestation_is_self_consistent,
    verify_linux_process_membership,
)

_MAX_REQUEST_BYTES = 16 * 1024
_REQUEST_TIMEOUT_SECONDS = 10.0
_RELAY_CHUNK_BYTES = 64 * 1024
_MAX_BUFFERED_BYTES = 1024 * 1024
_DEFAULT_IDLE_TIMEOUT_SECONDS = 300.0
# Linux UAPI value from include/uapi/asm-generic/socket.h. Python versions
# that predate the constant still run on kernels that implement the option.
_SO_PEERPIDFD = getattr(socket, "SO_PEERPIDFD", 77)

_Dialer = Callable[[str], PinnedConnection]
_PeerAuthorizer = Callable[[socket.socket], bool]


class _ConnectRequestError(ValueError):
    pass


def _get_peer_pidfd(channel: socket.socket) -> int:
    """Get a kernel-pinned pidfd for an AF_UNIX peer, or fail closed."""

    return channel.getsockopt(socket.SOL_SOCKET, _SO_PEERPIDFD)


def attempt_scoped_peer_authorizer(
    attestation: RunningRuntimeAttestation,
) -> _PeerAuthorizer:
    """Bind CONNECT authorization to a collector-issued Linux runtime attempt.

    The worker's mapped host UID/GID alone are not a boundary: another
    same-UID host process must also fail the exact attempt-cgroup check. This
    callback does not create or protect the listening socket itself.
    """

    def authorize_peer(channel: socket.socket) -> bool:
        peer_credentials = getattr(socket, "SO_PEERCRED", None)
        if (
            not sys.platform.startswith("linux")
            or peer_credentials is None
            or not running_attestation_has_collector_provenance(attestation)
            or not running_attestation_is_self_consistent(attestation)
            or type(channel) is not socket.socket
        ):
            return False
        peer_pidfd = -1
        authorized = False
        try:
            if (
                channel.family != socket.AF_UNIX
                or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
            ):
                return False
            # SO_PEERCRED supplies a numeric PID. Keep SO_PEERPIDFD open while
            # resolving /proc/<pid>, preventing PID reuse between the kernel's
            # peer-credential snapshot and the first procfs read.
            candidate_pidfd = _get_peer_pidfd(channel)
            if type(candidate_pidfd) is not int or candidate_pidfd < 0:
                return False
            peer_pidfd = candidate_pidfd
            if os.get_inheritable(peer_pidfd):
                return False
            raw_credentials = channel.getsockopt(
                socket.SOL_SOCKET, peer_credentials, struct.calcsize("3i")
            )
            peer_pid, peer_uid, peer_gid = struct.unpack("3i", raw_credentials)
            if peer_pid <= 0 or peer_uid != os.geteuid() or peer_gid != os.getegid():
                return False
            verify_linux_process_membership(
                peer_pid,
                expected_cgroup=attestation.cgroup_path,
            )
            authorized = True
        except (AttributeError, OSError, SupervisorError, struct.error, TypeError, ValueError):
            authorized = False
        finally:
            if peer_pidfd >= 0:
                try:
                    os.close(peer_pidfd)
                except OSError:
                    authorized = False
        return authorized

    return authorize_peer


def _read_connect_request(client: socket.socket) -> str:
    received = bytearray()
    deadline = time.monotonic() + _REQUEST_TIMEOUT_SECONDS
    while b"\r\n\r\n" not in received:
        if len(received) >= _MAX_REQUEST_BYTES:
            raise _ConnectRequestError("CONNECT headers exceed the size limit")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("CONNECT headers timed out")
        client.settimeout(remaining)
        chunk = client.recv(min(4096, _MAX_REQUEST_BYTES - len(received)))
        if not chunk:
            raise _ConnectRequestError("client closed before completing CONNECT headers")
        received.extend(chunk)

    header_end = received.index(b"\r\n\r\n")
    header_block = bytes(received[:header_end])
    early_tunnel_data = bytes(received[header_end + 4 :])
    if early_tunnel_data:
        raise _ConnectRequestError("tunnel bytes arrived with CONNECT headers")
    try:
        lines = header_block.decode("ascii").split("\r\n")
    except UnicodeDecodeError as error:
        raise _ConnectRequestError("CONNECT headers must be ASCII") from error
    if not lines:
        raise _ConnectRequestError("CONNECT request line is missing")
    request_parts = lines[0].split(" ")
    if (
        len(request_parts) != 3
        or request_parts[0] != "CONNECT"
        or request_parts[2] not in {"HTTP/1.0", "HTTP/1.1"}
    ):
        raise _ConnectRequestError("only HTTP/1.0 or HTTP/1.1 CONNECT is supported")
    authority = request_parts[1]
    if not authority:
        raise _ConnectRequestError("CONNECT authority is empty")

    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if (
            not separator
            or not name
            or any(
                not (
                    character.isascii() and (character.isalnum() or character in "!#$%&'*+-.^_`|~")
                )
                for character in name
            )
            or "\r" in value
            or "\n" in value
        ):
            raise _ConnectRequestError("CONNECT header syntax is invalid")
        headers.setdefault(name.lower(), []).append(value.strip(" \t"))

    if "transfer-encoding" in headers:
        raise _ConnectRequestError("CONNECT request bodies are not supported")
    content_lengths = headers.get("content-length", [])
    if content_lengths and content_lengths != ["0"]:
        raise _ConnectRequestError("CONNECT request bodies are not supported")
    if "proxy-authorization" in headers:
        raise _ConnectRequestError("proxy authentication is not supported on this channel")

    host_values = headers.get("host", [])
    if len(host_values) > 1:
        raise _ConnectRequestError("duplicate Host headers are not supported")
    if host_values:
        if host_values[0] != authority:
            raise _ConnectRequestError("Host header does not match CONNECT authority")
    elif request_parts[2] == "HTTP/1.1":
        raise _ConnectRequestError("HTTP/1.1 CONNECT requires a matching Host header")

    client.settimeout(None)
    return authority


def _send_error(client: socket.socket, status: str) -> None:
    try:
        client.sendall(
            f"HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".encode("ascii")
        )
    except OSError:
        pass


def _reject_queued_tunnel_data(client: socket.socket) -> None:
    """Reject data already queued after CONNECT headers but before acceptance."""
    previous_timeout = client.gettimeout()
    try:
        client.setblocking(False)
        try:
            queued = client.recv(1, socket.MSG_PEEK)
        except BlockingIOError:
            return
        if not queued:
            raise _ConnectRequestError("client closed before CONNECT was accepted")
        raise _ConnectRequestError("tunnel bytes were queued before CONNECT was accepted")
    finally:
        client.settimeout(previous_timeout)


def _relay(client: socket.socket, upstream: socket.socket) -> None:
    peers = {client: upstream, upstream: client}
    buffers = {client: bytearray(), upstream: bytearray()}
    read_open = {client, upstream}
    write_shutdown: set[socket.socket] = set()
    selector = selectors.DefaultSelector()
    last_activity = time.monotonic()
    sockets = (client, upstream)

    try:
        for stream in sockets:
            stream.setblocking(False)
        while True:
            if not read_open and not any(buffers.values()):
                return

            for stream in sockets:
                events = 0
                if stream in read_open and len(buffers[peers[stream]]) < _MAX_BUFFERED_BYTES:
                    events |= selectors.EVENT_READ
                if buffers[stream]:
                    events |= selectors.EVENT_WRITE
                try:
                    if events:
                        selector.modify(stream, events)
                    else:
                        selector.unregister(stream)
                except KeyError:
                    if events:
                        selector.register(stream, events)

            remaining = _DEFAULT_IDLE_TIMEOUT_SECONDS - (time.monotonic() - last_activity)
            if remaining <= 0:
                return
            ready = selector.select(remaining)
            if not ready:
                return

            for key, mask in ready:
                stream = key.fileobj
                peer = peers[stream]
                if mask & selectors.EVENT_READ:
                    try:
                        remaining_capacity = _MAX_BUFFERED_BYTES - len(buffers[peer])
                        if remaining_capacity <= 0:
                            continue
                        chunk = stream.recv(min(_RELAY_CHUNK_BYTES, remaining_capacity))
                    except BlockingIOError:
                        chunk = None
                    if chunk is None:
                        continue
                    last_activity = time.monotonic()
                    if chunk:
                        if len(buffers[peer]) + len(chunk) > _MAX_BUFFERED_BYTES:
                            return
                        buffers[peer].extend(chunk)
                    else:
                        read_open.discard(stream)
                        if not buffers[peer] and peer not in write_shutdown:
                            try:
                                peer.shutdown(socket.SHUT_WR)
                            except OSError:
                                pass
                            write_shutdown.add(peer)

                if mask & selectors.EVENT_WRITE and buffers[stream]:
                    try:
                        sent = stream.send(buffers[stream])
                    except BlockingIOError:
                        continue
                    if sent <= 0:
                        return
                    del buffers[stream][:sent]
                    last_activity = time.monotonic()
                    if (
                        not buffers[stream]
                        and peers[stream] not in read_open
                        and stream not in write_shutdown
                    ):
                        try:
                            stream.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        write_shutdown.add(stream)
    finally:
        selector.close()


def serve_connect_connection(
    client: socket.socket,
    policy: ProviderEgressPolicy,
    *,
    authorize_peer: _PeerAuthorizer,
) -> None:
    """Handle one CONNECT request on a caller-authenticated stream channel.

    This function owns and closes both ``client`` and any resulting upstream
    socket. It intentionally handles one CONNECT per channel: a new TLS
    connection, including one created after an HTTP redirect, requires a new
    independently authorized channel and policy check.
    """
    _serve_connect_connection(
        client,
        dial=policy.connect_authority,
        authorize_peer=authorize_peer,
    )


def _serve_connect_connection(
    client: socket.socket,
    *,
    dial: _Dialer,
    authorize_peer: _PeerAuthorizer,
) -> None:
    upstream: socket.socket | None = None
    try:
        try:
            authorized = authorize_peer(client)
        except Exception:
            authorized = False
        if not authorized:
            _send_error(client, "403 Forbidden")
            return
        authority = _read_connect_request(client)
        try:
            pinned = dial(authority)
        except EgressPolicyError as error:
            if error.code == "invalid_authority":
                _send_error(client, "400 Bad Request")
            elif error.code in {"destination_denied", "destination_address_denied"}:
                _send_error(client, "403 Forbidden")
            else:
                _send_error(client, "502 Bad Gateway")
            return
        upstream = pinned.socket
        _reject_queued_tunnel_data(client)
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        _relay(client, upstream)
    except _ConnectRequestError:
        _send_error(client, "400 Bad Request")
    except TimeoutError:
        _send_error(client, "408 Request Timeout")
    except OSError:
        return
    finally:
        if upstream is not None:
            try:
                upstream.close()
            except OSError:
                pass
        try:
            client.close()
        except OSError:
            pass
