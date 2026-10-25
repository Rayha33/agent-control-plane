"""Single-connection HTTP CONNECT tunnelling for a trusted provider broker.

This module provides attempt-scoped Unix listener and peer-authorizer
primitives, but the caller must still own their lifecycle, channel distribution,
and worker integration. The
CONNECT authority is checked by
``ProviderEgressPolicy`` before any upstream connection is made; after the
200 response, bytes are relayed unchanged so TLS and certificate validation
remain the worker client's responsibility.
"""

from __future__ import annotations

import math
import os
import selectors
import socket
import stat
import struct
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

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
_RELAY_CANCEL_POLL_SECONDS = 0.1
# Use the narrower sockaddr_un.sun_path size across Linux and Darwin.
_MAX_UNIX_SOCKET_PATH_BYTES = 103
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


def require_peer_pidfd_support() -> None:
    """Reject provider-proxy mode unless the host kernel can pin UDS peers."""

    if not sys.platform.startswith("linux") or getattr(socket, "SO_PEERCRED", None) is None:
        raise SupervisorError(
            "provider_proxy_peer_pidfd_unsupported",
            "provider proxy requires Linux SO_PEERCRED and SO_PEERPIDFD support",
        )

    peer_pidfd: int | None = None
    try:
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            peer_pidfd = _get_peer_pidfd(left)
            if type(peer_pidfd) is not int or peer_pidfd < 0:
                raise SupervisorError(
                    "provider_proxy_peer_pidfd_unsupported",
                    "provider proxy kernel peer-pidfd probe returned an invalid descriptor",
                )
            if os.get_inheritable(peer_pidfd):
                raise SupervisorError(
                    "provider_proxy_peer_pidfd_unsupported",
                    "provider proxy kernel peer-pidfd descriptor is inheritable",
                )
        finally:
            try:
                left.close()
            finally:
                right.close()
    except SupervisorError:
        raise
    except (AttributeError, OSError, TypeError, ValueError) as error:
        raise SupervisorError(
            "provider_proxy_peer_pidfd_unsupported",
            "provider proxy requires kernel SO_PEERPIDFD support",
        ) from error
    finally:
        if type(peer_pidfd) is int and peer_pidfd >= 0:
            try:
                os.close(peer_pidfd)
            except OSError as error:
                raise SupervisorError(
                    "provider_proxy_peer_pidfd_unsupported",
                    "provider proxy kernel peer-pidfd probe descriptor could not be closed",
                ) from error


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


class AttemptProviderProxyListener:
    """Own one attempt-directory Unix listener and its exact socket entry.

    The caller must create a fresh mode-0700 directory and must authorize each
    accepted stream before reading it (normally with
    :func:`attempt_scoped_peer_authorizer` and
    :func:`serve_connect_connection`). This object owns bind/listen and safe
    inode-checked unlink under an exclusive-directory-owner assumption. Every
    parent must be owned by root or the current euid and not group/world writable,
    except sticky directories. It does not defend against concurrent same-UID
    mutation. It does not create a thread, mount the directory, configure a
    worker, or provide a lifecycle outside the caller's attempt.
    """

    socket_name = "provider.sock"

    def __init__(self, directory: Path, *, backlog: int = 16) -> None:
        if type(backlog) is not int or backlog < 1:
            raise SupervisorError(
                "provider_proxy_backlog_invalid", "listener backlog must be positive"
            )
        if not isinstance(directory, (str, Path)):
            raise SupervisorError(
                "provider_proxy_directory_invalid", "listener directory is invalid"
            )
        path = Path(directory)
        if not path.is_absolute():
            raise SupervisorError(
                "provider_proxy_directory_invalid", "listener directory must be absolute"
            )
        try:
            raw_info = path.lstat()
        except OSError as error:
            raise SupervisorError(
                "provider_proxy_directory_invalid", "listener directory is unavailable"
            ) from error
        if stat.S_ISLNK(raw_info.st_mode):
            raise SupervisorError(
                "provider_proxy_directory_unsafe", "listener directory is a symlink"
            )
        try:
            canonical_path = path.resolve(strict=True)
            directory_info = canonical_path.lstat()
        except OSError as error:
            raise SupervisorError(
                "provider_proxy_directory_invalid", "listener directory is unavailable"
            ) from error
        if (
            canonical_path != path
            or not stat.S_ISDIR(directory_info.st_mode)
            or directory_info.st_uid != os.geteuid()
            or stat.S_IMODE(directory_info.st_mode) != 0o700
        ):
            raise SupervisorError(
                "provider_proxy_directory_unsafe",
                "listener directory must be canonical, test-owned, and mode 0700",
            )
        if not self._parent_chain_is_trusted(canonical_path):
            raise SupervisorError(
                "provider_proxy_parent_unsafe",
                "listener directory parents must be trusted and not untrusted-writable",
            )

        socket_path = canonical_path / self.socket_name
        if len(os.fsencode(socket_path)) >= _MAX_UNIX_SOCKET_PATH_BYTES:
            raise SupervisorError(
                "provider_proxy_path_too_long", "Unix listener path exceeds the portable limit"
            )
        if os.path.lexists(socket_path):
            raise SupervisorError(
                "provider_proxy_socket_exists", "listener refuses to replace an existing path"
            )
        try:
            with os.scandir(canonical_path) as entries:
                if next(entries, None) is not None:
                    raise SupervisorError(
                        "provider_proxy_directory_not_empty",
                        "listener directory must be empty before binding",
                    )
        except OSError as error:
            raise SupervisorError(
                "provider_proxy_directory_invalid", "listener directory cannot be inspected"
            ) from error

        listener: socket.socket | None = None
        bound = False
        socket_identity: tuple[int, int] | None = None
        try:
            socket_type = socket.SOCK_STREAM | getattr(socket, "SOCK_CLOEXEC", 0)
            listener = socket.socket(socket.AF_UNIX, socket_type)
            if os.get_inheritable(listener.fileno()):
                raise SupervisorError(
                    "provider_proxy_fd_inheritable", "listener descriptor is inheritable"
                )
            listener.bind(str(socket_path))
            bound = True
            bound_info = socket_path.lstat()
            socket_identity = (bound_info.st_dev, bound_info.st_ino)
            os.chmod(socket_path, 0o600)
            socket_info = socket_path.lstat()
            if (
                not stat.S_ISSOCK(socket_info.st_mode)
                or socket_info.st_uid != os.geteuid()
                or stat.S_IMODE(socket_info.st_mode) != 0o600
                or (socket_info.st_dev, socket_info.st_ino) != socket_identity
            ):
                raise SupervisorError(
                    "provider_proxy_socket_unsafe", "bound socket identity or permissions changed"
                )
            current_directory = canonical_path.lstat()
            if not stat.S_ISDIR(current_directory.st_mode) or (
                current_directory.st_dev,
                current_directory.st_ino,
            ) != (directory_info.st_dev, directory_info.st_ino):
                raise SupervisorError(
                    "provider_proxy_directory_changed", "listener directory identity changed"
                )
            listener.listen(backlog)
        except BaseException as error:
            cleanup_error: BaseException | None = None
            if listener is not None:
                try:
                    listener.close()
                except BaseException as close_error:
                    cleanup_error = close_error
            if bound and (
                socket_identity is None
                or not self._unlink_if_exact(
                    socket_path, canonical_path, directory_info, socket_identity
                )
            ):
                cleanup_error = error
            if cleanup_error is not None:
                raise SupervisorError(
                    "provider_proxy_socket_cleanup_unverified",
                    "failed setup left socket cleanup unverified",
                ) from cleanup_error
            raise

        self.directory = canonical_path
        self.path = socket_path
        self.identity = socket_identity
        self._directory_identity = (directory_info.st_dev, directory_info.st_ino)
        self._listener = listener
        self._closed = False
        self._close_error: SupervisorError | None = None

    @staticmethod
    def _parent_chain_is_trusted(directory: Path) -> bool:
        """Reject writable ancestors that could let another UID rename the path."""
        for parent in directory.parents:
            try:
                info = parent.lstat()
            except OSError:
                return False
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.geteuid()}:
                return False
            mode = stat.S_IMODE(info.st_mode)
            if mode & 0o022 and not info.st_mode & stat.S_ISVTX:
                return False
        return True

    @staticmethod
    def _unlink_if_exact(
        socket_path: Path,
        directory: Path,
        directory_info: os.stat_result,
        socket_identity: tuple[int, int],
    ) -> bool:
        """Remove only a matching socket, assuming no concurrent same-UID mutation."""
        try:
            current_directory = directory.lstat()
        except OSError:
            return False
        if (
            not stat.S_ISDIR(current_directory.st_mode)
            or (current_directory.st_dev, current_directory.st_ino)
            != (directory_info.st_dev, directory_info.st_ino)
            or current_directory.st_uid != os.geteuid()
            or stat.S_IMODE(current_directory.st_mode) != 0o700
        ):
            return False
        try:
            current_socket = socket_path.lstat()
        except FileNotFoundError:
            return True
        except OSError:
            return False
        if (
            stat.S_ISSOCK(current_socket.st_mode)
            and current_socket.st_uid == os.geteuid()
            and (current_socket.st_dev, current_socket.st_ino) == socket_identity
        ):
            try:
                socket_path.unlink()
            except OSError:
                return False
            return True
        return False

    def accept(self, *, timeout: float) -> socket.socket | None:
        """Accept one stream, or return ``None`` when the bounded wait expires.

        Only one caller may accept at a time. The returned stream remains the
        caller's responsibility and must be authorized before request bytes are
        read.
        """
        if self._closed:
            raise SupervisorError("provider_proxy_closed", "listener is closed")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
            raise SupervisorError(
                "provider_proxy_timeout_invalid", "accept timeout must be positive"
            )
        try:
            timeout_seconds = float(timeout)
        except (OverflowError, ValueError):
            timeout_seconds = math.inf
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise SupervisorError(
                "provider_proxy_timeout_invalid", "accept timeout must be finite and positive"
            )
        self._listener.settimeout(timeout_seconds)
        try:
            client, _address = self._listener.accept()
        except TimeoutError:
            return None
        if os.get_inheritable(client.fileno()):
            client.close()
            raise SupervisorError(
                "provider_proxy_fd_inheritable", "accepted descriptor is inheritable"
            )
        return client

    def close(self) -> None:
        """Close the listener and unlink only its recorded socket inode."""
        if self._closed:
            if self._close_error is not None:
                raise self._close_error
            return
        self._closed = True
        try:
            self._listener.close()
        except BaseException as error:
            self._close_error = SupervisorError(
                "provider_proxy_listener_close_unverified",
                "listener descriptor close is unverified",
            )
            raise self._close_error from error
        try:
            current_directory = self.directory.lstat()
            if (
                not stat.S_ISDIR(current_directory.st_mode)
                or (current_directory.st_dev, current_directory.st_ino) != self._directory_identity
                or current_directory.st_uid != os.geteuid()
                or stat.S_IMODE(current_directory.st_mode) != 0o700
            ):
                raise SupervisorError(
                    "provider_proxy_directory_changed", "listener directory identity changed"
                )
            current_socket = self.path.lstat()
            if (
                not stat.S_ISSOCK(current_socket.st_mode)
                or current_socket.st_uid != os.geteuid()
                or stat.S_IMODE(current_socket.st_mode) != 0o600
                or (current_socket.st_dev, current_socket.st_ino) != self.identity
            ):
                raise SupervisorError(
                    "provider_proxy_socket_changed", "listener socket identity changed"
                )
            self.path.unlink()
        except OSError as error:
            self._close_error = SupervisorError(
                "provider_proxy_socket_cleanup_unverified", "listener socket cleanup is unverified"
            )
            raise self._close_error from error
        except SupervisorError as error:
            self._close_error = error
            raise


class AttemptProviderProxyService:
    """Own an attempt listener, accepted channels, and bounded handler threads.

    This service only composes the existing CONNECT policy primitives. The
    caller still owns the worker mount and must stop this service before the
    attempt can be recorded as cleaned up. Closing it shuts down accepted
    client streams, signals the CONNECT relay, and waits for every handler; a
    handler that cannot drain before the deadline makes shutdown unverified.
    The listener must be exclusively owned by this service while it runs; do
    not call ``accept`` concurrently. Synchronous name resolution cannot be
    interrupted, so a stalled resolver can still make shutdown unverified. It
    does not create a network namespace, bridge TCP to AF_UNIX, or provide a
    broader lifecycle than the caller gives it.
    """

    _ACCEPT_POLL_SECONDS = 0.1
    _MAX_CONNECTIONS = 128
    _MAX_SHUTDOWN_SECONDS = 60.0

    def __init__(
        self,
        listener: AttemptProviderProxyListener,
        policy: ProviderEgressPolicy,
        *,
        authorize_peer: _PeerAuthorizer,
        max_connections: int = 8,
    ) -> None:
        if type(listener) is not AttemptProviderProxyListener:
            raise SupervisorError(
                "provider_proxy_listener_invalid",
                "attempt proxy service requires its owned listener",
            )
        if type(policy) is not ProviderEgressPolicy:
            raise SupervisorError(
                "provider_proxy_policy_invalid", "attempt proxy service requires an egress policy"
            )
        if not callable(authorize_peer):
            raise SupervisorError(
                "provider_proxy_authorizer_invalid",
                "attempt proxy service requires a peer authorizer",
            )
        if type(max_connections) is not int or not 1 <= max_connections <= self._MAX_CONNECTIONS:
            raise SupervisorError(
                "provider_proxy_connection_limit_invalid",
                "attempt proxy connection limit is outside the supported bound",
            )

        self.listener = listener
        self.policy = policy
        self.authorize_peer = authorize_peer
        self.max_connections = max_connections
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._accept_thread: threading.Thread | None = None
        self._handler_threads: set[threading.Thread] = set()
        self._channels: set[socket.socket] = set()
        self._failure: SupervisorError | None = None
        self._started = False
        self._closed = False

    def start(self) -> None:
        """Start the bounded accept loop exactly once."""
        with self._lock:
            if self._started or self._closed:
                raise SupervisorError(
                    "provider_proxy_service_state_invalid",
                    "attempt proxy service cannot be started in its current state",
                )
            thread = threading.Thread(
                target=self._accept_loop,
                name="acp-attempt-provider-proxy",
                daemon=False,
            )
            self._accept_thread = thread
            self._started = True
            try:
                thread.start()
            except BaseException as error:
                self._started = False
                self._accept_thread = None
                raise SupervisorError(
                    "provider_proxy_service_start_failed",
                    "attempt proxy accept loop could not be started",
                ) from error

    def _remember_failure(self, error: SupervisorError) -> None:
        with self._lock:
            if self._failure is None:
                self._failure = error

    def _prune_finished_handlers_locked(self) -> None:
        finished = tuple(thread for thread in self._handler_threads if not thread.is_alive())
        for thread in finished:
            thread.join(timeout=0)
        self._handler_threads.difference_update(finished)

    def _close_channel(self, channel: socket.socket) -> None:
        try:
            channel.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            channel.close()
        except OSError:
            if channel.fileno() >= 0:
                self._remember_failure(
                    SupervisorError(
                        "provider_proxy_channel_close_unverified",
                        "accepted provider proxy channel did not close",
                    )
                )

    def _stop_accepting(self) -> None:
        self._stop.set()
        try:
            self.listener.close()
        except SupervisorError as error:
            self._remember_failure(error)
        with self._lock:
            channels = tuple(self._channels)
        for channel in channels:
            self._close_channel(channel)

    def _fail(self, message: str) -> None:
        self._remember_failure(SupervisorError("provider_proxy_service_failed", message))
        self._stop_accepting()

    def _handle_channel(self, channel: socket.socket) -> None:
        try:
            serve_connect_connection(
                channel,
                self.policy,
                authorize_peer=self.authorize_peer,
                cancel_event=self._stop,
            )
        except OSError:
            if not self._stop.is_set():
                self._fail("attempt proxy request handler failed")
        except Exception:
            # The service closes accepted sockets while cancellation unwinds
            # relay selectors. Exceptions from that concurrent close are
            # expected once shutdown has begun; `close()` still waits for this
            # handler and verifies that every channel drained.
            if not self._stop.is_set():
                self._fail("attempt proxy request handler failed")
        except BaseException:
            # Preserve process-control exceptions even when ordinary relay
            # exceptions are expected during shutdown.
            self._fail("attempt proxy request handler failed")
        finally:
            self._close_channel(channel)
            with self._lock:
                self._channels.discard(channel)

    def _accept_loop(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    channel = self.listener.accept(timeout=self._ACCEPT_POLL_SECONDS)
                except (OSError, SupervisorError):
                    if self._stop.is_set():
                        break
                    self._fail("attempt proxy listener failed while accepting a channel")
                    break
                if channel is None:
                    continue

                close_channel = False
                with self._lock:
                    self._prune_finished_handlers_locked()
                    if self._stop.is_set() or len(self._channels) >= self.max_connections:
                        close_channel = True
                    else:
                        thread = threading.Thread(
                            target=self._handle_channel,
                            args=(channel,),
                            name="acp-attempt-provider-proxy-channel",
                            daemon=False,
                        )
                        self._channels.add(channel)
                        self._handler_threads.add(thread)
                        try:
                            thread.start()
                        except BaseException:
                            self._channels.discard(channel)
                            self._handler_threads.discard(thread)
                            close_channel = True
                            self._failure = self._failure or SupervisorError(
                                "provider_proxy_handler_start_failed",
                                "attempt proxy request handler could not be started",
                            )
                            self._stop.set()
                if close_channel:
                    self._close_channel(channel)
                    if self._stop.is_set():
                        self._stop_accepting()
                        break
        except BaseException:
            self._fail("attempt proxy accept loop failed")

    def close(self, *, timeout: float = 10.0) -> None:
        """Stop accepting, close streams, and join every handler by deadline.

        Failure to close the listener or drain all handlers is reported as
        unverified so callers can retain the attempt's cleanup fence.
        """
        if type(timeout) not in {int, float}:
            raise SupervisorError(
                "provider_proxy_shutdown_timeout_invalid",
                "attempt proxy shutdown timeout is outside the supported bound",
            )
        try:
            timeout_seconds = float(timeout)
        except (OverflowError, ValueError):
            timeout_seconds = math.inf
        if (
            not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= self._MAX_SHUTDOWN_SECONDS
        ):
            raise SupervisorError(
                "provider_proxy_shutdown_timeout_invalid",
                "attempt proxy shutdown timeout is outside the supported bound",
            )
        current_thread = threading.current_thread()
        with self._lock:
            if self._closed:
                if self._failure is not None:
                    raise self._failure
                return
            if current_thread is self._accept_thread or current_thread in self._handler_threads:
                raise SupervisorError(
                    "provider_proxy_shutdown_unverified",
                    "attempt proxy service cannot join itself during shutdown",
                )
            accept_thread = self._accept_thread

        self._stop_accepting()
        deadline = time.monotonic() + timeout_seconds
        if accept_thread is not None:
            accept_thread.join(max(0.0, deadline - time.monotonic()))
        with self._lock:
            threads = tuple(self._handler_threads)
        for thread in threads:
            thread.join(max(0.0, deadline - time.monotonic()))

        with self._lock:
            self._prune_finished_handlers_locked()
            handlers_alive = tuple(self._handler_threads)
            accept_alive = accept_thread is not None and accept_thread.is_alive()
            channels_remain = bool(self._channels)
            if not handlers_alive and not accept_alive and not channels_remain:
                self._closed = True
            failure = self._failure
        if handlers_alive or accept_alive or channels_remain:
            raise SupervisorError(
                "provider_proxy_shutdown_unverified",
                "attempt proxy listener or accepted channels did not drain before the deadline",
            )
        if failure is not None:
            raise failure


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


def _relay(
    client: socket.socket,
    upstream: socket.socket,
    *,
    cancel_event: threading.Event | None = None,
) -> None:
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
            if cancel_event is not None and cancel_event.is_set():
                return
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
            select_timeout = remaining
            if cancel_event is not None:
                select_timeout = min(remaining, _RELAY_CANCEL_POLL_SECONDS)
            ready = selector.select(select_timeout)
            if cancel_event is not None and cancel_event.is_set():
                return
            if not ready:
                if (
                    cancel_event is None
                    or time.monotonic() - last_activity >= _DEFAULT_IDLE_TIMEOUT_SECONDS
                ):
                    return
                continue

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
    cancel_event: threading.Event | None = None,
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
        cancel_event=cancel_event,
    )


def _serve_connect_connection(
    client: socket.socket,
    *,
    dial: _Dialer,
    authorize_peer: _PeerAuthorizer,
    cancel_event: threading.Event | None = None,
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
        if cancel_event is not None and cancel_event.is_set():
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
        if cancel_event is not None and cancel_event.is_set():
            return
        _reject_queued_tunnel_data(client)
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        _relay(client, upstream, cancel_event=cancel_event)
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
