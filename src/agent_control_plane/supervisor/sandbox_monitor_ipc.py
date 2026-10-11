"""Linux Unix-socket status/cancel protocol for a per-attempt monitor.

This module implements authenticated control messages and durable replay
protection. It does not start workers, create or accept a runc launch handle, or
connect the protocol to ``run_worker``. A server stores injected status/cancel
callbacks, which may retain caller-owned state. No production worker-execution
path invokes this protocol today. It exposes only status and cancellation, so a
controller cannot ask it to reconstruct or start an execution from
caller-supplied data.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import stat
import struct
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .sandbox_monitor_receipt import (
    SandboxMonitorReceipt,
    SandboxMonitorReceiptError,
    _reject_duplicate_keys,
    decode_sandbox_monitor_control_request,
    encode_sandbox_monitor_control_request,
    sandbox_container_id,
)

_MAX_FRAME_BYTES = 4096
_MAX_STATUS_BYTES = 2048
_MAX_REQUESTS = 256
_CONTROL_KEY_BYTES = 32
_REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")
_SOCKET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,72}\.sock\Z")
_PHASES = frozenset(
    {"reserved", "launched", "running", "stopping", "exited", "cleanup_verified", "unknown"}
)


class SandboxMonitorIPCError(RuntimeError):
    """The monitor control channel or its durable replay ledger is unsafe."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def _open_private_directory(path: Path) -> int:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or path == Path("/")
        or ".." in path.parts
        or str(path) != os.path.normpath(str(path))
    ):
        raise SandboxMonitorIPCError("monitor IPC directory path is not canonical and absolute")

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise SandboxMonitorIPCError("monitor IPC directory must be owned and mode 0700")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise SandboxMonitorIPCError("monitor IPC durable write made no progress")
        view = view[written:]


def _read_private_record(directory_fd: int, name: str, *, limit: int) -> bytes:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fd,
        )
    except FileNotFoundError:
        raise
    except OSError as error:
        raise SandboxMonitorIPCError(
            "monitor IPC ledger record could not be opened safely"
        ) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > limit
        ):
            raise SandboxMonitorIPCError("monitor IPC ledger record has unsafe metadata")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(data) != before.st_size
            or len(data) > limit
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise SandboxMonitorIPCError("monitor IPC ledger record changed while being read")
        return data
    finally:
        os.close(descriptor)


def _create_private_record(directory_fd: int, name: str, data: bytes) -> None:
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
    except FileExistsError:
        raise
    except OSError as error:
        raise SandboxMonitorIPCError(
            "monitor IPC ledger record could not be created safely"
        ) from error
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise SandboxMonitorIPCError("monitor IPC ledger created an unsafe record")
        _write_all(descriptor, data)
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        try:
            os.unlink(name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise
    else:
        os.close(descriptor)
        os.fsync(directory_fd)


def _linux_process_identity(pid: int) -> str:
    if type(pid) is not int or pid <= 0:
        raise SandboxMonitorIPCError("monitor peer PID is invalid")
    try:
        record = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        closing = record.rfind(")")
        observed_pid = int(record[: record.find(" ")])
        fields_after_comm = record[closing + 2 :].split()
        start_time = int(fields_after_comm[19])  # proc stat field 22
    except (OSError, ValueError, IndexError) as error:
        raise SandboxMonitorIPCError("monitor peer PID start identity is unavailable") from error
    if observed_pid != pid or start_time <= 0:
        raise SandboxMonitorIPCError("monitor peer PID start identity is malformed")
    return f"linux:{pid}:{start_time}"


def _peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        raise SandboxMonitorIPCError("Unix peer credentials are unsupported on this platform")
    try:
        raw = connection.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", raw)
    except (OSError, struct.error) as error:
        raise SandboxMonitorIPCError("Unix peer credentials are unavailable") from error
    if pid <= 0 or uid < 0 or gid < 0:
        raise SandboxMonitorIPCError("Unix peer credentials are invalid")
    return pid, uid, gid


def _validate_status_payload(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) - {
        "phase",
        "worker_pid",
        "worker_exit_code",
        "cleanup_verified",
    }:
        raise SandboxMonitorIPCError("monitor status has an unsupported shape")
    phase = value.get("phase")
    if not isinstance(phase, str) or phase not in _PHASES:
        raise SandboxMonitorIPCError("monitor status phase is invalid")
    result: dict[str, Any] = {"phase": phase}
    if "worker_pid" in value:
        worker_pid = value["worker_pid"]
        if worker_pid is not None and (type(worker_pid) is not int or worker_pid <= 0):
            raise SandboxMonitorIPCError("monitor status worker PID is invalid")
        result["worker_pid"] = worker_pid
    if "worker_exit_code" in value:
        exit_code = value["worker_exit_code"]
        if exit_code is not None and (type(exit_code) is not int or not -255 <= exit_code <= 255):
            raise SandboxMonitorIPCError("monitor status worker exit code is invalid")
        result["worker_exit_code"] = exit_code
    if "cleanup_verified" in value:
        if type(value["cleanup_verified"]) is not bool:
            raise SandboxMonitorIPCError("monitor cleanup status is invalid")
        result["cleanup_verified"] = value["cleanup_verified"]
    if len(_canonical_json(result)) > _MAX_STATUS_BYTES:
        raise SandboxMonitorIPCError("monitor status exceeds its response bound")
    return result


def _encode_response(
    *,
    key: bytes,
    request_id: str,
    operation: str,
    outcome: str,
    payload: Mapping[str, Any],
) -> bytes:
    if len(key) != _CONTROL_KEY_BYTES or outcome not in {"ok", "unknown"}:
        raise SandboxMonitorIPCError("monitor response authentication or outcome is invalid")
    material = {
        "version": 1,
        "request_id": request_id,
        "operation": operation,
        "outcome": outcome,
        "payload": _validate_status_payload(payload),
    }
    tag = hmac.new(key, _canonical_json(material), hashlib.sha256).hexdigest()
    encoded = _canonical_json({**material, "mac": tag})
    if len(encoded) > _MAX_FRAME_BYTES:
        raise SandboxMonitorIPCError("monitor response exceeds its size bound")
    return encoded


@dataclass(frozen=True)
class SandboxMonitorControlResponse:
    request_id: str
    operation: str
    outcome: str
    payload: dict[str, Any]


def _decode_response(
    encoded: bytes,
    *,
    key: bytes,
    request_id: str,
    operation: str,
) -> SandboxMonitorControlResponse:
    if not encoded or len(encoded) > _MAX_FRAME_BYTES:
        raise SandboxMonitorIPCError("monitor response is empty or oversized")
    try:
        decoded = json.loads(encoded.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, SandboxMonitorReceiptError) as error:
        raise SandboxMonitorIPCError("monitor response is not valid canonical JSON") from error
    expected = {"version", "request_id", "operation", "outcome", "payload", "mac"}
    if not isinstance(decoded, dict) or set(decoded) != expected:
        raise SandboxMonitorIPCError("monitor response has an unsupported shape")
    if _canonical_json(decoded) != encoded:
        raise SandboxMonitorIPCError("monitor response is not canonical JSON")
    if (
        type(decoded["version"]) is not int
        or decoded["version"] != 1
        or decoded["request_id"] != request_id
        or decoded["operation"] != operation
        or not isinstance(decoded["outcome"], str)
        or decoded["outcome"] not in {"ok", "unknown"}
        or not isinstance(decoded["mac"], str)
        or re.fullmatch(r"[0-9a-f]{64}", decoded["mac"]) is None
    ):
        raise SandboxMonitorIPCError("monitor response identity or fields do not match request")
    material = {name: value for name, value in decoded.items() if name != "mac"}
    expected_mac = hmac.new(key, _canonical_json(material), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(decoded["mac"], expected_mac):
        raise SandboxMonitorIPCError("monitor response authentication failed")
    payload = _validate_status_payload(decoded["payload"])
    return SandboxMonitorControlResponse(
        request_id=request_id,
        operation=operation,
        outcome=decoded["outcome"],
        payload=payload,
    )


def _receive_exact(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise SandboxMonitorIPCError("monitor control peer closed an incomplete frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _receive_frame(connection: socket.socket) -> bytes:
    size = struct.unpack("!I", _receive_exact(connection, 4))[0]
    if size <= 0 or size > _MAX_FRAME_BYTES:
        raise SandboxMonitorIPCError("monitor control frame is empty or oversized")
    return _receive_exact(connection, size)


def _send_frame(connection: socket.socket, body: bytes) -> None:
    if not body or len(body) > _MAX_FRAME_BYTES:
        raise SandboxMonitorIPCError("monitor control frame is empty or oversized")
    connection.sendall(struct.pack("!I", len(body)) + body)


class SandboxMonitorControlServer:
    """Single-process server bound to the monitor's live runc-handle owner."""

    def __init__(
        self,
        *,
        socket_path: Path,
        request_directory: Path,
        key: bytes,
        expected_identity: tuple[str, int, str],
        expected_uid: int,
        status_provider: Callable[[], Mapping[str, Any]],
        cancel_action: Callable[[], Mapping[str, Any]],
        request_limit: int = _MAX_REQUESTS,
        client_timeout_seconds: float = 2.0,
    ) -> None:
        if not hasattr(socket, "SO_PEERCRED") or not hasattr(socket, "AF_UNIX"):
            raise SandboxMonitorIPCError("monitor control IPC requires Linux Unix peer credentials")
        if type(key) is not bytes or len(key) != _CONTROL_KEY_BYTES:
            raise SandboxMonitorIPCError("monitor control key must contain exactly 32 bytes")
        if (
            not isinstance(expected_identity, tuple)
            or len(expected_identity) != 3
            or type(expected_identity[1]) is not int
        ):
            raise SandboxMonitorIPCError("monitor control execution identity is invalid")
        try:
            sandbox_container_id(*expected_identity)
        except SandboxMonitorReceiptError as error:
            raise SandboxMonitorIPCError("monitor control execution identity is invalid") from error
        if type(expected_uid) is not int or expected_uid != os.geteuid():
            raise SandboxMonitorIPCError("monitor control peer UID must match the service owner")
        if not callable(status_provider) or not callable(cancel_action):
            raise SandboxMonitorIPCError("monitor control handlers must be callable")
        if type(request_limit) is not int or not 1 <= request_limit <= _MAX_REQUESTS:
            raise SandboxMonitorIPCError("monitor control request limit is invalid")
        if (
            type(client_timeout_seconds) not in {int, float}
            or not 0.05 <= client_timeout_seconds <= 30
        ):
            raise SandboxMonitorIPCError("monitor control client timeout is invalid")

        self._key = key
        self._expected_identity = expected_identity
        self._expected_uid = expected_uid
        self._status_provider = status_provider
        self._cancel_action = cancel_action
        self._request_limit = request_limit
        self._client_timeout_seconds = float(client_timeout_seconds)
        self._lock = threading.Lock()
        self._lifecycle_lock = threading.Lock()
        self._cleanup_lock = threading.Lock()
        self._stopping = threading.Event()
        self._serving = False
        self._terminated = False
        self._cleaned = False
        self._ledger_fd = _open_private_directory(request_directory)
        self._socket_parent_fd = -1
        self._listener: socket.socket | None = None
        self._socket_path = socket_path
        self._socket_name = ""
        self._socket_identity: tuple[int, int] | None = None
        try:
            self._bind_socket()
        except BaseException:
            if self._socket_parent_fd >= 0:
                os.close(self._socket_parent_fd)
                self._socket_parent_fd = -1
            os.close(self._ledger_fd)
            self._ledger_fd = -1
            raise

    def _bind_socket(self) -> None:
        path = self._socket_path
        if (
            not isinstance(path, Path)
            or not path.is_absolute()
            or path == Path("/")
            or ".." in path.parts
            or str(path) != os.path.normpath(str(path))
            or _SOCKET_NAME.fullmatch(path.name) is None
            or len(os.fsencode(path)) >= 108
        ):
            raise SandboxMonitorIPCError("monitor control socket path is invalid or too long")
        self._socket_parent_fd = _open_private_directory(path.parent)
        self._socket_name = path.name
        try:
            os.stat(self._socket_name, dir_fd=self._socket_parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise SandboxMonitorIPCError("monitor control socket path already exists")

        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(path))
            bound_info = os.stat(
                self._socket_name, dir_fd=self._socket_parent_fd, follow_symlinks=False
            )
            if not stat.S_ISSOCK(bound_info.st_mode) or bound_info.st_uid != os.geteuid():
                raise SandboxMonitorIPCError("monitor control socket was replaced during bind")
            self._socket_identity = (bound_info.st_dev, bound_info.st_ino)
            os.chmod(path, 0o600, follow_symlinks=False)
            info = os.stat(self._socket_name, dir_fd=self._socket_parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISSOCK(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                raise SandboxMonitorIPCError("monitor control socket metadata is unsafe")
            if (info.st_dev, info.st_ino) != self._socket_identity:
                raise SandboxMonitorIPCError("monitor control socket identity changed during bind")
            listener.listen(8)
            listener.settimeout(0.2)
            self._listener = listener
        except BaseException:
            listener.close()
            self._remove_socket_if_owned()
            if self._socket_parent_fd >= 0:
                os.close(self._socket_parent_fd)
                self._socket_parent_fd = -1
            raise

    def _accepted_record_name(self, request_id: str) -> str:
        return f"r-{request_id}.accepted"

    def _response_record_name(self, request_id: str) -> str:
        return f"r-{request_id}.response"

    def _record_request_count(self) -> int:
        return sum(name.endswith(".accepted") for name in os.listdir(self._ledger_fd))

    def _accepted_record(self, request_id: str) -> dict[str, str] | None:
        try:
            encoded = _read_private_record(
                self._ledger_fd, self._accepted_record_name(request_id), limit=512
            )
        except FileNotFoundError:
            return None
        try:
            decoded = json.loads(encoded.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
        except (UnicodeDecodeError, json.JSONDecodeError, SandboxMonitorReceiptError) as error:
            raise SandboxMonitorIPCError("monitor accepted-request record is corrupt") from error
        if (
            not isinstance(decoded, dict)
            or set(decoded) != {"version", "request_sha256", "operation"}
            or type(decoded["version"]) is not int
            or decoded["version"] != 1
            or not isinstance(decoded["request_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", decoded["request_sha256"]) is None
            or not isinstance(decoded["operation"], str)
            or decoded["operation"] not in {"status", "cancel"}
            or _canonical_json(decoded) != encoded
        ):
            raise SandboxMonitorIPCError("monitor accepted-request record is invalid")
        return {"request_sha256": decoded["request_sha256"], "operation": decoded["operation"]}

    def _load_response(
        self, request_id: str, operation: str
    ) -> tuple[bytes, SandboxMonitorControlResponse] | None:
        try:
            encoded = _read_private_record(
                self._ledger_fd, self._response_record_name(request_id), limit=_MAX_FRAME_BYTES
            )
        except FileNotFoundError:
            return None
        return encoded, _decode_response(
            encoded,
            key=self._key,
            request_id=request_id,
            operation=operation,
        )

    def _dispatch(self, peer_uid: int, encoded_request: bytes) -> bytes:
        if peer_uid != self._expected_uid:
            raise SandboxMonitorIPCError("monitor control peer UID is not authorized")
        try:
            request = decode_sandbox_monitor_control_request(
                encoded_request,
                key=self._key,
                expected_identity=self._expected_identity,
            )
        except SandboxMonitorReceiptError as error:
            raise SandboxMonitorIPCError("monitor control request authentication failed") from error

        # Status is read-only and potentially polled frequently. It deliberately
        # does not consume the bounded side-effect replay ledger.
        if request.operation == "status":
            try:
                payload = _validate_status_payload(self._status_provider())
                outcome = "ok"
            except Exception:
                payload = {"phase": "unknown"}
                outcome = "unknown"
            return _encode_response(
                key=self._key,
                request_id=request.request_id,
                operation=request.operation,
                outcome=outcome,
                payload=payload,
            )

        digest = hashlib.sha256(encoded_request).hexdigest()
        accepted_name = self._accepted_record_name(request.request_id)
        response_name = self._response_record_name(request.request_id)
        with self._lock:
            accepted = self._accepted_record(request.request_id)
            response = self._load_response(request.request_id, request.operation)
            if accepted is None:
                if response is not None:
                    raise SandboxMonitorIPCError(
                        "monitor response exists without an accepted request"
                    )
                if self._record_request_count() >= self._request_limit:
                    raise SandboxMonitorIPCError("monitor replay ledger reached its request limit")
                accepted_value = {
                    "version": 1,
                    "request_sha256": digest,
                    "operation": request.operation,
                }
                _create_private_record(
                    self._ledger_fd, accepted_name, _canonical_json(accepted_value)
                )
            elif accepted != {"request_sha256": digest, "operation": request.operation}:
                raise SandboxMonitorIPCError("monitor request ID was reused with different content")

            if response is not None:
                return response[0]

            # A durable acceptance without a response is ambiguous after a crash.
            # Return a terminal unknown result; never repeat a potentially applied action.
            if accepted is not None:
                encoded_response = _encode_response(
                    key=self._key,
                    request_id=request.request_id,
                    operation=request.operation,
                    outcome="unknown",
                    payload={"phase": "unknown"},
                )
                _create_private_record(self._ledger_fd, response_name, encoded_response)
                return encoded_response

            try:
                if request.operation == "status":
                    payload = _validate_status_payload(self._status_provider())
                elif request.operation == "cancel":
                    payload = _validate_status_payload(self._cancel_action())
                    if payload["phase"] not in {"stopping", "exited"}:
                        raise SandboxMonitorIPCError(
                            "monitor cancel handler did not confirm stopping or exited"
                        )
                else:  # Defense in depth if the codec's operation set changes.
                    raise SandboxMonitorIPCError("monitor control operation is unsupported")
                outcome = "ok"
            except Exception:
                payload = {"phase": "unknown"}
                outcome = "unknown"

            encoded_response = _encode_response(
                key=self._key,
                request_id=request.request_id,
                operation=request.operation,
                outcome=outcome,
                payload=payload,
            )
            _create_private_record(self._ledger_fd, response_name, encoded_response)
            return encoded_response

    def serve_forever(self) -> None:
        with self._lifecycle_lock:
            listener = self._listener
            if listener is None or self._stopping.is_set() or self._terminated:
                raise SandboxMonitorIPCError("monitor control server is closed")
            if self._serving:
                raise SandboxMonitorIPCError("monitor control server is already serving")
            self._serving = True
        try:
            while not self._stopping.is_set():
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if self._stopping.is_set():
                        break
                    raise
                with connection:
                    connection.settimeout(self._client_timeout_seconds)
                    try:
                        _pid, uid, _gid = _peer_credentials(connection)
                        response = self._dispatch(uid, _receive_frame(connection))
                        _send_frame(connection, response)
                    except (SandboxMonitorIPCError, OSError, ValueError, TimeoutError):
                        continue
        finally:
            with self._lifecycle_lock:
                self._serving = False
                self._terminated = True
            self._cleanup()

    def _remove_socket_if_owned(self) -> None:
        if self._socket_parent_fd < 0 or self._socket_identity is None:
            return
        try:
            info = os.stat(self._socket_name, dir_fd=self._socket_parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if (info.st_dev, info.st_ino) == self._socket_identity and stat.S_ISSOCK(info.st_mode):
            os.unlink(self._socket_name, dir_fd=self._socket_parent_fd)
            os.fsync(self._socket_parent_fd)

    def _cleanup(self) -> None:
        with self._cleanup_lock:
            if self._cleaned:
                return
            self._cleaned = True
            if self._listener is not None:
                self._listener.close()
                self._listener = None
            try:
                self._remove_socket_if_owned()
            finally:
                if self._socket_parent_fd >= 0:
                    os.close(self._socket_parent_fd)
                    self._socket_parent_fd = -1
                if self._ledger_fd >= 0:
                    os.close(self._ledger_fd)
                    self._ledger_fd = -1

    def close(self) -> None:
        self._stopping.set()
        listener = self._listener
        if listener is not None:
            listener.close()
        with self._lifecycle_lock:
            serving = self._serving
        if not serving:
            self._cleanup()

    def __enter__(self) -> SandboxMonitorControlServer:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class SandboxMonitorControlClient:
    """Controller that verifies the connected server against a durable receipt."""

    def __init__(
        self,
        *,
        receipt: SandboxMonitorReceipt,
        socket_path: Path,
        key: bytes,
        expected_uid: int,
        timeout_seconds: float = 2.0,
    ) -> None:
        if type(receipt) is not SandboxMonitorReceipt:
            raise SandboxMonitorIPCError("monitor client requires a durable typed receipt")
        if type(key) is not bytes or len(key) != _CONTROL_KEY_BYTES:
            raise SandboxMonitorIPCError("monitor control key must contain exactly 32 bytes")
        if type(expected_uid) is not int or expected_uid != os.geteuid():
            raise SandboxMonitorIPCError("monitor server UID must match the controller owner")
        if type(timeout_seconds) not in {int, float} or not 0.05 <= timeout_seconds <= 30:
            raise SandboxMonitorIPCError("monitor client timeout is invalid")
        if (
            not isinstance(socket_path, Path)
            or not socket_path.is_absolute()
            or ".." in socket_path.parts
            or str(socket_path) != os.path.normpath(str(socket_path))
            or _SOCKET_NAME.fullmatch(socket_path.name) is None
            or len(os.fsencode(socket_path)) >= 108
        ):
            raise SandboxMonitorIPCError("monitor client socket path is invalid")
        try:
            socket_info = os.lstat(socket_path)
        except OSError as error:
            raise SandboxMonitorIPCError("monitor client socket is unavailable") from error
        if (
            not stat.S_ISSOCK(socket_info.st_mode)
            or socket_info.st_uid != expected_uid
            or stat.S_IMODE(socket_info.st_mode) != 0o600
        ):
            raise SandboxMonitorIPCError(
                "monitor client socket metadata does not match the configured service owner"
            )
        self._receipt = receipt
        self._socket_path = socket_path
        self._key = key
        self._expected_uid = expected_uid
        self._timeout_seconds = float(timeout_seconds)

    def _request(
        self, operation: str, request_id: str | None = None
    ) -> SandboxMonitorControlResponse:
        request_id = secrets.token_hex(16) if request_id is None else request_id
        if not isinstance(request_id, str) or _REQUEST_ID.fullmatch(request_id) is None:
            raise SandboxMonitorIPCError(
                "monitor control request ID must be 32 lowercase hex digits"
            )
        try:
            encoded = encode_sandbox_monitor_control_request(
                attempt_id=self._receipt.attempt_id,
                claim_token=self._receipt.claim_token,
                execution_id=self._receipt.execution_id,
                request_id=request_id,
                operation=operation,
                key=self._key,
            )
        except SandboxMonitorReceiptError as error:
            raise SandboxMonitorIPCError("monitor control request could not be encoded") from error

        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(self._timeout_seconds)
        try:
            client.connect(str(self._socket_path))
            peer_pid, peer_uid, _peer_gid = _peer_credentials(client)
            if peer_uid != self._expected_uid:
                raise SandboxMonitorIPCError("connected monitor UID does not match service owner")
            if peer_pid != self._receipt.main_pid:
                raise SandboxMonitorIPCError("connected monitor PID does not match its receipt")
            if _linux_process_identity(peer_pid) != self._receipt.main_identity:
                raise SandboxMonitorIPCError("connected monitor PID start identity changed")
            _send_frame(client, encoded)
            response_body = _receive_frame(client)
        except (OSError, TimeoutError) as error:
            raise SandboxMonitorIPCError("monitor control connection failed") from error
        finally:
            client.close()
        return _decode_response(
            response_body,
            key=self._key,
            request_id=request_id,
            operation=operation,
        )

    def status(self, request_id: str | None = None) -> SandboxMonitorControlResponse:
        """Return current state; status requests are read-only and not ledgered."""

        return self._request("status", request_id)

    def cancel(self, request_id: str) -> SandboxMonitorControlResponse:
        """Request cancellation with a caller-held ID, reusable after ambiguous timeouts."""
        if not isinstance(request_id, str) or _REQUEST_ID.fullmatch(request_id) is None:
            raise SandboxMonitorIPCError(
                "cancel requires a caller-held 32-digit request ID for safe retries"
            )
        return self._request("cancel", request_id)
