"""Opaque, versioned credential handles and descriptor-only delivery.

Credential providers deliberately separate three things that environment
variables collapse into one global value: the configured credential name, the
immutable version used by an attempt, and the short-lived plaintext material.
Only the first two cross a transaction boundary. Plaintext is read into a
sealed anonymous file descriptor immediately before a trusted driver starts and
is never placed in argv, inherited environment values, SQLite, or evidence.
"""

from __future__ import annotations

import hmac
import json
import os
import stat
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Protocol

MAX_CREDENTIAL_BYTES = 1024 * 1024
PROVIDER_KINDS = ("versioned_file",)


class CredentialError(Exception):
    """A credential definition, version, or materialization is unsafe."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class CredentialDefinition:
    name: str
    provider: str
    options: Mapping[str, str]

    def option(self, key: str, default: str | None = None) -> str | None:
        return self.options.get(key, default)

    @property
    def fingerprint(self) -> str:
        payload = json.dumps(
            {
                "name": self.name,
                "provider": self.provider,
                "options": dict(sorted(self.options.items())),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return sha256(payload).hexdigest()


@dataclass(frozen=True)
class CredentialHandle:
    """Internal, non-plaintext reference to one immutable credential version."""

    provider: str
    credential: str
    version: str
    provider_fingerprint: str
    source_reference: str
    source_device: int
    source_inode: int
    target_fingerprint: str

    def as_internal_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "credential": self.credential,
            "version": self.version,
            "provider_fingerprint": self.provider_fingerprint,
            "source_reference": self.source_reference,
            "source_device": self.source_device,
            "source_inode": self.source_inode,
            "target_fingerprint": self.target_fingerprint,
        }

    @classmethod
    def from_internal_dict(cls, raw: Mapping[str, Any]) -> CredentialHandle:
        try:
            return cls(
                provider=str(raw["provider"]),
                credential=str(raw["credential"]),
                version=str(raw["version"]),
                provider_fingerprint=str(raw["provider_fingerprint"]),
                source_reference=str(raw["source_reference"]),
                source_device=int(raw["source_device"]),
                source_inode=int(raw["source_inode"]),
                target_fingerprint=str(raw["target_fingerprint"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise CredentialError(
                "credential_handle_invalid",
                "stored credential handle is incomplete or invalid",
            ) from error


@dataclass(frozen=True)
class CredentialMaterial:
    """Ephemeral descriptor plus values that must be removed from observations."""

    fd: int
    path: str
    redactions: tuple[str, ...]


class CredentialProvider(Protocol):
    def resolve_current(self) -> CredentialHandle: ...

    @contextmanager
    def materialize(
        self, handle: CredentialHandle, runtime_dir: Path
    ) -> Iterator[CredentialMaterial]: ...


def _outside_repo(path: Path, repo_root: Path) -> bool:
    try:
        path.relative_to(repo_root.resolve())
    except ValueError:
        return True
    return False


def _validate_parent_chain(path: Path) -> None:
    expected_owners = {0, os.getuid()}
    parent = path.parent
    while True:
        info = parent.stat()
        if info.st_uid not in expected_owners:
            raise CredentialError(
                "credential_source_unsafe",
                "credential source has an unexpected parent owner",
            )
        writable = info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if writable and not sticky_root:
            raise CredentialError(
                "credential_source_unsafe",
                "credential source has a group/world-writable parent",
            )
        if sticky_root or parent == parent.parent:
            break
        parent = parent.parent


def _validate_secret_file(path: Path, info: os.stat_result) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise CredentialError("credential_source_unsafe", "credential target is not a file")
    if info.st_uid not in {0, os.getuid()}:
        raise CredentialError(
            "credential_source_unsafe", "credential target has an unexpected owner"
        )
    if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise CredentialError(
            "credential_source_unsafe", "credential target permissions must be 0600 or stricter"
        )
    if info.st_size < 1 or info.st_size > MAX_CREDENTIAL_BYTES:
        raise CredentialError(
            "credential_source_unsafe", "credential target size is outside the allowed range"
        )
    _validate_parent_chain(path)


def _read_exact_file(
    path: Path,
    expected_identity: tuple[int, int] | None = None,
) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise CredentialError(
            "credential_unavailable", "credential version is unavailable"
        ) from error
    try:
        before = os.fstat(fd)
        _validate_secret_file(path, before)
        identity = (before.st_dev, before.st_ino)
        if expected_identity is not None and identity != expected_identity:
            raise CredentialError(
                "credential_version_changed", "credential version identity changed"
            )
        chunks: list[bytes] = []
        remaining = MAX_CREDENTIAL_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) or len(payload) != before.st_size:
            raise CredentialError(
                "credential_version_changed", "credential version changed while being read"
            )
        if not payload or len(payload) > MAX_CREDENTIAL_BYTES:
            raise CredentialError(
                "credential_source_unsafe", "credential payload size is outside the allowed range"
            )
        return payload, before
    finally:
        os.close(fd)


def _target_fingerprint(
    secret: bytes,
    definition: CredentialDefinition,
    version: str,
    payload: bytes,
) -> str:
    message = b"\x00".join(
        (
            definition.fingerprint.encode(),
            definition.name.encode(),
            version.encode(),
            payload,
        )
    )
    return hmac.new(secret, message, sha256).hexdigest()


def _pgpass_passwords(line: str) -> tuple[str, ...]:
    r"""Return encoded and libpq-decoded password fields from one pgpass row.

    A colon is a delimiter only when it is not escaped. Splitting from the
    right is unsafe because a password may legally end in ``\:``. The same
    rule applies to backslashes, so observations may contain either the
    on-disk spelling or libpq's decoded value and both must be redacted.
    """

    fields: list[str] = []
    field: list[str] = []
    escaped = False
    password_raw: list[str] = []
    for char in line:
        if len(fields) == 4:
            password_raw.append(char)
        if escaped:
            field.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":" and len(fields) < 4:
            fields.append("".join(field))
            field = []
        else:
            field.append(char)
    if escaped:
        # Invalid/implementation-defined trailing escapes still need literal
        # redaction rather than being silently shortened.
        field.append("\\")
    fields.append("".join(field))
    if len(fields) != 5:
        return ()
    raw = "".join(password_raw)
    decoded = fields[-1]
    return tuple(value for value in (raw, decoded) if value)


def _redaction_values(payload: bytes) -> tuple[str, ...]:
    """Generate conservative literal redactions without interpreting the secret."""

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return ()
    values = {text, text.strip()}
    for line in text.splitlines():
        # pgpass fields are not whitespace-trimmed. Preserve the complete row
        # so passwords with leading/trailing spaces receive the same treatment
        # as any other valid value.
        row = line.removesuffix("\r")
        if not row or row.startswith("#"):
            continue
        values.add(row)
        # Covers both the encoded pgpass field and the value libpq actually
        # uses after unescaping terminal colons/backslashes.
        values.update(_pgpass_passwords(row))
        if "=" in row:
            values.add(row.split("=", 1)[-1].strip())
    return tuple(sorted((value for value in values if value), key=len, reverse=True))


def _anonymous_fd(payload: bytes, runtime_dir: Path) -> int:
    memfd_create = getattr(os, "memfd_create", None)
    if memfd_create is not None:
        flags = getattr(os, "MFD_CLOEXEC", 0) | getattr(os, "MFD_ALLOW_SEALING", 0)
        fd = memfd_create("acp-credential", flags)
    else:
        staging = runtime_dir / ".credentials"
        staging.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(staging, 0o700)
        fd, raw_path = tempfile.mkstemp(prefix="material-", dir=staging)
        os.unlink(raw_path)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.lseek(fd, 0, os.SEEK_SET)
        if memfd_create is not None and getattr(os, "MFD_ALLOW_SEALING", 0):
            try:
                import fcntl

                seals = (
                    fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
                )
                fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
            except (AttributeError, OSError):
                # Descriptor delivery is still safe on kernels/filesystems
                # without sealing; the file is private and already unlinked.
                pass
        return fd
    except BaseException:
        os.close(fd)
        raise


class VersionedFileProvider:
    """Resolve an atomic ``current`` symlink to a retained immutable file."""

    def __init__(self, definition: CredentialDefinition, repo_root: Path, secret: bytes) -> None:
        self.definition = definition
        self.repo_root = repo_root.resolve()
        self.secret = secret

    @property
    def current_path(self) -> Path:
        raw = self.definition.option("current") or ""
        return Path(raw)

    def resolve_current(self) -> CredentialHandle:
        current = self.current_path
        try:
            current_before = current.lstat()
            link_before = os.readlink(current)
        except OSError as error:
            raise CredentialError(
                "credential_unavailable",
                f"credential {self.definition.name!r} has no current version",
            ) from error
        if not stat.S_ISLNK(current_before.st_mode):
            raise CredentialError(
                "credential_unavailable",
                f"credential {self.definition.name!r} current reference is not an atomic symlink",
            )
        _validate_parent_chain(current)
        try:
            target = current.resolve(strict=True)
        except OSError as error:
            raise CredentialError(
                "credential_unavailable",
                f"credential {self.definition.name!r} has no current version",
            ) from error
        try:
            current_after = current.lstat()
            link_after = os.readlink(current)
        except OSError as error:
            raise CredentialError(
                "credential_version_changed", "credential current version changed while resolving"
            ) from error
        if (current_before.st_dev, current_before.st_ino) != (
            current_after.st_dev,
            current_after.st_ino,
        ) or link_before != link_after:
            raise CredentialError(
                "credential_version_changed", "credential current version changed while resolving"
            )
        if not _outside_repo(target, self.repo_root):
            raise CredentialError(
                "credential_source_unsafe", "credential versions must live outside the repository"
            )
        payload, info = _read_exact_file(target)
        version_source = (
            f"{self.definition.fingerprint}:{info.st_dev}:{info.st_ino}:"
            f"{info.st_size}:{info.st_ctime_ns}"
        ).encode()
        version = sha256(version_source).hexdigest()
        return CredentialHandle(
            provider=self.definition.provider,
            credential=self.definition.name,
            version=version,
            provider_fingerprint=self.definition.fingerprint,
            source_reference=str(target),
            source_device=info.st_dev,
            source_inode=info.st_ino,
            target_fingerprint=_target_fingerprint(self.secret, self.definition, version, payload),
        )

    def _read_handle(self, handle: CredentialHandle) -> bytes:
        if (
            handle.provider != self.definition.provider
            or handle.credential != self.definition.name
            or not hmac.compare_digest(handle.provider_fingerprint, self.definition.fingerprint)
        ):
            raise CredentialError(
                "credential_provider_drift", "credential provider definition changed"
            )
        source = Path(handle.source_reference)
        if not source.is_absolute() or not _outside_repo(source, self.repo_root):
            raise CredentialError(
                "credential_handle_invalid", "stored credential source is not trusted"
            )
        payload, _ = _read_exact_file(source, (handle.source_device, handle.source_inode))
        expected = _target_fingerprint(self.secret, self.definition, handle.version, payload)
        if not hmac.compare_digest(handle.target_fingerprint, expected):
            raise CredentialError(
                "credential_version_changed", "credential version contents changed"
            )
        return payload

    @contextmanager
    def materialize(
        self, handle: CredentialHandle, runtime_dir: Path
    ) -> Iterator[CredentialMaterial]:
        payload = self._read_handle(handle)
        fd = _anonymous_fd(payload, runtime_dir)
        descriptor_root = "/proc/self/fd" if Path("/proc/self/fd").is_dir() else "/dev/fd"
        material = CredentialMaterial(
            fd=fd,
            path=f"{descriptor_root}/{fd}",
            redactions=_redaction_values(payload),
        )
        try:
            yield material
        finally:
            os.close(fd)


class CredentialRegistry:
    """Resolve named definitions and reopen exact stored versions."""

    def __init__(
        self,
        definitions: Sequence[CredentialDefinition],
        repo_root: Path,
        secret: bytes,
    ) -> None:
        self._providers: dict[str, CredentialProvider] = {}
        for definition in definitions:
            if definition.provider == "versioned_file":
                provider: CredentialProvider = VersionedFileProvider(definition, repo_root, secret)
            else:  # pragma: no cover - parsing rejects unknown providers
                raise CredentialError(
                    "invalid_config", f"unknown credential provider {definition.provider!r}"
                )
            self._providers[definition.name] = provider

    def resolve_current(self, name: str) -> CredentialHandle:
        provider = self._providers.get(name)
        if provider is None:
            raise CredentialError(
                "credential_unavailable", f"credential {name!r} is not configured"
            )
        return provider.resolve_current()

    @contextmanager
    def materialize(
        self, handle: CredentialHandle, runtime_dir: Path
    ) -> Iterator[CredentialMaterial]:
        provider = self._providers.get(handle.credential)
        if provider is None:
            raise CredentialError(
                "credential_unavailable", "stored credential provider is unavailable"
            )
        with provider.materialize(handle, runtime_dir) as material:
            yield material


def parse_credential_definitions(
    entries: Sequence[Mapping[str, Any]], repo_root: Path
) -> tuple[CredentialDefinition, ...]:
    definitions: list[CredentialDefinition] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        name = str(entry.get("name") or "").strip()
        if not name:
            raise CredentialError("invalid_config", f"credential #{index} needs a name")
        if name in seen:
            raise CredentialError("invalid_config", f"duplicate credential name {name!r}")
        seen.add(name)
        provider = str(entry.get("provider") or "").strip()
        if provider not in PROVIDER_KINDS:
            raise CredentialError(
                "invalid_config", f"credential {name!r} has unknown provider {provider!r}"
            )
        options = {
            str(key): str(value) for key, value in entry.items() if key not in {"name", "provider"}
        }
        if provider == "versioned_file":
            unknown = set(entry) - {"name", "provider", "current"}
            if unknown:
                raise CredentialError(
                    "invalid_config",
                    f"credential {name!r} has unknown options: {', '.join(sorted(unknown))}",
                )
            current = Path(options.get("current", "")).expanduser()
            if not current.is_absolute():
                raise CredentialError(
                    "invalid_config",
                    f"credential {name!r} current path must be absolute",
                )
            if not _outside_repo(current, repo_root):
                raise CredentialError(
                    "credential_source_unsafe",
                    f"credential {name!r} current path must live outside the repository",
                )
            options = {"current": str(current)}
        definitions.append(CredentialDefinition(name=name, provider=provider, options=options))
    return tuple(definitions)
