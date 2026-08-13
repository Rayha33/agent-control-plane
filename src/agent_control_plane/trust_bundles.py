"""Install, pin, and verify immutable privileged executable bundles.

The installer copies from already-open, no-follow file descriptors.  Runtime
consumers never follow a mutable ``current`` name after an attempt starts: they
store the returned manifest, inode, and content digests and revalidate that pin
before every privileged execution.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import sys
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

BUNDLE_FORMAT = "acp.trust-bundle.v1"
if sys.platform == "darwin":
    DEFAULT_TRUST_ROOT = Path("/Library/Application Support/AgentControlPlane/trust")
    DEFAULT_HELPER = Path("/Library/PrivilegedHelperTools/acp-trust-helper")
else:
    DEFAULT_TRUST_ROOT = Path("/var/lib/agent-control-plane/trust")
    DEFAULT_HELPER = Path("/usr/local/libexec/acp-trust-helper")
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class TrustBundleError(RuntimeError):
    def __init__(self, code: str, message: str, errors: list[str] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.errors = errors or [message]


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _safe_label(value: str, kind: str) -> str:
    if not _SAFE_LABEL.fullmatch(value):
        raise TrustBundleError("invalid_trust_bundle", f"unsafe {kind}: {value!r}")
    return value


def _safe_relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise TrustBundleError("invalid_trust_bundle", f"unsafe source path: {value!r}")
    return path


def _open_source(root_fd: int, relative: PurePosixPath) -> int:
    """Open a regular source file without following any path component."""

    current = os.dup(root_fd)
    try:
        for component in relative.parts[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=current,
            )
            os.close(current)
            current = next_fd
        return os.open(
            relative.parts[-1],
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=current,
        )
    except OSError as error:
        raise TrustBundleError(
            "untrusted_bundle_source", f"source path is missing, replaced, or a symlink: {relative}"
        ) from error
    finally:
        os.close(current)


def _open_absolute_directory(path: Path) -> int:
    """Open an absolute directory without following intermediate symlinks."""

    if not path.is_absolute():
        raise TrustBundleError("untrusted_bundle_source", "source directory must be absolute")
    current = os.open(
        path.anchor,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        for component in path.parts[1:]:
            next_fd = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=current,
            )
            os.close(current)
            current = next_fd
        return current
    except OSError as error:
        os.close(current)
        raise TrustBundleError(
            "untrusted_bundle_source", "source path contains a symlink or non-directory"
        ) from error


def _chown(path: Path, owner_uid: int) -> None:
    if os.geteuid() == 0:
        os.chown(path, owner_uid, -1, follow_symlinks=False)


def _secure_directory(path: Path, owner_uid: int, mode: int = 0o755) -> None:
    try:
        details = path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=mode)
        _chown(path, owner_uid)
        os.chmod(path, mode, follow_symlinks=False)
        details = path.lstat()
    if not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode):
        raise TrustBundleError("insecure_trust_root", f"trust path is not a real directory: {path}")
    if details.st_uid not in {0, owner_uid}:
        raise TrustBundleError("insecure_trust_root", f"trust directory has wrong owner: {path}")
    if details.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise TrustBundleError(
            "insecure_trust_root", f"trust directory is group/world writable: {path}"
        )


def _validate_parent_chain(path: Path, owner_uid: int) -> None:
    cursor = path
    while True:
        try:
            details = cursor.lstat()
        except OSError as error:
            raise TrustBundleError(
                "insecure_trust_root", f"trust parent is unavailable: {cursor}"
            ) from error
        if not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode):
            raise TrustBundleError(
                "insecure_trust_root", f"trust parent is a symlink or non-directory: {cursor}"
            )
        if details.st_uid not in {0, owner_uid}:
            raise TrustBundleError(
                "insecure_trust_root", f"trust parent has unexpected owner: {cursor}"
            )
        writable = details.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        sticky_root_anchor = details.st_uid == 0 and bool(details.st_mode & stat.S_ISVTX)
        if writable and not sticky_root_anchor:
            raise TrustBundleError(
                "insecure_trust_root", f"trust parent is group/world writable: {cursor}"
            )
        if sticky_root_anchor or cursor == cursor.parent:
            return
        cursor = cursor.parent


def _prepare_root(root: Path, owner_uid: int, *, allow_create: bool = False) -> None:
    if owner_uid < 0:
        raise TrustBundleError("invalid_trust_owner", "owner UID must be non-negative")
    # Packaging creates the system parent.  Creating the final root here keeps
    # local/test installs useful without recursively changing unrelated parents.
    if not root.exists():
        if not allow_create:
            raise TrustBundleError(
                "insecure_trust_root",
                "trust root must be pre-created by the OS package before privileged install",
            )
        root.mkdir(parents=True, mode=0o755)
        _chown(root, owner_uid)
        os.chmod(root, 0o755, follow_symlinks=False)
    _validate_parent_chain(root, owner_uid)
    _secure_directory(root, owner_uid)
    for name in ("bundles", "retired"):
        _secure_directory(root / name, owner_uid)


def _write_all(fd: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        offset += os.write(fd, value[offset:])


def _atomic_pointer(root: Path, bundle_id: str, owner_uid: int) -> None:
    temporary = root / f".current-{secrets.token_hex(8)}"
    fd = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        _write_all(fd, (bundle_id + "\n").encode())
        os.fsync(fd)
        os.fchmod(fd, 0o444)
        if os.geteuid() == 0:
            os.fchown(fd, owner_uid, -1)
    finally:
        os.close(fd)
    os.replace(temporary, root / "current")
    directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _remove_staging(staging: Path) -> None:
    if not staging.exists():
        return
    staging.chmod(0o700, follow_symlinks=False)
    for child in staging.iterdir():
        child.chmod(0o600, follow_symlinks=False)
        child.unlink()
    staging.rmdir()


def install_bundle(
    source: str | Path,
    root: str | Path,
    version: str,
    executables: Mapping[str, str],
    *,
    owner_uid: int = 0,
    require_privilege: bool = True,
) -> dict[str, Any]:
    """Copy and activate a bundle through the privileged-helper boundary."""

    if require_privilege and os.geteuid() not in {0, owner_uid}:
        raise TrustBundleError(
            "trust_helper_privilege_required",
            f"installer must run as root or dedicated trust UID {owner_uid}",
        )
    version = _safe_label(version, "version")
    if not executables:
        raise TrustBundleError("invalid_trust_bundle", "at least one executable is required")
    normalized = {
        _safe_label(str(name), "executable name"): _safe_relative(str(relative))
        for name, relative in executables.items()
    }
    destination_root = Path(root).expanduser().absolute()
    _prepare_root(destination_root, owner_uid, allow_create=not require_privilege)
    source_path = Path(source).expanduser().absolute()
    try:
        source_fd = _open_absolute_directory(source_path)
    except OSError as error:
        raise TrustBundleError(
            "untrusted_bundle_source", "source must be a real, readable directory"
        ) from error

    staging = destination_root / "bundles" / f".stage-{secrets.token_hex(12)}"
    staging.mkdir(mode=0o700)
    _chown(staging, owner_uid)
    manifest_files: dict[str, dict[str, Any]] = {}
    try:
        for name, relative in sorted(normalized.items()):
            source_file_fd = _open_source(source_fd, relative)
            target = staging / name
            try:
                before = os.fstat(source_file_fd)
                if not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o111:
                    raise TrustBundleError(
                        "untrusted_bundle_source", f"source is not a regular executable: {relative}"
                    )
                target_fd = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o500,
                )
                digest = hashlib.sha256()
                total = 0
                try:
                    while True:
                        chunk = os.read(source_file_fd, 1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
                        _write_all(target_fd, chunk)
                        total += len(chunk)
                    os.fsync(target_fd)
                    os.fchmod(target_fd, 0o555)
                    if os.geteuid() == 0:
                        os.fchown(target_fd, owner_uid, -1)
                finally:
                    os.close(target_fd)
                after = os.fstat(source_file_fd)
                identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                if identity_before != identity_after or total != before.st_size:
                    raise TrustBundleError(
                        "bundle_source_changed", f"source changed while being copied: {relative}"
                    )
                installed = target.stat()
                manifest_files[name] = {
                    "path": name,
                    "sha256": digest.hexdigest(),
                    "size": total,
                    "mode": stat.S_IMODE(installed.st_mode),
                }
            finally:
                os.close(source_file_fd)
        manifest = {
            "format": BUNDLE_FORMAT,
            "version": version,
            "owner_uid": owner_uid,
            "executables": manifest_files,
        }
        manifest_bytes = _canonical(manifest)
        manifest_sha256 = _digest(manifest_bytes)
        bundle_id = f"{version}-{manifest_sha256}"
        manifest_path = staging / "manifest.json"
        manifest_fd = os.open(
            manifest_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        try:
            _write_all(manifest_fd, manifest_bytes)
            os.fsync(manifest_fd)
            os.fchmod(manifest_fd, 0o444)
            if os.geteuid() == 0:
                os.fchown(manifest_fd, owner_uid, -1)
        finally:
            os.close(manifest_fd)
        os.chmod(staging, 0o555, follow_symlinks=False)
        final = destination_root / "bundles" / bundle_id
        if final.exists():
            existing_manifest = _read_regular(final / "manifest.json")
            if _digest(existing_manifest) != manifest_sha256:
                raise TrustBundleError("trust_bundle_collision", f"bundle id collision at {final}")
            _remove_staging(staging)
        else:
            try:
                os.rename(staging, final)
            except FileExistsError:
                _remove_staging(staging)
        pin = load_bundle(destination_root, bundle_id, owner_uid=owner_uid)
        _atomic_pointer(destination_root, bundle_id, owner_uid)
    except Exception:
        _remove_staging(staging)
        raise
    finally:
        os.close(source_fd)
    return pin


def _read_regular(path: Path, *, limit: int = 1024 * 1024) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise TrustBundleError(
            "trust_bundle_missing", f"trusted file is unavailable: {path}"
        ) from error
    try:
        details = os.fstat(fd)
        if not stat.S_ISREG(details.st_mode) or details.st_size > limit:
            raise TrustBundleError(
                "invalid_trust_bundle", f"trusted file is not a bounded regular file: {path}"
            )
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        if len(value) > limit:
            raise TrustBundleError(
                "invalid_trust_bundle", f"trusted file exceeds size limit: {path}"
            )
        return value
    finally:
        os.close(fd)


def _hash_regular(path: Path) -> tuple[os.stat_result, str, int]:
    try:
        fd = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as error:
        raise TrustBundleError(
            "trust_bundle_missing", f"trusted file is unavailable: {path}"
        ) from error
    try:
        details = os.fstat(fd)
        if not stat.S_ISREG(details.st_mode):
            raise TrustBundleError("invalid_trust_bundle", f"trusted file is not regular: {path}")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(fd)
        if (details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) or total != details.st_size:
            raise TrustBundleError(
                "trust_bundle_tampered", f"trusted file changed while read: {path}"
            )
        return after, digest.hexdigest(), total
    finally:
        os.close(fd)


def current_bundle_id(root: str | Path, *, owner_uid: int = 0) -> str:
    pointer = Path(root) / "current"
    try:
        details = pointer.lstat()
    except OSError as error:
        raise TrustBundleError(
            "trust_bundle_missing", "current trust pointer is unavailable"
        ) from error
    if (
        not stat.S_ISREG(details.st_mode)
        or stat.S_ISLNK(details.st_mode)
        or details.st_uid not in {0, owner_uid}
        or details.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise TrustBundleError("insecure_trust_bundle", "current trust pointer is unsafe")
    value = _read_regular(pointer, limit=256).decode("utf-8").strip()
    return _safe_label(value, "bundle id")


def load_bundle(root: str | Path, bundle_id: str, *, owner_uid: int = 0) -> dict[str, Any]:
    """Validate an immutable bundle and return the complete runtime pin."""

    bundle_id = _safe_label(bundle_id, "bundle id")
    trust_root = Path(root).expanduser().absolute()
    bundle = trust_root / "bundles" / bundle_id
    manifest_bytes = _read_regular(bundle / "manifest.json")
    try:
        manifest = json.loads(manifest_bytes)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise TrustBundleError("invalid_trust_bundle", "bundle manifest is invalid JSON") from error
    if manifest.get("format") != BUNDLE_FORMAT or manifest.get("owner_uid") != owner_uid:
        raise TrustBundleError("invalid_trust_bundle", "bundle manifest format or owner is invalid")
    if manifest_bytes != _canonical(manifest):
        raise TrustBundleError("invalid_trust_bundle", "bundle manifest is not canonical JSON")
    files = manifest.get("executables")
    if not isinstance(files, dict) or not files:
        raise TrustBundleError("invalid_trust_bundle", "bundle manifest has no executables")
    pin: dict[str, Any] = {
        "format": BUNDLE_FORMAT,
        "root": str(trust_root),
        "bundle_id": bundle_id,
        "version": str(manifest.get("version", "")),
        "owner_uid": owner_uid,
        "manifest_sha256": _digest(manifest_bytes),
        "executables": {},
    }
    for name, record in sorted(files.items()):
        _safe_label(str(name), "executable name")
        if not isinstance(record, dict) or record.get("path") != name:
            raise TrustBundleError("invalid_trust_bundle", f"invalid executable record: {name}")
        path = bundle / name
        try:
            details = path.lstat()
        except OSError:
            details = None
        expected_digest = record.get("sha256")
        expected_size = record.get("size")
        if (
            not isinstance(expected_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_digest)
            or isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size < 0
        ):
            raise TrustBundleError("invalid_trust_bundle", f"invalid executable digest: {name}")
        pin["executables"][name] = {
            "path": str(path),
            "sha256": expected_digest,
            "size": expected_size,
            "device": details.st_dev if details else None,
            "inode": details.st_ino if details else None,
        }
    diagnostics = verify_bundle_pin(pin)
    if not diagnostics["ok"]:
        raise TrustBundleError(
            "insecure_trust_bundle",
            "; ".join(diagnostics["errors"]),
            diagnostics["errors"],
        )
    return pin


def load_current_bundle(root: str | Path, *, owner_uid: int = 0) -> dict[str, Any]:
    return load_bundle(root, current_bundle_id(root, owner_uid=owner_uid), owner_uid=owner_uid)


def executable_from_pin(pin: Mapping[str, Any], name: str) -> Path:
    try:
        return Path(pin["executables"][name]["path"])
    except (KeyError, TypeError) as error:
        raise TrustBundleError(
            "trust_executable_missing",
            f"bundle {pin.get('bundle_id', '?')} has no executable {name!r}",
        ) from error


def verify_bundle_pin(pin: Mapping[str, Any]) -> dict[str, Any]:
    """Return every failed check so ``acp doctor`` is diagnostic, not binary."""

    errors: list[str] = []
    root = Path(str(pin.get("root", "")))
    bundle_id = str(pin.get("bundle_id", ""))
    owner_uid = pin.get("owner_uid")
    if not root.is_absolute():
        errors.append("trust root is not absolute")
    try:
        _safe_label(bundle_id, "bundle id")
    except TrustBundleError as error:
        errors.append(error.message)
    bundle = root / "bundles" / bundle_id
    # Check every directory in the controlled tree. Avoid resolve(), which
    # would hide symlink substitution.
    controlled_paths: list[Path] = []
    cursor = root
    while True:
        controlled_paths.append(cursor)
        try:
            cursor_details = cursor.lstat()
        except OSError:
            break
        if (
            cursor_details.st_uid == 0
            and cursor_details.st_mode & stat.S_ISVTX
            and cursor_details.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ) or cursor == cursor.parent:
            break
        cursor = cursor.parent
    controlled_paths.extend((root / "bundles", bundle))
    for path in dict.fromkeys(controlled_paths):
        try:
            details = path.lstat()
        except OSError:
            errors.append(f"missing trust directory: {path}")
            continue
        if not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode):
            errors.append(f"trust directory is a symlink or non-directory: {path}")
        if details.st_uid not in {0, owner_uid}:
            errors.append(f"unexpected trust directory owner: {path}")
        if details.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            sticky_root_anchor = details.st_uid == 0 and bool(details.st_mode & stat.S_ISVTX)
            if not sticky_root_anchor:
                errors.append(f"group/world-writable trust directory: {path}")
        if path == bundle and details.st_mode & stat.S_IWUSR:
            errors.append(f"mutable bundle directory: {path}")
    manifest_path = bundle / "manifest.json"
    try:
        manifest_details = manifest_path.lstat()
        manifest_bytes = _read_regular(manifest_path)
    except (OSError, TrustBundleError):
        errors.append(f"missing or unsafe manifest: {manifest_path}")
        manifest_details = None
        manifest_bytes = b""
    if manifest_details is not None:
        if manifest_details.st_uid not in {0, owner_uid}:
            errors.append("unexpected manifest owner")
        if manifest_details.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            errors.append("group/world-writable manifest")
        if manifest_details.st_mode & stat.S_IWUSR:
            errors.append("mutable manifest")
        actual_manifest = _digest(manifest_bytes)
        if actual_manifest != pin.get("manifest_sha256"):
            errors.append(
                f"manifest digest mismatch: expected {pin.get('manifest_sha256')}, got {actual_manifest}"
            )
    executables = pin.get("executables", {})
    if not isinstance(executables, dict) or not executables:
        errors.append("pin has no executables")
        executables = {}
    for name, expected in sorted(executables.items()):
        path = Path(str(expected.get("path", "")))
        expected_path = bundle / str(name)
        if path != expected_path:
            errors.append(f"executable {name} escapes pinned bundle: {path}")
            continue
        try:
            details, actual, actual_size = _hash_regular(path)
        except TrustBundleError:
            errors.append(f"missing pinned executable {name}: {path}")
            continue
        if details.st_uid not in {0, owner_uid}:
            errors.append(f"unexpected owner for pinned executable {name}")
        if details.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            errors.append(f"group/world-writable pinned executable {name}")
        if details.st_mode & stat.S_IWUSR:
            errors.append(f"mutable pinned executable {name}")
        if not details.st_mode & 0o111:
            errors.append(f"pinned executable {name} is not executable")
        if (details.st_dev, details.st_ino) != (expected.get("device"), expected.get("inode")):
            errors.append(f"inode mismatch for pinned executable {name}")
        if actual != expected.get("sha256"):
            errors.append(
                f"digest mismatch for pinned executable {name}: expected {expected.get('sha256')}, got {actual}"
            )
        if actual_size != expected.get("size"):
            errors.append(f"size mismatch for pinned executable {name}")
    return {"ok": not errors, "bundle_id": bundle_id, "errors": errors}


def diagnose_current(root: str | Path, *, owner_uid: int = 0) -> dict[str, Any]:
    try:
        pin = load_current_bundle(root, owner_uid=owner_uid)
    except TrustBundleError as error:
        return {
            "ok": False,
            "bundle_id": None,
            "errors": [f"{error.code}: {item}" for item in error.errors],
        }
    return verify_bundle_pin(pin)


def retire_bundle(root: str | Path, bundle_id: str, *, owner_uid: int = 0) -> dict[str, Any]:
    """Mark a bundle retired without deleting evidence referenced by attempts/QC."""

    trust_root = Path(root).expanduser().absolute()
    _prepare_root(trust_root, owner_uid)
    bundle_id = _safe_label(bundle_id, "bundle id")
    if current_bundle_id(trust_root, owner_uid=owner_uid) == bundle_id:
        raise TrustBundleError(
            "active_bundle", "rotate current to a different bundle before retiring it"
        )
    load_bundle(trust_root, bundle_id, owner_uid=owner_uid)
    marker = trust_root / "retired" / bundle_id
    try:
        fd = os.open(
            marker,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o444,
        )
    except FileExistsError:
        return {"bundle_id": bundle_id, "retired": True, "deleted": False}
    try:
        _write_all(fd, b"retired\n")
        os.fsync(fd)
        if os.geteuid() == 0:
            os.fchown(fd, owner_uid, -1)
    finally:
        os.close(fd)
    return {"bundle_id": bundle_id, "retired": True, "deleted": False}


def activate_bundle(root: str | Path, bundle_id: str, *, owner_uid: int = 0) -> dict[str, Any]:
    """Atomically make an already-installed immutable bundle current."""

    trust_root = Path(root).expanduser().absolute()
    pin = load_bundle(trust_root, bundle_id, owner_uid=owner_uid)
    _atomic_pointer(trust_root, pin["bundle_id"], owner_uid)
    return pin


def list_bundles(root: str | Path, *, owner_uid: int = 0) -> dict[str, Any]:
    trust_root = Path(root).expanduser().absolute()
    current = current_bundle_id(trust_root, owner_uid=owner_uid)
    bundles = []
    for path in sorted((trust_root / "bundles").iterdir()):
        if path.name.startswith("."):
            continue
        try:
            pin = load_bundle(trust_root, path.name, owner_uid=owner_uid)
            health = verify_bundle_pin(pin)
        except TrustBundleError as error:
            health = {
                "ok": False,
                "errors": [f"{error.code}: {item}" for item in error.errors],
            }
        bundles.append(
            {
                "bundle_id": path.name,
                "current": path.name == current,
                "retired": (trust_root / "retired" / path.name).is_file(),
                "health": health,
            }
        )
    return {"root": str(trust_root), "current": current, "bundles": bundles}
