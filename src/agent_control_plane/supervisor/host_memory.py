"""Bounded, best-effort host-memory observations for worker admission.

The only supported signal is Linux ``MemAvailable``. It is an OS estimate of
memory available without swapping, not a promise that a worker fits or that an
OOM cannot occur. Unsupported or unreadable observations remain explicit.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

_MEMINFO_PATH = Path("/proc/meminfo")
_MAX_MEMINFO_BYTES = 64 * 1024
_MAX_AVAILABLE_BYTES = 2**63 - 1
_MEMAVAILABLE = re.compile(r"[ \t]*([0-9]+)[ \t]+kB[ \t]*\Z", re.ASCII)


@dataclass(frozen=True)
class HostMemorySnapshot:
    """Small operator-safe sample; contains no process arguments or environment."""

    status: str
    source: str | None
    observed_at: str | None
    available_bytes: int | None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "source": self.source,
            "observed_at": self.observed_at,
            "available_bytes": self.available_bytes,
            "error": self.error,
        }


def _unavailable(error: str) -> HostMemorySnapshot:
    return HostMemorySnapshot("unavailable", "linux.proc_meminfo.MemAvailable", None, None, error)


def read_host_memory_snapshot() -> HostMemorySnapshot:
    """Read one bounded, non-symlink-following Linux MemAvailable sample."""

    if not sys.platform.startswith("linux"):
        return HostMemorySnapshot("unsupported", None, None, None, "platform_unsupported")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(_MEMINFO_PATH, flags)
    except OSError:
        return _unavailable("read_failed")
    try:
        try:
            raw = os.read(descriptor, _MAX_MEMINFO_BYTES + 1)
        except OSError:
            return _unavailable("read_failed")
    finally:
        os.close(descriptor)

    if len(raw) > _MAX_MEMINFO_BYTES:
        return _unavailable("sample_too_large")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return _unavailable("sample_not_ascii")

    available_values: list[int] = []
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if key != "MemAvailable":
            continue
        match = _MEMAVAILABLE.fullmatch(value) if separator else None
        if match is None:
            return _unavailable("malformed_memavailable")
        digits = match.group(1)
        if len(digits) > 16:
            return _unavailable("memavailable_out_of_range")
        try:
            kibibytes = int(digits)
        except ValueError:
            return _unavailable("malformed_memavailable")
        byte_count = kibibytes * 1024
        if byte_count > _MAX_AVAILABLE_BYTES:
            return _unavailable("memavailable_out_of_range")
        available_values.append(byte_count)

    if len(available_values) != 1:
        return _unavailable("memavailable_missing_or_duplicate")
    return HostMemorySnapshot(
        "available",
        "linux.proc_meminfo.MemAvailable",
        datetime.now(UTC).isoformat(),
        available_values[0],
    )


def host_memory_snapshot_is_fresh(
    snapshot: HostMemorySnapshot,
    *,
    now: datetime | None = None,
    max_age_seconds: int = 5,
) -> bool:
    """Validate signal shape and a narrow timestamp window before admission."""

    if (
        snapshot.status != "available"
        or snapshot.source != "linux.proc_meminfo.MemAvailable"
        or type(snapshot.available_bytes) is not int
        or not 0 <= snapshot.available_bytes <= _MAX_AVAILABLE_BYTES
        or not isinstance(snapshot.observed_at, str)
    ):
        return False
    try:
        observed_at = datetime.fromisoformat(snapshot.observed_at)
    except ValueError:
        return False
    if observed_at.tzinfo is None or observed_at.utcoffset() != timedelta(0):
        return False
    current = now or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() != timedelta(0):
        return False
    age_seconds = (current - observed_at).total_seconds()
    return -1.0 <= age_seconds <= max_age_seconds
