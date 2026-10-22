"""Opt-in Linux/systemd proofs for OCI launch-driver and monitor components.

The process-local runc handle must remain in the exact systemd launch-driver
process; a separate systemd-owned service controls the exact worker scope. The
default branch proves launch-to-``running``, natural completion, and
reaper-driven cleanup verification/runtime release. Opt-in branches also cover
fresh-supervisor cancellation, launch-driver timeout, and cleanup recovery after
a launch-driver crash between durable wait and cleanup report. The production
producer runs in a short-lived process that exits abruptly after durable
handoff; fresh supervisor processes cancel (when requested) and reap the exact
execution. An additional opt-in natural-completion branch asks the independent
cleanup verifier to prove teardown, performs a deterministic source edit and
test inside the private workspace, then imports the host-captured result into
the normal pending-QC submission path. An explicit opt-in mode drives that
fixture through ``WorkersMixin.run_worker`` and its verified-import boundary;
it can be combined with the host-path probes to test those denials through the
public supervisor path. A separate synthetic FD4 canary may be combined only
with that supervised/import mode, proving the test-only descriptor handoff,
cleanup verification, and digest-only result import in one no-provider run.
These are no-model executor proofs; they do not start a provider/model worker
or enable the default ``run_worker`` path.

The legacy direct-monitor lifecycle fixture is intentionally skipped: it starts
runc from a monitor-owned service and cannot satisfy the current launch-driver
redemption contract. The production launch-driver test remains opt-in. Its
default branch verifies natural completion; setting
`ACP_LIVE_CANCEL_AFTER_START=1` runs the same fixture with a long payload and
verifies cancellation from a fresh supervisor. Setting
`ACP_LIVE_TIMEOUT_AFTER_START=1` uses a one-second driver timeout with a long
payload and verifies automatic stop-intent recording, monitor cancellation,
and cleanup verification. Setting
`ACP_LIVE_LEASE_EXPIRY_AFTER_STOP=1` records a durable stop, expires the exact
fixture attempt, runs the production reaper in a fresh process, and verifies
lease-loss quarantine, launch-driver monitor cancellation, pinned-runc deletion,
and retained resource fences until independent cleanup verification. Setting
`ACP_LIVE_CRASH_AFTER_MANAGER_ACCEPTANCE=1` exits the producer after successful
`systemd-run` return but before receipt propagation, then verifies a fresh
producer cannot replay the launch. Crash, cancellation, timeout, and lease-expiry
modes are mutually exclusive. Run on a disposable supported Linux host
with rootless runc 1.5.2,
delegated cgroup v2, and an active private systemd user manager:

    ACP_RUN_SANDBOX_WORKER_LIFECYCLE=1 \
    ACP_OCI_TEST_RUNC=/usr/bin/runc \
    ACP_OCI_TEST_RUNC_VERSION=1.5.2 \
    uv run --extra dev pytest -q tests/test_sandbox_worker_lifecycle_integration.py

For a disposable-guest proof of the production attempt-scoped provider UDS
mount, cgroup peer authorization, destination denial, and teardown, add:

    ACP_LIVE_PROVIDER_PROXY_UDS=1

This mode makes no DNS lookup or provider connection. It must run alone with
natural worker completion; it does not enable the generic ``run_worker`` path.
To additionally prove that cancellation closes a connected/open partial UDS
request, combine ``ACP_LIVE_PROVIDER_PROXY_CANCEL=1`` with
``ACP_LIVE_CANCEL_AFTER_START=1``. Neither mode uses provider credentials;
service-level accepted-channel shutdown is separately covered by unit tests.

For the launch-driver post-wait/pre-report recovery boundary, combine:

    ACP_LIVE_PROVIDER_PROXY_UDS=1
    ACP_LIVE_CRASH_AFTER_EXIT_BEFORE_CLEANUP_REPORT=1

This creates and inode-checks the real provider socket/directory but sends no
provider-proxy request. A test-only service wrapper exits after the kernel wait
is durably recorded and the proxy is closed, before pinned-runc deletion or the
cleanup report; a fresh production reaper must finish exact cleanup and resource
release. It makes no DNS lookup or provider/model call and uses no credentials.

For the fresh-supervisor cancellation branch, add:

    ACP_LIVE_CANCEL_AFTER_START=1

For the launch-driver timeout branch, add:

    ACP_LIVE_TIMEOUT_AFTER_START=1

For the durable-stop / lease-expiry race branch, add:

    ACP_LIVE_LEASE_EXPIRY_AFTER_STOP=1

For the manager-accepted/pre-receipt crash branch, add:

    ACP_LIVE_CRASH_AFTER_MANAGER_ACCEPTANCE=1

For the live crash after the recovery monitor is accepted but before the
launch-driver records that receipt, add:

    ACP_LIVE_CRASH_AFTER_MONITOR_ACCEPTANCE=1

For a driver crash after the gated runc scope exists but before monitor
activation is requested, add:

    ACP_LIVE_CRASH_BEFORE_MONITOR_START=1

To re-exec the user manager after the launch-driver crash and before fresh
supervisor reconciliation, combine either monitor crash mode with:

    ACP_LIVE_USER_MANAGER_REEXEC_AFTER_DRIVER_CRASH=1

This verifies transient unit identities survive `systemctl --user daemon-reexec`;
it does not simulate manager shutdown, logout/linger, or reboot.

For an actual systemd user-manager service restart in a disposable VM, combine
either monitor crash mode with:

    ACP_LIVE_USER_MANAGER_RESTART_AFTER_DRIVER_CRASH=1
    ACP_LIVE_USER_MANAGER_RESTART_DISPOSABLE_HOST=<exact-guest-hostname>
    ACP_LIVE_USER_MANAGER_RESTART_ACK=RESTART_ONLY_THIS_DISPOSABLE_GUEST

This additionally requires `systemd-detect-virt --quiet --vm`, Debian 12,
passwordless `sudo -n`, and the exact allowlisted Debian 12 Lima unit inventory.
It compares all rows from `systemctl --user list-units --all`, including device
units and unrecognized unit types, against the exact baseline. It also checks
every process in the manager cgroup against the exact manager, D-Bus, and
test-unit cgroups. Any unrecognized unit, state, or process fails closed. It
restarts only the current test user's `user@<uid>.service`. Before
fresh-supervisor recovery, the driver and monitor services and worker scope
must be absent, with no test process remaining. Systemd may retain the exact
attempt-specific slice as `loaded/inactive/dead`; if so, its control group must
be empty and the manager-cgroup process audit must still pass. No other test
unit may remain. A timeout or uncertain postflight preserves the VM and fixture
for manual inspection without retry or automatic cleanup. Never use this mode
on a shared host or the NAS.

For natural completion followed by production cleanup verification, a
deterministic in-sandbox source edit and test, and host-side sandbox-result
import (mutually exclusive with cancellation, timeout, and crash modes), add:

    ACP_LIVE_IMPORT_RESULT_AFTER_CLEANUP=1

For two simultaneous, isolated cancellation attempts on the same disposable
Linux host, add:

    ACP_LIVE_CONCURRENT_ATTEMPTS=1

This launches two fresh pytest processes with no provider credentials, observes
two distinct live ACP scopes in consecutive samples, and requires both exact
launch-driver fixtures to verify cancellation and teardown. It does not prove
same-repository cross-attempt workspace isolation or wire ``run_worker``.
"""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import posixpath
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path, PurePosixPath
from typing import Any
from unittest.mock import patch

import pytest
from support import init_repo, make_task
from test_oci_worker_runtime import (
    _CONTAINER_CPU_PERIOD_US,
    _CONTAINER_CPU_QUOTA_US,
    _CONTAINER_MEMORY_BYTES,
    _CONTAINER_PIDS_LIMIT,
    _copy_busybox_closure,
)

import agent_control_plane.supervisor.oci_worker as oci_worker
from agent_control_plane.git_supervisor import GitSupervisor
from agent_control_plane.supervisor import (
    sandbox_attestation,
    sandbox_launch_driver_service,
    sandbox_monitor_ipc,
    sandbox_monitor_lifecycle,
    sandbox_monitor_service,
)
from agent_control_plane.supervisor import (
    sandbox_execution_journal as journal_module,
)
from agent_control_plane.supervisor.common import SupervisorError, utc_now
from agent_control_plane.supervisor.sandbox_attestation import collect_running_runtime_attestation
from agent_control_plane.supervisor.sandbox_monitor_ipc import _linux_process_identity
from agent_control_plane.supervisor.sandbox_monitor_receipt import (
    sandbox_attempt_slice_unit,
    sandbox_monitor_service_unit,
)
from agent_control_plane.supervisor.sandbox_workspace import collect_changes, copy_snapshot

_LIVE_ENABLED = os.environ.get("ACP_RUN_SANDBOX_WORKER_LIFECYCLE") == "1"
_SUPPORTED_RUNC_VERSION = "1.5.2"
_PROVIDER_PROXY_PROBE_SOURCE = r"""#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/un.h>
#include <unistd.h>

static bool denied_socket_family(int family, int type) {
    int fd = socket(family, type, 0);
    if (fd >= 0) {
        close(fd);
        return false;
    }
    return errno == EPERM || errno == EACCES || errno == EAFNOSUPPORT || errno == ENOSYS;
}

static bool proxy_request_has_status(const char *request, const char *status) {
    const char *path = getenv("ACP_PROVIDER_PROXY_UNIX_SOCKET");
    if (path == NULL || strcmp(path, "/run/acp/provider.sock") != 0) {
        return false;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return false;
    }
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(address.sun_path)) {
        close(fd);
        return false;
    }
    memcpy(address.sun_path, path, strlen(path) + 1);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return false;
    }
    size_t request_size = strlen(request);
    size_t sent = 0;
    while (sent < request_size) {
        ssize_t count = send(fd, request + sent, request_size - sent, 0);
        if (count <= 0) {
            close(fd);
            return false;
        }
        sent += (size_t)count;
    }
    shutdown(fd, SHUT_WR);
    char response[1024];
    size_t received = 0;
    while (received + 1 < sizeof(response)) {
        ssize_t count = recv(fd, response + received, sizeof(response) - received - 1, 0);
        if (count <= 0) {
            break;
        }
        received += (size_t)count;
    }
    response[received] = '\0';
    close(fd);
    return strstr(response, status) != NULL;
}

#if defined(ACP_LIVE_PROVIDER_CANCEL)
static int connect_provider_proxy(void) {
    const char *path = getenv("ACP_PROVIDER_PROXY_UNIX_SOCKET");
    if (path == NULL || strcmp(path, "/run/acp/provider.sock") != 0) {
        return -1;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(address.sun_path)) {
        close(fd);
        return -1;
    }
    memcpy(address.sun_path, path, strlen(path) + 1);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}
#endif

int main(void) {
    const char *path = getenv("ACP_PROVIDER_PROXY_UNIX_SOCKET");
    struct statvfs mount_info;
    struct stat socket_info;
    if (path == NULL || strcmp(path, "/run/acp/provider.sock") != 0) return 2;
    if (statvfs("/run/acp", &mount_info) != 0 || !(mount_info.f_flag & ST_RDONLY)) return 3;
    if (lstat(path, &socket_info) != 0 || !S_ISSOCK(socket_info.st_mode)) return 4;
    if (!denied_socket_family(AF_INET, SOCK_STREAM)) return 5;
    if (!denied_socket_family(AF_INET, SOCK_DGRAM)) return 6;
    if (!denied_socket_family(AF_INET6, SOCK_STREAM)) return 7;
    if (!denied_socket_family(AF_INET6, SOCK_DGRAM)) return 8;
    if (!proxy_request_has_status("NOT-CONNECT / HTTP/1.1\r\n\r\n", "400 Bad Request")) return 9;
    if (!proxy_request_has_status(
            "CONNECT blocked.example.invalid:443 HTTP/1.1\r\n"
            "Host: blocked.example.invalid:443\r\n\r\n",
            "403 Forbidden")) return 10;
    int marker = open("/workspace/provider-probe-result", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (marker < 0) return 11;
    const char result[] = "attempt-uds-policy-pass\n";
    if (write(marker, result, sizeof(result) - 1) != (ssize_t)(sizeof(result) - 1)) {
        close(marker);
        return 12;
    }
    close(marker);
#if defined(ACP_LIVE_PROVIDER_CANCEL)
    int pending = connect_provider_proxy();
    if (pending < 0) return 13;
    const char partial_request[] = "CONNECT ";
    if (send(pending, partial_request, sizeof(partial_request) - 1, 0)
            != (ssize_t)(sizeof(partial_request) - 1)) {
        close(pending);
        return 14;
    }
    int open_marker = open("/workspace/provider-probe-open", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (open_marker < 0) {
        close(pending);
        return 15;
    }
    const char opened[] = "partial-connect-open\n";
    if (write(open_marker, opened, sizeof(opened) - 1) != (ssize_t)(sizeof(opened) - 1)) {
        close(open_marker);
        close(pending);
        return 16;
    }
    close(open_marker);
    for (;;) pause();
#else
    for (int attempt = 0; attempt < 30000; ++attempt) {
        if (access("/workspace/provider-probe-release", F_OK) == 0) return 0;
        usleep(1000);
    }
    return 17;
#endif
    return 0;
}
"""
_WORKER_CANARY_FD4_PROBE_SOURCE = r"""
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    uint32_t state[8];
    uint64_t bit_length;
    unsigned char block[64];
    size_t block_length;
} sha256_context;

static const uint32_t sha256_round_constants[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t rotate_right(uint32_t value, unsigned int count) {
    return (value >> count) | (value << (32 - count));
}

static void sha256_transform(sha256_context *context, const unsigned char block[64]) {
    uint32_t words[64];
    for (size_t index = 0; index < 16; index++) {
        size_t offset = index * 4;
        words[index] = ((uint32_t) block[offset] << 24)
            | ((uint32_t) block[offset + 1] << 16)
            | ((uint32_t) block[offset + 2] << 8)
            | (uint32_t) block[offset + 3];
    }
    for (size_t index = 16; index < 64; index++) {
        uint32_t lower = rotate_right(words[index - 15], 7)
            ^ rotate_right(words[index - 15], 18)
            ^ (words[index - 15] >> 3);
        uint32_t upper = rotate_right(words[index - 2], 17)
            ^ rotate_right(words[index - 2], 19)
            ^ (words[index - 2] >> 10);
        words[index] = words[index - 16] + lower + words[index - 7] + upper;
    }

    uint32_t a = context->state[0];
    uint32_t b = context->state[1];
    uint32_t c = context->state[2];
    uint32_t d = context->state[3];
    uint32_t e = context->state[4];
    uint32_t f = context->state[5];
    uint32_t g = context->state[6];
    uint32_t h = context->state[7];
    for (size_t index = 0; index < 64; index++) {
        uint32_t sum_one = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
        uint32_t choose = (e & f) ^ ((~e) & g);
        uint32_t temporary_one = h + sum_one + choose
            + sha256_round_constants[index] + words[index];
        uint32_t sum_zero = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temporary_two = sum_zero + majority;
        h = g;
        g = f;
        f = e;
        e = d + temporary_one;
        d = c;
        c = b;
        b = a;
        a = temporary_one + temporary_two;
    }
    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;
}

static void sha256_init(sha256_context *context) {
    static const uint32_t initial_state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    memcpy(context->state, initial_state, sizeof(initial_state));
    context->bit_length = 0;
    context->block_length = 0;
}

static void sha256_update(sha256_context *context, const unsigned char *bytes, size_t length) {
    for (size_t index = 0; index < length; index++) {
        context->block[context->block_length++] = bytes[index];
        if (context->block_length == sizeof(context->block)) {
            sha256_transform(context, context->block);
            context->bit_length += 512;
            context->block_length = 0;
        }
    }
}

static void sha256_final(sha256_context *context, unsigned char digest[32]) {
    size_t index = context->block_length;
    context->block[index++] = 0x80;
    if (index > 56) {
        memset(context->block + index, 0, sizeof(context->block) - index);
        sha256_transform(context, context->block);
        memset(context->block, 0, 56);
    } else {
        memset(context->block + index, 0, 56 - index);
    }
    context->bit_length += (uint64_t) context->block_length * 8;
    for (size_t offset = 0; offset < 8; offset++) {
        context->block[63 - offset] = (unsigned char) (context->bit_length >> (offset * 8));
    }
    sha256_transform(context, context->block);
    for (size_t word = 0; word < 8; word++) {
        for (size_t byte = 0; byte < 4; byte++) {
            digest[word * 4 + byte] = (unsigned char) (context->state[word] >> (24 - byte * 8));
        }
    }
}

static int write_marker(const char *path, const char *value) {
    size_t length = 0;
    while (value[length] != '\0') length++;
    int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (descriptor < 0) return -1;
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = write(descriptor, value + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            close(descriptor);
            return -1;
        }
        offset += (size_t) count;
    }
    return close(descriptor);
}

int main(int argc, char **argv) {
    if (write_marker("/workspace/launch-driver-started", "production-driver-started\n") != 0) {
        return 9;
    }
    if (argc != 2) return 10;
    char *end = NULL;
    long expected = strtol(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0' || expected < 1 || expected > 4096) return 11;
    unsigned char buffer[4096];
    size_t total = 0;
    sha256_context digest_context;
    sha256_init(&digest_context);
    while (total < (size_t) expected) {
        ssize_t count = read(4, buffer + total, (size_t) expected - total);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 12;
        sha256_update(&digest_context, buffer + total, (size_t) count);
        total += (size_t) count;
    }
    unsigned char extra;
    ssize_t trailing;
    do {
        trailing = read(4, &extra, 1);
    } while (trailing < 0 && errno == EINTR);
    if (trailing != 0) return 13;

    unsigned char digest[32];
    char digest_hex[65];
    static const char hexadecimal[] = "0123456789abcdef";
    sha256_final(&digest_context, digest);
    for (size_t index = 0; index < sizeof(digest); index++) {
        digest_hex[index * 2] = hexadecimal[digest[index] >> 4];
        digest_hex[index * 2 + 1] = hexadecimal[digest[index] & 0x0f];
    }
    digest_hex[64] = '\0';
    char result_marker[96];
    if (snprintf(result_marker, sizeof(result_marker), "worker-canary-fd4-sha256=%s\n", digest_hex) < 0) {
        return 14;
    }
    if (write_marker("/workspace/worker-canary-fd4-result", result_marker) != 0) {
        return 14;
    }
    if (write_marker("/workspace/launch-driver-marker", "production-driver-ran\n") != 0) {
        return 15;
    }
    return 0;
}
"""
_MONITOR_SLICE_UNIT = "user-acp.slice"
_PAYLOAD_MARKER = "lifecycle-gate-marker"
_GIT_METADATA_MARKER = "git-metadata-absent-marker"
_CROSS_ATTEMPT_PROBE_SCRIPT_NAME = "acp-live-cross-attempt-probe.sh"
_CROSS_ATTEMPT_PROBE_SCRIPT = r"""
set -eu
umask 077
printf 'production-driver-started\n' > /workspace/__STARTED_MARKER__
probe_config=/workspace/.acp-live-cross-attempt-targets
probe_go=/workspace/.acp-live-cross-attempt-go
probe_result=/workspace/.acp-live-cross-attempt-result
probe_result_tmp=/workspace/.acp-live-cross-attempt-result.tmp
probe_mountinfo=/workspace/.acp-live-cross-attempt-mountinfo
attempt=0
while [ ! -f "$probe_go" ] && [ "$attempt" -lt 300 ]; do
  /bin/busybox sleep 0.1
  attempt=$((attempt + 1))
done
test -f "$probe_go"
{ read -r other_workspace_sentinel; read -r shared_git_sentinel; } < "$probe_config"
: > "$probe_result_tmp"
probe_read() {
  label=$1
  target=$2
  if ! /bin/busybox test -e "$target"; then
    /bin/busybox printf '%s=not-visible\n' "$label" >> "$probe_result_tmp"
  elif /bin/busybox cat "$target" >/dev/null 2>&1; then
    /bin/busybox printf '%s=readable\n' "$label" >> "$probe_result_tmp"
  else
    /bin/busybox printf '%s=unreadable\n' "$label" >> "$probe_result_tmp"
  fi
}
probe_write() {
  label=$1
  target=$2
  if ! /bin/busybox test -e "$target"; then
    /bin/busybox printf '%s=target-not-visible\n' "$label" >> "$probe_result_tmp"
  elif /bin/busybox printf 'acp-cross-attempt-write-probe\n' > "$target" 2>/dev/null; then
    /bin/busybox printf '%s=write-succeeded\n' "$label" >> "$probe_result_tmp"
  else
    /bin/busybox printf '%s=write-denied\n' "$label" >> "$probe_result_tmp"
  fi
}
probe_read other-workspace "$other_workspace_sentinel"
probe_write other-workspace "$other_workspace_sentinel"
probe_read shared-git "$shared_git_sentinel"
probe_write shared-git "$shared_git_sentinel"
if ! /bin/busybox ln -s "$other_workspace_sentinel" /workspace/.acp-live-cross-attempt-link; then
  exit 71
fi
probe_read other-workspace-symlink /workspace/.acp-live-cross-attempt-link
/bin/busybox rm /workspace/.acp-live-cross-attempt-link
canonical_target=/workspace/../../${other_workspace_sentinel#/}
probe_read other-workspace-canonical "$canonical_target"
if /bin/busybox test -e /workspace/.git; then
  /bin/busybox printf 'workspace-git=visible\n' >> "$probe_result_tmp"
else
  /bin/busybox printf 'workspace-git=absent\n' >> "$probe_result_tmp"
fi
/bin/busybox cat /proc/self/mountinfo > "$probe_mountinfo"
/bin/busybox mv "$probe_result_tmp" "$probe_result"
while :; do /bin/busybox sleep 1; done
"""

_LIVE_HOST_SENTINEL_HELPER = r"""
import json
import os
import stat
import sys

mode, raw_path, raw_token, *identity = sys.argv[1:]
path = os.fsencode(raw_path)
token = bytes.fromhex(raw_token)
if mode in {"create", "create-fail-after-open"}:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o644,
    )
    try:
        created = os.fstat(descriptor)
        try:
            os.fchmod(descriptor, 0o644)
            if mode == "create-fail-after-open":
                raise OSError("injected post-create write failure")
            if mode == "create-fail-after-partial-write":
                partial_size = max(1, len(token) // 2)
                os.write(descriptor, token[:partial_size])
                raise OSError("injected mid-write failure")
            offset = 0
            while offset < len(token):
                offset += os.write(descriptor, token[offset:])
            os.fsync(descriptor)
            info = os.fstat(descriptor)
            print(json.dumps({"device": info.st_dev, "inode": info.st_ino}), flush=True)
        except BaseException:
            try:
                current = os.lstat(path)
                if (
                    stat.S_ISREG(current.st_mode)
                    and (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino)
                ):
                    read_descriptor = os.open(
                        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                    )
                    try:
                        opened = os.fstat(read_descriptor)
                        content = bytearray()
                        while chunk := os.read(read_descriptor, 4096):
                            content.extend(chunk)
                    finally:
                        os.close(read_descriptor)
                    current = os.lstat(path)
                    if (
                        stat.S_ISREG(current.st_mode)
                        and (opened.st_dev, opened.st_ino)
                        == (created.st_dev, created.st_ino)
                        and (current.st_dev, current.st_ino)
                        == (created.st_dev, created.st_ino)
                        and len(content) <= len(token)
                        and bytes(content) == token[: len(content)]
                    ):
                        os.unlink(path)
            except OSError:
                # The parent records this exact candidate before creation and
                # will preserve/report any artifact not returned with identity.
                pass
            raise
    finally:
        os.close(descriptor)
elif mode == "remove":
    expected_device, expected_inode = (int(value) for value in identity)
    info = os.lstat(path)
    if (
        not stat.S_ISREG(info.st_mode)
        or (info.st_dev, info.st_ino) != (expected_device, expected_inode)
    ):
        raise SystemExit("sentinel identity changed; preserving it")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        content = bytearray()
        while chunk := os.read(descriptor, 4096):
            content.extend(chunk)
    finally:
        os.close(descriptor)
    if (
        (opened.st_dev, opened.st_ino) != (expected_device, expected_inode)
        or bytes(content) != token
    ):
        raise SystemExit("sentinel content or opened identity changed; preserving it")
    os.unlink(path)
else:
    raise SystemExit("invalid sentinel helper operation")
"""


def _live_isolation_sentinel(
    path: Path, token: bytes, *, privileged: bool = False
) -> tuple[int, int]:
    executable = ["sudo", "-n", sys.executable] if privileged else [sys.executable]
    completed = subprocess.run(
        [*executable, "-c", _LIVE_HOST_SENTINEL_HELPER, "create", str(path), token.hex()],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    identity = json.loads(completed.stdout)
    return int(identity["device"]), int(identity["inode"])


def _remove_live_isolation_sentinel(
    path: Path,
    token: bytes,
    identity: tuple[int, int],
    *,
    privileged: bool = False,
) -> None:
    executable = ["sudo", "-n", sys.executable] if privileged else [sys.executable]
    subprocess.run(
        [
            *executable,
            "-c",
            _LIVE_HOST_SENTINEL_HELPER,
            "remove",
            str(path),
            token.hex(),
            str(identity[0]),
            str(identity[1]),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )


def _remove_live_isolation_write_probe(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(info.st_mode) or info.st_size != 0 or info.st_uid != os.geteuid():
        raise AssertionError(f"unexpected worker write-probe artifact preserved: {path}")
    path.unlink()


def _remove_live_isolation_scratch(path: Path, expected_content: bytes) -> None:
    """Remove only a token-specific scratch file created by the live probe."""

    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_size != len(expected_content)
    ):
        raise AssertionError(f"unexpected worker scratch artifact preserved: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        content = bytearray()
        while chunk := os.read(descriptor, 4096):
            content.extend(chunk)
    finally:
        os.close(descriptor)
    current = path.lstat()
    if (
        not stat.S_ISREG(current.st_mode)
        or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
        or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)
        or bytes(content) != expected_content
    ):
        raise AssertionError(f"worker scratch identity or content changed; preserving it: {path}")
    path.unlink()


def test_live_isolation_scratch_cleanup_removes_exact_probe_file(tmp_path: Path) -> None:
    path = tmp_path / "acp-live-worker-tmp-test"
    expected_content = b"acp-live-scratch-test"
    path.write_bytes(expected_content)

    _remove_live_isolation_scratch(path, expected_content)

    assert not path.exists()


def test_live_isolation_scratch_cleanup_preserves_unexpected_file(tmp_path: Path) -> None:
    path = tmp_path / "acp-live-worker-tmp-test"
    path.write_bytes(b"not the probe payload")

    with pytest.raises(AssertionError, match="identity or content changed"):
        _remove_live_isolation_scratch(path, b"acp-live-scratch-test")

    assert path.read_bytes() == b"not the probe payload"


def test_live_isolation_scratch_cleanup_preserves_symlink(tmp_path: Path) -> None:
    target = tmp_path / "user-data"
    target.write_bytes(b"preserve")
    path = tmp_path / "acp-live-worker-tmp-test"
    path.symlink_to(target)

    with pytest.raises(AssertionError, match="unexpected worker scratch artifact"):
        _remove_live_isolation_scratch(path, b"acp-live-scratch-test")

    assert path.is_symlink()
    assert target.read_bytes() == b"preserve"


@pytest.mark.parametrize(
    "failure_mode",
    ("create-fail-after-open", "create-fail-after-partial-write"),
)
def test_live_isolation_sentinel_creation_cleans_up_after_post_create_failure(
    tmp_path: Path, failure_mode: str
) -> None:
    path = tmp_path / "acp-live-sentinel-test"
    token = b"synthetic sentinel payload"
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            _LIVE_HOST_SENTINEL_HELPER,
            failure_mode,
            str(path),
            token.hex(),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode != 0
    assert not path.exists()


def _terminate_worker_from_fresh_process(
    repo: Path, attempt_id: str, credential: str, result_sender
) -> None:
    """Cancel through a genuinely fresh supervisor with no launch-handle registry."""

    from agent_control_plane.supervisor import sandbox_monitor_lifecycle

    supervisor = GitSupervisor(repo)
    reconnect_calls = 0
    legacy_pid_calls = 0
    original_reconnect = sandbox_monitor_lifecycle.reconnect_sandbox_monitor

    def record_reconnect(**kwargs: Any):
        nonlocal reconnect_calls
        reconnect_calls += 1
        return original_reconnect(**kwargs)

    def reject_legacy_pid(*_args: Any, **_kwargs: Any):
        nonlocal legacy_pid_calls
        legacy_pid_calls += 1
        raise AssertionError("fresh sandbox cancellation used the legacy PID path")

    sandbox_monitor_lifecycle.reconnect_sandbox_monitor = record_reconnect
    supervisor._open_registered_pidfd = reject_legacy_pid
    try:
        termination = supervisor.terminate_worker(attempt_id, credential=credential)
        result_sender.send(("ok", os.getpid(), termination, reconnect_calls, legacy_pid_calls))
    except SupervisorError as error:
        result_sender.send(("supervisor-error", error.code, reconnect_calls, legacy_pid_calls))
    except BaseException as error:
        result_sender.send(("error", type(error).__name__, reconnect_calls, legacy_pid_calls))
    finally:
        sandbox_monitor_lifecycle.reconnect_sandbox_monitor = original_reconnect
        result_sender.close()


def _start_launch_driver_then_crash_controller(
    repo: Path,
    attempt_id: str,
    claim_token: int,
    command: tuple[str, ...],
    memory_max_bytes: int,
    cpu_quota: int,
    cpu_period: int,
    pids_max: int,
    timeout_seconds: int,
    credential: str,
    service_log_path: Path,
    result_sender,
    crash_after_manager_acceptance: bool = False,
    monitor_acceptance_crash_marker: Path | None = None,
    crash_before_monitor_start: bool = False,
    concurrent_control_root: Path | None = None,
    concurrent_slot: str | None = None,
    concurrent_run_root: Path | None = None,
    concurrent_source_worktree: Path | None = None,
    crash_phase: str = "",
    test_worker_canary: bytes | None = None,
) -> None:
    """Exit the launch-driver service at the selected monitor-handoff crash point."""

    original_runner = sandbox_launch_driver_service._run_trusted_runtime_command

    def capture_driver_service_output(argv: list[str], *, environment: dict[str, str]) -> bytes:
        if Path(argv[0]).name == "systemd-run":
            if concurrent_control_root is not None:
                if (
                    concurrent_slot not in {"0", "1"}
                    or concurrent_run_root is None
                    or concurrent_source_worktree is None
                ):
                    raise RuntimeError("concurrent launch receipt inputs are incomplete")
                execution = GitSupervisor(repo)._sandbox_execution_get(attempt_id)
                if execution is None or (execution["attempt_id"], execution["claim_token"]) != (
                    attempt_id,
                    claim_token,
                ):
                    raise RuntimeError("concurrent launch receipt has no matching durable attempt")
                identity = (attempt_id, claim_token, execution["execution_id"])
                monitor_unit = sandbox_monitor_service_unit(*identity)
                prepared = {
                    "attempt_id": attempt_id,
                    "claim_token": claim_token,
                    "container_id": execution["container_id"],
                    "execution_id": execution["execution_id"],
                    "monitor_unit": monitor_unit,
                    "pytest_pid": os.getppid(),
                    "repo": str(repo.resolve(strict=True)),
                    "run_root": str(concurrent_run_root.resolve(strict=True)),
                    "scope_unit": f"acp-{execution['container_id']}.scope",
                    "service_unit": f"acp-launch-driver-{execution['execution_id']}.service",
                    "slice_unit": sandbox_attempt_slice_unit(*identity),
                    "slot": concurrent_slot,
                    "source_worktree": str(concurrent_source_worktree.resolve(strict=True)),
                    "workspace_root": str(
                        Path(execution["workspace_root_path"]).resolve(strict=True)
                    ),
                }
                _write_live_concurrent_marker(
                    concurrent_control_root,
                    f"prepared-{concurrent_slot}.json",
                    json.dumps(prepared, sort_keys=True).encode("utf-8"),
                )
            argv = list(argv)
            insertion = argv.index("--working-directory")
            argv[insertion:insertion] = [
                f"--property=StandardOutput=append:{service_log_path}",
                f"--property=StandardError=append:{service_log_path}",
            ]
            if test_worker_canary is not None:
                canary_text = test_worker_canary.decode("ascii")
                if canary_text in "\n".join(argv) or any(
                    canary_text in value for value in environment.values()
                ):
                    raise AssertionError(
                        "fake worker canary appeared in launch-driver argv or environment"
                    )
            if monitor_acceptance_crash_marker is not None:
                module_flag = argv.index("-m")
                python = argv[module_flag - 1]
                module_name = argv[module_flag + 1]
                if module_name != "agent_control_plane.supervisor.sandbox_launch_driver_service":
                    raise AssertionError("production launch-driver command changed unexpectedly")
                driver_args = argv[module_flag + 2 :]
                wrapper = """
import json
import os
import sys
from pathlib import Path

from agent_control_plane.git_supervisor import GitSupervisor
from agent_control_plane.supervisor import oci_worker, sandbox_launch_driver_service
from agent_control_plane.supervisor import sandbox_monitor_ipc, sandbox_monitor_service

marker = Path(sys.argv[1])
crash_phase = sys.argv[2]
driver_args = sys.argv[3:]
captured = {}
original_record_launch = GitSupervisor._sandbox_execution_record_launch

def capture_launch_handle(self, *args, **kwargs):
    handle = kwargs["runc_handle"]
    captured["runc_client_pid"] = oci_worker._runc_launch_pid(handle)
    captured["runc_client_identity"] = oci_worker._runc_launch_process_identity(handle)
    return original_record_launch(self, *args, **kwargs)

GitSupervisor._sandbox_execution_record_launch = capture_launch_handle
original_monitor_start = sandbox_monitor_service.start_sandbox_execution_monitor
original_record_exit = sandbox_launch_driver_service._record_driver_exit_with_lease_recovery

def write_crash_marker(kwargs, receipt):
    identity = kwargs["expected_identity"]
    attempt_slice = sandbox_launch_driver_service.sandbox_attempt_slice_unit(*identity)
    driver_unit = f"acp-launch-driver-{identity[2]}.service"
    monitor_unit = sandbox_launch_driver_service.sandbox_monitor_service_unit(*identity)
    properties = sandbox_launch_driver_service._unit_properties(
        driver_unit,
        ("ActiveState", "ControlGroup", "Id", "InvocationID", "MainPID", "Slice"),
    )
    monitor_value = None
    if receipt is not None:
        monitor_value = {
            "unit": receipt.unit,
            "invocation_id": receipt.invocation_id,
            "pid": receipt.main_pid,
            "identity": receipt.main_identity,
            "control_group": receipt.control_group,
            "attempt_id": receipt.attempt_id,
            "claim_token": receipt.claim_token,
            "execution_id": receipt.execution_id,
        }
    value = {
        "crash_phase": crash_phase,
        "identity": list(identity),
        "driver": {
            "unit": driver_unit,
            "pid": os.getpid(),
            "identity": sandbox_monitor_ipc._linux_process_identity(os.getpid()),
            "active_state": properties["ActiveState"],
            "invocation_id": properties["InvocationID"],
            "control_group": properties["ControlGroup"],
            "slice": properties["Slice"],
            "main_pid": int(properties["MainPID"]),
        },
        "monitor_unit": monitor_unit,
        "monitor": monitor_value,
        "attempt_slice": attempt_slice,
        "attempt_slice_control_group": kwargs["attempt_slice_control_group"],
        "scope": {
            "unit": kwargs["scope_unit"],
            "invocation_id": kwargs["scope_invocation_id"],
            "control_group": kwargs["scope_control_group"],
        },
        "runc_client_pid": captured["runc_client_pid"],
        "runc_client_identity": captured["runc_client_identity"],
    }
    marker.write_text(json.dumps(value, sort_keys=True), encoding="ascii")
    os._exit(74)

def crash_at_monitor_start(*args, **kwargs):
    if crash_phase == "before_monitor_start":
        write_crash_marker(kwargs, None)
    client = original_monitor_start(*args, **kwargs)
    if crash_phase != "after_monitor_acceptance":
        raise AssertionError("unknown live monitor crash phase")
    write_crash_marker(kwargs, client._receipt)

def crash_after_exit(supervisor, expected_identity, wait_receipt, *, credential):
    original_record_exit(supervisor, expected_identity, wait_receipt, credential=credential)
    execution = supervisor._sandbox_execution_get(expected_identity[0])
    if execution is None or execution["phase"] != "exited":
        raise AssertionError("production launch driver did not durably record the exact exit")
    driver_unit = f"acp-launch-driver-{expected_identity[2]}.service"
    properties = sandbox_launch_driver_service._unit_properties(
        driver_unit,
        ("ActiveState", "ControlGroup", "Id", "InvocationID", "MainPID", "Slice"),
    )
    driver_pid = os.getpid()
    if properties["ActiveState"] != "active" or properties["MainPID"] != str(driver_pid):
        raise AssertionError("post-wait crash hook lost the exact active launch-driver identity")
    value = {
        "crash_phase": crash_phase,
        "identity": list(expected_identity),
        "driver": {
            "unit": driver_unit,
            "pid": driver_pid,
            "identity": sandbox_monitor_ipc._linux_process_identity(driver_pid),
            "active_state": properties["ActiveState"],
            "invocation_id": properties["InvocationID"],
            "control_group": properties["ControlGroup"],
            "slice": properties["Slice"],
            "main_pid": int(properties["MainPID"]),
        },
        "execution_phase": execution["phase"],
        "runc_exit_code": execution["runc_exit_code"],
        "launch_submission_id": execution["launch_submission_id"],
        "launch_submission_digest": execution["launch_submission_digest"],
        "cleanup_receipt": execution["cleanup_receipt"],
        "provider_proxy_artifact": execution["provider_proxy_artifact"],
    }
    marker.write_text(json.dumps(value, sort_keys=True), encoding="ascii")
    os._exit(74)

if crash_phase == "after_exit_before_cleanup_report":
    sandbox_launch_driver_service._record_driver_exit_with_lease_recovery = crash_after_exit
elif crash_phase in {"after_monitor_acceptance", "before_monitor_start"}:
    sandbox_monitor_service.start_sandbox_execution_monitor = crash_at_monitor_start
else:
    raise AssertionError(f"unknown live launch-driver crash phase: {crash_phase!r}")
raise SystemExit(sandbox_launch_driver_service.main(driver_args))
"""
                argv[module_flag - 1 :] = [
                    python,
                    "-c",
                    wrapper,
                    str(monitor_acceptance_crash_marker),
                    crash_phase,
                    *driver_args,
                ]
        result = original_runner(argv, environment=environment)
        if crash_after_manager_acceptance and Path(argv[0]).name == "systemd-run":
            # Type=exec returns only after systemd accepts the unit and crosses
            # ExecStart. Lose the producer before it can observe or persist the
            # service receipt; the durable intent must prevent a duplicate start.
            result_sender.send(("manager_accepted", os.getpid()))
            result_sender.close()
            os._exit(74)
        return result

    exit_code = 73
    try:
        supervisor = GitSupervisor(repo)
        with patch.object(
            sandbox_launch_driver_service,
            "_run_trusted_runtime_command",
            capture_driver_service_output,
        ):
            if os.environ.get("ACP_LIVE_SUPERVISED_RUN_WORKER") == "1":
                run_worker_kwargs = {
                    "sandbox_experimental_opt_in": True,
                    "sandbox_memory_max_bytes": memory_max_bytes,
                    "sandbox_cpu_quota": cpu_quota,
                    "sandbox_cpu_period": cpu_period,
                    "sandbox_pids_max": pids_max,
                    "sandbox_timeout_seconds": timeout_seconds,
                }
                if test_worker_canary is None:
                    result = supervisor.run_worker(
                        attempt_id,
                        claim_token,
                        command,
                        credential,
                        **run_worker_kwargs,
                    )
                else:
                    original_start_registered = (
                        sandbox_launch_driver_service.start_registered_no_model_sandbox_worker
                    )

                    def start_registered_with_test_canary(*args: Any, **kwargs: Any) -> Any:
                        kwargs["_test_worker_canary"] = test_worker_canary
                        return original_start_registered(*args, **kwargs)

                    with patch.object(
                        sandbox_launch_driver_service,
                        "start_registered_no_model_sandbox_worker",
                        start_registered_with_test_canary,
                    ):
                        result = supervisor.run_worker(
                            attempt_id,
                            claim_token,
                            command,
                            credential,
                            **run_worker_kwargs,
                        )
                receipt_payload = result["sandbox_launch_receipt"]
                result_summary = {
                    "status": result["status"],
                    "sandbox_execution_id": result["sandbox_execution_id"],
                    "sandbox_cleanup_verified": result["sandbox_cleanup_verified"],
                }
            else:
                _execution, receipt = (
                    sandbox_launch_driver_service.start_registered_no_model_sandbox_worker(
                        supervisor,
                        attempt_id=attempt_id,
                        claim_token=claim_token,
                        command=command,
                        memory_max_bytes=memory_max_bytes,
                        cpu_quota=cpu_quota,
                        cpu_period=cpu_period,
                        pids_max=pids_max,
                        timeout_seconds=timeout_seconds,
                        credential=credential,
                        _test_worker_canary=test_worker_canary,
                        experimental_opt_in=True,
                        provider_egress_policy_name=(
                            "live-uds-only"
                            if os.environ.get("ACP_LIVE_PROVIDER_PROXY_UDS") == "1"
                            else None
                        ),
                        provider_egress_destinations=(
                            {"allowed.example.invalid": [443]}
                            if os.environ.get("ACP_LIVE_PROVIDER_PROXY_UDS") == "1"
                            else None
                        ),
                    )
                )
                receipt_payload = {
                    "attempt_id": receipt.attempt_id,
                    "claim_token": receipt.claim_token,
                    "execution_id": receipt.execution_id,
                    "service_unit": receipt.service_unit,
                    "invocation_id": receipt.invocation_id,
                    "driver_pid": receipt.driver_pid,
                    "driver_identity": receipt.driver_identity,
                    "control_group": receipt.control_group,
                }
                result_summary = None
        result_sender.send(
            (
                "ok",
                os.getpid(),
                receipt_payload,
                result_summary,
            )
        )
    except BaseException as error:
        exit_code = 1
        detail = str(error).replace(credential, "[redacted]")[:800]
        if test_worker_canary is not None:
            detail = detail.replace(test_worker_canary.decode("latin1"), "[redacted]")
        result_sender.send(("error", type(error).__name__, detail))
    finally:
        result_sender.close()
    # Abruptly lose the producer after the one-shot handoff. The independent
    # user manager retains the launch-driver service and its process-local handle.
    os._exit(exit_code)


def _retry_launch_driver_without_replay_from_fresh_process(
    repo: Path,
    expected_identity: tuple[str, int, str],
    command: tuple[str, ...],
    memory_max_bytes: int,
    cpu_quota: int,
    cpu_period: int,
    pids_max: int,
    timeout_seconds: int,
    credential: str,
    result_sender,
) -> None:
    """Prove a fresh producer cannot submit a second systemd start."""

    original_runner = sandbox_launch_driver_service._run_trusted_runtime_command
    start_submissions: list[tuple[str, ...]] = []

    def refuse_second_start(argv: list[str], *, environment: dict[str, str]) -> bytes:
        if Path(argv[0]).name == "systemd-run":
            start_submissions.append(tuple(argv))
            raise RuntimeError("duplicate launch-driver activation blocked by test")
        return original_runner(argv, environment=environment)

    try:
        with patch.object(
            sandbox_launch_driver_service,
            "_run_trusted_runtime_command",
            refuse_second_start,
        ):
            sandbox_launch_driver_service.start_sandbox_launch_driver(
                GitSupervisor(repo),
                expected_identity=expected_identity,
                command=command,
                memory_max_bytes=memory_max_bytes,
                cpu_quota=cpu_quota,
                cpu_period=cpu_period,
                pids_max=pids_max,
                timeout_seconds=timeout_seconds,
                credential=credential,
            )
        result_sender.send(("accepted", os.getpid(), len(start_submissions)))
    except sandbox_launch_driver_service.SandboxLaunchDriverServiceError as error:
        result_sender.send(("rejected", os.getpid(), type(error).__name__, len(start_submissions)))
    except BaseException as error:
        result_sender.send(("error", os.getpid(), type(error).__name__, len(start_submissions)))
    finally:
        result_sender.close()


def _reap_expired_from_fresh_process(
    repo: Path,
    now: int,
    result_sender,
    import_probe: tuple[str, str, str] | None = None,
) -> None:
    """Run the real reaper in a new supervisor process after producer loss."""

    try:
        supervisor = GitSupervisor(repo)

        def imported_state_snapshot() -> dict[str, Any]:
            if import_probe is None:
                return {}
            task_id, attempt_id, submission_id = import_probe
            task = supervisor.task(task_id)
            attempt = supervisor.attempt(attempt_id)
            submission = supervisor.submission(submission_id)
            execution = supervisor._sandbox_execution_get(attempt_id)
            if execution is None:
                raise AssertionError("fresh supervisor could not recover the imported execution")
            return {
                "task_status": task["status"],
                "attempt_status": attempt["status"],
                "submission_id": submission["id"],
                "submission_status": submission["status"],
                "submission_commit_sha": submission["commit_sha"],
                "task_latest_submission_id": task["latest_submission"]["id"],
                "execution_id": execution["execution_id"],
                "execution_phase": execution["phase"],
            }

        before = imported_state_snapshot()
        reaped = supervisor.reap_expired(now=now)
        after = imported_state_snapshot()
        result_sender.send(("ok", os.getpid(), reaped, before, after))
    except BaseException as error:
        result_sender.send(("error", type(error).__name__))
    finally:
        result_sender.close()


def _verify_sandbox_cleanup_from_fresh_process(
    repo: Path,
    attempt_id: str,
    claim_token: int,
    result_sender,
) -> None:
    """Run the production cleanup verifier outside both driver and reaper processes."""

    try:
        supervisor = GitSupervisor(repo)
        verified = supervisor._sandbox_execution_verify_cleanup(attempt_id, claim_token)
        result_sender.send(("ok", os.getpid(), verified["phase"]))
    except SupervisorError as error:
        result_sender.send(("supervisor-error", os.getpid(), error.code, str(error)))
    except BaseException as error:
        result_sender.send(("error", os.getpid(), type(error).__name__, str(error)))
    finally:
        result_sender.close()


def _reconcile_monitor_accepted_driver_crash_from_fresh_process(
    repo: Path,
    attempt_id: str,
    claim_token: int,
    execution_id: str,
    credential: str,
    result_sender,
) -> None:
    """Contain the exact interrupted handoff using a fresh supervisor process."""

    try:
        supervisor = GitSupervisor(repo)
        execution = supervisor._sandbox_execution_get(attempt_id)
        if execution is None:
            raise RuntimeError("execution disappeared before fresh-process reconciliation")
        intent = journal_module._SandboxLaunchDriverStartIntent(
            attempt_id=attempt_id,
            claim_token=claim_token,
            execution_id=execution_id,
            start_id=execution["launch_driver_start_id"],
            start_digest=execution["launch_driver_start_digest"],
            service_unit=execution["launch_driver_start_unit"],
        )
        result = sandbox_launch_driver_service._stop_and_reconcile_exact_start(
            supervisor,
            execution=execution,
            intent=intent,
            attempt_slice=sandbox_attempt_slice_unit(attempt_id, claim_token, execution_id),
            reason="live test: launch driver crashed after recovery-monitor acceptance",
            credential=credential,
        )
        result_sender.send(("ok", os.getpid(), result))
    except BaseException as error:
        result_sender.send(("error", os.getpid(), type(error).__name__, str(error)))
    finally:
        result_sender.close()


def _write_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _entry_is_present(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _persisted_write_set_rules(
    supervisor: GitSupervisor, attempt_id: str
) -> list[tuple[str, bool, bool]]:
    with supervisor.connect() as connection:
        attempt = connection.execute(
            "SELECT task_id FROM attempts WHERE id = ?", (attempt_id,)
        ).fetchone()
        if attempt is None:
            raise RuntimeError("test attempt disappeared before output collection")
        task = supervisor._task_row(connection, attempt["task_id"])
        return supervisor._write_set_rules(task, supervisor._case_sensitive_paths(connection))


def _unit_properties(unit: str, properties: tuple[str, ...]) -> dict[str, str]:
    raw = sandbox_attestation._run_trusted_runtime_command(
        [
            str(sandbox_attestation._trusted_systemctl_executable()),
            "--user",
            "show",
            "--no-pager",
            f"--property={','.join(properties)}",
            "--",
            unit,
        ],
        environment=sandbox_attestation._trusted_systemd_command_environment(),
    )
    values: dict[str, str] = {}
    for line in raw.decode("ascii").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise RuntimeError(f"malformed systemd properties for {unit}")
        values[key] = value
    if set(values) != set(properties):
        raise RuntimeError(f"incomplete systemd properties for {unit}: {values!r}")
    return values


def _user_manager_cidata_uuid_device_unit(
    systemd_escape: str,
    *,
    cidata_label_path: Path,
    uuid_directory: Path,
    expected_device_path: Path | None,
) -> str:
    """Resolve the sole UUID alias for the supported Lima CIDATA device."""
    try:
        cidata_device = cidata_label_path.resolve(strict=True)
        if expected_device_path is not None:
            expected_device = expected_device_path.resolve(strict=True)
            if cidata_device != expected_device or not stat.S_ISBLK(expected_device.stat().st_mode):
                raise RuntimeError("the CIDATA label does not resolve to the expected block device")
        uuid_aliases = [
            path
            for path in sorted(uuid_directory.iterdir())
            if path.is_symlink() and path.resolve(strict=True) == cidata_device
        ]
    except OSError as error:
        raise RuntimeError(f"could not identify the Lima CIDATA device: {error}") from error
    if len(uuid_aliases) != 1:
        raise RuntimeError("the Lima CIDATA device must have exactly one /dev/disk/by-uuid alias")
    uuid_alias = uuid_aliases[0]
    if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", uuid_alias.name):
        raise RuntimeError("the Lima CIDATA UUID alias has an unsupported name")
    escaped = _systemd_command([systemd_escape, "--path", "--suffix=device", str(uuid_alias)])
    expected_uuid = uuid_alias.name.replace("-", r"\x2d")
    expected_unit = r"dev-disk-by\x2duuid-" + expected_uuid + ".device"
    if escaped.returncode != 0 or escaped.stdout.strip() != expected_unit:
        raise RuntimeError(
            "systemd did not derive the expected unit for the verified Lima CIDATA UUID alias"
        )
    return expected_unit


def _user_manager_restart_expected_inventory(
    uid: int, *, cidata_uuid_device_unit: str
) -> dict[str, tuple[str, str, str]]:
    """Exact baseline inventory for the supported Debian 12 Lima user manager."""
    expected: dict[str, tuple[str, str, str]] = {}
    device_units = (
        "dev-disk-by\\x2ddiskseq-1.device",
        "dev-disk-by\\x2ddiskseq-2.device",
        "dev-disk-by\\x2dlabel-cidata.device",
        "dev-disk-by\\x2dpartuuid-5837337c\\x2d084c\\x2d4836\\x2d9e1a\\x2d47b625a8c517.device",
        "dev-disk-by\\x2dpartuuid-98dae4db\\x2d3ee7\\x2d40a9\\x2d8433\\x2dc4d56c32dedc.device",
        "dev-disk-by\\x2dpath-pci\\x2d0000:00:06.0.device",
        "dev-disk-by\\x2dpath-pci\\x2d0000:00:06.0\\x2dpart1.device",
        "dev-disk-by\\x2dpath-pci\\x2d0000:00:06.0\\x2dpart15.device",
        "dev-disk-by\\x2dpath-pci\\x2d0000:00:07.0.device",
        "dev-disk-by\\x2dpath-virtio\\x2dpci\\x2d0000:00:06.0.device",
        "dev-disk-by\\x2dpath-virtio\\x2dpci\\x2d0000:00:06.0\\x2dpart1.device",
        "dev-disk-by\\x2dpath-virtio\\x2dpci\\x2d0000:00:06.0\\x2dpart15.device",
        "dev-disk-by\\x2dpath-virtio\\x2dpci\\x2d0000:00:07.0.device",
        "dev-disk-by\\x2duuid-8588\\x2dFECA.device",
        "dev-disk-by\\x2duuid-db8fda2d\\x2d25d7\\x2d4bb8\\x2d827d\\x2d9c93ea89bf3c.device",
        *(f"dev-hvc{index}.device" for index in range(8)),
        "dev-vda.device",
        "dev-vda1.device",
        "dev-vda15.device",
        "dev-vdb.device",
        "dev-vport1p0.device",
        "sys-devices-pci0000:00-0000:00:01.0-virtio0-net-eth0.device",
        "sys-devices-pci0000:00-0000:00:05.0-virtio1-virtio\\x2dports-vport1p0.device",
        "sys-devices-pci0000:00-0000:00:06.0-virtio2-block-vda-vda1.device",
        "sys-devices-pci0000:00-0000:00:06.0-virtio2-block-vda-vda15.device",
        "sys-devices-pci0000:00-0000:00:06.0-virtio2-block-vda.device",
        "sys-devices-pci0000:00-0000:00:07.0-virtio3-block-vdb.device",
        *(f"sys-devices-virtual-tty-hvc{index}.device" for index in range(8)),
        "sys-module-configfs.device",
        "sys-module-fuse.device",
        "sys-subsystem-net-devices-eth0.device",
    )
    for unit in device_units:
        expected[unit] = ("loaded", "active", "plugged")
    expected[cidata_uuid_device_unit] = ("loaded", "active", "plugged")
    for unit in (
        "-.mount",
        "boot-efi.mount",
        "dev-hugepages.mount",
        "dev-mqueue.mount",
        "mnt-lima\\x2dcidata.mount",
        "proc-sys-fs-binfmt_misc.mount",
        "run-credentials-systemd\\x2dsysctl.service.mount",
        "run-credentials-systemd\\x2dsysusers.service.mount",
        "run-credentials-systemd\\x2dtmpfiles\\x2dsetup.service.mount",
        "run-credentials-systemd\\x2dtmpfiles\\x2dsetup\\x2ddev.service.mount",
        f"run-user-{uid}.mount",
        "sys-fs-fuse-connections.mount",
        "sys-kernel-config.mount",
        "sys-kernel-debug.mount",
        "sys-kernel-tracing.mount",
    ):
        expected[unit] = ("loaded", "active", "mounted")
    expected["init.scope"] = ("loaded", "active", "running")
    expected["dbus.service"] = ("loaded", "active", "running")
    for unit in ("-.slice", "app.slice", "session.slice", "user.slice"):
        expected[unit] = ("loaded", "active", "active")
    expected["dbus.socket"] = ("loaded", "active", "running")
    for unit in (
        "dirmngr.socket",
        "gpg-agent-browser.socket",
        "gpg-agent-extra.socket",
        "gpg-agent-ssh.socket",
        "gpg-agent.socket",
    ):
        expected[unit] = ("loaded", "active", "listening")
    for unit in (
        "basic.target",
        "default.target",
        "paths.target",
        "sockets.target",
        "timers.target",
    ):
        expected[unit] = ("loaded", "active", "active")
    for unit in ("dirmngr.service", "gpg-agent.service"):
        expected[unit] = ("loaded", "inactive", "dead")
    for unit in ("blockdev@dev-vda15.target", "blockdev@dev-vdb.target"):
        expected[unit] = ("not-found", "inactive", "dead")
    expected["shutdown.target"] = ("loaded", "inactive", "dead")
    return expected


def _user_manager_restart_inventory_is_allowlisted(
    actual: dict[str, tuple[str, str, str]],
    expected: dict[str, tuple[str, str, str]],
) -> bool:
    """Allow only known absent or empty states for the two parent slices."""
    if "user.slice" not in expected:
        return False
    allowed_parent_states = {
        "user.slice": {expected["user.slice"], ("loaded", "inactive", "dead"), None},
        "user-acp.slice": {("loaded", "active", "active"), ("loaded", "inactive", "dead"), None},
    }
    if any(actual.get(unit) not in states for unit, states in allowed_parent_states.items()):
        return False
    parent_slices = set(allowed_parent_states)
    expected_without_parent_slices = {
        unit: state for unit, state in expected.items() if unit not in parent_slices
    }
    actual_without_parent_slices = {
        unit: state for unit, state in actual.items() if unit not in parent_slices
    }
    return actual_without_parent_slices == expected_without_parent_slices


def _user_manager_parent_slice_state_is_safe(
    unit: str,
    state: tuple[str, str, str],
    manager_cgroup: str,
    *,
    allow_active: bool,
) -> bool:
    expected_suffix = {
        "user.slice": "user.slice",
        "user-acp.slice": "user.slice/user-acp.slice",
    }.get(unit)
    if expected_suffix is None:
        return False
    if state == ("loaded", "active", "active"):
        if not allow_active:
            return False
        properties = _unit_properties(unit, ("ControlGroup", "FragmentPath", "LoadState"))
        return (
            properties["LoadState"] == "loaded"
            and properties["ControlGroup"] == f"{manager_cgroup}/{expected_suffix}"
            and not properties["FragmentPath"]
        )
    if state == ("loaded", "inactive", "dead"):
        properties = _unit_properties(unit, ("ControlGroup", "FragmentPath", "LoadState"))
        return (
            properties["LoadState"] == "loaded"
            and not properties["ControlGroup"]
            and not properties["FragmentPath"]
        )
    return False


def _user_manager_unit_inventory(systemctl: str) -> dict[str, tuple[str, str, str]]:
    result = _systemd_command(
        [systemctl, "--user", "list-units", "--all", "--no-pager", "--output=json"]
    )
    if result.returncode != 0:
        raise RuntimeError(f"could not inventory user-manager units: {result.stderr!r}")
    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("user-manager unit inventory is not valid JSON") from error
    if not isinstance(rows, list):
        raise RuntimeError("user-manager unit inventory is not a JSON list")
    inventory: dict[str, tuple[str, str, str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError(f"malformed user-manager unit inventory object: {row!r}")
        unit = row.get("unit")
        load_state = row.get("load")
        active_state = row.get("active")
        sub_state = row.get("sub")
        if not all(
            isinstance(value, str) and value
            for value in (unit, load_state, active_state, sub_state)
        ):
            raise RuntimeError(f"incomplete user-manager unit inventory object: {row!r}")
        if unit in inventory:
            raise RuntimeError(f"duplicate user-manager inventory row for {unit}")
        inventory[unit] = (load_state, active_state, sub_state)
    return inventory


def _user_manager_restart_test_unit_state_is_safe(
    *, unit: str, attempt_slice_unit: str, state: tuple[str, str, str]
) -> bool:
    """Allow only absent units or the exact empty, inactive attempt slice."""
    absent = ("not-found", "inactive", "dead")
    return state == absent or (
        unit == attempt_slice_unit and state == ("loaded", "inactive", "dead")
    )


def test_user_manager_restart_accepts_only_exact_inactive_attempt_slice_residual() -> None:
    attempt_slice = "user-acp-0123456789abcdef.slice"
    assert _user_manager_restart_test_unit_state_is_safe(
        unit=attempt_slice,
        attempt_slice_unit=attempt_slice,
        state=("loaded", "inactive", "dead"),
    )
    assert _user_manager_restart_test_unit_state_is_safe(
        unit=attempt_slice,
        attempt_slice_unit=attempt_slice,
        state=("not-found", "inactive", "dead"),
    )
    assert _user_manager_restart_test_unit_state_is_safe(
        unit="acp-launch-driver-0123456789abcdef.service",
        attempt_slice_unit=attempt_slice,
        state=("not-found", "inactive", "dead"),
    )
    assert not _user_manager_restart_test_unit_state_is_safe(
        unit="acp-monitor-0123456789abcdef.service",
        attempt_slice_unit=attempt_slice,
        state=("loaded", "inactive", "dead"),
    )
    assert not _user_manager_restart_test_unit_state_is_safe(
        unit="user-acp-fedcba9876543210.slice",
        attempt_slice_unit=attempt_slice,
        state=("loaded", "inactive", "dead"),
    )
    assert not _user_manager_restart_test_unit_state_is_safe(
        unit=attempt_slice,
        attempt_slice_unit=attempt_slice,
        state=("loaded", "active", "active"),
    )


def _process_cgroup_identity(pid: int) -> tuple[str, str, int]:
    proc = Path("/proc") / str(pid)
    cgroup_lines = (proc / "cgroup").read_text(encoding="ascii").splitlines()
    unified = [line.partition("::")[2] for line in cgroup_lines if line.startswith("0::")]
    if len(unified) != 1:
        raise RuntimeError(f"process {pid} lacks one unified cgroup identity")
    stat_line = (proc / "stat").read_text(encoding="ascii")
    stat_tail = stat_line[stat_line.rfind(")") + 2 :].split()
    if len(stat_tail) < 2 or not stat_tail[1].isdecimal():
        raise RuntimeError(f"process {pid} has a malformed parent identity")
    return unified[0], (proc / "comm").read_text(encoding="utf-8").strip(), int(stat_tail[1])


def _assert_user_manager_process_inventory(
    *,
    manager_cgroup: str,
    manager_pid: str,
    test_cgroups: dict[str, str] | None = None,
    expected_monitor_pid: str | None = None,
    expected_baseline_processes: dict[str, frozenset[int]] | None = None,
) -> dict[str, frozenset[int]]:
    """Fail closed unless every manager-cgroup process belongs to an exact known unit."""
    if not manager_cgroup.startswith("/user.slice/user-") or not manager_pid.isdecimal():
        raise AssertionError("unexpected user-manager cgroup or PID identity")
    root = Path("/sys/fs/cgroup") / manager_cgroup.lstrip("/")
    root = root.resolve(strict=True)
    root_group = PurePosixPath(manager_cgroup)
    init = _unit_properties("init.scope", ("ControlGroup", "LoadState"))
    dbus = _unit_properties("dbus.service", ("ControlGroup", "LoadState", "MainPID"))
    if init["LoadState"] != "loaded" or dbus["LoadState"] != "loaded":
        raise AssertionError("manager init/dbus unit identities are not loaded")
    init_group = PurePosixPath(init["ControlGroup"])
    dbus_group = PurePosixPath(dbus["ControlGroup"])
    if init_group != root_group / "init.scope" or not dbus_group.is_relative_to(root_group):
        raise AssertionError("manager init/dbus cgroups escaped the exact manager subtree")
    if dbus["MainPID"] == "0" or not dbus["MainPID"].isdecimal():
        raise AssertionError("the user-manager D-Bus service has no exact MainPID")

    allowed_test_groups: dict[str, PurePosixPath] = {}
    for name, raw_group in (test_cgroups or {}).items():
        if not raw_group.startswith("/"):
            raise AssertionError(f"{name} has no absolute cgroup identity")
        group = PurePosixPath(raw_group)
        if not group.is_relative_to(root_group) or group == root_group:
            raise AssertionError(f"{name} cgroup is outside the manager subtree")
        allowed_test_groups[name] = group
    if len(set(allowed_test_groups.values())) != len(allowed_test_groups):
        raise AssertionError("test units unexpectedly share a cgroup identity")

    process_groups: dict[PurePosixPath, set[int]] = {}
    process_identities: dict[int, tuple[str, int]] = {}
    for procs_file in root.rglob("cgroup.procs"):
        group = root_group / PurePosixPath(procs_file.parent.relative_to(root).as_posix())
        pids = {int(value) for value in procs_file.read_text(encoding="ascii").split()}
        process_groups[group] = pids
        for pid in pids:
            proc_group, comm, ppid = _process_cgroup_identity(pid)
            if PurePosixPath(proc_group) != group:
                raise AssertionError(f"PID {pid} cgroup.procs disagrees with /proc/{pid}/cgroup")
            process_identities[pid] = (comm, ppid)

    init_pids = process_groups.get(init_group, set())
    manager_pid_int = int(manager_pid)
    if manager_pid_int not in init_pids:
        raise AssertionError("the current user manager is absent from init.scope")
    sd_pam_pids = init_pids - {manager_pid_int}
    if len(sd_pam_pids) != 1:
        raise AssertionError(
            f"expected exactly one baseline (sd-pam) process in init.scope, got {sorted(sd_pam_pids)}"
        )
    for pid in sd_pam_pids:
        comm, ppid = process_identities[pid]
        if comm != "(sd-pam)" or ppid != manager_pid_int:
            raise AssertionError(f"unexpected process {pid} in user-manager init.scope: {comm!r}")
    dbus_pids = process_groups.get(dbus_group, set())
    if dbus_pids != {int(dbus["MainPID"])}:
        raise AssertionError(
            f"unexpected processes in user-manager dbus.service: {sorted(dbus_pids)}"
        )
    baseline_processes = {
        "init.scope": frozenset(init_pids),
        "dbus.service": frozenset(dbus_pids),
    }
    if (
        expected_baseline_processes is not None
        and baseline_processes != expected_baseline_processes
    ):
        raise AssertionError(
            "manager init/dbus process inventory changed since preflight: "
            f"expected={expected_baseline_processes!r}, actual={baseline_processes!r}"
        )

    ordered_test_groups = sorted(
        allowed_test_groups.items(), key=lambda item: len(item[1].parts), reverse=True
    )
    for group, pids in process_groups.items():
        if not pids or group in {init_group, dbus_group}:
            continue
        if group.is_relative_to(dbus_group):
            raise AssertionError(
                f"unexpected child cgroup under user-manager dbus.service: {group}"
            )
        matches = [
            (name, candidate)
            for name, candidate in ordered_test_groups
            if group.is_relative_to(candidate)
        ]
        if not matches:
            raise AssertionError(f"unaccounted process cgroup under user manager: {group}")
        name, candidate = matches[0]
        if (
            name in {"attempt_slice", "launch_driver"}
            or group == candidate
            and name == "monitor"
            and expected_monitor_pid is None
        ):
            raise AssertionError(f"unexpected process in {name} cgroup: {sorted(pids)}")
        if name == "monitor" and pids != {int(expected_monitor_pid or "0")}:
            raise AssertionError(f"monitor PID does not match its cgroup: {sorted(pids)}")
    return baseline_processes


def test_user_manager_unit_inventory_retains_unknown_types_and_multiline_descriptions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unrecognized_unit = "unexpected-agent.busname"
    completed = subprocess.CompletedProcess(
        args=["systemctl"],
        returncode=0,
        stdout=json.dumps(
            [
                {
                    "unit": unrecognized_unit,
                    "load": "loaded",
                    "active": "active",
                    "sub": "running",
                    "description": "Example D-Bus name\nimport json",
                }
            ]
        ),
        stderr="",
    )
    monkeypatch.setattr(sys.modules[__name__], "_systemd_command", lambda _args: completed)

    assert _user_manager_unit_inventory("systemctl") == {
        unrecognized_unit: ("loaded", "active", "running")
    }


def test_user_manager_cidata_uuid_unit_tracks_only_the_labeled_device(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    device = tmp_path / "vdb"
    device.touch()
    unrelated_device = tmp_path / "vdc"
    unrelated_device.touch()
    by_label = tmp_path / "by-label"
    by_uuid = tmp_path / "by-uuid"
    by_label.mkdir()
    by_uuid.mkdir()
    (by_label / "cidata").symlink_to(device)
    uuid_name = "2026-10-21-08-08-25-32"
    (by_uuid / uuid_name).symlink_to(device)
    (by_uuid / "unrelated-volume").symlink_to(unrelated_device)
    expected_unit = r"dev-disk-by\x2duuid-2026\x2d10\x2d21\x2d08\x2d08\x2d25\x2d32.device"
    calls: list[list[str]] = []

    def fake_systemd_command(argv: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, f"{expected_unit}\n", "")

    monkeypatch.setattr(sys.modules[__name__], "_systemd_command", fake_systemd_command)

    assert (
        _user_manager_cidata_uuid_device_unit(
            "/usr/bin/systemd-escape",
            cidata_label_path=by_label / "cidata",
            uuid_directory=by_uuid,
            expected_device_path=None,
        )
        == expected_unit
    )
    assert calls == [
        ["/usr/bin/systemd-escape", "--path", "--suffix=device", str(by_uuid / uuid_name)]
    ]

    (by_uuid / "second-alias").symlink_to(device)
    with pytest.raises(RuntimeError, match="exactly one"):
        _user_manager_cidata_uuid_device_unit(
            "/usr/bin/systemd-escape",
            cidata_label_path=by_label / "cidata",
            uuid_directory=by_uuid,
            expected_device_path=None,
        )


def test_user_manager_restart_inventory_allows_only_known_user_slice_states() -> None:
    expected = _user_manager_restart_expected_inventory(
        501, cidata_uuid_device_unit=r"dev-disk-by\x2duuid-2026\x2d10\x2d21.device"
    )
    assert _user_manager_restart_inventory_is_allowlisted(expected, expected)

    absent_user_slice = {unit: state for unit, state in expected.items() if unit != "user.slice"}
    assert _user_manager_restart_inventory_is_allowlisted(absent_user_slice, expected)

    fixture_parent_slice = dict(absent_user_slice)
    fixture_parent_slice["user-acp.slice"] = ("loaded", "active", "active")
    assert _user_manager_restart_inventory_is_allowlisted(fixture_parent_slice, expected)

    fixture_parent_slice["user-acp.slice"] = ("loaded", "inactive", "dead")
    assert _user_manager_restart_inventory_is_allowlisted(fixture_parent_slice, expected)

    inactive_user_slice = dict(expected)
    inactive_user_slice["user.slice"] = ("loaded", "inactive", "dead")
    assert _user_manager_restart_inventory_is_allowlisted(inactive_user_slice, expected)

    unexpected_unit = dict(expected)
    unexpected_unit["agent-session.service"] = ("loaded", "active", "running")
    assert not _user_manager_restart_inventory_is_allowlisted(unexpected_unit, expected)

    changed_dbus = dict(expected)
    changed_dbus["dbus.service"] = ("loaded", "inactive", "dead")
    assert not _user_manager_restart_inventory_is_allowlisted(changed_dbus, expected)


def test_user_manager_parent_slice_requires_exact_empty_implicit_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unit = "user-acp.slice"
    manager_cgroup = "/user.slice/user-501.slice/user@501.service"
    properties = {
        "ControlGroup": f"{manager_cgroup}/user.slice/{unit}",
        "FragmentPath": "",
        "LoadState": "loaded",
    }
    monkeypatch.setattr(
        sys.modules[__name__], "_unit_properties", lambda _unit, _properties: properties
    )
    active = ("loaded", "active", "active")
    inactive = ("loaded", "inactive", "dead")
    assert _user_manager_parent_slice_state_is_safe(unit, active, manager_cgroup, allow_active=True)
    assert not _user_manager_parent_slice_state_is_safe(
        unit, active, manager_cgroup, allow_active=False
    )

    properties["ControlGroup"] = ""
    assert _user_manager_parent_slice_state_is_safe(
        unit, inactive, manager_cgroup, allow_active=False
    )
    properties["ControlGroup"] = "/unexpected/cgroup"
    assert not _user_manager_parent_slice_state_is_safe(
        unit, inactive, manager_cgroup, allow_active=False
    )


def _assert_units_available_for_test(*units: str) -> None:
    for unit in units:
        props = _unit_properties(unit, ("ActiveState", "ControlGroup", "FragmentPath", "LoadState"))
        if props["LoadState"] == "not-found":
            continue
        # systemd keeps implicit, inactive slices loaded after they are stopped.
        # Reusing one is safe only while it has no backing unit file or cgroup.
        if (
            unit.endswith(".slice")
            and props["LoadState"] == "loaded"
            and props["ActiveState"] == "inactive"
            and not props["ControlGroup"]
            and not props["FragmentPath"]
        ):
            continue
        pytest.fail(f"refusing to use pre-existing systemd unit {unit}")


def _wait_for_path(path: Path, error_path: Path, timeout: float = 45.0) -> Path:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            return path
        if error_path.is_file():
            error = json.loads(error_path.read_text(encoding="utf-8"))
            raise AssertionError(
                f"monitor child failed:\n{error.get('traceback', 'unknown error')}"
            )
        time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for monitor receipt {path.name}")


def _wait_for_receipt(control: Path, name: str, timeout: float = 45.0) -> Path:
    return _wait_for_path(control / name, control / "error.json", timeout)


def _apparmor_identity() -> str | None:
    try:
        return Path("/proc/self/attr/current").read_text(encoding="ascii").strip()
    except OSError:
        return None


def _cgroup_is_empty(control_group: str) -> bool:
    if (
        not isinstance(control_group, str)
        or not control_group.startswith("/")
        or posixpath.normpath(control_group) != control_group
        or any(part in {".", ".."} for part in PurePosixPath(control_group).parts)
    ):
        return False
    root = Path("/sys/fs/cgroup").resolve()
    path = root.joinpath(*PurePosixPath(control_group).parts[1:])
    if not path.exists():
        return True
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root):
            return False
        events = (resolved / "cgroup.events").read_text(encoding="ascii").splitlines()
    except OSError:
        return False
    return "populated 0" in events


def _monitor_child(
    repo: Path,
    rootfs_source: Path,
    source_worktree: Path,
    attempt_id: str,
    claim_token: int,
    execution_id: str,
    control: Path,
    terminate_before_gate: bool,
) -> None:
    """Perform process-local launch work in the driver and verify its monitor service."""

    handle: oci_worker.RuncLaunchHandle | None = None
    try:
        supervisor = GitSupervisor(repo)
        execution = supervisor._sandbox_execution_get(attempt_id)
        if (
            execution is None
            or execution["claim_token"] != claim_token
            or execution["execution_id"] != execution_id
            or execution["phase"] != "reserved"
        ):
            raise RuntimeError("child did not reopen the exact reserved execution")
        rootfs_pin = supervisor.config.oci_rootfs_pin
        runc_pin = supervisor.config.oci_runc_executable
        if rootfs_pin is None or runc_pin is None:
            raise RuntimeError("child configuration did not recreate trusted OCI pins")

        execution_root = Path(execution["bundle_path"]).parent
        bundle_root = Path(execution["bundle_path"])
        state_root = Path(execution["state_path"])
        baseline_root = execution_root / "baseline"
        workspace_root = execution_root / "workspace"
        for path in (execution_root, bundle_root, state_root):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            info = path.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise RuntimeError(f"reserved execution directory is not private: {path.name}")
        rootfs = bundle_root / "rootfs"
        if rootfs.exists():
            raise RuntimeError("reserved bundle rootfs already exists")
        shutil.copytree(rootfs_source, rootfs, symlinks=True)
        source_git_pointer = source_worktree / ".git"
        try:
            source_git_pointer_mode = source_git_pointer.lstat().st_mode
        except FileNotFoundError:
            raise RuntimeError(
                "attempt worktree is missing its expected .git pointer fixture"
            ) from None
        if not stat.S_ISREG(source_git_pointer_mode):
            raise RuntimeError("attempt worktree .git pointer fixture is not a regular file")
        git_pointer_text = source_git_pointer.read_text(encoding="utf-8").strip()
        pointer_key, separator, git_directory_value = git_pointer_text.partition(": ")
        if pointer_key != "gitdir" or not separator or not git_directory_value:
            raise RuntimeError("attempt worktree .git pointer is malformed")
        git_directory = Path(git_directory_value)
        if not git_directory.is_absolute():
            git_directory = source_worktree / git_directory
        git_directory = git_directory.resolve(strict=True)
        trusted_git_root = (repo / ".git").resolve(strict=True)
        if not git_directory.is_relative_to(trusted_git_root) or not git_directory.is_dir():
            raise RuntimeError("attempt worktree .git pointer escaped the private test repository")
        baseline = copy_snapshot(source_worktree, baseline_root)
        workspace = copy_snapshot(baseline.root, workspace_root)
        if _entry_is_present(baseline.root / ".git") or _entry_is_present(workspace.root / ".git"):
            raise RuntimeError("host Git pointer metadata entered a private worker snapshot")
        execution = supervisor._sandbox_execution_bind_workspace(
            attempt_id, claim_token, baseline, workspace
        )
        container_id = execution["container_id"]
        launch_driver_unit = f"acp-launch-driver-{execution_id}.service"
        launch_driver = _unit_properties(
            launch_driver_unit,
            ("ActiveState", "ControlGroup", "Id", "InvocationID", "MainPID", "Slice"),
        )
        if (
            launch_driver["Id"] != launch_driver_unit
            or launch_driver["ActiveState"] != "active"
            or int(launch_driver["MainPID"]) != os.getpid()
            or not launch_driver["InvocationID"]
            or not launch_driver["ControlGroup"]
        ):
            raise RuntimeError("child is not the exact live systemd launch-driver MainPID")

        attempt_slice_unit = oci_worker._oci_worker_systemd_slice(container_id)
        scope_unit = f"acp-{container_id}.scope"
        pid_file = state_root / "init.pid"
        marker = workspace_root / _PAYLOAD_MARKER
        git_marker = workspace_root / _GIT_METADATA_MARKER
        config = oci_worker.build_oci_worker_config(
            bundle_root,
            workspace,
            (
                "/bin/sh",
                "-c",
                "set -eu; "
                "test ! -e /workspace/.git; "
                "test ! -L /workspace/.git; "
                "test ! -e /workspace/.git/HEAD; "
                f"printf 'host-git-metadata-not-visible\\n' > /workspace/{_GIT_METADATA_MARKER}; "
                f"printf 'candidate-payload-ran\\n' > /workspace/{_PAYLOAD_MARKER}; "
                "/bin/busybox sleep 3",
            ),
            rootfs_pin=rootfs_pin,
            container_id=container_id,
            memory_bytes=_CONTAINER_MEMORY_BYTES,
            pids_limit=_CONTAINER_PIDS_LIMIT,
            cpu_quota_us=_CONTAINER_CPU_QUOTA_US,
            cpu_period_us=_CONTAINER_CPU_PERIOD_US,
        )
        binding = oci_worker._apply_pinned_runc_recursive_private_policy(
            config, runc_pin, expected_version=_SUPPORTED_RUNC_VERSION
        )
        submission: Any | None = None

        def authorize(target: oci_worker._RuncLaunchTarget) -> Any:
            nonlocal submission
            submission = supervisor._sandbox_execution_authorize_launch_submission(
                attempt_id, claim_token, launch_target=target
            )
            return submission

        handle = oci_worker.spawn_pinned_runc(
            binding,
            state_root,
            bundle_root,
            workspace_root,
            pid_file,
            container_id,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            _authorize_runc_submission=authorize,
        )
        client_pid = oci_worker._runc_launch_pid(handle)
        client_identity = oci_worker._runc_launch_process_identity(handle)
        process = oci_worker._runc_launch_process_for_testing(handle)
        if submission is None or client_pid is None or client_identity is None or process is None:
            raise RuntimeError("pinned runc did not retain the exact launch capability")
        deadline = time.monotonic() + 15.0
        while not pid_file.exists() and time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("pinned runc exited before reaching the held init gate")
            time.sleep(0.05)
        if not pid_file.is_file():
            raise TimeoutError("pinned runc did not create its private init PID file")

        attempt_slice = _unit_properties(
            attempt_slice_unit, ("ActiveState", "ControlGroup", "Id", "InvocationID")
        )
        scope = _unit_properties(scope_unit, ("ActiveState", "ControlGroup", "Id", "InvocationID"))
        for unit, props in ((attempt_slice_unit, attempt_slice), (scope_unit, scope)):
            if (
                props["ActiveState"] != "active"
                or props["Id"] != unit
                or not props["InvocationID"]
                or not props["ControlGroup"]
            ):
                raise RuntimeError(f"exact worker systemd identity is incomplete: {unit}")
        if Path(scope["ControlGroup"]).parent.as_posix() != attempt_slice["ControlGroup"]:
            raise RuntimeError("worker scope is not inside its exact attempt slice")

        try:
            sandbox_monitor_service._validate_scope_binding(
                expected_identity=(attempt_id, claim_token, execution_id),
                scope_unit=scope_unit,
                scope_invocation_id=scope["InvocationID"],
                scope_control_group=scope["ControlGroup"],
                attempt_slice_control_group=attempt_slice["ControlGroup"],
            )
        except sandbox_monitor_service.SandboxMonitorServiceError as error:
            raise RuntimeError(
                "live monitor scope binding rejected: "
                f"identity={(attempt_id, claim_token, execution_id)!r}; "
                f"scope_unit={scope_unit!r}; "
                f"scope_invocation_id={scope['InvocationID']!r}; "
                f"scope_control_group={scope['ControlGroup']!r}; "
                f"attempt_slice_unit={attempt_slice_unit!r}; "
                f"attempt_slice_control_group={attempt_slice['ControlGroup']!r}"
            ) from error

        supervisor._sandbox_execution_record_launch(
            attempt_id,
            claim_token,
            runc_handle=handle,
            launch_submission=submission,
            attempt_slice_unit=attempt_slice_unit,
            attempt_slice_invocation_id=attempt_slice["InvocationID"],
            attempt_slice_cgroup_path=attempt_slice["ControlGroup"],
            scope_unit=scope_unit,
            scope_invocation_id=scope["InvocationID"],
            cgroup_path=scope["ControlGroup"],
        )
        durable = supervisor._sandbox_execution_get(attempt_id)
        if durable is None or durable["phase"] != "launched":
            raise RuntimeError("trusted monitor did not durably record the launched execution")
        wrapper_unit = durable["wrapper_unit"]
        wrapper = _unit_properties(
            wrapper_unit,
            ("ActiveState", "ControlGroup", "Id", "InvocationID", "MainPID", "Slice"),
        )
        monitor_pid = durable["monitor_pid"]
        monitor_identity = durable["monitor_identity"]
        if (
            wrapper["Id"] != wrapper_unit
            or wrapper["ActiveState"] != "active"
            or wrapper["Slice"] != _MONITOR_SLICE_UNIT
            or int(wrapper["MainPID"]) != monitor_pid
            or wrapper["InvocationID"] != durable["wrapper_invocation_id"]
            or wrapper["ControlGroup"] != durable["wrapper_cgroup_path"]
            or _linux_process_identity(monitor_pid) != monitor_identity
            or _linux_process_identity(client_pid) != client_identity
            or Path(wrapper["ControlGroup"]).is_relative_to(Path(attempt_slice["ControlGroup"]))
        ):
            raise RuntimeError("service-owned monitor identity changed before running attestation")
        try:
            attestation = collect_running_runtime_attestation(
                runc_executable_pin=runc_pin,
                state_root=state_root,
                pid_file_path=pid_file,
                expected_container_id=container_id,
                expected_bundle_path=str(bundle_root),
                expected_monitor_pid=monitor_pid,
                expected_monitor_identity=monitor_identity,
                expected_runc_client_pid=client_pid,
                expected_runc_client_identity=client_identity,
                expected_wrapper_unit=wrapper_unit,
                expected_wrapper_invocation_id=wrapper["InvocationID"],
                expected_launch_driver_unit=launch_driver_unit,
                expected_attempt_slice_unit=attempt_slice_unit,
                expected_attempt_slice_invocation_id=attempt_slice["InvocationID"],
                expected_scope_unit=scope_unit,
                expected_scope_invocation_id=scope["InvocationID"],
                expected_cgroup_path=scope["ControlGroup"],
                expected_memory_max_bytes=_CONTAINER_MEMORY_BYTES,
                expected_cpu_quota=_CONTAINER_CPU_QUOTA_US,
                expected_cpu_period=_CONTAINER_CPU_PERIOD_US,
                expected_pids_max=_CONTAINER_PIDS_LIMIT,
            )
        except SupervisorError as error:
            try:
                init_pid = int(pid_file.read_text(encoding="ascii").strip())
                process_cgroups = {
                    pid: sandbox_attestation.read_linux_process_snapshot(pid).cgroup.decode(
                        "ascii", errors="replace"
                    )
                    for pid in (monitor_pid, client_pid, init_pid)
                }
            except BaseException as diagnostic_error:
                process_cgroups = {"diagnostic_error": repr(diagnostic_error)}
            raise RuntimeError(
                "live runtime attestation rejected process cgroup membership: "
                f"expected_scope={scope['ControlGroup']!r}; "
                f"observed_process_cgroups={process_cgroups!r}"
            ) from error
        durable = supervisor._sandbox_execution_get(attempt_id)
        if (
            durable is None
            or durable["phase"] != "launched"
            or marker.exists()
            or git_marker.exists()
        ):
            raise RuntimeError("payload ran before the durable running transition")
        _write_json(
            control / "pre-running.json",
            {
                "phase": durable["phase"],
                "monitor_pid": monitor_pid,
                "wrapper_main_pid": int(wrapper["MainPID"]),
                "runc_client_pid": client_pid,
                "launch_driver_apparmor_identity": _apparmor_identity(),
                "attestation_digest": attestation.evidence_sha256,
                "payload_marker_present": marker.exists(),
                "git_metadata_marker_present": git_marker.exists(),
                "source_git_pointer_regular_file": stat.S_ISREG(source_git_pointer.lstat().st_mode),
                "baseline_git_metadata_absent": not _entry_is_present(baseline.root / ".git"),
                "workspace_git_metadata_absent": not _entry_is_present(workspace.root / ".git"),
            },
        )
        _wait_for_receipt(control, "continue-running.json")
        durable = supervisor._sandbox_execution_get(attempt_id)
        if (
            durable is None
            or durable["phase"] != "launched"
            or marker.exists()
            or git_marker.exists()
        ):
            raise RuntimeError("journal or launch gate changed before test release")
        running = supervisor._sandbox_execution_record_running(
            attempt_id, claim_token, attestation=attestation, runc_handle=handle
        )
        if running["phase"] != "running" or marker.exists() or git_marker.exists():
            raise RuntimeError("payload escaped before the durable running transition")
        _write_json(
            control / "post-running.json",
            {
                "phase": running["phase"],
                "payload_marker_present_before_gate": marker.exists(),
                "git_metadata_marker_present_before_gate": git_marker.exists(),
            },
        )
        _wait_for_receipt(control, "running-observed.json")
        durable = supervisor._sandbox_execution_get(attempt_id)
        if (
            durable is None
            or durable["phase"] != "running"
            or marker.exists()
            or git_marker.exists()
        ):
            raise RuntimeError("worker gate changed before parent observed durable running state")
        if terminate_before_gate:
            termination = supervisor.terminate_worker(attempt_id)
            if (
                termination.get("outcome") != "ok"
                or termination.get("phase") != "stopping"
                or termination.get("monitor_phase") not in {"stopping", "exited"}
                or termination.get("stop_requested") is not True
                or termination.get("cleanup_verified") is not False
            ):
                raise RuntimeError(f"live monitor termination was not truthful: {termination!r}")
            if marker.exists() or git_marker.exists():
                raise RuntimeError("worker payload ran despite cancellation before gate release")
            wait_receipt = handle.wait(timeout=15.0)
            exited = supervisor._sandbox_execution_record_exit(
                attempt_id, claim_token, wait_receipt
            )
            if exited["phase"] != "exited":
                raise RuntimeError("cancelled runc client did not record its exact exit receipt")
            delete = subprocess.run(
                [str(runc_pin.path), "--root", str(state_root), "delete", "--force", container_id],
                check=False,
                capture_output=True,
                text=True,
                timeout=8.0,
                env=oci_worker._runc_client_environment(),
            )
            if delete.returncode != 0:
                raise RuntimeError("exact pinned runc state deletion failed after cancellation")
            _write_json(
                control / "result.json",
                {
                    "phase": exited["phase"],
                    "stop_outcome": termination["outcome"],
                    "stop_journal_phase": termination["phase"],
                    "stop_monitor_phase": termination["monitor_phase"],
                    "stop_requested": termination["stop_requested"],
                    "stop_cleanup_verified": termination["cleanup_verified"],
                    "runc_client_returncode": wait_receipt.returncode,
                    "runc_state_deleted": not (state_root / container_id).exists(),
                    "payload_marker_absent": not marker.exists(),
                    "git_marker_absent": not git_marker.exists(),
                    "cleanup_verified_written": False,
                },
            )
            return
        handle.release_gate()
        _wait_for_path(marker, control / "error.json", timeout=10.0)
        if marker.read_text(encoding="ascii") != "candidate-payload-ran\n":
            raise RuntimeError("payload wrote unexpected content into the private workspace")
        if git_marker.read_text(encoding="ascii") != "host-git-metadata-not-visible\n":
            raise RuntimeError("worker did not confirm the host .git pointer was absent")
        wait_receipt = handle.wait(timeout=15.0)
        exited = supervisor._sandbox_execution_record_exit(attempt_id, claim_token, wait_receipt)
        if exited["phase"] != "exited" or wait_receipt.returncode != 0:
            raise RuntimeError("test payload did not exit cleanly")
        write_set_rules = _persisted_write_set_rules(supervisor, attempt_id)
        change_set = collect_changes(
            baseline.manifest, workspace.root, write_set_rules=write_set_rules
        )
        if {
            change.path: change.content for change in change_set.changes if change.kind == "file"
        } != {
            _PAYLOAD_MARKER: b"candidate-payload-ran\n",
            _GIT_METADATA_MARKER: b"host-git-metadata-not-visible\n",
        }:
            raise RuntimeError("host change collection did not capture the exact declared output")
        undeclared_probe = workspace.root / "undeclared-output-probe"
        if _entry_is_present(undeclared_probe):
            raise RuntimeError("undeclared-write probe path already exists")
        try:
            undeclared_probe.write_bytes(b"must-not-be-authorized\n")
            try:
                collect_changes(baseline.manifest, workspace.root, write_set_rules=write_set_rules)
            except SupervisorError as error:
                if error.code != "undeclared_write":
                    raise
            else:
                raise RuntimeError("host change collector accepted an undeclared output")
        finally:
            undeclared_probe.unlink(missing_ok=True)
        if _entry_is_present(undeclared_probe):
            raise RuntimeError("undeclared-write probe remained in the private workspace")
        delete = subprocess.run(
            [str(runc_pin.path), "--root", str(state_root), "delete", "--force", container_id],
            check=False,
            capture_output=True,
            text=True,
            timeout=8.0,
            env=oci_worker._runc_client_environment(),
        )
        if delete.returncode != 0:
            raise RuntimeError("exact pinned runc state deletion failed after payload exit")
        _write_json(
            control / "result.json",
            {
                "phase": exited["phase"],
                "payload_marker": marker.read_text(encoding="ascii"),
                "git_metadata_absent_inside_worker": (
                    git_marker.read_text(encoding="ascii") == "host-git-metadata-not-visible\n"
                ),
                "runc_client_returncode": wait_receipt.returncode,
                "runc_state_deleted": not (state_root / container_id).exists(),
                "change_set_paths": [change.path for change in change_set.changes],
                "change_set_actions": [change.action for change in change_set.changes],
                "change_set_digest": change_set.digest,
                "undeclared_write_rejected": True,
                "cleanup_verified_written": False,
            },
        )
    except BaseException:
        _write_json(
            control / "error.json",
            {
                "traceback": traceback.format_exc(),
                "launch_driver_apparmor_identity": _apparmor_identity(),
            },
        )
        if handle is not None:
            handle.close_gate()
            process = oci_worker._runc_launch_process_for_testing(handle)
            if process is not None and process.poll() is None:
                try:
                    oci_worker._kill_process_group(process)
                except BaseException:
                    pass
        raise


def _monitor_child_entry(argv: list[str]) -> None:
    if len(argv) != 8 or argv[7] not in {"0", "1"}:
        raise SystemExit("monitor child requires seven arguments and a 0/1 terminate mode")
    repo, rootfs, worktree, attempt_id, claim_token, execution_id, control, terminate_mode = argv
    _monitor_child(
        Path(repo),
        Path(rootfs),
        Path(worktree),
        attempt_id,
        int(claim_token),
        execution_id,
        Path(control),
        terminate_mode == "1",
    )


def _systemd_command(argv: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=sandbox_attestation._trusted_systemd_command_environment(),
    )


def _live_concurrent_control() -> tuple[Path, str] | None:
    if os.environ.get("ACP_LIVE_CONCURRENT_CHILD") != "1":
        if os.environ.get("ACP_LIVE_CONCURRENT_CONTROL_ROOT") or os.environ.get(
            "ACP_LIVE_CONCURRENT_SLOT"
        ):
            raise RuntimeError("concurrent live control variables require child mode")
        return None
    raw_root = os.environ.get("ACP_LIVE_CONCURRENT_CONTROL_ROOT")
    slot = os.environ.get("ACP_LIVE_CONCURRENT_SLOT")
    if not raw_root or slot not in {"0", "1"}:
        raise RuntimeError("concurrent live child requires its private control root and slot")
    root = Path(raw_root)
    try:
        info = root.lstat()
    except OSError as error:
        raise RuntimeError("concurrent live control root is unavailable") from error
    if (
        not root.is_absolute()
        or not root.is_relative_to(Path("/tmp"))
        or not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise RuntimeError("concurrent live control root is not a private test-owned directory")
    return root, slot


def _write_live_concurrent_marker(root: Path, name: str, content: bytes) -> None:
    path = root / name
    temporary = root / f".{name}.{os.getpid()}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        if os.write(descriptor, content) != len(content):
            raise OSError("short write creating concurrent live control marker")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if os.path.lexists(path):
        temporary.unlink()
        raise FileExistsError(path)
    os.rename(temporary, path)


def _signal_live_test_process_group(process: subprocess.Popen[str], signum: int) -> None:
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        pass


def _wait_for_live_concurrent_release(
    control: tuple[Path, str],
    *,
    attempt: dict[str, Any],
    execution: dict[str, Any],
    repo: Path,
    run_root: Path,
    source_worktree: Path,
    workspace_root: Path,
) -> None:
    root, slot = control
    scope_unit = f"acp-{execution['container_id']}.scope"
    properties = _unit_properties(
        scope_unit,
        ("ActiveState", "ControlGroup", "Id", "InvocationID", "LoadState", "SubState"),
    )
    if (
        properties["Id"] != scope_unit
        or properties["LoadState"] != "loaded"
        or properties["ActiveState"] != "active"
        or properties["SubState"] != "running"
        or not properties["InvocationID"]
        or not properties["ControlGroup"]
    ):
        raise RuntimeError("concurrent child did not own an exact running ACP scope")
    with GitSupervisor(repo).connect() as connection:
        runtime_allocations = connection.execute(
            "SELECT pool_name, value, lease_expires_at FROM runtime_allocations "
            "WHERE attempt_id = ? ORDER BY pool_name, value",
            (attempt["id"],),
        ).fetchall()
    ready = {
        "attempt_id": attempt["id"],
        "claim_token": attempt["claim_token"],
        "container_id": execution["container_id"],
        "execution_id": execution["execution_id"],
        "pid": os.getpid(),
        "repo": str(repo.resolve(strict=True)),
        "runtime_allocations": [dict(row) for row in runtime_allocations],
        "run_root": str(run_root.resolve(strict=True)),
        "scope_control_group": properties["ControlGroup"],
        "scope_invocation_id": properties["InvocationID"],
        "scope_unit": scope_unit,
        "slot": slot,
        "source_worktree": str(source_worktree.resolve(strict=True)),
        "workspace_root": str(workspace_root.resolve(strict=True)),
    }
    _write_live_concurrent_marker(
        root,
        f"ready-{slot}.json",
        json.dumps(ready, sort_keys=True).encode("utf-8"),
    )
    release_path = root / f"release-{slot}"
    deadline = time.monotonic() + 90
    while not os.path.lexists(release_path) and time.monotonic() < deadline:
        time.sleep(0.05)
    try:
        release_info = release_path.lstat()
    except OSError as error:
        raise TimeoutError("parent did not release the concurrent live barrier") from error
    if (
        not stat.S_ISREG(release_info.st_mode)
        or stat.S_ISLNK(release_info.st_mode)
        or release_info.st_uid != os.geteuid()
        or stat.S_IMODE(release_info.st_mode) != 0o600
        or release_path.read_text(encoding="ascii") != "release"
    ):
        raise RuntimeError("concurrent live release marker identity or content changed")


def _wait_for_live_concurrent_cleanup_verification(
    control: tuple[Path, str], *, attempt_id: str, execution_id: str
) -> None:
    """Let both shared-repository attempts verify cleanup before either reaps."""

    root, slot = control
    marker = root / f"cleanup-verified-{slot}.json"
    _write_live_concurrent_marker(
        root,
        marker.name,
        json.dumps(
            {"attempt_id": attempt_id, "execution_id": execution_id, "slot": slot},
            sort_keys=True,
        ).encode("utf-8"),
    )
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        records: dict[str, dict[str, str]] = {}
        for expected_slot in ("0", "1"):
            path = root / f"cleanup-verified-{expected_slot}.json"
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise RuntimeError("concurrent cleanup-verification marker has unsafe metadata")
            record = json.loads(path.read_text(encoding="utf-8"))
            if (
                not isinstance(record, dict)
                or record.get("slot") != expected_slot
                or not isinstance(record.get("attempt_id"), str)
                or not isinstance(record.get("execution_id"), str)
            ):
                raise RuntimeError("concurrent cleanup-verification marker is malformed")
            records[expected_slot] = record
        if len(records) == 2:
            if (
                len({record["attempt_id"] for record in records.values()}) != 2
                or len({record["execution_id"] for record in records.values()}) != 2
                or records[slot]["attempt_id"] != attempt_id
                or records[slot]["execution_id"] != execution_id
            ):
                raise RuntimeError("concurrent cleanup-verification markers are not distinct")
            return
        time.sleep(0.05)
    raise TimeoutError("peer attempt did not verify cleanup before the shared reaper barrier")


def _read_live_concurrent_prepared_records(
    control_root: Path, *, expected_pids: dict[str, int] | None = None
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    records: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    for slot in ("0", "1"):
        path = control_root / f"prepared-{slot}.json"
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            failures.append(f"could not inspect slot {slot} cleanup receipt: {error}")
            continue
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            failures.append(f"slot {slot} cleanup receipt has unsafe file metadata")
            continue
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(record, dict):
                raise ValueError("receipt is not an object")
            attempt_id = record["attempt_id"]
            claim_token = record["claim_token"]
            execution_id = record["execution_id"]
            container_id = record["container_id"]
            pytest_pid = record["pytest_pid"]
            run_root = record["run_root"]
            if (
                record.get("slot") != slot
                or not isinstance(attempt_id, str)
                or not isinstance(execution_id, str)
                or not isinstance(container_id, str)
                or type(pytest_pid) is not int
                or pytest_pid <= 0
                or (expected_pids is not None and expected_pids.get(slot) != pytest_pid)
                or not isinstance(run_root, str)
                or not Path(run_root).is_absolute()
                or not Path(run_root).is_relative_to(Path("/tmp"))
                or Path(run_root).parent != Path("/tmp")
                or not Path(run_root).name.startswith("acp-live-launch-driver-")
            ):
                raise ValueError("receipt identity or run root is invalid")
            identity = (attempt_id, claim_token, execution_id)
            monitor_unit = sandbox_monitor_service_unit(*identity)
            expected_container_id = "acp-" + monitor_unit.removeprefix("acp-monitor-").removesuffix(
                ".service"
            )
            if container_id != expected_container_id:
                raise ValueError("receipt container does not match its attempt identity")
            expected_units = {
                "service_unit": f"acp-launch-driver-{execution_id}.service",
                "monitor_unit": monitor_unit,
                "scope_unit": f"acp-{expected_container_id}.scope",
                "slice_unit": sandbox_attempt_slice_unit(*identity),
            }
            if any(record.get(field) != value for field, value in expected_units.items()):
                raise ValueError("receipt systemd units do not match its attempt identity")
        except (KeyError, TypeError, ValueError) as error:
            failures.append(f"slot {slot} cleanup receipt is invalid: {error}")
            continue
        records[slot] = record
    return records, failures


def _wait_for_quiescence(service_unit: str | None, slice_unit: str | None) -> bool:
    safe = True
    for unit in (service_unit, slice_unit):
        if unit is None:
            continue
        try:
            properties = ("ActiveState", "ControlGroup", "Id", "LoadState")
            if unit.endswith(".service"):
                properties += ("MainPID",)
            props = _unit_properties(unit, properties)
        except Exception:
            return False
        not_running = props["LoadState"] == "not-found" or props["ActiveState"] == "inactive"
        if props["ActiveState"] == "failed":
            not_running = not unit.endswith(".service") or props["MainPID"] == "0"
        empty = (
            props["LoadState"] == "not-found"
            or (not props["ControlGroup"] and not_running)
            or _cgroup_is_empty(props["ControlGroup"])
        )
        inactive = not_running
        safe = safe and inactive and empty
    return safe


def _best_effort_stop_unit(systemctl: str, unit: str, *, timeout: float = 12.0) -> None:
    """Request stop even when a start client timed out after systemd accepted it."""

    try:
        _systemd_command([systemctl, "--user", "stop", unit], timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        # The caller still requires an independent exact-unit quiescence proof.
        pass


def _reset_transient_service_after_quiescence(systemctl: str, service_unit: str) -> bool:
    """Unload only the exact test-owned transient service after proving it is inert."""

    try:
        properties = _unit_properties(
            service_unit, ("ActiveState", "ControlGroup", "LoadState", "MainPID")
        )
        if properties["LoadState"] == "not-found":
            return (
                properties["ActiveState"] == "inactive"
                and not properties["ControlGroup"]
                and properties["MainPID"] == "0"
            )
        if (
            properties["LoadState"] != "loaded"
            or properties["ActiveState"] not in {"inactive", "failed"}
            or properties["ControlGroup"]
            or properties["MainPID"] != "0"
        ):
            return False
        reset = _systemd_command([systemctl, "--user", "reset-failed", service_unit], timeout=12.0)
        if reset.returncode != 0:
            return False
        properties = _unit_properties(
            service_unit, ("ActiveState", "ControlGroup", "LoadState", "MainPID")
        )
    except Exception:
        return False
    return (
        properties["LoadState"] == "not-found"
        and properties["ActiveState"] == "inactive"
        and not properties["ControlGroup"]
        and properties["MainPID"] == "0"
    )


def _stop_attempted_units_and_check_quiescence(
    systemctl: str,
    service_unit: str | None,
    service_start_attempted: bool,
    slice_unit: str | None,
    slice_start_attempted: bool,
) -> bool:
    """Stop and verify each unit whose start request might have reached systemd."""

    if service_start_attempted and service_unit is not None:
        _best_effort_stop_unit(systemctl, service_unit)
    if slice_start_attempted and slice_unit is not None:
        _best_effort_stop_unit(systemctl, slice_unit)
    quiescent = _wait_for_quiescence(
        service_unit if service_start_attempted else None,
        slice_unit if slice_start_attempted else None,
    )
    if not quiescent:
        return False
    if service_start_attempted and service_unit is not None:
        return _reset_transient_service_after_quiescence(systemctl, service_unit)
    return True


def test_attempted_systemd_starts_are_stopped_and_checked_after_client_timeouts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stop_requests: list[str] = []
    checked_units: list[tuple[str | None, str | None]] = []
    reset_units: list[str] = []

    def timed_out_stop(argv: list[str], timeout: float = 10.0) -> None:
        stop_requests.append(argv[-1])
        raise subprocess.TimeoutExpired(argv, timeout)

    def quiescent(service: str | None, slice_: str | None) -> bool:
        checked_units.append((service, slice_))
        return True

    def reset_after_quiescence(systemctl: str, service: str) -> bool:
        reset_units.append(service)
        return True

    monkeypatch.setattr(sys.modules[__name__], "_systemd_command", timed_out_stop)
    monkeypatch.setattr(sys.modules[__name__], "_wait_for_quiescence", quiescent)
    monkeypatch.setattr(
        sys.modules[__name__],
        "_reset_transient_service_after_quiescence",
        reset_after_quiescence,
    )
    assert _stop_attempted_units_and_check_quiescence(
        "/usr/bin/systemctl",
        "acp-test.service",
        True,
        "acp-test.slice",
        True,
    )
    assert stop_requests == ["acp-test.service", "acp-test.slice"]
    assert checked_units == [("acp-test.service", "acp-test.slice")]
    assert reset_units == ["acp-test.service"]


def test_reset_transient_service_requires_exact_unit_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []

    def command(argv: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
        commands.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    properties = {
        "ActiveState": "inactive",
        "ControlGroup": "",
        "LoadState": "not-found",
        "MainPID": "0",
    }
    monkeypatch.setattr(sys.modules[__name__], "_systemd_command", command)
    monkeypatch.setattr(
        sys.modules[__name__],
        "_unit_properties",
        lambda unit, requested: {name: properties[name] for name in requested},
    )

    assert _reset_transient_service_after_quiescence("/usr/bin/systemctl", "acp-test.service")
    assert commands == []

    properties["LoadState"] = "loaded"
    properties["ActiveState"] = "failed"
    properties["MainPID"] = "0"
    queue = [
        dict(properties),
        {
            "ActiveState": "inactive",
            "ControlGroup": "",
            "LoadState": "not-found",
            "MainPID": "0",
        },
    ]

    def queued_properties(unit: str, requested: tuple[str, ...]) -> dict[str, str]:
        current = queue.pop(0)
        return {name: current[name] for name in requested}

    monkeypatch.setattr(
        sys.modules[__name__],
        "_unit_properties",
        queued_properties,
    )
    assert _reset_transient_service_after_quiescence("/usr/bin/systemctl", "acp-test.service")
    assert commands == [["/usr/bin/systemctl", "--user", "reset-failed", "acp-test.service"]]


def test_unit_preflight_allows_only_inactive_empty_implicit_slices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unit_properties = {
        "ActiveState": "inactive",
        "ControlGroup": "",
        "FragmentPath": "",
        "LoadState": "loaded",
    }
    monkeypatch.setattr(
        sys.modules[__name__],
        "_unit_properties",
        lambda unit, properties: {name: unit_properties[name] for name in properties},
    )
    _assert_units_available_for_test("user-acp-test.slice")
    with pytest.raises(pytest.fail.Exception, match="pre-existing systemd unit"):
        _assert_units_available_for_test("acp-test.service")


def _remove_private_test_tree(
    root: Path, *, expected_identity: tuple[int, int] | None = None
) -> None:
    """Remove only this private fixture after making its read-only files deletable."""

    root_info = root.lstat()
    if (
        root.parent != Path("/tmp")
        or not root.name.startswith(
            (
                "acp-live-sandbox-lifecycle-",
                "acp-live-launch-driver-",
                "acp-live-concurrent-shared-",
            )
        )
        or not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != os.geteuid()
    ):
        raise RuntimeError("refusing to remove an unexpected live-test artifact root")
    if expected_identity is not None and (root_info.st_dev, root_info.st_ino) != expected_identity:
        raise RuntimeError("refusing to remove a replaced live-test artifact root")

    def fail_walk(error: OSError) -> None:
        raise error

    for directory, subdirectories, filenames in os.walk(
        root, topdown=False, followlinks=False, onerror=fail_walk
    ):
        current = Path(directory)
        for name in (*subdirectories, *filenames):
            child = current / name
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode):
                continue
            if info.st_uid != os.geteuid():
                raise RuntimeError(
                    f"refusing to change permissions on non-owned fixture data: {child}"
                )
            if stat.S_ISDIR(info.st_mode):
                child.chmod(0o700)
            elif stat.S_ISREG(info.st_mode):
                child.chmod(0o600)
        current.chmod(0o700)
    shutil.rmtree(root)


def _ensure_private_fixture_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise RuntimeError(f"fixture state path is not a real directory: {path.name}")
    if info.st_uid != os.geteuid():
        raise RuntimeError(f"fixture state directory has an unexpected owner: {path.name}")
    path.chmod(0o700)


@pytest.mark.skip(
    reason=(
        "superseded: direct monitor-owned launch violates exact launch-driver redemption; "
        "rebuild this harness on start_sandbox_launch_driver before re-enabling"
    )
)
@pytest.mark.parametrize("terminate_before_gate", [False, True], ids=["release", "terminate"])
def test_live_monitor_journal_holds_payload_until_durable_running_transition(
    terminate_before_gate: bool,
) -> None:
    """Deprecated harness; see the explicit skip reason and current producer proof."""

    source_root = Path(__file__).resolve().parents[1]
    if not sys.platform.startswith("linux") or os.geteuid() == 0:
        pytest.fail("live monitor/journal composition requires an unprivileged Linux user")
    if not source_root.is_relative_to(Path("/tmp")):
        pytest.fail("run this opt-in proof from a disposable checkout beneath /tmp")
    if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        pytest.fail("live monitor/journal composition requires unified cgroup v2")
    controllers = set(Path("/sys/fs/cgroup/cgroup.controllers").read_text().split())
    if not {"cpu", "memory", "pids"}.issubset(controllers):
        pytest.fail("cpu, memory, and pids cgroup v2 controllers are required")
    if os.environ.get("ACP_OCI_TEST_RUNC_VERSION") != _SUPPORTED_RUNC_VERSION:
        pytest.fail("set ACP_OCI_TEST_RUNC_VERSION=1.5.2 for this exact live proof")
    environment = sandbox_attestation._trusted_systemd_command_environment()
    if not (Path(environment["XDG_RUNTIME_DIR"]) / "bus").is_socket():
        pytest.fail("private systemd user-manager socket is unavailable")
    systemctl = str(sandbox_attestation._trusted_systemctl_executable())
    if _systemd_command([systemctl, "--user", "show-environment"]).returncode != 0:
        pytest.fail("active systemd user manager is required")
    if " - cgroup2 " not in Path("/proc/self/mountinfo").read_text(encoding="ascii"):
        pytest.fail("current host does not expose unified cgroup v2")

    runc_path = Path(os.environ.get("ACP_OCI_TEST_RUNC", "/usr/bin/runc"))
    busybox_path = Path(os.environ.get("ACP_OCI_TEST_BUSYBOX", "/usr/bin/busybox"))
    apparmor_profile = os.environ.get("ACP_OCI_TEST_APPARMOR_PROFILE", "").strip()
    apparmor_prefix: list[str] = []
    if apparmor_profile:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", apparmor_profile):
            pytest.fail("ACP_OCI_TEST_APPARMOR_PROFILE must be a simple profile name")
        aa_exec = shutil.which("aa-exec", path=environment["PATH"])
        if aa_exec is None:
            pytest.fail("aa-exec is required when an AppArmor profile is requested")
        profile_probe = _systemd_command([aa_exec, "-p", apparmor_profile, "--", "true"])
        if profile_probe.returncode != 0:
            pytest.fail(f"requested AppArmor profile is unavailable: {apparmor_profile}")
        apparmor_prefix = [aa_exec, "-p", apparmor_profile, "--"]
    systemd_run = shutil.which("systemd-run", path=environment["PATH"])
    if systemd_run is None:
        pytest.fail("systemd-run is required for the exact launch-driver service")
    run_root = Path(tempfile.mkdtemp(prefix="acp-live-sandbox-lifecycle-", dir="/tmp"))
    rootfs_source = run_root / "rootfs-source"
    service_unit: str | None = None
    monitor_unit: str | None = None
    slice_unit: str | None = None
    service_start_attempted = False
    monitor_start_attempted = False
    slice_start_attempted = False
    safe_to_remove = False
    try:
        run_root.chmod(0o700)
        rootfs_source.mkdir(mode=0o755)
        for directory in ("bin", "dev", "etc", "home/agent", "proc", "run", "tmp", "workspace"):
            (rootfs_source / directory).mkdir(parents=True, exist_ok=True, mode=0o755)
        _copy_busybox_closure(busybox_path, rootfs_source)
        repo_root = run_root / "repo"
        repo_root.mkdir(mode=0o700)
        repo = init_repo(repo_root)
        _ensure_private_fixture_directory(repo / ".acp")
        _ensure_private_fixture_directory(repo / ".acp" / "sandbox-executions")
        rootfs_manifest = oci_worker.rootfs_tree_manifest(rootfs_source)
        with (repo / "acp.toml").open("a", encoding="utf-8") as stream:
            stream.write(
                "\n[sandbox.oci]\n"
                f"runc_executable = {json.dumps(str(runc_path.resolve(strict=True)))}\n"
                f"runc_version = {json.dumps(_SUPPORTED_RUNC_VERSION)}\n"
                f"rootfs_path = {json.dumps(str(rootfs_source.resolve(strict=True)))}\n"
                f"rootfs_sha256 = {json.dumps(rootfs_manifest['rootfs_sha256'])}\n"
                f"rootfs_closure_sha256 = {json.dumps(rootfs_manifest['closure_sha256'])}\n"
            )
        supervisor = GitSupervisor(repo)
        task = make_task(
            supervisor,
            _PAYLOAD_MARKER,
            _GIT_METADATA_MARKER,
            title="sandbox lifecycle integration",
        )
        attempt = supervisor.claim(task["id"], "sandbox-lifecycle-test")
        pin = supervisor.config.oci_rootfs_pin
        runc_pin = supervisor.config.oci_runc_executable
        if (
            pin is None
            or runc_pin is None
            or supervisor.config.oci_runc_version != _SUPPORTED_RUNC_VERSION
        ):
            pytest.fail("test config did not pin the exact rootfs and runc identities")
        execution = supervisor._sandbox_execution_reserve(
            attempt["id"],
            attempt["claim_token"],
            rootfs_digest=pin.sha256,
            rootfs_closure_digest=pin.closure_sha256,
            runc_executable_digest=runc_pin.sha256,
            runtime_version=supervisor.config.oci_runc_version,
            oci_version="1.2.1",
        )
        execution_root = Path(execution["bundle_path"]).parent
        execution_root.mkdir(mode=0o700, parents=True)
        Path(execution["bundle_path"]).mkdir(mode=0o700)
        Path(execution["state_path"]).mkdir(mode=0o700)
        control = run_root / "control"
        control.mkdir(mode=0o700)
        monitor_unit = sandbox_monitor_service_unit(
            attempt["id"], attempt["claim_token"], execution["execution_id"]
        )
        service_unit = f"acp-launch-driver-{execution['execution_id']}.service"
        slice_unit = sandbox_attempt_slice_unit(
            attempt["id"], attempt["claim_token"], execution["execution_id"]
        )
        _assert_units_available_for_test(service_unit, monitor_unit, slice_unit)
        # Mark before IPC: a timeout/error can happen after systemd accepted the
        # request, so teardown must inspect and stop this exact unit regardless.
        slice_start_attempted = True
        started = _systemd_command([systemctl, "--user", "start", slice_unit])
        if started.returncode != 0:
            pytest.fail("systemd could not start the exact execution attempt slice")
        pythonpath = os.pathsep.join((str(source_root / "src"), str(source_root / "tests")))
        service_command = [
            systemd_run,
            "--user",
            f"--unit={service_unit}",
            f"--slice={slice_unit}",
            "--property=Type=exec",
            "--property=KillMode=control-group",
            "--property=RuntimeMaxSec=120s",
            f"--working-directory={source_root}",
            f"--setenv=PYTHONPATH={pythonpath}",
            "--no-block",
            *apparmor_prefix,
            sys.executable,
            str(Path(__file__).resolve()),
            "--monitor-child",
            str(repo),
            str(rootfs_source),
            str(attempt["worktree"]),
            attempt["id"],
            str(attempt["claim_token"]),
            execution["execution_id"],
            str(control),
            "1" if terminate_before_gate else "0",
        ]
        # The exact driver service is a child of the attempt slice and is
        # stopped and checked independently even if systemd-run times out.
        service_start_attempted = True
        # The launch driver creates this exact per-execution monitor unit after
        # the worker scope exists. Treat a driver timeout as an ambiguous start
        # of both units and inspect both during isolated test teardown.
        monitor_start_attempted = True
        launched = _systemd_command(service_command, timeout=12.0)
        if launched.returncode != 0:
            pytest.fail(f"could not start exact monitor service: {launched.stderr[-1200:]}")

        pre_path = _wait_for_receipt(control, "pre-running.json")
        pre = json.loads(pre_path.read_text(encoding="utf-8"))
        durable = supervisor._sandbox_execution_get(attempt["id"])
        marker = Path(durable["workspace_root_path"]) / _PAYLOAD_MARKER if durable else None
        git_marker = (
            Path(durable["workspace_root_path"]) / _GIT_METADATA_MARKER if durable else None
        )
        assert durable is not None and durable["phase"] == "launched"
        assert pre["phase"] == "launched"
        assert pre["monitor_pid"] == pre["wrapper_main_pid"]
        assert pre["payload_marker_present"] is False
        assert pre["git_metadata_marker_present"] is False
        assert pre["source_git_pointer_regular_file"] is True
        assert pre["baseline_git_metadata_absent"] is True
        assert pre["workspace_git_metadata_absent"] is True
        if apparmor_profile:
            profile_stack = (
                str(pre["launch_driver_apparmor_identity"]).partition(" (")[0].split("//&")
            )
            assert apparmor_profile in profile_stack
        assert marker is not None and not marker.exists()
        assert git_marker is not None and not git_marker.exists()

        (control / "continue-running.json").write_text("release-transition\n", encoding="ascii")
        post_path = _wait_for_receipt(control, "post-running.json")
        post = json.loads(post_path.read_text(encoding="utf-8"))
        durable = supervisor._sandbox_execution_get(attempt["id"])
        assert post["phase"] == "running"
        assert post["payload_marker_present_before_gate"] is False
        assert post["git_metadata_marker_present_before_gate"] is False
        assert durable is not None and durable["phase"] == "running"
        assert marker is not None
        assert not marker.exists()
        assert git_marker is not None and not git_marker.exists()
        (control / "running-observed.json").write_text("running-state-verified\n", encoding="ascii")
        result_path = _wait_for_receipt(control, "result.json", timeout=20.0)
        result = json.loads(result_path.read_text(encoding="utf-8"))
        durable = supervisor._sandbox_execution_get(attempt["id"])
        if terminate_before_gate:
            assert set(result) == {
                "phase",
                "stop_outcome",
                "stop_journal_phase",
                "stop_monitor_phase",
                "stop_requested",
                "stop_cleanup_verified",
                "runc_client_returncode",
                "runc_state_deleted",
                "payload_marker_absent",
                "git_marker_absent",
                "cleanup_verified_written",
            }
            assert result["stop_outcome"] == "ok"
            assert result["stop_journal_phase"] == "stopping"
            assert result["stop_monitor_phase"] in {"stopping", "exited"}
            assert result["stop_requested"] is True
            assert result["stop_cleanup_verified"] is False
            assert result["runc_state_deleted"] is True
            assert result["payload_marker_absent"] is True
            assert result["git_marker_absent"] is True
            assert result["cleanup_verified_written"] is False
            assert marker is not None and not marker.exists()
            assert git_marker is not None and not git_marker.exists()
        else:
            _wait_for_path(marker, control / "error.json", timeout=10.0)
            assert (
                marker is not None
                and marker.read_text(encoding="ascii") == "candidate-payload-ran\n"
            )
            assert (
                git_marker is not None
                and git_marker.read_text(encoding="ascii") == "host-git-metadata-not-visible\n"
            )
            assert set(result) == {
                "phase",
                "payload_marker",
                "git_metadata_absent_inside_worker",
                "runc_client_returncode",
                "runc_state_deleted",
                "change_set_paths",
                "change_set_actions",
                "change_set_digest",
                "undeclared_write_rejected",
                "cleanup_verified_written",
            }
            assert result["payload_marker"] == "candidate-payload-ran\n"
            assert result["git_metadata_absent_inside_worker"] is True
            assert result["runc_client_returncode"] == 0
            assert result["runc_state_deleted"] is True
            assert result["change_set_paths"] == sorted([_PAYLOAD_MARKER, _GIT_METADATA_MARKER])
            assert result["change_set_actions"] == ["create", "create"]
            assert re.fullmatch(r"[0-9a-f]{64}", result["change_set_digest"])
            assert result["undeclared_write_rejected"] is True
            assert result["cleanup_verified_written"] is False
        assert result["phase"] == "exited"
        assert durable is not None and durable["phase"] == "exited"
        worktree = Path(attempt["worktree"])
        binding = supervisor._sandbox_execution_restore_workspace_binding(
            attempt["id"], attempt["claim_token"]
        )
        source_after = copy_snapshot(worktree, control / "registered-source-after")
        assert source_after.manifest == binding["baseline"].manifest
        assert not _entry_is_present(worktree / _PAYLOAD_MARKER)
        assert not _entry_is_present(worktree / _GIT_METADATA_MARKER)
        with pytest.raises(SupervisorError) as unverified_result:
            supervisor._sandbox_execution_capture_result_candidate(
                attempt["id"], attempt["claim_token"]
            )
        assert unverified_result.value.code == "sandbox_result_evidence_unverified"
        durable_after_rejection = supervisor._sandbox_execution_get(attempt["id"])
        assert durable_after_rejection is not None
        assert durable_after_rejection["phase"] == "exited"
        assert durable_after_rejection["result_candidate"] is None
    finally:
        driver_and_slice_safe = _stop_attempted_units_and_check_quiescence(
            systemctl,
            service_unit,
            service_start_attempted,
            slice_unit,
            slice_start_attempted,
        )
        monitor_safe = False
        if driver_and_slice_safe:
            monitor_safe = _stop_attempted_units_and_check_quiescence(
                systemctl,
                monitor_unit,
                monitor_start_attempted,
                None,
                False,
            )
        safe_to_remove = driver_and_slice_safe and monitor_safe
        if safe_to_remove:
            _remove_private_test_tree(run_root)
        else:
            pytest.fail(f"exact test units are not quiescent; preserving artifacts at {run_root}")


@pytest.mark.skipif(
    not _LIVE_ENABLED,
    reason="set ACP_RUN_SANDBOX_WORKER_LIFECYCLE=1 on a disposable supported Linux host",
)
def test_live_production_launch_driver_runs_exact_pinned_runc_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use the production launcher and reaper across completion and failure paths."""

    source_root = Path(__file__).resolve().parents[1]
    concurrent_control = _live_concurrent_control()
    cross_attempt_probes = os.environ.get("ACP_LIVE_CROSS_ATTEMPT_PROBES") == "1"
    if cross_attempt_probes and concurrent_control is None:
        pytest.fail("cross-attempt probes require the concurrent live parent harness")
    shared_repo_value = os.environ.get("ACP_LIVE_SHARED_REPO", "")
    shared_rootfs_value = os.environ.get("ACP_LIVE_SHARED_ROOTFS", "")
    shared_port_range_value = os.environ.get("ACP_LIVE_SHARED_PORT_RANGE", "")
    if cross_attempt_probes and (not shared_repo_value or not shared_rootfs_value):
        pytest.fail("cross-attempt probes require the shared fixture repo and rootfs")
    shared_port_range: tuple[int, int] | None = None
    if cross_attempt_probes:
        try:
            shared_port_start, shared_port_end = (
                int(part) for part in shared_port_range_value.split(",", maxsplit=1)
            )
        except (ValueError, TypeError):
            pytest.fail("cross-attempt probes require a two-port shared runtime range")
        if not 1024 <= shared_port_start < shared_port_end <= 65535:
            pytest.fail("cross-attempt shared runtime range is invalid")
        shared_port_range = (shared_port_start, shared_port_end)
    from agent_control_plane.supervisor import sandbox_launch_driver_service as launch_service

    if Path(launch_service.__file__).resolve().parents[2] != (source_root / "src").resolve():
        pytest.fail("live producer did not import the package from this exact source checkout")

    original_systemd_environment = launch_service._trusted_systemd_command_environment

    def source_pinned_systemd_environment() -> dict[str, str]:
        environment = original_systemd_environment()
        environment["PYTHONPATH"] = str(source_root / "src")
        return environment

    monkeypatch.setattr(
        launch_service,
        "_trusted_systemd_command_environment",
        source_pinned_systemd_environment,
    )
    if not sys.platform.startswith("linux") or os.geteuid() == 0:
        pytest.fail("live launch-driver proof requires an unprivileged Linux user")
    if not source_root.is_relative_to(Path("/tmp")):
        pytest.fail("run this opt-in proof from a disposable checkout beneath /tmp")
    if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        pytest.fail("live launch-driver proof requires unified cgroup v2")
    controllers = set(Path("/sys/fs/cgroup/cgroup.controllers").read_text().split())
    if not {"cpu", "memory", "pids"}.issubset(controllers):
        pytest.fail("cpu, memory, and pids cgroup v2 controllers are required")
    if os.environ.get("ACP_OCI_TEST_RUNC_VERSION") != _SUPPORTED_RUNC_VERSION:
        pytest.fail("set ACP_OCI_TEST_RUNC_VERSION=1.5.2 for this exact live proof")
    environment = sandbox_attestation._trusted_systemd_command_environment()
    if not (Path(environment["XDG_RUNTIME_DIR"]) / "bus").is_socket():
        pytest.fail("private systemd user-manager socket is unavailable")
    systemctl = str(sandbox_attestation._trusted_systemctl_executable())
    if _systemd_command([systemctl, "--user", "show-environment"]).returncode != 0:
        pytest.fail("active systemd user manager is required")
    if " - cgroup2 " not in Path("/proc/self/mountinfo").read_text(encoding="ascii"):
        pytest.fail("current host does not expose unified cgroup v2")

    isolation_probes = os.environ.get("ACP_LIVE_ISOLATION_PROBES") == "1"
    import_result_after_cleanup = os.environ.get("ACP_LIVE_IMPORT_RESULT_AFTER_CLEANUP") == "1"
    supervised_run_worker = os.environ.get("ACP_LIVE_SUPERVISED_RUN_WORKER") == "1"
    provider_proxy_uds = os.environ.get("ACP_LIVE_PROVIDER_PROXY_UDS") == "1"
    provider_proxy_cancel = os.environ.get("ACP_LIVE_PROVIDER_PROXY_CANCEL") == "1"
    worker_canary_fd4 = os.environ.get("ACP_LIVE_WORKER_CANARY_FD4") == "1"
    test_worker_canary = (
        b"ACP-test-worker-canary-" + os.urandom(24).hex().encode("ascii")
        if worker_canary_fd4
        else None
    )
    expected_worker_canary_result = (
        f"worker-canary-fd4-sha256={hashlib.sha256(test_worker_canary).hexdigest()}\n"
        if test_worker_canary is not None
        else None
    )
    if worker_canary_fd4 and (
        os.environ.get("ACP_TEST_ALLOW_WORKER_CANARY") != "1"
        or supervised_run_worker != import_result_after_cleanup
        or provider_proxy_uds
        or provider_proxy_cancel
        or cross_attempt_probes
        or isolation_probes
        or os.environ.get("ACP_LIVE_CRASH_AFTER_EXIT_BEFORE_CLEANUP_REPORT") == "1"
    ):
        pytest.fail(
            "FD4 canary proof requires ACP_TEST_ALLOW_WORKER_CANARY=1 and either the isolated "
            "production no-model launch-driver mode or the supervised run_worker plus "
            "cleanup-verified import mode"
        )
    crash_after_exit_before_cleanup_report = (
        os.environ.get("ACP_LIVE_CRASH_AFTER_EXIT_BEFORE_CLEANUP_REPORT") == "1"
    )
    user_manager_restart_after_driver_crash = (
        os.environ.get("ACP_LIVE_USER_MANAGER_RESTART_AFTER_DRIVER_CRASH") == "1"
    )
    user_manager_restart_target: tuple[Path, str, str, str] | None = None
    user_manager_restart_baseline: dict[str, tuple[str, str, str]] | None = None
    user_manager_restart_baseline_processes: dict[str, frozenset[int]] | None = None
    user_manager_restart_busctl: Path | None = None
    user_manager_restart_uncertain = False
    if user_manager_restart_after_driver_crash:
        expected_host = os.environ.get("ACP_LIVE_USER_MANAGER_RESTART_DISPOSABLE_HOST", "")
        if not expected_host or expected_host != socket.gethostname():
            pytest.fail(
                "set ACP_LIVE_USER_MANAGER_RESTART_DISPOSABLE_HOST to this exact disposable VM hostname"
            )
        if (
            os.environ.get("ACP_LIVE_USER_MANAGER_RESTART_ACK")
            != "RESTART_ONLY_THIS_DISPOSABLE_GUEST"
        ):
            pytest.fail(
                "user-manager restart requires ACP_LIVE_USER_MANAGER_RESTART_ACK="
                "RESTART_ONLY_THIS_DISPOSABLE_GUEST"
            )
        detect_virt = shutil.which("systemd-detect-virt", path=environment["PATH"])
        if (
            detect_virt is None
            or _systemd_command(
                [str(Path(detect_virt).resolve(strict=True)), "--quiet", "--vm"]
            ).returncode
            != 0
        ):
            pytest.fail("user-manager restart is restricted to a virtual machine")
        os_release = {}
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                parsed_value = shlex.split(value)
                if len(parsed_value) == 1:
                    os_release[key] = parsed_value[0]
        if os_release.get("ID") != "debian" or os_release.get("VERSION_ID") != "12":
            pytest.fail("user-manager restart is restricted to the Debian 12 disposable Lima VM")
        sudo = shutil.which("sudo", path=environment["PATH"])
        if sudo is None:
            pytest.fail("user-manager restart requires passwordless sudo on its disposable VM")
        sudo_path = Path(sudo).resolve(strict=True)
        sudo_preflight = _systemd_command([str(sudo_path), "-n", "true"])
        if sudo_preflight.returncode != 0:
            pytest.fail("user-manager restart requires passwordless sudo on its disposable VM")
        busctl = shutil.which("busctl", path=environment["PATH"])
        if busctl is None:
            pytest.fail("user-manager restart requires busctl to verify the restarted user bus")
        user_manager_restart_busctl = Path(busctl).resolve(strict=True)
        initial_bus = _systemd_command(
            [str(user_manager_restart_busctl), "--user", "--no-pager", "status"], timeout=5
        )
        if initial_bus.returncode != 0:
            pytest.fail("the exact test user's D-Bus service could not be activated safely")
        systemd_escape = shutil.which("systemd-escape", path=environment["PATH"])
        if systemd_escape is None:
            pytest.fail("user-manager restart requires systemd-escape to verify the CIDATA alias")
        user_manager_unit = f"user@{os.getuid()}.service"
        manager_pid_result = _systemd_command(
            [
                str(sudo_path),
                "-n",
                systemctl,
                "show",
                user_manager_unit,
                "-p",
                "MainPID",
                "--value",
            ]
        )
        manager_pid = manager_pid_result.stdout.strip()
        if manager_pid_result.returncode != 0 or not manager_pid.isdecimal() or manager_pid == "0":
            pytest.fail("the exact test user's systemd manager service is not active")
        manager_cgroup_result = _systemd_command(
            [
                str(sudo_path),
                "-n",
                systemctl,
                "show",
                user_manager_unit,
                "-p",
                "ControlGroup",
                "--value",
            ]
        )
        manager_cgroup = manager_cgroup_result.stdout.strip()
        if manager_cgroup_result.returncode != 0 or not manager_cgroup:
            pytest.fail("the exact test user's manager cgroup is unavailable")
        try:
            cidata_uuid_device_unit = _user_manager_cidata_uuid_device_unit(
                str(Path(systemd_escape).resolve(strict=True)),
                cidata_label_path=Path("/dev/disk/by-label/cidata"),
                uuid_directory=Path("/dev/disk/by-uuid"),
                expected_device_path=Path("/dev/vdb"),
            )
        except (OSError, RuntimeError) as error:
            pytest.fail(f"refusing user-manager restart without exact CIDATA identity: {error}")
        user_manager_restart_baseline = _user_manager_restart_expected_inventory(
            os.getuid(), cidata_uuid_device_unit=cidata_uuid_device_unit
        )
        try:
            actual_inventory = _user_manager_unit_inventory(systemctl)
        except RuntimeError as error:
            pytest.fail(str(error))
        if not _user_manager_restart_inventory_is_allowlisted(
            actual_inventory, user_manager_restart_baseline
        ):
            pytest.fail(
                "refusing user-manager restart because the full baseline unit inventory does not "
                "match the explicit disposable-VM allowlist; "
                f"unexpected={actual_inventory!r}"
            )
        if actual_inventory.get(_MONITOR_SLICE_UNIT) is not None and actual_inventory.get(
            "user.slice"
        ) != ("loaded", "active", "active"):
            pytest.fail(
                "refusing user-manager restart because user-acp.slice lacks its exact parent"
            )
        parent_slices = {"user.slice", _MONITOR_SLICE_UNIT}
        for parent_slice in parent_slices & set(actual_inventory):
            if not _user_manager_parent_slice_state_is_safe(
                parent_slice,
                actual_inventory[parent_slice],
                manager_cgroup,
                allow_active=True,
            ):
                pytest.fail(
                    f"refusing user-manager restart with unsafe parent slice {parent_slice}"
                )
        user_manager_restart_baseline = {
            unit: state for unit, state in actual_inventory.items() if unit not in parent_slices
        }
        try:
            user_manager_restart_baseline_processes = _assert_user_manager_process_inventory(
                manager_cgroup=manager_cgroup,
                manager_pid=manager_pid,
            )
        except (AssertionError, OSError, RuntimeError) as error:
            pytest.fail(
                f"refusing user-manager restart because baseline cgroup audit failed: {error}"
            )
        user_manager_restart_target = (sudo_path, user_manager_unit, manager_pid, manager_cgroup)
        monitor_crash_modes = (
            os.environ.get("ACP_LIVE_CRASH_AFTER_MONITOR_ACCEPTANCE") == "1",
            os.environ.get("ACP_LIVE_CRASH_BEFORE_MONITOR_START") == "1",
        )
        if sum(monitor_crash_modes) != 1:
            pytest.fail(
                "user-manager restart requires exactly one monitor-acceptance or pre-monitor crash mode"
            )
        if any(
            os.environ.get(name) == "1"
            for name in (
                "ACP_LIVE_CANCEL_AFTER_START",
                "ACP_LIVE_TIMEOUT_AFTER_START",
                "ACP_LIVE_LEASE_EXPIRY_AFTER_STOP",
                "ACP_LIVE_CRASH_AFTER_MANAGER_ACCEPTANCE",
                "ACP_LIVE_USER_MANAGER_REEXEC_AFTER_DRIVER_CRASH",
            )
        ):
            pytest.fail("user-manager restart mode cannot be combined with another live mode")
    coding_task = isolation_probes or import_result_after_cleanup
    coding_source = "printf 'coding-task-pass\\n'"
    coding_script_name = "sandbox-coding-task.sh"
    coding_test_output_name = "sandbox-coding-task.test"
    if isolation_probes:
        if os.getpid() <= _CONTAINER_PIDS_LIMIT:
            pytest.fail("host controller PID must exceed the worker PID limit for this probe")
        if os.environ.get("ACP_LIVE_ISOLATION_DISPOSABLE_HOST") != socket.gethostname():
            pytest.fail(
                "set ACP_LIVE_ISOLATION_DISPOSABLE_HOST to this exact disposable VM hostname"
            )
        root_preflight = subprocess.run(
            ["sudo", "-n", "true"], capture_output=True, text=True, timeout=10
        )
        if root_preflight.returncode != 0:
            pytest.fail("isolation sentinel proof requires passwordless sudo on its disposable VM")
        if not stat.S_ISDIR(Path("/etc").lstat().st_mode):
            pytest.fail("isolation sentinel proof requires a real /etc directory")
        if not stat.S_ISDIR(Path("/usr/local/share").lstat().st_mode):
            pytest.fail("isolation sentinel proof requires the existing /usr/local/share directory")

    runc_path = Path(os.environ.get("ACP_OCI_TEST_RUNC", "/usr/bin/runc"))
    busybox_path = Path(os.environ.get("ACP_OCI_TEST_BUSYBOX", "/usr/bin/busybox"))
    run_root = Path(tempfile.mkdtemp(prefix="acp-live-launch-driver-", dir="/tmp"))
    isolation_token = os.urandom(12).hex()
    isolation_secret = f"synthetic ACP containment sentinel {isolation_token}".encode("ascii")
    isolation_sentinels: dict[str, tuple[Path, bytes, tuple[int, int], bool]] = {}
    isolation_sentinel_candidates: list[tuple[Path, bytes, bool]] = []
    isolation_write_probes: list[Path] = []
    isolation_created_directories: list[tuple[Path, tuple[int, int]]] = []
    isolation_sibling_root: Path | None = None
    isolation_sibling_identity: tuple[int, int] | None = None
    isolation_socket: socket.socket | None = None
    isolation_socket_path: Path | None = None
    isolation_socket_identity: tuple[int, int] | None = None
    isolation_tmp_scratch_path = Path("/tmp") / f"acp-live-worker-tmp-{isolation_token}"
    isolation_home_scratch_path = Path("/home/agent") / f"acp-live-worker-home-{isolation_token}"
    isolation_scratch_content = f"acp-live-scratch-{isolation_token}".encode("ascii")
    isolation_link_name = f".acp-live-path-escape-{isolation_token}"
    isolation_script_name = f".acp-live-isolation-probe-{isolation_token}.sh"
    rootfs_source = run_root / "rootfs-source"
    service_log_path = run_root / "launch-driver-service.log"
    service_unit: str | None = None
    monitor_unit: str | None = None
    slice_unit: str | None = None
    service_start_attempted = False
    monitor_start_attempted = False
    slice_start_attempted = False
    safe_to_remove = False
    provider_probe_release: Path | None = None
    provider_probe_result: Path | None = None
    provider_probe_open: Path | None = None
    provider_probe_release_error: OSError | None = None
    child_processes: list[multiprocessing.Process] = []
    host_process_sentinel: subprocess.Popen[bytes] | None = None
    try:
        run_root.chmod(0o700)
        if isolation_probes:
            host_process_sentinel = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(180)"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
            if (
                host_process_sentinel.poll() is not None
                or host_process_sentinel.pid <= _CONTAINER_PIDS_LIMIT
            ):
                pytest.fail(
                    "synthetic host process sentinel is not running above the worker PID limit"
                )
        if cross_attempt_probes:
            rootfs_source = Path(shared_rootfs_value).resolve(strict=True)
            repo = Path(shared_repo_value).resolve(strict=True)
            if (
                not rootfs_source.is_relative_to(Path("/tmp"))
                or not repo.is_relative_to(Path("/tmp"))
                or not rootfs_source.is_dir()
                or rootfs_source.is_symlink()
                or not (repo / ".git").is_dir()
                or repo.is_symlink()
                or repo.stat().st_uid != os.geteuid()
                or stat.S_IMODE(repo.stat().st_mode) != 0o700
            ):
                pytest.fail("shared concurrent fixture paths are not private disposable inputs")
            assert shared_port_range is not None
            runtime_test_port = shared_port_range[0]
        else:
            rootfs_source.mkdir(mode=0o755)
            rootfs_directories = [
                "bin",
                "dev",
                "etc",
                "home/agent",
                "proc",
                "run",
                "tmp",
                "workspace",
            ]
            if provider_proxy_uds:
                rootfs_directories.append("run/acp")
            for directory in rootfs_directories:
                (rootfs_source / directory).mkdir(parents=True, exist_ok=True, mode=0o755)
            _busybox_version, busybox_applets = _copy_busybox_closure(busybox_path, rootfs_source)
            if provider_proxy_uds and not crash_after_exit_before_cleanup_report:
                compiler = shutil.which("cc")
                if compiler is None:
                    pytest.fail("provider UDS proof requires the guest C compiler")
                provider_source_path = run_root / "provider-proxy-probe.c"
                provider_client_path = rootfs_source / "bin" / "provider-proxy-probe"
                provider_source_path.write_text(_PROVIDER_PROXY_PROBE_SOURCE, encoding="ascii")
                compile_result = subprocess.run(
                    [
                        compiler,
                        "-static",
                        "-O2",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        *(["-DACP_LIVE_PROVIDER_CANCEL=1"] if provider_proxy_cancel else []),
                        str(provider_source_path),
                        "-o",
                        str(provider_client_path),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if compile_result.returncode != 0:
                    pytest.fail(
                        "provider UDS guest probe failed to compile: "
                        f"{compile_result.stderr[-4000:]}"
                    )
                provider_client_path.chmod(0o755)
            if worker_canary_fd4:
                compiler = shutil.which("cc")
                if compiler is None:
                    pytest.fail("worker canary FD4 proof requires the guest C compiler")
                canary_source_path = run_root / "worker-canary-fd4-probe.c"
                canary_client_path = rootfs_source / "bin" / "worker-canary-fd4-probe"
                canary_source_path.write_text(_WORKER_CANARY_FD4_PROBE_SOURCE, encoding="ascii")
                compile_result = subprocess.run(
                    [
                        compiler,
                        "-static",
                        "-O2",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        str(canary_source_path),
                        "-o",
                        str(canary_client_path),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if compile_result.returncode != 0:
                    pytest.fail(
                        "worker canary FD4 guest probe failed to compile: "
                        f"{compile_result.stderr[-4000:]}"
                    )
                canary_client_path.chmod(0o755)
            if isolation_probes and "rm" not in busybox_applets:
                pytest.fail("trusted BusyBox lacks rm for the temporary workspace symlink probe")
            repo_root = run_root / "repo"
            repo_root.mkdir(mode=0o700)
            repo = init_repo(repo_root)
        if isolation_probes:
            host_home = Path.home().resolve(strict=True)
            home_config = host_home / ".config"
            home_ssh = host_home / ".ssh"
            for directory in (home_config, home_ssh):
                if not directory.exists():
                    directory.mkdir(mode=0o700)
                    info = directory.lstat()
                    isolation_created_directories.append((directory, (info.st_dev, info.st_ino)))
                elif not stat.S_ISDIR(directory.lstat().st_mode):
                    pytest.fail(f"isolation sentinel parent is not a directory: {directory}")
            # The worker's claimed attempt is created under repo/.acp/worktrees;
            # put this real sibling there so the probe covers the actual managed root.
            isolation_sibling_root = (
                repo / ".acp" / "worktrees" / f"acp-live-sibling-{isolation_token}"
            )
            _ensure_private_fixture_directory(isolation_sibling_root.parent)
            if os.path.lexists(isolation_sibling_root):
                pytest.fail("unique sibling-worktree sentinel directory already exists")
            unrelated_root = run_root / "unrelated-project"
            unrelated_root.mkdir(mode=0o700)
            isolation_socket_path = run_root / "host-only-control.sock"
            if os.path.lexists(isolation_socket_path):
                pytest.fail("unique host-only socket path already exists")
            isolation_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            isolation_socket.bind(str(isolation_socket_path))
            isolation_socket.listen(1)
            socket_info = isolation_socket_path.lstat()
            isolation_socket_identity = (socket_info.st_dev, socket_info.st_ino)

            sentinel_paths = {
                "host_etc": Path("/etc") / f"acp-live-{isolation_token}.sentinel",
                "host_usr": Path("/usr/local/share") / f"acp-live-{isolation_token}.sentinel",
                "host_home": host_home / f"acp-live-{isolation_token}.sentinel",
                "host_config": home_config / f"acp-live-{isolation_token}.sentinel",
                "host_credential": home_ssh / f"acp-live-{isolation_token}.key",
                "host_tmp": run_root / "host-temp-sentinel",
                "harness_checkout": source_root / f".acp-live-{isolation_token}-harness",
                "task_base_checkout": repo / f".acp-live-{isolation_token}-base",
                "sibling_worktree": isolation_sibling_root / f".acp-live-{isolation_token}-sibling",
                "unrelated_project": unrelated_root / "project-sentinel",
            }
            privileged_sentinels = {"host_etc", "host_usr"}
            for name, path in sentinel_paths.items():
                sidecar = Path(f"{path}.write-probe")
                if os.path.lexists(sidecar):
                    pytest.fail("unique isolation write-probe path already exists")
                isolation_write_probes.append(sidecar)
                if name == "sibling_worktree":
                    continue
                privileged = name in privileged_sentinels
                isolation_sentinel_candidates.append((path, isolation_secret, privileged))
                identity = _live_isolation_sentinel(
                    path,
                    isolation_secret,
                    privileged=privileged,
                )
                isolation_sentinels[name] = (
                    path,
                    isolation_secret,
                    identity,
                    privileged,
                )
            if os.path.lexists(isolation_tmp_scratch_path) or os.path.lexists(
                isolation_home_scratch_path
            ):
                pytest.fail("unique isolation scratch path already exists")
            probe_lines = [
                "set -eu",
                "printf 'production-driver-started\\n' > /workspace/launch-driver-started",
                "exec 2>> /workspace/launch-driver-started",
            ]
            for label, command in (
                ("toolchain", "/bin/busybox test -x /bin/busybox"),
                ("workspace-writable", "/bin/busybox test -w /workspace"),
                ("workspace-has-no-git", "/bin/busybox test ! -e /workspace/.git"),
                ("workspace-has-no-git-head", "/bin/busybox test ! -e /workspace/.git/HEAD"),
                ("host-usr-absent", "/bin/busybox test ! -e /usr"),
                (
                    "rootfs-read-only",
                    "if /bin/busybox touch "
                    f"/etc/acp-live-{isolation_token}-write-probe 2>/dev/null; then exit 67; fi",
                ),
                (
                    "tmp-is-tmpfs",
                    "/bin/busybox grep -F ' /tmp ' /proc/self/mountinfo | "
                    "/bin/busybox grep -F ' - tmpfs tmpfs ' >/dev/null",
                ),
                (
                    "agent-home-is-tmpfs",
                    "/bin/busybox grep -F ' /home/agent ' /proc/self/mountinfo | "
                    "/bin/busybox grep -F ' - tmpfs tmpfs ' >/dev/null",
                ),
            ):
                probe_lines.extend(
                    (
                        command,
                        f"/bin/busybox printf 'probe-ok:{label}\\n' "
                        ">> /workspace/launch-driver-started",
                    )
                )
            for name, path in sentinel_paths.items():
                quoted_path = shlex.quote(str(path))
                quoted_write_probe = shlex.quote(f"{path}.write-probe")
                probe_lines.extend(
                    (
                        f"if /bin/busybox test -e {quoted_path}; then exit 61; fi",
                        f"if /bin/busybox test -r {quoted_path}; then exit 62; fi",
                        f"if /bin/busybox touch {quoted_write_probe} 2>/dev/null; then exit 63; fi",
                        "/bin/busybox printf "
                        f"'probe-ok:sentinel-{name}\\n' >> /workspace/launch-driver-started",
                    )
                )
            if coding_task:
                probe_lines.extend(
                    (
                        "/bin/busybox printf %s "
                        f"{shlex.quote(coding_source)} > /workspace/{coding_script_name}",
                        f"coding_output=$(/bin/busybox sh /workspace/{coding_script_name})",
                        "test \"$coding_output\" = 'coding-task-pass'",
                        f"/bin/busybox printf '%s\\n' \"$coding_output\" > "
                        f"/workspace/{coding_test_output_name}",
                        "/bin/busybox printf 'probe-ok:coding-task\\n' "
                        ">> /workspace/launch-driver-started",
                    )
                )
            escape_link = f"/workspace/{isolation_link_name}"
            quoted_escape_link = shlex.quote(escape_link)
            quoted_canonical_escape = shlex.quote(
                "/workspace/../../" + str(isolation_sentinels["host_home"][0]).lstrip("/")
            )
            quoted_host_socket = shlex.quote(str(isolation_socket_path))
            quoted_systemd_socket = shlex.quote(str(Path(environment["XDG_RUNTIME_DIR"]) / "bus"))
            if host_process_sentinel is None or host_process_sentinel.poll() is not None:
                pytest.fail("synthetic host process sentinel exited before the worker probe")
            probe_lines.extend(
                (
                    "/bin/busybox ln -s "
                    f"{shlex.quote(str(isolation_sentinels['host_config'][0]))} "
                    f"{shlex.quote(f'/workspace/{isolation_link_name}')}",
                    f"/bin/busybox test -L {quoted_escape_link}",
                    f"if /bin/busybox cat {quoted_escape_link} >/dev/null 2>&1; then exit 64; fi",
                    f"/bin/busybox rm {quoted_escape_link}",
                    "/bin/busybox printf 'probe-ok:workspace-symlink-escape\\n' "
                    ">> /workspace/launch-driver-started",
                    "if /bin/busybox cat "
                    f"{quoted_canonical_escape} >/dev/null 2>&1; then exit 65; fi",
                    "/bin/busybox printf 'probe-ok:canonical-path-escape\\n' "
                    ">> /workspace/launch-driver-started",
                    "/bin/busybox test ! -e " + shlex.quote(f"/proc/{os.getpid()}"),
                    f"/bin/busybox test ! -e /proc/{host_process_sentinel.pid}",
                    f"/bin/busybox test ! -S {quoted_host_socket}",
                    f"/bin/busybox test ! -S {quoted_systemd_socket}",
                    "/bin/busybox printf 'probe-ok:host-process-visibility-and-sockets\\n' "
                    ">> /workspace/launch-driver-started",
                    "/bin/busybox printf "
                    f"{shlex.quote(isolation_scratch_content.decode('ascii'))} > "
                    f"{shlex.quote(f'/tmp/{isolation_tmp_scratch_path.name}')}",
                    "/bin/busybox printf "
                    f"{shlex.quote(isolation_scratch_content.decode('ascii'))} > "
                    f"{shlex.quote(f'/home/agent/{isolation_home_scratch_path.name}')}",
                    "network_error=$(/bin/busybox nc -w 1 192.0.2.1 443 </dev/null 2>&1) || true",
                    "case \"$network_error\" in *'Operation not permitted'*|*'Permission denied'*) ;; *) exit 66 ;; esac",
                    "/bin/busybox printf 'probe-ok:direct-ip-denied\\n' "
                    ">> /workspace/launch-driver-started",
                    "/bin/busybox printf 'probe-ok:workspace-scratch\\n' "
                    ">> /workspace/launch-driver-started",
                    "printf 'production-driver-ran\\ncontainment-probes-passed\\n' "
                    "> /workspace/launch-driver-marker",
                )
            )
            (repo / isolation_script_name).write_text(
                "\n".join(probe_lines) + "\n", encoding="ascii"
            )
            subprocess.run(
                ["git", "-C", str(repo), "add", "--", isolation_script_name],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            subprocess.run(
                ["git", "-C", str(repo), "commit", "-m", "fixture: host-path isolation probe"],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "worktree",
                    "add",
                    "--detach",
                    str(isolation_sibling_root),
                    "HEAD",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            sibling_info = isolation_sibling_root.lstat()
            isolation_sibling_identity = (sibling_info.st_dev, sibling_info.st_ino)
            sibling_sentinel_path = sentinel_paths["sibling_worktree"]
            isolation_sentinel_candidates.append((sibling_sentinel_path, isolation_secret, False))
            sibling_identity = _live_isolation_sentinel(sibling_sentinel_path, isolation_secret)
            isolation_sentinels["sibling_worktree"] = (
                sibling_sentinel_path,
                isolation_secret,
                sibling_identity,
                False,
            )
        if os.environ.get("ACP_LIVE_CANCEL_AFTER_START") == "1":
            config_path = repo / "acp.toml"
            config_text = config_path.read_text(encoding="utf-8")
            if "lease_seconds = 60" in config_text:
                config_path.write_text(
                    config_text.replace("lease_seconds = 60", "lease_seconds = 10", 1),
                    encoding="utf-8",
                )
            elif not (cross_attempt_probes and "lease_seconds = 10" in config_text):
                pytest.fail("live fixture did not start with the expected test lease")
        _ensure_private_fixture_directory(repo / ".acp")
        _ensure_private_fixture_directory(repo / ".acp" / "sandbox-executions")
        if not cross_attempt_probes:
            rootfs_manifest = oci_worker.rootfs_tree_manifest(rootfs_source)
            runtime_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                runtime_probe.bind(("127.0.0.1", 0))
                runtime_test_port = runtime_probe.getsockname()[1]
            finally:
                runtime_probe.close()
            with (repo / "acp.toml").open("a", encoding="utf-8") as stream:
                stream.write(
                    "\n[sandbox.oci]\n"
                    f"runc_executable = {json.dumps(str(runc_path.resolve(strict=True)))}\n"
                    f"runc_version = {json.dumps(_SUPPORTED_RUNC_VERSION)}\n"
                    f"rootfs_path = {json.dumps(str(rootfs_source.resolve(strict=True)))}\n"
                    f"rootfs_sha256 = {json.dumps(rootfs_manifest['rootfs_sha256'])}\n"
                    f"rootfs_closure_sha256 = {json.dumps(rootfs_manifest['closure_sha256'])}\n"
                    "\n[runtime.ports]\n"
                    f"LAUNCH_DRIVER_TEST_PORT = [{runtime_test_port}, {runtime_test_port}]\n"
                )
        supervisor = GitSupervisor(repo)
        live_marker_resource = "launch-driver-marker"
        live_started_resource = "launch-driver-started"
        if cross_attempt_probes and concurrent_control is not None:
            live_marker_resource = f"{live_marker_resource}-{concurrent_control[1]}"
            live_started_resource = f"{live_started_resource}-{concurrent_control[1]}"
        runner_name = "sandbox-launch-driver-test"
        if cross_attempt_probes and concurrent_control is not None:
            runner_name = f"{runner_name}-{concurrent_control[1]}"
        runner = supervisor.enroll_runner(runner_name, "worker")
        provider_probe_resources = (
            (
                "provider-probe-result",
                "provider-probe-release",
            )
            + (("provider-probe-open",) if provider_proxy_cancel else ())
            if provider_proxy_uds
            else ()
        )
        worker_canary_resources = ("worker-canary-fd4-result",) if worker_canary_fd4 else ()
        task = make_task(
            supervisor,
            live_marker_resource,
            live_started_resource,
            *provider_probe_resources,
            *worker_canary_resources,
            *((coding_script_name, coding_test_output_name) if coding_task else ()),
            title=(
                f"launch-driver producer test {concurrent_control[1]}"
                if cross_attempt_probes and concurrent_control is not None
                else "launch-driver producer test"
            ),
        )
        attempt = supervisor.claim(
            task["id"],
            runner_name,
            credential=runner["credential"],
        )
        initial_lease_expires_at = attempt["lease_expires_at"]
        rootfs_pin = supervisor.config.oci_rootfs_pin
        runc_pin = supervisor.config.oci_runc_executable
        if (
            rootfs_pin is None
            or runc_pin is None
            or supervisor.config.oci_runc_version != _SUPPORTED_RUNC_VERSION
        ):
            pytest.fail("test config did not pin the exact rootfs and runc identities")
        source_worktree = Path(attempt["worktree"])
        if isolation_probes:
            assert isolation_sibling_root is not None
            assert source_worktree.parent.resolve(
                strict=True
            ) == isolation_sibling_root.parent.resolve(strict=True)
            assert source_worktree != isolation_sibling_root
        execution: dict[str, Any] | None = None
        identity: tuple[str, int, str] | None = None
        provider_proxy_directory: Path | None = None
        provider_proxy_socket_path: Path | None = None

        cancel_after_start = os.environ.get("ACP_LIVE_CANCEL_AFTER_START") == "1"
        timeout_after_start = os.environ.get("ACP_LIVE_TIMEOUT_AFTER_START") == "1"
        concurrent_live_child = concurrent_control is not None
        lease_expiry_after_stop = os.environ.get("ACP_LIVE_LEASE_EXPIRY_AFTER_STOP") == "1"
        crash_after_manager_acceptance = (
            os.environ.get("ACP_LIVE_CRASH_AFTER_MANAGER_ACCEPTANCE") == "1"
        )
        crash_after_monitor_acceptance = (
            os.environ.get("ACP_LIVE_CRASH_AFTER_MONITOR_ACCEPTANCE") == "1"
        )
        crash_before_monitor_start = os.environ.get("ACP_LIVE_CRASH_BEFORE_MONITOR_START") == "1"
        driver_crash_phase = (
            "after_exit_before_cleanup_report"
            if crash_after_exit_before_cleanup_report
            else "before_monitor_start"
            if crash_before_monitor_start
            else "after_monitor_acceptance"
            if crash_after_monitor_acceptance
            else ""
        )
        user_manager_reexec_after_driver_crash = (
            os.environ.get("ACP_LIVE_USER_MANAGER_REEXEC_AFTER_DRIVER_CRASH") == "1"
        )
        if (
            sum(
                (
                    cancel_after_start,
                    timeout_after_start,
                    lease_expiry_after_stop,
                    crash_after_manager_acceptance,
                    crash_after_monitor_acceptance,
                    crash_before_monitor_start,
                    crash_after_exit_before_cleanup_report,
                )
            )
            > 1
        ):
            pytest.fail(
                "live cancel, timeout, lease-expiry, and crash-injection modes are mutually exclusive"
            )
        if user_manager_reexec_after_driver_crash and not (
            crash_after_monitor_acceptance or crash_before_monitor_start
        ):
            pytest.fail(
                "user-manager re-exec requires a monitor-acceptance or pre-monitor crash mode"
            )
        if user_manager_restart_after_driver_crash and not (
            crash_after_monitor_acceptance or crash_before_monitor_start
        ):
            pytest.fail(
                "user-manager restart requires a monitor-acceptance or pre-monitor crash mode"
            )
        if user_manager_reexec_after_driver_crash and user_manager_restart_after_driver_crash:
            pytest.fail("user-manager re-exec and restart modes are mutually exclusive")
        if import_result_after_cleanup and any(
            (
                cancel_after_start,
                timeout_after_start,
                lease_expiry_after_stop,
                crash_after_manager_acceptance,
                crash_after_monitor_acceptance,
                crash_before_monitor_start,
                crash_after_exit_before_cleanup_report,
                user_manager_reexec_after_driver_crash,
                user_manager_restart_after_driver_crash,
            )
        ):
            pytest.fail("live result import requires the natural-completion mode")
        crash_driver_service_before_receipt = (
            crash_after_manager_acceptance
            or crash_after_monitor_acceptance
            or crash_before_monitor_start
        )
        if crash_after_exit_before_cleanup_report and not provider_proxy_uds:
            pytest.fail(
                "post-wait cleanup-report crash proof requires ACP_LIVE_PROVIDER_PROXY_UDS=1"
            )
        if supervised_run_worker and (
            not import_result_after_cleanup
            or cancel_after_start
            or timeout_after_start
            or lease_expiry_after_stop
            or crash_driver_service_before_receipt
        ):
            pytest.fail(
                "supervisor run_worker proof requires successful coding-task completion and result import"
            )
        if isolation_probes and (
            cancel_after_start
            or timeout_after_start
            or lease_expiry_after_stop
            or crash_driver_service_before_receipt
        ):
            pytest.fail("live isolation probes require natural worker completion")
        if provider_proxy_uds and any(
            (
                cross_attempt_probes,
                isolation_probes,
                import_result_after_cleanup,
                supervised_run_worker,
                cancel_after_start and not provider_proxy_cancel,
                timeout_after_start,
                lease_expiry_after_stop,
                crash_driver_service_before_receipt,
                user_manager_reexec_after_driver_crash,
                user_manager_restart_after_driver_crash,
                concurrent_live_child,
            )
        ):
            pytest.fail("provider UDS live proof must run alone except for its cancellation mode")
        if provider_proxy_cancel and not (provider_proxy_uds and cancel_after_start):
            pytest.fail(
                "provider cancellation proof requires ACP_LIVE_PROVIDER_PROXY_UDS=1 and "
                "ACP_LIVE_CANCEL_AFTER_START=1"
            )
        if provider_proxy_uds and cancel_after_start and not provider_proxy_cancel:
            pytest.fail("provider UDS cancellation requires ACP_LIVE_PROVIDER_PROXY_CANCEL=1")
        monitor_acceptance_marker = run_root / "monitor-handoff-crash.json"
        payload_sleep_seconds = (
            120
            if concurrent_live_child
            else 30
            if cancel_after_start or timeout_after_start or lease_expiry_after_stop
            else 1
        )
        sandbox_timeout_seconds = 150 if concurrent_live_child else 1 if timeout_after_start else 30
        if isolation_probes:
            payload_command = ("/bin/busybox", "sh", f"/workspace/{isolation_script_name}")
        elif cross_attempt_probes:
            payload_command = (
                "/bin/busybox",
                "sh",
                f"/workspace/{_CROSS_ATTEMPT_PROBE_SCRIPT_NAME}",
            )
        elif provider_proxy_uds and crash_after_exit_before_cleanup_report:
            payload_command = (
                "/bin/busybox",
                "sh",
                "-c",
                "set -eu; "
                "printf 'production-driver-started\\n' > /workspace/launch-driver-started; "
                "while [ ! -e /workspace/provider-probe-release ]; do "
                "/bin/busybox sleep 0.1; done; "
                "printf 'production-driver-ran\\n' > /workspace/launch-driver-marker",
            )
        elif provider_proxy_uds:
            payload_command = (
                "/bin/busybox",
                "sh",
                "-c",
                "set -eu; "
                "printf 'production-driver-started\\n' > /workspace/launch-driver-started; "
                "/bin/provider-proxy-probe; "
                "printf 'production-driver-ran\\n' > /workspace/launch-driver-marker",
            )
        elif worker_canary_fd4 and coding_task:
            assert test_worker_canary is not None
            payload_command = (
                "/bin/busybox",
                "sh",
                "-c",
                "set -eu; "
                "/bin/busybox printf %s "
                f"{shlex.quote(coding_source)} > /workspace/{coding_script_name}; "
                f"coding_output=$(/bin/busybox sh /workspace/{coding_script_name}); "
                "test \"$coding_output\" = 'coding-task-pass'; "
                f"/bin/busybox printf '%s\\n' \"$coding_output\" > "
                f"/workspace/{coding_test_output_name}; "
                f"/bin/worker-canary-fd4-probe {len(test_worker_canary)}; "
                "/bin/busybox printf 'probe-ok:coding-task\\n' "
                ">> /workspace/launch-driver-started; "
                "printf 'production-driver-ran\\n' > /workspace/launch-driver-marker",
            )
        elif worker_canary_fd4:
            assert test_worker_canary is not None
            payload_command = (
                "/bin/worker-canary-fd4-probe",
                str(len(test_worker_canary)),
            )
        elif coding_task:
            payload_command = (
                "/bin/busybox",
                "sh",
                "-c",
                "set -eu; "
                "printf 'production-driver-started\\n' > /workspace/launch-driver-started; "
                "/bin/busybox printf %s "
                f"{shlex.quote(coding_source)} > /workspace/{coding_script_name}; "
                f"coding_output=$(/bin/busybox sh /workspace/{coding_script_name}); "
                "test \"$coding_output\" = 'coding-task-pass'; "
                f"/bin/busybox printf '%s\\n' \"$coding_output\" > "
                f"/workspace/{coding_test_output_name}; "
                "/bin/busybox printf 'probe-ok:coding-task\\n' "
                ">> /workspace/launch-driver-started; "
                "printf 'production-driver-ran\\n' > /workspace/launch-driver-marker",
            )
        else:
            payload_command = (
                "/bin/busybox",
                "sh",
                "-c",
                "printf 'production-driver-started\\n' > /workspace/launch-driver-started; "
                f"/bin/busybox sleep {payload_sleep_seconds} && "
                "printf 'production-driver-ran\\n' > /workspace/launch-driver-marker",
            )
        context = multiprocessing.get_context("spawn")
        producer_result_receiver, producer_result_sender = context.Pipe(duplex=False)
        producer_controller = context.Process(
            target=_start_launch_driver_then_crash_controller,
            args=(
                repo,
                attempt["id"],
                attempt["claim_token"],
                payload_command,
                _CONTAINER_MEMORY_BYTES,
                _CONTAINER_CPU_QUOTA_US,
                _CONTAINER_CPU_PERIOD_US,
                _CONTAINER_PIDS_LIMIT,
                sandbox_timeout_seconds,
                runner["credential"],
                service_log_path,
                producer_result_sender,
                crash_driver_service_before_receipt,
                monitor_acceptance_marker
                if (
                    crash_after_monitor_acceptance
                    or crash_before_monitor_start
                    or crash_after_exit_before_cleanup_report
                )
                else None,
                crash_before_monitor_start,
                concurrent_control[0] if concurrent_control is not None else None,
                concurrent_control[1] if concurrent_control is not None else None,
                run_root if concurrent_control is not None else None,
                source_worktree if concurrent_control is not None else None,
                driver_crash_phase,
                test_worker_canary,
            ),
        )
        producer_controller.start()
        child_processes.append(producer_controller)
        producer_result_sender.close()
        execution_deadline = time.monotonic() + 15
        while time.monotonic() < execution_deadline:
            execution = supervisor._sandbox_execution_get(attempt["id"])
            if execution is not None:
                break
            time.sleep(0.05)
        if execution is None:
            producer_detail = (
                producer_result_receiver.recv()
                if producer_result_receiver.poll()
                else "producer returned no diagnostic"
            )
            pytest.fail(
                "registered no-model path did not reserve the attempt; "
                f"producer result={producer_detail!r}; exit={producer_controller.exitcode}"
            )
        state_root = Path(execution["state_path"])
        identity = (attempt["id"], attempt["claim_token"], execution["execution_id"])
        service_unit = f"acp-launch-driver-{execution['execution_id']}.service"
        monitor_unit = sandbox_monitor_service_unit(*identity)
        slice_unit = sandbox_attempt_slice_unit(*identity)
        # The composition may already have reached systemd while this process
        # observed the reservation. Conservatively inspect all tuple-derived
        # units during teardown, including activation-uncertain failures.
        service_start_attempted = True
        slice_start_attempted = True
        monitor_start_attempted = True
        if provider_proxy_uds:
            bound_execution: dict[str, Any] | None = None
            bound_deadline = time.monotonic() + 20
            while time.monotonic() < bound_deadline:
                candidate = supervisor._sandbox_execution_get(attempt["id"])
                if (
                    candidate is not None
                    and candidate["execution_id"] == execution["execution_id"]
                    and candidate["phase"] == "running"
                    and candidate.get("workspace_root_path")
                    and candidate.get("cgroup_path")
                ):
                    bound_execution = candidate
                    break
                if candidate is not None and candidate["phase"] in {
                    "cleanup_reported",
                    "cleanup_verified",
                    "ambiguous",
                }:
                    break
                time.sleep(0.05)
            assert bound_execution is not None, (
                "production worker never reached a bound running row with a workspace and cgroup"
            )
            execution = bound_execution
            workspace_path_text = execution["workspace_root_path"]
            assert isinstance(workspace_path_text, str) and workspace_path_text, (
                "running execution row has no bound worker workspace"
            )
            workspace_root = Path(workspace_path_text)
            execution_root = Path(execution["bundle_path"]).parent
            canonical_execution_root = execution_root.resolve(strict=True)
            canonical_workspace = workspace_root.resolve(strict=True)
            assert workspace_root.is_absolute() and workspace_root == canonical_workspace, (
                "worker workspace path is not absolute and canonical"
            )
            assert canonical_workspace == canonical_execution_root / "workspace", (
                "worker workspace is not the exact private attempt execution child"
            )
            provider_proxy_directory, provider_proxy_socket_path = (
                sandbox_monitor_lifecycle.sandbox_provider_proxy_control_paths(
                    state_path=execution["state_path"],
                    expected_identity=identity,
                )
            )
            provider_probe_release = workspace_root / "provider-probe-release"
            provider_started_path = workspace_root / "launch-driver-started"
            probe_deadline = time.monotonic() + 15
            while (
                not _entry_is_present(provider_started_path) and time.monotonic() < probe_deadline
            ):
                time.sleep(0.05)
            assert _entry_is_present(provider_started_path), (
                "production worker did not reach its provider-proxy artifact gate"
            )
            if crash_after_exit_before_cleanup_report:
                current = supervisor._sandbox_execution_get(attempt["id"])
                assert current is not None and current["execution_id"] == execution["execution_id"]
                assert current["phase"] == "running"
                artifact = current["provider_proxy_artifact"]
                assert artifact["directory"]["path"] == str(provider_proxy_directory)
                assert artifact["socket"]["path"] == str(provider_proxy_socket_path)
                directory_info = provider_proxy_directory.lstat()
                socket_info = provider_proxy_socket_path.lstat()
                assert (directory_info.st_dev, directory_info.st_ino) == (
                    artifact["directory"]["device"],
                    artifact["directory"]["inode"],
                )
                assert stat.S_ISSOCK(socket_info.st_mode)
                assert (socket_info.st_dev, socket_info.st_ino) == (
                    artifact["socket"]["device"],
                    artifact["socket"]["inode"],
                )
                execution = current
                provider_probe_release.write_text("release-provider-probe\n", encoding="ascii")
            else:
                provider_probe_result = workspace_root / "provider-probe-result"
                if provider_proxy_cancel:
                    provider_probe_open = workspace_root / "provider-probe-open"
                while (
                    not _entry_is_present(provider_probe_result)
                    and time.monotonic() < probe_deadline
                ):
                    time.sleep(0.05)
                if not _entry_is_present(provider_probe_result):
                    current = supervisor._sandbox_execution_get(attempt["id"])
                    service_log = (
                        service_log_path.read_text(encoding="utf-8", errors="replace")
                        if service_log_path.exists()
                        else "<launch-driver service log was not created>"
                    )
                    service_log = service_log.replace(runner["credential"], "[redacted]")
                    pytest.fail(
                        "provider UDS in-cgroup probe did not pass; "
                        f"phase={current['phase'] if current is not None else None!r}; "
                        f"runc_exit_code={current.get('runc_exit_code') if current is not None else None!r}; "
                        f"exit_evidence={current.get('runc_exit_evidence_source') if current is not None else None!r}; "
                        f"started={_entry_is_present(provider_started_path)}; "
                        f"result={_entry_is_present(provider_probe_result)}; "
                        f"producer_result_ready={producer_result_receiver.poll()}; "
                        f"service_log_tail={service_log[-4000:]!r}"
                    )
                if provider_probe_open is not None:
                    open_deadline = time.monotonic() + 10
                    while (
                        not _entry_is_present(provider_probe_open)
                        and time.monotonic() < open_deadline
                    ):
                        time.sleep(0.05)
                    assert _entry_is_present(provider_probe_open), (
                        "worker did not retain a connected open partial provider request"
                    )
                current = supervisor._sandbox_execution_get(attempt["id"])
                assert current is not None and current["execution_id"] == execution["execution_id"]
                assert current["phase"] == "running", (
                    "worker left its running cgroup before the outside-peer probe: "
                    f"{current['phase']!r}"
                )
                workspace_path_text = current.get("workspace_root_path")
                assert isinstance(workspace_path_text, str) and workspace_path_text, (
                    "running execution row has no bound worker workspace"
                )
                assert Path(workspace_path_text) == workspace_root, (
                    "running execution workspace changed during the provider probe"
                )
                execution_root = Path(current["bundle_path"]).parent
                canonical_execution_root = execution_root.resolve(strict=True)
                assert (
                    workspace_root.resolve(strict=True) == canonical_execution_root / "workspace"
                ), "worker workspace is not the exact private attempt execution child"
                cgroup_path_text = current.get("cgroup_path")
                assert isinstance(cgroup_path_text, str) and cgroup_path_text, (
                    "running execution row has no worker cgroup identity"
                )
                worker_cgroup = PurePosixPath(cgroup_path_text)
                assert (
                    worker_cgroup.is_absolute()
                    and worker_cgroup.as_posix() == cgroup_path_text
                    and not any(part in {".", ".."} for part in worker_cgroup.parts)
                ), "running execution row has a non-canonical worker cgroup identity"
                execution = current
                outside_cgroup, _, _ = _process_cgroup_identity(os.getpid())
                assert not PurePosixPath(outside_cgroup).is_relative_to(worker_cgroup), (
                    "same-UID outside probe unexpectedly runs inside the worker cgroup"
                )
                outsider = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                outsider.settimeout(3)
                try:
                    outsider.connect(str(provider_proxy_socket_path))
                    outsider.sendall(b"NOT-CONNECT / HTTP/1.1\r\n\r\n")
                    outside_response = outsider.recv(1024)
                finally:
                    outsider.close()
                assert b"403 Forbidden" in outside_response, (
                    "same-UID outside-cgroup peer reached request parsing instead of failing "
                    f"peer authorization: {outside_response!r}"
                )
            if not provider_proxy_cancel:
                assert provider_probe_release is not None
                if not crash_after_exit_before_cleanup_report:
                    provider_probe_release.write_text("release-provider-probe\n", encoding="ascii")
        assert producer_result_receiver.poll(35), "launch producer did not report its handoff"
        producer_result = producer_result_receiver.recv()
        assert identity is not None and execution is not None
        producer_controller.join(timeout=5)
        assert not producer_controller.is_alive(), (
            "launch producer survived simulated controller loss"
        )
        if producer_result[0] not in {"ok", "manager_accepted"}:
            service_log = (
                service_log_path.read_text(encoding="utf-8", errors="replace")
                if service_log_path.exists()
                else ""
            )
            assert runner["credential"] not in service_log
            service_detail = service_log[-12_000:] or "<launch-driver service log was not created>"
            raise AssertionError(
                f"production launch-driver startup failed: {producer_result}; "
                f"service log tail:\n{service_detail}"
            )
        if crash_driver_service_before_receipt:
            assert producer_result[0] == "manager_accepted", producer_result
            producer_exit = 74
        else:
            assert producer_result[0] == "ok", producer_result
            producer_exit = 73
        assert producer_controller.exitcode == producer_exit
        producer_result_receiver.close()
        if producer_result[0] == "manager_accepted":
            controller_pid = producer_result[1]
            producer_receipt = None
            producer_summary = None
        else:
            controller_pid, producer_receipt, producer_summary = producer_result[1:]
            assert producer_receipt["attempt_id"] == identity[0]
            assert producer_receipt["claim_token"] == identity[1]
            assert producer_receipt["execution_id"] == identity[2]
        if supervised_run_worker:
            assert producer_summary == {
                "status": "pending_qc",
                "sandbox_execution_id": identity[2],
                "sandbox_cleanup_verified": True,
            }
        else:
            assert producer_summary is None
        if crash_after_monitor_acceptance or crash_before_monitor_start:
            _wait_for_receipt(run_root, "monitor-handoff-crash.json", timeout=40.0)
            accepted = json.loads(monitor_acceptance_marker.read_text(encoding="ascii"))
            expected_crash_phase = (
                "before_monitor_start" if crash_before_monitor_start else "after_monitor_acceptance"
            )
            assert accepted["crash_phase"] == expected_crash_phase
            assert accepted["identity"] == list(identity)
            driver = accepted["driver"]
            monitor = accepted["monitor"]
            scope = accepted["scope"]
            assert driver["unit"] == service_unit
            assert driver["pid"] == driver["main_pid"] > 0
            assert driver["identity"].startswith(f"linux:{driver['pid']}:")
            assert driver["active_state"] == "active"
            assert re.fullmatch(r"[0-9a-f]{32}", driver["invocation_id"])
            assert driver["slice"] == slice_unit
            assert PurePosixPath(driver["control_group"]).name == service_unit
            assert (
                PurePosixPath(driver["control_group"]).parent.as_posix()
                == accepted["attempt_slice_control_group"]
            )
            assert accepted["attempt_slice"] == slice_unit
            assert accepted["monitor_unit"] == monitor_unit
            if crash_before_monitor_start:
                assert monitor is None
            else:
                assert monitor is not None
                assert monitor["unit"] == monitor_unit
                assert (
                    monitor["attempt_id"],
                    monitor["claim_token"],
                    monitor["execution_id"],
                ) == identity
                assert monitor["pid"] > 0
                assert monitor["identity"].startswith(f"linux:{monitor['pid']}:")
                assert re.fullmatch(r"[0-9a-f]{32}", monitor["invocation_id"])
                assert monitor["control_group"]
                assert not PurePosixPath(monitor["control_group"]).is_relative_to(
                    PurePosixPath(accepted["attempt_slice_control_group"])
                )
            assert scope["unit"] == f"acp-{execution['container_id']}.scope"
            assert re.fullmatch(r"[0-9a-f]{32}", scope["invocation_id"])
            assert (
                PurePosixPath(scope["control_group"]).parent.as_posix()
                == (accepted["attempt_slice_control_group"])
            )
            assert accepted["runc_client_pid"] > 0
            assert accepted["runc_client_identity"].startswith(
                f"linux:{accepted['runc_client_pid']}:"
            )
            service_log = service_log_path.read_text(encoding="utf-8", errors="replace")
            assert runner["credential"] not in service_log

            deadline = time.monotonic() + 10
            driver_after_crash = _unit_properties(
                service_unit,
                (
                    "ActiveState",
                    "ControlGroup",
                    "Id",
                    "InvocationID",
                    "LoadState",
                    "MainPID",
                    "Slice",
                ),
            )
            while time.monotonic() < deadline and (
                driver_after_crash["MainPID"] != "0"
                or driver_after_crash["ActiveState"] not in {"failed", "inactive"}
            ):
                time.sleep(0.05)
                driver_after_crash = _unit_properties(
                    service_unit,
                    (
                        "ActiveState",
                        "ControlGroup",
                        "Id",
                        "InvocationID",
                        "LoadState",
                        "MainPID",
                        "Slice",
                    ),
                )
            assert driver_after_crash["Id"] == service_unit
            assert driver_after_crash["LoadState"] == "loaded"
            assert driver_after_crash["ActiveState"] in {"failed", "inactive"}
            assert driver_after_crash["MainPID"] == "0"
            assert driver_after_crash["InvocationID"] == driver["invocation_id"]
            assert driver_after_crash["Slice"] == slice_unit
            if user_manager_reexec_after_driver_crash:
                systemctl = str(sandbox_attestation._trusted_systemctl_executable())
                reexec = _systemd_command([systemctl, "--user", "daemon-reexec"], timeout=30)
                assert reexec.returncode == 0, (
                    "systemd user-manager daemon-reexec failed: "
                    f"stdout={reexec.stdout!r}; stderr={reexec.stderr!r}"
                )
                driver_after_reexec = _unit_properties(
                    service_unit,
                    (
                        "ActiveState",
                        "ControlGroup",
                        "Id",
                        "InvocationID",
                        "LoadState",
                        "MainPID",
                        "Slice",
                    ),
                )
                assert driver_after_reexec == driver_after_crash
            if user_manager_restart_target is not None:
                sudo_path, user_manager_unit, original_manager_pid, manager_cgroup = (
                    user_manager_restart_target
                )
                assert user_manager_restart_baseline is not None
                current_inventory = _user_manager_unit_inventory(systemctl)
                test_units = {
                    service_unit,
                    monitor_unit,
                    slice_unit,
                    scope["unit"],
                    "user.slice",
                    _MONITOR_SLICE_UNIT,
                }
                missing_baseline_units = set(user_manager_restart_baseline) - set(current_inventory)
                unexpected_units = (
                    set(current_inventory) - set(user_manager_restart_baseline) - test_units
                )
                changed_baseline_units = {
                    unit: (user_manager_restart_baseline[unit], current_inventory.get(unit))
                    for unit in user_manager_restart_baseline
                    if current_inventory.get(unit) != user_manager_restart_baseline[unit]
                }
                assert not missing_baseline_units, (
                    "refusing user-manager restart because baseline units disappeared: "
                    f"{sorted(missing_baseline_units)!r}"
                )
                assert not unexpected_units, (
                    "refusing user-manager restart because unapproved user units appeared: "
                    f"{sorted(unexpected_units)!r}"
                )
                assert not changed_baseline_units, (
                    "refusing user-manager restart because baseline unit states changed: "
                    f"{changed_baseline_units!r}"
                )
                assert current_inventory.get(_MONITOR_SLICE_UNIT) == (
                    "loaded",
                    "active",
                    "active",
                ), "the test-owned monitor parent slice is not active"
                assert current_inventory.get("user.slice") == (
                    "loaded",
                    "active",
                    "active",
                ), "the test-owned parent slice is not active"
                for parent_slice in {"user.slice", _MONITOR_SLICE_UNIT} & set(current_inventory):
                    assert _user_manager_parent_slice_state_is_safe(
                        parent_slice,
                        current_inventory[parent_slice],
                        manager_cgroup,
                        allow_active=True,
                    ), f"unsafe user-manager parent slice before restart: {parent_slice}"
                for unit in test_units & set(current_inventory):
                    active_state = current_inventory[unit][1]
                    assert active_state not in {"activating", "reloading", "deactivating"}, (
                        f"refusing user-manager restart during {unit} transition: {active_state}"
                    )
                    assert active_state != "failed" or unit == service_unit, (
                        f"refusing user-manager restart with failed non-driver unit {unit}"
                    )
                attempt_slice_properties = _unit_properties(
                    slice_unit, ("ActiveState", "ControlGroup", "LoadState")
                )
                assert attempt_slice_properties["LoadState"] == "loaded"
                assert attempt_slice_properties["ActiveState"] == "active"
                assert (
                    attempt_slice_properties["ControlGroup"]
                    == accepted["attempt_slice_control_group"]
                )
                if monitor is not None:
                    monitor_properties = _unit_properties(
                        monitor_unit, ("ActiveState", "ControlGroup", "LoadState", "MainPID")
                    )
                    assert monitor_properties["LoadState"] == "loaded"
                    assert monitor_properties["ActiveState"] == "active"
                    assert monitor_properties["MainPID"] == str(monitor["pid"])
                    assert monitor_properties["ControlGroup"] == monitor["control_group"]
                scope_properties = _unit_properties(
                    scope["unit"], ("ActiveState", "ControlGroup", "LoadState")
                )
                assert scope_properties["ActiveState"] in {"active", "inactive"}
                if scope_properties["ActiveState"] == "active":
                    assert scope_properties["ControlGroup"] == scope["control_group"]
                else:
                    assert not scope_properties["ControlGroup"]
                manager_pid_result = _systemd_command(
                    [
                        str(sudo_path),
                        "-n",
                        systemctl,
                        "show",
                        user_manager_unit,
                        "-p",
                        "MainPID",
                        "--value",
                    ]
                )
                assert manager_pid_result.returncode == 0
                assert manager_pid_result.stdout.strip() == original_manager_pid, (
                    "the test user's manager changed before the requested restart"
                )
                test_cgroups = {
                    "attempt_slice": accepted["attempt_slice_control_group"],
                    "launch_driver": driver["control_group"],
                    "scope": scope["control_group"],
                }
                expected_monitor_pid = None
                if monitor is not None:
                    test_cgroups["monitor"] = monitor["control_group"]
                    expected_monitor_pid = str(monitor["pid"])
                assert user_manager_restart_baseline_processes is not None
                _assert_user_manager_process_inventory(
                    manager_cgroup=manager_cgroup,
                    manager_pid=original_manager_pid,
                    test_cgroups=test_cgroups,
                    expected_monitor_pid=expected_monitor_pid,
                    expected_baseline_processes=user_manager_restart_baseline_processes,
                )
                user_manager_restart_uncertain = True
                try:
                    restart = _systemd_command(
                        [str(sudo_path), "-n", systemctl, "restart", user_manager_unit],
                        timeout=60,
                    )
                except subprocess.TimeoutExpired as error:
                    pytest.fail(
                        "user-manager restart timed out with an uncertain outcome; no retry or "
                        "automatic unit cleanup was attempted. Preserve this disposable VM and "
                        "manually inspect user@UID.service and the exact ACP fixture units before "
                        "any recovery or rerun."
                    )
                    raise error
                if restart.returncode != 0:
                    pytest.fail(
                        "user-manager restart returned nonzero with an uncertain outcome; no "
                        "retry or automatic unit cleanup was attempted. Preserve this disposable "
                        "VM and manually inspect user@UID.service and the exact ACP fixture units "
                        f"before recovery. stdout={restart.stdout!r}; stderr={restart.stderr!r}"
                    )
                manager_after_restart = ""
                manager_reachable = False
                user_bus_reachable = False
                assert user_manager_restart_busctl is not None
                restart_deadline = time.monotonic() + 15
                while time.monotonic() < restart_deadline:
                    manager_pid_result = _systemd_command(
                        [
                            str(sudo_path),
                            "-n",
                            systemctl,
                            "show",
                            user_manager_unit,
                            "-p",
                            "MainPID",
                            "--value",
                        ]
                    )
                    manager_after_restart = manager_pid_result.stdout.strip()
                    manager_reachable = (
                        _systemd_command(
                            [systemctl, "--user", "show-environment"], timeout=5
                        ).returncode
                        == 0
                    )
                    user_bus_reachable = (
                        _systemd_command(
                            [
                                str(user_manager_restart_busctl),
                                "--user",
                                "--no-pager",
                                "status",
                            ],
                            timeout=5,
                        ).returncode
                        == 0
                    )
                    if (
                        manager_pid_result.returncode == 0
                        and manager_after_restart.isdecimal()
                        and manager_after_restart not in {"0", original_manager_pid}
                        and manager_reachable
                        and user_bus_reachable
                    ):
                        break
                    time.sleep(0.25)
                assert manager_pid_result.returncode == 0, (
                    "restarted user manager PID could not be verified by systemd"
                )
                assert manager_after_restart.isdecimal()
                assert manager_after_restart not in {"0", original_manager_pid}
                assert manager_reachable, "restarted user manager did not become reachable"
                assert user_bus_reachable, "restarted user D-Bus did not become reachable"
                driver_after_restart = _unit_properties(
                    service_unit,
                    ("ActiveState", "ControlGroup", "Id", "InvocationID", "LoadState", "MainPID"),
                )
                assert driver_after_restart["Id"] == service_unit
                assert driver_after_restart["LoadState"] == "not-found"
                assert driver_after_restart["ActiveState"] == "inactive"
                assert driver_after_restart["MainPID"] == "0"
                assert not driver_after_restart["ControlGroup"]
                assert not driver_after_restart["InvocationID"]
            monitor_before_recovery = _unit_properties(
                monitor_unit,
                (
                    "ActiveState",
                    "ControlGroup",
                    "Id",
                    "InvocationID",
                    "LoadState",
                    "MainPID",
                    "Slice",
                ),
            )
            assert monitor_before_recovery["Id"] == monitor_unit
            if user_manager_restart_target is not None:
                assert monitor_before_recovery["ActiveState"] == "inactive"
                assert monitor_before_recovery["LoadState"] == "not-found"
                assert monitor_before_recovery["MainPID"] == "0"
                assert not monitor_before_recovery["InvocationID"]
                assert not monitor_before_recovery["ControlGroup"]
            elif crash_before_monitor_start:
                assert monitor_before_recovery["ActiveState"] == "inactive"
                assert monitor_before_recovery["LoadState"] == "not-found"
                assert monitor_before_recovery["MainPID"] == "0"
                assert not monitor_before_recovery["InvocationID"]
                assert not monitor_before_recovery["ControlGroup"]
            else:
                assert monitor_before_recovery["ActiveState"] == "active"
                assert monitor_before_recovery["LoadState"] == "loaded"
                assert monitor_before_recovery["MainPID"] == str(monitor["pid"])
                assert monitor_before_recovery["InvocationID"] == monitor["invocation_id"]
                assert monitor_before_recovery["ControlGroup"] == monitor["control_group"]
            attempt_slice_before_recovery = _unit_properties(
                slice_unit, ("ActiveState", "ControlGroup", "Id", "LoadState", "SubState")
            )
            assert attempt_slice_before_recovery["Id"] == slice_unit
            if user_manager_restart_target is not None:
                assert slice_unit == accepted["attempt_slice"]
                assert attempt_slice_before_recovery["ActiveState"] == "inactive"
                assert attempt_slice_before_recovery["LoadState"] in {"loaded", "not-found"}
                assert attempt_slice_before_recovery["SubState"] == "dead"
                assert not attempt_slice_before_recovery["ControlGroup"]
            else:
                assert attempt_slice_before_recovery["ActiveState"] == "active"
                assert (
                    attempt_slice_before_recovery["ControlGroup"]
                    == accepted["attempt_slice_control_group"]
                )
            scope_before_recovery = _unit_properties(
                scope["unit"],
                ("ActiveState", "ControlGroup", "Id", "InvocationID", "LoadState", "Slice"),
            )
            assert scope_before_recovery["Id"] == scope["unit"]
            if user_manager_restart_target is not None:
                assert scope_before_recovery["ActiveState"] == "inactive"
                assert scope_before_recovery["LoadState"] == "not-found"
                assert not scope_before_recovery["ControlGroup"]
            else:
                assert scope_before_recovery["ActiveState"] in {"active", "inactive"}
            if (
                user_manager_restart_target is None
                and scope_before_recovery["ActiveState"] == "active"
            ):
                assert scope_before_recovery["InvocationID"] == scope["invocation_id"]
                assert scope_before_recovery["ControlGroup"] == scope["control_group"]
                assert scope_before_recovery["Slice"] == slice_unit
            else:
                # With the gate still closed, EOF at driver death may reap the
                # blocked runc process before fresh-supervisor reconciliation.
                assert not scope_before_recovery["ControlGroup"]
                assert scope_before_recovery["LoadState"] in {"loaded", "not-found"}
                assert scope_before_recovery["Slice"] in {"", slice_unit}
            if user_manager_restart_target is not None:
                sudo_path, user_manager_unit, _original_manager_pid, manager_cgroup = (
                    user_manager_restart_target
                )
                current_cgroup_result = _systemd_command(
                    [
                        str(sudo_path),
                        "-n",
                        systemctl,
                        "show",
                        user_manager_unit,
                        "-p",
                        "ControlGroup",
                        "--value",
                    ]
                )
                assert current_cgroup_result.returncode == 0
                assert current_cgroup_result.stdout.strip() == manager_cgroup
                assert user_manager_restart_baseline is not None
                post_restart_inventory = _user_manager_unit_inventory(systemctl)
                test_units = {
                    service_unit,
                    monitor_unit,
                    slice_unit,
                    scope["unit"],
                    "user.slice",
                    _MONITOR_SLICE_UNIT,
                }
                assert (
                    set(post_restart_inventory) <= set(user_manager_restart_baseline) | test_units
                )
                for parent_slice in {"user.slice", _MONITOR_SLICE_UNIT} & set(
                    post_restart_inventory
                ):
                    assert _user_manager_parent_slice_state_is_safe(
                        parent_slice,
                        post_restart_inventory[parent_slice],
                        manager_cgroup,
                        allow_active=False,
                    ), f"parent slice remained active or nonempty after restart: {parent_slice}"
                for unit, expected_state in user_manager_restart_baseline.items():
                    actual_state = post_restart_inventory.get(unit)
                    assert actual_state == expected_state, (
                        f"baseline unit changed across manager restart: {unit} "
                        f"{actual_state!r} != {expected_state!r}"
                    )
                for unit in test_units & set(post_restart_inventory):
                    state = post_restart_inventory[unit]
                    if unit in {"user.slice", _MONITOR_SLICE_UNIT}:
                        continue
                    assert _user_manager_restart_test_unit_state_is_safe(
                        unit=unit,
                        attempt_slice_unit=slice_unit,
                        state=state,
                    ), (
                        f"test unit remained in an unsafe state after manager restart: "
                        f"{unit}={state!r}"
                    )
                _assert_user_manager_process_inventory(
                    manager_cgroup=manager_cgroup,
                    manager_pid=manager_after_restart,
                )
                user_manager_restart_uncertain = False

            durable_before_recovery = supervisor._sandbox_execution_get(attempt["id"])
            assert durable_before_recovery is not None
            assert durable_before_recovery["phase"] == "reserved"
            assert durable_before_recovery["launch_driver_start_id"]
            assert durable_before_recovery["launch_driver_start_digest"]
            assert durable_before_recovery["launch_submission_id"]
            assert durable_before_recovery["launch_submission_digest"]
            assert durable_before_recovery["launch_plan_binding_version"] == 0
            assert durable_before_recovery["launch_driver_start_redeemed_pid"] == driver["pid"]
            assert (
                durable_before_recovery["launch_driver_start_redeemed_invocation_id"]
                == driver["invocation_id"]
            )
            assert (
                durable_before_recovery["launch_driver_start_redeemed_identity"]
                == driver["identity"]
            )
            assert (
                durable_before_recovery["launch_driver_start_redeemed_cgroup_path"]
                == driver["control_group"]
            )
            assert durable_before_recovery["wrapper_unit"] == ""
            assert durable_before_recovery["monitor_pid"] is None
            payload_marker = Path(durable_before_recovery["workspace_root_path"])
            assert not (payload_marker / "launch-driver-started").exists()
            assert not (payload_marker / "launch-driver-marker").exists()
            assert Path(durable_before_recovery["state_path"]).is_dir()
            with supervisor.connect() as connection:
                resource_leases_before = connection.execute(
                    "SELECT resource, lease_expires_at FROM resource_leases WHERE attempt_id = ?",
                    (attempt["id"],),
                ).fetchall()
                allocation_before = connection.execute(
                    "SELECT pool_name, value, lease_expires_at FROM runtime_allocations "
                    "WHERE attempt_id = ?",
                    (attempt["id"],),
                ).fetchone()
                runtime_before = connection.execute(
                    "SELECT state FROM runtime_environments WHERE attempt_id = ?",
                    (attempt["id"],),
                ).fetchone()
            assert resource_leases_before
            assert allocation_before is not None
            assert runtime_before is not None and runtime_before["state"] != "released"

            context = multiprocessing.get_context("spawn")
            recovery_receiver, recovery_sender = context.Pipe(duplex=False)
            recovery = context.Process(
                target=_reconcile_monitor_accepted_driver_crash_from_fresh_process,
                args=(
                    repo,
                    attempt["id"],
                    attempt["claim_token"],
                    execution["execution_id"],
                    runner["credential"],
                    recovery_sender,
                ),
            )
            recovery.start()
            child_processes.append(recovery)
            recovery_sender.close()
            assert recovery_receiver.poll(30), (
                "fresh supervisor did not reconcile the exact handoff"
            )
            recovery_result = recovery_receiver.recv()
            recovery.join(timeout=10)
            assert not recovery.is_alive()
            assert recovery.exitcode == 0
            recovery_receiver.close()
            assert recovery_result[0] == "ok", recovery_result
            recovery_excluded_pids = {
                controller_pid,
                driver["pid"],
                accepted["runc_client_pid"],
            }
            if monitor is not None:
                recovery_excluded_pids.add(monitor["pid"])
            assert recovery_result[1] not in recovery_excluded_pids
            assert recovery_result[2] is False

            for unit in (service_unit, monitor_unit):
                props = _unit_properties(
                    unit, ("ActiveState", "ControlGroup", "Id", "LoadState", "MainPID")
                )
                assert props["Id"] == unit
                assert props["LoadState"] in {"loaded", "not-found"}
                assert props["ActiveState"] in {"inactive", "failed"}
                assert props["MainPID"] == "0"
                assert not props["ControlGroup"]
                if crash_before_monitor_start and unit == monitor_unit:
                    assert props["LoadState"] == "not-found"
                    assert props["ActiveState"] == "inactive"
            scope_after_recovery = _unit_properties(
                scope["unit"], ("ActiveState", "ControlGroup", "Id", "LoadState")
            )
            assert scope_after_recovery["Id"] == scope["unit"]
            assert scope_after_recovery["LoadState"] in {"loaded", "not-found"}
            assert scope_after_recovery["ActiveState"] in {"inactive", "failed"}
            assert not scope_after_recovery["ControlGroup"]
            slice_props = _unit_properties(
                slice_unit, ("ActiveState", "ControlGroup", "Id", "LoadState")
            )
            assert slice_props["Id"] == slice_unit
            assert slice_props["ActiveState"] in {"inactive", "failed"}
            assert slice_props["LoadState"] in {"loaded", "not-found"}
            assert not slice_props["ControlGroup"]
            observed_processes = [
                (driver["pid"], driver["identity"]),
                (accepted["runc_client_pid"], accepted["runc_client_identity"]),
            ]
            if monitor is not None:
                observed_processes.append((monitor["pid"], monitor["identity"]))
            for observed_pid, observed_identity in observed_processes:
                try:
                    current_identity = _linux_process_identity(observed_pid)
                except sandbox_monitor_ipc.SandboxMonitorIPCError:
                    current_identity = ""
                assert current_identity != observed_identity

            durable_after_recovery = supervisor._sandbox_execution_get(attempt["id"])
            assert durable_after_recovery is not None
            assert durable_after_recovery["phase"] == "ambiguous"
            assert (
                durable_after_recovery["launch_driver_start_id"]
                == durable_before_recovery["launch_driver_start_id"]
            )
            assert (
                durable_after_recovery["launch_driver_start_digest"]
                == (durable_before_recovery["launch_driver_start_digest"])
            )
            assert (
                durable_after_recovery["launch_submission_id"]
                == durable_before_recovery["launch_submission_id"]
            )
            assert (
                durable_after_recovery["launch_submission_digest"]
                == (durable_before_recovery["launch_submission_digest"])
            )
            assert durable_after_recovery["launch_plan_binding_version"] == 0
            assert durable_after_recovery["cleanup_verification_json"] == "{}"
            assert not (payload_marker / "launch-driver-started").exists()
            assert not (payload_marker / "launch-driver-marker").exists()
            assert Path(durable_after_recovery["state_path"]).is_dir()
            assert supervisor.attempt(attempt["id"])["termination_target_status"] == "quarantined"
            assert supervisor.task(task["id"])["cleanup_target_status"] == "blocked"
            with pytest.raises(SupervisorError) as result_rejected:
                supervisor._sandbox_execution_capture_result_candidate(
                    attempt["id"], attempt["claim_token"], credential=runner["credential"]
                )
            assert result_rejected.value.code == "claim_inactive"
            assert supervisor._sandbox_execution_get(attempt["id"])["result_candidate"] is None

            with supervisor.connect() as connection:
                leases = connection.execute(
                    "SELECT resource, lease_expires_at FROM resource_leases WHERE attempt_id = ?",
                    (attempt["id"],),
                ).fetchall()
                allocation = connection.execute(
                    "SELECT pool_name, value, lease_expires_at FROM runtime_allocations "
                    "WHERE attempt_id = ?",
                    (attempt["id"],),
                ).fetchone()
                runtime = connection.execute(
                    "SELECT state FROM runtime_environments WHERE attempt_id = ?",
                    (attempt["id"],),
                ).fetchone()
            assert leases and [row["resource"] for row in leases] == [
                row["resource"] for row in resource_leases_before
            ]
            assert all(
                row["lease_expires_at"] == journal_module.CLEANUP_FENCE_EPOCH for row in leases
            )
            assert allocation is not None and allocation_before is not None
            assert (allocation["pool_name"], allocation["value"]) == (
                allocation_before["pool_name"],
                allocation_before["value"],
            )
            assert allocation["pool_name"] == "LAUNCH_DRIVER_TEST_PORT"
            assert allocation["value"] == runtime_test_port
            assert allocation["lease_expires_at"] == journal_module.CLEANUP_FENCE_EPOCH
            assert runtime is not None and runtime["state"] == runtime_before["state"]

            start_identity_before_retry = tuple(
                durable_after_recovery[field]
                for field in (
                    "launch_driver_start_id",
                    "launch_driver_start_digest",
                    "launch_driver_start_unit",
                    "launch_driver_start_redeemed_invocation_id",
                    "launch_driver_start_redeemed_pid",
                    "launch_driver_start_redeemed_identity",
                    "launch_driver_start_redeemed_cgroup_path",
                )
            )
            retry_receiver, retry_sender = context.Pipe(duplex=False)
            retry_controller = context.Process(
                target=_retry_launch_driver_without_replay_from_fresh_process,
                args=(
                    repo,
                    identity,
                    payload_command,
                    _CONTAINER_MEMORY_BYTES,
                    _CONTAINER_CPU_QUOTA_US,
                    _CONTAINER_CPU_PERIOD_US,
                    _CONTAINER_PIDS_LIMIT,
                    sandbox_timeout_seconds,
                    runner["credential"],
                    retry_sender,
                ),
            )
            retry_controller.start()
            child_processes.append(retry_controller)
            retry_sender.close()
            assert retry_receiver.poll(20), "fresh retry did not reject the one-shot launch"
            retry_result = retry_receiver.recv()
            retry_controller.join(timeout=5)
            assert not retry_controller.is_alive()
            assert retry_controller.exitcode == 0
            retry_receiver.close()
            assert retry_result[0] == "rejected", retry_result
            assert retry_result[1] not in {
                controller_pid,
                driver["pid"],
                recovery_result[1],
            }
            assert retry_result[2] == "SandboxLaunchDriverServiceError"
            assert retry_result[3] == 0, "fresh retry reached systemd-run and could replay the unit"
            final_row = supervisor._sandbox_execution_get(attempt["id"])
            assert final_row is not None
            assert (
                tuple(
                    final_row[field]
                    for field in (
                        "launch_driver_start_id",
                        "launch_driver_start_digest",
                        "launch_driver_start_unit",
                        "launch_driver_start_redeemed_invocation_id",
                        "launch_driver_start_redeemed_pid",
                        "launch_driver_start_redeemed_identity",
                        "launch_driver_start_redeemed_cgroup_path",
                    )
                )
                == start_identity_before_retry
            )
            assert (
                final_row["launch_submission_id"] == durable_after_recovery["launch_submission_id"]
            )
            assert (
                final_row["launch_submission_digest"]
                == durable_after_recovery["launch_submission_digest"]
            )
            assert monitor_acceptance_marker.is_file()
            return
        if crash_after_exit_before_cleanup_report:
            _wait_for_receipt(run_root, monitor_acceptance_marker.name, timeout=40.0)
            crashed = json.loads(monitor_acceptance_marker.read_text(encoding="ascii"))
            assert crashed["crash_phase"] == "after_exit_before_cleanup_report"
            assert crashed["identity"] == list(identity)
            driver = crashed["driver"]
            assert driver["unit"] == service_unit
            assert driver["pid"] == driver["main_pid"] > 0
            assert driver["identity"].startswith(f"linux:{driver['pid']}:")
            assert driver["active_state"] == "active"
            assert re.fullmatch(r"[0-9a-f]{32}", driver["invocation_id"])
            assert driver["slice"] == slice_unit
            assert PurePosixPath(driver["control_group"]).name == service_unit

            durable_before_recovery = supervisor._sandbox_execution_get(attempt["id"])
            assert durable_before_recovery is not None
            assert durable_before_recovery["phase"] == "exited"
            assert durable_before_recovery["runc_exit_code"] == 0
            assert (
                durable_before_recovery["runc_exit_evidence_source"] == "runc_client_kernel_waitpid"
            )
            assert durable_before_recovery["cleanup_receipt"] == {}
            assert durable_before_recovery["cleanup_verification_json"] == "{}"
            assert (
                durable_before_recovery["launch_submission_id"] == crashed["launch_submission_id"]
            )
            assert (
                durable_before_recovery["launch_submission_digest"]
                == crashed["launch_submission_digest"]
            )
            assert durable_before_recovery["launch_driver_pid"] == driver["pid"]
            assert durable_before_recovery["launch_driver_identity"] == driver["identity"]
            assert durable_before_recovery["launch_driver_invocation_id"] == driver["invocation_id"]
            assert crashed["execution_phase"] == "exited"
            assert crashed["runc_exit_code"] == 0
            assert crashed["cleanup_receipt"] == {}

            driver_after_crash = _unit_properties(
                service_unit,
                ("ActiveState", "ControlGroup", "Id", "InvocationID", "LoadState", "MainPID"),
            )
            quiescence_deadline = time.monotonic() + 10
            while time.monotonic() < quiescence_deadline and (
                driver_after_crash["MainPID"] != "0"
                or driver_after_crash["ActiveState"] not in {"failed", "inactive"}
            ):
                time.sleep(0.05)
                driver_after_crash = _unit_properties(
                    service_unit,
                    (
                        "ActiveState",
                        "ControlGroup",
                        "Id",
                        "InvocationID",
                        "LoadState",
                        "MainPID",
                    ),
                )
            assert driver_after_crash["Id"] == service_unit
            assert driver_after_crash["LoadState"] == "loaded"
            assert driver_after_crash["ActiveState"] in {"failed", "inactive"}
            assert driver_after_crash["MainPID"] == "0"
            assert driver_after_crash["InvocationID"] == driver["invocation_id"]
            assert not driver_after_crash["ControlGroup"]

            assert provider_proxy_directory is not None
            assert provider_proxy_socket_path is not None
            provider_artifact = durable_before_recovery["provider_proxy_artifact"]
            assert provider_artifact["directory"]["path"] == str(provider_proxy_directory)
            assert provider_artifact["socket"]["path"] == str(provider_proxy_socket_path)
            directory_info = provider_proxy_directory.lstat()
            assert (directory_info.st_dev, directory_info.st_ino) == (
                provider_artifact["directory"]["device"],
                provider_artifact["directory"]["inode"],
            )
            assert not os.path.lexists(provider_proxy_socket_path)
            assert list(provider_proxy_directory.iterdir()) == []
            container_state_entry = state_root / durable_before_recovery["container_id"]
            assert container_state_entry.is_dir(), (
                "the exact stopped runc state entry must still exist at the injected crash"
            )

            reaper_epoch = (
                max(int(time.time()), int(supervisor.attempt(attempt["id"])["lease_expires_at"]))
                + 1
            )
            recovery_receiver, recovery_sender = context.Pipe(duplex=False)
            recovery = context.Process(
                target=_reap_expired_from_fresh_process,
                args=(repo, reaper_epoch, recovery_sender),
            )
            recovery.start()
            child_processes.append(recovery)
            recovery_sender.close()
            assert recovery_receiver.poll(45), "fresh reaper did not recover the post-wait crash"
            recovery_result = recovery_receiver.recv()
            recovery.join(timeout=10)
            assert not recovery.is_alive()
            assert recovery.exitcode == 0
            recovery_receiver.close()
            assert recovery_result[0] == "ok", recovery_result
            assert recovery_result[1] not in {controller_pid, driver["pid"]}
            recovered = supervisor._sandbox_execution_get(attempt["id"])
            assert recovered is not None and recovered["phase"] == "cleanup_verified"
            cleanup_receipt = recovered["cleanup_receipt"]
            assert cleanup_receipt["version"] == 4
            recovery_receipt = cleanup_receipt["recovery"]
            assert recovery_receipt["launch_submission_id"] == crashed["launch_submission_id"]
            assert (
                recovery_receipt["launch_submission_digest"] == crashed["launch_submission_digest"]
            )
            assert recovery_receipt["container_id"] == durable_before_recovery["container_id"]
            assert recovery_receipt["runc_delete_action"] is not None
            runc_action = recovery_receipt["runc_delete_action"]
            assert (
                runc_action["executable_digest"]
                == durable_before_recovery["runc_executable_digest"]
            )
            assert runc_action["runtime_version"] == _SUPPORTED_RUNC_VERSION
            assert runc_action["argv"][3:] == (
                "delete",
                "--force",
                durable_before_recovery["container_id"],
            ) or runc_action["argv"][3:] == [
                "delete",
                "--force",
                durable_before_recovery["container_id"],
            ]
            assert runc_action["state_entry_absent"] is True
            assert (
                recovered["cleanup_verification"]["observations"]["paths"][
                    "provider_proxy_directory"
                ]["absent"]
                is True
            )
            assert not os.path.lexists(provider_proxy_socket_path)
            assert not os.path.lexists(provider_proxy_directory)
            assert not container_state_entry.exists()
            assert not state_root.exists()
            assert not Path(recovered["bundle_path"]).exists()
            release_rows = [
                item
                for item in recovery_result[2]["runtime_cleanup"]
                if item.get("attempt_id") == attempt["id"] and item.get("state") == "released"
            ]
            assert len(release_rows) == 1, recovery_result[2]
            assert supervisor.attempt(attempt["id"])["status"] == "orphaned"
            assert supervisor.task(task["id"])["status"] == "orphaned"
            with supervisor.connect() as connection:
                remaining_leases = connection.execute(
                    "SELECT resource FROM resource_leases WHERE task_id = ? AND attempt_id = ?",
                    (task["id"], attempt["id"]),
                ).fetchall()
                remaining_allocation = connection.execute(
                    "SELECT pool_name, value FROM runtime_allocations WHERE attempt_id = ?",
                    (attempt["id"],),
                ).fetchone()
            assert not remaining_leases
            assert remaining_allocation is None
            service_log = service_log_path.read_text(encoding="utf-8", errors="replace")
            assert runner["credential"] not in service_log
            return
        launch_receipt_deadline = time.monotonic() + 30
        durable_before_retry = supervisor._sandbox_execution_get(attempt["id"])
        while time.monotonic() < launch_receipt_deadline and (
            durable_before_retry is None
            or durable_before_retry["phase"] == "reserved"
            or not durable_before_retry["launch_driver_invocation_id"]
            or not durable_before_retry["launch_driver_pid"]
            or (
                producer_receipt is not None
                and (
                    durable_before_retry["launch_driver_invocation_id"]
                    != producer_receipt["invocation_id"]
                    or durable_before_retry["launch_driver_pid"] != producer_receipt["driver_pid"]
                )
            )
        ):
            time.sleep(0.05)
            durable_before_retry = supervisor._sandbox_execution_get(attempt["id"])
        assert durable_before_retry is not None
        assert durable_before_retry["phase"] != "reserved"
        assert durable_before_retry["launch_driver_start_id"]
        assert durable_before_retry["launch_driver_start_digest"]
        assert durable_before_retry["launch_driver_invocation_id"]
        assert durable_before_retry["launch_driver_pid"]
        if producer_receipt is not None:
            assert (
                durable_before_retry["launch_driver_invocation_id"]
                == producer_receipt["invocation_id"]
            )
            assert durable_before_retry["launch_driver_pid"] == producer_receipt["driver_pid"]
        driver_pid = durable_before_retry["launch_driver_pid"]
        start_identity_before_retry = tuple(
            durable_before_retry[field]
            for field in (
                "launch_driver_start_id",
                "launch_driver_start_digest",
                "launch_driver_invocation_id",
                "launch_driver_pid",
                "launch_driver_identity",
                "launch_driver_cgroup_path",
            )
        )
        retry_receiver, retry_sender = context.Pipe(duplex=False)
        retry_controller = context.Process(
            target=_retry_launch_driver_without_replay_from_fresh_process,
            args=(
                repo,
                identity,
                payload_command,
                _CONTAINER_MEMORY_BYTES,
                _CONTAINER_CPU_QUOTA_US,
                _CONTAINER_CPU_PERIOD_US,
                _CONTAINER_PIDS_LIMIT,
                sandbox_timeout_seconds,
                runner["credential"],
                retry_sender,
            ),
        )
        retry_controller.start()
        child_processes.append(retry_controller)
        retry_sender.close()
        assert retry_receiver.poll(20), "fresh retry controller did not reject the duplicate start"
        retry_result = retry_receiver.recv()
        retry_controller.join(timeout=5)
        assert not retry_controller.is_alive()
        assert retry_controller.exitcode == 0
        retry_receiver.close()
        assert retry_result[0] == "rejected", retry_result
        assert retry_result[1] not in {os.getpid(), controller_pid, driver_pid}
        assert retry_result[2] == "SandboxLaunchDriverServiceError"
        assert retry_result[3] == 0, "fresh retry reached systemd-run and risked replay"
        durable_after_retry = supervisor._sandbox_execution_get(attempt["id"])
        assert durable_after_retry is not None
        assert (
            tuple(
                durable_after_retry[field]
                for field in (
                    "launch_driver_start_id",
                    "launch_driver_start_digest",
                    "launch_driver_invocation_id",
                    "launch_driver_pid",
                    "launch_driver_identity",
                    "launch_driver_cgroup_path",
                )
            )
            == start_identity_before_retry
        )
        if cancel_after_start or lease_expiry_after_stop:
            running_deadline = time.monotonic() + 30
            durable = supervisor._sandbox_execution_get(attempt["id"])
            while (
                durable is not None
                and durable["phase"] != "running"
                and time.monotonic() < running_deadline
            ):
                time.sleep(0.05)
                durable = supervisor._sandbox_execution_get(attempt["id"])
            assert durable is not None and durable["phase"] == "running"
            started_marker = Path(durable["workspace_root_path"]) / "launch-driver-started"
            started_deadline = time.monotonic() + 5
            while not _entry_is_present(started_marker) and time.monotonic() < started_deadline:
                time.sleep(0.05)
            assert _entry_is_present(started_marker), "bounded payload never entered its command"

            if cancel_after_start:
                if concurrent_control is not None:
                    assert execution is not None
                    _wait_for_live_concurrent_release(
                        concurrent_control,
                        attempt=attempt,
                        execution=execution,
                        repo=repo,
                        run_root=run_root,
                        source_worktree=source_worktree,
                        workspace_root=Path(durable["workspace_root_path"]),
                    )
                # Cross the deliberately short ten-second claim lease while the
                # payload remains active; both fresh cancellation and normal exit
                # depend on the execution owner renewing the exact attempt.
                time.sleep(12)
                renewed_attempt = supervisor.attempt(attempt["id"])
                assert renewed_attempt["status"] == "working"
                assert renewed_attempt["lease_expires_at"] > initial_lease_expires_at
                assert renewed_attempt["lease_expires_at"] > int(time.time())

                wrong_credential_supervisor = GitSupervisor(repo)
                with patch.object(
                    sandbox_monitor_lifecycle,
                    "reconnect_sandbox_monitor",
                    side_effect=AssertionError("invalid runner credential reached the monitor"),
                ) as reconnect:
                    with pytest.raises(SupervisorError) as rejected:
                        wrong_credential_supervisor.terminate_worker(
                            attempt["id"], credential="not-the-enrolled-runner-credential"
                        )
                    assert rejected.value.code == "runner_authentication_failed"
                    reconnect.assert_not_called()

                result_receiver, result_sender = context.Pipe(duplex=False)
                fresh_controller = context.Process(
                    target=_terminate_worker_from_fresh_process,
                    args=(repo, attempt["id"], runner["credential"], result_sender),
                )
                fresh_controller.start()
                child_processes.append(fresh_controller)
                result_sender.close()
                assert result_receiver.poll(20), (
                    "fresh controller did not receive a monitor response"
                )
                termination_result = result_receiver.recv()
                fresh_controller.join(timeout=5)
                assert not fresh_controller.is_alive()
                assert fresh_controller.exitcode == 0
                result_receiver.close()
                assert termination_result[0] == "ok", termination_result
                assert termination_result[1] not in {driver_pid, controller_pid}
                termination = termination_result[2]
                assert termination_result[3:] == (1, 0)
                assert termination["attempt_id"] == attempt["id"]
                assert termination["execution_id"] == execution["execution_id"]
                assert termination["stop_requested"] is True
                assert termination["cleanup_verified"] is False
                assert termination["monitor_phase"] in {"stopping", "exited"}
            else:
                stopped = supervisor._sandbox_execution_request_stop(
                    attempt["id"],
                    attempt["claim_token"],
                    "live test: durable stop before attempt lease expiry",
                    credential=runner["credential"],
                )
                assert stopped["phase"] == "stopping"
                assert stopped["stop_reason"] == (
                    "live test: durable stop before attempt lease expiry"
                )
                with supervisor.connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    expired = connection.execute(
                        "UPDATE attempts SET lease_expires_at = 0, updated_at = ? "
                        "WHERE id = ? AND claim_token = ? AND status = 'working'",
                        (utc_now(), attempt["id"], attempt["claim_token"]),
                    ).rowcount
                assert expired == 1, "the exact working fixture attempt was not expired"

                reap_receiver, reap_sender = context.Pipe(duplex=False)
                lease_loss_reaper = context.Process(
                    target=_reap_expired_from_fresh_process,
                    args=(repo, int(time.time()), reap_sender),
                )
                lease_loss_reaper.start()
                child_processes.append(lease_loss_reaper)
                reap_sender.close()
                assert reap_receiver.poll(30), "fresh reaper did not quarantine the expired attempt"
                lease_loss_result = reap_receiver.recv()
                lease_loss_reaper.join(timeout=5)
                assert not lease_loss_reaper.is_alive()
                assert lease_loss_reaper.exitcode == 0
                reap_receiver.close()
                assert lease_loss_result[0] == "ok", lease_loss_result
                assert lease_loss_result[1] not in {controller_pid, driver_pid}
                assert lease_loss_result[2]["orphaned"] == []
                assert lease_loss_result[2]["runtime_cleanup"] == []
                expired_attempt = supervisor.attempt(attempt["id"])
                expired_task = supervisor.task(task["id"])
                assert expired_attempt["status"] == "terminating"
                assert expired_attempt["termination_target_status"] == "quarantined"
                assert expired_task["status"] == "cleanup_pending"
                assert expired_task["cleanup_target_status"] == "blocked"

        deadline = time.monotonic() + 30
        durable = supervisor._sandbox_execution_get(attempt["id"])
        while (
            durable is not None
            and durable["phase"] not in {"cleanup_reported", "cleanup_verified"}
            and time.monotonic() < deadline
        ):
            time.sleep(0.05)
            durable = supervisor._sandbox_execution_get(attempt["id"])
        service_log = service_log_path.read_text(encoding="utf-8", errors="replace")
        assert runner["credential"] not in service_log
        expected_cleanup_phase = "cleanup_verified" if supervised_run_worker else "cleanup_reported"
        assert durable is not None and durable["phase"] == expected_cleanup_phase, service_log
        expected_worker_credential_transport = "test_canary_fd4" if worker_canary_fd4 else "none"
        assert (
            durable["launch_plan"]["launch"]["worker_credential_transport"]
            == expected_worker_credential_transport
        )
        if cross_attempt_probes:
            if concurrent_control is None or execution is None:
                pytest.fail(
                    "cross-attempt cleanup barrier requires exact concurrent execution identity"
                )
            verified_cleanup = supervisor._sandbox_execution_verify_cleanup(
                attempt["id"],
                attempt["claim_token"],
                credential=runner["credential"],
            )
            assert verified_cleanup["phase"] == "cleanup_verified"
            assert verified_cleanup["cleanup_verification"]["observations"]
            _wait_for_live_concurrent_cleanup_verification(
                concurrent_control,
                attempt_id=attempt["id"],
                execution_id=execution["execution_id"],
            )
        if isolation_probes and durable["runc_exit_code"] != 0:
            probe_marker = Path(durable["workspace_root_path"]) / "launch-driver-started"
            probe_detail = (
                probe_marker.read_text(encoding="ascii", errors="replace")
                if probe_marker.exists()
                else "<worker did not create its probe marker>"
            )
            pytest.fail(
                f"registered worker isolation probe exited {durable['runc_exit_code']}: "
                f"{probe_detail}; service log tail:\n{service_log[-4000:]}"
            )
        if isolation_probes:
            visible_write_probes = [
                str(path) for path in isolation_write_probes if os.path.lexists(path)
            ]
            assert not visible_write_probes, (
                "worker created a write probe outside its assigned workspace: "
                f"{visible_write_probes}"
            )
            assert not os.path.lexists(isolation_tmp_scratch_path), (
                "worker /tmp scratch leaked into the host /tmp directory"
            )
            assert not os.path.lexists(isolation_home_scratch_path), (
                "worker /home/agent scratch leaked into the host filesystem"
            )
        if provider_proxy_uds:
            assert provider_probe_result is not None
            assert provider_probe_result.read_text(encoding="ascii") == (
                "attempt-uds-policy-pass\n"
            )
            if provider_proxy_cancel:
                assert provider_probe_open is not None
                assert provider_probe_open.read_text(encoding="ascii") == ("partial-connect-open\n")
            else:
                assert provider_probe_release is not None
                assert provider_probe_release.read_text(encoding="ascii") == (
                    "release-provider-probe\n"
                )
            assert provider_proxy_directory is not None
            assert provider_proxy_socket_path is not None
            assert not os.path.lexists(provider_proxy_socket_path), (
                "attempt provider proxy socket remained after production cleanup"
            )
            if expected_cleanup_phase == "cleanup_reported":
                provider_artifact = durable["provider_proxy_artifact"]
                assert provider_artifact["directory"]["path"] == str(provider_proxy_directory)
                provider_directory_info = provider_proxy_directory.lstat()
                assert (provider_directory_info.st_dev, provider_directory_info.st_ino) == (
                    provider_artifact["directory"]["device"],
                    provider_artifact["directory"]["inode"],
                ), "cleanup_reported provider directory no longer matches its durable inode fence"
                assert list(provider_proxy_directory.iterdir()) == [], (
                    "provider directory must be empty, but remain fenced until independent cleanup verification"
                )
            else:
                assert not os.path.lexists(provider_proxy_directory), (
                    "verified provider proxy directory remained after production cleanup"
                )
        if not cancel_after_start and not timeout_after_start and not lease_expiry_after_stop:
            assert durable["runc_exit_code"] == 0
        else:
            assert type(durable["runc_exit_code"]) is int
            assert durable["runc_exit_code"] != 0
        attempt_after_execution = supervisor.attempt(attempt["id"])
        assert durable["launch_driver_pid"] == driver_pid
        assert (
            durable["launch_driver_invocation_id"]
            == durable_before_retry["launch_driver_invocation_id"]
        )
        assert durable["launch_driver_identity"] == durable_before_retry["launch_driver_identity"]
        assert (
            durable["launch_driver_cgroup_path"]
            == durable_before_retry["launch_driver_cgroup_path"]
        )
        assert durable["launch_driver_cgroup_path"] == (
            f"{durable['attempt_slice_cgroup_path']}/{service_unit}"
        )
        if producer_receipt is not None:
            assert producer_receipt["service_unit"] == service_unit
            assert producer_receipt["driver_pid"] == durable["launch_driver_pid"]
            assert producer_receipt["driver_identity"] == durable["launch_driver_identity"]
            assert producer_receipt["invocation_id"] == durable["launch_driver_invocation_id"]
            assert producer_receipt["control_group"] == durable["launch_driver_cgroup_path"]
        assert durable["wrapper_cgroup_path"] != durable["attempt_slice_cgroup_path"]
        assert not Path(durable["wrapper_cgroup_path"]).is_relative_to(
            Path(durable["attempt_slice_cgroup_path"])
        )
        assert (
            Path(durable["cgroup_path"]).parent.as_posix() == durable["attempt_slice_cgroup_path"]
        )
        marker = Path(durable["workspace_root_path"]) / "launch-driver-marker"
        if cancel_after_start or timeout_after_start or lease_expiry_after_stop:
            assert _entry_is_present(Path(durable["workspace_root_path"]) / "launch-driver-started")
            assert not _entry_is_present(marker)
        else:
            expected_marker = "production-driver-ran\n"
            if isolation_probes:
                expected_marker += "containment-probes-passed\n"
                assert not os.path.lexists(isolation_tmp_scratch_path)
                assert not os.path.lexists(isolation_home_scratch_path)
                assert all(not os.path.lexists(path) for path in isolation_write_probes)
            assert marker.read_text(encoding="ascii") == expected_marker
        if coding_task:
            worker_workspace = Path(durable["workspace_root_path"])
            assert (worker_workspace / coding_script_name).read_text(encoding="ascii") == (
                coding_source
            )
            assert (worker_workspace / coding_test_output_name).read_text(
                encoding="ascii"
            ) == "coding-task-pass\n"
            assert "probe-ok:coding-task" in (worker_workspace / "launch-driver-started").read_text(
                encoding="ascii"
            )
        if worker_canary_fd4:
            worker_workspace = Path(durable["workspace_root_path"])
            assert expected_worker_canary_result is not None
            assert (worker_workspace / "worker-canary-fd4-result").read_text(
                encoding="ascii"
            ) == expected_worker_canary_result
        assert not _entry_is_present(source_worktree / "launch-driver-marker")
        with supervisor.connect() as connection:
            events = connection.execute(
                "SELECT sequence, event_type FROM events "
                "WHERE json_extract(payload_json, '$.execution_id') = ? "
                "AND event_type IN (?, ?, ?, ?, ?, ?) ORDER BY sequence",
                (
                    execution["execution_id"],
                    "sandbox.execution_launch_submission_authorized",
                    "sandbox.execution_launched",
                    "sandbox.execution_running",
                    "sandbox.execution_stop_requested",
                    "sandbox.execution_exited",
                    "sandbox.execution_cleanup_reported",
                ),
            ).fetchall()
        expected_events = [
            "sandbox.execution_launch_submission_authorized",
            "sandbox.execution_launched",
            "sandbox.execution_running",
        ]
        if cancel_after_start or timeout_after_start or lease_expiry_after_stop:
            expected_events.append("sandbox.execution_stop_requested")
        expected_events.extend(["sandbox.execution_exited", "sandbox.execution_cleanup_reported"])
        assert [row["event_type"] for row in events] == expected_events
        assert len({row["sequence"] for row in events}) == len(expected_events)
        with supervisor.connect() as connection:
            event_bodies = "\n".join(
                row[0]
                for row in connection.execute(
                    "SELECT payload_json FROM events "
                    "WHERE json_extract(payload_json, '$.attempt_id') = ?",
                    (attempt["id"],),
                )
            )
        assert runner["credential"] not in event_bodies
        assert runner["credential"].encode("utf-8") not in Path(supervisor.db_path).read_bytes()
        if test_worker_canary is not None:
            canary_text = test_worker_canary.decode("ascii")
            database_bytes = Path(supervisor.db_path).read_bytes()
            assert canary_text not in event_bodies
            assert test_worker_canary not in database_bytes
            if service_log_path.exists():
                assert test_worker_canary not in service_log_path.read_bytes()
        assert not (Path(execution["state_path"]) / "launch-driver-request.json").exists()
        assert durable["phase"] == expected_cleanup_phase
        assert durable["cleanup_receipt"]["version"] == 3
        assert durable["cleanup_receipt"]["verification_status"] == "unverified"
        action = durable["cleanup_receipt"]["action"]
        assert action["operation"] == "runc-delete-force"
        assert action["argv"] == [
            str(runc_pin.path),
            "--root",
            str(state_root),
            "delete",
            "--force",
            execution["container_id"],
        ]
        assert action["actor"]["pid"] == durable["launch_driver_pid"]
        assert action["actor"]["identity"] == durable["launch_driver_identity"]
        assert action["returncode"] == 0
        assert action["state_entry_absent_immediately_after_delete"] is True
        assert not (state_root / execution["container_id"]).exists()

        imported_submission = None
        if import_result_after_cleanup:
            verified_before_import = supervisor._sandbox_execution_verify_cleanup(
                attempt["id"],
                attempt["claim_token"],
                credential=runner["credential"],
            )
            assert verified_before_import["phase"] == "cleanup_verified"
            assert verified_before_import["runc_exit_code"] == 0
            assert verified_before_import["cleanup_verification"]["observations"]
            assert not _entry_is_present(
                Path(verified_before_import["workspace_root_path"]) / ".git"
            )

            imported_submission = supervisor.import_sandbox_execution_result(
                attempt["id"], attempt["claim_token"], credential=runner["credential"]
            )
            assert imported_submission["status"] == "pending_qc"
            assert imported_submission["commit_sha"]
            assert supervisor.attempt(attempt["id"])["status"] == "submitted"
            assert supervisor.task(task["id"])["status"] == "qc_review"

            def git_text(*arguments: str) -> str:
                completed = subprocess.run(
                    ["git", "-C", str(repo), *arguments],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                return completed.stdout.strip()

            def git_bytes(*arguments: str) -> bytes:
                completed = subprocess.run(
                    ["git", "-C", str(repo), *arguments],
                    check=True,
                    capture_output=True,
                    timeout=10,
                )
                return completed.stdout

            assert git_text("rev-parse", "HEAD") == task["base_sha"]
            assert (
                git_text("rev-parse", f"{imported_submission['commit_sha']}^") == task["base_sha"]
            )
            imported_paths = git_text(
                "diff",
                "--name-only",
                "--no-renames",
                task["base_sha"],
                imported_submission["commit_sha"],
            ).splitlines()
            expected_imported_paths = ["launch-driver-marker", "launch-driver-started"]
            if coding_task:
                expected_imported_paths.extend([coding_script_name, coding_test_output_name])
            if worker_canary_fd4:
                expected_imported_paths.append("worker-canary-fd4-result")
            assert imported_paths == expected_imported_paths
            assert (
                git_text("show", f"{imported_submission['commit_sha']}:launch-driver-started")
                == (Path(verified_before_import["workspace_root_path"]) / "launch-driver-started")
                .read_text(encoding="ascii")
                .strip()
            )
            assert git_text(
                "show", f"{imported_submission['commit_sha']}:launch-driver-marker"
            ) == expected_marker.rstrip("\n")
            if coding_task:
                imported_coding_source = git_bytes(
                    "show",
                    f"{imported_submission['commit_sha']}:{coding_script_name}",
                )
                imported_coding_test_output = git_bytes(
                    "show",
                    f"{imported_submission['commit_sha']}:{coding_test_output_name}",
                )
                workspace = Path(verified_before_import["workspace_root_path"])
                assert imported_coding_source == coding_source.encode("ascii")
                assert imported_coding_source == (workspace / coding_script_name).read_bytes()
                assert imported_coding_test_output == b"coding-task-pass\n"
                assert (
                    imported_coding_test_output
                    == (workspace / coding_test_output_name).read_bytes()
                )
            if worker_canary_fd4:
                assert test_worker_canary is not None and expected_worker_canary_result is not None
                assert git_bytes(
                    "show",
                    f"{imported_submission['commit_sha']}:worker-canary-fd4-result",
                ) == expected_worker_canary_result.encode("ascii")
            assert (
                subprocess.run(
                    ["git", "-C", str(source_worktree), "status", "--porcelain=v1"],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                ).stdout
                == ""
            )

            with supervisor.connect() as connection:
                imported_row = connection.execute(
                    "SELECT * FROM result_imports WHERE attempt_id = ?",
                    (attempt["id"],),
                ).fetchone()
                import_source = supervisor._sandbox_execution_result_import_source(
                    connection, attempt["id"], attempt["claim_token"]
                )
            assert imported_row is not None
            assert imported_row["phase"] == "submitted"
            assert imported_row["source_kind"] == "sandbox_execution"
            assert imported_row["sandbox_execution_id"] == execution["execution_id"]
            assert (
                imported_row["sandbox_cleanup_receipt_digest"]
                == import_source["cleanup_receipt_digest"]
            )
            assert imported_row["worker_pid"] is None
            assert imported_row["worker_identity"] == ""
            assert imported_row["worker_exit_receipt_json"] == ""

        if lease_expiry_after_stop:
            # cleanup_reported is committed before the systemd service exits.
            # Let that exact invocation quiesce before the independent reaper
            # verifies its absence; never treat a still-running cleanup actor as
            # independent teardown proof.
            assert service_unit is not None
            driver_exit_deadline = time.monotonic() + 10
            driver_after_cleanup = _unit_properties(service_unit, ("ActiveState", "MainPID"))
            while time.monotonic() < driver_exit_deadline and (
                driver_after_cleanup["MainPID"] != "0"
                or driver_after_cleanup["ActiveState"] not in {"failed", "inactive"}
            ):
                time.sleep(0.05)
                driver_after_cleanup = _unit_properties(service_unit, ("ActiveState", "MainPID"))
            assert driver_after_cleanup["MainPID"] == "0"
            assert driver_after_cleanup["ActiveState"] in {"failed", "inactive"}

        with supervisor.connect() as connection:
            lease_before_rows = connection.execute(
                "SELECT resource, task_id, attempt_id, lease_expires_at "
                "FROM resource_leases WHERE task_id = ? ORDER BY resource",
                (task["id"],),
            ).fetchall()
            runtime_before = connection.execute(
                "SELECT state FROM runtime_environments WHERE attempt_id = ?",
                (attempt["id"],),
            ).fetchone()
            allocations_before = connection.execute(
                "SELECT pool_name, value, lease_expires_at FROM runtime_allocations "
                "WHERE attempt_id = ?",
                (attempt["id"],),
            ).fetchall()
        lease_before = {row["resource"]: row for row in lease_before_rows}
        assert set(lease_before) == set(task["resources"])
        assert len(lease_before) == (
            2
            + (2 if provider_proxy_uds else 0)
            + (1 if provider_proxy_cancel else 0)
            + (2 if coding_task else 0)
            + (1 if worker_canary_fd4 else 0)
        )
        assert len({row["lease_expires_at"] for row in lease_before.values()}) == 1
        expected_lease_expiry = next(iter(lease_before.values()))["lease_expires_at"]
        if lease_expiry_after_stop:
            assert attempt_after_execution["status"] == "terminating"
            assert attempt_after_execution["termination_target_status"] == "quarantined"
            assert supervisor.task(task["id"])["cleanup_target_status"] == "blocked"
            for lease in lease_before.values():
                assert lease["task_id"] == task["id"]
                assert lease["attempt_id"] == attempt["id"]
                assert lease["lease_expires_at"] == journal_module.CLEANUP_FENCE_EPOCH
        elif imported_submission is None:
            for lease in lease_before.values():
                assert lease["task_id"] == task["id"]
                assert lease["attempt_id"] == attempt["id"]
                assert lease["lease_expires_at"] == attempt_after_execution["lease_expires_at"]
        else:
            for lease in lease_before.values():
                assert lease["task_id"] == task["id"]
                assert lease["attempt_id"] is None
                assert lease["lease_expires_at"] > attempt_after_execution["lease_expires_at"]
        assert len(allocations_before) == 1
        assert runtime_before is not None and runtime_before["state"] != "released"
        if cross_attempt_probes:
            assert shared_port_range is not None
            allocation = allocations_before[0]
            assert allocation["pool_name"] == "LAUNCH_DRIVER_TEST_PORT"
            assert shared_port_range[0] <= allocation["value"] <= shared_port_range[1]
            assert allocation["lease_expires_at"] == expected_lease_expiry
        else:
            assert [
                (row["pool_name"], row["value"], row["lease_expires_at"])
                for row in allocations_before
            ] == [("LAUNCH_DRIVER_TEST_PORT", runtime_test_port, expected_lease_expiry)]

        reap_receiver, reap_sender = context.Pipe(duplex=False)
        import_probe = (
            (task["id"], attempt["id"], imported_submission["id"])
            if imported_submission is not None
            else None
        )
        fresh_reaper = context.Process(
            target=_reap_expired_from_fresh_process,
            args=(repo, attempt_after_execution["lease_expires_at"] + 1, reap_sender, import_probe),
        )
        fresh_reaper.start()
        child_processes.append(fresh_reaper)
        reap_sender.close()
        assert reap_receiver.poll(30), "fresh supervisor did not finish the real reaper"
        reap_result = reap_receiver.recv()
        fresh_reaper.join(timeout=5)
        assert not fresh_reaper.is_alive()
        assert fresh_reaper.exitcode == 0
        reap_receiver.close()
        assert reap_result[0] == "ok", reap_result
        assert reap_result[1] not in {controller_pid, driver_pid}
        reaped = reap_result[2]
        if lease_expiry_after_stop:
            if not reaped["runtime_cleanup"]:
                # If the first bounded reaper pass leaves cleanup unverified,
                # keep the attempt quarantined while a separate fresh process
                # runs the exact production verifier; then let a fresh reaper
                # release runtime resources while preserving the blocked task.
                pending_verification = supervisor._sandbox_execution_get(attempt["id"])
                assert pending_verification is not None
                assert pending_verification["phase"] == "cleanup_reported"
                verify_receiver, verify_sender = context.Pipe(duplex=False)
                cleanup_verifier = context.Process(
                    target=_verify_sandbox_cleanup_from_fresh_process,
                    args=(repo, attempt["id"], attempt["claim_token"], verify_sender),
                )
                cleanup_verifier.start()
                child_processes.append(cleanup_verifier)
                verify_sender.close()
                assert verify_receiver.poll(30), (
                    "fresh cleanup verifier did not finish exact lease-loss verification"
                )
                verify_result = verify_receiver.recv()
                cleanup_verifier.join(timeout=5)
                assert not cleanup_verifier.is_alive()
                assert cleanup_verifier.exitcode == 0
                verify_receiver.close()
                if verify_result[0] != "ok":
                    verify_durable = supervisor._sandbox_execution_get(attempt["id"])
                    assert verify_durable is not None
                    unit_names = {
                        "monitor": verify_durable["wrapper_unit"],
                        "launch_driver": verify_durable["launch_driver_unit"],
                        "scope": verify_durable["scope_unit"],
                        "attempt_slice": verify_durable["attempt_slice_unit"],
                    }
                    unit_diagnostics = {
                        name: _unit_properties(
                            unit,
                            (
                                "ActiveState",
                                "ControlGroup",
                                "Id",
                                "InvocationID",
                                "LoadState",
                            )
                            + (() if name in {"scope", "attempt_slice"} else ("MainPID",)),
                        )
                        for name, unit in unit_names.items()
                    }
                    pytest.fail(
                        f"fresh cleanup verification failed: {verify_result}; "
                        f"exact unit state={unit_diagnostics!r}"
                    )
                assert verify_result[1] not in {controller_pid, driver_pid}
                assert verify_result[2] == "cleanup_verified"

                retry_receiver, retry_sender = context.Pipe(duplex=False)
                retry_reaper = context.Process(
                    target=_reap_expired_from_fresh_process,
                    args=(repo, attempt_after_execution["lease_expires_at"] + 1, retry_sender),
                )
                retry_reaper.start()
                child_processes.append(retry_reaper)
                retry_sender.close()
                assert retry_receiver.poll(30), (
                    "fresh reaper did not resume cleanup after independent verification"
                )
                retry_result = retry_receiver.recv()
                retry_reaper.join(timeout=5)
                assert not retry_reaper.is_alive()
                assert retry_reaper.exitcode == 0
                retry_receiver.close()
                assert retry_result[0] == "ok", retry_result
                assert retry_result[1] not in {controller_pid, driver_pid}
                reaped = retry_result[2]

            assert reaped["orphaned"] == []
            assert {"attempt_id": attempt["id"], "state": "released"} in reaped["runtime_cleanup"]
            assert {
                "task_id": task["id"],
                "attempt_id": attempt["id"],
                "state": "released",
            } in reaped["runtime_cleanup"]
            assert supervisor.attempt(attempt["id"])["status"] == "quarantined"
            assert supervisor.attempt(attempt["id"])["termination_target_status"] == ""
            assert supervisor.task(task["id"])["status"] == "blocked"
            assert supervisor.task(task["id"])["cleanup_target_status"] == ""
        elif imported_submission is None:
            if cross_attempt_probes:
                # The reaper scans the shared repository, so the peer child may
                # have atomically orphaned this attempt in its own pass.
                cleanup_deadline = time.monotonic() + 20
                while time.monotonic() < cleanup_deadline and (
                    supervisor.attempt(attempt["id"])["status"] != "orphaned"
                    or supervisor.task(task["id"])["status"] != "orphaned"
                ):
                    time.sleep(0.05)
                assert supervisor.attempt(attempt["id"])["status"] == "orphaned"
                assert supervisor.task(task["id"])["status"] == "orphaned"
            else:
                assert reaped["orphaned"] == [task["id"]]
                assert reaped["runtime_cleanup"] == [
                    {"attempt_id": attempt["id"], "state": "released"}
                ]
            assert supervisor.attempt(attempt["id"])["status"] == "orphaned"
            assert supervisor.task(task["id"])["status"] == "orphaned"
        else:
            assert reaped["orphaned"] == []
            assert reaped["runtime_cleanup"] == []
            assert supervisor.attempt(attempt["id"])["status"] == "submitted"
            assert supervisor.task(task["id"])["status"] == "qc_review"
            recovered_before, recovered_after = reap_result[3:5]
            assert recovered_before == recovered_after
            assert recovered_before == {
                "task_status": "qc_review",
                "attempt_status": "submitted",
                "submission_id": imported_submission["id"],
                "submission_status": "pending_qc",
                "submission_commit_sha": imported_submission["commit_sha"],
                "task_latest_submission_id": imported_submission["id"],
                "execution_id": execution["execution_id"],
                "execution_phase": "cleanup_verified",
            }
        with supervisor.connect() as connection:
            lease_resources = sorted(lease_before)
            placeholders = ", ".join("?" for _ in lease_resources)
            lease_after_rows = connection.execute(
                "SELECT resource, task_id, attempt_id, lease_expires_at FROM resource_leases "
                f"WHERE resource IN ({placeholders}) ORDER BY resource",
                lease_resources,
            ).fetchall()
            runtime_after = connection.execute(
                "SELECT state FROM runtime_environments WHERE attempt_id = ?",
                (attempt["id"],),
            ).fetchone()
            allocations_after = connection.execute(
                "SELECT pool_name, value FROM runtime_allocations WHERE attempt_id = ?",
                (attempt["id"],),
            ).fetchall()
        lease_after = {row["resource"]: row for row in lease_after_rows}
        assert set(lease_after) == set(lease_before)
        assert runtime_after is not None
        if lease_expiry_after_stop:
            for lease in lease_after.values():
                assert lease["task_id"] is None
                assert lease["attempt_id"] is None
                assert lease["lease_expires_at"] == 0
            assert runtime_after["state"] == "released"
            assert allocations_after == []
        elif imported_submission is None:
            for resource, lease in lease_after.items():
                assert lease["task_id"] is None
                assert lease["attempt_id"] is None
                assert lease["lease_expires_at"] == 0
                assert lease_before[resource]["task_id"] == task["id"]
            assert runtime_after["state"] == "released"
            assert allocations_after == []
        else:
            for resource, lease in lease_after.items():
                assert lease["task_id"] == task["id"]
                assert lease["attempt_id"] is None
                assert lease["lease_expires_at"] == lease_before[resource]["lease_expires_at"]
            assert runtime_after["state"] == runtime_before["state"]
            assert [(row["pool_name"], row["value"]) for row in allocations_after] == [
                ("LAUNCH_DRIVER_TEST_PORT", runtime_test_port)
            ]
            qc_reap_receiver, qc_reap_sender = context.Pipe(duplex=False)
            fresh_qc_reaper = context.Process(
                target=_reap_expired_from_fresh_process,
                args=(repo, expected_lease_expiry + 1, qc_reap_sender, import_probe),
            )
            fresh_qc_reaper.start()
            child_processes.append(fresh_qc_reaper)
            qc_reap_sender.close()
            assert qc_reap_receiver.poll(30), "fresh supervisor did not expire the QC reservation"
            qc_reap_result = qc_reap_receiver.recv()
            fresh_qc_reaper.join(timeout=5)
            assert not fresh_qc_reaper.is_alive()
            assert fresh_qc_reaper.exitcode == 0
            qc_reap_receiver.close()
            assert qc_reap_result[0] == "ok", qc_reap_result
            assert qc_reap_result[1] not in {controller_pid, driver_pid}
            qc_reaped = qc_reap_result[2]
            assert qc_reaped["conflicted"] == [task["id"]]
            assert qc_reaped["orphaned"] == []
            assert {
                tuple(sorted(item.items()))
                for item in qc_reaped["runtime_cleanup"]
                if item.get("task_id") == task["id"]
            } == {
                tuple(
                    sorted(
                        {
                            "task_id": task["id"],
                            "attempt_id": attempt["id"],
                            "state": "released",
                        }.items()
                    )
                )
            }
            recovered_before_expiry, recovered_after_expiry = qc_reap_result[3:5]
            assert recovered_before_expiry == recovered_after
            assert recovered_after_expiry == {
                "task_status": "conflicted",
                "attempt_status": "submitted",
                "submission_id": imported_submission["id"],
                "submission_status": "pending_qc",
                "submission_commit_sha": imported_submission["commit_sha"],
                "task_latest_submission_id": imported_submission["id"],
                "execution_id": execution["execution_id"],
                "execution_phase": "cleanup_verified",
            }
            assert supervisor.task(task["id"])["status"] == "conflicted"
            assert supervisor.attempt(attempt["id"])["status"] == "submitted"
            assert supervisor.submission(imported_submission["id"])["status"] == "pending_qc"
            with supervisor.connect() as connection:
                final_lease_rows = connection.execute(
                    "SELECT resource, task_id, attempt_id, lease_expires_at FROM resource_leases "
                    f"WHERE resource IN ({placeholders}) ORDER BY resource",
                    lease_resources,
                ).fetchall()
                final_runtime = connection.execute(
                    "SELECT state FROM runtime_environments WHERE attempt_id = ?",
                    (attempt["id"],),
                ).fetchone()
                final_allocations = connection.execute(
                    "SELECT pool_name, value FROM runtime_allocations WHERE attempt_id = ?",
                    (attempt["id"],),
                ).fetchall()
            assert {row["resource"] for row in final_lease_rows} == set(lease_before)
            assert all(
                row["task_id"] is None
                and row["attempt_id"] is None
                and row["lease_expires_at"] == 0
                for row in final_lease_rows
            )
            assert final_runtime is not None and final_runtime["state"] == "released"
            assert final_allocations == []
        verified = supervisor._sandbox_execution_get(attempt["id"])
        assert verified is not None
        assert verified["phase"] == "cleanup_verified"
        if provider_proxy_uds:
            assert provider_proxy_directory is not None
            assert provider_proxy_socket_path is not None
            assert not os.path.lexists(provider_proxy_socket_path)
            assert not os.path.lexists(provider_proxy_directory), (
                "provider proxy directory remained after independent cleanup verification"
            )
        if cancel_after_start or timeout_after_start or lease_expiry_after_stop:
            assert verified["runc_exit_code"] != 0
            if timeout_after_start:
                assert verified["stop_reason"] == "execution_timeout"
            if lease_expiry_after_stop:
                assert verified["stop_reason"] == (
                    "live test: durable stop before attempt lease expiry"
                )
                assert verified["failure_reason"] == (
                    launch_service._LAUNCH_DRIVER_LEASE_LOSS_REASON
                )
            with supervisor.connect() as connection:
                with pytest.raises(SupervisorError) as result_rejected:
                    journal_module._require_sandbox_execution_result_eligible(
                        connection, attempt["id"]
                    )
            assert result_rejected.value.code == "sandbox_result_unverified"
        observations = verified["cleanup_verification"]["observations"]
        if lease_expiry_after_stop:
            assert observations["units"]["launch_driver"]["active_state"] in {
                "failed",
                "inactive",
                "not-found",
            }
        assert all(item["absent"] for item in observations["processes"].values())
        assert all(observations["cgroups"].values())
        assert observations["paths"]["runc_state_entry_absent"] is True
        assert observations["paths"]["monitor_socket"]["absent"] is True
        assert not Path(durable["bundle_path"]).exists()
        assert not state_root.exists()
        if host_process_sentinel is not None:
            assert host_process_sentinel.poll() is None, (
                "synthetic host process sentinel exited before the worker probe completed; "
                f"pid={host_process_sentinel.pid}"
            )
    finally:
        if (
            provider_probe_release is not None
            and not provider_proxy_cancel
            and provider_probe_release.parent.is_dir()
        ):
            try:
                provider_probe_release.write_text("release-provider-probe\n", encoding="ascii")
            except OSError as error:
                provider_probe_release_error = error
        for child in child_processes:
            child.join(timeout=30)
        live_children = [child.pid for child in child_processes if child.is_alive()]
        if live_children:
            pytest.fail(
                "controller child processes are not quiescent; preserving the exact "
                f"fixture and service state at {run_root}; pids={live_children}"
            )
        if user_manager_restart_uncertain:
            pytest.fail(
                "user-manager restart outcome or postflight remains uncertain; no retry, unit "
                "stop, fixture deletion, or automatic recovery was attempted. Preserve the "
                f"disposable VM and exact fixture at {run_root}; manually inspect user@UID.service "
                "and the exact ACP fixture units before recovery."
            )
        driver_safe = _stop_attempted_units_and_check_quiescence(
            systemctl, service_unit, service_start_attempted, slice_unit, slice_start_attempted
        )
        monitor_safe = False
        if driver_safe:
            monitor_safe = _stop_attempted_units_and_check_quiescence(
                systemctl, monitor_unit, monitor_start_attempted, None, False
            )
        safe_to_remove = driver_safe and monitor_safe
        if safe_to_remove:
            if host_process_sentinel is not None:
                try:
                    if host_process_sentinel.poll() is None:
                        host_process_sentinel.terminate()
                except ProcessLookupError:
                    pass
                try:
                    host_process_sentinel.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        host_process_sentinel.kill()
                    except ProcessLookupError:
                        pass
                    try:
                        host_process_sentinel.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pytest.fail(
                            "synthetic host process sentinel did not terminate after ACP "
                            "units were confirmed quiescent; "
                            f"pid={host_process_sentinel.pid}"
                        )
            isolation_cleanup_errors: list[str] = []
            if isolation_socket is not None:
                isolation_socket.close()
                isolation_socket = None
            for path in isolation_write_probes:
                try:
                    _remove_live_isolation_write_probe(path)
                except BaseException as error:
                    isolation_cleanup_errors.append(f"{path}: {error}")
            for path in (isolation_tmp_scratch_path, isolation_home_scratch_path):
                try:
                    _remove_live_isolation_scratch(path, isolation_scratch_content)
                except BaseException as error:
                    isolation_cleanup_errors.append(f"{path}: {error}")
            for path, token, identity, privileged in isolation_sentinels.values():
                try:
                    _remove_live_isolation_sentinel(path, token, identity, privileged=privileged)
                except BaseException as error:
                    isolation_cleanup_errors.append(f"{path}: {error}")
            registered_sentinel_paths = {item[0] for item in isolation_sentinels.values()}
            unregistered_sentinel_paths: list[Path] = []
            for path, _token, _privileged in isolation_sentinel_candidates:
                if path not in registered_sentinel_paths and os.path.lexists(path):
                    unregistered_sentinel_paths.append(path)
                    isolation_cleanup_errors.append(
                        f"{path}: sentinel creation did not return an identity; preserving artifact"
                    )
            if isolation_socket_path is not None and os.path.lexists(isolation_socket_path):
                try:
                    socket_info = isolation_socket_path.lstat()
                    if (
                        not stat.S_ISSOCK(socket_info.st_mode)
                        or isolation_socket_identity is None
                        or (socket_info.st_dev, socket_info.st_ino) != isolation_socket_identity
                    ):
                        raise AssertionError("host-only socket identity changed")
                    isolation_socket_path.unlink()
                except BaseException as error:
                    isolation_cleanup_errors.append(f"{isolation_socket_path}: {error}")
            sibling_has_remaining_sentinel = isolation_sibling_root is not None and any(
                path.is_relative_to(isolation_sibling_root) and os.path.lexists(path)
                for path, _token, _privileged in isolation_sentinel_candidates
            )
            if (
                isolation_sibling_root is not None
                and os.path.lexists(isolation_sibling_root)
                and not sibling_has_remaining_sentinel
            ):
                try:
                    sibling_info = isolation_sibling_root.lstat()
                    if (
                        not stat.S_ISDIR(sibling_info.st_mode)
                        or isolation_sibling_identity is None
                        or (sibling_info.st_dev, sibling_info.st_ino) != isolation_sibling_identity
                    ):
                        raise AssertionError("sibling-worktree sentinel directory changed")
                    sibling_status = subprocess.run(
                        ["git", "-C", str(isolation_sibling_root), "status", "--porcelain=v1"],
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    ).stdout
                    if sibling_status:
                        raise AssertionError("sibling worktree has unexpected changes")
                    subprocess.run(
                        ["git", "-C", str(repo), "worktree", "remove", str(isolation_sibling_root)],
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if os.path.lexists(isolation_sibling_root):
                        raise AssertionError("sibling worktree removal left its exact path behind")
                except BaseException as error:
                    isolation_cleanup_errors.append(f"{isolation_sibling_root}: {error}")
            for directory, identity in reversed(isolation_created_directories):
                if not os.path.lexists(directory):
                    continue
                try:
                    info = directory.lstat()
                    if (
                        not stat.S_ISDIR(info.st_mode)
                        or (info.st_dev, info.st_ino) != identity
                        or any(directory.iterdir())
                    ):
                        raise AssertionError("test-created config directory changed or is nonempty")
                    directory.rmdir()
                except BaseException as error:
                    isolation_cleanup_errors.append(f"{directory}: {error}")
            if isolation_cleanup_errors:
                pytest.fail(
                    "isolation fixtures were not removed exactly; preserving the test tree at "
                    f"{run_root}: " + "; ".join(isolation_cleanup_errors)
                )
            _remove_private_test_tree(run_root)
        else:
            teardown_error = (
                "exact production-driver test units are not quiescent; preserving "
                f"artifacts at {run_root}"
            )
            if provider_probe_release_error is not None:
                teardown_error += f"; release marker also failed: {provider_probe_release_error}"
            pytest.fail(teardown_error)
        if provider_probe_release_error is not None:
            pytest.fail(
                "provider proxy release marker failed, but exact unit stop/quiescence and "
                "fixture teardown completed: "
                f"{provider_probe_release_error}"
            )


@pytest.mark.skipif(
    not _LIVE_ENABLED or os.environ.get("ACP_LIVE_CONCURRENT_ATTEMPTS") != "1",
    reason=(
        "set ACP_RUN_SANDBOX_WORKER_LIFECYCLE=1 and ACP_LIVE_CONCURRENT_ATTEMPTS=1 "
        "on a disposable supported Linux host"
    ),
)
def test_live_concurrent_attempts_use_distinct_scopes_and_clean_up() -> None:
    """Observe two fresh no-model cancellation runs active at the same time."""

    source_root = Path(__file__).resolve().parents[1]
    if not sys.platform.startswith("linux") or os.geteuid() == 0:
        pytest.fail("concurrent live proof requires an unprivileged Linux user")
    if not source_root.is_relative_to(Path("/tmp")):
        pytest.fail("run this opt-in proof from a disposable checkout beneath /tmp")
    if os.environ.get("ACP_OCI_TEST_RUNC_VERSION") != _SUPPORTED_RUNC_VERSION:
        pytest.fail("set ACP_OCI_TEST_RUNC_VERSION=1.5.2 for this exact live proof")
    runc_path = Path(os.environ.get("ACP_OCI_TEST_RUNC", "/usr/bin/runc"))
    if not runc_path.is_file():
        pytest.fail("set ACP_OCI_TEST_RUNC to the trusted runc 1.5.2 executable")
    runc_path = runc_path.resolve(strict=True)
    runc_info = runc_path.lstat()
    if (
        not stat.S_ISREG(runc_info.st_mode)
        or stat.S_ISLNK(runc_info.st_mode)
        or runc_info.st_uid != 0
        or stat.S_IMODE(runc_info.st_mode) & 0o022
    ):
        pytest.fail("concurrent live proof requires a root-owned, non-group/world-writable runc")

    systemctl = str(sandbox_attestation._trusted_systemctl_executable())
    systemd_environment = sandbox_attestation._trusted_systemd_command_environment()
    if _systemd_command([systemctl, "--user", "show-environment"]).returncode != 0:
        pytest.fail("active systemd user manager is required")

    def acp_scope_states() -> dict[str, tuple[str, str]]:
        result = _systemd_command(
            [
                systemctl,
                "--user",
                "list-units",
                "--all",
                "--type=scope",
                "--no-legend",
                "--plain",
            ]
        )
        if result.returncode != 0:
            raise RuntimeError(f"could not inspect systemd scopes: {result.stderr[-2000:]}")
        states: dict[str, tuple[str, str]] = {}
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 4 and fields[0].startswith("acp-") and fields[0].endswith(".scope"):
                states[fields[0]] = (fields[2], fields[3])
        return states

    preexisting = {
        unit
        for unit, (active_state, _sub_state) in acp_scope_states().items()
        if active_state not in {"inactive", "failed"}
    }
    if preexisting:
        pytest.fail(
            f"refusing concurrent proof with pre-existing ACP scopes: {sorted(preexisting)}"
        )

    control_root = Path(tempfile.mkdtemp(prefix="acp-live-concurrent-control-", dir="/tmp"))
    control_info = control_root.lstat()
    if (
        not stat.S_ISDIR(control_info.st_mode)
        or stat.S_ISLNK(control_info.st_mode)
        or control_info.st_uid != os.geteuid()
        or stat.S_IMODE(control_info.st_mode) != 0o700
    ):
        pytest.fail("concurrent control root is not a private test-owned directory")

    shared_fixture_root = Path(tempfile.mkdtemp(prefix="acp-live-concurrent-shared-", dir="/tmp"))
    shared_fixture_info = shared_fixture_root.lstat()
    shared_fixture_identity = (shared_fixture_info.st_dev, shared_fixture_info.st_ino)
    try:
        rootfs_source = shared_fixture_root / "rootfs-source"
        rootfs_source.mkdir(mode=0o755)
        for directory in (
            "bin",
            "dev",
            "etc",
            "home/agent",
            "proc",
            "run",
            "tmp",
            "workspace",
        ):
            (rootfs_source / directory).mkdir(parents=True, exist_ok=True, mode=0o755)
        busybox_value = os.environ.get("ACP_OCI_TEST_BUSYBOX") or shutil.which("busybox")
        if busybox_value is None:
            pytest.fail("concurrent live proof requires the trusted BusyBox executable")
        _busybox_version, busybox_applets = _copy_busybox_closure(
            Path(busybox_value).resolve(strict=True), rootfs_source
        )
        required_applets = {
            "cat",
            "ln",
            "mv",
            "printf",
            "rm",
            "sh",
            "sleep",
            "test",
            "touch",
        }
        if not required_applets.issubset(busybox_applets):
            pytest.fail(
                "trusted BusyBox lacks cross-attempt probe applets: "
                f"{sorted(required_applets - busybox_applets)}"
            )
        repo_root = shared_fixture_root / "repo"
        repo_root.mkdir(mode=0o700)
        shared_repo = init_repo(repo_root)
        shared_port_start: int | None = None
        for _ in range(32):
            first_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                first_probe.bind(("127.0.0.1", 0))
                candidate = first_probe.getsockname()[1]
            finally:
                first_probe.close()
            if candidate >= 65535:
                continue
            second_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                second_probe.bind(("127.0.0.1", candidate + 1))
            except OSError:
                continue
            else:
                shared_port_start = candidate
                break
            finally:
                second_probe.close()
        if shared_port_start is None:
            pytest.fail("could not reserve a free adjacent two-port runtime fixture range")
        shared_port_range = (shared_port_start, shared_port_start + 1)
        probe_script = shared_repo / _CROSS_ATTEMPT_PROBE_SCRIPT_NAME
        probe_script.write_text(
            _CROSS_ATTEMPT_PROBE_SCRIPT.replace(
                "__STARTED_MARKER__", "launch-driver-started"
            ).lstrip(),
            encoding="ascii",
        )
        subprocess.run(
            ["git", "-C", str(shared_repo), "add", "--", probe_script.name],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        subprocess.run(
            ["git", "-C", str(shared_repo), "commit", "-m", "fixture: cross-attempt probes"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        config_path = shared_repo / "acp.toml"
        config_text = config_path.read_text(encoding="utf-8")
        if config_text.count("lease_seconds = 60") != 1:
            pytest.fail("shared live fixture did not have exactly one default lease")
        config_text = config_text.replace("lease_seconds = 60", "lease_seconds = 10", 1)
        config_path.write_text(config_text, encoding="utf-8")
        rootfs_manifest = oci_worker.rootfs_tree_manifest(rootfs_source)
        with config_path.open("a", encoding="utf-8") as stream:
            stream.write(
                "\n[sandbox.oci]\n"
                f"runc_executable = {json.dumps(str(runc_path))}\n"
                f"runc_version = {json.dumps(_SUPPORTED_RUNC_VERSION)}\n"
                f"rootfs_path = {json.dumps(str(rootfs_source.resolve(strict=True)))}\n"
                f"rootfs_sha256 = {json.dumps(rootfs_manifest['rootfs_sha256'])}\n"
                f"rootfs_closure_sha256 = {json.dumps(rootfs_manifest['closure_sha256'])}\n"
                "\n[runtime.ports]\n"
                f"LAUNCH_DRIVER_TEST_PORT = [{shared_port_range[0]}, {shared_port_range[1]}]\n"
            )
        GitSupervisor(shared_repo)
    except BaseException:
        _remove_private_test_tree(shared_fixture_root, expected_identity=shared_fixture_identity)
        control_root.rmdir()
        raise

    child_environment = dict(systemd_environment)
    child_environment["PYTHONPATH"] = str(source_root / "src")
    child_environment["ACP_RUN_SANDBOX_WORKER_LIFECYCLE"] = "1"
    child_environment["ACP_LIVE_CANCEL_AFTER_START"] = "1"
    child_environment["ACP_LIVE_CROSS_ATTEMPT_PROBES"] = "1"
    child_environment["ACP_LIVE_SHARED_REPO"] = str(shared_repo)
    child_environment["ACP_LIVE_SHARED_ROOTFS"] = str(rootfs_source)
    child_environment["ACP_LIVE_SHARED_PORT_RANGE"] = (
        f"{shared_port_range[0]},{shared_port_range[1]}"
    )
    child_environment["ACP_OCI_TEST_RUNC"] = str(runc_path)
    child_environment["ACP_OCI_TEST_RUNC_VERSION"] = _SUPPORTED_RUNC_VERSION
    if os.environ.get("ACP_OCI_TEST_BUSYBOX"):
        child_environment["ACP_OCI_TEST_BUSYBOX"] = os.environ["ACP_OCI_TEST_BUSYBOX"]

    target = (
        f"{Path(__file__).resolve()}::"
        "test_live_production_launch_driver_runs_exact_pinned_runc_request"
    )
    command = [sys.executable, "-m", "pytest", target]
    preexisting_run_roots = {
        str(path)
        for path in Path("/tmp").glob("acp-live-launch-driver-*")
        if path.is_dir() or path.is_symlink()
    }
    processes: list[subprocess.Popen[str]] = []
    child_output_paths: dict[str, Path] = {}
    child_output_streams: dict[str, Any] = {}

    def close_child_output_streams() -> None:
        for stream in child_output_streams.values():
            if not stream.closed:
                stream.flush()
                stream.close()

    try:
        for slot in ("0", "1"):
            slot_environment = dict(child_environment)
            slot_environment["ACP_LIVE_CONCURRENT_CHILD"] = "1"
            slot_environment["ACP_LIVE_CONCURRENT_CONTROL_ROOT"] = str(control_root)
            slot_environment["ACP_LIVE_CONCURRENT_SLOT"] = slot
            output_path = control_root / f"child-{slot}.log"
            output_fd = os.open(
                output_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            output_stream = os.fdopen(output_fd, "w", encoding="utf-8", errors="replace")
            child_output_paths[slot] = output_path
            child_output_streams[slot] = output_stream
            processes.append(
                subprocess.Popen(
                    command,
                    cwd=source_root,
                    env=slot_environment,
                    stdout=output_stream,
                    stderr=subprocess.STDOUT,
                    text=True,
                    start_new_session=True,
                )
            )
    except BaseException as spawn_error:
        cleanup_failures: list[str] = []
        for slot in ("0", "1"):
            release_path = control_root / f"release-{slot}"
            try:
                if os.path.lexists(release_path):
                    info = release_path.lstat()
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or stat.S_ISLNK(info.st_mode)
                        or info.st_uid != os.geteuid()
                        or stat.S_IMODE(info.st_mode) != 0o600
                        or release_path.read_text(encoding="ascii") != "release"
                    ):
                        raise RuntimeError("existing release marker has unsafe identity or content")
                else:
                    _write_live_concurrent_marker(control_root, release_path.name, b"release")
            except (OSError, RuntimeError) as error:
                cleanup_failures.append(f"could not release slot {slot} from its barrier: {error}")

        prepared_records: dict[str, dict[str, Any]] = {}
        stopped_units: set[str] = set()

        def add_cleanup_failure(message: str) -> None:
            if message not in cleanup_failures:
                cleanup_failures.append(message)

        def refresh_prepared_records() -> None:
            expected_pids = {str(index): process.pid for index, process in enumerate(processes)}
            records, record_failures = _read_live_concurrent_prepared_records(
                control_root, expected_pids=expected_pids
            )
            prepared_records.update(records)
            for failure in record_failures:
                add_cleanup_failure(failure)

        def stop_exact_units(*, retry: bool = False) -> None:
            refresh_prepared_records()
            for record in prepared_records.values():
                for unit in (
                    record["service_unit"],
                    record["monitor_unit"],
                    record["scope_unit"],
                    record["slice_unit"],
                ):
                    if unit in stopped_units and not retry:
                        continue
                    _best_effort_stop_unit(systemctl, unit, timeout=3.0)
                    stopped_units.add(unit)

        def process_group_exists(process: subprocess.Popen[str]) -> bool:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return False
            except PermissionError:
                return True
            return True

        natural_deadline = time.monotonic() + 45
        while time.monotonic() < natural_deadline:
            refresh_prepared_records()
            if all(process.poll() is not None for process in processes):
                break
            time.sleep(0.1)

        # The receipt is atomically published before any exact unit is started.
        # Read it before interruption and again during teardown so a raced
        # manager acceptance is always stopped by its attempt-derived names.
        stop_exact_units()
        for process in processes:
            if process.poll() is None or process_group_exists(process):
                _signal_live_test_process_group(process, signal.SIGINT)
        interrupt_deadline = time.monotonic() + 20
        while time.monotonic() < interrupt_deadline:
            refresh_prepared_records()
            if all(
                process.poll() is not None and not process_group_exists(process)
                for process in processes
            ):
                break
            time.sleep(0.1)
        stop_exact_units(retry=True)
        for process in processes:
            if process.poll() is None or process_group_exists(process):
                _signal_live_test_process_group(process, signal.SIGTERM)
        terminate_deadline = time.monotonic() + 10
        while time.monotonic() < terminate_deadline:
            refresh_prepared_records()
            if all(
                process.poll() is not None and not process_group_exists(process)
                for process in processes
            ):
                break
            time.sleep(0.1)
        refresh_prepared_records()
        stop_exact_units(retry=True)
        for process in processes:
            if process.poll() is None or process_group_exists(process):
                _signal_live_test_process_group(process, signal.SIGKILL)

        for process in processes:
            try:
                process.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                cleanup_failures.append(
                    f"test process group {process.pid} did not close its output pipes"
                )
        close_child_output_streams()
        # After bounded process termination, retry exact-unit stops to close
        # an activation race against an earlier stop request.
        stop_exact_units(retry=True)
        for process in processes:
            if process.poll() is None or process_group_exists(process):
                cleanup_failures.append(
                    f"test-owned process group {process.pid} survived bounded cleanup"
                )

        refresh_prepared_records()
        for record in prepared_records.values():
            for unit in (
                record["service_unit"],
                record["monitor_unit"],
                record["scope_unit"],
                record["slice_unit"],
            ):
                try:
                    properties = _unit_properties(
                        unit,
                        ("ActiveState", "ControlGroup", "Id", "LoadState", "MainPID")
                        if unit.endswith(".service")
                        else ("ActiveState", "ControlGroup", "Id", "LoadState"),
                    )
                except Exception as error:
                    cleanup_failures.append(f"could not verify exact unit {unit}: {error}")
                    continue
                if (
                    properties["Id"] != unit
                    or properties["ActiveState"] not in {"inactive", "failed"}
                    or properties["LoadState"] not in {"loaded", "not-found"}
                    or properties["ControlGroup"]
                    or ("MainPID" in properties and properties["MainPID"] != "0")
                ):
                    cleanup_failures.append(f"exact unit {unit} was not quiescent")
            if os.path.lexists(record["run_root"]):
                cleanup_failures.append(f"child test root was not removed: {record['run_root']}")

        try:
            active_scopes = {
                unit
                for unit, (active_state, _sub_state) in acp_scope_states().items()
                if active_state not in {"inactive", "failed"}
            }
            if active_scopes:
                cleanup_failures.append(
                    f"partial launch cleanup left active ACP scopes: {sorted(active_scopes)}"
                )
        except Exception as error:
            cleanup_failures.append(f"could not verify global ACP scope quiescence: {error}")

        remaining_run_roots = {
            str(path)
            for path in Path("/tmp").glob("acp-live-launch-driver-*")
            if path.is_dir() or path.is_symlink()
        } - preexisting_run_roots
        if remaining_run_roots:
            cleanup_failures.append(
                f"partial launch cleanup left test roots: {sorted(remaining_run_roots)}"
            )

        if not cleanup_failures:
            allowed_names = (
                {
                    f"{kind}-{slot}{suffix}"
                    for slot in ("0", "1")
                    for kind, suffix in (("prepared", ".json"), ("ready", ".json"), ("release", ""))
                }
                | {f"child-{slot}.log" for slot in ("0", "1")}
                | {f"cleanup-verified-{slot}.json" for slot in ("0", "1")}
            )
            try:
                entries = list(control_root.iterdir())
            except OSError as error:
                cleanup_failures.append(f"could not inspect concurrent control directory: {error}")
            else:
                if any(path.name not in allowed_names for path in entries):
                    cleanup_failures.append(
                        "concurrent control directory contains unexpected artifacts"
                    )
                else:
                    for path in entries:
                        try:
                            info = path.lstat()
                        except OSError as error:
                            cleanup_failures.append(
                                f"could not inspect concurrent control artifact {path.name}: {error}"
                            )
                            break
                        if (
                            not stat.S_ISREG(info.st_mode)
                            or stat.S_ISLNK(info.st_mode)
                            or info.st_uid != os.geteuid()
                            or stat.S_IMODE(info.st_mode) != 0o600
                        ):
                            cleanup_failures.append(
                                f"concurrent control artifact has unsafe metadata: {path.name}"
                            )
                            break
                    if not cleanup_failures:
                        for path in entries:
                            try:
                                path.unlink()
                            except OSError as error:
                                cleanup_failures.append(
                                    f"could not remove concurrent control artifact {path.name}: {error}"
                                )
                                break
                    if not cleanup_failures:
                        try:
                            control_root.rmdir()
                        except OSError as error:
                            cleanup_failures.append(
                                f"could not remove concurrent control directory: {error}"
                            )
        if cleanup_failures:
            raise RuntimeError(
                "partial concurrent launch cleanup could not be verified: "
                + "; ".join(dict.fromkeys(cleanup_failures))
            ) from spawn_error
        try:
            _remove_private_test_tree(
                shared_fixture_root, expected_identity=shared_fixture_identity
            )
        except (OSError, RuntimeError) as error:
            raise RuntimeError(
                "child cleanup passed but the shared concurrent fixture could not be removed; "
                f"preserving {shared_fixture_root}: {error}"
            ) from spawn_error
        raise

    failures: list[str] = []
    prepared_records: dict[str, dict[str, Any]] = {}
    ready_records: dict[str, dict[str, Any]] = {}
    ready_deadline = time.monotonic() + 90
    try:
        while time.monotonic() < ready_deadline:
            if all((control_root / f"ready-{slot}.json").is_file() for slot in ("0", "1")):
                break
            if any(process.poll() is not None for process in processes):
                break
            time.sleep(0.1)

        prepared_records, receipt_failures = _read_live_concurrent_prepared_records(
            control_root,
            expected_pids={str(index): process.pid for index, process in enumerate(processes)},
        )
        failures.extend(receipt_failures)
        for slot in ("0", "1"):
            ready_path = control_root / f"ready-{slot}.json"
            if ready_path.is_file():
                ready_records[slot] = json.loads(ready_path.read_text(encoding="utf-8"))

        if len(ready_records) != 2 or len(prepared_records) != 2:
            failures.append("both child attempts did not reach the exact-scope readiness barrier")
        else:
            shared_fields = (
                "attempt_id",
                "claim_token",
                "container_id",
                "execution_id",
                "repo",
                "run_root",
                "scope_unit",
                "source_worktree",
                "workspace_root",
            )
            for slot in ("0", "1"):
                prepared = prepared_records[slot]
                ready = ready_records[slot]
                if ready.get("slot") != slot or ready.get("pid") != processes[int(slot)].pid:
                    failures.append(
                        f"slot {slot} readiness receipt is not tied to its child process"
                    )
                if prepared.get("pytest_pid") != ready.get("pid"):
                    failures.append(
                        f"slot {slot} prepared receipt is not tied to its pytest process"
                    )
                if any(prepared.get(field) != ready.get(field) for field in shared_fields):
                    failures.append(f"slot {slot} prepared and live receipts disagree")

            unique_fields = (
                "attempt_id",
                "container_id",
                "execution_id",
                "pid",
                "run_root",
                "scope_unit",
                "source_worktree",
                "workspace_root",
            )
            if {ready["repo"] for ready in ready_records.values()} != {str(shared_repo)}:
                failures.append("both attempts did not use the exact shared fixture repository")
            assert shared_port_range is not None
            shared_runtime_allocations: list[dict[str, Any]] = []
            for slot in ("0", "1"):
                allocations = ready_records[slot].get("runtime_allocations")
                if not isinstance(allocations, list) or len(allocations) != 1:
                    failures.append(f"slot {slot} did not retain one runtime-port allocation")
                    continue
                allocation = allocations[0]
                if (
                    not isinstance(allocation, dict)
                    or allocation.get("pool_name") != "LAUNCH_DRIVER_TEST_PORT"
                    or type(allocation.get("value")) is not int
                    or not shared_port_range[0] <= allocation["value"] <= shared_port_range[1]
                ):
                    failures.append(
                        f"slot {slot} runtime-port allocation is outside the fixture pool"
                    )
                else:
                    shared_runtime_allocations.append(allocation)
            if (
                len(shared_runtime_allocations) == 2
                and shared_runtime_allocations[0]["value"] == shared_runtime_allocations[1]["value"]
            ):
                failures.append("the two active attempts shared one runtime-port allocation")
            for field in unique_fields:
                if len({ready[field] for ready in ready_records.values()}) != 2:
                    failures.append(f"the two child receipts do not have distinct {field} values")
            workspace_roots = {
                slot: Path(ready_records[slot]["workspace_root"]) for slot in ("0", "1")
            }
            mountinfo_paths = {
                slot: workspace_root / ".acp-live-cross-attempt-mountinfo"
                for slot, workspace_root in workspace_roots.items()
            }
            sandbox_execution_root = shared_repo / ".acp" / "sandbox-executions"
            shared_repo_supervisor = GitSupervisor(shared_repo)
            for slot, workspace_root in workspace_roots.items():
                workspace_info = workspace_root.lstat()
                if (
                    workspace_root.resolve(strict=True) != workspace_root
                    or not workspace_root.is_relative_to(
                        sandbox_execution_root.resolve(strict=True)
                    )
                    or workspace_root.parent.parent != sandbox_execution_root
                    or not stat.S_ISDIR(workspace_info.st_mode)
                    or stat.S_ISLNK(workspace_info.st_mode)
                    or workspace_info.st_uid != os.geteuid()
                    or stat.S_IMODE(workspace_info.st_mode) != 0o700
                ):
                    failures.append(
                        f"slot {slot} workspace is not the exact private shared-repo execution copy"
                    )
                if os.path.lexists(workspace_root / ".git"):
                    failures.append(f"slot {slot} workspace contains Git metadata")
                execution_record = shared_repo_supervisor._sandbox_execution_get(
                    ready_records[slot]["attempt_id"]
                )
                if (
                    execution_record is None
                    or execution_record["execution_id"] != ready_records[slot]["execution_id"]
                ):
                    failures.append(f"slot {slot} live execution journal identity changed")
            expected_units = {ready["scope_unit"] for ready in ready_records.values()}
            live_samples: list[dict[str, tuple[str, str, str]]] = []
            for _ in range(2):
                scope_states = acp_scope_states()
                live_units = {
                    unit
                    for unit, (active_state, _sub_state) in scope_states.items()
                    if active_state not in {"inactive", "failed"}
                }
                if live_units != expected_units:
                    failures.append(
                        "active ACP scopes do not equal the two child-reported scopes: "
                        f"expected={sorted(expected_units)} observed={sorted(live_units)}"
                    )
                sample: dict[str, tuple[str, str, str]] = {}
                for ready in ready_records.values():
                    unit = ready["scope_unit"]
                    properties = _unit_properties(
                        unit,
                        (
                            "ActiveState",
                            "ControlGroup",
                            "Id",
                            "InvocationID",
                            "LoadState",
                            "SubState",
                        ),
                    )
                    if (
                        properties["Id"] != unit
                        or properties["LoadState"] != "loaded"
                        or properties["ActiveState"] != "active"
                        or properties["SubState"] != "running"
                        or properties["InvocationID"] != ready["scope_invocation_id"]
                        or properties["ControlGroup"] != ready["scope_control_group"]
                    ):
                        failures.append(f"child scope {unit} was not the exact active invocation")
                    sample[unit] = (
                        properties["ActiveState"],
                        properties["InvocationID"],
                        properties["ControlGroup"],
                    )
                live_samples.append(sample)
                time.sleep(0.1)
            if len(live_samples) != 2 or live_samples[0] != live_samples[1]:
                failures.append(
                    "the two exact active scope identities were not stable across samples"
                )
            if not failures:
                probe_token = os.urandom(12).hex()
                sentinel_bytes = f"acp-live-cross-attempt-{probe_token}\n".encode("ascii")
                git_probe_root = shared_repo / ".git" / f"acp-live-cross-attempt-{probe_token}"
                git_probe_root.mkdir(mode=0o700)
                git_sentinel = git_probe_root / "shared-git.sentinel"
                _write_live_concurrent_marker(git_probe_root, git_sentinel.name, sentinel_bytes)
                git_info = git_sentinel.lstat()
                git_identity = (git_info.st_dev, git_info.st_ino)
                workspace_sentinels: dict[str, Path] = {}
                workspace_sentinel_identities: dict[str, tuple[int, int]] = {}
                result_paths: dict[str, Path] = {}
                for slot in ("0", "1"):
                    workspace_root = workspace_roots[slot]
                    workspace_sentinel = workspace_root / (
                        f".acp-live-cross-attempt-{probe_token}-{slot}.sentinel"
                    )
                    workspace_sentinels[slot] = workspace_sentinel
                    _write_live_concurrent_marker(
                        workspace_root,
                        workspace_sentinel.name,
                        sentinel_bytes,
                    )
                    sentinel_info = workspace_sentinel.lstat()
                    workspace_sentinel_identities[slot] = (
                        sentinel_info.st_dev,
                        sentinel_info.st_ino,
                    )
                    for name in (
                        ".acp-live-cross-attempt-targets",
                        ".acp-live-cross-attempt-go",
                        ".acp-live-cross-attempt-result",
                        ".acp-live-cross-attempt-result.tmp",
                        ".acp-live-cross-attempt-mountinfo",
                        ".acp-live-cross-attempt-link",
                    ):
                        if os.path.lexists(workspace_root / name):
                            raise RuntimeError(
                                f"slot {slot} workspace already contains probe path {name}"
                            )
                    result_paths[slot] = workspace_root / ".acp-live-cross-attempt-result"
                for slot in ("0", "1"):
                    other_slot = "1" if slot == "0" else "0"
                    workspace_root = workspace_roots[slot]
                    targets = (f"{workspace_sentinels[other_slot]}\n{git_sentinel}\n").encode()
                    _write_live_concurrent_marker(
                        workspace_root,
                        ".acp-live-cross-attempt-targets",
                        targets,
                    )
                    _write_live_concurrent_marker(
                        workspace_root,
                        ".acp-live-cross-attempt-go",
                        b"go\n",
                    )

                expected_probe = (
                    "other-workspace=not-visible\n"
                    "other-workspace=target-not-visible\n"
                    "shared-git=not-visible\n"
                    "shared-git=target-not-visible\n"
                    "other-workspace-symlink=not-visible\n"
                    "other-workspace-canonical=not-visible\n"
                    "workspace-git=absent\n"
                ).encode("ascii")
                probe_deadline = time.monotonic() + 35
                probe_results: dict[str, bytes] = {}
                while time.monotonic() < probe_deadline:
                    for slot, result_path in result_paths.items():
                        if slot in probe_results or not os.path.lexists(result_path):
                            continue
                        result_info = result_path.lstat()
                        if (
                            not stat.S_ISREG(result_info.st_mode)
                            or stat.S_ISLNK(result_info.st_mode)
                            or result_info.st_uid != os.geteuid()
                        ):
                            raise RuntimeError(
                                f"slot {slot} cross-attempt result has unsafe file identity"
                            )
                        probe_results[slot] = result_path.read_bytes()
                    if len(probe_results) == 2:
                        break
                    if any(process.poll() is not None for process in processes):
                        raise RuntimeError(
                            "a concurrent worker exited before reporting isolation probes"
                        )
                    time.sleep(0.1)
                if len(probe_results) != 2:
                    raise TimeoutError("both workers did not finish cross-attempt isolation probes")
                for slot, actual in probe_results.items():
                    if actual != expected_probe:
                        raise AssertionError(
                            f"slot {slot} cross-attempt probe mismatch: {actual!r}"
                        )
                workspace_mount_roots: dict[str, str] = {}
                for slot, mountinfo_path in mountinfo_paths.items():
                    mountinfo_info = mountinfo_path.lstat()
                    if (
                        not stat.S_ISREG(mountinfo_info.st_mode)
                        or stat.S_ISLNK(mountinfo_info.st_mode)
                        or mountinfo_info.st_uid != os.geteuid()
                        or mountinfo_info.st_size > 1024 * 1024
                    ):
                        raise RuntimeError(
                            f"slot {slot} worker mountinfo has unsafe file identity or size"
                        )
                    records: list[tuple[str, str, str, str]] = []
                    for line in mountinfo_path.read_text(encoding="ascii").splitlines():
                        fields = line.split()
                        try:
                            separator = fields.index("-")
                        except ValueError as error:
                            raise RuntimeError(
                                f"slot {slot} worker mountinfo has no field separator"
                            ) from error
                        if separator < 6 or len(fields) < separator + 3:
                            raise RuntimeError(
                                f"slot {slot} worker mountinfo has a truncated record"
                            )

                        def decode_mount_field(value: str) -> str:
                            return (
                                value.replace("\\040", " ")
                                .replace("\\011", "\t")
                                .replace("\\012", "\n")
                                .replace("\\134", "\\")
                            )

                        records.append(
                            (
                                decode_mount_field(fields[3]),
                                decode_mount_field(fields[4]),
                                fields[separator + 1],
                                decode_mount_field(fields[separator + 2]),
                            )
                        )
                    by_target: dict[str, list[tuple[str, str, str, str]]] = {}
                    for record in records:
                        by_target.setdefault(record[1], []).append(record)
                    for target in ("/proc", "/dev", "/workspace", "/tmp", "/home/agent"):
                        if len(by_target.get(target, [])) != 1:
                            raise AssertionError(
                                f"slot {slot} live mountinfo does not show exactly one {target} mount"
                            )
                    for target in ("/tmp", "/home/agent", "/dev"):
                        if by_target[target][0][2] != "tmpfs":
                            raise AssertionError(f"slot {slot} live {target} mount is not tmpfs")
                    if by_target["/proc"][0][2] != "proc":
                        raise AssertionError(f"slot {slot} live /proc mount is not procfs")
                    workspace_record = by_target["/workspace"][0]
                    expected_mount_root = workspace_roots[slot].as_posix()
                    if workspace_record[0] != expected_mount_root:
                        raise AssertionError(
                            f"slot {slot} live /workspace mount root does not identify its exact "
                            f"host workspace: expected={expected_mount_root!r} "
                            f"observed={workspace_record[0]!r}"
                        )
                    fixture_mounts = [
                        record
                        for record in records
                        if record[0].startswith("/tmp/acp-live-concurrent-")
                    ]
                    if fixture_mounts != [workspace_record]:
                        raise AssertionError(
                            f"slot {slot} live mountinfo exposes a test-fixture host path "
                            "outside its exact assigned /workspace"
                        )
                    workspace_mount_roots[slot] = workspace_record[0]
                    if any(target in by_target for target in ("/etc", "/usr", "/home", "/root")):
                        raise AssertionError(
                            f"slot {slot} live mountinfo unexpectedly exposes a broad host path"
                        )
                if len(set(workspace_mount_roots.values())) != 2:
                    raise AssertionError(
                        "the two live worker namespaces do not report distinct workspace mounts"
                    )
                for slot, workspace_sentinel in workspace_sentinels.items():
                    sentinel_info = workspace_sentinel.lstat()
                    if (
                        not stat.S_ISREG(sentinel_info.st_mode)
                        or stat.S_ISLNK(sentinel_info.st_mode)
                        or (sentinel_info.st_dev, sentinel_info.st_ino)
                        != workspace_sentinel_identities[slot]
                        or workspace_sentinel.read_bytes() != sentinel_bytes
                    ):
                        raise AssertionError(
                            f"slot {slot} cross-attempt sentinel changed during live probes"
                        )
                git_info_after = git_sentinel.lstat()
                if (
                    not stat.S_ISREG(git_info_after.st_mode)
                    or stat.S_ISLNK(git_info_after.st_mode)
                    or (git_info_after.st_dev, git_info_after.st_ino) != git_identity
                    or git_sentinel.read_bytes() != sentinel_bytes
                ):
                    raise AssertionError("shared Git-metadata sentinel changed during live probes")
    except Exception as error:
        failures.append(
            f"concurrent readiness verification failed: {type(error).__name__}: {error}"
        )
    finally:
        for slot in ("0", "1"):
            release_path = control_root / f"release-{slot}"
            if not os.path.lexists(release_path):
                try:
                    _write_live_concurrent_marker(control_root, release_path.name, b"release")
                except OSError as error:
                    failures.append(f"could not release child {slot} from its barrier: {error}")

    def process_group_exists(process: subprocess.Popen[str]) -> bool:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def refresh_prepared_records() -> None:
        records, record_failures = _read_live_concurrent_prepared_records(
            control_root,
            expected_pids={str(index): process.pid for index, process in enumerate(processes)},
        )
        prepared_records.update(records)
        for failure in record_failures:
            if failure not in failures:
                failures.append(failure)

    def stop_exact_units() -> None:
        refresh_prepared_records()
        for record in prepared_records.values():
            for unit in (
                record["service_unit"],
                record["monitor_unit"],
                record["scope_unit"],
                record["slice_unit"],
            ):
                _best_effort_stop_unit(systemctl, unit, timeout=3.0)

    process_deadline = time.monotonic() + 180
    while time.monotonic() < process_deadline and any(
        process.poll() is None for process in processes
    ):
        time.sleep(0.1)
    timed_out = [process for process in processes if process.poll() is None]
    if timed_out:
        failures.append("one or more cancellation test processes exceeded the 180-second limit")
    needs_forced_cleanup = bool(timed_out) or any(
        process_group_exists(process) for process in processes
    )
    if needs_forced_cleanup:
        for process in processes:
            if process.poll() is None or process_group_exists(process):
                _signal_live_test_process_group(process, signal.SIGINT)
        interrupt_deadline = time.monotonic() + 30
        while time.monotonic() < interrupt_deadline and any(
            process.poll() is None or process_group_exists(process) for process in processes
        ):
            time.sleep(0.1)

        # Stop receipt-validated units even when the pytest parent exited during
        # SIGINT; the worker/scope may outlive that process group.
        stop_exact_units()
        for process in processes:
            if process.poll() is None or process_group_exists(process):
                _signal_live_test_process_group(process, signal.SIGTERM)
        terminate_deadline = time.monotonic() + 15
        while time.monotonic() < terminate_deadline and any(
            process.poll() is None or process_group_exists(process) for process in processes
        ):
            time.sleep(0.1)
        stop_exact_units()
        for process in processes:
            if process.poll() is None or process_group_exists(process):
                _signal_live_test_process_group(process, signal.SIGKILL)

    outputs: list[str] = []
    for process in processes:
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            failures.append(f"test process group {process.pid} did not close")
            _signal_live_test_process_group(process, signal.SIGKILL)
            try:
                process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                failures.append(f"test process group {process.pid} survived SIGKILL")
        except OSError as error:
            failures.append(f"could not wait for test process {process.pid}: {error}")
            _signal_live_test_process_group(process, signal.SIGKILL)
    try:
        close_child_output_streams()
    except OSError as error:
        failures.append(f"could not close child output logs: {error}")
    for slot in ("0", "1"):
        output_path = child_output_paths.get(slot)
        if output_path is None:
            outputs.append("")
            continue
        try:
            outputs.append(output_path.read_text(encoding="utf-8", errors="replace")[-3000:])
        except OSError as error:
            failures.append(f"could not read slot {slot} child output log: {error}")
            outputs.append("")

    # Always retry exact stops after process-group and output-log cleanup. This closes
    # a late systemd activation race and ensures postflight is never skipped by
    # a communicate timeout.
    stop_exact_units()
    if any(process.returncode != 0 for process in processes):
        failures.append("one or more cancellation test processes exited unsuccessfully")
    if any(process.poll() is None for process in processes):
        failures.append("a cancellation test process remained after bounded signal cleanup")
    for process in processes:
        if process_group_exists(process):
            failures.append(f"test-owned process group {process.pid} survived its pytest process")

    try:
        quiescence_deadline = time.monotonic() + 30
        remaining = {
            unit
            for unit, (active_state, _sub_state) in acp_scope_states().items()
            if active_state not in {"inactive", "failed"}
        }
        while remaining and time.monotonic() < quiescence_deadline:
            time.sleep(0.1)
            remaining = {
                unit
                for unit, (active_state, _sub_state) in acp_scope_states().items()
                if active_state not in {"inactive", "failed"}
            }
        if remaining:
            failures.append(f"concurrent proof left active ACP scopes behind: {sorted(remaining)}")
    except Exception as error:
        failures.append(f"could not verify global ACP scope quiescence: {error}")

    for record in prepared_records.values():
        for unit in (
            record["service_unit"],
            record["monitor_unit"],
            record["scope_unit"],
            record["slice_unit"],
        ):
            try:
                properties = _unit_properties(
                    unit,
                    ("ActiveState", "ControlGroup", "Id", "LoadState", "MainPID")
                    if unit.endswith(".service")
                    else ("ActiveState", "ControlGroup", "Id", "LoadState"),
                )
            except Exception as error:
                failures.append(f"could not verify exact unit {unit}: {error}")
                continue
            if (
                properties["Id"] != unit
                or properties["ActiveState"] not in {"inactive", "failed"}
                or properties["LoadState"] not in {"loaded", "not-found"}
                or properties["ControlGroup"]
                or ("MainPID" in properties and properties["MainPID"] != "0")
            ):
                failures.append(f"exact unit {unit} was not quiescent after child exit")
        if os.path.lexists(record["run_root"]):
            failures.append(
                f"child test root was not removed after successful cleanup: {record['run_root']}"
            )

    try:
        remaining_run_roots = {
            str(path)
            for path in Path("/tmp").glob("acp-live-launch-driver-*")
            if path.is_dir() or path.is_symlink()
        } - preexisting_run_roots
        if remaining_run_roots:
            failures.append(
                f"concurrent proof left unaccounted test roots: {sorted(remaining_run_roots)}"
            )
    except OSError as error:
        failures.append(f"could not verify launch-driver test-root cleanup: {error}")

    if not failures:
        expected_markers: set[str] = set()
        for slot in ("0", "1"):
            expected_markers.update(
                {
                    f"prepared-{slot}.json",
                    f"ready-{slot}.json",
                    f"release-{slot}",
                    f"child-{slot}.log",
                    f"cleanup-verified-{slot}.json",
                }
            )
        try:
            control_entries = list(control_root.iterdir())
        except OSError as error:
            failures.append(f"could not inspect concurrent control directory: {error}")
            control_entries = []
        if not failures and {path.name for path in control_entries} != expected_markers:
            failures.append("concurrent control directory contains unexpected artifacts")
        for path in control_entries:
            if failures:
                break
            try:
                info = path.lstat()
                if (
                    not stat.S_ISREG(info.st_mode)
                    or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                ):
                    failures.append(f"concurrent control artifact has unsafe metadata: {path.name}")
                elif (
                    path.name.startswith("release-")
                    and path.read_text(encoding="ascii") != "release"
                ):
                    failures.append(
                        f"concurrent release marker has unexpected content: {path.name}"
                    )
            except OSError as error:
                failures.append(
                    f"could not verify concurrent control artifact {path.name}: {error}"
                )
        if not failures:
            for path in control_entries:
                try:
                    path.unlink()
                except OSError as error:
                    failures.append(
                        f"could not remove concurrent control artifact {path.name}: {error}"
                    )
                    break
        if not failures:
            try:
                control_root.rmdir()
            except OSError as error:
                failures.append(f"could not remove concurrent control directory: {error}")
    if not failures:
        try:
            _remove_private_test_tree(
                shared_fixture_root, expected_identity=shared_fixture_identity
            )
            if os.path.lexists(shared_fixture_root):
                failures.append("shared concurrent fixture remained after exact cleanup")
        except (OSError, RuntimeError) as error:
            failures.append(
                "shared concurrent fixture cleanup could not be verified; "
                f"preserving {shared_fixture_root}: {error}"
            )
    if failures:
        details = "; ".join(
            f"child {index} exit={process.returncode}: {output[-3000:]}"
            for index, (process, output) in enumerate(zip(processes, outputs, strict=True))
        )
        pytest.fail("; ".join(failures) + "; " + details)


if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "--monitor-child":
    _monitor_child_entry(sys.argv[2:])
