from __future__ import annotations

import os
import sys


def main() -> int:
    if len(sys.argv) < 3:
        return 125
    handshake_fd = int(sys.argv[1])
    command = sys.argv[2:]
    try:
        permission = os.read(handshake_fd, 1)
    finally:
        os.close(handshake_fd)
    if permission != b"G":
        return 125
    os.execvp(command[0], command)
    return 126


if __name__ == "__main__":
    raise SystemExit(main())
