"""Small privileged entry point for trust-bundle filesystem mutations."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from .trust_bundles import (
    TrustBundleError,
    activate_bundle,
    install_bundle,
    retire_bundle,
)


def _mapping(values: Sequence[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        name, separator, path = value.partition("=")
        if not separator or not name or not path or name in result:
            raise TrustBundleError(
                "invalid_trust_bundle", "--executable must be unique NAME=RELATIVE_PATH pairs"
            )
        result[name] = path
    return result


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="acp-trust-helper")
    commands = root.add_subparsers(dest="action", required=True)
    install = commands.add_parser("install")
    install.add_argument("--source", required=True)
    install.add_argument("--root", required=True)
    install.add_argument("--version", required=True)
    install.add_argument("--owner-uid", type=int, default=0)
    install.add_argument("--executable", action="append", default=[], required=True)
    for action in ("activate", "retire"):
        command = commands.add_parser(action)
        command.add_argument("bundle_id")
        command.add_argument("--root", required=True)
        command.add_argument("--owner-uid", type=int, default=0)
    return root


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.action == "install":
            result = install_bundle(
                args.source,
                args.root,
                args.version,
                _mapping(args.executable),
                owner_uid=args.owner_uid,
            )
        elif args.action == "activate":
            result = activate_bundle(args.root, args.bundle_id, owner_uid=args.owner_uid)
        else:
            result = retire_bundle(args.root, args.bundle_id, owner_uid=args.owner_uid)
        print(json.dumps(result, sort_keys=True))
        return 0
    except TrustBundleError as error:
        print(json.dumps({"error": error.code, "message": error.message}), file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
