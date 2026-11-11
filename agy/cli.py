"""Operate the AGY local research journal with externally signed commands."""

import argparse
import json
import os
from pathlib import Path
import stat
import sys

from agy.local_ledger import LedgerIntegrityError, LocalLedger
from agy.protocol import ProtocolError


def _read_file(path, limit):
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0))
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise ProtocolError("input must be a regular file")
            content = source.read(limit + 1)
    except OSError as exc:
        raise ProtocolError("cannot read input file") from exc
    if len(content) > limit:
        raise ProtocolError("input file exceeds its size limit")
    return content


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate JSON field")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ProtocolError("invalid JSON constant: " + value)


def _json_file(path, limit):
    return json.loads(_read_file(path, limit).decode("utf-8"),
                      object_pairs_hook=_unique_pairs, parse_constant=_invalid_constant)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="action", required=True)
    for action in ("init", "submit", "verify", "checkpoint"):
        subcommand = subcommands.add_parser(action)
        subcommand.add_argument("--database", type=Path, required=True)
        subcommand.add_argument("--policy", type=Path, required=True)
        if action == "submit":
            subcommand.add_argument("--command", type=Path, required=True)
            subcommand.add_argument("--signature", type=Path, required=True,
                                    help="file containing the detached Ed25519 signature in hex")
            subcommand.add_argument("--artifact", type=Path)
            subcommand.add_argument("--expected-head", required=True)
        elif action == "verify":
            anchor = subcommand.add_mutually_exclusive_group()
            anchor.add_argument("--expected-head")
            anchor.add_argument("--checkpoint", type=Path)
            subcommand.add_argument("--checkpoint-signature", type=Path)
        elif action == "checkpoint":
            subcommand.add_argument("--owner-id", required=True)
            subcommand.add_argument("--expected-head", required=True)
    args = parser.parse_args(argv)
    try:
        policy = _json_file(args.policy, 256 * 1024)
        if args.action == "init":
            ledger = LocalLedger(args.database, policy, exclusive=True)
            result = ledger.verify()
            result["status"] = "INITIALIZED"
        else:
            ledger = LocalLedger(args.database, policy, create=False)
            if args.action == "verify":
                if args.checkpoint is not None:
                    if args.checkpoint_signature is None:
                        raise ProtocolError("checkpoint requires a detached signature")
                    checkpoint = _json_file(args.checkpoint, 16 * 1024)
                    signature = _read_file(args.checkpoint_signature, 256).decode("ascii").strip()
                    result = ledger.verify_checkpoint(checkpoint, signature)
                    result["anchor_kind"] = "signed_checkpoint"
                    result["anchor_checked"] = True
                else:
                    if args.checkpoint_signature is not None:
                        raise ProtocolError("checkpoint signature requires a checkpoint")
                    result = ledger.verify(expected_head=args.expected_head)
                    result["anchor_checked"] = args.expected_head is not None
                    result["anchor_kind"] = "head" if args.expected_head is not None else "none"
                result["status"] = "CONSISTENT"
            elif args.action == "checkpoint":
                checkpoint = ledger.checkpoint_payload(args.owner_id, expected_head=args.expected_head)
                result = {"status": "UNSIGNED_CHECKPOINT", "checkpoint": checkpoint}
            else:
                command = _json_file(args.command, 16 * 1024)
                signature = _read_file(args.signature, 256).decode("ascii").strip()
                result = ledger.submit(command, signature, artifact=args.artifact,
                                       expected_head=args.expected_head)
                result["status"] = "RECORDED"
    except (LedgerIntegrityError, ProtocolError, UnicodeError, ValueError, RecursionError) as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
