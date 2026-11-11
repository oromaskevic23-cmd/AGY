#!/usr/bin/env python3
"""Experimental offline evidence integrity check. Not an authorization system."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import re
import sys

MAX_RECEIPT_BYTES = 64 * 1024
CHUNK_SIZE = 1024 * 1024
SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
MISSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
FIELDS = {"schema", "mission_id", "artifact_sha256", "artifact_size_bytes"}


def _unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate receipt field")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("invalid JSON constant: " + value)


def verify(receipt_path: Path, artifact_path: Path, expected_receipt_sha256: str) -> str:
    """Check bytes against an independently obtained receipt digest; return mission ID."""
    if not SHA256.fullmatch(expected_receipt_sha256):
        raise ValueError("expected receipt digest must be 64 hexadecimal characters")

    with receipt_path.open("rb") as receipt_file:
        raw = receipt_file.read(MAX_RECEIPT_BYTES + 1)
    if len(raw) > MAX_RECEIPT_BYTES:
        raise ValueError("receipt exceeds size limit")
    actual_receipt_hash = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(actual_receipt_hash, expected_receipt_sha256.lower()):
        raise ValueError("receipt digest does not match the trusted digest")

    receipt = json.loads(
        raw.decode("utf-8"), object_pairs_hook=_unique_fields, parse_constant=_reject_constant
    )
    if not isinstance(receipt, dict) or set(receipt) != FIELDS:
        raise ValueError("receipt must contain exactly the four v1 fields")
    if receipt["schema"] != "agy.evidence.v1":
        raise ValueError("unsupported receipt schema")
    mission_id = receipt["mission_id"]
    if not isinstance(mission_id, str) or not MISSION_ID.fullmatch(mission_id):
        raise ValueError("invalid mission ID")
    artifact_hash = receipt["artifact_sha256"]
    if not isinstance(artifact_hash, str) or not SHA256.fullmatch(artifact_hash):
        raise ValueError("invalid artifact digest")
    artifact_size = receipt["artifact_size_bytes"]
    if type(artifact_size) is not int or artifact_size < 0:
        raise ValueError("invalid artifact size")

    digest = hashlib.sha256()
    actual_size = 0
    with artifact_path.open("rb") as artifact_file:
        for chunk in iter(lambda: artifact_file.read(CHUNK_SIZE), b""):
            actual_size += len(chunk)
            digest.update(chunk)
    if actual_size != artifact_size or not hmac.compare_digest(
        digest.hexdigest(), artifact_hash.lower()
    ):
        raise ValueError("artifact size or digest does not match the receipt")
    return mission_id


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--expected-receipt-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        mission_id = verify(args.receipt, args.artifact, args.expected_receipt_sha256)
    except (OSError, ValueError, UnicodeError, RecursionError) as error:
        print(json.dumps({"status": "INTEGRITY_NOT_VERIFIED", "error": str(error)}), file=sys.stderr)
        return 1
    print(json.dumps({"status": "INTEGRITY_MATCH", "mission_id": mission_id}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
