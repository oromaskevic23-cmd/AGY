"""Local atomic checkpoint-head convenience file; NOT an independent trust domain.

Store trusted latest heads off-host / out-of-band for tamper/rollback resilience.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import tempfile

from agy.local_ledger import LedgerIntegrityError
from agy.protocol import HASH, canonical_json


class LocalHeadAnchor:
    SCHEMA = "agy.local-head-anchor.v1"

    def __init__(self, path, *, initial_head=None):
        self.path = Path(path)
        if initial_head is not None:
            self._validate(initial_head)
            blob = canonical_json({"schema": self.SCHEMA, "head": initial_head}) + b"\n"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self.path, flags, 0o600)
            try:
                if os.write(fd, blob) != len(blob):
                    raise LedgerIntegrityError("incomplete anchor initialization")
                os.fsync(fd)
            finally:
                os.close(fd)
        self.read()

    @staticmethod
    def _validate(head):
        if type(head) is not str or not HASH.fullmatch(head):
            raise LedgerIntegrityError("invalid head anchor")

    def read(self):
        if not stat.S_ISREG(self.path.lstat().st_mode):
            raise LedgerIntegrityError("anchor must be regular file")
        with self.path.open("rb") as source:
            data = source.read(1024)
        try:
            obj = json.loads(data)
            if (type(obj) is not dict or set(obj) != {"schema", "head"}
                    or obj["schema"] != self.SCHEMA
                    or canonical_json(obj) + b"\n" != data):
                raise ValueError("non-canonical trusted anchor")
            self._validate(obj["head"])
            return obj["head"]
        except (ValueError, TypeError, UnicodeError) as exc:
            raise LedgerIntegrityError("trusted anchor is invalid") from exc

    def advance(self, expected_old, new_head):
        self._validate(expected_old)
        self._validate(new_head)
        if not hmac.compare_digest(self.read(), expected_old):
            raise LedgerIntegrityError("anchor changed unexpectedly")
        encoded = canonical_json({"schema": self.SCHEMA, "head": new_head}) + b"\n"
        # Atomic in-place directory replacement, but no protection against a
        # malicious operator controlling both this file and the ledger.
        fd, temporary = tempfile.mkstemp(prefix=".agy-anchor-", dir=str(self.path.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.path)
            if os.name == "posix":
                directory = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return new_head
