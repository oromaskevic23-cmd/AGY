"""Single-host, local-only signed mission journal for protocol research."""

from __future__ import annotations

from contextlib import contextmanager
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import stat
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agy.protocol import (HASH, SIGNATURE, ProtocolError, ProtocolState, canonical_json,
                          checkpoint_signing_bytes, validate_policy)


class LedgerIntegrityError(RuntimeError):
    """Local storage, policy binding, chain consistency, or an expected head failed."""


MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_EVENTS = 10_000
EVENT_DOMAIN = b"AGY-LOCAL-EVENT-V1\x00"
GENESIS_DOMAIN = b"AGY-LOCAL-GENESIS-V1\x00"


def _pairs_without_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _bad_constant(value):
    raise ValueError("invalid JSON constant: " + value)


def _event_hash(seq: int, previous: str, body: str) -> str:
    return hashlib.sha256(EVENT_DOMAIN + seq.to_bytes(8, "big")
                          + bytes.fromhex(previous) + body.encode("ascii")).hexdigest()


def _artifact_hash(path: Path) -> str:
    """Hash one local regular file with a fixed resource limit."""
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0))
    try:
        fd = os.open(os.fspath(path), flags)
        with os.fdopen(fd, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_ARTIFACT_BYTES:
                raise ProtocolError("artifact must be a regular file within the size limit")
            digest = hashlib.sha256()
            total = 0
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                total += len(chunk)
                if total > MAX_ARTIFACT_BYTES:
                    raise ProtocolError("artifact exceeds size limit")
                digest.update(chunk)
            after = os.fstat(source.fileno())
            if (total != before.st_size or after.st_size != before.st_size
                    or after.st_mtime_ns != before.st_mtime_ns):
                raise ProtocolError("artifact changed while being read")
            return digest.hexdigest()
    except ProtocolError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise ProtocolError("artifact cannot be read safely") from exc


class LocalLedger:
    """Append and replay signed local state transitions with SQLite transactions.

    The operator must protect the policy, clock, database, and optional external
    head anchor. No network, distributed consensus or execution is provided.
    """

    def __init__(self, path: Path, policy: dict, *, clock=None, create=True, exclusive=False):
        self.path = Path(path)
        if str(self.path) == ":memory:":
            raise ProtocolError("a persistent local database path is required")
        if type(create) is not bool or type(exclusive) is not bool or (exclusive and not create):
            raise ProtocolError("invalid ledger creation mode")
        validated = validate_policy(policy)
        self._policy_json = canonical_json(validated)
        self._policy_sha256 = hashlib.sha256(self._policy_json).hexdigest()
        self._network_id = validated["network_id"]
        self._genesis = hashlib.sha256(GENESIS_DOMAIN + bytes.fromhex(self._policy_sha256)).hexdigest()
        self._clock = clock if clock is not None else time.time
        self._prepare_path(create=create, exclusive=exclusive)
        self._initialize(create=create)

    def _prepare_path(self, *, create, exclusive):
        if not create:
            self._check_regular_path()
            return
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_BINARY", 0)
        try:
            fd = os.open(self.path, flags, 0o600)
        except FileExistsError:
            if exclusive:
                raise LedgerIntegrityError("ledger path already exists")
            self._check_regular_path()
        except OSError as exc:
            raise LedgerIntegrityError("ledger path cannot be created safely") from exc
        else:
            os.close(fd)

    def _check_regular_path(self):
        try:
            if not stat.S_ISREG(self.path.lstat().st_mode):
                raise LedgerIntegrityError("ledger path must be a regular file")
        except OSError as exc:
            raise LedgerIntegrityError("ledger path is unavailable") from exc

    @contextmanager
    def _transaction(self, *, write: bool):
        conn = None
        try:
            conn = sqlite3.connect(str(self.path), timeout=5, isolation_level=None)
            conn.execute("PRAGMA trusted_schema = OFF")
            conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield conn
            conn.commit()
        except sqlite3.Error as exc:
            if conn is not None:
                conn.rollback()
            raise LedgerIntegrityError("local ledger is unavailable or invalid") from exc
        except BaseException:
            if conn is not None:
                conn.rollback()
            raise
        finally:
            if conn is not None:
                conn.close()

    def _expected_metadata(self):
        return {"format": "agy-local-ledger-v1", "network_id": self._network_id,
                "policy_sha256": self._policy_sha256}

    def _check_metadata(self, conn):
        entries = dict(conn.execute("SELECT key, value FROM metadata"))
        if entries != self._expected_metadata():
            raise LedgerIntegrityError("ledger policy or metadata does not match")

    def _initialize(self, *, create):
        with self._transaction(write=True) as conn:
            tables = {row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")}
            if not tables:
                if not create:
                    raise LedgerIntegrityError("existing file is not an initialized ledger")
                conn.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                conn.execute("CREATE TABLE events (seq INTEGER PRIMARY KEY, previous_hash TEXT NOT NULL, "
                             "body TEXT NOT NULL, event_hash TEXT NOT NULL UNIQUE)")
                conn.executemany("INSERT INTO metadata(key, value) VALUES (?, ?)",
                                 self._expected_metadata().items())
            elif tables != {"metadata", "events"}:
                raise LedgerIntegrityError("unexpected local database schema")
            self._check_metadata(conn)

    def _replay(self, conn):
        self._check_metadata(conn)
        policy = json.loads(self._policy_json)
        state = ProtocolState()
        previous = self._genesis
        count = 0
        last_time = 0
        for seq, previous_hash, body, event_hash in conn.execute(
                "SELECT seq, previous_hash, body, event_hash FROM events ORDER BY seq"):
            count += 1
            if (count > MAX_EVENTS or seq != count or previous_hash != previous
                    or type(body) is not str or len(body) > 16_384
                    or type(event_hash) is not str or not HASH.fullmatch(event_hash)):
                raise LedgerIntegrityError("invalid event sequence or format")
            try:
                obj = json.loads(body, object_pairs_hook=_pairs_without_duplicates,
                                 parse_constant=_bad_constant)
                if (type(obj) is not dict or set(obj) != {"payload", "signature", "accepted_at"}
                        or canonical_json(obj).decode("ascii") != body
                        or type(obj["accepted_at"]) is not int or obj["accepted_at"] < last_time):
                    raise ValueError("invalid event body")
                if not hmac.compare_digest(_event_hash(seq, previous, body), event_hash):
                    raise ValueError("event hash mismatch")
                if (obj["payload"].get("kind") == "resume"
                        and obj["payload"].get("control_head") != previous):
                    raise ValueError("resume is not bound to predecessor head")
                state.apply(obj["payload"], obj["signature"], policy, obj["accepted_at"])
            except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
                raise LedgerIntegrityError("event failed replay or integrity verification") from exc
            previous = event_hash
            last_time = obj["accepted_at"]
        return state, count, previous, last_time

    @staticmethod
    def _check_head(expected_head, actual_head):
        if expected_head is not None:
            if (type(expected_head) is not str or not HASH.fullmatch(expected_head)
                    or not hmac.compare_digest(expected_head, actual_head)):
                raise LedgerIntegrityError("ledger head does not match the trusted anchor")

    def verify(self, *, expected_head=None):
        """Replay local signatures and hashes; an external head detects rollback."""
        with self._transaction(write=False) as conn:
            state, count, head, _ = self._replay(conn)
            self._check_head(expected_head, head)
            return {"events": count, "head": head, "missions": copy.deepcopy(state.missions),
                    "revoked_actors": sorted(state.revoked_actors), "halted": state.halted,
                    "control_epoch": state.control_epoch}

    def checkpoint_payload(self, owner_id, *, expected_head=None):
        """Prepare an unsigned snapshot for a separately controlled owner signer."""
        policy = json.loads(self._policy_json)
        if type(owner_id) is not str or owner_id not in policy.get("owners", {}):
            raise ProtocolError("checkpoint owner is not configured")
        snapshot = self.verify(expected_head=expected_head)
        return {"schema": "agy.local-checkpoint.v1", "network_id": self._network_id,
                "policy_sha256": self._policy_sha256, "owner_id": owner_id,
                "event_count": snapshot["events"], "head": snapshot["head"]}

    def verify_checkpoint(self, checkpoint, signature):
        """Verify an owner's signed snapshot against the entire local journal."""
        fields = {"schema", "network_id", "policy_sha256", "owner_id", "event_count", "head"}
        if (type(checkpoint) is not dict or set(checkpoint) != fields
                or checkpoint["schema"] != "agy.local-checkpoint.v1"
                or checkpoint["network_id"] != self._network_id
                or checkpoint["policy_sha256"] != self._policy_sha256
                or type(checkpoint["event_count"]) is not int
                or not 0 <= checkpoint["event_count"] <= MAX_EVENTS
                or type(checkpoint["head"]) is not str or not HASH.fullmatch(checkpoint["head"])
                or type(checkpoint["owner_id"]) is not str
                or type(signature) is not str or not SIGNATURE.fullmatch(signature)):
            raise LedgerIntegrityError("invalid signed checkpoint")
        key = json.loads(self._policy_json).get("owners", {}).get(checkpoint["owner_id"])
        if key is None:
            raise LedgerIntegrityError("checkpoint owner is not trusted")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
                bytes.fromhex(signature), checkpoint_signing_bytes(checkpoint))
        except (InvalidSignature, ValueError) as exc:
            raise LedgerIntegrityError("checkpoint signature verification failed") from exc
        snapshot = self.verify(expected_head=checkpoint["head"])
        if snapshot["events"] != checkpoint["event_count"]:
            raise LedgerIntegrityError("checkpoint event count does not match")
        snapshot["checkpoint_owner"] = checkpoint["owner_id"]
        snapshot["freshness_verified"] = False
        return snapshot

    def submit(self, payload: dict, signature: str, *, artifact=None, expected_head=None):
        """Append one authorized transition; rejected attempts do not modify the ledger."""
        command = copy.deepcopy(payload)
        with self._transaction(write=True) as conn:
            state, count, head, last_time = self._replay(conn)
            self._check_head(expected_head, head)
            if count >= MAX_EVENTS:
                raise ProtocolError("local ledger event limit reached")
            try:
                accepted_at = int(self._clock())
            except (ValueError, TypeError, OverflowError) as exc:
                raise ProtocolError("local clock is unavailable") from exc
            if accepted_at < last_time:
                raise ProtocolError("local clock moved backwards")
            if command.get("kind") == "resume":
                if expected_head is None or command.get("control_head") != head:
                    raise ProtocolError("resume requires a matching externally retained head")
            mission = state.apply(command, signature, json.loads(self._policy_json), accepted_at)
            if command["kind"] in ("evidence", "attestation"):
                if artifact is None or not hmac.compare_digest(
                        _artifact_hash(artifact), command["artifact_sha256"]):
                    raise ProtocolError("artifact does not match signed digest")
            elif artifact is not None:
                raise ProtocolError("artifact is not accepted for this command")
            body = canonical_json({"payload": command, "signature": signature,
                                   "accepted_at": accepted_at}).decode("ascii")
            seq = count + 1
            next_head = _event_hash(seq, head, body)
            conn.execute("INSERT INTO events(seq, previous_hash, body, event_hash) VALUES (?, ?, ?, ?)",
                         (seq, head, body, next_head))
            result = {"sequence": seq, "head": next_head, "state": mission["state"]}
            if command["kind"] == "revoke":
                result["target_actor_id"] = command["target_actor_id"]
            elif command["kind"] not in ("halt", "resume"):
                result["mission_id"] = command["mission_id"]
            return result
