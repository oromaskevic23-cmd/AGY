"""LOCAL-ONLY reference executor for owner-signed AGY controls.

Not a sandbox, distributed kill switch, HANTER integration, or production NCA.
Only launches the fixed disposable worker in agy.nca_test_worker. A stop is
CONFIRMED only after this process supervisor observes process exit.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import threading
import time

from agy.local_ledger import LedgerIntegrityError, LocalLedger
from agy.protocol import HASH, ProtocolError, canonical_json


class RuntimeControlError(RuntimeError):
    """Local execution is denied or process status remains uncertain."""


class LocalSecurityAudit:
    """Hash-linked LOCAL record of accepted and rejected control attempts.

    An external trusted anchor is needed to detect rollback of this file.
    These records do not create distributed immutability.
    """

    ZERO = "0" * 64

    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.RLock()
        if not self.path.exists():
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self.path, flags, 0o600)
            os.close(fd)
        self.verify()

    def verify(self, expected_head=None):
        with self._lock:
            if not stat.S_ISREG(self.path.lstat().st_mode):
                raise LedgerIntegrityError("security audit is not a regular file")
            head = self.ZERO
            count = 0
            with self.path.open("rb") as source:
                for raw in source:
                    try:
                        entry = json.loads(raw)
                        body = entry["body"]
                        digest = entry["hash"]
                        if (set(entry) != {"body", "hash"} or type(body) is not dict
                                or set(body) != {"sequence", "previous", "action", "outcome"}
                                or type(body["sequence"]) is not int
                                or body["sequence"] != count + 1
                                or body["previous"] != head
                                or type(digest) is not str or not HASH.fullmatch(digest)
                                or raw != canonical_json(entry) + b"\n"
                                or digest != hashlib.sha256(canonical_json(body)).hexdigest()):
                            raise ValueError("security audit chain invalid")
                        head = digest
                        count += 1
                    except (ValueError, KeyError, TypeError, UnicodeError) as exc:
                        raise LedgerIntegrityError("security audit integrity failed") from exc
            if expected_head is not None and not hmac.compare_digest(head, expected_head):
                raise LedgerIntegrityError("audit head differs from independent anchor")
            return {"events": count, "head": head}

    def record(self, action, outcome):
        if action not in ("halt", "resume", "revoke") or outcome not in ("ACCEPTED", "REJECTED"):
            raise ValueError("invalid local audit classification")
        with self._lock:
            previous = self.verify()
            body = {"sequence": previous["events"] + 1, "previous": previous["head"],
                    "action": action, "outcome": outcome}
            entry = {"body": body, "hash": hashlib.sha256(canonical_json(body)).hexdigest()}
            flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self.path, flags)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise LedgerIntegrityError("security audit path is not regular")
                encoded = canonical_json(entry) + b"\n"
                if os.write(fd, encoded) != len(encoded):
                    raise LedgerIntegrityError("incomplete security audit append")
                os.fsync(fd)
            finally:
                os.close(fd)
            return entry["hash"]


class LocalControlRuntime:
    """Single-process educational HANTER-compatible executor boundary.

    No authentication is attached to any transport envelope; the actual signed
    authority is checked by LocalLedger. All operations require a retained head.
    Concurrent external ledger writers are not supported for production safety.
    """

    def __init__(self, ledger: LocalLedger, *, audit=None, stop_timeout=0.30):
        if not 0.02 <= stop_timeout <= 10:
            raise ValueError("stop_timeout outside safe local demo bounds")
        self.ledger = ledger
        self.audit = audit
        self.stop_timeout = stop_timeout
        self._lock = threading.RLock()
        self._workers = {}
        # Fail closed until a caller supplies an independently held head to start().
        self._fenced = True
        self._audit_failed = False

    def start(self, mission_id, *, expected_head, mode="cooperative"):
        """Start fixed code only, after AGY approval and head verification."""
        with self._lock:
            snapshot = self.ledger.verify(expected_head=expected_head)
            if self._audit_failed:
                raise RuntimeControlError("local security audit was not safely recorded")
            if snapshot["halted"]:
                self._fenced = True
            elif self._fenced and self._workers:
                raise RuntimeControlError("runtime stop fence remains active")
            if snapshot["halted"]:
                raise RuntimeControlError("AGY admission is halted")
            mission = snapshot["missions"].get(mission_id)
            if (mission is None or mission["state"] != "AUTHORIZED"
                    or mission["agent_id"] in snapshot["revoked_actors"]
                    or int(time.time()) > mission["authorization_expires_at"]):
                raise RuntimeControlError("mission is not currently authorized")
            if mission_id in self._workers:
                raise RuntimeControlError("worker already registered")
            if mode not in ("cooperative", "ignore-stop", "ignore-term"):
                raise RuntimeControlError("invalid fixed worker mode")
            self._fenced = False
            process = subprocess.Popen(
                [sys.executable, "-u", "-m", "agy.nca_test_worker", "--mode", mode],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, close_fds=True,
            )
            try:
                # Reject if the ledger changed while the worker was spawned.
                latest = self.ledger.verify(expected_head=expected_head)
                if latest["halted"]:
                    raise RuntimeControlError("AGY halt raced with worker start")
            except BaseException:
                self._force_cleanup(process)
                raise
            self._workers[mission_id] = (process, mission["agent_id"])
            return {"mission_id": mission_id, "pid": process.pid, "status": "LOCAL_WORKER_STARTED",
                    "control_epoch": latest["control_epoch"]}

    def _force_cleanup(self, process):
        if process.poll() is None:
            try:
                process.kill()
                process.wait(timeout=self.stop_timeout)
            except (OSError, subprocess.TimeoutExpired):
                pass
        for channel in (process.stdin, process.stdout):
            if channel:
                channel.close()

    def _stop_one(self, mission_id, process):
        stages = ["STOP_REQUESTED"]
        acknowledged = False
        try:
            if process.poll() is None:
                try:
                    output, _ = process.communicate(input="STOP\n", timeout=self.stop_timeout)
                    acknowledged = "AGY_STOP_ACK" in output.splitlines()
                    if acknowledged:
                        stages.append("STOP_ACKNOWLEDGED")
                except (subprocess.TimeoutExpired, BrokenPipeError, OSError):
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(timeout=self.stop_timeout)
                    except subprocess.TimeoutExpired:
                        if process.poll() is None:
                            process.kill()
                        try:
                            process.wait(timeout=self.stop_timeout)
                        except subprocess.TimeoutExpired:
                            pass
        except (OSError, ValueError):
            pass
        observed = process.poll() is not None
        status = "STOP_CONFIRMED" if observed else "STOP_UNCONFIRMED"
        stages.append(status)
        if observed:
            for channel in (process.stdin, process.stdout):
                if channel and not channel.closed:
                    channel.close()
        return {"mission_id": mission_id, "state": status, "stages": stages,
                "worker_acknowledged": acknowledged, "exit_code": process.poll()}

    def _apply(self, action, command, signature, *, expected_head):
        if type(command) is not dict or command.get("kind") != action:
            raise RuntimeControlError("unexpected signed control type")
        try:
            result = self.ledger.submit(command, signature, expected_head=expected_head)
        except (ProtocolError, LedgerIntegrityError):
            if self.audit is not None:
                self.audit.record(action, "REJECTED")
            raise
        if self.audit is not None:
            try:
                self.audit.record(action, "ACCEPTED")
                result["local_audit_recorded"] = True
            except (OSError, LedgerIntegrityError, ValueError):
                # A failed auxiliary audit must NEVER prevent stopping a worker.
                # The executor stays fail-closed for subsequent admissions.
                self._audit_failed = True
                result["local_audit_recorded"] = False
        return result

    def halt(self, command, signature, *, expected_head):
        with self._lock:
            result = self._apply("halt", command, signature, expected_head=expected_head)
            self._fenced = True
            outcomes = []
            for mission_id, (process, _) in list(self._workers.items()):
                receipt = self._stop_one(mission_id, process)
                outcomes.append(receipt)
                if receipt["state"] == "STOP_CONFIRMED":
                    del self._workers[mission_id]
            return {**result, "stop_receipts": outcomes,
                    "fully_stopped": all(x["state"] == "STOP_CONFIRMED" for x in outcomes)}

    def revoke(self, command, signature, *, expected_head):
        with self._lock:
            result = self._apply("revoke", command, signature, expected_head=expected_head)
            target = command["target_actor_id"]
            outcomes = []
            snapshot = self.ledger.verify(expected_head=result["head"])
            for mission_id, (process, agent_id) in list(self._workers.items()):
                mission = snapshot["missions"][mission_id]
                if agent_id == target or mission["approved_by"] == target:
                    receipt = self._stop_one(mission_id, process)
                    outcomes.append(receipt)
                    if receipt["state"] == "STOP_CONFIRMED":
                        del self._workers[mission_id]
            return {**result, "stop_receipts": outcomes}

    def resume(self, command, signature, *, expected_head):
        with self._lock:
            if self._audit_failed:
                raise RuntimeControlError("security audit failure prevents recovery")
            if any(process.poll() is None for process, _ in self._workers.values()):
                raise RuntimeControlError("cannot resume with unconfirmed running workers")
            result = self._apply("resume", command, signature, expected_head=expected_head)
            self._fenced = False
            return result

    def cleanup_disposable_workers(self):
        """TEST TEARDOWN ONLY; not an owner-authorized runtime operation."""
        with self._lock:
            for process, _ in self._workers.values():
                self._force_cleanup(process)
            self._workers.clear()
            self._fenced = True
