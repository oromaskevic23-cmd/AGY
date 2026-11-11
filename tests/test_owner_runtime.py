"""Offline v0.3 acceptance: actual disposable process exit, signed recovery and negatives."""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import tempfile
import time
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agy.local_control_runtime import LocalControlRuntime, LocalSecurityAudit, RuntimeControlError
from agy.local_head_anchor import LocalHeadAnchor
from agy.local_ledger import LedgerIntegrityError, LocalLedger
from agy.protocol import ProtocolError, canonical_json, intent_digest, signing_bytes


def public_hex(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


class TestOwnerRuntime(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="agy-v03-test-")
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.owner, self.agent, self.other_agent, self.approver, self.verifier = (
            Ed25519PrivateKey.generate() for _ in range(5))
        self.now = int(time.time())
        self.policy = {
            "schema": "agy.local-policy.v2", "network_id": "agy-v03-test",
            "agents": {
                "agent-1": {"public_key": public_hex(self.agent),
                            "capabilities": ["read.report"]},
                "agent-2": {"public_key": public_hex(self.other_agent),
                            "capabilities": ["read.report"]}},
            "approvers": {"approver-1": public_hex(self.approver)},
            "verifiers": {"verifier-1": public_hex(self.verifier)},
            "owners": {"owner-1": public_hex(self.owner)}}
        self.policy_sha256 = hashlib.sha256(canonical_json(self.policy)).hexdigest()
        self.database = root / "journal.sqlite3"
        self.ledger = LocalLedger(self.database, self.policy)
        self.head = self.ledger.verify()["head"]
        self.anchor = LocalHeadAnchor(root / "trusted-head.json", initial_head=self.head)
        self.audit = LocalSecurityAudit(root / "security-audit.jsonl")
        self.runtime = LocalControlRuntime(self.ledger, audit=self.audit, stop_timeout=0.35)
        self.addCleanup(self.runtime.cleanup_disposable_workers)

    def command(self, kind, actor, nonce, **additional):
        return {"kind": kind, "network_id": self.policy["network_id"],
                "actor_id": actor, "nonce": nonce,
                "issued_at": self.now, "expires_at": self.now + 300, **additional}

    @staticmethod
    def sign(key, command):
        return key.sign(signing_bytes(command)).hex()

    def remember(self, result):
        self.anchor.advance(self.head, result["head"])
        self.head = result["head"]
        self.assertEqual(self.anchor.read(), self.head)
        return result

    def send(self, key, command):
        return self.remember(self.ledger.submit(
            command, self.sign(key, command), expected_head=self.head))

    def authorize(self, mission_id, actor="agent-1"):
        key = self.agent if actor == "agent-1" else self.other_agent
        intent = self.command("intent", actor, "intent-" + mission_id,
                              mission_id=mission_id, capability="read.report")
        self.send(key, intent)
        approval = self.command("approval", "approver-1", "approve-" + mission_id,
                                mission_id=mission_id, intent_sha256=intent_digest(intent),
                                decision="APPROVE")
        self.send(self.approver, approval)
        return intent

    def halt(self, nonce="halt-1"):
        command = self.command("halt", "owner-1", nonce,
                               policy_sha256=self.policy_sha256,
                               reason_code="OWNER_DECISION")
        return self.remember(self.runtime.halt(
            command, self.sign(self.owner, command), expected_head=self.head))

    def resume(self, nonce="resume-1"):
        snapshot = self.ledger.verify(expected_head=self.head)
        command = self.command("resume", "owner-1", nonce,
                               policy_sha256=self.policy_sha256,
                               reason_code="OWNER_DECISION",
                               control_head=self.head,
                               control_epoch=snapshot["control_epoch"] + 1)
        return self.remember(self.runtime.resume(
            command, self.sign(self.owner, command), expected_head=self.head))

    def test_owner_halt_stops_real_worker_and_resume_needs_fresh_mission(self):
        self.authorize("mission-1")
        launched = self.runtime.start("mission-1", expected_head=self.head)
        self.assertGreater(launched["pid"], 0)
        stopped = self.halt()
        self.assertTrue(stopped["fully_stopped"])
        self.assertEqual(stopped["stop_receipts"][0]["state"], "STOP_CONFIRMED")
        self.assertEqual(stopped["stop_receipts"][0]["stages"][-1], "STOP_CONFIRMED")
        self.assertTrue(self.ledger.verify(expected_head=self.head)["halted"])
        with self.assertRaises(RuntimeControlError):
            self.runtime.start("mission-1", expected_head=self.head)
        resumed = self.resume()
        self.assertEqual(resumed["state"], "RESUMED")
        self.assertEqual(self.ledger.verify(expected_head=self.head)["control_epoch"], 2)
        with self.assertRaises(RuntimeControlError):
            self.runtime.start("mission-1", expected_head=self.head)
        self.authorize("mission-2")
        launched_new = self.runtime.start("mission-2", expected_head=self.head)
        self.assertGreater(launched_new["pid"], 0)
        self.assertEqual(self.audit.verify()["events"], 2)

    def test_force_termination_is_not_misreported_as_acknowledgment(self):
        self.authorize("mission-slow")
        self.runtime.start("mission-slow", expected_head=self.head, mode="ignore-term")
        stopped = self.halt()
        self.assertTrue(stopped["fully_stopped"])
        receipt = stopped["stop_receipts"][0]
        self.assertEqual(receipt["state"], "STOP_CONFIRMED")
        self.assertFalse(receipt["worker_acknowledged"])
        self.assertNotIn("STOP_ACKNOWLEDGED", receipt["stages"])

    def test_revocation_persists_after_resume(self):
        self.authorize("mission-1")
        self.halt()
        command = self.command("revoke", "owner-1", "revoke-1",
                               target_actor_id="agent-1",
                               policy_sha256=self.policy_sha256,
                               reason_code="OWNER_DECISION")
        self.send(self.owner, command)
        self.resume()
        self.assertIn("agent-1", self.ledger.verify(expected_head=self.head)["revoked_actors"])
        wrong = self.command("intent", "agent-1", "new-intent",
                             mission_id="fresh-but-revoked", capability="read.report")
        with self.assertRaises(ProtocolError):
            self.ledger.submit(wrong, self.sign(self.agent, wrong), expected_head=self.head)
        self.authorize("mission-2", actor="agent-2")

    def test_revoke_stops_active_local_actor(self):
        self.authorize("mission-1")
        self.runtime.start("mission-1", expected_head=self.head)
        command = self.command("revoke", "owner-1", "revoke-1",
                               target_actor_id="agent-1", reason_code="MISUSE",
                               policy_sha256=self.policy_sha256)
        stopped = self.remember(self.runtime.revoke(
            command, self.sign(self.owner, command), expected_head=self.head))
        self.assertEqual(stopped["stop_receipts"][0]["state"], "STOP_CONFIRMED")
        with self.assertRaises(RuntimeControlError):
            self.runtime.start("mission-1", expected_head=self.head)

    def test_reject_invalid_signature_stale_head_and_wrong_policy(self):
        self.authorize("mission-1")
        command = self.command("halt", "owner-1", "halt-bad",
                               policy_sha256=self.policy_sha256,
                               reason_code="OWNER_DECISION")
        with self.assertRaises(ProtocolError):
            self.runtime.halt(command, self.sign(self.agent, command), expected_head=self.head)
        tampered = dict(command, policy_sha256="a" * 64)
        with self.assertRaises(ProtocolError):
            self.runtime.halt(tampered, self.sign(self.owner, tampered),
                              expected_head=self.head)
        self.assertEqual(self.audit.verify()["events"], 2)
        self.halt()
        bad_resume = self.command(
            "resume", "owner-1", "resume-bad",
            reason_code="OWNER_DECISION", policy_sha256=self.policy_sha256,
            control_head="0" * 64, control_epoch=2)
        with self.assertRaises(ProtocolError):
            self.runtime.resume(bad_resume, self.sign(self.owner, bad_resume),
                                expected_head=self.head)
        with self.assertRaises(LedgerIntegrityError):
            self.runtime.start("mission-1", expected_head="0" * 64)

    def test_resume_is_signed_and_replay_safe(self):
        self.halt()
        expected = self.head
        command = self.command("resume", "owner-1", "resume-unique",
                               reason_code="OWNER_DECISION", policy_sha256=self.policy_sha256,
                               control_head=expected, control_epoch=2)
        with self.assertRaises(ProtocolError):
            self.runtime.resume(command, self.sign(self.agent, command), expected_head=expected)
        self.remember(self.runtime.resume(
            command, self.sign(self.owner, command), expected_head=expected))
        with self.assertRaises((ProtocolError, LedgerIntegrityError)):
            self.runtime.resume(command, self.sign(self.owner, command), expected_head=expected)
        self.assertEqual(self.ledger.verify(expected_head=self.head)["control_epoch"], 2)

    def test_trusted_head_exposes_rolled_back_database(self):
        self.authorize("mission-1")
        backup = Path(self.temporary.name) / "pre-halt.db"
        shutil.copyfile(self.database, backup)
        self.halt()
        shutil.copyfile(backup, self.database)
        with self.assertRaises(LedgerIntegrityError):
            self.ledger.verify(expected_head=self.anchor.read())

    def test_audit_chain_requires_independent_anchor(self):
        self.halt()
        audit_head = self.audit.verify()["head"]
        self.assertEqual(self.audit.verify(expected_head=audit_head)["events"], 1)
        with self.assertRaises(LedgerIntegrityError):
            self.audit.verify(expected_head="0" * 64)


if __name__ == "__main__":
    unittest.main()
