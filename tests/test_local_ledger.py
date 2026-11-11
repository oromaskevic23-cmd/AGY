import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agy.local_ledger import LedgerIntegrityError, LocalLedger, MAX_ARTIFACT_BYTES
from agy.protocol import ProtocolError, intent_digest, signing_bytes


NOW = 1_750_000_000


def public_hex(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class LocalLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.db = self.directory / "agy.sqlite3"
        self.artifact = self.directory / "artifact.bin"
        self.artifact.write_bytes(b"local mission evidence\n")
        self.artifact_hash = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        self.agent = Ed25519PrivateKey.generate()
        self.approver = Ed25519PrivateKey.generate()
        self.verifier = Ed25519PrivateKey.generate()
        self.policy = {
            "schema": "agy.local-policy.v1",
            "network_id": "agy-test-local",
            "agents": {"agent-1": {"public_key": public_hex(self.agent),
                                    "capabilities": ["read.report"]}},
            "approvers": {"approver-1": public_hex(self.approver)},
            "verifiers": {"verifier-1": public_hex(self.verifier)},
        }
        self.ledger = LocalLedger(self.db, self.policy, clock=lambda: NOW)

    def payload(self, kind, actor, nonce, **values):
        return {"kind": kind, "network_id": "agy-test-local", "actor_id": actor,
                "mission_id": "mission-1", "nonce": nonce, "issued_at": NOW - 5,
                "expires_at": NOW + 300, **values}

    def sign(self, key, payload):
        return key.sign(signing_bytes(payload)).hex()

    def submit(self, key, payload, artifact=None, **kwargs):
        return self.ledger.submit(payload, self.sign(key, payload),
                                  artifact=artifact, **kwargs)

    def intent(self, nonce="n-intent"):
        return self.payload("intent", "agent-1", nonce, capability="read.report")

    def approval(self, intent, nonce="n-approval", decision="APPROVE"):
        return self.payload("approval", "approver-1", nonce,
                            intent_sha256=intent_digest(intent), decision=decision)

    def evidence(self, intent, nonce="n-evidence"):
        return self.payload("evidence", "agent-1", nonce,
                            intent_sha256=intent_digest(intent),
                            artifact_sha256=self.artifact_hash)

    def attestation(self, intent, nonce="n-attestation", verdict="ACCEPT"):
        return self.payload("attestation", "verifier-1", nonce,
                            intent_sha256=intent_digest(intent),
                            artifact_sha256=self.artifact_hash, verdict=verdict)

    def pending(self):
        intent = self.intent()
        self.submit(self.agent, intent)
        return intent

    def authorized(self):
        intent = self.pending()
        self.submit(self.approver, self.approval(intent))
        return intent

    def with_evidence(self):
        intent = self.authorized()
        self.submit(self.agent, self.evidence(intent), self.artifact)
        return intent

    def test_complete_flow_persists_across_reopen(self):
        intent = self.with_evidence()
        result = self.submit(self.verifier, self.attestation(intent), self.artifact)
        self.assertEqual(result["state"], "ATTESTED_ACCEPTED")
        reopened = LocalLedger(self.db, self.policy).verify(expected_head=result["head"])
        self.assertEqual(reopened["events"], 4)
        self.assertEqual(reopened["missions"]["mission-1"]["state"], "ATTESTED_ACCEPTED")

    def test_intent_requires_separate_approval(self):
        intent = self.pending()
        self.assertEqual(self.ledger.verify()["missions"]["mission-1"]["state"], "PENDING_APPROVAL")
        with self.assertRaises(ProtocolError):
            self.submit(self.agent, self.evidence(intent), self.artifact)
        self.assertEqual(self.ledger.verify()["events"], 1)

    def test_denial_is_recorded_and_cannot_be_followed_by_evidence(self):
        intent = self.pending()
        result = self.submit(self.approver, self.approval(intent, decision="DENY"))
        self.assertEqual(result["state"], "DENIED")
        with self.assertRaises(ProtocolError):
            self.submit(self.agent, self.evidence(intent), self.artifact)

    def test_verifier_rejection_is_recorded_without_claiming_success(self):
        intent = self.with_evidence()
        result = self.submit(self.verifier, self.attestation(intent, verdict="REJECT"), self.artifact)
        self.assertEqual(result["state"], "ATTESTED_REJECTED")

    def test_unknown_agent_rejected(self):
        intent = self.intent()
        intent["actor_id"] = "unknown"
        with self.assertRaises(ProtocolError):
            self.submit(self.agent, intent)
        self.assertEqual(self.ledger.verify()["events"], 0)

    def test_capability_not_granted_by_identity(self):
        intent = self.intent()
        intent["capability"] = "transfer.funds"
        with self.assertRaises(ProtocolError):
            self.submit(self.agent, intent)

    def test_wrong_signature_rejected(self):
        with self.assertRaises(ProtocolError):
            self.submit(self.verifier, self.intent())

    def test_changed_signed_payload_rejected(self):
        intent = self.intent()
        signature = self.sign(self.agent, intent)
        intent["mission_id"] = "mission-2"
        with self.assertRaises(ProtocolError):
            self.ledger.submit(intent, signature)

    def test_expired_and_future_signed_messages_rejected(self):
        for issued, expires in [(NOW - 60, NOW - 1), (NOW + 1, NOW + 30)]:
            with self.subTest(issued=issued):
                payload = self.intent()
                payload["issued_at"], payload["expires_at"] = issued, expires
                with self.assertRaises(ProtocolError):
                    self.submit(self.agent, payload)

    def test_boolean_timestamp_and_unknown_fields_rejected(self):
        for edit in [{"issued_at": True}, {"is_admin": True}]:
            with self.subTest(edit=edit):
                payload = self.intent()
                payload.update(edit)
                with self.assertRaises(ProtocolError):
                    self.submit(self.agent, payload)

    def test_cross_network_replay_rejected(self):
        intent = self.intent()
        intent["network_id"] = "other-network"
        with self.assertRaises(ProtocolError):
            self.submit(self.agent, intent)

    def test_replayed_nonce_rejected_even_across_command_types(self):
        intent = self.authorized()
        with self.assertRaises(ProtocolError):
            self.submit(self.agent, self.evidence(intent, nonce="n-intent"), self.artifact)

    def test_duplicate_mission_rejected(self):
        self.pending()
        with self.assertRaises(ProtocolError):
            self.submit(self.agent, self.intent(nonce="different-nonce"))

    def test_approval_must_bind_exact_signed_intent(self):
        intent = self.pending()
        approval = self.approval(intent)
        approval["intent_sha256"] = "0" * 64
        with self.assertRaises(ProtocolError):
            self.submit(self.approver, approval)

    def test_expired_intent_cannot_be_approved(self):
        intent = self.pending()
        later = NOW + 301
        self.ledger._clock = lambda: later
        approval = self.approval(intent)
        approval["issued_at"] = later - 1
        approval["expires_at"] = later + 60
        with self.assertRaises(ProtocolError):
            self.submit(self.approver, approval)

    def test_expired_approval_cannot_authorize_later_evidence(self):
        intent = self.pending()
        approval = self.approval(intent)
        approval["expires_at"] = NOW + 30
        self.submit(self.approver, approval)
        later = NOW + 31
        self.ledger._clock = lambda: later
        evidence = self.evidence(intent)
        evidence["issued_at"] = later - 1
        evidence["expires_at"] = later + 30
        with self.assertRaises(ProtocolError):
            self.submit(self.agent, evidence, self.artifact)

    def test_clock_rollback_rejects_new_command(self):
        intent = self.pending()
        self.ledger._clock = lambda: NOW - 1
        with self.assertRaises(ProtocolError):
            self.submit(self.approver, self.approval(intent))
        self.assertEqual(self.ledger.verify()["events"], 1)

    def test_agent_key_cannot_act_as_approver(self):
        intent = self.pending()
        with self.assertRaises(ProtocolError):
            self.submit(self.agent, self.approval(intent))

    def test_same_key_cannot_be_configured_for_multiple_roles(self):
        policy = copy.deepcopy(self.policy)
        policy["approvers"]["approver-1"] = public_hex(self.agent)
        with self.assertRaises(ProtocolError):
            LocalLedger(self.directory / "other.sqlite3", policy)

    def test_evidence_requires_local_file_matching_signed_digest(self):
        intent = self.authorized()
        with self.assertRaises(ProtocolError):
            self.submit(self.agent, self.evidence(intent))
        self.artifact.write_bytes(b"altered")
        with self.assertRaises(ProtocolError):
            self.submit(self.agent, self.evidence(intent), self.artifact)
        self.assertEqual(self.ledger.verify()["events"], 2)

    def test_oversized_evidence_is_rejected(self):
        intent = self.authorized()
        with self.artifact.open("wb") as file:
            file.truncate(MAX_ARTIFACT_BYTES + 1)
        with self.assertRaises(ProtocolError):
            self.submit(self.agent, self.evidence(intent), self.artifact)
        self.assertEqual(self.ledger.verify()["events"], 2)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW") and hasattr(os, "symlink"),
                         "no-follow file flag and symlinks required")
    def test_symlink_evidence_is_rejected(self):
        intent = self.authorized()
        link = self.directory / "evidence-link"
        try:
            link.symlink_to(self.artifact)
        except OSError as exc:
            self.skipTest(str(exc))
        with self.assertRaises(ProtocolError):
            self.submit(self.agent, self.evidence(intent), link)

    def test_only_intent_agent_can_submit_evidence(self):
        intent = self.authorized()
        evidence = self.evidence(intent)
        evidence["actor_id"] = "approver-1"
        with self.assertRaises(ProtocolError):
            self.submit(self.approver, evidence, self.artifact)

    def test_attestation_requires_separate_verifier_and_matching_artifact(self):
        intent = self.with_evidence()
        with self.assertRaises(ProtocolError):
            self.submit(self.agent, self.attestation(intent), self.artifact)
        self.artifact.write_bytes(b"modified")
        with self.assertRaises(ProtocolError):
            self.submit(self.verifier, self.attestation(intent), self.artifact)
        self.assertEqual(self.ledger.verify()["events"], 3)

    def test_unknown_policy_change_rejected_for_existing_ledger(self):
        changed = copy.deepcopy(self.policy)
        changed["agents"]["agent-1"]["capabilities"].append("transfer.funds")
        with self.assertRaises(LedgerIntegrityError):
            LocalLedger(self.db, changed)

    def test_modified_event_detected_before_reads_and_writes(self):
        self.pending()
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE events SET body = REPLACE(body, 'mission-1', 'mission-2')")
        with self.assertRaises(LedgerIntegrityError):
            self.ledger.verify()
        with self.assertRaises(LedgerIntegrityError):
            self.submit(self.agent, self.intent(nonce="n-new"))

    def test_forged_event_with_recomputed_hash_still_fails_signature(self):
        self.pending()
        with sqlite3.connect(self.db) as conn:
            seq, previous, body = conn.execute(
                "SELECT seq, previous_hash, body FROM events").fetchone()
            event = json.loads(body)
            event["payload"]["mission_id"] = "forged-mission"
            body = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            forged_hash = hashlib.sha256(b"AGY-LOCAL-EVENT-V1\x00" + seq.to_bytes(8, "big")
                                         + bytes.fromhex(previous) + body.encode("ascii")).hexdigest()
            conn.execute("UPDATE events SET body = ?, event_hash = ?", (body, forged_hash))
        with self.assertRaises(LedgerIntegrityError):
            self.ledger.verify()

    def test_truncation_detected_when_head_is_pinned_externally(self):
        intent = self.pending()
        result = self.submit(self.approver, self.approval(intent))
        with sqlite3.connect(self.db) as conn:
            conn.execute("DELETE FROM events WHERE seq = 2")
        with self.assertRaises(LedgerIntegrityError):
            self.ledger.verify(expected_head=result["head"])

    def test_stale_expected_head_rejects_append(self):
        intent = self.pending()
        with self.assertRaises(LedgerIntegrityError):
            self.submit(self.approver, self.approval(intent), expected_head="0" * 64)
        self.assertEqual(self.ledger.verify()["events"], 1)

    def test_evidence_content_is_not_stored_in_ledger(self):
        self.with_evidence()
        self.assertNotIn(b"local mission evidence", self.db.read_bytes())

    @unittest.skipUnless(os.name == "posix", "POSIX file mode test")
    def test_new_ledger_file_is_private_by_default(self):
        self.assertEqual(self.db.stat().st_mode & 0o077, 0)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_symlink_database_path_is_rejected(self):
        link = self.directory / "database-link"
        try:
            link.symlink_to(self.db)
        except OSError as exc:
            self.skipTest(str(exc))
        with self.assertRaises(LedgerIntegrityError):
            LocalLedger(link, self.policy)

    def test_concurrent_duplicate_approval_has_one_winner(self):
        intent = self.pending()
        approval = self.approval(intent)
        barrier = threading.Barrier(2)

        def attempt():
            barrier.wait()
            try:
                self.submit(self.approver, approval)
                return "accepted"
            except ProtocolError:
                return "rejected"

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: attempt(), range(2)))
        self.assertCountEqual(outcomes, ["accepted", "rejected"])
        self.assertEqual(self.ledger.verify()["events"], 2)


if __name__ == "__main__":
    unittest.main()
