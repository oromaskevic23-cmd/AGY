from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agy.local_ledger import LedgerIntegrityError, LocalLedger
from agy.protocol import (ProtocolError, canonical_json, checkpoint_signing_bytes,
                          intent_digest, signing_bytes)


ROOT = Path(__file__).resolve().parents[1]
NOW = 1_750_000_000


def public_hex(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


class OwnerControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.db = self.directory / "ledger.sqlite3"
        self.artifact = self.directory / "evidence.txt"
        self.artifact.write_bytes(b"local evidence\n")
        self.artifact_hash = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        self.owner, self.agent, self.approver, self.verifier = (
            Ed25519PrivateKey.generate() for _ in range(4))
        self.policy = {
            "schema": "agy.local-policy.v2", "network_id": "agy-owner-test",
            "agents": {"agent-1": {"public_key": public_hex(self.agent),
                                    "capabilities": ["read.report"]}},
            "approvers": {"approver-1": public_hex(self.approver)},
            "verifiers": {"verifier-1": public_hex(self.verifier)},
            "owners": {"owner-1": public_hex(self.owner)},
        }
        self.ledger = LocalLedger(self.db, self.policy, clock=lambda: NOW)

    def common(self, kind, actor, nonce, **fields):
        return {"kind": kind, "network_id": "agy-owner-test", "actor_id": actor,
                "nonce": nonce, "issued_at": NOW - 10, "expires_at": NOW + 300, **fields}

    def submit(self, key, payload, artifact=None):
        return self.ledger.submit(payload, key.sign(signing_bytes(payload)).hex(),
                                  artifact=artifact)

    def intent(self, mission="mission-1", nonce="intent-1"):
        return self.common("intent", "agent-1", nonce, mission_id=mission,
                           capability="read.report")

    def approval(self, intent, nonce="approval-1"):
        return self.common("approval", "approver-1", nonce, mission_id=intent["mission_id"],
                           intent_sha256=intent_digest(intent), decision="APPROVE")

    def evidence(self, intent, nonce="evidence-1"):
        return self.common("evidence", "agent-1", nonce, mission_id=intent["mission_id"],
                           intent_sha256=intent_digest(intent), artifact_sha256=self.artifact_hash)

    def attestation(self, intent, nonce="attestation-1"):
        return self.common("attestation", "verifier-1", nonce, mission_id=intent["mission_id"],
                           intent_sha256=intent_digest(intent), artifact_sha256=self.artifact_hash,
                           verdict="ACCEPT")

    def revoke(self, target, nonce="owner-revoke-1"):
        return self.common("revoke", "owner-1", nonce, target_actor_id=target,
                           reason_code="OWNER_DECISION",
                           policy_sha256=hashlib.sha256(canonical_json(self.policy)).hexdigest())

    def halt(self, nonce="owner-halt-1"):
        return self.common("halt", "owner-1", nonce, reason_code="OWNER_DECISION",
                           policy_sha256=hashlib.sha256(canonical_json(self.policy)).hexdigest())

    def authorized(self):
        intent = self.intent()
        self.submit(self.agent, intent)
        self.submit(self.approver, self.approval(intent))
        return intent

    def with_evidence(self):
        intent = self.authorized()
        self.submit(self.agent, self.evidence(intent), self.artifact)
        return intent

    def test_owner_revokes_agent_and_invalidates_pending_authorization(self):
        intent = self.authorized()
        result = self.submit(self.owner, self.revoke("agent-1"))
        self.assertEqual(result["state"], "REVOKED")
        with self.assertRaises(ProtocolError):
            self.submit(self.agent, self.evidence(intent), self.artifact)
        reopened = LocalLedger(self.db, self.policy).verify(expected_head=result["head"])
        self.assertEqual(reopened["missions"]["mission-1"]["state"], "BLOCKED_REVOKED")
        self.assertEqual(reopened["revoked_actors"], ["agent-1"])

    def test_revoked_agent_cannot_create_new_intent(self):
        self.submit(self.owner, self.revoke("agent-1"))
        with self.assertRaises(ProtocolError):
            self.submit(self.agent, self.intent())

    def test_revoked_approver_invalidates_its_existing_authorization(self):
        intent = self.authorized()
        self.submit(self.owner, self.revoke("approver-1"))
        with self.assertRaises(ProtocolError):
            self.submit(self.agent, self.evidence(intent), self.artifact)
        self.assertEqual(self.ledger.verify()["missions"]["mission-1"]["state"], "BLOCKED_REVOKED")

    def test_revoked_verifier_cannot_submit_an_attestation(self):
        intent = self.with_evidence()
        self.submit(self.owner, self.revoke("verifier-1"))
        with self.assertRaises(ProtocolError):
            self.submit(self.verifier, self.attestation(intent), self.artifact)

    def test_agent_revoked_after_evidence_does_not_erase_prior_receipt(self):
        intent = self.with_evidence()
        self.submit(self.owner, self.revoke("agent-1"))
        result = self.submit(self.verifier, self.attestation(intent), self.artifact)
        self.assertEqual(result["state"], "ATTESTED_ACCEPTED")

    def test_non_owner_cannot_revoke_or_halt(self):
        for command in (self.revoke("agent-1"), self.halt()):
            with self.subTest(kind=command["kind"]), self.assertRaises(ProtocolError):
                self.submit(self.agent, command)
        self.assertEqual(self.ledger.verify()["events"], 0)

    def test_valid_agent_signature_still_cannot_issue_owner_control(self):
        command = self.revoke("agent-1")
        command["actor_id"] = "agent-1"
        with self.assertRaises(ProtocolError):
            self.submit(self.agent, command)

    def test_owner_control_is_bound_to_exact_policy(self):
        command = self.halt()
        command["policy_sha256"] = "0" * 64
        with self.assertRaises(ProtocolError):
            self.submit(self.owner, command)

    def test_owner_control_rejects_expired_signature_and_freeform_reason(self):
        for field, value in (("expires_at", NOW - 1), ("reason_code", "a private detail")):
            command = self.revoke("agent-1")
            command[field] = value
            with self.subTest(field=field), self.assertRaises(ProtocolError):
                self.submit(self.owner, command)

    def test_owner_cannot_revoke_unknown_actor_or_an_owner(self):
        for target in ("missing", "owner-1"):
            with self.subTest(target=target), self.assertRaises(ProtocolError):
                self.submit(self.owner, self.revoke(target))
        self.assertEqual(self.ledger.verify()["events"], 0)

    def test_revocation_is_irreversible_and_nonce_protected(self):
        self.submit(self.owner, self.revoke("agent-1"))
        for command in (self.revoke("agent-1"), self.revoke("agent-1", "new-owner-nonce")):
            with self.subTest(nonce=command["nonce"]), self.assertRaises(ProtocolError):
                self.submit(self.owner, command)

    def test_halt_blocks_existing_and_future_mission_actions(self):
        intent = self.authorized()
        result = self.submit(self.owner, self.halt())
        self.assertEqual(result["state"], "HALTED")
        with self.assertRaises(ProtocolError):
            self.submit(self.agent, self.evidence(intent), self.artifact)
        with self.assertRaises(ProtocolError):
            self.submit(self.agent, self.intent("mission-2", "intent-2"))
        state = LocalLedger(self.db, self.policy).verify()
        self.assertTrue(state["halted"])
        self.assertEqual(state["missions"]["mission-1"]["state"], "BLOCKED_HALTED")

    def test_halt_still_allows_revocation_and_verification_of_prior_evidence(self):
        intent = self.with_evidence()
        self.submit(self.owner, self.halt())
        self.submit(self.owner, self.revoke("agent-1"))
        result = self.submit(self.verifier, self.attestation(intent), self.artifact)
        self.assertEqual(result["state"], "ATTESTED_ACCEPTED")

    def test_halt_cannot_be_repeated_or_undone_by_a_made_up_command(self):
        self.submit(self.owner, self.halt())
        with self.assertRaises(ProtocolError):
            self.submit(self.owner, self.halt("halt-again"))
        with self.assertRaises(ProtocolError):
            self.submit(self.owner, self.common("resume", "owner-1", "resume-1"))

    def test_owner_key_must_be_distinct_and_present_in_v2_policy(self):
        for owners in ({}, {"owner-1": public_hex(self.agent)}):
            invalid = dict(self.policy, owners=owners)
            with self.subTest(owners=owners), self.assertRaises(ProtocolError):
                LocalLedger(self.directory / "invalid.sqlite3", invalid)

    def test_halt_and_intent_race_cannot_leave_an_authorized_mission(self):
        barrier = threading.Barrier(2)
        intent, halt = self.intent(), self.halt()

        def attempt(pair):
            barrier.wait()
            try:
                self.submit(pair[0], pair[1])
            except ProtocolError:
                pass

        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(attempt, [(self.agent, intent), (self.owner, halt)]))
        state = self.ledger.verify()
        self.assertTrue(state["halted"])
        if "mission-1" in state["missions"]:
            self.assertEqual(state["missions"]["mission-1"]["state"], "BLOCKED_HALTED")

    def signed_checkpoint(self):
        head = self.ledger.verify()["head"]
        payload = self.ledger.checkpoint_payload("owner-1", expected_head=head)
        return payload, self.owner.sign(checkpoint_signing_bytes(payload)).hex()

    def test_signed_checkpoint_verifies_current_journal(self):
        self.authorized()
        checkpoint, signature = self.signed_checkpoint()
        result = self.ledger.verify_checkpoint(checkpoint, signature)
        self.assertEqual(result["events"], 2)
        self.assertEqual(result["head"], checkpoint["head"])
        self.assertFalse(result["freshness_verified"])

    def test_altered_checkpoint_or_wrong_owner_signature_rejected(self):
        self.authorized()
        checkpoint, signature = self.signed_checkpoint()
        checkpoint["event_count"] += 1
        with self.assertRaises(LedgerIntegrityError):
            self.ledger.verify_checkpoint(checkpoint, signature)
        checkpoint["event_count"] -= 1
        wrong_signature = self.agent.sign(checkpoint_signing_bytes(checkpoint)).hex()
        with self.assertRaises(LedgerIntegrityError):
            self.ledger.verify_checkpoint(checkpoint, wrong_signature)

    def test_signed_incorrect_event_count_is_rejected(self):
        self.authorized()
        checkpoint, _ = self.signed_checkpoint()
        checkpoint["event_count"] += 1
        signature = self.owner.sign(checkpoint_signing_bytes(checkpoint)).hex()
        with self.assertRaises(LedgerIntegrityError):
            self.ledger.verify_checkpoint(checkpoint, signature)

    def test_stale_checkpoint_does_not_match_a_longer_journal(self):
        checkpoint, signature = self.signed_checkpoint()
        self.submit(self.owner, self.revoke("agent-1"))
        with self.assertRaises(LedgerIntegrityError):
            self.ledger.verify_checkpoint(checkpoint, signature)

    def test_old_signed_checkpoint_cannot_establish_freshness_by_itself(self):
        checkpoint, signature = self.signed_checkpoint()
        self.submit(self.owner, self.revoke("agent-1"))
        with sqlite3.connect(self.db) as conn:
            conn.execute("DELETE FROM events")
        result = self.ledger.verify_checkpoint(checkpoint, signature)
        self.assertEqual(result["events"], 0)

    def test_checkpoint_rejects_wrong_network_or_untrusted_owner(self):
        checkpoint, signature = self.signed_checkpoint()
        for field, value in (("network_id", "other-network"), ("owner_id", "unknown")):
            altered = dict(checkpoint, **{field: value})
            signed = self.owner.sign(checkpoint_signing_bytes(altered)).hex()
            with self.subTest(field=field), self.assertRaises(LedgerIntegrityError):
                self.ledger.verify_checkpoint(altered, signed)

    def test_command_signature_cannot_be_used_as_checkpoint_signature(self):
        checkpoint, _ = self.signed_checkpoint()
        wrong_domain_signature = self.owner.sign(signing_bytes(checkpoint)).hex()
        with self.assertRaises(LedgerIntegrityError):
            self.ledger.verify_checkpoint(checkpoint, wrong_domain_signature)

    def test_cli_produces_and_verifies_detached_signed_checkpoint(self):
        policy_file = self.directory / "policy.json"
        policy_file.write_text(json.dumps(self.policy), encoding="utf-8")
        base = [sys.executable, "-m", "agy.cli"]
        common = ["--database", str(self.db), "--policy", str(policy_file)]
        head = self.ledger.verify()["head"]
        made = subprocess.run(base + ["checkpoint"] + common +
                              ["--owner-id", "owner-1", "--expected-head", head],
                              cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(made.returncode, 0, made.stderr)
        checkpoint = json.loads(made.stdout)["checkpoint"]
        checkpoint_file = self.directory / "checkpoint.json"
        signature_file = self.directory / "checkpoint.sig"
        checkpoint_file.write_text(json.dumps(checkpoint), encoding="utf-8")
        signature_file.write_text(self.owner.sign(checkpoint_signing_bytes(checkpoint)).hex(),
                                  encoding="ascii")
        verified = subprocess.run(base + ["verify"] + common +
                                  ["--checkpoint", str(checkpoint_file),
                                   "--checkpoint-signature", str(signature_file)],
                                  cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        report = json.loads(verified.stdout)
        self.assertTrue(report["anchor_checked"])
        self.assertEqual(report["anchor_kind"], "signed_checkpoint")
        self.assertFalse(report["freshness_verified"])

    def test_cli_records_signed_revocation_in_separate_process(self):
        policy_file = self.directory / "policy.json"
        command_file = self.directory / "revoke.json"
        signature_file = self.directory / "revoke.sig"
        policy_file.write_text(json.dumps(self.policy), encoding="utf-8")
        current = int(time.time())
        command = self.revoke("agent-1")
        command["issued_at"], command["expires_at"] = current, current + 60
        command_file.write_text(json.dumps(command), encoding="utf-8")
        signature_file.write_text(self.owner.sign(signing_bytes(command)).hex(), encoding="ascii")
        head = self.ledger.verify()["head"]
        args = [sys.executable, "-m", "agy.cli", "submit", "--database", str(self.db),
                "--policy", str(policy_file), "--command", str(command_file),
                "--signature", str(signature_file), "--expected-head", head]
        completed = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["state"], "REVOKED")
        self.assertEqual(self.ledger.verify(expected_head=result["head"])["revoked_actors"], ["agent-1"])

    def test_cli_rejects_checkpoint_without_signature(self):
        policy_file = self.directory / "policy.json"
        checkpoint_file = self.directory / "checkpoint.json"
        policy_file.write_text(json.dumps(self.policy), encoding="utf-8")
        checkpoint, _ = self.signed_checkpoint()
        checkpoint_file.write_text(json.dumps(checkpoint), encoding="utf-8")
        args = [sys.executable, "-m", "agy.cli", "verify", "--database", str(self.db),
                "--policy", str(policy_file), "--checkpoint", str(checkpoint_file)]
        completed = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertNotEqual(completed.returncode, 0)

    def test_v1_ledger_has_no_owner_control(self):
        legacy = dict(self.policy)
        legacy.pop("owners")
        legacy["schema"] = "agy.local-policy.v1"
        ledger = LocalLedger(self.directory / "legacy.sqlite3", legacy, clock=lambda: NOW)
        command = self.halt()
        command["policy_sha256"] = hashlib.sha256(canonical_json(legacy)).hexdigest()
        with self.assertRaises(ProtocolError):
            ledger.submit(command, self.owner.sign(signing_bytes(command)).hex())
        with self.assertRaises(ProtocolError):
            ledger.checkpoint_payload("owner-1")


if __name__ == "__main__":
    unittest.main()
