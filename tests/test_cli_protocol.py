import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agy.protocol import intent_digest, signing_bytes


ROOT = Path(__file__).resolve().parents[1]


def public_hex(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


class ProtocolCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.db = self.directory / "ledger.sqlite3"
        self.policy_path = self.directory / "policy.json"
        self.command_path = self.directory / "command.json"
        self.signature_path = self.directory / "signature.txt"
        self.artifact = self.directory / "evidence.txt"
        self.artifact.write_bytes(b"CLI evidence\n")
        self.agent = Ed25519PrivateKey.generate()
        self.approver = Ed25519PrivateKey.generate()
        self.verifier = Ed25519PrivateKey.generate()
        self.policy = {
            "schema": "agy.local-policy.v1", "network_id": "agy-cli-test",
            "agents": {"agent-1": {"public_key": public_hex(self.agent),
                                    "capabilities": ["read.report"]}},
            "approvers": {"approver-1": public_hex(self.approver)},
            "verifiers": {"verifier-1": public_hex(self.verifier)},
        }
        self.policy_path.write_text(json.dumps(self.policy), encoding="utf-8")
        self.now = int(time.time())

    def call(self, action, *extra):
        args = [sys.executable, "-m", "agy.cli", action, "--database", str(self.db),
                "--policy", str(self.policy_path), *map(str, extra)]
        return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False)

    def payload(self, kind, actor, nonce, **extra):
        return {"kind": kind, "network_id": "agy-cli-test", "actor_id": actor,
                "mission_id": "cli-mission-1", "nonce": nonce,
                "issued_at": self.now - 1, "expires_at": self.now + 300, **extra}

    def submit(self, key, command, head, artifact=None):
        self.command_path.write_text(json.dumps(command), encoding="utf-8")
        self.signature_path.write_text(key.sign(signing_bytes(command)).hex(), encoding="ascii")
        options = ["--command", self.command_path, "--signature", self.signature_path,
                   "--expected-head", head]
        if artifact is not None:
            options += ["--artifact", artifact]
        return self.call("submit", *options)

    def test_separate_cli_processes_complete_signed_mission(self):
        result = self.call("init")
        self.assertEqual(result.returncode, 0, result.stderr)
        head = json.loads(result.stdout)["head"]
        intent = self.payload("intent", "agent-1", "nonce-1", capability="read.report")
        intent_hash = intent_digest(intent)
        artifact_hash = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        commands = [
            (self.agent, intent, None),
            (self.approver, self.payload("approval", "approver-1", "nonce-2",
                                        intent_sha256=intent_hash, decision="APPROVE"), None),
            (self.agent, self.payload("evidence", "agent-1", "nonce-3",
                                     intent_sha256=intent_hash, artifact_sha256=artifact_hash), self.artifact),
            (self.verifier, self.payload("attestation", "verifier-1", "nonce-4",
                                        intent_sha256=intent_hash, artifact_sha256=artifact_hash,
                                        verdict="ACCEPT"), self.artifact),
        ]
        for key, command, artifact in commands:
            result = self.submit(key, command, head, artifact)
            self.assertEqual(result.returncode, 0, result.stderr)
            head = json.loads(result.stdout)["head"]
        result = self.call("verify", "--expected-head", head)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["anchor_checked"])
        self.assertEqual(report["events"], 4)
        self.assertEqual(report["missions"]["cli-mission-1"]["state"], "ATTESTED_ACCEPTED")

    def test_verify_missing_database_does_not_create_one(self):
        result = self.call("verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.db.exists())

    def test_init_refuses_existing_database(self):
        self.assertEqual(self.call("init").returncode, 0)
        result = self.call("init")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.call("verify").returncode, 0)

    def test_duplicate_json_policy_fields_rejected(self):
        self.policy_path.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
        result = self.call("init")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.db.exists())

    def test_submit_rejects_wrong_pinned_head(self):
        self.assertEqual(self.call("init").returncode, 0)
        intent = self.payload("intent", "agent-1", "nonce-1", capability="read.report")
        result = self.submit(self.agent, intent, "0" * 64)
        self.assertNotEqual(result.returncode, 0)
        verified = self.call("verify")
        self.assertEqual(json.loads(verified.stdout)["events"], 0)


if __name__ == "__main__":
    unittest.main()
