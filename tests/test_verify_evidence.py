import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.verify_evidence import MAX_RECEIPT_BYTES, verify


ROOT = Path(__file__).resolve().parents[1]


class EvidenceIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.artifact = self.directory / "artifact.bin"
        self.receipt = self.directory / "receipt.json"
        self.data = b"AGY evidence\x00\n"
        self.artifact.write_bytes(self.data)
        self.payload = {
            "schema": "agy.evidence.v1",
            "mission_id": "mission-01",
            "artifact_sha256": hashlib.sha256(self.data).hexdigest(),
            "artifact_size_bytes": len(self.data),
        }
        self.digest = self.write_receipt(self.payload)

    def write_raw(self, data):
        self.receipt.write_bytes(data)
        return hashlib.sha256(data).hexdigest()

    def write_receipt(self, value):
        return self.write_raw(json.dumps(value).encode("utf-8"))

    def check(self, digest=None):
        return verify(self.receipt, self.artifact, digest or self.digest)

    def test_matching_artifact_and_pinned_receipt(self):
        self.assertEqual(self.check(), "mission-01")

    def test_altered_artifact_rejected(self):
        self.artifact.write_bytes(b"forged evidence")
        with self.assertRaisesRegex(ValueError, "artifact size or digest"):
            self.check()

    def test_same_size_altered_artifact_rejected(self):
        self.artifact.write_bytes(b"X" * len(self.data))
        with self.assertRaisesRegex(ValueError, "artifact size or digest"):
            self.check()

    def test_altered_receipt_rejected_even_if_artifact_matches(self):
        self.payload["mission_id"] = "forged"
        self.write_receipt(self.payload)
        with self.assertRaisesRegex(ValueError, "trusted digest"):
            self.check()

    def test_wrong_trusted_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, "trusted digest"):
            self.check("0" * 64)

    def test_invalid_trusted_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, "64 hexadecimal"):
            self.check("not-a-digest")

    def test_invalid_artifact_size_rejected(self):
        self.payload["artifact_size_bytes"] = True
        self.digest = self.write_receipt(self.payload)
        with self.assertRaisesRegex(ValueError, "invalid artifact size"):
            self.check()

    def test_wrong_size_rejected(self):
        self.payload["artifact_size_bytes"] += 1
        self.digest = self.write_receipt(self.payload)
        with self.assertRaisesRegex(ValueError, "artifact size or digest"):
            self.check()

    def test_duplicate_fields_rejected(self):
        self.digest = self.write_raw(b'{"schema":"agy.evidence.v1","schema":"agy.evidence.v1"}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.check()

    def test_unknown_fields_rejected(self):
        self.payload["approved"] = True
        self.digest = self.write_receipt(self.payload)
        with self.assertRaisesRegex(ValueError, "exactly"):
            self.check()

    def test_unsupported_schema_rejected(self):
        self.payload["schema"] = "agy.evidence.v2"
        self.digest = self.write_receipt(self.payload)
        with self.assertRaisesRegex(ValueError, "unsupported"):
            self.check()

    def test_invalid_mission_id_rejected(self):
        self.payload["mission_id"] = "../outside"
        self.digest = self.write_receipt(self.payload)
        with self.assertRaisesRegex(ValueError, "mission ID"):
            self.check()

    def test_oversized_receipt_rejected(self):
        self.digest = self.write_raw(b" " * (MAX_RECEIPT_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "size limit"):
            self.check()

    def test_missing_artifact_rejected(self):
        self.artifact.unlink()
        with self.assertRaises(FileNotFoundError):
            self.check()

    def test_cli_success_and_failure(self):
        command = [sys.executable, str(ROOT / "tools/verify_evidence.py"),
                   "--receipt", str(self.receipt), "--artifact", str(self.artifact),
                   "--expected-receipt-sha256", self.digest]
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "INTEGRITY_MATCH")
        self.artifact.write_bytes(b"changed")
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stderr)["status"], "INTEGRITY_NOT_VERIFIED")


if __name__ == "__main__":
    unittest.main()
