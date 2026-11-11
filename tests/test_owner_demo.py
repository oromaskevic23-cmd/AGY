import json
from pathlib import Path
import subprocess
import sys
import unittest


class OwnerDemoTests(unittest.TestCase):
    def test_owner_controls_and_checkpoint_demo(self):
        root = Path(__file__).resolve().parents[1]
        completed = subprocess.run([sys.executable, "-m", "agy.owner_demo"], cwd=root,
                                   capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["result"], "LOCAL_OWNER_DEMO_COMPLETE")
        self.assertEqual(report["revoked_agent_action"], "REJECTED")
        self.assertEqual(report["post_halt_approval"], "REJECTED")
        self.assertEqual(report["checkpoint"], "SIGNATURE_AND_HEAD_VERIFIED")
        self.assertTrue(report["halted"])
        self.assertEqual(report["events_replayed"], 5)


if __name__ == "__main__":
    unittest.main()
