import json
from pathlib import Path
import subprocess
import sys
import unittest


class LocalDemoTests(unittest.TestCase):
    def test_demo_runs_end_to_end(self):
        root = Path(__file__).resolve().parents[1]
        completed = subprocess.run([sys.executable, "-m", "agy.demo"], cwd=root,
                                   capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["result"], "LOCAL_DEMO_COMPLETE")
        self.assertEqual(report["stages"], ["PENDING_APPROVAL", "AUTHORIZED",
                                            "EVIDENCE_SUBMITTED", "ATTESTED_ACCEPTED"])
        self.assertEqual(report["events_replayed"], 4)


if __name__ == "__main__":
    unittest.main()
