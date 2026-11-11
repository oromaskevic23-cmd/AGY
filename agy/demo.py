"""Run a disposable, offline end-to-end AGY local protocol demonstration."""

import hashlib
import json
from pathlib import Path
import tempfile
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agy.local_ledger import LocalLedger
from agy.protocol import intent_digest, signing_bytes


def _public_hex(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def main():
    agent, approver, verifier = (Ed25519PrivateKey.generate() for _ in range(3))
    now = int(time.time())
    network = "agy-local-demo"
    policy = {
        "schema": "agy.local-policy.v1", "network_id": network,
        "agents": {"demo-agent": {"public_key": _public_hex(agent),
                                  "capabilities": ["read.report"]}},
        "approvers": {"demo-approver": _public_hex(approver)},
        "verifiers": {"demo-verifier": _public_hex(verifier)},
    }
    with tempfile.TemporaryDirectory(prefix="agy-local-demo-") as directory:
        root = Path(directory)
        artifact = root / "evidence.txt"
        artifact.write_bytes(b"AGY local development evidence\n")
        evidence_hash = hashlib.sha256(artifact.read_bytes()).hexdigest()
        ledger = LocalLedger(root / "ledger.sqlite3", policy)

        def payload(kind, actor, nonce, **extra):
            return {"kind": kind, "network_id": network, "actor_id": actor,
                    "mission_id": "demo-mission-1", "nonce": nonce,
                    "issued_at": now, "expires_at": now + 300, **extra}

        intent = payload("intent", "demo-agent", "demo-intent-1", capability="read.report")
        reference = intent_digest(intent)
        commands = [
            (agent, intent, None),
            (approver, payload("approval", "demo-approver", "demo-approval-1",
                               intent_sha256=reference, decision="APPROVE"), None),
            (agent, payload("evidence", "demo-agent", "demo-evidence-1",
                            intent_sha256=reference, artifact_sha256=evidence_hash), artifact),
            (verifier, payload("attestation", "demo-verifier", "demo-attestation-1",
                               intent_sha256=reference, artifact_sha256=evidence_hash,
                               verdict="ACCEPT"), artifact),
        ]
        head = ledger.verify()["head"]
        stages = []
        for key, command, evidence in commands:
            result = ledger.submit(command, key.sign(signing_bytes(command)).hex(),
                                   artifact=evidence, expected_head=head)
            head = result["head"]
            stages.append(result["state"])
        replay = LocalLedger(root / "ledger.sqlite3", policy).verify(expected_head=head)
        print(json.dumps({"result": "LOCAL_DEMO_COMPLETE", "stages": stages,
                          "events_replayed": replay["events"],
                          "final_state": replay["missions"]["demo-mission-1"]["state"],
                          "storage": "temporary; removed after demonstration"}))


if __name__ == "__main__":
    main()
