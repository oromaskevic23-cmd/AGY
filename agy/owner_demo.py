"""Demonstrate disposable local owner controls and a signed checkpoint."""

import hashlib
import json
from pathlib import Path
import tempfile
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agy.local_ledger import LocalLedger
from agy.protocol import (ProtocolError, canonical_json, checkpoint_signing_bytes,
                          intent_digest, signing_bytes)


def _public_hex(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def main():
    owner, agent1, agent2, approver, verifier = (
        Ed25519PrivateKey.generate() for _ in range(5))
    now = int(time.time())
    network = "agy-owner-demo"
    policy = {
        "schema": "agy.local-policy.v2", "network_id": network,
        "agents": {"agent-1": {"public_key": _public_hex(agent1), "capabilities": ["read.report"]},
                   "agent-2": {"public_key": _public_hex(agent2), "capabilities": ["read.report"]}},
        "approvers": {"approver-1": _public_hex(approver)},
        "verifiers": {"verifier-1": _public_hex(verifier)},
        "owners": {"owner-1": _public_hex(owner)},
    }
    policy_hash = hashlib.sha256(canonical_json(policy)).hexdigest()

    def payload(kind, actor, nonce, **extra):
        return {"kind": kind, "network_id": network, "actor_id": actor, "nonce": nonce,
                "issued_at": now, "expires_at": now + 300, **extra}

    with tempfile.TemporaryDirectory(prefix="agy-owner-demo-") as directory:
        root = Path(directory)
        artifact = root / "evidence.txt"
        artifact.write_bytes(b"AGY owner-control demonstration\n")
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        ledger = LocalLedger(root / "ledger.sqlite3", policy)
        head = ledger.verify()["head"]

        def record(key, command, evidence=None):
            nonlocal head
            result = ledger.submit(command, key.sign(signing_bytes(command)).hex(),
                                   artifact=evidence, expected_head=head)
            head = result["head"]
            return result

        def must_reject(key, command, evidence=None):
            try:
                record(key, command, evidence)
            except ProtocolError:
                return "REJECTED"
            raise RuntimeError("local owner control did not reject a blocked action")

        intent1 = payload("intent", "agent-1", "intent-1", mission_id="mission-1",
                          capability="read.report")
        record(agent1, intent1)
        record(approver, payload("approval", "approver-1", "approval-1", mission_id="mission-1",
                                 intent_sha256=intent_digest(intent1), decision="APPROVE"))
        record(owner, payload("revoke", "owner-1", "revoke-1", target_actor_id="agent-1",
                              reason_code="OWNER_DECISION", policy_sha256=policy_hash))
        rejected_agent = must_reject(
            agent1, payload("evidence", "agent-1", "evidence-1", mission_id="mission-1",
                            intent_sha256=intent_digest(intent1), artifact_sha256=digest), artifact)

        intent2 = payload("intent", "agent-2", "intent-2", mission_id="mission-2",
                          capability="read.report")
        record(agent2, intent2)
        record(owner, payload("halt", "owner-1", "halt-1", reason_code="OWNER_DECISION",
                              policy_sha256=policy_hash))
        rejected_approval = must_reject(
            approver, payload("approval", "approver-1", "approval-2", mission_id="mission-2",
                              intent_sha256=intent_digest(intent2), decision="APPROVE"))
        checkpoint = ledger.checkpoint_payload("owner-1", expected_head=head)
        signature = owner.sign(checkpoint_signing_bytes(checkpoint)).hex()
        replay = LocalLedger(root / "ledger.sqlite3", policy).verify_checkpoint(checkpoint, signature)
        print(json.dumps({"result": "LOCAL_OWNER_DEMO_COMPLETE", "halted": replay["halted"],
                          "revoked_agent_action": rejected_agent,
                          "post_halt_approval": rejected_approval,
                          "checkpoint": "SIGNATURE_AND_HEAD_VERIFIED",
                          "events_replayed": replay["events"],
                          "storage": "temporary; removed after demonstration"}))


if __name__ == "__main__":
    main()
