"""Reproducible offline AGY v0.3 test worker stop and owner recovery."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agy.local_control_runtime import LocalControlRuntime, LocalSecurityAudit
from agy.local_head_anchor import LocalHeadAnchor
from agy.local_ledger import LocalLedger
from agy.protocol import canonical_json, intent_digest, signing_bytes


def public_hex(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def main():
    owner, agent, approver, verifier = (Ed25519PrivateKey.generate() for _ in range(4))
    now = int(time.time())
    policy = {
        "schema": "agy.local-policy.v2", "network_id": "agy-v03-disposable",
        "agents": {"agent-1": {"public_key": public_hex(agent),
                                 "capabilities": ["read.report"]}},
        "approvers": {"approver-1": public_hex(approver)},
        "verifiers": {"verifier-1": public_hex(verifier)},
        "owners": {"owner-1": public_hex(owner)}}
    policy_hash = hashlib.sha256(canonical_json(policy)).hexdigest()

    def command(kind, actor, nonce, **fields):
        return {"kind": kind, "network_id": policy["network_id"], "actor_id": actor,
                "nonce": nonce, "issued_at": now, "expires_at": now + 300, **fields}

    def sign(key, payload):
        return key.sign(signing_bytes(payload)).hex()

    with tempfile.TemporaryDirectory(prefix="agy-runtime-v03-") as temporary:
        path = Path(temporary)
        ledger = LocalLedger(path / "journal.sqlite3", policy)
        head = ledger.verify()["head"]
        anchor = LocalHeadAnchor(path / "trusted-head.json", initial_head=head)
        audit = LocalSecurityAudit(path / "security-audit.jsonl")
        runtime = LocalControlRuntime(ledger, audit=audit)

        def keep(record):
            nonlocal head
            anchor.advance(head, record["head"])
            head = record["head"]
            return record

        def submit(key, payload):
            return keep(ledger.submit(payload, sign(key, payload), expected_head=head))

        def authorize(mission):
            intent = command("intent", "agent-1", "intent-" + mission,
                             mission_id=mission, capability="read.report")
            submit(agent, intent)
            approve = command("approval", "approver-1", "approval-" + mission,
                              mission_id=mission, intent_sha256=intent_digest(intent),
                              decision="APPROVE")
            submit(approver, approve)

        try:
            authorize("before-halt")
            first = runtime.start("before-halt", expected_head=head)
            halt_command = command("halt", "owner-1", "owner-halt",
                                   reason_code="OWNER_DECISION", policy_sha256=policy_hash)
            halt_result = keep(runtime.halt(
                halt_command, sign(owner, halt_command), expected_head=head))
            if not halt_result["fully_stopped"]:
                raise RuntimeError("test worker could not be proven stopped")

            resume_command = command("resume", "owner-1", "owner-resume",
                                     reason_code="OWNER_DECISION", policy_sha256=policy_hash,
                                     control_head=head,
                                     control_epoch=ledger.verify(expected_head=head)["control_epoch"] + 1)
            resume_result = keep(runtime.resume(
                resume_command, sign(owner, resume_command), expected_head=head))
            authorize("after-resume")
            second = runtime.start("after-resume", expected_head=head)
            # Local test teardown, not owner-authorized production execution.
            runtime.cleanup_disposable_workers()
            print(json.dumps({
                "result": "LOCAL_RUNTIME_V03_DEMO_COMPLETE",
                "execution_scope": "single host / disposable fixed worker",
                "first_worker_pid": first["pid"],
                "halt": halt_result["state"],
                "stopped": halt_result["stop_receipts"][0]["state"],
                "resume": resume_result["state"],
                "new_worker_started": second["status"],
                "control_epoch": ledger.verify(expected_head=anchor.read())["control_epoch"],
                "audit_events": audit.verify()["events"],
                "checkpoint_in_separate_file": True,
                "production_hanter_connected": False,
                "production_blockchain": False
            }, sort_keys=True))
        finally:
            runtime.cleanup_disposable_workers()


if __name__ == "__main__":
    main()
