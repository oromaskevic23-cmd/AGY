# AGY v0.3 — Sovereign Agent Control & Recovery (offline reference)

**Owner / Architect:** Alexander Nikolaevich Romaskevich (RomaskevicH)  
**Status:** LOCAL_ONLY / EXPERIMENTAL / NOT SECURITY AUDITED.  
**Mission:** [Directive 016](https://github.com/oromaskevic23-cmd/AGY/issues/6).

## What is demonstrably implemented

An existing v2 owner-signed `halt` or `revoke` is accepted into AGY's local,
hash-linked SQLite journal, then interpreted by `LocalControlRuntime`, which
only supervises a fixed disposable Python worker. A stop is reported as
`STOP_CONFIRMED` **only after the supervisor sees the process exit**.
`STOP_ACKNOWLEDGED` is used only when that worker explicitly sends an ACK.
An OS terminate/kill request is not itself an ACK or proof of termination.

The owner-signed `resume` is new: it is bound to the policy digest and exact
immediately preceding journal head (`control_head`) and must advance the
monotonically incremented local `control_epoch`. To submit it, the caller
must supply the separately retained latest head as `expected_head`. Restart
does not automatically clear a halted ledger. Revoked actors remain revoked.
An old intent or approval becomes `BLOCKED_HALTED`, never resurrected. A
subsequent worker requires an entirely new approved intent with a fresh ID.
Attestation of evidence accepted before the halt remains allowed.

**This is not a production kill switch:** the journal by itself cannot stop
externally running processes. This adapter sees only processes it launched.
It is neither a sandbox nor an authenticated network interface. A separate
client that modifies the ledger without calling the runtime adapter can
leave running processes alive. No remote executor, real HANTER production
deployment, persistent process supervision, crash-consistent cross-process
fencing, AI Passport issuance, Guardian Core deployment, approval service,
BFT consensus, validator mesh or AGY blockchain exists as a result of this PR.

## Offline demonstration

Python 3.10+ with the pinned dependency from `requirements.txt`:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m agy.runtime_demo
.venv/bin/python -m unittest discover -s tests -v
```

The demonstration uses fresh temporary Ed25519 keys, a disposable worker,
temporary SQLite database, separate local anchor, and local audit file. It
makes no network calls after dependencies are installed. Nothing is deployed.
The demo deliberately cleans up its second worker via test-only teardown;
this is **not** an owner-authorized kill-switch operation.

## Local reference integration contract for HANTER

HANTER is the central AI Command Center, not a global orchestrator. AGY's
architecture remains federated: Architect → HANTER command boundary →
domain orchestrator → NCA executor → independently inspected execution
receipt. Domain orchestrators do not inherit authority from mere possession
of AGY records.

Proposed **local-only**, versioned request structure:

```json
{
  "schema": "agy.hanter-control-request.v1",
  "correlation_id": "correlation-123",
  "target_agent_id": "agent-1",
  "requested_action": "halt",
  "signed_owner_command": {
    "kind": "halt",
    "network_id": "agy-v03-disposable",
    "actor_id": "owner-1",
    "nonce": "owner-halt",
    "issued_at": 1750000000,
    "expires_at": 1750000300,
    "policy_sha256": "64_lowercase_hex_chars",
    "reason_code": "OWNER_DECISION"
  },
  "owner_signature_hex": "128_lowercase_hex_chars",
  "trusted_head": "64_lowercase_hex_chars"
}
```

**This is an illustrative schema, not a live endpoint.** The numeric times,
hexadecimal values, and identifiers above are illustrative. Exact command
fields, sign bytes and policy validation are defined by `agy.protocol`. The
`correlation_id` and requested target are **not authenticated** by the owner
signature and must never grant any authority. The `halt` command applies to
the whole local policy; target-specific controls require a separately signed
`revoke`. Do not infer that `target_agent_id` restricts a global halt.
A production adapter must authenticate its transport, bind intended target
and authorization scope in the owner signature, establish idempotency,
deadlines, replay prevention, independent runtime receipts and secure queues
before any live integration.

Local result fields: `sequence`, `head`, `state`, `stop_receipts[]`.
Each stop receipt includes `mission_id`, `state`, `stages[]`,
`worker_acknowledged`, and `exit_code`. The stages distinguish
`STOP_REQUESTED`, optional explicit `STOP_ACKNOWLEDGED`,
`STOP_CONFIRMED` and `STOP_UNCONFIRMED`.
`STOP_UNCONFIRMED` must not be interpreted as a successful kill.
The owner must receive a failure/unknown result rather than a false PASS.

## Security and provenance boundaries

- Preserve all v1 bytes and hash vectors; no implicit v1→v2 migration.
- v2+ `resume` uses existing command Ed25519 domain, is restricted to a
  configured owner, checks the exact pre-event head at submission and replay,
  and increments the control epoch. There is no owner key rotation,
  multisignature threshold, reinstatement, durable cross-process distributed
  lease, or live Approval Gateway integration.
- The `LocalHeadAnchor` file uses atomic local replacement and is deliberately
  **separate from the SQLite journal**, but both remain in the same local trust
  domain in the demo. A malicious operator who can replace both can roll
  them back together. Independently protect/retain the latest anchor
  off-host/out-of-band before making any freshness claim.
- The `LocalSecurityAudit` is a hash-linked local supplementary log for
  runtime-adapter accepted/rejected owner controls. It does not log every
  rejected lower-level API attempt. Without an independent latest audit head
  it too is vulnerable to truncation and replacement. It is **not** a
  distributed immutable Audit Ledger.
- If the process cannot be confirmed exited, `STOP_UNCONFIRMED` is emitted
  and resume is refused while the local worker process remains alive.
  It cannot prove that descendants or other remote workers have stopped.
- This reference is for local research only. Do not run untrusted worker
  code, spend funds, access sensitive data, or expose it to the internet.

## Further engineering gates

Before production: security design review, signed target-bound capabilities
and operational roles, owner key recovery, Guardian Core and Approval Gateway
enforcement, authenticated HANTER adapter and verified process/host control,
independent durable anchor store, watchdog restart policy, and adversarial
tests including cross-process races and system power loss.

IMPERIUM remains a long-term architectural digital currency concept for AI
agents worldwide. There is no claim of AGY payments or global agent adoption.
