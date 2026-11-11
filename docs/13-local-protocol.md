# AGY local signed mission prototype

Author & Architect: Alexander Romaskevich (RomaskevicH)

**Status: EXPERIMENTAL / LOCAL ONLY / NOT SECURITY AUDITED.** This prototype
implements a narrow mission-state journal with signed commands. It does not
implement a blockchain network, BFT consensus, a deployed node, AI Passport,
the production Guardian Core or Approval Gateway, payments, or execution of an
agent's work. Do not use it for real authority, funds, or sensitive evidence.

## Run

Install Python 3.10 or later and the pinned development dependency in an
isolated environment. On Unix-like systems, from the repository root:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m agy.demo
.venv/bin/python -m agy.owner_demo
.venv/bin/python -m unittest discover -s tests -v
```

On Windows, use `.venv\Scripts\python.exe` instead. The demos generate temporary
Ed25519 keys in memory, create temporary SQLite databases, replay the journals,
and remove the temporary files on completion. The owner demo additionally
exercises a revocation, a halt and a signed checkpoint. The demos make no
network calls. The dependency must be installed beforehand; installation itself
may need network access.

## Local command interface

The optional CLI accepts a trusted local policy JSON file, a command JSON file
and its detached Ed25519 signature in hexadecimal. It does not generate, read
or store private keys. Construct a signature in a separate trusted signer using
`private_key.sign(signing_bytes(command)).hex()`, where `signing_bytes` is
provided by `agy.protocol`. Protect signing keys outside this prototype.

Initialize a new ledger and independently retain the returned `head`:

```sh
python3 -m agy.cli init --database ledger.sqlite3 --policy policy.json
```

For each signed command, set `TRUSTED_HEAD` to the independently retained head
from the preceding accepted event, then submit it:

```sh
python3 -m agy.cli submit --database ledger.sqlite3 --policy policy.json \
  --command command.json --signature signature.txt --expected-head "$TRUSTED_HEAD"
```

Evidence and attestation commands also require `--artifact PATH`. Retain the
newly returned head independently before the next operation. Check an existing
ledger against a retained head with:

```sh
python3 -m agy.cli verify --database ledger.sqlite3 --policy policy.json \
  --expected-head "$TRUSTED_HEAD"
```

`init` refuses to overwrite an existing file. `submit` requires a head anchor;
`verify` can run without one but reports `anchor_checked: false`, so it cannot
detect rollback to a prior valid history. Neither `submit` nor `verify` creates
a missing ledger. See [the end-to-end CLI tests](../tests/test_cli_protocol.py)
for policy and signed-command examples using temporary test keys.

## Owner controls in policy v2

The new `agy.local-policy.v2` format adds an `owners` map of owner IDs to
distinct, trusted public keys. It requires at least one owner key; keys and IDs
must be distinct from agent, approver and verifier identities. One configured
owner signature is sufficient in this prototype. There is no multisignature
threshold, owner-key rotation or owner revocation.

Policy v1 remains supported and its existing signed events retain their hashes.
It has no configured owner role and therefore cannot accept the new owner
commands. Existing ledgers are bound to their original policy; there is no
in-place v1-to-v2 migration or automatic transfer of data.

An illustrative v2 policy has this shape. Replace every placeholder with a
distinct 32-byte public key encoded as 64 lowercase hexadecimal characters;
use a unique network ID for each independent local environment.

```json
{
  "schema": "agy.local-policy.v2",
  "network_id": "agy-local-unique-id",
  "agents": {
    "agent-1": {"public_key": "AGENT_PUBLIC_KEY_HEX", "capabilities": ["read.report"]}
  },
  "approvers": {"approver-1": "APPROVER_PUBLIC_KEY_HEX"},
  "verifiers": {"verifier-1": "VERIFIER_PUBLIC_KEY_HEX"},
  "owners": {"owner-1": "OWNER_PUBLIC_KEY_HEX"}
}
```

The placeholders are deliberately invalid until replaced. Never put private
keys in this policy or commit them to a repository.

An owner signs a `revoke` command to block a configured agent, approver or
verifier. A revoked agent cannot submit new intent or evidence. Revoking an
approver invalidates its pending authorizations; revoking a verifier blocks
future attestations from that key. Pending or authorized missions affected by
a revocation become `BLOCKED_REVOKED`. Evidence already accepted remains in
the journal and can still receive a separate verifier's attestation.

An owner-signed `halt` blocks new intents, approvals and evidence submissions
and marks pending or authorized missions `BLOCKED_HALTED`. Owner revocations
and attestations for evidence already submitted remain possible. Both controls
are one-way in this version: reinstatement, resumption and migration require a
future reviewed design. A local halt does not stop an external process or an
agent already executing elsewhere, and is not an integration with HANTER or
the production Owner Kill Switch.

Owner commands use the usual network, actor, nonce and validity fields, plus a
`policy_sha256` binding to the exact canonical policy and a fixed `reason_code`
(`COMPROMISE`, `MISUSE`, `OWNER_DECISION` or `OTHER`). A `revoke` command also
includes `target_actor_id`; a `halt` command has no mission ID. Send them via
the same `submit` CLI as other externally signed commands. Test examples use
temporary keys in [owner-control tests](../tests/test_owner_controls.py).

For a policy object already obtained from a trusted source, derive the policy
digest using the same canonical representation as the local journal:

```python
import hashlib
from agy.protocol import canonical_json, validate_policy

policy_sha256 = hashlib.sha256(canonical_json(validate_policy(policy))).hexdigest()
```

A revocation command has the following fields; replace the digest and times
with the actual policy digest and current Unix timestamps before signing:

```json
{
  "kind": "revoke",
  "network_id": "agy-local-unique-id",
  "actor_id": "owner-1",
  "nonce": "unique-owner-command-1",
  "issued_at": 1750000000,
  "expires_at": 1750000300,
  "policy_sha256": "REPLACE_WITH_POLICY_SHA256",
  "target_actor_id": "agent-1",
  "reason_code": "OWNER_DECISION"
}
```

## Signed checkpoints

The CLI can prepare an **unsigned** snapshot for an authorized owner signer.
Set `TRUSTED_HEAD` to the independently retained latest head:

```sh
python3 -m agy.cli checkpoint --database ledger.sqlite3 --policy policy.json \
  --owner-id owner-1 --expected-head "$TRUSTED_HEAD"
```

The result wraps the payload in its `checkpoint` field. Save that payload as
JSON and have a trusted external owner signer sign
`checkpoint_signing_bytes(checkpoint)` from `agy.protocol`. Store the detached
hex signature separately. The payload binds the network ID, policy hash, owner
ID, event count and journal head; checkpoint signatures use a separate domain
from command signatures. The CLI never reads a private signing key.

```sh
python3 -m agy.cli verify --database ledger.sqlite3 --policy policy.json \
  --checkpoint checkpoint.json --checkpoint-signature checkpoint.sig
```

A valid signature authenticates that checkpoint under the configured owner
key; verification also replays the local journal and requires the event count
and head to match. The result explicitly reports `freshness_verified: false`.
**A signed checkpoint does not prove it is the latest.** An
attacker who supplies an older valid checkpoint together with a matching rolled
back database can pass this check. The operator must obtain and retain the
latest trusted checkpoint or head independently and protect the local policy.

## Implemented local path

1. A signed agent intent identifies a mission, a capability, a nonce, a
   network ID, and a limited validity window. A locally configured policy
   checks the agent key and allowed capability. Unknown actors and capabilities
   are rejected. Each accepted intent starts as `PENDING_APPROVAL`.
2. A different configured approver key signs an `APPROVE` or `DENY` decision
   bound to the exact intent digest. Approval cannot be added after the intent
   expires. An agent key alone cannot act as the approver.
3. For an approved and unexpired intent, the original agent signs the evidence
   file's SHA-256 digest. The local implementation checks the supplied file
   against that digest before recording `EVIDENCE_SUBMITTED`.
4. A separate configured verifier key signs an `ACCEPT` or `REJECT`
   attestation bound to the intent and evidence digest. The supplied local file
   must match that digest. The result is named `ATTESTED_ACCEPTED` or
   `ATTESTED_REJECTED` to distinguish a signed opinion from proven truth.

Distinct keys do not establish independent people, organizations or machines.
The verifier's signature does not prove that its assessment was correct or
that the work was actually performed. The demonstration controls all three
keys in one process and is not a test of organizational independence.

## Data and trust assumptions

- The operator supplies and protects the local policy, process, system clock,
  keys and database. Policy contains public keys and explicit agent capability
  lists; it is bound to the database at initialization. Policy changes and key
  rotation are not implemented; v2 supports one-way local actor revocation.
- Signed messages use canonical JSON, Ed25519 signatures, protocol domain
  separation, an explicit network ID, one-use actor nonces and an expiry window
  of at most one hour. Replay checks apply within the surviving local ledger;
  duplicated environments with the same identity or rollback without a
  trusted anchor are not protected against replay.
- The journal records accepted transitions, including an explicit signed
  denial. Invalid or rejected requests are not recorded. It is not a complete
  security audit log. Only artifact digests are stored, not artifact contents;
  hashes and identifiers can still disclose information.
- SQLite transactions serialize local writes. Journal events are hash-linked
  and signatures are checked during replay. The database owner can truncate or
  rewrite local data. Store the latest trusted head independently and supply it
  to `verify(expected_head=...)` or `submit(..., expected_head=...)` to detect
  mismatch or rollback relative to that anchor. This does not turn the journal
  into an immutable or distributed ledger.
- New database files are created with owner-only file mode on POSIX systems.
  Existing file permissions are not changed. Secure directories, Windows ACLs,
  backups, file race protection, clock security and key custody remain the
  operator's responsibility. The demo does not persist private keys.
- Evidence files are limited to 64 MiB, and the research journal to 10,000
  events. Each operation replays the full journal; this is not a throughput or
  scalability design.

## Work before a network or production claim

Specify the network state machine and wire formats; independently review the
cryptography and authorization model; add secure identity issuance, key
rotation, production revocation, complete audit handling, persistent evidence
storage, recovery, and a selected BFT protocol. Implement a multi-validator devnet and
test failures, partitions and adversarial behavior. Performance, zero-fee
economics, production security and any IMPERIUM role remain unverified.
