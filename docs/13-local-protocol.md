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
.venv/bin/python -m unittest discover -s tests -v
```

On Windows, use `.venv\Scripts\python.exe` instead. The demo generates three
temporary Ed25519 keys in memory, creates a temporary SQLite database, checks a
small local file, reopens and replays the journal, and removes the temporary
files on completion. It makes no network calls. The dependency must be
installed beforehand; installation itself may need network access.

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
  lists; it is bound to the database at initialization. Policy change, key
  rotation and revocation are not implemented for an existing ledger.
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
rotation and revocation, complete audit handling, persistent evidence storage,
recovery, and a selected BFT protocol. Implement a multi-validator devnet and
test failures, partitions and adversarial behavior. Performance, zero-fee
economics, production security and any IMPERIUM role remain unverified.
