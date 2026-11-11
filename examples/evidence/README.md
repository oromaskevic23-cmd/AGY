# Offline evidence-integrity prototype

This local, dependency-free Python prototype checks an artifact against an
evidence receipt whose exact SHA-256 digest is supplied independently by the
operator. It demonstrates integrity checking only. It is not an AGY blockchain,
consensus protocol, signed attestation, AI Passport, approval, reputation
engine, or verification that a mission was performed correctly.

## Run the example

From the repository root with Python 3.10 or later:

```sh
python3 tools/verify_evidence.py \
  --receipt examples/evidence/receipt.json \
  --artifact examples/evidence/artifact.txt \
  --expected-receipt-sha256 9980b63d569977f01bdc19ed7dfa0baf7d44f86c221fa8b7e960ba8a6dfc6e13
```

For the unchanged sample, the output is `INTEGRITY_MATCH` and the process exits
with status 0. Altering the artifact or receipt makes the check fail with a
nonzero status. The pinned digest above is for demonstration only.

Run the local tests with:

```sh
python3 -m unittest discover -s tests -v
```

## Trust and limits

The caller must receive the expected receipt digest over an independently
trusted channel. If an attacker can replace the receipt, the artifact **and**
the expected digest, this check cannot detect the substitution. A matching
digest authenticates neither the issuer nor the verifier and proves neither
authorization nor the truth or usefulness of a mission result. Key management,
digital signatures, replay prevention, expiry, audit, privacy, robust file
handling under adversarial races, and production review are not implemented.

The v1 sample receipt contains only `schema`, `mission_id`,
`artifact_sha256`, and `artifact_size_bytes`. The trusted digest covers the
exact receipt bytes, including whitespace. Keep private evidence out of public
repositories and do not use sample keys or digests as trust anchors.
