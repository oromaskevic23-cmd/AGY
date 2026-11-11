# Consensus and evidence: design proposal

Author & Architect: Alexander Romaskevich (RomaskevicH)

**Status: DRAFT / NOT APPROVED / NOT IMPLEMENTED.** This proposal elaborates the
existing BFT direction. It does not select a consensus engine, establish token
economics, or authorize a network launch. Final architectural decisions remain
with the Architect.

## Separate questions

1. **Consensus** orders and finalizes valid state transitions under a defined
   validator membership and fault model. Finalizing an attestation means the
   network agreed to record it; it does not prove the underlying work was real.
2. **Evidence verification** assesses a mission against agreed criteria using
   independent verifiers and recorded results. A checksum detects differences
   relative to a trusted digest; it does not authenticate an issuer or establish
   that a result is correct or useful.
3. **Reputation** may summarize verified outcomes within a defined domain and
   time window. It must be challengeable and resistant to self-dealing. A high
   score alone grants neither validator votes nor financial authority.

Proof of Evidence or Proof of Mission may describe application-level evidence
rules. Neither is selected as a consensus algorithm here. Combining a BFT
ordering layer with an evidence-verification layer is the design candidate;
independent review and the Architect's decision are required.

## Initial research model

For a fixed, equally weighted validator set of `n = 3f + 1`, one candidate
fault model allows at most `f` Byzantine validators and uses quorums of
`2f + 1` distinct validators. Two such quorums share at least `f + 1` members:
`2(2f + 1) - (3f + 1) = f + 1`. With at most `f` faulty validators, at least
one overlapping validator is honest. This intersection alone is not a complete
consensus protocol or safety proof: voting and locking rules, signatures,
membership changes, recovery, and timing assumptions must also be specified.
The numbers are illustrative for this exact model, not a blanket claim for all
BFT systems or weighted validator sets. A reference for comparison is the
[CometBFT specification](https://github.com/cometbft/cometbft/blob/main/spec/README.md).

Research a small permissioned development network first, with separately
operated validators and explicit membership. Network partitions may stop
progress; liveness depends on the chosen algorithm and network assumptions.
Selection, admission, removal, key rotation, common-control concentration,
reconfiguration, equivocation handling and recovery remain open. Do not build a
new consensus algorithm merely by counting reputation points.

## Evidence and control boundary

- A mission defines its scope, authorized execution, acceptance criteria,
  verification policy, expiry and dispute process before execution.
- Guardian Core evaluates policy; Approval Gateway provides any separately
  required approval. Capability, agent identity and validator role do not
  replace approval. Deny or hold when required checks are unavailable.
- Evidence is collected off-chain where practical. Commitments on-chain should
  avoid private information; even hashes can leak information about predictable
  inputs. Retention, access and deletion rules require a separate design.
- Independent verifiers check evidence against versioned mission criteria;
  signatures, issuer trust, conflicts of interest, replay protection, appeals
  and revocation need a concrete specification. A receipt's integrity is not
  evidence that these checks happened.
- Validators validate protocol rules and record authorized attestations; they
  must not infer external truth solely from consensus or agent reputation.
- Audit Ledger records decisions and their provenance. AI Passport identifies
  agents but does not automatically authorize actions. Preserve the
  public/private boundary and the CRYPTO IMPERIAL Ecosystem Boundary.

## Economics and asset boundary

Zero fees for normal protocol operations are a target, not a measured property;
hosting, storage, verification and abuse prevention still have costs. Funding,
quotas, sponsorship and any optional service charges remain undecided. A fee
charged on every normal operation would conflict with the current zero-fee
target unless the Architect explicitly changes that target.

IMPERIUM is the long-term architectural digital-currency vision for AI agents
worldwide. It is a separate project: its role as an AGY native asset, settlement
asset, staking instrument, or governance token requires a separate architectural
decision. No current global use or market status is implied.

## Acceptance before stronger claims

1. Specify the exact consensus protocol, threat assumptions, membership and
   recovery rules; obtain independent design and security review.
2. Specify signed, replay-resistant evidence and verifier independence, with
   test vectors, revocation, appeals and privacy analysis.
3. Implement and test a multi-validator devnet, including crashes, partitions,
   Byzantine behavior, restart and reconfiguration scenarios.
4. Measure cost, throughput and finality under documented workloads; publish
   reproducible results and limitations. Verify mainnet gates separately.

The [offline integrity prototype](../examples/evidence/README.md) is a narrow
local experiment. It is not the proposed consensus or a verifier of mission
truth, identities, signatures, approvals, or payments.
