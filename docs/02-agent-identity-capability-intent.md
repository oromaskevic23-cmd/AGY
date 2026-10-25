Author & Architect: Alexander Romaskevich (RomaskevicH)

Agent identity, capability, and intent

Identity
- AI Passport: cryptographic binding of agent metadata, public keys, and attested attributes.
- Identity is NOT authority. Identity provides an anchor for accountability and provenance.

Capability
- Capabilities are scoped permissions and interfaces an agent can request or be granted.
- Capability is NOT approval; execution requires separate authorization.

Intent
- Intent encodes the high-level goal an agent expresses. Intents are structured, signed assertions possibly carrying constrained parameters and resources.

Data models (high level)
- Passport: {id, public_key, issuer, attestations[]}
- Capability descriptor: {capability_id, scope, constraints, delegation_policy}
- Intent envelope: {intent_id, actor_id, capability_refs[], mission_spec, expiry, nonce, signature}

Interaction flow
1. Agent provisions AI Passport.
2. Agent requests or advertises Capabilities.
3. Agent expresses Intent (signed intent envelope).
4. Intent is evaluated by Authorization (Guardian) before mission execution.
