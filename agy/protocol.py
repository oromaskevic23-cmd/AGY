"""Signed messages and deterministic state transitions for the local prototype."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class ProtocolError(ValueError):
    """A local policy or signed command was rejected."""


IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
SIGNATURE = re.compile(r"[0-9a-f]{128}\Z")
DOMAIN = b"AGY-LOCAL-SIGNED-COMMAND-V1\x00"
CHECKPOINT_DOMAIN = b"AGY-LOCAL-CHECKPOINT-V1\x00"
MAX_VALIDITY_SECONDS = 3600
COMMON = {"kind", "network_id", "actor_id", "nonce", "issued_at", "expires_at"}
EXTRAS = {
    "intent": {"mission_id", "capability"},
    "approval": {"mission_id", "intent_sha256", "decision"},
    "evidence": {"mission_id", "intent_sha256", "artifact_sha256"},
    "attestation": {"mission_id", "intent_sha256", "artifact_sha256", "verdict"},
    "revoke": {"target_actor_id", "reason_code", "policy_sha256"},
    "halt": {"reason_code", "policy_sha256"},
}
REASON_CODES = ("COMPROMISE", "MISUSE", "OWNER_DECISION", "OTHER")


def canonical_json(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ProtocolError("value is not canonicalizable JSON") from exc


def signing_bytes(payload: dict) -> bytes:
    return DOMAIN + canonical_json(payload)


def checkpoint_signing_bytes(payload: dict) -> bytes:
    return CHECKPOINT_DOMAIN + canonical_json(payload)


def intent_digest(payload: dict) -> str:
    return hashlib.sha256(signing_bytes(payload)).hexdigest()


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or not IDENTIFIER.fullmatch(value):
        raise ProtocolError("invalid " + label)
    return value


def _digest(value: object, label: str) -> str:
    if type(value) is not str or not HASH.fullmatch(value):
        raise ProtocolError("invalid " + label)
    return value


def validate_policy(raw: dict) -> dict:
    """Copy and validate an operator-supplied, locally trusted development policy."""
    if type(raw) is not dict:
        raise ProtocolError("invalid policy fields")
    base_fields = {"schema", "network_id", "agents", "approvers", "verifiers"}
    if raw.get("schema") == "agy.local-policy.v1" and set(raw) == base_fields:
        roles = ("agents", "approvers", "verifiers")
    elif raw.get("schema") == "agy.local-policy.v2" and set(raw) == base_fields | {"owners"}:
        if type(raw["owners"]) is not dict or not raw["owners"]:
            raise ProtocolError("v2 policy requires at least one owner")
        roles = ("agents", "approvers", "verifiers", "owners")
    else:
        raise ProtocolError("unsupported policy schema or invalid fields")
    policy = copy.deepcopy(raw)
    _identifier(policy["network_id"], "network ID")
    seen_ids = set()
    seen_keys = set()
    for role in roles:
        entries = policy[role]
        if type(entries) is not dict or len(entries) > 1000:
            raise ProtocolError("invalid policy entries")
        for actor, entry in entries.items():
            _identifier(actor, "actor ID")
            if actor in seen_ids:
                raise ProtocolError("actor IDs must be unique across roles")
            seen_ids.add(actor)
            if role == "agents":
                if type(entry) is not dict or set(entry) != {"public_key", "capabilities"}:
                    raise ProtocolError("invalid agent policy")
                capabilities = entry["capabilities"]
                if type(capabilities) is not list or len(capabilities) > 128:
                    raise ProtocolError("invalid capabilities")
                for capability in capabilities:
                    _identifier(capability, "capability")
                if len(set(capabilities)) != len(capabilities):
                    raise ProtocolError("duplicate capabilities")
                key = entry["public_key"]
            else:
                key = entry
            _digest(key, "public key")
            if key in seen_keys:
                raise ProtocolError("public keys must be distinct across actors and roles")
            seen_keys.add(key)
    return policy


def _validated_payload(payload: object, policy: dict, at: int) -> tuple[dict, str]:
    if type(payload) is not dict:
        raise ProtocolError("command must be an object")
    kind = payload.get("kind")
    if type(kind) is not str or kind not in EXTRAS or set(payload) != COMMON | EXTRAS[kind]:
        raise ProtocolError("invalid command fields")
    for field_name in ("network_id", "actor_id", "nonce"):
        _identifier(payload[field_name], field_name)
    if kind in ("intent", "approval", "evidence", "attestation"):
        _identifier(payload["mission_id"], "mission_id")
    if kind == "revoke":
        _identifier(payload["target_actor_id"], "target actor ID")
    if kind in ("revoke", "halt") and payload["reason_code"] not in REASON_CODES:
        raise ProtocolError("invalid owner control reason")
    if kind in ("revoke", "halt"):
        _digest(payload["policy_sha256"], "policy digest")
        if payload["policy_sha256"] != hashlib.sha256(canonical_json(policy)).hexdigest():
            raise ProtocolError("owner control does not match the local policy")
    if payload["network_id"] != policy["network_id"]:
        raise ProtocolError("wrong network")
    issued = payload["issued_at"]
    expires = payload["expires_at"]
    if (type(issued) is not int or type(expires) is not int or type(at) is not int
            or issued < 0 or expires <= issued or expires - issued > MAX_VALIDITY_SECONDS
            or not issued <= at <= expires):
        raise ProtocolError("command is outside its validity window")
    if kind == "intent":
        _identifier(payload["capability"], "capability")
    elif kind in ("approval", "evidence", "attestation"):
        _digest(payload["intent_sha256"], "intent digest")
    if kind in ("evidence", "attestation"):
        _digest(payload["artifact_sha256"], "artifact digest")
    if kind == "approval" and payload["decision"] not in ("APPROVE", "DENY"):
        raise ProtocolError("invalid approval decision")
    if kind == "attestation" and payload["verdict"] not in ("ACCEPT", "REJECT"):
        raise ProtocolError("invalid attestation verdict")
    return payload, kind


@dataclass
class ProtocolState:
    missions: dict = field(default_factory=dict)
    used_nonces: set = field(default_factory=set)
    revoked_actors: set = field(default_factory=set)
    halted: bool = False

    def apply(self, payload: dict, signature: str, policy: dict, at: int) -> dict:
        payload, kind = _validated_payload(payload, policy, at)
        actor = payload["actor_id"]
        nonce = (actor, payload["nonce"])
        if nonce in self.used_nonces:
            raise ProtocolError("nonce already used by actor")
        if actor in self.revoked_actors:
            raise ProtocolError("actor has been revoked")
        if self.halted and kind in ("intent", "approval", "evidence"):
            raise ProtocolError("local admission is halted")
        role = {"intent": "agents", "evidence": "agents", "approval": "approvers",
                "attestation": "verifiers", "revoke": "owners", "halt": "owners"}[kind]
        entry = policy.get(role, {}).get(actor)
        if entry is None:
            raise ProtocolError("actor has no role for this command")
        key_hex = entry["public_key"] if role == "agents" else entry
        if type(signature) is not str or not SIGNATURE.fullmatch(signature):
            raise ProtocolError("invalid signature format")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(
                bytes.fromhex(signature), signing_bytes(payload))
        except (InvalidSignature, ValueError) as exc:
            raise ProtocolError("signature verification failed") from exc

        if kind == "revoke":
            target = payload["target_actor_id"]
            if not any(target in policy[role] for role in ("agents", "approvers", "verifiers")):
                raise ProtocolError("target is not a revocable actor")
            if target in self.revoked_actors:
                raise ProtocolError("actor is already revoked")
            self.revoked_actors.add(target)
            for mission in self.missions.values():
                if (mission["state"] in ("PENDING_APPROVAL", "AUTHORIZED")
                        and (mission["agent_id"] == target or mission["approved_by"] == target)):
                    mission["state"] = "BLOCKED_REVOKED"
            self.used_nonces.add(nonce)
            return {"state": "REVOKED", "target_actor_id": target}
        if kind == "halt":
            if self.halted:
                raise ProtocolError("local admission is already halted")
            self.halted = True
            for mission in self.missions.values():
                if mission["state"] in ("PENDING_APPROVAL", "AUTHORIZED"):
                    mission["state"] = "BLOCKED_HALTED"
            self.used_nonces.add(nonce)
            return {"state": "HALTED"}

        mission_id = payload["mission_id"]
        mission = self.missions.get(mission_id)
        if kind == "intent":
            if mission is not None:
                raise ProtocolError("mission already exists")
            if payload["capability"] not in entry["capabilities"]:
                raise ProtocolError("capability denied by local policy")
            mission = {"state": "PENDING_APPROVAL", "agent_id": actor,
                       "capability": payload["capability"],
                       "intent_sha256": intent_digest(payload),
                       "intent_expires_at": payload["expires_at"],
                       "authorization_expires_at": None, "approved_by": None,
                       "artifact_sha256": None}
            self.missions[mission_id] = mission
        else:
            if mission is None or payload["intent_sha256"] != mission["intent_sha256"]:
                raise ProtocolError("command does not bind to an existing intent")
            if kind == "approval":
                if mission["state"] != "PENDING_APPROVAL" or at > mission["intent_expires_at"]:
                    raise ProtocolError("mission is not waiting for approval")
                mission["state"] = "AUTHORIZED" if payload["decision"] == "APPROVE" else "DENIED"
                if payload["decision"] == "APPROVE":
                    mission["approved_by"] = actor
                    mission["authorization_expires_at"] = min(payload["expires_at"],
                                                              mission["intent_expires_at"])
            elif kind == "evidence":
                if (mission["state"] != "AUTHORIZED" or actor != mission["agent_id"]
                        or at > mission["authorization_expires_at"]):
                    raise ProtocolError("evidence is not authorized")
                mission["artifact_sha256"] = payload["artifact_sha256"]
                mission["state"] = "EVIDENCE_SUBMITTED"
            else:
                if (mission["state"] != "EVIDENCE_SUBMITTED"
                        or payload["artifact_sha256"] != mission["artifact_sha256"]):
                    raise ProtocolError("attestation does not match submitted evidence")
                mission["state"] = ("ATTESTED_ACCEPTED" if payload["verdict"] == "ACCEPT"
                                    else "ATTESTED_REJECTED")
        self.used_nonces.add(nonce)
        return copy.deepcopy(mission)
