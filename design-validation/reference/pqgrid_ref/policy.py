"""Signed policy model + topic->tier engine (strongest matching rule wins; no match -> CONTROL)."""
from __future__ import annotations
import json
from dataclasses import dataclass
from enum import IntEnum

class Tier(IntEnum):
    TELEMETRY = 1
    ALERT = 2
    CONTROL = 3

class PolicyError(ValueError): pass

_ID = __import__("re").compile(rb"^[a-z0-9][a-z0-9-]{0,31}$")
def valid_device_id(did: bytes) -> bool:
    """Device IDs become MQTT topic levels and ACL usernames: no '/', '+', '#', spaces, or unicode tricks."""
    return bool(_ID.match(did))

def topic_matches(pattern: str, topic: str) -> bool:
    p, t = pattern.split("/"), topic.split("/")
    for i, seg in enumerate(p):
        if seg == "#": return i == len(p) - 1
        if i >= len(t): return False
        if seg != "+" and seg != t[i]: return False
    return len(p) == len(t)

@dataclass(frozen=True)
class Policy:
    policy_id: str
    version: int
    rules: tuple
    classes: dict
    utility_kem_pk: bytes
    utility_cmd_pk: bytes
    raw: bytes

    def tier(self, topic: str) -> Tier:
        hits = [Tier[r["tier"]] for r in self.rules if topic_matches(r["pattern"], topic)]
        return max(hits) if hits else Tier.CONTROL          # fail-safe default

    def info(self) -> bytes:                                  # POLICY_INFO, bound into keys
        return self.policy_id.encode() + b"|" + self.version.to_bytes(4, "big")

def build(policy_id, version, rules, classes, utility_kem_pk, utility_cmd_pk) -> bytes:
    doc = {"policy_id": policy_id, "version": version, "default_tier": "CONTROL", "rules": rules,
           "classes": classes, "utility_kem_pk": utility_kem_pk.hex(), "utility_cmd_pk": utility_cmd_pk.hex()}
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    validate(load(raw)); return raw

def load(raw: bytes) -> Policy:
    d = json.loads(raw)
    return Policy(d["policy_id"], int(d["version"]), tuple(d["rules"]), d["classes"],
                  bytes.fromhex(d["utility_kem_pk"]), bytes.fromhex(d["utility_cmd_pk"]), raw)

MAX_TICKET_S = 7 * 86400
def validate(p: Policy) -> None:
    for r in p.rules:
        if r["tier"] not in Tier.__members__: raise PolicyError(f"bad tier {r['tier']}")
    for name, c in p.classes.items():
        if c["resume"] not in ("NONE", "PSK", "PSK_KEM"): raise PolicyError(f"{name}: bad resume mode")
        if c.get("unicast_control") and c["resume"] == "PSK":
            raise PolicyError(f"{name}: receives unicast control, so PSK-only resumption (no forward secrecy) is forbidden")
        if not (0 < c["ticket_lifetime_s"] <= c["max_chain_age_s"] <= MAX_TICKET_S):
            raise PolicyError(f"{name}: lifetimes must satisfy 0 < ticket <= chain <= 7 days")
