"""Policy data model (Master §12 "Policy Structure").

A Policy is immutable. `raw` holds the exact signed bytes it was decoded from; nothing is ever
re-serialised for installation or verification (Master §12 "Signed Policy").
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
from types import MappingProxyType
from typing import Mapping, Optional

from ..errors import PolicyError
from ..suite.aead import AeadAlg


class Tier(IntEnum):
    """Ordered so that max() is "strongest" (Master §11)."""
    TELEMETRY = 1
    ALERT = 2
    CONTROL = 3


class ResumeMode(str, Enum):
    NONE = "NONE"
    PSK = "PSK"
    PSK_KEM = "PSK_KEM"


class Profile(str, Enum):
    FULL = "FULL"
    CONSTRAINED = "CONSTRAINED"


class Reconnect(str, Enum):
    BATCH = "BATCH"
    PERSISTENT = "PERSISTENT"


class CmdType(str, Enum):
    CMD = "CMD"
    GRANT = "GRANT"
    SETPOINT = "SETPOINT"


@dataclass(frozen=True)
class ClassProfile:
    """Per-class record. Fixed by the signed policy, never negotiated on the wire (I-20)."""
    name: str
    profile: Profile
    resume: ResumeMode
    ticket_lifetime_s: int
    max_chain_age_s: int
    unicast_control: bool
    cmd_types: frozenset
    max_setpoint_rate: int            # per minute
    aead: AeadAlg
    tls_max_record: Optional[int]     # None = TLS default; for an MCU TLS stack (D-1), not applied here (§25 L18)
    max_packet: int
    fota_chunk_size: int
    reconnect: Reconnect
    reconnect_interval_s: int         # BATCH interval; 0 for PERSISTENT
    backoff_base_s: int
    backoff_cap_s: int
    session_expiry_s: int
    keepalive_s: int
    dup_window_s: int
    pending_ttl_s: int
    outbox_cap: int


@dataclass(frozen=True)
class Rule:
    pattern: str
    tier: Tier


@dataclass(frozen=True)
class Policy:
    policy_id: str
    version: int
    activate_at: int
    default_tier: Tier
    rules: tuple
    classes: Mapping[str, ClassProfile]
    utility_kem_pk: bytes
    utility_cmd_pk: bytes
    ca_set: tuple
    raw: bytes = field(default=b"", compare=False, repr=False)

    def __post_init__(self):
        if not isinstance(self.classes, MappingProxyType):
            object.__setattr__(self, "classes", MappingProxyType(dict(self.classes)))

    def info(self) -> bytes:
        """POLICY_INFO = policy_id ‖ "|" ‖ u32(version) (Master §12), bound into every session key."""
        if not 0 <= self.version < 1 << 32:
            raise PolicyError("policy version does not fit POLICY_INFO's u32")
        return self.policy_id.encode() + b"|" + self.version.to_bytes(4, "big")

    def tier(self, topic: str) -> Tier:
        from .engine import tier_for
        return tier_for(self, topic)

    def profile(self, dclass: str) -> ClassProfile:
        try:
            return self.classes[dclass]
        except KeyError:
            raise PolicyError(f"class {dclass!r} is not defined by policy {self.policy_id} v{self.version}")
