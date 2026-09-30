"""Policy validator (Master §12 "Signed Policy", rules 1–10). A policy that fails any rule is never installed.

Beyond the ten design rules, a few structural checks keep the rules meaningful (all fail closed):
  * the version fits POLICY_INFO's u32, so two versions can never share a POLICY_INFO;
  * key lengths are exact; identifiers and topic filters are well formed;
  * class names are unique (guaranteed by the canonical codec).
"""
from __future__ import annotations

import re
from typing import Optional

from cryptography import x509

from ..errors import PolicyError
from ..suite.aead import AeadAlg
from ..suite.hkem import PK_LEN as HKEM_PK_LEN
from ..suite.sig import MLDSA65_PK_LEN
from .engine import valid_filter
from .model import CmdType, Policy, Reconnect, ResumeMode, Tier

SEVEN_DAYS = 7 * 86400
TLS_RECORD_CHOICES = (512, 1024, 2048, 4096)

# Rule 7 needs a concrete bound for "proof + headers" (IMPLEMENTATION-ROADMAP.md E11):
#   Merkle proof ≤ 16 levels × 32 B (≤ 65,536 chunks)                        = 512 B
#   chunk record enc[type, u64 version, u64 index, data, proof]: 5×4 + 1+8+8 =  37 B
#   MQTT fixed header, topic and properties reserve                           = 128 B
CHUNK_OVERHEAD = 512 + 37 + 128
MIN_DUP_WINDOW_S, MIN_PENDING_TTL_S = 120, 60

_POLICY_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
_CLASS_NAME = re.compile(r"^[a-z0-9][a-z0-9_]{0,31}$")


def _is_ca_certificate(der: bytes) -> bool:
    try:
        cert = x509.load_der_x509_certificate(bytes(der))
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except (ValueError, x509.ExtensionNotFound):
        return False


def validate(p: Policy, installed_version: Optional[int] = None) -> None:
    def fail(msg: str):
        raise PolicyError(msg)

    # ---- structure
    if not _POLICY_ID.fullmatch(p.policy_id):             # fullmatch: '$' alone accepts a final '\n'
        fail("policy_id must match ^[a-z0-9][a-z0-9-]{0,31}$")
    if not 0 < p.version < 1 << 32:
        fail("version must be in 1 … 2^32-1 (POLICY_INFO carries it as u32)")
    if len(p.utility_kem_pk) != HKEM_PK_LEN:
        fail("utility_kem_pk must be a 1,216-byte hybrid public key")
    if len(p.utility_cmd_pk) != MLDSA65_PK_LEN:
        fail("utility_cmd_pk must be a 1,952-byte ML-DSA-65 public key")
    if not p.classes:
        fail("a policy must define at least one device class")

    # ---- rule 1: default tier
    if p.default_tier is not Tier.CONTROL:
        fail("rule 1: default_tier must be CONTROL")
    # ---- rule 2: tiers valid (and every pattern a valid MQTT filter)
    for r in p.rules:
        if not isinstance(r.tier, Tier):
            fail("rule 2: unknown tier")
        if not valid_filter(r.pattern):
            fail(f"rule 2: invalid topic filter {r.pattern!r}")
    # ---- rule 5: monotonic version
    if installed_version is not None and p.version <= installed_version:
        fail("rule 5: rollback: version not newer than installed")
    # ---- rule 10: CA set (the devices' pinned TLS trust anchors: current and, during a roll-over, next; §4.5)
    if not 1 <= len(p.ca_set) <= 2:
        fail("rule 10: ca_set must hold 1 or 2 certificates")
    for der in p.ca_set:
        if not _is_ca_certificate(der):
            fail("rule 10: every ca_set entry must be a DER X.509 CA certificate (basicConstraints CA:TRUE)")

    for name, c in p.classes.items():
        if not _CLASS_NAME.fullmatch(name) or c.name != name:
            fail(f"class name {name!r} is invalid")
        # rule 3: unicast control forces forward-secret resumption
        if c.unicast_control and c.resume not in (ResumeMode.PSK_KEM, ResumeMode.NONE):
            fail(f"rule 3: {name}: receives unicast control, so PSK-only resumption is forbidden")
        # rule 4: lifetimes
        if not 0 < c.ticket_lifetime_s <= c.max_chain_age_s <= SEVEN_DAYS:
            fail(f"rule 4: {name}: need 0 < ticket_lifetime <= max_chain_age <= 7 days")
        # rule 6: SETPOINT only under GRANT
        if CmdType.SETPOINT in c.cmd_types and CmdType.GRANT not in c.cmd_types:
            fail(f"rule 6: {name}: SETPOINT requires GRANT")
        if CmdType.SETPOINT in c.cmd_types and c.max_setpoint_rate <= 0:
            fail(f"rule 6: {name}: SETPOINT requires a positive max_setpoint_rate")
        # rule 7: artifacts fit the device's packet limit
        if c.fota_chunk_size <= 0 or c.fota_chunk_size + CHUNK_OVERHEAD > c.max_packet:
            fail(f"rule 7: {name}: fota_chunk_size + {CHUNK_OVERHEAD} must be <= max_packet")
        # rule 8: known TLS record size and AEAD
        if c.tls_max_record is not None and c.tls_max_record not in TLS_RECORD_CHOICES:
            fail(f"rule 8: {name}: tls_max_record must be one of {TLS_RECORD_CHOICES} or default")
        if not isinstance(c.aead, AeadAlg):
            fail(f"rule 8: {name}: unknown AEAD")
        # rule 9: duplicate and pending windows never below the floor
        if c.dup_window_s < MIN_DUP_WINDOW_S or c.pending_ttl_s < MIN_PENDING_TTL_S:
            fail(f"rule 9: {name}: dup_window_s >= {MIN_DUP_WINDOW_S} and pending_ttl_s >= {MIN_PENDING_TTL_S}")
        # reconnect sanity (§10.5)
        if c.reconnect is Reconnect.BATCH and c.reconnect_interval_s <= 0:
            fail(f"{name}: BATCH reconnect needs a positive interval")
        if not 0 < c.backoff_base_s <= c.backoff_cap_s:
            fail(f"{name}: need 0 < backoff_base_s <= backoff_cap_s")
