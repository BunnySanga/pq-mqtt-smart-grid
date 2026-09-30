"""Binary policy codec (Master §12; DR-014, DR-042).

Layout (every field length-prefixed by the wire codec):

    policy = enc[ "PQPOL2", policy_id, u64 version, u64 activate_at, u8 default_tier,
                  rules, classes, utility_kem_pk (1,216), utility_cmd_pk (1,952), ca_set ]
    rules   = counted list of enc[pattern, u8 tier]                       (declaration order)
    classes = counted list of class records                               (sorted by name)
    ca_set  = counted list of DER certificates
    class   = enc[ name, profile, resume, u32 ticket_lifetime_s, u32 max_chain_age_s, u8 unicast_control,
                   u8 cmd_mask, u16 max_setpoint_rate, aead, u16 tls_max_record (0 = default),
                   u32 max_packet, u32 fota_chunk_size, reconnect, u32 reconnect_interval_s,
                   u32 backoff_base_s, u32 backoff_cap_s, u32 session_expiry_s, u32 keepalive_s,
                   u32 dup_window_s, u32 pending_ttl_s, u32 outbox_cap ]

Decoding is strict and canonical: the decoded policy must re-encode to exactly the input bytes, so a
signed policy has one and only one byte representation.
"""
from __future__ import annotations

from ..errors import PolicyError, WireError
from ..suite.aead import AeadAlg
from ..wire import dec, dec_list, enc, enc_list, r16, r32, r64, r8, u16, u32, u64, u8
from .model import ClassProfile, CmdType, Policy, Profile, Reconnect, ResumeMode, Rule, Tier

MAGIC = b"PQPOL2"
MAX_RULES, MAX_CLASSES, MAX_CA = 1024, 64, 2
_CMD_BITS = {CmdType.CMD: 1, CmdType.GRANT: 2, CmdType.SETPOINT: 4}


def encode_policy(p: Policy) -> bytes:
    rules = enc_list([enc([r.pattern.encode(), u8(int(r.tier))]) for r in p.rules], MAX_RULES)
    classes = enc_list([_enc_class(p.classes[name]) for name in sorted(p.classes)], MAX_CLASSES)
    ca = enc_list(list(p.ca_set), MAX_CA)
    return enc([MAGIC, p.policy_id.encode(), u64(p.version), u64(p.activate_at), u8(int(p.default_tier)),
                rules, classes, p.utility_kem_pk, p.utility_cmd_pk, ca])


def decode_policy(raw: bytes) -> Policy:
    try:
        (magic, pid, ver, act, dtier, rules_b, classes_b, kem_pk, cmd_pk, ca_b) = dec(raw, 10)
        if magic != MAGIC:
            raise PolicyError("not a v2.2 policy (bad magic)")
        rules = tuple(_dec_rule(x) for x in dec_list(rules_b, MAX_RULES))
        class_list = [_dec_class(x) for x in dec_list(classes_b, MAX_CLASSES)]
        policy = Policy(policy_id=_text(pid), version=r64(ver), activate_at=r64(act), default_tier=_tier(dtier),
                        rules=rules, classes={c.name: c for c in class_list}, utility_kem_pk=kem_pk,
                        utility_cmd_pk=cmd_pk, ca_set=tuple(dec_list(ca_b, MAX_CA)), raw=bytes(raw))
    except WireError as e:
        raise PolicyError(f"malformed policy: {e}") from e
    if len(class_list) != len(policy.classes) or encode_policy(policy) != bytes(raw):
        raise PolicyError("policy encoding is not canonical")
    return policy


def _enc_class(c: ClassProfile) -> bytes:
    mask = 0
    for t in c.cmd_types:
        mask |= _CMD_BITS[CmdType(t)]
    return enc([c.name.encode(), c.profile.value.encode(), c.resume.value.encode(), u32(c.ticket_lifetime_s),
                u32(c.max_chain_age_s), u8(1 if c.unicast_control else 0), u8(mask), u16(c.max_setpoint_rate),
                c.aead.value.encode(), u16(c.tls_max_record or 0), u32(c.max_packet), u32(c.fota_chunk_size),
                c.reconnect.value.encode(), u32(c.reconnect_interval_s), u32(c.backoff_base_s),
                u32(c.backoff_cap_s), u32(c.session_expiry_s), u32(c.keepalive_s), u32(c.dup_window_s),
                u32(c.pending_ttl_s), u32(c.outbox_cap)])


def _dec_class(b: bytes) -> ClassProfile:
    f = dec(b, 21)
    unicast = r8(f[5])
    if unicast not in (0, 1):
        raise PolicyError("unicast_control must be 0 or 1")
    mask = r8(f[6])
    if mask & ~0b111:
        raise PolicyError("unknown command type bits")
    tls = r16(f[9])
    return ClassProfile(
        name=_text(f[0]), profile=_enum(Profile, f[1]), resume=_enum(ResumeMode, f[2]),
        ticket_lifetime_s=r32(f[3]), max_chain_age_s=r32(f[4]), unicast_control=bool(unicast),
        cmd_types=frozenset(t for t, bit in _CMD_BITS.items() if mask & bit), max_setpoint_rate=r16(f[7]),
        aead=_enum(AeadAlg, f[8]), tls_max_record=tls or None, max_packet=r32(f[10]),
        fota_chunk_size=r32(f[11]), reconnect=_enum(Reconnect, f[12]), reconnect_interval_s=r32(f[13]),
        backoff_base_s=r32(f[14]), backoff_cap_s=r32(f[15]), session_expiry_s=r32(f[16]),
        keepalive_s=r32(f[17]), dup_window_s=r32(f[18]), pending_ttl_s=r32(f[19]), outbox_cap=r32(f[20]))


def _dec_rule(b: bytes) -> Rule:
    pattern, tier = dec(b, 2)
    return Rule(_text(pattern), _tier(tier))


def _tier(b: bytes) -> Tier:
    try:
        return Tier(r8(b))
    except ValueError as e:
        raise PolicyError("unknown tier") from e


def _enum(cls, b: bytes):
    try:
        return cls(_text(b))
    except ValueError as e:
        raise PolicyError(f"unknown {cls.__name__} value") from e


def _text(b: bytes) -> str:
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError as e:
        raise PolicyError("text field is not UTF-8") from e
