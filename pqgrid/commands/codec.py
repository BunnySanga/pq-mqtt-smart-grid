"""CONTROL plaintexts and signature inputs (Master §13.1, §13.4, §13.5, §4.7; IMPLEMENTATION-ROADMAP §9.1).

    CMD      pt = enc["CMD", u64 cmd_seq, command, u64 expires_at, u8 idempotent, σ]
             σ  = ML-DSA-65("pqgrid/v2/cmd" ‖ H(device_id, topic, cmd_seq, expires_at, idempotent, command))
    GRANT    pt = enc["GRANT", u64 cmd_seq, grant_id(8), sid(8), target, i64 min, i64 max, u32 max_rate,
                      u64 not_before, u64 expires_at, σ]
             σ  = ML-DSA-65("pqgrid/v2/grant" ‖ H(device_id, topic, cmd_seq, grant_id, sid, target, min, max,
                                                  max_rate, not_before, expires_at))
    SETPOINT pt = enc["SETPOINT", grant_id(8), i64 value, u64 expires_at]                 (no signature)
    ZONEKEY  pt = enc["ZONEKEY", zone, u64 key_epoch, aead, key(32)]                       (no signature; DR-047)

cmd_seq sits inside pt and under σ (C5); σ does not cover sid for CMD (redelivery across sessions) but does
for GRANT (session binding). Values and bounds are signed integers, never floats (E29).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..errors import WireError
from ..suite.aead import AeadAlg
from ..suite.kdf import h
from ..wire import dec, enc, i64, peek_tag, r8, r32, r64, ri64, u8, u32, u64

CTX_CMD, CTX_GRANT, CTX_BCAST = b"pqgrid/v2/cmd", b"pqgrid/v2/grant", b"pqgrid/v2/bcast"   # Appendix C
GRANT_ID_LEN, SID_LEN, ZONE_KEY_LEN = 8, 8, 32
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{1,32}$")        # targets and zone names


def valid_token(s: str) -> bool:
    return bool(_TOKEN.match(s))


@dataclass(frozen=True)
class Command:
    cmd_seq: int
    command: bytes
    expires_at: int
    idempotent: bool
    sig: bytes = field(repr=False)


@dataclass(frozen=True)
class Grant:
    cmd_seq: int
    grant_id: bytes
    sid: bytes
    target: str
    min: int
    max: int
    max_rate: int
    not_before: int
    expires_at: int
    sig: bytes = field(repr=False)


@dataclass(frozen=True)
class Setpoint:
    grant_id: bytes
    value: int
    expires_at: int


@dataclass(frozen=True)
class ZoneKey:
    zone: str
    key_epoch: int
    aead: AeadAlg
    key: bytes = field(repr=False)


# ------------------------------------------------------------------------------------------ signed inputs
def cmd_signed_input(device_id: bytes, topic: str, cmd_seq: int, expires_at: int, idempotent: bool,
                     command: bytes) -> bytes:
    return CTX_CMD + h(device_id, topic.encode(), u64(cmd_seq), u64(expires_at), u8(int(idempotent)), command)


def grant_signed_input(device_id: bytes, topic: str, g: Grant) -> bytes:
    return CTX_GRANT + h(device_id, topic.encode(), u64(g.cmd_seq), g.grant_id, g.sid, g.target.encode(),
                         i64(g.min), i64(g.max), u32(g.max_rate), u64(g.not_before), u64(g.expires_at))


def bcast_signed_input(zone: str, bseq: int, expires_at: int, event: bytes) -> bytes:
    """σ over the LOGICAL event (M7): no crypto group and no key epoch, so one signature serves every group and
    survives a key rotation; bseq is the event's identity within the zone."""
    return CTX_BCAST + h(zone.encode(), u64(bseq), u64(expires_at), event)


# ----------------------------------------------------------------------------------------------- encoding
def encode(m) -> bytes:
    if isinstance(m, Command):
        return enc([b"CMD", u64(m.cmd_seq), m.command, u64(m.expires_at), u8(int(m.idempotent)), m.sig])
    if isinstance(m, Grant):
        return enc([b"GRANT", u64(m.cmd_seq), m.grant_id, m.sid, m.target.encode(), i64(m.min), i64(m.max),
                    u32(m.max_rate), u64(m.not_before), u64(m.expires_at), m.sig])
    if isinstance(m, Setpoint):
        return enc([b"SETPOINT", m.grant_id, i64(m.value), u64(m.expires_at)])
    if isinstance(m, ZoneKey):
        return enc([b"ZONEKEY", m.zone.encode(), u64(m.key_epoch), m.aead.value.encode(), m.key])
    raise TypeError(f"not a CONTROL message: {type(m).__name__}")


def decode(pt: bytes):
    """Strict: exact field count, exact widths, known tokens. Raises WireError on anything else."""
    tag = peek_tag(pt)
    try:
        if tag == b"CMD":
            _, seq, command, exp, idem, sig = dec(pt, 6)
            if r8(idem) not in (0, 1):
                raise WireError("idempotent flag must be 0 or 1")
            return Command(r64(seq), command, r64(exp), r8(idem) == 1, sig)
        if tag == b"GRANT":
            _, seq, gid, sid, target, lo, hi, rate, nb, exp, sig = dec(pt, 11)
            g = Grant(r64(seq), gid, sid, target.decode("ascii"), ri64(lo), ri64(hi), r32(rate), r64(nb),
                      r64(exp), sig)
            if len(gid) != GRANT_ID_LEN or len(sid) != SID_LEN or not valid_token(g.target):
                raise WireError("malformed grant")
            return g
        if tag == b"SETPOINT":
            _, gid, value, exp = dec(pt, 4)
            if len(gid) != GRANT_ID_LEN:
                raise WireError("malformed set-point")
            return Setpoint(gid, ri64(value), r64(exp))
        if tag == b"ZONEKEY":
            _, zone, epoch, alg, key = dec(pt, 5)
            z = ZoneKey(zone.decode("ascii"), r64(epoch), AeadAlg(alg.decode("ascii")), key)
            if not valid_token(z.zone) or len(key) != ZONE_KEY_LEN:
                raise WireError("malformed zone key")
            return z
    except (UnicodeDecodeError, ValueError) as e:
        if isinstance(e, WireError):
            raise
        raise WireError("malformed control plaintext") from e
    raise WireError("unknown CONTROL sub-type")
