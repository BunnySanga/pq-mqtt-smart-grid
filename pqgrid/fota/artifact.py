"""FOTA artifact codec (Master §15.2, §15.8; IMPLEMENTATION-ROADMAP §12.1, E61).

    manifest = enc["PQFW2", u8 type, device_class, u64 version, u64 payload_length, sha256(payload),
                   u32 chunk_size, u32 chunk_count, merkle_root, u64 activate_at, u64 issued_at, u8 signer_anchor_id]
    signed   = enc[manifest, SLH-DSA-SHA2-128s(anchor, manifest)]
    part     = enc["MP", u8 type, u64 version, u16 index, u16 total, bytes]        retained, ≤ class max_packet
    chunk    = enc[u8 type, u64 version, u32 index, data, merkle path (32-byte hashes concatenated)]

Types are one byte, so a chunk record stays within the 37 B Master budgets (E11). Parsing is strict: exact field
counts, exact widths, known types, and structural limits checked before anything is trusted.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..errors import PqgridError, WireError
from ..wire import dec, enc, r8, r16, r32, r64, u8, u16, u32, u64
from . import merkle

MAX_CHUNKS = 1024                 # chunks per artifact: bounds the device's download record (bitmap ≤ 128 B)

MAGIC = b"PQFW2"
FIRMWARE, POLICY, KEYREVOKE = 1, 2, 3
TYPE_NAMES = {FIRMWARE: "firmware", POLICY: "policy", KEYREVOKE: "keyrevoke"}
ANCHOR_A, ANCHOR_B = 0, 1                       # release anchor, offline recovery anchor (§15.13, DR-050)
MAX_PARTS = 64


def release_anchor(revoked) -> int:
    """DR-050 as finalized (clarification 8): A signs ordinary releases while it is active; B, the offline
    recovery anchor, signs none of them until KEYREVOKE(A); afterwards B is the release anchor and A never again."""
    return ANCHOR_B if ANCHOR_A in revoked else ANCHOR_A


def check_signer(type_: int, signer: int, revoked) -> None:
    """The anchor-role rule, applied wherever a signed artifact is accepted or committed."""
    if signer in revoked:
        raise FotaError("manifest signed by a revoked anchor")
    if type_ == KEYREVOKE:
        if signer != ANCHOR_B:
            raise FotaError("a KEYREVOKE must be signed by the recovery anchor B (DR-050)")
    elif signer != release_anchor(revoked):
        raise FotaError("the recovery anchor B may not sign ordinary releases while A is active (DR-050)")


class FotaError(PqgridError, ValueError):
    """An artifact, part or chunk was refused. Nothing is installed or committed."""


@dataclass(frozen=True)
class Manifest:
    type: int
    device_class: str
    version: int
    payload_length: int
    payload_sha256: bytes
    chunk_size: int
    chunk_count: int
    merkle_root: bytes
    activate_at: int
    issued_at: int
    signer_anchor_id: int

    def encode(self) -> bytes:
        return enc([MAGIC, u8(self.type), self.device_class.encode(), u64(self.version), u64(self.payload_length),
                    self.payload_sha256, u32(self.chunk_size), u32(self.chunk_count), self.merkle_root,
                    u64(self.activate_at), u64(self.issued_at), u8(self.signer_anchor_id)])


def decode_manifest(raw: bytes) -> Manifest:
    try:
        f = dec(raw, 12)
        m = Manifest(r8(f[1]), f[2].decode("ascii"), r64(f[3]), r64(f[4]), f[5], r32(f[6]), r32(f[7]), f[8],
                     r64(f[9]), r64(f[10]), r8(f[11]))
    except (WireError, UnicodeDecodeError) as e:
        raise FotaError("malformed manifest") from e
    if f[0] != MAGIC:
        raise FotaError("bad manifest magic")
    if m.type not in TYPE_NAMES or len(m.payload_sha256) != 32 or len(m.merkle_root) != 32:
        raise FotaError("malformed manifest")
    if m.chunk_size == 0 or m.chunk_count != max(1, -(-m.payload_length // m.chunk_size)):
        raise FotaError("chunk_count does not match payload_length / chunk_size")          # E61
    return m


def split_signed(signed: bytes) -> tuple[bytes, bytes]:
    try:
        manifest, sig = dec(signed, 2)
    except WireError as e:
        raise FotaError("malformed signed manifest") from e
    return manifest, sig


def chunks_of(payload: bytes, chunk_size: int) -> list[bytes]:
    return [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)] or [b""]


def encode_part(type_: int, version: int, index: int, total: int, data: bytes) -> bytes:
    return enc([b"MP", u8(type_), u64(version), u16(index), u16(total), data])


def decode_part(raw: bytes) -> tuple[int, int, int, int, bytes]:
    try:
        tag, t, v, i, n, data = dec(raw, 6)
        t, v, i, n = r8(t), r64(v), r16(i), r16(n)
    except WireError as e:
        raise FotaError("malformed manifest part") from e
    if tag != b"MP" or t not in TYPE_NAMES or not 0 < n <= MAX_PARTS or i >= n:
        raise FotaError("malformed manifest part")
    return t, v, i, n, data


def encode_chunk(type_: int, version: int, index: int, data: bytes, path: list[bytes]) -> bytes:
    return enc([u8(type_), u64(version), u32(index), data, b"".join(path)])


def decode_chunk(raw: bytes) -> tuple[int, int, int, bytes, list[bytes]]:
    try:
        t, v, i, data, p = dec(raw, 5)
        t, v, i = r8(t), r64(v), r32(i)
    except WireError as e:
        raise FotaError("malformed chunk") from e
    if len(p) % merkle.HASH_LEN:
        raise FotaError("malformed chunk")
    return t, v, i, data, [p[k:k + merkle.HASH_LEN] for k in range(0, len(p), merkle.HASH_LEN)]
