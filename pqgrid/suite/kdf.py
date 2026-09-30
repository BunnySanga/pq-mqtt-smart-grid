"""HKDF-SHA-256, HMAC-SHA-256 and the transcript hash (Master §6.6–§6.8, §7.10–§7.11).

`h(*parts)` hashes length-prefixed parts, so different splits of the same bytes can never collide.
All MAC comparisons go through `ct_eq` (constant time; Master §6.7).
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

HASH_LEN = 32
_LEN = struct.Struct(">I")


def h(*parts: bytes) -> bytes:
    """SHA-256 over length-prefixed parts: the transcript and AAD digest."""
    d = hashlib.sha256()
    for p in parts:
        d.update(_LEN.pack(len(p)))
        d.update(p)
    return d.digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 Extract: PRK = HMAC-SHA-256(salt, IKM)."""
    return _hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 Expand with `info` as the domain-separation label."""
    return HKDFExpand(hashes.SHA256(), length, info).derive(prk)


def mac(key: bytes, msg: bytes) -> bytes:
    return _hmac.new(key, msg, hashlib.sha256).digest()


def ct_eq(a: bytes, b: bytes) -> bool:
    """Constant-time equality for MACs, identifiers and POLICY_INFO."""
    return _hmac.compare_digest(a, b)


def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()
