"""Length-prefixed binary codec (Master §12 "Binary Encoding"; invariant I-21).

Every field is a 4-byte big-endian length followed by that many bytes. Decoding is strict:
  * the caller states the exact field count;
  * no trailing bytes are allowed;
  * every length is checked against MAX_FIELD before any slice is taken.
Fixed-width integers are decoded with exact-length checks so a short field can never be read as a number.
"""
from __future__ import annotations

import struct
from typing import Iterable

from .errors import WireError

MAX_FIELD = 1 << 20          # 1 MiB per field (Master §12); checked before allocation
_LEN = struct.Struct(">I")


def enc(fields: Iterable[bytes]) -> bytes:
    """Encode fields as length ‖ bytes ‖ length ‖ bytes …"""
    out = []
    for f in fields:
        if not isinstance(f, (bytes, bytearray)):
            raise WireError(f"field must be bytes, got {type(f).__name__}")
        if len(f) > MAX_FIELD:
            raise WireError("field too large")
        out.append(_LEN.pack(len(f)))
        out.append(bytes(f))
    return b"".join(out)


def dec(buf: bytes, n: int) -> list[bytes]:
    """Decode exactly `n` fields that must consume all of `buf`."""
    out, i = [], 0
    for _ in range(n):
        if i + 4 > len(buf):
            raise WireError("truncated")
        (length,) = _LEN.unpack_from(buf, i)
        i += 4
        if length > MAX_FIELD:
            raise WireError("field too large")
        if i + length > len(buf):
            raise WireError("truncated")
        out.append(bytes(buf[i:i + length]))
        i += length
    if i != len(buf):
        raise WireError("trailing bytes")
    return out


def peek_tag(buf: bytes, max_len: int = 16) -> bytes:
    """Return the first field without decoding the rest (message dispatch)."""
    if len(buf) < 4:
        raise WireError("truncated")
    (length,) = _LEN.unpack_from(buf, 0)
    if length > max_len or 4 + length > len(buf):
        raise WireError("bad tag")
    return bytes(buf[4:4 + length])


def enc_list(items: list[bytes], max_count: int) -> bytes:
    """A counted list: enc[u16 count, item₁ … itemₙ]. Used for bundles and nested records."""
    if len(items) > max_count:
        raise WireError("too many items")
    return enc([u16(len(items)), *items])


def dec_list(buf: bytes, max_count: int) -> list[bytes]:
    """Inverse of enc_list, refusing counts above `max_count` before decoding the items."""
    if len(buf) < 6:
        raise WireError("truncated")
    (length,) = _LEN.unpack_from(buf, 0)
    if length != 2:
        raise WireError("bad count field")
    count = r16(buf[4:6])
    if count > max_count:
        raise WireError("too many items")
    return dec(buf, 1 + count)[1:]


def u8(v: int) -> bytes:
    return _uint(v, 1)


def u16(v: int) -> bytes:
    return _uint(v, 2)


def u32(v: int) -> bytes:
    return _uint(v, 4)


def u64(v: int) -> bytes:
    return _uint(v, 8)


def r8(b: bytes) -> int:
    return _rint(b, 1)


def r16(b: bytes) -> int:
    return _rint(b, 2)


def r32(b: bytes) -> int:
    return _rint(b, 4)


def r64(b: bytes) -> int:
    return _rint(b, 8)


def i64(v: int) -> bytes:
    """Signed 64-bit big-endian (set-point values and bounds, IMPLEMENTATION-ROADMAP E29)."""
    if not isinstance(v, int) or isinstance(v, bool) or not -(1 << 63) <= v < (1 << 63):
        raise WireError("integer out of range for signed 8 bytes")
    return v.to_bytes(8, "big", signed=True)


def ri64(b: bytes) -> int:
    if len(b) != 8:
        raise WireError(f"expected an 8-byte integer, got {len(b)} bytes")
    return int.from_bytes(b, "big", signed=True)


def _uint(v: int, width: int) -> bytes:
    if not isinstance(v, int) or isinstance(v, bool) or v < 0 or v >= 1 << (8 * width):
        raise WireError(f"integer out of range for {width} bytes")
    return v.to_bytes(width, "big")


def _rint(b: bytes, width: int) -> int:
    if len(b) != width:
        raise WireError(f"expected a {width}-byte integer, got {len(b)} bytes")
    return int.from_bytes(b, "big")
