"""Length-prefixed binary codec (deterministic; replaces canonical JSON). Strict: exact field count, no trailing
bytes, and a hard cap on every length so a malicious peer cannot make the parser allocate huge buffers."""
import struct
MAX_FIELD = 1 << 20          # 1 MiB per field; firmware chunks are far smaller (policy sets chunk size)
class WireError(ValueError): pass
def enc(fields) -> bytes: return b"".join(struct.pack(">I", len(f)) + f for f in fields)
def dec(buf: bytes, n: int) -> list:
    out, i = [], 0
    for _ in range(n):
        if i + 4 > len(buf): raise WireError("truncated")
        (L,) = struct.unpack_from(">I", buf, i); i += 4
        if L > MAX_FIELD: raise WireError("field too large")
        if i + L > len(buf): raise WireError("truncated")
        out.append(buf[i:i+L]); i += L
    if i != len(buf): raise WireError("trailing bytes")
    return out
def peek_tag(buf: bytes) -> bytes:
    if len(buf) < 4: raise WireError("truncated")
    (L,) = struct.unpack_from(">I", buf, 0)
    if L > 16 or 4 + L > len(buf): raise WireError("bad tag")
    return buf[4:4+L]
u64 = lambda v: v.to_bytes(8, "big"); r64 = lambda b: int.from_bytes(b, "big")
