"""RFC 6962 Merkle tree over chunks, with audit paths verified as in RFC 9162 §2.1.3.2 (Master §15.7).

    leaf  = SHA-256(0x00 ‖ chunk)        node = SHA-256(0x01 ‖ left ‖ right)
The 0x00/0x01 prefixes keep leaves and nodes apart (no second-preimage splicing); the path verification binds the
leaf's index and the tree size, so a valid chunk cannot be presented at another position.
"""
from __future__ import annotations

import hashlib

HASH_LEN = 32


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """The largest power of two smaller than n (n ≥ 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def root(chunks: list[bytes]) -> bytes:
    if not chunks:
        raise ValueError("a tree needs at least one chunk")
    if len(chunks) == 1:
        return leaf_hash(chunks[0])
    k = _split(len(chunks))
    return node_hash(root(chunks[:k]), root(chunks[k:]))


def audit_path(m: int, chunks: list[bytes]) -> list[bytes]:
    if not 0 <= m < len(chunks):
        raise IndexError("leaf index out of range")
    if len(chunks) == 1:
        return []
    k = _split(len(chunks))
    if m < k:
        return audit_path(m, chunks[:k]) + [root(chunks[k:])]
    return audit_path(m - k, chunks[k:]) + [root(chunks[:k])]


def max_path_len(n: int) -> int:
    """⌈log₂ n⌉: the longest audit path in a tree of n leaves."""
    return max(0, (n - 1).bit_length())


def verify(m: int, n: int, data: bytes, path: list[bytes], expected_root: bytes) -> bool:
    """RFC 9162 §2.1.3.2 inclusion-proof verification."""
    if not 0 <= m < n or len(path) > max_path_len(n) or any(len(p) != HASH_LEN for p in path):
        return False
    fn, sn, r = m, n - 1, leaf_hash(data)
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == expected_root
