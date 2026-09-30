"""Codec strictness (Master §12 Binary Encoding, I-21)."""
import random
import struct

import pytest

from pqgrid.errors import WireError
from pqgrid.wire import (MAX_FIELD, dec, dec_list, enc, enc_list, peek_tag, r16, r64, u8, u16, u64)


def test_roundtrip():
    fields = [b"", b"a", b"\x00" * 300, bytes(range(256))]
    assert dec(enc(fields), 4) == fields


def test_exact_field_count_and_no_trailing_bytes():
    buf = enc([b"x", b"y"])
    with pytest.raises(WireError):
        dec(buf, 1)                      # trailing bytes
    with pytest.raises(WireError):
        dec(buf, 3)                      # truncated
    with pytest.raises(WireError):
        dec(buf + b"\x00", 2)            # trailing byte


def test_oversized_length_rejected_before_allocation():
    evil = struct.pack(">I", 0xFFFFFFFF) + b"x" * 16
    with pytest.raises(WireError, match="too large"):
        dec(evil, 1)
    with pytest.raises(WireError):
        enc([b"x" * (MAX_FIELD + 1)])


def test_integers_are_exact_width():
    assert r64(u64(2**64 - 1)) == 2**64 - 1
    with pytest.raises(WireError):
        r64(b"\x00" * 7)
    with pytest.raises(WireError):
        u8(256)
    with pytest.raises(WireError):
        u16(-1)
    with pytest.raises(WireError):
        u8(True)                         # bools are not integers here


def test_counted_list_caps():
    items = [b"a", b"bb", b"ccc"]
    assert dec_list(enc_list(items, 3), 3) == items
    with pytest.raises(WireError):
        enc_list(items, 2)
    with pytest.raises(WireError):
        dec_list(enc_list(items, 3), 2)  # count above the receiver's cap
    assert r16(enc_list(items, 3)[4:6]) == 3


def test_peek_tag():
    assert peek_tag(enc([b"CH", b"rest"])) == b"CH"
    with pytest.raises(WireError):
        peek_tag(b"\x00\x00")


def test_random_mutations_only_raise_wireerror():
    rng = random.Random(1)
    base = enc([b"CH", b"\x01" * 50, b"\x02" * 70])
    for _ in range(2000):
        b = bytearray(base)
        op = rng.randrange(3)
        if op == 0:
            b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
        elif op == 1:
            del b[rng.randrange(len(b)):]
        else:
            b += bytes(rng.randrange(256) for _ in range(rng.randrange(1, 8)))
        try:
            dec(bytes(b), 3)
        except WireError:
            pass
