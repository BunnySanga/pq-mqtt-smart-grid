"""CONTROL building blocks: plaintext codec, signature inputs, applied-sequence bitmap, epoch allocator,
status tokens (Master §13, §16; IMPLEMENTATION-ROADMAP §9, E29, E33, E34)."""
import pytest

from pqgrid.commands.codec import (Command, Grant, Setpoint, ZoneKey, cmd_signed_input, decode, encode,
                                   grant_signed_input)
from pqgrid.commands.device import WINDOW, DeviceCommandState
from pqgrid.commands.utility import UtilityCommandStore
from pqgrid.e2e.envelopes import valid_status
from pqgrid.errors import WireError
from pqgrid.suite.aead import AeadAlg
from pqgrid.wire import enc, i64, ri64

T0 = 1_790_000_000
G = Grant(7, b"g" * 8, b"s" * 8, "P_ACTIVE_W", -5000, 5000, 12, T0, T0 + 3600, b"sig")


# ---------------------------------------------------------------------------------------------- codec
@pytest.mark.parametrize("m", [Command((T0 << 32) | 1, b"CURTAIL", T0 + 60, True, b"sig"), G,
                               Setpoint(b"g" * 8, -42, T0 + 5),
                               ZoneKey("feeder7", 3, AeadAlg.CHACHA20POLY1305, b"k" * 32)])
def test_control_plaintext_roundtrip(m):
    assert decode(encode(m)) == m


@pytest.mark.parametrize("pt", [
    enc([b"CMD", bytes(8), b"x", bytes(8), b"\x02", b"s"]),                     # idempotent must be 0/1
    enc([b"CMD", bytes(7), b"x", bytes(8), b"\x00", b"s"]),                     # cmd_seq width
    enc([b"CMD", bytes(8), b"x", bytes(8), b"\x00"]),                           # field count
    enc([b"SETPOINT", b"g" * 7, bytes(8), bytes(8)]),                           # grant_id length
    enc([b"ZONEKEY", b"feeder7", bytes(8), b"DES", b"k" * 32]),                 # unknown AEAD
    enc([b"ZONEKEY", b"feed/er", bytes(8), b"AES256GCM", b"k" * 32]),           # zone name token
    enc([b"ZONEKEY", b"feeder7", bytes(8), b"AES256GCM", b"k" * 31]),           # key length
    enc([b"GRANT", bytes(8), b"g" * 8, b"s" * 8, b"P#", bytes(8), bytes(8), bytes(4), bytes(8), bytes(8), b""]),
    enc([b"REBOOT"]),                                                           # unknown sub-type
    encode(Setpoint(b"g" * 8, 1, 2)) + b"\x00",                                 # trailing bytes
])
def test_control_plaintext_is_strict(pt):
    with pytest.raises(WireError):
        decode(pt)


def test_signed_integers_cover_the_full_range_and_nothing_else():
    for v in (-(1 << 63), -1, 0, 1, (1 << 63) - 1):
        assert ri64(i64(v)) == v
    for bad in ((1 << 63), -(1 << 63) - 1, True, 1.5):
        with pytest.raises(WireError):
            i64(bad)


def test_command_signature_covers_every_field():
    base = (b"der-0001", "grid/der_ctrl/der-0001/control", 5, T0, False, b"TRIP")
    ref = cmd_signed_input(*base)
    for i, alt in enumerate([b"der-0002", "grid/der_ctrl/der-0002/control", 6, T0 + 1, True, b"CLOSE"]):
        changed = list(base)
        changed[i] = alt
        assert cmd_signed_input(*changed) != ref


def test_grant_signature_covers_every_field_including_sid():
    import dataclasses
    ref = grant_signed_input(b"der-0001", "t", G)
    for name, alt in [("cmd_seq", 8), ("grant_id", b"h" * 8), ("sid", b"t" * 8), ("target", "Q_VAR"),
                      ("min", -5001), ("max", 5001), ("max_rate", 13), ("not_before", T0 + 1),
                      ("expires_at", T0 + 3601)]:
        assert grant_signed_input(b"der-0001", "t", dataclasses.replace(G, **{name: alt})) != ref


# ----------------------------------------------------------------------------------- applied bitmap
def test_bitmap_tracks_applied_sequences_below_last_applied():
    st = DeviceCommandState()
    for seq in (10, 12, 15):
        st.write_applied(seq)
    assert [s for s in range(1, 17) if st.is_applied(s)] == [10, 12, 15]
    st.write_applied(15 + WINDOW)
    assert st.is_applied(15) and not st.is_applied(12)          # 12 fell out of the 64-sequence window
    assert not st.is_applied(0)


def test_bitmap_update_across_an_epoch_jump_is_constant_time():
    """Regression: a new utility epoch moves cmd_seq by ~2^32 per second of epoch; shifting the bitmap by that
    distance allocated gigabytes (found as an 18 s test, 2026-09-25)."""
    import time
    st = DeviceCommandState()
    st.write_applied((T0 << 32) | 1)
    st.write_applied((T0 << 32) | 2)
    t = time.perf_counter()
    st.write_applied(((T0 + 86400) << 32) | 1)
    assert time.perf_counter() - t < 0.01
    assert st.bitmap == 0 and st.is_applied(((T0 + 86400) << 32) | 1) and not st.is_applied((T0 << 32) | 2)


def test_pending_is_interrupted_until_applied():
    st = DeviceCommandState()
    st.write_pending(Command(9, b"x", T0, False, b""))
    assert st.is_interrupted(9) and not st.is_applied(9)
    st.write_applied(9)
    assert not st.is_interrupted(9) and st.is_applied(9)


# ---------------------------------------------------------------------------------- epoch allocator
def test_epoch_is_strictly_increasing_even_with_a_stalled_clock():
    store = UtilityCommandStore()
    assert store.start(T0) == T0
    assert store.start(T0) == T0 + 1                              # restarted within the same second
    assert store.start(T0 - 1000) == T0 + 2                       # clock went backwards


def test_command_sequence_is_epoch_then_counter():
    store = UtilityCommandStore()
    e = store.start(T0)
    a, b = store.allocate(b"d", e), store.allocate(b"d", e)
    assert (a >> 32, a & 0xFFFFFFFF, b & 0xFFFFFFFF) == (T0, 1, 2)
    e2 = store.start(T0 + 5)
    assert store.allocate(b"d", e2) > b                          # any sequence of a newer epoch is larger


def test_restore_from_an_old_backup_still_moves_forward():
    """V-S1 at the allocator: the restored counter is old, but the new epoch dominates."""
    store = UtilityCommandStore()
    e1 = store.start(T0)
    backup = store.snapshot()
    last = max(store.allocate(b"d", e1) for _ in range(5))
    restored = backup
    e2 = restored.start(T0 + 60)
    assert restored.allocate(b"d", e2) > last


# --------------------------------------------------------------------------------------- statuses
def test_status_tokens():
    for ok in (b"OK", b"DUP", b"SUPERSEDED", b"EXPIRED", b"INTERRUPTED", b"REJECTED:signature"):
        assert valid_status(ok)
    for bad in (b"", b"ok", b"REJECTED", b"REJECTED:", b"REJECTED:because", b"UNKNOWN"):
        assert not valid_status(bad)
