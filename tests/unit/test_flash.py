"""Device flash record store: CRC, newest-wins, deletions, compaction, power loss at any point, and the
DR-049 scrub of superseded secrets (Master §16; IMPLEMENTATION-ROADMAP §10.2, E39, E40)."""
import os
import random

import pytest

from pqgrid.persistence.flash import FlashSim, PowerLoss, RecordStore, StoreFull

T_A, T_B, T_SECRET = 1, 2, 3


def state(store: RecordStore) -> dict:
    return {k: v[1] for k, v in store._live.items()}


def apply(store_or_model, op):
    kind, t, k, v = op
    if isinstance(store_or_model, dict):
        if kind == "put":
            store_or_model[(t, k)] = v
        else:
            store_or_model.pop((t, k), None)
    elif kind == "put":
        store_or_model.put(t, k, v)
    else:
        store_or_model.delete(t, k)


def test_put_get_delete_and_reboot():
    f = FlashSim()
    s = RecordStore(f)
    s.put(T_A, b"x", b"1")
    s.put(T_A, b"x", b"2")
    s.put(T_B, b"x", b"other type")
    s.put(T_A, b"y", b"3")
    s.delete(T_A, b"y")
    r = RecordStore(f)
    assert r.get(T_A, b"x") == b"2" and r.get(T_B, b"x") == b"other type" and r.get(T_A, b"y") is None


def test_torn_record_is_ignored_and_the_store_keeps_working():
    f = FlashSim()
    s = RecordStore(f)
    s.put(T_A, b"k", b"old")
    f.fail_after = 10                                         # power fails 10 bytes into the next record
    with pytest.raises(PowerLoss):
        s.put(T_A, b"k", b"new value")
    f.fail_after = None
    r = RecordStore(f)
    assert r.get(T_A, b"k") == b"old"
    r.put(T_A, b"k", b"after reboot")
    assert RecordStore(f).get(T_A, b"k") == b"after reboot"


def test_torn_header_near_the_end_of_a_page_does_not_block_later_writes():
    """Regression: power fails right after the TYPE byte of a record that starts in the last 267 bytes of a page.
    Its key_len then reads 0xFF, so the header seems to run past the page end. The boot scan must treat that as a
    tear (the rest of the page is abandoned), not as the end of the log: otherwise the next write programs over
    the non-erased type byte and every later small write fails, bricking the store."""
    f = FlashSim(pages=4, page_size=4096)
    s = RecordStore(f)
    i = 0
    while s._pos[1] <= 4096 - (2 + 255 + 10):                 # past the point where a 0xFF key_len overruns
        s.put(T_A, b"k%03d" % i, b"x" * 40)
        i += 1
    page_before = s._pos[0]
    f.fail_after = 1                                          # exactly one byte (the type) is programmed
    with pytest.raises(PowerLoss):
        s.put(T_A, b"torn", b"y" * 20)
    f.fail_after = None
    r = RecordStore(f)
    assert r._pos == (page_before + 1, 0)                     # the torn page's tail is abandoned
    assert r.get(T_A, b"torn") is None and r.get(T_A, b"k000") == b"x" * 40
    r.put(T_A, b"after", b"z" * 10)                           # small writes still work …
    r.put(T_A, b"k000", b"updated")
    again = RecordStore(f)                                    # … and survive the next reboot
    assert again.get(T_A, b"after") == b"z" * 10 and again.get(T_A, b"k000") == b"updated"
    assert state(again) == state(r)


def test_compaction_keeps_exactly_the_live_records():
    f = FlashSim(pages=4, page_size=512)
    s = RecordStore(f)
    for i in range(400):                                      # many times the flash size: forces compactions
        s.put(T_A, bytes([i % 7]), os.urandom(20))
        if i % 5 == 0:
            s.delete(T_A, bytes([(i + 3) % 7]))
    assert sum(f.erase_counts) > 0
    assert state(RecordStore(f)) == state(s)


def test_store_full_is_refused_without_damage():
    f = FlashSim(pages=4, page_size=512)
    s = RecordStore(f)
    for i in range(2):                                        # records never span pages: two fill a bank
        s.put(T_A, bytes([i]), b"v" * 300)
    with pytest.raises(StoreFull):
        s.put(T_A, b"\x09", b"w" * 300)                      # the live set would exceed one bank
    assert state(s) == state(RecordStore(f)) == {(T_A, bytes([i])): b"v" * 300 for i in range(2)}
    s.put(T_A, b"\x00", b"smaller")                          # the store still works after the refusal
    assert RecordStore(f).get(T_A, b"\x00") == b"smaller"


def test_power_loss_at_every_point_leaves_before_or_after_state():
    """The core property: a write (with any compaction it triggers) is atomic across power loss, and so is the
    reboot that follows it. Never a mix, never a resurrected deletion."""
    rng = random.Random(4)
    keys = [bytes([c]) for c in b"abcd"]
    ops = []
    for _ in range(120):
        t, k = rng.choice([T_A, T_B]), rng.choice(keys)
        ops.append(("del", t, k, None) if rng.random() < 0.25 else ("put", t, k, os.urandom(rng.randint(1, 60))))
    f = FlashSim(pages=4, page_size=512)
    s, model, checked = RecordStore(f), {}, 0
    for op in ops:
        before = dict(model)
        after = dict(model)
        apply(after, op)
        probe = f.clone()
        ps = RecordStore(probe)
        t0 = probe.ticks
        apply(ps, op)
        n = probe.ticks - t0
        for k in range(n):                                    # every programmed byte and every erase step
            c = f.clone()
            cs = RecordStore(c)
            c.fail_after = k
            with pytest.raises(PowerLoss):
                apply(cs, op)
            c.fail_after = rng.randint(0, 40)                # and power fails again during the reboot …
            try:
                RecordStore(c)
            except PowerLoss:
                pass
            c.fail_after = None
            rs = RecordStore(c)
            got = state(rs)                                   # … the next clean boot still recovers
            assert got in (before, after), f"op {op[0]} failed at {k}/{n}: mixed state"
            rs.put(T_A, b"z", b"written after recovery")      # … and the recovered store accepts writes
            assert state(RecordStore(c)) == {**got, (T_A, b"z"): b"written after recovery"}, \
                f"op {op[0]} failed at {k}/{n}: store unusable after recovery"
            checked += 1
        apply(s, op)
        model = after
        assert state(s) == model
    assert checked > 5000, checked
    print(f"power-loss points checked: {checked}")


def test_DR049_superseded_secret_is_erased_within_7_days():
    now = [1_790_000_000.0]
    f = FlashSim()
    s = RecordStore(f, clock=lambda: now[0], secret_types={T_SECRET})
    old = os.urandom(32)
    s.put(T_SECRET, b"", old)
    s.put(T_SECRET, b"", os.urandom(32))                     # the old psk is superseded but still in flash
    assert old in f.mem
    now[0] += 7 * 86400 - 1
    s.put(T_A, b"k", b"x")
    assert old in f.mem                                      # not yet 7 days
    now[0] += 1
    s.put(T_A, b"k", b"y")
    assert old not in f.mem                                  # scrubbed (compaction erased it)


def test_DR049_superseded_secret_found_at_boot_is_erased_at_boot():
    f = FlashSim()
    s = RecordStore(f, secret_types={T_SECRET})
    old = os.urandom(32)
    s.put(T_SECRET, b"", old)
    s.delete(T_SECRET, b"")                                  # ticket cleared at RS; residue remains
    assert old in f.mem
    RecordStore(f, secret_types={T_SECRET})                  # age unknown after a reboot: scrub now
    assert old not in f.mem


def test_maybe_scrub_without_writes():
    now = [0.0]
    f = FlashSim()
    s = RecordStore(f, clock=lambda: now[0], secret_types={T_SECRET})
    old = os.urandom(32)
    s.put(T_SECRET, b"", old)
    s.delete(T_SECRET, b"")
    now[0] = 7 * 86400
    s.maybe_scrub()
    assert old not in f.mem
