"""Utility database: WAL + synchronous=FULL, owner-only file, each table's durability and atomicity, u64 ordering
past 2038, and the atomic file writer (Master §16; IMPLEMENTATION-ROADMAP §10.1, E43, E45)."""
import os
import stat

import pytest

from pqgrid.commands.codec import Command
from pqgrid.commands.utility import QueuedCommand
from pqgrid.persistence.atomic import atomic_write
from pqgrid.persistence.utility_db import (SqlCommandStore, SqlRegistry, SqlStekTable, SqlUsedTickets, UtilityDB)
from pqgrid.pasr.stek import ROTATION_S
from pqgrid.registry import DeviceRecord
from pqgrid.suite.hkem import HybridKeyPair

T0 = 1_790_000_000


@pytest.fixture
def path(tmp_path):
    return str(tmp_path / "utility.db")


def test_wal_full_sync_and_owner_only_file(path):
    db = UtilityDB(path)
    assert db.c.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert db.c.execute("PRAGMA synchronous").fetchone()[0] == 2            # FULL
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600                    # it holds the STEK


def test_stek_is_durable_before_use_and_retires(path):
    db = UtilityDB(path)
    st = SqlStekTable(db)
    k0 = st.current(T0)
    db.close()
    again = SqlStekTable(UtilityDB(path))                                  # restart
    assert again.key(0, T0 + 1) == k0.key and again.current(T0 + 1).kid == 0
    again.current(T0 + ROTATION_S)                                         # rotation persists kid 1
    for day in range(2, 10):
        again.current(T0 + day * ROTATION_S)                               # kid 0 retires and is deleted
    kids = [r[0] for r in again.db.c.execute("SELECT kid FROM stek ORDER BY kid")]
    assert 0 not in kids and kids == again.live_kids()


def test_used_tickets_survive_restart_and_are_pruned(path):
    used = SqlUsedTickets(UtilityDB(path))
    assert used.consume(b"a" * 16, T0 + 10, T0) and not used.consume(b"a" * 16, T0 + 10, T0)
    used.db.close()
    again = SqlUsedTickets(UtilityDB(path))
    assert not again.consume(b"a" * 16, T0 + 10, T0 + 1)                  # E-P4 at the store
    assert again.consume(b"b" * 16, T0 + 999, T0 + 100)                    # prune ran: "a" expired
    assert len(again) == 1


def _q(did, seq, topic="t"):
    return QueuedCommand(did, topic, Command(seq, b"TRIP", T0 + 60, False, b"sig"))


def test_sequence_and_queue_are_one_transaction(path):
    store = SqlCommandStore(UtilityDB(path))
    e = store.start(T0)

    def failing_build(seq):
        raise RuntimeError("signing service failed")
    with pytest.raises(RuntimeError):
        store.allocate_and_enqueue(b"d", e, failing_build)
    assert store.db.c.execute("SELECT COUNT(*) FROM device_seq").fetchone()[0] == 0     # rolled back together
    q = store.allocate_and_enqueue(b"d", e, lambda seq: _q(b"d", seq))
    assert q.cmd.cmd_seq == (e << 32) | 1 and store.open_commands(b"d")[0].cmd == q.cmd


def test_epoch_and_queue_survive_restart(path):
    store = SqlCommandStore(UtilityDB(path))
    e1 = store.start(T0)
    q = store.allocate_and_enqueue(b"d", e1, lambda seq: _q(b"d", seq))
    store.mark_sent(q, b"s" * 8)
    store.db.close()
    again = SqlCommandStore(UtilityDB(path))
    e2 = again.start(T0)                                                    # same clock second
    assert e2 == e1 + 1
    [r] = again.open_commands(b"d")
    assert (r.sends, r.last_sid, r.cmd.cmd_seq) == (1, b"s" * 8, q.cmd.cmd_seq)
    again.close(r, b"OK")
    assert again.open_commands(b"d") == [] and again.get(b"d", q.cmd.cmd_seq).status == b"OK"


def test_cmd_seq_beyond_2038_keeps_numeric_order(path):
    """E45: epoch ≥ 2^31 (2038) makes cmd_seq ≥ 2^63, past SQLite's signed INTEGER."""
    store = SqlCommandStore(UtilityDB(path))
    for epoch in (T0, (1 << 31) + 5, (1 << 32) - 1):
        store.allocate_and_enqueue(b"d", epoch, lambda seq: _q(b"d", seq))
    seqs = [q.cmd.cmd_seq for q in store.open_commands(b"d")]
    assert seqs == sorted(seqs) and seqs[-1] > 1 << 63


def test_registry_and_revocation_survive_restart(path):
    reg = SqlRegistry(UtilityDB(path))
    pk = HybridKeyPair.generate().pk
    reg.add(DeviceRecord(b"meter-0001", "smart_meter", pk))
    reg.revoke(b"meter-0001")
    again = SqlRegistry(UtilityDB(path))
    rec = again.get(b"meter-0001")
    assert rec.e2e_pk == pk and not rec.active


def test_atomic_write_replaces_and_never_tears(tmp_path, monkeypatch):
    target = tmp_path / "acl.conf"
    atomic_write(str(target), b"old contents")
    assert target.read_bytes() == b"old contents" and stat.S_IMODE(target.stat().st_mode) == 0o600

    def crash(*a):
        raise OSError("power lost before rename")
    monkeypatch.setattr(os, "replace", crash)
    with pytest.raises(OSError):
        atomic_write(str(target), b"new contents")
    assert target.read_bytes() == b"old contents"                          # old file intact
    assert [p.name for p in tmp_path.iterdir()] == ["acl.conf"]            # no temporary left behind


def test_an_empty_persistent_store_is_used_not_replaced(path):
    """Regression (found by E-P4, slice 4): `used or UsedTickets()` replaced an EMPTY SQLite set (len 0) with an
    in-memory one, so consumed tickets were forgotten at the next restart."""
    from pqgrid.pasr.tickets import TicketIssuer
    db = UtilityDB(path)
    used, stek = SqlUsedTickets(db), SqlStekTable(db)
    assert len(used) == 0
    issuer = TicketIssuer(stek, used)
    assert issuer.used is used and issuer.stek is stek
