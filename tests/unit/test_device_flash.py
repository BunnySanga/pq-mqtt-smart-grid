"""Device state in flash: command state and intents, zone sequences, and the bounded alert outbox
(Master §16 Device Command State, Intent Log, Outbox; DR-048; IMPLEMENTATION-ROADMAP §10.2, §10.3, E41)."""
import os

import pytest

from pqgrid.commands.codec import Command
from pqgrid.persistence.device import DeviceFlash
from pqgrid.persistence.flash import FlashSim

T0 = 1_790_000_000
TOPIC = "grid/smart_meter/meter-0001/alert"


def boot(f: FlashSim) -> DeviceFlash:
    return DeviceFlash(f, clock=lambda: T0)


def aid() -> bytes:
    return os.urandom(16)


def test_command_state_survives_reboot():
    f = FlashSim()
    st = boot(f).command_state()
    st.write_applied((T0 << 32) | 1)
    st.write_applied((T0 << 32) | 3)
    st.write_pending(Command((T0 << 32) | 4, b"TRIP", T0 + 60, False, b""))
    st.write_zone_bseq("feeder7", 42)
    again = boot(f).command_state()
    assert again.last_applied == (T0 << 32) | 3 and again.is_applied((T0 << 32) | 1)
    assert not again.is_applied((T0 << 32) | 2)
    assert again.is_interrupted((T0 << 32) | 4) and again.pending[(T0 << 32) | 4].command == b"TRIP"
    assert again.zone_bseq == {"feeder7": 42}


def test_three_flash_writes_per_discrete_command_and_nothing_left_behind():
    """Remediation H2: PENDING (intent record), APPLIED (state record), then the intent is deleted, so an
    applied command leaves no record behind and the log cannot grow."""
    from pqgrid.persistence.device import T_INTENT
    f = FlashSim()
    df = boot(f)
    st = df.command_state()
    w0 = df.store._wseq
    seq = (T0 << 32) | 1
    st.write_pending(Command(seq, b"TRIP", T0 + 60, False, b""))
    assert list(df.store.items(T_INTENT)) and df.store._wseq - w0 == 1
    st.write_applied(seq)
    assert df.store._wseq - w0 == 3 and df.store.items(T_INTENT) == {}
    assert boot(f).command_state().is_applied(seq)


def test_outbox_keeps_alerts_until_acked_across_reboot():
    f = FlashSim()
    ob = boot(f).outbox(TOPIC, 4096)
    a, b = aid(), aid()
    ob.add(a, b"TAMPER", b"TAMPER")
    ob.add(b, b"SAG 190V", b"VOLTAGE")
    ob2 = boot(f).outbox(TOPIC, 4096)                               # reboot
    assert [x[1:] for x in ob2.queued()] == [(a, b"TAMPER"), (b, b"SAG 190V")]
    ob2.ack(a)
    assert [x[1] for x in boot(f).outbox(TOPIC, 4096).queued()] == [b]


def test_outbox_full_merges_same_kind_then_drops_oldest_and_counts():
    f = FlashSim()
    from pqgrid.persistence.device import Outbox
    ob = boot(f).outbox(TOPIC, 3 * (40 + 5 + Outbox.OVERHEAD))      # room for three 40-byte alerts (real bytes)
    ids = [aid() for _ in range(5)]
    ob.add(ids[0], b"x" * 40, b"SAG__")
    ob.add(ids[1], b"y" * 40, b"TAMPR")
    ob.add(ids[2], b"z" * 40, b"SAG__")
    ob.add(ids[3], b"w" * 40, b"SAG__")                             # full: both older SAG__ merge into this
    assert [x[1] for x in ob.queued()[1:]] == [ids[1], ids[3]] and ob.dropped() == 2
    ob.add(ids[4], b"v" * 40, b"OTHER")
    ob.add(aid(), b"u" * 40, b"NEWKD")                              # full, no same kind: drop the oldest
    assert ids[1] not in [x[1] for x in ob.queued()] and ob.dropped() == 3
    counter = ob.queued()[0]
    assert counter[2] == b"DROPPED:3"                               # sent first, as an alert of its own
    ob.ack(counter[1])
    assert ob.dropped() == 0 and not ob.queued()[0][2].startswith(b"DROPPED")


def test_outbox_counter_gets_a_new_alert_id_when_it_changes():
    ob = boot(FlashSim()).outbox(TOPIC, 30)
    ob.add(aid(), b"x" * 100)                                        # larger than the cap: counted, not kept
    first = ob.queued()[0][1]
    ob.add(aid(), b"y" * 100)
    assert ob.queued()[0][1] != first and ob.queued()[0][2] == b"DROPPED:2"


def test_outbox_ack_seqs_maps_df_order():
    ob = boot(FlashSim()).outbox(TOPIC, 4096)
    ids = [aid() for _ in range(3)]
    for i in ids:
        ob.add(i, b"p")
    sent = ob.queued()
    ob.ack_seqs(sent, [1, 3])
    assert [x[1] for x in ob.queued()] == [ids[1]]


def test_outbox_rejects_bad_alert_id():
    with pytest.raises(ValueError):
        boot(FlashSim()).outbox(TOPIC, 100).add(b"short", b"p")
