"""Final remediation, flash capacity: the device record store must hold the documented worst case (every record
that can legitimately coexist, each at its largest: persistence.device.budget), survive a power cut while it
compacts that state, and refuse an impossible configuration explicitly (CapacityError) at start-up or before a
policy that would need more is committed. Also: DF carries only as many alerts as its NT/FIN reply can ACK within
the class packet limit, so a full outbox never blocks establishment."""
import os

import pytest

from conftest import World, make_policy, replace_class
from test_fota import CHUNK, MP, build, station  # noqa: F401  (fixture)
from pqgrid.commands.codec import Command
from pqgrid.commands.device import MAX_COMMAND, MAX_INTENTS
from pqgrid.commands.zones import MAX_ZONES
from pqgrid.e2e.envelopes import ACK_BUNDLE_ENTRY, MAX_BUNDLE, alert_topic, df_alert_limit
from pqgrid.e2e.handshake import DeviceEndpoint, StoredTicket
from pqgrid.errors import CapacityError
from pqgrid.fota.artifact import ANCHOR_A, ANCHOR_B, FIRMWARE, KEYREVOKE, POLICY, FotaError
from pqgrid.fota.installer import FotaFlash, Installer
from pqgrid.mqtt import topics
from pqgrid.fota.publisher import part_payload_budget
from pqgrid.persistence.device import DeviceFlash, budget
from pqgrid.persistence.flash import FlashSim, PowerLoss, RecordStore, record_size
from pqgrid.policy import encode_policy
from pqgrid.registry import DeviceRecord
from pqgrid.suite.hkem import HybridKeyPair
from pqgrid.suite.sig import mldsa_public_bytes

LONGEST = b"c2-" + b"x" * 29                                     # a 32-character device id (the maximum)
T_TICKET, T_RH, T_CMD, T_ZONE, T_OUTBOX, T_OUTMETA, T_TIME, T_INTENT = 1, 2, 3, 4, 5, 6, 7, 8


def live_view(store) -> dict:
    return {k: v[1] for k, v in store._live.items()}


def by_type(store) -> dict[int, int]:
    """Flash bytes of the live records, per record type."""
    out: dict[int, int] = {}
    for (t, k), (_, v) in store._live.items():
        out[t] = out.get(t, 0) + record_size(len(k), len(v))
    return out


class Worst:
    """A C2 device with every legitimate state present at once."""

    def __init__(self, world: World, station, flash: FlashSim | None = None):
        self.w, self.f = world, flash or FlashSim()
        self.kp = HybridKeyPair.generate()
        world.registry.add(DeviceRecord(LONGEST, "c2_meter", self.kp.pk))
        self.prof = world.policy.profile("c2_meter")
        self.prot, self.ff, self.anchors = FlashSim(), FotaFlash(64 * 1024), station.anchors
        self.boot()
        world.full(self.d)                                       # ticket (PSK) + time floor
        self.d.resume_hello()                                    # the stored RH, while the ticket is still held
        self.outbox = self.df.outbox(alert_topic("c2_meter", LONGEST), self.prof.outbox_cap)
        for i in range(2):
            self.outbox.add(os.urandom(16), b"B" * 1024, b"BIG%d" % i)          # two maximum-size alerts
        i = 0
        while True:                                              # then small ones, all of different kinds,
            before = self.outbox.dropped()                       # until the cap forces a drop (full + counter)
            self.outbox.add(os.urandom(16), b"s", b"k%05d" % i)
            i += 1
            if self.outbox.dropped() > before:
                break
        st = self.df.command_state()
        for n in range(1, MAX_INTENTS):                          # 31 interrupted intents …
            st.write_pending(Command(n, b"x", 10 ** 10, False, b""))
            st.mark_interrupted(n)
        st.write_pending(Command(MAX_INTENTS, b"C" * MAX_COMMAND, 10 ** 10, True, b""))   # … + 1 pending body
        for z in range(MAX_ZONES):
            st.write_zone_bseq(("z%02d" % z).ljust(32, "z"), (7 << 32) | z)
        fw = build(station, FIRMWARE, 2, os.urandom(20_000))
        pol = build(station, POLICY, 2, os.urandom(3000))
        rev = station.keyrevoke("c2_meter", 1, ANCHOR_A, CHUNK, part_payload_budget(MP, "c2_meter", KEYREVOKE, 1),
                                anchor_id=ANCHOR_B)
        for p in fw.parts + rev.parts:                           # FIRMWARE, KEYREVOKE: manifests accepted,
            self.inst.on_part(p)                                 # downloads open
        for p in pol.parts:
            self.inst.on_part(p)
        for c in pol.chunks:                                     # POLICY: fully staged
            self.inst.on_chunk(c)
        for c in fw.chunks[:3]:                                  # FIRMWARE: 3 of its chunks in the bitmap
            self.inst.on_chunk(c)
        assert {FIRMWARE, KEYREVOKE} <= set(self.inst.downloads) and POLICY in self.inst.staged

    def boot(self):
        self.df = DeviceFlash(self.f, clock=lambda: self.w.t)
        self.d = DeviceEndpoint(LONGEST, "c2_meter", self.w.policy, 1, self.kp, clock=lambda: self.w.t, flash=self.df)
        self.inst = Installer(self.anchors, "c2_meter", self.prof.max_packet, self.ff, RecordStore(self.prot, lambda: self.w.t),
                              self.df.store, lambda: self.w.t)


def test_worst_case_state_fits_the_budget_item_by_item(world: World, station):
    items, largest = budget(world.policy.profile("c2_meter"))
    wc = Worst(world, station)
    used = by_type(wc.df.store)
    fota = used.get(30, 0) + used.get(31, 0)
    assert used[T_TICKET] <= items["ticket"] and used[T_RH] <= items["resume hello"]
    assert used[T_OUTBOX] + used[T_OUTMETA] <= items["outbox (cap) + drop counter"]
    assert used[T_INTENT] <= items[f"intents ({MAX_INTENTS - 1} interrupted + 1 pending body)"]
    assert used[T_ZONE] <= items[f"zones ({MAX_ZONES})"] and fota <= items["FOTA (3 types)"]
    need, usable = wc.df.capacity(wc.prof)
    total = sum(used.values())
    assert total + largest <= need <= usable                              # the model covers what really exists
    print(f"\nworst case live {total} B (+{largest} B in flight); budget {need} B; bank holds ≥ {usable} B")


def test_power_cut_while_compacting_the_worst_case_then_reboot_recovers_everything(world: World, station):
    wc = Worst(world, station)
    snap, state0 = wc.f.clone(), live_view(wc.df.store)
    probe = DeviceFlash(snap.clone(), clock=lambda: world.t)
    t0 = probe.store.f.ticks
    probe.store.compact()
    n = probe.store.f.ticks - t0
    assert n >= sum(by_type(wc.df.store).values())               # every live byte is re-programmed
    for k in list(range(0, n, max(1, n // 60))) + [n - 1]:
        f = snap.clone()
        df = DeviceFlash(f, clock=lambda: world.t)
        f.fail_after = k
        with pytest.raises(PowerLoss):
            df.store.compact()
        f.fail_after = None
        again = DeviceFlash(f, clock=lambda: world.t)            # reboot
        assert live_view(again.store) == state0, k
        st = again.command_state()
        assert len(st.pending) == MAX_INTENTS and st.pending[MAX_INTENTS].command == b"C" * MAX_COMMAND
        assert len(st.zone_bseq) == MAX_ZONES and again.load_ticket(StoredTicket) is not None
        assert again.load_rh() is not None and again.time_floor() > 0


def test_an_impossible_flash_is_refused_at_start_up(world: World):
    kp = HybridKeyPair.generate()
    world.registry.add(DeviceRecord(LONGEST, "c2_meter", kp.pk))
    small = DeviceFlash(FlashSim(pages=4), clock=lambda: world.t)   # two 8 KiB banks: the old default
    with pytest.raises(CapacityError, match="worst case needs 10758 B.*holds 6034 B"):
        DeviceEndpoint(LONGEST, "c2_meter", world.policy, 1, kp, clock=lambda: world.t, flash=small)


def test_a_policy_needing_more_flash_is_refused_before_it_is_committed(world: World, station):
    kp = HybridKeyPair.generate()
    world.registry.add(DeviceRecord(LONGEST, "c2_meter", kp.pk))
    df = DeviceFlash(FlashSim(), clock=lambda: world.t)
    d = DeviceEndpoint(LONGEST, "c2_meter", world.policy, 1, kp, clock=lambda: world.t, flash=df)
    big = make_policy(world.u_static.pk, mldsa_public_bytes(world.cmd_sk), version=2,
                      classes=replace_class(world.policy, "c2_meter", outbox_cap=8192))
    with pytest.raises(CapacityError):
        d.install_policy(big)
    assert d.policy is world.policy                               # nothing changed
    inst = Installer(station.anchors, "c2_meter", 4096, FotaFlash(64 * 1024), RecordStore(FlashSim(), lambda: world.t),
                     df.store, lambda: world.t)
    art = build(station, POLICY, 2, encode_policy(big))
    for p in art.parts:
        inst.on_part(p)
    for c in art.chunks:
        inst.on_chunk(c)
    with pytest.raises(FotaError, match="policy refused: device flash too small"):
        inst.activate_policy(world.policy, admit=lambda p: df.require_capacity(p.profile("c2_meter")))
    assert inst.committed(POLICY) == 0


def test_df_carries_only_what_its_reply_can_acknowledge_within_the_packet_limit(world: World):
    k = df_alert_limit(4096)
    assert k == (4096 - 420) // ACK_BUNDLE_ENTRY == 53 and df_alert_limit(65536) == MAX_BUNDLE
    kp = HybridKeyPair.generate()
    world.registry.add(DeviceRecord(LONGEST, "c2_meter", kp.pk))
    d = DeviceEndpoint(LONGEST, "c2_meter", world.policy, 1, kp, clock=lambda: world.t)
    t = alert_topic("c2_meter", LONGEST)
    res, acked = world.full(d, alerts=[(t, os.urandom(16), b"") for _ in range(k)])
    assert len(acked) == k and topics.publish_size(topics.hs_down(LONGEST), res.final) <= 4096


# ----------------------------------------------------------------------- each bound the budget relies on
def test_a_second_command_before_recovery_leaves_at_most_one_pending_body(world: World):
    """Two commands interrupted in a row, the second delivered before recovery ran: the first becomes INTERRUPTED
    (body dropped, never re-applied: E37) the moment the second is accepted, so flash never holds two bodies."""
    from pqgrid.commands import CommandProcessor, CommandService
    from pqgrid.e2e.envelopes import control_topic
    from pqgrid.persistence.device import T_INTENT
    from pqgrid.wire import dec
    d1 = b"der-0001"
    kp, f = HybridKeyPair.generate(), FlashSim()
    world.registry.add(DeviceRecord(d1, "der_ctrl", kp.pk))
    svc = CommandService(world.utility, world.cmd_sk)
    topic = control_topic("der_ctrl", d1)

    def boot():
        df = DeviceFlash(f, clock=lambda: world.t)
        d = DeviceEndpoint(d1, "der_ctrl", world.policy, 1, kp, clock=lambda: world.t, flash=df)
        return df, d
    df, d = boot()
    world.full(d)
    for body in (b"A" * MAX_COMMAND, b"B" * MAX_COMMAND):
        svc.issue(d1, body, 600, idempotent=True)
        env = svc.outgoing(d1)[-1]

        def crash(cmd):
            raise PowerLoss()
        with pytest.raises(PowerLoss):
            CommandProcessor(d, crash, state=df.command_state()).on_control(topic, env)
        bodies = [v for _, v in df.store.items(T_INTENT).values() if len(dec(v, 4)[3]) == MAX_COMMAND]
        assert len(bodies) == 1                                    # never two bodies at once
        df, d = boot()
        world.t += 1
        world.resume(d)                                            # no recover() yet: the next command comes first
    st = df.command_state()
    assert [r.interrupted for r in sorted(st.pending.values(), key=lambda r: r.cmd_seq)] == [True, False]


def test_a_manifest_with_more_chunks_than_the_download_record_allows_is_refused(station):
    from test_fota import Dev
    d = Dev(station)
    art = build(station, FIRMWARE, 2, os.urandom(20_000), chunk=16)            # 1,250 chunks
    with pytest.raises(FotaError, match="more than 1024 chunks"):
        d.feed(art, chunks=[])
    assert d.inst.downloads == {}


def test_zone_membership_is_bounded_on_both_sides(world: World):
    from pqgrid.commands import CommandProcessor, CommandService, ZoneManager
    from pqgrid.e2e.envelopes import control_topic
    from pqgrid.errors import CommandError
    from pqgrid.wire import dec
    d1 = b"der-0001"
    d = world.device(d1, "der_ctrl")
    world.full(d)
    svc = CommandService(world.utility, world.cmd_sk)
    zm, proc = ZoneManager(svc), CommandProcessor(d, lambda c: None)
    for z in range(MAX_ZONES):
        zm.create(f"z{z}")
        zm.add_member(f"z{z}", d1)
    zm.create("one-too-many")
    with pytest.raises(CommandError, match="already in 16 zones"):
        zm.add_member("one-too-many", d1)                          # the utility refuses the 17th
    topic = control_topic("der_ctrl", d1)
    for env in zm.zonekeys_for(d1):
        assert dec(proc.on_control(topic, env), 6)[4] == b"OK"
    from pqgrid.commands.codec import ZoneKey, encode
    from pqgrid.e2e.envelopes import seal_control
    extra = ZoneKey("one-too-many", 1, d.profile.aead, os.urandom(32))
    ack = proc.on_control(topic, seal_control(world.policy, world.utility.session_for(d1), topic, encode(extra)))
    assert dec(ack, 6)[4] == b"REJECTED:capacity"                  # and so does the device


def test_an_alert_larger_than_the_record_bound_is_refused_not_truncated(world: World):
    df = DeviceFlash(FlashSim(), clock=lambda: world.t)
    ob = df.outbox("grid/c2_meter/c2-0001/alert", 4096)
    with pytest.raises(ValueError, match="alert payload"):
        ob.add(os.urandom(16), b"x" * 1025)
    with pytest.raises(ValueError, match="alert payload"):
        ob.add(os.urandom(16), b"x", b"k" * 17)
    assert ob.queued() == []


def test_df_size_is_bounded_by_the_outbox_cap_for_c2(world: World):
    """The largest possible C2 DF: 53 alerts (the reply limit) sharing the rest of the 4 KiB outbox as payload.
    By hand: 52 B DF framing + 53 × 77 B per empty alert + 1,976 B payload (4,096 − 53 × 40 B record overhead)
    = 6,109 B, sent upstream (the device's 4 KiB limit is for what it receives: the reply, ≤ 4,096 B)."""
    from pqgrid.persistence.device import Outbox
    kp = HybridKeyPair.generate()
    world.registry.add(DeviceRecord(LONGEST, "c2_meter", kp.pk))
    df = DeviceFlash(FlashSim(), clock=lambda: world.t)
    d = DeviceEndpoint(LONGEST, "c2_meter", world.policy, 1, kp, clock=lambda: world.t, flash=df)
    ob = df.outbox(alert_topic("c2_meter", LONGEST), 4096)
    k = df_alert_limit(4096)
    share = (4096 - k * Outbox.OVERHEAD) // k                     # payload per alert that fills the cap exactly
    for i in range(k):
        ob.add(os.urandom(16), b"p" * share)
    sent = ob.queued()[:k]
    assert len(ob.queued()) == k and ob.dropped() == 0
    d.on_server_hello(world.utility.on_client_hello(LONGEST, d.client_hello()))
    dfm = d.finished(sent)
    res = world.utility.on_finished(LONGEST, dfm)
    assert len(dfm) <= 52 + k * 77 + (4096 - k * Outbox.OVERHEAD) == 6109
    assert topics.publish_size(topics.hs_down(LONGEST), res.final) <= 4096 and len(res.alerts) == k
