"""Restarts and reboots over real storage: the utility on an SQLite file, devices on simulated NOR flash
(Master §9.8, §16; S1, S2, S3, S4, V-S1, V-S3, E-P2, E-P3, E-P4; DR-041, DR-048, DR-049; C8, C9).

S3 kills a writer process with SIGKILL: that is a process crash, not a power cut. Power-cut durability of
SQLite (WAL + synchronous=FULL, i.e. fsync per commit) is relied on, not re-proven here; the device side, whose
store is our own code, is tested at every simulated power-loss point."""
import os
import signal
import statistics
import subprocess
import sys
import time
from pathlib import Path

import pytest

from conftest import World, make_policy
from pqgrid.commands import CommandProcessor, CommandService
from pqgrid.e2e.envelopes import alert_topic, control_topic
from pqgrid.e2e.handshake import DeviceEndpoint, UnknownSessionError
from pqgrid.errors import EnvelopeError, ReplayError, TicketError, TicketReusedError
from pqgrid.persistence.device import DeviceFlash
from pqgrid.persistence.flash import FlashSim, PowerLoss
from pqgrid.persistence.utility_db import SqlUsedTickets, UtilityDB, open_utility
from pqgrid.policy import validate
from pqgrid.registry import DeviceRecord
from pqgrid.suite.hkem import HybridKeyPair
from pqgrid.suite.sig import mldsa_keygen, mldsa_public_bytes

ROOT = Path(__file__).resolve().parents[2]
M1, D1 = b"meter-0001", b"der-0001"
T0 = 1_790_000_000.0


class Plant:
    """A utility process on an SQLite file, and devices on simulated flash."""

    def __init__(self, tmp_path):
        self.t, self.path = T0, str(tmp_path / "utility.db")
        self.u_static, self.cmd_sk = HybridKeyPair.generate(), mldsa_keygen()
        self.policy = make_policy(self.u_static.pk, mldsa_public_bytes(self.cmd_sk))
        validate(self.policy)
        self.node = open_utility(self.path, self.policy, self.u_static, self.cmd_sk, lambda: self.t)

    @property
    def u(self):
        return self.node.endpoint

    def restart(self, path=None):
        """The utility process dies: RAM (sessions, half-open state, duplicate cache) is gone."""
        self.node.db.close()
        self.node = open_utility(path or self.path, self.policy, self.u_static, self.cmd_sk, lambda: self.t)

    def device(self, did, dclass):
        return Dev(self, did, dclass)

    def full(self, dev, alerts=()):
        dev.d.on_server_hello(self.u.on_client_hello(dev.did, dev.d.client_hello()))
        res = self.u.on_finished(dev.did, dev.d.finished(list(alerts)))
        return res, dev.d.on_final(res.final)

    def resume(self, dev, alerts=()):
        dev.d.on_resume_server(self.u.on_resume_hello(dev.did, dev.d.resume_hello()))
        res = self.u.on_finished(dev.did, dev.d.finished(list(alerts)))
        return res, dev.d.on_final(res.final)


class Dev:
    def __init__(self, plant: Plant, did: bytes, dclass: str):
        self.p, self.did, self.dclass = plant, did, dclass
        self.kp, self.flash, self.applied = HybridKeyPair.generate(), FlashSim(), []
        plant.u.registry.add(DeviceRecord(did, dclass, self.kp.pk))
        self.boot()

    def boot(self):
        """Power-on: everything is rebuilt from flash."""
        self.df = DeviceFlash(self.flash, clock=lambda: self.p.t)
        self.d = DeviceEndpoint(self.did, self.dclass, self.p.policy, 1, self.kp, clock=lambda: self.p.t, flash=self.df)
        self.proc = CommandProcessor(self.d, self.applied.append, state=self.df.command_state())


@pytest.fixture
def p(tmp_path) -> Plant:
    return Plant(tmp_path)


# =============================================================================================== utility restarts
def test_tickets_and_steks_survive_a_utility_restart(p: Plant):
    dev = p.device(M1, "smart_meter")
    p.full(dev)
    p.t += 60
    p.restart()
    p.resume(dev)
    assert dev.d.confirmed and dev.d.ticket is not None


def test_EP4_consumed_ticket_replayed_after_a_restart(p: Plant):
    dev = p.device(M1, "smart_meter")
    p.full(dev)
    rh = dev.d.resume_hello()
    p.resume(dev)
    p.restart()                                                        # the duplicate cache is gone too
    with pytest.raises(TicketReusedError):
        p.u.on_resume_hello(M1, rh)


def test_EP3_counterfactual_restart_without_the_stek_kills_every_ticket(p: Plant, tmp_path):
    dev = p.device(M1, "smart_meter")
    p.full(dev)
    p.restart(path=str(tmp_path / "lost.db"))                          # the database (and STEK) is lost
    p.u.registry.add(DeviceRecord(M1, "smart_meter", dev.kp.pk))       # re-provisioned
    other = p.device(b"meter-0002", "smart_meter")
    p.full(other)                                                      # the new STEK takes kid 0 again
    with pytest.raises(TicketError, match="ticket not authentic"):
        p.u.on_resume_hello(M1, dev.d.resume_hello())


def test_S1_and_VS1_commands_after_restart_and_after_restore_from_backup(p: Plant, tmp_path):
    dev = p.device(D1, "der_ctrl")
    p.full(dev)
    topic = control_topic("der_ctrl", D1)

    def pump():
        return [p.node.commands.on_status(dev.proc.on_control(topic, e))[2] for e in p.node.commands.outgoing(D1)]
    p.node.commands.issue(D1, b"A", 300)
    assert pump() == [b"OK"]
    backup = str(tmp_path / "backup.db")
    p.node.db.backup_to(backup)
    p.node.commands.issue(D1, b"B", 300)
    assert pump() == [b"OK"]
    p.t += 5
    p.restart()                                                        # S1: plain restart
    p.resume(dev)
    p.node.commands.issue(D1, b"C", 300)
    assert pump() == [b"OK"]
    p.t += 60
    p.restart(path=backup)                                             # V-S1: restore an old backup
    p.full(dev)                                                        # its ticket store predates the resume
    p.node.commands.issue(D1, b"D", 300)
    assert pump() == [b"OK"] and dev.applied == [b"A", b"B", b"C", b"D"] and p.node.commands.alarms == []


def test_EP2_restart_resync_resume_and_the_outbox_alert_is_delivered(p: Plant):
    dev = p.device(M1, "smart_meter")
    p.full(dev)
    topic = alert_topic("smart_meter", M1)
    outbox = dev.df.outbox(topic, p.policy.profile("smart_meter").outbox_cap)
    aid = os.urandom(16)
    outbox.add(aid, b"TAMPER", b"TAMPER")
    env = dev.d.seal_alert(topic, aid, b"TAMPER")
    p.restart()                                                        # the utility restarts before it arrives
    with pytest.raises(UnknownSessionError) as e:
        p.u.open_alert(topic, env)
    with pytest.raises(EnvelopeError, match="already sent"):          # U-6: one hint per 30 s per device
        p.u.open_alert(topic, env)
    assert dev.d.on_resync_hint(e.value.hint)
    sent = outbox.queued()
    res, acked = p.resume(dev, sent)                                   # the outbox rides inside DF
    assert res.alerts == [(aid, b"TAMPER", False)]
    outbox.ack_seqs(sent, acked)
    assert outbox.queued() == []


def test_resync_hint_is_bound_to_the_live_sid_and_rate_limited(p: Plant):
    dev = p.device(M1, "smart_meter")
    p.full(dev)
    assert not dev.d.on_resync_hint(b"garbage")
    assert not dev.d.on_resync_hint(UnknownSessionError(os.urandom(8)).hint)      # another sid: ignored
    assert dev.d.on_resync_hint(UnknownSessionError(dev.d.session.sid).hint)
    p.resume(dev)
    p.t += 10
    assert not dev.d.on_resync_hint(UnknownSessionError(dev.d.session.sid).hint)  # within 30 s: ignored
    p.t += 20
    assert dev.d.on_resync_hint(UnknownSessionError(dev.d.session.sid).hint)


# ================================================================================================ device reboots
def test_C9_reboot_between_rs_and_nt_means_a_full_handshake_and_no_false_alarm(p: Plant):
    dev = p.device(M1, "smart_meter")
    p.full(dev)
    dev.d.on_resume_server(p.u.on_resume_hello(M1, dev.d.resume_hello()))
    dev.boot()                                                         # power lost before NT arrived
    assert dev.d.ticket is None and not dev.d.can_resume()
    p.full(dev)
    assert dev.d.ticket is not None


def test_S5_reboot_after_the_rh_was_processed_resends_the_identical_rh(p: Plant):
    dev = p.device(M1, "smart_meter")
    p.full(dev)
    rh = dev.d.resume_hello()
    p.u.on_resume_hello(M1, rh)                                        # processed; the RS is lost
    dev.boot()
    assert dev.d.resume_hello() == rh                                  # from flash (PSK)
    p.t += 5
    dev.d.on_resume_server(p.u.on_resume_hello(M1, rh))                # identical RS from the duplicate cache
    dev.d.on_final(p.u.on_finished(M1, dev.d.finished()).final)
    assert dev.d.confirmed


def test_C8_psk_kem_reboot_after_rh_drops_the_ticket_without_a_false_alarm(p: Plant):
    dev = p.device(D1, "der_ctrl")
    p.full(dev)
    rh = dev.d.resume_hello()
    assert dev.flash.mem.find(dev.d._reph.private_bytes()) < 0         # the ephemeral key never reached flash
    p.u.on_resume_hello(D1, rh)
    dev.boot()
    assert dev.d.ticket is None                                        # dropped: it may have been consumed
    p.full(dev)                                                        # a full handshake; no reuse alarm raised
    assert dev.d.confirmed


def test_DR048_with_real_flash(p: Plant):
    from pqgrid.suite.aead import AeadAlg
    from pqgrid.commands import event_topic
    dev = p.device(D1, "der_ctrl")
    p.full(dev)
    zm = p.node.zones
    zt = event_topic("f7", AeadAlg.CHACHA20POLY1305)
    zm.create("f7")
    zm.add_member("f7", D1)
    topic = control_topic("der_ctrl", D1)
    dev.proc.on_control(topic, zm.distribute("f7")[D1])
    seen = zm.publish("f7", b"E1", 600)[zt]
    dev.proc.zones.open(zt, seen)
    dev.boot()                                                         # device reboot
    p.t += 1
    p.resume(dev)
    p.restart()                                                        # and a utility restart
    p.full(dev)
    for env in p.node.zones.zonekeys_for(D1):                          # zones reloaded from the database
        dev.proc.on_control(topic, env)
    queued = p.node.zones.publish("f7", b"E2", 600)[zt]
    with pytest.raises(ReplayError, match="broadcast replay"):
        dev.proc.zones.open(zt, seen)
    assert dev.proc.zones.open(zt, queued) == b"E2"


@pytest.mark.parametrize("idempotent", [False, True])
def test_VS3_power_loss_at_every_flash_step_of_a_command(idempotent):
    """S2a/S2b/V-S3 over the real flash store: power is cut at every programmed byte while a command is
    processed. Afterwards the device never actuates a non-idempotent command twice, reports OK/DUP only when
    APPLIED is durable, and reports INTERRUPTED when the outcome is unknown."""
    w = World()
    svc = CommandService(w.utility, w.cmd_sk)
    topic_of = lambda did: control_topic("der_ctrl", did)             # noqa: E731

    def run(k):
        did = f"der-{k:05d}".encode()
        kp, f, applied = HybridKeyPair.generate(), FlashSim(), []
        w.registry.add(DeviceRecord(did, "der_ctrl", kp.pk))

        def boot():
            df = DeviceFlash(f, clock=lambda: w.t)
            d = DeviceEndpoint(did, "der_ctrl", w.policy, 1, kp, clock=lambda: w.t, flash=df)
            return d, CommandProcessor(d, applied.append, state=df.command_state())
        d, proc = boot()
        w.full(d)
        seq = svc.issue(did, b"TRIP", 300, idempotent)
        env = svc.outgoing(did)[0]
        t0 = f.ticks
        f.fail_after = k
        try:
            svc.on_status(proc.on_control(topic_of(did), env))
            crashed = False
        except PowerLoss:
            crashed = True
        f.fail_after = None
        used = f.ticks - t0
        if crashed:
            d, proc = boot()
            w.resume(d)
            for r in proc.recover():
                svc.on_status(r)
            for e in svc.outgoing(did):
                svc.on_status(proc.on_control(topic_of(did), e))
        outcome = svc.outcome(did, seq)
        if idempotent:
            assert outcome in (b"OK", b"DUP") and 1 <= len(applied) <= 2
        else:
            assert len(applied) <= 1, "a non-idempotent command was actuated twice"
            assert outcome in (b"OK", b"DUP", b"INTERRUPTED")
            if outcome == b"INTERRUPTED":
                assert len(applied) == 1                             # the device honestly does not know
        if outcome in (b"OK", b"DUP"):
            assert proc.state.is_applied(seq) and len(applied) >= 1
        return crashed, used

    crashed, n = run(10 ** 9)                                         # no crash: count the flash operations
    assert not crashed and n > 0
    outcomes = [run(k)[0] for k in range(n)]
    assert all(outcomes) and len(outcomes) == n
    print(f"V-S3 power-loss points (idempotent={idempotent}): {n}")


# ====================================================================================== S3: kill -9 the writer
_CHILD = r"""
import sys
sys.path.insert(0, {root!r})
from pqgrid.persistence.utility_db import UtilityDB, SqlUsedTickets, SqlCommandStore
from pqgrid.commands.utility import QueuedCommand
from pqgrid.commands.codec import Command
db = UtilityDB({path!r})
used, store = SqlUsedTickets(db), SqlCommandStore(db)
epoch = store.start(1_790_000_000)
i = 0
while True:
    i += 1
    tid = i.to_bytes(16, "big")
    used.consume(tid, 1_790_100_000, 1_790_000_000)
    q = store.allocate_and_enqueue(b"der-0001", epoch, lambda s: QueuedCommand(b"der-0001", "t", Command(s, b"X", 1, False, b"s")))
    print(tid.hex(), q.cmd.cmd_seq, flush=True)          # printed only after both commits returned
"""


@pytest.mark.parametrize("lines", [1, 37, 211])
def test_S3_writer_killed_mid_stream_loses_no_promise(tmp_path, lines):
    path = str(tmp_path / "u.db")
    child = subprocess.Popen([sys.executable, "-c", _CHILD.format(root=str(ROOT), path=path)],
                             stdout=subprocess.PIPE, text=True)
    promised = []
    while len(promised) < lines:
        promised.append(child.stdout.readline().split())
    os.kill(child.pid, signal.SIGKILL)
    child.wait()
    promised += [ln.split() for ln in child.stdout.read().splitlines() if ln]
    db = UtilityDB(path)                                              # the restart
    assert db.c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    used = SqlUsedTickets(db)
    for tid_hex, seq in promised:
        assert not used.consume(bytes.fromhex(tid_hex), 1_790_100_000, 1_790_000_001)   # still consumed
    seqs = {int(r[0].hex(), 16) for r in db.c.execute("SELECT cmd_seq FROM commands")}
    assert {int(s) for _, s in promised} <= seqs                     # every announced command is queued


# ================================================================================ S4: cost does not grow
def test_S4_resume_cost_is_constant_with_100k_outstanding_tickets(tmp_path):
    def per_consume(n_existing: int) -> float:
        db = UtilityDB(str(tmp_path / f"s4-{n_existing}.db"))
        with db.tx() as c:
            c.executemany("INSERT INTO used_tickets VALUES (?, ?)",
                          ((i.to_bytes(16, "big"), 1_790_100_000) for i in range(n_existing)))
        used, times = SqlUsedTickets(db), []
        for i in range(200):
            t = time.perf_counter()
            assert used.consume(os.urandom(16), 1_790_100_000, 1_790_000_000)
            times.append(time.perf_counter() - t)
        db.close()
        return statistics.median(times)
    small, big = per_consume(100), per_consume(100_000)
    print(f"S4 median per resume: {small * 1e3:.3f} ms at 100 tickets, {big * 1e3:.3f} ms at 100,000")
    assert big < 4 * small + 0.002                                    # v2.1: 41.9 ms and 4.8 MB per resume
