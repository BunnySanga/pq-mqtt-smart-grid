"""CONTROL tier: signed commands, at-most-once with honest statuses, crash safety, GRANT/SETPOINT limits, zone
keys and DR broadcasts (Master §11, §13, §16; §24.1 A9–A11, C-E3, E-CMD1–5, E-Z1, S1, S2, V-G1–6, V-S1–3, V-Z1;
DR-045–DR-048; IMPLEMENTATION-ROADMAP §9).

A reboot is modelled by keeping the device's flash objects (command state, ticket) and discarding the rest."""
import dataclasses
import os

import pytest

from conftest import World, make_policy, replace_class
from pqgrid.commands import CommandProcessor, CommandService, DeviceCommandState, UtilityCommandStore, ZoneManager
from pqgrid.commands.codec import Command, Grant, Setpoint, ZoneKey, bcast_signed_input, cmd_signed_input, encode, \
    grant_signed_input
from pqgrid.commands.zones import event_topic
from pqgrid.e2e.envelopes import control_topic, seal_control
from pqgrid.e2e.handshake import DeviceEndpoint
from pqgrid.errors import CommandError, EnvelopeError, ReplayError
from pqgrid.policy.model import CmdType
from pqgrid.suite.aead import AeadAlg
from pqgrid.suite.sig import mldsa_keygen, mldsa_public_bytes, mldsa_sign
from pqgrid.wire import dec, enc

D1, D2, M1 = b"der-0001", b"der-0002", b"meter-0001"
TARGET = "P_ACTIVE_W"


class PowerLoss(Exception):
    """The device loses power in the middle of actuation."""


class Ctl:
    """One command service and one device with a command processor, over a live E2E session."""

    def __init__(self, world: World, did=D1, dclass="der_ctrl", svc=None, connect=True):
        self.w, self.did, self.topic = world, did, control_topic(dclass, did)
        self.svc = svc or CommandService(world.utility, world.cmd_sk)
        self.d = world.device(did, dclass)
        self.applied, self.sps, self.state = [], [], DeviceCommandState()
        self._new_processor()
        if connect:
            world.full(self.d)

    def _new_processor(self):
        self.proc = CommandProcessor(self.d, self.applied.append, lambda t, v: self.sps.append((t, v)),
                                     targets={TARGET}, state=self.state)

    def issue(self, cmd=b"TRIP", ttl=300, idem=False) -> int:
        return self.svc.issue(self.did, cmd, ttl, idem)

    def pump(self) -> list[bytes]:
        """Deliver everything the utility has for this device; return the statuses the utility settled."""
        out = []
        for env in self.svc.outgoing(self.did):
            ack = self.proc.on_control(self.topic, env)
            out.append(self.svc.on_status(ack)[2])
        return out

    def deliver(self, env) -> bytes:
        return self.svc.on_status(self.proc.on_control(self.topic, env))[2]

    def reconnect(self):
        self.w.t += 1
        self.w.resume(self.d)

    def reboot(self):
        """RAM is lost; the command state and the ticket survive (flash, §16, §14.7)."""
        old = self.d
        self.d = DeviceEndpoint(old.id, old.dclass, old.policy, old.fw, old.static, clock=lambda: self.w.t)
        self.d.ticket = old.ticket
        self._new_processor()
        self.w.t += 1
        self.w.resume(self.d)


@pytest.fixture
def c(world: World) -> Ctl:
    return Ctl(world)


# ================================================================================================= CMD
def test_CE3_command_verified_applied_acked_and_queue_cleared(c: Ctl):
    seq = c.issue(b"CURTAIL 50%")
    assert c.pump() == [b"OK"] and c.applied == [b"CURTAIL 50%"]
    assert c.svc.outcome(D1, seq) == b"OK" and c.svc.outgoing(D1) == []


def test_command_accepted_before_nt_arrives(world: World):
    """The session is authentic for the device once SH verified; a command may overtake NT (other topic)."""
    c = Ctl(world, connect=False)
    c.d.on_server_hello(world.utility.on_client_hello(D1, c.d.client_hello()))
    world.utility.on_finished(D1, c.d.finished())                   # NT not yet delivered
    c.issue()
    assert c.pump() == [b"OK"]


def test_A9_replayed_envelope_and_redelivery_never_reapply(c: Ctl):
    c.issue()
    env = c.svc.outgoing(D1)[0]
    c.proc.on_control(c.topic, env)                                  # applied; the OK is lost
    with pytest.raises(ReplayError):
        c.proc.on_control(c.topic, env)                              # the same bytes again
    c.reconnect()
    assert c.pump() == [b"DUP"] and c.applied == [b"TRIP"]            # E-CMD2: redelivered → DUP
    assert c.svc.alarms == []                                        # redelivery answered DUP is normal


def test_forged_control_envelope_does_not_burn_the_sequence(c: Ctl):
    """As A8 for ALERT: validate before AEAD, accept after (I-7)."""
    c.issue()
    [env] = c.svc.outgoing(D1)
    f = dec(env, 4)
    f[3] = f[3][:-1] + bytes([f[3][-1] ^ 1])
    with pytest.raises(EnvelopeError):
        c.proc.on_control(c.topic, enc(f))
    assert c.deliver(env) == b"OK"


def test_ECMD1_command_for_an_offline_device_is_delivered_at_its_next_session(world: World):
    c = Ctl(world, connect=False)
    seq = c.issue()
    assert c.svc.outgoing(D1) == []
    world.full(c.d)
    assert c.pump() == [b"OK"] and c.svc.outcome(D1, seq) == b"OK"


def test_ECMD3_applied_ack_lost_reboot_redelivery_is_dup(c: Ctl):
    c.issue()
    c.proc.on_control(c.topic, c.svc.outgoing(D1)[0])
    c.reboot()
    assert c.pump() == [b"DUP"] and c.applied == [b"TRIP"]


def test_ECMD4_expired_commands(c: Ctl):
    never_sent = c.issue(ttl=10)
    sent = c.issue(ttl=20)
    [_, env] = c.svc.outgoing(D1)                                     # both sent; the second is lost
    c.w.t += 30
    assert c.svc.outgoing(D1) == []                                   # nothing expired is (re)delivered
    assert c.svc.outcome(D1, sent) == b"UNKNOWN"                      # E38: sent, unanswered: may be applied
    late = c.issue(b"LATE", ttl=5)
    [env] = c.svc.outgoing(D1)
    c.w.t += 6
    assert c.deliver(env) == b"EXPIRED" and b"LATE" not in c.applied
    lone = Ctl(c.w, did=D2)
    s = lone.issue(ttl=5)
    c.w.t += 6
    assert lone.svc.outgoing(D2) == [] and lone.svc.outcome(D2, s) == b"EXPIRED"   # never sent
    assert never_sent and late


def test_ECMD5_out_of_order_newest_wins(c: Ctl):
    c.issue(b"A")
    c.svc.outgoing(D1)                                               # A is lost in transit
    c.issue(b"B")
    assert c.pump() == [b"OK"]
    c.reconnect()
    assert c.pump() == [b"SUPERSEDED"] and c.applied == [b"B"]        # A redelivered, older than B
    assert c.svc.alarms == []


def test_DR046_late_redelivery_of_an_applied_command_is_dup_not_expired(c: Ctl):
    c.issue(ttl=60)
    c.proc.on_control(c.topic, c.svc.outgoing(D1)[0])                # applied; OK lost
    c.reconnect()
    [env] = c.svc.outgoing(D1)                                       # redelivered while still valid …
    c.w.t += 120                                                     # … but arrives after expiry
    assert c.deliver(env) == b"DUP"                                  # truthful: it WAS applied


def test_A10_session_key_holder_cannot_forge_commands(c: Ctl):
    s = c.w.utility.session_for(D1)
    rogue = mldsa_keygen()
    seq, exp = (c.svc.epoch << 32) | 99, int(c.w.t) + 60
    forged = Command(seq, b"TRIP", exp, False, mldsa_sign(rogue, cmd_signed_input(D1, c.topic, seq, exp, False, b"TRIP")))
    assert c.deliver(seal_control(c.w.policy, s, c.topic, encode(forged))) == b"REJECTED:signature"
    assert c.applied == []


def test_command_for_one_device_cannot_be_moved_to_another(world: World):
    a, b = Ctl(world, D1), Ctl(world, D2, svc=None)
    seq = a.issue(b"TRIP")
    cmd = a.svc.store.get(D1, seq).cmd
    env = seal_control(world.policy, world.utility.session_for(D2), b.topic, encode(cmd))
    assert b.deliver(env) == b"REJECTED:signature" and b.applied == []


# ================================================================================ restart and crashes
def test_S1_utility_restart_then_new_command_is_applied(c: Ctl):
    c.issue(b"A")
    assert c.pump() == [b"OK"]
    c.w.t += 5
    c.svc = CommandService(c.w.utility, c.w.cmd_sk, store=c.svc.store)          # restart
    c.issue(b"B")
    assert c.pump() == [b"OK"] and c.applied == [b"A", b"B"]


def test_VS1_restore_from_an_old_backup_then_new_command_is_applied(c: Ctl):
    c.issue(b"A")
    c.pump()
    backup = c.svc.store.snapshot()
    c.issue(b"B")
    c.pump()
    c.w.t += 60
    c.svc = CommandService(c.w.utility, c.w.cmd_sk, store=backup)               # restart from the backup
    c.issue(b"C")
    assert c.pump() == [b"OK"] and c.applied == [b"A", b"B", b"C"] and c.svc.alarms == []


def test_VS2_fresh_command_answered_superseded_raises_the_regression_alarm(c: Ctl):
    c.issue(b"A")
    c.pump()
    c.w.t -= 3600                                                   # database lost and the clock is wrong
    c.svc = CommandService(c.w.utility, c.w.cmd_sk, store=UtilityCommandStore())
    c.w.t += 3600
    c.issue(b"B")
    assert c.pump() == [b"SUPERSEDED"] and c.applied == [b"A"]
    assert c.svc.alarms and c.svc.alarms[0][0] == "sequence regression"


@pytest.mark.parametrize("idempotent", [False, True])
@pytest.mark.parametrize("step", ["before_actuation", "after_actuation"])
@pytest.mark.parametrize("order", ["recover_first", "redelivery_first"])
def test_S2a_VS3_crash_during_actuation(c: Ctl, step, idempotent, order):
    seq = c.issue(b"SET_MODE", idem=idempotent)
    env = c.svc.outgoing(D1)[0]

    def crash(cmd):
        if step == "after_actuation":
            c.applied.append(cmd)
        raise PowerLoss()
    c.proc.actuate = crash
    with pytest.raises(PowerLoss):
        c.proc.on_control(c.topic, env)                            # no status can leave: OK needs APPLIED (S2b)
    before = len(c.applied)
    c.reboot()
    if order == "recover_first":
        statuses = [c.svc.on_status(r)[2] for r in c.proc.recover()] + c.pump()
    else:
        statuses = c.pump() + [c.svc.on_status(r)[2] for r in c.proc.recover()]
    if idempotent:
        assert statuses[0] == b"OK" and len(c.applied) == before + 1       # re-applied once, then settled
        assert c.svc.outcome(D1, seq) == b"OK" and c.svc.interrupted == []
    else:
        assert set(statuses) == {b"INTERRUPTED"} and len(c.applied) == before   # never applied automatically
        assert c.svc.outcome(D1, seq) == b"INTERRUPTED" and c.svc.interrupted == [(D1, seq)]
    assert c.svc.outgoing(D1) == []


def test_crash_after_applied_before_the_ack_left(c: Ctl):
    c.issue()
    c.proc.on_control(c.topic, c.svc.outgoing(D1)[0])               # APPLIED; power lost before sending OK
    c.reboot()
    assert c.proc.recover() == [] and c.pump() == [b"DUP"] and c.applied == [b"TRIP"]


def test_E37_interrupted_idempotent_command_is_not_reapplied_after_a_newer_one(c: Ctl):
    c.issue(b"OLD", idem=True)
    env = c.svc.outgoing(D1)[0]
    c.proc.actuate = lambda cmd: (_ for _ in ()).throw(PowerLoss())
    with pytest.raises(PowerLoss):
        c.proc.on_control(c.topic, env)
    c.reboot()
    c.issue(b"NEW")
    envs = c.svc.outgoing(D1)                                       # [redelivered OLD, NEW]; OLD is lost
    assert c.deliver(envs[1]) == b"OK"                              # the newer one is applied first
    assert [c.svc.on_status(r)[2] for r in c.proc.recover()] == [b"INTERRUPTED"]
    assert c.applied == [b"NEW"]                                    # OLD never undoes NEW


# ======================================================================================= GRANT / SETPOINT
def test_grant_then_setpoints_with_cumulative_ack(c: Ctl):
    gid, env = c.svc.grant(D1, TARGET, -5000, 5000, 12, 3600)
    assert c.deliver(env) == b"OK"
    for v in (1000, -2500, 4000):
        assert c.proc.on_control(c.topic, c.svc.setpoint(D1, gid, v, 30)) is None
    assert c.sps == [(TARGET, 1000), (TARGET, -2500), (TARGET, 4000)]
    assert c.svc.on_status(c.proc.setpoint_ack())[2] == b"OK"


def test_VG1_forged_grant_is_rejected(c: Ctl):
    s = c.w.utility.session_for(D1)
    g = Grant((c.svc.epoch << 32) | 50, b"g" * 8, s.sid, TARGET, -10 ** 9, 10 ** 9, 12, int(c.w.t),
              int(c.w.t) + 3600, b"")
    g = dataclasses.replace(g, sig=mldsa_sign(mldsa_keygen(), grant_signed_input(D1, c.topic, g)))
    assert c.deliver(seal_control(c.w.policy, s, c.topic, encode(g))) == b"REJECTED:signature"


def test_VG2_grant_from_another_session_is_rejected(c: Ctl):
    gid, _ = c.svc.grant(D1, TARGET, 0, 100, 12, 3600)              # issued for session X, never delivered
    g = c.svc._grants[c.w.utility.session_for(D1).sid][gid]
    c.reconnect()                                                    # session Y
    env = seal_control(c.w.policy, c.w.utility.session_for(D1), c.topic, encode(g))
    assert c.deliver(env) == b"REJECTED:sid"


def test_VG3_setpoint_without_a_live_grant(c: Ctl):
    s = c.w.utility.session_for(D1)
    env = seal_control(c.w.policy, s, c.topic, encode(Setpoint(os.urandom(8), 10, int(c.w.t) + 30)))
    assert c.deliver(env) == b"REJECTED:no-grant"
    gid, genv = c.svc.grant(D1, TARGET, 0, 100, 12, 3600)
    c.deliver(genv)
    c.reconnect()                                                    # the GRANT died with its session
    with pytest.raises(CommandError):
        c.svc.setpoint(D1, gid, 10, 30)
    env = seal_control(c.w.policy, c.w.utility.session_for(D1), c.topic, encode(Setpoint(gid, 10, int(c.w.t) + 30)))
    assert c.deliver(env) == b"REJECTED:no-grant" and c.sps == []


def _raw_setpoint(c: Ctl, gid, value, ttl=30):
    return seal_control(c.w.policy, c.w.utility.session_for(D1), c.topic, encode(Setpoint(gid, value, int(c.w.t) + ttl)))


def test_VG4_bounds_rate_and_time(c: Ctl):
    gid, genv = c.svc.grant(D1, TARGET, -100, 100, 12, 600)
    c.deliver(genv)
    assert c.deliver(_raw_setpoint(c, gid, 101)) == b"REJECTED:bounds"
    assert c.deliver(_raw_setpoint(c, gid, -101)) == b"REJECTED:bounds"
    results = [c.proc.on_control(c.topic, c.svc.setpoint(D1, gid, 1, 30)) for _ in range(13)]
    assert results[:12] == [None] * 12
    assert c.svc.on_status(results[12])[2] == b"REJECTED:rate"        # 13th within 60 s
    c.w.t += 60
    assert c.proc.on_control(c.topic, c.svc.setpoint(D1, gid, 2, 30)) is None     # the window moved on
    assert c.deliver(_raw_setpoint(c, gid, 3, ttl=0)) == b"REJECTED:time"         # the set-point expired
    c.w.t += 600
    assert c.deliver(_raw_setpoint(c, gid, 3)) == b"REJECTED:time"                # the GRANT expired
    assert len(c.sps) == 13


def test_utility_grant_memory_is_bounded_by_live_grants(c: Ctl):
    """Resource bound: each GRANT holds a 3,309-B signature. The utility forgets GRANTs of a device's earlier
    sessions (they died with their session, §13.4) and GRANTs expired beyond the device-clock slack, when it issues
    the next one. Before the fix every GRANT ever issued stayed in RAM (hourly GRANTs: ~570 KB per device per week)."""
    from pqgrid.commands.utility import GRANT_CLOCK_SLACK_S
    for _ in range(5):                                               # five sessions, one GRANT each
        gid, genv = c.svc.grant(D1, TARGET, 0, 100, 12, 3600)
        assert c.deliver(genv) == b"OK"
        c.reconnect()
    live = c.w.utility.session_for(D1)
    gid, genv = c.svc.grant(D1, TARGET, 0, 100, 12, 60)
    assert c.deliver(genv) == b"OK"
    assert list(c.svc._grants) == [live.sid]                         # only the live session's GRANTs remain
    for _ in range(20):                                              # one session, a short GRANT every hour
        c.w.t += 3600
        gid, genv = c.svc.grant(D1, TARGET, 0, 100, 12, 60)
        assert c.deliver(genv) == b"OK"
    assert list(c.svc._grants[live.sid]) == [gid]                    # the expired ones were dropped
    c.w.t += 60                                                      # just expired, inside the clock slack: kept,
    assert c.deliver(c.svc.setpoint(D1, gid, 5, 30)) == b"REJECTED:time"   # so the device still decides (E56)
    g2, genv = c.svc.grant(D1, TARGET, 0, 50, 12, 3600)             # a replaced but unexpired GRANT stays usable
    assert c.deliver(genv) == b"OK" and gid in c.svc._grants[live.sid]
    c.w.t += GRANT_CLOCK_SLACK_S
    c.svc.grant(D1, TARGET, 0, 50, 12, 3600)
    assert gid not in c.svc._grants[live.sid] and g2 in c.svc._grants[live.sid]

def test_grant_not_yet_valid(c: Ctl):
    gid, genv = c.svc.grant(D1, TARGET, 0, 100, 12, 3600, not_before=int(c.w.t) + 300)
    assert c.deliver(genv) == b"OK"
    assert c.deliver(_raw_setpoint(c, gid, 5)) == b"REJECTED:time"
    c.w.t += 300
    assert c.proc.on_control(c.topic, _raw_setpoint(c, gid, 5)) is None


def test_VG5_replayed_setpoint_is_dropped(c: Ctl):
    gid, genv = c.svc.grant(D1, TARGET, 0, 100, 12, 3600)
    c.deliver(genv)
    env = c.svc.setpoint(D1, gid, 50, 30)
    c.proc.on_control(c.topic, env)
    c.proc.on_control(c.topic, c.svc.setpoint(D1, gid, 60, 30))
    with pytest.raises(ReplayError):
        c.proc.on_control(c.topic, env)                             # the older value never comes back (C7)
    assert c.sps == [(TARGET, 50), (TARGET, 60)]


def test_VG6_broker_forged_setpoint_fails_aead(c: Ctl):
    gid, genv = c.svc.grant(D1, TARGET, 0, 100, 12, 3600)
    c.deliver(genv)
    f = dec(c.svc.setpoint(D1, gid, 50, 30), 4)
    f[3] = f[3][:-1] + bytes([f[3][-1] ^ 1])
    with pytest.raises(EnvelopeError):
        c.proc.on_control(c.topic, enc(f))
    assert c.sps == []


def test_grant_rules_newest_wins_dup_target_and_rate_cap(c: Ctl):
    s = c.w.utility.session_for(D1)
    g1, e1 = c.svc.grant(D1, TARGET, 0, 100, 12, 3600)
    g2, e2 = c.svc.grant(D1, TARGET, 0, 50, 6, 3600)
    assert c.deliver(e1) == b"OK" and c.deliver(e2) == b"OK"
    old = c.svc._grants[s.sid][g1]
    assert c.deliver(seal_control(c.w.policy, s, c.topic, encode(old))) == b"SUPERSEDED"
    new = c.svc._grants[s.sid][g2]
    assert c.deliver(seal_control(c.w.policy, s, c.topic, encode(new))) == b"DUP"
    assert c.deliver(_raw_setpoint(c, g1, 10)) == b"REJECTED:no-grant"      # replaced
    _, e3 = c.svc.grant(D1, "Q_VAR", 0, 10, 1, 3600)
    assert c.deliver(e3) == b"REJECTED:target"
    with pytest.raises(CommandError):
        c.svc.grant(D1, TARGET, 0, 10, 13, 3600)                    # above the class max_setpoint_rate
    over = Grant((c.svc.epoch << 32) | 777, b"o" * 8, s.sid, TARGET, 0, 10, 13, int(c.w.t), int(c.w.t) + 60, b"")
    over = dataclasses.replace(over, sig=mldsa_sign(c.w.cmd_sk, grant_signed_input(D1, c.topic, over)))
    assert c.deliver(seal_control(c.w.policy, s, c.topic, encode(over))) == b"REJECTED:bounds"


# ===================================================================================== class gating (E32)
def test_E32_classes_without_unicast_control_get_no_commands(world: World):
    meter = world.device(M1, "smart_meter")
    world.full(meter)
    svc = CommandService(world.utility, world.cmd_sk)
    with pytest.raises(CommandError):
        svc.issue(M1, b"TRIP", 60)
    proc = CommandProcessor(meter, lambda cmd: None, state=DeviceCommandState())
    topic = control_topic("smart_meter", M1)
    seq, exp = (svc.epoch << 32) | 1, int(world.t) + 60
    cmd = Command(seq, b"TRIP", exp, False, mldsa_sign(world.cmd_sk, cmd_signed_input(M1, topic, seq, exp, False, b"TRIP")))
    ack = proc.on_control(topic, seal_control(world.policy, world.utility.session_for(M1), topic, encode(cmd)))
    assert svc.on_status(ack)[2] == b"REJECTED:not-allowed"


def test_E32_cmd_types_without_the_unicast_control_flag_is_refused(world: World):
    world.utility.policy = make_policy(world.u_static.pk, mldsa_public_bytes(world.cmd_sk),
                                       classes=replace_class(world.policy, "smart_meter",
                                                             cmd_types=frozenset({CmdType.CMD})))
    world.device(M1, "smart_meter")                                  # registered; no live session needed
    with pytest.raises(CommandError, match="does not accept CMD"):
        CommandService(world.utility, world.cmd_sk).issue(M1, b"TRIP", 60)


# =============================================================================================== status
def test_status_ack_is_authenticated_and_session_bound(c: Ctl):
    c.issue()
    ack = c.proc.on_control(c.topic, c.svc.outgoing(D1)[0])
    f = dec(ack, 6)
    f[4] = b"DUP"                                                    # broker rewrites OK → DUP
    with pytest.raises(EnvelopeError, match="forged"):
        c.svc.on_status(enc(f))
    f = dec(ack, 6)
    f[3] = (int.from_bytes(f[3], "big") + 1).to_bytes(8, "big")      # … or points it at another command (DR-045)
    with pytest.raises(EnvelopeError, match="forged"):
        c.svc.on_status(enc(f))
    c.reconnect()
    with pytest.raises(EnvelopeError, match="unknown session"):
        c.svc.on_status(ack)                                         # the old session is gone
    assert c.pump() == [b"DUP"]                                      # the redelivery settles it truthfully


# ============================================================================================ zones / DR
ZN = "feeder7"
ZT = event_topic(ZN, AeadAlg.CHACHA20POLY1305)                      # der_ctrl is a ChaCha class


@pytest.fixture
def z(c: Ctl):
    zm = ZoneManager(c.svc)
    zm.create(ZN)
    zm.add_member(ZN, D1)
    assert c.deliver(zm.distribute(ZN)[D1]) == b"OK"
    return zm


def ev(z: ZoneManager, payload: bytes, ttl: int) -> bytes:
    """The ChaCha group's publication of one new logical event."""
    return z.publish(ZN, payload, ttl)[ZT]


def test_dr_event_delivered_to_member(c: Ctl, z: ZoneManager):
    assert c.proc.zones.open(ZT, ev(z, b"SHED 20%", 300)) == b"SHED 20%"


def test_A11_member_forges_an_event_and_replays_one(c: Ctl, z: ZoneManager):
    group = z.zones[ZN].groups[AeadAlg.CHACHA20POLY1305]
    e = ev(z, b"SHED 20%", 300)
    assert c.proc.zones.open(ZT, e)
    with pytest.raises(ReplayError, match="broadcast replay"):
        c.proc.zones.open(ZT, e)
    from pqgrid.commands.zones import seal_event
    bseq, exp = (c.svc.epoch << 32) | 99, int(c.w.t) + 300                # a member holds K_group …
    sig = mldsa_sign(mldsa_keygen(), bcast_signed_input(ZN, bseq, exp, b"SHED 100%"))
    forged = seal_event(ZN, AeadAlg.CHACHA20POLY1305, group.key_epoch, group.key, bseq, exp, b"SHED 100%", sig)
    with pytest.raises(EnvelopeError, match="signature invalid"):   # … but not the command key
        c.proc.zones.open(ZT, forged)


def test_EZ1_removed_member_cannot_read_the_new_epoch(world: World, c: Ctl, z: ZoneManager):
    other = Ctl(world, D2, svc=c.svc)
    z.add_member(ZN, D2)
    for did, env in z.distribute(ZN).items():
        (c if did == D1 else other).deliver(env)
    z.remove_member(ZN, D1)
    assert list(z.distribute(ZN)) == [D2]
    other.deliver(z.distribute(ZN)[D2])
    e = ev(z, b"SHED", 300)
    assert other.proc.zones.open(ZT, e) == b"SHED"
    with pytest.raises(EnvelopeError, match="no key for zone/epoch"):
        c.proc.zones.open(ZT, e)


def test_VZ1_broker_cannot_forge_a_zonekey(c: Ctl, z: ZoneManager):
    f = dec(z.distribute(ZN)[D1], 4)
    f[3] = f[3][:-1] + bytes([f[3][-1] ^ 1])
    with pytest.raises(EnvelopeError):
        c.proc.on_control(c.topic, enc(f))


def test_DR047_amended_mixed_aead_members_form_separate_crypto_groups(world: World, c: Ctl, z: ZoneManager):
    """Clarification 4: an AES meter joins the same LOGICAL zone in its own AES group; a device still refuses a
    ZONEKEY for an AEAD other than its class's."""
    world.device(M1, "smart_meter")
    z.add_member(ZN, M1)
    assert set(z.zones[ZN].groups) == {AeadAlg.CHACHA20POLY1305, AeadAlg.AES256GCM}
    assert z.members_of(ZN, AeadAlg.AES256GCM) == [M1] and z.members_of(ZN, AeadAlg.CHACHA20POLY1305) == [D1]
    s = world.utility.session_for(D1)
    foreign = ZoneKey(ZN, 1, AeadAlg.AES256GCM, os.urandom(32))
    assert c.deliver(seal_control(world.policy, s, c.topic, encode(foreign))) == b"REJECTED:aead"


def test_DR048_rebooted_device_refuses_replays_but_accepts_queued_events(c: Ctl, z: ZoneManager):
    seen = ev(z, b"E1", 600)
    assert c.proc.zones.open(ZT, seen)
    c.reboot()                                                      # zone keys (RAM) lost; last bseq kept
    queued = ev(z, b"RESTORE: stagger load", 600)                   # issued while the device was down
    for env in z.zonekeys_for(D1):
        assert c.deliver(env) == b"OK"
    with pytest.raises(ReplayError):
        c.proc.zones.open(ZT, seen)
    assert c.proc.zones.open(ZT, queued) == b"RESTORE: stagger load"


def test_DR048_utility_restart_does_not_turn_new_events_into_replays(c: Ctl, z: ZoneManager):
    assert c.proc.zones.open(ZT, ev(z, b"E1", 600))
    c.w.t += 5
    z.svc = CommandService(c.w.utility, c.w.cmd_sk, store=c.svc.store)    # restart: new epoch
    z.zones[ZN].counter = 0                                                # the RAM counter is lost
    assert c.proc.zones.open(ZT, ev(z, b"E2", 600)) == b"E2"


def test_event_after_rotation_under_the_previous_key_still_opens(c: Ctl, z: ZoneManager):
    in_flight = ev(z, b"E1", 600)
    z.rotate(ZN)
    c.deliver(z.distribute(ZN)[D1])
    assert c.proc.zones.open(ZT, in_flight) == b"E1"


def test_expired_event_is_refused(c: Ctl, z: ZoneManager):
    e = ev(z, b"E1", 60)
    c.w.t += 61
    with pytest.raises(EnvelopeError, match="expired"):
        c.proc.zones.open(ZT, e)
    assert c.proc.zones.open(ZT, ev(z, b"E2", 60)) == b"E2"          # expiry did not burn bseq


def test_event_on_another_zones_or_groups_topic_is_refused(c: Ctl, z: ZoneManager):
    e = ev(z, b"E1", 60)
    for wrong in (event_topic("feeder8", AeadAlg.CHACHA20POLY1305), event_topic(ZN, AeadAlg.AES256GCM)):
        with pytest.raises(EnvelopeError, match="not a broadcast for this topic"):
            c.proc.zones.open(wrong, e)
    assert c.proc.zones.open(ZT, e) == b"E1"


def test_E56_grant_tolerates_a_device_clock_lagging_by_one_transit(c: Ctl):
    """The device sets its clock from SH/RS time, so it lags the utility by up to one message transit plus the
    rounding to whole seconds. A GRANT starting at the utility's 'now' would be refused for that long."""
    c.d.offset -= 2                                                    # the device is 2 s behind the utility
    gid, genv = c.svc.grant(D1, TARGET, 0, 100, 12, 3600)
    assert c.deliver(genv) == b"OK"
    assert c.proc.on_control(c.topic, c.svc.setpoint(D1, gid, 5, 30)) is None
    assert c.sps == [(TARGET, 5)]


def test_clarification3_supersession_is_checked_before_expiry(c: Ctl):
    """APPLIED → DUP, PENDING → INTERRUPTED, then SUPERSEDED, then EXPIRED: a redelivered command that is both
    older than the last applied one and expired is SUPERSEDED (the audit's probe scenario)."""
    c.issue(b"A", ttl=60)
    c.svc.outgoing(D1)                                               # A lost in transit
    c.issue(b"B", ttl=600)
    assert c.pump() == [b"OK"]                                       # B applied
    c.reconnect()
    [env] = c.svc.outgoing(D1)                                       # A redelivered while still valid …
    c.w.t += 120                                                     # … arrives after it expired
    assert c.deliver(env) == b"SUPERSEDED" and c.applied == [b"B"]


# ============================================================================ mutation-found gaps (C1-9)
def test_control_is_sealed_and_opened_only_for_its_own_device_on_a_control_tier_topic(c: Ctl, world: World):
    """§11: the sealer and the receiver check, from their OWN policy, that the topic is CONTROL tier and that the
    topic's device owns the session. (The AEAD's topic binding would also refuse a moved envelope, which masked the
    explicit checks in every earlier test.)"""
    from pqgrid.e2e.envelopes import open_control
    from pqgrid.policy import Rule, Tier
    s = world.utility.session_for(D1)
    with pytest.raises(EnvelopeError, match="another device"):
        seal_control(world.policy, s, control_topic("der_ctrl", D2), b"x")
    env = seal_control(world.policy, s, c.topic, b"x")
    with pytest.raises(EnvelopeError, match="another device"):
        open_control(world.policy, c.d.session, control_topic("der_ctrl", D2), env)
    weak = make_policy(world.u_static.pk, mldsa_public_bytes(world.cmd_sk), rules=(Rule("grid/#", Tier.TELEMETRY),))
    with pytest.raises(EnvelopeError, match="not CONTROL tier"):
        seal_control(weak, s, c.topic, b"x")
    with pytest.raises(EnvelopeError, match="not CONTROL tier"):
        open_control(weak, c.d.session, c.topic, env)


def test_a_status_with_an_unknown_token_is_refused_even_under_a_valid_mac(c: Ctl):
    """DR-045: only the defined statuses settle a command; a device (or its key holder) cannot write another."""
    from pqgrid.e2e.envelopes import T_STATUS
    from pqgrid.suite.kdf import mac
    from pqgrid.wire import u64
    seq = c.issue()
    s = c.d.session
    body = [s.sid, u64(1), u64(seq), b"PROBABLY"]
    with pytest.raises(EnvelopeError, match="unknown status"):
        c.svc.on_status(enc([T_STATUS, *body, mac(s.key("ACK", "up"), b"".join(body))]))
    assert c.svc.outcome(D1, seq) is None and c.pump() == [b"OK"]


def test_setpoints_refused_for_a_class_that_allows_grants_but_not_setpoints(world: World):
    world.policy = make_policy(world.u_static.pk, mldsa_public_bytes(world.cmd_sk),
                               classes=replace_class(world.policy, "der_ctrl",
                                                     cmd_types=frozenset({CmdType.CMD, CmdType.GRANT})))
    world.utility.policy = world.policy
    c = Ctl(world)
    gid, genv = c.svc.grant(D1, TARGET, 0, 100, 12, 3600)
    assert c.deliver(genv) == b"OK"
    with pytest.raises(CommandError, match="does not accept SETPOINT"):
        c.svc.setpoint(D1, gid, 5, 30)                                    # the utility will not send it …
    assert c.deliver(_raw_setpoint(c, gid, 5)) == b"REJECTED:not-allowed"  # … and the device refuses it anyway
    assert c.sps == []


def test_an_oversized_signed_command_is_refused_before_anything_is_written(c: Ctl):
    """E44: a PENDING intent must fit one flash record. The utility never issues a body above MAX_COMMAND; a signed
    one that is larger anyway is refused as malformed: nothing actuated, no intent written."""
    from pqgrid.commands.device import MAX_COMMAND
    seq, exp, body = (c.svc.epoch << 32) | 99, int(c.w.t) + 60, b"x" * (MAX_COMMAND + 1)
    cmd = Command(seq, body, exp, False, mldsa_sign(c.w.cmd_sk, cmd_signed_input(D1, c.topic, seq, exp, False, body)))
    s = c.w.utility.session_for(D1)
    assert c.deliver(seal_control(c.w.policy, s, c.topic, encode(cmd))) == b"REJECTED:malformed"
    assert c.applied == [] and c.state.pending == {} and c.state.last_applied == 0
    with pytest.raises(CommandError, match="larger than"):
        c.svc.issue(D1, body, 60)


def test_an_interrupted_idempotent_command_is_not_reapplied_after_it_expired(c: Ctl):
    """§13.7: re-applied only if idempotent, UNEXPIRED and still the newest; otherwise reported INTERRUPTED."""
    seq = c.issue(b"SET_MODE", ttl=300, idem=True)
    env = c.svc.outgoing(D1)[0]
    c.proc.actuate = lambda cmd: (_ for _ in ()).throw(PowerLoss())
    with pytest.raises(PowerLoss):
        c.proc.on_control(c.topic, env)
    c.w.t += 300                                                     # power back only after it expired
    c.reboot()
    assert [c.svc.on_status(r)[2] for r in c.proc.recover()] == [b"INTERRUPTED"]
    assert c.applied == [] and c.svc.outcome(D1, seq) == b"INTERRUPTED"


def test_the_utility_refuses_a_setpoint_outside_its_grant(c: Ctl):
    gid, genv = c.svc.grant(D1, TARGET, 0, 100, 12, 3600)
    assert c.deliver(genv) == b"OK"
    for bad in (101, -1):
        with pytest.raises(CommandError, match="outside the GRANT bounds"):
            c.svc.setpoint(D1, gid, bad, 30)
    assert c.proc.on_control(c.topic, c.svc.setpoint(D1, gid, 100, 30)) is None and c.sps == [(TARGET, 100)]
