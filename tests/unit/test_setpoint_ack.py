"""E-3 resolved (final remediation, Master §13.5): the cumulative SETPOINT ACK. One OK for the newest applied
SETPOINT, covering every earlier msg_seq of the session; due when ≥ 30 s have passed since the last one (the
boundary is inclusive), or at once when the GRANT of an unacknowledged SETPOINT ends (expiry or replacement): its
final ACK. A SETPOINT after the GRANT expired is refused and never acknowledged as applied. The step under test is
the main loop's own (_setpoint_ack_step); only the clocks and the publish are controlled."""
import ssl

from conftest import World
from pqgrid.commands import CommandProcessor, CommandService
from pqgrid.e2e.envelopes import control_topic
from pqgrid.mqtt import device_node
from pqgrid.mqtt.device_node import SETPOINT_ACK_EVERY_S, DeviceMqtt
from pqgrid.wire import dec, r64

D1, TARGET = b"der-0001", "P_ACTIVE_W"


class Rig:
    def __init__(self, world: World, monkeypatch):
        self.w, self.mono = world, [5000.0]
        monkeypatch.setattr(device_node.time, "monotonic", lambda: self.mono[0])
        self.d = world.device(D1, "der_ctrl")
        world.full(self.d)
        self.svc = CommandService(world.utility, world.cmd_sk)
        self.applied = []
        self.proc = CommandProcessor(self.d, lambda c: None, lambda t, v: self.applied.append(v), targets={TARGET})
        self.mq = DeviceMqtt(self.d, self.proc, None, ssl.create_default_context(), "localhost", 1)
        self.sent = []
        self.mq._publish = lambda topic, payload: self.sent.append(payload)
        self.topic = control_topic("der_ctrl", D1)

    def grant(self, ttl):
        gid, env = self.svc.grant(D1, TARGET, -5000, 5000, 12, ttl)
        assert dec(self.proc.on_control(self.topic, env), 6)[4] == b"OK"
        return gid

    def setpoint(self, gid, v):
        env = self.svc.setpoint(D1, gid, v, 30)
        return self.proc.on_control(self.topic, env), dec(env, 4)

    def advance(self, s):
        self.mono[0] += s
        self.w.t += s

    def step(self):
        n = len(self.sent)
        self.mq._setpoint_ack_step()
        return self.sent[n:]


def acked_msg_seq(ack: bytes) -> int:
    return r64(dec(ack, 6)[2])


def test_multiple_setpoints_within_the_interval_give_one_ack_for_the_newest(world: World, monkeypatch):
    r = Rig(world, monkeypatch)
    gid = r.grant(3600)
    r.setpoint(gid, 100)
    [first] = r.step()                                                    # nothing acknowledged yet: at once
    assert r.svc.on_status(first)[2] == b"OK"
    t_ack, seqs = r.mono[0], []
    for v in (200, 300, 400):
        r.advance(5)
        assert r.setpoint(gid, v)[0] is None                              # applied, no per-SETPOINT ACK
        seqs.append(r.proc.last_setpoint()[1])
        assert r.step() == []                                             # inside the interval
    r.mono[0] = t_ack + SETPOINT_ACK_EVERY_S - 0.001                      # 29.999 s after the first ACK
    assert r.step() == []
    r.mono[0] = t_ack + SETPOINT_ACK_EVERY_S                              # exactly 30 s: due (inclusive)
    [cum] = r.step()
    assert acked_msg_seq(cum) == seqs[-1] and r.svc.on_status(cum)[2] == b"OK"   # the newest, once
    assert r.step() == [] and r.applied == [100, 200, 300, 400]


def test_no_setpoint_is_applied_or_acknowledged_after_the_grant_expired(world: World, monkeypatch):
    r = Rig(world, monkeypatch)
    gid = r.grant(20)
    r.setpoint(gid, 100)
    r.step()
    r.advance(21)                                                         # the GRANT has expired
    status, _ = r.setpoint(gid, 999)
    assert dec(status, 6)[4] == b"REJECTED:time" and r.applied == [100]
    r.advance(SETPOINT_ACK_EVERY_S)
    assert r.step() == []                                                 # nothing new to acknowledge


def test_final_cumulative_ack_when_the_grant_expires_before_the_interval(world: World, monkeypatch):
    r = Rig(world, monkeypatch)
    gid = r.grant(20)
    r.setpoint(gid, 100)
    r.step()
    r.advance(5)
    r.setpoint(gid, 200)
    last = r.proc.last_setpoint()[1]
    r.advance(10)
    assert r.step() == []                                                 # 15 s: GRANT live, interval not due
    r.advance(5)                                                          # 20 s: the GRANT has ended
    [final] = r.step()                                                    # final ACK now, not at 30 s
    assert acked_msg_seq(final) == last and r.svc.on_status(final)[2] == b"OK"
    r.advance(SETPOINT_ACK_EVERY_S)
    assert r.step() == []                                                 # sent once


def test_final_cumulative_ack_when_a_newer_grant_replaces_it(world: World, monkeypatch):
    r = Rig(world, monkeypatch)
    old = r.grant(3600)
    r.setpoint(old, 100)
    r.step()
    r.advance(2)
    r.setpoint(old, 200)
    last = r.proc.last_setpoint()[1]
    r.advance(2)
    new = r.grant(3600)                                                   # a newer GRANT for the same target
    [final] = r.step()
    assert acked_msg_seq(final) == last
    r.advance(5)
    r.setpoint(new, 300)                                                  # under the new GRANT, 5 s later:
    assert r.step() == []                                                 # the interval applies again
