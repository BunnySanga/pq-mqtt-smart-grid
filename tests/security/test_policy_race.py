"""Remediation M1: a policy activated between SH/RS and DF. The session was derived under the old POLICY_INFO,
so at DF it is not installed, the bundled alerts are not opened and no ticket is issued; the device must
handshake under the current policy (Master §12 Policy Updates, P5, P10). Activation also closes every
old-policy session: no command, zone key or status is accepted under one afterwards."""
import os

import pytest

from conftest import World, make_policy
from pqgrid.commands import CommandProcessor, CommandService
from pqgrid.commands.device import DeviceCommandState
from pqgrid.commands.zones import ZoneManager
from pqgrid.e2e.envelopes import alert_topic, control_topic
from pqgrid.errors import CommandError, EnvelopeError, HandshakeError
from pqgrid.suite.sig import mldsa_public_bytes

D1 = b"der-0001"
T1 = alert_topic("der_ctrl", D1)


def v2(world: World):
    return make_policy(world.u_static.pk, mldsa_public_bytes(world.cmd_sk), version=2)


def count_tickets(world: World) -> list:
    issued, real = [], world.tickets.issue
    world.tickets.issue = lambda *a, **k: issued.append(a) or real(*a, **k)
    return issued


@pytest.mark.parametrize("resume", [False, True])
def test_M1_policy_activated_between_hello_and_DF_is_refused_at_DF(world: World, resume: bool):
    d = world.device(D1, "der_ctrl")
    if resume:
        world.full(d)                                               # a ticket of the old policy
        hello = world.utility.on_resume_hello(D1, d.resume_hello())
        d.on_resume_server(hello)
    else:
        d.on_server_hello(world.utility.on_client_hello(D1, d.client_hello()))
    before = dict(world.utility.sessions)
    issued = count_tickets(world)
    new = v2(world)
    world.utility.install_policy(new)                               # the race: activation lands here
    aid = os.urandom(16)
    df = d.finished([(T1, aid, b"SAG 190V")])
    with pytest.raises(HandshakeError, match="policy changed during the handshake"):
        world.utility.on_finished(D1, df)
    assert issued == []                                             # no ticket
    assert D1 not in world.utility._pending
    s = world.utility.session_for(D1)
    assert s is None or (s in before.values() and s.k_master == b"")    # nothing new installed; the old one closed
    with pytest.raises(HandshakeError, match="no pending handshake"):
        world.utility.on_finished(D1, df)                          # the identical DF resent: still nothing
    d.install_policy(new)                                           # the device installs v2 and handshakes again
    res, _ = world.full(d, alerts=[(T1, aid, b"SAG 190V")])
    assert res.alerts == [(aid, b"SAG 190V", False)]                # first delivery: the refused DF was never opened
    assert world.utility.current_session(D1).policy_info == new.info() and len(issued) == 1


def test_M1_activation_closes_old_sessions_for_commands_zone_keys_status_and_alerts(world: World):
    d = world.device(D1, "der_ctrl")
    world.full(d)
    svc = CommandService(world.utility, world.cmd_sk)
    zones = ZoneManager(svc)
    zones.create("feeder7")
    zones.add_member("feeder7", D1)
    proc = CommandProcessor(d, lambda cmd: None, state=DeviceCommandState())
    topic = control_topic("der_ctrl", D1)
    seq = svc.issue(D1, b"TRIP", 600)
    [env] = svc.outgoing(D1)
    ack = proc.on_control(topic, env)                               # executed; its status is still in flight
    old = world.utility.session_for(D1)
    assert world.utility.install_policy(v2(world)) == 1 and old.k_master == b""
    with pytest.raises(EnvelopeError, match="old policy"):
        svc.on_status(ack)
    with pytest.raises(EnvelopeError, match="old policy"):
        world.utility.open_alert(T1, d.seal_alert(T1, os.urandom(16), b"x"))
    assert svc.outgoing(D1) == [] and zones.zonekeys_for(D1) == [] and zones.distribute("feeder7") == {}
    with pytest.raises(CommandError, match="no live session under the current policy"):
        svc.grant(D1, "P_ACTIVE_W", 0, 10, 1, 60)
    assert svc.outcome(D1, seq) is None                              # not settled from an old-policy session
    d.install_policy(world.utility.policy)
    world.full(d)
    [again] = svc.outgoing(D1)                                      # redelivered under the v2 session
    svc.on_status(proc.on_control(topic, again))
    assert svc.outcome(D1, seq) == b"DUP" and svc.alarms == []       # already applied: learned, not re-actuated
    assert len(zones.zonekeys_for(D1)) == 1
