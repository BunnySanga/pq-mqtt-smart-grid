"""Remediation M2: a live session ends with its chain (Master §9.7, §9.4; glossary "Ticket / chain": one full
handshake plus the resumptions that follow it, ≤ max_chain_age_s). Exactly at chain_expires the utility refuses
data under the session and removes it, the device drops the session and its same-chain ticket, and only a full
handshake remains; that full handshake starts a NEW chain and is never limited by the old one."""
import os

import pytest

from conftest import World, make_policy, replace_class
from pqgrid.commands import CommandProcessor, CommandService
from pqgrid.commands.device import DeviceCommandState
from pqgrid.e2e.envelopes import alert_topic, control_topic
from pqgrid.e2e.handshake import UnknownSessionError, UtilityEndpoint
from pqgrid.errors import CommandError, EnvelopeError, HandshakeError, TicketError
from pqgrid.policy import ResumeMode
from pqgrid.suite.sig import mldsa_public_bytes

D1 = b"der-0001"
T1, CTL = alert_topic("der_ctrl", D1), control_topic("der_ctrl", D1)
CHAIN, LIFETIME = 1000, 600


def chain_world() -> World:
    world = World()
    world.policy = make_policy(world.u_static.pk, mldsa_public_bytes(world.cmd_sk),
                               classes=replace_class(world.policy, "der_ctrl", ticket_lifetime_s=LIFETIME,
                                                     max_chain_age_s=CHAIN))
    world.utility = UtilityEndpoint(world.policy, world.u_static, world.registry, clock=lambda: world.t,
                                    tickets=world.tickets)
    return world


def test_M2_resumed_session_ends_exactly_at_its_chain_expiry():
    world = chain_world()
    t0, actuated = world.t, []
    d = world.device(D1, "der_ctrl")
    world.full(d)
    world.t = t0 + 500
    world.resume(d)                                                  # the resumed session inherits the chain
    s = world.utility.session_for(D1)
    assert s.resume_mode is ResumeMode.PSK_KEM and s.chain_expires == d.session.chain_expires == t0 + CHAIN
    svc = CommandService(world.utility, world.cmd_sk)
    proc = CommandProcessor(d, actuated.append, state=DeviceCommandState())
    world.t = t0 + CHAIN - 1                                         # one second before: everything works
    world.utility.open_alert(T1, d.seal_alert(T1, os.urandom(16), b"in time"))
    first = svc.issue(D1, b"TRIP", 600)
    [env] = svc.outgoing(D1)
    svc.on_status(proc.on_control(CTL, env))
    assert svc.outcome(D1, first) == b"OK"
    late = svc.issue(D1, b"LATE", 600)
    [late_env] = svc.outgoing(D1)                                    # sealed before the end, arrives after it
    late_alert = d.seal_alert(T1, os.urandom(16), b"sealed in time")
    stale_ticket = d.ticket
    world.t = t0 + CHAIN                                             # the boundary itself
    with pytest.raises(UnknownSessionError, match="chain expired") as hint:
        world.utility.open_alert(T1, late_alert)
    assert world.utility.session_for(D1) is None and s.k_master == b""
    assert svc.outgoing(D1) == []
    with pytest.raises(CommandError, match="no live session"):
        svc.grant(D1, "P_ACTIVE_W", 0, 10, 1, 60)
    with pytest.raises(EnvelopeError, match="chain expired"):
        proc.on_control(CTL, late_env)
    assert d.session is None and d.ticket is None and not d.can_resume() and actuated == [b"TRIP"]
    d.ticket = stale_ticket                                          # a copy of the same-chain ticket
    with pytest.raises(TicketError, match="ticket expired"):
        world.utility.on_resume_hello(D1, d.resume_hello())
    d.ticket = None
    world.full(d)                                                    # full handshake: a new chain
    assert world.utility.session_for(D1).chain_expires == d.session.chain_expires == t0 + 2 * CHAIN
    [again] = svc.outgoing(D1)                                       # LATE redelivered under the new session
    svc.on_status(proc.on_control(CTL, again))
    assert svc.outcome(D1, late) == b"OK" and actuated == [b"TRIP", b"LATE"]
    assert hint.value.hint


def test_M2_full_handshake_session_ends_with_its_chain_and_a_status_after_it_is_refused():
    world = chain_world()
    t0 = world.t
    d = world.device(D1, "der_ctrl")
    world.full(d)
    svc = CommandService(world.utility, world.cmd_sk)
    proc = CommandProcessor(d, lambda c: None, state=DeviceCommandState())
    seq = svc.issue(D1, b"TRIP", 3600)
    [env] = svc.outgoing(D1)
    world.t = t0 + CHAIN - 1
    ack = proc.on_control(CTL, env)                                  # applied one second before the end
    world.t = t0 + CHAIN
    with pytest.raises(EnvelopeError, match="chain expired"):
        svc.on_status(ack)                                           # its status arrives at the end: refused
    assert world.utility.session_for(D1) is None and svc.outcome(D1, seq) is None
    with pytest.raises(EnvelopeError, match="chain expired"):
        d.seal_alert(T1, os.urandom(16), b"x")
    world.full(d)
    [again] = svc.outgoing(D1)
    svc.on_status(proc.on_control(CTL, again))
    assert svc.outcome(D1, seq) == b"DUP" and svc.alarms == []       # learned, not actuated twice


def test_M2_a_fresh_full_handshake_is_never_limited_by_an_old_chain():
    world = chain_world()
    t0 = world.t
    d = world.device(D1, "der_ctrl")
    world.full(d)
    world.t = t0 + CHAIN - 10
    d.ticket = None
    world.full(d)                                                    # a fresh handshake just before the end
    assert world.utility.session_for(D1).chain_expires == t0 + 2 * CHAIN - 10
    world.t = t0 + CHAIN + 10                                        # the OLD chain has ended; this one has not
    world.utility.open_alert(T1, d.seal_alert(T1, os.urandom(16), b"still fine"))
    world.resume(d)
    assert world.utility.session_for(D1).chain_expires == t0 + 2 * CHAIN - 10


def test_M2_device_with_a_lagging_clock_is_refused_then_recovers_through_the_resync_hint():
    world = chain_world()
    t0, lag = world.t, [0.0]
    d = world.device(D1, "der_ctrl", clock=lambda: world.t - lag[0])
    world.full(d)
    lag[0] = 5.0                                                     # the RTC falls 5 s behind after SH
    world.t = t0 + CHAIN
    env = d.seal_alert(T1, os.urandom(16), b"device thinks it is t0+995")
    with pytest.raises(UnknownSessionError, match="chain expired") as e:
        world.utility.open_alert(T1, env)
    assert d.on_resync_hint(e.value.hint) and d.can_resume()
    with pytest.raises(TicketError, match="ticket expired"):
        world.utility.on_resume_hello(D1, d.resume_hello())         # refused (not answered over MQTT: E49)
    d.ticket = None                                                  # the transport's fallback: full handshake
    world.full(d)
    assert world.utility.session_for(D1).chain_expires == t0 + 2 * CHAIN
    with pytest.raises(EnvelopeError, match="resync hint already sent"):
        world.utility.open_alert(T1, env)                            # the old sid again: no second hint in 30 s


def test_M2_chain_ending_between_RS_and_DF_installs_nothing():
    world = chain_world()
    t0 = world.t
    d = world.device(D1, "der_ctrl")
    world.full(d)
    world.t = t0 + 500
    world.resume(d)                                                  # its ticket now lasts to the chain end
    world.t = t0 + CHAIN - 1
    d.on_resume_server(world.utility.on_resume_hello(D1, d.resume_hello()))
    world.t = t0 + CHAIN
    issued, real = [], world.tickets.issue
    world.tickets.issue = lambda *a, **k: issued.append(a) or real(*a, **k)
    with pytest.raises(HandshakeError, match="chain expired"):
        world.utility.on_finished(D1, d.finished([(T1, os.urandom(16), b"x")]))
    assert issued == [] and world.utility.current_session(D1) is None
