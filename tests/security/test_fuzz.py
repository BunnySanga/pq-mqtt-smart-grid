"""Corrupted messages into every slice-1 handler: each must be refused with a controlled error, never
accepted and never crash, and the genuine message must still work afterwards (Master §12, I-21)."""
import os
import random

import pytest

from conftest import World
from pqgrid.e2e.envelopes import alert_topic
from pqgrid.errors import EnvelopeError, HandshakeError, ReplayError, WireError

CONTROLLED = (HandshakeError, EnvelopeError, ReplayError, WireError)
N = 300


def mutations(base: bytes, rng: random.Random):
    for _ in range(N):
        b = bytearray(base)
        op = rng.randrange(4)
        if op == 0:
            for _ in range(rng.randrange(1, 4)):
                b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
        elif op == 1:
            del b[rng.randrange(1, len(b)):]
        elif op == 2:
            b += os.urandom(rng.randrange(1, 32))
        else:
            i = rng.randrange(len(b))
            b[i:i + 8] = os.urandom(8)
        if bytes(b) != base:
            yield bytes(b)


def refused(fn, msg) -> bool:
    try:
        fn(msg)
    except CONTROLLED:
        return True
    return False


@pytest.mark.parametrize("handler", ["client_hello", "server_hello", "finished", "alert"])
def test_corrupted_messages_are_refused_cleanly(world: World, handler):
    rng = random.Random(hash(handler) & 0xFFFF)
    d = world.device(b"meter-0770", "smart_meter")
    ch = d.client_hello()
    if handler == "client_hello":
        target, fn = ch, lambda m: world.utility.on_client_hello(d.id, m)
    else:
        sh = world.utility.on_client_hello(d.id, ch)
        if handler == "server_hello":
            target, fn = sh, d.on_server_hello
        else:
            d.on_server_hello(sh)
            topic = alert_topic("smart_meter", d.id)
            df = d.finished([(topic, os.urandom(16), b"queued")])
            if handler == "finished":
                target, fn = df, lambda m: world.utility.on_finished(d.id, m)
            else:
                d.on_final(world.utility.on_finished(d.id, df).final)
                target = d.seal_alert(topic, os.urandom(16), b"live")
                fn = lambda m: world.utility.open_alert(topic, m)   # noqa: E731
    count = 0
    for m in mutations(target, rng):
        assert refused(fn, m), f"{handler}: a corrupted message was accepted"
        count += 1
    assert count >= N * 0.9
    fn(target)                                   # the genuine message is still accepted afterwards


@pytest.mark.parametrize("handler,dclass", [("resume_hello", "smart_meter"), ("resume_hello", "der_ctrl"),
                                            ("resume_server", "der_ctrl"), ("resume_finished", "smart_meter"),
                                            ("new_ticket", "smart_meter")])
def test_corrupted_resume_messages_are_refused_cleanly(world: World, handler, dclass):
    """RH, RS, resume DF and NT. A refused RH must never consume the ticket: the genuine RH still works."""
    rng = random.Random(hash((handler, dclass)) & 0xFFFF)
    did = b"fuzz-0001"
    d = world.device(did, dclass)
    world.full(d)
    rh = d.resume_hello()
    if handler == "resume_hello":
        target, fn = rh, lambda m: world.utility.on_resume_hello(did, m)
    else:
        rs = world.utility.on_resume_hello(did, rh)
        if handler == "resume_server":
            target, fn = rs, d.on_resume_server
        else:
            d.on_resume_server(rs)
            df = d.finished([(alert_topic(dclass, did), os.urandom(16), b"queued")])
            if handler == "resume_finished":
                target, fn = df, lambda m: world.utility.on_finished(did, m)
            else:
                target, fn = world.utility.on_finished(did, df).final, d.on_final
    count = 0
    for m in mutations(target, rng):
        assert refused(fn, m), f"{handler}: a corrupted message was accepted"
        count += 1
    assert count >= N * 0.9
    fn(target)                                   # the genuine message is still accepted afterwards


@pytest.mark.parametrize("handler", ["control_cmd", "control_grant", "status", "broadcast"])
def test_corrupted_control_messages_are_refused_cleanly(world: World, handler):
    """CONTROL envelopes, status ACKs and DR broadcasts. A refused envelope never burns its msg_seq, a refused
    status never settles a command, and the genuine message is still accepted afterwards."""
    from pqgrid.commands import CommandProcessor, CommandService, ZoneManager, event_topic
    from pqgrid.e2e.envelopes import control_topic
    from pqgrid.suite.aead import AeadAlg
    rng = random.Random(hash(handler) & 0xFFFF)
    did = b"fuzz-der-1"
    d = world.device(did, "der_ctrl")
    world.full(d)
    svc = CommandService(world.utility, world.cmd_sk)
    proc = CommandProcessor(d, lambda c: None, lambda t, v: None, targets={"P_ACTIVE_W"})
    topic = control_topic("der_ctrl", did)
    if handler == "control_cmd":
        svc.issue(did, b"TRIP", 300)
        target, fn = svc.outgoing(did)[0], lambda m: proc.on_control(topic, m)
    elif handler == "control_grant":
        target, fn = svc.grant(did, "P_ACTIVE_W", 0, 100, 12, 3600)[1], lambda m: proc.on_control(topic, m)
    elif handler == "status":
        svc.issue(did, b"TRIP", 300)
        target, fn = proc.on_control(topic, svc.outgoing(did)[0]), svc.on_status
    else:
        zm = ZoneManager(svc)
        zm.create("z1")
        zm.add_member("z1", did)
        proc.on_control(topic, zm.distribute("z1")[did])
        zt = event_topic("z1", AeadAlg.CHACHA20POLY1305)
        target, fn = zm.publish("z1", b"SHED", 300)[zt], lambda m: proc.zones.open(zt, m)
    count = 0
    for m in mutations(target, rng):
        assert refused(fn, m), f"{handler}: a corrupted message was accepted"
        count += 1
    assert count >= N * 0.9
    fn(target)


@pytest.mark.parametrize("handler", ["zone_sync", "alert_ack", "resent_event", "setpoint", "zonekey", "fin"])
def test_corrupted_later_message_types_are_refused_cleanly(world: World, handler):
    """The message types added after slice 1 (E-2 ZONESYNC, re-sent DR events, SETPOINT, ZONEKEY, ALERT ACK, FIN):
    every corruption is refused with a controlled error, nothing else escapes, and the genuine message still works."""
    from pqgrid.commands import CommandProcessor, CommandService, ZoneManager
    from pqgrid.e2e.envelopes import control_topic, open_zone_sync, verify_alert_ack, zone_sync, zone_sync_sid
    rng = random.Random(hash(handler) & 0xFFFF)
    did = b"fuzz-der-2"
    if handler == "fin":
        world.utility.tickets = None
    d = world.device(did, "der_ctrl")
    if handler == "fin":
        d.on_server_hello(world.utility.on_client_hello(did, d.client_hello()))
        target, fn = world.utility.on_finished(did, d.finished()).final, d.on_final
    else:
        world.full(d)
        svc = CommandService(world.utility, world.cmd_sk)
        proc = CommandProcessor(d, lambda c: None, lambda t, v: None, targets={"P_ACTIVE_W"})
        topic = control_topic("der_ctrl", did)
        zm = ZoneManager(svc)
        zm.create("z1")
        zm.add_member("z1", did)
        s_u = world.utility.session_for(did)
        if handler == "zone_sync":
            def fn(m):                                   # what UtilityMqtt._zone_sync does with it
                if zone_sync_sid(m) != s_u.sid:
                    raise EnvelopeError("zone sync outside the device's current session")
                return open_zone_sync(s_u, m)
            target = zone_sync(d.session, "z1", 1)
        elif handler == "alert_ack":
            topic_a = alert_topic("der_ctrl", did)
            ack = world.utility.open_alert(topic_a, d.seal_alert(topic_a, os.urandom(16), b"x"))[1]
            target, fn = ack, lambda m: verify_alert_ack(d.session, m)
        elif handler == "resent_event":
            proc.on_control(topic, zm.distribute("z1")[did])
            zm.publish("z1", b"SHED", 300)
            key, target = zm.sync_for(did, "z1")
            proc.on_control(topic, key)
            fn = proc.zones.open_resent
        elif handler == "setpoint":
            gid, genv = svc.grant(did, "P_ACTIVE_W", 0, 100, 12, 3600)
            proc.on_control(topic, genv)
            target, fn = svc.setpoint(did, gid, 5, 30), lambda m: proc.on_control(topic, m)
        else:
            target, fn = zm.distribute("z1")[did], lambda m: proc.on_control(topic, m)
    count = 0
    for m in mutations(target, rng):
        assert refused(fn, m), f"{handler}: a corrupted message was accepted"
        count += 1
    assert count >= N * 0.9
    fn(target)                                   # the genuine message is still accepted afterwards
