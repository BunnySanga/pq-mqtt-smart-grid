"""Live revocation (remediation H1): a revoked device loses everything at once, independently of the broker ACL.
Durable first; then sessions, half-open state, commands, status ACKs and zone membership (with new zone keys)."""
import os

import pytest

from conftest import World
from pqgrid.commands import CommandProcessor, CommandService, ZoneManager, event_topic
from pqgrid.e2e.envelopes import alert_topic, control_topic
from pqgrid.errors import CommandError, EnvelopeError, HandshakeError
from pqgrid.suite.aead import AeadAlg

D1, D2 = b"der-0001", b"der-0002"


def setup(world: World):
    svc = CommandService(world.utility, world.cmd_sk)
    d1, d2 = world.device(D1, "der_ctrl"), world.device(D2, "der_ctrl")
    world.full(d1)
    world.full(d2)
    p1, p2 = CommandProcessor(d1, lambda c: None), CommandProcessor(d2, lambda c: None)
    zm = ZoneManager(svc)
    zm.create("f7")
    for did, p in ((D1, p1), (D2, p2)):
        zm.add_member("f7", did)
    for did, p in ((D1, p1), (D2, p2)):
        p.on_control(control_topic("der_ctrl", did), zm.distribute("f7")[did])
    return svc, d1, d2, p1, p2, zm


def test_revoked_device_live_session_is_refused_everywhere(world: World):
    svc, d1, d2, p1, p2, zm = setup(world)
    seq = svc.issue(D1, b"TRIP", 300)
    [env] = svc.outgoing(D1)
    ack = p1.on_control(control_topic("der_ctrl", D1), env)              # a status ACK in flight
    t1 = alert_topic("der_ctrl", D1)
    before = d1.seal_alert(t1, os.urandom(16), b"sealed before revocation")
    assert world.utility.revoke_device(D1) == 1
    with pytest.raises(EnvelopeError, match="revoked"):
        world.utility.open_alert(t1, before)                              # ALERT on the old live session
    with pytest.raises(EnvelopeError, match="revoked|unknown session"):
        svc.on_status(ack)                                                # CONTROL status ACK
    assert svc.outcome(D1, seq) is None
    with pytest.raises(CommandError, match="revoked"):
        svc.issue(D1, b"CLOSE", 300)                                      # no new commands
    assert world.utility.session_for(D1) is None and D1 not in world.utility._pending
    assert world.utility.session_for(D2) is not None                      # other devices untouched


def test_revocation_removes_the_device_from_zones_and_rotates_their_keys(world: World):
    svc, d1, d2, p1, p2, zm = setup(world)
    group = zm.zones["f7"].groups[AeadAlg.CHACHA20POLY1305]
    old_epoch, zt = group.key_epoch, event_topic("f7", AeadAlg.CHACHA20POLY1305)
    world.utility.revoke_device(D1)
    assert zm.remove_device(D1) == ["f7"]
    assert D1 not in zm.zones["f7"].members and group.key_epoch > old_epoch
    p2.on_control(control_topic("der_ctrl", D2), zm.distribute("f7")[D2])   # the remaining member re-keyed
    ev = zm.publish("f7", b"SHED 20%", 600)[zt]
    assert p2.zones.open(zt, ev) == b"SHED 20%"
    with pytest.raises(EnvelopeError, match="no key"):
        p1.zones.open(zt, ev)                                             # the revoked member cannot read it
    assert zm.resend_for(D1) == []                                        # and nothing is re-sent to it
    assert D1 not in zm.distribute("f7")                                   # no new key for the revoked device
    with pytest.raises(CommandError, match="revoked"):
        svc.seal_for(D1, b"x")                                             # nothing can be sealed for it


def test_revoked_device_cannot_handshake_or_resume_even_from_the_duplicate_cache(world: World):
    d = world.device(D1, "der_ctrl")
    world.full(d)
    rh = d.resume_hello()
    world.utility.on_resume_hello(D1, rh)                                # cached RS
    world.utility.revoke_device(D1)
    with pytest.raises(HandshakeError, match="revoked"):
        world.utility.on_resume_hello(D1, rh)                            # the cache is not consulted first
    d._ch = None
    with pytest.raises(HandshakeError, match="revoked"):
        world.utility.on_client_hello(D1, d.client_hello())


def test_revocation_is_durable_across_a_utility_restart(tmp_path):
    from conftest import make_policy
    from pqgrid.e2e.handshake import DeviceEndpoint
    from pqgrid.persistence.utility_db import open_utility
    from pqgrid.policy import validate
    from pqgrid.registry import DeviceRecord
    from pqgrid.suite.hkem import HybridKeyPair
    from pqgrid.suite.sig import mldsa_keygen, mldsa_public_bytes
    t = [1_790_000_000.0]
    u_static, cmd = HybridKeyPair.generate(), mldsa_keygen()
    policy = make_policy(u_static.pk, mldsa_public_bytes(cmd))
    validate(policy)
    node = open_utility(str(tmp_path / "u.db"), policy, u_static, cmd, lambda: t[0])
    kp = HybridKeyPair.generate()
    node.endpoint.registry.add(DeviceRecord(D1, "der_ctrl", kp.pk))
    node.endpoint.revoke_device(D1)
    node.db.close()
    again = open_utility(str(tmp_path / "u.db"), policy, u_static, cmd, lambda: t[0])
    d = DeviceEndpoint(D1, "der_ctrl", policy, 1, kp, clock=lambda: t[0])
    with pytest.raises(HandshakeError, match="revoked"):
        again.endpoint.on_client_hello(D1, d.client_hello())


def test_a_revocation_that_reached_only_the_registry_is_still_enforced(world: World):
    """H1 in depth: every E2E use consults the registry's current state, so a revocation recorded in the registry
    alone (without UtilityEndpoint.revoke_device, e.g. by another operator process) still refuses the device's live
    session for commands, GRANTs and status ACKs (mutation-found gap: the checks were masked because revoke_device
    also removes the sessions)."""
    from pqgrid.e2e.envelopes import status_ack
    svc, d1, d2, p1, p2, zm = setup(world)
    seq = svc.issue(D1, b"TRIP", 300)
    [env] = svc.outgoing(D1)
    world.registry.revoke(D1)                                              # the registry only
    assert world.utility.session_for(D1) is not None                       # the session is still in RAM …
    assert world.utility.current_session(D1) is None                       # … but no longer usable
    with pytest.raises(EnvelopeError, match="revoked"):
        svc.on_status(p1.on_control(control_topic("der_ctrl", D1), env))
    with pytest.raises(EnvelopeError, match="revoked"):
        svc.on_status(status_ack(d1.session, 0, seq, b"INTERRUPTED"))
    assert svc.outcome(D1, seq) is None                                    # nothing settled by a revoked device
    with pytest.raises(CommandError, match="revoked"):
        svc.grant(D1, "P_ACTIVE_W", 0, 10, 1, 60)
    assert zm.zonekeys_for(D1) == [] and svc.outgoing(D1) == []


def test_revocation_drops_the_half_open_handshake(world: World):
    d = world.device(D1, "der_ctrl")
    world.utility.on_client_hello(D1, d.client_hello())
    assert D1 in world.utility._pending
    world.utility.revoke_device(D1)
    assert D1 not in world.utility._pending                                # nothing of it stays in RAM
