"""ALERT tier: confidentiality against the broker, tier enforcement, replay, ownership, policy currency,
ACK integrity (Master §11 Alert, §9.6; A5–A8, E-X1, P10)."""
import os

import pytest

from conftest import World, make_policy
from pqgrid.e2e.envelopes import alert_topic, verify_alert_ack
from pqgrid.errors import EnvelopeError, ReplayError
from pqgrid.suite.sig import mldsa_public_bytes
from pqgrid.wire import dec, enc

M1, M2 = b"meter-0001", b"meter-0002"
T1 = alert_topic("smart_meter", M1)


def ready(world: World, did=M1):
    d = world.device(did, "smart_meter")
    world.full(d)
    return d


def test_alert_roundtrip_and_ack(world: World):
    d = ready(world)
    payload, ack, dup = world.utility.open_alert(T1, d.seal_alert(T1, os.urandom(16), b"FREQ_DEVIATION"))
    assert payload == b"FREQ_DEVIATION" and not dup
    assert verify_alert_ack(d.session, ack) == 1


def test_A5_broker_sees_no_plaintext(world: World):
    d = ready(world)
    env = d.seal_alert(T1, os.urandom(16), b"TAMPER_SWITCH_OPENED")
    assert b"TAMPER_SWITCH_OPENED" not in env


def test_A6_plaintext_on_alert_topic_is_refused(world: World):
    ready(world)
    with pytest.raises(EnvelopeError):
        world.utility.open_alert(T1, b"plain text reading")


def test_A7_device_refuses_alert_on_telemetry_topic(world: World):
    d = ready(world)
    with pytest.raises(EnvelopeError, match="not ALERT tier"):
        d.seal_alert("grid/smart_meter/meter-0001/telemetry", os.urandom(16), b"x")


def test_A8_replay_rejected_and_forgery_does_not_burn_the_sequence(world: World):
    d = ready(world)
    env1 = d.seal_alert(T1, os.urandom(16), b"one")
    world.utility.open_alert(T1, env1)
    with pytest.raises(ReplayError):
        world.utility.open_alert(T1, env1)
    env2 = d.seal_alert(T1, os.urandom(16), b"two")
    f = dec(env2, 4)
    forged = enc([f[0], f[1], f[2], f[3][:-1] + bytes([f[3][-1] ^ 1])])
    with pytest.raises(EnvelopeError, match="authentication"):
        world.utility.open_alert(T1, forged)
    assert world.utility.open_alert(T1, env2)[0] == b"two"    # genuine seq 2 still accepted


def test_EX1_envelope_replayed_on_another_devices_topic(world: World):
    d1, _ = ready(world, M1), ready(world, M2)
    env = d1.seal_alert(T1, os.urandom(16), b"x")
    with pytest.raises(EnvelopeError, match="another device"):
        world.utility.open_alert(alert_topic("smart_meter", M2), env)


def test_duplicate_alert_id_is_recognised(world: World):
    d = ready(world)
    aid = os.urandom(16)
    world.utility.open_alert(T1, d.seal_alert(T1, aid, b"x"))
    _, _, dup = world.utility.open_alert(T1, d.seal_alert(T1, aid, b"x"))   # resend, new seq, same id
    assert dup


def test_P10_old_policy_session_refused_after_activation(world: World):
    d = ready(world)
    world.utility.policy = make_policy(world.u_static.pk, mldsa_public_bytes(world.cmd_sk), version=2)
    with pytest.raises(EnvelopeError, match="old policy"):
        world.utility.open_alert(T1, d.seal_alert(T1, os.urandom(16), b"x"))


def test_forged_ack_rejected(world: World):
    d = ready(world)
    _, ack, _ = world.utility.open_alert(T1, d.seal_alert(T1, os.urandom(16), b"x"))
    f = dec(ack, 4)
    with pytest.raises(EnvelopeError, match="forged"):
        verify_alert_ack(d.session, enc([f[0], f[1], f[2], bytes(32)]))


def test_alerts_before_confirmation_must_ride_in_DF(world: World):
    d = world.device(M1, "smart_meter")
    d.on_server_hello(world.utility.on_client_hello(M1, d.client_hello()))
    with pytest.raises(EnvelopeError, match="no confirmed session"):
        d.seal_alert(T1, os.urandom(16), b"x")
