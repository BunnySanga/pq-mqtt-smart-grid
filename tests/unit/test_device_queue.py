"""IMPLEMENTATION-ROADMAP §16.8, item 1: a device publish made while disconnected raises (rc ≠ 0) but paho still keeps
the message for the reconnect, and nothing bounded paho's queue, so every attempt during a long broker outage grew
the device's memory. The queue is now bounded by the most outbox entries the class allows plus QUEUE_HEADROOM (the
burst after an establishment must still fit); beyond it paho keeps nothing (MQTT_ERR_QUEUE_SIZE). Real paho client,
never connected: no broker needed."""
import ssl

import pytest

import conftest
from pqgrid.commands import CommandProcessor
from pqgrid.mqtt.device_node import QUEUE_HEADROOM, DeviceMqtt, TransportError
from pqgrid.persistence.device import Outbox
from pqgrid.suite.sig import mldsa_public_bytes

TOPIC = "grid/smart_meter/meter-0001/telemetry"


def device(world):
    d = world.device(b"meter-0001", "smart_meter")
    return d, DeviceMqtt(d, CommandProcessor(d, lambda c: None), None, ssl.create_default_context(), "localhost", 1)


def fill(mq, n):
    for i in range(n):
        with pytest.raises(TransportError, match="not currently connected"):
            mq._publish(TOPIC, b"%d" % i)                                 # rc 4, but paho keeps it


def test_the_device_client_queue_is_bounded_while_the_broker_is_down(world):
    d, mq = device(world)
    cap = d.profile.outbox_cap // Outbox.OVERHEAD + QUEUE_HEADROOM
    fill(mq, cap)
    with pytest.raises(TransportError, match="queue full"):
        mq._publish(TOPIC, b"one too many")                               # before the fix: kept like the rest


def test_the_bound_follows_a_policy_that_changes_the_outbox_size_from_the_next_connect(world):
    """paho refuses to change the bound on an established connection (RuntimeError: found by the broker tests, where
    every policy activation failed in the device loop), so the new bound applies at the next connect()."""
    d, mq = device(world)
    bigger = conftest.replace_class(world.policy, "smart_meter", outbox_cap=2 * d.profile.outbox_cap)
    v2 = conftest.make_policy(world.u_static.pk, mldsa_public_bytes(world.cmd_sk), version=2, classes=bigger)
    mq._install_policy(v2)                                                # what the device loop does at activate_at
    with pytest.raises(OSError):
        mq.connect(timeout=0.1)                                           # nothing listens on port 1: the bound
    #                                                                       is set before the attempt all the same
    fill(mq, v2.profile("smart_meter").outbox_cap // Outbox.OVERHEAD + QUEUE_HEADROOM)
    with pytest.raises(TransportError, match="queue full"):
        mq._publish(TOPIC, b"one too many")
