"""Codex audit P1-2 (2026-10-03, IMPLEMENTATION-ROADMAP §16) over the real broker: utility-side publishes during a
broker outage, across a utility restart, and refused by the broker. Commands count as delivered only on the
device's status ACK; artifacts count as retained only once the broker has acknowledged every message.
The production main loops run throughout (tests/integration/harness.py)."""
import os

from harness import broker, loops, plant, requires_broker, start, wait_for   # noqa: F401  (fixtures)
from pqgrid.fota.artifact import FIRMWARE

pytestmark = requires_broker
M1, D1 = b"meter-0001", b"der-0001"
FW = ("smart_meter", FIRMWARE)


def test_a_command_issued_during_a_broker_outage_is_delivered_and_later_commands_still_go_out(plant, broker):
    """paho keeps the command published while the broker is down (rc 4) and sends it after reconnecting. Before
    the fix the utility's bookkeeping then raised on EVERY later publish (RuntimeError from paho's
    MQTTMessageInfo), so the next command, and everything sent after an establishment, failed until a restart."""
    d = plant.add(D1, "der_ctrl")
    start(plant)
    with loops(plant, d):
        assert wait_for(lambda: d.d.confirmed, 15), d.mq.errors
        broker.stop()
        assert wait_for(lambda: not plant.u.c.is_connected(), 10)
        first = plant.u.command(D1, b"CMD-1", 600)                       # rc 4: kept by paho
        broker.start()
        assert wait_for(lambda: plant.node.commands.outcome(D1, first) == b"OK", 30), (d.mq.errors, plant.u.refused)
        second = plant.u.command(D1, b"CMD-2", 600)                      # before the fix: RuntimeError
        assert wait_for(lambda: plant.node.commands.outcome(D1, second) == b"OK", 15), d.mq.errors
        assert plant.u.flush(5)                                          # every utility publish acknowledged
    assert d.applied == [b"CMD-1", b"CMD-2"]                             # each applied once


def test_an_artifact_published_during_an_outage_reaches_the_device_although_the_utility_restarted(plant, broker):
    """The artifact is published while the broker is down, so it exists only in paho's memory, and the utility
    stops before the broker is back. Before the fix its database already said "retained", nothing published it
    again (the E-4 offer skips a retained artifact) and the device never saw it within the 30-day window."""
    m = plant.add(M1, "smart_meter")
    art = plant.artifact(FIRMWARE, "smart_meter", 2, os.urandom(9_000))
    start(plant)
    broker.stop()
    assert wait_for(lambda: not plant.u.c.is_connected(), 10)
    plant.u.publish_artifact(art)
    plant.u.stop(flush_timeout=0.2)                                      # gone with paho's queue
    broker.start()
    plant.restart_utility()
    with loops(plant, m):
        assert wait_for(lambda: FIRMWARE in m.mq.fota_staged, 30), (m.mq.errors, plant.u.refused)
        assert wait_for(lambda: plant.publisher.live[FW].confirmed, 10)


def test_an_artifact_the_broker_refused_is_published_again_once_the_broker_accepts_it(plant, broker):
    """A stale broker ACL refuses the utility's artifact publishes: Mosquitto answers the QoS 1 PUBLISH with a PUBACK
    carrying 0x87 (Not authorized). That is not acceptance: the artifact stays unconfirmed and is published again
    after retry_every_s; once the ACL is right the device gets it and the artifact is confirmed."""
    m = plant.add(M1, "smart_meter")
    art = plant.artifact(FIRMWARE, "smart_meter", 2, os.urandom(9_000))
    start(plant)
    full = open(broker.acl).read()
    assert "topic write pqgrid/fota/#\n" in full
    broker.load_acl(full.replace("topic write pqgrid/fota/#\n", ""))
    plant.publisher.retry_every_s = 1
    with loops(plant, m):
        assert wait_for(lambda: m.d.confirmed, 15), m.mq.errors
        plant.u.publish_artifact(art)
        assert plant.u.flush(10)                                         # the broker answered every message …
        assert FIRMWARE not in m.mq.fota_staged                          # … and stored none of them
        broker.load_acl(full)
        assert wait_for(lambda: FIRMWARE in m.mq.fota_staged, 30), (m.mq.errors, plant.u.refused)
        assert wait_for(lambda: plant.publisher.live[FW].confirmed, 10)
    assert any("Not authorized" in r for r in plant.u.publish_refusals)
