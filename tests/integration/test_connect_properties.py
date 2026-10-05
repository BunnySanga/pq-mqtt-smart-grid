"""CONNECT properties follow the installed policy (Master §12 Policy Updates "takes effect at the next connection",
§10.2, §10.4; audit H-2). Everything is observed at the REAL broker: which CONNECTs it accepted (its log shows each
one's Keep Alive), which PUBLISH sizes it forwards to the device (it silently drops anything larger than the
Maximum Packet Size the live connection declared, [DOCKER T1]) and whether it kept the session after a disconnect
(Session Expiry). Before the fix a policy raising max_packet left the live connection on the old limit: the NT
answering a DF with an alert backlog was dropped and the device could not re-establish until something else
reconnected it (audit repro). All loops are the production ones (DeviceMqtt.run, UtilityMqtt.run)."""
import dataclasses
import os
import re
import time

import pytest

import conftest
from harness import broker, loops, plant, requires_broker, start, wait_for          # noqa: F401  (fixtures)
from pqgrid.commands.zones import event_topic
from pqgrid.fota.artifact import FIRMWARE, POLICY, FotaError
from pqgrid.fota.publisher import part_payload_budget
from pqgrid.mqtt import topics
from pqgrid.policy import encode_policy

pytestmark = requires_broker
C2, M1 = b"c2-0001", b"meter-0001"


def connects(plant, did: bytes) -> list[int]:
    """The Keep Alive of every CONNECT the broker accepted from `did`, oldest first (Mosquitto's notice log)."""
    with open(plant.b.log, errors="replace") as f:
        return [int(k) for k in re.findall(rf"New client connected from \S+ as {did.decode()} \(p5, c\d, k(\d+)",
                                           f.read())]


def reaches(plant, dev, publish_size: int) -> bool:
    """Does the broker forward a PUBLISH of `publish_size` bytes to the device? The utility publishes it raw on the
    device's control topic (bypassing its own size check); the device logs every control message it receives."""
    topic = topics.control(dev.dclass, dev.did)
    n = publish_size - topics.publish_size(topic, b"")
    while topics.publish_size(topic, b"\xff" * n) > publish_size:   # the length field grows with the payload
        n -= 1
    payload = b"\xff" * n
    assert topics.publish_size(topic, payload) == publish_size
    before = sum(1 for e in list(dev.mq.errors) if e.startswith(topic))
    plant.u.c.publish(topic, payload, qos=1).wait_for_publish(5)
    return wait_for(lambda: sum(1 for e in list(dev.mq.errors) if e.startswith(topic)) > before, 3)


def with_class(plant, version: int, dclass: str, activate_in: float = 5, **over):
    classes = conftest.replace_class(plant.policy, dclass, **over)
    return conftest.make_policy(plant.u_static.pk, plant.policy.utility_cmd_pk, version=version, classes=classes,
                                ca_set=plant.policy.ca_set, activate_at=int(time.time() + activate_in))


def fleet_artifact(plant, policy, dclass: str, part_limit: int, chunk_size: int):
    """The POLICY artifact sized so that every device of the class can receive it (the delivery floor)."""
    return plant.station.build(POLICY, dclass, policy.version, encode_policy(policy), chunk_size,
                               part_payload_budget(part_limit, dclass, POLICY, policy.version),
                               activate_at=policy.activate_at)


def roll_out(plant, dev, policy, art) -> None:
    plant.u.publish_artifact(art)
    plant.u.schedule_policy(art.signed, art.payload, plant.station.anchors)
    assert wait_for(lambda: POLICY in dev.mq.fota_staged, 15), dev.mq.errors
    assert wait_for(lambda: plant.node.endpoint.policy.version == policy.version and dev.d.confirmed
                    and dev.d.session.policy_info == policy.info(), 30), dev.mq.errors


# ---------------------------------------------------------------------------- A, D, E, F, L: raising the limit
def test_raising_max_packet_reconnects_once_and_the_broker_then_forwards_the_larger_messages(plant):
    c = plant.add(C2, "c2_meter")                                      # 4096 B, keep-alive 300 s
    v2 = with_class(plant, 2, "c2_meter", max_packet=16384, keepalive_s=60)
    start(plant)
    with loops(plant, c):
        assert wait_for(lambda: c.d.confirmed, 15)
        assert connects(plant, C2) == [300]
        assert not reaches(plant, c, 10_000)                           # the old connection: dropped by the broker
        for i in range(60):                                            # a backlog for the re-establishment DF:
            c.outbox.add(os.urandom(16), b"x", b"k%d" % i)             # its NT (60 ACKs) is larger than 4096 B
        roll_out(plant, c, v2, fleet_artifact(plant, v2, "c2_meter", 4096, 3072))
        assert c.mq.policy_reconnects == 1 and connects(plant, C2) == [300, 60]   # one CONNECT, new values
        assert wait_for(lambda: c.outbox.queued() == [], 10)           # the whole backlog delivered
        assert sum(1 for did, p, _ in plant.u.alerts if did == C2 and p == b"x") == 60
        assert reaches(plant, c, 10_000)                               # the broker now forwards 10 kB to it
        time.sleep(1.0)                                                # many loop ticks: no reconnect storm
        assert c.mq.policy_reconnects == 1 and connects(plant, C2) == [300, 60]


# ----------------------------------------------------------------------------- B, C: lowering, session expiry
def test_lowering_max_packet_and_session_expiry_take_effect_at_the_broker(plant):
    m = plant.add(M1, "smart_meter")                                   # 65,536 B, session expiry 7 days
    v2 = with_class(plant, 2, "smart_meter", max_packet=4096, fota_chunk_size=3072, session_expiry_s=3)
    start(plant)
    with loops(plant, m):
        assert wait_for(lambda: m.d.confirmed, 15)
        assert reaches(plant, m, 10_000)
        roll_out(plant, m, v2, fleet_artifact(plant, v2, "smart_meter", 4096, 3072))
        assert m.mq.policy_reconnects == 1 and len(connects(plant, M1)) == 2
        assert not reaches(plant, m, 10_000)                           # the broker enforces the new 4096 B
    m.mq.disconnect()                                                  # the session now expires 3 s after this
    time.sleep(5)
    m.mq.connect()
    assert m.mq.session_present is False                               # the broker applied the new expiry
    with loops(plant, m):
        assert wait_for(lambda: m.d.confirmed and m.d.session.policy_info == v2.info(), 20), m.mq.errors


# ------------------------------------------------------------------- I, J: broker outage and reboot in between
def test_connect_properties_follow_the_policy_through_a_broker_outage_and_a_reboot(plant, broker):
    c = plant.add(C2, "c2_meter")
    v2 = with_class(plant, 2, "c2_meter", activate_in=8, max_packet=16384, keepalive_s=60)
    art = fleet_artifact(plant, v2, "c2_meter", 4096, 3072)
    start(plant)
    with loops(plant, c):
        assert wait_for(lambda: c.d.confirmed, 15)
        plant.u.publish_artifact(art)
        plant.u.schedule_policy(art.signed, art.payload, plant.station.anchors)
        assert wait_for(lambda: POLICY in c.mq.fota_staged, 15), c.mq.errors
        broker.stop()                                                  # down across the activation
        assert wait_for(lambda: c.d.policy.version == 2 and plant.node.endpoint.policy.version == 2, 20)
        time.sleep(1)
        broker.start()
        assert wait_for(lambda: c.d.confirmed and c.d.session.policy_info == v2.info(), 40), c.mq.errors
        assert connects(plant, C2)[-1] == 60 and reaches(plant, c, 10_000)
    c.mq.disconnect()
    plant.boot(c)                                                      # power cycle: boots on its installed v2
    with loops(plant, c):
        assert wait_for(lambda: c.d.confirmed, 20), c.mq.errors
        assert connects(plant, C2)[-1] == 60 and reaches(plant, c, 10_000)
        assert c.mq.policy_reconnects == 0                             # it CONNECTed with v2's values at once


# --------------------------------------------------------------- K, L: no CONNECT change, no reconnect at all
def test_a_policy_that_changes_no_connect_property_causes_no_reconnect(plant):
    c = plant.add(C2, "c2_meter")
    v2 = with_class(plant, 2, "c2_meter", outbox_cap=2048)            # a class change outside CONNECT
    start(plant)
    with loops(plant, c):
        assert wait_for(lambda: c.d.confirmed, 15)
        roll_out(plant, c, v2, fleet_artifact(plant, v2, "c2_meter", 4096, 3072))
        time.sleep(1.0)
        assert c.mq.policy_reconnects == 0 and connects(plant, C2) == [300]


# ------------------------------------------------------------------------- G, H: FOTA and DR at the boundary
def test_fota_and_dr_messages_between_the_old_and_the_new_limit(plant):
    c = plant.add(C2, "c2_meter")
    v2 = with_class(plant, 2, "c2_meter", max_packet=16384, fota_chunk_size=12288)
    start(plant)
    with loops(plant, c):
        assert wait_for(lambda: c.d.confirmed, 15)
        plant.node.zones.create("f7")
        plant.u.join_zone("f7", C2)
        plant.publish_acl()
        roll_out(plant, c, v2, fleet_artifact(plant, v2, "c2_meter", 4096, 3072))
        assert wait_for(lambda: event_topic("f7", c.d.profile.aead) in c.mq.subscribed, 10)
        prof = v2.profile("c2_meter")
        fw = plant.station.build(FIRMWARE, "c2_meter", 2, os.urandom(30_000), prof.fota_chunk_size,
                                 part_payload_budget(prof.max_packet, "c2_meter", FIRMWARE, 2))
        assert max(len(ch) for ch in fw.chunks) > 12_000               # every chunk above the old 4096 B limit
        plant.u.publish_artifact(fw)                                    # FIRMWARE follows the current policy …
        assert wait_for(lambda: FIRMWARE in c.mq.fota_staged, 20), c.mq.errors
        v3 = dataclasses.replace(v2, version=3)
        big = plant.station.build(POLICY, "c2_meter", 3, encode_policy(v3), 12288,
                                  part_payload_budget(16384, "c2_meter", POLICY, 3))
        with pytest.raises(FotaError, match="largest packet every device of the class can receive"):
            plant.u.publish_artifact(big)                              # … a POLICY must reach devices still on v1
        event = os.urandom(6000)                                       # a DR event above the old limit
        assert plant.u.dr_event("f7", event, 600) == 1
        assert wait_for(lambda: ("f7", event) in c.mq.events, 10), c.mq.dr_refused
    plant.restart_utility()                                            # the floor survives a restart
    with pytest.raises(FotaError, match="largest packet every device of the class can receive"):
        plant.u.publish_artifact(big)


# ------------------------------------------------ retained artifacts dropped under the old limit (mutation #155)
def test_a_retained_artifact_dropped_under_the_old_limit_arrives_after_the_reconnect(plant):
    """DR-052 / Master §15.9: the utility activates v2 and publishes FIRMWARE sized for v2's 16 KiB while the device's
    live connection still declares 4 KiB. The broker drops it for that connection, and retained messages come only
    with a SUBSCRIBE: after its one planned reconnect the device must subscribe to the retained artifacts again, or
    it would not see this firmware until the retention window ended. Found by mutation analysis (#155 survived every
    other test)."""
    c = plant.add(C2, "c2_meter")                                      # 4096 B
    v2 = with_class(plant, 2, "c2_meter", activate_in=6, max_packet=16384, fota_chunk_size=12288)
    art = fleet_artifact(plant, v2, "c2_meter", 4096, 3072)
    start(plant)
    with loops(plant, c):
        assert wait_for(lambda: c.d.confirmed, 15)
        plant.u.publish_artifact(art)
        plant.u.schedule_policy(art.signed, art.payload, plant.station.anchors)
        assert wait_for(lambda: POLICY in c.mq.fota_staged, 15), c.mq.errors
    assert wait_for(lambda: time.time() >= v2.activate_at, 15)         # both loops stopped; the device's 4 KiB
    plant.u.tick()                                                     # connection stays up. The utility activates
    assert plant.node.endpoint.policy.version == 2                     # v2 and publishes FIRMWARE for 16 KiB
    fw = plant.station.build(FIRMWARE, "c2_meter", 2, os.urandom(30_000), 12288,
                             part_payload_budget(16384, "c2_meter", FIRMWARE, 2))
    plant.u.publish_artifact(fw)
    time.sleep(2)                                                      # precondition: nothing reached the device
    assert FIRMWARE not in c.fota.downloads and FIRMWARE not in c.mq.fota_staged
    with loops(plant, c):                                              # it activates v2, reconnects once, and
        assert wait_for(lambda: FIRMWARE in c.mq.fota_staged, 30), c.mq.errors   # the retained firmware arrives
        assert c.mq.policy_reconnects == 1 and connects(plant, C2)[-1] == c.d.profile.keepalive_s


def test_a_policy_that_grows_the_outbox_reconnects_once_for_the_queue_bound(plant):
    """Third Codex review, finding 7, over the broker: the outbox grows (CONNECT unchanged), so paho's queue bound must
    grow too, which paho allows only between connections: exactly one planned reconnect."""
    m = plant.add(M1, "smart_meter")
    v2 = with_class(plant, 2, "smart_meter", outbox_cap=4608)
    start(plant)
    with loops(plant, m):
        assert wait_for(lambda: m.d.confirmed, 15), m.mq.errors
        roll_out(plant, m, v2, fleet_artifact(plant, v2, "smart_meter", 65536, 16384))
        assert wait_for(lambda: m.mq.policy_reconnects == 1 and m.d.confirmed and m.d.policy.version == 2, 30), \
            m.mq.errors
        assert not m.mq.stale_connect_properties()
