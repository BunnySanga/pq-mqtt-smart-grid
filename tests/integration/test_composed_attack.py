"""I1 (Master §24.4): a composed attack during a policy rollout over the real broker. The attacker is the network /
broker: it injects a tampered FOTA chunk (retained), replays a captured CONTROL envelope, and pushes the old policy
back (a downgrade), all while v1 -> v2 is rolling out. Each is refused by its own mechanism (Merkle proof; envelope
replay guard and session binding; anti-rollback and POLICY_INFO binding), and the rollout still completes.
Injection uses the utility's broker identity, whose ACL may write every one of these topics: the same power as a
malicious broker. Captured bytes are what the broker forwarded."""
import time

import pytest

import conftest
from harness import broker, loops, plant, requires_broker, start, wait_for          # noqa: F401  (fixtures)
from pqgrid.e2e.handshake import DeviceEndpoint
from pqgrid.errors import PolicyError, PolicyMismatchError
from pqgrid.fota.artifact import POLICY
from pqgrid.mqtt import topics
from pqgrid.suite.hkem import HybridKeyPair

pytestmark = requires_broker
D1 = b"der-0001"


def test_I1_tampered_chunk_replayed_command_and_downgrade_during_a_rollout(plant):
    d = plant.add(D1, "der_ctrl")
    v2 = conftest.make_policy(plant.u_static.pk, plant.policy.utility_cmd_pk, version=2, ca_set=plant.policy.ca_set,
                              activate_at=int(time.time()) + 8)
    art = plant.sign_policy(v2, "der_ctrl")
    v1_art = plant.sign_policy(plant.policy, "der_ctrl")
    wire: list[tuple[str, bytes]] = []                                 # what the broker forwarded to the device
    real = plant.u.c.publish

    def tap(topic, payload=None, *a, **k):
        wire.append((topic, bytes(payload or b"")))
        return real(topic, payload, *a, **k)
    plant.u.c.publish = tap
    start(plant)
    with loops(plant, d):
        assert wait_for(lambda: d.d.confirmed, 15)
        # 1. a tampered chunk, retained in place of the genuine one, while v2 is being downloaded
        good = art.chunks[0]
        bad = bytearray(good)
        bad[40] ^= 1                                                     # inside the chunk data
        chunk_topic = topics.fota_chunk("der_ctrl", "policy", 2, 0)
        plant.u.c.publish(chunk_topic, bytes(bad), qos=1, retain=True)
        for i, part in enumerate(art.parts):
            plant.u.c.publish(topics.fota_part("der_ctrl", "policy", 2, i), part, qos=1, retain=True)
        assert wait_for(lambda: any("failed Merkle verification" in e for e in d.mq.errors), 15), d.mq.errors
        assert POLICY not in d.mq.fota_staged
        plant.u.c.publish(chunk_topic, good, qos=1, retain=True)       # the genuine chunk (republished)
        assert wait_for(lambda: POLICY in d.mq.fota_staged, 15), d.mq.errors
        # 2. a command, captured on the wire and replayed, in the same session and after the switch
        seq = plant.u.command(D1, b"TRIP BREAKER 7", 600)
        assert wait_for(lambda: plant.node.commands.outcome(D1, seq) == b"OK", 15)
        control = topics.control("der_ctrl", D1)
        captured = [p for t, p in wire if t == control and p[4:5] == b"\x03"][-1]
        plant.u.c.publish(control, captured, qos=1)
        assert wait_for(lambda: any("not newer than" in e for e in d.mq.errors), 10), d.mq.errors
        plant.u.schedule_policy(art.signed, art.payload, plant.station.anchors)
        assert wait_for(lambda: d.d.confirmed and d.d.session.policy_info == v2.info(), 30), d.mq.errors
        plant.u.c.publish(control, captured, qos=1)                    # replay into the NEW session
        assert wait_for(lambda: any("not a control envelope for this session" in e for e in d.mq.errors), 10)
        assert d.applied == [b"TRIP BREAKER 7"]                          # applied exactly once
        # 3. a downgrade: the old signed policy pushed back to the device, and an old-policy hello to the utility
        for i, part in enumerate(v1_art.parts):
            plant.u.c.publish(topics.fota_part("der_ctrl", "policy", 1, i), part, qos=1, retain=True)
        assert wait_for(lambda: any("rollback" in e for e in d.mq.errors), 10), d.mq.errors
        assert d.d.policy.version == 2 and d.fota.committed(POLICY) == 2
        stale = DeviceEndpoint(D1, "der_ctrl", plant.policy, 1, HybridKeyPair.generate(), clock=time.time)
        with pytest.raises(PolicyMismatchError):
            plant.node.endpoint.on_client_hello(D1, stale.client_hello())
        with pytest.raises(PolicyError, match="rule 5"):
            plant.u.schedule_policy(v1_art.signed, v1_art.payload, plant.station.anchors)
        assert d.d.confirmed and plant.node.endpoint.policy.version == 2 # the rollout completed regardless
