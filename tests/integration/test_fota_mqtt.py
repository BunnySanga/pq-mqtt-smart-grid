"""FOTA over the real broker (Master §15, §10.2–§10.3, §12 Policy Distribution; V-F1, E-F1, E-F4, F6, V-F2, P5,
P10; IMPLEMENTATION-ROADMAP §12). Artifacts are retained; every message fits the class packet limit."""
import os
import time

import pytest

from harness import broker, plant, requires_broker, wait_for          # noqa: F401  (fixtures)
from pqgrid.fota.artifact import ANCHOR_A, ANCHOR_B, FIRMWARE, KEYREVOKE, POLICY
from pqgrid.fota.publisher import part_payload_budget

pytestmark = requires_broker
C2, M1 = b"c2-0001", b"meter-0001"


def online(plant, *devs):
    plant.publish_acl()
    plant.u.start()
    for dev in devs:
        dev.mq.connect()
        dev.mq.establish()


def test_firmware_to_a_constrained_device_over_the_broker(plant):
    """V-F1 over MQTT: 4,096 B packets, so the 8 KB signed manifest arrives in 3 retained parts."""
    c2 = plant.add(C2, "c2_meter")
    online(plant, c2)
    art = plant.artifact(FIRMWARE, "c2_meter", 2, os.urandom(20_000))
    assert len(art.parts) == 3
    plant.u.publish_artifact(art)
    assert wait_for(lambda: FIRMWARE in c2.mq.fota_staged, 15), c2.mq.errors
    assert c2.fota.boot_staged_firmware(lambda img: img == art.payload) == "committed"
    c2.d.fw = 2                                                      # running the new image
    assert not c2.d.can_resume()                                     # the ticket was bound to fw 1 (P7)
    c2.mq.establish()                                                # a full handshake with the new version
    assert c2.d.confirmed


def test_download_resumes_after_a_reboot(plant):
    """E-F1 over MQTT: half the chunks, power loss, reboot; the retained rest completes the image."""
    c2 = plant.add(C2, "c2_meter")
    online(plant, c2)
    art = plant.artifact(FIRMWARE, "c2_meter", 2, os.urandom(30_000))
    msgs = plant.publisher.messages(art)
    parts, chunks = msgs[:len(art.parts)], msgs[len(art.parts):]
    for t, p in parts + chunks[:4]:
        plant.u.c.publish(t, p, qos=1, retain=True)
    assert wait_for(lambda: FIRMWARE in c2.fota.downloads and sum(bin(b).count("1") for b in
                                                                 c2.fota.downloads[FIRMWARE].have) == 4, 15)
    c2.mq.disconnect()
    plant.boot(c2)                                                   # power loss: RAM gone, flash kept
    for t, p in chunks[4:]:
        plant.u.c.publish(t, p, qos=1, retain=True)
    c2.mq.connect()                                                  # re-subscribes: retained chunks again
    assert wait_for(lambda: FIRMWARE in c2.mq.fota_staged, 15), c2.mq.errors
    assert c2.fota.boot_staged_firmware(lambda img: img == art.payload) == "committed"


def test_retention_cleanup_and_rate_limited_republish(plant):
    m = plant.add(M1, "smart_meter")
    online(plant, m)
    art = plant.artifact(FIRMWARE, "smart_meter", 2, os.urandom(10_000))
    plant.publisher.clock = lambda: time.time() - 31 * 86400         # published 31 days ago …
    plant.u.publish_artifact(art)
    assert wait_for(lambda: FIRMWARE in m.mq.fota_staged, 15)
    plant.publisher.clock = time.time
    assert plant.publisher.cleanup(plant.u.c) == 1                   # … so the retention window has passed
    assert not plant.publisher.live                                  # nothing retained any more
    late = plant.add(b"meter-0002", "smart_meter")                   # a device that was offline all along
    online(plant, late)                                              # E-4: it reports fw 1 < 2 at establishment
    assert wait_for(lambda: FIRMWARE in late.mq.fota_staged, 15), late.mq.errors
    assert list(plant.u.republished) == [(b"meter-0002", [FIRMWARE])]   # a proactive republish, once
    late.mq.request_republish()                                      # its own request, within the hour …
    late.mq.send_alert(b"X", b"barrier")                             # (the request was processed before the ACK)
    assert wait_for(lambda: late.outbox.queued() == [])
    assert list(plant.u.republished) == [(b"meter-0002", [FIRMWARE])]   # … is rate-limited


def test_signed_policy_rollout_and_activation(plant):
    """§12 Policy Distribution: installed ahead of activate_at; at activation the utility refuses old-policy
    sessions (P10) and tickets (P5); the device re-handshakes under the new policy."""
    m = plant.add(M1, "smart_meter")
    online(plant, m)
    import conftest
    new = conftest.make_policy(plant.u_static.pk, plant.policy.utility_cmd_pk, version=2,
                               activate_at=int(time.time()) + 3)
    art = plant.sign_policy(new)
    plant.u.publish_artifact(art)
    assert wait_for(lambda: POLICY in m.mq.fota_staged, 15), m.mq.errors
    assert m.fota.activate_policy(m.d.policy) is None                # not yet
    old_ticket = m.d.ticket
    assert wait_for(lambda: plant.u.activate_policy(art.signed, art.payload, plant.station.anchors), 10)
    m.mq.send_alert(b"X", b"on the old session")
    assert wait_for(lambda: any("old policy" in r for r in plant.u.refused), 10)       # P10
    got = []                                                         # the device's clock trails the utility's
    assert wait_for(lambda: got.append(m.fota.activate_policy(m.d.policy)) or got[-1] is not None, 10)
    p = got[-1]                                                      # by up to one transit + 1 s (E56)
    assert p.version == 2 and m.fota.committed(POLICY) == 2
    m.d.install_policy(p)
    assert not m.d.can_resume() and old_ticket.policy_info != p.info()                 # P5 on the device side
    m.mq.establish()                                                 # a full handshake under version 2
    assert m.d.confirmed and m.d.session.policy_info == p.info()


def test_M1_policy_activated_between_SH_and_DF_over_the_broker(plant):
    """Remediation M1 on the real broker: the utility activates v2 after answering the device's CH and before its
    DF arrives. The DF is refused (not answered: G-1), no session exists, the alert bundled in DF is neither
    delivered nor ACKed (it stays in the outbox); once the device installs v2 it establishes and the alert is
    delivered exactly once."""
    import conftest
    from pqgrid.mqtt.device_node import TransportError
    m = plant.add(M1, "smart_meter")
    plant.publish_acl()
    plant.u.start()
    m.mq.connect()
    new = conftest.make_policy(plant.u_static.pk, plant.policy.utility_cmd_pk, version=2,
                               activate_at=int(time.time()) - 1)
    art = plant.sign_policy(new)
    ep, activated = plant.u.n.endpoint, []
    real = ep.on_client_hello

    def racing(did, ch):
        sh = real(did, ch)
        activated.append(plant.u.activate_policy(art.signed, art.payload, plant.station.anchors))
        return sh
    ep.on_client_hello = racing
    m.mq.tries = 1
    aid = m.mq.send_alert(b"VOLTAGE", b"SAG 190V")                  # no session yet: rides in DF
    with pytest.raises(TransportError, match="no answer to the finished message"):
        m.mq.establish()
    assert activated == [True]
    assert wait_for(lambda: any("policy changed during the handshake" in r for r in plant.u.refused), 5)
    assert plant.u.alerts == [] and ep.current_session(M1) is None
    assert [x[1] for x in m.outbox.queued()] == [aid]                # not ACKed: nothing was opened
    ep.on_client_hello = real
    m.d.install_policy(new)
    m.mq.establish()
    assert m.d.confirmed and m.d.session.policy_info == new.info() == ep.current_session(M1).policy_info
    assert wait_for(lambda: plant.u.alerts == [(M1, b"SAG 190V", False)], 5)
    assert m.outbox.queued() == [] and plant.u.internal_errors == []


def test_revoked_release_anchor_over_the_broker(plant):
    """V-F2 over MQTT: KEYREVOKE(A) signed by B; A-signed firmware is then refused, B-signed installs."""
    m = plant.add(M1, "smart_meter")
    online(plant, m)
    prof = plant.policy.profile("smart_meter")
    plant.u.publish_artifact(plant.station.keyrevoke("smart_meter", 1, ANCHOR_A, prof.fota_chunk_size,
                                                     part_payload_budget(prof.max_packet, "smart_meter", KEYREVOKE, 1)))
    assert wait_for(lambda: m.fota.prot.revoked == {ANCHOR_A}, 15), m.mq.errors
    plant.u.publish_artifact(plant.artifact(FIRMWARE, "smart_meter", 2, os.urandom(5000)))           # A-signed
    assert wait_for(lambda: any("revoked anchor" in e for e in m.mq.errors), 10)
    plant.u.publish_artifact(plant.artifact(FIRMWARE, "smart_meter", 3, os.urandom(5000), anchor_id=ANCHOR_B))
    assert wait_for(lambda: FIRMWARE in m.mq.fota_staged, 15), m.mq.errors
    assert m.fota.boot_staged_firmware(lambda img: True) == "committed"


def test_devices_cannot_publish_artifacts(plant):
    """The ACL lets a device read its class's artifacts and write only its own request topic."""
    a, b = plant.add(M1, "smart_meter"), plant.add(b"meter-0002", "smart_meter")
    online(plant, a, b)
    fake = plant.artifact(FIRMWARE, "smart_meter", 9, os.urandom(4000))
    pubacks = {}
    a.mq.c.on_publish = lambda c, u, mid, rc, props: pubacks.__setitem__(mid, rc.value)
    mids = [a.mq.c.publish(t, p, qos=1, retain=True).mid for t, p in plant.publisher.messages(fake)]
    assert wait_for(lambda: set(mids) <= set(pubacks))                # a captured meter tries to publish …
    assert {pubacks[m] for m in mids} == {0x87}                       # … every message: Not authorized
    b.mq.send_alert(b"X", b"barrier")
    assert wait_for(lambda: b.outbox.queued() == [])
    assert b.mq.fota_staged == [] and FIRMWARE not in b.fota.downloads and b.fota._parts == {}


def test_chunks_lost_before_they_reached_flash_come_back_after_reboot(plant):
    """Chunks delivered (QoS 1 acknowledged) but lost before being written: the broker will not send them again,
    so after the reboot the device must SUBSCRIBE to its download's chunks to get the retained copies (E-F1)."""
    from pqgrid.fota.artifact import FotaError
    c2 = plant.add(C2, "c2_meter")
    online(plant, c2)
    art = plant.artifact(FIRMWARE, "c2_meter", 2, os.urandom(30_000))
    real, seen = c2.fota.on_chunk, set()

    def power_fails_mid_stream(raw):
        from pqgrid.fota.artifact import decode_chunk
        seen.add(decode_chunk(raw)[2])
        if decode_chunk(raw)[2] >= 4:
            raise FotaError("simulated: power lost before the chunk reached flash")
        return real(raw)
    c2.fota.on_chunk = power_fails_mid_stream
    plant.u.publish_artifact(art)                                    # every chunk is delivered now …
    assert wait_for(lambda: FIRMWARE in c2.fota.downloads and sum(bin(b).count("1") for b in
                                                                 c2.fota.downloads[FIRMWARE].have) == 4, 15)
    assert wait_for(lambda: len(seen) == len(art.chunks), 15)       # every chunk was delivered once
    c2.mq.disconnect()
    plant.boot(c2)                                                   # … but only four survived the reboot
    c2.mq.connect()
    assert wait_for(lambda: FIRMWARE in c2.mq.fota_staged, 15), c2.mq.errors
    assert c2.fota.boot_staged_firmware(lambda img: img == art.payload) == "committed"
