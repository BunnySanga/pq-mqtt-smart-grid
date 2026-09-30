"""Integration over a real broker: Mosquitto 2.0 + OpenSSL 3.5, hybrid-only TLS 1.3, ECDSA P-256 PKI, compiled ACL
(Master §8, §10, §9.4, §13, §14; I1, E-P2, N3, N4, N5, N6, T1, T2, T4, T7, A12; IMPLEMENTATION-ROADMAP §11).

Every check is on delivery, never on SUBACK: Mosquitto grants forbidden subscriptions and simply never delivers."""
import dataclasses
import os
import ssl
import socket

import pytest

from harness import broker, plant, requires_broker, wait_for          # noqa: F401  (fixtures)
from pqgrid.e2e.handshake import StoredTicket
from pqgrid.mqtt import pki, topics, tls
from pqgrid.errors import CommandError
from pqgrid.mqtt.device_node import TransportError
from pqgrid.suite.aead import AeadAlg

pytestmark = requires_broker
D1, D2, M1, C2 = b"der-0001", b"der-0002", b"meter-0001", b"c2-0001"


def online(plant, *devs):
    plant.publish_acl()
    if not plant.u.connected.is_set():
        plant.u.start()
    for dev in devs:
        dev.mq.connect()
        dev.mq.establish()


# ====================================================================================== I1: the lifecycle
def test_I1_lifecycle_over_the_broker(plant):
    der, meter = plant.add(D1, "der_ctrl"), plant.add(M1, "smart_meter")
    online(plant)
    der.mq.connect()
    queued = der.mq.send_alert(b"TAMPER", b"cover opened while offline")        # no session yet: outbox
    der.mq.establish()                                                         # full handshake; DF carries it
    assert wait_for(lambda: (D1, b"cover opened while offline", False) in plant.u.alerts)
    assert der.outbox.queued() == [] and queued
    meter.mq.connect()
    meter.mq.establish()

    der.mq.send_alert(b"SAG", b"voltage sag 190 V")                           # live ALERT + ACK
    assert wait_for(lambda: (D1, b"voltage sag 190 V", False) in plant.u.alerts)
    assert wait_for(lambda: der.outbox.queued() == [])

    seq = plant.u.command(D1, b"CURTAIL 50%", 300)                            # CMD + status
    assert wait_for(lambda: plant.node.commands.outcome(D1, seq) == b"OK") and der.applied == [b"CURTAIL 50%"]

    gid = plant.u.grant(D1, "P_ACTIVE_W", -5000, 5000, 12, 3600)              # GRANT + SETPOINT
    assert wait_for(lambda: (D1, (plant.node.commands.epoch << 32) | 2, b"OK") in plant.u.statuses)
    plant.u.setpoint(D1, gid, 2500, 30)
    assert wait_for(lambda: der.setpoints == [("P_ACTIVE_W", 2500)]), (der.mq.errors, plant.u.statuses[-3:])
    assert der.mq.send_setpoint_ack()

    plant.node.zones.create("f7")                    # ZONEKEY + DR broadcast
    plant.u.join_zone("f7", D1)
    plant.publish_acl()                                                        # zone read right
    assert wait_for(lambda: topics.dr_event("f7", AeadAlg.CHACHA20POLY1305) in der.mq.subscribed)
    plant.u.dr_event("f7", b"SHED 20% 14:00-16:00", 600)
    assert wait_for(lambda: der.mq.events == [("f7", b"SHED 20% 14:00-16:00")])

    meter.mq.send_telemetry(b"kWh=1234.5")                                     # TELEMETRY: TLS only
    assert wait_for(lambda: (M1, b"kWh=1234.5") in plant.u.telemetry)

    der.mq.disconnect()                                                        # persistent session: the broker
    seq2 = plant.u.command(D1, b"CLOSE BREAKER 3", 300)                        # queues QoS 1 CONTROL
    assert plant.u.flush()                                                     # stored by the broker
    der.mq.connect()
    assert der.mq.session_present                                             # no SUBSCRIBE on wake (§10.4)
    assert wait_for(lambda: plant.node.commands.outcome(D1, seq2) == b"OK")
    assert der.applied == [b"CURTAIL 50%", b"CLOSE BREAKER 3"]

    der.mq.establish()                                                         # 1-RTT resume (PSK_KEM class)
    assert der.d.confirmed and der.d.session.resume_mode.value == "PSK_KEM"
    assert der.mq.errors == [] or all("skipped" in e for e in der.mq.errors)


# ================================================================================ restarts (E-P2, N5)
def test_EP2_utility_restart_resync_and_outbox_over_mqtt(plant):
    der = plant.add(D1, "der_ctrl")
    online(plant, der)
    plant.restart_utility()                                                    # sessions gone, database kept
    der.mq.send_alert(b"TAMPER", b"after the utility restart")
    assert wait_for(lambda: der.mq.resync_requested.is_set())                  # hint on hs/down
    der.mq.establish()                                                         # resume with the persisted STEK
    assert wait_for(lambda: (D1, b"after the utility restart", False) in plant.u.alerts)
    assert der.outbox.queued() == []
    seq = plant.u.command(D1, b"TRIP", 300)
    assert wait_for(lambda: plant.node.commands.outcome(D1, seq) == b"OK")


def test_N5_broker_restart_keeps_the_persistent_session_and_its_queue(plant, broker):
    der = plant.add(D1, "der_ctrl")
    online(plant, der)
    der.mq.disconnect()
    seq = plant.u.command(D1, b"TRIP", 600)                                    # queued for the sleeping device
    assert plant.u.flush()                                                     # PUBACK: the broker has it
    broker.restart()                                                           # persistence true
    assert wait_for(lambda: plant.u.c.is_connected(), 15)                      # paho reconnects the utility
    der.mq.connect()
    assert der.mq.session_present
    assert wait_for(lambda: plant.node.commands.outcome(D1, seq) == b"OK", 15)


def test_device_reboot_after_outage_gets_queued_dr_event(plant):
    """M5 (replacing E55): the broker delivers its queue at CONNACK, before this session's ZONEKEY. The queued copy
    is refused with a recorded reason (no RAM buffer); the utility re-sends the still-valid event after the
    ZONEKEY on the control topic, so it is applied exactly once."""
    der = plant.add(D1, "der_ctrl")
    online(plant, der)
    plant.node.zones.create("f7")
    plant.u.join_zone("f7", D1)
    plant.publish_acl()
    assert wait_for(lambda: topics.dr_event("f7", AeadAlg.CHACHA20POLY1305) in der.mq.subscribed)
    der.mq.disconnect()
    plant.boot(der)                                                            # power loss: RAM gone
    plant.u.dr_event("f7", b"RESTORE: stagger load", 600)                      # issued while it is down
    assert plant.u.flush()                                                     # queued by the broker
    der.mq.connect()
    der.mq.establish()
    assert wait_for(lambda: der.mq.events == [("f7", b"RESTORE: stagger load")])
    assert any("no key" in why for _, why in der.mq.dr_refused)             # the early copy: refused, recorded
    assert der.mq.internal_errors == []


# ======================================================================================== TLS (N3, T7, T4, T2)
def test_N3_T7_only_hybrid_tls13_is_accepted(broker):
    """Exact refusals [DOCKER, OpenSSL 3 s_client]: a classical-only group list gets handshake_failure (alert 40),
    TLS 1.2 gets protocol_version (alert 70); neither reaches a negotiated protocol."""
    out = broker.s_client()
    assert "Negotiated TLS1.3 group: X25519MLKEM768" in out and "Protocol version: TLSv1.3" in out
    classical = broker.s_client("-groups", "X25519")
    assert "alert handshake failure" in classical and "SSL alert number 40" in classical
    assert "Protocol version" not in classical and "X25519MLKEM768" not in classical
    tls12 = broker.s_client("-tls1_2")
    assert "alert protocol version" in tls12 and "SSL alert number 70" in tls12 and "Protocol version" not in tls12
    for suite in ("TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"):   # both class suites (§8.4, E53)
        assert f"Ciphersuite: {suite}" in broker.s_client("-ciphersuites", suite)


def _tls_connect(ctx, port):
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), 5), server_hostname="localhost")
    s.sendall(b"\x10\x14\x00\x04MQTT\x04\x02\x00\x3c\x00\x08tls-test")
    ok = s.recv(4)
    s.close()
    return ok


def test_T4_device_tls_ignores_certificate_time_but_not_the_chain(broker, tmp_path):
    dev = pki.device_cert(broker.ca, str(tmp_path), b"der-0009")
    with pytest.raises(ssl.SSLCertVerificationError, match="not yet valid"):
        _tls_connect(tls.utility_context([broker.ca.crt], dev.crt, dev.key), broker.port_future)
    assert _tls_connect(broker.device_ctx(dev), broker.port_future)            # dates ignored (§8.8)
    other_ca = pki.make_ca(str(tmp_path), "rogue-ca")
    with pytest.raises(ssl.SSLCertVerificationError):                           # chain still verified
        _tls_connect(tls.device_context([other_ca.crt], dev.crt, dev.key), broker.port)
    expired = pki.issue(broker.ca, str(tmp_path), "old", "der-0010", "clientAuth",
                        not_before="20200101000000Z", not_after="20210101000000Z")
    assert _tls_connect(broker.device_ctx(dev), broker.port)                   # the broker is reachable …
    failures = open(broker.log).read().count("certificate verify failed")
    with pytest.raises(ssl.SSLError, match="SSLV3_ALERT_CERTIFICATE_EXPIRED"):  # … and refuses an expired cert
        _tls_connect(broker.device_ctx(expired), broker.port)
    assert wait_for(lambda: open(broker.log).read().count("certificate verify failed") == failures + 1, 5)


def test_T2_the_tls_hop_resumes(plant):
    der = plant.add(D1, "der_ctrl")
    plant.publish_acl()
    der.mq.connect()
    assert not der.mq.tls_resumed()
    der.mq.disconnect()
    der.mq.connect()
    assert der.mq.tls_resumed()


# ================================================================================= ACL (A12), takeover (N4)
def test_A12_devices_cannot_read_or_write_other_devices_topics(plant):
    """Mosquitto 2.x [DOCKER]: a SUBSCRIBE outside the ACL is granted (SUBACK 0x01) but nothing is delivered on it
    (the read check runs per message); a PUBLISH outside it gets PUBACK 0x87 Not authorized and is not
    forwarded. The connection stays up. Non-delivery is shown with barriers, not by waiting."""
    d1, d2 = plant.add(D1, "der_ctrl"), plant.add(D2, "der_ctrl")
    online(plant, d1, d2)
    stolen, subacks, pubacks = [], {}, {}
    d2.mq.c.message_callback_add(topics.control("der_ctrl", D1), lambda c, u, m: stolen.append(m.payload))
    d2.mq.c.on_subscribe = lambda c, u, mid, rcs, props: subacks.__setitem__(mid, [r.value for r in rcs])
    d2.mq.c.on_publish = lambda c, u, mid, rc, props: pubacks.__setitem__(mid, rc.value)
    _, smid = d2.mq.c.subscribe(topics.control("der_ctrl", D1), qos=1)
    assert wait_for(lambda: smid in subacks) and subacks[smid] == [1]          # granted …
    seq = plant.u.command(D1, b"TRIP", 300)
    assert wait_for(lambda: plant.node.commands.outcome(D1, seq) == b"OK")    # … routed by the broker …
    barrier = plant.u.command(D2, b"BARRIER", 300)                             # … before this one to d2 itself
    assert wait_for(lambda: plant.node.commands.outcome(D2, barrier) == b"OK")
    assert stolen == [] and d2.applied == [b"BARRIER"]                         # … and never delivered to d2
    before = list(plant.u.telemetry)
    bad1 = d2.mq.c.publish(topics.telemetry("der_ctrl", D1), b"forged reading", qos=1)
    bad2 = d2.mq.c.publish(topics.hs_up(D1), b"forged handshake", qos=1)
    good = d2.mq.c.publish(topics.telemetry("der_ctrl", D2), b"barrier", qos=1)   # same client, after them
    assert wait_for(lambda: {bad1.mid, bad2.mid, good.mid} <= set(pubacks))
    assert (pubacks[bad1.mid], pubacks[bad2.mid], pubacks[good.mid]) == (0x87, 0x87, 0x00)
    assert wait_for(lambda: (D2, b"barrier") in plant.u.telemetry)
    assert plant.u.telemetry == before + [(D2, b"barrier")]                    # the forged reading never arrived
    assert not any("forged handshake" in r for r in plant.u.refused)          # nor the forged handshake
    assert d2.mq.connected.is_set()                                            # the connection stayed up


def test_revocation_takes_effect_through_acl_reload(plant):
    m = plant.add(M1, "smart_meter")
    online(plant, m)
    m.mq.send_telemetry(b"r1")
    assert wait_for(lambda: (M1, b"r1") in plant.u.telemetry)
    plant.node.endpoint.registry.revoke(M1)
    plant.publish_acl()                                                        # recompiled, SIGHUP
    pubacks = {}
    m.mq.c.on_publish = lambda c, u, mid, rc, props: pubacks.__setitem__(mid, rc.value)
    info = m.mq.c.publish(topics.telemetry("smart_meter", M1), b"r2", qos=1)
    assert wait_for(lambda: info.mid in pubacks) and pubacks[info.mid] == 0x87   # refused, so never forwarded
    assert (M1, b"r2") not in plant.u.telemetry


def test_N4_repeated_takeovers_raise_the_clone_alarm(plant):
    m = plant.add(M1, "smart_meter")
    online(plant, m)
    assert M1 not in plant.u.takeover_alarms
    for k in range(4):
        clone = plant.boot(dataclasses.replace(m, flash=m.flash))              # same identity and certificate
        clone.mq.connect()                                                     # the broker drops the other one
        assert wait_for(lambda: len(plant.u._online.get(M1, ())) >= k + 2, 5)  # its announcement was counted
    assert "already connected, closing old connection" in open(plant.b.log).read()
    assert wait_for(lambda: M1 in plant.u.takeover_alarms, 5), plant.u._online


# ================================================================================= packet limits (N6, T1)
def test_N6_T1_nothing_larger_than_the_device_limit_is_sent(plant):
    c2 = plant.add(C2, "c2_meter")                                             # max_packet 4,096 B
    online(plant, c2)
    got = []
    c2.mq.c.message_callback_add(topics.control("c2_meter", C2), lambda c, u, m: got.append(len(m.payload)))
    plant.u.c.publish(topics.control("c2_meter", C2), os.urandom(5000), qos=1)  # bypassing the check …
    plant.u.c.publish(topics.control("c2_meter", C2), os.urandom(3000), qos=1)
    assert wait_for(lambda: 3000 in got)                                        # same topic, same publisher:
    assert got == [3000] and c2.mq.connected.is_set()                           # the 5000 was dropped (T1)
    with pytest.raises(TransportError, match="maximum packet size"):
        plant.u._publish(C2, topics.control("c2_meter", C2), os.urandom(5000))  # so the utility refuses


# ============================================================================ refused resume (E49)
def test_refused_resume_falls_back_to_a_full_handshake(plant):
    m = plant.add(M1, "smart_meter")
    online(plant, m)
    t = m.d.ticket
    blob = bytearray(t.blob)
    blob[20] ^= 1
    m.d.ticket = dataclasses.replace(t, blob=bytes(blob))                       # a ticket the utility refuses
    m.d.session, m.d.confirmed = None, False
    m.mq.reply_timeout, m.mq.tries = 0.5, 2
    m.mq.establish()                                                           # RH unanswered → CH
    assert m.d.confirmed and any("falling back" in e for e in m.mq.errors)
    assert isinstance(m.d.ticket, StoredTicket) and m.d.ticket.blob != bytes(blob)


def test_S5_lost_reply_is_recovered_by_identical_retransmission(plant):
    """The first SH is lost on its way down: the device resends the IDENTICAL CH and the utility's duplicate cache
    answers it with the identical SH (I-18), so the handshake completes without a new key exchange."""
    m = plant.add(M1, "smart_meter")
    online(plant)
    m.mq.connect()
    seen, dropped = [], []
    publish, handshake = plant.u._publish, plant.u._handshake

    def lossy(did, topic, payload):
        if topic == topics.hs_down(M1) and not dropped:
            dropped.append(payload)                                            # lost in transit
            return
        publish(did, topic, payload)

    def spy(did, msg):
        seen.append(msg)
        handshake(did, msg)
    plant.u._publish, plant.u._handshake = lossy, spy
    m.mq.reply_timeout = 1.0
    m.mq.establish()
    assert m.d.confirmed and len(dropped) == 1
    assert seen[0] == seen[1] and seen[0][:6] == b"\x00\x00\x00\x02CH"          # the same CH bytes, twice


def test_H1_live_revocation_over_the_broker_without_any_acl_change(plant):
    """E2E revocation must not depend on the broker ACL: no recompile happens in this test."""
    d1, d2 = plant.add(D1, "der_ctrl"), plant.add(D2, "der_ctrl")
    online(plant, d1, d2)
    plant.node.zones.create("f7")
    plant.u.join_zone("f7", D1)
    plant.u.join_zone("f7", D2)
    plant.publish_acl()                                                       # zone read rights, BEFORE revocation
    assert wait_for(lambda: "f7" in d1.mq._zones and "f7" in d2.mq._zones)
    plant.u.revoke_device(D1)                                                 # acl_hook is None here
    d1.mq.send_alert(b"X", b"after revocation")
    assert wait_for(lambda: any("revoked" in r for r in plant.u.refused))     # refused at the E2E layer
    assert all(p != b"after revocation" for _, p, _ in plant.u.alerts)
    with pytest.raises(CommandError, match="revoked"):
        plant.u.command(D1, b"TRIP", 300)
    cc = AeadAlg.CHACHA20POLY1305
    assert wait_for(lambda: d2.mq.proc.zones._keys.get(("f7", cc)) and max(d2.mq.proc.zones._keys[("f7", cc)]) ==
                    plant.node.zones.zones["f7"].groups[cc].key_epoch)       # D2 got the new key
    plant.u.dr_event("f7", b"SHED", 600)
    assert wait_for(lambda: ("f7", b"SHED") in d2.mq.events)
    assert wait_for(lambda: any("no key" in why for _, why in d1.mq.dr_refused))   # delivered, unreadable
    assert ("f7", b"SHED") not in d1.mq.events


def test_H3_device_network_loop_survives_callback_faults(plant):
    from pqgrid.e2e.envelopes import alert_ack
    d = plant.add(D1, "der_ctrl")
    online(plant, d)
    queued = alert_ack(plant.node.endpoint.session_for(D1), 1)            # a genuine ACK …
    d.mq.disconnect()
    info = plant.u.c.publish(topics.control("der_ctrl", D1), queued, qos=1)
    info.wait_for_publish(5)                                               # … queued by the broker (PUBACK)
    plant.boot(d)                                                          # power loss: no session in RAM
    d.mq.connect()                                                         # delivered at CONNACK, no session
    assert wait_for(lambda: any("without a session" in e for e in d.mq.errors))
    assert d.mq.internal_errors == []
    d.mq.establish()                                                       # the loop is alive: full exchange
    assert d.d.confirmed
    real = d.mq.proc.on_control

    def fault(topic, env):
        raise RuntimeError("k_master=00112233 must never be logged")
    d.mq.proc.on_control = fault                                           # an unexpected internal error
    plant.u.command(D1, b"FIRST", 300)
    assert wait_for(lambda: len(d.mq.internal_errors) == 1)
    where, kind, frames = d.mq.internal_errors[0]
    assert (where, kind) == ("message", "RuntimeError") and "00112233" not in repr(d.mq.internal_errors)
    d.mq.proc.on_control = real
    seq = plant.u.command(D1, b"SECOND", 300)                               # still processing messages
    assert wait_for(lambda: plant.node.commands.outcome(D1, seq) == b"OK")
    d.mq.disconnect()
    d.mq.connect()                                                         # and it can still reconnect
    d.mq.establish()
    assert d.d.confirmed


def test_M8_utility_network_loop_survives_a_database_failure(plant):
    import sqlite3
    d = plant.add(D1, "der_ctrl")
    online(plant, d)
    real = plant.node.commands.on_status

    def broken(ack):
        raise sqlite3.OperationalError("disk I/O error at /secret/path")
    plant.node.commands.on_status = broken
    plant.u.command(D1, b"TRIP", 300)                                      # the status ACK hits the failure
    assert wait_for(lambda: any(a[1] == "OperationalError" for a in plant.u.internal_errors))
    assert "/secret/path" not in repr(plant.u.internal_errors)
    plant.node.commands.on_status = real
    m = plant.add(M1, "smart_meter")                                       # the utility still works
    plant.publish_acl()
    m.mq.connect()
    m.mq.establish()
    assert m.d.confirmed


# =============================================================================== logical zones (M4, M5, M7)
def zone_online(plant, *devs):
    """Join f7 through the production path (join_zone: rotate + ZONEKEY), grant the ACL, and wait for every
    member's SUBACK on its own group topic (no sleep)."""
    if "f7" not in plant.node.zones.zones:
        plant.node.zones.create("f7")
    for dev in devs:
        plant.u.join_zone("f7", dev.did)
    plant.publish_acl()
    for dev in devs:
        t = topics.dr_event("f7", dev.d.profile.aead)
        assert wait_for(lambda: t in dev.mq.subscribed), dev.mq.errors


def test_M7_aes_and_chacha_members_get_one_logical_event_over_the_broker(plant):
    m, d = plant.add(M1, "smart_meter"), plant.add(D1, "der_ctrl")          # AES and ChaCha
    online(plant, m, d)
    zone_online(plant, m, d)
    assert plant.u.dr_event("f7", b"SHED 20%", 600) == 2                     # one publication per group
    assert wait_for(lambda: m.mq.events == [("f7", b"SHED 20%")] and d.mq.events == [("f7", b"SHED 20%")])
    assert m.proc.state.zone_bseq["f7"] == d.proc.state.zone_bseq["f7"]      # one logical identity
    assert not m.mq.dr_refused and not d.mq.dr_refused
    assert m.mq.internal_errors == d.mq.internal_errors == plant.u.internal_errors == []


def test_M4_rotation_while_down_then_reboot_over_the_broker(plant):
    d1 = plant.add(D1, "der_ctrl")
    online(plant, d1)
    zone_online(plant, d1)
    d1.mq.disconnect()
    plant.u.dr_event("f7", b"RESTORE: stagger load", 600)                    # queued under the old key
    plant.add(D2, "der_ctrl")
    plant.u.join_zone("f7", D2)                                              # the ChaCha key rotates meanwhile
    plant.boot(d1)                                                           # power loss: keys (RAM) gone
    d1.mq.connect()
    d1.mq.establish()
    assert wait_for(lambda: d1.mq.events == [("f7", b"RESTORE: stagger load")])   # re-sent, current key
    assert any("no key" in why for _, why in d1.mq.dr_refused)             # the queued copy: refused, recorded
    d1.mq.establish()                                                        # re-sent again: a duplicate
    assert wait_for(lambda: d1.mq.dr_duplicates >= 1)
    assert d1.mq.events == [("f7", b"RESTORE: stagger load")] and d1.mq.internal_errors == []


def test_M5_live_rotation_then_event_needs_no_buffer_over_the_broker(plant):
    """A member stays online through five rotations, each followed at once by an event. Whatever order the broker
    delivers the key (control topic) and the event (group topic) in, every event is delivered exactly once, with
    no RAM buffer: an event that overtook its key is refused, recorded, and recovered by a zone sync (E-2).
    (Mosquitto usually keeps one publisher's order [DOCKER, observed]; nothing relies on it.)"""
    d1 = plant.add(D1, "der_ctrl")
    online(plant, d1)
    zone_online(plant, d1)
    for i in range(5):
        plant.add(b"der-01%02d" % i, "der_ctrl")
        plant.u.join_zone("f7", b"der-01%02d" % i)                           # rotation: new ZONEKEY to d1
        plant.u.dr_event("f7", b"E%d" % i, 600)                              # immediately after it
    assert wait_for(lambda: len(d1.mq.events) == 5, 20), (d1.mq.dr_refused, d1.mq.errors)
    assert d1.mq.events == [("f7", b"E%d" % i) for i in range(5)]
    missing = [why for _, why in d1.mq.dr_refused if "no key" in why]
    assert (not missing) or d1.mq.zone_sync_requests >= 1                      # any overtaken event was synced


# ================================================================================ A5 over the real path
def test_A5_what_the_broker_forwards_and_stores_carries_no_plaintext(plant, broker):
    """The ALERT envelope is what the broker routes (live) and what it writes to its persistence file (queued for
    an offline utility): the plaintext is in neither, and the destination still opens it."""
    der = plant.add(D1, "der_ctrl")
    online(plant, der)
    wire, sent = [], []
    real_on_message, real_publish = plant.u.c.on_message, der.mq._publish
    plant.u.c.on_message = lambda c, u, m: (wire.append((m.topic, bytes(m.payload))), real_on_message(c, u, m))
    der.mq._publish = lambda topic, payload: (sent.append((topic, payload)), real_publish(topic, payload))
    secret = b"TAMPER_SWITCH_OPENED_" + os.urandom(6).hex().encode()
    der.mq.send_alert(b"TAMPER", secret)
    assert wait_for(lambda: (D1, secret, False) in plant.u.alerts)             # the destination decrypts it …
    [env] = [p for t, p in wire if t == topics.alert("der_ctrl", D1)]
    assert env == sent[-1][1] and secret not in env                            # … from bytes without plaintext
    plant.u.stop()                                                             # utility offline: the broker queues
    at_rest = b"PRICE_SIGNAL_" + os.urandom(6).hex().encode()
    pubacks = {}
    der.mq.c.on_publish = lambda c, u, mid, rc, props: pubacks.__setitem__(mid, rc.value)
    der.mq.send_alert(b"PRICE", at_rest)
    stored_env = sent[-1][1]
    assert wait_for(lambda: pubacks and all(v == 0 for v in pubacks.values()))
    broker.stop()                                                              # SIGTERM: persistence written
    db = open(f"{broker.dir}/db/mosquitto.db", "rb").read()
    assert stored_env in db and at_rest not in db                              # stored as the envelope only
    broker.start()
    plant.u.start()                                                            # persistent session: delivered
    assert wait_for(lambda: (D1, at_rest, False) in plant.u.alerts, 15)


def test_full_outbox_of_small_alerts_still_establishes_over_the_broker(plant):
    """Final remediation: a C2 device (4 KiB packets) comes back with its outbox full of small alerts, more than
    one NT can acknowledge. DF carries what the reply can ACK within 4 KiB; the rest go live after confirmation.
    Every queued alert (and the drop counter) arrives exactly once."""
    from pqgrid.e2e.envelopes import df_alert_limit
    c2 = plant.add(C2, "c2_meter")
    plant.publish_acl()
    plant.u.start()
    c2.mq.connect()
    for i in range(200):                                                       # no session yet: queued only
        c2.mq.send_alert(b"k%03d" % i, b"s%03d" % i)
    queued = [p for _, _, p in c2.outbox.queued()]
    assert len(queued) > df_alert_limit(4096) and queued[0].startswith(b"DROPPED:")
    c2.mq.establish()
    assert wait_for(lambda: c2.outbox.queued() == [], 15), c2.mq.errors
    got = [p for d, p, dup in plant.u.alerts if d == C2]
    assert sorted(got) == sorted(queued) and not any(dup for d, _, dup in plant.u.alerts if d == C2)
    assert plant.u.internal_errors == [] and c2.mq.internal_errors == []


def test_live_remainder_with_lost_acks_rides_the_next_df_and_is_flagged_duplicate(plant):
    """The alerts that did not fit DF go live after confirmation. If some of their ACKs are lost, they stay in the
    outbox and ride in the next DF; the utility recognises their alert IDs (duplicate = True), so the application
    sees every alert exactly once as new."""
    c2 = plant.add(C2, "c2_meter")
    plant.publish_acl()
    plant.u.start()
    c2.mq.connect()
    for i in range(120):
        c2.mq.send_alert(b"k%03d" % i, b"s%03d" % i)
    queued = [p for _, _, p in c2.outbox.queued()]
    real, dropped = plant.u._publish, []

    def lossy(did, topic, payload):
        if payload[4:5] == b"\x05" and len(dropped) < 5 and plant.u.alerts and did == C2:
            dropped.append(payload)                                   # lose five live ALERT ACKs
            return
        real(did, topic, payload)
    plant.u._publish = lossy
    c2.mq.establish()
    assert wait_for(lambda: len(c2.outbox.queued()) == 5, 15), (len(c2.outbox.queued()), c2.mq.errors)
    plant.u._publish = real
    c2.mq.establish()                                                 # the next session: they ride in its DF
    assert wait_for(lambda: c2.outbox.queued() == [], 15), c2.mq.errors
    mine = [(p, dup) for d, p, dup in plant.u.alerts if d == C2]
    assert sorted(p for p, dup in mine if not dup) == sorted(queued)  # each alert once as new …
    assert len([p for p, dup in mine if dup]) == 5                    # … the five re-sent ones flagged duplicate


# ============================================================================= E-2: zone key sync (final)
def _hold_first_control_to(plant, did):
    """Hold back the next CONTROL (tag 0x03) to `did`: the rotation's ZONEKEY. Returns the list it lands in."""
    real, held = plant.u._publish, []

    def publish(d, topic, payload):
        if d == did and payload[4:5] == b"\x03" and not held:
            held.append((d, topic, payload))
            return
        real(d, topic, payload)
    plant.u._publish = publish
    return held, real


def test_E2_event_before_its_zonekey_is_recovered_by_a_zone_sync_over_the_broker(plant):
    """A. d1 is online during a key rotation; B. its new ZONEKEY is held back, so the next event (group topic)
    arrives first; C. the event is still valid; D. d1 records the refusal and asks for a zone sync; E. the utility
    answers with the current ZONEKEY and republishes the event under it (same bseq), on d1's control topic;
    F. d1 accepts it once; G. the original copy, replayed, is rejected as a duplicate."""
    d1, d2 = plant.add(D1, "der_ctrl"), plant.add(D2, "der_ctrl")
    online(plant, d1, d2)
    zone_online(plant, d1)
    captured, real_pub = [], plant.node.zones.publish
    plant.node.zones.publish = lambda *a, **k: captured.append(real_pub(*a, **k)) or captured[-1]
    held, real = _hold_first_control_to(plant, D1)
    plant.u.join_zone("f7", D2)                                                # A: rotation, d1's key held (B)
    assert wait_for(lambda: len(held) == 1)
    plant.u.dr_event("f7", b"SHED 30%", 600)                                  # C: valid for 10 minutes
    plant.u.dr_event("f7", b"SHED 40%", 600)                                  # a second one, same race
    assert wait_for(lambda: ("f7", b"SHED 40%") in d1.mq.events, 15), (d1.mq.dr_refused, d1.mq.errors)
    assert len([1 for _, why in d1.mq.dr_refused if "no key" in why]) == 2   # D: both refused, recorded, …
    assert d1.mq.zone_sync_requests == 1 and list(plant.u.zone_syncs) == [(D1, "f7")]   # … ONE sync (E)
    assert d1.mq.events == [("f7", b"SHED 30%"), ("f7", b"SHED 40%")]         # F: each once, in bseq order
    plant.u._publish = real
    real(*held[0])                                                            # the late ZONEKEY: harmless
    topic, env = next(iter(captured[-2].items()))                             # SHED 30%'s own publication
    before = len(d1.mq.dr_refused)
    plant.u.c.publish(topic, env, qos=1)                                      # G: the original copy again
    assert wait_for(lambda: len(d1.mq.dr_refused) > before, 10)
    assert "broadcast replay" in d1.mq.dr_refused[-1][1] and d1.mq.events.count(("f7", b"SHED 30%")) == 1
    assert d1.mq.internal_errors == [] and plant.u.internal_errors == []


def test_E2_an_event_that_expired_before_the_sync_is_not_republished(plant):
    d1, d2 = plant.add(D1, "der_ctrl"), plant.add(D2, "der_ctrl")
    online(plant, d1, d2)
    zone_online(plant, d1)
    held, real = _hold_first_control_to(plant, D1)
    plant.u.join_zone("f7", D2)
    assert wait_for(lambda: len(held) == 1)
    calls, real_sync = [], plant.u._zone_sync
    plant.u._zone_sync = lambda did, env: calls.append((did, env))           # the request waits …
    plant.u.dr_event("f7", b"SHORT", 60)
    assert wait_for(lambda: len(calls) == 1, 15)
    clock = plant.node.endpoint.clock
    plant.node.endpoint.clock = lambda: clock() + 61                         # … until the event has expired
    with plant.u.lock:
        real_sync(*calls[0])
    plant.u._publish = real
    assert wait_for(lambda: plant.u.zone_syncs and plant.u.zone_syncs[-1] == (D1, "f7"), 10)
    plant.u.dr_event("f7", b"AFTER", 600)                                     # a later event: d1 has the key now
    assert wait_for(lambda: ("f7", b"AFTER") in d1.mq.events, 10)
    assert ("f7", b"SHORT") not in d1.mq.events                               # never republished once expired
