"""The utility's main-loop step (UtilityMqtt.tick) without a broker (Master §10.5 "Main loops", §12 Policy
Distribution; remediation M9). Nothing here is published: the MQTT client is never connected."""
import ssl

import pytest

import conftest
from pqgrid.errors import PolicyError
from pqgrid.fota.artifact import POLICY
from pqgrid.fota.publisher import part_payload_budget
from pqgrid.fota.station import Station, find_openssl
from pqgrid.mqtt.utility_node import ZONE_ROTATE_EVERY_S, UtilityMqtt
from pqgrid.persistence.utility_db import open_utility
from pqgrid.policy import encode_policy, validate
from pqgrid.registry import DeviceRecord
from pqgrid.suite.aead import AeadAlg
from pqgrid.suite.hkem import HybridKeyPair
from pqgrid.suite.sig import mldsa_keygen, mldsa_public_bytes

requires_station = pytest.mark.skipif(find_openssl() is None,
                                      reason="needs OpenSSL >= 3.5 for SLH-DSA: runs in the Docker test image")
T0 = 1_790_000_000


class Msg:                                                             # what paho hands the utility's callback
    def __init__(self, topic, payload):
        self.topic, self.payload = topic, payload


@pytest.fixture
def util(tmp_path):
    now = [float(T0)]
    u_static, cmd_sk = HybridKeyPair.generate(), mldsa_keygen()
    v1 = conftest.make_policy(u_static.pk, mldsa_public_bytes(cmd_sk))
    validate(v1)
    node = open_utility(str(tmp_path / "u.db"), v1, u_static, cmd_sk, lambda: now[0])
    node.endpoint.registry.add(DeviceRecord(b"der-0001", "der_ctrl", HybridKeyPair.generate().pk))
    station = Station(str(tmp_path))

    def signed(version: int, activate_at: int):
        p = conftest.make_policy(u_static.pk, mldsa_public_bytes(cmd_sk), version=version, activate_at=activate_at)
        prof = p.profile("smart_meter")
        art = station.build(POLICY, "smart_meter", version, encode_policy(p), prof.fota_chunk_size,
                            part_payload_budget(prof.max_packet, "smart_meter", POLICY, version),
                            activate_at=activate_at)
        return art.signed, art.payload, station.anchors

    nodes = [node]

    def restart():
        """A real process restart: the database reopened with the bootstrap configuration (policy v1), a new
        UtilityMqtt. Only what the database holds survives."""
        nodes[-1].db.close()
        nodes.append(open_utility(str(tmp_path / "u.db"), v1, u_static, cmd_sk, lambda: now[0]))
        return UtilityMqtt(nodes[-1], ssl.create_default_context(), "localhost", 1, clock=lambda: now[0]), nodes[-1]

    u = UtilityMqtt(node, ssl.create_default_context(), "localhost", 1, clock=lambda: now[0])
    yield u, node, now, signed, restart
    nodes[-1].db.close()


@requires_station
def test_scheduling_a_policy_that_is_not_newer_is_refused_at_once(util):
    u, node, now, signed, restart = util
    with pytest.raises(PolicyError, match="rule 5"):
        u.schedule_policy(*signed(1, T0))                             # the installed version: never activatable
    assert node.db.load_policy("scheduled") is None


@requires_station
def test_a_scheduled_policy_refused_at_activation_is_dropped_and_the_loop_keeps_working(util):
    """v2 is scheduled; before it is due the operator activates v3 directly. When v2 falls due it can never be
    activated (rule 5). It is refused once, recorded and dropped, and every tick still does its housekeeping (here:
    the weekly zone-key rotation). Before the fix the refusal escaped tick() before the housekeeping, on every tick,
    for ever."""
    u, node, now, signed, restart = util
    node.zones.create("f7")
    node.zones.add_member("f7", b"der-0001")
    g = node.zones.zones["f7"].groups[AeadAlg.CHACHA20POLY1305]
    u.schedule_policy(*signed(2, T0 + 60))
    assert u.activate_policy(*signed(3, T0))                           # the urgent v3, activated directly
    assert node.endpoint.policy.version == 3
    e0 = g.key_epoch                                                   # (v3's activation rotated every zone)
    now[0] += ZONE_ROTATE_EVERY_S                                      # v2 is due; the zone key is a week old
    u.tick()
    assert node.endpoint.policy.version == 3                           # v2 was not activated …
    assert node.db.load_policy("scheduled") is None                    # … it was dropped …
    assert [r for r in u.refused if "rule 5" in r] != []              # … and the refusal recorded (G-1: locally)
    assert g.key_epoch == e0 + 1 and u.ticks == 1                      # housekeeping ran in the same tick
    now[0] += ZONE_ROTATE_EVERY_S
    u.tick()
    assert g.key_epoch == e0 + 2 and u.ticks == 2
    assert len([r for r in u.refused if "rule 5" in r]) == 1          # not retried


@requires_station
def test_a_restarted_utility_keeps_the_policy_it_activated(util):
    """Master §4.4 / U-4: the rollout state is durable. A utility restarted after activating v2 (with its bootstrap
    configuration, v1) must still run v2; otherwise every device that switched is refused for its POLICY_INFO."""
    from pqgrid.e2e.handshake import DeviceEndpoint
    from pqgrid.policy import decode_policy
    u, node, now, signed, restart = util
    art = signed(2, T0)
    assert u.activate_policy(*art)
    u, node = restart()
    assert node.endpoint.policy.version == 2
    kp = HybridKeyPair.generate()
    node.endpoint.registry.add(DeviceRecord(b"der-0002", "der_ctrl", kp.pk))
    d = DeviceEndpoint(b"der-0002", "der_ctrl", decode_policy(art[1]), 1, kp, clock=lambda: now[0])
    d.on_server_hello(node.endpoint.on_client_hello(b"der-0002", d.client_hello()))   # a v2 device is served


@requires_station
def test_a_policy_scheduled_before_a_restart_is_still_activated_at_its_time(util):
    """Devices that staged v2 switch at activate_at whatever happens to the utility; a restart in between must not
    lose the utility's side of that promise."""
    u, node, now, signed, restart = util
    u.schedule_policy(*signed(2, T0 + 60))
    u, node = restart()
    u.tick()
    assert node.endpoint.policy.version == 1                            # not yet due
    now[0] = T0 + 60
    u.tick()
    assert node.endpoint.policy.version == 2
    u, node = restart()
    u.tick()
    assert node.endpoint.policy.version == 2 and node.db.load_policy("scheduled") is None   # activated once


@requires_station
def test_a_crash_while_activating_never_leaves_the_new_policy_on_the_old_zone_keys(util, monkeypatch):
    """Key table §4.7: zone keys rotate at a policy change. If the activation is interrupted at the rotation (it
    fails here as a crash would), the restarted utility must not run the new policy on the old zone keys: the old
    policy is still active, and the scheduled activation runs again, rotation included."""
    u, node, now, signed, restart = util
    node.zones.create("f7")
    node.zones.add_member("f7", b"der-0001")

    def epoch(n):
        return n.zones.zones["f7"].groups[AeadAlg.CHACHA20POLY1305].key_epoch
    e0 = epoch(node)
    u.schedule_policy(*signed(2, T0 + 60))
    now[0] = T0 + 60

    def crash():
        raise RuntimeError("power lost while rotating the zone keys")
    monkeypatch.setattr(node.zones, "rotate_all", crash)
    with pytest.raises(RuntimeError):
        u.tick()
    u, node = restart()
    assert node.endpoint.policy.version == 1 and epoch(node) == e0     # nothing half done
    u.tick()                                                           # the scheduled activation, again
    assert node.endpoint.policy.version == 2 and epoch(node) == e0 + 1


@requires_station
def test_telemetry_is_accepted_only_from_an_active_device_on_its_own_class_topic(util):
    """H1 / K-5 through paho's callback (no broker): TELEMETRY is hop-only, so the utility's registry decides."""
    u, node, now, signed, restart = util
    u.c.on_message(None, None, Msg("grid/der_ctrl/der-0001/telemetry", b"r1"))
    u.c.on_message(None, None, Msg("grid/smart_meter/der-0001/telemetry", b"r2"))   # another class's topic
    u.c.on_message(None, None, Msg("grid/der_ctrl/der-0404/telemetry", b"r3"))      # unknown device
    node.endpoint.revoke_device(b"der-0001")
    u.c.on_message(None, None, Msg("grid/der_ctrl/der-0001/telemetry", b"r4"))      # revoked
    assert u.telemetry == [(b"der-0001", b"r1")] and u.internal_errors == []
    assert sum("telemetry from an unknown or revoked device" in r for r in u.refused) == 3


@requires_station
def test_an_acl_hook_failure_is_retried_and_never_reported_as_a_refused_activation(util):
    """Audit L-1: the hook ran after the activation, and when it raised tick() reported "scheduled policy refused at
    activation" for a policy that WAS active, and never recompiled the ACL. Now the activation stands, the failure is
    recorded as an ACL failure, and every tick retries the owed recompile until it succeeds."""
    u, node, now, signed, restart = util
    calls = []

    def hook():
        calls.append(node.endpoint.policy.version)
        if len(calls) == 1:
            raise OSError("broker restarting: SIGHUP failed")
    u.acl_hook = hook
    u.schedule_policy(*signed(2, T0 + 60))
    now[0] = T0 + 61
    u.tick()
    assert node.endpoint.policy.version == 2 and node.db.load_policy("scheduled") is None
    assert not any("refused" in r for r in u.refused) and not u.internal_errors
    assert calls == [2] and len(u.acl_failures) == 1 and u.acl_failures[0][1] == "OSError"
    u.tick()                                                           # retried …
    assert calls == [2, 2] and len(u.acl_failures) == 1
    u.tick()                                                           # … until it succeeded, then no more
    assert calls == [2, 2]



def _device(node, now, did: bytes, dclass: str, max_packet=None):
    from pqgrid.e2e.handshake import DeviceEndpoint
    kp = HybridKeyPair.generate()
    node.endpoint.registry.add(DeviceRecord(did, dclass, kp.pk, max_packet=max_packet))
    return DeviceEndpoint(did, dclass, node.endpoint.policy, 1, kp, clock=lambda: now[0])


@requires_station
def test_df_alerts_reach_the_application_even_when_the_reply_cannot_be_published(util):
    """Audit L-4: the DF's alerts were recorded as seen (their IDs) and handed to the application only AFTER NT was
    published; a refused publish lost them for the application, and their resend was flagged as duplicate. Here the
    registry's per-device limit (the latent DeviceRecord.max_packet path) admits the SH but not an NT carrying 40
    ACKs: the alerts are delivered once, the refusal is recorded, and a retransmitted DF delivers nothing twice."""
    import os
    u, node, now, signed, restart = util
    d = _device(node, now, b"der-0003", "der_ctrl", max_packet=2700)
    sh = node.endpoint.on_client_hello(b"der-0003", d.client_hello())
    d.on_server_hello(sh)
    alerts = [("grid/der_ctrl/der-0003/alert", os.urandom(16), b"A%d" % i) for i in range(40)]
    df = d.finished(alerts)
    u.c.on_message(None, None, Msg("pqgrid/hs/der-0003/up", df))
    assert [p for did, p, dup in u.alerts if did == b"der-0003" and not dup] == [a[2] for a in alerts]
    assert any("exceeds der-0003's maximum packet size" in r for r in u.refused) and not u.internal_errors
    u.c.on_message(None, None, Msg("pqgrid/hs/der-0003/up", df))       # the identical DF again (QoS 1 / retry)
    assert len([1 for did, _, _ in u.alerts if did == b"der-0003"]) == 40


@requires_station
def test_a_reused_ticket_raises_the_clone_alarm(util):
    """Master §27.8 M-1 (audit L-9): "ticket already used" is a clone indicator; it was only in the refusal log."""
    from pqgrid.e2e.handshake import DeviceEndpoint
    u, node, now, signed, restart = util
    d = _device(node, now, b"meter-0009", "smart_meter")
    ep = node.endpoint
    d.on_server_hello(ep.on_client_hello(b"meter-0009", d.client_hello()))
    d.on_final(ep.on_finished(b"meter-0009", d.finished()).final)
    ticket = d.ticket
    u.c.on_message(None, None, Msg("pqgrid/hs/meter-0009/up", d.resume_hello()))   # the genuine resume
    clone = DeviceEndpoint(b"meter-0009", "smart_meter", ep.policy, 1, d.static, clock=lambda: now[0])
    clone.ticket = ticket                                              # a copy of the flash, a fresh RH
    now[0] += 200                                                      # beyond the duplicate window
    u.c.on_message(None, None, Msg("pqgrid/hs/meter-0009/up", clone.resume_hello()))
    assert [did for did, _ in u.ticket_reuse_alarms] == [b"meter-0009"]
    assert any("ticket already used" in r for r in u.refused)


@requires_station
def test_a_joining_member_gets_its_read_right_before_its_new_zone_key(util):
    """Found by the final concurrent broker runs: join_zone published the new ZONEKEY and only then ran the ACL
    hook. Mosquitto grants the SUBACK without a read right and filters at delivery, so a member that subscribed on
    that key could have the next events silently dropped until the broker reloaded, and nothing re-sends them while
    it stays connected. Now the ACL naming the new member is written and the broker told before its key goes out."""
    from pqgrid.mqtt import topics
    u, node, now, signed, restart = util
    order = []

    class Client:                                                      # the utility's MQTT client, recording
        def publish(self, topic, payload, qos=0, retain=False):
            order.append(("publish", topic))
            return type("Info", (), {"is_published": lambda self: True})()
    u.c = Client()
    u.acl_hook = lambda: order.append(("acl", set(node.zones.zones["f7"].members)))
    d = _device(node, now, b"der-0003", "der_ctrl")
    ep = node.endpoint
    d.on_server_hello(ep.on_client_hello(b"der-0003", d.client_hello()))
    d.on_final(ep.on_finished(b"der-0003", d.finished()).final)       # a live session: its key is sent at once
    node.zones.create("f7")
    u.join_zone("f7", b"der-0003")
    assert order == [("acl", {b"der-0003"}), ("publish", topics.control("der_ctrl", b"der-0003"))]
    assert not u.acl_failures
