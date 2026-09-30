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
    assert u._scheduled is None


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
    assert u._scheduled is None                                        # … it was dropped …
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
    assert node.endpoint.policy.version == 2 and u._scheduled is None   # activated once, not scheduled again


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

    class Msg:                                                         # what paho hands the callback
        def __init__(self, topic, payload):
            self.topic, self.payload = topic, payload
    u.c.on_message(None, None, Msg("grid/der_ctrl/der-0001/telemetry", b"r1"))
    u.c.on_message(None, None, Msg("grid/smart_meter/der-0001/telemetry", b"r2"))   # another class's topic
    u.c.on_message(None, None, Msg("grid/der_ctrl/der-0404/telemetry", b"r3"))      # unknown device
    node.endpoint.revoke_device(b"der-0001")
    u.c.on_message(None, None, Msg("grid/der_ctrl/der-0001/telemetry", b"r4"))      # revoked
    assert u.telemetry == [(b"der-0001", b"r1")] and u.internal_errors == []
    assert sum("telemetry from an unknown or revoked device" in r for r in u.refused) == 3
