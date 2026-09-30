"""Remediation M9: the production main loops, DeviceMqtt.run() and UtilityMqtt.run(), drive reconnection,
(re)establishment, FOTA policy activation and firmware commit, republish requests, publisher cleanup, weekly
zone-key rotation and ACL recompilation. Every test runs the real loops in threads over the real broker; no test
calls a wired step directly to stand in for its production caller."""
import os
import threading
import time
from contextlib import contextmanager

from harness import broker, plant, requires_broker, wait_for          # noqa: F401  (fixtures)
from pqgrid.fota.artifact import FIRMWARE, POLICY
from pqgrid.fota.publisher import RETENTION_S
from pqgrid.mqtt.broker import compile_acl
from pqgrid.suite.aead import AeadAlg

pytestmark = requires_broker
M1, D1 = b"meter-0001", b"der-0001"
DAY = 86400


class NoSpread:
    """rng for the tests: the §12 random re-handshake delay and the back-off jitter become 0."""

    def uniform(self, a, b):
        return a


@contextmanager
def loops(plant, *devs, interval=0.05, rng=None):
    """The utility's and the devices' main loops in threads, stopped (and joined) at the end."""
    stop = threading.Event()
    threads = [threading.Thread(target=plant.u.run, args=(stop, interval), daemon=True)]
    for dev in devs:
        dev.mq.rng = rng or NoSpread()
        threads.append(threading.Thread(target=dev.mq.run, args=(stop, interval), daemon=True))
    for t in threads:
        t.start()
    try:
        yield
    finally:
        stop.set()
        for t in threads:
            t.join(10)
    for dev in devs:
        assert dev.mq.internal_errors == [], dev.mq.internal_errors
    assert plant.u.internal_errors == [], plant.u.internal_errors


def start(plant):
    plant.publish_acl()
    plant.u.start()


def test_M9_device_loop_connects_establishes_and_recovers_from_a_drop_and_a_utility_restart(plant):
    m = plant.add(M1, "smart_meter")
    start(plant)
    with loops(plant, m):
        assert wait_for(lambda: m.d.confirmed, 15), m.mq.errors                 # connect + full handshake
        m.mq.c.disconnect()                                                     # the network drops
        assert wait_for(lambda: not m.mq.connected.is_set(), 5)
        assert wait_for(lambda: m.mq.connected.is_set() and m.d.confirmed, 15), m.mq.errors
        plant.restart_utility()                                                 # sessions gone at the utility
        m.mq.send_alert(b"TAMPER", b"after the restart")                       # → resync hint → loop resumes
        assert wait_for(lambda: (M1, b"after the restart", False) in plant.u.alerts, 20), m.mq.errors
        assert wait_for(lambda: m.outbox.queued() == [], 5)                     # NT/FIN reached the device loop


def test_M9_scheduled_policy_rollout_end_to_end(plant):
    """§12 through both loops: the station-signed policy is published, installed ahead of activate_at, activated by
    the utility's tick (old sessions closed, zone keys rotated, ACL recompiled from the new artifact) and by the
    device's tick (random-delay re-handshake under v2)."""
    import conftest
    m = plant.add(M1, "smart_meter")
    new = conftest.make_policy(plant.u_static.pk, plant.policy.utility_cmd_pk, version=2,
                               activate_at=int(time.time()) + 4)
    art = plant.sign_policy(new)
    acl_versions = []

    def recompile():                                                           # the operator's ACL hook
        members = {n: set(z.members) for n, z in plant.node.zones.zones.items()}
        plant.b.load_acl(compile_acl(art.signed, art.payload, plant.station.anchors,
                                     plant.node.endpoint.registry.records(), members))
        acl_versions.append(new.version)
    plant.u.acl_hook = recompile
    start(plant)
    with loops(plant, m):
        assert wait_for(lambda: m.d.confirmed, 15)
        plant.node.zones.create("f7")
        plant.u.join_zone("f7", M1)
        cc0 = plant.node.zones.zones["f7"].groups[AeadAlg.AES256GCM].key_epoch
        plant.u.publish_artifact(art)
        plant.u.schedule_policy(art.signed, art.payload, plant.station.anchors)
        assert wait_for(lambda: POLICY in m.mq.fota_staged, 15), m.mq.errors   # installed ahead of time
        assert m.d.policy.version == 1
        assert wait_for(lambda: m.d.confirmed and m.d.policy.version == 2 and
                        m.d.session.policy_info == new.info(), 30), m.mq.errors
        assert plant.node.endpoint.policy.version == 2
        assert wait_for(lambda: acl_versions == [2], 5)                        # recompiled after the switch
        assert plant.node.endpoint.current_session(M1).policy_info == new.info()
        assert plant.node.zones.zones["f7"].groups[AeadAlg.AES256GCM].key_epoch > cc0   # policy change: rotated
        assert m.fota.committed(POLICY) == 2
    m.mq.disconnect()
    plant.boot(m)                                                              # power cycle after the rollout:
    assert m.d.policy.version == 2                                             # it boots with its installed v2 …
    with loops(plant, m):
        assert wait_for(lambda: m.d.confirmed and m.d.session.policy_info == new.info(), 30), m.mq.errors
        assert plant.node.endpoint.current_session(M1).policy_info == new.info()   # … and is not locked out
    plant.restart_utility()                                                    # a utility restart (bootstrap v1):
    assert plant.node.endpoint.policy.version == 2                             # the rollout state survived (U-4)
    with loops(plant, m):
        m.mq.send_alert(b"X", b"after both restarts")                         # resync hint → resume under v2
        assert wait_for(lambda: (M1, b"after both restarts", False) in plant.u.alerts, 20), m.mq.errors


def test_M9_firmware_is_committed_by_the_loop_and_the_device_re_handshakes_with_its_new_version(plant):
    m = plant.add(M1, "smart_meter")
    art = plant.artifact(FIRMWARE, "smart_meter", 2, os.urandom(20_000))
    m.mq.self_test = lambda image: image == art.payload
    start(plant)
    with loops(plant, m):
        assert wait_for(lambda: m.d.confirmed, 15)
        plant.u.publish_artifact(art)
        assert wait_for(lambda: m.mq.fw_results == ["committed"], 20), m.mq.errors
        assert wait_for(lambda: m.d.confirmed and m.d.fw == 2, 15), m.mq.errors
        assert plant.node.endpoint.current_session(M1).fw_version == 2           # the utility sees the new image
        assert m.d.ticket is None or m.d.ticket.fw_version == 2                   # no ticket of the old image
    m.mq.disconnect()
    plant.boot(m)                                                                # power cycle: it runs image 2 …
    assert m.d.fw == 2
    with loops(plant, m):
        assert wait_for(lambda: m.d.confirmed, 15), m.mq.errors
        assert plant.node.endpoint.current_session(M1).fw_version == 2           # … and says so
    assert list(plant.u.republished) == []                                       # nothing offered again (E-4)


def _cleaned_up(plant, art):
    """Publish `art`, then let the utility loop remove it once the retention window has passed."""
    plant.u.publish_artifact(art)
    real = plant.publisher.clock
    with loops(plant):
        plant.publisher.clock = lambda: real() + RETENTION_S + 1
        assert wait_for(lambda: not plant.publisher.live, 5)
    plant.publisher.clock = real


def test_E4_a_newer_firmware_that_is_no_longer_retained_is_offered_at_establishment(plant):
    """E-4, utility side: the device reports fw_version 1 in its handshake; the utility's newest FIRMWARE (2) was
    cleaned up after the retention window, so the utility republishes it (no device clock involved)."""
    m = plant.add(M1, "smart_meter")
    art = plant.artifact(FIRMWARE, "smart_meter", 2, os.urandom(9_000))
    start(plant)
    _cleaned_up(plant, art)
    with loops(plant, m):
        assert wait_for(lambda: FIRMWARE in m.mq.fota_staged, 20), (m.mq.errors, plant.u.refused)
    assert list(plant.u.republished) == [(M1, [FIRMWARE])]


def test_E4_a_stalled_download_asks_for_a_republish(plant):
    """E-4, device side: chunks lost before they reached flash are not sent again by the broker; after
    republish_stall_s with no progress the loop asks, the utility republishes, the download completes."""
    from pqgrid.fota.artifact import FotaError, decode_chunk
    m = plant.add(M1, "smart_meter")
    art = plant.artifact(FIRMWARE, "smart_meter", 2, os.urandom(40_000))
    real, lost, failed = m.fota.on_chunk, [True], []

    def flaky(raw):
        if lost[0] and decode_chunk(raw)[2] >= 1:
            failed.append(decode_chunk(raw)[2])
            raise FotaError("simulated: lost before it reached flash")
        return real(raw)
    m.fota.on_chunk = flaky
    start(plant)
    m.mq.republish_stall_s = 0.5
    with loops(plant, m, interval=0.02):
        assert wait_for(lambda: m.d.confirmed, 15)
        plant.u.publish_artifact(art)
        assert wait_for(lambda: sorted(failed) == [1, 2], 15)                  # both lost: the download stalls
        assert wait_for(lambda: m.mq.republish_requests == 1, 10)              # it asks …
        t0 = m.mq.ticks
        assert wait_for(lambda: m.mq.ticks >= t0 + 10, 5)                      # … and not again within the
        assert m.mq.republish_requests == 1                                    # stall period (still stalled)
        lost[0] = False                                                        # deliveries succeed from now on
        real_clock = plant.publisher.clock
        plant.publisher.clock = lambda: real_clock() + 3600                    # the utility's hour has passed
        assert wait_for(lambda: FIRMWARE in m.mq.fota_staged, 20), (m.mq.errors, plant.u.republished)
    assert m.mq.republish_requests == 2                                        # once per stall period
    assert list(plant.u.republished) == [(M1, [FIRMWARE]), (M1, [FIRMWARE])]


def test_E4_a_device_refused_for_an_old_policy_is_sent_the_current_one(plant):
    """E-4, utility side: v2 was activated while the device slept and its artifact is no longer retained; the
    device's CH (POLICY_INFO v1) is refused (G-1) and the utility republishes POLICY v2; the device installs it,
    activates it and establishes under v2."""
    import conftest
    m = plant.add(M1, "smart_meter")
    new = conftest.make_policy(plant.u_static.pk, plant.policy.utility_cmd_pk, version=2,
                               activate_at=int(time.time()) - 1)
    art = plant.sign_policy(new)
    start(plant)
    assert plant.u.activate_policy(art.signed, art.payload, plant.station.anchors)
    _cleaned_up(plant, art)
    with loops(plant, m):
        assert wait_for(lambda: m.d.policy.version == 2 and m.d.confirmed, 30), (m.mq.errors, plant.u.refused)
    assert (M1, [POLICY]) in list(plant.u.republished)
    assert any("POLICY_INFO mismatch" in r for r in plant.u.refused)


def test_M9_weekly_zone_rotation_is_done_by_the_utility_loop(plant):
    d = plant.add(D1, "der_ctrl")
    start(plant)
    with loops(plant, d):
        assert wait_for(lambda: d.d.confirmed, 15)
        plant.node.zones.create("f7")
        plant.u.join_zone("f7", D1)
        g = plant.node.zones.zones["f7"].groups[AeadAlg.CHACHA20POLY1305]
        e0 = g.key_epoch
        assert wait_for(lambda: max(d.proc.zones._keys.get(("f7", AeadAlg.CHACHA20POLY1305), {0: 0})) == e0, 10)
        t0 = plant.u.ticks
        assert wait_for(lambda: plant.u.ticks >= t0 + 3, 5)
        assert g.key_epoch == e0                                                # 3 ticks, not due: no rotation
        with plant.u.lock:
            g.rotated_at -= 7 * DAY                                             # the key is now a week old
        assert wait_for(lambda: g.key_epoch == e0 + 1, 10)                      # the loop rotated it …
        assert wait_for(lambda: max(d.proc.zones._keys[("f7", AeadAlg.CHACHA20POLY1305)]) == e0 + 1, 10)   # … sent it


class ScaledRng:
    """Records every full-jitter window it is asked for and waits 1/500 of it (seconds become milliseconds)."""

    def __init__(self):
        self.windows = []

    def uniform(self, a, b):
        self.windows.append(b)
        return b / 500


def test_M9_reconnect_back_off_grows_across_ticks_and_resets_on_success(plant, broker):
    """§10.5 in the production loop: with the broker down, each failed connect doubles the jitter window
    (2, 4, 8, … s, capped at 300 s) across ticks instead of restarting at 2; the loop ticks far more often than
    it connects (no storm); a CONNACK resets the count, and the next drop starts again at the base window."""
    m = plant.add(M1, "smart_meter")                                            # base 2 s, cap 300 s
    start(plant)
    rng = ScaledRng()
    with loops(plant, m, interval=0.002, rng=rng):
        assert wait_for(lambda: m.d.confirmed, 15), m.mq.errors
        n0, t0 = len(rng.windows), m.mq.ticks
        broker.stop()
        assert wait_for(lambda: len(rng.windows) >= n0 + 9, 30), rng.windows
        down = rng.windows[n0:n0 + 9]
        assert down == [2, 4, 8, 16, 32, 64, 128, 256, 300]                     # grows, then the cap
        attempts = m.mq._conn_attempt
        assert attempts >= 8 and m.mq.ticks - t0 >= 3 * attempts                # not an attempt per tick
        broker.start()
        assert wait_for(lambda: m.mq.connected.is_set(), 30), m.mq.errors
        assert wait_for(lambda: m.mq._conn_attempt == 0, 5)                    # a success resets it
        n1 = len(rng.windows)
        m.mq.c.disconnect()                                                    # the next drop …
        assert wait_for(lambda: len(rng.windows) > n1, 10)
        assert rng.windows[n1] == 2                                            # … starts at the base again
        assert wait_for(lambda: m.mq.connected.is_set() and m.d.confirmed, 30)


def test_E3_cumulative_and_final_setpoint_acks_through_the_device_loop(plant):
    """E-3 through the production loop over the broker: the first SETPOINT is acknowledged at once; the next ones
    wait for the 30 s interval, except that the GRANT's end (3 s here) triggers its final cumulative ACK."""
    d = plant.add(D1, "der_ctrl")
    start(plant)
    with loops(plant, d):
        assert wait_for(lambda: d.d.confirmed, 15)
        gid = plant.u.grant(D1, "P_ACTIVE_W", -5000, 5000, 12, 3)
        grant_seq = (plant.node.commands.epoch << 32) | 1

        def cumulative():
            return [s for s in plant.u.statuses if s == (D1, grant_seq, b"OK")]
        assert wait_for(lambda: len(cumulative()) == 1, 10)                      # the GRANT's own OK
        plant.u.setpoint(D1, gid, 1000, 30)
        assert wait_for(lambda: len(cumulative()) == 2, 10)                      # first SETPOINT: at once
        plant.u.setpoint(D1, gid, 2000, 30)
        assert wait_for(lambda: d.setpoints[-1:] == [("P_ACTIVE_W", 2000)], 10)
        assert wait_for(lambda: len(cumulative()) == 3, 10)                      # final ACK at the GRANT's end
        t0 = d.mq.ticks
        assert wait_for(lambda: d.mq.ticks >= t0 + 20, 10)
        assert len(cumulative()) == 3                                            # and only once
