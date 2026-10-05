"""Codex audit P1-2 (2026-10-03, IMPLEMENTATION-ROADMAP §16): a utility-side publish that does not reach the broker
must never leave the utility believing that a command or an artifact went out.

paho 2.1.0 keeps a QoS 1 message published while the client is disconnected (rc = MQTT_ERR_NO_CONN) and sends it
after reconnecting [DOCKER, tests/integration/test_publish_outage.py], but the MQTTMessageInfo it returned keeps that
rc for good and raises whenever it is asked whether the message was published. Before the fix the utility's own
bookkeeping asked exactly that on every later publish, so ONE publish during a broker outage made every later one
raise until the utility restarted: the commands, zone keys and DR re-sends that follow an establishment were not sent.

In-process here, with paho's real MQTTMessageInfo and the utility on SQLite; PUBACKs are delivered by hand."""
import os
import ssl

import paho.mqtt.client as mqtt
import pytest
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.reasoncodes import ReasonCode

from test_restart import Plant
from pqgrid.e2e.envelopes import control_topic
from pqgrid.mqtt.device_node import TransportError
from pqgrid.fota.artifact import FIRMWARE
from pqgrid.fota.publisher import part_payload_budget
from pqgrid.fota.station import Station, find_openssl
from pqgrid.mqtt.utility_node import UtilityMqtt
from pqgrid.persistence.utility_db import SqlPublisher
from pqgrid.suite.sig import slh_available

D1 = b"der-0001"
requires_station = pytest.mark.skipif(find_openssl() is None or not slh_available(),
                                      reason="needs OpenSSL >= 3.5 with SLH-DSA (runs in the Docker test image)")


class Paho:
    """Stands in for paho's client: publish() hands out paho's own MQTTMessageInfo with the rc paho would report;
    puback() does what paho does when the broker acknowledges (the on_publish callback, then the info is marked)."""

    def __init__(self):
        self.rc, self.mid, self.queued, self.refused = mqtt.MQTT_ERR_SUCCESS, 0, [], set()

    def publish(self, topic, payload, qos=1, retain=False):
        self.mid += 1
        info = mqtt.MQTTMessageInfo(self.mid)
        info.rc = self.rc
        if self.rc in (mqtt.MQTT_ERR_SUCCESS, mqtt.MQTT_ERR_NO_CONN):    # what paho keeps in its queue
            self.queued.append((topic, bytes(payload), retain, info))
        return info

    def puback(self, u: UtilityMqtt, ok: bool = True, only=None) -> None:
        for topic, _, _, info in self.queued:
            if (only is None or only(topic)) and not info._published:
                u._on_publish(self, None, info.mid, ReasonCode(PacketTypes.PUBACK, "Success" if ok else
                                                               "Not authorized"), None)
                info._set_as_published()
                if not ok:
                    self.refused.add(info.mid)                        # the broker did not take it

    def topics(self) -> list[str]:
        return [t for t, _, _, _ in self.queued]


def utility(p: Plant, publisher=None) -> tuple[UtilityMqtt, Paho]:
    u = UtilityMqtt(p.node, ssl.create_default_context(), "localhost", 1, clock=lambda: p.t, publisher=publisher)
    u.c = Paho()
    return u, u.c


def applied_on_device(dev, paho: Paho) -> list[bytes]:
    """The broker delivers what paho queued since the last call (each envelope once: the device refuses a replay)."""
    topic, start = control_topic(dev.dclass, dev.did), getattr(paho, "delivered", 0)
    for t, env, _, info in paho.queued[start:]:
        if t == topic and info.mid not in paho.refused:
            dev.proc.on_control(topic, env)
    paho.delivered = len(paho.queued)
    return dev.applied


# =================================================================================================== commands
def test_a_publish_made_during_a_broker_outage_does_not_break_every_later_publish(tmp_path):
    p = Plant(tmp_path)
    d = p.device(D1, "der_ctrl")
    p.full(d)
    u, paho = utility(p)
    paho.rc = mqtt.MQTT_ERR_NO_CONN                                       # the broker is down
    first = u.command(D1, b"CMD-1", 600)                                  # paho keeps it for the reconnect
    paho.rc = mqtt.MQTT_ERR_SUCCESS                                       # reconnected
    second = u.command(D1, b"CMD-2", 600)                                 # before the fix: RuntimeError
    assert applied_on_device(d, paho) == [b"CMD-1", b"CMD-2"]             # each sent once in this session
    assert not u.flush(0.05)                                              # nothing acknowledged yet …
    paho.puback(u)
    assert u.flush(0.05)                                                  # … now the broker has both
    assert u.n.commands.outcome(D1, first) is None and u.n.commands.outcome(D1, second) is None   # open until
    #                                                                       the device's status ACK, never earlier


def test_a_command_the_client_did_not_queue_is_not_counted_as_sent(tmp_path):
    """paho refuses to queue (MQTT_ERR_QUEUE_SIZE): the command stays unsent in this session, so the next flush sends
    it, and if it expires before that it is EXPIRED (never sent), not UNKNOWN (perhaps executed)."""
    p = Plant(tmp_path)
    d = p.device(D1, "der_ctrl")
    p.full(d)
    u, paho = utility(p)
    paho.rc = mqtt.MQTT_ERR_QUEUE_SIZE
    with pytest.raises(TransportError, match="not queued"):
        u.command(D1, b"CMD-1", 600)                                      # before the fix: no error at all
    store = p.node.commands.store
    [q] = store.open_commands(D1)
    assert (q.sends, q.last_sid) == (0, b"")                              # the record of the attempt is undone
    paho.rc = mqtt.MQTT_ERR_SUCCESS
    u.command(D1, b"CMD-2", 600)                                          # the next flush sends both
    assert applied_on_device(d, paho) == [b"CMD-1", b"CMD-2"]
    paho.rc = mqtt.MQTT_ERR_QUEUE_SIZE
    with pytest.raises(TransportError):
        u.command(D1, b"CMD-3", 10)
    [late] = [q.cmd.cmd_seq for q in store.open_commands(D1) if q.cmd.command == b"CMD-3"]
    p.t += 11
    paho.rc = mqtt.MQTT_ERR_SUCCESS
    u.command(D1, b"CMD-4", 600)
    assert p.node.commands.outcome(D1, late) == b"EXPIRED"                # never sent: not UNKNOWN
    assert applied_on_device(d, paho) == [b"CMD-1", b"CMD-2", b"CMD-4"]


def test_a_command_the_broker_refused_is_sent_again_in_the_same_session(tmp_path):
    """Second Codex review, finding 1: a PUBACK with a failure reason code (e.g. a stale ACL) means the command never
    reached the device. Before the fix it stayed recorded as sent in that session, so no later flush of the session
    sent it again. Now its record is undone and the device's commands go again after retry_every_s."""
    p = Plant(tmp_path)
    d = p.device(D1, "der_ctrl")
    p.full(d)
    u, paho = utility(p)
    seq = u.command(D1, b"CMD-A", 600)
    paho.puback(u, ok=False)                                              # the broker refused it
    u.tick()
    [q] = p.node.commands.store.open_commands(D1)
    assert (q.cmd.cmd_seq, q.sends, q.last_sid) == (seq, 0, b"")          # not counted as sent any more
    n = len(paho.queued)
    p.t += u.retry_every_s - 1
    u.tick()
    assert len(paho.queued) == n                                          # not before retry_every_s
    p.t += 1
    u.tick()
    assert len(paho.queued) == n + 1                                      # CMD-A again, in the same session
    paho.puback(u)
    u.tick()
    assert applied_on_device(d, paho) == [b"CMD-A"]                       # it reached the device once
    p.t += u.retry_every_s
    u.tick()
    assert len(paho.queued) == n + 1                                      # accepted: never sent again


def test_the_client_queue_and_the_tracking_are_bounded_while_the_broker_is_down(tmp_path):
    """Second Codex review, finding 6: during a broker outage paho kept every publish in memory and the utility's
    tracking grew with it (and was rebuilt in full on every publish). paho now holds at most CLIENT_QUEUE_MAX; the
    next publish is not queued (TransportError, which the command and artifact paths handle: P1-2)."""
    from pqgrid.mqtt.utility_node import CLIENT_QUEUE_MAX, UNACKED_TRACKED
    p = Plant(tmp_path)
    u = UtilityMqtt(p.node, ssl.create_default_context(), "localhost", 1, clock=lambda: p.t)   # real paho, offline
    for i in range(CLIENT_QUEUE_MAX):
        u._send("pqgrid/test", b"%d" % i)                                 # rc 4: kept for the reconnect
    with pytest.raises(TransportError, match="not queued"):
        u._send("pqgrid/test", b"one too many")
    assert len(u._unacked) <= UNACKED_TRACKED                             # (private: the tracking's size)


def test_open_commands_per_device_are_capped(tmp_path):
    """Second Codex review, finding 6: commands had no per-device quota. The cap is above the device's own
    MAX_INTENTS, so the device's REJECTED path is unchanged."""
    from pqgrid.commands.device import MAX_INTENTS
    from pqgrid.commands.utility import MAX_QUEUED_COMMANDS
    from pqgrid.errors import CommandError
    assert MAX_QUEUED_COMMANDS > MAX_INTENTS
    p = Plant(tmp_path)
    p.device(D1, "der_ctrl")
    svc = p.node.commands
    for i in range(MAX_QUEUED_COMMANDS):
        svc.issue(D1, b"C%d" % i, 600)
    with pytest.raises(CommandError, match="already open"):
        svc.issue(D1, b"one too many", 600)


def test_a_status_ack_reply_and_a_dr_event_are_tracked_like_any_other_publish(tmp_path):
    """The other utility publishes (handshake replies, zone keys, DR events) go through the same tracking."""
    p = Plant(tmp_path)
    d = p.device(D1, "der_ctrl")
    p.full(d)
    u, paho = utility(p)
    p.node.zones.create("f7")
    paho.rc = mqtt.MQTT_ERR_NO_CONN
    u.join_zone("f7", D1)                                                 # its zone key: queued for the reconnect
    paho.rc = mqtt.MQTT_ERR_SUCCESS
    assert u.dr_event("f7", b"SHED 10%", 600) == 1                        # before the fix: RuntimeError
    paho.puback(u)
    assert u.flush(0.05)


# ======================================================================================================= FOTA
@pytest.fixture(scope="module")
def station(tmp_path_factory):
    if find_openssl() is None or not slh_available():
        pytest.skip("needs OpenSSL >= 3.5 with SLH-DSA (runs in the Docker test image)")
    return Station(str(tmp_path_factory.mktemp("station")))


def firmware(p: Plant, station, version=2):
    prof = p.policy.profile("smart_meter")
    return station.build(FIRMWARE, "smart_meter", version, os.urandom(9000), prof.fota_chunk_size,
                         part_payload_budget(prof.max_packet, "smart_meter", FIRMWARE, version))


def art_topics(paho: Paho, art) -> list[str]:
    return [t for t in paho.topics() if f"/firmware/{art.manifest.version}/" in t]


@requires_station
def test_an_artifact_counts_as_retained_only_once_the_broker_acknowledged_every_message(tmp_path, station):
    p = Plant(tmp_path)
    u, paho = utility(p, SqlPublisher(p.node.db, p.policy, clock=lambda: p.t))
    art = firmware(p, station)
    paho.rc = mqtt.MQTT_ERR_NO_CONN                                       # broker down: paho keeps every message
    u.publish_artifact(art)
    key = ("smart_meter", FIRMWARE)
    assert u.publisher.live[key].confirmed is False
    u.tick()
    assert u.publisher.live[key].confirmed is False                       # nothing acknowledged yet
    paho.puback(u, only=lambda t: t.endswith("/manifest/0"))
    u.tick()
    assert u.publisher.live[key].confirmed is False                       # one message is not the artifact
    paho.puback(u)
    u.tick()
    assert u.publisher.live[key].confirmed is True
    assert SqlPublisher(p.node.db, p.policy, clock=lambda: p.t).live[key].confirmed is True   # durable


@requires_station
def test_an_artifact_that_never_reached_the_broker_is_published_again_after_a_utility_restart(tmp_path, station):
    """Before the fix the database said "retained" from the moment the publication started, so a utility that
    restarted before the broker had stored the messages (they were only in paho's memory) never sent them again:
    the E-4 offer at establishment skips an artifact it believes retained, for the whole 30-day window."""
    p = Plant(tmp_path)
    u, paho = utility(p, SqlPublisher(p.node.db, p.policy, clock=lambda: p.t))
    art = firmware(p, station)
    paho.rc = mqtt.MQTT_ERR_NO_CONN
    u.publish_artifact(art)                                               # only in paho's memory …
    p.restart()                                                           # … which the restart loses
    u, paho = utility(p, SqlPublisher(p.node.db, p.policy, clock=lambda: p.t))
    u.tick()
    expected = [t for t, _ in u.publisher.messages(art)]
    assert art_topics(paho, art) == expected                              # published again, every message …
    assert all(retain for t, _, retain, _ in paho.queued)                 # … retained
    paho.puback(u)
    u.tick()
    u.tick()
    assert art_topics(paho, art) == expected                              # once: confirmed now, not again
    assert u.publisher.live[("smart_meter", FIRMWARE)].confirmed is True


@requires_station
def test_an_artifact_message_the_broker_refused_is_published_again(tmp_path, station):
    """A PUBACK with a failure reason code (e.g. 0x87 Not authorized: a stale broker ACL) is not acceptance: the
    artifact stays unconfirmed and is published again after retry_every_s, until the broker takes it."""
    p = Plant(tmp_path)
    u, paho = utility(p, SqlPublisher(p.node.db, p.policy, clock=lambda: p.t))
    art = firmware(p, station)
    u.publish_artifact(art)
    paho.puback(u, ok=False, only=lambda t: t.endswith("/chunk/0"))
    paho.puback(u)
    u.tick()
    key = ("smart_meter", FIRMWARE)
    assert u.publisher.live[key].confirmed is False and any("Not authorized" in r for r in u.publish_refusals)
    n = len(paho.queued)
    u.tick()
    assert len(paho.queued) == n                                          # not before retry_every_s …
    p.t += u.publisher.retry_every_s
    u.tick()
    assert len(paho.queued) == n + len(u.publisher.messages(art))         # … then the whole artifact again
    paho.puback(u)
    u.tick()
    assert u.publisher.live[key].confirmed is True


@requires_station
def test_an_unconfirmed_artifact_that_is_no_longer_valid_is_not_published_again(tmp_path, station):
    """retry() never resurrects what is no longer valid (E-4's rule): release anchor A is revoked while its firmware
    is still unconfirmed, so the restarted utility does not publish it again."""
    from pqgrid.fota.artifact import ANCHOR_A
    p = Plant(tmp_path)
    u, paho = utility(p, SqlPublisher(p.node.db, p.policy, clock=lambda: p.t))
    art = firmware(p, station)
    assert art.manifest.signer_anchor_id == ANCHOR_A
    paho.rc = mqtt.MQTT_ERR_NO_CONN
    u.publish_artifact(art)
    p.node.db.add_revoked(ANCHOR_A)                                       # a KEYREVOKE published meanwhile
    p.restart()
    u, paho = utility(p, SqlPublisher(p.node.db, p.policy, clock=lambda: p.t))
    u.tick()
    assert paho.queued == []
