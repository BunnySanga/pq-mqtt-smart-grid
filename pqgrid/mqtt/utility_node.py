"""The utility on the broker (Master §9.4, §10, §11, §13; IMPLEMENTATION-ROADMAP §11).

  * Answers CH/RH/DF on `pqgrid/hs/{id}/down`; a refused handshake is not answered (E49; G-1).
  * After every (re)establishment, sends queued commands (redelivery, §13.6), the device's zone keys and then its
    zones' still-valid DR events re-encrypted under the current group keys, all on its control topic (M4, M5).
  * A DR event is published once per crypto group of the logical zone (M7), after it is durably retained.
  * Opens alerts and ACKs them; an alert for an unknown session gets the resync hint on `hs/down` (DR-041, U-6).
  * Refuses to publish anything larger than the device's Maximum Packet Size: the broker would drop it silently
    and the device would never learn of it (§10.2, [DOCKER T1]).
  * Counts each device's "online" announcements (sent after every CONNACK): repeated connects raise a takeover
    (clone) alarm (§10.4, E52). Mosquitto 2.0.21 does not publish the Last Will of a session that is taken over
    [DOCKER, observed in this slice], so the Will alone cannot reveal a clone.
  * Connects with a persistent session, so device messages published while the utility restarts are kept.
  * run() is the utility's main loop (M9); each tick(): a scheduled policy is activated at activate_at (old-
    policy sessions closed, every zone key rotated, the ACL recompiled); zone keys at least a week old are
    rotated and sent to live members; retained artifacts past the retention window are removed; sessions whose
    chain ended and expired half-open handshakes are dropped.
"""
from __future__ import annotations

import threading
import time
from collections import deque

import paho.mqtt.client as mqtt
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.properties import Properties

from ..e2e.handshake import UnknownSessionError
from ..errors import EnvelopeError, PolicyMismatchError, PqgridError
from ..suite.kdf import ct_eq
from ..wire import peek_tag
from . import topics
from .guard import BoundedLog, guarded
from .topics import publish_size
from .device_node import TransportError

TAKEOVER_WINDOW_S, TAKEOVER_LIMIT = 600, 5
FIRMWARE_T, POLICY_T = 1, 2                                         # fota.artifact types (avoids an import cycle)
ZONE_ROTATE_EVERY_S = 7 * 86400                                     # key table §4.7: … and weekly


class UtilityMqtt:
    def __init__(self, node, tls_ctx, host: str, port: int, client_id: str = "utility", clock=time.time,
                 publisher=None, acl_hook=None):
        self.n, self.host, self.port, self.clock = node, host, port, clock
        self.publisher = publisher                                     # fota.publisher.Publisher, or None
        self.acl_hook = acl_hook                                       # recompile + reload the broker ACL, or None
        self.lock = threading.RLock()
        self.c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id, protocol=mqtt.MQTTv5)
        self.c.tls_set_context(tls_ctx)
        self.refused: list[str] = BoundedLog()                         # expected protocol refusals (G-1, local)
        self.internal_errors: list[tuple] = BoundedLog()               # unexpected: type + locations only (M8)
        self.c.suppress_exceptions = True
        self.c.on_connect = guarded(self, "connect", self._on_connect, self.refused, self.internal_errors)
        self.c.on_message = guarded(self, "message", self._on_message, self.refused, self.internal_errors)
        self._props = Properties(PacketTypes.CONNECT)
        self._props.SessionExpiryInterval = 86400
        self.connected = threading.Event()
        self.alerts: list[tuple[bytes, bytes, bool]] = []              # (device, payload, duplicate)
        self.telemetry: list[tuple[bytes, bytes]] = []
        self.statuses: list[tuple[bytes, int, bytes]] = []
        self.takeover_alarms: list[bytes] = []
        self._online: dict[bytes, deque] = {}
        self._scheduled = node.db.load_policy("scheduled")             # a verified policy awaiting activate_at
        self._unacked: list = []                                       # MQTTMessageInfo not yet PUBACKed
        self.ticks = 0                                                 # completed main-loop steps
        self.zone_syncs: list[tuple[bytes, str]] = BoundedLog()        # answered zone sync requests (E-2)
        self.republished: list[tuple[bytes, list]] = BoundedLog()      # proactive republishes (E-4)

    # ------------------------------------------------------------------------------------------ connection
    def start(self, timeout: float = 10.0) -> None:
        self.connected.clear()
        self.c.connect(self.host, self.port, keepalive=60, clean_start=False, properties=self._props)
        self.c.loop_start()
        if not self.connected.wait(timeout):
            raise TransportError("utility: no CONNACK")

    def stop(self, flush_timeout: float = 2.0) -> None:
        """Graceful: wait (briefly) until the broker has stored what was published, so a command queued just
        before shutdown is not lost with paho's in-memory queue."""
        self.flush(flush_timeout)
        self.c.disconnect()
        self.c.loop_stop()

    def _on_connect(self, client, userdata, flags, rc, props):
        client.subscribe([(t, 1) for t in topics.UTILITY_SUBSCRIPTIONS])
        self.connected.set()

    def _max_packet(self, device_id: bytes) -> int:
        rec = self.n.endpoint.registry.get(device_id)
        prof = self.n.endpoint.policy.profile(rec.dclass)
        return min(rec.max_packet or prof.max_packet, prof.max_packet)

    def _publish(self, device_id: bytes, topic: str, payload: bytes) -> None:
        size, limit = publish_size(topic, payload), self._max_packet(device_id)
        if size > limit:                                                 # §10.2: never send what gets dropped
            raise TransportError(f"{size} B PUBLISH exceeds {device_id.decode()}'s maximum packet size {limit} B")
        self._track(self.c.publish(topic, payload, qos=1))

    def _track(self, info) -> None:
        self._unacked = [i for i in self._unacked if not i.is_published()] + [info]

    def flush(self, timeout: float = 10.0) -> bool:
        """True once the broker has acknowledged (stored) every QoS 1 message this node published so far, e.g.
        before a graceful shutdown."""
        end = time.monotonic() + timeout
        for info in list(self._unacked):
            try:
                info.wait_for_publish(max(0.0, end - time.monotonic()))
            except (RuntimeError, ValueError):
                return False
        return all(i.is_published() for i in self._unacked)

    # ------------------------------------------------------------------------------------------- inbound
    def _on_message(self, client, userdata, m):
        payload = bytes(m.payload)
        try:
            kind, cls, who = topics.parse(m.topic)
            did = who.encode()
            with self.lock:
                if kind == "hs_up":
                    self._handshake(did, payload)
                elif kind == "alert":
                    self._alert_topic(did, m.topic, payload)
                elif kind == "telemetry":
                    self.telemetry.append((did, payload))
                elif kind == "status" and payload == b"online":
                    self._connects(did)
                elif kind == "fota_request" and self.publisher is not None:
                    rec = self.n.endpoint.registry.get(did)
                    if rec is None or not rec.active or rec.dclass != cls:
                        raise ValueError("republish request from an unknown device or the wrong class")
                    got = self.publisher.on_request(self.c, cls, did)       # E-4: rate-limited, valid only
                    if got:
                        self.republished.append((did, got))
        except (PqgridError, ValueError) as e:
            self.refused.append(f"{m.topic}: {e}")

    def _handshake(self, did: bytes, msg: bytes) -> None:
        u, tag = self.n.endpoint, peek_tag(msg)
        if tag == b"CH":
            try:
                sh = u.on_client_hello(did, msg)
            except PolicyMismatchError:
                self._offer(did, types={POLICY_T})                       # E-4: it needs the current policy
                raise
            self._publish(did, topics.hs_down(did), sh)
        elif tag == b"RH":
            self._publish(did, topics.hs_down(did), u.on_resume_hello(did, msg))
        elif tag == b"DF":
            res = u.on_finished(did, msg)
            self._publish(did, topics.hs_down(did), res.final)
            self.alerts += [(did, p, dup) for _, p, dup in res.alerts]
            if not res.replayed:
                self._flush(did)
                self._offer(did, types={FIRMWARE_T}, newer_than={FIRMWARE_T: res.session.fw_version},
                            only_missing=True)                           # E-4: a newer image it cannot see
        else:
            raise ValueError("unexpected handshake message")

    def _alert_topic(self, did: bytes, topic: str, env: bytes) -> None:
        tag = peek_tag(env)
        if tag == b"\x06":
            self.statuses.append(self.n.commands.on_status(env))
            return
        if tag == b"\x08":                                              # E-2: zone key sync request
            self._zone_sync(did, env)
            return
        try:
            payload, ack, dup = self.n.endpoint.open_alert(topic, env)
        except UnknownSessionError as e:                                 # after a restart: DR-041
            self._publish(did, topics.hs_down(did), e.hint)
            return
        self.alerts.append((did, payload, dup))
        rec = self.n.endpoint.registry.get(did)
        self._publish(did, topics.control(rec.dclass, did), ack)

    def _offer(self, did: bytes, **which) -> None:
        """E-4: a proactive republish for this device (rate-limited with its own requests)."""
        rec = self.n.endpoint.registry.get(did)
        if self.publisher is None or rec is None or not rec.active:
            return
        got = self.publisher.on_request(self.c, rec.dclass, did, **which)
        if got:
            self.republished.append((did, got))

    def _zone_sync(self, did: bytes, env: bytes) -> None:
        """Authenticated under the device's current session, then answered on its control topic (key first)."""
        from ..e2e.envelopes import open_zone_sync, zone_sync_sid
        s = self.n.endpoint.current_session(did)
        if s is None or not ct_eq(zone_sync_sid(env), s.sid):
            raise EnvelopeError("zone sync outside the device's current session")
        zone, _ = open_zone_sync(s, env)
        rec = self.n.endpoint.registry.get(did)
        for out in self.n.zones.sync_for(did, zone):
            self._publish(did, topics.control(rec.dclass, did), out)
        self.zone_syncs.append((did, zone))

    def _connects(self, did: bytes) -> None:
        now, q = self.clock(), self._online.setdefault(did, deque())
        q.append(now)
        while q and q[0] <= now - TAKEOVER_WINDOW_S:
            q.popleft()
        if len(q) >= TAKEOVER_LIMIT and did not in self.takeover_alarms:
            self.takeover_alarms.append(did)                             # repeated takeovers: a clone? (§10.4)

    # ---------------------------------------------------------------------------------- application API
    def _flush(self, did: bytes) -> None:
        rec, z = self.n.endpoint.registry.get(did), self.n.zones
        for env in self.n.commands.outgoing(did) + z.zonekeys_for(did) + z.resend_for(did):
            self._publish(did, topics.control(rec.dclass, did), env)      # one topic: keys before events

    def command(self, did: bytes, command: bytes, ttl_s: int, idempotent: bool = False) -> int:
        with self.lock:
            seq = self.n.commands.issue(did, command, ttl_s, idempotent)
            self._flush(did)
            return seq

    def grant(self, did: bytes, target: str, lo: int, hi: int, max_rate: int, ttl_s: int) -> bytes:
        with self.lock:
            gid, env = self.n.commands.grant(did, target, lo, hi, max_rate, ttl_s)
            self._publish(did, topics.control(self.n.endpoint.registry.get(did).dclass, did), env)
            return gid

    def setpoint(self, did: bytes, gid: bytes, value: int, ttl_s: int) -> None:
        with self.lock:
            env = self.n.commands.setpoint(did, gid, value, ttl_s)
            self._publish(did, topics.control(self.n.endpoint.registry.get(did).dclass, did), env)

    def join_zone(self, zone: str, did: bytes) -> None:
        with self.lock:
            self.n.zones.add_member(zone, did)
            self._send_zone_keys(zone)                                 # new epoch to every live member

    def revoke_device(self, did: bytes) -> None:
        """Live revocation (H1): durable registry change, sessions and half-open state invalidated, the device
        removed from its zones with new keys sent to the remaining members, then the broker ACL recompiled.
        E2E refusal does not depend on the last step."""
        with self.lock:
            self.n.endpoint.revoke_device(did)
            for zone in self.n.zones.remove_device(did):
                self._send_zone_keys(zone)
        if self.acl_hook:
            self.acl_hook()

    def _send_zone_keys(self, zone: str) -> None:
        for member, env in self.n.zones.distribute(zone).items():
            self._publish(member, topics.control(self.n.endpoint.registry.get(member).dclass, member), env)

    def publish_artifact(self, art) -> None:
        with self.lock:
            self.publisher.publish(self.c, art)

    def activate_policy(self, signed: bytes, payload: bytes, anchors: dict, revoked=frozenset()) -> bool:
        """At activate_at the utility switches to the verified new policy: old-policy sessions and tickets are
        refused from then on (P5, P10), every zone key rotates (key table §4.7; members get the new keys when
        they re-handshake) and the broker ACL is recompiled from the new policy. False while not yet due."""
        from ..fota.policy_artifact import verify_policy_artifact
        from ..policy import validate
        p = verify_policy_artifact(signed, payload, anchors, revoked)
        if self.clock() < p.activate_at:
            return False
        with self.lock:
            validate(p, installed_version=self.n.endpoint.policy.version)
            self.n.db.save_policy("active", signed, payload, anchors, revoked)   # durable before it takes effect
            self.n.endpoint.install_policy(p)                        # old-policy sessions closed (M1)
            self.n.zones.rotate_all()
            if self.publisher is not None:
                self.publisher.policy = p
        if self.acl_hook:
            self.acl_hook()
        return True

    def schedule_policy(self, signed: bytes, payload: bytes, anchors: dict, revoked=frozenset()) -> None:
        """Keep a verified policy until its activate_at; tick() activates it (§12 Policy Distribution)."""
        from ..fota.policy_artifact import verify_policy_artifact
        from ..policy import validate
        p = verify_policy_artifact(signed, payload, anchors, revoked)  # a bad artifact is refused now …
        validate(p, installed_version=self.n.endpoint.policy.version)  # … and so is one that is not newer
        self.n.db.save_policy("scheduled", signed, payload, anchors, revoked)   # survives a restart (U-4)
        self._scheduled = (signed, payload, anchors, frozenset(revoked))

    # ------------------------------------------------------------------------------------------ main loop
    def run(self, stop: threading.Event, interval: float = 1.0) -> None:
        from .guard import EXPECTED, internal_alarm
        while not stop.is_set():
            try:
                self.tick()
            except EXPECTED as e:
                self.refused.append(f"tick: {e}")
            except Exception as e:
                self.internal_errors.append(internal_alarm("tick", e))
            stop.wait(interval)

    def tick(self) -> None:
        from .guard import EXPECTED
        if self._scheduled is not None:
            try:
                if self.activate_policy(*self._scheduled):
                    self._forget_scheduled()
            except EXPECTED as e:
                # A refusal is final (its signature, the anchors and the installed version can only keep it
                # refused, e.g. a newer policy was activated meanwhile): drop it, as the device's installer does,
                # so it cannot abort the housekeeping below on every tick.
                self._forget_scheduled()
                self.refused.append(f"scheduled policy refused at activation: {e}")
        with self.lock:
            for zone in self.n.zones.rotate_due(ZONE_ROTATE_EVERY_S):
                self._send_zone_keys(zone)
            if self.publisher is not None:
                self.publisher.cleanup(self.c)
            self.n.endpoint.sweep()
        self.ticks += 1

    def _forget_scheduled(self) -> None:
        self.n.db.drop_policy("scheduled")
        self._scheduled = None

    def dr_event(self, zone: str, event: bytes, ttl_s: int) -> int:
        """One logical event, one publication per crypto group (M7). Returns the number of publications."""
        def fits(alg, topic, env):                                       # every member's limit, before retaining
            for member in self.n.zones.members_of(zone, alg):
                if publish_size(topic, env) > self._max_packet(member):
                    raise TransportError(f"DR event too large for {member.decode()}")
        with self.lock:
            pubs = self.n.zones.publish(zone, event, ttl_s, fits)
            for topic, env in pubs.items():
                self._track(self.c.publish(topic, env, qos=1))
            return len(pubs)
