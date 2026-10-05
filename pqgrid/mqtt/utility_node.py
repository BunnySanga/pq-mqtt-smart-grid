"""The utility on the broker (Master §9.4, §10, §11, §13; IMPLEMENTATION-ROADMAP §11).

  * Answers CH/RH/DF on `pqgrid/hs/{id}/down`; a refused handshake is not answered (E49; G-1).
  * After every (re)establishment, sends queued commands (redelivery, §13.6), the device's zone keys and then its
    zones' still-valid DR events re-encrypted under the current group keys, all on its control topic (M4, M5).
  * A DR event is published once per crypto group of the logical zone (M7), after it is durably retained.
  * Opens alerts and ACKs them; an alert for an unknown session gets the resync hint on `hs/down` (DR-041, U-6).
  * Refuses to publish anything larger than the device's Maximum Packet Size: the broker would drop it silently
    and the device would never learn of it (§10.2, [DOCKER T1]).
  * Tracks every QoS 1 publish until the broker's PUBACK (Codex audit P1-2, IMPLEMENTATION-ROADMAP §16). A publish
    made while disconnected (MQTT_ERR_NO_CONN) is not a failure: paho keeps it and sends it after reconnecting
    [DOCKER]. Only a publish paho did not queue is one (TransportError), and then nothing counts it as sent. A PUBACK
    with a failure reason code is recorded (publish_refusals); an artifact is confirmed only when all its messages
    were accepted, and tick() publishes an unconfirmed one again.
  * Counts each device's "online" announcements (sent after every CONNACK): repeated connects raise a takeover
    (clone) alarm (§10.4, E52). Mosquitto 2.0.21 does not publish the Last Will of a session that is taken over
    [DOCKER, observed in this slice], so the Will alone cannot reveal a clone.
  * Connects with a persistent session, so device messages published while the utility restarts are kept.
  * run() is the utility's main loop (M9); each tick(): an owed ACL recompile is retried (L-1); a scheduled policy is
    activated at activate_at (old-policy sessions closed, every zone key rotated, the ACL recompiled); zone keys at
    least a week old are
    rotated and sent to live members; retained artifacts past the retention window are removed; sessions whose
    chain ended and expired half-open handshakes are dropped.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from typing import Optional

import paho.mqtt.client as mqtt
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.properties import Properties

from ..e2e.handshake import UnknownSessionError
from ..errors import EnvelopeError, PolicyError, PolicyMismatchError, PqgridError, TicketReusedError
from ..suite.kdf import ct_eq
from ..wire import peek_tag
from . import topics
from .guard import BoundedLog, guarded
from .topics import publish_size
from .device_node import TransportError

TAKEOVER_WINDOW_S, TAKEOVER_LIMIT = 600, 5
REFUSAL_MEMORY_S, REFUSALS_KEPT = 600, 1024    # refused PUBACKs kept for matching against tracked publishes
INBOX_CAP = 1000                               # entries per application inbox (alerts, telemetry, statuses, alarms)
CLIENT_QUEUE_MAX = 4096        # messages paho may hold (in flight + waiting for a reconnect); beyond: not queued,
#                                which the publishers handle (P1-2): backpressure during a broker outage (finding 6)
UNACKED_TRACKED = 1024         # utility publishes tracked for flush() (about 20 are in flight while connected);
#                                during an outage the oldest beyond this are no longer waited for
COMMAND_RETRY_S = 60           # a command the broker refused is sent again after this (second Codex review, finding 1)
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
        self.c.max_queued_messages_set(CLIENT_QUEUE_MAX)
        self.refused: list[str] = BoundedLog()                         # expected protocol refusals (G-1, local)
        self.internal_errors: list[tuple] = BoundedLog()               # unexpected: type + locations only (M8)
        self.c.suppress_exceptions = True
        self.c.on_connect = guarded(self, "connect", self._on_connect, self.refused, self.internal_errors)
        self.c.on_message = guarded(self, "message", self._on_message, self.refused, self.internal_errors)
        self.c.on_publish = guarded(self, "publish", self._on_publish, self.refused, self.internal_errors)
        self._props = Properties(PacketTypes.CONNECT)
        self._props.SessionExpiryInterval = 86400
        self.connected = threading.Event()
        # What the utility hands its application, bounded (Codex audit C): the application drains them; an overflow
        # drops the oldest entries and counts them (`dropped`), so valid traffic cannot grow the utility's memory.
        self.alerts: list[tuple[bytes, bytes, bool]] = BoundedLog(INBOX_CAP)   # (device, payload, duplicate)
        self.telemetry: list[tuple[bytes, bytes]] = BoundedLog(INBOX_CAP)
        self.statuses: list[tuple[bytes, int, bytes]] = BoundedLog(INBOX_CAP)
        self.takeover_alarms: list[bytes] = BoundedLog(INBOX_CAP)
        self.ticket_reuse_alarms: list[tuple[bytes, float]] = BoundedLog()   # "ticket already used" (M-1, §27.8)
        self._online: dict[bytes, deque] = {}
        self._scheduled = node.db.load_policy("scheduled")             # a verified policy awaiting activate_at
        self._recheck_scheduled()                                      # M-1: revocations since it was scheduled
        self._unacked: deque = deque()                                 # MQTTMessageInfo not yet PUBACKed, oldest first
        self._cmd_pubs: list = BoundedLog(UNACKED_TRACKED)             # (info, device, cmd_seq, sid) awaiting PUBACK
        self._cmd_retry: dict[bytes, float] = {}                       # device → when its refused commands go again
        self.retry_every_s = COMMAND_RETRY_S
        self._ack_lock = threading.Lock()                              # never held while calling into paho
        self._refused_mids: OrderedDict[int, float] = OrderedDict()    # mid → when its PUBACK refused it
        self.publish_refusals: list[str] = BoundedLog()                # refused PUBACKs, publishes paho did not queue
        self._fota_out = _FotaClient(self)                             # what the publisher publishes through
        self.ticks = 0                                                 # completed main-loop steps
        self.zone_syncs: list[tuple[bytes, str]] = BoundedLog()        # answered zone sync requests (E-2)
        self.acl_failures: list[tuple] = BoundedLog()                  # failed ACL hook runs (type + locations)
        self._acl_due = False                                          # an ACL recompile is owed (retried by tick)
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
        return self._send(topic, payload)

    def _send(self, topic: str, payload: bytes, retain: bool = False):
        """Hand one QoS 1 message to paho and track it until the broker acknowledges it; returns its MQTTMessageInfo.
        MQTT_ERR_NO_CONN is NOT a failure: paho keeps the message and sends it after reconnecting [DOCKER], but the
        info keeps that rc and then raises whenever it is asked whether it was published, which made every later
        publish raise (P1-2). Its rc is therefore reset, so the info reports the PUBACK like any other. Any other rc
        (MQTT_ERR_QUEUE_SIZE in paho 2.1.0) means paho did not keep the message: TransportError, nothing sent.
        Callers hold self.lock, which also guards _unacked (pruned from the oldest end: amortised O(1), bounded)."""
        info = self.c.publish(topic, payload, qos=1, retain=retain)
        if info.rc == mqtt.MQTT_ERR_NO_CONN:
            info.rc = mqtt.MQTT_ERR_SUCCESS                              # queued by paho for the reconnect
        elif info.rc != mqtt.MQTT_ERR_SUCCESS:
            self.publish_refusals.append(f"{topic}: not queued by the client: {mqtt.error_string(info.rc)}")
            raise TransportError(f"{topic}: not queued by the client ({mqtt.error_string(info.rc)})")
        while self._unacked and self._unacked[0].is_published():
            self._unacked.popleft()
        self._unacked.append(info)
        if len(self._unacked) > UNACKED_TRACKED:                         # finding 6: no unbounded tracking
            self._unacked.popleft()
        return info

    def _on_publish(self, client, userdata, mid, reason_code, properties) -> None:
        """paho's PUBACK callback (on its own thread, holding its own lock: only in-memory bookkeeping here). paho
        marks the message published after this returns, whatever the reason code, so a refusal is recorded first."""
        if not reason_code.is_failure:
            return
        now = time.monotonic()
        with self._ack_lock:
            self._refused_mids[mid] = now
            while self._refused_mids and (len(self._refused_mids) > REFUSALS_KEPT or
                                          next(iter(self._refused_mids.values())) < now - REFUSAL_MEMORY_S):
                self._refused_mids.popitem(last=False)
        self.publish_refusals.append(f"mid {mid}: {reason_code}")

    def _acked(self, info) -> Optional[bool]:
        """True: the broker accepted the message; False: its PUBACK refused it; None: no answer yet."""
        if info is None or not info.is_published():
            return None
        with self._ack_lock:
            return self._refused_mids.pop(info.mid, None) is None

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
                elif kind == "telemetry":                            # hop-only tier: the broker ACL admits it,
                    rec = self.n.endpoint.registry.get(did)          # the registry decides (H1: revocation must
                    if rec is None or not rec.active or rec.dclass != cls:   # not wait for an ACL recompile)
                        raise ValueError("telemetry from an unknown or revoked device, or on another class's topic")
                    self.telemetry.append((did, payload))
                elif kind == "status" and payload == b"online":
                    self._connects(did)
                elif kind == "fota_request" and self.publisher is not None:
                    rec = self.n.endpoint.registry.get(did)
                    if rec is None or not rec.active or rec.dclass != cls:
                        raise ValueError("republish request from an unknown device or the wrong class")
                    got = self.publisher.on_request(self._fota_out, cls, did)   # E-4: rate-limited, valid only
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
            try:
                rs = u.on_resume_hello(did, msg)
            except TicketReusedError:
                self.ticket_reuse_alarms.append((did, self.clock()))     # M-1 (§27.8): a clone indicator
                raise
            self._publish(did, topics.hs_down(did), rs)
        elif tag == b"DF":
            res = u.on_finished(did, msg)
            self.alerts += [(did, p, dup) for _, p, dup in res.alerts]   # to the application BEFORE the reply is
            self._publish(did, topics.hs_down(did), res.final)           # published: a failed publish cannot lose them
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
        got = self.publisher.on_request(self._fota_out, rec.dclass, did, **which)
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
        """Commands first, each handed over right after it is recorded as sent (a publish that is not queued undoes
        its record and stops the flush: P1-2), then zone keys and DR re-sends (nothing records those as sent)."""
        z = self.n.zones
        topic = self._send_commands(did)
        for env in z.zonekeys_for(did) + z.resend_for(did):
            self._publish(did, topic, env)                               # one topic: keys before events

    def _send_commands(self, did: bytes) -> str:
        """The device's open commands for its live session, each followed to its PUBACK (finding 1: a refusing PUBACK
        undoes the command's sent record and the device's commands go again after retry_every_s)."""
        rec, s = self.n.endpoint.registry.get(did), self.n.endpoint.current_session(did)
        topic = topics.control(rec.dclass, did)

        def send(env: bytes, cmd_seq: int) -> None:
            self._cmd_pubs.append((self._publish(did, topic, env), did, cmd_seq, s.sid))
        self.n.commands.outgoing(did, send=send)
        return topic

    def _settle_commands(self) -> None:
        """Second Codex review, finding 1 (tick): a command whose PUBLISH the broker refused never reached the device,
        so its record of being sent in that session is undone and the device's commands go again, at most once per
        retry_every_s (a broker that keeps refusing is not hammered). Accepted ones are simply forgotten."""
        now, keep = self.clock(), []
        for entry in list(self._cmd_pubs):
            info, did, cmd_seq, sid = entry
            ok = self._acked(info)
            if ok is None:
                keep.append(entry)
            elif ok is False and self.n.commands.unsend(did, cmd_seq, sid):
                self._cmd_retry.setdefault(did, now + self.retry_every_s)
        self._cmd_pubs.drain()
        self._cmd_pubs.extend(keep)
        for did, at in list(self._cmd_retry.items()):
            if now < at:
                continue
            del self._cmd_retry[did]
            if self.n.endpoint.current_session(did) is None:
                continue                                                 # its next establishment sends them
            try:
                self._send_commands(did)
            except PqgridError as e:
                self.refused.append(f"command retry for {did.decode()}: {e}")

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
        """The new member's read right (§10.1 ACL) is compiled and the broker told BEFORE its key goes out: Mosquitto
        grants a SUBACK without the right and filters at delivery, so a member subscribing on its key ahead of the
        reload would silently lose the next events. Mosquitto handles the reload signal at the end of a pass of its
        loop, before it forwards a key published after the signal (observed, not specified: Master §25 L23). A
        failed hook is retried by tick() (L-1); the key is sent regardless."""
        with self.lock:
            self.n.zones.add_member(zone, did)
            self._acl_due = True
            self.recompile_acl()
            self._send_zone_keys(zone)                                 # new epoch to every live member

    def revoke_device(self, did: bytes) -> None:
        """Live revocation (H1): durable registry change, sessions and half-open state invalidated, the device
        removed from its zones with new keys sent to the remaining members, then the broker ACL recompiled.
        E2E refusal does not depend on the last step."""
        with self.lock:
            self.n.endpoint.revoke_device(did)
            for zone in self.n.zones.remove_device(did):
                self._send_zone_keys(zone)
        self._acl_due = True
        self.recompile_acl()

    def reprovision_device(self, rec) -> None:
        """Codex audit P1-1: the device's class and/or E2E key change (UtilityNode.reprovision: its sessions, tickets,
        open commands, GRANTs and zone keys end), the remaining members of its zones get the new keys, and the broker
        ACL is recompiled for the new record (its class decides its topics). The device establishes again under its
        new identity; a failed ACL hook is retried by tick() (L-1). The new zone keys go out even if the record change
        fails after the rotation (second Codex review, finding 5); the error is then raised and the ACL is untouched."""
        def send_keys(zones: list[str]) -> None:
            for zone in zones:
                try:
                    self._send_zone_keys(zone)
                except PqgridError as e:
                    self.refused.append(f"zone keys for {zone} after a re-provisioning: {e}")
        with self.lock:
            self.n.reprovision(rec, rotated=send_keys)
        self._acl_due = True
        self.recompile_acl()

    def _send_zone_keys(self, zone: str) -> None:
        for member, env in self.n.zones.distribute(zone).items():
            self._publish(member, topics.control(self.n.endpoint.registry.get(member).dclass, member), env)

    def publish_artifact(self, art) -> None:
        """Retained until the retention window ends; confirmed once the broker has acknowledged every message, and
        published again by tick() while it is not (P1-2)."""
        with self.lock:
            self.publisher.publish(self._fota_out, art)

    def prepare_keys(self, kem=None, cmd=None, expect_kem_pk: bytes | None = None,
                     expect_cmd_pk: bytes | None = None) -> None:
        """Hold the private keys a coming policy will name (a rotation, DR-051), durably, before that policy is
        scheduled. `expect_*` refuses a private key that does not match the public key meant to be prepared."""
        with self.lock:
            self.n.keyring.add(kem=kem, cmd=cmd, expect_kem_pk=expect_kem_pk, expect_cmd_pk=expect_cmd_pk)

    def activate_policy(self, signed: bytes, payload: bytes, anchors: dict, revoked=frozenset()) -> bool:
        """At activate_at the utility switches to the verified new policy: old-policy sessions and tickets are
        refused from then on (P5, P10), every zone key rotates (key table §4.7; members get the new keys when
        they re-handshake) and the broker ACL is recompiled from the new policy. False while not yet due.
        The utility then operates with the private keys the policy names (DR-051); a policy whose keys it does not
        hold is refused before anything changes (KeyringError)."""
        from ..fota.policy_artifact import verify_policy_artifact
        from ..policy import validate
        revoked = self.revoked_anchors() | set(revoked)             # M-1: the revocations of NOW, not a snapshot
        p = verify_policy_artifact(signed, payload, anchors, revoked)
        if self.clock() < p.activate_at:
            return False
        with self.lock:
            validate(p, installed_version=self.n.endpoint.policy.version)
            static, cmd_key = self.n.keyring.keys_for(p)             # H-1: refused before any state changes
            self.n.zones.rotate_all()                                # first: a crash then leaves the old policy
            self.n.db.save_policy("active", signed, payload, anchors, revoked)   # active; durable before effect
            self.n.endpoint.install_policy(p, static=static)         # old-policy sessions closed (M1), new E2E key
            self.n.endpoint.retired = self.n.keyring.retired_kems(static.pk)
            self.n.commands.cmd_key = cmd_key                        # new command key (keys follow the policy)
            if self.publisher is not None:
                self.publisher.policy = p
        self._acl_due = True
        self.recompile_acl()                                         # its failure never un-does the activation
        return True

    def schedule_policy(self, signed: bytes, payload: bytes, anchors: dict, revoked=frozenset()) -> None:
        """Keep a verified policy until its activate_at; tick() activates it (§12 Policy Distribution)."""
        from ..fota.policy_artifact import verify_policy_artifact
        from ..policy import validate
        revoked = frozenset(self.revoked_anchors() | set(revoked))    # M-1: the utility's authoritative set
        p = verify_policy_artifact(signed, payload, anchors, revoked)  # a bad artifact is refused now …
        validate(p, installed_version=self.n.endpoint.policy.version)  # … and so is one that is not newer …
        self.n.keyring.keys_for(p)                                     # … or whose private keys are not held
        self.n.db.save_policy("scheduled", signed, payload, anchors, revoked)   # survives a restart (U-4)
        self._scheduled = (signed, payload, anchors, revoked)

    def revoked_anchors(self) -> set:
        """The utility's authoritative revoked anchors (audit M-1, DR-050 as amended): what its published
        KEYREVOKEs revoked, durable in its database. Every policy that is not yet in force is checked against this
        set when it is scheduled, when it is activated (tick() re-checks a scheduled one), after a restart, when an
        ACL is compiled for it and when it would be republished. The policy already in force is not re-judged: like a
        device's installed policy it stays until a newer one (signed by the release anchor of the day) replaces it."""
        out = set(self.n.db.revoked_anchors())
        if self.publisher is not None:
            out |= self.publisher.current_revoked()
        return out

    def acl_text(self, bootstrap=None) -> str:
        """The broker ACL for the policy in force (U-8, B-4): compiled from its signed artifact (the stored active one,
        or `bootstrap` = (signed, payload, anchors) before any activation), the registry and zone membership. A policy
        in force is verified with the revocations it was activated under (DR-050 as amended); compile_acl() with the
        current set is what refuses a new policy signed by a revoked anchor."""
        from .broker import compile_acl
        stored = self.n.db.load_policy("active")
        if stored is not None:
            signed, payload, anchors, revoked = stored
        elif bootstrap is not None:
            (signed, payload, anchors), revoked = bootstrap, frozenset()
        else:
            raise PolicyError("no activated policy artifact: pass the bootstrap POLICY artifact")
        with self.lock:
            members = {n: set(z.members) for n, z in self.n.zones.zones.items()}
            return compile_acl(signed, payload, anchors, self.n.endpoint.registry.records(), members, revoked)

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
        self.recompile_acl()                                         # L-1: an owed ACL recompile is retried
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
                self.publisher.cleanup(self._fota_out)
                self.publisher.settle(self._acked)                     # P1-2: confirmed only on the broker's PUBACKs
                self.publisher.retry(self._fota_out)                   # … and published again while it is not
            self._settle_commands()                                    # finding 1: refused commands go again
            self.n.endpoint.sweep()
        self.ticks += 1

    def _recheck_scheduled(self) -> None:
        """After a restart: a scheduled policy is re-verified against the revocations of now (M-1)."""
        from ..fota.policy_artifact import verify_policy_artifact
        if self._scheduled is None:
            return
        signed, payload, anchors, _ = self._scheduled
        try:
            verify_policy_artifact(signed, payload, anchors, self.revoked_anchors())
        except PqgridError as e:
            self._forget_scheduled()
            self.refused.append(f"scheduled policy refused after a restart: {e}")

    def recompile_acl(self) -> bool:
        """Run the ACL hook if an ACL recompile is owed (after an activation or a revocation). A failure (e.g. the
        broker is restarting) is recorded in acl_failures, never reported as a refusal of the change that needed
        it, and retried by every tick until it succeeds (audit L-1). E2E refusal never depends on it (H1)."""
        from .guard import internal_alarm
        if not self._acl_due or self.acl_hook is None:
            self._acl_due = False
            return True
        try:
            self.acl_hook()
        except Exception as e:                                       # noqa: BLE001 - recorded and retried
            self.acl_failures.append(internal_alarm("acl hook", e))
            return False
        self._acl_due = False
        return True

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
                self._send(topic, env)                                   # retained by the utility (M4) either way
            return len(pubs)


class _FotaClient:
    """What the artifact publisher publishes through: the utility's tracked publish, so every artifact message is
    followed to its PUBACK (P1-2). publish() returns the MQTTMessageInfo the publisher keeps as its token."""

    def __init__(self, utility: UtilityMqtt):
        self.u = utility

    def publish(self, topic: str, payload: bytes, qos: int = 1, retain: bool = False):
        return self.u._send(topic, payload, retain=retain)
