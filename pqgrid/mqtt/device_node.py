"""A device on the broker (Master §10.4, §10.5, §9.4, §9.8, §8.9; IMPLEMENTATION-ROADMAP §11).

  * MQTT 5, clean_start = false with the class Session Expiry: the broker keeps subscriptions and queues QoS 1
    CONTROL while the device sleeps, so a wake needs no SUBSCRIBE (§10.4); Maximum Packet Size = class max_packet
    (§10.2); keep-alive from the class; Last Will "offline" on the status topic.
  * Establishment: 1-RTT resume when the ticket allows, else a full handshake. On a timeout the IDENTICAL CH/RH
    is resent (S5); a refused resume is never answered (E49), so the device falls back to a full handshake.
    DF carries the outbox (I-19); NT/FIN acknowledges it; recovery reports are sent afterwards (§13.7).
  * Every reconnect waits a full-jitter back-off (§10.5). The TLS hop resumes with its session ticket (T2).
  * CONNECT carries the INSTALLED policy's class values. When a new policy changes one of them, the device reconnects
    once, at its §12 re-handshake time and before it re-establishes (DR-052, audit H-2): the broker enforces what the
    live connection declared and drops anything larger silently. After a CONNECT that raised the maximum packet
    size it re-subscribes to the retained FOTA topics, so artifacts dropped under the smaller limit arrive.
  * All protocol state is touched under one lock: paho delivers messages on its own thread.
  * run() is the device main loop (M9); each tick(): flash and intent housekeeping; FOTA (policy activation at
    activate_at, then a re-handshake after a random delay within the class back-off cap: §12; firmware trial
    boot and commit, then a full handshake: tickets are bound to fw_version); the cumulative SETPOINT ACK, at
    most once per SETPOINT_ACK_EVERY_S; reconnect with full-jitter back-off (§10.5); (re)establishment when
    there is no confirmed session (reboot, resync hint, chain end, policy or firmware change); after it, a
    republish request if the device was offline longer than the retention window (§15.8).
  * DR events: the device follows its own crypto group's topic of each zone it has a key for (M7). An event that
    cannot be opened (e.g. delivered from the broker queue at CONNACK, before this session's ZONEKEY) is refused
    and recorded in `dr_refused` with its reason, never held in RAM: the utility re-sends every still-valid
    event of the device's zones after the ZONEKEY on the control topic (M4), so it is not lost (M5, replacing
    the E55 buffer).
"""
from __future__ import annotations

import queue
import random
import socket
import threading
import time
from collections import deque
from typing import Callable, Optional

import paho.mqtt.client as mqtt
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.properties import Properties

from ..commands.zones import ZoneKeyMissing
from ..e2e.envelopes import df_alert_limit, verify_alert_ack, zone_sync
from ..errors import EnvelopeError, HandshakeError, PqgridError, ReplayError
from ..suite.rand import random_bytes
from ..wire import dec, peek_tag, r64
from . import topics
from .guard import BoundedLog, guarded


class TransportError(PqgridError):
    pass


SETPOINT_ACK_EVERY_S = 30.0      # E-3 (§13.5): the cumulative SETPOINT ACK interval; a transport default
ZONE_SYNC_RETRY_S = 10.0         # E-2: one outstanding zone sync per zone; retried after this if unanswered
REPUBLISH_STALL_S = 600.0        # E-4: a verified download with no new chunk for this long asks for a republish
PLANNED_FLUSH_S = 2.0            # H-2: how long a planned reconnect waits for the old connection's PUBACKs
UNACKED_TRACKED = 256            # bound on the QoS 1 publishes tracked for that wait


class _Client(mqtt.Client):
    """TCP_NODELAY and TLS 1.3 session reuse. paho 2.1.0 has no hook for either, so its private socket wrap is
    overridden (requirements pin paho-mqtt==2.1.0)."""
    tls_session = None

    def _ssl_wrap_socket(self, tcp_sock):
        tcp_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s = self._ssl_context.wrap_socket(tcp_sock, server_hostname=self._host, do_handshake_on_connect=False,
                                          session=self.tls_session)
        s.settimeout(self._keepalive)
        s.do_handshake()
        return s


class DeviceMqtt:
    def __init__(self, device, processor, outbox, tls_ctx, host: str, port: int, reply_timeout: float = 3.0,
                 tries: int = 3, on_event: Optional[Callable[[str, bytes], None]] = None,
                 rng: random.Random = random, fota=None,
                 self_test: Optional[Callable[[bytes], bool]] = None):
        self.d, self.proc, self.outbox = device, processor, outbox
        self.host, self.port, self.reply_timeout, self.tries = host, port, reply_timeout, tries
        self.on_event, self.rng = on_event, rng
        prof, did = device.profile, device.id
        self.cls, self.did = prof.name, did
        # paho's own reconnect backs off without jitter; §10.5 requires full jitter, so reconnecting is ours
        self.c = _Client(mqtt.CallbackAPIVersion.VERSION2, client_id=did.decode(), protocol=mqtt.MQTTv5,
                         reconnect_on_failure=False)
        self.c.tls_set_context(tls_ctx)
        self.c.will_set(topics.status(self.cls, did), b"offline", qos=1)
        self.errors: list[str] = BoundedLog()                 # expected protocol refusals (local log only)
        self.internal_errors: list[tuple] = BoundedLog()      # unexpected: type + code locations only (H3)
        self.c.suppress_exceptions = True                     # second line: paho never ends its thread
        self.c.on_connect = guarded(self, "connect", self._on_connect, self.errors, self.internal_errors)
        self.c.on_message = guarded(self, "message", self._on_message, self.errors, self.internal_errors)
        self.c.on_disconnect = guarded(self, "disconnect", self._on_disc, self.errors, self.internal_errors)
        self.c.on_subscribe = guarded(self, "subscribe", self._on_suback, self.errors, self.internal_errors)
        self._sub_pending: dict[int, list[str]] = {}          # SUBSCRIBE mid → topics (paho thread only)
        self.subscribed: set[str] = set()                     # granted by the broker (SUBACK)
        self._props = Properties(PacketTypes.CONNECT)
        self._props.SessionExpiryInterval = prof.session_expiry_s
        self._props.MaximumPacketSize = prof.max_packet
        self.lock = threading.RLock()
        self.connected, self.resync_requested = threading.Event(), threading.Event()
        self.session_present = False
        self._replies: "queue.Queue[bytes]" = queue.Queue()
        self._live: dict[int, bytes] = {}                    # msg_seq → alert_id of alerts sent in this session
        self._zones: set[str] = set()                         # zones this device holds (or held) a key for
        self._dr_topics: set[str] = set()                     # their event topics, for its CURRENT crypto group
        self.dr_refused: deque = deque(maxlen=256)            # (topic, reason) of every DR event refused (M5)
        self.dr_duplicates = 0                                # re-sent events already accepted (M4): not errors
        self._sync_pending: dict[str, tuple[float, int]] = {} # zone → (retry deadline, ZONEKEYs seen then)
        self.zone_sync_requests = 0
        self.events: list[tuple[str, bytes]] = []
        self.fota = fota                                      # a fota.installer.Installer, or None
        self.self_test = self_test                            # trial-boot check of a staged image (§15.12)
        self.fw_results: list[str] = []                       # outcome of each staged-firmware boot
        self._rehandshake_at = 0.0                            # monotonic: the §12 random delay, or the back-off
        self._est_failures = 0                                # consecutive failed establishments (§10.5)
        self._conn_attempt = 0                                # consecutive failed connects (§10.5), across ticks
        self._reconnect_at: Optional[float] = None            # monotonic time of the next connect attempt
        self.ticks = 0                                        # completed main-loop steps
        self._sp_acked: Optional[tuple] = None
        self._sp_acked_at = float("-inf")
        self.republish_stall_s = REPUBLISH_STALL_S
        self._dl_seen: dict[int, tuple[int, float]] = {}      # type → (chunks held, monotonic time it changed)
        self._last_republish_request = float("-inf")
        self.republish_requests = 0
        self.fota_staged: list[int] = []                      # artifact types staged since boot
        self._fota_subscribed = False                         # RAM: once per boot (retained re-delivery)
        self._declared: Optional[tuple[int, int, int]] = None  # CONNECT properties the live connection declared
        self.policy_reconnects = 0                            # planned reconnects after a CONNECT-property change
        self._unacked: list = []                              # recent QoS 1 publishes not yet acknowledged

    # ------------------------------------------------------------------------------------------ connection
    @staticmethod
    def _connect_props(prof) -> tuple[int, int, int]:
        """What the class profile puts into CONNECT: Maximum Packet Size, Session Expiry Interval, Keep Alive."""
        return prof.max_packet, prof.session_expiry_s, prof.keepalive_s

    def connect(self, timeout: float = 10.0) -> None:
        """CONNECT with the INSTALLED policy's class values (§12: a class profile change takes effect at the next
        connection; _connection_step makes that connection as soon as a new policy changes them)."""
        prof = self.d.profile
        want = self._connect_props(prof)
        if self._declared is not None and want[0] > self._declared[0]:
            self._fota_subscribed = False                     # retained artifacts dropped under the smaller limit
        self._props.MaximumPacketSize, self._props.SessionExpiryInterval = prof.max_packet, prof.session_expiry_s
        self.connected.clear()
        self.c.connect(self.host, self.port, keepalive=prof.keepalive_s, clean_start=False, properties=self._props)
        self.c.loop_start()
        if not self.connected.wait(timeout):
            raise TransportError("no CONNACK")
        self._declared = want                                 # what the broker now enforces for this connection
        sock = self.c.socket()
        self.c.tls_session = getattr(sock, "session", None)  # T2: resume the TLS hop next time (RAM only)

    def stale_connect_properties(self) -> bool:
        """The live connection declared other CONNECT properties than the installed policy's class values."""
        return self._declared is not None and self._declared != self._connect_props(self.d.profile)

    def _planned_reconnect(self) -> None:
        """H-2: a newly installed policy changed CONNECT properties. The broker enforces what the live connection
        declared (a larger reply would be dropped silently, [DOCKER T1]), so the device reconnects once, before it
        re-establishes: pending QoS 1 publishes get a short chance to be acknowledged (everything that matters is
        also in the outbox or redelivered by the utility), then DISCONNECT and an immediate CONNECT (no back-off)."""
        self.flush(PLANNED_FLUSH_S)
        self.disconnect()
        self.connected.clear()
        self._reconnect_at = time.monotonic()
        self.policy_reconnects += 1

    def _reconnect_step(self) -> bool:
        """§10.5 across main-loop ticks (final remediation): before every (re)connect a full-jitter delay whose
        window doubles with each consecutive failure, up to the class cap; a successful CONNACK resets it. The
        state lives here, not in one call, so it keeps growing across ticks; the loop never sleeps in it.
        Returns True when connected."""
        if self.connected.is_set():
            return True
        now = time.monotonic()
        if self._reconnect_at is None:                        # a drop (or the boot) just noticed: wait first
            self._reconnect_at = now + self._backoff(self._conn_attempt)
        if now < self._reconnect_at:
            return False
        try:
            self.connect()
        except (OSError, TransportError) as e:
            self.c.loop_stop()
            self._conn_attempt += 1
            self._reconnect_at = time.monotonic() + self._backoff(self._conn_attempt)
            raise TransportError(f"broker unreachable (attempt {self._conn_attempt})") from e
        self._conn_attempt, self._reconnect_at = 0, None
        return True

    def _republish_step(self) -> None:
        """E-4: a verified download that has gained no chunk for republish_stall_s (while connected) is missing
        chunks the broker will not send again: ask for a republish, at most once per stall period. No clock
        other than this device's own monotonic time is involved."""
        if self.fota is None:
            return
        now = time.monotonic()
        with self.lock:
            downloads = {t: sum(bin(b).count("1") for b in dl.have) for t, dl in self.fota.downloads.items()}
        for t in list(self._dl_seen):
            if t not in downloads:
                del self._dl_seen[t]                          # finished or dropped
        stalled = False
        for t, have in downloads.items():
            seen = self._dl_seen.get(t)
            if seen is None or seen[0] != have:
                self._dl_seen[t] = (have, now)
            elif now - seen[1] >= self.republish_stall_s:
                stalled = True
        if stalled and now - self._last_republish_request >= self.republish_stall_s:
            self._last_republish_request = now
            self.republish_requests += 1
            self.request_republish()

    def _backoff(self, attempt: int) -> float:
        prof = self.d.profile
        return topics.backoff_delay(attempt, prof.backoff_base_s, prof.backoff_cap_s, self.rng)

    def tls_resumed(self) -> bool:
        sock = self.c.socket()
        return bool(sock is not None and getattr(sock, "session_reused", False))

    def disconnect(self) -> None:
        self.c.disconnect()
        self.c.loop_stop()

    def flush(self, timeout: float) -> bool:
        """True once every QoS 1 message published on this connection has been acknowledged by the broker."""
        end = time.monotonic() + timeout
        for info in list(self._unacked):
            try:
                info.wait_for_publish(max(0.0, end - time.monotonic()))
            except (RuntimeError, ValueError):
                return False
        return all(i.is_published() for i in self._unacked)

    def _on_connect(self, client, userdata, flags, rc, props):
        self.session_present = bool(flags.session_present)
        if not self.session_present:                         # first connect, or the broker lost the session
            subs = [(topics.hs_down(self.did), 1), (topics.control(self.cls, self.did), 1)]
            self._dr_topics = {topics.dr_event(z, self.d.profile.aead) for z in self._zones}
            subs += [(t, 1) for t in sorted(self._dr_topics)]
            self._subscribe(subs)
        client.publish(topics.status(self.cls, self.did), b"online", qos=1)   # E52: the utility counts these
        if self.fota is not None and not self._fota_subscribed:
            # After every boot: retained manifests, and the chunks of any download that survived in flash (E-F1).
            # Retained messages come only with a SUBSCRIBE, so a reboot must subscribe even in a kept session.
            self._fota_subscribed = True
            subs = [(f"pqgrid/fota/{self.cls}/+/+/manifest/+", 1)]
            subs += [(self._chunk_topic(dl.manifest), 1) for dl in self.fota.downloads.values()]
            self._subscribe(subs)
        self.connected.set()

    def _subscribe(self, subs: list[tuple[str, int]]) -> None:
        """Called on paho's thread only, so the SUBACK cannot be handled before the mid is recorded."""
        _, mid = self.c.subscribe(subs)
        self._sub_pending[mid] = [t for t, _ in subs]

    def _on_suback(self, client, userdata, mid, reason_codes, props):
        """A subscription the broker refuses (e.g. an ACL not yet updated) would silently cut the device off from
        its DR events: record it."""
        for topic, rc in zip(self._sub_pending.pop(mid, []), reason_codes):
            if rc.is_failure:
                self.errors.append(f"subscription refused: {topic}: {rc}")
            else:
                self.subscribed.add(topic)

    def _chunk_topic(self, m) -> str:
        from ..fota.artifact import TYPE_NAMES
        return f"pqgrid/fota/{self.cls}/{TYPE_NAMES[m.type]}/{m.version}/chunk/+"

    def request_republish(self) -> None:
        """Offline beyond the retention window (§15.8): ask on the own, ACL-scoped request topic."""
        self._publish(topics.fota_request(self.cls, self.did), b"")

    def _on_disc(self, client, userdata, flags, rc, props):
        self.connected.clear()

    def _publish(self, topic: str, payload: bytes) -> None:
        info = self.c.publish(topic, payload, qos=1)
        if info.rc != mqtt.MQTT_ERR_SUCCESS:
            raise TransportError(f"publish failed: {mqtt.error_string(info.rc)}")
        self._unacked = [i for i in self._unacked if not i.is_published()][-UNACKED_TRACKED:] + [info]

    # ------------------------------------------------------------------------------------- establishment
    def _exchange(self, msg: bytes, accept: Callable[[bytes], object]):
        """Publish msg; wait for a reply that `accept` takes (stale or foreign replies raise HandshakeError and
        are skipped); resend the IDENTICAL bytes on each timeout."""
        for _ in range(self.tries):
            self._publish(topics.hs_up(self.did), msg)
            deadline = time.monotonic() + self.reply_timeout
            while (left := deadline - time.monotonic()) > 0:
                try:
                    reply = self._replies.get(timeout=left)
                except queue.Empty:
                    break
                try:
                    with self.lock:
                        return accept(reply)
                except HandshakeError as e:
                    self.errors.append(f"reply skipped: {e}")
        return None

    def establish(self) -> None:
        d = self.d
        with self.lock:
            d.expire_stale_attempt()                          # DR-053: a hello too old to be answered is dropped
        for resume in ([True, False] if d.can_resume() else [False]):
            with self.lock:
                msg = d.resume_hello() if resume else d.client_hello()
            if self._exchange(msg, d.on_resume_server if resume else d.on_server_hello) is None:
                if resume:
                    self.errors.append("resume not answered: falling back to a full handshake (E49)")
                    continue
                raise TransportError("no answer to the client hello")
            with self.lock:
                sent = self.outbox.queued()[:df_alert_limit(d.profile.max_packet)]   # the reply must fit
                df = d.finished(sent)
            acked = self._exchange(df, d.on_final)
            if acked is None:
                raise TransportError("no answer to the finished message")
            with self.lock:
                self.outbox.ack_seqs(sent, acked)
                self._live.clear()
                reports = self.proc.recover()                 # INTERRUPTED / re-applied commands (§13.7)
                in_df = {aid for _, aid, _ in sent}
                for topic, aid, payload in self.outbox.queued():
                    if aid not in in_df:                      # what did not fit in DF goes live now
                        self._send_live(topic, aid, payload)
            for r in reports:
                self._publish(topics.alert(self.cls, self.did), r)
            self.resync_requested.clear()
            return
        raise TransportError("establishment failed")

    # ------------------------------------------------------------------------------------------ main loop
    def run(self, stop: threading.Event, interval: float = 1.0) -> None:
        """The device main loop (M9): tick() until `stop` is set. An expected failure (broker unreachable, a
        refused artifact) is logged and retried on the next tick; nothing ends the loop but `stop`."""
        from .guard import EXPECTED, internal_alarm
        while not stop.is_set():
            try:
                self.tick()
            except EXPECTED as e:
                self.errors.append(f"tick: {e}")
            except OSError as e:
                self.errors.append(f"tick: network: {e}")
            except Exception as e:
                self.internal_errors.append(internal_alarm("tick", e))
            self.ticks += 1
            stop.wait(interval)

    def tick(self) -> None:
        self.housekeeping()
        self._setpoint_ack_step()
        self._connection_step()

    def housekeeping(self) -> None:
        """The part of tick() that needs no network."""
        with self.lock:
            if self.d.flash is not None:
                self.d.flash.maintenance()                    # DR-049 without a write (M3)
            self.proc.maintenance()                           # terminal command intents (H2)
            self._fota_step()

    def _fota_step(self) -> None:
        if self.fota is None:
            return
        p = self.fota.activate_policy(self.d.policy, admit=self._admit_policy)   # None until due; FotaError if refused
        if p is not None:
            self._install_policy(p)
        if self.self_test is not None:
            result = self.fota.boot_staged_firmware(self.self_test)
            if result != "nothing staged" and result != "waiting for activate_at":
                self.fw_results.append(result)
            if result == "committed":
                from ..fota.artifact import FIRMWARE
                self.d.install_firmware(self.fota.committed(FIRMWARE))
                self._rehandshake_at = time.monotonic() + self._spread()

    def _admit_policy(self, p) -> None:
        if self.d.flash is not None:
            self.d.flash.require_capacity(p.profile(self.cls))  # refused before the version is committed

    def _install_policy(self, p) -> None:
        self.d.install_policy(p)                              # the old session and ticket are now useless
        prof = self.d.profile
        if self.outbox is not None:
            self.outbox.cap = prof.outbox_cap                 # the budget require_capacity() just checked
        self._rehandshake_at = time.monotonic() + self._spread()   # CONNECT values: at the planned reconnect

    def _spread(self) -> float:
        """§12: re-handshake after a random delay within the class back-off cap (no reconnection storm)."""
        return self.rng.uniform(0, self.d.profile.backoff_cap_s)

    def _setpoint_ack_step(self) -> None:
        """E-3 (§13.5): one cumulative OK for the newest applied SETPOINT (it covers every earlier msg_seq of the
        session), due when ≥ SETPOINT_ACK_EVERY_S have passed since the last one (inclusive), or at once when the
        GRANT of an unacknowledged SETPOINT has ended (its final ACK). Nothing is sent without a new SETPOINT."""
        with self.lock:
            cur = self.proc.last_setpoint()
            if cur is None or cur == self._sp_acked:
                return
            due = self.proc.grant_ended_since_ack() or \
                time.monotonic() - self._sp_acked_at >= SETPOINT_ACK_EVERY_S
        if due and self.send_setpoint_ack():
            with self.lock:
                self.proc.setpoint_acked()
            self._sp_acked, self._sp_acked_at = cur, time.monotonic()

    def _connection_step(self) -> None:
        if (self.connected.is_set() and self.stale_connect_properties()
                and time.monotonic() >= self._rehandshake_at):
            self._planned_reconnect()                         # H-2: at the §12 spread time, before re-establishing
        if not self._reconnect_step():                        # §10.5: waiting for the next attempt
            return
        self._republish_step()
        with self.lock:
            ended = self.d.end_expired_chain()
            need = ended or self.d.session is None or not self.d.confirmed   # a resync hint clears the session
        if not need or time.monotonic() < self._rehandshake_at:
            return
        try:
            self.establish()
        except TransportError:                                # §10.5: a failed attempt backs off, with jitter
            self._rehandshake_at = time.monotonic() + self._backoff(self._est_failures)
            self._est_failures += 1
            raise
        self._est_failures = 0

    # ------------------------------------------------------------------------------------ application API
    def send_alert(self, kind: bytes, payload: bytes) -> bytes:
        """Durable in the outbox first; sent now if the session is confirmed, otherwise inside the next DF."""
        with self.lock:
            aid = random_bytes(16)
            self.outbox.add(aid, payload, kind)
            if self.d.session is not None and self.d.confirmed and not self.d.end_expired_chain():
                self._send_live(topics.alert(self.cls, self.did), aid, payload)
            return aid

    def _send_live(self, topic: str, aid: bytes, payload: bytes) -> None:
        env = self.d.seal_alert(topic, aid, payload)
        self._live[r64(dec(env, 4)[2])] = aid
        self._publish(topic, env)

    def send_telemetry(self, payload: bytes) -> None:
        self._publish(topics.telemetry(self.cls, self.did), payload)     # TELEMETRY: the TLS hop only (§11)

    def send_setpoint_ack(self) -> bool:
        with self.lock:
            ack = self.proc.setpoint_ack()
        if ack:
            self._publish(topics.alert(self.cls, self.did), ack)
        return ack is not None

    # ------------------------------------------------------------------------------------------ inbound
    def _on_message(self, client, userdata, m):
        try:                                                  # expected refusals are logged with their topic
            kind, _, who = topics.parse(m.topic)
            payload = bytes(m.payload)
            if kind == "hs_down":
                if peek_tag(payload) == b"\x07":
                    with self.lock:
                        if self.d.on_resync_hint(payload):
                            self.resync_requested.set()
                else:
                    self._replies.put(payload)
            elif kind == "control":
                self._on_control(m.topic, payload)
            elif kind == "dr_event":
                self._dr(m.topic, who, payload)
            elif kind in ("fota_part", "fota_chunk") and self.fota is not None and payload:
                with self.lock:
                    if kind == "fota_part":
                        man = self.fota.on_part(payload)
                        if man is not None:                   # verified: fetch its chunks (retained)
                            self._subscribe([(self._chunk_topic(man), 1)])
                    elif (done := self.fota.on_chunk(payload)) is not None:
                        self.fota_staged.append(done)
        except (PqgridError, ValueError) as e:
            self.errors.append(f"{m.topic}: {e}")

    def _on_control(self, topic: str, payload: bytes) -> None:
        tag = peek_tag(payload)
        with self.lock:
            if tag == b"\x05":                                # ALERT ACK
                if self.d.session is None or self.d.end_expired_chain():   # e.g. queued before a reboot (H3)
                    raise EnvelopeError("alert ACK without a session: ignored (the outbox resends in DF)")
                aid = self._live.pop(verify_alert_ack(self.d.session, payload), None)
                if aid:
                    self.outbox.ack(aid)
                return
            if tag == b"\x04":                                # a still-valid DR event re-sent to us (M4)
                try:
                    self._deliver(topic, lambda: self.proc.zones.open_resent(payload))
                except ReplayError:
                    self.dr_duplicates += 1                   # already accepted: expected after every re-send
                return
            ack = self.proc.on_control(topic, payload)
            self._zones |= self.proc.zones.zones()
            want = {topics.dr_event(z, self.d.profile.aead) for z in self._zones}
            new, old = sorted(want - self._dr_topics), sorted(self._dr_topics - want)
            self._dr_topics = want
        if ack:
            self._publish(topics.alert(self.cls, self.did), ack)
        if old:                                               # a policy moved its class to another AEAD, so to
            self.c.unsubscribe(old)                           # another crypto group (DR-047): leave the old topic
        if new:                                               # a ZONEKEY arrived: follow its group's events (a new
            self._subscribe([(t, 1) for t in new])            # zone, or its new group after an AEAD change)

    def _request_zone_sync(self, zone: str, epoch: int) -> None:
        """E-2: at most one outstanding request per zone; answered when a ZONEKEY for the zone arrives, retried after
        ZONE_SYNC_RETRY_S otherwise. Only with a confirmed session (establishment re-sends everything anyway)."""
        with self.lock:
            s, seen = self.d.session, self.proc.zones.installs.get(zone, 0)
            pending = self._sync_pending.get(zone)
            if s is None or not self.d.confirmed:
                return
            if pending and time.monotonic() < pending[0] and seen == pending[1]:
                return                                        # one already in flight for this zone
            env = zone_sync(s, zone, epoch)
            self._sync_pending[zone] = (time.monotonic() + ZONE_SYNC_RETRY_S, seen)
            self.zone_sync_requests += 1
        self._publish(topics.alert(self.cls, self.did), env)

    def _dr(self, topic: str, zone: str, env: bytes) -> None:
        self._deliver(topic, lambda: (zone, self.proc.zones.open(topic, env)))

    def _deliver(self, topic: str, open_) -> None:
        """Open a DR event; a refusal is recorded with its reason (never silent) and re-raised for the log."""
        try:
            with self.lock:
                zone, event = open_()
        except PqgridError as e:
            self.dr_refused.append((topic, str(e)))
            if isinstance(e, ZoneKeyMissing):
                self._request_zone_sync(e.zone, e.epoch)          # E-2: never silent, never buffered
            raise
        self.events.append((zone, event))
        if self.on_event:
            self.on_event(zone, event)
