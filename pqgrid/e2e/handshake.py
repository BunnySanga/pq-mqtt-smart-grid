"""The v2.2 KEM-MQTT handshake and PASR resume, device ↔ utility (Master §9.4, §14; DR-007, DR-008, DR-023,
DR-044).

Full handshake:
    D → U  CH : "CH", pk_e, ct_U, n_D, nonce, AEAD_KB(enc[id_D, class, POLICY_INFO_D, fw_version, device_time])
    U → D  SH : "SH", ct_e, n_U, nonce, AEAD_K1(enc[ct_D, POLICY_INFO_U, resume_mode, chain_expiry, utility_time]), MAC_U
Resume (one round trip to data):
    D → U  RH : "RH", blob, n_D, mode, pk_e′|"", id, POLICY_INFO, fw_version, device_time, binder
    U → D  RS : "RS", n_U, ct_e′|"", utility_time, chain_expiry, MAC_U        th_R = H(RH, "RS", n_U, …, chain)
Both then:
    D → U  DF : "DF", MAC_D, bundle                   MAC_D covers H(bundle) (DR-044)
    U → D  NT : "NT", nonce, AEAD_class(K_nt, enc[ticket_id, blob, expires], H("NT", sid)), ack_bundle
       or  FIN: "FIN", HMAC(fin, sid), ack_bundle    (class resume mode NONE, or no ticket issuer)

Rules enforced here:
  * mutual authentication without signatures: only U can open ct_U, only D can open ct_D;
  * POLICY_INFO checked in both directions and bound into K_master through the transcript (I-4);
  * finished carries data: the utility verifies MAC_D *before* touching the bundle (I-19);
  * identical requests within the class DUP window get identical replies (I-18);
  * at most one half-open handshake per device, forgotten after the class PENDING TTL;
  * one live session per device (DR-036);
  * device_time is informational only; the device's clock comes from authenticated utility_time (I-17);
  * resume: the 9 ticket checks, consumption after the binder and before RS (I-8), identical RH resent (S5),
    the ticket dropped at RS and replaced at NT (single use, §14.7).
"""
from __future__ import annotations

import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Optional

from ..errors import (CryptoError, EnvelopeError, HandshakeError, PolicyError, PolicyMismatchError, ReplayError,
                      WireError)
from ..policy.model import Policy, ResumeMode
from ..registry import Registry
from ..suite import aead, hkem
from ..suite.hkem import HybridKeyPair
from ..suite.kdf import ct_eq, h, mac
from ..suite.rand import random_bytes
from ..wire import dec, enc, peek_tag, r64, u64
from . import keys
from .envelopes import (alert_ack, alert_topic, decode_bundle, encode_bundle, envelope_sid, open_alert,
                        seal_alert, verify_alert_ack)
from .session import Session

if TYPE_CHECKING:
    from ..pasr.tickets import TicketIssuer

NONCE_LEN, N_LEN, TICKET_ID_LEN = 12, 32, 16
ALERT_DEDUP_PER_DEVICE = 4096     # bounded memory for alert_id deduplication (IMPLEMENTATION-ROADMAP E7)


# ================================================================================================== device
@dataclass(frozen=True)
class StoredTicket:
    """What the device keeps from NT (Master §14.7); in flash through persistence.device.DeviceFlash."""
    ticket_id: bytes
    blob: bytes
    psk: bytes = field(repr=False)
    expires_at: int
    mode: ResumeMode
    policy_info: bytes
    fw_version: int


class DeviceEndpoint:
    """Device side. Full: IDLE → SENT_CH → UNCONFIRMED (after SH; data only inside DF) → CONFIRMED (after NT/FIN).
    Resume: HAS_TICKET → SENT_RH → UNCONFIRMED (after RS; ticket dropped) → CONFIRMED (after NT; new ticket)."""

    RESYNC_INTERVAL_S = 30                                  # DR-041: at most one resume per hint per 30 s

    def __init__(self, device_id: bytes, dclass: str, policy: Policy, fw_version: int, static: HybridKeyPair,
                 clock: Callable[[], float] = time.time, flash=None):
        self.id, self.dclass, self.policy, self.fw = device_id, dclass, policy, fw_version
        self.static, self.clock, self.offset = static, clock, 0
        self.profile = policy.profile(dclass)
        self.session: Optional[Session] = None
        self.confirmed = False
        self._ch: Optional[bytes] = None
        self._eph: Optional[HybridKeyPair] = None
        self._ss_u: Optional[bytes] = None
        self._confirm: Optional[tuple] = None
        self._df: Optional[bytes] = None
        self.ticket: Optional[StoredTicket] = None
        self._rh: Optional[bytes] = None
        self._reph: Optional[HybridKeyPair] = None
        self._last_resync = float("-inf")
        self.flash = flash                                  # a persistence.device.DeviceFlash, or None (RAM only)
        if flash is not None:
            flash.require_capacity(self.profile)            # an impossible storage configuration: refused here
            floor = flash.time_floor()                      # §8.9: boot time = max(RTC, last authenticated time)
            if floor > self.clock():
                self.offset = floor - self.clock()
            flash.bind_clock(self.now)                      # DR-049 ages on authenticated device time (M3)
            self.ticket = flash.load_ticket(StoredTicket)
            stored = flash.load_rh()
            if stored is not None:
                if self.ticket is not None and self.ticket.mode is ResumeMode.PSK and stored.startswith(enc([b"RH"])[:6]):
                    self._rh = stored                       # S5: resend the identical RH after the reboot
                else:                                       # C8: a PSK_KEM RH cannot be resent; the ticket may
                    flash.clear_ticket()                    # already be consumed, so drop it (no false clone
                    flash.clear_rh()                        # alarm) and do a full handshake
                    self.ticket = None

    def now(self) -> int:
        return int(self.clock() + self.offset)

    def _new_attempt(self) -> None:
        """A new CH or RH abandons any other attempt in progress (the ticket itself is kept)."""
        self.session, self.confirmed, self._df, self._confirm = None, False, None, None
        if self._rh is not None and self.flash is not None:
            self.flash.clear_rh()
        self._ch = self._eph = self._ss_u = self._rh = self._reph = None

    def client_hello(self) -> bytes:
        """Build CH, or return the identical CH while it is outstanding (QoS 1 retransmission)."""
        if self._ch is not None:
            return self._ch
        self._new_attempt()
        self._eph = HybridKeyPair.generate()
        self._ss_u, ct_u = hkem.encaps(self.policy.utility_kem_pk)
        n_d, nonce = random_bytes(N_LEN), random_bytes(NONCE_LEN)
        k_b = keys.early_key(self._ss_u, self._eph.pk, ct_u, n_d)
        body = enc([self.id, self.dclass.encode(), self.policy.info(), u64(self.fw), u64(self.now())])
        ct_body = aead.seal(self.profile.aead, k_b, nonce, body, h(b"CH", self._eph.pk, ct_u, n_d))
        self._ch = enc([b"CH", self._eph.pk, ct_u, n_d, nonce, ct_body])
        return self._ch

    def on_server_hello(self, sh: bytes) -> Session:
        if self._ch is None or self._eph is None:
            raise HandshakeError("no handshake in progress (late or foreign server hello)")
        try:
            tag, ct_e, n_u, nonce, ct_inner, mu = dec(sh, 6)
        except WireError as e:
            raise HandshakeError("malformed server hello") from e
        if tag != b"SH" or len(n_u) != N_LEN or len(nonce) != NONCE_LEN:
            raise HandshakeError("unexpected message")
        try:
            ss_e = hkem.decaps(self._eph, ct_e)
            k1 = keys.k1_key(ss_e, self._ss_u, self._ch)
            ct_d, pinfo_u, mode_b, chain_b, utime_b = dec(
                aead.open_(self.profile.aead, k1, nonce, ct_inner, h(b"SH", ct_e, n_u)), 5)
            chain, utime = r64(chain_b), r64(utime_b)
        except (CryptoError, WireError) as e:
            raise HandshakeError("server hello failed authentication") from e
        if not ct_eq(pinfo_u, self.policy.info()):
            raise HandshakeError("POLICY_INFO mismatch: refusing session")
        if mode_b != self.profile.resume.value.encode():
            raise HandshakeError("resume mode does not match the installed policy")
        try:
            ss_d = hkem.decaps(self.static, ct_d)
        except CryptoError as e:
            raise HandshakeError("server hello failed authentication") from e
        th2 = h(self._ch, b"SH", ct_e, n_u, nonce, ct_inner)
        mk = keys.derive_master(th2, ss_e + self._ss_u + ss_d)
        if not ct_eq(keys.mac_u(mk.kc_u, th2), mu):
            raise HandshakeError("utility key confirmation failed")
        self.offset = utime - self.clock()               # authenticated utility time (I-17)
        if self.flash is not None:
            self.flash.update_time_floor(self.now())
            self.flash.maintenance()                     # DR-049 on the new authenticated time (M3)
        self.session = Session(self.id, self.dclass, self.policy.info(), self.fw, self.profile.aead,
                               mk.k_master, mk.sid, self.profile.resume, chain)
        self._confirm = (mk.kc_d, th2, mu)
        self._ch = self._eph = self._ss_u = None          # the handshake secrets are no longer needed
        return self.session

    def can_resume(self) -> bool:
        """A stored ticket that matches the installed policy, firmware and class mode.

        Expiry is not checked here: device time never gates a connection (Master §8.8); the utility decides."""
        t = self.ticket
        return (t is not None and t.mode is not ResumeMode.NONE and t.mode is self.profile.resume
                and ct_eq(t.policy_info, self.policy.info()) and t.fw_version == self.fw)

    def resume_hello(self) -> bytes:
        """Build RH, or return the identical RH while it is outstanding (S5: a rebuilt RH would be refused as
        "already used" once the first copy has been processed)."""
        if self._rh is not None:
            return self._rh
        if not self.can_resume():
            raise HandshakeError("no usable ticket: use a full handshake")
        t = self.ticket
        self._new_attempt()
        self._reph = HybridKeyPair.generate() if t.mode is ResumeMode.PSK_KEM else None
        fields = [b"RH", t.blob, random_bytes(N_LEN), t.mode.value.encode(), self._reph.pk if self._reph else b"",
                  self.id, self.policy.info(), u64(self.fw), u64(self.now())]
        rh = enc(fields + [mac(keys.binder_key(t.psk), h(*fields))])
        if self.flash is not None:
            self.flash.save_rh(rh, t.mode)                  # durable before it is sent (§9.8, C8)
        self._rh = rh
        return self._rh

    def on_resume_server(self, rs: bytes) -> Session:
        if self._rh is None or self.ticket is None:
            raise HandshakeError("no resumption in progress (late or duplicate resume reply)")
        try:
            tag, n_u, ct_e, utime_b, chain_b, mu = dec(rs, 6)
            utime, chain = r64(utime_b), r64(chain_b)
        except WireError as e:
            raise HandshakeError("malformed resume reply") from e
        if tag != b"RS" or len(n_u) != N_LEN:
            raise HandshakeError("unexpected message")
        t = self.ticket
        try:
            if t.mode is ResumeMode.PSK_KEM:
                ss_e = hkem.decaps(self._reph, ct_e)
            elif ct_e:
                raise HandshakeError("resume reply failed authentication")
            else:
                ss_e = b""
        except CryptoError as e:
            raise HandshakeError("resume reply failed authentication") from e
        th = h(self._rh, b"RS", n_u, ct_e, utime_b, chain_b)
        mk = keys.derive_master(th, t.psk + ss_e)
        if not ct_eq(keys.mac_u(mk.kc_u, th), mu):
            raise HandshakeError("utility key confirmation failed")
        self.offset = utime - self.clock()               # authenticated utility time (I-17)
        if self.flash is not None:
            self.flash.update_time_floor(self.now())
            self.flash.maintenance()                     # DR-049 on the new authenticated time (M3)
        self.session = Session(self.id, self.dclass, self.policy.info(), self.fw, self.profile.aead,
                               mk.k_master, mk.sid, t.mode, chain)
        self._confirm = (mk.kc_d, th, mu)
        if self.flash is not None:                       # C9: cleared at RS, so a reboot before NT cannot
            self.flash.clear_ticket()                    # present a consumed ticket
            self.flash.clear_rh()
        self._rh = self._reph = None                     # a duplicate RS is now refused (no counter restart)
        self.ticket = None                               # single use: the replacement arrives in NT (§14.7)
        return self.session

    def finished(self, queued_alerts: list[tuple[str, bytes, bytes]] = ()) -> bytes:
        """Build DF carrying the queued alerts (topic, alert_id, payload), sealed under the new session.

        Returns the identical DF on a retry, so a lost DF/FIN never re-seals (and never re-numbers) data."""
        if self._df is not None:
            return self._df
        if self.session is None or self._confirm is None:
            raise HandshakeError("no session awaiting confirmation")
        envs = [seal_alert(self.policy, self.session, t, aid, p) for t, aid, p in queued_alerts]
        bundle = encode_bundle(envs)
        kc_d, th2, mu = self._confirm
        self._df = enc([b"DF", keys.mac_d(kc_d, th2, mu, bundle), bundle])
        return self._df

    def on_final(self, msg: bytes) -> list[int]:
        """Verify NT or FIN; store the new ticket (NT); return the msg_seq values acknowledged by the ACKs."""
        s = self.session
        if s is None or self._df is None:
            raise HandshakeError("no finished message outstanding")
        ticket = None
        try:
            tag = peek_tag(msg)
            if tag == b"NT":
                _, nonce, ct, ack_bundle = dec(msg, 4)
            else:
                tag, m, ack_bundle = dec(msg, 3)
            acks = decode_bundle(ack_bundle)
        except WireError as e:
            raise HandshakeError("malformed final message") from e
        if tag == b"NT":
            if s.resume_mode is ResumeMode.NONE:
                raise HandshakeError("unexpected ticket: this class does not resume")
            try:
                tid, blob, exp_b = dec(aead.open_(s.aead, keys.new_ticket_key(s.k_master), nonce, ct,
                                                  h(b"NT", s.sid)), 3)
                exp = r64(exp_b)
            except (CryptoError, WireError) as e:
                raise HandshakeError("final message failed authentication") from e
            if len(tid) != TICKET_ID_LEN:
                raise HandshakeError("final message failed authentication")
            ticket = StoredTicket(tid, blob, keys.resumption_psk(s.k_master, tid), exp, s.resume_mode,
                                  s.policy_info, s.fw_version)
        elif tag != b"FIN" or not ct_eq(m, mac(keys.fin_key(s.k_master), s.sid)):
            raise HandshakeError("final message failed authentication")
        try:
            acked = [verify_alert_ack(s, a) for a in acks]
        except EnvelopeError as e:
            raise HandshakeError("bad acknowledgement in final message") from e
        if ticket is not None:                           # stored only once everything in NT has verified
            if self.flash is not None:
                self.flash.save_ticket(ticket)
            self.ticket = ticket
        self.confirmed, self._confirm = True, None
        return acked

    def install_policy(self, policy: Policy) -> None:
        """A new policy became active (installed through FOTA, §12 Policy Updates): the session and ticket belong
        to the old POLICY_INFO, so the device must handshake again (with the class back-off)."""
        if self.flash is not None:
            self.flash.require_capacity(policy.profile(self.dclass))   # before anything changes
        self.policy, self.profile = policy, policy.profile(self.dclass)
        self._new_attempt()

    def install_firmware(self, version: int) -> None:
        """The new image was committed and runs (§15.12). Tickets are bound to fw_version (check 7), so the old
        one is dropped (a superseded secret: DR-049) and the next establishment is a full handshake."""
        self.fw = version
        self._new_attempt()
        if self.ticket is not None:
            self.ticket = None
            if self.flash is not None:
                self.flash.clear_ticket()

    def on_resync_hint(self, hint: bytes) -> bool:
        """DR-041: the utility lost our session. The hint is unauthenticated, so it only makes the device drop the
        session and resume (itself authenticated), at most once per 30 s. Returns True if the caller should now
        resume (or do a full handshake)."""
        try:
            tag, sid = dec(hint, 2)
        except WireError:
            return False
        if tag != b"\x07" or self.session is None or not ct_eq(sid, self.session.sid):
            return False
        if self.clock() - self._last_resync < self.RESYNC_INTERVAL_S:
            return False
        self._last_resync = self.clock()
        self.session, self.confirmed, self._df, self._confirm = None, False, None, None
        return True

    def end_expired_chain(self) -> bool:
        """Remediation M2 (§9.7): a session ends with its chain, i.e. the full handshake and the resumptions after
        it, at most max_chain_age_s. Once the chain has ended the session and the ticket (same chain) are dropped
        and only a full handshake remains. On the device this can only force a full handshake early, never block
        one, so device time still never gates a connection (§8.8); the utility's clock is authoritative.
        Returns True if the session was ended now."""
        s = self.session
        if s is None or self.now() < s.chain_expires:
            return False
        s.close()
        self.session, self.confirmed, self._df, self._confirm = None, False, None, None
        if self.ticket is not None:
            self.ticket = None
            if self.flash is not None:
                self.flash.clear_ticket()
        return True

    def seal_alert(self, topic: str, alert_id: bytes, payload: bytes) -> bytes:
        """After confirmation only; before that, alerts travel inside DF (I-19)."""
        if self.end_expired_chain():
            raise EnvelopeError("session chain expired: a full handshake is required")
        if not (self.session and self.confirmed):
            raise EnvelopeError("no confirmed session: queue the alert for the next DF")
        return seal_alert(self.policy, self.session, topic, alert_id, payload)


# ================================================================================================= utility
@dataclass
class _Pending:
    session: Session
    kc_d: bytes = field(repr=False)
    th2: bytes
    mu: bytes
    expires: int


@dataclass
class FinishedResult:
    session: Session
    final: bytes
    alerts: list = field(default_factory=list)       # (alert_id, payload, duplicate)
    rejected: int = 0
    replayed: bool = False                           # True: a duplicate DF; bundle NOT processed again


class _DupCache:
    """Identical request → identical reply within the class window (I-18). Oldest entries evicted first, by age
    and by count, so a flood of distinct requests cannot grow it without bound."""
    MAX_ENTRIES = 4096

    def __init__(self):
        self._d: "OrderedDict[bytes, tuple]" = OrderedDict()

    def get(self, key: bytes, now: int):
        v = self._d.get(key)
        return v[0] if v and now - v[1] <= v[2] else None

    def put(self, key: bytes, val, now: int, window: int) -> None:
        self._d[key] = (val, now, window)
        while len(self._d) > self.MAX_ENTRIES:
            self._d.popitem(last=False)
        while self._d:
            k0, (_, t0, w0) = next(iter(self._d.items()))
            if now - t0 <= w0:
                break
            del self._d[k0]


class UnknownSessionError(EnvelopeError):
    """The utility has no session for this sid (e.g. after a restart, or its chain ended). `hint` is the resync
    hint 0x07 ‖ sid."""

    def __init__(self, sid: bytes, reason: str = "unknown session"):
        super().__init__(reason)
        self.hint = enc([b"\x07", sid])


class UtilityEndpoint:
    def __init__(self, policy: Policy, static: HybridKeyPair, registry: Registry,
                 clock: Callable[[], float] = time.time, tickets: Optional["TicketIssuer"] = None):
        self.policy, self.static, self.registry, self.clock = policy, static, registry, clock
        self.tickets = tickets                                              # None: FIN only, no resumption
        self.sessions: dict[bytes, Session] = {}
        self._by_device: dict[bytes, bytes] = {}
        self._pending: "OrderedDict[bytes, _Pending]" = OrderedDict()   # insertion order = creation order
        self._dup = _DupCache()
        self._seen_alerts: dict[bytes, deque] = {}
        self._last_hint: dict[str, int] = {}                                # U-6: 1 hint per 30 s per device

    def now(self) -> int:
        return int(self.clock())

    def revoke_device(self, device_id: bytes) -> int:
        """Live revocation (remediation H1). The revocation is made durable first (the registry stores it before it
        takes effect), then every live session and half-open handshake of the device is invalidated, so nothing
        it sends afterwards is accepted, whatever the broker ACL says. Returns the number of sessions closed."""
        self.registry.revoke(device_id)
        closed = 0
        for sid, s in list(self.sessions.items()):
            if s.device_id == device_id:
                del self.sessions[sid]
                s.close()
                closed += 1
        self._by_device.pop(device_id, None)
        self._pending.pop(device_id, None)
        return closed

    def active(self, device_id: bytes) -> bool:
        rec = self.registry.get(device_id)
        return rec is not None and rec.active

    def install_policy(self, policy: Policy) -> int:
        """The utility activates a verified new policy (Master §12 Policy Updates, P5, P10; remediation M1).
        Every session of the old POLICY_INFO is closed at once (its keys dropped); the entry stays until the
        device establishes again, so what it still sends gets the explicit old-policy refusal (not a resync hint).
        A handshake already past SH is refused at DF (on_finished). Returns the number of sessions closed."""
        self.policy, info, closed = policy, policy.info(), 0
        for s in self.sessions.values():
            if s.k_master and not ct_eq(s.policy_info, info):
                s.close()
                closed += 1
        return closed

    def current_session(self, device_id: bytes) -> Optional[Session]:
        """The device's live session, only if the device is active, the session belongs to the current policy and
        its chain has not ended: what the utility may seal commands and zone keys under, and accept status ACKs
        from."""
        s = self.session_for(device_id)
        if (s is None or not self.active(device_id) or not ct_eq(s.policy_info, self.policy.info())
                or self.end_expired_chain(s)):
            return None
        return s

    def end_expired_chain(self, s: Session) -> bool:
        """Remediation M2 (§9.7): a session, full or resumed, ends with its chain (the full handshake plus the
        resumptions that follow it, ≤ max_chain_age_s from the full handshake). At the chain expiry (utility
        clock) the session is removed and closed; the device then needs a full handshake, which starts a new
        chain. Returns True if the chain has ended."""
        if self.now() < s.chain_expires:
            return False
        if self.sessions.get(s.sid) is s:
            del self.sessions[s.sid]
            if self._by_device.get(s.device_id) == s.sid:
                del self._by_device[s.device_id]
        s.close()
        return True

    def sweep(self) -> int:
        """Periodic RAM hygiene (the utility's tick): sessions whose chain ended, half-open handshakes past their
        TTL. Correctness never depends on it (every use checks again). Returns the sessions ended."""
        now, ended = self.now(), 0
        for s in list(self.sessions.values()):
            ended += self.end_expired_chain(s)
        for did, p in list(self._pending.items()):
            if now > p.expires:
                del self._pending[did]
        return ended

    def session_for(self, device_id: bytes) -> Optional[Session]:
        """The device's one live session (DR-036), or None."""
        sid = self._by_device.get(device_id)
        return self.sessions.get(sid) if sid is not None else None

    def _profile_for(self, topic_id: bytes):
        rec = self.registry.get(topic_id)
        if rec is None or not rec.active:
            raise HandshakeError("unknown or revoked device")
        try:
            return rec, self.policy.profile(rec.dclass)
        except PolicyError as e:
            raise HandshakeError("device class not in the current policy") from e

    def on_client_hello(self, topic_id: bytes, ch: bytes) -> bytes:
        now = self.now()
        rec, prof = self._profile_for(topic_id)
        key = h(b"CH", topic_id, ch)
        cached = self._dup.get(key, now)
        if cached is not None:
            return cached
        try:
            tag, pk_e, ct_u, n_d, nonce, ct_body = dec(ch, 6)
        except WireError as e:
            raise HandshakeError("malformed client hello") from e
        if tag != b"CH" or len(n_d) != N_LEN or len(nonce) != NONCE_LEN:
            raise HandshakeError("unexpected message")
        try:
            ss_u = hkem.decaps(self.static, ct_u)
            k_b = keys.early_key(ss_u, pk_e, ct_u, n_d)
            did, dclass, pinfo, fw_b, _dtime = dec(aead.open_(prof.aead, k_b, nonce, ct_body, h(b"CH", pk_e, ct_u, n_d)), 5)
            fw = r64(fw_b)
        except (CryptoError, WireError) as e:
            raise HandshakeError("client hello failed authentication") from e
        if not ct_eq(did, topic_id):
            raise HandshakeError("identity does not match the device's topic")
        if dclass != rec.dclass.encode():
            raise HandshakeError("device class mismatch")
        if not ct_eq(pinfo, self.policy.info()):
            raise PolicyMismatchError("POLICY_INFO mismatch: device must install the current policy")
        try:
            ss_e, ct_e = hkem.encaps(pk_e)
            ss_d, ct_d = hkem.encaps(rec.e2e_pk)
        except CryptoError as e:
            raise HandshakeError("client hello carries an invalid ephemeral key") from e
        n_u, nonce2 = random_bytes(N_LEN), random_bytes(NONCE_LEN)
        k1 = keys.k1_key(ss_e, ss_u, ch)
        chain = now + prof.max_chain_age_s
        inner = enc([ct_d, self.policy.info(), prof.resume.value.encode(), u64(chain), u64(now)])
        ct_inner = aead.seal(prof.aead, k1, nonce2, inner, h(b"SH", ct_e, n_u))
        th2 = h(ch, b"SH", ct_e, n_u, nonce2, ct_inner)
        mk = keys.derive_master(th2, ss_e + ss_u + ss_d)
        mu = keys.mac_u(mk.kc_u, th2)
        self._expire_pending(now)
        session = Session(did, rec.dclass, pinfo, fw, prof.aead, mk.k_master, mk.sid, prof.resume, chain)
        self._pending.pop(did, None)                                         # one half-open per device
        self._pending[did] = _Pending(session, mk.kc_d, th2, mu, now + prof.pending_ttl_s)
        sh = enc([b"SH", ct_e, n_u, nonce2, ct_inner, mu])
        self._dup.put(key, sh, now, prof.dup_window_s)
        return sh

    def on_resume_hello(self, topic_id: bytes, rh: bytes) -> bytes:
        """RH → RS. The 9 checks run in TicketIssuer.redeem; the ticket is consumed there, before RS exists (I-8)."""
        now = self.now()
        self._profile_for(topic_id)                                          # unknown/revoked: cheapest refusal
        key = h(b"RH", topic_id, rh)
        cached = self._dup.get(key, now)
        if cached is not None:                                               # QoS 1 duplicate: identical RS
            return cached
        if self.tickets is None:
            raise HandshakeError("resumption is not offered")
        try:
            f = dec(rh, 10)
            tag, blob, n_d, mode_b, pk_e, did, pinfo, fw_b, dtime_b, binder = f
            fw, _ = r64(fw_b), r64(dtime_b)                                  # device_time: informational only
        except WireError as e:
            raise HandshakeError("malformed resume hello") from e
        if tag != b"RH" or len(n_d) != N_LEN:
            raise HandshakeError("unexpected message")
        t = self.tickets.redeem(blob=blob, topic_id=topic_id, claimed_id=did, policy_info=pinfo, fw_version=fw,
                                mode=mode_b, pk_e=pk_e, binder=binder, binder_input=h(*f[:9]),
                                registry=self.registry, policy=self.policy, now=now)
        try:
            ss_e, ct_e = hkem.encaps(pk_e) if t.resume_mode is ResumeMode.PSK_KEM else (b"", b"")
        except CryptoError as e:
            raise HandshakeError("resume hello carries an invalid ephemeral key") from e
        prof = self.policy.profile(t.dclass)
        n_u, utime_b, chain_b = random_bytes(N_LEN), u64(now), u64(t.chain_expires_at)
        th = h(rh, b"RS", n_u, ct_e, utime_b, chain_b)
        mk = keys.derive_master(th, t.psk + ss_e)
        mu = keys.mac_u(mk.kc_u, th)
        session = Session(t.device_id, t.dclass, t.policy_info, t.fw_version, prof.aead, mk.k_master, mk.sid,
                          t.resume_mode, t.chain_expires_at)
        self._expire_pending(now)
        self._pending.pop(t.device_id, None)                                 # one half-open per device (CH or RH)
        self._pending[t.device_id] = _Pending(session, mk.kc_d, th, mu, now + prof.pending_ttl_s)
        rs = enc([b"RS", n_u, ct_e, utime_b, chain_b, mu])
        self._dup.put(key, rs, now, prof.dup_window_s)
        return rs

    def on_finished(self, topic_id: bytes, df: bytes) -> FinishedResult:
        now = self.now()
        rec, prof = self._profile_for(topic_id)
        key = h(b"DF", topic_id, df)
        cached = self._dup.get(key, now)
        if cached is not None:                       # identical DF: identical FIN, data not delivered twice
            session, final = cached
            return FinishedResult(session, final, replayed=True)
        self._expire_pending(now)
        pend = self._pending.get(topic_id)
        if pend is None or now > pend.expires:
            self._pending.pop(topic_id, None)
            raise HandshakeError("no pending handshake")
        try:
            tag, mac_d_rx, bundle = dec(df, 3)
        except WireError as e:
            raise HandshakeError("malformed finished") from e
        if tag != b"DF" or not ct_eq(keys.mac_d(pend.kc_d, pend.th2, pend.mu, bundle), mac_d_rx):
            raise HandshakeError("device key confirmation failed")          # nothing in the bundle is touched
        del self._pending[topic_id]
        s = pend.session
        if not ct_eq(s.policy_info, self.policy.info()):                    # M1: activated between SH and DF
            s.close()
            raise HandshakeError("policy changed during the handshake: not installed, bundle not opened, "
                                 "no ticket; the device must handshake under the current policy")
        if now >= s.chain_expires:                                            # M2: the chain ended after RS
            s.close()
            raise HandshakeError("session chain expired: a full handshake is required")
        old = self._by_device.get(s.device_id)
        if old is not None:                                                  # one live session per device
            prev = self.sessions.pop(old, None)
            if prev is not None:
                prev.close()
        self.sessions[s.sid], self._by_device[s.device_id] = s, s.sid
        result = FinishedResult(s, b"")
        acks = []
        try:
            envs = decode_bundle(bundle)
        except WireError:
            envs, result.rejected = [], 1
        topic, opened = alert_topic(s.dclass, s.device_id), []
        for env in envs:
            try:
                aid, payload, seq = open_alert(self.policy, s, topic, env)
            except (EnvelopeError, ReplayError):
                result.rejected += 1
                continue
            opened.append((aid, payload))
            acks.append(alert_ack(s, seq))
        result.final = self._final(s, prof, acks, now)       # may fail (e.g. storing a new STEK): then nothing
        result.alerts = [(aid, p, self._dedup(s.device_id, aid)) for aid, p in opened]   # is recorded as seen
        self._dup.put(key, (s, result.final), now, prof.dup_window_s)
        return result

    def _final(self, s: Session, prof, acks: list[bytes], now: int) -> bytes:
        """NT (new ticket, same chain expiry) for resumable classes; FIN otherwise (Master §9.4)."""
        ack_bundle = encode_bundle(acks)
        if self.tickets is None or prof.resume is ResumeMode.NONE:
            return enc([b"FIN", mac(keys.fin_key(s.k_master), s.sid), ack_bundle])
        tid, blob, expires = self.tickets.issue(s, prof.ticket_lifetime_s, now)
        nonce = random_bytes(NONCE_LEN)
        ct = aead.seal(s.aead, keys.new_ticket_key(s.k_master), nonce, enc([tid, blob, u64(expires)]),
                       h(b"NT", s.sid))
        return enc([b"NT", nonce, ct, ack_bundle])

    def open_alert(self, topic: str, env: bytes) -> tuple[bytes, bytes, bool]:
        """Returns (payload, ACK, duplicate). Unknown session → UnknownSessionError with a resync hint."""
        try:
            sid = envelope_sid(env)
        except WireError as e:
            raise EnvelopeError("malformed alert envelope") from e
        who = topic.split("/")[2] if topic.count("/") == 3 else ""
        if not self.active(who.encode()):                                    # current revocation state (H1)
            raise EnvelopeError("device unknown or revoked")
        s, reason = self.sessions.get(sid), "unknown session"
        if s is not None and self.end_expired_chain(s):                     # M2: gone, as after a restart
            s, reason = None, "session chain expired: a full handshake is required"
        if s is None:                                                        # DR-041: hint, at most every 30 s
            now = self.now()
            if now - self._last_hint.get(who, -DeviceEndpoint.RESYNC_INTERVAL_S) < DeviceEndpoint.RESYNC_INTERVAL_S:
                raise EnvelopeError(f"{reason} (resync hint already sent)")
            self._last_hint[who] = now
            raise UnknownSessionError(sid, reason)
        if not ct_eq(s.policy_info, self.policy.info()):
            raise EnvelopeError("session belongs to an old policy")
        aid, payload, seq = open_alert(self.policy, s, topic, env)
        return payload, alert_ack(s, seq), self._dedup(s.device_id, aid)

    def _dedup(self, device_id: bytes, alert_id: bytes) -> bool:
        seen = self._seen_alerts.setdefault(device_id, deque(maxlen=ALERT_DEDUP_PER_DEVICE))
        if alert_id in seen:
            return True
        seen.append(alert_id)
        return False

    def _expire_pending(self, now: int) -> None:
        """Drop expired half-open states from the oldest end: O(1) amortised per message.

        TTLs differ per class, so an unexpired entry can shield newer expired ones for a while; those are
        still refused exactly at lookup (on_finished checks `expires`), so correctness never depends on this."""
        while self._pending:
            did, p = next(iter(self._pending.items()))
            if now <= p.expires:
                break
            del self._pending[did]
