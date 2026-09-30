"""PCHC end-to-end session (v2): hybrid KEM-MQTT handshake device <-> utility with POLICY_INFO bound into keys,
tier protection, end-to-end acknowledgements, and the edge-case handling found in design review:
  - idempotent responses to MQTT QoS 1 duplicates (hello / finished / resume)
  - explicit final confirmation (NT or FIN) before the device treats a session as established
  - utility-authenticated time (a device clock reset by a power outage cannot lock it out)
  - constant-time comparisons for every MAC
  - end-to-end ACKs so lost alerts are resent and lost commands are re-delivered on the next session
  - persisted command sequence (flash) so commands cannot be replayed across reboots
"""
from __future__ import annotations
import hmac as _hmac, os, time
from dataclasses import dataclass, field
from .suite import (HybridKeyPair, hkem_encaps, hkem_decaps, hkdf_extract, hkdf_expand, mac, h,
                    aead_seal, aead_open, mldsa_verify)
from .wire import enc, dec, u64, r64, peek_tag
from .policy import Policy, Tier, valid_device_id

class HandshakeError(ValueError): pass
class ReplayError(ValueError): pass
class UnknownSession(ValueError):
    def __init__(self, hint: bytes): super().__init__("unknown session"); self.hint = hint

SALT = b"pqgrid/v1/hs"
DUP_WINDOW_S = 120          # how long a response is kept to answer MQTT duplicates identically
PENDING_TTL_S = 60          # half-open handshakes are forgotten after this
ct_eq = _hmac.compare_digest

class ReplayGuard:          # two-phase: validate before AEAD, accept after
    def __init__(self): self.hi = 0
    def validate(self, seq):
        if seq <= self.hi: raise ReplayError(f"seq {seq} <= {self.hi}")
    def accept(self, seq): self.validate(seq); self.hi = seq

@dataclass
class Session:
    device_id: bytes; dclass: str; policy_info: bytes; fw_version: int
    k_master: bytes; sid: bytes; resume_mode: str; chain_expires: int
    send_seq: int = 0
    guards: dict = field(default_factory=dict)
    def key(self, name: str, direction: bytes) -> bytes:
        return hkdf_expand(self.k_master, b"key|" + name.encode() + b"|" + direction)
    def guard(self, name) -> ReplayGuard: return self.guards.setdefault(name, ReplayGuard())

def _derive(th: bytes, ikm: bytes):
    k = hkdf_extract(th, ikm)
    return k, hkdf_expand(k, b"kc-U"), hkdf_expand(k, b"kc-D"), hkdf_expand(k, b"sid", 8)

def fin_msg(s: Session) -> bytes:            # final confirmation for classes that get no ticket
    return enc([b"FIN", mac(hkdf_expand(s.k_master, b"fin"), s.sid)])

class _DupCache:
    def __init__(self): self.d = {}
    def get(self, key, now):
        v = self.d.get(key); return v[0] if v and now - v[1] <= DUP_WINDOW_S else None
    def put(self, key, val, now):
        self.d[key] = (val, now)
        while self.d:                                   # insertion-ordered: drop expired entries from the front, O(1) amortised
            k0 = next(iter(self.d))
            if now - self.d[k0][1] <= DUP_WINDOW_S: break
            del self.d[k0]

# =============================== device side ===============================
class Device:
    """RAM: session, handshake state.  FLASH (survives reboot): ticket, last_cmd_seq, outbox, installed policy."""
    def __init__(self, device_id: bytes, dclass: str, policy: Policy, fw_version: int,
                 static: HybridKeyPair | None = None, clock=time.time):
        if not valid_device_id(device_id): raise ValueError("invalid device id")
        self.id, self.dclass, self.policy, self.fw = device_id, dclass, policy, fw_version
        self.static = static or HybridKeyPair()
        self.clock, self.offset = clock, 0
        self.session: Session | None = None; self.confirmed = False
        self.flash = {"ticket": None, "last_cmd_seq": 0, "outbox": []}
        self._last_resync = -1e18

    def now(self) -> int: return int(self.clock() + self.offset)
    @property
    def ticket(self): return self.flash["ticket"]
    @ticket.setter
    def ticket(self, t): self.flash["ticket"] = t

    def reboot(self):                       # power loss: RAM gone, flash kept
        self.session, self.confirmed, self.offset = None, False, 0
        for a in ("_eph", "_ss_u", "_m1", "_th3", "_reph", "_r1", "_rmode"): self.__dict__.pop(a, None)

    def hello(self) -> bytes:
        self._eph = HybridKeyPair()
        ss_u, ct_u = hkem_encaps(self.policy.utility_kem_pk)
        n_d, nonce = os.urandom(32), os.urandom(12)
        k_b = hkdf_expand(hkdf_extract(SALT, ss_u), b"early" + h(self._eph.pk, ct_u, n_d))
        body = enc([self.id, self.dclass.encode(), self.policy.info(), u64(self.fw), u64(self.now())])  # time is informational
        ct_body = aead_seal(k_b, nonce, body, h(b"CH", self._eph.pk, ct_u, n_d))
        self._ss_u = ss_u
        self._m1 = enc([b"CH", self._eph.pk, ct_u, n_d, nonce, ct_body]); return self._m1

    def on_server_hello(self, m2: bytes) -> bytes:
        if not hasattr(self, "_m1"): raise HandshakeError("no handshake in progress (late or foreign server hello)")
        tag, ct_e, n_u, nonce, ct_inner, mac_u = dec(m2, 6)
        if tag != b"SH": raise HandshakeError("unexpected message")
        ss_e = hkem_decaps(self._eph, ct_e)
        k1 = hkdf_expand(hkdf_extract(SALT, ss_e + self._ss_u), b"k1" + h(self._m1))
        try: ct_d, pinfo_u, mode, chain, u_time = dec(aead_open(k1, nonce, ct_inner, h(b"SH", ct_e, n_u)), 5)
        except Exception as e: raise HandshakeError("server hello failed authentication") from e
        if not ct_eq(pinfo_u, self.policy.info()): raise HandshakeError("POLICY_INFO mismatch: refusing session")
        ss_d = hkem_decaps(self.static, ct_d)
        th2 = h(self._m1, b"SH", ct_e, n_u, nonce, ct_inner)
        k, kc_u, kc_d, sid = _derive(th2, ss_e + self._ss_u + ss_d)
        if not ct_eq(mac(kc_u, b"U-finished" + th2), mac_u): raise HandshakeError("utility key confirmation failed")
        self.offset = r64(u_time) - self.clock()          # clock taken from the authenticated utility
        self.session = Session(self.id, self.dclass, self.policy.info(), self.fw, k, sid, mode.decode(), r64(chain))
        self.confirmed = False
        for a in ("_eph", "_ss_u", "_m1"): self.__dict__.pop(a, None)
        return enc([b"DF", mac(kc_d, b"D-finished" + h(th2, mac_u))])

    def on_final(self, m4: bytes) -> list:
        """NT (ticket) or FIN confirms the utility holds the session. Returns alerts to (re)send."""
        s = self.session
        if not s: raise HandshakeError("no session awaiting confirmation")
        tag = peek_tag(m4)
        if tag == b"FIN":
            _, m = dec(m4, 2)
            if not ct_eq(m, mac(hkdf_expand(s.k_master, b"fin"), s.sid)): raise HandshakeError("bad FIN")
        elif tag == b"NT":
            tag, n, ct = dec(m4, 3)
            tid, blob, exp = dec(aead_open(hkdf_expand(s.k_master, b"new-ticket"), n, ct, s.sid), 3)
            self.ticket = {"blob": blob, "psk": hkdf_expand(s.k_master, b"res|" + tid), "exp": r64(exp), "mode": s.resume_mode}
        else:
            raise HandshakeError("unexpected final message")
        self.confirmed = True
        pending, self.flash["outbox"] = self.flash["outbox"], []
        return [self.seal_alert(t, p, aid) for t, p, _, _, aid in pending]   # resend unacknowledged alerts: new seq, same alert id

    # ---- ALERT (device -> utility), acknowledged end to end ----
    def seal_alert(self, topic: str, payload: bytes, aid: bytes | None = None) -> bytes:
        if self.policy.tier(topic) != Tier.ALERT: raise ValueError("topic is not ALERT tier under installed policy")
        if not (self.session and self.confirmed): raise ValueError("no confirmed session")
        aid = aid or os.urandom(16)
        s = self.session; s.send_seq += 1; seq = u64(s.send_seq)
        ct = aead_seal(s.key("ALERT", b"up"), b"\x01\x00\x00\x00" + seq, enc([aid, payload]), h(b"ALERT", topic.encode(), s.sid, seq))
        self.flash["outbox"].append((topic, payload, s.sid, s.send_seq, aid))
        return enc([b"\x02", s.sid, seq, ct])

    def on_alert_ack(self, ack: bytes):
        t, sid, seq, m = dec(ack, 4)
        s = self.session
        if t != b"\x05" or not s or sid != s.sid: raise ValueError("ack for another session")
        if not ct_eq(m, mac(s.key("ACK", b"down"), sid + seq)): raise ValueError("forged ack")
        self.flash["outbox"] = [o for o in self.flash["outbox"] if not (o[2] == sid and o[3] == r64(seq))]

    # ---- CONTROL unicast (utility -> device), acknowledged end to end ----
    def open_control(self, topic: str, env: bytes) -> tuple[bytes | None, bytes]:
        """Returns (command-to-apply or None, authenticated ACK). A command is applied at most once (flash seq);
        an authentic duplicate or superseded command is acknowledged but not re-applied, so the utility stops retrying."""
        s = self.session
        t, sid, seq, ct = dec(env, 4)
        if t != b"\x03" or not s or sid != s.sid: raise ValueError("wrong envelope/session")
        pt = aead_open(s.key("CONTROL", b"down"), b"\x02\x00\x00\x00" + seq, ct, h(b"CONTROL", topic.encode(), sid, seq))
        cmd, exp, sig = dec(pt, 3)
        signed = b"pqgrid/v1/cmd" + h(self.id, topic.encode(), seq, exp, cmd)
        if not mldsa_verify(self.policy.utility_cmd_pk, sig, signed): raise ValueError("command signature invalid")
        n = r64(seq)
        if n <= self.flash["last_cmd_seq"]: status, apply = b"DUP", None           # replay/redelivery: never re-apply
        elif r64(exp) < self.now():        status, apply = b"EXPIRED", None
        else:
            status, apply = b"OK", cmd
            self.flash["last_cmd_seq"] = n                                          # commit only after all checks
        return apply, enc([b"\x06", sid, seq, status, mac(s.key("ACK", b"up"), sid + seq + status)])

    def on_resync(self, hint: bytes) -> bool:
        """Unauthenticated hint that the utility lost our session. Rate-limited; the resume itself is authenticated."""
        t, sid = dec(hint, 2)
        if t != b"\x07" or not self.session or sid != self.session.sid: return False
        if self.clock() - self._last_resync < 30: return False
        self._last_resync = self.clock(); self.session, self.confirmed = None, False
        return True

# =============================== utility side ===============================
class Utility:
    def __init__(self, policy: Policy, static: HybridKeyPair, cmd_sk, registry: dict, pasr=None, clock=time.time):
        self.policy, self.static, self.cmd_sk, self.registry, self.pasr, self.clock = policy, static, cmd_sk, registry, pasr, clock
        self.pending, self.sessions, self.cmd_seq, self.pending_cmds, self.seen_alerts = {}, {}, {}, {}, {}
        self.dup = _DupCache()

    def now(self) -> int: return int(self.clock())

    def on_client_hello(self, topic_id: bytes, m1: bytes, now=None) -> bytes:
        now = int(now or self.now())
        key = h(b"CH", topic_id, m1)
        cached = self.dup.get(key, now)
        if cached: return cached                                         # QoS 1 duplicate: identical answer
        tag, pk_e, ct_u, n_d, nonce, ct_body = dec(m1, 6)
        if tag != b"CH": raise HandshakeError("unexpected message")
        ss_u = hkem_decaps(self.static, ct_u)
        k_b = hkdf_expand(hkdf_extract(SALT, ss_u), b"early" + h(pk_e, ct_u, n_d))
        try: did, dclass, pinfo, fw, ts = dec(aead_open(k_b, nonce, ct_body, h(b"CH", pk_e, ct_u, n_d)), 5)
        except Exception as e: raise HandshakeError("client hello failed authentication") from e
        if not ct_eq(did, topic_id): raise HandshakeError("identity does not match the device's topic")
        reg = self.registry.get(did)
        if not reg or not reg["active"]: raise HandshakeError("unknown or revoked device")
        if dclass.decode() != reg["class"]: raise HandshakeError("device class mismatch")
        if not ct_eq(pinfo, self.policy.info()): raise HandshakeError("POLICY_INFO mismatch: device must install current policy")
        ss_e, ct_e = hkem_encaps(pk_e); ss_d, ct_d = hkem_encaps(reg["pk"])
        n_u, nonce2 = os.urandom(32), os.urandom(12)
        k1 = hkdf_expand(hkdf_extract(SALT, ss_e + ss_u), b"k1" + h(m1))
        cls = self.policy.classes[reg["class"]]
        chain = now + cls["max_chain_age_s"]
        inner = enc([ct_d, self.policy.info(), cls["resume"].encode(), u64(chain), u64(now)])
        ct_inner = aead_seal(k1, nonce2, inner, h(b"SH", ct_e, n_u))
        th2 = h(m1, b"SH", ct_e, n_u, nonce2, ct_inner)
        k, kc_u, kc_d, sid = _derive(th2, ss_e + ss_u + ss_d)
        mac_u = mac(kc_u, b"U-finished" + th2)
        self.pending = {d: v for d, v in self.pending.items() if now - v[3] <= PENDING_TTL_S}   # bound half-open state
        self.pending[did] = (Session(did, reg["class"], pinfo, r64(fw), k, sid, cls["resume"], chain), kc_d, h(th2, mac_u), now)
        m2 = enc([b"SH", ct_e, n_u, nonce2, ct_inner, mac_u])
        self.dup.put(key, m2, now); return m2

    def on_finished(self, topic_id: bytes, m3: bytes, now=None) -> tuple[Session, bytes]:
        now = int(now or self.now())
        key = h(b"DF", topic_id, m3)
        cached = self.dup.get(key, now)
        if cached: return cached                                         # duplicate finished: same final message
        if topic_id not in self.pending: raise HandshakeError("no pending handshake")
        s, kc_d, th3, _ = self.pending[topic_id]
        tag, mac_d = dec(m3, 2)
        if tag != b"DF" or not ct_eq(mac(kc_d, b"D-finished" + th3), mac_d): raise HandshakeError("device key confirmation failed")
        del self.pending[topic_id]
        self.sessions = {sid: x for sid, x in self.sessions.items() if x.device_id != s.device_id}   # one live session per device
        self.sessions[s.sid] = s
        final = (self.pasr.issue(s, now) if self.pasr else None) or fin_msg(s)
        self.dup.put(key, (s, final), now)
        return s, final

    def open_alert(self, topic: str, env: bytes) -> tuple[bytes, bytes]:
        t, sid, seq, ct = dec(env, 4)
        if t != b"\x02": raise ValueError("not an alert envelope")
        s = self.sessions.get(sid)
        if not s: raise UnknownSession(enc([b"\x07", sid]))
        if not ct_eq(s.policy_info, self.policy.info()): raise ValueError("session belongs to an old policy")
        if self.policy.tier(topic) != Tier.ALERT: raise ValueError("topic is not ALERT tier")
        parts = topic.split("/")
        if len(parts) != 4 or parts[2].encode() != s.device_id: raise ValueError("envelope belongs to another device's session")
        g = s.guard("alert"); g.validate(r64(seq))
        pt = aead_open(s.key("ALERT", b"up"), b"\x01\x00\x00\x00" + seq, ct, h(b"ALERT", topic.encode(), sid, seq))
        g.accept(r64(seq))
        aid, payload = dec(pt, 2)
        seen = self.seen_alerts.setdefault(s.device_id, [])
        duplicate = aid in seen
        if not duplicate: seen.append(aid); del seen[:-4096]                     # bounded per-device memory
        return payload, enc([b"\x05", sid, seq, mac(s.key("ACK", b"down"), sid + seq)]), duplicate

    def seal_control(self, s: Session, topic: str, cmd: bytes, ttl_s=60, now=None) -> bytes:
        now = int(now or self.now())
        n = self.cmd_seq.get(s.device_id, 0) + 1; self.cmd_seq[s.device_id] = n
        seq, exp = u64(n), u64(now + ttl_s)
        sig = self.cmd_sk.sign(b"pqgrid/v1/cmd" + h(s.device_id, topic.encode(), seq, exp, cmd))
        self.pending_cmds.setdefault(s.device_id, {})[n] = (topic, cmd, exp, sig)
        return self._encrypt_cmd(s, topic, seq, cmd, exp, sig)

    def _encrypt_cmd(self, s, topic, seq, cmd, exp, sig):
        ct = aead_seal(s.key("CONTROL", b"down"), b"\x02\x00\x00\x00" + seq, enc([cmd, exp, sig]), h(b"CONTROL", topic.encode(), s.sid, seq))
        return enc([b"\x03", s.sid, seq, ct])

    def on_command_ack(self, ack: bytes) -> bytes:
        t, sid, seq, status, m = dec(ack, 5)
        s = self.sessions.get(sid)
        if t != b"\x06" or not s or not ct_eq(m, mac(s.key("ACK", b"up"), sid + seq + status)): raise ValueError("bad command ack")
        self.pending_cmds.get(s.device_id, {}).pop(r64(seq), None); return status

    def redeliver_commands(self, s: Session, now=None) -> list:
        """After a device re-establishes: re-send unacknowledged, unexpired commands (same seq and signature)."""
        now = int(now or self.now()); out = []
        for n, (topic, cmd, exp, sig) in sorted(self.pending_cmds.get(s.device_id, {}).items()):
            if r64(exp) >= now: out.append((topic, self._encrypt_cmd(s, topic, u64(n), cmd, exp, sig)))
        return out
