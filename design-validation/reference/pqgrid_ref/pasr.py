"""PASR v2: policy-aware resumption of the PCHC end-to-end session.
Utility-issued, STEK-sealed, single-use tickets. v2 edge-case handling:
  - STEK keys and the used-ticket record are persisted, so a utility restart neither invalidates every ticket
    (which would trigger a fleet-wide full-handshake storm) nor re-opens replay of consumed tickets
  - identical answers to MQTT QoS 1 duplicates of a resume hello / finished
  - no device-clock gate; the resume reply carries authenticated utility time
"""
from __future__ import annotations
import json, os, time
from .suite import HybridKeyPair, hkem_encaps, hkem_decaps, hkdf_expand, mac, h, aead_seal, aead_open
from .wire import enc, dec, u64, r64
from .e2e import Session, HandshakeError, _derive, Device, ct_eq, _DupCache

class STEK:
    """Ticket keys. Rotated daily; old keys kept at least as long as the longest ticket lifetime."""
    def __init__(self, path: str | None = None):
        self.path, self.keys, self.kid = path, {}, 0
        if path and os.path.exists(path): self._load()
        else: self.rotate()
    def rotate(self):
        self.kid = (self.kid + 1) % 256; self.keys[self.kid] = os.urandom(32); self._save()
    def retire(self, kid): self.keys.pop(kid, None); self._save()
    def _save(self):
        if self.path:   # prototype: a file. Production: an HSM or an encrypted keystore.
            json.dump({"kid": self.kid, "keys": {k: v.hex() for k, v in self.keys.items()}}, open(self.path, "w"))
    def _load(self):
        d = json.load(open(self.path)); self.kid = d["kid"]; self.keys = {int(k): bytes.fromhex(v) for k, v in d["keys"].items()}

class PASR:
    def __init__(self, utility, stek: STEK, used_path: str | None = None):
        self.u, self.stek, self.used_path, self.pending, self.dup = utility, stek, used_path, {}, _DupCache()
        self.used = {bytes.fromhex(k): v for k, v in json.load(open(used_path)).items()} if used_path and os.path.exists(used_path) else {}

    def _persist_used(self):
        if self.used_path: json.dump({k.hex(): v for k, v in self.used.items()}, open(self.used_path, "w"))

    def issue(self, s: Session, now=None) -> bytes | None:
        now = int(now or self.u.now())
        cls = self.u.policy.classes[s.dclass]
        if cls["resume"] == "NONE": return None
        tid = os.urandom(16); psk = hkdf_expand(s.k_master, b"res|" + tid)
        exp = min(now + cls["ticket_lifetime_s"], s.chain_expires)
        pt = enc([tid, s.device_id, s.dclass.encode(), s.policy_info, u64(s.fw_version), s.resume_mode.encode(),
                  u64(now), u64(exp), u64(s.chain_expires), psk])
        kid, n = bytes([self.stek.kid]), os.urandom(12)
        blob = b"\x01" + kid + n + aead_seal(self.stek.keys[self.stek.kid], n, pt, b"\x01" + kid)
        n2 = os.urandom(12)
        return enc([b"NT", n2, aead_seal(hkdf_expand(s.k_master, b"new-ticket"), n2, enc([tid, blob, u64(exp)]), s.sid)])

    def on_resume_hello(self, topic_id: bytes, r1: bytes, now=None) -> bytes:
        now = int(now or self.u.now())
        key = h(b"RH", topic_id, r1)
        cached = self.dup.get(key, now)
        if cached: return cached                                       # QoS 1 duplicate: identical answer
        tag, blob, n_d, mode, pk_e, did, pinfo, fw, ts, binder = dec(r1, 10)
        if tag != b"RH" or blob[:1] != b"\x01" or len(blob) < 14: raise HandshakeError("unexpected message")
        key_s = self.stek.keys.get(blob[1])
        if key_s is None: raise HandshakeError("ticket key retired")
        try: t = dec(aead_open(key_s, blob[2:14], blob[14:], blob[:2]), 10)
        except Exception as e: raise HandshakeError("ticket not authentic") from e
        tid, t_did, t_cls, t_pinfo, t_fw, t_mode, t_iss, t_exp, t_chain, psk = t
        reg = self.u.registry.get(t_did)
        cls = self.u.policy.classes.get(t_cls.decode(), {})
        checks = [
            (ct_eq(t_did, topic_id) and ct_eq(t_did, did),        "ticket/device identity mismatch"),
            (bool(reg) and reg["active"],                          "device unknown or revoked"),
            (now < r64(t_exp) and now < r64(t_chain),              "ticket expired"),
            (ct_eq(t_pinfo, pinfo) and ct_eq(pinfo, self.u.policy.info()), "ticket issued under a different policy"),
            (ct_eq(t_fw, fw),                                      "ticket issued for different firmware"),
            (t_mode == mode == cls.get("resume", "NONE").encode(), "resume mode does not match policy"),
            (mode != b"PSK_KEM" or len(pk_e) == 1216,              "PSK_KEM requires a fresh ephemeral key"),
            (ct_eq(mac(hkdf_expand(psk, b"binder"), h(tag, blob, n_d, mode, pk_e, did, pinfo, fw, ts)), binder), "binder invalid"),
            (tid not in self.used,                                 "ticket already used"),
        ]
        for ok, why in checks:
            if not ok: raise HandshakeError(why)
        self.used[tid] = r64(t_exp); self._persist_used()             # consumed only after the binder is verified
        ss_e, ct_e = hkem_encaps(pk_e) if mode == b"PSK_KEM" else (b"", b"")
        n_u = os.urandom(32)
        tail = enc([u64(now), u64(r64(t_chain))])                      # authenticated below via the transcript/MAC
        th = h(r1, b"RS", n_u, ct_e, tail)
        k, kc_u, kc_d, sid = _derive(th, psk + ss_e)
        mac_u = mac(kc_u, b"U-finished" + th)
        s = Session(did, t_cls.decode(), pinfo, r64(fw), k, sid, mode.decode(), r64(t_chain))
        self.pending[did] = (s, kc_d, h(th, mac_u))
        r2 = enc([b"RS", n_u, ct_e, tail, mac_u])
        self.dup.put(key, r2, now); return r2

    def on_resume_finished(self, topic_id: bytes, r3: bytes, now=None):
        now = int(now or self.u.now())
        key = h(b"RF", topic_id, r3)
        cached = self.dup.get(key, now)
        if cached: return cached
        if topic_id not in self.pending: raise HandshakeError("no pending resumption")
        s, kc_d, th3 = self.pending[topic_id]
        tag, mac_d = dec(r3, 2)
        if tag != b"DF" or not ct_eq(mac(kc_d, b"D-finished" + th3), mac_d): raise HandshakeError("device key confirmation failed")
        del self.pending[topic_id]
        self.u.sessions = {sid: x for sid, x in self.u.sessions.items() if x.device_id != s.device_id}
        self.u.sessions[s.sid] = s
        out = (s, self.issue(s, now))
        self.dup.put(key, out, now); return out

    def purge(self, now):
        self.used = {k: v for k, v in self.used.items() if v > now}; self._persist_used()

# =============================== device side ===============================
def store_ticket(d: Device, m4: bytes): return d.on_final(m4)

def resume_hello(d: Device, force_mode: str | None = None) -> bytes:
    t = d.ticket
    if not t: raise HandshakeError("no ticket stored")
    mode = (force_mode or t["mode"]).encode()
    d._reph = HybridKeyPair() if mode == b"PSK_KEM" else None
    pk_e = d._reph.pk if d._reph else b""
    f = [b"RH", t["blob"], os.urandom(32), mode, pk_e, d.id, d.policy.info(), u64(d.fw), u64(d.now())]
    d._r1 = enc(f + [mac(hkdf_expand(t["psk"], b"binder"), h(*f))]); d._rmode = mode
    return d._r1

def on_resume_server(d: Device, r2: bytes) -> bytes:
    tag, n_u, ct_e, tail, mac_u = dec(r2, 5)
    if tag != b"RS": raise HandshakeError("unexpected message")
    ss_e = hkem_decaps(d._reph, ct_e) if d._rmode == b"PSK_KEM" else b""
    th = h(d._r1, b"RS", n_u, ct_e, tail)
    k, kc_u, kc_d, sid = _derive(th, d.ticket["psk"] + ss_e)
    if not ct_eq(mac(kc_u, b"U-finished" + th), mac_u): raise HandshakeError("utility key confirmation failed")
    u_time, chain = dec(tail, 2)
    d.offset = r64(u_time) - d.clock()
    d.session = Session(d.id, d.dclass, d.policy.info(), d.fw, k, sid, d._rmode.decode(), r64(chain))
    d.confirmed, d.ticket = False, None          # single-use: wait for the replacement ticket (NT)
    return enc([b"DF", mac(kc_d, b"D-finished" + h(th, mac_u))])
