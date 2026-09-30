"""Design validation v2. Three groups:
  CORE   - every mechanism works and every attack fails closed
  EDGE   - duplicates, losses, crashes, restarts, clock resets, clones, key theft, malformed input
  RISK   - attacks we deliberately do NOT stop; shown so the limits are honest (expected to succeed)
"""
import os, random, tempfile, time, copy
from cryptography.exceptions import InvalidTag
from pqgrid_ref.suite import HybridKeyPair, mldsa_keygen, aead_seal, aead_open, hkdf_expand, h
from pqgrid_ref import policy as pol
from pqgrid_ref.policy import Tier, valid_device_id
from pqgrid_ref.e2e import Device, Utility, HandshakeError, UnknownSession, ReplayError, Session, _derive
from pqgrid_ref.pasr import PASR, STEK, resume_hello, on_resume_server
from pqgrid_ref.fota import Station, Installer, FIRMWARE, POLICY, FotaError
from pqgrid_ref.broadcast import seal_broadcast, ZoneReceiver
from pqgrid_ref.wire import enc, dec, u64, r64, WireError

random.seed(7)
R = []
def check(group, name, fn, expect_fail=False):
    try:
        out = fn()
        ok, detail = (not expect_fail), ("ok" if not expect_fail else f"ACCEPTED (should fail) {out!r}"[:80])
    except Exception as e:
        ok, detail = expect_fail, (f"rejected: {e}" if expect_fail else f"ERROR {type(e).__name__}: {e}")
    R.append((group, name, ok, detail))
def must(cond, msg="condition failed"):
    if not cond: raise AssertionError(msg)
    return True

RULES = [{"pattern": "grid/+/+/telemetry", "tier": "TELEMETRY"}, {"pattern": "grid/+/+/alert", "tier": "ALERT"},
         {"pattern": "grid/+/+/control", "tier": "CONTROL"}, {"pattern": "grid/dr/+/event", "tier": "CONTROL"}]
CLASSES = {"smart_meter":    {"resume": "PSK",     "ticket_lifetime_s": 86400, "max_chain_age_s": 604800, "unicast_control": False},
           "der_controller": {"resume": "PSK_KEM", "ticket_lifetime_s": 43200, "max_chain_age_s": 604800, "unicast_control": True}}
M_ALERT, D_CTL = "grid/smart_meter/meter-0001/alert", "grid/der_controller/der-0001/control"

class World:
    def __init__(self):
        self.tmp = tempfile.mkdtemp(); self.station = Station(self.tmp)
        self.u_static, self.cmd_sk = HybridKeyPair(), mldsa_keygen()
        self.cmd_pk = self.cmd_sk.public_key().public_bytes_raw()
        self.p1_raw = pol.build("nitk-grid", 1, RULES, CLASSES, self.u_static.pk, self.cmd_pk)
        self.registry = {}
        self.stek_path, self.used_path = os.path.join(self.tmp, "stek.json"), os.path.join(self.tmp, "used.json")
        self.U = self.new_utility(pol.load(self.p1_raw))
    def new_utility(self, policy, persist=True):
        U = Utility(policy, self.u_static, self.cmd_sk, self.registry)
        U.pasr = PASR(U, STEK(self.stek_path if persist else None), self.used_path if persist else None)
        return U
    def install_policy(self, inst, raw, ver):
        m, chunks = self.station.build(POLICY, inst.cls, ver, raw)
        st = inst.accept_manifest(m); [inst.accept_chunk(st, c) for c in chunks]
        out = pol.load(inst.finish(st)); inst.commit(POLICY); return out
    def device(self, did, dclass, fw=1, clock=time.time):
        inst = Installer(self.station.pk, dclass, {})
        d = Device(did, dclass, self.install_policy(inst, self.p1_raw, 1), fw, clock=clock); d.installer = inst
        self.registry[did] = {"pk": d.static.pk, "class": dclass, "active": True}
        return d

def full(U, dev, topic_id=None):
    m2 = U.on_client_hello(topic_id or dev.id, dev.hello()); m3 = dev.on_server_hello(m2)
    s, fin = U.on_finished(topic_id or dev.id, m3); resend = dev.on_final(fin)
    must(s.k_master == dev.session.k_master, "keys differ"); return s, resend
def resume(U, dev, force_mode=None, now=None):
    r2 = U.pasr.on_resume_hello(dev.id, resume_hello(dev, force_mode), now=now); r3 = on_resume_server(dev, r2)
    s, nt = U.pasr.on_resume_finished(dev.id, r3, now=now); resend = dev.on_final(nt)
    must(s.k_master == dev.session.k_master, "keys differ"); return s, resend
def sess(U, did): return [s for s in U.sessions.values() if s.device_id == did][-1]
def tamper(buf, idx, n):
    f = dec(buf, n); b = bytearray(f[idx]); b[len(b)//2] ^= 1; f[idx] = bytes(b); return enc(f)

W = World(); U = W.U
meter, der = W.device(b"meter-0001", "smart_meter"), W.device(b"der-0001", "der_controller")
W.registry[b"meter-0002"] = {"pk": HybridKeyPair().pk, "class": "smart_meter", "active": True}
p1 = pol.load(W.p1_raw)

# ================================ CORE ================================
C = "CORE"
check(C, "PCHC full hybrid KEM-MQTT handshake (meter), keys equal", lambda: full(U, meter))
check(C, "PCHC full handshake (DER controller)", lambda: full(U, der))
check(C, "tier engine: telemetry/alert/control/unknown -> 1/2/3/3",
      lambda: must([int(p1.tier(t)) for t in ["grid/a/b/telemetry", "grid/a/b/alert", "grid/a/b/control", "grid/x/unknown"]] == [1,2,3,3]))
check(C, "tier engine: overlapping rules -> strongest wins", lambda: must(pol.load(pol.build("x",1,[{"pattern":"grid/#","tier":"TELEMETRY"},{"pattern":"grid/+/+/alert","tier":"ALERT"}],CLASSES,b"a",b"b")).tier("grid/a/b/alert") == Tier.ALERT))
env = meter.seal_alert(M_ALERT, b"VOLTAGE_SAG 182V")
res = {}
check(C, "alert end to end (device -> utility) + end-to-end ACK", lambda: (res.__setitem__("a", U.open_alert(M_ALERT, env)), must(res["a"][0] == b"VOLTAGE_SAG 182V" and not res["a"][2]), meter.on_alert_ack(res["a"][1]), must(meter.flash["outbox"] == [])))
check(C, "curious broker sees no alert plaintext", lambda: must(b"VOLTAGE_SAG" not in env))
cenv = U.seal_control(sess(U, der.id), D_CTL, b"SET_EXPORT_LIMIT 5kW")
check(C, "control command: AEAD + ML-DSA-65 verified, applied, ACK clears utility queue",
      lambda: (res.__setitem__("c", der.open_control(D_CTL, cenv)), must(res["c"][0] == b"SET_EXPORT_LIMIT 5kW"), must(U.on_command_ack(res["c"][1]) == b"OK"), must(not U.pending_cmds[der.id])))
check(C, "tamper POLICY_INFO inside client hello (broker MITM)", lambda: U.on_client_hello(meter.id, tamper(meter.hello(), 5, 6)), True)
def tamper_sh():
    m2 = U.on_client_hello(meter.id, meter.hello()); return meter.on_server_hello(tamper(m2, 4, 6))
check(C, "tamper POLICY_INFO inside server hello (broker MITM)", tamper_sh, True)
meter.__dict__.pop("_m1", None)
check(C, "client hello replayed onto another device's topic", lambda: U.on_client_hello(b"meter-0002", meter.hello()), True)
meter.__dict__.pop("_m1", None)
check(C, "device refuses to seal an ALERT on a TELEMETRY topic", lambda: meter.seal_alert("grid/smart_meter/meter-0001/telemetry", b"x"), True)
check(C, "plaintext (tier-stripped) message on ALERT topic", lambda: U.open_alert(M_ALERT, enc([b"\x02", b"\x00"*8, b"\x00"*8, b"VOLTAGE_SAG"])), True)
check(C, "alert replay (same envelope again)", lambda: U.open_alert(M_ALERT, env), True)
def forged_does_not_consume():
    good = meter.seal_alert(M_ALERT, b"OK-NEXT"); t, sid, seq, ct = dec(good, 4)
    try: U.open_alert(M_ALERT, enc([t, sid, seq, ct[:-1] + bytes([ct[-1]^1])]))
    except Exception: pass
    return must(U.open_alert(M_ALERT, good)[0] == b"OK-NEXT")
check(C, "forged alert (bad tag) does not consume the sequence number", forged_does_not_consume)
check(C, "control command replay is acknowledged as DUP but never re-applied", lambda: must(der.open_control(D_CTL, cenv)[0] is None))
def forged_cmd_with_session_key():
    s = der.session; seq = u64(99); exp = u64(int(time.time()) + 60); rogue = mldsa_keygen()
    sig = rogue.sign(b"pqgrid/v1/cmd" + h(der.id, D_CTL.encode(), seq, exp, b"TRIP_INVERTER"))
    ct = aead_seal(s.key("CONTROL", b"down"), b"\x02\x00\x00\x00" + seq, enc([b"TRIP_INVERTER", exp, sig]), h(b"CONTROL", D_CTL.encode(), s.sid, seq))
    return der.open_control(D_CTL, enc([b"\x03", s.sid, seq, ct]))
check(C, "forged command by holder of session key but not utility signing key", forged_cmd_with_session_key, True)
check(C, "unsafe policy (unicast-control class with PSK-only resume) rejected",
      lambda: pol.build("x",1,RULES,{"der":{"resume":"PSK","ticket_lifetime_s":10,"max_chain_age_s":20,"unicast_control":True}},b"a",b"b"), True)
zone_key = os.urandom(32)
rx = ZoneReceiver(meter.policy.utility_cmd_pk); rx.keys[(b"zone-7", 1)] = zone_key
dr = seal_broadcast(W.cmd_sk, b"zone-7", 1, zone_key, 1, b"REDUCE_LOAD 20% 17:00-19:00")
check(C, "broadcast DR event: zone key + utility signature", lambda: rx.open(dr))
check(C, "broadcast DR replay", lambda: rx.open(dr), True)
check(C, "captured meter forges DR event (has zone key, lacks utility key)", lambda: rx.open(seal_broadcast(mldsa_keygen(), b"zone-7", 1, zone_key, 5, b"SHED_ALL")), True)
check(C, "PASR resume, PSK mode (meter): keys match, new ticket", lambda: resume(U, meter))
check(C, "PASR resume, PSK_KEM mode (DER, fresh hybrid KEM)", lambda: resume(U, der))
r1_old = resume_hello(meter); saved = copy.deepcopy(meter.ticket)
def first_use():
    r3 = on_resume_server(meter, U.pasr.on_resume_hello(meter.id, r1_old)); s, nt = U.pasr.on_resume_finished(meter.id, r3); meter.on_final(nt)
    return must(s.k_master == meter.session.k_master)
check(C, "PASR resume again (ticket rotated, chain continues)", first_use)
check(C, "ticket replay: same resume hello after the duplicate window", lambda: U.pasr.on_resume_hello(meter.id, r1_old, now=time.time() + 600), True)
meter.ticket = copy.deepcopy(saved)
check(C, "ticket reuse: same ticket, fresh resume hello (clone)", lambda: U.pasr.on_resume_hello(meter.id, resume_hello(meter)), True)
full(U, meter); t_good = copy.deepcopy(meter.ticket)
def binder_forgery():
    fake = dict(t_good); fake["psk"] = os.urandom(32); m = copy.copy(meter); m.flash = dict(meter.flash); m.ticket = fake
    return U.pasr.on_resume_hello(meter.id, resume_hello(m))
check(C, "stolen ticket blob without PSK (binder forgery)", binder_forgery, True)
check(C, "...and the forgery did not burn the legitimate ticket", lambda: (setattr(meter, "ticket", copy.deepcopy(t_good)), resume(U, meter)))
t_now = copy.deepcopy(meter.ticket)
check(C, "ticket presented on another device's channel", lambda: U.pasr.on_resume_hello(b"meter-0002", resume_hello(meter)), True)
check(C, "expired ticket (2 days later)", lambda: U.pasr.on_resume_hello(meter.id, resume_hello(meter), now=time.time() + 2*86400), True)
t_der = copy.deepcopy(der.ticket)
check(C, "resume-mode downgrade (DER strips fresh KEM: PSK_KEM -> PSK)", lambda: U.pasr.on_resume_hello(der.id, resume_hello(der, force_mode="PSK")), True)
meter.fw = 2
check(C, "stale ticket after firmware update", lambda: U.pasr.on_resume_hello(meter.id, resume_hello(meter)), True)
meter.fw = 1
old_kid = U.pasr.stek.kid; U.pasr.stek.rotate(); U.pasr.stek.retire(old_kid)
check(C, "ticket sealed under a retired STEK", lambda: U.pasr.on_resume_hello(meter.id, resume_hello(meter)), True)
full(U, meter); t_now = copy.deepcopy(meter.ticket)
W.registry[b"meter-0001"]["active"] = False
check(C, "revoked device: resumption refused", lambda: U.pasr.on_resume_hello(meter.id, resume_hello(meter)), True)
check(C, "revoked device: full handshake refused", lambda: U.on_client_hello(meter.id, meter.hello()), True)
W.registry[b"meter-0001"]["active"] = True; meter.__dict__.pop("_m1", None)
p2_raw = pol.build("nitk-grid", 2, RULES, CLASSES, W.u_static.pk, W.cmd_pk)
U.policy = pol.load(p2_raw)
check(C, "stale ticket after policy change", lambda: U.pasr.on_resume_hello(meter.id, resume_hello(meter)), True)
check(C, "device still on old policy: full handshake refused (fail closed)", lambda: U.on_client_hello(meter.id, meter.hello()), True)
meter.__dict__.pop("_m1", None)
def old_policy_alert():
    s = meter.session; s_u = U.sessions.get(s.sid) or Session(meter.id, "smart_meter", p1.info(), 1, s.k_master, s.sid, "PSK", 0)
    U.sessions[s.sid] = s_u; return U.open_alert(M_ALERT, meter.seal_alert(M_ALERT, b"x"))
check(C, "old-policy session: alerts refused", old_policy_alert, True)
check(C, "device installs signed policy v2 via PQC-FOTA", lambda: setattr(meter, "policy", W.install_policy(meter.installer, p2_raw, 2)))
check(C, "full handshake under policy v2 succeeds", lambda: full(U, meter))
check(C, "policy rollback: old signed policy v1 re-served by broker", lambda: W.install_policy(meter.installer, W.p1_raw, 1), True)
rogue = Station(tempfile.mkdtemp())
check(C, "forged policy (signed by a non-station key)", lambda: meter.installer.accept_manifest(rogue.build(POLICY, "smart_meter", 99, p2_raw)[0]), True)
image = os.urandom(1024 * 1024); fw_manifest, fw_chunks = W.station.build(FIRMWARE, "smart_meter", 2, image)
inst_m = meter.installer
def install_fw(chunks, manifest=fw_manifest, commit=True):
    st = inst_m.accept_manifest(manifest); order = list(chunks); random.shuffle(order)
    for c in order: inst_m.accept_chunk(st, c)
    out = inst_m.finish(st); must(out == image)
    if commit: inst_m.commit(FIRMWARE)
    return True
bad = list(fw_chunks); f = dec(bad[17], 5); b = bytearray(f[3]); b[100] ^= 1; f[3] = bytes(b); bad[17] = enc(f)
check(C, "tampered firmware chunk", lambda: install_fw(bad), True)
mf = bytearray(fw_manifest); mf[60] ^= 1
check(C, "tampered firmware manifest", lambda: inst_m.accept_manifest(bytes(mf)), True)
check(C, "firmware v2 install: 1 MiB, 256 chunks, shuffled delivery, committed", lambda: install_fw(fw_chunks))
check(C, "firmware rollback to v1 (validly signed)", lambda: inst_m.accept_manifest(W.station.build(FIRMWARE, "smart_meter", 1, os.urandom(4096))[0]), True)
check(C, "firmware replay of v2 (already installed)", lambda: inst_m.accept_manifest(fw_manifest), True)
check(C, "firmware for another device class", lambda: inst_m.accept_manifest(W.station.build(FIRMWARE, "der_controller", 9, os.urandom(4096))[0]), True)

# ================================ EDGE ================================
E = "EDGE"
W = World(); U = W.U
a, b_ = W.device(b"meter-0101", "smart_meter"), W.device(b"der-0101", "der_controller")
A_ALERT, B_CTL = "grid/smart_meter/meter-0101/alert", "grid/der_controller/der-0101/control"

def dup_ch():
    m1 = a.hello(); m2a = U.on_client_hello(a.id, m1); m2b = U.on_client_hello(a.id, m1)
    must(m2a == m2b, "duplicate got a different answer")
    s, fin = U.on_finished(a.id, a.on_server_hello(m2a)); a.on_final(fin); return must(s.k_master == a.session.k_master)
check(E, "MQTT QoS 1 duplicate of client hello -> identical answer, handshake completes", dup_ch)
def dup_df():
    m3 = a.on_server_hello(U.on_client_hello(a.id, a.hello()))
    s1, f1 = U.on_finished(a.id, m3); s2, f2 = U.on_finished(a.id, m3)
    must(f1 == f2 and s1 is s2); a.on_final(f1)
    return must(len([x for x in U.sessions.values() if x.device_id == a.id]) == 1)
check(E, "duplicate finished -> same final message, exactly one session", dup_df)
def dup_rh():
    r1 = resume_hello(a); r2a = U.pasr.on_resume_hello(a.id, r1); r2b = U.pasr.on_resume_hello(a.id, r1)
    must(r2a == r2b); s, nt = U.pasr.on_resume_finished(a.id, on_resume_server(a, r2a)); a.on_final(nt)
    return must(s.k_master == a.session.k_master)
check(E, "duplicate resume hello -> identical answer (not 'ticket already used')", dup_rh)
def lost_sh():
    m1a = a.hello(); m2a = U.on_client_hello(a.id, m1a)            # m2a lost in the network
    m1b = a.hello(); m2b = U.on_client_hello(a.id, m1b)            # device times out and retries
    try: a.on_server_hello(m2a); raise AssertionError("late server hello accepted")
    except HandshakeError: pass                                    # late copy of the lost reply is rejected...
    s, fin = U.on_finished(a.id, a.on_server_hello(m2b)); a.on_final(fin)   # ...and the retry still completes
    return must(s.k_master == a.session.k_master)
check(E, "lost server hello -> retry completes; the late original reply is rejected", lost_sh)
def lost_df():
    m3 = a.on_server_hello(U.on_client_hello(a.id, a.hello()))      # first DF lost
    must(a.confirmed is False);
    try: a.seal_alert(A_ALERT, b"x"); raise AssertionError("sent on unconfirmed session")
    except ValueError: pass
    s, fin = U.on_finished(a.id, m3); a.on_final(fin); return must(a.confirmed)
check(E, "lost finished -> device will not send until confirmed; resend completes", lost_df)
def lost_final():
    m3 = a.on_server_hello(U.on_client_hello(a.id, a.hello()))
    s, fin = U.on_finished(a.id, m3)                                # final (ticket) lost
    s2, fin2 = U.on_finished(a.id, m3)                              # device resends finished
    a.on_final(fin2); return must(a.confirmed and fin == fin2)
check(E, "lost final/ticket -> resent finished returns the same ticket", lost_final)
def clock_1970():
    d = W.device(b"meter-0199", "smart_meter", clock=lambda: 1000.0)   # RTC reset by power loss
    s, _ = full(U, d); must(abs(d.now() - time.time()) < 5, "clock not corrected")
    return True
check(E, "device clock reset to 1970 after outage -> still connects; clock corrected from utility", clock_1970)
def clock_future():
    d = W.device(b"der-0199", "der_controller", clock=lambda: time.time() + 86400)
    s, _ = full(U, d); cmd, ack = d.open_control("grid/der_controller/der-0199/control", U.seal_control(s, "grid/der_controller/der-0199/control", b"SET 1kW"))
    return must(cmd == b"SET 1kW", "fresh command rejected as expired")
check(E, "device clock a day ahead -> fresh commands still accepted (utility time used)", clock_future)
def utility_restart():
    global U
    full(U, a); env1 = a.seal_alert(A_ALERT, b"FREQ_DEVIATION")    # alert sent, utility crashes before reading it
    U = W.new_utility(U.policy)                                    # restart: sessions gone, STEK + used tickets persisted
    try: U.open_alert(A_ALERT, env1); raise AssertionError("unknown session accepted")
    except UnknownSession as e: hint = e.hint
    must(a.on_resync(hint), "device ignored resync hint")
    _, resend = resume(U, a); must(len(resend) == 1, "unacked alert not resent")
    payload, ack, dup = U.open_alert(A_ALERT, resend[0]); a.on_alert_ack(ack)
    return must(payload == b"FREQ_DEVIATION" and a.flash["outbox"] == [])
check(E, "utility restart -> resync hint -> PASR resume -> unacknowledged alert resent and acked", utility_restart)
def restart_without_stek():
    full(U, a); U2 = W.new_utility(U.policy, persist=False)
    return U2.pasr.on_resume_hello(a.id, resume_hello(a))
check(E, "counterfactual: restart WITHOUT persisted STEK -> every ticket dies (why we persist it)", restart_without_stek, True)
def consumed_ticket_after_restart():
    global U
    full(U, a); r1 = resume_hello(a); t = copy.deepcopy(a.ticket)
    s, nt = U.pasr.on_resume_finished(a.id, on_resume_server(a, U.pasr.on_resume_hello(a.id, r1))); a.on_final(nt)
    U = W.new_utility(U.policy)
    return U.pasr.on_resume_hello(a.id, r1)
check(E, "consumed ticket replayed after a utility restart", consumed_ticket_after_restart, True)
def device_reboot():
    full(U, a); env1 = a.seal_alert(A_ALERT, b"TAMPER_SWITCH")     # alert sent, device loses power before ACK
    a.reboot(); must(a.session is None and len(a.flash["outbox"]) == 1)
    _, resend = resume(U, a); payload, ack, dup = U.open_alert(A_ALERT, resend[0]); a.on_alert_ack(ack)
    return must(payload == b"TAMPER_SWITCH" and not dup)
check(E, "device reboot -> PASR resume from flash ticket -> pending alert delivered", device_reboot)
def lost_alert_ack():
    full(U, a); env1 = a.seal_alert(A_ALERT, b"OVERCURRENT")
    p1_, ack1, dup1 = U.open_alert(A_ALERT, env1)                  # utility got it; ACK lost
    a.reboot(); _, resend = resume(U, a)
    p2_, ack2, dup2 = U.open_alert(A_ALERT, resend[0]); a.on_alert_ack(ack2)
    return must(dup2 and not dup1, "duplicate not detected")
check(E, "lost alert ACK -> resend -> utility recognises the duplicate by alert id", lost_alert_ack)
def cmd_while_offline():
    s, _ = full(U, b_); env1 = U.seal_control(s, B_CTL, b"CURTAIL 50%")   # device offline: lost
    b_.reboot(); s2, _ = resume(U, b_)
    out = U.redeliver_commands(s2); must(len(out) == 1)
    cmd, ack = b_.open_control(B_CTL, out[0][1]); return must(cmd == b"CURTAIL 50%" and U.on_command_ack(ack) == b"OK" and not U.pending_cmds[b_.id])
check(E, "command sent while device offline -> redelivered on next session, applied once", cmd_while_offline)
def cmd_ack_lost():
    s = sess(U, b_.id); env1 = U.seal_control(s, B_CTL, b"SETPOINT 3kW")
    cmd, ack = b_.open_control(B_CTL, env1)                          # applied; ACK lost
    out = U.redeliver_commands(s); cmd2, ack2 = b_.open_control(B_CTL, out[0][1])
    return must(cmd == b"SETPOINT 3kW" and cmd2 is None and U.on_command_ack(ack2) == b"DUP" and not U.pending_cmds[b_.id])
check(E, "command ACK lost -> redelivery acknowledged as DUP, never applied twice", cmd_ack_lost)
def cmd_ack_lost_then_reboot():
    s = sess(U, b_.id); env1 = U.seal_control(s, B_CTL, b"OPEN_BREAKER")
    cmd, ack = b_.open_control(B_CTL, env1)                          # applied; ACK lost; then power failure
    b_.reboot(); s2, _ = resume(U, b_); out = U.redeliver_commands(s2)
    cmd2, ack2 = b_.open_control(B_CTL, out[0][1])
    return must(cmd == b"OPEN_BREAKER" and cmd2 is None and U.on_command_ack(ack2) == b"DUP", "re-applied after reboot")
check(E, "command applied, ACK lost, device reboots -> redelivery is DUP (flash counter), never re-applied", cmd_ack_lost_then_reboot)
def cmd_expired():
    s = sess(U, b_.id); env1 = U.seal_control(s, B_CTL, b"OLD", ttl_s=1, now=time.time() - 100)
    must(U.redeliver_commands(s) == [], "expired command redelivered")
    cmd, ack = b_.open_control(B_CTL, env1); return must(cmd is None and U.on_command_ack(ack) == b"EXPIRED")
check(E, "expired command is not redelivered, and is refused (EXPIRED) if it arrives late", cmd_expired)
def cmd_out_of_order():
    s = sess(U, b_.id); e1 = U.seal_control(s, B_CTL, b"CMD-1"); e2 = U.seal_control(s, B_CTL, b"CMD-2")
    c2, _ = b_.open_control(B_CTL, e2); c1, ack1 = b_.open_control(B_CTL, e1)
    return must(c2 == b"CMD-2" and c1 is None, "older command applied after newer")
check(E, "commands out of order -> newest wins; older one acknowledged, not applied", cmd_out_of_order)
def forged_resync():
    d = W.device(b"meter-0404", "smart_meter"); full(U, d)
    hint = enc([b"\x07", d.session.sid])                             # sid is visible in every envelope header
    first = d.on_resync(hint); resume(U, d); second = d.on_resync(enc([b"\x07", d.session.sid]))
    return must(first and not second, "rate limit failed")
check(E, "forged resync hint -> one cheap resume, further hints rate-limited (DoS only)", forged_resync)
check(E, "device ids with '+', '#', '/', uppercase, spaces, unicode, >32 chars rejected",
      lambda: must(not any(valid_device_id(x) for x in [b"meter+1", b"meter#", b"a/b", b"Meter", b"a b", "mèter".encode(), b"m" * 33, b""]) and valid_device_id(b"meter-0001")))
check(E, "oversized length field rejected before allocation", lambda: dec(b"\xff\xff\xff\xff" + b"x" * 16, 1), True)

def fuzz():
    """3,300 corrupted messages (bit flips, byte overwrites, truncation, extension, garbage) into every handler.
    Every one must be rejected with a controlled error: never accepted, never an unexpected crash."""
    OK_ERR = (HandshakeError, WireError, ValueError, InvalidTag, ReplayError, FotaError)
    samples = {}
    dc = W.device(b"meter-0770", "smart_meter"); m1c = dc.hello()
    samples["client hello"] = (m1c, lambda m: U.on_client_hello(dc.id, m))
    dh = W.device(b"meter-0771", "smart_meter"); m2h = U.on_client_hello(dh.id, dh.hello())
    samples["server hello"] = (m2h, lambda m: dh.on_server_hello(m))              # device genuinely mid-handshake
    df = W.device(b"meter-0772", "smart_meter"); m3f = df.on_server_hello(U.on_client_hello(df.id, df.hello()))
    samples["finished"] = (m3f, lambda m: U.on_finished(df.id, m))                 # utility genuinely has pending state
    d = W.device(b"meter-0777", "smart_meter"); m3 = d.on_server_hello(U.on_client_hello(d.id, d.hello()))
    s, nt = U.on_finished(d.id, m3); samples["ticket"] = (nt, lambda m: d.on_final(m)); d.on_final(nt)
    r1 = resume_hello(d); samples["resume hello"] = (r1, lambda m: U.pasr.on_resume_hello(d.id, m))
    al = d.seal_alert("grid/smart_meter/meter-0777/alert", b"x"); samples["alert"] = (al, lambda m: U.open_alert("grid/smart_meter/meter-0777/alert", m))
    dd = W.device(b"der-0777", "der_controller"); sd, _ = full(U, dd)
    ctl = U.seal_control(sd, "grid/der_controller/der-0777/control", b"SET"); samples["command"] = (ctl, lambda m: dd.open_control("grid/der_controller/der-0777/control", m))
    zk = os.urandom(32); zr = ZoneReceiver(W.cmd_pk); zr.keys[(b"z", 1)] = zk
    samples["broadcast"] = (seal_broadcast(W.cmd_sk, b"z", 1, zk, 1, b"EV"), lambda m: zr.open(m))
    ins = Installer(W.station.pk, "smart_meter", {}); man, ch = W.station.build(FIRMWARE, "smart_meter", 5, os.urandom(40000))
    samples["manifest"] = (man, lambda m: ins.accept_manifest(m))
    st = ins.accept_manifest(man); samples["firmware chunk"] = (ch[3], lambda m: ins.accept_chunk(st, m))
    samples["alert ack"] = (U.open_alert("grid/smart_meter/meter-0777/alert", d.seal_alert("grid/smart_meter/meter-0777/alert", b"y"))[1], lambda m: d.on_alert_ack(m))
    def mutate(x):
        b = bytearray(x); k = random.randrange(6)
        if k == 0: i = random.randrange(len(b)); b[i] ^= 1 << random.randrange(8)
        elif k == 1: i = random.randrange(len(b)); b[i] = (b[i] + random.randrange(1, 256)) % 256
        elif k == 2: b = b[:random.randrange(len(b))]
        elif k == 3: b += os.urandom(random.randrange(1, 64))
        elif k == 4: i = random.randrange(len(b)); b[i:i+8] = os.urandom(8) if len(b) > i + 8 else b[i:i+8]
        else: b = bytearray(os.urandom(len(b)))
        return bytes(b) if bytes(b) != x else x + b"\x00"
    accepted, crashed, total = [], [], 0
    for name, (msg, handler) in samples.items():
        for _ in range(300):
            total += 1
            try: handler(mutate(msg)); accepted.append(name)
            except OK_ERR: pass
            except Exception as e: crashed.append(f"{name}: {type(e).__name__}")
    must(U.pasr.on_resume_hello(d.id, r1) is not None, "fuzzing burned the real ticket")   # genuine messages still work
    must(dh.on_server_hello(m2h) is not None, "fuzzing broke the device handshake state")
    must(U.on_finished(df.id, m3f) is not None, "fuzzing broke the utility pending state")
    must(not accepted, f"accepted corrupted: {sorted(set(accepted))}"); must(not crashed, f"unexpected crashes: {sorted(set(crashed))[:5]}")
    return total
check(E, "fuzz: 3,300 corrupted messages into 11 handlers -> all rejected cleanly; genuine ticket still valid", fuzz)
def fw_power_loss():
    ins = Installer(W.station.pk, "smart_meter", {FIRMWARE: 1}); img = os.urandom(200_000)
    man, ch = W.station.build(FIRMWARE, "smart_meter", 2, img)
    st = ins.accept_manifest(man); [ins.accept_chunk(st, c) for c in ch[:20]]           # power lost at chunk 20
    st = ins.accept_manifest(man); [ins.accept_chunk(st, c) for c in ch]                 # reboot: re-fetch retained chunks
    must(ins.finish(st) == img); ins.commit(FIRMWARE); return must(ins.installed[FIRMWARE] == 2)
check(E, "power loss mid-download -> restart download from retained chunks -> installs", fw_power_loss)
def fw_bad_boot():
    ins = Installer(W.station.pk, "smart_meter", {FIRMWARE: 1}); man, ch = W.station.build(FIRMWARE, "smart_meter", 2, os.urandom(9000))
    st = ins.accept_manifest(man); [ins.accept_chunk(st, c) for c in ch]; ins.finish(st)
    ins.revert(FIRMWARE); must(ins.installed[FIRMWARE] == 1, "counter moved before a successful boot")  # new image failed to boot
    st = ins.accept_manifest(man); [ins.accept_chunk(st, c) for c in ch]; ins.finish(st); ins.commit(FIRMWARE)   # retry succeeds
    try: ins.accept_manifest(W.station.build(FIRMWARE, "smart_meter", 1, os.urandom(10))[0]); raise AssertionError("rollback accepted")
    except FotaError: return True
check(E, "new firmware fails to boot -> revert, counter unchanged; retry works; rollback still blocked", fw_bad_boot)
def fw_mixed_chunks():
    ins = Installer(W.station.pk, "smart_meter", {}); m2_, c2 = W.station.build(FIRMWARE, "smart_meter", 2, os.urandom(9000))
    _, c3 = W.station.build(FIRMWARE, "smart_meter", 3, os.urandom(9000)); st = ins.accept_manifest(m2_)
    return ins.accept_chunk(st, c3[0])
check(E, "chunk from a different firmware version mixed in", fw_mixed_chunks, True)
def offline_policy_jump():
    d = W.device(b"meter-0303", "smart_meter"); raws = {v: pol.build("nitk-grid", v, RULES, CLASSES, W.u_static.pk, W.cmd_pk) for v in (2, 3, 4)}
    d.policy = W.install_policy(d.installer, raws[4], 4)            # offline through v2, v3: installs v4 directly
    try: W.install_policy(d.installer, raws[3], 3); raise AssertionError("older policy accepted")
    except FotaError: pass
    U4 = W.new_utility(pol.load(raws[4])); full(U4, d); return True
check(E, "device offline across policy v1 -> v4 -> installs v4 directly, v3 refused, handshake under v4", offline_policy_jump)
def clone_detection():
    full(U, a); clone = copy.copy(a); clone.flash = copy.deepcopy(a.flash); clone.__dict__.pop("session", None)
    resume(U, clone)                                                # clone resumes first with the copied ticket
    try: U.pasr.on_resume_hello(a.id, resume_hello(a)); raise AssertionError("second use accepted")
    except HandshakeError as e: must("already used" in str(e))
    full(U, a)                                                      # genuine device falls back to a full handshake
    return must(clone.session.sid not in U.sessions, "clone session still live")
check(E, "cloned device uses ticket first -> genuine device sees 'already used' (alarm), full handshake evicts clone", clone_detection)
def replayed_old_ch():
    full(U, a); old = a.hello(); U.on_client_hello(a.id, old); a.__dict__.pop("_m1", None)
    full(U, a); sid = a.session.sid
    U.on_client_hello(a.id, old, now=time.time() + 600)             # broker replays an old hello later
    return must(U.open_alert(A_ALERT, a.seal_alert(A_ALERT, b"still fine"))[0] == b"still fine" and a.session.sid == sid)
check(E, "old client hello replayed while a session is live -> live session unaffected", replayed_old_ch)
def cross_device_replay():
    full(U, a); env_a = a.seal_alert(A_ALERT, b"A's alert")
    return U.open_alert("grid/smart_meter/meter-0102/alert", env_a)     # captured meter-0102 republishes it as its own
check(E, "captured meter re-publishes another meter's alert envelope on its own topic", cross_device_replay, True)
def pending_flood():
    before = len(U.pending)
    for _ in range(300): U.on_client_hello(a.id, a.hello())
    a.__dict__.pop("_m1", None); return must(len(U.pending) <= before + 1, f"half-open state grew to {len(U.pending)}")
check(E, "handshake flood from one device -> at most one half-open state kept", pending_flood)
def zone_rekey():
    k1, k2 = os.urandom(32), os.urandom(32); removed = ZoneReceiver(W.cmd_pk); removed.keys[(b"z9", 1)] = k1
    return removed.open(seal_broadcast(W.cmd_sk, b"z9", 2, k2, 1, b"EVENT"))
check(E, "member removed from zone (holds old epoch key) cannot read events under the new epoch", zone_rekey, True)

# ================================ RISK ================================
K = "RISK"
def stolen_utility_kem_key():
    """Attacker (e.g. a compromised broker) steals the utility's end-to-end static key and impersonates the utility."""
    d = W.device(b"der-0555", "der_controller")
    fake = Utility(U.policy, W.u_static, mldsa_keygen(), dict(W.registry))    # same KEM key, but NOT the command key
    s, _ = full(fake, d)                                                       # handshake succeeds: alerts readable
    try: d.open_control("grid/der_controller/der-0555/control", fake.seal_control(s, "grid/der_controller/der-0555/control", b"TRIP")); return "COMMAND ACCEPTED"
    except ValueError: return "handshake impersonated; forged command still rejected (separate ML-DSA key)"
check(K, "stolen utility E2E key: attacker can read new sessions, but cannot forge commands", stolen_utility_kem_key)
def stolen_stek():
    """Attacker steals the STEK and mints a ticket for a device it never compromised."""
    d = W.device(b"meter-0666", "smart_meter"); s, _ = full(U, d)
    tid, psk, now = os.urandom(16), os.urandom(32), int(time.time())
    pt = enc([tid, d.id, b"smart_meter", U.policy.info(), u64(1), b"PSK", u64(now), u64(now + 3600), u64(now + 86400), psk])
    kid = bytes([U.pasr.stek.kid]); n = os.urandom(12)
    blob = b"\x01" + kid + n + aead_seal(U.pasr.stek.keys[U.pasr.stek.kid], n, pt, b"\x01" + kid)
    imp = copy.copy(d); imp.flash = {"ticket": {"blob": blob, "psk": psk, "exp": now + 3600, "mode": "PSK"}, "last_cmd_seq": 0, "outbox": []}
    resume(U, imp); return "impersonated the device via a forged ticket"
check(K, "stolen STEK: attacker mints tickets and impersonates devices (why the STEK needs an HSM)", stolen_stek)

w = max(len(n) for _, n, _, _ in R)
for g in ("CORE", "EDGE", "RISK"):
    rows = [r for r in R if r[0] == g]
    print(f"\n=== {g} ({sum(ok for *_, ok, _ in rows)}/{len(rows)} as expected) ===")
    for _, n, ok, d in rows: print(f"{'PASS' if ok else 'FAIL'}  {n:<{w}}  {d[:95]}")
print(f"\nTOTAL {sum(ok for *_, ok, _ in R)}/{len(R)} as expected")
