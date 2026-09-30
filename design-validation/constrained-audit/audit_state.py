"""Persistent-state audit of the v2.1 reference implementation (design-validation/reference/pqgrid_ref).
Each check DEMONSTRATES a weakness: "DEMONSTRATED" means the weakness is real in the reference code.
These were not covered by validate.py's 80 scenarios.                                 [REAL DOCKER MEASUREMENT]
  S1 utility restart resets the per-device command sequence -> new commands answered DUP, silently dropped
  S2 crash between the flash counter write and actuation -> command acknowledged OK but never applied
  S3 crash while rewriting used-ticket / STEK files (non-atomic) -> utility cannot restart
  S4 cost of rewriting the whole used-ticket file on every resumption, vs fleet size
  S5 device retries a resume with a rebuilt (not identical) hello after the first was processed -> full handshake"""
import os, sys, time, json, tempfile, copy
sys.path.insert(0, "/proto")
from pqgrid_ref.suite import HybridKeyPair, mldsa_keygen
from pqgrid_ref import policy as pol
from pqgrid_ref.e2e import Device, Utility, HandshakeError
from pqgrid_ref.pasr import PASR, STEK, resume_hello, on_resume_server
from pqgrid_ref.fota import Station, Installer, POLICY

RULES = [{"pattern": "grid/+/+/telemetry", "tier": "TELEMETRY"}, {"pattern": "grid/+/+/alert", "tier": "ALERT"},
         {"pattern": "grid/+/+/control", "tier": "CONTROL"}]
CLASSES = {"smart_meter":    {"resume": "PSK",     "ticket_lifetime_s": 86400, "max_chain_age_s": 604800, "unicast_control": False},
           "der_controller": {"resume": "PSK_KEM", "ticket_lifetime_s": 43200, "max_chain_age_s": 604800, "unicast_control": True}}
CTL = "grid/der_controller/der-0001/control"

class World:
    def __init__(self):
        self.tmp = tempfile.mkdtemp(); self.station = Station(self.tmp)
        self.u_static, self.cmd_sk = HybridKeyPair(), mldsa_keygen()
        self.raw = pol.build("nitk-grid", 1, RULES, CLASSES, self.u_static.pk, self.cmd_sk.public_key().public_bytes_raw())
        self.registry = {}; self.stek_path, self.used_path = f"{self.tmp}/stek.json", f"{self.tmp}/used.json"
        self.U = self.new_utility()
    def new_utility(self):
        U = Utility(pol.load(self.raw), self.u_static, self.cmd_sk, self.registry)
        U.pasr = PASR(U, STEK(self.stek_path), self.used_path); return U
    def device(self, did, dclass):
        inst = Installer(self.station.pk, dclass, {})
        m, chunks = self.station.build(POLICY, dclass, 1, self.raw); st = inst.accept_manifest(m)
        [inst.accept_chunk(st, c) for c in chunks]; p = pol.load(inst.finish(st)); inst.commit(POLICY)
        d = Device(did, dclass, p, 1); self.registry[did] = {"pk": d.static.pk, "class": dclass, "active": True}; return d

def full(U, d):
    s, fin = U.on_finished(d.id, d.on_server_hello(U.on_client_hello(d.id, d.hello()))); d.on_final(fin); return s
def resume(U, d):
    s, nt = U.pasr.on_resume_finished(d.id, on_resume_server(d, U.pasr.on_resume_hello(d.id, resume_hello(d)))); d.on_final(nt); return s
def report(tag, demonstrated, detail): print(f"  {tag}: {'DEMONSTRATED' if demonstrated else 'not reproduced'} - {detail}")

W = World(); U = W.U; der = W.device(b"der-0001", "der_controller")
print("== persistent-state audit of the v2.1 reference implementation ==")

# ---------------------------------------------------------------- S1
s = full(U, der); applied = []
for cmd in (b"SET 1kW", b"SET 2kW", b"SET 3kW"):
    c, ack = der.open_control(CTL, U.seal_control(s, CTL, cmd)); U.on_command_ack(ack); applied.append(c)
U = W.new_utility()                                         # utility restart: STEK + used list persisted, cmd_seq is not
s2 = resume(U, der)
c, ack = der.open_control(CTL, U.seal_control(s2, CTL, b"CURTAIL 40%")); status = U.on_command_ack(ack)
report("S1 utility restart", c is None and status == b"DUP" and not U.pending_cmds.get(der.id),
       f"3 commands applied before restart; after restart the new command got seq={U.cmd_seq[der.id]}, "
       f"device last_cmd_seq={der.flash['last_cmd_seq']} -> device answered {status.decode()}, applied={c}, "
       f"utility still holds it for redelivery: {bool(U.pending_cmds.get(der.id))}")

# ---------------------------------------------------------------- S2
d2 = W.device(b"der-0002", "der_controller"); s = full(U, d2); T2 = "grid/der_controller/der-0002/control"
env = U.seal_control(s, T2, b"OPEN_BREAKER")
cmd, ack = d2.open_control(T2, env)          # counter committed to flash here; actuation not yet done
d2.reboot()                                  # power fails before the actuator acts (the ACK never left the device)
s3 = resume(U, d2); out = U.redeliver_commands(s3)
cmd2, ack2 = d2.open_control(T2, out[0][1]); st2 = U.on_command_ack(ack2)
report("S2a crash after counter write, before actuation, ACK not sent", cmd2 is None and st2 == b"DUP",
       f"redelivered command answered {st2.decode()} -> never applied, and the utility dropped it")
d3 = W.device(b"der-0003", "der_controller"); s = full(U, d3); T3 = "grid/der_controller/der-0003/control"
cmd, ack = d3.open_control(T3, U.seal_control(s, T3, b"OPEN_BREAKER")); st3 = U.on_command_ack(ack)   # ACK sent first
d3.reboot()                                  # ...then power fails before actuation
report("S2b crash after the OK ACK was sent, before actuation", st3 == b"OK" and not U.pending_cmds.get(d3.id),
       "utility recorded OK and holds nothing to redeliver -> command lost with a false confirmation")

# ---------------------------------------------------------------- S3
tmp = tempfile.mkdtemp(); sp, up = f"{tmp}/stek.json", f"{tmp}/used.json"
st = STEK(sp); pa = PASR(W.U, st, up); pa.used = {os.urandom(16): 2_000_000_000 for _ in range(1000)}; pa._persist_used()
size = os.path.getsize(up); open(up, "r+").truncate(size // 2)          # power loss half-way through json.dump
try: PASR(W.U, STEK(sp), up); ok = False; why = "restarted"
except Exception as e: ok, why = True, f"{type(e).__name__}: {str(e)[:60]}"
report("S3 torn write of used.json", ok, f"utility restart fails ({why}); open(path,'w') truncates before writing, no fsync/rename")
head = open(sp).read()[:10]; open(sp, "w").write(head)                 # torn STEK file
try: STEK(sp); ok = False; why = "loaded"
except Exception as e: ok, why = True, f"{type(e).__name__}"
report("S3 torn write of stek.json", ok, f"STEK load fails ({why}) -> either no restart, or (if caught) every ticket in the fleet dies")

# ---------------------------------------------------------------- S4
print("  S4 used-ticket persistence cost: the whole file is rewritten on every consumed ticket")
for n in (1_000, 10_000, 100_000):
    pa.used = {os.urandom(16): 2_000_000_000 for _ in range(n)}
    t = time.perf_counter(); pa._persist_used(); dt = (time.perf_counter() - t) * 1e3; sz = os.path.getsize(up)
    print(f"     {n:>7} outstanding tickets: file {sz/1e6:6.2f} MB, one rewrite {dt:7.1f} ms -> if each of {n} devices resumes once a day: "
          f"{n*sz/1e9:8.1f} GB written/day, {n*dt/1e3/3600:6.2f} h of rewrite time/day (this container)")

# ---------------------------------------------------------------- S5
m = W.device(b"meter-0005", "smart_meter"); full(U, m)
r1 = resume_hello(m); rs = U.pasr.on_resume_hello(m.id, r1)          # RS lost on the radio link
same = U.pasr.on_resume_hello(m.id, r1) == rs                         # identical retransmission: fine
r1b = resume_hello(m)                                                  # app-level retry rebuilds the hello (new nonce)
try: U.pasr.on_resume_hello(m.id, r1b); res = "accepted"
except HandshakeError as e: res = str(e)
report("S5 rebuilt resume hello after the first was processed", res == "ticket already used",
       f"identical retransmission answered identically: {same}; rebuilt hello -> '{res}' -> device must do a full handshake")
