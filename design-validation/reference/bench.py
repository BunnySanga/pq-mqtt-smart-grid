import os, time, statistics as st, tempfile, random
from pqgrid_ref.suite import HybridKeyPair, mldsa_keygen
from pqgrid_ref import policy as pol
from pqgrid_ref.e2e import Device, Utility
from pqgrid_ref.pasr import PASR, STEK, resume_hello, on_resume_server
from pqgrid_ref.fota import Station, Installer, FIRMWARE, mth, path
from pqgrid_ref.broadcast import seal_broadcast

N, WARM = 200, 20
def med(xs): return st.median(xs[WARM:]) * 1e3   # ms
u_static, cmd_sk = HybridKeyPair(), mldsa_keygen()
RULES = [{"pattern": "grid/+/+/alert", "tier": "ALERT"}, {"pattern": "grid/+/+/control", "tier": "CONTROL"}]
CL = {"smart_meter": {"resume": "PSK", "ticket_lifetime_s": 86400, "max_chain_age_s": 604800, "unicast_control": False},
      "der_controller": {"resume": "PSK_KEM", "ticket_lifetime_s": 43200, "max_chain_age_s": 604800, "unicast_control": True}}
p = pol.load(pol.build("nitk-grid", 1, RULES, CL, u_static.pk, cmd_sk.public_key().public_bytes_raw()))
meter, der = Device(b"meter-0001", "smart_meter", p, 1), Device(b"der-0001", "der_controller", p, 1)
reg = {meter.id: {"pk": meter.static.pk, "class": "smart_meter", "active": True}, der.id: {"pk": der.static.pk, "class": "der_controller", "active": True}}
U = Utility(p, u_static, cmd_sk, reg); U.pasr = PASR(U, STEK())
T = time.perf_counter

def full(dev):
    a=T(); m1=dev.hello(); b=T(); m2=U.on_client_hello(dev.id, m1); c=T(); m3=dev.on_server_hello(m2); d=T(); s,m4=U.on_finished(dev.id, m3); e=T(); dev.on_final(m4); f=T()
    return (b-a)+(d-c)+(f-e), (c-b)+(e-d), [len(m1), len(m2), len(m3), len(m4)]
def res(dev):
    a=T(); r1=resume_hello(dev); b=T(); r2=U.pasr.on_resume_hello(dev.id, r1); c=T(); r3=on_resume_server(dev, r2); d=T(); s,r4=U.pasr.on_resume_finished(dev.id, r3); e=T(); dev.on_final(r4); f=T()
    return (b-a)+(d-c)+(f-e), (c-b)+(e-d), [len(r1), len(r2), len(r3), len(r4)]

rows = []
for label, fn, dev in [("Full handshake (hybrid KEM-MQTT, 3 KEMs)", full, meter), ("PASR resume, PSK mode", res, meter),
                       ("Full handshake (DER)", full, der), ("PASR resume, PSK_KEM mode", res, der)]:
    D, Uu = [], []
    for _ in range(N):
        dd, uu, sz = fn(dev); D.append(dd); Uu.append(uu)
    rows.append((label, med(D), med(Uu), sz))
import platform, sys, cryptography
print(f"ENVIRONMENT: {platform.system()} {platform.machine()} | Python {sys.version.split()[0]} | cryptography {cryptography.__version__} | median of {N-WARM} runs after {WARM} warm-up")
print("E2E SESSION ESTABLISHMENT")
print(f"{'':44s} {'device ms':>10s} {'utility ms':>11s}  bytes: msg1/msg2/msg3/ticket = total")
for l, d, u, sz in rows: print(f"{l:44s} {d:10.3f} {u:11.3f}  {'/'.join(map(str,sz))} = {sum(sz)}")

# per-message overhead
payload = b"x" * 64
s_der = [s for s in U.sessions.values() if s.device_id == der.id][-1]
ae = meter.seal_alert("grid/smart_meter/meter-0001/alert", payload)
ce = U.seal_control(s_der, "grid/der_controller/der-0001/control", payload)
be = seal_broadcast(cmd_sk, b"zone-7", 1, os.urandom(32), 1, payload)
ta = [];  
for _ in range(N): a=T(); meter.seal_alert("grid/smart_meter/meter-0001/alert", payload); ta.append(T()-a)
tc = []
for _ in range(N): a=T(); env=U.seal_control(s_der, "grid/der_controller/der-0001/control", payload); b=T(); der.open_control("grid/der_controller/der-0001/control", env); tc.append(T()-b)
print("\nPER-MESSAGE (64-byte payload)")
print(f"  TELEMETRY  wire = 64 B app payload (TLS only)")
print(f"  ALERT      wire = {len(ae)} B  (+{len(ae)-64} B)   device seal {med(ta):.3f} ms")
print(f"  CONTROL    wire = {len(ce)} B (+{len(ce)-64} B)  device open+verify {med(tc):.3f} ms")
print(f"  BROADCAST  wire = {len(be)} B (+{len(be)-64} B)")

# FOTA
tmp = tempfile.mkdtemp(); stn = Station(tmp); image = os.urandom(1024*1024)
a=T(); m, chunks = stn.build(FIRMWARE, "smart_meter", 2, image); build=T()-a
inst = Installer(stn.pk, "smart_meter", {})
tv = []
for _ in range(30): a=T(); inst.accept_manifest(m); tv.append(T()-a)
a=T(); stt = inst.accept_manifest(m); order=list(chunks); random.shuffle(order)
for c in order: inst.accept_chunk(stt, c)
inst.finish(stt); inst.commit(FIRMWARE); tot=T()-a
print("\nPQC-FOTA  (1 MiB image, 4 KiB chunks, SLH-DSA-SHA2-192s)")
print(f"  signed manifest {len(m)} B | trust anchor {len(stn.pk)} B | chunks {len(chunks)} | Merkle proof per chunk {len(path(0,[b'']*256))*32} B")
print(f"  flat hash list would be {len(chunks)*32} B in the manifest; Merkle keeps 32 B root")
print(f"  station build+sign {build*1e3:.0f} ms (offline) | device manifest verify median {st.median(tv[5:])*1e3:.3f} ms | full install (256 chunks, shuffled) {tot*1e3:.0f} ms")
