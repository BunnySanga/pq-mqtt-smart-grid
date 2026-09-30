"""TLS-layer audit experiments (real Mosquitto 2.0 + OpenSSL 3.5 in Docker)          [REAL DOCKER MEASUREMENT]
  T2  TLS 1.3 session-ticket lifetime: advertised hint, and resumption just before / after it
      (the broker runs under libfaketime so its clock can be moved forward without waiting two hours)
  T3  RFC 6066 max_fragment_length: does the broker honour a small-record request? (device receive buffer)
  T4  device clock reset / clock ahead / expired device certificate: does the TLS hop still connect?
      The E2E layer repairs the device clock from authenticated utility time (BalaMP.md §5.2), but that repair
      runs only AFTER the TLS hop is up. This checks whether TLS lets the device get that far."""
import os, ssl, socket, subprocess, time, sys
from linkproxy import LinkProxy

P = "/audit/pki"
FT_LIB = os.environ.get("FT_LIB", "")

_CTX = {}
def tls_connect(port, cert="meter1", session=None):
    if cert not in _CTX:                       # ONE context per device, or Python refuses session reuse
        c = ssl.create_default_context(cafile=f"{P}/ca.crt"); c.load_cert_chain(f"{P}/{cert}.crt", f"{P}/{cert}.key"); _CTX[cert] = c
    ctx = _CTX[cert]
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    s = ctx.wrap_socket(raw, server_hostname="127.0.0.1", session=session)
    s.sendall(b"\x10\x14\x00\x04MQTT\x04\x02\x00\x3c\x00\x08tls-time"); s.recv(4)   # MQTT CONNECT, read CONNACK
    out = (s.session, s.session_reused); s.close(); return out

# =============================================================== T2
print("== T2 TLS 1.3 session-ticket lifetime (broker clock moved with libfaketime) ==")
open("/tmp/ft", "w").write("+0\n")
env = dict(os.environ, LD_PRELOAD=FT_LIB, FAKETIME_TIMESTAMP_FILE="/tmp/ft", FAKETIME_NO_CACHE="1")
env.pop("OPENSSL_CONF", None); env["OPENSSL_CONF"] = "/work/hybrid-only.cnf"
subprocess.Popen(["mosquitto", "-c", "/audit/mosquitto_faketime.conf"], env=env,
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); time.sleep(1.5)
sess, _ = tls_connect(8891)
print(f"  ticket received: lifetime hint {sess.ticket_lifetime_hint} s; client-side session timeout {sess.timeout} s")
for off in (3600, 7000, 7300, 90000):
    open("/tmp/ft", "w").write(f"+{off}\n"); time.sleep(0.2)
    faked = subprocess.run(["date", "+%s"], env=dict(env, LD_PRELOAD=FT_LIB), capture_output=True, text=True).stdout.strip()
    try:
        _, reused = tls_connect(8891, session=sess)
        print(f"  broker clock +{off:>5} s (faked now={faked}): resumption {'ACCEPTED' if reused else 'REFUSED -> full hybrid handshake'}")
    except Exception as e:
        print(f"  broker clock +{off:>5} s: connection failed: {type(e).__name__}: {e}")
open("/tmp/ft", "w").write("+0\n")

# =============================================================== T3
print("\n== T3 max_fragment_length (RFC 6066): can a small device ask for small TLS records? ==")
def mqtt_connect_subscribe(cid=b"mfl-test", topic=b"pqgrid/fota/smart_meter/manifest"):
    var = b"\x00\x04MQTT\x04\x02\x00\x3c" + len(cid).to_bytes(2, "big") + cid
    conn = b"\x10" + bytes([len(var)]) + var
    sv = b"\x00\x01" + len(topic).to_bytes(2, "big") + topic + b"\x01"
    return conn + b"\x82" + bytes([len(sv)]) + sv
man = "/tmp/manifest.bin"; open(man, "wb").write(os.urandom(16405))    # the signed-manifest size, retained
subprocess.run(["mosquitto_pub", "-h", "127.0.0.1", "-p", "8890", "--cafile", f"{P}/ca.crt", "--cert", f"{P}/utility.crt",
                "--key", f"{P}/utility.key", "-t", "pqgrid/fota/smart_meter/manifest", "-r", "-q", "1", "-f", man, "-V", "mqttv5"],
               env={k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}, check=False, timeout=20)
for mfl in (None, 512, 1024):
    port = 9120 + (mfl or 0) // 512
    px = LinkProxy(port, ("127.0.0.1", 8890)); px.start(); px.ready.wait()
    cmd = ["openssl", "s_client", "-connect", f"127.0.0.1:{port}", "-CAfile", f"{P}/ca.crt", "-cert", f"{P}/meter1.crt",
           "-key", f"{P}/meter1.key", "-nocommands", "-ign_eof"] + (["-maxfraglen", str(mfl)] if mfl else [])
    envc = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=envc)
    time.sleep(1.0); p.stdin.write(mqtt_connect_subscribe()); p.stdin.flush(); time.sleep(2.5)
    try: out = p.communicate(timeout=3)[0].decode(errors="replace")
    except subprocess.TimeoutExpired: p.kill(); out = p.communicate()[0].decode(errors="replace")
    conn = px.last(); recs = conn[1].records if conn else []
    app = [ln for t, ln in recs if t == 23]
    mline = [l.strip() for l in out.splitlines() if "Max Fragment" in l or "fragment" in l.lower()]
    print(f"  client asks max_fragment_length={mfl}: broker->device records {len(recs)}, largest {max(app) if app else None} B "
          f"(ciphertext incl. 17 B overhead); s_client says {mline[:1] or ['(no MFL line)']}")

# =============================================================== T4
print("\n== T4 device clock and certificate validity vs the TLS hop (ECDSA P-256 PKI) ==")
print("   certificates:", open("/tmp/pki.txt").read().strip().replace("\n", " | "))
def device_attempt(label, cert="meter1", faketime=None, extra=()):
    code = ("import ssl,socket\n"
            "ctx=ssl.create_default_context(cafile='/audit/pki/ca.crt'); ctx.load_cert_chain('/audit/pki/%s.crt','/audit/pki/%s.key')\n"
            "s=ctx.wrap_socket(socket.create_connection(('127.0.0.1',8890),timeout=10),server_hostname='127.0.0.1')\n"
            "s.sendall(b'\\x10\\x14\\x00\\x04MQTT\\x04\\x02\\x00\\x3c\\x00\\x08clk-test'); r=s.recv(4)\n"
            "print('CONNECTED, CONNACK', r.hex())\n") % (cert, cert)
    cmd = ((["faketime", "-f", faketime] if faketime.startswith("+") else ["faketime", faketime]) if faketime else []) + ["python", "-c", code]
    envd = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}
    r = subprocess.run(cmd, capture_output=True, text=True, env=envd, timeout=30)
    txt = (r.stdout + r.stderr).strip().splitlines()
    res = next((l for l in txt if "CONNECTED" in l), None) or next((l.split(": ", 1)[-1] for l in reversed(txt) if "Error" in l), txt[-1] if txt else "?")
    print(f"  {label:<74} -> {res[:150]}")
def s_client_attempt(label, faketime, flags):
    cmd = ["faketime", faketime, "openssl", "s_client", "-connect", "127.0.0.1:8890", "-CAfile", f"{P}/ca.crt",
           "-cert", f"{P}/meter1.crt", "-key", f"{P}/meter1.key", "-verify_return_error", "-brief"] + flags
    envd = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}
    r = subprocess.run(cmd, input=b"", capture_output=True, env=envd, timeout=20)
    txt = (r.stdout + r.stderr).decode(errors="replace")
    ok = "CONNECTION ESTABLISHED" in txt
    why = next((l.strip() for l in txt.splitlines() if "verify error" in l or "error" in l.lower()), "")
    print(f"  {label:<74} -> {'HANDSHAKE OK' if ok else 'HANDSHAKE FAILED'} {why[:110]}")
device_attempt("a) normal device, correct clock")
device_attempt("b) device RTC reset to 1970 after power loss (no battery-backed RTC)", faketime="1970-01-02 00:00:00")
s_client_attempt("c) same 1970 clock, strict verification (typical embedded default)", "1970-01-02 00:00:00", [])
s_client_attempt("d) same 1970 clock, time checks disabled (X509_V_FLAG_NO_CHECK_TIME)", "1970-01-02 00:00:00", ["-no_check_time"])
device_attempt("e) device clock 3 years ahead (drifted/garbage RTC)", faketime="+1095d")   # libfaketime relative offset (-f)
device_attempt("f) device certificate expired while the device was offline (correct clock)", cert="devexp")
device_attempt("g) device certificate with notAfter 9999-12-31, correct clock", cert="devlong")
time.sleep(0.5)
try:
    log = open("/tmp/mosq_audit.log").read().splitlines()
    print("   broker log (certificate errors):", [l.split(": ", 1)[-1] for l in log if "certificate" in l.lower() or "verify" in l.lower()][-3:])
except OSError: pass

# =============================================================== T7
print("\n== T7 hop authentication with a per-device external PSK instead of ECDSA certificates ==")
ident, key = open("/audit/pskfile").read().strip().split(":")
envc = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}
def psk_try(port, ver, k=None):
    r = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{port}", "-psk_identity", ident, "-psk", k or key,
                        ver, "-brief"], input=b"", capture_output=True, env=envc, timeout=15)
    t = (r.stdout + r.stderr).decode(errors="replace")
    if "ESTABLISHED" in t:
        return "ESTABLISHED " + " | ".join(l.strip() for l in t.splitlines() if any(x in l for x in ("Protocol version", "Ciphersuite", "Temp Key", "group")))
    return "REFUSED " + next((l.split(":")[-1].strip() for l in t.splitlines() if "alert" in l), "")
print(f"  listener tls_version tlsv1.3 + psk_hint, client TLS 1.3: {psk_try(8892, '-tls1_3')}")
print(f"  listener tls_version tlsv1.2 + psk_hint, client TLS 1.3: {psk_try(8893, '-tls1_3')}")
print(f"  listener tls_version tlsv1.2 + psk_hint, client TLS 1.2: {psk_try(8893, '-tls1_2')}")
print(f"  same, WRONG key:                                         {psk_try(8893, '-tls1_2', '00' * 32)}")
print("  broker log:", sorted(set(l.split(': ', 1)[-1][:90] for l in open('/tmp/mosq_psk.log').read().splitlines() if 'failed' in l))[:2])
