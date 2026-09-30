"""Network-level attacks against the real broker, using an interception proxy (an attacker on the link).
Brokers (started by the runner): 8889 default groups, 8885 hybrid-only groups, 8886 persistence on,
8887 persistence off, 8888 max_packet_size 300000."""
import os, socket, ssl, subprocess, threading, time
import paho.mqtt.client as mqtt

P = "/work/pki"
T = "grid/smart_meter/meter-0001/telemetry"

def make(cid, name, port, ctx=None, nodelay=True):
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=cid, protocol=mqtt.MQTTv5)
    if ctx is None:
        ctx = ssl.create_default_context(cafile=f"{P}/ca.crt"); ctx.load_cert_chain(f"{P}/{name}.crt", f"{P}/{name}.key")
    c.tls_set_context(ctx); c.got, c.ev, c.disc = [], threading.Event(), []
    c.on_connect = lambda cl, u, f, rc, p: cl.ev.set()
    c.on_message = lambda cl, u, m: cl.got.append((m.topic, len(m.payload), m.retain))
    c.on_disconnect = lambda cl, u, f, rc, p: cl.disc.append(str(rc))
    c.port = port
    return c
def up(c, host="localhost"):
    c.connect(host, c.port, keepalive=30); c.loop_start(); c.ev.wait(5); return c

class Proxy(threading.Thread):
    """Man-in-the-middle TCP relay. Records client->server bytes; optionally flips one bit after `tamper_after` s."""
    def __init__(self, listen, target, tamper_after=None):
        super().__init__(daemon=True); self.listen, self.target, self.tamper_after = listen, target, tamper_after
        self.c2s, self.tampered, self.ready = [], False, threading.Event()
    def run(self):
        srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.listen)); srv.listen(1); self.ready.set()
        cli, _ = srv.accept(); upstream = socket.create_connection(self.target); t0 = time.time()
        for s_ in (cli, upstream): s_.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        def pump(src, dst, c2s):
            try:
                while True:
                    data = src.recv(65536)
                    if not data: break
                    if c2s:
                        self.c2s.append(data)
                        if self.tamper_after is not None and not self.tampered and time.time() - t0 > self.tamper_after:
                            b = bytearray(data); b[len(b) // 2] ^= 0x01; data = bytes(b); self.tampered = True
                    dst.sendall(data)
            except OSError: pass
            for s_ in (src, dst):
                try: s_.shutdown(socket.SHUT_RDWR)
                except OSError: pass
        a = threading.Thread(target=pump, args=(cli, upstream, True), daemon=True)
        b = threading.Thread(target=pump, args=(upstream, cli, False), daemon=True)
        a.start(); b.start(); a.join(); b.join()

def log_tail(port, n=400):
    try: return open(f"/tmp/mosq_{port}.log").read()[-n:]
    except OSError: return ""

res = {}
# ---------------------------------------------------------------- N1 replay of captured bytes
util = up(make("utility", "utility", 8889)); util.subscribe(T, qos=1); time.sleep(0.3)
px = Proxy(9001, ("127.0.0.1", 8889)); px.start(); px.ready.wait()
m = make("meter-0001", "meter1", 9001); up(m, "localhost")
m.publish(T, b"kWh=1.25", qos=1); time.sleep(0.5); m.disconnect(); m.loop_stop(); time.sleep(0.5)
genuine = sum(1 for t, *_ in util.got if t == T)
captured = b"".join(px.c2s)
s = socket.create_connection(("127.0.0.1", 8889))
for chunk in px.c2s:
    try: s.sendall(chunk); time.sleep(0.05)
    except OSError: break
s.settimeout(2); got = b""
try:
    while True:
        d = s.recv(65536)
        if not d: break
        got += d
except OSError: pass
s.close(); time.sleep(0.5)
after = sum(1 for t, *_ in util.got if t == T)
res["N1 genuine session through the proxy delivered"] = genuine
res["N1 attacker replays all %d captured client bytes on a new connection -> extra messages delivered" % len(captured)] = after - genuine
res["N1 broker log for the replay"] = [l.split(": ", 1)[-1] for l in log_tail(8889, 3000).splitlines() if "OpenSSL" in l or "error" in l.lower()][-2:]

# ---------------------------------------------------------------- N2 bit flip in a live encrypted packet
before = sum(1 for t, *_ in util.got if t == T)
px2 = Proxy(9002, ("127.0.0.1", 8889), tamper_after=0.6); px2.start(); px2.ready.wait()
m2 = make("meter-0001", "meter1", 9002); up(m2, "localhost"); time.sleep(0.8)
m2.publish(T, b"kWh=9.99", qos=1); time.sleep(1.0)
res["N2 one bit flipped in the encrypted PUBLISH -> tampered?"] = px2.tampered
res["N2 -> tampered message delivered"] = sum(1 for t, *_ in util.got if t == T) - before
res["N2 -> connection dropped by broker"] = bool(m2.disc) or not m2.is_connected()
res["N2 broker log"] = [l.split(": ", 1)[-1] for l in log_tail(8889, 3000).splitlines() if "OpenSSL" in l][-1:]
m2.loop_stop(); util.disconnect(); util.loop_stop()

# ---------------------------------------------------------------- N3 classical-only client vs default / hybrid-only broker
def s_client(port, groups=None):
    cmd = ["openssl", "s_client", "-connect", f"localhost:{port}", "-CAfile", f"{P}/ca.crt", "-cert", f"{P}/meter1.crt",
           "-key", f"{P}/meter1.key", "-brief"] + (["-groups", groups] if groups else [])
    env = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}
    out = subprocess.run(cmd, input=b"Q\n", capture_output=True, env=env, timeout=10)
    txt = (out.stdout + out.stderr).decode(errors="replace")
    g = [l.strip() for l in txt.splitlines() if "Negotiated TLS1.3 group" in l or "Peer Temp Key" in l]
    if g: return " | ".join(g)
    return "HANDSHAKE FAILURE (" + next((l.strip() for l in txt.splitlines() if "alert" in l), "no shared group") + ")"
res["N3 default broker, client offers ONLY classical X25519"] = s_client(8889, "X25519")
res["N3 hybrid-only broker, client offers ONLY classical X25519"] = s_client(8885, "X25519")
res["N3 hybrid-only broker, client with default groups"] = s_client(8885)

# ---------------------------------------------------------------- N4 clone: second connection with the same identity
first = up(make("meter-0001", "meter1", 8889)); time.sleep(0.3)
clone = up(make("meter-0001", "meter1", 8889)); time.sleep(0.8)
res["N4 genuine device after clone connects: disconnected with"] = first.disc
res["N4 broker log"] = [l.split(": ", 1)[-1] for l in log_tail(8889, 4000).splitlines() if "already connected" in l or "taken over" in l.lower()][-1:]
for c in (first, clone):
    try: c.disconnect(); c.loop_stop()
    except Exception: pass

# ---------------------------------------------------------------- N5 broker restart: retained firmware manifest
def retained_after_restart(port, conf):
    u = up(make("utility", "utility", port)); u.publish("pqgrid/fota/smart_meter/manifest", b"M" * 16624, qos=1, retain=True)
    time.sleep(0.5); u.disconnect(); u.loop_stop()
    subprocess.run(["pkill", "-f", conf]); time.sleep(1.0)
    subprocess.Popen(["mosquitto", "-c", f"/work/{conf}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); time.sleep(1.0)
    d = up(make("meter-0001", "meter1", port)); d.subscribe("pqgrid/fota/smart_meter/#", qos=1); time.sleep(1.0)
    got = [(t, l) for t, l, r in d.got]; d.disconnect(); d.loop_stop(); return got
res["N5 retained manifest after broker restart, persistence ON"] = retained_after_restart(8886, "mosquitto_persist.conf")
res["N5 retained manifest after broker restart, persistence OFF"] = retained_after_restart(8887, "mosquitto_nopersist.conf")

# ---------------------------------------------------------------- N6 max_packet_size
u = up(make("utility", "utility", 8888)); r = up(make("meter-0001", "meter1", 8888)); r.subscribe("pqgrid/fota/smart_meter/#", qos=1); time.sleep(0.3)
u.publish("pqgrid/fota/smart_meter/1/chunk/0", b"A" * 262144, qos=1); time.sleep(0.8)
u.publish("pqgrid/fota/smart_meter/1/chunk/1", b"B" * 400000, qos=1); time.sleep(0.8)
res["N6 with max_packet_size 300000: delivered sizes"] = [l for t, l, _ in r.got]
res["N6 sender of the 400 KB packet was disconnected"] = u.disc
for c in (u, r):
    try: c.disconnect(); c.loop_stop()
    except Exception: pass

# ---------------------------------------------------------------- N7 TLS resumption after an IP address change
ip = subprocess.run(["hostname", "-i"], capture_output=True, text=True).stdout.split()[0]
ctx = ssl.create_default_context(cafile=f"{P}/ca.crt"); ctx.load_cert_chain(f"{P}/meter1.crt", f"{P}/meter1.key")
def raw(host, session=None):
    raw_s = socket.create_connection((host, 8889)); raw_s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s_ = ctx.wrap_socket(raw_s, server_hostname="localhost", session=session)
    s_.sendall(b"\x10\x16\x00\x04MQTT\x04\x02\x00\x1e\x00\x0ameter-0001"); s_.recv(4)
    out = (s_.session, s_.session_reused, s_.getsockname()[0]); s_.close(); return out
sess, _, src1 = raw("127.0.0.1")
_, reused, src2 = raw(ip, sess)
res[f"N7 session from {src1} resumed from a different source IP {src2}"] = reused

for k, v in res.items(): print(f"{k}: {v}")
