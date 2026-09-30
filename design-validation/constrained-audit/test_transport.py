"""Transport-level audit experiments against a real Mosquitto 2.0 + OpenSSL 3.5 broker in Docker.
  T1  MQTT 5 Maximum Packet Size vs the 16,405-byte signed FOTA manifest          [REAL DOCKER MEASUREMENT]
  T5  bytes on the wire per connection phase and per message (TCP payload bytes)  [REAL DOCKER MEASUREMENT]
  T6  time-to-ready over modelled constrained links                                [RESOURCE-CONSTRAINED SIMULATION]
The E2E handshake in T6 is SIZE-EQUIVALENT: payloads have the exact byte sizes measured in results/bench.txt
but carry random bytes, because the question is link time, not crypto (host crypto is < 0.3 ms)."""
import os, ssl, socket, threading, time, statistics as st, sys
import paho.mqtt.client as mqtt
from paho.mqtt.properties import Properties
from paho.mqtt.packettypes import PacketTypes
from linkproxy import LinkProxy

P, BROKER = "/audit/pki", ("127.0.0.1", 8890)
MANIFEST, CHUNK = 16405, 4096 + 256          # signed SLH-DSA-192s manifest; 4 KiB chunk + 8-level Merkle proof

class PQClient(mqtt.Client):
    """paho 2.1.0: TCP_NODELAY + TLS 1.3 session reuse (private-method override, as in broker/test_paho_resume.py)."""
    tls_session = None
    def _ssl_wrap_socket(self, tcp_sock):
        tcp_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return self._ssl_context.wrap_socket(tcp_sock, server_hostname=self._host, session=self.tls_session)

_CTX = {}
def ctx(name):
    if name not in _CTX:
        c = ssl.create_default_context(cafile=f"{P}/ca.crt"); c.load_cert_chain(f"{P}/{name}.crt", f"{P}/{name}.key")
        _CTX[name] = c
    return _CTX[name]

def client(cid, name="meter1", max_packet=None, clean=True, expiry=None, session=None):
    c = PQClient(mqtt.CallbackAPIVersion.VERSION2, client_id=cid, protocol=mqtt.MQTTv5)
    c.tls_set_context(ctx(name)); c.tls_session = session; c.connect_timeout = 300
    props = Properties(PacketTypes.CONNECT)
    if max_packet: props.MaximumPacketSize = max_packet
    if expiry: props.SessionExpiryInterval = expiry
    c._props, c._clean = props, clean
    c.got, c.conn_ev, c.sub_ev, c.disc, c.tags = [], threading.Event(), threading.Event(), [], {}
    c.on_connect = lambda cl, u, f, rc, p: cl.conn_ev.set()
    c.on_subscribe = lambda cl, u, mid, rc, p: cl.sub_ev.set()
    def on_msg(cl, u, m):
        cl.got.append((m.topic, len(m.payload)))
        cl.tags.setdefault(bytes(m.payload[:2]), threading.Event()).set()
    c.on_message = on_msg
    c.on_disconnect = lambda cl, u, f, rc, p: cl.disc.append(str(rc))
    return c
def connect(c, port, timeout=300):
    c.connect("127.0.0.1", port, keepalive=600, clean_start=c._clean, properties=c._props)
    c.loop_start(); return c.conn_ev.wait(timeout)
def close(*cs):
    for c in cs:
        try: c.disconnect(); c.loop_stop()
        except Exception: pass
def wait_tag(c, tag, timeout=300):
    return c.tags.setdefault(tag, threading.Event()).wait(timeout)

def log_lines(pat, n=4000):
    try: return [l.split(": ", 1)[-1] for l in open("/tmp/mosq_audit.log").read()[-n:].splitlines() if pat in l]
    except OSError: return []

# =============================================================== T1
print("== T1 MQTT 5 Maximum Packet Size vs the signed manifest [REAL DOCKER MEASUREMENT] ==")
u = client("utility", "utility"); connect(u, BROKER[1])
u.publish("pqgrid/fota/smart_meter/manifest", os.urandom(MANIFEST), qos=1, retain=True).wait_for_publish(5)
u.publish("pqgrid/fota/smart_meter/5/chunk/0", os.urandom(CHUNK), qos=1, retain=True).wait_for_publish(5)
for mps in (8192, 16384, 16445, 16500, 32768, None):
    d = client(f"t1-{mps}", "meter1", max_packet=mps); connect(d, BROKER[1])
    d.subscribe("pqgrid/fota/smart_meter/#", qos=1); d.sub_ev.wait(5); time.sleep(1.5)
    got = sorted(l for _, l in d.got)
    man = MANIFEST in got
    print(f"  device Maximum Packet Size {str(mps):>6}: received payload sizes {got} -> manifest "
          f"{'RECEIVED' if man else 'NEVER DELIVERED (no error to the device)'}; still connected: {d.is_connected()}")
    close(d)
print("  broker log lines mentioning size/drop:", log_lines("size")[-2:] + log_lines("drop")[-2:])
close(u)

# =============================================================== T5
print("\n== T5 bytes on the wire, TCP payload (TLS 1.3 hybrid-pinned, ECDSA P-256 mutual) [REAL DOCKER MEASUREMENT] ==")
print("   (IP/TCP headers are extra: >= 40 B per segment plus ACK segments; not counted here)")
px = LinkProxy(9101, BROKER); px.start(); px.ready.wait()
def snap(): return px.totals()
def delta(a, b): return b[0] - a[0], b[1] - a[1]
b0 = snap(); d = client("meter-0001", "meter1", clean=False, expiry=86400); connect(d, 9101); time.sleep(0.3)
b1 = snap(); up_, down = px.last()
print(f"  full TLS handshake + MQTT CONNECT/CONNACK: up {b1[0]-b0[0]} B, down {b1[1]-b0[1]} B, total {sum(delta(b0,b1))} B")
print(f"    TLS records up  (type,len): {up_.records[:8]}")
print(f"    TLS records down(type,len): {down.records[:12]}")
sess = d.socket().session
print(f"  TLS session ticket: lifetime hint {getattr(sess,'ticket_lifetime_hint',None)} s, timeout {getattr(sess,'timeout',None)} s")
d.subscribe("pqgrid/hs/meter-0001/down", qos=1); d.sub_ev.wait(5); time.sleep(0.2); b2 = snap()
print(f"  SUBSCRIBE/SUBACK: {sum(delta(b1,b2))} B")
T = "grid/smart_meter/meter-0001/telemetry"
for label, size, qos in [("TELEMETRY 64 B QoS 0", 64, 0), ("TELEMETRY 64 B QoS 1", 64, 1),
                         ("ALERT envelope 137 B QoS 1", 137, 1), ("CONTROL envelope 3,442 B QoS 1", 3442, 1)]:
    a = snap(); info = d.publish(T, os.urandom(size), qos=qos)
    if qos: info.wait_for_publish(5)
    time.sleep(0.3); b = snap(); du, dd = delta(a, b)
    print(f"  publish {label:<32}: up {du} B, down {dd} B -> overhead {du + dd - size} B over the payload")
try:
    pa = Properties(PacketTypes.PUBLISH); pa.TopicAlias = 1
    d.publish(T, os.urandom(64), qos=0, properties=pa); time.sleep(0.3)
    a = snap(); d.publish("", os.urandom(64), qos=0, properties=pa); time.sleep(0.3); b = snap()
    print(f"  publish TELEMETRY 64 B QoS 0 with MQTT 5 topic alias: up {delta(a,b)[0]} B (topic is {len(T)} B)")
except Exception as e:
    print(f"  topic alias via paho: not possible ({type(e).__name__}: {e}); saving = topic bytes - 3-byte alias property")
close(d); time.sleep(0.3)
b3 = snap(); d = client("meter-0001", "meter1", clean=False, expiry=86400, session=sess); connect(d, 9101); time.sleep(0.3)
b4 = snap(); print(f"  TLS 1.3 RESUMED handshake + CONNECT/CONNACK (session kept, no SUBSCRIBE needed): "
                  f"{sum(delta(b3,b4))} B, resumed={d.socket().session_reused}")
close(d)

# =============================================================== T6
print("\n== T6 time until the device can send its first end-to-end protected message [RESOURCE-CONSTRAINED SIMULATION] ==")
print("   link model: one-way delay + serialisation rate per direction + TCP handshake RTT; proxy terminates TCP;")
print("   no radio scheduling, repetitions, loss or TCP congestion control. Utility is on the broker's LAN.")
SIZES = {b"CH": 2493, b"SH": 2411, b"DF": 42, b"NT": 266, b"RH": 337, b"RS": 110, b"RK": 1560, b"RQ": 1230,
         b"DA": 42, b"AL": 137, b"AK": 58}
REPLY = {b"CH": b"SH", b"DF": b"NT", b"RH": b"RS", b"RK": b"RQ", b"DA": b"NT", b"AL": b"AK"}
def pay(tag): return tag + os.urandom(SIZES[tag] - 2)
util = client("utility", "utility"); connect(util, BROKER[1])
def respond(cl, ud, m):
    tag = bytes(m.payload[:2])
    if m.topic.endswith("/up") and tag in REPLY:
        dev = m.topic.split("/")[2]; cl.publish(f"pqgrid/hs/{dev}/down", pay(REPLY[tag]), qos=1)
util.on_message = respond; util.subscribe("pqgrid/hs/+/up", qos=1); util.sub_ev.wait(5)
UP, DOWN = "pqgrid/hs/meter-0001/up", "pqgrid/hs/meter-0001/down"

def scenario(port, name, tls_resume, persistent, e2e):
    """e2e: 'full' | 'psk' | 'pskkem' | 'psk-1rtt' (proposal: DF + first alert sent right after RS) | 'none'"""
    # setup (untimed): obtain a TLS session and a persistent MQTT session with the subscription in place
    s0 = client("meter-0001", "meter1", clean=True, expiry=86400); connect(s0, BROKER[1])   # fresh session, kept after disconnect
    s0.subscribe(DOWN, qos=1); s0.sub_ev.wait(5); time.sleep(0.2); sess = s0.socket().session; close(s0); time.sleep(0.3)
    c = client("meter-0001", "meter1", clean=not persistent, expiry=86400 if persistent else None,
               session=sess if tls_resume else None)
    b0 = px_t.totals(); t0 = time.monotonic()
    connect(c, port)
    if not persistent: c.subscribe(DOWN, qos=1); c.sub_ev.wait(300)
    if e2e == "full":
        c.publish(UP, pay(b"CH"), qos=1); wait_tag(c, b"SH"); c.publish(UP, pay(b"DF"), qos=1); wait_tag(c, b"NT")
    elif e2e in ("psk", "pskkem"):
        c.publish(UP, pay(b"RH" if e2e == "psk" else b"RK"), qos=1); wait_tag(c, b"RS" if e2e == "psk" else b"RQ")
        c.publish(UP, pay(b"DF"), qos=1); wait_tag(c, b"NT")
    elif e2e == "psk-1rtt":
        c.publish(UP, pay(b"RH"), qos=1); wait_tag(c, b"RS")
        c.publish(UP, pay(b"DA"), qos=1); c.publish(UP, pay(b"AL"), qos=1)   # finished + first alert, same flight
    elif e2e == "none":
        c.publish("grid/smart_meter/meter-0001/telemetry", os.urandom(64), qos=1).wait_for_publish(300)
    t_ready = time.monotonic() - t0
    if e2e == "psk-1rtt": wait_tag(c, b"AK")
    time.sleep(0.2); b1 = px_t.totals(); close(c); time.sleep(0.3)
    return t_ready, (b1[0] - b0[0]) + (b1[1] - b0[1])

SCEN = [("A  cold start: full TLS + SUBSCRIBE + full E2E handshake",        False, False, "full"),
        ("B  reboot (per §4.6): full TLS + SUBSCRIBE + PASR PSK resume",    False, False, "psk"),
        ("C  wake: TLS resumed + SUBSCRIBE + PASR PSK resume",              True,  False, "psk"),
        ("C' wake: TLS resumed + SUBSCRIBE + PASR PSK+KEM resume",          True,  False, "pskkem"),
        ("D  proposal: TLS resumed + persistent MQTT session + 1-RTT PSK",  True,  True,  "psk-1rtt"),
        ("E  telemetry-only wake: TLS resumed + persistent session + 1 publish", True, True, "none")]
PROFILES = [("LTE-M-like    RTT 0.2 s, 200 kbit/s", 0.1, 200_000, 3),
            ("NB-IoT-good   RTT 1.0 s,  20 kbit/s", 0.5, 20_000, 3),
            ("NB-IoT-poor   RTT 4.0 s,   2 kbit/s", 2.0, 2_000, 1)]
port = 9200
for pname, owd, bps, n in PROFILES:
    port += 1; px_t = LinkProxy(port, BROKER, delay=owd, up_bps=bps, down_bps=bps); px_t.start(); px_t.ready.wait()
    print(f"  -- {pname} (assumed parameters; n={n} per scenario) --")
    for sname, tr, persist, e2e in SCEN:
        runs = [scenario(port, sname, tr, persist, e2e) for _ in range(n)]
        print(f"     {sname:<68} ready {st.median(r[0] for r in runs):7.2f} s   bytes {st.median(r[1] for r in runs):6.0f}")
    sys.stdout.flush()
close(util)
