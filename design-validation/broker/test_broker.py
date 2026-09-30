import ssl, time, threading, statistics as st, socket, struct
import paho.mqtt.client as mqtt
from paho.mqtt.properties import Properties
from paho.mqtt.packettypes import PacketTypes

P = "/work/pki"
HOST, PORT = "localhost", 8883

def make(cid, name):
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=cid, protocol=mqtt.MQTTv5)
    c.tls_set(ca_certs=f"{P}/ca.crt", certfile=f"{P}/{name}.crt", keyfile=f"{P}/{name}.key",
              cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS_CLIENT)
    c.got = []; c.acks = {}; c.subacks = []; c.connected = threading.Event(); c.conn_rc = None
    def on_connect(cl, ud, flags, rc, props): cl.conn_rc = rc; cl.connected.set()
    def on_message(cl, ud, m): cl.got.append((m.topic, len(m.payload), m.retain, m.properties))
    def on_publish(cl, ud, mid, rc, props): cl.acks[mid] = rc
    def on_subscribe(cl, ud, mid, rcs, props): cl.subacks.append([str(r) for r in rcs])
    c.on_connect, c.on_message, c.on_publish, c.on_subscribe = on_connect, on_message, on_publish, on_subscribe
    return c

def up(c):
    c.connect(HOST, PORT, keepalive=30); c.loop_start()
    assert c.connected.wait(10), "no CONNACK"
    return c

res = {}
util = up(make("utility", "utility")); util.subscribe("grid/#", qos=1); util.subscribe("pqgrid/hs/#", qos=1)
m1 = up(make("meter-0001", "meter1"))
res["T1 mTLS connect with ML-DSA-65 client cert"] = str(m1.conn_rc)
time.sleep(0.5)

# T2 allowed publish
i = m1.publish("grid/smart_meter/meter-0001/telemetry", b"kWh=1.25", qos=1); time.sleep(0.5)
res["T2 allowed publish -> PUBACK"] = str(m1.acks.get(i.mid)); res["T2 utility received allowed msg"] = any(t=="grid/smart_meter/meter-0001/telemetry" for t,*_ in util.got)
# T3 forbidden publish (other meter's topic)
i = m1.publish("grid/smart_meter/meter-0002/telemetry", b"spoof", qos=1); time.sleep(0.5)
res["T3 forbidden publish -> PUBACK"] = str(m1.acks.get(i.mid)); res["T3 utility received spoofed msg"] = any(t=="grid/smart_meter/meter-0002/telemetry" for t,*_ in util.got)
# T4 forbidden subscribe
m1.subscribe("grid/smart_meter/meter-0002/control", qos=1); time.sleep(0.5)
res["T4 forbidden subscribe -> SUBACK"] = m1.subacks[-1] if m1.subacks else None
# T5 MQTT5 properties pass through broker
pr = Properties(PacketTypes.PUBLISH); pr.UserProperty = [("policy_id","grid-pol"),("policy_version","7")]
pr.ResponseTopic = "pqgrid/hs/meter-0001/down"; pr.CorrelationData = b"hs-42"
m1.publish("pqgrid/hs/meter-0001/up", b"\x01"*1200, qos=1, properties=pr); time.sleep(0.5)
hs = [p for t,_,_,p in util.got if t=="pqgrid/hs/meter-0001/up"]
if hs:
    p = hs[0]; res["T5 user props / response topic / correlation forwarded"] = (getattr(p,"UserProperty",None), getattr(p,"ResponseTopic",None), getattr(p,"CorrelationData",None))
# T6 retained large messages (manifest 16 KB + chunk 256 KB) delivered to a late subscriber
for name, size in [("manifest", 16_224+400), ("1/chunk/0", 256*1024)]:
    util.publish(f"pqgrid/fota/smart_meter/{name}", b"\xAB"*size, qos=1, retain=True)
time.sleep(1.0)
m1.subscribe("pqgrid/fota/smart_meter/#", qos=1); time.sleep(1.5)
res["T6 retained msgs delivered to late subscriber (topic,len,retain)"] = [(t,l,r) for t,l,r,_ in m1.got if t.startswith("pqgrid/fota")]
m1.disconnect(); m1.loop_stop()

# T7 full TLS+MQTT connect latency (new session each time)
lat = []
for k in range(30):
    c = make(f"meter-0001", "meter1"); a = time.perf_counter(); c.connect(HOST, PORT); c.loop_start(); c.connected.wait(10); lat.append((time.perf_counter()-a)*1e3); c.disconnect(); c.loop_stop()
res["T7 full hybrid-TLS + mTLS + MQTT CONNECT latency, median ms (n=30, loopback, first 5 dropped)"] = round(st.median(lat[5:]), 2)
util.disconnect(); util.loop_stop()

# T8 TLS 1.3 session resumption against Mosquitto (raw ssl + hand-made MQTT 3.1.1 CONNECT)
ctx = ssl.create_default_context(cafile=f"{P}/ca.crt"); ctx.load_cert_chain(f"{P}/meter1.crt", f"{P}/meter1.key")
def mqtt_connect_packet(cid):
    vh = b"\x00\x04MQTT\x04\x02\x00\x1e"; pl = struct.pack("!H", len(cid)) + cid.encode()
    return b"\x10" + bytes([len(vh)+len(pl)]) + vh + pl
def one(session=None):
    a = time.perf_counter()
    s = ctx.wrap_socket(socket.create_connection((HOST, PORT)), server_hostname=HOST, session=session)
    s.sendall(mqtt_connect_packet("meter-0001")); ack = s.recv(4)
    dt = (time.perf_counter()-a)*1e3; sess = s.session; reused = s.session_reused; s.close()
    return dt, sess, reused, ack
d0, sess, r0, ack0 = one()
full, resumed, flags = [], [], []
for _ in range(20):
    d, s1, r, _ = one(); full.append(d)
    d2, _, r2, ack = one(session=s1); resumed.append(d2); flags.append(r2)
res["T8 CONNACK ok"] = ack0[:2] == b"\x20\x02"
res["T8 TLS resumption actually reused session (20 tries)"] = f"{sum(flags)}/20"
res["T8 full vs resumed TLS+CONNECT median ms"] = (round(st.median(full),2), round(st.median(resumed),2))

for k, v in res.items(): print(f"{k}: {v}")
