import ssl, time, socket, struct, statistics as st, threading, inspect, sys
import paho.mqtt.client as mqtt
P="/work/pki"; HOST, PORT = "localhost", int(sys.argv[1])
def make(cid, name):
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=cid, protocol=mqtt.MQTTv5)
    c.tls_set(ca_certs=f"{P}/ca.crt", certfile=f"{P}/{name}.crt", keyfile=f"{P}/{name}.key", cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS_CLIENT)
    c.got=[]; c.ev=threading.Event()
    c.on_connect=lambda cl,u,f,rc,p: cl.ev.set(); c.on_message=lambda cl,u,m: cl.got.append(m.topic)
    return c
# F1: forbidden subscription must receive nothing
u = make("utility","utility"); u.connect(HOST,PORT); u.loop_start(); u.ev.wait(5)
m = make("meter-0001","meter1"); m.connect(HOST,PORT); m.loop_start(); m.ev.wait(5)
m.subscribe("grid/smart_meter/meter-0002/control", qos=1); time.sleep(0.5)
u.publish("grid/smart_meter/meter-0002/control", b"setpoint", qos=1); time.sleep(1)
print("F1 meter-0001 received meter-0002's control msg:", "grid/smart_meter/meter-0002/control" in m.got)
m.disconnect(); u.disconnect(); m.loop_stop(); u.loop_stop()
# F2: latency with TCP_NODELAY on the client (raw ssl) — full vs resumed
ctx = ssl.create_default_context(cafile=f"{P}/ca.crt"); ctx.load_cert_chain(f"{P}/meter1.crt", f"{P}/meter1.key")
def pkt(cid):
    vh=b"\x00\x04MQTT\x04\x02\x00\x1e"; pl=struct.pack("!H",len(cid))+cid.encode(); return b"\x10"+bytes([len(vh)+len(pl)])+vh+pl
def one(session=None):
    a=time.perf_counter(); raw=socket.create_connection((HOST,PORT)); raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s=ctx.wrap_socket(raw, server_hostname=HOST, session=session); s.sendall(pkt("meter-0001")); s.recv(4)
    d=(time.perf_counter()-a)*1e3; ss=s.session; r=s.session_reused; s.close(); return d,ss,r
full,res=[],[]
for _ in range(25):
    d,ss,_=one(); full.append(d); d2,_,r=one(ss); res.append(d2)
print(f"F2 client TCP_NODELAY, server port {PORT}: full median {st.median(full[3:]):.2f} ms | resumed median {st.median(res[3:]):.2f} ms")
# F3: does paho already set TCP_NODELAY, and where does it wrap TLS?
src = inspect.getsource(mqtt.Client)
print("F3 paho sets TCP_NODELAY:", "TCP_NODELAY" in src, "| wrap_socket call present:", "wrap_socket(" in src)
