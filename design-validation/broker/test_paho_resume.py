import ssl, socket, time, threading, statistics as st
import paho.mqtt.client as mqtt
P = "/work/pki"
CTX = ssl.create_default_context(cafile=f"{P}/ca.crt"); CTX.load_cert_chain(f"{P}/meter1.crt", f"{P}/meter1.key")   # ONE context per device lifetime
class PQClient(mqtt.Client):
    """paho 2.1.0 subclass: TCP_NODELAY + TLS 1.3 session reuse (overrides a private method; pin paho==2.1.0)."""
    tls_session = None
    def _ssl_wrap_socket(self, tcp_sock):
        tcp_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return self._ssl_context.wrap_socket(tcp_sock, server_hostname=self._host, session=self.tls_session)
def connect_once(session=None):
    c = PQClient(mqtt.CallbackAPIVersion.VERSION2, client_id="meter-0001", protocol=mqtt.MQTTv5)
    c.tls_set_context(CTX); c.tls_session = session; ev = threading.Event(); c.on_connect = lambda *a: ev.set()
    a = time.perf_counter(); c.connect("localhost", 8884); c.loop_start(); ev.wait(5); dt = (time.perf_counter() - a) * 1e3
    time.sleep(0.05); sock = c.socket(); sess, reused = sock.session, sock.session_reused
    c.disconnect(); c.loop_stop(); return dt, sess, reused
_, sess, _ = connect_once()
full, res, flags = [], [], []
for _ in range(25):
    d, s1, _ = connect_once(); full.append(d)
    d2, _, r = connect_once(s1); res.append(d2); flags.append(r)
print(f"paho subclass: TLS resumed {sum(flags)}/25 | full median {st.median(full[3:]):.2f} ms | resumed median {st.median(res[3:]):.2f} ms  (loopback, ML-DSA-65 certs, TCP_NODELAY both sides)")
