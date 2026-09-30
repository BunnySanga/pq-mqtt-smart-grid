"""TCP relay between a client and the broker, used as (a) a byte counter and TLS-record parser and
(b) a crude link model: one-way delay + serialisation rate per direction, plus one RTT for the TCP handshake.

LIMITS (stated wherever results are reported): the proxy terminates TCP, so TCP slow start, ACK clocking,
radio scheduling, repetitions, loss and retransmission are NOT modelled. Results under a link model are
[RESOURCE-CONSTRAINED SIMULATION], not NB-IoT measurements."""
import socket, threading, time, heapq, collections

class Direction:
    def __init__(self, name, delay, bps):
        self.name, self.delay, self.bps = name, delay, bps
        self.bytes, self.chunks, self.records, self._buf = 0, 0, [], b""
        self.ready_at = 0.0                           # earliest time the next chunk may start serialising
    def parse_tls(self, data):                        # TLS record headers: type(1) version(2) length(2)
        self._buf += data
        while len(self._buf) >= 5:
            ln = int.from_bytes(self._buf[3:5], "big")
            if len(self._buf) < 5 + ln: break
            self.records.append((self._buf[0], ln)); self._buf = self._buf[5 + ln:]

class LinkProxy(threading.Thread):
    def __init__(self, listen, target, delay=0.0, up_bps=None, down_bps=None):
        super().__init__(daemon=True)
        self.listen, self.target = listen, target
        self.delay, self.up_bps, self.down_bps = delay, up_bps, down_bps
        self.ready, self.conns, self.lock = threading.Event(), [], threading.Lock()
    def run(self):
        srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.listen)); srv.listen(8); self.ready.set()
        while True:
            cli, _ = srv.accept()
            threading.Thread(target=self._serve, args=(cli,), daemon=True).start()
    def _serve(self, cli):
        t_acc = time.monotonic()
        up_ = Direction("up", self.delay, self.up_bps); down = Direction("down", self.delay, self.down_bps)
        up_.ready_at = t_acc + 2 * self.delay         # SYN / SYN-ACK round trip before the client's first byte
        with self.lock: self.conns.append((up_, down))
        try: srv_sock = socket.create_connection(self.target)
        except OSError: cli.close(); return
        for s_ in (cli, srv_sock): s_.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=self._pump, args=(cli, srv_sock, up_), daemon=True).start()
        threading.Thread(target=self._pump, args=(srv_sock, cli, down), daemon=True).start()
    def _pump(self, src, dst, d: Direction):
        q, cv, done = collections.deque(), threading.Condition(), [False]
        def sender():
            while True:
                with cv:
                    while not q and not done[0]: cv.wait()
                    if not q and done[0]: break
                    at, data = q.popleft()
                wait = at - time.monotonic()
                if wait > 0: time.sleep(wait)
                try: dst.sendall(data)
                except OSError: break
            for s_ in (src, dst):
                try: s_.shutdown(socket.SHUT_RDWR)
                except OSError: pass
        threading.Thread(target=sender, daemon=True).start()
        try:
            while True:
                data = src.recv(65536)
                if not data: break
                now = time.monotonic()
                d.bytes += len(data); d.chunks += 1; d.parse_tls(data)
                start = max(now, d.ready_at)
                ser = (len(data) * 8 / d.bps) if d.bps else 0.0
                d.ready_at = start + ser
                with cv: q.append((d.ready_at + d.delay, data)); cv.notify()
        except OSError: pass
        with cv: done[0] = True; cv.notify()
    def totals(self):
        with self.lock: return sum(u.bytes for u, _ in self.conns), sum(d.bytes for _, d in self.conns)
    def last(self):
        with self.lock: return self.conns[-1] if self.conns else None
