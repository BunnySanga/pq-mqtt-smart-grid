"""Objective 1 (PCHC-MQTT) measured on the final `pqgrid` code: the tier each topic gets, per-tier message sizes and
compute, the full end-to-end handshake, and every downgrade / tamper / replay / forgery attempt with the reason it is
refused (Master §11, §12, §9.4, §24). Runs in the test image (Mosquitto + OpenSSL 3.5 for the TLS part):

    docker run --rm pqgrid-tests python tools/bench_objective1.py            # full: median of 200 after 20 warm-up
    docker run --rm pqgrid-tests python tools/bench_objective1.py --quick    # a smoke run (40 after 5)

Every figure is [DOCKER]: a laptop container, NOT a device measurement (Master §32). Byte counts are the same on any
platform; times are not (device-class cycles: Master §22, [LIT]). The method follows
design-validation/reference/bench.py (v2.1), so the two can be compared.
"""
from __future__ import annotations

import os
import platform
import ssl
import statistics as st
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "tests"), os.path.join(ROOT, "tests", "integration"), ROOT]

import cryptography                                                               # noqa: E402
from conftest import RULES, World, make_policy                                    # noqa: E402
from pqgrid.commands import CommandProcessor, CommandService, ZoneManager         # noqa: E402
from pqgrid.commands.codec import Command, cmd_signed_input, encode               # noqa: E402
from pqgrid.e2e.envelopes import alert_topic, control_topic, seal_control         # noqa: E402
from pqgrid.errors import EnvelopeError, HandshakeError, PqgridError, ReplayError  # noqa: E402
from pqgrid.mqtt import topics                                                    # noqa: E402
from pqgrid.policy.engine import tier_for                                         # noqa: E402
from pqgrid.policy import Rule, Tier                                              # noqa: E402
from pqgrid.suite.sig import mldsa_keygen, mldsa_public_bytes, mldsa_sign         # noqa: E402
from pqgrid.wire import dec, enc                                                  # noqa: E402

QUICK = "--quick" in sys.argv
N, WARM = (40, 5) if QUICK else (200, 20)
PAYLOAD = b"P" * 64                                                               # the 64-byte payload of §11
M1, D1 = b"meter-0001", b"der-0001"
TARGET = "P_ACTIVE_W"
T = time.perf_counter


def med_ms(xs: list[float]) -> float:
    return st.median(xs[WARM:]) * 1e3


def flip(buf: bytes, field: int, n: int) -> bytes:
    """What a tampering broker does: one bit changed in one field of a message (as tests/security/test_handshake.py)."""
    f = dec(buf, n)
    b = bytearray(f[field])
    b[len(b) // 2] ^= 1
    f[field] = bytes(b)
    return enc(f)


def table(head: list[str], rows: list[list]) -> str:
    out = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


class Der:
    """A der_ctrl device (it accepts CMD, GRANT and SETPOINT) with a command processor, on a live E2E session."""

    def __init__(self, w: World):
        self.w, self.topic = w, control_topic("der_ctrl", D1)
        self.svc = CommandService(w.utility, w.cmd_sk)
        self.d = w.device(D1, "der_ctrl")
        self.applied: list[bytes] = []
        self.proc = CommandProcessor(self.d, self.applied.append, lambda t, v: None, targets={TARGET})
        w.full(self.d)


# ======================================================================================== 1. the tier engine
def tiers() -> str:
    w = World()
    overlapping = make_policy(w.u_static.pk, mldsa_public_bytes(w.cmd_sk),
                              rules=RULES + (Rule("grid/#", Tier.TELEMETRY),))     # a careless, overlapping rule
    cases = [("grid/smart_meter/meter-0001/telemetry", w.policy, "rule: TELEMETRY"),
             ("grid/smart_meter/meter-0001/alert", w.policy, "rule: ALERT"),
             ("grid/der_ctrl/der-0001/control", w.policy, "rule: CONTROL"),
             ("grid/dr/f7/AES256GCM/event", w.policy, "rule: CONTROL (broadcast)"),
             ("grid/smart_meter/meter-0001/debug", w.policy, "no rule matches: the default"),
             ("grid/smart_meter/meter-0001/alert", overlapping, "plus `grid/#` -> TELEMETRY: strongest wins"),
             ("grid/+/meter-0001/alert", w.policy, "not a valid topic: the default")]
    return table(["Topic", "Tier", "Why"], [[f"`{t}`", tier_for(p, t).name, why] for t, p, why in cases])


# ================================================================================== 2. sizes and compute
def per_tier() -> tuple[str, dict]:
    w = World()
    m = w.device(M1, "smart_meter")
    w.full(m)
    c = Der(w)
    ta, tt = alert_topic("smart_meter", M1), topics.telemetry("smart_meter", M1)

    seal, open_ = [], []                                                           # ALERT
    for _ in range(N):
        t0 = T()
        env = m.seal_alert(ta, os.urandom(16), PAYLOAD)
        t1 = T()
        _, ack, _ = w.utility.open_alert(ta, env)
        seal.append(t1 - t0)
        open_.append(T() - t1)
    alert_env, alert_ack = env, ack

    sign, verify = [], []                                                          # CONTROL: a discrete command
    for i in range(N):
        t0 = T()
        c.svc.issue(D1, PAYLOAD, 300)
        [cmd_env] = c.svc.outgoing(D1)
        t1 = T()
        status = c.proc.on_control(c.topic, cmd_env)
        verify.append(T() - t1)
        sign.append(t1 - t0)
        c.svc.on_status(status)                                                    # closes it (not timed)
    gsign, gverify = [], []                                                        # CONTROL: GRANT
    for _ in range(max(N // 4, WARM + 5)):
        t0 = T()
        gid, grant_env = c.svc.grant(D1, TARGET, -5000, 5000, 12, 3600)
        t1 = T()
        c.proc.on_control(c.topic, grant_env)
        gverify.append(T() - t1)
        gsign.append(t1 - t0)
    sseal, sapply = [], []                                                         # CONTROL: SETPOINT
    for i in range(N):
        w.t += 6                                                                   # 10 a minute: within the GRANT's 12
        t0 = T()
        sp_env = c.svc.setpoint(D1, gid, i % 5000, 30)
        t1 = T()
        c.proc.on_control(c.topic, sp_env)
        sapply.append(T() - t1)
        sseal.append(t1 - t0)
    zm = ZoneManager(c.svc)                                                        # CONTROL: broadcast DR event
    zm.create("f7")
    zm.add_member("f7", D1)
    [(bt, bc_env)] = zm.publish("f7", PAYLOAD, 600).items()

    rows = [
        ["TELEMETRY", "hybrid TLS hop only", "none: the 64 B as is", 0, topics.publish_size(tt, PAYLOAD), "—", "—"],
        ["ALERT", "+ E2E AEAD, sequence number, end-to-end ACK", len(alert_env),
         len(alert_env) - 64, topics.publish_size(ta, alert_env), f"seal {med_ms(seal):.4f}", f"open {med_ms(open_):.4f}"],
        ["CONTROL: command", "+ E2E AEAD + ML-DSA-65 signature", len(cmd_env), len(cmd_env) - 64,
         topics.publish_size(c.topic, cmd_env), f"open + verify + apply {med_ms(verify):.4f}",
         f"sign + seal {med_ms(sign):.4f}"],
        ["CONTROL: GRANT", "+ E2E AEAD + ML-DSA-65, session-bound limits", len(grant_env), "—",
         topics.publish_size(c.topic, grant_env), f"open + verify {med_ms(gverify):.4f}", f"sign + seal {med_ms(gsign):.4f}"],
        ["CONTROL: SETPOINT", "+ E2E AEAD within a GRANT (no signature)", len(sp_env), "—",
         topics.publish_size(c.topic, sp_env), f"open + check + apply {med_ms(sapply):.4f}", f"seal {med_ms(sseal):.4f}"],
        ["CONTROL: broadcast event", "+ zone-key AEAD + ML-DSA-65", len(bc_env), len(bc_env) - 64,
         topics.publish_size(bt, bc_env), "—", "—"],
    ]
    t = table(["Tier", "Protection on top of hybrid TLS", "E2E envelope (B)", "Overhead vs 64 B", "MQTT PUBLISH (B)",
               "Device (ms, median)", "Utility (ms, median)"], rows)
    acks = (f"Acknowledgements: ALERT ACK {len(alert_ack)} B (utility -> device); command status ACK {len(status)} B "
            f"(device -> utility).")
    return t + "\n\n" + acks, {"alert": len(alert_env), "cmd": len(cmd_env), "grant": len(grant_env),
                               "setpoint": len(sp_env), "broadcast": len(bc_env)}


# ============================================================================================ 3. the handshake
def handshake() -> str:
    rows = []
    for did, dclass in ((M1, "smart_meter"), (D1, "der_ctrl")):
        w = World()
        d = w.device(did, dclass)
        dev, utl = [], []
        for _ in range(N):
            t0 = T()
            ch = d.client_hello()
            t1 = T()
            sh = w.utility.on_client_hello(did, ch)
            t2 = T()
            d.on_server_hello(sh)
            df = d.finished([])
            t3 = T()
            fin = w.utility.on_finished(did, df).final
            t4 = T()
            d.on_final(fin)
            t5 = T()
            dev.append((t1 - t0) + (t3 - t2) + (t5 - t4))
            utl.append((t2 - t1) + (t4 - t3))
        total = len(ch) + len(sh) + len(df) + len(fin)
        rows.append([f"{dclass} ({w.policy.profile(dclass).resume.name})", len(ch), len(sh), len(df), len(fin), total,
                     f"{med_ms(dev):.3f}", f"{med_ms(utl):.3f}"])
    return table(["Device class (resume mode)", "CH (B)", "SH (B)", "DF (B)", "NT/FIN (B)", "Total (B)",
                  "Device (ms, median)", "Utility (ms, median)"], rows) + (
        "\n\nThree hybrid KEMs (ML-KEM-768 + X25519, X-Wing): ephemeral (forward secrecy), to the utility's key "
        "(authenticates the utility), to the device's key (authenticates the device); POLICY_INFO inside the "
        "encrypted CH and SH, hashed into K_master.")


# ======================================================================================== 4. the attacks
def outcome(fn) -> str:
    try:
        r = fn()
    except (PqgridError, ValueError) as e:
        return f"{type(e).__name__}: {e}"
    return f"returned {r!r}"


def attacks() -> tuple[str, int]:
    rows, failed = [], 0

    def check(aid: str, what: str, expect: str, observed: str) -> None:
        nonlocal failed
        ok = expect in observed
        failed += not ok
        rows.append([aid, what, f"`{expect}`", observed if len(observed) < 110 else observed[:107] + "...",
                     "REFUSED as expected" if ok else "**NOT AS EXPECTED**"])

    w = World()
    d = w.device(M1, "smart_meter")
    check("A1", "Broker changes POLICY_INFO in the client hello", "client hello failed authentication",
          outcome(lambda: w.utility.on_client_hello(M1, flip(d.client_hello(), 5, 6))))
    w = World()
    d = w.device(M1, "smart_meter")
    sh = w.utility.on_client_hello(M1, d.client_hello())
    check("A2", "Broker changes POLICY_INFO in the server hello", "server hello failed authentication",
          outcome(lambda: d.on_server_hello(flip(sh, 4, 6))))
    w = World()
    d = w.device(M1, "smart_meter")
    sh = w.utility.on_client_hello(M1, d.client_hello())
    check("A2b", "Broker changes the utility's key confirmation", "key confirmation",
          outcome(lambda: d.on_server_hello(flip(sh, 5, 6))))
    w = World()
    old = make_policy(w.u_static.pk, mldsa_public_bytes(w.cmd_sk), version=1)
    w.utility.policy = make_policy(w.u_static.pk, mldsa_public_bytes(w.cmd_sk), version=2)
    d = w.device(M1, "smart_meter", policy=old)
    check("A4", "Device still on an older (weaker) policy", "POLICY_INFO mismatch",
          outcome(lambda: w.utility.on_client_hello(M1, d.client_hello())))

    w = World()
    d = w.device(M1, "smart_meter")
    w.full(d)
    ta = alert_topic("smart_meter", M1)
    env = d.seal_alert(ta, os.urandom(16), b"TAMPER_SWITCH_OPENED")
    check("A5", "Broker looks for the alert's text in the envelope", "not found",
          "not found" if b"TAMPER_SWITCH_OPENED" not in env else "FOUND IN CLEAR")
    check("A6", "Plaintext (tier-stripped) message on an ALERT topic", "EnvelopeError",
          outcome(lambda: w.utility.open_alert(ta, b"plain text reading")))
    check("A7", "Device asked to send an ALERT on a TELEMETRY topic", "not ALERT tier",
          outcome(lambda: d.seal_alert(topics.telemetry("smart_meter", M1), os.urandom(16), b"x")))
    w.utility.open_alert(ta, env)
    check("A8", "Broker replays an alert already delivered", "ReplayError",
          outcome(lambda: w.utility.open_alert(ta, env)))

    w = World()
    c = Der(w)
    c.svc.issue(D1, b"TRIP", 300)
    [cmd] = c.svc.outgoing(D1)
    c.proc.on_control(c.topic, cmd)
    check("A9", "Broker replays a command already applied", "ReplayError",
          outcome(lambda: c.proc.on_control(c.topic, cmd)))
    w = World()                                                                     # a fresh device: nothing applied
    c = Der(w)
    rogue, s = mldsa_keygen(), w.utility.session_for(D1)
    seq, exp = (c.svc.epoch << 32) | 99, int(w.t) + 60
    forged = Command(seq, b"TRIP", exp, False, mldsa_sign(rogue, cmd_signed_input(D1, c.topic, seq, exp, False, b"TRIP")))
    status = c.svc.on_status(c.proc.on_control(c.topic, seal_control(w.policy, s, c.topic, encode(forged))))[2]
    check("A10", "Someone with the session key (not the command key) forges a command", "REJECTED:signature",
          f"status {status.decode()}; forged command applied: {'YES' if c.applied else 'no'}")
    return table(["ID", "Attack", "Expected refusal", "Observed", "Result"], rows), failed


def tls() -> tuple[str, int]:
    """N3 over the real broker (hybrid-only OpenSSL configuration, as tests/integration/test_mqtt.py)."""
    try:
        from harness import Broker
        b = Broker(tempfile.mkdtemp())
    except Exception as e:                                                          # noqa: BLE001
        return f"_Not run here: {type(e).__name__}: {e}. Run it in the test image (Mosquitto, OpenSSL >= 3.5)._", 0
    try:
        rows, failed = [], 0
        for what, args, expect in [("Device with the default group list", (), "Negotiated TLS1.3 group: X25519MLKEM768"),
                                   ("Client offering ONLY classical X25519", ("-groups", "X25519"), "alert handshake failure"),
                                   ("Client offering only TLS 1.2", ("-tls1_2",), "alert protocol version")]:
            out = b.s_client(*args)
            ok = expect in out
            failed += not ok
            line = next((ln for ln in out.splitlines() if expect.split(":")[0] in ln), out.splitlines()[0] if out else "")
            rows.append([what, f"`{expect}`", line.strip()[:100], "as expected" if ok else "**NOT AS EXPECTED**"])
        return table(["N3: TLS client", "Expected", "Observed (openssl s_client)", "Result"], rows), failed
    finally:
        b.stop()


def main() -> int:
    print("# Objective 1 (PCHC-MQTT) on the final pqgrid code\n")
    label = "[DOCKER]" if os.path.exists("/.dockerenv") else "[LOCAL, not the canonical image]"
    print(f"ENVIRONMENT {label}: {platform.system()} {platform.machine()} | Python {sys.version.split()[0]} | "
          f"cryptography {cryptography.__version__} | {ssl.OPENSSL_VERSION} | median of {N - WARM} runs after {WARM} "
          f"warm-up{' (QUICK smoke run)' if QUICK else ''}. On a laptop: not a device measurement.\n")
    print("## 1. Which tier a topic gets (signed policy, strongest rule wins, no rule -> CONTROL)\n")
    print(tiers(), "\n")
    print("## 2. Per-tier cost for a 64-byte payload\n")
    t, _ = per_tier()
    print(t, "\n")
    print("## 3. The full end-to-end handshake (device <-> utility, through the broker)\n")
    print(handshake(), "\n")
    print("## 4. Downgrade, tamper, replay and forgery attempts\n")
    t, failed = attacks()
    print(t, "\n")
    print("## 5. Hybrid-only TLS at the broker\n")
    t2, failed2 = tls()
    print(t2, "\n")
    print(f"RESULT: {'every attempt refused as expected' if failed + failed2 == 0 else f'{failed + failed2} NOT AS EXPECTED'}")
    return 1 if failed + failed2 else 0


if __name__ == "__main__":
    sys.exit(main())
