"""Objective 1 (PCHC-MQTT) LIVE, over the real broker: every scenario, step by step, with what actually went over the
wire. The real Mosquitto broker (hybrid-only TLS 1.3), the real utility program and two emulated devices (a smart
meter and a DER controller) run their production main loops (`run()`: tick, wait, repeat until stopped), each with a
TLS socket to the broker, exactly as in tests/integration. Runs in the test image:

    docker run --rm pqgrid-tests python tools/demo_objective1.py              # the scenarios, then stop
    docker run --rm -it pqgrid-tests python tools/demo_objective1.py --forever # then keep running (Ctrl+C stops)

Scenarios: S1 connect + end-to-end handshake; S2 TELEMETRY; S3 ALERT; S4 CONTROL command; S5 GRANT + SETPOINT;
S6 broadcast DR event; S7 attacks over the broker (plaintext on an ALERT topic, a forged command, a replayed command,
a classical-only TLS client); S8 policy change (every device moves to the new policy and re-handshakes).
Sizes are the bytes each program handed to MQTT (the E2E envelope; TLS adds its own record overhead). [DOCKER]
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "tests"), os.path.join(ROOT, "tests", "integration"), ROOT]

import conftest                                                                     # noqa: E402
from harness import Broker, Plant, loops, start, wait_for                           # noqa: E402
from pqgrid.commands.codec import Command, cmd_signed_input, encode                 # noqa: E402
from pqgrid.e2e.envelopes import seal_control                                       # noqa: E402
from pqgrid.mqtt import topics                                                      # noqa: E402
from pqgrid.suite.aead import AeadAlg                                               # noqa: E402
from pqgrid.suite.sig import mldsa_keygen, mldsa_sign                              # noqa: E402

M1, D1 = b"meter-0001", b"der-0001"
FOREVER = "--forever" in sys.argv
RESULTS: list[list[str]] = []


class Wire:
    """Records what each program hands to MQTT: (who, topic, size, payload)."""

    def __init__(self):
        self.log: list[tuple[str, str, int, bytes]] = []

    def device(self, dev) -> None:
        real, who = dev.mq._publish, dev.did.decode()

        def rec(topic, payload):
            self.log.append((who, topic, len(payload), payload))
            return real(topic, payload)
        dev.mq._publish = rec

    def utility(self, u) -> None:
        real = u._send

        def rec(topic, payload, retain=False):
            self.log.append(("utility", topic, len(payload), payload))
            return real(topic, payload, retain)
        u._send = rec

    def mark(self) -> int:
        return len(self.log)

    def since(self, n: int, who: str | None = None, topic_end: str | None = None) -> list:
        return [x for x in self.log[n:] if (who is None or x[0] == who)
                and (topic_end is None or x[1].endswith(topic_end))]


def step(sid: str, title: str) -> None:
    print(f"\n=== {sid}  {title}")


def say(msg: str) -> None:
    print(f"    {msg}")


def result(sid: str, scenario: str, ok: bool, evidence: str) -> None:
    RESULTS.append([sid, scenario, "PASS" if ok else "**FAIL**", evidence])
    say(("OK   " if ok else "FAIL ") + evidence)


def sizes(entries) -> str:
    return ", ".join(f"{n} B" for _, _, n, _ in entries) or "nothing"


def info(pinfo: bytes) -> str:
    """POLICY_INFO = policy_id ‖ "|" ‖ u32(version), readable."""
    pid, _, ver = pinfo.partition(b"|")
    return f"{pid.decode()} v{int.from_bytes(ver, 'big')}"


def main() -> int:
    tmp = tempfile.mkdtemp()
    b = Broker(tmp)
    p = Plant(b, tmp)
    meter, der = p.add(M1, "smart_meter"), p.add(D1, "der_ctrl")
    wire = Wire()
    wire.device(meter)
    wire.device(der)
    wire.utility(p.u)
    print("# Objective 1 (PCHC-MQTT) live over the real broker")
    print(f"Broker: Mosquitto on 127.0.0.1:{b.port}, TLS 1.3 only, hybrid groups only (X25519MLKEM768). Devices: "
          f"{M1.decode()} (smart_meter: TELEMETRY + ALERT) and {D1.decode()} (der_ctrl: also takes commands). "
          f"Policy {info(p.policy.info())}.")
    try:
        start(p)
        with loops(p, meter, der):
            scenarios(p, b, wire, meter, der)
            if FOREVER:
                forever(p, meter)
    finally:
        p.close()
        b.stop()
    print("\n## Summary\n")
    print(conftest_table(["Step", "Scenario", "Result", "Evidence"], RESULTS))
    failed = sum(r[2] != "PASS" for r in RESULTS)
    print(f"\nRESULT: {'all ' + str(len(RESULTS)) + ' checks passed' if not failed else str(failed) + ' FAILED'}")
    return 1 if failed else 0


def conftest_table(head, rows) -> str:
    out = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    return "\n".join(out + ["| " + " | ".join(str(c) for c in r) + " |" for r in rows])


def scenarios(p, b, wire, meter, der) -> None:
    # ---------------------------------------------------------------------------------------- S1 connect
    step("S1", "Connect over hybrid TLS 1.3, then the end-to-end handshake (device <-> utility)")
    n = wire.mark()
    ok = wait_for(lambda: meter.d.confirmed and der.d.confirmed, 30)
    for dev in (meter, der):
        up, down = wire.since(n, dev.did.decode(), "/up"), wire.since(n, "utility", f"{dev.did.decode()}/down")
        say(f"{dev.did.decode()}: CH {up[0][2] if up else '?'} B -> SH {down[0][2] if down else '?'} B -> "
            f"DF {up[1][2] if len(up) > 1 else '?'} B -> NT/FIN {down[1][2] if len(down) > 1 else '?'} B")
    s = p.node.endpoint.current_session(D1)
    result("S1", "Connect + end-to-end handshake", ok and s is not None,
           f"both sessions established; policy bound into the keys: {info(s.policy_info)}" if s else "no session")

    # ---------------------------------------------------------------------------------------- S2 telemetry
    step("S2", "TELEMETRY: a meter reading, protected by the hybrid TLS hop only")
    n, reading = wire.mark(), b"kWh=1234.5;V=230.1;A=4.2"
    meter.mq.send_telemetry(reading)
    ok = wait_for(lambda: (M1, reading) in p.u.telemetry, 10)
    say(f"meter -> broker -> utility: {sizes(wire.since(n, 'meter-0001'))}, the reading as is (no E2E layer)")
    result("S2", "TELEMETRY delivered", ok, f"utility received {reading.decode()!r} from {M1.decode()}")

    # ---------------------------------------------------------------------------------------- S3 alert
    step("S3", "ALERT: encrypted end to end, numbered, acknowledged; kept in the device outbox until the ACK")
    n, text = wire.mark(), b"cover opened"
    meter.mq.send_alert(b"TAMPER", text)
    ok = wait_for(lambda: (M1, text, False) in p.u.alerts, 10) and wait_for(lambda: meter.outbox.queued() == [], 10)
    env = wire.since(n, "meter-0001", "/alert")
    say(f"meter -> utility: ALERT envelope {env[0][2] if env else '?'} B; the text is "
        f"{'NOT' if env and text not in env[0][3] else 'VISIBLE'} in the bytes the broker carries")
    say(f"utility -> meter: ACK {sizes(wire.since(n, 'utility', '/control'))}; device outbox now empty")
    result("S3", "ALERT delivered, ACKed, not readable by the broker", ok and bool(env) and text not in env[0][3],
           f"utility received {text.decode()!r}; ACK cleared the outbox")

    # ---------------------------------------------------------------------------------------- S4 command
    step("S4", "CONTROL: a discrete command, encrypted end to end AND signed with ML-DSA-65")
    n = wire.mark()
    seq = p.u.command(D1, b"CURTAIL 50%", 300)
    ok = wait_for(lambda: p.node.commands.outcome(D1, seq) == b"OK", 15)
    cmd = wire.since(n, "utility", "/control")
    say(f"utility -> der: CMD envelope {cmd[0][2] if cmd else '?'} B (includes the 3,309-B signature)")
    say(f"der -> utility: status {sizes(wire.since(n, 'der-0001', '/alert'))}; applied: {der.applied}")
    result("S4", "Command verified, applied once, status OK", ok and der.applied == [b"CURTAIL 50%"],
           f"cmd_seq {seq:#x} -> OK; device applied {der.applied}")
    replay = cmd[0][3] if cmd else b""

    # ---------------------------------------------------------------------------------------- S5 grant + setpoint
    step("S5", "CONTROL: one signed GRANT, then cheap SETPOINTs within its limits")
    n = wire.mark()
    gid = p.u.grant(D1, "P_ACTIVE_W", -5000, 5000, 12, 3600)
    grant_ok = wait_for(lambda: any(st[0] == D1 and st[2] == b"OK" and st[1] != seq for st in p.u.statuses), 15)
    p.u.setpoint(D1, gid, 2500, 30)
    ok = wait_for(lambda: der.setpoints == [("P_ACTIVE_W", 2500)], 15)
    ctl = wire.since(n, "utility", "/control")
    say(f"utility -> der: GRANT {ctl[0][2] if ctl else '?'} B (signed: P_ACTIVE_W in [-5000, 5000] W, <= 12/min, 1 h)"
        f", SETPOINT {ctl[1][2] if len(ctl) > 1 else '?'} B (no signature)")
    result("S5", "GRANT accepted; SETPOINT applied within its limits", grant_ok and ok,
           f"device set-points {der.setpoints}")

    # ---------------------------------------------------------------------------------------- S6 broadcast
    step("S6", "CONTROL broadcast: a demand-response event for a zone (zone key + ML-DSA-65)")
    n = wire.mark()
    p.node.zones.create("f7")
    p.u.join_zone("f7", D1)
    p.publish_acl()                                                                # the zone's read right
    sub = wait_for(lambda: topics.dr_event("f7", AeadAlg.CHACHA20POLY1305) in der.mq.subscribed, 15)
    p.u.dr_event("f7", b"SHED 20% 14:00-16:00", 600)
    ok = wait_for(lambda: der.mq.events == [("f7", b"SHED 20% 14:00-16:00")], 15)
    say(f"utility -> der: ZONEKEY {sizes(wire.since(n, 'utility', '/control'))}; utility -> zone f7: "
        f"event {sizes(wire.since(n, 'utility', '/event'))} (one per crypto group)")
    result("S6", "Zone key delivered; broadcast event verified and accepted", sub and ok, f"device events {der.mq.events}")

    # ---------------------------------------------------------------------------------------- S7 attacks
    step("S7", "Attacks over the broker")
    ta = topics.alert("smart_meter", M1)
    before = len(p.u.refused)
    meter.mq.c.publish(ta, b"plain text: meter tampered", qos=1)                  # tier stripped: plaintext
    ok = wait_for(lambda: any(ta in r for r in list(p.u.refused)[before:]), 10)
    why = next((r for r in list(p.u.refused)[before:] if ta in r), "")
    result("S7a", "Plaintext (tier-stripped) message on an ALERT topic", ok,
           f"utility refused it: not an end-to-end envelope ({why.split(': ', 1)[-1]})")

    tc = topics.control("der_ctrl", D1)
    rogue, s = mldsa_keygen(), p.node.endpoint.session_for(D1)
    fseq, exp = (p.node.commands.epoch << 32) | 999, int(time.time()) + 60
    forged = Command(fseq, b"TRIP BREAKER 1", exp, False,
                     mldsa_sign(rogue, cmd_signed_input(D1, tc, fseq, exp, False, b"TRIP BREAKER 1")))
    with p.u.lock:
        p.u._send(tc, seal_control(p.node.endpoint.policy, s, tc, encode(forged)))  # valid session, wrong key
    ok = wait_for(lambda: (D1, fseq, b"REJECTED:signature") in p.u.statuses, 15)
    result("S7b", "Forged command (session key, but not the command key)", ok and b"TRIP BREAKER 1" not in der.applied,
           "device answered REJECTED:signature; not applied")

    before = len(der.mq.errors)
    with p.u.lock:
        p.u._send(tc, replay)                                                      # S4's command, again
    ok = wait_for(lambda: any("not newer" in e for e in list(der.mq.errors)[before:]), 10)
    result("S7c", "Replayed command (S4's envelope sent again)", ok and der.applied.count(b"CURTAIL 50%") == 1,
           "device refused it as a replay; applied once")

    out = b.s_client("-groups", "X25519")
    result("S7d", "Client offering only classical X25519 key exchange", "alert handshake failure" in out,
           "broker refused the TLS handshake (alert 40: handshake failure)")

    # ---------------------------------------------------------------------------------------- S8 policy change
    step("S8", "Policy change: a new signed policy (v2) becomes active; every session moves to it")
    old_info = p.node.endpoint.policy.info()
    new = conftest.make_policy(p.u_static.pk, p.policy.utility_cmd_pk, version=2, ca_set=p.policy.ca_set,
                               activate_at=int(time.time()) + 6)
    arts = [p.sign_policy(new, cls) for cls in ("smart_meter", "der_ctrl")]
    for art in arts:
        p.u.publish_artifact(art)                                                  # delivered as Objective 2 does
    p.u.schedule_policy(arts[0].signed, arts[0].payload, p.station.anchors)
    ok = wait_for(lambda: all(d.d.confirmed and d.d.session.policy_info == new.info() for d in (meter, der))
                  and p.node.endpoint.policy.version == 2, 45)
    say(f"policy {info(old_info)} -> {info(p.node.endpoint.policy.info())}; both devices re-handshook under v2")
    result("S8", "Policy v1 -> v2: old sessions closed, devices re-established under v2", ok,
           f"meter and der sessions now bound to {info(new.info())}")


def forever(p, meter) -> None:
    print("\n=== Running until Ctrl+C: the meter sends a reading every 5 s; the utility prints what it receives")
    k = 0
    try:
        while True:
            time.sleep(5)
            k += 1
            reading = f"kWh={1234.5 + k / 10:.1f}".encode()
            meter.mq.send_telemetry(reading)
            if wait_for(lambda: (M1, reading) in p.u.telemetry, 5):
                print(f"    {time.strftime('%H:%M:%S')}  utility <- {M1.decode()}: {reading.decode()}")
    except KeyboardInterrupt:
        print("\n    stopped by Ctrl+C")


if __name__ == "__main__":
    sys.exit(main())
