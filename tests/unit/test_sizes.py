"""Wire sizes must match the numbers published in Master.md (§9.4 table, Appendix C), so the implementation
and the design cannot drift apart silently.

    CH 2,493 B · SH 2,411 B (meter-0001 / smart_meter, PSK)   [DOCKER bench, v2.1 layout unchanged]
    ALERT envelope 137 B for a 64-byte payload               [DOCKER bench]
    DF alone 46 B · DF + one ALERT 193 B                      [ANALYTICAL, Appendix C]

Resume and NT sizes are the v2.2 layout measured here (IMPLEMENTATION-ROADMAP §8.2). They differ from Master's
v2.1 bench table (§9.4: PSK 337 + 110 + 42 + 266) by the 16-bit kid (+1), the DF bundle field (+4), the NT ACK
field (+4, +1 kid) and the flat RS layout (−4, E17). Pinned so the layout cannot drift silently.
    PSK resume (meter-0001 / smart_meter)   RH 338 · RS 106 · DF 46 · NT 271 = 761 B
    PSK_KEM resume (der-0001 / der_ctrl)    RH 1,555 · RS 1,226 · DF 46 · NT 270 = 3,097 B
    Full handshake with NT                  2,493 + 2,411 + 46 + 271 = 5,221 B

CONTROL (v2.2 layout, der-0001 / der_ctrl, measured here; Master Appendix C figures are [ANALYTICAL] and omit
cmd_seq (C5) and the ZONEKEY aead field (DR-047)):
    CMD (64-byte command) 3,466 · GRANT (target "P_ACTIVE_W") 3,477 · SETPOINT 97 · ZONEKEY ("zone-7") 138
    status ACK 83 (b"OK") · DR broadcast (64-byte event, "zone-7") 3,468
"""
import os

from conftest import World
from pqgrid.e2e.envelopes import alert_topic


def test_published_handshake_and_alert_sizes(world: World):
    d = world.device(b"meter-0001", "smart_meter")
    ch = d.client_hello()
    sh = world.utility.on_client_hello(d.id, ch)
    d.on_server_hello(sh)
    topic = alert_topic("smart_meter", d.id)
    df = d.finished([(topic, os.urandom(16), b"p" * 64)])
    assert (len(ch), len(sh), len(df)) == (2493, 2411, 193)


def test_df_alone_and_live_alert_sizes(world: World):
    d = world.device(b"meter-0001", "smart_meter")
    d.on_server_hello(world.utility.on_client_hello(d.id, d.client_hello()))
    df = d.finished()
    assert len(df) == 46
    d.on_final(world.utility.on_finished(d.id, df).final)
    env = d.seal_alert(alert_topic("smart_meter", d.id), os.urandom(16), b"p" * 64)
    assert len(env) == 137


def _resume_sizes(world: World, did: bytes, dclass: str):
    d = world.device(did, dclass)
    full = world.full(d)[0].final
    rh = d.resume_hello()
    rs = world.utility.on_resume_hello(d.id, rh)
    d.on_resume_server(rs)
    df = d.finished()
    nt = world.utility.on_finished(d.id, df).final
    return len(full), (len(rh), len(rs), len(df), len(nt))


def test_resume_sizes_v22_layout(world: World):
    nt_full, psk = _resume_sizes(world, b"meter-0001", "smart_meter")
    _, psk_kem = _resume_sizes(world, b"der-0001", "der_ctrl")
    assert nt_full == 271
    assert psk == (338, 106, 46, 271) and sum(psk) == 761
    assert psk_kem == (1555, 1226, 46, 270) and sum(psk_kem) == 3097


def test_control_sizes_v22_layout(world: World):
    from pqgrid.commands import CommandProcessor, CommandService, ZoneManager
    from pqgrid.e2e.envelopes import control_topic
    from pqgrid.suite.aead import AeadAlg
    d = world.device(b"der-0001", "der_ctrl")
    world.full(d)
    svc = CommandService(world.utility, world.cmd_sk)
    proc = CommandProcessor(d, lambda c: None, lambda t, v: None, targets={"P_ACTIVE_W"})
    svc.issue(d.id, b"c" * 64, 300)
    cmd = svc.outgoing(d.id)[0]
    ack = proc.on_control(control_topic("der_ctrl", d.id), cmd)
    gid, grant = svc.grant(d.id, "P_ACTIVE_W", -5000, 5000, 12, 3600)
    sp = svc.setpoint(d.id, gid, 2500, 30)
    zm = ZoneManager(svc)
    zm.create("zone-7")
    zm.add_member("zone-7", d.id)
    zk = zm.distribute("zone-7")[d.id]
    [ev] = zm.publish("zone-7", b"e" * 64, 300).values()
    # DR event (M7), by hand: enc of 7 fields = 7×4 prefix + 0x04(1) + "zone-7"(6) + "chacha20poly1305"(16)
    # + epoch(8) + bseq(8) + nonce(12) = 79, plus ct = enc[event 64, exp 8, σ 3309] (3×4 + 3381) + tag 16 = 3409
    assert 7 * 4 + 1 + 6 + 16 + 8 + 8 + 12 + (3 * 4 + 64 + 8 + 3309) + 16 == 3488
    assert (len(cmd), len(grant), len(sp), len(zk), len(ack), len(ev)) == (3466, 3477, 97, 138, 83, 3488)
