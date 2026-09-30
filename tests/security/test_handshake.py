"""E2E establishment: success, downgrade and authentication attacks, DR-044 bundle binding, duplicates,
half-open limits, one live session per device (Master §9.4–§9.6; A1–A4; I-4, I-18, I-19)."""
import os

import pytest

from conftest import World, make_policy
from pqgrid.e2e.envelopes import alert_topic
from pqgrid.e2e.handshake import UnknownSessionError
from pqgrid.errors import HandshakeError
from pqgrid.registry import DeviceRecord
from pqgrid.suite.sig import mldsa_public_bytes
from pqgrid.wire import dec, enc, enc_list

M1, D1 = b"meter-0001", b"der-0001"


def flip(buf: bytes, field: int, n: int) -> bytes:
    f = dec(buf, n)
    b = bytearray(f[field])
    b[len(b) // 2] ^= 1
    f[field] = bytes(b)
    return enc(f)


@pytest.mark.parametrize("did,dclass", [(M1, "smart_meter"), (D1, "der_ctrl"), (b"c2-0001", "c2_meter")])
def test_full_handshake_both_aeads(world: World, did, dclass):
    d = world.device(did, dclass)
    res, acked = world.full(d)
    s_u = world.utility.sessions[res.session.sid]
    assert s_u.k_master == d.session.k_master and s_u.sid == d.session.sid
    assert d.confirmed and acked == [] and res.alerts == []
    assert d.session.aead is world.policy.profile(dclass).aead


def test_device_clock_comes_from_authenticated_utility_time(world: World):
    d = world.device(M1, "smart_meter", clock=lambda: 1000.0)              # RTC reset to 1970
    world.full(d)
    assert abs(d.now() - world.t) < 2


# ---------------------------------------------------------------------------------------------- A1–A4
def test_A1_broker_tampers_client_hello(world: World):
    d = world.device(M1, "smart_meter")
    with pytest.raises(HandshakeError, match="client hello failed authentication"):
        world.utility.on_client_hello(M1, flip(d.client_hello(), 5, 6))


def test_A2_broker_tampers_server_hello(world: World):
    d = world.device(M1, "smart_meter")
    sh = world.utility.on_client_hello(M1, d.client_hello())
    with pytest.raises(HandshakeError, match="server hello failed authentication"):
        d.on_server_hello(flip(sh, 4, 6))


def test_A2b_tampered_utility_confirmation(world: World):
    d = world.device(M1, "smart_meter")
    sh = world.utility.on_client_hello(M1, d.client_hello())
    with pytest.raises(HandshakeError, match="key confirmation"):
        d.on_server_hello(flip(sh, 5, 6))


def test_A3_client_hello_replayed_on_another_topic(world: World):
    world.device(b"meter-0002", "smart_meter")
    d = world.device(M1, "smart_meter")
    with pytest.raises(HandshakeError, match="identity does not match"):
        world.utility.on_client_hello(b"meter-0002", d.client_hello())


def test_client_hello_claiming_another_class_than_the_registry_is_refused(world: World):
    """The registry fixes a device's class (§4.4). A CH that claims another class with the same AEAD (so its body
    opens) is refused: no half-open state and no reply under either class's profile (mutation-found gap)."""
    d = world.device(b"c2-0001", "der_ctrl", register=False)               # der_ctrl and c2_meter: both ChaCha
    world.registry.add(DeviceRecord(b"c2-0001", "c2_meter", d.static.pk))
    with pytest.raises(HandshakeError, match="device class mismatch"):
        world.utility.on_client_hello(d.id, d.client_hello())
    assert b"c2-0001" not in world.utility._pending


def test_A4_device_on_old_policy(world: World):
    old = make_policy(world.u_static.pk, mldsa_public_bytes(world.cmd_sk), version=1)
    world.utility.policy = make_policy(world.u_static.pk, mldsa_public_bytes(world.cmd_sk), version=2)
    d = world.device(M1, "smart_meter", policy=old)
    with pytest.raises(HandshakeError, match="POLICY_INFO mismatch"):
        world.utility.on_client_hello(M1, d.client_hello())


def test_unknown_and_revoked_devices(world: World):
    stranger = world.device(b"meter-0404", "smart_meter", register=False)
    with pytest.raises(HandshakeError, match="unknown or revoked"):
        world.utility.on_client_hello(stranger.id, stranger.client_hello())
    d = world.device(M1, "smart_meter")
    world.registry.revoke(M1)
    with pytest.raises(HandshakeError, match="unknown or revoked"):
        world.utility.on_client_hello(M1, d.client_hello())


def test_utility_impostor_cannot_complete(world: World):
    """Someone without the utility's static key answers the CH: the device refuses (only U can open ct_U)."""
    from pqgrid.e2e.handshake import UtilityEndpoint
    from pqgrid.suite.hkem import HybridKeyPair
    d = world.device(M1, "smart_meter")
    impostor = UtilityEndpoint(world.policy, HybridKeyPair.generate(), world.registry, clock=lambda: world.t)
    with pytest.raises(HandshakeError):
        impostor.on_client_hello(M1, d.client_hello())


# ------------------------------------------------------------------------------ DR-044 / finished carries data
def _to_df(world: World, d, alerts):
    sh = world.utility.on_client_hello(d.id, d.client_hello())
    d.on_server_hello(sh)
    return d.finished(alerts)


def _alerts(d, n):
    return [(alert_topic(d.dclass, d.id), os.urandom(16), f"alert-{i}".encode()) for i in range(n)]


def test_finished_carries_alerts_delivered_once(world: World):
    d = world.device(M1, "smart_meter")
    queued = _alerts(d, 3)
    res, acked = world.full(d, queued)
    assert [p for _, p, _ in res.alerts] == [b"alert-0", b"alert-1", b"alert-2"]
    assert acked == [1, 2, 3] and res.rejected == 0


@pytest.mark.parametrize("mutate", ["strip", "append", "reorder", "truncate", "empty"])
def test_bundle_tampering_fails_key_confirmation(world: World, mutate):
    d = world.device(M1, "smart_meter")
    df = _to_df(world, d, _alerts(d, 3))
    tag, mac_d, bundle = dec(df, 3)
    envs = dec(bundle, 4)[1:]
    if mutate == "strip":
        bundle = enc_list(envs[:2], 64)
    elif mutate == "append":
        bundle = enc_list(envs + [envs[0]], 64)
    elif mutate == "reorder":
        bundle = enc_list([envs[1], envs[0], envs[2]], 64)
    elif mutate == "truncate":
        bundle = bundle[:-5]
    else:
        bundle = b""
    with pytest.raises(HandshakeError, match="device key confirmation failed"):
        world.utility.on_finished(M1, enc([tag, mac_d, bundle]))
    res = world.utility.on_finished(M1, df)                 # the genuine DF still completes
    assert len(res.alerts) == 3


# ------------------------------------------------------------------------------------ duplicates (I-18)
def test_duplicate_client_hello_gets_identical_server_hello(world: World):
    d = world.device(M1, "smart_meter")
    ch = d.client_hello()
    assert d.client_hello() == ch                            # the device retransmits identical bytes
    assert world.utility.on_client_hello(M1, ch) == world.utility.on_client_hello(M1, ch)


def test_duplicate_finished_is_idempotent_and_does_not_redeliver(world: World):
    d = world.device(M1, "smart_meter")
    df = _to_df(world, d, _alerts(d, 2))
    assert d.finished() == df                                # identical retransmission
    first = world.utility.on_finished(M1, df)
    again = world.utility.on_finished(M1, df)
    assert again.final == first.final and again.replayed and again.alerts == []
    assert len(first.alerts) == 2


def test_lost_final_resend_completes(world: World):
    d = world.device(M1, "smart_meter")
    df = _to_df(world, d, _alerts(d, 1))
    world.utility.on_finished(M1, df)                         # FIN lost on the way back
    fin = world.utility.on_finished(M1, d.finished()).final  # device resends the identical DF
    assert d.on_final(fin) == [1] and d.confirmed


# ------------------------------------------------------------------------- half-open and session limits
def test_one_half_open_per_device(world: World):
    d = world.device(M1, "smart_meter")
    df_old = _to_df(world, d, [])
    d2 = world.device(M1, "smart_meter", register=False)     # same identity, new attempt (e.g. after reboot)
    d2.static = d.static
    world.utility.on_client_hello(M1, d2.client_hello())    # replaces the half-open state
    with pytest.raises(HandshakeError):
        world.utility.on_finished(M1, df_old)


def test_pending_state_expires(world: World):
    d = world.device(M1, "smart_meter")
    df = _to_df(world, d, [])
    world.t += world.policy.profile("smart_meter").pending_ttl_s + 1
    with pytest.raises(HandshakeError, match="no pending handshake"):
        world.utility.on_finished(M1, df)


def test_pending_expiry_is_exact_per_class_even_behind_a_longer_ttl(world: World):
    """der_ctrl gets a 600 s pending TTL and starts first; meter's 60 s entry sits behind it in the queue."""
    import dataclasses
    from pqgrid.e2e.handshake import UtilityEndpoint
    from conftest import replace_class
    policy = make_policy(world.u_static.pk, mldsa_public_bytes(world.cmd_sk),
                         classes=replace_class(world.policy, "der_ctrl", pending_ttl_s=600))
    world.policy = policy
    world.utility = UtilityEndpoint(policy, world.u_static, world.registry, clock=lambda: world.t)
    der, meter = world.device(D1, "der_ctrl"), world.device(M1, "smart_meter")
    df_der, df_meter = _to_df(world, der, []), _to_df(world, meter, [])
    world.t += 61
    with pytest.raises(HandshakeError, match="no pending handshake"):
        world.utility.on_finished(M1, df_meter)             # expired, although not at the queue front
    assert world.utility.on_finished(D1, df_der).session.device_id == D1
    assert dataclasses.is_dataclass(world.utility.sessions[der.session.sid])


def test_many_devices_pending_are_bounded_by_expiry(world: World):
    devs = [world.device(f"meter-{i:04d}".encode(), "smart_meter") for i in range(50)]
    for d in devs:
        world.utility.on_client_hello(d.id, d.client_hello())
    assert len(world.utility._pending) == 50
    world.t += 61
    late = world.device(b"meter-9999", "smart_meter")
    world.utility.on_client_hello(late.id, late.client_hello())
    assert list(world.utility._pending) == [late.id]         # the expired 50 were dropped from the front


def test_one_live_session_per_device_and_resync_hint(world: World):
    d = world.device(M1, "smart_meter")
    world.full(d)
    old_sid = d.session.sid
    world.t += 1
    d._ch = None
    world.full(d)
    assert old_sid not in world.utility.sessions and d.session.sid in world.utility.sessions
    stale = enc([b"\x02", old_sid, (1).to_bytes(8, "big"), b"x" * 32])
    with pytest.raises(UnknownSessionError) as e:
        world.utility.open_alert(alert_topic("smart_meter", M1), stale)
    assert dec(e.value.hint, 2) == [b"\x07", old_sid]


# --------------------------------------------------------------- device-side checks (mutation-found gaps)
def _sh_from_the_utility_key(w: World, d, ch: bytes, pinfo: bytes, mode: bytes) -> bytes:
    """A well-formed, fully authenticated SH as a holder of the utility's E2E private key could build it (RISK-2):
    everything verifies, so only the device's own checks against its installed policy can refuse it."""
    from pqgrid.e2e import keys
    from pqgrid.suite import aead, hkem
    from pqgrid.suite.kdf import h
    from pqgrid.wire import u64
    _, pk_e, ct_u, _n_d, _nonce, _ = dec(ch, 6)
    ss_u, (ss_e, ct_e), (ss_d, ct_d) = hkem.decaps(w.u_static, ct_u), hkem.encaps(pk_e), hkem.encaps(d.static.pk)
    n_u, nonce, now = os.urandom(32), os.urandom(12), int(w.t)
    inner = aead.seal(d.profile.aead, keys.k1_key(ss_e, ss_u, ch), nonce,
                      enc([ct_d, pinfo, mode, u64(now + 3600), u64(now)]), h(b"SH", ct_e, n_u))
    th2 = h(ch, b"SH", ct_e, n_u, nonce, inner)
    return enc([b"SH", ct_e, n_u, nonce, inner, keys.mac_u(keys.derive_master(th2, ss_e + ss_u + ss_d).kc_u, th2)])


def test_device_refuses_an_authenticated_server_hello_with_another_policy_or_resume_mode(world: World):
    """§9.4 "check POLICY_INFO_U = installed" and I-20 (the profile is never negotiated): even an SH that fully
    authenticates cannot move the device to another policy, nor downgrade a PSK_KEM class to PSK resumption."""
    d = world.device(D1, "der_ctrl")                                        # PSK_KEM: forward-secret resumption
    ch = d.client_hello()
    bad_policy = _sh_from_the_utility_key(world, d, ch, b"nitk-grid|\x00\x00\x00\x09", b"PSK_KEM")
    with pytest.raises(HandshakeError, match="POLICY_INFO mismatch"):
        d.on_server_hello(bad_policy)
    downgrade = _sh_from_the_utility_key(world, d, ch, world.policy.info(), b"PSK")
    with pytest.raises(HandshakeError, match="resume mode does not match"):
        d.on_server_hello(downgrade)
    assert d.session is None
    d.on_server_hello(_sh_from_the_utility_key(world, d, ch, world.policy.info(), b"PSK_KEM"))   # the control:
    assert d.session is not None                                            # the same SH, honest, is accepted


def test_forged_fin_is_refused_and_the_genuine_one_confirms(world: World):
    """Without a ticket issuer the utility ends the handshake with FIN = HMAC(fin key, sid): a broker cannot
    confirm the session in its place, nor inject ACKs."""
    world.utility.tickets = None
    d = world.device(M1, "smart_meter")
    d.on_server_hello(world.utility.on_client_hello(M1, d.client_hello()))
    fin = world.utility.on_finished(M1, d.finished()).final
    assert dec(fin, 3)[0] == b"FIN"
    with pytest.raises(HandshakeError, match="final message failed authentication"):
        d.on_final(flip(fin, 1, 3))
    assert not d.confirmed
    assert d.on_final(fin) == [] and d.confirmed and d.ticket is None


def test_a_class_that_never_resumes_refuses_a_ticket(world: World):
    """Resume mode NONE (§14): the device never stores a ticket, even one that authenticates under the session."""
    from conftest import replace_class
    from pqgrid.e2e import keys
    from pqgrid.policy import ResumeMode
    from pqgrid.suite import aead
    from pqgrid.suite.kdf import h
    from pqgrid.wire import u64
    world.policy = make_policy(world.u_static.pk, mldsa_public_bytes(world.cmd_sk),
                               classes=replace_class(world.policy, "smart_meter", resume=ResumeMode.NONE))
    world.utility.policy = world.policy
    d = world.device(M1, "smart_meter")
    d.on_server_hello(world.utility.on_client_hello(M1, d.client_hello()))
    res = world.utility.on_finished(M1, d.finished())
    s, nonce = res.session, os.urandom(12)
    nt = enc([b"NT", nonce, aead.seal(s.aead, keys.new_ticket_key(s.k_master), nonce,
                                      enc([os.urandom(16), b"blob", u64(int(world.t) + 60)]), h(b"NT", s.sid)), b""])
    with pytest.raises(HandshakeError, match="unexpected ticket"):
        d.on_final(nt)
    assert d.ticket is None and not d.confirmed
    assert d.on_final(res.final) == [] and d.confirmed and d.ticket is None    # the genuine FIN


def test_alerts_of_a_df_whose_reply_failed_to_persist_arrive_as_new_next_time(world: World, monkeypatch):
    """Authentication succeeded but persistence failed: issuing the NT's ticket fails (a database error while
    storing a new STEK). Nothing in that bundle may be recorded as seen, because the application never received it:
    the device resends the same alerts in its next DF and they must arrive as new, not as duplicates."""
    d = world.device(M1, "smart_meter")
    aid = os.urandom(16)
    alerts = [(alert_topic("smart_meter", M1), aid, b"cover opened")]
    d.on_server_hello(world.utility.on_client_hello(M1, d.client_hello()))

    def broken(*args, **kwargs):
        raise RuntimeError("database is locked")
    monkeypatch.setattr(world.tickets, "issue", broken)
    with pytest.raises(RuntimeError):
        world.utility.on_finished(M1, d.finished(alerts))
    monkeypatch.undo()
    world.t += 1
    res, acked = world.full(d, alerts)                                     # the device's next establishment
    assert res.alerts == [(aid, b"cover opened", False)] and acked == [1]
