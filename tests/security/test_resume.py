"""PASR resume: the 9 checks and their attacks (P1–P9), duplicates and retransmission (E-P1, S5), clone
detection (E-P5), downgrade, binder coverage, single use, chain cap, DF-carries-data on resume
(Master §9.4, §9.8, §14; §24.2; IMPLEMENTATION-ROADMAP §8)."""
import os

import pytest

from conftest import World, make_policy, replace_class
from pqgrid.e2e import keys
from pqgrid.e2e.envelopes import alert_topic
from pqgrid.e2e.handshake import UnknownSessionError, UtilityEndpoint
from pqgrid.errors import HandshakeError, TicketError, TicketReusedError
from pqgrid.policy.model import ResumeMode
from pqgrid.registry import DeviceRecord
from pqgrid.suite.hkem import HybridKeyPair
from pqgrid.suite.kdf import h, mac
from pqgrid.suite.sig import mldsa_public_bytes
from pqgrid.wire import dec, enc, u64

M1, M2, D1 = b"meter-0001", b"meter-0002", b"der-0001"
DAY = 86400


def ready(world: World, did=M1, dclass="smart_meter"):
    """A device that completed a full handshake and holds a ticket."""
    d = world.device(did, dclass)
    world.full(d)
    assert d.ticket is not None
    return d


def forge_rh(world: World, d, psk=None, **over) -> bytes:
    """An RH built field by field. With the device's psk the binder is valid (the genuine device, or a clone
    holding its flash); with another psk it is an attacker holding only the blob."""
    t = d.ticket
    f = dict(tag=b"RH", blob=t.blob, n_d=os.urandom(32), mode=t.mode.value.encode(),
             pk_e=HybridKeyPair.generate().pk if t.mode is ResumeMode.PSK_KEM else b"", id=d.id,
             pinfo=d.policy.info(), fw=u64(d.fw), dtime=u64(int(world.t)))
    f.update(over)
    fields = list(f.values())
    return enc(fields + [mac(keys.binder_key(psk or t.psk), h(*fields))])


def with_policy(world: World, policy) -> None:
    world.policy = policy
    world.utility = UtilityEndpoint(policy, world.u_static, world.registry, clock=lambda: world.t,
                                    tickets=world.tickets)


# ------------------------------------------------------------------------------------------------ success
@pytest.mark.parametrize("did,dclass", [(M1, "smart_meter"), (D1, "der_ctrl"), (b"c2-0001", "c2_meter")])
def test_resume_psk_and_psk_kem(world: World, did, dclass):
    d = ready(world, did, dclass)
    old_sid, old_ticket, chain = d.session.sid, d.ticket, d.session.chain_expires
    world.t += 3600
    rs = world.utility.on_resume_hello(d.id, d.resume_hello())
    d.on_resume_server(rs)
    assert d.ticket is None                                           # single use: dropped at RS (§14.7)
    res = world.utility.on_finished(d.id, d.finished())
    d.on_final(res.final)
    s_u = world.utility.sessions[d.session.sid]
    assert s_u.k_master == d.session.k_master and d.confirmed
    assert old_sid not in world.utility.sessions                      # one live session per device
    assert d.session.chain_expires == s_u.chain_expires == chain      # same chain expiry (§9.4)
    assert d.ticket is not None and d.ticket.ticket_id != old_ticket.ticket_id
    assert d.session.resume_mode is world.policy.profile(dclass).resume


def test_psk_kem_resume_has_a_fresh_kem_and_psk_does_not(world: World):
    d, m = ready(world, D1, "der_ctrl"), ready(world, M1, "smart_meter")
    rh_kem, rh_psk = d.resume_hello(), m.resume_hello()
    assert len(dec(rh_kem, 10)[4]) == 1216 and dec(rh_psk, 10)[4] == b""
    assert len(dec(world.utility.on_resume_hello(D1, rh_kem), 6)[2]) == 1120
    assert dec(world.utility.on_resume_hello(M1, rh_psk), 6)[2] == b""


def test_resume_df_carries_alerts_delivered_once(world: World):
    d = ready(world)
    world.t += 60
    topic = alert_topic("smart_meter", M1)
    res, acked = world.resume(d, [(topic, os.urandom(16), b"OUTAGE_RESTORED")])
    assert [p for _, p, _ in res.alerts] == [b"OUTAGE_RESTORED"] and acked == [1]


def test_alert_resent_after_lost_ack_is_recognised_as_duplicate(world: World):
    """§9.8: the outbox resends unacknowledged alerts inside the resume DF; dedup by alert_id."""
    d = ready(world)
    topic, aid = alert_topic("smart_meter", M1), os.urandom(16)
    world.utility.open_alert(topic, d.seal_alert(topic, aid, b"TAMPER"))          # its ACK is lost
    world.t += 60
    res, _ = world.resume(d, [(topic, aid, b"TAMPER")])                          # device reboots, resumes
    assert res.alerts == [(aid, b"TAMPER", True)]


def test_class_without_resumption_gets_fin_and_no_ticket(world: World):
    with_policy(world, make_policy(world.u_static.pk, mldsa_public_bytes(world.cmd_sk),
                                   classes=replace_class(world.policy, "smart_meter", resume=ResumeMode.NONE)))
    d = world.device(M1, "smart_meter")
    res, _ = world.full(d)
    assert dec(res.final, 3)[0] == b"FIN" and d.ticket is None and not d.can_resume()
    with pytest.raises(HandshakeError, match="no usable ticket"):
        d.resume_hello()


def test_chain_cap_forces_a_full_handshake_after_7_days(world: World):
    d = ready(world)
    chain = d.session.chain_expires
    for _ in range(7):                                                # daily resumes keep the original chain
        world.t += DAY - 1
        world.resume(d)
        assert d.session.chain_expires == chain
    assert d.ticket.expires_at == chain < world.t + DAY               # the last ticket is cut to the chain
    world.t = chain
    with pytest.raises(TicketError, match="ticket expired"):          # P4 (chain)
        world.utility.on_resume_hello(M1, d.resume_hello())


def test_device_with_reset_clock_still_resumes(world: World):
    """Device time never gates a connection (§8.8); the resume reply sets the clock (§8.9)."""
    d = ready(world)
    d.clock, d.offset = (lambda: 1000.0), 0
    world.resume(d)
    assert abs(d.now() - world.t) < 2


# --------------------------------------------------------------------------------------------- P1–P9
def test_P1_rh_replayed_after_duplicate_window_and_clone_rh(world: World):
    d = ready(world)
    rh = d.resume_hello()
    world.resume(d)
    world.t += world.policy.profile("smart_meter").dup_window_s + 1
    with pytest.raises(TicketReusedError, match="ticket already used"):
        world.utility.on_resume_hello(M1, rh)                         # replayed bytes
    d2 = ready(world, M2)
    t2 = d2.ticket
    world.resume(d2)
    d2.ticket = t2                                                    # clone holding the consumed ticket
    with pytest.raises(TicketReusedError):
        world.utility.on_resume_hello(M2, d2.resume_hello())          # fresh RH, same ticket


def test_P2_stolen_blob_without_psk_cannot_burn_the_ticket(world: World):
    d = ready(world)
    with pytest.raises(TicketError, match="binder invalid"):
        world.utility.on_resume_hello(M1, forge_rh(world, d, psk=os.urandom(32)))
    world.resume(d)                                                   # the genuine ticket survived


def test_P3_ticket_on_another_devices_channel(world: World):
    d = ready(world)
    ready(world, M2)
    rh = d.resume_hello()
    with pytest.raises(TicketError, match="identity mismatch"):
        world.utility.on_resume_hello(M2, rh)
    with pytest.raises(TicketError, match="identity mismatch"):
        world.utility.on_resume_hello(M1, forge_rh(world, d, id=M2))


def test_P4_expired_ticket(world: World):
    d = ready(world)
    world.t += world.policy.profile("smart_meter").ticket_lifetime_s
    with pytest.raises(TicketError, match="ticket expired"):
        world.utility.on_resume_hello(M1, d.resume_hello())


def test_P5_ticket_after_policy_change(world: World):
    d = ready(world)
    new = make_policy(world.u_static.pk, mldsa_public_bytes(world.cmd_sk), version=2)
    with_policy(world, new)
    with pytest.raises(TicketError, match="different policy"):
        world.utility.on_resume_hello(M1, d.resume_hello())          # device still on the old policy
    d.policy = new
    assert not d.can_resume()                                        # after installing it: full handshake


def test_P6_mode_downgrade_is_refused(world: World):
    d = ready(world, D1, "der_ctrl")                                 # policy: PSK_KEM (unicast control)
    with pytest.raises(TicketError, match="resume mode does not match policy"):
        world.utility.on_resume_hello(D1, forge_rh(world, d, psk=os.urandom(32), mode=b"PSK", pk_e=b""))
    with pytest.raises(TicketError, match="requires a fresh ephemeral key"):
        world.utility.on_resume_hello(D1, forge_rh(world, d, psk=os.urandom(32), pk_e=b""))
    m = ready(world, M1, "smart_meter")
    with pytest.raises(TicketError, match="must not carry a key"):
        world.utility.on_resume_hello(M1, forge_rh(world, m, pk_e=HybridKeyPair.generate().pk))
    world.resume(d)                                                  # none of these consumed the ticket


def test_P7_ticket_after_firmware_update(world: World):
    d = ready(world)
    with pytest.raises(TicketError, match="different firmware"):
        world.utility.on_resume_hello(M1, forge_rh(world, d, fw=u64(d.fw + 1)))
    d.fw += 1
    assert not d.can_resume()


def test_P8_ticket_under_a_retired_stek(world: World):
    d = ready(world)
    world.t += 8 * DAY
    with pytest.raises(TicketError, match="ticket key retired"):
        world.utility.on_resume_hello(M1, d.resume_hello())


def test_P9_revoked_device(world: World):
    d = ready(world)
    world.registry.revoke(M1)
    with pytest.raises(HandshakeError, match="unknown or revoked"):
        world.utility.on_resume_hello(M1, d.resume_hello())


def test_reclassified_device_must_do_a_full_handshake(world: World):
    d = ready(world)
    world.registry.add(DeviceRecord(M1, "c2_meter", d.static.pk))   # moved to another class (E22)
    with pytest.raises(TicketError, match="class does not match the registry"):
        world.utility.on_resume_hello(M1, d.resume_hello())


# ------------------------------------------------------------------------------------------ binder / RS
@pytest.mark.parametrize("field", [2, 4, 8])                        # n_D, pk_e′, device_time
def test_binder_covers_fields_no_earlier_check_reads(world: World, field):
    d = ready(world, D1, "der_ctrl")
    f = dec(d.resume_hello(), 10)
    b = bytearray(f[field])
    b[len(b) // 2] ^= 1
    f[field] = bytes(b)
    with pytest.raises(TicketError, match="binder invalid"):
        world.utility.on_resume_hello(D1, enc(f))
    d._rh = None
    world.resume(d)                                                 # the ticket was not consumed


@pytest.mark.parametrize("field", [1, 2, 3, 4, 5])                  # n_U, ct_e′, utility_time, chain, MAC_U
def test_tampered_resume_reply_is_refused_and_the_genuine_one_still_works(world: World, field):
    d = ready(world, D1, "der_ctrl")
    rs = world.utility.on_resume_hello(D1, d.resume_hello())
    f = dec(rs, 6)
    b = bytearray(f[field])
    b[len(b) // 2] ^= 1
    f[field] = bytes(b)
    with pytest.raises(HandshakeError, match="authentication|key confirmation"):
        d.on_resume_server(enc(f))
    d.on_resume_server(rs)
    d.on_final(world.utility.on_finished(D1, d.finished()).final)
    assert d.confirmed


def test_psk_resume_reply_with_a_kem_ciphertext_is_refused(world: World):
    d = ready(world)
    tag, n_u, _, ut, ch, mu = dec(world.utility.on_resume_hello(M1, d.resume_hello()), 6)
    with pytest.raises(HandshakeError, match="resume reply failed authentication"):
        d.on_resume_server(enc([tag, n_u, os.urandom(1120), ut, ch, mu]))


# ------------------------------------------------------------------------- duplicates, S5, E-P1, E-P5
def test_EP1_duplicate_rh_gets_identical_rs_and_consumes_once(world: World):
    d = ready(world)
    rh = d.resume_hello()
    assert world.utility.on_resume_hello(M1, rh) == world.utility.on_resume_hello(M1, rh)
    assert len(world.tickets.used) == 1


def test_S5_identical_rh_is_resent_and_completes_but_a_rebuilt_one_is_refused(world: World):
    d = ready(world)
    rh = d.resume_hello()
    world.utility.on_resume_hello(M1, rh)                            # processed; the RS is lost
    assert d.resume_hello() == rh                                    # the device resends identical bytes
    d.on_resume_server(world.utility.on_resume_hello(M1, rh))        # identical RS from the cache
    d.on_final(world.utility.on_finished(M1, d.finished()).final)
    assert d.confirmed

    e = ready(world, M2)
    world.utility.on_resume_hello(M2, e.resume_hello())              # processed; the RS is lost
    e._rh = None                                                     # the stored RH did not survive
    with pytest.raises(TicketReusedError):
        world.utility.on_resume_hello(M2, e.resume_hello())          # rebuilt → full handshake (by design)


def test_EP5_clone_resumes_first_then_genuine_full_handshake_evicts_it(world: World):
    d = ready(world)
    clone = world.device(M1, "smart_meter", register=False)
    clone.ticket = d.ticket                                          # clone read the device's flash
    world.resume(clone)
    with pytest.raises(TicketReusedError):                           # the genuine device sees the alarm
        world.utility.on_resume_hello(M1, d.resume_hello())
    d._rh = None
    world.full(d)                                                    # full handshake: one session per device
    topic = alert_topic("smart_meter", M1)
    with pytest.raises(UnknownSessionError):
        world.utility.open_alert(topic, clone.seal_alert(topic, os.urandom(16), b"spoof"))


def test_RISK_clone_with_flash_keeps_resuming_until_its_chain_expires(world: World):
    """Residual risk, shown on purpose (IMPLEMENTATION-ROADMAP §8.4): a clone holding the device's flash got a
    ticket of its own from NT, so it can resume again after the genuine device's full handshake, until the
    chain expires. The same flash holds the static E2E key, so this is device compromise (Master §2.4)."""
    d = ready(world)
    clone = world.device(M1, "smart_meter", register=False)
    clone.ticket = d.ticket
    world.resume(clone)
    world.full(d)
    world.resume(clone)
    assert world.utility.sessions[clone.session.sid].device_id == M1
    world.t = clone.session.chain_expires
    with pytest.raises(TicketError, match="ticket expired"):
        world.utility.on_resume_hello(M1, clone.resume_hello())


def test_duplicate_server_replies_are_refused_so_counters_never_restart(world: World):
    d = ready(world)
    rs = world.utility.on_resume_hello(M1, d.resume_hello())
    s = d.on_resume_server(rs)
    with pytest.raises(HandshakeError, match="no resumption in progress"):
        d.on_resume_server(rs)
    assert d.session is s
    e = world.device(M2, "smart_meter")
    sh = world.utility.on_client_hello(M2, e.client_hello())
    s = e.on_server_hello(sh)
    with pytest.raises(HandshakeError, match="no handshake in progress"):
        e.on_server_hello(sh)
    assert e.session is s


def test_lost_nt_identical_df_gets_identical_nt(world: World):
    d = ready(world)
    d.on_resume_server(world.utility.on_resume_hello(M1, d.resume_hello()))
    df = d.finished()
    first = world.utility.on_finished(M1, df)                        # NT lost
    again = world.utility.on_finished(M1, d.finished())
    assert again.final == first.final and again.replayed
    d.on_final(again.final)
    assert d.ticket is not None and len(world.tickets.used) == 1


def test_tampered_nt_stores_no_ticket_and_the_genuine_nt_still_works(world: World):
    d = ready(world)
    d.on_resume_server(world.utility.on_resume_hello(M1, d.resume_hello()))
    nt = world.utility.on_finished(M1, d.finished()).final
    f = dec(nt, 4)
    f[2] = f[2][:-1] + bytes([f[2][-1] ^ 1])
    with pytest.raises(HandshakeError, match="final message failed authentication"):
        d.on_final(enc(f))
    assert d.ticket is None and not d.confirmed
    d.on_final(nt)
    assert d.ticket is not None


# ------------------------------------------------------------------------------------ half-open state
def test_one_half_open_per_device_across_full_and_resume(world: World):
    d = ready(world)
    d.on_resume_server(world.utility.on_resume_hello(M1, d.resume_hello()))
    df_resume = d.finished()
    d2 = world.device(M1, "smart_meter", register=False)
    d2.static = d.static
    world.utility.on_client_hello(M1, d2.client_hello())             # a CH replaces the pending resume
    with pytest.raises(HandshakeError, match="device key confirmation failed"):
        world.utility.on_finished(M1, df_resume)


def test_pending_resume_expires(world: World):
    d = ready(world)
    d.on_resume_server(world.utility.on_resume_hello(M1, d.resume_hello()))
    world.t += world.policy.profile("smart_meter").pending_ttl_s + 1
    with pytest.raises(HandshakeError, match="no pending handshake"):
        world.utility.on_finished(M1, d.finished())


# ------------------------------------------------------------------------ direct checks and wire format
def test_redeem_itself_refuses_revoked_devices(world: World):
    """Check 4 inside TicketIssuer.redeem (the endpoint also refuses earlier: E23; defence in depth)."""
    d = ready(world)
    world.registry.revoke(M1)
    f = dec(d.resume_hello(), 10)
    with pytest.raises(TicketError, match="device unknown or revoked"):
        world.tickets.redeem(blob=f[1], topic_id=M1, claimed_id=M1, policy_info=f[6], fw_version=d.fw,
                             mode=f[3], pk_e=f[4], binder=f[9], binder_input=h(*f[:9]),
                             registry=world.registry, policy=world.policy, now=int(world.t))


def test_nt_wire_format(world: World):
    """Format conformance (IMPLEMENTATION-ROADMAP §8.2, E18): NT = "NT", nonce, AEAD_class(K_nt,
    enc[ticket_id, blob, u64 expires], AAD = H("NT", sid)), ack_bundle."""
    from pqgrid.suite import aead
    from pqgrid.errors import CryptoError
    d = world.device(M1, "smart_meter")
    res, _ = world.full(d)
    s = d.session
    tag, nonce, ct, acks = dec(res.final, 4)
    assert tag == b"NT" and len(nonce) == 12 and acks == b""
    tid, blob, exp = dec(aead.open_(s.aead, keys.new_ticket_key(s.k_master), nonce, ct, h(b"NT", s.sid)), 3)
    assert tid == d.ticket.ticket_id and blob == d.ticket.blob
    with pytest.raises(CryptoError):
        aead.open_(s.aead, keys.new_ticket_key(s.k_master), nonce, ct, h(b"NT"))
