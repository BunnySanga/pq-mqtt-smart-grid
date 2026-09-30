"""Authenticated utility_time must also be fresh (DR-053; audit M-2).

A device keeps retransmitting its outstanding CH/RH identically (QoS 1, D-3) and takes its clock from the utility_time
in the SH/RS that answers it (§9.4, I-17). Before DR-053 the same CH could be resent for ever, so a broker could hold
back an authentic SH for hours and deliver it later: the device set its clock hours back (audit repro), and every
expiry it checks on that clock (DR events, FOTA activate_at, the chain end) was shifted. Now a hello is resent, and a
reply to it accepted, only for the attempt lifetime max(DUP_WINDOW, PENDING_TTL), the longest the utility itself can
still answer it; the error such a delayed reply can cause is bounded by that lifetime. Everything below uses the
production endpoints; the property asserted is always the device's time or a decision taken on it."""
import pytest

from conftest import World, make_policy
from test_fota import C2, MP, build, station  # noqa: F401  (fixture)
from pqgrid.commands import CommandProcessor, CommandService, ZoneManager
from pqgrid.e2e.envelopes import control_topic
from pqgrid.e2e.handshake import DeviceEndpoint
from pqgrid.errors import EnvelopeError, HandshakeError
from pqgrid.fota.artifact import POLICY
from pqgrid.fota.installer import FotaFlash, Installer
from pqgrid.persistence.device import DeviceFlash
from pqgrid.persistence.flash import FlashSim, RecordStore
from pqgrid.policy import encode_policy
from pqgrid.registry import DeviceRecord
from pqgrid.suite.hkem import HybridKeyPair
from pqgrid.suite.sig import mldsa_public_bytes

M1, D1, CD = b"meter-0001", b"der-0001", b"c2-0001"
SIX_HOURS = 6 * 3600


def test_the_lifetime_is_the_longest_the_utility_can_answer(world: World):
    d = world.device(M1, "smart_meter")                                  # dup_window 120 s, pending_ttl 60 s
    assert d.attempt_lifetime() == 120


# --------------------------------------------------------------------------------------------- A, B: withheld SH
def test_a_server_hello_withheld_for_six_hours_never_moves_the_clock_back(world: World):
    d = world.device(M1, "smart_meter")
    ch = d.client_hello()
    sh = world.utility.on_client_hello(M1, ch)                           # authentic; the broker holds it back
    retransmitted = []
    for _ in range(12):                                                  # the device keeps retrying meanwhile
        world.t += 30 * 60
        retransmitted.append(d.client_hello())
    assert retransmitted[0] != ch                                        # after the lifetime: a NEW hello
    with pytest.raises(HandshakeError):
        d.on_server_hello(sh)
    assert d.now() == int(world.t) and d.session is None                 # no rollback, no session


@pytest.mark.parametrize("delay, accepted", [(0, True), (120, True), (121, False), (SIX_HOURS, False)])
def test_a_reply_is_accepted_only_within_the_attempt_lifetime(world: World, delay, accepted):
    d = world.device(M1, "smart_meter")
    sh = world.utility.on_client_hello(M1, d.client_hello())
    world.t += delay                                                     # no retransmission in between
    if accepted:
        d.on_server_hello(sh)
        assert int(world.t) - d.now() == delay <= d.attempt_lifetime()   # the error is bounded by the lifetime
    else:
        with pytest.raises(HandshakeError, match="stale server hello"):
            d.on_server_hello(sh)
        assert d.now() == int(world.t)


def test_an_authentic_fresh_reply_still_moves_a_lagging_clock_forward(world: World):
    d = world.device(M1, "smart_meter", clock=lambda: world.t - 5000)    # RTC 5,000 s behind
    world.full(d)
    assert d.now() == int(world.t)


# ------------------------------------------------------------------------------- E: DR-event expiry on that clock
def test_an_expired_dr_event_stays_expired_whatever_reply_the_broker_withheld(world: World):
    d = world.device(D1, "der_ctrl")
    world.full(d)
    svc = CommandService(world.utility, world.cmd_sk)
    zm = ZoneManager(svc)
    zm.create("f7")
    zm.add_member("f7", D1)
    proc = CommandProcessor(d, lambda c: None, targets=set())
    for env in zm.zonekeys_for(D1):
        proc.on_control(control_topic("der_ctrl", D1), env)
    (topic, event), = zm.publish("f7", b"SHED 20% 14:00-15:00", 600).items()   # held back by the broker too
    sh = world.utility.on_client_hello(D1, d.client_hello())            # a new attempt; its SH is held back
    world.t += 3600                                                      # the event expired 50 minutes ago
    with pytest.raises(HandshakeError):
        d.on_server_hello(sh)                                            # the stale SH cannot roll the clock back …
    with pytest.raises(EnvelopeError, match="broadcast expired"):
        proc.zones.open(topic, event)                                    # … so the late event is still expired


# ------------------------------------------------------------------------------------ F: FOTA activate_at
def test_a_staged_policy_activates_on_time_whatever_reply_the_broker_withheld(world: World, station):
    d = world.device(CD, "c2_meter")
    world.full(d)
    clock = lambda: world.t                                              # noqa: E731
    inst = Installer(station.anchors, C2, MP, FotaFlash(64 * 1024), RecordStore(FlashSim(), clock),
                     RecordStore(FlashSim(), clock), clock=d.now)        # the device's (authenticated) time
    v2 = make_policy(world.u_static.pk, mldsa_public_bytes(world.cmd_sk), version=2, activate_at=int(world.t) + 600)
    art = build(station, POLICY, 2, encode_policy(v2), activate_at=v2.activate_at)
    for part in art.parts:
        inst.on_part(part)
    for chunk in art.chunks:
        inst.on_chunk(chunk)
    sh = world.utility.on_client_hello(CD, d.client_hello())            # held back while activate_at passes
    world.t += 3600
    with pytest.raises(HandshakeError):
        d.on_server_hello(sh)
    assert inst.activate_policy(world.policy).info() == v2.info()        # due on the device's (true) time


# ----------------------------------------------------------------------- G, H: resume, ticket and retransmission
def test_rh_is_resent_identically_only_within_the_lifetime_and_a_stale_rs_is_refused(world: World):
    d = world.device(M1, "smart_meter")                                  # PSK class
    world.full(d)
    rh = d.resume_hello()
    rs = world.utility.on_resume_hello(M1, rh)                           # consumed the ticket; RS held back
    world.t += 100
    assert d.resume_hello() == rh                                        # within the lifetime: identical (S5)
    world.t += SIX_HOURS
    with pytest.raises(HandshakeError, match="stale resume reply"):
        d.on_resume_server(rs)
    assert d.now() == int(world.t) and d.ticket is None and not d.can_resume()   # the ticket is gone: full
    world.full(d)                                                        # handshake, no false clone alarm
    assert d.confirmed


def test_a_stale_final_message_is_refused(world: World):
    d = world.device(M1, "smart_meter")
    d.on_server_hello(world.utility.on_client_hello(M1, d.client_hello()))
    nt = world.utility.on_finished(M1, d.finished()).final
    world.t += SIX_HOURS
    with pytest.raises(HandshakeError, match="stale final message"):
        d.on_final(nt)
    assert not d.confirmed and d.ticket is None and d.session is None


# ----------------------------------------------------------------------- D, I: reboot and no persistent rollback
def test_after_a_reboot_the_stored_rh_is_resent_only_while_it_can_still_be_answered(world: World):
    kp, fs = HybridKeyPair.generate(), FlashSim()
    world.registry.add(DeviceRecord(M1, "smart_meter", kp.pk))

    def boot() -> DeviceEndpoint:                                        # power-on: only the flash survives
        return DeviceEndpoint(M1, "smart_meter", world.policy, 1, kp, clock=lambda: world.t,
                              flash=DeviceFlash(fs, clock=lambda: world.t))
    d = boot()
    world.full(d)
    floor = d.flash.time_floor()
    rh = d.resume_hello()
    world.t += 60
    assert boot().resume_hello() == rh                                   # reboot within the lifetime: identical (S5)
    rs = world.utility.on_resume_hello(M1, rh)                           # its RS is held back
    world.t += SIX_HOURS
    late = boot()                                                        # reboot long after: RH and ticket
    assert late.ticket is None and not late.can_resume()                 # dropped (its age is too great)
    with pytest.raises(HandshakeError):
        late.on_resume_server(rs)
    assert late.now() == int(world.t) and late.flash.time_floor() >= floor   # no rollback, in RAM or in flash
    world.full(late)
    assert late.confirmed
