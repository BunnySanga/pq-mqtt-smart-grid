"""Remediation M4, M5, M7 (clarifications 4, 5, 6): a LOGICAL zone with one crypto group per AEAD, one logical
event identity (σ, bseq) across groups, the device's highest accepted bseq per logical zone in flash, and the
utility re-sending still-valid events under the CURRENT group key after a member re-establishes. Utility on
SQLite, devices on simulated flash (reboots and restarts are real)."""
import pytest

from conftest import make_policy, replace_class
from test_restart import Plant
from pqgrid.commands.zones import MAX_RETAINED, _parse, event_topic
from pqgrid.e2e.envelopes import control_topic
from pqgrid.errors import EnvelopeError, ReplayError
from pqgrid.suite.aead import AeadAlg
from pqgrid.suite.sig import mldsa_public_bytes
from pqgrid.wire import dec

AES, CC = AeadAlg.AES256GCM, AeadAlg.CHACHA20POLY1305
M1, D1, D2 = b"meter-0001", b"der-0001", b"der-0002"
Z = "f7"


def join(p: Plant, *devs):
    zm = p.node.zones
    if Z not in zm.zones:
        zm.create(Z)
    for dev in devs:
        zm.add_member(Z, dev.did)


def keys(p: Plant, dev):
    """The utility's flush after establishment, first part: the device's zone keys under its session."""
    envs = p.node.zones.zonekeys_for(dev.did)
    assert envs
    for env in envs:
        assert dec(dev.proc.on_control(control_topic(dev.dclass, dev.did), env), 6)[4] == b"OK"


def bseq(env: bytes) -> int:
    return _parse(env)[4]


def epoch(env: bytes) -> int:
    return _parse(env)[3]


def online(p: Plant, *devs):
    for dev in devs:
        p.full(dev)
    join(p, *devs)
    for dev in devs:
        keys(p, dev)


# ======================================================================================================= M7
def test_M7_one_logical_event_is_sealed_once_per_crypto_group(tmp_path):
    p = Plant(tmp_path)
    m, d = p.device(M1, "smart_meter"), p.device(D1, "der_ctrl")              # AES and ChaCha classes
    online(p, m, d)
    zm = p.node.zones
    assert set(zm.zones[Z].groups) == {AES, CC} and zm.members_of(Z, AES) == [M1] and zm.members_of(Z, CC) == [D1]
    pubs = zm.publish(Z, b"SHED 20%", 600)
    ta, tc = event_topic(Z, AES), event_topic(Z, CC)
    assert set(pubs) == {ta, tc}
    ea, ec = pubs[ta], pubs[tc]
    assert ea != ec and bseq(ea) == bseq(ec)                                  # two encryptions, one identity
    assert m.proc.zones.open(ta, ea) == d.proc.zones.open(tc, ec) == b"SHED 20%"
    assert m.proc.state.zone_bseq[Z] == d.proc.state.zone_bseq[Z] == bseq(ea)  # per LOGICAL zone
    [ev] = zm.zones[Z].events                                                # the utility keeps ONE event
    assert ev.bseq == bseq(ea)
    with pytest.raises(EnvelopeError, match="no key"):
        d.proc.zones.open(ta, ea)                                           # the ChaCha device has no AES key
    with pytest.raises(EnvelopeError, match="not a broadcast for this topic"):
        m.proc.zones.open(ta, ec)                                           # a group's envelope on another's topic


def test_M7_membership_change_rotates_only_the_affected_group_on_join(tmp_path):
    p = Plant(tmp_path)
    m, d1, d2 = p.device(M1, "smart_meter"), p.device(D1, "der_ctrl"), p.device(D2, "der_ctrl")
    online(p, m, d1)
    g = p.node.zones.zones[Z].groups
    aes0, cc0 = g[AES].key_epoch, g[CC].key_epoch
    p.full(d2)
    join(p, d2)                                                             # a ChaCha device joins
    assert (g[AES].key_epoch, g[CC].key_epoch) == (aes0, cc0 + 1)
    p.node.zones.remove_member(Z, D2)                                       # a removal re-keys every group
    assert (g[AES].key_epoch, g[CC].key_epoch) == (aes0 + 1, cc0 + 2)


def test_M7_replay_protection_holds_across_both_groups(tmp_path):
    """The meter's class moves from AES to ChaCha (policy v2): it stays in the same logical zone, now in the
    ChaCha group. The same logical event, re-sent under the ChaCha key, is a replay for it."""
    p = Plant(tmp_path)
    m = p.device(M1, "smart_meter")
    online(p, m)
    ta = event_topic(Z, AES)
    first = p.node.zones.publish(Z, b"SHED", 600)[ta]
    assert m.proc.zones.open(ta, first) == b"SHED"
    v2 = make_policy(p.u_static.pk, mldsa_public_bytes(p.cmd_sk), version=2,
                     classes=replace_class(p.policy, "smart_meter", aead=CC))
    p.policy = v2
    p.node.endpoint.install_policy(v2)
    m.d.install_policy(v2)
    p.full(m)
    keys(p, m)                                                              # now the ChaCha group key
    [again] = p.node.zones.resend_for(M1)
    assert _parse(again)[2] is CC and bseq(again) == bseq(first)
    with pytest.raises(ReplayError, match="broadcast replay"):
        m.proc.zones.open_resent(again)
    tc = event_topic(Z, CC)
    assert m.proc.zones.open(tc, p.node.zones.publish(Z, b"NEXT", 600)[tc]) == b"NEXT"


# ======================================================================================================= M4
def test_M4_event_queued_under_an_old_key_is_reissued_under_the_current_key_after_a_reboot(tmp_path):
    p = Plant(tmp_path)
    d1, d2 = p.device(D1, "der_ctrl"), p.device(D2, "der_ctrl")
    online(p, d1, d2)
    zt, zm = event_topic(Z, CC), p.node.zones
    seen = zm.publish(Z, b"E0", 3600)[zt]
    assert d1.proc.zones.open(zt, seen) == b"E0"
    queued = zm.publish(Z, b"RESTORE", 3600)[zt]                           # d1 is away: the broker queues it
    zm.remove_member(Z, D2)                                                 # the group key rotates meanwhile
    current = zm.zones[Z].groups[CC].key_epoch
    assert current > epoch(queued)
    d1.boot()                                                               # reboot: keys (RAM) gone, bseq kept
    p.t += 1
    p.resume(d1)
    with pytest.raises(EnvelopeError, match="no key"):
        d1.proc.zones.open(zt, queued)                                      # the queued copy: unreadable
    keys(p, d1)
    resent = zm.resend_for(D1)
    assert [bseq(e) for e in resent] == [bseq(seen), bseq(queued)]         # bseq order, same identities
    assert {epoch(e) for e in resent} == {current}                          # under the CURRENT key
    with pytest.raises(ReplayError):
        d1.proc.zones.open_resent(resent[0])                                # E0: accepted before the reboot
    assert d1.proc.zones.open_resent(resent[1]) == (Z, b"RESTORE")          # new bseq: accepted
    for e in zm.resend_for(D1):                                             # a later duplicate: rejected
        with pytest.raises(ReplayError):
            d1.proc.zones.open_resent(e)
    d1.boot()                                                               # and after another reboot (DR-048)
    p.t += 1
    p.resume(d1)
    keys(p, d1)
    for e in zm.resend_for(D1):
        with pytest.raises(ReplayError):
            d1.proc.zones.open_resent(e)


def test_M4_still_valid_events_survive_a_utility_restart(tmp_path):
    p = Plant(tmp_path)
    d1 = p.device(D1, "der_ctrl")
    online(p, d1)
    zt = event_topic(Z, CC)
    queued = p.node.zones.publish(Z, b"RESTORE", 3600)[zt]                 # d1 never saw it
    p.restart()                                                             # sessions gone; SQLite kept
    d1.boot()
    p.t += 1
    p.resume(d1)
    keys(p, d1)
    [again] = p.node.zones.resend_for(D1)
    assert bseq(again) == bseq(queued)
    assert d1.proc.zones.open_resent(again) == (Z, b"RESTORE")


def test_M4_a_new_member_gets_no_event_from_before_it_joined(tmp_path):
    p = Plant(tmp_path)
    d1, d2 = p.device(D1, "der_ctrl"), p.device(D2, "der_ctrl")
    online(p, d1)
    zt = event_topic(Z, CC)
    p.node.zones.publish(Z, b"BEFORE", 3600)
    online(p, d2)
    assert p.node.zones.resend_for(D2) == []                                # E-Z1: nothing from before it joined
    after = p.node.zones.publish(Z, b"AFTER", 3600)[zt]
    assert [bseq(e) for e in p.node.zones.resend_for(D2)] == [bseq(after)]


def test_M4_expired_events_are_not_resent_and_retention_overflow_raises_an_alarm(tmp_path):
    p = Plant(tmp_path)
    d1 = p.device(D1, "der_ctrl")
    online(p, d1)
    zm = p.node.zones
    zm.publish(Z, b"short", 10)
    long_ = zm.publish(Z, b"long", 3600)[event_topic(Z, CC)]
    p.t += 10
    assert [bseq(e) for e in zm.resend_for(D1)] == [bseq(long_)]           # the expired one is gone
    for i in range(MAX_RETAINED):
        zm.publish(Z, b"E%d" % i, 3600)
    assert len(zm.zones[Z].events) == MAX_RETAINED
    assert [a[0].split(":")[0] for a in zm.alarms] == ["retention overflow"]   # never silent
    p.restart()
    assert len(p.node.zones.zones[Z].events) == MAX_RETAINED                # the retained set is durable


def test_a_device_whose_class_changes_aead_follows_its_new_groups_event_topic(world):
    """DR-047: a member listens on its own crypto group's topic. A policy that moves its class to another AEAD moves it
    to another group, so when its new ZONEKEY arrives it must subscribe to that group's topic. Before the fix it only
    subscribed for a NEW zone name, so it kept listening on the old group's topic and silently missed every live
    event (nothing arrived, so not even a zone sync was triggered). Through paho's callback, without a broker."""
    import ssl
    from pqgrid.commands import CommandProcessor, CommandService, ZoneManager
    from pqgrid.mqtt.device_node import DeviceMqtt
    d = world.device(D1, "der_ctrl")                                       # ChaCha20-Poly1305 under v1
    world.full(d)
    svc = CommandService(world.utility, world.cmd_sk)
    zm, proc = ZoneManager(svc), CommandProcessor(d, lambda c: None)
    mq = DeviceMqtt(d, proc, None, ssl.create_default_context(), "localhost", 1)
    subscribed, unsubscribed = [], []
    mq._publish = lambda topic, payload: None
    mq._subscribe = lambda subs: subscribed.extend(t for t, _ in subs)
    mq.c.unsubscribe = lambda topics: unsubscribed.extend(topics)
    zm.create(Z)
    zm.add_member(Z, D1)
    mq._on_control(control_topic("der_ctrl", D1), zm.distribute(Z)[D1])
    assert subscribed == [event_topic(Z, AeadAlg.CHACHA20POLY1305)]
    v2 = make_policy(world.u_static.pk, mldsa_public_bytes(world.cmd_sk), version=2,
                     classes=replace_class(world.policy, "der_ctrl", aead=AeadAlg.AES256GCM))
    world.utility.install_policy(v2)
    mq._install_policy(v2)                                                 # what the device loop does at activate_at
    world.full(d)                                                          # the re-handshake under v2
    for env in zm.zonekeys_for(D1):                                        # its new group's ZONEKEY
        mq._on_control(control_topic("der_ctrl", D1), env)
    assert subscribed[-1] == event_topic(Z, AeadAlg.AES256GCM)
    assert unsubscribed == [event_topic(Z, AeadAlg.CHACHA20POLY1305)]     # its old group's topic is left
    ev = zm.publish(Z, b"SHED", 600)                                       # published on the AES group's topic …
    assert list(ev) == [event_topic(Z, AeadAlg.AES256GCM)]
    assert proc.zones.open(event_topic(Z, AeadAlg.AES256GCM), ev[event_topic(Z, AeadAlg.AES256GCM)]) == b"SHED"
