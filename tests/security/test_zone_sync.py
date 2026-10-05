"""E-2 resolved (final remediation): no dependence on MQTT ordering across topics. A device that receives a DR event
it holds no key for asks for a ZONE SYNC (authenticated, replay-protected, under its own key label); the utility
answers on the device's control topic with its group's CURRENT ZONEKEY, then the zone's still-valid events
re-encrypted under that key (same σ, same bseq). Expired events are never republished; the persisted bseq drops
duplicates; nothing is buffered on the device."""
import pytest

from conftest import World
from pqgrid.commands import CommandProcessor, CommandService, ZoneManager
from pqgrid.commands.zones import ZONE_SYNC_MIN_S, ZoneKeyMissing, _parse, event_topic
from pqgrid.e2e.envelopes import control_topic, open_zone_sync, zone_sync
from pqgrid.errors import CommandError, EnvelopeError, ReplayError
from pqgrid.suite.aead import AeadAlg
from pqgrid.wire import dec, enc

D1, D2 = b"der-0001", b"der-0002"
Z, CC = "f7", AeadAlg.CHACHA20POLY1305
ZT = event_topic(Z, CC)


def setup(world: World):
    d1, d2 = world.device(D1, "der_ctrl"), world.device(D2, "der_ctrl")
    world.full(d1)
    world.full(d2)
    svc = CommandService(world.utility, world.cmd_sk)
    zm, p1 = ZoneManager(svc), CommandProcessor(d1, lambda c: None)
    zm.create(Z)
    zm.add_member(Z, D1)
    for env in zm.zonekeys_for(D1):
        p1.on_control(control_topic("der_ctrl", D1), env)
    return d1, zm, p1


def test_zone_sync_request_is_authenticated_and_replay_protected(world: World):
    d1, zm, p1 = setup(world)
    s_dev, s_utl = d1.session, world.utility.session_for(D1)
    req = zone_sync(s_dev, Z, 3)
    assert open_zone_sync(s_utl, req) == (Z, 3)
    with pytest.raises(ReplayError):
        open_zone_sync(s_utl, req)                                          # the same request again
    f = dec(zone_sync(s_dev, Z, 3), 6)
    f[4] = b"f8"                                                            # another zone, same MAC
    with pytest.raises(EnvelopeError, match="forged"):
        open_zone_sync(s_utl, enc(f))
    assert open_zone_sync(s_utl, zone_sync(s_dev, Z, 4)) == (Z, 4)          # the forgery burned nothing


def test_the_answer_is_the_current_key_then_the_still_valid_events_under_it(world: World):
    d1, zm, p1 = setup(world)
    old = zm.publish(Z, b"E1", 600)[ZT]
    zm.add_member(Z, D2)                                  # D2 (registered by setup) joins: d1 misses the new key
    new = zm.publish(Z, b"E2", 600)[ZT]
    with pytest.raises(ZoneKeyMissing) as missing:
        p1.zones.open(ZT, new)
    assert (missing.value.zone, missing.value.epoch) == (Z, _parse(new)[3])
    answer = zm.sync_for(D1, Z)
    assert dec(p1.on_control(control_topic("der_ctrl", D1), answer[0]), 6)[4] == b"OK"   # the ZONEKEY first
    assert p1.zones.open_resent(answer[1]) == (Z, b"E1")                  # d1 never opened E1 live
    assert [_parse(e)[4] for e in answer[1:]] == [_parse(old)[4], _parse(new)[4]]        # same identities
    assert {_parse(e)[3] for e in answer[1:]} == {zm.zones[Z].groups[CC].key_epoch}       # current key
    assert p1.zones.open_resent(answer[2]) == (Z, b"E2")
    with pytest.raises(ReplayError):
        p1.zones.open(ZT, new)                                              # the original copy: a duplicate


def test_sync_is_refused_for_non_members_and_rate_limited(world: World):
    d1, zm, p1 = setup(world)                                               # D2: registered, not a member
    with pytest.raises(CommandError, match="not a member"):
        zm.sync_for(D2, Z)
    zm.sync_for(D1, Z)
    with pytest.raises(CommandError, match="rate-limited"):
        zm.sync_for(D1, Z)
    world.t += ZONE_SYNC_MIN_S
    assert zm.sync_for(D1, Z)


def test_expired_events_are_never_republished(world: World):
    d1, zm, p1 = setup(world)
    zm.publish(Z, b"SHORT", 10)
    keep = zm.publish(Z, b"LONG", 600)[ZT]
    world.t += 10
    answer = zm.sync_for(D1, Z)
    assert [_parse(e)[4] for e in answer[1:]] == [_parse(keep)[4]]
