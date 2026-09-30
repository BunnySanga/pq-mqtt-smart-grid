"""Transport pieces that need no broker: topics, back-off, broker-config validator, ACL compiler, PUBLISH size,
time floor (Master §8.9, §10, §27.1; IMPLEMENTATION-ROADMAP §11, C10, E48, E50, E51)."""
import random

import pytest

from conftest import World
from pqgrid.mqtt import topics
from pqgrid.mqtt.broker import ConfigError, hybrid_openssl_cnf, render_acl, render_config, validate_config
from pqgrid.mqtt.utility_node import publish_size
from pqgrid.persistence.device import DeviceFlash
from pqgrid.persistence.flash import FlashSim
from pqgrid.e2e.handshake import DeviceEndpoint
from pqgrid.registry import DeviceRecord
from pqgrid.suite.aead import AeadAlg

LISTENER = {"port": 8883, "cafile": "/p/ca.crt", "certfile": "/p/b.crt", "keyfile": "/p/b.key"}


def test_topics_roundtrip_and_reject_foreign_topics():
    d = b"der-0001"
    assert topics.parse(topics.alert("der_ctrl", d)) == ("alert", "der_ctrl", "der-0001")
    assert topics.parse(topics.hs_down(d)) == ("hs_down", "", "der-0001")
    assert topics.parse(topics.dr_event("f7", AeadAlg.AES256GCM)) == ("dr_event", "aes256gcm", "f7")
    assert topics.dr_event("f7", AeadAlg.CHACHA20POLY1305) == "grid/dr/f7/chacha20poly1305/event"
    for bad in ("grid/x", "pqgrid/hs/a/sideways", "other/a/b/alert", "grid/a/b/c/alert"):
        with pytest.raises(ValueError):
            topics.parse(bad)


def test_backoff_is_full_jitter_and_capped():
    rng = random.Random(7)
    for attempt in range(12):
        bound = min(300, 2 * 2 ** attempt)
        xs = [topics.backoff_delay(attempt, 2, 300, rng) for _ in range(400)]
        assert all(0 <= x <= bound for x in xs)
        assert 0.35 * bound < sum(xs) / len(xs) < 0.65 * bound          # uniform over [0, bound]: mean ≈ bound/2
    assert topics.backoff_delay(10 ** 6, 2, 300, rng) <= 300                # no overflow on huge attempt counts


def test_rendered_config_passes_and_every_rule_is_enforced():
    good = render_config([LISTENER], "/p/acl", "/p/db")
    validate_config(good)
    for broken, why in [
        (good.replace("tls_version tlsv1.3", "tls_version tlsv1.2"), "tls_version tlsv1.3"),
        (good.replace("persistence true", "persistence false"), "persistence"),
        (good.replace("allow_anonymous false", "allow_anonymous true"), "allow_anonymous"),
        (good.replace("require_certificate true", "require_certificate false"), "require_certificate"),
        (good.replace("use_identity_as_username true", ""), "use_identity_as_username"),
        (good.replace("max_packet_size 300000", "max_packet_size 400000"), "max_packet_size"),
        (good + "\nlistener 1883\n", "no plaintext listeners"),
    ]:
        with pytest.raises(ConfigError, match=why):
            validate_config(broken)


def test_openssl_pin_is_hybrid_only_and_tls13():
    cnf = hybrid_openssl_cnf()
    assert "Groups = X25519MLKEM768:SecP256r1MLKEM768" in cnf and "MinProtocol = TLSv1.3" in cnf
    assert "X25519\n" not in cnf and ":X25519:" not in cnf


def test_acl_gives_each_device_only_its_own_topics(world: World):
    world.device(b"der-0001", "der_ctrl")
    world.device(b"meter-0001", "smart_meter")
    world.device(b"meter-0002", "smart_meter")
    world.registry.revoke(b"meter-0002")
    recs = [world.registry.get(d) for d in (b"der-0001", b"meter-0001", b"meter-0002")]
    acl = render_acl(world.policy, recs, {"f7": {b"der-0001"}})
    blocks = {b.split("\n", 1)[0]: b for b in acl.split("\n\n")}
    der = blocks["user der-0001"]
    assert "topic read grid/der_ctrl/der-0001/control" in der
    assert "topic read grid/dr/f7/chacha20poly1305/event" in der                # its own crypto group only
    assert "grid/dr/f7/aes256gcm/event" not in der
    assert "meter-0001" not in der and "+" not in der                          # nothing but its own topics
    assert [l for l in der.splitlines() if "#" in l] == ["topic read pqgrid/fota/der_ctrl/#"]   # its class's artifacts
    assert "grid/dr/f7" not in blocks["user meter-0001"]                       # not a member
    assert "user meter-0002" not in blocks                                     # revoked: no rights at all
    util = blocks["user utility"]
    assert "readwrite" not in util and "topic write pqgrid/hs/+/down" in util and "topic read pqgrid/hs/+/up" in util


def test_acl_refuses_a_device_whose_class_is_not_in_the_policy(world: World):
    rec = DeviceRecord(b"x-0001", "unknown_class", b"\x00" * 1216)
    with pytest.raises(Exception):
        render_acl(world.policy, [rec], {})


def test_publish_size_is_exact():
    # fixed header (1) + remaining length varint + topic length (2) + topic + packet id (2) + properties length (1)
    assert publish_size("a/b", b"x" * 10) == 1 + 1 + 2 + 3 + 2 + 1 + 10
    assert publish_size("t", b"x" * 200) == 1 + 2 + 2 + 1 + 2 + 1 + 200         # two-byte remaining length


def test_time_floor_survives_reboot_and_is_written_at_most_daily(world: World):
    f, kp = FlashSim(), None
    d = world.device(b"meter-0001", "smart_meter")
    kp = d.static
    df = DeviceFlash(f, clock=lambda: world.t)
    d = DeviceEndpoint(b"meter-0001", "smart_meter", world.policy, 1, kp, clock=lambda: world.t, flash=df)
    world.full(d)
    from pqgrid.persistence.device import T_TIME
    floor_wseq = lambda: df.store.items(T_TIME)[b""][0]            # noqa: E731
    assert df.time_floor() == int(world.t)                          # first authenticated time after boot
    w0 = floor_wseq()
    world.t += 3600
    d._ch = None
    world.full(d)
    assert floor_wseq() == w0                                       # same day: no second floor write
    world.t += 86400
    d._ch = None
    world.full(d)
    assert floor_wseq() > w0 and df.time_floor() == int(world.t)    # a day later: written again
    booted = DeviceEndpoint(b"meter-0001", "smart_meter", world.policy, 1, kp, clock=lambda: 1000.0,
                            flash=DeviceFlash(f, clock=lambda: 1000.0))
    assert booted.now() >= int(world.t) - 3600                      # RTC reset to 1970: starts from the floor
