"""E-4 resolved (final remediation): the republish rule, independent of any time floor. Only the newest artifact
per (class, type), only while still valid NOW (signer not revoked and in its DR-050 role; a POLICY not older than
the active one), at most once an hour per device, and never an expired DR event (M4, E-2)."""
import os

from conftest import World, make_policy
from test_fota import CHUNK, MP, build, station  # noqa: F401  (fixture)
from pqgrid.fota.artifact import ANCHOR_A, ANCHOR_B, FIRMWARE, KEYREVOKE, POLICY
from pqgrid.fota.publisher import REPUBLISH_EVERY_S, Publisher, part_payload_budget
from pqgrid.suite.sig import mldsa_public_bytes

C2, DEV = "c2_meter", b"c2-0001"


class Client:
    def __init__(self):
        self.msgs = []

    def publish(self, topic, payload, qos=1, retain=False):
        self.msgs.append((topic, payload, retain))


def republished(client, art) -> bool:
    return any(t.startswith(f"pqgrid/fota/{C2}/") and p == art.parts[0] for t, p, _ in client.msgs)


def test_a_missing_valid_artifact_is_republished_and_only_the_newest(world: World, station):
    t = [1000.0]
    pub, c = Publisher(world.policy, clock=lambda: t[0]), Client()
    v2, v3 = build(station, FIRMWARE, 2, os.urandom(9000)), build(station, FIRMWARE, 3, os.urandom(9000))
    pub.publish(c, v2)
    pub.publish(c, v3)                                                   # v3 supersedes v2
    t[0] += 31 * 86400
    pub.cleanup(c)                                                       # retention over: nothing retained
    c2 = Client()
    assert pub.on_request(c2, C2, DEV) == [FIRMWARE]
    assert republished(c2, v3) and not republished(c2, v2)               # the newest only


def test_a_stale_policy_is_never_resurrected(world: World, station):
    pub, c = Publisher(world.policy, clock=lambda: 1000.0), Client()
    old = build(station, POLICY, 1, os.urandom(500))
    pub.publish(c, old)
    pub.policy = make_policy(world.u_static.pk, mldsa_public_bytes(world.cmd_sk), version=2)   # v2 is active now
    assert pub.on_request(Client(), C2, DEV) == []                       # v1 is older than the active policy
    new = build(station, POLICY, 2, os.urandom(500))
    pub.publish(c, new)
    c2 = Client()
    assert pub.on_request(c2, C2, DEV) == [POLICY] and republished(c2, new)


def test_nothing_signed_by_a_revoked_anchor_is_republished(world: World, station):
    pub, c = Publisher(world.policy, clock=lambda: 1000.0), Client()
    by_a = build(station, FIRMWARE, 2, os.urandom(9000), anchor_id=ANCHOR_A)
    pub.publish(c, by_a)
    rev = station.keyrevoke(C2, 1, ANCHOR_A, CHUNK, part_payload_budget(MP, C2, KEYREVOKE, 1), anchor_id=ANCHOR_B)
    pub.publish(c, rev)
    assert pub.revoked == {ANCHOR_A}
    c2 = Client()
    assert pub.on_request(c2, C2, DEV) == [KEYREVOKE] and not republished(c2, by_a)   # A is gone for good
    by_b = build(station, FIRMWARE, 3, os.urandom(9000), anchor_id=ANCHOR_B)
    pub.publish(c, by_b)
    pub._last_request.clear()
    c3 = Client()
    assert sorted(pub.on_request(c3, C2, DEV)) == [FIRMWARE, KEYREVOKE] and republished(c3, by_b)


def test_requests_are_rate_limited_and_an_empty_offer_costs_nothing(world: World, station):
    t = [1000.0]
    pub, c = Publisher(world.policy, clock=lambda: t[0]), Client()
    fw = build(station, FIRMWARE, 2, os.urandom(9000))
    pub.publish(c, fw)
    assert pub.on_request(Client(), C2, DEV, types={FIRMWARE}, newer_than={FIRMWARE: 2}) == []   # nothing newer …
    assert pub.on_request(Client(), C2, DEV, types={FIRMWARE}, only_missing=True) == []         # … or retained
    assert pub.on_request(Client(), C2, DEV) == [FIRMWARE]               # the hour was not consumed above
    assert pub.on_request(Client(), C2, DEV) == []                       # a repeated request within the hour
    t[0] += REPUBLISH_EVERY_S
    assert pub.on_request(Client(), C2, DEV) == [FIRMWARE]


def test_the_publishers_rollout_state_survives_a_utility_restart(world: World, station, tmp_path):
    """Master §4.4 / U-4: the artifact publisher's rollout state is durable. After a restart the utility still knows
    its newest artifacts (E-4 republish), still removes what it retained once the window has passed, and still
    knows the anchors revoked by the KEYREVOKEs it published (so it never republishes their releases)."""
    from pqgrid.fota.publisher import RETENTION_S
    from pqgrid.persistence.utility_db import SqlPublisher, UtilityDB
    t, path = [1000.0], str(tmp_path / "u.db")
    db = UtilityDB(path)
    pub, c = SqlPublisher(db, world.policy, clock=lambda: t[0]), Client()
    fw_a = build(station, FIRMWARE, 2, os.urandom(9000))                       # signed by A
    rev = station.keyrevoke(C2, 1, ANCHOR_A, CHUNK, part_payload_budget(MP, C2, KEYREVOKE, 1))
    pub.publish(c, fw_a)
    pub.publish(c, rev)
    retained = {topic for topic, _, r in c.msgs if r}
    db.close()
    db = UtilityDB(path)                                                         # restart
    pub = SqlPublisher(db, world.policy, clock=lambda: t[0])
    assert pub.revoked == {ANCHOR_A}
    c2 = Client()
    assert pub.on_request(c2, C2, DEV) == [KEYREVOKE]                            # A's firmware: not any more
    t[0] += RETENTION_S
    c3 = Client()
    assert pub.cleanup(c3) == 2 and {topic for topic, p, r in c3.msgs if p == b"" and r} == retained
    db.close()
    db = UtilityDB(path)                                                         # restart after the clean-up:
    pub = SqlPublisher(db, world.policy, clock=lambda: t[0])
    assert pub.live == {} and not pub.retained(rev)                              # it knows nothing is retained
    fw_b = build(station, FIRMWARE, 3, os.urandom(9000), anchor_id=ANCHOR_B)    # B releases after the revocation
    pub.publish(Client(), fw_b)
    db.close()
    db = UtilityDB(path)                                                         # restart again
    pub, c4 = SqlPublisher(db, world.policy, clock=lambda: t[0] + REPUBLISH_EVERY_S), Client()
    assert pub.on_request(c4, C2, DEV) == [FIRMWARE, KEYREVOKE] and republished(c4, fw_b)
    db.close()
