"""The utility's anchor revocations are one authoritative set (DR-050 as amended; audit M-1).

Before the fix a policy scheduled while A was valid carried that snapshot: after KEYREVOKE(A) the utility's tick still
activated the A-signed policy, which every device refuses at activation (roles re-checked, §15.14), so the utility
and the fleet ended on different policies and every client hello was refused (audit repro). Here the production
utility (open_utility + UtilityMqtt + SqlPublisher, one database), a station with anchors A and B, and a device
installer check every place a policy is accepted: scheduling, activation (tick), restart, ACL compilation and
republication."""
import ssl

import pytest

import conftest
from test_fota import C2, CHUNK, MP, Dev, station  # noqa: F401  (fixture)
from pqgrid.fota.artifact import ANCHOR_A, ANCHOR_B, KEYREVOKE, POLICY, FotaError
from pqgrid.fota.publisher import part_payload_budget
from pqgrid.mqtt.broker import compile_acl
from pqgrid.mqtt.utility_node import UtilityMqtt
from pqgrid.persistence.utility_db import SqlPublisher, open_utility
from pqgrid.policy import encode_policy, validate
from pqgrid.suite.hkem import HybridKeyPair
from pqgrid.suite.sig import mldsa_keygen, mldsa_public_bytes

T0 = 1_790_000_000


class FakeBroker:
    """The utility's MQTT client stand-in: records what would be published (nothing here needs delivery)."""

    def __init__(self):
        self.published = []

    def publish(self, topic, payload, qos=0, retain=False):
        self.published.append((topic, bytes(payload)))


class Utility:
    def __init__(self, tmp, station):
        self.tmp, self.station, self.now = tmp, station, [float(T0)]
        self.kem, self.cmd = HybridKeyPair.generate(), mldsa_keygen()
        self.v1 = conftest.make_policy(self.kem.pk, mldsa_public_bytes(self.cmd))
        validate(self.v1)
        self.v1_art = self.artifact(self.v1)
        self.broker = FakeBroker()
        self.open()

    def open(self):
        self.node = open_utility(f"{self.tmp}/u.db", self.v1, self.kem, self.cmd, lambda: self.now[0])
        self.pub = SqlPublisher(self.node.db, self.node.endpoint.policy, clock=lambda: self.now[0])
        self.u = UtilityMqtt(self.node, ssl.create_default_context(), "localhost", 1, clock=lambda: self.now[0],
                             publisher=self.pub)

    def restart(self):
        self.node.db.close()
        self.open()

    def policy(self, version: int, activate_at: int = T0 + 60):
        return conftest.make_policy(self.kem.pk, mldsa_public_bytes(self.cmd), version=version,
                                    activate_at=activate_at)

    def artifact(self, p, anchor: int = ANCHOR_A):
        return self.station.build(POLICY, C2, p.version, encode_policy(p), CHUNK,
                                  part_payload_budget(MP, C2, POLICY, p.version), activate_at=p.activate_at,
                                  anchor_id=anchor)

    def revoke_A(self):
        kr = self.station.keyrevoke(C2, 1, ANCHOR_A, CHUNK, part_payload_budget(MP, C2, KEYREVOKE, 1))
        self.pub.publish(self.broker, kr)                               # durable before the broker is told
        return kr


@pytest.fixture
def ut(tmp_path, station):
    u = Utility(tmp_path, station)
    yield u
    u.node.db.close()


def test_a_policy_scheduled_before_its_anchor_was_revoked_is_never_activated(ut: Utility):
    v2 = ut.policy(2)
    art = ut.artifact(v2)                                               # A-signed, A still active: accepted
    ut.u.schedule_policy(art.signed, art.payload, ut.station.anchors)
    ut.revoke_A()
    assert ut.u.revoked_anchors() == {ANCHOR_A}
    ut.now[0] = T0 + 61
    ut.u.tick()
    ut.u.tick()                                                         # duplicate ticks: refused once, dropped
    assert ut.node.endpoint.policy.version == 1
    assert ut.node.db.load_policy("scheduled") is None
    assert [r for r in ut.u.refused if "revoked" in r and "refused at activation" in r] and not ut.u.internal_errors
    with pytest.raises(FotaError, match="revoked"):                     # nor can it be scheduled again
        ut.u.schedule_policy(art.signed, art.payload, ut.station.anchors)


def test_a_restart_between_the_revocation_and_the_activation_still_refuses_it(ut: Utility):
    v2 = ut.policy(2)
    art = ut.artifact(v2)
    ut.u.schedule_policy(art.signed, art.payload, ut.station.anchors)
    ut.revoke_A()
    ut.restart()                                                        # the revocation is durable …
    assert ut.u.revoked_anchors() == {ANCHOR_A}
    assert ut.node.db.load_policy("scheduled") is None                  # … and re-checked at start
    assert any("refused after a restart" in r for r in ut.u.refused)
    ut.now[0] = T0 + 61
    ut.u.tick()
    assert ut.node.endpoint.policy.version == 1


def test_the_B_signed_replacement_activates_and_every_device_accepts_it(ut: Utility, station):
    a_art = ut.artifact(ut.policy(2))
    ut.u.schedule_policy(a_art.signed, a_art.payload, ut.station.anchors)
    ut.revoke_A()
    b = ut.policy(2)
    b_art = ut.artifact(b, anchor=ANCHOR_B)                             # after KEYREVOKE(A), B is the release anchor
    ut.u.schedule_policy(b_art.signed, b_art.payload, ut.station.anchors)
    ut.now[0] = T0 + 61
    ut.u.tick()
    assert ut.node.endpoint.policy.info() == b.info()
    d = Dev(station)                                                    # a device that received KEYREVOKE(A) …
    d.feed(ut.revoke_A())
    assert d.inst.prot.revoked == {ANCHOR_A}
    with pytest.raises(FotaError, match="revoked anchor"):
        d.feed(a_art, chunks=[])                                        # … refuses the A-signed policy
    d.feed(b_art)                                                       # … and installs the B-signed one
    d.now[0] = T0 + 61
    assert d.inst.activate_policy(ut.v1).info() == b.info()             # utility and fleet on the same policy


def test_acl_compilation_uses_the_current_revocations_for_a_new_policy(ut: Utility):
    v2 = ut.policy(2, activate_at=T0)
    art = ut.artifact(v2)
    assert ut.u.activate_policy(art.signed, art.payload, ut.station.anchors)   # A-signed v2 in force
    ut.revoke_A()
    assert "user utility" in ut.u.acl_text()                            # the policy in force: still compiled
    v3_art = ut.artifact(ut.policy(3))                                  # a NEW A-signed policy: refused with the
    with pytest.raises(FotaError, match="revoked"):                     # utility's current revocations
        compile_acl(v3_art.signed, v3_art.payload, ut.station.anchors, [], {}, ut.u.revoked_anchors())
    ut.restart()
    assert ut.node.endpoint.policy.version == 2 and "user utility" in ut.u.acl_text()


def test_nothing_signed_by_a_revoked_anchor_is_republished_even_after_a_restart(ut: Utility):
    art = ut.artifact(ut.policy(2))
    ut.pub.publish(ut.broker, art)                                      # the newest POLICY for the class
    ut.revoke_A()
    ut.restart()
    assert ut.pub.on_request(ut.broker, C2, b"c2-0001", types={POLICY}) == []
    b_art = ut.artifact(ut.policy(3), anchor=ANCHOR_B)
    ut.pub.publish(ut.broker, b_art)
    ut.now[0] += 3601
    assert ut.pub.on_request(ut.broker, C2, b"c2-0001", types={POLICY}) == [POLICY]


def test_the_bootstrap_acl_needs_its_artifact(ut: Utility):
    with pytest.raises(Exception, match="bootstrap"):
        ut.u.acl_text()
    text = ut.u.acl_text(bootstrap=(ut.v1_art.signed, ut.v1_art.payload, ut.station.anchors))
    assert "user utility" in text
