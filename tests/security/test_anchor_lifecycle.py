"""DR-050 as finalized (remediation H4): A is the operational release anchor; B is the offline recovery anchor.
While A is active only A signs releases and only B may sign KEYREVOKE(A); afterwards B is the release anchor
and A is never accepted again. A can never revoke B."""
import os

import pytest

from conftest import World
from test_fota import CHUNK, MP, C2, Dev, build, station  # noqa: F401  (fixture)
from pqgrid.fota.artifact import ANCHOR_A, ANCHOR_B, FIRMWARE, KEYREVOKE, POLICY, FotaError
from pqgrid.fota.policy_artifact import verify_policy_artifact
from pqgrid.fota.publisher import part_payload_budget
from pqgrid.policy import encode_policy


def fw(station, v, anchor):
    return build(station, FIRMWARE, v, os.urandom(9000), anchor_id=anchor)


def revoke(station, counter, target, signer):
    return station.keyrevoke(C2, counter, target, CHUNK, part_payload_budget(MP, C2, KEYREVOKE, counter),
                             anchor_id=signer)


def install(d, art):
    d.feed(art)
    return d.inst.boot_staged_firmware(lambda img: True) if art.manifest.type == FIRMWARE else "applied"


def test_A_signs_releases_while_active_and_B_may_not(station):
    d = Dev(station)
    assert install(d, fw(station, 2, ANCHOR_A)) == "committed"
    with pytest.raises(FotaError, match="B may not sign ordinary releases while A is active"):
        d.feed(fw(station, 3, ANCHOR_B), chunks=[])
    with pytest.raises(FotaError, match="B may not sign ordinary releases while A is active"):
        d.feed(build(station, POLICY, 9, os.urandom(500), anchor_id=ANCHOR_B), chunks=[])
    assert d.inst.committed(FIRMWARE) == 2


def test_only_B_may_revoke_and_only_A(station):
    d = Dev(station)
    with pytest.raises(FotaError, match="recovery anchor B"):
        d.feed(revoke(station, 1, ANCHOR_B, ANCHOR_A), chunks=[])          # A revoking B
    with pytest.raises(FotaError, match="recovery anchor B"):
        d.feed(revoke(station, 1, ANCHOR_A, ANCHOR_A), chunks=[])          # A revoking itself
    with pytest.raises(FotaError, match="only the recovery anchor B may revoke the release anchor A"):
        d.feed(revoke(station, 1, ANCHOR_B, ANCHOR_B))                     # B revoking B: the role rule
    with pytest.raises(FotaError, match="only the recovery anchor B may revoke the release anchor A"):
        d.feed(revoke(station, 1, 7, ANCHOR_B))                            # an anchor that does not exist
    assert d.inst.prot.revoked == set() and d.inst.committed(KEYREVOKE) == 0


def test_after_B_revokes_A_B_releases_and_A_is_refused_forever(station):
    d = Dev(station)
    assert install(d, fw(station, 2, ANCHOR_A)) == "committed"
    d.feed(revoke(station, 1, ANCHOR_A, ANCHOR_B))
    assert d.inst.prot.revoked == {ANCHOR_A} and d.inst.committed(KEYREVOKE) == 1
    for art in (fw(station, 3, ANCHOR_A), build(station, POLICY, 9, os.urandom(500), anchor_id=ANCHOR_A),
                revoke(station, 2, ANCHOR_B, ANCHOR_A)):
        with pytest.raises(FotaError, match="revoked anchor"):
            d.feed(art, chunks=[])                                         # A: nothing accepted, ever
    assert install(d, fw(station, 3, ANCHOR_B)) == "committed"             # B is now the release anchor
    with pytest.raises(FotaError, match="rollback"):
        d.feed(revoke(station, 1, ANCHOR_A, ANCHOR_B), chunks=[])          # the same KEYREVOKE replayed
    d.boot()                                                               # the roles survive a reboot
    assert d.inst.prot.revoked == {ANCHOR_A}
    assert install(d, fw(station, 4, ANCHOR_B)) == "committed"


def test_utility_and_acl_apply_the_same_roles(station, world: World):
    payload = encode_policy(world.policy)
    by_a = build(station, POLICY, world.policy.version, payload, anchor_id=ANCHOR_A)
    by_b = build(station, POLICY, world.policy.version, payload, anchor_id=ANCHOR_B)
    assert verify_policy_artifact(by_a.signed, payload, station.anchors).info() == world.policy.info()
    with pytest.raises(FotaError, match="B may not sign ordinary releases"):
        verify_policy_artifact(by_b.signed, payload, station.anchors)
    assert verify_policy_artifact(by_b.signed, payload, station.anchors, revoked={ANCHOR_A})
    with pytest.raises(FotaError, match="revoked"):
        verify_policy_artifact(by_a.signed, payload, station.anchors, revoked={ANCHOR_A})
