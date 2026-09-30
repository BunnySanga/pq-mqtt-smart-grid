"""CA roll-over through the signed policy over the real broker (Master §4.5 "the new CA certificate travels in a signed
policy before the broker switches; devices pin {current, next} during the overlap", K-4; audit M-3). The devices' TLS
trust is their installed policy's ca_set (tls.device_context_from_policy, the harness's production path)."""
import ssl
import time

import pytest

import conftest
from harness import broker, loops, plant, requires_broker, start, wait_for          # noqa: F401  (fixtures)
from pqgrid.fota.artifact import POLICY

pytestmark = requires_broker
M1, D1 = b"meter-0001", b"der-0001"


def test_ca_rollover_through_the_signed_policy(plant, broker):
    m = plant.add(M1, "smart_meter")                                  # receives v2: {current, next}
    n = plant.add(D1, "der_ctrl")                                     # never receives it: {current} only
    v2 = conftest.make_policy(plant.u_static.pk, plant.policy.utility_cmd_pk, version=2,
                              ca_set=(broker.ca_der(broker.ca), broker.ca_der(broker.ca_next)),
                              activate_at=int(time.time()) + 4)
    art = plant.sign_policy(v2, "smart_meter")
    start(plant)
    with loops(plant, m, n):
        assert wait_for(lambda: m.d.confirmed and n.d.confirmed, 20)
        plant.u.publish_artifact(art)
        plant.u.schedule_policy(art.signed, art.payload, plant.station.anchors)
        assert wait_for(lambda: m.d.confirmed and m.d.session.policy_info == v2.info(), 30), m.mq.errors
    broker.switch_to_next_ca()                                        # the broker now presents a next-CA certificate
    with loops(plant, m):
        assert wait_for(lambda: m.mq.connected.is_set() and m.d.confirmed, 30), m.mq.errors   # trusted via v2
    n.mq.disconnect()
    with pytest.raises(ssl.SSLCertVerificationError):
        n.mq.connect()                                                # v1 trust only: the next CA is not trusted
    m.mq.disconnect()
    plant.boot(m)                                                     # power cycle: trust from the installed v2
    assert m.d.policy.ca_set == v2.ca_set
    with loops(plant, m):
        assert wait_for(lambda: m.mq.connected.is_set() and m.d.confirmed, 30), m.mq.errors
    assert POLICY in m.mq.fota_staged or m.fota.committed(POLICY) == 2
