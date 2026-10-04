"""Codex audit P1-1 (2026-10-03, IMPLEMENTATION-ROADMAP §16) over the real broker: a device re-provisioned with a new
E2E key or a new class establishes again under its new identity through the production loops. It boots from flash
still holding the ticket of its old record; the utility refuses that ticket, so the device falls back to a full
handshake (E49). For the class change the production ACL hook recompiles the broker ACL from the new record."""
from dataclasses import replace

from harness import broker, loops, plant, requires_broker, start, wait_for   # noqa: F401  (fixtures)
from pqgrid.mqtt.broker import acl_installer
from pqgrid.suite.hkem import HybridKeyPair

pytestmark = requires_broker
D1 = b"der-0001"


def production_acl_hook(plant):
    plant.u.acl_hook = acl_installer(plant.u, plant.b.acl, lambda: plant.b.proc.pid,
                                     bootstrap=(plant.policy_art.signed, plant.policy_art.payload,
                                                plant.station.anchors))


def test_a_device_with_a_replaced_key_establishes_again_and_its_old_ticket_is_refused(plant):
    d = plant.add(D1, "der_ctrl")
    production_acl_hook(plant)
    start(plant)
    with loops(plant, d):
        assert wait_for(lambda: d.d.confirmed and d.d.ticket is not None, 15), d.mq.errors
        old_sid = d.d.session.sid
    d.mq.disconnect()
    d.kp = HybridKeyPair.generate()                                    # a replaced module: a new E2E key
    plant.u.reprovision_device(replace(plant.node.endpoint.registry.get(D1), e2e_pk=d.kp.pk))
    assert plant.node.endpoint.current_session(D1) is None
    plant.boot(d)                                                      # flash still holds the old ticket
    with loops(plant, d):
        assert wait_for(lambda: d.d.confirmed and d.d.session.sid != old_sid, 30), (d.mq.errors, plant.u.refused)
        assert any("re-provisioned" in r for r in plant.u.refused)       # the old ticket was refused
        seq = plant.u.command(D1, b"AFTER", 600)
        assert wait_for(lambda: plant.node.commands.outcome(D1, seq) == b"OK", 15), d.mq.errors
    assert d.applied == [b"AFTER"]


def test_a_device_moved_to_another_class_establishes_under_it_with_a_recompiled_acl(plant):
    d = plant.add(D1, "der_ctrl")
    production_acl_hook(plant)
    start(plant)
    with loops(plant, d):
        assert wait_for(lambda: d.d.confirmed, 15), d.mq.errors
        queued = plant.u.command(D1, b"CLOSE BREAKER 3", 600)
        assert wait_for(lambda: plant.node.commands.outcome(D1, queued) == b"OK", 15)
    d.mq.disconnect()
    plant.u.reprovision_device(replace(plant.node.endpoint.registry.get(D1), dclass="c2_meter"))
    assert "grid/c2_meter/der-0001/control" in open(plant.b.acl).read() and not plant.u.acl_failures
    d.dclass = "c2_meter"
    plant.boot(d)
    with loops(plant, d):
        assert wait_for(lambda: d.d.confirmed and d.d.session.dclass == "c2_meter", 30), (d.mq.errors,
                                                                                         plant.u.refused)
        assert plant.node.endpoint.current_session(D1).dclass == "c2_meter"
    assert d.applied == [b"CLOSE BREAKER 3"]                           # applied once, before the change
