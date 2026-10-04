"""Codex audit P1-1 (2026-10-03, IMPLEMENTATION-ROADMAP §16): re-provisioning a device, a new class and/or E2E key,
ends everything its old record authorised: the live session and half-open handshake, its resumption tickets, its
open commands and GRANTs, and the zone keys it could hold. Before the fix `Registry.add` silently replaced the record
and all of it stayed valid: a der_ctrl device moved to c2_meter (no commands) still received a command queued for
der_ctrl, and the holder of an old key kept its session and could resume with its old ticket.

Utility on SQLite, devices on simulated flash (test_restart.Plant): the restart after the change is real."""
from dataclasses import replace

import pytest

from test_restart import Dev, Plant
from pqgrid.e2e.envelopes import control_topic
from pqgrid.errors import CommandError, CryptoError, HandshakeError, PolicyError, TicketError
from pqgrid.persistence.flash import FlashSim
from pqgrid.suite.hkem import HybridKeyPair
from pqgrid.wire import dec

D1, D2 = b"der-0001", b"der-0002"


class Identity(Dev):
    """A device object for an ALREADY registered ID with another class and/or key: the registry is changed by
    re-provisioning, never by this object."""

    def __init__(self, plant: Plant, did: bytes, dclass: str, kp: HybridKeyPair):
        self.p, self.did, self.dclass = plant, did, dclass
        self.kp, self.flash, self.applied = kp, FlashSim(), []
        self.boot()


def before_the_change(tmp_path):
    """A der_ctrl device with a live session, a resumption ticket, a command sent in that session, a command not yet
    sent, a GRANT and a zone membership."""
    p = Plant(tmp_path)
    old = p.device(D1, "der_ctrl")
    p.full(old)
    assert old.d.ticket is not None
    svc = p.node.commands
    sent = svc.issue(D1, b"CLOSE BREAKER 3", 600)
    assert len(svc.outgoing(D1)) == 1                                      # recorded as sent in this session
    unsent = svc.issue(D1, b"TRIP", 600)                                   # queued, not sent yet
    gid, _ = svc.grant(D1, "P_ACTIVE_W", -10, 10, 5, 600)
    p.node.zones.create("f7")
    p.node.zones.add_member("f7", D1)
    return p, old, sent, unsent, gid


def epochs(p: Plant) -> dict:
    return {alg: g.key_epoch for alg, g in p.node.zones.zones["f7"].groups.items()}


def test_a_class_change_ends_everything_the_old_record_authorised(tmp_path):
    p, old, sent, unsent, gid = before_the_change(tmp_path)
    before, svc = epochs(p), p.node.commands
    assert p.node.reprovision(replace(p.u.registry.get(D1), dclass="c2_meter")) == ["f7"]
    assert p.u.current_session(D1) is None and p.u.session_for(D1) is None        # the session
    assert (svc.outcome(D1, sent), svc.outcome(D1, unsent)) == (b"UNKNOWN", b"CANCELLED")   # its commands
    assert svc.outgoing(D1) == []
    with pytest.raises(CommandError):
        svc.setpoint(D1, gid, 5, 30)                                       # its GRANT
    assert all(epochs(p)[alg] > e for alg, e in before.items())            # the zone keys it held
    with pytest.raises(TicketError):
        p.resume(old)                                                      # its ticket
    with pytest.raises(HandshakeError, match="class mismatch"):
        p.u.on_client_hello(D1, old.d.client_hello())                      # its old class
    new = Identity(p, D1, "c2_meter", old.kp)                              # the same key, the new class
    p.t += 1
    p.full(new)
    s = p.u.current_session(D1)
    assert s is not None and s.dclass == "c2_meter" and s.sid == new.d.session.sid
    assert svc.outgoing(D1) == []                                          # nothing of der_ctrl reaches it


def test_a_key_change_ends_the_old_keys_session_ticket_and_commands(tmp_path):
    p, old, sent, unsent, gid = before_the_change(tmp_path)
    kp, svc = HybridKeyPair.generate(), p.node.commands
    p.node.reprovision(replace(p.u.registry.get(D1), e2e_pk=kp.pk))      # same class: a replaced key
    assert p.u.current_session(D1) is None
    assert (svc.outcome(D1, sent), svc.outcome(D1, unsent)) == (b"UNKNOWN", b"CANCELLED")
    with pytest.raises(TicketError, match="re-provisioned"):
        p.resume(old)                                                      # only the provisioning floor stops it
    sh = p.u.on_client_hello(D1, old.d.client_hello())                     # answered (encapsulated to the NEW key) …
    with pytest.raises((HandshakeError, CryptoError)):
        old.d.on_server_hello(sh)                                          # … so the old key cannot complete it
    new = Identity(p, D1, "der_ctrl", kp)
    p.t += 1
    p.full(new)
    p.t += 1
    p.resume(new)                                                          # tickets issued after the change work
    assert p.u.current_session(D1).sid == new.d.session.sid
    with pytest.raises(CommandError):
        svc.setpoint(D1, gid, 5, 30)                                       # the old GRANT is not the new identity's
    seq = svc.issue(D1, b"AFTER", 600)
    [env] = svc.outgoing(D1)                                               # only the new command
    assert dec(new.proc.on_control(control_topic("der_ctrl", D1), env), 6)[4] == b"OK"
    assert new.applied == [b"AFTER"] and svc.outcome(D1, seq) is None     # OK once its status ACK arrives


def test_the_change_survives_a_restart(tmp_path):
    p, old, sent, unsent, gid = before_the_change(tmp_path)
    p.node.reprovision(replace(p.u.registry.get(D1), dclass="c2_meter"))
    changed_at = p.t
    p.restart()
    rec = p.u.registry.get(D1)
    assert (rec.dclass, rec.active, rec.provisioned_at) == ("c2_meter", True, changed_at)
    svc = p.node.commands
    assert (svc.outcome(D1, sent), svc.outcome(D1, unsent)) == (b"UNKNOWN", b"CANCELLED")
    p.t += 60
    with pytest.raises(TicketError):
        p.resume(old)
    new = Identity(p, D1, "c2_meter", old.kp)
    p.full(new)
    assert p.u.current_session(D1).dclass == "c2_meter"


def test_the_record_and_its_commands_change_together_or_not_at_all(tmp_path, monkeypatch):
    """One transaction: if the new record cannot be written, the commands closed just before are open again, so a
    restart never sees the old record without its commands (or the new record with them)."""
    p, old, sent, unsent, gid = before_the_change(tmp_path)

    def disk_full(rec):
        raise OSError("disk full")
    monkeypatch.setattr(p.u.registry, "_store", disk_full)
    with pytest.raises(OSError):
        p.node.reprovision(replace(p.u.registry.get(D1), dclass="c2_meter"))
    p.restart()
    assert p.u.registry.get(D1).dclass == "der_ctrl"
    assert p.node.commands.outcome(D1, unsent) is None                     # still open, as the record says


def test_the_registry_never_changes_a_device_by_overwriting_it(tmp_path):
    p = Plant(tmp_path)
    p.device(D1, "der_ctrl")
    rec = p.u.registry.get(D1)
    for changed in (replace(rec, dclass="c2_meter"), replace(rec, e2e_pk=HybridKeyPair.generate().pk),
                    replace(rec, active=False)):
        with pytest.raises(PolicyError, match="reprovision"):
            p.u.registry.add(changed)
    p.u.registry.add(rec)                                                  # the same record again: no change
    p.u.revoke_device(D1)
    with pytest.raises(PolicyError, match="reprovision"):
        p.u.registry.add(rec)                                              # re-activation is a re-provisioning
    with pytest.raises(PolicyError, match="not registered"):
        p.u.registry.reprovision(replace(rec, device_id=D2), p.t)


def test_the_utility_sends_the_remaining_members_new_keys_and_recompiles_the_acl(tmp_path):
    from test_utility_publish import utility
    p = Plant(tmp_path)
    d1, d2 = p.device(D1, "der_ctrl"), p.device(D2, "der_ctrl")
    p.full(d1)
    p.full(d2)
    p.node.zones.create("f7")
    p.node.zones.add_member("f7", D1)
    p.node.zones.add_member("f7", D2)
    u, paho = utility(p)
    seen = []
    u.acl_hook = lambda: seen.append(p.u.registry.get(D1).dclass)          # compiled from the registry
    u.reprovision_device(replace(p.u.registry.get(D1), dclass="c2_meter"))
    assert paho.topics() == [control_topic("der_ctrl", D2)]               # the remaining member's new key only
    assert dec(d2.proc.on_control(control_topic("der_ctrl", D2), paho.queued[0][1]), 6)[4] == b"OK"
    assert seen == ["c2_meter"] and not u.acl_failures
