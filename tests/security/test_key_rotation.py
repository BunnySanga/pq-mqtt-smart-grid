"""Utility key rotation through the signed policy (Master §12 Policy Updates, §4.7, §23.7; DR-051; audit H-1).

The utility operates with the private keys its ACTIVE policy names, taken from its keyring. Everything here runs the
production utility (open_utility + UtilityMqtt: the database, the endpoint, the command service and the zone
manager) with station-signed policies, and real devices (DeviceEndpoint, CommandProcessor) that trust only their
installed policy. Before DR-051 activating a policy with new keys succeeded while the utility kept its old keys, so
no device could establish (audit repro): these tests would all fail on that code."""
import ssl

import pytest

import conftest
from pqgrid.commands import CommandProcessor
from pqgrid.commands.codec import bcast_signed_input, cmd_signed_input
from pqgrid.e2e.envelopes import control_topic
from pqgrid.e2e.handshake import DeviceEndpoint
from pqgrid.errors import HandshakeError, KeyringError, PolicyError, PolicyMismatchError
from pqgrid.fota.artifact import POLICY
from pqgrid.fota.publisher import part_payload_budget
from pqgrid.fota.station import Station, find_openssl
from pqgrid.mqtt.utility_node import UtilityMqtt
from pqgrid.persistence.utility_db import open_utility
from pqgrid.policy import encode_policy, validate
from pqgrid.registry import DeviceRecord
from pqgrid.suite.hkem import HybridKeyPair
from pqgrid.suite.sig import mldsa_keygen, mldsa_private_bytes, mldsa_public_bytes, mldsa_verify

pytestmark = pytest.mark.skipif(find_openssl() is None,
                                reason="needs OpenSSL >= 3.5 for SLH-DSA: runs in the Docker test image")
T0 = 1_790_000_000
DID, CLS, TARGET = b"der-0001", "der_ctrl", "P_ACTIVE_W"


class Rig:
    """One restartable utility process (its database survives), a station, and a registered DER device."""

    def __init__(self, tmp):
        self.tmp, self.now = tmp, [float(T0)]
        self.kem1, self.cmd1 = HybridKeyPair.generate(), mldsa_keygen()
        self.v1 = conftest.make_policy(self.kem1.pk, mldsa_public_bytes(self.cmd1))
        validate(self.v1)
        self.station = Station(str(tmp))
        self.dev_kp = HybridKeyPair.generate()
        self.open()
        self.node.endpoint.registry.add(DeviceRecord(DID, CLS, self.dev_kp.pk))

    def open(self, kem=None, cmd=None, bootstrap=None):
        self.node = open_utility(f"{self.tmp}/u.db", bootstrap or self.v1, kem or self.kem1, cmd or self.cmd1,
                                 lambda: self.now[0])
        self.u = UtilityMqtt(self.node, ssl.create_default_context(), "localhost", 1, clock=lambda: self.now[0])

    def restart(self, **kw):
        self.node.db.close()
        self.open(**kw)

    def policy(self, version: int, kem=None, cmd=None, activate_at: int = T0):
        p = conftest.make_policy((kem or self.kem1).pk, mldsa_public_bytes(cmd or self.cmd1), version=version,
                                 activate_at=activate_at)
        prof = p.profile("smart_meter")
        art = self.station.build(POLICY, "smart_meter", version, encode_policy(p), prof.fota_chunk_size,
                                 part_payload_budget(prof.max_packet, "smart_meter", POLICY, version),
                                 activate_at=activate_at)
        return p, (art.signed, art.payload, self.station.anchors)

    def device(self, policy) -> tuple[DeviceEndpoint, CommandProcessor, list]:
        d = DeviceEndpoint(DID, CLS, policy, 1, self.dev_kp, clock=lambda: self.now[0])
        applied: list = []
        return d, CommandProcessor(d, applied.append, lambda t, v: None, targets={TARGET}), applied

    def establish(self, d: DeviceEndpoint) -> None:
        ep = self.node.endpoint
        d.on_server_hello(ep.on_client_hello(DID, d.client_hello()))
        d.on_final(ep.on_finished(DID, d.finished()).final)

    def deliver(self, proc: CommandProcessor) -> list[bytes]:
        """Every queued command for the device's live session, through the device, settled at the utility."""
        topic = control_topic(CLS, DID)
        return [self.node.commands.on_status(proc.on_control(topic, env))[2]
                for env in self.node.commands.outgoing(DID)]

    def keys(self) -> tuple[bytes, bytes]:
        return self.node.endpoint.static.pk, mldsa_public_bytes(self.node.commands.cmd_key)


@pytest.fixture
def rig(tmp_path):
    r = Rig(tmp_path)
    yield r
    r.node.db.close()


def _check_consistent(rig: Rig) -> None:
    """DR-051 invariant (L): the keys in use are exactly the ones the active policy names."""
    assert rig.node.keys_match_policy()
    p = rig.node.endpoint.policy
    assert rig.keys() == (p.utility_kem_pk, p.utility_cmd_pk)


# ------------------------------------------------------------------------------------------- A, B, C: rotations
@pytest.mark.parametrize("rotate", ["kem", "cmd", "both"])
def test_rotation_through_a_policy_switches_the_keys_the_utility_uses(rig: Rig, rotate):
    kem2 = HybridKeyPair.generate() if rotate in ("kem", "both") else None
    cmd2 = mldsa_keygen() if rotate in ("cmd", "both") else None
    v2, art = rig.policy(2, kem=kem2, cmd=cmd2)
    rig.u.prepare_keys(kem=kem2, cmd=cmd2)
    rig.u.schedule_policy(*art)
    rig.u.tick()                                                       # due at T0: activated by the loop
    assert rig.node.endpoint.policy.version == 2
    _check_consistent(rig)
    old, _, _ = rig.device(rig.v1)                                     # a device still on v1 is refused …
    with pytest.raises(PolicyMismatchError):
        rig.node.endpoint.on_client_hello(DID, old.client_hello())
    d, proc, applied = rig.device(v2)                                  # … one on v2 establishes with the new
    rig.establish(d)                                                   # E2E key and accepts a command signed
    assert d.confirmed                                                 # with the new command key
    seq = rig.node.commands.issue(DID, b"CURTAIL 50%", 300)
    assert rig.deliver(proc) == [b"OK"] and applied == [b"CURTAIL 50%"]
    assert rig.node.commands.outcome(DID, seq) == b"OK"


# -------------------------------------------------------------------------------------- D, E: keys not available
def test_a_policy_whose_private_keys_are_not_held_is_refused_and_nothing_changes(rig: Rig):
    kem2, cmd2 = HybridKeyPair.generate(), mldsa_keygen()
    _, art = rig.policy(2, kem=kem2, cmd=cmd2)
    before = rig.keys()
    with pytest.raises(KeyringError, match="no private KEM key"):
        rig.u.schedule_policy(*art)
    with pytest.raises(KeyringError, match="no private KEM key"):
        rig.u.activate_policy(*art)
    assert rig.node.db.load_policy("scheduled") is None and rig.node.db.load_policy("active") is None
    assert rig.node.endpoint.policy.version == 1 and rig.keys() == before
    rig.u.prepare_keys(kem=kem2)                                       # half of it is still not enough
    with pytest.raises(KeyringError, match="no private command key"):
        rig.u.activate_policy(*art)
    assert rig.node.endpoint.policy.version == 1 and rig.keys() == before
    d, _, _ = rig.device(rig.v1)
    rig.establish(d)                                                   # the old state still serves the fleet
    assert d.confirmed


def test_a_prepared_key_that_does_not_match_the_expected_public_key_is_refused(rig: Rig):
    kem2, cmd2, wrong_kem, wrong_cmd = HybridKeyPair.generate(), mldsa_keygen(), HybridKeyPair.generate(), mldsa_keygen()
    with pytest.raises(KeyringError, match="does not match the expected public key"):
        rig.u.prepare_keys(kem=wrong_kem, cmd=cmd2, expect_kem_pk=kem2.pk)
    with pytest.raises(KeyringError, match="does not match the expected public key"):
        rig.u.prepare_keys(kem=kem2, cmd=wrong_cmd, expect_cmd_pk=mldsa_public_bytes(cmd2))
    _, art = rig.policy(2, kem=kem2, cmd=cmd2)
    with pytest.raises(KeyringError):                                  # nothing was stored by the refusals
        rig.u.schedule_policy(*art)
    rig.u.prepare_keys(kem=wrong_kem, cmd=wrong_cmd)                   # unrelated keys do not help either
    with pytest.raises(KeyringError):
        rig.u.schedule_policy(*art)
    _check_consistent(rig)


# --------------------------------------------------------------------------------- F, G: restarts after rotation
def test_utility_and_device_restarts_after_a_rotation_keep_the_new_keys(rig: Rig):
    kem2, cmd2 = HybridKeyPair.generate(), mldsa_keygen()
    v2, art = rig.policy(2, kem=kem2, cmd=cmd2)
    rig.u.prepare_keys(kem=kem2, cmd=cmd2)
    assert rig.u.activate_policy(*art)
    rig.restart()                                                      # bootstrap config (v1, old keys) again:
    assert rig.node.endpoint.policy.version == 2                       # the active policy and its keys resume
    _check_consistent(rig)
    d, proc, applied = rig.device(v2)                                  # a (re)booted device on its installed v2
    rig.establish(d)
    rig.node.commands.issue(DID, b"TRIP", 300)
    assert rig.deliver(proc) == [b"OK"] and applied == [b"TRIP"]
    d2, proc2, applied2 = rig.device(v2)                               # device reboot: new endpoint, same keys
    rig.now[0] += 1
    rig.establish(d2)
    assert d2.confirmed and applied2 == []                             # nothing re-applied


# ------------------------------------------------------------------------ H, I: crash around the activation write
def test_a_crash_before_the_activation_is_persisted_leaves_the_old_policy_and_keys(rig: Rig, monkeypatch):
    kem2, cmd2 = HybridKeyPair.generate(), mldsa_keygen()
    _, art = rig.policy(2, kem=kem2, cmd=cmd2)
    rig.u.prepare_keys(kem=kem2, cmd=cmd2)
    rig.u.schedule_policy(*art)
    real = rig.node.db.save_policy

    def crash(slot, *a):
        if slot == "active":
            raise OSError("power lost while writing the active policy")
        return real(slot, *a)
    monkeypatch.setattr(rig.node.db, "save_policy", crash)
    with pytest.raises(OSError):
        rig.u.activate_policy(*art)
    rig.restart()
    assert rig.node.endpoint.policy.version == 1
    _check_consistent(rig)
    d, _, _ = rig.device(rig.v1)
    rig.establish(d)
    assert d.confirmed
    rig.u.tick()                                                       # the scheduled rotation still completes
    assert rig.node.endpoint.policy.version == 2
    _check_consistent(rig)


def test_a_crash_right_after_the_activation_is_persisted_resumes_the_new_policy_and_keys(rig: Rig, monkeypatch):
    kem2, cmd2 = HybridKeyPair.generate(), mldsa_keygen()
    v2, art = rig.policy(2, kem=kem2, cmd=cmd2)
    rig.u.prepare_keys(kem=kem2, cmd=cmd2)

    def crash(*a, **k):
        raise OSError("power lost after the policy was written")
    monkeypatch.setattr(rig.node.endpoint, "install_policy", crash)
    with pytest.raises(OSError):
        rig.u.activate_policy(*art)
    rig.restart()
    assert rig.node.endpoint.policy.version == 2
    _check_consistent(rig)
    d, _, _ = rig.device(v2)
    rig.establish(d)
    assert d.confirmed


# ------------------------------------------------------------------------ J: bootstrap key and policy disagree
def test_a_utility_is_never_started_with_keys_its_policy_does_not_name(rig: Rig):
    with pytest.raises(KeyringError, match="no private KEM key"):      # bootstrap policy v1, another E2E key
        open_utility(f"{rig.tmp}/fresh.db", rig.v1, HybridKeyPair.generate(), rig.cmd1, lambda: T0)
    kem2 = HybridKeyPair.generate()
    _, art = rig.policy(2, kem=kem2)
    rig.u.prepare_keys(kem=kem2)
    assert rig.u.activate_policy(*art)
    rig.node.db.execute("DELETE FROM utility_keys WHERE kind = 'kem' AND pk = ?", (kem2.pk,))
    rig.node.db.close()
    with pytest.raises(KeyringError, match="no private KEM key"):      # the active policy's key is gone:
        rig.open()                                                     # refused, never a silent lock-out
    with pytest.raises(HandshakeError):
        rig.node.endpoint.install_policy(rig.v1, static=HybridKeyPair.generate())


# --------------------------------------------------------------- K: commands and DR events queued across a rotation
def test_commands_and_dr_events_queued_before_a_command_key_rotation_are_signed_with_the_new_key(rig: Rig):
    cmd2 = mldsa_keygen()
    v2, art = rig.policy(2, cmd=cmd2)
    zm = rig.node.zones
    zm.create("f7")
    zm.add_member("f7", DID)
    seq = rig.node.commands.issue(DID, b"CLOSE BREAKER 3", 3600, idempotent=True)   # device offline: queued
    zm.publish("f7", b"SHED 20%", 3600)                                              # retained for re-send (M4)
    rig.u.prepare_keys(cmd=cmd2)
    assert rig.u.activate_policy(*art)
    d, proc, applied = rig.device(v2)
    rig.establish(d)
    assert rig.deliver(proc) == [b"OK"] and applied == [b"CLOSE BREAKER 3"]
    assert rig.node.commands.outcome(DID, seq) == b"OK"
    for z in zm.zonekeys_for(DID):                                     # the zone key, then the re-sent event,
        proc.on_control(control_topic(CLS, DID), z)                    # opened and verified by the device with
    events = [proc.zones.open_resent(e) for e in zm.resend_for(DID)]   # the v2 command key
    assert events == [("f7", b"SHED 20%")]
    rig.restart()                                                      # the new σ was stored: a redelivery after
    ev = rig.node.zones.zones["f7"].events[0]                          # a restart carries it unchanged
    assert mldsa_verify(mldsa_public_bytes(cmd2), ev.sig, bcast_signed_input("f7", ev.bseq, ev.expires_at, ev.event))
    q = rig.node.commands.store.get(DID, seq)
    assert mldsa_verify(mldsa_public_bytes(cmd2), q.cmd.sig,
                        cmd_signed_input(DID, control_topic(CLS, DID), seq, q.cmd.expires_at, True, q.cmd.command))


# ------------------------------------------------------------------------ M, N: duplicate activation and rollback
def test_duplicate_activation_and_an_older_policy_change_nothing(rig: Rig):
    kem2, cmd2 = HybridKeyPair.generate(), mldsa_keygen()
    _, art2 = rig.policy(2, kem=kem2, cmd=cmd2)
    rig.u.prepare_keys(kem=kem2, cmd=cmd2)
    assert rig.u.activate_policy(*art2)
    keys = rig.keys()
    with pytest.raises(PolicyError, match="rule 5"):                   # the same policy again
        rig.u.activate_policy(*art2)
    rig.node.db.save_policy("scheduled", *art2, frozenset())           # a duplicate left scheduled (e.g. restart)
    rig.restart()
    rig.u.tick()
    assert rig.node.db.load_policy("scheduled") is None and rig.keys() == keys
    _, art1b = rig.policy(1)                                           # a rollback to the old keys
    with pytest.raises(PolicyError, match="rule 5"):
        rig.u.activate_policy(*art1b)
    assert rig.node.endpoint.policy.version == 2 and rig.keys() == keys
    _check_consistent(rig)


# --------------------------------------------------------------------------------------- private keys stay private
def test_private_keys_never_appear_in_reprs_or_diagnostics(rig: Rig):
    kem2, cmd2 = HybridKeyPair.generate(), mldsa_keygen()
    rig.u.prepare_keys(kem=kem2, cmd=cmd2)
    secrets = [kem2.private_bytes().hex(), mldsa_private_bytes(cmd2).hex(), rig.kem1.private_bytes().hex()]
    text = repr(rig.node.keyring)
    _, art = rig.policy(3, kem=HybridKeyPair.generate())
    try:
        rig.u.schedule_policy(*art)
    except KeyringError as e:
        text += str(e)
    assert "no private KEM key" in text
    assert not any(s in text or s[:16] in text for s in secrets)


def test_a_hello_under_a_retired_key_is_only_recognised_never_established(rig: Rig):
    """After an E2E key rotation the utility still recognises a v1 device's hello (so E-4 can send it v2), but a
    hello under the retired key that claims the CURRENT policy is refused: the old key never establishes a session."""
    kem2 = HybridKeyPair.generate()
    v2, art = rig.policy(2, kem=kem2)
    rig.u.prepare_keys(kem=kem2)
    assert rig.u.activate_policy(*art)
    old, _, _ = rig.device(rig.v1)
    with pytest.raises(PolicyMismatchError, match="retired utility E2E key"):
        rig.node.endpoint.on_client_hello(DID, old.client_hello())
    forged_policy = conftest.make_policy(rig.kem1.pk, mldsa_public_bytes(rig.cmd1), version=2)
    assert forged_policy.info() == v2.info()                             # current POLICY_INFO, retired key
    forged, _, _ = rig.device(forged_policy)
    with pytest.raises(HandshakeError, match="client hello failed authentication") as e:
        rig.node.endpoint.on_client_hello(DID, forged.client_hello())
    assert not isinstance(e.value, PolicyMismatchError)
    assert rig.node.endpoint.session_for(DID) is None
