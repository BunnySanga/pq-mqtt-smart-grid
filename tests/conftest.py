"""Shared fixtures: a valid v2.2 policy and an in-process world (utility + registry + devices).

Classes chosen to exercise both AEADs and both profiles (Master §5, §6.5):
  smart_meter  FULL,        AES-256-GCM,       resume PSK,     no unicast control
  der_ctrl     FULL,        ChaCha20-Poly1305, resume PSK_KEM, unicast control, CMD/GRANT/SETPOINT
  c2_meter     CONSTRAINED, ChaCha20-Poly1305, resume PSK,     max_packet 4096, 1 KiB TLS records
"""
from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pqgrid.e2e.handshake import DeviceEndpoint, UtilityEndpoint  # noqa: E402
from pqgrid.pasr import TicketIssuer  # noqa: E402
from pqgrid.policy import (ClassProfile, CmdType, Policy, Profile, Reconnect, ResumeMode, Rule, Tier,  # noqa: E402
                           decode_policy, encode_policy, validate)
from pqgrid.registry import DeviceRecord, Registry  # noqa: E402
from pqgrid.suite.aead import AeadAlg  # noqa: E402
from pqgrid.suite.hkem import HybridKeyPair  # noqa: E402
from pqgrid.suite.sig import mldsa_keygen, mldsa_public_bytes  # noqa: E402

def make_ca_der(name: str = "pqgrid-test-ca") -> bytes:
    """A real self-signed ECDSA P-256 CA certificate (DER): validator rule 10 accepts only CA certificates."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


TEST_CA_DER = make_ca_der()

RULES = (Rule("grid/+/+/telemetry", Tier.TELEMETRY), Rule("grid/+/+/alert", Tier.ALERT),
         Rule("grid/+/+/control", Tier.CONTROL), Rule("grid/dr/+/+/event", Tier.CONTROL))


def make_class(name: str, **over) -> ClassProfile:
    base = dict(name=name, profile=Profile.FULL, resume=ResumeMode.PSK, ticket_lifetime_s=86400,
                max_chain_age_s=604800, unicast_control=False, cmd_types=frozenset(), max_setpoint_rate=0,
                aead=AeadAlg.AES256GCM, tls_max_record=None, max_packet=65536, fota_chunk_size=16384,
                reconnect=Reconnect.PERSISTENT, reconnect_interval_s=0, backoff_base_s=2, backoff_cap_s=300,
                session_expiry_s=604800, keepalive_s=300, dup_window_s=120, pending_ttl_s=60, outbox_cap=4096)
    base.update(over)
    return ClassProfile(**base)


DEFAULT_CLASSES = {
    "smart_meter": make_class("smart_meter"),
    "der_ctrl": make_class("der_ctrl", resume=ResumeMode.PSK_KEM, unicast_control=True,
                           cmd_types=frozenset({CmdType.CMD, CmdType.GRANT, CmdType.SETPOINT}),
                           max_setpoint_rate=12, aead=AeadAlg.CHACHA20POLY1305),
    "c2_meter": make_class("c2_meter", profile=Profile.CONSTRAINED, aead=AeadAlg.CHACHA20POLY1305,
                           tls_max_record=1024, max_packet=4096, fota_chunk_size=3072,
                           reconnect=Reconnect.BATCH, reconnect_interval_s=21600),
}


def make_policy(utility_pk: bytes, cmd_pk: bytes, version: int = 1, classes=None, rules=RULES,
                **over) -> Policy:
    p = Policy(policy_id=over.pop("policy_id", "nitk-grid"), version=version, activate_at=over.pop("activate_at", 0),
               default_tier=over.pop("default_tier", Tier.CONTROL), rules=tuple(rules),
               classes=dict(classes or DEFAULT_CLASSES), utility_kem_pk=utility_pk, utility_cmd_pk=cmd_pk,
               ca_set=over.pop("ca_set", (TEST_CA_DER,)))
    assert not over, over
    return decode_policy(encode_policy(p))          # always go through the signed-bytes path


class World:
    """One utility, one registry, devices on demand; a controllable clock."""

    def __init__(self):
        self.t = 1_790_000_000.0
        self.u_static = HybridKeyPair.generate()
        self.cmd_sk = mldsa_keygen()
        self.policy = make_policy(self.u_static.pk, mldsa_public_bytes(self.cmd_sk))
        validate(self.policy)
        self.registry = Registry()
        self.tickets = TicketIssuer()
        self.utility = UtilityEndpoint(self.policy, self.u_static, self.registry, clock=lambda: self.t,
                                       tickets=self.tickets)

    def device(self, did: bytes, dclass: str, *, clock=None, policy=None, register=True) -> DeviceEndpoint:
        kp = HybridKeyPair.generate()
        if register:
            self.registry.add(DeviceRecord(did, dclass, kp.pk))
        return DeviceEndpoint(did, dclass, policy or self.policy, 1, kp, clock=clock or (lambda: self.t))

    def full(self, d: DeviceEndpoint, alerts=()):
        """Run CH → SH → DF(+alerts) → NT/FIN; returns (utility FinishedResult, acked msg_seqs)."""
        sh = self.utility.on_client_hello(d.id, d.client_hello())
        d.on_server_hello(sh)
        res = self.utility.on_finished(d.id, d.finished(list(alerts)))
        acked = d.on_final(res.final)
        return res, acked

    def resume(self, d: DeviceEndpoint, alerts=()):
        """Run RH → RS → DF(+alerts) → NT; returns (utility FinishedResult, acked msg_seqs)."""
        rs = self.utility.on_resume_hello(d.id, d.resume_hello())
        d.on_resume_server(rs)
        res = self.utility.on_finished(d.id, d.finished(list(alerts)))
        acked = d.on_final(res.final)
        return res, acked


@pytest.fixture
def world() -> World:
    return World()


def replace_class(policy: Policy, name: str, **over) -> dict:
    classes = dict(policy.classes)
    classes[name] = dataclasses.replace(classes[name], **over)
    return classes
