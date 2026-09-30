"""The devices' TLS trust anchors come from the signed policy's ca_set (Master §4.5 CA roll-over, §12 rule 10, K-4;
audit M-3). Before, ca_set was parsed and checked for being non-empty only, and the device's TLS context was built
from provisioning files: a policy could not move the trust anchors, so the specified CA roll-over did not exist."""
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import conftest
from pqgrid.errors import PolicyError, WireError
from pqgrid.mqtt.tls import device_context_from_policy
from pqgrid.policy import validate
from pqgrid.suite.hkem import HybridKeyPair
from pqgrid.suite.sig import mldsa_keygen, mldsa_public_bytes

KEYS = (HybridKeyPair.generate().pk, mldsa_public_bytes(mldsa_keygen()))


def _cert(ca: bool, key=None, name="x"):
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True).sign(key, hashes.SHA256()))
    return cert, key


@pytest.mark.parametrize("ca_set, ok", [
    ((conftest.TEST_CA_DER,), True),
    ((conftest.TEST_CA_DER, conftest.make_ca_der("next")), True),                  # current + next (roll-over)
    ((), False),
    ((b"placeholder-ca-der",), False),                                             # not a certificate
    ((_cert(ca=False)[0].public_bytes(serialization.Encoding.DER),), False),      # a leaf, not a CA
])
def test_rule_10_accepts_only_one_or_two_ca_certificates(ca_set, ok):
    p = conftest.make_policy(*KEYS, ca_set=ca_set)
    if ok:
        validate(p)
    else:
        with pytest.raises(PolicyError, match="rule 10"):
            validate(p)


def test_more_than_two_cas_are_refused_by_the_codec_already():
    with pytest.raises(WireError, match="too many items"):
        conftest.make_policy(*KEYS, ca_set=(conftest.TEST_CA_DER,) * 3)


def test_the_device_tls_context_trusts_exactly_the_policy_ca_set(tmp_path):
    leaf, key = _cert(ca=False, name="meter-0001")
    crt, pem = tmp_path / "d.crt", tmp_path / "d.key"
    crt.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    nxt = conftest.make_ca_der("next")
    for ca_set in [(conftest.TEST_CA_DER,), (conftest.TEST_CA_DER, nxt)]:
        ctx = device_context_from_policy(conftest.make_policy(*KEYS, ca_set=ca_set), str(crt), str(pem))
        assert sorted(ctx.get_ca_certs(binary_form=True)) == sorted(ca_set)
        assert ctx.check_hostname and ctx.minimum_version.name == "TLSv1_3"
