"""Crypto suite: sizes, round-trips, tamper behaviour, and structure checks (Master §6, §7)."""
import shutil
import subprocess

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

from pqgrid.errors import CryptoError
from pqgrid.suite import aead, hkem
from pqgrid.suite.kdf import h, hkdf_expand, hkdf_extract, sha3_256
from pqgrid.suite.sig import (MLDSA65_SIG_LEN, SLH_PK_LEN, SLH_SIG_LEN, mldsa_keygen, mldsa_public_bytes,
                              mldsa_sign, mldsa_verify, slh_available, slh_verify)


# ------------------------------------------------------------------------------------------------ hybrid KEM
def test_hkem_sizes_and_roundtrip():
    kp = hkem.HybridKeyPair.generate()
    assert len(kp.pk) == 1216
    ss, ct = hkem.encaps(kp.pk)
    assert len(ct) == 1120 and len(ss) == 32
    assert hkem.decaps(kp, ct) == ss


def test_hkem_private_key_storage_is_96_bytes_and_restores():
    kp = hkem.HybridKeyPair.generate()
    blob = kp.private_bytes()
    assert len(blob) == 96
    kp2 = hkem.HybridKeyPair.from_private_bytes(blob)
    assert kp2.pk == kp.pk
    ss, ct = hkem.encaps(kp.pk)
    assert hkem.decaps(kp2, ct) == ss


def test_xwing_combiner_structure():
    """ss must equal SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label), computed here independently."""
    kp = hkem.HybridKeyPair.generate()
    pk_m, pk_x = kp.pk[:1184], kp.pk[1184:]
    ss_m, ct_m = mlkem.MLKEM768PublicKey.from_public_bytes(pk_m).encapsulate()
    eph = x25519.X25519PrivateKey.generate()
    ct_x = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ss_x = eph.exchange(x25519.X25519PublicKey.from_public_bytes(pk_x))
    expected = sha3_256(ss_m + ss_x + ct_x + pk_x + b"\\.//^\\")
    assert hkem.decaps(kp, ct_m + ct_x) == expected


@pytest.mark.parametrize("where", [0, 500, 1087, 1088, 1119])
def test_hkem_tampered_ciphertext_gives_a_different_secret(where):
    kp = hkem.HybridKeyPair.generate()
    ss, ct = hkem.encaps(kp.pk)
    bad = bytearray(ct)
    bad[where] ^= 1
    try:
        assert hkem.decaps(kp, bytes(bad)) != ss        # ML-KEM implicit rejection / X25519 change
    except CryptoError:
        pass                                            # or an outright refusal (e.g. low-order point)


def test_hkem_rejects_wrong_lengths():
    kp = hkem.HybridKeyPair.generate()
    with pytest.raises(CryptoError):
        hkem.encaps(kp.pk[:-1])
    with pytest.raises(CryptoError):
        hkem.decaps(kp, b"\x00" * 1119)
    with pytest.raises(CryptoError):
        hkem.HybridKeyPair.from_private_bytes(b"\x00" * 95)


# ---------------------------------------------------------------------------------------------------- AEAD
@pytest.mark.parametrize("alg", list(aead.AeadAlg))
def test_aead_roundtrip_and_tamper(alg):
    key, nonce = b"k" * 32, aead.counter_nonce(aead.DIR_ALERT_UP, 7)
    ct = aead.seal(alg, key, nonce, b"payload", b"aad")
    assert len(ct) == len(b"payload") + 16
    assert aead.open_(alg, key, nonce, ct, b"aad") == b"payload"
    for bad in (ct[:-1] + bytes([ct[-1] ^ 1]), ct):
        with pytest.raises(CryptoError):
            aead.open_(alg, key, nonce, bad, b"AAD")     # wrong AAD or wrong tag


def test_counter_nonce_layout():
    n = aead.counter_nonce(aead.DIR_CONTROL_DOWN, 0x0102)
    assert n == b"\x02\x00\x00\x00" + (0x0102).to_bytes(8, "big") and len(n) == 12
    with pytest.raises(CryptoError):
        aead.counter_nonce(aead.DIR_ALERT_UP, 0)         # counters start at 1
    with pytest.raises(CryptoError):
        aead.counter_nonce(0x09, 1)


# ------------------------------------------------------------------------------------------------ KDF / hash
def test_hkdf_rfc5869_case1():
    prk = hkdf_extract(bytes(range(13)), b"\x0b" * 22)
    assert prk.hex() == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    okm = hkdf_expand(prk, bytes(range(0xF0, 0xFA)), 42)
    assert okm.hex() == ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865")


def test_transcript_hash_is_length_prefixed():
    assert h(b"ab", b"c") != h(b"a", b"bc")


# ------------------------------------------------------------------------------------------------ signatures
def test_mldsa65_sign_verify():
    sk = mldsa_keygen()
    pk = mldsa_public_bytes(sk)
    sig = mldsa_sign(sk, b"pqgrid/v2/cmd")
    assert len(sig) == MLDSA65_SIG_LEN
    assert mldsa_verify(pk, sig, b"pqgrid/v2/cmd")
    assert not mldsa_verify(pk, sig, b"pqgrid/v2/cmX")
    assert not mldsa_verify(pk[:-1], sig, b"pqgrid/v2/cmd")


def _openssl_slh():
    exe = shutil.which("openssl")
    if not exe or not slh_available():
        return None
    out = subprocess.run([exe, "list", "-signature-algorithms"], capture_output=True, text=True).stdout
    return exe if "SLH-DSA-SHA2-128s" in out else None


@pytest.mark.skipif(_openssl_slh() is None, reason="OpenSSL >= 3.5 with SLH-DSA not available")
def test_slh_dsa_128s_verify_against_openssl(tmp_path):
    exe = _openssl_slh()
    key, msg, sig = tmp_path / "k.pem", tmp_path / "m.bin", tmp_path / "s.bin"
    subprocess.run([exe, "genpkey", "-algorithm", "SLH-DSA-SHA2-128s", "-out", key], check=True)
    der = subprocess.run([exe, "pkey", "-in", key, "-pubout", "-outform", "DER"], check=True,
                         capture_output=True).stdout
    pk = der[-SLH_PK_LEN:]
    msg.write_bytes(b"PQFW2 manifest bytes")
    subprocess.run([exe, "pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", msg, "-out", sig], check=True)
    s = sig.read_bytes()
    assert len(s) == SLH_SIG_LEN
    assert slh_verify(pk, s, b"PQFW2 manifest bytes")
    assert not slh_verify(pk, s, b"PQFW2 manifest bytez")
    bad = bytearray(s)
    bad[100] ^= 1
    assert not slh_verify(pk, bytes(bad), b"PQFW2 manifest bytes")
    assert not slh_verify(bytes(32), s, b"PQFW2 manifest bytes")
