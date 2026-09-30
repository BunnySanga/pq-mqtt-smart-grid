"""Hybrid KEM: X25519 + ML-KEM-768 with the X-Wing combiner (Master §6.2, §6.4, §7.1–§7.4).

    pk = ek_ML-KEM-768 (1,184 B) ‖ pk_X25519 (32 B)                     = 1,216 B
    ct = ct_ML-KEM-768 (1,088 B) ‖ ephemeral pk_X25519 (32 B)           = 1,120 B
    ss = SHA3-256(ss_ML-KEM ‖ ss_X25519 ‖ ct_X25519 ‖ pk_X25519 ‖ "\\.//^\\")  = 32 B

The shared secret stays secure while either X25519 or ML-KEM-768 holds.
Private-key storage form (96 B): ML-KEM-768 seed (64 B) ‖ X25519 private key (32 B).
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

from ..errors import CryptoError
from .kdf import sha3_256

MLKEM_EK_LEN, MLKEM_CT_LEN, MLKEM_SEED_LEN = 1184, 1088, 64
X_LEN = 32
PK_LEN = MLKEM_EK_LEN + X_LEN            # 1,216
CT_LEN = MLKEM_CT_LEN + X_LEN            # 1,120
SS_LEN = 32
SK_STORAGE_LEN = MLKEM_SEED_LEN + X_LEN  # 96
XWING_LABEL = b"\\.//^\\"                # the X-Wing label: \.//^\

_RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)
_RAW_PRIV = (serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


@dataclass
class HybridKeyPair:
    """An X25519 + ML-KEM-768 key pair. Ephemeral pairs live for one handshake; static pairs are stored."""
    _m: mlkem.MLKEM768PrivateKey
    _x: x25519.X25519PrivateKey

    @classmethod
    def generate(cls) -> "HybridKeyPair":
        return cls(mlkem.MLKEM768PrivateKey.generate(), x25519.X25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, blob: bytes) -> "HybridKeyPair":
        if len(blob) != SK_STORAGE_LEN:
            raise CryptoError("hybrid private key must be 96 bytes")
        try:
            return cls(mlkem.MLKEM768PrivateKey.from_seed_bytes(bytes(blob[:MLKEM_SEED_LEN])),
                       x25519.X25519PrivateKey.from_private_bytes(bytes(blob[MLKEM_SEED_LEN:])))
        except ValueError as e:
            raise CryptoError("invalid hybrid private key") from e

    def private_bytes(self) -> bytes:
        return self._m.private_bytes_raw() + self._x.private_bytes(*_RAW_PRIV)

    @property
    def pk_x(self) -> bytes:
        return self._x.public_key().public_bytes(*_RAW)

    @property
    def pk(self) -> bytes:
        return self._m.public_key().public_bytes_raw() + self.pk_x


def encaps(pk: bytes) -> tuple[bytes, bytes]:
    """Encapsulate to a 1,216-byte hybrid public key. Returns (shared secret, ciphertext)."""
    if len(pk) != PK_LEN:
        raise CryptoError("hybrid public key must be 1,216 bytes")
    pk_m, pk_x = pk[:MLKEM_EK_LEN], pk[MLKEM_EK_LEN:]
    try:
        ss_m, ct_m = mlkem.MLKEM768PublicKey.from_public_bytes(pk_m).encapsulate()   # returns (ss, ct)
        eph = x25519.X25519PrivateKey.generate()
        ct_x = eph.public_key().public_bytes(*_RAW)
        ss_x = eph.exchange(x25519.X25519PublicKey.from_public_bytes(pk_x))
    except ValueError as e:                      # malformed ek, or an X25519 low-order point
        raise CryptoError("encapsulation failed") from e
    return _combine(ss_m, ss_x, ct_x, pk_x), ct_m + ct_x


def decaps(kp: HybridKeyPair, ct: bytes) -> bytes:
    """Decapsulate a 1,120-byte hybrid ciphertext with our key pair."""
    if len(ct) != CT_LEN:
        raise CryptoError("hybrid ciphertext must be 1,120 bytes")
    ct_m, ct_x = ct[:MLKEM_CT_LEN], ct[MLKEM_CT_LEN:]
    try:
        ss_m = kp._m.decapsulate(ct_m)           # ML-KEM implicit rejection: never reports why
        ss_x = kp._x.exchange(x25519.X25519PublicKey.from_public_bytes(ct_x))
    except ValueError as e:
        raise CryptoError("decapsulation failed") from e
    return _combine(ss_m, ss_x, ct_x, kp.pk_x)


def _combine(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    return sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL)
