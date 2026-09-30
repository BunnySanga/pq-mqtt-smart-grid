"""AEAD selected per device class, the same at the TLS and E2E layers (Master §6.5, §8.4, DR-003).

Keys are 32 bytes, nonces 12 bytes, tags 16 bytes. Traffic nonces are counters (Master §9.7):
    nonce = direction (1 B) ‖ 0x000000 ‖ msg_seq (8 B, big-endian)
Session keys and their counters live only in RAM and die together (I-6), so a nonce never repeats under a key.
"""
from __future__ import annotations

from enum import Enum

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from ..errors import CryptoError

KEY_LEN, NONCE_LEN, TAG_LEN = 32, 12, 16

DIR_ALERT_UP = 0x01       # device → utility ALERT envelopes (Master §11)
DIR_CONTROL_DOWN = 0x02   # utility → device CONTROL envelopes (Master §13.1)


class AeadAlg(str, Enum):
    AES256GCM = "AES256GCM"
    CHACHA20POLY1305 = "CHACHA20POLY1305"


def _cipher(alg: AeadAlg, key: bytes):
    if len(key) != KEY_LEN:
        raise CryptoError("AEAD key must be 32 bytes")
    if alg is AeadAlg.AES256GCM:
        return AESGCM(key)
    if alg is AeadAlg.CHACHA20POLY1305:
        return ChaCha20Poly1305(key)
    raise CryptoError(f"unknown AEAD {alg!r}")


def seal(alg: AeadAlg, key: bytes, nonce: bytes, pt: bytes, aad: bytes) -> bytes:
    if len(nonce) != NONCE_LEN:
        raise CryptoError("AEAD nonce must be 12 bytes")
    return _cipher(alg, key).encrypt(nonce, pt, aad)


def open_(alg: AeadAlg, key: bytes, nonce: bytes, ct: bytes, aad: bytes) -> bytes:
    if len(nonce) != NONCE_LEN:
        raise CryptoError("AEAD nonce must be 12 bytes")
    if len(ct) < TAG_LEN:
        raise CryptoError("ciphertext shorter than the tag")
    try:
        return _cipher(alg, key).decrypt(nonce, ct, aad)
    except InvalidTag as e:
        raise CryptoError("authentication failed") from e


def counter_nonce(direction: int, msg_seq: int) -> bytes:
    """Master §9.7: direction ‖ 000 ‖ seq. `msg_seq` is the per-session, per-direction counter."""
    if direction not in (DIR_ALERT_UP, DIR_CONTROL_DOWN):
        raise CryptoError("unknown nonce direction")
    if not 0 < msg_seq < 1 << 64:
        raise CryptoError("message sequence out of range")
    return bytes([direction]) + b"\x00\x00\x00" + msg_seq.to_bytes(8, "big")
