"""Signatures (Master §7.6, §7.7).

* ML-DSA-65 (FIPS 204): the utility signs CMD and GRANT, the device verifies (used from slice 3).
* SLH-DSA-SHA2-128s (FIPS 205): the offline station signs artifacts, the device verifies. `cryptography`
  does not provide SLH-DSA, so verification calls OpenSSL >= 3.5 through ctypes (the approach validated in
  design-validation). Signing belongs to the offline station and is not part of the device code.

Library discovery never falls back to macOS's /usr/lib/libcrypto.dylib, which aborts the process when
loaded directly. Set PQGRID_LIBCRYPTO to override.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa

from ..errors import CryptoError

MLDSA65_PK_LEN, MLDSA65_SIG_LEN = 1952, 3309
SLH_ALG = "SLH-DSA-SHA2-128s"
SLH_PK_LEN, SLH_SIG_LEN = 32, 7856


# ----------------------------------------------------------------------------------------------- ML-DSA-65
def mldsa_keygen() -> mldsa.MLDSA65PrivateKey:
    return mldsa.MLDSA65PrivateKey.generate()


def mldsa_public_bytes(sk: mldsa.MLDSA65PrivateKey) -> bytes:
    return sk.public_key().public_bytes_raw()


def mldsa_private_bytes(sk: mldsa.MLDSA65PrivateKey) -> bytes:
    """The 32-byte seed (FIPS 204 ξ) from which the key pair is re-derived: the storage form of the command key."""
    return sk.private_bytes_raw()


def mldsa_from_private_bytes(seed: bytes) -> mldsa.MLDSA65PrivateKey:
    try:
        return mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes(seed))
    except ValueError as e:
        raise CryptoError("invalid ML-DSA-65 private key") from e


def mldsa_sign(sk: mldsa.MLDSA65PrivateKey, msg: bytes) -> bytes:
    return sk.sign(msg)


def mldsa_verify(pk: bytes, sig: bytes, msg: bytes) -> bool:
    if len(pk) != MLDSA65_PK_LEN or len(sig) != MLDSA65_SIG_LEN:
        return False
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(pk).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


# --------------------------------------------------------------------------------------- SLH-DSA-SHA2-128s
_LIB = None


def _candidates() -> list[str]:
    env = os.environ.get("PQGRID_LIBCRYPTO")
    if env:
        return [env]
    if sys.platform == "darwin":
        return ["/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib", "/usr/local/opt/openssl@3/lib/libcrypto.3.dylib"]
    found = ctypes.util.find_library("crypto")
    return [found] if found else []


def _lib():
    global _LIB
    if _LIB is not None:
        return _LIB
    for path in _candidates():
        if not path or (os.path.isabs(path) and not os.path.exists(path)):
            continue
        try:
            c = ctypes.CDLL(path)
        except OSError:
            continue
        if not hasattr(c, "EVP_PKEY_new_raw_public_key_ex"):
            continue
        c.OpenSSL_version_num.restype = ctypes.c_ulong
        if c.OpenSSL_version_num() < 0x30500000:
            continue
        c.EVP_PKEY_new_raw_public_key_ex.restype = ctypes.c_void_p
        c.EVP_PKEY_new_raw_public_key_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
                                                     ctypes.c_char_p, ctypes.c_size_t]
        c.EVP_MD_CTX_new.restype = ctypes.c_void_p
        c.EVP_DigestVerifyInit_ex.restype = ctypes.c_int
        c.EVP_DigestVerifyInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p,
                                              ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p]
        c.EVP_DigestVerify.restype = ctypes.c_int
        c.EVP_DigestVerify.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,
                                       ctypes.c_size_t]
        c.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]
        c.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
        c.ERR_clear_error.restype = None
        _LIB = c
        return c
    raise CryptoError("no OpenSSL >= 3.5 libcrypto found for SLH-DSA (set PQGRID_LIBCRYPTO)")


def slh_available() -> bool:
    try:
        _lib()
        return True
    except CryptoError:
        return False


def slh_verify(pk: bytes, sig: bytes, msg: bytes) -> bool:
    """Verify an SLH-DSA-SHA2-128s signature (empty context string, as `openssl pkeyutl -sign -rawin`)."""
    if len(pk) != SLH_PK_LEN or len(sig) != SLH_SIG_LEN:
        return False
    c = _lib()
    key = c.EVP_PKEY_new_raw_public_key_ex(None, SLH_ALG.encode(), None, pk, len(pk))
    if not key:
        c.ERR_clear_error()
        return False
    ctx = c.EVP_MD_CTX_new()
    if not ctx:                                                  # allocation failed: never pass NULL on
        c.EVP_PKEY_free(key)
        c.ERR_clear_error()
        raise CryptoError("OpenSSL could not allocate a digest context: signature not verified")
    try:
        ok = (c.EVP_DigestVerifyInit_ex(ctx, None, None, None, None, key, None) == 1
              and c.EVP_DigestVerify(ctx, sig, len(sig), msg, len(msg)) == 1)
        if not ok:
            c.ERR_clear_error()
        return ok
    finally:
        c.EVP_MD_CTX_free(ctx)
        c.EVP_PKEY_free(key)
