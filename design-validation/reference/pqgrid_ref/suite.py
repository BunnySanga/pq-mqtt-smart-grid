"""Crypto suite for the refactored design (reference / validation only)."""
from __future__ import annotations
import ctypes, ctypes.util, hashlib, hmac, os, struct
from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives import hashes, serialization

XWING_LABEL = b"\\.//^\\"          # X-Wing combiner label (draft-connolly-cfrg-xwing-kem)
RAW = serialization.Encoding.Raw, serialization.PublicFormat.Raw

# ---------- hybrid KEM: ML-KEM-768 + X25519, X-Wing-style combiner ----------
class HybridKeyPair:
    def __init__(self):
        self.m = mlkem.MLKEM768PrivateKey.generate()
        self.x = x25519.X25519PrivateKey.generate()
        self.pk_x = self.x.public_key().public_bytes(*RAW)
        self.pk = self.m.public_key().public_bytes_raw() + self.pk_x        # 1184 + 32

def hkem_encaps(pk: bytes) -> tuple[bytes, bytes]:
    pk_m, pk_x = pk[:1184], pk[1184:]
    ss_m, ct_m = mlkem.MLKEM768PublicKey.from_public_bytes(pk_m).encapsulate()   # NOTE: (ss, ct)
    ek = x25519.X25519PrivateKey.generate()
    ct_x = ek.public_key().public_bytes(*RAW)
    ss_x = ek.exchange(x25519.X25519PublicKey.from_public_bytes(pk_x))
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL).digest(), ct_m + ct_x   # ss, ct(1120)

def hkem_decaps(kp: HybridKeyPair, ct: bytes) -> bytes:
    ct_m, ct_x = ct[:1088], ct[1088:]
    ss_m = kp.m.decapsulate(ct_m)
    ss_x = kp.x.exchange(x25519.X25519PublicKey.from_public_bytes(ct_x))
    return hashlib.sha3_256(ss_m + ss_x + ct_x + kp.pk_x + XWING_LABEL).digest()

# ---------- symmetric ----------
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()
def hkdf_expand(prk: bytes, info: bytes, n: int = 32) -> bytes:
    return HKDFExpand(hashes.SHA256(), n, info).derive(prk)
def mac(k: bytes, m: bytes) -> bytes: return hmac.new(k, m, hashlib.sha256).digest()
def h(*parts: bytes) -> bytes:
    d = hashlib.sha256()
    for p in parts: d.update(struct.pack(">I", len(p)) + p)
    return d.digest()
def aead_seal(k, nonce, pt, aad): return ChaCha20Poly1305(k).encrypt(nonce, pt, aad)
def aead_open(k, nonce, ct, aad): return ChaCha20Poly1305(k).decrypt(nonce, ct, aad)

# ---------- signatures ----------
def mldsa_keygen(): return mldsa.MLDSA65PrivateKey.generate()
def mldsa_verify(pub_raw: bytes, sig: bytes, msg: bytes) -> bool:
    try: mldsa.MLDSA65PublicKey.from_public_bytes(pub_raw).verify(sig, msg); return True
    except Exception: return False

_LIB = os.environ.get("LIBCRYPTO") or ctypes.util.find_library("crypto") or "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib"
_C = ctypes.CDLL(_LIB)
_C.EVP_PKEY_new_raw_public_key_ex.restype = ctypes.c_void_p
_C.EVP_PKEY_new_raw_public_key_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
_C.EVP_MD_CTX_new.restype = ctypes.c_void_p
_C.EVP_DigestVerifyInit_ex.argtypes = [ctypes.c_void_p]*2 + [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p]
_C.EVP_DigestVerify.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
_C.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]; _C.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
SLH = "SLH-DSA-SHA2-192s"
def slh_verify(pub_raw: bytes, sig: bytes, msg: bytes) -> bool:
    pk = _C.EVP_PKEY_new_raw_public_key_ex(None, SLH.encode(), None, pub_raw, len(pub_raw))
    if not pk: return False
    ctx = _C.EVP_MD_CTX_new()
    try:
        return _C.EVP_DigestVerifyInit_ex(ctx, None, None, None, None, pk, None) == 1 and \
               _C.EVP_DigestVerify(ctx, sig, len(sig), msg, len(msg)) == 1
    finally: _C.EVP_MD_CTX_free(ctx); _C.EVP_PKEY_free(pk)
