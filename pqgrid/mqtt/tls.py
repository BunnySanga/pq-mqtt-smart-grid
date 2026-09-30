"""TLS 1.3 contexts for the MQTT hop (Master §8; IMPLEMENTATION-ROADMAP §11).

Device (§8.8): the chain is verified to the **pinned** CA set {current, next} and the hostname is checked, but
certificate validity **times are not**: a device whose RTC reset to 1970 must still reach the utility that repairs
its clock. Utility: full verification (its clock is trusted).

Hybrid key exchange is enforced by the broker's group pin (X25519MLKEM768, SecP256r1MLKEM768); Python's `ssl` has
no API to choose TLS 1.3 groups or cipher suites (E53). The OpenSSL default already offers X25519MLKEM768 first.
"""
from __future__ import annotations

import ssl

X509_V_FLAG_NO_CHECK_TIME = 0x200000                    # OpenSSL flag; not named in Python's ssl module
HYBRID_GROUPS = "X25519MLKEM768:SecP256r1MLKEM768"
CLASS_SUITE = {"AES256GCM": "TLS_AES_256_GCM_SHA384", "CHACHA20POLY1305": "TLS_CHACHA20_POLY1305_SHA256"}


def _base(ca_files: list[str], cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)          # verify_mode CERT_REQUIRED, check_hostname True
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    for ca in ca_files:
        ctx.load_verify_locations(cafile=ca)
    ctx.load_cert_chain(cert, key)
    return ctx


def device_context(ca_files: list[str], cert: str, key: str) -> ssl.SSLContext:
    ctx = _base(ca_files, cert, key)
    ctx.verify_flags |= X509_V_FLAG_NO_CHECK_TIME           # §8.8 (1): chain and name yes, dates no
    return ctx


def utility_context(ca_files: list[str], cert: str, key: str) -> ssl.SSLContext:
    return _base(ca_files, cert, key)
