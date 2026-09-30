"""ECDSA P-256 hop PKI (Master §4.5, §8.5–§8.8), made with the `openssl` CLI (OpenSSL ≥ 3.4 for -not_after).

    CA        offline in production; pinned by devices as the set {current, next}
    broker    SAN = its host names, a normal lifetime, rotated under CA overlap
    device    CN = device ID (the MQTT user name), notAfter = 99991231235959Z: never locked out while offline
    utility   CN = "utility"
The prototype writes keys owner-only; production keeps the CA key offline (§27).
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass

NEVER = "99991231235959Z"


@dataclass(frozen=True)
class Cert:
    crt: str
    key: str


def _openssl(*args: str, exe: str = "openssl") -> None:
    subprocess.run([exe, *args], check=True, capture_output=True)


def make_ca(directory: str, name: str = "pqgrid-ca", exe: str = "openssl") -> Cert:
    crt, key = os.path.join(directory, f"{name}.crt"), os.path.join(directory, f"{name}.key")
    _openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-keyout", key, "-out", crt,
             "-days", "3650", "-nodes", "-subj", f"/CN={name}", "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign", exe=exe)
    os.chmod(key, 0o600)
    return Cert(crt, key)


def issue(ca: Cert, directory: str, name: str, cn: str, eku: str, san: str | None = None,
          not_before: str | None = None, not_after: str | None = None, days: int = 365, exe: str = "openssl") -> Cert:
    crt, key, csr = (os.path.join(directory, f"{name}.{ext}") for ext in ("crt", "key", "csr"))
    req = ["req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-keyout", key, "-out", csr, "-nodes",
           "-subj", f"/CN={cn}", "-addext", "basicConstraints=critical,CA:FALSE",
           "-addext", "keyUsage=critical,digitalSignature", "-addext", f"extendedKeyUsage={eku}"]
    if san:
        req += ["-addext", f"subjectAltName={san}"]
    _openssl(*req, exe=exe)
    sign = ["x509", "-req", "-in", csr, "-CA", ca.crt, "-CAkey", ca.key, "-out", crt, "-copy_extensions", "copy"]
    sign += (["-not_before", not_before] if not_before else []) + (["-not_after", not_after] if not_after else ["-days", str(days)])
    _openssl(*sign, exe=exe)
    os.remove(csr)
    os.chmod(key, 0o600)
    return Cert(crt, key)


def device_cert(ca: Cert, directory: str, device_id: bytes, exe: str = "openssl") -> Cert:
    return issue(ca, directory, device_id.decode(), device_id.decode(), "clientAuth", not_after=NEVER, exe=exe)
