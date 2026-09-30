"""The offline signing station (Master §15.3, §15.13; DR-050; IMPLEMENTATION-ROADMAP §12.1).

Two independent SLH-DSA-SHA2-128s anchors with separate custodians: A (id 0) signs every release; B (id 1) is kept
offline for recovery and is the only key that may sign a KEYREVOKE, which can revoke only A (DR-050). Both public
keys (32 B each) are burned into every bootloader. Signing uses the OpenSSL CLI (OpenSSL ≥ 3.5); it runs once per
release, on the station, never on a device.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass

from ..suite.sig import SLH_ALG, SLH_PK_LEN
from ..wire import enc, u8
from . import merkle
from .artifact import (ANCHOR_A, ANCHOR_B, KEYREVOKE, MAX_PARTS, TYPE_NAMES, FotaError, Manifest, chunks_of,
                       encode_chunk, encode_part)


def find_openssl() -> str | None:
    """An `openssl` that can sign with SLH-DSA (PQGRID_OPENSSL overrides)."""
    exe = os.environ.get("PQGRID_OPENSSL") or shutil.which("openssl")
    if not exe:
        return None
    out = subprocess.run([exe, "list", "-signature-algorithms"], capture_output=True, text=True).stdout
    return exe if SLH_ALG in out else None


@dataclass(frozen=True)
class Artifact:
    manifest: Manifest
    signed: bytes                        # enc[manifest, σ]
    parts: list[bytes]                   # each fits the class max_packet
    chunks: list[bytes]
    payload: bytes


class Station:
    def __init__(self, workdir: str, openssl: str | None = None):
        self.exe = openssl or find_openssl()
        if not self.exe:
            raise RuntimeError("no OpenSSL with SLH-DSA-SHA2-128s (need OpenSSL >= 3.5)")
        self.dir = workdir
        self._keys, self.anchors = {}, {}
        for aid, name in ((ANCHOR_A, "anchor-A"), (ANCHOR_B, "anchor-B")):
            key = os.path.join(workdir, f"{name}.pem")
            self._run("genpkey", "-algorithm", SLH_ALG, "-out", key)
            os.chmod(key, 0o600)
            der = self._run("pkey", "-in", key, "-pubout", "-outform", "DER")
            self._keys[aid], self.anchors[aid] = key, der[-SLH_PK_LEN:]

    def _run(self, *args: str) -> bytes:
        return subprocess.run([self.exe, *args], check=True, capture_output=True).stdout

    def sign(self, anchor_id: int, msg: bytes) -> bytes:
        with tempfile.NamedTemporaryFile(dir=self.dir, delete=False) as f:
            f.write(msg)
        try:
            return self._run("pkeyutl", "-sign", "-rawin", "-inkey", self._keys[anchor_id], "-in", f.name)
        finally:
            os.unlink(f.name)

    def build(self, type_: int, device_class: str, version: int, payload: bytes, chunk_size: int, part_size: int,
              activate_at: int = 0, anchor_id: int = ANCHOR_A, issued_at: int | None = None) -> Artifact:
        """part_size: bytes of the signed manifest per part, chosen by the publisher to fit the class max_packet."""
        chunks = chunks_of(payload, chunk_size)
        m = Manifest(type_, device_class, version, len(payload), hashlib.sha256(payload).digest(), chunk_size,
                     len(chunks), merkle.root(chunks), activate_at, int(time.time()) if issued_at is None else issued_at,
                     anchor_id)
        body = m.encode()
        signed = enc([body, self.sign(anchor_id, body)])
        pieces = [signed[i:i + part_size] for i in range(0, len(signed), part_size)]
        if len(pieces) > MAX_PARTS:
            raise FotaError("manifest needs too many parts for this packet size")
        parts = [encode_part(type_, version, i, len(pieces), p) for i, p in enumerate(pieces)]
        blobs = [encode_chunk(type_, version, i, c, merkle.audit_path(i, chunks)) for i, c in enumerate(chunks)]
        return Artifact(m, signed, parts, blobs, payload)

    def keyrevoke(self, device_class: str, counter: int, revoked_anchor: int, chunk_size: int, part_size: int,
                  anchor_id: int = ANCHOR_B) -> Artifact:
        """E58: payload = enc[u8 revoked_anchor_id]. DR-050: signed by B, revoking A (the device enforces it)."""
        return self.build(KEYREVOKE, device_class, counter, enc([u8(revoked_anchor)]), chunk_size, part_size,
                          anchor_id=anchor_id)


def topic_prefix(device_class: str, type_: int, version: int) -> str:
    return f"pqgrid/fota/{device_class}/{TYPE_NAMES[type_]}/{version}"
