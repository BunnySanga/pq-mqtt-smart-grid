"""PQC-FOTA: offline SLH-DSA-signed manifests, RFC 6962 Merkle-authenticated chunks, monotonic versions.
One pipeline for two artifact types: FIRMWARE and POLICY."""
from __future__ import annotations
import hashlib, os, shutil, subprocess, tempfile, time
from .suite import slh_verify
from .wire import enc, dec, u64, r64

FIRMWARE, POLICY = b"\x01", b"\x02"
OPENSSL = os.environ.get("OPENSSL") or shutil.which("openssl") or "/opt/homebrew/opt/openssl@3/bin/openssl"
class FotaError(ValueError): pass

# ---- RFC 6962 Merkle tree ----
def _leaf(d): return hashlib.sha256(b"\x00" + d).digest()
def _node(l, r): return hashlib.sha256(b"\x01" + l + r).digest()
def _k(n):  # largest power of two < n
    k = 1
    while k * 2 < n: k *= 2
    return k
def mth(leaves):
    if len(leaves) == 1: return _leaf(leaves[0])
    k = _k(len(leaves)); return _node(mth(leaves[:k]), mth(leaves[k:]))
def path(m, leaves):
    if len(leaves) == 1: return []
    k = _k(len(leaves))
    return path(m, leaves[:k]) + [mth(leaves[k:])] if m < k else path(m - k, leaves[k:]) + [mth(leaves[:k])]
def verify_path(m, n, leaf_data, proof, root):          # RFC 9162 section 2.1.3.2 style
    if m >= n: return False
    fn, sn, r = m, n - 1, _leaf(leaf_data)
    for p in proof:
        if sn == 0: return False
        if fn & 1 or fn == sn:
            r = _node(p, r)
            while not (fn & 1) and fn != 0: fn >>= 1; sn >>= 1
        else: r = _node(r, p)
        fn >>= 1; sn >>= 1
    return sn == 0 and r == root

# ---- signing station (offline; OpenSSL CLI) ----
class Station:
    def __init__(self, workdir):
        self.dir = workdir; self.key = os.path.join(workdir, "station.pem")
        subprocess.run([OPENSSL, "genpkey", "-algorithm", "SLH-DSA-SHA2-192s", "-out", self.key], check=True, capture_output=True)
        der = subprocess.run([OPENSSL, "pkey", "-in", self.key, "-pubout", "-outform", "DER"], check=True, capture_output=True).stdout
        self.pk = der[-48:]                                   # 48-byte trust anchor burned into bootloaders
    def sign(self, msg: bytes) -> bytes:
        with tempfile.NamedTemporaryFile(dir=self.dir, delete=False) as f: f.write(msg)
        try:
            return subprocess.run([OPENSSL, "pkeyutl", "-sign", "-rawin", "-inkey", self.key, "-in", f.name],
                                  check=True, capture_output=True).stdout
        finally: os.unlink(f.name)
    def build(self, kind: bytes, device_class: str, version: int, payload: bytes, chunk_size=4096, activate_at=0):
        chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)] or [b""]
        root = mth(chunks)
        manifest = enc([b"PQFW1", kind, device_class.encode(), u64(version), u64(len(payload)),
                        hashlib.sha256(payload).digest(), u64(chunk_size), u64(len(chunks)), root, u64(activate_at), u64(int(time.time()))])
        signed = enc([manifest, self.sign(manifest)])
        blobs = [enc([kind, u64(version), u64(i), c, b"".join(path(i, chunks))]) for i, c in enumerate(chunks)]
        return signed, blobs

# ---- device installer (A/B slots: stage, then commit only after a successful boot) ----
MAX_CHUNKS, MAX_IMAGE = 1 << 16, 64 << 20
class Installer:
    """committed = persisted anti-rollback counters (in protected storage, NOT erased by factory reset).
    The counter moves forward only on commit(): after the new firmware boots and passes its self-test,
    or immediately for a POLICY after it validates. A failed boot calls revert() and the old slot keeps running."""
    def __init__(self, anchor_pk: bytes, device_class: str, installed: dict):
        self.pk, self.cls, self.installed, self.staged = anchor_pk, device_class, installed, {}
    def accept_manifest(self, signed: bytes) -> dict:
        manifest, sig = dec(signed, 2)
        if not slh_verify(self.pk, sig, manifest): raise FotaError("manifest signature invalid")
        magic, kind, cls, ver, ln, digest, cs, n, root, act, iss = dec(manifest, 11)
        if magic != b"PQFW1": raise FotaError("bad manifest")
        if cls.decode() != self.cls: raise FotaError("manifest targets another device class")
        if r64(ver) <= self.installed.get(kind, 0): raise FotaError("rollback: version not newer than installed")
        if not (0 < r64(n) <= MAX_CHUNKS and r64(ln) <= MAX_IMAGE): raise FotaError("manifest exceeds device limits")
        return {"kind": kind, "ver": r64(ver), "len": r64(ln), "sha": digest, "n": r64(n), "root": root, "act": r64(act), "chunks": {}}
    def accept_chunk(self, st: dict, blob: bytes) -> None:
        kind, ver, idx, data, prf = dec(blob, 5)
        if kind != st["kind"] or r64(ver) != st["ver"]: raise FotaError("chunk from another artifact")
        proof = [prf[i:i+32] for i in range(0, len(prf), 32)]
        if not verify_path(r64(idx), st["n"], data, proof, st["root"]): raise FotaError(f"chunk {r64(idx)} failed Merkle verification")
        st["chunks"][r64(idx)] = data                     # duplicates (QoS 1 / re-publication) are harmless
    def finish(self, st: dict) -> bytes:
        if len(st["chunks"]) != st["n"]: raise FotaError("missing chunks")
        payload = b"".join(st["chunks"][i] for i in range(st["n"]))
        if len(payload) != st["len"] or hashlib.sha256(payload).digest() != st["sha"]: raise FotaError("image hash mismatch")
        self.staged[st["kind"]] = st["ver"]; return payload           # written to the inactive slot, not yet committed
    def commit(self, kind: bytes) -> None:
        self.installed[kind] = self.staged.pop(kind)                   # anti-rollback counter moves forward here
    def revert(self, kind: bytes) -> None:
        self.staged.pop(kind, None)                                    # failed boot: old slot keeps running
