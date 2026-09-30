"""Device-side FOTA installer and bootloader model (Master §15.2, §15.7–§15.14; DR-050; IMPLEMENTATION-ROADMAP §12,
E57–E63).

Order of trust for every artifact:
  1. the signed manifest, verified against a burned-in, non-revoked anchor before any field is believed;
  2. class, type, limits (payload ≤ this device's own slot: V-F5; chunks fit its packet limit: E61) and
     version > committed[type] (anti-rollback: F4–F6), all before downloading anything;
  3. each chunk against the signed Merkle root (F1), written to the inactive slot, then its bit in the bitmap
     made durable (resume after power loss: E-F1);
  4. the whole payload's length and SHA-256: "staged".
Then, by type: FIRMWARE boots into the new slot only at activate_at (E60), after the bootloader re-hashes the
slot (V-F4 model) and re-checks the signer (E59); the self-test decides commit or revert (E-F2). POLICY is
validated and activated at activate_at (E57). KEYREVOKE applies DR-050: only B revokes A, never the last anchor.

Protected storage (§15.11) is a separate record store that a factory reset does not erase. Its one record holds
committed[FIRMWARE], committed[POLICY], the revocation counter, the revoked anchors and the active slot, so every
commit is a single atomic write (§15.12).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..errors import CapacityError, PolicyError, WireError
from ..policy import decode_policy, validate
from ..persistence.flash import RecordStore
from ..suite.sig import slh_verify
from ..wire import dec, enc, r8, r64, u8, u64
from . import merkle
from .artifact import (ANCHOR_A, ANCHOR_B, FIRMWARE, KEYREVOKE, MAX_CHUNKS, MAX_PARTS, POLICY, TYPE_NAMES, FotaError, Manifest,
                       check_signer, decode_chunk, decode_manifest, decode_part, split_signed)

T_PROTECTED = 1                              # in the protected store
T_DOWNLOAD, T_STAGED = 30, 31                # in the device's normal record store
CHUNK_RECORD, MQTT_RESERVE = 37, 128         # E11
STAGING_CAP = 16 * 1024                      # manifest parts (8,042 B signed manifest at 128s)
MAX_ASSEMBLIES = 4                           # manifests assembled at once; the least recently used is evicted


@dataclass
class FotaFlash:
    """Simulated flash regions that survive a reboot: the two firmware slots and the small-artifact areas."""
    slot_size: int
    area_size: int = 16 * 1024
    slots: list = field(default_factory=list)
    areas: dict = field(default_factory=dict)

    def __post_init__(self):
        self.slots = self.slots or [bytearray(self.slot_size), bytearray(self.slot_size)]
        self.areas = self.areas or {POLICY: bytearray(self.area_size), KEYREVOKE: bytearray(self.area_size)}


class Protected:
    def __init__(self, store: RecordStore):
        self.s = store
        raw = store.get(T_PROTECTED, b"state")
        if raw:
            fw, pol, rev, bits, active = dec(raw, 5)
            self.committed = {FIRMWARE: r64(fw), POLICY: r64(pol), KEYREVOKE: r64(rev)}
            self.revoked = {a for a in (ANCHOR_A, ANCHOR_B) if r8(bits) >> a & 1}
            self.active = r8(active)
        else:
            self.committed, self.revoked, self.active = {FIRMWARE: 0, POLICY: 0, KEYREVOKE: 0}, set(), 0

    def _save(self, committed: dict, revoked: set, active: int) -> None:
        bits = sum(1 << a for a in revoked)
        self.s.put(T_PROTECTED, b"state", enc([u64(committed[FIRMWARE]), u64(committed[POLICY]),
                                               u64(committed[KEYREVOKE]), u8(bits), u8(active)]))
        self.committed, self.revoked, self.active = committed, revoked, active     # only after the durable write

    def commit(self, type_: int, version: int, active: Optional[int] = None) -> None:
        self._save({**self.committed, type_: version}, set(self.revoked), self.active if active is None else active)

    def revoke(self, anchor: int, counter: int) -> None:
        self._save({**self.committed, KEYREVOKE: counter}, self.revoked | {anchor}, self.active)


@dataclass
class Download:
    manifest: Manifest
    raw: bytes                                   # the verified manifest bytes (what the signature covered)
    have: bytearray                              # bitmap, one bit per chunk

    def complete(self) -> bool:
        return all(self.have[i // 8] >> (i % 8) & 1 for i in range(self.manifest.chunk_count))


class Installer:
    def __init__(self, anchors: dict[int, bytes], device_class: str, max_packet: int, flash: FotaFlash,
                 protected: RecordStore, store: RecordStore, clock: Callable[[], float]):
        self.anchors, self.cls, self.max_packet = dict(anchors), device_class, max_packet
        self.flash, self.store, self.clock = flash, store, clock
        self.prot = Protected(protected)
        self._parts: dict[tuple[int, int], dict] = {}
        self.downloads: dict[int, Download] = {}
        self.staged: dict[int, Manifest] = {}
        for key, (_, raw) in store.items(T_DOWNLOAD).items():          # resume after a reboot (E-F1)
            mraw, have = dec(raw, 2)
            self.downloads[key[0]] = Download(decode_manifest(mraw), mraw, bytearray(have))
        for key, (_, raw) in store.items(T_STAGED).items():
            self.staged[key[0]] = decode_manifest(raw)
        self._finish_interrupted_commits()
        self._finish_interrupted_keyrevoke()

    def _finish_interrupted_commits(self) -> None:
        """A commit is one protected record; the staging record is dropped after it. If power failed in between, the
        artifact is staged (or downloading) at a version already committed: finish the commit by dropping it. For
        FIRMWARE the other slot is now the OLD image, so re-hashing it would report a false "staged image modified"
        (found by the power-loss test)."""
        for t, m in [*self.staged.items(), *((t, d.manifest) for t, d in self.downloads.items())]:
            if m.version <= self.prot.committed[t]:
                self._drop(t)

    def _finish_interrupted_keyrevoke(self) -> None:
        """A KEYREVOKE is applied as soon as it is staged. If power failed while protected storage was written,
        it is still staged at boot: apply it now (found by the power-loss test; without this it stayed staged
        and every redelivery was ignored as "already in progress", so a revoked anchor stayed trusted)."""
        m = self.staged.get(KEYREVOKE)
        if m is None:
            return
        if self.prot.committed[KEYREVOKE] >= m.version:                   # the write had completed
            self._drop(KEYREVOKE)
            return
        payload = bytes(self.flash.areas[KEYREVOKE][:m.payload_length])
        if hashlib.sha256(payload).digest() != m.payload_sha256:
            self._drop(KEYREVOKE)                                          # area lost: fetch it again
            return
        self._apply_keyrevoke(m, payload)

    # --------------------------------------------------------------------------------------- manifest
    def on_part(self, raw: bytes) -> Optional[Manifest]:
        """Collect retained manifest parts; when all have arrived, verify the whole. Returns the accepted manifest
        (or None while parts are missing, or for a duplicate of the manifest already in progress)."""
        t, v, i, n, data = decode_part(raw)
        if v <= self.prot.committed[t]:
            raise FotaError("rollback: manifest part for a version not newer than installed")
        slot = self._parts.pop((t, v), None)                             # re-inserted: most recently used last
        if slot is None or slot["n"] != n:
            slot = {"n": n, "p": {}}                                     # new, or inconsistent totals: start over
        self._parts[(t, v)] = slot
        while len(self._parts) > MAX_ASSEMBLIES:                         # bounded however many headers are forged
            del self._parts[next(iter(self._parts))]
        slot["p"][i] = data
        if sum(len(x) for x in slot["p"].values()) > STAGING_CAP:
            del self._parts[(t, v)]
            raise FotaError("manifest larger than the staging area")
        if len(slot["p"]) < n:
            return None
        del self._parts[(t, v)]
        return self.accept_signed(b"".join(slot["p"][k] for k in range(n)), label=(t, v))

    def accept_signed(self, signed: bytes, label: Optional[tuple[int, int]] = None) -> Optional[Manifest]:
        """`label`: the (type, version) the parts claimed. Part headers are not signed, so they must match the
        signed manifest: an old manifest re-wrapped under a newer label is refused, whatever the early checks."""
        raw, sig = split_signed(signed)
        m = decode_manifest(raw)                                         # parsed, not yet believed
        if m.signer_anchor_id not in self.anchors:
            raise FotaError("manifest names an unknown anchor")
        if m.signer_anchor_id in self.prot.revoked:
            raise FotaError("manifest signed by a revoked anchor")        # V-F2 (cheap, before the verify)
        if not slh_verify(self.anchors[m.signer_anchor_id], sig, raw):
            raise FotaError("manifest signature invalid")                 # F2, F3
        check_signer(m.type, m.signer_anchor_id, self.prot.revoked)       # DR-050 roles (H4)
        if label is not None and label != (m.type, m.version):
            raise FotaError("manifest parts labelled with another type or version")
        # ------------------------------------------------------------------- trusted from here on
        if m.device_class != self.cls:
            raise FotaError("manifest targets another device class")      # F7
        cap = self.flash.slot_size if m.type == FIRMWARE else self.flash.area_size
        if m.payload_length > cap:
            raise FotaError("payload larger than this device's slot")        # V-F5, before any download
        if m.chunk_count > MAX_CHUNKS:
            raise FotaError(f"more than {MAX_CHUNKS} chunks: the download record would not fit its budget")
        if m.chunk_size + merkle.HASH_LEN * merkle.max_path_len(m.chunk_count) + CHUNK_RECORD + MQTT_RESERVE \
                > self.max_packet:
            raise FotaError("chunks would exceed this device's packet limit")  # E61
        if m.version <= self.prot.committed[m.type]:
            raise FotaError("rollback: version not newer than installed")  # F4, F5, F6
        cur = self.downloads.get(m.type) or (Download(self.staged[m.type], b"", bytearray())
                                            if m.type in self.staged else None)
        if cur is not None:
            if m.version == cur.manifest.version:
                if cur.raw and raw != cur.raw:
                    raise FotaError("a different manifest for the same version")
                return None                                                # a duplicate: already in progress
            if m.version < cur.manifest.version:
                raise FotaError("older than the artifact already in progress")   # E-F4
        self._drop(m.type)                                                 # a newer version replaces it
        self.downloads[m.type] = Download(m, raw, bytearray((m.chunk_count + 7) // 8))
        self._save_download(m.type)
        return m

    # ----------------------------------------------------------------------------------------- chunks
    def _area(self, t: int) -> bytearray:
        return self.flash.slots[1 - self.prot.active] if t == FIRMWARE else self.flash.areas[t]

    def on_chunk(self, raw: bytes) -> Optional[int]:
        """Returns the artifact type when this chunk completed (and staged) it."""
        t, v, i, data, path = decode_chunk(raw)
        dl = self.downloads.get(t)
        if dl is None or dl.manifest.version != v:
            raise FotaError("chunk from another artifact")                 # E-F3
        m = dl.manifest
        if i >= m.chunk_count:
            raise FotaError("chunk index out of range")
        want = m.chunk_size if i < m.chunk_count - 1 else m.payload_length - m.chunk_size * (m.chunk_count - 1)
        if len(data) != want:
            raise FotaError("chunk has the wrong length")
        if not merkle.verify(i, m.chunk_count, data, path, m.merkle_root):
            raise FotaError(f"chunk {i} failed Merkle verification")      # F1
        if dl.have[i // 8] >> (i % 8) & 1:
            return None                                                    # duplicate (QoS 1, re-publication)
        area = self._area(t)
        area[i * m.chunk_size:i * m.chunk_size + len(data)] = data         # the chunk is written first …
        dl.have[i // 8] |= 1 << (i % 8)
        self._save_download(t)                                             # … then its bit is made durable
        if not dl.complete():
            return None
        payload = bytes(area[:m.payload_length])
        if hashlib.sha256(payload).digest() != m.payload_sha256:
            self._drop(t)
            raise FotaError("image hash mismatch")
        del self.downloads[t]
        self.store.delete(T_DOWNLOAD, bytes([t]))
        self.staged[t] = m
        self.store.put(T_STAGED, bytes([t]), dl.raw)
        if t == KEYREVOKE:
            self._apply_keyrevoke(m, payload)
        return t

    # ------------------------------------------------------------------------------------ activation
    def boot_staged_firmware(self, self_test: Callable[[bytes], bool]) -> str:
        m = self.staged.get(FIRMWARE)
        if m is None:
            return "nothing staged"
        if self.clock() < m.activate_at:
            return "waiting for activate_at"                               # E60
        try:
            check_signer(FIRMWARE, m.signer_anchor_id, self.prot.revoked)  # E59: roles re-checked at commit
        except FotaError:
            self._drop(FIRMWARE)
            return "refused: signer revoked"
        new = 1 - self.prot.active
        image = bytes(self.flash.slots[new][:m.payload_length])
        if hashlib.sha256(image).digest() != m.payload_sha256:
            self._drop(FIRMWARE)
            return "refused: staged image modified"                        # V-F4 (bootloader re-hash)
        if not self_test(image):                                          # trial boot; a power loss here also
            self._drop(FIRMWARE)                                           # leaves the old slot active
            return "reverted"                                              # E-F2: counter unchanged
        self.prot.commit(FIRMWARE, m.version, active=new)                  # version and slot: one atomic record
        self._drop(FIRMWARE)
        return "committed"

    def activate_policy(self, installed, admit: Optional[Callable] = None):
        """Returns the newly active Policy, or None when there is nothing due. `admit(policy)` may refuse it
        (e.g. the device's flash cannot hold the new class's worst case) before anything is committed."""
        m = self.staged.get(POLICY)
        if m is None or self.clock() < m.activate_at:
            return None
        try:
            check_signer(POLICY, m.signer_anchor_id, self.prot.revoked)    # E59: roles re-checked at commit
        except FotaError:
            self._drop(POLICY)
            raise FotaError("staged policy signed by a revoked anchor")
        payload = bytes(self.flash.areas[POLICY][:m.payload_length])
        try:
            p = decode_policy(payload)
            if p.version != m.version or p.activate_at != m.activate_at:
                raise PolicyError("manifest and policy disagree on version or activate_at (E57)")
            validate(p, installed_version=installed.version)
            if admit is not None:
                admit(p)
        except (PolicyError, WireError, CapacityError) as e:
            self._drop(POLICY)
            raise FotaError(f"policy refused: {e}") from e
        self.prot.commit(POLICY, m.version)
        self._drop(POLICY)
        return p

    def _apply_keyrevoke(self, m: Manifest, payload: bytes) -> None:
        try:
            (rid,) = dec(payload, 1)
            rid = r8(rid)
        except WireError as e:
            self._drop(KEYREVOKE)
            raise FotaError("malformed KEYREVOKE payload") from e
        if m.signer_anchor_id != ANCHOR_B or rid != ANCHOR_A:
            self._drop(KEYREVOKE)
            raise FotaError("only the recovery anchor B may revoke the release anchor A (DR-050)")
        if not (set(self.anchors) - self.prot.revoked - {rid}):
            self._drop(KEYREVOKE)
            raise FotaError("refusing to revoke the last active anchor")   # V-F3
        self.prot.revoke(rid, m.version)                                   # counter + revoked set: one record
        self._drop(KEYREVOKE)
        for t in [t for t, x in {**self.staged, **{k: d.manifest for k, d in self.downloads.items()}}.items()
                  if x.signer_anchor_id == rid]:
            self._drop(t)                                                  # E59: in-flight A-signed artifacts

    # --------------------------------------------------------------------------------------- helpers
    def _save_download(self, t: int) -> None:
        dl = self.downloads[t]
        self.store.put(T_DOWNLOAD, bytes([t]), enc([dl.raw, bytes(dl.have)]))

    def _drop(self, t: int) -> None:
        if self.downloads.pop(t, None) is not None:
            self.store.delete(T_DOWNLOAD, bytes([t]))
        if self.staged.pop(t, None) is not None:
            self.store.delete(T_STAGED, bytes([t]))

    def committed(self, t: int) -> int:
        return self.prot.committed[t]


TYPES = TYPE_NAMES
__all__ = ["Installer", "FotaFlash", "Protected", "FotaError", "FIRMWARE", "POLICY", "KEYREVOKE", "MAX_PARTS"]
