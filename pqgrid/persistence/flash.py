"""Device flash: a NOR flash model and the log-structured record store (Master §16 Flash Wear; DR-049;
IMPLEMENTATION-ROADMAP §10.2, E39, E40).

Record  = type(1) ‖ key_len(1) ‖ key ‖ wseq(8) ‖ len(2) ‖ payload ‖ CRC32(4)
          newest record per (type, key) wins; len = 0 is a deletion; a torn record fails its CRC.
Banks   = the pages split in two. Writes append to the active bank. When it is full, the live records are
          copied to the other bank between BANK(gen) and COMMIT(gen) records, then the old bank is erased.
Boot    = the bank with the newest COMMIT is active; the other bank is erased (an interrupted compaction is
          either finished or undone, because only a COMMIT makes a bank count).
Secrets = records of `secret_types` that were superseded are erased within `scrub_age` (DR-049), and at boot
          when any is found (their age is unknown after a reboot). The age is measured on `clock`, which the
          device binds to its authenticated time (DeviceFlash.bind_clock), and checked after every write and at
          every maybe_scrub() call (remediation M3). Nothing is claimed about flash that is powered off.
"""
from __future__ import annotations

import struct
import time
import zlib
from typing import Callable, Iterable, Optional

ERASED = 0xFF
T_BANK, T_COMMIT = 0xF0, 0xF1                  # system records; application types are 1 … 0xEF
_HEAD = struct.Struct(">BB")                  # type, key_len
_TAIL = struct.Struct(">QH")                  # wseq, len
MAX_KEY = 64
RECORD_OVERHEAD = _HEAD.size + _TAIL.size + 4   # type, key_len, wseq, len, CRC32: 16 B per record


def record_size(key_len: int, payload_len: int) -> int:
    return RECORD_OVERHEAD + key_len + payload_len


class PowerLoss(Exception):
    """Injected by FlashSim: power failed in the middle of a program or erase."""


class StoreFull(Exception):
    """The live records no longer fit in one bank (the class outbox cap should prevent this)."""


class FlashSim:
    """NOR flash: pages erase to 0xFF, and a byte can be programmed only while it is erased.

    `fail_after` counts operations (one per programmed byte, one per 256 bytes erased); when it reaches zero the
    current operation stops half done and PowerLoss is raised. The memory keeps whatever state it reached."""

    ERASE_CHUNK = 256

    def __init__(self, pages: int = 8, page_size: int = 4096):
        """Default: 4 KiB pages (Master §16), two banks of four = 32 KiB, the size persistence.device.budget()
        requires for the default classes (4 KiB outbox). DeviceEndpoint checks it at start-up."""
        if pages < 4 or pages % 2:
            raise ValueError("need an even number of pages, at least 4 (two banks of at least two pages)")
        self.pages, self.page_size = pages, page_size
        self.mem = bytearray([ERASED]) * (pages * page_size)
        self.fail_after: Optional[int] = None
        self.erase_counts = [0] * pages
        self.ticks = 0

    def clone(self) -> "FlashSim":
        c = FlashSim(self.pages, self.page_size)
        c.mem, c.erase_counts = bytearray(self.mem), list(self.erase_counts)
        return c

    def _tick(self) -> None:
        self.ticks += 1
        if self.fail_after is not None:
            if self.fail_after <= 0:
                raise PowerLoss()
            self.fail_after -= 1

    def read(self, off: int, n: int) -> bytes:
        return bytes(self.mem[off:off + n])

    def program(self, off: int, data: bytes) -> None:
        for i, b in enumerate(data):
            self._tick()
            if self.mem[off + i] != ERASED:
                raise RuntimeError("programming a byte that is not erased (store bug)")
            self.mem[off + i] = b

    def erase(self, page: int) -> None:
        base = page * self.page_size
        for c in range(0, self.page_size, self.ERASE_CHUNK):
            self._tick()
            self.mem[base + c:base + c + self.ERASE_CHUNK] = bytes([ERASED]) * self.ERASE_CHUNK
        self.erase_counts[page] += 1


def _encode(rtype: int, key: bytes, wseq: int, payload: bytes) -> bytes:
    body = _HEAD.pack(rtype, len(key)) + key + _TAIL.pack(wseq, len(payload)) + payload
    return body + struct.pack(">I", zlib.crc32(body))


class RecordStore:
    def __init__(self, flash: FlashSim, clock: Callable[[], float] = time.time,
                 secret_types: Iterable[int] = (), scrub_age: int = 7 * 86400):
        self.f, self.clock = flash, clock
        self.secret_types, self.scrub_age = frozenset(secret_types), scrub_age
        self.bank_pages = flash.pages // 2
        self._live: dict[tuple[int, bytes], tuple[int, bytes]] = {}     # (type, key) → (wseq, payload)
        self._secret_since: Optional[float] = None
        self._boot()

    # ------------------------------------------------------------------------------------------ public API
    def get(self, rtype: int, key: bytes = b"") -> Optional[bytes]:
        v = self._live.get((rtype, key))
        return v[1] if v else None

    def items(self, rtype: int) -> dict[bytes, tuple[int, bytes]]:
        """key → (wseq, payload) for every live record of this type."""
        return {k: v for (t, k), v in self._live.items() if t == rtype}

    def put(self, rtype: int, key: bytes, payload: bytes) -> None:
        if not payload:
            raise ValueError("an empty payload is a deletion: use delete()")
        self._write(rtype, key, payload)

    def delete(self, rtype: int, key: bytes = b"") -> None:
        if (rtype, key) in self._live:
            self._write(rtype, key, b"")

    def compact(self) -> None:
        """Copy the live records into the other bank, commit it, erase the old one."""
        old, new, gen, saved = self._active, 1 - self._active, self._gen + 1, (self._active, self._gen, self._pos)
        for p in self._pages(new):
            if self.f.read(p * self.f.page_size, self.f.page_size) != bytes([ERASED]) * self.f.page_size:
                self.f.erase(p)
        self._active, self._gen, self._pos = new, gen, (0, 0)
        try:
            self._append(_encode(T_BANK, b"", gen, b"\x01"))
            for (t, k), (w, payload) in sorted(self._live.items(), key=lambda kv: kv[1][0]):
                self._append(_encode(t, k, w, payload))
            self._append(_encode(T_COMMIT, b"", gen, b"\x01"))
        except StoreFull:
            for p in self._pages(new):                         # undo: the old bank was never touched
                self.f.erase(p)
            self._active, self._gen, self._pos = saved
            raise
        for p in self._pages(old):
            self.f.erase(p)
        self._secret_since = None

    # ------------------------------------------------------------------------------------------ internals
    def _pages(self, bank: int) -> range:
        return range(bank * self.bank_pages, (bank + 1) * self.bank_pages)

    def _write(self, rtype: int, key: bytes, payload: bytes) -> None:
        if not 1 <= rtype < T_BANK or len(key) > MAX_KEY:
            raise ValueError("bad record type or key")
        prev = self._live.get((rtype, key))
        self._wseq += 1
        rec = _encode(rtype, key, self._wseq, payload)
        if len(rec) > self.f.page_size:
            raise ValueError("record larger than a page")
        if not self._fits(len(rec)):
            self.compact()
            if not self._fits(len(rec)):
                raise StoreFull("live records do not fit in one bank")
        self._append(rec)
        if payload:
            self._live[(rtype, key)] = (self._wseq, payload)
        else:
            self._live.pop((rtype, key), None)
        if prev is not None and rtype in self.secret_types and self._secret_since is None:
            self._secret_since = self.clock()                   # a secret was superseded: DR-049 clock starts
        if self._secret_since is not None and self.clock() - self._secret_since >= self.scrub_age:
            self.compact()

    def maybe_scrub(self) -> bool:
        """DR-049 without a write (remediation M3): called after every authenticated time update and from the
        device's periodic tick. Returns True if it compacted."""
        if self._secret_since is not None and self.clock() - self._secret_since >= self.scrub_age:
            self.compact()
            return True
        return False

    def _fits(self, n: int) -> bool:
        page, off = self._pos
        return off + n <= self.f.page_size or page + 1 < self.bank_pages

    def _append(self, rec: bytes) -> None:
        page, off = self._pos
        if off + len(rec) > self.f.page_size:
            page, off = page + 1, 0
            if page >= self.bank_pages:
                raise StoreFull("bank full during compaction")
        self.f.program((self._active * self.bank_pages + page) * self.f.page_size + off, rec)
        self._pos = (page, off + len(rec))

    def _scan_bank(self, bank: int):
        """Valid records of a bank in write order, and the position after the last one."""
        recs, end = [], (0, 0)
        for i, p in enumerate(self._pages(bank)):
            data, off = self.f.read(p * self.f.page_size, self.f.page_size), 0
            while off + _HEAD.size <= len(data) and data[off] != ERASED:
                rtype, klen = _HEAD.unpack_from(data, off)
                tail = off + _HEAD.size + klen
                if tail + _TAIL.size > len(data):              # no real record overruns its page: a header torn
                    end = (i + 1, 0)                           # after its type byte (key_len still 0xFF), so
                    break                                      # nothing more on this page, as for a bad CRC
                wseq, plen = _TAIL.unpack_from(data, tail)
                crc_at = tail + _TAIL.size + plen
                if crc_at + 4 > len(data) or zlib.crc32(data[off:crc_at]) != struct.unpack_from(">I", data, crc_at)[0]:
                    end = (i + 1, 0)                               # torn write: nothing more on this page
                    break
                recs.append((rtype, data[off + _HEAD.size:tail], wseq, data[tail + _TAIL.size:crc_at]))
                off = crc_at + 4
                end = (i, off)
            else:
                if off:
                    end = (i, off)
        return recs, end

    def _boot(self) -> None:
        scans = [self._scan_bank(b) for b in (0, 1)]
        committed = []
        for b, (recs, _) in enumerate(scans):
            if recs and recs[0][0] == T_BANK:
                gen = recs[0][2]
                if any(r[0] == T_COMMIT and r[2] == gen for r in recs):
                    committed.append((gen, b))
        if not committed:                                          # blank, or the first format was interrupted
            for p in range(self.f.pages):
                self.f.erase(p)
            self._active, self._gen, self._pos, self._wseq = 0, 1, (0, 0), 0
            self._append(_encode(T_BANK, b"", 1, b"\x01"))
            self._append(_encode(T_COMMIT, b"", 1, b"\x01"))
            return
        self._gen, self._active = max(committed)
        recs, end = scans[self._active]
        other = 1 - self._active
        if scans[other][0] or any(self.f.read(p * self.f.page_size, 1)[0] != ERASED for p in self._pages(other)):
            for p in self._pages(other):
                self.f.erase(p)                                   # finish or undo an interrupted compaction
        self._wseq, superseded_secret = 0, False
        for rtype, key, wseq, payload in recs:
            if rtype in (T_BANK, T_COMMIT):
                continue
            self._wseq = max(self._wseq, wseq)
            if (rtype, key) in self._live and rtype in self.secret_types:
                superseded_secret = True
            if payload:
                self._live[(rtype, key)] = (wseq, payload)
            else:
                self._live.pop((rtype, key), None)
                superseded_secret |= rtype in self.secret_types
        self._pos = end if end[0] < self.bank_pages else (self.bank_pages, 0)
        if end[0] >= self.bank_pages or superseded_secret:
            self.compact()                                        # full after a tear, or DR-049 at boot
