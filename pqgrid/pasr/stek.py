"""Session Ticket Encryption Keys (Master §14.4; IMPLEMENTATION-ROADMAP E21).

The STEK is utility-only (§9.5) and seals tickets with ChaCha20-Poly1305. Rules:
  * rotation: a new key when a ticket is issued and the current key is ≥ 24 h old;
  * retirement: automatic at created_at + 24 h + 7 days. A key seals only while it is < 24 h old, and
    validator rule 4 caps every ticket at 7 days, so no ticket sealed under a key outlives its retirement;
  * key ids are 16 bits (v2.2) and never wrap into a key that is still live.

Storage here is in memory; persistence.utility_db.SqlStekTable keeps it in SQLite WAL, with a new key committed
before the first ticket is sealed under it (§16); production uses an HSM (RISK-1: a stolen STEK mints tickets).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..errors import TicketError
from ..suite.rand import random_bytes

ROTATION_S = 24 * 3600
MAX_TICKET_S = 7 * 24 * 3600
KID_MOD = 1 << 16
STEK_LEN = 32


@dataclass(frozen=True)
class StekKey:
    kid: int
    key: bytes = field(repr=False)
    created_at: int
    retire_at: int


class StekTable:
    def __init__(self):
        self._keys: dict[int, StekKey] = {}
        self._current: Optional[StekKey] = None

    def current(self, now: int) -> StekKey:
        """The key to seal with; rotates first if the current key is 24 h old."""
        cur = self._current
        if cur is None or now >= cur.created_at + ROTATION_S:
            cur = self._rotate(now)
        return cur

    def key(self, kid: int, now: int) -> bytes:
        """Check 1 of §14.5: the key id must be live."""
        k = self._keys.get(kid)
        if k is None or now >= k.retire_at:
            raise TicketError("ticket key retired")
        return k.key

    def live_kids(self) -> list[int]:
        return sorted(self._keys)

    def _rotate(self, now: int) -> StekKey:
        retired = [kid for kid, k in self._keys.items() if now >= k.retire_at]
        for kid in retired:
            del self._keys[kid]                                   # automatic retirement (≤ 9 keys, once a day)
        if retired:
            self._store_retired(retired)
        kid = 0 if self._current is None else (self._current.kid + 1) % KID_MOD
        if kid in self._keys:
            raise TicketError("STEK key id is still live: refusing to reuse it")
        k = StekKey(kid, random_bytes(STEK_LEN), now, now + ROTATION_S + MAX_TICKET_S)
        self._store_new(k)                                        # durable before any ticket is sealed under it
        self._keys[kid] = k
        self._current = k
        return k

    # persistence hooks (slice 4: persistence.utility_db); in memory they do nothing
    def _store_new(self, k: StekKey) -> None:
        pass

    def _store_retired(self, kids: list[int]) -> None:
        pass
