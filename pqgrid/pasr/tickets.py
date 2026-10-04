"""Resumption tickets: sealing, the single-use set, and the 9 resume checks (Master §14.3, §14.5, §14.6).

    blob = 0x01 ‖ kid (u16) ‖ nonce (12) ‖ ChaCha20-Poly1305(STEK[kid], pt, AAD = 0x01 ‖ kid)
    pt   = enc[ticket_id(16), device_id, class, POLICY_INFO, u64 fw_version, resume_mode,
               u64 issued_at, u64 expires_at, u64 chain_expires_at, psk(32)]

The utility keeps no per-device session state for tickets: only the STEK table and the set of used ticket ids.
Every failure is a TicketError (a HandshakeError): the device does a full handshake, never a weaker session.
"""
from __future__ import annotations

import heapq
from dataclasses import dataclass, field

from ..e2e import keys
from ..e2e.session import Session
from ..errors import CryptoError, PolicyError, TicketError, TicketReusedError, WireError
from ..policy.model import Policy, ResumeMode
from ..registry import Registry
from ..suite import aead, hkem
from ..suite.aead import AeadAlg
from ..suite.kdf import ct_eq, mac
from ..suite.rand import random_bytes
from ..wire import dec, enc, r16, r64, u16, u64
from .stek import StekTable

VERSION = b"\x01"
TICKET_ID_LEN, PSK_LEN = 16, 32
_HEAD = len(VERSION) + 2                      # version ‖ kid
_NONCE_END = _HEAD + aead.NONCE_LEN
TICKET_AEAD = AeadAlg.CHACHA20POLY1305        # Master §6.5 / §7.9: STEK sealing is always ChaCha20-Poly1305


@dataclass(frozen=True)
class Ticket:
    ticket_id: bytes
    device_id: bytes
    dclass: str
    policy_info: bytes
    fw_version: int
    resume_mode: ResumeMode
    issued_at: int
    expires_at: int
    chain_expires_at: int
    psk: bytes = field(repr=False)


def seal_ticket(stek: StekTable, t: Ticket, now: int) -> bytes:
    k = stek.current(now)
    head = VERSION + u16(k.kid)
    nonce = random_bytes(aead.NONCE_LEN)                          # random 96-bit nonce (Master §6.5)
    pt = enc([t.ticket_id, t.device_id, t.dclass.encode(), t.policy_info, u64(t.fw_version),
              t.resume_mode.value.encode(), u64(t.issued_at), u64(t.expires_at), u64(t.chain_expires_at), t.psk])
    return head + nonce + aead.seal(TICKET_AEAD, k.key, nonce, pt, head)


def open_ticket(stek: StekTable, blob: bytes, now: int) -> Ticket:
    """Checks 1 (kid live) and 2 (authentic)."""
    if len(blob) < _NONCE_END + aead.TAG_LEN or blob[:1] != VERSION:
        raise TicketError("malformed ticket")
    key = stek.key(r16(blob[1:_HEAD]), now)                                               # check 1
    try:
        pt = aead.open_(TICKET_AEAD, key, blob[_HEAD:_NONCE_END], blob[_NONCE_END:], blob[:_HEAD])   # check 2
        tid, did, dclass, pinfo, fw, mode, issued, expires, chain, psk = dec(pt, 10)
        t = Ticket(tid, did, dclass.decode("ascii"), pinfo, r64(fw), ResumeMode(mode.decode("ascii")),
                   r64(issued), r64(expires), r64(chain), psk)
    except (CryptoError, WireError, ValueError) as e:
        raise TicketError("ticket not authentic") from e
    if len(t.ticket_id) != TICKET_ID_LEN or len(t.psk) != PSK_LEN:
        raise TicketError("ticket not authentic")
    return t


class UsedTickets:
    """Single-use set: ticket_id → expires_at (Master §14.5, §14.7).

    An entry is forgotten once its ticket has expired: check 5 already refuses an expired ticket, so the
    record is no longer needed. Pruning uses a min-heap, O(log n) per resume (E28; audit S4).
    persistence.utility_db.SqlUsedTickets makes consume() durable (SQLite WAL, synchronous = FULL); callers consume
    before replying."""

    def __init__(self):
        self._exp: dict[bytes, int] = {}
        self._heap: list[tuple[int, bytes]] = []

    def consume(self, ticket_id: bytes, expires_at: int, now: int) -> bool:
        """Mark the ticket used. False if it was already used."""
        self._prune(now)
        if ticket_id in self._exp:
            return False
        self._exp[ticket_id] = expires_at
        heapq.heappush(self._heap, (expires_at, ticket_id))
        return True

    def __len__(self) -> int:
        return len(self._exp)

    def _prune(self, now: int) -> None:
        while self._heap and self._heap[0][0] <= now:
            _, tid = heapq.heappop(self._heap)
            self._exp.pop(tid, None)


class TicketIssuer:
    """The utility's ticket authority: issues tickets for NT and redeems them for RH."""

    def __init__(self, stek: StekTable | None = None, used: UsedTickets | None = None):
        # `is None`, never `or`: an empty store has len() == 0 and would be silently replaced (found in slice 4)
        self.stek = StekTable() if stek is None else stek
        self.used = UsedTickets() if used is None else used

    def issue(self, s: Session, lifetime_s: int, now: int) -> tuple[bytes, bytes, int]:
        """Returns (ticket_id, blob, expires_at). The chain expiry is inherited, never extended (§9.4)."""
        tid = random_bytes(TICKET_ID_LEN)
        expires = min(now + lifetime_s, s.chain_expires)
        t = Ticket(tid, s.device_id, s.dclass, s.policy_info, s.fw_version, s.resume_mode, now, expires,
                   s.chain_expires, keys.resumption_psk(s.k_master, tid))
        return tid, seal_ticket(self.stek, t, now), expires

    def redeem(self, *, blob: bytes, topic_id: bytes, claimed_id: bytes, policy_info: bytes, fw_version: int,
               mode: bytes, pk_e: bytes, binder: bytes, binder_input: bytes, registry: Registry, policy: Policy,
               now: int) -> Ticket:
        """The 9 checks of Master §14.5, in order. The ticket is consumed only after the binder verifies."""
        t = open_ticket(self.stek, blob, now)                                                  # 1, 2
        if not (ct_eq(t.device_id, topic_id) and ct_eq(t.device_id, claimed_id)):
            raise TicketError("ticket/device identity mismatch")                               # 3
        rec = registry.get(t.device_id)
        if rec is None or not rec.active:
            raise TicketError("device unknown or revoked")                                     # 4
        if rec.dclass != t.dclass:
            raise TicketError("ticket class does not match the registry")                      # 4 (E22)
        if rec.provisioned_at and t.issued_at <= rec.provisioned_at:
            raise TicketError("ticket issued before the device was re-provisioned")            # 4 (P1-1)
        if not (now < t.expires_at and now < t.chain_expires_at):
            raise TicketError("ticket expired")                                                # 5
        if not (ct_eq(t.policy_info, policy_info) and ct_eq(policy_info, policy.info())):
            raise TicketError("ticket issued under a different policy")                        # 6
        if t.fw_version != fw_version:
            raise TicketError("ticket issued for different firmware")                          # 7
        try:
            current = policy.profile(t.dclass).resume
        except PolicyError as e:
            raise TicketError("resume mode does not match policy") from e
        if not (mode == t.resume_mode.value.encode() and t.resume_mode is current
                and current is not ResumeMode.NONE):
            raise TicketError("resume mode does not match policy")                             # 8
        if len(pk_e) != (hkem.PK_LEN if current is ResumeMode.PSK_KEM else 0):
            raise TicketError("PSK_KEM requires a fresh ephemeral key" if current is ResumeMode.PSK_KEM
                              else "PSK resume must not carry a key")                          # 8
        if not ct_eq(mac(keys.binder_key(t.psk), binder_input), binder):
            raise TicketError("binder invalid")                                                # 9
        if not self.used.consume(t.ticket_id, t.expires_at, now):
            raise TicketReusedError("ticket already used")                                     # 9
        return t
