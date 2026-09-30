"""Device state in flash (Master §16, §14.7, §9.8; DR-048, DR-049; IMPLEMENTATION-ROADMAP §10.2, C8, C9, E41).

    ticket  written when NT verifies; deleted at RS (C9). It holds the psk, so superseded copies are erased
            within 7 days (DR-049).
    rh      PSK: the identical RH bytes, written before the RH is first sent (S5, resend after a reboot).
            PSK_KEM: only an "in flight" marker; the ephemeral private key never reaches flash (C8), so after
            a reboot the device drops the possibly consumed ticket and does a full handshake (no false clone
            alarm).
    cmd     last_applied, bitmap and the PENDING intents: one record per step, in P8 order.
    zone    last accepted broadcast sequence per zone (DR-048).
    outbox  unacknowledged ALERTs, bounded by the class outbox_cap in real flash bytes, plus a drop counter.

Capacity (final remediation): budget() lists every record that can legitimately coexist, each at its largest;
DeviceFlash.require_capacity() refuses (CapacityError) a store whose bank cannot hold that worst case plus one
record in flight, allowing for the unusable end of each page. DeviceEndpoint calls it at start-up and before a
new policy is adopted.
"""
from __future__ import annotations

from typing import Optional

from ..commands.device import MAX_COMMAND, MAX_INTENTS, DeviceCommandState, IntentRecord
from ..commands.zones import MAX_ZONES
from ..errors import CapacityError
from ..fota.artifact import MAX_CHUNKS
from ..policy.model import ResumeMode
from ..suite.rand import random_bytes
from ..wire import dec, enc, r8, r32, r64, u8, u32, u64
from .flash import FlashSim, RecordStore, record_size

T_TICKET, T_RH, T_CMD, T_ZONE, T_OUTBOX, T_OUTMETA, T_TIME, T_INTENT = 1, 2, 3, 4, 5, 6, 7, 8
TIME_FLOOR_EVERY_S = 86400                 # §8.9: at most one write a day, plus the first after boot
SECRET_TYPES = {T_TICKET}
RH_INFLIGHT = b"\x00"                    # PSK_KEM marker: an RH was sent, but it cannot be resent
ALERT_ID_LEN = 16
MAX_ALERT_PAYLOAD, MAX_ALERT_KIND = 1024, 16   # one ALERT; larger is refused (ValueError), never truncated
MAX_ID = 32                                     # device id, class, policy id, zone name (registry, validator)
MANIFEST_MAX = 159 + MAX_ID                     # FOTA manifest with the longest class name (167 B at 8 chars)
FOTA_TYPES = 3                                  # FIRMWARE, POLICY, KEYREVOKE: one download or staged each


def _enc_len(*field_lens: int) -> int:
    return sum(4 + n for n in field_lens)


def budget(profile) -> tuple[dict[str, int], int]:
    """The documented worst case (Master §16 Capacity): every record that can coexist, each at its largest.
    Returns ({item: flash bytes}, largest single record). Field bounds: IDs ≤ 32 B, POLICY_INFO ≤ 37 B."""
    pinfo = MAX_ID + 1 + 4
    blob = 1 + 2 + 12 + _enc_len(16, MAX_ID, MAX_ID, pinfo, 8, 7, 8, 8, 8, 32) + 16          # sealed ticket
    ticket = record_size(0, _enc_len(16, blob, 32, 8, 7, pinfo, 8))
    rh = record_size(0, _enc_len(2, blob, 32, 7, 0, MAX_ID, pinfo, 8, 8, 32))                  # PSK; PSK_KEM: 1 B
    intent_body = record_size(8, _enc_len(1, 1, 8, MAX_COMMAND))
    download = record_size(1, _enc_len(MANIFEST_MAX, MAX_CHUNKS // 8))
    alert = record_size(ALERT_ID_LEN, _enc_len(MAX_ALERT_PAYLOAD, MAX_ALERT_KIND))
    items = {
        "bank markers": 2 * record_size(0, 1),
        "time floor": record_size(0, 8),
        "command state": record_size(5, _enc_len(8, 8)),
        f"intents ({MAX_INTENTS - 1} interrupted + 1 pending body)":
            (MAX_INTENTS - 1) * record_size(8, _enc_len(1, 1, 8, 0)) + intent_body,
        "ticket": ticket,
        "resume hello": rh,
        "outbox (cap) + drop counter": profile.outbox_cap + record_size(7, 4 + ALERT_ID_LEN),
        f"FOTA ({FOTA_TYPES} types)": FOTA_TYPES * max(download, record_size(1, MANIFEST_MAX)),
        f"zones ({MAX_ZONES})": MAX_ZONES * record_size(MAX_ID, 8),
    }
    return items, max(intent_body, alert, rh, ticket, download)


class DeviceFlash:
    """One device's flash. Pass it to DeviceEndpoint(flash=…) and use its command state and outbox."""

    def __init__(self, flash: FlashSim, clock):
        self.store = RecordStore(flash, clock, secret_types=SECRET_TYPES)
        self._floor_written_at: Optional[int] = None         # RAM: None until the first write after boot

    # ------------------------------------------------------------------------------------ capacity
    def capacity(self, profile) -> tuple[int, int]:
        """(bytes the worst case needs, bytes one bank can surely hold). A record never spans pages, so each
        page may end with up to largest−1 unusable bytes; one record may be in flight while it replaces another."""
        items, largest = budget(profile)
        f = self.store.f
        if largest > f.page_size:
            return sum(items.values()) + largest, 0
        return sum(items.values()) + largest, self.store.bank_pages * (f.page_size - (largest - 1))

    def require_capacity(self, profile) -> None:
        need, usable = self.capacity(profile)
        if need > usable:
            raise CapacityError(f"device flash too small for class {profile.name}: the worst case needs {need} B, "
                                f"a bank of {self.store.bank_pages} × {self.store.f.page_size} B holds {usable} B")

    # ------------------------------------------------------------------------------ DR-049 scrub (M3)
    def bind_clock(self, clock) -> None:
        """The DeviceEndpoint's time (RTC + authenticated offset, never below the persisted floor): the 7-day
        secret age then advances with authenticated time even if the RTC stopped (e.g. during deep sleep)."""
        self.store.clock = clock

    def maintenance(self) -> bool:
        """DR-049 check without a write. Called after each authenticated time update (SH/RS) and from the
        transport's periodic tick; boot and every ticket write check on their own. True if it compacted."""
        return self.store.maybe_scrub()

    # ------------------------------------------------------------------------------- time floor (§8.9, E50)
    def time_floor(self) -> int:
        raw = self.store.get(T_TIME)
        return r64(raw) if raw else 0

    def update_time_floor(self, authenticated_now: int) -> None:
        """Called with authenticated utility time (after SH/RS)."""
        last = self._floor_written_at
        if authenticated_now > self.time_floor() and (last is None or authenticated_now - last >= TIME_FLOOR_EVERY_S):
            self.store.put(T_TIME, b"", u64(authenticated_now))
            self._floor_written_at = authenticated_now

    # ------------------------------------------------------------------------------------ ticket and RH
    def save_ticket(self, t) -> None:
        self.store.put(T_TICKET, b"", enc([t.ticket_id, t.blob, t.psk, u64(t.expires_at), t.mode.value.encode(),
                                           t.policy_info, u64(t.fw_version)]))

    def load_ticket(self, cls):
        raw = self.store.get(T_TICKET)
        if raw is None:
            return None
        tid, blob, psk, exp, mode, pinfo, fw = dec(raw, 7)
        return cls(tid, blob, psk, r64(exp), ResumeMode(mode.decode()), pinfo, r64(fw))

    def clear_ticket(self) -> None:
        self.store.delete(T_TICKET)

    def save_rh(self, rh: bytes, mode: ResumeMode) -> None:
        self.store.put(T_RH, b"", rh if mode is ResumeMode.PSK else RH_INFLIGHT)

    def load_rh(self) -> Optional[bytes]:
        return self.store.get(T_RH)

    def clear_rh(self) -> None:
        self.store.delete(T_RH)

    def command_state(self) -> "FlashCommandState":
        return FlashCommandState(self.store)

    def outbox(self, topic: str, cap: int) -> "Outbox":
        return Outbox(self.store, topic, cap)


# ================================================================================ command state (§16)
_PENDING, _INTERRUPTED = 0, 1


def _encode_intent(r: IntentRecord) -> bytes:
    return enc([u8(_INTERRUPTED if r.interrupted else _PENDING), u8(int(r.idempotent)), u64(r.expires_at),
                r.command])


class FlashCommandState(DeviceCommandState):
    """DeviceCommandState on the flash record store (remediation H2):
         state          one record: last_applied ‖ bitmap           (APPLIED is durable here before "OK")
         intent/<seq>   one record per command: PENDING (with body) → INTERRUPTED (no body) → deleted
    Order: PENDING before actuation; the state record before the intent is deleted, so a crash in between leaves
    an intent whose sequence is already applied, which the boot reconciliation deletes. Every record is bounded
    (a body ≤ MAX_COMMAND), and terminal records are reclaimed, so the log cannot outgrow its bank."""

    def __init__(self, store: RecordStore):
        super().__init__()
        self._s = store
        raw = store.get(T_CMD, b"state")
        if raw is not None:
            last, bitmap = dec(raw, 2)
            self.last_applied, self.bitmap = r64(last), r64(bitmap)
        for key, (_, v) in store.items(T_INTENT).items():
            state, idem, exp, command = dec(v, 4)
            seq = r64(key)
            if self.is_applied(seq):
                store.delete(T_INTENT, key)                  # crash after APPLIED, before the intent was deleted
                continue
            self.pending[seq] = IntentRecord(seq, r8(idem) == 1, command, r64(exp), r8(state) == _INTERRUPTED)
        for key, (_, v) in store.items(T_ZONE).items():
            self.zone_bseq[key.decode()] = r64(v)

    def write_pending(self, c) -> None:
        super().write_pending(c)
        self._s.put(T_INTENT, u64(c.cmd_seq), _encode_intent(self.pending[c.cmd_seq]))

    def write_applied(self, seq: int) -> None:
        super().write_applied(seq)
        self._s.put(T_CMD, b"state", enc([u64(self.last_applied), u64(self.bitmap)]))   # APPLIED is durable …
        self._s.delete(T_INTENT, u64(seq))                                              # … then the intent goes
        for gone in self.reclaim_superseded():
            self._s.delete(T_INTENT, u64(gone))

    def reclaim_superseded(self) -> list[int]:
        gone = [r.cmd_seq for r in self.pending.values() if r.interrupted and r.cmd_seq <= self.last_applied]
        for seq in gone:
            self.pending.pop(seq)
        return gone

    def mark_interrupted(self, seq: int) -> None:
        super().mark_interrupted(seq)
        self._s.put(T_INTENT, u64(seq), _encode_intent(self.pending[seq]))

    def reclaim(self, now: int, grace: int) -> list[int]:
        gone = super().reclaim(now, grace)
        for seq in gone:
            self._s.delete(T_INTENT, u64(seq))
        return gone

    def write_zone_bseq(self, zone: str, bseq: int) -> None:
        super().write_zone_bseq(zone, bseq)
        self._s.put(T_ZONE, zone.encode(), u64(bseq))


# ======================================================================================== outbox (§16)
class Outbox:
    """Unacknowledged ALERTs (Master §16 Outbox; E41). Every queued alert rides in the next DF; an entry is
    removed on its end-to-end ACK. When full: merge queued alerts of the same kind (the newest stays), then drop
    the oldest; the number lost is itself sent as an alert "DROPPED:<n>"."""

    OVERHEAD = record_size(ALERT_ID_LEN, 8)            # real flash bytes per entry besides payload and kind: 40

    def __init__(self, store: RecordStore, topic: str, cap: int):
        self._s, self.topic, self.cap = store, topic, cap

    def _entries(self) -> list[tuple[int, bytes, bytes, bytes]]:
        """(wseq, alert_id, payload, kind), oldest first."""
        out = []
        for aid, (w, raw) in self._s.items(T_OUTBOX).items():
            payload, kind = dec(raw, 2)
            out.append((w, aid, payload, kind))
        return sorted(out)

    def _size(self, payload: bytes, kind: bytes) -> int:
        return len(payload) + len(kind) + self.OVERHEAD

    def dropped(self) -> int:
        raw = self._s.get(T_OUTMETA, b"dropped")
        return r32(raw[:4]) if raw else 0

    def _count_drops(self, n: int) -> None:
        if n:                                               # a new alert_id whenever the count changes
            self._s.put(T_OUTMETA, b"dropped", u32(self.dropped() + n) + random_bytes(ALERT_ID_LEN))

    def add(self, alert_id: bytes, payload: bytes, kind: bytes = b"") -> None:
        if len(alert_id) != ALERT_ID_LEN:
            raise ValueError("alert_id must be 16 bytes")
        if len(payload) > MAX_ALERT_PAYLOAD or len(kind) > MAX_ALERT_KIND:
            raise ValueError(f"alert payload ≤ {MAX_ALERT_PAYLOAD} B and kind ≤ {MAX_ALERT_KIND} B")
        need, entries = self._size(payload, kind), self._entries()
        used, drops = sum(self._size(p, k) for _, _, p, k in entries), 0
        if need > self.cap:
            self._count_drops(1)
            return
        if used + need > self.cap and kind:
            for _, aid, p, k in entries:
                if k == kind:                                   # merge: the new one replaces older repeats
                    self._s.delete(T_OUTBOX, aid)
                    used, drops = used - self._size(p, k), drops + 1
            entries = self._entries()
        for _, aid, p, k in entries:
            if used + need <= self.cap:
                break
            self._s.delete(T_OUTBOX, aid)                       # drop the oldest
            used, drops = used - self._size(p, k), drops + 1
        self._s.put(T_OUTBOX, alert_id, enc([payload, kind]))
        self._count_drops(drops)

    def queued(self) -> list[tuple[str, bytes, bytes]]:
        """(topic, alert_id, payload) for the next DF: the drop counter first, then the alerts, oldest first."""
        out = []
        meta = self._s.get(T_OUTMETA, b"dropped")
        if meta:
            out.append((self.topic, meta[4:], b"DROPPED:%d" % r32(meta[:4])))
        return out + [(self.topic, aid, p) for _, aid, p, _ in self._entries()]

    def ack(self, alert_id: bytes) -> None:
        meta = self._s.get(T_OUTMETA, b"dropped")
        if meta and meta[4:] == alert_id:
            self._s.delete(T_OUTMETA, b"dropped")
        else:
            self._s.delete(T_OUTBOX, alert_id)

    def ack_seqs(self, sent: list[tuple[str, bytes, bytes]], acked: list[int]) -> None:
        """Map the msg_seqs acknowledged in NT/FIN back to the alerts sent in DF (sequence i ↔ sent[i-1])."""
        for seq in acked:
            if 1 <= seq <= len(sent):
                self.ack(sent[seq - 1][1])
