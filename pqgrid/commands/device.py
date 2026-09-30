"""Device side of CONTROL: classification, intent log, GRANTs, SETPOINTs, zone keys, status ACKs
(Master §13.1, §13.4–§13.7, §16; DR-045, DR-046, DR-047; IMPLEMENTATION-ROADMAP §9.2, §9.3).

A signed command is applied at most once, and "OK" is sent only after APPLIED is durable. "Exactly once"
is never claimed (§13.7): a crash during actuation is reported as INTERRUPTED unless the command is
idempotent, unexpired and still the newest (E37).
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..e2e.envelopes import open_control, status_ack
from ..e2e.session import Session
from ..errors import EnvelopeError, HandshakeError, WireError
from ..policy.model import CmdType
from ..suite.kdf import ct_eq
from ..suite.sig import mldsa_verify
from .codec import (Command, Grant, Setpoint, ZoneKey, cmd_signed_input, decode, grant_signed_input)
from .zones import MAX_ZONES, ZoneReceiver

WINDOW = 64                       # applied-sequence bitmap below last_applied (Appendix C)
MAX_COMMAND = 1024                # a PENDING intent (with its body) must fit one flash record (E44)
MAX_INTENTS = 32                  # PENDING + INTERRUPTED records held at once (remediation H2); beyond: REJECTED
RATE_WINDOW_S = 60                # max_setpoint_rate is per minute (§12)


@dataclass
class IntentRecord:
    """INTENT{seq, PENDING, idempotent} with what recovery needs to re-apply (C6). Once settled as INTERRUPTED the
    body is dropped: an interrupted command is never applied automatically again (§13.7), so only its sequence and
    expiry remain, to answer a redelivery truthfully and to know when the record can be reclaimed."""
    cmd_seq: int
    idempotent: bool
    command: bytes = field(repr=False)
    expires_at: int
    interrupted: bool = False


class DeviceCommandState:
    """What Master §16 keeps in device flash: last_applied, a 64-bit bitmap of applied sequences just below it,
    the intent log, and the last accepted broadcast sequence per zone (DR-048).

    Remediation H2: every intent is its own bounded record, and INTERRUPTED records are reclaimed when
      * a newer command has been applied (a redelivery is then answered SUPERSEDED), or
      * no redelivery can still arrive: authenticated time ≥ expires_at + grace, where grace covers the broker
        session that could still hold a queued copy (class Session Expiry) plus transit slack.
    PENDING records (outcome still undecided) are never reclaimed. At most MAX_INTENTS are held; a new command
    beyond that is refused explicitly (REJECTED:capacity), never lost silently."""

    def __init__(self):
        self.last_applied = 0
        self.bitmap = 0
        self.pending: dict[int, IntentRecord] = {}
        self.zone_bseq: dict[str, int] = {}

    def has_capacity(self) -> bool:
        return len(self.pending) < MAX_INTENTS

    def mark_interrupted(self, seq: int) -> None:
        r = self.pending[seq]
        self.pending[seq] = IntentRecord(r.cmd_seq, r.idempotent, b"", r.expires_at, True)

    def reclaim(self, now: int, grace: int) -> list[int]:
        gone = [r.cmd_seq for r in self.pending.values()
                if r.interrupted and (r.cmd_seq <= self.last_applied or now >= r.expires_at + grace)]
        for seq in gone:
            self.pending.pop(seq)
        return gone

    def is_applied(self, seq: int) -> bool:
        if seq <= 0 or seq > self.last_applied:
            return False
        d = self.last_applied - seq
        return d == 0 or (d <= WINDOW and (self.bitmap >> (d - 1)) & 1 == 1)

    def is_interrupted(self, seq: int) -> bool:
        return seq in self.pending

    def write_pending(self, c: Command) -> None:
        self.pending[c.cmd_seq] = IntentRecord(c.cmd_seq, c.idempotent, c.command, c.expires_at)

    def write_zone_bseq(self, zone: str, bseq: int) -> None:
        self.zone_bseq[zone] = bseq

    def write_applied(self, seq: int) -> None:
        self.pending.pop(seq, None)
        if seq > self.last_applied:
            d = seq - self.last_applied
            # Sequences jump by ~2^32 per utility epoch: never shift by d itself (that allocates d bits).
            if self.last_applied and d <= WINDOW:
                self.bitmap = ((self.bitmap << d) | (1 << (d - 1))) & ((1 << WINDOW) - 1)
            else:
                self.bitmap = 0                                   # everything older left the window
            self.last_applied = seq
        elif self.last_applied - seq <= WINDOW:
            self.bitmap |= 1 << (self.last_applied - seq - 1)


class CommandProcessor:
    """Handles envelopes on the device's own `grid/{class}/{id}/control` topic and DR broadcasts."""

    def __init__(self, device, actuate: Callable[[bytes], None],
                 apply_setpoint: Optional[Callable[[str, int], None]] = None, targets=(),
                 state: Optional[DeviceCommandState] = None):
        self.d = device
        self.actuate, self.apply_setpoint = actuate, apply_setpoint
        self.targets = frozenset(targets)
        self.state = DeviceCommandState() if state is None else state
        self.zones = ZoneReceiver(device, self.state)
        self._grants: dict[str, Grant] = {}                      # target → newest GRANT (RAM, session-bound)
        self._rate: dict[str, deque] = {}                         # target → times of applied set-points
        self._last_sp: Optional[tuple[bytes, int, int]] = None    # (sid, msg_seq, grant cmd_seq)
        self._sp_unacked: set[int] = set()                        # GRANTs with a SETPOINT not yet in an ACK (E-3)

    # -------------------------------------------------------------------------------------------- dispatch
    def on_control(self, topic: str, env: bytes) -> Optional[bytes]:
        """Returns the status ACK to publish, or None for an applied SETPOINT (acknowledged cumulatively).
        An envelope that fails authentication or replay raises: there is nothing authentic to acknowledge."""
        if self.d.end_expired_chain():                                    # M2 (§9.7)
            raise EnvelopeError("session chain expired: a full handshake is required")
        s = self.d.session
        if s is None:
            raise EnvelopeError("no session")
        pt, msg_seq = open_control(self.d.policy, s, topic, env)
        try:
            m = decode(pt)
        except WireError:
            return status_ack(s, msg_seq, 0, b"REJECTED:malformed")
        if isinstance(m, Command):
            return self._command(s, topic, msg_seq, m)
        if isinstance(m, Grant):
            return self._grant(s, topic, msg_seq, m)
        if isinstance(m, Setpoint):
            return self._setpoint(s, msg_seq, m)
        return self._zonekey(s, msg_seq, m)

    def _allowed(self, ctype: CmdType) -> bool:
        prof = self.d.profile                                     # E32: flag and sub-type both required
        return prof.unicast_control and ctype in prof.cmd_types

    def _verify(self, sig: bytes, signed: bytes) -> bool:
        return mldsa_verify(self.d.policy.utility_cmd_pk, sig, signed)

    # ------------------------------------------------------------------------------------------------- CMD
    def _command(self, s: Session, topic: str, msg_seq: int, c: Command) -> bytes:
        def ack(status: bytes) -> bytes:
            return status_ack(s, msg_seq, c.cmd_seq, status)
        if not self._allowed(CmdType.CMD):
            return ack(b"REJECTED:not-allowed")
        if not self._verify(c.sig, cmd_signed_input(self.d.id, topic, c.cmd_seq, c.expires_at, c.idempotent,
                                                      c.command)):
            return ack(b"REJECTED:signature")
        st = self.state
        if st.is_applied(c.cmd_seq):                              # DR-046: "already seen" before expiry
            return ack(b"DUP")
        if st.is_interrupted(c.cmd_seq):
            return ack(self._settle(st.pending[c.cmd_seq]))          # the §13.7 rule, whichever comes first
        if c.cmd_seq <= st.last_applied:                           # clarification 3: supersession before expiry
            return ack(b"SUPERSEDED")
        if self.d.now() >= c.expires_at:
            return ack(b"EXPIRED")
        if len(c.command) > MAX_COMMAND:
            return ack(b"REJECTED:malformed")
        if not st.has_capacity():
            self.maintenance()
            if not st.has_capacity():
                return ack(b"REJECTED:capacity")                   # explicit, never a silent loss (H2)
        for r in [r for r in st.pending.values() if not r.interrupted]:
            st.mark_interrupted(r.cmd_seq)                        # E37: never re-applied once another command
                                                                  # arrived; reported INTERRUPTED by recover().
                                                                  # So at most one PENDING body is in flash.
        st.write_pending(c)                                       # PENDING durable before actuation (§13.7)
        self.actuate(c.command)                                   # a crash here leaves PENDING behind
        st.write_applied(c.cmd_seq)                               # APPLIED durable before "OK"
        return ack(b"OK")

    def recover(self) -> list[bytes]:
        """After a reboot, once a session has restored authenticated time: settle every PENDING record.
        Returns unsolicited status ACKs (msg_seq 0) for the utility."""
        s = self.d.session
        if s is None:
            raise HandshakeError("recovery needs an authenticated session (for time)")
        return [status_ack(s, 0, r.cmd_seq, self._settle(r))
                for r in sorted(self.state.pending.values(), key=lambda r: r.cmd_seq)]

    def _settle(self, r: IntentRecord) -> bytes:
        """§13.7: re-apply an interrupted command only if idempotent, unexpired and still the newest (E37);
        otherwise it becomes INTERRUPTED (terminal) and is never applied automatically."""
        if r.interrupted:
            return b"INTERRUPTED"
        if r.idempotent and self.d.now() < r.expires_at and r.cmd_seq > self.state.last_applied:
            self.actuate(r.command)
            self.state.write_applied(r.cmd_seq)
            return b"OK"
        self.state.mark_interrupted(r.cmd_seq)
        return b"INTERRUPTED"

    def reclaim_grace(self) -> int:
        prof = self.d.profile
        return prof.session_expiry_s + prof.dup_window_s

    def maintenance(self) -> list[int]:
        """Reclaim terminal INTERRUPTED records (H2). Needs authenticated time: callers run it with a session."""
        if self.d.session is None:
            return []
        return self.state.reclaim(self.d.now(), self.reclaim_grace())

    # ----------------------------------------------------------------------------------------------- GRANT
    def _grant(self, s: Session, topic: str, msg_seq: int, g: Grant) -> bytes:
        def ack(status: bytes) -> bytes:
            return status_ack(s, msg_seq, g.cmd_seq, status)
        if not self._allowed(CmdType.GRANT):
            return ack(b"REJECTED:not-allowed")
        if not self._verify(g.sig, grant_signed_input(self.d.id, topic, g)):
            return ack(b"REJECTED:signature")
        if not ct_eq(g.sid, s.sid):
            return ack(b"REJECTED:sid")                           # V-G2: issued for another session
        cur = self._grants.get(g.target)
        live = cur is not None and ct_eq(cur.sid, s.sid)
        if live and g.cmd_seq == cur.cmd_seq:
            return ack(b"DUP")
        if g.target not in self.targets:
            return ack(b"REJECTED:target")
        if not (g.min <= g.max and 0 < g.max_rate <= self.d.profile.max_setpoint_rate):
            return ack(b"REJECTED:bounds")
        if g.not_before >= g.expires_at:
            return ack(b"REJECTED:time")
        if self.d.now() >= g.expires_at:
            return ack(b"EXPIRED")
        if live and g.cmd_seq < cur.cmd_seq:
            return ack(b"SUPERSEDED")                             # newest GRANT per target wins (C4)
        self._grants[g.target] = g
        return ack(b"OK")

    # -------------------------------------------------------------------------------------------- SETPOINT
    def _setpoint(self, s: Session, msg_seq: int, sp: Setpoint) -> Optional[bytes]:
        if not self._allowed(CmdType.SETPOINT):
            return status_ack(s, msg_seq, 0, b"REJECTED:not-allowed")
        g = next((g for g in self._grants.values() if g.grant_id == sp.grant_id and ct_eq(g.sid, s.sid)), None)
        if g is None:
            return status_ack(s, msg_seq, 0, b"REJECTED:no-grant")          # rule 2 (V-G3)

        def ack(status: bytes) -> bytes:
            return status_ack(s, msg_seq, g.cmd_seq, status)
        now = self.d.now()
        if not (g.not_before <= now < g.expires_at and now < sp.expires_at):
            return ack(b"REJECTED:time")                                    # rule 3
        if not g.min <= sp.value <= g.max:
            return ack(b"REJECTED:bounds")                                  # rule 4
        win = self._rate.setdefault(g.target, deque())
        while win and win[0] <= now - RATE_WINDOW_S:
            win.popleft()
        if len(win) >= g.max_rate:
            return ack(b"REJECTED:rate")                                    # rule 5 (E31)
        # rule 1 is open_control (current session); rule 6 is its replay guard on msg_seq (C7)
        self.apply_setpoint(g.target, sp.value)
        win.append(now)
        self._last_sp = (s.sid, msg_seq, g.cmd_seq)
        self._sp_unacked.add(g.cmd_seq)
        return None

    def grant_ended_since_ack(self) -> bool:
        """E-3: a GRANT under which a not-yet-acknowledged SETPOINT was applied has ended (expired on authenticated
        device time, or replaced by a newer GRANT for its target): its final cumulative ACK is due now."""
        now, current = self.d.now(), {g.cmd_seq: g for g in self._grants.values()}
        return any(seq not in current or now >= current[seq].expires_at for seq in self._sp_unacked)

    def setpoint_acked(self) -> None:
        self._sp_unacked.clear()

    def last_setpoint(self) -> Optional[tuple[bytes, int, int]]:
        """(sid, msg_seq, grant cmd_seq) of the newest applied set-point: the transport ACKs each one once."""
        return self._last_sp

    def setpoint_ack(self) -> Optional[bytes]:
        """Cumulative OK for the newest applied set-point of this session; the transport decides when (§13.5)."""
        s = self.d.session
        if self._last_sp is None or s is None or not ct_eq(self._last_sp[0], s.sid):
            return None
        return status_ack(s, self._last_sp[1], self._last_sp[2], b"OK")

    # --------------------------------------------------------------------------------------------- ZONEKEY
    def _zonekey(self, s: Session, msg_seq: int, z: ZoneKey) -> bytes:
        if z.aead is not self.d.profile.aead:
            return status_ack(s, msg_seq, 0, b"REJECTED:aead")               # DR-047
        known = set(self.state.zone_bseq) | self.zones.zones()
        if z.zone not in known and len(known) >= MAX_ZONES:
            return status_ack(s, msg_seq, 0, b"REJECTED:capacity")          # its bseq record would not fit
        self.zones.install(z)
        return status_ack(s, msg_seq, 0, b"OK")
