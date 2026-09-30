"""Utility side of CONTROL: command sequence, redelivery queue, GRANT/SETPOINT issue, status handling
(Master §13.1, §13.4–§13.7, §16; DR-045, DR-046; IMPLEMENTATION-ROADMAP §9.4, E36, E38).

    cmd_seq = epoch(32) ‖ counter(32), epoch = max(now_s, last_epoch + 1) fixed once per start (§13.6).

A restart, or a restore from an old backup, starts a newer epoch, so a new command can never reuse a sequence
the device has already seen (the S1 bug). Allocating the sequence and queueing the signed command are one store
operation that completes before anything is sent (P8).
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field, replace
from typing import Callable, Optional

from ..e2e.envelopes import control_topic, seal_control, status_sid, verify_status_ack
from ..e2e.session import Session
from ..errors import CommandError, EnvelopeError, PolicyError, WireError
from ..policy.model import CmdType
from ..suite.kdf import ct_eq
from ..suite.rand import random_bytes
from ..suite.sig import mldsa_sign
from .device import MAX_COMMAND
from .codec import GRANT_ID_LEN, Command, Grant, Setpoint, cmd_signed_input, encode, grant_signed_input, valid_token

COUNTER_MAX = (1 << 32) - 1
GRANT_CLOCK_SLACK_S = 60          # E56: the device's clock lags by up to one message transit (+ <1 s rounding)


@dataclass
class QueuedCommand:
    device_id: bytes
    topic: str
    cmd: Command
    sends: int = 0                                     # number of sessions it was sent in
    last_sid: bytes = b""                              # the session it was last sent in
    status: Optional[bytes] = None                     # None while open


class UtilityCommandStore:
    """What Master §16 keeps in SQLite: utility_epoch, device_seq and the commands table (= the redelivery
    queue). In memory here (E36); slice 4 makes allocate_and_enqueue one WAL transaction."""

    def __init__(self):
        self.last_epoch = 0
        self.counters: dict[bytes, int] = {}
        self.commands: dict[bytes, dict[int, QueuedCommand]] = {}

    def start(self, now: int) -> int:
        epoch = max(int(now), self.last_epoch + 1)
        if epoch > COUNTER_MAX:
            raise CommandError("utility epoch exhausted")
        self.last_epoch = epoch                                    # persisted at start
        return epoch

    def allocate(self, device_id: bytes, epoch: int) -> int:
        n = self.counters.get(device_id, 0) + 1
        if n > COUNTER_MAX:
            raise CommandError("command counter exhausted for this device")
        self.counters[device_id] = n
        return (epoch << 32) | n

    def allocate_and_enqueue(self, device_id: bytes, epoch: int,
                             build: Callable[[int], QueuedCommand]) -> QueuedCommand:
        """One step: the sequence and the queued command become durable together, before sending (§16)."""
        q = build(self.allocate(device_id, epoch))
        self.commands.setdefault(device_id, {})[q.cmd.cmd_seq] = q
        return q

    def open_commands(self, device_id: bytes) -> list[QueuedCommand]:
        return [q for _, q in sorted(self.commands.get(device_id, {}).items()) if q.status is None]

    def get(self, device_id: bytes, cmd_seq: int) -> Optional[QueuedCommand]:
        return self.commands.get(device_id, {}).get(cmd_seq)

    def mark_sent(self, q: QueuedCommand, sid: bytes) -> None:
        q.sends, q.last_sid = q.sends + 1, sid

    def close(self, q: QueuedCommand, status: bytes) -> None:
        q.status = status

    def snapshot(self) -> "UtilityCommandStore":
        """A backup copy (for restore tests: V-S1)."""
        return copy.deepcopy(self)


class CommandService:
    def __init__(self, utility, cmd_key, store: Optional[UtilityCommandStore] = None):
        self.u = utility                                           # a UtilityEndpoint: sessions, policy, registry
        self.cmd_key = cmd_key                                     # ML-DSA-65 command key (HSM in production)
        self.store = UtilityCommandStore() if store is None else store
        self.epoch = self.store.start(self.u.now())
        self.alarms: list[tuple] = []                              # V-S2: sequence regression
        self.interrupted: list[tuple[bytes, int]] = []             # INTERRUPTED: an operator decides (§13.7)
        self._grants: dict[bytes, dict[bytes, Grant]] = {}        # sid → grant_id → GRANT (session-bound)
        self._grant_sid: dict[bytes, bytes] = {}                  # device → the sid its GRANTs are held under

    # ------------------------------------------------------------------------------------------- helpers
    def now(self) -> int:
        return self.u.now()

    def has_session(self, device_id: bytes) -> bool:
        return self.u.current_session(device_id) is not None

    def class_profile(self, device_id: bytes):
        rec = self.u.registry.get(device_id)
        if rec is None or not rec.active:
            raise CommandError("unknown or revoked device")
        try:
            return self.u.policy.profile(rec.dclass)
        except PolicyError as e:
            raise CommandError("device class not in the current policy") from e

    def _topic(self, device_id: bytes, ctype: Optional[CmdType]) -> str:
        prof = self.class_profile(device_id)
        if ctype is not None and not (prof.unicast_control and ctype in prof.cmd_types):
            raise CommandError(f"class {prof.name} does not accept {ctype.value} (E32)")
        return control_topic(prof.name, device_id)

    def _live(self, device_id: bytes) -> Session:
        s = self.u.current_session(device_id)
        if s is None:
            raise CommandError("no live session under the current policy for this device")
        return s

    def seal_for(self, device_id: bytes, pt: bytes) -> bytes:
        """Seal an unsigned CONTROL plaintext (ZONEKEY) under the device's live session."""
        topic = self._topic(device_id, None)                       # registry state first (revoked → refused)
        return seal_control(self.u.policy, self._live(device_id), topic, pt)

    # ------------------------------------------------------------------------------------------------- CMD
    def issue(self, device_id: bytes, command: bytes, ttl_s: int, idempotent: bool = False) -> int:
        """Sign and queue a discrete command; returns its cmd_seq. It is sent by `outgoing`."""
        topic = self._topic(device_id, CmdType.CMD)
        if len(command) > MAX_COMMAND:
            raise CommandError(f"command body larger than {MAX_COMMAND} bytes (E44)")
        exp = self.now() + ttl_s

        def build(cmd_seq: int) -> QueuedCommand:
            sig = mldsa_sign(self.cmd_key, cmd_signed_input(device_id, topic, cmd_seq, exp, idempotent, command))
            return QueuedCommand(device_id, topic, Command(cmd_seq, command, exp, idempotent, sig))
        return self.store.allocate_and_enqueue(device_id, self.epoch, build).cmd.cmd_seq

    def outgoing(self, device_id: bytes) -> list[bytes]:
        """Envelopes to publish for the device's live session: each open, unexpired command once per session,
        in cmd_seq order (same cmd_seq and σ on redelivery, new keys). Expired ones are closed (E38)."""
        s = self.u.current_session(device_id)                      # M1: never under an old-policy session
        if s is None:
            return []
        now, out = self.now(), []
        for q in self.store.open_commands(device_id):
            if now >= q.cmd.expires_at:
                self.store.close(q, b"UNKNOWN" if q.sends else b"EXPIRED")
                continue
            if q.last_sid == s.sid:
                continue
            self.store.mark_sent(q, s.sid)                          # recorded before the envelope leaves
            out.append(seal_control(self.u.policy, s, q.topic, encode(q.cmd)))
        return out

    def outcome(self, device_id: bytes, cmd_seq: int) -> Optional[bytes]:
        q = self.store.get(device_id, cmd_seq)
        return q.status if q else None

    # -------------------------------------------------------------------------------------- GRANT / SETPOINT
    def grant(self, device_id: bytes, target: str, lo: int, hi: int, max_rate: int, ttl_s: int,
              not_before: Optional[int] = None) -> tuple[bytes, bytes]:
        """A signed GRANT bound to the device's live session. Returns (grant_id, envelope). Never queued."""
        topic = self._topic(device_id, CmdType.GRANT)
        prof, s = self.class_profile(device_id), self._live(device_id)
        if not (valid_token(target) and lo <= hi and 0 < max_rate <= prof.max_setpoint_rate):
            raise CommandError("GRANT outside the class limits")
        now = self.now()
        nb = now - GRANT_CLOCK_SLACK_S if not_before is None else not_before
        g = Grant(self.store.allocate(device_id, self.epoch), random_bytes(GRANT_ID_LEN), s.sid, target, lo, hi,
                  max_rate, nb, now + ttl_s, b"")
        g = replace(g, sig=mldsa_sign(self.cmd_key, grant_signed_input(device_id, topic, g)))
        self._forget_grants(device_id, s.sid, now)
        self._grants.setdefault(s.sid, {})[g.grant_id] = g
        return g.grant_id, seal_control(self.u.policy, s, topic, encode(g))

    def _forget_grants(self, device_id: bytes, sid: bytes, now: int) -> None:
        """Bounded memory (each GRANT carries a 3,309-B σ): a device's GRANTs of an earlier session died with it
        (§13.4), and one expired beyond the device-clock slack can no longer be used on either side."""
        old = self._grant_sid.get(device_id)
        if old is not None and old != sid:
            self._grants.pop(old, None)
        self._grant_sid[device_id] = sid
        live = self._grants.get(sid, {})
        for gid in [gid for gid, g in live.items() if now >= g.expires_at + GRANT_CLOCK_SLACK_S]:
            del live[gid]

    def setpoint(self, device_id: bytes, grant_id: bytes, value: int, ttl_s: int) -> bytes:
        topic = self._topic(device_id, CmdType.SETPOINT)
        s = self._live(device_id)
        g = self._grants.get(s.sid, {}).get(grant_id)
        if g is None:
            raise CommandError("no GRANT with this id in the live session")
        if not g.min <= value <= g.max:
            raise CommandError("value outside the GRANT bounds")
        return seal_control(self.u.policy, s, topic, encode(Setpoint(grant_id, value, self.now() + ttl_s)))

    # ---------------------------------------------------------------------------------------------- status
    def on_status(self, ack: bytes) -> tuple[bytes, int, bytes]:
        """Verify a status ACK (DR-045) and settle the queue. Returns (device_id, cmd_seq, status)."""
        try:
            sid = status_sid(ack)
        except WireError as e:
            raise EnvelopeError("malformed status ack") from e
        s = self.u.sessions.get(sid)
        if s is None:
            raise EnvelopeError("status for an unknown session")
        if not self.u.active(s.device_id):                               # current revocation state (H1)
            raise EnvelopeError("status from a revoked device")
        if not ct_eq(s.policy_info, self.u.policy.info()):               # P10 (M1)
            raise EnvelopeError("status on a session of an old policy")
        if self.u.end_expired_chain(s):                                  # M2: the session ended with its chain
            raise EnvelopeError("status on a session whose chain expired")
        msg_seq, cmd_seq, status = verify_status_ack(s, ack)
        q = self.store.get(s.device_id, cmd_seq)
        if q is not None and q.status is None:                     # GRANT/SETPOINT/ZONEKEY have no queue entry
            if status in (b"DUP", b"SUPERSEDED") and q.sends == 1 and msg_seq != 0:
                self.alarms.append(("sequence regression", s.device_id, cmd_seq, status))   # V-S2
            if status == b"INTERRUPTED":
                self.interrupted.append((s.device_id, cmd_seq))
            self.store.close(q, status)
        return s.device_id, cmd_seq, status
