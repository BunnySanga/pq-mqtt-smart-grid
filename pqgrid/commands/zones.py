"""Demand-response zones: logical zones, per-AEAD crypto groups, ZONEKEY delivery and signed broadcast events
(Master §4.7, §11; DR-020, DR-047 as amended, DR-048; remediation M4, M5, M7).

A LOGICAL zone (name, members, bseq, events) has one CRYPTO GROUP per AEAD used by its members' classes. Each
group has its own ZONEKEY, key epoch and topic (clarification 4):

    grid/dr/{zone}/{group}/event          group = the AEAD token: aes256gcm or chacha20poly1305
    enc[0x04, zone, group, u64 key_epoch, u64 bseq, nonce(12),
        AEAD_group(K_group, nonce, enc[event, u64 expires_at, σ], AAD = H("BCAST", zone, group, key_epoch, bseq))]
    σ = ML-DSA-65("pqgrid/v2/bcast" ‖ H(zone, bseq, expires_at, event))        logical: no group, no key epoch

  * one logical event = one σ and one bseq, sealed once per group: an AES member and a ChaCha member receive the
    same event identity, and the device's replay state is per LOGICAL zone (DR-048);
  * bseq = utility epoch(32) ‖ per-zone counter(32): a utility restart never moves it backwards (clarification 5);
  * membership is logical; a member's group is its class AEAD in the current policy. A join rotates the joiner's
    group key (a new member cannot read earlier ciphertexts); a removal rotates every group of the zone (the
    removed device cannot read anything published afterwards, whichever group key it held) (E-Z1);
  * the utility keeps every still-valid event (M4). After a member (re)establishes it gets its ZONEKEY and then
    the still-valid events issued while it was a member, re-encrypted under its group's CURRENT key with the same
    σ and bseq, both on its control topic, so MQTT's per-topic order puts the key first. The device drops those
    it already accepted (bseq). This replaces the device's early-event RAM buffer (E55, M5).
  * members can read but never forge events (σ; DR-020).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from ..errors import CommandError, CryptoError, EnvelopeError, PolicyError, ReplayError, WireError
from ..policy.model import Tier
from ..suite import aead
from ..suite.aead import AeadAlg
from ..suite.kdf import h
from ..suite.rand import random_bytes
from ..suite.sig import mldsa_sign, mldsa_verify
from ..wire import dec, enc, r64, u64
from .codec import ZONE_KEY_LEN, ZoneKey, bcast_signed_input, encode, valid_token

T_BCAST = b"\x04"
KEEP_EPOCHS = 2                   # an event sealed just before a rotation still opens
ZONE_SYNC_MIN_S = 5               # at most one zone-sync answer per (device, zone) this often (E-2)


class ZoneKeyMissing(EnvelopeError):
    """A DR event whose (zone, group, key epoch) this device holds no key for. Not silent: the transport records
    it and asks the utility for a zone sync (E-2)."""

    def __init__(self, zone: str, epoch: int):
        super().__init__("no key for zone/epoch")
        self.zone, self.epoch = zone, epoch
MAX_RETAINED = 64                 # still-valid events kept per zone for re-sending (M4)
MAX_ZONES = 16                    # zones per device: each costs the device one persisted bseq record (budget)


def group_of(alg: AeadAlg) -> str:
    return alg.value.lower()


_GROUPS = {group_of(a): a for a in AeadAlg}


def event_topic(zone: str, alg: AeadAlg) -> str:
    return f"grid/dr/{zone}/{group_of(alg)}/event"


def _parse(env: bytes):
    try:
        t, zone_b, group_b, epoch_b, bseq_b, nonce, ct = dec(env, 7)
        zone, alg = zone_b.decode("ascii"), _GROUPS[group_b.decode("ascii")]
        return t, zone, alg, r64(epoch_b), r64(bseq_b), nonce, ct, (zone_b, group_b, epoch_b, bseq_b)
    except (WireError, UnicodeDecodeError, KeyError) as e:
        raise EnvelopeError("malformed broadcast") from e


def seal_event(zone: str, alg: AeadAlg, key_epoch: int, key: bytes, bseq: int, expires_at: int, event: bytes,
               sig: bytes) -> bytes:
    nonce = random_bytes(aead.NONCE_LEN)                        # random: the group key is shared, U is the sender
    zb, gb, eb, bb = zone.encode(), group_of(alg).encode(), u64(key_epoch), u64(bseq)
    ct = aead.seal(alg, key, nonce, enc([event, u64(expires_at), sig]), h(b"BCAST", zb, gb, eb, bb))
    return enc([T_BCAST, zb, gb, eb, bb, nonce, ct])


# ================================================================================================== device
class ZoneReceiver:
    """Group keys live in RAM (re-sent under each new session); the last accepted bseq per LOGICAL zone lives in
    `state` (flash, DR-048)."""

    def __init__(self, device, state):
        self.d, self.state = device, state
        self._keys: dict[tuple[str, AeadAlg], dict[int, ZoneKey]] = {}
        self.installs: dict[str, int] = {}                     # ZONEKEYs received per zone (sync bookkeeping)

    def install(self, z: ZoneKey) -> None:
        self.installs[z.zone] = self.installs.get(z.zone, 0) + 1
        ks = self._keys.setdefault((z.zone, z.aead), {})
        ks[z.key_epoch] = z
        for old in sorted(ks)[:-KEEP_EPOCHS]:
            del ks[old]

    def zones(self) -> set[str]:
        return {zone for zone, _ in self._keys}

    def open(self, topic: str, env: bytes) -> bytes:
        t, zone, alg, epoch, bseq, nonce, ct, aad = _parse(env)
        if t != T_BCAST or topic != event_topic(zone, alg) or self.d.policy.tier(topic) is not Tier.CONTROL:
            raise EnvelopeError("not a broadcast for this topic")
        z = self._keys.get((zone, alg), {}).get(epoch)
        if z is None:
            raise ZoneKeyMissing(zone, epoch)
        if bseq <= self.state.zone_bseq.get(zone, 0):              # phase 1: before decryption
            raise ReplayError("broadcast replay: bseq not newer than the last accepted for this zone")
        try:
            event, exp_b, sig = dec(aead.open_(z.aead, z.key, nonce, ct, h(b"BCAST", *aad)), 3)
            exp = r64(exp_b)
        except (CryptoError, WireError) as e:
            raise EnvelopeError("broadcast failed authentication") from e
        if self.d.now() >= exp:
            raise EnvelopeError("broadcast expired")
        if not mldsa_verify(self.d.policy.utility_cmd_pk, sig, bcast_signed_input(zone, bseq, exp, event)):
            raise EnvelopeError("broadcast signature invalid")    # a member holds K_group but not the command key
        self.state.write_zone_bseq(zone, bseq)                    # phase 2: a flash record (DR-048)
        return event

    def open_resent(self, env: bytes) -> tuple[str, bytes]:
        """An event the utility re-sent on this device's own control topic (M4): exactly the checks of `open`,
        for the group named in the envelope (the device holds only its own group's keys). Returns (zone, event)."""
        _, zone, alg, *_ = _parse(env)
        return zone, self.open(event_topic(zone, alg), env)


# ================================================================================================= utility
@dataclass
class GroupKey:
    key_epoch: int = 0
    key: bytes = field(default=b"", repr=False)
    rotated_at: int = 0                                        # utility time of the last rotation (weekly rule)


@dataclass
class LogicalEvent:
    zone: str
    bseq: int
    expires_at: int
    event: bytes
    sig: bytes = field(repr=False)


@dataclass
class Zone:
    name: str
    members: dict = field(default_factory=dict)                # device_id → last bseq issued before it joined
    groups: dict = field(default_factory=dict)                 # AeadAlg → GroupKey
    counter: int = 0                                           # RAM: the utility epoch makes restarts safe
    events: list = field(default_factory=list)                 # still-valid LogicalEvents, in bseq order (M4)


class ZoneManager:
    def __init__(self, service):
        self.svc = service                                     # a CommandService: utility, command key, epoch
        self.alarms: list[tuple] = []                          # retention overflow (M4): never silent
        self._last_sync: dict[tuple[bytes, str], int] = {}     # (device, zone) → time of the last sync answer
        self.zones: dict[str, Zone] = self._load()
        self._finish_revocations()

    def _finish_revocations(self) -> None:
        """H1 at start: revocation is made durable in the registry before the device leaves its zones. A crash in
        between left a revoked member holding the CURRENT zone key after the restart, able to read every event
        published afterwards; it leaves its zones now, with new keys (the others get them when they establish)."""
        for did in sorted({d for z in self.zones.values() for d in z.members if not self.svc.u.active(d)}):
            self.remove_device(did)

    # persistence hooks (persistence.utility_db); in memory they do nothing
    def _load(self) -> dict[str, Zone]:
        return {}

    def _save(self, z: Zone) -> None:
        pass

    def _save_event(self, ev: LogicalEvent) -> None:
        pass

    def _drop_events(self, zone: str, bseqs: list[int]) -> None:
        pass

    def _save_event_sig(self, ev: LogicalEvent) -> None:
        pass

    # ------------------------------------------------------------------------------------------ membership
    def create(self, name: str) -> Zone:
        if not valid_token(name) or name in self.zones:
            raise CommandError("invalid or duplicate zone name")
        z = self.zones[name] = Zone(name)
        self._save(z)
        return z

    def group_for(self, device_id: bytes) -> Optional[AeadAlg]:
        """The crypto group of a device: its class AEAD in the current policy (None if the class is unknown)."""
        rec = self.svc.u.registry.get(device_id)
        try:
            return self.svc.u.policy.profile(rec.dclass).aead if rec is not None else None
        except PolicyError:
            return None

    def members_of(self, name: str, alg: AeadAlg) -> list[bytes]:
        return sorted(d for d in self.zones[name].members if self.group_for(d) is alg)

    def add_member(self, name: str, device_id: bytes) -> None:
        z = self.zones[name]
        alg = self.svc.class_profile(device_id).aead           # unknown or revoked: refused here
        if device_id not in z.members and sum(device_id in x.members for x in self.zones.values()) >= MAX_ZONES:
            raise CommandError(f"device already in {MAX_ZONES} zones (its flash budget)")
        z.members.setdefault(device_id, (self.svc.epoch << 32) | z.counter)   # a re-join keeps its start
        self._rotate(z, [alg])

    def remove_member(self, name: str, device_id: bytes) -> None:
        z = self.zones[name]
        z.members.pop(device_id, None)
        self._rotate(z, list(z.groups))

    def remove_device(self, device_id: bytes) -> list[str]:
        """Revocation (H1): the device leaves every zone and each affected zone gets new keys, so it cannot read
        events published from now on. Returns the affected zones (their members need the new keys)."""
        affected = [z.name for z in self.zones.values() if device_id in z.members]
        for name in affected:
            self.remove_member(name, device_id)
        return affected

    def rotate(self, name: str) -> None:
        z = self.zones[name]
        self._rotate(z, list(z.groups))

    def rotate_device(self, device_id: bytes) -> list[str]:
        """Re-provisioning (Codex audit P1-1): the device stays in its zones, but every group key it could hold under
        its old record is replaced. Returns the affected zones (their members need the new keys)."""
        affected = [z.name for z in self.zones.values() if device_id in z.members]
        for name in affected:
            self.rotate(name)
        return affected

    def rotate_all(self) -> list[str]:
        """A policy change (key table §4.7): every group of every zone gets a new key."""
        for z in self.zones.values():
            self._rotate(z, list(z.groups))
        return sorted(self.zones)

    def rotate_due(self, max_age_s: int) -> list[str]:
        """The weekly rule (§4.7): each group whose key is at least max_age_s old gets a new one."""
        now, out = self.svc.now(), []
        for z in self.zones.values():
            due = [a for a, g in z.groups.items() if now - g.rotated_at >= max_age_s]
            if due:
                self._rotate(z, due)
                out.append(z.name)
        return out

    def _rotate(self, z: Zone, algs) -> None:
        now = self.svc.now()
        for alg in algs:
            g = z.groups.setdefault(alg, GroupKey())
            g.key_epoch += 1
            g.key = random_bytes(ZONE_KEY_LEN)
            g.rotated_at = now
        self._save(z)                                          # membership and the new keys saved together

    def _group_key(self, z: Zone, alg: AeadAlg) -> GroupKey:
        if alg not in z.groups:                                # a member's class moved to a new AEAD (policy)
            self._rotate(z, [alg])
        return z.groups[alg]

    # --------------------------------------------------------------------------------------------- ZONEKEY
    def _zonekey(self, z: Zone, did: bytes) -> Optional[bytes]:
        alg = self.group_for(did)
        if alg is None or not self.svc.has_session(did):
            return None
        g = self._group_key(z, alg)
        return self.svc.seal_for(did, encode(ZoneKey(z.name, g.key_epoch, alg, g.key)))

    def zonekeys_for(self, device_id: bytes) -> list[bytes]:
        """ZONEKEY envelopes for every zone the device belongs to, under its live session (none if offline)."""
        out = [self._zonekey(z, device_id) for z in self.zones.values() if device_id in z.members]
        return [e for e in out if e is not None]

    def distribute(self, name: str) -> dict[bytes, bytes]:
        """Its group's current key to every member with a live session; the others get it at their next session."""
        z = self.zones[name]
        out = {did: self._zonekey(z, did) for did in sorted(z.members)}
        return {did: e for did, e in out.items() if e is not None}

    # ---------------------------------------------------------------------------------------------- events
    def publish(self, name: str, event: bytes, ttl_s: int,
                check: Optional[Callable[[AeadAlg, str, bytes], None]] = None) -> dict[str, bytes]:
        """Issue one logical event and seal it once per crypto group that has members: {topic: envelope}.
        `check` may refuse a publication (e.g. too large for a member) before the event is retained."""
        z, now = self.zones[name], self.svc.now()
        self._prune(z, now)
        z.counter += 1
        bseq = (self.svc.epoch << 32) | z.counter
        exp = now + ttl_s
        ev = LogicalEvent(name, bseq, exp, event, mldsa_sign(self.svc.cmd_key, bcast_signed_input(name, bseq, exp,
                                                                                                    event)))
        algs = sorted({a for a in map(self.group_for, z.members) if a is not None}, key=lambda a: a.value)
        out = {}
        for alg in algs:
            topic, env = event_topic(name, alg), self._seal(z, alg, ev)
            if check is not None:
                check(alg, topic, env)
            out[topic] = env
        self._retain(z, ev)
        return out

    def _seal(self, z: Zone, alg: AeadAlg, ev: LogicalEvent) -> bytes:
        g = self._group_key(z, alg)
        signed = bcast_signed_input(ev.zone, ev.bseq, ev.expires_at, ev.event)
        if not mldsa_verify(self.svc.u.policy.utility_cmd_pk, ev.sig, signed):   # retained across a command-key
            ev.sig = mldsa_sign(self.svc.cmd_key, signed)                         # rotation: re-signed under the
            self._save_event_sig(ev)                                              # active key (DR-051), same bseq
        return seal_event(z.name, alg, g.key_epoch, g.key, ev.bseq, ev.expires_at, ev.event, ev.sig)

    def resend_for(self, device_id: bytes) -> list[bytes]:
        """M4: after the device (re)established, the still-valid events of its zones that were issued while it was
        a member, re-encrypted under its group's current key (same σ, same bseq), in bseq order per zone."""
        alg, now, out = self.group_for(device_id), self.svc.now(), []
        if alg is None or not self.svc.has_session(device_id):
            return out
        for z in self.zones.values():
            if device_id not in z.members:
                continue
            self._prune(z, now)
            joined = z.members[device_id]
            out += [self._seal(z, alg, ev) for ev in z.events if ev.bseq > joined]
        return out

    def sync_for(self, device_id: bytes, name: str) -> list[bytes]:
        """E-2: the answer to a device's zone sync request, for its control topic, in this order: its group's
        CURRENT ZONEKEY, then the zone's still-valid events issued while it was a member, re-encrypted under that
        key (same σ, same bseq). Refused for a non-member, without a live session, or more often than
        ZONE_SYNC_MIN_S per (device, zone)."""
        z, now = self.zones.get(name), self.svc.now()
        if z is None or device_id not in z.members:
            raise CommandError("zone sync from a device that is not a member")
        if now - self._last_sync.get((device_id, name), -ZONE_SYNC_MIN_S) < ZONE_SYNC_MIN_S:
            raise CommandError("zone sync rate-limited")
        key = self._zonekey(z, device_id)
        if key is None:
            raise CommandError("zone sync without a live session under the current policy")
        self._last_sync[(device_id, name)] = now
        self._prune(z, now)
        alg, joined = self.group_for(device_id), z.members[device_id]
        return [key] + [self._seal(z, alg, ev) for ev in z.events if ev.bseq > joined]

    def _retain(self, z: Zone, ev: LogicalEvent) -> None:
        z.events.append(ev)
        self._save_event(ev)
        if len(z.events) > MAX_RETAINED:
            gone = z.events.pop(0)
            self._drop_events(z.name, [gone.bseq])
            self.alarms.append(("retention overflow: oldest valid event no longer re-sent", z.name, gone.bseq))

    def _prune(self, z: Zone, now: int) -> None:
        gone = [ev.bseq for ev in z.events if now >= ev.expires_at]
        if gone:
            z.events = [ev for ev in z.events if now < ev.expires_at]
            self._drop_events(z.name, gone)
