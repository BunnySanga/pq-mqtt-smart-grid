"""The utility's durable state in SQLite (Master §16; IMPLEMENTATION-ROADMAP §10.1, E43, E45).

journal_mode = WAL, synchronous = FULL: a transaction commits entirely or not at all, and is on disk when the
commit returns. Every promise is committed before it is communicated (P8):
  * a consumed ticket before RS is built (I-8);
  * a new STEK before a ticket is sealed under it;
  * a command's sequence together with the queued, signed command, before it is sent (§13.6);
  * a revocation, a zone membership change and its new group keys;
  * a DR event before it is published (it is re-sent after a member re-establishes: M4);
  * the rollout state (Master §4.4, U-4): the active and the scheduled POLICY artifact, with the anchors and
    revocations they were verified against, before the policy takes effect or is promised; the publisher's newest
    artifacts, what is retained since when and the anchors its KEYREVOKEs revoked, before the broker is told;
  * the utility's private keys (keyring, DR-051), before a policy naming them can be scheduled (HSM in production).
Sessions, half-open handshakes and the duplicate cache stay in RAM (recovered through resync + PASR).

u64 values that can exceed 2^63 (cmd_seq = epoch ‖ counter reaches 2^63 in January 2038) are stored as 8-byte
big-endian BLOBs, whose byte order equals their numeric order (E45).
"""
from __future__ import annotations

import os
import sqlite3
import stat
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass

from ..commands.codec import Command
from ..commands.utility import CommandService, QueuedCommand, UtilityCommandStore
from ..commands.zones import GroupKey, LogicalEvent, Zone, ZoneManager
from ..e2e.handshake import UtilityEndpoint
from ..errors import PolicyError
from ..fota.artifact import MAX_CHUNKS, MAX_PARTS, decode_manifest, split_signed
from ..fota.publisher import Published, Publisher, Removal
from ..fota.station import Artifact
from ..keyring import UtilityKeyring
from ..pasr.stek import StekKey, StekTable
from ..pasr.tickets import TicketIssuer, UsedTickets
from ..registry import DeviceRecord, Registry
from ..suite.aead import AeadAlg
from ..suite.hkem import HybridKeyPair
from ..suite.sig import mldsa_from_private_bytes, mldsa_private_bytes, mldsa_public_bytes
from ..wire import dec, dec_list, enc, enc_list, r8, r64, u8, u64

SCHEMA = """
CREATE TABLE IF NOT EXISTS utility_epoch(id INTEGER PRIMARY KEY CHECK (id = 1), last_epoch INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS device_seq(device_id BLOB PRIMARY KEY, counter INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS commands(
    device_id BLOB NOT NULL, cmd_seq BLOB NOT NULL, topic TEXT NOT NULL, body BLOB NOT NULL, sig BLOB NOT NULL,
    expires_at INTEGER NOT NULL, idempotent INTEGER NOT NULL, status BLOB,
    sends INTEGER NOT NULL DEFAULT 0, last_sid BLOB NOT NULL DEFAULT x'', provisioned_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (device_id, cmd_seq));
CREATE INDEX IF NOT EXISTS commands_open ON commands(device_id, cmd_seq) WHERE status IS NULL;
CREATE TABLE IF NOT EXISTS used_tickets(ticket_id BLOB PRIMARY KEY, expires_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS used_tickets_expiry ON used_tickets(expires_at);
CREATE TABLE IF NOT EXISTS stek(kid INTEGER PRIMARY KEY, key BLOB NOT NULL, created_at INTEGER NOT NULL,
                                retire_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS registry(device_id BLOB PRIMARY KEY, dclass TEXT NOT NULL, e2e_pk BLOB NOT NULL,
                                    active INTEGER NOT NULL, max_packet INTEGER,
                                    provisioned_at INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS zones(name TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS zone_groups(name TEXT NOT NULL, aead TEXT NOT NULL, key_epoch INTEGER NOT NULL,
                                       key BLOB NOT NULL, rotated_at INTEGER NOT NULL, PRIMARY KEY (name, aead));
CREATE TABLE IF NOT EXISTS zone_members(name TEXT NOT NULL, device_id BLOB NOT NULL, joined_bseq BLOB NOT NULL,
                                        PRIMARY KEY (name, device_id));
CREATE TABLE IF NOT EXISTS zone_events(name TEXT NOT NULL, bseq BLOB NOT NULL, expires_at INTEGER NOT NULL,
                                       event BLOB NOT NULL, sig BLOB NOT NULL, PRIMARY KEY (name, bseq));
CREATE TABLE IF NOT EXISTS policy_state(slot TEXT PRIMARY KEY CHECK (slot IN ('active', 'scheduled')),
                                        signed BLOB NOT NULL, payload BLOB NOT NULL, anchors BLOB NOT NULL,
                                        revoked BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS artifacts(dclass TEXT NOT NULL, type INTEGER NOT NULL, signed BLOB NOT NULL,
                                     payload BLOB NOT NULL, parts BLOB NOT NULL, chunks BLOB NOT NULL,
                                     retained_at REAL, topics BLOB, confirmed INTEGER NOT NULL DEFAULT 0,
                                     PRIMARY KEY (dclass, type));
CREATE TABLE IF NOT EXISTS artifact_removals(dclass TEXT NOT NULL, type INTEGER NOT NULL, version INTEGER NOT NULL,
                                             topics BLOB NOT NULL, PRIMARY KEY (dclass, type, version));
CREATE TABLE IF NOT EXISTS revoked_anchors(anchor INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS class_floor(dclass TEXT PRIMARY KEY, max_packet INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS utility_keys(kind TEXT NOT NULL CHECK (kind IN ('kem', 'cmd')), pk BLOB NOT NULL,
                                        sk BLOB NOT NULL, PRIMARY KEY (kind, pk));
"""
MAX_ANCHORS = 16
DB_MODE = 0o600                                   # the database holds private keys and STEKs (P1-3)


def require_owner_only(path: str) -> None:
    """Codex audit P1-3: the utility database holds the utility's private keys and the STEKs, so its file and the
    files SQLite keeps beside it (-wal, -shm, -journal) must belong to this process's user and be readable or
    writable by nobody else. Checked when a database (or a restored backup) is opened and when a backup is written;
    raises PermissionError otherwise."""
    for f in (path, path + "-wal", path + "-shm", path + "-journal"):
        try:
            st = os.stat(f)
        except FileNotFoundError:
            continue
        if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
            raise PermissionError(f"{f}: mode {stat.S_IMODE(st.st_mode):04o}, owner uid {st.st_uid}: the utility "
                                  f"database holds private keys and STEKs and must be owner-only (chmod 600)")
MAX_TOPICS = MAX_PARTS + MAX_CHUNKS


class UtilityDB:
    def __init__(self, path: str):
        self.path = path
        if not os.path.exists(path):                          # holds the STEK: owner-only (0600)
            os.close(os.open(path, os.O_CREAT | os.O_RDWR, DB_MODE))
        require_owner_only(path)                              # an existing file, or a restored backup (P1-3)
        # One connection shared by the MQTT thread and the application: every statement and transaction runs
        # under self.lock, so check_same_thread can be off without two threads ever interleaving on it.
        self.lock = threading.RLock()
        self.c = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        if self.c.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() != "wal":
            raise RuntimeError("SQLite WAL mode is not available")
        self.c.execute("PRAGMA synchronous=FULL")
        self.c.execute("PRAGMA fullfsync=ON")                 # macOS: fsync alone does not flush the drive (E46)
        if self.c.execute("PRAGMA synchronous").fetchone()[0] != 2:
            raise RuntimeError("SQLite synchronous=FULL was not applied")
        self.c.executescript(SCHEMA)
        if "provisioned_at" not in {r[1] for r in self.c.execute("PRAGMA table_info(commands)")}:
            # Before the second Codex review (finding 2): commands issued under the record as it is now (0, never
            # re-provisioned) or before a re-provisioning that UtilityNode.reprovision already closed them for.
            self.c.execute("ALTER TABLE commands ADD COLUMN provisioned_at INTEGER NOT NULL DEFAULT 0")
        if "provisioned_at" not in {r[1] for r in self.c.execute("PRAGMA table_info(registry)")}:
            # A database from before §16 (P1-1): no device was re-provisioned under the floor yet.
            self.c.execute("ALTER TABLE registry ADD COLUMN provisioned_at INTEGER NOT NULL DEFAULT 0")
        if "confirmed" not in {r[1] for r in self.c.execute("PRAGMA table_info(artifacts)")}:
            # A database from before IMPLEMENTATION-ROADMAP §16 (P1-2): its retained artifacts count as unconfirmed,
            # so the publisher sends them once more rather than trusting a publication that may never have arrived.
            self.c.execute("ALTER TABLE artifacts ADD COLUMN confirmed INTEGER NOT NULL DEFAULT 0")

    @contextmanager
    def tx(self):
        """One atomic, durable transaction."""
        with self.lock:
            self.c.execute("BEGIN IMMEDIATE")
            try:
                yield self.c
            except BaseException:
                self.c.execute("ROLLBACK")
                raise
            self.c.execute("COMMIT")

    def execute(self, sql: str, params=()) -> list:
        """One statement (its own durable transaction in autocommit mode); returns all rows."""
        with self.lock:
            return self.c.execute(sql, params).fetchall()

    def one(self, sql: str, params=()):
        rows = self.execute(sql, params)
        return rows[0] if rows else None

    # ------------------------------------------------------------------------------ rollout state (U-4)
    def save_policy(self, slot: str, signed: bytes, payload: bytes, anchors: dict, revoked) -> None:
        """The active or the scheduled POLICY artifact, with the anchors and revocations it was verified against:
        durable before the policy takes effect or is promised (P8)."""
        blob = enc_list([enc([u8(a), pk]) for a, pk in sorted(anchors.items())], MAX_ANCHORS)
        self.execute("INSERT OR REPLACE INTO policy_state VALUES (?, ?, ?, ?, ?)",
                     (slot, signed, payload, blob, bytes(sorted(revoked))))

    def load_policy(self, slot: str):
        """(signed, payload, anchors, revoked) as saved, or None."""
        row = self.one("SELECT signed, payload, anchors, revoked FROM policy_state WHERE slot = ?", (slot,))
        if row is None:
            return None
        signed, payload, blob, revoked = row
        anchors = {r8(a): pk for a, pk in (dec(x, 2) for x in dec_list(blob, MAX_ANCHORS))}
        return signed, payload, anchors, frozenset(revoked)

    def drop_policy(self, slot: str) -> None:
        self.execute("DELETE FROM policy_state WHERE slot = ?", (slot,))

    # ------------------------------------------------------------------ revoked anchors (DR-050 as amended)
    def revoked_anchors(self) -> frozenset:
        """The utility's ONE authoritative set of revoked anchors (audit M-1): every anchor a KEYREVOKE published by
        this utility revoked, durable before the broker was told."""
        return frozenset(a for (a,) in self.execute("SELECT anchor FROM revoked_anchors"))

    def add_revoked(self, anchor: int) -> None:
        self.execute("INSERT OR IGNORE INTO revoked_anchors VALUES (?)", (anchor,))

    def backup_to(self, path: str) -> None:
        """A consistent copy (for restore tests: V-S1). It holds the same private keys and STEKs, so it is owner-only
        like the database (P1-3): created 0600 whatever the umask, and an existing file is narrowed to 0600 before
        anything is written into it (sqlite3.connect alone created it with the default mode, 0644 under umask 022).
        SQLite gives the copy's journal the copy's mode."""
        fd = os.open(path, os.O_CREAT | os.O_WRONLY, DB_MODE)
        try:
            os.fchmod(fd, DB_MODE)                            # an existing file keeps its old mode on open
        finally:
            os.close(fd)
        require_owner_only(path)
        dst = sqlite3.connect(path)
        with dst:
            self.c.backup(dst)
        dst.close()

    def close(self) -> None:
        self.c.close()


# ====================================================================================================== PASR
class SqlStekTable(StekTable):
    def __init__(self, db: UtilityDB):
        super().__init__()
        self.db = db
        for kid, key, created, retire in db.execute("SELECT kid, key, created_at, retire_at FROM stek"):
            self._keys[kid] = StekKey(kid, key, created, retire)
        if self._keys:
            self._current = max(self._keys.values(), key=lambda k: k.created_at)

    def _store_new(self, k: StekKey) -> None:
        self.db.execute("INSERT OR REPLACE INTO stek VALUES (?, ?, ?, ?)", (k.kid, k.key, k.created_at, k.retire_at))

    def _store_retired(self, kids: list[int]) -> None:
        with self.db.tx() as c:
            c.executemany("DELETE FROM stek WHERE kid = ?", [(k,) for k in kids])


class SqlUsedTickets(UsedTickets):
    PRUNE_EVERY_S = 60                                     # E43

    def __init__(self, db: UtilityDB):
        super().__init__()
        self.db = db
        self._last_prune = float("-inf")

    def consume(self, ticket_id: bytes, expires_at: int, now: int) -> bool:
        if now - self._last_prune >= self.PRUNE_EVERY_S:
            self.db.execute("DELETE FROM used_tickets WHERE expires_at <= ?", (now,))
            self._last_prune = now
        try:                                               # one insert, committed (fsync) before returning
            self.db.execute("INSERT INTO used_tickets VALUES (?, ?)", (ticket_id, expires_at))
        except sqlite3.IntegrityError:
            return False
        return True

    def __len__(self) -> int:
        return self.db.one("SELECT COUNT(*) FROM used_tickets")[0]


# ================================================================================================= commands
def _row_to_queued(row) -> QueuedCommand:
    did, seq, topic, body, sig, exp, idem, status, sends, last_sid, prov = row
    return QueuedCommand(did, topic, Command(r64(seq), body, exp, bool(idem), sig), sends, last_sid, status, prov)


_COLS = "device_id, cmd_seq, topic, body, sig, expires_at, idempotent, status, sends, last_sid, provisioned_at"


class SqlCommandStore(UtilityCommandStore):
    def __init__(self, db: UtilityDB):
        self.db = db

    @property
    def last_epoch(self) -> int:
        row = self.db.one("SELECT last_epoch FROM utility_epoch WHERE id = 1")
        return row[0] if row else 0

    def start(self, now: int) -> int:
        with self.db.tx() as c:
            row = c.execute("SELECT last_epoch FROM utility_epoch WHERE id = 1").fetchone()
            epoch = max(int(now), (row[0] if row else 0) + 1)
            c.execute("INSERT OR REPLACE INTO utility_epoch VALUES (1, ?)", (epoch,))
        return epoch

    def _allocate(self, c, device_id: bytes, epoch: int) -> int:
        row = c.execute("SELECT counter FROM device_seq WHERE device_id = ?", (device_id,)).fetchone()
        n = (row[0] if row else 0) + 1
        if n >= 1 << 32:
            raise OverflowError("command counter exhausted for this device")
        c.execute("INSERT OR REPLACE INTO device_seq VALUES (?, ?)", (device_id, n))
        return (epoch << 32) | n

    def allocate(self, device_id: bytes, epoch: int) -> int:
        with self.db.tx() as c:
            return self._allocate(c, device_id, epoch)

    def allocate_and_enqueue(self, device_id: bytes, epoch: int, build) -> QueuedCommand:
        with self.db.tx() as c:                            # sequence + queued command: one transaction (§16)
            q = build(self._allocate(c, device_id, epoch))
            c.execute(f"INSERT INTO commands ({_COLS}) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 0, x'', ?)",
                      (device_id, u64(q.cmd.cmd_seq), q.topic, q.cmd.command, q.cmd.sig, q.cmd.expires_at,
                       int(q.cmd.idempotent), q.provisioned_at))
        return q

    def open_commands(self, device_id: bytes) -> list[QueuedCommand]:
        return [_row_to_queued(r) for r in self.db.execute(
            f"SELECT {_COLS} FROM commands WHERE device_id = ? AND status IS NULL ORDER BY cmd_seq", (device_id,))]

    def get(self, device_id: bytes, cmd_seq: int):
        row = self.db.one(f"SELECT {_COLS} FROM commands WHERE device_id = ? AND cmd_seq = ?",
                          (device_id, u64(cmd_seq)))
        return _row_to_queued(row) if row else None

    def mark_sent(self, q: QueuedCommand, sid: bytes) -> None:
        self.db.execute("UPDATE commands SET sends = sends + 1, last_sid = ? WHERE device_id = ? AND cmd_seq = ?",
                          (sid, q.device_id, u64(q.cmd.cmd_seq)))
        q.sends, q.last_sid = q.sends + 1, sid

    def unmark_sent(self, q: QueuedCommand, prev_sid: bytes) -> None:
        self.db.execute("UPDATE commands SET sends = sends - 1, last_sid = ? WHERE device_id = ? AND cmd_seq = ?",
                        (prev_sid, q.device_id, u64(q.cmd.cmd_seq)))
        q.sends, q.last_sid = q.sends - 1, prev_sid

    def close(self, q: QueuedCommand, status: bytes) -> None:
        self.db.execute("UPDATE commands SET status = ? WHERE device_id = ? AND cmd_seq = ?",
                          (status, q.device_id, u64(q.cmd.cmd_seq)))
        q.status = status

    def resign(self, q: QueuedCommand, sig: bytes) -> None:
        self.db.execute("UPDATE commands SET sig = ? WHERE device_id = ? AND cmd_seq = ?",
                        (sig, q.device_id, u64(q.cmd.cmd_seq)))
        super().resign(q, sig)

    def snapshot(self):
        raise NotImplementedError("use UtilityDB.backup_to()")


# ============================================================================================ registry, zones
class SqlRegistry(Registry):
    def __init__(self, db: UtilityDB):
        super().__init__()
        self.db = db
        for did, dclass, pk, active, mp, prov in db.execute(
                "SELECT device_id, dclass, e2e_pk, active, max_packet, provisioned_at FROM registry"):
            self._d[did] = DeviceRecord(did, dclass, pk, bool(active), mp, prov)

    def _store(self, rec: DeviceRecord) -> None:
        self.db.execute("INSERT OR REPLACE INTO registry (device_id, dclass, e2e_pk, active, max_packet, "
                        "provisioned_at) VALUES (?, ?, ?, ?, ?, ?)",
                        (rec.device_id, rec.dclass, rec.e2e_pk, int(rec.active), rec.max_packet, rec.provisioned_at))


class SqlZoneManager(ZoneManager):
    def __init__(self, service, db: UtilityDB):
        self.db = db
        super().__init__(service)

    def _load(self) -> dict[str, Zone]:
        zones = {name: Zone(name) for (name,) in self.db.execute("SELECT name FROM zones")}
        for name, alg, epoch, key, at in self.db.execute(
                "SELECT name, aead, key_epoch, key, rotated_at FROM zone_groups"):
            zones[name].groups[AeadAlg(alg)] = GroupKey(epoch, key, at)
        for name, did, joined in self.db.execute("SELECT name, device_id, joined_bseq FROM zone_members"):
            zones[name].members[did] = r64(joined)
        for name, bseq, exp, event, sig in self.db.execute(
                "SELECT name, bseq, expires_at, event, sig FROM zone_events ORDER BY name, bseq"):
            zones[name].events.append(LogicalEvent(name, r64(bseq), exp, event, sig))
        return zones

    def _save(self, z: Zone) -> None:
        with self.db.tx() as c:                            # membership and the new group keys together
            c.execute("INSERT OR IGNORE INTO zones VALUES (?)", (z.name,))
            c.execute("DELETE FROM zone_groups WHERE name = ?", (z.name,))
            c.executemany("INSERT INTO zone_groups VALUES (?, ?, ?, ?, ?)",
                          [(z.name, a.value, g.key_epoch, g.key, g.rotated_at) for a, g in z.groups.items()])
            c.execute("DELETE FROM zone_members WHERE name = ?", (z.name,))
            c.executemany("INSERT INTO zone_members VALUES (?, ?, ?)",
                          [(z.name, d, u64(j)) for d, j in z.members.items()])

    def _save_event(self, ev: LogicalEvent) -> None:
        with self.db.tx() as c:                            # durable before it is published (P8)
            c.execute("INSERT INTO zone_events VALUES (?, ?, ?, ?, ?)",
                      (ev.zone, u64(ev.bseq), ev.expires_at, ev.event, ev.sig))

    def _drop_events(self, zone: str, bseqs: list[int]) -> None:
        with self.db.tx() as c:
            c.executemany("DELETE FROM zone_events WHERE name = ? AND bseq = ?", [(zone, u64(b)) for b in bseqs])

    def _save_event_sig(self, ev: LogicalEvent) -> None:
        self.db.execute("UPDATE zone_events SET sig = ? WHERE name = ? AND bseq = ?", (ev.sig, ev.zone, u64(ev.bseq)))


# ============================================================================================ publisher
class SqlPublisher(Publisher):
    """The artifact publisher's rollout state in SQLite (Master §4.4, U-4): per (class, type) the newest artifact and,
    while it is retained, its topics and publication time; the anchors revoked by the KEYREVOKEs it published; each
    class's delivery floor (the smallest max_packet any activated policy gave it, H-2).
    Without it a restarted utility could republish nothing (E-4), never cleaned up what it had retained, and forgot
    its revocations."""

    def __init__(self, db: UtilityDB, policy, clock=time.time):
        self.db = db
        super().__init__(policy, clock)
        for dclass, t, signed, payload, parts, chunks, at, topics, confirmed in db.execute(
                "SELECT dclass, type, signed, payload, parts, chunks, retained_at, topics, confirmed FROM artifacts"):
            art = Artifact(decode_manifest(split_signed(signed)[0]), signed, dec_list(parts, MAX_PARTS),
                           dec_list(chunks, MAX_CHUNKS), payload)
            self.newest[(dclass, t)] = art
            if at is not None:                                   # nothing in flight after a restart (P1-2)
                self.live[(dclass, t)] = Published(art, [x.decode() for x in dec_list(topics, MAX_TOPICS)], at,
                                                   bool(confirmed))
        self.revoked = set(db.revoked_anchors())

    def _store(self, key: tuple[str, int], art: Artifact, retained) -> None:
        topics = None if retained is None else enc_list([t.encode() for t in retained.topics], MAX_TOPICS)
        self.db.execute("INSERT OR REPLACE INTO artifacts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (key[0], key[1], art.signed, art.payload, enc_list(art.parts, MAX_PARTS),
                         enc_list(art.chunks, MAX_CHUNKS), None if retained is None else retained.at, topics,
                         int(retained is not None and retained.confirmed)))

    def _store_revoked(self, anchor: int) -> None:
        self.db.add_revoked(anchor)

    def current_revoked(self) -> set:
        return set(self.db.revoked_anchors()) | self.revoked

    def _load_floor(self) -> dict[str, int]:
        return {dclass: mp for dclass, mp in self.db.execute("SELECT dclass, max_packet FROM class_floor")}

    def _load_removals(self) -> list:
        return [Removal((dclass, t), v, [x.decode() for x in dec_list(topics, MAX_TOPICS)])
                for dclass, t, v, topics in self.db.execute(
                    "SELECT dclass, type, version, topics FROM artifact_removals ORDER BY dclass, type, version")]

    def _atomic(self):
        return self.db.tx()

    def _store_removal(self, r: Removal) -> None:
        self.db.execute("INSERT OR REPLACE INTO artifact_removals VALUES (?, ?, ?, ?)",
                        (r.key[0], r.key[1], r.version, enc_list([t.encode() for t in r.topics], MAX_TOPICS)))

    def _forget_removal(self, r: Removal) -> None:
        self.db.execute("DELETE FROM artifact_removals WHERE dclass = ? AND type = ? AND version = ?",
                        (r.key[0], r.key[1], r.version))

    def _store_floor(self, dclass: str, max_packet: int) -> None:
        self.db.execute("INSERT OR REPLACE INTO class_floor VALUES (?, ?)", (dclass, max_packet))


# ================================================================================================ keyring
class SqlKeyring(UtilityKeyring):
    """The utility's private keys in the database (prototype, L16; an HSM in production), written before they can be
    named by a scheduled policy (DR-051)."""

    def __init__(self, db: UtilityDB):
        super().__init__()
        self.db = db
        for kind, pk, sk in db.execute("SELECT kind, pk, sk FROM utility_keys ORDER BY rowid"):
            if kind == "kem":
                kp = HybridKeyPair.from_private_bytes(sk)
                if kp.pk == pk:
                    self._kem[pk] = kp
            else:
                cmd = mldsa_from_private_bytes(sk)
                if mldsa_public_bytes(cmd) == pk:
                    self._cmd[pk] = cmd

    def _store_kem(self, kp: HybridKeyPair) -> None:
        self.db.execute("INSERT OR IGNORE INTO utility_keys VALUES ('kem', ?, ?)", (kp.pk, kp.private_bytes()))

    def _store_cmd(self, sk) -> None:
        self.db.execute("INSERT OR IGNORE INTO utility_keys VALUES ('cmd', ?, ?)",
                        (mldsa_public_bytes(sk), mldsa_private_bytes(sk)))


# ================================================================================================= assembly
@dataclass
class UtilityNode:
    db: UtilityDB
    endpoint: UtilityEndpoint
    tickets: TicketIssuer
    commands: CommandService
    zones: ZoneManager
    keyring: UtilityKeyring

    def reprovision(self, rec: DeviceRecord, rotated=None) -> list[str]:
        """Codex audit P1-1: a registered device's class and/or E2E key change, and nothing authorised under its old
        record survives: its sessions and half-open handshakes (RAM), its resumption tickets (refused by the record's
        provisioning time), its open commands and GRANTs, and the zone keys it could hold. Crash-coherent order: the
        zone keys are rotated first (alone, a crash leaves an extra rotation); then the record and the closing of its
        commands are ONE transaction, so a restart sees either the old record with its commands or the new record
        without them; then the RAM state goes. Returns the zones whose live members need the new keys.
        `rotated(zones)` is called once the keys rotated, EVEN IF the record change then fails: the members must get
        the keys that are now in force either way (second Codex review, finding 5)."""
        self._check_reprovision(rec)                       # third review, finding 6: before ANY side effect
        zones = self.zones.rotate_device(rec.device_id)
        try:
            with self.db.tx():
                self.commands.cancel_device(rec.device_id)
                self.endpoint._reprovision_device(rec)
        finally:
            if rotated is not None:
                rotated(zones)
        return zones

    def _check_reprovision(self, rec: DeviceRecord) -> None:
        """Third Codex review, finding 6: everything that can refuse a re-provisioning is checked before the zone keys
        rotate or anything is written. The device must be registered, its new identity well formed (Registry._check),
        its class one the policy in force defines (otherwise it could never establish again), and a reported
        max_packet must not be below the class's: the utility sends at most min(both), so a smaller one could make
        the NT/FIN unpublishable (Master §25 L22)."""
        Registry._check(rec)
        if self.endpoint.registry.get(rec.device_id) is None:
            raise PolicyError("device not registered: use add()")
        prof = self.endpoint.policy.profile(rec.dclass)             # PolicyError: a class the policy does not have
        if rec.max_packet is not None and rec.max_packet < prof.max_packet:
            raise PolicyError(f"reported max_packet {rec.max_packet} B is below the class's {prof.max_packet} B: the "
                              f"NT/FIN could not be published (Master §25 L22)")

    def keys_match_policy(self) -> bool:
        """DR-051 invariant: the keys in use are exactly those the active policy names."""
        p = self.endpoint.policy
        return (self.endpoint.static.pk == p.utility_kem_pk
                and mldsa_public_bytes(self.commands.cmd_key) == p.utility_cmd_pk)


def open_utility(path: str, policy, static, cmd_key, clock) -> UtilityNode:
    """A utility process whose durable state is the database at `path`. Opening it again is a restart. `policy` is
    the bootstrap configuration and (`static`, `cmd_key`) the bootstrap keys, added to the keyring. A newer policy
    the utility activated earlier (rollout state, U-4) is resumed from the database, re-verified against the anchors
    it was accepted with (DR-050 as amended: an active policy stays in force until it is superseded). The keys in
    use are then taken from the keyring by the public keys the active policy names (DR-051): a restart after a key
    rotation resumes the new keys, and a policy whose private keys the utility does not hold is refused here
    (KeyringError) instead of starting a utility that no device can reach."""
    db = UtilityDB(path)
    keyring = SqlKeyring(db)
    keyring.add(kem=static, cmd=cmd_key)
    stored = db.load_policy("active")
    if stored is not None:
        from ..fota.policy_artifact import verify_policy_artifact
        active = verify_policy_artifact(*stored)           # its activation-time revocations: in force until superseded
        if active.version > policy.version:
            policy = active
    static, cmd_key = keyring.keys_for(policy)
    tickets = TicketIssuer(SqlStekTable(db), SqlUsedTickets(db))
    endpoint = UtilityEndpoint(policy, static, SqlRegistry(db), clock=clock, tickets=tickets)
    endpoint.retired = keyring.retired_kems(static.pk)
    commands = CommandService(endpoint, cmd_key, store=SqlCommandStore(db))
    return UtilityNode(db, endpoint, tickets, commands, SqlZoneManager(commands, db), keyring)
