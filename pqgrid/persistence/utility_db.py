"""The utility's durable state in SQLite (Master §16; IMPLEMENTATION-ROADMAP §10.1, E43, E45).

journal_mode = WAL, synchronous = FULL: a transaction commits entirely or not at all, and is on disk when the
commit returns. Every promise is committed before it is communicated (P8):
  * a consumed ticket before RS is built (I-8);
  * a new STEK before a ticket is sealed under it;
  * a command's sequence together with the queued, signed command, before it is sent (§13.6);
  * a revocation, a zone membership change and its new group keys;
  * a DR event before it is published (it is re-sent after a member re-establishes: M4);
  * the rollout state (Master §4.4, U-4): the active and the scheduled POLICY artifact, with the anchors and
    revocations they were verified against, before the policy takes effect or is promised.
Sessions, half-open handshakes and the duplicate cache stay in RAM (recovered through resync + PASR).

u64 values that can exceed 2^63 (cmd_seq = epoch ‖ counter reaches 2^63 in January 2038) are stored as 8-byte
big-endian BLOBs, whose byte order equals their numeric order (E45).
"""
from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass

from ..commands.codec import Command
from ..commands.utility import CommandService, QueuedCommand, UtilityCommandStore
from ..commands.zones import GroupKey, LogicalEvent, Zone, ZoneManager
from ..e2e.handshake import UtilityEndpoint
from ..pasr.stek import StekKey, StekTable
from ..pasr.tickets import TicketIssuer, UsedTickets
from ..registry import DeviceRecord, Registry
from ..suite.aead import AeadAlg
from ..wire import dec, dec_list, enc, enc_list, r8, r64, u8, u64

SCHEMA = """
CREATE TABLE IF NOT EXISTS utility_epoch(id INTEGER PRIMARY KEY CHECK (id = 1), last_epoch INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS device_seq(device_id BLOB PRIMARY KEY, counter INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS commands(
    device_id BLOB NOT NULL, cmd_seq BLOB NOT NULL, topic TEXT NOT NULL, body BLOB NOT NULL, sig BLOB NOT NULL,
    expires_at INTEGER NOT NULL, idempotent INTEGER NOT NULL, status BLOB,
    sends INTEGER NOT NULL DEFAULT 0, last_sid BLOB NOT NULL DEFAULT x'',
    PRIMARY KEY (device_id, cmd_seq));
CREATE INDEX IF NOT EXISTS commands_open ON commands(device_id, cmd_seq) WHERE status IS NULL;
CREATE TABLE IF NOT EXISTS used_tickets(ticket_id BLOB PRIMARY KEY, expires_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS used_tickets_expiry ON used_tickets(expires_at);
CREATE TABLE IF NOT EXISTS stek(kid INTEGER PRIMARY KEY, key BLOB NOT NULL, created_at INTEGER NOT NULL,
                                retire_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS registry(device_id BLOB PRIMARY KEY, dclass TEXT NOT NULL, e2e_pk BLOB NOT NULL,
                                    active INTEGER NOT NULL, max_packet INTEGER);
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
"""
MAX_ANCHORS = 16


class UtilityDB:
    def __init__(self, path: str):
        self.path = path
        if not os.path.exists(path):                          # holds the STEK: owner-only (0600)
            os.close(os.open(path, os.O_CREAT | os.O_RDWR, 0o600))
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

    def backup_to(self, path: str) -> None:
        """A consistent copy (for restore tests: V-S1)."""
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
    did, seq, topic, body, sig, exp, idem, status, sends, last_sid = row
    return QueuedCommand(did, topic, Command(r64(seq), body, exp, bool(idem), sig), sends, last_sid, status)


_COLS = "device_id, cmd_seq, topic, body, sig, expires_at, idempotent, status, sends, last_sid"


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
            c.execute(f"INSERT INTO commands ({_COLS}) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 0, x'')",
                      (device_id, u64(q.cmd.cmd_seq), q.topic, q.cmd.command, q.cmd.sig, q.cmd.expires_at,
                       int(q.cmd.idempotent)))
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

    def close(self, q: QueuedCommand, status: bytes) -> None:
        self.db.execute("UPDATE commands SET status = ? WHERE device_id = ? AND cmd_seq = ?",
                          (status, q.device_id, u64(q.cmd.cmd_seq)))
        q.status = status

    def snapshot(self):
        raise NotImplementedError("use UtilityDB.backup_to()")


# ============================================================================================ registry, zones
class SqlRegistry(Registry):
    def __init__(self, db: UtilityDB):
        super().__init__()
        self.db = db
        for did, dclass, pk, active, mp in db.execute("SELECT * FROM registry"):
            self._d[did] = DeviceRecord(did, dclass, pk, bool(active), mp)

    def _store(self, rec: DeviceRecord) -> None:
        self.db.execute("INSERT OR REPLACE INTO registry VALUES (?, ?, ?, ?, ?)",
                          (rec.device_id, rec.dclass, rec.e2e_pk, int(rec.active), rec.max_packet))


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


# ================================================================================================= assembly
@dataclass
class UtilityNode:
    db: UtilityDB
    endpoint: UtilityEndpoint
    tickets: TicketIssuer
    commands: CommandService
    zones: ZoneManager


def open_utility(path: str, policy, static, cmd_key, clock) -> UtilityNode:
    """A utility process whose durable state is the database at `path`. Opening it again is a restart. `policy` is
    the bootstrap configuration: a newer policy the utility activated earlier (rollout state, U-4) is resumed from
    the database, re-verified against the anchors it was accepted with. Without it a restart after a rollout put
    the utility back on its bootstrap policy and every device that had switched was refused."""
    db = UtilityDB(path)
    stored = db.load_policy("active")
    if stored is not None:
        from ..fota.policy_artifact import verify_policy_artifact
        active = verify_policy_artifact(*stored)
        if active.version > policy.version:
            policy = active
    tickets = TicketIssuer(SqlStekTable(db), SqlUsedTickets(db))
    endpoint = UtilityEndpoint(policy, static, SqlRegistry(db), clock=clock, tickets=tickets)
    commands = CommandService(endpoint, cmd_key, store=SqlCommandStore(db))
    return UtilityNode(db, endpoint, tickets, commands, SqlZoneManager(commands, db))
