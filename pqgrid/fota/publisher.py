"""Utility-side artifact publication (Master §15.2, §15.8, §15.9, §10.2–§10.3; E62).

Every message (manifest part or chunk) is checked against the target class's max_packet before anything is
published: the broker would drop a larger one silently [DOCKER T1]. Artifacts are retained, so a device that
subscribes later still gets them; after the retention window they are removed (an empty retained publish).
Republish (E-4, final remediation), at most once an hour per device, never resurrecting what is no longer valid:
  * on the device's request (its own ACL-scoped topic), sent when a verified download stalls (chunks missing);
  * proactively by the utility: its newest POLICY when a device's CH is refused for an old POLICY_INFO, and its
    newest FIRMWARE when an established device reports an older fw_version and that artifact is not retained.
Only the newest artifact per (class, type), only if still valid now: its signer is not revoked and holds the
right role (DR-050 roles, current revocations), and a POLICY is not older than the active one.
The rollout state (newest artifacts, what is retained since when, published revocations) is kept in memory here;
persistence.utility_db.SqlPublisher makes it durable (Master §4.4, U-4), written before the broker is told.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from ..mqtt import topics
from ..wire import dec, enc, r8, u8, u16, u64
from .artifact import KEYREVOKE, MAX_CHUNKS, POLICY, TYPE_NAMES, FotaError, check_signer
from .station import Artifact

RETENTION_S = 30 * 86400
REPUBLISH_EVERY_S = 3600


def part_payload_budget(max_packet: int, device_class: str, type_: int, version: int) -> int:
    """How many signed-manifest bytes one part may carry so the whole PUBLISH fits max_packet."""
    empty = enc([b"MP", u8(type_), u64(version), u16(0), u16(0), b""])
    overhead = topics.publish_size(topics.fota_part(device_class, TYPE_NAMES[type_], version, 99), empty)
    return max_packet - overhead


@dataclass
class Published:
    artifact: Artifact
    topics: list
    at: float


class Publisher:
    def __init__(self, policy, clock=time.time):
        self.policy, self.clock = policy, clock
        self.live: dict[tuple[str, int], Published] = {}           # (class, type) → what is retained right now
        self.newest: dict[tuple[str, int], Artifact] = {}          # kept after cleanup, for republish requests
        self._last_request: dict[bytes, float] = {}
        self.revoked: set[int] = set()                             # anchors revoked by published KEYREVOKEs

    def messages(self, art: Artifact) -> list[tuple[str, bytes]]:
        m = art.manifest
        name, limit = TYPE_NAMES[m.type], self.policy.profile(m.device_class).max_packet
        if len(art.chunks) > MAX_CHUNKS:
            raise FotaError(f"more than {MAX_CHUNKS} chunks: no device accepts it")
        out = [(topics.fota_part(m.device_class, name, m.version, i), p) for i, p in enumerate(art.parts)]
        out += [(topics.fota_chunk(m.device_class, name, m.version, i), c) for i, c in enumerate(art.chunks)]
        for topic, payload in out:
            if topics.publish_size(topic, payload) > limit:
                raise FotaError(f"{topic} would be {topics.publish_size(topic, payload)} B > {limit} B max_packet")
        return out

    def publish(self, client, art: Artifact) -> None:
        msgs = self.messages(art)                                  # all checked before the first publish
        key = (art.manifest.device_class, art.manifest.type)
        old, pub = self.live.get(key), Published(art, [t for t, _ in msgs], self.clock())
        rid = r8(dec(art.payload, 1)[0]) if art.manifest.type == KEYREVOKE else None
        self._store(key, art, pub)                                 # the rollout state first (U-4), so a restart
        if rid is not None:                                        # never forgets what it retained or revoked
            self._store_revoked(rid)
        for topic, payload in msgs:
            client.publish(topic, payload, qos=1, retain=True)
        self.live[key], self.newest[key] = pub, art
        if rid is not None:
            self.revoked.add(rid)
        if old and old.artifact.manifest.version != art.manifest.version:
            self._remove(client, old)                              # only the newest needs to stay retained

    def cleanup(self, client) -> int:
        now, removed = self.clock(), 0
        for key, pub in list(self.live.items()):
            if now - pub.at >= RETENTION_S:
                self._remove(client, pub)
                del self.live[key]
                self._store(key, pub.artifact, None)               # still the newest; no longer retained
                removed += 1
        return removed

    # persistence hooks (persistence.utility_db.SqlPublisher); in memory they do nothing
    def _store(self, key: tuple[str, int], art: Artifact, retained) -> None:
        pass

    def _store_revoked(self, anchor: int) -> None:
        pass

    def valid(self, art: Artifact) -> bool:
        """Still valid NOW: signer not revoked and in its role (DR-050), and a POLICY not older than the active."""
        m = art.manifest
        try:
            check_signer(m.type, m.signer_anchor_id, self.revoked)
        except FotaError:
            return False
        return not (m.type == POLICY and m.version < self.policy.version)

    def retained(self, art: Artifact) -> bool:
        pub = self.live.get((art.manifest.device_class, art.manifest.type))
        return pub is not None and pub.artifact.manifest.version == art.manifest.version

    def on_request(self, client, device_class: str, device_id: bytes, types=None, newer_than=None,
                   only_missing: bool = False) -> list[int]:
        """Republish the newest still-valid artifact of each type (or of `types`) for the class; `newer_than`
        {type: version} keeps only newer ones, `only_missing` skips those still retained. Rate-limited per device
        (E62); the hour is consumed only when something is republished. Returns the types republished."""
        now = self.clock()
        if now - self._last_request.get(device_id, float("-inf")) < REPUBLISH_EVERY_S:
            return []                                              # rate limit (E62)
        arts = [a for (cls, t), a in sorted(self.newest.items()) if cls == device_class
                and (types is None or t in types) and self.valid(a)
                and (newer_than is None or a.manifest.version > newer_than.get(t, -1))
                and not (only_missing and self.retained(a))]
        if not arts:
            return []
        self._last_request[device_id] = now
        for art in arts:
            self.publish(client, art)
        return [a.manifest.type for a in arts]

    def _remove(self, client, pub: Published) -> None:
        for t in pub.topics:
            client.publish(t, b"", qos=1, retain=True)             # an empty retained message deletes it
