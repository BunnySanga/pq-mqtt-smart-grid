"""Topic names (Master §10.1) and which envelope travels where (IMPLEMENTATION-ROADMAP §11.2, C10).

No message gets a topic of its own: ACKs and the resync hint ride on the existing topic whose publisher and
direction already match, so the ACL grants nobody anything new."""
from __future__ import annotations

import random


def telemetry(dclass: str, did: bytes) -> str:
    return f"grid/{dclass}/{did.decode()}/telemetry"


def alert(dclass: str, did: bytes) -> str:              # device → utility: ALERT 0x02, status ACK 0x06
    return f"grid/{dclass}/{did.decode()}/alert"


def control(dclass: str, did: bytes) -> str:            # utility → device: CONTROL 0x03, ALERT ACK 0x05
    return f"grid/{dclass}/{did.decode()}/control"


def status(dclass: str, did: bytes) -> str:             # Last Will, informational (§10.4)
    return f"grid/{dclass}/{did.decode()}/status"


def hs_up(did: bytes) -> str:                           # CH, RH, DF
    return f"pqgrid/hs/{did.decode()}/up"


def hs_down(did: bytes) -> str:                         # SH, RS, NT/FIN, resync hint 0x07
    return f"pqgrid/hs/{did.decode()}/down"


def dr_event(zone: str, alg) -> str:                  # one topic per crypto group of a logical zone (M7)
    from ..commands.zones import event_topic
    return event_topic(zone, alg)


UTILITY_SUBSCRIPTIONS = ("pqgrid/hs/+/up", "grid/+/+/alert", "grid/+/+/telemetry", "grid/+/+/status",
                         "pqgrid/fota/+/request/+")


def parse(topic: str) -> tuple[str, str, str]:
    """(kind, class or '', device id or zone) for the topics above; ValueError otherwise."""
    p = topic.split("/")
    if len(p) == 4 and p[0] == "pqgrid" and p[1] == "hs" and p[3] in ("up", "down"):
        return "hs_" + p[3], "", p[2]
    if len(p) == 5 and p[0] == "grid" and p[1] == "dr" and p[4] == "event":
        return "dr_event", p[3], p[2]                    # (kind, crypto group, zone)
    if len(p) == 4 and p[0] == "grid" and p[3] in ("telemetry", "alert", "control", "status"):
        return p[3], p[1], p[2]
    if len(p) == 5 and p[:2] == ["pqgrid", "fota"] and p[3] == "request":
        return "fota_request", p[2], p[4]
    if len(p) == 7 and p[:2] == ["pqgrid", "fota"] and p[5] in ("manifest", "chunk"):
        return "fota_" + ("part" if p[5] == "manifest" else "chunk"), p[2], p[3]
    raise ValueError(f"not a pqgrid topic: {topic}")


def fota_part(dclass: str, type_name: str, version: int, index: int) -> str:
    return f"pqgrid/fota/{dclass}/{type_name}/{version}/manifest/{index}"


def fota_chunk(dclass: str, type_name: str, version: int, index: int) -> str:
    return f"pqgrid/fota/{dclass}/{type_name}/{version}/chunk/{index}"


def fota_request(dclass: str, did: bytes) -> str:                 # republish request (§15.8)
    return f"pqgrid/fota/{dclass}/request/{did.decode()}"


def publish_size(topic: str, payload: bytes, qos: int = 1) -> int:
    """Exact MQTT 5 PUBLISH size with no properties: fixed header + remaining length."""
    remaining = 2 + len(topic.encode()) + (2 if qos else 0) + 1 + len(payload)
    varint = 1 if remaining < 128 else 2 if remaining < 16384 else 3 if remaining < 2097152 else 4
    return 1 + varint + remaining


def backoff_delay(attempt: int, base_s: float, cap_s: float, rng: random.Random = random) -> float:
    """Full-jitter exponential back-off on every reconnect (Master §10.5, E51)."""
    return rng.uniform(0, min(cap_s, base_s * (2 ** min(attempt, 32))))
