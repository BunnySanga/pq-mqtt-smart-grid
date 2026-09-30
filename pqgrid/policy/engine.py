"""Topic → tier (Master §11): the strongest matching rule wins; no match → CONTROL (I-5)."""
from __future__ import annotations

from .model import Tier

_MAX_TOPIC_BYTES = 65535      # MQTT limit on a UTF-8 topic string


def valid_filter(pattern: str) -> bool:
    """An MQTT topic filter: '+' only as a whole level; '#' only as the whole last level."""
    if not pattern or "\x00" in pattern or len(pattern.encode()) > _MAX_TOPIC_BYTES:
        return False
    levels = pattern.split("/")
    for i, level in enumerate(levels):
        if "#" in level and (level != "#" or i != len(levels) - 1):
            return False
        if "+" in level and level != "+":
            return False
    return True


def valid_topic(topic: str) -> bool:
    """A concrete topic name: non-empty, no wildcards, no NUL."""
    return (bool(topic) and "+" not in topic and "#" not in topic and "\x00" not in topic
            and len(topic.encode()) <= _MAX_TOPIC_BYTES)


def topic_matches(pattern: str, topic: str) -> bool:
    p, t = pattern.split("/"), topic.split("/")
    for i, seg in enumerate(p):
        if seg == "#":
            return i == len(p) - 1
        if i >= len(t):
            return False
        if seg != "+" and seg != t[i]:
            return False
    return len(p) == len(t)


def tier_for(policy, topic: str) -> Tier:
    """Strongest tier among matching rules. A topic nobody thought of gets maximum protection."""
    if not valid_topic(topic):
        return Tier.CONTROL
    hits = [r.tier for r in policy.rules if topic_matches(r.pattern, topic)]
    return max(hits) if hits else Tier.CONTROL
