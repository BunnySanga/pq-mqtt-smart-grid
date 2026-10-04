"""Error boundaries for MQTT callbacks (remediation H3, M8).

paho runs every callback on its network thread and, by default, re-raises a callback's exception there, which
ends the thread: the node would stay connected at TCP level but process nothing ("silently deaf"). Every callback
therefore runs inside a boundary that separates:
  * expected protocol refusals (PqgridError, ValueError): the message is refused and recorded as a protocol event;
  * unexpected internal errors (anything else, e.g. a database failure): recorded as an internal alarm with only
    the exception type and the code locations. The message text and local values are never recorded, because
    they could contain key material or plaintext.
Neither kind escapes to paho. As a second line, paho's own suppress_exceptions is also set.
"""
from __future__ import annotations

import os
import traceback

from ..errors import PqgridError

EXPECTED = (PqgridError, ValueError)


def internal_alarm(where: str, exc: BaseException) -> tuple[str, str, list[str]]:
    frames = traceback.extract_tb(exc.__traceback__)[-4:]
    return where, type(exc).__name__, [f"{os.path.basename(f.filename)}:{f.lineno}:{f.name}" for f in frames]


def guarded(node, where: str, fn, protocol_log: list, alarms: list):
    """A paho callback that runs fn inside the boundary."""
    def callback(*args):
        try:
            fn(*args)
        except EXPECTED as e:
            protocol_log.append(f"{where}: {e}")
        except Exception as e:                                   # noqa: BLE001 - the boundary is the point
            alarms.append(internal_alarm(where, e))
    return callback


class BoundedLog(list):
    """A local log, or the inbox a node hands its application (alerts, telemetry, statuses, alarms), that keeps the
    newest `cap` entries: a flood of refusals or of valid traffic cannot grow a node's memory (Codex audit C). What
    falls off is counted in `dropped`, never silent; the application takes its entries with drain(). append(),
    extend() and += are all bounded (before the audit only append() was, and the utility added a DF's alerts
    with +=)."""

    def __init__(self, cap: int = 1000):
        super().__init__()
        self.cap, self.dropped = cap, 0

    def append(self, item) -> None:
        super().append(item)
        self._trim()

    def extend(self, items) -> None:
        super().extend(items)
        self._trim()

    def __iadd__(self, items):
        self.extend(items)
        return self

    def _trim(self) -> None:
        over = len(self) - self.cap
        if over > 0:
            del self[:over]
            self.dropped += over

    def drain(self) -> list:
        """Every entry, oldest first, removed from the log: the consumer's API."""
        out = list(self)
        self.clear()
        return out
