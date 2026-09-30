"""The device main loop's pacing (Master §10.5, §12): a failed establishment is retried only after a full-jitter
exponential back-off, which resets after a success. No broker: the connection is marked up and establish()
is replaced, so only the pacing rule is under test."""
import contextlib
import ssl

from conftest import World
from pqgrid.commands import CommandProcessor
from pqgrid.mqtt import device_node
from pqgrid.mqtt.device_node import DeviceMqtt, TransportError

M1 = b"meter-0001"


class RecordingRng:
    """Returns the top of each jitter window and records it."""

    def __init__(self):
        self.bounds = []

    def uniform(self, a, b):
        self.bounds.append(b)
        return b


def test_failed_establishment_backs_off_with_full_jitter_and_resets_on_success(world: World, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(device_node.time, "monotonic", lambda: now[0])
    d = world.device(M1, "smart_meter")                              # back-off base 2 s, cap 300 s
    rng = RecordingRng()
    mq = DeviceMqtt(d, CommandProcessor(d, lambda c: None), None, ssl.create_default_context(), "localhost", 1,
                    rng=rng)
    mq.connected.set()
    attempts, succeed = [], [False]

    def establish():
        attempts.append(now[0])
        if not succeed[0]:
            raise TransportError("no answer to the client hello")
    mq.establish = establish
    for _ in range(14):                                              # one tick per second, all failing
        with contextlib.suppress(TransportError):
            mq._connection_step()
        now[0] += 1
    assert attempts == [1000, 1002, 1006] and rng.bounds == [2, 4, 8]   # waits 2, 4, 8 s: not every tick
    now[0] = 1014
    succeed[0] = True
    mq._connection_step()
    assert attempts[-1] == 1014 and mq._est_failures == 0             # a success resets the back-off
