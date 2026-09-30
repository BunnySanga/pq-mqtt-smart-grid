"""DR-event delivery across a power loss (Master §11, DR-048; audit L-3, design ambiguity 5).

The device records the event's bseq in flash (DR-048) and THEN hands the event to the application. The semantics are
therefore AT MOST ONCE, like commands (§13.7), but without a status: a broadcast has no ACK. A power loss before the
bseq record is durable leaves the event unaccepted, so the utility's re-send after re-establishment (M4) is accepted;
a power loss after it (before the application acted) loses that event, and the re-send is refused as a replay. Both
sides of that boundary are exercised here with the flash power-loss model at every byte of the record."""
import pytest

from conftest import World
from pqgrid.commands import CommandProcessor, CommandService, ZoneManager
from pqgrid.e2e.envelopes import control_topic
from pqgrid.e2e.handshake import DeviceEndpoint
from pqgrid.errors import ReplayError
from pqgrid.persistence.device import DeviceFlash
from pqgrid.persistence.flash import FlashSim, PowerLoss, record_size
from pqgrid.registry import DeviceRecord
from pqgrid.suite.hkem import HybridKeyPair

D1, CLS, ZONE = b"der-0001", "der_ctrl", "f7"


class Device:
    """A DER whose command state (bseq records) lives in simulated flash; boot() is a power-on."""

    def __init__(self, world: World):
        self.w, self.kp, self.fs = world, HybridKeyPair.generate(), FlashSim()
        world.registry.add(DeviceRecord(D1, CLS, self.kp.pk))
        self.boot()

    def boot(self):
        df = DeviceFlash(self.fs, clock=lambda: self.w.t)
        self.d = DeviceEndpoint(D1, CLS, self.w.policy, 1, self.kp, clock=lambda: self.w.t, flash=df)
        self.proc = CommandProcessor(self.d, lambda c: None, targets=set(), state=df.command_state())
        self.w.t += 1
        self.w.full(self.d)

    def keys(self, zm: ZoneManager) -> None:
        for env in zm.zonekeys_for(D1):
            self.proc.on_control(control_topic(CLS, D1), env)


@pytest.fixture
def rig(world: World):
    dev = Device(world)
    zm = ZoneManager(CommandService(world.utility, world.cmd_sk))
    zm.create(ZONE)
    zm.add_member(ZONE, D1)
    dev.keys(zm)
    (topic, env), = zm.publish(ZONE, b"SHED 20%", 3600).items()
    return world, dev, zm, topic, env


BSEQ_RECORD = record_size(len(ZONE), 8)                                  # the bytes one accepted event writes


@pytest.mark.parametrize("cut_after", range(BSEQ_RECORD))
def test_a_power_loss_before_the_bseq_record_is_durable_leaves_the_event_to_be_accepted_again(rig, cut_after):
    world, dev, zm, topic, env = rig
    dev.fs.fail_after = cut_after                                        # power fails while the record is written
    with pytest.raises(PowerLoss):
        dev.proc.zones.open(topic, env)
    dev.fs.fail_after = None
    dev.boot()                                                           # the torn record is ignored at boot
    dev.keys(zm)
    assert [dev.proc.zones.open_resent(e) for e in zm.resend_for(D1)] == [(ZONE, b"SHED 20%")]


def test_a_power_loss_after_the_bseq_record_is_durable_loses_the_event_at_most_once(rig):
    world, dev, zm, topic, env = rig
    assert dev.proc.zones.open(topic, env) == (b"SHED 20%")             # durable; the application never saw it
    dev.boot()
    dev.keys(zm)
    with pytest.raises(ReplayError):                                     # never delivered twice: at most once
        [dev.proc.zones.open_resent(e) for e in zm.resend_for(D1)]
