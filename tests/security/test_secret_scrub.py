"""Remediation M3: DR-049 as clarified. A superseded resumption PSK may stay physically in flash for a while, but
software erases it within 7 days of device time, on the production paths: boot, every authenticated time update
(SH/RS), the device main loop's tick (housekeeping), and every ticket write. Resumes do not erase a bank each time. Power loss
during the scrub compaction never loses the live ticket and never brings the old PSK back. Nothing here says
anything about flash while the device is powered off."""
import ssl

import pytest

from conftest import World
from pqgrid.commands import CommandProcessor
from pqgrid.e2e.handshake import DeviceEndpoint, StoredTicket
from pqgrid.mqtt.device_node import DeviceMqtt
from pqgrid.persistence.device import DeviceFlash
from pqgrid.persistence.flash import FlashSim, PowerLoss
from pqgrid.registry import DeviceRecord
from pqgrid.suite.hkem import HybridKeyPair

M1 = b"meter-0001"
DAY, WEEK = 86400, 7 * 86400


class Meter:
    """A smart meter (PSK resumption) on simulated flash; `rtc` is its own clock, which may stop or drift."""

    def __init__(self, world: World, flash: FlashSim | None = None, kp=None):
        self.w, self.flash, self.rtc = world, flash or FlashSim(), [world.t]
        self.kp = kp or HybridKeyPair.generate()
        if world.registry.get(M1) is None:
            world.registry.add(DeviceRecord(M1, "smart_meter", self.kp.pk))
        self.boot()

    def boot(self):
        self.df = DeviceFlash(self.flash, clock=lambda: self.rtc[0])
        self.d = DeviceEndpoint(M1, "smart_meter", self.w.policy, 1, self.kp, clock=lambda: self.rtc[0],
                                flash=self.df)
        self.mq = DeviceMqtt(self.d, CommandProcessor(self.d, lambda c: None), None,
                             ssl.create_default_context(), "localhost", 1)       # never connected: housekeeping() only

    def advance(self, seconds: float, rtc_runs: bool = True):
        self.w.t += seconds
        if rtc_runs:
            self.rtc[0] += seconds

    def has(self, secret: bytes) -> bool:
        return secret in bytes(self.flash.mem)


def superseded(world: World) -> tuple[Meter, bytes, bytes]:
    """A meter whose first ticket (psk_a) was superseded by a resume; returns (meter, psk_a, psk_b)."""
    m = Meter(world)
    world.full(m.d)
    psk_a = m.d.ticket.psk
    m.advance(60)
    world.resume(m.d)                                                # RS deletes A, NT stores B: A is residue
    return m, psk_a, m.d.ticket.psk


def test_M3_no_flash_write_for_seven_days_the_periodic_tick_scrubs(world: World):
    m, psk_a, psk_b = superseded(world)
    erases = sum(m.flash.erase_counts)
    assert m.has(psk_a)                                              # residue is allowed for a while …
    m.advance(WEEK - 1)
    m.mq.housekeeping()
    assert m.has(psk_a) and sum(m.flash.erase_counts) == erases
    m.advance(1)                                                     # … but not past 7 days of device time
    m.mq.housekeeping()
    assert not m.has(psk_a) and m.has(psk_b)
    m.boot()
    assert m.d.ticket.psk == psk_b                                   # the live ticket survived the scrub


def test_M3_authenticated_time_advance_scrubs_even_if_the_rtc_stopped(world: World):
    m, psk_a, psk_b = superseded(world)
    m.advance(8 * DAY, rtc_runs=False)                               # deep sleep with the RTC stopped
    m.mq.housekeeping()
    assert m.has(psk_a)                                              # the device cannot know time passed …
    m.d.ticket = None                                                # (ticket and STEK long expired)
    world.full(m.d)                                                  # … until authenticated time arrives (SH)
    assert not m.has(psk_a) and m.has(m.d.ticket.psk)               # B is now the newest residue: ≤ 7 days


def test_M3_boot_after_long_inactivity_scrubs_before_anything_else(world: World):
    m, psk_a, psk_b = superseded(world)
    m.advance(30 * DAY)                                              # powered off: nothing ran
    assert m.has(psk_a)
    m.boot()
    assert not m.has(psk_a) and m.d.ticket.psk == psk_b
    erases = sum(m.flash.erase_counts)
    m.boot()                                                         # nothing superseded now: no erase at boot
    assert sum(m.flash.erase_counts) == erases


def test_M3_resumes_do_not_erase_a_bank_each_time_and_one_scrub_covers_them_all(world: World):
    m = Meter(world)
    world.full(m.d)
    old = [m.d.ticket.psk]
    erases = sum(m.flash.erase_counts)
    for _ in range(5):
        m.advance(3600)
        world.resume(m.d)
        old.append(m.d.ticket.psk)
    live = old.pop()
    assert sum(m.flash.erase_counts) == erases and all(m.has(p) for p in old)
    m.advance(WEEK - 4 * 3600 - 1)                                   # the first supersession was at +1 h
    m.mq.housekeeping()
    assert all(m.has(p) for p in old)
    m.advance(1)                                                     # 7 days after the FIRST supersession
    m.mq.housekeeping()
    assert not any(m.has(p) for p in old) and m.has(live)


@pytest.mark.parametrize("crash_boot_too", [False, True])
def test_M3_power_loss_during_the_scrub_compaction(world: World, crash_boot_too: bool):
    probe, _, _ = superseded(world)
    probe.advance(WEEK)
    t0 = probe.flash.ticks
    probe.mq.housekeeping()
    n = probe.flash.ticks - t0
    assert n > 0
    for k in range(0, n, max(1, n // 40)):
        w = World()
        m, psk_a, psk_b = superseded(w)
        m.advance(WEEK)
        m.flash.fail_after = k
        with pytest.raises(PowerLoss):
            m.mq.housekeeping()
        if crash_boot_too:                                           # the boot scrub is cut as well
            m.flash.fail_after = k // 2
            try:
                m.boot()
            except PowerLoss:
                pass
        m.flash.fail_after = None
        m.boot()
        assert not m.has(psk_a), k                                   # never back, whatever step failed
        assert m.df.load_ticket(StoredTicket).psk == psk_b, k        # the live ticket is never lost
        assert m.d.ticket.psk == psk_b and m.d.can_resume(), k
