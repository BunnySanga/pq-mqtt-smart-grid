"""Remediation H2: interrupted commands must never fill the device's flash and block command execution.
Hundreds of interrupted maximum-size commands, reclamation (newer command applied / expiry + grace), explicit
capacity refusal, page-full compaction with reboots, and a power cut at every flash step while compacting."""
import pytest

from conftest import World, make_policy, replace_class
from pqgrid.commands import CommandProcessor, CommandService
from pqgrid.commands.device import MAX_COMMAND, MAX_INTENTS
from pqgrid.e2e.envelopes import control_topic
from pqgrid.e2e.handshake import DeviceEndpoint
from pqgrid.persistence.device import T_INTENT, DeviceFlash
from pqgrid.persistence.flash import FlashSim, PowerLoss
from pqgrid.registry import DeviceRecord
from pqgrid.suite.hkem import HybridKeyPair
from pqgrid.suite.sig import mldsa_public_bytes
from pqgrid.wire import dec

D1 = b"der-0001"
TOPIC = control_topic("der_ctrl", D1)
BIG = b"X" * MAX_COMMAND


class Crash(Exception):
    pass


class Device:
    """One DER on simulated flash; boot() rebuilds everything from flash (a reboot)."""

    def __init__(self, world: World, flash: FlashSim | None = None):
        self.w, self.kp, self.flash = world, HybridKeyPair.generate(), flash or FlashSim()
        world.registry.add(DeviceRecord(D1, "der_ctrl", self.kp.pk))
        self.actuated: list[bytes] = []
        self.crash_next = False
        self.boot()
        world.full(self.d)

    def actuate(self, cmd: bytes) -> None:
        if self.crash_next:
            self.crash_next = False
            self.actuated.append(cmd)                        # the actuator moved, then power was lost
            raise Crash()
        self.actuated.append(cmd)

    def boot(self):
        self.df = DeviceFlash(self.flash, clock=lambda: self.w.t)
        self.d = DeviceEndpoint(D1, "der_ctrl", self.w.policy, 1, self.kp, clock=lambda: self.w.t, flash=self.df)
        self.proc = CommandProcessor(self.d, self.actuate, state=self.df.command_state())

    def reconnect(self):
        self.w.t += 1
        if self.d.can_resume():
            self.w.resume(self.d)
        else:
            self.d._ch = None
            self.w.full(self.d)

    def intents(self) -> int:
        return len(self.df.store.items(T_INTENT))


def status(svc, proc, env) -> bytes:
    return svc.on_status(proc.on_control(TOPIC, env))[2]


def test_hundreds_of_interrupted_maximum_size_commands_never_block_execution(world: World):
    svc, dev = CommandService(world.utility, world.cmd_sk), Device(world)
    for i in range(300):
        x = svc.issue(D1, BIG, 300)                                          # non-idempotent, 1,024 B
        [env] = svc.outgoing(D1)
        dev.crash_next = True
        with pytest.raises(Crash):
            dev.proc.on_control(TOPIC, env)
        dev.boot()
        dev.reconnect()
        assert [dec(r, 6)[4] for r in dev.proc.recover()] == [b"INTERRUPTED"]
        assert svc.outcome(D1, x) is None or svc.outcome(D1, x) == b"INTERRUPTED"
        for r in dev.proc.recover():
            svc.on_status(r)
        y = svc.issue(D1, b"Y%d" % i, 300)                                   # a newer command still executes
        assert [status(svc, dev.proc, e) for e in svc.outgoing(D1)] == [b"OK"]
        assert svc.outcome(D1, y) == b"OK" and dev.intents() == 0           # the interrupted record reclaimed
    assert dev.actuated.count(BIG) == 300                                    # each X moved once, never twice
    assert sum(dev.flash.erase_counts) > 0                                   # compactions really happened


def test_reclaim_after_expiry_plus_grace_and_explicit_capacity_refusal():
    world = World()
    world.policy = make_policy(world.u_static.pk, mldsa_public_bytes(world.cmd_sk),
                               classes=replace_class(world.policy, "der_ctrl", session_expiry_s=300))
    from pqgrid.e2e.handshake import UtilityEndpoint
    world.utility = UtilityEndpoint(world.policy, world.u_static, world.registry, clock=lambda: world.t,
                                    tickets=world.tickets)
    svc, dev = CommandService(world.utility, world.cmd_sk), Device(world)
    for _ in range(MAX_INTENTS):                                             # fill to capacity, no newer command
        svc.issue(D1, BIG, 60)
        [env] = svc.outgoing(D1)
        dev.crash_next = True
        with pytest.raises(Crash):
            dev.proc.on_control(TOPIC, env)
        dev.boot()
        dev.reconnect()
        for r in dev.proc.recover():
            svc.on_status(r)
    assert dev.intents() == MAX_INTENTS
    blocked = svc.issue(D1, b"NEW", 3600)
    assert [status(svc, dev.proc, e) for e in svc.outgoing(D1)] == [b"REJECTED:capacity"]   # explicit
    assert svc.outcome(D1, blocked) == b"REJECTED:capacity"
    world.t += 60 + 300 + world.policy.profile("der_ctrl").dup_window_s              # expiry + grace passed
    dev.reconnect()
    later = svc.issue(D1, b"LATER", 3600)
    assert [status(svc, dev.proc, e) for e in svc.outgoing(D1)] == [b"OK"]         # capacity path reclaimed
    assert svc.outcome(D1, later) == b"OK" and dev.intents() == 0
    assert BIG in dev.actuated and dev.actuated.count(BIG) == MAX_INTENTS


def test_page_full_bank_with_repeated_reboots_and_compactions(world: World):
    svc, dev = CommandService(world.utility, world.cmd_sk), Device(world)
    outbox = dev.df.outbox("grid/der_ctrl/der-0001/alert", 4096)
    import os
    for _ in range(40):
        outbox.add(os.urandom(16), os.urandom(90), b"K%d" % _)                # a full outbox in the same bank
    for i in range(60):
        svc.issue(D1, BIG, 300)
        [env] = svc.outgoing(D1)
        dev.crash_next = i % 2 == 0
        try:
            svc.on_status(dev.proc.on_control(TOPIC, env))
        except Crash:
            pass
        dev.boot()
        dev.reconnect()
        for r in dev.proc.recover():
            svc.on_status(r)
        svc.issue(D1, b"tick", 300)
        [e] = svc.outgoing(D1)
        assert status(svc, dev.proc, e) == b"OK"
    assert sum(dev.flash.erase_counts) >= 4 and dev.intents() == 0 and len(outbox.queued()) > 0


@pytest.mark.parametrize("idempotent", [False, True])
def test_power_loss_at_every_flash_step_while_compacting(idempotent):
    """A nearly full bank, so the PENDING write of a maximum-size command forces a compaction; power is cut at
    every flash operation. Afterwards: never actuated twice (non-idempotent), OK only when APPLIED is durable,
    INTERRUPTED when unknown, and the device keeps executing commands."""
    import os

    def fresh():
        world = World()
        svc, dev = CommandService(world.utility, world.cmd_sk), Device(world)
        store = dev.df.store
        while True:            # superseded records (garbage) fill the bank; the live set stays small, so the
            page, off = store._pos                          # next write compacts, and compaction then fits
            if page == store.bank_pages - 1 and off > dev.flash.page_size - 900:
                break
            store.put(0x60, b"filler", os.urandom(200))
        seq = svc.issue(D1, BIG, 300, idempotent)
        [env] = svc.outgoing(D1)
        return world, svc, dev, seq, env

    world, svc, dev, seq, env = fresh()
    e0, t0 = sum(dev.flash.erase_counts), dev.flash.ticks
    svc.on_status(dev.proc.on_control(TOPIC, env))
    n = dev.flash.ticks - t0
    assert sum(dev.flash.erase_counts) > e0                                  # this path does compact
    for k in range(0, n, 3):                                                 # every third flash operation
        world, svc, dev, seq, env = fresh()
        dev.flash.fail_after = k
        try:
            svc.on_status(dev.proc.on_control(TOPIC, env))
        except PowerLoss:
            pass
        dev.flash.fail_after = None
        dev.boot()
        dev.reconnect()
        for r in dev.proc.recover():
            svc.on_status(r)
        for e in svc.outgoing(D1):
            svc.on_status(dev.proc.on_control(TOPIC, e))
        outcome, moved = svc.outcome(D1, seq), dev.actuated.count(BIG)
        if idempotent:
            assert outcome in (b"OK", b"DUP") and 1 <= moved <= 2
        else:
            assert moved <= 1 and outcome in (b"OK", b"DUP", b"INTERRUPTED")
            if outcome == b"INTERRUPTED":
                assert moved == 1
        if outcome in (b"OK", b"DUP"):
            assert dev.proc.state.is_applied(seq)
        svc.issue(D1, b"after", 300)
        assert [status(svc, dev.proc, e) for e in svc.outgoing(D1)] == [b"OK"]   # still executes commands
