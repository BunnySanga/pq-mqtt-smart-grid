"""Codex audit improvement C (2026-10-03, IMPLEMENTATION-ROADMAP §16): what the utility hands its application
(alerts, telemetry, statuses, takeover alarms) was kept in plain lists that grew with every valid message, so
sustained valid traffic could exhaust the utility's memory. They are bounded now, with the overflow counted, and the
application drains them. Also: BoundedLog bounded only append(), while the utility added a DF's alerts with +=."""
from test_utility_loop import Msg, util  # noqa: F401  (fixture)
from pqgrid.mqtt.guard import BoundedLog


def test_a_flood_of_valid_telemetry_keeps_the_newest_entries_and_counts_the_rest(util):
    u = util[0]
    topic, n = "grid/der_ctrl/der-0001/telemetry", u.telemetry.cap + 500
    for i in range(n):
        u._on_message(None, None, Msg(topic, b"%d" % i))                  # valid: registered, active, its class
    assert len(u.telemetry) == u.telemetry.cap and u.telemetry.dropped == 500   # before the fix: 1,500 kept
    assert u.telemetry[-1] == (b"der-0001", b"%d" % (n - 1))              # the newest are kept
    assert len(u.telemetry.drain()) == u.telemetry.cap and len(u.telemetry) == 0
    assert u.internal_errors == [] and u.refused == []


def test_every_application_inbox_is_bounded(util):
    u = util[0]
    for name in ("alerts", "telemetry", "statuses", "takeover_alarms"):
        assert isinstance(getattr(u, name), BoundedLog), name


def test_a_bounded_log_stays_bounded_when_extended():
    log = BoundedLog(cap=10)
    log += list(range(25))                                                # how the utility adds a DF's alerts
    assert log == list(range(15, 25)) and log.dropped == 15               # before the fix: all 25 kept
    log.extend(range(25, 30))
    assert log == list(range(20, 30)) and log.dropped == 20


def test_draining_while_another_thread_appends_loses_nothing():
    """Second Codex review, finding 7: drain() copied, then cleared, without a lock, so an entry appended in between
    (paho's thread, while the application drains) was lost without a trace. Every entry is now either drained or
    still in the log. (A race test: before the fix it CAN lose entries; whether a given run does is not
    deterministic, so it proves the fix, not the bug.)"""
    import threading
    log, taken, n = BoundedLog(cap=10 ** 9), [], 200_000

    def producer():
        for i in range(n):
            log.append(i)
    t = threading.Thread(target=producer)
    t.start()
    while t.is_alive():
        taken += log.drain()
    t.join()
    taken += log.drain()
    assert sorted(taken) == list(range(n)) and log.dropped == 0


def test_the_device_keeps_a_bounded_list_of_accepted_events():
    """Second Codex review, finding 6: the device's accepted DR events grew without bound."""
    import ssl
    import conftest
    from pqgrid.commands import CommandProcessor
    from pqgrid.mqtt.device_node import DeviceMqtt
    w = conftest.World()
    d = w.device(b"der-0001", "der_ctrl")
    mq = DeviceMqtt(d, CommandProcessor(d, lambda c: None), None, ssl.create_default_context(), "localhost", 1)
    assert isinstance(mq.events, BoundedLog)
    mq.events += [("f7", b"E%d" % i) for i in range(mq.events.cap + 5)]
    assert len(mq.events) == mq.events.cap and mq.events.dropped == 5
