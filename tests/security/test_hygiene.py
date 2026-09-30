"""Remediation "SECURITY HYGIENE": secrets never appear in a repr (hence not in logs or tracebacks that print
objects), caches and local logs are bounded, and a NULL from OpenSSL fails closed instead of being passed on."""
import os

import pytest

from pqgrid.commands.codec import ZoneKey
from pqgrid.commands.zones import GroupKey
from pqgrid.e2e.handshake import StoredTicket, _DupCache, _Pending
from pqgrid.e2e.keys import MasterKeys
from pqgrid.e2e.session import Session
from pqgrid.errors import CryptoError
from pqgrid.mqtt.guard import BoundedLog
from pqgrid.pasr.stek import StekKey
from pqgrid.pasr.tickets import Ticket
from pqgrid.policy import ResumeMode
from pqgrid.suite import sig as sigmod
from pqgrid.suite.aead import AeadAlg

SECRET = bytes.fromhex("5ec2e7") * 11                     # 33 B, easy to spot in any repr


def test_no_secret_in_any_repr():
    s = Session(b"d", "c", b"p", 1, AeadAlg.AES256GCM, SECRET, b"sid", ResumeMode.PSK, 0)
    objs = [s, MasterKeys(SECRET, SECRET, SECRET, b"sid"), _Pending(s, SECRET, b"th", b"mu", 0),
            StoredTicket(b"t", b"blob", SECRET, 0, ResumeMode.PSK, b"p", 1),
            Ticket(b"t", b"d", "c", b"p", 1, ResumeMode.PSK, 0, 0, 0, SECRET),
            StekKey(1, SECRET, 0, 0), ZoneKey("z", 1, AeadAlg.AES256GCM, SECRET), GroupKey(1, SECRET, 0)]
    for o in objs:
        r = repr(o)
        assert repr(SECRET) not in r and SECRET.hex() not in r and "5ec2e7" not in r, type(o).__name__


def test_duplicate_reply_cache_is_bounded_by_count():
    c = _DupCache()
    for i in range(_DupCache.MAX_ENTRIES + 1000):             # a flood of distinct requests in one window
        c.put(i.to_bytes(4, "big"), b"reply", 0, 120)
    assert len(c._d) == _DupCache.MAX_ENTRIES
    assert c.get((0).to_bytes(4, "big"), 0) is None           # the oldest went first
    assert c.get((_DupCache.MAX_ENTRIES + 999).to_bytes(4, "big"), 0) == b"reply"


def test_a_duplicate_hello_beyond_the_cache_bound_costs_one_more_attempt_and_nothing_else(world, monkeypatch):
    """Audit L-8 (§14.1, Master §22.2): past the bound, a QoS 1 duplicate CH whose entry was evicted gets a FRESH SH
    (I-18 no longer holds for it). The device keeps the first SH; the utility's one half-open state now belongs to
    the second, so the DF is refused, no session exists on either side, and the device's next attempt establishes.
    The bound is lowered to 1 here instead of flooding 4,096 real hellos."""
    from pqgrid.errors import HandshakeError
    monkeypatch.setattr(_DupCache, "MAX_ENTRIES", 1)
    d, other = world.device(b"meter-0001", "smart_meter"), world.device(b"meter-0002", "smart_meter")
    ch = d.client_hello()
    sh1 = world.utility.on_client_hello(d.id, ch)
    world.utility.on_client_hello(other.id, other.client_hello())   # evicts meter-0001's entry
    sh2 = world.utility.on_client_hello(d.id, ch)                   # the broker's duplicate of the same CH
    assert sh2 != sh1
    d.on_server_hello(sh1)
    with pytest.raises(HandshakeError):
        world.utility.on_finished(d.id, d.finished())
    assert world.utility.session_for(d.id) is None
    world.full(d)                                                   # the next attempt
    assert d.confirmed and world.utility.session_for(d.id).sid == d.session.sid


def test_node_logs_keep_only_the_newest_entries():
    log = BoundedLog(cap=100)
    for i in range(250):
        log.append(i)
    assert log == list(range(150, 250))


def test_slh_verify_fails_closed_when_openssl_cannot_allocate_a_context(monkeypatch):
    lib = sigmod._lib()
    monkeypatch.setattr(lib, "EVP_MD_CTX_new", lambda: None)
    with pytest.raises(CryptoError, match="could not allocate a digest context"):
        sigmod.slh_verify(os.urandom(sigmod.SLH_PK_LEN), os.urandom(sigmod.SLH_SIG_LEN), b"manifest")
