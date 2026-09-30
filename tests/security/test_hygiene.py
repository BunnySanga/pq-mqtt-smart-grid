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
