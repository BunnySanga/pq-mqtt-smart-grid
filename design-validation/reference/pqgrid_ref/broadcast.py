"""Broadcast CONTROL (demand-response): zone key (delivered over each member's E2E session) + utility ML-DSA-65 signature."""
from __future__ import annotations
import os, time
from .suite import aead_seal, aead_open, mldsa_verify, h
from .wire import enc, dec, u64, r64

def seal_broadcast(cmd_sk, zone: bytes, epoch: int, zone_key: bytes, seq: int, event: bytes, ttl_s=300, now=None) -> bytes:
    now = int(now or time.time()); exp = u64(now + ttl_s); s, e = u64(seq), u64(epoch)
    sig = cmd_sk.sign(b"pqgrid/v1/bcast" + h(zone, e, s, exp, event))
    n = os.urandom(12)
    return enc([b"\x04", zone, e, s, n, aead_seal(zone_key, n, enc([event, exp, sig]), h(b"BCAST", zone, e, s))])

class ZoneReceiver:
    def __init__(self, cmd_pk: bytes): self.cmd_pk, self.keys, self.hi = cmd_pk, {}, {}
    def open(self, env: bytes, now=None) -> bytes:
        now = int(now or time.time())
        t, zone, e, s, n, ct = dec(env, 6)
        key = self.keys.get((zone, r64(e)))
        if t != b"\x04" or key is None: raise ValueError("no key for zone/epoch")
        if r64(s) <= self.hi.get(zone, 0): raise ValueError("broadcast replay")
        event, exp, sig = dec(aead_open(key, n, ct, h(b"BCAST", zone, e, s)), 3)
        if r64(exp) < now: raise ValueError("broadcast expired")
        if not mldsa_verify(self.cmd_pk, sig, b"pqgrid/v1/bcast" + h(zone, e, s, exp, event)): raise ValueError("broadcast signature invalid")
        self.hi[zone] = r64(s); return event
