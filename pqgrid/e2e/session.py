"""An established E2E session (Master §9.5, §9.7).

Keys and message counters live only in RAM and die together (I-6); nothing here is ever persisted.
Python cannot guarantee memory erasure: `close()` drops every reference so the keys become unreachable,
which is the strongest property this prototype can claim (it is not "zeroised").
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..policy.model import ResumeMode
from ..suite.aead import AeadAlg
from .keys import traffic_key
from .replay import ReplayGuard


@dataclass
class Session:
    device_id: bytes
    dclass: str
    policy_info: bytes
    fw_version: int
    aead: AeadAlg
    k_master: bytes = field(repr=False)
    sid: bytes
    resume_mode: ResumeMode
    chain_expires: int
    provisioned_at: int = 0          # utility side: the device record's provisioned_at when it was established; a
    #                                  re-provisioning ends it wherever it is used (second Codex review, finding 2)
    _keys: dict = field(default_factory=dict, repr=False)
    _send: dict = field(default_factory=dict, repr=False)
    _guards: dict = field(default_factory=dict, repr=False)

    def key(self, name: str, direction: str) -> bytes:
        k = self._keys.get((name, direction))
        if k is None:
            k = self._keys[(name, direction)] = traffic_key(self.k_master, name, direction)
        return k

    def next_send_seq(self, name: str, direction: str) -> int:
        """Per-session, per-direction message counter, starting at 1 (the AEAD nonce input)."""
        n = self._send.get((name, direction), 0) + 1
        self._send[(name, direction)] = n
        return n

    def guard(self, name: str, direction: str) -> ReplayGuard:
        return self._guards.setdefault((name, direction), ReplayGuard())

    def close(self) -> None:
        self._keys.clear()
        self.k_master = b""
