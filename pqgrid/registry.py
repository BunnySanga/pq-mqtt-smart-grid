"""Utility-side device registry (Master §4.4): device ID → class, E2E public key, active flag, packet limit.

A record is added once. Changing a device's class or E2E key, or its revocation, is never a silent overwrite (Codex
audit P1-1, IMPLEMENTATION-ROADMAP §16): revoke() and UtilityNode.reprovision (persistence.utility_db, or
UtilityMqtt.reprovision_device) are the only ways. _reprovision() here is only the record step of the latter; sessions
and queued commands carry the record's provisioned_at and are refused wherever they are used once it changed
(second Codex review, finding 2), so even the record step alone lets nothing of the old record through except the
zone keys it held, which only the whole operation rotates.

Device IDs become MQTT topic levels and ACL user names, so they are restricted to
^[a-z0-9][a-z0-9-]{0,31}$ (Master §10.1, I-21): '+', '#', '/' could otherwise inject rules.
This class keeps it in memory; persistence.utility_db.SqlRegistry stores every change first (slice 4).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Optional

from .errors import PolicyError
from .suite.hkem import PK_LEN as HKEM_PK_LEN

_DEVICE_ID = re.compile(rb"^[a-z0-9][a-z0-9-]{0,31}$")


def valid_device_id(device_id: bytes) -> bool:
    return bool(_DEVICE_ID.fullmatch(device_id))       # not match(): '$' also matches before a final '\n'


@dataclass(frozen=True)
class DeviceRecord:
    device_id: bytes
    dclass: str
    e2e_pk: bytes
    active: bool = True
    max_packet: Optional[int] = None  # the device's reported maximum (Master §10.2); the utility never sends more
    #                                    than min(this, class max_packet). pqgrid devices declare the class value, so
    #                                    a smaller value here can make an NT/FIN unpublishable (Master §25 L22)
    provisioned_at: int = 0           # utility time of the last re-provisioning (0: never): a resumption ticket
    #                                    issued at or before it is refused (P1-1)


class Registry:
    def __init__(self):
        self._d: dict[bytes, DeviceRecord] = {}

    def add(self, rec: DeviceRecord) -> None:
        """Register a device. A new record starts at provisioned_at 0 (never re-provisioned), whatever the caller
        passes. Adding a registered device again with the same class, key and state may only update its reported
        max_packet: its provisioned_at is KEPT (third Codex review, finding 1: an "idempotent" add stored the caller's
        default 0, and the old key's tickets were accepted again)."""
        self._check(rec)
        old = self._d.get(rec.device_id)
        if old is not None and (old.dclass, old.e2e_pk, old.active) != (rec.dclass, rec.e2e_pk, rec.active):
            raise PolicyError("device already registered: a class, key or revocation change goes through "
                              "UtilityNode.reprovision or revoke(), never an overwrite (P1-1)")
        rec = replace(rec, provisioned_at=0 if old is None else old.provisioned_at)
        self._store(rec)
        self._d[rec.device_id] = rec

    def _reprovision(self, rec: DeviceRecord, now: int) -> DeviceRecord:
        """The record step of UtilityNode.reprovision (internal: call that, or UtilityMqtt.reprovision_device). A
        registered device gets a new class and/or E2E key (or the same ones again, e.g. after a clone: "revoke and
        re-provision", Master §23.11). The record is active again and stamped with `now`: no resumption ticket, session
        or queued command of the old record is accepted from then on. Durable before it takes effect."""
        self._check(rec)
        old = self._d.get(rec.device_id)
        if old is None:
            raise PolicyError("device not registered: use add()")
        # A generation that only ever grows (third review, finding 1): the utility's clock, but never at or below the
        # previous value, so a clock set back or two re-provisionings in one second cannot reuse a generation.
        rec = replace(rec, active=True, provisioned_at=max(int(now), old.provisioned_at + 1))
        self._store(rec)
        self._d[rec.device_id] = rec
        return rec

    @staticmethod
    def _check(rec: DeviceRecord) -> None:
        if not valid_device_id(rec.device_id):
            raise PolicyError("invalid device id")
        if len(rec.e2e_pk) != HKEM_PK_LEN:
            raise PolicyError("device E2E public key must be 1,216 bytes")

    def get(self, device_id: bytes) -> Optional[DeviceRecord]:
        return self._d.get(device_id)

    def records(self) -> list[DeviceRecord]:
        return list(self._d.values())

    def revoke(self, device_id: bytes) -> None:
        rec = self._d.get(device_id)
        if rec:
            rec = replace(rec, active=False)
            self._store(rec)                                   # revocation is durable before it takes effect
            self._d[device_id] = rec

    def _store(self, rec: DeviceRecord) -> None:
        """Persistence hook; in memory it does nothing."""
