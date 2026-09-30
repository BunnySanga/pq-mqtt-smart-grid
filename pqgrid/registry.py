"""Utility-side device registry (Master §4.4): device ID → class, E2E public key, active flag, packet limit.

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
    max_packet: Optional[int] = None


class Registry:
    def __init__(self):
        self._d: dict[bytes, DeviceRecord] = {}

    def add(self, rec: DeviceRecord) -> None:
        if not valid_device_id(rec.device_id):
            raise PolicyError("invalid device id")
        if len(rec.e2e_pk) != HKEM_PK_LEN:
            raise PolicyError("device E2E public key must be 1,216 bytes")
        self._store(rec)
        self._d[rec.device_id] = rec

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
