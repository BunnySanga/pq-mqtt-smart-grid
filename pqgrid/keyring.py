"""The utility's private keys and how a policy selects them (Master §4.4, §4.7, §12 Policy Updates; DR-051).

The signed policy carries the utility's PUBLIC keys: `utility_kem_pk` (hybrid E2E) and `utility_cmd_pk` (ML-DSA-65
command key). The utility keeps a keyring of PRIVATE keys: the ones in use and any prepared for a rotation. It always
operates with the pair whose public keys its ACTIVE policy names, so the persisted active policy alone decides which
keys are in use: there is no second "current key" record that a crash could leave disagreeing with the policy.

A rotation is therefore: prepare the new private keys (durable), then schedule and activate a policy that names them.
A policy whose keys are not in the keyring is refused when it is scheduled and again when it is activated, before
anything changes (audit H-1: activating it used to succeed while the utility kept its old keys, which locked every
device out). Keys are never removed here; a retired key is simply no longer named by the active policy.

Private keys never appear in a repr, a log or an exception; diagnostics name a key by a public fingerprint.
Prototype storage is the utility database (L16); production keeps them in an HSM.
"""
from __future__ import annotations

import hashlib
from typing import Optional

from .errors import KeyringError
from .suite.hkem import HybridKeyPair
from .suite.sig import mldsa_public_bytes


RETIRED_KEMS = 2              # older E2E keys tried to recognise an old-policy client hello (bounded work per CH)


def fingerprint(pk: bytes) -> str:
    """A public key's short name for diagnostics: the first 8 bytes of its SHA-256, in hex."""
    return hashlib.sha256(pk).hexdigest()[:16]


class UtilityKeyring:
    def __init__(self):
        self._kem: dict[bytes, HybridKeyPair] = {}
        self._cmd: dict[bytes, object] = {}

    def __repr__(self) -> str:
        return f"UtilityKeyring(kem={sorted(map(fingerprint, self._kem))}, cmd={sorted(map(fingerprint, self._cmd))})"

    def add(self, kem: Optional[HybridKeyPair] = None, cmd=None, expect_kem_pk: Optional[bytes] = None,
            expect_cmd_pk: Optional[bytes] = None) -> None:
        """Hold private keys (durably before they can be used). Each public key is derived from its private key;
        `expect_*` refuses a key that does not match the public key the operator meant to prepare. Nothing is stored
        if any check fails."""
        if kem is not None and not isinstance(kem, HybridKeyPair):
            raise KeyringError("the KEM key must be a hybrid X25519 + ML-KEM-768 key pair")
        kem_pk = kem.pk if kem is not None else None
        cmd_pk = mldsa_public_bytes(cmd) if cmd is not None else None
        if expect_kem_pk is not None and kem_pk != expect_kem_pk:
            raise KeyringError(f"the prepared KEM private key does not match the expected public key "
                               f"{fingerprint(expect_kem_pk)}")
        if expect_cmd_pk is not None and cmd_pk != expect_cmd_pk:
            raise KeyringError(f"the prepared command private key does not match the expected public key "
                               f"{fingerprint(expect_cmd_pk)}")
        if kem is not None and kem_pk not in self._kem:
            self._store_kem(kem)
            self._kem[kem_pk] = kem
        if cmd is not None and cmd_pk not in self._cmd:
            self._store_cmd(cmd)
            self._cmd[cmd_pk] = cmd

    def kem_for(self, pk: bytes) -> HybridKeyPair:
        kp = self._kem.get(pk)
        if kp is None:
            raise KeyringError(f"the utility holds no private KEM key for utility_kem_pk {fingerprint(pk)}")
        return kp

    def cmd_for(self, pk: bytes):
        sk = self._cmd.get(pk)
        if sk is None:
            raise KeyringError(f"the utility holds no private command key for utility_cmd_pk {fingerprint(pk)}")
        return sk

    def keys_for(self, policy) -> tuple[HybridKeyPair, object]:
        """The (KEM key pair, command key) a policy needs; KeyringError if either is missing."""
        return self.kem_for(policy.utility_kem_pk), self.cmd_for(policy.utility_cmd_pk)

    def retired_kems(self, active_pk: bytes, limit: int = RETIRED_KEMS) -> list[HybridKeyPair]:
        """The most recently held KEM keys other than the active one, newest first. The endpoint uses them only to
        RECOGNISE a client hello from a device still on an older policy (so it can be refused as such and sent the
        current policy, E-4), never to establish a session (DR-051)."""
        return [kp for pk, kp in reversed(list(self._kem.items())) if pk != active_pk][:limit]

    # persistence hooks (persistence.utility_db.SqlKeyring); in memory they do nothing
    def _store_kem(self, kp: HybridKeyPair) -> None:
        pass

    def _store_cmd(self, sk) -> None:
        pass
