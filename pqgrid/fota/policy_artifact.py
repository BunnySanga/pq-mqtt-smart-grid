"""The signed policy (Master §12 Signed Policy / Distribution; E13 closed, E57).

A policy is accepted only from a POLICY artifact: the manifest signature is checked against a non-revoked anchor,
the payload against the signed length and SHA-256, and the exact signed bytes are decoded (nothing is
re-serialised). The utility and the broker's ACL compiler use this; devices use the installer, which adds
anti-rollback and activation.
"""
from __future__ import annotations

import hashlib

from ..errors import PolicyError, WireError
from ..policy import decode_policy
from ..suite.sig import slh_verify
from .artifact import POLICY, FotaError, check_signer, decode_manifest, split_signed


def verify_policy_artifact(signed: bytes, payload: bytes, anchors: dict[int, bytes], revoked=frozenset()):
    raw, sig = split_signed(signed)
    m = decode_manifest(raw)
    if m.signer_anchor_id not in anchors or m.signer_anchor_id in revoked:
        raise FotaError("policy signed by an unknown or revoked anchor")
    if not slh_verify(anchors[m.signer_anchor_id], sig, raw):
        raise FotaError("manifest signature invalid")
    if m.type != POLICY:
        raise FotaError("not a POLICY artifact")
    check_signer(POLICY, m.signer_anchor_id, revoked)                   # DR-050 roles (H4)
    if len(payload) != m.payload_length or hashlib.sha256(payload).digest() != m.payload_sha256:
        raise FotaError("policy bytes do not match the signed manifest")
    try:
        p = decode_policy(payload)
    except (PolicyError, WireError) as e:
        raise FotaError(f"signed policy does not decode: {e}") from e
    if p.version != m.version or p.activate_at != m.activate_at:
        raise FotaError("manifest and policy disagree on version or activate_at (E57)")
    return p
