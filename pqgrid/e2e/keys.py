"""The key schedule (Master §9.4, §9.5, Appendix C; DR-044).

    K_B       = HKDF-Expand(HKDF-Extract(SALT, ss_U),        "early" ‖ H(pk_e, ct_U, n_D))   CH inner block
    K1        = HKDF-Expand(HKDF-Extract(SALT, ss_e ‖ ss_U), "k1"    ‖ H(CH))                SH inner block
    K_master  = HKDF-Extract(salt = th2 = H(transcript), IKM = ss_e ‖ ss_U ‖ ss_D)             session root
    kc_U, kc_D, sid, fin, key|<tier>|<dir>   = HKDF-Expand(K_master, label)
    MAC_U     = HMAC(kc_U, "U-finished" ‖ th2)
    MAC_D     = HMAC(kc_D, "D-finished" ‖ H(th2, MAC_U, H(bundle)))                            DR-044

Resumption (Master §9.4, §9.5, §14; IMPLEMENTATION-ROADMAP §8.1):
    psk       = HKDF-Expand(K_master, "res|" ‖ ticket_id)          sealed in the ticket, held by the device
    K_binder  = HKDF-Expand(psk, "binder")                         RH binder (psk is already uniform: E19)
    K_nt      = HKDF-Expand(K_master, "new-ticket")                NT ticket delivery
    K_master′ = HKDF-Extract(salt = th_R, IKM = psk ‖ [ss_e′])     then the same labels as above

Every derived key has its own label (domain separation). The SALT separates v2.2 transcripts from v2.1's.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..suite.kdf import h, hkdf_expand, hkdf_extract, mac

SALT = b"pqgrid/v2/hs"
SID_LEN = 8

L_EARLY, L_K1 = b"early", b"k1"
L_KC_U, L_KC_D, L_SID, L_FIN, L_NEW_TICKET = b"kc_U", b"kc_D", b"sid", b"fin", b"new-ticket"
L_RES, L_BINDER = b"res|", b"binder"
TRAFFIC = {("ALERT", "up"), ("CONTROL", "down"), ("ACK", "up"), ("ACK", "down"), ("SYNC", "up")}   # SYNC: E-2


@dataclass(frozen=True)
class MasterKeys:
    k_master: bytes = field(repr=False)
    kc_u: bytes = field(repr=False)
    kc_d: bytes = field(repr=False)
    sid: bytes


def early_key(ss_u: bytes, pk_e: bytes, ct_u: bytes, n_d: bytes) -> bytes:
    return hkdf_expand(hkdf_extract(SALT, ss_u), L_EARLY + h(pk_e, ct_u, n_d))


def k1_key(ss_e: bytes, ss_u: bytes, ch: bytes) -> bytes:
    return hkdf_expand(hkdf_extract(SALT, ss_e + ss_u), L_K1 + h(ch))


def derive_master(th2: bytes, ikm: bytes) -> MasterKeys:
    k = hkdf_extract(th2, ikm)
    return MasterKeys(k, hkdf_expand(k, L_KC_U), hkdf_expand(k, L_KC_D), hkdf_expand(k, L_SID, SID_LEN))


def traffic_key(k_master: bytes, name: str, direction: str) -> bytes:
    if (name, direction) not in TRAFFIC:
        raise ValueError(f"no traffic key {name}|{direction}")
    return hkdf_expand(k_master, b"key|" + name.encode() + b"|" + direction.encode())


def fin_key(k_master: bytes) -> bytes:
    return hkdf_expand(k_master, L_FIN)


def resumption_psk(k_master: bytes, ticket_id: bytes) -> bytes:
    return hkdf_expand(k_master, L_RES + ticket_id)


def binder_key(psk: bytes) -> bytes:
    return hkdf_expand(psk, L_BINDER)


def new_ticket_key(k_master: bytes) -> bytes:
    return hkdf_expand(k_master, L_NEW_TICKET)


def mac_u(kc_u: bytes, th2: bytes) -> bytes:
    return mac(kc_u, b"U-finished" + th2)


def mac_d(kc_d: bytes, th2: bytes, mac_u_: bytes, bundle: bytes) -> bytes:
    """DR-044: the device's key confirmation also covers the bundle carried in DF."""
    return mac(kc_d, b"D-finished" + h(th2, mac_u_, h(bundle)))
