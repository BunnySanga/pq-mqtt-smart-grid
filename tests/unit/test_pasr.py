"""PASR building blocks: STEK lifecycle, ticket sealing, the single-use set, resumption labels
(Master §14.3–§14.7, §9.5; IMPLEMENTATION-ROADMAP E19–E21, E28)."""
import os

import pytest

from pqgrid.e2e import keys
from pqgrid.errors import TicketError
from pqgrid.pasr import StekTable, Ticket, UsedTickets, open_ticket, seal_ticket
from pqgrid.pasr.stek import KID_MOD, MAX_TICKET_S, ROTATION_S, StekKey
from pqgrid.policy.model import ResumeMode

T0 = 1_790_000_000


def ticket(**over) -> Ticket:
    base = dict(ticket_id=os.urandom(16), device_id=b"meter-0001", dclass="smart_meter",
                policy_info=b"nitk-grid|\x00\x00\x00\x01", fw_version=7, resume_mode=ResumeMode.PSK,
                issued_at=T0, expires_at=T0 + 86400, chain_expires_at=T0 + 604800, psk=os.urandom(32))
    base.update(over)
    return Ticket(**base)


# ---------------------------------------------------------------------------------------------------- STEK
def test_stek_rotates_after_24h_and_keeps_old_keys_until_retirement():
    st = StekTable()
    k0 = st.current(T0)
    assert st.current(T0 + ROTATION_S - 1) is k0                      # still current just before 24 h
    k1 = st.current(T0 + ROTATION_S)
    assert (k0.kid, k1.kid) == (0, 1) and k0.key != k1.key
    assert st.key(0, T0 + ROTATION_S) == k0.key                       # old key still opens its tickets


def test_stek_retires_exactly_when_no_ticket_it_sealed_can_be_alive():
    st = StekTable()
    k0 = st.current(T0)
    assert k0.retire_at == T0 + ROTATION_S + MAX_TICKET_S
    assert st.key(0, k0.retire_at - 1) == k0.key
    with pytest.raises(TicketError, match="ticket key retired"):
        st.key(0, k0.retire_at)
    with pytest.raises(TicketError, match="ticket key retired"):
        st.key(12345, T0)                                              # never existed


def test_stek_retired_keys_are_dropped_on_rotation():
    st = StekTable()
    for day in range(12):
        st.current(T0 + day * ROTATION_S)
    assert st.live_kids() == list(range(4, 12))       # key d retires at day d + 8 (24 h current + 7 days)


def test_stek_kid_is_16_bits_and_never_reuses_a_live_kid():
    st = StekTable()
    k0 = st.current(T0)                                                # kid 0, live for 8 days
    last = StekKey(KID_MOD - 1, os.urandom(32), T0, T0 + ROTATION_S + MAX_TICKET_S)
    st._keys[last.kid], st._current = last, last                      # as if 65,535 rotations had happened
    with pytest.raises(TicketError, match="still live"):
        st.current(T0 + ROTATION_S)                                    # would wrap onto live kid 0
    st._keys = {0: k0, last.kid: last}
    wrapped = st.current(k0.retire_at)                                 # kid 0 has retired: wrap allowed
    assert wrapped.kid == 0 and wrapped.key != k0.key


# ------------------------------------------------------------------------------------------------- tickets
def test_ticket_roundtrip_and_layout():
    st, t = StekTable(), ticket()
    blob = seal_ticket(st, t, T0)
    assert blob[:1] == b"\x01" and blob[1:3] == b"\x00\x00"           # version ‖ kid (u16, big-endian)
    assert open_ticket(st, blob, T0) == t


@pytest.mark.parametrize("where", [3, 10, 20, -1])                   # nonce, ciphertext, tag
def test_tampered_ticket_is_not_authentic(where):
    st = StekTable()
    blob = bytearray(seal_ticket(st, ticket(), T0))
    blob[where] ^= 1
    with pytest.raises(TicketError, match="ticket not authentic"):
        open_ticket(st, bytes(blob), T0)


def test_ticket_header_is_authenticated():
    """Moving a ticket to another live kid, or changing its version, is refused (AAD = 0x01 ‖ kid)."""
    st = StekTable()
    blob = seal_ticket(st, ticket(), T0)
    st.current(T0 + ROTATION_S)                                        # kid 1 now live too
    with pytest.raises(TicketError, match="ticket not authentic"):
        open_ticket(st, blob[:1] + b"\x00\x01" + blob[3:], T0 + ROTATION_S)
    with pytest.raises(TicketError, match="malformed ticket"):
        open_ticket(st, b"\x02" + blob[1:], T0)
    with pytest.raises(TicketError, match="malformed ticket"):
        open_ticket(st, blob[:20], T0)


def test_ticket_from_another_stek_is_not_authentic():
    """Same kid, different key (a utility that lost its STEK, or an attacker's): refused."""
    blob = seal_ticket(StekTable(), ticket(), T0)
    other = StekTable()
    other.current(T0)
    with pytest.raises(TicketError, match="ticket not authentic"):
        open_ticket(other, blob, T0)


# -------------------------------------------------------------------------------------------- single use
def test_used_tickets_single_use_and_pruned_after_expiry():
    used = UsedTickets()
    assert used.consume(b"a" * 16, T0 + 10, T0)
    assert not used.consume(b"a" * 16, T0 + 10, T0 + 5)
    assert used.consume(b"b" * 16, T0 + 100, T0 + 5)
    assert len(used) == 2
    used.consume(b"c" * 16, T0 + 200, T0 + 10)                         # a's record expires at T0 + 10
    assert len(used) == 2                                              # a forgotten; b and c remain


def test_used_tickets_prune_is_by_expiry_not_by_insertion_order():
    used = UsedTickets()
    used.consume(b"long" + bytes(12), T0 + 1000, T0)
    used.consume(b"short" + bytes(11), T0 + 10, T0)
    used.consume(b"x" * 16, T0 + 2000, T0 + 11)
    assert len(used) == 2 and not used.consume(b"long" + bytes(12), T0 + 1000, T0 + 11)


# ------------------------------------------------------------------------------------------------- labels
def test_resumption_keys_are_separated():
    km, tid = os.urandom(32), os.urandom(16)
    psk = keys.resumption_psk(km, tid)
    derived = {psk, keys.binder_key(psk), keys.new_ticket_key(km), keys.fin_key(km),
               keys.resumption_psk(km, os.urandom(16)), keys.derive_master(b"t" * 32, km).kc_u}
    assert len(derived) == 6 and all(len(k) == 32 for k in derived)


def test_ticket_aad_is_exactly_version_and_kid():
    """Format conformance (Master §14.3): AAD = 0x01 ‖ kid. Behaviourally redundant with one key per kid, so
    it is pinned here directly."""
    from pqgrid.suite import aead
    from pqgrid.errors import CryptoError
    st = StekTable()
    blob = seal_ticket(st, ticket(), T0)
    key, nonce, ct = st.key(0, T0), blob[3:15], blob[15:]
    assert aead.open_(aead.AeadAlg.CHACHA20POLY1305, key, nonce, ct, b"\x01\x00\x00")
    for other in (b"", b"\x01", b"\x01\x00\x01"):
        with pytest.raises(CryptoError):
            aead.open_(aead.AeadAlg.CHACHA20POLY1305, key, nonce, ct, other)
