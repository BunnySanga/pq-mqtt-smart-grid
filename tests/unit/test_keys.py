"""Key schedule: every label yields an independent key; DR-044 binds the bundle (Master §9.5)."""
import pytest

from pqgrid.e2e import keys


def test_all_session_keys_are_distinct():
    mk = keys.derive_master(b"t" * 32, b"s" * 96)
    derived = [mk.k_master, mk.kc_u, mk.kc_d, keys.fin_key(mk.k_master)]
    derived += [keys.traffic_key(mk.k_master, n, d) for n, d in sorted(keys.TRAFFIC)]
    assert len(mk.sid) == 8
    assert len(set(derived)) == len(derived)


def test_transcript_changes_every_key():
    a = keys.derive_master(b"t" * 32, b"s" * 96)
    b = keys.derive_master(b"u" * 32, b"s" * 96)
    assert a.k_master != b.k_master and a.sid != b.sid and a.kc_d != b.kc_d


def test_unknown_traffic_key_refused():
    with pytest.raises(ValueError):
        keys.traffic_key(b"k" * 32, "ALERT", "down")


def test_mac_d_binds_the_bundle():
    base = keys.mac_d(b"k" * 32, b"t" * 32, b"m" * 32, b"")
    assert base != keys.mac_d(b"k" * 32, b"t" * 32, b"m" * 32, b"x")
    assert base != keys.mac_d(b"k" * 32, b"t" * 32, b"M" * 32, b"")


def test_pre_handshake_keys_are_domain_separated():
    assert keys.early_key(b"s" * 32, b"p", b"c", b"n") != keys.k1_key(b"s" * 16, b"s" * 16, b"p")
