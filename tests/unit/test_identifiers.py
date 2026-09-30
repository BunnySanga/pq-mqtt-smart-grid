"""Identifier grammars (Master §10.1, §12, I-21). Device IDs, policy IDs, class names, zone names and GRANT targets
become MQTT topic levels, ACL lines, POLICY_INFO or certificate CNs, so each must match its whole grammar: a
trailing newline would split an ACL line, and '+', '#', '/' would inject topic rules. The expected verdicts below are
written by hand from the grammars, not derived from the implementation."""
import os

import pytest

from conftest import make_class, make_policy
from pqgrid.commands.codec import decode, valid_token
from pqgrid.commands.zones import ZoneManager
from pqgrid.errors import CommandError, PolicyError, WireError
from pqgrid.policy import validate
from pqgrid.registry import DeviceRecord, Registry, valid_device_id
from pqgrid.suite.hkem import HybridKeyPair
from pqgrid.suite.sig import mldsa_keygen, mldsa_public_bytes
from pqgrid.wire import enc, i64, u32, u64

UPK = HybridKeyPair.generate().pk
CPK = mldsa_public_bytes(mldsa_keygen())

# ^[a-z0-9][a-z0-9-]{0,31}$ over the WHOLE string
DEVICE_OK = [b"a", b"0", b"meter-0001", b"der-0001", b"a" * 32, b"0-"]
DEVICE_BAD = [b"", b"meter-0001\n", b"\nmeter", b"-meter", b"Meter", b"meter_1", b"a" * 33, b"meter/1",
              b"meter+", b"meter#", b"meter 1", b"meter\x00", b"meter-0001\r"]
# ^[A-Za-z0-9_-]{1,32}$ over the whole string (zone names, GRANT targets)
TOKEN_OK = ["f7", "P_ACTIVE_W", "Z-1", "a" * 32]
TOKEN_BAD = ["", "f7\n", "f7/x", "+", "#", "f 7", "a" * 33, "zöne"]


@pytest.mark.parametrize("did", DEVICE_OK)
def test_device_id_grammar_accepts(did):
    assert valid_device_id(did)


@pytest.mark.parametrize("did", DEVICE_BAD)
def test_device_id_grammar_rejects_and_registry_refuses(did):
    assert not valid_device_id(did)
    with pytest.raises(PolicyError, match="invalid device id"):
        Registry().add(DeviceRecord(did, "smart_meter", UPK))


@pytest.mark.parametrize("tok", TOKEN_OK)
def test_token_grammar_accepts(tok):
    assert valid_token(tok)


@pytest.mark.parametrize("tok", TOKEN_BAD)
def test_token_grammar_rejects_zone_names_and_targets_everywhere(tok):
    assert not valid_token(tok)
    with pytest.raises(CommandError):
        ZoneManager(service=None).create(tok)                           # utility: zone creation
    zonekey = enc([b"ZONEKEY", tok.encode(), u64(1), b"AES256GCM", os.urandom(32)])
    grant = enc([b"GRANT", u64(1), b"g" * 8, b"s" * 8, tok.encode(), i64(0), i64(1), u32(1), u64(0), u64(1),
                 b"sig"])
    for pt in (zonekey, grant):                                         # device: authenticated plaintexts
        with pytest.raises(WireError):
            decode(pt)


@pytest.mark.parametrize("pid", ["nitk-grid\n", "Nitk", "-grid", "a" * 33, "grid/1", ""])
def test_policy_id_grammar(pid):
    with pytest.raises(PolicyError, match="policy_id"):
        validate(make_policy(UPK, CPK, policy_id=pid))


@pytest.mark.parametrize("name", ["smart_meter\n", "Smart", "_meter", "meter-1", "a" * 33, "grid/x", "m+"])
def test_class_name_grammar(name):
    with pytest.raises(PolicyError, match="class name"):
        validate(make_policy(UPK, CPK, classes={name: make_class(name)}))


def test_the_longest_valid_identifiers_are_accepted_end_to_end():
    validate(make_policy(UPK, CPK, policy_id="p" * 32, classes={"c" * 32: make_class("c" * 32)}))
    Registry().add(DeviceRecord(b"d" * 32, "c" * 32, UPK))
