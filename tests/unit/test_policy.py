"""Binary policy codec, tier engine, validator rules 1–10 (Master §11, §12)."""
import dataclasses

import pytest

from conftest import DEFAULT_CLASSES, make_class, make_policy
from pqgrid.errors import PolicyError
from pqgrid.policy import (CmdType, ResumeMode, Rule, Tier, decode_policy, encode_policy, tier_for, topic_matches,
                           valid_filter, validate)
from pqgrid.suite.hkem import HybridKeyPair
from pqgrid.suite.sig import mldsa_keygen, mldsa_public_bytes
from pqgrid.wire import dec, enc

UPK = HybridKeyPair.generate().pk
CPK = mldsa_public_bytes(mldsa_keygen())


def policy(**kw):
    return make_policy(UPK, CPK, **kw)


# ------------------------------------------------------------------------------------------------ codec
def test_roundtrip_is_exact_and_raw_is_kept():
    p = policy()
    raw = encode_policy(p)
    q = decode_policy(raw)
    assert q == p and q.raw == raw and encode_policy(q) == raw


def test_policy_info_format():
    p = policy(version=7)
    assert p.info() == b"nitk-grid|" + (7).to_bytes(4, "big")


def test_noncanonical_class_order_is_rejected():
    raw = encode_policy(policy())
    f = dec(raw, 10)
    classes = dec(f[6], 1 + len(DEFAULT_CLASSES))
    swapped = enc([classes[0], classes[2], classes[1], classes[3]])        # reorder two class records
    f[6] = swapped
    with pytest.raises(PolicyError, match="canonical"):
        decode_policy(enc(f))


@pytest.mark.parametrize("idx,value", [(0, b"PQPOL1"), (4, b"\x09")])
def test_bad_magic_or_tier_rejected(idx, value):
    f = dec(encode_policy(policy()), 10)
    f[idx] = value
    with pytest.raises(PolicyError):
        decode_policy(enc(f))


def test_truncated_policy_rejected():
    raw = encode_policy(policy())
    with pytest.raises(PolicyError):
        decode_policy(raw[:-1])


# ------------------------------------------------------------------------------------------------ engine
def test_tier_mapping_and_fail_safe_default():
    p = policy()
    assert p.tier("grid/smart_meter/m1/telemetry") is Tier.TELEMETRY
    assert p.tier("grid/smart_meter/m1/alert") is Tier.ALERT
    assert p.tier("grid/der_ctrl/d1/control") is Tier.CONTROL
    assert p.tier("grid/smart_meter/m1/unknown") is Tier.CONTROL          # nobody thought of it → strongest
    assert p.tier("grid/+/m1/alert") is Tier.CONTROL                      # a filter is not a topic


def test_strongest_rule_wins_regardless_of_order():
    rules = (Rule("grid/#", Tier.TELEMETRY), Rule("grid/+/+/control", Tier.CONTROL))
    for rs in (rules, tuple(reversed(rules))):
        p = policy(rules=rs)
        assert tier_for(p, "grid/der_ctrl/d1/control") is Tier.CONTROL
        assert tier_for(p, "grid/der_ctrl/d1/telemetry") is Tier.TELEMETRY


def test_filters_and_matching():
    assert valid_filter("grid/+/x/#") and not valid_filter("grid/a+/x") and not valid_filter("grid/#/x")
    assert topic_matches("grid/#", "grid/a/b") and topic_matches("grid/+/b", "grid/a/b")
    assert not topic_matches("grid/+", "grid/a/b")


# ------------------------------------------------------------------------------------------------ validator
def test_default_policy_is_valid():
    validate(policy())


def _with_class(**over):
    classes = dict(DEFAULT_CLASSES)
    classes["der_ctrl"] = dataclasses.replace(classes["der_ctrl"], **over)
    return policy(classes=classes)


@pytest.mark.parametrize("build,rule", [
    (lambda: policy(default_tier=Tier.TELEMETRY), "rule 1"),
    (lambda: policy(rules=(Rule("grid/a+/x", Tier.ALERT),)), "rule 2"),
    (lambda: _with_class(resume=ResumeMode.PSK), "rule 3"),
    (lambda: _with_class(ticket_lifetime_s=0), "rule 4"),
    (lambda: _with_class(max_chain_age_s=8 * 86400, ticket_lifetime_s=86400), "rule 4"),
    (lambda: _with_class(ticket_lifetime_s=900000, max_chain_age_s=604800), "rule 4"),
    (lambda: _with_class(cmd_types=frozenset({CmdType.SETPOINT})), "rule 6"),
    (lambda: _with_class(fota_chunk_size=65536 - 100), "rule 7"),
    (lambda: _with_class(tls_max_record=3000), "rule 8"),
    (lambda: _with_class(dup_window_s=119), "rule 9"),
    (lambda: _with_class(pending_ttl_s=59), "rule 9"),
    (lambda: policy(ca_set=()), "rule 10"),
])
def test_each_rule_rejects(build, rule):
    with pytest.raises(PolicyError, match=rule):
        validate(build())


def test_rule5_rollback_and_u32_version():
    validate(policy(version=5), installed_version=4)
    with pytest.raises(PolicyError, match="rule 5"):
        validate(policy(version=4), installed_version=4)
    with pytest.raises(PolicyError, match="u32"):
        validate(policy(version=1 << 32))


def test_key_lengths_checked():
    with pytest.raises(PolicyError, match="1,216"):
        validate(make_policy(UPK[:-1], CPK))


def test_constrained_class_fits_its_packet_limit():
    c2 = DEFAULT_CLASSES["c2_meter"]
    assert c2.fota_chunk_size + 677 <= c2.max_packet == 4096
    with pytest.raises(PolicyError, match="rule 7"):
        classes = dict(DEFAULT_CLASSES)
        classes["c2_meter"] = make_class("c2_meter", max_packet=4096, fota_chunk_size=3500)
        validate(policy(classes=classes))
