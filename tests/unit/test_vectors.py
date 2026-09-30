"""Independent oracles (remediation, "INDEPENDENT ORACLES"). Nothing here is computed by the code under test:

  * X-Wing: the first known-answer vector of draft-connolly-cfrg-xwing-kem-11, Appendix C, stored verbatim in
    tests/vectors/. The 96-byte expanded key comes from hashlib.shake_256 (the draft's expandDecapsulationKey).
  * Wire formats: every expected byte string is written out by hand, field by field, from the layouts in Master
    §12, §13.1, §14.3 and §15 (u32 big-endian length ‖ bytes per field). Signature inputs are recomputed with
    hashlib from the Master's labels and field order. The encoders must produce exactly these bytes and the
    decoders must return exactly these values.
"""
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from pqgrid.commands.codec import (Command, Grant, Setpoint, ZoneKey, bcast_signed_input, cmd_signed_input, decode,
                                   encode, grant_signed_input)
from pqgrid.fota.artifact import FIRMWARE, Manifest, decode_manifest
from pqgrid.pasr.stek import StekTable
from pqgrid.pasr.tickets import Ticket, seal_ticket
from pqgrid.policy import ClassProfile, Policy, Profile, Reconnect, ResumeMode, Rule, Tier, decode_policy, encode_policy
from pqgrid.suite.aead import AeadAlg
from pqgrid.suite.hkem import HybridKeyPair, decaps

VECTORS = Path(__file__).resolve().parents[1] / "vectors"


def L(b: bytes) -> bytes:
    """One field of the wire format, restated here from the spec: u32 big-endian length, then the bytes."""
    return len(b).to_bytes(4, "big") + b


def H(*parts: bytes) -> bytes:
    """The transcript/signature digest, restated from the spec: SHA-256 over length-prefixed parts."""
    return hashlib.sha256(b"".join(L(p) for p in parts)).digest()


# ================================================================================================ X-Wing KAT
def test_xwing_known_answer_vector_from_the_draft():
    v = json.loads((VECTORS / "xwing_draft11_vector1.json").read_text())
    seed, pk, ct, ss = (bytes.fromhex(v[k]) for k in ("seed", "pk", "ct", "ss"))
    assert (len(seed), len(pk), len(ct), len(ss)) == (32, 1216, 1120, 32)
    kp = HybridKeyPair.from_private_bytes(hashlib.shake_256(seed).digest(96))   # d ‖ z ‖ sk_X
    assert kp.pk == pk                                                         # ML-KEM-768 ek ‖ X25519 pk
    assert decaps(kp, ct) == ss                                                # both KEMs and the combiner
    bad = bytearray(ct)
    bad[0] ^= 1
    assert decaps(kp, bytes(bad)) != ss                                        # implicit rejection, no error


# ============================================================================================ CONTROL (§13.1)
SEQ = (1 << 32) | 2                                                            # epoch 1, counter 2
EXP = 0x6A000000


def test_cmd_fixture_and_signed_input():
    expected = bytes.fromhex(
        "00000003" "434d44"                       # "CMD"
        "00000008" "0000000100000002"             # u64 cmd_seq
        "00000004" "54524950"                     # command "TRIP"
        "00000008" "000000006a000000"             # u64 expires_at
        "00000001" "01"                           # u8 idempotent
        "00000002" "aabb")                        # σ (a stand-in; ML-DSA-65 is 3,309 B)
    c = Command(SEQ, b"TRIP", EXP, True, b"\xaa\xbb")
    assert encode(c) == expected and decode(expected) == c
    topic = "grid/der_ctrl/der-0001/control"
    assert cmd_signed_input(b"der-0001", topic, SEQ, EXP, True, b"TRIP") == b"pqgrid/v2/cmd" + H(
        b"der-0001", topic.encode(), SEQ.to_bytes(8, "big"), EXP.to_bytes(8, "big"), b"\x01", b"TRIP")


def test_grant_fixture_and_signed_input():
    expected = bytes.fromhex(
        "00000005" "4752414e54"                   # "GRANT"
        "00000008" "0000000100000002"             # u64 cmd_seq
        "00000008" "0102030405060708"             # grant_id
        "00000008" "1112131415161718"             # sid
        "0000000a" "505f4143544956455f57"         # target "P_ACTIVE_W"
        "00000008" "ffffffffffffec78"             # i64 min = -5000
        "00000008" "0000000000001388"             # i64 max = 5000
        "00000004" "0000000c"                     # u32 max_rate = 12
        "00000008" "0000000069ffffc4"             # u64 not_before = EXP - 60
        "00000008" "000000006a000e10"             # u64 expires_at = EXP + 3600
        "00000001" "cc")                          # σ stand-in
    g = Grant(SEQ, bytes.fromhex("0102030405060708"), bytes.fromhex("1112131415161718"), "P_ACTIVE_W", -5000, 5000,
              12, EXP - 60, EXP + 3600, b"\xcc")
    assert encode(g) == expected and decode(expected) == g
    topic = "grid/der_ctrl/der-0001/control"
    assert grant_signed_input(b"der-0001", topic, g) == b"pqgrid/v2/grant" + H(
        b"der-0001", topic.encode(), SEQ.to_bytes(8, "big"), g.grant_id, g.sid, b"P_ACTIVE_W",
        (-5000).to_bytes(8, "big", signed=True), (5000).to_bytes(8, "big", signed=True), (12).to_bytes(4, "big"),
        (EXP - 60).to_bytes(8, "big"), (EXP + 3600).to_bytes(8, "big"))


def test_setpoint_and_zonekey_fixtures():
    sp = bytes.fromhex(
        "00000008" "534554504f494e54"             # "SETPOINT"
        "00000008" "0102030405060708"             # grant_id
        "00000008" "00000000000009c4"             # i64 value = 2500
        "00000008" "000000006a00001e")            # u64 expires_at = EXP + 30
    s = Setpoint(bytes.fromhex("0102030405060708"), 2500, EXP + 30)
    assert encode(s) == sp and decode(sp) == s
    key = bytes(range(32))
    zk = bytes.fromhex(
        "00000007" "5a4f4e454b4559"               # "ZONEKEY"
        "00000002" "6637"                         # zone "f7"
        "00000008" "0000000000000003"             # u64 key_epoch = 3
        "00000010" "4348414348413230504f4c5931333035"   # aead "CHACHA20POLY1305" (16 B)
        "00000020" + key.hex())                   # key (32 B)
    z = ZoneKey("f7", 3, AeadAlg.CHACHA20POLY1305, key)
    assert encode(z) == zk and decode(zk) == z
    assert bcast_signed_input("f7", SEQ, EXP, b"SHED") == b"pqgrid/v2/bcast" + H(
        b"f7", SEQ.to_bytes(8, "big"), EXP.to_bytes(8, "big"), b"SHED")          # logical σ (M7)


# ================================================================================================ ticket (§14.3)
def test_ticket_plaintext_and_blob_layout_opened_with_an_independent_cipher():
    stek = StekTable()
    now = 1_790_000_000
    t = Ticket(bytes(range(16)), b"der-0001", "der_ctrl", b"nitk-grid|\x00\x00\x00\x01", 1, ResumeMode.PSK_KEM,
               now, now + 86400, now + 604800, bytes(range(100, 132)))
    blob = seal_ticket(stek, t, now)
    k = stek.current(now)
    head = b"\x01" + k.kid.to_bytes(2, "big")                                 # version ‖ kid
    assert blob[:3] == head
    pt = ChaCha20Poly1305(k.key).decrypt(blob[3:15], blob[15:], head)         # AAD = head
    assert pt == bytes.fromhex(
        "00000010" + bytes(range(16)).hex() +     # ticket_id (16 B)
        "00000008" "6465722d30303031"             # device_id "der-0001"
        "00000008" "6465725f6374726c"             # class "der_ctrl"
        "0000000e" "6e69746b2d677269647c00000001"  # POLICY_INFO "nitk-grid|" ‖ u32 version 1
        "00000008" "0000000000000001"             # u64 fw_version 1
        "00000007" "50534b5f4b454d"               # resume_mode "PSK_KEM"
        "00000008" + now.to_bytes(8, "big").hex() +              # u64 issued_at
        "00000008" + (now + 86400).to_bytes(8, "big").hex() +    # u64 expires_at
        "00000008" + (now + 604800).to_bytes(8, "big").hex() +   # u64 chain_expires_at
        "00000020" + bytes(range(100, 132)).hex())               # psk (32 B)


# =========================================================================================== FOTA manifest (§15)
def test_fota_manifest_fixture():
    sha, root = bytes([0x11] * 32), bytes([0x22] * 32)
    m = Manifest(FIRMWARE, "c2_meter", 2, 20000, sha, 3072, 7, root, 1_790_000_600, 1_790_000_000, 0)
    expected = bytes.fromhex(
        "00000005" "5051465732"                   # "PQFW2"
        "00000001" "01"                           # u8 type FIRMWARE
        "00000008" "63325f6d65746572"             # class "c2_meter"
        "00000008" "0000000000000002"             # u64 version
        "00000008" "0000000000004e20"             # u64 payload_length 20,000
        "00000020" + sha.hex() +                  # payload SHA-256
        "00000004" "00000c00"                     # u32 chunk_size 3,072
        "00000004" "00000007"                     # u32 chunk_count 7
        "00000020" + root.hex() +                 # Merkle root
        "00000008" + (1_790_000_600).to_bytes(8, "big").hex() +  # u64 activate_at
        "00000008" + (1_790_000_000).to_bytes(8, "big").hex() +  # u64 issued_at
        "00000001" "00")                          # u8 signer anchor A
    assert len(expected) == 167                   # the size pinned in test_fota (hand count: 12×4 + 119)
    assert m.encode() == expected and decode_manifest(expected) == m


# ================================================================================================ policy (§12)
def test_policy_fixture_one_rule_one_class():
    c = ClassProfile(name="m", profile=Profile.FULL, resume=ResumeMode.PSK, ticket_lifetime_s=86400,
                     max_chain_age_s=604800, unicast_control=False, cmd_types=frozenset(), max_setpoint_rate=0,
                     aead=AeadAlg.AES256GCM, tls_max_record=None, max_packet=65536, fota_chunk_size=16384,
                     reconnect=Reconnect.PERSISTENT, reconnect_interval_s=0, backoff_base_s=2, backoff_cap_s=300,
                     session_expiry_s=604800, keepalive_s=300, dup_window_s=120, pending_ttl_s=60, outbox_cap=4096)
    p = Policy(policy_id="g", version=7, activate_at=0, default_tier=Tier.CONTROL,
               rules=(Rule("grid/+/+/alert", Tier.ALERT),), classes={"m": c}, utility_kem_pk=b"K" * 3,
               utility_cmd_pk=b"C" * 2, ca_set=(b"D",))
    u32 = lambda v: v.to_bytes(4, "big")                                       # noqa: E731
    cls = (L(b"m") + L(b"FULL") + L(b"PSK") + L(u32(86400)) + L(u32(604800)) + L(b"\x00") + L(b"\x00") +
           L(b"\x00\x00") + L(b"AES256GCM") + L(b"\x00\x00") + L(u32(65536)) + L(u32(16384)) + L(b"PERSISTENT") +
           L(u32(0)) + L(u32(2)) + L(u32(300)) + L(u32(604800)) + L(u32(300)) + L(u32(120)) + L(u32(60)) +
           L(u32(4096)))
    expected = (L(b"PQPOL2") + L(b"g") + L((7).to_bytes(8, "big")) + L(bytes(8)) + L(b"\x03") +
                L(L(b"\x00\x01") + L(L(b"grid/+/+/alert") + L(b"\x02"))) +    # rules: u16 count, then records
                L(L(b"\x00\x01") + L(cls)) +                                   # classes: u16 count, then records
                L(b"KKK") + L(b"CC") + L(L(b"\x00\x01") + L(b"D")))            # keys, then ca_set (counted)
    assert encode_policy(p) == expected
    q = decode_policy(expected)
    assert q == p and q.info() == b"g|\x00\x00\x00\x07"                        # POLICY_INFO = id ‖ "|" ‖ u32 version
