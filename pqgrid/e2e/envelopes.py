"""ALERT and CONTROL envelopes, their ACKs, and DF/FIN bundles (Master §11, §9.4, §13; DR-044, DR-045).

    ALERT   = enc[0x02, sid(8), msg_seq(8), AEAD(K_ALERT|up, nonce = 0x01‖000‖msg_seq,
                                               pt = enc[alert_id(16), payload],
                                               aad = H("ALERT", topic, sid, msg_seq))]
    ACK     = enc[0x05, sid(8), msg_seq(8), HMAC(K_ACK|down, sid ‖ msg_seq)]
    CONTROL = enc[0x03, sid(8), msg_seq(8), AEAD(K_CONTROL|down, nonce = 0x02‖000‖msg_seq, pt,
                                               aad = H("CONTROL", topic, sid, msg_seq))]
    STATUS  = enc[0x06, sid(8), msg_seq(8), cmd_seq(8), status, HMAC(K_ACK|up, sid ‖ msg_seq ‖ cmd_seq ‖ status)]
              (DR-045; status is the only variable-length MAC input and comes last)
    ZONESYNC = enc[0x08, sid(8), seq(8), key_epoch_seen(8), zone, HMAC(K_SYNC|up, sid ‖ seq ‖ epoch ‖ zone)]
              (E-2: a device that got a DR event it cannot open asks for its current zone key and the zone's
               still-valid events; own key label, own replay guard; the zone is the only variable-length input)
    bundle = b"" (empty) or enc[u16 count ≥ 1, item₁ … itemₙ]   (canonical: an empty bundle is 0 bytes)

Receivers check the tier from their **own** installed policy and that the topic's device owns the session.
"""
from __future__ import annotations

from ..errors import CryptoError, EnvelopeError, WireError
from ..policy.model import Tier
from ..suite import aead
from ..suite.kdf import ct_eq, h, mac
from ..wire import dec, dec_list, enc, enc_list, peek_tag, r64, u64
from .session import Session

T_ALERT, T_ALERT_ACK = b"\x02", b"\x05"
T_CONTROL, T_STATUS = b"\x03", b"\x06"
T_ZONESYNC = b"\x08"
STATUSES = {b"OK", b"DUP", b"SUPERSEDED", b"EXPIRED", b"INTERRUPTED"}
REJECT_REASONS = {b"signature", b"sid", b"bounds", b"rate", b"time", b"no-grant", b"target", b"not-allowed",
                  b"aead", b"malformed", b"capacity"}
ALERT_ID_LEN = 16
MAX_BUNDLE = 64            # engineering cap on envelopes carried in one DF / FIN (IMPLEMENTATION-ROADMAP E12)
ACK_BUNDLE_ENTRY = 4 + 65  # one ALERT ACK in the NT/FIN bundle: length prefix + enc[tag, sid(8), u64, MAC(32)]
FINAL_REPLY_FIXED = 420    # NT with the largest ticket + PUBLISH header and topic, before the ACKs (≤ 403 B)


def df_alert_limit(max_packet: int) -> int:
    """How many queued alerts one DF may carry so that the NT/FIN answering it, with one ACK each, still fits the
    device's Maximum Packet Size (the broker drops a larger PUBLISH silently). The rest go live after it."""
    return max(0, min(MAX_BUNDLE, (max_packet - FINAL_REPLY_FIXED) // ACK_BUNDLE_ENTRY))


def alert_topic(dclass: str, device_id: bytes) -> str:
    return f"grid/{dclass}/{device_id.decode()}/alert"


def _check_alert_topic(policy, topic: str, s: Session) -> None:
    if policy.tier(topic) is not Tier.ALERT:
        raise EnvelopeError("topic is not ALERT tier under the installed policy")
    parts = topic.split("/")
    if len(parts) != 4 or parts[0] != "grid" or parts[3] != "alert":
        raise EnvelopeError("not an alert topic")
    if parts[1] != s.dclass or parts[2].encode() != s.device_id:
        raise EnvelopeError("envelope belongs to another device's session")


def seal_alert(policy, s: Session, topic: str, alert_id: bytes, payload: bytes) -> bytes:
    """Device side. The sender's own policy must also say ALERT (Master A7)."""
    if len(alert_id) != ALERT_ID_LEN:
        raise EnvelopeError("alert_id must be 16 bytes")
    _check_alert_topic(policy, topic, s)
    seq = s.next_send_seq("ALERT", "up")
    ct = aead.seal(s.aead, s.key("ALERT", "up"), aead.counter_nonce(aead.DIR_ALERT_UP, seq),
                   enc([alert_id, payload]), h(b"ALERT", topic.encode(), s.sid, u64(seq)))
    return enc([T_ALERT, s.sid, u64(seq), ct])


def envelope_sid(env: bytes) -> bytes:
    """Read the sid of an ALERT envelope so the receiver can find the session (no authentication yet)."""
    t, sid, _seq, _ct = dec(env, 4)
    if t != T_ALERT or len(sid) != 8:
        raise EnvelopeError("not an alert envelope")
    return sid


def open_alert(policy, s: Session, topic: str, env: bytes) -> tuple[bytes, bytes, int]:
    """Utility side. Returns (alert_id, payload, msg_seq). Replay check is two-phase (I-7)."""
    try:
        t, sid, seq_b, ct = dec(env, 4)
        seq = r64(seq_b)
    except WireError as e:
        raise EnvelopeError("malformed alert envelope") from e
    if t != T_ALERT or not ct_eq(sid, s.sid):
        raise EnvelopeError("not an alert for this session")
    _check_alert_topic(policy, topic, s)
    guard = s.guard("ALERT", "up")
    guard.validate(seq)                                   # phase 1: before decryption
    try:
        pt = aead.open_(s.aead, s.key("ALERT", "up"), aead.counter_nonce(aead.DIR_ALERT_UP, seq), ct,
                        h(b"ALERT", topic.encode(), s.sid, seq_b))
    except CryptoError as e:
        raise EnvelopeError("alert failed authentication") from e
    guard.accept(seq)                                     # phase 2: only after authentication
    try:
        alert_id, payload = dec(pt, 2)
    except WireError as e:
        raise EnvelopeError("malformed alert plaintext") from e
    if len(alert_id) != ALERT_ID_LEN:
        raise EnvelopeError("bad alert_id length")
    return alert_id, payload, seq


def alert_ack(s: Session, msg_seq: int) -> bytes:
    return enc([T_ALERT_ACK, s.sid, u64(msg_seq), mac(s.key("ACK", "down"), s.sid + u64(msg_seq))])


def verify_alert_ack(s: Session, ack: bytes) -> int:
    """Device side. Returns the acknowledged msg_seq."""
    try:
        t, sid, seq_b, m = dec(ack, 4)
        seq = r64(seq_b)
    except WireError as e:
        raise EnvelopeError("malformed ack") from e
    if t != T_ALERT_ACK or not ct_eq(sid, s.sid):
        raise EnvelopeError("ack for another session")
    if not ct_eq(m, mac(s.key("ACK", "down"), sid + seq_b)):
        raise EnvelopeError("forged ack")
    return seq


def encode_bundle(items: list[bytes]) -> bytes:
    return enc_list(items, MAX_BUNDLE) if items else b""


def decode_bundle(b: bytes) -> list[bytes]:
    if b == b"":
        return []
    items = dec_list(b, MAX_BUNDLE)
    if not items:
        raise WireError("non-canonical empty bundle")
    return items


# ================================================================================================ CONTROL
def control_topic(dclass: str, device_id: bytes) -> str:
    return f"grid/{dclass}/{device_id.decode()}/control"


def _check_control_topic(policy, topic: str, s: Session) -> None:
    if policy.tier(topic) is not Tier.CONTROL:
        raise EnvelopeError("topic is not CONTROL tier under the installed policy")
    parts = topic.split("/")
    if len(parts) != 4 or parts[0] != "grid" or parts[3] != "control":
        raise EnvelopeError("not a unicast control topic")
    if parts[1] != s.dclass or parts[2].encode() != s.device_id:
        raise EnvelopeError("envelope belongs to another device's session")


def seal_control(policy, s: Session, topic: str, pt: bytes) -> bytes:
    """Utility side."""
    _check_control_topic(policy, topic, s)
    seq = s.next_send_seq("CONTROL", "down")
    ct = aead.seal(s.aead, s.key("CONTROL", "down"), aead.counter_nonce(aead.DIR_CONTROL_DOWN, seq), pt,
                   h(b"CONTROL", topic.encode(), s.sid, u64(seq)))
    return enc([T_CONTROL, s.sid, u64(seq), ct])


def open_control(policy, s: Session, topic: str, env: bytes) -> tuple[bytes, int]:
    """Device side. Returns (pt, msg_seq). Two-phase replay check (I-7): a forgery never burns a sequence."""
    try:
        t, sid, seq_b, ct = dec(env, 4)
        seq = r64(seq_b)
    except WireError as e:
        raise EnvelopeError("malformed control envelope") from e
    if t != T_CONTROL or not ct_eq(sid, s.sid):
        raise EnvelopeError("not a control envelope for this session")
    _check_control_topic(policy, topic, s)
    guard = s.guard("CONTROL", "down")
    guard.validate(seq)
    try:
        pt = aead.open_(s.aead, s.key("CONTROL", "down"), aead.counter_nonce(aead.DIR_CONTROL_DOWN, seq), ct,
                        h(b"CONTROL", topic.encode(), s.sid, seq_b))
    except CryptoError as e:
        raise EnvelopeError("control envelope failed authentication") from e
    guard.accept(seq)
    return pt, seq


def valid_status(status: bytes) -> bool:
    if status in STATUSES:
        return True
    head, _, reason = status.partition(b":")
    return head == b"REJECTED" and reason in REJECT_REASONS


def status_ack(s: Session, msg_seq: int, cmd_seq: int, status: bytes) -> bytes:
    """Device side (DR-045). msg_seq 0 marks an unsolicited report (IMPLEMENTATION-ROADMAP E34)."""
    if not valid_status(status):
        raise EnvelopeError("unknown status")
    body = [s.sid, u64(msg_seq), u64(cmd_seq), status]
    return enc([T_STATUS, *body, mac(s.key("ACK", "up"), b"".join(body))])


def zone_sync(s: Session, zone: str, epoch_seen: int) -> bytes:
    """Device side (E-2): ask for the current key of `zone` and its still-valid events."""
    body = [s.sid, u64(s.next_send_seq("SYNC", "up")), u64(epoch_seen), zone.encode()]
    return enc([T_ZONESYNC, *body, mac(s.key("SYNC", "up"), b"".join(body))])


def zone_sync_sid(env: bytes) -> bytes:
    if peek_tag(env) != T_ZONESYNC:
        raise EnvelopeError("not a zone sync request")
    sid = dec(env, 6)[1]
    if len(sid) != 8:
        raise EnvelopeError("not a zone sync request")
    return sid


def open_zone_sync(s: Session, env: bytes) -> tuple[str, int]:
    """Utility side: authenticate and replay-check a ZONESYNC. Returns (zone, key epoch the device saw)."""
    try:
        t, sid, seq_b, epoch_b, zone_b, m = dec(env, 6)
        seq, epoch, zone = r64(seq_b), r64(epoch_b), zone_b.decode("ascii")
    except (WireError, UnicodeDecodeError) as e:
        raise EnvelopeError("malformed zone sync request") from e
    if t != T_ZONESYNC or not ct_eq(sid, s.sid):
        raise EnvelopeError("zone sync request for another session")
    guard = s.guard("SYNC", "up")
    guard.validate(seq)
    if not ct_eq(m, mac(s.key("SYNC", "up"), sid + seq_b + epoch_b + zone_b)):
        raise EnvelopeError("forged zone sync request")
    guard.accept(seq)
    return zone, epoch


def status_sid(ack: bytes) -> bytes:
    """Read the sid of a status ACK so the utility can find the session (no authentication yet)."""
    if peek_tag(ack) != T_STATUS:
        raise EnvelopeError("not a status ack")
    sid = dec(ack, 6)[1]
    if len(sid) != 8:
        raise EnvelopeError("not a status ack")
    return sid


def verify_status_ack(s: Session, ack: bytes) -> tuple[int, int, bytes]:
    """Utility side. Returns (msg_seq, cmd_seq, status)."""
    try:
        t, sid, mseq_b, cseq_b, status, m = dec(ack, 6)
        mseq, cseq = r64(mseq_b), r64(cseq_b)
    except WireError as e:
        raise EnvelopeError("malformed status ack") from e
    if t != T_STATUS or not ct_eq(sid, s.sid):
        raise EnvelopeError("status ack for another session")
    if not ct_eq(m, mac(s.key("ACK", "up"), sid + mseq_b + cseq_b + status)):
        raise EnvelopeError("forged status ack")
    if not valid_status(status):
        raise EnvelopeError("unknown status")
    return mseq, cseq, status
