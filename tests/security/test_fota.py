"""PQC-FOTA: signed artifacts, Merkle chunks, anti-rollback, A/B slots, anchor revocation, signed policy
(Master §15, §12; F1–F7, E-F1–E-F4, V-F1–V-F5, KEYREVOKE crash; DR-050; IMPLEMENTATION-ROADMAP §12, E57–E63).
Real SLH-DSA-SHA2-128s signatures from the station (OpenSSL ≥ 3.5)."""
import os
import random

import pytest

from conftest import World, make_policy
from pqgrid.fota.artifact import ANCHOR_A, ANCHOR_B, FIRMWARE, KEYREVOKE, POLICY, FotaError
from pqgrid.fota.installer import FotaFlash, Installer
from pqgrid.fota.policy_artifact import verify_policy_artifact
from pqgrid.fota.publisher import Publisher, part_payload_budget
from pqgrid.fota.station import Station, find_openssl
from pqgrid.persistence.flash import FlashSim, PowerLoss, RecordStore
from pqgrid.policy import encode_policy
from pqgrid.suite.sig import mldsa_public_bytes, slh_available

T0 = 1_790_000_000
C2, MP = "c2_meter", 4096                                   # the constrained class: 4 KiB packets, 3 KiB chunks
CHUNK = 3072


@pytest.fixture(scope="module")
def station(tmp_path_factory):
    if find_openssl() is None or not slh_available():
        pytest.skip("needs OpenSSL >= 3.5 with SLH-DSA (runs in the Docker test image)")
    return Station(str(tmp_path_factory.mktemp("station")))


def build(station, t, v, payload, cls=C2, max_packet=MP, chunk=CHUNK, **kw):
    return station.build(t, cls, v, payload, chunk, part_payload_budget(max_packet, cls, t, v), **kw)


class Dev:
    """One device's FOTA storage: normal flash, protected storage, slots. `boot()` models a reboot."""

    def __init__(self, station, cls=C2, max_packet=MP, slot=64 * 1024):
        self.station, self.cls, self.max_packet = station, cls, max_packet
        self.now = [T0]
        self.norm, self.prot, self.ff = FlashSim(), FlashSim(), FotaFlash(slot)
        self.boot()

    def boot(self):
        clock = lambda: self.now[0]                        # noqa: E731
        self.inst = Installer(self.station.anchors, self.cls, self.max_packet, self.ff,
                              RecordStore(self.prot, clock), RecordStore(self.norm, clock), clock)
        return self.inst

    def feed(self, art, parts=None, chunks=None, shuffle=True):
        parts, chunks = list(art.parts if parts is None else parts), list(art.chunks if chunks is None else chunks)
        if shuffle:
            random.shuffle(parts)
            random.shuffle(chunks)
        m = None
        for p in parts:
            m = self.inst.on_part(p) or m
        done = [t for c in chunks if (t := self.inst.on_chunk(c))]
        return m, done


@pytest.fixture
def dev(station):
    return Dev(station)


def firmware(n=20_000):
    return os.urandom(n)


# ================================================================================ install and boot
def test_V_F1_parted_manifest_installs_at_4096_and_8192(station):
    for max_packet, chunk in ((4096, 3072), (8192, 6144)):
        d = Dev(station, max_packet=max_packet)
        art = build(station, FIRMWARE, 2, firmware(), max_packet=max_packet, chunk=chunk)
        assert len(art.parts) == (3 if max_packet == 4096 else 1)          # 3 parts at 4 KiB; fits 8 KiB (§15.4)
        m, done = d.feed(art)
        assert m.version == 2 and done == [FIRMWARE]
        assert d.inst.boot_staged_firmware(lambda img: img == art.payload) == "committed"
        assert d.inst.committed(FIRMWARE) == 2


def test_every_published_message_fits_the_class_packet_limit(station, world: World):
    art = build(station, FIRMWARE, 2, firmware(50_000))
    pub = Publisher(world.policy)
    for topic, payload in pub.messages(art):
        from pqgrid.mqtt.topics import publish_size
        assert publish_size(topic, payload) <= MP


# ======================================================================================= F1–F7
def test_F1_tampered_chunk_is_refused_and_the_genuine_one_still_completes(dev, station):
    art = build(station, FIRMWARE, 2, firmware())
    dev.feed(art, chunks=[])
    bad = bytearray(art.chunks[3])
    bad[30] ^= 1
    with pytest.raises(FotaError, match="chunk 3 failed Merkle verification"):
        dev.inst.on_chunk(bytes(bad))
    assert [t for c in art.chunks if (t := dev.inst.on_chunk(c))] == [FIRMWARE]


def test_F2_tampered_manifest_is_refused(dev, station):
    """One flipped bit in the SLH-DSA signature, or in a signed field (the payload hash), fails exactly the
    signature check, directly and through the parts path; nothing starts downloading."""
    art = build(station, FIRMWARE, 2, firmware())
    for at in (len(art.signed) - 40, art.signed.index(art.manifest.payload_sha256) + 5):
        signed = bytearray(art.signed)
        signed[at] ^= 1
        with pytest.raises(FotaError, match="^manifest signature invalid$"):
            dev.inst.accept_signed(bytes(signed))
    part = bytearray(art.parts[0])
    part[-40] ^= 1                                                       # the last field of a part is its data
    with pytest.raises(FotaError, match="^manifest signature invalid$"):
        dev.feed(art, parts=[bytes(part)] + art.parts[1:], chunks=[], shuffle=False)
    assert dev.inst.downloads == {} and dev.inst.committed(FIRMWARE) == 0


def test_F3_artifact_from_a_foreign_station_is_refused(dev, tmp_path):
    rogue = Station(str(tmp_path))                                        # same anchor id 0, different key
    with pytest.raises(FotaError, match="manifest signature invalid"):
        dev.feed(build(rogue, FIRMWARE, 9, firmware()), chunks=[])


def test_F4_F5_rollback_and_replay_are_refused(dev, station):
    dev.feed(build(station, FIRMWARE, 3, firmware()))
    assert dev.inst.boot_staged_firmware(lambda img: True) == "committed"
    with pytest.raises(FotaError, match="rollback"):
        dev.feed(build(station, FIRMWARE, 2, firmware()), chunks=[])      # F4 older
    with pytest.raises(FotaError, match="rollback"):
        dev.feed(build(station, FIRMWARE, 3, firmware()), chunks=[])      # F5 the installed version


def test_F4_F5_the_signed_version_is_checked_not_just_the_part_labels(dev, station):
    """Part headers are unsigned. The early part check sees only the label; the signed manifest's own version is
    what counts: direct submission, and an old or installed manifest re-wrapped under a newer label."""
    from pqgrid.fota.artifact import encode_part
    old, cur = build(station, FIRMWARE, 2, firmware()), build(station, FIRMWARE, 3, firmware())
    dev.feed(cur)
    assert dev.inst.boot_staged_firmware(lambda img: True) == "committed"
    for art in (old, cur):
        with pytest.raises(FotaError, match="^rollback: version not newer than installed$"):
            dev.inst.accept_signed(art.signed)                              # F4 older, F5 installed
        relabelled = [encode_part(FIRMWARE, 9, i, 3, art.signed[k:k + 3000])      # 8,031 B → 3 parts
                      for i, k in enumerate(range(0, len(art.signed), 3000))]
        with pytest.raises(FotaError, match="^manifest parts labelled with another type or version$"):
            dev.feed(art, parts=relabelled, chunks=[], shuffle=False)
    assert dev.inst.committed(FIRMWARE) == 3 and dev.inst.downloads == {}


def test_F7_firmware_for_another_class_is_refused(dev, station):
    with pytest.raises(FotaError, match="another device class"):
        dev.feed(build(station, FIRMWARE, 2, firmware(), cls="der_ctrl"), chunks=[])


# ===================================================================================== E-F1–E-F4
def test_EF1_power_loss_mid_download_resumes_from_the_bitmap(dev, station):
    art = build(station, FIRMWARE, 2, firmware(30_000))
    dev.feed(art, chunks=art.chunks[:4], shuffle=False)
    dev.norm.fail_after = 30                                               # power fails while chunk 4's bit is saved
    with pytest.raises(PowerLoss):
        dev.inst.on_chunk(art.chunks[4])
    dev.norm.fail_after = None
    inst = dev.boot()                                                      # reboot: download state from flash
    assert FIRMWARE in inst.downloads
    have = inst.downloads[FIRMWARE].have
    assert all(have[i // 8] >> (i % 8) & 1 for i in range(4))               # the first four survived
    done = [t for c in art.chunks if (t := inst.on_chunk(c))]              # retained chunks again, duplicates ok
    assert done == [FIRMWARE] and inst.boot_staged_firmware(lambda i: i == art.payload) == "committed"


def test_EF2_failed_boot_reverts_and_the_same_version_can_be_retried(dev, station):
    art = build(station, FIRMWARE, 2, firmware())
    old_active = dev.inst.prot.active
    dev.feed(art)
    assert dev.inst.boot_staged_firmware(lambda img: False) == "reverted"
    assert dev.inst.committed(FIRMWARE) == 0 and dev.inst.prot.active == old_active   # counter unchanged
    dev.feed(art)                                                          # the same version again
    assert dev.inst.boot_staged_firmware(lambda img: True) == "committed"
    with pytest.raises(FotaError, match="rollback"):
        dev.feed(build(station, FIRMWARE, 1, firmware()), chunks=[])       # rollback still blocked


def test_EF3_chunk_from_another_version_is_refused(dev, station):
    a2, a3 = build(station, FIRMWARE, 2, firmware()), build(station, FIRMWARE, 3, firmware())
    dev.feed(a2, chunks=[])
    with pytest.raises(FotaError, match="chunk from another artifact"):
        dev.inst.on_chunk(a3.chunks[0])


def test_EF4_offline_across_policy_versions_installs_the_newest(dev, station, world: World):
    pk, ck = world.u_static.pk, mldsa_public_bytes(world.cmd_sk)
    arts = {v: build(station, POLICY, v, encode_policy(make_policy(pk, ck, version=v)), chunk=CHUNK)
            for v in (2, 3, 4)}
    dev.feed(arts[2], chunks=[])                                           # v2 arrives first …
    dev.feed(arts[4], chunks=[])                                           # … v4 replaces it
    with pytest.raises(FotaError, match="older than the artifact already in progress"):
        dev.feed(arts[3], chunks=[])                                       # v3 refused
    dev.feed(arts[4], parts=[])
    p = dev.inst.activate_policy(world.policy)
    assert p.version == 4 and dev.inst.committed(POLICY) == 4


# ========================================================================================= V-F2–V-F5
def test_VF2_keyrevoke_A_by_B_then_A_signed_artifacts_are_refused(dev, station):
    in_flight = build(station, FIRMWARE, 2, firmware())                   # A-signed, staged before the revoke
    dev.feed(in_flight)
    dev.feed(station.keyrevoke(C2, 1, ANCHOR_A, CHUNK, part_payload_budget(MP, C2, KEYREVOKE, 1)))
    assert dev.inst.prot.revoked == {ANCHOR_A} and dev.inst.committed(KEYREVOKE) == 1
    assert FIRMWARE not in dev.inst.staged                                 # E59: dropped
    with pytest.raises(FotaError, match="revoked anchor"):
        dev.feed(build(station, FIRMWARE, 3, firmware()), chunks=[])       # A-signed: refused
    b_signed = build(station, FIRMWARE, 3, firmware(), anchor_id=ANCHOR_B)
    dev.feed(b_signed)
    assert dev.inst.boot_staged_firmware(lambda img: True) == "committed"


def test_VF3_revocation_safety(dev, station):
    budget = part_payload_budget(MP, C2, KEYREVOKE, 1)
    with pytest.raises(FotaError, match="recovery anchor B"):              # signed by A: refused (DR-050)
        dev.feed(station.keyrevoke(C2, 1, ANCHOR_B, CHUNK, budget, anchor_id=ANCHOR_A), chunks=[])
    with pytest.raises(FotaError, match="only the recovery anchor B may revoke the release anchor A"):
        dev.feed(station.keyrevoke(C2, 1, ANCHOR_B, CHUNK, budget))         # B revoking itself: the last anchor
    assert dev.inst.prot.revoked == set() and dev.inst.committed(KEYREVOKE) == 0


def test_VF4_model_staged_image_modified_before_boot(dev, station):
    art = build(station, FIRMWARE, 2, firmware())
    dev.feed(art)
    dev.ff.slots[1 - dev.inst.prot.active][100] ^= 1                        # external slot tampered after staging
    assert dev.inst.boot_staged_firmware(lambda img: True) == "refused: staged image modified"
    assert dev.inst.committed(FIRMWARE) == 0


def test_VF5_payload_larger_than_the_own_slot_is_refused_before_download(station):
    d = Dev(station, slot=16 * 1024)
    with pytest.raises(FotaError, match="larger than this device's slot"):
        d.feed(build(station, FIRMWARE, 2, firmware(20_000)), chunks=[])
    assert d.inst.downloads == {}


def test_E61_chunks_that_would_not_fit_the_packet_limit_are_refused(station):
    d = Dev(station, max_packet=4096)
    with pytest.raises(FotaError, match="packet limit"):
        d.feed(build(station, FIRMWARE, 2, firmware(), max_packet=8192, chunk=6144), chunks=[])


# ============================================================================ crash safety, factory reset
def test_keyrevoke_power_loss_leaves_old_or_new_never_torn(station):
    art = station.keyrevoke(C2, 1, ANCHOR_A, CHUNK, part_payload_budget(MP, C2, KEYREVOKE, 1))
    probe = Dev(station)
    probe.feed(art, chunks=[])
    t0 = probe.prot.ticks
    probe.feed(art, parts=[])
    n = probe.prot.ticks - t0                                              # protected-store operations
    assert n > 0
    for k in range(n):
        d = Dev(station)
        d.feed(art, chunks=[])
        d.prot.fail_after = k
        with pytest.raises(PowerLoss):
            d.feed(art, parts=[])
        d.prot.fail_after = None
        inst = d.boot()                                                    # boot finishes an interrupted revoke
        assert (inst.prot.revoked, inst.committed(KEYREVOKE)) == ({ANCHOR_A}, 1), f"power loss at {k}/{n}"
        assert KEYREVOKE not in inst.staged


def test_factory_reset_does_not_reopen_rollback(dev, station):
    dev.feed(build(station, FIRMWARE, 5, firmware()))
    assert dev.inst.boot_staged_firmware(lambda img: True) == "committed"
    dev.norm = FlashSim()                                                  # factory reset: normal flash erased
    dev.boot()
    with pytest.raises(FotaError, match="rollback"):
        dev.feed(build(station, FIRMWARE, 4, firmware()), chunks=[])


def test_E60_firmware_waits_for_activate_at(dev, station):
    dev.feed(build(station, FIRMWARE, 2, firmware(), activate_at=T0 + 3600))
    assert dev.inst.boot_staged_firmware(lambda img: True) == "waiting for activate_at"
    dev.now[0] = T0 + 3600
    assert dev.inst.boot_staged_firmware(lambda img: True) == "committed"


# ================================================================================== signed policy
def test_policy_activates_at_its_time_and_E57_binds_versions(dev, station, world: World):
    pk, ck = world.u_static.pk, mldsa_public_bytes(world.cmd_sk)
    v2 = make_policy(pk, ck, version=2, activate_at=T0 + 600)
    dev.feed(build(station, POLICY, 2, encode_policy(v2), activate_at=T0 + 600))
    assert dev.inst.activate_policy(world.policy) is None                  # installed ahead of activation
    dev.now[0] = T0 + 600
    assert dev.inst.activate_policy(world.policy).info() == v2.info()
    liar = build(station, POLICY, 7, encode_policy(make_policy(pk, ck, version=3)))   # manifest 7, policy 3
    dev.feed(liar)
    with pytest.raises(FotaError, match="E57"):
        dev.inst.activate_policy(v2)
    assert dev.inst.committed(POLICY) == 2


def test_utility_and_acl_accept_only_a_verified_policy(station, world: World, tmp_path):
    payload = encode_policy(world.policy)
    art = build(station, POLICY, world.policy.version, payload)
    assert verify_policy_artifact(art.signed, payload, station.anchors).info() == world.policy.info()
    with pytest.raises(FotaError, match="do not match"):
        verify_policy_artifact(art.signed, payload[:-1] + b"\x00", station.anchors)
    with pytest.raises(FotaError, match="revoked"):
        verify_policy_artifact(art.signed, payload, station.anchors, revoked={ANCHOR_A})
    rogue = Station(str(tmp_path))
    with pytest.raises(FotaError, match="signature invalid"):
        verify_policy_artifact(build(rogue, POLICY, world.policy.version, payload).signed, payload, station.anchors)
    from pqgrid.mqtt.broker import compile_acl
    with pytest.raises(FotaError):
        compile_acl(art.signed, payload + b"x", station.anchors, [], {})


# ============================================================================================ publisher
def test_publisher_retention_and_rate_limited_republish(station, world: World):
    sent = []

    class Client:
        def publish(self, topic, payload, qos, retain):
            sent.append((topic, payload, retain))
    now = [T0]
    pub = Publisher(world.policy, clock=lambda: now[0])
    art = build(station, FIRMWARE, 2, firmware())
    pub.publish(Client(), art)
    assert all(r for _, _, r in sent) and len(sent) == len(art.parts) + len(art.chunks)
    newer = build(station, FIRMWARE, 3, firmware())
    sent.clear()
    pub.publish(Client(), newer)                                           # the older version is cleared
    assert sum(1 for _, p, _ in sent if p == b"") == len(art.parts) + len(art.chunks)
    now[0] += 30 * 86400
    sent.clear()
    assert pub.cleanup(Client()) == 1 and all(p == b"" for _, p, _ in sent)   # retained copies removed …
    sent.clear()
    assert pub.on_request(Client(), C2, b"c2-0001")                        # … but a late device still gets it
    assert {p for _, p, _ in sent} >= set(newer.parts) | set(newer.chunks)
    assert not pub.on_request(Client(), C2, b"c2-0001")                    # at most once an hour
    now[0] += 3600
    assert pub.on_request(Client(), C2, b"c2-0001")


def test_signed_manifest_size(station):
    """Master §15.2: 8,042 B [ANALYTICAL] for the 128s signed manifest. Measured here for class "c2_meter"."""
    art = build(station, FIRMWARE, 2, firmware())
    print(f"signed manifest: {len(art.signed)} B in {len(art.parts)} parts at {MP} B")
    # manifest: 12 length prefixes (48) + 5 + 1 + 8 ("c2_meter") + 8 + 8 + 32 + 4 + 4 + 32 + 8 + 8 + 1 = 167 B;
    # signed: 4 + 167 + 4 + 7,856 (SLH-DSA-SHA2-128s) = 8,031 B
    assert len(art.manifest.encode()) == 167 and len(art.signed) == 8031


@pytest.mark.parametrize("target", ["part", "chunk", "signed"])
def test_corrupted_fota_messages_are_refused_cleanly(station, target):
    """300 random mutations into each FOTA parser: every one is refused (FotaError, or held and never accepted),
    nothing is installed, the staging area stays bounded, and the staging is NOT cleared by the test: poisoned
    staging must be detected by the installer (a failed verification) and the genuine artifact must still
    install, at the latest on its next retained re-delivery."""
    from test_fuzz import mutations
    from pqgrid.fota.installer import MAX_ASSEMBLIES
    rng = random.Random(hash(target) & 0xFFFF)
    art = build(station, FIRMWARE, 2, firmware(9000))
    d = Dev(station)
    if target == "chunk":
        d.feed(art, chunks=[])
        fn, base = d.inst.on_chunk, art.chunks[1]
    elif target == "part":
        fn, base = d.inst.on_part, art.parts[0]
    else:
        fn, base = d.inst.accept_signed, art.signed
    count, accepted = 0, []
    for m in mutations(base, rng):
        try:
            if fn(m) is not None:
                accepted.append(m)                                       # a manifest, or a completed artifact
        except FotaError:
            pass
        count += 1
    assert count >= 270 and accepted == [] and d.inst.committed(FIRMWARE) == 0
    assert len(d.inst._parts) <= MAX_ASSEMBLIES and FIRMWARE not in d.inst.staged
    detected = []
    for delivery in range(2):                                            # the retained copies, twice at most
        try:
            d.feed(art)
            break
        except FotaError as e:
            detected.append(str(e))
    assert all("signature invalid" in e for e in detected) and len(detected) <= 1
    assert d.inst.boot_staged_firmware(lambda img: img == art.payload) == "committed"


def test_manifest_staging_is_bounded_and_the_genuine_parts_still_assemble(station):
    """Forged part headers (50 distinct versions) cannot grow the staging area beyond MAX_ASSEMBLIES; the genuine
    parts evict them and install; once installed, a part for that version is refused before it is staged."""
    from pqgrid.fota.artifact import encode_part
    from pqgrid.fota.installer import MAX_ASSEMBLIES
    art = build(station, FIRMWARE, 2, firmware(9000))
    d = Dev(station)
    for v in range(3, 53):
        assert d.inst.on_part(encode_part(FIRMWARE, v, 0, 2, b"x" * 100)) is None
    assert len(d.inst._parts) == MAX_ASSEMBLIES
    d.feed(art)
    assert d.inst.boot_staged_firmware(lambda img: img == art.payload) == "committed"
    with pytest.raises(FotaError, match="rollback: manifest part"):
        d.inst.on_part(art.parts[0])
    assert len(d.inst._parts) <= MAX_ASSEMBLIES


def test_a_validly_signed_but_invalid_policy_is_refused_at_activation(dev, station, world: World):
    """A signature proves origin, not safety: the validator (rules 1–10) still runs (§12 Signed Policy)."""
    import dataclasses
    from conftest import replace_class
    from pqgrid.policy.model import ResumeMode
    pk, ck = world.u_static.pk, mldsa_public_bytes(world.cmd_sk)
    unsafe = make_policy(pk, ck, version=2, classes=replace_class(world.policy, "der_ctrl", resume=ResumeMode.PSK))
    dev.feed(build(station, POLICY, 2, encode_policy(unsafe)))
    with pytest.raises(FotaError, match="rule 3"):                          # A13 through FOTA
        dev.inst.activate_policy(world.policy)
    assert dev.inst.committed(POLICY) == 0 and POLICY not in dev.inst.staged
    assert dataclasses.is_dataclass(unsafe)


def test_publisher_refuses_messages_larger_than_the_class_limit(station, world: World):
    oversized = build(station, FIRMWARE, 2, firmware(), max_packet=8192, chunk=6144)   # built for 8 KiB …
    with pytest.raises(FotaError, match="max_packet"):
        Publisher(world.policy).messages(oversized)                        # … published to a 4 KiB class
