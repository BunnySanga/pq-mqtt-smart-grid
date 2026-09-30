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


def test_power_loss_between_the_commit_and_dropping_the_staged_record(dev, station):
    """§15.12: the commit is one protected record; the staging record is dropped after it. A power cut in between
    leaves a staged manifest whose version is already committed. The next boot must finish the commit (drop it), not
    re-hash the slot that is now the OLD one and report a false "staged image modified" (a tamper alarm)."""
    art = build(station, FIRMWARE, 2, firmware())
    dev.feed(art)
    active = dev.inst.prot.active
    dev.norm.fail_after = 0                                          # the protected write completes, then power fails
    with pytest.raises(PowerLoss):
        dev.inst.boot_staged_firmware(lambda img: img == art.payload)
    dev.norm.fail_after = None
    dev.boot()
    assert dev.inst.committed(FIRMWARE) == 2 and dev.inst.prot.active == 1 - active
    assert dev.inst.boot_staged_firmware(lambda img: True) == "nothing staged"
    assert dev.inst.staged == {} and dev.inst.downloads == {}


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


def _policy_art(station, world: World, version: int, activate_at: int = T0):
    p = make_policy(world.u_static.pk, mldsa_public_bytes(world.cmd_sk), version=version, activate_at=activate_at)
    return p, build(station, POLICY, version, encode_policy(p), activate_at=activate_at)


def test_the_installed_policy_is_kept_in_flash_across_reboots_and_updates(dev, station, world: World):
    """Master §4.1: the device holds its installed policy in flash. A factory device has none (its factory policy
    applies); after an activation the exact signed bytes come back after a reboot, and after a factory reset of the
    normal flash; a newer policy is staged BESIDE the installed one, which stays intact until the next commit.
    Before the fix nothing persisted it: after a reboot the device ran its factory policy, the utility refused it
    and the current policy it re-sent was refused as a rollback, for ever."""
    assert dev.inst.installed_policy() is None
    v2, a2 = _policy_art(station, world, 2)
    dev.feed(a2)
    assert dev.inst.activate_policy(world.policy).raw == v2.raw
    dev.boot()
    assert dev.inst.installed_policy().raw == v2.raw
    v3, a3 = _policy_art(station, world, 3, activate_at=T0 + 600)
    dev.feed(a3)                                                           # staged ahead of activate_at …
    dev.boot()
    assert dev.inst.installed_policy().raw == v2.raw                       # … without touching the installed one
    dev.now[0] = T0 + 600
    assert dev.inst.activate_policy(dev.inst.installed_policy()).raw == v3.raw
    dev.norm = FlashSim()                                                  # factory reset: normal flash erased
    dev.boot()
    assert dev.inst.installed_policy().raw == v3.raw and dev.inst.committed(POLICY) == 3


def test_a_modified_policy_area_is_refused_at_activation_and_at_boot(dev, station, world: World):
    """Like the firmware slot (V-F4), a policy read back from flash is checked against its signed SHA-256. A byte
    changed inside utility_cmd_pk still decodes and validates, so without the check the device committed (and would
    boot with) a command key nobody signed."""
    v2, a2 = _policy_art(station, world, 2)
    dev.feed(a2)
    area = dev.ff.policy_areas[1 - dev.inst.prot.policy[0]]                 # the staging area
    off = bytes(area).find(v2.utility_cmd_pk) + 100
    area[off] ^= 1
    with pytest.raises(FotaError, match="staged policy modified"):
        dev.inst.activate_policy(world.policy)
    assert dev.inst.committed(POLICY) == 0 and dev.inst.installed_policy() is None
    dev.feed(a2)                                                           # the genuine artifact re-delivered
    assert dev.inst.activate_policy(world.policy).utility_cmd_pk == v2.utility_cmd_pk
    dev.ff.policy_areas[dev.inst.prot.policy[0]][off] ^= 1                  # now the INSTALLED copy is modified
    dev.boot()
    with pytest.raises(FotaError, match="installed policy"):
        dev.inst.installed_policy()


def test_a_device_rebooted_after_a_policy_update_establishes_under_it(station, world: World):
    """The lock-out, end to end in process: v2 activated on both sides, the device reboots and boots with its
    installed policy (not the factory one), and a full handshake under v2 succeeds."""
    from pqgrid.e2e.handshake import DeviceEndpoint
    from pqgrid.persistence.device import DeviceFlash
    from pqgrid.registry import DeviceRecord
    from pqgrid.suite.hkem import HybridKeyPair
    v2, a2 = _policy_art(station, world, 2, activate_at=int(world.t))
    kp, norm, prot, ff = HybridKeyPair.generate(), FlashSim(), FlashSim(), FotaFlash(64 * 1024)
    world.registry.add(DeviceRecord(b"c2-0001", C2, kp.pk))
    clock = lambda: world.t                                                # noqa: E731

    def boot():
        df = DeviceFlash(norm, clock)
        inst = Installer(station.anchors, C2, MP, ff, RecordStore(prot, clock), df.store, clock)
        return DeviceEndpoint(b"c2-0001", C2, inst.installed_policy() or world.policy, 1, kp, clock=clock,
                              flash=df), inst
    d, inst = boot()
    for p in a2.parts:
        inst.on_part(p)
    for c in a2.chunks:
        inst.on_chunk(c)
    d.install_policy(inst.activate_policy(d.policy))
    world.utility.install_policy(v2)
    d, inst = boot()                                                       # reboot
    assert d.policy.info() == v2.info()
    world.full(d)
    assert d.confirmed and world.utility.current_session(b"c2-0001").policy_info == v2.info()



def test_the_installer_follows_the_packet_limit_of_the_policy_it_commits(dev, station, world: World):
    """E61 checks chunks against the device's packet limit, a class value of the INSTALLED policy. A policy that raises
    it (the device then declares 8 KiB to the broker and the publisher builds for 8 KiB) must let those artifacts in,
    now and after a reboot; before the fix the installer kept its factory limit and refused them for ever."""
    from conftest import replace_class
    v2 = make_policy(world.u_static.pk, mldsa_public_bytes(world.cmd_sk), version=2, activate_at=T0,
                     classes=replace_class(world.policy, C2, max_packet=8192, fota_chunk_size=6144))
    dev.feed(build(station, POLICY, 2, encode_policy(v2), activate_at=T0))
    dev.inst.activate_policy(world.policy)
    art = build(station, FIRMWARE, 2, firmware(), max_packet=8192, chunk=6144)
    assert dev.feed(art)[1] == [FIRMWARE]
    dev.boot()                                                             # Dev.boot passes the factory 4 KiB
    assert dev.inst.max_packet == 8192
    assert dev.feed(build(station, FIRMWARE, 3, firmware(), max_packet=8192, chunk=6144))[1] == [FIRMWARE]


def test_a_policy_without_the_devices_own_class_is_refused_before_commit(dev, station, world: World):
    """The manifest names the class (F7), but the policy inside might not define it. Committed, it would leave the
    device with an installed policy it cannot run (every class value comes from it): a lock-out. Refused first."""
    others = {n: c for n, c in world.policy.classes.items() if n != C2}
    v2 = make_policy(world.u_static.pk, mldsa_public_bytes(world.cmd_sk), version=2, activate_at=T0, classes=others)
    dev.feed(build(station, POLICY, 2, encode_policy(v2), activate_at=T0))
    with pytest.raises(FotaError, match="c2_meter"):
        dev.inst.activate_policy(world.policy)
    assert dev.inst.committed(POLICY) == 0 and dev.inst.installed_policy() is None


def test_the_device_loop_applies_every_class_value_of_a_newly_activated_policy(station, world: World):
    """§12 through the production step (DeviceMqtt.housekeeping, no broker): after the loop activates a policy, the
    E2E endpoint, the MQTT CONNECT properties, the FOTA installer's packet limit and the outbox cap all follow the
    new class profile; before the fix the outbox and the installer kept their factory values."""
    import ssl
    from conftest import replace_class
    from pqgrid.commands import CommandProcessor
    from pqgrid.mqtt.device_node import DeviceMqtt
    from pqgrid.persistence.device import DeviceFlash
    from pqgrid.e2e.handshake import DeviceEndpoint
    from pqgrid.registry import DeviceRecord
    from pqgrid.suite.hkem import HybridKeyPair
    v2 = make_policy(world.u_static.pk, mldsa_public_bytes(world.cmd_sk), version=2, activate_at=int(world.t),
                     classes=replace_class(world.policy, C2, max_packet=8192, fota_chunk_size=6144, outbox_cap=2048,
                                           session_expiry_s=3600))
    kp, clock = HybridKeyPair.generate(), (lambda: world.t)
    world.registry.add(DeviceRecord(b"c2-0001", C2, kp.pk))
    df = DeviceFlash(FlashSim(), clock)
    d = DeviceEndpoint(b"c2-0001", C2, world.policy, 1, kp, clock=clock, flash=df)
    inst = Installer(station.anchors, C2, MP, FotaFlash(64 * 1024), RecordStore(FlashSim(), clock), df.store, clock)
    outbox = df.outbox("grid/c2_meter/c2-0001/alert", world.policy.profile(C2).outbox_cap)
    mq = DeviceMqtt(d, CommandProcessor(d, lambda c: None), outbox, ssl.create_default_context(), "localhost", 1,
                    fota=inst)
    art = build(station, POLICY, 2, encode_policy(v2), activate_at=int(world.t))
    for part in art.parts:
        inst.on_part(part)
    for chunk in art.chunks:
        inst.on_chunk(chunk)
    mq.housekeeping()                                                      # the loop activates it
    new = v2.profile(C2)
    assert d.policy.info() == v2.info() and d.profile == new
    assert mq._connect_props(d.profile) == (8192, 3600, new.keepalive_s)   # what the next CONNECT declares; the
    # broker-observed effect (one planned reconnect, the new limit enforced) is in tests/integration/
    # test_connect_properties.py (H-2)
    assert inst.max_packet == new.max_packet and outbox.cap == new.outbox_cap

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
    with pytest.raises(FotaError, match="do not match"):
        compile_acl(art.signed, payload + b"x", station.anchors, [], {})
    as_firmware = build(station, FIRMWARE, world.policy.version, payload)       # validly signed, wrong type
    with pytest.raises(FotaError, match="not a POLICY artifact"):
        verify_policy_artifact(as_firmware.signed, payload, station.anchors)
    liar = build(station, POLICY, world.policy.version + 6, payload)            # manifest 7, policy 1 (E57)
    with pytest.raises(FotaError, match="E57"):
        verify_policy_artifact(liar.signed, payload, station.anchors)


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
    with pytest.raises(FotaError, match="> 4096 B, the largest packet every device of the class can receive"):
        Publisher(world.policy).messages(oversized)                        # … published to a 4 KiB class
