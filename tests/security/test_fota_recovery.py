"""Codex audit P0-1 (2026-10-03, IMPLEMENTATION-ROADMAP §16): no FOTA artifact recovered from flash activates unless
its original signed manifest verifies again, at recovery and right before activation. Before the fix the staged
manifest was stored WITHOUT its signature in the normal record store and believed as it was after a reboot:
rewriting that record and the slot made a forged image boot and commit (reproduced: version 99 committed).

The device keeps the signed manifest (manifest + SLH-DSA signature) in the tail of the artifact's own area; the record
store's copy is only an index that must match it. Every test: a genuine signed artifact is persisted, something
persisted is modified, the device reboots (or simply activates), and the activation must fail."""
import hashlib
from dataclasses import replace

import pytest

from conftest import World
from test_fota import CHUNK, MP, C2, T0, Dev, _policy_art, build, dev, firmware, station  # noqa: F401  (fixtures)
from pqgrid.fota.artifact import ANCHOR_A, FIRMWARE, KEYREVOKE, POLICY, FotaError, decode_manifest
from pqgrid.fota.installer import SIGNED_RESERVE, T_DOWNLOAD, T_STAGED
from pqgrid.fota.publisher import part_payload_budget
from pqgrid.wire import dec, enc, r32, u32

EVIL = b"EVIL FIRMWARE " * 1000


def flip_in_signature(area: bytearray) -> None:
    """Change one byte inside the kept signed manifest's signature (not in the padding after it)."""
    tail = len(area) - SIGNED_RESERVE
    n = r32(bytes(area[tail:tail + 4]))
    area[tail + 4 + n - 100] ^= 1


def keep(area: bytearray, signed: bytes) -> None:
    """What an attacker with flash access writes into the kept slot."""
    area[len(area) - SIGNED_RESERVE:] = (u32(len(signed)) + signed).ljust(SIGNED_RESERVE, b"\0")


def forge(m, payload):
    return replace(m, version=99, payload_length=len(payload), payload_sha256=hashlib.sha256(payload).digest(),
                   chunk_count=-(-len(payload) // m.chunk_size))


def test_a_forged_staged_record_and_slot_do_not_activate_after_a_reboot(dev, station):
    """Codex's reproduction: the staged record says v99 with the hash of the attacker's image, which is in the slot."""
    dev.feed(build(station, FIRMWARE, 2, firmware()))
    m = decode_manifest(dev.inst.store.get(T_STAGED, bytes([FIRMWARE])))
    dev.inst.store.put(T_STAGED, bytes([FIRMWARE]), forge(m, EVIL).encode())
    dev.ff.slots[1 - dev.inst.prot.active][:len(EVIL)] = EVIL
    dev.boot()
    assert dev.inst.boot_staged_firmware(lambda img: True) == "nothing staged"   # before the fix: "committed"
    assert dev.inst.committed(FIRMWARE) == 0 and dev.inst.recovery_refused


def test_a_modified_kept_signature_drops_the_staged_artifact_at_the_reboot(dev, station):
    dev.feed(build(station, FIRMWARE, 2, firmware()))
    flip_in_signature(dev.ff.slots[1 - dev.inst.prot.active])
    dev.boot()
    assert FIRMWARE not in dev.inst.staged and dev.inst.boot_staged_firmware(lambda img: True) == "nothing staged"
    assert dev.inst.committed(FIRMWARE) == 0


def test_a_genuine_signed_manifest_of_another_artifact_does_not_vouch_for_the_staged_one(dev, station):
    """The attacker copies a validly signed manifest (v3, another image) into the kept slot of a staged v2."""
    v3 = build(station, FIRMWARE, 3, firmware())
    dev.feed(build(station, FIRMWARE, 2, firmware()))
    keep(dev.ff.slots[1 - dev.inst.prot.active], v3.signed)
    dev.boot()
    assert FIRMWARE not in dev.inst.staged and dev.inst.committed(FIRMWARE) == 0


def test_a_forged_download_record_is_not_resumed_after_a_reboot(dev, station):
    """An interrupted download (E-F1): its record names the Merkle root every later chunk is checked against.
    Rewritten to the attacker's root, the resumed download would accept the attacker's chunks."""
    art = build(station, FIRMWARE, 2, firmware())
    dev.feed(art, chunks=art.chunks[:1])                                  # one chunk in, then power off
    raw, have = dec(dev.inst.store.get(T_DOWNLOAD, bytes([FIRMWARE])), 2)
    forged = replace(decode_manifest(raw), merkle_root=bytes(32), payload_sha256=bytes(32))
    dev.inst.store.put(T_DOWNLOAD, bytes([FIRMWARE]), enc([forged.encode(), have]))
    dev.boot()
    assert FIRMWARE not in dev.inst.downloads and dev.inst.recovery_refused
    dev.feed(art)                                                         # the genuine artifact, delivered again
    assert dev.inst.boot_staged_firmware(lambda img: art.payload == img) == "committed"


def test_a_genuine_interrupted_download_still_resumes(dev, station):
    """E-F1 is kept: an untouched download record and its kept copy verify, and the download resumes."""
    art = build(station, FIRMWARE, 2, firmware())
    dev.feed(art, chunks=art.chunks[:1])
    dev.boot()
    assert FIRMWARE in dev.inst.downloads and not dev.inst.recovery_refused
    dev.feed(art, parts=[], chunks=art.chunks[1:], shuffle=False)
    assert dev.inst.boot_staged_firmware(lambda img: True) == "committed"


def test_the_kept_copy_modified_while_running_is_caught_right_before_activation(dev, station):
    dev.now[0] = T0
    art = build(station, FIRMWARE, 2, firmware(), activate_at=T0 + 600)
    dev.feed(art)
    assert dev.inst.boot_staged_firmware(lambda img: True) == "waiting for activate_at"
    flip_in_signature(dev.ff.slots[1 - dev.inst.prot.active])           # no reboot in between
    dev.now[0] = T0 + 600
    assert dev.inst.boot_staged_firmware(lambda img: True) == "refused: staged manifest not verified"
    assert dev.inst.committed(FIRMWARE) == 0


def test_a_staged_policy_whose_kept_copy_was_modified_is_refused_at_activation(dev, station):
    world = World()
    _, art = _policy_art(station, world, 2)
    dev.feed(art)
    flip_in_signature(dev.ff.policy_areas[1 - dev.inst.prot.policy[0]])
    with pytest.raises(FotaError, match="signature invalid"):
        dev.inst.activate_policy(world.policy)
    assert dev.inst.committed(POLICY) == 0 and POLICY not in dev.inst.staged


def test_an_interrupted_keyrevoke_whose_kept_copy_was_modified_is_not_applied_at_boot(station):
    """KEYREVOKE is applied as soon as it is staged; a power loss before its protected write leaves it staged, and
    the boot finishes it. That boot must not apply a revocation whose signed manifest no longer verifies."""
    from pqgrid.persistence.flash import PowerLoss
    art = station.keyrevoke(C2, 1, ANCHOR_A, CHUNK, part_payload_budget(MP, C2, KEYREVOKE, 1))
    d = Dev(station)
    d.feed(art, chunks=[])
    d.prot.fail_after = 0                                                 # the protected write never happens
    with pytest.raises(PowerLoss):
        d.feed(art, parts=[])
    d.prot.fail_after = None
    flip_in_signature(d.ff.areas[KEYREVOKE])
    inst = d.boot()
    assert inst.prot.revoked == set() and inst.committed(KEYREVOKE) == 0 and KEYREVOKE not in inst.staged


def test_the_payload_capacity_leaves_room_for_the_kept_signed_manifest(station):
    """V-F5 now counts the kept copy: a payload that fits the slot but not slot − SIGNED_RESERVE is refused before
    anything is downloaded."""
    dev = Dev(station, slot=32 * 1024)
    with pytest.raises(FotaError, match="larger than this device's slot"):
        dev.feed(build(station, FIRMWARE, 2, firmware(32 * 1024 - SIGNED_RESERVE + 1)), chunks=[])
    dev.feed(build(station, FIRMWARE, 2, firmware(32 * 1024 - SIGNED_RESERVE)))
    assert dev.inst.boot_staged_firmware(lambda img: True) == "committed"


# ======================================================================= second Codex review, finding 3
@pytest.mark.parametrize("key", [b"", bytes([9]), bytes([FIRMWARE, 0]), bytes([POLICY])],
                         ids=["empty key", "unknown type", "two-byte key", "key of another type"])
def test_a_record_under_a_wrong_key_is_dropped_and_the_boot_survives(dev, station, key):
    """Recovery read key[0] and trusted the type before validating: an empty key aborted the boot (IndexError), an
    unknown type aborted it later (KeyError). Each such record is now refused and deleted, and updates still work."""
    art = build(station, FIRMWARE, 2, firmware())
    dev.feed(art, chunks=art.chunks[:1])
    raw = dev.inst.store.get(T_DOWNLOAD, bytes([FIRMWARE]))
    dev.inst.store.delete(T_DOWNLOAD, bytes([FIRMWARE]))
    dev.inst.store.put(T_DOWNLOAD, key, raw)                              # a record recovery never wrote
    dev.boot()                                                            # before the fix: IndexError / KeyError
    assert dev.inst.downloads == {} and dev.inst.recovery_refused
    assert dev.inst.store.get(T_DOWNLOAD, key) is None                    # deleted, not met again at every boot
    dev.feed(art)
    assert dev.inst.boot_staged_firmware(lambda img: True) == "committed"


def test_a_truncated_download_bitmap_is_dropped_instead_of_wedging_the_update(dev, station):
    """A genuine manifest with a bitmap shorter than its chunk count passed recovery, then every chunk raised
    IndexError, so the download could never finish. The record is now refused at boot and the download starts over."""
    art = build(station, FIRMWARE, 2, firmware())
    dev.feed(art, chunks=art.chunks[:1])
    raw, _ = dec(dev.inst.store.get(T_DOWNLOAD, bytes([FIRMWARE])), 2)
    dev.inst.store.put(T_DOWNLOAD, bytes([FIRMWARE]), enc([raw, b""]))   # the genuine manifest, an empty bitmap
    dev.boot()
    assert FIRMWARE not in dev.inst.downloads and dev.inst.recovery_refused
    dev.feed(art)                                                         # before the fix: IndexError per chunk
    assert dev.inst.boot_staged_firmware(lambda img: True) == "committed"
