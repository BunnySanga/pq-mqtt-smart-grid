"""Codex audit improvement B (2026-10-03, IMPLEMENTATION-ROADMAP §16): the Master requires two burned-in anchors with
separate custodians (O7, §15.13-§15.14, DR-050: only B revokes A). Before the fix the installer accepted any anchor
set: one anchor, the same key twice, a key of the wrong size or an anchor id no role knows."""
import os

import pytest

from pqgrid.fota.artifact import ANCHOR_A, ANCHOR_B, FotaError
from pqgrid.fota.installer import FotaFlash, Installer
from pqgrid.persistence.flash import FlashSim, RecordStore
from pqgrid.suite.sig import SLH_PK_LEN


def installer(anchors):
    clock = lambda: 0                                                     # noqa: E731
    return Installer(anchors, "c2_meter", 4096, FotaFlash(64 * 1024), RecordStore(FlashSim(), clock),
                     RecordStore(FlashSim(), clock), clock)


def test_two_distinct_anchors_of_the_right_size_are_accepted():
    installer({ANCHOR_A: os.urandom(SLH_PK_LEN), ANCHOR_B: os.urandom(SLH_PK_LEN)})


@pytest.mark.parametrize("which, why", [
    ("A only", "exactly two anchors"),
    ("B only", "exactly two anchors"),
    ("same key twice", "distinct"),
    ("short key", "32-byte"),
    ("a third anchor", "exactly two anchors"),
])
def test_an_anchor_set_the_master_does_not_allow_is_refused(which, why):
    a, b = os.urandom(SLH_PK_LEN), os.urandom(SLH_PK_LEN)
    anchors = {"A only": {ANCHOR_A: a}, "B only": {ANCHOR_B: b}, "same key twice": {ANCHOR_A: a, ANCHOR_B: a},
               "short key": {ANCHOR_A: a, ANCHOR_B: b[:-1]}, "a third anchor": {ANCHOR_A: a, ANCHOR_B: b, 7: a[::-1]}}
    with pytest.raises(FotaError, match=why):
        installer(anchors[which])
