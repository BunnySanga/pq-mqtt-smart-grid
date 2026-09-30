"""RFC 6962 Merkle tree and RFC 9162 inclusion proofs (Master §15.7)."""
import os
import random

import pytest

from pqgrid.fota import merkle

# Certificate Transparency reference vectors (RFC 6962 tree heads for the first 1..8 leaves)
CT_LEAVES = [b"", b"\x00", b"\x10", b"\x20\x21", b"\x30\x31", b"\x40\x41\x42\x43",
             bytes(range(0x50, 0x58)), bytes(range(0x60, 0x70))]
CT_ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]


@pytest.mark.parametrize("n", range(1, 9))
def test_rfc6962_reference_roots(n):
    assert merkle.root(CT_LEAVES[:n]).hex() == CT_ROOTS[n - 1]


@pytest.mark.parametrize("n", list(range(1, 34)) + [64, 100, 256])
def test_every_leaf_verifies_and_nothing_else_does(n):
    # distinct chunks: with two equal chunks a proof legitimately verifies at the twin's position too
    chunks = [i.to_bytes(2, "big") + os.urandom(random.randint(0, 40)) for i in range(n)]
    r = merkle.root(chunks)
    other = merkle.root(chunks + [b"one more chunk"])      # (size, root) always come from the SIGNED manifest
    for m in range(n):
        path = merkle.audit_path(m, chunks)
        assert len(path) <= merkle.max_path_len(n)
        assert merkle.verify(m, n, chunks[m], path, r)
        assert not merkle.verify(m, n, chunks[m] + b"x", path, r)                  # tampered data
        if n > 1:
            assert not merkle.verify((m + 1) % n, n, chunks[m], path, r)           # another position
            assert not merkle.verify(m, n, chunks[m], path[:-1], r)                # shortened proof
        assert not merkle.verify(m, n, chunks[m], path + [os.urandom(32)], r)      # lengthened proof
        assert not merkle.verify(m, n, chunks[m], path, other)                     # another tree's root


def test_leaf_and_node_hashes_are_domain_separated():
    a, b = os.urandom(32), os.urandom(32)
    assert merkle.leaf_hash(a + b) != merkle.node_hash(a, b)


def test_out_of_range_and_bad_hash_lengths():
    chunks = [b"a", b"b", b"c"]
    r = merkle.root(chunks)
    assert not merkle.verify(3, 3, b"a", merkle.audit_path(0, chunks), r)
    assert not merkle.verify(0, 3, b"a", [p[:31] for p in merkle.audit_path(0, chunks)], r)
    with pytest.raises(ValueError):
        merkle.root([])
