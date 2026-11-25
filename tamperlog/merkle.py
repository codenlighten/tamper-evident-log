"""A Merkle tree as defined by RFC 6962 (Certificate Transparency), with inclusion and consistency proofs.

Leaves and inner nodes are hashed with different prefixes (0x00 and 0x01), so a leaf can never be passed
off as an inner node. An inclusion proof shows that one entry is in a tree with a given root; a consistency
proof shows that a tree with `first` entries is a prefix of a tree with `second` entries, that is, that
nothing was changed or removed, only appended.

The verification functions follow RFC 9162 section 2.1; the proof generators follow RFC 6962 section 2.1.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

HASH_SIZE = 32
EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """The largest power of two strictly less than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def _mth(h: Sequence[bytes], lo: int, hi: int) -> bytes:
    """Merkle tree hash of the leaf hashes h[lo:hi]."""
    n = hi - lo
    if n == 1:
        return h[lo]
    k = _split(n)
    return node_hash(_mth(h, lo, lo + k), _mth(h, lo + k, hi))


def root(leaf_hashes: Sequence[bytes]) -> bytes:
    """The tree root for these leaf hashes (the hash of the empty string for an empty tree)."""
    if not leaf_hashes:
        return EMPTY_ROOT
    return _mth(leaf_hashes, 0, len(leaf_hashes))


def inclusion_proof(leaf_hashes: Sequence[bytes], index: int) -> list[bytes]:
    """The audit path for the leaf at ``index``: the sibling hashes from the leaf up to the root."""
    n = len(leaf_hashes)
    if not 0 <= index < n:
        raise IndexError(f"leaf index {index} outside a tree of {n} leaves")

    def path(m: int, lo: int, hi: int) -> list[bytes]:
        size = hi - lo
        if size == 1:
            return []
        k = _split(size)
        if m < k:
            return path(m, lo, lo + k) + [_mth(leaf_hashes, lo + k, hi)]
        return path(m - k, lo + k, hi) + [_mth(leaf_hashes, lo, lo + k)]

    return path(index, 0, n)


def verify_inclusion(leaf: bytes, index: int, size: int, proof: Sequence[bytes], expected_root: bytes) -> bool:
    """True if ``leaf`` (a leaf hash) is entry ``index`` of the tree of ``size`` entries with ``expected_root``."""
    if size <= 0 or not 0 <= index < size:
        return False
    fn, sn = index, size - 1
    r = leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == expected_root


def consistency_proof(leaf_hashes: Sequence[bytes], first: int) -> list[bytes]:
    """Proof that the tree of the first ``first`` leaves is a prefix of the tree of all of them."""
    n = len(leaf_hashes)
    if not 0 <= first <= n:
        raise ValueError(f"first size {first} outside 0..{n}")
    if first in (0, n):
        return []

    def sub(m: int, lo: int, hi: int, complete: bool) -> list[bytes]:
        size = hi - lo
        if m == size:
            return [] if complete else [_mth(leaf_hashes, lo, hi)]
        k = _split(size)
        if m <= k:
            return sub(m, lo, lo + k, complete) + [_mth(leaf_hashes, lo + k, hi)]
        return sub(m - k, lo + k, hi, False) + [_mth(leaf_hashes, lo, lo + k)]

    return sub(first, 0, n, True)


def verify_consistency(first: int, second: int, first_root: bytes, second_root: bytes, proof: Sequence[bytes]) -> bool:
    """True if the tree of ``first`` leaves (root ``first_root``) is a prefix of the tree of ``second`` leaves."""
    if first < 0 or second < first:
        return False
    if first == 0:
        # The empty tree is a prefix of every tree, but its root is defined: anything else is not an empty tree.
        # (This says nothing about ``second_root``, which the caller must authenticate some other way.)
        return not proof and first_root == EMPTY_ROOT
    if first == second:
        return not proof and first_root == second_root
    path = list(proof)
    if first & (first - 1) == 0:  # an exact power of two: the first root is itself a subtree root
        path.insert(0, first_root)
    if not path:
        return False
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0
