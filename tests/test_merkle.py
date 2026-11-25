from __future__ import annotations

import hashlib
import random

import pytest

from tamperlog import merkle

# Leaves of the Certificate Transparency reference tests, and the roots they give for the first 1..8 leaves.
CT_LEAVES = [
    b"",
    b"\x00",
    b"\x10",
    b"\x20\x21",
    b"\x30\x31",
    b"\x40\x41\x42\x43",
    bytes(range(0x50, 0x58)),
    bytes(range(0x60, 0x70)),
]
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


def leaves(n: int, salt: int = 0) -> list[bytes]:
    return [merkle.leaf_hash(f"leaf {salt}:{i}".encode()) for i in range(n)]


def test_empty_tree_root_is_the_hash_of_the_empty_string() -> None:
    assert merkle.root([]) == hashlib.sha256(b"").digest()
    assert merkle.root([]).hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.mark.parametrize("n", range(1, 9))
def test_roots_match_the_certificate_transparency_reference_values(n: int) -> None:
    hashes = [merkle.leaf_hash(x) for x in CT_LEAVES[:n]]
    assert merkle.root(hashes).hex() == CT_ROOTS[n - 1]


def test_leaves_and_inner_nodes_are_hashed_differently() -> None:
    """A leaf holding the bytes of two child hashes must not equal the inner node over those children."""
    a, b = merkle.leaf_hash(b"a"), merkle.leaf_hash(b"b")
    assert merkle.leaf_hash(a + b) != merkle.node_hash(a, b)


def _reference_root(hashes: list[bytes]) -> bytes:
    """An independent implementation of the same tree: merge equal-sized subtrees with an explicit stack, then
    fold what is left from the right. It shares no code with the recursive definition in the library."""
    stack: list[tuple[bytes, int]] = []
    for h in hashes:
        node, size = h, 1
        while stack and stack[-1][1] == size:
            left, _ = stack.pop()
            node, size = merkle.node_hash(left, node), size * 2
        stack.append((node, size))
    acc = stack.pop()[0]
    while stack:
        acc = merkle.node_hash(stack.pop()[0], acc)
    return acc


@pytest.mark.parametrize("n", range(1, 130))
def test_the_recursive_root_agrees_with_an_independent_stack_implementation(n: int) -> None:
    assert merkle.root(leaves(n)) == _reference_root(leaves(n))


def test_every_inclusion_proof_verifies_in_every_tree_size_up_to_70() -> None:
    for n in range(1, 71):
        hashes = leaves(n)
        r = merkle.root(hashes)
        for i in range(n):
            proof = merkle.inclusion_proof(hashes, i)
            assert merkle.verify_inclusion(hashes[i], i, n, proof, r), (n, i)
            assert len(proof) <= n.bit_length()


def test_inclusion_proofs_fail_when_anything_is_changed() -> None:
    n = 21
    hashes = leaves(n)
    r = merkle.root(hashes)
    proof = merkle.inclusion_proof(hashes, 9)
    assert merkle.verify_inclusion(hashes[9], 9, n, proof, r)
    assert not merkle.verify_inclusion(hashes[8], 9, n, proof, r)  # the wrong leaf
    assert not merkle.verify_inclusion(hashes[9], 8, n, proof, r)  # the wrong position
    assert not merkle.verify_inclusion(hashes[9], 9, n, proof, merkle.root(leaves(n, salt=1)))  # the wrong root
    assert not merkle.verify_inclusion(hashes[9], 9, 40, proof, r)  # a size that changes the shape of the proof
    assert not merkle.verify_inclusion(hashes[9], 9, n, proof[:-1], r)  # a proof that is too short
    assert not merkle.verify_inclusion(hashes[9], 9, n, [*proof, hashes[0]], r)  # a proof that is too long
    for step in range(len(proof)):
        for bit in (0, 7, 100, 255):
            bad = list(proof)
            flipped = int.from_bytes(bad[step], "big") ^ (1 << bit)
            bad[step] = flipped.to_bytes(32, "big")
            assert not merkle.verify_inclusion(hashes[9], 9, n, bad, r), (step, bit)


def test_inclusion_rejects_impossible_positions_and_sizes() -> None:
    hashes = leaves(5)
    r = merkle.root(hashes)
    assert not merkle.verify_inclusion(hashes[0], 5, 5, [], r)
    assert not merkle.verify_inclusion(hashes[0], -1, 5, [], r)
    assert not merkle.verify_inclusion(hashes[0], 0, 0, [], r)
    with pytest.raises(IndexError):
        merkle.inclusion_proof(hashes, 5)


def test_every_consistency_proof_verifies_for_every_pair_of_sizes_up_to_40() -> None:
    for n in range(1, 41):
        hashes = leaves(n)
        second = merkle.root(hashes)
        for m in range(0, n + 1):
            proof = merkle.consistency_proof(hashes, m)
            assert merkle.verify_consistency(m, n, merkle.root(hashes[:m]), second, proof), (m, n)


def test_consistency_proofs_fail_for_a_history_that_was_rewritten() -> None:
    n, m = 30, 11
    hashes = leaves(n)
    rewritten = leaves(n)
    rewritten[3] = merkle.leaf_hash(b"changed")  # an entry inside the first m was altered
    proof = merkle.consistency_proof(hashes, m)
    assert merkle.verify_consistency(m, n, merkle.root(hashes[:m]), merkle.root(hashes), proof)
    assert not merkle.verify_consistency(m, n, merkle.root(rewritten[:m]), merkle.root(hashes), proof)
    assert not merkle.verify_consistency(m, n, merkle.root(hashes[:m]), merkle.root(rewritten), proof)


def test_consistency_proofs_fail_when_the_proof_or_sizes_are_wrong() -> None:
    n, m = 30, 11
    hashes = leaves(n)
    first, second = merkle.root(hashes[:m]), merkle.root(hashes)
    proof = merkle.consistency_proof(hashes, m)
    assert not merkle.verify_consistency(m, n, first, second, proof[:-1])
    assert not merkle.verify_consistency(m, n, first, second, [*proof, hashes[0]])
    assert not merkle.verify_consistency(m + 1, n, first, second, proof)
    assert not merkle.verify_consistency(m, 100, first, second, proof)  # a size that changes the shape of the proof
    assert not merkle.verify_consistency(n, m, second, first, proof)  # backwards: the longer tree cannot be a prefix
    for step in range(len(proof)):
        bad = list(proof)
        bad[step] = bytes(32)
        assert not merkle.verify_consistency(m, n, first, second, bad)


def test_the_empty_and_equal_cases_of_consistency() -> None:
    hashes = leaves(7)
    r = merkle.root(hashes)
    assert merkle.verify_consistency(0, 7, merkle.EMPTY_ROOT, r, [])
    assert not merkle.verify_consistency(0, 7, b"x" * 32, r, [])  # an "empty tree" with some other root is not empty
    assert not merkle.verify_consistency(0, 1, b"x" * 32, b"y" * 32, [])
    assert merkle.verify_consistency(7, 7, r, r, [])
    assert not merkle.verify_consistency(7, 7, r, merkle.root(leaves(7, 1)), [])
    assert not merkle.verify_consistency(7, 7, r, r, [r])
    with pytest.raises(ValueError):
        merkle.consistency_proof(hashes, 8)


def test_random_trees_behave() -> None:
    rng = random.Random(20261125)
    for _ in range(40):
        n = rng.randint(1, 500)
        hashes = [merkle.leaf_hash(rng.randbytes(rng.randint(0, 40))) for _ in range(n)]
        r = merkle.root(hashes)
        i = rng.randrange(n)
        m = rng.randint(0, n)
        assert merkle.verify_inclusion(hashes[i], i, n, merkle.inclusion_proof(hashes, i), r)
        assert merkle.verify_consistency(m, n, merkle.root(hashes[:m]), r, merkle.consistency_proof(hashes, m))


def test_a_root_alone_does_not_authenticate_the_tree_size() -> None:
    """Verification uses the size only to know which siblings are on the left and which on the right. A different
    size with the same proof shape accepts the same root. So a proof must always be checked against a SIGNED
    (size, root) pair, as `verify_proof` does with a checkpoint, and never against a bare root."""
    hashes = leaves(21)
    r = merkle.root(hashes)
    proof = merkle.inclusion_proof(hashes, 9)
    assert merkle.verify_inclusion(hashes[9], 9, 21, proof, r)
    assert merkle.verify_inclusion(hashes[9], 9, 22, proof, r)  # same shape, so accepted: the root says nothing of size
    assert not merkle.verify_inclusion(hashes[9], 9, 40, proof, r)  # a different shape is not
