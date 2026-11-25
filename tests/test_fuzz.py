"""Properties over thousands of random mutations (deterministic, so a failure can be replayed)."""

from __future__ import annotations

import json
import random
from pathlib import Path

from tamperlog import merkle
from tamperlog.canonical import CanonicalError
from tamperlog.proofs import load_package, make_proof, verify_proof
from tamperlog.verify import verify_log

from .helpers import build


def mutate(rng: random.Random, data: bytes) -> bytes:
    kind = rng.randrange(8)
    lines = data.splitlines(keepends=True)
    if kind == 0:  # flip one bit
        i = rng.randrange(len(data))
        return data[:i] + bytes([data[i] ^ (1 << rng.randrange(8))]) + data[i + 1 :]
    if kind == 1:  # replace a byte
        i = rng.randrange(len(data))
        return data[:i] + bytes([rng.randrange(256)]) + data[i + 1 :]
    if kind == 2:  # delete a run of bytes
        i = rng.randrange(len(data))
        return data[:i] + data[i + rng.randint(1, 30) :]
    if kind == 3:  # insert random bytes
        i = rng.randrange(len(data) + 1)
        return data[:i] + rng.randbytes(rng.randint(1, 20)) + data[i:]
    if kind == 4:  # delete a whole line
        j = rng.randrange(len(lines))
        return b"".join(lines[:j] + lines[j + 1 :])
    if kind == 5:  # duplicate a line
        j = rng.randrange(len(lines))
        return b"".join(lines[: j + 1] + [lines[j]] + lines[j + 1 :])
    if kind == 6:  # swap two lines
        a, b = rng.randrange(len(lines)), rng.randrange(len(lines))
        lines[a], lines[b] = lines[b], lines[a]
        return b"".join(lines)
    j = rng.randrange(len(lines))  # replace one line with another
    lines[j] = lines[rng.randrange(len(lines))]
    return b"".join(lines)


def test_every_changed_byte_is_detected_when_the_log_has_a_checkpoint_covering_all_of_it(tmp_path: Path) -> None:
    """The strong property: with a checkpoint over the whole log, ANY modification at all is caught."""
    fx = build(tmp_path, 8, checkpoint_at=(8,))
    data, cps = fx.path.read_bytes(), fx.checkpoints()
    assert verify_log(data, fx.pub, fx.log_id, cps).ok
    rng = random.Random(0xC0FFEE)
    tried = 0
    for _ in range(4000):
        changed = mutate(rng, data)
        if changed == data:
            continue
        tried += 1
        assert not verify_log(changed, fx.pub, fx.log_id, cps).ok, f"an undetected change: {changed!r}"
    assert tried > 3500


def test_without_a_checkpoint_every_change_is_detected_except_cutting_whole_entries_off_the_end(tmp_path: Path) -> None:
    fx = build(tmp_path, 8, checkpoint_at=())
    data = fx.path.read_bytes()
    boundaries = [i + 1 for i, byte in enumerate(data) if byte == 10]
    shorter_valid_logs = {data[:b] for b in boundaries} | {b""}
    rng = random.Random(0xBADC0DE)
    for _ in range(4000):
        changed = mutate(rng, data)
        if changed == data or changed in shorter_valid_logs:
            continue  # unchanged, or a log that is simply shorter: not detectable without a checkpoint
        assert not verify_log(changed, fx.pub, fx.log_id).ok, f"an undetected change: {changed!r}"


def test_random_garbage_never_crashes_the_verifier(tmp_path: Path) -> None:
    fx = build(tmp_path, 3, checkpoint_at=())
    rng = random.Random(7)
    for _ in range(1500):
        junk = rng.randbytes(rng.randint(0, 400))
        report = verify_log(junk, fx.pub, fx.log_id)
        assert isinstance(report.ok, bool)
    for _ in range(300):
        report = verify_log(b"\n" * rng.randint(0, 5) + fx.path.read_bytes()[: rng.randint(0, 600)], fx.pub, fx.log_id)
        assert isinstance(report.ok, bool)


def test_every_changed_character_of_a_proof_package_is_detected(tmp_path: Path) -> None:
    fx = build(tmp_path, 9, checkpoint_at=(9,))
    package = make_proof(fx.entries(), 4, fx.checkpoints()[0])
    text = json.dumps(package, sort_keys=True)
    assert verify_proof(package, fx.pub, fx.log_id) is None
    rng = random.Random(99)
    alphabet = "0123456789abcdef"
    tried = 0
    for _ in range(3000):
        i = rng.randrange(len(text))
        replacement = rng.choice(alphabet + '{}[]",: 9')
        changed = text[:i] + replacement + text[i + 1 :]
        if changed == text:
            continue
        try:
            parsed = load_package(changed.encode())
        except CanonicalError:
            continue  # not even valid JSON
        if parsed == package:
            continue  # the same package written differently (for example, whitespace)
        tried += 1
        assert verify_proof(parsed, fx.pub, fx.log_id) is not None, f"an undetected change: {changed}"
    assert tried > 1000


def test_random_trees_and_corrupted_proofs_never_verify() -> None:
    rng = random.Random(5)
    for _ in range(300):
        n = rng.randint(2, 60)
        hashes = [merkle.leaf_hash(rng.randbytes(8)) for _ in range(n)]
        r = merkle.root(hashes)
        i = rng.randrange(n)
        proof = merkle.inclusion_proof(hashes, i)
        if not proof:
            continue
        bad = list(proof)
        bad[rng.randrange(len(bad))] = rng.randbytes(32)
        assert not merkle.verify_inclusion(hashes[i], i, n, bad, r)
