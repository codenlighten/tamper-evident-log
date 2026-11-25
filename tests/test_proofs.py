from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tamperlog.checkpoint import Checkpoint
from tamperlog.entry import make_entry
from tamperlog.proofs import make_proof, verify_proof

from .helpers import Fixture, build


@pytest.fixture
def fx(tmp_path: Path) -> Fixture:
    return build(tmp_path, 10, checkpoint_at=(4, 10))


def _package(fx: Fixture) -> dict[str, Any]:
    return make_proof(fx.entries(), 4, fx.checkpoints()[1])


def test_every_entry_can_be_proven_against_the_latest_checkpoint_using_only_the_public_key(fx: Fixture) -> None:
    entries, cp = fx.entries(), fx.checkpoints()[1]
    for i in range(10):
        assert verify_proof(make_proof(entries, i, cp), fx.pub, fx.log_id) is None


def test_an_entry_can_be_proven_against_an_older_checkpoint_that_covers_it(fx: Fixture) -> None:
    assert verify_proof(make_proof(fx.entries(), 2, fx.checkpoints()[0]), fx.pub, fx.log_id) is None


def test_an_entry_a_checkpoint_does_not_cover_cannot_be_packaged(fx: Fixture) -> None:
    with pytest.raises(ValueError, match="not covered"):
        make_proof(fx.entries(), 6, fx.checkpoints()[0])


def test_a_changed_entry_is_rejected(fx: Fixture) -> None:
    p = _package(fx)
    p["entry"]["payload"] = {"event": "forged"}
    assert verify_proof(p, fx.pub, fx.log_id) == "the entry's hash does not match its content"


def test_an_entry_resigned_by_someone_else_is_rejected(fx: Fixture) -> None:
    p = _package(fx)
    e = fx.entries()[4]
    p["entry"] = make_entry(fx.log_id, e.seq, e.time, e.payload, e.prev, Ed25519PrivateKey.generate()).as_dict()
    assert verify_proof(p, fx.pub, fx.log_id) == "the entry was not signed by the expected key"


def test_a_proof_for_another_position_is_rejected(fx: Fixture) -> None:
    p = _package(fx)
    p["index"] = 5
    assert verify_proof(p, fx.pub, fx.log_id) == "the entry's own number does not match the index"
    p2 = make_proof(fx.entries(), 5, fx.checkpoints()[1])
    p2["entry"] = fx.entries()[4].as_dict()
    p2["index"] = 4
    assert verify_proof(p2, fx.pub, fx.log_id) == "the entry is not in the tree the checkpoint describes"


def test_a_damaged_path_is_rejected(fx: Fixture) -> None:
    p = _package(fx)
    p["proof"][0] = "00" * 32
    assert verify_proof(p, fx.pub, fx.log_id) == "the entry is not in the tree the checkpoint describes"
    p = _package(fx)
    p["proof"] = p["proof"][:-1]
    assert verify_proof(p, fx.pub, fx.log_id) == "the entry is not in the tree the checkpoint describes"


def test_a_checkpoint_from_another_signer_is_rejected(fx: Fixture, tmp_path: Path) -> None:
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    other = build(other_dir, 10, checkpoint_at=(10,))
    p = _package(fx)
    p["checkpoint"] = other.checkpoints()[0].as_dict()
    assert verify_proof(p, fx.pub, fx.log_id) == "the checkpoint was not signed by the expected key"


def test_the_wrong_public_key_is_rejected(fx: Fixture) -> None:
    reason = verify_proof(_package(fx), Ed25519PrivateKey.generate().public_key(), fx.log_id)
    assert reason == "the checkpoint was not signed by the expected key"


@pytest.mark.parametrize(
    "package",
    [
        None,
        [],
        {},
        {"entry": {}, "index": 0, "proof": [], "checkpoint": {}},
        {"entry": 1, "index": 0, "proof": [], "checkpoint": 2},
    ],
)
def test_malformed_packages_get_a_reason_not_a_crash(fx: Fixture, package: Any) -> None:
    assert isinstance(verify_proof(package, fx.pub, fx.log_id), str)


def test_wrongly_typed_fields_get_a_reason(fx: Fixture) -> None:
    for field, value in (
        ("index", "4"),
        ("index", True),
        ("index", 4.5),
        ("proof", "abc"),
        ("proof", [1, 2]),
        ("proof", ["zz"]),
    ):
        p = _package(fx)
        p[field] = value
        assert isinstance(verify_proof(p, fx.pub, fx.log_id), str), (field, value)
    p = _package(fx)
    p["proof"] = ["ab" * 31]  # 31 bytes
    assert verify_proof(p, fx.pub, fx.log_id) == "every proof step must be 32 bytes"
    cp = fx.checkpoints()[1]
    p = _package(fx)
    p["checkpoint"] = Checkpoint(cp.size, cp.root, cp.time, cp.sig).as_dict() | {"size": -1}
    assert isinstance(verify_proof(p, fx.pub, fx.log_id), str)


def test_a_proof_for_another_log_is_rejected_even_under_the_same_key(fx: Fixture) -> None:
    assert verify_proof(_package(fx), fx.pub, "some-other-log") == "the checkpoint was not signed by the expected key"


def test_a_payload_that_cannot_be_encoded_is_a_reason_not_a_crash(fx: Fixture) -> None:
    for bad in (1.5, {"x": float("nan")}, {1: 2}):
        p = _package(fx)
        p["entry"]["payload"] = bad
        reason = verify_proof(p, fx.pub, fx.log_id)
        assert isinstance(reason, str) and reason.startswith("malformed proof")
