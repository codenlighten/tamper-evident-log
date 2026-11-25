"""The formats, pinned independently of the library's own helpers.

Every other test would still pass if the writer and the verifier were changed together (say, a different
domain-separation string), because they would agree with each other. These tests rebuild the documented
formats from scratch with the standard library, so a change to a format is a visible, deliberate act.
"""

from __future__ import annotations

import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tamperlog.checkpoint import message as checkpoint_message
from tamperlog.entry import GENESIS_PREV, compute_hash, make_entry, signing_message

TIME = "2026-01-01T00:00:00Z"


def spec_canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def test_the_entry_hash_is_sha256_of_a_domain_prefix_and_the_canonical_body() -> None:
    body = {"log": "L", "seq": 0, "time": TIME, "payload": {"a": 1}, "prev": GENESIS_PREV}
    expected = hashlib.sha256(b"tamperlog-entry-v1\x00" + spec_canonical(body)).digest()
    assert compute_hash("L", 0, TIME, {"a": 1}, GENESIS_PREV) == expected


def test_the_entry_hash_has_a_pinned_value() -> None:
    assert (
        compute_hash("L", 0, TIME, {"a": 1}, GENESIS_PREV).hex()
        == "5ab1ae4c931871e20a4859c44f628abe4c5b7bb6e016b46cfad6409ea14013a5"
    )


def test_the_signature_covers_a_different_domain_prefix_and_the_entry_hash() -> None:
    digest = compute_hash("L", 0, TIME, {"a": 1}, GENESIS_PREV)
    assert signing_message(digest) == b"tamperlog-entry-sig-v1\x00" + digest
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    entry = make_entry("L", 0, TIME, {"a": 1}, GENESIS_PREV, key)
    key.public_key().verify(bytes.fromhex(entry.sig), b"tamperlog-entry-sig-v1\x00" + digest)  # raises if wrong


def test_the_checkpoint_message_is_a_domain_prefix_and_the_canonical_body() -> None:
    body = {"log": "L", "size": 3, "root": "ab" * 32, "time": "2026-01-01T00:00:05Z"}
    expected = b"tamperlog-checkpoint-v1\x00" + spec_canonical(body)
    assert checkpoint_message("L", 3, "ab" * 32, "2026-01-01T00:00:05Z") == expected
    assert hashlib.sha256(expected).hexdigest() == "faa23b9c285b0ccdd479d6798de346523d6b9408eb97bda90d8bee94965fd41f"


def test_the_three_signed_or_hashed_things_can_never_be_mistaken_for_one_another() -> None:
    """Different domain prefixes, so a value valid in one role is never valid in another."""
    digest = compute_hash("L", 0, TIME, {"a": 1}, GENESIS_PREV)
    prefixes = {b"tamperlog-entry-v1\x00", b"tamperlog-entry-sig-v1\x00", b"tamperlog-checkpoint-v1\x00"}
    assert len(prefixes) == 3
    assert not signing_message(digest).startswith(b"tamperlog-checkpoint-v1\x00")
    assert not checkpoint_message("L", 0, digest.hex(), TIME).startswith(b"tamperlog-entry-sig-v1\x00")


def test_each_field_changes_the_hash() -> None:
    base = compute_hash("L", 5, TIME, {"a": 1}, GENESIS_PREV)
    variants = [
        compute_hash("M", 5, TIME, {"a": 1}, GENESIS_PREV),
        compute_hash("L", 6, TIME, {"a": 1}, GENESIS_PREV),
        compute_hash("L", 5, "2026-01-01T00:00:01Z", {"a": 1}, GENESIS_PREV),
        compute_hash("L", 5, TIME, {"a": 2}, GENESIS_PREV),
        compute_hash("L", 5, TIME, {"a": 1}, "1" + GENESIS_PREV[1:]),
    ]
    assert len({base, *variants}) == 6
