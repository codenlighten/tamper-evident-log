"""Signed checkpoints: "at this time the log had this many entries and this Merkle root".

A checkpoint is how truncation can be shown: a hash chain alone cannot prove that nothing was cut off the
end. That only works if the verifier holds a checkpoint the log's writer (or an attacker with the writer's
files) could not have removed: published somewhere outside the log's storage, such as a notice board,
another organisation, or a public ledger. The ``.checkpoints`` file next to a log is a convenience, not such
an anchor. A log that is shorter than a trusted checkpoint, or whose first ``size`` entries no longer hash
to its root, has been tampered with.

A checkpoint signature covers the log id, so a checkpoint of one log cannot vouch for another.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import merkle
from .canonical import canonical_json
from .entry import Entry, check_log_id, parse_time
from .keys import verify_signature

CHECKPOINT_DOMAIN = b"tamperlog-checkpoint-v1\x00"
CHECKPOINT_FIELDS = frozenset({"size", "root", "time", "sig"})
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")


@dataclass(frozen=True)
class Checkpoint:
    size: int
    root: str
    time: str
    sig: str

    def as_dict(self) -> dict[str, Any]:
        return {"size": self.size, "root": self.root, "time": self.time, "sig": self.sig}

    def line(self) -> bytes:
        return canonical_json(self.as_dict()) + b"\n"


def leaf_hashes(entries: Sequence[Entry]) -> list[bytes]:
    """The Merkle leaves of a log: one per entry, over the entry's hash."""
    return [merkle.leaf_hash(e.hash_bytes()) for e in entries]


def message(log_id: str, size: int, root: str, time: str) -> bytes:
    return CHECKPOINT_DOMAIN + canonical_json({"log": check_log_id(log_id), "size": size, "root": root, "time": time})


def make_checkpoint(log_id: str, entries: Sequence[Entry], key: Ed25519PrivateKey, time: str) -> Checkpoint:
    parse_time(time)
    root = merkle.root(leaf_hashes(entries)).hex()
    return Checkpoint(
        size=len(entries), root=root, time=time, sig=key.sign(message(log_id, len(entries), root, time)).hex()
    )


def verify_checkpoint_signature(log_id: str, cp: Checkpoint, public_key: Ed25519PublicKey) -> bool:
    try:
        signature = bytes.fromhex(cp.sig)
        return verify_signature(public_key, signature, message(log_id, cp.size, cp.root, cp.time))
    except ValueError:
        return False  # a malformed checkpoint object does not verify; it must not crash the verifier


def checkpoint_from_dict(raw: Any) -> Checkpoint:
    if not isinstance(raw, dict) or set(raw) != CHECKPOINT_FIELDS:
        raise ValueError("a checkpoint must be an object with exactly: " + ", ".join(sorted(CHECKPOINT_FIELDS)))
    size, root, time, sig = raw["size"], raw["root"], raw["time"], raw["sig"]
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ValueError("size must be a non-negative integer")
    if not isinstance(root, str) or not _HEX64.match(root):
        raise ValueError("root must be 64 lowercase hex characters")
    if not isinstance(sig, str) or not _HEX128.match(sig):
        raise ValueError("sig must be 128 lowercase hex characters")
    if not isinstance(time, str):
        raise ValueError("time must be a string")
    parse_time(time)
    return Checkpoint(size=size, root=root, time=time, sig=sig)
