"""Inclusion proofs a third party can check with only a public key: no access to the log is needed.

``make_proof`` packages one entry with its audit path and the signed checkpoint it is proven against.
``verify_proof`` checks that package alone: the checkpoint's signature, the entry's own hash and signature,
and the path from the entry up to the checkpoint's root.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import merkle
from .canonical import CanonicalError, parse_json
from .checkpoint import Checkpoint, checkpoint_from_dict, leaf_hashes, verify_checkpoint_signature
from .entry import Entry, compute_hash, entry_from_dict, signing_message
from .keys import verify_signature


def make_proof(entries: Sequence[Entry], index: int, checkpoint: Checkpoint) -> dict[str, Any]:
    if not 0 <= index < checkpoint.size <= len(entries):
        raise ValueError(f"entry {index} is not covered by a checkpoint of size {checkpoint.size}")
    path = merkle.inclusion_proof(leaf_hashes(entries[: checkpoint.size]), index)
    return {
        "entry": entries[index].as_dict(),
        "index": index,
        "proof": [p.hex() for p in path],
        "checkpoint": checkpoint.as_dict(),
    }


def verify_proof(package: Any, public_key: Ed25519PublicKey, log_id: str) -> str | None:
    """Returns None if the package proves what it claims, otherwise a short reason. Never raises on bad input."""
    try:
        if not isinstance(package, dict) or set(package) != {"entry", "index", "proof", "checkpoint"}:
            return "a proof must be an object with exactly: checkpoint, entry, index, proof"
        entry = entry_from_dict(package["entry"])
        cp = checkpoint_from_dict(package["checkpoint"])
        index, proof = package["index"], package["proof"]
        if isinstance(index, bool) or not isinstance(index, int):
            return "index must be an integer"
        if not isinstance(proof, list) or not all(isinstance(p, str) for p in proof):
            return "proof must be a list of hex strings"
        path = [bytes.fromhex(p) for p in proof]
    except (ValueError, CanonicalError) as err:
        return f"malformed proof: {err}"
    if any(len(p) != merkle.HASH_SIZE for p in path):
        return "every proof step must be 32 bytes"
    if not verify_checkpoint_signature(log_id, cp, public_key):
        return "the checkpoint was not signed by the expected key"
    if entry.seq != index:
        return "the entry's own number does not match the index"
    if compute_hash(log_id, entry.seq, entry.time, entry.payload, entry.prev).hex() != entry.hash:
        return "the entry's hash does not match its content"
    if not verify_signature(public_key, bytes.fromhex(entry.sig), signing_message(entry.hash_bytes())):
        return "the entry was not signed by the expected key"
    if not merkle.verify_inclusion(merkle.leaf_hash(entry.hash_bytes()), index, cp.size, path, bytes.fromhex(cp.root)):
        return "the entry is not in the tree the checkpoint describes"
    return None


def load_package(data: bytes) -> Any:
    return parse_json(data)
